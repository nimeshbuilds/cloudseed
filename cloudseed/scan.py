"""Security and compliance scans with saved reports and a printed verdict.

  cs scan cis      CIS Kubernetes Benchmark on the cluster (kube-bench, distro-aware: eks/gke/aks/rke2/vanilla profiles)
  cs scan kube     NSA + MITRE ATT&CK (+ CIS) posture scan of the cluster (kubescape)
  cs scan images   vulnerabilities in running workloads (trivy-operator reports, or a one-off trivy scan)
  cs scan host     CIS benchmark of the hosts (bastion, VPN, local Kubernetes nodes) with OpenSCAP + SCAP Security Guide
  cs scan stig     DISA STIG: hosts with OpenSCAP STIG profiles; EKS with kube-bench's Kubernetes STIG benchmark
  cs scan cloud    CIS benchmark of the cloud account / project / subscription (prowler)
  cs scan fips     verifies FIPS 140 mode end to end (hosts, SSH, TLS, nodes, cloud endpoints, platform items)
  cs scan all      everything that applies to the environment

Every scan writes <workdir>/scans/<kind>-<timestamp>.json (+ .md, + raw tool output) and prints a summary.
"""

from __future__ import annotations

import contextlib
import contextvars
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

from . import audit, deps, netutil, paths, provision as prov, secrets, ui

SCAN_NS = "cloudseed-scan"
SSG_FALLBACK = "0.1.82"

# ---------------------------------------------------------------- reports

def _reports_dir(env) -> Path:
    d = env.dir / "scans"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


RUN_FORMAT = "%Y%m%d-%H%M%S"   # run ids: UTC, one-second resolution; every report and output name ends with one


def run_stamp() -> str:
    return time.strftime(RUN_FORMAT, time.gmtime())


def _later(run: str, n: int) -> str | None:
    """The run id n seconds later (None: `run` is not a YYYYmmdd-HHMMSS stamp)."""
    try:
        return (datetime.strptime(run, RUN_FORMAT) + timedelta(seconds=n)).strftime(RUN_FORMAT)
    except ValueError:
        return None


# The paths a command's scans claimed (reports, their .md, raw tool output files and directories), when it asked for
# them with collect(): a scan that failed part-way still leaves outputs (an openscap-<run>/ directory, a raw trivy file)
# that no returned report names. Per context, so scans running in parallel (web console threads) never mix.
_CLAIMS: contextvars.ContextVar = contextvars.ContextVar("cloudseed_scan_claims", default=None)


@contextlib.contextmanager
def collect():
    """with scan.collect() as made: ... - `made` lists every path claim_run_path created and every report file
    save_report wrote inside the block (in order, each once), whether the scan finished or not. Some may be gone again
    (a reserved output the tool never wrote is removed): check that they exist before using them."""
    made: list[Path] = []
    token = _CLAIMS.set(made)
    try:
        yield made
    finally:
        _CLAIMS.reset(token)


def _claimed(path: Path) -> None:
    made = _CLAIMS.get()
    if made is not None and path not in made:
        made.append(path)


def claim_run_path(d: Path, prefix: str, suffix: str, run: str, directory: bool = False) -> tuple[Path, str]:
    """Create <d>/<prefix><run><suffix> exclusively (an empty file, or a directory) and return it with the run id it got.

    Run ids have one-second resolution, so two runs started in the same second (two terminals, an agent next to the web
    console) would write the same report or output. Creation is atomic: the later run moves on to the next free second
    and can never overwrite or share the other's files. Names keep the <prefix>YYYYmmdd-HHMMSS form that every reader
    (reports(), last_report(), the web console) sorts and parses. An id that is not a run stamp is used as given."""
    if _later(run, 0) is None:
        path = d / f"{prefix}{run}{suffix}"
        if directory:
            path.mkdir(exist_ok=True)
        return path, run
    for n in range(3600):
        cand = _later(run, n) or run
        path = d / f"{prefix}{cand}{suffix}"
        try:
            if directory:
                path.mkdir()
            else:
                os.close(os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            _claimed(path)   # created here, so it is this run's alone
            return path, cand
        except FileExistsError:
            continue
    raise ui.Abort(f"No free name for {prefix}{run}{suffix} in {d} (an hour of runs already used).")


def md_cell(value, limit: int | None = None) -> str:
    """Text for one Markdown table cell: whitespace and newlines folded, '|' escaped, so no message can split the row."""
    text = " ".join(str("" if value is None else value).split())
    if limit and len(text) > limit:
        text = text[:limit - 1] + "\u2026"
    return text.replace("|", "\\|")


def tail_text(text, n: int = 200, lines: int = 1) -> str:
    """The end of a tool's error output as one message line: its last `lines` non-empty lines joined with ' · ',
    whitespace folded, clipped at a word boundary - never a cut mid-word ('ng Kubernetes API ...') and never a newline
    that breaks a panel row."""
    rows = [" ".join(ln.split()) for ln in str(text or "").splitlines() if ln.strip()]
    return ui.clip(" · ".join(rows[-max(1, lines):]), n) if rows else ""


def save_report(env, kind: str, report: dict) -> Path:
    path, run = claim_run_path(_reports_dir(env), f"{kind}-", ".json", str(report.get("run") or run_stamp()))
    report["run"], report["kind"] = run, kind
    paths.atomic_write(path, json.dumps(report, indent=2, default=str) + "\n")   # never a half-written report
    md = [f"# {kind} scan {run} · {env.id}", ""]
    if report.get("verdict"):
        md += [f"**Verdict:** {md_cell(report['verdict'])}", ""]
    for k, v in report.get("summary", {}).items():
        md.append(f"- **{md_cell(k)}**: {md_cell(v)}")
    if report.get("scope"):
        md += ["", f"**Scope:** {md_cell(report['scope'])}"]
    if report.get("failure_policy"):
        md += ["", f"**Failure policy:** {md_cell(report['failure_policy'])}"]
    if report.get("coverage_limits"):
        md += ["", "## Coverage and limits", "", *["- " + md_cell(x) for x in report["coverage_limits"]]]
    if report.get("findings"):
        # The terminal/UI may show a bounded preview. The saved artifact retains
        # every normalized finding and its full explanation/remediation.
        md += ["", "| status | severity | finding | detail |", "|---|---|---|---|"]
        md += [f"| {md_cell(f.get('status', ''))} | {md_cell(f.get('severity', ''))} | {md_cell(f.get('title', ''))} | {md_cell(f.get('detail', ''))} |"
               for f in report["findings"] if isinstance(f, dict)]
        for index, finding in enumerate(report["findings"], 1):
            if not isinstance(finding, dict):
                continue
            extras = {k: v for k, v in finding.items() if k not in ("status", "severity", "title", "detail") and v not in (None, "", [], {})}
            if extras:
                md += ["", f"### Finding {index}: {md_cell(finding.get('title', ''))}", ""]
                for key, value in extras.items():
                    md.append(f"- **{md_cell(key)}:** {md_cell(json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value)}")
    # Preserve scanner-specific evidence (FIPS checks, per-host OpenSCAP results,
    # runtime diagnostics) as well as the common summary/findings schema.
    for key in ("checks", "hosts", "results", "diagnostics"):
        if report.get(key):
            md += ["", "## " + key.replace("_", " ").title(), "", "```json",
                   json.dumps(report[key], indent=2, ensure_ascii=False, default=str).replace("`", "\\u0060"), "```"]
    if report.get("raw"):
        md += ["", f"**Raw scanner output:** {md_cell(report['raw'])}"]
    if report.get("hint"):   # the panel's "next step" row, so the saved report says it too
        md += ["", f"**Next step:** {' '.join(str(report['hint']).split())}"]
    md.append("")
    paths.atomic_write(path.with_suffix(".md"), "\n".join(md))
    _claimed(path)
    _claimed(path.with_suffix(".md"))
    audit.note(env, f"scan-{kind}", {"run": run, "summary": report.get("summary", {}), "report": str(path)})
    return path


def report_order(p: Path) -> tuple:
    """Sort key for scan reports: by the run stamp (<kind>-YYYYmmdd-HHMMSS), whatever the kind; then by name."""
    m = re.search(r"(\d{8}-\d{6})$", p.stem)
    return (m.group(1) if m else "", p.name)


def reports(env) -> list[Path]:
    """Saved scan reports, oldest first by run time (so [-n:] are the n newest, whatever the kind). Raw tool output
    (kubescape/trivy dumps) is not a report: save_report always writes a .md twin and raw files never have one (new raw
    output also lives in scans/raw/)."""
    d = env.dir / "scans"
    found = [p for p in d.glob("*-*.json") if p.with_suffix(".md").exists()] if d.exists() else []
    return sorted(found, key=report_order)


def _raw_dir(env) -> Path:
    d = _reports_dir(env) / "raw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _drop_empty(path: Path) -> bool:
    """Remove a reserved output file the tool never wrote (True when it was missing or empty)."""
    try:
        if path.stat().st_size:
            return False
        path.unlink()
    except OSError:
        pass
    return True


def _panel(title: str, summary: dict, findings: list[dict], path: Path | None, verdict: str | None = None, limit: int = 12, note: str = "",
           hint: str = "") -> None:
    rows: list = [(k, v) for k, v in summary.items()]
    bad = [f for f in findings if str(f.get("status", "")).upper() in
           ("FAIL", "FAILED", "CRITICAL", "HIGH", "UNKNOWN", "MANUAL", "WARN", "ERROR", "SKIP", "SKIPPED") or
           not f.get("status") and f.get("severity") in ("CRITICAL", "HIGH")]
    if bad:
        rows.append(("", ""))
        rows.append((ui.style(f"top findings ({len(bad)})", "bold", "text"), ""))
        for f in bad[:limit]:
            status = str(f.get("status", "")).upper()
            label = " · ".join(str(x) for x in (status, f.get("severity")) if x)
            rows.append((ui.style(label.ljust(8), "seed" if status in ("UNKNOWN", "MANUAL", "WARN", "SKIP", "SKIPPED") else "rose"),
                         f"{ui.clip(str(f.get('title', '')), 70)}   {ui.dim(ui.clip(str(f.get('detail', '')), 60))}"))
        if len(bad) > limit:
            rows.append(("", ui.dim(f"... {len(bad) - limit} more in the report")))
    if note:
        rows.append(("", ui.dim(note)))
    if hint:   # what to do about it: its own row, never read as part of the last finding
        rows += [("", ""), ("next step", hint)]
    tone = "leaf" if not verdict or verdict.startswith("PASS") else "seed" if verdict.startswith(("N/A", "INCOMPLETE")) else "rose"
    if verdict:
        rows.append(("", ""))
        rows.append(("verdict", ui.style(verdict, tone, "bold")))
    if path:
        rows.append(("report", ui.dim(f"{path}  ·  {path.with_suffix('.md')}")))
    ui.panel(title, rows, accent="rose" if bad and tone == "leaf" else tone)


def _ensure_kubectl() -> str:
    """The cluster scans need kubectl only (helm is never used here). Installed with consent: asked on a terminal, or
    CLOUDSEED_AUTO_INSTALL=1; `scan` has no --auto-approve, so a -y run stops with exit 2 and the install command."""
    found = deps.find("kubectl")
    if found:
        return found
    from . import services
    return services.ensure_tool("kubectl", "to run the scan against the cluster", default=True, argv_consent=False)


def _kubectl(ctx, *args: str, input: str | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    kubectl = _ensure_kubectl()
    try:
        return subprocess.run([kubectl, *args], env=ctx.procenv(), capture_output=True, text=True, input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(["kubectl", *args], 124, "", f"kubectl {' '.join(args[:3])} timed out after {timeout}s")


def _fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "cloudseed"})
    with urllib.request.urlopen(req, timeout=timeout, context=netutil.https_context()) as resp:
        return resp.read()


def _latest_tag(repo: str) -> str:
    """Newest release tag of a GitHub repo (API first, the /releases/latest redirect when the API is rate-limited)."""
    try:
        return str(json.loads(_fetch(f"https://api.github.com/repos/{repo}/releases/latest", 30))["tag_name"])
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        req = urllib.request.Request(f"https://github.com/{repo}/releases/latest", headers={"User-Agent": "cloudseed"})
        with urllib.request.urlopen(req, timeout=30, context=netutil.https_context()) as resp:
            final = resp.geturl()
        m = re.search(r"/releases/tag/([^/?#]+)", final)
        if not m:
            raise ValueError(f"no release found for {repo}")
        return m.group(1)


def _install_release(name: str, repo: str, asset: str, sums_file: str, tag: str) -> Path:
    """Download a release tarball, verify its SHA256 against the release's checksum file, install the binary into ~/.cloudseed/bin."""
    base = f"https://github.com/{repo}/releases/download/{tag}"
    with ui.Spinner(f"Downloading {name} {tag} ({asset})") as sp:
        blob = _fetch(f"{base}/{asset}", 900)
        sums = _fetch(f"{base}/{sums_file}", 60).decode("utf-8", "replace")
        expected = next((ln.split()[0] for ln in sums.splitlines() if len(ln.split()) == 2 and ln.split()[1].lstrip("*") == asset), None)
        if not expected:
            raise ui.Abort(f"The {name} {tag} release lists no checksum for {asset}; refusing to install it unverified.")
        if hashlib.sha256(blob).hexdigest() != expected.lower():
            raise ui.Abort(f"Checksum mismatch for {asset}; the download was discarded.")
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.isfile() and os.path.basename(m.name) == name), None)
            fh = tar.extractfile(member) if member is not None else None
            if fh is None:
                raise ui.Abort(f"{asset} contains no {name} binary.")
            data = fh.read()
        paths.BIN_DIR.mkdir(parents=True, exist_ok=True)
        target = paths.BIN_DIR / name
        tmp = target.with_name(name + ".tmp")
        tmp.write_bytes(data)
        tmp.chmod(0o755)
        os.replace(tmp, target)
        sp.done_text = f"{name} {tag} installed at {target} (SHA256 verified)"
    return target


def _install_kubescape() -> Path:
    os_name, arch = deps._os_arch()
    tag = _latest_tag("kubescape/kubescape")
    return _install_release("kubescape", "kubescape/kubescape", f"kubescape_{tag.lstrip('v')}_{os_name}_{arch}.tar.gz", "checksums.sha256", tag)


def _install_trivy() -> Path:
    os_name, arch = deps._os_arch()
    tag = _latest_tag("aquasecurity/trivy")
    ver = tag.lstrip("v")
    plat = {"darwin": "macOS", "linux": "Linux"}[os_name] + "-" + {"amd64": "64bit", "arm64": "ARM64"}[arch]
    return _install_release("trivy", "aquasecurity/trivy", f"trivy_{ver}_{plat}.tar.gz", f"trivy_{ver}_checksums.txt", tag)


def _no_install_in_agent_session(problem: str, how: str) -> None:
    """A scanner is only installed on the user's own run: a session driven by an agent or the MCP server (CLOUDSEED_AGENT
    is set) stops with the command instead. Confirming an MCP scan approves the scan, not software on this machine."""
    agent = os.environ.get("CLOUDSEED_AGENT")
    if agent:
        raise ui.Abort(f"{problem}, and cloudseed does not install software from an agent session ({agent}). "
                       f"Install it yourself ({how}), then re-run.", code=2)


# how to install each scanner by hand; the scan itself installs it when the user runs it (see _tool)
_INSTALL_HOW = {"kubescape": "brew install kubescape, or run `cs scan kube` once in your own terminal: it puts the SHA256-verified release in ~/.cloudseed/bin",
                "trivy": "brew install trivy, or run `cs scan images` once in your own terminal: it puts the SHA256-verified release in ~/.cloudseed/bin"}


def _tool(name: str, brew_pkg: str | None, installer=None) -> str:
    """Find a CLI on PATH / ~/.cloudseed/bin or install it (Homebrew when present, else the official release, SHA256-verified, into ~/.cloudseed/bin)."""
    found = deps.find(name)
    if found:
        return found
    _no_install_in_agent_session(f"{name} is not installed", _INSTALL_HOW.get(name, f"brew install {brew_pkg or name}"))
    ui.info(f"{name} is needed for this scan; installing it")
    if brew_pkg and shutil.which("brew"):
        r = subprocess.run(["brew", "install", brew_pkg], capture_output=True, text=True)
        found = deps.find(name)
        if found:
            return found
        ui.warn(f"brew install {brew_pkg} failed ({tail_text(r.stderr or r.stdout, 200)}); trying the official release")
    if installer:
        try:
            installer()
        except (urllib.error.URLError, OSError, TimeoutError, ValueError, KeyError, tarfile.TarError) as e:
            raise ui.Abort(f"Could not install {name}: {e}. Install it yourself (e.g. brew install {brew_pkg or name}) and re-run.")
        found = deps.find(name)
        if found:
            return found
    raise ui.Abort(f"Install {name} first (e.g. brew install {brew_pkg or name}) and re-run.")


# ---------------------------------------------------------------- CIS (kube-bench)

KUBE_BENCH_IMAGE = "docker.io/aquasec/kube-bench:v0.16.0"  # pinned: its cfg/ ships every benchmark in BENCHMARKS below
# The host mounts are appended per distro (KUBE_BENCH_MOUNTS): mounting a path a node does not have makes the runtime
# create it (stray directories) or fail on read-only roots (GKE COS, Bottlerocket).
# The namespace is exempt from Pod Security Admission (kube-bench needs hostPID and host paths): RKE2's CIS profile
# enforces "restricted" cluster-wide, and namespace labels override those defaults (audit/warn too, or every apply warns).
# The service account gets a token only in the job that runs the `policies` target (see _kube_bench_manifest).
KUBE_BENCH_JOB = """apiVersion: v1
kind: Namespace
metadata:
  name: %(ns)s
  labels: {pod-security.kubernetes.io/enforce: privileged, pod-security.kubernetes.io/audit: privileged, pod-security.kubernetes.io/warn: privileged}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: kube-bench, namespace: %(ns)s, labels: {app: kube-bench}}
automountServiceAccountToken: false
---
apiVersion: batch/v1
kind: Job
metadata: {name: kube-bench-%(role)s, namespace: %(ns)s, labels: {app: kube-bench}}
spec:
  ttlSecondsAfterFinished: 1800
  activeDeadlineSeconds: 600
  backoffLimit: 0
  template:
    metadata: {labels: {app: kube-bench, role: %(role)s}}
    spec:
      hostPID: true
      restartPolicy: Never
      serviceAccountName: kube-bench
      automountServiceAccountToken: false
      %(placement)s
      containers:
        - name: kube-bench
          image: """ + KUBE_BENCH_IMAGE + """
          command: %(command)s
"""
_KB_BASE = [("/var/lib/kubelet", "/var/lib/kubelet"), ("/etc/systemd", "/etc/systemd"), ("/etc/kubernetes", "/etc/kubernetes")]
_KB_NODE_TOOLS = [("/usr/bin", "/usr/local/mount-from-host/bin"), ("/etc/cni/net.d", "/etc/cni/net.d"), ("/opt/cni/bin", "/opt/cni/bin"), ("/var/lib/cni", "/var/lib/cni")]
# (host path, path in the kube-bench container) per distro, after upstream's job-eks/gke/aks.yaml and job.yaml
KUBE_BENCH_MOUNTS = {
    "eks": _KB_BASE,
    "gke": _KB_BASE + [("/home/kubernetes", "/home/kubernetes")],
    "aks": _KB_BASE + [("/etc/default", "/etc/default")],
    "rke2": [("/var/lib/rancher", "/var/lib/rancher"), ("/etc/rancher", "/etc/rancher"), ("/var/lib/kubelet", "/var/lib/kubelet"),
             ("/etc/systemd", "/etc/systemd"), ("/lib/systemd", "/lib/systemd")] + _KB_NODE_TOOLS,
    "kubeadm": [("/var/lib/etcd", "/var/lib/etcd")] + _KB_BASE + [("/lib/systemd", "/lib/systemd")] + _KB_NODE_TOOLS,
}


# The `policies` checks (cluster-admin bindings, wildcard roles, default service accounts, network policies ...) run
# kubectl inside the pod. Without API access every one of them fails - or passes - on "connection refused", whatever the
# cluster's RBAC. This read-only role lets them see what they audit; it never includes secrets, and it is cluster-scoped,
# so cis() removes it again when the scan is over.
KUBE_BENCH_RBAC = "cloudseed-kube-bench"
KUBE_BENCH_RBAC_MANIFEST = """---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: %(rbac)s, labels: {app: kube-bench, app.kubernetes.io/managed-by: cloudseed}}
rules:
  - {apiGroups: [""], resources: [pods, serviceaccounts, namespaces, nodes, services, replicationcontrollers], verbs: [get, list]}
  - {apiGroups: [rbac.authorization.k8s.io], resources: [roles, rolebindings, clusterroles, clusterrolebindings], verbs: [get, list]}
  - {apiGroups: [networking.k8s.io], resources: [networkpolicies, ingresses], verbs: [get, list]}
  - {apiGroups: [networking.gke.io], resources: [managedcertificates], verbs: [get, list]}
  - {apiGroups: [apps], resources: [deployments, replicasets, daemonsets, statefulsets], verbs: [get, list]}
  - {apiGroups: [batch], resources: [jobs, cronjobs], verbs: [get, list]}
  - {apiGroups: [autoscaling], resources: [horizontalpodautoscalers], verbs: [get, list]}
  - {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests], verbs: [get, list]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: %(rbac)s, labels: {app: kube-bench, app.kubernetes.io/managed-by: cloudseed}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: %(rbac)s}
subjects: [{kind: ServiceAccount, name: kube-bench, namespace: %(ns)s}]
"""


def _runs_policies(targets: str | None) -> bool:
    """Whether a kube-bench run includes the `policies` target (no --targets means every target of the benchmark)."""
    return targets is None or "policies" in [t.strip() for t in targets.split(",")]


def _kube_bench_manifest(distro: str, role: str, placement: str, cmd: list[str], api: bool = False) -> str:
    """The Job (and its namespace + service account); api=True mounts the read-only token and adds its ClusterRole."""
    mounts = [m for m in KUBE_BENCH_MOUNTS.get(distro, KUBE_BENCH_MOUNTS["kubeadm"]) if not (role == "node" and m[0] == "/var/lib/etcd")]
    out = KUBE_BENCH_JOB % {"ns": SCAN_NS, "role": role, "placement": placement, "command": json.dumps(cmd)}
    if api:
        out = out.replace("      automountServiceAccountToken: false\n", "      automountServiceAccountToken: true\n", 1)
    out += "          volumeMounts:\n" + "".join(f"            - {{name: m{i}, mountPath: {c}, readOnly: true}}\n" for i, (_, c) in enumerate(mounts))
    out += "      volumes:\n" + "".join(f"        - {{name: m{i}, hostPath: {{path: {h}}}}}\n" for i, (h, _) in enumerate(mounts))
    if api:
        out += KUBE_BENCH_RBAC_MANIFEST % {"rbac": KUBE_BENCH_RBAC, "ns": SCAN_NS}
    return out


def _kube_bench_cleanup_rbac(ctx) -> None:
    """The cluster-scoped read-only role outlives the namespace: remove it (best effort) once the scan is over."""
    try:
        _kubectl(ctx, "delete", "clusterrolebinding,clusterrole", KUBE_BENCH_RBAC, "--ignore-not-found", "--wait=false", timeout=60)
    except (OSError, ui.Abort):
        pass


# kube-bench's own complaints about a benchmark it cannot apply here (the only case a retry with auto-detection helps)
_KB_BENCHMARK_ERRORS = ("unable to find benchmark", "No targets configured for", "are not configured for the CIS Benchmark",
                        "unable to get benchmark version", "unable to determine benchmark version")
_KB_RESULT_START = re.compile(r'\{\s*"Controls"\s*:')
# what a kubectl audit prints when it could not ask the API server (a check that could not look is not evaluated);
# some audits swallow kubectl's error and print their own marker instead (GKE 5.6.7: ERROR_KUBECTL_LIST:INGRESS_FORBIDDEN)
_KB_NO_API = re.compile(r"[Cc]ouldn't get current server API group list|The connection to the server|Error from server \((Forbidden|Unauthorized)\)"
                        r"|is forbidden: User|You must be logged in to the server|dial tcp [^ ]*:8080|ERROR_KUBECTL_LIST|\b[A-Z][A-Z_]*_FORBIDDEN\b")


def _kube_bench_json(logs: str) -> tuple[dict, bool]:
    """(kube-bench's result object, whether one started in the log). The pod log mixes stderr with the JSON, in any
    order, and stderr lines can contain braces too: only an object with "Controls" that parses completely counts."""
    dec = json.JSONDecoder()
    seen = False
    for m in _KB_RESULT_START.finditer(logs or ""):
        seen = True
        try:
            obj, _ = dec.raw_decode(logs, m.start())
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("Controls"), list):
            return obj, True
    return {}, seen


def _server_minor(ctx) -> str:
    """'1.35' from the API server (kube-bench maps it to the newest CIS benchmark for that version or older)."""
    proc = _kubectl(ctx, "version", "-o", "json", timeout=60)
    try:
        sv = json.loads(proc.stdout or "{}").get("serverVersion") or {} if proc.returncode == 0 else {}
    except (ValueError, AttributeError):
        sv = {}
    m = re.match(r"^v?(\d+)\.(\d+)", str(sv.get("gitVersion") or "")) if isinstance(sv, dict) else None
    return f"{m.group(1)}.{m.group(2)}" if m else ""


# newest benchmark per distro (verified against kube-bench's cfg/ directory); "" = let kube-bench auto-detect
BENCHMARKS = {"eks": "eks-1.8.0", "gke": "gke-1.9.0", "aks": "aks-1.8", "rke2": "rke2-cis-1.9", "kubeadm": ""}
STIG_BENCHMARKS = {"eks": "eks-stig-kubernetes-v1r6"}


_POD_FATAL = ("ErrImagePull", "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError", "CreateContainerError", "RunContainerError")


def _kube_bench_state(ctx, role: str) -> tuple[str, str, bool]:
    """(state, detail, ran) of the kube-bench Job: state is done | failed | running; ran = the container started."""
    job = f"kube-bench-{role}"
    try:
        st = json.loads(_kubectl(ctx, "-n", SCAN_NS, "get", "job", job, "-o", "json", timeout=60).stdout or "{}").get("status") or {}
    except ValueError:
        st = {}
    conds = {c.get("type"): c for c in st.get("conditions") or [] if isinstance(c, dict)}
    try:
        pods = json.loads(_kubectl(ctx, "-n", SCAN_NS, "get", "pods", "-l", f"job-name={job}", "-o", "json", timeout=60).stdout or "{}").get("items") or []
    except ValueError:
        pods = []
    ran, detail = False, ""
    for pod in pods:
        pst = pod.get("status") or {}
        for cs in pst.get("containerStatuses") or []:
            state = cs.get("state") or {}
            if state.get("running") or state.get("terminated"):
                ran = True
            waiting = state.get("waiting") or {}
            if waiting.get("reason") in _POD_FATAL:
                return "failed", f"{waiting.get('reason')}: {str(waiting.get('message', '')).strip()[:300]}", ran
            if state.get("terminated"):
                t = state["terminated"]
                detail = f"container exited {t.get('exitCode')} ({t.get('reason', '')})"
        for c in pst.get("conditions") or []:
            if c.get("type") == "PodScheduled" and c.get("status") == "False" and c.get("reason") == "Unschedulable":
                return "failed", f"Unschedulable: {str(c.get('message', ''))[:300]}", ran
        detail = detail or f"pod {pst.get('phase', 'Pending')}"
    if int(st.get("succeeded") or 0) >= 1 or str((conds.get("Complete") or {}).get("status")) == "True":
        return "done", "complete", True
    failed = conds.get("Failed") or {}
    if str(failed.get("status")) == "True":
        return "failed", f"{failed.get('reason', 'Failed')}: {str(failed.get('message', '')).strip()[:300]}", ran
    if not pods:
        ev = _kubectl(ctx, "-n", SCAN_NS, "get", "events", "--field-selector", f"involvedObject.name={job}", "-o", "json", timeout=60)
        try:
            items = json.loads(ev.stdout or "{}").get("items") or []
        except ValueError:
            items = []
        bad = [e for e in items if e.get("reason") == "FailedCreate"]
        if bad:
            return "failed", f"FailedCreate: {str(bad[-1].get('message', ''))[:300]}", False
        detail = "waiting for the pod"
    return "running", detail, ran


def _kube_bench_diag(ctx, role: str) -> str:
    events = _kubectl(ctx, "-n", SCAN_NS, "get", "events", "--sort-by=.lastTimestamp", timeout=60).stdout.strip().splitlines()
    return "\n".join(["recent events in " + SCAN_NS + ":"] + ["  " + e[:220] for e in events[1:][-6:]]) if len(events) > 1 else ""


def _kube_bench_run(ctx, role: str, benchmark: str, targets: str | None, timeout: int = 300, version: str = "") -> dict:
    """Run one kube-bench Job and return its JSON. `version` (Kubernetes major.minor) picks the benchmark when there is
    no distro benchmark: inside the pod kube-bench would otherwise guess (and assume 1.18 when it cannot ask)."""
    what = benchmark or (f"CIS benchmark for Kubernetes {version}" if version else "auto-detected benchmark")
    cmd = (["kube-bench", "run", "--json"] + (["--benchmark", benchmark] if benchmark else ["--version", version] if version else [])
           + (["--targets", targets] if targets else []))
    placement = ""
    if role == "master":
        placement = ("nodeSelector: {node-role.kubernetes.io/control-plane: \"true\"}\n      tolerations: [{operator: Exists}]"
                     if ctx.distro == "rke2" else "nodeSelector: {node-role.kubernetes.io/control-plane: \"\"}\n      tolerations: [{operator: Exists}]")
    manifest = _kube_bench_manifest(ctx.distro, role, placement, cmd, api=_runs_policies(targets))
    job = f"kube-bench-{role}"
    # foreground: the previous run's pods must be gone too, or the first poll would read their state (e.g. an old ErrImagePull)
    _kubectl(ctx, "-n", SCAN_NS, "delete", "job", job, "--ignore-not-found", "--cascade=foreground", "--wait=true", timeout=180)
    r = _kubectl(ctx, "apply", "-f", "-", input=manifest)
    if r.returncode != 0:
        raise ui.Abort(f"could not create the kube-bench job: {tail_text(r.stderr or r.stdout, 300, lines=3)}")
    state, detail, ran = "running", "", False
    deadline = time.time() + timeout
    with ui.Spinner(f"kube-bench ({role}, {what})") as sp:
        while time.time() < deadline:
            state, detail, ran = _kube_bench_state(ctx, role)
            if state != "running":
                break
            sp.update(f"kube-bench ({role}, {what}) · {detail}")
            time.sleep(4)
        if state == "done":
            sp.done_text = f"kube-bench {role} finished"
    lr = _kubectl(ctx, "-n", SCAN_NS, "logs", f"job/{job}", timeout=120) if (ran or state != "running") else None
    logs = (lr.stdout or "") if lr is not None else ""
    data, started = _kube_bench_json(logs)
    if data:
        _kubectl(ctx, "-n", SCAN_NS, "delete", "job", job, "--ignore-not-found", "--wait=false")
        return data
    rejected = next((e for e in _KB_BENCHMARK_ERRORS if e.lower() in logs.lower()), "")
    if (benchmark or version) and ran and state != "running" and not started and rejected:
        # kube-bench itself refused the benchmark (not a crash, not a half-written result): let it pick one
        ui.warn(f"kube-bench cannot apply {what} here ({rejected}); retrying with its auto-detection")
        return _kube_bench_run(ctx, role, "", targets, timeout)
    if started:
        why = "its result was cut off or unreadable"
    else:
        why = detail if state != "running" else f"no result within {timeout}s ({detail or 'pod not started'})"
    tail = [ln for ln in ((lr.stdout or lr.stderr) if lr is not None else "").splitlines() if ln.strip()][-8:]
    parts = [f"kube-bench ({role}) produced no results: {why}."]
    if tail:
        parts += ["last output:"] + ["  " + ui.clip(ln, 200) for ln in tail]
    if state != "done":
        parts += [ln for ln in _kube_bench_diag(ctx, role).splitlines() if ln.strip()]
    parts.append(f"The job pulls {KUBE_BENCH_IMAGE} (Docker Hub rate limits apply) and needs hostPID"
                 + (" and a control-plane node" if role == "master" else "") + f". Inspect it (kept 30 minutes): kubectl -n {SCAN_NS} describe job {job}")
    raise ui.Abort("\n    ".join(parts))


def _not_evaluated(res: dict) -> bool:
    """A kubectl-based check whose audit could not reach the API server: its PASS or FAIL says nothing about the cluster."""
    if "kubectl" not in str(res.get("audit") or ""):
        return False
    return bool(_KB_NO_API.search(f"{res.get('actual_value') or ''}\n{res.get('reason') or ''}"))


# kube-bench's "The default namespace should not be used" audits (EKS 4.5.2: every listable namespaced type; GKE 4.6.4 /
# AKS 4.6.3: the `all` category) print their objects as kind/name, so the grep that drops the `kubernetes` Service never
# matches: objects every cluster has fail them on any cluster. And inside the scan pod they only see what its read-only
# role may list (never secrets or configmaps). cloudseed lists the namespace itself, with the environment's credentials.
_DEFAULT_NS_BUILTIN = {"service/kubernetes", "serviceaccount/default", "configmap/kube-root-ca.crt", "endpoints/kubernetes",
                       "endpointslice.discovery.k8s.io/kubernetes"}
# records the cluster writes there (node events, leases) and metrics views of pods: not objects someone placed
_DEFAULT_NS_NOT_PLACED = ("event/", "event.events.k8s.io/", "lease.coordination.k8s.io/", "podmetrics.metrics.k8s.io/")


def _default_ns_scope(res: dict) -> str | None:
    """'every' (all listable namespaced types) or 'all' (the `all` category) for a default-namespace audit, else None."""
    audit_ = str(res.get("audit") or "")
    if "-n default" not in audit_:
        return None
    if "NO_USER_RESOURCES_IN_DEFAULT" in audit_ and "api-resources" in audit_:
        return "every"
    if "DEFAULT_NAMESPACE_UNUSED" in audit_ and "get all" in audit_:
        return "all"
    return None


def _default_ns_objects(ctx, scope: str) -> list[str] | None:
    """What was placed in the default namespace (kind/name), read from this machine; None: it could not be listed.
    kubectl lists what it can when one API group fails (an aggregated API that is down): objects it found still count,
    but an incomplete listing that found none proves nothing."""
    what = "all"
    if scope == "every":
        types = _kubectl(ctx, "api-resources", "--verbs=list", "--namespaced=true", "-o", "name", timeout=120)
        names = [t for t in (types.stdout or "").split() if "/" not in t and not t.endswith(".metrics.k8s.io")]
        if not names:
            return None
        what = ",".join(names)
    proc = _kubectl(ctx, "get", what, "-n", "default", "-o", "name", "--ignore-not-found", timeout=180)
    objs = [ln.strip() for ln in (proc.stdout or "").splitlines() if "/" in ln]
    placed = [o for o in objs if o not in _DEFAULT_NS_BUILTIN and not o.startswith(_DEFAULT_NS_NOT_PLACED)]
    if proc.returncode != 0 and not placed:
        return None
    return placed


def _default_ns_result(ctx, res: dict, scope: str, seen: dict) -> tuple[str, str]:
    """(status, detail) of a default-namespace check, decided from this machine's own listing of the namespace."""
    if scope not in seen:
        try:
            seen[scope] = _default_ns_objects(ctx, scope)
        except (OSError, ui.Abort):
            seen[scope] = None
    objs = seen[scope]
    if objs is None:
        return "WARN", ("not evaluated: kube-bench counts objects every cluster has (service/kubernetes, serviceaccount/default), "
                        f"and cloudseed could not list the namespace itself - look: cs kubectl {ctx.target} --env {ctx.env.name} get all -n default")
    if not objs:
        return "PASS", ""
    status = "FAIL" if res.get("scored", True) is not False else "WARN"   # an unscored (Manual) check only asks to review
    return status, (", ".join(objs[:6]) + (f" (+{len(objs) - 6} more)" if len(objs) > 6 else "")
                    + " in the default namespace (listed by cloudseed); move them into their own namespaces")


def _cis_profile_hint(ctx, fails: int) -> str:
    """On a VMware RKE2 cluster whose CIS hardening profile is off, how to turn it on ('' otherwise): the settings the
    profile applies are what many of the benchmark's checks look for."""
    if not fails or ctx.distro != "rke2" or ctx.target != "vmware":
        return ""
    from .clouds.base import as_bool
    try:
        on = as_bool((getattr(ctx, "cfg", None) or {}).get("vars", {}).get("kubernetes_cis_profile", False))
    except (ValueError, AttributeError):
        on = False
    if on:
        return ""
    env = ctx.env.name
    return (f"RKE2's CIS hardening profile is off for this cluster (kubernetes_cis_profile=false), and many of these checks test "
            f"what it sets. Enable it: cs setup vmware --env {env} --var kubernetes_cis_profile=true, then "
            f"cs provision vmware --env {env} --host k8s (it enforces the restricted Pod Security Standard outside the system namespaces).")


def cis(ctx, stig: bool = False) -> Path:
    _ensure_kubectl()
    benchmark = STIG_BENCHMARKS.get(ctx.distro) if stig else BENCHMARKS.get(ctx.distro, "")
    if stig and not benchmark:
        raise ui.Abort(f"kube-bench has no STIG benchmark for {ctx.distro} (only EKS: eks-stig-kubernetes-v1r6). "
                       "Use `cs scan cis` for the CIS benchmark and `cs scan stig --host` for the hosts.")
    version = "" if benchmark else _server_minor(ctx)
    if not benchmark and not version:
        ui.warn("Could not read the cluster's Kubernetes version; kube-bench picks the benchmark itself (check the benchmark in the report).")
    runs = [("node", None)] if ctx.distro in ("eks", "gke", "aks") else [("master", None), ("node", "node,policies")]
    if ctx.distro in ("rke2", "kubeadm"):
        runs = [("master", "master,etcd,controlplane,policies"), ("node", "node")]
    findings: list[dict] = []
    checks, raw_results, diagnostics = [], [], []
    totals = {"pass": 0, "fail": 0, "warn": 0, "info": 0, "unknown": 0}
    used: list[str] = []
    not_evaluated = 0
    default_ns: dict = {}   # the default namespace's own listing, read once per scan
    try:
        for role, targets in runs:
            try:
                data = _kube_bench_run(ctx, role, benchmark or "", targets, version=version)
            except ui.Abort as exc:
                diagnostics.append(f"{role}: {exc}")
                continue
            raw_results.append({"role": role, "result": data})
            before = len(checks)
            controls = data.get("Controls") if isinstance(data, dict) else None
            if not isinstance(controls, list):
                diagnostics.append(f"{role}: kube-bench returned an invalid Controls list.")
                continue
            for control in controls:
                if not isinstance(control, dict) or not isinstance(control.get("tests"), list):
                    diagnostics.append(f"{role}: a benchmark control could not be read.")
                    continue
                if control.get("version") and control["version"] not in used:
                    used.append(str(control["version"]))
                for test in control.get("tests", []):
                    if not isinstance(test, dict) or not isinstance(test.get("results"), list):
                        diagnostics.append(f"{role}: benchmark test results could not be read.")
                        continue
                    for res in test.get("results", []):
                        if not isinstance(res, dict):
                            diagnostics.append(f"{role}: an individual check result could not be read.")
                            continue
                        st = str(res.get("status", "")).upper()
                        st = st if st in ("PASS", "FAIL", "WARN", "INFO") else "UNKNOWN"
                        detail = str(res.get("remediation") or "").strip()
                        unknown_reason = ""
                        if st == "UNKNOWN":
                            supplied = res.get("status")
                            unknown_reason = ("kube-bench did not supply a result status." if supplied is None or supplied == "" else
                                              f"kube-bench supplied unsupported result status {supplied!r}; this check's outcome cannot be determined.")
                            detail = unknown_reason + (" " + detail if detail else "")
                        scope = _default_ns_scope(res) if st in ("PASS", "FAIL", "WARN") else None
                        if scope:
                            st, verdict_detail = _default_ns_result(ctx, res, scope, default_ns)
                            detail = verdict_detail or detail
                            not_evaluated += default_ns.get(scope) is None   # cloudseed could not list it either
                        elif st in ("PASS", "FAIL") and _not_evaluated(res):
                            st, detail = "WARN", "not evaluated: kube-bench could not query the Kubernetes API from its pod"
                            not_evaluated += 1
                        totals[st.lower()] = totals.get(st.lower(), 0) + 1
                        check = {"id": str(res.get("test_number") or ""), "status": st,
                                 "severity": "HIGH" if st == "FAIL" else "MEDIUM" if st == "WARN" else "INFO",
                                 "title": f"{res.get('test_number')} {res.get('test_desc')}", "detail": detail,
                                 "remediation": str(res.get("remediation") or ""), "reason": res.get("reason"),
                                 "actual_value": res.get("actual_value"), "node_type": control.get("node_type"),
                                 "section": test.get("section"), "role": role, "scanner_status": res.get("status")}
                        if unknown_reason:
                            check["reason"] = unknown_reason + (" Scanner reason: " + str(res["reason"]) if res.get("reason") else "")
                            check["remediation"] = "Inspect the raw kube-bench result and scanner version, resolve the missing or unsupported status, then rerun this benchmark." + (
                                " Scanner guidance: " + check["remediation"] if check["remediation"] else "")
                        elif st == "WARN":
                            if not check["reason"]:
                                check["reason"] = detail or "kube-bench reported WARN, which requires manual attention; the scanner supplied no check-specific explanation."
                            if not detail:
                                check["detail"] = check["reason"]
                            if not check["remediation"]:
                                check["remediation"] = "Review this check in the raw kube-bench report, complete any required manual assessment or restore unavailable API access, then rerun the benchmark."
                        checks.append(check)
                        if st != "PASS":
                            findings.append(check)
            if len(checks) == before:
                diagnostics.append(f"{role}: kube-bench returned no evaluated checks.")
    finally:
        if any(_runs_policies(t) for _, t in runs):
            _kube_bench_cleanup_rbac(ctx)
    ran = ", ".join(used) or benchmark or (f"CIS for Kubernetes {version}" if version else "auto-detected")
    if benchmark and used and used != [benchmark]:
        ui.warn(f"kube-bench ran {ran}, not the {ctx.distro} benchmark {benchmark}: the paths it checks may not match this distro.")
        diagnostics.append(f"Requested benchmark {benchmark} differs from reported benchmark {ran}; applicability requires review.")
    kind = "stig-k8s" if stig else "cis"
    summary = {"benchmark": ran, "distro": ctx.distro, **totals}
    if not_evaluated:
        summary["not evaluated"] = not_evaluated
    # kube-bench defines INFO as informational / intentionally skipped: it does
    # not request further action. WARN, in contrast, requires manual attention.
    # Keep INFO visible without treating it as an evidence collection failure.
    incomplete = bool(diagnostics or not checks or totals["warn"] or totals["unknown"] or not_evaluated)
    informational_only = bool(checks) and not totals["pass"] and totals["info"] == len(checks)
    report = {"summary": summary, "findings": findings, "checks": checks, "raw_results": raw_results,
              "diagnostics": diagnostics, "tool": "kube-bench",
              "failure_policy": "Any failed check fails this benchmark; manual, unknown, unevaluated, or missing checks make it incomplete. Informational checks do not block a completed assessment; an informational-only scope is N/A.",
              "coverage_limits": ["kube-bench samples the scheduled node for each role; this is not evidence that every node or every framework requirement was assessed."],
              "verdict": "FAIL" if totals["fail"] else "INCOMPLETE" if incomplete else "N/A" if informational_only else "PASS"}
    hint = "" if stig else _cis_profile_hint(ctx, totals["fail"])
    if hint:
        report["hint"] = hint
    path = save_report(ctx.env, kind, report)
    _panel(f"{'Kubernetes STIG' if stig else 'CIS Kubernetes Benchmark'} · {ctx.env.id}", report["summary"], findings, path,
           verdict=f"{report['verdict']} - {totals['fail']} failed, {totals['warn']} to review (WARN = manual check"
                   + (f"; {not_evaluated} could not query the API" if not_evaluated else "") + ")", hint=hint)
    return path


# ---------------------------------------------------------------- kubescape

def _scanner_error_count(output: str) -> int:
    """Count execution-error messages without persisting possible credentials from stderr."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output or "")
    return sum(bool(re.search(r"\b(?:ERROR|FATAL|AccessDenied\w*|Unauthorized\w*|Forbidden|EndpointConnectionError)\b|"
                              r"Could not connect to the endpoint URL|\baccess denied\b", line, re.I))
               for line in clean.splitlines())


def kube(ctx, frameworks: str | None = None) -> Path:
    from . import platform as platformmod
    _ensure_kubectl()
    ks = _tool("kubescape", "kubescape", _install_kubescape)
    fw = frameworks or "nsa,mitre"
    out, run = claim_run_path(_raw_dir(ctx.env), "kubescape-", ".json", run_stamp())   # the report gets the same run id
    try:
        with ui.Spinner(f"kubescape scan framework {fw}") as sp:
            r = subprocess.run([ks, "scan", "framework", fw, "--format", "json", "--output", str(out)],
                               env=ctx.procenv(), capture_output=True, text=True, timeout=1800)
            # exit 1 is both "a threshold tripped" (report written) and "could not reach the cluster" (nothing written)
            if r.returncode in (0, 1) and out.exists() and out.stat().st_size > 0:
                sp.done_text = "kubescape finished"
    except subprocess.TimeoutExpired:
        _drop_empty(out)
        raise ui.Abort(f"kubescape did not finish within 30 minutes. Check the cluster connection - {platformmod._unreachable_hint(ctx)} "
                       f"(then: cs kubectl {ctx.target} --env {ctx.env.name} get nodes) - and re-run: cs scan kube {ctx.target} --env {ctx.env.name}")
    try:
        data = json.loads(out.read_text(), parse_constant=str)  # preserve invalid NaN/Infinity as text, never emit invalid report JSON
    except (OSError, ValueError):
        _drop_empty(out)
        raise ui.Abort(f"kubescape failed (exit {r.returncode}): {tail_text(r.stderr or r.stdout, 600, lines=2)}")
    if not isinstance(data, dict) or not isinstance(data.get("summaryDetails", {}), dict):
        raise ui.Abort(f"kubescape wrote an invalid report ({out}): expected a summaryDetails object.")
    sd = data.get("summaryDetails", {})
    findings, checks, diagnostics = [], [], []
    counts = {"passed": 0, "failed": 0, "skipped": 0, "not applicable": 0}
    controls = sd.get("controls") or {}
    if not isinstance(controls, dict):
        raise ui.Abort(f"kubescape wrote an invalid report ({out}): expected controls keyed by ID.")
    for cid, c in controls.items():
        if not isinstance(c, dict):
            diagnostics.append(f"Control {cid} has no readable result.")
            counts["unknown"] = counts.get("unknown", 0) + 1
            why = "Kubescape returned a null control result." if c is None else f"Kubescape returned a {type(c).__name__} instead of a control result object."
            findings.append({"id": cid, "status": "UNKNOWN", "severity": "UNKNOWN", "title": str(cid),
                             "detail": why, "reason": why, "evidence": c,
                             "remediation": "Inspect the raw Kubescape report and scanner version, then rerun the scan to obtain a readable control result."})
            continue
        raw = c.get("status")
        status_info = c.get("statusInfo") or {}
        supplied_status = raw.get("status") if isinstance(raw, dict) else raw
        if supplied_status is None or supplied_status == "":
            supplied_status = status_info.get("status") if isinstance(status_info, dict) else None
        st = str(supplied_status).lower()
        st = st if st in ("passed", "failed", "skipped") else "unknown"
        unknown_reasons = []
        action = ""
        if st == "unknown":
            unknown_reasons.append("Kubescape did not supply a recognized result status." if supplied_status is None or supplied_status == "" else
                                   f"Kubescape supplied unsupported result status {supplied_status!r}.")
            action = "Inspect the raw control result and scanner version, resolve the missing or unsupported status, then rerun the scan."
        partial_coverage = isinstance(status_info, dict) and status_info.get("subStatus") == "incompleteCoverage"
        if partial_coverage:
            diagnostics.append(f"Control {cid}: Kubescape reports incompleteCoverage; only part of the resource evidence was evaluated.")
            if st == "passed":
                st = "unknown"
                unknown_reasons.append("Kubescape explicitly reported incompleteCoverage; only part of the resource evidence was evaluated.")
            action = "Inspect the raw control result and scanner collection messages, restore the missing resource coverage, then rerun the scan."
        counters = c.get("ResourceCounters") or c.get("resourceCounters") or {}
        counters = counters if isinstance(counters, dict) else {}
        # Kubescape v4.0.14 / opa-utils v0.0.312 uses passed+irrelevant for no
        # matching resources. It also propagates irrelevant from individual
        # resources, so only explicit all-zero counters establish whole-control N/A.
        counter_names = ("passedResources", "failedResources", "skippedResources", "excludedResources")
        if (st == "passed" and isinstance(status_info, dict) and status_info.get("subStatus") == "irrelevant"
                and all(type(counters.get(k)) is int and counters[k] == 0 for k in counter_names)):
            st = "not applicable"
        counts[st] = counts.get(st, 0) + 1
        sev = str(c.get("severity") or "").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            try:
                factor = float(c["scoreFactor"])
                if not 0 <= factor <= 10:  # also rejects NaN and infinities
                    raise ValueError
                sev = "CRITICAL" if factor >= 9 else "HIGH" if factor >= 7 else "MEDIUM" if factor >= 4 else "LOW"
            except (KeyError, TypeError, ValueError):
                sev = "UNKNOWN"
                unknown_reasons.append(f"Kubescape supplied no recognized severity and no valid scoreFactor from 0 to 10 (severity={c.get('severity')!r}, scoreFactor={c.get('scoreFactor')!r}).")
                if not action:
                    action = "Review this control's published severity and raw result, update the scanner if needed, then rerun before relying on the severity threshold."
        status = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP", "not applicable": "NOT_APPLICABLE", "unknown": "UNKNOWN"}[st]
        category = c.get("category") or {}
        category = category.get("name", "") if isinstance(category, dict) else str(category)
        detail = f"{counters.get('failedResources', '?')} failing resources ({category})" if st == "failed" else str(c.get("statusInfo") or raw or "No evaluation status")
        if partial_coverage:
            detail = "Kubescape reported incomplete resource coverage; this control is not fully verified. " + detail
        reason = ""
        if st == "skipped":
            substatus = status_info.get("subStatus") if isinstance(status_info, dict) else None
            substatus = substatus if isinstance(substatus, str) else None
            why_and_action = {
                "notEvaluated": ("Required resource types could not be collected.", "Inspect collection errors, restore access to the required resource types, then rerun the scan."),
                "configuration": ("The control's required configuration is missing.", "Configure the inputs required by this Kubescape control, then rerun the scan."),
                "integration": ("The control requires an integration that was not available to this scan.", "Review the scanner's integration details, configure the required integration, then rerun the scan."),
                "requires review": ("Kubescape marks this control as requiring review.", "Complete the review described by this control and record the assessment evidence."),
                "manual review": ("Kubescape marks this control as requiring manual review.", "Complete the manual assessment described by this control and record the evidence."),
                "incompleteCoverage": ("Kubescape explicitly reported incomplete resource coverage.", "Inspect collection messages, restore the missing resource coverage, then rerun the scan."),
            }
            reason, action = why_and_action.get(substatus, (
                "Kubescape skipped this control without a recognized structured reason.",
                "Inspect this control's raw statusInfo and scanner messages, determine why it was skipped, then complete the assessment or rerun it."))
            detail = reason + " " + detail
        if unknown_reasons:
            detail = " ".join(unknown_reasons) + " " + detail
        check = {"id": cid, "status": status, "severity": sev, "title": f"{cid} {c.get('name', '')}",
                 "detail": detail, "evidence": c}
        if reason or unknown_reasons:
            check["reason"] = " ".join([reason, *unknown_reasons]).strip()
        if action:
            check["remediation"] = action
        checks.append(check)
        if st != "passed":
            findings.append(check)
    order = {s: i for i, s in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"))}
    findings.sort(key=lambda f: (f["status"] != "FAIL", order[f["severity"]]))
    if not controls:
        diagnostics.append("Kubescape returned no controls; cluster coverage could not be established.")
    if r.returncode not in (0, 1) or (r.returncode == 1 and not counts["failed"]):
        diagnostics.append(f"Kubescape exited {r.returncode}; available results may be partial.")
    error_lines = _scanner_error_count((r.stderr or "") + "\n" + (r.stdout or ""))
    if error_lines:
        diagnostics.append(f"Kubescape reported {error_lines} execution/permission/endpoint error message(s); coverage may be incomplete.")
    if any(f["status"] == "FAIL" and f["severity"] == "UNKNOWN" for f in findings):
        diagnostics.append("Some failed controls have unknown severity; their threshold outcome requires review.")
    def percentage(value):
        try:
            if value is None:
                return "-"
            score_value = float(value)
            return f"{round(score_value, 1)}%" if 0 <= score_value <= 100 else "unknown"
        except (TypeError, ValueError):
            return "unknown"
    score = sd.get("complianceScore") if sd.get("complianceScore") is not None else sd.get("score")
    per_fw = ", ".join(f"{f.get('name')} {percentage(f.get('complianceScore'))}" for f in (sd.get("frameworks") or []) if isinstance(f, dict))
    failed_threshold = any(f["status"] == "FAIL" and f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    incomplete = bool(diagnostics or counts["skipped"] or counts.get("unknown"))
    all_na = bool(controls) and counts["not applicable"] == len(controls)
    report = {"run": run, "summary": {"frameworks": fw, "controls passed": counts.get("passed", 0), "controls failed": counts.get("failed", 0), "skipped": counts.get("skipped", 0),
                          "not applicable": counts["not applicable"], "unknown": counts.get("unknown", 0),
                          "compliance score": percentage(score) + (f"  ({per_fw})" if per_fw else "")}, "findings": findings, "checks": checks,
              "tool": "kubescape", "raw": str(out), "scanner_rc": r.returncode, "diagnostics": diagnostics,
              "failure_policy": "Critical or High failed controls fail this scan. Medium and Low failures remain findings even when the threshold passes. Explicit irrelevant controls with no matching resources are not applicable. Skipped, unknown, empty or partial evidence makes it incomplete.",
              "coverage_limits": ["Results cover only resources and controls Kubescape could evaluate with the current Kubernetes identity; manual organizational controls require separate review."],
              "verdict": "FAIL" if failed_threshold else "INCOMPLETE" if incomplete else "N/A" if all_na else "PASS"}
    path = save_report(ctx.env, "kube", report)
    _panel(f"Kubernetes posture (kubescape {fw}) · {ctx.env.id}", report["summary"], findings, path,
           verdict=f"{report['verdict']} - {counts['failed']} failing controls (failure threshold: High/Critical)")
    return path


# ---------------------------------------------------------------- images (trivy)

def images(ctx) -> Path:
    _ensure_kubectl()
    findings: list[dict] = []
    def explain_severity(finding, supplied):
        if finding["severity"] != "UNKNOWN":
            return finding
        reason = ("Trivy did not supply a vulnerability severity." if supplied is None or supplied == "" else
                  "Trivy explicitly reported UNKNOWN severity; no supported severity classification was supplied." if str(supplied).upper() == "UNKNOWN" else
                  f"Trivy supplied unsupported vulnerability severity {supplied!r}.")
        finding["reason"] = reason
        finding["detail"] = reason + " " + finding["detail"]
        finding["remediation"] = "Review the vulnerability's vendor advisory and refresh the scanner/database before relying on its severity. " + finding["remediation"]
        return finding
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    diagnostics = []
    observed = 0
    scanner_rc = 0
    source = "trivy-operator"
    r = _kubectl(ctx, "get", "vulnerabilityreports", "-A", "-o", "json")
    try:
        operator_items = json.loads(r.stdout or "{}", parse_constant=str).get("items") if r.returncode == 0 else None
    except (ValueError, AttributeError):
        operator_items = None
    if not isinstance(operator_items, list):
        operator_items = None
    raw, run = None, run_stamp()
    if operator_items:
        raw, run = claim_run_path(_raw_dir(ctx.env), "trivy-operator-", ".json", run)
        raw.write_text(r.stdout)
        for it in operator_items:
            report_data = it.get("report") if isinstance(it, dict) else None
            if not isinstance(report_data, dict) or not isinstance(report_data.get("summary"), dict):
                diagnostics.append("An operator report has no readable vulnerability summary.")
                continue
            observed += 1
            s = report_data["summary"]
            if not any(k.lower() + "Count" in s for k in sev):
                diagnostics.append("An operator summary contains no severity totals.")
            listed = {k: 0 for k in sev}
            metadata = it.get("metadata") or {}
            metadata = metadata if isinstance(metadata, dict) else {}
            labels = metadata.get("labels") or {}
            labels = labels if isinstance(labels, dict) else {}
            resource = f"{metadata.get('namespace', '?')}/{labels.get('trivy-operator.resource.name', metadata.get('name', '?'))}"
            vulnerabilities = report_data.get("vulnerabilities")
            if vulnerabilities is None:
                vulnerabilities = []
            if not isinstance(vulnerabilities, list):
                diagnostics.append(f"{resource}: vulnerability details are malformed.")
                vulnerabilities = []
            for v in vulnerabilities:
                if not isinstance(v, dict):
                    diagnostics.append(f"{resource}: an individual vulnerability could not be read.")
                    continue
                severity = str(v.get("severity") or "UNKNOWN").upper()
                severity = severity if severity in sev else "UNKNOWN"
                listed[severity] += 1
                findings.append(explain_severity({"id": str(v.get("vulnerabilityID") or ""), "status": "FAIL", "severity": severity,
                                 "title": f"{v.get('vulnerabilityID')} {v.get('resource')} {v.get('installedVersion')}",
                                 "detail": f"{resource}  fixed: {v.get('fixedVersion') or '-'}",
                                 "resource": resource, "remediation": f"Upgrade to {v['fixedVersion']}" if v.get("fixedVersion") else "No fixed version was reported; review vendor guidance and exposure.",
                                 "evidence": v}, v.get("severity")))
            for k in sev:
                declared = s.get(f"{k.lower()}Count", 0)
                if type(declared) is not int or declared < 0:
                    declared = 0
                    diagnostics.append(f"{resource}: the {k.lower()} total is invalid.")
                sev[k] += max(declared, listed[k])
                if declared > listed[k]:
                    diagnostics.append(f"{resource}: summary reports {declared} {k.lower()} vulnerabilities but only {listed[k]} details are available.")
    else:
        source = "trivy k8s"
        trivy = _tool("trivy", "trivy", _install_trivy)
        out, run = claim_run_path(_raw_dir(ctx.env), "trivy-", ".json", run)
        raw = out
        try:
            with ui.Spinner("trivy k8s (all namespaces, vulnerabilities; first run downloads the DB)") as sp:
                p = subprocess.run([trivy, "k8s", "--report", "all", "--scanners", "vuln", "--format", "json", "--output", str(out), "--severity", "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN", "--timeout", "30m"],
                                   env=ctx.procenv(), capture_output=True, text=True, timeout=3600)
                if p.returncode == 0:
                    sp.done_text = "trivy finished"
        except subprocess.TimeoutExpired:
            _drop_empty(out)
            raise ui.Abort("trivy did not finish within an hour; check the cluster connection and re-run.")
        if _drop_empty(out):   # the name was reserved up front: an empty file means trivy wrote nothing
            raise ui.Abort(f"trivy failed (exit {p.returncode}): {tail_text(p.stderr or p.stdout, 600, lines=2) or 'no output'}")
        if p.returncode != 0:   # a report exists: some targets could not be scanned
            ui.warn(f"trivy reported errors: {tail_text(p.stderr or p.stdout, 300, lines=2)}")
            diagnostics.append(f"Trivy exited {p.returncode}; available results may be partial.")
        error_lines = _scanner_error_count((p.stderr or "") + "\n" + (p.stdout or ""))
        if error_lines:
            diagnostics.append(f"Trivy reported {error_lines} execution/permission/endpoint error message(s); coverage may be incomplete.")
        scanner_rc = p.returncode

        def walk(o, where=""):
            nonlocal observed
            if isinstance(o, dict):
                where = o.get("Target") or o.get("Name") or where
                if "Vulnerabilities" in o or ("Target" in o and any(k in o for k in ("Class", "Type", "Packages"))):
                    observed += 1
                for key in ("Error", "Errors"):
                    if o.get(key):
                        diagnostics.append(f"{where or 'scan target'}: {o[key]}")
                vulnerabilities = o.get("Vulnerabilities")
                if vulnerabilities is None:
                    vulnerabilities = []
                if not isinstance(vulnerabilities, list):
                    diagnostics.append(f"{where or 'scan target'}: vulnerability details are malformed.")
                    vulnerabilities = []
                for v in vulnerabilities:
                    if not isinstance(v, dict):
                        diagnostics.append(f"{where or 'scan target'}: an individual vulnerability could not be read.")
                        continue
                    s = str(v.get("Severity") or "UNKNOWN").upper()
                    s = s if s in sev else "UNKNOWN"
                    sev[s] += 1
                    findings.append(explain_severity({"id": str(v.get("VulnerabilityID") or ""), "status": "FAIL", "severity": s,
                                     "title": f"{v.get('VulnerabilityID')} {v.get('PkgName')} {v.get('InstalledVersion')}",
                                     "detail": f"{where} fixed: {v.get('FixedVersion') or '-'}", "resource": where,
                                     "remediation": f"Upgrade to {v['FixedVersion']}" if v.get("FixedVersion") else "No fixed version was reported; review vendor guidance and exposure.",
                                     "evidence": v}, v.get("Severity")))
                for k, v in o.items():
                    walk(v, o.get("Target") or o.get("Name") or where)
            elif isinstance(o, list):
                for v in o:
                    walk(v, where)
        try:
            walk(json.loads(out.read_text(), parse_constant=str))
        except ValueError:
            raise ui.Abort(f"trivy wrote an unreadable report ({out}): {tail_text(p.stderr or p.stdout, 400, lines=2)}")
    findings.sort(key=lambda f: list(sev).index(f["severity"]))  # stable: keeps the tool's order inside a severity
    total_bad = len(findings)
    if not observed:
        diagnostics.append("No readable image scan results were returned; workload image coverage could not be established.")
    if sev["UNKNOWN"]:
        diagnostics.append("Some vulnerabilities have unknown severity and require review.")
    report = {"run": run, "summary": {"source": source, "reports observed": observed, **{k.lower(): v for k, v in sev.items()}}, "findings": findings, "tool": source,
              "findings_total": total_bad, "scanner_rc": scanner_rc, "diagnostics": diagnostics,
              "failure_policy": "Critical vulnerabilities fail this scan. High, Medium and Low vulnerabilities remain findings even when the threshold passes. Missing, partial or unknown-severity evidence makes it incomplete.",
              "coverage_limits": ["Results cover reported/scanned images only; they do not prove every workload image was scanned or that cached operator reports are current."],
              "verdict": "FAIL" if sev["CRITICAL"] else "INCOMPLETE" if diagnostics else "PASS"}
    if raw:
        report["raw"] = str(raw)
    note = "The saved report retains every reported severity; failure threshold: Critical. Review High/Medium/Low findings too."
    path = save_report(ctx.env, "images", report)
    _panel(f"Workload vulnerabilities ({source}) · {ctx.env.id}", report["summary"], findings, path,
           verdict=f"{report['verdict']} - {sev['CRITICAL']} critical, {sev['HIGH']} high", note=note)
    return path


# ---------------------------------------------------------------- hosts (OpenSCAP)

def _ssg_version() -> str:
    try:
        with urllib.request.urlopen("https://api.github.com/repos/ComplianceAsCode/content/releases/latest", timeout=10,
                                    context=netutil.https_context()) as r:
            return json.load(r)["tag_name"].lstrip("v")
    except Exception:  # noqa: BLE001
        return SSG_FALLBACK


HOST_KINDS = ("bastion", "vpn", "k8s")


def parse_hosts(values) -> list[str]:
    """--host values as the host scans take them: bastion / vpn / k8s, comma-separated or repeated, any case or spacing.
    An unknown one stops the scan (exit 2) - it would otherwise scan nothing and blame the environment."""
    if values is None:
        return list(HOST_KINDS)
    out: list[str] = []
    for item in ([values] if isinstance(values, str) else values):
        for h in re.split(r"[,\s]+", str(item or "")):
            h = h.strip().lower()
            if not h:
                continue
            if h not in HOST_KINDS:
                near = difflib.get_close_matches(h, HOST_KINDS, n=1, cutoff=0.5)
                raise ui.Abort(f"Unknown --host '{h}'" + (f" (did you mean {near[0]}?)" if near else "")
                               + ": use bastion, vpn or k8s (comma-separated or repeated).", code=2)
            if h not in out:
                out.append(h)
    if not out:
        raise ui.Abort("--host names no host: use bastion, vpn or k8s (comma-separated or repeated).", code=2)
    return out


def _hosts(cloud, env, cfg: dict, outputs: dict, which: list[str], note: bool = True) -> list[tuple[str, str]]:
    """(name, ip) of the SSH-reachable hosts of the environment. note=False: the managed-nodes note was shown already."""
    out = []
    if "bastion" in which and outputs.get("bastion_public_ip"):
        out.append(("bastion", outputs["bastion_public_ip"]))
    if "vpn" in which and outputs.get("vpn_public_ip"):
        out.append(("vpn", outputs["vpn_public_ip"]))
    if "k8s" in which and cloud.local:
        out += [(f"{cfg['name']}-{cfg['env']}-cp{i + 1}", ip) for i, ip in enumerate(outputs.get("kubernetes_control_plane_ips") or [])]
        out += [(f"{cfg['name']}-{cfg['env']}-wk{i + 1}", ip) for i, ip in enumerate(outputs.get("kubernetes_worker_ips") or [])]
    elif "k8s" in which and not cloud.local and outputs.get("kubernetes_cluster_name") and note:
        ui.info("Managed Kubernetes nodes (EKS/GKE/AKS) are not SSH-reachable; the cloud provider hardens them. Use `cs scan cis` for the cluster.")
    return out


def no_host_message(cloud, env, cfg: dict, outputs: dict, which: list[str]) -> str:
    """Why there is nothing to scan: the environment has no host at all, or none of the kinds --host asked for."""
    have = _hosts(cloud, env, cfg, outputs, list(HOST_KINDS), note=False)
    if not have or set(which) >= set(HOST_KINDS):
        return f"No SSH-reachable host in {env.id} yet (bastion / vpn / local k8s nodes)."
    kinds = list(dict.fromkeys(n if n in ("bastion", "vpn") else "k8s" for n, _ in have))
    return (f"No SSH-reachable host for --host {','.join(which)} in {env.id} (it has: {', '.join(kinds)}); "
            f"scan those with --host {','.join(kinds)}.")


def _rerun_advice(cloud, env, profile: str) -> str:
    """The closing advice of an unreachable host in a scan: re-run the scan (re-provisioning is not what a scan needs)."""
    again = f"cs scan {'stig' if profile == 'stig' else 'host'} {cloud.key} --env {env.name}"
    return f"then re-run the scan ({again})."


def host(cloud, env, cfg: dict, outputs: dict, which: list[str], profile: str = "cis", note: bool = True,
         unreachable: dict | None = None) -> Path:
    """OpenSCAP scan of the environment's hosts. A host that does not answer over SSH is reported and the others are
    still scanned; `unreachable` (shared by `scan all`) remembers such hosts, so the next scan does not wait for them again."""
    which = parse_hosts(which)
    hosts = _hosts(cloud, env, cfg, outputs, which, note=note)
    if not hosts:
        raise ui.Abort(no_host_message(cloud, env, cfg, outputs, which))
    user, key = cloud.ssh_user(cfg), env.private_key_path(cfg)
    down = {} if unreachable is None else unreachable
    reachable = []
    for name, ip in hosts:
        if name in down:   # found unreachable earlier in this run: not waited for twice
            continue
        try:
            prov.Host(ip, user, key, name, env=env).wait(timeout=120, retry=_rerun_advice(cloud, env, profile))
            reachable.append((name, ip))
        except ui.Abort as e:
            down[name] = str(getattr(e, "msg", "") or e)
    missed = [(n, down[n]) for n, _ in hosts if n in down]
    if not reachable:
        if len(missed) == 1:
            raise ui.Abort(missed[0][1])
        raise ui.Abort("No host answered over SSH, so nothing was scanned: " + "  ·  ".join(f"{n}: {why}" for n, why in missed))
    for n, why in missed:
        ui.warn(f"{n} is not scanned: {why}")
    dest, run = claim_run_path(_reports_dir(env), "openscap-", "", run_stamp(), directory=True)   # never shared with a parallel scan
    inv = ["[all]"] + [f"{name} ansible_host={ip}" for name, ip in reachable] + ["", "[all:vars]", f"ansible_user={user}", f"ansible_ssh_private_key_file={json.dumps(str(key))}",
          prov.ansible_ssh_common_args(env),   # quoted: a workdir path may contain spaces
          "ansible_python_interpreter=/usr/bin/python3"]
    (dest / "inventory.ini").write_text("\n".join(inv) + "\n")
    ssg = _ssg_version()
    playbook = deps.ensure_local_ansible()
    cmd = [str(playbook), "-i", str(dest / "inventory.ini"), str(paths.REPO_ROOT / "ansible" / "scan.yml"),
           "-e", json.dumps({"scan_profile": profile, "ssg_version": ssg, "scan_dest": str(dest)})]
    ui.header(f"OpenSCAP {profile.upper()} scan of {', '.join(n for n, _ in reachable)}  (SCAP Security Guide {ssg})")
    audit.write("$ " + " ".join(cmd))
    # host keys stay pinned (checked against the environment's known_hosts); colour follows cloudseed's own output (NO_COLOR)
    child = subprocess.Popen(cmd, env=prov.ansible_env(),
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=str(paths.REPO_ROOT / "ansible"))
    for line in child.stdout:  # type: ignore[union-attr]
        audit.write(line)
        if not line.strip():
            continue
        if not line.startswith(("TASK", "PLAY", "ok:", "changed:", "skipping:")) or "fail" in line.lower() or "Evaluate" in line:
            print("  " + line, end="", flush=True)
    rc = child.wait()
    per_host = {}
    findings: list[dict] = []
    reached = {n for n, _ in reachable}
    for name, _ in hosts:
        if name not in reached:
            per_host[name] = {"error": "unreachable - " + ui.clip(down.get(name, "no SSH"), 160)}
            continue
        res = dest / name / "results.xml"
        if not res.exists():
            try:   # a host without content for this profile (e.g. no DISA STIG for AL2023/Debian 12) is not a failure
                skipped = json.loads((dest / name / "meta.json").read_text()).get("skipped")
            except (OSError, ValueError, AttributeError):
                skipped = None
            per_host[name] = {"error": f"n/a - {skipped}", "skipped": skipped} if skipped else {"error": "no results (see the log above)"}
            continue
        per_host[name] = _parse_xccdf(res)
        for rule in per_host[name]["failed_rules"]:
            findings.append({"status": "FAIL", "severity": rule["severity"].upper(), "title": f"{name}: {rule['title']}",
                             "detail": rule.get("detail") or rule["id"], "id": rule["id"],
                             "remediation": rule.get("remediation") or "Review this rule in the host's OpenSCAP HTML report and the selected profile."})
        for rule in per_host[name].get("unresolved_rules", []):
            findings.append({"status": "UNKNOWN", "severity": rule["severity"].upper(), "title": f"{name}: {rule['title']}",
                             "detail": rule["detail"], "id": rule["id"], "remediation": rule["remediation"]})
        meta = dest / name / "meta.json"
        if meta.exists():
            try:
                metadata = json.loads(meta.read_text())
                if not isinstance(metadata, dict):
                    raise ValueError("metadata is not an object")
                per_host[name]["meta"] = metadata
            except (OSError, ValueError):
                per_host[name]["metadata_error"] = "Host profile metadata is unreadable."
    findings.sort(key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].index(f["severity"]) if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") else 9)
    scanned = [r for r in per_host.values() if "score" in r and not r.get("parse_error")]
    not_applicable = [r for r in per_host.values() if r.get("skipped")]   # no content for this profile: n/a, not an error
    # numeric totals (summed over hosts) so dashboards can tell pass from fail; hosts without results are counted, never "clean"
    result_kinds = ("pass", "fail", "notapplicable", "notchecked", "error", "unknown", "informational", "notselected")
    excluded_kinds = ("notapplicable", "informational", "notselected")
    summary = {"profile": profile, "ssg": ssg, "pass": sum(r["pass"] for r in scanned), "fail": sum(r["fail"] for r in scanned)}
    summary["unknown"] = sum(r.get("notchecked", 0) + r.get("error", 0) + r.get("unknown", 0)
                             + int(not sum(r.get(k, 0) for k in result_kinds))
                             + int(bool(r.get("metadata_error"))) for r in scanned)
    # XCCDF informational rules were checked for information; notselected rules are outside this profile.
    # Keep these visible without treating an explicit exclusion as missing evidence.
    for kind in excluded_kinds:
        summary[kind] = sum(r.get(kind, 0) for r in scanned)
    if len(scanned) + len(not_applicable) < len(per_host):
        summary["errors"] = len(per_host) - len(scanned) - len(not_applicable)
    for name, r in per_host.items():
        problem = r.get("parse_error") or r.get("metadata_error") or (r.get("error") if isinstance(r.get("error"), str) and not r.get("skipped") else None)
        empty = "score" in r and not sum(r.get(k, 0) for k in result_kinds)
        if problem or empty:
            findings.append({"status": "UNKNOWN", "severity": "MEDIUM", "title": f"{name}: incomplete host scan",
                             "detail": problem or "The result contains no evaluated applicable checks.",
                             "remediation": "Inspect the scan log and raw host report, resolve collection or profile errors, then rerun the scan."})
        summary[name] = (f"score {r['score']}%  pass {r['pass']}  fail {r['fail']}  n/a {r['notapplicable']}  ({str(r.get('meta', {}).get('profile', '?')).split('_profile_')[-1]})"
                         if "score" in r and not r.get("parse_error") else r.get("parse_error") or r["error"])
    if rc:
        findings.append({"status": "UNKNOWN", "severity": "MEDIUM", "title": "OpenSCAP collection did not complete successfully",
                         "detail": f"The Ansible playbook exited {rc}; available host findings are retained, but coverage may be partial.",
                         "remediation": "Inspect the Ansible log, resolve execution errors and rerun the scan."})
    report = {"run": run, "summary": summary, "findings": findings, "hosts": per_host, "tool": "openscap", "raw": str(dest), "ansible_rc": rc,
              "coverage_limits": ["Only the selected reachable hosts and available profile rules were evaluated.",
                                  "Manual, not-checked, unknown or error results require review; no-content hosts are explicitly N/A.",
                                  "Informational and notselected rules do not block completed checks; a scope containing only these or notapplicable rules is N/A.",
                                  "Scores alone do not establish compliance; inspect every failed rule and unresolved observation."]}
    all_na = rc == 0 and bool(per_host) and not summary.get("errors") and not summary["unknown"] and \
        len(not_applicable) + sum(sum(r.get(k, 0) for k in excluded_kinds) > 0 and r["pass"] == 0 and r["fail"] == 0 for r in scanned) == len(per_host)
    incomplete = rc != 0 or bool(summary.get("errors") or summary["unknown"]) or not scanned
    report["verdict"] = "N/A" if all_na else "FAIL" if summary["fail"] else "INCOMPLETE" if incomplete else "PASS"
    kind = "stig-host" if profile == "stig" else f"host-{profile}"
    path = save_report(env, kind, report)
    if all_na:
        verdict = f"N/A - no applicable compliance checks for {'DISA STIG' if profile == 'stig' else profile.upper()} on the selected hosts (excluded/informational rules or unavailable profile)"
    elif not scanned:   # nothing was evaluated: no rule count, no score, no HTML report to point at
        verdict = f"INCOMPLETE - no host could be scanned ({summary.get('errors', 0)} without results; see the log above)"
    else:
        worst = min(r["score"] for r in scanned)
        verdict = (f"{report['verdict']} - {summary['fail']} failed rules, {summary['unknown']} unresolved checks, lowest score {worst}%"
                   + (f"; {summary['errors']} host(s) not scanned" if summary.get("errors") else "")
                   + f"  (HTML reports: {dest}/<host>/report.html)")
    _panel(f"Host {profile.upper()} benchmark (OpenSCAP) · {env.id}", summary, findings, path, verdict=verdict)
    return path


def _parse_xccdf(path: Path) -> dict:
    ns = {"x": "http://checklists.nist.gov/xccdf/1.2"}
    counts = {"pass": 0, "fail": 0, "notapplicable": 0, "notchecked": 0, "error": 0, "informational": 0, "notselected": 0, "unknown": 0}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        problem = ("The XCCDF result contains malformed XML." if isinstance(exc, ET.ParseError) else
                   "The XCCDF result file does not exist." if isinstance(exc, FileNotFoundError) else
                   "Permission was denied while reading the XCCDF result." if isinstance(exc, PermissionError) else
                   f"The XCCDF result could not be read (filesystem error {exc.errno}).")
        return {**counts, "score": 0.0, "failed_rules": [], "unresolved_rules": [], "parse_error": problem}
    tr = root.find(".//x:TestResult", ns)
    tr = root if tr is None else tr
    failed, unresolved = [], []
    rules = {r.get("id"): r for r in root.findall(".//x:Rule", ns)}
    def text_of(element):
        return " ".join("".join(element.itertext()).split()) if element is not None else ""
    for rr in tr.findall("x:rule-result", ns):
        res = (rr.findtext("x:result", default="unknown", namespaces=ns) or "unknown").strip().lower()
        counts[res if res in counts else "unknown"] += 1
        if res == "fail" or res not in ("pass", "notapplicable", "notselected", "informational"):
            rid = rr.get("idref", "")
            rule = rules.get(rid)
            title = text_of(rule.find("x:title", ns)) if rule is not None else ""
            remediation = text_of(rule.find("x:fixtext", ns)) if rule is not None else ""
            detail = " · ".join(text_of(m) for m in rr.findall("x:message", ns))
            reason = {"notchecked": "OpenSCAP did not execute this check; its automated result cannot establish compliance.",
                      "error": "OpenSCAP reported a check execution error.",
                      "unknown": "OpenSCAP supplied no determined compliance result for this check."}.get(res, "")
            if not reason and res != "fail":
                reason = "OpenSCAP supplied an unsupported result status; the check outcome cannot be determined."
            if reason:
                reason += " Scanner messages are included below." if detail else " No further cause was supplied in the XCCDF messages."
            row = {"id": rid, "severity": rr.get("severity", "unknown"),
                   "title": title or rid.split("_rule_")[-1].replace("_", " "),
                   "detail": f"{rid}: result={res}" + (f" · {reason}" if reason else "") + (f" · {detail}" if detail else ""),
                   "remediation": ("Inspect this rule's XCCDF messages and scan log; complete the profile's manual assessment or restore its check prerequisites, then rerun. " if reason else "")
                                  + (remediation or "Review this rule in the host's OpenSCAP HTML report and the selected profile.")}
            (failed if res == "fail" else unresolved).append(row)
    score_el = tr.find("x:score", ns)
    try:
        score = round(float(score_el.text), 1) if score_el is not None and score_el.text else 0.0
        if not 0 <= score <= 100:
            raise ValueError("invalid score")
    except (ValueError, OverflowError):
        counts["unknown"] += 1
        score = 0.0
        unresolved.append({"id": "xccdf.score", "severity": "unknown", "title": "Invalid XCCDF score",
                           "detail": "The scanner score is invalid; rule observations are retained.",
                           "remediation": "Inspect the raw XCCDF result and rerun the scanner."})
    return {**counts, "score": score, "failed_rules": failed, "unresolved_rules": unresolved}


# ---------------------------------------------------------------- cloud (prowler)

PROWLER_SPEC = "prowler>=5,<6"
PROWLER_PYTHON = ((3, 10), (3, 14))  # prowler 5 requires Python >= 3.10, < 3.14 (pip would silently pick the broken 3.x line otherwise)


def _py_version(exe: str) -> tuple[int, int] | None:
    try:
        out = subprocess.run([exe, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"], capture_output=True, text=True, timeout=30).stdout.strip()
        major, minor = out.split(".")
        return int(major), int(minor)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def _supported(v: tuple[int, int] | None) -> bool:
    return bool(v) and PROWLER_PYTHON[0] <= v < PROWLER_PYTHON[1]  # type: ignore[operator]


def _prowler_python() -> tuple[str, tuple[int, int]]:
    """An interpreter prowler 5 supports: this one, else python3.13 ... python3.10 / python3 on PATH (never the bundle binary)."""
    cands = [] if paths.IS_BUNDLE else [sys.executable]
    cands += [p for p in (shutil.which(n) for n in ("python3.13", "python3.12", "python3.11", "python3.10", "python3")) if p]
    for exe in dict.fromkeys(cands):
        v = tuple(sys.version_info[:2]) if (exe == sys.executable and not paths.IS_BUNDLE) else _py_version(exe)
        if _supported(v):  # type: ignore[arg-type]
            return exe, v  # type: ignore[return-value]
    lo, hi = PROWLER_PYTHON
    raise ui.Abort(f"prowler 5 needs Python {lo[0]}.{lo[1]}-{hi[0]}.{hi[1] - 1} and none was found on PATH (cloudseed runs on "
                   f"{sys.version.split()[0]}). Install one (macOS: brew install python@3.13 · Debian/Ubuntu: apt install python3.12) and re-run.")


def _prowler_problem(venv: Path) -> str:
    """Why an existing prowler venv cannot be used ('' when it is fine)."""
    py = venv / "bin" / "python"
    v = _py_version(str(py)) if py.exists() else None
    if not _supported(v):
        return f"it uses Python {'.'.join(map(str, v)) if v else '?'}, which prowler 5 does not support"
    try:
        ver = subprocess.run([str(py), "-c", "import importlib.metadata as m; print(m.version('prowler'))"], capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        ver = ""
    if not ver.startswith("5."):
        return f"it holds prowler {ver or '(unknown)'}, not 5.x"
    return ""


def _prowler() -> str:
    venv = paths.HOME / "venv-prowler"
    binary = venv / "bin" / "prowler"
    why = ""
    if binary.exists():
        if not deps.venv_usable(venv) or not deps._shebang_ok(binary):
            # created by another system (e.g. inside the container runtime) or its Python was removed since
            why = "its Python does not run on this machine"
        else:
            why = _prowler_problem(venv)
        if not why:
            return str(binary)
    elif venv.exists():  # a half-built venv from an interrupted install
        why = "an earlier install did not finish"
    _no_install_in_agent_session(f"The prowler venv {venv} is unusable ({why})" if why else "prowler 5 is not installed",
                                 f"run `cs scan cloud` once in your own terminal: it builds {venv} with prowler 5")
    if venv.exists():
        if binary.exists():
            ui.warn(f"Rebuilding {venv}: {why}.")
        shutil.rmtree(venv, ignore_errors=True)
    py, v = _prowler_python()
    err = ""
    with ui.Spinner(f"Installing prowler 5 into ~/.cloudseed/venv-prowler with Python {v[0]}.{v[1]} (first time only; a few minutes)") as sp:
        try:
            subprocess.run([py, "-m", "venv", str(venv)], check=True, capture_output=True, text=True, timeout=300)
            r = subprocess.run([str(venv / "bin" / "pip"), "install", "--quiet", "--upgrade", "pip", PROWLER_SPEC], capture_output=True, text=True, timeout=3600)
            if r.returncode != 0:
                err = tail_text(r.stderr or r.stdout, 600, lines=3)
        except subprocess.CalledProcessError as e:
            err = f"python -m venv failed: {tail_text(e.stderr or e.stdout, 400, lines=3)}"
        except (OSError, subprocess.TimeoutExpired) as e:
            err = str(e)
        if not err and binary.exists():
            sp.done_text = f"prowler installed (Python {v[0]}.{v[1]})"
    if err or not binary.exists():
        shutil.rmtree(venv, ignore_errors=True)
        raise ui.Abort(f"prowler install failed ({py}, Python {v[0]}.{v[1]}): {err or 'no prowler binary after pip install'}")
    return str(binary)


def _cis_version(name: str) -> tuple[int, ...]:
    """cis_10.0_aws -> (10, 0): frameworks compare by version number, not as strings."""
    parts = name.split("_")
    return tuple(int(x) for x in parts[1].split(".") if x.isdigit()) if len(parts) > 2 else ()


_LOGIN_HINTS = {"aws": "log in: aws configure  (or aws sso login --profile <profile>)",
                "gcp": "log in: gcloud auth application-default login  (prowler uses Application Default Credentials)",
                "azure": "log in: az login  (or export ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_TENANT_ID for a service principal)"}


def _prowler_error(r: subprocess.CompletedProcess | None, provider: str) -> str:
    text = _cloud_safe_output(((r.stderr or "") + "\n" + (r.stdout or "")) if r is not None else "")
    lines = [ln.strip() for ln in text.splitlines() if re.search(r"\b(CRITICAL|ERROR)\b", ln)]
    msg = ui.clip(" | ".join(lines[-4:]), 800) if lines else tail_text(text, 800, lines=3)
    if re.search(r"credential|NoCredentials|DefaultCredentialsError|Unable to locate|az login|AADSTS|not logged in|expired", text, re.I):
        msg += f". {_LOGIN_HINTS.get(provider, '')}"
    return msg or "no output"


_CLOUD_DIAGNOSTIC_CHAR_LIMIT = 1024 * 1024
_CLOUD_ERROR_EXAMPLE_LIMIT = 8
_CLOUD_ERROR_EXAMPLE_CHARS = 1200


def _cloud_safe_output(output: str | bytes | None) -> str:
    """Redact the entire stream before taking excerpts, including multiline keys."""
    if isinstance(output, bytes):  # TimeoutExpired may retain bytes even with text=True.
        output = output.decode("utf-8", errors="replace")
    clean = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", output or "")
    clean = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", clean)
    return secrets.redact(clean, auth=True)


def _cloud_error_lines(clean: str) -> list[tuple[int, str]]:
    """Prowler log levels/exception names, excluding literal zero-error counters.

    Prowler 5 uses `ERROR: message` or JSON `"level": "ERROR"`. A prose
    reference to errors, or an `error=0` counter, does not establish a gap.
    """
    found = []
    for number, line in enumerate(clean.splitlines(), 1):
        counted = re.sub(r"\b(?:errors?|criticals?|fatals?)[\"']?\s*[:=]\s*(?:0+(?:\.0+)?|false|none|null)\b", "", line, flags=re.I)
        level = re.search(r"(?:^|\[\s*)(?:ERROR|CRITICAL|FATAL)\b|\b(?:ERROR|CRITICAL|FATAL)\s*:|"
                          r"[\"']level[\"']\s*:\s*[\"'](?:ERROR|CRITICAL|FATAL)[\"']", counted, re.I)
        failure = re.search(r"\b(?:AccessDenied\w*|Unauthorized\w*|Forbidden|EndpointConnectionError)\b|"
                            r"Could not connect to the endpoint URL|\baccess denied\b", counted, re.I)
        if level or failure:
            found.append((number, line.strip()))
    return found


def _cloud_output_artifact(env, outdir: Path, *, stdout=None, stderr=None, timed_out: bool = False) -> dict:
    """Persist bounded, redacted output even when no normalized report is produced."""
    clean = "[stderr]\n" + _cloud_safe_output(stderr) + "\n[stdout]\n" + _cloud_safe_output(stdout)
    total = len(clean)
    saved = min(total, _CLOUD_DIAGNOSTIC_CHAR_LIMIT)
    omitted = total - saved
    if omitted:
        head = saved // 2
        clean = clean[:head] + f"\n[Cloudseed omitted {omitted} redacted characters from the middle of scanner output.]\n" + clean[-(saved - head):]
    target = outdir / "prowler.log"
    header = ("Cloudseed Prowler diagnostic output (redacted; saved evidence is untrusted text).\n"
              f"Collection timed out: {'yes' if timed_out else 'no'}. Omitted characters: {omitted}.\n\n")
    paths.atomic_write(target, header + clean + "\n")
    _claimed(target)
    return {"output_artifact": str(target.relative_to(env.dir)), "output_redacted": True,
            "output_total_characters": total, "output_saved_characters": saved,
            "output_omitted_characters": omitted, "output_complete": not omitted}


def _azure_auth(env_: dict) -> list[str]:
    """prowler's Azure login, from the credentials cloudseed documents. The ARM_* service principal Terraform uses is
    handed to prowler as the AZURE_* variables it reads (in the child's environment only; ones already set win)."""
    for arm, azure in (("ARM_CLIENT_ID", "AZURE_CLIENT_ID"), ("ARM_CLIENT_SECRET", "AZURE_CLIENT_SECRET"), ("ARM_TENANT_ID", "AZURE_TENANT_ID")):
        if env_.get(arm) and not env_.get(azure):
            env_[azure] = env_[arm]
    if all(env_.get(k) for k in ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID")):
        return ["--sp-env-auth"]
    if str(env_.get("ARM_USE_MSI", "")).strip().lower() in ("1", "true", "yes"):
        return ["--managed-identity-auth"]
    az = deps.find("az")
    if az:
        # Merely having Azure CLI installed does not mean it has a login. Refuse
        # before downloading Prowler or starting a scan against an empty profile.
        try:
            account = subprocess.run([az, "account", "show", "-o", "json"], env=env_,
                                     capture_output=True, text=True, timeout=15)
            if account.returncode == 0 and json.loads(account.stdout or "{}").get("id"):
                return ["--az-cli-auth"]
        except (OSError, subprocess.SubprocessError, ValueError, AttributeError):
            pass
    raise ui.Abort("prowler needs Azure credentials: az login (cloudseed install az), or a service principal in ARM_CLIENT_ID / "
                   "ARM_CLIENT_SECRET / ARM_TENANT_ID (certificate or OIDC logins need az here).", code=2)


def cloud_verdict(report: dict) -> str:
    """Consistent saved cloud verdict for CLI/UI, including older severity-only reports."""
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    diagnostics = report.get("diagnostics") if isinstance(report.get("diagnostics"), dict) else {}
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    counts = {k: v for k, v in summary.items() if type(v) is int and v >= 0}
    statuses = {str(f.get("status", "")).upper() for f in findings if isinstance(f, dict)}
    if (report.get("verdict") == "FAIL" or counts.get("fail", 0) or "FAIL" in statuses or
            any(v for k, v in counts.items() if k.startswith("failed "))):
        return "FAIL"
    invalid_counts = any(k not in counts for k in ("pass", "fail")) or any(
        k not in counts for k in summary if k in ("manual", "unknown") or k.startswith("failed "))
    if (invalid_counts or report.get("verdict") == "INCOMPLETE" or counts.get("manual", 0) or counts.get("unknown", 0) or
            statuses - {"PASS", "FAIL"} or
            diagnostics.get("process_exit_code", 0) != 0 or diagnostics.get("error_lines", 0) != 0):
        return "INCOMPLETE"
    return "PASS" if counts.get("pass", 0) > 0 else "INCOMPLETE"


def _cloud_results(data, *, returncode: int = 0, output: str = "") -> dict:
    """Normalize Prowler OCSF observations without turning missing checks into a pass.

    OCSF's `status` is the finding lifecycle (often New), not its check result. Preserve
    every non-passing observation, including manual checks, with the actual explanation.
    Counts are resource/check observations, not distinct benchmark requirements.
    """
    if not isinstance(data, list):
        raise ui.Abort("prowler wrote an invalid report: expected an OCSF list of findings.")
    counts = {s: 0 for s in ("PASS", "FAIL", "MANUAL", "UNKNOWN")}
    severity = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN")}
    findings, checks = [], set()
    obj = lambda value: value if isinstance(value, dict) else {}
    string = lambda value: value if isinstance(value, str) else ""
    for index, record in enumerate(data, 1):
        row = obj(record)
        # Legacy fixtures/exporters may use PASS/FAIL directly as status; lifecycle
        # values and new/unsupported result codes must remain unassessed.
        raw_status = row.get("status_code") or row.get("status")
        status = string(raw_status).upper()
        status = status if status in counts else "UNKNOWN"
        info = obj(row.get("finding_info"))
        check_id = string(obj(info.get("analytic")).get("uid")).strip()
        unidentified_pass = status == "PASS" and not check_id
        if unidentified_pass:
            status = "UNKNOWN"
        counts[status] += 1
        if check_id:
            checks.add(check_id)
        sev = string(row.get("severity")).upper()
        sev = sev if sev in severity else "UNKNOWN"
        if status == "FAIL":
            severity[sev] += 1
        if status == "PASS":
            continue
        resources = row.get("resources")
        resources = resources if isinstance(resources, list) else []
        resource_ids = [string(r.get("uid")) for r in resources if isinstance(r, dict) and string(r.get("uid"))]
        remediation = obj(row.get("remediation"))
        refs = remediation.get("references")
        reason = ""
        if status == "UNKNOWN":
            if unidentified_pass:
                reason = "Prowler reported PASS but supplied no finding_info.analytic.uid, so the benchmark check cannot be identified."
            elif not isinstance(record, dict):
                reason = f"Observation {index} is not an OCSF object, so its check result cannot be read."
            elif not raw_status:
                reason = "Prowler supplied no check result (status_code or recognized legacy status)."
            elif not row.get("status_code") and string(raw_status).upper() not in counts:
                reason = "Prowler supplied a finding lifecycle status but no recognized check result; lifecycle status does not establish compliance."
            elif string(raw_status).upper() == "UNKNOWN":
                reason = "Prowler explicitly marked this check result UNKNOWN."
            else:
                reason = "Prowler supplied an unsupported check result; Cloudseed cannot classify it as pass, fail or manual."
        elif status == "MANUAL":
            reason = "Prowler requires manual verification for this control; this scan did not establish a pass or fail."
        explanation = string(row.get("status_detail")) or string(row.get("message"))
        next_step = string(remediation.get("desc"))
        if status == "UNKNOWN":
            next_step = "Inspect this observation in the raw Prowler report and confirm the scanner's result format; resolve the reported cause and rerun the cloud scan." + (" Scanner guidance: " + next_step if next_step else "")
        elif status == "MANUAL" and not next_step:
            next_step = "Review the named control and resources against its provider guidance and record the required manual evidence."
        findings.append({"id": check_id, "status": status, "severity": sev,
                         "title": string(info.get("title")) or check_id or "Unrecognized Prowler observation",
                         "detail": ((reason + (" Scanner explanation: " + explanation if explanation else "")) if reason else explanation) or
                                   "The scanner supplied no result explanation; inspect the raw report.",
                         **({"reason": reason, "scanner_status": raw_status} if reason else {}),
                         "resource": resource_ids[0] if resource_ids else "", "resources": resource_ids,
                         "region": string(obj(row.get("cloud")).get("region")),
                         "remediation": next_step,
                         "references": [r for r in refs if isinstance(r, str) and r.startswith("https://")] if isinstance(refs, list) else []})
    order = {s: i for i, s in enumerate(severity)}
    findings.sort(key=lambda f: (f["status"] != "FAIL", order[f["severity"]], f["id"], f["resource"]))
    # A successful process can still log skipped services/permission errors. Keep
    # safely redacted examples so a reviewer can explain the actual recorded cause.
    clean = _cloud_safe_output(output)
    errors = _cloud_error_lines(clean)
    error_lines = len(errors)
    examples = [{"line": line, "text": text[:_CLOUD_ERROR_EXAMPLE_CHARS],
                 "omitted_characters": max(0, len(text) - _CLOUD_ERROR_EXAMPLE_CHARS)}
                for line, text in errors[:_CLOUD_ERROR_EXAMPLE_LIMIT]]
    diagnostics = {"process_exit_code": returncode, "error_lines": error_lines, "error_examples": examples,
                   "error_examples_omitted": max(0, error_lines - len(examples)),
                   "error_examples_redacted": True}
    reasons = []
    if not data:
        reasons.append("Prowler returned zero observations; no applicable check result was available to assess.")
    if returncode:
        reasons.append(f"Prowler exited with code {returncode}; collection did not complete successfully.")
    if error_lines:
        error_text = "\n".join(text for _, text in errors)
        denied = bool(re.search(r"\b(?:AccessDenied\w*|Unauthorized\w*|Forbidden)\b|\baccess denied\b", error_text, re.I))
        endpoint = bool(re.search(r"EndpointConnectionError|Could not connect to the endpoint URL", error_text, re.I))
        reasons.append(f"Scanner output contains {error_lines} error line(s)" +
                       (" including permission/access denial" if denied else "") +
                       (" and unreachable service endpoints" if denied and endpoint else " including unreachable service endpoints" if endpoint else "") +
                       "; affected checks may be absent from this report.")
    if counts["UNKNOWN"]:
        reasons.append(f"{counts['UNKNOWN']} observation(s) have no recognized result; each finding explains the missing or unsupported field.")
    if counts["MANUAL"]:
        reasons.append(f"{counts['MANUAL']} control observation(s) require manual verification; review their individual explanations and guidance.")
    if reasons:
        diagnostics["reason"] = " ".join(reasons)
        diagnostics["next_step"] = "Review the recorded error examples, saved diagnostic output and finding reasons; correct scanner access, connectivity or result-format problems if reported, and collect any required manual evidence before reassessing. Do not infer an unrecorded cause."
    incomplete = bool(returncode or error_lines or counts["MANUAL"] or counts["UNKNOWN"] or not data)
    verdict = "FAIL" if counts["FAIL"] else "INCOMPLETE" if incomplete else "PASS"
    return {"summary": {**{k.lower(): v for k, v in counts.items()},
                        **{"failed " + k.lower(): v for k, v in severity.items()},
                        "observations": len(data), "identified checks": len(checks)},
            "findings": findings, "diagnostics": diagnostics,
            "failure_policy": "Any failed observation fails the cloud benchmark, regardless of severity. With no failures, required manual reviews, unknown results, empty output or detected collection errors make it incomplete.",
            "verdict": verdict}


def cloud_scan(cloud, env, cfg: dict, framework: str | None = None) -> Path:
    from . import services
    if cloud.local:
        raise ui.Abort("There is no cloud account to scan for a local VMware environment (try: cs scan host).")
    provider = cloud.key
    # the environment's own endpoints and credentials: FIPS endpoints in an AWS FIPS environment (like every other AWS
    # call it makes), its AWS profile, and on Azure the ARM_* service principal mapped to what prowler reads
    env_ = dict(services.cloud_cli_env(provider, cfg))
    secrets.register(*(value for key, value in env_.items() if secrets.is_secret_env(key)))
    if cfg["vars"].get("profile"):
        env_["AWS_PROFILE"] = cfg["vars"]["profile"]
    fips_regions: list[str] = []
    if services._aws_fips(provider, cfg):
        # prowler sweeps every region by default; most services have no <svc>-fips endpoint outside the FIPS regions, and
        # the calls that cannot connect would silently drop out of the report - so it scans the environment's region
        fips_regions = [str(cfg.get("region") or "us-east-1")]
    auth = _azure_auth(env_) if provider == "azure" else []
    prowler = _prowler()
    if not framework:
        try:
            lp = subprocess.run([prowler, provider, "--list-compliance"], env=env_, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            raise ui.Abort("prowler --list-compliance did not answer within 5 minutes.")
        if lp.returncode != 0:
            raise ui.Abort(f"prowler cannot list its compliance frameworks: {_prowler_error(lp, provider)}. "
                           f"If it keeps failing, remove {paths.HOME / 'venv-prowler'} and re-run to reinstall it.")
        cis_ = sorted(set(re.findall(r"\b(cis_[0-9.]+_%s)\b" % provider, lp.stdout)), key=_cis_version)
        framework = cis_[-1] if cis_ else ""
        if framework:
            ui.info(f"Using the newest CIS framework prowler has for {provider}: {framework}")
    outdir, run = claim_run_path(_reports_dir(env), "prowler-", "", run_stamp(), directory=True)
    cmd = [prowler, provider, "-M", "json-ocsf", "-o", str(outdir), "-F", "prowler", "--no-banner", "-z"]
    if framework:
        cmd += ["--compliance", framework]
    if provider == "gcp" and cfg["vars"].get("project_id"):
        cmd += ["--project-ids", cfg["vars"]["project_id"]]
    if fips_regions:
        cmd += ["-f", *fips_regions]
    if provider == "azure":
        cmd += auth
        if cfg["vars"].get("subscription_id"):  # prowler scans every subscription it can see unless told which one
            cmd += ["--subscription-ids", cfg["vars"]["subscription_id"]]
    r = None
    try:
        with ui.Spinner(f"prowler {provider} {framework or 'all checks'} (this takes a while)") as sp:
            r = subprocess.run(cmd, env=env_, capture_output=True, text=True, timeout=7200)
            if r.returncode == 0:  # -z: failed checks still exit 0, so anything else is a real error
                sp.done_text = "prowler finished"
    except subprocess.TimeoutExpired as exc:
        diagnostics = _cloud_output_artifact(env, outdir, stdout=exc.stdout, stderr=exc.stderr, timed_out=True)
        raise ui.Abort("prowler did not finish within 2 hours; re-run with a narrower framework: cs scan cloud --framework <name>. "
                       f"Redacted diagnostic evidence: {diagnostics['output_artifact']}")
    output_evidence = _cloud_output_artifact(env, outdir, stdout=r.stdout if r else None, stderr=r.stderr if r else None)
    ocsf = next(iter(outdir.glob("prowler*.ocsf.json")), None)
    if not ocsf:
        raise ui.Abort(f"prowler produced no report (exit {r.returncode if r else '?'}): {_prowler_error(r, provider)}. "
                       f"Redacted diagnostic evidence: {output_evidence['output_artifact']}")
    if r is not None and r.returncode != 0:
        ui.warn(f"prowler exited {r.returncode}: {_prowler_error(r, provider)}")
    out_text = ((r.stderr or "") + "\n" + (r.stdout or "")) if r is not None else ""
    unreachable = len(set(re.findall(r'Could not connect to the endpoint URL:\s*"?([^"\s]+)', out_text))) or \
        (1 if "EndpointConnectionError" in out_text else 0)
    if unreachable:
        ui.warn(f"prowler could not reach {unreachable} service endpoint(s)" + (" (services without a FIPS endpoint in this region)" if fips_regions else "")
                + "; their checks are missing from the report.")
    try:
        data = json.loads(ocsf.read_text())
    except ValueError:
        raise ui.Abort(f"prowler wrote an unreadable report: {ocsf}")
    result = _cloud_results(data, returncode=r.returncode if r is not None else 1, output=out_text)
    result["diagnostics"].update(output_evidence)
    scope = {"aws": "AWS account accessible to the selected credentials; includes resources outside this Cloudseed environment",
             "gcp": "Selected GCP project(s); includes resources outside this Cloudseed environment",
             "azure": "Selected Azure subscription(s); includes resources outside this Cloudseed environment"}[provider]
    if provider == "aws":
        scope += "; environment region only" if fips_regions else "; all regions scanned by Prowler and global services"
    report = {**result, "schema_version": 1, "cloud": provider, "env": env.id, "run": run,
              "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "scope": scope,
              "summary": {"provider": provider, "framework": framework or "all checks", **result["summary"]},
              "tool": "prowler", "raw": str(outdir),
              "coverage_limits": [scope + ".",
                  "Counts are resource/check observations, not distinct CIS requirements; manual checks need review.",
                  "PASS means no failed or manual/unknown observations and no detected execution errors. It does not prove all permissions, services or framework requirements were covered.",
                  "Prowler titles describe the desired control; the finding detail explains the observed failure.",
                  "A permissive network ACL alone does not prove public reachability; also review routing, public addresses and security groups."],
              "hint": "Review every failed and manual finding and its resource scope. Resolve scanner errors before trusting coverage; rerun scan architecture afterward to use this saved evidence."}
    if provider == "azure" and cfg["vars"].get("subscription_id"):
        report["summary"]["subscription"] = cfg["vars"]["subscription_id"]
    if fips_regions:
        report["summary"]["endpoints"] = f"FIPS (regions: {', '.join(fips_regions)})"
    if result["diagnostics"]["error_lines"] or result["diagnostics"]["process_exit_code"]:
        report["coverage_limits"].append("Scanner execution errors were detected; some checks may be missing even when other findings are valid.")
    path = save_report(env, "cloud", report)
    _panel(f"Cloud benchmark (prowler {framework or 'all'}) · {env.id}", report["summary"], report["findings"], path,
           verdict=f"{report['verdict']} - {report['summary']['fail']} failed observations", note=scope, hint=report["hint"])
    return path


# ---------------------------------------------------------------- FIPS verification

GCP_PRO_FIPS_IMAGE = "ubuntu-os-pro-cloud/ubuntu-pro-fips-2204-lts"
GCP_DEFAULT_BASTION_IMAGE = "debian-cloud/debian-12"


def fips_env(cfg: dict, outputs: dict | None = None) -> bool:
    """Whether the environment was created in FIPS mode (config vars or the stack's fips_mode output)."""
    return bool((cfg.get("vars") or {}).get("fips_mode")) or bool((outputs or {}).get("fips_mode"))


def _gcp_bastion_image(env, cfg: dict, wanted: bool) -> str:
    """The image Terraform boots the GCP bastion from (same rule as terraform/gcp/main.tf)."""
    try:
        rendered = json.loads((env.stack_dir / "main.tf.json").read_text())["module"]["stack"]
    except (OSError, ValueError, KeyError, TypeError):
        rendered = {}
    v = {**(cfg.get("vars") or {}), **(cfg.get("extra_vars") or {})}
    img = str(rendered.get("bastion_image") or v.get("bastion_image") or GCP_DEFAULT_BASTION_IMAGE)
    return GCP_PRO_FIPS_IMAGE if wanted and img == GCP_DEFAULT_BASTION_IMAGE else img


def _gcp_vpn_image(wanted: bool) -> str | None:
    """The GCP VPN image, derived from the module Terraform applies (None when it cannot be told statically)."""
    try:
        text = (paths.REPO_ROOT / "terraform" / "gcp" / "modules" / "vpn" / "main.tf").read_text()
    except OSError:
        return None
    m = re.search(r"^\s*image\s*=\s*(.+)$", text, re.M)
    if not m:
        return None
    expr = m.group(1)
    quoted = re.findall(r'"([^"]+)"', expr)
    if "?" in expr and "fips" in expr and len(quoted) >= 2:  # var.fips_mode ? "<FIPS image>" : "<plain image>"
        return quoted[0] if wanted else quoted[1]
    return quoted[0] if len(quoted) == 1 and "?" not in expr else None


def _ssh_key_check(pub: str, cloud_key: str) -> tuple[bool | None, str]:
    """(ok, detail) of the environment's SSH key in FIPS mode, by the same rules setup applies (netutil.ssh_key_problem):
    no ed25519, RSA >= 3072 bits, and a type the cloud accepts (EC2 key pairs and Azure VMs refuse ECDSA)."""
    if not pub.strip():
        return None, "no key recorded"
    algo, bits = netutil.ssh_key_info(pub)
    if not algo:   # not a parseable key line: judge the type it names (its size cannot be checked)
        algo = pub.split()[0][:40]
        if algo == "ssh-ed25519":
            return False, f"{algo}: ed25519 is not a FIPS 140-approved algorithm"
        if algo.startswith("ecdsa-") and cloud_key in ("aws", "azure"):
            return False, f"{algo}: {'EC2 key pairs' if cloud_key == 'aws' else 'Azure VMs'} refuse ECDSA keys"
        if algo == "ssh-rsa" or algo.startswith("ecdsa-sha2-nistp"):
            return None, f"{algo} (the recorded key could not be parsed, so its size was not checked)"
        return None, f"{algo}: the recorded key could not be parsed"
    problem = netutil.ssh_key_problem(pub, fips=True, cloud=cloud_key)
    return problem is None, problem or f"{algo} ({bits} bits)"


_SSHD_ALG_KEYS = ("ciphers", "kexalgorithms", "macs", "hostkeyalgorithms", "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes")
# X25519/Ed25519/Ed448 curves, ChaCha20, UMAC and the NTRU hybrids are not FIPS-approved (mlkem768x25519 is an X25519
# hybrid; mlkem768nistp256 is approved and passes); SHA-1 signatures and SHA-1 key exchange are not either.
_SSHD_NOT_FIPS = ("chacha20", "curve25519", "x25519", "ed25519", "ed448", "sntrup", "umac")
_SSHD_SHA1_KEYS = ("ssh-rsa", "ssh-rsa-cert-v01@openssh.com", "ssh-dss", "ssh-dss-cert-v01@openssh.com")


def sshd_fips_problems(text: str) -> tuple[list[str], dict]:
    """('setting: algorithm' entries sshd offers that FIPS 140 does not approve, {setting: [algorithms]}) from `sshd -T`."""
    settings: dict = {}
    for ln in (text or "").splitlines():
        key, _, val = ln.strip().partition(" ")
        if key.lower() in _SSHD_ALG_KEYS and val.strip():
            settings[key.lower()] = [a.strip() for a in val.strip().lower().split(",") if a.strip()]
    bad = []
    for key, algs in settings.items():
        for a in algs:
            if (any(p in a for p in _SSHD_NOT_FIPS)
                    or (key in ("hostkeyalgorithms", "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes") and a in _SSHD_SHA1_KEYS)
                    or (key == "kexalgorithms" and a.endswith("-sha1"))):
                bad.append(f"{key}: {a}")
    return bad, settings


def _fips_nodes(ctx) -> list[dict] | None:
    """The cluster's nodes with what FIPS depends on (None: the kubectl node query failed)."""
    proc = _kubectl(ctx, "get", "nodes", "-o", "jsonpath={range .items[*]}{.metadata.name}={.status.nodeInfo.osImage}|"
                    "{.status.nodeInfo.kernelVersion}|{.metadata.labels.kubernetes\\.azure\\.com/fips_enabled}|"
                    "{.metadata.labels.karpenter\\.sh/nodepool}{\"\\n\"}{end}", timeout=120)
    if proc.returncode != 0:
        return None
    out = []
    for n in proc.stdout.strip().splitlines():
        name, _, info = n.partition("=")
        parts = (info.split("|") + ["", "", "", ""])[:4]
        out.append({"name": name, "os": parts[0], "kernel": parts[1], "aks_fips": parts[2].strip().lower(), "karpenter": parts[3].strip()})
    return out


# Bottlerocket's FIPS variants carry -fips in their osImage ("Bottlerocket OS 1.26.1 (aws-k8s-1.31-fips)"); the standard
# ones - Karpenter's bottlerocket@latest alias among them - do not, and EKS has no other FIPS node image
_EKS_FIPS_IMAGE = re.compile(r"-fips\b")


def _node_fips(cloud, node: dict) -> tuple[bool | None, str]:
    """(FIPS?, detail) of one node, from what the node itself reports - never from the environment's settings."""
    osi = node["os"].lower()
    if cloud.local:
        return None, "local nodes are verified over SSH above"
    if cloud.key == "azure":   # AzureLinux is the OS in both modes: only the pool's FIPS image says it
        ok = node["aks_fips"] == "true"
        return ok, "FIPS-enabled node image" if ok else f"kubernetes.azure.com/fips_enabled {'label absent' if not node['aks_fips'] else '= ' + node['aks_fips']}"
    if cloud.key == "gcp" and ("container-optimized" in osi or osi.startswith("cos ")):
        return True, "Container-Optimized OS (FIPS-validated kernel crypto module)"
    if cloud.key == "aws":
        ok = bool(_EKS_FIPS_IMAGE.search(osi))
        if ok:
            return True, "Bottlerocket FIPS variant"
        by = f"; launched by Karpenter (NodePool {node['karpenter']}): cs platform install karpenter --upgrade" if node.get("karpenter") else ""
        return False, "not a Bottlerocket FIPS variant (no -fips in its image)" + by
    ok = "fips" in osi
    return ok, "FIPS node image" if ok else "not a FIPS node image"


def _eks_nodes_row(nodes: list[dict]) -> tuple[bool, str]:
    """The live answer to 'EKS nodes run a Bottlerocket FIPS variant', from what every node reports."""
    bad = [n for n in nodes if not _EKS_FIPS_IMAGE.search(n["os"].lower())]
    if not bad:
        return True, ui.clip(f"all {len(nodes)} node(s): " + ", ".join(sorted({n['os'] for n in nodes})), 160)
    karp = [n["name"] for n in bad if n.get("karpenter")]
    return False, (f"{len(bad)} of {len(nodes)} node(s) run a standard image: " + ", ".join(n["name"] for n in bad[:4])
                   + (f" (+{len(bad) - 4} more)" if len(bad) > 4 else "")
                   + (f"; {len(karp)} launched by Karpenter - re-apply its FIPS EC2NodeClass: cs platform install karpenter --upgrade" if karp else ""))


# AWS FIPS environments: the in-cluster AWS controllers reach AWS through its FIPS endpoints as well (their aws+fips chart
# values set AWS_USE_FIPS_ENDPOINT=true); a release's webhook / cert-controller Deployments call no AWS API
_AWS_FIPS_CONTROLLERS = ("external-secrets", "karpenter", "cluster-autoscaler", "external-dns", "aws-load-balancer-controller")
_NO_AWS_CALLS = ("-webhook", "-cert-controller")


def _items_of(proc: subprocess.CompletedProcess) -> list[dict] | None:
    """The items of a `kubectl get -o json` list (None: the call failed or printed no list)."""
    if proc.returncode != 0:
        return None
    try:
        items = json.loads(proc.stdout or "{}").get("items")
    except (ValueError, AttributeError):
        return None
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else None


def _uses_fips_endpoints(deployment: dict) -> bool:
    containers = (((deployment.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []
    return any(str(e.get("name")) == "AWS_USE_FIPS_ENDPOINT" and str(e.get("value", "")).strip().lower() == "true"
               for c in containers if isinstance(c, dict) for e in (c.get("env") or []) if isinstance(e, dict))


def _aws_fips_platform_checks(ctx, releases: dict, add) -> None:
    """AWS FIPS environments: the AWS controllers' endpoints, Velero's bucket endpoint and Karpenter's node images, read
    from the live objects (never from what the chart values should have set)."""
    from . import platform as platformmod

    def installed(item: str) -> dict | None:
        spec = platformmod.CATALOG.get(item)
        return spec if spec and platformmod._release_state(spec, item, releases) is not None else None

    for item in _AWS_FIPS_CONTROLLERS:
        spec = installed(item)
        if not spec:
            continue
        ns, _, release = platformmod._release_key(spec, item).partition("/")
        check = f"{item}: AWS API calls go through FIPS endpoints (AWS_USE_FIPS_ENDPOINT=true)"
        deps_ = _items_of(_kubectl(ctx, "-n", ns, "get", "deploy", "-l", f"app.kubernetes.io/instance={release}", "-o", "json", timeout=60))
        mine = [d for d in deps_ or [] if not str((d.get("metadata") or {}).get("name", "")).endswith(_NO_AWS_CALLS)]
        if not mine:
            add("platform", check, None, f"its Deployments in {ns} could not be read: the query failed or returned no JSON items list; the underlying query cause was not retained" if deps_ is None else f"no Deployment of release {release} in {ns}")
            continue
        bad = [str((d.get("metadata") or {}).get("name", "?")) for d in mine if not _uses_fips_endpoints(d)]
        add("platform", check, not bad, (f"{', '.join(bad)} without it: its SDK calls go to the standard endpoints; "
                                         f"fix: cs platform install {item} --upgrade") if bad else ", ".join(
                                            str((d.get("metadata") or {}).get("name", "?")) for d in mine))
    spec = installed("velero")
    if spec:
        ns = spec.get("ns", "velero")
        locs = _items_of(_kubectl(ctx, "-n", ns, "get", "backupstoragelocations.velero.io", "-o", "json", timeout=60))
        aws_locs = [b for b in locs or [] if str((b.get("spec") or {}).get("provider", "")).endswith("aws")]
        if locs is None:
            add("platform", "velero: backups reach S3 through its FIPS endpoint", None, "the backup storage locations could not be read: the query failed or returned no JSON items list; the underlying query cause was not retained")
        for b in aws_locs:
            name = str((b.get("metadata") or {}).get("name", "?"))
            url = str(((b.get("spec") or {}).get("config") or {}).get("s3Url") or "")
            ok = "-fips." in url
            add("platform", f"velero: backup location {name} reaches S3 through its FIPS endpoint", ok,
                url if ok else (f"s3Url {url or 'unset (the standard s3.<region> endpoint)'}; fix: cs platform install velero --upgrade"
                                if name == "default" else f"s3Url {url or 'unset'}: set config.s3Url https://s3-fips.<region>.amazonaws.com"))
    if installed("karpenter"):
        classes = _items_of(_kubectl(ctx, "get", "ec2nodeclasses.karpenter.k8s.aws", "-o", "json", timeout=60))
        if classes is None:
            add("platform", "karpenter: EC2NodeClasses select Bottlerocket FIPS AMIs", None, "the EC2NodeClasses could not be read: the query failed or returned no JSON items list; the underlying query cause was not retained")
        for nc in classes or []:
            name = str((nc.get("metadata") or {}).get("name", "?"))
            terms = [t for t in (nc.get("spec") or {}).get("amiSelectorTerms") or [] if isinstance(t, dict)]
            aliases = [str(t["alias"]) for t in terms if t.get("alias")]
            ssm = [str(t["ssmParameter"]) for t in terms if t.get("ssmParameter")]
            check = f"karpenter: EC2NodeClass {name} selects Bottlerocket FIPS AMIs"
            if aliases:
                add("platform", check, False, f"amiSelectorTerms alias {aliases[0]}: Karpenter's AMI aliases have no FIPS variant, so its nodes "
                    "run standard images; " + ("fix: cs platform install karpenter --upgrade" if name == "default" else
                                               "select /aws/service/bottlerocket/aws-k8s-<version>-fips/<arch>/latest/image_id (ssmParameter)"))
            elif ssm and all("-fips/" in p for p in ssm):
                add("platform", check, True, ssm[0])
            else:
                add("platform", check, None, "No exclusively FIPS SSM selector was verified in amiSelectorTerms. Resolve each ID/tag/name or other selector to its actual AMI and attest that it is a Bottlerocket FIPS variant; node rows only describe nodes already running.")


def fips(cloud, env, cfg: dict, outputs: dict, ctx=None, note: bool = True) -> Path:
    from . import platform as platformmod
    checks: list[dict] = []

    def add(area: str, name: str, ok: bool | None, detail: str = "", *, informational: bool = False, remediation: str = ""):
        status = "PASS" if ok else ("INFO" if informational or not wanted else "UNKNOWN") if ok is None else "FAIL"
        if status == "UNKNOWN" and not remediation:
            remediation = {
                "ssh": "Record a valid public key and verify its parsed type and size against this cloud's FIPS SSH requirements, then rerun.",
                "cloud": "Inspect the saved stack and effective provider/image settings named in this check; obtain the missing configuration evidence and rerun.",
                "hosts": "Verify the host addresses, SSH access and required privileged probe commands; inspect the failed command output and rerun.",
                "kubernetes": "Verify this environment's kubeconfig and permission to read node runtime information; inspect the node query result and rerun.",
                "platform": "Inspect the named release or Kubernetes resource and its effective FIPS settings; obtain the missing runtime evidence and rerun.",
            }.get(area, "Inspect the missing evidence named in this check, obtain it, then rerun FIPS verification.")
        checks.append({"area": area, "check": name,
                       "status": status, "detail": detail, "remediation": remediation})

    wanted = fips_env(cfg, outputs)
    add("config", "fips_mode enabled for the environment", wanted,
        "fips_mode=true" if wanted else "chosen at creation: cs setup <cloud> --var fips_mode=true (new environments only; they get an RSA-4096 SSH key)")
    add("ssh", "environment SSH key is FIPS-approved (RSA-4096; ECDSA only on GCP/VMware)", *_ssh_key_check(str(cfg.get("ssh_public_key") or ""), cloud.key))
    nodes: list[dict] | None = None
    cluster_note = ""
    if ctx is not None:
        try:
            nodes = _fips_nodes(ctx)
            cluster_note = "" if nodes is not None else "the kubectl node query failed; no successful node response is available (the underlying cause was not retained)"
        except ui.Abort as e:   # kubectl is missing (and was not installed): the other layers are still verified
            cluster_note = tail_text(str(getattr(e, "msg", "") or e), 200)
            add("kubernetes", "cluster not checked", None, cluster_note)
            ctx = None
    # cloud layer
    if cloud.key == "aws":
        try:
            rendered = json.loads((env.stack_dir / "main.tf.json").read_text())
            aws_provider = rendered.get("provider", {}).get("aws", {})
            value = aws_provider.get("use_fips_endpoint")
            # This is rendered Terraform input: only literal booleans and its
            # supported string conversions establish a value, never bool(str).
            enabled = value if type(value) is bool else value == "true" if isinstance(value, str) and value in ("true", "false") else None
            if enabled is not None:
                detail = f"provider.aws.use_fips_endpoint is {'true' if enabled else 'false'} in main.tf.json."
            elif "use_fips_endpoint" not in aws_provider:
                detail = "main.tf.json does not declare provider.aws.use_fips_endpoint; the effective AWS provider setting was not verified."
            elif isinstance(value, str) and ("${" in value or "%{" in value):
                detail = "provider.aws.use_fips_endpoint uses a Terraform expression or template; its evaluated boolean value was not inspected."
            else:
                detail = "provider.aws.use_fips_endpoint is not a literal boolean (true/false) in main.tf.json; its effective setting cannot be determined."
            add("cloud", "AWS provider uses FIPS endpoints", enabled, detail,
                remediation="Inspect the resolved AWS provider configuration and determine its effective use_fips_endpoint value; set it to true when FIPS endpoints are required, then rerun verification." if enabled is None else "")
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            why = ("The rendered stack main.tf.json does not exist." if isinstance(exc, FileNotFoundError) else
                   "Permission was denied while reading main.tf.json." if isinstance(exc, PermissionError) else
                   f"main.tf.json could not be read (filesystem error {exc.errno})." if isinstance(exc, OSError) else
                   "main.tf.json is not valid JSON." if isinstance(exc, ValueError) else
                   "main.tf.json does not contain the expected provider.aws object.")
            add("cloud", "AWS provider uses FIPS endpoints", None, why)
    if cloud.key in ("aws", "azure") and outputs.get("kubernetes_cluster_name") and not nodes:
        # the node rows below verify every node live; without them this is only what fips_mode asked for
        add("kubernetes", "EKS nodes run a Bottlerocket FIPS variant" if cloud.key == "aws" else "AKS node pool is fips_enabled", None,
            ("ami_type BOTTLEROCKET_*_FIPS" if cloud.key == "aws" else "default_node_pool.fips_enabled")
            + f" is set by fips_mode={'true' if wanted else 'false'}; not verified live ("
            + (cluster_note or ("the cluster has no nodes" if nodes == [] else "no cluster connection")) + ")")
    if cloud.key == "gcp":
        img = _gcp_bastion_image(env, cfg, bool(cfg["vars"].get("fips_mode")))
        add("cloud", "bastion image is Ubuntu Pro FIPS", "ubuntu-pro-fips" in img, img)
        if cfg["vars"].get("enable_vpn") or outputs.get("vpn_public_ip"):
            vimg = _gcp_vpn_image(bool(cfg["vars"].get("fips_mode")))
            add("cloud", "VPN image is Ubuntu Pro FIPS", ("ubuntu-pro-fips" in vimg) if vimg else None, vimg or "not derivable from the stack; the VPN host's kernel is checked below")
        if outputs.get("kubernetes_cluster_name"):
            add("kubernetes", "GKE node pool declares Container-Optimized OS", None,
                "image_type COS_CONTAINERD is declared; live node rows below verify the actual node images." if nodes else
                "image_type COS_CONTAINERD is declared; no live node images were verified.", informational=bool(nodes))
    # hosts
    user, key = cloud.ssh_user(cfg), env.private_key_path(cfg)
    hosts = _hosts(cloud, env, cfg, outputs, ["bastion", "vpn", "k8s"], note=note)
    if wanted and not hosts:
        add("hosts", "host runtime FIPS checks", None, "No host addresses are available; kernel, sshd and OpenSSL were not verified.")
    for name, ip in hosts:
        h = prov.Host(ip, user, key, name, env=env)
        try:
            probe = subprocess.run(h.ssh("cat /proc/sys/crypto/fips_enabled 2>/dev/null; echo ---; sudo sshd -T 2>/dev/null | "
                                     "grep -Ei '^(ciphers|kexalgorithms|macs|hostkeyalgorithms|pubkeyacceptedalgorithms|pubkeyacceptedkeytypes) ' ; echo ---; "
                                     "if command -v openssl >/dev/null 2>&1 && openssl version >/dev/null 2>&1; then "
                                     "(openssl list -providers 2>/dev/null | grep -qi fips && echo openssl-fips) || "
                                     "(openssl md5 /dev/null >/dev/null 2>&1 && echo openssl-not-fips || echo openssl-fips); "
                                     "else echo openssl-unavailable; fi; "
                                     "echo ---; (pro status 2>/dev/null | grep -Ei 'fips' | head -2) || true"),
                               capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            why = ("The SSH runtime probe timed out after 60 seconds; no completed probe result is available." if isinstance(exc, subprocess.TimeoutExpired) else
                   f"The local SSH runtime probe could not execute (filesystem/process error {exc.errno}).")
            add("hosts", f"{name}: runtime checks unavailable", None, why)
            continue
        if probe.returncode != 0 and not probe.stdout.strip():
            add("hosts", f"{name}: reachable over SSH", None, tail_text(probe.stderr, 160, lines=2) or f"ssh exited {probe.returncode}")
            continue
        if probe.returncode:
            add("hosts", f"{name}: runtime probe completed", None, f"SSH exited {probe.returncode}; partial observations are retained.")
        parts = probe.stdout.split("---")
        state = parts[0].strip()
        add("hosts", f"{name}: kernel FIPS mode (fips_enabled=1)", state == "1", f"fips_enabled={state or 'absent'}")
        bad, settings = sshd_fips_problems(parts[1] if len(parts) > 1 else "")
        complete_sshd = {"ciphers", "kexalgorithms", "macs", "hostkeyalgorithms"} <= set(settings) and \
            bool({"pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes"} & set(settings))
        missing_sshd = sorted({"ciphers", "kexalgorithms", "macs", "hostkeyalgorithms"} - set(settings))
        if not {"pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes"} & set(settings):
            missing_sshd.append("pubkeyacceptedalgorithms/pubkeyacceptedkeytypes")
        add("hosts", f"{name}: sshd offers only FIPS-approved algorithms", False if bad else True if complete_sshd else None,
            (", ".join(bad[:6]) + (f" (+{len(bad) - 6} more)" if len(bad) > 6 else "")) if bad
            else (f"{', '.join(sorted(settings))} checked" if complete_sshd else "The sshd -T probe did not return required algorithm settings: " + ", ".join(missing_sshd) + ". Its stderr was not collected; no command-level cause is available."),
            remediation="Run sudo sshd -T on this host, inspect its exit status and stderr, and obtain all listed algorithm settings before rerunning FIPS verification." if not complete_sshd and not bad else "")
        openssl = parts[2].strip() if len(parts) > 2 else ""
        openssl_detail = ("The SSH probe returned no OpenSSL result section; provider activation was not observed." if not openssl else
                          "The probe could not find openssl or run openssl version; it did not distinguish these causes." if "openssl-unavailable" in openssl else openssl[:80])
        add("hosts", f"{name}: OpenSSL FIPS provider active", None if not openssl or "openssl-unavailable" in openssl else "openssl-fips" in openssl, openssl_detail,
            remediation="Check command -v openssl and openssl version on this host, then inspect the active FIPS provider/module and rerun the runtime probe." if not openssl or "openssl-unavailable" in openssl else "")
        if len(parts) > 3 and parts[3].strip():
            add("hosts", f"{name}: Ubuntu Pro FIPS services", bool(re.search(r"\benabled\b", parts[3].lower())), parts[3].strip().replace("\n", " | ")[:120])
    # kubernetes + platform
    if ctx is None and wanted and (outputs.get("kubernetes_cluster_name") or (cfg.get("vars") or {}).get("enable_kubernetes") is True):
        add("kubernetes", "cluster and platform runtime checks", None, "No cluster connection is available; node, controller and TLS checks were not completed.")
    if ctx is not None:
        if nodes is None:
            add("kubernetes", "nodes not checked", None, cluster_note or "The kubectl node query returned no usable result; the underlying cause was not retained.")
        elif not nodes:
            add("kubernetes", "node runtime FIPS checks", None, "The cluster returned no nodes; no node image or runtime was verified.")
        if cloud.key == "aws" and nodes:
            add("kubernetes", "EKS nodes run a Bottlerocket FIPS variant", *_eks_nodes_row(nodes))   # from the live nodes
        for n in nodes or []:
            ok, detail = _node_fips(cloud, n)
            add("kubernetes", f"node {n['name']}: {n['os']}", ok, detail, informational=cloud.local)
        if ctx.distro == "rke2":
            version = _kubectl(ctx, "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.kubeletVersion}")
            v = version.stdout.strip()
            add("kubernetes", "RKE2 (FIPS 140-2 compliant build: Go BoringCrypto)",
                True if wanted and version.returncode == 0 and "rke2" in v.lower() else None,
                v if wanted and version.returncode == 0 and "rke2" in v.lower() else
                f"The kubelet version query exited {version.returncode}; the running RKE2 build was not verified." if version.returncode else
                "The node response contains no RKE2 version marker; the running build cannot be identified as RKE2.")
        elif ctx.distro == "kubeadm":
            add("kubernetes", "kubeadm binaries are not FIPS builds", False, "use kubernetes_distro=rke2 in FIPS environments")
        try:
            rel = platformmod.installed_releases(ctx)
        except platformmod.ClusterUnreachable as e:
            rel = {}
            add("platform", "platform items not checked", None, "Installed releases could not be listed. " + (ui.clip(str(e), 200) or "The release query supplied no further cause."))
        for item, spec in platformmod.CATALOG.items():
            if platformmod._release_state(spec, item, rel) is not None and not spec.get("hidden"):
                cap = spec.get("fips")
                if cap == "tls-restricted":   # user-facing TLS terminator: suites pinned, proxy crypto module not validated
                    add("platform", f"{item}: TLS pinned to FIPS suites, proxy crypto not FIPS-validated", False if wanted else None,
                        "terminates user TLS with Envoy BoringSSL / OpenSSL (TLS 1.2+, FIPS ciphers enforced); use a FIPS build of the proxy image for strict compliance")
                    continue
                if cap == "crypto-restricted":   # its job is cryptography, done by a module that is not FIPS-validated
                    add("platform", f"{item}: key generation/encryption uses non-FIPS-validated crypto", False if wanted else None,
                        "generates keys, signs or encrypts with upstream Go crypto / OpenSSL builds that are not a FIPS 140-validated "
                        "module; use a FIPS build of its image for strict compliance")
                    continue
                add("platform", f"{item}: {'FIPS-compatible' if cap else 'not known to be FIPS-validated'}", bool(cap) if wanted else None,
                    "runs on FIPS kernels; no user-facing TLS with its own policy" if cap else "application image ships its own crypto library")
        if cloud.key == "aws" and wanted and rel:   # set up only in FIPS environments: in any other one they are simply absent
            _aws_fips_platform_checks(ctx, rel, add)
        ctp = _kubectl(ctx, "-n", "cloudseed", "get", "clienttrafficpolicy", "cloudseed-fips-tls").returncode == 0
        gw = _kubectl(ctx, "-n", "cloudseed", "get", "gateway", "cloudseed").returncode == 0
        if gw:
            add("platform", "shared Gateway enforces TLS 1.2+/FIPS cipher suites (ClientTrafficPolicy cloudseed-fips-tls)", ctp, "cs platform install envoy-gateway --upgrade" if not ctp else "")
    failed = [c for c in checks if c["status"] == "FAIL"]
    unknown = [c for c in checks if c["status"] == "UNKNOWN"]
    verdict = "N/A" if not wanted else "FAIL" if failed else "INCOMPLETE" if unknown else "PASS"
    report = {"summary": {"fips_mode": wanted, "checks": len(checks), "pass": sum(1 for c in checks if c["status"] == "PASS"), "fail": len(failed), "unknown": len(unknown), "info": sum(1 for c in checks if c["status"] == "INFO")},
              "findings": [{"status": c["status"], "severity": "HIGH" if c["status"] == "FAIL" else "MEDIUM" if c["status"] == "UNKNOWN" else "INFO", "title": f"[{c['area']}] {c['check']}", "detail": c["detail"],
                            "remediation": c["remediation"] or ("Resolve the reported configuration or runtime issue, then rerun FIPS verification." if c["status"] == "FAIL" else "")} for c in checks],
              "checks": checks, "tool": "cloudseed", "verdict": verdict,
              "coverage_limits": ["Verification covers the reported configuration and reachable host/cluster checks; missing runtime evidence remains UNKNOWN.",
                                  "A PASS is not FIPS certification of every application or cryptographic module."]}
    path = save_report(env, "fips", report)
    rows = [f"{ui.style('✔', 'leaf', 'bold') if c['status'] == 'PASS' else ui.style('✖', 'rose', 'bold') if c['status'] == 'FAIL' else ui.style('○', 'muted')} "
            f"{ui.style(c['area'].ljust(11), 'muted')} {c['check']}   {ui.dim(str(c['detail']))}" for c in checks]
    tone = {"PASS": "leaf", "FAIL": "rose", "N/A": "seed", "INCOMPLETE": "seed"}[verdict]
    head = (f"N/A - {env.id} is not a FIPS environment (FIPS is chosen at creation); {len(failed)} of {len(checks)} checks would fail" if verdict == "N/A"
            else f"{verdict} - {report['summary']['pass']} passed, {len(failed)} failed, {len(unknown)} unknown, {report['summary']['info']} informational")
    rows += ["", ui.style(head, tone, "bold"), ui.dim(f"report: {path}")]
    ui.panel(f"FIPS 140 verification · {env.id}", rows, accent=tone)
    return path


# ---------------------------------------------------------------- everything

def _verdict_of(path: Path) -> str:
    try:
        report = json.loads(path.read_text())
        return cloud_verdict(report) if report.get("kind") == "cloud" or path.name.startswith("cloud-") else str(report.get("verdict") or "?")
    except (OSError, ValueError, AttributeError):
        return "?"


def run_all(cloud, env, cfg: dict, outputs: dict, ctx, host_which: list[str], errors: list | None = None,
            explicit_hosts: bool = False) -> list[Path]:
    """Every applicable scan; one that cannot run is reported and its label added to `errors` (the rest still run).
    explicit_hosts: --host was given, so finding none of those hosts is an error (not a silent skip)."""
    done: list[Path] = []
    errors = [] if errors is None else errors
    host_which = parse_hosts(host_which)

    def attempt(label: str, fn):
        try:
            done.append(fn())
        except ui.Abort as e:
            errors.append(label)
            ui.warn(f"{label}: {getattr(e, 'msg', '') or 'failed'}")
        except Exception as e:  # noqa: BLE001
            errors.append(label)
            ui.warn(f"{label} failed: {type(e).__name__}: {ui.clip(str(e), 200)}")

    if ctx is not None:
        attempt("cis", lambda: cis(ctx))
        attempt("kube", lambda: kube(ctx))
        attempt("images", lambda: images(ctx))
        if ctx.distro in STIG_BENCHMARKS:
            attempt("stig-k8s", lambda: cis(ctx, stig=True))
    if _hosts(cloud, env, cfg, outputs, host_which):   # (shows the managed-nodes note once for the whole run)
        down: dict = {}   # a host that did not answer for the CIS scan is not waited for again by the STIG scan
        attempt("host cis", lambda: host(cloud, env, cfg, outputs, host_which, "cis", note=False, unreachable=down))
        attempt("host stig", lambda: host(cloud, env, cfg, outputs, host_which, "stig", note=False, unreachable=down))
    elif explicit_hosts:
        errors.append("host")
        ui.warn(f"host: {no_host_message(cloud, env, cfg, outputs, host_which)}")
    else:
        ui.info(f"Host scans skipped: {env.id} has no SSH-reachable host (bastion / vpn / local k8s nodes).")
    if not cloud.local:
        attempt("cloud", lambda: cloud_scan(cloud, env, cfg))
    if fips_env(cfg, outputs):
        attempt("fips", lambda: fips(cloud, env, cfg, outputs, ctx, note=False))
    else:
        ui.info(f"FIPS verification skipped: {env.id} is not a FIPS environment (fips_mode=false); `cs scan fips` runs it anyway.")
    verdicts = [(p, _verdict_of(p)) for p in done]
    rows: list = [(ui.style(v, "leaf" if v == "PASS" else "seed" if v in ("N/A", "INCOMPLETE") else "rose", "bold"), str(p)) for p, v in verdicts]
    rows += [(ui.style("ERROR", "rose", "bold"), f"{label}: did not complete (see above)") for label in errors]
    clean = not errors and all(v in ("PASS", "N/A") for _, v in verdicts)
    incomplete = not errors and bool(done) and all(v in ("PASS", "N/A", "INCOMPLETE") for _, v in verdicts)
    ui.panel(f"Scan summary · {env.id}", rows or [ui.dim("nothing ran")], accent="leaf" if clean and done else "seed" if incomplete else "rose")
    return done


def show_reports(env, last: int = 10) -> None:
    rows = []
    for p in (reports(env)[-last:] if last > 0 else []):
        try:
            r = json.loads(p.read_text())
            v = cloud_verdict(r) if r.get("kind") == "cloud" or p.name.startswith("cloud-") else str(r.get("verdict") or "")
            rows.append((p.stem, (ui.style(v, "leaf" if v == "PASS" else "seed" if v in ("N/A", "INCOMPLETE") else "rose", "bold") + "  " if v else "")
                         + "  ".join(f"{k}={val}" for k, val in list(r.get("summary", {}).items())[:6])))
        except ValueError:
            rows.append((p.stem, ""))
    ui.panel(f"Scan reports · {env.id}  ({_reports_dir(env)})", rows or [ui.dim("none yet  (cs scan all)")])
