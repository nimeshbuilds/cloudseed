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

from . import audit, deps, netutil, paths, provision as prov, ui

SCAN_NS = "cloudseed-scan"
SSG_FALLBACK = "0.1.82"
IMAGE_FINDINGS_MAX = 1000  # critical/high image findings kept in a report (all critical first)

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
    for k, v in report.get("summary", {}).items():
        md.append(f"- **{k}**: {v}")
    if report.get("findings"):
        md += ["", "| status | severity | finding | detail |", "|---|---|---|---|"]
        md += [f"| {md_cell(f.get('status', ''))} | {md_cell(f.get('severity', ''))} | {md_cell(f.get('title', ''), 90)} | {md_cell(f.get('detail', ''), 120)} |"
               for f in report["findings"][:200]]
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
    bad = [f for f in findings if str(f.get("status", "")).upper() in ("FAIL", "FAILED", "CRITICAL", "HIGH") or f.get("severity") in ("CRITICAL", "HIGH")]
    if bad:
        rows.append(("", ""))
        rows.append((ui.style(f"top findings ({len(bad)})", "bold", "text"), ""))
        for f in bad[:limit]:
            rows.append((ui.style(str(f.get("severity") or f.get("status") or "").ljust(8), "rose"),
                         f"{ui.clip(str(f.get('title', '')), 70)}   {ui.dim(ui.clip(str(f.get('detail', '')), 60))}"))
        if len(bad) > limit:
            rows.append(("", ui.dim(f"... {len(bad) - limit} more in the report")))
    if note:
        rows.append(("", ui.dim(note)))
    if hint:   # what to do about it: its own row, never read as part of the last finding
        rows += [("", ""), ("next step", hint)]
    tone = "leaf" if not verdict or verdict.startswith("PASS") else "seed" if verdict.startswith("N/A") else "rose"
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
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _latest_tag(repo: str) -> str:
    """Newest release tag of a GitHub repo (API first, the /releases/latest redirect when the API is rate-limited)."""
    try:
        return str(json.loads(_fetch(f"https://api.github.com/repos/{repo}/releases/latest", 30))["tag_name"])
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        req = urllib.request.Request(f"https://github.com/{repo}/releases/latest", headers={"User-Agent": "cloudseed"})
        with urllib.request.urlopen(req, timeout=30) as resp:
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
    totals = {"pass": 0, "fail": 0, "warn": 0, "info": 0}
    used: list[str] = []
    not_evaluated = 0
    default_ns: dict = {}   # the default namespace's own listing, read once per scan
    try:
        for role, targets in runs:
            data = _kube_bench_run(ctx, role, benchmark or "", targets, version=version)
            for control in data.get("Controls", []):
                if control.get("version") and control["version"] not in used:
                    used.append(str(control["version"]))
                for test in control.get("tests", []):
                    for res in test.get("results", []):
                        st = str(res.get("status", "")).upper()
                        detail = (res.get("remediation") or "").strip().replace("\n", " ")[:300]
                        scope = _default_ns_scope(res) if st in ("PASS", "FAIL", "WARN") else None
                        if scope:
                            st, verdict_detail = _default_ns_result(ctx, res, scope, default_ns)
                            detail = verdict_detail or detail
                            not_evaluated += default_ns.get(scope) is None   # cloudseed could not list it either
                        elif st in ("PASS", "FAIL") and _not_evaluated(res):
                            st, detail = "WARN", "not evaluated: kube-bench could not query the Kubernetes API from its pod"
                            not_evaluated += 1
                        totals[st.lower()] = totals.get(st.lower(), 0) + 1
                        if st in ("FAIL", "WARN"):
                            findings.append({"status": st, "severity": "HIGH" if st == "FAIL" else "MEDIUM", "title": f"{res.get('test_number')} {res.get('test_desc')}",
                                             "detail": detail, "node_type": control.get("node_type"), "section": test.get("section")})
    finally:
        if any(_runs_policies(t) for _, t in runs):
            _kube_bench_cleanup_rbac(ctx)
    ran = ", ".join(used) or benchmark or (f"CIS for Kubernetes {version}" if version else "auto-detected")
    if benchmark and used and used != [benchmark]:
        ui.warn(f"kube-bench ran {ran}, not the {ctx.distro} benchmark {benchmark}: the paths it checks may not match this distro.")
    kind = "stig-k8s" if stig else "cis"
    summary = {"benchmark": ran, "distro": ctx.distro, "pass": totals["pass"], "fail": totals["fail"], "warn": totals["warn"], "info": totals["info"]}
    if not_evaluated:
        summary["not evaluated"] = not_evaluated
    report = {"summary": summary, "findings": findings, "tool": "kube-bench", "verdict": "PASS" if totals["fail"] == 0 else "FAIL"}
    hint = "" if stig else _cis_profile_hint(ctx, totals["fail"])
    if hint:
        report["hint"] = hint
    path = save_report(ctx.env, kind, report)
    _panel(f"{'Kubernetes STIG' if stig else 'CIS Kubernetes Benchmark'} · {ctx.env.id}", report["summary"], findings, path,
           verdict=f"{report['verdict']} - {totals['fail']} failed, {totals['warn']} to review (WARN = manual check"
                   + (f"; {not_evaluated} could not query the API" if not_evaluated else "") + ")", hint=hint)
    return path


# ---------------------------------------------------------------- kubescape

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
        data = json.loads(out.read_text())
    except (OSError, ValueError):
        _drop_empty(out)
        raise ui.Abort(f"kubescape failed (exit {r.returncode}): {tail_text(r.stderr or r.stdout, 600, lines=2)}")
    sd = data.get("summaryDetails", {})
    findings = []
    counts = {"passed": 0, "failed": 0, "skipped": 0}
    for cid, c in (sd.get("controls") or {}).items():
        raw = c.get("status")
        st = str(raw if isinstance(raw, str) else (raw or {}).get("status") or (c.get("statusInfo") or {}).get("status", "")).lower()
        counts[st] = counts.get(st, 0) + 1
        if st == "failed":
            rc = c.get("ResourceCounters") or c.get("resourceCounters") or {}
            sev = str(c.get("severity") or "").upper()
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                f_ = c.get("scoreFactor", 0)
                sev = "CRITICAL" if f_ >= 9 else "HIGH" if f_ >= 7 else "MEDIUM" if f_ >= 4 else "LOW"
            findings.append({"status": "FAIL", "severity": sev, "title": f"{cid} {c.get('name', '')}",
                             "detail": f"{rc.get('failedResources', '?')} failing resources ({c.get('category', {}).get('name', '')})"})
    findings.sort(key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f["severity"]))
    score = sd.get("complianceScore") if sd.get("complianceScore") is not None else sd.get("score")
    per_fw = ", ".join(f"{f.get('name')} {round(float(f.get('complianceScore', 0)), 1)}%" for f in (sd.get("frameworks") or []) if isinstance(f, dict))
    report = {"run": run, "summary": {"frameworks": fw, "controls passed": counts.get("passed", 0), "controls failed": counts.get("failed", 0), "skipped": counts.get("skipped", 0),
                          "compliance score": (f"{round(float(score), 1)}%" if score is not None else "-") + (f"  ({per_fw})" if per_fw else "")}, "findings": findings, "tool": "kubescape", "raw": str(out),
              "verdict": "PASS" if not any(f["severity"] in ("CRITICAL", "HIGH") for f in findings) else "FAIL"}
    path = save_report(ctx.env, "kube", report)
    _panel(f"Kubernetes posture (kubescape {fw}) · {ctx.env.id}", report["summary"], findings, path,
           verdict=f"{report['verdict']} - {len(findings)} failing controls")
    return path


# ---------------------------------------------------------------- images (trivy)

def images(ctx) -> Path:
    _ensure_kubectl()
    findings: list[dict] = []
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    source = "trivy-operator"
    r = _kubectl(ctx, "get", "vulnerabilityreports", "-A", "-o", "json")
    try:
        operator_items = json.loads(r.stdout or "{}").get("items") if r.returncode == 0 else None
    except ValueError:
        operator_items = None
    raw, run = None, run_stamp()
    if operator_items:
        for it in operator_items:
            s = it.get("report", {}).get("summary", {})
            for k in sev:
                sev[k] += int(s.get(f"{k.lower()}Count", 0))
            crit = [v for v in it.get("report", {}).get("vulnerabilities", []) if v.get("severity") in ("CRITICAL", "HIGH")]
            for v in crit:
                findings.append({"status": "FAIL", "severity": v["severity"], "title": f"{v.get('vulnerabilityID')} {v.get('resource')} {v.get('installedVersion')}",
                                 "detail": f"{it['metadata']['namespace']}/{it['metadata'].get('labels', {}).get('trivy-operator.resource.name', it['metadata']['name'])}  fixed: {v.get('fixedVersion') or '-'}"})
    else:
        source = "trivy k8s"
        trivy = _tool("trivy", "trivy", _install_trivy)
        out, run = claim_run_path(_raw_dir(ctx.env), "trivy-", ".json", run)
        raw = out
        try:
            with ui.Spinner("trivy k8s (all namespaces, vulnerabilities; first run downloads the DB)") as sp:
                p = subprocess.run([trivy, "k8s", "--report", "all", "--scanners", "vuln", "--format", "json", "--output", str(out), "--severity", "CRITICAL,HIGH,MEDIUM,LOW", "--timeout", "30m"],
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

        def walk(o, where=""):
            if isinstance(o, dict):
                for v in o.get("Vulnerabilities") or []:
                    s = v.get("Severity", "")
                    if s in sev:
                        sev[s] += 1
                    if s in ("CRITICAL", "HIGH"):
                        findings.append({"status": "FAIL", "severity": s, "title": f"{v.get('VulnerabilityID')} {v.get('PkgName')} {v.get('InstalledVersion')}",
                                         "detail": f"{where} fixed: {v.get('FixedVersion') or '-'}"})
                for k, v in o.items():
                    walk(v, o.get("Target") or o.get("Name") or where)
            elif isinstance(o, list):
                for v in o:
                    walk(v, where)
        try:
            walk(json.loads(out.read_text()))
        except ValueError:
            raise ui.Abort(f"trivy wrote an unreadable report ({out}): {tail_text(p.stderr or p.stdout, 400, lines=2)}")
    findings.sort(key=lambda f: ["CRITICAL", "HIGH"].index(f["severity"]))  # stable: keeps the tool's order inside a severity
    total_bad = len(findings)
    findings = findings[:IMAGE_FINDINGS_MAX]
    report = {"run": run, "summary": {"source": source, **{k.lower(): v for k, v in sev.items()}}, "findings": findings, "tool": source,
              "findings_total": total_bad, "verdict": "PASS" if sev["CRITICAL"] == 0 else "FAIL"}
    if raw:
        report["raw"] = str(raw)
    note = (f"the report lists the first {len(findings)} of {total_bad} critical/high findings (critical first)"
            + (f"; all of them: {raw}" if raw else "")) if total_bad > len(findings) else ""
    path = save_report(ctx.env, "images", report)
    _panel(f"Workload vulnerabilities ({source}) · {ctx.env.id}", report["summary"], findings, path,
           verdict=f"{report['verdict']} - {sev['CRITICAL']} critical, {sev['HIGH']} high", note=note)
    return path


# ---------------------------------------------------------------- hosts (OpenSCAP)

def _ssg_version() -> str:
    try:
        with urllib.request.urlopen("https://api.github.com/repos/ComplianceAsCode/content/releases/latest", timeout=10) as r:
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
            findings.append({"status": "FAIL", "severity": rule["severity"].upper(), "title": f"{name}: {rule['title']}", "detail": rule["id"]})
        meta = dest / name / "meta.json"
        if meta.exists():
            per_host[name]["meta"] = json.loads(meta.read_text())
    findings.sort(key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].index(f["severity"]) if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") else 9)
    scanned = [r for r in per_host.values() if "score" in r]
    not_applicable = [r for r in per_host.values() if r.get("skipped")]   # no content for this profile: n/a, not an error
    # numeric totals (summed over hosts) so dashboards can tell pass from fail; hosts without results are counted, never "clean"
    summary = {"profile": profile, "ssg": ssg, "pass": sum(r["pass"] for r in scanned), "fail": sum(r["fail"] for r in scanned)}
    if len(scanned) + len(not_applicable) < len(per_host):
        summary["errors"] = len(per_host) - len(scanned) - len(not_applicable)
    for name, r in per_host.items():
        summary[name] = (f"score {r['score']}%  pass {r['pass']}  fail {r['fail']}  n/a {r['notapplicable']}  ({r.get('meta', {}).get('profile', '?').split('_profile_')[-1]})"
                         if "score" in r else r["error"])
    report = {"run": run, "summary": summary, "findings": findings, "hosts": per_host, "tool": "openscap", "raw": str(dest), "ansible_rc": rc}
    all_na = bool(per_host) and len(not_applicable) == len(per_host)
    clean = rc == 0 and not findings and not summary.get("errors")   # a host that was not scanned is never "clean"
    report["verdict"] = "N/A" if all_na else "PASS" if clean else "FAIL"
    kind = "stig-host" if profile == "stig" else f"host-{profile}"
    path = save_report(env, kind, report)
    if all_na:
        verdict = f"N/A - no scanned host has {'DISA STIG' if profile == 'stig' else profile.upper()} content (reasons above)"
    elif not scanned:   # nothing was evaluated: no rule count, no score, no HTML report to point at
        verdict = f"ERROR - no host could be scanned ({summary.get('errors', 0)} without results; see the log above)"
    else:
        worst = min(r["score"] for r in scanned)
        verdict = (f"{'PASS' if clean else 'FAIL'} - {len(findings)} failed rules, lowest score {worst}%"
                   + (f"; {summary['errors']} host(s) not scanned" if summary.get("errors") else "")
                   + f"  (HTML reports: {dest}/<host>/report.html)")
    _panel(f"Host {profile.upper()} benchmark (OpenSCAP) · {env.id}", summary, findings, path, verdict=verdict)
    return path


def _parse_xccdf(path: Path) -> dict:
    ns = {"x": "http://checklists.nist.gov/xccdf/1.2"}
    root = ET.parse(path).getroot()
    tr = root.find(".//x:TestResult", ns)
    tr = root if tr is None else tr
    counts = {"pass": 0, "fail": 0, "notapplicable": 0, "notchecked": 0, "error": 0, "informational": 0, "notselected": 0, "unknown": 0}
    failed = []
    for rr in tr.findall("x:rule-result", ns):
        res = (rr.findtext("x:result", default="unknown", namespaces=ns) or "unknown").strip()
        counts[res] = counts.get(res, 0) + 1
        if res == "fail":
            rid = rr.get("idref", "")
            failed.append({"id": rid, "severity": rr.get("severity", "unknown"), "title": rid.split("_rule_")[-1].replace("_", " ")})
    score_el = tr.find("x:score", ns)
    score = round(float(score_el.text), 1) if score_el is not None and score_el.text else 0.0
    return {**counts, "score": score, "failed_rules": failed}


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
    text = ((r.stderr or "") + "\n" + (r.stdout or "")) if r is not None else ""
    lines = [ln.strip() for ln in text.splitlines() if re.search(r"\b(CRITICAL|ERROR)\b", ln)]
    msg = ui.clip(" | ".join(lines[-4:]), 800) if lines else tail_text(text, 800, lines=3)
    if re.search(r"credential|NoCredentials|DefaultCredentialsError|Unable to locate|az login|AADSTS|not logged in|expired", text, re.I):
        msg += f". {_LOGIN_HINTS.get(provider, '')}"
    return msg or "no output"


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
    if deps.find("az"):
        return ["--az-cli-auth"]
    raise ui.Abort("prowler needs Azure credentials: az login (cloudseed install az), or a service principal in ARM_CLIENT_ID / "
                   "ARM_CLIENT_SECRET / ARM_TENANT_ID (certificate or OIDC logins need az here).", code=2)


def cloud_scan(cloud, env, cfg: dict, framework: str | None = None) -> Path:
    from . import services
    if cloud.local:
        raise ui.Abort("There is no cloud account to scan for a local VMware environment (try: cs scan host).")
    provider = cloud.key
    # the environment's own endpoints and credentials: FIPS endpoints in an AWS FIPS environment (like every other AWS
    # call it makes), its AWS profile, and on Azure the ARM_* service principal mapped to what prowler reads
    env_ = dict(services.cloud_cli_env(provider, cfg))
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
    except subprocess.TimeoutExpired:
        shutil.rmtree(outdir, ignore_errors=True)
        raise ui.Abort("prowler did not finish within 2 hours; re-run with a narrower framework: cs scan cloud --framework <name>")
    ocsf = next(iter(outdir.glob("prowler*.ocsf.json")), None)
    if not ocsf:
        shutil.rmtree(outdir, ignore_errors=True)
        raise ui.Abort(f"prowler produced no report (exit {r.returncode if r else '?'}): {_prowler_error(r, provider)}")
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
    counts = {"PASS": 0, "FAIL": 0, "MANUAL": 0}
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    findings = []
    for f in data:
        st = str(f.get("status_code") or f.get("status") or "").upper()
        counts[st] = counts.get(st, 0) + 1
        s = str(f.get("severity", ""))
        if st == "FAIL":
            sev[s] = sev.get(s, 0) + 1
            if s in ("Critical", "High"):
                findings.append({"status": "FAIL", "severity": s.upper(), "title": (f.get("finding_info") or {}).get("title", "")[:120],
                                 "detail": ((f.get("resources") or [{}])[0].get("uid") or "")[:100]})
    findings.sort(key=lambda x: 0 if x["severity"] == "CRITICAL" else 1)
    report = {"run": run, "summary": {"provider": provider, "framework": framework or "all checks", **{k.lower(): v for k, v in counts.items()},
                                      "failed critical": sev["Critical"], "failed high": sev["High"], "failed medium": sev["Medium"], "failed low": sev["Low"]},
              "findings": findings, "tool": "prowler", "raw": str(outdir), "verdict": "PASS" if sev["Critical"] == 0 and sev["High"] == 0 else "FAIL"}
    if provider == "azure" and cfg["vars"].get("subscription_id"):
        report["summary"]["subscription"] = cfg["vars"]["subscription_id"]
    if fips_regions:
        report["summary"]["endpoints"] = f"FIPS (regions: {', '.join(fips_regions)})"
    path = save_report(env, "cloud", report)
    _panel(f"Cloud benchmark (prowler {framework or 'all'}) · {env.id}", report["summary"], findings, path,
           verdict=f"{report['verdict']} - {counts['FAIL']} failed checks")
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
            return True, f"{algo} (the recorded key could not be parsed, so its size was not checked)"
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
    """The cluster's nodes with what FIPS depends on (None: the cluster did not answer)."""
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
            add("platform", check, None, f"its Deployments in {ns} could not be read" if deps_ is None else f"no Deployment of release {release} in {ns}")
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
            add("platform", "velero: backups reach S3 through its FIPS endpoint", None, "the backup storage locations could not be read")
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
            add("platform", "karpenter: EC2NodeClasses select Bottlerocket FIPS AMIs", None, "the EC2NodeClasses could not be read")
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
                add("platform", check, None, "AMIs chosen by id, tag or name: the node rows show what its nodes run")


def fips(cloud, env, cfg: dict, outputs: dict, ctx=None, note: bool = True) -> Path:
    from . import platform as platformmod
    checks: list[dict] = []

    def add(area: str, name: str, ok: bool | None, detail: str = ""):
        checks.append({"area": area, "check": name, "status": "PASS" if ok else "INFO" if ok is None else "FAIL", "detail": detail})

    wanted = fips_env(cfg, outputs)
    add("config", "fips_mode enabled for the environment", wanted,
        "fips_mode=true" if wanted else "chosen at creation: cs setup <cloud> --var fips_mode=true (new environments only; they get an RSA-4096 SSH key)")
    add("ssh", "environment SSH key is FIPS-approved (RSA-4096; ECDSA only on GCP/VMware)", *_ssh_key_check(str(cfg.get("ssh_public_key") or ""), cloud.key))
    nodes: list[dict] | None = None
    cluster_note = ""
    if ctx is not None:
        try:
            nodes = _fips_nodes(ctx)
            cluster_note = "" if nodes is not None else "the cluster did not answer"
        except ui.Abort as e:   # kubectl is missing (and was not installed): the other layers are still verified
            cluster_note = tail_text(str(getattr(e, "msg", "") or e), 200)
            add("kubernetes", "cluster not checked", None, cluster_note)
            ctx = None
    # cloud layer
    if cloud.key == "aws":
        try:
            rendered = json.loads((env.stack_dir / "main.tf.json").read_text())
            add("cloud", "AWS provider uses FIPS endpoints", bool(rendered.get("provider", {}).get("aws", {}).get("use_fips_endpoint")), "provider.aws.use_fips_endpoint")
        except (OSError, ValueError):
            add("cloud", "AWS provider uses FIPS endpoints", None, "stack not rendered yet")
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
            add("kubernetes", "GKE nodes run Container-Optimized OS (FIPS-validated kernel crypto module, BoringCrypto)", True, "image_type COS_CONTAINERD")
    # hosts
    user, key = cloud.ssh_user(cfg), env.private_key_path(cfg)
    for name, ip in _hosts(cloud, env, cfg, outputs, ["bastion", "vpn", "k8s"], note=note):
        h = prov.Host(ip, user, key, name, env=env)
        probe = subprocess.run(h.ssh("cat /proc/sys/crypto/fips_enabled 2>/dev/null; echo ---; sudo sshd -T 2>/dev/null | "
                                     "grep -Ei '^(ciphers|kexalgorithms|macs|hostkeyalgorithms|pubkeyacceptedalgorithms|pubkeyacceptedkeytypes) ' ; echo ---; "
                                     "(openssl list -providers 2>/dev/null | grep -qi fips && echo openssl-fips) || (openssl md5 /dev/null >/dev/null 2>&1 || echo openssl-fips); "
                                     "echo ---; (pro status 2>/dev/null | grep -Ei 'fips' | head -2) || true"),
                               capture_output=True, text=True, timeout=60)
        if probe.returncode != 0 and not probe.stdout.strip():
            add("hosts", f"{name}: reachable over SSH", False, tail_text(probe.stderr, 160, lines=2) or f"ssh exited {probe.returncode}")
            continue
        parts = probe.stdout.split("---")
        state = parts[0].strip()
        add("hosts", f"{name}: kernel FIPS mode (fips_enabled=1)", state == "1", f"fips_enabled={state or 'absent'}")
        bad, settings = sshd_fips_problems(parts[1] if len(parts) > 1 else "")
        add("hosts", f"{name}: sshd offers only FIPS-approved algorithms", not bad if settings else None,
            (", ".join(bad[:6]) + (f" (+{len(bad) - 6} more)" if len(bad) > 6 else "")) if bad
            else (f"{', '.join(sorted(settings))} checked" if settings else "sshd -T unavailable"))
        add("hosts", f"{name}: OpenSSL FIPS provider active", "openssl-fips" in (parts[2] if len(parts) > 2 else ""), (parts[2].strip() if len(parts) > 2 else "")[:80])
        if len(parts) > 3 and parts[3].strip():
            add("hosts", f"{name}: Ubuntu Pro FIPS services", bool(re.search(r"\benabled\b", parts[3].lower())), parts[3].strip().replace("\n", " | ")[:120])
    # kubernetes + platform
    if ctx is not None:
        if nodes is None:
            add("kubernetes", "nodes not checked", None, cluster_note or "the cluster did not answer")
        if cloud.key == "aws" and nodes:
            add("kubernetes", "EKS nodes run a Bottlerocket FIPS variant", *_eks_nodes_row(nodes))   # from the live nodes
        for n in nodes or []:
            ok, detail = _node_fips(cloud, n)
            add("kubernetes", f"node {n['name']}: {n['os']}", ok, detail)
        if ctx.distro == "rke2":
            v = _kubectl(ctx, "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.kubeletVersion}").stdout.strip()
            add("kubernetes", "RKE2 (FIPS 140-2 compliant build: Go BoringCrypto)", True if wanted else None, v)
        elif ctx.distro == "kubeadm":
            add("kubernetes", "kubeadm binaries are not FIPS builds", False, "use kubernetes_distro=rke2 in FIPS environments")
        try:
            rel = platformmod.installed_releases(ctx)
        except platformmod.ClusterUnreachable as e:
            rel = {}
            add("platform", "platform items not checked", None, ui.clip(str(e), 200))
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
    verdict = "N/A" if not wanted else "PASS" if not failed else "FAIL"
    report = {"summary": {"fips_mode": wanted, "checks": len(checks), "pass": sum(1 for c in checks if c["status"] == "PASS"), "fail": len(failed), "info": sum(1 for c in checks if c["status"] == "INFO")},
              "findings": [{"status": c["status"], "severity": "HIGH" if c["status"] == "FAIL" else "INFO", "title": f"[{c['area']}] {c['check']}", "detail": c["detail"]} for c in checks],
              "checks": checks, "tool": "cloudseed", "verdict": verdict}
    path = save_report(env, "fips", report)
    rows = [f"{ui.style('✔', 'leaf', 'bold') if c['status'] == 'PASS' else ui.style('✖', 'rose', 'bold') if c['status'] == 'FAIL' else ui.style('○', 'muted')} "
            f"{ui.style(c['area'].ljust(11), 'muted')} {c['check']}   {ui.dim(str(c['detail']))}" for c in checks]
    tone = {"PASS": "leaf", "FAIL": "rose", "N/A": "seed"}[verdict]
    head = (f"N/A - {env.id} is not a FIPS environment (FIPS is chosen at creation); {len(failed)} of {len(checks)} checks would fail" if verdict == "N/A"
            else f"{verdict} - {report['summary']['pass']} passed, {len(failed)} failed, {report['summary']['info']} informational")
    rows += ["", ui.style(head, tone, "bold"), ui.dim(f"report: {path}")]
    ui.panel(f"FIPS 140 verification · {env.id}", rows, accent=tone)
    return path


# ---------------------------------------------------------------- everything

def _verdict_of(path: Path) -> str:
    try:
        return str(json.loads(path.read_text()).get("verdict") or "?")
    except (OSError, ValueError):
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
    rows: list = [(ui.style(v, "leaf" if v == "PASS" else "seed" if v == "N/A" else "rose", "bold"), str(p)) for p, v in verdicts]
    rows += [(ui.style("ERROR", "rose", "bold"), f"{label}: did not complete (see above)") for label in errors]
    clean = not errors and all(v in ("PASS", "N/A") for _, v in verdicts)
    ui.panel(f"Scan summary · {env.id}", rows or [ui.dim("nothing ran")], accent="leaf" if clean and done else "rose")
    return done


def show_reports(env, last: int = 10) -> None:
    rows = []
    for p in (reports(env)[-last:] if last > 0 else []):
        try:
            r = json.loads(p.read_text())
            v = str(r.get("verdict") or "")
            rows.append((p.stem, (ui.style(v, "leaf" if v == "PASS" else "seed" if v == "N/A" else "rose", "bold") + "  " if v else "")
                         + "  ".join(f"{k}={val}" for k, val in list(r.get("summary", {}).items())[:6])))
        except ValueError:
            rows.append((p.stem, ""))
    ui.panel(f"Scan reports · {env.id}  ({_reports_dir(env)})", rows or [ui.dim("none yet  (cs scan all)")])
