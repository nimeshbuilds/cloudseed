"""Disaster recovery: Velero backups, restores, schedules and an automated DR drill with a verdict.

`cs dr` drives the Velero server that `cs platform install velero` deploys (cloud bucket + identity created on demand
by the cloudseed stack, MinIO on local clusters). The `velero` CLI is fetched on demand (SHA256-verified against the
release CHECKSUM file), pinned to the server version - on the user's own run only (a terminal, or -y with
--auto-approve), never from an agent session; `cs dr status` and `cs dr backups` read Velero's objects with kubectl
and need no CLI at all. Velero's `--wait` exits 0 even when a backup or restore failed, so every command reads the
final phase and only reports success for a Completed one.
`cs dr test` is the end-to-end drill: create a sample workload, back it up, delete it, restore it, verify, report.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import io
import json
import os
import platform as _platform
import re
import secrets
import signal
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import audit, deps, paths, ui

VELERO_DEFAULT = "v1.18.2"  # appVersion of the pinned chart (velero 12.2.0); used when the server image has no version tag
# the project moved from vmware-tanzu to velero-io; the old URL only works through GitHub's rename redirect
RELEASES = "https://github.com/velero-io/velero/releases/download"
UNDO_LABEL = ("cloudseed.io/undo-point", "true")   # cloudseed's own pre-change backups (undo.VELERO_LABEL)

DRILL_NS = "cloudseed-dr-test"
# The web workload is agnhost serve-hostname (a single "/" handler; netexec would expose /shell and /upload),
# non-root on a read-only root filesystem.
DRILL_MANIFEST = """apiVersion: v1
kind: Namespace
metadata: {name: %(ns)s, labels: {cloudseed.io/dr: drill}}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: drill-data, namespace: %(ns)s}
data: {token: "%(token)s", created: "%(created)s"}
---
apiVersion: v1
kind: Secret
metadata: {name: drill-secret, namespace: %(ns)s}
type: Opaque
stringData: {token: "%(token)s"}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: drill, namespace: %(ns)s, labels: {app: drill}}
spec:
  replicas: 2
  selector: {matchLabels: {app: drill}}
  template:
    metadata: {labels: {app: drill}}
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: web
          image: registry.k8s.io/e2e-test-images/agnhost:2.53
          args: ["serve-hostname", "--port=8080"]
          ports: [{containerPort: 8080}]
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          readinessProbe: {httpGet: {path: /healthz, port: 8080}, periodSeconds: 2}
          resources: {requests: {cpu: 20m, memory: 32Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: drill, namespace: %(ns)s}
spec:
  selector: {app: drill}
  ports: [{port: 8080, targetPort: 8080}]
"""
# The writer pod only sleeps: the volume token is written once with `kubectl exec` after the pod is ready, so a restored
# pod can never recreate it; only a real volume restore brings it back. It passes the "restricted" Pod Security Standard
# (enforced cluster-wide by RKE2's CIS profile): non-root, no capabilities; fsGroup makes a CSI volume writable for it
# (local-path volumes are created world-writable).
DRILL_PVC = """apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: drill-data, namespace: %(ns)s}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 1Gi}}
---
apiVersion: v1
kind: Pod
metadata: {name: drill-writer, namespace: %(ns)s, labels: {app: drill-writer}}
spec:
  restartPolicy: Always
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: w
      image: busybox:1.36
      command: ["sh", "-c", "sleep 1000000"]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts: [{name: data, mountPath: /data}]
  volumes: [{name: data, persistentVolumeClaim: {claimName: drill-data}}]
"""
# The drill's backup expires by itself after this (without --keep): Velero refuses to delete a backup that is still in
# progress, so one the drill could not delete after a Ctrl-C is still garbage-collected by Velero.
DRILL_BACKUP_TTL = "24h"
BACKUP_DONE = ("Completed", "PartiallyFailed", "Failed", "FailedValidation")   # phases a backup can be deleted in
SETTLE_S = 120   # how long an interrupted drill waits for its running backup to finish before it deletes it
# Velero parses schedules with robfig/cron ParseStandard: 5 fields or a descriptor, optionally after a CRON_TZ=/TZ= zone
CRON_RE = re.compile(r"^((CRON_)?TZ=\S+\s+)?(@(yearly|annually|monthly|weekly|daily|midnight|hourly)|@every\s+\S+|(\S+\s+){4}\S+)$")
# Velero's --ttl is a Go duration (time.ParseDuration) without a sign: 720h, 1.5h, 90m30s, 500ms, 0 - no day unit
GO_DURATION = re.compile(r"0|((\d+(\.\d*)?|\.\d+)(ns|us|\u00b5s|\u03bcs|ms|s|m|h))+")
TTL_DEFAULT = "720h"   # Velero's own default: 30 days


def kubectl_path() -> str:
    """kubectl, installed only with consent like every other cluster command (asked on a terminal; with -y only after
    --auto-approve, else exit 2 with `cloudseed install kubectl`) - never a TypeError from running [None, ...]."""
    found = deps.find("kubectl")
    if found:
        return found
    from . import services
    return services.ensure_tool("kubectl", "to talk to the cluster", default=True)


def _tail(text, n: int = 200, lines: int = 1) -> str:
    from .scan import tail_text
    return tail_text(text, n, lines)


def _kubectl(ctx, *args: str, input: str | None = None, timeout: int = 180) -> subprocess.CompletedProcess:
    kubectl = kubectl_path()
    try:
        return subprocess.run([kubectl, *args], env=ctx.procenv(), capture_output=True, text=True, input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(["kubectl", *args], 124, "", f"kubectl {' '.join(args[:3])} timed out after {timeout}s")


def _memo(ctx, key: str, value):
    try:
        setattr(ctx, key, value)
    except AttributeError:
        pass
    return value


def _kubectl_hint(ctx, *args: str) -> str:
    """A kubectl command the user can paste as is: `cs kubectl` picks this environment's kubeconfig."""
    env = getattr(ctx, "env", None)
    where = f"{ctx.target} --env {env.name} " if env is not None and getattr(ctx, "target", None) else ""
    return f"cs kubectl {where}" + " ".join(args)


# Where `kubectl exec|logs` reach the Velero server: its Service (the metrics Service, which the catalog always enables),
# whose selector carries the server pod's own `name: velero` label. Not `deploy/velero`: the chart's Deployment selector
# (app.kubernetes.io/name + instance) also matches the node-agent DaemonSet's pods, and kubectl then picks one of those
# ("container velero is not valid for pod node-agent-..."). A name, not a looked-up pod: hints read nothing from the cluster.
SERVER = "svc/velero"


def _storage_config(ctx) -> dict:
    """spec.config of the default BackupStorageLocation (remembered from the last location check). Read with kubectl
    when nothing is remembered yet, like `cs dr status`: a hint never needs (or downloads) the velero CLI."""
    cfg = getattr(ctx, "_velero_bsl_config", None)
    if cfg is None:
        try:
            locations, problem = _objects(ctx, "backupstoragelocations")
        except (OSError, ui.Abort):   # no kubectl (and none may be installed): the location is unknown
            locations, problem = [], "kubectl unavailable"
        cfg = _memo(ctx, "_velero_bsl_config", {}) if problem else _remember_location(ctx, locations)
    return cfg if isinstance(cfg, dict) else {}


def in_cluster_storage(ctx) -> bool:
    """Whether the backup storage only answers inside the cluster: the MinIO of a local cluster (s3Url
    http://minio.minio.svc:9000, no publicUrl). `velero <kind> describe` and `velero <kind> logs` download results, logs
    and volume info through that URL, so from this machine they fail ('lookup minio.minio.svc: no such host')."""
    cfg = _storage_config(ctx)
    url = str(cfg.get("publicUrl") or cfg.get("s3Url") or "")
    if not url:
        return not cfg and getattr(ctx, "target", "") == "vmware"   # location unreadable: local clusters use the in-cluster MinIO
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    return host.endswith((".svc", ".svc.cluster.local", ".cluster.local")) or (bool(host) and "." not in host and host != "localhost")


INSPECT_KINDS = ("backup", "restore")   # what `cs dr describe|logs` shows
INSPECT_VERBS = ("describe", "logs")


def _dr_hint(ctx, *words: str) -> str:
    """A `cs dr` command line for this environment's cluster, to paste as is (`cs dr describe backup b1 vmware --env
    lab`). A word that is itself a cloud key (a backup named 'aws') would be read as the target: --cloud then names it."""
    env = getattr(ctx, "env", None)
    target = getattr(ctx, "target", None)
    where = ""
    if env is not None and target:
        clash = any(w in ("aws", "gcp", "azure", "vmware") for w in words)
        where = f" {'--cloud ' if clash else ''}{target} --env {env.name}"
    return "cs dr " + " ".join(words) + where


def velero_hint(ctx, *args: str) -> str:
    """The command that runs `velero <args>` for this cluster, never relying on a velero CLI on PATH or on the current
    kube context: `velero backup|restore describe|logs <name>` is `cs dr describe|logs backup|restore <name>` (which
    picks the velero CLI here, or the velero pod when the backup storage only answers inside the cluster); anything else
    (delete ...) runs in the velero pod (its /velero binary), which reaches the API and the storage wherever it is."""
    if len(args) >= 3 and args[0] in INSPECT_KINDS and args[1] in INSPECT_VERBS:
        extra = [a for a in args[3:] if a == "--details" and args[1] == "describe"]
        return _dr_hint(ctx, args[1], args[0], args[2], *extra)
    return _kubectl_hint(ctx, "-n", "velero", "exec", SERVER, "-c", "velero", "--", "/velero", *args)


def show(ctx, verb: str, kind: str, name: str, details: bool = False) -> int:
    """`cs dr describe|logs <backup|restore> <name> [--details]`: velero's own view of one backup or restore. It runs the
    velero CLI of the server's version here with this environment's kubeconfig - or, when the backup storage only answers
    inside the cluster (MinIO on a local cluster: describe --details and logs download from it) or no velero CLI may be
    fetched in this run (an agent session, -y without --auto-approve), the same command in the velero pod. Returns
    velero's exit code."""
    if verb not in INSPECT_VERBS or kind not in INSPECT_KINDS:
        raise ui.Abort(f"cs dr {'|'.join(INSPECT_VERBS)} {'|'.join(INSPECT_KINDS)} <name>", code=2)
    if not installed(ctx):
        raise ui.Abort("Velero is not installed on this cluster. Install it (bucket + identity are created for you): cs platform install velero")
    args = [kind, verb, name] + (["--details"] if details and verb == "describe" else [])
    cmd = None
    if not in_cluster_storage(ctx):
        try:
            cmd = [ensure_cli(ctx), "-n", "velero", *args]
        except ui.Abort:   # not fetched in this run (agent session, -y) or not downloadable: the velero pod has the binary
            ui.info("No velero CLI of the server's version here (and none is fetched in this run): running velero in the velero pod.")
    if cmd is None:
        cmd = [kubectl_path(), "-n", "velero", "exec", SERVER, "-c", "velero", "--", "/velero", "-n", "velero", *args]
        print(ui.dim("  $ " + _kubectl_hint(ctx, "-n", "velero", "exec", SERVER, "-c", "velero", "--", "/velero", *args)))
    else:
        print(ui.dim("  $ velero " + " ".join(args)))
    audit.write("$ " + " ".join(cmd))
    from . import secrets as _csecrets
    if _csecrets.redact_enabled():   # an agent session: velero's output (object specs, logs) is redacted line by line
        return _csecrets.run_redacted(cmd, env=ctx.procenv())
    return subprocess.call(cmd, env=ctx.procenv())


def installed(ctx) -> bool:
    return _kubectl(ctx, "-n", "velero", "get", "deploy", "velero").returncode == 0


def image_version(img: str) -> str | None:
    """vX.Y.Z from a container image reference (digest, registry port and suffixes like -fips ignored); None if it has none."""
    ref = img.strip().split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else ""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", tag)
    return f"v{m.group(1)}.{m.group(2)}.{m.group(3)}" if m else None


def server_version(ctx) -> str:
    cached = getattr(ctx, "_velero_version", None)
    if cached:
        return cached
    img = _kubectl(ctx, "-n", "velero", "get", "deploy", "velero", "-o", "jsonpath={.spec.template.spec.containers[0].image}").stdout.strip()
    ver = image_version(img)
    if not ver:
        ver = VELERO_DEFAULT
        if img:
            ui.info(f"The Velero image '{img}' carries no version tag; using the velero CLI {ver}.")
    return _memo(ctx, "_velero_version", ver)


def _cli_version(binary: Path) -> tuple[int, ...] | None:
    try:
        out = subprocess.run([str(binary), "version", "--client-only"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"Version:\s*v?(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(x) for x in m.groups()) if m else None


def _get(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "cloudseed"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _download_cli(want: str, binary: Path) -> None:
    sysname = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(_platform.system())
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(_platform.machine().lower())
    if not sysname or not arch:
        raise ui.Abort(f"There is no velero CLI build for {_platform.system()}/{_platform.machine()}; put a velero {want} binary at {binary}.")
    asset = f"velero-{want}-{sysname}-{arch}.tar.gz"
    with ui.Spinner(f"Fetching velero CLI {want}") as sp:
        blob = _get(f"{RELEASES}/{want}/{asset}", 300)
        sums = _get(f"{RELEASES}/{want}/CHECKSUM", 60).decode("utf-8", "replace")
        expected = next((ln.split()[0] for ln in sums.splitlines() if len(ln.split()) == 2 and ln.split()[1].lstrip("*") == asset), None)
        if not expected:
            raise ui.Abort(f"The velero {want} release publishes no checksum for {asset}; refusing to install it unverified.")
        if hashlib.sha256(blob).hexdigest() != expected.lower():
            raise ui.Abort(f"Checksum mismatch for {asset} (expected {expected[:16]}...); the download was discarded.")
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.isfile() and os.path.basename(m.name) in ("velero", "velero.exe")), None)
            fh = tar.extractfile(member) if member is not None else None
            if fh is None:
                raise ui.Abort(f"{asset} contains no velero binary.")
            data = fh.read()
        paths.BIN_DIR.mkdir(parents=True, exist_ok=True)
        tmp = binary.with_name(binary.name + ".tmp")
        tmp.write_bytes(data)
        tmp.chmod(0o755)
        os.replace(tmp, binary)
        sp.done_text = f"velero CLI {want} ready (SHA256 verified)"


def _fetch_refusal() -> str:
    """Why the velero CLI may not be downloaded in this run ('' when it may): only the user's own run fetches it - on a
    terminal, or with -y after --auto-approve (MCP passes it for confirm=true actions only) - never an agent session."""
    from . import services
    if deps.agent_session():
        return "this is an agent session, and cloudseed never installs software for an agent"
    if ui.interactive() or services._install_approved():
        return ""
    return "a run with -y downloads it only when approved up front (--auto-approve)"


def _matching_cli_on_path(binary: Path, want_mm: tuple) -> str | None:
    """A velero on PATH (not the one in ~/.cloudseed/bin) of the server's minor version, or None."""
    for d in deps.path_env()["PATH"].split(os.pathsep):
        cand = Path(d) / binary.name if d else None
        if cand is None or not cand.is_file() or not os.access(cand, os.X_OK):
            continue
        try:
            if cand.resolve() == binary.resolve():
                continue
        except OSError:
            continue
        v = _cli_version(cand)
        return str(cand) if v and v[:2] == want_mm else None   # the first one on PATH is what the user runs
    return None


def ensure_cli(ctx) -> str:
    """The velero CLI must match the server's minor version; fetch the release binary into ~/.cloudseed/bin."""
    cached = getattr(ctx, "_velero_cli", None)
    if cached:
        return cached
    want = server_version(ctx)
    binary = paths.BIN_DIR / ("velero.exe" if _platform.system() == "Windows" else "velero")
    have = _cli_version(binary) if binary.exists() else None
    want_mm = tuple(int(x) for x in want.lstrip("v").split(".")[:2])
    if have and have[:2] == want_mm:
        return _memo(ctx, "_velero_cli", str(binary))
    refusal = _fetch_refusal()
    if refusal:
        other = _matching_cli_on_path(binary, want_mm)
        if other:   # e.g. a Homebrew velero of the server's minor version: nothing to download
            return _memo(ctx, "_velero_cli", other)
        if have:
            ui.warn(f"The velero CLI here is v{'.'.join(map(str, have))}, the server runs {want}; using it anyway ({refusal}).")
            return _memo(ctx, "_velero_cli", str(binary))
        raise ui.Abort(f"The velero CLI {want} is not installed at {binary}: {refusal}. Run the same `cs dr` command once in your "
                       f"own terminal (it fetches the SHA256-verified release), or put a velero {want} binary there.", code=2)
    try:
        _download_cli(want, binary)
    except (urllib.error.URLError, OSError, TimeoutError, tarfile.TarError, ValueError) as e:
        if have:
            ui.warn(f"Could not fetch the velero CLI {want} ({e}); using the installed v{'.'.join(map(str, have))} instead.")
            return _memo(ctx, "_velero_cli", str(binary))
        raise ui.Abort(f"Could not download the velero CLI {want} ({e}). Check network/proxy access to github.com, "
                       f"or put a velero {want} binary at {binary}.")
    return _memo(ctx, "_velero_cli", str(binary))


def _velero(ctx, *args: str, check: bool = True, stream: bool = False, timeout: int = 1800, quiet: bool = False) -> subprocess.CompletedProcess:
    cmd = [ensure_cli(ctx), "-n", "velero", *args]
    if not quiet:
        print(ui.dim("  $ velero " + " ".join(args)))
    audit.write("$ " + " ".join(cmd))
    if stream:
        child = subprocess.Popen(cmd, env=ctx.procenv(), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = []
        interrupts = 0
        while True:
            try:
                for line in child.stdout:  # type: ignore[union-attr]
                    print("    " + line, end="", flush=True)
                    audit.write(line)
                    out.append(line)
                child.wait()
                break
            except KeyboardInterrupt:
                # keep reading until velero has stopped: walking away from the pipe would kill it with SIGPIPE mid-write
                interrupts += 1
                _stop_child(child, interrupts)
        if child.stdout is not None:
            child.stdout.close()
        if interrupts:
            raise KeyboardInterrupt
        proc = subprocess.CompletedProcess(cmd, child.returncode, "".join(out), "")
    else:
        try:
            proc = subprocess.run(cmd, env=ctx.procenv(), capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc = subprocess.CompletedProcess(cmd, 124, "", f"velero {' '.join(args[:2])} timed out after {timeout}s")
    if check and proc.returncode != 0:
        raise ui.Abort(f"velero {' '.join(args[:2])} failed: {velero_error(proc)}")
    return proc


# velero reports a failure as "An error occurred: ..." (its own errors) or "Error: ..." (cobra: a bad flag or argument,
# followed by the whole usage text); the message is that line, never the flag help printed after it
_VELERO_ERROR = re.compile(r"^(?:An error occurred|Error):\s*(\S.*)$")


def velero_error(proc: subprocess.CompletedProcess) -> str:
    """The message of a failed velero command: its last 'An error occurred:' / 'Error:' line (usage text dropped),
    else the tail of its output."""
    text = f"{proc.stderr or ''}\n{proc.stdout or ''}"
    found = [m.group(1).strip() for m in (_VELERO_ERROR.match(ln.strip("\r")) for ln in text.splitlines()) if m]
    if found:
        return ui.clip(found[-1], 600)
    return _tail(proc.stderr or proc.stdout, 800, lines=4) or f"exit code {proc.returncode}"


def _stop_child(child: subprocess.Popen, count: int) -> None:
    """Ctrl-C while velero streams: the first one stops its --wait (the backup/restore itself goes on in the cluster;
    velero usually got the same SIGINT from the terminal already), a second kills it."""
    try:
        if count == 1:
            child.send_signal(signal.SIGINT)
        else:
            child.kill()
    except (ProcessLookupError, OSError, ValueError):   # already gone; ValueError: SIGINT is not supported on Windows
        try:
            child.kill()
        except OSError:
            pass


def _items(text: str) -> list[dict]:
    """velero ... -o json prints a List, or the bare object when there is exactly one."""
    try:
        j = json.loads(text or "{}")
    except ValueError:
        return []
    items = (j.get("items", [j]) if isinstance(j, dict) else j) or []
    return [i for i in items if isinstance(i, dict) and i.get("metadata")]


def _status(ctx, kind: str, name: str) -> dict:
    proc = _velero(ctx, kind, "get", name, "-o", "json", check=False, quiet=True)
    try:
        st = json.loads(proc.stdout or "{}").get("status") or {}
    except (ValueError, AttributeError):
        st = {}
    return st if isinstance(st, dict) else {}


def _counts(st: dict) -> str:
    return f"{st.get('errors', 0) or 0} error(s), {st.get('warnings', 0) or 0} warning(s)"


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def parse_result_errors(text: str, limit: int = 5) -> list[str]:
    """The messages of the 'Errors:' block of `velero <kind> describe --details`, in order ('Velero:' / 'Cluster:' labels
    dropped, a namespace's messages keep their '<namespace>:' prefix). Velero keeps them only in the object store: the
    Backup/Restore object itself has just the counts."""
    lines = _ANSI.sub("", text or "").splitlines()
    out: list[str] = []
    for i, ln in enumerate(lines):
        m = re.match(r"^Errors:\s*(.*)$", ln)
        if not m:
            continue
        if m.group(1).strip():   # "<error getting errors: ...>": the results could not be downloaded from here
            return []
        for body in lines[i + 1:]:
            if not body.strip() or not body[:1].isspace():
                break
            msg = " ".join(body.split())
            label = re.match(r"^(Velero|Cluster):\s*(.*)$", msg)
            if label:
                msg = label.group(2)
            if not msg or msg == "<none>" or re.match(r"^\S+:\s*(<none>)?$", msg):
                continue
            out.append(msg)
        break
    return out[:limit]


def result_errors(ctx, kind: str, name: str, limit: int = 3) -> list[str]:
    """The first error messages of a finished backup/restore, read the way that works for this cluster: with the velero
    CLI here, or - when the storage only answers inside the cluster (MinIO on VMware) - with the velero binary of the
    Velero pod. Best effort: [] when they cannot be read."""
    try:
        if in_cluster_storage(ctx):
            proc = _kubectl(ctx, "-n", "velero", "exec", SERVER, "-c", "velero", "--", "/velero", "-n", "velero",
                            kind, "describe", name, "--details", timeout=120)
        else:
            proc = _velero(ctx, kind, "describe", name, "--details", check=False, quiet=True, timeout=120)
    except (OSError, ui.Abort):
        return []
    return parse_result_errors(proc.stdout if proc.returncode == 0 else "", limit)


def _first_errors(ctx, kind: str, name: str, st: dict) -> str:
    if not (st.get("errors") or 0):
        return ""
    msgs = result_errors(ctx, kind, name)
    return (" First error(s): " + " | ".join(ui.clip(m, 220) for m in msgs) + ".") if msgs else ""


def _finish(ctx, kind: str, name: str, allow_partial: bool) -> str:
    """Read the final phase after `velero <kind> create --wait` (which exits 0 whatever happened). Returns the phase or aborts."""
    st = _status(ctx, kind, name)
    phase = str(st.get("phase", ""))
    what = kind.capitalize()
    hint = f"{velero_hint(ctx, kind, 'describe', name, '--details')}  ·  {velero_hint(ctx, kind, 'logs', name)}"
    if phase == "Completed":
        return phase
    if phase == "PartiallyFailed":
        errors = _first_errors(ctx, kind, name, st)
        if allow_partial:
            ui.warn(f"{what} {name} finished PartiallyFailed ({_counts(st)}): some items were not restored.{errors} Details: {hint}")
            return phase
        raise ui.Abort(f"{what} {name} finished PartiallyFailed ({_counts(st)}): some items were NOT saved.{errors} It is kept (restoring it "
                       f"brings back what it holds; remove it with: {velero_hint(ctx, kind, 'delete', name, '--confirm')}). Details: {hint}")
    if phase in ("Failed", "FailedValidation"):
        why = st.get("failureReason") or "; ".join(str(v) for v in st.get("validationErrors") or [])
        if not why:
            msgs = result_errors(ctx, kind, name)
            why = " | ".join(ui.clip(m, 220) for m in msgs) or "see the logs"
        raise ui.Abort(f"{what} {name} {phase}: {why}. Details: {hint}")
    raise ui.Abort(f"{what} {name} has not finished (phase {phase or 'unknown'}); follow it with: {velero_hint(ctx, kind, 'describe', name)}")


def backup_usable(ctx, name: str) -> bool:
    """Whether a finished backup can serve as a restore point (undo points): Completed, or PartiallyFailed with a warning."""
    st = _status(ctx, "backup", name)
    phase = str(st.get("phase", ""))
    if phase == "Completed":
        return True
    if phase == "PartiallyFailed":
        ui.warn(f"Velero backup {name} is PartiallyFailed ({_counts(st)}); the undo point restores only what it holds.")
        return True
    ui.warn(f"Velero backup {name} ended {phase or 'in an unknown state'}"
            + (f" ({st.get('failureReason')})" if st.get("failureReason") else "") + f"; it is not usable as an undo point ({velero_hint(ctx, 'backup', 'describe', name, '--details')}).")
    return False


def require(ctx) -> None:
    if not installed(ctx):
        raise ui.Abort("Velero is not installed on this cluster. Install it (bucket + identity are created for you): cs platform install velero")
    wait_location(ctx)


def _location(ctx) -> tuple[dict, str]:
    proc = _velero(ctx, "backup-location", "get", "default", "-o", "json", check=False, quiet=True)
    try:
        loc = json.loads(proc.stdout or "{}")
        st = loc.get("status") or {}
        if proc.returncode == 0 and isinstance(loc.get("spec"), dict):
            cfg = loc["spec"].get("config") or {}
            _memo(ctx, "_velero_bsl_config", cfg if isinstance(cfg, dict) else {})
    except (ValueError, AttributeError):
        st = {}
    st = st if isinstance(st, dict) else {}
    return st, str(st.get("message") or st.get("phase") or _tail(proc.stderr, 200))


def wait_location(ctx, timeout: int = 180) -> None:
    """The default BackupStorageLocation must be Available (bucket reachable, credentials valid) before anything else makes sense."""
    ensure_cli(ctx)
    st, last = _location(ctx)
    if st.get("phase") == "Available":
        return
    deadline = time.time() + timeout
    unavailable_since = None
    with ui.Spinner("Waiting for Velero's backup storage location to become Available") as sp:
        while time.time() < deadline:
            phase = st.get("phase") or "not validated yet"
            sp.update(f"Waiting for Velero's backup storage location ({phase}{': ' + last[:90] if last and last != phase else ''})")
            if st.get("phase") == "Unavailable" and st.get("lastValidationTime"):
                # a real validation result: Velero re-validates about once a minute, give it one more round
                unavailable_since = unavailable_since or time.time()
                if time.time() - unavailable_since > 70:
                    break
            time.sleep(5)
            st, last = _location(ctx)
            if st.get("phase") == "Available":
                sp.done_text = "Velero backup storage location is Available"
                return
    raise ui.Abort(f"Velero's backup storage location is not Available: {last or 'unknown'}. "
                   f"Check the bucket/credentials (cs dr status; {_kubectl_hint(ctx, '-n', 'velero', 'logs', SERVER, '-c', 'velero')}) "
                   "or re-run: cs platform install velero --upgrade")


# ---------------------------------------------------------------- commands

def rto_text(rep: dict) -> str | None:
    """The measured RTO of a drill report ('34.5s'), or None when nothing was measured: only a PASS drill recovered
    anything (failed and interrupted drills - and reports written before this rule - store 0 or a failed restore's time)."""
    if not isinstance(rep, dict) or str(rep.get("verdict", "")).upper() != "PASS":
        return None
    v = rep.get("rto_s")
    return f"{v}s" if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _drill_row(env) -> str:
    last = last_report(env)
    if not last:
        return ui.dim("none yet  (cs dr test)")
    try:
        rep = json.loads(last.read_text())
    except (OSError, ValueError):
        return last.name
    if not isinstance(rep, dict):
        return last.name
    v = str(rep.get("verdict", "?"))
    rto = rto_text(rep)
    return (ui.style(v, "leaf" if v == "PASS" else "rose", "bold") + (f" · RTO {rto}" if rto else " · RTO not measured")
            + f" · run {rep.get('run', '?')}" + (" · with a volume" if rto and rep.get("volume_tested") else "") + ui.dim("  (cs dr test to re-run)"))


def when(ts) -> str:
    """'2026-09-24 06:12 UTC' from a Kubernetes RFC 3339 UTC timestamp ('-' when there is none)."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(:\d{2})?(\.\d+)?Z$", str(ts or ""))
    return f"{m.group(1)} {m.group(2)} UTC" if m else (str(ts) if ts else "-")


def _objects(ctx, plural: str) -> tuple[list[dict], str]:
    """Velero objects of one kind read with kubectl: `cs dr status` / `cs dr backups` need no velero CLI (nothing to
    download - they work offline and from agent sessions) and work while the storage location is down.
    Returns (items, problem) - problem is the error text when they could not be read."""
    proc = _kubectl(ctx, "-n", "velero", "get", f"{plural}.velero.io", "-o", "json", timeout=60)
    if proc.returncode != 0:
        return [], _tail(proc.stderr or proc.stdout, 200) or f"kubectl exited {proc.returncode}"
    return _items(proc.stdout), ""


def _started(obj: dict) -> str:
    return str((obj.get("status") or {}).get("startTimestamp") or (obj.get("metadata") or {}).get("creationTimestamp") or "")


def _newest_first(items: list[dict]) -> list[dict]:
    """By start time, newest first (the API lists them by name)."""
    return sorted(items, key=_started, reverse=True)


def _undo_point(obj: dict) -> bool:
    return ((obj.get("metadata") or {}).get("labels") or {}).get(UNDO_LABEL[0]) == UNDO_LABEL[1]


def _remember_location(ctx, locations: list[dict]) -> dict:
    """The default location's config, for velero_hint (so a hint never needs the velero CLI)."""
    cfg: dict = {}
    for b in locations:
        if (b.get("metadata") or {}).get("name") == "default" and isinstance(b.get("spec"), dict):
            cfg = b["spec"].get("config") or {}
    return _memo(ctx, "_velero_bsl_config", cfg if isinstance(cfg, dict) else {})


def _backup_brief(b: dict) -> str:
    return f"{(b.get('metadata') or {}).get('name')} ({(b.get('status') or {}).get('phase') or 'New'}, {when(_started(b))})"


def status(ctx) -> None:
    """The DR panel. It never waits: an Unavailable storage location is exactly what this panel has to show."""
    if not installed(ctx):
        raise ui.Abort("Velero is not installed on this cluster. Install it (bucket + identity are created for you): cs platform install velero")
    rows: list = [("Velero", server_version(ctx))]
    locations, problem = _objects(ctx, "backupstoragelocations")
    _remember_location(ctx, locations)
    unavailable = False
    if not locations:
        rows.append(("locations", ui.style(problem or "none", "rose")))
        unavailable = True
    for b in locations:
        spec, st = b.get("spec") or {}, b.get("status") or {}
        phase = str(st.get("phase") or "")
        if phase == "Available":
            shown = ui.style(phase, "leaf")
        elif not phase:
            shown = ui.dim("validating...")
        else:
            shown, unavailable = ui.style(phase, "rose"), True
        text = (f"{spec.get('provider')} {(spec.get('objectStorage') or {}).get('bucket')}  {shown}"
                + ui.dim(f"  last validated {when(st.get('lastValidationTime'))}"))
        if phase not in ("Available", "") and st.get("message"):
            text += "  " + ui.style(ui.clip(str(st["message"]), 400), "rose")
        rows.append((f"location {b['metadata'].get('name', '?')}", text))
    agents = _kubectl(ctx, "-n", "velero", "get", "ds", "node-agent", "-o", "jsonpath={.status.numberReady}/{.status.desiredNumberScheduled}").stdout.strip()
    rows.append(("node agent", f"{agents or '-'} ready (file-system volume backups)"))
    items, problem = _objects(ctx, "backups")
    if problem:
        rows.append(("backups", ui.style(problem, "rose")))
    else:
        items = _newest_first(items)
        ours, undo_points = [b for b in items if not _undo_point(b)], [b for b in items if _undo_point(b)]
        shown = ", ".join(_backup_brief(b) for b in ours[:5]) + (f", ... {len(ours) - 5} older (cs dr backups)" if len(ours) > 5 else "")
        rows.append(("backups", f"{len(ours)}  " + ui.dim(shown or "none yet  (cs dr backup [name] [--namespaces a,b])")))
        if undo_points:
            rows.append(("undo points", f"{len(undo_points)}  " + ui.dim(f"cloudseed's pre-change backups (cs undo); newest {_backup_brief(undo_points[0])}")))
    schedules, problem = _objects(ctx, "schedules")
    for s in schedules:
        spec, st = s.get("spec") or {}, s.get("status") or {}
        phase = str(st.get("phase") or "")
        text = (f"{spec.get('schedule', '?')} · keep {(spec.get('template') or {}).get('ttl') or '720h'} · last backup "
                + (when(st.get("lastBackup")) if st.get("lastBackup") else "never")
                + (ui.dim("  paused") if spec.get("paused") else "") + ("" if phase in ("Enabled", "") else "  " + ui.style(phase, "rose")))
        rows.append((f"schedule {s['metadata'].get('name', '?')}", text))
    if not schedules:
        rows.append(("schedules", ui.style(problem, "rose") if problem else ui.dim("none  (cs dr schedule nightly --cron '0 2 * * *')")))
    rows.append(("last drill", _drill_row(ctx.env)))
    ui.panel(f"Disaster recovery · {ctx.env.id}", rows, accent="rose" if unavailable else "brand")
    if unavailable:
        print(ui.style("  Backups cannot run until the location is Available.", "rose"))
        print(ui.dim(f"  Look at: {_kubectl_hint(ctx, '-n', 'velero', 'logs', SERVER, '-c', 'velero')}   ·   repair: cs platform install velero --upgrade"))
    print(ui.dim("  cs dr backup [name] [--namespaces a,b]   ·   cs dr restore <backup>   ·   cs dr backups"))
    print(ui.dim("  cs dr schedule <name> --cron '0 2 * * *'   ·   cs dr test   ·   cs dr describe|logs backup|restore <name>"))


def _namespaces(ctx, namespaces: str | None, strict: bool = True) -> str | None:
    """--namespaces as Velero gets it ("a,b": blanks and empty items dropped). Plain names must exist on the cluster: an
    unknown one makes Velero end the backup PartiallyFailed, with the reason only in its logs. Globs (shop-*) are Velero's
    to match. strict=False (a schedule, whose namespaces may come later) only warns."""
    if namespaces is None:
        return None
    names = [n.strip() for n in namespaces.split(",") if n.strip()]
    if not names:
        raise ui.Abort(f"--namespaces '{namespaces}' names no namespace: give a comma-separated list, e.g. --namespaces shop,payments", code=2)
    plain = [n for n in names if not any(c in n for c in "*?[]")]
    if plain:
        proc = _kubectl(ctx, "get", "ns", "-o", "jsonpath={.items[*].metadata.name}", timeout=60)
        have = proc.stdout.split() if proc.returncode == 0 else []
        missing = [n for n in plain if n not in have] if have else []   # cannot list them: Velero reports it
        if missing:
            near = {n: difflib.get_close_matches(n, have, n=1) for n in missing}
            text = ", ".join(n + (f" (did you mean {near[n][0]}?)" if near[n] else "") for n in missing)
            if strict:
                raise ui.Abort(f"Namespace(s) not on the cluster: {text}. Nothing was backed up. The cluster has: "
                               f"{ui.clip(', '.join(have), 300)}", code=2)
            ui.warn(f"Namespace(s) not on the cluster yet: {text}. The schedule's backups end PartiallyFailed until they exist.")
    return ",".join(names)


def backup(ctx, name: str | None, namespaces: str | None, wait: bool = True) -> str:
    namespaces = _namespaces(ctx, namespaces)
    require(ctx)
    name = name or f"cloudseed-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}"
    args = ["backup", "create", name]
    if namespaces:
        args += ["--include-namespaces", namespaces]
    if wait:
        args.append("--wait")
    _velero(ctx, *args, stream=True)
    if not wait:
        audit.note(ctx.env, "dr-backup", {"backup": name, "namespaces": namespaces or "all", "phase": "submitted"})
        ui.ok(f"Backup {name} submitted; follow it with: {velero_hint(ctx, 'backup', 'describe', name)}  (cs dr status lists it)")
        return name
    phase = _finish(ctx, "backup", name, allow_partial=False)
    audit.note(ctx.env, "dr-backup", {"backup": name, "namespaces": namespaces or "all", "phase": phase})
    ui.ok(f"Backup {name} Completed. Restore with: cs dr restore {name}")
    return name


def restore(ctx, backup_name: str, namespaces: str | None, wait: bool = True) -> str:
    if namespaces is not None:   # namespaces of the backup, which need not exist on the cluster: only tidied
        namespaces = ",".join(n.strip() for n in namespaces.split(",") if n.strip()) or None
    require(ctx)
    name = f"{backup_name}-restore-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}"
    args = ["restore", "create", name, "--from-backup", backup_name, "--existing-resource-policy", "update"]
    if namespaces:
        args += ["--include-namespaces", namespaces]
    if wait:
        args.append("--wait")
    _velero(ctx, *args, stream=True)
    if not wait:
        audit.note(ctx.env, "dr-restore", {"backup": backup_name, "restore": name, "phase": "submitted"})
        ui.ok(f"Restore {name} submitted; follow it with: {velero_hint(ctx, 'restore', 'describe', name)}")
        return name
    phase = _finish(ctx, "restore", name, allow_partial=True)
    audit.note(ctx.env, "dr-restore", {"backup": backup_name, "restore": name, "phase": phase})
    if phase == "Completed":
        ui.ok(f"Restore {name} Completed (object list: {velero_hint(ctx, 'restore', 'describe', name, '--details')}).")
    return name


def ttl_duration(ttl) -> str:
    """--ttl as Velero takes it: a Go duration. Days are what people write, and Go has no day unit, so 30d becomes 720h;
    empty means Velero's default (720h). Anything else stops here (exit 2), before Velero prints its usage text."""
    text = str(ttl if ttl is not None else "").strip()
    if not text:
        return TTL_DEFAULT
    days = re.fullmatch(r"(\d+)d", text)
    if days:
        return f"{int(days.group(1)) * 24}h"
    if not GO_DURATION.fullmatch(text):
        raise ui.Abort(f"--ttl '{ttl}' is not a duration: use h/m/s, e.g. 720h (30 days), 168h (a week) or 30d.", code=2)
    return text


def schedule(ctx, name: str, cron: str, namespaces: str | None, ttl: str) -> None:
    if not CRON_RE.match((cron or "").strip()):
        raise ui.Abort(f"--cron '{cron}' is not a cron expression: use 5 fields (minute hour day-of-month month day-of-week, e.g. '0 2 * * *') "
                       "or a descriptor like @daily / @every 6h.", code=2)
    ttl = ttl_duration(ttl)
    namespaces = _namespaces(ctx, namespaces, strict=False)
    require(ctx)
    args = ["schedule", "create", name, "--schedule", cron.strip(), "--ttl", ttl]
    if namespaces:
        args += ["--include-namespaces", namespaces]
    _velero(ctx, *args)
    # the schedule controller validates the cron expression asynchronously (the CLI exits 0 either way)
    st: dict = {}
    deadline = time.time() + 20
    while time.time() < deadline:
        st = _status(ctx, "schedule", name)
        if st.get("phase") in ("Enabled", "FailedValidation"):
            break
        time.sleep(2)
    if st.get("phase") == "FailedValidation":
        _velero(ctx, "schedule", "delete", name, "--confirm", check=False, quiet=True)
        raise ui.Abort(f"Velero rejected schedule {name}: {'; '.join(str(v) for v in st.get('validationErrors') or []) or 'validation failed'}. It was removed.")
    audit.note(ctx.env, "dr-schedule", {"schedule": name, "cron": cron, "ttl": ttl})
    ui.ok(f"Schedule {name} ({cron}, keep {ttl})" + ("" if st.get("phase") == "Enabled" else " created; Velero has not validated it yet") + ". List: cs dr status")


def backups(ctx) -> None:
    """Every Velero backup, newest first. Read with kubectl: no velero CLI, and it works while the location is down."""
    if not installed(ctx):
        raise ui.Abort("Velero is not installed on this cluster. Install it (bucket + identity are created for you): cs platform install velero")
    items, problem = _objects(ctx, "backups")
    if problem:
        raise ui.Abort(f"Could not list the Velero backups: {problem}")
    _remember_location(ctx, _objects(ctx, "backupstoragelocations")[0])
    if not items:
        print(ui.dim("  No Velero backups yet  (cs dr backup [name] [--namespaces a,b]   ·   cs dr schedule <name> --cron '0 2 * * *')"))
        return
    rows = []
    for b in _newest_first(items):
        md, spec, st = b.get("metadata") or {}, b.get("spec") or {}, b.get("status") or {}
        rows.append([str(md.get("name", "?")) + (" (undo point)" if _undo_point(b) else ""), st.get("phase") or "New",
                     st.get("errors") or 0, st.get("warnings") or 0, when(_started(b)), when(st.get("expiration")),
                     ",".join(spec.get("includedNamespaces") or []) or "*"])
    print()
    ui.table(["NAME", "STATUS", "ERRORS", "WARNINGS", "STARTED", "EXPIRES", "NAMESPACES"], rows)
    print(ui.dim(f"  details: {velero_hint(ctx, 'backup', 'describe', '<name>', '--details')}   ·   restore: cs dr restore <name>"))


# ---------------------------------------------------------------- drill

def _default_storage_class(ctx) -> str | None:
    out = _kubectl(ctx, "get", "sc", "-o", "jsonpath={range .items[?(@.metadata.annotations.storageclass\\.kubernetes\\.io/is-default-class==\"true\")]}{.metadata.name}{end}").stdout.strip()
    return out or None


_QUANTITY = {"": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
             "Ki": 2 ** 10, "Mi": 2 ** 20, "Gi": 2 ** 30, "Ti": 2 ** 40, "Pi": 2 ** 50, "Ei": 2 ** 60}


def _bytes(quantity) -> float:
    """A Kubernetes storage quantity ('1Gi', '500M', '2e9') in bytes (0 when it cannot be read)."""
    m = re.match(r"^\s*([0-9.]+(?:[eE][0-9]+)?)\s*(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?\s*$", str(quantity or ""))
    try:
        return float(m.group(1)) * _QUANTITY.get(m.group(2) or "", 0) if m else 0.0
    except ValueError:
        return 0.0


def _unclassed_pvs(ctx) -> list[str] | None:
    """Available PersistentVolumes with no storage class, ReadWriteOnce and >= 1Gi: what the drill's class-less claim can
    bind to on a cluster without a default StorageClass (a hand-made NFS or local PV). None: they could not be listed
    (no permission to list PVs, API timeout) - which says nothing about whether one exists."""
    proc = _kubectl(ctx, "get", "pv", "-o", "json", timeout=60)
    if proc.returncode != 0:
        return None
    try:
        items = json.loads(proc.stdout or "{}").get("items") or []
    except (ValueError, AttributeError):
        return None
    out = []
    for pv in items:
        spec, st = (pv.get("spec") or {}), (pv.get("status") or {})
        if (st.get("phase") == "Available" and not spec.get("storageClassName") and "ReadWriteOnce" in (spec.get("accessModes") or [])
                and _bytes((spec.get("capacity") or {}).get("storage")) >= 2 ** 30):
            out.append(str((pv.get("metadata") or {}).get("name") or "?"))
    return out


def _volume_ops(ctx, kind: str, label: str, name: str) -> list[str]:
    """Phases of the PodVolumeBackups / PodVolumeRestores Velero created for a backup / restore ("?" = no phase yet)."""
    proc = _kubectl(ctx, "-n", "velero", "get", kind, "-l", f"{label}={name}", "-o", "jsonpath={range .items[*]}{.status.phase}{\"\\n\"}{end}", timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"could not list Velero {kind}: {_tail(proc.stderr, 200)}")
    return [p.strip() or "?" for p in proc.stdout.splitlines()]


def _phase(ctx, kind: str, name: str) -> str | None:
    """Phase of a Velero backup / restore / schedule ('New' before Velero picked it up), or None when it does not exist
    or cannot be read. Callers that must not guess (is a restore still running? did it ever start?) treat None as
    unknown, never as finished."""
    try:
        proc = _velero(ctx, kind, "get", name, "-o", "json", check=False, quiet=True)
    except (OSError, ui.Abort):   # no velero CLI here (and none may be fetched): unknown
        return None
    if proc.returncode != 0:
        return None
    try:
        obj = json.loads(proc.stdout or "{}")
    except ValueError:
        obj = {}
    if isinstance(obj, dict) and isinstance(obj.get("items"), list):   # a List: the named object is its only item
        obj = next((i for i in obj["items"] if isinstance(i, dict)), None)
        if obj is None:   # an empty List: there is no such object
            return None
    st = obj.get("status") if isinstance(obj, dict) else None
    return str((st.get("phase") if isinstance(st, dict) else "") or "New")


def _backup_phase(ctx, name: str) -> str | None:
    """Phase of a backup ('New' before Velero picked it up), or None when it does not exist (or cannot be read)."""
    return _phase(ctx, "backup", name)


def _settle_backup(ctx, name: str, timeout: int = SETTLE_S) -> str | None:
    """Wait (bounded) until a backup has left its running phases, because Velero refuses to delete a backup in progress.
    Returns the last phase seen (None: the backup does not exist). A second Ctrl-C ends the wait."""
    phase = _backup_phase(ctx, name)
    if phase is None or phase in BACKUP_DONE:
        return phase
    deadline = time.time() + timeout
    try:
        with ui.Spinner(f"Backup {name} is {phase}; waiting up to {timeout}s for it to finish so it can be deleted (Ctrl-C leaves it)") as sp:
            while time.time() < deadline:
                time.sleep(3)
                phase = _backup_phase(ctx, name)
                if phase is None or phase in BACKUP_DONE:
                    sp.done_text = f"backup {name} {phase or 'gone'}"
                    return phase
                sp.update(f"Backup {name} is {phase}; waiting up to {timeout}s for it to finish so it can be deleted (Ctrl-C leaves it)")
    except KeyboardInterrupt:
        pass
    return phase


def _node_agent_identity_problem(ctx) -> str:
    """On AKS the node agent uploads file-system volume backups to Azure Blob with workload identity only: the webhook
    injects AZURE_FEDERATED_TOKEN_FILE into pods labelled for it. Without it every PodVolumeBackup fails to authenticate."""
    proc = _kubectl(ctx, "-n", "velero", "get", "pods", "-l", "name=node-agent", "-o", "json", timeout=60)
    try:
        pods = json.loads(proc.stdout or "{}").get("items") or [] if proc.returncode == 0 else []
    except (ValueError, AttributeError):
        pods = []
    missing = []
    for pod in pods:
        containers = ((pod.get("spec") or {}).get("containers") or []) if isinstance(pod, dict) else []
        names = {e.get("name") for c in containers for e in (c.get("env") or []) if isinstance(e, dict)}
        if "AZURE_FEDERATED_TOKEN_FILE" not in names:
            missing.append(str((pod.get("metadata") or {}).get("name") or "?"))
    if not missing:   # all set, or no node-agent pod to look at (the PodVolumeBackup check below reports that)
        return ""
    return (f"the Velero node-agent pods have no Azure workload identity (AZURE_FEDERATED_TOKEN_FILE missing in {', '.join(missing[:3])}), "
            "so the volume backup cannot authenticate to Azure Blob. Re-apply Velero's values (they label the node agent for "
            "workload identity): cs platform install velero --upgrade")


def test(ctx, keep: bool = False, with_volume: bool | None = None) -> int:
    """DR drill: create → backup → delete → restore → verify. Returns 0 when the restored workload is intact (130 when interrupted)."""
    _memo(ctx, "dr_drill", None)   # set again once this run's report is saved: a drill that stops before then left nothing
    require(ctx)
    sc = _default_storage_class(ctx)
    use_pvc = with_volume if with_volume is not None else bool(sc)
    unclassed: list = []
    if use_pvc and not sc:   # --volume without a default StorageClass: the class-less claim can only bind to a pre-made PV
        found = _unclassed_pvs(ctx)
        if found is None:    # cannot tell: go ahead, but say what the claim needs
            ui.warn("--volume without a default StorageClass, and the PersistentVolumes could not be listed: the drill's volume "
                    "claim binds only to an Available ReadWriteOnce PV of 1Gi or more with no storage class (step 1 fails after 4 minutes otherwise).")
        unclassed = found or []
        if found is not None and not found:
            classes = _kubectl(ctx, "get", "sc", "-o", "jsonpath={.items[*].metadata.name}").stdout.split()
            fix = (f"mark one as the default: {_kubectl_hint(ctx, 'annotate', 'sc', classes[0], 'storageclass.kubernetes.io/is-default-class=true', '--overwrite')}"
                   + (f" (classes: {', '.join(classes)})" if len(classes) > 1 else "")) if classes else "this cluster has no StorageClass at all"
            raise ui.Abort("--volume needs a default StorageClass, or an Available ReadWriteOnce PersistentVolume of 1Gi or more with no "
                           f"storage class, for the drill's volume claim: {fix}; or run without --volume. Nothing was created.", code=2)
    sc_name = sc or "none (a pre-provisioned PV without a class)"
    run_id = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    token = f"drill-{run_id}"
    vol_token = secrets.token_hex(16)  # lives only on the volume: no manifest, ConfigMap or Secret can bring it back
    bname, rname = f"dr-test-{run_id}", f"dr-test-{run_id}-restore"
    started = {"backup": False, "restore": False}
    backup_phase: list = [None]   # last phase read after the backup step (None: unknown, e.g. interrupted while it ran)
    steps: list[dict] = []
    ui.header(f"DR drill {run_id} on {ctx.env.id}")

    def step(name: str, fn):
        t0 = time.time()
        try:
            detail = fn()
            steps.append({"step": name, "ok": True, "seconds": round(time.time() - t0, 1), "detail": detail or ""})
            ui.ok(f"{name}  ({round(time.time() - t0, 1)}s)" + (f"  {ui.dim(str(detail))}" if detail else ""))
            return True
        except (Exception, ui.Abort) as e:  # noqa: BLE001 - every failure is a drill result, not a crash
            msg = _tail(str(getattr(e, "msg", "") or e), 400, lines=3)
            steps.append({"step": name, "ok": False, "seconds": round(time.time() - t0, 1), "detail": msg})
            ui.err(f"{name}: {msg}")
            return False

    def create():
        _kubectl(ctx, "delete", "ns", DRILL_NS, "--ignore-not-found", "--wait=true", timeout=300)
        m = DRILL_MANIFEST % {"ns": DRILL_NS, "token": token, "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        if use_pvc:
            m += "---\n" + DRILL_PVC % {"ns": DRILL_NS}
        r = _kubectl(ctx, "apply", "-f", "-", input=m)
        if r.returncode != 0:
            raise RuntimeError(r.stderr)
        r = _kubectl(ctx, "-n", DRILL_NS, "rollout", "status", "deploy/drill", "--timeout=240s", timeout=260)
        if r.returncode != 0:
            raise RuntimeError("workload did not become ready: " + _tail(r.stderr, 200))
        if use_pvc:
            r = _kubectl(ctx, "-n", DRILL_NS, "wait", "--for=condition=Ready", "pod/drill-writer", "--timeout=240s", timeout=260)
            if r.returncode != 0:
                raise RuntimeError(f"volume writer pod not ready (storage class {sc_name}): {_tail(r.stderr, 200)}")
            w = _kubectl(ctx, "-n", DRILL_NS, "exec", "drill-writer", "--", "sh", "-c", f"echo {vol_token} > /data/token && sync && cat /data/token", timeout=60)
            if w.returncode != 0 or w.stdout.strip() != vol_token:
                # (kubectl exec ends with "command terminated with exit code 1": the shell's own error is the line before)
                why = _tail(w.stderr, 200, lines=2) or f"read back {w.stdout.strip()[:40]!r}"
                perm = (" The writer runs as uid/gid 1000 (restricted Pod Security): the volume must honour fsGroup or be writable for"
                        " that user." if "denied" in (w.stderr or "").lower() else "")
                raise RuntimeError(f"could not write the test file on the volume ({why}); check the storage class {sc_name}.{perm}")
            where = (f"on {sc}" if sc else "(no StorageClass: a pre-provisioned PV" + (f" such as {unclassed[0]})" if unclassed else ")"))
            return f"deployment 2/2, configmap, secret, 1Gi volume {where} with a random test file"
        return "deployment 2/2, configmap, secret" + (" (volume test skipped: --no-volume)" if with_volume is False
                                                      else " (no default StorageClass: volume test skipped)")

    def do_backup():
        if use_pvc and ctx.target == "azure":
            problem = _node_agent_identity_problem(ctx)
            if problem:
                raise RuntimeError(problem)
        started["backup"] = True
        args = ["backup", "create", bname, "--include-namespaces", DRILL_NS, "--wait"] + ([] if keep else ["--ttl", DRILL_BACKUP_TTL])
        proc = _velero(ctx, *args, check=False, stream=True)
        st = _status(ctx, "backup", bname)
        phase = backup_phase[0] = str(st.get("phase", ""))
        if proc.returncode != 0 or phase != "Completed":
            raise RuntimeError(f"backup phase {phase or '?'} ({_counts(st)}).{_first_errors(ctx, 'backup', bname, st)} "
                               f"Details: {velero_hint(ctx, 'backup', 'describe', bname, '--details')}")
        detail = f"{bname} Completed"
        if use_pvc:
            ops = _volume_ops(ctx, "podvolumebackups", "velero.io/backup-name", bname)
            if not ops:
                raise RuntimeError("the volume was NOT backed up (no PodVolumeBackup): Velero's file-system backup skipped it. "
                                   "hostPath volumes are not supported and the node agent must run on the pod's node "
                                   f"({velero_hint(ctx, 'backup', 'logs', bname)} | grep -i volume)")
            bad = [p for p in ops if p != "Completed"]
            if bad:
                raise RuntimeError(f"volume backup {', '.join(bad)}: {velero_hint(ctx, 'backup', 'describe', bname, '--details')}")
            detail += f", volume data saved ({len(ops)} PodVolumeBackup)"
        return detail

    def destroy():
        r = _kubectl(ctx, "delete", "ns", DRILL_NS, "--wait=true", timeout=400)
        if r.returncode != 0:
            raise RuntimeError(r.stderr)
        if _kubectl(ctx, "get", "ns", DRILL_NS).returncode == 0:
            raise RuntimeError("namespace still exists")
        return "namespace deleted (simulated loss)"

    def do_restore():
        started["restore"] = True
        proc = _velero(ctx, "restore", "create", rname, "--from-backup", bname, "--wait", check=False, stream=True)
        st = _status(ctx, "restore", rname)
        phase = str(st.get("phase", ""))
        if proc.returncode != 0 or phase != "Completed":
            raise RuntimeError(f"restore phase {phase or '?'} ({_counts(st)}).{_first_errors(ctx, 'restore', rname, st)} "
                               f"Details: {velero_hint(ctx, 'restore', 'describe', rname, '--details')}")
        detail = f"{rname} Completed"
        if use_pvc:
            ops = _volume_ops(ctx, "podvolumerestores", "velero.io/restore-name", rname)
            bad = [p for p in ops if p != "Completed"]
            if not ops or bad:
                raise RuntimeError(f"volume data not restored ({', '.join(bad) or 'no PodVolumeRestore'}): {velero_hint(ctx, 'restore', 'describe', rname, '--details')}")
            detail += f", volume data restored ({len(ops)} PodVolumeRestore)"
        return detail

    def verify():
        r = _kubectl(ctx, "-n", DRILL_NS, "rollout", "status", "deploy/drill", "--timeout=300s", timeout=320)
        if r.returncode != 0:
            raise RuntimeError("restored deployment not ready: " + _tail(r.stderr, 200))
        cm = _kubectl(ctx, "-n", DRILL_NS, "get", "cm", "drill-data", "-o", "jsonpath={.data.token}").stdout.strip()
        sec = _kubectl(ctx, "-n", DRILL_NS, "get", "secret", "drill-secret", "-o", "jsonpath={.data.token}").stdout.strip()
        try:
            sec_val = base64.b64decode(sec).decode()
        except (binascii.Error, UnicodeDecodeError, ValueError):
            sec_val = ""
        if cm != token or sec_val != token:
            raise RuntimeError(f"restored data mismatch: configmap={cm!r}, secret {'ok' if sec_val == token else 'missing or different'}")
        if _kubectl(ctx, "-n", DRILL_NS, "get", "svc", "drill").returncode != 0:
            raise RuntimeError("service not restored")
        detail = "deployment 2/2, configmap + secret contents identical, service present"
        if use_pvc:
            r = _kubectl(ctx, "-n", DRILL_NS, "wait", "--for=condition=Ready", "pod/drill-writer", "--timeout=300s", timeout=320)
            if r.returncode != 0:
                raise RuntimeError("restored volume pod not ready: " + _tail(r.stderr, 200))
            got = _kubectl(ctx, "-n", DRILL_NS, "exec", "drill-writer", "--", "cat", "/data/token", timeout=60)
            data = got.stdout.strip()
            if data != vol_token:
                raise RuntimeError(f"volume content not restored (the test file is {'missing' if not data else 'different'}): Velero's file-system "
                                   f"backup skipped or failed it (hostPath volumes are not supported; {velero_hint(ctx, 'backup', 'logs', bname)})")
            detail += ", volume content restored (random file written before the backup read back)"
        return detail

    ok = interrupted = False
    left: list = []   # what the cleanup could not remove
    try:
        ok = step("1. create sample workload", create) and step("2. backup", do_backup) and step("3. delete it (disaster)", destroy) \
            and step("4. restore from backup", do_restore) and step("5. verify", verify)
    except KeyboardInterrupt:
        interrupted = True
        steps.append({"step": "interrupted", "ok": False, "seconds": 0, "detail": "Ctrl-C; the drill namespace and backup were cleaned up" if not keep else "Ctrl-C"})
        ui.warn("interrupted; cleaning up the drill")
    finally:
        if not keep:
            try:
                if started["restore"] and not ok:  # an unfinished restore could recreate objects after the namespace delete
                    _velero(ctx, "restore", "delete", rname, "--confirm", check=False, quiet=True)
                _kubectl(ctx, "delete", "ns", DRILL_NS, "--ignore-not-found", "--wait=false")
                if started["backup"]:
                    # interrupted while Velero was still writing it: a running backup cannot be deleted, let it finish first
                    phase = backup_phase[0] if backup_phase[0] in BACKUP_DONE else _settle_backup(ctx, bname)
                    _velero(ctx, "backup", "delete", bname, "--confirm", check=False, quiet=True)
                    if phase is not None and phase not in BACKUP_DONE:
                        left.append(f"backup {bname} (still {phase}; it expires after {DRILL_BACKUP_TTL})")
                        ui.warn(f"Backup {bname} is still {phase}, and Velero does not delete a backup in progress. It expires by "
                                f"itself after {DRILL_BACKUP_TTL}; or remove it once it has finished: "
                                f"{velero_hint(ctx, 'backup', 'delete', bname, '--confirm')}")
            except (Exception, ui.Abort) as e:  # noqa: BLE001 - cleanup is best effort, the report still gets written
                left.append("what the failed cleanup step would have removed")
                ui.warn(f"drill cleanup incomplete ({getattr(e, 'msg', '') or e}); remove it with: {_kubectl_hint(ctx, 'delete', 'ns', DRILL_NS)}")
    for st in steps:   # the interrupted row was written before the cleanup ran: say what it could not remove
        if st["step"] == "interrupted" and left:
            st["detail"] = "Ctrl-C; cleaned up except " + ", ".join(left)
    real = [s for s in steps if s["step"] != "interrupted"]
    # the RTO is measured only when the drill recovered the workload: a failed or interrupted one has none (not "0s")
    report = {"run": run_id, "env": ctx.env.id, "cloud": ctx.target, "distro": ctx.distro, "velero": server_version(ctx), "volume_tested": use_pvc,
              "volume_verified": bool(ok and use_pvc), "kept": keep, "steps": steps, "verdict": "PASS" if ok else ("INTERRUPTED" if interrupted else "FAIL"),
              "total_s": round(sum(s["seconds"] for s in real), 1),
              "rto_s": round(sum(s["seconds"] for s in real if s["step"].startswith(("4.", "5."))), 1) if ok else None,
              # what the drill created in the cluster (None: its backup was never started), so a kept drill can be removed
              "namespace": DRILL_NS, "backup": bname if started["backup"] else None}
    path = save_report(ctx, report)
    # the caller (cs dr test) records exactly this run: its report, and with --keep the namespace + backup it left
    _memo(ctx, "dr_drill", {"report": str(path), "run": report["run"], "verdict": report["verdict"], "kept": keep,
                            "namespace": DRILL_NS, "backup": report["backup"]})
    print_report(report, path)
    if keep:
        _kept_hint(ctx, report["backup"])
    audit.note(ctx.env, "dr-test", {"run": run_id, "verdict": report["verdict"], "report": str(path)})
    if interrupted:
        return 130
    return 0 if ok else 1


def _kept_hint(ctx, backup: str | None) -> None:
    """--keep: say what the drill left in the cluster and how to remove it. The kept backup has no drill TTL, so Velero
    keeps it for its default 30 days."""
    kept = f"namespace {DRILL_NS}" + (f" and backup {backup} (no drill TTL: Velero's default of 30 days applies)" if backup else "")
    remove = _kubectl_hint(ctx, "delete", "ns", DRILL_NS, "--ignore-not-found") + (
        f"  ·  {velero_hint(ctx, 'backup', 'delete', backup, '--confirm')}" if backup else "")
    ui.info(f"Kept for inspection: {kept}. Remove when done: {remove}")


def _volume_words(report: dict) -> str:
    if not report.get("volume_tested"):
        return "volumes skipped"
    return "volumes tested" if str(report.get("verdict", "")).upper() == "PASS" else "volume included, not verified"


def print_report(report: dict, path: Path | None = None) -> None:
    rows = [f"{ui.style('✔', 'leaf', 'bold') if s.get('ok') else ui.style('✖', 'rose', 'bold')} {ui.style(str(s.get('step', '?')).ljust(28), 'text')} "
            f"{str(s.get('seconds', '-')).rjust(6)}s   {ui.dim(str(s.get('detail', '')))}" for s in report.get("steps") or []]
    verdict = str(report.get("verdict", "?"))
    headline = {"PASS": ui.style("PASS - backup and restore are trustworthy", "leaf", "bold"),
                "INTERRUPTED": ui.style("INTERRUPTED - the drill did not finish; nothing was proven", "rose", "bold")}.get(verdict, ui.style("FAIL - see the failing step", "rose", "bold"))
    rto = rto_text(report)
    rows += ["", headline + ui.dim(f"   total {report.get('total_s', '-')}s · " + (f"measured RTO (restore + verify) {rto}" if rto else "RTO not measured")
                                   + f" · {_volume_words(report)}")]
    if verdict == "FAIL" and report.get("kept") is False:
        rows.append(ui.dim("the drill removed its namespace and backup; to inspect them with the commands above, re-run: cs dr test --keep"))
    if path:
        rows.append(ui.dim(f"report: {path}"))
    ui.panel(f"DR drill · {report.get('env', '?')} · run {report.get('run', '?')}", rows, accent="leaf" if verdict == "PASS" else "rose")


def save_report(ctx, report: dict) -> Path:
    from .scan import claim_run_path, md_cell
    d = ctx.env.dir / "dr"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    path, report["run"] = claim_run_path(d, "drill-", ".json", str(report["run"]))   # a parallel drill never overwrites it
    paths.atomic_write(path, json.dumps(report, indent=2) + "\n")   # an interrupted save never leaves a half-written report
    md = [f"# DR drill {report['run']} · {report['env']}", "", f"Velero {report['velero']} on {report['cloud']}/{report['distro']} · {_volume_words(report)}", "",
          "| step | result | seconds | detail |", "|---|---|---|---|"]
    md += [f"| {md_cell(s['step'])} | {'ok' if s['ok'] else 'FAILED'} | {s['seconds']} | {md_cell(s['detail'])} |" for s in report["steps"]]
    md += ["", f"**{report['verdict']}** · total {report['total_s']}s · RTO {rto_text(report) or 'not measured'}", ""]
    paths.atomic_write(path.with_suffix(".md"), "\n".join(md))
    return path


def last_report(env) -> Path | None:
    d = env.dir / "dr"
    reports = sorted(d.glob("drill-*.json")) if d.exists() else []
    return reports[-1] if reports else None
