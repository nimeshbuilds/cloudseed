"""Run cloudseed inside a Docker/Podman container that has every dependency preinstalled.

How the host and the container share state:
  * CLOUDSEED_HOME is mounted at the SAME absolute path inside the container, so every path cloudseed records (audit
    logs, undo entries, inventory notes, workdirs.json) is valid on both sides.
  * Tools the container installs at run time (Linux binaries in ~/.cloudseed/bin, virtualenvs, the Go toolchain, ...)
    live in a per-platform directory (~/.cloudseed/container-linux-<arch>/) that is mounted over those locations, so a
    Linux binary never shadows the host's own tools, and a host binary never shadows the container's.
  * Credentials are passed by name (`-e KEY`: the engine copies the value from its own environment), never as
    KEY=VALUE on the command line where `ps` would show them. Variables that hold a file path are mapped into the
    container (or dropped when the file is not there).
  * Everything inside runs as root. Where that root is the host's root (rootful Docker on Linux), the image's entry
    point (scripts/container-entrypoint.sh) hands what the run created in the mounted host directories back to the
    host user afterwards (CLOUDSEED_HOST_UID/GID, CLOUDSEED_CHOWN_PATHS). Docker Desktop, podman (keep-id) and
    rootless Docker already map the container's root to the user.
"""

from __future__ import annotations

import getpass
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from . import netutil, paths, secrets, ui

IMAGE = os.environ.get("CLOUDSEED_IMAGE", "cloudseed:local")
ENV_PREFIXES = ("AWS_", "GOOGLE_", "CLOUDSDK_", "GCLOUD_", "ARM_", "AZURE_", "TF_", "HTTP_PROXY", "HTTPS_PROXY",
                "NO_PROXY", "NO_COLOR", "CLOUDSEED_")
CRED_DIRS = {".aws": "/root/.aws", ".config/gcloud": "/root/.config/gcloud", ".azure": "/root/.azure"}
# set by reexec itself (or meaningless inside): never inherited from the host environment
OWN_VARS = ("CLOUDSEED_HOME", "CLOUDSEED_IN_CONTAINER", "CLOUDSEED_HOST_NAME", "CLOUDSEED_USER", "CLOUDSEED_HOST_UID",
            "CLOUDSEED_HOST_GID", "CLOUDSEED_CHOWN_PATHS")
# where versions before the same-path mount put the home inside the container (old records still carry it)
LEGACY_HOME = "/root/.cloudseed"
# locations under CLOUDSEED_HOME that hold platform-specific binaries: the container gets its own copy of each
TOOL_DIRS = ("bin", "aws-cli", "go", "google-cloud-sdk", "venv-agent", "venv-ansible", "venv-az", "venv-prowler", "venv-snow")
# variables whose value is a path: (is a directory, writable)
PATH_VARS = {
    "GOOGLE_APPLICATION_CREDENTIALS": (False, False), "AWS_SHARED_CREDENTIALS_FILE": (False, False),
    "AWS_CONFIG_FILE": (False, False), "AWS_WEB_IDENTITY_TOKEN_FILE": (False, False), "AWS_CA_BUNDLE": (False, False),
    "ARM_CLIENT_CERTIFICATE_PATH": (False, False), "TF_CLI_CONFIG_FILE": (False, False),
    "TF_PLUGIN_CACHE_DIR": (True, True), "CLOUDSDK_CONFIG": (True, True), "AZURE_CONFIG_DIR": (True, True),
}
DAEMON_TIMEOUT = 30
ENTRYPOINT = "/workspace/scripts/container-entrypoint.sh"


def available_engines() -> list[str]:
    return [e for e in ("docker", "podman") if shutil.which(e)]


def choose_engine(settings: dict, explicit: str | None = None) -> str:
    """The container engine to use. One that was asked for - `explicit`, the --engine flag (the dispatcher also copies
    it into settings) or the saved preference - is used or its absence reported (ensure_engine: offers to install it
    on a terminal, otherwise stops naming the other engine); it is never silently swapped for the other one. Without
    a preference: the only installed engine, or a choice between both."""
    preferred = explicit or settings.get("engine")
    if preferred:
        return ensure_engine(preferred)
    engines = available_engines()
    if not engines:
        raise ui.Abort("Neither docker nor podman was found.\n"
                       "  Docker:  https://docs.docker.com/get-docker/\n"
                       "  Podman:  https://podman.io/docs/installation")
    if len(engines) == 1:
        ui.info(f"Using container engine: {engines[0]}")
        return engines[0]
    return ui.choose("Which container engine should cloudseed use?",
                     [(e, e) for e in engines], default=engines[0])


ENGINE_INSTALL = {
    "podman": ("brew install podman && podman machine init && podman machine start",
               "https://podman.io/docs/installation"),
    "docker": ("brew install --cask docker   (then open Docker.app once)", "https://docs.docker.com/get-docker/"),
}


def ensure_engine(engine: str) -> str:
    """Make sure the chosen engine exists; on macOS offer to install it with Homebrew."""
    if engine not in ENGINE_INSTALL:
        raise ui.Abort(f"Unknown container engine '{engine}': use docker or podman.", code=2)
    if shutil.which(engine):
        return engine
    cmd, url = ENGINE_INSTALL.get(engine, ("", ""))
    ui.warn(f"{engine} is not installed.")
    if ui.interactive() and shutil.which("brew") and ui.confirm(f"Install it now?  ({cmd})", default=True):
        rc = subprocess.call(["bash", "-lc", cmd.split("   (")[0]])
        if rc == 0 and shutil.which(engine):
            ui.ok(f"{engine} installed")
            return engine
    other = [e for e in available_engines() if e != engine]
    alt = (f"   or use {other[0]}: --engine {other[0]} (to make it the default: cloudseed deps runtime container "
           f"--engine {other[0]})") if other else "   or pick the other engine with --engine."
    raise ui.Abort(f"Install {engine} first: {cmd}   ({url}){alt}")


_DAEMON_OK: set = set()
_ENGINE_INFO: dict = {}     # engine -> its `info` output (security options: rootless, userns; Docker Desktop)


def _start_hint(engine: str, detail: str = "") -> str:
    if "permission denied" in detail.lower() and engine == "docker":
        return "add yourself to the docker group: sudo usermod -aG docker $USER   (then log in again)"
    if engine == "podman":
        return "start it: podman machine start" if sys.platform == "darwin" else "check: podman info"
    return "start Docker Desktop (open -a Docker)" if sys.platform == "darwin" else "start it: sudo systemctl start docker"


def ensure_daemon(engine: str) -> str:
    """The engine binary exists AND its daemon answers (with a timeout: a half-started Docker Desktop hangs forever)."""
    ensure_engine(engine)
    if engine in _DAEMON_OK:
        return engine
    try:
        r = subprocess.run([engine, "info"], capture_output=True, text=True, timeout=DAEMON_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ui.Abort(f"{engine} is installed but its daemon is not responding (still starting?). Wait a moment and "
                       f"retry, or restart it: {_start_hint(engine)}") from None
    except OSError as e:
        raise ui.Abort(f"{engine} could not be run: {e}") from None
    if r.returncode != 0:
        lines = [x for x in (r.stderr or r.stdout or "").strip().splitlines() if x.strip()]
        detail = lines[-1].strip() if lines else ""
        raise ui.Abort(f"{engine} is installed but not running: {_start_hint(engine, detail)}" + (f"\n  {detail}" if detail else ""))
    _ENGINE_INFO[engine] = r.stdout or ""
    _DAEMON_OK.add(engine)
    return engine


def host_owner(engine: str, info: str | None = None) -> tuple[int, int] | None:
    """(uid, gid) that files the container's root writes into host directories must be handed back to, or None when
    the engine already maps that root to the user: only rootful Docker on Linux (no userns-remap, not Docker Desktop's
    VM) makes them root's on the host."""
    if not sys.platform.startswith("linux") or engine != "docker" or not hasattr(os, "getuid"):
        return None
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        return None
    text = (_ENGINE_INFO.get(engine, "") if info is None else info).lower()
    if "rootless" in text or "userns" in text or "docker desktop" in text:
        return None
    return uid, gid


def image_exists(engine: str) -> bool:
    ensure_daemon(engine)
    try:
        r = subprocess.run([engine, "image", "inspect", IMAGE], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise ui.Abort(f"{engine} did not answer `image inspect {IMAGE}` within a minute; is the daemon healthy? "
                       f"{_start_hint(engine)}") from None
    return r.returncode == 0


def build_image(engine: str) -> None:
    ensure_daemon(engine)
    dockerfile = paths.REPO_ROOT / "Dockerfile"
    if not dockerfile.exists():
        raise ui.Abort("Dockerfile not found; building the image needs a source checkout "
                       "(or set CLOUDSEED_IMAGE to a prebuilt image).")
    ui.info(f"Building container image {IMAGE} with {engine} (first time only, several minutes)...")
    rc = subprocess.run([engine, "build", "-t", IMAGE, "-f", str(dockerfile), str(paths.REPO_ROOT)]).returncode
    if rc != 0:
        raise ui.Abort(f"Image build failed ({engine} build exited {rc}); the output above shows the failing step.")
    ui.ok(f"Image {IMAGE} ready")


# ---------------------------------------------------------------- host <-> container paths

def _arch() -> str:
    m = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(m, m or "unknown")


def tools_home() -> Path:
    """Host directory that holds the container's own tools (mounted over ~/.cloudseed/bin & co inside)."""
    return paths.HOME / f"container-linux-{_arch()}"


def host_path(p) -> Path:
    """A path recorded by cloudseed, as seen from here. Records written by older container runs carry the in-container
    home (/root/.cloudseed/...); on the host that is CLOUDSEED_HOME."""
    s = str(p)
    if not paths.IN_CONTAINER and str(paths.HOME) != LEGACY_HOME and (s == LEGACY_HOME or s.startswith(LEGACY_HOME + "/")):
        return paths.HOME / s[len(LEGACY_HOME):].lstrip("/")
    return Path(s)


def _within(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def _map_path_var(key: str, value: str, home: Path, mounts: list[str]) -> str | None:
    """In-container value for a path-valued variable, adding a mount when needed; None drops it."""
    is_dir, writable = PATH_VARS[key]
    p = Path(value).expanduser()
    try:
        p = p.resolve()
    except OSError:
        pass
    if _within(p, paths.HOME.resolve()):
        return str(p)                                    # the home is mounted at the same path
    for rel, inside in CRED_DIRS.items():
        base = (home / rel)
        if base.exists() and _within(p, base.resolve()):
            return inside + "/" + str(p.relative_to(base.resolve())) if p != base.resolve() else inside
    if not p.exists():
        return None
    if is_dir != p.is_dir():
        return None
    target = f"/run/cloudseed/{key.lower()}" + ("" if is_dir else (p.suffix or ""))
    mounts += ["-v", f"{p}:{target}" + ("" if writable else ":ro")]
    return target


def _strip_runtime_flags(argv: list[str]) -> list[str]:
    out, skip = [], False
    for a in argv:
        if skip:
            skip = False
            continue
        if a in ("--runtime", "--engine"):
            skip = True
            continue
        if a.startswith(("--runtime=", "--engine=")):
            continue
        out.append(a)
    return out


def _workdir_mounts() -> list[str]:
    """Environments with a custom working directory outside CLOUDSEED_HOME are mounted at the same path too."""
    out: list[str] = []
    try:
        index = paths._load_index()
    except Exception:  # noqa: BLE001
        index = {}
    home = paths.HOME.resolve()
    for d in sorted(set(index.values())):
        p = Path(d)
        if p.is_dir() and not _within(p.resolve(), home):
            out += ["-v", f"{p}:{p}"]
    return out


def build_run_command(engine: str, argv: list[str], environ: dict | None = None, tty: bool | None = None) -> list[str]:
    """The `<engine> run ...` command line for argv (no secret values on it: see the module docstring)."""
    environ = dict(os.environ if environ is None else environ)
    home = Path.home()
    ch = str(paths.HOME)
    cmd = [engine, "run", "--rm", "-e", "CLOUDSEED_IN_CONTAINER=1", "-e", f"CLOUDSEED_HOME={ch}", "-v", f"{ch}:{ch}"]
    tools = tools_home()
    for name in TOOL_DIRS:
        cmd += ["-v", f"{tools / name}:{paths.HOME / name}"]
    if sys.stdin.isatty() if tty is None else tty:
        cmd.append("-it")
    if not paths.IS_BUNDLE:
        cmd += ["-v", f"{paths.REPO_ROOT}:/workspace", "-w", "/workspace"]
    if engine == "podman":
        cmd += ["--userns=keep-id:uid=0,gid=0"]
    cmd += _workdir_mounts()

    for rel, inside in CRED_DIRS.items():
        p = home / rel
        if p.exists():
            cmd += ["-v", f"{p}:{inside}"]

    # who and where: the audit trail and the Owner tag / login user name record the person on the host, not "root".
    # Everything inside runs as root, so default login names (GCP/VMware ssh_username) come from CLOUDSEED_USER: the
    # host user, not 'root' (which PermitRootLogin=no on the bastion would lock out).
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = environ.get("USER", "")
    if user:
        cmd += ["-e", f"USER={user}", "-e", f"LOGNAME={user}"]
    cmd += ["-e", f"CLOUDSEED_USER={environ.get('CLOUDSEED_USER') or netutil.local_username()}"]
    cmd += ["-e", f"CLOUDSEED_HOST_NAME={environ.get('CLOUDSEED_HOST_NAME') or socket.gethostname()}"]

    mounts: list[str] = []
    for key in sorted(environ):
        if not key.startswith(ENV_PREFIXES) or key in OWN_VARS:
            continue
        if key in PATH_VARS:
            mapped = _map_path_var(key, environ[key], home, mounts)
            if mapped is not None:
                cmd += ["-e", f"{key}={mapped}"]   # a path, not a secret
            continue
        cmd += ["-e", key]                          # value inherited from the environment the engine runs with
    cmd += mounts
    owner = host_owner(engine)
    entry: list[str] = []
    if owner:
        # the writable host directories mounted above: what the run creates there goes back to the host user
        targets: list[str] = []
        for t in sorted({spec.split(":")[1] for flag, spec in zip(cmd, cmd[1:]) if flag == "-v" and not spec.endswith(":ro")},
                        key=len):
            if not any(t == k or t.startswith(k.rstrip("/") + "/") for k in targets):   # a parent covers it
                targets.append(t)
        cmd += ["-e", f"CLOUDSEED_HOST_UID={owner[0]}", "-e", f"CLOUDSEED_HOST_GID={owner[1]}",
                "-e", "CLOUDSEED_CHOWN_PATHS=" + ":".join(targets)]
        if not paths.IS_BUNDLE:
            # the entry point from this checkout (mounted at /workspace): also works with images built before it existed
            cmd += ["--entrypoint", "/bin/sh"]
            entry = [ENTRYPOINT]
    cmd += [IMAGE, *entry, "--runtime", "local", *_strip_runtime_flags(argv)]
    return cmd


def reexec(engine: str, argv: list[str], rebuild: bool = False) -> int:
    """Re-run the current command inside the container. Never returns on success."""
    ensure_daemon(engine)
    if rebuild or not image_exists(engine):
        build_image(engine)
    paths.ensure_home()
    for name in TOOL_DIRS:           # mount sources and targets exist up front (podman refuses missing sources)
        (tools_home() / name).mkdir(parents=True, exist_ok=True)
        (paths.HOME / name).mkdir(parents=True, exist_ok=True)
    cmd = build_run_command(engine, argv)
    print(ui.dim(f"$ {engine} run ... {IMAGE} {' '.join(secrets.redact(a) for a in _strip_runtime_flags(argv))}"))
    os.execvp(engine, cmd)          # the engine inherits os.environ: that is where `-e KEY` takes the values from
    return 1  # pragma: no cover
