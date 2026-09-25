"""Dependency detection and installation.

Three ways to satisfy dependencies, chosen by the user:
  1. install locally  -> Homebrew when available, otherwise official releases into ~/.cloudseed/bin
                         (terraform, kubectl, helm, go, k9s, databricks: checksum-verified release archives;
                          gcloud / aws / az / snow: the vendors' own HTTPS downloads or pip)
  2. container        -> see container.py (Docker or Podman image with everything preinstalled)
  3. bundle           -> single binary built by scripts/build-bundle.sh (Terraform embedded)
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from . import paths, ui

TERRAFORM_FALLBACK_VERSION = "1.13.3"
HELM_FALLBACK_VERSION = "v4.3.0"
DATABRICKS_FALLBACK_VERSION = "1.17.0"
K9S_FALLBACK_VERSION = "v0.51.0"

# tool -> metadata (min_version: older installs count as missing; every stack says required_version >= 1.10)
TOOLS: dict[str, dict] = {
    "terraform": {"required": True, "clouds": ("aws", "gcp", "azure", "vmware"), "brew": "hashicorp/tap/terraform",
                  "desc": "Terraform >= 1.10 (required)", "min_version": "1.10"},
    "ssh-keygen": {"required": True, "clouds": ("aws", "gcp", "azure", "vmware"), "brew": None,
                   "desc": "OpenSSH client (key generation + ssh)"},
    "aws": {"required": False, "clouds": ("aws",), "brew": "awscli",
            "desc": "AWS CLI (optional: `aws configure` / `aws sso login`)"},
    "gcloud": {"required": False, "clouds": ("gcp",), "brew": "--cask google-cloud-sdk",
               "desc": "Google Cloud CLI (optional: `gcloud auth application-default login`)"},
    # a gcloud component (never linked into ~/.cloudseed/bin: gcloud writes its full SDK path into GKE kubeconfigs)
    "gke-gcloud-auth-plugin": {"required": False, "clouds": ("gcp",), "brew": None,
                               "desc": "GKE auth plugin (kubectl/helm/platform on GKE clusters; a gcloud component)"},
    "az": {"required": False, "clouds": ("azure",), "brew": "azure-cli",
           "desc": "Azure CLI (needed for `az login` auth; optional with ARM_* service-principal/MSI vars)"},
    "vmrun": {"required": True, "clouds": ("vmware",), "brew": None,
              "desc": "VMware Fusion Pro / Workstation Pro (vmrun)"},
    # providers/vmdesktop/go.mod says `go 1.25`: an older Go builds it only by downloading a newer toolchain
    # (GOTOOLCHAIN=auto), which fails offline or with GOTOOLCHAIN=local
    "go": {"required": False, "clouds": ("vmware",), "brew": "go",
           "desc": "Go >= 1.25 (builds the VMware Terraform provider once)", "min_version": "1.25"},
    "qemu-img": {"required": False, "clouds": ("vmware",), "brew": "qemu",
                 "desc": "qemu-img (converts qcow2 cloud images to VMDK on arm64 hosts / Debian)"},
    "kubectl": {"required": False, "clouds": (), "brew": "kubectl",
                "desc": "kubectl (talk to the clusters cloudseed creates)"},
    "helm": {"required": False, "clouds": (), "brew": "helm", "desc": "Helm (installs the platform catalog)"},
    "databricks": {"required": False, "clouds": (), "brew": "databricks/tap/databricks", "desc": "Databricks CLI (cs databricks ...)"},
    "snow": {"required": False, "clouds": (), "brew": "snowflake-cli", "desc": "Snowflake CLI (cs snowflake ...)"},
    "k9s": {"required": False, "clouds": (), "brew": "k9s", "desc": "k9s terminal UI for Kubernetes"},
    "openvpn": {"required": False, "clouds": (), "brew": "openvpn",
                "desc": "OpenVPN client (for `cloudseed vpn connect`)"},
    "tailscale": {"required": False, "clouds": (), "brew": "--cask tailscale",
                  "desc": "Tailscale client (when vpn_type=tailscale)"},
}
CLOUD_CLI = {"aws": "aws", "gcp": "gcloud", "azure": "az", "vmware": None}


def agent_session() -> bool:
    """True inside a session driven by an AI agent (the built-in one, Claude Code, Codex ...: CLOUDSEED_AGENT, or the
    redacted environment an agent session hands its commands), where cloudseed never installs software on its own:
    it stops with the install command for the human instead. MCP tool calls (CLOUDSEED_AGENT=mcp) are not counted:
    their installs are confirm-gated."""
    agent = os.environ.get("CLOUDSEED_AGENT") or ""
    if agent:
        return agent != "mcp"
    return os.environ.get("CLOUDSEED_REDACT") == "1"


def refuse_install_in_agent_session(tools, why: str = "") -> None:
    """Abort with the commands to run by hand when an agent session would otherwise install `tools`."""
    if not agent_session():
        return
    tools = [tools] if isinstance(tools, str) else list(tools)
    raise ui.Abort(f"Missing: {', '.join(tools)}{' ' + why if why else ''}. This is an agent session, and cloudseed "
                   "never installs software for an agent; ask the user to run: "
                   + "   ".join(f"cloudseed install {t}" for t in tools), code=2)


# ---------- lookup ----------

def path_env() -> dict:
    env = dict(os.environ)
    extra = [str(paths.BIN_DIR)]
    bundled = paths.bundled_terraform_binary()
    if bundled:
        extra.append(str(bundled.parent))
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    return env


_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
_ELF_MACHINE = {"amd64": 0x3E, "arm64": 0xB7}


def runs_here(path: str) -> bool:
    """False for an executable built for another OS/CPU, e.g. a Linux binary the container runtime left in
    ~/.cloudseed/bin on a Mac (running it fails with 'exec format error'). Scripts and unknown formats pass."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
    except OSError:
        return True
    system = platform.system().lower()
    if head[:4] == b"\x7fELF":
        if system != "linux":
            return False
        want = _ELF_MACHINE.get({"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower(), ""))
        if want and len(head) >= 20:
            machine = int.from_bytes(head[18:20], "little" if head[5:6] == b"\x01" else "big")
            return machine == want
        return True
    if head[:4] in _MACHO:
        return system == "darwin"
    return True


def find(tool: str) -> str | None:
    if tool == "terraform":
        bundled = paths.bundled_terraform_binary()
        if bundled:
            return str(bundled)
    if tool == "vmrun":
        from . import localvm
        h = localvm.detect_host()
        return str(h["vmrun"]) if h and h["found"] else None
    # like shutil.which over cloudseed's PATH, but never a binary built for another platform
    for d in path_env()["PATH"].split(os.pathsep):
        if not d:
            continue
        cand = os.path.join(d, tool)
        if os.path.isfile(cand) and os.access(cand, os.X_OK) and runs_here(cand):
            return cand
    if tool == GKE_AUTH_PLUGIN:
        return _gcloud_component(tool)
    if tool == "tailscale" and platform.system().lower() == "darwin" and os.access(TAILSCALE_APP, os.X_OK):
        return str(TAILSCALE_APP)
    return None


GKE_AUTH_PLUGIN = "gke-gcloud-auth-plugin"
# The macOS app (Homebrew's cask, the App Store, the standalone download) is also its CLI when run by this path, and
# puts no `tailscale` on PATH unless its "Install CLI" setting is used
TAILSCALE_APP = Path("/Applications/Tailscale.app/Contents/MacOS/Tailscale")


def _gcloud_component(name: str) -> str | None:
    """A gcloud component binary next to gcloud itself in <sdk>/bin (components are not linked onto PATH: Homebrew's
    cask and the tarball SDK keep them in the SDK)."""
    gcloud = None
    for d in path_env()["PATH"].split(os.pathsep):
        cand = os.path.join(d, "gcloud") if d else ""
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            gcloud = cand
            break
    if not gcloud:
        return None
    cand = os.path.join(os.path.dirname(os.path.realpath(gcloud)), name)
    return cand if os.path.isfile(cand) and os.access(cand, os.X_OK) and runs_here(cand) else None


def version_of(tool: str) -> str:
    binary = find(tool)
    if not binary:
        return ""
    try:
        if tool == "terraform":
            out = subprocess.run([binary, "version", "-json"], capture_output=True, text=True, timeout=20).stdout
            return json.loads(out)["terraform_version"]
        if tool == "aws":
            return subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=20).stdout.split()[0]
        if tool == "gcloud":
            out = subprocess.run([binary, "version", "--format=value(\"Google Cloud SDK\")"], capture_output=True,
                                 text=True, timeout=30).stdout.strip()
            return out or "installed"
        if tool == "az":
            out = subprocess.run([binary, "version", "-o", "json"], capture_output=True, text=True, timeout=60).stdout
            return "az " + json.loads(out).get("azure-cli", "?")
        if tool == "ssh-keygen":
            return "ok"
        if tool == "go":
            return _go_version(binary) or "installed"
    except Exception:
        return "installed"
    return "installed"


def _go_version(binary: str) -> str:
    """The version of the Go installed at `binary` ('go1.27.1' -> '1.27.1'), not of a toolchain it would switch to:
    GOTOOLCHAIN=local, and a neutral working directory (a go.mod there could name another toolchain)."""
    env = dict(path_env(), GOTOOLCHAIN="local")
    cwd = str(paths.HOME) if Path(paths.HOME).is_dir() else None
    for cmd in ([binary, "env", "GOVERSION"], [binary, "version"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=env, cwd=cwd).stdout or ""
        except (OSError, subprocess.SubprocessError):
            continue
        m = re.search(r"\bgo(\d+\.\d+(?:\.\d+)?(?:(?:rc|beta)\d+)?)", out)
        if m:
            return m.group(1)
    return ""


def _vtuple(ver: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", ver or "")
    return tuple(int(x) for x in m.groups() if x is not None) if m else None


def too_old(tool: str, ver: str) -> bool:
    """Installed but older than TOOLS[tool]['min_version']. An unknown/unparseable version never blocks anyone."""
    want = (TOOLS.get(tool) or {}).get("min_version")
    have = _vtuple(ver)
    return bool(want and have and have < _vtuple(want))


def status(cloud: str | None = None) -> list[dict]:
    rows = []
    for tool, meta in TOOLS.items():
        if cloud and meta["clouds"] and cloud not in meta["clouds"]:
            continue
        p = find(tool)
        ver = version_of(tool) if p else ""
        outdated = bool(p) and too_old(tool, ver)
        rows.append({"tool": tool, "path": p, "required": meta["required"], "desc": meta["desc"],
                     "version": f"{ver} (needs >= {meta['min_version']})" if outdated else ver, "outdated": outdated,
                     "clouds": tuple(meta["clouds"])})    # () = every cloud (kubectl, helm, ...)
    return rows


def missing(cloud: str) -> tuple[list[str], list[str]]:
    """(required_missing, optional_missing) for a cloud. A tool older than its minimum version counts as missing."""
    req, opt = [], []
    for row in status(cloud):
        if row["path"] and not row.get("outdated"):
            continue
        (req if row["required"] else opt).append(row["tool"])
    return req, opt


# ---------- helpers ----------

def _os_arch() -> tuple[str, str]:
    os_name = platform.system().lower()
    if os_name not in ("darwin", "linux"):
        raise ui.Abort(f"Unsupported OS for local install: {os_name}. Use --runtime container.")
    m = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(m)
    if not arch:
        raise ui.Abort(f"Unsupported CPU architecture: {m}")
    return os_name, arch


class InstallError(Exception):
    """A tool could not be installed for a reason outside cloudseed (network, proxy, a bad archive): install() reports
    it and returns False, so the caller's own message (\"Could not install X\") follows and other tools still get
    their turn - never the crash banner of an unexpected error."""


class DownloadError(InstallError):
    pass


# network failures of urllib: refused/unreachable/DNS (URLError), HTTP errors, a connection cut mid-body
# (http.client.IncompleteRead), read timeouts (socket.timeout / TimeoutError are OSErrors), a malformed URL (ValueError)
_NET_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError, ValueError)


def _download(url: str, timeout: int = 120) -> bytes:
    ui.info(f"Downloading {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cloudseed"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise DownloadError(f"Download of {url} failed: HTTP {e.code} {e.reason}.") from None
    except _NET_ERRORS as e:
        raise DownloadError(f"Download of {url} failed: {_reason(e)}. Check the network connection or the proxy "
                            "(HTTPS_PROXY / HTTP_PROXY / NO_PROXY).") from None


def _reason(e: BaseException) -> str:
    return str(getattr(e, "reason", None) or e) or type(e).__name__


def _latest_github_tag(repo: str, fallback: str) -> str:
    """Tag of a repo's latest release, from the /releases/latest redirect (no API rate limit)."""
    try:
        req = urllib.request.Request(f"https://github.com/{repo}/releases/latest", headers={"User-Agent": "cloudseed"}, method="HEAD")
        with urllib.request.urlopen(req, timeout=30) as resp:
            tag = resp.geturl().rstrip("/").rsplit("/", 1)[-1]
        return tag if re.fullmatch(r"v?\d+\.\d+\.\d+[\w.-]*", tag) else fallback
    except Exception:  # noqa: BLE001 - offline / rate limited: a pinned known-good release
        return fallback


def _verify_sha256(blob: bytes, expected: str | None, what: str) -> None:
    if not expected or not re.fullmatch(r"[0-9a-fA-F]{64}", expected.strip()):
        raise ui.Abort(f"No published checksum found for {what}; not installing an unverified download.")
    if hashlib.sha256(blob).hexdigest() != expected.strip().lower():
        raise ui.Abort(f"{what}: checksum mismatch (corrupted or tampered download). Nothing was installed.")


def _sum_for(sums: str, name: str) -> str | None:
    """The hash for `name` in a SHA256SUMS-style file ('<hash>  <name>' or '<hash> *<name>')."""
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == name:
            return parts[0]
    return None


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    """extractall that refuses absolute paths, '..' and links leaving dest (tarfile's 'data' filter when available)."""
    if hasattr(tarfile, "data_filter"):
        tf.extractall(dest, filter="data")
        return
    root = os.path.realpath(dest)
    for m in tf.getmembers():
        target = os.path.realpath(os.path.join(root, m.name))
        if not (target == root or target.startswith(root + os.sep)) or m.isdev():
            raise ui.Abort(f"refusing to extract {m.name!r}: it points outside {dest}")
        if m.issym() or m.islnk():
            base = root if m.islnk() else os.path.dirname(target)   # hard links are relative to the archive root
            if not os.path.realpath(os.path.join(base, m.linkname)).startswith(root + os.sep):
                raise ui.Abort(f"refusing to extract link {m.name!r} -> {m.linkname!r}")
    tf.extractall(dest)


def _brew() -> str | None:
    return shutil.which("brew")


def install_homebrew() -> bool:
    """Offer Homebrew on macOS: only when asked at a terminal. Never unattended (-y, --auto-approve, a run without a
    terminal: its official script asks for the user's password) and never in an agent session - those runs use the
    official, checksum-verified releases instead."""
    if _brew():
        return True
    if platform.system().lower() != "darwin" or agent_session() or not ui.interactive():
        return False       # (an agent session never installs a package manager: official releases are used instead)
    ui.warn("Homebrew is not installed; it is the easiest way to install tools on macOS.")
    if not ui.confirm("Install Homebrew now (official script, asks for your password)?", default=True):
        return False
    rc = subprocess.call(["/bin/bash", "-c",
                          "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"])
    for cand in ("/opt/homebrew/bin", "/usr/local/bin"):
        if Path(cand, "brew").exists():
            os.environ["PATH"] = cand + os.pathsep + os.environ.get("PATH", "")
    return rc == 0 and _brew() is not None


def _brew_install(pkg: str) -> bool:
    brew = _brew()
    if not brew and platform.system().lower() == "darwin" and ui.interactive():
        install_homebrew()
        brew = _brew()
    if not brew:
        return False
    ui.info(f"brew install {pkg}")
    return subprocess.run([brew, "install", *pkg.split()]).returncode == 0


def _link(target: Path, name: str) -> None:
    paths.ensure_home()
    link = paths.BIN_DIR / name
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target)


# ---------- installers ----------

def latest_terraform_version() -> str:
    try:
        data = json.loads(_download("https://checkpoint-api.hashicorp.com/v1/check/terraform", timeout=15))
        return data["current_version"]
    except Exception:  # noqa: BLE001 - DownloadError included: only the version check is blocked, releases may not be
        return TERRAFORM_FALLBACK_VERSION


def install_terraform_release(version: str | None = None, dest_dir: Path | None = None) -> Path:
    """Download an official Terraform release, verify its SHA256, unzip into dest_dir."""
    os_name, arch = _os_arch()
    version = version or latest_terraform_version()
    dest_dir = dest_dir or paths.BIN_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    base = f"https://releases.hashicorp.com/terraform/{version}"
    zip_name = f"terraform_{version}_{os_name}_{arch}.zip"
    blob = _download(f"{base}/{zip_name}", timeout=300)
    sums = _download(f"{base}/terraform_{version}_SHA256SUMS", timeout=60).decode()
    expected = next((line.split()[0] for line in sums.splitlines() if line.endswith(zip_name)), None)
    if not expected:
        raise ui.Abort("Could not find a checksum for the Terraform download.")
    actual = hashlib.sha256(blob).hexdigest()
    if actual != expected:
        raise ui.Abort("Terraform download checksum mismatch. Aborting.")
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        zf.extract("terraform", dest_dir)
    binary = dest_dir / "terraform"
    binary.chmod(0o755)
    ui.ok(f"Terraform {version} installed at {binary}")
    return binary


def install_terraform() -> bool:
    if _brew_install(TOOLS["terraform"]["brew"]):
        return True
    install_terraform_release()
    return True


def install_aws() -> bool:
    if _brew_install("awscli"):
        return True
    os_name, arch = _os_arch()
    if os_name == "darwin":
        ui.warn("The AWS CLI on macOS without Homebrew needs the signed .pkg installer:")
        ui.warn("  curl -o AWSCLIV2.pkg https://awscli.amazonaws.com/AWSCLIV2.pkg && sudo installer -pkg AWSCLIV2.pkg -target /")
        return False
    machine = "x86_64" if arch == "amd64" else "aarch64"
    blob = _download(f"https://awscli.amazonaws.com/awscli-exe-linux-{machine}.zip", timeout=300)
    tmp = paths.HOME / "tmp-awscli"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        zf.extractall(tmp)
    installer = tmp / "aws" / "install"
    installer.chmod(0o755)
    for f in (tmp / "aws" / "dist").rglob("*"):
        if f.is_file() and not f.suffix:
            f.chmod(0o755)
    rc = subprocess.run([str(installer), "-i", str(paths.HOME / "aws-cli"), "-b", str(paths.BIN_DIR), "--update"]).returncode
    shutil.rmtree(tmp, ignore_errors=True)
    if rc == 0:
        ui.ok(f"AWS CLI installed into {paths.BIN_DIR}")
    return rc == 0


def install_gcloud() -> bool:
    """The Google Cloud CLI, with the GKE auth plugin component (kubectl/helm need it for GKE clusters)."""
    if _brew_install("--cask google-cloud-sdk"):
        _gcloud_components_install(GKE_AUTH_PLUGIN)   # best effort: `cloudseed install gke-gcloud-auth-plugin` retries
        return True
    os_name, arch = _os_arch()
    plat = {"darwin": {"amd64": "darwin-x86_64", "arm64": "darwin-arm"},
            "linux": {"amd64": "linux-x86_64", "arm64": "linux-arm"}}[os_name][arch]
    blob = _download(f"https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-{plat}.tar.gz",
                     timeout=600)
    sdk = paths.HOME / "google-cloud-sdk"
    shutil.rmtree(sdk, ignore_errors=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        _safe_extract(tf, paths.HOME)   # Google publishes no checksum for the rolling archive; HTTPS from dl.google.com
    subprocess.run([str(sdk / "install.sh"), "--quiet", "--usage-reporting=false", "--path-update=false",
                    "--command-completion=false", "--additional-components", GKE_AUTH_PLUGIN], check=False)
    for name in ("gcloud", "gsutil", "bq"):
        if (sdk / "bin" / name).exists():
            _link(sdk / "bin" / name, name)
    ui.ok(f"Google Cloud CLI installed at {sdk}")
    return True


def _gcloud_components_install(component: str) -> bool:
    gcloud = find("gcloud")
    if not gcloud:
        return False
    ui.info(f"gcloud components install {component}")
    try:
        proc = subprocess.run([gcloud, "components", "install", component, "--quiet"], env=path_env(),
                              capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as e:
        ui.warn(f"gcloud components install {component} failed: {e}")
        return False
    if proc.returncode != 0:
        lines = [x for x in (proc.stderr or proc.stdout or "").strip().splitlines() if x.strip()]
        ui.warn(f"gcloud components install {component} failed" + (f": {lines[-1].strip()[:200]}" if lines else ""))
        return False
    return True


def install_gke_gcloud_auth_plugin() -> bool:
    """gke-gcloud-auth-plugin: a gcloud component (installed with gcloud when gcloud is missing). A gcloud from apt/dnf
    has the component manager disabled: its package google-cloud-cli-gke-gcloud-auth-plugin is installed instead.
    It is not linked into ~/.cloudseed/bin: gcloud writes the plugin's full SDK path into the kubeconfig."""
    if not find("gcloud"):
        install_gcloud()
    elif not _gcloud_components_install(GKE_AUTH_PLUGIN) and platform.system().lower() == "linux":
        pkg = "google-cloud-cli-gke-gcloud-auth-plugin"
        for mgr, cmd in (("apt-get", ["sudo", "apt-get", "install", "-y", pkg]), ("dnf", ["sudo", "dnf", "install", "-y", pkg])):
            if shutil.which(mgr):
                subprocess.run(cmd)
                break
    if find(GKE_AUTH_PLUGIN):
        ui.ok(f"{GKE_AUTH_PLUGIN} installed at {find(GKE_AUTH_PLUGIN)}")
        return True
    ui.warn(f"{GKE_AUTH_PLUGIN} is still missing: gcloud components install {GKE_AUTH_PLUGIN}   "
            "(gcloud from apt/dnf: install the package google-cloud-cli-gke-gcloud-auth-plugin)")
    return False


def install_az() -> bool:
    if _brew_install("azure-cli"):
        return True
    return _pip_cli("az")


# current azure-cli (2.80+) and snowflake-cli (3.x) need Python >= 3.10: on 3.9 pip would silently pick releases that
# are a year (or a major version) old
PIP_CLI_PYTHON = (3, 10)
# tool -> (PyPI package, binary, venv directory under CLOUDSEED_HOME, display name, note) for the CLIs installed from PyPI
# into a private virtualenv when Homebrew is not used
_PIP_CLIS = {"az": ("azure-cli", "az", "venv-az", "Azure CLI", "(this takes a few minutes)"),
             "snow": ("snowflake-cli", "snow", "venv-snow", "Snowflake CLI", "")}


def _inside(path: str, folder: Path) -> bool:
    try:
        real, root = os.path.realpath(path), os.path.realpath(str(folder))
    except OSError:
        return False
    return real.startswith(root.rstrip(os.sep) + os.sep)


def _venv_version(venv: Path) -> tuple | None:
    """(major, minor) of a virtualenv's interpreter, or None when it does not run here."""
    try:
        out = subprocess.run([str(venv / "bin" / "python"), "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        return tuple(int(x) for x in out.split(".")) if re.fullmatch(r"\d+\.\d+", out) else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def _pip_cli(tool: str) -> bool:
    """A vendor CLI from PyPI in a private virtualenv (Python >= 3.10), linked into ~/.cloudseed/bin. A venv built by an
    older cloudseed on Python 3.9 (stuck on an outdated release) is rebuilt."""
    package, binary, venv_name, name, note = _PIP_CLIS[tool]
    venv = paths.HOME / venv_name
    try:
        py = venv_python(PIP_CLI_PYTHON, package)        # never the bundle binary
    except ui.Abort as e:                                # no Python 3.10+: say how to get one, then the next tool
        raise InstallError(str(e)) from None
    existed = venv.exists()
    have = _venv_version(venv) if existed else None
    # An outdated venv is set aside until the new one works, and put back when it does not (a venv cannot be built
    # elsewhere and moved in: its scripts name their interpreter by absolute path).
    kept = None
    if existed and (have is None or have < PIP_CLI_PYTHON):
        ui.info(f"Rebuilding {venv} with Python {'.'.join(map(str, PIP_CLI_PYTHON))}+ (it was built with "
                f"{'.'.join(map(str, have)) if have else 'an interpreter that no longer runs'})")
        kept = venv.with_name(venv.name + ".outdated")
        shutil.rmtree(kept, ignore_errors=True)
        try:
            venv.rename(kept)
        except OSError:
            shutil.rmtree(venv, ignore_errors=True)
            kept = None
        existed = False

    def give_up() -> None:
        """A failed rebuild leaves the previous CLI in place (outdated, but working); a failed first install nothing."""
        if not existed:
            shutil.rmtree(venv, ignore_errors=True)
        if kept is not None and kept.exists() and not venv.exists():
            try:
                kept.rename(venv)
            except OSError:
                pass

    ui.info(f"Installing {package} into a private virtualenv at {venv}" + (f" {note}" if note else ""))
    try:
        subprocess.run([py, "-m", "venv", str(venv)], check=True)
    except (subprocess.CalledProcessError, OSError) as e:
        give_up()
        raise InstallError(f"Could not create the virtualenv {venv}: {e}") from None
    rc = subprocess.run([str(venv / "bin" / "pip"), "install", "--quiet", "--disable-pip-version-check", "--upgrade",
                         "pip", package]).returncode
    if rc != 0:
        give_up()
        ui.warn(f"pip could not install {package} (see above); check the network/proxy access to PyPI."
                + (f" The previous {binary} was kept." if kept is not None and venv.exists() else ""))
        return False
    if kept is not None:
        shutil.rmtree(kept, ignore_errors=True)
    _link(venv / "bin" / binary, binary)
    ui.ok(f"{name} installed at {paths.BIN_DIR / binary}")
    return True


def install_ssh() -> bool:
    if platform.system().lower() == "linux":
        for mgr, cmd in (("apt-get", ["sudo", "apt-get", "install", "-y", "openssh-client"]),
                         ("dnf", ["sudo", "dnf", "install", "-y", "openssh-clients"]),
                         ("apk", ["sudo", "apk", "add", "openssh-client"])):
            if shutil.which(mgr):
                return subprocess.run(cmd).returncode == 0
    ui.warn("Install the OpenSSH client with your OS package manager.")
    return False


def _pkg_install(brew_pkg: str, apt_pkg: str, dnf_pkg: str) -> bool:
    if _brew_install(brew_pkg):
        return True
    if platform.system().lower() == "linux":
        for mgr, cmd in (("apt-get", ["sudo", "apt-get", "install", "-y", apt_pkg]),
                         ("dnf", ["sudo", "dnf", "install", "-y", dnf_pkg])):
            if shutil.which(mgr):
                return subprocess.run(cmd).returncode == 0
    ui.warn(f"Install {brew_pkg} with your OS package manager.")
    return False


def _brew_has(formula: str) -> bool:
    """Homebrew itself installed `formula` (`brew list --versions` prints nothing and exits 1 otherwise)."""
    brew = _brew()
    if not brew:
        return False
    try:
        p = subprocess.run([brew, "list", "--versions", formula], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0 and bool((p.stdout or "").strip())


def _go_ok() -> bool:
    return bool(find("go")) and not too_old("go", version_of("go"))


def install_go() -> bool:
    """Go for the VMware provider build: Homebrew (an old brew Go is upgraded - `brew install` would leave it as it is),
    else the latest official release (SHA256-verified) into ~/.cloudseed/go, linked into ~/.cloudseed/bin, which
    comes first on cloudseed's PATH - also when an older Go elsewhere on PATH shadows a fresh brew one."""
    have = find("go")
    if have and _brew_has("go"):
        ui.info("brew upgrade go")
        subprocess.run([_brew(), "upgrade", "go"])
    else:
        _brew_install("go")
    if _go_ok():
        if have:
            ui.ok(f"Go {version_of('go')}: {find('go')}")
        return True
    now = find("go")
    if now:                  # an old Go that brew did not replace, or one that comes before brew's on PATH
        ui.info(f"The Go at {now} is {version_of('go') or 'of an unknown version'}, older than "
                f"{TOOLS['go']['min_version']}: installing the official release into {paths.HOME / 'go'}")
    os_name, arch = _os_arch()
    data = json.loads(_download("https://go.dev/dl/?mode=json", timeout=30))
    release = data[0]
    version = release["version"]
    f = next((x for x in release.get("files", []) if x.get("os") == os_name and x.get("arch") == arch and x.get("kind") == "archive"), None)
    if not f:
        raise ui.Abort(f"go.dev lists no {os_name}/{arch} archive for {version}.")
    blob = _download(f"https://go.dev/dl/{f['filename']}", timeout=600)
    _verify_sha256(blob, f.get("sha256"), f["filename"])
    dest = paths.HOME / "go"
    shutil.rmtree(dest, ignore_errors=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        _safe_extract(tf, paths.HOME)
    _link(dest / "bin" / "go", "go")
    ui.ok(f"Go {version} installed at {dest} (SHA256 verified)")
    return _go_ok()


def install_qemu_img() -> bool:
    return _pkg_install("qemu", "qemu-utils", "qemu-img")


def install_vmrun() -> bool:
    from . import localvm
    return localvm.install_hypervisor()


def install_kubectl() -> bool:
    if _brew_install("kubectl"):
        return True
    os_name, arch = _os_arch()
    ver = _download("https://dl.k8s.io/release/stable.txt", timeout=30).decode().strip()
    blob = _download(f"https://dl.k8s.io/release/{ver}/bin/{os_name}/{arch}/kubectl", timeout=300)
    expected = _download(f"https://dl.k8s.io/release/{ver}/bin/{os_name}/{arch}/kubectl.sha256", timeout=30).decode().strip()
    if hashlib.sha256(blob).hexdigest() != expected:
        raise ui.Abort("kubectl checksum mismatch")
    paths.BIN_DIR.mkdir(parents=True, exist_ok=True)
    target = paths.BIN_DIR / "kubectl"
    target.write_bytes(blob)
    target.chmod(0o755)
    ui.ok(f"kubectl {ver} installed at {target}")
    return True


def install_databricks() -> bool:
    """Homebrew, else the official release zip (checksum-verified) into ~/.cloudseed/bin. The vendor's install.sh
    always targets /usr/local/bin (needs sudo), so it is not used."""
    if _brew_install("databricks/tap/databricks"):
        return True
    os_name, arch = _os_arch()
    ver = _latest_github_tag("databricks/cli", "v" + DATABRICKS_FALLBACK_VERSION).lstrip("v")
    base = f"https://github.com/databricks/cli/releases/download/v{ver}"
    zip_name = f"databricks_cli_{ver}_{os_name}_{arch}.zip"
    blob = _download(f"{base}/{zip_name}", timeout=300)
    sums = _download(f"{base}/databricks_cli_{ver}_SHA256SUMS", timeout=60).decode()
    _verify_sha256(blob, _sum_for(sums, zip_name), zip_name)
    paths.BIN_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        member = next((n for n in zf.namelist() if os.path.basename(n) == "databricks"), None)
        if not member:
            raise ui.Abort(f"{zip_name} does not contain a databricks binary.")
        target = paths.BIN_DIR / "databricks"
        target.write_bytes(zf.read(member))
    target.chmod(0o755)
    ui.ok(f"Databricks CLI {ver} installed at {target} (SHA256 verified)")
    return True


def install_snow() -> bool:
    if _brew_install("snowflake-cli"):
        return True
    return _pip_cli("snow")


def install_helm() -> bool:
    """Homebrew, else the official release archive from get.helm.sh, checked against its published .sha256sum."""
    if _brew_install("helm"):
        return True
    os_name, arch = _os_arch()
    ver = _latest_github_tag("helm/helm", HELM_FALLBACK_VERSION)
    if not ver.startswith("v"):
        ver = "v" + ver
    name = f"helm-{ver}-{os_name}-{arch}.tar.gz"
    blob = _download(f"https://get.helm.sh/{name}", timeout=300)
    expected = _download(f"https://get.helm.sh/{name}.sha256sum", timeout=60).decode().split()
    _verify_sha256(blob, expected[0] if expected else None, name)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        member = next((m for m in tf.getmembers() if m.isfile() and os.path.basename(m.name) == "helm"), None)
        if member is None:
            raise ui.Abort(f"{name} does not contain a helm binary.")
        data = tf.extractfile(member).read()  # type: ignore[union-attr]
    paths.BIN_DIR.mkdir(parents=True, exist_ok=True)
    target = paths.BIN_DIR / "helm"
    target.write_bytes(data)
    target.chmod(0o755)
    ui.ok(f"helm {ver} installed at {target} (SHA256 verified)")
    return True


def install_k9s() -> bool:
    if _brew_install("k9s"):
        return True
    os_name, arch = _os_arch()
    plat = {"darwin": "Darwin", "linux": "Linux"}[os_name]
    tag = _latest_github_tag("derailed/k9s", K9S_FALLBACK_VERSION)   # one tag for both downloads (no race)
    name = f"k9s_{plat}_{arch}.tar.gz"
    base = f"https://github.com/derailed/k9s/releases/download/{tag}"
    blob = _download(f"{base}/{name}", timeout=300)
    sums = _download(f"{base}/checksums.sha256", timeout=60).decode()
    _verify_sha256(blob, _sum_for(sums, name), name)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        member = next((m for m in tf.getmembers() if m.isfile() and os.path.basename(m.name) == "k9s"), None)
        if member is None:
            raise ui.Abort(f"{name} does not contain a k9s binary.")
        data = tf.extractfile(member).read()  # type: ignore[union-attr]
    paths.BIN_DIR.mkdir(parents=True, exist_ok=True)
    target = paths.BIN_DIR / "k9s"
    target.write_bytes(data)
    target.chmod(0o755)
    ui.ok(f"k9s {tag} installed at {target} (SHA256 verified)")
    return True


ANSIBLE_VENV = paths.HOME / "venv-ansible"


def venv_usable(venv: Path, module: str | None = None) -> bool:
    """A virtualenv whose interpreter exists and runs here (one created by the container runtime, or by another
    Python that has since been removed, points at an interpreter this machine does not have). With `module`, that
    package must also import (a venv made by another Python version keeps its packages where this one never looks)."""
    py = venv / "bin" / "python"
    try:
        real = os.path.realpath(py)
        return os.path.exists(real) and runs_here(real) and \
            subprocess.run([str(py), "-c", f"import {module}" if module else "0"], capture_output=True,
                           timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _shebang_ok(script: Path) -> bool:
    """The interpreter a script's #! line names exists here (entry points of a venv created inside the container
    point at the container's path of that venv)."""
    try:
        with open(script, "rb") as fh:
            first = fh.readline(512)
    except OSError:
        return False
    if not first.startswith(b"#!"):
        return True
    parts = first[2:].strip().split()
    return bool(parts) and os.path.exists(parts[0].decode(errors="replace"))


def ensure_local_ansible() -> Path:
    """ansible-playbook on this machine (for the local VMware target), in a private venv."""
    if os.name == "nt":
        # ansible-core cannot be a native Windows control node (and its venv would use Scripts\, not bin/)
        raise ui.Abort("Provisioning local VMs runs Ansible on this machine, and Ansible does not run natively on "
                       "Windows. Run cloudseed from WSL (Windows Subsystem for Linux), or create the VMs without "
                       "provisioning (--no-provision) and configure them yourself.", code=2)
    binary = ANSIBLE_VENV / "bin" / "ansible-playbook"
    if binary.exists() and _shebang_ok(binary) and venv_usable(ANSIBLE_VENV, "ansible"):
        return binary
    if ANSIBLE_VENV.exists():
        shutil.rmtree(ANSIBLE_VENV, ignore_errors=True)   # broken or foreign venv: recreate it
    ui.info(f"Installing ansible-core into {ANSIBLE_VENV} (first time only)")
    # builtin modules only: the playbooks need no Ansible Galaxy collections (and no netaddr)
    try:
        subprocess.run([venv_python(purpose="ansible-core"), "-m", "venv", str(ANSIBLE_VENV)], check=True)
        subprocess.run([str(ANSIBLE_VENV / "bin" / "pip"), "install", "--quiet", "--disable-pip-version-check", "--upgrade",
                        "pip", "ansible-core>=2.16"], check=True)
    except (subprocess.CalledProcessError, OSError) as e:
        shutil.rmtree(ANSIBLE_VENV, ignore_errors=True)   # never leave a half-built venv behind
        raise ui.Abort(f"Could not install ansible-core into {ANSIBLE_VENV}: {e}. Check the network/proxy access to PyPI, "
                       "then re-run.")
    return binary


def venv_python(min_version: tuple = (3, 10), purpose: str = "this feature") -> str:
    """An interpreter that can build a virtualenv for `purpose`: this Python when it is new enough, else (and always
    in the single-binary build, where sys.executable is the cloudseed binary itself) a system python3.x with venv and
    ensurepip. ansible-core >= 2.16 needs Python >= 3.10; macOS's /usr/bin/python3 is 3.9."""
    if not paths.IS_BUNDLE and sys.version_info[:2] >= tuple(min_version):
        return sys.executable
    search = path_env().get("PATH")
    check = "import sys, venv, ensurepip; sys.exit(0 if sys.version_info[:2] >= %r else 1)" % (tuple(min_version),)
    for name in ("python3.14", "python3.13", "python3.12", "python3.11", "python3.10", "python3"):
        exe = shutil.which(name, path=search)
        if not exe:
            continue
        try:
            if subprocess.run([exe, "-c", check], capture_output=True, timeout=30).returncode == 0:
                return exe
        except (OSError, subprocess.TimeoutExpired):
            continue
    need = ".".join(str(v) for v in min_version)
    raise ui.Abort(f"Installing {purpose} needs Python {need}+ with venv, and none was found"
                   + (" (the single-binary build cannot create virtualenvs itself)" if paths.IS_BUNDLE else
                      f" (this is Python {sys.version.split()[0]})")
                   + ". Install one (macOS: brew install python; Debian/Ubuntu: apt install python3 python3-venv; "
                   "RHEL/Fedora/Amazon Linux: dnf install python3.12)"
                   + (", or run cloudseed from a source checkout / --runtime container." if paths.IS_BUNDLE else
                      "; cloudseed finds it on PATH (python3.10 ... python3.14), or use --runtime container."))


def install_openvpn() -> bool:
    return _pkg_install("openvpn", "openvpn", "openvpn")


def install_kubescape() -> bool:
    """Homebrew, else the official release (SHA256-verified) into ~/.cloudseed/bin - what `cs scan kube` does on first use."""
    if _brew_install("kubescape"):
        return True
    from . import scan
    _scanner_release("kubescape", scan._install_kubescape)
    return find("kubescape") is not None


def install_trivy() -> bool:
    """Homebrew, else the official release (SHA256-verified) into ~/.cloudseed/bin - what `cs scan images` does on first use."""
    if _brew_install("trivy"):
        return True
    from . import scan
    _scanner_release("trivy", scan._install_trivy)
    return find("trivy") is not None


def _scanner_release(name: str, installer) -> None:
    """scan's own release installer (it downloads with its own urllib calls): its network and archive failures are an
    InstallError, as they are for `cs scan` itself."""
    try:
        installer()
    except (InstallError, ui.Abort):
        raise
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ConnectionError) as e:
        raise DownloadError(f"Could not download {name}: {_reason(e)}. Check the network connection or the proxy "
                            "(HTTPS_PROXY / HTTP_PROXY / NO_PROXY).") from None
    except (OSError, ValueError, KeyError, tarfile.TarError) as e:
        raise InstallError(f"Could not install {name}: {_reason(e)}.") from None


def install_tailscale() -> bool:
    if _brew_install("--cask tailscale"):
        return True
    if platform.system().lower() == "linux":
        return subprocess.run(["bash", "-c", "curl -fsSL https://tailscale.com/install.sh | sh"]).returncode == 0
    ui.warn("Install Tailscale from https://tailscale.com/download")
    return False


# kubescape and trivy are not in TOOLS (doctor lists what environments need): `cs scan` installs them on first use,
# and `cloudseed install kubescape|trivy` does the same up front
INSTALLERS = {"terraform": install_terraform, "aws": install_aws, "gcloud": install_gcloud, "az": install_az,
              "ssh-keygen": install_ssh, "openvpn": install_openvpn, "tailscale": install_tailscale,
              "go": install_go, "qemu-img": install_qemu_img, "vmrun": install_vmrun, "kubectl": install_kubectl,
              "helm": install_helm, "k9s": install_k9s, "databricks": install_databricks, "snow": install_snow,
              GKE_AUTH_PLUGIN: install_gke_gcloud_auth_plugin, "kubescape": install_kubescape, "trivy": install_trivy}


# What the non-Homebrew installers put into cloudseed's home besides a link in ~/.cloudseed/bin: the undo of an
# install (cli._install_tool) removes these directories too, not only the link
INSTALL_DIRS = {"go": ["go"], "gcloud": ["google-cloud-sdk"], GKE_AUTH_PLUGIN: ["google-cloud-sdk"],
                "az": ["venv-az"], "snow": ["venv-snow"], "aws": ["aws-cli"]}


def install(tool: str) -> bool:
    """Install one tool; False when it could not be (network/proxy trouble, a failed package manager, ...), with the
    reason already printed. An installer that reports success is checked: the tool must now be found (a package
    manager can exit 0 and leave nothing on PATH, e.g. a cask that installs only an app)."""
    if tool not in INSTALLERS:
        raise ui.Abort(f"Unknown tool '{tool}'. Known: {', '.join(INSTALLERS)}")
    try:
        ok = _install(tool)
    except InstallError as e:
        brew = (TOOLS.get(tool) or {}).get("brew") or tool
        ui.err(f"{e} Or install {tool} yourself (e.g. brew install {brew}, or your package manager) and re-run.")
        return False
    except (zipfile.BadZipFile, tarfile.TarError) as e:
        ui.err(f"The {tool} download is not a valid archive ({e}): a proxy or captive portal may have answered instead. "
               "Nothing was installed.")
        return False
    if ok and not find(tool):
        ui.err(_not_found_after_install(tool))
        return False
    return bool(ok)


def _not_found_after_install(tool: str) -> str:
    """Why an install that reported success still left no usable `tool`, with what to do."""
    if tool == "tailscale":
        return (f"The Tailscale installer finished, but there is no `tailscale` command on PATH (nor the macOS app's "
                f"{TAILSCALE_APP}): on macOS install the app into /Applications (or enable its CLI: Tailscale menu > "
                "Settings > Install CLI); elsewhere install it from https://tailscale.com/download. Then re-run.")
    pkg = (TOOLS.get(tool) or {}).get("brew") or tool
    where = f"brew list {pkg}" if _brew() else f"your package manager's file list for {pkg}"
    return (f"The {tool} installer reported success, but {tool} is still not found on PATH ({paths.BIN_DIR} or your "
            f"shell's PATH): the package manager may have installed it somewhere else, or nothing at all. Check where "
            f"it went ({where}), add that directory to PATH, and re-run.")


def _install(tool: str) -> bool:
    have = find(tool)
    venv = paths.HOME / _PIP_CLIS[tool][2] if tool in _PIP_CLIS else None
    if have and venv is not None and _inside(have, venv):
        built = _venv_version(venv)
        if built is None or built < PIP_CLI_PYTHON:
            # a venv an older cloudseed built with Python 3.9: pip kept it on the last release for 3.9
            ui.warn(f"{tool} at {have} was installed with Python "
                    f"{'.'.join(map(str, built)) if built else '(an interpreter that no longer runs)'} and is stuck on "
                    "an outdated release; rebuilding it")
            return _pip_cli(tool)
    if have:
        ver = version_of(tool) if TOOLS.get(tool, {}).get("min_version") else ""
        if not too_old(tool, ver):
            ui.ok(f"{tool} already installed: {have}")
            return True
        if tool == "terraform":
            # brew would be a no-op for an old brew terraform (it needs `brew upgrade`) and another terraform may
            # come first on PATH anyway: a verified release in ~/.cloudseed/bin always wins (it is first on PATH)
            ui.warn(f"Terraform {ver} at {have} is older than {TOOLS['terraform']['min_version']} (the stacks need it); "
                    f"installing a current release into {paths.BIN_DIR}")
            install_terraform_release()
            return not too_old("terraform", version_of("terraform"))
        ui.warn(f"{tool} {ver} at {have} is older than {TOOLS[tool]['min_version']}; updating it")
    return INSTALLERS[tool]()


# ---------- live credential check (uses the cloud CLI when installed; never prints secrets) ----------

def live_credential_check(cloud: str) -> tuple[bool, str] | None:
    def sh(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=path_env())
            return p.returncode, (p.stdout + p.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            return 1, str(e)

    if cloud == "aws" and find("aws"):
        rc, out = sh([find("aws"), "sts", "get-caller-identity", "--output", "json"])
        if rc == 0:
            try:
                d = json.loads(out)
                return True, f"AWS credentials valid: account {d.get('Account')} as {d.get('Arn', '').split('/')[-1]}"
            except ValueError:
                return True, "AWS credentials valid"
        profile = re.search(r"config profile \((.{1,128}?)\) could not be found", out)
        if profile:
            return False, (f"The AWS profile '{profile.group(1)}' does not exist  ->  aws configure --profile "
                           f"{profile.group(1)} | aws configure sso")
        if re.search(r"Unable to locate credentials|NoCredentials|no credentials", out, re.I):
            return False, "No AWS credentials found  ->  aws configure | aws sso login"
        if not out:   # a broken wrapper/shim, or the CLI killed by a signal: nothing says the credentials are bad
            return False, (f"The AWS credential check failed: `aws sts get-caller-identity` exited {rc} with no output  "
                           "->  check the aws CLI itself (aws --version), then: aws sso login | aws configure")
        from . import secrets   # (lazy: secrets imports nothing from deps, but keep deps importable on its own)
        return False, (f"AWS credentials invalid/expired: {secrets.redact(out.splitlines()[-1][:160])}  ->  "
                       "aws sso login | aws configure")
    if cloud == "gcp" and find("gcloud"):
        if _google_env_credentials():
            # Terraform's google provider and the GCS backend use these before application-default credentials, which
            # is all the gcloud check below can test: its verdict would be about credentials nothing uses (the
            # callers then check the variables themselves: GCP.credential_warnings)
            return None
        if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip():
            # A malformed explicitly selected key cannot be repaired by an ADC login. Preserve the adapter's
            # actionable file diagnosis even when gcloud is installed (and only offers a generic login failure).
            from .clouds.gcp import GCP
            warnings = GCP().credential_warnings({"vars": {}})
            if warnings:
                return False, "; ".join(warnings)
        rc, out = sh([find("gcloud"), "auth", "application-default", "print-access-token"], 30)
        if rc == 0:
            return True, "Google application-default credentials valid"
        keyfile = [k for k in _GOOGLE_PROVIDER_ONLY if os.environ.get(k, "").strip()]
        if keyfile:   # the provider signs in with it, the GCS state backend still needs ADC (or GOOGLE_CREDENTIALS)
            return False, (f"Google ADC missing/expired: {keyfile[0]} signs in the google provider only, Terraform's GCS "
                           "state backend uses application-default credentials  ->  gcloud auth application-default "
                           f"login, or export the key as GOOGLE_CREDENTIALS instead of {keyfile[0]}")
        return False, "Google ADC missing/expired  ->  gcloud auth application-default login"
    if cloud == "azure" and find("az"):
        rc, out = sh([find("az"), "account", "show", "-o", "json"], 40)
        if rc == 0:
            try:
                d = json.loads(out)
                return True, f"Azure login valid: subscription {d.get('name')} ({d.get('id')})"
            except ValueError:
                return True, "Azure login valid"
        return False, "Azure login missing/expired  ->  az login"
    return None


# read by the google provider and by Terraform's GCS state backend before application-default credentials
# (GOOGLE_APPLICATION_CREDENTIALS is ADC itself, which the gcloud check tests)
_GOOGLE_ENV_CREDENTIALS = ("GOOGLE_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN")
# read by the google provider only: the GCS state backend still signs in with application-default credentials, so the
# ADC check stays meaningful next to them
_GOOGLE_PROVIDER_ONLY = ("GOOGLE_CLOUD_KEYFILE_JSON", "GCLOUD_KEYFILE_JSON")


def _google_env_credentials() -> list[str]:
    return [k for k in _GOOGLE_ENV_CREDENTIALS if os.environ.get(k, "").strip()]


# ---------- runtime negotiation ----------

def describe_missing(req: list[str]) -> str:
    """'terraform (1.5.0 is older than 1.10), ssh-keygen' for messages."""
    out = []
    for t in req:
        have = find(t) if t != "vmrun" else None
        ver = version_of(t) if have and TOOLS.get(t, {}).get("min_version") else ""
        out.append(f"{t} ({ver} is older than {TOOLS[t]['min_version']})" if ver and too_old(t, ver) else t)
    return ", ".join(out)


def _ensure_vmware_tools() -> None:
    """VMware environments always run on this machine: terraform and ssh-keygen must be here (checked before anything
    expensive such as building the provider or downloading images). There is no container alternative."""
    req, _ = missing("vmware")
    req = [t for t in req if t != "vmrun"]          # the hypervisor is handled by ensure_hypervisor
    if not req:
        return
    refuse_install_in_agent_session(req, "(required for VMware environments)")
    ui.warn(f"Missing required tools for VMware environments: {describe_missing(req)}")
    if ui.interactive() and ui.confirm(f"Install {', '.join(req)} now?", default=True):
        for tool in req:
            if not install(tool):
                raise ui.Abort(f"Could not install {tool}: cloudseed install {tool}", code=2)
        return
    raise ui.Abort("Install them first: " + "   ".join(f"cloudseed install {t}" for t in req), code=2)


def optional_cli_note(cloud: str, cli: str) -> str:
    """Why the cloud's own CLI is (not quite) optional, for the offer to install it."""
    if cloud == "azure":
        try:
            from .clouds.azure import arm_credentials   # (lazy: clouds/azure.py imports deps)
            via = arm_credentials()
        except Exception:  # noqa: BLE001 - a partial install: say what az is needed for
            via = None
        if via:
            return (f"The az CLI is not installed. Terraform authenticates with {via} from the ARM_* variables you "
                    "exported, so it is optional here; it makes `az login` and troubleshooting easier.")
        return ("The az CLI is not installed. Terraform's azurerm provider authenticates through it (az login) unless "
                "the ARM_* variables name another identity: ARM_CLIENT_ID + ARM_CLIENT_SECRET (or "
                "ARM_CLIENT_CERTIFICATE_PATH) + ARM_TENANT_ID for a service principal, ARM_CLIENT_ID + ARM_TENANT_ID + "
                "ARM_USE_OIDC=true for OpenID Connect, or ARM_USE_MSI=true for a managed identity (a system-assigned one "
                "needs no ARM_CLIENT_ID). Without one of those, setup cannot authenticate.")
    return (f"The {cli} CLI is not installed. It is optional (cloudseed authenticates through Terraform using env vars / "
            "credential files), but it makes logging in easier.")


def ensure_runtime(cloud: str, want: str, settings: dict, needs_host: bool = True, nag_optional: bool = True) -> str:
    """Decide how to run: returns 'local' or 'container'. May install tools or persist a preference.
    nag_optional: offer to install the cloud's own CLI when it is missing (setup passes True; read-only commands
    should not prompt)."""
    from . import container  # local import: keep deps.py importable everywhere

    if paths.IN_CONTAINER:
        return "local"
    if cloud == "vmware":
        if want == "container":
            ui.warn("VMware environments run on this machine; ignoring --runtime container.")
        from . import localvm
        if needs_host and not find("vmrun") and not localvm.DRY_RUN_OK.get("active"):
            localvm.ensure_hypervisor()   # installs Fusion/Workstation (with consent) or aborts with instructions
        if needs_host:                    # commands that plan/apply; read-only ones (troubleshoot, ...) must still run
            _ensure_vmware_tools()
        return "local"
    if want == "container":
        return "container"

    req, opt = missing(cloud)
    if not req:
        cli = CLOUD_CLI.get(cloud)
        # only when the cloud's OWN CLI is missing (not k9s, tailscale & co, which are also in `opt`)
        if nag_optional and cli and cli in opt and ui.interactive() and not agent_session() \
                and not settings.get(f"skip_optional_{cloud}"):
            ui.warn(optional_cli_note(cloud, cli))
            if ui.confirm(f"Install {cli} now?", default=False):
                install(cli)
            elif ui.confirm("Don't ask again for this cloud?", default=True):
                settings[f"skip_optional_{cloud}"] = True
                paths.save_settings(settings)
        return "local"

    ui.warn(f"Missing required tools: {describe_missing(req)}")
    refuse_install_in_agent_session(req, f"(required for {cloud}; `--runtime container` would run it in a container "
                                         "that has everything instead)")
    if not ui.interactive():
        raise ui.Abort("Fix with " + ", ".join(f"`cloudseed install {t}`" for t in req) + ", or run with "
                       "`--runtime container`, or use the self-contained binary (`cloudseed install bundle`).", code=2)

    mode = ui.choose("How should cloudseed get its dependencies?", [
        ("install", "Install them on this machine (Homebrew if present, else official releases into ~/.cloudseed/bin)"),
        ("container", "Run everything inside a container (Docker or Podman) with all tools preinstalled"),
        ("bundle", "Build a single self-contained cloudseed binary with Terraform embedded"),
    ], default="install")

    if mode == "install":
        for tool in req:
            if not install(tool):
                raise ui.Abort(f"Could not install {tool}.")
        cli = CLOUD_CLI.get(cloud)
        if cli and not find(cli) and ui.confirm(f"Also install the optional {cli} CLI?", default=False):
            install(cli)
        settings["runtime"] = "local"
        paths.save_settings(settings)
        return "local"

    if mode == "container":
        engine = container.choose_engine(settings)
        settings["runtime"] = "container"
        settings["engine"] = engine
        paths.save_settings(settings)
        return "container"

    # bundle
    script = paths.REPO_ROOT / "scripts" / "build-bundle.sh"
    if not script.exists():
        raise ui.Abort("Bundle builder not available from this location (needs a source checkout).")
    ui.info("Building the self-contained bundle (downloads Terraform, needs python3 + pip + internet)...")
    rc = subprocess.run(["bash", str(script)]).returncode
    if rc != 0:
        raise ui.Abort("Bundle build failed.")
    raise ui.Abort("Bundle built under ./dist. Run that binary instead of this script.", code=0)
