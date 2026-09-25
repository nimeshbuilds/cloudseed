"""Local virtualization on VMware Fusion Pro (macOS) / Workstation Pro (Windows, Linux).

Host detection, cloud-image download + conversion for the host's guest architecture, vmrest lifecycle,
and building/installing the cloudseed Terraform provider (providers/vmdesktop) into a filesystem mirror.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import deps, paths, secrets, ui

PROVIDER_VERSION = "0.1.0"
PROVIDERS_DIR = paths.HOME / "providers"
TERRAFORM_RC = paths.HOME / "terraform.rc"
IMAGES_DIR = paths.HOME / "images"
VMS_DIR = paths.HOME / "vms"
VMREST_CREDS = paths.HOME / "vmware.json"
VMREST_PID = paths.HOME / "vmrest.pid"      # the vmrest this cloudseed home started (the only one it ever stops)
VMREST_LOCK = paths.HOME / "vmrest.lock"
VMREST_URL = "http://127.0.0.1:8697"
# Kept in a VM bundle by the provider while it creates that VM (removed once the VM is in the Terraform state): a bundle
# with it is the debris of a failed create, one without it a VM of its own (providers/vmdesktop incompleteMarker).
INCOMPLETE_MARKER = ".cloudseed-incomplete"
DRY_RUN_OK: dict = {}   # set by the CLI for --dry-run: the hypervisor is not required
DOWNLOAD_PAGES = {
    "fusion": "https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Fusion",
    "workstation": "https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Workstation+Pro",
}
INSTALLER_GLOBS = {
    "darwin": ["VMware-Fusion-*.dmg", "VMware Fusion*.dmg"],
    "linux": ["VMware-Workstation-Full-*.bundle", "VMware-Workstation-*.bundle"],
    "windows": ["VMware-workstation-full-*.exe", "VMware-workstation-*.exe"],
}

# Guest OS catalogue: per host guest-arch, the image to fetch and whether it needs qemu-img conversion.
UBUNTU = "https://cloud-images.ubuntu.com/releases/{rel}/release/"
DEBIAN = "https://cloud.debian.org/images/cloud/{code}/latest/"
IMAGES: dict[str, dict] = {
    "ubuntu-24.04": {
        "label": "Ubuntu 24.04 LTS", "guest_os": {"amd64": "ubuntu-64", "arm64": "arm-ubuntu-64"},
        "amd64": {"file": "ubuntu-24.04-server-cloudimg-amd64.vmdk", "base": UBUNTU.format(rel="24.04"), "sums": "SHA256SUMS", "convert": False},
        "arm64": {"file": "ubuntu-24.04-server-cloudimg-arm64.img", "base": UBUNTU.format(rel="24.04"), "sums": "SHA256SUMS", "convert": True},
    },
    "ubuntu-22.04": {
        "label": "Ubuntu 22.04 LTS", "guest_os": {"amd64": "ubuntu-64", "arm64": "arm-ubuntu-64"},
        "amd64": {"file": "ubuntu-22.04-server-cloudimg-amd64.vmdk", "base": UBUNTU.format(rel="22.04"), "sums": "SHA256SUMS", "convert": False},
        "arm64": {"file": "ubuntu-22.04-server-cloudimg-arm64.img", "base": UBUNTU.format(rel="22.04"), "sums": "SHA256SUMS", "convert": True},
    },
    # Debian's "generic" images, not "genericcloud": the cloud kernel is built without AHCI (CONFIG_SATA_AHCI unset), so
    # it never sees the SATA CD-ROM with the NoCloud seed - and with no open-vm-tools in the image (no guestinfo either)
    # the guest would boot without its user, key or network. The VMDK gets its own name, so a disk an older version
    # built from genericcloud is never reused ("replaces": cache files of that superseded build, removed once this one
    # is ready).
    "debian-12": {
        "label": "Debian 12", "guest_os": {"amd64": "debian12-64", "arm64": "arm-debian12-64"},
        "amd64": {"file": "debian-12-generic-amd64.qcow2", "base": DEBIAN.format(code="bookworm"), "sums": "SHA512SUMS", "convert": True,
                  "vmdk": "debian-12-generic-amd64.vmdk", "replaces": ["debian-12-genericcloud-amd64.qcow2", "debian-12-amd64.vmdk"]},
        "arm64": {"file": "debian-12-generic-arm64.qcow2", "base": DEBIAN.format(code="bookworm"), "sums": "SHA512SUMS", "convert": True,
                  "vmdk": "debian-12-generic-arm64.vmdk", "replaces": ["debian-12-genericcloud-arm64.qcow2", "debian-12-arm64.vmdk"]},
    },
}
DEFAULT_OS = "ubuntu-24.04"


def _note(msg: str, kind: str = "info", stderr: bool = False) -> None:
    """ui.info / ui.ok, or the same line on stderr: the progress of an implicit step (the provider build any vmware
    command may start) must never end up in a command's stdout, such as `output --json` or `inventory`."""
    if not stderr:
        (ui.ok if kind == "ok" else ui.info)(msg)
        return
    ui.eprint(f"  {ui.style(ui.GLYPH[kind], *(('leaf', 'bold') if kind == 'ok' else ('brand',)))} {msg}", tee=True)


def _stderr_fd():
    """stderr's file descriptor for a child process's stdout (None: inherit stdout, e.g. under a test's StringIO)."""
    try:
        return sys.stderr.fileno()
    except (AttributeError, OSError, ValueError):
        return None


@contextlib.contextmanager
def _locked(path: Path, what: str = "", quiet_stdout: bool = False):
    """Exclusive advisory lock shared by every cloudseed process (CLI, web console, MCP). Where the platform or file
    system cannot lock, it proceeds unlocked rather than failing. quiet_stdout: the wait notice goes to stderr."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+")
    try:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)   # retries for ~10 s, then OSError
            else:
                import fcntl
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    if what:
                        _note(f"Waiting for another cloudseed run ({what})...", stderr=quiet_stdout)
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except OSError:
            pass
        yield
    finally:
        fh.close()


# ---------------- host detection ----------------

def _tool_base(home: str | None, defaults: list[Path]) -> Path:
    """Where vmrun & co. are looked for: $VMWARE_HOME when that directory exists, else the first default location that
    exists (else the first default) - the provider's Detect rule, so both always use the same installation."""
    for base in ([Path(home)] if home else []) + defaults:
        if base.is_dir():
            return base
    return defaults[0]


# Where Workstation's installer records its version on Windows (packer's vmware driver reads the same value): the
# 32-bit registry view of a 64-bit Windows first, then the native one.
_WORKSTATION_KEYS = (r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation", r"SOFTWARE\VMware, Inc.\VMware Workstation")


def _windows_workstation_version() -> str | None:
    """Workstation's ProductVersion from the Windows registry ("17.5.2.23775571"), or None when it cannot be read."""
    try:
        import winreg   # Windows only
    except ImportError:
        return None
    for key in _WORKSTATION_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                value, _ = winreg.QueryValueEx(k, "ProductVersion")
        except OSError:
            continue
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def detect_host() -> dict | None:
    """Mirror of the provider's detection: product, version, arch, tool paths. None when VMware is absent.
    "vmware_home": VMWARE_HOME when set (vmware_home_problem explains a vmrun missing there)."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    home = os.environ.get("VMWARE_HOME") or None
    info = {"os": system, "arch": arch, "guest_arch": arch}
    if system == "darwin":
        base = _tool_base(home, [Path("/Applications/VMware Fusion.app/Contents/Library")])
        info.update(product="fusion", vmrun=base / "vmrun", vmrest=base / "vmrest", vdisk=base / "vmware-vdiskmanager",
                    install="https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Fusion  (Fusion Pro is free for personal and commercial use)")
        plist = base.parent / "Info.plist"   # <app>/Contents/Library -> <app>/Contents/Info.plist
        if plist.exists():
            try:
                info["version"] = subprocess.run(["defaults", "read", str(plist), "CFBundleShortVersionString"],
                                                 capture_output=True, text=True, timeout=10).stdout.strip()
            except Exception:
                pass
    elif system == "linux":
        def tool(name: str) -> Path:   # each tool from VMWARE_HOME when it is there, else /usr/bin (as the provider)
            return Path(home) / name if home and (Path(home) / name).exists() else Path("/usr/bin") / name
        info.update(product="workstation", vmrun=tool("vmrun"), vmrest=tool("vmrest"), vdisk=tool("vmware-vdiskmanager"),
                    install="https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Workstation+Pro  (free)")
        vmware = shutil.which("vmware")
        if vmware:   # "VMware Workstation 17.5.2 build-23775571"
            try:
                out = subprocess.run([vmware, "-v"], capture_output=True, text=True, timeout=10).stdout
                m = re.search(r"Workstation\s+(\S+)", out or "")
                if m:
                    info["version"] = m.group(1)
            except Exception:
                pass
    elif system == "windows":
        base = _tool_base(home, [Path(r"C:\Program Files (x86)\VMware\VMware Workstation"),
                                 Path(r"C:\Program Files\VMware\VMware Workstation")])
        info.update(product="workstation", vmrun=base / "vmrun.exe", vmrest=base / "vmrest.exe", vdisk=base / "vmware-vdiskmanager.exe",
                    install="https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Workstation+Pro  (free)")
        version = _windows_workstation_version()
        if version:
            info["version"] = version
    else:
        return None
    info["found"] = Path(info["vmrun"]).exists()
    if home:
        info["vmware_home"] = home
    info.setdefault("version", "unknown")
    return info


def vmware_home_problem(h: dict | None) -> str | None:
    """When VMWARE_HOME is set and no vmrun was found: what to fix, instead of sending the user to download a VMware
    they may well have installed."""
    h = h or {}
    home = h.get("vmware_home")
    if not home or h.get("found"):
        return None
    exe = "vmrun.exe" if h.get("os") == "windows" else "vmrun"
    where = (f"has no {exe} (expected {Path(home) / exe})" if Path(home).is_dir() else
             "does not exist, and VMware is not in its default location either")
    return (f"VMWARE_HOME={home} {where}. Point VMWARE_HOME at the directory that contains {exe} (Fusion: "
            "/Applications/VMware Fusion.app/Contents/Library), or unset it to use the default location.")


# Oldest releases the VMs cloudseed writes run on: arm64 guests need Fusion 13, and the NVMe / PCIe-root-port layout of
# the generated .vmx needs virtual hardware 20 (Fusion 13 / Workstation 17); 13.5 / 17.5 and later get version 21.
MIN_VERSION = {"fusion": (13, 0), "workstation": (17, 0)}


def version_tuple(version) -> tuple[int, int] | None:
    """(major, minor) of a VMware version string ("13.6.4", "17.5.2 build-...", "25H2"); None when unknown."""
    m = re.search(r"(\d+)(?:\.(\d+))?", str(version or ""))
    return (int(m.group(1)), int(m.group(2) or 0)) if m else None


def version_problem(h: dict | None) -> str | None:
    """Why this VMware release cannot run the VMs cloudseed creates, or None (also when the version is unknown)."""
    h = h or {}
    have, need = version_tuple(h.get("version")), MIN_VERSION.get(str(h.get("product")))
    if not have or not need or have >= need:
        return None
    name = "VMware Fusion Pro" if h.get("product") == "fusion" else "VMware Workstation Pro"
    page = DOWNLOAD_PAGES["fusion" if h.get("product") == "fusion" else "workstation"]
    return (f"{name} {h.get('version')} is too old: cloudseed's VMs need {name} {need[0]} or newer (virtual hardware 20+, "
            f"NVMe boot disks{', arm64 guests' if h.get('arch') == 'arm64' else ''}). Update it (free): {page}")


def require_host() -> dict:
    h = detect_host()
    if not h or not h["found"]:
        ensure_hypervisor()
        h = detect_host()
    if not h or not h["found"]:
        problem = vmware_home_problem(h)
        if problem:
            raise ui.Abort(problem)
        prod = "VMware Fusion Pro" if platform.system() == "Darwin" else "VMware Workstation Pro"
        raise ui.Abort(f"{prod} is not installed (vmrun not found).\n  Install it: {(h or {}).get('install', 'see broadcom.com')}\n"
                       "  or set VMWARE_HOME to the directory containing vmrun.")
    return h


# ---------------- hypervisor installation (as automatic as Broadcom's login-gated download allows) ----------------

def _search_dirs() -> list[Path]:
    home = Path.home()
    return [home / "Downloads", home / "Desktop", Path.cwd(), paths.HOME / "downloads"]


def find_installer(extra: str | None = None) -> Path | None:
    system = platform.system().lower()
    if extra:
        p = Path(extra).expanduser()
        return p if p.is_file() else None
    found: list[Path] = []
    for d in _search_dirs():
        if d.exists():
            for pattern in INSTALLER_GLOBS.get(system, []):
                found += d.glob(pattern)
    found = [f for f in found if f.is_file()]
    return max(found, key=lambda f: f.stat().st_mtime) if found else None


def _install_dmg(dmg: Path) -> bool:
    mount = Path("/Volumes/cloudseed-vmware")
    ui.info(f"Mounting {dmg.name}")
    if subprocess.run(["hdiutil", "attach", "-nobrowse", "-quiet", "-mountpoint", str(mount), str(dmg)]).returncode != 0:
        ui.err("Could not mount the disk image (is the download complete?).")
        return False
    try:
        app = next(mount.glob("*.app"), None)
        if not app:
            ui.err("No application found inside the disk image.")
            return False
        dest = Path("/Applications") / app.name
        ui.info(f"Installing {app.name} into /Applications (may ask for your password)")
        rc = subprocess.run(["cp", "-R", str(app), str(dest)]).returncode
        if rc != 0:
            rc = subprocess.run(["sudo", "cp", "-R", str(app), str(dest)]).returncode
        if rc != 0:
            ui.err("Copy failed.")
            return False
        subprocess.run(["xattr", "-dr", "com.apple.quarantine", str(dest)], capture_output=True)
    finally:
        subprocess.run(["hdiutil", "detach", "-quiet", str(mount)], capture_output=True)
    ui.ok(f"{dest.name} installed")
    ui.info("Opening it once so macOS can approve its network/system extensions and you can accept the license.")
    subprocess.run(["open", "-a", dest.name.replace(".app", "")], capture_output=True)
    return True


def _install_bundle(bundle: Path) -> bool:
    bundle.chmod(0o755)
    ui.info(f"Running {bundle.name} (sudo; the installer is interactive unless --console works headless)")
    return subprocess.run(["sudo", str(bundle), "--console", "--eulas-agreed", "--required"]).returncode == 0


def _install_exe(exe: Path) -> bool:
    ui.info(f"Running {exe.name} silently (UAC prompt)")
    return subprocess.run([str(exe), "/s", "/v/qn", "EULAS_AGREED=1", "AUTOSOFTWAREUPDATE=0"]).returncode == 0


def install_hypervisor(installer: str | None = None) -> bool:
    """Install Fusion/Workstation from a downloaded installer; opens the download page and waits when needed."""
    h = detect_host() or {}
    system = platform.system().lower()
    product = "VMware Fusion Pro" if system == "darwin" else "VMware Workstation Pro"
    given = Path(installer).expanduser() if installer else None
    if h.get("found"):
        version = h.get("version") if h.get("version") not in (None, "", "unknown") else ""
        ui.ok(f"{' '.join(x for x in (product, version) if x)} already installed ({h['vmrun']})")
        if given:
            ui.info(f"--from {installer} ignored: VMware is already installed")
        too_old = version_problem(h)
        if too_old:
            ui.warn(too_old)
        return True
    problem = vmware_home_problem(h)
    if problem and not given:   # VMware may well be installed elsewhere: no download page, no 30-minute wait
        raise ui.Abort(problem)
    if given and not given.is_file():   # before any download page or ~/Downloads wait: the user named a file
        raise ui.Abort(f"Installer not found: {given}" + (" (that is a directory)" if given.is_dir() else "") +
                       f"\n  Download {product} from {DOWNLOAD_PAGES['fusion' if system == 'darwin' else 'workstation']} "
                       "and pass the downloaded file: cloudseed install vmrun --from <file>")
    page = DOWNLOAD_PAGES["fusion" if system == "darwin" else "workstation"]
    path = find_installer(installer)
    if not path:
        ui.warn(f"{product} is not installed and Broadcom only serves the (free) installer after a login, "
                "so cloudseed cannot download it for you.")
        ui.info(f"Download page: {page}")
        ui.info("Sign in (free Broadcom account) -> download the latest release -> cloudseed picks it up from ~/Downloads.")
        if not ui.interactive():
            raise ui.Abort(f"Download {product} from {page}, then run: cloudseed install vmrun   (or pass the file: cloudseed install vmrun --from <file>)")
        if ui.confirm("Open the download page in your browser now?", default=True):
            opener = {"darwin": ["open", page], "linux": ["xdg-open", page], "windows": ["cmd", "/c", "start", page]}[system]
            subprocess.run(opener, capture_output=True)
        ui.info("Waiting for the installer to appear in ~/Downloads (Ctrl-C to stop; re-run `cloudseed install vmrun` later)...")
        deadline = time.time() + 30 * 60
        while time.time() < deadline and not path:
            time.sleep(5)
            path = find_installer()
            if path and path.stat().st_size < 50 * 1024 * 1024:
                path = None  # still downloading
        if not path:
            raise ui.Abort("No installer found. After downloading, run: cloudseed install vmrun")
    ui.ok(f"Installer found: {path}")
    if system == "darwin":
        ok = _install_dmg(path)
    elif system == "linux":
        ok = _install_bundle(path)
    else:
        ok = _install_exe(path)
    if not ok:
        return False
    for _ in range(12):
        if (detect_host() or {}).get("found"):
            return True
        time.sleep(5)
    ui.warn("Installed, but vmrun is not visible yet. Finish the first-run dialog in VMware, then re-run.")
    return False


def ensure_hypervisor() -> None:
    """Called before any VM work: install (with consent) or abort with instructions."""
    if DRY_RUN_OK.get("active"):
        return
    h = detect_host() or {}
    if h.get("found"):
        return
    problem = vmware_home_problem(h)
    if problem:
        raise ui.Abort(problem)
    product = "VMware Fusion Pro" if platform.system() == "Darwin" else "VMware Workstation Pro"
    ui.header(f"{product} is required for local VMs")
    if not ui.interactive():
        raise ui.Abort(f"{product} is not installed. Download it from {DOWNLOAD_PAGES['fusion' if platform.system() == 'Darwin' else 'workstation']} "
                       "and run `cloudseed install vmrun` (or `cloudseed install vmrun --from <installer>`).")
    if not install_hypervisor():
        raise ui.Abort(f"{product} is still not available; re-run `cloudseed install vmrun` when it is installed.")


def guest_os_id(os_key: str, guest_arch: str) -> str:
    return IMAGES[os_key]["guest_os"][guest_arch]


# ---------------- images ----------------

class _FetchError(Exception):
    """A download or checksum-list fetch failed (network, HTTP, disk); the message says what and why."""


def _download(url: str, dest: Path, expected: tuple[str, str] | None = None) -> None:
    """Download url to dest. The file only appears under its final name once it is complete and, when `expected`
    (algo, hexdigest) is given, matches it: an interrupted or corrupt download never looks like a cached image."""
    ui.info(f"Downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "cloudseed"})
    tmp = dest.with_name(f"{dest.name}.{os.getpid()}.part")
    digest = hashlib.new(expected[0]) if expected else None
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as fh:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                if digest:
                    digest.update(chunk)
                done += len(chunk)
                if total and sys.stdout.isatty():
                    print(f"\r  {done // (1024 * 1024)} / {total // (1024 * 1024)} MiB", end="", flush=True)
        if sys.stdout.isatty():
            print()
        if total and done != total:
            raise _FetchError(f"{url}: the download stopped at {done} of {total} bytes")
        if expected and digest and digest.hexdigest() != expected[1]:
            raise ui.Abort(f"Checksum mismatch for {dest.name} ({expected[0]}); the download was discarded. Try again.")
        os.replace(tmp, dest)
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
        # URLError/OSError: network, proxy, disk; HTTPException: a connection cut mid-body (IncompleteRead);
        # ValueError: a malformed Content-Length or URL
        raise _FetchError(f"{url}: {getattr(e, 'reason', None) or e or type(e).__name__}") from None
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _expected_sum(sums_url: str, filename: str) -> tuple[str, str]:
    try:
        req = urllib.request.Request(sums_url, headers={"User-Agent": "cloudseed"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode(errors="replace")
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
        raise _FetchError(f"{sums_url}: {getattr(e, 'reason', None) or e or type(e).__name__}") from None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == filename:
            algo = "sha512" if len(parts[0]) == 128 else "sha256"
            return algo, parts[0].lower()
    raise ui.Abort(f"No checksum for {filename} in {sums_url}")


def _digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _marker(path: Path, suffix: str) -> Path:
    return path.with_name(path.name + suffix)


def _read_marker(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        return True   # cannot tell cheaply: keep the file
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _remove_stale_partials(directory: Path, name: str) -> None:
    """Delete <name>.<pid>.part / .tmp files whose process is gone: a run killed outright (a closed terminal's SIGHUP,
    SIGKILL, a crash) never reaches its own cleanup, and a multi-GB partial download would otherwise stay forever."""
    for f in directory.glob(f"{name}.*"):
        m = re.fullmatch(re.escape(name) + r"\.(\d+)\.(part|tmp)", f.name)
        stale = (f.name == f"{name}.part"   # the fixed name older versions downloaded to
                 or (m is not None and int(m.group(1)) != os.getpid() and not _pid_alive(int(m.group(1)))))
        if stale:
            try:
                f.unlink()
            except OSError:
                pass


def ensure_image(os_key: str, guest_arch: str) -> Path:
    """Return a base VMDK for the OS on this host architecture, downloading/verifying/converting once.

    Only a complete, verified result is ever reused: the download is checked against the distribution's published
    checksum before it gets its final name (<image>.sha records that), and the VMDK is converted/copied to a temporary
    file that replaces the old one only on success (<vmdk>.ok records that). A VMDK without that record - interrupted,
    or built by an older version - is rebuilt from the verified download."""
    if os_key not in IMAGES:
        raise ui.Abort(f"Unknown guest OS '{os_key}'. Choose from: {', '.join(IMAGES)}")
    spec = IMAGES[os_key][guest_arch]
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    src = IMAGES_DIR / spec["file"]
    vmdk = image_vmdk(os_key, guest_arch)
    done, verified = _marker(vmdk, ".ok"), _marker(src, ".sha")
    if vmdk.exists() and done.exists():
        return vmdk
    label = IMAGES[os_key]["label"]
    with _locked(IMAGES_DIR / ".lock", f"{label} base image"):
        if vmdk.exists() and done.exists():   # another run finished it while this one waited
            return vmdk
        _remove_stale_partials(IMAGES_DIR, src.name)
        _remove_stale_partials(IMAGES_DIR, vmdk.name)
        sums_url = spec["base"] + spec["sums"]
        try:
            algo, expected = _expected_sum(sums_url, spec["file"])
        except _FetchError as e:
            if vmdk.exists():   # built by an older version: keep working offline, verify on the next online run
                ui.warn(f"Could not fetch the {label} checksums to verify the cached base image ({e}); using {vmdk.name} as is.")
                return vmdk
            raise ui.Abort(f"Could not fetch the {label} checksum list ({e}). Check the network (or proxy) and retry.") from None
        want = f"{algo}:{expected}"
        if src.exists() and _read_marker(verified) != want:
            ui.info(f"Verifying the cached {src.name} ({algo})")
            if _digest(src, algo) == expected:
                verified.write_text(want + "\n")
            else:
                ui.warn(f"The cached {src.name} does not match the published checksum (incomplete, or a newer release); "
                        "downloading it again.")
                src.unlink()
                verified.unlink(missing_ok=True)
        if not src.exists():
            try:
                _download(spec["base"] + spec["file"], src, expected=(algo, expected))
            except _FetchError as e:
                raise ui.Abort(f"Could not download the {label} base image ({e}). Check the network (or proxy) and retry.") from None
            verified.write_text(want + "\n")
            ui.ok(f"Checksum OK ({algo})")
        done.unlink(missing_ok=True)
        tmp = vmdk.with_name(f"{vmdk.name}.{os.getpid()}.tmp")
        try:
            if spec["convert"]:
                qemu = deps.find("qemu-img") or _ensure_tool(
                    "qemu-img", f"to convert the {label} image (published as qcow2 for {guest_arch}) to a VMDK")
                ui.info(f"Converting {src.name} -> {vmdk.name} (qemu-img)")
                # monolithicSparse keeps the descriptor inside the one file, so the result can be renamed into place
                if subprocess.run([qemu, "convert", "-p", "-f", "qcow2", "-O", "vmdk", "-o", "adapter_type=lsilogic,subformat=monolithicSparse",
                                   str(src), str(tmp)]).returncode != 0:
                    raise ui.Abort(f"qemu-img could not convert {src.name} (its error is above); nothing was changed. If the disk "
                                   f"is full, free space and retry; otherwise delete {src} to download it again.")
            else:
                shutil.copyfile(src, tmp)
            os.replace(tmp, vmdk)
        except OSError as e:
            raise ui.Abort(f"Could not write the base image {vmdk.name}: {e}") from None
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        done.write_text(want + "\n")
        _drop_superseded(spec)
    ui.ok(f"Base image ready: {vmdk}")
    return vmdk


def image_vmdk(os_key: str, guest_arch: str) -> Path:
    """Where the base VMDK of this guest OS / architecture is cached."""
    spec = IMAGES[os_key][guest_arch]
    return IMAGES_DIR / spec.get("vmdk", f"{os_key}-{guest_arch}.vmdk")


def _drop_superseded(spec: dict) -> None:
    """Delete the cache files of a build this image replaces (e.g. Debian's genericcloud download and its VMDK): VMs
    only ever use their own clone of a base disk, so nothing refers to them any more."""
    for name in spec.get("replaces") or ():
        for f in (IMAGES_DIR / name, _marker(IMAGES_DIR / name, ".ok"), _marker(IMAGES_DIR / name, ".sha")):
            try:
                f.unlink()
            except OSError:
                pass


def _ensure_tool(tool: str, why: str) -> str:
    """A tool the local VMs need (qemu-img, Go), installed only with consent - services.ensure_tool's rule: never for an
    agent session (it stops with the command for the user), asked on a terminal, and without one only when the run was
    approved up front (--auto-approve); otherwise it stops with `cloudseed install <tool>`."""
    # (services.ensure_tool refuses an agent session itself, before any question - also for a Go that is only too old)
    from . import services   # imported here: services pulls in the provisioning modules
    return services.ensure_tool(tool, why)


# ---------------- terraform provider (built from providers/vmdesktop) ----------------

def _platform_dir() -> str:
    system = platform.system().lower()
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
    return f"{system}_{arch}"


def provider_binary() -> Path:
    name = f"terraform-provider-vmdesktop_v{PROVIDER_VERSION}" + (".exe" if platform.system() == "Windows" else "")
    return PROVIDERS_DIR / "registry.local" / "cloudseed" / "vmdesktop" / PROVIDER_VERSION / _platform_dir() / name


def write_terraform_rc() -> Path:
    """The Terraform CLI configuration with cloudseed's provider mirror. Every vmware command calls this, and other
    cloudseed processes (web console, MCP jobs) may be starting `terraform init` with it at that moment: it is only
    written when its content changes, and then replaced atomically - never truncated and rewritten in place, where a
    concurrent reader would see an empty file (Terraform then silently loses the mirror and cannot find the provider)."""
    paths.ensure_home()
    # JSON string syntax is valid HCL: a Windows path (C:\Users\...) would otherwise hold illegal escapes, and Terraform
    # then drops the whole file (the provider mirror) with only a warning.
    text = f'''provider_installation {{
  filesystem_mirror {{
    path    = {json.dumps(PROVIDERS_DIR.as_posix())}
    include = ["registry.local/*/*"]
  }}
  direct {{
    exclude = ["registry.local/*/*"]
  }}
}}
'''
    try:
        if TERRAFORM_RC.read_text() == text:
            return TERRAFORM_RC
    except (OSError, UnicodeDecodeError):
        pass
    paths.atomic_write(TERRAFORM_RC, text, 0o644)
    return TERRAFORM_RC


def _provider_stamp(binary: Path) -> Path:
    """Digest of the sources the binary was built from. Kept beside the platform directory, not in it: Terraform's
    package checksum covers every file of that directory, so anything extra there breaks .terraform.lock.hcl."""
    return binary.parent.parent / f".{binary.parent.name}.source-sha256"


def _provider_digest(src: Path) -> str:
    """Digest of the provider's build inputs (Go sources without tests, go.mod, go.sum), its version and the target
    platform. Content, not mtimes: a single-file bundle extracts its sources with fresh mtimes on every run."""
    h = hashlib.sha256(f"{PROVIDER_VERSION}\0{_platform_dir()}\0".encode())
    files = sorted(f for f in src.rglob("*") if f.is_file() and
                   ((f.suffix == ".go" and not f.name.endswith("_test.go")) or f.name in ("go.mod", "go.sum")))
    for f in files:
        h.update(f.relative_to(src).as_posix().encode() + b"\0")
        h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


def _provider_stale(binary: Path, src: Path) -> bool:
    """The installed binary was not built from these sources (a fix has not been built yet): rebuild."""
    try:
        return _read_marker(_provider_stamp(binary)) != _provider_digest(src)
    except OSError:
        return False


def ensure_provider(rebuild: bool | None = None, announce: bool | None = None, stale_ok: bool = False) -> Path:
    """Build the provider from providers/vmdesktop into the filesystem mirror when it is missing or out of date.

    `announce` reports an up-to-date build instead of staying silent. It defaults to on when `rebuild` is given
    explicitly - the `install vmware-provider [--rebuild]` command - and off for the implicit call every vmware
    command makes (prepare), which must stay quiet. When an existing build cannot be replaced, the implicit call warns
    and keeps using it: without Go (or with one older than go.mod's 1.25) always; when the build fails only with
    `stale_ok` - the commands that change no VM (status, destroy, troubleshoot ...), so they never depend on Go. A
    command that creates or changes VMs stops instead of applying with a provider older than the stack it renders."""
    if announce is None:
        announce = rebuild is not None
    implicit = rebuild is None
    rebuild = bool(rebuild)
    binary = provider_binary()
    write_terraform_rc()
    src = paths.REPO_ROOT / "providers" / "vmdesktop"
    have_src = (src / "go.mod").exists()
    if binary.exists() and not rebuild and (not have_src or not _provider_stale(binary, src)):
        if announce:
            ui.ok(f"vmware-provider {PROVIDER_VERSION} already built: {binary}   (rebuild: cloudseed install vmware-provider --rebuild)")
        return binary
    if not have_src:
        raise ui.Abort("Provider sources not found (needs a source checkout with providers/vmdesktop).")
    # An existing build keeps working (status, ssh, destroy ...) when this one cannot be replaced - no Go, or a build
    # that fails (offline with a cold module cache, a Go too old for go.mod): only an explicit rebuild insists.
    fallback = binary.exists() and not rebuild
    go = deps.find("go")
    # a Go older than go.mod's `go 1.25` builds it only by downloading a newer toolchain (fails offline or with
    # GOTOOLCHAIN=local): the same as no Go at all
    have = deps.version_of("go") if go else ""
    old = have if have and deps.too_old("go", have) else ""
    if (not go or old) and fallback:
        ui.warn("The VMware provider sources changed since it was built, but "
                + (f"Go {old} is older than {deps.TOOLS['go']['min_version']}" if old else "Go is not installed")
                + "; using the existing build. Update it with: cloudseed install go && cloudseed install vmware-provider --rebuild")
        return binary
    if not go or old:
        # installed with consent; an old one is upgraded (brew) or replaced by the official release (install_go)
        go = _ensure_tool("go", "to build the VMware provider (terraform-provider-vmdesktop) from source")
    binary.parent.mkdir(parents=True, exist_ok=True)
    stamp = _provider_stamp(binary)
    # The implicit build (any vmware command) reports on stderr: stdout may be a command's data (output --json).
    quiet = not announce
    with _locked(binary.parent.parent / ".build.lock", "VMware provider build", quiet_stdout=quiet):
        digest = _provider_digest(src)
        if not rebuild and binary.exists() and _read_marker(stamp) == digest:   # built by a run we waited for
            return binary
        _note(f"Building terraform-provider-vmdesktop {PROVIDER_VERSION} with {go}", stderr=quiet)
        env = deps.path_env()
        # -mod=readonly: build from the shipped go.mod/go.sum, never rewrite them (no `go mod tidy`, no network when the
        # module cache is warm); -trimpath: the same sources give the same binary wherever they were unpacked.
        tmp = binary.with_name(f"{binary.name}.{os.getpid()}.tmp")
        try:
            try:
                failed = subprocess.run([go, "build", "-mod=readonly", "-trimpath", "-o", str(tmp), "."], cwd=src, env=env,
                                        stdout=_stderr_fd() if quiet else None).returncode != 0
                why = "see the Go output above"
            except OSError as e:   # a broken or non-executable go
                failed, why = True, f"{go}: {e}"
            if failed:
                if fallback and implicit and stale_ok:   # the stamp stays stale: the next run tries again
                    ui.warn(f"Rebuilding the VMware provider from the updated sources failed ({why}); using the existing "
                            "build. Retry once Go can reach its module proxy: cloudseed install vmware-provider --rebuild")
                    return binary
                raise ui.Abort(f"Building the VMware provider failed ({why}). If Go reports missing modules, it needs network "
                               "access once to fill its module cache; go.mod needs Go 1.25 or newer."
                               + (" The existing build is older than these sources: commands that change no VM (status, "
                                  "destroy ...) keep using it, but VMs are only created or changed with the current one."
                                  if fallback and implicit else ""))
            os.replace(tmp, binary)
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        stamp.write_text(digest + "\n")
    _note(f"Provider installed: {binary}", "ok", stderr=quiet)
    return binary


# ---------------- vmrest ----------------
#
# vmrest is one per OS user (port 8697, one `vmrest -C` configuration), so cloudseed is careful with it: it starts one
# when none runs and records that process (vmrest.pid); it re-configures credentials without asking only on a definite
# 401 from a vmrest it started and configured itself; a vmrest it did not start (or credentials the user gave it) is
# stopped and re-configured only after the user agrees interactively, and teardown stops only the recorded process.

def load_creds() -> dict | None:
    try:
        creds = json.loads(VMREST_CREDS.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(creds, dict) or not creds.get("user") or not creds.get("password"):
        return None
    return creds


def save_creds(user: str, password: str, managed: bool = True) -> None:
    """managed: cloudseed generated these and configured vmrest with them (else they came from VMREST_USER/_PASSWORD)."""
    paths.ensure_home()
    fd = os.open(VMREST_CREDS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"user": user, "password": password, "managed": managed}, fh)


def _port_open(port: int = 8697) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _auth_request(creds: dict, path: str = "/api/vmnet") -> urllib.request.Request:
    import base64
    return urllib.request.Request(VMREST_URL + path, headers={
        "Accept": "application/vnd.vmware.vmw.rest-v1+json",
        "Authorization": "Basic " + base64.b64encode(f"{creds['user']}:{creds['password']}".encode()).decode()})


def _vmrest_open(req: urllib.request.Request, timeout: float):
    """Open a request to vmrest on 127.0.0.1 directly, never through http_proxy / https_proxy (urlopen's default
    ProxyHandler would send the Basic-auth credentials to the proxy, and a proxy cannot reach this machine's loopback)."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout)


def _rest_status(creds: dict, timeout: float = 15) -> int | None:
    """HTTP status vmrest answers with these credentials (200 ok, 401 rejected), or None when it does not answer
    (refused, timed out, reset) - which says nothing about the credentials."""
    try:
        with _vmrest_open(_auth_request(creds), timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _rest_ok(creds: dict) -> bool:
    return _rest_status(creds) == 200


def _wait_status(creds: dict, total: float = 45) -> int | None:
    """_rest_status, retried with backoff while vmrest is not answering or answers 5xx (busy, or just started)."""
    deadline = time.monotonic() + total
    delay = 1.0
    while True:
        left = deadline - time.monotonic()
        status = _rest_status(creds, timeout=max(1.0, min(15.0, left)))
        if status is not None and status < 500:
            return status
        if time.monotonic() + delay > deadline:
            return status
        time.sleep(delay)
        delay = min(delay * 2, 8.0)


def _generate_vmrest_password() -> str:
    """vmrest -C requires 8-12 chars with upper, lower, digit and one of !#$%&'()*+,-./:;<=>?@[]^_`{|}~."""
    import secrets as pysecrets
    import string
    while True:
        pw = "".join(pysecrets.choice(string.ascii_letters + string.digits + "!#$%&*+-=?@^_") for _ in range(12))
        if any(c.isupper() for c in pw) and any(c.islower() for c in pw) and any(c.isdigit() for c in pw) and any(c in "!#$%&*+-=?@^_" for c in pw):
            return pw


def configure_vmrest(host: dict, user: str, password: str, timeout: float = 60) -> bool:
    """Non-interactive `vmrest -C`. vmrest reads the answers from the controlling terminal, so drive it through a pty.
    Bounded: a vmrest that keeps prompting (a changed prompt, a refused password) is stopped after `timeout`."""
    if os.name == "nt":
        try:
            proc = subprocess.run([str(host["vmrest"]), "-C"], input=f"{user}\n{password}\n{password}\n", capture_output=True,
                                  text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            ui.warn(f"vmrest -C did not finish within {int(timeout)}s (unexpected prompt?)")
            return False
        except OSError as e:
            ui.warn(f"vmrest -C could not run: {e}")
            return False
        return proc.returncode == 0
    import pty
    import select
    pid, fd = pty.fork()
    if pid == 0:  # child
        try:
            os.execv(str(host["vmrest"]), [str(host["vmrest"]), "-C"])
        finally:
            os._exit(127)
    answers = [("sername", user), ("assword", password), ("assword", password)]
    transcript = b""
    deadline = time.time() + timeout
    timed_out = True
    status = 0
    try:
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 1.0)
            if not r:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                timed_out = False
                break
            if not chunk:
                timed_out = False
                break
            transcript += chunk
            tail = transcript.decode(errors="replace").lower()
            if answers and answers[0][0] in tail.rsplit("\n", 1)[-1]:
                os.write(fd, (answers.pop(0)[1] + "\n").encode())
                transcript += b"\n"  # prompt consumed
        if timed_out:
            # still waiting for input nobody will give: end it instead of waiting for it forever
            transcript += b"\n(timed out waiting for vmrest -C; unexpected prompt?)"
            status = _end_child(pid)
        else:
            _, status = os.waitpid(pid, 0)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    text = transcript.decode(errors="replace")
    ok = not timed_out and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and "error" not in text.lower()
    if not ok:
        ui.warn("vmrest -C: " + secrets.redact(text.strip())[-300:])   # redacted whole: a cut must not split a secret
    return ok


def _end_child(pid: int) -> int:
    """SIGTERM, a short grace period, then SIGKILL; returns the wait status."""
    for sig, grace in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 5.0)):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
        end = time.time() + grace
        while time.time() < end:
            try:
                wpid, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                return 0
            if wpid:
                return status
            time.sleep(0.1)
    _, status = os.waitpid(pid, 0)
    return status


def _is_vmrest(pid: int) -> bool:
    """Is `pid` a running vmrest (guards against a recycled PID)?"""
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                                 timeout=10).stdout
            return "vmrest" in out.lower()
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass   # exists, owned by someone else
    except (OSError, subprocess.SubprocessError):
        return False
    try:
        comm = subprocess.run(["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return os.path.basename(comm) == "vmrest"


def _own_vmrest_pid() -> int | None:
    """PID of the vmrest this cloudseed home started, if it still runs."""
    try:
        pid = int(json.loads(VMREST_PID.read_text()).get("pid"))
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    return pid if pid > 0 and _is_vmrest(pid) else None


def _kill(pid: int) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=30)
        else:
            os.kill(pid, signal.SIGTERM)
    except (OSError, subprocess.SubprocessError):
        pass


def _wait_port_closed(seconds: float = 10) -> bool:
    end = time.monotonic() + seconds
    while _port_open():
        if time.monotonic() >= end:
            return False
        time.sleep(0.5)
    return True


def _vmrest_log() -> Path:
    """vmrest's log, in this cloudseed home (CLOUDSEED_HOME moves it)."""
    return paths.HOME / "vmrest.log"


def _start_vmrest(host: dict) -> dict | None:
    """Start vmrest in the background. None when it runs (or is still starting); {"code", "tail"} when it exited at
    once - "tail" is what it logged on the way out (this run's part of the log only, redacted)."""
    log_path = _vmrest_log()
    ui.info(f"Starting vmrest in the background (log: {log_path})")
    paths.ensure_home()
    kwargs = {"start_new_session": True} if os.name != "nt" else {"creationflags": 0x00000008}
    with open(log_path, "ab") as log:
        offset = os.fstat(log.fileno()).st_size   # the log is appended to: only what this run writes counts
        proc = subprocess.Popen([str(host["vmrest"])], stdout=log, stderr=log, stdin=subprocess.DEVNULL, **kwargs)
    fd = os.open(VMREST_PID, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"pid": proc.pid, "exe": str(host["vmrest"])}, fh)
    for _ in range(30):
        time.sleep(0.5)
        if _port_open():
            return None
        code = proc.poll()
        if code is not None:   # exited at once (not configured, port taken ...): it is not ours to track
            VMREST_PID.unlink(missing_ok=True)
            try:
                with open(log_path, "rb") as fh:
                    fh.seek(offset)
                    tail = fh.read().decode(errors="replace")
            except OSError:
                tail = ""
            return {"code": code, "tail": secrets.redact(" / ".join(ln.strip() for ln in tail.splitlines() if ln.strip()))[-600:]}
    return None


def _vmrest_config() -> Path:
    """Where `vmrest -C` keeps this OS user's credentials (vmrest reads it from the user's home)."""
    if os.name == "nt":
        return Path(os.environ.get("USERPROFILE") or Path.home()) / "vmrest.cfg"
    return Path.home() / ".vmrestCfg"


def _vmrest_unconfigured(exited: dict) -> bool:
    """Did vmrest exit because `vmrest -C` was never run for this OS user? It then says "Please use -C to update
    credential"; the wording may change between releases, so a missing configuration file counts as well."""
    if not exited or exited.get("code") in (0, None):
        return False
    tail = str(exited.get("tail") or "").lower()
    return "update credential" in tail or "use -c" in tail or not _vmrest_config().exists()


def _vmrest_exited(exited: dict) -> ui.Abort:
    return ui.Abort(f"vmrest exited at once (exit code {exited.get('code')}): {exited.get('tail') or 'no output'}\n"
                    f"  Full log: {_vmrest_log()}")


def _restart_unconfigured(host: dict, exited: dict, creds: dict | None, stored: dict | None, from_env: bool) -> dict:
    """vmrest exited right after starting. Not configured for this OS user (a new Mac or user, another HOME, a copied
    cloudseed home): configure it when the credentials are cloudseed's own and start it again; the user's own
    credentials are never written into vmrest's configuration without asking. Returns the credentials to use."""
    if not _vmrest_unconfigured(exited):
        raise _vmrest_exited(exited)
    users_own = from_env or (bool(stored) and stored.get("managed") is False)
    if users_own:
        where = "VMREST_USER/VMREST_PASSWORD" if from_env else f"{VMREST_CREDS} (saved from VMREST_USER/VMREST_PASSWORD earlier)"
        undo = "unset them" if from_env else f"delete {VMREST_CREDS}"
        raise ui.Abort(f"vmrest is not configured for this OS user (it exited: {exited.get('tail') or 'no output'}). Run "
                       f"`vmrest -C` with the credentials in {where}, or {undo} to let cloudseed configure vmrest; then retry.")
    ui.info("vmrest has no credential configuration for this OS user yet; configuring it for cloudseed")
    if not (creds and configure_vmrest(host, creds["user"], creds["password"])):
        creds = _configure_new(host)   # no stored pair, or vmrest refused it (a changed password policy)
    again = _start_vmrest(host)
    if again and not _port_open():
        raise _vmrest_exited(again)
    return creds


def _listener_pids(port: int = 8697) -> list[int]:
    """PIDs of the processes listening on 127.0.0.1:`port` that this user can see (lsof, else ss). Empty when neither
    tool is there or the listener belongs to another user (root's `sudo vmrest`)."""
    if os.name == "nt":
        return []
    tries = [["lsof", "-nP", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"], ["ss", "-Hltnp", f"sport = :{port}"]]
    for cmd in tries:
        exe = shutil.which(cmd[0]) or next((p for p in (f"/usr/sbin/{cmd[0]}", f"/usr/bin/{cmd[0]}", f"/sbin/{cmd[0]}")
                                           if os.path.exists(p)), None)
        if not exe:
            continue
        try:
            out = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True, timeout=15).stdout or ""
        except (OSError, subprocess.SubprocessError):
            continue
        found = re.findall(r"^\s*(\d+)\s*$", out, re.M) if cmd[0] == "lsof" else re.findall(r"pid=(\d+)", out)
        pids = sorted({int(x) for x in found if int(x) > 0})
        if pids:
            return pids
    return []


def _stop_users_vmrest() -> None:
    """Stop the vmrest on port 8697 (only after the user agreed): the process holding the port when it can be told,
    so no other vmrest of this user (another port, another tool) is touched; otherwise this user's vmrest processes."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/IM", "vmrest.exe", "/F"], capture_output=True, timeout=30)
            return
        pids = [pid for pid in _listener_pids() if _is_vmrest(pid)]
        if pids:
            for pid in pids:
                _kill(pid)
            return
        subprocess.run(["pkill", "-x", "-U", str(os.getuid()), "vmrest"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass


def _configure_new(host: dict) -> dict:
    creds = {"user": "cloudseed", "password": _generate_vmrest_password()}
    if not configure_vmrest(host, creds["user"], creds["password"]):
        raise ui.Abort("Could not configure vmrest automatically. Run `vmrest -C` yourself, then export VMREST_USER/VMREST_PASSWORD and retry.")
    save_creds(creds["user"], creds["password"], managed=True)
    return creds


def ensure_vmrest(host: dict) -> dict:
    """Make sure VMware's REST service is configured, running and reachable - fully automatic.

    Credentials: VMREST_USER/VMREST_PASSWORD from the environment, else the ones cloudseed stored, else a fresh
    strong pair that cloudseed configures itself with `vmrest -C` (answered on stdin) and keeps in <cloudseed home>/vmware.json
    (0600). A vmrest that exits at once because this OS user never ran `vmrest -C` is configured with cloudseed's own
    credentials, or reported at once when the credentials are the user's.
    A slow or failing vmrest is waited for and reported - never mistaken for rejected credentials.
    """
    with _locked(VMREST_LOCK, "vmrest"):
        return _ensure_vmrest(host)


def _ensure_vmrest(host: dict) -> dict:
    stored = load_creds()   # read under the lock: another run may just have (re)configured vmrest
    env_user, env_pass = os.environ.get("VMREST_USER"), os.environ.get("VMREST_PASSWORD")
    from_env = bool(env_user and env_pass)
    creds = {"user": env_user, "password": env_pass} if from_env else stored
    if not _port_open():
        if not creds:
            ui.info("Configuring VMware's REST API (vmrest) with credentials generated for cloudseed")
            creds = _configure_new(host)
        exited = _start_vmrest(host)
        if exited and not _port_open():   # (an open port: another run's vmrest won the start - wait for it as usual)
            creds = _restart_unconfigured(host, exited, creds, stored, from_env)
    status = _wait_status(creds) if creds else 401
    if status == 200:
        if from_env and (not stored or (stored.get("user"), stored.get("password")) != (env_user, env_pass)):
            save_creds(env_user, env_pass, managed=False)   # later runs (web console, MCP) use them too
        return creds
    if status is None or status >= 500:
        raise ui.Abort(f"vmrest is not responding ({'no answer' if status is None else f'HTTP {status}'} from {VMREST_URL} "
                       f"within 45s). Check {_vmrest_log()}; if it hangs, quit VMware (or stop vmrest) and retry.")
    if status not in (401, 403):
        raise ui.Abort(f"Unexpected HTTP {status} from {VMREST_URL}/api/vmnet: is another service using port 8697?")
    if from_env:
        raise ui.Abort("vmrest rejected VMREST_USER/VMREST_PASSWORD. Set them to the credentials that vmrest on port 8697 was "
                       "configured with (`vmrest -C`), or unset them to let cloudseed manage vmrest.")
    own = _own_vmrest_pid()
    # re-configured without asking only when cloudseed both started it and configured it: credentials that came from
    # VMREST_USER/VMREST_PASSWORD (managed: false) are the user's own `vmrest -C` configuration
    users_config = bool(stored) and stored.get("managed") is False
    if own and not users_config:
        ui.warn("The vmrest cloudseed started rejected the stored credentials; re-configuring it for cloudseed")
        _kill(own)
    else:
        what = "does not accept cloudseed's stored credentials" if creds else "cloudseed has no credentials for it"
        msg = (f"The vmrest running on port 8697 was not started by cloudseed, and {what}" if not own else
               "The vmrest on port 8697 rejects the credentials you gave cloudseed earlier (VMREST_USER/VMREST_PASSWORD, "
               f"saved in {VMREST_CREDS}); its `vmrest -C` configuration is yours")
        if not (ui.interactive() and ui.confirm(f"{msg}. Stop it and re-configure vmrest for cloudseed (this replaces "
                                                "vmrest's saved credentials)?", default=False)):
            raise ui.Abort(f"{msg}.\n  Export VMREST_USER/VMREST_PASSWORD with the credentials it was configured with "
                           "(`vmrest -C`), or stop it and retry (cloudseed then starts and configures its own).")
        if own:
            _kill(own)
        else:
            _stop_users_vmrest()
    if not _wait_port_closed(10):
        raise ui.Abort("The vmrest on port 8697 could not be stopped (it may run as root, e.g. `sudo vmrest`). Export "
                       "VMREST_USER/VMREST_PASSWORD with its credentials, or stop it yourself, then retry.")
    VMREST_PID.unlink(missing_ok=True)
    creds = _configure_new(host)
    exited = _start_vmrest(host)
    if exited and not _port_open():
        raise _vmrest_exited(exited)
    status = _wait_status(creds)
    if status != 200:
        raise ui.Abort(f"vmrest is not answering with the new credentials ({'no answer' if status is None else f'HTTP {status}'}); "
                       f"check {_vmrest_log()}")
    ui.ok("vmrest configured and running")
    return creds


def list_vmnets(creds: dict) -> list[dict] | None:
    """vmrest's virtual networks ({name, type, subnet, mask, dhcp}), or None when it cannot be asked."""
    try:
        with _vmrest_open(_auth_request(creds), timeout=15) as resp:
            nets = json.loads(resp.read()).get("vmnets", [])
    except (urllib.error.URLError, OSError, ValueError, AttributeError):
        return None
    return [n for n in nets if isinstance(n, dict)]


def vmnet_cidr(net: dict) -> str | None:
    import ipaddress
    try:
        return str(ipaddress.ip_network(f"{net['subnet']}/{net['mask']}", strict=False)) if net.get("subnet") and net.get("mask") else None
    except (ValueError, KeyError):
        return None


def hostonly_vmnet(creds: dict) -> dict | None:
    """The built-in host-only network (vmnet1): {name, cidr}. Creating custom vmnets needs root, so cloudseed uses this one."""
    for n in list_vmnets(creds) or []:
        cidr = vmnet_cidr(n)
        if n.get("type") == "hostOnly" and cidr:
            return {"name": n["name"], "cidr": cidr, "dhcp": n.get("dhcp") == "true"}
    return None


def provider_env(creds: dict) -> dict:
    return {"VMREST_USER": creds["user"], "VMREST_PASSWORD": creds["password"], "VMREST_URL": VMREST_URL}


# ---------------- teardown helpers (used by `cs destroy vmware`) ----------------

# Every VM bundle the vmware stack creates: <name>-<env>-bastion, -vmN (workloads), -cpN / -wkN (Kubernetes).
_BUNDLE_SUFFIX = r"-(bastion|vm\d+|cp\d+|wk\d+)\.vmwarevm"


def env_vm_bundle(bundle_name: str, prefix: str) -> bool:
    """Is this <x>.vmwarevm one the stack creates for the environment with this prefix (<name>-<env>)? Matched exactly:
    env 'dev' never claims env 'dev-2's VMs (cloudseed-dev-2-bastion)."""
    return bool(prefix) and re.fullmatch(re.escape(prefix) + _BUNDLE_SUFFIX, bundle_name) is not None


def vmrun_list(host: dict, *, strict: bool = False) -> list[str]:
    """The .vmx paths of running VMs; destructive callers require a verified list."""
    try:
        result = subprocess.run([str(host["vmrun"]), "-T", "fusion" if host["product"] == "fusion" else "ws", "list"],
                                capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or f"exit {result.returncode}").strip())
        lines = (result.stdout or "").strip().splitlines()
        count = re.fullmatch(r"Total running VMs:\s*(\d+)", lines[0].strip()) if lines else None
        running = [line.strip() for line in lines[1:] if line.strip()]
        if count is None or int(count.group(1)) != len(running):
            raise RuntimeError("vmrun returned an incomplete or unrecognized running-VM list")
        return running
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        if strict:
            raise ui.Abort(f"Cannot establish which VMware VMs are running: {exc}. "
                           "No further VM files were removed. Restore vmrun access and retry destroy.") from exc
        return []


def _cleanup_vmrun(host: dict, operation: str, vmx: Path, *args: str) -> None:
    cmd = [str(host["vmrun"]), "-T", "fusion" if host["product"] == "fusion" else "ws", operation, str(vmx), *args]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or f"exit {result.returncode}").strip())
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        raise ui.Abort(f"VMware {operation} failed for {vmx}: {exc}. No direct file cleanup was attempted for this bundle. "
                       "Resolve the VMware error and retry destroy; keep the environment's state and configuration.") from exc


def recorded_vmx_path(path, workdir=None) -> str:
    """A vmx path the provider recorded in an environment's Terraform state, resolved. Older versions kept a relative
    vm_dir as given, and the provider recorded such paths relative to Terraform's working directory, <workdir>/stack -
    never relative to wherever cloudseed happens to run."""
    p = str(path)
    if not os.path.isabs(p) and workdir:
        p = os.path.join(str(workdir), "stack", p)
    return os.path.realpath(p)


def sweep_vms(host: dict, vm_dir: Path, prefix: str | None = None, known_vmx=(), remove_dir: bool = False,
              workdir=None) -> list[str]:
    """Stop and delete the VMs of ONE environment still under vm_dir (covers VMs Terraform lost track of).

    Only bundles named like that environment's VMs (see env_vm_bundle) or holding a .vmx Terraform recorded for it
    (known_vmx; relative ones are taken from the environment's <workdir>/stack, see recorded_vmx_path) are touched.
    Everything else in vm_dir - the user's own VMs, other environments', other files - is left alone, and vm_dir itself
    is only removed when remove_dir is set (cloudseed's own <workdir>/vms) and it is empty.
    Any uncertain stop/delete or failed filesystem cleanup aborts destroy so its configuration can be kept for a retry."""
    removed: list[str] = []
    vm_dir = Path(vm_dir)
    try:
        bundles = sorted(p for p in vm_dir.iterdir() if p.name.endswith(".vmwarevm"))
    except FileNotFoundError:
        return removed
    except OSError as exc:
        raise ui.Abort(f"Cannot inspect VM directory {vm_dir}: {exc}. Check folder access and retry destroy.") from exc
    known = {recorded_vmx_path(p, workdir) for p in known_vmx if p}
    for bundle in bundles:
        known_bundle = any(os.path.dirname(p) == os.path.realpath(bundle) for p in known)
        if not (env_vm_bundle(bundle.name, prefix or "") or known_bundle):
            continue
        if bundle.is_symlink():
            raise ui.Abort(f"Refusing to remove VM bundle symlink {bundle}. Check its target and retry destroy.")
        try:
            vmxs = sorted(p for p in bundle.iterdir() if p.suffix == ".vmx")
        except OSError as exc:
            raise ui.Abort(f"Cannot inspect VM bundle {bundle}: {exc}. Check folder access and retry destroy.") from exc
        running = {os.path.realpath(p) for p in vmrun_list(host, strict=True)}
        # Include a running VM whose VMX was removed or renamed after the scan.
        in_bundle = {p for p in running if os.path.dirname(p) == os.path.realpath(bundle)}
        for vmx in sorted(in_bundle):
            _cleanup_vmrun(host, "stop", Path(vmx), "hard")
        still_running = {os.path.realpath(p) for p in vmrun_list(host, strict=True)} if in_bundle else running
        if any(os.path.dirname(p) == os.path.realpath(bundle) for p in still_running):
            raise ui.Abort(f"VMware still reports a VM running in {bundle}. Its files were not removed. Stop it and retry destroy.")
        for vmx in vmxs:
            _cleanup_vmrun(host, "deleteVM", vmx)
        try:
            try:
                bundle.stat()
            except FileNotFoundError:
                pass   # deleteVM may already have removed the entire bundle
            else:
                shutil.rmtree(bundle)
        except OSError as exc:
            raise ui.Abort(f"Could not finish removing {bundle}: {exc}. Check folder permissions and retry destroy. "
                           "Keep this environment's configuration until its remaining VM files are removed.") from exc
        removed.append(bundle.name)
    if remove_dir:
        try:
            vm_dir.rmdir()   # only when empty
        except OSError:
            pass
    return removed


NETWORKING_FILE = {"darwin": Path("/Library/Preferences/VMware Fusion/networking"), "linux": Path("/etc/vmware/networking")}


def vmnet_users(vmnet: str, exclude: str | None = None) -> list[str]:
    """VMware environments (other than `exclude`) whose last known outputs use this vmnet."""
    users = []
    for e in paths.Env.list_all():
        if e.cloud != "vmware" or e.id == exclude:
            continue
        try:
            if json.loads((e.dir / "outputs.json").read_text()).get("private_vmnet") == vmnet:
                users.append(e.id)
        except (OSError, ValueError, AttributeError):
            continue
    return users


def remove_vmnet(host: dict, vmnet: str, adopted: bool | None = None, env_id: str | None = None,
                 auto_approve: bool = False) -> bool:
    """Delete a custom vmnet this environment created (VMware has no API for it): drop its lines from the networking
    file and re-apply with vmnet-cli. Returns False (the vmnet stays, and is reused next time) when:
      - it is VMware's own (vmnet0/1/8), or it was adopted - it existed before - or that is not known (adopted is None:
        recorded by an older version); only adopted=False (the stack's `private_vmnet_adopted` output) removes it;
      - another VMware environment still uses it;
      - sudo is not available without a prompt in a non-interactive or --auto-approve run, or the user declines."""
    if not vmnet or vmnet in ("vmnet0", "vmnet1", "vmnet8") or adopted is not False:
        return False
    users = vmnet_users(vmnet, exclude=env_id) if env_id else ["(unknown)"]
    if users:
        if env_id:
            ui.info(f"{vmnet} is still used by {', '.join(users)}; keeping it.")
        return False
    system = host.get("os", platform.system().lower())
    netfile = NETWORKING_FILE.get(system)
    cli = Path(host["vmrun"]).parent / "vmnet-cli"
    if not netfile or not netfile.exists() or not cli.exists():
        return False
    num = vmnet.replace("vmnet", "")
    try:
        lines = netfile.read_text().splitlines()
    except OSError:
        return False
    keep = [l for l in lines if not l.startswith(f"answer VNET_{num}_")]
    if len(keep) == len(lines):
        return False
    prompt_ok = ui.interactive() and not auto_approve
    if prompt_ok and not ui.confirm(f"Remove {vmnet} from VMware's network configuration? This restarts all VMware networking "
                                    "(running VMs lose their network briefly) and asks for your password (sudo).", default=True):
        return False
    tmp = paths.HOME / "networking.new"
    tmp.write_text("\n".join(keep) + "\n")
    ui.info(f"Removing {vmnet} from VMware's network configuration (sudo)")
    sudo = ["sudo"] if prompt_ok else ["sudo", "-n"]   # never wait on a password prompt nobody can answer
    steps = [[*sudo, "cp", str(tmp), str(netfile)], [*sudo, str(cli), "--configure"], [*sudo, str(cli), "--stop"], [*sudo, str(cli), "--start"]]
    try:
        for cmd in steps:
            if subprocess.run(cmd).returncode != 0:
                ui.warn(f"{' '.join(cmd[len(sudo):len(sudo) + 2])} failed; {vmnet} stays configured (harmless, reused next time)")
                return False
    finally:
        tmp.unlink(missing_ok=True)
    return True


def stop_vmrest() -> bool:
    """Stop the vmrest this cloudseed home started (tracked by PID) - never one it did not start (the user's own,
    another home's, another tool's, root's). True when it stopped one."""
    pid = _own_vmrest_pid()
    VMREST_PID.unlink(missing_ok=True)
    if not pid:
        return False
    _kill(pid)
    _wait_port_closed(5)
    return True
