"""Where cloudseed keeps things on disk, and how it finds its own Terraform code."""

from __future__ import annotations

import contextlib
import errno
import fnmatch
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import ui

try:
    import fcntl
except ImportError:  # Native Windows has no flock; environment mutations are refused.
    fcntl = None  # type: ignore[assignment]

IS_BUNDLE = bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")
IN_CONTAINER = os.environ.get("CLOUDSEED_IN_CONTAINER") == "1"

# In a PyInstaller bundle, resources live in a per-run temp dir (sys._MEIPASS).
REPO_ROOT = Path(sys._MEIPASS) if IS_BUNDLE else Path(__file__).resolve().parent.parent  # type: ignore[attr-defined]

HOME = Path(os.environ.get("CLOUDSEED_HOME", str(Path.home() / ".cloudseed"))).expanduser()
ENVS_DIR = HOME / "envs"
BIN_DIR = HOME / "bin"
SETTINGS_PATH = HOME / "settings.json"
WORKDIRS_INDEX = HOME / "workdirs.json"   # env id -> custom working directory (when not under ENVS_DIR)


def ensure_home() -> None:
    for d in (HOME, ENVS_DIR, BIN_DIR):
        d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(HOME, 0o700)
    except OSError:
        pass


# Never part of the Terraform module tree cloudseed ships: provider caches and lock files a developer's `terraform init`
# left in a module directory (hundreds of MB), state, plans. Skipped by the bundle digest and the copy below.
TF_TREE_IGNORE = (".terraform", ".terraform.lock.hcl", "*.tfstate", "*.tfstate.*", ".terraform.tfstate.lock.info",
                  "tfplan", "crash.log", ".DS_Store")
_TF_COMPLETE = ".cloudseed-complete"      # written last into a copied tree: a copy without it was interrupted


def _tf_ignored(name: str) -> bool:
    return name == _TF_COMPLETE or any(fnmatch.fnmatchcase(name, pat) for pat in TF_TREE_IGNORE)


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    root = Path(root)
    files = []
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not _tf_ignored(d))      # never descend into provider caches
        files += [Path(dirpath) / n for n in names if not _tf_ignored(n)]
    for p in sorted(files, key=lambda f: f.relative_to(root).as_posix()):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()[:12]


def tf_root() -> Path:
    """Directory holding the per-cloud Terraform modules.

    For a source checkout that's ./terraform. For a single-file bundle the
    modules are copied out of the temp extraction dir into ~/.cloudseed so
    that module source paths stay valid between runs.
    """
    src = REPO_ROOT / "terraform"
    if not IS_BUNDLE:
        return src
    ensure_home()
    digest = _tree_digest(src)
    dst = HOME / "terraform" / digest
    if (dst / _TF_COMPLETE).is_file():
        return dst
    # Copy into a temporary sibling and rename it into place: an interrupted copy (Ctrl-C, full disk) never leaves a
    # half tree under the final name, which every later run would use; two runs racing both end up with one tree.
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(dir=str(dst.parent), prefix=f".{digest}."))
    try:
        shutil.copytree(src, tmp / "tree", ignore=shutil.ignore_patterns(*TF_TREE_IGNORE))
        (tmp / "tree" / _TF_COMPLETE).write_text(digest + "\n")
        if dst.exists() and not (dst / _TF_COMPLETE).is_file():
            os.replace(dst, tmp / "partial")                  # a half copy (no marker): moved aside, then deleted
        try:
            os.replace(tmp / "tree", dst)
        except OSError:
            if not (dst / _TF_COMPLETE).is_file():            # not another run's complete copy: a real error
                raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return dst


def bundled_terraform_binary() -> Path | None:
    if not IS_BUNDLE:
        return None
    p = REPO_ROOT / "tfbin" / "terraform"
    return p if p.exists() else None


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Replace `path` with `text` atomically: a crash, a full disk or Ctrl-C mid-write leaves the old file intact
    instead of a truncated one. The temp file is created 0600 and chmod'ed before the rename, so the content is never
    readable with looser permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class ConfigError(ValueError):
    """An environment's config.json cannot be read. A ValueError, so code that tolerates unreadable environments
    (`except ValueError`) keeps working; the CLI prints just the message."""


# ---------- settings (global preferences) ----------

def load_settings() -> dict:
    try:
        return json.loads(SETTINGS_PATH.read_text())
    except (OSError, ValueError):
        return {}


def save_settings(settings: dict) -> None:
    ensure_home()
    atomic_write(SETTINGS_PATH, json.dumps(settings, indent=2) + "\n")


# ---------- environments ----------

def _load_index() -> dict:
    try:
        return json.loads(WORKDIRS_INDEX.read_text())
    except (OSError, ValueError):
        return {}


def _save_index(index: dict) -> None:
    ensure_home()
    atomic_write(WORKDIRS_INDEX, json.dumps(index, indent=2) + "\n")


def config_owner(config_path: Path) -> str | None:
    """The environment id ('<cloud>-<env>') a config.json says it belongs to; None when it cannot be read or does not
    say (a hand-written or very old file)."""
    try:
        cfg = json.loads(Path(config_path).read_text())
    except (OSError, ValueError):
        return None
    if isinstance(cfg, dict) and cfg.get("cloud") and cfg.get("env"):
        return f"{cfg['cloud']}-{cfg['env']}"
    return None


# What cloudseed itself creates in a working directory (every command's outputs included). Anything else found in a
# directory offered as a new working directory belongs to someone else.
ENV_ARTIFACTS = ("config.json", "inventory.json", "outputs.json", "stack", "bootstrap", "ssh", "logs", "vms", "k8s",
                 "dry-run", "scans", "finops", "chaos", "dr", "vpn", "platform", "operations")
_OS_DEBRIS = (".DS_Store", "Thumbs.db", "desktop.ini")


def _within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def abandoned_workdir(directory: Path) -> bool:
    """True when an indexed working directory no longer holds an environment: no config.json and no local Terraform
    state (the directory was deleted or moved aside). A directory that lost only its config.json but still holds a
    local terraform.tfstate is not abandoned: another environment taking it over would plan against that state (and
    offer to delete what it records)."""
    d = Path(directory)
    return not any((d / f).exists() for f in ("config.json", "stack/terraform.tfstate", "bootstrap/terraform.tfstate"))


def workdir_problem(target: str | Path, env_id: str) -> str | None:
    """Why `target` must not become env_id's working directory, or None.

    A working directory is cloudseed's own: it is made private (0700), its config and Terraform state are rewritten,
    and `destroy --purge` deletes what cloudseed put there. So it may not be the filesystem root, the home directory,
    cloudseed's home, the cloudseed checkout or a parent of any of them, and an existing directory must be empty
    or already hold this environment (another environment's config, or files that are not cloudseed's, are refused)."""
    target = Path(target).expanduser().resolve()
    envs = ENVS_DIR.expanduser().resolve()
    use = f"use a dedicated directory such as {target / env_id}"
    for what, place in (("your home directory", "~"), ("cloudseed's home", HOME), ("the cloudseed installation", REPO_ROOT)):
        try:
            p = Path(place).expanduser().resolve()
        except (OSError, RuntimeError):   # no home directory for this user
            continue
        if _within(p, target):
            desc = what if p == target else f"a parent of {what} ({p})"
            return f"{target} is {desc}; it cannot be an environment's working directory ({use})."
    if target == Path(target.anchor) or target == envs:
        return f"{target} cannot be an environment's working directory ({use})."
    if _within(target, HOME.expanduser().resolve()) and not _within(target, envs / env_id):
        return (f"{target} is inside cloudseed's own directory {HOME}; leave --workdir out to use {envs / env_id}, or "
                "choose a directory outside it.")
    # another environment's remembered working directory (workdirs.json) that still holds it: the same directory, one
    # inside it or around it. An abandoned one (deleted or moved aside) is released by set_workdir instead.
    for other, p in _load_index().items():
        if other == env_id:
            continue
        try:
            d = Path(p).expanduser().resolve()
        except (OSError, RuntimeError, TypeError):
            continue
        if (_within(d, target) or _within(target, d)) and not abandoned_workdir(d):
            how = "is the working directory" if d == target else f"overlaps the working directory ({d})"
            return f"{target} {how} of {other}; choose a separate directory for {env_id}."
    if not target.exists():
        return None
    if not target.is_dir():
        return f"{target} is a file, not a directory."
    owner = config_owner(target / "config.json")
    if (target / "config.json").exists():
        if owner == env_id:
            return None                                   # this environment's own directory
        held = f"the configuration of {owner}" if owner else "a config.json that is not this environment's"
        return f"{target} already holds {held}; choose an empty directory for {env_id}."
    try:
        foreign = sorted(p.name for p in target.iterdir() if p.name not in ENV_ARTIFACTS + _OS_DEBRIS)
    except OSError as e:
        return f"{target} cannot be read ({e.strerror or e})."
    if foreign:
        shown = ", ".join(foreign[:5]) + (", ..." if len(foreign) > 5 else "")
        return (f"{target} is not empty ({shown}); cloudseed makes its working directory private and manages what is in "
                f"it, so give {env_id} a new or empty directory (e.g. {target / env_id}).")
    return None


def _stale_claims(index: dict, target: Path, env_id: str) -> list[str]:
    """Other workdirs.json entries a directory being claimed now makes obsolete: ones whose directory is `target`,
    inside it or around it and is abandoned (abandoned_workdir: deleted or moved aside, so that environment is gone;
    `list` no longer shows it). Kept, such an entry would map two ids to one directory. Entries elsewhere stay, even
    abandoned-looking ones: a volume that is only unmounted looks the same, and forgetting it would lose track of an
    environment that may own cloud resources."""
    out = []
    for other, p in index.items():
        if other == env_id:
            continue
        try:
            d = Path(p).expanduser().resolve()
        except (OSError, RuntimeError, TypeError):
            continue
        if (_within(d, target) or _within(target, d)) and abandoned_workdir(d):
            out.append(other)
    return out


class EnvBusy(ui.Abort):
    """Another cloudseed run holds the environment's lock (Env.lock)."""


# Env.lock bookkeeping: the locks this process holds (env id -> open lock file, owning thread, depth), and the
# environment variable that tells cloudseed processes started under a lock that their parent holds it.
_LOCKS: dict = {}
_LOCKS_GUARD = threading.Lock()
LOCK_ENV_VAR = "CLOUDSEED_ENV_LOCKS"


def _inherited_locks() -> dict:
    out = {}
    for item in os.environ.get(LOCK_ENV_VAR, "").split(","):
        env_id, _, pid = item.strip().rpartition("=")
        if env_id and pid.isdigit():
            out[env_id] = int(pid)
    return out


def _set_inherited(env_id: str, pid: int | None) -> None:
    held = _inherited_locks()
    if pid is None:
        held.pop(env_id, None)
    else:
        held[env_id] = pid
    if held:
        os.environ[LOCK_ENV_VAR] = ",".join(f"{k}={v}" for k, v in sorted(held.items()))
    else:
        os.environ.pop(LOCK_ENV_VAR, None)


class Env:
    """One environment: <cloud>-<name>, e.g. aws-dev.

    Its working directory holds config.json, the generated SSH key, the rendered Terraform roots, local state,
    provisioning artifacts and (for local targets) the VM files. Default: ~/.cloudseed/envs/<id>; a custom
    path can be chosen with `cloudseed setup ... --workdir PATH` and is remembered in workdirs.json.
    """

    # set by cli._cache_outputs for this run: why terraform could not read the stack's outputs (None when it could)
    outputs_error: str | None = None

    def __init__(self, cloud: str, name: str, workdir: str | Path | None = None):
        self.cloud = cloud
        self.name = name
        self.id = f"{cloud}-{name}"
        custom = workdir or _load_index().get(self.id)
        self.dir = Path(custom).expanduser().resolve() if custom else ENVS_DIR / self.id
        self._layout()

    def _layout(self) -> None:
        self.config_path = self.dir / "config.json"
        self.stack_dir = self.dir / "stack"
        self.bootstrap_dir = self.dir / "bootstrap"
        self.ssh_dir = self.dir / "ssh"
        self.vms_dir = self.dir / "vms"
        self.logs_dir = self.dir / "logs"

    def set_workdir(self, path: str | Path | None) -> None:
        """Choose (and create) the working directory; remembered globally when it is not the default. Raises ui.Abort
        for a directory that cannot be one (see workdir_problem): the home directory, a parent of cloudseed's own
        files, another environment's directory, a directory holding files that are not cloudseed's."""
        index = _load_index()
        if path:
            target = Path(path).expanduser().resolve()
            if target != self.dir.resolve() or index.get(self.id) != str(target):
                problem = workdir_problem(target, self.id)
                if problem:
                    raise ui.Abort(problem)
            self.dir = target
            index[self.id] = str(self.dir)
            for other in _stale_claims(index, target, self.id):
                index.pop(other, None)
        else:
            self.dir = ENVS_DIR / self.id
            index.pop(self.id, None)
        _save_index(index)
        self._layout()
        self.create_dirs()

    def create_dirs(self) -> None:
        """Create the working directory and its subdirectories. A directory cloudseed creates is made private (0700),
        and ssh/ always is; a directory that existed already outside cloudseed's home (a --workdir the user made)
        keeps its permissions."""
        try:
            own = not self.dir.exists() or _within(self.dir.resolve(), ENVS_DIR.resolve())
        except OSError:
            own = False
        for d in (self.dir, self.stack_dir, self.ssh_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)
        for d in ((self.dir, self.ssh_dir) if own else (self.ssh_dir,)):
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

    def exists(self) -> bool:
        return self.config_path.exists()

    def load(self) -> dict:
        """The saved configuration. Raises ConfigError (naming the file and the way out) when it is not a JSON object,
        e.g. after a hand edit went wrong or a write from an older cloudseed was interrupted."""
        try:
            text = self.config_path.read_text()
        except UnicodeDecodeError as e:
            raise ConfigError(self._broken(f"not UTF-8 text ({e.reason})")) from None
        try:
            cfg = json.loads(text)
        except ValueError as e:
            where = f", line {e.lineno} column {e.colno}" if isinstance(e, json.JSONDecodeError) else ""
            raise ConfigError(self._broken(f"not valid JSON ({getattr(e, 'msg', e)}{where})")) from None
        if not isinstance(cfg, dict):
            raise ConfigError(self._broken(f"a JSON {type(cfg).__name__}, not an object"))
        owner = f"{cfg['cloud']}-{cfg['env']}" if cfg.get("cloud") and cfg.get("env") else None
        if owner and owner != self.id:
            raise ConfigError(self._foreign(owner))
        return cfg

    def _foreign(self, owner: str) -> str:
        """config.json belongs to another environment: older versions let two environments share a directory, and
        loading it as this one would plan, apply or destroy the other environment's resources."""
        way_out = (f"remove the \"{self.id}\" entry from {WORKDIRS_INDEX}" if self.id in _load_index()
                   else f"move {self.dir} to {ENVS_DIR / owner}")
        return (f"{self.config_path} holds the configuration of environment {owner}, not of {self.id} (older cloudseed "
                f"versions could give two environments the same working directory). Commands for {self.id} are "
                f"refused so they cannot act on {owner}'s resources. To make cloudseed forget {self.id}, {way_out} "
                "(cloud resources, if any, are not touched).")

    def _broken(self, why: str) -> str:
        forget = f"move {self.dir} aside"
        if self.id in _load_index():   # a --workdir environment: workdirs.json still points at the directory
            forget += f" and remove the \"{self.id}\" entry from {WORKDIRS_INDEX}"
        return (f"The configuration of environment {self.id} is unreadable: {self.config_path} is {why}. "
                f"Repair the file by hand, or {forget} to make cloudseed forget {self.id} "
                "(its cloud resources, if any, are not touched).")

    def try_load(self) -> tuple[dict, str | None]:
        """(config, None), or ({}, problem) when config.json is missing or unreadable: for code that walks every
        environment and must not fail because one of them is broken."""
        try:
            return self.load(), None
        except ConfigError as e:
            return {}, str(e)
        except OSError as e:
            return {}, f"{self.config_path}: {e.strerror or e}"

    def save(self, cfg: dict) -> None:
        if "uid" not in cfg and not self.config_path.exists():
            # a new environment: its unique id, tagged CloudseedEnvId on every resource (Cloud.tags) so it only ever
            # adopts what it created itself, never a same-named environment's resources (reconcile.ownership)
            cfg["uid"] = uuid.uuid4().hex[:16]
        self.create_dirs()
        cfg["workdir"] = str(self.dir)
        cfg.setdefault("created_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        cfg["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        atomic_write(self.config_path, json.dumps(cfg, indent=2) + "\n", 0o600)

    def known_hosts_path(self) -> Path:
        """Per-environment known_hosts. Private IPs (and cloud public IPs) are reused when an environment is
        re-created, so the user's ~/.ssh/known_hosts would hold a stale key and every ssh would be refused."""
        return self.dir / "ssh" / "known_hosts"

    def ssh_options(self) -> list[str]:
        """ssh -o options for this environment's hosts. The known_hosts path is double-quoted inside its value:
        ssh splits an unquoted UserKnownHostsFile at spaces (it takes a list of files), so a working directory with a
        space would otherwise make it read and write two wrong files."""
        self.known_hosts_path().parent.mkdir(parents=True, exist_ok=True)
        return ["-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-o", f'UserKnownHostsFile="{self.known_hosts_path()}"']

    def forget_host_keys(self) -> None:
        """After VMs/hosts are destroyed the next ones get new keys: drop the remembered ones."""
        try:
            self.known_hosts_path().unlink()
        except OSError:
            pass

    GENERATED_KEYS = ("id_ed25519", "id_rsa", "id_ecdsa")   # netutil.ensure_ssh_key's file names

    def private_key_path(self, cfg: dict) -> Path:
        """The SSH identity for this environment: the user's --ssh-private-key, else the generated pair whose public
        half is the environment's key (id_ed25519 normally, id_rsa in FIPS mode; FIPS environments made by older
        versions keep an ECDSA key under the id_ed25519 name)."""
        custom = cfg.get("ssh_private_key_path")
        if custom:
            return Path(custom).expanduser()
        want = str(cfg.get("ssh_public_key") or "").split()[:2]
        present = []
        for name in self.GENERATED_KEYS:
            priv = self.ssh_dir / name
            if not priv.is_file():
                continue
            present.append(priv)
            try:
                have = (self.ssh_dir / f"{name}.pub").read_text().split()[:2]
            except (OSError, UnicodeDecodeError):
                continue
            if want and have == want:
                return priv
        return present[0] if present else self.ssh_dir / "id_ed25519"

    @staticmethod
    def list_all() -> list["Env"]:
        """Every environment with a config.json. A workdirs.json entry whose directory holds another environment's
        configuration (two environments were given one directory by an older version) is skipped: that directory is
        listed once, as the environment its config.json names. Commands for the skipped id are refused by load()."""
        out: dict[str, Env] = {}
        if ENVS_DIR.exists():
            for d in sorted(ENVS_DIR.iterdir()):
                if (d / "config.json").exists():
                    cloud, _, name = d.name.partition("-")
                    out[d.name] = Env(cloud, name)
        for env_id, path in _load_index().items():
            cfg_file = Path(path).expanduser() / "config.json"
            if cfg_file.exists():
                owner = config_owner(cfg_file)
                if owner and owner != env_id:
                    continue
                cloud, _, name = env_id.partition("-")
                out[env_id] = Env(cloud, name, path)
        return [out[k] for k in sorted(out)]

    # ---- the per-environment lock ----
    def lock_path(self) -> Path:
        return HOME / "locks" / f"{self.id}.lock"

    @contextlib.contextmanager
    def lock(self, action: str = "", wait: float = 0.0):
        """Exclusive lock for a command that changes this environment (setup, plan, apply, destroy, update-ip,
        provision, undo, cluster changes): a second cloudseed working on the same environment - another terminal, the
        web console, an MCP client or agent - gets EnvBusy, naming the run that holds it, instead of racing it on
        config.json and the Terraform working directory. `wait`: seconds to wait for the other run first.

        flock-based, so a crashed run never leaves it held. Re-entrant within the thread that holds it, and for
        cloudseed processes that run starts (they inherit CLOUDSEED_ENV_LOCKS). The lock file lives in cloudseed's
        home, not the working directory, so it also covers a first setup whose directory does not exist yet.
        Inability to create, acquire or record this lock aborts the command before entering the mutation body."""
        me = threading.get_ident()
        with _LOCKS_GUARD:
            held = _LOCKS.get(self.id)
            if held is not None and held["thread"] == me:
                held["depth"] += 1
            else:
                held = None
        if held is not None:                      # nested in this thread (e.g. setup running provision)
            try:
                yield self
            finally:
                with _LOCKS_GUARD:
                    held["depth"] -= 1
            return
        fh = self._acquire(action, wait)
        if fh is None:                            # a verified parent process already holds the lock
            yield self
            return
        with _LOCKS_GUARD:
            _LOCKS[self.id] = {"fh": fh, "thread": me, "depth": 1}
        _set_inherited(self.id, os.getpid())
        try:
            yield self
        finally:
            with _LOCKS_GUARD:
                _LOCKS.pop(self.id, None)
            _set_inherited(self.id, None)
            try:
                fh.seek(0)
                fh.truncate()
            except OSError:
                pass
            fh.close()                            # releases the flock

    def lock_holder(self) -> dict:
        """What the lock file says about the run holding the lock: pid, action, since ({} when free or unreadable)."""
        try:
            data = json.loads(self.lock_path().read_text() or "{}")
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _acquire(self, action: str, wait: float):
        if fcntl is None:
            raise ui.Abort(f"Cannot lock {self.id}: this platform has no supported environment locking. "
                           "Run environment-changing commands from macOS or Linux; native Windows mutation is unsupported.")
        try:
            self.lock_path().parent.mkdir(parents=True, exist_ok=True)
            fh = open(self.lock_path(), "a+")
        except OSError as e:
            raise ui.Abort(f"Cannot open the environment lock for {self.id} at {self.lock_path()}: {e}. "
                           "Check the lock directory's permissions and available space before retrying.") from e
        deadline = time.monotonic() + max(0.0, float(wait or 0))
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                    fh.close()
                    raise ui.Abort(f"Cannot acquire the environment lock for {self.id} at {self.lock_path()}: {e}. "
                                   "Use a writable filesystem that supports file locking before retrying.") from e
            holder = self.lock_holder()
            if holder.get("pid") not in (None, os.getpid()) and _inherited_locks().get(self.id) == holder.get("pid"):
                fh.close()
                return None                       # started by the run that holds it: that run is waiting for us
            if time.monotonic() >= deadline:
                fh.close()
                what = f"`cloudseed {holder['action']}`" if holder.get("action") else "another cloudseed command"
                since = f" since {holder['since']}" if holder.get("since") else ""
                pid = f" (pid {holder['pid']}{since})" if holder.get("pid") else ""
                raise EnvBusy(f"{self.id} is busy: {what}{pid} is changing it. Wait for it to finish (or stop it), "
                              "then run this again.")
            time.sleep(0.2)
        try:
            fh.seek(0)
            fh.truncate()
            fh.write(json.dumps({"pid": os.getpid(), "action": action or " ".join(sys.argv[1:3]) or "",
                                 "since": datetime.now(timezone.utc).isoformat(timespec="seconds")}) + "\n")
            fh.flush()
        except OSError as e:
            fh.close()
            raise ui.Abort(f"Cannot record the environment lock for {self.id} at {self.lock_path()}: {e}. "
                           "Check the lock directory's permissions and available space before retrying.") from e
        return fh
