"""Post-apply provisioning: copy the parts of this repository a host needs to it and run the Ansible playbook there.

Only an allow-list of the repository is copied (ansible/, terraform/, skills/, cloudseed/, bin/, ...), without local
secrets that may sit in a checkout (.env files, *.tfvars, Terraform state/plans, crash logs, private keys and
certificates, kubeconfigs, cloud credential files, .ssh/ and .kube/ directories) and without any cloudseed working
directory placed inside it; a file whose content is a private key or a service-account key under any other name stops
the copy. Nothing from ~/.cloudseed (state, keys, config) ever leaves this machine. Ansible runs ON the host, so it
does not need to be installed locally.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets as pysecrets
import shlex
import socket
import subprocess
import tarfile
import threading
import time
from pathlib import Path

from . import audit, paths, secrets, ui

# What a host gets: the playbooks (ansible/), and what the tools/agents on the bastion use (cloudseed + cs, skills,
# the Terraform stacks, templates). Anything else in the checkout (tests, scripts, a custom workdir, dotfiles,
# build output such as tfbin/ and the PyInstaller runtime in bundle mode) stays here.
SHIP_TOP = ("ansible", "assets", "bin", "cloudseed", "providers", "README.md", "skills", "templates", "terraform")
EXCLUDE_DIRS = {".git", "build", "dist", "__pycache__", ".terraform", "node_modules", ".venv", ".pytest_cache", "tfbin",
                ".ssh", ".kube"}
# exact names and suffixes only: a substring match (*kubeconfig*) would also drop real sources such as a kubeconfig.py
EXCLUDE_SUFFIXES = (".tfplan", ".pyc", ".png", ".tfvars", ".tfvars.json",
                    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ovpn", ".kubeconfig", ".ppk")
EXCLUDE_NAMES = {"tfplan", "crash.log", ".DS_Store", "kubeconfig", "credentials", "credentials.json",
                 "gcp-credentials.json", ".netrc", ".pgpass"}
_SSH_KEY_NAME = re.compile(r"id_(rsa|dsa|ecdsa|ed25519)(_sk)?(\.|$)")
MAX_SYNC_BYTES = 50 * 1024 * 1024
REMOTE_DIR = "cloudseed"
SECRETS_FILE = "~/cloudseed-secrets.json"


def _include(path: Path) -> bool:
    """Is this repository-relative file shipped to hosts?"""
    parts = path.parts
    if not parts or parts[0] not in SHIP_TOP or set(parts) & EXCLUDE_DIRS:
        return False
    name = path.name
    if name.startswith((".env", ".terraform.lock")) or ".tfstate" in name:   # .env*, terraform.tfstate.<ts>.backup, ...
        return False
    if _SSH_KEY_NAME.match(name):                                             # id_ed25519, id_rsa.pub, id_ecdsa_sk ...
        return False
    return not (name.endswith(EXCLUDE_SUFFIXES) or name in EXCLUDE_NAMES)


# Key material under a name the filters above cannot know: a PEM private key (or OpenVPN static key) block, or a cloud
# service-account key file. Whole header lines only, so source code that merely names the markers is not matched.
_PEM_KEY_LINE = re.compile(rb"^-----BEGIN (?:[A-Z0-9]+ )*(?:PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V\d)-----\s*$", re.M)
_SA_KEY = (re.compile(rb'"type"\s*:\s*"service_account"'), re.compile(rb'"private_key"\s*:\s*"-----BEGIN'))
_SCAN_BYTES = 64 * 1024


def key_material_files(root: Path, files: list[Path]) -> list[Path]:
    """The files among `files` (repository-relative) whose content is a private key or a service-account key."""
    found = []
    for rel in files:
        full = root / rel
        try:
            if full.is_symlink() or not full.is_file():
                continue
            with open(full, "rb") as fh:
                head = fh.read(_SCAN_BYTES)
        except OSError:
            continue
        if _PEM_KEY_LINE.search(head) or all(rx.search(head) for rx in _SA_KEY):
            found.append(rel)
    return found


def _protected_roots(root: Path) -> list[Path]:
    """cloudseed state that lives inside the checkout (CLOUDSEED_HOME, custom --workdir envs): never shipped."""
    cands = [paths.HOME]
    try:
        cands += [Path(p) for p in paths._load_index().values()]
    except Exception:  # noqa: BLE001 - an unreadable index must not block provisioning
        pass
    out = []
    for c in cands:
        try:
            r = Path(c).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if r != root and root in r.parents:
            out.append(r)
    return out


def _is_env_dir(d: Path) -> bool:
    """A cloudseed working directory (config.json next to ssh/ with the generated key), wherever it is."""
    return (d / "config.json").is_file() and (d / "ssh").is_dir()


def repo_files(root: Path | None = None) -> list[Path]:
    root = Path(root or paths.REPO_ROOT).resolve()
    protected = _protected_roots(root)
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):     # followlinks=False: a symlink never pulls in outside trees
        d = Path(dirpath)
        rel_dir = d.relative_to(root)
        keep = []
        for name in dirnames:
            full = d / name
            if (not rel_dir.parts and name not in SHIP_TOP) or name in EXCLUDE_DIRS or _is_env_dir(full):
                continue
            try:
                resolved = full.resolve()
            except (OSError, RuntimeError):
                continue
            if any(resolved == p or p in resolved.parents for p in protected):
                continue
            keep.append(name)
        dirnames[:] = sorted(keep)
        for name in filenames:
            rel = rel_dir / name
            if _include(rel):
                out.append(rel)
    return sorted(out)


def _sync_size_problem(root: Path, files: list[Path]) -> str | None:
    sizes = []
    for rel in files:
        try:
            sizes.append(((root / rel).lstat().st_size, rel))
        except OSError:
            pass
    total = sum(s for s, _ in sizes)
    if total <= MAX_SYNC_BYTES:
        return None
    largest = ", ".join(f"{rel} ({s // (1024 * 1024)} MiB)" for s, rel in sorted(sizes, reverse=True)[:5])
    return (f"The repository copy for the host would be {total // (1024 * 1024)} MiB (limit {MAX_SYNC_BYTES // (1024 * 1024)} "
            f"MiB); largest files: {largest}. Move them out of {root}.")


def ansible_ssh_common_args(env) -> str:
    """The `ansible_ssh_common_args=...` inventory line for an environment. Ansible shlex-splits the value, and ssh
    splits an unquoted UserKnownHostsFile at spaces, so the path is double-quoted inside its -o value, every token is
    shell-quoted, and the whole value is a quoted literal for the INI parser (a workdir may contain spaces)."""
    args = ["-o", "StrictHostKeyChecking=accept-new", "-o", "IdentitiesOnly=yes", "-o", "LogLevel=ERROR",
            "-o", f'UserKnownHostsFile="{env.known_hosts_path()}"']
    return "ansible_ssh_common_args=" + json.dumps(" ".join(shlex.quote(a) for a in args))


# What a local playbook reads from the controller's environment (kubernetes.yml: lookup('env', ...)). Of the values the
# credentials vault put into this process, only these reach ansible-playbook.
ANSIBLE_VAULT_VARS = ("UBUNTU_PRO_TOKEN",)


def ansible_env(**extra: str) -> dict:
    """Environment for a local ansible-playbook run: host keys are checked against the environment's known_hosts (the
    inventory's StrictHostKeyChecking=accept-new handles first contact), colour follows cloudseed's own output
    (NO_COLOR, TERM=dumb, pipes). Built from the real shell environment: the values the credentials vault injected
    (cloud keys, API tokens, anything ANSIBLE_* that an older vault still holds) are left out, except the ones a
    playbook reads (ANSIBLE_VAULT_VARS)."""
    try:
        from . import creds
        base = creds.shell_env()
    except Exception:  # noqa: BLE001 - the vault is optional here; never block a playbook run on it
        base = dict(os.environ)
    for k in ANSIBLE_VAULT_VARS:
        if os.environ.get(k):
            base[k] = os.environ[k]
    color = getattr(ui, "_COLOR", False)
    return dict(base, ANSIBLE_HOST_KEY_CHECKING="True", ANSIBLE_FORCE_COLOR="1" if color else "0",
                ANSIBLE_NOCOLOR="0" if color else "1", ANSIBLE_CONFIG=str(paths.REPO_ROOT / "ansible" / "ansible.cfg"),
                **extra)


def _stream(child) -> None:
    """Print a child's merged output as it arrives, redacted, and log it. One StreamRedactor per stream: a private
    key printed over several lines is hidden whole (line-by-line redaction would pass its body through)."""
    shown = secrets.StreamRedactor().feed
    for line in child.stdout:
        out = shown(line)
        if out:
            print(out, end="", flush=True)
            audit.write(out)


def forget_host_key(env, ip: str) -> None:
    """Drop the remembered SSH host key of one address (a VM re-created there has a new one). ssh-keygen -R also
    finds hashed entries, which a text filter would miss."""
    kh = env.known_hosts_path()
    if not kh.exists():
        return
    subprocess.run(["ssh-keygen", "-R", str(ip), "-f", str(kh)], capture_output=True)
    try:
        Path(f"{kh}.old").unlink()
    except OSError:
        pass


# Hosts Terraform can rebuild behind an address that stays (an Elastic/static IP): <host>_public_ip, <host>_instance_id
REPLACEABLE_HOSTS = ("bastion", "vpn")


def forget_replaced_hosts(env, before: dict | None, after: dict | None) -> list[str]:
    """After an apply: drop the remembered SSH host keys of the hosts that were replaced, i.e. whose instance id
    changed between the previous outputs and these, at the old and the new address. The new instance has new host
    keys behind the same IP, and every ssh would otherwise stop at 'REMOTE HOST IDENTIFICATION HAS CHANGED'. A key is
    only dropped on that proof: a host whose id is missing on either side keeps its key. Returns the addresses."""
    before, after = before or {}, after or {}
    gone: list[str] = []
    for host in REPLACEABLE_HOSTS:
        old_id, new_id = before.get(f"{host}_instance_id"), after.get(f"{host}_instance_id")
        if not old_id or not new_id or old_id == new_id:
            continue
        for ip in (before.get(f"{host}_public_ip"), after.get(f"{host}_public_ip")):
            if ip and ip not in gone:
                forget_host_key(env, ip)
                gone.append(ip)
    return gone


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


_KEY_CHANGED = re.compile(r"REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed|Host key for .* has changed")


class Host:
    def __init__(self, ip: str, user: str, key: Path, label: str, env: "paths.Env | None" = None, local: bool | None = None):
        self.ip, self.user, self.key, self.label = ip, user, key, label
        self.env = env
        # local VMs sit on a host-only network: the public IP of this machine is irrelevant for reaching them
        self.local = (getattr(env, "cloud", "") == "vmware") if local is None else local
        # per-environment known_hosts: re-created hosts reuse IPs and would otherwise be refused as "changed"
        self.ssh_opts = env.ssh_options() if env is not None else ["-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new"]

    def ssh(self, *args: str) -> list[str]:
        # LogLevel=ERROR: no login banner, "Permanently added" or post-quantum-kex notices in captured output and
        # error messages; real failures (refused, publickey, changed host key) are errors and still come through
        return ["ssh", "-i", str(self.key), *self.ssh_opts,
                "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=30", "-o", "LogLevel=ERROR",
                # overrides the workstation locale ssh forwards (SendEnv LANG LC_*), which the host may not have
                "-o", "SetEnv=LC_ALL=C.UTF-8 LANG=C.UTF-8",
                f"{self.user}@{self.ip}", *args]

    def _known_hosts(self) -> str:
        return str(self.env.known_hosts_path()) if self.env is not None else "~/.ssh/known_hosts"

    def command(self, verb: str) -> str:
        """`cloudseed <verb> <cloud> --env <name>` for this host's environment: the bare forms fail ('needs a cloud')."""
        env = self.env
        target = f"{env.cloud} --env {env.name}" if env is not None else "<cloud> --env <name>"
        return f"cloudseed {verb} {target}"

    @property
    def what(self) -> str:
        """The host after 'the': 'bastion', 'VPN host', or 'VM <name>' / 'host <name>' (a Kubernetes node)."""
        if self.label in ("bastion", "vpn"):
            return {"vpn": "VPN host"}.get(self.label, self.label)
        return f"{'VM' if self.local else 'host'} {self.label}"

    def wait(self, timeout: int = 420, retry: str | None = None) -> None:
        """Wait until the host takes SSH. `retry`: the closing advice when it never does (default: 'then re-run
        `cloudseed provision <cloud> --env <name>`.'); a scan or a node join passes its own."""
        deadline = time.time() + timeout
        attempt = 0
        last = ""
        problem = None
        with ui.Spinner(f"Waiting for SSH on {self.label} ({self.user}@{self.ip})") as sp:
            while time.time() < deadline:
                attempt += 1
                p = subprocess.run(self.ssh("true"), capture_output=True, text=True)
                if p.returncode == 0:
                    sp.done_text = f"{self.label} reachable at {self.ip}"
                    return
                err = (p.stderr or "").strip()
                last = err.splitlines()[-1].strip() if err else last
                if _KEY_CHANGED.search(err):
                    # permanent: retrying for minutes cannot help, and the key must never be dropped silently
                    kh = self._known_hosts()
                    problem = (f"{self.label} at {self.ip} presents a different SSH host key than the one recorded in {kh}. "
                               f"If the VM/host was re-created on this address, forget the old key and re-run:\n"
                               f"    ssh-keygen -R {self.ip} -f {shlex.quote(kh)}\n"
                               "Otherwise do not continue: something else may be answering on this address.")
                    break
                sp.update(f"Waiting for SSH on {self.label} ({self.user}@{self.ip}) · attempt {attempt}")
                time.sleep(min(15, 5 + attempt))
        if problem:
            raise ui.Abort(problem)
        why = f" Last error: {last.rstrip('.')}." if last else ""
        # named as the advice names it ('The VPN host', 'The VM cs-dev-wk1'), not by the internal label ('vpn')
        raise ui.Abort(f"The {self.what} at {self.ip} did not accept SSH within {timeout}s.{why} "
                       f"{self._unreachable_hint(last, retry)}")

    def _gcp_os_login(self) -> tuple[dict, dict] | None:
        """GCP with enable_os_login: (the recorded OS Login profile, {} when none was registered; the config), else None."""
        if self.env is None or getattr(self.env, "cloud", "") != "gcp":
            return None
        cfg, _ = self.env.try_load()
        if not _truthy((cfg.get("vars") or {}).get("enable_os_login")):
            return None
        profile = cfg.get("os_login")
        return (profile if isinstance(profile, dict) else {}), cfg

    def _refused_hint(self, retry: str) -> str:
        """A refused key (not OS Login): the login side is the problem. A source address the firewall does not admit
        times out and is never refused, so update-ip is no help here."""
        env = self.env
        text = (f"The {self.what} refuses the SSH key {self.key} for user {self.user} (a firewall problem would time out, "
                "not refuse): ")
        if self.local:
            text += ("the VM installs the key on its first boot, so cloud-init may still be running or may have failed "
                     "there (see the VM's console in VMware), or the key or the user is not the one the VM was created "
                     "with. ")
        else:
            text += "the key or the user is not the one the host was created with. "
        where = f"the ssh_public_key in {env.config_path}" if env is not None else "the environment's ssh_public_key"
        text += (f"Check that `ssh-keygen -y -f {shlex.quote(str(self.key))}` prints {where} (a matching private key "
                 f"kept elsewhere is set with `{self.command('setup')} --ssh-public-key <its .pub> --ssh-private-key "
                 "<it>`)")
        if getattr(env, "cloud", "") == "gcp":
            text += ("; on GCP, an organization policy that enforces OS Login also refuses metadata keys (then switch "
                     f"OS Login on: `{self.command('setup')} --var enable_os_login=true`)")
        return f"{text}, {retry}"

    def _unreachable_hint(self, last: str, retry: str | None = None) -> str:
        retry = retry or f"then re-run `{self.command('provision')}`."
        status = f"`{self.command('status')}`"
        refused = "Permission denied" in last
        found = None if self.local else self._gcp_os_login()
        if refused and found is None:
            return self._refused_hint(retry)
        if self.local:
            # a host-only network: the public IP of this machine plays no part (update-ip does not apply)
            return f"Check that the VM is running ({status}), {retry}"
        network = f"Check {status} and your public IP (`{self.command('update-ip')}`)"
        if found is None:
            return f"{network}, {retry}"
        profile, cfg = found
        env = self.env
        if not profile.get("user"):
            login = (f"OS Login is on, but no OS Login profile is recorded for {env.id} (set up with --dry-run?), so SSH "
                     f"used the metadata user {self.user}, which an OS Login {self.what} ignores. With gcloud logged in, "
                     f"re-run `{self.command('setup')}`: it registers the key, records the POSIX user name and grants "
                     "the access.")
        else:
            account = profile.get("account") or "your gcloud account"
            member = profile.get("member") or account
            project = str((cfg.get("vars") or {}).get("project_id") or "")
            in_project = f" --project {shlex.quote(project)}" if project else ""
            login = (f"OS Login is on: the {self.what} accepts only {profile['user']} (the POSIX user of {account}) with "
                     f"the key registered to that account (`gcloud compute os-login ssh-keys add --key-file "
                     f"{shlex.quote(str(self.key) + '.pub')}{in_project}`), and only while {member} holds "
                     f"roles/compute.osAdminLogin on the {self.what} and roles/iam.serviceAccountUser on its service "
                     "account (the stack grants both; IAM changes take a minute or two). Check the login with "
                     f"`gcloud compute os-login describe-profile{in_project}`, {retry}")
        if refused:
            # a refused key: the login side is the problem; a timeout can still be the cloud firewall
            return f"The {self.what} refuses the SSH key {self.key} for user {self.user}. {login}"
        return f"{network}. {login}"

    def wait_cloud_init(self, timeout: int = 900) -> None:
        """cloud-init still runs (package upgrades) when SSH first answers; wait so apt is not locked underneath Ansible."""
        with ui.Spinner(f"Waiting for cloud-init to finish on the {self.label}") as sp:
            subprocess.run(self.ssh(f"command -v cloud-init >/dev/null && timeout {timeout} cloud-init status --wait >/dev/null 2>&1; true"),
                           capture_output=True, timeout=timeout + 60)
            sp.done_text = f"{self.label} finished first boot"

    def sync_repo(self) -> None:
        root = Path(paths.REPO_ROOT).resolve()
        files = repo_files(root)
        problem = _sync_size_problem(root, files)
        if problem:
            raise ui.Abort(problem)
        keys = key_material_files(root, files)
        if keys:
            # refused, not skipped: the key should not sit in the checkout at all, and a false match must never
            # silently leave a file out of the host's copy
            shown = ", ".join(str(k) for k in keys[:5]) + (f" and {len(keys) - 5} more" if len(keys) > 5 else "")
            raise ui.Abort(f"Private key material in the repository checkout, which is copied to the {self.label}: {shown}. "
                           f"Move it out of {root} (keys belong in ~/.ssh, cloud credentials in your cloud CLI's "
                           "config), then re-run.")
        ui.info(f"Copying repository ({root}) to {self.label}:~/{REMOTE_DIR}")
        cmd = self.ssh(f"rm -rf ~/{REMOTE_DIR} && mkdir -p ~/{REMOTE_DIR} && tar xzf - -C ~/{REMOTE_DIR}")
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        assert proc.stdin is not None and proc.stderr is not None
        # stderr is drained while the archive streams: a remote that writes a lot of it (tar clock-skew warnings for
        # every file) must never fill the pipe and stall the copy
        err_chunks: list[bytes] = []
        drain = threading.Thread(target=lambda: err_chunks.append(proc.stderr.read()), daemon=True)
        drain.start()
        sent, local_err = 0, None
        try:
            with tarfile.open(fileobj=proc.stdin, mode="w|gz") as tar:   # streamed: nothing is held in memory
                for rel in files:
                    tar.add(str(root / rel), arcname=str(rel), recursive=False)
                    sent += (root / rel).lstat().st_size
        except (BrokenPipeError, ConnectionResetError):
            pass                                   # the remote side ended early: its stderr says why
        except OSError as e:
            local_err = e                          # a local file could not be read: the copy on the host is incomplete
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass
        rc = proc.wait()
        drain.join(timeout=30)
        err = b"".join(err_chunks).decode(errors="replace")
        if local_err is not None:
            raise ui.Abort(f"Repository copy failed: {local_err}")
        if rc != 0:
            raise ui.Abort(f"Repository copy failed: {secrets.redact(err.strip()[-800:])}")
        ui.ok(f"{len(files)} files ({sent // 1024} KiB) copied")

    def put_json(self, remote_path: str, data: dict) -> None:
        proc = subprocess.run(self.ssh(f"umask 077 && cat > {remote_path}"), input=json.dumps(data).encode(),
                              capture_output=True)
        if proc.returncode != 0:
            raise ui.Abort(f"Could not write {remote_path}: {proc.stderr.decode(errors='replace')[-400:]}")

    def remove_secrets(self) -> None:
        """Best effort: the Ubuntu Pro token / Tailscale key file `cloudseed provision` may have put on the host."""
        try:
            subprocess.run(self.ssh(f"rm -f {SECRETS_FILE}"), capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def run(self, command: str, extra_env: dict | None = None) -> int:
        """Stream a remote command; output is redacted before it is printed."""
        env_prefix = " ".join(f"{k}={json.dumps(v)}" for k, v in (extra_env or {}).items())
        full = f"{env_prefix} {command}".strip()
        audit.write(f"$ ssh {self.user}@{self.ip} {command}")
        with subprocess.Popen(self.ssh(full), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
            _stream(child)
        return child.returncode


def new_cluster_token(distro: str = "rke2") -> str:
    """Each distro parses the join token differently: kubeadm needs its bootstrap-token format
    ([a-z0-9]{6}.[a-z0-9]{16}); RKE2 rejects that (a '.' makes it look like its K10 CA-hash format) and takes
    a plain secret, so it gets 48 hex characters."""
    if distro == "kubeadm":
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        pick = lambda n: "".join(pysecrets.choice(alphabet) for _ in range(n))
        return f"{pick(6)}.{pick(16)}"
    return pysecrets.token_hex(24)


def cluster_token_ok(token: str, distro: str) -> bool:
    """Can `distro` use this join token? (An env re-created with the other distro still has the old token file.)"""
    if distro == "kubeadm":
        return re.fullmatch(r"[a-z0-9]{6}\.[a-z0-9]{16}", token) is not None
    return bool(token) and "." not in token and re.fullmatch(r"[A-Za-z0-9_+/=-]+", token) is not None


def _cluster_token(k8s_dir: Path, distro: str) -> str:
    token_file = k8s_dir / "token"
    try:
        token = token_file.read_text().strip()
    except OSError:
        token = ""
    if not cluster_token_ok(token, distro):
        token = new_cluster_token(distro)
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(token)
    return token


def local_source_address(ip: str) -> str | None:
    """The address this machine sends from to reach `ip` (a route lookup: no packet is sent). For a local VM that is
    exactly the source its sshd sees - the VMware host adapter - so fail2ban can be told never to ban it."""
    try:
        target = ipaddress.ip_address(str(ip).strip())
        with socket.socket(socket.AF_INET6 if target.version == 6 else socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((str(target), 22))
            addr = ipaddress.ip_address(s.getsockname()[0])
    except (OSError, ValueError):
        return None
    return None if addr.is_unspecified or addr.is_loopback else str(addr)


def _source_cidrs(ips) -> list[str]:
    out = []
    for ip in ips:
        addr = local_source_address(ip)
        cidr = f"{addr}/{128 if addr and ':' in addr else 32}" if addr else None
        if cidr and cidr not in out:
            out.append(cidr)
    return out


# Pod and Service ranges of the self-managed distributions: RKE2's defaults (ansible/roles/rke2 leaves them as they
# are), kubeadm's kubeadm_pod_cidr (also in Flannel's manifest) and kubeadm_service_cidr (ansible/roles/kubeadm/defaults).
# A node network that overlaps them breaks the cluster: Service IPs land on real hosts, pod routes shadow the nodes.
LOCAL_K8S_RANGES = {"rke2": (("pod", "10.42.0.0/16"), ("Service", "10.43.0.0/16")),
                    "kubeadm": (("pod", "10.244.0.0/16"), ("Service", "10.96.0.0/16"))}


def local_k8s_range_problems(network_cidr, distro: str) -> list[str]:
    """Why a local environment's network cannot carry a `distro` cluster ([] when it can, or is unknown)."""
    nets = _ipv4_nets([network_cidr])
    if not nets:
        return []
    return [f"the network {nets[0]} overlaps {rng}, the {kind} range of the {distro} cluster"
            for kind, rng in LOCAL_K8S_RANGES.get(distro, ()) if nets[0].overlaps(ipaddress.ip_network(rng))]


def saved_harden(cfg: dict) -> bool:
    """Whether the cluster's nodes were provisioned with OS hardening (--no-harden: False): the kubernetes record, else
    the bastion's (setup provisions every host with the same flags), else True."""
    provisioned = cfg.get("provisioned") or {}
    for host in ("kubernetes", "bastion"):
        rec = provisioned.get(host) if isinstance(provisioned, dict) else None
        if isinstance(rec, dict) and "harden" in rec:
            value = rec["harden"]
            if isinstance(value, bool):
                return value
            text = str(value).strip().lower()
            if text in ("1", "true", "yes", "on", "0", "false", "no", "off"):
                return _truthy(text)
    return True


def forget_removed_cluster(cfg: dict, outputs: dict) -> bool:
    """Drop the provisioned record of a local cluster whose VMs are gone: `outputs` (read from the Terraform state just
    after an apply or a destroy) list no control-plane VM - Kubernetes was turned off, or its VMs were destroyed. A
    cluster created later on the environment is a new one: provision_local_kubernetes then refuses a network that
    overlaps its pod/Service ranges instead of only warning, and its nodes inherit nothing from the old record.
    Returns True when the record was dropped (the caller saves the configuration)."""
    rec = cfg.get("provisioned") if isinstance(cfg, dict) else None
    if not isinstance(rec, dict) or "kubernetes" not in rec or (outputs or {}).get("kubernetes_control_plane_ips"):
        return False
    del rec["kubernetes"]
    return True


def rerun_command(cloud, env, host: str | None = None, *, harden: bool = True, firewall: bool = True,
                  tools: bool = True, sync_only: bool = False) -> str:
    """The `cloudseed provision` command that repeats a run with the same choices: a plain re-run would harden a host
    provisioned with --no-harden again, or put back a host firewall that --no-firewall removed."""
    parts = ["cloudseed", "provision", getattr(cloud, "key", str(cloud)), "--env", env.name]
    if host:
        parts += ["--host", host]
    if sync_only:
        parts.append("--sync-only")
    else:
        parts += [flag for flag, on in (("--no-harden", harden), ("--no-firewall", firewall), ("--no-tools", tools))
                  if not on]
    return " ".join(parts)


def provision_local_kubernetes(cloud, env, cfg: dict, outputs: dict, limit: list[str] | None = None, *,
                               harden: bool | None = None, rerun: str | None = None) -> None:
    """Install RKE2 / kubeadm on the private node VMs, driving Ansible from this machine (host-only network).
    `limit`: only these (new) nodes join; their IPs were just (re)assigned to fresh VMs. `harden`: None = as the
    cluster was provisioned before (saved_harden). `rerun`: the command that repeats this (default: provision
    --host k8s with the same hardening choice)."""
    from . import deps
    if harden is None:
        harden = saved_harden(cfg)
    rerun = rerun or rerun_command(cloud, env, "k8s", harden=harden)
    cps = outputs.get("kubernetes_control_plane_ips") or []
    wks = outputs.get("kubernetes_worker_ips") or []
    if not cps:
        return
    distro = outputs.get("kubernetes_distro") or cfg["vars"].get("kubernetes_distro", "rke2")
    clash = local_k8s_range_problems(cfg.get("network_cidr"), distro)
    if clash:
        if not (cfg.get("provisioned") or {}).get("kubernetes") and not limit:
            # a new cluster: refused before anything is installed
            raise ui.Abort(f"Kubernetes cannot run on {env.id}: {'; '.join(clash)}. Re-create the environment with "
                           f"another network, e.g. cloudseed setup {cloud.key} --env {env.name} --cidr 10.123.0.0/24.")
        ui.warn(f"{env.id}: {'; '.join(clash)}. Services or pods may collide with hosts on the network; the cluster "
                "is left as it is.")
    k8s_dir = env.dir / "k8s"
    k8s_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(k8s_dir, 0o700)
    token = _cluster_token(k8s_dir, distro)
    user = cloud.ssh_user(cfg)
    key = env.private_key_path(cfg)
    inv = ["[control_plane]"]
    inv += [f"{cfg['name']}-{cfg['env']}-cp{i + 1} ansible_host={ip}" for i, ip in enumerate(cps)]
    inv += ["", "[workers]"]
    inv += [f"{cfg['name']}-{cfg['env']}-wk{i + 1} ansible_host={ip}" for i, ip in enumerate(wks)]
    inv += ["", "[k8s:children]", "control_plane", "workers", "", "[k8s:vars]",
            f"ansible_user={user}", f"ansible_ssh_private_key_file={json.dumps(str(key))}",
            ansible_ssh_common_args(env),
            "ansible_python_interpreter=/usr/bin/python3"]
    (k8s_dir / "inventory.ini").write_text("\n".join(inv) + "\n")
    version = str(cfg["vars"].get("kubernetes_version") or "").strip()
    # The Ubuntu Pro token is not written here: kubernetes.yml reads UBUNTU_PRO_TOKEN from this process's environment.
    # fail2ban_ignore_cidrs: this machine's address on the nodes' network (the VMware host adapter), which the nodes'
    # fail2ban must never ban - every cloudseed command reaches them from there. RKE2's CNI is Canal (fixed in the role).
    vars_ = {"kubernetes_distro": distro, "k8s_token": token,
             "kubeconfig_dest": str(k8s_dir / "kubeconfig"), "cluster_name": env.id,
             "ssh_user": user, "allowed_ssh_cidrs": [], "fail2ban_ignore_cidrs": _source_cidrs(list(cps) + list(wks)),
             "harden": harden, "harden_ssh": harden, "enable_auditd": harden,
             "fips_mode": bool(cfg["vars"].get("fips_mode", False)),
             # "false" saved by hand or an older version is off (bool() would read it as on)
             "rke2_cis_profile": _truthy(cfg["vars"].get("kubernetes_cis_profile", False))}
    if version:   # empty: RKE2 joins every node at the version the cluster runs; kubeadm uses its supported default
        vars_["rke2_version" if distro == "rke2" else "kubernetes_version"] = version
    fd = os.open(k8s_dir / "vars.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(vars_, fh)
    ui.header(f"Kubernetes ({distro}) on {len(cps)} control-plane + {len(wks)} worker VM(s)" + (f"  · joining {', '.join(limit)}" if limit else ""))
    all_nodes = {f"{cfg['name']}-{cfg['env']}-cp{i + 1}": ip for i, ip in enumerate(cps)}
    all_nodes.update({f"{cfg['name']}-{cfg['env']}-wk{i + 1}": ip for i, ip in enumerate(wks)})
    for name, ip in all_nodes.items():
        if limit and name not in limit:
            continue
        if limit:
            forget_host_key(env, ip)     # a freshly created VM on a reused address: the old node's key is stale
        h = Host(ip, user, key, name, env=env, local=True)
        h.wait(timeout=600, retry=f"then re-run `{rerun}`.")
        h.wait_cloud_init()
    playbook = deps.ensure_local_ansible()
    cmd = [str(playbook), "-i", str(k8s_dir / "inventory.ini"), str(paths.REPO_ROOT / "ansible" / "kubernetes.yml"),
           "-e", f"@{k8s_dir / 'vars.json'}"]
    if limit:
        first_cp = f"{cfg['name']}-{cfg['env']}-cp1"
        cmd += ["--limit", ",".join(dict.fromkeys(limit + [first_cp]))]
    print(ui.dim("$ ansible-playbook -i k8s/inventory.ini ansible/kubernetes.yml"))
    audit.write("$ " + " ".join(cmd))
    (k8s_dir / "version").unlink(missing_ok=True)      # rewritten by the playbook's last play
    with subprocess.Popen(cmd, env=ansible_env(), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          cwd=str(paths.REPO_ROOT / "ansible")) as child:
        _stream(child)
    rc = child.returncode
    if rc != 0:
        raise ui.Abort(f"Kubernetes installation failed (exit {rc}). Re-run: {rerun}")
    try:
        running = (k8s_dir / "version").read_text().strip()
    except OSError:
        running = ""
    cfg.setdefault("provisioned", {})["kubernetes"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                                       "distro": distro, "control_planes": len(cps), "workers": len(wks),
                                                       "harden": harden,   # nodes added later join the same way
                                                       **({"version": running} if running else {})}
    env.save(cfg)
    audit.note(env, "provision-kubernetes", {"distro": distro, "control_planes": cps, "workers": wks})
    if not running:
        # the playbook's last step asks the API server for its version: no answer means it is not serving (yet)
        ui.warn(f"The Kubernetes API at https://{cps[0]}:6443 did not answer after the installation: it may still be "
                "starting, or a node did not come back. Check with: kubectl --kubeconfig "
                f"{shlex.quote(str(k8s_dir / 'kubeconfig'))} get nodes   (re-run: {rerun})")
    ui.panel("Kubernetes ready" if running else "Kubernetes installed", [
        ("distro", distro + (f" {running}" if running else "")),
        ("api", f"https://{cps[0]}:6443"),
        ("kubeconfig", str(k8s_dir / "kubeconfig")),
        ("use it", f"cs k8s kubeconfig {cloud.key} --env {env.name}   ·   kubectl get nodes"),
    ], accent="leaf")


def ssh_allow_list(cidrs) -> list[str]:
    """The host firewall's SSH allow-list: IPv4 only (the hosts have no IPv6 address), normalized, with duplicate,
    overlapping and adjacent ranges merged (nftables rejects overlapping elements of an interval set)."""
    nets = []
    for c in cidrs or []:
        try:
            net = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            raise ui.Abort(f"'{c}' in the SSH allow-list is not a valid IP or CIDR. Fix it with `cloudseed update-ip`.")
        if net.version == 4:
            nets.append(net)
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


def operator_cidrs(cidrs) -> list[str]:
    """The operator's IPv4 sources (the saved SSH allow-list), leniently: fail2ban must never ban them, also on hosts
    whose firewall does not pin SSH sources. An entry that does not parse is left out, never an error here."""
    nets = []
    for c in cidrs or []:
        try:
            net = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4:
            nets.append(net)
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


VPN_POOL_DEFAULT = "10.8.0.0/24"
# AKS pod / Service CIDRs (terraform/azure/modules/kubernetes; cli.AKS_RANGES): inside an Azure VNet's reach, but never
# reported as outputs, so an OpenVPN client pool must stay out of them too
AKS_RANGES = ("10.244.0.0/16", "10.250.0.0/16")


def _ipv4_nets(cidrs) -> list:
    nets = []
    for c in cidrs or ():
        try:
            net = ipaddress.ip_network(str(c).strip(), strict=False) if c else None
        except ValueError:
            net = None
        if net is not None and net.version == 4:
            nets.append(net)
    return nets


def vpn_routes(cfg: dict, outputs: dict) -> list:
    """The networks the VPN host pushes (OpenVPN) / advertises (Tailscale): the private network, plus private endpoints
    outside it, i.e. the GKE control plane (kubernetes_master_cidr) and pod range when the stack reports them."""
    return list(ipaddress.collapse_addresses(_ipv4_nets(
        (cfg.get("network_cidr") or "10.0.0.0/16", outputs.get("kubernetes_master_cidr"), outputs.get("kubernetes_pod_cidr")))))


def _vpn_pool_candidates():
    """10.8.0.0/24 first, so every VPN whose network leaves it free keeps the pool it always had; then /24s at the top of
    10.0.0.0/8, whose /16s netutil.pick_network_cidr hands out last; then 192.168.255.0/24. Never 100.64.0.0/10
    (Tailscale and carrier-grade NAT on the workstation) or 172.17-31 (Docker networks on the workstation)."""
    yield VPN_POOL_DEFAULT
    for a in range(255, 8, -1):
        yield f"10.{a}.255.0/24"
    yield "192.168.255.0/24"


def pick_vpn_client_cidr(avoid, prefer_avoid=()) -> str:
    """The OpenVPN client pool: the first candidate /24 that overlaps nothing in `avoid` (the networks the VPN routes,
    reserved ranges: a hard rule) and, when one is left, nothing in `prefer_avoid` (other environments' networks and
    pools, so one workstation can be connected to several VPNs at once)."""
    hard, soft = _ipv4_nets(avoid), _ipv4_nets(prefer_avoid)
    fallback = None
    for cand in _vpn_pool_candidates():
        net = ipaddress.ip_network(cand)
        if any(net.overlaps(h) for h in hard):
            continue
        if not any(net.overlaps(s) for s in soft):
            return cand
        fallback = fallback or cand
    if fallback:
        return fallback
    raise ui.Abort("No free /24 is left for the OpenVPN client pool: the environment's networks cover 10.8.0.0/24, "
                   "every 10.N.255.0/24 (N = 9 to 255) and 192.168.255.0/24. Use a smaller network (--cidr).")


def vpn_network_vars(cfg: dict, outputs: dict, client_cidr: str | None = None) -> dict:
    """What vpn.yml needs, computed here so the host needs no ansible.utils/netaddr: the routes (vpn_routes) and the
    OpenVPN client pool, which must not overlap any of them. The server takes the pool's first address on tun0, so a
    pool inside the private network would shadow its gateway, DNS resolver and hosts. client_cidr=None: picked."""
    routes = vpn_routes(cfg, outputs)
    if client_cidr is None:
        client_cidr = pick_vpn_client_cidr(routes)
    try:
        client = ipaddress.ip_network(str(client_cidr).strip(), strict=False)
    except ValueError:
        raise ui.Abort(f"'{client_cidr}' is not a valid OpenVPN client pool (a CIDR such as 10.8.0.0/24).") from None
    if client.version != 4 or client.prefixlen > 29:
        raise ui.Abort(f"The OpenVPN client pool {client} must be an IPv4 network of /29 or larger.")
    clash = [str(r) for r in routes if client.overlaps(r)]
    if clash:
        raise ui.Abort(f"The OpenVPN client pool {client} overlaps {', '.join(clash)}, which the VPN routes: the server "
                       "would take an address of that network. It needs a range outside every routed network.")
    return {"vpn_client_net": str(client.network_address), "vpn_client_mask": str(client.netmask),
            "vpn_routes": [str(n) for n in routes],
            "vpn_push_routes": [[str(n.network_address), str(n.netmask)] for n in routes]}


def _other_env_networks(env) -> list[str]:
    """Network CIDRs and OpenVPN pools of every other environment (an unreadable one is skipped)."""
    out: list[str] = []
    try:
        envs = paths.Env.list_all()
    except Exception:  # noqa: BLE001 - listing environments must never block provisioning
        return out
    for e in envs:
        if e.id == env.id:
            continue
        other, problem = e.try_load()
        if problem:
            continue
        out += [str(other[k]) for k in ("network_cidr", "vpn_client_cidr") if other.get(k)]
    return out


def choose_vpn_client_cidr(cloud, env, cfg: dict, outputs: dict) -> str:
    """The environment's OpenVPN client pool: the one it has (cfg["vpn_client_cidr"]) while that is still outside every
    network the VPN routes, else a new pick, which `provision` keeps in the config. Clients need no new profile when it
    changes: the server pushes it."""
    avoid: list = list(vpn_routes(cfg, outputs))
    if getattr(cloud, "key", "") == "azure" and (cfg.get("vars") or {}).get("enable_kubernetes"):
        avoid += AKS_RANGES
    saved = cfg.get("vpn_client_cidr")
    if saved:
        nets = _ipv4_nets([saved])
        if nets and nets[0].prefixlen <= 29 and not any(nets[0].overlaps(a) for a in _ipv4_nets(avoid)):
            return str(nets[0])
    pool = pick_vpn_client_cidr(avoid, _other_env_networks(env))
    if saved:
        ui.info(f"OpenVPN client pool {saved} overlaps a network the VPN routes now: moving it to {pool}.")
    elif pool != VPN_POOL_DEFAULT:
        default = ipaddress.ip_network(VPN_POOL_DEFAULT)
        routed = any(default.overlaps(a) for a in _ipv4_nets(avoid))
        why = ("overlaps a network the VPN routes" if routed else
               "is used by another environment's network or VPN; a pool of its own lets this machine reach both at once")
        if isinstance((cfg.get("provisioned") or {}).get("vpn"), dict):
            # a VPN provisioned before pools were chosen ran the default pool and has none saved: it moves
            ui.info(f"OpenVPN client pool: moving it from {VPN_POOL_DEFAULT} to {pool} ({VPN_POOL_DEFAULT} {why}). "
                    "Client profiles need no change: the server pushes the pool.")
        else:
            ui.info(f"OpenVPN client pool: {pool} ({VPN_POOL_DEFAULT} {why}).")
    return pool


def cluster_version(cloud, cfg: dict, outputs: dict) -> str:
    """The managed cluster's Kubernetes version the bastion's kubectl follows (its minor; kubectl supports one minor of
    skew). On GKE kubernetes_version is only a minimum - the release channel upgrades the control plane past it - so the
    running version the stack reported at the last apply wins there. EKS and AKS run the configured version ("" on EKS:
    the tools role asks EKS)."""
    if getattr(cloud, "key", "") == "gcp":
        running = str(outputs.get("kubernetes_master_version") or "").strip()
        if running:
            return running
    return str((cfg.get("vars") or {}).get("kubernetes_version") or "").strip()


def provision(cloud, env, cfg: dict, outputs: dict, *, harden: bool = True, firewall: bool = True,
              tools: bool = True, sync_only: bool = False, playbook: str = "bastion.yml",
              host_key: str = "bastion_public_ip", label: str = "bastion", extra_vars: dict | None = None,
              rerun: str | None = None) -> None:
    """Provision one host (bastion.yml / vpn.yml run on it). `rerun`: the command that repeats this run, named when
    it fails (default: the same flags, for the whole environment when this is the bastion, else --host <label>; a
    caller that ran `--host bastion` passes rerun_command(cloud, env, "bastion", ...))."""
    ip = outputs.get(host_key)
    local = bool(getattr(cloud, "local", False))
    if not ip:
        if local and outputs:
            # the VM exists (apply ran) but its guest reported no address: the fix is in the guest, apply then refreshes
            raise ui.Abort(f"The {label} VM of {env.id} has no IP address yet: VMware reports one only when open-vm-tools "
                           "runs in the guest and the VM got an address from the NAT network's (vmnet8) DHCP. Check the "
                           "VM's console in VMware, then refresh the outputs with "
                           f"`cloudseed apply {cloud.key} --env {env.name}` and run "
                           f"`cloudseed provision {cloud.key} --env {env.name}`.")
        raise ui.Abort(f"No {label} IP in outputs; run `cloudseed apply {cloud.key} --env {env.name}` first.")
    host = Host(ip, cloud.ssh_user(cfg), env.private_key_path(cfg), label, env=env, local=local)
    # the command that repeats this run with the same choices (the bastion's run is the whole environment's)
    rerun = rerun or rerun_command(cloud, env, None if label == "bastion" else label, harden=harden,
                                   firewall=firewall, tools=tools or label != "bastion", sync_only=sync_only)
    ui.header(f"Provisioning the {label} ({env.id})")
    host.wait(retry=f"then re-run `{rerun}`.")
    try:
        host.wait_cloud_init()
        host.sync_repo()
        if sync_only:
            ui.ok("Repository synced (provisioning skipped).")
            return
        vars_ = {
            "cloud": cloud.key,
            "ssh_user": cloud.ssh_user(cfg),
            "allowed_ssh_cidrs": cfg.get("allowed_ssh_cidrs", []),
            "ssh_open_any": local,          # local VMs: host-only network, SSH from any source on it
            "harden": harden,
            "harden_ssh": harden,
            "host_firewall": firewall,
            "enable_auditd": harden,
            # --no-harden leaves automatic updates as the image ships them. A VMware VM's first boot switched its apt
            # timers off (cloudseed's own template, so package installs never race apt-daily; older templates did it on
            # every boot), and only this role switches them back on: local VMs always get it, hardened or not
            "auto_updates": harden or local,
            "install_terraform": tools,
            "install_cloud_cli": tools,
            # the bastion gets kubectl for the managed cluster (the tools role; its role/identity may reach the API)
            "enable_kubernetes": _truthy((cfg.get("vars") or {}).get("enable_kubernetes", False)),
            "kubernetes_version": cluster_version(cloud, cfg, outputs),
            "kubernetes_cluster_name": str(outputs.get("kubernetes_cluster_name") or ""),
            "cloud_region": str(cfg.get("region") or ""),
            "env_id": env.id,
            "infra_name": cfg.get("name"),
            "network_cidr": cfg.get("network_cidr"),
            # never banned by fail2ban, whatever the host firewall's allow-list is (callers may leave that empty); a
            # local VM also sees this machine's host adapter address, which is in no allow-list (bootstrap.sh adds the
            # SSH session's own source on every host)
            "fail2ban_ignore_cidrs": operator_cidrs(cfg.get("allowed_ssh_cidrs")) + (_source_cidrs([ip]) if local else []),
        }
        if playbook == "vpn.yml":
            pool = None
            if (extra_vars or {}).get("vpn_type", "openvpn") == "openvpn":
                pool = cfg["vpn_client_cidr"] = choose_vpn_client_cidr(cloud, env, cfg, outputs)   # saved on success
            vars_.update(vpn_network_vars(cfg, outputs, pool))
        vars_.update(extra_vars or {})
        requested = list(vars_.get("allowed_ssh_cidrs") or [])
        vars_["allowed_ssh_cidrs"] = ssh_allow_list(requested)
        if firewall and not vars_["allowed_ssh_cidrs"] and not vars_.get("ssh_open_any"):
            # fail closed: an empty list would render a host firewall that either opens TCP/22 to everyone or locks SSH out
            raise ui.Abort(("The SSH allow-list has no IPv4 entry (" + ", ".join(map(str, requested)) + "): the hosts only have "
                            "IPv4 addresses. " if requested else "The environment has no SSH allow-list. ") +
                           f"Set your IPv4 address with: cloudseed update-ip {cloud.key} --env {env.name}")
        host.put_json("~/cloudseed-vars.json", vars_)
        ui.info(f"Running Ansible on the {label} (installs ansible-core there on first run)")
        # a UTF-8 locale every image has: ssh forwards the workstation's LANG/LC_*, which the host may not have
        rc = host.run(f"bash ~/{REMOTE_DIR}/ansible/bootstrap.sh",
                      {"CLOUDSEED_PLAYBOOK": playbook, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})
    finally:
        host.remove_secrets()   # also after a failed or sync-only run: no Pro token / Tailscale key left on the host
    if rc != 0:
        raise ui.Abort(f"Provisioning failed (exit {rc}). Re-run with: {rerun}")
    before = (cfg.get("provisioned") or {}).get(label)
    before = before if isinstance(before, dict) else {}
    cfg.setdefault("provisioned", {})[label] = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                                "playbook": playbook, "harden": harden, "firewall": firewall,
                                                "tools": tools}
    env.save(cfg)
    audit.note(env, f"provision-{label}", {"playbook": playbook, "host": ip, "harden": harden, "firewall": firewall, "tools": tools})
    skipped = [what for what, on in (("OS hardening", harden), ("host firewall", firewall)) if not on]
    done = f"{label} provisioned ({', '.join(skipped)} skipped)" if skipped else f"{label} provisioned and hardened"
    if host_key == "bastion_public_ip":
        login = f"cloudseed ssh {cloud.key} --env {env.name}"
    else:   # `cloudseed ssh` goes to the bastion; this host takes SSH on its own address
        login = " ".join(shlex.quote(a) for a in ["ssh", "-i", str(host.key), *env.ssh_options(), f"{host.user}@{ip}"])
    ui.ok(f"{done}. SSH in with: {login}")
    # the roles remove what an earlier run installed for a control that is off now (hardening role, first lines)
    removed = []
    if not firewall and before.get("firewall"):
        # vpn.yml's hosts and local bastions forward traffic for others: their NAT rule is kept (nftables-off.conf.j2)
        forwards = playbook == "vpn.yml" or bool((extra_vars or {}).get("nat_source_cidrs"))
        removed.append("the host firewall" + (" (the NAT for the traffic it forwards stays)" if forwards else ""))
    if not harden and before.get("harden"):
        # automatic security updates are left on (Ubuntu images ship them enabled; turning them off is no rollback)
        removed.append("the OS hardening: sshd settings, fail2ban, audit rules, kernel/core-dump/sudo settings (the "
                       "PAM null-password and umask edits and automatic security updates stay; kernel settings return "
                       "to the defaults at the next reboot)")
    if removed:
        ui.info(f"Removed from the {label} what an earlier run installed: {'; '.join(removed)}.")


FIPS_PENDING = "/etc/cloudseed-fips-pending"


def await_fips(host: Host, rerun: str) -> None:
    """After a bastion/VPN play with fips_mode: wait for the reboot the fips role scheduled (a systemd timer a minute
    after the play) and verify fips_enabled=1. `rerun`: the command that provisions the environment again. A failed
    SSH check right after the play is never taken as "no reboot pending": the host may already be going down, so it is
    waited for. Only a fips_enabled value actually read is reported as "not active"; a host that does not come back
    is reported as unreachable (Host.wait)."""
    try:
        p = subprocess.run(host.ssh(f"test -f {FIPS_PENDING} && echo yes || echo no"), capture_output=True, text=True,
                           timeout=90)
        rc, pending = p.returncode, (p.stdout or "").strip()
    except subprocess.TimeoutExpired:
        rc, pending = 124, ""
    if rc != 0 or pending != "no":
        with ui.Spinner(f"{host.label}: rebooting to activate FIPS mode") as sp:
            time.sleep(75)
            sp.done_text = f"{host.label}: reboot issued"
        host.wait(timeout=600, retry=f"then re-run `{rerun}`.")
        rm = subprocess.run(host.ssh(f"sudo -n rm -f {FIPS_PENDING}"), capture_output=True, text=True)
        if rm.returncode != 0:
            ui.warn(f"{host.label}: could not remove {FIPS_PENDING} ({(rm.stderr or '').strip()[-200:] or f'exit {rm.returncode}'}); "
                    "the next provisioning run removes it once FIPS mode is active.")
    p = subprocess.run(host.ssh("cat /proc/sys/crypto/fips_enabled"), capture_output=True, text=True)
    state = (p.stdout or "").strip()
    if p.returncode != 0:
        detail = secrets.redact((p.stderr or "").strip())[-300:]
        raise ui.Abort(f"{host.label}: could not read the FIPS state (ssh exit {p.returncode}"
                       f"{': ' + detail if detail else ''}). Check that the host is up, then re-run: {rerun}")
    if state == "1":
        ui.ok(f"{host.label}: FIPS mode active (fips_enabled=1)")
        return
    raise ui.Abort(f"{host.label}: FIPS mode is NOT active after provisioning (fips_enabled={state or '?'}). "
                   f"Check the provisioning log, then re-run: {rerun}")
