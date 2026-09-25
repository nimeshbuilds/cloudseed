"""Day-2 helpers for optional services: Kubernetes kubeconfig and the VPN (OpenVPN / Tailscale)."""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import audit, deps, paths, provision as prov, secrets, ui


# ---------------- tools, installed only with consent ----------------

AUTO_INSTALL = False   # the CLI may set this when the run was approved up front (--auto-approve)


def _install_approved(argv: bool = True) -> bool:
    """Non-interactive runs install missing tools only when approved up front (--auto-approve, or opt-in env var).
    argv=False: the command line is not cloudseed's to read (the databricks/snowflake passthrough, where an
    --auto-approve belongs to the vendor CLI's own command)."""
    return AUTO_INSTALL or os.environ.get("CLOUDSEED_AUTO_INSTALL") == "1" or (argv and "--auto-approve" in sys.argv[1:])


# how a non-interactive run may still install a missing tool: every command honours the opt-in variable, while
# --auto-approve exists only on some commands (and on the databricks/snowflake passthrough it is the vendor's own)
_UNATTENDED_INSTALL_HINT = "or run it on a terminal without -y to be asked, or set CLOUDSEED_AUTO_INSTALL=1 to let cloudseed install it"


def ensure_tool(tool: str, why: str, default: bool = True, argv_consent: bool = True) -> str:
    """Path of `tool`. A missing one is installed only with consent: asked on a terminal; with -y only when the run was
    approved up front (CLOUDSEED_AUTO_INSTALL=1, or the command's own --auto-approve; not read from the command line when
    argv_consent=False); otherwise stop with the exact command to install it. An agent session never installs anything:
    it stops with the command for the human to run."""
    found = deps.find(tool)
    minimum = (deps.TOOLS.get(tool) or {}).get("min_version")
    # a tool older than its minimum version (deps.TOOLS: Go for the VMware provider) counts as missing, as in doctor
    have = deps.version_of(tool) if found and minimum else ""
    old = bool(have) and deps.too_old(tool, have)
    if found and not old:
        return found
    how = f"cloudseed install {tool}"
    lack = f"the one at {found} is {have}, older than {minimum}" if old else "is not installed"
    verb = "Update" if old else "Install"
    if tool not in deps.INSTALLERS:
        raise ui.Abort(f"{tool} is needed {why} but {lack}. {verb} it first.")
    # before any question: --auto-approve is no consent for an agent (an old tool is not "missing": say what it is)
    if old and deps.agent_session():
        raise ui.Abort(f"{tool} is needed {why} but {lack}. This is an agent session, and cloudseed never installs "
                       f"software for an agent; ask the user to run: {how}", code=2)
    deps.refuse_install_in_agent_session(tool, why)
    brew_pkg = (deps.TOOLS.get(tool) or {}).get("brew")
    method = f"brew install {brew_pkg}" if brew_pkg and shutil.which("brew") else f"the official release into {paths.BIN_DIR}"
    if old:     # deps.install updates it: brew upgrade, else a current release first on cloudseed's PATH
        method = how
    if ui.interactive():
        if not ui.confirm(f"{tool} is needed {why} but {lack}. {verb} it now ({method})?", default=default):
            raise ui.Abort(f"{tool} is required {why}. {verb} it with: {how}")
    elif not _install_approved(argv=argv_consent):
        raise ui.Abort(f"{tool} is needed {why} but {lack}. {verb} it first: {how}   ({_UNATTENDED_INSTALL_HINT})", code=2)
    else:
        ui.info(f"{tool} is needed {why}; {'updating' if old else 'installing'} it ({method})")
    deps.install(tool)
    found = deps.find(tool)
    if not found:
        raise ui.Abort(f"Could not install {tool}; try: {how}")
    now = deps.version_of(tool) if minimum else ""
    if now and deps.too_old(tool, now):
        raise ui.Abort(f"{tool} at {found} is still {now}, older than {minimum}; try: {how}")
    return found


# ---------------- settings of an environment ----------------

def _vars(cfg: dict) -> dict:
    v = (cfg or {}).get("vars")
    return v if isinstance(v, dict) else {}


def _var_on(cfg: dict, key: str) -> bool:
    """A boolean setting (cfg['vars'][key]) read the way setup reads it (clouds.base.as_bool): a saved string such as
    "false", "no" or "0" is off, where plain truthiness would read it as on. A value that is no boolean at all is off."""
    from .clouds.base import as_bool   # local import: the cloud adapters are not needed to load this module
    try:
        return as_bool(_vars(cfg).get(key, False), key)
    except ValueError:
        return False


def _env_dir(cloud_key: str, cfg: dict) -> Path | None:
    """The environment's working directory as every command resolves it (workdirs.json, else the default under
    CLOUDSEED_HOME). The `workdir` recorded in config.json is only a copy that goes stale when cloudseed's home or the
    directory moves; it is used when the environment cannot be resolved (no config.json where it should be)."""
    saved = Path(cfg["workdir"]).expanduser() if cfg.get("workdir") else None
    if not cfg.get("env"):
        return saved
    env = paths.Env(cfg.get("cloud") or cloud_key, str(cfg["env"]))
    if env.config_path.exists() or saved is None:
        return env.dir
    return saved


def _needs(cloud_key: str, cfg: dict, what: str, value, fix: str):
    """A setting the kubeconfig fetch cannot do without: its value, or a clear stop (instead of a bare KeyError)."""
    if value:
        return value
    raise ui.Abort(f"{what} of {cloud_key}-{cfg.get('env')} has no {fix}")


# ---------------- Kubernetes ----------------

def _no_cluster_message(cloud_key: str, cfg: dict) -> str:
    """No cluster in the outputs: create the one the settings already enable (a --dry-run / --plan-only / declined setup
    leaves it switched on), or enable one."""
    env_name = cfg.get("env")
    if _var_on(cfg, "enable_kubernetes"):
        return f"Kubernetes is enabled for {cloud_key}-{env_name} but not created yet: cloudseed setup {cloud_key} --env {env_name}"
    return ("This environment has no Kubernetes cluster. Enable one with: "
            f"cloudseed setup {cloud_key} --env {env_name} --var enable_kubernetes=true")


_PRIVATELINK_WHY = "Its privatelink name resolves only inside the VNet, so the VPN cannot reach it either."


def _azure_privatelink(cloud_key: str, outputs: dict) -> bool:
    """An AKS API endpoint still reported by its privatelink name (an environment not re-applied since the stack began
    publishing the public <prefix>.hcp.<region>.azmk8s.io name of private clusters): that name resolves only inside
    the VNet, so a VPN client cannot use it - only the bastion tunnel can."""
    return cloud_key == "azure" and ".privatelink." in str(outputs.get("kubernetes_endpoint") or "").lower()


def kubeconfig_command(cloud_key: str, cfg: dict, outputs: dict, kubeconfig: Path | None = None) -> list[str]:
    """The cloud CLI call that writes the cluster's kubeconfig; `kubeconfig` names the file explicitly (az ignores
    $KUBECONFIG and would otherwise always write ~/.kube/config)."""
    name = outputs.get("kubernetes_cluster_name")
    env_name = cfg.get("env")
    if cloud_key == "vmware":
        return ["export", f"KUBECONFIG={(_env_dir(cloud_key, cfg) or Path('.')) / 'k8s' / 'kubeconfig'}"]
    if not name:
        raise ui.Abort(_no_cluster_message(cloud_key, cfg))
    v = _vars(cfg)
    public = _var_on(cfg, "kubernetes_public_endpoint")
    if cloud_key == "aws":
        cmd = ["aws", "eks", "update-kubeconfig", "--name", name,
               "--region", _needs(cloud_key, cfg, "config.json", cfg.get("region"),
                                  f"region: cloudseed setup aws --env {env_name} --region REGION"),
               "--alias", f"{cloud_key}-{env_name}"]
        if v.get("profile"):
            cmd += ["--profile", v["profile"]]
        if kubeconfig:
            cmd += ["--kubeconfig", str(kubeconfig)]
        return cmd
    if cloud_key == "gcp":
        cmd = ["gcloud", "container", "clusters", "get-credentials", name,
               "--project", _needs(cloud_key, cfg, "config.json", v.get("project_id"),
                                   f"project_id: cloudseed setup gcp --env {env_name} --project-id ID"),
               "--location", _needs(cloud_key, cfg, "outputs.json", outputs.get("kubernetes_location") or v.get("zone"),
                                    f"kubernetes_location: run cloudseed output gcp --env {env_name} (or cloudseed apply gcp --env {env_name})")]
        if not public:
            cmd.append("--internal-ip")
        return cmd                          # gcloud writes the first file of $KUBECONFIG
    rg = _needs(cloud_key, cfg, "outputs.json", outputs.get("resource_group_name"),
                f"resource_group_name: run cloudseed output azure --env {env_name} (or cloudseed apply azure --env {env_name})")
    sub = _needs(cloud_key, cfg, "config.json", v.get("subscription_id"),
                 f"subscription_id: cloudseed setup azure --env {env_name} --subscription-id ID")
    cmd = ["az", "aks", "get-credentials", "--resource-group", rg, "--name", name, "--overwrite-existing", "--subscription", sub]
    if not public and outputs.get("kubernetes_endpoint") and not _azure_privatelink(cloud_key, outputs):
        # a private cluster that publishes its <prefix>.hcp.<region>.azmk8s.io name (resolving to the private endpoint):
        # without the flag az writes the privatelink server name, which VPN clients cannot resolve. An environment not
        # re-applied yet still reports the privatelink name, and there the flag would fail (no public FQDN yet).
        cmd.append("--public-fqdn")
    if kubeconfig:
        cmd += ["--file", str(kubeconfig)]
    return cmd


def _aws_fips(cloud_key: str, cfg: dict, outputs: dict | None = None) -> bool:
    """An AWS environment created in FIPS mode (its settings or the stack's fips_mode output)."""
    if cloud_key != "aws":
        return False
    for v in ((cfg.get("vars") or {}).get("fips_mode"), (outputs or {}).get("fips_mode")):
        if v is True or str(v).strip().lower() in ("true", "1", "yes", "on"):
            return True
    return False


def cloud_cli_env(cloud_key: str, cfg: dict, outputs: dict | None = None) -> dict:
    """Environment for the cloud CLI calls made here (the kubeconfig fetch): in AWS FIPS mode every call goes to the FIPS
    endpoints, as the Terraform provider's do (use_fips_endpoint)."""
    e = deps.path_env()
    if _aws_fips(cloud_key, cfg, outputs):
        e["AWS_USE_FIPS_ENDPOINT"] = "true"
    return e


def _eks_token_users(data: dict, cluster: str) -> list[str]:
    """Users of a kubeconfig (kubectl config view -o json) that get their token from `aws eks get-token` for `cluster`."""
    out = []
    for u in data.get("users") or []:
        ex = (u.get("user") or {}).get("exec") or {}
        args = [str(a) for a in ex.get("args") or []]
        if os.path.basename(str(ex.get("command") or "")) not in ("aws", "aws.exe") or "get-token" not in args:
            continue
        named = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("--cluster-name", "--cluster-id")]
        if cluster in named and u.get("name"):
            out.append(u["name"])
    return out


def pin_fips_token_endpoint(kubeconfig: Path, cluster: str) -> bool:
    """AWS FIPS mode: the token command the kubeconfig runs (`aws eks get-token`, from kubectl, helm, k9s or the user's own
    tools, whatever their environment) must sign against the FIPS STS endpoint too - set AWS_USE_FIPS_ENDPOINT=true in
    that user's exec env. Only this cluster's users are touched; idempotent. False when it could not be done."""
    kubectl = deps.find("kubectl")
    if not kubectl or not cluster:
        return False
    env_ = dict(deps.path_env(), KUBECONFIG=str(kubeconfig))
    view = subprocess.run([kubectl, "config", "view", "--raw", "-o", "json"], env=env_, capture_output=True, text=True)
    try:
        users = _eks_token_users(json.loads(view.stdout or "{}"), cluster)
    except ValueError:
        return False
    ok = bool(users)
    for name in users:
        ok = subprocess.run([kubectl, "config", "set-credentials", name, "--exec-env=AWS_USE_FIPS_ENDPOINT=true"], env=env_,
                            capture_output=True, text=True).returncode == 0 and ok
    return ok


def kubeconfig_path(env) -> Path:
    return env.dir / "k8s" / "kubeconfig"


def home_kubeconfig() -> Path:
    """The kubeconfig file kubectl writes to: the first entry of $KUBECONFIG, else ~/.kube/config."""
    first = next((p for p in os.environ.get("KUBECONFIG", "").split(os.pathsep) if p.strip()), "")
    return Path(first).expanduser() if first else Path.home() / ".kube" / "config"


def _tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _gcloud_sdk_root(gcloud: str) -> Path | None:
    try:
        out = subprocess.run([gcloud, "info", "--format=value(installation.sdk_root)"], env=deps.path_env(),
                             capture_output=True, text=True, timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return Path(out) if out else None


def ensure_gke_auth_plugin(gcloud: str) -> None:
    """GKE kubeconfigs exec gke-gcloud-auth-plugin (kubectl 1.26+ has no built-in GCP auth), which gcloud does not ship
    by default. It must exist BEFORE get-credentials: gcloud writes its full SDK path (or the bare name when it is on
    PATH) into the kubeconfig and only prints a warning when it is missing."""
    if deps.find("gke-gcloud-auth-plugin"):
        return
    root = _gcloud_sdk_root(gcloud)
    if root and (root / "bin" / "gke-gcloud-auth-plugin").exists():
        return
    how = "gcloud components install gke-gcloud-auth-plugin"
    pkg = "sudo apt-get install google-cloud-cli-gke-gcloud-auth-plugin (dnf: google-cloud-cli-gke-gcloud-auth-plugin)"
    why = "to authenticate kubectl/helm to GKE"
    deps.refuse_install_in_agent_session(deps.GKE_AUTH_PLUGIN, why)
    if ui.interactive():
        if not ui.confirm(f"gke-gcloud-auth-plugin is needed {why}. Install it now ({how})?", default=True):
            raise ui.Abort(f"gke-gcloud-auth-plugin is required {why}: {how}   (gcloud from apt/dnf: {pkg})")
    elif not _install_approved():
        raise ui.Abort(f"gke-gcloud-auth-plugin is needed {why} but is not installed. Install it first: {how}   "
                       f"(gcloud from apt/dnf: {pkg}; {_UNATTENDED_INSTALL_HINT})", code=2)
    else:
        ui.info(f"gke-gcloud-auth-plugin is needed {why}; installing it ({how})")
    proc = subprocess.run([gcloud, "components", "install", "gke-gcloud-auth-plugin", "--quiet"], env=deps.path_env(),
                          capture_output=True, text=True)
    if proc.returncode != 0:
        tail = secrets.redact((proc.stderr or proc.stdout).strip())[-300:]
        raise ui.Abort(f"Could not install gke-gcloud-auth-plugin ({tail}). When gcloud comes from a system package the "
                       f"component manager is disabled: {pkg}")
    ui.ok("gke-gcloud-auth-plugin installed")


def _check_exec_plugins(kubeconfig: Path, stderr: str, search_path: str) -> None:
    """Refuse to hand out a kubeconfig whose exec credential plugin cannot run (gcloud exits 0 and only warns)."""
    if "gke-gcloud-auth-plugin" in (stderr or "") and "not found" in (stderr or "").lower():
        raise ui.Abort("The GKE kubeconfig needs gke-gcloud-auth-plugin, which gcloud could not find: "
                       "gcloud components install gke-gcloud-auth-plugin (or install google-cloud-cli-gke-gcloud-auth-plugin), then re-run.")
    kubectl = deps.find("kubectl")
    if not kubectl:
        return
    out = subprocess.run([kubectl, "config", "view", "--raw", "--minify", "-o", "jsonpath={.users[*].user.exec.command}"],
                         env=dict(deps.path_env(), KUBECONFIG=str(kubeconfig)), capture_output=True, text=True).stdout.split()
    for c in out:
        if "gke-gcloud-auth-plugin" not in c:
            continue
        if (os.path.isabs(c) and os.access(c, os.X_OK)) or shutil.which(c, path=search_path):
            continue
        raise ui.Abort(f"The GKE kubeconfig runs {c}, which is not installed here: gcloud components install gke-gcloud-auth-plugin "
                       "(or install google-cloud-cli-gke-gcloud-auth-plugin), then re-run.")


def _stamp_path(env) -> Path:
    return env.dir / "k8s" / "kubeconfig.src"


def _read_stamp(env) -> dict:
    try:
        return json.loads(_stamp_path(env).read_text())
    except (OSError, ValueError):
        return {}


def _write_stamp(env, data: dict) -> None:
    _stamp_path(env).write_text(json.dumps(data, sort_keys=True))


def ensure_kubeconfig(cloud, env, cfg: dict, outputs: dict, refresh: bool = False) -> Path:
    """A kubeconfig file for this environment only: produced by provisioning (vmware) or fetched once from the cloud CLI
    (managed clusters; exec credential plugins keep tokens fresh, so it is re-fetched only when the cluster/endpoint
    changes or refresh=True). Private endpoints are reached through an SSH tunnel via the bastion when not on the VPN."""
    kc = kubeconfig_path(env)
    if cloud.key == "vmware":
        if not kc.exists():
            raise ui.Abort(_no_local_kubeconfig(env.name, cfg, outputs))
        return kc
    if not outputs.get("kubernetes_cluster_name"):
        raise ui.Abort(f"Kubernetes is enabled for {env.id} but not created yet: cloudseed setup {cloud.key} --env {env.name}"
                       if _var_on(cfg, "enable_kubernetes") else
                       f"No cluster in {env.id}: cloudseed setup {cloud.key} --env {env.name} --var enable_kubernetes=true")
    # the command first: a setting it cannot do without stops here (_needs)
    source = {"cmd": kubeconfig_command(cloud.key, cfg, outputs), "endpoint": outputs.get("kubernetes_endpoint") or ""}
    kc.parent.mkdir(parents=True, exist_ok=True)   # only now: a refused request leaves no empty k8s/ directory behind
    stamp = _read_stamp(env)
    if refresh or not kc.exists() or stamp.get("source") != source:
        _fetch_kubeconfig(cloud, cfg, outputs, kc)
        stamp = {"source": source, "tunnel": False}
        _write_stamp(env, stamp)
    via = _ensure_reachable(cloud, env, cfg, outputs, kc)
    if via is None and stamp.get("tunnel"):
        # it was pointed at a tunnel that is no longer needed (VPN now up, endpoint public ...): fetch it afresh
        _fetch_kubeconfig(cloud, cfg, outputs, kc)
        stamp = {"source": source, "tunnel": False}
        _write_stamp(env, stamp)
        via = _ensure_reachable(cloud, env, cfg, outputs, kc)
    if isinstance(via, tuple) and not stamp.get("tunnel"):
        stamp["tunnel"] = True
        _write_stamp(env, stamp)
    if _aws_fips(cloud.key, cfg, outputs) and not stamp.get("fips_token"):
        # every fetch writes a fresh kubeconfig: pin its token command to the FIPS endpoint (again), once kubectl exists
        if pin_fips_token_endpoint(kc, outputs.get("kubernetes_cluster_name") or ""):
            stamp["fips_token"] = True
            _write_stamp(env, stamp)
    return kc


def _no_local_kubeconfig(env_name: str, cfg: dict, outputs: dict) -> str:
    """Why a vmware environment has no kubeconfig yet, and the one command that gets it there: provisioning (the node
    VMs exist), applying the saved setting (enabled but never created) or enabling Kubernetes at all."""
    if outputs.get("kubernetes_control_plane_ips"):   # the node VMs exist; Kubernetes was never installed on them
        return f"No kubeconfig yet. Run: cloudseed provision vmware --env {env_name} --host k8s"
    if _var_on(cfg, "enable_kubernetes"):
        return f"Kubernetes is enabled for vmware-{env_name} but not created yet: cloudseed setup vmware --env {env_name}"
    return f"No cluster yet: cloudseed setup vmware --env {env_name} --var enable_kubernetes=true"


def _fetch_kubeconfig(cloud, cfg: dict, outputs: dict, kc: Path) -> None:
    cmd = kubeconfig_command(cloud.key, cfg, outputs, kubeconfig=kc)
    cmd[0] = ensure_tool(cmd[0], "to fetch the cluster's kubeconfig", default=False)
    if cloud.key == "gcp":
        ensure_gke_auth_plugin(cmd[0])
    env_ = dict(cloud_cli_env(cloud.key, cfg, outputs), KUBECONFIG=str(kc))
    proc = subprocess.run(cmd, env=env_, capture_output=True, text=True)
    if proc.returncode != 0 or not kc.exists():
        raise ui.Abort("Could not fetch the kubeconfig: " + secrets.redact((proc.stderr or proc.stdout).strip())[-400:])
    os.chmod(kc, 0o600)
    if cloud.key == "gcp":
        _check_exec_plugins(kc, proc.stderr, deps.path_env()["PATH"])


def _endpoint(outputs: dict) -> tuple[str, int]:
    from urllib.parse import urlparse
    endpoint = outputs.get("kubernetes_endpoint") or ""
    u = urlparse(endpoint if "://" in endpoint else "https://" + endpoint)
    try:
        port = u.port or 443
    except ValueError:
        port = 443
    return (u.hostname or ""), port


def _tunnel_file(env) -> Path:
    """env: a paths.Env or its working directory."""
    return (env if isinstance(env, Path) else env.dir) / "k8s" / "tunnel.pid"


def _cmdline(pid: int) -> str:
    try:
        return subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True).stdout.strip()
    except OSError:
        return ""


def tunnel_info(env) -> dict | None:
    """{pid, port, host, rport} of this environment's live SSH tunnel, or None (a stale/foreign pidfile is ignored)."""
    try:
        raw = _tunnel_file(env).read_text().strip()
    except OSError:
        return None
    try:
        info = json.loads(raw)
        if not isinstance(info, dict):
            info = {"pid": int(info)}
    except ValueError:
        return None
    try:
        pid = int(info.get("pid"))
        os.kill(pid, 0)
    except (TypeError, ValueError, OSError):
        return None
    info["pid"] = pid
    cmdline = _cmdline(pid)
    if not info.get("port"):            # pidfile of an older cloudseed (just the pid): read the forward off its ssh
        m = re.search(r"-L 127\.0\.0\.1:(\d+):(\S+):(\d+)\b", cmdline) if "ssh" in cmdline else None
        if not m:
            return None
        info.update(port=int(m.group(1)), host=m.group(2), rport=int(m.group(3)))
    port, host, rport = info.get("port"), info.get("host"), info.get("rport", 443)
    if not port or not host or f"{port}:{host}:{rport}" not in cmdline:
        return None                     # PID reused by something else
    return info


def _free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    return preferred


def _ensure_reachable(cloud, env, cfg, outputs, kc: Path):
    """Private API endpoint and no VPN? Open (or reuse) an SSH tunnel through the bastion and point the kubeconfig at
    it. Returns (port, host) when the tunnel is used, None when the endpoint is reached directly, False when neither."""
    host, rport = _endpoint(outputs)
    if not host:
        return None
    live = tunnel_info(env)
    if live and (live.get("host") != host or int(live.get("rport", 443)) != rport):
        close_tunnel(env, quiet=True)   # the cluster was re-created with another endpoint
        live = None
    if live and _tcp_open("127.0.0.1", int(live["port"]), 1):
        _point_kubeconfig(kc, int(live["port"]), host)
        return int(live["port"]), host
    if _tcp_open(host, rport, 2):
        return None
    bastion = outputs.get("bastion_public_ip")
    if not bastion:
        ui.warn(f"The API endpoint {host} is private and no bastion is available" + (
            f". {_PRIVATELINK_WHY} Re-run cloudseed setup azure --env {env.name} (it publishes a name VPN clients can "
            f"resolve), then connect the VPN (cloudseed vpn connect azure --env {env.name})."
            if _azure_privatelink(cloud.key, outputs) else
            f"; connect the VPN first (cloudseed vpn connect {cloud.key} --env {env.name})."))
        return False
    close_tunnel(env, quiet=True)
    port = _free_port(16443 + (sum(map(ord, env.id)) % 1000))
    forward = f"127.0.0.1:{port}:{host}:{rport}"
    key = env.private_key_path(cfg)
    cmd = ["ssh", "-i", str(key), *env.ssh_options(), "-o", "ExitOnForwardFailure=yes", "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
           "-fN", "-L", forward, f"{cloud.ssh_user(cfg)}@{bastion}"]
    print(ui.dim("  $ " + " ".join(cmd)))
    # -f forks after authentication: the background ssh inherits our stderr, so capture it in a file, never a pipe
    with tempfile.TemporaryFile(mode="w+") as err:
        rc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err).returncode
        err.seek(0)
        detail = err.read().strip()
    if rc != 0:
        ui.warn(f"Could not open the SSH tunnel to the private API endpoint through the bastion {bastion}"
                + (f" ({secrets.redact(detail.splitlines()[-1])})" if detail else "")
                + f". If your public IP changed: cloudseed update-ip {cloud.key} --env {env.name}"
                + (f". {_PRIVATELINK_WHY} Re-run cloudseed setup azure --env {env.name} to publish a name VPN clients can resolve."
                   if _azure_privatelink(cloud.key, outputs) else
                   f"; or connect the VPN (cloudseed vpn connect {cloud.key} --env {env.name})."))
        return False
    out = subprocess.run(["pgrep", "-f", forward], capture_output=True, text=True).stdout.split()
    if out:
        _tunnel_file(env).write_text(json.dumps({"pid": int(out[0]), "port": port, "host": host, "rport": rport}))
    ui.ok(f"SSH tunnel to the private API endpoint via the bastion (127.0.0.1:{port}); close it with cs k8s untunnel")
    _point_kubeconfig(kc, port, host)
    return port, host


def _point_kubeconfig(kc: Path, port: int, host: str, context_cluster: str | None = None) -> bool:
    """Point the kubeconfig's cluster (the current context's, or the named one) at the local tunnel end, keeping TLS
    verification against the real endpoint name."""
    kubectl = deps.find("kubectl")
    if not kubectl:
        return False
    env_ = dict(deps.path_env(), KUBECONFIG=str(kc))
    cur = context_cluster or subprocess.run([kubectl, "config", "view", "--minify", "-o", "jsonpath={.contexts[0].context.cluster}"],
                                            env=env_, capture_output=True, text=True).stdout.strip()
    if not cur:
        return False
    return subprocess.run([kubectl, "config", "set-cluster", cur, f"--server=https://127.0.0.1:{port}", f"--tls-server-name={host}"],
                          env=env_, capture_output=True).returncode == 0


def close_tunnel(env, quiet: bool = False) -> None:
    pidfile = _tunnel_file(env)
    info = tunnel_info(env)
    if info:
        try:
            os.kill(int(info["pid"]), 15)
        except OSError:
            pass
    try:
        pidfile.unlink()
    except OSError:
        pass
    if not quiet:
        (ui.ok if info else ui.info)("Tunnel closed." if info else "No tunnel running.")


def _rename_kubeconfig(data: dict, name: str) -> dict:
    """Give every cluster/user/context of a fetched kubeconfig one unique name (the env id), so merging never overwrites
    the user's own entries ('default' from k3s/RKE2, 'kubernetes'/'kubernetes-admin' from kubeadm)."""
    def new(kind: str, i: int) -> str:
        return name if i == 0 else f"{name}-{kind}{i}"
    cmap = {c.get("name"): new("c", i) for i, c in enumerate(data.get("clusters") or [])}
    umap = {u.get("name"): new("u", i) for i, u in enumerate(data.get("users") or [])}
    xmap = {x.get("name"): new("x", i) for i, x in enumerate(data.get("contexts") or [])}
    for c in data.get("clusters") or []:
        c["name"] = cmap[c.get("name")]
    for u in data.get("users") or []:
        u["name"] = umap[u.get("name")]
    for x in data.get("contexts") or []:
        x["name"] = xmap[x.get("name")]
        ctx = x.setdefault("context", {})
        if ctx.get("cluster") in cmap:
            ctx["cluster"] = cmap[ctx["cluster"]]
        if ctx.get("user") in umap:
            ctx["user"] = umap[ctx["user"]]
    data["current-context"] = xmap.get(data.get("current-context"), name)
    return data


def _write_0600(path: Path, text: str) -> None:
    """Atomic 0600 write; a symlinked kubeconfig (dotfiles) is written through, never replaced by a plain file."""
    path = Path(os.path.realpath(path))
    tmp = path.with_name(path.name + ".cloudseed-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def kubeconfig_local(cfg: dict, outputs: dict) -> int:
    """Local clusters: merge the fetched kubeconfig into the user's kubeconfig (renamed to vmware-<env> so nothing of
    theirs is overwritten) and make it the current context; without kubectl, print how to use the file. Only cloudseed's
    own entries are made self-contained (flattened): the user's entries keep their file references (certificates and
    keys another tool rotates) exactly as written, and one of them naming a file that is gone blocks nothing."""
    kc = (_env_dir("vmware", cfg) or Path(".")) / "k8s" / "kubeconfig"   # what kubeconfig_path(env) names
    if not kc.exists():
        raise ui.Abort(_no_local_kubeconfig(cfg["env"], cfg, outputs))
    kubectl = deps.find("kubectl")
    if not kubectl:
        ui.warn("kubectl is not installed (cloudseed install kubectl).")
        ui.info(f"Use it with:  export KUBECONFIG={kc}")
        return 0
    name = f"vmware-{cfg['env']}"
    view = subprocess.run([kubectl, "config", "view", "--flatten", "-o", "json"], capture_output=True, text=True,
                          env=dict(deps.path_env(), KUBECONFIG=str(kc)))
    try:
        data = _rename_kubeconfig(json.loads(view.stdout), name)
    except ValueError:
        raise ui.Abort(f"Could not read {kc}: " + secrets.redact(view.stderr.strip())[-300:])
    target = home_kubeconfig()
    target.parent.mkdir(parents=True, exist_ok=True)
    renamed = kc.parent / "kubeconfig.merge"
    _write_0600(renamed, json.dumps(data))
    try:
        # --raw, never --flatten: the merge must not read (or inline) the files the user's own entries point at
        merged = subprocess.run([kubectl, "config", "view", "--raw"], capture_output=True, text=True,
                                env=dict(deps.path_env(), KUBECONFIG=f"{renamed}{os.pathsep}{target}" if target.exists() else str(renamed)))
    finally:
        renamed.unlink(missing_ok=True)
    if merged.returncode != 0 or not merged.stdout.strip():
        raise ui.Abort(f"Could not merge into {target}: " + secrets.redact(merged.stderr.strip())[-300:])
    _write_0600(target, merged.stdout)
    rc = subprocess.run([kubectl, "config", "use-context", name], capture_output=True, text=True,
                        env=dict(deps.path_env(), KUBECONFIG=str(target))).returncode
    if rc != 0:
        ui.warn(f"Merged into {target}, but could not switch to context {name}: kubectl config use-context {name}")
        return 1
    ui.ok(f"Merged into {target} as context {name} (current). Try: kubectl get nodes")
    return 0


def kubeconfig(cloud_key: str, cfg: dict, outputs: dict) -> int:
    """Merge the cluster into the user's kubeconfig ($KUBECONFIG's first file or ~/.kube/config). A private endpoint that
    is only reachable through the bastion tunnel (opened by ensure_kubeconfig) is pointed at the tunnel."""
    if cloud_key == "vmware":
        return kubeconfig_local(cfg, outputs)
    target = home_kubeconfig()
    target.parent.mkdir(parents=True, exist_ok=True)
    cmd = kubeconfig_command(cloud_key, cfg, outputs, kubeconfig=target)
    binary = deps.find(cmd[0])
    if not binary:
        raise ui.Abort(f"{cmd[0]} CLI is required for kubeconfig: cloudseed install {cmd[0]}")
    cmd[0] = binary
    if cloud_key == "gcp":
        ensure_gke_auth_plugin(binary)
    print(ui.dim("$ " + " ".join(cmd)))
    proc = subprocess.run(cmd, env=dict(cloud_cli_env(cloud_key, cfg, outputs), KUBECONFIG=str(target)), capture_output=True, text=True)
    for stream in (proc.stdout, proc.stderr):
        if stream.strip():
            print(secrets.redact(stream.rstrip()))
    if proc.returncode != 0:
        return proc.returncode
    if cloud_key == "gcp":
        _check_exec_plugins(target, proc.stderr, os.environ.get("PATH", ""))
    if _aws_fips(cloud_key, cfg, outputs) and not pin_fips_token_endpoint(target, outputs.get("kubernetes_cluster_name") or ""):
        ui.warn(f"FIPS mode: could not set AWS_USE_FIPS_ENDPOINT=true for this cluster's token command in {target} "
                "(needs kubectl); tokens are signed by the standard STS endpoint unless you export AWS_USE_FIPS_ENDPOINT=true.")
    ui.ok(f"kubeconfig updated: {target}")
    if _var_on(cfg, "kubernetes_public_endpoint"):
        return 0
    env_dir = _env_dir(cloud_key, cfg)
    env_name = cfg.get("env", "<env>")
    live = tunnel_info(env_dir) if env_dir else None
    host, rport = _endpoint(outputs)
    privatelink = _azure_privatelink(cloud_key, outputs)
    if live and host and live.get("host") == host:
        if _point_kubeconfig(target, int(live["port"]), host):
            ui.info(f"The API endpoint is private: this context goes through the bastion tunnel on 127.0.0.1:{live['port']}. "
                    "It works while the tunnel is open: reopen it with `cs k8s tunnel`, close it with `cs k8s untunnel`; "
                    + (f"after `cloudseed setup azure --env {env_name}` (it publishes a name VPN clients can resolve) and on "
                       "the VPN, re-run `cs k8s kubeconfig` to use the endpoint directly." if privatelink else
                       "on the VPN, re-run `cs k8s kubeconfig` to use the endpoint directly."))
    elif host and not _tcp_open(host, rport, 2):
        kc_hint = f"export KUBECONFIG={env_dir / 'k8s' / 'kubeconfig'} after `cs k8s tunnel`" if env_dir else "`cs k8s tunnel`"
        if privatelink:
            ui.info(f"The API endpoint {host} is private and not reachable from here. {_PRIVATELINK_WHY} "
                    f"Re-run cloudseed setup azure --env {env_name} (it publishes a name VPN clients can resolve), then "
                    f"`cs k8s kubeconfig` again; meanwhile use `cs kubectl ...` / `cs k8s tunnel` (they open a tunnel "
                    f"through the bastion), or {kc_hint}.")
        else:
            ui.info(f"The API endpoint {host} is private and not reachable from here: connect the VPN (cloudseed vpn connect {cloud_key} --env {env_name}), "
                    f"or use `cs kubectl ...` / `cs k8s tunnel` (they open a tunnel through the bastion), "
                    f"or {kc_hint}.")
    return 0


# ---------------- VPN ----------------

_CLIENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def check_client_name(name) -> str:
    """VPN client names become certificate names, file names and part of a remote command: letters, digits, '.', '_',
    '-' only (1-64), starting with a letter or digit; 'server' is the server's own certificate."""
    if not isinstance(name, str) or not _CLIENT_NAME.fullmatch(name) or name.lower() == "server":
        raise ui.Abort(f"Invalid VPN client name {name!r}: use 1-64 letters, digits, '.', '_' or '-', starting with a letter "
                       "or digit ('server' is reserved).")
    return name


def _default_client_name() -> str:
    raw = os.environ.get("USER") or "me"
    cand = re.sub(r"[^A-Za-z0-9._-]", "-", raw).lstrip("._-")[:64]
    return cand if cand and _CLIENT_NAME.fullmatch(cand) and cand.lower() != "server" else "me"


def vpn_dir(env: paths.Env) -> Path:
    d = env.dir / "vpn"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


# the same reason `cloudseed setup vmware --var enable_vpn=true` and `cloudseed vpn provision vmware` give
VPN_LOCAL_REASON = ("the private network of a local VMware environment is reachable from this machine directly, "
                    "so there is no VPN host to create")


def _is_local(cloud=None, env=None, cfg: dict | None = None) -> bool:
    """A target on this machine (vmware), from the cloud object when there is one, else from the environment's cloud
    key looked up in the cloud registry (its own `local` flag, so a new local target needs no list here)."""
    local = getattr(cloud, "local", None)
    if isinstance(local, bool):
        return local
    for key in (getattr(cloud, "key", None), (cfg or {}).get("cloud"), getattr(env, "cloud", None)):
        if isinstance(key, str) and key:
            from . import clouds    # local import: the cloud adapters are only needed on this fallback path
            return bool(getattr(clouds.CLOUDS.get(key), "local", False))
    return False


def vpn_not_applicable(cloud_key: str, env_name: str) -> str:
    """The answer to every VPN request on a local target: there is nothing to enable, the VMs are reached directly."""
    return (f"The VPN does not apply to {cloud_key}: {VPN_LOCAL_REASON}. "
            f"Reach its VMs with: cloudseed ssh {cloud_key} --env {env_name}")


def vpn_host(cloud, env: paths.Env, cfg: dict, outputs: dict) -> prov.Host:
    if _is_local(cloud, env, cfg):
        raise ui.Abort(vpn_not_applicable(cloud.key, env.name))
    ip = outputs.get("vpn_public_ip")
    if not ip:
        raise ui.Abort(f"The VPN is enabled for {env.id} but not created yet: cloudseed setup {cloud.key} --env {env.name}"
                       if _var_on(cfg, "enable_vpn") else "This environment has no VPN host. Enable one with: "
                       f"cloudseed setup {cloud.key} --env {env.name} --var enable_vpn=true")
    return prov.Host(ip, cloud.ssh_user(cfg), env.private_key_path(cfg), "vpn", env=env)


def _vpn_type(cfg: dict, outputs: dict) -> str:
    return outputs.get("vpn_type") or (cfg.get("vars") or {}).get("vpn_type") or "openvpn"


def add_user(cloud, env, cfg, outputs, name: str) -> Path:
    check_client_name(name)
    if not _is_local(cloud, env, cfg) and _vpn_type(cfg, outputs) != "openvpn":
        raise ui.Abort("Client profiles are an OpenVPN feature; with Tailscale, add devices in your tailnet instead.")
    host = vpn_host(cloud, env, cfg, outputs)
    proc = subprocess.run(host.ssh("sudo /usr/local/sbin/cloudseed-vpn-client add " + shlex.quote(name)), capture_output=True, text=True)
    if proc.returncode != 0 or "<ca>" not in proc.stdout:
        raise ui.Abort(f"Could not create the profile: {secrets.redact(proc.stderr or proc.stdout)[-600:]}")
    target = vpn_dir(env) / f"{name}.ovpn"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(proc.stdout)
    audit.note(env, "vpn-add-user", {"user": name, "profile": str(target)})
    return target


def revoke_user(cloud, env, cfg, outputs, name: str) -> None:
    check_client_name(name)
    if not _is_local(cloud, env, cfg) and _vpn_type(cfg, outputs) != "openvpn":
        raise ui.Abort("Client certificates are an OpenVPN feature; with Tailscale, remove the device from your tailnet "
                       "instead (admin console > Machines, or `tailscale logout` on that device).")
    host = vpn_host(cloud, env, cfg, outputs)
    rc = host.run("sudo /usr/local/sbin/cloudseed-vpn-client revoke " + shlex.quote(name))
    if rc != 0:   # the host's own output (streamed above) says why
        raise ui.Abort(f"Could not revoke {name} on the VPN host {host.ip} (exit {rc})" + (
            f". SSH to it failed - if your public IP changed: cloudseed update-ip {cloud.key} --env {env.name}" if rc == 255 else "."))
    (env.dir / "vpn" / f"{name}.ovpn").unlink(missing_ok=True)
    audit.note(env, "vpn-revoke-user", {"user": name})


def list_users(cloud, env, cfg, outputs) -> list[str]:
    """Client certificates issued on the OpenVPN host. Raises when the host could not be asked: an empty answer must mean
    'none yet', never 'SSH failed'."""
    if not _is_local(cloud, env, cfg) and _vpn_type(cfg, outputs) != "openvpn":
        raise ui.Abort("Client certificates are an OpenVPN feature; with Tailscale, the devices are in your tailnet (tailscale status).")
    host = vpn_host(cloud, env, cfg, outputs)
    proc = subprocess.run(host.ssh("sudo /usr/local/sbin/cloudseed-vpn-client list"), capture_output=True, text=True)
    if proc.returncode != 0:
        detail = secrets.redact((proc.stderr or proc.stdout or "").strip())[-300:]
        hint = (f". SSH to the VPN host {host.ip} failed - if your public IP changed: cloudseed update-ip {cloud.key} --env {env.name}"
                if proc.returncode == 255 else "")
        raise ui.Abort(f"Could not list the VPN clients (exit {proc.returncode}{': ' + detail if detail else ''}){hint}")
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


# ---------------- certificate expiry (OpenVPN) ----------------

RENEW_DAYS = 30        # the window in which the openvpn role / `cloudseed-vpn-client add` renew a certificate
SERVER_CERT = "server"  # the server's own certificate among the issued ones


def _parse_cert_date(text: str):
    """openssl's notAfter as an aware UTC datetime: ISO 8601 ('2028-12-27 12:00:00Z', -dateopt iso_8601) or openssl's
    default ('Dec 27 12:00:00 2028 GMT'); None when it is neither."""
    from datetime import datetime, timezone
    s = " ".join(str(text or "").split())
    for fmt in ("%Y-%m-%d %H:%M:%SZ", "%Y-%m-%dT%H:%M:%SZ", "%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def cert_expiry(cloud, env, cfg, outputs, connect_timeout: int | None = None) -> dict | None:
    """{certificate name: expiry (aware datetime; None when the date could not be read)} for every certificate the
    OpenVPN host issued, the server's ('server') included, in one SSH call. None when the host predates this (provisioned
    by an older cloudseed: its script has no `certs` action). Raises ui.Abort when the host could not be asked."""
    if not _is_local(cloud, env, cfg) and _vpn_type(cfg, outputs) != "openvpn":
        raise ui.Abort("Certificates are an OpenVPN feature; with Tailscale, the devices are in your tailnet (tailscale status).")
    host = vpn_host(cloud, env, cfg, outputs)
    cmd = host.ssh("sudo /usr/local/sbin/cloudseed-vpn-client certs")
    if connect_timeout:                 # ssh takes the first value of an option: this one wins over Host.ssh's default
        cmd[1:1] = ["-o", f"ConnectTimeout={int(connect_timeout)}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=90)
    except subprocess.TimeoutExpired:
        raise ui.Abort(f"The VPN host {host.ip} did not answer within 90 s") from None
    except OSError as e:
        raise ui.Abort(f"Could not run ssh: {e.strerror or e}") from None
    if proc.returncode == 2 and "usage" in (proc.stderr or "").lower():
        return None                     # an older host: `certs` is unknown there
    if proc.returncode != 0:
        detail = secrets.redact((proc.stderr or proc.stdout or "").strip())[-300:]
        hint = (f". SSH to the VPN host {host.ip} failed - if your public IP changed: cloudseed update-ip {cloud.key} --env {env.name}"
                if proc.returncode == 255 else "")
        raise ui.Abort(f"Could not read the VPN certificates (exit {proc.returncode}{': ' + detail if detail else ''}){hint}")
    out: dict = {}
    for line in proc.stdout.splitlines():
        name, _, when = line.partition("\t")
        if name.strip():
            out[name.strip()] = _parse_cert_date(when)
    return out


def expiry_text(when, now=None, compact: bool = False) -> tuple[str, str]:
    """(text, level) for a certificate's expiry: level 'ok', 'soon' (within RENEW_DAYS), 'expired' or 'unknown'.
    compact: the short form for a list ('until 2028-12-27', 'expires in 12 days', 'expired 2026-01-01')."""
    from datetime import datetime, timezone
    if when is None:
        return "expiry unknown", "unknown"
    now = now or datetime.now(timezone.utc)
    date = when.strftime("%Y-%m-%d")
    left = (when - now).total_seconds()
    if left <= 0:
        return f"expired {date}", "expired"
    days = int(round(left / 86400))    # 8 days 23 hours reads as 'in 9 days'
    span = "in less than a day" if days == 0 else f"in {days} day{'' if days == 1 else 's'}"
    level = "soon" if left < RENEW_DAYS * 86400 else "ok"
    if compact:
        return (f"until {date}" if level == "ok" else f"expires {span}"), level
    return f"expires {date} ({span})", level


def _styled_expiry(when, now=None, compact: bool = False) -> str:
    text, level = expiry_text(when, now, compact)
    return {"ok": ui.dim(text), "soon": ui.style(text, "seed", "bold"), "expired": ui.style(text, "rose", "bold")}.get(level, ui.dim(text))


def _renew_server_hint(cloud_key: str, env_name: str) -> str:
    return f"cloudseed vpn provision {cloud_key} --env {env_name}"


def _renew_client_hint(cloud_key: str, env_name: str, user: str) -> str:
    return f"cloudseed vpn add-user {cloud_key} --env {env_name} {user}"


def users_report(cloud, env, cfg, outputs) -> int:
    """`cs vpn users`: the client certificates issued on the OpenVPN host, each with its expiry (a host provisioned by an
    older cloudseed cannot tell: listed without) and whether its profile is on this machine. A certificate that has
    expired or expires within RENEW_DAYS days, the server's included, is flagged with the command that renews it."""
    certs = cert_expiry(cloud, env, cfg, outputs)
    if certs is None:
        names, dates = list_users(cloud, env, cfg, outputs), {}
    else:
        names, dates = [n for n in certs if n != SERVER_CERT], certs
    local = {p.stem for p in local_profiles(env)}
    width = max((len(n) for n in names), default=0)
    renew = []
    for u in names:
        extra = []
        if certs is not None:
            extra.append(_styled_expiry(dates.get(u)))
            if expiry_text(dates.get(u))[1] in ("soon", "expired"):
                renew.append(u)
        if u in local:
            extra.append(ui.dim("profile on this machine"))
        print(f"  {u.ljust(width)}  {'  ·  '.join(extra)}".rstrip())
    if not names:
        ui.info(f"No client certificates yet: cloudseed vpn add-user {cloud.key} --env {env.name} <name>")
    for u in renew:
        ui.warn(f"The certificate of {u} {expiry_text(dates.get(u))[0]}: issue a new profile with "
                f"{_renew_client_hint(cloud.key, env.name, u)} (then import it again, or reconnect)")
    if certs is None:
        ui.info(f"Expiry dates need a newer VPN host script: {_renew_server_hint(cloud.key, env.name)}")
    elif SERVER_CERT in certs and expiry_text(certs[SERVER_CERT])[1] in ("soon", "expired"):
        ui.warn(f"The VPN server's certificate {expiry_text(certs[SERVER_CERT])[0]}: renew it with "
                f"{_renew_server_hint(cloud.key, env.name)}")
    return 0


def local_profiles(env) -> list[Path]:
    d = env.dir / "vpn"                 # read-only: looking creates no directory
    return sorted(d.glob("*.ovpn")) if d.is_dir() else []


def _pidfile(env) -> Path:
    """The OpenVPN client's pidfile, for writing (its directory is created)."""
    return vpn_dir(env) / "openvpn.pid"


def _pidfile_path(env) -> Path:
    """The same path for reading: a status or disconnect creates no directory."""
    return env.dir / "vpn" / "openvpn.pid"


def _running(env) -> int | None:
    """PID of this environment's OpenVPN client, or None. The daemon runs as root (started through sudo), so signalling
    it as the user fails with EPERM although it is alive; and a stale pidfile may name a PID that now belongs to another
    process - so the PID must also be an openvpn started with this pidfile."""
    pf = _pidfile_path(env)
    try:
        pid = int(pf.read_text().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass                            # alive, owned by root
    except OSError:
        return None
    cmdline = _cmdline(pid)
    if "openvpn" not in cmdline or str(pf) not in cmdline:
        return None
    return pid


def _has_tty() -> bool:
    """A controlling terminal sudo can ask for the password on (a console job, a scheduler or an agent's subprocess
    has none)."""
    try:
        fd = os.open("/dev/tty", os.O_RDWR | getattr(os, "O_NOCTTY", 0))
    except OSError:
        return False
    os.close(fd)
    return True


_SUDO_CONF = "/etc/sudo.conf"


def _askpass() -> str:
    """The askpass helper `sudo -A` would run to ask for the password without a terminal (a GUI dialog, a password
    manager): $SUDO_ASKPASS when it is set (and not empty), else a `Path askpass` line of sudo.conf, as sudo picks it.
    '' when there is none, or when it is not an executable file (sudo -A would only fail on it)."""
    helper = os.environ.get("SUDO_ASKPASS") or ""
    if not helper:
        try:
            text = Path(_SUDO_CONF).read_text(errors="replace")
        except OSError:
            text = ""
        for line in text.splitlines():
            words = line.split("#", 1)[0].split(None, 2)
            if len(words) == 3 and words[0] == "Path" and words[1] == "askpass":
                helper = words[2].strip()
    return helper if helper and os.path.isfile(helper) and os.access(helper, os.X_OK) else ""


def _sudo() -> list[str]:
    """The prefix for a command that needs root: nothing as root; plain `sudo` on a terminal (it asks there). Without
    a terminal, `sudo -A` when an askpass helper is set up (SUDO_ASKPASS or sudo.conf), which asks for the password
    its own way; otherwise `sudo -n`, so sudo fails at once instead of waiting for a password nobody can type (the
    refusal is then explained, see _sudo_refusal). A passwordless (NOPASSWD) rule works with all three."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    if _has_tty():
        return ["sudo"]
    return ["sudo", "-A"] if _askpass() else ["sudo", "-n"]


# what sudo says when it will not run the command (as opposed to the command itself failing); with -A also when the
# askpass helper gave no password or there is none (sudo's own words: OpenVPN has an --askpass option of its own)
_SUDO_NEEDS_PASSWORD = ("a password is required", "a terminal is required", "no tty present", "must have a tty",
                        "incorrect password attempt", "no password was provided", "no askpass program")
_SUDO_NOT_ALLOWED = ("not in the sudoers", "is not allowed to", "may not run sudo")


def _privileged(cmd: list[str]) -> tuple[int, str]:
    """Run a command with _sudo()'s prefix: (exit code, what it wrote to stderr). On a terminal its messages (and
    sudo's password prompt, "Sorry, try again") go straight there and are not returned; without one (`sudo -n`,
    `sudo -A`) they are captured so that a refusal by sudo can be told apart from the command failing (the caller
    shows them: _show_stderr)."""
    if cmd[:2] not in (["sudo", "-n"], ["sudo", "-A"]):
        try:
            return subprocess.call(cmd), ""
        except OSError as e:            # no sudo at all
            return 127, f"{cmd[0]}: {e.strerror or e}"
    with tempfile.TemporaryFile(mode="w+") as fh:   # a file, never a pipe: a daemon (openvpn --daemon) may inherit it
        try:
            rc = subprocess.call(cmd, stdin=subprocess.DEVNULL, stderr=fh)
        except OSError as e:
            return 127, f"{cmd[0]}: {e.strerror or e}"
        fh.seek(0)
        err = fh.read()
    return rc, err


def _show_stderr(err: str) -> None:
    """What a privileged command wrote to its captured stderr, for the user (a sudo refusal is not shown: the stop
    message quotes it)."""
    if err.strip() and not _sudo_refusal(err):
        sys.stderr.write(secrets.redact(err if err.endswith("\n") else err + "\n"))


def _sudo_refusal(err: str) -> tuple[str, str] | None:
    """('password' | 'denied', sudo's own line) when sudo refused to run the command, else None."""
    for line in (err or "").splitlines():
        low = line.lower()
        if any(p in low for p in _SUDO_NEEDS_PASSWORD):
            return "password", line.strip()
        if any(p in low for p in _SUDO_NOT_ALLOWED):
            return "denied", line.strip()
    return None


def _sudo_abort(action: str, env, what: str, refusal: tuple[str, str], askpass: str = "", kept=None,
                user: str | None = None) -> ui.Abort:
    """The stop message for a command sudo refused to run. askpass: the helper `sudo -A` used ('' for `sudo -n`).
    kept: a client profile this connect created before sudo refused; it stays, and the re-run connects with it.
    user: connect's --user, repeated in the command to re-run (without it the re-run would take the first profile)."""
    kind, line = refusal
    where = f"cs vpn {action} {env.cloud} --env {env.name}" + (f" --user {user}" if user else "")
    note = (f" The client profile {kept.name} created for this is kept: the re-run connects with it (no second "
            f"certificate)." if kept is not None else "")
    if kind == "password":
        said = line if line.startswith("sudo: ") else f"sudo: {line}"
        how = (f": there is no terminal here, and the askpass helper ({askpass}) did not supply it" if askpass else
               ", and there is no terminal here to type it into")
        return ui.Abort(f"vpn {action} needs your sudo password ({what} runs as root){how} ({said}). "
                        f"Run it in a terminal: {where}   (or allow passwordless sudo for {what}).{note}")
    return ui.Abort(f"sudo does not let this user run {what}, which vpn {action} needs as root ({line}). Ask an "
                    f"administrator for a sudo rule for {what}, or run {where} as a user who has one.{note}")


def ensure_openvpn_client() -> str:
    """The OpenVPN client binary. A missing one is installed only with consent (asked on a terminal; with -y only when
    the run was approved up front: CLOUDSEED_AUTO_INSTALL=1), never for an agent session; otherwise stop with how to
    install it (exit code 2 when there was nobody to ask)."""
    binary = deps.find("openvpn")
    if binary:
        return binary
    manual = ("Install OpenVPN (cloudseed install openvpn · macOS: brew install openvpn · Debian/Ubuntu: sudo apt install openvpn · "
              "Windows: https://openvpn.net/community-downloads/) or import the .ovpn file into any OpenVPN client.")
    deps.refuse_install_in_agent_session("openvpn", "(the OpenVPN client for cloudseed vpn connect)")
    ui.warn("The OpenVPN client is not installed.")
    if ui.interactive():
        if not ui.confirm("Install it now?", default=True):
            raise ui.Abort(manual)
    elif not _install_approved():
        raise ui.Abort(f"{manual}   ({_UNATTENDED_INSTALL_HINT})", code=2)
    deps.install("openvpn")
    binary = deps.find("openvpn")
    if not binary:
        raise ui.Abort(f"Could not install the OpenVPN client. {manual}")
    return binary


# how long a `tailscale up` without a terminal waits for Tailscale to come up before it gives up
TAILSCALE_UP_TIMEOUT = 60


def _tailscale_state(ts: str) -> str:
    """This machine's Tailscale backend state (Running, Stopped, NeedsLogin, NeedsMachineAuth ...); "" when unknown."""
    try:
        proc = subprocess.run([ts, "status", "--json"], capture_output=True, text=True, timeout=15)
        data = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return str(data.get("BackendState") or "") if isinstance(data, dict) else ""


def _tailscale_up(env) -> int:
    """Join this machine to the tailnet and accept the subnet router's routes. Without a terminal it never waits for
    a browser login that nobody can do: a logged-out Tailscale is refused, and `tailscale up` gets a timeout."""
    ts = deps.find("tailscale")
    if not ts:
        raise ui.Abort("Install Tailscale on this machine (https://tailscale.com/download), log in, then re-run. "
                       "Approve the advertised route in the admin console once.")
    cmd = [ts, "up", "--accept-routes"]
    if not ui.interactive():
        state = _tailscale_state(ts)
        if state in ("NeedsLogin", "NeedsMachineAuth"):
            raise ui.Abort(f"Tailscale on this machine is not logged in ({state}), and there is no terminal to finish a "
                           f"browser login from: run `tailscale up --accept-routes` in a terminal once, then re-run "
                           f"`cloudseed vpn connect` for {env.id}.")
        cmd.append(f"--timeout={TAILSCALE_UP_TIMEOUT}s")
    print(ui.dim("$ " + " ".join(cmd)))
    if ui.interactive():
        return subprocess.call(cmd)
    try:
        return subprocess.call(cmd, stdin=subprocess.DEVNULL, timeout=TAILSCALE_UP_TIMEOUT + 30)
    except subprocess.TimeoutExpired:
        raise ui.Abort(f"`tailscale up` did not finish within {TAILSCALE_UP_TIMEOUT + 30} s; check Tailscale on this "
                       "machine (tailscale status) and re-run.") from None


def connect(cloud, env, cfg, outputs, user: str | None) -> int:
    if _is_local(cloud, env, cfg):
        raise ui.Abort(vpn_not_applicable(cloud.key, env.name))
    kind = _vpn_type(cfg, outputs)
    if kind == "tailscale":
        # like OpenVPN: nothing on this machine changes before it is known that the subnet router exists (a
        # `tailscale up` for an environment without one would still switch this machine's Tailscale on)
        vpn_host(cloud, env, cfg, outputs)
        return _tailscale_up(env)
    if user:
        check_client_name(user)
    pid = _running(env)
    master = outputs.get("kubernetes_master_cidr")
    if pid:
        ui.ok(f"OpenVPN already connected (pid {pid}).")
        if master:
            where = f"{cloud.key} --env {env.name}"
            ui.info(f"Routes are set when the tunnel starts: if the GKE API ({master}) does not answer, reconnect "
                    f"(cloudseed vpn disconnect {where}, then cloudseed vpn connect {where}); a VPN host set up by an older "
                    f"cloudseed first needs: cloudseed vpn provision {where}")
        return 0
    # nothing is announced or created before it is known that there is a VPN host to connect to and a client to
    # connect with: a missing host or client must not leave a fresh certificate on the server behind
    vpn_host(cloud, env, cfg, outputs)
    binary = ensure_openvpn_client()
    profiles = local_profiles(env)
    created = None                      # a profile made by this run: kept when sudo then refuses (the re-run uses it)
    if user:
        profile = vpn_dir(env) / f"{user}.ovpn"
        if not profile.exists():
            profile = created = add_user(cloud, env, cfg, outputs, user)
    elif profiles:
        profile = profiles[0]
    else:
        default_user = _default_client_name()
        ui.info(f"No client profile yet; creating one for '{default_user}'.")
        profile = created = add_user(cloud, env, cfg, outputs, default_user)
    log = vpn_dir(env) / "openvpn.log"
    # create the log as the user first: openvpn (root) then appends to a file the user can read; and only lines written
    # after this point count, so an old session's "Initialization Sequence Completed" is not mistaken for this one
    try:
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    except PermissionError:             # a root-owned log from an older run: the vpn dir is ours, so replace it
        log.unlink()
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    offset = log.stat().st_size
    _pidfile(env).unlink(missing_ok=True)
    sudo = _sudo()
    cmd = [*sudo, binary, "--config", str(profile), "--daemon", "cloudseed-vpn", "--writepid", str(_pidfile(env)),
           "--log-append", str(log)]
    if platform.system() == "Darwin":
        cmd += ["--dev", "utun"]
    print(ui.dim("$ " + " ".join(cmd)))
    askpass = _askpass() if sudo == ["sudo", "-A"] else ""
    if sudo == ["sudo"]:
        ui.info("OpenVPN needs administrator rights to create the tunnel interface (sudo prompt).")
    elif askpass:
        ui.info(f"OpenVPN needs administrator rights to create the tunnel interface: sudo asks for the password "
                f"through the askpass helper ({askpass}).")
    rc, err = _privileged(cmd)
    _show_stderr(err)
    if rc != 0:
        refusal = _sudo_refusal(err)
        if refusal:
            raise _sudo_abort("connect", env, "openvpn", refusal, askpass=askpass, kept=created, user=user)
        raise ui.Abort(f"OpenVPN failed to start (exit {rc}); see {log}")
    for _ in range(30):
        time.sleep(1)
        try:
            with open(log, "rb") as fh:
                fh.seek(offset)
                fresh = fh.read().decode("utf-8", "replace")
        except OSError:
            continue
        if "Initialization Sequence Completed" in fresh:
            gke = f" and the GKE API ({master})" if master else ""
            ui.ok(f"VPN connected using {profile.name}. Private network {cfg.get('network_cidr')}{gke} {'are' if master else 'is'} reachable.")
            return 0
        if "AUTH_FAILED" in fresh or "Exiting due to fatal error" in fresh:
            raise ui.Abort(f"OpenVPN could not connect; see {log}")
    ui.warn(f"OpenVPN started but did not report completion yet; check {log}")
    return 0


_STOP_WAIT = 10.0   # seconds OpenVPN gets to shut down after SIGTERM (it tells the server it is leaving first)


def disconnect(env) -> int:
    """Stop this environment's OpenVPN client (it runs as root: `sudo kill -TERM`) and wait until it is gone. The pidfile
    is only removed once the process has ended: a refused or failed kill, or a client that does not stop, raises
    ui.Abort and leaves both in place, so the VPN is never reported disconnected while it still runs."""
    pid = _running(env)
    if not pid:
        _pidfile_path(env).unlink(missing_ok=True)     # stale pidfile from a crash/reboot: start clean next time
        ui.info("VPN is not connected.")
        return 0
    cmd = [*_sudo(), "kill", "-TERM", str(pid)]
    rc, err = _privileged(cmd)
    if rc != 0:
        if not _running(env):          # it ended by itself in the meantime (kill: no such process)
            _pidfile_path(env).unlink(missing_ok=True)
            ui.info("VPN is not connected (OpenVPN had already stopped).")
            return 0
        _show_stderr(err)
        refusal = _sudo_refusal(err)
        if refusal:
            raise _sudo_abort("disconnect", env, "kill", refusal, askpass=_askpass() if cmd[:2] == ["sudo", "-A"] else "")
        raise ui.Abort(f"Could not stop OpenVPN (pid {pid}): `{' '.join(cmd[:-2])}` exited with {rc}. The VPN is still connected; "
                       f"stop it with: sudo kill -TERM {pid}   (then cs vpn disconnect {env.cloud} --env {env.name} tidies up)")
    deadline = time.monotonic() + _STOP_WAIT
    while _running(env):
        if time.monotonic() >= deadline:
            raise ui.Abort(f"OpenVPN (pid {pid}) is still running {int(_STOP_WAIT)} s after it was asked to stop. Force it: "
                           f"sudo kill -KILL {pid}   (then cs vpn disconnect {env.cloud} --env {env.name} tidies up)")
        time.sleep(0.2)
    _pidfile_path(env).unlink(missing_ok=True)
    ui.ok("VPN disconnected.")
    return 0


def _status_certs(cloud, env, cfg, outputs) -> tuple[dict | None, str]:
    """For `vpn status`: (the certificates' expiry, or None; '' or why they are unknown). Never raises: the rest of
    the panel is local and must show whatever the VPN host says (or not)."""
    if cloud is None:
        from . import clouds    # local import: the cloud adapters are only needed here
        cloud = clouds.CLOUDS.get(env.cloud)
    if cloud is None:
        return None, "unknown"
    if not env.private_key_path(cfg).exists():
        return None, "unknown - this environment's SSH key is not on this machine"
    try:
        certs = cert_expiry(cloud, env, cfg, outputs, connect_timeout=5)
    except (ui.Abort, OSError, ValueError, KeyError):
        return None, f"unknown - the VPN host did not answer (cs vpn users {env.cloud} --env {env.name} shows why)"
    if certs is None:
        return None, f"unknown - the VPN host's script predates expiry checks (update it: {_renew_server_hint(env.cloud, env.name)})"
    return certs, ""


def status(env, cfg, outputs, cloud=None, certs: bool = True) -> None:
    """`cs vpn status`: the VPN host, this machine's profiles and connection. With `certs` (the default) and an OpenVPN
    host, one SSH call adds the certificates' expiry: the server's, and each local profile's, flagged within RENEW_DAYS."""
    if _is_local(cloud, env, cfg):
        # nothing to enable: every hint of the cloud panel (enable_vpn, add-user) would lead to a refused command
        ui.panel(f"VPN · {env.id}", [("VPN", ui.dim(f"not applicable on {env.cloud}: {VPN_LOCAL_REASON}")),
                                     ("Reach the VMs", f"cs ssh {env.cloud} --env {env.name}")])
        return
    pid = _running(env)
    host = outputs.get("vpn_public_ip")
    kind = _vpn_type(cfg, outputs)
    issued, why = (None, "")
    if certs and host and kind == "openvpn":
        issued, why = _status_certs(cloud, env, cfg, outputs)
    renew = []

    def _profile(name: str) -> str:
        if issued is None:
            return name
        if name not in issued:          # revoked, or issued by an earlier VPN host (another CA): it cannot connect
            renew.append(name)
            return f"{name} {ui.style('(not issued by this VPN host)', 'rose')}"
        if expiry_text(issued[name])[1] in ("soon", "expired"):
            renew.append(name)
        return f"{name} {ui.dim('(')}{_styled_expiry(issued[name], compact=True)}{ui.dim(')')}"

    profiles = ", ".join(_profile(p.stem) for p in local_profiles(env))
    if profiles:
        prof_row = profiles
    elif kind != "openvpn":
        prof_row = ui.dim("none - Tailscale devices join your tailnet (tailscale status)")
    elif host:
        prof_row = ui.dim(f"none yet  (cs vpn add-user {env.cloud} --env {env.name} <name>)")
    else:
        prof_row = ui.dim("none")
    rows = [("Type", kind),
            ("Host", host or ui.dim(f"configured, not created yet - cs setup {env.cloud} --env {env.name}"
                                    if _var_on(cfg, "enable_vpn") else
                                    f"none - enable with: cs setup {env.cloud} --env {env.name} --var enable_vpn=true")),
            ("Port", outputs.get("vpn_port") or ui.dim("-"))]
    if issued is not None or why:
        server = issued.get(SERVER_CERT) if issued is not None else None
        if issued is None:
            rows.append(("Server cert", ui.dim(why)))
        elif SERVER_CERT not in issued:
            rows.append(("Server cert", ui.dim("unknown - not listed by the VPN host")))
        else:
            level = expiry_text(server)[1]
            rows.append(("Server cert", _styled_expiry(server) + (
                ui.dim(f"  - renew: {_renew_server_hint(env.cloud, env.name)}") if level in ("soon", "expired") else "")))
    rows += [("Local profiles", prof_row),
             ("Connected", ui.style(f"yes (pid {pid})", "leaf", "bold") if pid else ui.dim("no"))]
    ui.panel(f"VPN · {env.id}", rows)
    for name in renew:
        state = (expiry_text(issued[name])[0] if name in issued else
                 "was not issued by this VPN host (revoked, or the host was re-created)")
        ui.warn(f"The profile {name} {state}: get a new one with {_renew_client_hint(env.cloud, env.name, name)}")
