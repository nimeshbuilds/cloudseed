"""Bounded drift inspection and reviewed, version-pinned cluster upgrades.

Reports never contain Terraform values, Kubernetes Secret values or command output.
Saved plans are data, never executable commands. Apply reconstructs commands from
validated parameters and repeats live preflight before changing anything.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import deps, paths, services, ui

LIMIT = 4 * 1024 * 1024
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,126}\Z")
VERSION = re.compile(r"v?(1)\.(\d{1,2})(?:\.(\d{1,3}))?(?:(?:\+|-)rke2r\d+|-gke\.\d+)?\Z")


def bounded_run(argv, *, env=None, cwd=None, timeout=120, input=None):
    """Drain both pipes with a fixed combined cap; kill the process group on overflow.

    No shell. A timeout first sends SIGINT so Terraform can release its state lock.
    Raw output is consumed locally and never included in public failure reports.
    """
    try:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name != "nt")
    except OSError:
        return subprocess.CompletedProcess(argv, 127, "", "tool unavailable")
    chunks = [bytearray(), bytearray()]
    overflow = threading.Event()
    guard = threading.Lock()
    def read(pipe, index):
        try:
            while True:
                data = pipe.read(65536)
                if not data:
                    break
                with guard:
                    remaining = LIMIT - sum(map(len, chunks))
                    chunks[index].extend(data[:max(0, remaining)])
                    if len(data) > remaining:
                        overflow.set()
                if overflow.is_set():
                    break
        finally:
            pipe.close()
    threads = [threading.Thread(target=read, args=(p, i), daemon=True) for i, p in enumerate((child.stdout, child.stderr))]
    for t in threads:
        t.start()
    def stop(sig):
        try:
            os.killpg(child.pid, sig) if os.name != "nt" else child.terminate()
        except OSError:
            pass
    deadline = time.monotonic() + timeout
    rc = None
    try:
        if input is not None:
            try:
                child.stdin.write(input.encode() if isinstance(input, str) else input)
                child.stdin.close()
            except BrokenPipeError:
                pass
        while child.poll() is None:
            if overflow.is_set() or time.monotonic() >= deadline:
                rc = 125 if overflow.is_set() else 124
                stop(signal.SIGINT)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    stop(signal.SIGKILL)
                break
            time.sleep(.025)
        child.wait()
    except BaseException:
        stop(signal.SIGINT)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            stop(signal.SIGKILL)
            child.wait()
        raise
    finally:
        for t in threads:
            t.join(timeout=2)
    return subprocess.CompletedProcess(argv, rc if rc is not None else (125 if overflow.is_set() else child.returncode),
                                       chunks[0].decode("utf-8", "replace"), chunks[1].decode("utf-8", "replace"))


def _key(cloud):
    return cloud if isinstance(cloud, str) else cloud.key


def integer(params, key, default, low=1, high=7200):
    value = params.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ui.Abort(f"{key} must be an integer from {low} to {high}.", code=2)
    return value


def flag(params, key, default=False):
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise ui.Abort(f"{key} must be true or false.", code=2)
    return value


def safe_name(value, field):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ui.Abort(f"{field} needs a simple resource name.", code=2)
    return value


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError("missing, symlinked or oversized JSON")
    with path.open() as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("expected object")
    return data


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _config_hash(env, cfg):
    files = {}
    candidates = set()
    for pattern in ("*.tf", "*.tf.json", "*.tfvars", "*.tfvars.json", ".terraform.lock.hcl"):
        candidates.update(env.stack_dir.glob(pattern))
    for path in sorted(candidates):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
            raise ui.Abort("Upgrade planning requires regular, bounded Terraform configuration files.", code=2)
        files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return _hash({"saved": cfg, "terraform": files})


def _report(action, cloud, env):
    return {"schema_version": 1, "kind": action, "action": action, "cloud": _key(cloud), "env": env.id,
            "run": uuid.uuid4().hex, "generated_at": datetime.now(timezone.utc).isoformat(),
            "verdict": "INCOMPLETE", "checks": [], "coverage_limits": []}


def check(report, name, ok, detail):
    report["checks"].append({"id": name, "status": "PASS" if ok is True else "FAIL" if ok is False else "UNKNOWN", "detail": detail})


def finish(env, report):
    checks = report["checks"]
    if any(c["status"] == "FAIL" for c in checks):
        report["verdict"] = "FAIL"
    elif checks and all(c["status"] in ("PASS", "NOT_APPLICABLE") for c in checks):
        report["verdict"] = "PASS"
    else:
        report["verdict"] = "INCOMPLETE"
    report["status"] = report["verdict"]
    report["exit_code"] = {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3}[report["verdict"]]
    folder = env.dir / "operations"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if folder.is_symlink():
        raise ui.Abort("The operations report directory must not be a symlink.", code=2)
    path = folder / f"{report['action']}-{report['run']}.json"
    report["report"] = str(path)
    paths.atomic_write(path, json.dumps(report, indent=2) + "\n", 0o600)
    from .scan import md_cell
    lines = [f"# {report['action']} · {report['env']}", "", f"**{report['verdict']}**", "", "| Check | Result | Detail |", "|---|---|---|"]
    lines += [f"| {md_cell(c['id'])} | {c['status']} | {md_cell(c['detail'])} |" for c in checks]
    lines += ["", *report.get("coverage_limits", [])]
    paths.atomic_write(path.with_suffix(".md"), "\n".join(lines) + "\n", 0o600)
    return report


def process_env(cloud, env, cfg):
    e = deps.path_env()
    e["KUBECONFIG"] = str(services.kubeconfig_path(env))
    e.update({"TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "AWS_PAGER": "", "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"})
    profile = (cfg.get("vars") or {}).get("profile")
    if _key(cloud) == "aws" and profile:
        e["AWS_PROFILE"] = str(profile)
    return e


def command(tool, args, e, timeout=120, cwd=None, input=None):
    binary = deps.find(tool)
    if not binary:
        return subprocess.CompletedProcess([tool, *args], 127, "", "tool unavailable")
    return bounded_run([binary, *args], env=e, cwd=cwd, timeout=timeout, input=input)


def kube(args, e, timeout=120, input=None):
    # A missing environment kubeconfig must never fall back to the operator's default cluster.
    if not Path(e["KUBECONFIG"]).is_file():
        return subprocess.CompletedProcess(["kubectl", *args], 127, "", "environment kubeconfig unavailable")
    return command("kubectl", ["--request-timeout=60s", *args], e, timeout, input=input)


def parsed(proc):
    if proc.returncode:
        return None
    try:
        value = json.loads(proc.stdout)
        return value if isinstance(value, dict) else None
    except ValueError:
        return None


def _state(env, e):
    p = command("terraform", ["state", "pull"], e, cwd=env.stack_dir)
    state = parsed(p)
    return _hash(state) if isinstance(state, dict) and state.get("lineage") and isinstance(state.get("serial"), int) else None


def drift(cloud, env, cfg, params):
    report = _report("drift", cloud, env)
    e = process_env(cloud, env, cfg)
    timeout = integer(params, "timeout_s", 300)
    if not env.stack_dir.is_dir():
        check(report, "terraform", None, "No rendered stack. Run setup and initialize Terraform first.")
        return finish(env, report)
    # Both plans are read-only; normal -refresh=false isolates desired configuration changes.
    for mode, flags, field in (("drift", ["-refresh-only"], "resource_drift"), ("intent", ["-refresh=false"], "resource_changes")):
        with tempfile.TemporaryDirectory(prefix="cloudseed-drift-") as td:
            plan = str(Path(td) / "plan")
            p = command("terraform", ["plan", "-input=false", "-no-color", "-lock-timeout=30s", "-detailed-exitcode", *flags, f"-out={plan}"],
                        e, timeout, env.stack_dir)
            if p.returncode not in (0, 2):
                check(report, mode, None, f"Terraform {mode} plan unavailable (exit {p.returncode}); no state or infrastructure was applied.")
                continue
            data = parsed(command("terraform", ["show", "-json", plan], e, timeout, env.stack_dir))
            if not isinstance(data, dict):
                check(report, mode, None, "Terraform plan JSON was unavailable; no conclusion drawn.")
                continue
            changes = []
            for resource in data.get(field, []):
                actions = (resource.get("change") or {}).get("actions") or []
                if actions and actions != ["no-op"] and resource.get("mode", "managed") == "managed":
                    # Addresses may embed user-controlled for_each keys. Publish type/count/actions only.
                    changes.append({"type": str(resource.get("type", "resource"))[:100], "actions": [a for a in actions if a in ("create", "read", "update", "delete", "forget")]})
            report[mode] = {"count": len(changes), "changes": changes[:200], "truncated": len(changes) > 200}
            check(report, mode, not changes, f"{len(changes)} {'out-of-band drift' if mode == 'drift' else 'desired configuration change'} resource(s).")
    report["coverage_limits"] = ["Only managed resources in this Terraform state are covered. Values are deliberately omitted. No refresh-only apply is run.",
                                 "Intent uses recorded state without refresh; review both results before deciding how to reconcile."]
    return finish(env, report)


def _version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ui.Abort("target_version must be a pinned Kubernetes version (for example 1.36, 1.36.4 or v1.36.4+rke2r1).", code=2)
    m = VERSION.fullmatch(value)
    return (int(m[1]), int(m[2]), int(m[3] or 0))


def _version_order(value, server=False):
    # Provider security fixes can increment only the GKE/RKE2 build suffix.
    base = _version(re.sub(r"[-+].*$", "", value)) if server else _version(value)
    suffix = re.search(r"(?:-gke\.|[+-]rke2r)(\d+)$", value)
    return (*base, int(suffix[1]) if suffix else 0)


def _outputs(env):
    try:
        return read_json(env.dir / "outputs.json")
    except (OSError, ValueError):
        return {}


def provider_args(cloud, cfg, outputs):
    target = _key(cloud)
    name = safe_name(outputs.get("kubernetes_cluster_name"), "cached Kubernetes cluster name")
    values = cfg.get("vars") or {}
    if target == "aws":
        return "aws", ["eks"], ["--region", safe_name(cfg.get("region"), "region")], name
    if target == "gcp":
        return "gcloud", ["container", "clusters"], ["--project", safe_name(values.get("project_id"), "project_id"), "--location", safe_name(outputs.get("kubernetes_location"), "location"), "--format=json"], name
    return "az", ["aks"], ["--subscription", safe_name(values.get("subscription_id"), "subscription_id"), "--resource-group", safe_name(outputs.get("resource_group_name"), "resource_group"), "--output", "json"], name


def _endpoint(value):
    from urllib.parse import urlparse
    if not isinstance(value, str) or not value:
        return ""
    return (urlparse(value if "://" in value else "https://" + value).hostname or "").lower()


def _managed_identity(cloud, env, cfg, e, report):
    outputs = _outputs(env)
    tool, prefix, common, name = provider_args(cloud, cfg, outputs)
    action = ["describe-cluster", "--name", name] if _key(cloud) == "aws" else ["describe", name] if _key(cloud) == "gcp" else ["show", "--name", name]
    data = parsed(command(tool, [*prefix, *action, *common, *(["--output", "json"] if _key(cloud) == "aws" else [])], e))
    cluster = (data or {}).get("cluster", {}) if _key(cloud) == "aws" else data or {}
    endpoints = {_endpoint(cluster.get(k)) for k in ("endpoint", "fqdn", "privateFqdn")} - {""}
    saved_endpoint = _endpoint(outputs.get("kubernetes_endpoint"))
    local = parsed(kube(["config", "view", "--raw", "--minify", "-o", "json"], e)) or {}
    entries = local.get("clusters") or []
    connection = entries[0].get("cluster", {}) if entries else {}
    origin = _endpoint(connection.get("tls-server-name") or connection.get("server"))
    match = bool(saved_endpoint) and saved_endpoint in endpoints and origin == saved_endpoint
    ca_hash = None
    if _key(cloud) in ("aws", "gcp"):
        provider_ca = (cluster.get("certificateAuthority") or {}).get("data") if _key(cloud) == "aws" else (cluster.get("masterAuth") or {}).get("clusterCaCertificate")
        local_ca = connection.get("certificate-authority-data")
        try:
            server_bytes = base64.b64decode(provider_ca, validate=True)
            client_bytes = base64.b64decode(local_ca, validate=True)
            same_ca = bool(server_bytes) and server_bytes == client_bytes
            ca_hash = hashlib.sha256(server_bytes).hexdigest() if same_ca else None
        except (ValueError, TypeError, binascii.Error):
            same_ca = False
        match = match and same_ca
    report["provider_identity_hash"] = _hash({"id": cluster.get("arn") or cluster.get("id") or cluster.get("selfLink"), "endpoint": saved_endpoint, "name": name, "ca_hash": ca_hash}) if match else None
    check(report, "provider_identity", match if data is not None and entries else None,
          "Provider endpoint, saved endpoint and kubeconfig TLS identity must match; EKS/GKE also require identical certificate-authority data (private IPs can repeat across networks).")


def _preflight(cloud, env, cfg, params, report):
    e = process_env(cloud, env, cfg)
    target = str(params.get("target_version", ""))
    wanted = _version_order(target)
    report.update(target_version=target, config_hash=_config_hash(env, cfg), state_hash=_state(env, e), compatibility_reviewed=flag(params, "compatibility_reviewed"))
    check(report, "state", bool(report["state_hash"]) or None, "Terraform state identity captured." if report["state_hash"] else "Cannot read Terraform state; initialize and authenticate first.")
    check(report, "compatibility", True if report["compatibility_reviewed"] else None,
          "Operator reviewed charts, CRDs, CNI/CSI and provider compatibility." if report["compatibility_reviewed"] else "Set compatibility_reviewed=true only after reviewing charts, CRDs, CNI/CSI and provider compatibility.")
    version = parsed(kube(["version", "-o", "json"], e)) or {}
    current = (version.get("serverVersion") or {}).get("gitVersion", "")
    try:
        actual = _version_order(current, server=True)
    except ui.Abort:
        actual = None
    report["current_version"] = current
    check(report, "version_step", wanted > actual and wanted[0] == actual[0] and wanted[1] <= actual[1] + 1 if actual else None,
          "Only forward, at most one-minor upgrades are allowed; provider patch versions must be pinned.")
    ident = parsed(kube(["get", "namespace", "kube-system", "-o", "json"], e)) or {}
    report["cluster_uid"] = (ident.get("metadata") or {}).get("uid")
    check(report, "cluster_identity", bool(report["cluster_uid"]) or None, "Cluster identity must be available and unchanged before apply.")
    nodes = parsed(kube(["get", "nodes", "-o", "json"], e))
    items = nodes.get("items", []) if isinstance(nodes, dict) else []
    ready = bool(items) and all(any(c.get("type") == "Ready" and c.get("status") == "True" for c in n.get("status", {}).get("conditions", [])) for n in items)
    check(report, "nodes_ready", ready if nodes is not None else None, "Every node must report Ready.")
    pdb = parsed(kube(["get", "pdb", "-A", "-o", "json"], e))
    budgets = pdb.get("items", []) if isinstance(pdb, dict) else []
    blocked = [p for p in budgets if int((p.get("status") or {}).get("disruptionsAllowed", 0)) < 1 and int((p.get("status") or {}).get("expectedPods", 0)) > 0]
    check(report, "eviction_budget", not blocked if pdb is not None else None, f"{len(blocked)} disruption budgets block eviction; upgrades never force eviction.")
    pods = parsed(kube(["get", "pods", "-A", "-o", "json"], e))
    unmanaged = [p for p in (pods or {}).get("items", []) if p.get("status", {}).get("phase") not in ("Succeeded", "Failed") and not p.get("metadata", {}).get("ownerReferences") and not p.get("metadata", {}).get("annotations", {}).get("kubernetes.io/config.mirror")]
    check(report, "drain_safety", not unmanaged if pods is not None else None, f"{len(unmanaged)} running unmanaged pods would be lost by a node replacement; move them under a controller.")
    metrics = kube(["get", "--raw", "/metrics"], e)
    deprecated = []
    if not metrics.returncode:
        for line in metrics.stdout.splitlines():
            if line.startswith("apiserver_requested_deprecated_apis{") and not line.endswith(" 0"):
                removed = re.search(r'removed_release="(\d+)\.(\d+)"', line)
                if removed and tuple(map(int, removed.groups())) <= wanted[:2]:
                    deprecated.append(line)
    check(report, "deprecated_apis", not deprecated if not metrics.returncode else None,
          f"{len(deprecated)} observed API usages removed by the target version. Metrics cover observed requests only.")
    backup = params.get("backup")
    backup_data = parsed(kube(["get", "backup.velero.io", safe_name(backup, "backup"), "-n", "velero", "-o", "json"], e)) if backup else None
    status = (backup_data or {}).get("status") or {}
    age = None
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(status.get("completionTimestamp", "").replace("Z", "+00:00"))).total_seconds()
    except (ValueError, TypeError):
        pass
    complete = status.get("phase") == "Completed" and isinstance(age, (int, float)) and 0 <= age <= 86400 and status.get("errors", 0) == 0
    report["backup"] = backup
    check(report, "backup", complete if backup_data else None, "A Completed Velero backup with zero errors from the last 24 hours is required. Confirm its application and volume coverage during compatibility review.")
    if _key(cloud) == "vmware":
        distro = (cfg.get("vars") or {}).get("kubernetes_distro", "rke2")
        report["distro"] = distro
        exact = bool(re.fullmatch(r"v1\.\d+\.\d+\+rke2r\d+", target)) if distro == "rke2" else bool(re.fullmatch(r"v?1\.\d+\.\d+", target))
        check(report, "local_runner", distro in ("rke2", "kubeadm") and exact,
              "RKE2 requires an exact v1.x.y+rke2rN release. kubeadm requires an exact v1.x.y patch on Debian/Ubuntu with the target package repository already configured.")
        if distro == "kubeadm" and exact:
            package = params.get("kubeadm_package_version", target.lstrip("v") + "-1.1")
            if not isinstance(package, str) or not re.fullmatch(re.escape(target.lstrip("v")) + r"-\d+\.\d+", package):
                raise ui.Abort("kubeadm_package_version must match target_version and include its Debian revision (for example 1.36.4-1.1).", code=2)
            report["kubeadm_package_version"] = package
        outputs = _outputs(env)
        cps = outputs.get("kubernetes_control_plane_ips") or []
        wks = outputs.get("kubernetes_worker_ips") or []
        import ipaddress
        try:
            known = {str(ipaddress.ip_address(ip)) for ip in cps + wks}
            found = {a.get("address") for n in items for a in n.get("status", {}).get("addresses", []) if a.get("type") == "InternalIP"}
            mapped = bool(cps) and known == found and len(items) == len(known)
        except ValueError:
            mapped = False
        check(report, "node_inventory", mapped, "Live internal node addresses must exactly match the environment's saved VM inventory.")
        if distro == "kubeadm" and exact and mapped:
            from . import clouds, provision
            adapter = clouds.get(cloud) if isinstance(cloud, str) else cloud
            eligible = True
            for ip in cps + wks:
                host = provision.Host(ip, adapter.ssh_user(cfg), env.private_key_path(cfg), "upgrade-preflight", env=env, local=True)
                script = "command -v apt-get >/dev/null && test -s /etc/apt/keyrings/kubernetes-apt-keyring.gpg && sudo -n true && apt-cache madison kubeadm kubelet kubectl"
                probe = bounded_run(host.ssh(script), env=e, timeout=30)
                offered = {line.split("|")[0].strip() for line in probe.stdout.splitlines() if len(line.split("|")) >= 2 and line.split("|")[1].strip() == package}
                eligible = eligible and not probe.returncode and {"kubeadm", "kubelet", "kubectl"}.issubset(offered)
            check(report, "kubeadm_packages", eligible, "Every node must already offer the exact signed Debian package revision for kubeadm, kubelet and kubectl; configure the target minor repository and refresh its cache first.")
    else:
        try:
            _managed_identity(cloud, env, cfg, e, report)
            tool, prefix, common, name = provider_args(cloud, cfg, _outputs(env))
            if _key(cloud) == "aws":
                available = parsed(command(tool, [*prefix, "describe-cluster-versions", "--cluster-versions", target, *common, "--output", "json"], e))
                supported = any(v.get("clusterVersion") == target and v.get("versionStatus", "") in ("STANDARD_SUPPORT", "EXTENDED_SUPPORT") for v in (available or {}).get("clusterVersions", []))
            elif _key(cloud) == "gcp":
                available = parsed(command(tool, ["container", "get-server-config", *common], e))
                supported = target in (available or {}).get("validMasterVersions", []) and target in (available or {}).get("validNodeVersions", [])
            else:
                available = parsed(command(tool, [*prefix, "get-upgrades", "--name", name, *common], e))
                supported = any(v.get("kubernetesVersion") == target for v in (available or {}).get("controlPlaneProfile", {}).get("upgrades", []))
            check(report, "provider_version", supported if available is not None else None, "The exact target must be offered by the provider in this location.")
        except ui.Abort:
            check(report, "provider_version", None, "Cached cluster outputs or provider scope are missing; refresh this environment's outputs.")
    report["coverage_limits"] = ["No automatic downgrade or control-plane rollback. Keep the backup and use the provider recovery procedure if an upgrade fails.",
                                 "Charts/CRDs, unobserved deprecated API clients, workload-specific consistency, surge capacity and provider add-ons require operator compatibility review."]
    return e


def upgrade_plan(cloud, env, cfg, params):
    report = _report("upgrade-plan", cloud, env)
    _preflight(cloud, env, cfg, params, report)
    report["expires_at"] = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
    report["plan_digest"] = _hash(report)
    return finish(env, report)


def _load_plan(env, value):
    if not isinstance(value, str) or not value:
        raise ui.Abort("plan must name an upgrade-plan report from this environment.", code=2)
    folder = env.dir / "operations"
    path = Path(value)
    if not path.is_absolute():
        path = folder / path
    if path.parent.resolve() != folder.resolve() or not re.fullmatch(r"upgrade-plan-[a-f0-9]{32}\.json", path.name):
        raise ui.Abort("plan must be an upgrade-plan report in this environment's operations directory.", code=2)
    try:
        result = read_json(path)
        digest = result.pop("plan_digest")
        original = {k: v for k, v in result.items() if k not in ("report", "status", "exit_code")}
        # finish() sets verdict after the digest was calculated.
        original["verdict"] = "INCOMPLETE"
        if _hash(original) != digest:
            raise ValueError("edited plan")
        return result
    except (OSError, ValueError, KeyError):
        raise ui.Abort("The plan is missing, edited or unreadable. Create a fresh upgrade plan.", code=2) from None


def _wait_eks(e, common, name, update, timeout, node=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        extra = ["--nodegroup-name", node] if node else []
        data = parsed(command("aws", ["eks", "describe-update", "--name", name, "--update-id", update, *extra, *common, "--output", "json"], e))
        status = (data or {}).get("update", {}).get("status")
        if status == "Successful":
            return True
        if status in ("Failed", "Cancelled") or data is None:
            return False
        time.sleep(min(10, max(0, deadline - time.monotonic())))
    return False


def _managed_upgrade(cloud, env, cfg, target, e, timeout, report):
    tool, prefix, common, name = provider_args(cloud, cfg, _outputs(env))
    outputs = _outputs(env)
    if _key(cloud) == "aws":
        for node in (None, safe_name(outputs.get("kubernetes_node_group_name"), "node group")):
            args = ["update-nodegroup-version", "--cluster-name", name, "--nodegroup-name", node] if node else ["update-cluster-version", "--name", name]
            data = parsed(command(tool, [*prefix, *args, "--kubernetes-version", target, *common, "--output", "json"], e, timeout))
            update = (data or {}).get("update", {}).get("id")
            ok = bool(update) and _wait_eks(e, common, name, safe_name(update, "update ID"), timeout, node)
            check(report, "node_pool" if node else "control_plane", ok, "Provider upgrade reached Successful." if ok else "Provider update did not complete. Inspect the provider operation before retrying; no rollback attempted.")
            if not ok:
                return False
    elif _key(cloud) == "gcp":
        for args in (["--master"], ["--node-pool", safe_name(outputs.get("kubernetes_node_pool"), "node pool")]):
            p = command(tool, [*prefix, "upgrade", name, *args, "--cluster-version", target, "--quiet", *common], e, timeout)
            check(report, "control_plane" if args == ["--master"] else "node_pool", not p.returncode,
                  "Provider operation completed." if not p.returncode else f"Provider operation incomplete (exit {p.returncode}); inspect before retrying.")
            if p.returncode:
                return False
    else:
        p = command(tool, [*prefix, "upgrade", "--name", name, "--kubernetes-version", target, "--yes", *common], e, timeout)
        check(report, "control_plane_and_pools", not p.returncode, "AKS upgrade completed." if not p.returncode else f"AKS operation incomplete (exit {p.returncode}); inspect before retrying.")
        if p.returncode:
            return False
    return True


def _rke2_upgrade(cloud, env, cfg, target, e, timeout, report):
    from . import clouds, provision
    cloud = clouds.get(cloud) if isinstance(cloud, str) else cloud
    outputs = _outputs(env)
    live = parsed(kube(["get", "nodes", "-o", "json"], e)) or {}
    mapping = {a.get("address"): n.get("metadata", {}).get("name") for n in live.get("items", []) for a in n.get("status", {}).get("addresses", []) if a.get("type") == "InternalIP"}
    rows = [(ip, "server") for ip in outputs.get("kubernetes_control_plane_ips", [])] + [(ip, "agent") for ip in outputs.get("kubernetes_worker_ips", [])]
    for index, (ip, role) in enumerate(rows):
        name = safe_name(mapping.get(ip), "node name")
        host = provision.Host(ip, cloud.ssh_user(cfg), env.private_key_path(cfg), name, env=env, local=True)
        if index == 0:
            snapshot = bounded_run(host.ssh("sudo -n /usr/local/bin/rke2 etcd-snapshot save --name cloudseed-pre-upgrade"), env=e, timeout=timeout)
            check(report, "etcd_snapshot", not snapshot.returncode, "RKE2 local etcd snapshot saved; copy it off-node for disaster recovery.")
            if snapshot.returncode:
                return False
        drain = kube(["drain", name, "--ignore-daemonsets", f"--timeout={timeout}s"], e, timeout + 5)
        if drain.returncode:
            check(report, f"drain-{index}", False, "Drain failed without force. Node remains cordoned; inspect PDBs, unmanaged pods and emptyDir before uncordoning.")
            return False
        # Version and role have strict allowlists. The script is fixed, never accepted from a saved report.
        script = f'''set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
case "$(uname -m)" in x86_64) arch=amd64;; aarch64) arch=arm64;; *) exit 2;; esac
base='https://github.com/rancher/rke2/releases/download/{target.replace('+', '%2B')}'
asset="rke2.linux-$arch.tar.gz"
curl --proto '=https' --tlsv1.2 -fsSL --max-time 300 "$base/$asset" -o "$asset"
curl --proto '=https' --tlsv1.2 -fsSL --max-time 60 "$base/sha256sum-$arch.txt" -o sums
awk -v asset="$asset" '$2 == asset || $2 == "*" asset {{print}}' sums > selected
test "$(wc -l < selected)" -eq 1
sha256sum -c selected
sudo -n tar xzf "$asset" -C /usr/local
sudo -n systemctl daemon-reload
sudo -n systemctl restart rke2-{role}
'''
        upgrade = bounded_run(host.ssh("sh -s"), env=e, timeout=timeout, input=script)
        check(report, f"upgrade-{index}", not upgrade.returncode, "Pinned RKE2 archive checksum verified and service restarted." if not upgrade.returncode else "Node upgrade failed; node stays cordoned for inspection.")
        if upgrade.returncode:
            return False
        deadline = time.monotonic() + timeout
        verified = False
        while time.monotonic() < deadline:
            node = parsed(kube(["get", "node", name, "-o", "json"], e)) or {}
            st = node.get("status", {})
            verified = st.get("nodeInfo", {}).get("kubeletVersion") == target and any(c.get("type") == "Ready" and c.get("status") == "True" for c in st.get("conditions", []))
            if verified:
                break
            time.sleep(min(5, max(0, deadline - time.monotonic())))
        uncordon = kube(["uncordon", name], e) if verified else None
        check(report, f"verify-{index}", verified and uncordon.returncode == 0, "Node reports the exact target and Ready, then is uncordoned; otherwise it stays cordoned.")
        if not verified or uncordon.returncode:
            return False
    return True


def _kubeadm_upgrade(cloud, env, cfg, target, e, timeout, report):
    """Serial Debian/Ubuntu runner, preserving package holds and stopping at each failure."""
    from . import clouds, provision
    cloud = clouds.get(cloud) if isinstance(cloud, str) else cloud
    outputs = _outputs(env)
    nodes = (parsed(kube(["get", "nodes", "-o", "json"], e)) or {}).get("items", [])
    mapping = {a.get("address"): n.get("metadata", {}).get("name") for n in nodes for a in n.get("status", {}).get("addresses", []) if a.get("type") == "InternalIP"}
    rows = [(ip, "server") for ip in outputs.get("kubernetes_control_plane_ips", [])] + [(ip, "agent") for ip in outputs.get("kubernetes_worker_ips", [])]
    package = report["kubeadm_package_version"]
    for index, (ip, role) in enumerate(rows):
        name = safe_name(mapping.get(ip), "node name")
        host = provision.Host(ip, cloud.ssh_user(cfg), env.private_key_path(cfg), name, env=env, local=True)
        if index == 0:
            # kubeadm's stacked etcd static pod mounts this directory from the node. Save a verified snapshot before changes.
            args = ["exec", "-n", "kube-system", "etcd-" + name, "--", "etcdctl", "--endpoints=https://127.0.0.1:2379",
                    "--cacert=/etc/kubernetes/pki/etcd/ca.crt", "--cert=/etc/kubernetes/pki/etcd/server.crt",
                    "--key=/etc/kubernetes/pki/etcd/server.key", "snapshot", "save", f"/var/lib/etcd/cloudseed-{report['run']}.db"]
            snapshot = kube(args, e, timeout)
            check(report, "etcd_snapshot", not snapshot.returncode, "Stacked etcd snapshot saved on the first control plane; copy it off-node for disaster recovery.")
            if snapshot.returncode:
                return False
        drained = kube(["drain", name, "--ignore-daemonsets", f"--timeout={timeout}s"], e, timeout + 5)
        if drained.returncode:
            check(report, f"drain-{index}", False, "Drain failed without force. Node remains cordoned for inspection.")
            return False
        action = f"sudo -n kubeadm upgrade apply v{target.lstrip('v')} --yes" if index == 0 else "sudo -n kubeadm upgrade node"
        plan = f"sudo -n kubeadm upgrade plan v{target.lstrip('v')}" if index == 0 else "true"
        # The repository and signing key were configured before planning. No key or repository is fetched implicitly.
        script = f'''set -eu
trap 'sudo -n apt-mark hold kubeadm kubelet kubectl >/dev/null' EXIT
sudo -n apt-mark unhold kubeadm
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends kubeadm={package}
sudo -n apt-mark hold kubeadm
{plan}
{action}
sudo -n apt-mark unhold kubelet kubectl
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends kubelet={package} kubectl={package}
sudo -n apt-mark hold kubelet kubectl
sudo -n systemctl daemon-reload
sudo -n systemctl restart kubelet
'''
        upgraded = bounded_run(host.ssh("sh -s"), env=e, timeout=timeout, input=script)
        check(report, f"upgrade-{index}", not upgraded.returncode, "Exact kubeadm/kubelet/kubectl packages installed with signature verification and holds restored." if not upgraded.returncode else "Node upgrade failed; node remains cordoned and packages are held.")
        if upgraded.returncode:
            return False
        deadline = time.monotonic() + timeout
        verified = False
        while time.monotonic() < deadline:
            status = (parsed(kube(["get", "node", name, "-o", "json"], e)) or {}).get("status", {})
            verified = status.get("nodeInfo", {}).get("kubeletVersion", "").lstrip("v") == target.lstrip("v") and any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", []))
            if verified:
                break
            time.sleep(min(5, max(0, deadline - time.monotonic())))
        released = kube(["uncordon", name], e) if verified else None
        check(report, f"verify-{index}", verified and released.returncode == 0, "Exact kubelet target and node readiness verified before uncordon.")
        if not verified or released.returncode:
            return False
    return bool(rows)


def upgrade_apply(cloud, env, cfg, params):
    if not flag(params, "approve"):
        raise ui.Abort("upgrade-apply requires approve=true after reviewing the saved plan.", code=2)
    plan = _load_plan(env, params.get("plan"))
    report = _report("upgrade-apply", cloud, env)
    try:
        fresh = datetime.fromisoformat(plan["expires_at"]) > datetime.now(timezone.utc)
    except (KeyError, TypeError, ValueError):
        fresh = False
    if not fresh or plan.get("env") != env.id or plan.get("cloud") != _key(cloud) or plan.get("verdict") != "PASS" or plan.get("config_hash") != _config_hash(env, cfg):
        check(report, "reviewed_plan", False, "Plan is expired, blocked, belongs elsewhere, or configuration changed. Create and review a fresh plan.")
        return finish(env, report)
    fresh_params = {k: plan.get(k) for k in ("target_version", "backup", "compatibility_reviewed", "kubeadm_package_version")}
    e = _preflight(cloud, env, cfg, fresh_params, report)
    matched = all(plan.get(key) == report.get(key) for key in ("state_hash", "cluster_uid", "current_version", "provider_identity_hash"))
    check(report, "reviewed_plan", matched, "Configuration, Terraform state, cluster identity and current version must match the reviewed plan.")
    if any(c["status"] != "PASS" for c in report["checks"]):
        return finish(env, report)
    timeout = integer(params, "timeout_s", 1800)
    target = plan["target_version"]
    # Pin reviewed intent before contacting an upgrade API. Even a partial provider
    # upgrade must never be followed by Terraform attempting the old version.
    updated = copy.deepcopy(cfg)
    updated.setdefault("vars" if _key(cloud) == "vmware" else "extra_vars", {})["kubernetes_version"] = target
    root = env.stack_dir / "main.tf.json"
    original = None
    try:
        if _key(cloud) != "vmware":
            original = read_json(root)
            rendered = copy.deepcopy(original)
            rendered["module"]["stack"]["kubernetes_version"] = target
            paths.atomic_write(root, json.dumps(rendered, indent=2) + "\n", 0o600)
        env.save(updated)
    except (OSError, ValueError, KeyError, TypeError):
        if original is not None:
            paths.atomic_write(root, json.dumps(original, indent=2) + "\n", 0o600)
        check(report, "configuration_pin", False, "Could not save reviewed version intent; no cluster upgrade was started.")
        return finish(env, report)
    check(report, "configuration_pin", True, "Reviewed target saved before upgrade. It remains pinned if a later step fails, preventing an accidental downgrade. Inspect provider status and finish recovery before Terraform apply.")
    if _key(cloud) == "vmware" and report.get("distro") == "kubeadm":
        ok = _kubeadm_upgrade(cloud, env, cfg, target, e, timeout, report)
    else:
        runner = _rke2_upgrade if _key(cloud) == "vmware" else _managed_upgrade
        ok = runner(cloud, env, cfg, target, e, timeout, report)
    if ok:
        version = parsed(kube(["version", "-o", "json"], e)) or {}
        actual = version.get("serverVersion", {}).get("gitVersion", "")
        nodes = parsed(kube(["get", "nodes", "-o", "json"], e)) or {}
        try:
            match = _version(re.sub(r"[-+].*$", "", actual))[:2] == _version(target)[:2]
        except ui.Abort:
            match = False
        ready = bool(nodes.get("items")) and all(any(c.get("type") == "Ready" and c.get("status") == "True" for c in n.get("status", {}).get("conditions", [])) for n in nodes.get("items", []))
        exact = _key(cloud) == "aws"
        def version_matches(value):
            try:
                actual_tuple = _version(re.sub(r"[-+].*$", "", value))
                return actual_tuple[:2] == _version(target)[:2] if exact else value.lstrip("v") == target.lstrip("v")
            except ui.Abort:
                return False
        pinned = version_matches(actual) and all(version_matches(n.get("status", {}).get("nodeInfo", {}).get("kubeletVersion", "")) for n in nodes.get("items", []))
        workload = parsed(kube(["get", "deployments,statefulsets,daemonsets", "-A", "-o", "json"], e))
        healthy = workload is not None
        for item in (workload or {}).get("items", []):
            spec, status = item.get("spec", {}), item.get("status", {})
            expected = status.get("desiredNumberScheduled", 0) if item.get("kind") == "DaemonSet" else spec.get("replicas", 1)
            available = status.get("numberAvailable", 0) if item.get("kind") == "DaemonSet" else status.get("readyReplicas", 0)
            healthy = healthy and available >= expected and status.get("observedGeneration", 0) >= item.get("metadata", {}).get("generation", 0)
        check(report, "post_upgrade", match and ready and pinned and healthy,
              "Control-plane and every kubelet match the pinned target (minor for EKS); all nodes and workload controllers are ready.")
    return finish(env, report)


def execute(action, cloud, env, cfg, params):
    if action == "drift":
        return drift(cloud, env, cfg, params)
    if action == "upgrade-plan":
        return upgrade_plan(cloud, env, cfg, params)
    if action == "upgrade-apply":
        return upgrade_apply(cloud, env, cfg, params)
    raise ui.Abort(f"Unknown lifecycle action: {action}", code=2)
