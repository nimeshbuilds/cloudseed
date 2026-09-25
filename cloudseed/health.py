"""Bounded environment diagnostics. Offline by default; active probes require a separate opt-in.

The caller saves returned reports. Only an explicitly active probe writes a cleanup manifest, before it creates
its temporary namespace. No helper fetches credentials, installs tools, or opens a tunnel.
"""
from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import secrets
import signal
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import architecture, deps, paths, services, ui

MAX_OUTPUT = 1024 * 1024
DEFAULT_ENDPOINTS = ("https://registry.k8s.io/v2/", "https://example.com/")
PROBE_IMAGE = "python:3.12-alpine"
OWNER_LABEL = "cloudseed.io/network-probe"


def _run(argv, *, env=None, timeout=30, input=None, graceful=False):
    """Bound capture without a shell; stateful children get interrupt grace and continue draining after truncation."""
    proc = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name == "posix")
    streams = [bytearray(), bytearray()]
    overflow = threading.Event()
    lock = threading.Lock()

    def stop():
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass

    def read(pipe, dest):
        try:
            while True:
                data = pipe.read(65536)
                if not data:
                    break
                with lock:
                    remaining = MAX_OUTPUT - sum(map(len, streams))
                    dest.extend(data[:max(0, remaining)])
                    if len(data) > remaining:
                        overflow.set()
                        if not graceful:
                            stop()
        finally:
            pipe.close()

    readers = [threading.Thread(target=read, args=(pipe, dest), daemon=True)
               for pipe, dest in zip((proc.stdout, proc.stderr), streams)]
    for reader in readers:
        reader.start()
    try:
        if input is not None:
            try:
                proc.stdin.write(input.encode("utf-8"))
                proc.stdin.close()
            except BrokenPipeError:
                pass
        proc.wait(timeout=timeout)
        rc = proc.returncode
    except BaseException as error:
        # Acceptance uses this grace period so Terraform can persist state and release locks before cleanup.
        if graceful:
            try:
                os.killpg(proc.pid, signal.SIGINT) if os.name == "posix" else proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                stop()
        else:
            stop()
        proc.wait()
        if not isinstance(error, subprocess.TimeoutExpired):
            raise
        rc = 124
    finally:
        # Descendants holding stdout open cannot keep this call or its reader threads indefinitely alive.
        stop()
        for reader in readers:
            reader.join(timeout=2)
    if overflow.is_set() and not graceful:
        rc = 125
    return subprocess.CompletedProcess(argv, rc, *(b.decode("utf-8", "replace") for b in streams))


@contextlib.contextmanager
def _cleanup_on_term():
    """Turn SIGTERM into a cleanup opportunity on the main thread; preserve the caller's signal policy."""
    previous = None
    if threading.current_thread() is threading.main_thread():
        previous = signal.getsignal(signal.SIGTERM)
        def interrupt(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupt)
    try:
        yield
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)


def _list(value):
    return value if isinstance(value, list) else []


def _object(value):
    return value if isinstance(value, dict) else {}


def _items(value):
    value = _object(value).get("items")
    return value if isinstance(value, list) and all(isinstance(x, dict) for x in value) else None


def _json(proc):
    if proc.returncode:
        return None
    try:
        value = json.loads(proc.stdout)
        return value if isinstance(value, dict) else None
    except (ValueError, RecursionError):
        return None


def _endpoint(value):
    if not isinstance(value, str) or len(value) > 512 or any(c.isspace() for c in value):
        raise ui.Abort("Probe endpoints must be HTTPS URLs without credentials, queries or fragments.", code=2)
    try:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment \
                or parts.port not in (None, 443) or not re.fullmatch(r"[A-Za-z0-9.-]+", parts.hostname):
            raise ValueError()
        try:
            address = ipaddress.ip_address(parts.hostname)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError()
        if parts.hostname.lower() in ("localhost", "metadata.google.internal"):
            raise ValueError()
    except ValueError:
        raise ui.Abort("Probe endpoints require HTTPS on port 443, no credentials/query/fragment, and no local or metadata IP.", code=2) from None
    return value


def _options(params):
    if not isinstance(params, dict):
        raise ui.Abort("Diagnostic options must be an object.", code=2)
    live, active = params.get("live", False), params.get("active", False)
    if type(live) is not bool or type(active) is not bool or active and not live:
        raise ui.Abort("Active probes require live=true; live and active must be booleans.", code=2)
    timeout = params.get("timeout", 30)
    if type(timeout) is not int or not 5 <= timeout <= 300:
        raise ui.Abort("Diagnostic timeout must be an integer from 5 to 300 seconds per command.", code=2)
    age = params.get("max_age_days", 1)
    if type(age) is not int or not 1 <= age <= 365:
        raise ui.Abort("Diagnostic evidence age must be from 1 to 365 days.", code=2)
    endpoints = params.get("endpoints", list(DEFAULT_ENDPOINTS))
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 8:
        raise ui.Abort("Supply between one and eight probe endpoints.", code=2)
    return live, active, timeout, age, [_endpoint(x) for x in endpoints]


def _finding(id_, status, title, detail, remediation, *, live=False, **evidence):
    return {"id": id_, "status": status, "severity": "HIGH" if status == "FAIL" else "MEDIUM", "title": title,
            "detail": detail, "remediation": remediation,
            "evidence": [{"type": "live_query" if live else "local_inspection", "live_verified": live, **evidence}]}


def _finish(action, target, env, live, active, findings, now, **extra):
    counts = {s.lower(): sum(f["status"] == s for f in findings) for s in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")}
    return {"schema_version": 1, "kind": action, "cloud": target, "target": target, "env": env.id,
            "generated_at": now.isoformat().replace("+00:00", "Z"), "run": now.strftime("%Y%m%d-%H%M%S"),
            "live": live, "active": active, "verdict": "FAIL" if counts["fail"] else "INCOMPLETE" if counts["unknown"] else "PASS",
            "summary": counts, "findings": findings, "coverage_limits": [
                "Local configuration and saved reports do not establish current cloud health.",
                "Live reads use only this environment's existing kubeconfig; connect its VPN/tunnel first if required.",
                "An active probe samples one scheduled pod and selected endpoints; it does not prove every node, subnet, registry or workload policy.",
                "Read-only health queries do not test restores, database consistency, application SLOs or all certificate types."], **extra}


def execute(action, cloud, env, cfg, params=None):
    """Assess health/network. Options: live=False, active=False, timeout=30, max_age_days=1, endpoints=[HTTPS URLs]."""
    target = cloud if isinstance(cloud, str) else cloud.key
    if action not in ("health", "network") or target not in ("aws", "gcp", "azure", "vmware") or not isinstance(cfg, dict):
        raise ui.Abort("Diagnostics require health/network, a supported cloud and an environment configuration.", code=2)
    live, active, timeout, age, endpoints = _options({} if params is None else params)
    now = datetime.now(timezone.utc)
    findings = []
    add = lambda *a, **kw: findings.append(_finding(*a, **kw))
    k8s = architecture._flag(cfg, "enable_kubernetes", None)
    expected = {"aws": "private node subnet → NAT gateway → internet gateway (isolated data subnets have no default internet route)",
                "gcp": "private node subnet → Cloud NAT", "azure": "private node subnet → attached NAT gateway",
                "vmware": "private node → bastion forwarding/NAT → host network"}[target]
    add("network.route", "UNKNOWN", "Private node egress", f"Expected Cloudseed route: {expected}. The deployed route is not inspected.",
        "Run an active probe, then inspect subnet routes, NAT health, firewalls and NetworkPolicies if it fails.", expected_route=expected)
    saved, evidence = architecture._latest(env, "scans", action, now, age)
    matching = saved and saved.get("cloud") == target and saved.get("env") == env.id and saved.get("kind") == action
    if saved and not matching:
        evidence["reason"] = "latest report target does not match this environment"
    add("evidence.previous", "NOT_APPLICABLE" if live else "UNKNOWN", "Previous diagnostic evidence",
        "A recent report is available; rerun live checks to establish current health." if matching else "No recent matching report is available.",
        "Run with --live after configuring cluster access.", source=evidence.get("source"),
        previous_verdict=saved.get("verdict") if matching else None, reason=evidence.get("reason"))
    checks = [("cluster.api", "Cluster API"), ("cluster.nodes", "Node readiness"), ("cluster.platform", "Deployment availability"),
              ("cluster.certificates", "Certificate expiry"), ("cluster.backups", "Backup freshness")] if action == "health" else [("cluster.api", "Cluster API")]
    if not live or k8s is False:
        status = "NOT_APPLICABLE" if k8s is False else "UNKNOWN"
        for id_, title in checks + [("network.dns", "Cluster DNS"), ("network.registry", "Registry image pull"), ("network.tls", "TLS and HTTPS egress")]:
            add(id_, status, title, "Kubernetes is disabled in saved configuration." if k8s is False else "Not queried: offline mode.",
                "Enable Kubernetes and configure access." if k8s is False else "Use --live; DNS, registry and TLS probes additionally require --active.")
        return _finish(action, target, env, live, active, findings, now)
    kubectl = deps.find("kubectl")
    kc = services.kubeconfig_path(env)
    safe = kc.is_file() and not kc.is_symlink() and not kc.parent.is_symlink()
    if not kubectl or not safe:
        for id_, title in checks + [("network.dns", "Cluster DNS"), ("network.registry", "Registry image pull"), ("network.tls", "TLS and HTTPS egress")]:
            add(id_, "UNKNOWN", title, "kubectl or the environment's regular kubeconfig file is unavailable.",
                f"Install kubectl explicitly; configure access with cs k8s kubeconfig {target} --env {getattr(env, 'name', env.id)}.")
        return _finish(action, target, env, live, active, findings, now)
    procenv = dict(services.cloud_cli_env(target, cfg), KUBECONFIG=str(kc))

    def query(*args, input=None, seconds=None):
        try:
            return _run([kubectl, "--kubeconfig", str(kc), f"--request-timeout={timeout}s", *args],
                        env=procenv, timeout=seconds or timeout + 2, input=input)
        except OSError:
            return subprocess.CompletedProcess(args, 127, "", "")

    api = query("get", "--raw=/readyz")
    api_ok = api.returncode == 0 and api.stdout.strip() == "ok"
    add("cluster.api", "PASS" if api_ok else "UNKNOWN", "Cluster API",
        "The API readiness endpoint answered successfully." if api_ok else "The API readiness endpoint could not be verified (access, RBAC, tunnel or readiness).",
        "Check cluster state, credentials, VPN/tunnel and /readyz RBAC.", live=api_ok, exit_code=api.returncode)
    if action == "health":
        _health_reads(query, add, now, age)
    if active:
        with _cleanup_on_term():
            _active_probe(query, add, env, endpoints, timeout)
    else:
        for id_, title in (("network.dns", "Cluster DNS"), ("network.registry", "Registry image pull"), ("network.tls", "TLS and HTTPS egress")):
            add(id_, "UNKNOWN", title, "Read-only mode does not create a probe workload.", "Use --live --active to authorize a temporary restricted probe pod and its cleanup.")
    return _finish(action, target, env, live, active, findings, now, endpoints=endpoints if active else [])


def _health_reads(query, add, now, age):
    nodes = _items(_json(query("get", "nodes", "-o", "json")))
    ready = lambda n: any(c.get("type") == "Ready" and c.get("status") == "True" for c in _list(_object(n.get("status")).get("conditions")) if isinstance(c, dict))
    pressure = lambda n: any(c.get("type") in ("MemoryPressure", "DiskPressure", "PIDPressure") and c.get("status") == "True"
                             for c in _list(_object(n.get("status")).get("conditions")) if isinstance(c, dict))
    bad = sum(not ready(n) or pressure(n) for n in nodes or [])
    add("cluster.nodes", "UNKNOWN" if nodes is None else "FAIL" if not nodes or bad else "PASS", "Node readiness",
        "Node status unavailable." if nodes is None else f"{len(nodes)} nodes inspected; {bad} not ready or under pressure.",
        "Inspect node conditions, capacity, kubelet and network health.", live=nodes is not None, node_count=len(nodes or []), unhealthy=bad)
    deployments = _items(_json(query("get", "deployments", "--all-namespaces", "-o", "json")))
    bad = 0
    for item in deployments or []:
        spec, status, metadata = (_object(item.get(k)) for k in ("spec", "status", "metadata"))
        values = (spec.get("replicas", 1), status.get("availableReplicas", 0), metadata.get("generation", 0), status.get("observedGeneration", 0))
        bad += any(type(v) is not int or v < 0 for v in values) or values[1] < values[0] or values[3] < values[2]
    add("cluster.platform", "UNKNOWN" if deployments is None or not deployments else "FAIL" if bad else "PASS", "Deployment availability",
        "Deployment state unavailable or no deployments found." if not deployments else f"{len(deployments)} deployments inspected; {bad} unavailable or reconciling.",
        "Inspect rollout status, pod events, registry pulls and resource limits.", live=deployments is not None, deployment_count=len(deployments or []), unhealthy=bad)
    certificates = _items(_json(query("get", "certificates.cert-manager.io", "--all-namespaces", "-o", "json")))
    expires = [architecture._utc(_object(c.get("status")).get("notAfter")) for c in certificates or []]
    bad = sum(dt is not None and dt < now + timedelta(days=30) for dt in expires)
    unknown = any(dt is None for dt in expires)
    add("cluster.certificates", "FAIL" if bad else "UNKNOWN" if not certificates or unknown else "PASS", "Certificate expiry",
        "No complete cert-manager expiry evidence available." if not certificates or unknown else f"{len(certificates)} cert-manager certificates inspected; {bad} expire within 30 days.",
        "Inspect cert-manager renewal/issuer conditions; separately check ingress and provider-managed certificates.",
        live=bool(certificates) and not unknown, expiring=bad)
    backups = _items(_json(query("get", "backups.velero.io", "--all-namespaces", "-o", "json")))
    completed = [architecture._utc(_object(b.get("status")).get("completionTimestamp")) for b in backups or []
                 if _object(b.get("status")).get("phase") == "Completed"]
    recent = [dt for dt in completed if dt is not None and now - timedelta(days=age) <= dt <= datetime.now(timezone.utc)]
    add("cluster.backups", "UNKNOWN" if backups is None else "PASS" if recent else "FAIL", "Backup freshness",
        "Velero backups could not be queried." if backups is None else f"{len(recent)} completed backups within {age} day(s). Completion does not prove recovery.",
        "Check backup schedules/storage and run a restore drill; confirm required namespaces and volumes are covered.", live=backups is not None, recent_completed=len(recent))


# No shell, service account token, host mount, privilege, or elevated capability is required by this script.
PROBE_CODE = '''import ipaddress,json,socket,ssl,sys,urllib.request,urllib.error
from urllib.parse import urlsplit
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
opener=urllib.request.build_opener(NoRedirect)
results=[]
try:
 socket.getaddrinfo("kubernetes.default.svc",443)
 results.append({"check":"dns","ok":True})
except Exception:
 results.append({"check":"dns","ok":False})
for endpoint in json.loads(sys.argv[1]):
 try:
  host=urlsplit(endpoint).hostname
  if not all(ipaddress.ip_address(x[4][0]).is_global for x in socket.getaddrinfo(host,443)): raise ValueError("non-public endpoint")
  with socket.create_connection((host,443),timeout=8) as raw:
   with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as tls:
    tls.getpeercert()
  try:
   with opener.open(endpoint,timeout=8) as response: code=response.status
  except urllib.error.HTTPError as error: code=error.code
  results.append({"check":"https","endpoint":endpoint,"ok":True,"http_status":code})
 except Exception:
  results.append({"check":"https","endpoint":endpoint,"ok":False})
print(json.dumps({"results":results}))
'''


def _active_probe(query, add, env, endpoints, timeout):
    token = secrets.token_hex(8)
    namespace = "cloudseed-net-" + token
    manifest_root = Path(env.dir) / "operations"
    if manifest_root.is_symlink():
        raise ui.Abort("Refusing a symlinked diagnostic manifest directory.", code=2)
    manifest_path = manifest_root / (namespace + ".json")
    cleanup = {"schema_version": 1, "namespace": namespace, "owner": token, "uid": None, "cleanup": "pending", "env": env.id}
    paths.atomic_write(manifest_path, json.dumps(cleanup, indent=2) + "\n")
    ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": {
        OWNER_LABEL: token, "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "latest"}}}
    uid = None
    try:
        create = query("create", "-f", "-", "-o", "json", input=json.dumps(ns))
        obj = _json(create)
        if create.returncode:
            add("network.probe", "UNKNOWN", "Active network probe", "Temporary namespace creation failed or timed out; no pod was started.",
                f"Inspect RBAC and cleanup manifest {manifest_path.name}. A namespace may exist if the API response was lost.")
            return
        meta = _object(_object(obj).get("metadata"))
        uid = meta.get("uid")
        if not isinstance(uid, str) or not uid or _object(meta.get("labels")).get(OWNER_LABEL) != token:
            add("network.probe", "UNKNOWN", "Active network probe", "Namespace ownership could not be established; no pod was started.", "Inspect the saved cleanup manifest.")
            return
        cleanup["uid"] = uid
        paths.atomic_write(manifest_path, json.dumps(cleanup, indent=2) + "\n")
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "probe", "namespace": namespace, "labels": {OWNER_LABEL: token}},
               "spec": {"restartPolicy": "Never", "activeDeadlineSeconds": timeout, "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": "probe", "image": PROBE_IMAGE, "imagePullPolicy": "Always", "command": ["python3", "-c", PROBE_CODE, json.dumps(endpoints)],
                                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "100m", "memory": "64Mi"}}}]}}
        made = query("create", "-f", "-", input=json.dumps(pod))
        if made.returncode:
            add("network.probe", "UNKNOWN", "Active network probe", "Restricted probe pod creation failed.", "Inspect admission policies and namespace RBAC.")
            return
        waited = query("wait", "-n", namespace, "pod/probe", "--for=jsonpath={.status.phase}=Succeeded", f"--timeout={timeout}s", seconds=timeout + 5)
        observed = _json(query("get", "pod", "probe", "-n", namespace, "-o", "json"))
        statuses = _list(_object(_object(observed).get("status")).get("containerStatuses"))
        pulled = any(isinstance(c, dict) and c.get("imageID") for c in statuses if isinstance(statuses, list))
        pull_failed = any(_object(_object(c.get("state")).get("waiting")).get("reason") in ("ErrImagePull", "ImagePullBackOff")
                          for c in statuses if isinstance(c, dict)) if isinstance(statuses, list) else False
        add("network.registry", "PASS" if pulled else "FAIL" if pull_failed else "UNKNOWN", "Registry image pull",
            "The selected node pulled/resolved the probe image with imagePullPolicy Always." if pulled else "Probe image pull was not verified.",
            "Inspect image credentials, DNS, NAT and registry allowlists; other node pools and workload registries need separate testing.", live=bool(pulled or pull_failed), image=PROBE_IMAGE)
        logs = _json(query("logs", "-n", namespace, "probe")) if waited.returncode == 0 else None
        results = _object(logs).get("results", [])
        results = results if isinstance(results, list) else []
        dns = next((r for r in results if isinstance(r, dict) and r.get("check") == "dns" and type(r.get("ok")) is bool), None)
        add("network.dns", "UNKNOWN" if dns is None else "PASS" if dns["ok"] else "FAIL", "Cluster DNS",
            "kubernetes.default.svc resolved from the probe pod." if dns and dns["ok"] else "Cluster DNS resolution was not successful or the probe did not finish.",
            "Inspect CoreDNS, pod DNS configuration and NetworkPolicies.", live=dns is not None)
        for i, endpoint in enumerate(endpoints):
            result = next((r for r in results if isinstance(r, dict) and r.get("check") == "https" and r.get("endpoint") == endpoint and type(r.get("ok")) is bool), None)
            add(f"network.tls.{i + 1}", "UNKNOWN" if result is None else "PASS" if result["ok"] else "FAIL", "TLS and HTTPS egress",
                f"{endpoint}: " + ("DNS, TLS certificate verification and HTTPS response succeeded." if result and result["ok"] else "connectivity was not verified."),
                "Inspect DNS, NAT/routes, egress firewall/NetworkPolicy and TLS trust. HTTP errors prove connectivity, not application health.",
                live=result is not None, endpoint=endpoint, http_status=result.get("http_status") if result else None)
    finally:
        # Read ownership back even after an ambiguous create: only the exact random label + UID can authorize deletion.
        current = _json(query("get", "namespace", namespace, "-o", "json"))
        meta = _object(_object(current).get("metadata"))
        current_uid = meta.get("uid")
        owns = isinstance(current_uid, str) and bool(current_uid) and _object(meta.get("labels")).get(OWNER_LABEL) == token and (uid is None or uid == current_uid)
        if owns:
            opts = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": current_uid}, "propagationPolicy": "Foreground"}
            deleted = query("delete", f"--raw=/api/v1/namespaces/{namespace}", "-f", "-", input=json.dumps(opts))
            gone = query("wait", "--for=delete", "namespace/" + namespace, f"--timeout={timeout}s", seconds=timeout + 5) if deleted.returncode == 0 else deleted
            cleanup["cleanup"] = "complete" if gone.returncode == 0 else "failed"
        else:
            cleanup["cleanup"] = "unknown"  # never equate unreadable with absent
        cleanup["uid"] = uid or (current_uid if owns else None)
        paths.atomic_write(manifest_path, json.dumps(cleanup, indent=2) + "\n")
        add("network.cleanup", "PASS" if cleanup["cleanup"] == "complete" else "UNKNOWN", "Probe cleanup",
            "The owned temporary namespace was deleted and deletion verified." if cleanup["cleanup"] == "complete" else "Cleanup could not be verified; inspect the manifest before removing anything.",
            f"Review operations/{manifest_path.name}; delete only the namespace with the recorded owner label and UID.",
            live=cleanup["cleanup"] == "complete", namespace=namespace, manifest=f"operations/{manifest_path.name}")
