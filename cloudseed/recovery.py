"""Selected-application Velero recovery into a new, isolated namespace.

The original namespace is never deleted or modified. Only fixed built-in
consistency commands can run; arbitrary shell hooks are refused. Reports contain
comparison results, never Secret values or their reusable unsalted hashes.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone

from . import ui
from .lifecycle import (_report, check, finish, flag, integer, kube, parsed,
                        process_env, safe_name)

LABEL = "cloudseed.io/recovery-run"
DNS = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
SELECTOR = re.compile(r"[A-Za-z0-9_.\-/]+=[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.\-/]+=[A-Za-z0-9_.-]+)*\Z")
RESOURCES = ["pods", "replicasets.apps", "deployments.apps", "statefulsets.apps", "configmaps", "secrets", "serviceaccounts", "persistentvolumeclaims"]


def _params(params):
    ns = params.get("namespace")
    if not isinstance(ns, str) or not DNS.fullmatch(ns) or ns.startswith(("kube-", "cloudseed-recovery-")) or ns in ("default", "velero"):
        raise ui.Abort("namespace must be an application namespace (not default, velero, kube-* or a drill namespace).", code=2)
    selector = params.get("selector", "")
    if not isinstance(selector, str) or (selector and not SELECTOR.fullmatch(selector)):
        raise ui.Abort("selector supports comma-separated key=value labels.", code=2)
    hook = params.get("consistency_hook", "none")
    if hook not in ("none", "filesystem-sync", "postgres-checkpoint"):
        raise ui.Abort("consistency_hook must be none, filesystem-sync or postgres-checkpoint; arbitrary shell commands are not accepted.", code=2)
    out = {"namespace": ns, "selector": selector, "consistency_hook": hook,
           "timeout_s": integer(params, "timeout_s", 600), "rto_seconds": integer(params, "rto_seconds", 600, high=86400),
           "rpo_seconds": integer(params, "rpo_seconds", 3600, high=86400 * 30)}
    for key in ("verify_data", "with_volumes", "keep", "isolation_reviewed"):
        out[key] = flag(params, key)
    if hook != "none" or params.get("data_file"):
        out["pod"] = safe_name(params.get("pod"), "pod")
        out["container"] = safe_name(params.get("container"), "container")
    data_file = params.get("data_file")
    if data_file:
        if not isinstance(data_file, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]{1,255}", data_file) or ".." in data_file.split("/"):
            raise ui.Abort("data_file must be an absolute path without traversal or shell characters.", code=2)
        out["data_file"] = data_file
    return out


def _objects(e, ns, resources, selector=""):
    proc = kube(["get", ",".join(resources), "-n", ns, *(["-l", selector] if selector else []), "-o", "json"], e)
    data = parsed(proc)
    return data.get("items", []) if isinstance(data, dict) and isinstance(data.get("items"), list) else None


def _pod_specs(items):
    for item in items:
        spec = item.get("spec", {})
        if item.get("kind") == "Pod":
            yield item.get("metadata", {}), spec
        elif item.get("kind") in ("Deployment", "StatefulSet", "ReplicaSet"):
            template = spec.get("template", {})
            yield template.get("metadata", {}), template.get("spec", {})


def _preflight(e, params, report):
    items = _objects(e, params["namespace"], RESOURCES, params["selector"])
    check(report, "source", bool(items) if items is not None else None, "Selected application resources must exist and be readable.")
    if items is None:
        items = []
    pods = [i for i in items if i.get("kind") == "Pod"]
    controllers = [i for i in items if i.get("kind") in ("Deployment", "StatefulSet")]
    check(report, "workload_scope", bool(pods) and bool(controllers), "Select running pods and their Deployment or StatefulSet, plus labelled dependencies when using a selector.")
    dangerous = hooks = 0
    for meta, spec in _pod_specs(items):
        annotations = meta.get("annotations") or {}
        hooks += int(any("hook" in k and "velero.io" in k for k in annotations))
        dangerous += int(bool(spec.get("hostNetwork") or spec.get("hostPID") or spec.get("hostIPC") or
                              any(v.get("hostPath") for v in spec.get("volumes", [])) or
                              any(c.get("securityContext", {}).get("privileged") for c in spec.get("containers", []) + spec.get("initContainers", []))))
    check(report, "safe_restore", dangerous == 0, "Host networking, host namespaces, privileged containers and hostPath are refused; the destination enforces restricted Pod Security.")
    check(report, "hooks", hooks == 0, "Existing Velero shell hook annotations must be removed from the selected scope; only fixed Cloudseed hooks may run.")
    check(report, "network_isolation", True if params["isolation_reviewed"] else None,
          "Confirm isolation_reviewed=true only after verifying that this cluster's CNI enforces NetworkPolicy; the drill creates deny-all ingress and egress before restoring.")
    agents = parsed(kube(["get", "daemonsets", "-A", "-o", "json"], e))
    known = {"calico-node", "cilium-agent", "cilium", "azure-npm", "aws-network-policy-agent", "antrea-agent"}
    capable = False
    for agent in (agents or {}).get("items", []):
        meta, status = agent.get("metadata", {}), agent.get("status", {})
        recognized = any(c.get("name") in known for c in agent.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []))
        # GKE Dataplane V2 runs its managed Cilium distribution as anetd.
        recognized = recognized or (meta.get("namespace") == "kube-system" and meta.get("name") == "anetd" and meta.get("labels", {}).get("k8s-app") == "cilium")
        desired = status.get("desiredNumberScheduled", 0)
        capable = capable or (recognized and desired > 0 and status.get("numberReady", 0) == desired and status.get("numberUnavailable", 0) == 0)
    check(report, "policy_engine", True if capable else None, "A fully Ready NetworkPolicy engine (Calico, Cilium/GKE anetd, Azure NPM, AWS network-policy agent or Antrea) must be visible; Flannel alone does not enforce isolation.")
    pvcs = [i for i in items if i.get("kind") == "PersistentVolumeClaim"]
    check(report, "volume_scope", not pvcs or params["with_volumes"], f"{len(pvcs)} PVCs selected. Set with_volumes=true for file-system backup and restore; cluster-scoped PVs and snapshots are never restored.")
    bound = all(p.get("spec", {}).get("storageClassName") and p.get("status", {}).get("phase") == "Bound" for p in pvcs)
    check(report, "dynamic_storage", bound, "PVC restores require Bound claims using a StorageClass with dynamic provisioning; verify available capacity before approval.")
    velero = parsed(kube(["get", "deployment", "velero", "-n", "velero", "-o", "json"], e))
    check(report, "velero", bool((velero or {}).get("status", {}).get("availableReplicas")) if velero else None, "Velero must be available before the drill.")
    if params["consistency_hook"] != "none" or params.get("data_file"):
        match = next((p for p in pods if p.get("metadata", {}).get("name") == params["pod"]), None)
        exists = match and any(c.get("name") == params["container"] for c in match.get("spec", {}).get("containers", []))
        check(report, "selected_container", bool(exists), "The hook/checksum pod and container must belong to the selected application.")
    report["coverage_limits"] = ["This is an isolated same-cluster clone drill, not a regional outage or external database recovery test.",
        "Services, ingress, jobs, operators, RBAC and cluster-scoped resources are excluded. Deny-all networking can prevent applications with dependencies from becoming Ready.",
        "File-system backups are crash-consistent unless the application is quiesced externally; checkpoint/sync alone does not prove transaction consistency.",
        "RPO measures age of this drill's completed backup at restore start. It does not measure the production backup schedule or database transaction loss.",
        "ConfigMap/Secret equality and an optional read-only file checksum are verified in memory; sensitive values and digests are never saved."]
    return items


def _create(e, value):
    return kube(["create", "-f", "-"], e, input=json.dumps(value)).returncode == 0


def _wait(e, kind, name, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        obj = parsed(kube(["get", kind, name, "-n", "velero", "-o", "json"], e))
        status = (obj or {}).get("status") or {}
        if status.get("phase") in ("Completed", "PartiallyFailed", "Failed", "FailedValidation"):
            return obj
        if obj is None:
            return None
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    return None


def _complete(obj):
    s = (obj or {}).get("status") or {}
    return s.get("phase") == "Completed" and s.get("errors", 0) == 0


def _fingerprints(items):
    result = {}
    for item in items:
        if item.get("kind") not in ("ConfigMap", "Secret"):
            continue
        # Token Secrets are regenerated and never demonstrate recoverable application data.
        if item.get("type") == "kubernetes.io/service-account-token":
            continue
        value = {k: item.get(k) for k in ("data", "binaryData", "type") if k in item}
        result[(item["kind"], item.get("metadata", {}).get("name"))] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).digest()
    return result


def _checksum(e, ns, p):
    proc = kube(["exec", "-n", ns, p["pod"], "-c", p["container"], "--", "sha256sum", "--", p["data_file"]], e)
    digest = proc.stdout.split()[0] if proc.returncode == 0 and proc.stdout.split() else ""
    return digest if re.fullmatch(r"[a-fA-F0-9]{64}", digest) else None


def _volume_ok(e, kind, key, value):
    items = _objects(e, "velero", [kind], f"{key}={value}")
    return bool(items) and all(i.get("status", {}).get("phase") == "Completed" for i in items)


def _cleanup(e, run, namespace, backup, restore, restore_finished, report):
    owned = parsed(kube(["get", "namespace", namespace, "-o", "json"], e))
    namespace_owned = (owned or {}).get("metadata", {}).get("labels", {}).get(LABEL) == run
    if not restore_finished and restore:
        check(report, "cleanup", None, "Restore completion is unknown. Isolated namespace and owned backup remain for inspection; no original resources were removed.")
        return
    failures = []
    if namespace_owned:
        uid = owned.get("metadata", {}).get("uid")
        opts = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}, "propagationPolicy": "Foreground"}
        deleted = kube(["delete", f"--raw=/api/v1/namespaces/{namespace}", "-f", "-"], e, input=json.dumps(opts)) if uid else None
        gone = kube(["wait", "--for=delete", "namespace/" + namespace, "--timeout=120s"], e, 125) if deleted is not None and not deleted.returncode else None
        if gone is None or gone.returncode:
            failures.append("namespace deletion not verified")
    else:
        failures.append("namespace ownership mismatch or unknown")
    for kind, name in (("restore.velero.io", restore), ("backup.velero.io", backup)):
        if not name:
            continue
        obj = parsed(kube(["get", kind, name, "-n", "velero", "-o", "json"], e))
        if (obj or {}).get("metadata", {}).get("labels", {}).get(LABEL) != run:
            failures.append(kind + " ownership unknown")
            continue
        if kind.startswith("backup"):
            # The controller deletes the backup data as well; deleting only the CR would orphan bucket objects.
            req = {"apiVersion": "velero.io/v1", "kind": "DeleteBackupRequest", "metadata": {"name": f"delete-{name}", "namespace": "velero", "labels": {LABEL: run}}, "spec": {"backupName": name}}
            if not _create(e, req) or kube(["wait", "--for=delete", f"{kind}/{name}", "-n", "velero", "--timeout=120s"], e, 125).returncode:
                failures.append("backup deletion not verified")
        else:
            uid = obj.get("metadata", {}).get("uid")
            opts = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}}
            deleted = kube(["delete", f"--raw=/apis/velero.io/v1/namespaces/velero/restores/{name}", "-f", "-"], e, input=json.dumps(opts)) if uid else None
            if deleted is None or deleted.returncode:
                failures.append("restore")
    check(report, "cleanup", not failures, "Owned namespace deletion verified with a UID precondition; restore metadata removed and Velero backup deletion verified. Backup also expires after 24h." if not failures else "Cleanup needs inspection: " + ", ".join(failures))


def execute(action, cloud, env, cfg, params):
    if action not in ("recovery-plan", "recovery-test"):
        raise ui.Abort(f"Unknown recovery action: {action}", code=2)
    p = _params(params)
    if action == "recovery-test" and not flag(params, "approve"):
        raise ui.Abort("recovery-test requires approve=true after reviewing recovery-plan.", code=2)
    report = _report(action, cloud, env)
    report["parameters"] = p
    report["source_namespace"] = p["namespace"]
    e = process_env(cloud, env, cfg)
    items = _preflight(e, p, report)
    if action == "recovery-plan" or any(c["status"] != "PASS" for c in report["checks"]):
        return finish(env, report)
    suffix = report["run"][:16]
    ns, backup, restore = f"cloudseed-recovery-{suffix}", f"recovery-{suffix}", f"recovery-{suffix}-restore"
    report.update(namespace=ns, backup=backup, restore=restore, rto_s=None, rpo_s=None, volume_tested=p["with_volumes"], volume_verified=False)
    created_ns = created_backup = created_restore = restored = False
    source_data = _fingerprints(items) if p["verify_data"] else {}
    file_hash = None
    try:
        if p["consistency_hook"] != "none":
            argv = ["sync"] if p["consistency_hook"] == "filesystem-sync" else ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-c", "CHECKPOINT"]
            hook = kube(["exec", "-n", p["namespace"], p["pod"], "-c", p["container"], "--", *argv], e)
            check(report, "consistency_hook", not hook.returncode, "Fixed consistency command completed; ongoing writes still require application-specific recovery verification.")
            if hook.returncode:
                return finish(env, report)
        if p.get("data_file"):
            file_hash = _checksum(e, p["namespace"], p)
            check(report, "source_file", bool(file_hash), "Read-only source file checksum captured in memory; file must remain stable during the drill.")
            if not file_hash:
                return finish(env, report)
        manifest = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": {LABEL: report["run"], "pod-security.kubernetes.io/enforce": "restricted"}}}
        created_ns = _create(e, manifest)
        if not created_ns:
            check(report, "destination", False, "Could not create unique isolated namespace; nothing was restored.")
            return finish(env, report)
        policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "cloudseed-deny-all", "namespace": ns, "labels": {LABEL: report["run"]}},
                  "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}}
        if not _create(e, policy):
            check(report, "destination", False, "Could not create deny-all networking; nothing was restored.")
            return finish(env, report)
        check(report, "destination", True, "Unique namespace with restricted Pod Security and deny-all ingress/egress created before restore.")
        spec = {"includedNamespaces": [p["namespace"]], "includedResources": RESOURCES, "includeClusterResources": False,
                "snapshotVolumes": False, "defaultVolumesToFsBackup": p["with_volumes"], "ttl": "24h0m0s"}
        if p["selector"]:
            spec["labelSelector"] = {"matchLabels": dict(part.split("=", 1) for part in p["selector"].split(","))}
        created_backup = _create(e, {"apiVersion": "velero.io/v1", "kind": "Backup", "metadata": {"name": backup, "namespace": "velero", "labels": {LABEL: report["run"]}}, "spec": spec})
        result = _wait(e, "backup.velero.io", backup, p["timeout_s"]) if created_backup else None
        ok = _complete(result)
        check(report, "backup", ok, "Velero backup reached Completed with zero errors." if ok else "Backup did not complete successfully; no restore started.")
        if not ok:
            return finish(env, report)
        if p["with_volumes"]:
            ok = _volume_ok(e, "podvolumebackups.velero.io", "velero.io/backup-name", backup)
            check(report, "volume_backup", ok, "File-system PodVolumeBackups must exist and all be Completed.")
            if not ok:
                return finish(env, report)
        # Detect application data changing during backup, instead of asserting equality against a stale pre-backup snapshot.
        if p["verify_data"]:
            after = _objects(e, p["namespace"], ["configmaps", "secrets"], p["selector"])
            stable = after is not None and _fingerprints(after) == source_data
            check(report, "stable_source_data", stable, "Selected ConfigMap/Secret values must stay stable while backing up.")
            if not stable:
                return finish(env, report)
        completion = (result or {}).get("status", {}).get("completionTimestamp", "")
        try:
            rpo = (datetime.now(timezone.utc) - datetime.fromisoformat(completion.replace("Z", "+00:00"))).total_seconds()
        except (ValueError, TypeError):
            rpo = None
        report["rpo_s"] = round(rpo, 3) if rpo is not None and rpo >= 0 else None
        check(report, "rpo", rpo is not None and 0 <= rpo <= p["rpo_seconds"], "Backup age at restore start must meet the configured RPO objective.")
        t0 = time.monotonic()
        rspec = {"backupName": backup, "includedNamespaces": [p["namespace"]], "namespaceMapping": {p["namespace"]: ns},
                 "includedResources": RESOURCES, "includeClusterResources": False, "restorePVs": False,
                 "existingResourcePolicy": "none"}
        created_restore = _create(e, {"apiVersion": "velero.io/v1", "kind": "Restore", "metadata": {"name": restore, "namespace": "velero", "labels": {LABEL: report["run"]}}, "spec": rspec})
        result = _wait(e, "restore.velero.io", restore, p["timeout_s"]) if created_restore else None
        restored = result is not None
        ok = _complete(result)
        check(report, "restore", ok, "Velero isolated restore reached Completed with zero errors." if ok else "Restore failed or timed out; inspect its Velero status.")
        if not ok:
            return finish(env, report)
        controllers = [i for i in items if i.get("kind") in ("Deployment", "StatefulSet")]
        ready = True
        for item in controllers:
            name = safe_name(item.get("metadata", {}).get("name"), "workload")
            resource = "deployment" if item["kind"] == "Deployment" else "statefulset"
            proc = kube(["rollout", "status", f"{resource}/{name}", "-n", ns, f"--timeout={p['timeout_s']}s"], e, p["timeout_s"] + 5)
            ready = ready and not proc.returncode
        check(report, "workload_ready", ready, "Every selected Deployment/StatefulSet must complete rollout in the isolated namespace.")
        if p["verify_data"]:
            restored_items = _objects(e, ns, ["configmaps", "secrets"], p["selector"])
            got = _fingerprints(restored_items or [])
            equal = bool(source_data) and all(got.get(k) == v for k, v in source_data.items())
            check(report, "data_equality", equal, "All selected ConfigMap/Secret application data must match (no values or hashes saved)." if source_data else "No ConfigMap/Secret data matched; data equality was not demonstrated.")
        if p["with_volumes"]:
            verified = _volume_ok(e, "podvolumerestores.velero.io", "velero.io/restore-name", restore)
            report["volume_verified"] = verified
            check(report, "volume_restore", verified, "Every file-system PodVolumeRestore must complete; optionally provide data_file for an application file checksum.")
        if p.get("data_file"):
            equal = _checksum(e, ns, p) == file_hash and _checksum(e, p["namespace"], p) == file_hash
            check(report, "file_checksum", equal, "Source and restored file SHA256 must match and source must remain stable; hashes are not retained.")
        elapsed = time.monotonic() - t0
        report["rto_s"] = round(elapsed, 3)
        check(report, "rto", elapsed <= p["rto_seconds"] and ready, "Restore plus verification elapsed time must meet the configured RTO objective.")
    except (OSError, ValueError, KeyError, TypeError, ui.Abort):
        check(report, "execution", False, "Recovery was interrupted by an unavailable dependency or malformed response; inspect cluster and Velero status. Raw output is omitted.")
    finally:
        if created_ns and not p["keep"]:
            try:
                _cleanup(e, report["run"], ns, backup if created_backup else None, restore if created_restore else None, restored or not created_restore, report)
            except (OSError, ValueError, KeyError, TypeError, ui.Abort):
                check(report, "cleanup", None, "Cleanup could not be confirmed; inspect the owned isolated namespace and Velero objects.")
        elif created_ns:
            check(report, "cleanup", True, "Owned isolated namespace and reports retained as requested; backup expires after 24h.")
        # Write again after cleanup even when a guarded return above produced an intermediate report.
        finish(env, report)
    return report
