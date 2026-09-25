"""Application recovery verifies isolation, checksums, phases and owned cleanup."""
import copy
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-operations-test-"))

from cloudseed import recovery as rec, paths, ui


def proc(value=None, rc=0):
    return subprocess.CompletedProcess([], rc, json.dumps(value) if value is not None else "", "")


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = paths.Env("aws", "test", workdir=self.tmp.name)
        self.env.create_dirs()
        self.cfg = {"cloud": "aws", "env": "test", "vars": {}}
        self.params = {"namespace": "shop", "selector": "app=shop", "approve": True, "isolation_reviewed": True, "verify_data": True}
        self.items = [
            {"kind": "Deployment", "metadata": {"name": "web", "labels": {"app": "shop"}}, "spec": {"template": {"spec": {"containers": [{"name": "app"}]}}}},
            {"kind": "Pod", "metadata": {"name": "web-abc", "labels": {"app": "shop"}}, "spec": {"containers": [{"name": "app"}]}},
            {"kind": "ConfigMap", "metadata": {"name": "settings", "labels": {"app": "shop"}}, "data": {"api": "secret-config"}},
            {"kind": "Secret", "metadata": {"name": "password", "labels": {"app": "shop"}}, "type": "Opaque", "data": {"password": "secret-base64-value"}}]
        self.calls, self.created = [], []
        self.labels = {}
        self.backup_phase = self.restore_phase = "Completed"
        self.mismatch = self.changed_source = False
        self.future_backup = False
        self.cleanup_error = False
        self.source_reads = 0

    def kubectl(self, args, e, *extra, **kw):
        self.calls.append(args)
        if args[0] == "create":
            obj = json.loads(kw["input"])
            self.created.append(obj)
            self.labels[(obj["kind"], obj["metadata"]["name"])] = obj["metadata"].get("labels", {})
            return proc(obj)
        if args[:2] == ["get", "daemonsets"]:
            return proc({"items": [{"spec": {"template": {"spec": {"containers": [{"name": "calico-node"}]}}}, "status": {"numberReady": 1, "desiredNumberScheduled": 1}}]})
        if args[:2] == ["get", "deployment"]:
            return proc({"status": {"availableReplicas": 1}})
        if args[:2] == ["get", "namespace"]:
            return proc({"metadata": {"uid": "namespace-uid", "labels": self.labels.get(("Namespace", args[2]), {})}})
        if args[:2] in (["get", "backup.velero.io"], ["get", "restore.velero.io"]):
            kind = "Backup" if args[1].startswith("backup") else "Restore"
            phase = self.backup_phase if kind == "Backup" else self.restore_phase
            return proc({"metadata": {"uid": "owned-uid", "labels": self.labels.get((kind, args[2]), {})}, "status": {"phase": phase, "errors": 0, "completionTimestamp": "2999-01-01T00:00:00+00:00" if self.future_backup else datetime.now(timezone.utc).isoformat()}})
        if args[0] == "get" and "-o" in args:
            namespace = args[args.index("-n") + 1]
            if "podvolumebackups" in args[1] or "podvolumerestores" in args[1]:
                return proc({"items": [{"status": {"phase": "Completed"}}]})
            if namespace == "shop":
                self.source_reads += 1
                items = copy.deepcopy(self.items)
                if self.changed_source and self.source_reads > 1:
                    items[-1]["data"]["password"] = "changed"
                return proc({"items": items})
            items = copy.deepcopy(self.items)
            if self.mismatch:
                items[-1]["data"]["password"] = "wrong"
            return proc({"items": items})
        if args[0] == "wait":
            return proc()
        if args[0] == "delete":
            return proc({}, 1 if self.cleanup_error else 0)
        if args[0] == "exec":
            if "sha256sum" in args:
                return subprocess.CompletedProcess([], 0, "a" * 64 + "  /data/token\n", "")
            return proc()
        if args[0] == "rollout":
            return proc()
        raise AssertionError(args)

    def run_drill(self, action="recovery-test", **changes):
        with patch.object(rec, "kube", side_effect=self.kubectl):
            return rec.execute(action, "aws", self.env, self.cfg, {**self.params, **changes})

    def test_plan_is_read_only_and_contains_coverage_limits(self):
        report = self.run_drill("recovery-plan")
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(self.created, [])
        self.assertFalse(any(c[0] in ("delete", "exec", "rollout") for c in self.calls))
        self.assertIn("same-cluster", " ".join(report["coverage_limits"]))

    def test_complete_restore_keeps_source_and_verifies_data(self):
        report = self.run_drill()
        self.assertEqual(report["verdict"], "PASS", report["checks"])
        self.assertEqual(report["exit_code"], 0)
        self.assertIsNotNone(report["rto_s"])
        self.assertIsNotNone(report["rpo_s"])
        self.assertEqual([c["kind"] for c in self.created[:4]], ["Namespace", "NetworkPolicy", "Backup", "Restore"])
        policy = self.created[1]
        self.assertEqual(policy["spec"]["policyTypes"], ["Ingress", "Egress"])
        self.assertEqual(policy["spec"]["egress"], [])
        restore = self.created[3]["spec"]
        self.assertEqual(restore["namespaceMapping"], {"shop": report["namespace"]})
        self.assertFalse(restore["includeClusterResources"])
        self.assertFalse(restore["restorePVs"])
        self.assertNotIn("services", restore["includedResources"])
        self.assertFalse(any(c[0] == "delete" and "shop" in c for c in self.calls))
        self.assertNotIn("secret-base64-value", Path(report["report"]).read_text())
        self.assertNotIn("secret-config", Path(report["report"]).read_text())
        self.assertEqual(self.created[-1]["kind"], "DeleteBackupRequest")

    def test_gke_anetd_is_recognized_only_when_every_agent_is_ready(self):
        original = self.kubectl
        for ready, expected in ((2, "PASS"), (1, "INCOMPLETE")):
            def kubectl(args, *a, **kw):
                if args[:2] == ["get", "daemonsets"]:
                    return proc({"items": [{"metadata": {"name": "anetd", "namespace": "kube-system", "labels": {"k8s-app": "cilium"}}, "status": {"numberReady": ready, "desiredNumberScheduled": 2}}]})
                return original(args, *a, **kw)
            with patch.object(rec, "kube", side_effect=kubectl):
                report = rec.execute("recovery-plan", "gcp", self.env, self.cfg, self.params)
            self.assertEqual(report["verdict"], expected)

    def test_namespace_and_restore_deletion_bind_uid_and_verify_completion(self):
        bodies = []
        original = self.kubectl
        def kubectl(args, *a, **kw):
            if args[0] == "delete":
                bodies.append((args, json.loads(kw["input"])))
            return original(args, *a, **kw)
        with patch.object(rec, "kube", side_effect=kubectl):
            report = rec.execute("recovery-test", "aws", self.env, self.cfg, self.params)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual([body["preconditions"]["uid"] for _, body in bodies], ["namespace-uid", "owned-uid"])
        self.assertTrue(all("--raw=" in args[1] for args, _ in bodies))
        self.assertTrue(any(a[0] == "wait" and "namespace/" + report["namespace"] in a for a in self.calls))
        self.assertTrue(any(a[0] == "wait" and "backup.velero.io/" + report["backup"] in a for a in self.calls))

    def test_missing_isolation_attestation_blocks_all_writes(self):
        report = self.run_drill(isolation_reviewed=False)
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertFalse(self.created)

    def test_existing_velero_hooks_and_privileged_pods_refused(self):
        for field in ("hooks", "hostNetwork", "privileged"):
            original = copy.deepcopy(self.items)
            if field == "hooks":
                self.items[1]["metadata"]["annotations"] = {"pre.hook.backup.velero.io/command": '["sh","-c","bad"]'}
            elif field == "hostNetwork":
                self.items[1]["spec"]["hostNetwork"] = True
            else:
                self.items[1]["spec"]["containers"][0]["securityContext"] = {"privileged": True}
            report = self.run_drill()
            self.assertEqual(report["verdict"], "FAIL", field)
            self.assertFalse(self.created)
            self.items = original

    def test_failed_or_partial_backup_never_restores(self):
        for phase in ("Failed", "PartiallyFailed"):
            self.backup_phase = phase
            self.created.clear()
            report = self.run_drill()
            self.assertEqual(report["verdict"], "FAIL")
            self.assertFalse(any(c["kind"] == "Restore" for c in self.created))

    def test_mismatched_or_changing_data_fails(self):
        self.mismatch = True
        self.assertEqual(self.run_drill()["verdict"], "FAIL")
        self.mismatch, self.changed_source = False, True
        self.created.clear()
        self.source_reads = 0
        report = self.run_drill()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertFalse(any(c["kind"] == "Restore" for c in self.created))

    def test_future_backup_timestamp_never_proves_rpo(self):
        self.future_backup = True
        report = self.run_drill()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIsNone(report["rpo_s"])

    def test_inflight_restore_namespace_is_not_deleted(self):
        with patch.object(rec, "_wait", side_effect=[{"status": {"phase": "Completed", "completionTimestamp": datetime.now(timezone.utc).isoformat()}}, None]):
            report = self.run_drill()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertFalse(any(c[0] == "delete" for c in self.calls))
        self.assertIn("completion is unknown", next(c["detail"] for c in report["checks"] if c["id"] == "cleanup"))

    def test_keep_skips_cleanup_but_preserves_expiry(self):
        report = self.run_drill(keep=True)
        self.assertEqual(report["verdict"], "PASS")
        self.assertFalse(any(c[0] == "delete" for c in self.calls))
        backup = next(c for c in self.created if c["kind"] == "Backup")
        self.assertEqual(backup["spec"]["ttl"], "24h0m0s")

    def test_cleanup_failure_affects_final_saved_verdict(self):
        self.cleanup_error = True
        report = self.run_drill()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(json.loads(Path(report["report"]).read_text())["verdict"], "FAIL")

    def test_volume_opt_in_and_completed_volume_operations(self):
        self.items.append({"kind": "PersistentVolumeClaim", "metadata": {"name": "data"}, "spec": {"storageClassName": "standard"}, "status": {"phase": "Bound"}})
        self.assertEqual(self.run_drill()["verdict"], "FAIL")
        self.assertFalse(self.created)
        report = self.run_drill(with_volumes=True)
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(report["volume_verified"])
        backup = next(c for c in self.created if c["kind"] == "Backup")
        self.assertTrue(backup["spec"]["defaultVolumesToFsBackup"])
        self.assertFalse(backup["spec"]["snapshotVolumes"])

    def test_only_fixed_consistency_hooks_and_checksum_commands(self):
        report = self.run_drill(consistency_hook="postgres-checkpoint", pod="web-abc", container="app", data_file="/data/token")
        self.assertEqual(report["verdict"], "PASS", report["checks"])
        execs = [c[c.index("--") + 1:] for c in self.calls if c[0] == "exec"]
        self.assertEqual(execs[0], ["psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres", "-c", "CHECKPOINT"])
        self.assertEqual(execs[1], ["sha256sum", "--", "/data/token"])
        self.assertNotIn("a" * 64, json.dumps(report))
        with self.assertRaises(ui.Abort):
            self.run_drill(consistency_hook="sh -c evil")

    def test_invalid_names_paths_flags_and_unselected_hook_pods(self):
        for args in ({"namespace": "kube-system"}, {"namespace": "default"}, {"namespace": "--all"}, {"selector": "x;curl=bad"},
                     {"verify_data": "true"}, {"timeout_s": True}, {"data_file": "/tmp/../secret", "pod": "web-abc", "container": "app"}):
            with self.subTest(args=args), self.assertRaises(ui.Abort):
                self.run_drill(**args)
        report = self.run_drill(consistency_hook="filesystem-sync", pod="unselected", container="app")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertFalse(self.created)

    def test_approval_required_before_any_cluster_access(self):
        with self.assertRaises(ui.Abort):
            self.run_drill(approve=False)
        self.assertEqual(self.calls, [])

    def test_cleanup_refuses_foreign_namespace_and_backup(self):
        report = {"checks": []}
        with patch.object(rec, "kube", return_value=proc({"metadata": {"labels": {rec.LABEL: "someone-else"}}})) as kube:
            rec._cleanup({}, "mine", "clone", "backup", "restore", True, report)
        self.assertFalse(any(c.args[0][0] in ("delete", "create") for c in kube.call_args_list))
        self.assertEqual(report["checks"][0]["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
