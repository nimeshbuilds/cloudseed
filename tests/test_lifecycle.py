"""Lifecycle safety gates, provider commands, and bounded real subprocess tests."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-operations-test-"))

from cloudseed import lifecycle as lc, paths, ui


def proc(value=None, rc=0):
    return subprocess.CompletedProcess([], rc, json.dumps(value) if value is not None else "", "")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = paths.Env("aws", "test", workdir=self.tmp.name)
        self.env.create_dirs()
        self.cfg = {"cloud": "aws", "env": "test", "name": "demo", "region": "us-east-1", "vars": {}}
        self.params = {"target_version": "1.36", "compatibility_reviewed": True, "backup": "daily"}
        self.outputs = {"kubernetes_cluster_name": "demo-test", "kubernetes_node_group_name": "main", "kubernetes_endpoint": "https://cluster.example.test"}
        (self.env.dir / "outputs.json").write_text(json.dumps(self.outputs))
        (self.env.stack_dir / "main.tf.json").write_text('{"module":{"stack":{}}}')
        self.nodes = {"items": [{"metadata": {"name": "node1"}, "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.35.4"}}}]}

    def kubectl(self, args, *a, **kw):
        if args[:1] == ["config"]:
            return proc({"clusters": [{"cluster": {"server": "https://cluster.example.test", "certificate-authority-data": "Q0E="}}]})
        if args[:1] == ["version"]:
            return proc({"serverVersion": {"gitVersion": "v1.35.4"}})
        if args[:2] == ["get", "namespace"]:
            return proc({"metadata": {"uid": "cluster-123"}})
        if args[:2] == ["get", "nodes"]:
            return proc(self.nodes)
        if args[:2] in (["get", "pods"], ["get", "pdb"]):
            return proc({"items": []})
        if args[:2] == ["get", "backup.velero.io"]:
            return proc({"status": {"phase": "Completed", "errors": 0, "completionTimestamp": datetime.now(timezone.utc).isoformat()}})
        if args[:2] == ["get", "--raw"]:
            return proc()
        raise AssertionError(args)

    def provider(self, tool, args, *a, **kw):
        if args[:2] == ["state", "pull"]:
            return proc({"serial": 1, "lineage": "state"})
        if "describe-cluster" in args:
            return proc({"cluster": {"endpoint": "https://cluster.example.test", "arn": "cluster-arn", "certificateAuthority": {"data": "Q0E="}}})
        if "describe-cluster-versions" in args:
            return proc({"clusterVersions": [{"clusterVersion": "1.36", "versionStatus": "STANDARD_SUPPORT"}]})
        raise AssertionError((tool, args))

    def plan(self, **changes):
        with patch.object(lc, "kube", side_effect=self.kubectl), patch.object(lc, "command", side_effect=self.provider):
            return lc.execute("upgrade-plan", "aws", self.env, self.cfg, {**self.params, **changes})

    def test_plan_serializes_secret_safe_reviewable_identity(self):
        self.cfg["secret"] = "NEVER_REPORT_ME"
        report = self.plan()
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["current_version"], "v1.35.4")
        self.assertNotIn("NEVER_REPORT_ME", Path(report["report"]).read_text())
        self.assertEqual(lc._load_plan(self.env, report["report"])["target_version"], "1.36")
        self.assertEqual(Path(report["report"]).stat().st_mode & 0o777, 0o600)

    def test_missing_compatibility_review_is_incomplete(self):
        result = self.plan(compatibility_reviewed=False)
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertEqual(result["exit_code"], 3)

    def test_downgrade_minor_skip_and_invalid_version_rejected(self):
        for version in ("1.34", "1.37"):
            with self.subTest(version=version):
                self.assertEqual(self.plan(target_version=version)["verdict"], "FAIL")
        for version in ("1.36;touch /tmp/oops", "latest", True):
            with self.assertRaises(ui.Abort):
                self.plan(target_version=version)

    def test_blocked_pdb_prevents_apply(self):
        original = self.kubectl
        def run(args, *a, **kw):
            if args[:2] == ["get", "pdb"]:
                return proc({"items": [{"status": {"expectedPods": 1, "disruptionsAllowed": 0}}]})
            return original(args, *a, **kw)
        with patch.object(lc, "kube", side_effect=run), patch.object(lc, "command", side_effect=self.provider):
            report = lc.upgrade_plan("aws", self.env, self.cfg, self.params)
        self.assertEqual(report["verdict"], "FAIL")
        with patch.object(lc, "_managed_upgrade") as mutate:
            result = lc.upgrade_apply("aws", self.env, self.cfg, {"approve": True, "plan": report["report"]})
        mutate.assert_not_called()
        self.assertEqual(result["verdict"], "FAIL")

    def test_deprecated_api_removed_at_target_blocks(self):
        original = self.kubectl
        def run(args, *a, **kw):
            if args[:2] == ["get", "--raw"]:
                return subprocess.CompletedProcess([], 0, 'apiserver_requested_deprecated_apis{removed_release="1.36",resource="old"} 1\n', "")
            return original(args, *a, **kw)
        with patch.object(lc, "kube", side_effect=run), patch.object(lc, "command", side_effect=self.provider):
            report = lc.upgrade_plan("aws", self.env, self.cfg, self.params)
        self.assertEqual(next(c["status"] for c in report["checks"] if c["id"] == "deprecated_apis"), "FAIL")

    def test_stale_config_state_or_cluster_never_mutates(self):
        report = self.plan()
        for change in ("config", "state", "cluster"):
            cfg = copy.deepcopy(self.cfg)
            if change == "config":
                cfg["region"] = "us-west-2"
            def state(tool, args, *a, **kw):
                if args[:2] == ["state", "pull"] and change == "state":
                    return proc({"serial": 2, "lineage": "state"})
                return self.provider(tool, args, *a, **kw)
            def kubectl(args, *a, **kw):
                if args[:2] == ["get", "namespace"] and change == "cluster":
                    return proc({"metadata": {"uid": "other"}})
                return self.kubectl(args, *a, **kw)
            with patch.object(lc, "kube", side_effect=kubectl), patch.object(lc, "command", side_effect=state), patch.object(lc, "_managed_upgrade") as mutate:
                result = lc.upgrade_apply("aws", self.env, cfg, {"approve": True, "plan": report["report"]})
            mutate.assert_not_called()
            self.assertEqual(result["verdict"], "FAIL", change)

    def test_changed_rendered_terraform_invalidates_plan(self):
        plan = self.plan()
        (self.env.stack_dir / "extra.tf").write_text('locals { operator_change = true }')
        with patch.object(lc, "_managed_upgrade") as mutate:
            result = lc.upgrade_apply("aws", self.env, self.cfg, {"approve": True, "plan": plan["report"]})
        mutate.assert_not_called()
        self.assertEqual(result["verdict"], "FAIL")

    def test_approval_and_tampered_plan_refused(self):
        report = self.plan()
        with self.assertRaises(ui.Abort):
            lc.upgrade_apply("aws", self.env, self.cfg, {"plan": report["report"]})
        saved = json.loads(Path(report["report"]).read_text())
        saved["target_version"] = "1.37"
        Path(report["report"]).write_text(json.dumps(saved))
        with self.assertRaises(ui.Abort):
            lc._load_plan(self.env, report["report"])

    def test_foreign_and_symlink_plan_refused(self):
        with self.assertRaises(ui.Abort):
            lc._load_plan(self.env, "/tmp/upgrade-plan-" + "f" * 32 + ".json")
        report = self.plan()
        alias = Path(report["report"]).with_name("upgrade-plan-" + "f" * 32 + ".json")
        alias.symlink_to(report["report"])
        with self.assertRaises(ui.Abort):
            lc._load_plan(self.env, str(alias))

    def test_eks_upgrade_waits_between_controlplane_and_nodes(self):
        events = []
        def run(tool, args, *a, **kw):
            events.append(args)
            return proc({"update": {"id": "update-123", "status": "Successful"}})
        report = lc._report("upgrade-apply", "aws", self.env)
        with patch.object(lc, "command", side_effect=run):
            self.assertTrue(lc._managed_upgrade("aws", self.env, self.cfg, "1.36", {}, 1, report))
        self.assertEqual([e[1] for e in events], ["update-cluster-version", "describe-update", "update-nodegroup-version", "describe-update"])
        self.assertFalse(any("--force" in a for a in events))
        self.assertIn("--nodegroup-name", events[-1])

    def test_eks_failure_stops_before_nodes(self):
        calls = []
        def run(tool, args, *a, **kw):
            calls.append(args)
            return proc({"update": {"id": "update-123", "status": "Failed"}})
        with patch.object(lc, "command", side_effect=run):
            self.assertFalse(lc._managed_upgrade("aws", self.env, self.cfg, "1.36", {}, 1, lc._report("upgrade-apply", "aws", self.env)))
        self.assertEqual(len(calls), 2)

    def test_gke_and_aks_commands_pin_scope_and_version(self):
        outputs = {**self.outputs, "kubernetes_location": "us-central1-a", "kubernetes_node_pool": "pool", "resource_group_name": "rg"}
        (self.env.dir / "outputs.json").write_text(json.dumps(outputs))
        cfg = {"vars": {"project_id": "project-id", "subscription_id": "12345678-1234-1234-1234-123456789abc"}}
        for cloud, expected in (("gcp", 2), ("azure", 1)):
            with patch.object(lc, "command", return_value=proc({})) as run:
                self.assertTrue(lc._managed_upgrade(cloud, self.env, cfg, "1.36.4", {}, 1, lc._report("upgrade-apply", cloud, self.env)))
            self.assertEqual(run.call_count, expected)
            self.assertTrue(all("1.36.4" in c.args[1] for c in run.call_args_list))
            self.assertIn("--project" if cloud == "gcp" else "--subscription", run.call_args.args[1])

    def test_drift_distinguishes_intent_without_leaking_values(self):
        calls = []
        def run(tool, args, *a, **kw):
            calls.append(args)
            if args[0] == "plan":
                return proc({}, 2)
            field = "resource_drift" if len(calls) == 2 else "resource_changes"
            return proc({field: [{"address": 'aws_instance.foo["secret-key"]', "type": "aws_instance", "change": {"actions": ["update"], "before": {"password": "secret-value"}}}]})
        with patch.object(lc, "command", side_effect=run):
            report = lc.drift("aws", self.env, self.cfg, {})
        self.assertEqual(report["drift"]["count"], 1)
        self.assertEqual(report["intent"]["count"], 1)
        self.assertIn("-refresh-only", calls[0])
        self.assertIn("-refresh=false", calls[2])
        self.assertNotIn("secret", json.dumps(report))
        self.assertFalse(any("apply" in c for c in calls))

    def test_drift_unavailable_is_unknown_not_clean(self):
        with patch.object(lc, "command", return_value=proc({}, 124)):
            report = lc.drift("aws", self.env, self.cfg, {})
        self.assertEqual(report["verdict"], "INCOMPLETE")

    def test_no_environment_kubeconfig_never_uses_default(self):
        with patch.object(lc, "command") as command:
            result = lc.kube(["get", "nodes"], {"KUBECONFIG": str(self.env.dir / "missing")})
        command.assert_not_called()
        self.assertEqual(result.returncode, 127)

    def test_kubectl_timeout_flag_precedes_exec_separator(self):
        path = self.env.dir / "kubeconfig"
        path.write_text("x")
        with patch.object(lc, "command", return_value=proc()) as command:
            lc.kube(["exec", "pod", "--", "sync"], {"KUBECONFIG": str(path)})
        self.assertEqual(command.call_args.args[1][-2:], ["--", "sync"])

    def test_bounded_subprocess_success_timeout_and_overflow(self):
        good = lc.bounded_run([sys.executable, "-c", "print('hello')"], timeout=2)
        self.assertEqual((good.returncode, good.stdout.strip()), (0, "hello"))
        slow = lc.bounded_run([sys.executable, "-c", "import time;time.sleep(10)"], timeout=.1)
        self.assertEqual(slow.returncode, 124)
        with patch.object(lc, "LIMIT", 1000):
            huge = lc.bounded_run([sys.executable, "-c", "import sys;sys.stdout.write('x'*100000)"], timeout=2)
        self.assertEqual(huge.returncode, 125)
        self.assertLessEqual(len(huge.stdout) + len(huge.stderr), 1000)

    def test_rke2_no_force_drain_and_failed_node_stays_cordoned(self):
        outputs = {"kubernetes_control_plane_ips": ["10.1.0.10"], "kubernetes_worker_ips": []}
        (self.env.dir / "outputs.json").write_text(json.dumps(outputs))
        node = {"metadata": {"name": "cp1"}, "status": {"addresses": [{"type": "InternalIP", "address": "10.1.0.10"}]}}
        calls = []
        def kube(args, *a, **kw):
            calls.append(args)
            if args[:2] == ["get", "nodes"]:
                return proc({"items": [node]})
            return proc({}, 1)
        with patch.object(lc, "kube", side_effect=kube), patch.object(lc, "bounded_run", return_value=proc()) as run:
            self.assertFalse(lc._rke2_upgrade("vmware", self.env, {"vars": {}, "ssh_public_key": ""}, "v1.36.4+rke2r1", {}, 1, lc._report("upgrade-apply", "vmware", self.env)))
        self.assertEqual(run.call_count, 1)  # etcd snapshot only; failed drain prevents installation
        self.assertIn("drain", calls[-1])
        self.assertNotIn("--force", calls[-1])
        self.assertFalse(any("uncordon" in c for c in calls))

    def test_same_patch_provider_builds_order_forward_and_back(self):
        self.assertGreater(lc._version_order("1.35.6-gke.1962000"), lc._version_order("v1.35.6-gke.1307000", server=True))
        self.assertGreater(lc._version_order("v1.35.6+rke2r2"), lc._version_order("v1.35.6+rke2r1", server=True))
        self.assertLess(lc._version_order("v1.35.6+rke2r1"), lc._version_order("v1.35.6+rke2r2", server=True))
        self.assertEqual(lc._version_order("v1.35.6-eks-abcd", server=True)[:3], (1, 35, 6))

    def test_same_private_endpoint_different_certificate_authority_refused(self):
        original = self.provider
        def run(tool, args, *a, **kw):
            if "describe-cluster" in args:
                return proc({"cluster": {"endpoint": "https://cluster.example.test", "certificateAuthority": {"data": "T1RIRVI="}}})
            return original(tool, args, *a, **kw)
        with patch.object(lc, "kube", side_effect=self.kubectl), patch.object(lc, "command", side_effect=run):
            report = lc.upgrade_plan("aws", self.env, self.cfg, self.params)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIsNone(report["provider_identity_hash"])

    def test_provider_endpoint_mismatch_blocks_before_mutation(self):
        original = self.provider
        def run(tool, args, *a, **kw):
            if "describe-cluster" in args:
                return proc({"cluster": {"endpoint": "https://wrong-account-cluster.example.test"}})
            return original(tool, args, *a, **kw)
        with patch.object(lc, "kube", side_effect=self.kubectl), patch.object(lc, "command", side_effect=run):
            report = lc.upgrade_plan("aws", self.env, self.cfg, self.params)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIsNone(report["provider_identity_hash"])

    def test_failed_provider_upgrade_leaves_reviewed_target_pinned(self):
        plan = self.plan()
        def fail(*args):
            lc.check(args[-1], "provider", False, "Simulated failed update")
            return False
        with patch.object(lc, "kube", side_effect=self.kubectl), patch.object(lc, "command", side_effect=self.provider), patch.object(lc, "_managed_upgrade", side_effect=fail):
            report = lc.upgrade_apply("aws", self.env, self.cfg, {"approve": True, "plan": plan["report"]})
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(self.env.load()["extra_vars"]["kubernetes_version"], "1.36")
        self.assertEqual(json.loads((self.env.stack_dir / "main.tf.json").read_text())["module"]["stack"]["kubernetes_version"], "1.36")

    def test_rke2_and_kubeadm_serial_runner_validates_shell_and_gates_each_node(self):
        outputs = {"kubernetes_control_plane_ips": ["10.1.0.10"], "kubernetes_worker_ips": ["10.1.0.11"]}
        (self.env.dir / "outputs.json").write_text(json.dumps(outputs))
        for distro, runner, target in (("rke2", lc._rke2_upgrade, "v1.36.4+rke2r1"), ("kubeadm", lc._kubeadm_upgrade, "v1.36.4")):
            calls, scripts = [], []
            nodes = [{"metadata": {"name": name}, "status": {"addresses": [{"type": "InternalIP", "address": ip}], "nodeInfo": {"kubeletVersion": target}, "conditions": [{"type": "Ready", "status": "True"}]}}
                     for name, ip in (("cp1", "10.1.0.10"), ("wk1", "10.1.0.11"))]
            def kube(args, *a, **kw):
                calls.append(args)
                if args[:2] == ["get", "nodes"]:
                    return proc({"items": nodes})
                if args[:2] == ["get", "node"]:
                    return proc(next(n for n in nodes if n["metadata"]["name"] == args[2]))
                return proc()
            def run(argv, **kw):
                if kw.get("input"):
                    script = kw["input"]
                    scripts.append(script)
                    self.assertEqual(subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode, 0)
                return proc()
            report = lc._report("upgrade-apply", "vmware", self.env)
            report["kubeadm_package_version"] = "1.36.4-1.1"
            with patch.object(lc, "kube", side_effect=kube), patch.object(lc, "bounded_run", side_effect=run):
                self.assertTrue(runner("vmware", self.env, {"vars": {}, "ssh_public_key": ""}, target, {}, 1, report), distro)
            self.assertEqual([(a[0], a[1]) for a in calls if a[0] in ("drain", "uncordon")], [("drain", "cp1"), ("uncordon", "cp1"), ("drain", "wk1"), ("uncordon", "wk1")])
            self.assertEqual(len(scripts), 2)
            if distro == "rke2":
                self.assertTrue(all("sha256sum -c selected" in s and "%2B" in s for s in scripts))
            else:
                self.assertIn("upgrade apply v1.36.4 --yes", scripts[0])
                self.assertIn("upgrade node", scripts[1])
                self.assertTrue(all("kubelet=1.36.4-1.1" in s and "apt-mark hold" in s for s in scripts))
                self.assertFalse(any("--allow-unauthenticated" in s for s in scripts))

    def test_post_upgrade_stale_kubelet_fails_even_when_ready(self):
        plan = self.plan()
        post = [False]
        def runner(*args):
            post[0] = True
            return True
        def kubectl(args, *a, **kw):
            if post[0] and args[0] == "version":
                return proc({"serverVersion": {"gitVersion": "v1.36.4"}})
            if args[:2] == ["get", "deployments,statefulsets,daemonsets"]:
                return proc({"items": []})
            return self.kubectl(args, *a, **kw)
        with patch.object(lc, "kube", side_effect=kubectl), patch.object(lc, "command", side_effect=self.provider), patch.object(lc, "_managed_upgrade", side_effect=runner):
            report = lc.upgrade_apply("aws", self.env, self.cfg, {"approve": True, "plan": plan["report"]})
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(next(c["status"] for c in report["checks"] if c["id"] == "post_upgrade"), "FAIL")


if __name__ == "__main__":
    unittest.main()
