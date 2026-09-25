"""Diagnostics distinguish checked evidence from declarations and own every active probe resource."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cloudseed import health, ui


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = SimpleNamespace(dir=Path(self.tmp.name), id="aws-test", name="test")
        self.cfg = {"vars": {"enable_kubernetes": True}}

    def execute(self, action="health", **params):
        return health.execute(action, "aws", self.env, self.cfg, params)

    def finding(self, report, id_):
        return next(f for f in report["findings"] if f["id"] == id_)

    def kubeconfig(self):
        kc = self.env.dir / "k8s" / "kubeconfig"
        kc.parent.mkdir()
        kc.write_text("apiVersion: v1\n")
        return kc

    def test_every_cloud_offline_is_read_only_and_honestly_incomplete(self):
        before = copy.deepcopy(self.cfg)
        with mock.patch("subprocess.Popen", side_effect=AssertionError("no child")), \
                mock.patch("socket.socket", side_effect=AssertionError("no network")):
            for cloud in ("aws", "gcp", "azure", "vmware"):
                for action in ("health", "network"):
                    result = health.execute(action, cloud, self.env, self.cfg, {})
                    self.assertEqual(result["verdict"], "INCOMPLETE")
                    self.assertFalse(any(f["status"] == "PASS" for f in result["findings"]))
                    json.dumps(result, allow_nan=False)
        self.assertEqual(self.cfg, before)
        self.assertEqual(list(self.env.dir.iterdir()), [])

    def test_rejects_invalid_and_ambiguous_options_before_calls(self):
        cases = ({"active": True}, {"live": "yes"}, {"active": 1}, {"timeout": True}, {"timeout": 4}, {"timeout": 301},
                 {"max_age_days": 0}, {"endpoints": []}, {"endpoints": ["https://user:secret@example.com/"]},
                 {"endpoints": ["http://example.com/"]}, {"endpoints": ["https://example.com/?token=secret"]},
                 {"endpoints": ["https://169.254.169.254/"]}, {"endpoints": ["https://localhost/"]},
                 {"endpoints": ["https://example.com:444/"]}, {"endpoints": ["https://metadata.google.internal/"]})
        with mock.patch.object(health, "_run", side_effect=AssertionError("no child")):
            for params in cases:
                with self.subTest(params=params), self.assertRaises(ui.Abort):
                    self.execute(**params)

    def test_missing_local_tool_or_kubeconfig_never_uses_global_context(self):
        with mock.patch.object(health.deps, "find", return_value="/mock/kubectl"), \
                mock.patch.object(health, "_run", side_effect=AssertionError("no child")):
            report = self.execute(live=True)
        self.assertEqual(self.finding(report, "cluster.nodes")["status"], "UNKNOWN")
        self.assertEqual(list(self.env.dir.iterdir()), [])

    def test_symlinked_kubeconfig_refused(self):
        kc = self.kubeconfig()
        kc.unlink()
        kc.symlink_to(self.env.dir / "other")
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run") as runner:
            self.execute(live=True)
        runner.assert_not_called()

    def test_disabled_cluster_skips_even_requested_active_probes(self):
        self.cfg["vars"]["enable_kubernetes"] = False
        with mock.patch.object(health, "_run") as runner:
            report = self.execute(live=True, active=True)
        self.assertEqual(self.finding(report, "cluster.api")["status"], "NOT_APPLICABLE")
        runner.assert_not_called()

    def live_runner(self, argv, **kwargs):
        self.assertEqual(argv[:3], ["/mock/kubectl", "--kubeconfig", str(self.env.dir / "k8s" / "kubeconfig")])
        self.assertEqual(kwargs["env"]["KUBECONFIG"], str(self.env.dir / "k8s" / "kubeconfig"))
        if "--raw=/readyz" in argv:
            return subprocess.CompletedProcess(argv, 0, "ok", "")
        now = datetime.now(timezone.utc)
        responses = {
            "nodes": {"items": [{"status": {"conditions": [{"type": "Ready", "status": "True"}]}}]},
            "deployments": {"items": [{"spec": {"replicas": 2}, "status": {"availableReplicas": 2, "observedGeneration": 2}, "metadata": {"generation": 2}}]},
            "certificates.cert-manager.io": {"items": [{"status": {"notAfter": (now + timedelta(days=60)).isoformat()}}]},
            "backups.velero.io": {"items": [{"status": {"phase": "Completed", "completionTimestamp": now.isoformat()}}]},
        }
        kind = argv[argv.index("get") + 1]
        return subprocess.CompletedProcess(argv, 0, json.dumps(responses[kind]), "")

    def test_live_queries_are_bounded_scoped_and_do_not_imply_network_success(self):
        self.kubeconfig()
        with mock.patch.object(health.deps, "find", return_value="/mock/kubectl"), \
                mock.patch.object(health, "_run", side_effect=self.live_runner) as run:
            report = self.execute(live=True)
        for id_ in ("cluster.api", "cluster.nodes", "cluster.platform", "cluster.certificates", "cluster.backups"):
            self.assertEqual(self.finding(report, id_)["status"], "PASS", id_)
        self.assertEqual(self.finding(report, "network.registry")["status"], "UNKNOWN")
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertTrue(all(c.kwargs["timeout"] <= 32 for c in run.call_args_list))
        self.assertEqual(list(self.env.dir.iterdir()), [self.env.dir / "k8s"])

    def test_failed_query_invalid_json_and_partial_api_results_stay_unknown(self):
        self.kubeconfig()
        for rc, text in ((1, "secret-password"), (0, "not JSON"), (0, "[]"), (0, "{}")):
            with self.subTest(rc=rc, text=text), mock.patch.object(health.deps, "find", return_value="kubectl"), \
                    mock.patch.object(health, "_run", return_value=subprocess.CompletedProcess([], rc, text, "secret-password")):
                report = self.execute(live=True)
                self.assertEqual(self.finding(report, "cluster.nodes")["status"], "UNKNOWN")
                self.assertNotIn("secret-password", json.dumps(report))

    def test_known_unhealthy_nodes_deployments_certificates_and_old_backups_fail(self):
        self.kubeconfig()
        now = datetime.now(timezone.utc)
        def run(argv, **kwargs):
            items = {"nodes": [{"status": {"conditions": [{"type": "Ready", "status": "False"}]}}],
                     "deployments": [{"spec": {"replicas": 2}, "status": {"availableReplicas": 1}}],
                     "certificates.cert-manager.io": [{"status": {"notAfter": (now - timedelta(days=1)).isoformat()}}],
                     "backups.velero.io": [{"status": {"phase": "Completed", "completionTimestamp": (now - timedelta(days=2)).isoformat()}}]}
            return subprocess.CompletedProcess(argv, 0, json.dumps({"items": items.get(argv[argv.index("get") + 1], [])}), "")
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=run):
            report = self.execute(live=True)
        self.assertEqual(report["verdict"], "FAIL")
        for id_ in ("cluster.nodes", "cluster.platform", "cluster.certificates", "cluster.backups"):
            self.assertEqual(self.finding(report, id_)["status"], "FAIL")

    def active_runner(self, *, dns_ok=True, foreign=False, lost_create=False, cleanup_fails=False):
        state = {"namespace": None, "pod": None, "deleted": False, "delete_options": None}
        def run(argv, **kwargs):
            code, out = 0, {}
            if "--raw=/readyz" in argv:
                return subprocess.CompletedProcess(argv, 0, "ok", "")
            if "create" in argv:
                obj = json.loads(kwargs["input"])
                if obj["kind"] == "Namespace":
                    state["namespace"] = obj
                    obj["metadata"]["uid"] = "owned-uid"
                    out = obj
                    if lost_create:
                        code = 124
                else:
                    state["pod"] = obj
                    out = obj
            elif "get" in argv and "namespace" in argv:
                out = copy.deepcopy(state["namespace"])
                if foreign:
                    out["metadata"]["labels"][health.OWNER_LABEL] = "someone-else"
            elif "get" in argv and "pod" in argv:
                out = {"status": {"containerStatuses": [{"imageID": "containerd://sha256:123"}]}}
            elif "logs" in argv:
                out = {"results": [{"check": "dns", "ok": dns_ok},
                                   *[{"check": "https", "ok": True, "endpoint": x, "http_status": 401} for x in health.DEFAULT_ENDPOINTS]]}
            elif "delete" in argv:
                state["deleted"] = True
                state["delete_options"] = json.loads(kwargs["input"])
                if cleanup_fails:
                    code = 1
            return subprocess.CompletedProcess(argv, code, json.dumps(out), "")
        return run, state

    def test_active_probe_is_restricted_and_uid_owned_cleanup_is_verified(self):
        self.kubeconfig()
        runner, state = self.active_runner()
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=runner):
            report = self.execute("network", live=True, active=True)
        for id_ in ("network.registry", "network.dns", "network.tls.1", "network.tls.2", "network.cleanup"):
            self.assertEqual(self.finding(report, id_)["status"], "PASS")
        pod = state["pod"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(pod["containers"][0]["imagePullPolicy"], "Always")
        self.assertEqual(state["delete_options"]["preconditions"], {"uid": "owned-uid"})
        manifest = next((self.env.dir / "operations").glob("*.json"))
        self.assertEqual(json.loads(manifest.read_text())["cleanup"], "complete")
        self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)

    def test_active_failure_reports_fail_and_still_cleans(self):
        self.kubeconfig()
        runner, state = self.active_runner(dns_ok=False)
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=runner):
            report = self.execute("network", live=True, active=True)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(state["deleted"])

    def test_never_deletes_a_namespace_with_different_ownership(self):
        self.kubeconfig()
        runner, state = self.active_runner(foreign=True)
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=runner):
            report = self.execute("network", live=True, active=True)
        self.assertFalse(state["deleted"])
        self.assertEqual(self.finding(report, "network.cleanup")["status"], "UNKNOWN")

    def test_lost_create_response_recovers_only_owned_namespace_and_starts_no_pod(self):
        self.kubeconfig()
        runner, state = self.active_runner(lost_create=True)
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=runner):
            report = self.execute("network", live=True, active=True)
        self.assertIsNone(state["pod"])
        self.assertTrue(state["deleted"])
        self.assertEqual(self.finding(report, "network.probe")["status"], "UNKNOWN")

    def test_cleanup_failure_is_not_reported_as_success(self):
        self.kubeconfig()
        runner, _ = self.active_runner(cleanup_fails=True)
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=runner):
            report = self.execute("network", live=True, active=True)
        self.assertEqual(self.finding(report, "network.cleanup")["status"], "UNKNOWN")

    def test_probe_code_does_not_follow_redirects_or_include_credentials(self):
        compile(health.PROBE_CODE, "probe", "exec")
        self.assertIn("class NoRedirect", health.PROBE_CODE)
        self.assertIn("opener.open(endpoint", health.PROBE_CODE)
        self.assertIn("ipaddress.ip_address(x[4][0]).is_global", health.PROBE_CODE)

    @unittest.skipIf(os.name != "posix", "POSIX graceful process-group interrupt")
    def test_mutating_child_gets_graceful_interrupt_before_forced_cleanup(self):
        command = "import signal,time,sys; signal.signal(signal.SIGINT, lambda *a: (print('state saved',flush=True),sys.exit(0))); print('ready',flush=True); time.sleep(30)"
        timed = health._run([sys.executable, "-c", command], timeout=2, graceful=True)
        self.assertEqual(timed.returncode, 124)
        self.assertIn("state saved", timed.stdout)

    def test_real_subprocess_timeout_and_output_are_bounded(self):
        timed = health._run([sys.executable, "-c", "import time; time.sleep(3)"], timeout=0.1)
        self.assertEqual(timed.returncode, 124)
        with mock.patch.object(health, "MAX_OUTPUT", 4096):
            huge = health._run([sys.executable, "-c", "import sys; sys.stdout.write('x'*100000);sys.stderr.write('y'*100000)"], timeout=3)
        self.assertEqual(huge.returncode, 125)
        self.assertLessEqual(len(huge.stdout) + len(huge.stderr), 4096)
        with mock.patch.object(health, "MAX_OUTPUT", 4096):
            drained = health._run([sys.executable, "-c", "import sys; sys.stdout.write('x'*100000)"], timeout=3, graceful=True)
        self.assertEqual(drained.returncode, 0)
        self.assertLessEqual(len(drained.stdout), 4096)


if __name__ == "__main__":
    unittest.main()
