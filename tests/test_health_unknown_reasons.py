"""Health/network UNKNOWN results explain the observed cause and a specific next action."""

import json
import subprocess
import unittest
from unittest import mock

from cloudseed import health
import test_operations_health as fixtures


class HealthUnknownReasonTests(unittest.TestCase):
    def setUp(self):
        self.base = fixtures.HealthTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)

    def test_query_failures_have_safe_specific_categories(self):
        cases = ((124, "", "timed out"), (125, "", "output limit"), (127, "", "helper could not run"),
                 (1, "Forbidden secret-value", "Forbidden"), (1, "Unauthorized secret-value", "authentication"),
                 (1, "x509: secret-value", "TLS certificate"), (1, "no such host secret-value", "could not be resolved"),
                 (1, "connection refused secret-value", "refused the connection"),
                 (1, "the server doesn't have a resource type secret-value", "resource type is not served"))
        for code, error, expected in cases:
            with self.subTest(expected=expected):
                detail, action = health._query_problem(subprocess.CompletedProcess([], code, "", error), "Node query")
                self.assertIn(expected, detail)
                self.assertTrue(action)
                self.assertNotIn("secret-value", detail + action)

    def test_unrecognized_failure_and_bad_success_output_do_not_invent_a_cause(self):
        detail, action = health._query_problem(subprocess.CompletedProcess([], 1, "", "unrecognized secret-value"), "Query")
        self.assertIn("without a recognized cause", detail)
        self.assertNotIn("timed out", detail)
        self.assertNotIn("Forbidden", detail)
        self.assertIn("inspect its stderr", action)
        detail, action = health._query_problem(subprocess.CompletedProcess([], 0, "{}", ""), "Query", "a JSON items array")
        self.assertIn("succeeded but did not return a JSON items array", detail)

    def test_missing_kubeconfig_does_not_blame_an_installed_kubectl(self):
        with mock.patch.object(health.deps, "find", return_value="/mock/kubectl"), mock.patch.object(health, "_run") as runner:
            report = self.base.execute(live=True)
        finding = self.base.finding(report, "cluster.api")
        self.assertIn("kubeconfig is not available as a regular file", finding["detail"])
        self.assertNotIn("kubectl was not found", finding["detail"])
        self.assertNotIn("Install kubectl", finding["remediation"])
        runner.assert_not_called()

    def test_missing_kubectl_and_refused_symlink_are_distinct(self):
        kc = self.base.kubeconfig()
        with mock.patch.object(health.deps, "find", return_value=None):
            finding = self.base.finding(self.base.execute(live=True), "cluster.nodes")
        self.assertIn("kubectl was not found", finding["detail"])
        self.assertNotIn("kubeconfig", finding["detail"])
        kc.unlink()
        kc.symlink_to(kc.parent / "missing")
        with mock.patch.object(health.deps, "find", return_value="kubectl"):
            finding = self.base.finding(self.base.execute(live=True), "cluster.nodes")
        self.assertIn("symlink and was refused", finding["detail"])

    def test_live_read_results_distinguish_denial_empty_lists_and_missing_expiry(self):
        self.base.kubeconfig()
        def run(argv, **kwargs):
            if "--raw=/readyz" in argv:
                return subprocess.CompletedProcess(argv, 0, "ok", "")
            kind = argv[argv.index("get") + 1]
            if kind == "nodes":
                return subprocess.CompletedProcess(argv, 1, "", "Forbidden secret-value")
            if kind == "backups.velero.io":
                return subprocess.CompletedProcess(argv, 1, "", "the server doesn't have a resource type backups")
            return subprocess.CompletedProcess(argv, 0, json.dumps({"items": [{}] if kind == "certificates.cert-manager.io" else []}), "")
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=run):
            report = self.base.execute(live=True)
        for id_, message in (("cluster.nodes", "Forbidden"), ("cluster.platform", "no Deployments"),
                             ("cluster.certificates", "missing or unreadable status.notAfter"), ("cluster.backups", "resource type is not served")):
            finding = self.base.finding(report, id_)
            self.assertEqual(finding["status"], "UNKNOWN")
            self.assertIn(message, finding["detail"])
            self.assertTrue(finding["remediation"])
        self.assertNotIn("secret-value", json.dumps(report))

    def test_probe_timeout_explains_missing_dns_and_https_results(self):
        self.base.kubeconfig()
        runner, _ = self.base.active_runner()
        def run(argv, **kwargs):
            if "wait" in argv and "pod/probe" in argv:
                return subprocess.CompletedProcess(argv, 124, "", "")
            return runner(argv, **kwargs)
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=run):
            report = self.base.execute("network", live=True, active=True)
        for id_ in ("network.dns", "network.tls.1"):
            finding = self.base.finding(report, id_)
            self.assertEqual(finding["status"], "UNKNOWN")
            self.assertIn("Probe completion: the command timed out", finding["detail"])
            self.assertIn("timeout", finding["remediation"])

    def test_probe_log_omission_is_not_described_as_dns_failure(self):
        self.base.kubeconfig()
        runner, _ = self.base.active_runner()
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, "{}", "") if "logs" in argv else runner(argv, **kwargs)
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=run):
            report = self.base.execute("network", live=True, active=True)
        finding = self.base.finding(report, "network.dns")
        self.assertEqual(finding["status"], "UNKNOWN")
        self.assertIn("logs did not contain a valid result", finding["detail"])
        self.assertNotIn("did not resolve", finding["detail"])
        self.assertIn("Inspect the probe logs", finding["remediation"])

    def test_cleanup_ownership_mismatch_is_explained_without_deletion(self):
        self.base.kubeconfig()
        runner, state = self.base.active_runner(foreign=True)
        with mock.patch.object(health.deps, "find", return_value="kubectl"), mock.patch.object(health, "_run", side_effect=runner):
            report = self.base.execute("network", live=True, active=True)
        finding = self.base.finding(report, "network.cleanup")
        self.assertEqual(finding["status"], "UNKNOWN")
        self.assertIn("matching owner label and UID", finding["detail"])
        self.assertIn("deletion was refused", finding["detail"])
        self.assertFalse(state["deleted"])


if __name__ == "__main__":
    unittest.main()
