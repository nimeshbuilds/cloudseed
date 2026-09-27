"""Empty or unverified host/FIPS evidence must not become a passing scan."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-report-tests-"))

from cloudseed import clouds, scan  # noqa: E402


class HostFipsCompletenessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cloudseed-host-fips-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = SimpleNamespace(id="aws-review", name="review", dir=self.root, stack_dir=self.root / "stack",
                                   private_key_path=lambda cfg: self.root / "key")
        self.env.stack_dir.mkdir()
        (self.env.stack_dir / "main.tf.json").write_text(json.dumps({"provider": {"aws": {"use_fips_endpoint": True}}}))

    def xccdf(self, results, score="100"):
        rows = "".join(f'<rule-result idref="r{i}" severity="medium"><result>{status}</result>'
                       f'<message>Evidence for {status}</message></rule-result>' for i, status in enumerate(results))
        return f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult>{rows}<score>{score}</score></TestResult></Benchmark>'

    def host_report(self, xml, rc=0, skipped=None):
        class Child:
            stdout = iter(())
            def wait(self):
                return rc
        def launch(cmd, **kwargs):
            dest = Path(json.loads(cmd[cmd.index("-e") + 1])["scan_dest"]) / "bastion"
            dest.mkdir()
            if xml is not None:
                (dest / "results.xml").write_text(xml)
            if skipped:
                (dest / "meta.json").write_text(json.dumps({"skipped": skipped}))
            return Child()
        with mock.patch.object(scan, "_hosts", return_value=[("bastion", "192.0.2.2")]), \
                mock.patch.object(scan.prov, "Host"), mock.patch.object(scan.prov, "ansible_ssh_common_args", return_value=""), \
                mock.patch.object(scan.prov, "ansible_env", return_value={}), \
                mock.patch.object(scan, "_ssg_version", return_value="test"), \
                mock.patch.object(scan.deps, "ensure_local_ansible", return_value=Path("/fake/ansible")), \
                mock.patch.object(scan.subprocess, "Popen", side_effect=launch), mock.patch.object(scan, "audit"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            path = scan.host(clouds.get("aws"), self.env, {"vars": {}}, {}, ["bastion"])
        return json.loads(path.read_text())

    def test_empty_or_malformed_host_results_are_incomplete(self):
        for xml in (self.xccdf([]), "<unrelated/>", "<broken", None):
            with self.subTest(xml=xml):
                report = self.host_report(xml)
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertTrue(any(f["status"] == "UNKNOWN" for f in report["findings"]))

    def test_manual_error_and_unknown_host_rules_remain_visible(self):
        for status in ("notchecked", "error", "unknown", "unexpected-state"):
            with self.subTest(status=status):
                report = self.host_report(self.xccdf(["pass", status]))
                self.assertEqual(report["verdict"], "INCOMPLETE")
                pending = [f for f in report["findings"] if f["status"] == "UNKNOWN"]
                self.assertEqual(len(pending), 1)
                self.assertIn(status, pending[0]["detail"])
                self.assertTrue(pending[0]["remediation"])

    def test_failed_host_rule_wins_over_incomplete_collection(self):
        report = self.host_report(self.xccdf(["fail", "notchecked"]), rc=2)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["summary"]["fail"], 1)
        self.assertTrue(any(f["status"] == "UNKNOWN" for f in report["findings"]))
        self.assertTrue(any("Evidence for fail" in f["detail"] for f in report["findings"]))

    def test_successful_rules_do_not_hide_collection_error(self):
        self.assertEqual(self.host_report(self.xccdf(["pass"]), rc=2)["verdict"], "INCOMPLETE")
        self.assertEqual(self.host_report(self.xccdf(["pass"]))["verdict"], "PASS")

    def test_informational_rules_and_not_applicable_profiles_remain_distinct(self):
        self.assertEqual(self.host_report(self.xccdf(["pass", "informational", "notselected"]))["verdict"], "PASS")
        self.assertEqual(self.host_report(self.xccdf(["notapplicable"]))["verdict"], "N/A")
        self.assertEqual(self.host_report(None, skipped="No profile for this OS")["verdict"], "N/A")
        self.assertEqual(self.host_report(None, skipped="No profile for this OS", rc=2)["verdict"], "INCOMPLETE")

    def test_explicitly_excluded_or_informational_only_scope_is_not_applicable(self):
        for results in (["informational"], ["notselected"], ["informational", "notselected", "notapplicable"]):
            with self.subTest(results=results):
                report = self.host_report(self.xccdf(results))
                self.assertEqual(report["verdict"], "N/A")
                self.assertEqual(report["summary"]["unknown"], 0)
                self.assertFalse(any(f["status"] == "UNKNOWN" for f in report["findings"]))
                for kind in ("informational", "notselected", "notapplicable"):
                    self.assertEqual(report["summary"][kind], results.count(kind))

    def test_explicit_exclusions_do_not_hide_unresolved_or_failed_checks(self):
        for status in ("notchecked", "error", "unknown"):
            with self.subTest(status=status):
                report = self.host_report(self.xccdf(["informational", "notselected", status]))
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertEqual(report["summary"]["unknown"], 1)
        self.assertEqual(self.host_report(self.xccdf(["informational", "fail"]))["verdict"], "FAIL")
        self.assertEqual(self.host_report(self.xccdf(["informational"]), rc=2)["verdict"], "INCOMPLETE")

    def test_xccdf_retains_rule_title_and_remediation(self):
        path = self.root / "rules.xml"
        path.write_text('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><Rule id="r">'
                        '<title>Disable root login</title><fixtext>Set PermitRootLogin no.</fixtext></Rule>'
                        '<TestResult><rule-result idref="r"><result>fail</result><message>Root login enabled.</message>'
                        '</rule-result><score>0</score></TestResult></Benchmark>')
        rule = scan._parse_xccdf(path)["failed_rules"][0]
        self.assertEqual(rule["title"], "Disable root login")
        self.assertIn("Root login enabled", rule["detail"])
        self.assertEqual(rule["remediation"], "Set PermitRootLogin no.")

    def fips_report(self, *, wanted=True, hosts=None, probe=None, ctx=None, nodes=None, cfg_extra=None, outputs=None):
        cfg = {"vars": {"fips_mode": wanted}, "ssh_public_key": "test-fixture"}
        cfg["vars"].update(cfg_extra or {})
        with mock.patch.object(scan, "_hosts", return_value=hosts or []), \
                mock.patch.object(scan, "_ssh_key_check", return_value=(True, "approved fixture key")), \
                mock.patch.object(scan.prov, "Host"), mock.patch.object(scan.subprocess, "run", side_effect=probe if isinstance(probe, Exception) else None,
                    return_value=probe or subprocess.CompletedProcess([], 0, "", "")), \
                mock.patch.object(scan, "_fips_nodes", return_value=nodes), \
                mock.patch.object(scan, "_kubectl", return_value=subprocess.CompletedProcess([], 1, "", "")), \
                mock.patch("cloudseed.platform.installed_releases", return_value={}), \
                mock.patch.object(scan, "audit"), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            path = scan.fips(clouds.get("aws"), self.env, cfg, outputs or {}, ctx)
        return json.loads(path.read_text())

    def test_fips_enabled_without_runtime_hosts_is_incomplete(self):
        report = self.fips_report()
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(report["summary"]["fail"], 0)
        self.assertGreater(report["summary"]["unknown"], 0)

    def test_fips_provider_literal_booleans_and_strings_are_respected(self):
        for value, status in ((True, "PASS"), ("true", "PASS"), (False, "FAIL"), ("false", "FAIL")):
            with self.subTest(value=value):
                (self.env.stack_dir / "main.tf.json").write_text(json.dumps({"provider": {"aws": {"use_fips_endpoint": value}}}))
                report = self.fips_report()
                row = next(c for c in report["checks"] if c["check"] == "AWS provider uses FIPS endpoints")
                self.assertEqual(row["status"], status)
                if status == "FAIL":
                    self.assertEqual(report["verdict"], "FAIL")
                    self.assertIn("is false", row["detail"])

    def test_fips_provider_unresolved_or_invalid_values_have_specific_unknown_reason(self):
        for value in (None, 1, 0, [], {}, "yes", "FALSE", "${var.fips_mode}", "%{if var.enabled}true%{endif}"):
            with self.subTest(value=value):
                (self.env.stack_dir / "main.tf.json").write_text(json.dumps({"provider": {"aws": {"use_fips_endpoint": value}}}))
                report = self.fips_report()
                row = next(c for c in report["checks"] if c["check"] == "AWS provider uses FIPS endpoints")
                self.assertEqual(row["status"], "UNKNOWN")
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertIn("expression or template" if isinstance(value, str) and value.startswith(("${", "%{")) else "not a literal boolean", row["detail"])
                self.assertIn("resolved AWS provider configuration", row["remediation"])
        (self.env.stack_dir / "main.tf.json").write_text(json.dumps({"provider": {"aws": {}}}))
        row = next(c for c in self.fips_report()["checks"] if c["check"] == "AWS provider uses FIPS endpoints")
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertIn("does not declare", row["detail"])
        self.assertIn("resolved AWS provider configuration", row["remediation"])

    def test_unparseable_approved_key_name_is_not_a_pass(self):
        for key in ("ssh-rsa AAAA", "ecdsa-sha2-nistp384 AAAA"):
            with self.subTest(key=key):
                ok, detail = scan._ssh_key_check(key, "gcp")
                self.assertIsNone(ok)
                self.assertIn("could not be parsed", detail)

    def test_non_fips_environment_remains_not_applicable(self):
        report = self.fips_report(wanted=False)
        self.assertEqual(report["verdict"], "N/A")

    def test_observed_fips_host_can_pass(self):
        probe = subprocess.CompletedProcess([], 0, "1\n---\nciphers aes256-ctr\n---\nopenssl-fips\n---\n", "")
        settings = {k: ["approved"] for k in ("ciphers", "kexalgorithms", "macs", "hostkeyalgorithms", "pubkeyacceptedalgorithms")}
        with mock.patch.object(scan, "sshd_fips_problems", return_value=([], settings)):
            report = self.fips_report(hosts=[("bastion", "192.0.2.2")], probe=probe)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["unknown"], 0)

    def test_partial_sshd_settings_do_not_establish_fips_algorithms(self):
        probe = subprocess.CompletedProcess([], 0, "1\n---\nciphers aes256-ctr\n---\nopenssl-fips\n---\n", "")
        report = self.fips_report(hosts=[("bastion", "192.0.2.2")], probe=probe)
        self.assertEqual(report["verdict"], "INCOMPLETE")
        row = next(c for c in report["checks"] if "sshd offers" in c["check"])
        self.assertEqual(row["status"], "UNKNOWN")

    def test_fips_unreachable_and_timed_out_hosts_are_unknown(self):
        for probe in (subprocess.CompletedProcess([], 255, "", "connection failed"), subprocess.TimeoutExpired("ssh", 60)):
            with self.subTest(probe=type(probe).__name__):
                report = self.fips_report(hosts=[("bastion", "192.0.2.2")], probe=probe)
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertTrue(any(c["area"] == "hosts" and c["status"] == "UNKNOWN" for c in report["checks"]))

    def test_missing_openssl_is_unverified_not_passed(self):
        report = self.fips_report(hosts=[("bastion", "192.0.2.2")],
                                 probe=subprocess.CompletedProcess([], 0, "1\n---\n---\nopenssl-unavailable\n---\n", ""))
        self.assertEqual(report["verdict"], "INCOMPLETE")
        row = next(c for c in report["checks"] if "OpenSSL" in c["check"])
        self.assertEqual(row["status"], "UNKNOWN")

    def test_fips_failure_wins_over_unknown_runtime_checks(self):
        report = self.fips_report(hosts=[("bastion", "192.0.2.2")],
                                 probe=subprocess.CompletedProcess([], 0, "0\n---\n---\nopenssl-unavailable\n---\n", ""))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertGreater(report["summary"]["unknown"], 0)

    def test_no_live_nodes_or_missing_connection_remains_unknown(self):
        for ctx, nodes in ((None, None), (SimpleNamespace(distro="eks"), [])):
            with self.subTest(ctx=ctx):
                report = self.fips_report(ctx=ctx, nodes=nodes, outputs={"kubernetes_cluster_name": "fixture"})
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertTrue(any(c["area"] == "kubernetes" and c["status"] == "UNKNOWN" for c in report["checks"]))

    def test_run_all_shows_incomplete_as_amber(self):
        path = self.root / "fips-20260926-120000.json"
        path.write_text(json.dumps({"verdict": "INCOMPLETE"}))
        with mock.patch.object(scan, "_hosts", return_value=[]), mock.patch.object(scan, "fips", return_value=path), \
                mock.patch.object(scan.ui, "panel") as panel, contextlib.redirect_stdout(io.StringIO()):
            result = scan.run_all(clouds.get("vmware"), self.env, {"vars": {"fips_mode": True}}, {}, None, ["bastion"])
        self.assertEqual(result, [path])
        self.assertEqual(panel.call_args.kwargs["accent"], "seed")

    def test_unknown_host_rules_explain_observation_without_inventing_cause(self):
        path = self.root / "manual.xml"
        path.write_text('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult>'
                        '<rule-result idref="manual"><result>notchecked</result></rule-result>'
                        '<rule-result idref="error"><result>error</result><message>probe failed</message></rule-result>'
                        '</TestResult></Benchmark>')
        rows = scan._parse_xccdf(path)["unresolved_rules"]
        self.assertIn("did not execute", rows[0]["detail"])
        self.assertIn("No further cause was supplied", rows[0]["detail"])
        self.assertIn("manual assessment", rows[0]["remediation"])
        self.assertIn("execution error", rows[1]["detail"])
        self.assertIn("probe failed", rows[1]["detail"])
        path.write_text("<broken")
        self.assertIn("malformed XML", scan._parse_xccdf(path)["parse_error"])
        path.unlink()
        self.assertIn("does not exist", scan._parse_xccdf(path)["parse_error"])

    def test_fips_unknown_openssl_and_sshd_have_specific_causes_and_next_steps(self):
        report = self.fips_report(hosts=[("bastion", "192.0.2.2")],
                                 probe=subprocess.CompletedProcess([], 0, "1\n---\nciphers aes256-ctr\n---\n", ""))
        openssl = next(f for f in report["findings"] if "OpenSSL" in f["title"])
        sshd = next(f for f in report["findings"] if "sshd offers" in f["title"])
        self.assertEqual(openssl["status"], "UNKNOWN")
        self.assertIn("no OpenSSL result section", openssl["detail"])
        self.assertIn("openssl version", openssl["remediation"])
        self.assertIn("kexalgorithms", sshd["detail"])
        self.assertIn("pubkeyacceptedalgorithms", sshd["detail"])
        self.assertIn("stderr was not collected", sshd["detail"])
        self.assertIn("sudo sshd -T", sshd["remediation"])
        for check in report["checks"]:
            if check["status"] == "UNKNOWN":
                self.assertTrue(check["detail"])
                self.assertTrue(check["remediation"])
        markdown = next((self.env.dir / "scans").glob("fips-*.md")).read_text()
        self.assertIn(openssl["detail"], markdown)
        self.assertIn(openssl["remediation"], markdown)

    def test_fips_timeout_and_missing_stack_have_distinct_causes(self):
        for probe, reason in ((subprocess.TimeoutExpired("ssh", 60), "timed out after 60 seconds"),
                              (FileNotFoundError(2, "fixture missing"), "could not execute")):
            with self.subTest(reason=reason):
                report = self.fips_report(hosts=[("bastion", "192.0.2.2")], probe=probe)
                row = next(f for f in report["findings"] if "runtime checks unavailable" in f["title"])
                self.assertIn(reason, row["detail"])
        (self.env.stack_dir / "main.tf.json").write_text("{")
        row = next(f for f in self.fips_report()["findings"] if "AWS provider" in f["title"])
        self.assertIn("not valid JSON", row["detail"])
        self.assertNotIn("not rendered", row["detail"])


if __name__ == "__main__":
    unittest.main()
