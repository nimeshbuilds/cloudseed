"""Architecture screening cannot turn declarations, incomplete scans or unsafe evidence into live proof."""

import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cloudseed import architecture, scan, ui


class ArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cloudseed-architecture-test-")
        self.addCleanup(self.tmp.cleanup)
        self.env = SimpleNamespace(dir=Path(self.tmp.name), id="aws-review")
        self.now = datetime(2026, 9, 24, 16, 0, tzinfo=timezone.utc)
        patcher = mock.patch.object(architecture, "_now", return_value=self.now)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cfg = {"vars": {"single_nat_gateway": False}, "allowed_ssh_cidrs": ["192.0.2.4/32"]}

    def assess(self, target="aws", **kwargs):
        self.env.id = target + "-review"
        return architecture.assess(SimpleNamespace(key=target), self.env, self.cfg, **kwargs)

    def finding(self, id_, target="aws", **kwargs):
        return next(f for f in self.assess(target, **kwargs)["findings"] if f["id"] == id_)

    def save(self, folder, prefix, data, age=0):
        stamp = (self.now - timedelta(days=age, seconds=1)).strftime(scan.RUN_FORMAT)
        data = {"run": stamp, **data}
        dest = self.env.dir / folder / (prefix + "-" + stamp + ".json")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(data))
        return dest

    def cloud_report(self, **updates):
        report = {"kind": "cloud", "verdict": "PASS", "summary": {"provider": "aws", "pass": 20, "fail": 0}}
        report.update(updates)
        return report

    def dr_report(self, **updates):
        report = {"env": "aws-review", "cloud": "aws", "verdict": "PASS", "volume_tested": True,
                  "volume_verified": True, "rto_s": 4.0,
                  "steps": [{"step": name, "ok": True, "seconds": 2.0} for name in architecture._DR_STEPS]}
        report.update(updates)
        return report

    def test_all_targets_have_stable_json_schema_and_six_domains(self):
        for target in ("aws", "gcp", "azure", "vmware"):
            with self.subTest(target=target):
                report = self.assess(target)
                json.dumps(report, allow_nan=False)
                self.assertEqual(report["schema_version"], 1)
                self.assertEqual(report["target"], target)
                self.assertEqual(report["env"], target + "-review")
                self.assertEqual(report["generated_at"], "2026-09-24T16:00:00Z")
                self.assertEqual(set(f["pillar"] for f in report["findings"]), set(architecture.PILLARS))
                self.assertEqual(len({f["id"] for f in report["findings"]}), len(report["findings"]))
                for finding in report["findings"]:
                    self.assertTrue(set(("id", "pillar", "status", "severity", "title", "detail", "remediation", "evidence", "references")) <= set(finding))
                    self.assertTrue(all(e["live_verified"] is False for e in finding["evidence"]))
                    self.assertTrue(all(ref["url"].startswith("https://") for ref in finding["references"]))
                if target == "azure":
                    self.assertIn("five", " ".join(report["coverage_limits"]))
                if target == "vmware":
                    self.assertIn("not an official", " ".join(report["coverage_limits"]))

    def test_no_provider_calls_or_config_mutations(self):
        before = copy.deepcopy(self.cfg)
        before_files = list(self.env.dir.rglob("*"))
        with mock.patch("subprocess.run", side_effect=AssertionError("no subprocess")), \
                mock.patch("socket.socket", side_effect=AssertionError("no network")), \
                mock.patch("cloudseed.paths.tf_root", side_effect=AssertionError("no bundle extraction")):
            report = self.assess()
        self.assertEqual(self.cfg, before)
        self.assertEqual(list(self.env.dir.rglob("*")), before_files)
        self.assertEqual(report["verdict"], "INCOMPLETE")

    def test_vmware_api_guidance_does_not_suggest_unsupported_cloud_flags(self):
        self.cfg["vars"]["enable_kubernetes"] = True
        finding = self.finding("security.kubernetes_api", "vmware")
        self.assertEqual(finding["status"], "UNKNOWN")
        self.assertNotIn("kubernetes_public_endpoint", json.dumps(finding))
        self.assertIn("host firewall", finding["remediation"])

    def test_production_defaults_report_known_topology_gaps(self):
        self.cfg["vars"] = {"enable_kubernetes": True}
        for target, id_ in (("aws", "reliability.aws_egress"), ("gcp", "reliability.gke_location"),
                            ("azure", "reliability.aks_availability"), ("vmware", "reliability.vmware_host")):
            with self.subTest(target=target):
                self.assertEqual(self.finding(id_, target)["status"], "FAIL")
                self.assertEqual(self.assess(target)["verdict"], "FAIL")
                self.assertEqual(self.finding(id_, target, profile="lab")["status"], "NOT_APPLICABLE")

    def test_extra_vars_precedence_and_strict_boolean_strings(self):
        self.cfg["vars"].update(enable_kubernetes="yes", kubernetes_public_endpoint="true", single_nat_gateway="no")
        self.cfg["extra_vars"] = {"kubernetes_public_endpoint": "false", "single_nat_gateway": "true"}
        self.assertEqual(self.finding("security.kubernetes_api")["status"], "PASS")
        self.assertEqual(self.finding("reliability.aws_egress")["status"], "FAIL")
        for value in ("nonsense", [], None, 3):
            with self.subTest(value=value):
                self.cfg["extra_vars"]["single_nat_gateway"] = value
                self.assertEqual(self.finding("reliability.aws_egress")["status"], "UNKNOWN")

    def test_invalid_az_and_kubernetes_settings_are_unknown(self):
        for value in (True, "abc", -1, 1.2):
            self.cfg["vars"]["az_count"] = value
            status = self.finding("reliability.aws_egress")["status"]
            self.assertIn(status, ("FAIL", "UNKNOWN"))
        self.cfg["vars"]["enable_kubernetes"] = "maybe"
        self.assertEqual(self.finding("security.kubernetes_api")["status"], "UNKNOWN")

    def test_invalid_az_upper_bound_cannot_pass(self):
        self.cfg["vars"]["az_count"] = 6
        self.assertEqual(self.finding("reliability.aws_egress")["status"], "FAIL")
        self.cfg["vars"]["az_count"] = 10 ** 600
        self.assertEqual(self.finding("reliability.aws_egress")["status"], "UNKNOWN")

    def test_single_letter_saved_boolean_answers_match_rendering(self):
        self.cfg["vars"].update(enable_kubernetes="y", kubernetes_public_endpoint="n")
        self.assertEqual(self.finding("security.kubernetes_api")["status"], "PASS")

    def test_raw_boolean_overrides_require_terraform_boolean_values(self):
        checks = (("aws", "single_nat_gateway", "reliability.aws_egress"),
                  ("aws", "kubernetes_public_endpoint", "security.kubernetes_api"),
                  ("aws", "enable_cloudtrail", "security.audit_logging"),
                  ("aws", "enable_flow_logs", "operations.network_logs"),
                  ("azure", "enable_activity_log", "security.audit_logging"),
                  ("gcp", "enable_data_access_audit_logs", "security.audit_logging"))
        self.cfg["vars"]["enable_kubernetes"] = True
        for target, key, id_ in checks:
            for value in ("yes", "no", "on", "off", "y", "n", "True", "FALSE", " true ", "0", "1", 0, 1):
                with self.subTest(target=target, key=key, value=value):
                    self.cfg["extra_vars"] = {key: value}
                    self.assertEqual(self.finding(id_, target)["status"], "UNKNOWN")
        for value in (False, "false"):
            self.cfg["extra_vars"] = {"kubernetes_public_endpoint": value}
            self.assertEqual(self.finding("security.kubernetes_api")["status"], "PASS")
        for value in (True, "true"):
            self.cfg["extra_vars"] = {"enable_flow_logs": value}
            self.assertEqual(self.finding("operations.network_logs")["status"], "PASS")

    def test_raw_kubernetes_and_baseline_enablement_cannot_use_prompt_coercion(self):
        for value in ("yes", "no", 0, 1):
            with self.subTest(value=value):
                self.cfg["extra_vars"] = {"enable_kubernetes": value}
                self.assertEqual(self.finding("security.kubernetes_api")["status"], "UNKNOWN")
                self.cfg["extra_vars"] = {"enable_account_baseline": value}
                self.assertEqual(self.finding("security.audit_logging")["status"], "UNKNOWN")
                self.cfg["extra_vars"] = {"enable_project_baseline": value}
                self.assertEqual(self.finding("security.audit_logging", "gcp")["status"], "UNKNOWN")

    def test_ssh_extra_override_cannot_hide_enforced_world_access(self):
        self.cfg["allowed_ssh_cidrs"] = ["0.0.0.0/0"]
        self.cfg["extra_vars"] = {"allowed_ssh_cidrs": ["192.0.2.1/32"]}
        self.assertEqual(self.finding("security.ssh_access")["status"], "FAIL")
        self.cfg["allowed_ssh_cidrs"] = ["192.0.2.1/32"]
        self.cfg["extra_vars"]["allowed_ssh_cidrs"] = ["0.0.0.0/0"]
        self.assertEqual(self.finding("security.ssh_access")["status"], "PASS")

    def test_ssh_malformed_empty_and_ipv6(self):
        for cidrs in (None, [], "192.0.2.4/32", [4], ["bad"], ["192.0.2.4"], ["192.0.2.0/255.255.255.0"],
                      ["192.0.2.4/32 "], ["192.0.2.4/+32"], ["192.0.2.4/32", "192.0.2.5"]):
            self.cfg["allowed_ssh_cidrs"] = cidrs
            self.assertEqual(self.finding("security.ssh_access")["status"], "UNKNOWN")
        self.cfg["allowed_ssh_cidrs"] = ["::/0"]
        self.assertEqual(self.finding("security.ssh_access")["status"], "FAIL")

    def test_baseline_delegation_is_not_missing_security(self):
        self.cfg["extra_vars"] = {"enable_account_baseline": False, "enable_cloudtrail": False}
        self.assertEqual(self.finding("security.audit_logging")["status"], "UNKNOWN")
        self.assertEqual(self.finding("security.baseline_ownership")["status"], "UNKNOWN")
        self.cfg["extra_vars"]["enable_account_baseline"] = True
        self.assertEqual(self.finding("security.audit_logging")["status"], "FAIL")

    def test_raw_terraform_settings_follow_extra_vars_not_misplaced_answers(self):
        self.cfg["vars"]["enable_cloudtrail"] = False
        self.cfg["vars"]["enable_flow_logs"] = False
        self.assertEqual(self.finding("security.audit_logging")["status"], "PASS")
        self.assertEqual(self.finding("operations.network_logs")["status"], "PASS")
        self.cfg["extra_vars"] = {"enable_cloudtrail": False, "enable_flow_logs": False}
        self.assertEqual(self.finding("security.audit_logging")["status"], "FAIL")
        self.assertEqual(self.finding("operations.network_logs")["status"], "FAIL")

    def test_lab_relaxes_topology_without_claiming_complete_coverage(self):
        self.assertEqual(self.assess("vmware", profile="lab")["verdict"], "INCOMPLETE")
        self.assertEqual(self.assess("aws", profile="lab")["verdict"], "INCOMPLETE")

    def test_rejects_invalid_options(self):
        for age in (0, -1, 3651, True, "30", None):
            with self.assertRaises(ui.Abort) as error:
                self.assess(max_age_days=age)
            self.assertEqual(error.exception.code, 2)
        with self.assertRaises(ui.Abort):
            self.assess(profile="secret-arbitrary-value")
        with self.assertRaises(ui.Abort):
            self.assess("unsupported")
        self.cfg["vars"] = ["invalid"]
        with self.assertRaises(ui.Abort):
            self.assess()

    def test_security_pass_is_not_completeness_attestation(self):
        self.save("scans", "cloud", self.cloud_report())
        self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")
        self.assertEqual(self.assess()["verdict"], "INCOMPLETE")

    def test_medium_low_failures_are_fail_even_when_prowler_verdict_pass(self):
        self.save("scans", "cloud", self.cloud_report(summary={"provider": "aws", "pass": 20, "fail": 2, "failed high": 0, "failed medium": 2}))
        finding = self.finding("security.saved_cloud_scan")
        self.assertEqual(finding["status"], "FAIL")
        self.assertEqual(finding["evidence"][0]["checks_failed"], 2)
        self.assertEqual(self.assess()["verdict"], "FAIL")

    def test_cloud_sparse_mismatched_or_invalid_counts_cannot_pass(self):
        for report in ({"verdict": "PASS"}, self.cloud_report(summary=[]), self.cloud_report(summary={"provider": "azure", "pass": 1, "fail": 1}),
                       self.cloud_report(summary={"provider": "aws", "pass": True, "fail": 0}),
                       self.cloud_report(summary={"provider": "aws", "pass": 1, "fail": -1})):
            self.save("scans", "cloud", report)
            self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")

    def test_stale_future_and_mismatched_timestamp_evidence_is_unknown(self):
        for age in (31, -1):
            with self.subTest(age=age):
                path = self.save("scans", "cloud", self.cloud_report(summary={"provider": "aws", "pass": 2, "fail": 1}), age=age)
                self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")
                path.unlink()
        self.save("scans", "cloud", self.cloud_report(run="20200101-000000"))
        self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")

    def test_newer_corrupt_report_does_not_fall_back_to_older(self):
        self.cfg["vars"]["enable_kubernetes"] = True
        self.save("dr", "drill", self.dr_report(), age=1)
        path = self.save("dr", "drill", self.dr_report())
        path.write_text("{broken-json")
        self.assertEqual(self.finding("reliability.restore_drill")["status"], "UNKNOWN")

    def test_valid_drill_proves_only_sample_recovery(self):
        self.cfg["vars"]["enable_kubernetes"] = True
        self.save("dr", "drill", self.dr_report())
        finding = self.finding("reliability.restore_drill")
        self.assertEqual(finding["status"], "PASS")
        self.assertEqual(finding["evidence"][0]["measured_sample_rto_seconds"], 4)
        self.assertIn("does not prove application", finding["detail"])
        self.assertEqual(self.finding("reliability.workload_objectives")["status"], "UNKNOWN")

    def test_drill_requires_valid_steps_rto_and_verified_volume(self):
        self.cfg["vars"]["enable_kubernetes"] = True
        for updates in ({"steps": []}, {"steps": "bad"}, {"steps": [{}] * 5}, {"rto_s": 0}, {"rto_s": True},
                        {"rto_s": float("nan")}, {"rto_s": float("inf")}, {"rto_s": "10"}, {"rto_s": 9999},
                        {"volume_tested": False}, {"volume_verified": False}, {"volume_verified": "true"},
                        {"cloud": "gcp"}, {"env": "aws-other"}, {"verdict": "INTERRUPTED"}):
            with self.subTest(updates=updates):
                self.save("dr", "drill", self.dr_report(**updates))
                self.assertEqual(self.finding("reliability.restore_drill")["status"], "UNKNOWN")

    def test_failed_latest_drill_wins_over_old_success(self):
        self.cfg["vars"]["enable_kubernetes"] = True
        self.save("dr", "drill", self.dr_report(), age=1)
        self.save("dr", "drill", self.dr_report(verdict="FAIL", rto_s=None))
        self.assertEqual(self.finding("reliability.restore_drill")["status"], "FAIL")

    def test_evidence_is_bounded_and_does_not_echo_secret_text(self):
        secret = "do-not-copy-this-private-payload"
        path = self.save("scans", "cloud", self.cloud_report(raw=secret, findings=[{"detail": secret}]))
        self.assertNotIn(secret, json.dumps(self.assess()))
        with mock.patch.object(architecture, "MAX_EVIDENCE_BYTES", 20):
            self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")
        path.write_text('"' + secret + '"')
        self.assertNotIn(secret, json.dumps(self.assess()))
        self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")

    @unittest.skipIf(os.name == "nt", "symlink and descriptor safety uses POSIX file primitives")
    def test_symlinked_file_and_directory_are_not_followed(self):
        path = self.save("scans", "cloud", self.cloud_report(summary={"provider": "aws", "pass": 1, "fail": 2}))
        outside = self.env.dir / "outside.json"
        path.rename(outside)
        path.symlink_to(outside)
        self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")
        path.unlink()
        outside.rename(path)
        folder = self.env.dir / "scans"
        folder.rename(self.env.dir / "elsewhere")
        folder.symlink_to(self.env.dir / "elsewhere", target_is_directory=True)
        self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")

    @unittest.skipIf(os.name == "nt", "FIFO safety uses POSIX file primitives")
    def test_fifo_is_rejected_without_blocking(self):
        path = self.save("scans", "cloud", self.cloud_report())
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(self.finding("security.saved_cloud_scan")["status"], "UNKNOWN")

    def test_evidence_directory_count_is_bounded(self):
        self.save("scans", "cloud", self.cloud_report(summary={"provider": "aws", "pass": 1, "fail": 2}))
        (self.env.dir / "scans" / "extra").touch()
        with mock.patch.object(architecture, "MAX_DIRECTORY_ENTRIES", 1):
            finding = self.finding("security.saved_cloud_scan")
        self.assertEqual(finding["status"], "UNKNOWN")
        self.assertIn("entry limit", finding["evidence"][0]["reason"])

    def test_install_note_is_not_proof_of_effective_helm_defaults(self):
        self.cfg["vars"]["enable_kubernetes"] = True
        timestamp = (self.now - timedelta(seconds=30)).isoformat()
        inventory = {"env": self.env.id, "current": {"notes": {"platform-install-vault": {"at": timestamp}}}}
        (self.env.dir / "inventory.json").write_text(json.dumps(inventory))
        finding = self.finding("security.platform_vault")
        self.assertEqual(finding["status"], "UNKNOWN")
        self.assertTrue(finding["evidence"][0]["recent_install_recorded"])
        self.assertIn("development mode", finding["detail"])
        self.assertIn("custom overrides", finding["detail"])
        inventory["current"]["notes"]["platform-uninstall-vault"] = {"at": self.now.isoformat()}
        (self.env.dir / "inventory.json").write_text(json.dumps(inventory))
        self.assertFalse(self.finding("security.platform_vault")["evidence"][0]["recent_install_recorded"])

    def test_run_json_and_saved_reports_use_collection(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), scan.collect() as made:
            path = architecture.run("aws", self.env, self.cfg, json_output=True)
        printed = json.loads(stdout.getvalue())
        self.assertEqual(json.loads(path.read_text()), printed)
        self.assertEqual(printed["kind"], "architecture")
        self.assertEqual(made, [path, path.with_suffix(".md")])
        self.assertTrue(path.with_suffix(".md").exists())
        markdown = path.with_suffix(".md").read_text()
        self.assertIn("**Remediation:**", markdown)
        self.assertIn(printed["findings"][0]["detail"], markdown)
        self.assertIn(printed["findings"][0]["references"][0]["url"], markdown)
        self.assertIn(path, scan.reports(self.env))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertIn("scan-architecture", (self.env.dir / "inventory.json").read_text())

    def test_run_prints_human_summary_when_json_not_requested(self):
        with mock.patch.object(scan, "_panel") as panel:
            path = architecture.run("aws", self.env, self.cfg)
        self.assertTrue(path.exists())
        self.assertEqual(panel.call_args.kwargs["verdict"], "INCOMPLETE")
        displayed_findings = panel.call_args.args[2]
        self.assertTrue(displayed_findings)
        for finding in displayed_findings:
            self.assertIn(finding["status"], ("UNKNOWN", "FAIL"))
            self.assertTrue(finding["title"].startswith(finding["status"] + " · "))
        self.assertNotIn("verdict", panel.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
