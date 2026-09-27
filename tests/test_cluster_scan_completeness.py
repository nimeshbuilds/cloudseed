"""Cluster scans retain complete evidence and cannot pass on missing or partial results."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from cloudseed import scan, ui


class ClusterScanCompletenessTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="cloudseed-cluster-scan-")))
        self.env = SimpleNamespace(dir=folder, id="aws-scan-test", name="scan-test", cloud="aws")
        self.ctx = SimpleNamespace(env=self.env, target="aws", distro="eks", cfg={"vars": {}}, procenv=lambda: {})
        self.stack.enter_context(mock.patch.object(scan, "_ensure_kubectl"))

    def cis(self, results, *, stig=False):
        data = {"Controls": [{"node_type": "node", "tests": [{"results": results}]}]}
        with mock.patch.object(scan, "_kube_bench_run", return_value=data), \
                mock.patch.object(scan, "_kube_bench_cleanup_rbac"):
            return json.loads(scan.cis(self.ctx, stig=stig).read_text())

    def kube(self, controls, rc=0, **summary):
        return self.tool_scan(scan.kube, {"summaryDetails": {"controls": controls, **summary}}, rc)

    def tool_scan(self, scanner, data, rc=0, stderr=None):
        def run(args, **kwargs):
            Path(args[args.index("--output") + 1]).write_text(json.dumps(data))
            return subprocess.CompletedProcess(args, rc, "", stderr if stderr is not None else "tool diagnostic" if rc else "")
        with mock.patch.object(scan, "_tool", return_value="/fake/scanner"), \
                mock.patch.object(scan.subprocess, "run", side_effect=run), \
                mock.patch.object(scan, "_kubectl", return_value=subprocess.CompletedProcess([], 1, "", "CRD absent")):
            return json.loads(scanner(self.ctx).read_text())

    def operator(self, vulnerabilities=None, summary=None, items=None):
        if items is None:
            items = [{"metadata": {"namespace": "apps", "name": "demo"},
                      "report": {"summary": summary if summary is not None else {"criticalCount": 0, "highCount": 0, "mediumCount": 0, "lowCount": 0},
                                 "vulnerabilities": vulnerabilities or []}}]
        proc = subprocess.CompletedProcess([], 0, json.dumps({"items": items}), "")
        with mock.patch.object(scan, "_kubectl", return_value=proc):
            return json.loads(scan.images(self.ctx).read_text())

    def test_cis_and_stig_empty_manual_and_unknown_are_incomplete(self):
        for stig in (False, True):
            for results in ([], [{"status": "WARN"}], [{"status": "mystery"}]):
                with self.subTest(stig=stig, results=results):
                    report = self.cis(results, stig=stig)
                    self.assertEqual(report["verdict"], "INCOMPLETE")
                    self.assertEqual(len(report["findings"]), len(results))

    def test_cis_and_stig_information_does_not_block_evaluated_checks(self):
        for stig in (False, True):
            with self.subTest(stig=stig):
                report = self.cis([{"status": "PASS"}, {"status": "INFO"}], stig=stig)
                self.assertEqual(report["verdict"], "PASS")
                self.assertEqual(report["summary"]["info"], 1)
                self.assertEqual(self.cis([{"status": "INFO"}], stig=stig)["verdict"], "N/A")
                self.assertEqual(self.cis([{"status": "PASS"}, {"status": "WARN"}], stig=stig)["verdict"], "INCOMPLETE")

    def test_cis_complete_passes_and_full_failure_evidence_is_retained(self):
        self.assertEqual(self.cis([{"status": "PASS"}])["verdict"], "PASS")
        detail = "Remediation " * 100
        report = self.cis([{"status": "FAIL", "test_number": "1.2", "test_desc": "Test", "remediation": detail,
                            "actual_value": "observed", "reason": "reason"}])
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["findings"][0]["detail"], detail.strip())
        self.assertEqual(report["checks"][0]["actual_value"], "observed")
        self.assertEqual(report["raw_results"][0]["result"]["Controls"][0]["tests"][0]["results"][0]["reason"], "reason")

    def test_cis_unknown_status_explains_reason_and_next_action(self):
        for original, expected in (({}, "did not supply"), ({"status": "mystery", "reason": "scanner detail"}, "unsupported result status")):
            with self.subTest(original=original):
                report = self.cis([original])
                finding = report["findings"][0]
                self.assertEqual(finding["status"], "UNKNOWN")
                self.assertIn(expected, finding["reason"])
                self.assertIn(expected, finding["detail"])
                self.assertIn("rerun", finding["remediation"])
                self.assertEqual(finding["scanner_status"], original.get("status"))
                self.assertEqual(report["raw_results"][0]["result"]["Controls"][0]["tests"][0]["results"][0], original)

    def test_cis_partial_role_failure_keeps_successful_results(self):
        self.ctx.distro = "rke2"
        data = {"Controls": [{"tests": [{"results": [{"status": "PASS"}]}]}]}
        with mock.patch.object(scan, "_kube_bench_run", side_effect=[data, ui.Abort("worker could not run")]), \
                mock.patch.object(scan, "_kube_bench_cleanup_rbac"):
            report = json.loads(scan.cis(self.ctx).read_text())
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(report["summary"]["pass"], 1)
        self.assertIn("worker could not run", report["diagnostics"][0])

    def test_cis_malformed_results_are_incomplete(self):
        for data in ({"Controls": "broken"}, {"Controls": [None]}, {"Controls": [{"tests": [{"results": [None]}]}]}):
            with self.subTest(data=data), mock.patch.object(scan, "_kube_bench_run", return_value=data), \
                    mock.patch.object(scan, "_kube_bench_cleanup_rbac"):
                report = json.loads(scan.cis(self.ctx).read_text())
            self.assertEqual(report["verdict"], "INCOMPLETE")
            self.assertTrue(report["diagnostics"])

    def test_cis_missing_containers_are_not_hidden_by_other_passing_checks(self):
        for incomplete in ({}, {"tests": [{}]}):
            for stig in (False, True):
                data = {"Controls": [{"tests": [{"results": [{"status": "PASS"}]}]}, incomplete]}
                with self.subTest(incomplete=incomplete, stig=stig), \
                        mock.patch.object(scan, "_kube_bench_run", return_value=data), \
                        mock.patch.object(scan, "_kube_bench_cleanup_rbac"):
                    report = json.loads(scan.cis(self.ctx, stig=stig).read_text())
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertEqual(report["summary"]["pass"], 1)
                self.assertTrue(report["diagnostics"])

    def test_kubescape_preserves_low_failures_and_explicit_threshold(self):
        control = {"status": "failed", "severity": "LOW", "name": "low finding", "remediation": "full instructions"}
        report = self.kube({"C-1": control})
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["findings"][0]["evidence"], control)
        self.assertIn("Medium and Low", report["failure_policy"])
        self.assertEqual(self.kube({"C-1": dict(control, severity="HIGH")})["verdict"], "FAIL")

    def test_kubescape_empty_skipped_unknown_and_bad_execution_are_incomplete(self):
        for controls, rc in (({}, 0), ({"C-1": {"status": "skipped"}}, 0),
                             ({"C-1": {"status": True}}, 0), ({"C-1": None}, 0),
                             ({"C-1": {"status": "passed"}}, 2), ({"C-1": {"status": "passed"}}, 1)):
            with self.subTest(controls=controls, rc=rc):
                self.assertEqual(self.kube(controls, rc)["verdict"], "INCOMPLETE")
        self.assertEqual(self.kube({"C-1": {"status": "passed"}}, complianceScore="unavailable")["verdict"], "PASS")

    def test_kubescape_unknown_failed_severity_does_not_claim_threshold_passed(self):
        report = self.kube({"C-1": {"status": "failed", "scoreFactor": "bad"}})
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(report["findings"][0]["severity"], "UNKNOWN")
        self.assertIn("no valid scoreFactor", report["findings"][0]["reason"])
        self.assertIn("raw result", report["findings"][0]["remediation"])

    def test_kubescape_unknown_status_explains_original_input_without_inventing_cause(self):
        for control, expected in ((None, "null control"), ({}, "did not supply"),
                                  ({"status": True}, "unsupported result status"), ({"status": "future-value"}, "future-value")):
            with self.subTest(control=control):
                finding = self.kube({"C-1": control})["findings"][0]
                self.assertEqual(finding["status"], "UNKNOWN")
                self.assertIn(expected, finding["reason"])
                self.assertTrue(finding["remediation"])
                self.assertEqual(finding["evidence"], control)
                self.assertNotIn("permission", finding["reason"].lower())

    def test_kubescape_skips_explain_structured_reason_and_next_action(self):
        for substatus, expected in (("notEvaluated", "could not be collected"), ("configuration", "configuration is missing"),
                                   ("manual review", "manual review"), ("integration", "integration"),
                                   (None, "without a recognized structured reason"), ({}, "without a recognized structured reason")):
            with self.subTest(substatus=substatus):
                control = {"status": "skipped", "severity": "LOW", "statusInfo": {"status": "skipped", "subStatus": substatus, "info": "Original scanner detail"}}
                finding = self.kube({"C-1": control})["findings"][0]
                self.assertEqual(finding["status"], "SKIP")
                self.assertIn(expected, finding["reason"])
                self.assertIn("Original scanner detail", finding["detail"])
                self.assertTrue(finding["remediation"])
                self.assertEqual(finding["evidence"], control)

    def irrelevant_control(self, **changes):
        # Real Kubescape v4.0.14 / opa-utils v0.0.312 summary schema.
        return {"status": "passed", "statusInfo": {"status": "passed", "subStatus": "irrelevant"},
                "ResourceCounters": {"passedResources": 0, "failedResources": 0, "skippedResources": 0, "excludedResources": 0},
                **changes}

    def test_kubescape_explicit_irrelevant_empty_controls_are_not_applicable(self):
        report = self.kube({"C-1": self.irrelevant_control()})
        self.assertEqual(report["verdict"], "N/A")
        self.assertEqual(report["summary"]["not applicable"], 1)
        self.assertEqual(report["summary"]["controls passed"], 0)
        self.assertEqual(report["checks"][0]["status"], "NOT_APPLICABLE")
        self.assertEqual(report["findings"][0]["evidence"]["statusInfo"]["subStatus"], "irrelevant")
        mixed = self.kube({"C-1": self.irrelevant_control(), "C-2": {"status": "passed"}})
        self.assertEqual(mixed["verdict"], "PASS")
        self.assertEqual(mixed["summary"]["controls passed"], 1)

    def test_kubescape_irrelevant_substatus_alone_does_not_prove_no_applicable_resources(self):
        for counters in ({}, {"passedResources": 0},
                         {"passedResources": 1, "failedResources": 0, "skippedResources": 0, "excludedResources": 0}):
            with self.subTest(counters=counters):
                report = self.kube({"C-1": self.irrelevant_control(ResourceCounters=counters)})
                self.assertEqual(report["verdict"], "PASS")
                self.assertEqual(report["summary"]["not applicable"], 0)

    def test_kubescape_not_applicable_does_not_hide_unevaluated_checks_or_errors(self):
        for substatus in ("irrelevant", "notEvaluated", "configuration", "manual review", "integration"):
            skipped = {"status": "skipped", "statusInfo": {"status": "skipped", "subStatus": substatus}}
            report = self.kube({"C-1": self.irrelevant_control(), "C-2": skipped})
            self.assertEqual(report["verdict"], "INCOMPLETE")
            self.assertTrue(any(f["status"] == "SKIP" for f in report["findings"]))
        self.assertEqual(self.kube({"C-1": self.irrelevant_control()}, rc=2)["verdict"], "INCOMPLETE")
        self.assertEqual(self.kube({"C-1": self.irrelevant_control(), "C-2": {"status": "failed", "severity": "HIGH"}})["verdict"], "FAIL")

    def test_kubescape_explicit_incomplete_coverage_cannot_be_hidden_by_passes(self):
        partial = {"status": "passed", "statusInfo": {"status": "passed", "subStatus": "incompleteCoverage"}}
        for additional in ({}, {"C-2": {"status": "passed"}}, {"C-2": self.irrelevant_control()}):
            with self.subTest(additional=additional):
                report = self.kube({"C-1": partial, **additional})
                self.assertEqual(report["verdict"], "INCOMPLETE")
                row = next(f for f in report["findings"] if f["id"] == "C-1")
                self.assertEqual(row["status"], "UNKNOWN")
                self.assertEqual(row["evidence"], partial)
                self.assertIn("incomplete resource coverage", row["detail"])
                self.assertIn("incompleteCoverage", row["reason"])
                self.assertIn("restore the missing resource coverage", row["remediation"])
                self.assertTrue(any("incompleteCoverage" in d for d in report["diagnostics"]))

    def test_kubescape_failure_precedes_incomplete_coverage(self):
        for severity, verdict in (("HIGH", "FAIL"), ("LOW", "INCOMPLETE")):
            with self.subTest(severity=severity):
                report = self.kube({"C-1": {"status": "failed", "severity": severity,
                                          "statusInfo": {"status": "failed", "subStatus": "incompleteCoverage"}}})
                self.assertEqual(report["verdict"], verdict)
                self.assertEqual(report["findings"][0]["status"], "FAIL")
                self.assertTrue(report["diagnostics"])

    def test_kubescape_nonfinite_or_out_of_range_score_cannot_choose_a_severity(self):
        for factor in (float("nan"), float("inf"), float("-inf"), -1, 11):
            with self.subTest(factor=factor):
                report = self.kube({"C-1": {"status": "failed", "scoreFactor": factor}})
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertEqual(report["findings"][0]["severity"], "UNKNOWN")
        for score in (float("nan"), float("inf"), -1, 101):
            with self.subTest(score=score):
                report = self.kube({"C-1": {"status": "passed"}}, complianceScore=score)
                self.assertEqual(report["summary"]["compliance score"], "unknown")

    def test_success_exit_with_execution_errors_stays_incomplete_and_diagnostics_are_safe(self):
        fixtures = ((scan.kube, {"summaryDetails": {"controls": {"C-1": {"status": "passed"}}}}),
                    (scan.images, {"Results": [{"Target": "apps/demo", "Vulnerabilities": []}]}))
        for scanner, data in fixtures:
            for message in ("ERROR unexpected failure", "AccessDeniedException", "EndpointConnectionError"):
                with self.subTest(scanner=scanner.__name__, message=message):
                    report = self.tool_scan(scanner, data, stderr=message + " secret-value")
                    self.assertEqual(report["verdict"], "INCOMPLETE")
                    self.assertIn("1 execution/permission/endpoint", report["diagnostics"][0])
                    self.assertNotIn("secret-value", json.dumps(report))

    def test_kubescape_malformed_top_level_is_actionable(self):
        for data in ([], {"summaryDetails": []}, {"summaryDetails": {"controls": [1]}}):
            with self.subTest(data=data), self.assertRaises(ui.Abort) as caught:
                self.tool_scan(scan.kube, data)
            self.assertIn("invalid report", str(caught.exception))

    def test_operator_preserves_every_severity_and_raw_evidence(self):
        vulnerabilities = [{"severity": severity, "vulnerabilityID": f"CVE-{severity}", "description": "full explanation", "fixedVersion": "2.0"}
                           for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")]
        report = self.operator(vulnerabilities)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(len(report["findings"]), 5)
        self.assertEqual([f["severity"] for f in report["findings"]], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
        self.assertEqual(report["findings"][-1]["evidence"]["description"], "full explanation")
        self.assertEqual(len(json.loads(Path(report["raw"]).read_text())["items"][0]["report"]["vulnerabilities"]), 5)

    def test_image_unknown_severity_explains_missing_explicit_and_unsupported_values(self):
        for value, expected in ((None, "did not supply"), ("UNKNOWN", "explicitly reported UNKNOWN"), ("future-severity", "unsupported vulnerability severity")):
            with self.subTest(value=value):
                operator_vuln = {"vulnerabilityID": "CVE-fixture", "severity": value}
                cli_vuln = {"VulnerabilityID": "CVE-fixture", "Severity": value}
                reports = (self.operator([operator_vuln]),
                           self.tool_scan(scan.images, {"Results": [{"Target": "apps/demo", "Vulnerabilities": [cli_vuln]}]}))
                for report, original in zip(reports, (operator_vuln, cli_vuln)):
                    finding = report["findings"][0]
                    self.assertEqual(report["verdict"], "INCOMPLETE")
                    self.assertEqual(finding["severity"], "UNKNOWN")
                    self.assertIn(expected, finding["reason"])
                    self.assertIn(expected, finding["detail"])
                    self.assertIn("vendor advisory", finding["remediation"])
                    self.assertEqual(finding["evidence"], original)

    def test_operator_actual_zero_summary_can_pass(self):
        report = self.operator()
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["reports observed"], 1)
        self.assertFalse(report["diagnostics"])

    def test_operator_missing_details_and_malformed_records_cannot_pass(self):
        for report in (self.operator(summary={"highCount": 2}), self.operator(summary={}),
                       self.operator(summary={"criticalCount": "unknown"}), self.operator(items=[{}]),
                       self.operator(items=[None]), self.operator(items=[{"report": "broken"}])):
            self.assertEqual(report["verdict"], "INCOMPLETE")
            self.assertTrue(report["diagnostics"])
        self.assertEqual(self.operator(summary={"criticalCount": 1})["verdict"], "FAIL")

    def test_image_malformed_falsy_vulnerability_containers_cannot_pass(self):
        for value in ({}, False, 0, ""):
            with self.subTest(value=value):
                operator = self.operator(items=[{"report": {"summary": {"criticalCount": 0}, "vulnerabilities": value}}])
                cli = self.tool_scan(scan.images, {"Results": [{"Target": "apps/demo", "Vulnerabilities": value}]})
                for report in (operator, cli):
                    self.assertEqual(report["verdict"], "INCOMPLETE")
                    self.assertTrue(any("vulnerability details are malformed" in d for d in report["diagnostics"]))

    def test_image_null_or_absent_vulnerability_lists_can_represent_clean_results(self):
        for detail in ({}, {"vulnerabilities": None}):
            with self.subTest(detail=detail):
                report = self.operator(items=[{"report": {"summary": {"criticalCount": 0}, **detail}}])
                self.assertEqual(report["verdict"], "PASS")
        for detail in ({}, {"Vulnerabilities": None}):
            with self.subTest(detail=detail):
                report = self.tool_scan(scan.images, {"Results": [{"Target": "apps/demo", "Class": "os-pkgs", **detail}]})
                self.assertEqual(report["verdict"], "PASS")

    def test_operator_severity_counts_require_nonnegative_integers(self):
        for value in (0.5, 0.0, True, False, "0", -1, None, {}, []):
            with self.subTest(value=value):
                report = self.operator(summary={"criticalCount": value})
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertTrue(any("critical total is invalid" in d for d in report["diagnostics"]))

    def test_trivy_partial_and_empty_reports_are_incomplete(self):
        for data, rc in (({}, 0), ([], 0), ({"Results": []}, 0), ({"Results": [{"Vulnerabilities": []}]}, 2),
                         ({"Results": [{"Vulnerabilities": [], "Error": "target inaccessible"}]}, 0),
                         ({"Results": [{"Vulnerabilities": "bad"}]}, 0)):
            with self.subTest(data=data, rc=rc):
                self.assertEqual(self.tool_scan(scan.images, data, rc)["verdict"], "INCOMPLETE")

    def test_trivy_retains_low_findings_and_target_before_recursing(self):
        data = {"Results": [{"Target": "apps/demo", "Vulnerabilities": [
            {"Severity": "LOW", "VulnerabilityID": "CVE-low", "Description": "full description", "FixedVersion": "3.0"}]}]}
        report = self.tool_scan(scan.images, data)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["findings"][0]["resource"], "apps/demo")
        self.assertEqual(report["findings"][0]["evidence"]["Description"], "full description")
        self.assertIn("Critical", report["failure_policy"])

    def test_trivy_clean_evaluated_target_can_pass(self):
        data = {"Results": [{"Target": "apps/demo", "Class": "os-pkgs", "Type": "debian"}]}
        self.assertEqual(self.tool_scan(scan.images, data)["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
