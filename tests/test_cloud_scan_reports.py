"""Cloud findings, incomplete coverage and comprehensive exports across providers."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-scan-reports-"))
from cloudseed import cli, scan, ui


def observation(status="FAIL", severity="Medium", **changes):
    row = {"status": "New", "status_code": status, "severity": severity,
           "finding_info": {"analytic": {"uid": "example_check"}, "title": "Desired secure state"},
           "status_detail": "The resource does not have this protection enabled.",
           "resources": [{"uid": "resource-one"}, {"uid": "resource-two"}],
           "cloud": {"region": "example-region"},
           "remediation": {"desc": "Review the setting and enable protection.", "references": ["https://example.com/check"]}}
    row.update(changes)
    return row


class CloudReportTests(unittest.TestCase):
    def test_all_severities_and_manual_findings_preserve_details(self):
        rows = [observation(severity=s) for s in ("Critical", "High", "Medium", "Low", "Informational")]
        rows += [observation("MANUAL"), observation("PASS"), observation("unrecognized", "invalid")]
        result = scan._cloud_results(rows)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["summary"]["fail"], 5)
        self.assertEqual(result["summary"]["manual"], 1)
        self.assertEqual(result["summary"]["unknown"], 1)
        self.assertEqual(len(result["findings"]), 7)
        f = result["findings"][0]
        self.assertEqual(f["id"], "example_check")
        self.assertEqual(f["resources"], ["resource-one", "resource-two"])
        self.assertEqual(f["detail"], rows[0]["status_detail"])
        self.assertEqual(f["remediation"], rows[0]["remediation"]["desc"])
        self.assertEqual(f["region"], "example-region")

    def test_partial_empty_and_manual_reports_never_pass(self):
        cases = [([], {}), ([observation("MANUAL")], {}), ([None], {}),
                 ([observation("PASS")], {"returncode": 1}),
                 ([observation("PASS")], {"output": "ERROR AccessDenied: secret must not appear"}),
                 ([observation("PASS")], {"output": 'Could not connect to the endpoint URL: https://user:secret@proxy/'})]
        for rows, args in cases:
            with self.subTest(rows=rows, args=args):
                result = scan._cloud_results(rows, **args)
                self.assertEqual(result["verdict"], "INCOMPLETE")
                self.assertEqual(scan.cloud_verdict(result), "INCOMPLETE")
                self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(scan._cloud_results([observation("PASS")])["verdict"], "PASS")

    def test_malformed_shapes_are_unknown_or_explained(self):
        for value in ({}, None, "not a report"):
            with self.assertRaises(ui.Abort):
                scan._cloud_results(value)
        result = scan._cloud_results([{"status": "New", "finding_info": [], "resources": {}, "remediation": []}])
        self.assertEqual(result["verdict"], "INCOMPLETE")

    def test_every_unknown_has_its_specific_cause_and_next_action(self):
        cases = [(None, "not an OCSF object"), ({}, "no check result"),
                 ({"status": "New"}, "lifecycle status"),
                 (observation("UNKNOWN"), "explicitly marked"),
                 (observation("FUTURE_RESULT"), "unsupported check result"),
                 (observation({"unexpected": "shape"}), "unsupported check result")]
        for record, cause in cases:
            with self.subTest(cause=cause, record=record):
                result = scan._cloud_results([record])
                finding = result["findings"][0]
                self.assertEqual(finding["status"], "UNKNOWN")
                self.assertIn(cause, finding["detail"])
                self.assertIn(cause, finding["reason"])
                self.assertIn("raw Prowler report", finding["remediation"])
                self.assertIn("no recognized result", result["diagnostics"]["reason"])
                if isinstance(record, dict) and record.get("status_detail"):
                    self.assertIn(record["status_detail"], finding["detail"])

    def test_unidentifiable_pass_is_an_explained_gap_and_cannot_hide_failure(self):
        for info in (None, [], {}, {"analytic": {"uid": " "}}):
            row = observation("PASS", finding_info=info)
            result = scan._cloud_results([row])
            self.assertEqual(result["verdict"], "INCOMPLETE")
            self.assertEqual(result["summary"]["pass"], 0)
            self.assertEqual(result["summary"]["unknown"], 1)
            self.assertIn("finding_info.analytic.uid", result["findings"][0]["reason"])
            self.assertEqual(result["findings"][0]["scanner_status"], "PASS")
            self.assertEqual(scan._cloud_results([row, observation("FAIL")])["verdict"], "FAIL")

    def test_execution_and_empty_gaps_have_safe_specific_explanations(self):
        result = scan._cloud_results([], returncode=7, output="AccessDenied secret-credential\nEndpointConnectionError https://user:secret@proxy/")
        reason = result["diagnostics"]["reason"]
        for message in ("zero observations", "code 7", "permission/access denial", "unreachable service endpoints"):
            self.assertIn(message, reason)
        self.assertNotIn("secret", json.dumps(result))
        self.assertIn("correct scanner access", result["diagnostics"]["next_step"])
        result = scan._cloud_results([observation("MANUAL", remediation={})])
        self.assertIn("manual verification", result["findings"][0]["reason"])
        self.assertTrue(result["findings"][0]["remediation"])

    def test_legacy_medium_fail_and_corrupt_counts_cannot_pass(self):
        self.assertEqual(scan.cloud_verdict({"verdict": "PASS", "summary": {"pass": 135, "fail": 14}}), "FAIL")
        for sm in ({}, {"pass": 1}, {"pass": 1, "fail": -1}, {"pass": 1, "fail": "0"}):
            self.assertEqual(scan.cloud_verdict({"verdict": "PASS", "summary": sm}), "INCOMPLETE")
        self.assertEqual(scan.cloud_verdict({"summary": {"pass": 2, "fail": 0}}), "PASS")

    def test_cloud_end_to_end_normalization_all_three_providers(self):
        for provider in ("aws", "gcp", "azure"):
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as tmp:
                env = SimpleNamespace(dir=Path(tmp), id=provider + "-fixture")
                cfg = {"vars": {"project_id": "test-project", "subscription_id": "test-subscription"}}
                calls = []
                def run(cmd, **kwargs):
                    calls.append(cmd)
                    directory = Path(cmd[cmd.index("-o") + 1])
                    (directory / "prowler.ocsf.json").write_text(json.dumps([observation(), observation("MANUAL")]))
                    return subprocess.CompletedProcess(cmd, 0, "", "")
                with mock.patch.object(scan, "_prowler", return_value="fake-prowler"), \
                     mock.patch.object(scan, "_azure_auth", return_value=["--az-cli-auth"]), \
                     mock.patch.object(scan.subprocess, "run", side_effect=run), \
                     mock.patch.object(scan.audit, "note"), contextlib.redirect_stdout(io.StringIO()):
                    path = scan.cloud_scan(SimpleNamespace(key=provider, local=False), env, cfg, framework="test")
                report = json.loads(path.read_text())
                self.assertEqual(report["verdict"], "FAIL")
                self.assertEqual(report["env"], env.id)
                self.assertEqual(report["cloud"], provider)
                self.assertIn("outside this Cloudseed environment", report["scope"])
                self.assertEqual(len(report["findings"]), 2)
                self.assertEqual(cli._report_verdict(path), "FAIL")
                self.assertIn("Review the setting", path.with_suffix(".md").read_text())
                self.assertEqual(len(calls), 1)

    def test_markdown_keeps_every_finding_without_cutting_details(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(scan.audit, "note"):
            env = SimpleNamespace(dir=Path(tmp), id="vmware-report")
            findings = [{"status": "FAIL", "title": f"finding-{i}", "detail": "x" * 200 + "END",
                         "remediation": "review-" + str(i)} for i in range(205)]
            report = {"findings": findings, "summary": {}, "verdict": "FAIL", "coverage_limits": ["Coverage limit"],
                      "checks": [{"status": "UNKNOWN", "detail": "unreachable host"}], "hosts": {"bastion": {"error": "no response"}}}
            path = scan.save_report(env, "host-cis", report)
            md = path.with_suffix(".md").read_text()
            self.assertIn("finding-204", md)
            self.assertIn("x" * 200 + "END", md)
            self.assertIn("review-204", md)
            self.assertIn("unreachable host", md)
            self.assertIn("Coverage limit", md)

    def test_cli_incomplete_scan_exits_three_and_failure_takes_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = SimpleNamespace(dir=Path(tmp), id="aws-test")
            cloud = SimpleNamespace(key="aws")
            for verdict, expected in (("PASS", 0), ("FAIL", 1), ("INCOMPLETE", 3)):
                with self.subTest(verdict=verdict):
                    path = Path(tmp) / "cloud-20260926-120000.json"
                    report = {"kind": "cloud", "verdict": verdict, "summary": {"pass": 1, "fail": int(verdict == "FAIL")}}
                    path.write_text(json.dumps(report))
                    args = cli.build_parser().parse_args(["scan", "cloud", "aws", "--env", "test"])
                    with mock.patch.object(cli, "_resolve_plain_env"), \
                         mock.patch.object(cli, "_load_env", return_value=(cloud, env, {"vars": {}})), \
                         mock.patch.object(cli, "_cached_outputs", return_value={}), \
                         mock.patch.object(cli.scan, "cloud_scan", return_value=path), \
                         mock.patch.object(cli, "_scan_outputs", return_value=[]):
                        self.assertEqual(cli.cmd_scan(args, {}), expected)


if __name__ == "__main__":
    unittest.main()
