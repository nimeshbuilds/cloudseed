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
from cloudseed import cli, evidence, scan, secrets, ui


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
                 ([observation("PASS")], {"output": "ERROR AccessDenied: password=secret-value-must-not-appear"}),
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
        result = scan._cloud_results([], returncode=7, output="AccessDenied password=secret-credential\nEndpointConnectionError https://user:secret@proxy/")
        reason = result["diagnostics"]["reason"]
        for message in ("zero observations", "code 7", "permission/access denial", "unreachable service endpoints"):
            self.assertIn(message, reason)
        self.assertNotIn("secret", json.dumps(result))
        self.assertIn("correct scanner access", result["diagnostics"]["next_step"])
        result = scan._cloud_results([observation("MANUAL", remediation={})])
        self.assertIn("manual verification", result["findings"][0]["reason"])
        self.assertTrue(result["findings"][0]["remediation"])

    def test_recorded_error_examples_explain_actual_cause_without_secrets(self):
        output = ('INFO: complete checks may coexist with collection errors\n'
                  '09/27/2026 03:02:35 AM [File: service.py:42] [Module: service] ERROR: AccessDenied while collecting fixture-service; password=private-value\n'
                  'EndpointConnectionError https://user:proxy-pass@proxy.invalid/\n'
                  'ERROR: request failed Authorization: Bearer abcdefghijklmnopqrstuv\n'
                  'ERROR: fixture custom credential registered-private-value\n'
                  '-----BEGIN ' + 'PRIVATE KEY-----\nkey-body-private-value\n-----END PRIVATE KEY-----')
        with mock.patch.object(secrets, '_literals', return_value=('registered-private-value',)):
            result = scan._cloud_results([observation('PASS')], output=output)
        diag = result['diagnostics']
        self.assertEqual(diag['error_lines'], 4)
        self.assertEqual(len(diag['error_examples']), 4)
        self.assertEqual(diag['error_examples_omitted'], 0)
        self.assertIn('collecting fixture-service', diag['error_examples'][0]['text'])
        self.assertIn('proxy.invalid', diag['error_examples'][1]['text'])
        for forbidden in ('private-value', 'proxy-pass', 'abcdefghijklmnopqrstuv'):
            self.assertNotIn(forbidden, json.dumps(result))
        self.assertEqual(result['verdict'], 'INCOMPLETE')
        self.assertEqual(scan._cloud_results([observation('FAIL')], output=output)['verdict'], 'FAIL')

    def test_zero_error_counters_and_prose_do_not_invent_collection_gaps(self):
        benign = ['error=0', 'ERROR=0', 'errors: 0', '{"error": 0}', '{"error": false}',
                  'INFO: error=0; findings=1', 'INFO: no error encountered', 'No errors were reported.',
                  'INFO: check verifies error logging is configured']
        for output in benign:
            with self.subTest(output=output):
                result = scan._cloud_results([observation('PASS')], output=output)
                self.assertEqual(result['diagnostics']['error_lines'], 0)
                self.assertEqual(result['verdict'], 'PASS')
        for output in ('ERROR: failed request', '[error] failed request', '{"level":"ERROR","message":"request failed"}',
                       'INFO: error=0\nERROR: actual failure'):
            with self.subTest(output=output):
                self.assertEqual(scan._cloud_results([observation('PASS')], output=output)['diagnostics']['error_lines'], 1)

    def test_diagnostic_examples_and_saved_output_have_explicit_bounds(self):
        output = '\n'.join('ERROR: issue-' + str(i) + 'x' * 1500 for i in range(12))
        diag = scan._cloud_results([observation('PASS')], output=output)['diagnostics']
        self.assertEqual(diag['error_lines'], 12)
        self.assertEqual(len(diag['error_examples']), 8)
        self.assertEqual(diag['error_examples_omitted'], 4)
        self.assertTrue(all(len(x['text']) == 1200 and x['omitted_characters'] > 0 for x in diag['error_examples']))
        with tempfile.TemporaryDirectory() as tmp:
            env = SimpleNamespace(dir=Path(tmp), id='aws-fixture')
            outdir = env.dir / 'scans/prowler-20260927-030241'
            outdir.mkdir(parents=True)
            with mock.patch.object(scan, '_CLOUD_DIAGNOSTIC_CHAR_LIMIT', 300):
                saved = scan._cloud_output_artifact(env, outdir, stdout='prefix-' + 'x' * 2000 + '-suffix',
                                                   stderr='ERROR: password=private-value')
            self.assertFalse(saved['output_complete'])
            self.assertEqual(saved['output_saved_characters'], 300)
            self.assertEqual(saved['output_total_characters'] - 300, saved['output_omitted_characters'])
            page = evidence.read_artifact(env, saved['output_artifact'])
            self.assertTrue(page['complete'])
            self.assertIn('Cloudseed omitted', page['content'])
            self.assertIn('-suffix', page['content'])
            self.assertNotIn('private-value', page['content'])
            self.assertEqual((outdir / 'prowler.log').stat().st_mode & 0o777, 0o600)

    def test_cloud_scan_persists_readable_diagnostics_on_success_and_failure(self):
        for scenario in ('complete', 'no-report', 'timeout', 'invalid-json'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                env = SimpleNamespace(dir=Path(tmp), id='aws-fixture')
                def run(cmd, **kwargs):
                    if scenario == 'timeout':
                        raise subprocess.TimeoutExpired(cmd, 7200, output=b'INFO: started', stderr=b'ERROR: deadline password=private-value')
                    directory = Path(cmd[cmd.index('-o') + 1])
                    if scenario != 'no-report':
                        (directory / 'prowler.ocsf.json').write_text('broken' if scenario == 'invalid-json' else json.dumps([observation('PASS')]))
                    return subprocess.CompletedProcess(cmd, 0 if scenario == 'complete' else 1,
                                                       'INFO: collected fixture records', 'ERROR: fixture service unavailable password=private-value')
                with mock.patch.object(scan, '_prowler', return_value='fake-prowler'), \
                     mock.patch.object(scan.subprocess, 'run', side_effect=run), \
                     mock.patch.object(scan.audit, 'note'), contextlib.redirect_stdout(io.StringIO()):
                    if scenario == 'complete':
                        path = scan.cloud_scan(SimpleNamespace(key='aws', local=False), env, {'vars': {}}, framework='test')
                        report = json.loads(path.read_text())
                        self.assertEqual(report['verdict'], 'INCOMPLETE')
                        self.assertIn('fixture service unavailable', report['diagnostics']['error_examples'][0]['text'])
                        self.assertTrue(report['diagnostics']['output_complete'])
                        artifact = report['diagnostics']['output_artifact']
                    else:
                        with self.assertRaises(ui.Abort) as error:
                            scan.cloud_scan(SimpleNamespace(key='aws', local=False), env, {'vars': {}}, framework='test')
                        self.assertNotIn('private-value', str(error.exception))
                        artifact = evidence.list_artifacts(env)['artifacts'][0]['artifact']
                        if scenario != 'invalid-json':
                            self.assertIn(artifact, str(error.exception))
                log = next(env.dir.glob('scans/prowler-*/prowler.log'))
                text = evidence.read_artifact(env, str(log.relative_to(env.dir)))['content']
                self.assertIn('[stderr]', text)
                self.assertIn('[stdout]', text)
                self.assertNotIn('private-value', text)
                self.assertIn('[REDACTED]', text)

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
