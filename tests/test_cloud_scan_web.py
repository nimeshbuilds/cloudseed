"""Scan report presentation keeps findings, scope, evidence and limits across scan kinds.

Only temporary report fixtures and local Node subprocesses; no cloud, credentials or real environments.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-scan-web-"))

from cloudseed import paths, webui  # noqa: E402

JS = (Path(webui.WEB_ROOT) / "app.js").read_text()
NODE = shutil.which("node")
FINDING = {"id": "ec2_networkacl_allow_ingress_any_port", "status": "FAIL", "severity": "LOW",
           "title": "Restrict network ACL ingress", "detail": "The ACL allows traffic on every port.",
           "resource": "arn:aws:ec2:us-east-1:000000000000:network-acl/acl-test", "resources": ["acl-test", "acl-other"],
           "region": "us-east-1", "remediation": "Review routing and security groups before narrowing the ACL.",
           "references": ["https://docs.example.test/network-acl"],
           "evidence": [{"observations": ["public route", "private subnet"], "live_verified": True}]}


class ScanReportBackendTests(unittest.TestCase):
    def test_cis_informational_rows_do_not_force_incomplete(self):
        for kind in ("cis", "stig-k8s"):
            for verdict in (None, "PASS"):
                with self.subTest(kind=kind, verdict=verdict):
                    base = {"summary": {"pass": 2, "fail": 0, "info": 1}, "findings": [{"status": "INFO"}]}
                    if verdict:
                        base["verdict"] = verdict
                    self.assertEqual(webui.scan_verdict(kind, base), "PASS")
                    base["summary"]["pass"] = 0
                    self.assertEqual(webui.scan_verdict(kind, base), "N/A")
                    base["summary"]["warn"] = 1
                    self.assertEqual(webui.scan_verdict(kind, base), "INCOMPLETE")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cloudseed-scan-report-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = SimpleNamespace(id="aws-fixture", dir=self.root)
        patch = mock.patch.object(paths.Env, "list_all", return_value=[self.env])
        patch.start()
        self.addCleanup(patch.stop)
        (self.root / "scans").mkdir()

    def report(self, data, kind="cloud"):
        path = self.root / "scans" / f"{kind}-20260926-120000.json"
        path.write_text(json.dumps(data))
        return path

    def test_every_scan_retains_rich_findings_and_explicit_truncation(self):
        for kind in ("cloud", "kube", "images", "cis", "host-cis", "stig-host", "fips", "architecture", "health", "network"):
            data = {"schema_version": 1, "verdict": "FAIL", "summary": {"fail": 125}, "findings": [dict(FINDING, id=f"check-{i}") for i in range(125)],
                    "scope": "Current AWS account and selected region, including resources outside Cloudseed.",
                    "coverage_limits": ["Manual checks require review."], "diagnostics": {"process_exit_code": 0, "error_lines": 2, "raw_stderr": "do not expose"}}
            self.report(data, kind)
        rows = webui.reports(self.env.id)["scans"]
        self.assertEqual(len(rows), 10)
        for row in rows:
            with self.subTest(kind=row["kind"]):
                self.assertEqual(len(row["findings"]), 100)
                self.assertEqual(row["findings_total"], 125)
                self.assertTrue(row["findings_truncated"])
                self.assertEqual(row["findings"][0], dict(FINDING, id="check-0"))
                self.assertIn("outside Cloudseed", row["scope"])
                self.assertEqual(row["coverage_limits"], ["Manual checks require review."])
                self.assertEqual(row["diagnostics"], {"process_exit_code": 0, "error_lines": 2})

    def test_legacy_cloud_report_explicitly_warns_about_omitted_findings(self):
        self.report({"verdict": "PASS", "summary": {"pass": 20, "fail": 3}, "findings": []})
        row = webui.reports(self.env.id)["scans"][0]
        self.assertTrue(row["legacy_cloud_report"])
        self.assertEqual(row["verdict"], "FAIL")
        self.assertTrue(any("only high/critical" in limit for limit in row["coverage_limits"]))

    def test_no_scan_kind_can_call_an_empty_report_clean(self):
        for kind in ("cloud", "kube", "images", "cis", "host-cis", "stig-host", "fips", "architecture", "health", "network"):
            for data in ({}, {"verdict": "PASS"}, {"summary": {"pass": 0, "fail": 0}}):
                with self.subTest(kind=kind, data=data):
                    self.assertEqual(webui.scan_verdict(kind, data), "INCOMPLETE")
        self.assertEqual(webui.scan_verdict("fips", {"verdict": "N/A"}), "N/A")
        self.assertEqual(webui.scan_verdict("images", {"verdict": "PASS", "summary": {"reports observed": 3, "critical": 0}}), "PASS")

    def test_generic_scanner_diagnostics_and_failure_policy_reach_the_report(self):
        self.report({"verdict": "INCOMPLETE", "failure_policy": "Critical vulnerabilities fail this scan.",
                     "diagnostics": ["No readable image scan results were returned."]}, "images")
        row = webui.reports(self.env.id)["scans"][0]
        self.assertEqual(row["failure_policy"], "Critical vulnerabilities fail this scan.")
        self.assertEqual(row["diagnostics"], ["No readable image scan results were returned."])

    def test_unknown_reasons_and_resolution_reach_the_web_report(self):
        finding = dict(FINDING, status="UNKNOWN", reason="Prowler supplied no check result.",
                       remediation="Inspect the raw report and rerun the cloud scan.")
        self.report({"schema_version": 1, "verdict": "INCOMPLETE", "findings": [finding],
                     "diagnostics": {"process_exit_code": 7, "reason": "Prowler exited with code 7.",
                                     "next_step": "Review scanner access.", "raw_stderr": "do not expose"}})
        row = webui.reports(self.env.id)["scans"][0]
        self.assertEqual(row["findings"][0]["reason"], finding["reason"])
        self.assertEqual(row["findings"][0]["remediation"], finding["remediation"])
        self.assertEqual(row["diagnostics"]["reason"], "Prowler exited with code 7.")
        self.assertEqual(row["diagnostics"]["next_step"], "Review scanner access.")
        self.assertNotIn("raw_stderr", row["diagnostics"])

    def test_existing_scanner_truncation_and_result_caps_stay_visible(self):
        self.report({"findings": [FINDING], "findings_total": 450, "checks": [{"id": str(i)} for i in range(205)],
                     "results": [{"test": i} for i in range(203)]}, "images")
        row = webui.reports(self.env.id)["scans"][0]
        self.assertEqual((row["findings_total"], row["checks_total"], row["results_total"]), (450, 205, 203))
        self.assertTrue(all(row[key + "_truncated"] for key in ("findings", "checks", "results")))

    def test_full_saved_json_and_markdown_are_not_cut_to_log_tail(self):
        data = {"findings": [dict(FINDING, detail="x" * 450000)], "summary": {"fail": 1}}
        path = self.report(data)
        markdown = path.with_suffix(".md")
        markdown.write_text("# Start of complete report\n" + "explanation " * 40000 + "\nEnd")
        row = webui.reports(self.env.id)["scans"][0]
        self.assertEqual(row["markdown_path"], str(markdown))
        self.assertEqual(json.loads(webui.read_env_file(str(path))), data)
        self.assertEqual(webui.read_env_file(str(markdown)), markdown.read_text())

    def test_oversized_full_report_is_refused_explicitly(self):
        path = self.report({"summary": {"pass": 1}})
        with mock.patch.object(webui, "MAX_REPORT_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "display limit"):
                webui.read_env_file(str(path))

    def test_cloud_verdict_never_hides_low_severity_or_incomplete_coverage(self):
        cases = [({"verdict": "PASS", "summary": {"pass": 20, "fail": 1}, "findings": [FINDING]}, "FAIL"),
                 ({"verdict": "PASS", "summary": {"pass": 20, "fail": 0, "manual": 1}}, "INCOMPLETE"),
                 ({"summary": {"pass": 20, "unknown": 1}}, "INCOMPLETE"),
                 ({"summary": {"pass": 20}, "diagnostics": {"process_exit_code": 1}}, "INCOMPLETE"),
                 ({"summary": {"pass": 20}, "diagnostics": {"error_lines": 1}}, "INCOMPLETE"),
                 ({"verdict": "PASS", "summary": {"pass": 0, "fail": 0}}, "INCOMPLETE"),
                 ({"verdict": "PASS", "summary": {"pass": 20, "fail": 0}, "diagnostics": {"process_exit_code": 0, "error_lines": 0}}, "PASS")]
        for report, expected in cases:
            with self.subTest(report=report):
                self.assertEqual(webui.scan_verdict("cloud", report), expected)


def js_def(name):
    lines = JS.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith((f"const {name} = ", f"function {name}(")):
            depth, result = 0, []
            for j in range(i, len(lines)):
                result.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and (lines[j].rstrip().endswith((";", "}")) or j > i):
                    return "\n".join(result)
    raise AssertionError("JavaScript definition missing: " + name)


@unittest.skipUnless(NODE, "node is not installed")
class ScanReportBrowserTests(unittest.TestCase):
    def node(self, names, code, prelude=""):
        result = subprocess.run([NODE], input=prelude + "\n" + "\n".join(js_def(name) for name in names) + "\n" + code,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_all_scan_exit_three_jobs_are_incomplete(self):
        kinds = ["architecture", "cis", "kube", "images", "host", "stig", "cloud", "fips", "all"]
        result = self.node(["interrupted", "jobState"], "const kinds=" + json.dumps(kinds) + ";\n" + """
const jobs=kinds.map(kind=>jobState({id:kind,rc:3,argv:['-y','--runtime=local','scan',kind,'aws']}));
const others=[['scan','reports'],['ssh','aws','--','scan','cloud'],['--unknown','scan','cis']].map(argv=>jobState({id:'x',rc:3,argv}));
console.log(JSON.stringify({jobs,others}));
""", "const INTERRUPTED=new Set();")
        self.assertEqual(result["jobs"], ["incomplete"] * len(kinds))
        self.assertEqual(result["others"], ["bad"] * 3)

    def test_manual_findings_and_cloud_incomplete_chips_are_amber(self):
        result = self.node(["num", "scanResult", "verdictClass", "scanChip"], """
console.log(JSON.stringify({manual:verdictClass('MANUAL'), chip:scanChip({kind:'cloud',verdict:'INCOMPLETE',summary:{pass:10,fail:0,manual:2,unknown:1}})}));
""")
        self.assertEqual(result["manual"], "seed")
        self.assertEqual(result["chip"]["cls"], "seed")
        self.assertEqual(result["chip"]["w"], 3)
        self.assertIn("manual / unknown", result["chip"]["title"])

    def test_every_scan_dialog_shows_safe_rich_fields_scope_and_truncation(self):
        prelude = """
const el=(tag,attrs={},...kids)=>{if('html' in attrs || 'innerHTML' in attrs) throw Error('unsafe HTML rendering'); return {tag,attrs,kids:kids.flat(Infinity).filter(x=>x!==null&&x!==undefined),append(...xs){this.kids.push(...xs);}};};
const walk=n=>typeof n==='object' ? [n,...n.kids.flatMap(walk)] : [];
const text=n=>typeof n==='object' ? n.kids.map(text).join(' ') : String(n);
const kv=(...items)=>el('div',{},...items.flat()); const currentEnv=()=>({id:'aws-fixture'}); let shown;
const modal=(title,body)=>{shown={title,text:text(body),links:walk(body).filter(n=>n.tag==='a').map(n=>n.attrs.href),buttons:walk(body).filter(n=>n.tag==='button').map(text)};};
const XQ_REPORT={scan:'scan'};
"""
        names = ["num", "scanResult", "verdictClass", "scanChip", "runKind", "runLabel", "REPORT_KIND", "SCAN_TITLES", "scanTitle", "reportChip", "COL_LABEL", "colLabel", "reportSummary", "cellChip", "REPORT_COLS", "reportCell", "showReport"]
        finding = dict(FINDING, title="<img src=x onerror=alert(1)>", status="UNKNOWN", reason="Scanner supplied no recognized result.", references=FINDING["references"] + ["javascript:alert(1)"])
        code = "const finding=" + json.dumps(finding) + ";\n" + """
const shownReports=[];
for(const kind of ['cloud','cis','kube','images','host-cis','stig-host','fips','architecture','health','network']) {
 showReport({kind,name:kind+'-20260926-120000',path:'/tmp/report.json',markdown_path:'/tmp/report.md',verdict:'FAIL',summary:{pass:3,fail:1},
 scope:'Current account, including resources outside Cloudseed', coverage_limits:['Manual checks require review'], diagnostics:{process_exit_code:0,error_lines:1},
 findings:[finding],findings_total:105,findings_truncated:true,checks:[{status:'FAIL',check:'extra-check',extra:{nested:['retained-check-detail']}}]});
 shownReports.push(shown);
}
console.log(JSON.stringify(shownReports));
"""
        results = self.node(names, code, prelude)
        self.assertEqual(len(results), 10)
        for row in results:
            for value in (FINDING["id"], FINDING["resource"], "acl-other", FINDING["region"], FINDING["detail"], FINDING["remediation"],
                          "public route", "private subnet", "Current account", "Manual checks require review", "Scanner diagnostics", "error lines", "Showing 1 of 105 findings",
                          "retained-check-detail", "<img src=x onerror=alert(1)>", "Scanner supplied no recognized result."):
                self.assertIn(value, row["text"])
            if "Why this is unknown" in row["text"]:
                self.assertIn("How to resolve", row["text"])
            self.assertEqual(row["links"], FINDING["references"])
            self.assertEqual(row["buttons"], ["View full JSON", "View full Markdown"])


if __name__ == "__main__":
    unittest.main()
