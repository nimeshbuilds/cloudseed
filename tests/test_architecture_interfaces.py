"""Well-Architected assessments through MCP, console actions, reports and browser rendering.

Only temporary files and local Python/node subprocesses; no cloud calls, tool installations or host changes.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-architecture-interfaces-"))

from cloudseed import mcp, paths, webui  # noqa: E402


class ArchitectureToolTests(unittest.TestCase):
    def test_shared_schema_and_argv_without_infrastructure_confirmation(self):
        args = {"kind": "architecture", "cloud": "azure", "env": "prod", "profile": "production", "max_age_days": 14, "json": True}
        expected = ["scan", "architecture", "azure", "--env", "prod", "--profile", "production", "--max-age-days", "14", "--json", "-y"]
        with mock.patch.object(mcp, "_run", return_value={"ran": True}) as run:
            self.assertEqual(mcp.call_tool("cloudseed_scan", args, {}), {"ran": True})
            self.assertEqual(run.call_args.args[1], expected)
        with mock.patch.object(webui.deps, "find", side_effect=AssertionError("local assessment must not check scanners")):
            self.assertEqual(webui.build_argv("cloudseed_scan", args), expected)
        t = mcp.TOOLS["cloudseed_scan"]
        self.assertFalse(mcp.needs_confirm(t, args))
        self.assertFalse(webui.is_destructive("cloudseed_scan", t, args))
        # The mixed scan tool still exposes destructive security scans; never advertise the whole tool as read-only.
        exposed = next(t for t in mcp.tool_list() if t["name"] == "cloudseed_scan")
        self.assertFalse(exposed["annotations"]["readOnlyHint"])
        props = exposed["inputSchema"]["properties"]
        self.assertIn("architecture", props["kind"]["enum"])
        self.assertEqual(props["max_age_days"]["minimum"], 1)
        self.assertEqual(props["max_age_days"]["maximum"], 3650)
        ui = next(t for t in webui.actions_catalog() if t["name"] == "cloudseed_scan")
        self.assertEqual(ui["schema"]["properties"]["max_age_days"]["type"], "integer")

    def test_defaults_and_lab_options_preserve_existing_security_scan_arguments(self):
        self.assertEqual(webui.build_argv("cloudseed_scan", {"kind": "architecture"}), ["scan", "architecture", "-y"])
        self.assertEqual(webui.build_argv("cloudseed_scan", {"kind": "architecture", "profile": "lab", "json": False}),
                         ["scan", "architecture", "--profile", "lab", "-y"])
        self.assertEqual(webui.build_argv("cloudseed_scan", {"kind": "host", "profile": "stig", "hosts": "bastion, k8s", "confirm": True}),
                         ["scan", "host", "--profile", "stig", "--host", "bastion,k8s", "-y"])
        for kind in ("cis", "kube", "images", "host", "stig", "cloud", "all"):
            with self.subTest(kind=kind):
                with self.assertRaises(webui.NeedsConfirm):
                    webui.build_argv("cloudseed_scan", {"kind": kind})

    def test_invalid_values_stop_before_mcp_or_console_execution(self):
        for field, value in (("max_age_days", 0), ("max_age_days", 3651), ("max_age_days", True), ("max_age_days", 1.5),
                             ("profile", "certified"), ("json", "true")):
            with self.subTest(field=field, value=value):
                args = {"kind": "architecture", field: value}
                with mock.patch.object(mcp, "_run", side_effect=AssertionError("invalid call ran")):
                    result = mcp.call_tool("cloudseed_scan", args, {})
                self.assertTrue(result["isError"])
                self.assertIn(field, result["content"][0]["text"])
                with self.assertRaises(ValueError):
                    webui.build_argv("cloudseed_scan", args)

    def test_raw_console_architecture_call_is_not_an_infrastructure_change(self):
        self.assertEqual(webui.raw_argv({"argv": ["scan", "architecture", "gcp", "--env", "prod"]}),
                         ["-y", "scan", "architecture", "gcp", "--env", "prod"])
        for argv in (["scan", "all", "aws"], ["scan", "cloud", "gcp"], ["scan", "--unknown", "architecture"]):
            with self.assertRaises(webui.NeedsConfirm):
                webui.raw_argv({"argv": argv})

    def test_json_assessment_keeps_full_report_and_exit_status_on_fail_or_incomplete(self):
        # Larger than the ordinary text-output cap: truncating this would discard checks and break JSON clients.
        fake = "import json,sys; rc=int(sys.argv[-1]); print(json.dumps({'verdict': {0:'PASS',1:'FAIL',3:'INCOMPLETE'}[rc], 'evidence':'x'*20000})); sys.stderr.write('saved report\\n'); sys.exit(rc)"
        for rc in (0, 1, 3):
            with self.subTest(rc=rc), mock.patch.object(mcp, "_launcher", return_value=[sys.executable, "-c", fake]), mock.patch.object(mcp, "_log"):
                result = mcp._spawn("cloudseed_scan", ["scan", "architecture", "--json", str(rc)], dict(os.environ))
            parsed = json.loads(result["content"][0]["text"])
            self.assertEqual(parsed, result["structuredContent"])
            self.assertEqual(len(parsed["evidence"]), 20000)
            self.assertEqual(result["isError"], rc != 0)
            self.assertIn(f"exit code: {rc}", result["content"][1]["text"])
            self.assertIn("saved report", result["content"][1]["text"])


class ArchitectureReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cs-architecture-reports-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        patch = mock.patch.object(paths, "ENVS_DIR", self.root / "envs")
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(paths, "WORKDIRS_INDEX", self.root / "workdirs.json")
        patch.start()
        self.addCleanup(patch.stop)
        self.env = paths.Env("aws", "prod")
        (self.env.dir / "scans").mkdir(parents=True)
        (self.env.dir / "config.json").write_text(json.dumps({"cloud": "aws", "env": "prod", "vars": {}}))

    def test_reports_and_latest_verdict_preserve_incomplete_and_evidence(self):
        data = {"run": "20260924-120000", "verdict": "INCOMPLETE", "summary": {"passed": 2, "failed": 0, "unknown": 1},
                "profile": "production", "max_age_days": 14, "scope": "saved configuration and evidence",
                "coverage_limits": ["Not full framework compliance or certification"],
                "findings": [{"status": "UNKNOWN", "pillar": "reliability", "title": "Restore evidence", "detail": "No recent drill",
                              "evidence": ["No saved report"], "remediation": "Run a restore drill", "references": ["https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html"]}]}
        report = self.env.dir / "scans" / "architecture-20260924-120000.json"
        report.write_text(json.dumps(data))
        (self.env.dir / "scans" / "prowler-raw-20260924-120001.json").write_text('{"verdict":"PASS"}')
        rows = webui.reports(self.env.id)["scans"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "architecture")
        self.assertEqual(rows[0]["verdict"], "INCOMPLETE")
        self.assertEqual(rows[0]["findings"], data["findings"])
        self.assertEqual(rows[0]["profile"], "production")
        self.assertEqual(rows[0]["max_age_days"], 14)
        self.assertEqual(rows[0]["coverage_limits"], data["coverage_limits"])
        self.assertEqual(webui.verdicts(self.env)["architecture"]["verdict"], "INCOMPLETE")
        self.assertEqual(json.loads(webui.read_env_file(str(report))), data)

    def test_missing_verdict_never_becomes_a_pass(self):
        for data in ({}, {"summary": {"pass": 10, "fail": 0}}, {"findings": [{"status": "UNKNOWN"}]}):
            self.assertEqual(webui.scan_verdict("architecture", data), "INCOMPLETE")
        self.assertEqual(webui.scan_verdict("architecture", {"findings": [{"status": "FAIL"}]}), "FAIL")
        self.assertEqual(webui.scan_verdict("architecture", {"summary": {"failed": 2}}), "FAIL")
        self.assertEqual(webui.scan_verdict("architecture", {"verdict": "PASS"}), "PASS")


JS = (Path(webui.WEB_ROOT) / "app.js").read_text()
NODE = shutil.which("node")


def js_def(name):
    lines = JS.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith((f"const {name} = ", f"function {name}(")):
            depth, out = 0, []
            for j in range(i, len(lines)):
                out.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and (lines[j].rstrip().endswith((";", "}")) or j > i):
                    return "\n".join(out)
    raise AssertionError(f"JavaScript definition not found: {name}")


@unittest.skipUnless(NODE, "node is not installed")
class ArchitectureBrowserTests(unittest.TestCase):
    def node(self, definitions, code, prelude=""):
        source = prelude + "\n" + "\n".join(js_def(name) for name in definitions) + "\n" + code
        result = subprocess.run([NODE], input=source, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_incomplete_chip_and_unknown_checks_are_amber(self):
        result = self.node(["num", "scanResult", "verdictClass", "scanChip", "scanProfileOptions"], """
const chip = scanChip({kind:'architecture', verdict:'INCOMPLETE', summary:{passed:3, failed:0, unknown:2}});
console.log(JSON.stringify({chip, unknown:verdictClass('UNKNOWN'), profiles:scanProfileOptions('architecture'), host:scanProfileOptions('host')}));
""")
        self.assertEqual(result["chip"]["label"], "incomplete")
        self.assertEqual(result["chip"]["cls"], "seed")
        self.assertEqual(result["chip"]["w"], 2)
        self.assertEqual(result["chip"]["p"], 3)
        self.assertIn("2 unknown", result["chip"]["title"])
        self.assertEqual(result["unknown"], "seed")
        self.assertEqual(result["profiles"], ["production", "lab"])
        self.assertEqual(result["host"], ["cis", "stig"])

    def test_assessment_exit_three_is_incomplete_other_commands_still_fail(self):
        result = self.node(["interrupted", "jobState", "jobStatusText"], """
const base = {id:'a', running:false, rc:3, seconds:1};
const j = {...base, argv:['scan','architecture','aws']};
console.log(JSON.stringify({state:jobState(j), status:jobStatusText(j), other:jobState({...base,argv:['scan','cloud']}), failed:jobState({...j,rc:1})}));
""", "const INTERRUPTED = new Set();")
        self.assertEqual(result["state"], "incomplete")
        self.assertIn("incomplete assessment", result["status"])
        self.assertEqual(result["other"], "bad")
        self.assertEqual(result["failed"], "bad")

    def test_report_renders_pillars_status_evidence_and_remediation(self):
        prelude = """
const el=(tag,attrs={},...kids)=>({tag,attrs,kids:kids.flat(Infinity).filter(x=>x!==null&&x!==undefined),append(...xs){this.kids.push(...xs);}});
const text=n=>typeof n==='object' ? n.kids.map(text).join(' ') : String(n);
const kv=(...items)=>el('div',{},...items.flat()); const currentEnv=()=>({id:'aws-prod'}); let shown;
const links=n=>typeof n==='object' ? [...(n.tag==='a'?[n.attrs.href]:[]),...n.kids.flatMap(links)] : [];
const modal=(title,body)=>{shown={title,text:text(body),links:links(body)};}; const XQ_REPORT={scan:'scan'};
"""
        definitions = ["num", "scanResult", "verdictClass", "scanChip", "runKind", "runLabel", "REPORT_KIND", "SCAN_TITLES", "scanTitle", "reportChip", "COL_LABEL", "colLabel", "reportSummary", "cellChip", "showReport"]
        result = self.node(definitions, """
showReport({name:'architecture-20260924-120000',path:'/tmp/report.json',verdict:'INCOMPLETE',profile:'production',max_age_days:30,summary:{passed:1,unknown:1},coverage_limits:['Not full framework compliance or certification'],
 findings:[{status:'UNKNOWN',pillar:'reliability',title:'Recovery drill',detail:'No fresh drill',evidence:[{type:'saved_report',reason:'Report is 45 days old',live_verified:false}],remediation:'Run a verified restore drill',references:[{url:'https://example.test/provider_guidance'}]} ]});
console.log(JSON.stringify(shown));
""", prelude)
        self.assertIn("Well-Architected assessment", result["title"])
        for text in ("UNKNOWN", "reliability", "Report is 45 days old", "Run a verified restore drill", "does not verify live infrastructure", "Evidence freshness: 30 days",
                     "Not full framework compliance or certification", "Not checked live", "Provider guidance"):
            self.assertIn(text, result["text"])
        self.assertEqual(result["links"], ["https://example.test/provider_guidance"])


if __name__ == "__main__":
    unittest.main()
