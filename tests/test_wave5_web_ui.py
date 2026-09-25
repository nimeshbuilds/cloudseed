"""Wave-5 (final) regression tests for the web console and what it needed from the rest of cloudseed.

  * wizard rows: depends_on (a switched-off feature's settings are hidden, as setup does not ask them), the declared
    number ranges (workload VMs from 0, control planes 1-20, AWS AZs 1-5), AWS Security Hub under the regional baseline
  * app.js: hidden settings are neither checked nor sent, ignored environment variables say why, netmask notation in
    CIDRs (as the CLI reads it), a DR drill's RTO only for a PASS, the interrupt button names the next interrupt, the
    undo limits, Plan keeps nothing (setup --preview) except a rename's plan, the managed stopgap is gone
  * boot.js applies the picked theme before the first paint (the locked page too)
  * the MCP form: auth / service choices mapped to --[no-]auth / --[no-]service (new CLI flags)
  * secrets: an auth scheme in a secret-named header is kept and the credential after it masked
  * audit: the console's own records go through audit.record (via=ui); an MCP server's tool calls are via=mcp even when
    the server was started from a console job
  * docs: the audit record's `via`, Go >= 1.25, the new flags

Stdlib only; the JavaScript checks run under node (skipped without it). No network, no cloud, no listening sockets."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-wave5-web-"))

from cloudseed import audit, clouds, creds, mcp, netutil, paths, secrets, webui  # noqa: E402
from cloudseed.clouds.base import Question  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
WEB = Path(webui.WEB_ROOT)
JS = (WEB / "app.js").read_text()
BOOT = WEB / "boot.js"
NODE = shutil.which("node")

_ENV_VARS = ("AWS_PROFILE", "GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT",
             "CLOUDSDK_COMPUTE_ZONE", "ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID", "CLOUDSEED_UI", "CLOUDSEED_AGENT")


def js_def(name: str) -> str:
    """Source of `const name = ...;` in app.js, up to the line that ends the statement (braces balanced)."""
    lines = JS.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(f"const {name} = "):
            depth, out = 0, []
            for j in range(i, len(lines)):
                out.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and lines[j].rstrip().endswith(";"):
                    return "\n".join(out)
    raise AssertionError(f"{name} not found in app.js")


def body_of(start: str, end: str) -> str:
    i = JS.index(start)
    return JS[i:JS.index(end, i)]


class Isolated(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w5-webui-"))
        self.patches = [mock.patch.object(paths, "HOME", self.tmp / "cs"), mock.patch.object(creds, "STORE", self.tmp / "credentials.json"),
                        mock.patch.dict(os.environ), mock.patch.dict(webui._DEFAULTS, clear=True), mock.patch.dict(creds.APPLIED, clear=True)]
        for p in self.patches:
            p.start()
        for k in _ENV_VARS:
            os.environ.pop(k, None)
        (self.tmp / "cs").mkdir()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def catalog(self) -> dict:
        return {k: {q["key"]: q for q in c["questions"]} for k, c in webui.clouds_catalog().items()}


# ============================================================================================ wizard rows (backend)
class WizardRowTests(Isolated):
    def test_settings_name_the_feature_they_belong_to(self):
        q = self.catalog()
        self.assertEqual(q["aws"]["enable_security_hub"]["depends_on"], "enable_regional_baseline")
        self.assertEqual(q["aws"]["vpn_type"]["depends_on"], "enable_vpn")
        for cloud in ("aws", "gcp", "azure"):
            self.assertEqual(q[cloud]["kubernetes_node_count"]["depends_on"], "enable_kubernetes", cloud)
            self.assertNotIn("depends_on", q[cloud]["enable_kubernetes"])
        self.assertEqual(q["vmware"]["kubernetes_workers"]["depends_on"], "enable_kubernetes")
        self.assertNotIn("depends_on", q["vmware"]["workload_count"])
        # every depends_on names a yes/no question of the same cloud (the page hides by its answer)
        for cloud, rows in q.items():
            for key, row in rows.items():
                if "depends_on" in row:
                    self.assertEqual(rows[row["depends_on"]]["kind"], "bool", f"{cloud}.{key}")

    def test_a_parent_the_cloud_does_not_ask_is_not_sent(self):
        orphan = Question("kubernetes_extra", "An orphan", 1, kind="int")          # implied parent enable_kubernetes
        with mock.patch.object(clouds.get("aws"), "questions", [orphan]):
            rows = self.catalog()["aws"]
        self.assertNotIn("depends_on", rows["kubernetes_extra"])

    def test_the_declared_ranges_reach_the_number_fields(self):
        q = self.catalog()
        vm = q["vmware"]
        self.assertEqual(vm["workload_count"].get("minimum"), 0)                    # 0 workload VMs is a valid answer
        self.assertEqual((vm["kubernetes_control_planes"]["minimum"], vm["kubernetes_control_planes"]["maximum"]), (1, 20))
        self.assertEqual((vm["bastion_memory_mb"]["minimum"], vm["bastion_disk_gb"]["minimum"]), (512, 10))
        self.assertEqual((q["aws"]["az_count"]["minimum"], q["aws"]["az_count"]["maximum"]), (1, 5))

    def test_aws_security_hub_is_not_asked_without_the_regional_baseline(self):
        aws = clouds.get("aws")
        hub, regional = aws.question("enable_security_hub"), aws.question("enable_regional_baseline")
        self.assertEqual(hub.depends_on, "enable_regional_baseline")
        self.assertEqual(regional.follows, "enable_account_baseline")               # declared in the constructor
        self.assertTrue(aws.unused(hub, {"vars": {"enable_regional_baseline": False}}))
        self.assertFalse(aws.unused(hub, {"vars": {"enable_regional_baseline": True}}))
        # a missing regional answer follows the account-wide one (its default)
        self.assertTrue(aws.unused(hub, {"vars": {"enable_account_baseline": False}}))
        self.assertFalse(aws.unused(hub, {"vars": {}}))


# ============================================================================================ app.js helpers (node)
@unittest.skipUnless(NODE, "node is not installed")
class AppJsTests(unittest.TestCase):
    def node(self, code: str):
        out = subprocess.run([NODE, "-e", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_app_and_boot_parse(self):
        for f in ("app.js", "boot.js"):
            out = subprocess.run([NODE, "--check", str(WEB / f)], capture_output=True, text=True, timeout=60)
            self.assertEqual(out.returncode, 0, f + out.stderr)

    def test_a_switched_off_feature_hides_its_settings(self):
        code = js_def("isYes") + "\n" + js_def("unusedIn") + """
const qs = [{ key: 'enable_vpn', kind: 'bool' }, { key: 'vpn_type', depends_on: 'enable_vpn' }, { key: 'zone' },
  { key: 'orphan', depends_on: 'missing' }, { key: 'self', depends_on: 'self' }];
const at = (answers) => (q) => answers[q.key];
const u = (key, answers) => unusedIn(qs.find((q) => q.key === key), qs, at(answers));
console.log(JSON.stringify([u('vpn_type', { enable_vpn: false }), u('vpn_type', { enable_vpn: true }), u('vpn_type', { enable_vpn: 'no' }),
  u('vpn_type', { enable_vpn: 'Yes' }), u('vpn_type', { enable_vpn: 'maybe' }), u('vpn_type', { enable_vpn: 1 }), u('zone', {}),
  u('orphan', {}), u('self', {}), ['true', 'y', 'ON', '1', true, 1, 'false', 0, '', null].map(isYes)]));"""
        off, on, no, yes, maybe, one, free, orphan, selfdep, words = self.node(code)
        self.assertEqual((off, on, no, yes, maybe, one), (True, False, True, False, True, False))   # as base.as_bool reads them
        self.assertEqual((free, orphan, selfdep), (False, False, False))    # no parent, an unknown one, itself: always asked
        self.assertEqual(words, [True, True, True, True, True, True, False, False, False, False])

    def test_hidden_settings_are_neither_checked_nor_sent(self):
        wiz = body_of("views.create = (opts = {}) =>", "// ---------------------------------------------------------------- platform")
        self.assertIn("for (const q of questions()) { if (unused(q)) continue; const val = effective(q);", wiz)   # buildArgs
        self.assertIn("if (unused(q)) continue;   // (not asked, not sent", wiz)                                  # problems
        self.assertIn("fld.hidden = unused(q);", wiz)
        self.assertIn("if (lab) lab.hidden = unused(q);", wiz)                                                    # sync
        self.assertIn("|| unused(q)) continue;   // (setup does not ask", wiz)                                    # summary

    def test_an_ignored_environment_variable_says_why(self):
        wiz = body_of("views.create = (opts = {}) =>", "// ---------------------------------------------------------------- platform")
        self.assertIn("return `$${x.name} is set but ignored: ${p.startsWith(lead) ? 'it ' + p.slice(lead.length) : p}`;", wiz)
        self.assertIn("[own, fixed || blank, elsewhere, follows, zoneMove, ignored]", wiz)

    def test_netmask_notation_is_read_as_the_cli_reads_it(self):
        code = "\n".join(js_def(n) for n in ("ipv4", "maskLen", "cidrProblem", "allowProblem", "allowListProblem"))
        nets = ["10.0.0.0/255.255.0.0", "10.0.0.0/0.0.255.255", "10.0.0.1/255.255.0.0", "10.0.0.0/255.0.255.0", "10.0.0.0/255.255.0.00",
                "10.0.0.0/16", "10.0.0.0/33", "10.0.0.0/255.255.255.255", "10.0.0.0/"]
        allow = ["198.51.100.0/255.255.255.0", "198.51.100.7/255.255.255.255", "198.51.100.7/255.255.255.0", "0.0.0.0/0.0.0.0",
                 "10.0.0.0/254.0.0.0", "10.0.0.0/255.0.0.0, 11.0.0.0/255.0.0.0", "1.2.3.4/255.0.255.0", "198.51.100.7/0.0.0.0"]
        got = self.node(code + f"\nconsole.log(JSON.stringify([{json.dumps(nets)}.map(cidrProblem), {json.dumps(allow)}.map(allowListProblem),"
                               " ['255.255.255.0', '0.0.0.255', '0.0.0.0', '255.255.255.255', '255.0.255.0', '1.2.3'].map(maskLen)]));")
        for case, js in zip(nets, got[0]):
            self.assertEqual(js is None, netutil.validate_cidr(case) is None, f"{case}: console {js!r}")
        for case, js in zip(allow, got[1]):
            self.assertEqual(js is None, netutil.validate_cidr_list(case) is None, f"{case}: console {js!r}, CLI {netutil.validate_cidr_list(case)!r}")
        self.assertEqual(got[2], [24, 24, 0, 32, None, None])
        self.assertIn("did you mean 10.0.0.0/16", got[0][2])

    def test_a_netmask_is_the_same_network_as_its_prefix(self):
        # the CLI saves 10.0.0.0/255.255.0.0 as 10.0.0.0/16: typed again in either notation it is no change to send
        import ipaddress
        cases = ["10.0.0.0/255.255.0.0", "10.1.0.0/0.0.255.255", " 198.51.100.0/255.255.255.0 ", "10.0.0.0/16", "1.2.3.4"]
        got = self.node("\n".join(js_def(n) for n in ("ipv4", "maskLen", "netText"))
                        + f"\nconsole.log(JSON.stringify([{json.dumps(cases)}.map(netText), netText('10.0.0.0/255.0.255.0'), netText(undefined)]));")
        for case, js in zip(cases, got[0]):
            self.assertEqual(js, str(ipaddress.ip_network(case.strip())) if "/" in case else case.strip(), case)
        self.assertEqual(got[1:], ["10.0.0.0/255.0.255.0", ""])      # not a mask: left for cidrProblem to report
        wiz = body_of("views.create = (opts = {}) =>", "// ---------------------------------------------------------------- platform")
        self.assertIn("!same(k === 'cidr' ? netText(data[k]) : data[k], base[k])", wiz)
        self.assertIn(".filter(Boolean).map(netText).map(", wiz)

    def test_a_drill_without_a_verdict_measured_no_rto(self):
        code = js_def("runKind") + "\n" + js_def("reportSummary") + """
const ok = [{ step: '4. restore from backup', ok: true, seconds: 30 }, { step: '5. verify', ok: true, seconds: 4.5 }];
const n = 'drill-20260923-093000';
console.log(JSON.stringify([reportSummary({ name: n, summary: {}, verdict: null, results: ok }), reportSummary({ name: n, summary: {}, verdict: 'PASS', results: ok }),
  reportSummary({ name: n, summary: { RTO: 'not measured', total: '9s' }, verdict: 'FAIL', results: ok })]));"""
        legacy, passed, server = self.node(code)
        self.assertEqual(legacy["RTO"], "—")                                    # cs dr: "RTO not measured"
        self.assertEqual(passed["RTO"], "34.5s")
        self.assertEqual(server, {"RTO": "not measured", "total": "9s"})        # the server's summary wins

    def test_the_interrupt_button_names_the_next_interrupt(self):
        tabs = body_of("function renderTabs()", "function trackJob(")
        self.assertIn("Number(aj.interrupts) || 0", tabs)
        self.assertIn("cb.textContent = sent >= 2 ? 'Kill' : sent === 1 ? 'Stop now' : 'Interrupt';", tabs)
        cancel = body_of("$('#job-cancel').onclick", "$('#job-copy').onclick")
        self.assertIn("interrupts: typeof r.interrupts === 'number' ? r.interrupts", cancel)
        self.assertIn("renderTabs();", cancel)

    def test_the_undo_limits_are_the_journal_s(self):
        from cloudseed import undo
        self.assertEqual((undo.KEEP_TOTAL, undo.KEEP, undo.KEEP_LIGHT), (15, 5, 5))
        for old in ("pushed out by five newer actions", "up to five are kept per environment", "Up to five entries are kept"):
            self.assertNotIn(old, JS)
        # (the same words as w5/ops-undo, which rewrote these lines too)
        self.assertIn("up to fifteen are kept per environment (at most five of one kind, and fifteen for global settings)", JS)
        self.assertIn("reports and scans have five slots of their own", JS)
        self.assertIn("pushed out of the history by newer changes;", JS)

    def test_plan_keeps_nothing_but_a_rename_s_plan(self):
        wiz = body_of("views.create = (opts = {}) =>", "// ---------------------------------------------------------------- platform")
        self.assertIn("if (data.mode === 'plan' && renaming(args)) args.save = true;", wiz)
        self.assertIn("a.save ? '--plan-only' : '--preview'", wiz)
        self.assertNotIn("a Plan saves the settings it planned", wiz)
        self.assertNotIn("(a Plan run also saves what it planned)", wiz)
        # a plan that puts the same settings back (or a failed run) is no reason to continue as another wizard
        self.assertIn("now.updated !== e.updated && settingsOf(now) !== settingsOf(e)", wiz)

    def test_the_managed_stopgap_is_gone(self):
        self.assertNotIn("pe.id", body_of("function actionForm(", "const action = (name) =>"))

    def test_mcp_form_shows_setup_s_fields_for_setup_only(self):
        rules = js_def("FORM_UI")
        self.assertIn("auth: { when: { action: ['setup'] } }, service: { when: { action: ['setup'] } }", rules)
        self.assertIn("need: { action: ['connect', 'disconnect'] }", rules)


@unittest.skipUnless(NODE, "node is not installed")
class BootThemeTests(unittest.TestCase):
    """boot.js runs before the page renders (the locked page has no other script): the stored theme applies at once."""

    def run_boot(self, stored, search="", meta=None, storage_throws=False) -> dict:
        code = """
const vm = require('vm'), fs = require('fs');
const [stored, search, meta, throws] = JSON.parse(process.argv[1]);
const root = { dataset: {}, style: {} };
const ctx = {
  localStorage: { getItem: (k) => { if (throws) throw new Error('blocked'); return k === 'cs-theme' ? stored : null; } },
  sessionStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  document: { documentElement: root, querySelector: () => (meta === null ? null : { getAttribute: () => meta }) },
  location: { search, pathname: '/', hash: '', replace: () => {} }, history: { state: null, replaceState: () => {} },
  URLSearchParams,
};
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), ctx);
console.log(JSON.stringify({ theme: root.dataset.theme === undefined ? null : root.dataset.theme }));
"""
        out = subprocess.run([NODE, "-e", code, json.dumps([stored, search, meta, storage_throws]), str(BOOT)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_the_picked_theme_applies_before_the_first_paint(self):
        self.assertEqual(self.run_boot("dark")["theme"], "dark")                      # the locked page (no meta)
        self.assertEqual(self.run_boot("light", meta="__CS_TOKEN__")["theme"], "light")
        self.assertEqual(self.run_boot("dark", search="?token=x", meta="tok")["theme"], "dark")   # the console
        self.assertIsNone(self.run_boot("purple")["theme"])                           # not a theme: the system's
        self.assertIsNone(self.run_boot(None)["theme"])
        self.assertIsNone(self.run_boot("dark", storage_throws=True)["theme"])        # storage blocked: no error

    def test_it_is_the_first_statement(self):
        src = BOOT.read_text()
        body = src[src.index("'use strict';"):]
        self.assertTrue(body.splitlines()[1].strip().startswith("try { const t = localStorage.getItem('cs-theme');"))


# ============================================================================================ the MCP form and the CLI flags
class McpFormTests(unittest.TestCase):
    def test_auth_and_service_map_to_the_setup_flags(self):
        props = {a["name"]: a for a in webui.actions_catalog()}["cloudseed_mcp"]["schema"]["properties"]
        self.assertNotIn("no_auth", props)
        self.assertEqual(props["auth"]["enum"], ["", "token", "none"])
        self.assertEqual(props["service"]["enum"], ["", "service", "background"])
        argv = lambda a: webui.build_argv("cloudseed_mcp", dict(a, confirm=True))  # noqa: E731
        self.assertEqual(argv({"action": "setup"}), ["mcp", "setup", "--client", "none", "-y"])       # blank: keep what is deployed
        self.assertEqual(argv({"action": "setup", "auth": "token", "service": "service"}), ["mcp", "setup", "--auth", "--service", "--client", "none", "-y"])
        self.assertEqual(argv({"action": "setup", "auth": "none", "service": "background"}), ["mcp", "setup", "--no-auth", "--no-service", "--client", "none", "-y"])
        with self.assertRaises(ValueError):
            argv({"action": "restart", "auth": "none"})
        with self.assertRaises(ValueError):
            argv({"action": "setup", "auth": "yes"})

    def test_the_cli_takes_both_directions(self):
        from cloudseed.cli import build_parser
        p = build_parser()
        for words, auth, service in ((["mcp", "setup"], None, None), (["mcp", "setup", "--auth", "--service"], True, True),
                                     (["mcp", "setup", "--no-auth", "--no-service"], False, False),
                                     (["mcp", "setup", "--no-auth", "--auth"], True, None)):
            a = p.parse_args(words)
            self.assertEqual((a.auth, a.service), (auth, service), words)
        helptext = (ROOT / "cloudseed" / "help.py").read_text()
        self.assertIn("[--[no-]auth] [--[no-]service]", helptext)
        self.assertIn("  --auth / --service   setup: the bearer token again after --no-auth", helptext)


class SetupPreviewTests(unittest.TestCase):
    def test_a_plan_keeps_nothing_unless_it_is_saved(self):
        argv = mcp.TOOLS["cloudseed_setup"]["argv"]
        self.assertEqual(argv({"cloud": "aws", "env": "dev"})[-1], "--preview")
        self.assertEqual(argv({"cloud": "aws", "env": "dev", "save": True})[-1], "--plan-only")
        self.assertEqual(argv({"cloud": "aws", "env": "dev", "apply": True, "save": True})[-1], "--auto-approve")
        self.assertEqual(argv({"cloud": "aws", "env": "dev", "dry_run": True})[-1], "--dry-run")
        self.assertIn("save", mcp.TOOLS["cloudseed_setup"]["schema"]["properties"])
        self.assertIn("rename", mcp.TOOLS["cloudseed_setup"]["description"])
        from cloudseed.cli import build_parser
        a = build_parser().parse_args(["setup", "aws", "--env", "dev", "--preview"])
        self.assertTrue(a.preview)
        self.assertFalse(a.plan_only)


# ============================================================================================ secrets, audit, MCP children
class RedactionTests(unittest.TestCase):
    def test_an_auth_scheme_is_kept_and_its_credential_masked(self):
        tok = "abcdef0123456789abcdef"
        for text, want in ((f"X-Auth-Token: Bearer {tok}", "X-Auth-Token: Bearer [REDACTED]"),
                           (f'curl -H "X-Auth-Token: Bearer {tok}" https://x', 'curl -H "X-Auth-Token: Bearer [REDACTED]" https://x'),
                           (f"api_key = token {tok}", "api_key = token [REDACTED]"),
                           ("X-Api-Key: Basic dXNlcjpwYXNzd29yZA==", "X-Api-Key: Basic [REDACTED]"),
                           ("token_type: Bearer", "token_type: Bearer"),                  # (a safe key: nothing to hide)
                           ("password: hunter22", "password: [REDACTED]")):
            self.assertEqual(secrets.redact(text, auth=False), want, text)
        self.assertEqual(secrets.mask_argv(["curl", "-H", f"X-Auth-Token: Bearer {tok}"]), ["curl", "-H", "X-Auth-Token: Bearer [REDACTED]"])
        self.assertNotIn(tok, audit.scrub_auth(secrets.redact(f"X-Auth-Token: Bearer {tok}", auth=True)))


class AuditTests(Isolated):
    def test_the_console_records_through_audit_record(self):
        with mock.patch.object(audit, "record") as rec:
            webui._audit(["creds", "set", "X=1"], rc=0, changed=["X"])
        rec.assert_called_once_with(["creds", "set", "X=1"], 0, via="ui", changed=["X"])
        webui._audit(["creds", "set", "MY_TOKEN=hunter2hunter2"], changed=["MY_TOKEN"])
        line = json.loads((self.tmp / "cs" / "logs" / "audit.jsonl").read_text().splitlines()[-1])
        self.assertEqual((line["via"], line["command"], line["exit_code"], line["changed"]), ("ui", "creds", 0, ["MY_TOKEN"]))
        self.assertNotIn("hunter2hunter2", json.dumps(line))

    def test_an_mcp_server_started_from_the_console_records_via_mcp(self):
        os.environ["CLOUDSEED_UI"] = "1"                      # a server started detached from a console job inherits it
        sid, env = mcp._child_env()
        try:
            self.assertNotIn("CLOUDSEED_UI", env)
            self.assertEqual(env["CLOUDSEED_AGENT"], "mcp")
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(audit.origin(), "mcp")
        finally:
            secrets.close_session(sid)
        self.assertEqual(os.environ.get("CLOUDSEED_UI"), "1")  # (the server's own environment is left alone)


class DocsTests(unittest.TestCase):
    def test_the_docs_say_where_a_record_comes_from_and_which_go(self):
        readme = (ROOT / "docs" / "guides" / "manual.md").read_text()   # the reference moved out of README.md
        helptext = (ROOT / "cloudseed" / "help.py").read_text()
        self.assertIn("from where: `via` is `cli`, `ui` for the web console", readme)
        self.assertIn("and from where (via: cli, ui", helptext)
        self.assertIn("Go >= 1.25", readme)
        self.assertIn("Go >= 1.25", helptext)
        self.assertIn("--preview", helptext)
        self.assertTrue(re.search(r"--plan-only \| --preview", readme))


if __name__ == "__main__":
    unittest.main()
