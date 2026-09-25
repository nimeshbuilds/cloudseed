"""Wave 4 web console fixes (cloudseed/web/app.js, style.css): what other parts of cloudseed needed from the console.

Pure helpers of app.js run under node (skipped when node is not installed) with a tiny stand-in for the DOM; the rest
are source-level guards on the shipped files and the server contracts the page relies on:
  * the SSH allow-list check mirrors the CLI: host bits, /0, ranges wider than /8, more than two /8s (a2-cli-lifecycle#4)
  * DR drills: an RTO only for a PASS, the 'interrupted' note is not a step (a2-resilience#7)
  * catalog: a chip for crypto-restricted items and amd64-only ones, per-target needs in Details (a2-platform-catalog)
  * credentials: server warnings as toasts, a stored path that does not exist and an unreadable JSON key say so (agentic#20)
  * wizard: an environment answer bound to another region does not count (gcp#9); a following answer follows (aws);
    Azure answer patterns and reserved names (a2-azure#3); a deployed environment's region / project / subscription /
    GKE zone are fixed and a rename is planned first (a2-gcp#1, a2-azure#4, a2-cli-lifecycle#8); Plan keeps nothing
    but a rename's plan (a2-mcp#19)
  * forms: the server's field titles as labels, fields shown / required per action (skills), hidden fields not sent
    (webui-functional#7)
  * MCP clients: Reconnect keeps a client's transport; Connect all leaves connected clients alone (a2-mcp#15)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-wave4-web-"))

from cloudseed import clouds, netutil, platform, webui  # noqa: E402

WEB = Path(webui.WEB_ROOT)
JS = (WEB / "app.js").read_text()
CSS = (WEB / "style.css").read_text()
NODE = shutil.which("node")

# a stand-in for the page's el(): {tag, attrs, kids}
EL_STUB = """
const el = (tag, attrs = {}, ...kids) => ({ tag, attrs: { ...attrs }, kids: kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false) });
const text = (n) => (n === null || n === undefined ? '' : typeof n === 'object' ? n.kids.map(text).join('') : String(n));
"""


def js_def(name: str) -> str:
    """Source of one definition of app.js: `const name = ...;` up to the line that ends the statement (braces balanced,
    a trailing ';'), or `function name(...) {...}` up to its closing brace."""
    lines = JS.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        const = s.startswith(f"const {name} = ")
        if const or s.startswith((f"function {name}(", f"async function {name}(")):
            depth, out = 0, []
            for j in range(i, len(lines)):
                out.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and lines[j].rstrip().endswith(";" if const else "}"):
                    return "\n".join(out)
            raise AssertionError(f"no end found for {name}")
    raise AssertionError(f"{name} not found in app.js")


def body_of(start: str, end: str) -> str:
    i = JS.index(start)
    return JS[i:JS.index(end, i)]


@unittest.skipUnless(NODE, "node is not installed")
class NodeHelperTests(unittest.TestCase):
    def node(self, code: str):
        out = subprocess.run([NODE, "-e", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_app_js_parses(self):
        out = subprocess.run([NODE, "--check", str(WEB / "app.js")], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)

    # ------------------------------------------------------------------ SSH allow-list (a2-cli-lifecycle#4)
    def test_allow_list_agrees_with_the_cli(self):
        cases = ["198.51.100.7", "198.51.100.7/32", "203.0.113.0/24", "203.0.113.7/24", "10.1.2.3/8", "1.2.3.4/0", "0.0.0.0/0",
                 "10.0.0.0/7", "10.0.0.0/8, 192.168.1.0/24", "10.0.0.0/8,11.0.0.0/8", "10.0.0.0/8,11.0.0.0/8,12.0.0.0/8",
                 "10.0.0.0/8,10.1.0.0/16,11.0.0.0/8", "300.1.1.1", "1.2.3.4/33", "1.2.3.4/5/6", "a.b.c.d"]
        got = self.node(js_def("ipv4") + "\n" + js_def("allowProblem") + f"\nconsole.log(JSON.stringify({json.dumps(cases)}.map(allowProblem)));")
        for case, js in zip(cases, got):
            cli = netutil.validate_cidr_list(case)
            self.assertEqual(js is None, cli is None, f"{case}: console says {js!r}, the CLI {cli!r}")
        msgs = dict(zip(cases, got))
        self.assertEqual(msgs["203.0.113.7/24"], "'203.0.113.7/24' has host bits set, so it means 203.0.113.0/24 (256 addresses). "
                                                 "Did you mean 203.0.113.7/32 (just that address), or 203.0.113.0/24 for the whole range?")
        self.assertIn("so it means 0.0.0.0/0", msgs["1.2.3.4/0"])
        self.assertNotIn("for the whole range", msgs["1.2.3.4/0"])      # (a /0 is never a suggestion)
        self.assertIn("0.0.0.0/0", msgs["0.0.0.0/0"])
        self.assertIn("wider than /8", msgs["10.0.0.0/7"])
        self.assertIn("50,331,648 addresses", msgs["10.0.0.0/8,11.0.0.0/8,12.0.0.0/8"])
        # the CLI's own wording for the same mistake
        self.assertIn(msgs["203.0.113.7/24"].rstrip("?"), netutil.validate_cidr_list("203.0.113.7/24"))

    def test_the_wizard_refuses_what_setup_refuses_in_an_allow_list(self):
        # IPv6 entries and octets with a leading zero are refused by setup too; allowProblem itself keeps passing IPv6 on
        # (tests/test_fix_web_logic), the wizard runs allowListProblem
        cases = ["2001:db8::1", "2001:db8::/32", "::/0", "198.51.100.7, 2001:db8::1", "010.1.2.3", "10.1.2.03/32", "0.0.0.0/32",
                 "198.51.100.7", "203.0.113.0/24, 198.51.100.7"]
        got = self.node("\n".join(js_def(n) for n in ("ipv4", "allowProblem", "allowListProblem")) + f"\nconsole.log(JSON.stringify({json.dumps(cases)}.map(allowListProblem)));")
        for case, js in zip(cases, got):
            cli = netutil.validate_cidr_list(case)
            self.assertEqual(js is None, cli is None, f"{case}: console says {js!r}, the CLI {cli!r}")
        msgs = dict(zip(cases, got))
        self.assertIn("'2001:db8::1' is an IPv6 address", msgs["198.51.100.7, 2001:db8::1"])
        self.assertIn("IPv4-only", msgs["2001:db8::/32"])
        # a network CIDR in IPv6 is refused as well (cloudseed networks are IPv4), and a leading zero is no octet
        net = self.node(js_def("ipv4") + "\n" + js_def("cidrProblem") + "\nconsole.log(JSON.stringify([cidrProblem('fd00::/64'), cidrProblem('010.0.0.0/16'), cidrProblem('10.0.0.0/16')]));")
        self.assertIn("IPv6", net[0])
        self.assertIsNotNone(net[1])
        self.assertIsNone(net[2])
        self.assertIsNotNone(netutil.validate_cidr("fd00::/64"))

    # ------------------------------------------------------------------ DR drill summary (a2-resilience#7)
    def test_a_drill_measures_an_rto_only_when_it_passed(self):
        code = js_def("runKind") + "\n" + js_def("reportSummary") + """
const ok = [{ step: '1. create sample workload', ok: true, seconds: 10 }, { step: '2. backup', ok: true, seconds: 20.5 },
  { step: '3. delete it (disaster)', ok: true, seconds: 7 }, { step: '4. restore from backup', ok: true, seconds: 30 }, { step: '5. verify', ok: true, seconds: 4.5 }];
const failed = ok.slice(0, 4).concat([{ step: '5. verify', ok: false, seconds: 4.5 }]);
const stopped = ok.slice(0, 3).concat([{ step: 'interrupted', ok: false, seconds: 0, detail: 'Ctrl-C' }]);
const n = 'drill-20260923-093000';
console.log(JSON.stringify([
  reportSummary({ name: n, summary: {}, verdict: 'PASS', rto_s: 34.5, total_s: 72, results: ok }),
  reportSummary({ name: n, summary: {}, verdict: 'PASS', results: ok }),
  reportSummary({ name: n, summary: {}, verdict: 'FAIL', total_s: 72, results: failed }),
  reportSummary({ name: n, summary: {}, verdict: 'INTERRUPTED', results: stopped }),
  reportSummary({ name: n, summary: {}, verdict: null, results: ok }),
  reportSummary({ name: n, summary: {}, verdict: 'FAIL', results: [] }),
]));"""
        passed, derived, failed, stopped, legacy, empty = self.node(code)
        self.assertEqual(passed, {"RTO": "34.5s", "total": "72s", "steps": "5/5 ok"})
        self.assertEqual(derived["RTO"], "34.5s")                  # a PASS written without rto_s: restore + verify
        self.assertEqual(failed, {"RTO": "—", "total": "72s", "steps": "4/5 ok"})   # a failed restore is no recovery time
        self.assertEqual(stopped["RTO"], "—")
        self.assertEqual(stopped["steps"], "3/3 ok")               # the interrupted note is not a step of the drill
        self.assertEqual(legacy["RTO"], "—")                       # a file without a verdict measured none (as cs dr says)
        self.assertEqual(legacy["steps"], "5/5 ok")
        self.assertEqual(empty, {})

    # ------------------------------------------------------------------ catalog chips (a2-platform-catalog)
    def test_every_fips_class_and_arch_restriction_has_a_chip(self):
        code = EL_STUB + "\n".join(js_def(n) for n in ("fipsChip", "archChip", "needsText")) + """
const txt = (c) => (c ? c.attrs.class + ':' + c.kids[0] : null);
const fipsEnv = { id: 'aws-dev', fips: true };
const velero = { needs: ['cert-manager'], needs_by_target: { vmware: ['local-path-provisioner', 'minio'], aws: [] } };
console.log(JSON.stringify({
  crypto: txt(fipsChip({ fips: 'crypto-restricted' }, fipsEnv)), cryptoPlain: txt(fipsChip({ fips: 'crypto-restricted' }, null)),
  cryptoTitle: fipsChip({ fips: 'crypto-restricted' }, fipsEnv).attrs.title,
  none: txt(fipsChip({ fips: '' }, fipsEnv)),
  arch: txt(archChip({ arch: ['amd64'] })), noArch: txt(archChip({ arch: [] })), missing: txt(archChip({})),
  needsVmware: needsText(velero, 'vmware'), needsAws: needsText(velero, 'aws'), needsAll: needsText(velero, null),
  needsNone: needsText({ needs: [] }, 'gcp'), needsOld: needsText({ needs: ['a'] }, 'gcp'),
}));"""
        got = self.node(code)
        self.assertEqual(got["crypto"], "chip seed:FIPS: crypto not validated")   # it installs: never the red 'not FIPS'
        self.assertEqual(got["cryptoPlain"], "chip seed:FIPS: crypto not validated")
        self.assertIn("cs scan fips", got["cryptoTitle"])
        self.assertEqual(got["none"], "chip rose:not FIPS")
        self.assertEqual((got["arch"], got["noArch"], got["missing"]), ("chip:amd64 only", None, None))
        self.assertEqual(got["needsVmware"], "cert-manager, local-path-provisioner, minio (on vmware)")
        self.assertEqual(got["needsAws"], "cert-manager")
        self.assertEqual(got["needsAll"], "cert-manager; local-path-provisioner, minio (on vmware)")
        self.assertEqual((got["needsNone"], got["needsOld"]), ("—", "a"))
        # every FIPS class the catalog knows is worded by the console
        for cls in platform.FIPS_CLASSES:
            self.assertIn(f"i.fips === '{cls}'", js_def("fipsChip"))

    # ------------------------------------------------------------------ wizard rules
    def test_an_environment_answer_counts_only_in_its_region(self):
        code = js_def("questionIn") + """
const zone = { key: 'zone', default: '', from_env: ['CLOUDSDK_COMPUTE_ZONE'], env_region: 'europe-west1',
  stock: { default: 'us-central1-a', region_defaults: { 'europe-west1': 'europe-west1-b' } } };
const project = { key: 'project_id', default: '', from_env: ['GOOGLE_PROJECT'], required: true };
const plain = { key: 'enable_vpn', default: false };
console.log(JSON.stringify([questionIn(zone, 'europe-west1'), questionIn(zone, ' Europe-West1 '), questionIn(zone, 'us-east4'),
  questionIn({ ...zone, stock: undefined }, 'us-east4'), questionIn(project, 'us-east4'), questionIn(plain, 'x')]));"""
        here, loose, there, nostock, project, plain = self.node(code)
        self.assertEqual((here["default"], here["from_env"]), ("", ["CLOUDSDK_COMPUTE_ZONE"]))   # blank = $CLOUDSDK_COMPUTE_ZONE
        self.assertEqual(loose["from_env"], ["CLOUDSDK_COMPUTE_ZONE"])
        # elsewhere the built-in default applies, as the CLI does: the zone field shows us-central1-a's derivation
        self.assertEqual((there["default"], there["from_env"], there["region_defaults"]), ("us-central1-a", [], {"europe-west1": "europe-west1-b"}))
        self.assertEqual((nostock["default"], nostock["from_env"]), ("", []))
        self.assertEqual(project["from_env"], ["GOOGLE_PROJECT"])  # not bound to a region: it counts everywhere
        self.assertEqual(plain, {"key": "enable_vpn", "default": False})

    def test_a_following_answer_follows_unless_saved_differently(self):
        code = js_def("same") + "\n" + js_def("followBase") + """
console.log(JSON.stringify([followBase(undefined, undefined, false), followBase(true, true, false), followBase('true', true, false),
  followBase(true, false, true), followBase(true, undefined, false), followBase(false, false, true)]));"""
        self.assertEqual(self.node(code), [False, False, False, True, True, True])
        # the same rule as setup (aws.collect_vars), and the console knows which question follows which
        q = clouds.get("aws").question("enable_regional_baseline")
        self.assertEqual(q.follows, "enable_account_baseline")
        self.assertIn(f"'aws:enable_regional_baseline': '{q.follows}'", JS)

    def test_a_deployed_environment_keeps_its_project_subscription_and_cluster_zone(self):
        code = js_def("same") + "\n" + js_def("pinnedWhy") + """
const dep = (vars, extra = {}) => ({ id: 'x-dev', resources: 12, vars, ...extra });
const zq = { key: 'zone', region_defaults: { 'europe-west1': 'europe-west1-b' } };
console.log(JSON.stringify([
  pinnedWhy('gcp', { key: 'project_id' }, dep({ project_id: 'acme-1' }), 'us-east4'),
  pinnedWhy('gcp', { key: 'project_id' }, { ...dep({ project_id: 'acme-1' }), resources: 0 }, 'us-east4'),
  pinnedWhy('gcp', { key: 'project_id' }, dep({}), 'us-east4'),
  pinnedWhy('azure', { key: 'subscription_id' }, dep({ subscription_id: '0000aaaa-0000-0000-0000-000000000000' }), 'westeurope'),
  pinnedWhy('aws', { key: 'profile' }, dep({ profile: 'work' }), 'us-east-1'),
  pinnedWhy('gcp', zq, dep({ zone: 'us-east4-b', enable_kubernetes: true }), 'us-east4'),
  pinnedWhy('gcp', zq, dep({ zone: 'us-east4-b' }, { kubernetes: true }), 'us-east4'),
  pinnedWhy('gcp', zq, dep({ zone: 'us-east4-b', enable_kubernetes: false }), 'us-east4'),
  pinnedWhy('gcp', zq, dep({ zone: 'us-central1-a', enable_kubernetes: true }), 'us-east4'),
  pinnedWhy('gcp', zq, dep({ zone: 'europe-west1-a', enable_kubernetes: true }), 'europe-west1'),
  // (an environment answer applies: the question carries its stock default's irregular regions only)
  pinnedWhy('gcp', { key: 'zone', stock: { default: 'us-central1-a', region_defaults: zq.region_defaults } }, dep({ zone: 'europe-west1-a', enable_kubernetes: true }), 'europe-west1'),
]));"""
        project, fresh, unsaved, sub, aws, gke, gke2, nocluster, outside, missing, missing2 = self.node(code)
        self.assertIn("cannot change on a deployed environment (setup refuses", project)
        self.assertIn("project", project)
        self.assertEqual((fresh, unsaved, aws), ("", "", ""))       # nothing deployed / nothing saved / not a fixed answer
        self.assertIn("subscription", sub)
        self.assertIn("zonal GKE cluster", gke)
        self.assertEqual(gke, gke2)
        # without a cluster a zone move only rebuilds the bastion (warned); a broken saved zone is repaired by setup
        self.assertEqual((nocluster, outside, missing, missing2), ("", "", "", ""))

    def test_answer_patterns_and_reserved_names(self):
        az = clouds.get("azure")
        pattern, hint = az.answer_patterns["subscription_id"]
        reserved = sorted(az.answer_reserved["admin_username"])
        sub = {"key": "subscription_id", "pattern": pattern, "pattern_hint": hint}
        user = {"key": "admin_username", "reserved": reserved}
        code = js_def("answerRule") + f"""
const sub = {json.dumps(sub)}, user = {json.dumps(user)};
const r = (q, v) => answerRule(q, v, 'Label', 'Azure');
console.log(JSON.stringify([r(sub, '0000aaaa-0000-0000-0000-000000000000'), r(sub, ' 0000AAAA-0000-0000-0000-000000000000 '), r(sub, 'my-subscription'),
  r(sub, ''), r(sub, undefined), r(user, 'Admin'), r(user, 'azureuser'), r({{ key: 'x', pattern: '(?P<bad>' }}, 'v'),
  r({{ key: 'x', pattern: '^a$' }}, 'b'), r({{ key: 'x', pattern: '^a$', pattern_hint: 'one letter a' }}, 'b')]));"""
        ok, spaced, bad, blank, missing, admin, fine, unreadable, nohint, plainhint = self.node(code)
        self.assertEqual((ok, spaced, blank, missing, fine, unreadable), ("", "", "", "", "", ""))
        self.assertEqual(bad, f"'my-subscription' is not {hint}")
        self.assertIsNone(az.answer_problem(az.question("subscription_id"), "0000aaaa-0000-0000-0000-000000000000", {"region": "westeurope"}))
        self.assertIsNotNone(az.answer_problem(az.question("subscription_id"), "my-subscription", {"region": "westeurope"}))
        self.assertIn("admin", reserved)
        self.assertEqual(admin, "'Admin' is a name Azure does not allow as a VM admin user")
        self.assertEqual((nohint, plainhint), ("Label: 'b' is not a valid value", "Label: one letter a"))

    # ------------------------------------------------------------------ forms
    def test_labels_come_from_the_server_titles(self):
        code = "\n".join(js_def(n) for n in ("KEY_LABELS", "WORDS", "humanKey", "FORM_UI", "fieldLabel", "ruleHolds")) + """
const a = { name: 'cloudseed_skill', schema: { properties: { action: { title: 'Action' }, name: { title: 'Skill name(s)' }, dir: { title: 'Folder' }, env: { title: 'Environment' }, purge_state: { title: 'Purge state' }, odd_key: {} } } };
const skill = FORM_UI.cloudseed_skill;
console.log(JSON.stringify({
  labels: ['action', 'name', 'dir', 'env', 'purge_state', 'odd_key'].map((k) => fieldLabel(a, k)),
  install: ['agent', 'dir', 'name'].map((k) => ruleHolds(skill[k].when, { action: 'install' })),
  list: ['agent', 'dir', 'name'].map((k) => ruleHolds(skill[k].when, { action: 'list' })),
  show: [ruleHolds(skill.name.when, { action: 'show' }), ruleHolds(skill.name.need, { action: 'show' }), ruleHolds(skill.name.need, { action: 'install' }), ruleHolds(skill.agent.when, { action: 'show' })],
  blank: ruleHolds({ action: [''] }, {}),
  vpn: ['add-user', 'revoke', 'status'].map((x) => ruleHolds(FORM_UI.cloudseed_vpn.name.need, { action: x })),
}));"""
        got = self.node(code)
        # a title the server sets wins over the key; the console's own wording (KEY_LABELS) wins over a generated title
        self.assertEqual(got["labels"], ["Action", "Skill name(s)", "Folder", "Environment", "Also delete the remote state storage", "Odd key"])
        self.assertEqual(got["install"], [True, True, True])
        self.assertEqual(got["list"], [False, False, False])
        self.assertEqual(got["show"], [True, True, False, False])   # show: only the name, and it is required
        self.assertTrue(got["blank"])
        self.assertEqual(got["vpn"], [True, True, False])

    # ------------------------------------------------------------------ MCP clients (a2-mcp#15)
    def test_reconnect_keeps_the_transport_and_connect_all_leaves_connected_clients(self):
        code = js_def("reconnectTransport") + "\n" + js_def("connectAll") + """
let STATE = { mcp: { url: 'http://127.0.0.1:7777/mcp', clients: {
  codex: { present: true, connected: 'stdio', stale: false }, cursor: { present: true, connected: 'http', stale: true },
  windsurf: { present: true, connected: null }, vscode: { present: false, connected: null }, claude: { present: true, connected: 'http', stale: false } } } };
const runs = []; const run = (a, args, label) => runs.push([a, args, label]); const toasts = []; const toast = (m) => toasts.push(m);
const t = (c) => reconnectTransport(c);
const withServer = [t({ connected: 'stdio' }), t({ connected: 'http' }), t({ connected: null })];
connectAll();
STATE = { mcp: { url: '', clients: { codex: { present: true, connected: 'stdio' } } } };
const noServer = [t({ connected: 'http' }), t({ connected: 'stdio' })];
connectAll();
STATE = { mcp: { url: '', clients: { codex: { present: false, connected: null } } } };
connectAll();
console.log(JSON.stringify({ withServer, noServer, runs, toasts }));"""
        got = self.node(code)
        self.assertEqual(got["withServer"], ["stdio", "http", ""])
        self.assertEqual(got["noServer"], ["stdio", "stdio"])       # an HTTP client whose server is gone moves to stdio
        # not codex (stdio on purpose), not claude (up to date), not vscode (not detected)
        self.assertEqual(got["runs"], [["cloudseed_mcp", {"action": "connect", "clients": ["cursor", "windsurf"]}, "connect cursor, windsurf"]])
        self.assertEqual(len(got["toasts"]), 2)
        self.assertIn("connected already", got["toasts"][0])
        self.assertIn("No MCP client was detected", got["toasts"][1])    # (not "connected already" when there is none)
        # the button sends the transport to `mcp connect`
        self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": "connect", "clients": ["codex"], "transport": "stdio"}),
                         ["mcp", "connect", "codex", "--transport", "stdio", "-y"])


class SourceTests(unittest.TestCase):
    """Behaviour that needs the whole page, pinned at the source (checked live in a browser as well)."""

    def test_credentials_say_what_needs_a_look(self):
        creds = body_of("views.creds = () =>", "// ---------------------------------------------------------------- help")
        self.assertIn("for (const w of (r && r.warnings) || []) toast('▲ ' + w, 'warn', 9000);", creds)
        self.assertIn("c.warning", creds)                               # a stored path that does not exist (yet)
        self.assertIn("class: 'field-warn'", creds)
        self.assertIn("paste the JSON key again", creds)                # a stored key that does not parse
        self.assertNotIn("placeholder: c.set ? 'paste a new JSON key to replace it' : '{...}'", creds)
        # a custom variable's value is typed blind and never offered by the password manager
        self.assertIn("field('VALUE', { type: 'string', label: 'Value', secret: true }", creds)
        self.assertIn("autocomplete: prop.secret ? 'new-password'", js_def("field"))

    def test_hidden_form_fields_are_not_sent(self):
        self.assertIn("if (!inp.name || inp.closest('[hidden]')) continue;", js_def("readForm"))
        form = js_def("actionForm")
        self.assertIn("lab.hidden = !shown;", form)
        self.assertIn("inp.required = req && inp.tagName !== 'SELECT'", form)   # a hidden control is never required
        self.assertIn("label: fieldLabel(a, name)", form)
        self.assertNotIn("a.name === 'cloudseed_vpn' && /^(add-user|revoke)$/", form)   # now a FORM_UI rule
        self.assertRegex(CSS, r"(?m)^\[hidden\] \{ display: none !important; \}")

    def test_wizard_rules(self):
        wiz = body_of("views.create = (opts = {}) =>", "// ---------------------------------------------------------------- platform")
        # every question loop sees the questions as they apply in the chosen region
        self.assertNotIn("for (const q of c().questions)", wiz)
        self.assertIn("const qv = (q) => questionIn(q, data.region);", wiz)
        self.assertIn("if (f) return followBase(saved, e && e.vars ? e.vars[f.key] : undefined, effective(f));", wiz)
        self.assertIn("answerProblem(q, val)", wiz)
        # a deployed environment: the region is fixed (setup refuses), no promise that a region change rebuilds anything
        self.assertNotIn("rebuilds every resource", wiz)
        self.assertNotIn("Changing the region replaces every resource", wiz)
        self.assertIn("else if (regionFixed()) b.region =", wiz)
        self.assertIn("cannot change on a deployed environment (setup refuses)", wiz)
        # (a deployed environment whose config lost its region is not locked out of giving one: setup takes it)
        self.assertIn("const regionPinned = deployed() && !!base.region;", wiz)
        self.assertIn("if (regionField && regionPinned && !regionFixed())", wiz)
        self.assertIn("hint: regionPinned ? `saved: ${base.region}; cannot change", wiz)
        # a rename of a deployed environment is planned first: the review says so and Apply waits
        self.assertIn("blocked = apply && renameNow ?", wiz)
        self.assertIn("runBtn.disabled = !confirmBox.checked || !!blocked;", wiz)
        self.assertIn("if (data.mode === 'apply' && renaming(buildArgs())) return toast(", wiz)
        self.assertIn("const renaming = (a) => deployed() && !!base.name && a.name !== undefined;", wiz)
        # the wizard's allow-list check is the whole one (IPv6 included), and a list of only commas is not sent
        self.assertIn("const p = allowListProblem(data.allow_ip); if (p) b.allow_ip = p;", wiz)
        self.assertIn("data.allow_ip && cidrList(data.allow_ip) && cidrList(data.allow_ip) !== cidrList(base.allow_ip)", wiz)
        self.assertIn("['SSH allowed from', (cidrList(data.allow_ip) && data.allow_ip) || 'your public IP (detected)']", wiz)
        # Plan keeps nothing (setup --preview) except a rename's plan, which the Apply after it needs (a2-mcp#19)
        self.assertIn("nothing is saved: ${e.id} keeps its settings until you Apply", wiz)
        self.assertIn("if (data.mode === 'plan' && renaming(args)) args.save = true;", wiz)
        self.assertIn("a.save ? '--plan-only' : '--preview'", wiz)
        self.assertNotIn("'shows exactly what would be created; nothing changes'", wiz)
        # a following answer shows its new value when the one it follows changes
        self.assertIn("if (!followed(q) || data.touched.has(q.key)) continue;", wiz)
        # the review lists a follower's change even when it was never saved (a config from before the question): it
        # was the answer it follows
        self.assertIn("const was = ev[q.key] !== undefined ? ev[q.key] : ev[f.key], now = effective(q);", wiz)

    def test_catalog_items_show_their_architecture_and_per_target_needs(self):
        plat = body_of("views.platform = async () =>", "const SUITE_LABEL = ")
        self.assertIn("fipsChip(i, e), archChip(i),", plat)
        self.assertIn("needsText(i, target)", plat)
        self.assertIn(".field-warn {", CSS)

    def test_reconnect_sends_the_transport(self):
        table = js_def("clientsTable")
        self.assertIn("...(transport ? { transport } : {})", table)
        self.assertIn("connect(!!c.stale, 'Reconnect', reTitle, tr)", table)
        self.assertNotIn("picks up a new transport", JS)
        self.assertIn("onclick: connectAll", JS)
        self.assertNotIn("clients: ['all'] }, 'connect all clients'", JS)


class ServerContractTests(unittest.TestCase):
    def test_skill_form_rules_name_real_fields(self):
        cat = {a["name"]: a for a in webui.actions_catalog()}
        props = cat["cloudseed_skill"]["schema"]["properties"]
        for k in ("agent", "dir", "name"):
            self.assertIn(k, props)
        self.assertEqual(set(props["action"]["enum"]), {"list", "install", "show"})
        self.assertIn("name", cat["cloudseed_vpn"]["schema"]["properties"])
        # every field has a title to use as its label
        for a in cat.values():
            for k, p in (a["schema"].get("properties") or {}).items():
                if isinstance(p, dict):
                    self.assertTrue(p.get("title"), f"{a['name']}.{k} has no title")

    def test_show_needs_exactly_one_name(self):
        with self.assertRaises(ValueError):
            webui.build_argv("cloudseed_skill", {"action": "show"})
        self.assertEqual(webui.build_argv("cloudseed_skill", {"action": "list"}), ["skill", "list"])

    def test_creds_answer_carries_warnings(self):
        src = Path(webui.__file__).read_text()
        self.assertIn('"warnings": warnings', src)
        self.assertIn('r["warning"] = warn', src)

    def test_catalog_rows_carry_what_the_wizard_reads(self):
        cat = webui.clouds_catalog()
        for cloud, c in cat.items():
            for q in c["questions"]:
                self.assertIn("from_env", q, f"{cloud}.{q['key']}")
                if q.get("env_region"):
                    self.assertTrue(re.fullmatch(r"[a-z0-9-]+", q["env_region"]))


if __name__ == "__main__":
    unittest.main()
