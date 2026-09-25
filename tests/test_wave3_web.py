"""Wave 3 web console fixes (cloudseed/web/app.js, style.css, index.html, locked.html).

Pure helpers of app.js run under node (skipped when node is not installed) with tiny stand-ins for the DOM; the rest
are source-level guards on the shipped files and the server contracts the page relies on:
  * CLI panels keep their frames in the Activity drawer; prose still wraps (webui-visual#3)
  * fields: three-part labels (the subgrid alignment), human labels with the argument name, secrets typed blind,
    helm --set values one per line, a saved value outside a select's list stays selectable (webui-visual#2/#10/#31,
    webui-functional#6, lead polish)
  * wizard prompts split into a short label and a hint; the vmware wizard sends --cidr (vmware#5, webui-visual#2)
  * job labels name the environment; interrupted jobs are not "failed" (webui-functional#11/#17)
  * api() replays an answer only once it has arrived (webui-functional#18)
  * the palette ranks exact names first (webui-functional#16)
  * report wording (scan titles, column names), CLOUDSEED_HOME shown as ~/ (webui-visual#22, lead polish)
  * contrast, forced colours, nowrap buttons, phone layouts, skip link, drawer separator (webui-visual#0/#4-#8/#13/#14/#27/#28)
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

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-wave3-web-"))

from cloudseed import webui  # noqa: E402

WEB = Path(webui.WEB_ROOT)
JS = (WEB / "app.js").read_text()
CSS = (WEB / "style.css").read_text()
INDEX = (WEB / "index.html").read_text()
LOCKED = (WEB / "locked.html").read_text()
NODE = shutil.which("node")


def js_def(name: str) -> str:
    """Source of one definition of app.js: `const name = ...` or `function name(...) {...}` (braces are balanced in its
    strings, so counting them finds the end), up to the end of the line where it closes."""
    lines = JS.splitlines()
    starts = (f"const {name} = ", f"function {name}(", f"async function {name}(")
    for i, line in enumerate(lines):
        if line.strip().startswith(starts):
            depth, out = 0, []
            for j in range(i, len(lines)):
                out.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                if depth <= 0 and (lines[j].rstrip().endswith((";", "}")) or j > i):
                    return "\n".join(out)
            raise AssertionError(f"no end found for {name}")
    raise AssertionError(f"{name} not found in app.js")


def body_of(start: str, end: str) -> str:
    i = JS.index(start)
    return JS[i:JS.index(end, i)]


# a stand-in for the page's el(): {tag, attrs, kids}, with the few element methods field() uses
EL_STUB = """
const el = (tag, attrs = {}, ...kids) => ({ tag, attrs: { ...attrs }, kids: kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false),
  setAttribute(k, v) { this.attrs[k] = v; }, prepend(x) { this.kids.unshift(x); }, value: attrs.value, required: false });
const text = (n) => (n === null || n === undefined ? '' : typeof n === 'object' ? n.kids.map(text).join('') : String(n));
"""


def contrast(a: str, b: str) -> float:
    def lum(h: str) -> float:
        r, g, bl = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
        f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
        return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(bl)
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def token(block_start: str, name: str) -> str:
    """--name in the first CSS block that starts with block_start."""
    i = CSS.index(block_start)
    block = CSS[i:CSS.index("}", i)]
    m = re.search(r"--" + re.escape(name) + r":\s*(#[0-9a-fA-F]{6})", block)
    if not m:
        raise AssertionError(f"--{name} not set in {block_start}")
    return m.group(1)


def media(query: str) -> str:
    i = CSS.index("@media " + query)
    depth, j = 0, CSS.index("{", i)
    for k in range(j, len(CSS)):
        depth += {"{": 1, "}": -1}.get(CSS[k], 0)
        if depth == 0:
            return CSS[j + 1:k]
    raise AssertionError("unbalanced @media " + query)


@unittest.skipUnless(NODE, "node is not installed")
class NodeHelperTests(unittest.TestCase):
    def node(self, code: str):
        out = subprocess.run([NODE, "-e", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_app_js_parses(self):
        out = subprocess.run([NODE, "--check", str(WEB / "app.js")], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_frames_keep_their_shape_prose_wraps(self):
        lines = ["╭─ State ──────────╮", "│ Resources  0     │", "╰──────────────────╯", "━━ Platform on aws-dev ━━━━━━━━━━",
                 "│ Error: Invalid provider configuration with a very long explanation that must wrap", "✖ terraform plan failed",
                 "plain prose", "  │ ✔ PASS pod-kill", "[interrupted (exit code 130)]"]
        got = self.node("const el = (t, a) => a.class;\n" + js_def("colorize") + f"\nconsole.log(JSON.stringify({json.dumps(lines)}.map(colorize)));")
        self.assertEqual(dict(zip(lines, got)), {
            "╭─ State ──────────╮": "dim box", "│ Resources  0     │": "dim box", "╰──────────────────╯": "dim box", "━━ Platform on aws-dev ━━━━━━━━━━": "info box",
            # terraform's open-sided diagnostic rows and every other line keep wrapping
            "│ Error: Invalid provider configuration with a very long explanation that must wrap": "bad", "✖ terraform plan failed": "bad",
            "plain prose": "", "  │ ✔ PASS pod-kill": "ok", "[interrupted (exit code 130)]": "warn"})

    def field_js(self, calls: str):
        return self.node(EL_STUB + js_def("field") + "\n" + calls)

    def test_field_is_label_control_notes(self):
        got = self.field_js("""
const f = field('days', { type: 'integer', minimum: 1, description: 'days of billing history' }, false, '');
const q = field('var:profile', { type: 'string', label: 'AWS CLI profile to use', hint: 'blank = $AWS_PROFILE from your environment or the vault', description: 'full prompt' }, false, '');
const b = field('env', { type: 'string', label: 'Environment', description: 'environment name' }, true, 'dev');
const c = field('cloud', { type: 'string', label: 'Cloud', enum: ['aws', 'gcp'] }, true, 'aws');
console.log(JSON.stringify({
  parts: f.kids.map((k) => k.tag), input: f.kids[1].attrs.type, notes: text(f.kids[2]),
  qLabel: text(q.kids[0]), qHint: text(q.kids[2]),
  bLabel: text(b.kids[0]), bKey: b.kids[0].kids[1].attrs.class,
  cLabel: text(c.kids[0]),
}));""")
        self.assertEqual(got["parts"], ["span", "input", "span"])          # label / control / notes: three grid rows
        self.assertEqual(got["input"], "number")
        self.assertEqual(got["notes"], "days of billing history")
        self.assertEqual(got["qLabel"], "AWS CLI profile to useprofile")   # a variable keeps its name next to the label
        self.assertEqual(got["qHint"], "blank = $AWS_PROFILE from your environment or the vault")
        self.assertEqual((got["bLabel"], got["bKey"]), ("Environment *env", "key"))
        self.assertEqual(got["cLabel"], "Cloud *")                          # a label that is just the name shows it once

    def test_field_secret_lines_and_enum(self):
        got = self.field_js("""
const s = field('VALUE', { type: 'string', label: 'Value', secret: true }, true, '');
const l = field('set', { type: 'array', items: { type: 'string' }, lines: true }, false, ['a=1', 'hosts={x,y}']);
const w = field('items', { type: 'array', items: { type: 'string', pattern: '^[^-\\\\s]' } }, false, ['a', 'b']);
const e = field('agent', { type: 'string', enum: ['builtin', 'claude'] }, true, 'my-agent');
const t = field('task', { type: 'string', multiline: true }, true, '', 'e.g. list my environments');
console.log(JSON.stringify({
  secret: [s.kids[1].attrs.type, s.kids[1].attrs.autocomplete],
  lines: [l.kids[1].tag, l.kids[1].attrs['data-kind'], l.kids[1].kids[0]],
  words: [w.kids[1].tag, w.kids[1].attrs['data-kind'], w.kids[1].attrs.value],
  options: e.kids[1].kids.map((o) => o.attrs.value),
  task: [t.kids[1].tag, t.kids[1].attrs.placeholder, t.kids[1].kids.length],
}));""")
        self.assertEqual(got["secret"], ["password", "new-password"])
        self.assertEqual(got["lines"], ["textarea", "lines", "a=1\nhosts={x,y}"])
        self.assertEqual(got["words"], ["input", "list", "a,b"])
        self.assertEqual(got["options"], ["builtin", "claude", "my-agent"])  # a custom agent stays selectable
        self.assertEqual(got["task"], ["textarea", "e.g. list my environments", 1])

    def test_read_field_lines_keep_commas(self):
        code = js_def("readField") + """
const inp = (kind, value) => ({ type: 'textarea', value, name: 'set', dataset: { kind } });
console.log(JSON.stringify([readField(inp('lines', 'ingress.hosts={a.example.com,b.example.com}\\nreplicas=2\\n\\n')), readField(inp('list', 'a, b,,c'))]));"""
        self.assertEqual(self.node(code), [["ingress.hosts={a.example.com,b.example.com}", "replicas=2"], ["a", "b", "c"]])

    def test_prompts_become_label_and_hint(self):
        prompts = ["Kubernetes version: an RKE2 release (e.g. v1.36.4+rke2r1) or a kubeadm minor", "Memory per Kubernetes node (MB)",
                   "Control-plane nodes (1-20)", "AWS CLI profile to use (blank = default credential chain)", "GCP project ID",
                   "Guest OS for the VMs (ubuntu-24.04, ubuntu-22.04, debian-12)", "Number of availability zones (1-5; EKS needs 2+)"]
        got = self.node(js_def("splitPrompt") + f"\nconsole.log(JSON.stringify({json.dumps(prompts)}.map(splitPrompt)));")
        self.assertEqual(got, [["Kubernetes version", "an RKE2 release (e.g. v1.36.4+rke2r1) or a kubeadm minor"], ["Memory per Kubernetes node (MB)", None],
                               ["Control-plane nodes (1-20)", None], ["AWS CLI profile to use", "blank = default credential chain"], ["GCP project ID", None],
                               ["Guest OS for the VMs", "ubuntu-24.04, ubuntu-22.04, debian-12"], ["Number of availability zones", "1-5; EKS needs 2+"]])

    def test_job_labels_name_the_environment(self):
        cases = [["cloudseed_vpn", {"action": "status", "cloud": "aws", "env": "demo"}, "vpn status"],
                 ["cloudseed_status", {"cloud": "aws", "env": "demo"}, "status aws-demo"],
                 ["cloudseed_setup", {"cloud": "aws", "env": "demo"}, "setup aws/demo (apply)"],
                 ["cloudseed_doctor", {"cloud": "gcp"}, "doctor gcp"],
                 ["cloudseed_doctor", {}, ""],
                 ["cloudseed_mcp", {"action": "status"}, "mcp status"]]
        got = self.node(js_def("jobLabel") + f"\nconsole.log(JSON.stringify({json.dumps(cases)}.map(([a, x, l]) => jobLabel(a, x, l))));")
        self.assertEqual(got, ["vpn status · aws-demo", "status aws-demo", "setup aws/demo (apply)", "doctor gcp", "doctor", "mcp status"])

    def test_interrupted_jobs_are_not_failed(self):
        code = "const INTERRUPTED = new Set(['j9']);\n" + js_def("interrupted") + "\n" + js_def("jobState") + """
const jobs = [{ id: 'a', running: true }, { id: 'b', rc: 0 }, { id: 'c', rc: 1 }, { id: 'd', rc: 130 }, { id: 'j9', rc: 137 }, { id: 'e', rc: 2, interrupted: true },
  { id: 'f', rc: -1, lost: true }, { id: 'g' }];
console.log(JSON.stringify(jobs.map(jobState)));"""
        self.assertEqual(self.node(code), ["running", "ok", "bad", "interrupted", "interrupted", "interrupted", "lost", ""])

    def test_api_replays_only_an_answer_that_arrived(self):
        # webui-functional#18: an identical request still on its way is run()'s business (inFlight); api() hands back
        # the same answer only for 1.5 s after it arrived
        code = """
let pressed = null; const PENDING = new Map(); let calls = 0; const resolvers = [];
const request = () => { calls++; return new Promise((r) => resolvers.push(r)); };
""" + js_def("api") + """
(async () => {
  const a = api('/api/run', { action: 'x' }); const b = api('/api/run', { action: 'x' });
  const whileOnItsWay = calls;
  resolvers.forEach((r) => r({ job: 'j1' })); await a; await b;
  const c = api('/api/run', { action: 'x' }); const replay = calls;
  const d = api('/api/state');
  console.log(JSON.stringify([whileOnItsWay, replay, c === b, calls]));
})();"""
        self.assertEqual(self.node(code), [2, 2, True, 3])

    def test_palette_prefers_exact_names(self):
        items = [{"kind": "action", "label": "dr", "sub": "Disaster recovery (Velero): status, backups"},
                 {"kind": "catalog", "label": "velero", "sub": "install… · Backup and restore"},
                 {"kind": "group", "label": "install resilience", "sub": "Resilience / DR: Velero"},
                 {"kind": "catalog", "label": "velero-ui", "sub": "install…"},
                 {"kind": "help", "label": "help dr", "sub": ""}]
        code = js_def("paletteRank") + f"""
const all = {json.dumps(items)};
const rank = (q) => all.map((i, n) => [paletteRank(i, q), n, i]).filter(([r]) => r >= 0).sort((a, b) => a[0] - b[0] || a[1] - b[1]).map(([, , i]) => i.label);
console.log(JSON.stringify([rank('velero'), rank('resilience'), rank('dr')]));"""
        velero, resilience, dr = self.node(code)
        self.assertEqual(velero, ["velero", "velero-ui", "dr", "install resilience"])
        self.assertEqual(resilience[0], "install resilience")
        self.assertEqual(dr[:2], ["dr", "help dr"])

    def test_labels_and_report_wording(self):
        code = "\n".join([js_def("KEY_LABELS"), js_def("WORDS"), js_def("humanKey"), js_def("SCAN_TITLES"), js_def("scanTitle"),
                          js_def("COL_LABEL"), js_def("colLabel"), js_def("tildePath")]) + """
console.log(JSON.stringify({
  keys: ['env', 'no_headliner', 'allow_ip', 'cloud', 'k8s_version', 'id'].map(humanKey),
  scans: ['cis', 'stig-host', 'host-cis', 'images', 'report', ''].map(scanTitle),
  cols: ['recovery_s', 'recovery_bound_s', 'min_availability', 'foo_bar'].map(colLabel),
  homes: ['/Users/ann/.cloudseed', '/home/bob/work/cs', '/root/.cloudseed', '/opt/cs', '/Users/ann'].map(tildePath),
}));"""
        got = self.node(code)
        self.assertEqual(got["keys"], ["Environment", "Skip the research brief", "Allow IP", "Cloud", "Kubernetes version", "ID"])
        self.assertEqual(got["scans"], ["CIS Kubernetes benchmark", "Host STIG (OpenSCAP)", "Host CIS (OpenSCAP)", "Vulnerability scan", "report scan", "Report"])
        self.assertEqual(got["cols"], ["recovery (s)", "recovery bound (s)", "min availability", "foo bar"])
        self.assertEqual(got["homes"], ["~/.cloudseed", "~/work/cs", "~/.cloudseed", "/opt/cs", "~"])

    def test_backticks_become_code(self):
        got = self.node(EL_STUB + js_def("withCode") + "\nconsole.log(JSON.stringify(withCode('pairs with `cs finops` for bills; `cs dr` too').map((x) => (typeof x === 'object' ? ['code', text(x)] : x))));")
        self.assertEqual(got, ["pairs with ", ["code", "cs finops"], " for bills; ", ["code", "cs dr"], " too"])


class SourceTests(unittest.TestCase):
    """Behaviour that needs the whole page, pinned at the source (the browser checks ran against a live console)."""

    def test_busy_buttons_keep_focus(self):
        api = js_def("api")
        self.assertIn("btn.setAttribute('aria-disabled', 'true')", api)
        self.assertNotIn("btn.disabled = true", api)
        self.assertIn("if (hit && hit.until && Date.now() < hit.until) return hit.p;", api)
        self.assertIn("if (isBusy(b)) { e.preventDefault(); e.stopImmediatePropagation(); return; }", JS)
        # a redraw puts focus back on the same button (data-fk) or the nearest one with the same text
        self.assertIn("'data-fk': fk('outputs')", JS)
        self.assertIn("focusBack(sec, mark)", body_of("function refreshView()", "function viewError"))

    def test_browsing_never_retargets_the_cli(self):
        # webui-functional#1/#13, webui-visual#9: choosing or managing an environment here does not run `cs env use`
        self.assertEqual(JS.count("/api/env/use"), 1)
        self.assertIn("/api/env/use", js_def("useInTerminal"))
        self.assertNotIn("api(", js_def("selectEnv"))
        card = js_def("envCard")
        self.assertIn("!full ? el('button'", card)                     # 'Manage →' only on the Overview
        self.assertIn("showEnvCard(e.id)", card)
        self.assertNotIn("go(e.kubernetes ? 'platform' : 'envs')", card)
        # Databricks / Snowflake profiles: the action has cloud / env fields (filled from the page's choice like every
        # other env-bound form), so the old stopgap that glued --env onto the free-form arguments is gone
        self.assertNotIn("pe.id", js_def("actionForm"))
        self.assertIn("env", webui.mcp.TOOLS["cloudseed_managed"]["schema"]["properties"])
        self.assertEqual(webui.build_argv("cloudseed_managed", {"service": "databricks", "cloud": "aws", "env": "dev"}), ["databricks", "--env", "aws-dev", "status"])
        self.assertEqual(webui.build_argv("cloudseed_managed", {"service": "databricks", "args": "--env aws-dev"}), ["databricks", "--env", "aws-dev"])

    def test_cards_disable_what_cannot_work_and_say_why(self):
        card = js_def("envCard")
        for why in ("vpnWhy", "sshWhy", "k8sWhy"):
            self.assertIn(f"...off({why})", card)
        self.assertIn("class: 'why muted small'", card)
        self.assertIn("run('cloudseed_update_ip', cl, 'update-ip ' + e.id, { message:", card)   # 409 brings the real command
        res = body_of("views.resilience = () =>", "views.actions = () =>")
        self.assertIn("host: needHosts, stig: needHosts, cloud: needCloud", res)

    def test_confirmation_is_narrow_and_goes_back(self):
        conf = js_def("confirmRun")
        self.assertIn("{ narrow: true, onClose: () => finish(null) }", conf)
        self.assertIn("modalSnapshot()", conf)
        self.assertIn("destroyConfirmNote(args, target)", conf)
        form = js_def("actionForm")
        self.assertIn("disabled: !!a.always_destructive", form)
        self.assertNotIn("None of this can be undone", JS)

    def test_wizard_keeps_its_draft_and_follows_its_runs(self):
        wiz = body_of("views.create = (opts = {}) =>", "// ---------------------------------------------------------------- platform")
        self.assertIn("cur.resume(); return;", wiz)
        self.assertIn("JOB_DONE.set(job", wiz)
        # a run that saved the environment (or put its previous settings back after a failed plan) never drops what was
        # typed: the Change wizard that continues the draft carries its answers and compares them with what is saved now
        self.assertIn("return cur.follow(saved);", wiz)
        self.assertIn("carry: carry(), fresh: true", wiz)
        self.assertIn("if (step === 3 && savedAs()) return follow(savedAs(), 3);", wiz)
        self.assertIn("for (const [k, val] of Object.entries(carried.qvars || {})) { data.touched.add(k); data.qvars[k] = val; }", wiz)
        self.assertNotIn("me.updated", wiz)
        self.assertIn("c().local ? ['name', 'cidr', 'workdir']", wiz)       # vmware#5: a dedicated network for local clouds
        self.assertIn("if (!!cc.local !== !!c().local) { data.cidr = undefined;", wiz)
        self.assertIn("k.includes('=')", wiz)                                # webui-functional#8: tag keys
        self.assertIn("disabled: apply", wiz)                                # Apply waits for the tick
        self.assertIn("aria-describedby", wiz)
        self.assertNotIn("role: 'alert', style: 'color:var(--rose)'", JS)    # webui-visual#5/#15
        for opener in ("go('create', { env: null })", "go('create', { env: null, fresh: true })"):
            self.assertIn(opener, JS)

    def test_agents_switches_read_the_state_when_clicked(self):
        self.assertIn("const on = featureOn(k);", js_def("toggleFeature"))
        self.assertIn("views.agents.patch = () =>", JS)
        self.assertIn("if (views[VIEW].patch) views[VIEW].patch();", js_def("refreshView"))

    def test_refused_token_is_explained_at_once(self):
        req = js_def("request")
        self.assertIn("r.status === 401", req)
        self.assertIn("tokenGone()", req)
        self.assertIn("tokenBack()", js_def("loadState"))


class StyleTests(unittest.TestCase):
    def test_running_job_tab_keeps_its_amber_dot(self):
        # the per-state tab dots come after `.dot.run` with the same specificity: the running one must be restated there
        tabs = CSS.index(".drawer-tabs .dot {")
        self.assertIn(".drawer-tabs .dot.run { background: var(--seed); }", CSS[tabs:tabs + 400])

    def test_buttons_and_chips_never_break_inside(self):
        self.assertIn(".btn, .chip { white-space: nowrap; }", CSS)
        self.assertIn("table.undo { min-width: 560px; }", CSS)

    def test_contrast_tokens(self):
        light, dark = ":root {", '[data-theme="dark"] {'
        self.assertGreaterEqual(contrast(token(light, "rose-text"), "#ffffff"), 4.5)
        self.assertGreaterEqual(contrast(token(dark, "rose-text"), token(dark, "card")), 4.5)
        self.assertGreaterEqual(contrast(token(light, "field-border"), "#ffffff"), 3)
        self.assertGreaterEqual(contrast(token(dark, "field-border"), token(dark, "card")), 3)
        self.assertGreaterEqual(contrast(token(light, "switch-off"), "#ffffff"), 3)   # the track on the card, and the white knob on it
        self.assertGreaterEqual(contrast(token(dark, "switch-off"), "#ffffff"), 3)    # the white knob on the dark track
        self.assertGreaterEqual(contrast(token(dark, "switch-off"), token(dark, "card")), 3)
        # the warn callout title on its amber tint (rgba(245,158,11,.08) over white)
        tint = "#" + "".join(f"{round(255 + (c - 255) * .08):02x}" for c in (245, 158, 11))
        self.assertGreaterEqual(contrast(token(light, "seed-text"), tint), 4.5)
        # both dark blocks carry the same new tokens
        m = media("(prefers-color-scheme: dark)")
        for name in ("rose-text", "field-border", "switch-off"):
            self.assertIn(f"--{name}: {token(dark, name)}", m)
        self.assertIn("::placeholder { color: var(--muted); opacity: 1; }", CSS)
        self.assertIn("color: var(--rose-text)", CSS[CSS.index(".field-err {"):])
        self.assertNotIn(".btn .kbd { font-size: 11px; opacity", CSS)
        self.assertIn(".group-tile .btn.ghost { background: rgba(2,6,23,.22)", CSS)

    def test_forced_colours(self):
        block = media("(forced-colors: active)")
        for sel in (".switch { border: 1px solid ButtonText; }", ".rail-nav a.active", ".card.flat[role=\"radio\"][aria-checked=\"true\"]",
                    ".palette-list .pi.active", "forced-color-adjust: none"):
            self.assertIn(sel, block)

    def test_phone_layouts(self):
        small = media("(max-width: 640px)")
        self.assertIn(".topbar .btn-text", small)                    # (the first 640px block keeps its earlier rules)
        self.assertIn("table.reports tr { display: grid;", small)
        self.assertIn(".row.wiz-actions { position: sticky;", small)
        self.assertIn("#job-status[data-state=\"running\"]::before", small)
        self.assertIn(".env-switch { flex: 1 1 100%; order: 2; }", media("(max-width: 400px)"))
        self.assertIn(".term .box { white-space: pre;", CSS)
        self.assertIn("grid-template-rows: subgrid", CSS)
        self.assertIn(".env-switch:focus-within { border-color: var(--brand);", CSS)
        self.assertIn("bottom: calc(var(--drawer-live, 0px) + 22px)", CSS)
        self.assertIn("input[readonly]", CSS)

    def test_shell_markup(self):
        self.assertLess(INDEX.index('id="skip"'), INDEX.index('<aside class="rail"'))
        self.assertIn('<main class="content" id="main" tabindex="-1"', INDEX)
        self.assertIn('role="separator" aria-orientation="horizontal" tabindex="0"', INDEX)
        self.assertIn('role="combobox" aria-expanded="false"', INDEX)
        self.assertRegex(INDEX, r'id="palette-btn"[^>]*aria-label="[^"]+"')
        self.assertNotIn("◐", INDEX)
        self.assertNotIn("↶", INDEX)
        self.assertIn('class="i-sun"', INDEX)
        self.assertIn("$('#skip').inert = $('.shell').inert", JS)
        # the locked page: the system's logo, or the theme the page was told
        self.assertIn('<picture class="logo-auto">', LOCKED)
        self.assertIn('class="logo-dark"', LOCKED)
        self.assertIn('[data-theme="dark"] .logo-dark', CSS)


class ServerContractTests(unittest.TestCase):
    def test_helm_set_values_stay_whole(self):
        argv = webui.build_argv("cloudseed_platform", {"action": "plan", "items": ["grafana"], "set": ["ingress.hosts={a.example.com,b.example.com}", "replicas=2"]})
        i = argv.index("--set")
        self.assertEqual(argv[i:i + 4], ["--set", "ingress.hosts={a.example.com,b.example.com}", "--set", "replicas=2"])

    def test_local_wizard_cidr_reaches_setup(self):
        argv = webui.build_argv("cloudseed_setup", {"cloud": "vmware", "env": "beta", "cidr": "10.124.0.0/24", "dry_run": True})
        self.assertEqual(argv[argv.index("--cidr") + 1], "10.124.0.0/24")


if __name__ == "__main__":
    unittest.main()
