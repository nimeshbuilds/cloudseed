"""Wave 2 web console fixes (cloudseed/web/app.js, style.css).

Pure helpers of app.js run under node (skipped when node is not installed) with tiny stand-ins for the DOM:
  * verdict colours: INCONCLUSIVE / N/A amber, FAIL / INTERRUPTED red (resilience#31, webui-backend#19)
  * the Reports scan chip follows the report's verdict, not its counters (webui-backend#19)
  * FIPS chips: 'compatible' only is FIPS-ok, 'tls-restricted' is TLS-pinned (platform-catalog#37)
  * failed / pending releases are shown but not counted as installed (platform-logic#20)
  * whole-number inputs carry step/min/max and refuse 2.5 or 0 nodes (azure#14)
  * the SSE stream resumes after its last event id instead of wiping the output (webui-backend#23)
  * a job the server reports lost (rc -1) stays lost (webui-backend#23)
  * Undo / Discard name the exact entry (ops#1, ops#30, webui-backend#0)
Server-side contracts the page relies on are checked in Python.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-wave2-web-"))

from cloudseed import mcp, webui  # noqa: E402

WEB = Path(webui.WEB_ROOT)
JS = (WEB / "app.js").read_text()
CSS = (WEB / "style.css").read_text()


def js_def(src: str, start: str) -> str:
    """Source of one top-level definition: `const x = ...;` up to its `;`, or `function x(...) {...}` up to its brace
    (strings and comments are skipped; the definitions read here hold no regex literal with a quote in it)."""
    i = src.index(start)
    is_fn = start.startswith(("function", "async function"))
    depth, k = 0, i
    while k < len(src):
        c = src[k]
        if src.startswith("//", k):              # a comment runs to the end of its line (it may hold an apostrophe)
            k = src.index("\n", k)
            continue
        if src.startswith("/*", k):
            k = src.index("*/", k) + 2
            continue
        if c in "'\"`":
            k += 1
            while src[k] != c:
                k += 2 if src[k] == "\\" else 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if is_fn and depth == 0 and c == "}":
                return src[i:k + 1]
        elif c == ";" and depth == 0 and not is_fn:
            return src[i:k + 1]
        k += 1
    raise AssertionError(f"no end found for {start}")


# a stand-in for the page's el(): {tag, attrs, kids}, with the few element methods field() uses
EL_STUB = """
const el = (tag, attrs = {}, ...kids) => ({ tag, attrs: { ...attrs }, kids: kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false),
  setAttribute(k, v) { this.attrs[k] = v; }, prepend(x) { this.kids.unshift(x); }, value: attrs.value, required: false });
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class NodeHelperTests(unittest.TestCase):
    def node(self, code: str):
        out = subprocess.run(["node", "-e", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_verdict_colours(self):
        code = js_def(JS, "const verdictClass = ") + "\nconsole.log(JSON.stringify(%s.map(verdictClass)));" % json.dumps(
            ["PASS", "FAIL", "FAIL - 2 failed", "INTERRUPTED", "INCONCLUSIVE", "N/A", "SKIP", "ERROR", "?", "", None, "pass"])
        self.assertEqual(self.node(code), ["leaf", "rose", "rose", "rose", "seed", "seed", "seed", "rose", "", "", "", "leaf"])

    def test_verdict_chip_and_cells_use_the_mapping(self):
        code = EL_STUB + js_def(JS, "const verdictClass = ") + "\n" + js_def(JS, "const verdictChip = ") + "\n" + js_def(JS, "const cellChip = ") + (
            "\nconsole.log(JSON.stringify([verdictChip('chaos', {verdict: 'INCONCLUSIVE'}).attrs.class, verdictChip('DR', {verdict: 'INTERRUPTED'}).attrs.class,"
            " verdictChip('FIPS', {verdict: 'N/A'}).attrs.class, verdictChip('CIS', null).kids[0], cellChip('MEDIUM').attrs.class, cellChip('OK').attrs.class]));")
        self.assertEqual(self.node(code), ["chip seed", "chip rose", "chip seed", "CIS: —", "chip seed", "chip leaf"])

    def test_scan_chip_follows_the_verdict(self):
        code = "\n".join([js_def(JS, "const verdictClass = "), js_def(JS, "const num = "), js_def(JS, "function scanResult("), js_def(JS, "function scanChip(")])
        cases = [
            {"verdict": "PASS", "summary": {"controls passed": 40, "controls failed": 3}},            # kube: failed LOW controls still PASS
            {"verdict": "FAIL", "summary": {"pass": 10, "fail": 4}},
            {"verdict": "INCONCLUSIVE", "summary": {}},
            {"verdict": "N/A", "summary": {"pass": 0, "fail": 0}},
            {"verdict": "FAIL", "summary": {"pass": 5, "fail": 0, "errors": 2}},
            {"summary": {}},                                                                          # an old file without totals
            {"summary": {"pass": 3, "fail": 0}},
            {"verdict": "PASS", "summary": {"pass": 12, "fail": 0}},
        ]
        got = self.node(code + f"\nconsole.log(JSON.stringify({json.dumps(cases)}.map((it) => {{ const c = scanChip(it); return [c.cls, c.label]; }})));")
        self.assertEqual(got, [["leaf", "passed"], ["rose", "4 failed"], ["seed", "inconclusive"], ["seed", "n/a"],
                               ["rose", "failed, 2 host(s) not scanned"], ["", "no totals"], ["leaf", "clean"], ["leaf", "clean"]])

    def test_fips_and_release_chips(self):
        code = EL_STUB + "\n".join([js_def(JS, "const relState = "), js_def(JS, "const isInstalled = "), js_def(JS, "const releaseFix = "),
                                    js_def(JS, "const releaseChip = "), js_def(JS, "const fipsChip = ")])
        code += """
const txt = (c) => (c ? c.attrs.class + ':' + c.kids[0] : null);
console.log(JSON.stringify({
  compatible: txt(fipsChip({ fips: 'compatible' }, null)),
  tls: txt(fipsChip({ fips: 'tls-restricted' }, { id: 'aws-dev', fips: true })),
  other: txt(fipsChip({ fips: 'yes' }, null)),
  none_plain: txt(fipsChip({ fips: '' }, { id: 'aws-dev', fips: false })),
  none_fips: txt(fipsChip({ fips: '' }, { id: 'aws-dev', fips: true })),
  states: [undefined, { state: 'installed' }, { state: 'built-in' }, { state: 'failed' }, { state: 'pending' }, { state: 'pending-upgrade' }].map((s) => [relState(s), isInstalled(s)]),
  failed: txt(releaseChip('keda', { state: 'failed' }, 'failed')),
  pendingTitle: releaseChip('keda', { state: 'pending', fix: 'cs helm rollback keda -n keda' }, 'pending').attrs.title,
}));"""
        got = self.node(code)
        self.assertEqual(got["compatible"], "chip sky:FIPS-ok")
        self.assertEqual(got["tls"], "chip seed:FIPS: TLS-pinned")
        self.assertIsNone(got["other"])                 # only 'compatible' is FIPS-ok
        self.assertIsNone(got["none_plain"])
        self.assertEqual(got["none_fips"], "chip rose:not FIPS")
        self.assertEqual(got["states"], [["", False], ["", True], ["", True], ["failed", False], ["pending", False], ["pending", False]])
        self.assertEqual(got["failed"], "chip rose:failed")
        self.assertEqual(got["pendingTitle"], "cs helm rollback keda -n keda")

    def test_integer_fields_have_bounds(self):
        code = EL_STUB + js_def(JS, "function field(") + """
const f = field('days', { type: 'integer', minimum: 1, description: 'days of billing history' }, false, '');
const input = f.kids[1];
console.log(JSON.stringify(input.attrs));"""
        attrs = self.node(code)
        self.assertEqual((attrs["type"], attrs["step"], attrs["min"]), ("number", "1", 1))
        self.assertIsNone(attrs.get("max"))             # el() leaves undefined attributes out

    def test_read_field_refuses_fractions_and_out_of_range(self):
        code = js_def(JS, "function readField(") + """
const inp = (value, min = '', max = '') => ({ type: 'number', step: '1', min, max, value, name: 'var:kubernetes_node_count', dataset: {}, validity: {} });
const res = [['3', '1'], ['2.5', '1'], ['0', '1'], ['7', '1', '5'], ['', '1']].map(([v, lo, hi]) => { try { return readField(inp(v, lo, hi)) ?? null; } catch (e) { return e.message; } });
console.log(JSON.stringify(res));"""
        self.assertEqual(self.node(code), [3, "kubernetes_node_count: a whole number", "kubernetes_node_count: at least 1",
                                           "kubernetes_node_count: at most 5", None])

    def test_wizard_integer_minimums(self):
        code = js_def(JS, "const intMin = ") + "\nconsole.log(JSON.stringify(%s.map(intMin)));" % json.dumps(
            [{"key": "kubernetes_node_count"}, {"key": "az_count"}, {"key": "workload_count"}, {"key": "kubernetes_workers"},
             {"key": "kubernetes_control_planes"}, {"key": "bastion_memory_mb"}, {"key": "workload_count", "minimum": 2}])
        self.assertEqual(self.node(code), [1, 1, 0, 0, 1, 1, 2])

    def test_stream_resumes_after_the_last_event_id(self):
        # the server honours Last-Event-ID on reconnect: the page must keep what it showed and skip repeats
        code = """
let activeJob = null, es = null; const jobs = new Map([['j1', { id: 'j1', label: 'plan', running: true }]]);
const out = { lines: [], append(x) { this.lines.push(x); }, scrollTop: 0, scrollHeight: 0 };
const status = { textContent: '' };
const $ = (s) => (s === '#job-output' ? out : status);
const jobHeader = () => { out.lines = []; }; const jobStatusText = () => 'running…'; const renderTabs = () => {}; const openDrawer = () => {};
const colorize = (l) => l; const TOKEN = 't'; const checkJob = () => {}; const LOST_LINE = 'LOST'; let finished = null; const jobFinished = (d) => { finished = d; };
class FakeES { constructor(u) { FakeES.last = this; this.url = u; this.readyState = 1; this.listeners = {}; } addEventListener(n, f) { this.listeners[n] = f; } close() { this.readyState = 2; } }
FakeES.CONNECTING = 0; const EventSource = FakeES;
""" + js_def(JS, "function showJob(") + """
showJob('j1'); const s = FakeES.last;
const msg = (line, id) => s.onmessage({ data: JSON.stringify(line), lastEventId: String(id) });
s.onopen(); msg('one', 1); msg('two', 2);
s.readyState = 0; s.onerror();            // network blip: the browser reconnects by itself
s.readyState = 1; s.onopen(); msg('two', 2); msg('three', 3);
console.log(JSON.stringify({ lines: out.lines, status: status.textContent, url: s.url }));"""
        got = self.node(code)
        self.assertEqual(got["lines"], ["one", "two", "three"])
        self.assertIn("/api/jobs/j1/stream?token=t", got["url"])

    def test_a_job_the_server_reports_lost_stays_lost(self):
        code = """
let activeJob = 'j1'; const jobs = new Map([['j1', { id: 'j1', label: 'apply', running: true }]]); const seenRunning = new Set();
const out = { lines: [], append(x) { this.lines.push(x); }, scrollTop: 0, scrollHeight: 0 }; const status = { textContent: '' };
const $ = (s) => (s === '#job-output' ? out : status); const colorize = (l) => l; const renderTabs = () => {}; const announce = () => false; const scheduleRefresh = () => {};
""" + "\n".join([js_def(JS, "const ENDED_UNKNOWN_LINE = "), js_def(JS, "const jobStatusText = "), js_def(JS, "function trackJob("), js_def(JS, "function jobFinished(")]) + """
jobFinished({ id: 'j1', rc: -1, lost: true, seconds: 3 });
const j = jobs.get('j1');
jobFinished({ id: 'j2', rc: 0, seconds: 1 });
console.log(JSON.stringify({ lost: j.lost, gone: !!j.gone, status: jobStatusText(j), last: out.lines[out.lines.length - 1], ok: jobs.get('j2').lost }));"""
        got = self.node(code)
        self.assertTrue(got["lost"])
        self.assertFalse(got["gone"])                    # its output is still on the server: the tab keeps streaming it
        self.assertEqual(got["status"], "lost (console server restarted)")
        self.assertIn("exit code is unknown", got["last"])
        self.assertFalse(got["ok"])

    def test_undo_and_discard_target_the_exact_entry(self):
        base = js_def(JS, "const action = ") + "\n" + js_def(JS, "const undoProps = ") + "\n" + js_def(JS, "function undoTarget(") + "\n" + js_def(JS, "const canDiscard = ")
        rows = [{"id": "e3", "scope": "aws-dev", "summary": "platform install keda"}, {"id": "e2", "scope": "global", "summary": "creds set X"},
                {"id": "e1", "scope": "vmware-lab-2", "summary": "setup"}]
        probe = f"\nconst list = {json.dumps(rows)};\nconsole.log(JSON.stringify(list.map((e) => [undoTarget(e, list), canDiscard(e)])));"
        with_drop = self.node("const ACTIONS = [{ name: 'cloudseed_undo', schema: { properties: { cloud: {}, env: {}, id: {}, drop: {}, list: {} } } }];\n" + base + probe)
        self.assertEqual(with_drop, [[{"cloud": "aws", "env": "dev", "id": "e3"}, True], [{"id": "e2"}, True],
                                     [{"cloud": "vmware", "env": "lab-2", "id": "e1"}, True]])
        # an older server without drop: no Discard button; without id a global row is only undoable when it is the newest overall
        without = self.node("const ACTIONS = [{ name: 'cloudseed_undo', schema: { properties: { cloud: {}, env: {}, list: {} } } }];\n" + base + probe)
        self.assertEqual(without, [[{"cloud": "aws", "env": "dev"}, False], [None, False], [{"cloud": "vmware", "env": "lab-2"}, False]])


class SourceTests(unittest.TestCase):
    def test_run_sends_only_registry_actions(self):
        # webui-backend#20: the unused raw {argv} fallback is gone; 409 answers are handled (tick dialog, conflicting job)
        body = js_def(JS, "async function run(")
        self.assertNotIn("argv: args", body)
        self.assertIn("api('/api/run', { action, args, label })", body)
        self.assertIn("d.needs_confirm", body)
        self.assertIn("adoptJob(d.job)", body)

    def test_cancel_toast_uses_the_server_message(self):
        self.assertIn("r.message ||", JS[JS.index("$('#job-cancel').onclick"):JS.index("$('#job-copy').onclick")])

    def test_update_ip_is_not_offered_for_local_clouds(self):
        card = js_def(JS, "function envCard(")
        self.assertIn(".local", card)
        self.assertIn("...ipOff", card)

    def test_change_wizard_keeps_workdir_and_allow_list(self):
        # cli-lifecycle#8: an existing environment cannot move (setup refuses another --workdir); a blank or unchanged
        # allow-list is not sent, so setup keeps the saved one
        self.assertIn("!(k === 'workdir' && isChange())", JS)
        self.assertIn("cidrList(data.allow_ip) !== cidrList(base.allow_ip)", JS)
        self.assertIn("workdir: e.workdir || undefined", JS)
        # a cleared saved answer is reset with KEY=null (back to the default) instead of being silently kept
        self.assertIn("if (cleared(q)) vars[q.key] = null;", JS)
        self.assertIn("if (vars[k] === null) continue;", JS)

    def test_platform_error_banner_and_attention_filter(self):
        plat = JS[JS.index("views.platform = async"):JS.index("views.resilience = ")]
        self.assertIn("class: 'callout warn', role: 'alert'", plat)
        self.assertIn("'Retry'", plat)
        self.assertIn("isInstalled(inst[i.name])", plat)          # failed/pending releases do not count as installed
        self.assertIn("PLAT_FILTER.i = ''", plat)

    def test_css(self):
        self.assertNotIn(".pi:hover", CSS)                         # JS moves the selection on mouse move: one highlight only
        for sel in (".callout.warn", ".item.failed", ".item.pending"):
            self.assertIn(sel + " {", CSS)


class ServerContractTests(unittest.TestCase):
    """What the console sends must build the intended command line."""

    def test_undo_by_id_builds_an_exact_command(self):
        props = mcp.TOOLS["cloudseed_undo"]["schema"]["properties"]
        self.assertIn("id", props)                                  # app.js only sends id when the schema declares it
        argv = webui.build_argv("cloudseed_undo", {"id": "20260101-000000-abcd", "confirm": True})
        self.assertEqual(argv[:3], ["undo", "--id", "20260101-000000-abcd"])
        if "global" not in props:
            self.assertNotIn("--global", argv)
        env_argv = webui.build_argv("cloudseed_undo", {"cloud": "aws", "env": "dev", "id": "x1", "confirm": True})
        self.assertIn("aws", env_argv)
        self.assertIn("--id", env_argv)
        if "drop" in props:                                         # the Discard button appears once the tool can drop
            self.assertIn("--drop", webui.build_argv("cloudseed_undo", {"id": "x1", "drop": True, "confirm": True}))

    def test_undo_without_a_target_is_refused(self):
        # a global row must never send an empty target (that would undo the newest entry of any environment)
        with self.assertRaises(ValueError):
            webui.build_argv("cloudseed_undo", {"confirm": True})

    def test_integer_schemas_expose_their_minimum(self):
        days = mcp.TOOLS["cloudseed_finops"]["schema"]["properties"]["days"]
        self.assertEqual((days["type"], days.get("minimum")), ("integer", 1))   # field() turns it into min="1"


if __name__ == "__main__":
    unittest.main()
