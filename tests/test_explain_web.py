"""The console's explain surface (cloudseed/web/app.js, style.css, index.html): the "?" buttons, the Explain panel,
the palette's "Explain: …" entries, the ? key and the Help page.

  * no "?" can point at a missing page: every query app.js names - the literal first argument of explainBtn /
    openExplain / modalExplain, every `explain: '…'` option, every value of the XQ_* tables, and each member of the
    dynamic families it builds (target <cloud>, group <g>, item <i>, variable <cloud> <question>, variables <cloud>,
    command <action>) - is one explain.lookup() finds; and every call passes one of those (no unchecked expression)
  * the reflow of help text into a page (xpBlocks, run under node when it is installed) keeps every word of every
    text section of every explainable page, and only the page's own commands become command rows
  * the panel is an accessible dialog; the Help page's `explain X` opens it instead of running a job
  * opt-in (CS_UI_SMOKE=<dir holding node_modules/puppeteer-core>): a headless Chrome opens the panel from several
    pages of a served console without console errors
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-explain-web-"))

from cloudseed import clouds, explain, platform as pl, webui  # noqa: E402

WEB = Path(webui.WEB_ROOT)
JS = (WEB / "app.js").read_text()
CSS = (WEB / "style.css").read_text()
INDEX = (WEB / "index.html").read_text()
NODE = shutil.which("node")
REPO = Path(__file__).resolve().parent.parent

# the calls that take a query, and which argument it is (0-based)
CALLS = {"explainBtn": 0, "openExplain": 0, "modalExplain": 0, "labelExplain": 1, "xqCorner": 1}
# a template literal's family -> every query it can produce
FAMILIES = {
    "target ${": lambda: [f"target {c}" for c in ("aws", "gcp", "azure", "vmware")],
    "group ${": lambda: [f"group {g}" for g in pl.GROUPS],
    "item ${": lambda: [f"item {i['name']}" for i in webui.platform_catalog()["items"]],
    "variables ${": lambda: [f"variables {c}" for c in ("aws", "gcp", "azure", "vmware")],
    "variable ${": lambda: [f"variable {c} {q.key}" for c in ("aws", "gcp", "azure", "vmware") for q in clouds.get(c).questions],
}
# the expressions a call may pass instead of a literal: each is checked below (actions, tables: bq is an XQ_BASICS
# value) or is the plumbing that carries a query already shown (the panel, the palette, a dialog put back)
ALLOWED_EXPR = re.compile(r"^(?:q|x|bq|xqNorm\(q\)|o\.explain|n\.query|r\.query|back\.explain|\(\$\('\.modal-head > \.xq'\) \|\| \{ dataset: \{\} \}\)\.dataset\.explain|"
                          r"actionXq\([\w.]+\)|XQ_[A-Z_]+\[.*\]|XQ_VIEW\[VIEW\] \?\? ''|"
                          r"\$\('#crumb-xq'\)\.dataset\.explain|XQ_CREDS\[g\] \|\| 'creds'|f \? f\.query : q|"
                          r"q\.replace\(/\^explain\\s\*/i, ''\))$")


def _args(src: str, start: int, n: int = 0) -> str:
    """Argument n of the call whose '(' is at start-1 (balanced brackets, quotes and template literals)."""
    depth, i, quote = 0, start, None
    while i < len(src):
        ch = src[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return src[start:i].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            if n == 0:
                return src[start:i].strip()
            n, start = n - 1, i + 1
        i += 1
    raise AssertionError("unbalanced call at %d" % start)


# app.js without its // comments (a comment starts a line or follows a space; `//` in strings and regexes does not)
CODE = re.sub(r"(?m)(?:^|(?<=\s))//(?:\s.*)?$", "", JS)


def call_args() -> list[str]:
    out = []
    for name, n in CALLS.items():
        for m in re.finditer(r"(?<![\w.])%s\(" % name, CODE):
            if CODE[max(0, m.start() - 20):m.start()].rstrip().endswith(("const", "function")):
                continue                                   # the definition itself
            out.append(_args(CODE, m.end(), n))
    for m in re.finditer(r"(?<![\w'-])explain: ", CODE):   # a modal's opts.explain (not 'data-explain': or a string)
        out.append(_args(CODE, m.end()))
    return out


def table_values() -> dict[str, list[str]]:
    """Every quoted value of each `const XQ_NAME = {...};` / `[...]` table (keys are bare identifiers)."""
    out = {}
    for m in re.finditer(r"const (XQ_[A-Z_]+) = ([\[{])", JS):
        close = {"[": "]", "{": "}"}[m.group(2)]
        depth, i = 0, m.end() - 1
        while True:
            depth += JS[i] == m.group(2)
            depth -= JS[i] == close
            if depth == 0:
                break
            i += 1
        body = JS[m.end() - 1:i + 1]
        vals = re.findall(r"(?::|\[|,)\s*'([^']*)'", body)
        out[m.group(1)] = vals
    return out


def action_queries() -> list[str]:
    """What actionXq() gives every action of the registry: XQ_ACTION's exception, else 'command <name, _ as ->'."""
    table = dict(re.findall(r"(cloudseed_\w+): '([^']*)'", JS[JS.index("const XQ_ACTION"):JS.index("\n", JS.index("const XQ_ACTION"))]))
    return ["command ops" if a["name"].startswith("cloudseed_ops_") else table.get(a["name"]) or
            "command " + a["name"].replace("cloudseed_", "").replace("_", "-") for a in webui.actions_catalog()]


class QueriesResolve(unittest.TestCase):
    """No "?" points at a missing page."""

    def assert_found(self, queries, where):
        missing = [q for q in queries if not explain.lookup(q)["found"]]
        self.assertEqual(missing, [], f"{where}: explain.lookup() finds nothing for these")

    def test_every_call_passes_a_literal_a_known_family_or_a_checked_expression(self):
        args = call_args()
        self.assertGreater(len(args), 40)
        literals, families, other = [], set(), []
        for a in args:
            if re.fullmatch(r"'[^']*'", a):
                literals.append(a[1:-1])
            elif a.startswith("`"):
                fam = next((f for f in FAMILIES if a.startswith("`" + f)), None)
                self.assertIsNotNone(fam, f"a template query of an unknown family: {a}")
                families.add(fam)
            elif not ALLOWED_EXPR.match(a):
                other.append(a)
        self.assertEqual(other, [], "explain calls with an expression this test does not check")
        self.assert_found(literals, "literal queries")
        self.assertEqual(families, set(FAMILIES), "every family is used (drop the ones that are not)")

    def test_every_family_member_resolves(self):
        for fam, members in FAMILIES.items():
            got = members()
            self.assertTrue(got, fam)
            self.assert_found(got, fam)

    def test_every_table_value_resolves(self):
        tables = table_values()
        for name in ("XQ_VIEW", "XQ_BASICS", "XQ_MODE", "XQ_CREDS", "XQ_REPORT", "XQ_POPULAR", "XQ_ACTION"):
            self.assertIn(name, tables)
            self.assertTrue(tables[name], name)
            self.assert_found(tables[name], name)
        # the index is the Help view's page; every view has one
        self.assertIn("help: ''", JS)
        views = re.findall(r"\['(\w+)', '[^']+', '\d'\]", JS)
        view_tbl = JS[JS.index("const XQ_VIEW"):JS.index("\n", JS.index("const XQ_VIEW"))]
        self.assertEqual([v for v in views if f"{v}: '" not in view_tbl], [])

    def test_every_action_card_resolves(self):
        qs = action_queries()
        self.assertEqual(len(qs), len(webui.actions_catalog()))
        self.assert_found(qs, "action cards")

    def test_basics_cover_each_clouds_fields(self):
        basics = JS[JS.index("const XQ_BASICS"):JS.index("};", JS.index("const XQ_BASICS"))]
        for cloud in ("aws", "gcp", "azure"):
            row = re.search(r"%s: \{([^}]*)\}" % cloud, basics).group(1)
            for key in ("env", "name", "region", "state", "cidr", "allow_ip", "workdir", "tags"):
                self.assertIn(f"{key}: '", row, f"{cloud} {key}")
        vm = re.search(r"vmware: \{([^}]*)\}", basics).group(1)
        for key in ("env", "name", "cidr", "workdir"):
            self.assertIn(f"{key}: '", vm)


def js_def(name: str) -> str:
    """Source of `const name = ...` in app.js, up to the line where its braces balance."""
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


@unittest.skipUnless(NODE, "node is not installed")
class Reflow(unittest.TestCase):
    """xpBlocks / xpListKind: help text laid out for a terminal, reflowed into a page."""

    def node(self, code: str):
        r = subprocess.run([NODE], input=code, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def blocks(self, cases):
        code = js_def("xpBlocks") + f"\nconsole.log(JSON.stringify({json.dumps(cases)}.map(([l, c]) => xpBlocks(l, c))));"
        return self.node(code)

    def test_shapes(self):
        cases = [
            # prose joined, bullets with continuation lines, a definition list with aligned continuations
            (["First line of a", "paragraph that goes on.", "", "- one bullet", "  continues here", "- two"], []),
            (["--env NAME      environment name", "                continued", "--tag K=V       extra tag"], []),
            # a variable row: its default on the term's line, its description indented under it
            (["az_count                      default: 2", "    Number of availability zones.", "subnet_newbits                default: 4"], []),
            # a command only when the page lists it; its comment becomes a note
            (["cloudseed destroy aws --env dev     # clean slate", "cloudseed is a stdlib CLI and"], ["cs destroy aws --env dev"]),
            # box drawing stays preformatted
            (["╭──╮", "│ x│", "╰──╯"], []),
        ]
        prose, dl, var, cmd, box = self.blocks(cases)
        self.assertEqual([b["type"] for b in prose], ["p", "ul"])
        self.assertEqual(prose[0]["text"], "First line of a paragraph that goes on.")
        self.assertEqual(prose[1]["items"], ["one bullet continues here", "two"])
        self.assertEqual([(r["term"], r["desc"]) for r in dl[0]["rows"]], [("--env NAME", "environment name continued"), ("--tag K=V", "extra tag")])
        self.assertEqual([(r["term"], r["desc"], r["more"]) for r in var[0]["rows"]],
                         [("az_count", "default: 2", "Number of availability zones."), ("subnet_newbits", "default: 4", "")])
        self.assertEqual(cmd[0], {"type": "cmd", "ind": 0, "rows": [{"cmd": "cloudseed destroy aws --env dev", "key": "cs destroy aws --env dev", "note": "clean slate"}]})
        self.assertEqual(cmd[1]["type"], "p")
        self.assertEqual(box, [{"type": "pre", "text": "╭──╮\n│ x│\n╰──╯"}])

    def test_list_kinds(self):
        code = js_def("xpListKind") + "\nconsole.log(JSON.stringify(%s.map(xpListKind)));" % json.dumps([
            ["cs vpn users", "cs vpn add-user alice"], ["group: resilience", "values[aws]: a.b = c"], ["istio — mesh  [extra]", "falco — runtime"],
            ["no public IPs", "allowed_ssh_cidrs: IPv4 only"], []])
        self.assertEqual(self.node(code), ["cmd", "kv", "links", "plain", "plain"])

    def test_every_text_section_keeps_its_words_and_only_its_commands(self):
        pages = [explain.lookup(n["query"]) for n in explain.names() if n["kind"] != "variable"]
        cases = [[s["lines"], p["commands"]] for p in pages for s in p["sections"] if s["format"] == "text"]
        self.assertGreater(len(cases), 100)
        got = self.blocks(cases)

        def words(text):
            return re.findall(r"[A-Za-z0-9_]{3,}", text)

        for (lines, cmds), blocks in zip(cases, got):
            shown = []
            for b in blocks:
                if b["type"] == "p":
                    shown.append(b["text"])
                elif b["type"] == "ul":
                    shown += b["items"]
                elif b["type"] == "pre":
                    shown.append(b["text"])
                elif b["type"] == "cmd":
                    shown += [r["cmd"] + " " + r["note"] for r in b["rows"]]
                    self.assertTrue(all(r["key"] in cmds for r in b["rows"]))
                else:
                    shown += [r["term"] + " " + r["desc"] + " " + r["more"] for r in b["rows"]]
            self.assertEqual(sorted(words(" ".join(shown))), sorted(words(" ".join(lines))), lines[:3])


class Markup(unittest.TestCase):
    def test_the_panel_is_a_labelled_modal_dialog(self):
        self.assertRegex(INDEX, r'id="xp-sheet" role="dialog" aria-modal="true" aria-labelledby="xp-title"')
        self.assertIn('id="xp-title" tabindex="-1"', INDEX)
        self.assertRegex(INDEX, r'id="crumb-xq"[^>]*aria-haspopup="dialog"[^>]*aria-label="Explain this page"')
        self.assertIn('id="xtip" class="xtip" role="tooltip" hidden', INDEX)
        # the page is inert while it is open; Esc and the backdrop close it; the ? key opens the page's own
        self.assertIn("layers.unshift([xp, () => $('#xp-title')])", JS)
        self.assertIn("if (e.key === '?') { e.preventDefault(); openExplain(XQ_VIEW[VIEW] ?? ''); return; }", JS)
        self.assertIn("$('#xp-scrim').onclick = () => closeExplain();", JS)

    def test_help_explain_uses_the_panel_not_a_job(self):
        self.assertNotIn("run('cloudseed_explain'", JS)
        self.assertIn("openExplain(q.replace(/^explain\\s*/i, ''), { from: inp })", JS)
        self.assertIn("kind: 'explain', label: 'Explain: '", JS)

    def test_styles(self):
        self.assertIn(".xp-sheet {", CSS)
        phone = CSS[CSS.rindex("@media (max-width: 640px) {"):]
        self.assertIn(".xp-sheet { top: auto; left: 0; right: 0; bottom: 0;", phone)                   # a bottom sheet on phones
        self.assertIn(".xq::after { content: \"\"; position: absolute; inset: -5px;", CSS)       # a finger-sized target
        self.assertIn("margin: -3px 0;", CSS[CSS.index(".xq {"):CSS.index("\n", CSS.index(".xq {"))])   # no taller lines


def _free_port() -> int:
    """A free ephemeral port chosen by the OS (bind to port 0): suites running at the same time never collide."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


SMOKE = os.environ.get("CS_UI_SMOKE", "")
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SMOKE_JS = r"""
const puppeteer = require('puppeteer-core');
(async () => {
  const [url, chrome] = process.argv.slice(2);
  const b = await puppeteer.launch({ executablePath: chrome, headless: 'new' });
  const p = await b.newPage(); await p.setViewport({ width: 1280, height: 860 });
  const errs = []; p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); }); p.on('pageerror', (e) => errs.push(e.message));
  await p.goto(url, { waitUntil: 'networkidle2' }); await new Promise((r) => setTimeout(r, 800));
  const got = [];
  for (const v of ['overview', 'create', 'platform', 'resilience', 'actions', 'agents', 'creds', 'help']) {
    await p.evaluate((v) => document.querySelector(`#nav a[data-view="${v}"]`).click(), v); await new Promise((r) => setTimeout(r, 500));
    await p.evaluate(() => (document.querySelector('.view.active .xq') || document.querySelector('#crumb-xq')).click()); await new Promise((r) => setTimeout(r, 600));
    got.push(await p.evaluate(() => ({ open: !document.querySelector('#explain').classList.contains('hidden'), kind: document.querySelector('#xp-kind').textContent, title: document.querySelector('#xp-title').textContent })));
    await p.keyboard.press('Escape'); await new Promise((r) => setTimeout(r, 300));
  }
  console.log(JSON.stringify({ got, errs })); await b.close();
})();
"""


@unittest.skipUnless(SMOKE and NODE and os.path.exists(CHROME), "opt-in: CS_UI_SMOKE=<dir with node_modules/puppeteer-core>")
class HeadlessSmoke(unittest.TestCase):
    def test_panel_opens_from_several_pages_without_errors(self):
        home = tempfile.mkdtemp(prefix="cs-explain-smoke-")
        Path(home, "settings.json").write_text('{"ui": true}')
        port = _free_port()
        env = dict(os.environ, CLOUDSEED_HOME=home, HOME=home)
        srv = subprocess.Popen([sys.executable, str(REPO / "bin" / "cloudseed"), "ui", "serve", "--port", str(port)], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            tok = Path(home, "ui", "token")
            for _ in range(100):
                if tok.exists():
                    break
                time.sleep(0.1)
            time.sleep(0.5)
            script = Path(home, "smoke.js")
            script.write_text(SMOKE_JS)
            r = subprocess.run([NODE, str(script), f"http://127.0.0.1:{port}/?token={tok.read_text().strip()}", CHROME],
                               capture_output=True, text=True, timeout=120, cwd=SMOKE, env=dict(os.environ, NODE_PATH=str(Path(SMOKE, "node_modules"))))
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout.strip().splitlines()[-1])
            self.assertEqual(out["errs"], [])
            for g in out["got"]:
                self.assertTrue(g["open"] and g["title"] and "Not found" not in g["kind"] and "Error" not in g["kind"], g)
        finally:
            srv.terminate()
            srv.wait(10)
            shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
