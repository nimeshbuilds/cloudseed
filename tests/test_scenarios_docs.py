"""The scenario pages (docs/scenarios/) never drift from the CLI.

- Every `cloudseed ...` / `cs ...` command in a shell code block of a scenario page parses with the real argparse parser
  (cloudseed.cli.build_parser, the same argv rewriting `cloudseed` itself applies). Nothing is executed, no network.
- Every page has the agreed anatomy (outcome, verification label, diagram, prerequisites, verify, clean up, what just
  happened, next steps) and a runnable script tests/scenarios/NN-<slug>.sh.
- The coverage matrix in docs/scenarios/index.md is exactly what the pages contain, and it leaves no command or
  sub-command of the CLI uncovered. After editing a page, regenerate it:

      python3 tests/test_scenarios_docs.py --write-matrix
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs" / "scenarios"
SCRIPTS = ROOT / "tests" / "scenarios"
INDEX = DOCS / "index.md"

sys.path.insert(0, str(ROOT))
_SAVED_HOME = os.environ.get("CLOUDSEED_HOME")
if "cloudseed" not in sys.modules:
    # isolate before cloudseed is imported (its paths are read at import time); parsing only reads, never writes
    os.environ["CLOUDSEED_HOME"] = tempfile.mkdtemp(prefix="cs-scenario-docs-")

from cloudseed import cli, paths  # noqa: E402

if _SAVED_HOME is None:           # leave the environment as it was for anything imported after this module
    os.environ.pop("CLOUDSEED_HOME", None)
else:
    os.environ["CLOUDSEED_HOME"] = _SAVED_HOME

SHELL_LANGS = {"bash", "sh", "shell", "zsh", "console", "shell-session"}
SEPARATORS = {"|", "||", "&&", ";", "&", "(", ")", "|&", ";;"}
REDIRECTS = {">", ">>", "<", "<<", "<<<", ">&", "&>", "<&", ">|", "&>>"}
FENCE = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})\s*(?P<info>[^`]*?)\s*$")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
PAGE = re.compile(r"^(\d\d)-([a-z0-9-]+)\.md$")

# Where each command sits in the coverage matrix. A command the CLI gains must be placed here (the test says so).
AREAS = [
    ("Environments", ["setup", "plan", "apply", "status", "output", "list", "inventory", "troubleshoot", "doctor",
                      "update-ip", "provision", "destroy"]),
    ("Access", ["ssh", "vpn"]),
    ("Kubernetes", ["k8s", "env", "node", "kubectl", "helm", "k9s"]),
    ("Platform catalog", ["platform"]),
    ("Resilience and security", ["dr", "chaos", "scan"]),
    ("Cost and data", ["finops", "databricks", "snowflake"]),
    ("AI agents and MCP", ["enable", "disable", "agents", "use", "model", "agentic", "do", "skill", "mcp"]),
    ("Console, safety and help", ["ui", "undo", "creds", "explain", "help"]),
    ("Tooling", ["install", "deps"]),
]
# sub-command dests of the parser, by command
SUB_DEST = {"k8s": "k8s_cmd", "vpn": "vpn_cmd", "env": "env_cmd", "node": "node_cmd", "platform": "platform_cmd",
            "dr": "dr_cmd", "chaos": "chaos_cmd", "scan": "scan_cmd", "finops": "finops_cmd", "mcp": "mcp_cmd",
            "ui": "ui_cmd", "creds": "creds_cmd", "enable": "feature", "disable": "feature", "deps": "deps_cmd",
            "skill": "skill_cmd"}
MANAGED_SUBS = ["connect", "test", "status", "CLI passthrough"]
UNDO_SUBS = ["newest", "--list", "--global", "--id", "--drop"]
SETUP_TARGETS = ["aws", "gcp", "azure", "vmware"]

# Features the index's feature table must name (the launch spec's list), as regexes over that table
FEATURES = ["web console", "MCP", "agent", "explain", "undo", "audit", "cred", "container", "bundle",
            "template gitlab-ci", "Databricks", "FinOps", "FIPS", "VPN", "Velero|disaster", "chaos", "scan|complian",
            "help"]


# ---------------------------------------------------------------- extraction

def code_blocks(text: str):
    """(language, line number of the first content line, content lines) of every fenced block, indented ones too
    (admonitions, content tabs); content is de-indented by the fence's own indentation."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            i += 1
            continue
        indent, fence = m.group("indent"), m.group("fence")
        lang = (m.group("info") or "").split()[0].lower() if m.group("info") else ""
        lang = lang.lstrip(".{").rstrip("}")
        body, j = [], i + 1
        while j < len(lines):
            stripped = lines[j].strip()
            if stripped.startswith(fence[0] * len(fence)) and set(stripped) <= {fence[0]}:
                break
            line = lines[j]
            body.append(line[len(indent):] if line.startswith(indent) else line.lstrip())
            j += 1
        yield lang, i + 2, body
        i = j + 1


HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def logical_lines(body: list, lang: str):
    """Shell lines with backslash continuations joined; console blocks keep only `$ ` prompt lines; the body of a
    here-document (YAML, JSON ...) is data, not commands."""
    buf, start, heredoc = "", None, None
    for n, raw in enumerate(body):
        line = raw.rstrip()
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        if not buf:
            if lang in ("console", "shell-session"):
                if not line.lstrip().startswith("$ "):
                    continue
                line = line.lstrip()[2:]
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        m = HEREDOC.search(buf)
        if m:
            heredoc = m.group(2)
        if buf.strip():
            yield start, buf
        buf = ""
    if buf.strip():
        yield start, buf


def shell_words(line: str) -> list:
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = "#"
    return list(lex)


def cs_commands(line: str):
    """The argument lists of every `cs` / `cloudseed` simple command on a shell line (pipes, &&, ; and redirects
    understood; leading VAR=value assignments skipped)."""
    try:
        words = shell_words(line)
    except ValueError:                       # unbalanced quotes: a broken command line if it is a cloudseed one
        if re.search(r"(^|[;&|(]\s*)(cs|cloudseed)\s", line.strip()):
            yield ["--unbalanced-quotes-in-the-docs", line]
        return
    seg: list = []
    for w in words + [";"]:
        if w in SEPARATORS:
            args = _cs_args(seg)
            if args is not None:
                yield args
            seg = []
        else:
            seg.append(w)


def _cs_args(seg: list):
    k = 0
    while k < len(seg) and ASSIGN.match(seg[k]):
        k += 1
    while k < len(seg) and seg[k] in ("time", "env", "command", "exec"):
        k += 1
    if k >= len(seg) or seg[k] not in ("cs", "cloudseed"):
        return None
    args = []
    for w in seg[k + 1:]:
        if w in REDIRECTS:
            if args and args[-1].isdigit():
                args.pop()
            break
        args.append(w)
    return args


def page_commands(path: Path):
    """(line number, argv) of every cs command in the page's shell blocks."""
    text = path.read_text(encoding="utf-8")
    for lang, first, body in code_blocks(text):
        if lang not in SHELL_LANGS:
            continue
        for offset, line in logical_lines(body, lang):
            for argv in cs_commands(line):
                yield first + offset, argv


# ---------------------------------------------------------------- parsing

def parse(argv: list):
    """Parse argv exactly like `cloudseed` does before dispatching. Returns (namespace, None) or (None, error text);
    a clean exit (--version, help output) counts as parsed."""
    argv = cli.normalize_argv(list(argv))
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(paths.Env, "list_all", return_value=[]), \
            mock.patch.object(paths, "load_settings", return_value={}), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            ns = cli.build_parser().parse_args(argv)
            if getattr(ns, "cmd", None) == "ssh" and "--" in argv:
                ns = cli._parse_ssh_argv(argv)
        except SystemExit as e:
            if e.code in (0, None):
                return argparse.Namespace(cmd=None), None
            return None, (err.getvalue() + out.getvalue()).strip() or f"exit {e.code}"
    return ns, None


def covered_keys(ns) -> list:
    """The coverage-matrix rows a parsed command exercises."""
    cmd = getattr(ns, "cmd", None)
    if cmd is None:
        return []
    if cmd == "setup":
        return [("setup", ns.cloud)]
    if cmd in ("databricks", "snowflake"):
        args = [a for a in (ns.svc_args or []) if a != "--"]
        first = args[0] if args else "status"
        return [(cmd, first if first in MANAGED_SUBS[:3] else "CLI passthrough")]
    if cmd == "undo":
        keys = [("undo", flag) for flag, on in (("--list", ns.list), ("--global", ns.global_scope),
                                                ("--id", bool(ns.id)), ("--drop", ns.drop)) if on]
        return keys or [("undo", "newest")]
    dest = SUB_DEST.get(cmd)
    if dest is None:
        return [(cmd, None)]
    return [(cmd, getattr(ns, dest, None))]


def cli_rows() -> list:
    """Every (command, sub-command) row the matrix must have, from the parser itself."""
    parser = cli.build_parser()
    subs = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    rows = []
    for name, sp in subs.choices.items():
        if name == "setup":
            rows += [("setup", t) for t in SETUP_TARGETS]
        elif name in ("databricks", "snowflake"):
            rows += [(name, s) for s in MANAGED_SUBS]
        elif name == "undo":
            rows += [("undo", s) for s in UNDO_SUBS]
        elif name in SUB_DEST:
            dest = SUB_DEST[name]
            nested = [a for a in sp._actions if isinstance(a, argparse._SubParsersAction)]
            if nested:
                choices = list(nested[0].choices)
            else:
                act = next(a for a in sp._actions if a.dest == dest)
                choices = list(act.choices)
            rows += [(name, c) for c in choices]
        else:
            rows.append((name, None))
    return rows


# ---------------------------------------------------------------- coverage matrix

def scenario_pages() -> list:
    return sorted(p for p in DOCS.glob("[0-9][0-9]-*.md"))


def coverage() -> dict:
    """{(command, sub): set of scenario numbers whose page shows a command exercising it}."""
    seen: dict = {}
    for page in scenario_pages():
        num = page.name[:2]
        for _line, argv in page_commands(page):
            ns, _err = parse(argv)
            if ns is None:
                continue
            for key in covered_keys(ns):
                seen.setdefault(key, set()).add(num)
    return seen


def _label(key) -> str:
    cmd, sub = key
    if sub is None:
        return f"`cs {cmd}`"
    if cmd == "undo" and sub == "newest":
        return "`cs undo`"
    if sub == "CLI passthrough":
        return f"`cs {cmd} <cli args>`"
    return f"`cs {cmd} {sub}`"


def render_matrix() -> str:
    """One table per area: every command / sub-command of the CLI and links to the scenarios whose pages run it."""
    seen = coverage()
    pages = {p.name[:2]: p for p in scenario_pages()}
    rows = cli_rows()
    placed = {c for _area, cmds in AREAS for c in cmds}
    out = []
    for area, cmds in AREAS:
        out += [f"### {area}", "", "| Command | Scenarios that run it |", "|---|---|"]
        for cmd in cmds:
            for key in [r for r in rows if r[0] == cmd]:
                hit = sorted(seen.get(key, set()))
                where = " · ".join(f"[{n}]({pages[n].name})" for n in hit) if hit else "**none**"
                out.append(f"| {_label(key)} | {where} |")
        out.append("")
    missing = sorted({r[0] for r in rows} - placed)
    if missing:
        out.append(f"<!-- not placed in AREAS: {', '.join(missing)} -->")
    return "\n".join(out).rstrip() + "\n"


MATRIX_START = "<!-- coverage-matrix:start (generated: python3 tests/test_scenarios_docs.py --write-matrix) -->"
MATRIX_END = "<!-- coverage-matrix:end -->"


def write_matrix() -> None:
    text = INDEX.read_text(encoding="utf-8")
    a, b = text.index(MATRIX_START), text.index(MATRIX_END)
    INDEX.write_text(text[:a + len(MATRIX_START)] + "\n\n" + render_matrix() + "\n" + text[b:], encoding="utf-8")


# ---------------------------------------------------------------- tests

class ScenarioCommandsParse(unittest.TestCase):
    def test_pages_exist(self):
        self.assertEqual(len(scenario_pages()), 15, "there are 15 scenario pages")

    def test_every_command_parses(self):
        problems, total = [], 0
        for page in scenario_pages() + [INDEX]:
            for line, argv in page_commands(page):
                total += 1
                ns, err = parse(argv)
                if ns is None:
                    why = next((ln.strip() for ln in (err or "").splitlines() if "✖" in ln or "error" in ln), err or "")
                    problems.append(f"{page.name}:{line}: cs {shlex.join(argv)}\n    {why}")
        self.assertGreater(total, 300, "the scenario pages show their commands in ```bash blocks")
        self.assertEqual(problems, [], "commands that the CLI parser rejects:\n" + "\n".join(problems))

    def test_extraction_understands_shell(self):
        self.assertEqual(list(cs_commands("cs output aws --env dev --json | jq -r .vpc_id")),
                         [["output", "aws", "--env", "dev", "--json"]])
        self.assertEqual(list(cs_commands("CLOUDSEED_AUTO_INSTALL=1 cs -y dr backup 2>/dev/null && cs dr backups")),
                         [["-y", "dr", "backup"], ["dr", "backups"]])
        self.assertEqual(list(cs_commands('cs agentic "list my environments"  # a comment')),
                         [["agentic", "list my environments"]])
        self.assertEqual(list(cs_commands("kubectl get nodes")), [])
        blocks = list(code_blocks("=== \"Tab\"\n\n    ```bash\n    cs list \\\n      -y\n    ```\n"))
        self.assertEqual([list(logical_lines(b, lang)) for lang, _n, b in blocks], [[(0, "cs list    -y")]])
        body = ["cat > pg.yaml <<'EOF'", "name: it's data", "EOF", "cs kubectl apply -f pg.yaml"]
        self.assertEqual([ln for _n, ln in logical_lines(body, "bash")], ["cat > pg.yaml <<'EOF'", "cs kubectl apply -f pg.yaml"])


class ScenarioPages(unittest.TestCase):
    REQUIRED = ["## What you'll build", "## Before you start", "## Verify it worked", "## Clean up",
                "## What just happened", "## Next steps"]

    def test_anatomy(self):
        for page in scenario_pages():
            text = page.read_text(encoding="utf-8")
            with self.subTest(page=page.name):
                self.assertRegex(text, r"\A---\ntitle: .+\ndescription: .{60,}\n---\n", "front matter: title + description")
                self.assertRegex(text, r"\n# \d\d · .+\n", "H1 with the scenario number")
                self.assertIn("**Outcome:**", text)
                self.assertRegex(text, r'!!! (success|info) "Verified (live on VMware Fusion 13\.6|with --dry-run|live)',
                                 "verification label")
                self.assertIn("```mermaid", text)
                self.assertRegex(text, r"\| :material-clock-outline: Time \|", "time / cost table")
                self.assertRegex(text, r"\n## Step 1: ", "numbered steps")
                for heading in self.REQUIRED:
                    self.assertIn("\n" + heading, text)
                self.assertIn(f"tests/scenarios/{page.stem}.sh", text, "links its test script")

    def test_every_page_has_its_script(self):
        pages = {p.stem for p in scenario_pages()}
        scripts = {p.stem for p in SCRIPTS.glob("[0-9][0-9]-*.sh")}
        self.assertEqual(pages, scripts)
        lib = (SCRIPTS / "lib.sh").read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", lib)
        self.assertIn("trap _scn_finish EXIT", lib)
        for name in sorted(scripts):
            script = SCRIPTS / f"{name}.sh"
            with self.subTest(script=script.name):
                text = script.read_text(encoding="utf-8")
                self.assertTrue(text.startswith("#!/usr/bin/env bash\n"))
                self.assertIn('source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"', text)
                self.assertIn(f"scn_begin {name} ", text)
                self.assertTrue(os.access(script, os.X_OK), "executable")
        self.assertTrue(os.access(SCRIPTS / "run.sh", os.X_OK))

    def test_index_links_every_scenario(self):
        text = INDEX.read_text(encoding="utf-8")
        for page in scenario_pages():
            self.assertIn(f"]({page.name})", text)


class CoverageMatrix(unittest.TestCase):
    def test_every_command_is_placed(self):
        placed = {c for _area, cmds in AREAS for c in cmds}
        self.assertEqual(sorted({r[0] for r in cli_rows()} - placed), [], "add new commands to AREAS")

    def test_nothing_uncovered(self):
        seen = coverage()
        missing = [_label(r) for r in cli_rows() if not seen.get(r)]
        self.assertEqual(missing, [], "commands no scenario page shows")

    def test_index_matrix_is_current(self):
        text = INDEX.read_text(encoding="utf-8")
        a, b = text.index(MATRIX_START) + len(MATRIX_START), text.index(MATRIX_END)
        self.assertEqual(text[a:b].strip(), render_matrix().strip(),
                         "docs/scenarios/index.md is out of date: python3 tests/test_scenarios_docs.py --write-matrix")

    def test_feature_table(self):
        text = INDEX.read_text(encoding="utf-8")
        table = text[text.index("## Every feature, and where to try it"):text.index(MATRIX_START)]
        for feature in FEATURES:
            self.assertRegex(table, re.compile(feature, re.I), f"feature table names {feature}")


if __name__ == "__main__":
    if "--write-matrix" in sys.argv:
        write_matrix()
        print(f"wrote the coverage matrix into {INDEX.relative_to(ROOT)}")
    else:
        unittest.main()
