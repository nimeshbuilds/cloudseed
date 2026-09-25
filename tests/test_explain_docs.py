"""`cs explain` everywhere, docs: the manual (docs/guides/manual.md), `cs help explain|ui|mcp`, the overview, the explain feature pages, the skills,
the headliner brief and the MCP guide describe what the code does - the --json keys, the MCP resource template and
format=json, the console's "?" buttons / Explain panel / ⌘K entries, and its keyboard shortcuts (compared with the list
the console itself shows).

Stdlib only, no network, no cloud, no subprocess."""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

# The reference text that README.md carried before it became the landing page lives in the manual on the docs
# site (docs/guides/manual.md); these checks follow it there. tests/test_readme.py checks the landing README.
MANUAL = "docs/guides/manual.md"
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-explain-docs-"))

from cloudseed import explain, headliner, mcp, ui  # noqa: E402
from cloudseed import help as h  # noqa: E402


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(ui._strip(text).split())


def _render(topic, columns: int) -> str:
    """`cs help <topic>` (None: the overview) as printed at that terminal width."""
    buf = io.StringIO()
    with mock.patch.dict(os.environ, {"COLUMNS": str(columns)}), contextlib.redirect_stdout(buf):
        h.print_page(topic, None)
    return ui._strip(buf.getvalue())


def _keys(listed: str) -> set:
    return {k.strip() for k in listed.split(",")}


# the keys every lookup() answer has (a variable page adds `cloud`)
LOOKUP_KEYS = set(explain.lookup("zzz-nothing-here"))


class JsonKeysAreDocumented(unittest.TestCase):
    def test_lookup_keys_match_the_docs(self):
        self.assertIn("did_you_mean", LOOKUP_KEYS)
        m = re.search(r"--json prints one as data \(([^)]*)\)", _flat(h.COMMANDS["explain"]))
        self.assertTrue(m, "cs help explain lists the --json keys")
        self.assertEqual(_keys(m.group(1)), LOOKUP_KEYS)
        m = re.search(r"`cs explain <name> --json` prints one as data \(([^;]*);", _flat(_read(MANUAL)))
        self.assertTrue(m, "the manual lists the --json keys")
        self.assertEqual(_keys(m.group(1)), LOOKUP_KEYS)

    def test_overview_names_json(self):
        row = next(ln for ln in h.OVERVIEW.splitlines() if ln.startswith("  explain "))
        self.assertIn("setup variable", row)
        self.assertIn("--json", h.OVERVIEW[h.OVERVIEW.index(row):].split("\n  undo", 1)[0])
        self.assertIn("explain [name] [--json]", _read(MANUAL))


class McpDocs(unittest.TestCase):
    def test_every_resource_template_is_documented(self):
        readme, page, feature = _flat(_read(MANUAL)), _flat(h.COMMANDS["mcp"]), explain.FEATURES["mcp"]["what"]
        for t in mcp.resource_templates():
            for name, text in (("manual", readme), ("cs help mcp", page), ("cs explain mcp", feature)):
                self.assertIn(t["uriTemplate"], text, name)
        self.assertIn("resources/templates/list", readme)

    def test_explain_format_is_documented(self):
        tool = {t["name"]: t for t in mcp.tool_list()}["cloudseed_explain"]
        self.assertEqual(tool["inputSchema"]["properties"]["format"]["enum"], ["text", "json"])
        for name, text in (("manual", _read(MANUAL)), ("cs help mcp", h.COMMANDS["mcp"]),
                           ("cs help explain", h.COMMANDS["explain"]), ("cs explain mcp", explain.FEATURES["mcp"]["what"]),
                           ("cloudseed skill", _read("skills/cloudseed/SKILL.md")),
                           ("architecture skill", _read("skills/cloudseed-architecture/SKILL.md"))):
            self.assertIn("format=json", text, name)

    def test_documented_resource_examples_resolve(self):
        readme = _flat(_read(MANUAL))
        m = re.search(r"with `/` between words \(([^)]*)\)", readme)
        self.assertTrue(m, "the manual gives resource examples")
        examples = re.findall(r"`([^`]+)`", m.group(1))
        self.assertGreaterEqual(len(examples), 4)
        uris = ["cloudseed://explain/" + e for e in examples]
        uris += re.findall(r"cloudseed://explain/[\w/%.-]+", _read("skills/cloudseed/SKILL.md"))
        for uri in uris:
            res = mcp.read_resource(uri)
            self.assertIsNotNone(res, uri)
            data = json.loads(res["contents"][0]["text"])
            self.assertTrue(data["found"], uri)
        index = json.loads(mcp.read_resource("cloudseed://explain")["contents"][0]["text"])
        self.assertEqual(index["kind"], "index")          # MANUAL_TEXT: cloudseed://explain alone is the index

    def test_guide_tells_how_to_ask(self):
        text = json.dumps(mcp.guide_lines(None), ensure_ascii=False)
        self.assertIn("cloudseed://explain/<query>", text)
        self.assertIn("format=json", text)


class ConsoleDocs(unittest.TestCase):
    def test_readme_and_help_describe_the_question_marks(self):
        readme = _flat(_read(MANUAL))
        page = _flat(h.COMMANDS["ui"])
        for name, text in (("manual", readme), ("cs help ui", page)):
            for part in ('"?"', "Explain panel", "Explain: <name>", "Open in Help", "/api/explain", "no audit entry"):
                self.assertIn(part, text, f"{name}: {part}")
        self.assertIn("/api/explain/names", readme)
        exp = _flat(h.COMMANDS["explain"])
        for part in ('"?" button', "the ? key", "⌘K", "/api/explain/names"):
            self.assertIn(part, exp, part)

    def test_ui_feature_page(self):
        f = explain.FEATURES["ui"]
        self.assertIn("/api/explain", f["what"])
        self.assertIn('"?"', f["what"])
        self.assertTrue(any("explain.py" in x for x in f["files"]))
        self.assertTrue(any("/api/explain" in x for x in f["controls"]))
        self.assertIn(str(explain.MAX_QUERY), " ".join(f["controls"]))
        self.assertIn('"?"', explain.SUMMARIES["feature ui"])
        self.assertLessEqual(len(explain.lookup("feature ui")["summary"]), 160)

    def test_keyboard_shortcuts_match_the_console(self):
        js = _read("cloudseed/web/app.js")
        block = js[js.index("const shortcutsCard"):]
        block = block[: block.index(".map(")]
        described = re.findall(r"\],\s*'([^']+)'\]", block)
        self.assertGreaterEqual(len(described), 7, "the console lists its shortcuts")
        page = _flat(h.COMMANDS["ui"]).lower()
        self.assertIn("keyboard", page)
        for what in described:
            self.assertIn(what.lower(), page, f"cs help ui misses the shortcut '{what}'")
        readme = _flat(_read(MANUAL))
        for key in ("⌘K / Ctrl+K", "`?` explains the page you are on", "⌘B / Ctrl+B", "Esc", "Alt+←"):
            self.assertIn(key, readme, key)


class AgentDocs(unittest.TestCase):
    def test_skills_say_look_it_up(self):
        skill = _flat(_read("skills/cloudseed/SKILL.md"))
        for part in ("cloudseed explain <thing> --json", "did_you_mean", "cloudseed://explain/<query>",
                     "variable <cloud> <name>", "before guessing"):
            self.assertIn(part, skill, part)
        arch = _flat(_read("skills/cloudseed-architecture/SKILL.md"))
        for part in ("--json", "cloudseed explain variable <cloud> <name>", "cloudseed://explain/<query>"):
            self.assertIn(part, arch, part)

    def test_headliner_and_mcp_instructions(self):
        self.assertIn("[--json]", headliner.CHEATSHEET)
        brief = headliner.build("x", {})
        self.assertIn("`--json`", brief)
        self.assertIn("variable <cloud> <name>", brief)
        self.assertIn("cloudseed://explain/", mcp.INSTRUCTIONS)


class Layout(unittest.TestCase):
    def test_edited_pages_fit_the_terminal(self):
        for width in (60, 80, 100):
            for topic in ("explain", "ui", "mcp", None):
                long = [ln for ln in _render(topic, width).splitlines() if len(ln) > width and '"' not in ln]
                self.assertEqual(long, [], f"help {topic or 'overview'} @ {width}")

    def test_feature_pages_fit_the_terminal(self):
        for width in (60, 100):
            for name in ("ui", "mcp"):
                for line in ui._strip(explain.page(name, width)).splitlines():
                    if len(line.split()) > 1:             # (the source checkout's path is one unbreakable word)
                        self.assertLessEqual(len(line), width, f"explain {name} @ {width}: {line!r}")


if __name__ == "__main__":
    unittest.main()
