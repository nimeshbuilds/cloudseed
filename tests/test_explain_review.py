"""`cs explain` everywhere, review follow-ups: the one-line summaries the console's "?" tooltips, the ⌘K palette and the
index show read as whole sentences, every hand-written summary is used, and the palette says which meaning of a word
each "Explain: …" entry is. Stdlib only, no network."""
import os
import re
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-explain-review-"))

from cloudseed import explain, webui  # noqa: E402

JS = (Path(webui.WEB_ROOT) / "app.js").read_text()


class Summaries(unittest.TestCase):
    def test_every_summary_is_one_whole_sentence(self):
        for n in explain.names():
            s = n["summary"]
            self.assertLessEqual(len(s), 160, n)
            self.assertRegex(s, r"[.!?…]$", n)
            self.assertEqual(explain.lookup(n["query"])["summary"], s, n)
            if n["kind"] != "variable":      # (a variable's long default may be cut; its description never is)
                self.assertFalse(s.endswith("…"), n)

    def test_every_written_summary_is_used(self):
        for key, text in explain.SUMMARIES.items():
            self.assertLessEqual(len(text), 160, key)
            r = explain.lookup(key)
            self.assertTrue(r["found"], key)
            self.assertEqual(r["summary"], text if text[-1] in ".!?" else text + ".", key)

    def test_the_page_summary_is_the_tooltip(self):
        """What the panel shows under the title is what the "?" tooltip said (names() and lookup() agree)."""
        for q in ("aws", "target vmware", "list", "kubectl", "group security", "security", "velero", "setup", "variable aws az_count"):
            r = explain.lookup(q)
            self.assertTrue(r["found"], q)
            self.assertRegex(r["summary"], r"[.!?]$", q)


class Palette(unittest.TestCase):
    def test_explain_entries_name_their_kind(self):
        """vpn is a feature and a command: two "Explain: vpn" entries would look the same, so each says which it is."""
        m = re.search(r"const xpLabel = \(n\) => \{(.*?)\};\n", JS, re.S)
        self.assertIsNotNone(m)
        self.assertIn("XKIND[n.kind]", m.group(1))
        self.assertIn("variable", m.group(1))
        self.assertIn("'Explain: ' + xpLabel(n)", JS)

    def test_exact_names_come_first_among_explain_entries(self):
        self.assertIn("all.map((i, n) => [paletteScore(i, q), n, i])", JS)


if __name__ == "__main__":
    unittest.main()
