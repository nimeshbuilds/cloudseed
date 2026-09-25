"""The landing README (README.md) says only what is true: its numbers and lists follow the code, every command in it
parses with the real CLI parser, its links point at pages and files that exist, its images and badges work outside
GitHub too (absolute URLs, the real workflows), and each scenario's "Verified" label is the one its page states - in
the README, on the site's landing page (overrides/home.html) and on the scenario index cards.
The exhaustive reference that README.md used to carry lives in docs/guides/manual.md, checked by the *_docs tests.
Stdlib only, no network."""

from __future__ import annotations

import argparse
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import test_scenarios_docs as scen  # noqa: E402  (isolates CLOUDSEED_HOME before cloudseed is imported)
from cloudseed import chaos, cli, mcp, platform as pl, undo  # noqa: E402

README = ROOT / "README.md"
TEXT = README.read_text(encoding="utf-8")
FLAT = " ".join(TEXT.split())
REPO = "nimeshbuilds/cloudseed"
SITE = "https://nimeshbuilds.github.io/cloudseed/"
RAW = f"https://raw.githubusercontent.com/{REPO}/main/"
GITHUB = f"https://github.com/{REPO}/"


def _urls() -> list[str]:
    """Every link and image target: markdown (text)(url), and href / src / srcset attributes."""
    urls = re.findall(r"\]\(([^)\s]+)\)", TEXT)
    urls += re.findall(r"""(?:href|src|srcset)=["']([^"']+)["']""", TEXT)
    return urls


def _site_page(url: str) -> Path | None:
    """The docs/ source of a documentation-site URL (…/guides/manual/ is docs/guides/manual.md)."""
    rel = url[len(SITE):].split("#")[0].strip("/")
    if not rel:
        return ROOT / "docs" / "index.md"
    for cand in (ROOT / "docs" / f"{rel}.md", ROOT / "docs" / rel / "index.md"):
        if cand.exists():
            return cand
    return None


class Links(unittest.TestCase):
    def test_nothing_relative(self):
        # GitHub resolves relative links, package indexes and other mirrors do not
        for url in _urls():
            self.assertTrue(url.startswith(("https://", "#")), url)

    def test_images_are_absolute_and_exist(self):
        images = re.findall(r"""<img[^>]*\ssrc=["']([^"']+)["']""", TEXT) + re.findall(r"!\[[^\]]*\]\(([^)\s]+)\)", TEXT)
        self.assertTrue(images)
        own = [u for u in images if u.startswith(RAW)]
        self.assertGreaterEqual(len(own), 2)                          # the banner and the demo
        for url in own:
            self.assertTrue((ROOT / url[len(RAW):]).is_file(), url)
        for url in images:
            self.assertTrue(url.startswith("https://"), url)
            self.assertNotRegex(url, r"^https://github\.com/[^/]+/[^/]+/(blob|raw)/", url)   # raw.githubusercontent.com

    def test_badges_are_the_real_workflows(self):
        badges = re.findall(rf"https://github\.com/{REPO}/actions/workflows/([\w.-]+)/badge\.svg", TEXT)
        self.assertEqual(sorted(badges), ["docs.yml", "tests.yml"])
        for wf in badges:
            self.assertTrue((ROOT / ".github" / "workflows" / wf).is_file(), wf)

    def test_site_links_have_a_page(self):
        site = [u for u in _urls() if u.startswith(SITE)]
        self.assertIn(SITE, site)
        for url in site:
            self.assertIsNotNone(_site_page(url), url)
        for need in ("getting-started/quickstart/", "scenarios/", "guides/manual/", "reference/"):
            self.assertIn(SITE + need, site, need)

    def test_repository_links_point_at_tracked_paths(self):
        for url in _urls():
            m = re.match(rf"https://github\.com/{REPO}/(?:blob|tree)/main/(.+)$", url)
            if m:
                self.assertTrue((ROOT / m.group(1)).exists(), url)


class Scenarios(unittest.TestCase):
    # the words each page's verification banner uses -> the README's label
    LABELS = {"Verified live on VMware": "live", "Verified live on macOS (local": "live (local)",
              "Verified with --dry-run": "dry-run"}

    def test_every_scenario_is_listed_with_its_page_label(self):
        found = re.findall(r"^\| (\d\d) \| \[[^\]]+\]\(" + re.escape(SITE) + r"scenarios/(\d\d-[a-z0-9-]+)/\) \|[^|]+\| ([^|]+?) \|$",
                           TEXT, re.M)
        pages = sorted(p.stem for p in (ROOT / "docs" / "scenarios").glob("[0-9][0-9]-*.md"))
        self.assertEqual(len(pages), 15)
        self.assertEqual(sorted(slug for _, slug, _ in found), pages)
        for num, slug, label in found:
            self.assertTrue(slug.startswith(num), slug)
            page = (ROOT / "docs" / "scenarios" / f"{slug}.md").read_text(encoding="utf-8")
            banner = re.search(r'^!!! \w+ "(Verified[^"]*)"', page, re.M)
            self.assertTrue(banner, slug)
            want = next((v for k, v in self.LABELS.items() if banner.group(1).startswith(k)), None)
            self.assertEqual(label.strip(), want, f"{slug}: the page says '{banner.group(1)}'")


class SiteLabels(unittest.TestCase):
    """Homepage entry points resolve, factual counts stay current, and scenario verification labels agree.

    The homepage links to selected walkthroughs; the scenario index owns the full verification inventory.
    """
    HOME = (ROOT / "overrides" / "home.html").read_text(encoding="utf-8")
    INDEX = (ROOT / "docs" / "scenarios" / "index.md").read_text(encoding="utf-8")
    BANNER = {"live": "Verified live on VMware", "local": "Verified live on macOS (local", "dry": "Verified with --dry-run"}

    def _banner(self, slug: str) -> str:
        page = (ROOT / "docs" / "scenarios" / f"{slug}.md").read_text(encoding="utf-8")
        return re.search(r'^!!! \w+ "(Verified[^"]*)"', page, re.M).group(1)

    def test_landing_page_scenario_links(self):
        links = re.findall(r"['\"]scenarios/(\d\d-[a-z0-9-]+)/['\"]", self.HOME)
        self.assertTrue(links)
        for slug in links:
            self.assertTrue((ROOT / "docs" / "scenarios" / (slug + ".md")).is_file(), slug)

    def test_scenario_index_cards(self):
        label = {"Live": "live", "Live (local)": "local", "Dry-run": "dry"}
        cards = re.findall(r":material-(?:check-decagram|test-tube): ([^<]+)</span>.*?\]\((\d\d-[a-z0-9-]+)\.md\)",
                           self.INDEX, re.S)
        self.assertEqual(len(cards), 15)
        for text, slug in cards:
            self.assertTrue(self._banner(slug).startswith(self.BANNER[label[text.strip()]]), f"{slug}: {text}")

    def test_landing_page_numbers(self):
        flat = " ".join(self.HOME.split())
        items = [n for n, spec in pl.CATALOG.items() if not spec.get("hidden")]
        for pattern, count in ((r"\b(\d+) (?:pinned |platform )?items\b", len(items)),
                               (r"\b(\d+) MCP tools\b", len(mcp.TOOLS))):
            for m in re.finditer(pattern, flat):
                self.assertEqual(int(m.group(1)), count, m.group(0))
        walkthroughs = re.search(r"\ball (\d+) walkthroughs\b", flat)
        self.assertIsNotNone(walkthroughs)
        self.assertEqual(int(walkthroughs.group(1)), len(list((ROOT / "docs" / "scenarios").glob("[0-9][0-9]-*.md"))))


class Claims(unittest.TestCase):
    def test_numbers_and_lists_follow_the_code(self):
        items = [n for n, spec in pl.CATALOG.items() if not spec.get("hidden")]
        for m in re.finditer(r"\b(\d+) (?:pinned )?items\b", FLAT):
            self.assertEqual(int(m.group(1)), len(items), m.group(0))
        for m in re.finditer(r"\b(\d+) groups\b", FLAT):
            self.assertEqual(int(m.group(1)), len(pl.GROUPS), m.group(0))
        for m in re.finditer(r"\b(\d+) tools\b", FLAT):
            self.assertEqual(int(m.group(1)), len(mcp.TOOLS), m.group(0))
        groups = re.search(r"`cs platform install <group>`: ([a-z0-9, -]+)\.", FLAT).group(1).split(", ")
        self.assertEqual(sorted(groups), sorted(pl.GROUPS))
        kinds = re.findall(r"`(\w+)`(?: \([^)]*\))?", re.search(r"`cs scan <type>`: (.+?), with saved reports", FLAT).group(1))
        sub = next(a for a in cli.build_parser()._actions if isinstance(a, argparse._SubParsersAction))
        choices = next(a.choices for a in sub.choices["scan"]._actions if a.dest == "scan_cmd")
        self.assertEqual(sorted(kinds), sorted(set(choices) - {"all", "reports"}))
        suites = re.search(r"`cs chaos run ([a-z|]+)`", TEXT).group(1).split("|")
        self.assertEqual(sorted(suites), sorted(chaos.SUITES))

    def test_undo_depth(self):
        words = {5: "five", 15: "fifteen"}
        self.assertIn(f"{words[undo.KEEP_TOTAL]} deep per environment", FLAT)
        self.assertIn(f"{words[undo.KEEP_TOTAL]} steps deep per environment", FLAT)
        self.assertNotRegex(FLAT, r"\bfive (steps )?deep\b")

    def test_python_floor_matches_the_launcher(self):
        launcher = (ROOT / "bin" / "cloudseed").read_text()
        floor = re.search(r"sys\.version_info < \((\d+), (\d+)\)", launcher)
        self.assertIn(f"Python {floor.group(1)}.{floor.group(2)}+", FLAT)
        self.assertIn(f"python-{floor.group(1)}.{floor.group(2)}%2B", TEXT)            # the badge

    def test_every_command_parses(self):
        cmds = list(scen.page_commands(README))
        self.assertGreaterEqual(len(cmds), 6)
        for line, argv in cmds:
            ns, err = scen.parse(argv)
            self.assertIsNone(err, f"README.md:{line}: cs {' '.join(argv)}: {err}")


if __name__ == "__main__":
    unittest.main()
