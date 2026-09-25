"""Regression tests for the web console's presentation layer (layout, accessibility, locked page, assets).

The console is static HTML/CSS/JS, so most checks read the shipped files; the page shells are also fetched through
the real request handler on a loopback port, and a few pure JS helpers are run under node when it is installed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "cloudseed" / "web"
CSS = (WEB / "style.css").read_text()
JS = (WEB / "app.js").read_text()
INDEX = (WEB / "index.html").read_text()
LOCKED = (WEB / "locked.html").read_text()
NODE = shutil.which("node")


def rule(selector: str) -> str:
    """Body of the first top-level CSS rule whose selector list is exactly `selector`."""
    m = re.search(r"(?m)^\s*" + re.escape(selector) + r"\s*\{([^}]*)\}", CSS)
    if not m:
        raise AssertionError(f"no CSS rule for {selector!r}")
    return m.group(1)


def media(query: str) -> str:
    """Contents of the first @media block with this query (balanced braces)."""
    i = CSS.index("@media " + query)
    depth, j = 0, CSS.index("{", i)
    for k in range(j, len(CSS)):
        depth += {"{": 1, "}": -1}.get(CSS[k], 0)
        if depth == 0:
            return CSS[j + 1:k]
    raise AssertionError("unbalanced @media " + query)


def token(block: str, name: str) -> str:
    m = re.search(r"--" + re.escape(name) + r":\s*(#[0-9a-fA-F]{6})", block)
    if not m:
        raise AssertionError(f"--{name} not set")
    return m.group(1)


def contrast(a: str, b: str) -> float:
    def lum(h: str) -> float:
        r, g, bl = (int(h[i:i + 2], 16) / 255 for i in (1, 3, 5))
        f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
        return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(bl)
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


class LayoutTests(unittest.TestCase):
    """webui-visual#3/#16/#33: no horizontal overflow, a navigation on narrow screens, a rail that fits short windows."""

    def test_shell_track_can_shrink(self):
        self.assertIn("grid-template-columns: minmax(0, 1fr)", rule(".shell"))
        self.assertIn("min-width: 0", rule(".topbar"))
        actions = rule(".topbar-actions")
        self.assertIn("min-width: 0", actions)
        self.assertIn("flex: 1 1 auto", actions)
        self.assertNotRegex(rule(".palette-btn"), r"min-width:\s*300px")
        self.assertNotRegex(rule(".env-select"), r"min-width:\s*150px")

    def test_grids_never_force_a_wider_page(self):
        for sel, px in ((".cols-2", 360), (".cols-3", 290), (".cols-4", 210), (".form-grid", 230), (".item-grid", 280), (".tiles", 170)):
            self.assertIn(f"minmax(min({px}px, 100%), 1fr)", rule(sel), sel)

    def test_narrow_screens_get_an_off_canvas_menu(self):
        narrow = media("(max-width: 900px)")
        self.assertIn(".app, .app.collapsed { grid-template-columns: minmax(0, 1fr); }", narrow)  # beats .app.collapsed
        self.assertNotRegex(narrow, r"\.rail\s*\{\s*display:\s*none")
        self.assertIn(".app.nav-open .rail", narrow)
        self.assertIn(".btn.menu-btn { display: inline-flex; }", narrow)
        self.assertIn("display: none", rule(".btn.menu-btn"))   # hidden on wide screens (must out-rank .btn)
        self.assertIn('id="menu-btn"', INDEX)
        self.assertIn("nav-open", JS)
        self.assertIn("matchMedia('(max-width: 900px)')", JS)

    def test_icon_only_topbar_buttons_keep_an_accessible_name(self):
        small = media("(max-width: 640px)")
        self.assertIn(".topbar .btn-text", small)
        self.assertNotRegex(small, r"\.btn-text\s*\{\s*display:\s*none")
        self.assertIn('<span class="btn-text">Undo</span>', INDEX)
        self.assertIn('<span class="btn-text">Activity</span>', INDEX)

    def test_rail_keeps_its_clip_and_only_the_nav_scrolls(self):
        self.assertIn("overflow: hidden", rule(".rail"))
        nav = rule(".rail-nav")
        for decl in ("flex: 1 1 auto", "min-height: 0", "overflow-y: auto", "overflow-x: hidden"):
            self.assertIn(decl, nav)

    def test_rail_collapse_is_a_labelled_persisted_toggle(self):
        self.assertIn('aria-label="Collapse sidebar"', INDEX)
        self.assertIn("<svg", re.search(r'<button class="rail-collapse".*?</button>', INDEX).group(0))
        self.assertNotIn(">⟨<", INDEX)
        self.assertIn(".collapsed .rail-collapse svg { transform: rotate(180deg); }", CSS)
        self.assertIn("store.set('cs-rail'", JS)
        self.assertIn("setRail(store.get('cs-rail') === '1')", JS)
        self.assertRegex(JS, r"key\.toLowerCase\(\) === 'b'\) \{ e\.preventDefault\(\); toggleRail\(\)")


class ThemeTests(unittest.TestCase):
    """webui-visual#18/#19/#29: theme-aware native controls, visible terminal boxes, reduced motion."""

    def test_color_scheme_follows_the_app_theme(self):
        self.assertIn("color-scheme: light", rule(":root"))
        self.assertIn("color-scheme: dark", rule('[data-theme="dark"]'))
        self.assertIn('<meta name="color-scheme" content="light dark">', INDEX)

    def test_terminal_boxes_stand_out_in_dark(self):
        self.assertNotEqual(token(rule('[data-theme="dark"]'), "term"), token(rule('[data-theme="dark"]'), "bg"))
        for sel in (".cmd-preview", "pre.help"):
            self.assertIn("border: 1px solid var(--line-2)", rule(sel), sel)
        self.assertNotIn("break-all", rule(".cmd-preview"))

    def test_reduced_motion_and_no_smooth_scroll_on_view_change(self):
        block = media("(prefers-reduced-motion: reduce)")
        self.assertIn("animation-duration: .01ms !important", block)
        self.assertIn("transition-duration: .01ms !important", block)
        self.assertNotIn("scroll-behavior: smooth", rule(".content"))

    def test_only_clickable_tiles_lift(self):
        self.assertNotRegex(CSS, r"(?m)^\.tile:hover")
        self.assertIn('.tile[role="button"]:hover', CSS)
        self.assertNotIn("style: onclick ? 'cursor:pointer'", JS)


class ContrastTests(unittest.TestCase):
    """webui-visual#13: WCAG AA (4.5:1) for text on the filled buttons, muted text, links and group tiles."""

    def test_button_and_text_tokens(self):
        root = rule(":root")
        for name in ("btn-brand", "btn-leaf", "btn-rose"):
            self.assertGreaterEqual(contrast("#ffffff", token(root, name)), 4.5, name)
        self.assertGreaterEqual(contrast(token(root, "muted"), token(root, "bg")), 4.5)
        self.assertGreaterEqual(contrast(token(root, "link"), "#ffffff"), 4.5)
        self.assertGreaterEqual(contrast(token(root, "seed-text"), "#ffffff"), 4.5)
        self.assertIn("background: var(--btn-brand)", rule(".btn"))
        self.assertRegex(CSS, r"\.filters \.chip\.on \{[^}]*background: var\(--btn-brand\)")
        self.assertRegex(CSS, r"\.btn\.leaf \{ background: var\(--btn-leaf\); \} \.btn\.rose \{ background: var\(--btn-rose\); \}")
        self.assertIn("brightness(.93)", rule(".btn:hover"))   # hover darkens, so it never drops below AA

    def test_group_tiles_keep_white_text_readable_at_the_light_end(self):
        tiles = re.findall(r"\.g-(\w+) \{ background: linear-gradient\(135deg, (#[0-9a-f]{6}), (#[0-9a-f]{6})\); \}", CSS)
        self.assertEqual(len(tiles), 10)
        for name, _dark, light in tiles:
            self.assertGreaterEqual(contrast("#ffffff", light), 4.5, name)
        self.assertIn("color: #fff", rule(".group-tile p"))

    def test_rail_footer_text_is_readable_on_the_navy_rail(self):
        m = re.search(r"\.rail-status \.rail-home \{ color: (#[0-9a-f]{6})", CSS)
        self.assertGreaterEqual(contrast(m.group(1), "#1e3a8a"), 4.5)

    def test_unavailable_items_are_not_faded(self):
        self.assertNotIn("opacity", rule(".item.na"))


class MarkupTests(unittest.TestCase):
    """webui-visual#5/#12/#14/#15/#17/#22/#26/#30/#32/#34: keyboard reach, dialog semantics and rendering fixes."""

    def test_dialogs_live_regions_and_labels(self):
        self.assertRegex(INDEX, r'class="modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title"')
        self.assertRegex(INDEX, r'class="palette-card" role="dialog" aria-modal="true"')
        self.assertIn('id="toasts" class="toasts" role="status" aria-live="polite"', INDEX)
        self.assertIn('<label class="env-label" for="current-env">', INDEX)
        self.assertIn('<h1 class="crumbs">', INDEX)
        for bid in ("theme-btn", "console-close", "modal-close"):
            self.assertRegex(INDEX, r'id="' + bid + r'"[^>]*aria-label="[^"]+"', bid)

    def test_clickable_elements_become_keyboard_operable(self):
        self.assertIn("if (!n.hasAttribute('role')) n.setAttribute('role', 'button');", JS)
        self.assertIn("if (!n.hasAttribute('tabindex')) n.setAttribute('tabindex', '0');", JS)
        self.assertIn("role: 'radiogroup', 'aria-label': 'Cloud'", JS)
        self.assertIn("role: 'radiogroup', 'aria-label': 'Run mode'", JS)
        self.assertIn("'aria-current': i === step ? 'step' : null", JS)
        self.assertIn("role: 'switch', 'aria-checked'", JS)
        self.assertIn("'aria-pressed'", JS)
        self.assertIn(":focus-visible { outline: 2px solid var(--brand)", CSS)

    def test_closed_drawer_and_background_are_inert(self):
        self.assertIn("drawer.inert = !open", JS)
        self.assertIn("$('.shell').inert = open.length > 0", JS)

    def test_glyph_badges_are_styled_everywhere(self):
        glyph = rule(".glyph")
        for decl in ("display: grid", "place-items: center", "width: 40px"):
            self.assertIn(decl, glyph)
        self.assertIn("width: 28px", rule(".glyph.sm"))
        self.assertIn("class: 'glyph sm ' + cloud", JS)
        self.assertNotIn("style: 'width:28px;height:28px;font-size:10px;border-radius:8px'", JS)

    def test_doctor_button_uses_a_monochrome_icon(self):
        self.assertNotIn("🩺", JS)
        self.assertIn("html: icon('doctor')", JS)
        self.assertIn(".btn > svg { width: 16px; height: 16px;", CSS)

    def test_clusters_tile_does_not_show_a_raw_variable(self):
        self.assertNotIn(": 'enable_kubernetes=true', 'leaf'", JS)
        self.assertIn("clusters ? 'leaf' : ''", JS)

    def test_resilience_hero_keeps_its_description(self):
        self.assertIn("(e ? `Acting on ${e.id}.` : STATE.envs.length ? 'Pick an environment (top right).' : 'Create an environment first.') + ' DR drills", JS)

    def test_mcp_clients_cell_is_a_real_table_cell(self):
        self.assertNotIn("el('td', { class: 'row' }", JS)
        self.assertIn("el('table', { class: 'clients' }", JS)
        self.assertIn("'Reconnect'", JS)

    def test_wizard_preview_and_review_step(self):
        self.assertIn("pvTitle.hidden = preview.hidden = step === 3", JS)
        # the review step's own command box (web-logic tags it review-preview so the live update reaches it too)
        self.assertRegex(JS, r"el\('div', \{ class: 'cmd-preview(?: review-preview)?' \}, cmdText\(\)\)")
        self.assertNotRegex(JS, r"I understand Apply creates billable cloud resources'\)\) : null")

    def test_modals_are_titled_sized_and_sticky(self):
        self.assertIn("{ narrow: true }", JS)
        self.assertIn("width: min(640px, 94vw)", rule(".modal-card.narrow"))
        self.assertIn("position: sticky", rule(".modal-head"))
        self.assertIn("callout danger", JS)

    def test_help_topics_and_accordions(self):
        self.assertIn("#help-topics a.active", CSS)
        self.assertIn(".accordion details[open] summary::after { transform: rotate(45deg); }", CSS)

    def test_drawer_shows_the_command_and_tells_runs_apart(self):
        self.assertIn('id="job-cmd"', INDEX)
        self.assertIn("toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })", JS)
        self.assertIn("$('#job-cancel').disabled = !(aj && aj.running)", JS)
        self.assertIn("content: attr(data-empty)", CSS)

    def test_busy_state_for_run_buttons(self):
        self.assertIn("@keyframes spin", CSS)
        self.assertIn(".btn.busy::after", CSS)
        self.assertIn("btn.classList.add('busy')", JS)


class LockedPageTests(unittest.TestCase):
    """webui-visual#20 / webui-backend#25."""

    def test_locked_page_markup(self):
        self.assertIn('<meta name="viewport" content="width=device-width, initial-scale=1">', LOCKED)
        self.assertIn('<meta name="color-scheme" content="light dark">', LOCKED)
        self.assertIn('<source srcset="/assets/logo-dark.svg" media="(prefers-color-scheme: dark)">', LOCKED)
        self.assertNotIn("~/.cloudseed/ui/token", LOCKED)     # wrong whenever CLOUDSEED_HOME is set
        self.assertIn("cs ui token", LOCKED)
        locked = rule(".locked")
        self.assertIn("min-height: 100vh", locked)
        self.assertIn("padding: 16px", locked)
        self.assertIn(":root:not([data-theme])", media("(prefers-color-scheme: dark)"))

    def test_logo_tagline_fits_its_viewbox(self):
        for name in ("logo.svg", "logo-dark.svg"):
            svg = (ROOT / "assets" / name).read_text()
            width = float(re.search(r'viewBox="0 0 (\d+) ', svg).group(1))
            tag = re.search(r'<text x="(\d+)" y="128" textLength="(\d+)" lengthAdjust="spacingAndGlyphs"', svg)
            self.assertIsNotNone(tag, name)
            self.assertLessEqual(float(tag.group(1)) + float(tag.group(2)), width - 10, name)


class ServedPagesTests(unittest.TestCase):
    """The shells as the console serves them: locked page without a token, the app with one."""

    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        from cloudseed import webui
        cls.webui = webui
        cls.saved = {k: getattr(webui._State, k) for k in ("token", "token_sig", "port") if hasattr(webui._State, k)}
        # a token file left by another test (or a server that re-reads it) must not replace the one this test uses
        cls.token_path = mock.patch.object(webui, "TOKEN_PATH", Path(tempfile.mkdtemp(prefix="cs-ui-")) / "token")
        cls.token_path.start()
        webui._State.token = "t" * 32
        if hasattr(webui._State, "token_sig"):
            webui._State.token_sig = None
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), webui._Handler)
        webui._State.port = cls.httpd.server_address[1]    # the Host-header check accepts only the port being served
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.token_path.stop()
        for k, v in cls.saved.items():
            setattr(cls.webui._State, k, v)

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=10) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_locked_page_is_served_without_a_token(self):
        code, body = self.get("/")
        self.assertIn(code, (200, 401))     # a plain visit may be a 200 lock screen; it is never the app
        self.assertNotIn('role="dialog"', body)
        self.assertIn("This console is locked", body)
        self.assertIn('name="viewport"', body)
        self.assertIn("logo-dark.svg", body)

    def test_app_shell_and_assets(self):
        code, body = self.get("/?token=" + "t" * 32)
        self.assertEqual(code, 200)
        self.assertIn('role="dialog"', body)
        self.assertIn('aria-live="polite"', body)
        for path in ("/static/style.css", "/static/app.js", "/assets/logo.svg", "/assets/logo-dark.svg"):
            self.assertEqual(self.get(path)[0], 200, path)


@unittest.skipUnless(NODE, "node is not installed")
class ScriptTests(unittest.TestCase):
    """app.js parses, and its pure formatting helpers behave (run under node, no browser)."""

    def node(self, src: str, tz: str = "America/Chicago") -> str:
        env = dict(os.environ, TZ=tz, LANG="en_US.UTF-8")
        out = subprocess.run([NODE, "-e", src], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.strip()

    @staticmethod
    def extract(name: str) -> str:
        """Source of `const <name> = ...;` from app.js (single line, or up to the closing `  };`)."""
        lines = JS.splitlines()
        for i, line in enumerate(lines):
            if line.strip().startswith(f"const {name} = "):
                if line.rstrip().endswith("{"):
                    j = next(k for k in range(i + 1, len(lines)) if lines[k].strip() == "};")
                    return "\n".join(lines[i:j + 1])
                return line
        raise AssertionError(f"{name} not found in app.js")

    def test_app_js_parses(self):
        out = subprocess.run([NODE, "--check", str(WEB / "app.js")], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_timestamps_are_shown_in_local_time(self):
        src = self.extract("fmtTime") + "\nconsole.log(JSON.stringify([fmtTime('2026-09-23T22:09:02+00:00'), fmtTime(''), fmtTime(null), fmtTime('not a date')]))"
        local, empty, none, bad = json.loads(self.node(src))
        self.assertRegex(local, r"\b(5|17):09\b")   # 22:09 UTC is 17:09 in Chicago (CDT)
        self.assertNotIn("22:09", local)
        self.assertEqual((empty, none), ("—", "—"))
        self.assertEqual(bad, "not a date")

    def test_report_names_and_dr_summary(self):
        src = "\n".join(self.extract(n) for n in ("runKind", "runLabel", "reportSummary")) + """
const steps = [{step: '1. create sample workload', ok: true, seconds: 10}, {step: '2. backup', ok: true, seconds: 20.5},
  {step: '3. delete it (disaster)', ok: true, seconds: 7}, {step: '4. restore from backup', ok: true, seconds: 30}, {step: '5. verify', ok: false, seconds: 4.5}];
console.log(JSON.stringify([runKind('host-stig-20260923-101500'), runKind('drill-20260923-093000'), runLabel('report-20260923-101500'), runLabel('odd-name'),
  reportSummary({name: 'drill-20260923-093000', summary: {}, results: steps}), reportSummary({name: 'cis-20260923-100500', summary: {pass: 3}, results: []})]))"""
        kind, drill, label, odd, dr, cis = json.loads(self.node(src))
        self.assertEqual((kind, drill), ("host-stig", "drill"))
        self.assertIn("5:15", label)             # the run stamp is UTC: 10:15Z is 05:15 in Chicago
        self.assertEqual(odd, "odd-name")
        # (a drill without a verdict measured no RTO, as `cs dr` and the server say; its time and steps still show)
        self.assertEqual(dr, {"RTO": "—", "total": "72s", "steps": "4/5 ok"})
        self.assertEqual(cis, {"pass": 3})


if __name__ == "__main__":
    unittest.main()
