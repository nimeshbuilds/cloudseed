"""Wave-3 regression tests for cloudseed/mcp.py: kubectl/helm cluster selectors, the helm status -o json|yaml gate, stdio
responses that are no longer held behind a long call, service definitions of another kind or home, Codex TOML entries in
forms the text rewrite cannot handle, protected client-config backups, the guide/descriptions, and the dr/chaos/skill/env/
help tool arguments. Stdlib only, no network, temp dirs; launchctl/systemctl are always mocked (nothing reaches the real
per-user launchd domain)."""
import contextlib
import io
import json
import os
import plistlib
import queue
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, mcp, paths, ui, webui  # noqa: E402
from cloudseed.cli import build_parser, normalize_argv  # noqa: E402

try:
    import tomllib  # noqa: F401
    HAS_TOMLLIB = True
except ImportError:     # Python < 3.11: mcp falls back to its line scan
    HAS_TOMLLIB = False


def _text(result: dict) -> str:
    return result["content"][0]["text"]


def _call(name: str, args: dict) -> dict:
    """call_tool without running anything: the tool result, or {'argv': [...]} when it would have run."""
    ran = {}

    def fake_run(_name, argv, _env, call=None, progress=None):
        ran["argv"] = argv
        return mcp._result("ran", False)
    with mock.patch.object(mcp, "_run", side_effect=fake_run):
        res = mcp.call_tool(name, args, {})
    return ran if ran else res


def _parse(argv):
    with contextlib.redirect_stderr(io.StringIO()):
        return build_parser().parse_args(normalize_argv(list(argv)))


# ------------------------------------------------------------------------------------------------ kubectl / helm selectors
class KubeSelectorTests(unittest.TestCase):                             # a2-mcp#1, a2-webui-backend#2, a2-platform-logic#3
    def test_cloud_or_env_alone_is_passed_on(self):
        for tool in ("cloudseed_kubectl", "cloudseed_helm"):
            argv = mcp.TOOLS[tool]["argv"]
            word = tool.split("_")[1]
            self.assertEqual(argv({"args": "get pods", "env": "prod"}), [word, "--env", "prod", "--", "get", "pods"])
            self.assertEqual(argv({"args": "get pods", "cloud": "gcp"}), [word, "gcp", "--", "get", "pods"])
            self.assertEqual(argv({"args": "get pods", "cloud": "gcp", "env": "dev"}), [word, "gcp", "--env", "dev", "--", "get", "pods"])
            self.assertEqual(argv({"args": "get pods"}), [word, "--", "get", "pods"])

    def test_the_cli_reads_the_selectors_the_way_they_were_meant(self):
        cases = (({"env": "prod"}, None, "prod"), ({"cloud": "gcp"}, "gcp", None), ({"cloud": "gcp", "env": "dev"}, "gcp", "dev"), ({}, None, None))
        for tool in ("cloudseed_kubectl", "cloudseed_helm"):
            for sel, cloud, env in cases:
                ns = _parse(mcp.TOOLS[tool]["argv"]({"args": "-n kube-system delete ns shop", **sel}))
                self.assertEqual((ns.cloud, ns.env), (cloud, env), (tool, sel))
                self.assertEqual(ns.tool_args, ["-n", "kube-system", "delete", "ns", "shop"], (tool, sel))

    def test_env_alone_picks_that_cluster_not_the_current_one(self):
        lab, lab2 = paths.Env("vmware", "lab"), paths.Env("vmware", "lab2")
        ns = _parse(mcp.TOOLS["cloudseed_kubectl"]["argv"]({"args": "delete ns shop", "env": "lab2", "confirm": True}))
        with mock.patch.object(paths.Env, "list_all", return_value=[lab, lab2]), mock.patch.object(cli, "_has_cluster", return_value=True):
            env, problem, _ = cli._pick_cluster_env(ns.cloud, ns.env, {"current_env": "vmware-lab"}, prompt=False)
        self.assertIsNone(problem)
        self.assertEqual(env.id, "vmware-lab2")

    def test_the_console_builds_the_same_command(self):
        a = {"args": "get pods", "cloud": "vmware", "env": "lab"}
        self.assertEqual(webui.build_argv("cloudseed_kubectl", a), mcp.TOOLS["cloudseed_kubectl"]["argv"](a))
        self.assertEqual(webui.build_argv("cloudseed_helm", {"args": "list -A", "env": "lab"}), ["helm", "--env", "lab", "--", "list", "-A"])

    def test_descriptions_say_either_selector_works(self):
        for tool in ("cloudseed_kubectl", "cloudseed_helm"):
            self.assertIn("cloud and/or env", mcp.TOOLS[tool]["description"])


# ------------------------------------------------------------------------------------------------ helm status -o json
class HelmStatusGateTests(unittest.TestCase):                           # a2-mcp#0
    def gated(self, args):
        return mcp._is_destructive(mcp.TOOLS["cloudseed_helm"], {"args": args})

    def test_status_with_a_machine_readable_output_needs_confirm(self):
        for args in ("status x -o json", "status x -ojson", "status x -o=yaml", "status x --output json", "status x --output=yaml",
                     "status x --revision 2 -o json", "-n monitoring status monitoring -o json", "status x -o table -o json", "status x -o",
                     "status x -o JSON"):
            self.assertTrue(self.gated(args), args)
            r = _call("cloudseed_helm", {"args": args})
            self.assertTrue(r.get("isError"), args)
            self.assertIn("confirm=true", _text(r))

    def test_plain_status_history_and_metadata_still_run(self):
        for args in ("status x", "status x -o table", "status x --output=table", "status x --show-resources", "history x -o json",
                     "get metadata x -o json", "list -A -o json"):
            self.assertFalse(self.gated(args), args)
            self.assertIn("argv", _call("cloudseed_helm", {"args": args}), args)

    def test_the_console_gate_follows(self):
        with self.assertRaises(webui.NeedsConfirm):
            webui.build_argv("cloudseed_helm", {"args": "status monitoring -n monitoring -o json"})

    def test_texts_name_the_gate(self):
        self.assertIn("status -o json/yaml", mcp.TOOLS["cloudseed_helm"]["confirm_when"])
        self.assertIn("helm status -o json/yaml", json.dumps(mcp.guide_lines(None)))
        self.assertIn("status -o json|yaml", mcp.__doc__)


# ------------------------------------------------------------------------------------------------ stdio response order
class OrderedTests(unittest.TestCase):                                  # a2-mcp#2
    def test_order_is_kept_while_the_earlier_request_is_quick(self):
        out = []
        o = mcp._Ordered(out.append, wait=5)
        a, b = o.reserve(), o.reserve()
        o.complete(b, {"id": 2})
        self.assertEqual(out, [])
        o.complete(a, {"id": 1})
        self.assertEqual(out, [{"id": 1}, {"id": 2}])

    def test_a_long_request_holds_later_answers_only_briefly(self):
        out: queue.Queue = queue.Queue()
        o = mcp._Ordered(out.put, wait=0.3)
        slow, quick = o.reserve(), o.reserve()
        started = time.monotonic()
        o.complete(quick, {"id": "quick"})
        self.assertEqual(out.get(timeout=5), {"id": "quick"})       # released by the timer, the slow one still runs
        self.assertLess(time.monotonic() - started, 3)
        later = o.reserve()                                          # arrives after the slow request's window: goes out at once
        o.complete(later, {"id": "later"})
        self.assertEqual(out.get_nowait(), {"id": "later"})
        o.complete(slow, {"id": "slow"})
        self.assertEqual(out.get_nowait(), {"id": "slow"})
        o.complete(o.reserve(), None)                                # a cancelled call writes nothing
        self.assertTrue(out.empty())

    def test_stdio_answers_tools_list_while_a_long_call_runs(self):
        slow = Path(tempfile.mkdtemp(prefix="cs-w3mcp-")) / "slow.py"
        slow.write_text("import time\ntime.sleep(8)\nprint('done')\n")
        r_in, w_in = os.pipe()
        r_out, w_out = os.pipe()
        fake_in, fake_out = SimpleNamespace(buffer=os.fdopen(r_in, "rb")), SimpleNamespace(buffer=os.fdopen(w_out, "wb"))
        lines: queue.Queue = queue.Queue()
        reader = os.fdopen(r_out, "rb")
        threading.Thread(target=lambda: [lines.put((time.monotonic(), json.loads(x))) for x in iter(reader.readline, b"")], daemon=True).start()
        writer = os.fdopen(w_in, "wb")

        def send(obj):
            writer.write((json.dumps(obj) + "\n").encode())
            writer.flush()
        try:
            with mock.patch.object(sys, "stdin", fake_in), mock.patch.object(sys, "stdout", fake_out), \
                    mock.patch.object(mcp, "_launcher", return_value=[sys.executable, str(slow)]), mock.patch.object(mcp, "ORDER_WAIT", 0.5), \
                    mock.patch.dict(os.environ, {"CLOUDSEED_MCP_FORCE": "1"}):
                srv = threading.Thread(target=mcp.serve, daemon=True)
                srv.start()
                t0 = time.monotonic()
                send({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cloudseed_list", "arguments": {}}})
                time.sleep(0.2)
                send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                send({"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
                got = [lines.get(timeout=6), lines.get(timeout=6)]
                self.assertEqual([m["id"] for _, m in got], [2, 3])
                self.assertLess(got[1][0] - t0, 5)                    # long before the 8 s call ends
                at, first = lines.get(timeout=30)
                self.assertEqual(first["id"], 1)
                self.assertIn("done", _text(first["result"]))
                writer.close()
                srv.join(20)
                self.assertFalse(srv.is_alive())
        finally:
            for fh in (fake_out.buffer, fake_in.buffer, reader):
                try:
                    fh.close()
                except OSError:
                    pass
            shutil.rmtree(slow.parent, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ service definitions
class _Launchctl:
    """Records launchctl/systemctl calls; `print` reports the job as gone, everything else succeeds (or fails on demand)."""

    def __init__(self, fail=()):
        self.calls: list = []
        self.fail = set(fail)

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        rc = 1 if (argv[:2] == ["launchctl", "print"] or tuple(argv[:2]) in self.fail) else 0
        return SimpleNamespace(returncode=rc, stdout="", stderr="refused" if rc else "")

    def labels(self, verb):
        return [a[2].rsplit("/", 1)[-1] for a in self.calls if a[:2] == ["launchctl", verb]]


class ServiceTests(unittest.TestCase):                                  # a2-mcp#3, a2-mcp#18
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="cs-w3mcp-home-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        p = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)

    def plist(self, label, home):
        path = self.home / "Library" / "LaunchAgents" / f"{label}.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as fh:
            plistlib.dump({"Label": label, "ProgramArguments": ["x"], "EnvironmentVariables": {"CLOUDSEED_HOME": str(home)}}, fh)
        return path

    def fake_start(self, state, lc):
        proc = SimpleNamespace(pid=999999, poll=lambda: None)
        with mock.patch.object(mcp.subprocess, "run", side_effect=lc), mock.patch.object(mcp.subprocess, "Popen", return_value=proc), \
                mock.patch.object(mcp, "health", return_value={"ok": True}), mock.patch.object(mcp, "save_state"), \
                mock.patch.object(mcp.shutil, "which", return_value=None), contextlib.redirect_stderr(io.StringIO()):
            return mcp.start(dict(state))

    def test_a_second_home_gets_its_own_label(self):
        self.assertNotEqual(mcp._home_path(), mcp._default_home())       # the test home is never the user's real one
        self.assertEqual(mcp._service_label(), f"{mcp.LAUNCHD_LABEL}.{mcp._home_id()}")
        self.assertEqual(mcp._systemd_name(), f"{mcp.SYSTEMD_UNIT}-{mcp._home_id()}")
        self.assertEqual(mcp._launchd_plist().name, f"{mcp.LAUNCHD_LABEL}.{mcp._home_id()}.plist")
        with mock.patch.object(mcp, "_default_home", return_value=mcp._home_path()):
            self.assertEqual(mcp._service_label(), mcp.LAUNCHD_LABEL)   # the default home keeps the name older versions used
            self.assertEqual(mcp._systemd_unit().name, "cloudseed-mcp.service")

    def test_switching_to_background_removes_this_homes_login_service(self):
        own = self.plist(mcp._service_label(), mcp._home_path())
        lc = _Launchctl()
        state = {"transport": "http", "host": "127.0.0.1", "port": 7761, "auth": "none", "service": "background"}
        self.assertEqual(mcp.leftover_services(state), [str(own)])
        self.assertEqual(self.fake_start(state, lc), "background")
        self.assertFalse(own.exists())
        self.assertIn(mcp._service_label(), lc.labels("bootout"))
        self.assertNotIn(mcp.LAUNCHD_LABEL, lc.labels("bootout"))        # never the shared name of the real launchd domain
        self.assertEqual(mcp.leftover_services(state), [])

    def test_a_refused_launchd_service_is_not_left_behind(self):
        lc = _Launchctl(fail={("launchctl", "bootstrap"), ("launchctl", "load")})
        kind = self.fake_start({"transport": "http", "host": "127.0.0.1", "port": 7762, "auth": "none", "service": "launchd"}, lc)
        self.assertEqual(kind, "background")
        self.assertFalse(mcp._launchd_plist().exists())

    def test_another_homes_definition_under_the_shared_name_is_left_alone(self):
        other = self.home / "elsewhere" / ".cloudseed"
        shared = self.plist(mcp.LAUNCHD_LABEL, other)
        lc = _Launchctl()
        with mock.patch.object(mcp, "_default_home", return_value=mcp._home_path()), mock.patch.object(mcp.subprocess, "run", side_effect=lc), \
                mock.patch.object(mcp.shutil, "which", return_value=None), mock.patch.object(mcp, "_read_pid", return_value=None):
            self.assertEqual(mcp._service_defs("launchd"), [])
            mcp.remove_service({"service": "launchd"})
            mcp.stop({"service": "launchd"})
        self.assertTrue(shared.exists())
        self.assertNotIn(mcp.LAUNCHD_LABEL, lc.labels("bootout"))

    def test_this_homes_definition_under_the_shared_name_is_migrated(self):
        shared = self.plist(mcp.LAUNCHD_LABEL, mcp._home_path())         # written by an older version for this (non-default) home
        lc = _Launchctl()
        with mock.patch.object(mcp.subprocess, "run", side_effect=lc), mock.patch.object(mcp.shutil, "which", return_value=None), \
                mock.patch.object(mcp, "_read_pid", return_value=None):
            self.assertIn((mcp.LAUNCHD_LABEL, shared), mcp._service_defs("launchd"))
            mcp.remove_service({})
        self.assertFalse(shared.exists())
        self.assertIn(mcp.LAUNCHD_LABEL, lc.labels("bootout"))

    def test_the_guide_names_this_homes_label(self):
        rows = dict(dict(mcp.guide_lines({"transport": "http", "host": "127.0.0.1", "port": 7763, "auth": "none", "service": "launchd"}))["1. Your cloudseed MCP server"])
        self.assertIn(mcp._service_label(), rows["Runs as"])


# ------------------------------------------------------------------------------------------------ Codex config.toml
class CodexTomlTests(unittest.TestCase):                                # a2-mcp#7
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="cs-w3mcp-codex-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        p = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        b = mock.patch.object(mcp, "BACKUPS_DIR", self.home / "backups")
        b.start()
        self.addCleanup(b.stop)
        self.cfg = self.home / ".codex" / "config.toml"
        self.cfg.parent.mkdir()

    def entries(self):
        text = self.cfg.read_text()
        if HAS_TOMLLIB:
            import tomllib
            return [tomllib.loads(text)["mcp_servers"]["cloudseed"]]
        return [m.group(0) for m in mcp._TOML_OUR_TABLE.finditer(text) if not m.group(0).rstrip().endswith(".env]")]

    def test_forms_the_rewrite_cannot_handle_are_refused_untouched(self):
        for doc in ('[mcp_servers]\ncloudseed = { command = "old", args = ["mcp", "serve"] }\n',
                    '[mcp_servers]  # mine\ncloudseed.command = "old"\n',
                    'model = "x"\nmcp_servers.cloudseed.command = "old"\n',
                    'mcp_servers = { other = { command = "y" } }\n',
                    '[[mcp_servers.cloudseed]]\ncommand = "old"\n' if not HAS_TOMLLIB else 'model = [\n'):
            self.cfg.write_text(doc)
            with self.assertRaises(ui.Abort) as cm, contextlib.redirect_stderr(io.StringIO()):
                mcp.connect("codex", "stdio", None)
            self.assertIn("left it untouched", cm.exception.msg, doc)
            self.assertEqual(self.cfg.read_text(), doc)
            self.assertFalse(mcp.BACKUPS_DIR.exists() and any(mcp.BACKUPS_DIR.iterdir()), doc)

    def test_ordinary_spellings_of_our_table_are_rewritten(self):
        for header in ('[mcp_servers.cloudseed]   # my entry', '[mcp_servers."cloudseed"]', "[ mcp_servers . 'cloudseed' ]", '["mcp_servers".cloudseed]'):
            self.cfg.write_text(f'model = "x"\n\n{header}\ncommand = "old"\n\n[mcp_servers.other]\ncommand = "y"\n')
            self.assertEqual(mcp.connected("codex"), "stdio", header)
            mcp.connect("codex", "stdio", None)
            text = self.cfg.read_text()
            self.assertNotIn('"old"', text, header)
            self.assertIn("[mcp_servers.other]", text)
            self.assertEqual(len(self.entries()), 1, header)

    def test_status_and_disconnect_see_the_inline_form(self):
        doc = '[mcp_servers]\ncloudseed = { url = "http://127.0.0.1:7433/mcp", http_headers = { Authorization = "Bearer x" } }\n'
        self.cfg.write_text(doc)
        self.assertEqual(mcp.connected("codex"), "http")
        self.assertTrue(mcp.stale("codex", {"transport": "http", "host": "127.0.0.1", "port": 7434, "auth": "none"}))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertIsNone(mcp.disconnect("codex"))     # never "removed" while the entry is still there
        self.assertIn("inline table", err.getvalue())
        self.assertEqual(self.cfg.read_text(), doc)
        self.cfg.write_text('mcp_servers.cloudseed.command = "x"\n')
        self.assertEqual(mcp.connected("codex"), "stdio")

    @unittest.skipUnless(HAS_TOMLLIB, "needs tomllib (Python 3.11+) to tell that the rewrite would break the file")
    def test_disconnect_never_writes_a_file_codex_cannot_load(self):
        doc = 'notes = """\n[mcp_servers.cloudseed]\n"""\nmodel = "x"\n'      # a header-like line inside a multi-line string
        self.cfg.write_text(doc)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertIsNone(mcp.disconnect("codex"))
        self.assertIn("left it untouched", err.getvalue())
        self.assertEqual(self.cfg.read_text(), doc)

    def test_a_normal_round_trip_still_works(self):
        self.cfg.write_text('model = "x"\n\n[mcp_servers.other]\ncommand = "y"\n')
        mcp.connect("codex", "stdio", None)
        self.assertEqual(mcp.connected("codex"), "stdio")
        self.assertIsNotNone(mcp.disconnect("codex"))
        self.assertIsNone(mcp.connected("codex"))
        self.assertIn("[mcp_servers.other]", self.cfg.read_text())


# ------------------------------------------------------------------------------------------------ client-config backups
class BackupTests(unittest.TestCase):                                   # a2-mcp#14
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="cs-w3mcp-bak-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        for p in (mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch.object(mcp, "BACKUPS_DIR", self.home / "backups")):
            p.start()
            self.addCleanup(p.stop)

    def test_the_commented_original_survives_many_rewrites(self):
        cfg = self.home / ".gemini" / "settings.json"
        cfg.parent.mkdir()
        cfg.write_text('{\n  // precious comment\n  "theme": "dark",\n}\n')
        state = {"transport": "http", "host": "127.0.0.1", "port": 7764, "auth": "none"}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            mcp.connect("gemini", "stdio", None)
            for i in range(8):                  # port changes / reconnects: every one rewrites and backs up
                mcp.connect("gemini", "http", {**state, "port": 7764 + i % 2})
        self.assertIn("never pruned", err.getvalue())
        names = sorted(p.name for p in mcp.BACKUPS_DIR.iterdir())
        originals = [n for n in names if n.startswith("gemini-original-")]
        self.assertEqual(len(originals), 1, names)
        self.assertIn("precious comment", (mcp.BACKUPS_DIR / originals[0]).read_text())
        self.assertEqual(len(names) - len(originals), mcp.KEEP_BACKUPS)

    def test_the_first_copy_of_a_plain_file_is_protected_too(self):
        cfg = self.home / ".cursor" / "mcp.json"
        cfg.parent.mkdir()
        cfg.write_text('{"mcpServers": {"mine": {"command": "z"}}}')
        state = {"transport": "http", "host": "127.0.0.1", "port": 7765, "auth": "none"}
        for i in range(8):
            mcp.connect("cursor", "http", {**state, "port": 7765 + i % 2})
        first = [p for p in mcp.BACKUPS_DIR.iterdir() if p.name.startswith("cursor-original-")]
        self.assertEqual(len(first), 1)
        self.assertNotIn("cloudseed", first[0].read_text())
        self.assertIn("never pruned", json.dumps(mcp.guide_lines(None)))

    def test_after_an_upgrade_the_oldest_existing_copy_is_protected(self):
        mcp.BACKUPS_DIR.mkdir()
        old = mcp.BACKUPS_DIR / "cursor-20240101-000000-mcp.json"          # left by a version without protected originals
        old.write_text('{"mcpServers": {"mine": {"command": "z"}}}')
        os.utime(old, (1_700_000_000, 1_700_000_000))
        (mcp.BACKUPS_DIR / "cursor-20240102-000000-mcp.json").write_text("{}")
        cfg = self.home / ".cursor" / "mcp.json"
        cfg.parent.mkdir()
        cfg.write_text('{"mcpServers": {"mine": {"command": "z"}}}')
        state = {"transport": "http", "host": "127.0.0.1", "port": 7767, "auth": "none"}
        for i in range(8):
            mcp.connect("cursor", "http", {**state, "port": 7767 + i % 2})
        names = sorted(p.name for p in mcp.BACKUPS_DIR.iterdir())
        self.assertIn("cursor-original-20240101-000000-mcp.json", names)
        self.assertEqual(len([n for n in names if n.startswith("cursor-original-")]), 1, names)
        self.assertEqual(len(names), mcp.KEEP_BACKUPS + 1, names)


# ------------------------------------------------------------------------------------------------ guide & descriptions
class GuideAndDescriptionTests(unittest.TestCase):                      # a2-mcp#15, #16, #19, #20, need-resilience
    def test_token_rotation_advice_does_not_rewire_clients(self):
        text = json.dumps(mcp.guide_lines({"transport": "http", "host": "127.0.0.1", "port": 7766, "auth": "token", "service": "background"}))
        self.assertNotIn("then cs mcp connect all", text)
        self.assertIn("updates every HTTP-connected client itself", text)

    def test_connected_clients_get_no_connect_hint(self):
        with mock.patch.object(mcp, "connected", side_effect=lambda k: "stdio" if k == "codex" else None), \
                mock.patch.object(mcp, "client_present", return_value=True), mock.patch.object(mcp, "stale", return_value=False):
            rows = dict(dict(mcp.guide_lines(None))["2. Connect a client  (cs mcp connect <client> | all)"])
        self.assertEqual(rows["OpenAI Codex CLI"], "✔ connected (stdio)")
        self.assertIn("cs mcp connect cursor", rows["Cursor"])

    def test_confirm_texts_are_not_repeated(self):
        for t in mcp.tool_list():
            d = t["description"]
            self.assertNotIn("Destructive uses need confirm=true:", d, t["name"])
            self.assertNotIn("confirm=true: needs confirm=true", d, t["name"])
            self.assertEqual(d.lower().count("need confirm=true") + d.lower().count("needs confirm=true"), 1 if t["annotations"]["destructiveHint"] else 0, t["name"])
        undo_ = {t["name"]: t for t in mcp.tool_list()}["cloudseed_undo"]["description"]
        self.assertIn("Everything except list=true needs confirm=true.", undo_)

    def test_scan_says_scanners_are_never_installed(self):
        cw = mcp.TOOLS["cloudseed_scan"]["confirm_when"]
        self.assertNotIn("or installs a scanner", cw)
        self.assertIn("never installed", cw)

    def test_kubeconfig_description_names_the_context_switch(self):
        d = mcp.TOOLS["cloudseed_k8s"]["description"]
        self.assertIn("current kubectl context", d)
        self.assertIn("$KUBECONFIG", d)

    def test_setup_says_what_a_plan_keeps(self):
        # a plan keeps nothing (setup --preview) unless save=true keeps the settings for cloudseed_apply (--plan-only)
        self.assertIn("Without apply nothing is kept", mcp.TOOLS["cloudseed_setup"]["description"])
        self.assertIn("save=true instead keeps the planned settings", mcp.TOOLS["cloudseed_setup"]["description"])
        self.assertIn("nothing is kept", mcp.TOOLS["cloudseed_setup"]["schema"]["properties"]["apply"]["description"])
        self.assertIn("cloudseed_plan first", mcp.TOOLS["cloudseed_apply"]["description"])
        self.assertIn("with save=true", mcp.TOOLS["cloudseed_apply"]["description"])

    def test_disconnect_message_does_not_repeat_the_client(self):
        with mock.patch.object(mcp.shutil, "which", return_value="/bin/claude"), \
                mock.patch.object(mcp.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
            msg = mcp.disconnect("claude-code")
        self.assertNotIn("Claude Code", msg)
        self.assertIn("user scope", msg)


# ------------------------------------------------------------------------------------------------ small MCP inconsistencies
class ArgumentTests(unittest.TestCase):                                 # a2-mcp#20, a2-docs-skills#13, a2-resilience#16
    def test_env_id_alone_means_use(self):
        self.assertEqual(_call("cloudseed_env", {"id": "aws-dev"})["argv"], ["env", "use", "aws-dev"])
        self.assertEqual(_call("cloudseed_env", {})["argv"], ["env", "show"])
        r = _call("cloudseed_env", {"action": "show", "id": "aws-dev"})
        self.assertTrue(r["isError"]); self.assertIn("action=use only", _text(r))
        r = _call("cloudseed_env", {"id": "dev"})
        self.assertTrue(r["isError"]); self.assertIn("environment id such as aws-dev", _text(r))
        self.assertEqual(_parse(["env", "use", "aws-dev"]).env_cmd, "use")

    def test_env_names_follow_the_cli_rule(self):
        for bad, why in (("Bad_Name", "2-24 lowercase"), (" ", "2-24 lowercase"), ("-x", "2-24 lowercase"), ("a", "2-24 lowercase")):
            r = _call("cloudseed_status", {"cloud": "aws", "env": bad})
            self.assertTrue(r["isError"], bad)
            self.assertIn(why, _text(r), bad)
            self.assertNotIn("(it must not start with '-')", _text(r), bad)    # the old, wrong reason for ' '
        self.assertEqual(_call("cloudseed_status", {"cloud": "aws", "env": "prod-2"})["argv"], ["status", "aws", "--env", "prod-2"])
        self.assertEqual(cli.NAME_RE.pattern, mcp.ENV_NAME)

    def test_pattern_messages_say_what_is_wrong(self):
        self.assertIn("must not start with a space", mcp._check(mcp.S_WORD, " x", "name"))
        self.assertIn("must not start with '-'", mcp._check(mcp.S_WORD, "-x", "name"))

    def test_resources_read_without_a_uri_is_an_invalid_params_error(self):
        s = mcp.Session({})
        for params in ({}, {"uri": 5}, {"uri": ""}):
            r = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": params}, s)
            self.assertEqual(r["error"]["code"], -32602, params)
        r = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": "cloudseed://nope"}}, s)
        self.assertEqual(r["error"]["code"], -32002)
        r = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": {"name": 7}}, s)
        self.assertEqual(r["error"]["code"], -32602)

    def test_skills_take_short_names(self):
        self.assertEqual(mcp.TOOLS["cloudseed_skill"]["argv"]({"name": "aws"}), ["skill", "show", "cloudseed-aws"])
        self.assertEqual(mcp.TOOLS["cloudseed_skill"]["argv"]({"name": "Platform"}), ["skill", "show", "cloudseed-platform"])
        self.assertEqual(mcp.TOOLS["cloudseed_skill"]["argv"]({"name": "cloudseed"}), ["skill", "show", "cloudseed"])
        r = _call("cloudseed_skill", {"name": "nope"})
        self.assertIn("unknown skill 'nope'", _text(r)); self.assertIn("aws", _text(r))
        for bad in ("../x", "/etc", ".hidden"):
            self.assertTrue(_call("cloudseed_skill", {"name": bad})["isError"], bad)
        res = mcp.read_resource("cloudseed://skills/aws")
        self.assertEqual(res["contents"][0]["uri"], "cloudseed://skills/aws")
        self.assertIn("aws", res["contents"][0]["text"].lower())
        self.assertIsNone(mcp.read_resource("cloudseed://skills/nope"))

    def test_help_takes_a_cloud(self):
        self.assertEqual(_call("cloudseed_help", {"topic": "variables", "cloud": "aws"})["argv"], ["help", "variables", "aws"])
        self.assertEqual(_call("cloudseed_help", {"topic": "variables aws", "cloud": "aws"})["argv"], ["help", "variables", "aws"])
        self.assertEqual(_parse(["help", "variables", "aws"]).cloud, "aws")

    def test_dr_options(self):
        argv = _call("cloudseed_dr", {"action": "schedule", "name": "nightly", "cloud": "vmware", "env": "lab", "ttl": "72h30m", "confirm": True})["argv"]
        self.assertEqual(argv[argv.index("--ttl") + 1], "72h30m")
        self.assertEqual(_parse(argv).ttl, "72h30m")
        argv = _call("cloudseed_dr", {"action": "test", "cloud": "vmware", "keep": True, "volume": "off", "confirm": True})["argv"]
        ns = _parse(argv)
        self.assertTrue(ns.keep); self.assertIs(ns.volume, False)
        self.assertIs(_parse(_call("cloudseed_dr", {"action": "test", "volume": "on", "confirm": True})["argv"]).volume, True)
        self.assertTrue(_parse(_call("cloudseed_dr", {"action": "backup", "no_wait": True, "confirm": True})["argv"]).no_wait)
        for bad in ("5", "-1h", "h", "d", "1.5d", "1d2h"):
            r = _call("cloudseed_dr", {"action": "schedule", "ttl": bad, "confirm": True})
            self.assertTrue(r["isError"], bad)
        # whole days: `cs dr schedule` rewrites them to hours (30d = 720h), so MCP passes them on (wave 4)
        argv = _call("cloudseed_dr", {"action": "schedule", "name": "nightly", "ttl": "30d", "confirm": True})["argv"]
        self.assertEqual(argv[argv.index("--ttl") + 1], "30d")
        # the console sends a blank select and an unticked box: neither may turn the drill's auto-detection off
        argv = webui.build_argv("cloudseed_dr", {"action": "test", "cloud": "vmware", "env": "lab", "volume": "", "keep": False, "confirm": True})
        self.assertNotIn("--no-volume", argv); self.assertNotIn("--volume", argv); self.assertNotIn("--keep", argv)

    def test_chaos_options(self):
        argv = _call("cloudseed_chaos", {"action": "run", "items": ["basic"], "replicas": 5, "keep": True, "confirm": True})["argv"]
        ns = _parse(argv)
        self.assertEqual(ns.replicas, 5); self.assertTrue(ns.keep)
        for bad in (1, 21):
            self.assertTrue(_call("cloudseed_chaos", {"action": "run", "replicas": bad, "confirm": True})["isError"], bad)
        self.assertNotIn("--keep", webui.build_argv("cloudseed_chaos", {"action": "run", "keep": False, "confirm": True}))


if __name__ == "__main__":
    unittest.main()
