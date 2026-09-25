"""Regression tests for the wave-3 cli-tools items: the human-only gate for agent sessions, pasting a JSON key at the
hidden prompt, `use --model <typo>` ordering, the headliner undo guards, readiness before side effects, `ui token
--rotate` / restart / stop with a foreground console, the runtime gate for finops and undo, `deps runtime` undo points,
the undo of `destroy mcp`, `mcp connect` while MCP is off, `mcp test` without a proxy, --port ranges, `mcp token
--rotate` in stdio mode, width-aware `-h`, scrolling menus, menu answers, TERM=dumb, did-you-mean, BrokenPipe, piped
`cs list`, wide-character wrapping and the install list.

CLI runs use a fresh CLOUDSEED_HOME and HOME and a PATH without terraform or agent CLIs; nothing is installed, no
server is started, and no network is used. Anything that edits MCP client configs runs in a child process whose HOME
is a temporary directory."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

ROOT = Path(__file__).resolve().parent.parent
CS = str(ROOT / "bin" / "cloudseed")
sys.path.insert(0, str(ROOT))

from cloudseed import agents, cli, mcp, ui, undo, webui  # noqa: E402

POSIX = os.name == "posix"


class Sandbox(unittest.TestCase):
    """A fresh cloudseed home and user home, and a PATH with only python and the system dirs (no terraform)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w3-tools-"))
        self.home, self.user, self.bin = self.tmp / "cs", self.tmp / "home", self.tmp / "bin"
        for d in (self.home, self.user, self.bin):
            d.mkdir()
        os.symlink(sys.executable, self.bin / "python3")
        for tool in ("launchctl", "systemctl"):   # never a real login service, whatever a command under test does
            (self.bin / tool).write_text("#!/bin/sh\nexit 1\n")
            (self.bin / tool).chmod(0o755)
        self.env = {"CLOUDSEED_HOME": str(self.home), "HOME": str(self.user), "NO_COLOR": "1", "COLUMNS": "100",
                    "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
                    "ANTHROPIC_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": "", "CLAUDE_CODE_OAUTH_TOKEN": ""}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cs(self, *args, env: dict | None = None):
        e = dict(self.env, **(env or {}))
        p = subprocess.run([sys.executable, CS, *args], env=e, capture_output=True, text=True, timeout=120,
                           stdin=subprocess.DEVNULL, cwd=str(self.tmp))
        return p.returncode, p.stdout + p.stderr

    def journal(self) -> list:
        try:
            data = json.loads((self.home / "undo.json").read_text())
        except OSError:
            return []
        return [e for entries in data.values() for e in entries] if isinstance(data, dict) else list(data)

    def settings(self) -> dict:
        try:
            return json.loads((self.home / "settings.json").read_text())
        except OSError:
            return {}

    def vault(self) -> dict:
        try:
            return json.loads((self.home / "credentials.json").read_text())
        except OSError:
            return {}


def _parse(*argv):
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        return cli.build_parser().parse_args(cli.normalize_argv(list(argv)))


def _parse_error(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(io.StringIO()), \
            mock.patch.object(sys, "argv", ["cloudseed", *argv]):
        try:
            cli.build_parser().parse_args(argv)
        except SystemExit as e:
            return e.code, buf.getvalue()
    return 0, buf.getvalue()


def _pty_write(master: int, data: bytes, piece: int = 256, timeout: float = 10.0) -> None:
    """Type `data` into a pty without ever blocking the test (the master is switched to non-blocking): pieces that do
    not fit are retried until `timeout`; a pty whose other side is gone ends the typing."""
    import fcntl
    fcntl.fcntl(master, fcntl.F_SETFL, fcntl.fcntl(master, fcntl.F_GETFL) | os.O_NONBLOCK)
    deadline = time.time() + timeout
    while data and time.time() < deadline:
        try:
            data = data[os.write(master, data[:piece]):]
        except BlockingIOError:
            pass
        except OSError:
            return
        time.sleep(0.005)


# ---------------------------------------------------------------- agentic#0: human-only commands in agent sessions

class HumanOnlyPolicyTest(unittest.TestCase):
    REFUSED = [
        ("creds", "set", "ANTHROPIC_BASE_URL=https://evil.example"), ("creds", "set", "HTTPS_PROXY=http://evil:8080"),
        ("creds", "unset", "X"), ("creds", "clear", "--forget"), ("use", "codex"), ("use",), ("model", "claude-opus-4-1"),
        ("model", "--forget", "x"), ("enable", "agentic"), ("disable", "headliner"), ("enable", "ui"), ("ui",),
        ("ui", "start"), ("ui", "stop"), ("ui", "restart"), ("ui", "serve"), ("ui", "token", "--rotate"), ("ui", "token"),
        ("mcp", "connect", "cursor"), ("mcp", "disconnect", "all"), ("mcp", "start"), ("mcp", "stop"), ("mcp", "restart"),
        ("mcp", "token"), ("mcp", "token", "--rotate"), ("mcp", "uninstall"), ("setup", "mcp"), ("destroy", "mcp"),
        ("install", "terraform"), ("install", "skills"), ("skill", "install"), ("deps", "install", "terraform"),
        ("deps", "image"), ("deps", "bundle"), ("deps", "runtime", "local"), ("agentic", "list", "envs"), ("do", "hi"),
    ]
    ALLOWED = [
        ("creds",), ("creds", "list"), ("model",), ("model", "--agent", "codex"), ("use", "list"), ("ui", "status"),
        ("ui", "logs"), ("mcp",), ("mcp", "status"), ("mcp", "guide"), ("mcp", "tools"), ("mcp", "config"),
        ("mcp", "test"), ("mcp", "serve"), ("mcp", "logs"), ("deps", "status"), ("skill", "list"), ("skill", "show", "aws"),
        ("install",), ("install", "list"), ("list",), ("status", "aws", "--env", "dev"), ("ssh", "aws", "--env", "dev"),
        ("undo", "--list"), ("env", "use", "aws-dev"), ("help", "creds"), ("explain", "mcp"), ("doctor",),
    ]

    def test_the_policy_refuses_changes_and_keeps_read_only_forms(self):
        for argv in self.REFUSED:
            self.assertIsNotNone(cli.human_only_reason(_parse(*argv)), argv)
            self.assertIsNotNone(cli.human_only_reason(_parse("-y", *argv)), argv)     # -y changes nothing
        for argv in self.ALLOWED:
            self.assertIsNone(cli.human_only_reason(_parse(*argv)), argv)

    def test_the_command_shown_to_the_human_carries_no_secret_and_no_y(self):
        self.assertEqual(cli._human_command(["-y", "creds", "set", "ANTHROPIC_BASE_URL=https://evil.example", "FOO=bar"]),
                         "cloudseed creds set ANTHROPIC_BASE_URL FOO")
        self.assertEqual(cli._human_command(["ui", "token", "--rotate", "-y"]), "cloudseed ui token --rotate")
        # global options before the command do not hide the value from the filter
        self.assertEqual(cli._human_command(["--runtime", "local", "creds", "-y", "set", "HTTPS_PROXY=http://evil:8080"]),
                         "cloudseed --runtime local creds set HTTPS_PROXY")
        self.assertIn("token", cli.human_only_reason(_parse("ui", "token")))   # it only prints the console's secret


class HumanOnlyGateTest(Sandbox):
    def test_agent_sessions_cannot_change_the_vault_settings_or_token(self):
        rc, out = self.cs("creds", "set", "OLD_TOKEN=keepme")
        self.assertEqual(rc, 0, out)
        before = (self.vault(), self.settings())
        agent = {"CLOUDSEED_AGENT": "claude", "CLOUDSEED_REDACT": "1"}
        for argv in (("-y", "creds", "set", "ANTHROPIC_BASE_URL=https://evil.example"), ("-y", "creds", "clear", "--forget"),
                     ("-y", "disable", "headliner"), ("-y", "use", "codex"), ("-y", "ui", "token", "--rotate"),
                     ("-y", "mcp", "connect", "cursor"), ("install", "skills", "-y")):
            rc, out = self.cs(*argv, env=agent)
            self.assertEqual(rc, 2, (argv, out))
            self.assertIn("human-only", out)
            self.assertIn("Ask the user to run it in a terminal", out)
            self.assertNotIn("evil.example", out)                  # the value never reaches the suggested command
        self.assertEqual((self.vault(), self.settings()), before)
        self.assertFalse((self.home / "ui" / "token").exists())
        self.assertFalse((self.user / ".claude").exists())         # no skills were installed
        self.assertFalse((self.user / ".cursor").exists())         # no client config was written
        rc, out = self.cs("creds", env=agent)                      # read-only forms still work
        self.assertEqual(rc, 0, out)
        self.assertIn("OLD_TOKEN", out)
        rc, out = self.cs("-y", "creds", "set", "OTHER=1", env={"CLOUDSEED_AGENT": "mcp", "CLOUDSEED_REDACT": "1"})
        self.assertEqual(rc, 0, out)                               # MCP tool calls are confirm-gated elsewhere
        self.assertEqual(self.vault().get("OTHER"), "1")


# ---------------------------------------------------------------- agentic#1: a pasted JSON key at the hidden prompt

def _json_key(size: int = 1726) -> str:
    return json.dumps({"type": "service_account", "project_id": "p", "private_key_id": "k" * 40,
                       "private_key": "-----BEGIN " + "PRIVATE KEY-----\\n" + "A" * size + "\\n-----END PRIVATE KEY-----\\n",
                       "client_email": "x@p.iam.gserviceaccount.com", "client_id": "1" * 21,
                       "token_uri": "https://oauth2.googleapis.com/token"}, indent=2)


@unittest.skipUnless(POSIX, "needs a pty")
class HiddenBlobTest(unittest.TestCase):
    def read(self, typed: bytes, **kw) -> tuple[str, str]:
        import fcntl
        import pty
        import termios
        master, slave = pty.openpty()
        fcntl.fcntl(master, fcntl.F_SETFL, fcntl.fcntl(master, fcntl.F_GETFL) | os.O_NONBLOCK)   # never block the test
        err = io.StringIO()
        stop = threading.Event()

        def writer():
            deadline = time.time() + 10
            while time.time() < deadline and not stop.is_set():   # wait until the prompt switched to non-canonical mode
                if not termios.tcgetattr(slave)[3] & termios.ICANON:
                    break
                time.sleep(0.01)
            data = typed
            while data and time.time() < deadline and not stop.is_set():   # a paste arrives in pieces
                try:
                    data = data[os.write(master, data[:512]):]
                except BlockingIOError:
                    pass
                time.sleep(0.005)

        t = threading.Thread(target=writer, daemon=True)
        t.start()
        try:
            with contextlib.redirect_stderr(err), mock.patch.object(ui, "_prompt_stream", return_value=None):
                value = ui.read_hidden_blob("GOOGLE_CREDENTIALS: paste", fd=slave, **kw)
        finally:
            stop.set()
            t.join(15)
            os.close(master)
            os.close(slave)
        return value, err.getvalue()

    def test_a_pretty_printed_key_with_a_long_line_is_read_whole(self):
        key = _json_key()
        value, _ = self.read(key.encode() + b"\n")
        self.assertEqual(json.loads(value), json.loads(key))
        self.assertGreater(len(value), 1900)

    def test_one_line_values_end_at_enter_and_ctrl_d_ends_early(self):
        self.assertEqual(self.read(b"/path/to/key.json\n")[0], "/path/to/key.json")
        self.assertEqual(self.read(b"\n")[0], "")
        self.assertEqual(self.read(b'{"type": "x"\x04')[0], '{"type": "x"')
        self.assertEqual(self.read(b'{"type": "xy\x7f"}')[0], '{"type": "x"}')      # backspace

    def test_keys_pressed_after_the_json_are_dropped(self):
        # the object is complete: what follows in the same read (a command typed after the paste) is not part of it
        self.assertEqual(self.read(b'{"type": "x"}\nls -la\n\x04')[0], '{"type": "x"}')


class CredsJsonValidationTest(Sandbox):
    def test_broken_json_keys_are_refused_before_anything_is_written(self):
        for value, why in (("{", "not JSON"), ('{"a": 1}', 'without a "type"'), ("/tmp/key.json", "not JSON")):
            rc, out = self.cs("creds", "set", f"GOOGLE_CREDENTIALS={value}")
            self.assertEqual(rc, 2, out)
            self.assertIn(why, out)
            self.assertIn("GOOGLE_APPLICATION_CREDENTIALS=/path/key.json", out)
        self.assertEqual(self.vault(), {})
        rc, out = self.cs("creds", "set", 'GOOGLE_CREDENTIALS={"type": "authorized_user", "client_id": "x"}')
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(self.vault()["GOOGLE_CREDENTIALS"])["type"], "authorized_user")

    @unittest.skipUnless(POSIX, "needs a pty")
    def test_the_prompt_stores_the_whole_pasted_key_and_leaves_nothing_for_the_shell(self):
        import pty
        master, slave = pty.openpty()
        key = _json_key()
        p = subprocess.Popen([sys.executable, CS, "creds", "set", "GOOGLE_CREDENTIALS"], env=self.env, stdin=slave,
                             stdout=slave, stderr=slave, cwd=str(self.tmp), start_new_session=True)
        os.close(slave)
        out = b""
        sent = False
        deadline = time.time() + 60
        try:
            while time.time() < deadline:
                r, _, _ = select.select([master], [], [], 0.2)
                if r:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out += chunk
                if not sent and b"paste the key" in out:
                    time.sleep(0.2)
                    _pty_write(master, key.encode() + b"\n")
                    sent = True
                if p.poll() is not None and not r:
                    break
        finally:
            if p.poll() is None:
                p.kill()
            p.wait(10)
            os.close(master)
        text = out.decode(errors="replace")
        self.assertEqual(p.returncode, 0, text)
        self.assertIn("JSON key received", text)
        self.assertNotIn("private_key", text)                      # never echoed
        self.assertEqual(json.loads(self.vault()["GOOGLE_CREDENTIALS"]), json.loads(key))


# ---------------------------------------------------------------- agentic#9 / #21 / #23: agent & model choices

class UseModelOrderTest(unittest.TestCase):
    def test_a_declined_model_typo_switches_nothing(self):
        settings = {"agent": "builtin"}
        ns = argparse.Namespace(agent="gemini", model="gemni-2.5-pro")
        with mock.patch.object(ui, "interactive", return_value=True), mock.patch.object(ui, "confirm", return_value=False), \
                mock.patch.object(cli, "_ensure_agent_ready", side_effect=AssertionError("must not run")), \
                mock.patch.object(cli.paths, "save_settings", side_effect=AssertionError("must not save")), \
                mock.patch.object(cli.undo, "record") as rec, contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(ui.Abort) as cm:
                cli.cmd_use(ns, settings)
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("Nothing was changed", cm.exception.msg)
        self.assertIn("did you mean gemini-2.5-pro", err.getvalue())
        rec.assert_not_called()
        self.assertEqual(settings, {"agent": "builtin"})

    def test_a_later_failure_still_records_what_was_saved(self):
        settings = {"agent": "builtin"}
        ns = argparse.Namespace(agent="gemini", model="gemini-2.5-pro")

        def ready(key, s, **kw):
            s["agent"] = key
            return agents.get(key)

        with mock.patch.object(cli, "_ensure_agent_ready", side_effect=ready), \
                mock.patch.object(cli, "_apply_model", side_effect=ui.Abort("disk full")), \
                mock.patch.object(cli.undo, "snapshot_settings", return_value={"settings": {"agent": "builtin"}, "what": []}), \
                mock.patch.object(cli.undo, "record") as rec:
            with self.assertRaises(ui.Abort):
                cli.cmd_use(ns, settings)
        self.assertEqual(rec.call_args[0][1], "use gemini --model gemini-2.5-pro")

    def test_alias_and_dated_model_ids_get_a_hint(self):
        spec = {"key": "claude", "display": "Claude Code", "models": ["claude-haiku-4-5-20251001"]}
        with mock.patch.object(ui, "interactive", return_value=False), contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(cli._confirm_model("claude", spec, "claude-haiku-4-5", {}))
        self.assertIn("did you mean claude-haiku-4-5-20251001", err.getvalue())


class HeadlinerUndoTest(unittest.TestCase):
    def run_cmd(self, fn, feature, settings):
        with mock.patch.object(cli.paths, "save_settings"), mock.patch.object(cli.undo, "record") as rec, \
                contextlib.redirect_stdout(io.StringIO()):
            fn(argparse.Namespace(feature=feature, agent=None, port=None, no_open=True), settings)
        return rec

    def test_the_default_on_headliner_is_compared_by_its_effective_value(self):
        rec = self.run_cmd(cli.cmd_disable, "headliner", {})
        self.assertEqual(rec.call_args[0][1], "disable headliner")
        self.assertEqual(rec.call_args[0][3], {"argv": ["enable", "headliner"]})
        self.run_cmd(cli.cmd_enable, "headliner", {}).assert_not_called()          # on by default: nothing changed
        self.run_cmd(cli.cmd_enable, "headliner", {"headliner": False}).assert_called_once()
        self.run_cmd(cli.cmd_disable, "headliner", {"headliner": False}).assert_not_called()


class AgentReadinessFirstTest(unittest.TestCase):
    def test_a_task_for_an_agent_that_cannot_run_stops_before_skills_are_installed(self):
        with mock.patch.object(agents, "installed", return_value="/usr/local/bin/codex"), \
                mock.patch.object(agents, "readiness", return_value=(False, "installed, not logged in  ->  codex login")), \
                mock.patch.object(cli, "_ensure_agent_skills", side_effect=AssertionError("no skills")), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(ui.Abort) as cm:
                cli._ensure_agent_ready("codex", {}, persist=False, require_creds=True)
        self.assertIn("not logged in", cm.exception.msg)
        self.assertEqual(err.getvalue(), "")                        # no warning first: one message, once


# ---------------------------------------------------------------- webui-backend#8: foreground console

class UiForegroundTest(unittest.TestCase):
    def run_ui(self, sub, st, settings=None, rotate=False, fg=None, login=None):
        ns = argparse.Namespace(ui_cmd=sub, rotate=rotate, lines=50, port=None, host=None, no_open=True)
        out = io.StringIO()
        with mock.patch.object(webui, "load_state", return_value=dict(st)), mock.patch.object(webui, "health", return_value=True), \
                mock.patch.object(webui, "stop", return_value=True) as stop, mock.patch.object(webui, "start") as start, \
                mock.patch.object(webui, "ensure_token"), mock.patch.object(webui, "url", return_value="http://127.0.0.1:7434/"), \
                mock.patch.object(webui, "running_pid", return_value=fg), mock.patch.object(cli, "_ui_login_item", return_value=login), \
                mock.patch.object(webui, "backup_file", create=True), mock.patch.object(cli.undo, "backup_file", return_value=None), \
                mock.patch.object(cli.undo, "record") as rec, contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                rc = cli.cmd_ui(ns, settings if settings is not None else {"ui": True})
            except ui.Abort as e:
                rc = ("abort", e.code, e.msg)
        return rc, out.getvalue(), stop, start, rec

    def test_token_rotation_never_restarts_the_console(self):
        rc, out, stop, start, rec = self.run_ui("token", {"port": 7434, "foreground_pid": 4242}, rotate=True, fg=4242)
        self.assertEqual(rc, 0)
        stop.assert_not_called()
        start.assert_not_called()
        self.assertNotIn("then", rec.call_args[0][3])              # and its undo does not restart it either

    def test_restart_and_stop_of_a_foreground_console(self):
        rc, out, stop, start, rec = self.run_ui("restart", {"port": 7434, "foreground_pid": 4242, "service": "launchd"}, fg=4242)
        self.assertEqual(rc[:2], ("abort", 0))
        self.assertIn("foreground", rc[2])
        stop.assert_not_called()
        start.assert_not_called()
        rc, out, stop, start, rec = self.run_ui("stop", {"port": 7434, "foreground_pid": 4242, "service": "launchd"}, fg=4242)
        self.assertEqual(rc, 0)
        self.assertNotIn("starts again at login", out)
        rec.assert_not_called()                                    # no undo that would turn it into a service

    def test_status_and_stop_trust_the_files_not_a_stale_service_key(self):
        rc, out, *_ = self.run_ui("status", {"port": 7434, "foreground_pid": 4242, "service": "launchd"}, fg=4242)
        self.assertIn("foreground (cs ui serve)", out)
        rc, out, *_ = self.run_ui("stop", {"port": 7434, "service": "launchd"}, fg=None, login=None)
        self.assertNotIn("starts again at login", out)
        rc, out, *_ = self.run_ui("stop", {"port": 7434}, fg=None, login="launchd")
        self.assertIn("starts again at login (launchd", out)


# ---------------------------------------------------------------- ops#1: runtime gate / ops#5: deps runtime

class RuntimeGateTest(unittest.TestCase):
    def setUp(self):
        self.scope = "aws-w3gate"
        undo.clear(self.scope)

    def tearDown(self):
        undo.clear(self.scope)

    def dispatch(self, *argv, mode="local"):
        calls = []
        reexec = []

        def ensure(cloud, want, settings, **kw):
            calls.append(cloud)
            return mode

        def handler(args, settings):
            calls.append(("handler", getattr(args, "undo_pick", None)))
            return 0

        with mock.patch.object(cli.deps, "ensure_runtime", side_effect=ensure), \
                mock.patch.dict(cli.HANDLERS, {"finops": handler, "undo": handler}), \
                mock.patch.object(cli.container, "choose_engine", return_value="docker"), \
                mock.patch.object(cli.container, "reexec", side_effect=lambda e, a: reexec.append(a) or 0), \
                mock.patch.object(cli.paths, "IN_CONTAINER", False), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli._dispatch(list(argv))
        return rc, calls, reexec

    def test_finops_never_needs_terraform(self):
        rc, calls, _ = self.dispatch("finops", "estimate", "aws", "--env", "w3gate", "-y")
        self.assertEqual(calls[0][0], "handler")
        rc, calls, _ = self.dispatch("finops", "report", "aws", "--env", "w3gate", "-y")
        self.assertEqual(calls[0][0], "handler")
        rc, calls, reexec = self.dispatch("finops", "cloud", "aws", "--env", "w3gate", "-y", "--runtime", "container", mode="container")
        self.assertEqual(calls, ["aws"])                            # a container user still gets the container's CLIs
        self.assertTrue(reexec)

    def test_undo_gates_by_what_the_entry_needs(self):
        undo.record(self.scope, "finops report", "delete-paths", {"paths": [str(Path(tempfile.gettempdir()) / "nothing-here")]})
        rc, calls, _ = self.dispatch("undo", "aws", "--env", "w3gate", "-y", "--auto-approve")
        self.assertEqual(len(calls), 1)                             # no runtime gate for a file delete
        self.assertEqual(calls[0][0], "handler")
        e = undo.record(self.scope, "apply aws-w3gate", "config", {"prev_cfg": {}})
        rc, calls, _ = self.dispatch("undo", "--env", "w3gate", "-y", "--auto-approve")   # no cloud typed: the entry's scope
        self.assertEqual(calls[0], "aws")
        self.assertEqual(calls[1][1][1]["id"], e["id"])             # cmd_undo reuses the picked entry
        rc, calls, reexec = self.dispatch("undo", "aws", "--env", "w3gate", "-y", "--auto-approve", mode="container")
        self.assertEqual(reexec[0][-2:], ["--id", e["id"]])         # the container undoes exactly that entry


class DepsRuntimeUndoTest(unittest.TestCase):
    def run_runtime(self, mode, settings, disk, engine=None, choose=None):
        ns = argparse.Namespace(deps_cmd="runtime", mode=mode, engine=engine)
        with mock.patch.object(cli.undo, "snapshot_settings", return_value={"settings": dict(disk), "what": ["runtime", "engine"]}), \
                mock.patch.object(cli.paths, "save_settings"), mock.patch.object(cli.undo, "record") as rec, \
                mock.patch.object(cli.container, "choose_engine", side_effect=choose or (lambda s, explicit=None: explicit or "docker")), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                cli.cmd_deps(ns, settings)
            except ui.Abort:
                pass
        return rec

    def test_only_real_changes_are_recorded(self):
        self.run_runtime("local", {"runtime": "local"}, {"runtime": "local"}).assert_not_called()
        rec = self.run_runtime("container", {"runtime": "local"}, {"runtime": "local"},
                               choose=lambda s, explicit=None: (_ for _ in ()).throw(ui.Abort("Neither docker nor podman was found.")))
        rec.assert_not_called()
        self.run_runtime("container", {"runtime": "local"}, {"runtime": "local"}, engine="podman").assert_called_once()


# ---------------------------------------------------------------- mcp#5 / #6 / #9 / #10 / #17, cli-ux#19

class McpRestoreArgvsTest(unittest.TestCase):
    def test_the_undo_brings_back_only_what_existed(self):
        self.assertEqual(cli._mcp_restore_argvs({}, {}, False), [])
        self.assertEqual(cli._mcp_restore_argvs({}, {"cursor": "stdio"}, True),
                         [["enable", "mcp"], ["mcp", "connect", "cursor", "--transport", "stdio"]])
        with mock.patch.object(cli, "_mcp_clients_wiring", return_value={"cursor": "http", "codex": "stdio"}):
            got = cli._mcp_restore_argvs({"transport": "http", "port": 7705, "service": "background"},
                                         {"cursor": "http", "codex": "stdio"}, False)
        self.assertEqual(got[0], ["mcp", "setup", "-y", "--transport", "http", "--client", "none", "--port", "7705", "--no-service"])
        self.assertIn(["mcp", "connect", "cursor", "--transport", "http"], got)
        self.assertIn(["mcp", "connect", "codex", "--transport", "stdio"], got)
        self.assertEqual(got[-1], ["disable", "mcp"])
        self.assertEqual(cli._mcp_restore_argvs({"transport": "stdio"}, {}, True),
                         [["mcp", "setup", "-y", "--transport", "stdio", "--client", "none"]])


class McpCliTest(Sandbox):
    def test_connect_on_a_fresh_home_enables_mcp_with_one_undo_point(self):
        (self.user / ".cursor").mkdir()
        rc, out = self.cs("mcp", "connect", "cursor")
        self.assertEqual(rc, 0, out)
        self.assertIn("MCP enabled", out)
        self.assertTrue(self.settings().get("mcp"))
        entries = self.journal()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["data"]["argvs"], [["mcp", "disconnect", "cursor"], ["disable", "mcp"]])

    def test_a_disabled_mcp_stays_off_and_says_so(self):
        (self.user / ".cursor").mkdir()
        (self.home / "settings.json").write_text(json.dumps({"mcp": False}))
        rc, out = self.cs("mcp", "connect", "cursor")
        self.assertEqual(rc, 0, out)
        self.assertIn("MCP is disabled", out)
        self.assertNotIn("Restart the client", out)
        self.assertFalse(self.settings().get("mcp"))
        rc, out = self.cs("mcp", "status")
        self.assertIn("connected but MCP is disabled", out)
        rc, out = self.cs("mcp", "test")
        self.assertEqual(rc, 1, out)
        self.assertIn("MCP is disabled", out)
        rc, out = self.cs("mcp", "config")
        self.assertIn("MCP is disabled", out)

    def test_an_undo_that_reconnects_a_client_leaves_mcp_as_it_was(self):
        (self.user / ".cursor").mkdir()
        rc, out = self.cs("-y", "mcp", "connect", "cursor", "--transport", "stdio", env={"CLOUDSEED_UNDOING": "1"})
        self.assertEqual(rc, 0, out)
        self.assertNotIn("MCP enabled", out)
        self.assertNotIn("mcp", self.settings())
        self.assertIn("MCP is disabled", out)

    def test_connect_and_disconnect_need_client_names_without_a_terminal(self):
        (self.user / ".cursor").mkdir()
        for sub in ("connect", "disconnect"):
            rc, out = self.cs("mcp", sub, "-y")
            self.assertEqual(rc, 2, out)
            self.assertIn(f"cs mcp {sub} <client>... | all", out)
        self.assertFalse((self.user / ".cursor" / "mcp.json").exists())
        self.assertEqual(self.journal(), [])

    def test_destroy_mcp_on_a_fresh_home_records_nothing(self):
        rc, out = self.cs("destroy", "mcp", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.journal(), [])

    def test_token_rotation_needs_an_http_deployment(self):
        rc, out = self.cs("mcp", "setup", "-y", "--transport", "stdio", "--client", "none")
        self.assertEqual(rc, 0, out)
        n = len(self.journal())
        rc, out = self.cs("mcp", "token", "--rotate")
        self.assertEqual(rc, 1, out)
        self.assertIn("Nothing to rotate", out)
        self.assertFalse((self.home / "mcp" / "token").exists())
        self.assertEqual(len(self.journal()), n)

    def test_a_refused_setup_leaves_mcp_off(self):
        rc, out = self.cs("mcp", "setup", "-y", "--transport", "http", "--host", "0.0.0.0", "--client", "none")
        self.assertEqual(rc, 2, out)
        self.assertNotIn("mcp", self.settings())


class McpHttpTestNoProxyTest(unittest.TestCase):
    def test_the_http_self_test_never_goes_through_a_proxy(self):
        class Resp:
            def __init__(self, body, sid="s1"):
                self.body, self.headers = body, {"Mcp-Session-Id": sid}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps(self.body).encode()

            def close(self):
                pass

        sent = []

        def fake_open(req, timeout):
            sent.append((req.get_method(), dict(req.header_items())))
            if req.get_method() == "DELETE":
                return Resp({})
            body = json.loads(req.data.decode())
            return Resp({"jsonrpc": "2.0", "id": body["id"], "result": {"tools": [1, 2]} if body["method"] == "tools/list" else {}})

        state = {"transport": "http", "host": "127.0.0.1", "port": 7641, "auth": "token"}
        with mock.patch.object(mcp, "enabled", return_value=True), mock.patch.object(mcp, "load_state", return_value=state), \
                mock.patch.object(mcp, "load_token", return_value="T"), mock.patch.object(mcp, "_open", side_effect=fake_open), \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("proxy-aware urlopen")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            rc = cli._mcp_test(argparse.Namespace(http=True))
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(sent[-1][0], "DELETE")                    # the test's session is ended
        self.assertEqual(sent[1][1].get("Mcp-session-id"), "s1")    # and used after initialize


class PortRangeTest(unittest.TestCase):
    def test_ports_out_of_range_are_usage_errors(self):
        for argv in (("mcp", "serve", "--http", "--port", "99999"), ("mcp", "setup", "--port", "0"), ("ui", "start", "--port", "-5"),
                     ("enable", "ui", "--port", "70000"), ("ui", "serve", "--port", "x")):
            rc, err = _parse_error(list(argv))
            self.assertEqual(rc, 2, argv)
            self.assertIn("--port", err)
        self.assertEqual(_parse("ui", "start", "--port", "7640").port, 7640)


# ---------------------------------------------------------------- cli-ux#5: width-aware -h

def _help(*argv, columns=80) -> str:
    out = io.StringIO()
    with mock.patch.dict(os.environ, {"COLUMNS": str(columns)}), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            cli.build_parser().parse_args(list(argv) + ["-h"])
        except SystemExit:
            pass
    return out.getvalue()


class HelpLayoutTest(unittest.TestCase):
    def test_help_fits_the_terminal(self):
        for argv in (("undo",), ("k8s",), ("ui",), ("mcp",), ("scan",), ("skill",), ("deps",), ("deps", "install"), ()):
            for cols in (100, 80):
                text = _help(*argv, columns=cols)
                wide = [l for l in text.splitlines() if ui.vis_len(l) > cols]
                self.assertEqual(wide, [], (argv, cols))

    def test_nothing_is_cut_mid_word_or_at_hyphens(self):
        text = _help(columns=100)
        self.assertNotRegex(text, r"status\|add-\n")
        self.assertNotRegex(text, r"\|st\n")

    def test_the_whole_description_and_the_subcommands_are_shown(self):
        text = " ".join(_help("k8s", columns=100).split())
        for part in ("untunnel closes that SSH tunnel", "Without <cloud> these act on", "Full guide: cloudseed help k8s"):
            self.assertIn(part, text)
        deps = " ".join(_help("deps", columns=100).split())
        self.assertIn("status tools, versions and credentials", deps)
        skill = " ".join(_help("skill", columns=100).split())
        self.assertIn("show print one skill", skill)
        self.assertIn("cloudseed deps install terraform", " ".join(_help("deps", "install", columns=100).split()))

    def test_every_option_the_audit_listed_has_help(self):
        p = cli.build_parser()
        sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
        want = {"k8s": ["--env"], "vpn": ["--env"], "node": ["--env", "--auto-approve", "--cloud"], "platform": ["--env", "--auto-approve", "--cloud"],
                "finops": ["--env"], "chaos": ["--env", "--auto-approve", "--cloud"], "dr": ["--env", "--auto-approve", "--cloud"],
                "scan": ["--env"], "undo": ["--env", "--auto-approve"], "apply": ["--auto-approve"], "destroy": ["--auto-approve"],
                "update-ip": ["--auto-approve"], "inventory": ["--json", "--last"], "output": ["--json"], "ui": ["--host", "--port"],
                "agentic": ["--agent", "--model", "--no-headliner"], "use": ["--model"], "model": ["--agent"], "install": ["--rebuild"]}
        for cmd, opts in want.items():
            actions = {o: a for a in sub.choices[cmd]._actions for o in a.option_strings}
            for o in opts:
                self.assertTrue(actions[o].help, (cmd, o))

    def test_pipes_keep_the_text_as_written(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=False), contextlib.redirect_stdout(out):
            os.environ.pop("COLUMNS", None)
            p = cli.build_parser()
            sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
            text = sub.choices["k8s"].format_help()
        self.assertIn("  info        cluster name/endpoint and the kubeconfig command", text)


# ---------------------------------------------------------------- cli-ux#9 / #10 / #11: menus

class _Screen:
    """Just enough of a terminal to replay a menu: rows, a cursor, scrollback."""

    def __init__(self, rows: int):
        self.rows, self.screen, self.scrollback, self.y = rows, [""] * rows, [], 0

    def feed(self, data: str) -> None:
        i = 0
        while i < len(data):
            ch = data[i]
            if ch == "\x1b":
                m = re.match(r"\x1b\[([0-9;?]*)([A-Za-z])", data[i:])
                if m:
                    arg, cmd = m.group(1), m.group(2)
                    if cmd == "A":
                        self.y = max(0, self.y - int(arg or 1))
                    elif cmd == "K":
                        self.screen[self.y] = ""
                    elif cmd == "J":
                        for r in range(self.y, self.rows):
                            self.screen[r] = ""
                    i += len(m.group(0))
                    continue
            if ch == "\n":
                if self.y == self.rows - 1:
                    self.scrollback.append(self.screen.pop(0))
                    self.screen.append("")
                else:
                    self.y += 1
            elif ch == "\r":
                pass
            else:
                self.screen[self.y] += ch
            i += 1


@unittest.skipUnless(POSIX, "needs a pty")
class MenuTest(unittest.TestCase):
    SCRIPT = ("import sys; sys.path.insert(0, %r)\n"
              "from cloudseed import ui\n"
              "opts = [('env-%%d' %% i, 'env-%%d   newest: setup' %% i, 'env-%%d' %% i) for i in range(%d)]\n"
              "k = ui.choose('Which environment?', opts)\n"
              "print('RESULT', k)\n")

    def run_menu(self, n: int, keys: bytes, rows: int = 10, term: str = "xterm") -> tuple[str, str]:
        import pty
        master, slave = pty.openpty()
        env = dict(os.environ, LINES=str(rows), COLUMNS="60", NO_COLOR="1", TERM=term)
        p = subprocess.Popen([sys.executable, "-c", self.SCRIPT % (str(ROOT), n)], env=env, stdin=slave, stdout=slave,
                             stderr=slave, start_new_session=True)
        os.close(slave)
        out = b""
        sent = False
        deadline = time.time() + 30
        try:
            while time.time() < deadline:
                r, _, _ = select.select([master], [], [], 0.1)
                if r:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out += chunk
                if not sent and (b"env-0" in out or b"choice:" in out):
                    time.sleep(0.2)
                    for k in re.findall(rb"\x1b\[.|.", keys, re.S):   # one key press at a time
                        _pty_write(master, k)
                        time.sleep(0.05)
                    sent = True
                if p.poll() is not None and not r:
                    break
        finally:
            if p.poll() is None:
                p.kill()
            p.wait(10)
            os.close(master)
        text = out.decode(errors="replace")
        m = re.search(r"RESULT (\S+)", text)
        return (m.group(1) if m else ""), text

    def test_a_menu_taller_than_the_terminal_scrolls_instead_of_piling_up(self):
        key, text = self.run_menu(14, b"\x1b[B\x1b[B\x1b[B\x1b[A\r")
        self.assertEqual(key, "env-2")
        scr = _Screen(10)
        scr.feed(text.replace("\r\n", "\n"))
        lines = [l for l in scr.scrollback + scr.screen if l.strip()]
        self.assertEqual([l for l in lines if "env-" in l and "RESULT" not in l], ["  ✔ Which environment?  ·  env-2"])
        self.assertIn("↓", text)                                    # the window says there is more below

    def test_the_answer_line_uses_the_short_answer(self):
        key, text = self.run_menu(3, b"\r")
        self.assertEqual(key, "env-0")
        self.assertIn("Which environment?  ·  env-0\n", text.replace("\r\n", "\n"))
        self.assertNotIn("·  env-0   newest", text)

    def test_term_dumb_gets_the_numbered_list_without_cursor_moves(self):
        key, text = self.run_menu(3, b"2\r", term="dumb")
        self.assertEqual(key, "env-1")
        self.assertNotIn("\x1b[", text)
        self.assertIn("type a number", text)


class DumbTerminalTest(unittest.TestCase):
    def test_prompts_and_spinners_do_not_move_the_cursor(self):
        buf = io.StringIO()
        with mock.patch.object(ui, "_DUMB", True), mock.patch.object(ui, "_isatty", return_value=True):
            ui._answered("Region", "eu-west-1", shown="  ? Region › eu-west-1", out=buf)
            with contextlib.redirect_stdout(io.StringIO()):
                sp = ui.Spinner("Waiting")
                with sp:
                    pass
        self.assertNotIn("\x1b[", buf.getvalue())
        self.assertIsNone(sp._thread)


# ---------------------------------------------------------------- cli-ux#14: did you mean

class DidYouMeanTest(unittest.TestCase):
    def test_common_mistakes_get_the_corrected_command(self):
        cases = {("aws", "setup"): "cloudseed setup aws", ("gcloud", "status", "--env", "dev"): "cloudseed status gcp --env dev",
                 ("delete", "aws"): "cloudseed destroy aws", ("teardown", "aws"): "cloudseed destroy aws",
                 ("create", "aws"): "cloudseed setup aws", ("version",): "cloudseed --version",
                 ("variables", "aws"): "cloudseed help variables aws", ("SETUP", "aws"): "cloudseed setup aws",
                 ("logs", "aws"): "cloudseed troubleshoot aws --log", ("--env", "w1", "status"): "cloudseed status --env w1"}
        for argv, want in cases.items():
            rc, err = _parse_error(list(argv))
            self.assertEqual(rc, 2, argv)
            self.assertIn(f"did you mean {want}?", err, argv)
            self.assertNotIn("Natural-language", err, argv)        # not a sentence for the agent
            self.assertNotIn('cloudseed agentic "', err, argv)
            self.assertNotIn("help topic cloudseed", err, argv)     # a corrected line needs no page pointer
        # a word that is exactly a help topic names that page (test_wave3_docs: no far-fetched did-you-mean)
        for argv, want in {("quickstart",): "cloudseed help quickstart", ("fips",): "cloudseed help fips"}.items():
            rc, err = _parse_error(list(argv))
            self.assertEqual(rc, 2, argv)
            self.assertIn(f"help topic {want}", err, argv)

    def test_a_sentence_is_not_pasted_into_the_corrected_command(self):
        rc, err = _parse_error(["create", "a", "staging", "env", "on", "gcp"])
        self.assertIn("did you mean cloudseed setup gcp?", err)
        self.assertIn('cloudseed agentic "create a staging env on gcp"', err)
        rc, err = _parse_error(["-y", "aws", "setup", "--env", "dev"])      # global options typed first are kept
        self.assertIn("did you mean cloudseed -y setup aws --env dev?", err)

    def test_single_words_get_no_agentic_advice_but_sentences_do(self):
        rc, err = _parse_error(["lisst"])
        self.assertIn("did you mean list", err)
        self.assertNotIn('cloudseed agentic "', err)
        rc, err = _parse_error(["set", "up", "aws"])
        self.assertIn('cloudseed agentic "set up aws"', err)

    def test_options_without_a_command(self):
        rc, err = _parse_error(["--verison"])
        self.assertIn("did you mean --version?", err)
        rc, err = _parse_error(["--dry-run"])
        self.assertIn("belongs to a command and goes after it", err)

    def test_install_targets_get_suggestions_and_aliases(self):
        with self.assertRaises(ui.Abort) as cm:
            cli._install_plan(["terrafrom"])
        self.assertIn("did you mean terraform?", cm.exception.msg)
        self.assertEqual(cli._install_plan(["azure", "gcp", "snowflake"]), [("tool", "az"), ("tool", "gcloud"), ("tool", "snow")])

    def test_help_topics_are_case_insensitive(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = cli.cmd_help(argparse.Namespace(topic="SETUP", cloud=None), {})
        self.assertEqual(rc, 0)
        self.assertIn("cloudseed setup", out.getvalue())


# ---------------------------------------------------------------- cli-ux#18: broken pipes

@unittest.skipUnless(POSIX, "needs pipes")
class BrokenPipeTest(Sandbox):
    def test_help_version_and_the_overview_into_a_closed_pipe(self):
        for argv in (["setup", "-h"], ["--version"], ["-h"], [], ["-y"]):
            r, w = os.pipe()
            os.close(r)                                             # the reader is gone before anything is written
            p = subprocess.run([sys.executable, CS, *argv], env=self.env, stdout=w, stderr=subprocess.PIPE, text=True,
                               stdin=subprocess.DEVNULL, timeout=60)
            os.close(w)
            self.assertEqual(p.returncode, 0, (argv, p.stderr))
            self.assertNotIn("BrokenPipeError", p.stderr, argv)
            self.assertNotIn("Exception ignored", p.stderr, argv)


# ---------------------------------------------------------------- cli-ux#20: cs list / cli-ux#22: wide text

class ListOutputTest(Sandbox):
    def test_piped_list_keeps_every_column_and_whole_paths(self):
        for i in range(2):
            d = self.home / "envs" / f"azure-production-westeurope{i}"
            d.mkdir(parents=True)
            (d / "config.json").write_text(json.dumps({"cloud": "azure", "env": f"production-westeurope{i}", "name": "averylongname",
                                                       "region": "australiasoutheast", "updated_at": "2026-09-24T10:00:00Z",
                                                       "state": {"type": "remote"}}))
        rc, out = self.cs("list")
        self.assertEqual(rc, 0, out)
        self.assertIn("UPDATED", out)
        self.assertIn(str(self.home / "envs" / "azure-production-westeurope0"), out)
        self.assertNotIn("…", out)


class WideTextTest(unittest.TestCase):
    def test_panels_and_rows_with_cjk_text_keep_their_border(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"COLUMNS": "80"}), contextlib.redirect_stdout(out):
            ui.panel("Environment aws-w1", [("Tags", "Owner=山田太郎のチーム名前がとても長い場合のテスト値です, Env=dev"),
                                            ("中文键", "全角文字" * 10), ("Working dir", "/tmp/" + "日本語フォルダ" * 8)])
            ui.kv("Tags", "Owner=山田太郎のチーム名前がとても長い場合のテスト値です" * 2)
        lines = [l for l in out.getvalue().splitlines() if l.strip()]
        self.assertTrue(all(ui.vis_len(l) <= 80 for l in lines), [l for l in lines if ui.vis_len(l) > 80])
        box = [l for l in lines if l.startswith("  │")]
        self.assertTrue(box and all(ui.vis_len(l) == 80 for l in box))
        self.assertIn("テスト値です", out.getvalue().replace("\n", "").replace(" ", "").replace("│", ""))   # wrapped, not cut

    def test_ascii_wrapping_is_unchanged(self):
        text = "a b " * 40 + "averyveryverylongwordthatneedstobesplitacrosslines"
        import textwrap
        self.assertEqual(ui._wrap(text, 30), textwrap.wrap(text, 30, break_long_words=True, break_on_hyphens=False))


# ---------------------------------------------------------------- ops: installable targets

class InstallListTest(Sandbox):
    def test_scanners_and_the_gke_plugin_are_listed(self):
        rc, out = self.cs("install", "list")
        self.assertEqual(rc, 0, out)
        for tool in ("gke-gcloud-auth-plugin", "kubescape", "trivy"):
            self.assertIn(tool, out)
        self.assertIn("cs scan on first use", out)
        self.assertIn("installed with gcloud", out)


if __name__ == "__main__":
    unittest.main()
