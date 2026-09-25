"""Regression tests for the MCP server fixes (validation, confirm gate, client-config safety, transports, cancellation,
service handling, undo scoping). Everything runs in temp dirs / on ephemeral loopback ports; nothing on this machine
(real client configs, launchd, the user's own MCP server) is touched."""
import io
import json
import os
import queue
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import mcp, paths, secrets, ui, undo  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CS = [sys.executable, str(ROOT / "bin" / "cloudseed")]


def _port(family=socket.AF_INET, host="127.0.0.1") -> int:
    """A free ephemeral port on host, chosen by the OS (bind to port 0): suites running at the same time never
    collide. OSError when host cannot be bound at all (no IPv6 loopback)."""
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _text(result: dict) -> str:
    return result["content"][0]["text"]


class _Home:
    """A throw-away $HOME for client-config tests."""

    def __enter__(self):
        self.old = {key: os.environ.get(key) for key in ("HOME", "XDG_CONFIG_HOME")}
        self.home = Path(tempfile.mkdtemp(prefix="cs-fixmcp-home-"))
        os.environ["HOME"] = str(self.home)
        os.environ["XDG_CONFIG_HOME"] = str(self.home / ".config")
        return self.home

    def __exit__(self, *exc):
        for key, value in self.old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        import shutil
        shutil.rmtree(self.home, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ validation & confirm
class ValidationAndConfirmTests(unittest.TestCase):
    env = dict(os.environ)

    def call(self, name, args):
        with mock.patch.object(mcp, "_run", side_effect=AssertionError("must not run")):
            return mcp.call_tool(name, args, self.env)

    def test_confirm_must_be_real_true(self):   # mcp#2
        for bad in ("false", "no", 1, "true"):
            r = self.call("cloudseed_apply", {"cloud": "aws", "env": "dev", "confirm": bad})
            self.assertTrue(r["isError"])
            self.assertIn("confirm", _text(r))
        r = self.call("cloudseed_apply", {"cloud": "aws", "env": "dev", "confirm": False})
        self.assertIn("confirm=true", _text(r))

    def test_boolean_flags_are_not_truthy_strings(self):   # mcp#2
        r = self.call("cloudseed_destroy", {"cloud": "aws", "purge": "false", "confirm": True})
        self.assertTrue(r["isError"]); self.assertIn("purge: expected boolean", _text(r))
        r = self.call("cloudseed_setup", {"cloud": "aws", "apply": "false", "confirm": "false"})
        self.assertTrue(r["isError"]); self.assertIn("expected boolean", _text(r))
        argv = mcp.TOOLS["cloudseed_destroy"]["argv"]({"cloud": "aws", "purge": "false", "purge_state": 1})   # defence in depth (web path)
        self.assertNotIn("--purge", argv); self.assertNotIn("--purge-state", argv)
        self.assertIn("--preview", mcp.TOOLS["cloudseed_setup"]["argv"]({"cloud": "aws", "apply": "false"}))   # a plan that keeps nothing
        self.assertIn("--plan-only", mcp.TOOLS["cloudseed_setup"]["argv"]({"cloud": "aws", "save": True}))

    def test_types_arrays_enums_unknown_keys(self):   # mcp#12
        cases = [("cloudseed_status", {"cloud": 5}, "cloud: expected string"),
                 ("cloudseed_status", {"cloud": "mcp"}, "must be one of"),          # no `status mcp` / `destroy mcp` alias through MCP
                 ("cloudseed_setup", {"cloud": "aws", "vars": "enable_kubernetes=true"}, "vars: expected object"),
                 ("cloudseed_setup", {"cloud": "aws", "tags": {"a": 1}}, "tags.a: expected string"),
                 ("cloudseed_destroy", {"cloud": "aws", "targets": "module.x", "confirm": True}, "targets: expected array"),
                 ("cloudseed_destroy", {"cloud": "aws", "targets": [""], "confirm": True}, "must not be empty"),
                 ("cloudseed_install", {"what": "terraform", "confirm": True}, "what: expected array"),
                 ("cloudseed_install", {"what": [], "confirm": True}, "needs at least 1"),
                 ("cloudseed_platform", {"action": "list", "items": "basek8s"}, "items: expected array"),
                 ("cloudseed_platform", {"action": "install", "items": ["--force"], "confirm": True}, "must not start with '-'"),
                 ("cloudseed_ssh", {"cloud": "aws", "command": ["uptime"], "confirm": True}, "command: expected string"),
                 ("cloudseed_ssh", {"cloud": "aws", "command": "-oProxyCommand=x", "confirm": True}, "must not start with '-'"),
                 ("cloudseed_helm", {"args": 5}, "args: expected string"),
                 ("cloudseed_kubectl", {"args": 'get "pods'}, "invalid arguments"),
                 ("cloudseed_node", {"action": "add", "count": "abc", "confirm": True}, "count: expected integer"),
                 ("cloudseed_node", {"action": "add", "count": 0, "confirm": True}, "must be >= 1"),
                 ("cloudseed_status", {"cloud": "aws", "bogus": 1}, "unknown argument 'bogus'"),
                 ("cloudseed_status", {}, "missing required argument 'cloud'"),
                 ("cloudseed_status", [], "arguments must be an object"),
                 ("cloudseed_skill", {"name": "nope"}, "unknown skill 'nope'"),
                 ("cloudseed_vpn", {"action": "add-user", "cloud": "aws", "name": "a;rm -rf /", "confirm": True}, "not allowed")]
        for name, args, needle in cases:
            r = self.call(name, args)
            self.assertTrue(r["isError"], (name, args))
            self.assertIn(needle, _text(r), (name, args, _text(r)))
            self.assertIn("expected:", _text(r))   # the schema hint lets an agent correct itself

    def test_integral_float_and_null_are_accepted(self):
        t = mcp.TOOLS["cloudseed_node"]
        args, err = mcp.validate_args(t, {"action": "add", "count": 2.0, "env": None, "confirm": True})
        self.assertIsNone(err); self.assertEqual(args, {"action": "add", "count": 2, "confirm": True})
        self.assertIn("2", t["argv"](args))

    def test_unknown_tool_is_a_protocol_error(self):   # mcp#12
        s = mcp.Session(self.env)
        r = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nope", "arguments": {}}}, s)
        self.assertEqual(r["error"]["code"], -32602)
        r = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"arguments": {}}}, s)
        self.assertEqual(r["error"]["code"], -32602)

    def test_setup_can_carry_confirm(self):   # mcp#3
        t = mcp.TOOLS["cloudseed_setup"]
        self.assertIsNone(mcp.validate_args(t, {"cloud": "aws", "apply": True, "confirm": True})[1])
        self.assertTrue(mcp._is_destructive(t, {"cloud": "aws", "apply": True}))
        self.assertFalse(mcp._is_destructive(t, {"cloud": "aws", "apply": True, "dry_run": True}))
        for tool in mcp.tool_list():   # every destructive tool can legally carry confirm (schemas forbid unknown keys)
            if tool["annotations"]["destructiveHint"]:
                self.assertIn("confirm", tool["inputSchema"]["properties"], tool["name"])
                self.assertEqual(tool["inputSchema"]["properties"]["confirm"]["type"], "boolean")

    def test_mutating_tools_are_marked_and_gated(self):   # mcp#1, platform-logic#13
        tools = {t["name"]: t for t in mcp.tool_list()}
        for name in ("cloudseed_update_ip", "cloudseed_provision", "cloudseed_managed", "cloudseed_scan", "cloudseed_vpn", "cloudseed_setup"):
            self.assertTrue(tools[name]["annotations"]["destructiveHint"], name)
            self.assertFalse(tools[name]["annotations"]["readOnlyHint"], name)
        for name in ("cloudseed_k8s", "cloudseed_env", "cloudseed_finops"):   # local writes: not read-only, but no confirm needed
            self.assertFalse(tools[name]["annotations"]["readOnlyHint"], name)
            self.assertFalse(tools[name]["annotations"]["destructiveHint"], name)
        for name in ("cloudseed_list", "cloudseed_status", "cloudseed_plan", "cloudseed_skill"):
            self.assertTrue(tools[name]["annotations"]["readOnlyHint"], name)
        gated = [("cloudseed_update_ip", {"cloud": "aws", "env": "dev", "allow_ip": "0.0.0.0/1,128.0.0.0/1"}),
                 ("cloudseed_provision", {"cloud": "aws"}),
                 ("cloudseed_managed", {"service": "snowflake", "args": 'sql -q "drop database prod"'}),
                 ("cloudseed_managed", {"service": "databricks", "args": "clusters delete 1234-abcd"}),
                 ("cloudseed_managed", {"service": "databricks", "args": "connect host=x"}),
                 ("cloudseed_vpn", {"action": "add-user", "cloud": "aws", "name": "alice"}),
                 ("cloudseed_vpn", {"action": "provision", "cloud": "aws"}),
                 ("cloudseed_scan", {"kind": "host"}), ("cloudseed_scan", {"kind": "all"}), ("cloudseed_scan", {"kind": "kube"}),
                 ("cloudseed_kubectl", {"args": "get secret db -o yaml"}), ("cloudseed_helm", {"args": "get values grafana"}),
                 ("cloudseed_undo", {"cloud": "aws", "env": "dev"})]
        for name, args in gated:
            r = self.call(name, args)
            self.assertTrue(r["isError"]); self.assertIn("confirm=true", _text(r), (name, args))
        m = mcp.TOOLS["cloudseed_managed"]["destructive_when"]
        for a in ("", "status", "test", "clusters list", "jobs get 1", "current-user me", "connection test"):
            self.assertFalse(m({"args": a}), a)
        for a in ("--debug clusters delete x", "clusters permanent-delete x", "secrets get-secret s k", 'sql -q "select 1"', 'get "x'):
            self.assertTrue(m({"args": a}), a)
        k = mcp.TOOLS["cloudseed_kubectl"]["destructive_when"]
        self.assertFalse(k({"args": "-n kube-system get pods"}))
        self.assertTrue(k({"args": "--unknown-flag delete pod x"}))
        for read_only in (("cloudseed_scan", {"kind": "fips"}), ("cloudseed_scan", {"kind": "reports"}), ("cloudseed_vpn", {"action": "status", "cloud": "aws"}),
                          ("cloudseed_managed", {"service": "databricks"})):
            self.assertFalse(mcp._is_destructive(mcp.TOOLS[read_only[0]], read_only[1]), read_only)
        with self.assertRaises(ValueError):   # the web console path (no schema check) cannot pick another top-level command
            mcp.TOOLS["cloudseed_managed"]["argv"]({"service": "destroy", "args": "aws"})

    def test_finops_does_not_save_by_default(self):   # mcp#13
        argv = mcp.TOOLS["cloudseed_finops"]["argv"]
        self.assertNotIn("--save", argv({"action": "estimate", "cloud": "aws", "env": "dev"}))
        self.assertIn("--save", argv({"action": "estimate", "save": True}))

    def test_ssh_command_is_one_argument(self):   # mcp#32
        cmd = "sudo sh -c 'nft list ruleset; ss -tlnp' && grep 'Failed password' /var/log/secure"
        argv = mcp.TOOLS["cloudseed_ssh"]["argv"]({"cloud": "aws", "env": "d", "command": cmd})
        self.assertEqual(argv, ["ssh", "aws", "--env", "d", "--", "-o", "BatchMode=yes", cmd])
        from cloudseed.cli import build_parser, _pull_env_from_remainder
        ns = build_parser().parse_args(argv)
        _pull_env_from_remainder(ns, "ssh_args")
        self.assertEqual(ns.env, "d")
        self.assertEqual([a for a in ns.ssh_args if a != "--"][-1], cmd)

    def test_undo_argv_needs_a_target(self):   # mcp#8
        argv = mcp.TOOLS["cloudseed_undo"]["argv"]
        self.assertEqual(argv({"list": True}), ["undo", "--list"])
        self.assertEqual(argv({"id": "20260101-000000-abcdef"}), ["undo", "--id", "20260101-000000-abcdef", "-y", "--auto-approve"])
        with self.assertRaises(ValueError):
            argv({"confirm": True})
        self.assertIn("say what to undo", _text(self.call("cloudseed_undo", {"confirm": True})))


# ------------------------------------------------------------------------------------------------ prompts & resources
class PromptAndResourceTests(unittest.TestCase):
    def test_required_prompt_arguments(self):   # mcp#25
        s = mcp.Session({})
        r = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": "teardown"}}, s)
        self.assertEqual(r["error"]["code"], -32602); self.assertIn("cloud, env", r["error"]["message"])
        r = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "prompts/get", "params": {"name": "teardown", "arguments": {"cloud": "gcp"}}}, s)
        self.assertEqual(r["error"]["code"], -32602); self.assertIn("env", r["error"]["message"])
        r = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": {"name": "create-environment", "arguments": {"cloud": 5, "env": ["x"]}}}, s)
        self.assertEqual(r["error"]["code"], -32602)
        r = mcp.handle({"jsonrpc": "2.0", "id": 4, "method": "prompts/get", "params": {"name": "create-environment", "arguments": {"cloud": "mars"}}}, s)
        self.assertEqual(r["error"]["code"], -32602)
        r = mcp.handle({"jsonrpc": "2.0", "id": 5, "method": "prompts/get", "params": {"name": "teardown", "arguments": {"cloud": "gcp", "env": "stage"}}}, s)
        self.assertIn("gcp/stage", r["result"]["messages"][0]["content"]["text"])
        r = mcp.handle({"jsonrpc": "2.0", "id": 6, "method": "prompts/get", "params": {"name": "nope"}}, s)
        self.assertEqual(r["error"]["code"], -32602)

    def test_corrupt_env_does_not_break_environments(self):   # mcp#31
        bad, good = paths.ENVS_DIR / "aws-fixmcpbroken", paths.ENVS_DIR / "aws-fixmcpgood"
        try:
            bad.mkdir(parents=True, exist_ok=True); good.mkdir(parents=True, exist_ok=True)
            (bad / "config.json").write_text("{not json")
            (good / "config.json").write_text(json.dumps({"region": "us-east-1", "ssh_public_key": "ssh-ed25519 AAAA"}))
            res = mcp.read_resource("cloudseed://environments")
            envs = {e["id"]: e for e in json.loads(res["contents"][0]["text"])}
            self.assertIn("error", envs["aws-fixmcpbroken"])
            self.assertEqual(envs["aws-fixmcpgood"]["config"]["region"], "us-east-1")
            self.assertNotIn("ssh_public_key", envs["aws-fixmcpgood"]["config"])
        finally:
            import shutil
            shutil.rmtree(bad, ignore_errors=True); shutil.rmtree(good, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ JSON-RPC framing
class FramingTests(unittest.TestCase):
    def test_handle_and_dispatch_never_crash(self):   # mcp#11
        s = mcp.Session({})
        for bad in ([1], 5, None, "x"):
            r = mcp.dispatch(bad, s)
            self.assertEqual((r[0] if isinstance(r, list) else r)["error"]["code"], -32600, bad)
        self.assertEqual(mcp.dispatch([], s)["error"]["code"], -32600)
        out = mcp.dispatch([{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                            {"jsonrpc": "2.0", "id": 2, "method": "initialize"}], s)
        self.assertEqual([o["id"] for o in out], [1, 2]); self.assertEqual(out[1]["error"]["code"], -32600)
        self.assertIsNone(mcp.dispatch([{"jsonrpc": "2.0", "method": "notifications/initialized"}], s))
        self.assertEqual(mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "ping", "params": [1]}, s)["error"]["code"], -32602)
        self.assertIsNone(mcp.handle({"jsonrpc": "2.0", "id": 4, "result": {}}, s))   # a client response

    def test_stdio_batches_and_garbage(self):   # mcp#11
        lines = ['[{"jsonrpc":"2.0","id":1,"method":"ping"}]', "5", "null", "{bad", "[]", '{"jsonrpc":"2.0","id":2,"method":"ping"}']
        p = subprocess.run(CS + ["mcp", "serve"], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, CLOUDSEED_MCP_FORCE="1"))
        self.assertEqual(p.returncode, 0, p.stderr)
        out = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
        self.assertEqual(len(out), 6, p.stdout)
        self.assertEqual(out[0][0]["id"], 1)
        self.assertEqual([o["error"]["code"] for o in out[1:5]], [-32600, -32600, -32700, -32600])
        self.assertEqual(out[5]["id"], 2)


# ------------------------------------------------------------------------------------------------ cancellation, progress, timeouts
class _FakeLauncher:
    """Replaces `cloudseed` with a python child that prints the pid of a grandchild `sleep` and waits."""
    CODE = "import subprocess,time; p=subprocess.Popen(['sleep','60']); print(p.pid, flush=True); time.sleep(60)"

    def __call__(self):
        return [sys.executable, "-c", self.CODE]


def _gone(pid, within=10.0) -> bool:
    end = time.time() + within
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.1)
    return False


def _interactive_sigint(test: unittest.TestCase) -> None:
    """Give the test the Ctrl-C of an interactive terminal. A runner started in the background by a non-interactive
    shell (`python -m unittest ... &`) ignores SIGINT, and every process it starts inherits that, so no interrupt or
    cancel could reach anything - whatever the code under test does."""
    old = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    test.addCleanup(signal.signal, signal.SIGINT, old if old is not None else signal.SIG_DFL)


class CancellationTests(unittest.TestCase):
    def setUp(self):
        _interactive_sigint(self)       # a cancel is a SIGINT to the tool's process group

    def _start_call(self, session, rid, notes):
        out = {}
        req = {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": "cloudseed_list", "arguments": {}, "_meta": {"progressToken": "tok"}}}
        th = threading.Thread(target=lambda: out.__setitem__("r", mcp.handle(req, session, notes.append)), daemon=True)
        th.start()
        end = time.time() + 15
        while time.time() < end and not any(str(n["params"]["message"]).isdigit() for n in notes):
            time.sleep(0.05)
        pids = [int(n["params"]["message"]) for n in notes if str(n["params"]["message"]).isdigit()]
        self.assertTrue(pids, f"no progress notification: {notes}")
        return th, out, pids[-1]

    def test_cancel_interrupts_the_whole_process_group(self):   # mcp#10
        with mock.patch.object(mcp, "_launcher", _FakeLauncher()), mock.patch.object(mcp, "PROGRESS_EVERY", 0.2):
            s = mcp.Session(dict(os.environ))
            notes: list = []
            th, out, grandchild = self._start_call(s, 42, notes)
            self.assertEqual(notes[0]["method"], "notifications/progress"); self.assertEqual(notes[0]["params"]["progressToken"], "tok")
            self.assertEqual([n["params"]["progress"] for n in notes], sorted({n["params"]["progress"] for n in notes}))
            self.assertIsNone(mcp.handle({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 42}}, s))
            th.join(20)
            self.assertFalse(th.is_alive())
            self.assertIsNone(out["r"])                 # no response for a cancelled request
            self.assertTrue(_gone(grandchild), "the terraform-like grandchild survived the cancel")
            self.assertFalse(s.busy())

    def test_timeout_interrupts_and_reports(self):   # mcp#10
        with mock.patch.object(mcp, "_launcher", _FakeLauncher()), mock.patch.object(mcp, "PROGRESS_EVERY", 0.2), \
                mock.patch.object(mcp, "TOOL_TIMEOUT", 1), mock.patch.object(mcp, "INTERRUPT_GRACE", 5):
            started = time.time()
            r = mcp.call_tool("cloudseed_list", {}, dict(os.environ))
            self.assertLess(time.time() - started, 20)
            self.assertTrue(r["isError"]); self.assertIn("timed out", _text(r))

    def test_stdio_answers_pings_during_a_call_and_honours_cancel(self):   # mcp#10
        r_in, w_in = os.pipe()
        r_out, w_out = os.pipe()
        fake_in, fake_out = SimpleNamespace(buffer=os.fdopen(r_in, "rb")), SimpleNamespace(buffer=os.fdopen(w_out, "wb"))
        lines: queue.Queue = queue.Queue()
        reader = os.fdopen(r_out, "rb")
        threading.Thread(target=lambda: [lines.put(json.loads(x)) for x in iter(reader.readline, b"")], daemon=True).start()
        writer = os.fdopen(w_in, "wb")

        def send(obj):
            writer.write((json.dumps(obj) + "\n").encode()); writer.flush()

        with mock.patch.object(sys, "stdin", fake_in), mock.patch.object(sys, "stdout", fake_out), \
                mock.patch.object(mcp, "_launcher", _FakeLauncher()), mock.patch.dict(os.environ, {"CLOUDSEED_MCP_FORCE": "1"}):
            srv = threading.Thread(target=mcp.serve, daemon=True)
            srv.start()
            send({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cloudseed_list", "arguments": {}}})
            time.sleep(0.5)
            send({"jsonrpc": "2.0", "id": 2, "method": "ping"})
            self.assertEqual(lines.get(timeout=10)["id"], 2)          # answered while the call runs
            send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1, "reason": "user"}})
            send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
            self.assertEqual(lines.get(timeout=20)["id"], 3)          # the cancelled call (id 1) never answers
            writer.close()
            srv.join(20)
            self.assertFalse(srv.is_alive())
        fake_out.buffer.close()
        fake_in.buffer.close()
        time.sleep(0.2)
        self.assertTrue(lines.empty())
        reader.close()


# ------------------------------------------------------------------------------------------------ stdio shutdown
class StdioSignalTests(unittest.TestCase):
    def test_server_exit_does_not_kill_a_running_command(self):   # mcp#10 / mcp#15
        """A client that closes the server (SIGTERM) mid-call must not break the command's output channel: with a pipe the
        cloudseed child died of EPIPE and its terraform grandchild of SIGPIPE, halfway through an apply."""
        d = Path(tempfile.mkdtemp(prefix="cs-fixmcp-survive-"))
        marker, child, srv = d / "marker", d / "child.py", d / "srv.py"
        child.write_text("import subprocess, sys\n"
                         "gc = subprocess.Popen([sys.executable, '-c', 'import time\\nfor i in range(8):\\n    print(i, flush=True); time.sleep(0.25)'], stdout=subprocess.PIPE, text=True)\n"
                         "for line in gc.stdout:\n    print('relay', line.strip(), flush=True)\n"
                         "open(sys.argv[1], 'w').write(str(gc.wait()))\n")
        srv.write_text(f"import sys\nsys.path.insert(0, {str(ROOT)!r})\nfrom cloudseed import mcp\n"
                       f"mcp._launcher = lambda: [sys.executable, {str(child)!r}]\n"
                       f"mcp.TOOLS['cloudseed_list']['argv'] = lambda a: [{str(marker)!r}]\nsys.exit(mcp.serve())\n")
        p = subprocess.Popen([sys.executable, str(srv)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=dict(os.environ, CLOUDSEED_MCP_FORCE="1"))
        try:
            p.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cloudseed_list","arguments":{}}}\n')
            p.stdin.flush()
            time.sleep(1.0)
            self.assertFalse(marker.exists())
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=20)
            for _ in range(150):
                if marker.exists():
                    break
                time.sleep(0.1)
            self.assertTrue(marker.exists(), "the running command died with the server")
            self.assertEqual(marker.read_text(), "0")
        finally:
            if p.poll() is None:
                p.kill()
            for f in (p.stdin, p.stdout, p.stderr):
                f.close()

    def _sigterm_session(self, force_file: bool) -> None:
        """Start a real stdio server, wait for its parked-credentials session (the unix-socket broker dir by default,
        the 0600 session file when no socket can be used), SIGTERM the server and require the session to be gone."""
        marker = "FAKEsecretFIXMCP" + str(os.getpid())
        env = dict(os.environ, CLOUDSEED_MCP_FORCE="1", AWS_SECRET_ACCESS_KEY=marker)
        cmd = CS + ["mcp", "serve"]
        if force_file:
            cmd = [sys.executable, "-c", f"import sys\nsys.path.insert(0, {str(ROOT)!r})\nfrom cloudseed import secrets, cli\n"
                                         "secrets._start_broker = lambda parked: None\nsys.exit(cli.main(['mcp', 'serve']))\n"]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            found = None
            for _ in range(100):
                for f in secrets.SESSIONS_DIR.glob("*.json"):
                    try:
                        if marker in f.read_text():
                            found = f
                    except OSError:
                        pass
                if not force_file:
                    for base in {tempfile.gettempdir(), "/tmp"}:
                        for d in Path(base).glob(f"{secrets._TMP_PREFIX}{p.pid}-*"):
                            if (d / "s").exists():
                                found = d
                if found:
                    break
                time.sleep(0.1)
            self.assertIsNotNone(found, "the parked-credentials session never appeared")
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=20)
            self.assertFalse(found.exists(), "SIGTERM left the parked credentials behind")
        finally:
            if p.poll() is None:
                p.kill()
            for s in (p.stdin, p.stdout, p.stderr):
                s.close()

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "unix sockets")
    def test_sigterm_removes_parked_credentials(self):   # mcp#15 (session broker socket)
        self._sigterm_session(force_file=False)

    def test_sigterm_removes_parked_credentials_file(self):   # mcp#15 (file fallback: plaintext on disk)
        self._sigterm_session(force_file=True)


# ------------------------------------------------------------------------------------------------ http transport
class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._force = os.environ.get("CLOUDSEED_MCP_FORCE")
        os.environ["CLOUDSEED_MCP_FORCE"] = "1"
        cls.port = _port()
        cls.token = mcp.ensure_token()
        cls.state = {"transport": "http", "host": "127.0.0.1", "port": cls.port, "auth": "token"}
        with redirect_stderr(io.StringIO()):   # (a thread is no service: it says where it listens, before it answers)
            threading.Thread(target=mcp.serve_http, args=("127.0.0.1", cls.port, True), daemon=True).start()
            for _ in range(100):
                if mcp.health(cls.state):
                    break
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):   # the servers keep running (daemon threads); only stop leaking the switch into later tests
        if cls._force is None:
            os.environ.pop("CLOUDSEED_MCP_FORCE", None)

    def raw(self, data: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as c:
            c.sendall(data)
            buf = b""
            try:
                while True:
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            except socket.timeout:
                pass
            return buf

    def post(self, body, headers=None, raw_body=None):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        h.update(headers or {})
        c.request("POST", "/mcp", body=raw_body if raw_body is not None else json.dumps(body), headers=h)
        r = c.getresponse()
        data = r.read().decode()
        c.close()
        return r.status, dict(r.getheaders()), data

    def test_backlog(self):   # mcp#9
        self.assertGreaterEqual(mcp._HTTPServer.request_queue_size, 128)
        errors: list = []

        def ping():
            try:
                st, _, _ = self.post({"jsonrpc": "2.0", "id": 1, "method": "ping"})
                if st != 200:
                    errors.append(st)
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
        ths = [threading.Thread(target=ping) for _ in range(48)]
        for t in ths:
            t.start()
        for t in ths:
            t.join(30)
        self.assertEqual(errors, [])

    def test_batches_and_bad_payloads(self):   # mcp#11
        st, _, body = self.post([{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
        self.assertEqual(st, 200); self.assertEqual([m["id"] for m in json.loads(body)], [1, 2])
        self.assertEqual(self.post([{"jsonrpc": "2.0", "method": "notifications/initialized"}])[0], 202)
        st, _, body = self.post(5)
        self.assertEqual(st, 400); self.assertEqual(json.loads(body)["error"]["code"], -32600)
        st, _, body = self.post(None, raw_body="{bad")
        self.assertEqual(st, 400); self.assertEqual(json.loads(body)["error"]["code"], -32700)

    def test_transport_robustness(self):   # mcp#30
        self.assertEqual(self.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"Authorization": f"bearer {self.token}"})[0], 200)
        self.assertEqual(self.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"Content-Type": "text/plain", "Origin": "http://localhost:3000"})[0], 415)
        self.assertEqual(self.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"Content-Type": "application/x-www-form-urlencoded"})[0], 415)
        auth = f"Authorization: Bearer {self.token}\r\n".encode()
        resp = self.raw(b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n" + auth + b"Content-Length: abc\r\n\r\n{}")
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        body = b'{"jsonrpc":"2.0","id":7,"method":"ping"}'
        chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        resp = self.raw(b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nConnection: close\r\n" + auth + b"Transfer-Encoding: chunked\r\n\r\n" + chunked)
        self.assertTrue(resp.startswith(b"HTTP/1.1 200"), resp[:80]); self.assertIn(b'"id": 7', resp)
        # 401 closes the connection: an unread body is never parsed as the next request
        resp = self.raw(b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\n\r\n12345678")
        self.assertEqual(resp.count(b"HTTP/1.1 "), 1, resp)

    def test_sessions_do_not_leak(self):   # mcp#30
        before = len(mcp._State.sessions)
        for _ in range(5):
            self.assertIsNotNone(mcp.health(self.state))
        self.assertLessEqual(len(mcp._State.sessions), before)
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("DELETE", "/mcp", headers={"Authorization": f"Bearer {self.token}", "Mcp-Session-Id": "nope"})
        self.assertEqual(c.getresponse().status, 404)
        c.close()
        with mock.patch.object(mcp, "MAX_SESSIONS", 3):
            for i in range(10):
                mcp._session_add(f"fix-{i}", mcp.Session({}))
            self.assertLessEqual(len([k for k in mcp._State.sessions if k.startswith("fix-")]), 3)
        for k in [k for k in mcp._State.sessions if k.startswith("fix-")]:
            mcp._session_drop(k)

    def test_http_cancel_and_progress_over_sse(self):   # mcp#10
        with mock.patch.object(mcp, "_launcher", _FakeLauncher()), mock.patch.object(mcp, "PROGRESS_EVERY", 0.2):
            st, hdr, _ = self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
            sid = hdr["Mcp-Session-Id"]
            import http.client
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
            c.request("POST", "/mcp", body=json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "cloudseed_list", "arguments": {}, "_meta": {"progressToken": 5}}}),
                      headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}", "Accept": "application/json, text/event-stream", "Mcp-Session-Id": sid})
            r = c.getresponse()
            first = b""
            while b"notifications/progress" not in first:
                first += r.readline()
            self.assertIn(b'"progressToken": 5', first)
            self.assertEqual(self.post({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}}, {"Mcp-Session-Id": sid})[0], 202)
            rest = r.read()
            c.close()
            self.assertNotIn(b'"id": 9', rest)    # cancelled: the stream ends without a result

    def test_ipv6_loopback(self):   # mcp#22
        try:
            port = _port(socket.AF_INET6, "::1")
        except OSError:
            self.skipTest("no IPv6 loopback")
        self.assertIs(mcp.server_class("::1"), mcp._HTTPServer6)
        self.assertEqual(mcp.url({"host": "::1", "port": port}), f"http://[::1]:{port}/mcp")
        self.assertIsNone(mcp.host_problem("::1")); self.assertIsNotNone(mcp.host_problem("0.0.0.0"))
        st = {"transport": "http", "host": "::1", "port": port, "auth": "token"}
        with redirect_stderr(io.StringIO()):   # (the foreground line of a thread that is no service)
            threading.Thread(target=mcp.serve_http, args=("::1", port, True), daemon=True).start()
            for _ in range(100):
                if mcp.health(st):
                    break
                time.sleep(0.05)
        self.assertIsNotNone(mcp.health(st))


# ------------------------------------------------------------------------------------------------ service pid handling
class PidTests(unittest.TestCase):
    def test_stale_pid_file_never_kills_another_process(self):   # mcp#6
        victim = subprocess.Popen(["sleep", "30"])
        try:
            mcp.MCP_DIR.mkdir(parents=True, exist_ok=True)
            mcp.PID_PATH.write_text(str(victim.pid))
            self.assertIsNone(mcp.running_pid())
            with mock.patch.object(mcp, "_launchd_plist", return_value=Path("/nonexistent/x.plist")), \
                    mock.patch.object(mcp, "_systemd_unit", return_value=Path("/nonexistent/x.service")):
                self.assertFalse(mcp.stop({}))
            self.assertIsNone(victim.poll(), "stop() killed an unrelated process")
            self.assertFalse(mcp.PID_PATH.exists(), "stale pid file kept")
        finally:
            victim.kill(); victim.wait()

    def test_stop_finds_and_stops_the_real_server(self):   # mcp#6
        port = _port()
        env = dict(os.environ, CLOUDSEED_MCP_FORCE="1")
        p = subprocess.Popen(CS + ["mcp", "serve", "--http", "--host", "127.0.0.1", "--port", str(port)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        st = {"transport": "http", "host": "127.0.0.1", "port": port, "auth": "token", "service": "background"}
        try:
            for _ in range(100):
                if mcp.alive(st) and mcp.running_pid() == p.pid:
                    break
                time.sleep(0.1)
            self.assertEqual(mcp.running_pid(), p.pid)
            mcp.PID_PATH.unlink()   # even a lost pid file: /health names the pid of this home's server
            with mock.patch.object(mcp, "_launchd_plist", return_value=Path("/nonexistent/x.plist")), \
                    mock.patch.object(mcp, "_systemd_unit", return_value=Path("/nonexistent/x.service")):
                self.assertTrue(mcp.stop(st))
            p.wait(timeout=20)
            self.assertIsNone(mcp.alive(st))
        finally:
            if p.poll() is None:
                p.kill(); p.wait()


# ------------------------------------------------------------------------------------------------ client configs
class ClientConfigTests(unittest.TestCase):
    JSONC = ('{\n  // my servers\n  "servers": {\n    "other": {"type": "http", "url": "https://example.com/mcp"}, // keep\n  },\n'
             '  /* inputs */ "inputs": [ {"id": "x", "type": "promptString", "description": "a // b"}, ],\n}\n')

    def test_jsonc_config_is_merged_not_wiped(self):   # mcp#0
        with _Home():
            path = mcp.CLIENTS["vscode"]["path"]()
            path.parent.mkdir(parents=True)
            path.write_text(self.JSONC)
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                msg = mcp.connect("vscode", "stdio", None)
            self.assertIn("(stdio)", msg); self.assertIn("previous version", msg)
            data = json.loads(path.read_text())
            self.assertEqual(data["servers"]["other"]["url"], "https://example.com/mcp")
            self.assertEqual(data["inputs"][0]["description"], "a // b")
            self.assertIn("cloudseed", data["servers"])
            self.assertEqual(mcp.connected("vscode"), "stdio")
            backups = list(mcp.BACKUPS_DIR.glob("vscode-*"))
            self.assertTrue(any(b.read_text() == self.JSONC for b in backups))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_jsonc_disconnect_and_connected(self):   # mcp#0
        with _Home():
            path = mcp.CLIENTS["vscode"]["path"]()
            path.parent.mkdir(parents=True)
            path.write_text(self.JSONC.replace('"other"', '"cloudseed": {"command": "x"},\n    "other"'))
            self.assertEqual(mcp.connected("vscode"), "stdio")
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertIsNotNone(mcp.disconnect("vscode"))
            data = json.loads(path.read_text())
            self.assertNotIn("cloudseed", data["servers"]); self.assertIn("other", data["servers"]); self.assertIn("inputs", data)

    def test_gemini_comments_and_settings_survive(self):   # mcp#0
        with _Home() as home:
            path = home / ".gemini" / "settings.json"
            path.parent.mkdir()
            path.write_text('{\n  // auth\n  "security": {"auth": {"selectedType": "oauth-personal"}},\n  "theme": "Dracula",\n  "mcpServers": {"other": {"command": "o"}}\n}\n')
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                mcp.connect("gemini", "stdio", None)
            data = json.loads(path.read_text())
            self.assertEqual(data["security"]["auth"]["selectedType"], "oauth-personal"); self.assertEqual(data["theme"], "Dracula")
            self.assertIn("other", data["mcpServers"])
            self.assertEqual(data["mcpServers"]["cloudseed"]["timeout"], mcp.CLIENT_TIMEOUT_SEC * 1000)

    def test_unparseable_or_odd_layout_is_never_overwritten(self):   # mcp#0
        with _Home() as home:
            path = home / ".cursor" / "mcp.json"
            path.parent.mkdir()
            for content in ('{"mcpServers": {"other": {"command": "o"}', "[1, 2]", '{"mcpServers": ["x"]}', '{"mcpServers": {"a": 1} /* open'):
                path.write_text(content)
                with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                    with self.assertRaises(ui.Abort):
                        mcp.connect("cursor", "stdio", None)
                    self.assertIsNone(mcp.disconnect("cursor"))
                self.assertIsNone(mcp.connected("cursor"))
                self.assertEqual(path.read_text(), content)

    def test_idempotent_symlink_and_private_mode(self):   # mcp#0, mcp#16
        with _Home() as home:
            real = home / "dotfiles" / "cursor-mcp.json"
            real.parent.mkdir()
            real.write_text('{"mcpServers": {"keep": {"command": "z"}}}')
            os.chmod(real, 0o644)
            (home / ".cursor").mkdir()
            link = home / ".cursor" / "mcp.json"
            link.symlink_to(real)
            state = {"transport": "http", "host": "127.0.0.1", "port": 7719, "auth": "token"}
            mcp.ensure_token()
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                mcp.connect("cursor", "http", state)
                self.assertTrue(link.is_symlink())
                self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o600)
                self.assertIn("Authorization", json.loads(real.read_text())["mcpServers"]["cloudseed"]["headers"])
                n = len(list(mcp.BACKUPS_DIR.glob("cursor-*")))
                self.assertIn("already up to date (http)", mcp.connect("cursor", "http", state))
                self.assertEqual(len(list(mcp.BACKUPS_DIR.glob("cursor-*"))), n)
                (home / ".codex").mkdir()
                mcp.connect("codex", "http", state)
                self.assertEqual(stat.S_IMODE((home / ".codex" / "config.toml").stat().st_mode), 0o600)

    def test_stdio_registrations_pin_home_and_timeouts(self):   # mcp#24, mcp#10
        with _Home() as home:
            calls = []

            def fake_run(argv, **kw):
                calls.append(argv)
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            with mock.patch.object(mcp.shutil, "which", return_value="/usr/bin/claude"), mock.patch.object(mcp.subprocess, "run", side_effect=fake_run):
                mcp.connect("claude-code", "stdio", None)
            add = [c for c in calls if c[:3] == ["claude", "mcp", "add"]][0]
            name_at, sep = add.index("cloudseed"), add.index("--")
            env_pairs = [add[i + 1] for i in range(name_at, sep) if add[i] == "-e"]
            self.assertGreater(add.index("-e"), name_at)
            self.assertIn(f"CLOUDSEED_HOME={paths.HOME.resolve()}", env_pairs)
            self.assertTrue(any(p.startswith("PATH=") for p in env_pairs))
            (home / ".codex").mkdir()
            with redirect_stdout(io.StringIO()):
                mcp.connect("codex", "stdio", None)
            toml = (home / ".codex" / "config.toml").read_text()
            head, _, env_table = toml.partition("[mcp_servers.cloudseed.env]")
            self.assertIn("tool_timeout_sec = 3600", head)
            self.assertIn("CLOUDSEED_HOME = ", env_table)
            self.assertIn("tool_timeout_sec = 3600", mcp._toml_section({"host": "127.0.0.1", "port": 7719, "auth": "none"}, "http"))
            snippet = [v for k, v in mcp.client_configs(None).items() if k.startswith("Claude Code")][0]
            self.assertIn("-e ", snippet); self.assertIn("CLOUDSEED_HOME=", snippet)


# ------------------------------------------------------------------------------------------------ undo scoping
class UndoScopeTests(unittest.TestCase):
    SCOPES = ("aws-fixmcpa", "gcp-fixmcpa")

    def setUp(self):
        self.saved = ui.NON_INTERACTIVE
        self._clean()

    def tearDown(self):
        ui.NON_INTERACTIVE = self.saved
        self._clean()

    def _clean(self):
        for s in self.SCOPES:
            undo.clear(s)
        for e in undo.entries(undo.GLOBAL):
            if e["summary"].startswith("fixmcp"):
                undo.pop(e)

    def cs(self, *argv, agent=None):
        from cloudseed import cli
        env = {"CLOUDSEED_AGENT": agent} if agent else {}
        with mock.patch.dict(os.environ, env), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            if not agent:
                os.environ.pop("CLOUDSEED_AGENT", None)
            rc = cli.main(list(argv))
        return rc, out.getvalue() + err.getvalue()

    def ids(self, scope):
        return [e["id"] for e in undo.entries(scope)]

    def test_global_row_undoes_only_the_global_entry(self):   # webui-backend#0
        g = undo.record(undo.GLOBAL, "fixmcp global change", "info", {"advice": "nothing"})
        time.sleep(1.1)
        e = undo.record("aws-fixmcpa", "fixmcp env change", "info", {"advice": "nothing"})
        rc, out = self.cs("undo", "--global", "-y", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertNotIn(g["id"], self.ids(undo.GLOBAL)); self.assertIn(e["id"], self.ids("aws-fixmcpa"))
        from cloudseed import webui
        self.assertEqual(webui.build_argv("cloudseed_undo", {"id": e["id"], "confirm": True}), ["undo", "--id", e["id"], "-y", "--auto-approve"])
        rc, out = self.cs("undo", "--id", e["id"], "-y", "--auto-approve")
        self.assertEqual(rc, 0, out); self.assertEqual(self.ids("aws-fixmcpa"), [])

    def test_id_must_be_the_newest_of_its_scope(self):   # webui-backend#0
        e1 = undo.record("aws-fixmcpa", "fixmcp one", "info", {"advice": "x"})
        time.sleep(1.1)
        e2 = undo.record("aws-fixmcpa", "fixmcp two", "info", {"advice": "x"})
        rc, out = self.cs("undo", "--id", e1["id"], "-y", "--auto-approve")
        self.assertNotEqual(rc, 0); self.assertIn("newer action", out)
        self.assertEqual(self.ids("aws-fixmcpa"), [e1["id"], e2["id"]])
        rc, out = self.cs("undo", "--id", "no-such-id", "-y", "--auto-approve")
        self.assertNotEqual(rc, 0)

    def test_agents_never_undo_global_entries(self):   # mcp#8
        e = undo.record("aws-fixmcpa", "fixmcp env change", "info", {"advice": "x"})
        time.sleep(1.1)
        g = undo.record(undo.GLOBAL, "fixmcp mcp setup", "info", {"advice": "x"})
        rc, out = self.cs("undo", "--global", "-y", "--auto-approve", agent="mcp")
        self.assertEqual(rc, 2); self.assertIn(g["id"], self.ids(undo.GLOBAL))
        rc, out = self.cs("undo", "--id", g["id"], "-y", "--auto-approve", agent="mcp")
        self.assertEqual(rc, 2); self.assertIn(g["id"], self.ids(undo.GLOBAL))
        rc, out = self.cs("undo", "-y", "--auto-approve", agent="mcp")   # newest overall is global: skipped for agents
        self.assertEqual(rc, 0, out)
        self.assertIn(g["id"], self.ids(undo.GLOBAL)); self.assertNotIn(e["id"], self.ids("aws-fixmcpa"))

    def test_env_without_cloud_never_widens_to_other_scopes(self):   # mcp#8 / webui-backend#0 related
        undo.record("aws-fixmcpa", "fixmcp a", "info", {"advice": "x"})
        undo.record("gcp-fixmcpa", "fixmcp b", "info", {"advice": "x"})
        g = undo.record(undo.GLOBAL, "fixmcp g", "info", {"advice": "x"})
        rc, out = self.cs("undo", "--env", "fixmcpa", "-y", "--auto-approve")
        self.assertEqual(rc, 2); self.assertIn("Several environments", out)
        self.assertIn(g["id"], self.ids(undo.GLOBAL))
        self.assertEqual(len(self.ids("aws-fixmcpa")) + len(self.ids("gcp-fixmcpa")), 2)
        undo.clear("gcp-fixmcpa")
        rc, out = self.cs("undo", "--env", "fixmcpa", "-y", "--auto-approve")   # now unambiguous
        self.assertEqual(rc, 0, out); self.assertEqual(self.ids("aws-fixmcpa"), []); self.assertIn(g["id"], self.ids(undo.GLOBAL))


if __name__ == "__main__":
    unittest.main()
