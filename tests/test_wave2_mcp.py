"""Wave-2 regression tests for cloudseed/mcp.py: the cross-group handoffs (tool schemas and descriptions that match the
CLI, the undo tool's drop, bounds, the kubectl/helm Secret gate, the platform groups, per-call credential freshness,
the background start's pid handling, non-UTF-8 subprocess output). Stdlib only, no network, temp dirs; the only port
used is an ephemeral loopback one."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import creds, mcp, secrets, undo, webui  # noqa: E402
from cloudseed import platform as catalog  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _text(result: dict) -> str:
    return result["content"][0]["text"]


def _call(name: str, args: dict) -> dict:
    """call_tool without running anything: returns the tool result, or {'argv': [...]} when it would have run."""
    ran = {}

    def fake_run(_name, argv, _env, call=None, progress=None):
        ran["argv"] = argv
        return mcp._result("ran", False)
    with mock.patch.object(mcp, "_run", side_effect=fake_run):
        res = mcp.call_tool(name, args, {})
    return ran if ran else res


class SchemaHandoffTests(unittest.TestCase):
    def props(self, tool):
        return mcp.TOOLS[tool]["schema"]["properties"]

    def test_destroy_fields_are_explained(self):                       # webui-visual#32, vmware#23
        p = self.props("cloudseed_destroy")
        self.assertIn("empty = everything", p["targets"]["description"])
        self.assertIn("irreversible", p["purge_state"]["description"])
        self.assertIn("state bucket", p["purge_state"]["description"])
        self.assertIn("undo journal", p["purge"]["description"])      # purge is undoable (config + SSH keys), VPN keys are not
        self.assertIn("VPN keys are not", p["purge"]["description"])
        self.assertNotIn("irreversible", p["purge"]["description"])
        desc = mcp.TOOLS["cloudseed_destroy"]["description"]
        self.assertIn("exit code 1", desc)
        self.assertIn("full destroy only", desc)
        listed = {t["name"]: t for t in mcp.tool_list()}["cloudseed_destroy"]["inputSchema"]["properties"]
        self.assertEqual(listed["purge"]["description"], p["purge"]["description"])   # what MCP clients and the console see

    def test_update_ip_says_it_is_for_cloud_targets_only(self):        # vmware#23
        desc = mcp.TOOLS["cloudseed_update_ip"]["description"]
        self.assertIn("not applicable to vmware", desc)
        self.assertTrue(mcp.TOOLS["cloudseed_update_ip"].get("destructive"))
        self.assertIn("confirm", self.props("cloudseed_update_ip"))   # webui-functional#5: gated like provision
        self.assertTrue(mcp.TOOLS["cloudseed_provision"].get("destructive"))
        # the console's env card still offers it on vmware envs: the CLI answers there with an info line (exit 0)
        self.assertIn("vmware", self.props("cloudseed_update_ip")["cloud"]["enum"])

    def test_setup_description_and_vars(self):                          # mcp#4
        self.assertIn("created first on apply", mcp.TOOLS["cloudseed_setup"]["description"])
        d = self.props("cloudseed_setup")["vars"]["description"]
        self.assertIn("refused", d)
        self.assertIn("allow_ip", d)

    def test_finops_is_read_only_unless_asked_and_days_bounded(self):   # mcp#5, ops#16, webui-functional#13
        self.assertEqual(_call("cloudseed_finops", {"action": "estimate", "cloud": "aws", "env": "dev"})["argv"],
                         ["finops", "estimate", "aws", "--env", "dev"])
        self.assertIn("--save", _call("cloudseed_finops", {"action": "estimate", "cloud": "aws", "save": True})["argv"])
        self.assertNotIn("--save", _call("cloudseed_finops", {"action": "estimate", "cloud": "aws", "save": False})["argv"])
        for bad, why in ((0, ">= 1"), (366, "<= 365")):
            r = _call("cloudseed_finops", {"action": "cloud", "cloud": "aws", "days": bad})
            self.assertTrue(r["isError"])
            self.assertIn(why, _text(r))
        self.assertIn("--days", _call("cloudseed_finops", {"action": "cloud", "cloud": "aws", "days": 365})["argv"])
        with self.assertRaises(ValueError):     # the console validates with the same rules
            webui.validate_args("cloudseed_finops", mcp.TOOLS["cloudseed_finops"], {"action": "cloud", "days": 400})

    def test_chaos_duration_matches_the_cli_bounds(self):               # resilience#17
        s = self.props("cloudseed_chaos")["duration"]
        self.assertEqual((s["minimum"], s["maximum"]), (15, 3600))
        for bad in (5, 14, 3601):
            r = _call("cloudseed_chaos", {"action": "run", "duration": bad, "confirm": True})
            self.assertTrue(r["isError"], bad)
            self.assertIn("duration", _text(r))
        argv = _call("cloudseed_chaos", {"action": "run", "items": ["basic"], "duration": 15, "confirm": True})["argv"]
        self.assertEqual(argv[argv.index("--duration") + 1], "15")
        with self.assertRaises(ValueError):
            webui.validate_args("cloudseed_chaos", mcp.TOOLS["cloudseed_chaos"], {"action": "run", "duration": 10})

    def test_node_scale(self):                                          # platform-logic#6
        p = self.props("cloudseed_node")
        self.assertIn("scale", p["action"]["enum"])
        self.assertEqual(p["count"]["minimum"], 1)
        argv = _call("cloudseed_node", {"action": "scale", "cloud": "aws", "env": "dev", "count": 3, "min": 0, "max": 5, "confirm": True})["argv"]
        self.assertEqual(argv[:3], ["node", "scale", "aws"])
        self.assertEqual(argv[argv.index("--min") + 1], "0")
        self.assertEqual(argv[argv.index("--max") + 1], "5")
        self.assertTrue(_call("cloudseed_node", {"action": "scale", "cloud": "aws", "count": 0, "confirm": True})["isError"])

    def test_vpn_and_platform_consent(self):                            # platform-logic#15, webui-backend#1
        t = mcp.TOOLS["cloudseed_vpn"]
        for action in ("add-user", "revoke", "provision"):
            self.assertTrue(mcp._is_destructive(t, {"action": action, "cloud": "aws"}), action)
        for action in ("status", "users"):
            self.assertFalse(mcp._is_destructive(t, {"action": action, "cloud": "aws"}), action)
        for bad in ("../x", "-x", "a b", "x;id", "a" * 65):
            self.assertTrue(_call("cloudseed_vpn", {"action": "add-user", "cloud": "aws", "name": bad, "confirm": True})["isError"], bad)
        for action in ("list", "status", "plan", "info"):
            self.assertNotIn("--auto-approve", _call("cloudseed_platform", {"action": action})["argv"], action)
        for action in ("install", "uninstall", "ui"):
            self.assertIn("--auto-approve", _call("cloudseed_platform", {"action": action, "items": ["basek8s"], "confirm": True})["argv"], action)


class UndoToolTests(unittest.TestCase):
    """cloudseed_undo: id and drop; never a global flag (an agent must not undo global entries: mcp#8).
    The journal lives in a throw-away CLOUDSEED_HOME shared with the real CLI children these tests start."""
    SCOPE = "aws-wave2mcp"

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="cs-w2mcp-undo-"))
        self.patches = [mock.patch.object(undo, "JOURNAL", self.home / "undo.json"), mock.patch.object(undo, "LOCK", self.home / "undo.lock"),
                        mock.patch.object(undo, "BACKUPS", self.home / "undo")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def child_env(self, agent: bool) -> dict:
        env = {k: v for k, v in os.environ.items() if k != "CLOUDSEED_AGENT"}
        env.update(CLOUDSEED_HOME=str(self.home), NO_COLOR="1")
        if agent:
            env["CLOUDSEED_AGENT"] = "mcp"
        return env

    def test_argv(self):                                                # ops#1, webui-functional#0
        argv = mcp.TOOLS["cloudseed_undo"]["argv"]
        self.assertEqual(argv({"id": "20260101-000000-abc123", "drop": True}), ["undo", "--id", "20260101-000000-abc123", "--drop", "-y", "--auto-approve"])
        self.assertEqual(argv({"cloud": "aws", "env": "dev", "drop": True}), ["undo", "aws", "--env", "dev", "--drop", "-y", "--auto-approve"])
        self.assertEqual(argv({"cloud": "aws", "list": True, "drop": True}), ["undo", "aws", "--list"])
        self.assertEqual(argv({"cloud": "aws"}), ["undo", "aws", "-y", "--auto-approve"])
        with self.assertRaises(ValueError) as cm:
            argv({"drop": True})
        self.assertIn("say what to drop", str(cm.exception))

    def test_drop_needs_confirm_and_global_is_not_offered(self):
        r = _call("cloudseed_undo", {"id": "20260101-000000-abc123", "drop": True})
        self.assertTrue(r["isError"])
        self.assertIn("confirm=true", _text(r))
        props = mcp.TOOLS["cloudseed_undo"]["schema"]["properties"]
        self.assertNotIn("global", props)
        self.assertNotIn("scope", props)
        r = _call("cloudseed_undo", {"global": True, "confirm": True})
        self.assertTrue(r["isError"])
        self.assertIn("unknown argument 'global'", _text(r))
        self.assertIn("refused", mcp.TOOLS["cloudseed_undo"]["description"])

    def test_global_entry_by_id_mcp_refused_console_allowed(self):
        """The real CLI child: over MCP (CLOUDSEED_AGENT=mcp) a global entry is refused even by id, while the console's
        {id, confirm} for the same row (no agent) runs it."""
        g = undo.record(undo.GLOBAL, "wave2mcp global toggle", "info", {"advice": "nothing"})
        r = mcp.call_tool("cloudseed_undo", {"id": g["id"], "drop": True, "confirm": True}, self.child_env(agent=True))
        self.assertTrue(r["isError"], _text(r))
        self.assertIn("can only be undone by you", _text(r))
        self.assertIn(g["id"], [e["id"] for e in undo.entries(undo.GLOBAL)])
        argv = webui.build_argv("cloudseed_undo", {"id": g["id"], "confirm": True})
        self.assertEqual(argv, ["undo", "--id", g["id"], "-y", "--auto-approve"])
        p = subprocess.run(mcp._launcher() + argv, env=self.child_env(agent=False), capture_output=True, text=True, errors="replace", timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn(g["id"], [e["id"] for e in undo.entries(undo.GLOBAL)])

    def test_env_entry_drop_over_mcp(self):
        e = undo.record(self.SCOPE, "wave2mcp step that can never succeed", "argv", {"argv": ["list"]})
        r = mcp.call_tool("cloudseed_undo", {"id": e["id"], "drop": True, "confirm": True}, self.child_env(agent=True))
        self.assertFalse(r["isError"], _text(r))
        self.assertIn("Dropped", _text(r))
        self.assertEqual(undo.entries(self.SCOPE), [])


class ReadGateTests(unittest.TestCase):                                 # mcp#14, platform-logic#4
    def kubectl(self, args):
        return mcp._is_destructive(mcp.TOOLS["cloudseed_kubectl"], {"args": args})

    def helm(self, args):
        return mcp._is_destructive(mcp.TOOLS["cloudseed_helm"], {"args": args})

    def test_kubectl(self):
        for ok in ("get pods -A", "-n kube-system get pods", "--namespace=x get deploy", "-n x logs pod/a",
                   "describe secret x", "get events -A"):
            self.assertFalse(self.kubectl(ok), ok)
        # --context points kubectl at another cluster/identity of the kubeconfig: the shared reader gates it (wave 4)
        for gated in ("get secret x -o yaml", "get secrets -A", "-n kube-system get secret/x", "get configmaps,secrets",
                      "get secrets.v1 -o json", "delete ns x", "--unknown-flag get pods", "apply -f x.yaml", 'get "unbalanced',
                      "--context c -n x logs pod/a"):
            self.assertTrue(self.kubectl(gated), gated)

    def test_helm(self):
        for ok in ("list -A", "-n x list", "status r", "get notes r", "get metadata r", "repo list", "history r"):
            self.assertFalse(self.helm(ok), ok)
        for gated in ("get values r", "get all r", "get manifest r", "get hooks r", "-n x get values r", "uninstall r", "repo add x y"):
            self.assertTrue(self.helm(gated), gated)

    def test_guide_says_secret_reads_need_confirm(self):
        text = json.dumps(mcp.guide_lines(None))
        self.assertIn("kubectl get secret", text)
        self.assertIn("helm get values", text)
        self.assertNotIn("kubectl get, scan fips", text)     # the old "kubectl get ... run immediately"
        self.assertIn("get of Secrets", mcp.TOOLS["cloudseed_kubectl"]["confirm_when"])
        self.assertIn("get values/all/manifest/hooks", mcp.TOOLS["cloudseed_helm"]["confirm_when"])


class PlatformGroupTests(unittest.TestCase):                            # mcp#27
    def test_groups_come_from_the_catalog(self):
        groups = " ".join(catalog.GROUPS)
        self.assertIn(f"({groups})", mcp.TOOLS["cloudseed_platform"]["description"])
        row = dict(mcp.TOOL_GROUPS)["Kubernetes & platform"]
        self.assertIn(f"({groups})", row)
        for g in ("resilience", "chaos"):     # the two the old hand-written list missed
            self.assertIn(g, row)
        section = dict(mcp.guide_lines(None))["4. What you can ask"]
        self.assertIn(("Kubernetes & platform", row), section)

    def test_every_tool_is_in_a_guide_group(self):
        listed = " ".join(v for _, v in mcp.TOOL_GROUPS)
        for name in mcp.TOOLS:
            self.assertIn(name, listed, name)


class LiveEnvTests(unittest.TestCase):                                  # webui-backend#5
    """Vault edits reach the next tool call of a long-running server; the startup values are never handed out again."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w2mcp-"))
        self.patches = [mock.patch.object(creds, "STORE", self.tmp / "credentials.json"),
                        mock.patch.object(creds, "GCP_FILE", self.tmp / "gcp-key.json"),
                        mock.patch.dict(creds.APPLIED, clear=True), mock.patch.dict(os.environ)]
        for p in self.patches:
            p.start()
        for k in ("TS_AUTHKEY", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
            os.environ.pop(k, None)
        self.live = None

    def tearDown(self):
        if self.live is not None:
            self.live.close()
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def parked(rec) -> dict:
        handle = rec["env"]["CLOUDSEED_SESSION"]
        if handle.startswith(secrets._SOCK_PREFIX):
            return secrets._fetch_from_broker(handle) or {}
        return json.loads((secrets.SESSIONS_DIR / f"{handle}.json").read_text())["env"]

    @staticmethod
    def gone(rec) -> bool:
        handle = rec["env"]["CLOUDSEED_SESSION"]
        if handle.startswith(secrets._SOCK_PREFIX):
            return secrets._fetch_from_broker(handle) is None
        return not (secrets.SESSIONS_DIR / f"{handle}.json").exists()

    def test_vault_changes_reach_the_next_call(self):
        creds.set_("TS_AUTHKEY", "tskey-" + "OLD-0123456789")
        creds.set_("AWS_DEFAULT_REGION", "eu-west-1")
        creds.apply()                                  # what cli.main does before `mcp serve`
        self.live = mcp.LiveEnv()
        first = self.live.acquire()
        self.assertEqual(self.parked(first)["TS_AUTHKEY"], "tskey-" + "OLD-0123456789")
        self.assertNotIn("TS_AUTHKEY", first["env"])   # secrets are parked, never in the child's plain environment
        self.assertEqual(first["env"]["AWS_DEFAULT_REGION"], "eu-west-1")
        self.assertEqual(first["env"]["CLOUDSEED_AGENT"], "mcp")
        self.live.release(first)
        same = self.live.acquire()                     # nothing changed: the same session is reused
        self.assertIs(same, first)
        # the user rotates one key and removes another (web console / cs creds) while that call is still running
        creds.set_("TS_AUTHKEY", "tskey-" + "NEW-9876543210")
        creds.unset("AWS_DEFAULT_REGION")
        second = self.live.acquire()
        self.assertIsNot(second, first)
        self.assertEqual(self.parked(second)["TS_AUTHKEY"], "tskey-" + "NEW-9876543210")
        self.assertNotIn("AWS_DEFAULT_REGION", second["env"])
        self.assertFalse(self.gone(first), "a session still used by a running call was closed")
        self.live.release(same)                        # that call ends: the superseded session goes
        self.assertTrue(self.gone(first))
        self.live.release(second)
        self.assertFalse(self.gone(second), "the current session must stay for the next call")
        creds.unset("TS_AUTHKEY")
        third = self.live.acquire()
        self.assertNotIn("TS_AUTHKEY", self.parked(third))
        self.live.release(third)
        self.assertTrue(self.gone(second))
        self.live.close()
        self.assertTrue(self.gone(third))
        self.live = None

    def test_shell_exports_still_win(self):
        os.environ["AWS_PROFILE"] = "from-shell"
        creds.set_("AWS_PROFILE", "from-vault")
        creds.apply()
        self.live = mcp.LiveEnv()
        rec = self.live.acquire()
        self.assertEqual(rec["env"]["AWS_PROFILE"], "from-shell")
        self.live.release(rec)

    def test_run_uses_and_releases_a_session(self):
        self.live = mcp.LiveEnv()
        seen = {}

        def spawn(_name, _argv, env, call=None, progress=None):
            seen["env"] = env
            return mcp._result("ok", False)
        with mock.patch.object(mcp, "_spawn", side_effect=spawn):
            res = mcp._run("cloudseed_list", ["list"], self.live)
        self.assertFalse(res["isError"])
        self.assertIn("CLOUDSEED_SESSION", seen["env"])
        self.assertEqual(self.live._cur["users"], 0)
        with mock.patch.object(self.live, "acquire", side_effect=OSError("no room for the session file")):
            res = mcp._run("cloudseed_list", ["list"], self.live)
        self.assertTrue(res["isError"])
        self.assertIn("could not open the credential session", _text(res))


class _NotFound(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST

    def log_message(self, *a):
        pass


class BackgroundStartTests(unittest.TestCase):                          # mcp#7
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w2mcp-start-"))
        mdir = self.tmp / "mcp"
        mdir.mkdir()
        self.patches = [mock.patch.object(mcp, "MCP_DIR", mdir), mock.patch.object(mcp, "PID_PATH", mdir / "server.pid"),
                        mock.patch.object(mcp, "LOG_PATH", mdir / "server.log"), mock.patch.object(mcp, "STATE_PATH", mdir / "server.json"),
                        mock.patch.dict(os.environ, {"CLOUDSEED_HOME": str(self.tmp), "CLOUDSEED_MCP_FORCE": "1"})]
        for p in self.patches:
            p.start()
        self.procs = []

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _port(self) -> int:
        """A free ephemeral port chosen by the OS (bind to port 0): suites running at the same time never collide."""
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_bind_failure_fails_fast_and_keeps_the_pid_file(self):
        port = self._port()
        busy = ThreadingHTTPServer(("127.0.0.1", port), _NotFound)   # someone else's server on that port
        threading.Thread(target=busy.serve_forever, daemon=True).start()
        try:
            mcp.PID_PATH.write_text("4242424")         # the record of a server that is (for all we know) still running
            state = {"transport": "http", "host": "127.0.0.1", "port": port, "auth": "none", "service": "background"}
            started = time.time()
            self.assertEqual(mcp.start(state), "background")
            self.assertLess(time.time() - started, 9, "a child that cannot bind must not be waited on for 10 s")
            self.assertEqual(mcp.PID_PATH.read_text(), "4242424", "start() overwrote server.pid before the server answered")
            self.assertIn("Cannot listen", mcp.LOG_PATH.read_text())
        finally:
            busy.shutdown()
            busy.server_close()

    def test_a_slow_child_stays_findable(self):
        slow = [sys.executable, "-c", "import time; time.sleep(60)"]
        state = {"transport": "http", "host": "127.0.0.1", "port": 7659, "auth": "none", "service": "background"}
        spawned = []
        real_popen = subprocess.Popen

        def popen(*a, **kw):
            p = real_popen(*a, **kw)
            spawned.append(p)
            return p
        try:
            with mock.patch.object(mcp, "_serve_argv", return_value=slow), mock.patch.object(mcp, "health", return_value=None), \
                    mock.patch.object(mcp.time, "sleep"), mock.patch.object(mcp.subprocess, "Popen", side_effect=popen):
                mcp.start(dict(state))
            self.assertEqual(mcp.PID_PATH.read_text(), str(spawned[0].pid))
            # but a pid file naming a live server of ours is never replaced
            mcp.PID_PATH.write_text("31337")
            with mock.patch.object(mcp, "_serve_argv", return_value=slow), mock.patch.object(mcp, "health", return_value=None), \
                    mock.patch.object(mcp.time, "sleep"), mock.patch.object(mcp.subprocess, "Popen", side_effect=popen), \
                    mock.patch.object(mcp, "_is_our_server", return_value=True):
                mcp.start(dict(state))
            self.assertEqual(mcp.PID_PATH.read_text(), "31337")
        finally:
            for p in spawned:
                p.kill()
                p.wait()


class NonUtf8OutputTests(unittest.TestCase):                             # webui-backend#6
    def test_cmdline_of_a_process_with_non_utf8_arguments(self):
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", b"caf\xe9-\xff"])
        try:
            cmd = mcp._cmdline(p.pid)
            self.assertIsInstance(cmd, str)
            self.assertIn("time.sleep", cmd)
            self.assertFalse(mcp._is_our_server(p.pid))
        finally:
            p.kill()
            p.wait()

    def test_tool_output_with_non_utf8_bytes(self):
        script = Path(tempfile.mkdtemp(prefix="cs-w2mcp-")) / "child.py"
        script.write_text("import sys\nsys.stdout.buffer.write(b'caf\\xe9 ok\\n')\n")
        try:
            with mock.patch.object(mcp, "_launcher", return_value=[sys.executable, str(script)]):
                res = mcp._run("cloudseed_list", [], dict(os.environ))
            self.assertFalse(res["isError"], _text(res))
            self.assertIn("caf� ok", _text(res))
        finally:
            shutil.rmtree(script.parent, ignore_errors=True)


class StdioEndToEndTests(unittest.TestCase):
    """The real `cloudseed mcp serve` over stdio: the new schemas are what a client gets."""

    def test_tools_list_and_bounds_over_stdio(self):
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": mcp.PROTOCOL, "capabilities": {}, "clientInfo": {"name": "w2"}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cloudseed_chaos", "arguments": {"action": "run", "duration": 10, "confirm": True}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cloudseed_undo", "arguments": {"cloud": "aws", "drop": True}}}]
        env = dict(os.environ, CLOUDSEED_MCP_FORCE="1")
        p = subprocess.run(mcp._launcher() + ["mcp", "serve"], input="".join(json.dumps(m) + "\n" for m in msgs), env=env,
                           capture_output=True, text=True, errors="replace", timeout=120)
        out = {r["id"]: r for r in (json.loads(x) for x in p.stdout.splitlines() if x.strip())}
        tools = {t["name"]: t for t in out[2]["result"]["tools"]}
        self.assertIn("irreversible", tools["cloudseed_destroy"]["inputSchema"]["properties"]["purge_state"]["description"])
        self.assertIn("cloudseed_undo", tools["cloudseed_destroy"]["inputSchema"]["properties"]["purge"]["description"])
        self.assertIn("drop", tools["cloudseed_undo"]["inputSchema"]["properties"])
        self.assertEqual(tools["cloudseed_chaos"]["inputSchema"]["properties"]["duration"]["minimum"], 15)
        self.assertTrue(out[3]["result"]["isError"])
        self.assertIn("must be >= 15", out[3]["result"]["content"][0]["text"])
        self.assertTrue(out[4]["result"]["isError"])
        self.assertIn("confirm=true", out[4]["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
