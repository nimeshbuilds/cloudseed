"""Wave 5 (cli-b) regression tests: `vpn connect/disconnect` without a terminal use a configured sudo askpass helper
(`sudo -A`) and say when a profile made for the refused connect is kept; `help vpn` covers certificate expiry and the
no-terminal sudo rules; MCP sends structuredContent only to peers that negotiated a protocol that defines it; an
invalid saved answer of a setting that is not in use never blocks a command; `undo --list` keeps the commands of a
sequence apart; ui._wrap breaks an over-long word after a separator (clusterrole.rbac.|authorization...).
Offline, stdlib only: sudo, ssh and the MCP children are faked."""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, help as helpmod, mcp, paths, services, ui, undo, webui  # noqa: E402

import test_fix_cli_life as life  # noqa: E402  (tests/ is on sys.path under unittest discovery)

_N = [0]


def _uid(prefix: str) -> str:
    while True:
        _N[0] += 1
        name = f"{prefix}{life.RUN_ID}{_N[0]}"
        if not life._taken(name):   # not an environment an earlier run left in a reused CLOUDSEED_HOME
            return name


@contextlib.contextmanager
def _silenced():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield buf


def _env(cloud: str, vars_: dict | None = None):
    name = _uid("w5b")
    env = paths.Env(cloud, name)
    env.create_dirs()
    cfg = {"env": name, "cloud": cloud, "region": "r", "network_cidr": "10.0.0.0/16", "vars": dict(vars_ or {}),
           "workdir": str(env.dir)}
    return env, cfg


def _helper(tmp: Path, name: str = "askpass", executable: bool = True) -> str:
    p = tmp / name
    p.write_text("#!/bin/sh\necho secret\n")
    p.chmod(0o700 if executable else 0o600)
    return str(p)


# ---------------------------------------------------------------- sudo without a terminal

class AskpassTests(unittest.TestCase):
    """services#2: `sudo -n` never runs a SUDO_ASKPASS / sudo.conf helper, so a console job could not connect even
    where the user set one up for exactly that. Without a terminal, such a helper now gets the password (`sudo -A`)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="w5b-askpass-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.conf = self.tmp / "sudo.conf"

    def askpass(self, env: dict, conf: str | None = None) -> str:
        if conf is not None:
            self.conf.write_text(conf)
        with mock.patch.dict(os.environ, env), mock.patch.object(services, "_SUDO_CONF", str(self.conf)):
            if "SUDO_ASKPASS" not in env:
                os.environ.pop("SUDO_ASKPASS", None)
            return services._askpass()

    def test_the_helper_comes_from_the_variable_then_sudo_conf(self):
        helper = _helper(self.tmp)
        self.assertEqual(self.askpass({"SUDO_ASKPASS": helper}), helper)
        other = _helper(self.tmp, "conf-askpass")
        conf = f"# comment\nPath noexec /usr/libexec/sudo_noexec.so\nPath askpass {other}   # the GUI one\n"
        self.assertEqual(self.askpass({}, conf), other)
        self.assertEqual(self.askpass({"SUDO_ASKPASS": ""}, conf), other)        # empty: sudo falls back to sudo.conf
        self.assertEqual(self.askpass({"SUDO_ASKPASS": helper}, conf), helper)   # the variable wins

    def test_no_usable_helper(self):
        self.assertEqual(self.askpass({}, "Path askpass\n#Path askpass /x\n"), "")
        self.assertEqual(self.askpass({"SUDO_ASKPASS": _helper(self.tmp, "plain", executable=False)}), "")
        self.assertEqual(self.askpass({"SUDO_ASKPASS": str(self.tmp / "missing")}), "")
        self.assertEqual(self.askpass({"SUDO_ASKPASS": str(self.tmp)}), "")      # a directory is no program

    def test_the_prefix(self):
        with mock.patch.object(services.os, "geteuid", return_value=501):
            for tty, helper, want in ((True, "/h", ["sudo"]), (False, "/h", ["sudo", "-A"]), (False, "", ["sudo", "-n"])):
                with mock.patch.object(services, "_has_tty", return_value=tty), \
                        mock.patch.object(services, "_askpass", return_value=helper):
                    self.assertEqual(services._sudo(), want, (tty, helper))
        with mock.patch.object(services.os, "geteuid", return_value=0):
            self.assertEqual(services._sudo(), [])

    def test_sudo_a_output_is_captured_and_its_refusals_are_recognised(self):
        seen = {}

        def call(cmd, **kw):
            seen.update(kw)
            kw["stderr"].write("sudo: no password was provided\n")
            return 1
        with mock.patch.object(services.subprocess, "call", side_effect=call):
            rc, err = services._privileged(["sudo", "-A", "kill", "-TERM", "1"])
        self.assertEqual(rc, 1)
        self.assertIs(seen.get("stdin"), services.subprocess.DEVNULL)
        self.assertEqual(services._sudo_refusal(err)[0], "password")
        for line in ("sudo: no askpass program specified, try setting SUDO_ASKPASS",
                     "sudo: 3 incorrect password attempts"):
            self.assertEqual(services._sudo_refusal(line)[0], "password", line)
        self.assertIsNone(services._sudo_refusal("Options error: --askpass fails with 'pw.txt': No such file"))   # openvpn's


class ConnectWithoutTerminalTests(unittest.TestCase):
    def setUp(self):
        self.env, self.cfg = _env("aws")
        self.outputs = {"vpn_public_ip": "203.0.113.20", "vpn_type": "openvpn"}

    def connect(self, call, askpass="", user=None, made=None):
        seen = []

        def record(cmd, **kw):
            seen.append(list(cmd))
            return call(cmd, **kw)

        def add_user(cloud, env, cfg, outputs, name):
            made.append(name)
            p = services.vpn_dir(env) / f"{name}.ovpn"
            p.write_text("client\n")
            return p
        with mock.patch.object(services, "_running", return_value=None), \
                mock.patch.object(services, "vpn_host"), \
                mock.patch.object(services, "add_user", side_effect=add_user), \
                mock.patch.object(services, "ensure_openvpn_client", return_value="/opt/openvpn"), \
                mock.patch.object(services, "_has_tty", return_value=False), \
                mock.patch.object(services, "_askpass", return_value=askpass), \
                mock.patch.object(services.os, "geteuid", return_value=501), \
                mock.patch.object(services.subprocess, "call", side_effect=record), \
                mock.patch.object(services.time, "sleep"), _silenced() as out:
            try:
                rc, msg = services.connect(clouds.get("aws"), self.env, self.cfg, self.outputs, user), ""
            except ui.Abort as e:
                rc, msg = e.code, e.msg
        return rc, msg, seen, out.getvalue()

    @staticmethod
    def refused(line):
        def call(cmd, stderr=None, **kw):
            stderr.write(line + "\n")
            return 1
        return call

    def test_askpass_helper_is_used_and_named_when_it_gives_nothing(self):
        (services.vpn_dir(self.env) / "me.ovpn").write_text("client\n")
        rc, msg, seen, out = self.connect(self.refused("sudo: no password was provided"), askpass="/usr/local/bin/pw")
        self.assertEqual(seen[0][:3], ["sudo", "-A", "/opt/openvpn"])
        self.assertEqual(rc, 1)
        self.assertIn("askpass helper (/usr/local/bin/pw) did not supply it", msg)
        self.assertIn(f"Run it in a terminal: cs vpn connect aws --env {self.env.name}", msg)
        self.assertIn("through the askpass helper (/usr/local/bin/pw)", out)
        self.assertNotIn("is kept", msg)                      # the profile was there before

    def test_a_profile_made_for_the_refused_connect_is_kept_and_said_so(self):
        made = []
        rc, msg, seen, _ = self.connect(self.refused("sudo: a password is required"), made=made)
        self.assertEqual(seen[0][:3], ["sudo", "-n", "/opt/openvpn"])
        self.assertEqual(len(made), 1)
        self.assertIn(f"The client profile {made[0]}.ovpn created for this is kept", msg)
        self.assertTrue((services.vpn_dir(self.env) / f"{made[0]}.ovpn").exists())
        made2 = []                                            # the re-run connects with it: no second certificate
        rc, msg, seen, _ = self.connect(lambda cmd, **kw: 0, made=made2)
        self.assertEqual(made2, [])
        self.assertIn(str(services.vpn_dir(self.env) / f"{made[0]}.ovpn"), seen[0])

    def test_a_named_user_profile_made_then_refused_by_sudoers(self):
        made = []
        _, msg, _, _ = self.connect(self.refused("bob is not in the sudoers file.  This incident will be reported."),
                                    user="alice", made=made)
        self.assertEqual(made, ["alice"])
        self.assertIn("sudo does not let this user run openvpn", msg)
        self.assertIn("The client profile alice.ovpn created for this is kept", msg)
        # the command to re-run names the profile: without --user it would take the first one (bob.ovpn below)
        self.assertIn(f"run cs vpn connect aws --env {self.env.name} --user alice as a user", msg)

    def test_the_rerun_command_keeps_the_user(self):
        (services.vpn_dir(self.env) / "alice.ovpn").write_text("client\n")
        (services.vpn_dir(self.env) / "bob.ovpn").write_text("client\n")
        _, msg, seen, _ = self.connect(self.refused("sudo: a password is required"), user="bob", made=[])
        self.assertIn(str(services.vpn_dir(self.env) / "bob.ovpn"), seen[0])
        self.assertIn(f"Run it in a terminal: cs vpn connect aws --env {self.env.name} --user bob ", msg)
        self.assertNotIn("is kept", msg)

    def test_disconnect_names_the_helper(self):
        pf = services._pidfile(self.env)
        pf.write_text("4242\n")
        ours = f"openvpn --config x --daemon cloudseed-vpn --writepid {pf} --log-append y"
        seen = []

        def call(cmd, stderr=None, **kw):
            seen.append(list(cmd))
            stderr.write("sudo: no password was provided\n")
            return 1
        with mock.patch.object(services.os, "kill", side_effect=PermissionError), \
                mock.patch.object(services, "_cmdline", return_value=ours), \
                mock.patch.object(services, "_has_tty", return_value=False), \
                mock.patch.object(services, "_askpass", return_value="/h/askpass"), \
                mock.patch.object(services.os, "geteuid", return_value=501), \
                mock.patch.object(services.subprocess, "call", side_effect=call), _silenced():
            with self.assertRaises(ui.Abort) as cm:
                services.disconnect(self.env)
        self.assertEqual(seen[0], ["sudo", "-A", "kill", "-TERM", "4242"])
        self.assertIn("askpass helper (/h/askpass)", cm.exception.msg)
        self.assertTrue(pf.exists())                          # still connected: nothing tidied away


class ConsolePreflightTests(unittest.TestCase):
    """The console refuses a VPN job up front when sudo would need a password; with an askpass helper the job's
    `sudo -A` asks for it, so the job is let through."""

    def setUp(self):
        self.env, _ = _env("aws")
        self.env.save({"cloud": "aws", "env": self.env.name, "vars": {}})
        (self.env.dir / "outputs.json").write_text('{"vpn_public_ip": "192.0.2.9"}')
        services.vpn_dir(self.env)
        (self.env.dir / "vpn" / "openvpn.pid").write_text("4242")

    def preflight(self, action, helper, user=None):
        with mock.patch.object(webui.os, "geteuid", return_value=501, create=True), \
                mock.patch.object(services, "_running", return_value=4242 if action == "disconnect" else None), \
                mock.patch.object(webui.deps, "find", return_value="/opt/bin/openvpn"), \
                mock.patch.object(webui, "_sudo_ok", return_value=False), \
                mock.patch.object(services, "_askpass", return_value=helper):
            webui._vpn_preflight({"action": action, "cloud": "aws", "env": self.env.name, **({"user": user} if user else {})})

    def test_an_askpass_helper_lets_the_job_run(self):
        for action in ("connect", "disconnect"):
            self.preflight(action, "/usr/local/bin/askpass")
            with self.assertRaises(ValueError) as cm:
                self.preflight(action, "")
            self.assertIn(f"cs vpn {action} aws --env {self.env.name}   (", str(cm.exception))
            self.assertIn("SUDO_ASKPASS", str(cm.exception))
        self.assertIn("SUDO_ASKPASS", webui.UI_ACTIONS["cloudseed_vpn_connect"]["description"])

    def test_the_terminal_command_keeps_the_user(self):
        with self.assertRaises(ValueError) as cm:
            self.preflight("connect", "", user="bob")
        self.assertIn(f"cs vpn connect aws --env {self.env.name} --user bob ", str(cm.exception))


class VpnHelpTests(unittest.TestCase):
    def test_help_vpn_covers_expiry_and_the_no_terminal_rules(self):
        text = helpmod.COMMANDS["vpn"]
        flat = " ".join(text.split())
        for words in ("825 days", "`vpn status` shows the server certificate's expiry", "within 30 days",
                      "cloudseed vpn provision <cloud> --env NAME", "cloudseed vpn add-user <cloud> --env NAME <name>",
                      "SUDO_ASKPASS", "`sudo -n`", "passwordless sudo for openvpn and kill"):
            self.assertIn(words, flat)
        added = text[text.index("Certificates (OpenVPN)"):text.index("EXAMPLES")]
        self.assertTrue(all(len(line) <= 118 for line in added.splitlines()), added)
        self.assertEqual(services.RENEW_DAYS, 30)            # the window the text names


# ---------------------------------------------------------------- MCP structuredContent

class StructuredContentTests(unittest.TestCase):
    """mcp: structuredContent (MCP 2025-06-18) only for a peer that negotiated that protocol or a later one."""

    RES = {"content": [{"type": "text", "text": "{\"a\": 1}"}], "isError": False, "structuredContent": {"a": 1}}

    def call(self, protocol: str | None) -> dict:
        s = mcp.Session({})
        params = {"clientInfo": {"name": "t"}} if protocol is None else {"protocolVersion": protocol, "clientInfo": {"name": "t"}}
        with _silenced():
            mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}, s)
            with mock.patch.object(mcp, "call_tool", return_value=dict(self.RES)):
                return mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                   "params": {"name": "cloudseed_output", "arguments": {}}}, s)["result"]

    def test_by_protocol(self):
        for protocol, has in (("2025-06-18", True), (None, True), ("2099-01-01", True),   # unknown: negotiated down
                              ("2025-03-26", False), ("2024-11-05", False)):
            r = self.call(protocol)
            self.assertEqual("structuredContent" in r, has, protocol)
            self.assertEqual(r["content"][0]["text"], "{\"a\": 1}")        # the JSON is the first block either way
        self.assertIn("structuredContent", self.RES)                         # the tool's own result is not changed


# ---------------------------------------------------------------- saved answers of a feature that is off

class UnusedInvalidAnswerTests(unittest.TestCase):
    """gcp reviewer: an old environment with Kubernetes off and a stale kubernetes_node_count=0 (now below minimum=1)
    was refused by apply/provision until setup ran. A setting that is not in use now never blocks a command."""

    def make(self, cloud: str, **vars_):
        name = _uid("w5u")
        env = paths.Env(cloud, name)
        env.create_dirs()
        cfg = {"cloud": cloud, "env": name, "name": "cloudseed", "region": "us-central1" if cloud == "gcp" else "us-east-1",
               "network_cidr": "10.0.0.0/16", "allowed_ssh_cidrs": ["203.0.113.1/32"], "state": {"type": "local"},
               "vars": dict(vars_), "extra_vars": {}, "tags": {}}
        env.save(cfg)
        self.addCleanup(lambda: __import__("shutil").rmtree(env.dir, ignore_errors=True))
        return clouds.get(cloud), env

    def check(self, cmd, cloud, env):
        cfg = env.load()
        with _silenced() as out:
            replaced = cli._check_saved_answers(SimpleNamespace(cmd=cmd), cloud, env, cfg)
        return cfg, replaced, out.getvalue()

    def test_a_changing_command_is_not_blocked_by_an_unused_setting(self):
        for key in ("gcp", "aws"):
            cloud, env = self.make(key, enable_kubernetes=False, kubernetes_node_count=0)
            for cmd in ("apply", "provision", "status"):
                cfg, replaced, out = self.check(cmd, cloud, env)
                self.assertEqual(cfg["vars"]["kubernetes_node_count"], 2, (key, cmd))
                self.assertEqual(replaced, {}, (key, cmd))
                flat = " ".join(out.split())
                self.assertIn("it is not in use (enable_kubernetes is off)", flat)
                self.assertIn(f"Fix: cloudseed setup {key} --env {env.name} --var kubernetes_node_count=VALUE", flat)
            self.assertEqual(env.load()["vars"]["kubernetes_node_count"], 0)   # nothing is written by the check

    def test_vpn_type_without_a_vpn(self):
        cloud, env = self.make("aws", enable_vpn="false", vpn_type="wireguard")
        cfg, replaced, _ = self.check("apply", cloud, env)
        self.assertEqual((cfg["vars"]["vpn_type"], replaced), ("openvpn", {}))

    def test_the_same_value_while_the_feature_is_on_is_still_refused(self):
        cloud, env = self.make("gcp", enable_kubernetes=True, kubernetes_node_count=0)
        with _silenced(), self.assertRaises(ui.Abort) as cm:
            cli._check_saved_answers(SimpleNamespace(cmd="apply"), cloud, env, env.load())
        self.assertIn("kubernetes_node_count=0", cm.exception.msg)

    def test_a_used_invalid_answer_next_to_an_unused_one(self):
        cloud, env = self.make("aws", enable_kubernetes="no", kubernetes_node_count=0, az_count="abc")
        with _silenced() as out, self.assertRaises(ui.Abort) as cm:
            cli._check_saved_answers(SimpleNamespace(cmd="apply"), cloud, env, env.load())
        self.assertIn("az_count", cm.exception.msg)
        self.assertNotIn("kubernetes_node_count", cm.exception.msg)          # only the one that matters is refused
        self.assertIn("not in use", out.getvalue())
        cfg, replaced, _ = self.check("status", cloud, env)
        self.assertEqual(replaced, {"az_count": "abc"})                         # the stand-in list for a save

    def test_an_invalid_parent_answer_still_refuses(self):
        cloud, env = self.make("aws", enable_kubernetes="maybe", kubernetes_node_count=0)
        with _silenced() as out, self.assertRaises(ui.Abort) as cm:
            cli._check_saved_answers(SimpleNamespace(cmd="apply"), cloud, env, env.load())
        self.assertIn("enable_kubernetes", cm.exception.msg)
        # whether the cluster is on is unknown: its sizing is not waved through as unused, and one fix covers both
        self.assertIn("--var enable_kubernetes=VALUE --var kubernetes_node_count=VALUE", cm.exception.msg)
        self.assertNotIn("not in use", out.getvalue())


# ---------------------------------------------------------------- undo --list and wrapping

class UndoListSequenceTests(unittest.TestCase):
    def listing(self, argvs, cols):
        scope = _uid("aws-w5l")
        e = undo.record(scope, "mcp uninstall", "argv-seq", {"argvs": argvs})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), mock.patch.object(ui, "cols", lambda: cols):
            undo.print_list(scope)
        undo.pop(e)
        return e, ui._strip(buf.getvalue())

    def test_one_line_keeps_the_commands_apart(self):
        _, out = self.listing([["mcp", "setup"], ["mcp", "start"]], 160)
        self.assertIn("run: cloudseed mcp setup; then cloudseed mcp start", out)

    def test_wrapped_each_command_starts_its_own_line(self):
        argvs = [["mcp", "setup", "--no-service", "--transport", "http", "--port", "7830"],
                 ["mcp", "connect", "claude-code", "cursor", "codex", "windsurf"], ["mcp", "start"], ["mcp", "status"]]
        e, out = self.listing(argvs, 70)
        lines = out.splitlines()
        starts = [l.strip().strip("│").strip() for l in lines]
        for cmd in ("then cloudseed mcp connect", "then cloudseed mcp start", "then cloudseed mcp status"):
            self.assertTrue(any(s.startswith(cmd) for s in starts), (cmd, out))
        self.assertIn("id " + e["id"], out)
        self.assertTrue(all(ui.vis_len(l) <= ui.width() for l in lines))


class WrapTests(unittest.TestCase):
    def test_a_long_name_breaks_after_a_separator(self):
        text = "run: kubectl delete clusterrole.rbac.authorization.k8s.io/cloudseed-scan --ignore-not-found"
        for n in (30, 40, 60):
            rows = ui._wrap(text, n)
            self.assertTrue(all(len(r) <= n for r in rows), rows)
            self.assertEqual(" ".join(rows).replace(". ", ".").replace("/ ", "/"), text)   # nothing lost or added
            self.assertFalse(any(r.endswith("au") for r in rows), rows)
        self.assertIn("clusterrole.rbac.", ui._wrap(text, 30))

    def test_a_word_without_a_separator_wraps_as_textwrap_does(self):
        text = "a b " * 40 + "averyveryverylongwordthatneedstobesplitacrosslines"
        self.assertEqual(ui._wrap(text, 30), textwrap.wrap(text, 30, break_long_words=True, break_on_hyphens=False))
        self.assertEqual(ui._wrap("x" * 25, 10), ["x" * 10, "x" * 10, "x" * 5])

    def test_no_stub_at_the_end_of_a_full_line(self):
        rows = ui._wrap("aaaa bbbb cccc /very/long/path/that/goes/on/and/on", 20)
        self.assertTrue(all(len(r) <= 20 for r in rows), rows)
        self.assertEqual(rows[0], "aaaa bbbb cccc")                            # not 'aaaa bbbb cccc /'

    def test_wide_characters(self):
        word = "/tmp/" + "日本語フォルダ" * 3 + "/x"
        rows = ui._wrap("路径 " + word, 20)
        self.assertTrue(all(ui.vis_len(r) <= 20 for r in rows), rows)
        self.assertEqual("".join(rows[1:]), word)
        self.assertEqual(rows[1], "/tmp/")
        self.assertEqual(ui._split_by_width("abcdefghij", 3), ["abc", "def", "ghi", "j"])


if __name__ == "__main__":
    unittest.main()
