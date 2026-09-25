"""Wave-3 regression tests for the web console backend (cloudseed/webui.py): the second audit's findings.

Stdlib only, no network, no cloud, no launchd/systemd (launchctl/systemctl are stubbed). In-process servers and the one
foreground console bind ephemeral 127.0.0.1 ports."""
import http.client
import json
import os
import plistlib
import re
import shutil
import signal
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

from cloudseed import agents, creds, mcp, paths, services, undo, webui  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def free_port() -> int:
    """A free ephemeral port chosen by the OS (bind to port 0): suites running at the same time never collide."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(cond, timeout=15.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


class Isolated(unittest.TestCase):
    """Every file the console touches lives in a fresh temp dir for each test."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w3-webui-"))
        ui_dir = self.tmp / "ui"
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.patches = [
            mock.patch.object(webui, "UI_DIR", ui_dir), mock.patch.object(webui, "JOBS_DIR", ui_dir / "jobs"),
            mock.patch.object(webui, "TOKEN_PATH", ui_dir / "token"), mock.patch.object(webui, "STATE_PATH", ui_dir / "server.json"),
            mock.patch.object(webui, "LOG_PATH", ui_dir / "server.log"), mock.patch.object(webui, "PID_PATH", ui_dir / "server.pid"),
            mock.patch.object(paths, "ENVS_DIR", self.tmp / "envs"), mock.patch.object(paths, "WORKDIRS_INDEX", self.tmp / "workdirs.json"),
            mock.patch.object(paths, "SETTINGS_PATH", self.tmp / "settings.json"), mock.patch.object(undo, "JOURNAL", self.tmp / "undo.json"),
            mock.patch.object(paths, "HOME", self.tmp / "cs"), mock.patch.object(paths, "BIN_DIR", self.tmp / "cs" / "bin"),
            mock.patch.object(creds, "STORE", self.tmp / "credentials.json"), mock.patch.object(agents, "AGENTS_FILE", self.tmp / "agents.json"),
            mock.patch.dict(webui.JOBS, clear=True), mock.patch.dict(creds.APPLIED, clear=True), mock.patch.dict(os.environ),
            mock.patch.dict(webui._DEFAULTS, clear=True),
        ]
        for p in self.patches:
            p.start()
        for k in (webui.MANAGED_ENV, "CLOUDSEED_UI_FORCE", "CLOUDSEED_UI_ALLOW_REMOTE", "XPC_SERVICE_NAME", "CLOUDSDK_COMPUTE_ZONE",
                  "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"):
            os.environ.pop(k, None)
        (self.tmp / "envs").mkdir()
        (self.tmp / "cs" / "bin").mkdir(parents=True)
        webui._State.token, webui._State.token_sig = None, None

    def tearDown(self):
        for j in list(webui.JOBS.values()):
            if j.running and j.pid:
                try:
                    os.killpg(j.pid, 9)
                except OSError:
                    pass
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_env(self, cloud="aws", name="dev", outputs=None, cfg=None, raw_cfg=None) -> Path:
        d = self.tmp / "envs" / f"{cloud}-{name}"
        d.mkdir(parents=True)
        (d / "config.json").write_text(raw_cfg if raw_cfg is not None else
                                       json.dumps(cfg or {"cloud": cloud, "env": name, "name": "cs", "region": "r1", "vars": {}, "state": {"type": "local"}}))
        if outputs is not None:
            (d / "outputs.json").write_text(json.dumps(outputs))
        return d

    def env(self, env_id):
        return {e.id: e for e in paths.Env.list_all()}[env_id]

    def audit_lines(self):
        p = self.tmp / "cs" / "logs" / "audit.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


# ---------------------------------------------------------------- agent / skill forms (agentic#20, webui-backend#14, webui-functional#7)

class AgentFormTests(Isolated):
    def test_skill_names_are_passed_for_install_and_checked(self):
        b = webui.build_argv
        self.assertEqual(b("cloudseed_skill", {"action": "install", "agent": "codex", "name": "aws destroy"}), ["skill", "install", "aws", "destroy", "--agent", "codex"])
        self.assertEqual(b("cloudseed_skill", {"action": "install", "name": "aws, destroy"}), ["skill", "install", "aws", "destroy"])
        self.assertEqual(b("cloudseed_skill", {"action": "install"}), ["skill", "install"])                  # blank = all
        self.assertEqual(b("cloudseed_skill", {"action": "install", "dir": "~/skills"}), ["skill", "install", "--dir", "~/skills"])
        self.assertEqual(b("cloudseed_skill", {"action": "list", "name": "aws", "agent": "codex"}), ["skill", "list"])   # list takes nothing
        self.assertEqual(b("cloudseed_skill", {"action": "show", "name": "aws"}), ["skill", "show", "aws"])
        for bad in ({"action": "show"}, {"action": "show", "name": "aws destroy"}, {"action": "show", "name": "all"},
                    {"action": "install", "name": "--dir=/tmp/x"}, {"action": "install", "name": "nosuchskill"}, {"action": "show", "name": "-h"}):
            with self.assertRaises(ValueError, msg=bad):
                b("cloudseed_skill", bad)
        with self.assertRaises(ValueError):
            b("cloudseed_skill", {"action": "install", "dir": "--project"})                                  # not an option
        # the 'project' box is gone: console jobs run in the home folder, so it always meant the agent's own folder
        schema = {a["name"]: a for a in webui.actions_catalog()}["cloudseed_skill"]["schema"]["properties"]
        self.assertNotIn("project", schema)
        self.assertEqual(b("cloudseed_skill", {"action": "install", "project": True}), ["skill", "install"])

    def test_custom_agents_from_agents_json_can_be_chosen(self):
        (self.tmp / "agents.json").write_text(json.dumps({"myagent": {"binary": "myagent", "exec": ["myagent", "{prompt}"]},
                                                          "skilled": {"binary": "sk", "skills_dir": "~/.skilled/skills"},
                                                          "-evil": {"binary": "x"}}))
        b = webui.build_argv
        self.assertEqual(b("cloudseed_use", {"agent": "myagent"}), ["use", "myagent"])
        self.assertEqual(b("cloudseed_agentic", {"task": "hi", "agent": "myagent", "confirm": True})[:3], ["agentic", "--agent", "myagent"])
        self.assertEqual(b("cloudseed_enable", {"feature": "agentic", "agent": "myagent"}), ["enable", "agentic", "--agent", "myagent"])
        cat = {a["name"]: a["schema"]["properties"] for a in webui.actions_catalog()}
        self.assertIn("myagent", cat["cloudseed_use"]["agent"]["enum"])
        self.assertNotIn("-evil", cat["cloudseed_use"]["agent"]["enum"])                      # would read as an option
        self.assertIn("skilled", cat["cloudseed_skill"]["agent"]["enum"])
        self.assertNotIn("myagent", cat["cloudseed_skill"]["agent"]["enum"])                  # no skills folder
        self.assertNotIn("builtin", cat["cloudseed_skill"]["agent"]["enum"])
        with self.assertRaises(ValueError):
            b("cloudseed_use", {"agent": "-evil"})
        # the shared definitions are not changed by a request
        self.assertNotIn("myagent", webui.UI_ACTIONS["cloudseed_use"]["schema"]["properties"]["agent"]["enum"])
        (self.tmp / "agents.json").unlink()                                                    # edited while the console runs
        with self.assertRaises(ValueError):
            b("cloudseed_use", {"agent": "myagent"})

    def test_option_like_values_ports_and_blank_tasks_are_refused(self):
        b = webui.build_argv
        for name, args in (("cloudseed_model", {"model": "--forget=x"}), ("cloudseed_model", {"agent": "--help"}),
                           ("cloudseed_use", {"agent": "claude", "model": "--x"}),
                           ("cloudseed_vpn_connect", {"action": "connect", "cloud": "aws", "user": "--help", "confirm": True}),
                           ("cloudseed_mcp", {"action": "connect", "port": -5}), ("cloudseed_mcp", {"action": "setup", "port": 70000, "confirm": True}),
                           ("cloudseed_agentic", {"task": "   ", "confirm": True})):
            with self.assertRaises(ValueError, msg=(name, args)):
                b(name, args)
        self.assertEqual(b("cloudseed_mcp", {"action": "status", "port": 7433}), ["mcp", "status", "--port", "7433", "-y"])
        self.assertEqual(b("cloudseed_model", {"model": "claude-opus-4"}), ["model", "claude-opus-4"])
        cat = {a["name"]: a for a in webui.actions_catalog()}
        self.assertNotRegex(cat["cloudseed_enable"]["description"], r"\bui\b")                  # the enum refuses it
        self.assertEqual(cat["cloudseed_mcp"]["schema"]["properties"]["port"]["maximum"], 65535)
        self.assertEqual(cat["cloudseed_agentic"]["schema"]["properties"]["task"]["title"], "Task")
        self.assertEqual(cat["cloudseed_agentic"]["schema"]["properties"]["no_headliner"]["title"], "Skip the research brief")
        # every field of every action has a label; the MCP tool definitions themselves are not changed
        self.assertTrue(all(p.get("title") for a in cat.values() for p in a["schema"]["properties"].values()))
        self.assertEqual(cat["cloudseed_setup"]["schema"]["properties"]["allow_ip"]["title"], "Allow IP")
        self.assertEqual(cat["cloudseed_status"]["schema"]["properties"]["env"]["title"], "Environment")
        self.assertNotIn("title", mcp.TOOLS["cloudseed_status"]["schema"]["properties"]["env"])


# ---------------------------------------------------------------- VPN client from the console (webui-backend#1)

class VpnPreflightTests(Isolated):
    def setUp(self):
        super().setUp()
        d = self.make_env("aws", "dev", outputs={"vpn_public_ip": "192.0.2.9"})
        (d / "vpn").mkdir()
        (d / "vpn" / "openvpn.pid").write_text("4242")        # what services._running (mocked here) checks
        self.p = [mock.patch.object(webui.os, "geteuid", return_value=501, create=True)]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        super().tearDown()

    def run_args(self, action):
        return {"action": action, "cloud": "aws", "env": "dev", "confirm": True}

    def test_disconnect_without_passwordless_sudo_is_refused_with_the_terminal_command(self):
        with mock.patch.object(services, "_running", return_value=4242), mock.patch.object(webui, "_sudo_ok", return_value=False) as ok:
            with self.assertRaises(ValueError) as cm:
                webui.build_argv("cloudseed_vpn_connect", self.run_args("disconnect"))
        self.assertIn("cs vpn disconnect aws --env dev", str(cm.exception))
        self.assertIn("sudo", str(cm.exception))
        ok.assert_called_with("kill", ["kill", "-0", "4242"])                  # the exact command, harmlessly (signal 0)
        with mock.patch.object(services, "_running", return_value=4242), mock.patch.object(webui, "_sudo_ok", return_value=True):
            self.assertEqual(webui.build_argv("cloudseed_vpn_connect", self.run_args("disconnect")), ["vpn", "disconnect", "aws", "--env", "dev"])
        with self.assertRaises(webui.NeedsConfirm):                        # the tick comes first, then the check
            webui.build_argv("cloudseed_vpn_connect", {"action": "disconnect", "cloud": "aws", "env": "dev"})

    def test_nothing_to_do_or_no_sudo_needed_is_not_refused(self):
        with mock.patch.object(services, "_running", return_value=None), mock.patch.object(webui, "_sudo_ok", return_value=False):
            self.assertEqual(webui.build_argv("cloudseed_vpn_connect", self.run_args("disconnect"))[:2], ["vpn", "disconnect"])   # not connected
            with mock.patch.object(webui.deps, "find", return_value=None):                                                      # no openvpn yet
                webui.build_argv("cloudseed_vpn_connect", self.run_args("connect"))
            with mock.patch.object(webui.deps, "find", return_value="/opt/bin/openvpn"):
                with self.assertRaises(ValueError) as cm:
                    webui.build_argv("cloudseed_vpn_connect", self.run_args("connect"))
                self.assertIn("cs vpn connect aws --env dev", str(cm.exception))
        (self.tmp / "envs" / "aws-dev" / "outputs.json").write_text(json.dumps({"vpn_public_ip": "192.0.2.9", "vpn_type": "tailscale"}))
        with mock.patch.object(services, "_running", return_value=None), mock.patch.object(webui, "_sudo_ok", return_value=False), \
                mock.patch.object(webui.deps, "find", return_value="/opt/bin/openvpn"):
            webui.build_argv("cloudseed_vpn_connect", self.run_args("connect"))                                                 # tailscale up: no sudo
        with mock.patch.object(webui.os, "geteuid", return_value=0, create=True), mock.patch.object(services, "_running", return_value=7), \
                mock.patch.object(webui, "_sudo_ok", return_value=False):
            webui.build_argv("cloudseed_vpn_connect", self.run_args("disconnect"))                                              # root

    def test_no_vpn_host_or_no_pidfile_needs_no_check(self):
        (self.tmp / "envs" / "aws-dev" / "vpn" / "openvpn.pid").unlink()
        with mock.patch.object(services, "_running", side_effect=AssertionError("looked")), mock.patch.object(webui, "_sudo_ok", return_value=False):
            webui.build_argv("cloudseed_vpn_connect", self.run_args("disconnect"))          # nothing is connected
        d = self.make_env("aws", "novpn", outputs={})
        with mock.patch.object(webui, "_sudo_ok", return_value=False), mock.patch.object(webui.deps, "find", return_value="/opt/bin/openvpn"):
            webui.build_argv("cloudseed_vpn_connect", {"action": "connect", "cloud": "aws", "env": "novpn", "confirm": True})
        self.assertFalse((d / "vpn").exists())                                             # the check leaves nothing behind

    def test_sudo_probe_is_non_interactive(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append((cmd, kw))
            return subprocess.CompletedProcess(cmd, 1 if cmd[2] == "true" else 0, "", "")
        with mock.patch.object(webui.shutil, "which", return_value="/usr/bin/sudo"), mock.patch.object(webui.subprocess, "run", side_effect=fake_run):
            self.assertTrue(webui._sudo_ok("/opt/bin/openvpn"))                  # a NOPASSWD rule for this command only
        self.assertEqual([c[0] for c in calls], [["/usr/bin/sudo", "-n", "true"], ["/usr/bin/sudo", "-n", "-l", "/opt/bin/openvpn"]])
        self.assertTrue(all(c[1]["stdin"] is subprocess.DEVNULL and c[1]["start_new_session"] for c in calls))
        with mock.patch.object(webui.shutil, "which", return_value="/usr/bin/sudo"), \
                mock.patch.object(webui.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "a password is required")):
            self.assertFalse(webui._sudo_ok("kill"))
        # disconnect: `sudo -l` would list kill as allowed whenever any rule is NOPASSWD (sudo's listpw=any), although
        # running it still needs the password; the probe runs the command itself instead (kill -0 changes nothing)
        calls.clear()
        with mock.patch.object(webui.shutil, "which", return_value="/usr/bin/sudo"), mock.patch.object(webui.subprocess, "run", side_effect=fake_run):
            self.assertTrue(webui._sudo_ok("kill", ["kill", "-0", "4242"]))
        self.assertEqual([c[0] for c in calls], [["/usr/bin/sudo", "-n", "true"], ["/usr/bin/sudo", "-n", "kill", "-0", "4242"]])
        with mock.patch.object(services, "_running", side_effect=[4242, None]), mock.patch.object(webui, "_sudo_ok", return_value=False):
            webui.build_argv("cloudseed_vpn_connect", self.run_args("disconnect"))   # it ended meanwhile: nothing to refuse

    def test_description_no_longer_promises_a_sudo_prompt(self):
        d = webui.UI_ACTIONS["cloudseed_vpn_connect"]["description"]
        self.assertNotIn("prompt for sudo in the server log", d)
        self.assertIn("passwordless sudo", d)


# ---------------------------------------------------------------- Platform status kubeconfig (webui-backend#0, #16)

class StatusKubeconfigTests(Isolated):
    def fake_cli(self, name, log):
        """A cloud CLI that writes a kubeconfig like the real one: to --file / --kubeconfig, else $KUBECONFIG (gcloud)
        or ~/.kube/config (az ignores $KUBECONFIG)."""
        script = self.tmp / "bin" / name
        script.parent.mkdir(exist_ok=True)
        script.write_text(f"""#!{sys.executable}
import json, os, sys
a = sys.argv[1:]
open({str(log)!r}, "a").write(json.dumps({{"argv": a, "fips": os.environ.get("AWS_USE_FIPS_ENDPOINT")}}) + "\\n")
target = None
for flag in ("--file", "--kubeconfig"):
    if flag in a:
        target = a[a.index(flag) + 1]
if target is None:
    target = os.path.expanduser("~/.kube/config") if {name!r} == "az" else os.environ["KUBECONFIG"]
os.makedirs(os.path.dirname(target), exist_ok=True)
open(target, "w").write("apiVersion: v1\\nclusters:\\n- cluster:\\n    server: https://127.0.0.1:9\\n")
print("Merged into " + target)
""")
        script.chmod(0o755)
        return str(script)

    def test_azure_fetch_writes_only_the_env_kubeconfig(self):
        from cloudseed import clouds
        d = self.make_env("azure", "drazure", outputs={"kubernetes_cluster_name": "cs-drazure", "resource_group_name": "rg-drazure"},
                          cfg={"cloud": "azure", "env": "drazure", "name": "cs", "region": "westeurope", "vars": {"subscription_id": "sub-1"}, "state": {"type": "local"}})
        log = self.tmp / "az.log"
        az = self.fake_cli("az", log)
        e = self.env("azure-drazure")
        with mock.patch.object(Path, "home", return_value=self.home), mock.patch.dict(os.environ, {"HOME": str(self.home)}), \
                mock.patch.object(webui.deps, "find", side_effect=lambda t: az if t == "az" else None):
            with self.assertRaises(webui._Unavailable) as cm:     # the fake server is not reachable: the fetch itself worked
                webui._status_kubeconfig(clouds.get("azure"), e, e.load(), json.loads((d / "outputs.json").read_text()))
        self.assertIn("not reachable", str(cm.exception))
        argv = json.loads(log.read_text().splitlines()[0])["argv"]
        self.assertEqual(argv[argv.index("--file") + 1], str(d / "k8s" / "kubeconfig"))
        self.assertTrue((d / "k8s" / "kubeconfig").exists())
        self.assertFalse((self.home / ".kube" / "config").exists())
        self.assertEqual(oct((d / "k8s" / "kubeconfig").stat().st_mode & 0o777), "0o600")

    def test_aws_fips_fetch_uses_the_fips_endpoints(self):
        from cloudseed import clouds
        d = self.make_env("aws", "fips", outputs={"kubernetes_cluster_name": "cs-fips"},
                          cfg={"cloud": "aws", "env": "fips", "name": "cs", "region": "us-east-1", "vars": {"fips_mode": True}, "state": {"type": "local"}})
        log = self.tmp / "aws.log"
        aws = self.fake_cli("aws", log)
        e = self.env("aws-fips")
        with mock.patch.object(webui.deps, "find", side_effect=lambda t: aws if t == "aws" else None):
            with self.assertRaises(webui._Unavailable):
                webui._status_kubeconfig(clouds.get("aws"), e, e.load(), json.loads((d / "outputs.json").read_text()))
        rec = json.loads(log.read_text().splitlines()[0])
        self.assertEqual(rec["fips"], "true")
        self.assertIn("--kubeconfig", rec["argv"])

    def test_missing_outputs_and_failed_fetches_read_well(self):
        from cloudseed import clouds
        self.make_env("azure", "half", outputs={"kubernetes_cluster_name": "cs-half"},
                      cfg={"cloud": "azure", "env": "half", "name": "cs", "region": "westeurope", "vars": {"subscription_id": "s"}, "state": {"type": "local"}})
        with mock.patch.object(webui.deps, "find", return_value="/usr/bin/false"):
            out = webui.platform_status("azure-half")
        self.assertIn("resource_group_name", out["error"])
        self.assertIn("cloudseed output azure --env half", out["error"])
        self.assertNotEqual(out["error"], "'resource_group_name'")
        self.assertEqual(webui._err_text(KeyError("x")), "missing 'x' in the environment's saved configuration or outputs")
        # a fetch that fails leaves no empty k8s/ behind
        d = self.make_env("aws", "nofetch", outputs={"kubernetes_cluster_name": "c"},
                          cfg={"cloud": "aws", "env": "nofetch", "name": "cs", "region": "us-east-1", "vars": {}, "state": {"type": "local"}})
        e = self.env("aws-nofetch")
        with mock.patch.object(webui.deps, "find", return_value="/usr/bin/false"):
            with self.assertRaises(webui._Unavailable):
                webui._status_kubeconfig(clouds.get("aws"), e, e.load(), {"kubernetes_cluster_name": "c"})
        self.assertFalse((d / "k8s").exists())

    def test_unreadable_config_is_reported_once(self):
        self.make_env("gcp", "drgcp", outputs={"kubernetes_cluster_name": "c"}, raw_cfg="{not json")
        err = webui.platform_status("gcp-drgcp")["error"]
        self.assertNotIn("cannot read gcp-drgcp/config.json", err)                 # not the same prefix twice
        self.assertEqual(err, self.env("gcp-drgcp").try_load()[1])                  # the message `cs list` shows


# ---------------------------------------------------------------- launchd / systemd service (webui-backend#3, #4, #5)

class ServiceTests(Isolated):
    def stub(self):
        self.cmds = []

        def fake_run(cmd, **kw):
            self.cmds.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return [mock.patch.object(Path, "home", return_value=self.home), mock.patch.object(webui.subprocess, "run", side_effect=fake_run),
                mock.patch.object(webui, "health", return_value=True), mock.patch.object(webui.os, "getuid", return_value=501, create=True),
                mock.patch.object(webui.shutil, "which", side_effect=lambda t: "/bin/" + t)]

    def with_stub(self, fn):
        ps = self.stub()
        for p in ps:
            p.start()
        try:
            return fn()
        finally:
            for p in reversed(ps):
                p.stop()

    def plist(self, label, home=None, managed=True, ptype="Interactive"):
        env = {"PATH": "/usr/bin"}
        if managed:
            env[webui.MANAGED_ENV] = "1"
        if home is not None:
            env["CLOUDSEED_HOME"] = str(home)
        p = self.home / "Library" / "LaunchAgents" / f"{label}.plist"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as fh:
            plistlib.dump({"Label": label, "ProgramArguments": ["cloudseed", "ui", "serve"], "EnvironmentVariables": env, "ProcessType": ptype}, fh)
        return p

    def test_plist_runs_interactive_not_background(self):
        self.with_stub(lambda: webui.start({"host": "127.0.0.1", "port": 7690, "service": "launchd"}))
        with open(self.home / "Library" / "LaunchAgents" / f"{webui.LAUNCHD_LABEL}.plist", "rb") as fh:
            pl = plistlib.load(fh)
        self.assertEqual(pl["ProcessType"], "Interactive")
        self.assertEqual(pl["Label"], webui.LAUNCHD_LABEL)

    def test_labels_are_per_home(self):
        self.assertNotEqual(webui.LAUNCHD_LABEL, webui.LEGACY_LAUNCHD_LABEL)          # the tests run with their own CLOUDSEED_HOME
        self.assertTrue(webui.LAUNCHD_LABEL.startswith("io.cloudseed.ui."))
        self.assertTrue(webui.SYSTEMD_UNIT.startswith("cloudseed-ui-"))

    def test_another_homes_service_is_never_touched(self):
        other = self.plist(webui.LEGACY_LAUNCHD_LABEL, home=self.tmp / "other-home")
        self.with_stub(lambda: (webui.stop(), webui.remove_service(), webui.start({"host": "127.0.0.1", "port": 7691, "service": "launchd"})))
        self.assertEqual([c for c in self.cmds if c[-1].endswith("/" + webui.LEGACY_LAUNCHD_LABEL)], [])   # no bootout / print of it
        self.assertTrue(other.exists())
        self.assertTrue(any(c[:2] == ["launchctl", "bootout"] and c[-1].endswith("/" + webui.LAUNCHD_LABEL) for c in self.cmds))

    def test_this_homes_legacy_login_item_is_migrated_and_removed(self):
        legacy = self.plist(webui.LEGACY_LAUNCHD_LABEL, home=paths.HOME, managed=False, ptype="Background")
        self.assertIn("older version", self.with_stub(lambda: webui.leftover_service({"ui": True})))
        self.with_stub(lambda: webui.start({"host": "127.0.0.1", "port": 7692, "service": "launchd"}))
        self.assertFalse(legacy.exists())
        self.assertIn(["launchctl", "bootout", f"gui/501/{webui.LEGACY_LAUNCHD_LABEL}"], self.cmds)
        self.assertIsNone(self.with_stub(lambda: webui.leftover_service({"ui": True})))
        self.assertIn("cs disable ui", self.with_stub(lambda: webui.leftover_service({"ui": False})))
        self.with_stub(webui.remove_service)
        self.assertFalse((self.home / "Library" / "LaunchAgents" / f"{webui.LAUNCHD_LABEL}.plist").exists())

    def test_health_is_scoped_to_this_home_and_skips_proxies(self):
        answers = {}

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(answers["health"]).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        port = free_port()
        srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        st = {"host": "127.0.0.1", "port": port}
        answers["health"] = {"server": "cloudseed-ui", "home": mcp._home_id()}
        self.assertTrue(webui.health(st))
        os.environ["http_proxy"] = os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"   # a dead proxy (corporate shells)
        self.assertTrue(webui.health(st))
        answers["health"] = {"server": "cloudseed-ui", "home": "another-home"}
        self.assertFalse(webui.health(st))
        answers["health"] = {"server": "cloudseed-ui"}                              # a console from before the home id
        self.assertTrue(webui.health(st))

    def test_disabled_console_started_by_launchd_exits_cleanly_and_drops_its_login_item(self):
        own = self.plist(webui.LAUNCHD_LABEL, home=paths.HOME)
        os.environ["XPC_SERVICE_NAME"] = webui.LAUNCHD_LABEL                     # a legacy plist has no MANAGED_ENV
        with mock.patch.object(Path, "home", return_value=self.home), mock.patch("sys.stderr"):
            self.assertEqual(webui.serve("127.0.0.1", free_port()), 0)         # KeepAlive does not restart it
        self.assertFalse(own.exists())
        self.assertIn("removed the login item", webui.LOG_PATH.read_text())
        os.environ["XPC_SERVICE_NAME"] = "0"                                       # a terminal
        with mock.patch("sys.stderr"):
            self.assertEqual(webui.serve("127.0.0.1", free_port()), 2)

    def test_jobs_do_not_inherit_the_consoles_launchd_name(self):
        os.environ["XPC_SERVICE_NAME"] = webui.LAUNCHD_LABEL
        self.assertNotIn("XPC_SERVICE_NAME", webui.child_env())
        os.environ["XPC_SERVICE_NAME"] = "application.com.apple.Terminal"
        self.assertEqual(webui.child_env()["XPC_SERVICE_NAME"], "application.com.apple.Terminal")

    def test_remote_listening_is_refused_even_with_the_old_flag(self):              # webui-backend#15
        paths.save_settings({"ui": True})
        os.environ["CLOUDSEED_UI_ALLOW_REMOTE"] = "1"
        with mock.patch("sys.stderr") as err:
            self.assertEqual(webui.serve("0.0.0.0", free_port()), 2)
        said = "".join(c.args[0] for c in err.write.call_args_list)
        self.assertIn("local-only", said)
        self.assertIn("ssh -L", said)


class ForegroundServeTests(unittest.TestCase):                                     # webui-backend#13
    def test_foreground_serve_says_where_it_is(self):
        home = Path(tempfile.mkdtemp(prefix="cs-w3-fg-"))
        self.addCleanup(shutil.rmtree, home, True)
        cs = home / "cs"
        cs.mkdir()
        (cs / "settings.json").write_text('{"ui": true}')
        env = dict(os.environ, CLOUDSEED_HOME=str(cs), HOME=str(home), NO_COLOR="1")
        for k in (webui.MANAGED_ENV, "XPC_SERVICE_NAME"):
            env.pop(k, None)
        for _ in range(5):      # (another run may take the port after free_port looked: then another one)
            port = free_port()
            proc = subprocess.Popen([sys.executable, str(REPO / "bin" / "cloudseed"), "ui", "serve", "--port", str(port)], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
            self.addCleanup(proc.stderr.close)
            self.addCleanup(lambda p=proc: p.poll() is None and (p.kill(), p.wait()))
            line = proc.stderr.readline().decode()
            if "Address already in use" not in line:
                break
            proc.wait(timeout=10)
        self.assertIn(f"http://127.0.0.1:{port}/", line)
        self.assertIn("cs ui open", line)
        tok = (cs / "ui" / "token").read_text().strip()
        self.assertNotIn(tok, line)                                                # the link with the token is not printed
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/health")
        h = json.loads(c.getresponse().read())
        c.close()
        self.assertEqual(h["pid"], proc.pid)
        self.assertEqual(len(h["home"]), 12)
        self.assertNotIn(str(cs), json.dumps(h))
        proc.send_signal(signal.SIGINT)
        proc.wait(15)
        proc.stderr.close()


# ---------------------------------------------------------------- audit trail (webui-backend#6)

class AuditTests(Isolated):
    def test_vault_and_env_changes_are_audited_without_secret_values(self):
        self.make_env("aws", "dev")
        self.make_env("gcp", "drgcp")
        secret = "wJalr" + "XUtnFEMIK7MDENG" + "bPxRfiCYEXAMPLEKEY99"
        webui.change_creds({"set": {"AWS_DEFAULT_REGION": "eu-west-1", "AWS_SECRET_ACCESS_KEY": secret}})
        webui.change_creds({"unset": ["AWS_SECRET_ACCESS_KEY"]})
        webui.use_env("gcp-drgcp")
        webui.use_env(None)
        with self.assertRaises(ValueError):
            webui.use_env("nope-nope")
        with self.assertRaises(ValueError):
            webui.change_creds({"set": {"PATH": "/tmp"}})
        webui.change_creds({"clear": True})
        lines = self.audit_lines()
        text = json.dumps(lines)
        self.assertNotIn(secret, text)
        self.assertTrue(all(x["via"] == "ui" for x in lines))
        argvs = [x["argv"] for x in lines]
        self.assertIn(["creds", "set", "AWS_DEFAULT_REGION=eu-west-1", "AWS_SECRET_ACCESS_KEY=[REDACTED]"], argvs)
        self.assertIn(["creds", "unset", "AWS_SECRET_ACCESS_KEY"], argvs)
        self.assertIn(["env", "use", "gcp-drgcp"], argvs)
        self.assertIn(["env", "clear"], argvs)
        self.assertIn(["creds", "clear"], argvs)
        failed = [x for x in lines if x["exit_code"] == 1]
        self.assertEqual([x["command"] for x in failed], ["env", "creds"])
        self.assertEqual({x["command"] for x in lines}, {"creds", "env"})

    def test_path_warnings_and_group_labels(self):
        out = webui.change_creds({"set": {"GOOGLE_APPLICATION_CREDENTIALS": str(self.tmp / "missing.json")}})
        self.assertEqual(len(out["warnings"]), 1)
        self.assertIn("does not exist", out["warnings"][0])
        row = next(r for r in out["creds"] if r["key"] == "GOOGLE_APPLICATION_CREDENTIALS")
        self.assertIn("does not exist", row["warning"])
        (self.tmp / "missing.json").write_text("{}")
        self.assertNotIn("warning", next(r for r in webui._creds_rows() if r["key"] == "GOOGLE_APPLICATION_CREDENTIALS"))
        with mock.patch.object(mcp, "connected", return_value=None), mock.patch.object(mcp, "client_present", return_value=False):
            st = webui.state()
        self.assertEqual(st["creds_groups"]["custom"], "Custom variables")


# ---------------------------------------------------------------- the per-environment job lock (webui-backend#9)

class EnvKeyTests(Isolated):
    def test_scale_global_options_and_ambiguous_names(self):
        for env_id in ("aws-dev", "aws-draws", "vmware-draws", "vmware-drvmware"):
            c, n = env_id.split("-", 1)
            self.make_env(c, n)
        k = webui.env_key
        self.assertEqual(k(["node", "scale", "aws", "--env", "dev", "--count", "3"]), "aws-dev")
        self.assertEqual(k(["-y", "--runtime", "local", "setup", "aws", "--env", "x"]), "aws-x")
        self.assertEqual(k(["--engine=docker", "destroy", "aws", "--env", "dev"]), "aws-dev")
        self.assertIsNone(k(["--runtime", "local", "status", "aws"]))
        self.assertEqual(k(["dr", "backup", "--env", "draws"]), "*")                    # aws-draws or vmware-draws
        paths.save_settings({"current_env": "vmware-draws"})
        self.assertEqual(k(["dr", "backup", "--env", "draws"]), "vmware-draws")         # the CLI prefers the current one
        self.assertEqual(k(["dr", "backup", "--env", "drvmware"]), "vmware-drvmware")

    def test_undo_by_id_is_keyed_by_what_it_touches(self):
        self.make_env("aws", "dev")
        undo.record(undo.GLOBAL, "env use aws-dev", "settings-restore", {"settings": {"current_env": None}})
        undo.record(undo.GLOBAL, "creds set X", "creds-restore", {"values": {}, "unset": ["X"]})
        undo.record(undo.GLOBAL, "enable ui", "argv", {"argv": ["disable", "ui"]})
        undo.record(undo.GLOBAL, "skill install", "restore-files", {"files": {str(self.home / ".claude" / "skills" / "cloudseed"): None}})
        undo.record(undo.GLOBAL, "install terraform", "restore-files", {"files": {str(paths.BIN_DIR / "terraform"): None}})
        undo.record("aws-dev", "platform install x", "info", {"advice": "x"})
        ids = {e["summary"]: e["id"] for e in undo.entries()}
        k = webui.env_key
        for summary in ("env use aws-dev", "creds set X", "enable ui", "skill install"):
            self.assertIsNone(k(["undo", "--id", ids[summary], "-y", "--auto-approve"]), summary)
        self.assertEqual(k(["undo", "--id", ids["install terraform"], "-y"]), "*")     # would delete a tool a job may use
        self.assertEqual(k(["undo", "--id", ids["platform install x"], "-y"]), "aws-dev")
        self.assertEqual(k(["undo", "--id", "no-such-id", "-y"]), "*")
        self.assertEqual(k(["undo", "-y"]), "*")
        # a global env-use undo runs while an environment job runs; an install undo does not
        running = webui.Job("j1", ["setup", "aws"], "setup", key="aws-dev")
        with webui.JOBS_LOCK:
            webui.JOBS["j1"] = running
        self.assertIsNone(webui._conflicting(k(["undo", "--id", ids["env use aws-dev"], "-y"])))
        self.assertIs(webui._conflicting(k(["undo", "--id", ids["install terraform"], "-y"])), running)

    def test_raw_argv_sees_the_command_after_global_options(self):
        with self.assertRaises(webui.NeedsConfirm) as cm:
            webui.raw_argv({"argv": ["--runtime", "local", "setup", "aws"]})
        self.assertIn("cloudseed setup", str(cm.exception))
        self.assertEqual(webui.raw_argv({"argv": ["--runtime", "local", "status", "aws"]}), ["-y", "--runtime", "local", "status", "aws"])
        self.assertEqual(webui.raw_argv({"argv": ["--runtime", "local", "destroy", "mcp"], "confirm": True}), ["-y", "--runtime", "local", "mcp", "uninstall"])


# ---------------------------------------------------------------- jobs: kills after a restart, masked commands (webui-backend#10, webui-functional#15)

class JobTests(Isolated):
    def runner(self, rc_path: Path) -> subprocess.Popen:
        """A job runner as the console starts it (own session; its command line names the rc file), that ignores
        Ctrl-C like a hung Terraform provider: only the third interrupt's SIGKILL ends it."""
        return subprocess.Popen(["/bin/sh", "-c", 'trap "" INT; while :; do sleep 0.1; done', "cloudseed-job", str(rc_path)],
                                start_new_session=True, stdin=subprocess.DEVNULL)

    def test_an_adopted_job_killed_by_the_third_interrupt_is_not_lost(self):
        webui._jobs_dir()
        job = webui.Job("20260101-000000-abcd", ["apply", "aws"], "apply", key="aws-dev")
        proc = self.runner(job.rc_path)
        self.addCleanup(proc.wait)
        job.pid = proc.pid
        job.log_path.write_text("")
        job.save_meta()
        self.assertTrue(wait_for(lambda: webui._alive(job.pid, str(job.rc_path)), 5))
        for _ in range(2):
            self.assertTrue(webui.cancel_job(job)["cancelled"])
        self.assertEqual(json.loads(job.meta_path.read_text())["cancels"], 2)
        # the console restarts: the job is adopted (no Popen handle) and keeps its interrupt count
        webui.JOBS.clear()
        webui._restore_jobs()
        adopted = webui.JOBS[job.id]
        self.assertIsNone(adopted.proc)
        self.assertEqual(adopted.cancels, 2)
        r = webui.cancel_job(adopted)
        self.assertEqual(r["interrupts"], 3)
        self.assertEqual(r["message"], "Job killed.")
        proc.wait(10)          # reap it here (a real adopted runner belongs to launchd/init, not to the console)
        self.assertTrue(wait_for(lambda: not adopted.running, 15))
        self.assertEqual((adopted.rc, adopted.lost), (137, False))
        self.assertNotIn("was not recorded", "\n".join(adopted.to_dict()["lines"]))
        meta = json.loads(job.meta_path.read_text())
        self.assertEqual((meta["rc"], meta["lost"], meta["killed"]), (137, False, True))

    def test_a_kill_recorded_before_the_console_stopped_is_restored_as_a_kill(self):
        webui._jobs_dir()
        (webui.JOBS_DIR / "j2.json").write_text(json.dumps({"id": "j2", "argv": ["apply"], "label": "apply", "pid": 999999999, "rc": None,
                                                             "started": time.time() - 5, "cancels": 3, "killed": True}))
        (webui.JOBS_DIR / "j2.log").write_text("x\n")
        webui._restore_jobs()
        self.assertEqual((webui.JOBS["j2"].rc, webui.JOBS["j2"].lost), (137, False))

    def test_job_commands_are_shown_and_stored_masked(self):
        webui._jobs_dir()
        seen = self.tmp / "seen.json"
        launcher = [sys.executable, "-c", f"import json, sys; open({str(seen)!r}, 'w').write(json.dumps(sys.argv[1:]))"]
        argv = ["kubectl", "create", "secret", "generic", "x", "--from-literal=password=S3cretPW99"]
        with mock.patch.object(mcp, "_launcher", return_value=launcher):
            job = webui.start_job(argv, "kubectl", None)
            self.assertTrue(wait_for(lambda: not job.running, 15))
        self.assertEqual(json.loads(seen.read_text()), argv)                     # the job ran the real command
        self.assertNotIn("S3cretPW99", json.dumps(job.to_dict()))
        self.assertNotIn("S3cretPW99", job.meta_path.read_text())
        self.assertNotIn("S3cretPW99", webui.LOG_PATH.read_text())
        self.assertIn("--from-literal=password=[REDACTED]", job.argv)
        # a record written by an older version is scrubbed when the console starts
        (webui.JOBS_DIR / "old.json").write_text(json.dumps({"id": "old", "argv": ["helm", "--set", "adminPassword=AdminPW999"], "label": "helm",
                                                              "rc": 0, "started": time.time() - 9, "finished": time.time() - 8}))
        # an older version's label (the command's first words) carried the value too
        (webui.JOBS_DIR / "old2.json").write_text(json.dumps({"id": "old2", "argv": ["creds", "set", "DB_PASS=VaultPW777"], "label": "creds set DB_PASS=VaultPW777",
                                                               "rc": 0, "started": time.time() - 7, "finished": time.time() - 6}))
        webui.JOBS.clear()
        webui._restore_jobs()
        self.assertNotIn("AdminPW999", (webui.JOBS_DIR / "old.json").read_text())
        self.assertNotIn("VaultPW777", (webui.JOBS_DIR / "old2.json").read_text())
        self.assertEqual(webui.JOBS["old2"].label, "creds set DB_PASS=[REDACTED]")
        with self.assertRaises(webui.NeedsConfirm) as cm:
            webui.build_argv("cloudseed_helm", {"args": "install x --set adminPassword=AdminPW999"})
        self.assertNotIn("AdminPW999", json.dumps(cm.exception.argv))

    def test_conflict_message_carries_date_and_zone(self):
        job = webui.Job("j3", ["setup", "aws"], "setup", key="aws-dev", started=time.time())
        with webui.JOBS_LOCK:
            webui.JOBS["j3"] = job
        with self.assertRaises(webui.Conflict) as cm:
            webui.start_job(["apply", "aws", "--env", "dev"], "apply", "aws-dev")
        self.assertIn(time.strftime("%Y-%m-%d", time.localtime(job.started)), str(cm.exception))
        self.assertIn(time.strftime("%Z", time.localtime(job.started)), str(cm.exception))


# ---------------------------------------------------------------- reports and the HTTP layer (webui-backend#16)

class VerdictTests(Isolated):
    def test_dr_rto_falls_back_like_the_reports_view(self):
        d = self.make_env("vmware", "lab")
        (d / "dr").mkdir()
        rep = d / "dr" / "drill-20260101-000000.json"
        rep.write_text(json.dumps({"verdict": "PASS", "run": "r1", "steps": [{"step": "4. restore", "seconds": 7.25}, {"step": "5. verify", "seconds": 4.75},
                                                                                {"step": "1. create", "seconds": 30}]}))
        self.assertEqual(webui.verdicts(self.env("vmware-lab"))["dr"]["detail"], "RTO 12s")
        rep.write_text(json.dumps({"verdict": "PASS", "run": "r1"}))
        self.assertEqual(webui.verdicts(self.env("vmware-lab"))["dr"]["detail"], "RTO ?s")
        rep.write_text(json.dumps({"verdict": "PASS", "run": "r1", "rto_s": 34.5}))
        self.assertEqual(webui.verdicts(self.env("vmware-lab"))["dr"]["detail"], "RTO 34.5s")


class HttpTests(Isolated):
    def setUp(self):
        super().setUp()
        self.port = free_port()
        self.token = webui.ensure_token()
        webui._State.host, webui._State.port = "127.0.0.1", self.port
        self.httpd = webui._Server(("127.0.0.1", self.port), webui._Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"X-CS-Token": self.token}
        h.update(headers or {})
        c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=h)
        r = c.getresponse()
        out = (r.status, dict(r.getheaders()), r.read())
        c.close()
        return out

    def test_other_methods_get_json_with_the_security_headers(self):
        for m in ("PUT", "DELETE", "OPTIONS", "PATCH"):
            code, h, body = self.req(m, "/api/state")
            self.assertEqual(code, 405, m)
            self.assertEqual(h["Allow"], "GET, POST")
            self.assertEqual(h["X-Content-Type-Options"], "nosniff")
            self.assertIn("Content-Security-Policy", h)
            self.assertIn("not allowed", json.loads(body)["error"])
        code, h, body = self.req("HEAD", "/")
        self.assertEqual((code, body), (405, b""))
        self.assertEqual(self.req("PUT", "/", headers={"Host": "evil.example:%d" % self.port})[0], 403)   # still no rebinding
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:          # a malformed request line
            s.sendall(b"GET / extra HTTP/1.1\r\n\r\n")
            raw = s.recv(4096).decode("latin-1")
        self.assertIn(" 400 ", raw.splitlines()[0])
        self.assertIn("X-Content-Type-Options: nosniff", raw)
        self.assertIn("application/json", raw)
        # the unread body of a refused PUT is never taken for the next request: the connection ends with the 405
        body = b'{"x": 1}'
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"PUT /api/state HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: %d\r\n\r\n%s" % (self.port, len(body), body)
                      + b"GET /health HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % self.port)
            raw = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                raw += chunk
        self.assertEqual(re.findall(r"HTTP/1\.[01] \d{3}", raw.decode("latin-1")), ["HTTP/1.1 405"])   # one answer, no stray 400

    def test_health_names_this_home_not_its_path(self):
        code, _h, body = self.req("GET", "/health", headers={"X-CS-Token": ""})
        data = json.loads(body)
        self.assertEqual((code, data["home"], data["pid"]), (200, mcp._home_id(), os.getpid()))
        self.assertNotIn(str(paths.HOME), body.decode())

    def test_run_answers_with_the_masked_command(self):
        with mock.patch.object(mcp, "_launcher", return_value=[sys.executable, "-c", "pass"]):
            code, _h, body = self.req("POST", "/api/run", {"action": "cloudseed_explain", "args": {"what": "AKIA" + "ABCDEFGHIJKLMNOP"}})
        self.assertEqual(code, 200, body)
        self.assertNotIn("AKIA" + "ABCDEFGHIJKLMNOP", body.decode())
        job = webui.JOBS[json.loads(body)["job"]]
        wait_for(lambda: not job.running, 10)


# ---------------------------------------------------------------- wizard: a region-bound answer from the environment (gcp#9)

class CatalogTests(Isolated):
    def q(self, cloud, key):
        return {x["key"]: x for x in webui.clouds_catalog()[cloud]["questions"]}[key]

    def test_env_zone_says_which_region_it_belongs_to(self):
        os.environ["CLOUDSDK_COMPUTE_ZONE"] = "europe-west1-c"
        zone = self.q("gcp", "zone")
        self.assertEqual((zone["default"], zone["from_env"], zone["env_region"]), ("", ["CLOUDSDK_COMPUTE_ZONE"], "europe-west1"))
        self.assertEqual(zone["stock"]["default"], "us-central1-a")                  # what the CLI uses in any other region
        self.assertEqual(zone["stock"]["region_defaults"], {"europe-west1": "europe-west1-b", "us-east1": "us-east1-b"})
        self.assertNotIn("europe-west1-c", json.dumps(zone))                          # names and regions only, never the value
        project = self.q("gcp", "project_id")
        self.assertNotIn("env_region", project)

    def test_region_independent_answers_get_no_region_and_run_no_cloud_cli(self):
        os.environ["ARM_SUBSCRIPTION_ID"] = "11111111-2222-3333-4444-555555555555"
        calls, orig = [], webui.computed_default

        def spy(cloud, q, cfg):
            calls.append((cloud, q.key))
            return orig(cloud, q, cfg)
        with mock.patch.object(webui, "computed_default", side_effect=spy):
            sub = self.q("azure", "subscription_id")
        self.assertNotIn(("azure", "subscription_id"), calls)                         # `az account show` never ran
        self.assertEqual(sub["from_env"], ["ARM_SUBSCRIPTION_ID"])
        self.assertNotIn("env_region", sub)
        self.assertNotIn("stock", sub)


if __name__ == "__main__":
    unittest.main()
