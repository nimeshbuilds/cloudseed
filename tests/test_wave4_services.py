"""Wave 4 regression tests for services.py and managed.py: the kubeconfig command (Azure --public-fqdn, readable stops
instead of KeyErrors, saved booleans read like setup reads them, the environment's real working directory), VPN
connect/disconnect through sudo without a terminal, certificate expiry for `vpn users` / `vpn status`, and the
databricks/snowflake passthrough refusing interactive commands in an agent session.
Offline, stdlib only: ssh, sudo, kubectl and the vendor CLIs are faked."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, managed, paths, services, ui, undo  # noqa: E402

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


def _env(cloud: str, vars_: dict | None = None, key: bool = False):
    name = _uid("w4")
    env = paths.Env(cloud, name)
    env.create_dirs()
    cfg = {"env": name, "cloud": cloud, "region": "r", "network_cidr": "10.0.0.0/16", "vars": dict(vars_ or {}),
           "workdir": str(env.dir)}
    if key:
        (env.ssh_dir / "id_ed25519").write_text("PRIVATE KEY")
    return env, cfg


def _cp(rc: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], rc, out, err)


# ---------------------------------------------------------------- kubeconfig command

class AzureKubeconfigTests(unittest.TestCase):
    """a2-azure#5: a private AKS cluster that publishes its hcp name gets --public-fqdn, so the kubeconfig names a server
    VPN clients can resolve; a privatelink endpoint (env not re-applied) or a public cluster does not."""

    CFG = {"env": "d", "cloud": "azure", "vars": {"subscription_id": "s"}}
    OUT = {"kubernetes_cluster_name": "c", "resource_group_name": "rg"}

    def cmd(self, endpoint, public=None, kubeconfig=Path("/x/kc")):
        cfg = json.loads(json.dumps(self.CFG))
        if public is not None:
            cfg["vars"]["kubernetes_public_endpoint"] = public
        out = dict(self.OUT, kubernetes_endpoint=endpoint) if endpoint is not None else dict(self.OUT)
        return services.kubeconfig_command("azure", cfg, out, kubeconfig=kubeconfig)

    def test_private_cluster_with_its_hcp_name_gets_the_flag(self):
        cmd = self.cmd("cs-d-abc123.hcp.westeurope.azmk8s.io")
        self.assertIn("--public-fqdn", cmd)
        self.assertEqual(cmd[-2:], ["--file", "/x/kc"])        # az still writes the named file
        self.assertIn("--public-fqdn", self.cmd("cs-d-abc123.hcp.westeurope.azmk8s.io", public="false"))   # a saved "false"

    def test_privatelink_endpoint_public_cluster_or_no_endpoint_get_none(self):
        for endpoint, public in (("cs-d-abc.privatelink.westeurope.azmk8s.io", None),
                                 ("CS-D-ABC.PRIVATELINK.westeurope.azmk8s.io", None),
                                 ("cs-d-abc.hcp.westeurope.azmk8s.io", True),
                                 ("cs-d-abc.hcp.westeurope.azmk8s.io", "true"),
                                 (None, None), ("", None)):
            self.assertNotIn("--public-fqdn", self.cmd(endpoint, public), (endpoint, public))

    def test_the_flag_changes_the_kubeconfig_stamp(self):
        # ensure_kubeconfig re-fetches when the command changes: an env re-applied with the hcp name gets a new file
        a = self.cmd("x.privatelink.westeurope.azmk8s.io", kubeconfig=None)
        b = self.cmd("x.hcp.westeurope.azmk8s.io", kubeconfig=None)
        self.assertNotEqual(a, b)

    def test_a_missing_setting_leaves_no_k8s_directory(self):
        env, cfg = _env("azure", {"subscription_id": "s"})
        with self.assertRaises(ui.Abort) as cm:
            services.ensure_kubeconfig(clouds.get("azure"), env, cfg, {"kubernetes_cluster_name": "c"})
        self.assertIn("has no resource_group_name", cm.exception.msg)
        self.assertFalse((env.dir / "k8s").exists())

    def test_missing_settings_stop_with_the_fix_not_a_key_error(self):
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_command("azure", self.CFG, {"kubernetes_cluster_name": "c"})
        self.assertIn("outputs.json of azure-d has no resource_group_name", cm.exception.msg)
        self.assertIn("cloudseed output azure --env d", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_command("azure", {"env": "d", "vars": {}}, self.OUT)
        self.assertIn("subscription_id", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_command("gcp", {"env": "g", "vars": {}}, {"kubernetes_cluster_name": "c"})
        self.assertIn("project_id", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_command("gcp", {"env": "g", "vars": {"project_id": "p"}}, {"kubernetes_cluster_name": "c"})
        self.assertIn("kubernetes_location", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_command("aws", {"env": "a", "vars": {}}, {"kubernetes_cluster_name": "c"})
        self.assertIn("region: cloudseed setup aws --env a --region REGION", cm.exception.msg)


class PrivatelinkHintTests(unittest.TestCase):
    """An Azure env still reporting the privatelink name: 'connect the VPN' cannot help; re-running setup can."""

    def test_no_bastion(self):
        env, cfg = _env("azure")
        outputs = {"kubernetes_endpoint": "https://x.privatelink.westeurope.azmk8s.io:443"}
        with mock.patch.object(services, "_tcp_open", return_value=False), _silenced() as out:
            self.assertFalse(services._ensure_reachable(clouds.get("azure"), env, cfg, outputs, env.dir / "kc"))
        text = out.getvalue()
        self.assertIn(f"Re-run cloudseed setup azure --env {env.name}", text)
        self.assertNotIn("connect the VPN first", text)
        outputs = {"kubernetes_endpoint": "x.hcp.westeurope.azmk8s.io"}
        with mock.patch.object(services, "_tcp_open", return_value=False), _silenced() as out:
            services._ensure_reachable(clouds.get("azure"), env, cfg, outputs, env.dir / "kc")
        self.assertIn("connect the VPN first", out.getvalue())

    def test_tunnel_failure(self):
        env, cfg = _env("azure")
        outputs = {"kubernetes_endpoint": "x.privatelink.westeurope.azmk8s.io", "bastion_public_ip": "203.0.113.5"}
        with mock.patch.object(services, "_tcp_open", return_value=False), \
                mock.patch.object(services.subprocess, "run", return_value=_cp(255)), _silenced() as out:
            self.assertFalse(services._ensure_reachable(clouds.get("azure"), env, cfg, outputs, env.dir / "kc"))
        self.assertIn(f"Re-run cloudseed setup azure --env {env.name}", out.getvalue())
        self.assertNotIn("or connect the VPN", out.getvalue())

    def test_merged_kubeconfig_advice(self):
        env, cfg = _env("azure", {"subscription_id": "s"})
        outputs = {"kubernetes_cluster_name": "c", "resource_group_name": "rg",
                   "kubernetes_endpoint": "x.privatelink.westeurope.azmk8s.io"}
        home = Path(tempfile.mkdtemp())
        with mock.patch.dict(os.environ, {"KUBECONFIG": str(home / "config")}), \
                mock.patch.object(services.deps, "find", return_value="/usr/bin/az"), \
                mock.patch.object(services.subprocess, "run", return_value=_cp(0)), \
                mock.patch.object(services, "_tcp_open", return_value=False), _silenced() as out:
            self.assertEqual(services.kubeconfig("azure", cfg, outputs), 0)
        text = out.getvalue()
        self.assertIn(f"Re-run cloudseed setup azure --env {env.name}", text)
        self.assertNotIn("connect the VPN (cloudseed vpn connect", text)
        self.assertIn(f"export KUBECONFIG={env.dir / 'k8s' / 'kubeconfig'}", text)


class SavedBooleanTests(unittest.TestCase):
    """need cli-cluster: a saved string "false" is off (plain truthiness read it as on)."""

    def test_var_on(self):
        for value, want in ((True, True), ("true", True), ("Yes", True), (1, True), ("on", True),
                            (False, False), ("false", False), ("no", False), (0, False), ("0", False), ("", False),
                            (None, False), ("maybe", False), ([1], False)):
            self.assertEqual(services._var_on({"vars": {"k": value}}, "k"), want, value)
        self.assertFalse(services._var_on({}, "k"))
        self.assertFalse(services._var_on({"vars": "garbage"}, "k"))

    def test_kubernetes_hints(self):
        env, cfg = _env("aws", {"enable_kubernetes": "false"})
        with self.assertRaises(ui.Abort) as cm:
            services.ensure_kubeconfig(clouds.get("aws"), env, cfg, {})
        self.assertIn("--var enable_kubernetes=true", cm.exception.msg)
        self.assertNotIn("not created yet", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_command("aws", cfg, {})
        self.assertIn("--var enable_kubernetes=true", cm.exception.msg)
        cfg["vars"]["enable_kubernetes"] = "true"
        with self.assertRaises(ui.Abort) as cm:
            services.ensure_kubeconfig(clouds.get("aws"), env, cfg, {})
        self.assertIn("not created yet", cm.exception.msg)
        self.assertIn("setup vmware --env x --var enable_kubernetes=true",
                      services._no_local_kubeconfig("x", {"vars": {"enable_kubernetes": "no"}}, {}))

    def test_gcp_public_endpoint_false_string_is_private(self):
        cfg = {"env": "g", "vars": {"project_id": "p", "zone": "z", "kubernetes_public_endpoint": "false"}}
        self.assertIn("--internal-ip", services.kubeconfig_command("gcp", cfg, {"kubernetes_cluster_name": "c"}))
        cfg["vars"]["kubernetes_public_endpoint"] = "true"
        self.assertNotIn("--internal-ip", services.kubeconfig_command("gcp", cfg, {"kubernetes_cluster_name": "c"}))

    def test_vpn_hints(self):
        env, cfg = _env("aws", {"enable_vpn": "false"})
        with self.assertRaises(ui.Abort) as cm:
            services.vpn_host(clouds.get("aws"), env, cfg, {})
        self.assertIn("--var enable_vpn=true", cm.exception.msg)
        self.assertNotIn("not created yet", cm.exception.msg)
        with _silenced() as out:
            services.status(env, cfg, {})
        self.assertIn("--var enable_vpn=true", out.getvalue())


class LocalKubeconfigDirTests(unittest.TestCase):
    """a2-vmware#12: the local kubeconfig is looked up in the environment's directory as cloudseed resolves it, not in
    a stale config.json 'workdir' (a moved CLOUDSEED_HOME)."""

    def test_the_resolved_directory_wins_over_a_stale_workdir(self):
        name = _uid("w4kc")
        env = paths.Env("vmware", name)
        env.save({"cloud": "vmware", "env": name, "vars": {"enable_kubernetes": True}})
        (env.dir / "k8s").mkdir(parents=True, exist_ok=True)
        (env.dir / "k8s" / "kubeconfig").write_text("{}")
        cfg = {"cloud": "vmware", "env": name, "vars": {"enable_kubernetes": True}, "workdir": "/nonexistent/old-home/envs/x"}
        with mock.patch.object(services.deps, "find", return_value=None), _silenced() as out:
            self.assertEqual(services.kubeconfig_local(cfg, {}), 0)
        self.assertIn(f"export KUBECONFIG={env.dir / 'k8s' / 'kubeconfig'}", out.getvalue())
        self.assertEqual(services.kubeconfig_command("vmware", cfg, {}),
                         ["export", f"KUBECONFIG={services.kubeconfig_path(env)}"])

    def test_the_saved_workdir_serves_an_unresolvable_environment(self):
        wd = Path(tempfile.mkdtemp())
        cfg = {"env": _uid("w4ext"), "workdir": str(wd), "vars": {}}
        self.assertEqual(services._env_dir("vmware", cfg), wd)
        self.assertIsNone(services._env_dir("vmware", {"vars": {}}))

    def test_three_way_hint(self):
        name = _uid("w4h")
        cfg = {"cloud": "vmware", "env": name, "vars": {}}
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_local(cfg, {"kubernetes_control_plane_ips": ["10.0.0.5"]})
        self.assertIn(f"provision vmware --env {name} --host k8s", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_local(dict(cfg, vars={"enable_kubernetes": "yes"}), {})
        self.assertIn(f"cloudseed setup vmware --env {name}", cm.exception.msg)
        self.assertNotIn("--var", cm.exception.msg)


# ---------------------------------------------------------------- VPN through sudo

class _PidEnv:
    """An aws env with a VPN host and a running (faked) OpenVPN client whose pidfile names pid 4242."""

    def make(self):
        self.env, self.cfg = _env("aws")
        self.pf = services._pidfile(self.env)
        self.pf.write_text("4242\n")
        self.ours = f"openvpn --config x --daemon cloudseed-vpn --writepid {self.pf} --log-append y"
        self.alive = True

    def patches(self, call, tty=False, root=False, still_alive_after_kill=False):
        test = self

        def fake_call(cmd, **kw):
            rc = call(cmd, **kw)
            if rc == 0 and "kill" in cmd and not still_alive_after_kill:
                test.alive = False
            return rc
        return [mock.patch.object(services.os, "kill", side_effect=PermissionError),
                mock.patch.object(services, "_cmdline", side_effect=lambda pid: test.ours if test.alive else ""),
                mock.patch.object(services, "_has_tty", return_value=tty),
                mock.patch.object(services.os, "geteuid", return_value=0 if root else 501),
                mock.patch.object(services.subprocess, "call", side_effect=fake_call),
                mock.patch.object(services.time, "sleep")]


class DisconnectTests(unittest.TestCase, _PidEnv):
    """webui-backend#1: a refused or failed `sudo kill` never reports 'disconnected' or drops the pidfile."""

    def setUp(self):
        self.make()

    def run_disconnect(self, call, **kw):
        seen = []

        def record(cmd, **k):
            seen.append((list(cmd), k))
            return call(cmd, **k)
        with contextlib.ExitStack() as stack:
            for p in self.patches(record, **kw):
                stack.enter_context(p)
            out = stack.enter_context(_silenced())
            try:
                rc = services.disconnect(self.env)
                msg = ""
            except ui.Abort as e:
                rc, msg = e.code, e.msg
        return rc, msg, seen, out.getvalue()

    def test_sudo_needing_a_password_without_a_terminal(self):
        def refused(cmd, stderr=None, **kw):
            stderr.write("sudo: a password is required\n")
            return 1
        rc, msg, seen, out = self.run_disconnect(refused)
        self.assertNotEqual(rc, 0)
        self.assertEqual(seen[0][0], ["sudo", "-n", "kill", "-TERM", "4242"])   # no terminal: never waits for a password
        self.assertIn("needs your sudo password", msg)
        self.assertIn(f"cs vpn disconnect aws --env {self.env.name}", msg)
        self.assertIn("passwordless sudo for kill", msg)
        self.assertNotIn("disconnected", out)
        self.assertTrue(self.pf.exists())               # still connected: the pidfile stays

    def test_a_terminal_gets_the_password_prompt_and_root_needs_no_sudo(self):
        rc, _, seen, out = self.run_disconnect(lambda cmd, **kw: 0, tty=True)
        self.assertEqual((rc, seen[0][0]), (0, ["sudo", "kill", "-TERM", "4242"]))
        self.assertNotIn("stderr", seen[0][1])          # sudo talks to the terminal directly
        self.assertIn("VPN disconnected", out)
        self.assertFalse(self.pf.exists())
        self.make()
        rc, _, seen, _ = self.run_disconnect(lambda cmd, **kw: 0, root=True)
        self.assertEqual((rc, seen[0][0]), (0, ["kill", "-TERM", "4242"]))

    def test_a_failed_kill_on_a_terminal(self):
        rc, msg, _, out = self.run_disconnect(lambda cmd, **kw: 1, tty=True)
        self.assertEqual(rc, 1)
        self.assertIn("Could not stop OpenVPN (pid 4242): `sudo kill` exited with 1", msg)
        self.assertIn("sudo kill -TERM 4242", msg)
        self.assertTrue(self.pf.exists())

    def test_a_client_that_does_not_stop(self):
        clock = iter(range(0, 1000, 3))
        with mock.patch.object(services.time, "monotonic", side_effect=lambda: next(clock)):
            rc, msg, _, out = self.run_disconnect(lambda cmd, **kw: 0, tty=True, still_alive_after_kill=True)
        self.assertEqual(rc, 1)
        self.assertIn("still running", msg)
        self.assertIn("sudo kill -KILL 4242", msg)
        self.assertNotIn("VPN disconnected", out)
        self.assertTrue(self.pf.exists())

    def test_a_client_that_ended_meanwhile(self):
        def gone(cmd, stderr=None, **kw):
            self.alive = False
            stderr.write("kill: 4242: No such process\n")
            return 1
        rc, msg, _, out = self.run_disconnect(gone)
        self.assertEqual((rc, msg), (0, ""))
        self.assertIn("already stopped", out)
        self.assertFalse(self.pf.exists())


class DisconnectUndoTests(life.LifeBase):
    """Through the CLI: a refused disconnect exits non-zero and records no undo entry."""

    def test_refused_kill_records_nothing(self):
        (self.env.dir / "outputs.json").write_text(json.dumps({"vpn_public_ip": "192.0.2.9", "vpn_type": "openvpn"}))
        pf = services._pidfile(self.env)
        pf.write_text("4242\n")
        ours = f"openvpn --config x --daemon cloudseed-vpn --writepid {pf} --log-append y"
        recorded = []

        def refused(cmd, stderr=None, **kw):
            stderr.write("sudo: a password is required\n")
            return 1
        with mock.patch.object(undo, "record", side_effect=lambda *a, **k: recorded.append(a)), \
                mock.patch.object(services.os, "kill", side_effect=PermissionError), \
                mock.patch.object(services, "_cmdline", return_value=ours), \
                mock.patch.object(services, "_has_tty", return_value=False), \
                mock.patch.object(services.os, "geteuid", return_value=501), \
                mock.patch.object(services.subprocess, "call", side_effect=refused):
            rc = self.run_cmd(cli.cmd_vpn, ["vpn", "disconnect", "aws", "--env", self.env_name])
        self.assertNotEqual(rc, 0)
        self.assertEqual(recorded, [])
        self.assertTrue(pf.exists())
        self.assertIn("needs your sudo password", self.out.getvalue())


class ConnectSudoTests(unittest.TestCase):
    """webui-backend#1: without a terminal, connect uses `sudo -n` and a refusal says so (not 'see openvpn.log')."""

    def setUp(self):
        self.env, self.cfg = _env("aws")
        (services.vpn_dir(self.env) / "me.ovpn").write_text("client\n")
        self.outputs = {"vpn_public_ip": "203.0.113.20", "vpn_type": "openvpn"}

    def connect(self, call, tty=False):
        seen = []

        def record(cmd, **kw):
            seen.append(list(cmd))
            return call(cmd, **kw)
        with mock.patch.object(services, "_running", return_value=None), \
                mock.patch.object(services, "ensure_openvpn_client", return_value="/opt/openvpn"), \
                mock.patch.object(services, "_has_tty", return_value=tty), \
                mock.patch.object(services.os, "geteuid", return_value=501), \
                mock.patch.object(services.subprocess, "call", side_effect=record), \
                mock.patch.object(services.time, "sleep"), _silenced() as out:
            try:
                rc, msg = services.connect(clouds.get("aws"), self.env, self.cfg, self.outputs, None), ""
            except ui.Abort as e:
                rc, msg = e.code, e.msg
        return rc, msg, seen, out.getvalue()

    def test_password_refusal(self):
        def refused(cmd, stderr=None, **kw):
            stderr.write("sudo: a password is required\n")
            return 1
        rc, msg, seen, out = self.connect(refused)
        self.assertEqual(seen[0][:3], ["sudo", "-n", "/opt/openvpn"])
        self.assertEqual(rc, 1)
        self.assertIn("needs your sudo password", msg)
        self.assertIn(f"Run it in a terminal: cs vpn connect aws --env {self.env.name}", msg)
        self.assertIn("passwordless sudo for openvpn", msg)
        self.assertNotIn("openvpn.log", msg)
        self.assertNotIn("sudo prompt", out)            # no prompt can appear without a terminal

    def test_not_in_sudoers(self):
        def denied(cmd, stderr=None, **kw):
            stderr.write("bob is not in the sudoers file.  This incident will be reported.\n")
            return 1
        _, msg, _, _ = self.connect(denied)
        self.assertIn("sudo does not let this user run openvpn", msg)

    def test_openvpn_itself_failing_points_at_its_log(self):
        def failed(cmd, stderr=None, **kw):
            stderr.write("Options error: something\n")
            return 1
        _, msg, _, _ = self.connect(failed)
        self.assertIn("OpenVPN failed to start (exit 1); see", msg)
        self.assertIn("openvpn.log", msg)

    def test_terminal_keeps_the_plain_sudo_prompt(self):
        rc, msg, seen, out = self.connect(lambda cmd, **kw: 1, tty=True)
        self.assertEqual(seen[0][:2], ["sudo", "/opt/openvpn"])
        self.assertIn("sudo prompt", out)
        self.assertIn("openvpn.log", msg)

    def test_refusal_phrases(self):
        self.assertEqual(services._sudo_refusal("sudo: a password is required\n")[0], "password")
        self.assertEqual(services._sudo_refusal("sudo: a terminal is required to read the password")[0], "password")
        self.assertEqual(services._sudo_refusal("sudo: sorry, you must have a tty to run sudo")[0], "password")   # requiretty
        self.assertEqual(services._sudo_refusal("Sorry, user bob is not allowed to execute '/bin/kill' as root")[0], "denied")
        self.assertIsNone(services._sudo_refusal("sudo: unable to resolve host box\nkill: 1: No such process"))
        self.assertIsNone(services._sudo_refusal(""))


# ---------------------------------------------------------------- certificate expiry

NOW = datetime.now(timezone.utc)


def _iso(days: int) -> str:
    return (NOW + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%SZ")


class CertDateTests(unittest.TestCase):
    def test_parse(self):
        want = datetime(2028, 12, 27, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(services._parse_cert_date("2028-12-27 12:00:00Z"), want)
        self.assertEqual(services._parse_cert_date("Dec 27 12:00:00 2028 GMT"), want)
        self.assertEqual(services._parse_cert_date("Dec  7 12:00:00 2028 GMT"), want.replace(day=7))
        self.assertIsNone(services._parse_cert_date("garbage"))
        self.assertIsNone(services._parse_cert_date(""))

    def test_expiry_text(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(services.expiry_text(now + timedelta(days=100, hours=1), now), ("expires 2026-04-11 (in 100 days)", "ok"))
        self.assertEqual(services.expiry_text(now + timedelta(days=29, hours=1), now)[1], "soon")
        self.assertEqual(services.expiry_text(now + timedelta(days=29, hours=23), now), ("expires 2026-01-30 (in 30 days)", "soon"))
        self.assertEqual(services.expiry_text(now + timedelta(days=30, hours=1), now)[1], "ok")
        self.assertEqual(services.expiry_text(now + timedelta(days=400), now, compact=True), ("until 2027-02-05", "ok"))
        self.assertEqual(services.expiry_text(now + timedelta(days=1), now, compact=True), ("expires in 1 day", "soon"))
        self.assertEqual(services.expiry_text(now + timedelta(hours=3), now), ("expires 2026-01-01 (in less than a day)", "soon"))
        self.assertEqual(services.expiry_text(now - timedelta(days=1), now), ("expired 2025-12-31", "expired"))
        self.assertEqual(services.expiry_text(None, now), ("expiry unknown", "unknown"))


class CertExpiryTests(unittest.TestCase):
    def setUp(self):
        self.env, self.cfg = _env("aws", key=True)
        self.outputs = {"vpn_public_ip": "203.0.113.30", "vpn_type": "openvpn"}
        self.cloud = clouds.get("aws")

    def test_parses_the_hosts_answer_in_one_call(self):
        seen = []

        def fake(cmd, **kw):
            seen.append(cmd)
            return _cp(0, "alice\t2028-12-27 12:00:00Z\nbob\tJan  5 10:00:00 2027 GMT\nserver\t2028-12-27 12:00:00Z\nodd\t??\n")
        with mock.patch.object(services.subprocess, "run", fake):
            certs = services.cert_expiry(self.cloud, self.env, self.cfg, self.outputs, connect_timeout=5)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][-1], "sudo /usr/local/sbin/cloudseed-vpn-client certs")
        self.assertEqual(seen[0][:3], ["ssh", "-o", "ConnectTimeout=5"])     # ssh's first value of an option wins
        self.assertEqual(certs["alice"].year, 2028)
        self.assertEqual(certs["bob"], datetime(2027, 1, 5, 10, 0, tzinfo=timezone.utc))
        self.assertIn("server", certs)
        self.assertIsNone(certs["odd"])

    def test_an_older_host_is_unknown_and_ssh_failure_explains(self):
        with mock.patch.object(services.subprocess, "run", return_value=_cp(2, "", "usage: x add|revoke <name> | list\n")):
            self.assertIsNone(services.cert_expiry(self.cloud, self.env, self.cfg, self.outputs))
        with mock.patch.object(services.subprocess, "run", return_value=_cp(255, "", "Connection timed out")):
            with self.assertRaises(ui.Abort) as cm:
                services.cert_expiry(self.cloud, self.env, self.cfg, self.outputs)
        self.assertIn(f"cloudseed update-ip aws --env {self.env.name}", cm.exception.msg)

    def test_tailscale_and_local_are_refused(self):
        with self.assertRaises(ui.Abort) as cm:
            services.cert_expiry(self.cloud, self.env, self.cfg, dict(self.outputs, vpn_type="tailscale"))
        self.assertIn("tailnet", cm.exception.msg)
        venv, vcfg = _env("vmware")
        with self.assertRaises(ui.Abort) as cm:
            services.cert_expiry(clouds.get("vmware"), venv, vcfg, {})
        self.assertIn("does not apply to vmware", cm.exception.msg)

    def test_users_report(self):
        (services.vpn_dir(self.env) / "alice.ovpn").write_text("x")
        answer = f"alice\t{_iso(400)}\nbob\t{_iso(10)}\nserver\t{_iso(5)}\n"
        with mock.patch.object(services.subprocess, "run", return_value=_cp(0, answer)), _silenced() as out:
            self.assertEqual(services.users_report(self.cloud, self.env, self.cfg, self.outputs), 0)
        text = out.getvalue()
        lines = [line for line in text.splitlines() if line.strip().startswith(("alice", "bob", "server"))]
        self.assertEqual([line.split()[0] for line in lines], ["alice", "bob"])   # the server is no user
        self.assertIn("profile on this machine", lines[0])
        self.assertIn("(in 400 days)", lines[0])
        self.assertIn(f"issue a new profile with cloudseed vpn add-user aws --env {self.env.name} bob", text)
        self.assertIn(f"renew it with cloudseed vpn provision aws --env {self.env.name}", text)

    def test_users_report_on_an_older_host(self):
        answers = iter([_cp(2, "", "usage: ...\n"), _cp(0, "alice\n")])
        with mock.patch.object(services.subprocess, "run", side_effect=lambda cmd, **kw: next(answers)), _silenced() as out:
            services.users_report(self.cloud, self.env, self.cfg, self.outputs)
        self.assertIn("alice", out.getvalue())
        self.assertIn("Expiry dates need a newer VPN host script", out.getvalue())

    def test_users_report_without_users(self):
        with mock.patch.object(services.subprocess, "run", return_value=_cp(0, f"server\t{_iso(700)}\n")), _silenced() as out:
            services.users_report(self.cloud, self.env, self.cfg, self.outputs)
        self.assertIn("No client certificates yet", out.getvalue())
        self.assertNotIn("renew", out.getvalue())


class StatusCertTests(unittest.TestCase):
    def setUp(self):
        self.env, self.cfg = _env("aws", key=True)
        self.outputs = {"vpn_public_ip": "203.0.113.40", "vpn_type": "openvpn"}

    def status(self, certs=None, raises=None, **kw):
        side = raises if raises else (lambda *a, **k: certs)
        with mock.patch.object(services, "cert_expiry", side_effect=side) as ce, _silenced() as out:
            services.status(self.env, self.cfg, self.outputs, **kw)
        return " ".join(out.getvalue().replace("\u2502", " ").split()), ce     # the panel's wrapping undone

    def test_server_row_and_profile_expiry(self):
        (services.vpn_dir(self.env) / "alice.ovpn").write_text("x")
        (services.vpn_dir(self.env) / "gone.ovpn").write_text("x")
        server = NOW + timedelta(days=12)
        text, ce = self.status({"server": server, "alice": NOW + timedelta(days=300)})
        self.assertIn("Server cert", text)
        self.assertIn(f"expires {server:%Y-%m-%d}", text)
        self.assertIn(f"renew: cloudseed vpn provision aws --env {self.env.name}", text)
        self.assertIn("alice (until ", text)
        self.assertIn("gone (not issued by this VPN host)", text)
        self.assertIn(f"cloudseed vpn add-user aws --env {self.env.name} gone", text)
        self.assertEqual(ce.call_args[1].get("connect_timeout"), 5)

    def test_unknown_cases_never_fail_the_panel(self):
        text, _ = self.status(raises=ui.Abort("ssh failed"))
        self.assertIn("did not answer", text)
        self.assertIn("Connected", text)
        text, _ = self.status(raises=PermissionError(13, "Permission denied"))   # e.g. its known_hosts directory
        self.assertIn("did not answer", text)
        self.assertIn("Connected", text)
        text, _ = self.status(None)
        self.assertIn("predates expiry checks", text)
        (self.env.ssh_dir / "id_ed25519").unlink()
        text, ce = self.status({})
        self.assertIn("SSH key is not on this machine", text)
        ce.assert_not_called()

    def test_no_probe_when_it_cannot_apply(self):
        for outputs, kw in (({"vpn_type": "openvpn"}, {}), ({"vpn_public_ip": "203.0.113.41", "vpn_type": "tailscale"}, {}),
                            (self.outputs, {"certs": False})):
            with mock.patch.object(services, "cert_expiry") as ce, _silenced() as out:
                services.status(self.env, self.cfg, outputs, **kw)
            ce.assert_not_called()
            self.assertNotIn("Server cert", out.getvalue())


# ---------------------------------------------------------------- managed passthrough in agent sessions

class ManagedTerminalTests(unittest.TestCase):
    """need cli-cluster/docs: a redacted (agent) run refuses what needs a terminal, before installing or echoing."""

    def test_needs_terminal(self):
        nt = managed.needs_terminal
        self.assertIn("browser", nt("databricks", ["auth", "login", "--host", "https://x"], piped=False))
        self.assertIn("browser", nt("databricks", ["-p", "prof", "auth", "login"], piped=True))
        self.assertIsNone(nt("databricks", ["clusters", "list", "-o", "json"], piped=False))
        self.assertIsNone(nt("databricks", ["-p", "auth", "clusters", "list"], piped=False))   # 'auth' is -p's value
        self.assertIn("configure", nt("databricks", ["configure"], piped=False))
        self.assertIsNone(nt("databricks", ["configure", "--host", "https://x"], piped=True))   # token on stdin
        self.assertIn("SQL shell", nt("snowflake", ["sql"], piped=False))
        self.assertIsNone(nt("snowflake", ["sql", "-q", "select 1"], piped=False))
        self.assertIsNone(nt("snowflake", ["sql", "--query=select 1"], piped=False))
        self.assertIsNone(nt("snowflake", ["sql", "-i"], piped=True))
        self.assertIn("--no-interactive", nt("snowflake", ["connection", "add"], piped=False))
        self.assertIsNone(nt("snowflake", ["connection", "add", "--no-interactive", "-n", "x"], piped=False))
        self.assertIsNone(nt("snowflake", ["-c", "sql", "connection", "test"], piped=False))
        self.assertIn("browser", nt("databricks", ["--", "auth", "login"], piped=False))
        self.assertEqual(managed._words("databricks", ["fs", "cp", "--", "-x", "auth"]), ["fs", "cp", "-x", "auth"])

    def test_help_never_needs_a_terminal(self):
        nt = managed.needs_terminal
        self.assertIsNone(nt("databricks", ["auth", "login", "--help"], piped=False))
        self.assertIsNone(nt("databricks", ["auth", "login", "-h"], piped=False))
        self.assertIsNone(nt("snowflake", ["sql", "--help"], piped=False))
        # snow connection add's -h is --host, not help; after `--` nothing is an option
        self.assertIsNotNone(nt("snowflake", ["connection", "add", "-h", "acct.example.com"], piped=False))
        self.assertIsNotNone(nt("databricks", ["auth", "login", "--", "--help"], piped=False))

    def test_dev_null_is_no_input(self):
        """Agent, MCP and console sessions run commands with stdin on /dev/null: not a terminal, but no input either,
        so a prompt would only read end-of-file - the interactive commands are refused there too."""
        def piped_with(fh):
            with mock.patch.object(managed.sys, "stdin", fh):
                return managed._stdin_piped()
        with open(os.devnull) as fh:
            self.assertFalse(piped_with(fh))
        r, w = os.pipe()
        try:
            with os.fdopen(r) as fh:
                self.assertTrue(piped_with(fh))
        finally:
            os.close(w)
        with tempfile.TemporaryFile("w+") as fh:
            self.assertTrue(piped_with(fh))
        self.assertFalse(piped_with(None))
        self.assertFalse(piped_with(io.StringIO("x")))        # no file descriptor: nothing to hand on
        with mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": "1"}), open(os.devnull) as fh, \
                mock.patch.object(managed.sys, "stdin", fh), mock.patch.object(managed, "ensure_tool") as et, \
                _silenced():
            with self.assertRaises(ui.Abort) as cm:
                managed.run("snowflake", "default", ["sql"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("interactive SQL shell", cm.exception.msg)
        et.assert_not_called()

    def test_redacted_run_refuses_before_anything(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": "1"}), \
                mock.patch.object(managed, "ensure_tool") as et, mock.patch.object(managed.subprocess, "call") as call, \
                mock.patch.object(managed, "_stdin_piped", return_value=False), _silenced() as out:
            with self.assertRaises(ui.Abort) as cm:
                managed.run("databricks", "default", ["auth", "login", "--host", "https://x"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("cs databricks auth login --host https://x", cm.exception.msg)
        self.assertIn("own terminal", cm.exception.msg)
        et.assert_not_called()
        call.assert_not_called()
        self.assertEqual(out.getvalue(), "")

    def test_the_terminal_command_repeats_this_run(self):
        """The suggested command must do the same thing when typed: the profile in use named, and the vendor's own
        --profile / trailing -y kept away from cloudseed behind a `--` (cloudseed would take them as its own)."""
        tc = managed.terminal_command
        self.assertEqual(tc("databricks", "default", ["auth", "login"]), "cs databricks auth login")
        self.assertEqual(tc("databricks", "prod", ["auth", "login", "--host", "https://x"]),
                         "cs databricks --profile prod auth login --host https://x")
        self.assertEqual(tc("databricks", "default", ["auth", "login", "--profile", "theirs"]),
                         "cs databricks -- auth login --profile theirs")
        self.assertEqual(tc("databricks", "aws-dev", ["-p", "theirs", "auth", "login"]),
                         "cs databricks --profile aws-dev -- -p theirs auth login")
        self.assertEqual(tc("snowflake", "default", ["connection", "add", "-y"]), "cs snowflake -- connection add -y")
        self.assertEqual(tc("snowflake", "default", ["connection", "add", "-p", "S3cret!"]),
                         "cs snowflake connection add -p '[REDACTED]'")
        with mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": "1"}), mock.patch.object(managed, "ensure_tool") as et, \
                mock.patch.object(managed, "_stdin_piped", return_value=False), _silenced():
            with self.assertRaises(ui.Abort) as cm:
                managed.run("databricks", "prod", ["auth", "login"])
        self.assertIn("Run it in your own terminal instead: cs databricks --profile prod auth login", cm.exception.msg)
        et.assert_not_called()

    def test_redacted_run_still_runs_plain_commands(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": "1"}), \
                mock.patch.object(managed, "ensure_tool", return_value="databricks"), \
                mock.patch.object(managed, "_stdin_piped", return_value=False), \
                mock.patch.object(managed, "_stdin_inheritable", return_value=False), \
                mock.patch.object(managed.secrets, "run_redacted", return_value=0) as rr, _silenced():
            self.assertEqual(managed.run("databricks", "default", ["clusters", "list"]), 0)
        self.assertEqual(rr.call_args[0][0], ["databricks", "clusters", "list"])
        self.assertIs(rr.call_args[1]["stdin"], subprocess.DEVNULL)

    def test_a_terminal_run_is_not_restricted(self):
        env = {k: v for k, v in os.environ.items() if k != "CLOUDSEED_REDACT"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(managed, "ensure_tool", return_value="databricks"), \
                mock.patch.object(managed.subprocess, "call", return_value=0) as call, _silenced():
            self.assertEqual(managed.run("databricks", "default", ["auth", "login"]), 0)
        self.assertEqual(call.call_args[0][0], ["databricks", "auth", "login"])


if __name__ == "__main__":
    unittest.main()
