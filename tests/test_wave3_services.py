"""Wave 3 regression tests for services.py (kubeconfig merge, VPN on local targets and Tailscale, install consent) and
managed.py (per-tool -p masking, the Databricks CLI's own profile, redacted output in agent sessions).
Offline, stdlib only: kubectl is used when installed (those tests are skipped otherwise), everything else is faked."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, clouds, managed, paths, secrets, services, ui  # noqa: E402

_AGENT_VARS = ("CLOUDSEED_AGENT", "CLOUDSEED_REDACT", "CLOUDSEED_AUTO_INSTALL")


@contextlib.contextmanager
def _silenced():
    """stdout and stderr (ui.warn / ui.info) into one buffer."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield buf


@contextlib.contextmanager
def _clean_env(**extra):
    """os.environ without the agent/consent switches of the calling shell, plus `extra`."""
    env = {k: v for k, v in os.environ.items() if k not in _AGENT_VARS}
    env.update(extra)
    with mock.patch.dict(os.environ, env, clear=True):
        yield


def _env(cloud: str, name: str, vars_: dict | None = None):
    env = paths.Env(cloud, name)
    env.create_dirs()
    cfg = {"env": name, "cloud": cloud, "region": "r", "network_cidr": "10.0.0.0/16", "vars": dict(vars_ or {}),
           "workdir": str(env.dir)}
    return env, cfg


# ---------------------------------------------------------------- cs k8s kubeconfig (vmware): the merge

class KubeconfigMergeTests(unittest.TestCase):
    """a2-platform-logic#4: the merge into the user's kubeconfig keeps their file references (never inlines their
    certificates/keys), and an entry of theirs that names a missing file does not block it."""

    def setUp(self):
        if not shutil.which("kubectl"):
            self.skipTest("kubectl not installed")
        self.tmp = Path(tempfile.mkdtemp())
        home = self.tmp / "home" / ".kube"
        home.mkdir(parents=True)
        self.target = home / "config"
        keys = self.tmp / "home" / "keys"
        keys.mkdir()
        for f, body in (("ca.crt", "FAKECA\n"), ("c.crt", "FAKECERT\n"), ("c.key", "FAKEKEY\n")):
            (keys / f).write_text(body)
        mine = {"apiVersion": "v1", "kind": "Config", "current-context": "minikube", "preferences": {},
                "clusters": [{"name": "minikube", "cluster": {"server": "https://192.0.2.10:8443",
                                                              "certificate-authority": str(keys / "ca.crt")}}],
                "users": [{"name": "minikube", "user": {"client-certificate": str(keys / "c.crt"),
                                                        "client-key": str(keys / "c.key")}},
                          {"name": "rel", "user": {"client-certificate": "../keys/c.crt", "client-key": "../keys/c.key"}},
                          {"name": "stale", "user": {"client-certificate": str(self.tmp / "gone.crt"),
                                                     "client-key": str(self.tmp / "gone.key")}}],
                "contexts": [{"name": "minikube", "context": {"cluster": "minikube", "user": "minikube"}},
                             {"name": "rel", "context": {"cluster": "minikube", "user": "rel"}},
                             {"name": "stale", "context": {"cluster": "minikube", "user": "stale"}}]}
        self.target.write_text(json.dumps(mine))
        self.patch = mock.patch.dict(os.environ, {"KUBECONFIG": str(self.target)})
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cloudseed_kc(self, name: str, ca_relative: bool = False) -> dict:
        wd = self.tmp / name
        (wd / "k8s").mkdir(parents=True)
        cluster = {"server": "https://10.100.0.10:6443"}
        if ca_relative:   # a file reference relative to <workdir>/k8s: must become inline data in the user's file
            (wd / "k8s" / "rke2-ca.crt").write_text("RKE2CA\n")
            cluster["certificate-authority"] = "rke2-ca.crt"
        kc = {"apiVersion": "v1", "kind": "Config", "current-context": "default",
              "clusters": [{"name": "default", "cluster": cluster}],
              "users": [{"name": "default", "user": {"token": "cs-token-" + name}}],
              "contexts": [{"name": "default", "context": {"cluster": "default", "user": "default"}}]}
        (wd / "k8s" / "kubeconfig").write_text(json.dumps(kc))
        return {"env": name, "workdir": str(wd), "vars": {"enable_kubernetes": True}}

    def _view(self) -> dict:
        out = subprocess.run(["kubectl", "config", "view", "--raw", "-o", "json"], capture_output=True, text=True,
                             env=dict(os.environ, KUBECONFIG=str(self.target)))
        return json.loads(out.stdout)

    def test_users_file_references_stay_references(self):
        with _silenced():
            rc = services.kubeconfig_local(self._cloudseed_kc("lab", ca_relative=True), {"kubernetes_control_plane_ips": ["10.100.0.10"]})
        self.assertEqual(rc, 0)   # the 'stale' entry's missing files did not abort the merge
        text = self.target.read_text()
        self.assertNotIn("client-key-data", text)
        self.assertNotIn("client-certificate-data", text)
        self.assertNotIn("RkFLRUtFWQ", text)    # base64 of the user's key never lands in the file
        self.assertIn("../keys/c.key", text)    # relative references stay relative
        view = self._view()
        users = {u["name"]: u["user"] for u in view["users"]}
        self.assertEqual(users["minikube"].get("client-key"), str(self.tmp / "home" / "keys" / "c.key"))
        self.assertNotIn("client-key-data", users["minikube"])
        self.assertEqual(users["vmware-lab"].get("token"), "cs-token-lab")
        clusters = {c["name"]: c["cluster"] for c in view["clusters"]}
        self.assertIn("certificate-authority", clusters["minikube"])
        self.assertNotIn("certificate-authority-data", clusters["minikube"])
        # cloudseed's own relative CA reference was made self-contained before the merge
        self.assertIn("certificate-authority-data", clusters["vmware-lab"])
        self.assertNotIn("certificate-authority", clusters["vmware-lab"])
        self.assertEqual(view["current-context"], "vmware-lab")
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)


class LocalKubeconfigAdviceTests(unittest.TestCase):
    """a2-cli-lifecycle#9: `cs k8s kubeconfig vmware` without a kubeconfig names the one command that helps."""

    def _cfg(self, name, vars_=None):
        wd = Path(tempfile.mkdtemp())
        return {"env": name, "workdir": str(wd), "vars": dict(vars_ or {})}

    def _msg(self, cfg, outputs):
        with self.assertRaises(ui.Abort) as cm:
            services.kubeconfig_local(cfg, outputs)
        return cm.exception.msg

    def test_three_cases(self):
        msg = self._msg(self._cfg("dev"), {})
        self.assertIn("--var enable_kubernetes=true", msg)
        self.assertNotIn("provision", msg)
        msg = self._msg(self._cfg("dev", {"enable_kubernetes": True}), {})
        self.assertIn("not created yet", msg)
        self.assertIn("cloudseed setup vmware --env dev", msg)
        self.assertNotIn("enable_kubernetes=true", msg)
        msg = self._msg(self._cfg("dev", {"enable_kubernetes": True}), {"kubernetes_control_plane_ips": ["10.1.0.5"]})
        self.assertIn("cloudseed provision vmware --env dev --host k8s", msg)

    def test_ensure_kubeconfig_gives_the_same_advice(self):
        env, cfg = _env("vmware", "w3kadv")
        with self.assertRaises(ui.Abort) as cm:
            services.ensure_kubeconfig(clouds.get("vmware"), env, cfg, {})
        self.assertIn("--var enable_kubernetes=true", cm.exception.msg)

    def test_a_refused_request_leaves_no_k8s_directory(self):
        for cloud in ("vmware", "aws"):
            env, cfg = _env(cloud, "w3knodir")
            shutil.rmtree(env.dir / "k8s", ignore_errors=True)   # CLOUDSEED_HOME may outlive a run
            with self.assertRaises(ui.Abort):
                services.ensure_kubeconfig(clouds.get(cloud), env, cfg, {})
            self.assertFalse((env.dir / "k8s").exists(), cloud)


# ---------------------------------------------------------------- VPN on a local target

class LocalVpnTests(unittest.TestCase):
    """a2-cli-ux#7 / a2-cli-lifecycle#9 / a2-docs-skills#0: no VPN subcommand on vmware advises enable_vpn=true (which
    setup refuses there); they all say the VPN does not apply and how the VMs are reached."""

    def setUp(self):
        self.env, self.cfg = _env("vmware", "w3lvpn")
        shutil.rmtree(self.env.dir / "vpn", ignore_errors=True)   # CLOUDSEED_HOME may outlive a run
        self.cloud = clouds.get("vmware")

    def test_every_operation_says_not_applicable(self):
        calls = {"vpn_host": lambda: services.vpn_host(self.cloud, self.env, self.cfg, {}),
                 "add_user": lambda: services.add_user(self.cloud, self.env, self.cfg, {}, "bob"),
                 "revoke_user": lambda: services.revoke_user(self.cloud, self.env, self.cfg, {}, "bob"),
                 "list_users": lambda: services.list_users(self.cloud, self.env, self.cfg, {}),
                 "connect": lambda: services.connect(self.cloud, self.env, self.cfg, {}, None)}
        for what, fn in calls.items():
            with mock.patch.object(services.subprocess, "run") as run, mock.patch.object(services.subprocess, "call") as call, \
                    _silenced() as out:
                with self.assertRaises(ui.Abort, msg=what) as cm:
                    fn()
            msg = cm.exception.msg
            self.assertIn("does not apply to vmware", msg, what)
            self.assertIn(services.VPN_LOCAL_REASON, msg, what)
            self.assertIn("cloudseed ssh vmware --env w3lvpn", msg, what)
            self.assertNotIn("enable_vpn", msg + out.getvalue(), what)
            self.assertNotIn("creating one", out.getvalue(), what)
            run.assert_not_called()
            call.assert_not_called()

    def test_status_shows_not_applicable_and_no_dead_end_hints(self):
        with _silenced() as out:
            services.status(self.env, self.cfg, {})
        text = out.getvalue()
        self.assertIn("not applicable on vmware", text)
        self.assertIn("cs ssh vmware --env w3lvpn", text)
        for bad in ("enable_vpn", "add-user", "Local profiles"):
            self.assertNotIn(bad, text)
        self.assertFalse((self.env.dir / "vpn").exists())   # a read-only status creates nothing

    def test_the_reason_matches_setups_refusal(self):
        from cloudseed import cli
        self.assertEqual(services.VPN_LOCAL_REASON, cli.LOCAL_NOT_APPLICABLE["enable_vpn"])

    def test_local_is_the_targets_own_flag(self):
        # without a cloud object (cmd_vpn's status call) the environment's cloud key decides, through the registry
        self.assertTrue(services._is_local(None, self.env, {}))
        self.assertTrue(services._is_local(None, None, {"cloud": "vmware"}))
        for key in ("aws", "gcp", "azure", "nosuchcloud"):
            self.assertFalse(services._is_local(None, None, {"cloud": key}), key)
        self.assertFalse(services._is_local(None, None, {}))
        self.assertFalse(services._is_local(clouds.get("aws"), self.env, self.cfg))   # the cloud object wins


class CloudVpnTests(unittest.TestCase):
    def test_connect_without_a_vpn_host_fails_before_announcing_a_profile(self):
        env, cfg = _env("aws", "w3novpn")
        with mock.patch.object(services, "add_user") as add, mock.patch.object(services, "ensure_openvpn_client") as ovpn, \
                _silenced() as out:
            with self.assertRaises(ui.Abort) as cm:
                services.connect(clouds.get("aws"), env, cfg, {}, None)
        self.assertIn("--var enable_vpn=true", cm.exception.msg)   # a cloud env: enabling it is the right advice
        self.assertNotIn("No client profile yet", out.getvalue())
        add.assert_not_called()
        ovpn.assert_not_called()

    def test_connect_checks_the_client_before_issuing_a_certificate(self):
        env, cfg = _env("aws", "w3noclient")
        outputs = {"vpn_public_ip": "203.0.113.9", "vpn_type": "openvpn"}
        with _clean_env(), mock.patch.object(services.deps, "find", return_value=None), \
                mock.patch.object(services.deps, "install") as inst, mock.patch.object(services, "add_user") as add, \
                mock.patch.object(services.ui, "interactive", return_value=False), \
                mock.patch.object(services, "_running", return_value=None), _silenced():
            with self.assertRaises(ui.Abort) as cm:
                services.connect(clouds.get("aws"), env, cfg, outputs, None)
        self.assertEqual(cm.exception.code, 2)   # documented: -y without consent stops with exit code 2
        self.assertIn("CLOUDSEED_AUTO_INSTALL=1", cm.exception.msg)
        add.assert_not_called()
        inst.assert_not_called()

    def test_revoke_on_tailscale_explains_instead_of_running_the_openvpn_script(self):   # a2-ansible#17
        env, cfg = _env("aws", "w3ts", {"enable_vpn": True, "vpn_type": "tailscale"})
        outputs = {"vpn_public_ip": "203.0.113.10", "vpn_type": "tailscale"}
        # subprocess is one module: these also stand in for provision.Host.run's ssh call
        with mock.patch.object(services.subprocess, "run") as run, mock.patch.object(services.subprocess, "call") as call, \
                mock.patch.object(services.subprocess, "Popen") as popen:
            with self.assertRaises(ui.Abort) as cm:
                services.revoke_user(clouds.get("aws"), env, cfg, outputs, "alice")
        self.assertIn("tailnet", cm.exception.msg)
        self.assertNotIn("Revocation failed", cm.exception.msg)
        for m in (run, call, popen):
            m.assert_not_called()

    def test_a_failed_revoke_says_what_to_do(self):
        env, cfg = _env("aws", "w3rev", {"enable_vpn": True})
        (env.dir / "vpn").mkdir(exist_ok=True)
        (env.dir / "vpn" / "alice.ovpn").write_text("x")
        outputs = {"vpn_public_ip": "203.0.113.13", "vpn_type": "openvpn"}
        with mock.patch.object(services.prov.Host, "run", return_value=255):
            with self.assertRaises(ui.Abort) as cm:
                services.revoke_user(clouds.get("aws"), env, cfg, outputs, "alice")
        self.assertIn("203.0.113.13", cm.exception.msg)
        self.assertIn("cloudseed update-ip aws --env w3rev", cm.exception.msg)
        self.assertTrue((env.dir / "vpn" / "alice.ovpn").exists())   # nothing revoked: the profile stays
        with mock.patch.object(services.prov.Host, "run", return_value=0), mock.patch.object(services.audit, "note"):
            services.revoke_user(clouds.get("aws"), env, cfg, outputs, "alice")
        self.assertFalse((env.dir / "vpn" / "alice.ovpn").exists())

    def test_status_hints_fit_the_vpn_type(self):
        env, cfg = _env("aws", "w3stat", {"vpn_type": "tailscale", "enable_vpn": True})
        with _silenced() as out:
            services.status(env, cfg, {"vpn_public_ip": "203.0.113.11", "vpn_type": "tailscale"})
        self.assertNotIn("add-user", out.getvalue())
        self.assertIn("tailnet", out.getvalue())
        env2, cfg2 = _env("aws", "w3stat2")
        with _silenced() as out:
            services.status(env2, cfg2, {})
        self.assertIn("cs setup aws --env w3stat2 --var enable_vpn=true", out.getvalue())
        self.assertNotIn("add-user", out.getvalue())   # no host yet: adding a user would fail
        with _silenced() as out:
            services.status(env2, cfg2, {"vpn_public_ip": "203.0.113.12"})
        self.assertIn("cs vpn add-user aws --env w3stat2 <name>", out.getvalue())


# ---------------------------------------------------------------- install consent

class InstallConsentTests(unittest.TestCase):
    """need-ops (agentic#1): an agent session never installs software, even with --auto-approve on the command line;
    need-docs: the -y message names what works for every command (CLOUDSEED_AUTO_INSTALL=1), not --auto-approve."""

    def _missing(self, argv, interactive=False, **env):
        with _clean_env(**env), mock.patch.object(services.deps, "find", return_value=None), \
                mock.patch.object(services.deps, "install") as inst, mock.patch.object(services.ui, "interactive", return_value=interactive), \
                mock.patch.object(services.ui, "confirm", return_value=True) as confirm, \
                mock.patch.object(services.sys, "argv", argv), _silenced():
            with self.assertRaises(ui.Abort) as cm:
                services.ensure_tool("kubectl", "to talk to the cluster")
        return cm.exception, inst, confirm

    def test_agent_sessions_never_install(self):
        for env in ({"CLOUDSEED_AGENT": "claude"}, {"CLOUDSEED_REDACT": "1"}):
            for interactive in (False, True):
                e, inst, confirm = self._missing(["cloudseed", "platform", "install", "keda", "--auto-approve"], interactive, **env)
                self.assertEqual(e.code, 2, env)
                self.assertIn("cloudseed install kubectl", e.msg)
                self.assertIn("agent session", e.msg)
                inst.assert_not_called()
                confirm.assert_not_called()

    def test_unattended_message_names_what_every_command_accepts(self):
        e, inst, _ = self._missing(["cloudseed", "-y", "kubectl", "get", "pods"])
        self.assertEqual(e.code, 2)
        self.assertIn("cloudseed install kubectl", e.msg)
        self.assertIn("CLOUDSEED_AUTO_INSTALL=1", e.msg)
        self.assertNotIn("--auto-approve", e.msg)
        inst.assert_not_called()

    def test_mcp_and_explicit_consent_still_install(self):
        for env, argv in (({"CLOUDSEED_AGENT": "mcp"}, ["cloudseed", "platform", "install", "keda", "-y", "--auto-approve"]),
                          ({"CLOUDSEED_AUTO_INSTALL": "1"}, ["cloudseed", "-y", "kubectl", "get", "pods"])):
            with _clean_env(**env), mock.patch.object(services.deps, "find", side_effect=[None, "/bin/kubectl"]), \
                    mock.patch.object(services.deps, "install") as inst, mock.patch.object(services.ui, "interactive", return_value=False), \
                    mock.patch.object(services.sys, "argv", argv), _silenced():
                self.assertEqual(services.ensure_tool("kubectl", "x"), "/bin/kubectl")
            inst.assert_called_once_with("kubectl")

    def test_gke_plugin_is_not_installed_for_an_agent(self):
        with _clean_env(CLOUDSEED_AGENT="codex"), mock.patch.object(services.deps, "find", return_value=None), \
                mock.patch.object(services, "_gcloud_sdk_root", return_value=None), \
                mock.patch.object(services.sys, "argv", ["cloudseed", "--auto-approve"]), \
                mock.patch.object(services.subprocess, "run") as run, _silenced():
            with self.assertRaises(ui.Abort) as cm:
                services.ensure_gke_auth_plugin("/bin/gcloud")
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("cloudseed install gke-gcloud-auth-plugin", cm.exception.msg)
        run.assert_not_called()
        with _clean_env(), mock.patch.object(services.deps, "find", return_value=None), \
                mock.patch.object(services, "_gcloud_sdk_root", return_value=None), \
                mock.patch.object(services.ui, "interactive", return_value=False), \
                mock.patch.object(services.sys, "argv", ["cloudseed", "-y", "k8s", "kubeconfig"]), \
                mock.patch.object(services.subprocess, "run") as run, _silenced():
            with self.assertRaises(ui.Abort) as cm:
                services.ensure_gke_auth_plugin("/bin/gcloud")
        self.assertIn("CLOUDSEED_AUTO_INSTALL=1", cm.exception.msg)
        self.assertNotIn("--auto-approve", cm.exception.msg)
        run.assert_not_called()

    def test_openvpn_client_consent(self):
        with _clean_env(CLOUDSEED_AGENT="claude"), mock.patch.object(services.deps, "find", return_value=None), \
                mock.patch.object(services.deps, "install") as inst, mock.patch.object(services.ui, "interactive", return_value=True), \
                _silenced():
            with self.assertRaises(ui.Abort) as cm:
                services.ensure_openvpn_client()
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("cloudseed install openvpn", cm.exception.msg)
        inst.assert_not_called()
        with _clean_env(), mock.patch.object(services.deps, "find", return_value=None), \
                mock.patch.object(services.deps, "install") as inst, mock.patch.object(services.ui, "interactive", return_value=True), \
                mock.patch.object(services.ui, "confirm", return_value=False), _silenced():
            with self.assertRaises(ui.Abort) as cm:
                services.ensure_openvpn_client()
        self.assertEqual(cm.exception.code, 1)   # declined on a terminal
        inst.assert_not_called()
        with _clean_env(CLOUDSEED_AUTO_INSTALL="1"), mock.patch.object(services.deps, "find", side_effect=[None, "/bin/openvpn"]), \
                mock.patch.object(services.deps, "install") as inst, mock.patch.object(services.ui, "interactive", return_value=False), \
                _silenced():
            self.assertEqual(services.ensure_openvpn_client(), "/bin/openvpn")
        inst.assert_called_once_with("openvpn")
        with _clean_env(CLOUDSEED_AUTO_INSTALL="1"), mock.patch.object(services.deps, "find", return_value=None), \
                mock.patch.object(services.deps, "install", return_value=False), \
                mock.patch.object(services.ui, "interactive", return_value=False), _silenced():
            with self.assertRaises(ui.Abort) as cm:
                services.ensure_openvpn_client()
        self.assertIn("Could not install", cm.exception.msg)


# ---------------------------------------------------------------- managed CLIs

class ManagedMaskTests(unittest.TestCase):
    """a2-platform-logic#31: -p is a secret for snow and helm only (databricks --profile, kubectl --previous/--patch)."""

    def test_per_tool_short_flags(self):
        R = secrets.REDACTED
        self.assertEqual(managed.mask_argv(["clusters", "list", "-p", "myprof"], "databricks"), ["clusters", "list", "-p", "myprof"])
        self.assertEqual(managed.mask_argv(["clusters", "list", "-p=myprof"], "databricks"), ["clusters", "list", "-p=myprof"])
        self.assertEqual(managed.mask_argv(["logs", "-p", "web-1"], "kubectl"), ["logs", "-p", "web-1"])
        self.assertEqual(managed.mask_argv(["registry", "login", "r", "-u", "me", "-p", "pw"], "helm")[-1], R)
        for tool in ("snowflake", "snow", None):   # unknown tool: masked, never leaked
            self.assertEqual(managed.mask_argv(["connection", "add", "-p", "SnowPass99"], tool)[-1], R, tool)
            self.assertEqual(managed.mask_argv(["connection", "add", "-p=SnowPass99"], tool)[-1], f"-p={R}", tool)
        # the always-secret flags stay masked for every tool
        for tool in ("databricks", "kubectl", "snowflake", None):
            self.assertNotIn("dapi0123456789", " ".join(managed.mask_argv(["x", "--pat", "dapi0123456789"], tool)))


class ManagedRunTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(managed.ui, "interactive", return_value=False), _silenced():
            managed.connect("databricks", "w3db", {"host": "https://cs-ws.cloud.databricks.com", "token": "dapiCloudseedToken123"})

    def test_databricks_own_profile(self):
        with mock.patch.object(managed, "ensure_tool", return_value="databricks"), \
                mock.patch.object(managed.subprocess, "call", return_value=0) as call, \
                mock.patch.object(managed.secrets, "redact_enabled", return_value=False), _silenced() as out:
            managed.run("databricks", "w3db", ["clusters", "list", "-p", "myprof"])
        env = call.call_args[1]["env"]
        self.assertNotIn("DATABRICKS_HOST", env)    # the CLI would let it override the host of the user's profile
        self.assertNotIn("DATABRICKS_TOKEN", env)
        text = out.getvalue()
        self.assertIn("databricks clusters list -p myprof", text)
        self.assertNotIn("REDACTED", text)
        self.assertNotIn("No Databricks profile", text)
        with mock.patch.object(managed, "ensure_tool", return_value="databricks"), \
                mock.patch.object(managed.subprocess, "call", return_value=0) as call, \
                mock.patch.object(managed.secrets, "redact_enabled", return_value=False), _silenced() as out:
            managed.run("databricks", "w3db", ["clusters", "list"])
        self.assertEqual(call.call_args[1]["env"]["DATABRICKS_HOST"], "https://cs-ws.cloud.databricks.com")
        self.assertIn("[databricks:w3db]", out.getvalue())
        with mock.patch.object(managed, "ensure_tool", return_value="databricks"), \
                mock.patch.object(managed.subprocess, "call", return_value=0), \
                mock.patch.object(managed.secrets, "redact_enabled", return_value=False), _silenced() as out, \
                _clean_env():
            os.environ.pop("DATABRICKS_HOST", None)
            managed.run("databricks", "nosuchprofile", ["clusters", "list", "--profile=prod"])
        self.assertNotIn("No Databricks profile", out.getvalue())

    def test_agent_sessions_get_redacted_output(self):   # agentic#10
        fake_stdin = mock.Mock()
        for tty, expect in ((True, subprocess.DEVNULL), (False, None)):
            fake_stdin.isatty.return_value = tty
            with mock.patch.object(managed, "ensure_tool", return_value="databricks"), \
                    mock.patch.object(managed.secrets, "redact_enabled", return_value=True), \
                    mock.patch.object(managed.secrets, "run_redacted", return_value=3) as rr, \
                    mock.patch.object(managed.subprocess, "call") as call, mock.patch.object(managed.sys, "stdin", fake_stdin), \
                    _silenced():
                self.assertEqual(managed.run("databricks", "w3db", ["clusters", "list"]), 3)
            call.assert_not_called()
            cmd, kw = rr.call_args[0][0], rr.call_args[1]
            self.assertEqual(cmd, ["databricks", "clusters", "list"])
            self.assertEqual(kw["env"]["DATABRICKS_HOST"], "https://cs-ws.cloud.databricks.com")
            self.assertIs(kw["stdin"], expect, tty)

    def test_redacted_run_really_redacts(self):
        # `databricks auth env` style output: the profile's own token (no recognisable shape) and a key pattern
        code = "import os; print('token', os.environ['DATABRICKS_TOKEN'], 'AKIA" + "IOSFODNN7EXAMPLE')"
        with mock.patch.object(managed, "ensure_tool", return_value=sys.executable), \
                mock.patch.object(managed.secrets, "redact_enabled", return_value=True), \
                mock.patch.object(managed.sys, "stdin", None), _silenced() as out:
            rc = managed.run("databricks", "w3db", ["-c", code])
        self.assertEqual(rc, 0)
        self.assertNotIn("AKIA" + "IOSFODNN7EXAMPLE", out.getvalue())
        self.assertNotIn("dapiCloudseedToken123", out.getvalue())
        self.assertIn("token " + secrets.REDACTED, out.getvalue())

    def test_audit_trail_still_masks_snowflake_passwords(self):
        snow = audit.safe_argv(["-y", "snowflake", "connection", "add", "-p", "Secr3tPw99"])
        self.assertNotIn("Secr3tPw99", " ".join(snow))


if __name__ == "__main__":
    unittest.main()
