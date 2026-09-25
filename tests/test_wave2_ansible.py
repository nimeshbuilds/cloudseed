"""Regression tests for the wave-2 Ansible/provisioning items: hand-offs from other groups that land in
cloudseed/provision.py and ansible/** (gcp#1, gcp#8, gcp#12, aws#1, vmware#21, platform-logic#15, resilience#22,
agentic#9, azure#24). Stdlib only, no network, no real hosts: subprocess is mocked or points at tiny local scripts."""

import configparser
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, paths, provision, ui  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (REPO / rel).read_text()


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class FakeProc:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = rc, stdout, stderr


# ---------------------------------------------------------------- Host.wait's advice (gcp#12, vmware#23)

class WaitAdviceTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.td.cleanup()

    def _env(self, cloud: str, cfg: dict) -> paths.Env:
        env = paths.Env(cloud, "wa", Path(self.td.name) / cloud)
        env.create_dirs()
        env.save(dict({"name": "cs", "env": "wa"}, **cfg))
        return env

    def _abort(self, env, stderr: str, user: str = "alice") -> str:
        h = provision.Host("198.51.100.9", user, Path(self.td.name) / "id_ed25519", "bastion", env=env)
        clock = iter([0, 0, 1000, 1000, 1000])
        with mock.patch.object(provision.subprocess, "run", return_value=FakeProc(255, "", stderr)), \
                mock.patch.object(provision.time, "time", side_effect=lambda: next(clock)), \
                mock.patch.object(provision.time, "sleep"), mock.patch.object(ui, "err"), mock.patch("builtins.print"):
            with self.assertRaises(ui.Abort) as cm:
                h.wait(timeout=5)
        return cm.exception.msg

    DENIED = "user_example_com@198.51.100.9: Permission denied (publickey).\n"
    TIMEOUT = "ssh: connect to host 198.51.100.9 port 22: Operation timed out\n"
    OS_LOGIN = {"account": "user@example.com", "user": "user_example_com", "member": "user:user@example.com"}

    def test_os_login_refusal_points_at_os_login_not_update_ip(self):
        env = self._env("gcp", {"vars": {"enable_os_login": True}, "os_login": self.OS_LOGIN})
        msg = self._abort(env, self.DENIED, user="user_example_com")
        self.assertIn("OS Login is on", msg)
        self.assertIn("user_example_com (the POSIX user of user@example.com)", msg)
        self.assertIn("gcloud compute os-login ssh-keys add --key-file", msg)
        self.assertIn("roles/compute.osAdminLogin", msg)
        self.assertIn("roles/iam.serviceAccountUser", msg)
        self.assertNotIn("update-ip", msg)                  # a refused key is never a firewall problem

    def test_os_login_timeout_names_both_causes(self):
        env = self._env("gcp", {"vars": {"enable_os_login": "true", "project_id": "my-proj-123"},   # a pre-gcp#13 string
                                "os_login": self.OS_LOGIN})
        msg = self._abort(env, self.TIMEOUT)
        self.assertIn("update-ip", msg)
        self.assertIn("roles/compute.osAdminLogin", msg)
        self.assertIn("Operation timed out", msg)
        self.assertIn("gcloud compute os-login describe-profile --project my-proj-123", msg)
        # the whole command: a bare `cloudseed provision` fails with 'needs a cloud' (a2-ansible#10, wave 4)
        self.assertEqual(msg.count("re-run `cloudseed provision gcp --env wa`"), 1)

    def test_os_login_without_a_registered_profile(self):
        env = self._env("gcp", {"vars": {"enable_os_login": True}})     # e.g. set up with --dry-run, applied later
        msg = self._abort(env, self.DENIED)
        self.assertIn("no OS Login profile is recorded for gcp-wa", msg)
        self.assertIn("metadata user alice", msg)
        self.assertIn("cloudseed setup gcp --env wa", msg)

    def test_plain_gcp_and_other_clouds_keep_the_network_advice(self):
        for cloud, cfg in (("gcp", {"vars": {"enable_os_login": False}, "os_login": self.OS_LOGIN}), ("aws", {"vars": {}})):
            msg = self._abort(self._env(cloud, cfg), self.TIMEOUT)
            self.assertIn("update-ip", msg, cloud)
            self.assertNotIn("OS Login", msg, cloud)

    def test_unreadable_config_never_hides_the_ssh_error(self):
        env = self._env("gcp", {"vars": {"enable_os_login": True}})
        env.config_path.write_text("{broken")
        msg = self._abort(env, self.TIMEOUT)
        self.assertIn("did not accept SSH", msg)
        self.assertIn("update-ip", msg)

    def test_local_vms_are_never_sent_to_update_ip(self):
        msg = self._abort(self._env("vmware", {"vars": {}}), self.TIMEOUT)
        self.assertNotIn("update-ip", msg)
        self.assertIn("VM is running", msg)
        self.assertEqual(msg.count("re-run `cloudseed provision vmware --env wa`"), 1)


# ---------------------------------------------------------------- provision() without an address (vmware#21)

class MissingAddressTests(unittest.TestCase):
    def _abort(self, cloud: str, outputs: dict) -> str:
        with tempfile.TemporaryDirectory() as td:
            env = paths.Env(cloud, "nip", Path(td) / "w")
            cfg = {"name": "cs", "env": "nip", "vars": {"ssh_username": "u"}}
            with mock.patch.object(provision.Host, "wait") as wait, mock.patch.object(ui, "err"):
                with self.assertRaises(ui.Abort) as cm:
                    provision.provision(clouds.get(cloud), env, cfg, outputs)
            wait.assert_not_called()
        return cm.exception.msg

    def test_local_vm_without_an_ip_explains_the_guest_side(self):
        msg = self._abort("vmware", {"bastion_public_ip": "", "bastion_private_ip": "192.168.160.2"})
        self.assertIn("has no IP address yet", msg)
        self.assertIn("open-vm-tools", msg)
        self.assertIn("vmnet8", msg)
        self.assertIn("`cloudseed apply vmware --env nip`", msg)
        self.assertIn("`cloudseed provision vmware --env nip`", msg)
        self.assertLess(msg.index("cloudseed apply"), msg.index("cloudseed provision"))

    def test_never_applied_still_says_apply_first(self):
        for cloud in ("vmware", "aws"):
            msg = self._abort(cloud, {})
            self.assertIn(f"run `cloudseed apply {cloud} --env nip` first", msg)
            self.assertNotIn("open-vm-tools", msg)
        self.assertNotIn("open-vm-tools", self._abort("aws", {"bastion_public_ip": "", "vpc_id": "vpc-1"}))


# ---------------------------------------------------------------- host firewall with cloud hosts (gcp#1, ansible#34, azure#24)

class CloudHostFirewallTests(unittest.TestCase):
    def _vars(self, cfg_cidrs, extra):
        with tempfile.TemporaryDirectory() as td:
            env = paths.Env("gcp", "fw", Path(td) / "w")
            env.create_dirs()
            cfg = {"name": "cs", "env": "fw", "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": cfg_cidrs,
                   "vars": {"ssh_username": "u"}, "ssh_private_key_path": str(Path(td) / "key")}
            put = {}
            with mock.patch.object(provision.Host, "wait"), mock.patch.object(provision.Host, "wait_cloud_init"), \
                    mock.patch.object(provision.Host, "sync_repo"), mock.patch.object(provision.Host, "remove_secrets"), \
                    mock.patch.object(provision.Host, "put_json", lambda s, p, d: put.update({p: d})), \
                    mock.patch.object(provision.Host, "run", return_value=0), mock.patch.object(ui, "header"), \
                    mock.patch.object(ui, "info"), mock.patch.object(ui, "ok"), mock.patch.object(ui, "err"), \
                    mock.patch.object(provision.audit, "note"):
                provision.provision(clouds.get("gcp"), env, cfg, {"bastion_public_ip": "198.51.100.9"}, extra_vars=extra)
        return put["~/cloudseed-vars.json"]

    def test_cloud_hosts_open_ssh_at_the_host_layer_on_purpose(self):
        # what cli._provision_all passes for every cloud bastion/VPN: the cloud firewall pins the sources
        v = self._vars(["2001:db8::1/128"], {"allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertEqual(v["allowed_ssh_cidrs"], [])
        self.assertTrue(v["ssh_open_any"])

    def test_without_ssh_open_any_an_empty_list_still_fails_closed(self):
        with mock.patch.object(ui, "err"), self.assertRaises(ui.Abort):
            self._vars(["2001:db8::1/128"], {})

    def test_ipv6_is_filtered_by_version_not_by_text(self):
        self.assertEqual(provision.ssh_allow_list(["::ffff:203.0.113.4", "203.0.113.4", " 203.0.113.0/24 "]),
                         ["203.0.113.0/24"])

    def test_template_branches(self):
        t = _read("ansible/roles/hardening/templates/nftables.conf.j2")
        self.assertIn("auto-merge", t)
        pinned = t.index("ip saddr @ssh_allowed tcp dport 22 ct state new accept")
        anyone = t.index("{% elif ssh_open_any | default(false) | bool %}\n    tcp dport 22 ct state new accept")
        self.assertLess(pinned, anyone)


def _jinja_python():
    """A Python that has jinja2 (this one, or cloudseed's local Ansible venv), else None: the render test is skipped."""
    try:
        import jinja2  # noqa: F401
        return sys.executable
    except ImportError:
        pass
    for base in (paths.HOME, Path.home() / ".cloudseed"):
        py = Path(base) / "venv-ansible" / "bin" / "python3"
        if py.exists():
            return str(py)
    return None


@unittest.skipUnless(_jinja_python(), "jinja2 not available")
class FirewallRenderTests(unittest.TestCase):
    # trim_blocks like Ansible's template module; `bool` is an Ansible filter
    RENDER = ("import jinja2,json,sys\n"
              "e=jinja2.Environment(loader=jinja2.FileSystemLoader(sys.argv[1]),trim_blocks=True)\n"
              "e.filters['bool']=lambda v: v if isinstance(v,bool) else str(v).strip().lower() in ('1','true','yes','on')\n"
              "print(e.get_template('nftables.conf.j2').render(**json.loads(sys.argv[2])))\n")

    def _render(self, **v) -> str:
        return subprocess.run([_jinja_python(), "-c", self.RENDER, str(REPO / "ansible/roles/hardening/templates"), json.dumps(v)],
                              capture_output=True, text=True, check=True, timeout=60).stdout

    def test_empty_list_with_ssh_open_any_keeps_ssh_reachable(self):
        out = self._render(allowed_ssh_cidrs=[], ssh_open_any=True)
        self.assertIn("\n    tcp dport 22 ct state new accept", out)
        self.assertNotIn("elements", out)

    def test_empty_list_without_ssh_open_any_opens_nothing(self):
        out = self._render(allowed_ssh_cidrs=[], ssh_open_any=False)
        self.assertNotIn("dport 22", out)

    def test_pinned_sources(self):
        out = self._render(allowed_ssh_cidrs=["198.51.100.0/24", "203.0.113.4/32"], ssh_open_any=True)
        self.assertIn("elements = { 198.51.100.0/24, 203.0.113.4/32 }", out)
        self.assertIn("ip saddr @ssh_allowed tcp dport 22 ct state new accept", out)
        self.assertNotIn("\n    tcp dport 22", out)


# ---------------------------------------------------------------- replaced hosts behind a kept address (aws#1)

class ReplacedHostTests(unittest.TestCase):
    def _forget(self, before, after):
        gone = []
        with mock.patch.object(provision, "forget_host_key", lambda env, ip: gone.append(ip)):
            ret = provision.forget_replaced_hosts(object(), before, after)
        self.assertEqual(ret, gone)
        return gone

    def test_a_new_instance_behind_the_same_ip_drops_its_key(self):
        before = {"bastion_public_ip": "198.51.100.9", "bastion_instance_id": "i-1",
                  "vpn_public_ip": "198.51.100.10", "vpn_instance_id": "i-2"}
        after = dict(before, vpn_instance_id="i-3")
        self.assertEqual(self._forget(before, after), ["198.51.100.10"])

    def test_a_replaced_host_on_a_new_ip_drops_both_addresses(self):
        before = {"bastion_public_ip": "198.51.100.9", "bastion_instance_id": "i-1"}
        after = {"bastion_public_ip": "198.51.100.77", "bastion_instance_id": "i-9"}
        self.assertEqual(self._forget(before, after), ["198.51.100.9", "198.51.100.77"])

    def test_no_proof_of_replacement_keeps_the_key(self):
        same = {"bastion_public_ip": "198.51.100.9", "bastion_instance_id": "i-1"}
        self.assertEqual(self._forget(same, dict(same)), [])
        self.assertEqual(self._forget({"vpn_public_ip": "198.51.100.10"}, {"vpn_public_ip": "198.51.100.10", "vpn_instance_id": "i-3"}), [])
        self.assertEqual(self._forget(same, {}), [])                   # a failed/empty output read is not a replacement
        self.assertEqual(self._forget(None, None), [])

    def test_ssh_keygen_removes_the_entry_from_the_env_known_hosts(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("ssh-keygen not installed")
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(Path(td) / "hk")], check=True,
                           capture_output=True, timeout=30)
            key = (Path(td) / "hk.pub").read_text().split()[1]
            env = paths.Env("aws", "rh", Path(td) / "w")
            env.create_dirs()
            env.known_hosts_path().write_text(f"198.51.100.10 ssh-ed25519 {key}\n198.51.100.9 ssh-ed25519 {key}\n")
            provision.forget_replaced_hosts(env, {"vpn_public_ip": "198.51.100.10", "vpn_instance_id": "i-2"},
                                            {"vpn_public_ip": "198.51.100.10", "vpn_instance_id": "i-3"})
            left = env.known_hosts_path().read_text()
            self.assertNotIn("198.51.100.10", left)
            self.assertIn("198.51.100.9", left)
            self.assertFalse(Path(f"{env.known_hosts_path()}.old").exists())


# ---------------------------------------------------------------- streamed output (agentic#9)

class StreamRedactionTests(unittest.TestCase):
    def test_a_multi_line_private_key_is_hidden_whole(self):
        body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"
        lines = ["TASK [show]\n", "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n", body + "\n", body[::-1] + "\n",
                 "-----END OPENSSH PRIVATE KEY-----\n", "ok: [localhost]\n"]
        child = mock.Mock(stdout=iter(lines))
        printed, logged = [], []
        with mock.patch("builtins.print", lambda s, **k: printed.append(s)), \
                mock.patch.object(provision.audit, "write", lambda s: logged.append(s)):
            provision._stream(child)
        for out in ("".join(printed), "".join(logged)):
            self.assertNotIn(body, out)
            self.assertNotIn(body[::-1], out)
            self.assertIn("TASK [show]", out)
            self.assertIn("ok: [localhost]", out)

    def test_each_stream_gets_its_own_redactor(self):
        # a key cut off in one run must not swallow the next run's output
        with mock.patch("builtins.print"), mock.patch.object(provision.audit, "write"):
            provision._stream(mock.Mock(stdout=iter(["-----BEGIN " + "RSA PRIVATE KEY-----\n", "MIIEow\n"])))
        printed = []
        with mock.patch("builtins.print", lambda s, **k: printed.append(s)), mock.patch.object(provision.audit, "write"):
            provision._stream(mock.Mock(stdout=iter(["PLAY RECAP\n"])))
        self.assertEqual(printed, ["PLAY RECAP\n"])


# ---------------------------------------------------------------- Ansible config and roles (resilience#22, gcp#8)

class AnsibleConfigTests(unittest.TestCase):
    def test_host_key_checking_is_on_by_config(self):
        cp = configparser.ConfigParser()
        cp.read(REPO / "ansible" / "ansible.cfg")
        self.assertTrue(cp.getboolean("defaults", "host_key_checking"))
        self.assertTrue(cp.getboolean("defaults", "force_handlers"))

    def test_bastion_gets_the_gke_auth_plugin(self):
        text = _read("ansible/roles/tools/tasks/main.yml")
        m = re.search(r"^- name: Google Cloud CLI\n(.*?)(?=^- name: |\Z)", text, re.M | re.S)
        self.assertIsNotNone(m)
        task = m.group(1)
        self.assertIn("- google-cloud-cli\n", task)
        self.assertIn("- google-cloud-cli-gke-gcloud-auth-plugin\n", task)
        self.assertIn("cloud == 'gcp'", task)


# ---------------------------------------------------------------- VPN client script on the host (platform-logic#15)

class VpnClientScriptTests(unittest.TestCase):
    """Runs the rendered cloudseed-vpn-client with bash against a scratch Easy-RSA directory and logging fakes."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        self.log = root / "calls.log"
        self.rsa = root / "easy-rsa"
        (self.rsa / "pki" / "issued").mkdir(parents=True)
        (self.rsa / "pki" / "private").mkdir(parents=True)
        for name in ("server", "alice"):
            (self.rsa / "pki" / "issued" / f"{name}.crt").write_text("cert\n")
            (self.rsa / "pki" / "private" / f"{name}.key").write_text("key\n")
        (self.rsa / "pki" / "ca.crt").write_text("ca\n")
        (self.rsa / "pki" / "crl.pem").write_text("crl\n")
        _script(self.rsa / "easyrsa", f'echo "easyrsa $*" >> "{self.log}"\n')
        fake = root / "bin"
        fake.mkdir()
        for tool in ("curl", "systemctl", "install", "openssl"):
            _script(fake / tool, f'echo "{tool} $*" >> "{self.log}"\n' + ('echo 203.0.113.50\n' if tool == "curl" else ""))
        text = _read("ansible/roles/openvpn/templates/cloudseed-vpn-client.j2")
        text = re.sub(r"^\{%.*%\}\n", "", text, flags=re.M)                 # the Jinja control lines
        text = text.replace("export {{ k }}={{ v | quote }}", "export EASYRSA_BATCH=1")
        text = re.sub(r"\{\{.*?\}\}", "1194", text)                          # vpn_port
        text = text.replace("cd /etc/openvpn/easy-rsa", f'cd "{self.rsa}"')
        self.script = root / "cloudseed-vpn-client"
        self.script.write_text(text)
        self.env = dict(os.environ, PATH=f"{fake}{os.pathsep}{os.environ.get('PATH', '')}")

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *argv):
        self.log.write_text("")
        p = subprocess.run(["bash", str(self.script), *argv], capture_output=True, text=True, env=self.env, timeout=30)
        return p.returncode, p.stdout, p.stderr, self.log.read_text()

    def test_revoke_validates_the_name_like_add(self):
        for bad in ("server", "Server", "-rf", "../pki/private/ca", "x;id", ".hidden", "a" * 65, "", "a b"):
            for action in ("add", "revoke"):
                rc, out, err, calls = self._run(action, bad)
                self.assertEqual(rc, 2, (action, bad, err))
                self.assertIn("invalid client name", err, (action, bad))
                self.assertEqual(calls, "", (action, bad))               # no easyrsa, no curl, no restart
                self.assertNotIn("key", out)

    def test_valid_names(self):
        rc, out, err, calls = self._run("revoke", "alice")
        self.assertEqual(rc, 0, err)
        self.assertIn("easyrsa --batch revoke alice", calls)
        self.assertNotIn("curl", calls)                                   # the public IP is only for add
        rc, out, err, calls = self._run("add", "bob.smith-2")
        self.assertEqual(rc, 0, err)
        self.assertIn("easyrsa --batch build-client-full bob.smith-2 nopass", calls)
        self.assertIn("remote 203.0.113.50 1194", out)
        self.assertEqual(self._run("add", "a" * 64)[0], 0)

    def test_list_needs_no_internet(self):
        _script(Path(self.td.name) / "bin" / "curl", "exit 6\n")         # no outbound HTTPS
        rc, out, err, _ = self._run("list")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.split(), ["alice"])


if __name__ == "__main__":
    unittest.main()
