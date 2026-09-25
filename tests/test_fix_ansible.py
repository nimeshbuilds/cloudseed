"""Regression tests for the Ansible provisioning fixes (cloudseed/provision.py, ansible/**, and the pieces of
deps.py / scan.py they rely on). Stdlib only, no network, no real hosts: subprocess is mocked or points at tiny
local scripts."""

import ast
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, deps, paths, provision, scan, ui  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
ANSIBLE = REPO / "ansible"


def _read(rel: str) -> str:
    return (REPO / rel).read_text()


def _code(text: str) -> str:
    """The text without comment lines/comments (YAML/shell/Jinja comments may name what the code no longer does)."""
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    return "\n".join(re.sub(r"(^|\s)#(?![!{]).*$", "", line) for line in text.splitlines())


def _task(text: str, name: str) -> str:
    """The YAML text of one task (from its `- name:` line to the next task at the same indentation)."""
    m = re.search(r"^(\s*)- name: " + re.escape(name) + r"\s*$", text, re.M)
    if not m:
        raise AssertionError(f"task {name!r} not found")
    indent = m.group(1)
    rest = text[m.end():]
    nxt = re.search(r"^" + indent + r"- name: ", rest, re.M)
    return text[m.start():m.end() + (nxt.start() if nxt else len(rest))]


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class FakeProc:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = rc, stdout, stderr


# ---------------------------------------------------------------- repository sync (ansible#17)

class RepoSyncTests(unittest.TestCase):
    def _tree(self, root: Path, files: list[str]) -> None:
        for f in files:
            p = root / f
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x")

    def test_secrets_and_state_never_ship(self):
        for rel in (".env", ".envrc", ".env.local", "crash.log", "terraform/aws/terraform.tfvars",
                    "terraform/aws/prod.tfvars.json", "terraform/aws/terraform.tfstate.1695000000.backup",
                    ".terraform.tfstate.lock.info", "terraform/aws/.terraform.tfstate.lock.info",
                    "envs/aws-dev/ssh/id_ed25519", "mywork/k8s/kubeconfig", "mywork/k8s/token", "tfbin/terraform",
                    ".DS_Store", "ansible/.DS_Store", "terraform/aws/crash.log", "base_library.zip",
                    "lib-dynload/_ssl.so", "tests/test_cloudseed.py", "scripts/install.sh"):
            self.assertFalse(provision._include(Path(rel)), rel)
        for rel in ("ansible/bootstrap.sh", "ansible/bastion.yml", "ansible/roles/common/templates/motd.j2",
                    "terraform/aws/main.tf", "cloudseed/provision.py", "bin/cloudseed", "skills/cloudseed/SKILL.md",
                    "README.md", "templates/gitlab-ci/.gitlab-ci.yml"):
            self.assertTrue(provision._include(Path(rel)), rel)

    def test_workdirs_and_cloudseed_home_inside_the_checkout_are_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            self._tree(root, ["ansible/bastion.yml", "terraform/aws/main.tf", "terraform/aws/terraform.tfvars",
                              ".env", "README.md",
                              # a --workdir placed under an allow-listed tree still carries config.json + ssh/
                              "terraform/dev/config.json", "terraform/dev/ssh/id_ed25519", "terraform/dev/k8s/token",
                              # CLOUDSEED_HOME inside the checkout
                              "cloudseed/.home/envs/aws-x/config.json", "cloudseed/.home/credentials.json",
                              "cloudseed/cli.py"])
            with mock.patch.object(paths, "HOME", root / "cloudseed" / ".home"), \
                    mock.patch.object(paths, "_load_index", return_value={}):
                files = [str(p) for p in provision.repo_files(root)]
        self.assertEqual(sorted(files), ["README.md", "ansible/bastion.yml", "cloudseed/cli.py", "terraform/aws/main.tf"])

    def test_symlinks_do_not_pull_in_outside_trees(self):
        with tempfile.TemporaryDirectory() as td:
            root, outside = Path(td) / "repo", Path(td) / "outside"
            self._tree(root, ["ansible/bastion.yml"])
            self._tree(outside, ["secret/id_rsa"])
            (root / "ansible" / "linked").symlink_to(outside / "secret", target_is_directory=True)
            with mock.patch.object(paths, "_load_index", return_value={}):
                files = [str(p) for p in provision.repo_files(root)]
        self.assertEqual(files, ["ansible/bastion.yml"])

    def test_oversized_copy_is_refused_with_the_largest_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            big = root / "terraform" / "huge.bin"
            big.parent.mkdir(parents=True)
            with open(big, "wb") as fh:
                fh.truncate(provision.MAX_SYNC_BYTES + 1)
            msg = provision._sync_size_problem(root, [Path("terraform/huge.bin")])
        self.assertIn("terraform/huge.bin", msg)
        self.assertIsNone(provision._sync_size_problem(root, []))

    def test_sync_streams_a_tar_to_the_host(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            self._tree(root, ["ansible/bootstrap.sh", ".env"])
            captured = {}

            class P:
                def __init__(self, cmd, stdin=None, stdout=None, stderr=None):
                    import io
                    captured["cmd"] = cmd
                    self.stdin = io.BytesIO()
                    self.stdin.close = lambda: captured.setdefault("blob", self.stdin.getvalue())
                    self.stderr = io.BytesIO(b"")

                def wait(self):
                    return 0

            h = provision.Host("10.0.0.5", "u", Path(td) / "key", "bastion")
            with mock.patch.object(paths, "REPO_ROOT", root), mock.patch.object(paths, "_load_index", return_value={}), \
                    mock.patch.object(provision.subprocess, "Popen", P), mock.patch.object(ui, "info"), mock.patch.object(ui, "ok"):
                h.sync_repo()
            import io
            import tarfile
            names = tarfile.open(fileobj=io.BytesIO(captured["blob"]), mode="r:gz").getnames()
        self.assertEqual(names, ["ansible/bootstrap.sh"])
        self.assertIn("tar xzf - -C ~/cloudseed", captured["cmd"][-1])

    def test_unreadable_local_file_fails_the_copy(self):
        # a truncated archive can still extract with exit 0 on the host: a local read error must fail the sync itself
        import io

        class P:
            def __init__(self, cmd, stdin=None, stdout=None, stderr=None):
                self.stdin, self.stderr = io.BytesIO(), io.BytesIO(b"")

            def wait(self):
                return 0

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            self._tree(root, ["ansible/bootstrap.sh"])
            h = provision.Host("10.0.0.5", "u", Path(td) / "key", "bastion")
            with mock.patch.object(paths, "REPO_ROOT", root), \
                    mock.patch.object(provision, "repo_files", return_value=[Path("ansible/bootstrap.sh"), Path("ansible/gone.yml")]), \
                    mock.patch.object(provision.subprocess, "Popen", P), mock.patch.object(ui, "info"), \
                    mock.patch.object(ui, "ok"), mock.patch.object(ui, "err"):
                with self.assertRaises(ui.Abort) as cm:
                    h.sync_repo()
        self.assertIn("gone.yml", cm.exception.msg)


# ---------------------------------------------------------------- SSH (ansible#18, #29, #32, #12)

class HostSshTests(unittest.TestCase):
    def test_non_interactive_ssh_is_quiet_and_pins_a_locale(self):
        h = provision.Host("10.0.0.5", "u", Path("/k"), "bastion")
        argv = h.ssh("true")
        self.assertIn("LogLevel=ERROR", argv)
        self.assertIn("SetEnv=LC_ALL=C.UTF-8 LANG=C.UTF-8", argv)
        self.assertNotIn("WarnWeakCrypto=no", " ".join(argv))   # OpenSSH < 10.1 rejects the unknown option

    def test_changed_host_key_fails_fast_with_the_fix(self):
        with tempfile.TemporaryDirectory() as td:
            env = paths.Env("vmware", "hk", Path(td) / "w")
            h = provision.Host("10.30.0.41", "u", Path(td) / "key", "wk2", env=env)
            err = ("@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
                   "Host key for 10.30.0.41 has changed and you have requested strict checking.\nHost key verification failed.\n")
            calls = []
            with mock.patch.object(provision.subprocess, "run", side_effect=lambda *a, **k: calls.append(1) or FakeProc(255, "", err)), \
                    mock.patch.object(provision.time, "sleep"), mock.patch.object(ui, "err"), mock.patch("builtins.print"):
                with self.assertRaises(ui.Abort) as cm:
                    h.wait(timeout=600)
        self.assertEqual(len(calls), 1)                      # no 10-minute retry loop
        self.assertIn("ssh-keygen -R 10.30.0.41 -f", cm.exception.msg)
        self.assertIn(str(env.known_hosts_path()), cm.exception.msg)
        self.assertNotIn("update-ip", cm.exception.msg)

    def _timeout_msg(self, local: bool) -> str:
        h = provision.Host("10.0.0.5", "u", Path("/k"), "bastion", local=local)
        clock = iter([0, 0, 1000, 1000, 1000])
        with mock.patch.object(provision.subprocess, "run", return_value=FakeProc(255, "", "ssh: connect to host 10.0.0.5 port 22: Connection refused\n")), \
                mock.patch.object(provision.time, "time", side_effect=lambda: next(clock)), \
                mock.patch.object(provision.time, "sleep"), mock.patch.object(ui, "err"), mock.patch("builtins.print"):
            with self.assertRaises(ui.Abort) as cm:
                h.wait(timeout=5)
        return cm.exception.msg

    def test_timeout_advice_depends_on_the_target(self):
        cloud_msg, local_msg = self._timeout_msg(False), self._timeout_msg(True)
        self.assertIn("update-ip", cloud_msg)
        self.assertIn("Connection refused", cloud_msg)
        self.assertNotIn("update-ip", local_msg)
        self.assertIn("VM is running", local_msg)

    def test_forget_host_key_uses_ssh_keygen(self):
        with tempfile.TemporaryDirectory() as td:
            env = paths.Env("vmware", "fk", Path(td) / "w")
            env.known_hosts_path().parent.mkdir(parents=True)
            env.known_hosts_path().write_text("10.30.0.41 ssh-ed25519 AAAA\n")
            with mock.patch.object(provision.subprocess, "run", return_value=FakeProc()) as run:
                provision.forget_host_key(env, "10.30.0.41")
            self.assertEqual(run.call_args[0][0], ["ssh-keygen", "-R", "10.30.0.41", "-f", str(env.known_hosts_path())])

    def test_inventory_args_survive_a_workdir_with_spaces(self):
        with tempfile.TemporaryDirectory() as td:
            env = paths.Env("vmware", "sp", Path(td) / "My Envs" / "dev")
            line = provision.ansible_ssh_common_args(env)
        key, _, value = line.partition("=")
        self.assertEqual(key, "ansible_ssh_common_args")
        tokens = shlex.split(ast.literal_eval(value))            # what Ansible's INI parser + ssh plugin do
        kh = tokens[tokens.index("-o", tokens.index("IdentitiesOnly=yes")) + 3]
        self.assertEqual(kh, f'UserKnownHostsFile="{env.known_hosts_path()}"')
        self.assertIn("StrictHostKeyChecking=accept-new", tokens)

    def test_ansible_env_checks_host_keys_and_follows_no_color(self):
        with mock.patch.object(ui, "_COLOR", False):
            e = provision.ansible_env()
        self.assertEqual(e["ANSIBLE_HOST_KEY_CHECKING"], "True")
        self.assertEqual(e["ANSIBLE_FORCE_COLOR"], "0")
        with mock.patch.object(ui, "_COLOR", True):
            self.assertEqual(provision.ansible_env()["ANSIBLE_FORCE_COLOR"], "1")


# ---------------------------------------------------------------- allow-list / VPN routes (ansible#14, #34, gcp#17)

class NetworkVarsTests(unittest.TestCase):
    def test_allow_list_is_ipv4_collapsed(self):
        self.assertEqual(provision.ssh_allow_list(["198.51.100.0/24", "198.51.100.7", "198.51.100.7/32"]), ["198.51.100.0/24"])
        self.assertEqual(provision.ssh_allow_list(["2001:db8::1", "203.0.113.4"]), ["203.0.113.4/32"])
        self.assertEqual(provision.ssh_allow_list(["2001:db8::1/128"]), [])
        with mock.patch.object(ui, "err"), self.assertRaises(ui.Abort):
            provision.ssh_allow_list(["not-an-ip"])

    def test_vpn_routes_include_the_gke_control_plane(self):
        v = provision.vpn_network_vars({"network_cidr": "10.0.0.0/16"}, {"kubernetes_master_cidr": "172.16.0.0/28"})
        self.assertEqual(v["vpn_routes"], ["10.0.0.0/16", "172.16.0.0/28"])
        self.assertEqual(v["vpn_push_routes"], [["10.0.0.0", "255.255.0.0"], ["172.16.0.0", "255.255.255.240"]])
        self.assertEqual((v["vpn_client_net"], v["vpn_client_mask"]), ("10.8.0.0", "255.255.255.0"))
        self.assertEqual(provision.vpn_network_vars({"network_cidr": "10.1.0.0/16"}, {"kubernetes_master_cidr": None})["vpn_routes"],
                         ["10.1.0.0/16"])

    def test_gcp_stack_reports_the_master_cidr(self):
        self.assertIn("kubernetes_master_cidr", clouds.get("gcp").outputs)
        self.assertIn('output "kubernetes_master_cidr"', _read("terraform/gcp/outputs.tf"))


# ---------------------------------------------------------------- provision() (ansible#24, #31, #34, #12)

class ProvisionFlowTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("aws", "pf", Path(self.td.name) / "w")
        self.env.create_dirs()
        self.cfg = {"name": "cs", "env": "pf", "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.4/32"],
                    "vars": {}, "ssh_private_key_path": str(Path(self.td.name) / "key")}
        self.calls = []

    def tearDown(self):
        self.td.cleanup()

    def _run(self, cloud="aws", rc=0, **kw):
        c = clouds.get(cloud)
        put = {}
        patches = [mock.patch.object(provision.Host, "wait"), mock.patch.object(provision.Host, "wait_cloud_init"),
                   mock.patch.object(provision.Host, "sync_repo"),
                   mock.patch.object(provision.Host, "put_json", lambda s, p, d: put.update({p: d})),
                   mock.patch.object(provision.Host, "run", lambda s, cmd, env=None: self.calls.append(("run", cmd, env)) or rc),
                   mock.patch.object(provision.Host, "remove_secrets", lambda s: self.calls.append(("rm",))),
                   mock.patch.object(ui, "header"), mock.patch.object(ui, "info"), mock.patch.object(ui, "err"),
                   mock.patch.object(provision.audit, "note")]
        oks = []
        patches.append(mock.patch.object(ui, "ok", lambda m: oks.append(m)))
        for p in patches:
            p.start()
        try:
            provision.provision(c, self.env, self.cfg, {"bastion_public_ip": "198.51.100.9", "vpn_public_ip": "198.51.100.10",
                                                        "kubernetes_master_cidr": "172.16.0.0/28"}, **kw)
        finally:
            for p in patches:
                p.stop()
        return put.get("~/cloudseed-vars.json"), oks

    def test_locale_and_secret_cleanup(self):
        vars_, oks = self._run()
        run = [c for c in self.calls if c[0] == "run"][0]
        self.assertEqual(run[2]["LC_ALL"], "C.UTF-8")
        self.assertEqual(self.calls[-1], ("rm",))
        self.assertTrue(vars_["harden"])
        self.assertFalse(vars_["ssh_open_any"])
        self.assertIn("provisioned and hardened", oks[-1])

    def test_secrets_removed_after_a_failed_play_and_after_sync_only(self):
        with self.assertRaises(ui.Abort):
            self._run(rc=2)
        self.assertEqual(self.calls[-1], ("rm",))
        self.calls.clear()
        vars_, _ = self._run(sync_only=True)
        self.assertIsNone(vars_)
        self.assertEqual(self.calls, [("rm",)])

    def test_no_harden_is_honest(self):
        vars_, oks = self._run(harden=False, firewall=False)
        self.assertFalse(vars_["harden"])
        self.assertFalse(vars_["auto_updates"])
        self.assertNotIn("hardened", oks[-1])
        self.assertIn("OS hardening, host firewall skipped", oks[-1])

    def test_ipv6_only_allow_list_fails_closed(self):
        self.cfg["allowed_ssh_cidrs"] = ["2001:db8::1/128"]
        with self.assertRaises(ui.Abort) as cm:
            self._run()
        self.assertIn("IPv4", cm.exception.msg)
        self.assertFalse([c for c in self.calls if c[0] == "run"])     # nothing ran on the host
        self.calls.clear()
        self._run(firewall=False)                                      # no host firewall: nothing to protect

    def test_local_bastion_opens_ssh_on_the_host_only_network(self):
        self.cfg["vars"]["ssh_username"] = "u"
        vars_, _ = self._run(cloud="vmware", extra_vars={"allowed_ssh_cidrs": [], "nat_source_cidrs": ["10.20.0.0/16"]})
        self.assertTrue(vars_["ssh_open_any"])
        self.assertEqual(vars_["allowed_ssh_cidrs"], [])

    def test_fail2ban_ignores_the_operator_when_the_firewall_does_not_pin_ssh(self):
        # cloud hosts are provisioned with allowed_ssh_cidrs=[] + ssh_open_any (the cloud firewall pins SSH sources):
        # fail2ban must still never ban the operator's own addresses (integration: cli-setup x ansible#27)
        self.cfg["allowed_ssh_cidrs"] = ["203.0.113.4/32", "203.0.113.0/24", "2001:db8::1/128", "not-an-ip"]
        vars_, _ = self._run(extra_vars={"allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertEqual(vars_["allowed_ssh_cidrs"], [])
        self.assertEqual(vars_["fail2ban_ignore_cidrs"], ["203.0.113.0/24"])
        jail = _task(_read("ansible/roles/hardening/tasks/main.yml"), "fail2ban sshd jail")
        self.assertIn("{% for c in fail2ban_ignore_cidrs | default([]) if c not in allowed_ssh_cidrs | default([]) %} {{ c }}", jail)

    def test_vpn_gets_routes_and_overlaps_are_merged(self):
        self.cfg["allowed_ssh_cidrs"] = ["198.51.100.0/24", "198.51.100.7/32"]
        vars_, _ = self._run(playbook="vpn.yml", host_key="vpn_public_ip", label="vpn", tools=False)
        self.assertEqual(vars_["allowed_ssh_cidrs"], ["198.51.100.0/24"])
        self.assertEqual(vars_["vpn_routes"], ["10.20.0.0/16", "172.16.0.0/28"])
        self.assertEqual(vars_["vpn_push_routes"][1], ["172.16.0.0", "255.255.255.240"])


# ---------------------------------------------------------------- local Kubernetes (ansible#15, #5, #24, #18, #23, e2e#23)

class LocalKubernetesTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("vmware", "k8", Path(self.td.name) / "work dir" / "vmware-k8")
        self.env.create_dirs()
        self.cfg = {"name": "cs", "env": "k8", "vars": {"ssh_username": "u", "fips_mode": True},
                    "ssh_private_key_path": str(Path(self.td.name) / "key")}
        self.fake = _script(Path(self.td.name) / "ansible-playbook", 'echo "argv: $*"\nexit 0\n')
        self.outputs = {"kubernetes_control_plane_ips": ["10.30.0.20"], "kubernetes_worker_ips": ["10.30.0.40", "10.30.0.41"]}

    def tearDown(self):
        self.td.cleanup()

    def _install(self, distro="rke2", limit=None, **kw):
        self.cfg["vars"]["kubernetes_distro"] = distro
        forgotten = []
        with mock.patch.object(provision.Host, "wait"), mock.patch.object(provision.Host, "wait_cloud_init"), \
                mock.patch.object(deps, "ensure_local_ansible", return_value=self.fake), \
                mock.patch.object(provision, "forget_host_key", lambda env, ip: forgotten.append(ip)), \
                mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": "C1234567890SECRETPROTOKEN"}), \
                mock.patch.object(ui, "header"), mock.patch.object(ui, "panel"), mock.patch("builtins.print"), \
                mock.patch.object(provision.audit, "note"):
            provision.provision_local_kubernetes(clouds.get("vmware"), self.env, self.cfg, dict(self.outputs, kubernetes_distro=distro),
                                                 limit=limit, **kw)
        k8s = self.env.dir / "k8s"
        return json.loads((k8s / "vars.json").read_text()), (k8s / "inventory.ini").read_text(), forgotten

    def test_token_follows_the_distro_and_is_never_rotated_needlessly(self):
        v1, _, _ = self._install("rke2")
        self.assertRegex(v1["k8s_token"], r"^[0-9a-f]{48}$")
        again, _, _ = self._install("rke2")
        self.assertEqual(again["k8s_token"], v1["k8s_token"])          # a live cluster keeps its token
        v2, _, _ = self._install("kubeadm")                             # env re-created with the other distro
        self.assertRegex(v2["k8s_token"], r"^[a-z0-9]{6}\.[a-z0-9]{16}$")
        self.assertEqual((self.env.dir / "k8s" / "token").read_text(), v2["k8s_token"])   # O_TRUNC: no stale tail
        v3, _, _ = self._install("rke2")
        self.assertRegex(v3["k8s_token"], r"^[0-9a-f]{48}$")

    def test_pro_token_never_written_and_flags_pass_through(self):
        self.cfg["vars"].update(kubernetes_version="v1.36.4+rke2r1", kubernetes_cis_profile=True)
        v, inv, _ = self._install("rke2", harden=False)
        text = (self.env.dir / "k8s" / "vars.json").read_text()
        self.assertNotIn("SECRETPROTOKEN", text)
        self.assertNotIn("ubuntu_pro_token", v)
        self.assertEqual((v["harden"], v["harden_ssh"], v["enable_auditd"]), (False, False, False))
        self.assertEqual(v["rke2_version"], "v1.36.4+rke2r1")
        self.assertTrue(v["rke2_cis_profile"])
        self.cfg["vars"].update(kubernetes_version="1.35")
        v, _, _ = self._install("kubeadm")
        self.assertEqual(v["kubernetes_version"], "1.35")
        self.assertIn('ansible_ssh_private_key_file="', inv)
        self.assertIn(provision.ansible_ssh_common_args(self.env), inv)

    def test_joining_nodes_forget_stale_host_keys(self):
        _, _, forgotten = self._install("rke2", limit=["cs-k8-wk2"])
        self.assertEqual(forgotten, ["10.30.0.41"])
        _, _, forgotten = self._install("rke2")
        self.assertEqual(forgotten, [])


# ---------------------------------------------------------------- deps (ansible#30, #13)

class LocalAnsibleTests(unittest.TestCase):
    def test_bundle_never_uses_its_own_binary_for_venvs(self):
        with tempfile.TemporaryDirectory() as td:
            good = _script(Path(td) / "python3.12", "exit 0\n")
            _script(Path(td) / "python3", "exit 1\n")
            with mock.patch.object(paths, "IS_BUNDLE", True), mock.patch.object(deps, "path_env", return_value={"PATH": td}):
                self.assertEqual(deps.venv_python(), str(good))
            good.unlink()
            with mock.patch.object(paths, "IS_BUNDLE", True), mock.patch.object(deps, "path_env", return_value={"PATH": td}), \
                    mock.patch.object(ui, "err"):
                with self.assertRaises(ui.Abort) as cm:
                    deps.venv_python(purpose="ansible-core")
            self.assertIn("single-binary", cm.exception.msg)

    def test_bundle_cli_venvs_use_a_system_python(self):
        # azure-cli / snowflake-cli venvs (no brew): `<bundle binary> -m venv` is the cloudseed CLI, not Python
        with tempfile.TemporaryDirectory() as td:
            py = _script(Path(td) / "python3.12", "exit 0\n")
            for install in (deps.install_az, deps.install_snow):
                calls = []
                with mock.patch.object(paths, "IS_BUNDLE", True), mock.patch.object(paths, "HOME", Path(td)), \
                        mock.patch.object(deps, "path_env", return_value={"PATH": td}), \
                        mock.patch.object(deps, "_brew_install", return_value=False), \
                        mock.patch.object(deps.subprocess, "run",   # the interpreter probe and venv succeed, pip fails
                                          side_effect=lambda cmd, **k: calls.append(cmd) or FakeProc(1 if "pip" in str(cmd[0]) else 0)), \
                        mock.patch.object(ui, "info"):
                    self.assertFalse(install())
                venv_calls = [c for c in calls if c[1:3] == ["-m", "venv"]]
                self.assertEqual([c[0] for c in venv_calls], [str(py)], install.__name__)

    def test_source_mode_uses_this_python_when_new_enough(self):
        with mock.patch.object(paths, "IS_BUNDLE", False):
            if sys.version_info[:2] >= (3, 10):
                self.assertEqual(deps.venv_python(), sys.executable)

    def test_no_galaxy_collections_and_clean_failure(self):
        with tempfile.TemporaryDirectory() as td:
            venv = Path(td) / "venv-ansible"
            calls = []

            def run(cmd, check=False, **kw):
                calls.append(cmd)
                if "venv" in cmd:
                    venv.mkdir(parents=True, exist_ok=True)
                if check and "pip" in str(cmd[0]):
                    raise subprocess.CalledProcessError(1, cmd)
                return FakeProc()

            with mock.patch.object(deps, "ANSIBLE_VENV", venv), mock.patch.object(deps.subprocess, "run", run), \
                    mock.patch.object(deps, "venv_python", return_value="/usr/bin/python3.12"), \
                    mock.patch.object(ui, "info"), mock.patch.object(ui, "err"):
                with self.assertRaises(ui.Abort):
                    deps.ensure_local_ansible()
            self.assertFalse(venv.exists())                             # no half-built venv left behind
            self.assertEqual(calls[0][:3], ["/usr/bin/python3.12", "-m", "venv"])
            self.assertFalse([c for c in calls if "ansible-galaxy" in str(c[0])])
            self.assertNotIn("netaddr", calls[1])


# ---------------------------------------------------------------- host scans (resilience#5/#6/#18, ansible#19, #29)

class HostScanTests(unittest.TestCase):
    def test_host_without_stig_content_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as td:
            env = paths.Env("aws", "sc", Path(td) / "work dir")
            env.create_dirs()
            cfg = {"name": "cs", "env": "sc", "vars": {}, "ssh_private_key_path": str(Path(td) / "key")}
            # stand-in for ansible-playbook: writes what the openscap role writes for an OS without the profile
            fake = _script(Path(td) / "ansible-playbook", (
                'for a in "$@"; do case "$a" in \\{*) extra="$a";; esac; done\n'
                'python3 -c "import json,sys,os; e=json.loads(sys.argv[1]); d=os.path.join(e[\'scan_dest\'], \'bastion\'); '
                'os.makedirs(d, exist_ok=True); json.dump({\'host\': \'bastion\', \'skipped\': \'no DISA STIG profile for al2023\'}, '
                'open(os.path.join(d, \'meta.json\'), \'w\'))" "$extra"\n'))
            panel = {}
            with mock.patch.object(scan, "_ssg_version", return_value="0.1.82"), \
                    mock.patch.object(scan.deps, "ensure_local_ansible", return_value=fake), \
                    mock.patch.object(scan.prov.Host, "wait"), \
                    mock.patch.object(scan, "_panel", lambda title, summary, findings, path, verdict=None, **k: panel.update(summary=summary, verdict=verdict)), \
                    mock.patch.object(ui, "header"), mock.patch("builtins.print"), warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)     # scan.host leaves its pipe to the GC
                path = scan.host(clouds.get("aws"), env, cfg, {"bastion_public_ip": "198.51.100.9"}, ["bastion"], "stig")
            report = json.loads(Path(path).read_text())
            inv = (Path(report["raw"]) / "inventory.ini").read_text()
        self.assertTrue(panel["verdict"].startswith("N/A"), panel["verdict"])
        self.assertEqual(report["hosts"]["bastion"]["skipped"], "no DISA STIG profile for al2023")
        self.assertIn("n/a - no DISA STIG profile", panel["summary"]["bastion"])
        self.assertIn('UserKnownHostsFile=\\"', inv)                    # quoted: the workdir has a space
        self.assertEqual(report["verdict"], "N/A")                       # persisted too: `cs scan` does not exit 1
        self.assertNotIn("errors", report["summary"])                    # n/a is not a host that failed to scan

    def test_host_scan_runs_ansible_with_host_key_checking(self):
        seen = {}

        class P:
            def __init__(self, cmd, env=None, **kw):
                seen.update(env or {})
                self.stdout = iter(())

            def wait(self):
                return 0

        with tempfile.TemporaryDirectory() as td:
            env = paths.Env("aws", "sk", Path(td) / "w")
            env.create_dirs()
            cfg = {"name": "cs", "env": "sk", "vars": {}, "ssh_private_key_path": str(Path(td) / "key")}
            with mock.patch.object(scan, "_ssg_version", return_value="0.1.82"), \
                    mock.patch.object(scan.deps, "ensure_local_ansible", return_value=Path("/usr/bin/true")), \
                    mock.patch.object(scan.prov.Host, "wait"), mock.patch.object(scan.subprocess, "Popen", P), \
                    mock.patch.object(scan, "_panel"), mock.patch.object(ui, "header"), mock.patch.object(ui, "_COLOR", False):
                scan.host(clouds.get("aws"), env, cfg, {"bastion_public_ip": "198.51.100.9"}, ["bastion"], "cis")
        self.assertEqual(seen["ANSIBLE_HOST_KEY_CHECKING"], "True")
        self.assertEqual(seen["ANSIBLE_FORCE_COLOR"], "0")               # NO_COLOR / pipes: no escape codes
        self.assertTrue(seen["ANSIBLE_CONFIG"].endswith("ansible.cfg"))


# ---------------------------------------------------------------- the playbooks and roles (static checks)

def ansible_text_files() -> dict:
    """Every text file of the playbooks and roles, whatever its suffix (a role's files/ may hold a .conf, .service or
    a file with no suffix, and the static checks below must see it too). Dot files (a macOS .DS_Store or ._* file, an
    editor swap file) and files that are not UTF-8 text (a stray binary in a real checkout) are not ours: skipped."""
    out = {}
    for p in sorted(ANSIBLE.rglob("*")):
        rel = p.relative_to(ANSIBLE)
        if not p.is_file() or any(part.startswith(".") for part in rel.parts):
            continue
        try:
            out[str(p.relative_to(REPO))] = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return out


class PlaybookTextTests(unittest.TestCase):
    def all_ansible(self) -> dict:
        files = ansible_text_files()
        self.assertIn("ansible/bastion.yml", files)          # the filter never hides the playbooks themselves
        return files

    def test_no_galaxy_collection_is_needed(self):
        for name, text in self.all_ansible().items():
            self.assertNotRegex(_code(text), r"community\.general|ansible\.utils|ansible\.posix|netaddr", name)
        self.assertNotIn("ansible-galaxy", _read("ansible/bootstrap.sh"))

    def test_secrets_are_read_on_the_target_not_the_controller(self):
        for name, text in self.all_ansible().items():
            self.assertNotIn("lookup('file'", text, name)
        k8s = _read("ansible/kubernetes.yml")
        self.assertNotIn("cloudseed-secrets.json", k8s)              # the Pro token never lands on node disks
        self.assertIn("lookup('env', 'UBUNTU_PRO_TOKEN')", k8s)
        fips = _read("ansible/roles/fips/tasks/main.yml")
        self.assertIn("--attach-config", fips)                         # token not on the command line
        self.assertNotRegex(fips, r"pro attach \{\{")
        ts = _read("ansible/roles/tailscale/tasks/main.yml")
        self.assertIn("--auth-key=file:", ts)
        self.assertIn("always:", ts)
        for pb in ("bastion.yml", "vpn.yml"):
            self.assertIn("tasks/read-secrets.yml", _read(f"ansible/{pb}"))

    def test_easy_rsa_31_compatible(self):
        role = _read("ansible/roles/openvpn/tasks/main.yml")
        self.assertNotIn("EASYRSA_REQ_CN", _code(role + _read("ansible/roles/openvpn/defaults/main.yml")))
        self.assertIn("--req-cn=cloudseed-vpn build-ca", role)
        self.assertIn('crl.pem, mode: "0644"', role)
        self.assertNotIn("CRL readable", role)                        # no chmod flip-flop restarting OpenVPN
        # easy-rsa 3.0.8 ignores ./vars: the settings (EC keys, 10-year CRL) reach every easyrsa call via the environment
        self.assertIn('EASYRSA_CRL_DAYS: "3650"', _read("ansible/roles/openvpn/defaults/main.yml"))
        self.assertIn("export {{ k }}={{ v | quote }}", _read("ansible/roles/openvpn/templates/cloudseed-vpn-client.j2"))
        for name in ("Build CA", "Server certificate", "CRL"):
            self.assertIn('environment: "{{ easyrsa_env }}"', _task(role, name), name)

    def test_bootstrap(self):
        b = _read("ansible/bootstrap.sh")
        self.assertIn("export LANG=\"$LOC\" LC_ALL=\"$LOC\"", b)
        self.assertIn("-m venv --clear", b)
        self.assertIn("python$v", b)                                  # AL2023: python3.12 next to its 3.9
        self.assertIn("restore_apt_timers", b)
        self.assertNotRegex(b, r"(?m)^exec ")
        r = subprocess.run(["bash", "-n", str(ANSIBLE / "bootstrap.sh")], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_amazon_linux(self):
        common = _task(_read("ansible/roles/common/tasks/main.yml"), "Base packages (Amazon Linux / RedHat family)")
        self.assertNotRegex(common, r"\bcurl\b")
        hardening = _read("ansible/roles/hardening/tasks/main.yml")
        boot = _task(hardening, "nftables.service loads the cloudseed ruleset at boot (RedHat family)")
        self.assertIn("/etc/sysconfig/nftables.conf", boot)
        self.assertIn('include "/etc/nftables.conf"', boot)
        rel = _task(hardening, "Follow the latest Amazon Linux 2023 repository release")
        self.assertIn("/etc/dnf/vars/releasever", rel)
        self.assertIn("ansible_facts['distribution'] == 'Amazon'", rel)
        f2b = _task(hardening, "fail2ban")
        self.assertIn("fail2ban-server", f2b)
        self.assertNotIn("os_family'] == 'Debian'", f2b)
        self.assertIn("- nftables", f2b)                               # the nftables banaction needs nft (also --no-firewall)
        jail = _task(hardening, "fail2ban sshd jail")
        self.assertIn("banaction = nftables-multiport", jail)
        self.assertIn("ignoreip = 127.0.0.1/8 ::1{% for c in allowed_ssh_cidrs", jail)   # never ban the operator
        enabled = _task(hardening, "fail2ban enabled")                  # RPMs are not enabled on install
        self.assertIn("enabled: true", enabled)
        self.assertIn("state: started", enabled)
        self.assertIn("force_handlers = True", _read("ansible/ansible.cfg"))

    def test_firewall_template(self):
        t = _read("ansible/roles/hardening/templates/nftables.conf.j2")
        self.assertIn("auto-merge", t)
        self.assertIn("ssh_open_any", t)                               # an empty allow-list is not "any" by default
        handlers = _read("ansible/roles/hardening/handlers/main.yml")
        self.assertLess(handlers.index("name: reload nftables"), handlers.index("name: restart fail2ban"))

    def test_no_harden_gates_hardening_but_not_forwarding(self):
        h = _read("ansible/roles/hardening/tasks/main.yml")
        for name in ("No null passwords via PAM (CIS no_empty_passwords)", "Kernel hardening sysctls", "Disable core dumps",
                     "Sudo logging and pty", "Restrictive default umask"):
            self.assertIn("harden | default(true) | bool", _task(h, name), name)
        fwd = _task(h, "IP forwarding")
        self.assertNotIn("when:", fwd)
        self.assertIn("net.ipv4.ip_forward", fwd)
        self.assertNotIn("net.ipv4.ip_forward", _task(h, "Kernel hardening sysctls"))

    def test_kubeadm(self):
        k = _read("ansible/roles/kubeadm/tasks/main.yml")
        cfg = _task(k, "containerd config with systemd cgroups")
        self.assertNotIn("creates:", cfg)                               # Debian 12 ships a config.toml
        self.assertIn("cmp -s", cfg)
        self.assertIn("'restarted'", _task(k, "containerd running with that config"))   # before kubeadm, not a handler
        self.assertFalse((ANSIBLE / "roles" / "kubeadm" / "handlers" / "main.yml").exists())
        self.assertNotRegex(k, r"--token \{\{|--certificate-key \{\{|token create \{\{")   # secrets via environment
        self.assertNotIn("default('1.33')", k)                          # EOL minor no longer the default
        self.assertIn("or '1.35'", k)

    def test_installers_fail_on_download_errors(self):
        rke2 = _task(_read("ansible/roles/rke2/tasks/main.yml"), "Install RKE2 ({{ node_role }})")
        tools = _read("ansible/roles/tools/tasks/main.yml")
        for text in (rke2, _task(_read("ansible/roles/tailscale/tasks/main.yml"), "Install Tailscale"),
                     _task(tools, "Azure CLI"), _task(tools, "Google Cloud CLI apt repo")):
            self.assertIn("set -eo pipefail", text)
            self.assertIn("executable: /bin/bash", text)
            self.assertNotRegex(text, r"curl [^\n]*\| *(sh|bash)")
        self.assertIn("gpg --batch --yes --dearmor", tools)
        self.assertIn("test -x /usr/local/bin/rke2", rke2)

    def test_kubernetes_cluster_shape(self):
        rke2 = _read("ansible/roles/rke2/tasks/main.yml")
        self.assertIn("{% if rke2_taint_servers | bool %}", rke2)
        self.assertIn("profile: cis", rke2)
        self.assertIn("delegate_to: \"{{ groups['control_plane'][0] }}\"", _task(rke2, "RKE2 version of the running cluster (first control plane)"))
        k8s = _read("ansible/kubernetes.yml")
        self.assertIn("No workers - the control planes run workloads", k8s)
        self.assertNotIn("replace('default'", k8s)                      # names rebuilt, not text-replaced
        self.assertIn("current-context: \"{{ kc_name }}\"", k8s)

    def test_openscap_role(self):
        o = _read("ansible/roles/openscap/tasks/main.yml")
        self.assertNotIn("dest: /opt", o)
        self.assertIn("unzip -o -j -q", o)
        self.assertIn("Remove the SSG release zip", o)
        self.assertIn("usg audit", o)
        self.assertIn("meta: end_host", o)
        self.assertIn("'skipped'", o)
        self.assertIn(f'ssg_version: "{scan.SSG_FALLBACK}"', _read("ansible/scan.yml"))

    def test_misc(self):
        self.assertNotRegex(_read("ansible/ansible.cfg"), r"(?m)^inventory\s*=")
        self.assertIn("-i localhost,", _read("ansible/bastion.yml").splitlines()[1])
        motd = _read("ansible/roles/common/templates/motd.j2")
        self.assertIn("ljust(w)", motd)
        self.assertIn("install_terraform", motd)
        self.assertIn("motd_title: cloudseed VPN host", _read("ansible/vpn.yml"))


if __name__ == "__main__":
    unittest.main()
