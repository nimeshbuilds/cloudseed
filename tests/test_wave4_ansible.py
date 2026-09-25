"""Regression tests for the wave-4 Ansible/provisioning items (cloudseed/provision.py, ansible/**): the unreachable-host
advice (whole commands, a refused key, the host's own label under OS Login, a caller's retry), the flags a re-run
repeats, the hardening choice of local Kubernetes nodes, the environment of local playbooks, kubectl on the bastion,
the apt timers of older VMware bastions, RKE2's Pod Security admission under the CIS profile and the OpenVPN pool
message. Stdlib only, no network, no real hosts: subprocess is mocked or points at tiny local scripts."""

import json
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, creds, deps, paths, provision, ui  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
ROLES = REPO / "ansible" / "roles"


def _read(rel: str) -> str:
    return (REPO / rel).read_text()


def _task(text: str, name: str) -> str:
    """The YAML text of one task (from its `- name:` line to the next task at the same indentation)."""
    m = re.search(r"^(\s*)- name: " + re.escape(name) + r"\s*$", text, re.M)
    if not m:
        raise AssertionError(f"no task named {name!r}")
    rest = text[m.end():]
    nxt = re.search(r"^" + re.escape(m.group(1)) + r"- name: ", rest, re.M)
    return text[m.start():m.end() + (nxt.start() if nxt else len(rest))]


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


DENIED = "ec2-user@198.51.100.9: Permission denied (publickey).\n"
TIMEOUT = "ssh: connect to host 198.51.100.9 port 22: Operation timed out\n"
OS_LOGIN = {"account": "user@example.com", "user": "user_example_com", "member": "user:user@example.com"}


# ---------------------------------------------------------------- Host.wait's advice (a2-ansible#10, a2-gcp#4, a2-resilience#20f)

class UnreachableAdviceTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.td.cleanup()

    def _env(self, cloud: str, cfg: dict) -> paths.Env:
        env = paths.Env(cloud, "w4", Path(self.td.name) / cloud)
        env.create_dirs()
        env.save(dict({"name": "cs", "env": "w4"}, **cfg))
        return env

    def _abort(self, env, stderr: str, label: str = "bastion", user: str = "ec2-user", **kw) -> str:
        h = provision.Host("198.51.100.9", user, Path(self.td.name) / "id_ed25519", label, env=env)
        clock = iter([0, 0, 1000, 1000, 1000])
        with mock.patch.object(provision.subprocess, "run", return_value=FakeProc(255, "", stderr)), \
                mock.patch.object(provision.time, "time", side_effect=lambda: next(clock)), \
                mock.patch.object(provision.time, "sleep"), mock.patch.object(ui, "err"), mock.patch("builtins.print"):
            with self.assertRaises(ui.Abort) as cm:
                h.wait(timeout=5, **kw)
        return cm.exception.msg

    def test_commands_name_the_cloud_and_the_environment(self):
        msg = self._abort(self._env("aws", {"vars": {}}), TIMEOUT)
        self.assertIn("`cloudseed status aws --env w4`", msg)
        self.assertIn("`cloudseed update-ip aws --env w4`", msg)
        self.assertIn("then re-run `cloudseed provision aws --env w4`.", msg)
        self.assertNotIn("`cloudseed provision`", msg)                    # the bare form fails: 'needs a cloud'
        self.assertNotIn("`cloudseed update-ip`", msg)

    def test_a_refused_key_names_the_key_and_the_user_not_the_network(self):
        env = self._env("aws", {"vars": {}})
        msg = self._abort(env, DENIED)
        key = str(Path(self.td.name) / "id_ed25519")
        self.assertIn(f"The bastion refuses the SSH key {key} for user ec2-user", msg)
        self.assertIn("ssh-keygen -y -f", msg)
        self.assertIn(str(env.config_path), msg)
        self.assertIn("cloudseed setup aws --env w4 --ssh-public-key", msg)
        self.assertNotIn("update-ip", msg)                                  # a wrong source IP times out, never refuses
        self.assertEqual(msg.count("then re-run `cloudseed provision aws --env w4`."), 1)
        self.assertNotIn("OS Login", msg)

    def test_a_refused_key_on_gcp_without_os_login_mentions_an_enforcing_org_policy(self):
        msg = self._abort(self._env("gcp", {"vars": {"enable_os_login": False}}), DENIED)
        self.assertIn("enforces OS Login", msg)
        self.assertIn("`cloudseed setup gcp --env w4 --var enable_os_login=true`", msg)   # a whole command
        self.assertNotIn("update-ip", msg)

    def test_local_vms_get_the_vm_side_of_a_refused_key(self):
        env = self._env("vmware", {"vars": {}})
        msg = self._abort(env, DENIED, label="cs-w4-wk2")
        self.assertIn("The VM cs-w4-wk2 refuses the SSH key", msg)
        self.assertIn("cloud-init", msg)
        self.assertNotIn("update-ip", msg)
        timeout = self._abort(env, TIMEOUT)
        self.assertIn("Check that the VM is running (`cloudseed status vmware --env w4`)", timeout)
        self.assertIn("then re-run `cloudseed provision vmware --env w4`.", timeout)
        self.assertNotIn("update-ip", timeout)

    def test_os_login_advice_names_the_host_it_is_about(self):
        cfg = {"vars": {"enable_os_login": True, "project_id": "p-1"}, "os_login": OS_LOGIN}
        for label, what in (("vpn", "VPN host"), ("bastion", "bastion")):
            for err in (DENIED, TIMEOUT):
                msg = self._abort(self._env("gcp", cfg), err, label=label, user="user_example_com")
                self.assertIn(f"OS Login is on: the {what} accepts only user_example_com", msg)
                self.assertIn(f"roles/compute.osAdminLogin on the {what} ", msg)
                if label == "vpn":
                    self.assertNotIn("bastion", msg)
                self.assertEqual("update-ip" in msg, err == TIMEOUT, (label, err))
                self.assertIn("then re-run `cloudseed provision gcp --env w4`.", msg)
        refused = self._abort(self._env("gcp", {"vars": {"enable_os_login": True}}), DENIED, label="vpn")
        self.assertIn("which an OS Login VPN host ignores", refused)
        self.assertIn("`cloudseed setup gcp --env w4`", refused)

    def test_a_caller_passes_its_own_retry(self):
        env = self._env("aws", {"vars": {}})
        again = "then re-run the scan (cs scan host aws --env w4)."
        for err in (TIMEOUT, DENIED):
            msg = self._abort(env, err, retry=again)
            self.assertTrue(msg.endswith(again), msg)
            self.assertNotIn("re-run `cloudseed provision", msg)

    def test_the_first_sentence_names_the_host_as_the_advice_does(self):
        # not the internal label ('vpn did not accept SSH'): the same words as the advice after it
        gcp = self._env("gcp", {"vars": {"enable_os_login": True}, "os_login": OS_LOGIN})
        msg = self._abort(gcp, DENIED, label="vpn", user="user_example_com")
        self.assertTrue(msg.startswith("The VPN host at 198.51.100.9 did not accept SSH within 5s. Last error: "), msg)
        self.assertIn("The VPN host refuses the SSH key", msg)
        node = self._abort(self._env("vmware", {"vars": {}}), TIMEOUT, label="cs-w4-wk1")
        self.assertTrue(node.startswith("The VM cs-w4-wk1 at 198.51.100.9 did not accept SSH within 5s."), node)
        bastion = self._abort(self._env("aws", {"vars": {}}), TIMEOUT)
        self.assertTrue(bastion.startswith("The bastion at 198.51.100.9 did not accept SSH within 5s."), bastion)

    def test_without_an_environment_the_placeholders_stay(self):
        h = provision.Host("10.0.0.5", "u", Path("/k"), "bastion", local=False)
        self.assertEqual(h.command("provision"), "cloudseed provision <cloud> --env <name>")
        hint = h._unreachable_hint(TIMEOUT.strip())
        self.assertIn("`cloudseed update-ip <cloud> --env <name>`", hint)


# ---------------------------------------------------------------- the command a re-run repeats (a2-ansible#10)

class RerunCommandTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("aws", "rr", Path(self.td.name) / "w")
        self.env.create_dirs()
        self.cfg = {"name": "cs", "env": "rr", "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.4/32"],
                    "region": "us-east-1", "vars": {"enable_kubernetes": True, "kubernetes_version": "1.33"},
                    "ssh_private_key_path": str(Path(self.td.name) / "key")}
        self._others = mock.patch.object(provision, "_other_env_networks", return_value=[])
        self._others.start()

    def tearDown(self):
        self._others.stop()
        self.td.cleanup()

    def test_the_command_keeps_the_choices_of_the_run(self):
        aws = clouds.get("aws")
        self.assertEqual(provision.rerun_command(aws, self.env), "cloudseed provision aws --env rr")
        self.assertEqual(provision.rerun_command(aws, self.env, "vpn", harden=False, firewall=False),
                         "cloudseed provision aws --env rr --host vpn --no-harden --no-firewall")
        self.assertEqual(provision.rerun_command(aws, self.env, tools=False), "cloudseed provision aws --env rr --no-tools")
        self.assertEqual(provision.rerun_command(aws, self.env, harden=False, sync_only=True),
                         "cloudseed provision aws --env rr --sync-only")

    def _provision(self, rc=0, **kw):
        waits, put = [], {}
        with mock.patch.object(provision.Host, "wait", lambda s, timeout=420, retry=None: waits.append(retry)), \
                mock.patch.object(provision.Host, "wait_cloud_init"), mock.patch.object(provision.Host, "sync_repo"), \
                mock.patch.object(provision.Host, "remove_secrets"), \
                mock.patch.object(provision.Host, "put_json", lambda s, p, d: put.update({p: d})), \
                mock.patch.object(provision.Host, "run", lambda s, cmd, env=None: rc), \
                mock.patch.object(ui, "header"), mock.patch.object(ui, "err"), mock.patch.object(ui, "warn"), \
                mock.patch.object(ui, "ok"), mock.patch.object(ui, "info"), mock.patch.object(provision.audit, "note"):
            try:
                provision.provision(clouds.get("aws"), self.env, self.cfg,
                                    {"bastion_public_ip": "198.51.100.9", "vpn_public_ip": "198.51.100.10",
                                     "kubernetes_cluster_name": "cs-rr-eks"}, **kw)
                err = None
            except ui.Abort as e:
                err = e.msg
        return waits, put.get("~/cloudseed-vars.json"), err

    def test_a_host_that_never_answers_is_retried_with_the_same_flags(self):
        waits, _, _ = self._provision(harden=False, extra_vars={"allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertEqual(waits, ["then re-run `cloudseed provision aws --env rr --no-harden`."])
        waits, _, _ = self._provision(playbook="vpn.yml", host_key="vpn_public_ip", label="vpn", tools=False,
                                      extra_vars={"vpn_type": "openvpn", "allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertEqual(waits, ["then re-run `cloudseed provision aws --env rr --host vpn`."])   # no --no-tools

    def test_a_caller_names_its_own_run(self):
        # `provision --host bastion --no-harden`: the whole environment's re-run would un-harden the other hosts too
        only = provision.rerun_command(clouds.get("aws"), self.env, "bastion", harden=False)
        waits, _, err = self._provision(rc=2, harden=False, rerun=only,
                                        extra_vars={"allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertEqual(waits, ["then re-run `cloudseed provision aws --env rr --host bastion --no-harden`."])
        self.assertIn("Re-run with: cloudseed provision aws --env rr --host bastion --no-harden", err)

    def test_a_failed_playbook_names_the_same_command(self):
        _, _, err = self._provision(rc=2, firewall=False, extra_vars={"allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertIn("Re-run with: cloudseed provision aws --env rr --no-firewall", err)

    def test_the_bastion_learns_about_the_managed_cluster(self):   # a2-aws#10
        _, vars_, _ = self._provision(extra_vars={"allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertIs(vars_["enable_kubernetes"], True)
        self.assertEqual(vars_["kubernetes_version"], "1.33")
        self.assertEqual(vars_["kubernetes_cluster_name"], "cs-rr-eks")
        self.assertEqual(vars_["cloud_region"], "us-east-1")
        self.cfg["vars"] = {"enable_kubernetes": "false"}           # a string saved by an older version is off
        _, vars_, _ = self._provision(extra_vars={"allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertIs(vars_["enable_kubernetes"], False)
        self.assertEqual(vars_["kubernetes_version"], "")


# ---------------------------------------------------------------- local Kubernetes: harden record and re-run (a2-ansible#4)

class LocalKubernetesTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("vmware", "k4", Path(self.td.name) / "w")
        self.env.create_dirs()
        self.cfg = {"name": "cs", "env": "k4", "vars": {"ssh_username": "u", "kubernetes_distro": "rke2"},
                    "ssh_private_key_path": str(Path(self.td.name) / "key")}
        self.outputs = {"kubernetes_control_plane_ips": ["10.30.0.20"], "kubernetes_worker_ips": ["10.30.0.40"]}
        self.ok = _script(Path(self.td.name) / "ansible-playbook", "exit 0\n")
        self.bad = _script(Path(self.td.name) / "ansible-playbook-fails", "exit 2\n")

    def tearDown(self):
        self.td.cleanup()

    def _install(self, playbook=None, **kw):
        waits = []
        with mock.patch.object(provision.Host, "wait", lambda s, timeout=420, retry=None: waits.append(retry)), \
                mock.patch.object(provision.Host, "wait_cloud_init"), \
                mock.patch.object(deps, "ensure_local_ansible", return_value=playbook or self.ok), \
                mock.patch.object(provision, "forget_host_key"), mock.patch.object(provision, "_source_cidrs", return_value=[]), \
                mock.patch.object(ui, "header"), mock.patch.object(ui, "panel"), mock.patch.object(ui, "warn"), \
                mock.patch("builtins.print"), mock.patch.object(provision.audit, "note"):
            provision.provision_local_kubernetes(clouds.get("vmware"), self.env, self.cfg, self.outputs, **kw)
        return json.loads((self.env.dir / "k8s" / "vars.json").read_text()), waits

    def test_the_hardening_choice_is_recorded(self):
        self._install(harden=False)
        self.assertIs(self.cfg["provisioned"]["kubernetes"]["harden"], False)
        self.assertIs(self.env.load()["provisioned"]["kubernetes"]["harden"], False)
        self._install(harden=True)
        self.assertIs(self.cfg["provisioned"]["kubernetes"]["harden"], True)

    def test_without_a_choice_the_nodes_keep_the_recorded_one(self):
        # e.g. `cs undo` re-joining nodes: a cluster provisioned --no-harden is never hardened behind the user's back
        self.cfg["provisioned"] = {"kubernetes": {"harden": False}}
        v, waits = self._install()
        self.assertEqual((v["harden"], v["harden_ssh"], v["enable_auditd"]), (False, False, False))
        self.assertTrue(all(w == "then re-run `cloudseed provision vmware --env k4 --host k8s --no-harden`." for w in waits))
        self.assertEqual(len(waits), 2)
        self.cfg["provisioned"] = {"bastion": {"harden": False}}          # older record: the bastion's flags
        self.assertFalse(provision.saved_harden(self.cfg))
        self.assertTrue(provision.saved_harden({}))
        self.assertTrue(provision.saved_harden({"provisioned": {"kubernetes": {"harden": "maybe"}}}))

    def test_a_failed_install_names_the_command_with_the_same_choice(self):
        with self.assertRaises(ui.Abort) as cm:
            self._install(playbook=self.bad, harden=False)
        self.assertIn("Re-run: cloudseed provision vmware --env k4 --host k8s --no-harden", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            self._install(playbook=self.bad, harden=True, rerun="cs node add worker vmware --env k4")
        self.assertIn("Re-run: cs node add worker vmware --env k4", cm.exception.msg)

    def test_a_cis_profile_saved_as_false_text_stays_off(self):
        self.cfg["vars"]["kubernetes_cis_profile"] = "false"
        v, _ = self._install(harden=True)
        self.assertIs(v["rke2_cis_profile"], False)
        self.cfg["vars"]["kubernetes_cis_profile"] = True
        v, _ = self._install(harden=True)
        self.assertIs(v["rke2_cis_profile"], True)


# ---------------------------------------------------------------- local playbooks' environment (a2-agentic#8)

class AnsibleEnvTests(unittest.TestCase):
    def test_vault_values_stay_out_except_what_a_playbook_reads(self):
        shell = {"PATH": os.environ.get("PATH", ""), "ANSIBLE_ROLES_PATH": "/mine", "AWS_PROFILE": "shell-profile"}
        vault = {"ANSIBLE_CALLBACKS_ENABLED": "evil", "AWS_SECRET_ACCESS_KEY": "vault-secret",
                 "UBUNTU_PRO_TOKEN": "C12345" + "67890PRO"}
        with mock.patch.dict(os.environ, dict(shell, **vault), clear=True), mock.patch.dict(creds.APPLIED, vault, clear=True):
            env = provision.ansible_env()
        self.assertNotIn("ANSIBLE_CALLBACKS_ENABLED", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertEqual(env["UBUNTU_PRO_TOKEN"], "C12345" + "67890PRO")         # kubernetes.yml: lookup('env', ...)
        self.assertEqual(env["ANSIBLE_ROLES_PATH"], "/mine")                # the user's own shell stays
        self.assertEqual(env["AWS_PROFILE"], "shell-profile")
        self.assertEqual(env["ANSIBLE_HOST_KEY_CHECKING"], "True")
        self.assertTrue(env["ANSIBLE_CONFIG"].endswith(os.path.join("ansible", "ansible.cfg")))

    def test_a_shell_value_the_vault_also_holds_is_kept(self):
        with mock.patch.dict(os.environ, {"AWS_REGION": "eu-west-1"}, clear=True), mock.patch.dict(creds.APPLIED, {}, clear=True):
            self.assertEqual(provision.ansible_env()["AWS_REGION"], "eu-west-1")
        self.assertIn("UBUNTU_PRO_TOKEN", provision.ANSIBLE_VAULT_VARS)
        self.assertIn("lookup('env', 'UBUNTU_PRO_TOKEN')", _read("ansible/kubernetes.yml"))

    def test_through_the_real_vault_injection(self):
        # what the CLI does at start (creds.apply fills in what the shell did not export), then a local playbook run
        vault = {"AWS_DEFAULT_REGION": "us-east-1", "OPENAI_API_KEY": "sk-vault", "UBUNTU_PRO_TOKEN": "C12345" + "67890PRO"}
        with mock.patch.dict(os.environ, {"PATH": os.environ.get("PATH", ""), "AWS_DEFAULT_REGION": "eu-west-1"},
                             clear=True), \
                mock.patch.dict(creds.APPLIED, {}, clear=True), mock.patch.object(creds, "env", return_value=vault):
            creds.apply()
            self.assertEqual(os.environ["OPENAI_API_KEY"], "sk-vault")        # this process has it ...
            env = provision.ansible_env()
        self.assertNotIn("OPENAI_API_KEY", env)                                 # ... ansible-playbook does not
        self.assertEqual(env["UBUNTU_PRO_TOKEN"], "C12345" + "67890PRO")
        self.assertEqual(env["AWS_DEFAULT_REGION"], "eu-west-1")               # the shell's own value wins and stays


# ---------------------------------------------------------------- kubectl on the bastion, FIPS endpoints (a2-aws#10)

class BastionKubectlTests(unittest.TestCase):
    TOOLS = _read("ansible/roles/tools/tasks/main.yml")

    def test_kubectl_is_for_managed_clusters_and_follows_the_tools_flag(self):
        bastion = _read("ansible/bastion.yml")
        m = re.search(r"^\s+install_kubectl: (.+)$", bastion, re.M)
        self.assertIsNotNone(m)
        expr = m.group(1)
        for part in ("install_cloud_cli | bool", "enable_kubernetes | bool", "cloud in ['aws', 'gcp', 'azure']"):
            self.assertIn(part, expr)
        for var in ("enable_kubernetes: false", 'kubernetes_version: ""', 'kubernetes_cluster_name: ""', 'cloud_region: ""'):
            self.assertIn(var, bastion)

    def test_kubectl_is_checksum_verified_from_dl_k8s_io(self):
        dl = _task(self.TOOLS, "kubectl (checksum verified)")
        self.assertIn("url: \"https://dl.k8s.io/release/{{ kubectl_release.content | trim }}/bin/linux/{{ tf_arch }}/kubectl\"", dl)
        self.assertIn("checksum: \"sha256:https://dl.k8s.io/release/{{ kubectl_release.content | trim }}/bin/linux/{{ tf_arch }}/kubectl.sha256\"", dl)
        self.assertIn("dest: /usr/local/bin/kubectl", dl)
        self.assertIn('mode: "0755"', dl)
        release = _task(self.TOOLS, "kubectl release to install")
        self.assertIn("stable-' + kubectl_minor", release)
        check = _task(self.TOOLS, "kubectl release answer is a version")
        self.assertIn("is match('^v[0-9]+[.][0-9]+[.][0-9]+$')", check)
        self.assertLess(self.TOOLS.index("- name: kubectl release answer is a version"),
                        self.TOOLS.index("- name: kubectl (checksum verified)"))
        for name in ("Kubernetes minor version for kubectl", "kubectl release to install", "kubectl (checksum verified)"):
            self.assertIn("when: install_kubectl | bool", _task(self.TOOLS, name))

    def test_the_eks_version_lookup_is_optional_and_boolean(self):
        eks = _task(self.TOOLS, "Cluster Kubernetes version (EKS, when the configuration leaves it to EKS)")
        self.assertIn("failed_when: false", eks)
        self.assertIn("argv: [aws, eks, describe-cluster", eks)
        self.assertIn("AWS_USE_FIPS_ENDPOINT", eks)
        # ansible-core 2.19+: a conditional must be a boolean, never a bare string
        self.assertIn("| length > 0", eks)
        self.assertNotRegex(eks, r"and \((kubernetes_cluster_name|cloud_region) \| default\('', true\)\)")

    def test_the_login_message_lists_what_is_installed(self):
        motd = _read("ansible/roles/common/templates/motd.j2")
        self.assertIn("['kubectl'] if install_kubectl | default(false) | bool", motd)
        self.assertIn("{'aws': 'aws', 'gcp': 'gcloud', 'azure': 'az'}", motd)
        self.assertNotIn("'cloud CLI'", motd)                               # a VMware bastion has none

    def test_fips_mode_points_the_aws_cli_at_the_fips_endpoints(self):
        on = _task(self.TOOLS, "AWS CLI uses the FIPS endpoints (FIPS mode)")
        self.assertIn("dest: /etc/profile.d/cloudseed-aws-fips.sh", on)
        self.assertIn("export AWS_USE_FIPS_ENDPOINT=true", on)
        self.assertIn("mode: \"0644\"", on)                                 # readable under the hardened umask
        self.assertIn("when: cloud == 'aws' and fips_mode | default(false) | bool", on)
        off = _task(self.TOOLS, "No AWS FIPS endpoint setting outside FIPS mode")
        self.assertIn("state: absent", off)


# ---------------------------------------------------------------- apt timers on older VMware bastions (a2-ansible#6)

class AptTimersTests(unittest.TestCase):
    ROLE = _read("ansible/roles/hardening/tasks/main.yml")

    def test_a_per_boot_script_switches_the_timers_back_on(self):
        task = _task(self.ROLE, "Keep the apt timers on after every boot")
        self.assertIn("dest: /var/lib/cloud/scripts/per-boot/50-cloudseed-apt-timers.sh", task)
        self.assertIn('mode: "0755"', task)
        self.assertIn("systemctl unmask apt-daily.service apt-daily-upgrade.service", task)
        self.assertIn("systemctl enable --now --no-block apt-daily.timer apt-daily-upgrade.timer", task)
        self.assertIn("when: auto_updates and ansible_facts['os_family'] == 'Debian'", task)
        self.assertIn("#!/bin/sh", task)
        self.assertLess(self.ROLE.index("- name: Enable apt timers"), self.ROLE.index("- name: cloud-init per-boot scripts directory"))
        self.assertLess(self.ROLE.index("- name: cloud-init per-boot scripts directory"),
                        self.ROLE.index("- name: Keep the apt timers on after every boot"))

    def test_the_legacy_template_really_masks_on_every_boot(self):
        # what the script undoes: the frozen template's bootcmd (every boot); new VMs mask on the first boot only
        tf = _read("terraform/vmware/modules/bastion/main.tf")
        self.assertIn("- [systemctl, mask, apt-daily.service, apt-daily-upgrade.service]", tf)
        self.assertIn("cloud-init-per, instance, cloudseed-apt-off", tf)


# ---------------------------------------------------------------- RKE2 CIS profile: Pod Security admission (a2-resilience#5)

class Rke2PodSecurityTests(unittest.TestCase):
    RKE2 = _read("ansible/roles/rke2/tasks/main.yml")

    def test_restricted_defaults_with_cloudseed_namespaces_exempt(self):
        fact = _task(self.RKE2, "Pod Security admission configuration (CIS profile)")
        for line in ('enforce: "restricted"', 'audit: "restricted"', 'warn: "restricted"', 'enforce-version: "latest"',
                     "kind: AdmissionConfiguration", "apiVersion: pod-security.admission.config.k8s.io/v1",
                     "- name: PodSecurity"):
            self.assertIn(line, fact)
        for ns in ("kube-system", "tigera-operator", "compliance-operator-system",
                   "cloudseed-scan", "velero", "local-path-storage", "minio", "chaos-mesh"):
            self.assertIn(ns, fact)
        self.assertIn("when: rke2_cis_profile | default(false) | bool and node_role == 'server'", fact)
        # the namespaces cloudseed's features create really are these
        self.assertIn("cloudseed-scan", _read("cloudseed/scan.py"))
        platform = _read("cloudseed/platform.py")
        for ns in ('"ns": "velero"', '"ns": "local-path-storage"', '"ns": "minio"', '"ns": "chaos-mesh"'):
            self.assertIn(ns, platform)

    def test_the_file_is_written_before_the_config_that_names_it(self):
        write = _task(self.RKE2, "Pod Security admission configuration file (CIS profile)")
        self.assertIn("dest: /etc/rancher/rke2/cloudseed-pss.yaml", write)
        self.assertIn('mode: "0600"', write)
        self.assertLess(self.RKE2.index("- name: Pod Security admission configuration file (CIS profile)"),
                        self.RKE2.index("- name: RKE2 config\n"))
        config = _task(self.RKE2, "RKE2 config")
        server = config[config.index("{% if node_role == 'server' %}"):config.index("{% else %}")]
        self.assertIn("pod-security-admission-config-file: /etc/rancher/rke2/cloudseed-pss.yaml", server)
        # a changed exemption list changes config.yaml, so the existing restart task restarts the server
        self.assertIn("{{ rke2_pss_config | hash('sha1') }}", server)
        self.assertIn("when: rke2_config is changed and rke2_started is not changed",
                      _task(self.RKE2, "Restart rke2-{{ node_role }} with the changed config"))

    def test_outside_the_cis_profile_the_file_goes(self):
        gone = _task(self.RKE2, "No cloudseed Pod Security admission configuration outside the CIS profile")
        self.assertIn("state: absent", gone)
        self.assertLess(self.RKE2.index("- name: RKE2 config\n"),
                        self.RKE2.index("- name: No cloudseed Pod Security admission configuration outside the CIS profile"))


# ---------------------------------------------------------------- OpenVPN pool moves are explained (ansible reviewer)

class VpnPoolMessageTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("aws", "vm", Path(self.td.name) / "w")

    def tearDown(self):
        self.td.cleanup()

    def _choose(self, cfg, others):
        infos = []
        with mock.patch.object(provision, "_other_env_networks", return_value=others), \
                mock.patch.object(ui, "info", lambda m: infos.append(m)):
            pool = provision.choose_vpn_client_cidr(clouds.get("aws"), self.env, cfg, {})
        return pool, infos

    def test_a_pool_without_a_saved_one_says_why_it_is_not_the_default(self):
        # a VPN provisioned before pools were chosen ran 10.8.0.0/24: it is told that it moves
        pool, infos = self._choose({"network_cidr": "10.0.0.0/16", "provisioned": {"vpn": {"at": "x"}}}, ["10.8.0.0/24"])
        self.assertEqual(pool, "10.255.255.0/24")
        self.assertEqual(len(infos), 1)
        self.assertIn("10.8.0.0/24 is used by another environment's network or VPN", infos[0])
        self.assertIn("moving it from 10.8.0.0/24 to 10.255.255.0/24", infos[0])
        self.assertIn("Client profiles need no change", infos[0])
        # a new VPN is only told which pool it got and why
        pool, infos = self._choose({"network_cidr": "10.8.0.0/16"}, [])
        self.assertEqual(infos, ["OpenVPN client pool: 10.255.255.0/24 (10.8.0.0/24 overlaps a network the VPN routes)."])

    def test_the_default_or_a_kept_pool_says_nothing(self):
        self.assertEqual(self._choose({"network_cidr": "10.0.0.0/16"}, []), ("10.8.0.0/24", []))
        self.assertEqual(self._choose({"network_cidr": "10.0.0.0/16", "vpn_client_cidr": "10.8.0.0/24"}, ["10.8.0.0/24"]),
                         ("10.8.0.0/24", []))


if __name__ == "__main__":
    unittest.main()
