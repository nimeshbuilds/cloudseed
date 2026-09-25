"""Regression tests for the wave-3 Ansible/provisioning items (cloudseed/provision.py, ansible/**): the OpenVPN client
pool, the FIPS reboot, --no-harden/--no-firewall on an earlier-hardened host, fail2ban and the operator's address, the
OpenVPN certificates and log, Flannel/RKE2/kubeadm, the repository copy, auditd and the provisioning output.
Stdlib only, no network, no real hosts: subprocess is mocked or points at tiny local scripts."""

import base64
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, deps, paths, provision, ui  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
ROLES = REPO / "ansible" / "roles"


def _read(rel: str) -> str:
    return (REPO / rel).read_text()


def _code(text: str) -> str:
    """The text without comments (a comment may name what the code no longer does)."""
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


def _jinja_python():
    """A Python with jinja2 (this one, or cloudseed's local Ansible venv), else None: render tests are skipped."""
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


def _render(template_dir: Path, name: str, **v) -> str:
    """Render a role template like Ansible's template module (trim_blocks; `bool` is an Ansible filter)."""
    code = ("import jinja2,json,sys\n"
            "e=jinja2.Environment(loader=jinja2.FileSystemLoader(sys.argv[1]),trim_blocks=True)\n"
            "e.filters['bool']=lambda v: v if isinstance(v,bool) else str(v).strip().lower() in ('1','true','yes','on')\n"
            "print(e.get_template(sys.argv[2]).render(**json.loads(sys.argv[3])))\n")
    return subprocess.run([_jinja_python(), "-c", code, str(template_dir), name, json.dumps(v)],
                          capture_output=True, text=True, check=True, timeout=60).stdout


def _ansible_playbook():
    """cloudseed's local Ansible (deps.ensure_local_ansible installs it there), else None: those tests are skipped."""
    for base in (paths.HOME, Path.home() / ".cloudseed"):
        pb = Path(base) / "venv-ansible" / "bin" / "ansible-playbook"
        if pb.exists():
            return pb
    return None


def _overlaps(a: str, b: str) -> bool:
    return ipaddress.ip_network(a).overlaps(ipaddress.ip_network(b))


class _ProvisionHarness:
    """provision.provision() with every host interaction faked; returns (vars sent to the host, ok lines, info lines)."""

    def _provision(self, cloud="aws", rc=0, outputs=None, **kw):
        put, oks, infos = {}, [], []
        patches = [mock.patch.object(provision.Host, "wait"), mock.patch.object(provision.Host, "wait_cloud_init"),
                   mock.patch.object(provision.Host, "sync_repo"), mock.patch.object(provision.Host, "remove_secrets"),
                   mock.patch.object(provision.Host, "put_json", lambda s, p, d: put.update({p: d})),
                   mock.patch.object(provision.Host, "run", lambda s, cmd, env=None: rc),
                   mock.patch.object(ui, "header"), mock.patch.object(ui, "err"), mock.patch.object(ui, "warn"),
                   mock.patch.object(ui, "ok", lambda m: oks.append(m)),
                   mock.patch.object(ui, "info", lambda m: infos.append(m)),
                   mock.patch.object(provision.audit, "note")]
        for p in patches:
            p.start()
        try:
            provision.provision(clouds.get(cloud), self.env, self.cfg,
                                outputs if outputs is not None else {"bastion_public_ip": "198.51.100.9",
                                                                     "vpn_public_ip": "198.51.100.10"}, **kw)
        finally:
            for p in patches:
                p.stop()
        return put.get("~/cloudseed-vars.json"), oks, infos


# ---------------------------------------------------------------- OpenVPN client pool (a2-gcp#0, a2-azure#0, a2-ansible#1)

class VpnPoolTests(unittest.TestCase, _ProvisionHarness):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("aws", "vp", Path(self.td.name) / "w")
        self.env.create_dirs()
        self.cfg = {"name": "cs", "env": "vp", "network_cidr": "10.8.0.0/16", "allowed_ssh_cidrs": ["203.0.113.4/32"],
                    "vars": {}, "ssh_private_key_path": str(Path(self.td.name) / "key")}
        # other environments in CLOUDSEED_HOME are this test's business only
        self._others = mock.patch.object(provision, "_other_env_networks", return_value=[])
        self._others.start()

    def tearDown(self):
        self._others.stop()
        self.td.cleanup()

    def _pool(self, network, outputs=None):
        v = provision.vpn_network_vars({"network_cidr": network}, outputs or {})
        pool = str(ipaddress.ip_network(f"{v['vpn_client_net']}/{v['vpn_client_mask']}"))
        for r in v["vpn_routes"]:
            self.assertFalse(_overlaps(pool, r), (network, pool, r))
        return pool

    def test_existing_networks_keep_10_8_0_0(self):
        self.assertEqual(self._pool("10.0.0.0/16", {"kubernetes_master_cidr": "172.16.0.0/28"}), "10.8.0.0/24")
        self.assertEqual(self._pool("10.9.0.0/16"), "10.8.0.0/24")

    def test_a_network_holding_the_default_pool_gets_another(self):
        self.assertEqual(self._pool("10.8.0.0/16"), "10.255.255.0/24")      # the 9th auto-assigned network
        self.assertEqual(self._pool("10.8.0.0/13"), "10.255.255.0/24")
        self.assertEqual(self._pool("10.0.0.0/8"), "192.168.255.0/24")      # gcp/azure accept a /8
        self.assertEqual(self._pool("10.255.0.0/16"), "10.8.0.0/24")

    def test_never_cgnat_or_docker_ranges(self):
        for cand in provision._vpn_pool_candidates():
            net = ipaddress.ip_network(cand)
            self.assertFalse(net.overlaps(ipaddress.ip_network("100.64.0.0/10")), cand)
            self.assertFalse(net.overlaps(ipaddress.ip_network("172.16.0.0/12")), cand)
            self.assertTrue(net.is_private and net.prefixlen == 24, cand)

    def test_an_explicit_pool_inside_a_route_is_refused(self):
        with mock.patch.object(ui, "err"), self.assertRaises(ui.Abort) as cm:
            provision.vpn_network_vars({"network_cidr": "10.8.0.0/16"}, {}, "10.8.0.0/24")
        self.assertIn("overlaps 10.8.0.0/16", cm.exception.msg)
        with mock.patch.object(ui, "err"), self.assertRaises(ui.Abort):
            provision.vpn_network_vars({"network_cidr": "10.0.0.0/16"}, {}, "not-a-cidr")

    def test_other_environments_are_avoided_when_possible(self):
        self.assertEqual(provision.pick_vpn_client_cidr(["10.0.0.0/16"], ["10.8.0.0/16"]), "10.255.255.0/24")
        self.assertEqual(provision.pick_vpn_client_cidr(["10.0.0.0/16"], ["10.8.0.0/24", "10.255.0.0/16"]), "10.254.255.0/24")
        # nothing free of the soft ranges: a pool that at least stays out of the routed networks
        self.assertEqual(provision.pick_vpn_client_cidr(["10.0.0.0/16"], ["0.0.0.0/0"]), "10.8.0.0/24")
        with mock.patch.object(ui, "err"), self.assertRaises(ui.Abort):
            provision.pick_vpn_client_cidr(["0.0.0.0/0"])

    def test_provision_saves_the_pool_and_reuses_it(self):
        vars_, _, _ = self._provision(playbook="vpn.yml", host_key="vpn_public_ip", label="vpn", tools=False,
                                      extra_vars={"vpn_type": "openvpn"})
        self.assertEqual((vars_["vpn_client_net"], vars_["vpn_routes"]), ("10.255.255.0", ["10.8.0.0/16"]))
        self.assertEqual(self.env.load()["vpn_client_cidr"], "10.255.255.0/24")
        # a later network next to it must not move a working pool
        with mock.patch.object(provision, "_other_env_networks", return_value=["10.255.0.0/16"]):
            vars_, _, _ = self._provision(playbook="vpn.yml", host_key="vpn_public_ip", label="vpn", tools=False)
        self.assertEqual(vars_["vpn_client_net"], "10.255.255.0")

    def test_a_saved_pool_that_now_overlaps_is_moved(self):
        self.cfg["vpn_client_cidr"] = "10.8.0.0/24"          # from before the network became 10.8.0.0/16
        vars_, _, infos = self._provision(playbook="vpn.yml", host_key="vpn_public_ip", label="vpn", tools=False)
        self.assertEqual(vars_["vpn_client_net"], "10.255.255.0")
        self.assertTrue(any("moving it to 10.255.255.0/24" in i for i in infos), infos)

    def test_azure_kubernetes_ranges_are_never_the_pool(self):
        env = paths.Env("azure", "vp", Path(self.td.name) / "az")
        env.create_dirs()
        cfg = {"network_cidr": "10.0.0.0/8", "vars": {"enable_kubernetes": True}}
        with mock.patch.object(ui, "info"):             # says which pool it took and why (wave 4)
            pool = provision.choose_vpn_client_cidr(clouds.get("azure"), env, cfg, {})
        for r in provision.AKS_RANGES + ("10.0.0.0/8",):
            self.assertFalse(_overlaps(pool, r), (pool, r))

    def test_tailscale_keeps_no_pool(self):
        self._provision(playbook="vpn.yml", host_key="vpn_public_ip", label="vpn", tools=False,
                        extra_vars={"vpn_type": "tailscale"})
        self.assertNotIn("vpn_client_cidr", self.env.load())

    def test_other_env_networks_reads_every_other_environment(self):
        self._others.stop()
        try:
            home = Path(self.td.name) / "home"
            with mock.patch.object(paths, "ENVS_DIR", home / "envs"), mock.patch.object(paths, "HOME", home), \
                    mock.patch.object(paths, "WORKDIRS_INDEX", home / "workdirs.json"):
                mine = paths.Env("aws", "a1")
                mine.save({"name": "cs", "env": "a1", "network_cidr": "10.0.0.0/16", "vars": {}})
                other = paths.Env("gcp", "b1")
                other.save({"name": "cs", "env": "b1", "network_cidr": "10.1.0.0/16", "vpn_client_cidr": "10.8.0.0/24",
                            "vars": {}})
                found = provision._other_env_networks(mine)
        finally:
            self._others.start()
        self.assertIn("10.1.0.0/16", found)
        self.assertIn("10.8.0.0/24", found)
        self.assertNotIn("10.0.0.0/16", found)

    def test_vpn_yml_values_are_only_fallbacks(self):
        self.assertIn("vpn_client_cidr", _read("ansible/vpn.yml"))


# ---------------------------------------------------------------- FIPS reboot (a2-ansible#0)

class FipsRebootTests(unittest.TestCase):
    ROLE = _read("ansible/roles/fips/tasks/main.yml")

    def test_reboot_never_goes_through_logind(self):
        code = _code(self.ROLE)
        self.assertNotIn("shutdown", code)                                   # /run/nologin blocks SSH for +1
        task = _task(self.ROLE, "Schedule a reboot one minute after provisioning finishes (local play)")
        self.assertIn("systemd-run", task)
        self.assertIn("--on-active=60", task)
        self.assertIn("systemctl stop cloudseed-fips-reboot.timer", task)    # a re-run inside the minute
        self.assertIn("reboot", task)

    def test_marker_is_written_before_the_reboot_is_scheduled(self):
        self.assertLess(self.ROLE.index("- name: FIPS reboot pending marker"),
                        self.ROLE.index("- name: Schedule a reboot one minute after provisioning finishes"))
        stale = _task(self.ROLE, "No FIPS reboot pending")
        self.assertIn("state: absent", stale)
        self.assertIn("when: fips_active", stale)

    def _await(self, answers, wait_side=None):
        host = provision.Host("198.51.100.9", "ec2-user", Path("/nonexistent/key"), "bastion")
        calls = []

        def run(cmd, **kw):
            calls.append(cmd[-1])
            return answers.pop(0)
        with mock.patch.object(provision.subprocess, "run", side_effect=run), \
                mock.patch.object(provision.time, "sleep") as sleep, \
                mock.patch.object(provision.Host, "wait", side_effect=wait_side) as wait, \
                mock.patch.object(ui, "ok") as ok, mock.patch.object(ui, "warn"), mock.patch.object(ui, "err"), \
                mock.patch("builtins.print"):
            try:
                provision.await_fips(host, "cloudseed provision aws --env f1")
                err = None
            except ui.Abort as e:
                err = e.msg
        return calls, sleep, wait, ok, err

    def test_ssh_refused_right_after_the_play_is_a_pending_reboot(self):
        calls, sleep, wait, ok, err = self._await([FakeProc(255, "", "Connection closed by 198.51.100.9 port 22"),
                                                   FakeProc(0), FakeProc(0, "1\n")])
        self.assertIsNone(err)
        sleep.assert_called_once_with(75)
        wait.assert_called_once()
        self.assertIn("rm -f /etc/cloudseed-fips-pending", calls[1])
        self.assertIn("FIPS mode active (fips_enabled=1)", ok.call_args_list[-1][0][0])

    def test_no_reboot_pending(self):
        calls, sleep, wait, ok, err = self._await([FakeProc(0, "no\n"), FakeProc(0, "1\n")])
        self.assertIsNone(err)
        sleep.assert_not_called()
        wait.assert_not_called()

    def test_an_unreadable_state_is_not_reported_as_fips_off(self):
        _, _, _, _, err = self._await([FakeProc(0, "no\n"), FakeProc(255, "", "Connection refused")])
        self.assertIn("could not read the FIPS state", err)
        self.assertNotIn("NOT active", err)
        self.assertIn("cloudseed provision aws --env f1", err)

    def test_fips_off_names_the_full_rerun(self):
        _, _, _, _, err = self._await([FakeProc(0, "no\n"), FakeProc(0, "0\n")])
        self.assertIn("FIPS mode is NOT active", err)
        self.assertIn("fips_enabled=0", err)
        self.assertIn("re-run: cloudseed provision aws --env f1", err)

    def test_a_host_that_never_comes_back_is_unreachable(self):
        _, _, wait, _, err = self._await([FakeProc(255)], wait_side=ui.Abort("bastion did not accept SSH within 600s."))
        self.assertIn("did not accept SSH", err)


# ---------------------------------------------------------------- --no-harden / --no-firewall on a hardened host (a2-ansible#3)

class ControlsOffTests(unittest.TestCase, _ProvisionHarness):
    ROLE = _read("ansible/roles/hardening/tasks/main.yml")

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("gcp", "off", Path(self.td.name) / "w")
        self.env.create_dirs()
        self.cfg = {"name": "cs", "env": "off", "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.4/32"],
                    "vars": {"ssh_username": "u"}, "ssh_private_key_path": str(Path(self.td.name) / "key")}

    def tearDown(self):
        self.td.cleanup()

    def test_every_hardening_file_is_removed_when_its_control_is_off(self):
        for name, path, cond in (
                ("cloudseed sshd settings from an earlier run (SSH hardening off)",
                 "/etc/ssh/sshd_config.d/00-cloudseed-hardening.conf", "not (harden_ssh | bool)"),
                ("cloudseed fail2ban jail from an earlier run (hardening off)",
                 "/etc/fail2ban/jail.d/cloudseed-sshd.local", "not (harden | default(true) | bool)"),
                ("cloudseed audit rules from an earlier run (auditd off)", "/etc/audit/rules.d/cloudseed.rules",
                 "not (enable_auditd | bool)")):
            task = _task(self.ROLE, name)
            self.assertIn(path, task)
            self.assertIn("state: absent", task)
            self.assertIn(f"when: {cond}", task)
        files = _task(self.ROLE, "cloudseed kernel, core dump and sudo settings from an earlier run (hardening off)")
        for path in ("/etc/sysctl.d/99-cloudseed-hardening.conf", "/etc/security/limits.d/99-cloudseed.conf",
                     "/etc/sudoers.d/99-cloudseed"):
            self.assertIn(path, files)
        stop = _task(self.ROLE, "fail2ban stopped (cloudseed installed it for the hardening)")
        self.assertIn("when: f2b_jail_removed is changed", stop)
        self.assertIn("enabled: false", stop)

    def test_firewall_off_only_touches_cloudseed_or_rule_less_rulesets(self):
        decide = _task(self.ROLE, "Host firewall off - what to write")
        self.assertIn("managed by cloudseed", decide)
        # single backslashes: Ansible passes a block scalar's regex through as written
        self.assertIn(r"search('\b(accept|drop|reject|masquerade", decide)
        self.assertNotIn(r"\\b", decide)
        write = _task(self.ROLE, "Host firewall off - cloudseed's NAT only")
        self.assertIn("src: nftables-off.conf.j2", write)
        self.assertIn("when: not host_firewall and nft_off_write | bool", write)
        self.assertIn("reload nftables", write)
        # the package / NAT boot load / ufw
        self.assertIn("host_firewall or (nft_off_write | default(false) | bool)", _task(self.ROLE, "nftables package"))
        self.assertIn("nft_needs_nat | bool", _task(self.ROLE, "nftables enabled (the NAT is loaded at boot)"))
        self.assertIn("when: host_firewall and", _task(self.ROLE, "Disable ufw if present (nftables takes over)"))

    @unittest.skipUnless(_ansible_playbook(), "no local ansible-playbook")
    def test_firewall_off_decision_runs_in_ansible(self):
        """The role's own set_fact task, run by ansible-playbook against the /etc/nftables.conf contents it meets."""
        task = _task(self.ROLE, "Host firewall off - what to write")
        stock = ("#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n\tchain input {\n"
                 "\t\ttype filter hook input priority filter;\n\t}\n}\n")
        custom = "#!/usr/sbin/nft -f\n# mine\ntable inet mine {\n chain input { tcp dport 22 accept\n }\n}\n"
        ours = _read("ansible/roles/hardening/templates/nftables.conf.j2")
        cases = {"stock_vpn": (stock, True, [], True), "stock_cloud": (stock, False, [], False),
                 "absent_vpn": (None, True, [], True), "custom_vpn": (custom, True, [], False),
                 "ours_cloud": (ours, False, [], True), "ours_vmware": (ours, False, ["10.1.0.0/24"], True)}
        plays = []
        for name, (content, vpn, nat, _) in cases.items():
            nft = {"content": base64.b64encode(content.encode()).decode()} if content is not None else {"msg": "missing"}
            body = "\n".join("    " + line if line else line for line in task.splitlines())
            plays.append(f"- name: {name}\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  vars:\n"
                         f"    host_firewall: false\n    vpn_forward: {str(vpn).lower()}\n"
                         f"    nat_source_cidrs: {json.dumps(nat)}\n    nft_current: {json.dumps(nft)}\n  tasks:\n{body}\n"
                         "    - ansible.builtin.debug:\n"
                         f"        msg: \"RESULT {name} {{{{ nft_off_write | bool }}}}\"\n")
        with tempfile.TemporaryDirectory() as td:
            pb = Path(td) / "pb.yml"
            pb.write_text("---\n" + "\n".join(plays))
            out = subprocess.run([str(_ansible_playbook()), "-i", "localhost,", str(pb)], capture_output=True, text=True,
                                 stdin=subprocess.DEVNULL, timeout=120,
                                 env=dict(os.environ, ANSIBLE_CONFIG=str(REPO / "ansible" / "ansible.cfg"), ANSIBLE_NOCOLOR="1"))
        self.assertEqual(out.returncode, 0, out.stdout[-2000:] + out.stderr[-2000:])
        got = dict(re.findall(r"RESULT (\w+) (True|False)", out.stdout))
        self.assertEqual(got, {name: str(c[3]) for name, c in cases.items()})

    @unittest.skipUnless(_jinja_python(), "jinja2 not available")
    def test_off_ruleset_removes_only_cloudseed_tables_and_keeps_nat(self):
        tdir = ROLES / "hardening" / "templates"
        cloud = _render(tdir, "nftables-off.conf.j2")
        self.assertIn("managed by cloudseed", cloud)
        self.assertNotIn("flush ruleset", _code(cloud))            # fail2ban's / Tailscale's tables stay
        self.assertIn("table inet filter\ndelete table inet filter", cloud)
        self.assertNotIn("masquerade", cloud)
        self.assertNotIn("policy drop", cloud)
        vpn = _render(tdir, "nftables-off.conf.j2", vpn_forward=True)
        self.assertIn('iifname { "tun0", "tailscale0" } oifname != { "tun0", "tailscale0" } masquerade', vpn)
        self.assertIn("table ip cloudseed_nat {", vpn)
        bastion = _render(tdir, "nftables-off.conf.j2", nat_source_cidrs=["10.1.0.0/24"])
        self.assertIn("ip saddr 10.1.0.0/24 oifname", bastion)

    def test_the_message_says_what_was_removed(self):
        self.cfg["provisioned"] = {"bastion": {"harden": True, "firewall": True, "tools": True}}
        _, oks, infos = self._provision(cloud="gcp", harden=False, firewall=False, extra_vars={"ssh_open_any": True})
        self.assertIn("OS hardening, host firewall skipped", oks[-1])
        removed = [i for i in infos if i.startswith("Removed from the bastion")]
        self.assertEqual(len(removed), 1, infos)
        self.assertIn("the host firewall", removed[0])
        self.assertIn("umask edits and automatic security updates stay", removed[0])
        rec = self.env.load()["provisioned"]["bastion"]
        self.assertEqual((rec["harden"], rec["firewall"]), (False, False))
        # a second run with the same flags removed nothing more
        _, _, infos = self._provision(cloud="gcp", harden=False, firewall=False, extra_vars={"ssh_open_any": True})
        self.assertFalse([i for i in infos if i.startswith("Removed from")], infos)


# ---------------------------------------------------------------- fail2ban and the operator's address (a2-ansible#5)

class Fail2banSourceTests(unittest.TestCase):
    def test_bootstrap_hands_the_ssh_source_to_the_play(self):
        text = _read("ansible/bootstrap.sh")
        start = text.index('CLIENT="${SSH_CLIENT:-}"')
        snippet = text[start:text.index('cd "$REPO/ansible"')]
        probe = ("set -euo pipefail\n" + snippet +
                 'for a in ${CLIENT_VARS[@]+"${CLIENT_VARS[@]}"}; do printf "%s|" "$a"; done\n')
        for ssh_client, want in (("172.16.128.1 51234 22", "-e|cloudseed_ssh_client=172.16.128.1|"),
                                 ("2001:db8::7 51234 22", "-e|cloudseed_ssh_client=2001:db8::7|"),
                                 ("", ""), ("$(id) 1 22", "")):
            env = dict(os.environ)
            env.pop("SSH_CLIENT", None)
            if ssh_client:
                env["SSH_CLIENT"] = ssh_client
            out = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(out.stdout, want, ssh_client)
        self.assertIn('${CLIENT_VARS[@]+"${CLIENT_VARS[@]}"} "$@"', text)

    def test_jail_ignores_that_source(self):
        jail = _task(_read("ansible/roles/hardening/tasks/main.yml"), "fail2ban sshd jail")
        self.assertIn("{% if (cloudseed_ssh_client | default('') | string) is match('^[0-9A-Fa-f:.]+$') %} "
                      "{{ cloudseed_ssh_client }}{% endif %}", jail)

    def test_local_source_address(self):
        self.assertIsNone(provision.local_source_address("not-an-ip"))
        self.assertIsNone(provision.local_source_address("127.0.0.1"))         # loopback: never a VM's view of us
        with mock.patch.object(provision.socket, "socket") as sock:
            sock.return_value.__enter__.return_value.getsockname.return_value = ("192.168.160.1", 5000)
            self.assertEqual(provision.local_source_address("192.168.160.20"), "192.168.160.1")
            sock.return_value.__enter__.return_value.connect.side_effect = OSError("no route")
            self.assertIsNone(provision.local_source_address("192.168.160.20"))
        with mock.patch.object(provision, "local_source_address", side_effect=["192.168.160.1", "192.168.160.1", None]):
            self.assertEqual(provision._source_cidrs(["a", "b", "c"]), ["192.168.160.1/32"])

    def test_local_bastion_ignores_the_host_adapter(self):
        with tempfile.TemporaryDirectory() as td:
            h = _ProvisionHarness()
            h.env = paths.Env("vmware", "fb", Path(td) / "w")
            h.env.create_dirs()
            h.cfg = {"name": "cs", "env": "fb", "network_cidr": "10.1.0.0/24", "allowed_ssh_cidrs": ["127.0.0.1/32"],
                     "vars": {"ssh_username": "u"}, "ssh_private_key_path": str(Path(td) / "key")}
            with mock.patch.object(provision, "local_source_address", return_value="172.16.128.1"):
                vars_, _, _ = h._provision(cloud="vmware", extra_vars={"allowed_ssh_cidrs": [], "ssh_open_any": True})
        self.assertIn("172.16.128.1/32", vars_["fail2ban_ignore_cidrs"])

    def test_cloud_hosts_do_not_add_a_lan_address(self):
        with tempfile.TemporaryDirectory() as td:
            h = _ProvisionHarness()
            h.env = paths.Env("aws", "fc", Path(td) / "w")
            h.env.create_dirs()
            h.cfg = {"name": "cs", "env": "fc", "network_cidr": "10.1.0.0/16", "allowed_ssh_cidrs": ["203.0.113.4/32"],
                     "vars": {}, "ssh_private_key_path": str(Path(td) / "key")}
            with mock.patch.object(provision, "local_source_address", return_value="192.168.1.5") as src:
                vars_, _, _ = h._provision(extra_vars={"allowed_ssh_cidrs": [], "ssh_open_any": True})
            src.assert_not_called()
        self.assertEqual(vars_["fail2ban_ignore_cidrs"], ["203.0.113.4/32"])


# ---------------------------------------------------------------- local Kubernetes (a2-ansible#2, #5, #12, #13)

class LocalKubernetesTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("vmware", "k3", Path(self.td.name) / "vmware-k3")
        self.env.create_dirs()
        self.cfg = {"name": "cs", "env": "k3", "network_cidr": "192.168.160.0/24", "vars": {"ssh_username": "u"},
                    "ssh_private_key_path": str(Path(self.td.name) / "key")}
        self.fake = _script(Path(self.td.name) / "ansible-playbook", 'echo "argv: $*"\nexit 0\n')
        self.outputs = {"kubernetes_control_plane_ips": ["192.168.160.20"], "kubernetes_worker_ips": ["192.168.160.40"]}

    def tearDown(self):
        self.td.cleanup()

    def _install(self, distro="rke2", limit=None, version_file=None):
        self.cfg["vars"]["kubernetes_distro"] = distro
        warns, panels = [], []
        fake = self.fake
        if version_file is not None:
            fake = _script(Path(self.td.name) / "ansible-playbook-v",
                           f'printf "%s\\n" "{version_file}" > "{self.env.dir / "k8s" / "version"}"\nexit 0\n')
        with mock.patch.object(provision.Host, "wait") as wait, mock.patch.object(provision.Host, "wait_cloud_init"), \
                mock.patch.object(deps, "ensure_local_ansible", return_value=fake), \
                mock.patch.object(provision, "forget_host_key"), \
                mock.patch.object(provision, "local_source_address", return_value="192.168.160.1"), \
                mock.patch.object(ui, "header"), mock.patch.object(ui, "err"), \
                mock.patch.object(ui, "panel", lambda title, rows, **k: panels.append(title)), \
                mock.patch.object(ui, "warn", lambda m: warns.append(m)), mock.patch("builtins.print"), \
                mock.patch.object(provision.audit, "note"):
            provision.provision_local_kubernetes(clouds.get("vmware"), self.env, self.cfg,
                                                 dict(self.outputs, kubernetes_distro=distro), limit=limit)
        v = json.loads((self.env.dir / "k8s" / "vars.json").read_text())
        return v, warns, panels, wait

    def test_ranges_match_the_roles(self):
        kubeadm = _read("ansible/roles/kubeadm/defaults/main.yml")
        ranges = dict(provision.LOCAL_K8S_RANGES["kubeadm"])
        self.assertIn(f"kubeadm_pod_cidr: {ranges['pod']}", kubeadm)
        self.assertIn(f"kubeadm_service_cidr: {ranges['Service']}", kubeadm)
        init = _task(_read("ansible/roles/kubeadm/tasks/main.yml"), "kubeadm init")
        self.assertIn("--pod-network-cidr {{ kubeadm_pod_cidr }}", init)
        self.assertIn("--service-cidr {{ kubeadm_service_cidr }}", init)
        # RKE2's defaults, left as they are by the role
        self.assertEqual(dict(provision.LOCAL_K8S_RANGES["rke2"]), {"pod": "10.42.0.0/16", "Service": "10.43.0.0/16"})
        self.assertNotIn("cluster-cidr", _code(_read("ansible/roles/rke2/tasks/main.yml")))

    def test_range_problems(self):
        self.assertEqual(provision.local_k8s_range_problems("10.100.0.0/24", "kubeadm"), [])   # the local fallback
        self.assertEqual(provision.local_k8s_range_problems("192.168.160.0/24", "rke2"), [])
        self.assertEqual(provision.local_k8s_range_problems(None, "rke2"), [])
        self.assertEqual(len(provision.local_k8s_range_problems("10.42.0.0/24", "rke2")), 1)
        self.assertIn("Service range", provision.local_k8s_range_problems("10.43.7.0/24", "rke2")[0])
        self.assertIn("pod range", provision.local_k8s_range_problems("10.244.1.0/24", "kubeadm")[0])
        self.assertTrue(provision.local_k8s_range_problems("10.96.0.0/24", "kubeadm"))

    def test_a_new_cluster_on_an_overlapping_network_is_refused_before_ansible(self):
        self.cfg["network_cidr"] = "10.42.0.0/24"
        with self.assertRaises(ui.Abort) as cm:
            self._install("rke2")
        self.assertIn("overlaps 10.42.0.0/16, the pod range of the rke2 cluster", cm.exception.msg)
        self.assertIn("--cidr", cm.exception.msg)
        self.assertFalse((self.env.dir / "k8s" / "vars.json").exists())

    def test_an_existing_cluster_is_only_warned_about(self):
        self.cfg["network_cidr"] = "10.42.0.0/24"
        self.cfg["provisioned"] = {"kubernetes": {"distro": "rke2"}}
        _, warns, _, _ = self._install("rke2", version_file="v1.36.4+rke2r1")
        self.assertTrue(any("overlaps 10.42.0.0/16" in w for w in warns), warns)

    def test_nodes_ignore_this_machines_address_and_the_cni_is_fixed(self):
        v, _, _, _ = self._install("rke2", version_file="v1.36.4+rke2r1")
        self.assertEqual(v["fail2ban_ignore_cidrs"], ["192.168.160.1/32"])
        self.assertNotIn("kubernetes_cni", v)
        rke2 = _code(_read("ansible/roles/rke2/tasks/main.yml"))
        self.assertIn("cni: canal", rke2)
        self.assertNotIn("kubernetes_cni", rke2)

    def test_ready_only_when_the_api_answered(self):
        _, warns, panels, _ = self._install("rke2", version_file="v1.36.4+rke2r1")
        self.assertEqual(panels, ["Kubernetes ready"])
        self.assertFalse(warns)
        _, warns, panels, _ = self._install("rke2")                 # the version step got no answer
        self.assertEqual(panels, ["Kubernetes installed"])
        self.assertTrue(any("did not answer" in w and "get nodes" in w for w in warns), warns)


# ---------------------------------------------------------------- RKE2 restart, Flannel (a2-ansible#12, #9)

class ClusterRoleTests(unittest.TestCase):
    RKE2 = _read("ansible/roles/rke2/tasks/main.yml")
    KUBEADM = _read("ansible/roles/kubeadm/tasks/main.yml")

    def test_rke2_restart_is_checked_and_not_doubled(self):
        self.assertFalse((ROLES / "rke2" / "handlers").exists())
        self.assertNotIn("notify", _code(self.RKE2))
        self.assertIn("register: rke2_config", _task(self.RKE2, "RKE2 config"))
        self.assertIn("register: rke2_started", _task(self.RKE2, "Enable and start rke2-{{ node_role }}"))
        restart = _task(self.RKE2, "Restart rke2-{{ node_role }} with the changed config")
        self.assertIn("timeout 900 systemctl restart rke2-{{ node_role }}", restart)
        self.assertIn("when: rke2_config is changed and rke2_started is not changed", restart)
        self.assertNotIn("failed_when", restart)
        # before the API wait, so a server that does not come back fails the (serial) play
        self.assertLess(self.RKE2.index("- name: Restart rke2-"), self.RKE2.index("- name: Wait for the API server"))

    def test_flannel_is_pinned_and_applied_only_when_missing(self):
        self.assertNotIn("releases/latest", self.KUBEADM)
        self.assertRegex(_read("ansible/roles/kubeadm/defaults/main.yml"), r"(?m)^flannel_version: v\d+\.\d+\.\d+$")
        check = _task(self.KUBEADM, "Flannel running in the cluster?")
        self.assertIn("get daemonset kube-flannel-ds", check)
        self.assertIn("'not found' not in flannel_ds.stderr", check)
        apply = _task(self.KUBEADM, "Flannel CNI {{ flannel_version }}")
        self.assertIn("releases/download/{{ flannel_version }}/kube-flannel.yml", apply)
        self.assertIn("and flannel_ds.rc != 0", apply)
        self.assertNotIn("changed_when: true", apply)


# ---------------------------------------------------------------- OpenVPN certificates and server config (a2-ansible#7, #8)

class OpenVpnTests(unittest.TestCase):
    TASKS = _read("ansible/roles/openvpn/tasks/main.yml")

    def test_server_certificate_is_renewed_before_it_expires(self):
        check = _task(self.TASKS, "Server certificate valid for 30 more days?")
        self.assertIn("openssl x509 -checkend 2592000", check)
        self.assertIn("failed_when: server_cert_check.rc not in [0, 1]", check)
        block = _task(self.TASKS, "Renew the server certificate")
        self.assertIn("when: server_cert_check.rc == 1", block)
        for step in ("./easyrsa --batch revoke server", "./easyrsa --batch build-server-full server nopass",
                     "./easyrsa --batch gen-crl"):
            self.assertIn(step, block)
        self.assertIn('environment: "{{ easyrsa_env }}"', block)
        self.assertLess(self.TASKS.index("- name: Renew the server certificate"),
                        self.TASKS.index("- name: Copy PKI material into place"))

    def test_server_log_goes_to_journald_and_groups_are_set(self):
        conf = _code(_read("ansible/roles/openvpn/templates/server.conf.j2"))
        self.assertNotIn("log-append", conf)
        self.assertNotIn("ecdh-curve", conf)
        self.assertIn("status /var/log/openvpn/status.log 30", conf)
        fips = conf[conf.index("{% if fips_mode"):conf.index("{% else %}")]
        self.assertIn("tls-groups secp384r1:secp256r1", fips)
        self.assertEqual(conf.count("tls-groups"), 1)              # never X25519 in FIPS mode

    @unittest.skipUnless(_jinja_python(), "jinja2 not available")
    def test_server_conf_renders(self):
        out = _render(ROLES / "openvpn" / "templates", "server.conf.j2", vpn_port=1194, vpn_client_net="10.255.255.0",
                      vpn_client_mask="255.255.255.0", vpn_push_routes=[["10.8.0.0", "255.255.0.0"]], fips_mode=True)
        self.assertIn("server 10.255.255.0 255.255.255.0", out)
        self.assertIn("tls-groups secp384r1:secp256r1", out)
        self.assertNotIn("log-append", out)


class VpnClientScriptTests(unittest.TestCase):
    """The rendered cloudseed-vpn-client, run with bash against a scratch Easy-RSA directory and logging fakes."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        self.log = root / "calls.log"
        self.rsa = root / "easy-rsa"
        (self.rsa / "pki" / "issued").mkdir(parents=True)
        (self.rsa / "pki" / "private").mkdir(parents=True)
        for name in ("server", "alice", "bob"):
            (self.rsa / "pki" / "issued" / f"{name}.crt").write_text(f"{name}\n")
            (self.rsa / "pki" / "private" / f"{name}.key").write_text("key\n")
        (self.rsa / "pki" / "ca.crt").write_text("ca\n")
        (self.rsa / "pki" / "crl.pem").write_text("crl\n")
        # revoke moves the certificate aside (as easy-rsa does), build-client-full issues a new one
        _script(self.rsa / "easyrsa", f'echo "easyrsa $*" >> "{self.log}"\n'
                                      'case "$2" in revoke) mv "pki/issued/$3.crt" "pki/issued/$3.revoked" ;;\n'
                                      '  build-client-full) echo new > "pki/issued/$3.crt" ;; esac\n')
        fake = root / "bin"
        fake.mkdir()
        _script(fake / "curl", f'echo "curl $*" >> "{self.log}"\necho 203.0.113.50\n')
        for tool in ("systemctl", "install"):
            _script(fake / tool, f'echo "{tool} $*" >> "{self.log}"\n')
        # alice's certificate is expired: -checkend fails for it; -enddate prints a date
        _script(fake / "openssl", f'echo "openssl $*" >> "{self.log}"\n'
                                  'case "$*" in *-checkend*alice.crt*) exit 1 ;; esac\n'
                                  'case "$*" in *-enddate*) echo "notAfter=2028-12-27 12:00:00Z" ;; *) cat "${@: -1}" 2>/dev/null ;; esac\n'
                                  'exit 0\n')
        text = _read("ansible/roles/openvpn/templates/cloudseed-vpn-client.j2")
        text = re.sub(r"^\{%.*%\}\n", "", text, flags=re.M)
        text = text.replace("export {{ k }}={{ v | quote }}", "export EASYRSA_BATCH=1")
        text = re.sub(r"\{\{.*?\}\}", "1194", text)
        text = text.replace("cd /etc/openvpn/easy-rsa", f'cd "{self.rsa}"')
        self.script = root / "cloudseed-vpn-client"
        self.script.write_text(text)
        (fake / "openssl").write_text((fake / "openssl").read_text().replace("#!/bin/sh", "#!/usr/bin/env bash"))
        self.env = dict(os.environ, PATH=f"{fake}{os.pathsep}{os.environ.get('PATH', '')}")

    def tearDown(self):
        self.td.cleanup()

    def _run(self, *argv):
        self.log.write_text("")
        p = subprocess.run(["bash", str(self.script), *argv], capture_output=True, text=True, env=self.env, timeout=30)
        return p.returncode, p.stdout, p.stderr, self.log.read_text()

    def test_an_expired_client_certificate_is_replaced(self):
        rc, out, err, calls = self._run("add", "alice")
        self.assertEqual(rc, 0, err)
        self.assertIn("easyrsa --batch revoke alice", calls)
        self.assertIn("easyrsa --batch gen-crl", calls)
        self.assertIn("install -m 0644 pki/crl.pem /etc/openvpn/server/crl.pem", calls)
        self.assertIn("easyrsa --batch build-client-full alice nopass", calls)
        self.assertNotIn("systemctl", calls)                      # connected clients are not dropped
        self.assertLess(calls.index("revoke alice"), calls.index("build-client-full alice"))

    def test_a_valid_certificate_is_reused(self):
        rc, out, err, calls = self._run("add", "bob")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("easyrsa", calls)
        self.assertIn("-checkend 2592000", calls)

    def test_certs_lists_expiry_dates_with_the_server(self):
        rc, out, err, _ = self._run("certs")
        self.assertEqual(rc, 0, err)
        rows = dict(line.split("\t") for line in out.splitlines())
        self.assertEqual(set(rows), {"server", "alice", "bob"})
        self.assertEqual(rows["server"], "2028-12-27 12:00:00Z")
        rc, out, _, _ = self._run("list")                          # unchanged format: names only
        self.assertEqual(sorted(out.split()), ["alice", "bob"])


# ---------------------------------------------------------------- repository copy (a2-ansible#14)

class RepoSyncTests(unittest.TestCase):
    def test_key_and_credential_names_never_ship(self):
        for rel in ("terraform/gcp/key.pem", "skills/x/server.key", "terraform/aws/id_ed25519", "terraform/aws/id_rsa.pub",
                    "skills/x/kubeconfig", "terraform/x/client.p12", "terraform/x/vpn.ovpn", "skills/x/cluster.kubeconfig",
                    "terraform/gcp/credentials.json", "skills/.ssh/config", "terraform/.kube/config", "bin/.netrc",
                    "terraform/x/store.jks", "terraform/x/putty.ppk", "terraform/x/id_ecdsa_sk"):
            self.assertFalse(provision._include(Path(rel)), rel)
        for rel in ("cloudseed/kubeconfig.py", "ansible/roles/x/tasks/kubeconfig.yml", "cloudseed/credentials_help.py",
                    "terraform/aws/main.tf", "skills/cloudseed/SKILL.md", "cloudseed/provision.py"):
            self.assertTrue(provision._include(Path(rel)), rel)

    def test_key_material_under_any_name_is_found(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            files = {
                "terraform/gcp/mykey.json": json.dumps({"type": "service_account", "private_key": "-----BEGIN " + "PRIVATE KEY-----\nMIIE\n"}),
                "skills/notes.txt": "hello\n-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE\n-----END OPENSSH PRIVATE KEY-----\n",
                "terraform/x/static.txt": "-----BEGIN OpenVPN Static key V1-----\nabc\n",
                "skills/backup.asc": "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\n",
                "skills/signing.asc": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBF\n",
                # code that only names the markers is not key material
                "cloudseed/redact.py": 'PEM = re.compile(r"-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----")\n',
                "terraform/gcp/sa-example.json": json.dumps({"type": "service_account", "client_email": "x"}),
                "skills/pub.txt": "-----BEGIN PUBLIC KEY-----\nMIIB\n",
            }
            for rel, body in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(body)
            (root / "skills" / "link.txt").symlink_to("/etc/hosts")
            found = provision.key_material_files(root, [Path(r) for r in files] + [Path("skills/link.txt"), Path("gone")])
        self.assertEqual(sorted(map(str, found)), ["skills/backup.asc", "skills/notes.txt", "terraform/gcp/mykey.json",
                                                   "terraform/x/static.txt"])

    def test_sync_refuses_instead_of_copying_a_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "ansible").mkdir()
            (root / "ansible" / "bastion.yml").write_text("---\n")
            (root / "ansible" / "leftover.txt").write_text("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow\n")
            host = provision.Host("198.51.100.9", "u", Path("/nonexistent"), "bastion")
            with mock.patch.object(paths, "REPO_ROOT", root), mock.patch.object(provision.subprocess, "Popen") as popen, \
                    mock.patch.object(ui, "err"), self.assertRaises(ui.Abort) as cm:
                host.sync_repo()
            popen.assert_not_called()
        self.assertIn("ansible/leftover.txt", cm.exception.msg)
        self.assertIn("Move it out of", cm.exception.msg)

    def test_the_shipped_tree_has_no_key_material(self):
        root = Path(paths.REPO_ROOT).resolve()
        self.assertEqual(provision.key_material_files(root, provision.repo_files(root)), [])


# ---------------------------------------------------------------- auditd, output, messages (a2-ansible#15, #18, #11; e2e2#7)

class HostOutputTests(unittest.TestCase, _ProvisionHarness):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.env = paths.Env("aws", "msg", Path(self.td.name) / "w")
        self.env.create_dirs()
        self.cfg = {"name": "cs", "env": "msg", "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.4/32"],
                    "vars": {}, "ssh_private_key_path": str(Path(self.td.name) / "key")}

    def tearDown(self):
        self.td.cleanup()

    def test_root_commands_are_audited_for_logins_only(self):
        rules = _task(_read("ansible/roles/hardening/tasks/main.yml"), "audit rules")
        self.assertIn("-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k rootcmd", rules)
        for watch in ("-w /etc/passwd -p wa -k identity", "-w /etc/sudoers -p wa -k sudoers"):
            self.assertIn(watch, rules)

    def test_sanity_asserts_are_quiet(self):
        for rel, name in (("ansible/bastion.yml", "Sanity check distro family"), ("ansible/vpn.yml", "Sanity check distro family"),
                          ("ansible/kubernetes.yml", "Debian family only (Ubuntu / Debian cloud images)")):
            task = _task(_read(rel), name)
            self.assertIn("quiet: true", task, rel)
            self.assertIn("fail_msg:", task, rel)

    def test_task_names_never_use_a_branch_only_variable(self):
        text = _read("ansible/roles/openscap/tasks/main.yml")
        self.assertIn("- name: usg audit {{ usg_profile | default('') }}", text)
        self.assertIn("- name: Evaluate {{ chosen_profile | default('') }}", text)

    def test_the_vpn_hint_is_a_real_ssh_command_for_the_vpn_host(self):
        _, oks, _ = self._provision(playbook="vpn.yml", host_key="vpn_public_ip", label="vpn", tools=False,
                                    extra_vars={"vpn_type": "tailscale"})
        self.assertNotIn("cloudseed ssh", oks[-1])                 # that goes to the bastion
        self.assertIn("SSH in with: ssh -i ", oks[-1])
        self.assertIn("ec2-user@198.51.100.10", oks[-1])
        self.assertIn("UserKnownHostsFile=", oks[-1])
        _, oks, _ = self._provision()
        self.assertTrue(oks[-1].endswith("SSH in with: cloudseed ssh aws --env msg"), oks[-1])


if __name__ == "__main__":
    unittest.main()
