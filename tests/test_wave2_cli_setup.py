"""Wave-2 regression tests for the setup / provision / lifecycle commands (cross-group handoffs):
setup flag checks before anything is written, environment identity (uid), saved tags, the working-directory marker that
lets --purge tell the user's files from cloudseed's, VMware address plan delegation and placeholders, summaries and
output panels, missing bastion addresses, VPN undo bookkeeping, account-wide objects on targeted destroys, VMware
teardown (vm_dir, vmnet ownership), Kubernetes access clean-up, GCP OS Login registration and read-only fallbacks.
Stdlib only; Terraform, kubectl, vmrun, gcloud and ssh are faked - nothing touches a cloud, a hypervisor or the network."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, localvm, paths, provision as prov, services, ui, undo  # noqa: E402
from cloudseed.clouds.gcp import GCP  # noqa: E402

import test_fix_cli_life as life  # noqa: E402  (tests/ is on sys.path under unittest discovery)
import test_fix_cli_setup as setup_base  # noqa: E402


def _cp(rc: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], rc, out, err)


def _capture(fn, *a, **k):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            result = fn(*a, **k)
        except SystemExit as e:
            if isinstance(e, ui.Abort):
                ui.show_abort(e)
            result = e.code
    return result, out.getvalue()


# ---------------------------------------------------------------- setup: flags, identity, tags, workdir marker

class SetupFlagTests(setup_base.SetupHarness):
    def test_bad_flags_are_refused_before_any_directory_exists(self):
        cases = [("--name", "my stack"), ("--cidr", "10.0.0.1/33"), ("--allow-ip", "0.0.0.0/0"),
                 ("--tag", "k${x}=v"), ("--region", "Not A Region")]
        for i, (flag, value) in enumerate(cases):
            env = self.env("aws", f"w2flag{i}")
            rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5",
                                 flag, value, "--dry-run")
            self.assertNotEqual(rc, 0, (flag, out))
            self.assertIn(flag, out, flag)
            self.assertFalse(env.dir.exists(), f"{flag}: the working directory was created before the check")

    def test_new_env_gets_a_uid_that_is_kept(self):
        env = self.env("aws", "w2uid")
        rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5", "--dry-run")
        self.assertEqual(rc, 0, out)
        uid = env.load().get("uid")
        self.assertRegex(uid or "", r"^[0-9a-f]{16}$")
        rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--var", "az_count=3", "--plan-only")
        self.assertEqual(rc, 0, out)
        self.assertEqual(env.load().get("uid"), uid)
        # reconcile's ownership check honours it
        from cloudseed import reconcile
        self.assertEqual(reconcile.expected_tags("aws", env.load()).get("cloudseedenvid"), uid)

    def test_a_deployed_env_without_uid_does_not_get_one(self):
        env = self.env("aws", "w2olduid")
        rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5", "--dry-run")
        self.assertEqual(rc, 0, out)
        cfg = env.load()
        cfg.pop("uid")
        env.save(cfg)
        with mock.patch.object(cli, "_env_has_resources", return_value=True):
            rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("uid", env.load())   # (its resources are not tagged with one: no mass re-tag)

    def test_invalid_saved_tag_is_dropped_with_a_warning(self):
        env = self.env("aws", "w2tags")
        rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5", "--dry-run",
                             "--tag", "team=a")
        self.assertEqual(rc, 0, out)
        cfg = env.load()
        cfg["tags"]["bad${x}"] = "v"          # saved by an older version
        env.save(cfg)
        rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--plan-only", "--tag", "owner2=b")
        self.assertEqual(rc, 0, out)
        self.assertIn("Dropping the saved tag bad${x}=v", out)
        self.assertEqual(env.load()["tags"], {"team": "a", "owner2": "b"})

    def test_custom_workdir_records_what_was_there_before(self):
        # A --workdir is "created by cloudseed" (help, README): a new or empty directory (paths.workdir_problem, w2/core).
        # What it may still hold - entries with cloudseed's own names, such as a project's k8s/ - is recorded, so
        # `destroy --purge` leaves it alone. A directory with someone else's files is refused before anything is written.
        base = Path(tempfile.mkdtemp(prefix="cs-w2-wd-"))
        self.addCleanup(shutil.rmtree, base, True)
        fresh, kube, used = base / "new-dir", base / "kube", base / "project"
        for d in (kube, used):
            (d / "k8s").mkdir(parents=True)
            (d / "k8s" / "app.yaml").write_text("kind: Deployment")
        (used / "notes.txt").write_text("mine")
        for name, target in (("w2wdnew", fresh), ("w2wdkube", kube)):
            self.env("aws", name)
            rc, out = self.setup("aws", "-y", "--env", name, "--state", "local", "--allow-ip", "203.0.113.5", "--dry-run",
                                 "--workdir", str(target))
            self.assertEqual(rc, 0, out)
            self.envs.append(paths.Env("aws", name))   # (now at the custom directory: cleaned up there too)
        self.assertEqual(paths.Env("aws", "w2wdnew").load()["workdir_preexisting"], [])
        self.assertEqual(paths.Env("aws", "w2wdkube").load()["workdir_preexisting"], ["k8s"])
        env = self.env("aws", "w2wdused")
        rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5", "--dry-run",
                             "--workdir", str(used))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("not empty (notes.txt)", out)
        self.assertNotIn("Location and network", out)                  # refused at step 1, before any other question
        self.assertEqual(sorted(p.name for p in used.iterdir()), ["k8s", "notes.txt"])     # nothing added or removed
        self.assertEqual([p.name for p in (used / "k8s").iterdir()], ["app.yaml"])
        self.assertNotIn(env.id, paths._load_index())


class LocalNetworkTests(unittest.TestCase):
    def cfg(self, cidr, **vars_):
        return {"name": "n", "env": "e", "network_cidr": cidr, "vars": vars_, "extra_vars": {}}

    def test_the_vmware_address_plan_is_the_adapters(self):
        vmware = clouds.get("vmware")
        self.assertFalse(hasattr(cli, "VMWARE_HOSTS"), "one copy of the address plan: VMware.address_problems")
        # workers past .127 would land in VMware's DHCP pool: only the adapter's rule knew that
        c = self.cfg("10.1.0.0/24", enable_kubernetes=True, kubernetes_workers=90)
        self.assertEqual(cli._network_problems(vmware, c), vmware.network_problems(c))
        self.assertTrue(cli._network_problems(vmware, c))
        problems = cli._config_problems(vmware, dict(c, tags={}, vars=dict(c["vars"], ssh_username="alice")))
        self.assertEqual(len([p for p in problems if "kubernetes_workers" in p]), 1, problems)

    def test_placeholder_cidr_avoids_other_environments(self):
        self.assertEqual(cli._local_default_cidr([]), "10.100.0.0/24")
        self.assertEqual(cli._local_default_cidr(["10.100.0.0/24", "10.101.0.0/16", "garbage"]), "10.102.0.0/24")
        env = paths.Env("vmware", "w2net")
        args = cli.build_parser().parse_args(["setup", "vmware", "--env", "w2net"])
        given = {"answers": {}, "extra": {}, "unset": []}
        with mock.patch.object(cli, "_other_env_cidrs", return_value=["10.100.0.0/24"]):
            cidr, explicit = cli._setup_network(args, clouds.get("vmware"), env, {}, given, {}, False)
        self.assertEqual((cidr, explicit), ("10.101.0.0/24", False))


# ---------------------------------------------------------------- summaries and outputs

class SummaryTests(unittest.TestCase):
    def _summary(self, cloud_key, cfg, **kw):
        env = paths.Env(cloud_key, cfg["env"])
        _, out = _capture(cli._print_summary, clouds.get(cloud_key), env, cfg, **kw)
        return out

    def test_vmware_rows_describe_what_really_applies(self):
        cfg = {"name": "n", "env": "w2sum", "region": "local", "network_cidr": "10.100.0.0/24", "cidr_explicit": False,
               "allowed_ssh_cidrs": ["127.0.0.1/32"], "state": {"type": "local"}, "vars": {"workload_count": 0},
               "tags": {"team": "x"}}
        out = self._summary("vmware", cfg, network_resolved=False)
        self.assertIn("VMware host-only vmnet (resolved at apply)", out)
        self.assertNotIn("10.100.0.0/24", out)
        self.assertIn("this machine only (host-only/NAT)", out)
        self.assertNotIn("127.0.0.1/32", out)
        self.assertIn("not applied", out)
        self.assertNotIn("team=x", out)
        # resolved by a real prepare (base image known) or chosen with --cidr: the CIDR itself
        self.assertTrue(cli._vmnet_resolved(dict(cfg, vars={"base_disk": "/img/base.vmdk"})))
        self.assertFalse(cli._vmnet_resolved(dict(cfg, vars={"base_disk": "/dev/null"})))
        self.assertTrue(cli._vmnet_resolved(dict(cfg, cidr_explicit=True)))
        self.assertIn("10.100.0.0/24", self._summary("vmware", cfg, network_resolved=True))

    def test_disabled_features_hide_their_settings_and_bools_read_true_false(self):
        cfg = {"name": "n", "env": "w2gcp", "region": "us-central1", "network_cidr": "10.0.0.0/16",
               "allowed_ssh_cidrs": ["203.0.113.5/32"], "state": {"type": "local"}, "tags": {},
               "vars": {"project_id": "p-123456", "zone": "us-central1-a", "enable_vpn": False, "vpn_type": "openvpn",
                        "enable_kubernetes": False, "kubernetes_public_endpoint": False, "fips_mode": False}}
        out = self._summary("gcp", cfg)
        self.assertNotIn("vpn_type", out)
        self.assertNotIn("kubernetes_public_endpoint", out)
        self.assertIn("enable_vpn", out)
        self.assertNotIn("False", out)
        self.assertIn("false", out)
        cfg["vars"]["enable_vpn"] = True
        self.assertIn("vpn_type", self._summary("gcp", cfg))

    def test_outputs_of_a_disabled_feature_are_left_out(self):
        outputs = {"bastion_public_ip": "192.0.2.1", "vpn_type": None, "vpn_public_ip": None,
                   "kubernetes_cluster_name": None, "fips_mode": False}
        _, out = _capture(cli._print_outputs, outputs, {"vars": {"enable_vpn": False, "enable_kubernetes": False}})
        self.assertNotIn("vpn_type", out)
        self.assertNotIn("kubernetes_cluster_name", out)
        self.assertIn("fips_mode", out)
        self.assertIn("false", out)
        _, out = _capture(cli._print_outputs, outputs)   # without the configuration (cmd_output --json path): all rows
        self.assertIn("vpn_type", out)


# ---------------------------------------------------------------- missing bastion address (VMware)

class MissingBastionIpTests(life.LifeBase):
    cloud = "vmware"

    def test_finish_shows_no_ready_panel_without_an_address(self):
        life.FakeTF.reset(outputs_value={"bastion_public_ip": "", "private_vmnet": "vmnet1"})
        with mock.patch.object(cli.audit, "refresh"):
            _, out = _capture(cli._finish, clouds.get("vmware"), self.env, self.cfg, life.FakeTF(self.env.stack_dir))
        self.assertNotIn("is ready", out)
        self.assertIn("No bastion IP", out)
        self.assertIn(f"cloudseed provision vmware --env {self.env_name}", out)

    def test_provision_all_refuses_at_once_instead_of_waiting(self):
        (self.env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": ""}))
        cfg = dict(self.cfg, vars={"fips_mode": True})
        with mock.patch.object(prov.Host, "wait", side_effect=AssertionError("waited on an empty address")), \
                mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": "t"}):
            rc, out = _capture(cli._provision_all, clouds.get("vmware"), self.env, cfg)
        self.assertEqual(rc, 1)
        self.assertIn("reported no address", out)

    def test_provision_re_reads_the_address_with_a_refresh_only_apply(self):
        class RefreshTF(life.FakeTF):
            def run(self, *args, capture=False, check=True):
                life.FakeTF.calls.append(("run",) + args)
                if args[:2] == ("apply", "-refresh-only"):
                    life.FakeTF.outputs_value = {"bastion_public_ip": "10.100.0.2"}
                return super().run(*args, capture=capture, check=check)
        life.FakeTF.reset(state=["module.stack.module.bastion.vmdesktop_vm.bastion"], outputs_value={"bastion_public_ip": ""})
        seen = {}
        with mock.patch.object(cli, "Terraform", RefreshTF), \
                mock.patch.object(cli, "_provision_all", side_effect=lambda cloud, env, cfg, **k: seen.update(
                    ip=cli._cached_outputs(env).get("bastion_public_ip")) or ["bastion"]), \
                mock.patch.object(undo, "record"):
            rc = self.run_cmd(cli.cmd_provision, ["provision", "vmware", "--env", self.env_name, "-y"])
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertTrue([c for c in life.FakeTF.calls if c[:3] == ("run", "apply", "-refresh-only")])
        self.assertEqual(seen["ip"], "10.100.0.2")

    def test_ssh_explains_a_missing_vmware_address(self):
        with mock.patch.object(cli, "_env_has_resources", return_value=True):
            rc = self.run_cmd(cli.cmd_ssh, ["ssh", "vmware", "--env", self.env_name])
        self.assertEqual(rc, 1)
        self.assertIn("open-vm-tools", self.out.getvalue())


# ---------------------------------------------------------------- VPN / provision undo bookkeeping

class VpnUndoTests(life.LifeBase):
    def setUp(self):
        super().setUp()
        (self.env.dir / "outputs.json").write_text(json.dumps({"vpn_public_ip": "192.0.2.9", "vpn_type": "openvpn",
                                                               "bastion_public_ip": "192.0.2.10"}))
        self.recorded = []
        p = mock.patch.object(undo, "record", side_effect=lambda *a, **k: self.recorded.append(a))
        p.start()
        self.addCleanup(p.stop)

    def vpn(self, *argv):
        return self.run_cmd(cli.cmd_vpn, ["vpn", *argv, "aws", "--env", self.env_name])

    def test_connect_records_only_a_real_change(self):
        running = {"pid": 4242}
        with mock.patch.object(services, "_running", side_effect=lambda env: running["pid"]), \
                mock.patch.object(services, "connect", return_value=0):
            self.assertEqual(self.vpn("connect"), 0)                       # already connected: nothing to undo
        self.assertEqual(self.recorded, [])
        state = {"pid": None}

        def connect(*a, **k):
            state["pid"] = 99
            return 0
        with mock.patch.object(services, "_running", side_effect=lambda env: state["pid"]), \
                mock.patch.object(services, "connect", side_effect=connect):
            self.assertEqual(self.vpn("connect"), 0)
        self.assertEqual(len(self.recorded), 1)
        self.assertIn("disconnect", self.recorded[0][3]["argv"])

    def test_disconnect_when_not_connected_records_nothing(self):
        with mock.patch.object(services, "_running", return_value=None), \
                mock.patch.object(services, "disconnect", return_value=0):
            self.assertEqual(self.vpn("disconnect"), 0)
        self.assertEqual(self.recorded, [])

    def test_vpn_provision_records_the_host_map_only_when_it_ran(self):
        with mock.patch.object(cli, "_provision_all", return_value=["vpn"]):
            self.assertEqual(self.vpn("provision"), 0)
        self.assertEqual(self.recorded[-1][2], "provision-prev")
        self.assertEqual(self.recorded[-1][3], {"hosts": {"vpn": None}})
        self.recorded.clear()
        with mock.patch.object(cli, "_provision_all", return_value=[]):
            self.assertEqual(self.vpn("provision"), 0)
        self.assertEqual(self.recorded, [])


# ---------------------------------------------------------------- destroy: account-wide objects, clusters

class RecordingTF(life.FakeTF):
    def run(self, *args, capture=False, check=True):
        life.FakeTF.calls.append(("run",) + tuple(args))
        return super().run(*args, capture=capture, check=check)


class TargetedKeepTests(life.LifeBase):
    cloud = "azure"
    DEFENDER = "module.stack.module.security_baseline[0].azurerm_security_center_subscription_pricing.this[\"VirtualMachines\"]"
    VNET = "module.stack.module.network.azurerm_virtual_network.this"

    def setUp(self):
        super().setUp()
        p = mock.patch.object(cli, "Terraform", RecordingTF)
        p.start()
        self.addCleanup(p.stop)
        self.keep = mock.patch.object(clouds.get("azure").__class__, "keep_on_destroy",
                                      lambda self_, cfg, resources: [(a, "Defender stays on") for a in resources
                                                                     if "security_center" in a])
        self.keep.start()
        self.addCleanup(self.keep.stop)

    def test_a_target_covering_a_subscription_setting_forgets_it(self):
        life.FakeTF.reset(state=[self.DEFENDER, self.VNET],
                          changes=[{"address": self.DEFENDER, "type": "azurerm_security_center_subscription_pricing",
                                    "mode": "managed", "change": {"actions": ["delete"]}}])
        rc = self.destroy("-y", "--auto-approve", "--target", "module.stack.module.security_baseline")
        self.assertEqual(rc, 0, self.out.getvalue())
        removed = [c for c in life.FakeTF.calls if c[:3] == ("run", "state", "rm")]
        self.assertEqual([c[3] for c in removed], [self.DEFENDER])
        replans = [c for c in life.FakeTF.calls if c[:2] == ("run", "plan")]
        self.assertTrue(replans and "-target=module.stack.module.security_baseline" in replans[0])
        order = [c[1] if c[0] == "run" else c[0] for c in life.FakeTF.calls]
        self.assertLess(order.index("state"), order.index("apply"))
        self.assertIn("Defender stays on", self.out.getvalue())
        self.assertIn("Nothing was deleted", self.out.getvalue())

    def test_a_target_elsewhere_leaves_the_setting_managed(self):
        life.FakeTF.reset(state=[self.DEFENDER, self.VNET],
                          changes=[{"address": self.VNET, "type": "azurerm_virtual_network", "mode": "managed",
                                    "change": {"actions": ["delete"]}}])
        rc = self.destroy("-y", "--auto-approve", "--target", "module.stack.module.network")
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertFalse([c for c in life.FakeTF.calls if c[:3] == ("run", "state", "rm")])


class AccountWideWarningTests(life.LifeBase):
    def test_full_destroy_preview_names_account_services_it_turns_off(self):
        life.FakeTF.reset(state=["module.stack.module.security_baseline[0].aws_guardduty_detector.this[0]",
                                 "module.stack.module.security_baseline[0].aws_securityhub_account.this[0]",
                                 "module.stack.module.network.aws_vpc.this"])
        rc = self.destroy("-y")
        self.assertEqual(rc, 3)
        out = self.out.getvalue()
        self.assertIn("GuardDuty, Security Hub", out)
        self.assertIn("us-east-1", out)
        self.assertEqual(cli._account_wide_deletes(["data.aws_guardduty_detector.x", "aws_vpc.v"], []), [])


class ClusterAccessTests(life.LifeBase):
    cloud = "vmware"

    def _k8s_files(self):
        k8s = self.env.dir / "k8s"
        k8s.mkdir(exist_ok=True)
        for name in ("kubeconfig", "kubeconfig.src", "token", "vars.json", "inventory.ini", "version"):
            (k8s / name).write_text("x")
        (k8s / "app.yaml").write_text("the user's own")
        return k8s

    def test_forget_removes_cloudseeds_files_and_only_vmware_named_entries(self):
        k8s = self._k8s_files()
        dropped = []
        home_kube = Path(tempfile.mkdtemp(prefix="cs-w2-kube-")) / "config"
        home_kube.write_text("apiVersion: v1\n")
        with mock.patch.object(cli.deps, "find", return_value="/fake/kubectl"), \
                mock.patch.object(cli, "_kubeconfig_view", return_value={"contexts": [{"name": "default"}],
                                                                        "clusters": [{"name": "default"}],
                                                                        "users": [{"name": "default"}]}), \
                mock.patch.object(cli, "_drop_kubeconfig_entries",
                                  side_effect=lambda kubectl, target, names, env_id: dropped.append((target, names))), \
                mock.patch.dict(os.environ, {"KUBECONFIG": str(home_kube)}):
            cli._forget_cluster_access(self.env)
        self.assertTrue(dropped)
        for _, names in dropped:
            self.assertEqual(names["contexts"], {f"vmware-{self.env_name}"})
            self.assertNotIn("default", names["clusters"] | names["users"], "never the cluster's own generic names")
        self.assertEqual(sorted(p.name for p in k8s.iterdir()), ["app.yaml"])

    def test_recorded_merge_is_used_and_the_k8s_dir_goes_when_empty(self):
        k8s = self.env.dir / "k8s"
        k8s.mkdir()
        target = Path(tempfile.mkdtemp(prefix="cs-w2-kube-")) / "merged-config"
        target.write_text("apiVersion: v1\n")
        (k8s / "merged.json").write_text(json.dumps({"files": [str(target)], "contexts": ["vmware-x"],
                                                     "clusters": ["vmware-x"], "users": ["vmware-x"]}))
        dropped = []
        with mock.patch.object(cli.deps, "find", return_value="/fake/kubectl"), \
                mock.patch.object(cli, "_drop_kubeconfig_entries",
                                  side_effect=lambda kubectl, t, names, env_id: dropped.append((t, names))), \
                mock.patch.dict(os.environ, {"KUBECONFIG": ""}):
            cli._forget_cluster_access(self.env)
        self.assertEqual(dropped[0][0], target)
        self.assertEqual(dropped[0][1]["contexts"], {"vmware-x"})
        self.assertFalse(k8s.exists())

    def test_record_keeps_only_names_present_in_the_target(self):
        k8s = self.env.dir / "k8s"
        k8s.mkdir()
        (k8s / "kubeconfig").write_text("x")
        target = Path(tempfile.mkdtemp(prefix="cs-w2-kube-")) / "config"
        target.write_text("x")
        views = {str(k8s / "kubeconfig"): {"contexts": [{"name": "default", "context": {"cluster": "default", "user": "default"}}],
                                           "clusters": [{"name": "default"}], "users": [{"name": "default"}],
                                           "current-context": "default"},
                 str(target): {"contexts": [{"name": f"vmware-{self.env_name}"}, {"name": "default"}],
                               "clusters": [{"name": f"vmware-{self.env_name}"}], "users": []}}
        with mock.patch.object(cli.deps, "find", return_value="/fake/kubectl"), \
                mock.patch.object(cli, "_kubeconfig_view", side_effect=lambda kubectl, p: json.loads(json.dumps(views[str(p)]))):
            cli._record_merged_kubeconfig(clouds.get("vmware"), self.env, target)
        rec = json.loads((k8s / "merged.json").read_text())
        self.assertEqual(rec["contexts"], [f"vmware-{self.env_name}"])
        self.assertEqual(rec["clusters"], [f"vmware-{self.env_name}"])
        self.assertEqual(rec["users"], [])
        self.assertEqual(rec["files"], [str(target)])

    def test_targeted_destroy_of_the_cluster_forgets_its_access(self):
        life.FakeTF.reset(state=["module.stack.module.kubernetes[0].vmdesktop_vm.node[\"cp1\"]"],
                          changes=[{"address": "module.stack.module.kubernetes[0].vmdesktop_vm.node[\"cp1\"]",
                                    "type": "vmdesktop_vm", "mode": "managed", "change": {"actions": ["delete"]}}],
                          outputs_value={})
        (self.env.dir / "outputs.json").write_text(json.dumps({"kubernetes_control_plane_ips": ["10.100.0.20"]}))
        with mock.patch.object(cli, "_prepare_local_teardown"), \
                mock.patch.object(cli, "_forget_cluster_access") as forget:
            rc = self.destroy("-y", "--auto-approve", "--target", "module.stack.module.kubernetes")
        self.assertEqual(rc, 0, self.out.getvalue())
        forget.assert_called_once()


# ---------------------------------------------------------------- VMware teardown: vm_dir and vmnet ownership

class VmwareTeardownTests(life.LifeBase):
    cloud = "vmware"

    def test_legacy_relative_vm_dir_resolves_where_the_provider_put_it(self):
        state = {"resources": [{"mode": "managed", "type": "vmdesktop_vm", "name": "bastion",
                                "instances": [{"attributes": {"path": "vms-old"}}]}]}
        (self.env.stack_dir / "terraform.tfstate").write_text(json.dumps(state))
        cfg = dict(self.cfg, vars={"vm_dir": "vms-old"})
        self.assertEqual(cli._vm_dir(self.env, cfg), self.env.stack_dir / "vms-old")
        self.assertEqual(cli._vm_dir(self.env, dict(self.cfg, vars={})), self.env.dir / "vms")

    def test_vmnet_is_removed_only_when_this_env_created_it(self):
        args = cli.build_parser().parse_args(["destroy", "vmware", "--env", self.env_name])
        with mock.patch.object(cli, "_vm_dir", return_value=self.env.dir / "vms"):
            adopted = cli._pending_cleanup(clouds.get("vmware"), self.env, self.cfg, args, (),
                                           {"private_vmnet": "vmnet3", "private_vmnet_adopted": True})
            created = cli._pending_cleanup(clouds.get("vmware"), self.env, self.cfg, args, (),
                                           {"private_vmnet": "vmnet3", "private_vmnet_adopted": False})
        self.assertFalse([p for p in adopted if "vmnet3" in p])
        self.assertTrue([p for p in created if "vmnet3" in p])
        host = {"found": True, "vmrun": "/fake/vmrun", "product": "fusion"}
        with mock.patch.object(localvm, "detect_host", lambda: host), \
                mock.patch.object(localvm, "vmrun_list", return_value=[]), \
                mock.patch.object(localvm, "remove_vmnet", return_value=False) as remove:
            _capture(cli._destroy_local_leftovers, self.env, self.cfg, purge=False, vmnet="vmnet3", adopted=False,
                     auto_approve=True)
        remove.assert_called_once_with(host, "vmnet3", adopted=False, env_id=self.env.id, auto_approve=True)


# ---------------------------------------------------------------- --purge with the workdir marker

class PurgeMarkerTests(unittest.TestCase):
    def _env(self, pre, files):
        d = Path(tempfile.mkdtemp(prefix="cs-w2-purge-")) / "work"
        d.mkdir()
        for rel, text in files.items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(text)
        env = paths.Env("aws", "w2purge", workdir=d)
        cfg = {"cloud": "aws", "env": "w2purge"}
        if pre is not None:
            cfg["workdir_preexisting"] = pre
        (d / "config.json").write_text(json.dumps(cfg))
        return env, d

    def test_directory_cloudseed_created_goes_wholesale(self):
        env, d = self._env([], {"stack/main.tf.json": "{}", "ssh/id_rsa": "k", "notes-added-later.txt": "x"})
        self.assertTrue(cli._workdir_owned(env))
        self.assertIn("Delete the working directory", cli._purge_question(env))
        left, protected = cli._remove_env_files(env)
        self.assertEqual((left, protected), ([], False))
        self.assertFalse(d.exists())

    def test_the_users_entries_stay_even_with_cloudseed_names(self):
        env, d = self._env(["k8s", "logs", "notes.txt"], {
            "notes.txt": "mine", "k8s/app.yaml": "mine", "k8s/kubeconfig": "cloudseed's, in the user's dir",
            "logs/app.log": "mine", "logs/audit.jsonl": "cloudseed", "stack/main.tf.json": "{}",
            "ssh/id_rsa": "fips key", "ssh/id_rsa.pub": "pub", "ssh/id_ed25519.pub.replaced-20260101000000": "old"})
        self.assertFalse(cli._workdir_owned(env))
        left, _ = cli._remove_env_files(env)
        self.assertEqual(left, ["k8s", "logs", "notes.txt"])
        self.assertTrue((d / "k8s" / "app.yaml").exists())
        self.assertTrue((d / "logs" / "app.log").exists())
        self.assertFalse((d / "logs" / "audit.jsonl").exists())
        self.assertFalse((d / "ssh").exists(), "cloudseed made ssh/ (FIPS id_rsa and set-aside keys included)")
        self.assertFalse((d / "stack").exists())

    def test_without_a_marker_the_ssh_files_of_every_key_type_go(self):
        env, d = self._env(None, {"ssh/id_rsa": "k", "ssh/id_rsa.pub": "p", "ssh/id_ecdsa": "k", "ssh/my-own-key": "mine"})
        cli._remove_env_files(env)
        self.assertEqual(sorted(p.name for p in (d / "ssh").iterdir()), ["my-own-key"])


# ---------------------------------------------------------------- GCP OS Login, read-only fallbacks

class OsLoginPrepareTests(life.LifeBase):
    cloud = "gcp"

    def setUp(self):
        super().setUp()
        self.cfg["vars"] = {"project_id": "p-123456", "zone": "us-central1-a", "enable_os_login": True}
        self.cfg["region"] = "us-central1"
        self.env.save(self.cfg)

    def _load(self, *cmd):
        args = cli.build_parser().parse_args([*cmd, "gcp", "--env", self.env_name])

        def prepare(self_, cfg, dry_run=False):
            cfg["os_login"] = {"account": "a@example.com", "user": "a_example_com", "member": "user:a@example.com"}
        with mock.patch.object(GCP, "prepare", prepare) as _:
            _capture(cli._load_env, args)

    def test_ssh_registers_the_os_login_key_first(self):
        self._load("ssh")
        self.assertEqual(self.env.load()["os_login"]["user"], "a_example_com")

    def test_read_only_commands_do_not(self):
        for cmd in (("status",), ("vpn", "status"), ("k8s", "info"), ("inventory",)):
            self._load(*cmd)
            self.assertNotIn("os_login", self.env.load(), cmd)
        self._load("vpn", "users")        # SSHes to the VPN host as the OS Login user
        self.assertIn("os_login", self.env.load())


class ReadOnlyFallbackTests(life.LifeBase):
    def _no_terraform(self, *a, **k):
        raise ui.Abort("terraform is not installed. Run `cloudseed install terraform`.")

    def test_status_without_terraform_shows_cached_outputs(self):
        (self.env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "192.0.2.10"}))
        with mock.patch.object(cli, "Terraform", side_effect=self._no_terraform):
            rc = self.run_cmd(cli.cmd_status, ["status", "aws", "--env", self.env_name])
        out = self.out.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("terraform is not installed", out)
        self.assertIn("192.0.2.10", out)
        self.assertIn("cloudseed install terraform", out)

    def test_output_falls_back_and_never_wipes_the_cache(self):
        cache = {"bastion_public_ip": "192.0.2.10"}
        (self.env.dir / "outputs.json").write_text(json.dumps(cache))
        with mock.patch.object(cli, "Terraform", side_effect=self._no_terraform):
            rc = self.run_cmd(cli.cmd_output, ["output", "aws", "--env", self.env_name, "--json"])
        self.assertEqual(rc, 1)
        self.assertIn('"bastion_public_ip": "192.0.2.10"', self.out.getvalue())

        class FailingOutputs(life.FakeTF):
            def run(self, *args, capture=False, check=True):
                if args[:1] == ("output",):
                    return _cp(1, "", "Error: failed to read state")
                return super().run(*args, capture=capture, check=check)
        with mock.patch.object(cli, "Terraform", FailingOutputs):
            rc = self.run_cmd(cli.cmd_output, ["output", "aws", "--env", self.env_name])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads((self.env.dir / "outputs.json").read_text()), cache)

        class GoodOutputs(life.FakeTF):
            def run(self, *args, capture=False, check=True):
                if args[:1] == ("output",):
                    return _cp(0, json.dumps({"bastion_public_ip": {"value": "192.0.2.11"}}))
                return super().run(*args, capture=capture, check=check)
        with mock.patch.object(cli, "Terraform", GoodOutputs):
            rc = self.run_cmd(cli.cmd_output, ["output", "aws", "--env", self.env_name, "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads((self.env.dir / "outputs.json").read_text()), {"bastion_public_ip": "192.0.2.11"})


if __name__ == "__main__":
    unittest.main()
