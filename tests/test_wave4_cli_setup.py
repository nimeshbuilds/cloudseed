"""Wave-4 regression tests for the setup / provision / lifecycle commands: the cross-file wiring other groups asked for
(GCP OS Login key release, kept shared singletons, singletons switched off at plan time, fail2ban after update-ip,
provision.await_fips, doctor's live credential check and Common tools), local VMs that leave the cluster before a lower
node count deletes them, --preview, AWS region/baseline rules, network overlap wording, tags, purge history, and ssh
options typed before an environment id. Stdlib only; Terraform, ssh, kubectl and the hypervisor are faked."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, cli, clouds, deps, paths, reconcile, services, ui, undo  # noqa: E402

import test_fix_cli_life as life  # noqa: E402  (tests/ is on sys.path under unittest discovery)
import test_fix_cli_setup as setup_base  # noqa: E402

_n = [0]


def _uid(prefix: str) -> str:
    while True:
        _n[0] += 1
        name = f"{prefix}{life.RUN_ID}v{_n[0]}"
        if not life._taken(name):   # not an environment an earlier run left in a reused CLOUDSEED_HOME
            return name


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


def _plain(text: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


class _Envs(unittest.TestCase):
    """Environments made by a test are removed again (and the settings file restored)."""

    def setUp(self):
        self.made: list[paths.Env] = []
        self.settings_before = paths.load_settings()
        self.ni = mock.patch.object(ui, "interactive", return_value=False)
        self.ni.start()

    def tearDown(self):
        self.ni.stop()
        paths.save_settings(self.settings_before)
        for e in self.made:
            undo.clear(e.id)
            shutil.rmtree(e.dir, ignore_errors=True)
            shutil.rmtree(paths.HOME / "logs" / "purged" / e.id, ignore_errors=True)
            index = paths._load_index()
            if index.pop(e.id, None):
                paths._save_index(index)
        log = audit._state.get("log")
        if log:
            log.close()

    def env(self, cloud: str, **extra) -> paths.Env:
        name = _uid("w")
        e = paths.Env(cloud, name)
        e.create_dirs()
        cfg = {"cloud": cloud, "env": name, "name": "cs", "region": "local" if cloud == "vmware" else "us-east-1",
               "network_cidr": "10.30.0.0/16", "allowed_ssh_cidrs": ["198.51.100.7/32"],
               "state": {"type": "local", "backend": None}, "vars": {}, "extra_vars": {}, "tags": {},
               "ssh_public_key": setup_base.fake_pub("ssh-ed25519")}
        cfg.update(extra)
        e.save(cfg)
        self.made.append(e)
        return e


# ---------------------------------------------------------------- AWS rules (aws group)

class AwsRuleTests(unittest.TestCase):
    aws = clouds.get("aws")

    def test_china_and_isolated_regions_are_refused_at_the_prompt(self):
        for bad in ("cn-north-1", "cn-northwest-1", "us-iso-east-1", "us-isob-east-1", "us-isof-south-1"):
            self.assertIn("is not supported", cli._setup_region_problem(self.aws, bad), bad)
            self.assertIsNone(cli._region_problem(self.aws, bad), bad)     # a region name all the same
        for ok in ("us-east-1", "us-gov-west-1", "ap-southeast-7"):
            self.assertIsNone(cli._setup_region_problem(self.aws, ok), ok)
        self.assertIsNone(cli._setup_region_problem(clouds.get("gcp"), "us-central1"))

    def test_setup_refuses_an_unsupported_region_flag_before_anything_is_written(self):
        args = cli.build_parser().parse_args(["setup", "aws", "--env", "rg1", "--region", "cn-north-1", "--dry-run", "-y"])
        with self.assertRaises(ui.Abort) as cm:
            cli._check_setup_flags(self.aws, args, {"answers": {}})
        self.assertIn("--region: Region cn-north-1 is not supported", cm.exception.msg)

    def cfg(self, name="acme-platform-team-east", env="production-blue", **vars_):
        extra = vars_.pop("extra", {})
        return {"cloud": "aws", "name": name, "env": env, "network_cidr": "10.0.0.0/16", "vars": vars_, "extra_vars": extra}

    def test_log_bucket_prefix_limit_follows_what_writes_to_the_bucket(self):
        # 39 characters: fits the state bucket rule (46), not the log bucket rule (39) ... 'x' makes it 40
        long = dict(name="acme-platform-team-eastx")
        self.assertTrue(cli._aws_log_bucket(self.cfg(**long)))                                      # CloudTrail on by default
        self.assertTrue([p for p in cli._config_problems(self.aws, self.cfg(**long)) if "log bucket" in p])
        no_trail = self.cfg(**long, extra={"enable_cloudtrail": False})
        self.assertFalse(cli._aws_log_bucket(no_trail))
        self.assertFalse([p for p in cli._config_problems(self.aws, no_trail) if "name prefix" in p])
        hub = self.cfg(**long, enable_security_hub=True, extra={"enable_cloudtrail": False})       # AWS Config -> bucket
        self.assertTrue(cli._aws_log_bucket(hub))
        self.assertTrue([p for p in cli._config_problems(self.aws, hub) if "name prefix" in p])
        # the regional half only (account half off): the adapter reports it - once
        regional = self.cfg(**long, enable_account_baseline=False, enable_regional_baseline=True, enable_security_hub=True)
        self.assertEqual(len([p for p in cli._config_problems(self.aws, regional) if "name prefix" in p]), 1)
        self.assertFalse(cli._aws_log_bucket(self.cfg(**long, enable_account_baseline="no")))    # strict, not truthy

    def test_security_hub_row_and_empty_bucket_output_hide_when_they_do_nothing(self):
        off = {"cloud": "aws", "vars": {"enable_account_baseline": False, "enable_security_hub": True}}
        self.assertTrue(cli._feature_off(off, "enable_security_hub"))
        self.assertFalse(cli._feature_off({"cloud": "aws", "vars": {}}, "enable_security_hub"))
        self.assertTrue(cli._feature_off({"cloud": "aws", "vars": {}, "extra_vars": {"enable_cloudtrail": False}},
                                         "cloudtrail_bucket"))
        self.assertFalse(cli._feature_off({"cloud": "aws", "vars": {}}, "cloudtrail_bucket"))
        _, out = _capture(cli._print_outputs, {"cloudtrail_bucket": None, "vpc_id": "vpc-1"},
                          {"cloud": "aws", "vars": {"enable_account_baseline": False}})
        self.assertNotIn("cloudtrail_bucket", out)
        self.assertIn("vpc-1", out)

    def test_access_analyzer_counts_as_an_account_wide_delete(self):
        self.assertEqual(cli._account_wide_deletes(
            ["module.stack.module.security_baseline[0].aws_accessanalyzer_analyzer.this[0]"], []), ["IAM Access Analyzer"])

    def test_network_rules_are_the_adapters_own_when_it_has_them(self):
        aws, gcp = clouds.get("aws"), clouds.get("gcp")
        self.assertTrue(cli._own_network_rules(aws))
        self.assertFalse(cli._own_network_rules(gcp))
        c = {"network_cidr": "10.0.0.0/16", "vars": {"az_count": 6}, "extra_vars": {}, "subnet_stride": 5}
        self.assertEqual(cli._network_problems(aws, c), aws.network_problems(c))


# ---------------------------------------------------------------- network, allow-list, tags, flags

class NetworkWordingTests(unittest.TestCase):
    def warn(self, cloud_key, cidr, networks):
        return _plain(_capture(cli._warn_network_overlaps, clouds.get(cloud_key), cidr, networks)[1])

    def test_overlap_warnings_say_what_really_conflicts(self):
        out = self.warn("vmware", "10.9.0.0/24", [("vmware-lab", "vmware", "10.9.0.0/24")])
        self.assertIn("same fixed addresses", out)
        self.assertIn("vmware-lab", out)
        self.assertNotIn("peering", out)
        out = self.warn("vmware", "10.9.0.0/24", [("aws-dev", "aws", "10.9.0.0/16")])
        self.assertIn("aws-dev", out)
        self.assertIn("VPN is connected", out)
        self.assertNotIn("peering", out)
        out = self.warn("aws", "10.9.0.0/16", [("vmware-lab", "vmware", "10.9.1.0/24"), ("gcp-x", "gcp", "10.9.0.0/20")])
        self.assertIn("local VMware network of vmware-lab", out)
        self.assertIn("gcp-x (10.9.0.0/20); VPN routes and peering", out)
        self.assertEqual(self.warn("aws", "10.9.0.0/16", [("aws-o", "aws", "10.10.0.0/16")]), "")

    def test_a_public_range_on_a_cloud_network_is_warned_about(self):
        self.assertIn("public address range", self.warn("aws", "8.8.8.0/24", []))
        self.assertEqual(self.warn("aws", "100.64.0.0/16", []), "")      # shared (CGNAT) space: not the internet's
        self.assertEqual(self.warn("vmware", "8.8.8.0/24", []), "")       # vmware refuses it in the adapter instead

    def test_legacy_allow_list_override_with_host_bits_is_migrated(self):
        args = SimpleNamespace(allow_ip=None)
        env = paths.Env("aws", "legacyallow")
        with mock.patch.object(cli.netutil, "detect_public_ip", return_value="198.51.100.7"), \
                mock.patch.object(ui, "interactive", return_value=False):
            got, out = _capture(cli._setup_allow_list, args, clouds.get("aws"), env, {}, {"unset": []},
                                {"allow": "198.51.100.7/24"})
        self.assertEqual(got, ["198.51.100.0/24"])
        self.assertIn("Moved the saved --var allowed_ssh_cidrs override", out)
        with mock.patch.object(cli.netutil, "detect_public_ip", return_value="198.51.100.7"), \
                mock.patch.object(ui, "interactive", return_value=False):
            got, out = _capture(cli._setup_allow_list, args, clouds.get("aws"), env, {"allowed_ssh_cidrs": ["203.0.113.9/32"]},
                                {"unset": []}, {"allow": "0.0.0.0/1,128.0.0.0/1"})
        self.assertIn("Dropping the saved --var allowed_ssh_cidrs override", out)
        self.assertEqual(got, ["203.0.113.9/32"])


class TagTests(unittest.TestCase):
    def test_a_new_tag_replaces_a_saved_one_in_any_spelling(self):
        self.assertEqual(cli._merge_tags({"team": "a", "cost": "1"}, {"Team": "b"}), {"cost": "1", "Team": "b"})
        self.assertEqual(cli._merge_tags({"Team": "a", "cost": "1"}, {"team": ""}), {"cost": "1"})   # KEY= removes it
        self.assertEqual(cli._merge_tags({}, {"team": "a", "Team": "b"}), {"team": "a", "Team": "b"})   # refused later
        problems = clouds.get("aws").tags_problems({"tags": cli._merge_tags({}, {"team": "a", "Team": "b"})})
        self.assertTrue(problems)

    def test_saved_tags_are_read_as_they_apply(self):
        aws = clouds.get("aws")
        self.assertEqual(cli._effective_tags({"Team": "x", "team": ""}), {})
        self.assertEqual(cli._saved_tags(aws, {"tags": {"Team": "x", "team": "", "cost": "1"}}), {"cost": "1"})
        # the rendered tags agree
        cfg = {"name": "n", "env": "e", "tags": {"Team": "x", "team": ""}}
        self.assertNotIn("Team", aws.tags(cfg))
        self.assertEqual(cli._changed_settings({"tags": {"Team": "x", "team": ""}}, {"tags": {}}), [])
        self.assertEqual(cli._changed_settings({"tags": {"a": "1"}}, {"tags": {"a": "2"}}), ["tags"])


class EarlyFlagTests(unittest.TestCase):
    def test_a_bad_subscription_id_is_refused_before_any_question(self):
        azure = clouds.get("azure")
        args = cli.build_parser().parse_args(["setup", "azure", "--env", "fl1", "--subscription-id", "not-a-guid", "-y"])
        with self.assertRaises(ui.Abort) as cm:
            cli._check_setup_flags(azure, args, {"answers": {}})
        self.assertIn("--subscription-id not-a-guid", cm.exception.msg)
        self.assertIn("not an Azure subscription ID", cm.exception.msg)
        args = cli.build_parser().parse_args(["setup", "azure", "--env", "fl1", "-y"])
        with self.assertRaises(ui.Abort) as cm:
            cli._check_setup_flags(azure, args, {"answers": {"subscription_id": "bad"}})
        self.assertIn("--var subscription_id=bad", cm.exception.msg)
        good = "0123abcd-0000-0000-0000-000000000000"
        args = cli.build_parser().parse_args(["setup", "azure", "--env", "fl1", "--subscription-id", good, "-y"])
        cli._check_setup_flags(azure, args, {"answers": {}})

    def test_a_zone_waits_for_the_region_unless_both_are_given(self):
        gcp = clouds.get("gcp")
        args = cli.build_parser().parse_args(["setup", "gcp", "--env", "fl2", "--zone", "europe-west1-b", "-y"])
        cli._check_setup_flags(gcp, args, {"answers": {}})                   # the saved region decides later
        args = cli.build_parser().parse_args(["setup", "gcp", "--env", "fl2", "--zone", "europe-west1-b",
                                              "--region", "us-central1", "-y"])
        with self.assertRaises(ui.Abort):
            cli._check_setup_flags(gcp, args, {"answers": {}})

    def test_saved_answer_fix_uses_the_questions_own_flag(self):
        gcp = clouds.get("gcp")
        cfg = {"vars": {"project_id": 7}}
        with mock.patch.object(clouds.Question, "coerce", side_effect=ValueError("bad")):
            with self.assertRaises(ui.Abort) as cm:
                cli._check_answers(gcp, paths.Env("gcp", "fl3"), cfg)
        self.assertIn("--project-id VALUE", cm.exception.msg)


class WorkdirClaimTests(_Envs):
    def test_an_abandoned_claim_does_not_block_its_directory(self):
        root = Path(tempfile.mkdtemp(prefix="cs-w4-wd-"))
        self.addCleanup(shutil.rmtree, root, True)
        gone = root / "gone"
        index = paths._load_index()
        index["aws-w4gone"] = str(gone)                  # its directory was deleted: nothing lives there any more
        paths._save_index(index)
        self.addCleanup(lambda: paths._save_index({k: v for k, v in paths._load_index().items() if k != "aws-w4gone"}))
        self.assertIsNone(cli._workdir_conflict(gone.resolve(), "aws-w4new"))
        gone.mkdir()
        (gone / "config.json").write_text("{}")          # it does hold an environment: still refused
        self.assertIn("aws-w4gone", cli._workdir_conflict(gone.resolve(), "aws-w4new"))


# ---------------------------------------------------------------- provisioning

class ProvisionTests(_Envs):
    def test_vpn_on_a_local_target_is_refused_before_the_environment_is_loaded(self):
        args = cli.build_parser().parse_args(["provision", "vmware", "--env", "x", "--host", "vpn"])
        with mock.patch.object(cli, "_load_env", side_effect=AssertionError("loaded")):
            with self.assertRaises(ui.Abort) as cm:
                cli.cmd_provision(args, {})
        self.assertIn("--host vpn does not apply to vmware", cm.exception.msg)
        self.assertEqual(cm.exception.code, 2)
        args = cli.build_parser().parse_args(["provision", "aws", "--env", "x", "--host", "k8s", "--sync-only"])
        with mock.patch.object(cli, "_load_env", side_effect=AssertionError("loaded")):
            with self.assertRaises(ui.Abort) as cm:
                cli.cmd_provision(args, {})
        self.assertEqual(cm.exception.code, 2)

    def test_provision_loads_without_hypervisor_work(self):
        e = self.env("vmware")
        (e.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "10.30.0.2"}))
        seen = {}
        vmware = clouds.get("vmware")
        with mock.patch.object(type(vmware), "prepare", lambda self, cfg, dry_run=False: seen.setdefault("dry", dry_run)), \
                mock.patch.object(cli, "_provision_all", return_value=["bastion"]), mock.patch.object(undo, "record"):
            args = cli.build_parser().parse_args(["provision", "vmware", "--env", e.name])
            self.assertEqual(_capture(cli.cmd_provision, args, {})[0], 0)
        self.assertIs(seen["dry"], True)

    def test_k8s_on_a_managed_cloud_without_a_cluster_is_an_error(self):
        e = self.env("aws", vars={"enable_kubernetes": True})
        (e.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "203.0.113.1"}))
        with self.assertRaises(ui.Abort) as cm:
            cli._provision_all(clouds.get("aws"), e, e.load(), only="k8s")
        self.assertIn("not applied", cm.exception.msg)
        e2 = self.env("aws")
        with self.assertRaises(ui.Abort) as cm:
            cli._provision_all(clouds.get("aws"), e2, e2.load(), only="k8s")
        self.assertIn("--var enable_kubernetes=true", cm.exception.msg)
        (e.dir / "outputs.json").write_text(json.dumps({"kubernetes_cluster_name": "c"}))
        self.assertEqual(_capture(cli._provision_all, clouds.get("aws"), e, e.load(), only="k8s")[0], [])

    def test_sync_only_names_the_synced_hosts_and_the_vpn_port_is_the_stacks(self):
        e = self.env("aws", vars={"vpn_type": "openvpn"}, extra_vars={"vpn_port": 443})
        (e.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "203.0.113.1", "vpn_public_ip": "203.0.113.2"}))
        seen = []
        with mock.patch.object(cli.prov, "provision", lambda *a, **k: seen.append(k)):
            done, _ = _capture(cli._provision_all, clouds.get("aws"), e, e.load(), sync_only=True)
        self.assertEqual(done, ["bastion", "vpn"])
        self.assertEqual(seen[-1]["extra_vars"]["vpn_port"], 443)           # no output yet: the configured port
        (e.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "203.0.113.1", "vpn_public_ip": "203.0.113.2",
                                                        "vpn_port": 1195}))
        with mock.patch.object(cli.prov, "provision", lambda *a, **k: seen.append(k)):
            _capture(cli._provision_all, clouds.get("aws"), e, e.load(), sync_only=True, only="vpn")
        self.assertEqual(seen[-1]["extra_vars"]["vpn_port"], 1195)

    def test_sync_only_records_an_undo_entry_only_for_synced_hosts(self):
        e = self.env("aws")
        (e.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "203.0.113.1"}))
        args = cli.build_parser().parse_args(["provision", "aws", "--env", e.name, "--sync-only"])
        with mock.patch.object(cli, "_provision_all", return_value=[]):
            _capture(cli.cmd_provision, args, {})
        self.assertIsNone(undo.latest(e.id))
        with mock.patch.object(cli, "_provision_all", return_value=["bastion"]):
            _capture(cli.cmd_provision, args, {})
        self.assertIn("(bastion)", undo.latest(e.id)["summary"])

    def test_a_gcp_vpn_host_needs_no_pro_token_whatever_the_bastion_image(self):
        # the bastion on a plain Ubuntu image needs the token; the VPN host boots GCP's Ubuntu Pro FIPS image and does not
        e = self.env("gcp", vars={"fips_mode": True, "enable_vpn": True, "vpn_type": "openvpn", "project_id": "p-123456"},
                     extra_vars={"bastion_image": "ubuntu-os-cloud/ubuntu-2404-lts-amd64"})
        (e.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "203.0.113.1", "vpn_public_ip": "203.0.113.2"}))
        seen = []
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": ""}), \
                mock.patch.object(cli.prov, "provision", lambda *a, **k: seen.append(k)), \
                mock.patch.object(cli, "_verify_fips"):
            done, out = _capture(cli._provision_all, clouds.get("gcp"), e, e.load(), only="vpn")
        self.assertEqual(done, ["vpn"], out)
        self.assertTrue(cli._fips_vpn_needs_token(clouds.get("aws")))
        self.assertFalse(cli._fips_vpn_needs_token(clouds.get("gcp")))

    def test_fips_verification_goes_through_provision_await_fips(self):
        host = SimpleNamespace(label="vpn", env=paths.Env("aws", "fp1"))
        with mock.patch.object(cli.prov, "await_fips") as waited:
            cli._verify_fips(host)
        waited.assert_called_once_with(host, "cloudseed provision aws --env fp1 --host vpn")

    def test_no_bastion_address_of_a_never_applied_environment(self):
        e = self.env("aws")
        msg = cli._no_bastion_ip(clouds.get("aws"), e, refreshed=True)
        self.assertIn("has not been applied yet", msg)
        (e.dir / "outputs.json").write_text(json.dumps({"vpc_id": "vpc-1"}))
        msg = cli._no_bastion_ip(clouds.get("aws"), e, refreshed=True)
        self.assertIn("state has no bastion address", msg)
        self.assertNotIn("cloudseed status", msg)


class VpnLocalTests(_Envs):
    def test_vpn_on_vmware_answers_without_terraform(self):
        e = self.env("vmware")
        with mock.patch.object(cli, "_outputs_fresh", side_effect=AssertionError("terraform")), \
                mock.patch.object(type(clouds.get("vmware")), "prepare", side_effect=AssertionError("provider")):
            rc, out = _capture(cli.cmd_vpn, cli.build_parser().parse_args(["vpn", "status", "vmware", "--env", e.name]), {})
            self.assertEqual(rc, 0, out)
            self.assertIn("not applicable", out)
            rc, out = _capture(cli.cmd_vpn, cli.build_parser().parse_args(["vpn", "disconnect", "vmware", "--env", e.name]), {})
            self.assertEqual(rc, 0, out)
            rc, out = _capture(cli.cmd_vpn, cli.build_parser().parse_args(["vpn", "add-user", "vmware", "--env", e.name, "bob"]), {})
            self.assertEqual(rc, 1)
            self.assertIn("The VPN does not apply to vmware", out)
        self.assertEqual(cli.LOCAL_NOT_APPLICABLE["enable_vpn"], services.VPN_LOCAL_REASON)


# ---------------------------------------------------------------- setup / apply wiring

class _TF(life.FakeTF):
    pass


class PlanForApplyTests(_Envs):
    def singleton(self, auto=True):
        return reconcile.SingletonExists("GuardDuty exists. Nothing was applied.", {"enable_guardduty": False}, auto,
                                         [("aws_guardduty_detector", "module.stack.x.aws_guardduty_detector.this", ["d-1"])])

    def test_default_on_singletons_are_switched_off_saved_and_planned_again(self):
        e = self.env("aws")
        cfg = e.load()
        t = SimpleNamespace(calls=0)

        def plan_for_apply(cloud_key, c, targets=()):
            t.calls += 1
            if t.calls == 1:
                raise self.singleton()
        t.plan_for_apply = plan_for_apply
        renders = []
        with mock.patch.object(cli, "_render", lambda *a: renders.append(a) or False):
            _, out = _capture(cli._plan_for_apply, clouds.get("aws"), e, cfg, t)
        self.assertEqual(t.calls, 2)
        self.assertEqual(len(renders), 1)
        self.assertIs(e.load()["extra_vars"]["enable_guardduty"], False)
        self.assertIn("enable_guardduty=false", out)

    def test_a_singleton_the_user_asked_for_still_stops(self):
        e = self.env("aws")
        t = SimpleNamespace(plan_for_apply=lambda *a, **k: (_ for _ in ()).throw(self.singleton(auto=False)))
        with self.assertRaises(reconcile.SingletonExists):
            cli._plan_for_apply(clouds.get("aws"), e, e.load(), t)


class LocalNodeTests(_Envs):
    def test_plan_that_lowers_the_worker_count_names_the_leaving_nodes(self):
        e = self.env("vmware", vars={"enable_kubernetes": True, "kubernetes_workers": 1})
        life.FakeTF.reset(changes=[
            {"address": 'module.stack.module.kubernetes[0].vmdesktop_vm.node["wk2"]', "type": "vmdesktop_vm",
             "mode": "managed", "change": {"actions": ["delete"]}},
            {"address": "module.stack.module.bastion.vmdesktop_vm.bastion", "type": "vmdesktop_vm", "mode": "managed",
             "change": {"actions": ["delete", "create"]}}])
        keys, out = _capture(cli._local_vm_plan, clouds.get("vmware"), e, e.load(), life.FakeTF(e.stack_dir))
        self.assertEqual(keys, ["wk2"])
        self.assertIn("re-creates 1 VM (module.bastion.vmdesktop_vm.bastion): their disks are wiped", _plain(out))
        self.assertIn('deletes 1 VM for good (module.kubernetes[0].vmdesktop_vm.node["wk2"])', _plain(out))
        self.assertNotIn("re-creates 2", _plain(out))          # a VM that goes is not called re-created
        # the whole cluster goes (enable_kubernetes off): nothing to drain one by one
        off = dict(e.load(), vars={"enable_kubernetes": False})
        self.assertEqual(_capture(cli._local_vm_plan, clouds.get("vmware"), e, off, life.FakeTF(e.stack_dir))[0], [])
        # an unreadable plan: the deployed nodes beyond the configured count
        life.FakeTF.reset(changes=None)
        (e.dir / "outputs.json").write_text(json.dumps({"kubernetes_worker_ips": ["10.30.0.40", "10.30.0.41", "10.30.0.42"],
                                                        "kubernetes_control_plane_ips": ["10.30.0.20"]}))
        self.assertEqual(cli._local_vm_plan(clouds.get("vmware"), e, e.load(), life.FakeTF(e.stack_dir)), ["wk2", "wk3"])

    def test_leaving_nodes_are_drained_workers_first_highest_first(self):
        e = self.env("vmware", vars={"enable_kubernetes": True})
        services.kubeconfig_path(e).parent.mkdir(parents=True, exist_ok=True)
        services.kubeconfig_path(e).write_text("kc")
        left = []
        with mock.patch.object(services, "ensure_kubeconfig", return_value=Path("/tmp/kc")), \
                mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"), \
                mock.patch.object(cli, "_node_json_or_none", return_value={}), \
                mock.patch.object(cli, "_leave_local_node", lambda *a, registered: left.append(a[-1])):
            cli._leave_deleted_nodes(clouds.get("vmware"), e, e.load(), ["cp2", "wk2", "wk3"])
        self.assertEqual(left, [f"cs-{e.name}-wk3", f"cs-{e.name}-wk2", f"cs-{e.name}-cp2"])

    def test_nothing_to_drain_when_the_cluster_was_never_installed(self):
        e = self.env("vmware", vars={"enable_kubernetes": True})
        with mock.patch.object(cli, "_leave_local_node", side_effect=AssertionError("drained")):
            _, out = _capture(cli._leave_deleted_nodes, clouds.get("vmware"), e, e.load(), ["wk2"])
        self.assertIn("never installed", out)


class SetupWiringTests(_Envs):
    """_setup's apply path with Terraform faked: OS Login keys are released, kept singletons settled, --preview."""

    def run_setup(self, argv, cloud="aws", prepare=None, preview=False, **patches):
        args = cli.build_parser().parse_args(argv)
        args.cloud = cloud
        if preview:          # setup --preview (the flag itself is build_parser's)
            args.preview = True
        life.FakeTF.reset(state=["module.stack.aws_vpc.this"], changes=[{"address": "module.stack.aws_vpc.this",
                                                                           "type": "aws_vpc", "mode": "managed",
                                                                           "change": {"actions": ["update"]}}])
        cls = type(clouds.get(cloud))
        ps = [mock.patch.object(cli, "Terraform", life.FakeTF), mock.patch.object(cli, "_render", lambda *a, **k: False),
              mock.patch.object(cls, "prepare", prepare or (lambda self, cfg, dry_run=False: None)),
              mock.patch.object(cli, "_provision_all", return_value=[]),
              mock.patch.object(cli.netutil, "detect_public_ip", return_value="198.51.100.7"),
              mock.patch.object(cli, "_finish", lambda *a, **k: None),
              mock.patch.object(cls, "credential_warnings", lambda self, cfg: [])]
        ps += [mock.patch.object(cli, k, v) for k, v in patches.items()]
        for p in ps:
            p.start()
        try:
            return _capture(cli.cmd_setup, args, {})
        finally:
            for p in ps:
                p.stop()

    def test_release_after_a_successful_apply_and_after_a_stopped_one(self):
        e = self.env("aws")
        released = []
        with mock.patch.object(type(clouds.get("aws")), "release_os_login",
                               lambda self, old, new=None: released.append((old.get("os_login"), new)) or False, create=True):
            cfg = e.load()
            cfg["os_login"] = {"account": "a@x", "key": "k", "added": True}
            e.save(cfg)
            rc, out = self.run_setup(["setup", "aws", "--env", e.name, "-y", "--auto-approve", "--state", "local",
                                      "--name", "cs", "--region", "us-east-1"])
            self.assertEqual(rc, 0, out)
            self.assertTrue(released and released[-1][0] == {"account": "a@x", "key": "k", "added": True})
            released.clear()
            rc, out = self.run_setup(["setup", "aws", "--env", e.name, "-y", "--state", "local", "--name", "cs",
                                      "--region", "us-east-1"])            # no --auto-approve: stops at the approval
            self.assertEqual(rc, 3, out)
            self.assertTrue(released, "a stopped run releases a key the restored configuration does not use")

    def test_kept_singletons_are_settled_after_the_apply(self):
        e = self.env("azure", region="eastus", vars={"subscription_id": "0123abcd-0000-0000-0000-000000000000"},
                     kept_shared={'module.stack.x.azurerm_security_center_subscription_pricing.this["VirtualMachines"]': "id"})
        life.FakeTF.reset()
        with mock.patch.object(reconcile, "settle_kept", return_value=True) as settled:
            t = life.FakeTF(e.stack_dir)
            cfg = e.load()
            cfg.pop("kept_shared")
            cli._settle_kept(e, cfg, t)       # nothing recorded: nothing to settle
            settled.assert_not_called()
            cli._settle_kept(e, e.load(), t)
            settled.assert_called_once()

    def test_preview_keeps_the_previous_configuration(self):
        e = self.env("aws")
        before = e.load()
        args = ["setup", "aws", "--env", e.name, "-y", "--state", "local", "--name", "cs", "--region", "us-east-1",
                "--var", "single_nat_gateway=false"]
        rc, out = self.run_setup(args, preview=True)
        self.assertEqual(rc, 0, out)
        self.assertIn("keeps its previous configuration", out)
        self.assertEqual(e.load()["vars"].get("single_nat_gateway"), before["vars"].get("single_nat_gateway"))

    def test_preview_of_a_new_environment_saves_nothing(self):
        name = _uid("pv")
        env = paths.Env("aws", name)
        self.made.append(env)
        args = ["setup", "aws", "--env", name, "-y", "--state", "local", "--name", "cs", "--region", "us-east-1"]
        rc, out = self.run_setup(args, preview=True)
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing was saved", out)
        self.assertFalse(env.exists())
        self.assertFalse(env.dir.exists())


class KeptOnApplyTests(_Envs):
    def test_an_apply_forgets_account_wide_settings_instead_of_deleting_them(self):
        e = self.env("aws")
        pab = "module.stack.module.security_baseline[0].aws_s3_account_public_access_block.this"
        life.FakeTF.reset(state=[pab, "module.stack.aws_vpc.this"], changes=[
            {"address": pab, "type": "aws_s3_account_public_access_block", "mode": "managed", "change": {"actions": ["delete"]}},
            {"address": "module.stack.aws_vpc.this", "type": "aws_vpc", "mode": "managed", "change": {"actions": ["update"]}}])
        t = life.FakeTF(e.stack_dir)
        ran = []
        t.run = lambda *a, **k: ran.append(a) or subprocess.CompletedProcess(a, 0, "", "")
        keep = cli._kept_deletes(clouds.get("aws"), e.load(), life.FakeTF(e.stack_dir))
        self.assertEqual(keep, [(pab, "")])
        _, out = _capture(cli._forget_kept_for_apply, e, e.load(), t, keep)
        self.assertIn(("state", "rm", pab), ran)
        self.assertEqual(life.FakeTF.calls[-1], ("plan", False, ()))            # planned again, not a destroy plan
        self.assertIn("Left in place", out)
        life.FakeTF.reset(changes=[{"address": pab, "type": "aws_s3_account_public_access_block", "mode": "managed",
                                    "change": {"actions": ["delete", "create"]}}])
        self.assertEqual(cli._kept_deletes(clouds.get("aws"), e.load(), life.FakeTF(e.stack_dir)), [])   # a replacement stays


class GcpFipsImageTests(unittest.TestCase):
    gcp = clouds.get("gcp")

    def cfg(self, image=None):
        extra = {"bastion_image": image} if image else {}
        return {"cloud": "gcp", "env": "f", "region": "us-central1", "vars": {"fips_mode": True}, "extra_vars": extra}

    def test_the_default_image_is_pro_fips_and_needs_no_token(self):
        self.assertEqual(cli._gcp_fips_bastion_image(self.cfg()), "ubuntu-os-pro-cloud/ubuntu-pro-fips-2204-lts")
        self.assertFalse(cli._fips_needs_pro_token(self.gcp, self.cfg()))
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": ""}):
            _capture(cli._check_fips, self.gcp, self.cfg(), applying=True)

    def test_a_plain_ubuntu_image_needs_the_token_and_debian_is_refused(self):
        plain = self.cfg("ubuntu-os-cloud/ubuntu-2404-lts-amd64")
        self.assertTrue(cli._fips_needs_pro_token(self.gcp, plain))
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": ""}):
            with self.assertRaises(ui.Abort) as cm:
                cli._check_fips(self.gcp, plain, applying=True)
        self.assertIn("the bastion (Ubuntu image without Pro)", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            cli._check_fips(self.gcp, self.cfg("my-project/debian-hardened"), applying=False)
        self.assertIn("bastion_image=my-project/debian-hardened", cm.exception.msg)


# ---------------------------------------------------------------- destroy and purge

class DestroyTests(_Envs):
    def test_kept_singletons_are_remembered_in_the_saved_configuration(self):
        e = self.env("azure", region="eastus", vars={"subscription_id": "0123abcd-0000-0000-0000-000000000000"})
        cfg = dict(e.load(), vars={"subscription_id": "stand-in"})           # the command's copy may hold stand-ins
        addr = 'module.stack.module.security[0].azurerm_security_center_subscription_pricing.this["VirtualMachines"]'
        cli._remember_kept(e, cfg, [(addr, "notice")])
        saved = e.load()
        self.assertIn(addr, saved.get("kept_shared") or {})
        self.assertEqual(saved["vars"]["subscription_id"], "0123abcd-0000-0000-0000-000000000000")

    def test_forget_kept_says_project_wide(self):
        t = SimpleNamespace(run=lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""))
        _, out = _capture(cli._forget_kept, t, [("module.stack.google_logging_project_bucket_config.x", "")])
        self.assertIn("account/subscription/project-wide", out)

    def test_dependents_of_the_targets_are_named(self):
        deletes = [{"address": "module.stack.module.bastion.aws_instance.bastion"},
                   {"address": "module.stack.module.vpn[0].aws_instance.vpn"},
                   {"address": "module.stack.module.vpn[0].aws_eip.vpn"}]
        _, out = _capture(cli._warn_dependents, deletes, ["module.stack.module.bastion"])
        self.assertIn("Also destroyed, because they depend on the targets (2 resources)", out)
        self.assertIn("module.vpn[0]: aws_instance.vpn, aws_eip.vpn", out)
        self.assertEqual(_capture(cli._warn_dependents, deletes[:1], ["module.stack.module.bastion"])[1], "")

    def test_destroy_tags_its_scope_for_troubleshoot(self):
        e = self.env("aws")
        life.FakeTF.reset(state=["module.stack.module.bastion.aws_instance.bastion", "module.stack.aws_vpc.this"],
                          changes=[{"address": "module.stack.module.bastion.aws_instance.bastion", "type": "aws_instance",
                                    "mode": "managed", "change": {"actions": ["delete"]}}])
        tags = {}
        with mock.patch.object(cli, "Terraform", life.FakeTF), mock.patch.object(cli, "_render", lambda *a, **k: False), \
                mock.patch.object(audit, "tag", lambda **k: tags.update(k)):
            args = cli.build_parser().parse_args(["destroy", "aws", "--env", e.name, "--target",
                                                  "module.stack.module.bastion", "--auto-approve", "-y"])
            rc, out = _capture(cli.cmd_destroy, args, {})
        self.assertEqual(rc, 0, out)
        self.assertEqual(tags.get("destroy_scope"), ["module.stack.module.bastion"])

    def test_select_without_a_terminal_is_a_usage_error(self):
        with mock.patch.object(ui, "ask", return_value="q"), mock.patch.object(ui, "interactive", return_value=False):
            rc, out = _capture(cli._select_targets, ["module.stack.aws_vpc.this"])
        self.assertEqual(rc, 2)
        self.assertIn("--select needs a terminal", out)
        with mock.patch.object(ui, "ask", return_value="q"), mock.patch.object(ui, "interactive", return_value=True):
            rc, out = _capture(cli._select_targets, ["module.stack.aws_vpc.this"])
        self.assertEqual(rc, 0)
        self.assertIn("Cancelled", out)

    def test_os_login_release_after_a_full_destroy_drops_the_saved_record(self):
        e = self.env("gcp", region="us-central1", os_login={"account": "a@x", "key": "k", "added": True})
        gcp = clouds.get("gcp")
        cfg = e.load()
        with mock.patch.object(type(gcp), "release_os_login", lambda self, old, new=None: old.pop("os_login", None) is not None):
            cli._release_os_login(gcp, e, cfg, None)
        self.assertNotIn("os_login", e.load())
        e2 = self.env("gcp", region="us-central1", os_login={"account": "a@x", "key": "k", "added": True})
        with mock.patch.object(type(gcp), "release_os_login", lambda self, old, new=None: False):
            cli._release_os_login(gcp, e2, e2.load(), None)
        self.assertIn("os_login", e2.load())        # not removed (another env uses it, or gcloud failed): kept

    def test_purge_keeps_a_private_growing_history(self):
        e = self.env("aws")
        (e.dir / "inventory.json").write_text('{"history": [1]}')
        (e.dir / "logs").mkdir(exist_ok=True)
        (e.dir / "logs" / "audit.jsonl").write_text('{"a": 1}\n')
        keep = paths.HOME / "logs" / "purged" / e.id
        keep.mkdir(parents=True, exist_ok=True)
        cli._keep_history(e, keep)
        (e.dir / "inventory.json").write_text('{"history": [1, 2]}')
        (e.dir / "logs" / "audit.jsonl").write_text('{"a": 1}\n{"b": 2}\n')
        cli._keep_history(e, keep)
        self.assertEqual((keep / "audit.jsonl").read_text(), '{"a": 1}\n{"b": 2}\n')      # appended, not repeated
        self.assertEqual(json.loads((keep / "inventory.json").read_text()), {"history": [1, 2]})
        self.assertEqual(len(list(keep.glob("inventory-*.json"))), 1)                      # the earlier one kept
        for f in keep.iterdir():
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600, f)

    def test_purge_copies_the_history_into_the_undo_backup_and_marks_the_workdir(self):
        e = self.env("aws")
        (e.dir / "inventory.json").write_text('{"history": []}')
        (e.dir / "logs").mkdir(exist_ok=True)
        (e.dir / "logs" / "audit.jsonl").write_text('{"a": 1}\n')
        settings = {"current_env": e.id}
        with mock.patch.object(paths, "save_settings"):
            _, out = _capture(cli._purge_env_dir, e, settings, None)
        ub = Path(out.split("Configuration and SSH keys kept for `cs undo` in ")[1].split()[0])
        self.addCleanup(shutil.rmtree, ub, True)
        self.assertTrue((ub / "inventory.json").is_file())
        self.assertTrue((ub / "logs" / "audit.jsonl").is_file())
        keep = paths.HOME / "logs" / "purged" / e.id
        self.assertEqual(stat.S_IMODE(keep.stat().st_mode), 0o700)
        self.assertNotIn("current_env", settings)


# ---------------------------------------------------------------- status, inventory, output, update-ip

class ReportTests(_Envs):
    def test_utc_times(self):
        self.assertEqual(cli._utc_time("2026-09-24T10:11:12Z"), "2026-09-24 10:11:12 UTC")
        self.assertEqual(cli._utc_time("2026-09-24T10:11:12+00:00"), "2026-09-24 10:11:12 UTC")
        self.assertEqual(cli._utc_time("now"), "now")

    def test_status_last_change_skips_notes(self):
        e = self.env("aws")
        inv = audit.load(e)
        inv["history"] = [{"at": "2026-01-01T00:00:00Z", "action": "apply", "resources": 3, "by_type": {}},
                          {"at": "2026-01-02T00:00:00Z", "action": "finops-report"}]
        audit.save(e, inv)
        life.FakeTF.reset(state=["module.stack.aws_vpc.this"])
        with mock.patch.object(cli, "Terraform", life.FakeTF), mock.patch.object(cli, "_render", lambda *a, **k: False):
            rc, out = _capture(cli.cmd_status, cli.build_parser().parse_args(["status", "aws", "--env", e.name]), {})
        row = next(ln for ln in _plain(out).splitlines() if "Last change" in ln)
        self.assertIn("apply", row)
        self.assertIn("2026-01-01 00:00:00 UTC", row)
        self.assertNotIn("finops", row)

    def test_inventory_refuses_a_last_below_one(self):
        rc, out = _capture(cli.cmd_inventory, SimpleNamespace(cloud="aws", env="x", last=0, json=False), {})
        self.assertEqual(rc, 2)
        self.assertIn("--last 0", out)

    def test_state_errors_name_the_working_directory(self):
        t = SimpleNamespace(workdir=Path("/w/envs/aws-t3/stack"),
                            run=lambda *a, **k: subprocess.CompletedProcess([], 1, "", "Error acquiring the state lock\nLock Info:\n  ID: 1\n"))
        with mock.patch("cloudseed.tf.explain", return_value="x") as explain:
            with self.assertRaises(cli.TerraformError):
                cli._state_addresses(t)
        self.assertEqual(explain.call_args[0][2], Path("/w/envs/aws-t3/stack"))

    def test_update_ip_lifts_a_fail2ban_ban_on_the_new_address(self):
        e = self.env("aws", provisioned={"bastion": {"at": "t"}, "vpn": {"at": "t"}})
        ran = []
        host = SimpleNamespace(label="bastion", ssh=lambda cmd: ["ssh", "bastion", cmd])

        def run(argv, **k):
            ran.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.object(cli.subprocess, "run", run), \
                mock.patch.object(cli.prov, "Host", lambda *a, **k: SimpleNamespace(label="vpn", ssh=lambda cmd: ["ssh", "vpn", cmd])):
            _, out = _capture(cli._fail2ban_admit_new_ip, clouds.get("aws"), e, e.load(),
                              {"vpn_public_ip": "203.0.113.2"}, host, ["198.51.100.9/32"])
        self.assertEqual([r[1] for r in ran], ["bastion", "vpn"])
        self.assertIn("unbanip 198.51.100.9", ran[0][2])
        self.assertIn("addignoreip 198.51.100.9", ran[0][2])
        self.assertIn("cloudseed provision aws --env", out)
        ran.clear()
        with mock.patch.object(cli.subprocess, "run", run), mock.patch.object(cli.netutil, "detect_public_ip", return_value=None):
            cli._fail2ban_admit_new_ip(clouds.get("aws"), e, {}, {}, host, ["198.51.100.0/24"])
        self.assertEqual(ran, [])        # a range and no known address of this machine: nothing to lift


# ---------------------------------------------------------------- doctor

class DoctorTests(unittest.TestCase):
    def run_doctor(self, cloud, live, warnings=("No AWS credentials detected.",), rows=None):
        rows = rows or [{"tool": "terraform", "path": "/x", "required": True, "desc": "d", "version": "1.9", "outdated": False}]
        with mock.patch.object(deps, "status", return_value=rows), \
                mock.patch.object(deps, "live_credential_check", return_value=live), \
                mock.patch.object(type(clouds.get(cloud or "aws")), "credential_warnings", lambda self, cfg: list(warnings)):
            return _capture(cli.cmd_doctor, argparse.Namespace(cloud=cloud), {})

    def test_a_valid_login_hides_the_static_hint(self):
        rc, out = self.run_doctor("aws", (True, "AWS credentials valid"))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("No AWS credentials detected", out)
        self.assertNotIn("not ready", out)
        rc, out = self.run_doctor("aws", (False, "No AWS credentials found  ->  aws configure"))
        self.assertIn("No AWS credentials found", out)
        self.assertNotIn("No AWS credentials detected", out)     # the live check said it, with its fix: not twice
        self.assertIn("not ready: the credentials do not work.", out)
        rc, out = self.run_doctor("aws", None)
        self.assertIn("No AWS credentials detected", out)
        self.assertLess(out.index("No AWS credentials detected"), out.index("not ready"))

    def test_tools_no_cloud_needs_are_listed_once(self):
        rows = [{"tool": "terraform", "path": "/x", "required": True, "desc": "d", "version": "1", "outdated": False},
                {"tool": "helm", "path": None, "required": False, "desc": "Helm", "version": "", "outdated": False}]
        rc, out = self.run_doctor(None, (True, "ok"), warnings=(), rows=rows)
        self.assertEqual(out.count(" helm "), 1)
        self.assertIn("Common tools", out)


# ---------------------------------------------------------------- k8s kubeconfig

class KubeconfigTests(_Envs):
    def test_refused_request_leaves_no_backup_and_a_merge_records_what_it_changed(self):
        e = self.env("aws")
        kube = Path(tempfile.mkdtemp(prefix="cs-w4-kube-")) / "config"
        self.addCleanup(shutil.rmtree, kube.parent, True)
        kube.write_text("old")
        args = cli.build_parser().parse_args(["k8s", "kubeconfig", "aws", "--env", e.name])
        with mock.patch.object(services, "home_kubeconfig", return_value=kube), \
                mock.patch.object(cli, "_outputs_fresh", return_value={"kubernetes_cluster_name": "c"}), \
                mock.patch.object(services, "ensure_kubeconfig", side_effect=ui.Abort("no cluster yet")), \
                mock.patch.object(undo, "backup_file", side_effect=AssertionError("backed up")):
            rc, out = _capture(cli.cmd_k8s, args, {})
        self.assertEqual(rc, 1)
        views = [{"contexts": [{"name": "mine", "context": {}}], "current-context": "mine"},
                 {"contexts": [{"name": "mine", "context": {}}, {"name": "c", "context": {"cluster": "c"}}],
                  "current-context": "c"}]

        def merge(*a):
            kube.write_text("new")
            return 0
        with mock.patch.object(services, "home_kubeconfig", return_value=kube), \
                mock.patch.object(cli, "_outputs_fresh", return_value={"kubernetes_cluster_name": "c"}), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=kube), \
                mock.patch.object(services, "kubeconfig", merge), mock.patch.object(cli, "_record_merged_kubeconfig"), \
                mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"), \
                mock.patch.object(cli, "_kubeconfig_raw", side_effect=views):
            rc, out = _capture(cli.cmd_k8s, args, {})
        self.assertEqual(rc, 0, out)
        entry = undo.latest(e.id)
        self.assertEqual(entry["data"]["kubeconfig"], {"names": {"contexts": ["c"], "clusters": [], "users": []},
                                                       "prev_current": "mine", "set_current": "c"})
        # a second merge (coalesced into the same undo slot) that also rewrote the cluster entry: the slot keeps the
        # oldest copy and state, and now names what either merge changed
        views2 = [views[1], dict(views[1], clusters=[{"name": "c", "cluster": {"server": "https://new"}}])]

        def merge2(*a):
            kube.write_text("newer")
            return 0
        with mock.patch.object(services, "home_kubeconfig", return_value=kube), \
                mock.patch.object(cli, "_outputs_fresh", return_value={"kubernetes_cluster_name": "c"}), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=kube), \
                mock.patch.object(services, "kubeconfig", merge2), mock.patch.object(cli, "_record_merged_kubeconfig"), \
                mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"), \
                mock.patch.object(cli, "_kubeconfig_raw", side_effect=views2):
            rc, out = _capture(cli.cmd_k8s, args, {})
        self.assertEqual(rc, 0, out)
        again = undo.latest(e.id)
        self.assertEqual(again["id"], entry["id"])
        self.assertEqual(again["data"]["files"], entry["data"]["files"])
        self.assertEqual(again["data"]["kubeconfig"], {"names": {"contexts": ["c"], "clusters": ["c"], "users": []},
                                                       "prev_current": "mine", "set_current": "c"})
        undo._discard_backups(again)


# ---------------------------------------------------------------- parser

class EnvPickTests(unittest.TestCase):
    def test_examples_repeat_the_subcommand(self):
        envs = [paths.Env("vmware", "v1"), paths.Env("vmware", "v2")]
        with mock.patch.object(paths.Env, "list_all", return_value=envs), \
                mock.patch.object(paths, "load_settings", return_value={}), \
                mock.patch.object(ui, "interactive", return_value=False):
            for ns, typed in ((argparse.Namespace(cmd="vpn", vpn_cmd="status"), "cloudseed vpn status vmware --env v1"),
                              (argparse.Namespace(cmd="k8s", k8s_cmd="info"), "cloudseed k8s info vmware --env v1"),
                              (argparse.Namespace(cmd="status"), "cloudseed status vmware --env v1")):
                with self.assertRaises(ui.Abort) as cm:
                    cli._pick_env_name(ns, clouds.get("vmware"))
                self.assertIn(typed, cm.exception.msg)
            msg = cli._missing_env(argparse.Namespace(cmd="vpn", vpn_cmd="users"), clouds.get("aws"), "v1").msg
            self.assertIn("cloudseed vpn users vmware --env v1", msg)


class ParserTests(unittest.TestCase):
    # (the corrected command lines and help-topic hints of _Parser.error / _unknown_command are cli-tools' change:
    # tests/test_wave4_cli_tools.py)
    def test_ssh_options_before_the_environment_id(self):
        envs = [paths.Env("aws", "f1")]
        with mock.patch.object(paths.Env, "list_all", return_value=envs), \
                mock.patch.object(paths, "load_settings", return_value={}), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli._default_env_argv(["ssh", "-L", "8080:x:80", "aws-f1"]),
                             ["ssh", "aws", "--env", "f1", "-L", "8080:x:80"])
            self.assertEqual(cli._default_env_argv(["ssh", "-p2222", "aws-f1", "uptime"]),
                             ["ssh", "aws", "--env", "f1", "-p2222", "uptime"])
            self.assertEqual(cli._default_env_argv(["ssh", "-o", "BatchMode=yes", "aws", "--env", "f1"]),
                             ["ssh", "aws", "-o", "BatchMode=yes", "--env", "f1"])
            self.assertEqual(cli._default_env_argv(["ssh", "--env", "f1", "aws"]), ["ssh", "--env", "f1", "aws"])
        self.assertEqual(cli._ssh_option_width("-L"), 2)
        self.assertEqual(cli._ssh_option_width("-p2222"), 1)
        self.assertEqual(cli._ssh_option_width("-N"), 1)


if __name__ == "__main__":
    unittest.main()
