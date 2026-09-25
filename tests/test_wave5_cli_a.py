"""Regression tests for the final cli-a pass: the platform mode/flag/list wiring, Cloud.unused in setup, the per-
environment lock of the changing commands, provisioning re-run commands, doctor/mcp/ui notes, vpn users, the purge
undo of a custom working directory, dr/chaos/scan undo points, and wrapped messages. Stdlib only; Terraform, helm,
kubectl, ssh and the clouds are faked - nothing touches a cloud, a hypervisor or the network."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloudseed import cli, clouds, dr, mcp, paths, platform as platformmod, provision as prov, scan, services, skills, ui, undo, webui  # noqa: E402,F401

import test_fix_cli_life as life  # noqa: E402  (FakeTF / LifeBase: a fake Terraform and an isolated environment)


def run_quiet(fn, *a, **kw):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            res = fn(*a, **kw)
        except SystemExit as e:
            if isinstance(e, ui.Abort):
                ui.show_abort(e)
            res = e.code
    return res, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def held_elsewhere(env: paths.Env, action: str = "apply aws --env other"):
    """env's lock, held by another thread for the duration (like another cloudseed run)."""
    ready, release = threading.Event(), threading.Event()

    def hold():
        with env.lock(action):
            ready.set()
            release.wait(20)
    t = threading.Thread(target=hold, daemon=True)
    t.start()
    assert ready.wait(10)
    try:
        yield
    finally:
        release.set()
        t.join(10)


# ---------------------------------------------------------------- platform: --set mode, plan warnings, list

class PlatformWiringTests(unittest.TestCase):
    def pargs(self, argv):
        return cli.build_parser().parse_args(["platform", *argv])

    def plan_options(self, argv):
        seen = {}
        real = platformmod.plan

        def plan(items, ctx, releases=None, force=False):
            seen["mode"] = ctx.options.get("mode")
            return real(items, ctx, releases=releases, force=force)
        with mock.patch.object(platformmod, "plan", side_effect=plan):
            rc, out, err = run_quiet(cli.cmd_platform, self.pargs(argv), {})
        return rc, out, err, seen

    def test_the_old_cli_copies_are_gone(self):
        self.assertFalse(hasattr(cli, "_target_flag_warnings"))    # platform.target_flag_warnings is the one copy
        # the mesh mode is platform.split_mode's: validated only with a meta item (istio) in the request
        with mock.patch.object(platformmod, "split_mode", return_value=("sidecar", [])) as split:
            self.assertEqual(cli._platform_mode(["istio"], ["mode=sidecar"]), "sidecar")
        split.assert_called_once_with(["istio"], ["mode=sidecar"])

    def test_mode_is_a_chart_value_without_istio(self):
        # MinIO's chart has a top-level `mode`: the CLI must not refuse it as an unknown mesh mode
        rc, out, err, seen = self.plan_options(["plan", "minio", "vmware", "--set", "mode=distributed"])
        self.assertEqual(rc, 0, err)
        self.assertNotIn("Unknown mode", err)
        self.assertIsNone(seen.get("mode"))
        # a mesh word on an item without istio is a chart value too: it never picks the mesh mode
        rc, out, err, seen = self.plan_options(["plan", "keda", "vmware", "--set", "mode=sidecar"])
        self.assertEqual(rc, 0, err)
        self.assertIsNone(seen.get("mode"))

    def test_mode_with_istio_is_the_mesh_mode_and_is_checked(self):
        rc, out, err, seen = self.plan_options(["plan", "istio", "vmware", "--set", "mode=sidecar"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(seen.get("mode"), "sidecar")
        rc, _, err, _ = self.plan_options(["plan", "security", "vmware", "--set", "mode=sidcar"])
        self.assertIn("Unknown mode 'sidcar'", err)

    def test_plan_warns_with_platforms_wording(self):
        rc, out, err = run_quiet(cli.cmd_platform, self.pargs(["plan", "kubeflow-trainer", "vmware", "--set", "foo=bar"]), {})
        self.assertEqual(rc, 0, err)
        self.assertIn("is not a Helm chart", err)
        self.assertNotIn("only --set mode=... is used by it", err)   # a manifest item takes no mode either
        self.assertIn("applied from manifests", err)

    def test_list_reads_the_releases_once_and_hands_them_over(self):
        env = paths.Env("vmware", life._uid("pl"))
        ctx = platformmod.Cluster(clouds.get("vmware"), env, {"vars": {}}, {}, Path("/nonexistent/kc"))
        rels = {"keda/keda": {"status": "deployed", "chart": "keda-2.0"}}
        with mock.patch.object(cli, "_catalog_ctx", return_value=(ctx, None)), \
                mock.patch.object(platformmod, "installed_releases", return_value=rels) as listed, \
                mock.patch.object(platformmod, "status") as status:
            rc, out, err = run_quiet(cli.cmd_platform, self.pargs(["list"]), {})
        self.assertEqual(rc, 0, err)
        self.assertEqual(listed.call_count, 1)
        status.assert_called_once_with(ctx, charts=False, unknown=False, releases=rels)
        self.assertNotIn("Install state unknown", err)


# ---------------------------------------------------------------- setup: settings of a feature that is off

class UnusedSettingTests(unittest.TestCase):
    def test_a_declared_depends_on_is_a_feature_off(self):
        aws = clouds.get("aws")
        q = aws.question("bastion_instance_type")
        with mock.patch.object(q, "depends_on", "enable_vpn"):
            self.assertTrue(cli._feature_off({"cloud": "aws", "vars": {}}, "bastion_instance_type"))
            self.assertFalse(cli._feature_off({"cloud": "aws", "vars": {"enable_vpn": "true"}}, "bastion_instance_type"))
        self.assertFalse(cli._feature_off({"cloud": "aws", "vars": {}}, "bastion_instance_type"))

    def test_outputs_keep_the_prefix_rule(self):
        self.assertTrue(cli._feature_off({"cloud": "gcp", "vars": {}}, "vpn_public_ip"))
        self.assertTrue(cli._feature_off({"cloud": "gcp", "vars": {"enable_kubernetes": "no"}}, "kubernetes_cluster_name"))
        self.assertFalse(cli._feature_off({"cloud": "gcp", "vars": {"enable_kubernetes": True}}, "kubernetes_cluster_name"))
        self.assertTrue(cli._feature_off({"vars": {}}, "vpn_type"))            # no cloud recorded: the old rule

    def test_an_invalid_saved_value_of_an_unused_setting_is_healed(self):
        gcp = clouds.get("gcp")
        env = paths.Env("gcp", "un1")
        cfg = {"cloud": "gcp", "vars": {"kubernetes_node_count": "abc"}}      # enable_kubernetes never answered: off
        rc, _, err = run_quiet(cli._check_answers, gcp, env, cfg)
        self.assertIn("it is not in use", err)
        self.assertNotIn("abc", str(cfg["vars"]["kubernetes_node_count"]))
        cfg = {"cloud": "gcp", "vars": {"enable_kubernetes": True, "kubernetes_node_count": "abc"}}
        rc, _, err = run_quiet(cli._check_answers, gcp, env, cfg)
        self.assertIn("is invalid", err)
        self.assertIn("kubernetes_node_count", err)

    def test_a_declared_depends_on_heals_an_invalid_saved_value(self):
        aws = clouds.get("aws")
        env = paths.Env("aws", "un2")
        q = aws.question("az_count")
        with mock.patch.object(q, "depends_on", "enable_vpn"):
            cfg = {"cloud": "aws", "vars": {"enable_vpn": "no", "az_count": "abc"}}
            rc, _, err = run_quiet(cli._check_answers, aws, env, cfg)
            self.assertIn("it is not in use", err)
            self.assertEqual(cfg["vars"]["az_count"], q.stock_default(cfg))
            cfg = {"cloud": "aws", "vars": {"enable_vpn": "yes", "az_count": "abc"}}
            rc, _, err = run_quiet(cli._check_answers, aws, env, cfg)
            self.assertIn("is invalid", err)
            self.assertIn("Fix it with", err)

    def test_network_rules_read_enable_kubernetes_strictly(self):
        azure = clouds.get("azure")
        cfg = {"cloud": "azure", "network_cidr": "10.244.0.0/16", "vars": {"enable_kubernetes": "false"}, "extra_vars": {}}
        self.assertFalse(any("reserves" in p for p in cli._network_problems(azure, cfg)))
        cfg["vars"]["enable_kubernetes"] = "true"
        self.assertTrue(any("reserves" in p for p in cli._network_problems(azure, cfg)))


# ---------------------------------------------------------------- the per-environment lock of changing commands

class EnvLockTests(life.LifeBase):
    def test_plan_holds_the_lock_and_releases_it(self):
        seen = {}

        def render(cloud, env, cfg):
            seen.update(env.lock_holder())
            return False
        with mock.patch.object(cli, "_render", side_effect=render), cli._env_lock_scope():
            rc = self.run_cmd(cli.cmd_plan, ["plan", "aws", "--env", self.env_name])
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertEqual(seen.get("action"), f"plan aws --env {self.env_name}")
        self.assertEqual(seen.get("pid"), os.getpid())
        self.assertEqual(self.env.lock_holder(), {})          # released with the command
        with self.env.lock("next"):
            pass

    def test_a_second_run_on_the_same_environment_is_refused(self):
        for argv, fn in ((["plan", "aws", "--env", self.env_name], cli.cmd_plan),
                         (["apply", "aws", "--env", self.env_name, "--auto-approve"], cli.cmd_apply),
                         (["destroy", "aws", "--env", self.env_name, "-y", "--auto-approve"], cli.cmd_destroy),
                         (["update-ip", "aws", "--env", self.env_name, "--allow-ip", "198.51.100.9"], cli.cmd_update_ip),
                         (["provision", "aws", "--env", self.env_name], cli.cmd_provision)):
            life.FakeTF.reset()
            self.out = io.StringIO()
            with held_elsewhere(self.env), cli._env_lock_scope():
                rc = self.run_cmd(fn, argv)
            self.assertNotEqual(rc, 0, argv)
            self.assertIn(f"{self.env.id} is busy", self.out.getvalue(), argv)
            self.assertIn("apply aws --env other", self.out.getvalue(), argv)
            self.assertEqual(life.FakeTF.calls, [], argv)       # stopped before Terraform ran

    def test_setup_is_refused_before_anything_is_written(self):
        env = paths.Env("aws", life._uid("lk"))
        with held_elsewhere(env), cli._env_lock_scope():
            rc = self.run_cmd(cli.cmd_setup, ["setup", "aws", "-y", "--env", env.name, "--allow-ip", "198.51.100.9",
                                              "--dry-run"])
        self.assertNotEqual(rc, 0)
        self.assertIn("is busy", self.out.getvalue())
        self.assertFalse(env.exists())

    def test_undo_waits_its_turn_and_keeps_the_entry(self):
        undo.record(self.env.id, "vpn add-user bob", "vpn-revoke", {"name": "bob"})
        with held_elsewhere(self.env), cli._env_lock_scope():
            rc = self.run_cmd(cli.cmd_undo, ["undo", "aws", "--env", self.env_name, "--auto-approve"])
        self.assertNotEqual(rc, 0)
        self.assertIn("is busy", self.out.getvalue())
        self.assertEqual([e["summary"] for e in undo.entries(self.env.id)], ["vpn add-user bob"])
        undo.clear(self.env.id)

    def test_busy_is_reported_without_the_commands_examples(self):
        with held_elsewhere(self.env), mock.patch.object(sys, "stdin", io.StringIO()):
            rc, out, err = run_quiet(cli._dispatch, ["plan", "aws", "--env", self.env_name])
        self.assertEqual(rc, 1, out + err)
        self.assertIn(f"{self.env.id} is busy", err)
        self.assertNotIn("Examples for", err)
        self.assertEqual(self.env.lock_holder(), {})

    def test_read_only_commands_and_direct_calls_take_no_lock(self):
        with held_elsewhere(self.env), cli._env_lock_scope():
            rc = self.run_cmd(cli.cmd_output, ["output", "aws", "--env", self.env_name])
        self.assertNotIn("is busy", self.out.getvalue())
        with held_elsewhere(self.env):                        # outside a dispatched command nothing is locked
            rc = self.run_cmd(cli.cmd_plan, ["plan", "aws", "--env", self.env_name])
        self.assertEqual(rc, 0, self.out.getvalue())


# ---------------------------------------------------------------- provisioning: re-run commands keep the flags

class ProvisionRerunTests(life.LifeBase):
    def setUp(self):
        super().setUp()
        (self.env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "192.0.2.10", "vpn_public_ip": "192.0.2.11"}))

    def provision_all(self, **kw):
        calls = []
        with mock.patch.object(prov, "provision", side_effect=lambda *a, **k: calls.append(k)):
            run_quiet(cli._provision_all, clouds.get("aws"), self.env, self.env.load(), **kw)
        return calls

    def test_bastion_only_rerun_is_the_bastion_with_the_same_flags(self):
        calls = self.provision_all(harden=False, only="bastion")
        self.assertEqual(calls[0]["rerun"], f"cloudseed provision aws --env {self.env_name} --host bastion --no-harden")

    def test_whole_environment_reruns(self):
        calls = self.provision_all(harden=False, firewall=False)
        self.assertEqual(calls[0]["rerun"], f"cloudseed provision aws --env {self.env_name} --no-harden --no-firewall")
        self.assertEqual(calls[1]["label"], "vpn")
        self.assertEqual(calls[1]["rerun"], f"cloudseed provision aws --env {self.env_name} --host vpn --no-harden --no-firewall")

    def test_fips_waits_and_token_hints_name_the_same_rerun(self):
        cfg = self.env.load()
        cfg["vars"]["fips_mode"] = True
        self.env.save(cfg)
        vpn = f"cloudseed provision aws --env {self.env_name} --host vpn --no-harden"
        waits, verified = [], []
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": "tok"}), \
                mock.patch.object(prov.Host, "wait", lambda h, timeout=420, retry=None: waits.append(retry)), \
                mock.patch.object(prov.Host, "put_json", lambda *a: None), \
                mock.patch.object(cli, "_verify_fips", lambda host, rerun=None: verified.append(rerun)):
            calls = self.provision_all(harden=False, only="vpn")
        self.assertEqual(waits, [f"then re-run `{vpn}`."])
        self.assertEqual(verified, [vpn])
        self.assertEqual(calls[0]["rerun"], vpn)
        env = {k: v for k, v in os.environ.items() if k != "UBUNTU_PRO_TOKEN"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(prov, "provision"):
            rc, _, err = run_quiet(cli._provision_all, clouds.get("aws"), self.env, self.env.load(), harden=False, only="vpn")
        self.assertIn(f"then re-run: {vpn}", err)

    def test_saved_harden_is_provisions(self):
        self.assertIs(cli._saved_harden, prov.saved_harden)


class ProvisionUpdatesTests(unittest.TestCase):
    def run_provision(self, cloud_key: str, harden: bool) -> dict:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        env = paths.Env(cloud_key, "au", Path(td.name) / "w")
        env.create_dirs()
        cfg = {"name": "cs", "env": "au", "network_cidr": "10.20.0.0/24", "allowed_ssh_cidrs": ["203.0.113.4/32"],
               "vars": {"ssh_username": "me"}, "ssh_private_key_path": str(Path(td.name) / "key")}
        put = {}
        patches = [mock.patch.object(prov.Host, "wait"), mock.patch.object(prov.Host, "wait_cloud_init"),
                   mock.patch.object(prov.Host, "sync_repo"), mock.patch.object(prov.Host, "put_json", lambda s, p, d: put.update({p: d})),
                   mock.patch.object(prov.Host, "run", lambda s, cmd, env=None: 0), mock.patch.object(prov.Host, "remove_secrets"),
                   mock.patch.object(prov.audit, "note")]
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            run_quiet(prov.provision, clouds.get(cloud_key), env, cfg, {"bastion_public_ip": "198.51.100.9"}, harden=harden)
        return put["~/cloudseed-vars.json"]

    def test_vmware_vms_keep_automatic_updates_without_hardening(self):
        # the VMware template switched the apt timers off at first boot: only this role switches them on again
        self.assertTrue(self.run_provision("vmware", harden=False)["auto_updates"])
        self.assertFalse(self.run_provision("vmware", harden=False)["harden"])
        self.assertFalse(self.run_provision("aws", harden=False)["auto_updates"])   # cloud images: left as they ship
        self.assertTrue(self.run_provision("aws", harden=True)["auto_updates"])


# ---------------------------------------------------------------- vpn users, doctor, mcp status, ui login item

class SmallWiringTests(life.LifeBase):
    def test_vpn_users_is_the_services_report(self):
        with mock.patch.object(cli, "_outputs_fresh", return_value={"vpn_public_ip": "192.0.2.11"}), \
                mock.patch.object(services, "users_report", return_value=0) as report, \
                mock.patch.object(services, "list_users", side_effect=AssertionError("second SSH call")):
            rc = self.run_cmd(cli.cmd_vpn, ["vpn", "users", "aws", "--env", self.env_name])
        self.assertEqual(rc, 0)
        cloud, env, cfg, outputs = report.call_args[0]
        self.assertEqual((cloud.key, env.id, outputs), ("aws", self.env.id, {"vpn_public_ip": "192.0.2.11"}))

    def test_doctor_notes_leftover_services_and_a_missing_engine(self):
        with mock.patch.object(webui, "leftover_service", return_value="a login item is still installed although the console is "
                               "disabled: /x/io.cloudseed.ui.plist  (remove it: cs disable ui)"), \
                mock.patch.object(mcp, "load_state", return_value={"transport": "stdio"}), \
                mock.patch.object(mcp, "leftover_services", return_value=["/x/io.cloudseed.mcp.plist"]), \
                mock.patch.object(mcp, "outdated_service", return_value=None), \
                mock.patch.object(cli.container, "available_engines", return_value=["docker"]):
            notes = cli._doctor_machine_notes({"engine": "podman", "runtime": "container"})
        text = "\n".join(notes)
        self.assertIn("Web console: a login item is still installed", text)
        self.assertIn("/x/io.cloudseed.mcp.plist", text)
        self.assertIn("cs setup mcp --transport stdio", text)
        self.assertIn("podman is not installed", text)
        self.assertIn("cloudseed deps runtime container --engine docker", text)
        with mock.patch.object(webui, "leftover_service", return_value=None), \
                mock.patch.object(mcp, "load_state", return_value={"transport": "http", "service": "launchd"}), \
                mock.patch.object(mcp, "leftover_services", return_value=[]), \
                mock.patch.object(mcp, "outdated_service", return_value="/x.plist runs the server as ProcessType Background"), \
                mock.patch.object(cli.container, "available_engines", return_value=["docker"]):
            notes = cli._doctor_machine_notes({"engine": "docker"})
        self.assertEqual(notes, ["MCP server: /x.plist runs the server as ProcessType Background  (cs mcp restart rewrites it)"])

    def test_doctor_prints_the_notes(self):
        with mock.patch.object(cli, "_doctor_machine_notes", return_value=["Web console: leftover"]), \
                mock.patch.object(cli.deps, "status", return_value=[]), \
                mock.patch.object(cli.deps, "live_credential_check", return_value=(True, "login valid")):
            self.run_cmd(cli.cmd_doctor, ["doctor", "aws"])
        self.assertIn("Web console: leftover", self.out.getvalue())

    def test_mcp_status_flags_an_outdated_service(self):
        state = {"transport": "http", "service": "launchd", "host": "127.0.0.1", "port": 7502, "auth": "token"}
        with mock.patch.object(mcp, "load_state", return_value=state), mock.patch.object(mcp, "health", return_value=None), \
                mock.patch.object(cli, "_mcp_health_info", return_value=None), mock.patch.object(mcp, "running_pid", return_value=None), \
                mock.patch.object(mcp, "leftover_services", return_value=[]), \
                mock.patch.object(mcp, "outdated_service", return_value="/x.plist runs the server as ProcessType Background"), \
                mock.patch.dict(mcp.CLIENTS, {}, clear=True):
            rc, out, err = run_quiet(cli._mcp_status, {"mcp": True})
        self.assertEqual(rc, 0, err)
        self.assertIn("Outdated", out)
        self.assertIn("ProcessType Background", out)
        self.assertIn("cs mcp restart rewrites it", out)

    def test_ui_login_item_is_webuis(self):
        with mock.patch.object(webui, "login_item", return_value="systemd"):
            self.assertEqual(cli._ui_login_item(), "systemd")


# ---------------------------------------------------------------- destroy --purge of a never-deployed custom workdir

class PurgeUndoTests(life.LifeBase):
    def test_custom_workdir_purge_is_undone_by_putting_the_files_back(self):
        root = Path(tempfile.mkdtemp(prefix="cs-w5purge-"))
        wd = root / "proj"
        name = life._uid("pw")                                 # an environment that only ever lived in `wd`
        env = paths.Env(self.cloud, name)
        env.set_workdir(wd)
        cfg = dict(self.cfg, env=name)
        env.save(cfg)
        (env.ssh_dir / "id_ed25519").write_text("PRIVATE KEY")
        life.FakeTF.reset(state=[])                            # nothing was ever deployed
        settings = {"current_env": env.id}
        with mock.patch.object(paths, "save_settings"):
            rc = self.run_cmd(cli.cmd_destroy, ["destroy", self.cloud, "--env", name, "-y", "--auto-approve", "--purge"], settings)
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertFalse((wd / "config.json").exists())
        self.assertNotIn(env.id, paths._load_index())
        entry = undo.latest(env.id)
        self.assertEqual(entry["kind"], "restore-files")      # not an 'info' entry that orphans the copy
        self.assertEqual(entry["data"]["workdir"], str(wd.resolve()))
        self.assertEqual(entry["data"]["current_env"], env.id)
        self.assertIn(str(env.ssh_dir), entry["data"]["files"])
        rc, out, err = run_quiet(undo.perform, entry, {}, True)
        self.assertIn(rc, (0, None), out + err)
        self.assertEqual(json.loads((wd / "config.json").read_text())["env"], name)
        self.assertEqual((wd / "ssh" / "id_ed25519").read_text(), "PRIVATE KEY")
        self.assertEqual(Path(paths._load_index()[env.id]).resolve(), wd.resolve())   # registered again
        index = paths._load_index()
        index.pop(env.id, None)
        paths._save_index(index)
        undo.clear(env.id)


# ---------------------------------------------------------------- undo header, help, parser

class UndoAndParserTests(unittest.TestCase):
    def test_undo_header_is_utc(self):
        undo.record("gcp-w5hdr", "some change", "info", {"advice": "nothing to do"})
        ns = cli.build_parser().parse_args(["undo", "gcp", "--env", "w5hdr", "--auto-approve"])
        rc, out, err = run_quiet(cli.cmd_undo, ns, {})
        header = next(ln for ln in out.splitlines() if "Undo: some change" in ln)
        self.assertRegex(header, r"\(\d{4}-\d\d-\d\d \d\d:\d\d UTC\)")
        undo.clear("gcp-w5hdr")

    def test_undo_help_names_the_real_history_size(self):
        sub = next(a for a in cli.build_parser()._actions if isinstance(a, argparse._SubParsersAction))
        text = next(ca.help for ca in sub._choices_actions if ca.dest == "undo")
        self.assertNotIn("five", text)
        self.assertIn(f"the last {undo.KEEP_TOTAL} changes per environment and globally, at most {undo.KEEP} of one kind", text)

    def test_setup_preview_and_provision_flags(self):
        ns = cli.build_parser().parse_args(["setup", "aws", "--preview"])
        self.assertTrue(ns.preview)
        self.assertFalse(cli.build_parser().parse_args(["setup", "aws"]).preview)
        self.assertFalse(cli.build_parser().parse_args(["provision", "aws"]).no_harden)
        sub = next(a for a in cli.build_parser()._actions if isinstance(a, argparse._SubParsersAction))
        for cmd in ("setup", "provision"):
            opts = {o: a.help for a in sub.choices[cmd]._actions for o in a.option_strings}
            self.assertIn("automatic updates are left as they are", opts["--no-harden"], cmd)
            self.assertIn("VPN/NAT hosts keep their NAT rule", opts["--no-firewall"], cmd)
            self.assertNotIn("skip OS hardening", opts["--no-harden"], cmd)

    def test_dr_ttl_uses_drs_rule(self):
        a = argparse.Namespace(dr_cmd="schedule", name="nightly", namespaces=None, cron="@daily", ttl="7d")
        run_quiet(cli._check_dr_args, a)
        self.assertEqual(a.ttl, "168h")
        rc, _, err = run_quiet(cli._check_dr_args, argparse.Namespace(dr_cmd="schedule", name="n", namespaces=None,
                                                                      cron="@daily", ttl="forever"))
        self.assertEqual(rc, 2)
        self.assertIn("not a duration", err)
        self.assertIs(cli._GO_DURATION, dr.GO_DURATION)


# ---------------------------------------------------------------- dr test --keep, chaos run, scan: exact undo points

class UndoPointTests(life.LifeBase):
    def run_dr_test_keep(self, drill):
        """`cs dr test --keep` with dr.test faked: it names what it left on the context (ctx.dr_drill), as the real
        one does once its report is saved (None: it stopped before that)."""
        ctx = SimpleNamespace(env=self.env)

        def fake_test(c, keep=False, with_volume=None):
            if drill is not None:
                c.dr_drill = drill
            return 0
        a = cli.build_parser().parse_args(["dr", "test", "--keep", "aws", "--env", self.env_name])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("aws"), self.env, self.env.load(), {})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=self.env.dir / "kc"), \
                mock.patch.object(platformmod, "Cluster", return_value=ctx), mock.patch.object(dr, "installed", return_value=True), \
                mock.patch.object(dr, "test", side_effect=fake_test):
            rc, out, err = run_quiet(cli.cmd_dr, a, {})
        self.assertEqual(rc, 0, out + err)
        entry = undo.latest(self.env.id)
        undo.clear(self.env.id)
        return entry

    @staticmethod
    def drill_kind_known() -> bool:
        return undo.describe({"kind": "dr-drill", "scope": "", "data": {"namespace": dr.DRILL_NS, "backup": None}}) != "dr-drill"

    def test_kept_drill_records_namespace_and_backup_when_undo_knows_the_kind(self):
        drill = {"namespace": dr.DRILL_NS, "backup": "dr-test-20260924", "kept": True, "report": "/x.json"}
        real = undo.describe
        with mock.patch.object(undo, "describe", lambda e: "delete the drill" if e.get("kind") == "dr-drill" else real(e)):
            entry = self.run_dr_test_keep(drill)
        self.assertEqual(entry["kind"], "dr-drill")
        self.assertEqual(entry["data"], {"namespace": dr.DRILL_NS, "backup": "dr-test-20260924"})
        self.assertIn("drill namespace and backup dr-test-20260924 kept", entry["summary"])   # names the backup (w5/ops-undo)
        self.assertTrue(entry["minor"])

    def test_kept_drill_without_a_known_kind_or_a_report_deletes_the_namespace(self):
        entry = self.run_dr_test_keep(None)                    # stopped before its report: the namespace only
        if entry["kind"] == "dr-drill":
            self.assertEqual(entry["data"], {"namespace": dr.DRILL_NS, "backup": None})
        else:
            self.assertEqual(entry["kind"], "argv-seq")
            self.assertEqual(entry["data"]["argvs"][0][-3:], ["ns", dr.DRILL_NS, "--ignore-not-found"])
        entry = self.run_dr_test_keep({"namespace": dr.DRILL_NS, "backup": "b1", "kept": True})
        if self.drill_kind_known():                            # this undo can delete the backup too
            self.assertEqual((entry["kind"], entry["data"]["backup"]), ("dr-drill", "b1"))
        else:                                                  # never an entry the undo cannot perform
            self.assertEqual(entry["kind"], "argv-seq")
            self.assertEqual(entry["data"]["argvs"][0][-3:], ["ns", dr.DRILL_NS, "--ignore-not-found"])

    def test_scan_that_fails_part_way_leaves_its_partial_outputs_undoable(self):
        made = {}

        def host(cloud, env, cfg, outputs, hosts, profile):
            made["dir"], _ = scan.claim_run_path(scan._reports_dir(env), "openscap-", "", scan.run_stamp(), directory=True)
            raise ui.Abort("ansible died")
        other = scan.claim_run_path(scan._reports_dir(self.env), "prowler-", "", "20200101-000000", directory=True)[0]
        with mock.patch.object(scan, "host", side_effect=host):
            rc = self.run_cmd(cli.cmd_scan, ["scan", "host", "aws", "--env", self.env_name])
        self.assertEqual(rc, 1)
        entry = undo.latest(self.env.id)
        self.assertEqual(entry["kind"], "delete-paths")
        self.assertEqual(entry["data"]["paths"], [str(made["dir"])])
        self.assertNotIn(str(other), entry["data"]["paths"])   # never a file this run did not create
        undo.clear(self.env.id)

    def test_chaos_run_takes_the_report_chaos_run_names(self):
        rep = self.env.dir / "chaos" / "report-20260924-000000.json"
        rep.parent.mkdir(parents=True, exist_ok=True)
        (rep.parent / "report-20260924-000001.json").write_text("{}")   # a parallel run's report
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "--cloud", "aws", "--env", self.env_name])

        def run(ctx, *a, **kw):   # a parallel run saves its report while this one runs (the old heuristic took none)
            (rep.parent / "report-20260924-000002.json").write_text("{}")
            rep.write_text("{}")
            ctx.chaos_report = rep
            return 0
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("aws"), self.env, self.env.load(), {})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=self.env.dir / "kc"), \
                mock.patch.object(cli, "_ensure_chaos_mesh"), mock.patch.object(cli.chaos, "run", side_effect=run):
            rc, _, err = run_quiet(cli.cmd_chaos, a, {})
        self.assertEqual(rc, 0, err)
        entry = undo.latest(self.env.id)
        self.assertEqual(entry["data"]["paths"], [str(rep), str(rep.with_suffix(".md"))])
        undo.clear(self.env.id)


# ---------------------------------------------------------------- skills list wording

class SkillListTests(unittest.TestCase):
    def test_skill_list_uses_state_text(self):
        with mock.patch.object(skills, "state_text", side_effect=lambda k: f"TEXT-{k}"):
            rc, out, err = run_quiet(cli.cmd_skill, argparse.Namespace(skill_cmd="list"), {})
        self.assertEqual(rc, 0, err)
        for key in ("claude", "codex", "gemini", "grok"):
            self.assertIn(f"TEXT-{key}", out)


# ---------------------------------------------------------------- messages at a terminal

class MessageWrapTests(unittest.TestCase):
    CMD = "cloudseed update-ip aws --env dev --allow-ip 10.0.0.0/8,198.51.100.7/32"

    def test_a_command_is_never_split(self):
        msg = ("Your public IP 198.51.100.7 is not in the SSH allow-list of aws-dev (10.0.0.0/8); the saved list is kept. "
               "To add it: " + self.CMD)
        lines = ui._wrap_message_lines(msg, 50)
        self.assertIn(self.CMD, lines)
        self.assertTrue(all(len(ln) <= 50 for ln in lines if ln != self.CMD), lines)
        self.assertEqual(" ".join(lines), msg)
        for msg in ("Nothing destroyed; re-run: cs destroy aws --env dev --auto-approve (the plan is above)",
                    "then re-run `cloudseed provision aws --env w4r --host bastion --no-harden`. The hardening stays off."):
            joined = "\n".join(ui._wrap_message_lines(msg, 30))
            cmd = "cs destroy aws --env dev --auto-approve" if "destroy" in msg else \
                "`cloudseed provision aws --env w4r --host bastion --no-harden`"
            self.assertTrue(any(ln.rstrip(".") == cmd for ln in joined.splitlines()), joined)

    def test_prose_mentions_of_a_tool_still_wrap(self):
        lines = ui._wrap_message_lines("the podman engine is not installed on this machine so container runs stop here", 30)
        self.assertTrue(all(len(ln) <= 30 for ln in lines), lines)

    def test_warn_wraps_with_a_hanging_indent_only_at_a_terminal(self):
        msg = "word " * 30 + "end"
        err = io.StringIO()
        with mock.patch.object(ui, "_isatty", return_value=True), mock.patch.object(ui, "cols", return_value=60), \
                mock.patch.object(ui, "_COLOR", False), contextlib.redirect_stderr(err):
            ui.warn(msg)
        rows = err.getvalue().rstrip("\n").split("\n")
        self.assertGreater(len(rows), 1)
        self.assertTrue(all(ui.vis_len(r) <= 59 for r in rows), rows)
        self.assertTrue(all(r.startswith("    ") for r in rows[1:]), rows)
        err = io.StringIO()
        with mock.patch.object(ui, "_isatty", return_value=False), contextlib.redirect_stderr(err):
            ui.warn(msg)
        self.assertEqual(err.getvalue().count("\n"), 1)                # piped: one line, greppable

    def test_list_items_hang_under_their_text(self):
        lines = ui._wrap_message_lines("Cannot deploy:\n  - " + "problem " * 12, 40)
        self.assertTrue(lines[2].startswith("    "), lines)

    def test_hints_fit_the_terminal_and_stay_whole_when_piped(self):
        parts = ["cs creds set AWS_PROFILE=prod", "cs creds set ANTHROPIC_API_KEY   (prompts, hidden)", "cs creds unset KEY"]
        out = io.StringIO()
        with mock.patch.object(ui, "stdout_is_tty", return_value=True), mock.patch.object(ui, "cols", return_value=60), \
                contextlib.redirect_stdout(out):
            ui.hints(parts)
        rows = [ui._strip(r) for r in out.getvalue().splitlines()]
        self.assertGreater(len(rows), 1)
        self.assertTrue(all(len(r) <= 59 for r in rows), rows)
        self.assertTrue(all(any(p in r for r in rows) for p in parts), rows)
        out = io.StringIO()
        with mock.patch.object(ui, "stdout_is_tty", return_value=False), contextlib.redirect_stdout(out):
            ui.hints(parts)
        self.assertEqual(ui._strip(out.getvalue()).strip(), "   ·   ".join(parts))


if __name__ == "__main__":
    unittest.main()
