"""Wave-3 regression tests for the setup / provision / lifecycle commands: environment resolution (<cloud> without --env,
env ids, typos, the current environment), --var shapes and hints, network and region checks, in-place guards (name,
project, subscription, zone), FIPS/Tailscale previews, no-op plans and undo slots, destroy gates (whole-environment
targets, account-wide warnings, state storage, --purge of a --workdir), clean --json output, doctor's verdict line, the
parser (flags after the task, ssh --help, mistyped options), agent skills next to a foreign directory and `ui start`.
Stdlib only; Terraform, ssh, kubectl and the hypervisor are faked - nothing touches a cloud or the network."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, cli, clouds, deps, paths, skills, ui, undo, webui  # noqa: E402

import test_fix_cli_life as life  # noqa: E402  (tests/ is on sys.path under unittest discovery)
import test_fix_cli_setup as setup_base  # noqa: E402

_n = [0]


def _uid(prefix: str) -> str:
    while True:
        _n[0] += 1
        name = f"{prefix}{life.RUN_ID}w{_n[0]}"
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


def _make_env(cloud: str, name: str, **extra) -> paths.Env:
    env = paths.Env(cloud, name)
    env.create_dirs()
    cfg = {"cloud": cloud, "env": name, "name": "cloudseed", "region": "local" if cloud == "vmware" else "us-east-1",
           "network_cidr": "10.30.0.0/16", "allowed_ssh_cidrs": ["198.51.100.7/32"], "state": {"type": "local", "backend": None},
           "vars": {}, "extra_vars": {}, "tags": {}, "ssh_public_key": "ssh-ed25519 AAAA test"}
    cfg.update(extra)
    env.save(cfg)
    return env


class _EnvCleanup(unittest.TestCase):
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
            index = paths._load_index()
            if index.pop(e.id, None):
                paths._save_index(index)
        log = audit._state.get("log")
        if log:
            log.close()
            audit._state.update(log=None, env=None)

    def make(self, cloud: str, name: str, **extra) -> paths.Env:
        env = _make_env(cloud, name, **extra)
        self.made.append(env)
        return env


# ---------------------------------------------------------------- <cloud> without --env, ids, typos

class LoadEnvResolutionTests(_EnvCleanup):
    def ns(self, cmd, cloud="aws", env=None, **kw):
        return argparse.Namespace(cmd=cmd, cloud=cloud, env=env, **kw)

    def only_cloud(self, *names):
        """Pretend the aws environments are exactly `names` (other test modules share the home)."""
        envs = [self.make("aws", n) for n in names]
        return mock.patch.object(paths.Env, "list_all", return_value=envs)

    def test_several_without_dev_are_listed_not_guessed(self):
        a, b = _uid("rc"), _uid("t")
        with self.only_cloud(a, b):
            rc, out = _capture(cli._load_env, self.ns("status"))
        self.assertEqual(rc, 2, out)
        self.assertIn(f"aws-{a}", out)
        self.assertIn(f"aws-{b}", out)
        self.assertNotIn("Create it with", out)
        self.assertNotIn("aws-dev does not exist", out)

    def test_dev_among_several_stays_the_default_and_says_so(self):
        other = _uid("nm")
        dev_existed = paths.Env("aws", "dev").exists()
        with self.only_cloud("dev", other) if not dev_existed else self.only_cloud(other):
            res, out = _capture(cli._load_env, self.ns("destroy"))
        if not dev_existed:
            self.assertEqual(res[1].name, "dev", out)
            self.assertIn(f"aws-{other}", out)          # the others are named, not silently ignored

    def test_the_current_env_wins_for_read_only_commands(self):
        a, b = _uid("cur"), _uid("oth")
        with self.only_cloud(a, b):
            paths.save_settings(dict(paths.load_settings(), current_env=f"aws-{b}"))
            res, out = _capture(cli._load_env, self.ns("status"))
            self.assertEqual(res[1].name, b, out)
            self.assertIn("the current environment", out)
            # a destroy never retargets at the current environment silently: it asks for --env instead
            rc, out = _capture(cli._load_env, self.ns("destroy"))
            self.assertEqual(rc, 2, out)
            self.assertIn(f"--env {b}", out)

    def test_an_env_id_is_accepted_as_a_fallback(self):
        name = _uid("idf")
        self.make("aws", name)
        res, out = _capture(cli._load_env, self.ns("status", env=f"aws-{name}"))
        self.assertEqual(res[1].id, f"aws-{name}", out)
        self.assertIn("is an environment id", out)

    def test_a_typo_lists_the_known_ones_without_inviting_setup(self):
        name = _uid("prod")
        self.make("aws", name)
        rc, out = _capture(cli._load_env, self.ns("destroy", env=name + "x"))
        self.assertEqual(rc, 1, out)
        self.assertIn("does not exist (nothing to destroy)", out)
        self.assertIn(f"Did you mean --env {name}", out)
        self.assertNotIn("Create it with", out)
        self.assertNotIn("cloudseed setup", out)

    def test_an_id_shaped_typo_is_matched_as_an_id(self):
        name = _uid("prod")
        self.make("aws", name)
        rc, out = _capture(cli._load_env, self.ns("status", env=f"aws-{name}x"))
        self.assertEqual(rc, 1, out)
        self.assertIn(f"Environment aws-{name}x does not exist", out)
        self.assertIn(f"Did you mean --env {name}", out)
        with mock.patch.object(paths.Env, "list_all", return_value=[]):
            rc, out = _capture(cli._load_env, self.ns("status", cloud="gcp", env="gcp-dev"))
        self.assertIn("cloudseed setup gcp --env dev", out)

    def test_no_env_of_that_cloud_suggests_setup(self):
        with mock.patch.object(paths.Env, "list_all", return_value=[]):
            rc, out = _capture(cli._load_env, self.ns("status", cloud="gcp", env="dev"))
        self.assertEqual(rc, 1)
        self.assertIn("cloudseed setup gcp --env dev", out)


class RequiredSettingsTests(_EnvCleanup):
    def test_missing_network_cidr_is_recovered_for_status_and_refused_for_apply(self):
        env = self.make("aws", _uid("keys"))
        cfg = env.load()
        cfg.pop("network_cidr")
        cfg.pop("allowed_ssh_cidrs")
        env.save(cfg)
        (env.dir / "outputs.json").write_text(json.dumps({"vpc_cidr": "10.77.0.0/16"}))
        res, out = _capture(cli._load_env, argparse.Namespace(cmd="status", cloud="aws", env=env.name))
        self.assertIsInstance(res, tuple, out)
        self.assertEqual(res[2]["network_cidr"], "10.77.0.0/16")
        self.assertTrue(res[2]["allowed_ssh_cidrs"])
        self.assertIn("for this command only", out)
        self.assertNotIn("network_cidr", env.load())            # nothing saved
        with self.assertRaises(paths.ConfigError) as cm, contextlib.redirect_stderr(io.StringIO()):
            cli._load_env(argparse.Namespace(cmd="apply", cloud="aws", env=env.name))
        self.assertIn("network_cidr", str(cm.exception))
        self.assertIn("--cidr", str(cm.exception))

    def test_summary_shows_missing_values(self):
        env = self.make("aws", _uid("sum"))
        cfg = env.load()
        for k in ("network_cidr", "allowed_ssh_cidrs"):
            cfg.pop(k)
        _, out = _capture(cli._print_summary, clouds.get("aws"), env, cfg)
        self.assertIn("(missing)", out)

    def test_a_local_target_needs_no_region_and_reports_get_a_vars_dict(self):
        cfg = {"name": "c", "network_cidr": "10.1.0.0/24", "ssh_public_key": "k", "vars": {}}
        env = paths.Env("vmware", _uid("loc"))
        self.assertEqual(cli._check_required_settings(argparse.Namespace(cmd="apply"), clouds.get("vmware"), env, cfg), [])
        self.assertEqual(cfg["region"], "local")
        cfg = {"name": "c", "region": "us-east-1"}
        filled = cli._check_required_settings(argparse.Namespace(cmd="troubleshoot"), clouds.get("aws"), env, cfg)
        self.assertEqual((filled, cfg["vars"]), (["vars"], {}))

    def test_os_login_never_registers_or_saves_a_placeholder(self):
        env = self.make("gcp", _uid("osl"), region="us-central1", vars={"project_id": "proj-123456", "enable_os_login": True})
        cfg = env.load()
        cfg.pop("ssh_public_key")
        cfg.pop("network_cidr")
        env.save(cfg)
        gcp = type(clouds.get("gcp"))
        with mock.patch.object(gcp, "prepare") as prep, contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            cli._load_env(argparse.Namespace(cmd="vpn", vpn_cmd="users", cloud="gcp", env=env.name))
        prep.assert_not_called()                            # the placeholder key is not the user's
        self.assertNotIn("network_cidr", env.load())
        cfg = env.load()
        cfg["ssh_public_key"] = "ssh-ed25519 AAAA real"
        env.save(cfg)

        def register(self, c, dry_run=False):
            c["os_login"] = {"user": "me_example_com"}
        with mock.patch.object(gcp, "prepare", register), contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            cli._load_env(argparse.Namespace(cmd="vpn", vpn_cmd="users", cloud="gcp", env=env.name))
        saved = env.load()
        self.assertEqual(saved["os_login"]["user"], "me_example_com")
        self.assertNotIn("network_cidr", saved)             # the placeholder of this run is not saved with it

    def test_setup_keeps_the_deployed_network_when_the_saved_one_is_lost(self):
        env = self.make("aws", _uid("net"))
        args = argparse.Namespace(cidr=None)
        given = {"unset": [], "extra": {}, "answers": {}}
        with self.assertRaises(ui.Abort) as cm:
            cli._setup_network(args, clouds.get("aws"), env, {"name": "c"}, given, {}, True)
        self.assertIn("--cidr <the deployed CIDR>", str(cm.exception))
        (env.dir / "outputs.json").write_text(json.dumps({"vpc_cidr": "10.77.0.0/16"}))
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli._setup_network(args, clouds.get("aws"), env, {"name": "c"}, given, {}, True),
                             ("10.77.0.0/16", False))


class SavedAnswerTests(_EnvCleanup):
    def test_read_only_vpn_and_k8s_commands_warn_changing_ones_refuse(self):
        env = self.make("aws", _uid("ans"), vars={"az_count": "abc"})
        cloud = clouds.get("aws")
        for ns in (SimpleNamespace(cmd="vpn", vpn_cmd="status"), SimpleNamespace(cmd="vpn", vpn_cmd="users"),
                   SimpleNamespace(cmd="vpn", vpn_cmd="disconnect"), SimpleNamespace(cmd="k8s", k8s_cmd="info")):
            cfg = env.load()
            with contextlib.redirect_stderr(io.StringIO()) as err:
                replaced = cli._check_saved_answers(ns, cloud, env, cfg)
            self.assertEqual(replaced, {"az_count": "abc"}, ns)
            self.assertIn("for this", err.getvalue())
        with self.assertRaises(SystemExit):
            cli._check_saved_answers(SimpleNamespace(cmd="vpn", vpn_cmd="add-user"), cloud, env, env.load())
        self.assertEqual(env.load()["vars"]["az_count"], "abc")   # config.json is not rewritten


# ---------------------------------------------------------------- --var shapes and hints, network, region

class VarShapeTests(unittest.TestCase):
    def bad(self, key, raw, ty):
        with self.assertRaises(SystemExit):
            cli._typed_var(key, raw, ty)

    def test_collections_must_have_their_declared_shape(self):
        self.bad("p", '{"a":1}', "list(string)")
        self.bad("p", '[["a"]]', "list(string)")
        self.bad("p", '[null]', "list(string)")
        self.bad("m", '["a"]', "map(string)")
        self.bad("m", '{"a": {"b": 1}}', "map(string)")
        self.bad("n", '["x"]', "list(number)")
        self.assertEqual(cli._typed_var("p", "[1,2]", "list(string)"), ["1", "2"])
        self.assertEqual(cli._typed_var("p", "[true]", "list(string)"), ["true"])
        self.assertEqual(cli._typed_var("p", "5", "list(string)"), ["5"])
        self.assertEqual(cli._typed_var("p", '"acme/"', "list(string)"), ["acme/"])
        self.assertEqual(cli._typed_var("p", "a,b", "list(string)"), ["a", "b"])
        self.assertEqual(cli._typed_var("m", '{"a": 1}', "map(string)"), {"a": 1})
        self.assertEqual(cli._typed_var("o", '{"a": [1]}', "object({a=list(number)})"), {"a": [1]})

    def test_hints_name_the_flag_to_use(self):
        with self.assertRaises(SystemExit) as cm:
            cli._check_extra_vars(clouds.get("aws"), {"region": "us-west-2"})
        self.assertIn("--region", cm.exception.msg)
        with self.assertRaises(SystemExit) as cm:
            cli._check_extra_vars(clouds.get("vmware"), {"region": "x"})
        self.assertNotIn("--region", cm.exception.msg)
        with self.assertRaises(SystemExit) as cm:
            cli._parse_setup_vars(clouds.get("gcp"), ["os_login_member=user:x@example.com"])
        self.assertIn("enable_os_login=true", cm.exception.msg)
        self.assertNotIn("the matching setup flag", cm.exception.msg)

    def test_parse_kv_takes_no_json_mode(self):
        self.assertEqual(cli._parse_kv(["a=[1]"]), {"a": "[1]"})
        with self.assertRaises(TypeError):
            cli._parse_kv(["a=1"], True)


class NetworkAndRegionTests(unittest.TestCase):
    def test_unusable_ranges_are_refused_public_and_cgnat_stay_allowed(self):
        for bad in ("127.0.0.0/24", "169.254.0.0/24", "224.0.0.0/24", "0.0.0.0/24", "240.0.0.0/24"):
            self.assertIsNotNone(cli._cidr_problem(bad), bad)
        for ok in ("10.0.0.0/16", "100.64.0.0/16", "8.8.8.0/24", "192.168.1.0/24"):
            self.assertIsNone(cli._cidr_problem(ok), ok)

    def test_aws_regions(self):
        aws = clouds.get("aws")
        for ok in ("us-east-1", "us-gov-west-1", "us-isof-south-1", "cn-northwest-1", "ap-southeast-7"):
            self.assertIsNone(cli._region_problem(aws, ok), ok)
        problem = cli._region_problem(aws, "eusc-de-east-1")
        self.assertIn("European Sovereign Cloud", problem)
        self.assertIn("an Amazon Web Services", cli._region_problem(aws, "mars"))
        self.assertIsNotNone(cli._region_problem(aws, "us-1"))

    def test_the_adapters_own_region_check_is_asked(self):
        az = clouds.get("azure")
        with mock.patch.object(type(az), "region_problem", create=True, new=lambda self, v: f"'{v}' is not a location"):
            self.assertIn("not a location", cli._region_problem(az, "Mars"))


# ---------------------------------------------------------------- setup: guards, previews, undo slots

class _NoopTF(setup_base.FakeTF):
    """A plan Terraform itself calls not applyable (nothing changes)."""

    def run(self, *args, capture=False, check=True):
        if args[:2] == ("show", "-json") and len(args) > 2:
            return subprocess.CompletedProcess(args, 0, json.dumps({"format_version": "1.2", "applyable": False}), "")
        return super().run(*args, capture=capture, check=check)


class SetupGuardTests(setup_base.SetupHarness):
    def created(self, cloud, *extra):
        env = self.env(cloud, _uid("sg"))
        base = ["-y", "--env", env.name, "--state", "local"] + (["--allow-ip", "203.0.113.5"] if cloud != "vmware" else [])
        rc, out = self.setup(cloud, *base, *extra, "--dry-run")
        self.assertEqual(rc, 0, out)
        return env

    def test_flags_of_another_cloud_are_named(self):
        env = self.env("aws", _uid("ff"))
        rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5",
                             "--zone", "us-east-1b", "--project-id", "my-proj-123", "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertIn("--zone (for gcp)", out)
        self.assertIn("--project-id (for gcp)", out)
        self.assertNotIn("zone", env.load()["vars"])

    def test_rename_of_a_deployed_env(self):
        env = self.created("aws")
        with mock.patch.object(cli, "_env_has_resources", return_value=True):
            rc, out = self.setup("aws", "-y", "--env", env.name, "--name", "renamed", "--auto-approve")
            self.assertEqual(rc, 2, out)
            self.assertIn("--plan-only", out)
            self.assertEqual(env.load()["name"], "cloudseed")
            rc, out = self.setup("aws", "-y", "--env", env.name, "--name", "renamed", "--plan-only")
        self.assertEqual(rc, 0, out)
        self.assertIn("changes from cloudseed to renamed", out)
        self.assertIn("renames the infrastructure", out)
        self.assertFalse((env.stack_dir / "tfplan").exists(), "a plan-only run leaves no saved plan behind")

    def test_project_and_subscription_cannot_move(self):
        env = self.created("gcp", "--project-id", "proj-one-123", "--region", "us-central1")
        with mock.patch.object(cli, "_env_has_resources", return_value=True):
            rc, out = self.setup("gcp", "-y", "--env", env.name, "--project-id", "proj-two-456", "--dry-run")
            self.assertEqual(rc, 1, out)
            self.assertIn("cannot be changed in place", out)
            rc, out = self.setup("gcp", "-y", "--env", env.name, "--var", "project_id=proj-two-456", "--dry-run")
            self.assertEqual(rc, 1, out)
        self.assertEqual(env.load()["vars"]["project_id"], "proj-one-123")
        guid = "11111111-2222-3333-4444-555555555555"
        az = self.created("azure", "--subscription-id", guid, "--region", "eastus")
        with mock.patch.object(cli, "_env_has_resources", return_value=True):
            rc, out = self.setup("azure", "-y", "--env", az.name, "--subscription-id", guid.upper(), "--dry-run")
            self.assertEqual(rc, 0, out)   # the same GUID in another case is the same subscription
            rc, out = self.setup("azure", "-y", "--env", az.name, "--subscription-id", guid.replace("1", "9"), "--dry-run")
            self.assertEqual(rc, 1, out)

    def test_gcp_zone_of_a_cluster_cannot_move(self):
        env = self.created("gcp", "--project-id", "proj-one-123", "--region", "us-central1", "--zone", "us-central1-a",
                           "--var", "enable_kubernetes=true")
        with mock.patch.object(cli, "_env_has_resources", return_value=True):
            rc, out = self.setup("gcp", "-y", "--env", env.name, "--zone", "us-central1-b", "--dry-run")
        self.assertEqual(rc, 1, out)
        self.assertIn("GKE cluster", out)

    def test_fips_preview_warns_about_the_pro_token(self):
        keydir = Path(tempfile.mkdtemp(prefix="cs-w3-key-"))
        self.addCleanup(shutil.rmtree, keydir, True)
        (keydir / "id_rsa.pub").write_text(setup_base.fake_pub("ssh-rsa") + "\n")
        (keydir / "id_rsa").write_text("PRIVATE\n")
        key = ["--ssh-public-key", str(keydir / "id_rsa.pub")]      # FIPS on AWS: RSA-4096
        env = self.env("aws", _uid("fp"))
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": ""}):
            rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5", *key,
                                 "--region", "us-east-1", "--var", "fips_mode=true", "--var", "enable_vpn=true", "--dry-run")
            self.assertEqual(rc, 0, out)
            self.assertIn("UBUNTU_PRO_TOKEN", out)
            env2 = self.env("aws", _uid("fp"))
            rc, out = self.setup("aws", "-y", "--env", env2.name, "--state", "local", "--allow-ip", "203.0.113.5", *key,
                                 "--region", "us-east-1", "--var", "fips_mode=true", "--var", "enable_vpn=true", "--auto-approve")
            self.assertEqual(rc, 1, out)
            self.assertIn("UBUNTU_PRO_TOKEN is not set", out)
            # a real configuration problem is refused in a dry run too
            env3 = self.env("aws", _uid("fp"))
            rc, out = self.setup("aws", "-y", "--env", env3.name, "--state", "local", "--allow-ip", "203.0.113.5",
                                 "--region", "eu-west-1", "--var", "fips_mode=true", "--dry-run")
            self.assertEqual(rc, 1, out)

    def test_tailscale_without_key_is_refused_before_anything_is_created(self):
        with mock.patch.dict(os.environ, {"TS_AUTHKEY": ""}):
            env = self.env("aws", _uid("ts"))
            rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5",
                                 "--var", "enable_vpn=true", "--var", "vpn_type=tailscale", "--auto-approve")
            self.assertEqual(rc, 1, out)
            self.assertIn("TS_AUTHKEY", out)
            self.assertFalse(self.calls("apply"))
            self.assertFalse(env.exists())
            env2 = self.env("aws", _uid("ts"))
            rc, out = self.setup("aws", "-y", "--env", env2.name, "--state", "local", "--allow-ip", "203.0.113.5",
                                 "--var", "enable_vpn=true", "--var", "vpn_type=tailscale", "--dry-run")
            self.assertEqual(rc, 0, out)
            self.assertIn("TS_AUTHKEY", out)

    def test_local_state_dry_run_renders_no_bootstrap(self):
        env = self.env("gcp", _uid("ls"))
        rc, out = self.setup("gcp", "-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5",
                             "--project-id", "proj-one-123", "--region", "us-central1", "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("bootstrap", out.split("Rendered root(s):")[-1])
        self.assertFalse((env.bootstrap_dir / "main.tf.json").exists())

    def test_noop_rerun_takes_no_undo_slot_and_skips_the_apply(self):
        env = self.env("aws", _uid("np"))
        argv = ["-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5", "--no-provision", "--auto-approve"]
        rc, out = self.setup("aws", *argv)
        self.assertEqual(rc, 0, out)
        self.assertEqual([e["kind"] for e in undo.entries(env.id)], ["created"])
        with mock.patch.object(cli, "Terraform", _NoopTF):
            for _ in range(2):
                rc, out = self.setup("aws", *argv)
                self.assertEqual(rc, 0, out)
                self.assertIn("No infrastructure changes", out)
        self.assertEqual([e["kind"] for e in undo.entries(env.id)], ["created"], "no-op re-runs must not evict it")
        with mock.patch.object(cli, "Terraform", _NoopTF):
            rc, out = self.setup("aws", "-y", "--env", env.name, "--no-provision")    # -y without --auto-approve
        self.assertEqual(rc, 0, out)
        self.assertIn("Hosts were not re-provisioned", out)
        # a changed setting only provisioning applies: still a preview (exit 3), the saved configuration unchanged
        before = env.load()
        with mock.patch.object(cli, "Terraform", _NoopTF):
            rc, out = self.setup("aws", "-y", "--env", env.name, "--no-provision", "--var", "az_count=3")
        self.assertEqual(rc, 3, out)
        self.assertIn("changed settings (az_count)", out)          # the variable, not "vars"
        self.assertEqual(env.load()["vars"], before["vars"])

    def test_changed_settings_are_named_in_the_undo_entry(self):
        env = self.env("aws", _uid("ch"))
        argv = ["-y", "--env", env.name, "--state", "local", "--allow-ip", "203.0.113.5", "--no-provision", "--auto-approve"]
        self.assertEqual(self.setup("aws", *argv)[0], 0)
        rc, out = self.setup("aws", *argv, "--var", "az_count=3")
        self.assertEqual(rc, 0, out)
        self.assertIn("changed: az_count", undo.entries(env.id)[-1]["summary"])   # the variable's name, not "vars"

    def test_env_id_as_a_new_name_is_refused(self):
        env = self.created("aws")
        clash = self.env("aws", f"aws-{env.name}")
        rc, out = self.setup("aws", "-y", "--env", clash.name, "--state", "local", "--allow-ip", "203.0.113.5", "--dry-run")
        self.assertEqual(rc, 2, out)
        self.assertIn(f"--env {env.name}", out)
        self.assertFalse(clash.exists())

    def test_no_detected_ip_without_a_terminal_is_one_clear_error(self):
        env = self.env("aws", _uid("ip"))
        with mock.patch.object(cli.netutil, "detect_public_ip", lambda timeout=5.0: None):
            rc, out = self.setup("aws", "-y", "--env", env.name, "--state", "local", "--dry-run")
        self.assertEqual(rc, 1, out)
        self.assertIn("pass --allow-ip", out)
        self.assertNotIn("enter it manually", out)


class ApplyNoopTests(life.LifeBase):
    def test_converged_apply_exits_zero(self):
        life.FakeTF.reset(state=["module.stack.aws_vpc.this"])
        with mock.patch.object(life.FakeTF, "run", lambda self, *a, **k: life._cp(0, json.dumps(
                {"format_version": "1.2", "applyable": False})) if a[:2] == ("show", "-json") and len(a) > 2 else life._cp(0)):
            rc = self.run_cmd(cli.cmd_apply, ["apply", "aws", "--env", self.env_name, "-y"])
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertIn("No changes", self.out.getvalue())
        self.assertEqual(life._names(life.FakeTF.calls, "apply_reconciled"), [])
        self.assertFalse((self.env.stack_dir / "tfplan").exists())

    def test_fips_apply_without_the_pro_token_says_provisioning_needs_it(self):
        cfg = self.env.load()
        cfg["vars"] = dict(cfg.get("vars") or {}, fips_mode=True, enable_vpn=True)
        self.env.save(cfg)
        life.FakeTF.reset(state=["module.stack.aws_vpc.this"])
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": ""}), \
                mock.patch.object(life.FakeTF, "run", lambda self, *a, **k: life._cp(0, json.dumps(
                    {"format_version": "1.2", "applyable": False})) if a[:2] == ("show", "-json") and len(a) > 2 else life._cp(0)):
            rc = self.run_cmd(cli.cmd_apply, ["apply", "aws", "--env", self.env_name, "-y"])
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertIn("UBUNTU_PRO_TOKEN is not set", self.out.getvalue())

    def test_unreadable_or_older_plans_are_not_noops(self):
        t = SimpleNamespace(run=lambda *a, **k: life._cp(0, json.dumps({"resource_changes": []})))
        self.assertFalse(cli._plan_is_noop(t))           # no format_version: cannot tell
        t = SimpleNamespace(run=lambda *a, **k: life._cp(1, "", "boom"))
        self.assertFalse(cli._plan_is_noop(t))
        plan = {"format_version": "1.0", "resource_changes": [{"change": {"actions": ["no-op"]}}],
                "output_changes": {"x": {"actions": ["create"]}}}
        t = SimpleNamespace(run=lambda *a, **k: life._cp(0, json.dumps(plan)))
        self.assertFalse(cli._plan_is_noop(t))           # a new output still needs the apply
        plan["output_changes"] = {"x": {"actions": ["no-op"]}}
        self.assertTrue(cli._plan_is_noop(t))


# ---------------------------------------------------------------- destroy

class DestroyWave3Tests(life.LifeBase):
    GCP = ["module.stack.google_project_service.apis[\"compute\"]", "module.stack.google_project_service.apis[\"iam\"]",
           "module.stack.module.network.google_compute_network.this", "module.stack.module.network.google_compute_subnetwork.a",
           "module.stack.module.network.google_compute_router.this", "module.stack.module.bastion.google_compute_instance.bastion",
           "module.stack.module.bastion.google_compute_address.bastion"]

    def test_module_counts_include_nested_modules(self):
        groups = cli._module_groups(self.GCP + ["module.stack.module.kubernetes[0].google_container_cluster.this"])
        self.assertEqual(groups["module.stack"], 8)
        self.assertEqual(groups["module.stack.module.network"], 3)
        self.assertEqual(groups["module.stack.module.kubernetes[0]"], 1)

    def test_select_does_not_offer_the_whole_environment_as_a_module(self):
        with mock.patch.object(ui, "ask", return_value="q"), contextlib.redirect_stdout(self.out):
            with self.assertRaises(SystemExit):
                cli._select_targets(self.GCP)
        out = self.out.getvalue()
        self.assertIn("all 7 resources - the whole environment", out)
        self.assertNotIn(") module.stack  (", out)
        self.assertIn(") module.stack.module.network  (3 resources)", out)
        self.assertIn(') module.stack.google_project_service.apis["iam"]', out)   # its own resources stay selectable

    def test_targets_covering_everything_need_the_typed_env_id(self):
        life.FakeTF.reset(state=list(self.GCP), changes=[
            {"address": a, "type": a.split(".")[-2], "mode": "managed", "change": {"actions": ["delete"]}} for a in self.GCP])
        with mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "require_typed", side_effect=life._raises("Confirmation did not match.")) as typed, \
                mock.patch.object(ui, "confirm", side_effect=AssertionError("a y/N is not enough")):
            rc = self.destroy("--target", "module.stack")
        self.assertEqual(rc, 1)
        typed.assert_called_once()
        self.assertEqual(life._names(life.FakeTF.calls, "apply"), [])
        self.assertIn("this destroys the whole environment", self.out.getvalue())

    def test_targeted_baseline_destroy_warns_about_guardduty(self):
        state = ["module.stack.module.network.aws_vpc.this",
                 "module.stack.module.security_baseline[0].aws_guardduty_detector.this[0]"]
        life.FakeTF.reset(state=state, changes=[{"address": state[1], "type": "aws_guardduty_detector", "mode": "managed",
                                                  "change": {"actions": ["delete"]}}])
        self.assertEqual(self.destroy("--target", "module.stack.module.security_baseline", "-y"), 3)
        self.assertIn("turns off GuardDuty for the whole account", self.out.getvalue())

    def test_preview_names_what_is_kept(self):
        state = ["module.stack.module.network.aws_vpc.this",
                 "module.stack.module.security_baseline[0].aws_s3_account_public_access_block.this[0]"]
        life.FakeTF.reset(state=state)
        self.assertEqual(self.destroy("-y"), 3)
        out = self.out.getvalue()
        self.assertIn("Kept in place", out)
        self.assertLess(out.index("Kept in place"), out.index("Nothing destroyed"))
        self.assertIn("except the settings kept in place", out)

    def _with_storage(self):
        (self.env.bootstrap_dir).mkdir(parents=True, exist_ok=True)
        (self.env.bootstrap_dir / "main.tf.json").write_text("{}")
        (self.env.bootstrap_dir / "terraform.tfstate").write_text(json.dumps(
            {"resources": [{"type": "aws_s3_bucket"}], "outputs": {"bucket": {"value": "cs-state-bucket"}}}))

    def test_purge_state_on_an_empty_stack_still_confirms_at_a_terminal(self):
        self._with_storage()
        life.FakeTF.reset(state=None)
        asked = []
        with mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "confirm", side_effect=lambda q, default=False: asked.append(q) or False):
            rc = self.destroy("--purge-state")
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertIn("cs-state-bucket", asked[0])
        self.assertEqual(len([q for q in asked if "state storage" in q]), 1, asked)
        self.assertTrue(any("working directory" in q or "cloudseed's files" in q for q in asked), "the purge question still comes")
        self.assertEqual(life._names(life.FakeTF.calls, "apply"), [])
        self.assertIn("kept (it is billable)", self.out.getvalue())
        self.assertIn("--purge-state", self.out.getvalue())

    def test_a_purge_that_keeps_the_storage_does_not_print_a_dead_command(self):
        self._with_storage()
        life.FakeTF.reset(state=None)
        with mock.patch.object(ui, "confirm", return_value=False):
            rc = self.destroy("-y", "--auto-approve", "--purge")
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertNotIn("--purge-state", self.out.getvalue())
        self.assertIn("terraform -chdir=", self.out.getvalue())


class PurgeWorkdirTests(unittest.TestCase):
    def _env(self, created, files):
        d = Path(tempfile.mkdtemp(prefix="cs-w3-purge-")) / "work"
        d.mkdir()
        self.addCleanup(shutil.rmtree, d.parent, True)
        for rel, text in files.items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(text)
        env = paths.Env("aws", "w3purge", workdir=d)
        cfg = {"cloud": "aws", "env": "w3purge", "workdir_preexisting": []}
        if created is not None:
            cfg["workdir_created"] = created
        (d / "config.json").write_text(json.dumps(cfg))
        return env, d

    def test_a_directory_the_user_made_keeps_their_files(self):
        for created in (False, True):
            env, d = self._env(created, {"stack/main.tf.json": "{}", "ssh/id_rsa": "k", "dry-run/stack/main.tf.json": "{}",
                                         "notes.txt": "mine"})
            self.assertFalse(cli._workdir_owned(env), created)
            self.assertIn("goes only when nothing else is left", cli._purge_question(env))
            left, protected = cli._remove_env_files(env)
            self.assertEqual((left, protected), (["notes.txt"], False), created)
            self.assertTrue((d / "notes.txt").exists())

    def test_nothing_else_left_removes_the_directory(self):
        env, d = self._env(False, {"stack/main.tf.json": "{}", "logs/audit.jsonl": "x", ".DS_Store": ""})
        left, _ = cli._remove_env_files(env)
        self.assertEqual(left, [])
        self.assertFalse(d.exists())

    def test_older_records_name_what_goes_with_the_directory(self):
        env, d = self._env(None, {"stack/main.tf.json": "{}", "notes.txt": "x"})
        self.assertTrue(cli._workdir_owned(env))
        self.assertIn("notes.txt, which goes with it", cli._purge_question(env))


# ---------------------------------------------------------------- output / inventory / kubeconfig / ssh

class JsonStdoutTests(life.LifeBase):
    def test_messages_while_loading_go_to_stderr(self):
        real = cli._load_env

        def noisy(args):
            ui.info("Building terraform-provider-vmdesktop")
            return real(args)
        life.FakeTF.reset(outputs_value={"bastion_public_ip": "192.0.2.9"})
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "_load_env", noisy), \
                mock.patch.object(cli, "_read_outputs", lambda t: {"bastion_public_ip": "192.0.2.9"}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.cmd_output(cli.build_parser().parse_args(["output", "aws", "--env", self.env_name, "--json"]), {})
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue()), {"bastion_public_ip": "192.0.2.9"})
        self.assertIn("Building", err.getvalue())
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "_load_env", noisy), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.cmd_inventory(cli.build_parser().parse_args(["inventory", "aws", "--env", self.env_name, "--json"]), {})
        self.assertEqual(rc, 0)
        json.loads(out.getvalue())

    def test_inventory_shows_the_objects_own_name_and_ip(self):
        audit.save(self.env, {"current": {"resources": [
            {"address": "module.stack.google_compute_address.bastion", "type": "google_compute_address", "name": "bastion",
             "ip_address": "203.0.113.4", "cloud_name": "cloudseed-dev-bastion-ip", "mode": "managed"}]}})
        rc = self.run_cmd(cli.cmd_inventory, ["inventory", "aws", "--env", self.env_name])
        self.assertEqual(rc, 0)
        out = self.out.getvalue()
        self.assertIn("google_compute_address.bastion", out)
        self.assertIn("name=cloudseed-dev-bastion-ip", out)
        self.assertIn("address=203.0.113.4", out)


class OutputsCacheTests(life.LifeBase):
    def test_a_replaced_bastion_forgets_its_host_key(self):
        (self.env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "198.51.100.9", "bastion_instance_id": "i-old"}))
        life.FakeTF.reset(outputs_value={"bastion_public_ip": "198.51.100.9", "bastion_instance_id": "i-new"})
        with mock.patch.object(cli.prov, "forget_host_key") as forget:
            cli._cache_outputs(self.env, life.FakeTF(self.env.stack_dir))
        forget.assert_called_once_with(self.env, "198.51.100.9")
        self.assertEqual(cli._cached_outputs(self.env)["bastion_instance_id"], "i-new")


class KubeconfigUndoTests(life.LifeBase):
    def test_unchanged_merges_take_no_slot_and_leave_no_copy(self):
        home = Path(tempfile.mkdtemp(prefix="cs-w3-kube-"))
        self.addCleanup(shutil.rmtree, home, True)
        kube = home / "config"
        kube.write_text("apiVersion: v1\n")
        (self.env.dir / "outputs.json").write_text(json.dumps({"kubernetes_cluster_name": "c"}))
        writes = iter(["apiVersion: v1\nclusters: [a]\n", "apiVersion: v1\nclusters: [a]\n", "apiVersion: v1\nclusters: [a, b]\n"])

        def merge(*a, **k):
            kube.write_text(next(writes))
            return 0
        backups_before = set(os.listdir(undo.BACKUPS)) if undo.BACKUPS.exists() else set()
        with mock.patch.object(cli.services, "home_kubeconfig", return_value=kube), \
                mock.patch.object(cli.services, "ensure_kubeconfig"), mock.patch.object(cli.services, "kubeconfig", merge), \
                mock.patch.object(cli, "_record_merged_kubeconfig"):
            for _ in range(3):
                self.assertEqual(self.run_cmd(cli.cmd_k8s, ["k8s", "kubeconfig", "aws", "--env", self.env_name]), 0)
        entries = [e for e in undo.entries(self.env.id) if e["summary"].startswith("k8s kubeconfig")]
        self.assertEqual(len(entries), 1, entries)
        kept = list(entries[0]["data"]["files"].values())
        self.assertEqual(Path(kept[0]).read_text(), "apiVersion: v1\n")      # before the whole run
        new = set(os.listdir(undo.BACKUPS)) - backups_before
        self.assertEqual(len(new), 1, new)                                    # no orphaned copies


class SshWave3Tests(life.LifeBase):
    def test_remote_commands_share_one_undo_slot_and_the_command_is_quoted(self):
        (self.env.dir / "outputs.json").write_text('{"bastion_public_ip": "192.0.2.10"}')
        with mock.patch.object(cli.subprocess, "call", return_value=0):
            for cmd in ("uptime", "df -h", "whoami"):
                self.run_cmd(cli.cmd_ssh, ["ssh", "aws", "--env", self.env_name, "--", *cmd.split()])
        entries = [e for e in undo.entries(self.env.id) if e["summary"].startswith("ssh command")]
        self.assertEqual(len(entries), 1)
        self.assertIn("whoami", entries[0]["summary"])
        self.assertIn("'df' '-h'".replace("'", ""), self.out.getvalue().replace("'", ""))


# ---------------------------------------------------------------- the parser

class DefaultEnvArgvTests(unittest.TestCase):
    def patch(self, envs, current=None):
        return contextlib.ExitStack(), [mock.patch.object(paths.Env, "list_all", return_value=envs),
                                        mock.patch.object(paths, "load_settings", return_value={"current_env": current} if current else {})]

    def run_with(self, envs, argv, current=None):
        err = io.StringIO()
        with mock.patch.object(paths.Env, "list_all", return_value=envs), \
                mock.patch.object(paths, "load_settings", return_value={"current_env": current} if current else {}), \
                contextlib.redirect_stderr(err):
            try:
                return cli._default_env_argv(list(argv)), err.getvalue()
            except SystemExit as e:
                return e.code, err.getvalue()

    def test_cloud_after_the_env_option_is_not_inserted_twice(self):
        dev = [paths.Env("aws", "dev")]
        for argv in (["status", "--env", "dev", "aws"], ["status", "--env=dev", "aws"], ["-y", "status", "-e", "dev", "aws"],
                     ["ssh", "--env", "dev", "aws"], ["ssh", "--env", "dev", "aws", "--", "uptime"],
                     ["vpn", "add-user", "--env", "dev", "aws", "alice"], ["vpn", "revoke", "--env", "dev", "aws"],
                     ["inventory", "--last", "3", "aws"], ["status", "-y", "aws"]):
            self.assertEqual(self.run_with(dev, argv)[0], argv, argv)
        self.assertEqual(self.run_with(dev, ["vpn", "add-user", "--env", "dev", "bob"])[0],
                         ["vpn", "add-user", "aws", "--env", "dev", "bob"])

    def test_env_ids_in_the_clouds_place(self):
        envs = [paths.Env("aws", "f1"), paths.Env("aws", "po1")]
        self.assertEqual(self.run_with(envs, ["status", "aws-f1"], "aws-po1")[0], ["status", "aws", "--env", "f1"])
        self.assertEqual(self.run_with(envs, ["ssh", "aws-f1", "--", "uptime"])[0], ["ssh", "aws", "--env", "f1", "--", "uptime"])
        self.assertEqual(self.run_with(envs, ["vpn", "connect", "aws-f1"])[0], ["vpn", "connect", "aws", "--env", "f1"])
        self.assertEqual(self.run_with(envs, ["vpn", "add-user", "bob"], "aws-po1")[0], ["vpn", "add-user", "aws", "--env", "po1", "bob"])
        # a bare word that is no environment: left for the parser to name (never the current env plus an error)
        argv, err = self.run_with(envs, ["status", "nope"], "aws-po1")
        self.assertEqual(argv, ["status", "nope"])
        self.assertEqual(err, "")
        # --env given as an id reaches the parser as the name
        self.assertEqual(self.run_with(envs, ["status", "--env", "aws-f1"])[0], ["status", "aws", "--env", "f1"])

    def test_unknown_or_ambiguous_env_is_refused_with_the_list(self):
        envs = [paths.Env("aws", "w1"), paths.Env("gcp", "w1")]
        code, err = self.run_with(envs, ["status", "--env", "nope"])
        self.assertEqual(code, 2)
        self.assertIn("No environment named 'nope'", err)
        self.assertIn("aws-w1", err)
        code, err = self.run_with(envs, ["status", "--env", "w1"], "gcp-w1")
        self.assertEqual(code, 2)
        self.assertIn("name the cloud too", err)
        code, err = self.run_with(envs, ["vpn", "add-user", "--env", "nope", "bob"])
        self.assertIn("No environment named 'nope'", err)
        self.assertEqual(self.run_with(envs, ["status", "--env", "nope", "--help"])[0], ["status", "--env", "nope", "--help"])

    def test_env_after_the_positional_word(self):
        envs = [paths.Env("aws", "f1"), paths.Env("aws", "prod"), paths.Env("gcp", "dev")]
        # argparse takes options anywhere: an --env after the client name still picks the cloud (as before wave 3)
        self.assertEqual(self.run_with(envs, ["vpn", "add-user", "bob", "--env", "prod"])[0],
                         ["vpn", "add-user", "aws", "bob", "--env", "prod"])
        self.assertEqual(self.run_with(envs, ["vpn", "revoke", "bob", "--env=prod"])[0],
                         ["vpn", "revoke", "aws", "bob", "--env=prod"])
        # an id in the cloud's place and a different --env after it: refused, never the last one silently
        for argv in (["status", "aws-f1", "--env", "prod"], ["ssh", "aws-f1", "--env", "prod"],
                     ["vpn", "add-user", "aws-f1", "bob", "--env", "prod"]):
            code, err = self.run_with(envs, argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("name different environments", err)
        self.assertEqual(self.run_with(envs, ["status", "aws-f1", "--env", "f1"])[0], ["status", "aws", "--env", "f1"])
        # ssh: after a word that is not an id the words are the remote command's, --env included
        self.assertEqual(self.run_with(envs, ["ssh", "uptime", "--env", "prod"])[0], ["ssh", "uptime", "--env", "prod"])

    def test_ssh_hint_is_printed_once(self):
        env = paths.Env("aws", "one")
        with mock.patch.object(paths.Env, "list_all", return_value=[env]), \
                mock.patch.object(paths, "load_settings", return_value={}), contextlib.redirect_stderr(io.StringIO()) as err:
            args = cli._parse_ssh_argv(cli._default_env_argv(["ssh", "--", "hostname"]))
        self.assertEqual(err.getvalue().count("(ssh: aws-one"), 1)
        self.assertEqual(args.ssh_args, ["--", "hostname"])


class ParserWave3Tests(unittest.TestCase):
    def parse(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                return cli.build_parser().parse_args(list(argv)), out.getvalue()
            except SystemExit as e:
                return e.code, out.getvalue()

    def test_mistyped_option_is_named_not_the_value(self):
        code, out = self.parse("finops", "cloud", "--dayz", "7")
        self.assertEqual(code, 2)
        self.assertIn("--dayz", out)
        self.assertIn("--days", out)
        self.assertNotIn("invalid choice: '7'", out)
        code, out = self.parse("finops", "cloud", "--da", "7", "awz")    # a valid abbreviation: the bad cloud is named
        self.assertIn("awz", out)

    def test_env_id_given_as_the_cloud(self):
        with mock.patch.object(paths.Env, "exists", return_value=True):
            code, out = self.parse("destroy", "aws-f1")
        self.assertEqual(code, 2)
        self.assertIn("cloudseed destroy aws --env f1", out)

    def test_flags_after_the_task_are_applied(self):
        ns, _ = self.parse("do", "--force", "list", "envs", "--model", "gpt-9", "--show-prompt", "--agent=codex", "-y")
        self.assertEqual(ns.task, ["list", "envs"])
        self.assertEqual((ns.model, ns.agent, ns.show_prompt, ns.force, ns.yes), ("gpt-9", "codex", True, True, True))
        ns, _ = self.parse("do", "show pods -n kube-system --model x")          # one quoted word: untouched
        self.assertEqual(ns.task, ["show pods -n kube-system --model x"])
        self.assertIsNone(ns.model)
        ns, _ = self.parse("do", "show", "pods", "-n", "kube-system")          # mid-sentence dashes stay
        self.assertEqual(ns.task, ["show", "pods", "-n", "kube-system"])
        ns, _ = self.parse("do", "--agent", "fake", "--", "list", "envs", "--model", "x")
        self.assertEqual(ns.task, ["list", "envs", "--model", "x"])
        self.assertIsNone(ns.model)
        code, out = self.parse("do", "--agent", "a", "list", "--agent", "b")
        self.assertEqual(code, 2)
        self.assertIn("given twice", out)
        code, out = self.parse("do", "list", "envs", "--agent")
        self.assertEqual(code, 2)
        code, out = self.parse("agentic", "list envs", "--help")
        self.assertEqual(code, 0)
        self.assertIn("usage", out.lower())

    def test_ssh_help_after_the_env(self):
        code, out = self.parse("ssh", "aws", "--env", "dev", "--help")
        self.assertEqual(code, 0)
        self.assertIn("usage", out.lower())
        argv = ["ssh", "aws", "--", "--help"]           # after `--` it is the remote side's
        with mock.patch.object(cli, "_ARGV", argv):
            ns, _ = self.parse(*argv)
        self.assertNotIsInstance(ns, int)
        ns = cli._parse_ssh_argv(argv)
        self.assertEqual(ns.ssh_args, ["--", "--help"])


# ---------------------------------------------------------------- doctor, agents, ui, misc

class DoctorTests(unittest.TestCase):
    def run_doctor(self, cloud, rows, warnings=(), live=None):
        with mock.patch.object(deps, "status", return_value=rows), \
                mock.patch.object(deps, "live_credential_check", return_value=live), \
                mock.patch.object(type(clouds.get(cloud)), "credential_warnings", lambda self, cfg: list(warnings)):
            return _capture(cli.cmd_doctor, argparse.Namespace(cloud=cloud), {})

    def row(self, tool, path="/x", required=True, outdated=False):
        return {"tool": tool, "path": path, "required": required, "desc": "d", "version": "1.0", "outdated": outdated}

    def test_verdict_for_a_named_cloud(self):
        rc, out = self.run_doctor("aws", [self.row("terraform", path=None), self.row("aws")])
        self.assertIn("not ready: terraform is missing", out)
        self.assertNotIn("not ready", self.run_doctor("aws", [self.row("terraform"), self.row("aws")], live=(True, "ok"))[1])
        self.assertIn("credentials do not work", self.run_doctor("aws", [self.row("terraform")], live=(False, "expired"))[1])
        self.assertIn("no credentials", self.run_doctor("aws", [self.row("terraform")], warnings=["No AWS credentials"])[1])

    def test_columns_fit_the_longest_tool(self):
        rc, out = self.run_doctor("gcp", [self.row("gke-gcloud-auth-plugin", required=False), self.row("terraform")],
                                  live=(True, "ok"))
        lines = [ln for ln in out.splitlines() if "gke-gcloud-auth-plugin" in ln or " terraform " in ln]
        self.assertEqual(len({ln.index("1.0") for ln in lines}), 1, lines)

    def test_stale_provider_is_not_reported_as_built(self):
        from cloudseed import localvm
        binary = Path(tempfile.mkdtemp()) / "terraform-provider-vmdesktop"
        binary.write_text("bin")
        self.addCleanup(shutil.rmtree, binary.parent, True)
        with mock.patch.object(localvm, "provider_binary", return_value=binary), \
                mock.patch.object(localvm, "_provider_stale", return_value=True), \
                mock.patch.object(localvm, "detect_host", return_value={"found": False}):
            rc, out = self.run_doctor("vmware", [self.row("terraform")])
        self.assertIn("stale", out)
        self.assertNotIn("built  ", out.split("provider")[-1][:30])


class AgentSkillTests(unittest.TestCase):
    def test_a_foreign_skill_directory_is_left_alone(self):
        dest = Path(tempfile.mkdtemp(prefix="cs-w3-skills-"))
        self.addCleanup(shutil.rmtree, dest, True)
        (dest / "cloudseed-aws").mkdir()
        (dest / "cloudseed-aws" / "SKILL.md").write_text("---\nname: my-own-aws\n---\n")
        spec = {"skills_dir": str(dest), "display": "Claude Code"}
        with mock.patch.object(skills, "installed", return_value=False), \
                mock.patch.object(skills, "target_dir", return_value=dest):
            rc, out = _capture(cli._ensure_agent_skills, "claude", spec)
            self.assertIsNone(rc, out)
            self.assertIn("Left", out)
            self.assertEqual((dest / "cloudseed-aws" / "SKILL.md").read_text(), "---\nname: my-own-aws\n---\n")
            self.assertTrue((dest / "cloudseed" / "SKILL.md").exists())
            rc, out = _capture(cli._ensure_agent_skills, "claude", spec)      # nothing else to install: quiet
        self.assertEqual(out, "")

    def test_agent_session_has_one_definition(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "", "CLOUDSEED_REDACT": "1"}):
            self.assertTrue(cli._agent_session())
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "mcp", "CLOUDSEED_REDACT": "1"}):
            self.assertFalse(cli._agent_session())


class UiStartTests(unittest.TestCase):
    def test_bad_port_and_host_are_refused_before_anything_changes(self):
        settings = {"ui": False}
        for port in (0, 70000, -1):
            rc, out = _capture(cli._ui_start, argparse.Namespace(port=port, host=None, no_open=True), settings)
            self.assertEqual(rc, 2, out)
            self.assertIn("not a TCP port", out)
        rc, out = _capture(cli._ui_start, argparse.Namespace(port=None, host="::1", no_open=True), settings)
        self.assertEqual(rc, 2, out)
        self.assertIn("only to `cs ui serve`", out)
        self.assertFalse(settings["ui"])

    def test_a_service_that_cannot_be_written_rolls_back(self):
        saved = paths.load_settings()
        self.addCleanup(paths.save_settings, saved)
        state_before = webui.STATE_PATH.read_text() if webui.STATE_PATH.exists() else None
        self.addCleanup(lambda: webui.STATE_PATH.write_text(state_before) if state_before is not None
                        else webui.STATE_PATH.unlink(missing_ok=True))
        settings = dict(saved, ui=False)
        paths.save_settings(settings)
        err = FileExistsError(17, "File exists", "/home/x/Library/LaunchAgents")
        with mock.patch.object(cli, "_can_bind", return_value=True), mock.patch.object(webui, "ensure_token"), \
                mock.patch.object(webui, "stop"), mock.patch.object(webui, "start", side_effect=err), \
                mock.patch.object(webui, "remove_service") as removed, mock.patch.object(webui, "load_state", return_value={}):
            rc, out = _capture(cli._ui_start, argparse.Namespace(port=7503, host=None, no_open=True), settings)
        self.assertEqual(rc, 1, out)
        self.assertIn("The UI did not start: File exists", out)
        self.assertIn("nothing was changed", out)
        self.assertNotIn("Unexpected", out)
        removed.assert_called_once()
        self.assertFalse(paths.load_settings().get("ui"))
        # a console that was running was stopped before the start failed: the message must not claim nothing changed
        settings = dict(saved, ui=True)
        with mock.patch.object(cli, "_can_bind", return_value=True), mock.patch.object(webui, "ensure_token"), \
                mock.patch.object(webui, "stop"), mock.patch.object(webui, "start", side_effect=err), \
                mock.patch.object(webui, "remove_service"), mock.patch.object(webui, "health", return_value=False), \
                mock.patch.object(webui, "load_state", return_value={"port": 7511}):
            rc, out = _capture(cli._ui_start, argparse.Namespace(port=7512, host=None, no_open=True), settings)
        self.assertEqual(rc, 1, out)
        self.assertIn("the console is stopped", out)
        self.assertNotIn("nothing was changed", out)
        self.assertTrue(settings["ui"])


class MiscWave3Tests(unittest.TestCase):
    def test_explain_also_wraps(self):
        with mock.patch.object(ui, "width", return_value=60), contextlib.redirect_stdout(io.StringIO()) as out:
            cli._explain_also("vmware")
        lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
        self.assertTrue(lines)
        self.assertTrue(all(len(ui._strip(ln)) <= 60 for ln in lines), lines)
        self.assertTrue(all("cs explain" in ln for ln in lines))

    def test_platform_plan_for_a_missing_env_is_not_offline(self):
        ns = argparse.Namespace(cloud="aws", env="surely-not-there")
        self.assertIsNone(cli._offline_plan_env(ns, {}))

    def test_recovery_hints_parse(self):
        host = SimpleNamespace(label="bastion", env=paths.Env("aws", "hint1"), ssh=lambda *a: ["true"])
        # provisioning verifies FIPS through provision.await_fips: no reboot pending ("no"), then fips_enabled=0
        answers = iter(["no\n", "0\n"])
        with mock.patch.object(cli.prov.subprocess, "run",
                               side_effect=lambda *a, **k: subprocess.CompletedProcess([], 0, next(answers), "")), \
                mock.patch.object(cli.prov.time, "sleep", side_effect=AssertionError("no reboot is pending")), \
                self.assertRaises(SystemExit) as cm:
            cli._verify_fips(host)
        self.assertIn("cloudseed provision aws --env hint1 --host bastion", cm.exception.msg)
        argv = cm.exception.msg.split("re-run: cloudseed ")[1].split()
        with contextlib.redirect_stderr(io.StringIO()):
            ns = cli.build_parser().parse_args(argv)
        self.assertEqual((ns.cloud, ns.env, ns.host), ("aws", "hint1", "bastion"))

    def test_vmware_bastion_trusts_only_the_static_zone(self):
        env = paths.Env("vmware", _uid("nat"))
        env.create_dirs()
        self.addCleanup(shutil.rmtree, env.dir, True)
        (env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "10.9.0.2"}))
        cfg = {"network_cidr": "10.9.0.0/24", "vars": {}, "ssh_username": "u"}
        seen = {}
        with mock.patch.object(cli.prov, "provision", lambda *a, **k: seen.update(k["extra_vars"])):
            cli._provision_all(clouds.get("vmware"), env, cfg, only="bastion", sync_only=True)
        self.assertEqual(seen["nat_source_cidrs"], ["10.9.0.0/25"])   # not VMware's DHCP pool above .127


if __name__ == "__main__":
    unittest.main()
