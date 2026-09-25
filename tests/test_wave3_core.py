"""Regression tests for the wave-3 core items: the SSH allow-list (host bits at every prefix, adjacent /8s), tag keys
that differ only in case, blank saved values, int bounds on questions, ignored environment variables, Terraform
hints (wrapped checksum errors, the failing root, plugin start-up failures, crashes, GCP projects), stale workdirs.json
reservations and the ansible text scan. Stdlib only; no network, no cloud."""
import contextlib
import importlib
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

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import netutil, paths, tf, ui  # noqa: E402
from cloudseed import clouds  # noqa: E402
from cloudseed.clouds import base  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        yield out, err


def _cfg(cloud="aws", env="w3", **kw):
    cfg = {"cloud": cloud, "env": env, "name": "cs", "region": "us-east-1", "network_cidr": "10.9.0.0/16",
           "allowed_ssh_cidrs": ["203.0.113.7/32"], "owner": "alice", "tags": {}, "vars": {}, "state": {"type": "local"}}
    cfg.update(kw)
    return cfg


# ---------------------------------------------------------------- SSH allow-list (cli-lifecycle#4, docs-skills#7)

class AllowListTests(unittest.TestCase):
    def test_host_bits_are_refused_at_every_prefix(self):
        for raw in ("203.0.113.7/16", "203.0.113.7/20", "203.0.113.7/24", "203.0.113.7/28", "203.0.113.7/31",
                    "1.2.3.4, 203.0.113.7/24"):
            with self.subTest(raw=raw):
                problem = netutil.validate_cidr_list(raw)
                self.assertIn("host bits", problem or "")
                self.assertIn("203.0.113.7/32", problem)
        # both likely intents are offered when the range itself would be allowed
        self.assertIn("or 203.0.113.0/24 for the whole range", netutil.validate_cidr_list("203.0.113.7/24"))
        # ...but a range too wide to allow is not suggested
        self.assertNotIn("whole range", netutil.validate_cidr_list("203.0.113.7/3"))

    def test_network_addresses_and_single_ips_pass(self):
        for raw in ("203.0.113.0/24", "198.51.100.16/28", "203.0.113.7/32", "203.0.113.7", "10.0.0.0/8"):
            with self.subTest(raw=raw):
                self.assertIsNone(netutil.validate_cidr_list(raw))

    def test_adjacent_slash8s_are_two_slash8s_not_a_slash7(self):
        for raw in ("10.0.0.0/8,11.0.0.0/8", "11.0.0.0/8,12.0.0.0/8", "10.0.0.0/9,10.128.0.0/9,11.0.0.0/8"):
            with self.subTest(raw=raw):
                self.assertIsNone(netutil.validate_cidr_list(raw))
                saved = netutil.normalize_cidr_list(raw)
                self.assertTrue(all(int(c.split("/")[1]) >= 8 for c in saved), saved)
                self.assertIsNone(netutil.validate_cidr_list(saved), "the saved list passes again on the next run")
        self.assertEqual(netutil.normalize_cidr_list("11.0.0.0/8, 10.0.0.0/8, 1.2.3.4"),
                         ["1.2.3.4/32", "10.0.0.0/8", "11.0.0.0/8"])

    def test_wide_ranges_stay_refused(self):
        self.assertIn("Refusing 10.0.0.0/7", netutil.validate_cidr_list("10.0.0.0/7"))
        self.assertIn("more than two /8", netutil.validate_cidr_list("10.0.0.0/8,11.0.0.0/8,12.0.0.0/8"))
        self.assertIn("together cover it", netutil.validate_cidr_list("0.0.0.0/1, 128.0.0.0/1"))
        self.assertIsNotNone(netutil.validate_cidr_list("0.0.0.0/1"))

    def test_setup_flag_check_uses_it(self):
        from cloudseed import cli
        self.assertIn("host bits", cli._allow_list_problem(["203.0.113.7/16"]))
        self.assertIsNone(cli._allow_list_problem("10.0.0.0/8,11.0.0.0/8"))


# ---------------------------------------------------------------- tags (aws#3, azure#6)

class TagCaseTests(unittest.TestCase):
    def test_builtin_keys_in_another_case_set_the_builtin(self):
        for key in ("aws", "azure"):
            c = clouds.get(key)
            tags = c.tags(_cfg(key, tags={"owner": "team-a", "environment": "staging", "PROJECT": "billing"}))
            self.assertEqual((tags["Owner"], tags["Environment"], tags["Project"]), ("team-a", "staging", "billing"))
            self.assertEqual(len({k.lower() for k in tags}), len(tags), f"{key}: no case-duplicate keys: {tags}")
            self.assertEqual(c.check_config(_cfg(key, tags={"owner": "team-a"})), [], key)

    def test_user_keys_differing_in_case_render_once_and_are_refused(self):
        aws = clouds.get("aws")
        cfg = _cfg(tags={"team": "a", "Team": "b"})
        tags = aws.tags(cfg)
        self.assertEqual([k for k in tags if k.lower() == "team"], ["Team"], "the later one wins when rendering")
        self.assertEqual(tags["Team"], "b")
        problems = aws.check_config(cfg)
        self.assertTrue(any("--tag team and --tag Team differ only in case" in p and "--tag team=" in p
                            for p in problems), problems)

    def test_an_emptied_tag_drops_every_spelling(self):
        aws = clouds.get("aws")
        cfg = _cfg(tags={"team": "a", "TEAM": ""})
        self.assertFalse({"team", "TEAM"} & set(aws.tags(cfg)))
        self.assertEqual(aws.check_config(cfg), [], "an emptied duplicate is no conflict")
        self.assertEqual(aws.tags(_cfg(tags={"Owner": "x", "owner": ""}))["Owner"], "alice",
                         "an emptied built-in shows its default again")

    def test_identity_tags_still_win(self):
        tags = clouds.get("aws").tags(_cfg(uid="u1", tags={"managedby": "tf", "cloudseedenvid": "zz"}))
        self.assertEqual((tags["ManagedBy"], tags["CloudseedEnvId"]), ("cloudseed", "u1"))
        self.assertFalse({"managedby", "cloudseedenvid"} & set(tags))

    def test_gcp_labels_follow_the_same_fold(self):
        labels = clouds.get("gcp").tags(_cfg("gcp", tags={"Owner": "Team-A", "owner": "b"}))
        self.assertEqual(labels["owner"], "b")


# ---------------------------------------------------------------- saved values and questions (aws#14, gcp#14)

class TypedValueTests(unittest.TestCase):
    def test_blank_or_missing_means_the_default(self):
        c = clouds.get("aws")
        for v in (None, "", "  "):
            with self.subTest(v=v):
                self.assertIs(c.var_bool(_cfg(vars={"enable_account_baseline": v}), "enable_account_baseline", True), True)
                self.assertEqual(c.var_int(_cfg(vars={"n": v}), "n", 3), 3)
        self.assertEqual(c.var_int(_cfg(), "missing", 7), 7)

    def test_strict_values_still_abort_with_the_fix(self):
        c = clouds.get("aws")
        with quiet(), self.assertRaises(ui.Abort) as cm:
            c.var_bool(_cfg(vars={"x": "maybe"}), "x", False)
        self.assertIn("--var x=VALUE", cm.exception.msg)
        with quiet(), self.assertRaises(ui.Abort) as cm:
            c.var_int(_cfg(vars={"n": "0"}), "n", 2, minimum=1)
        self.assertIn("must be >= 1", cm.exception.msg)
        self.assertEqual(c.var_int(_cfg(vars={"n": "4"}), "n", 2, minimum=1), 4)

    def test_dead_helpers_are_gone(self):
        self.assertFalse(hasattr(base, "slug"))
        self.assertFalse(hasattr(base.Question, "resolve_default"))

    def test_int_questions_carry_their_range(self):
        q = base.Question("az_count", "AZs", 2, kind="int", minimum=1, maximum=5)
        self.assertEqual(q.coerce("3"), 3)
        self.assertIn("must be >= 1", q.problem("0"))
        self.assertIn("must be <= 5", q.problem("6"))
        self.assertIn("must be >= 0", base.Question("n", "N", 0, kind="int").problem("-1"), "no bound = 0 and up")


class IgnoredEnvTests(unittest.TestCase):
    def setUp(self):
        base._ENV_WARNED.clear()
        self.gcp = clouds.get("gcp")
        self.q = self.gcp.question("project_id")

    def tearDown(self):
        base._ENV_WARNED.clear()

    def test_an_invalid_env_value_is_named_once(self):
        with mock.patch.dict(os.environ, {"GOOGLE_PROJECT": "Bad_Proj", "GOOGLE_CLOUD_PROJECT": "",
                                          "CLOUDSDK_CORE_PROJECT": "", "GCLOUD_PROJECT": ""}), \
                mock.patch.object(ui, "warn") as warn:
            self.assertEqual(self.gcp._default(self.q, _cfg("gcp", region="us-central1"), {}), "")
            self.gcp._default(self.q, _cfg("gcp", region="us-central1"), {})
        self.assertEqual(warn.call_count, 1, "said once, however often the question loop runs")
        self.assertIn("Ignoring GOOGLE_PROJECT='Bad_Proj'", warn.call_args[0][0])

    def test_a_later_valid_variable_still_wins(self):
        with mock.patch.dict(os.environ, {"GOOGLE_PROJECT": "Bad_Proj", "GOOGLE_CLOUD_PROJECT": "good-proj-123"}), \
                mock.patch.object(ui, "warn"):
            self.assertEqual(self.gcp._default(self.q, _cfg("gcp", region="us-central1"), {}), "good-proj-123")

    def test_a_valid_value_that_does_not_fit_is_only_mentioned(self):
        zone = self.gcp.question("zone")
        with mock.patch.dict(os.environ, {"CLOUDSDK_COMPUTE_ZONE": "europe-west4-b"}), \
                mock.patch.object(ui, "warn") as warn, mock.patch.object(ui, "info") as info:
            got = self.gcp._default(zone, _cfg("gcp", region="us-central1"), {})
        self.assertTrue(got.startswith("us-central1-"), got)
        warn.assert_not_called()
        self.assertIn("CLOUDSDK_COMPUTE_ZONE", info.call_args[0][0])

    def test_saved_answers_never_consult_the_environment(self):
        with mock.patch.dict(os.environ, {"GOOGLE_PROJECT": "Bad_Proj"}), mock.patch.object(ui, "warn") as warn:
            self.assertEqual(self.gcp._default(self.q, _cfg("gcp"), {"project_id": "saved-proj-1"}), "saved-proj-1")
        warn.assert_not_called()


# ---------------------------------------------------------------- Terraform hints (cli-ux#6, azure#15)

INIT_CHECKSUM = """Initializing provider plugins...
- Reusing previous version of hashicorp/google from the dependency lock file
Error: Failed to install provider

Error while installing hashicorp/google v7.46.1: the current package for
registry.terraform.io/hashicorp/google 7.46.1 doesn't match any of the
checksums previously recorded in the dependency lock file; for more
information: https://developer.hashicorp.com/terraform/language/provider-checksum-verification
"""

PLUGIN_START = """Error: Failed to load plugin schemas

Error while loading schemas for plugin components: Failed to obtain provider schema: Could not load the schema for
provider registry.terraform.io/hashicorp/azurerm: failed to instantiate provider
"registry.terraform.io/hashicorp/azurerm" to obtain schema: Unrecognized remote plugin message: Failed to read any
lines from plugin's stdout
This usually means
  the plugin was not compiled for this architecture,
  the plugin is missing dynamic-link libraries necessary to run,
  the plugin is not executable by this user, or
  the plugin was killed or crashed.
 MachO architecture: CpuArm64
"""

CRASH = """Stack trace from the terraform-provider-aws_v6.0.0_x5 plugin:

panic: runtime error: invalid memory address or nil pointer dereference

Error: The terraform-provider-aws_v6.0.0_x5 plugin crashed!

Error: Plugin did not respond

The plugin encountered an error, and failed to respond to the plugin.(*GRPCProvider).ApplyResourceChange call.
"""


class ExplainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w3tf-"))
        env = mock.patch.dict(os.environ)                     # restored after each test
        env.start()
        self.addCleanup(env.stop)
        for name in ("TF_PLUGIN_CACHE_DIR", "TF_CLI_CONFIG_FILE"):
            os.environ.pop(name, None)
        rc = mock.patch.object(tf, "user_cli_config", return_value=None)   # not this machine's ~/.terraformrc
        rc.start()
        self.addCleanup(rc.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_wrapped_init_checksum_error_names_the_real_root(self):
        root = self.tmp / "gcp-w1" / "bootstrap"
        msg = tf.explain(INIT_CHECKSUM, "init", root)
        self.assertIn(".terraform.lock.hcl", msg)
        self.assertIn(f"delete .terraform.lock.hcl and .terraform in {root}, then re-run", msg)
        self.assertNotIn("<env", msg)
        self.assertNotIn("<workdir>", msg)
        self.assertNotIn("parallel run", msg, "no plugin cache configured: a parallel run cannot be the cause")
        with mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": "/cache/tf"}):
            shared = tf.explain(INIT_CHECKSUM, "init", root)
        self.assertIn("a parallel run sharing the provider plugin cache (TF_PLUGIN_CACHE_DIR=/cache/tf)", shared)
        self.assertIn("if another cloudseed/terraform run is active, wait for it", shared)
        self.assertIn(f"delete .terraform.lock.hcl and .terraform in {root}", shared)
        # the validate wording, and terraform's coloured box gutter
        boxed = "╷\n│ Error: Inconsistent dependency lock file\n│ \n│ does not match any of the\n│ checksums recorded\n╵"
        self.assertIn(".terraform.lock.hcl", tf.explain(boxed, "validate", root))

    def test_the_lock_id_and_root_are_filled(self):
        out = ("╷\n│ Error: Error acquiring the state lock\n│ \n│ Lock Info:\n│   ID:        3a1c9d2e-1111-2222-3333-4444"
               "55556666\n│   Path:      b/stack.tfstate\n╵")
        msg = tf.explain(out, "plan", "/w/aws-dev/stack")
        self.assertIn("terraform -chdir=/w/aws-dev/stack force-unlock 3a1c9d2e-1111-2222-3333-444455556666", msg)
        self.assertIn("-chdir=<workdir>/stack", tf.explain(out, "plan"), "without a root: a readable placeholder")

    def test_env_is_filled_from_the_roots_config(self):
        wd = self.tmp / "custom dir"
        (wd / "stack").mkdir(parents=True)
        (wd / "config.json").write_text(json.dumps({"cloud": "aws", "env": "prod2"}))
        msg = tf.explain("failed to get shared config profile, missing", "plan", wd / "stack")
        self.assertIn("cloudseed setup aws --env prod2 --profile", msg)
        (wd / "dry-run" / "stack").mkdir(parents=True)
        self.assertIn("--env prod2", tf.explain("SharedConfigProfileNotExist", "validate", wd / "dry-run" / "stack"))

    def test_plugin_start_failure_and_crash_get_their_own_hints(self):
        start = tf.explain(PLUGIN_START, "validate", "/w/stack")
        self.assertIn("failed to start", start)
        self.assertIn("run out of memory", start)
        self.assertIn("delete /w/stack/.terraform and re-run", start)
        self.assertNotIn("plugin cache", start, "no cache configured: not blamed on one")
        with mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": "/cache/tf"}):
            shared = tf.explain(PLUGIN_START, "validate", "/w/stack")
        self.assertIn("another terraform or cloudseed run using the same provider plugin cache "
                      "(TF_PLUGIN_CACHE_DIR=/cache/tf)", shared)
        self.assertIn("give each its own TF_PLUGIN_CACHE_DIR", shared)
        crash = tf.explain(CRASH, "apply", "/w/stack")
        self.assertIn("provider crashed", crash)
        self.assertNotIn("plugin cache", crash)
        # troubleshoot shows the hints unfilled: they must read well as they are
        for _, what, fix in tf.HINTS:
            self.assertNotRegex(what + fix, r"<(root|startup|cache)[^>]*>")

    def test_plugin_cache_from_the_users_cli_config(self):
        rc = self.tmp / "tfrc"
        rc.write_text('plugin_cache_dir = "/home/u/.terraform.d/plugin-cache"\n')
        with mock.patch.object(tf, "user_cli_config", return_value=rc):
            self.assertEqual(f"plugin_cache_dir /home/u/.terraform.d/plugin-cache in {rc}", tf.plugin_cache())
            self.assertIn("plugin_cache_dir /home/u/", tf.explain(PLUGIN_START, "validate"))
        rc.write_text('# plugin_cache_dir = "/commented/out"\n')
        with mock.patch.object(tf, "user_cli_config", return_value=rc):
            self.assertIsNone(tf.plugin_cache())
        rc.write_text('{"plugin_cache_dir": "/json/cache", "disable_checkpoint": true}\n')   # the JSON syntax
        with mock.patch.object(tf, "user_cli_config", return_value=rc):
            self.assertEqual(f"plugin_cache_dir /json/cache in {rc}", tf.plugin_cache())
        self.assertIsNone(tf.plugin_cache())

    def test_a_missing_provider_is_not_blamed_on_the_cache(self):
        out = ('Error: failed to read schema for module.stack.vm in registry.local/cloudseed/vmdesktop: failed to '
               'instantiate provider "registry.local/cloudseed/vmdesktop" to obtain schema: unavailable provider '
               '"registry.local/cloudseed/vmdesktop"')
        msg = tf.explain(out, "plan", "/w/stack")
        self.assertIn("not installed in /w/stack/.terraform", msg)
        self.assertIn("cloudseed install vmware-provider", msg)

    def test_gcp_project_errors(self):
        msg = tf.explain("googleapi: Error 404: The resource 'projects/my-proj-123' was not found, notFound", "plan")
        self.assertIn("project does not exist", msg)
        self.assertIn("gcloud projects describe my-proj-123", msg)
        # a resource inside the project that is gone is not the project
        self.assertNotIn("project does not exist", tf.explain(
            "googleapi: Error 404: The resource 'projects/my-proj-123/global/networks/n1' was not found", "plan"))
        self.assertIn("lacks permissions", tf.explain(
            "googleapi: Error 403: Required 'compute.networks.create' permission for 'projects/p1', forbidden", "apply"))

    def test_hints_stay_line_local(self):
        # an unrelated "already exists" after a successful GuardDuty create is not a GuardDuty conflict
        out = ("module.stack.aws_guardduty_detector.this[0]: Creation complete after 1s [id=abc]\n"
               "Error: creating S3 Bucket (cs-w3-state): BucketAlreadyExists")
        self.assertIn("same name already exists", tf.explain(out, "apply"))

    def test_terraform_errors_carry_the_workdir(self):
        root = self.tmp / "stack"
        root.mkdir()
        with mock.patch.object(tf.deps, "find", return_value="/usr/bin/terraform"):
            t = tf.Terraform(root)
        failed = subprocess.CompletedProcess([], 1, "", INIT_CHECKSUM)
        with mock.patch.object(t, "_run_captured", return_value=failed), mock.patch.object(t, "_platform_guard"), \
                quiet():
            with self.assertRaises(tf.TerraformError) as cm:
                t.init()
        self.assertIn(f"delete .terraform.lock.hcl and .terraform in {root}", str(cm.exception))

    def test_plan_for_apply_docstring_matches_preflight(self):
        doc = tf.Terraform.plan_for_apply.__doc__
        self.assertIn("never adopts", doc)
        self.assertNotIn("(e.g. a\n        GuardDuty detector) are adopted", doc)


# ---------------------------------------------------------------- stale workdirs.json entries (cli-lifecycle#21)

class StaleWorkdirTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w3wd-"))
        self.index_before = paths._load_index()

    def tearDown(self):
        paths._save_index(self.index_before)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _indexed(self, env_id: str, d: Path, live: bool) -> None:
        d.mkdir(parents=True, exist_ok=True)
        if live:
            cloud, _, name = env_id.partition("-")
            (d / "config.json").write_text(json.dumps({"cloud": cloud, "env": name}))
        index = paths._load_index()
        index[env_id] = str(d.resolve())
        paths._save_index(index)

    def test_claiming_a_directory_forgets_the_stale_entries_it_collides_with(self):
        gone = self.tmp / "wd" / "with space"
        self._indexed("aws-w3gone", gone, live=False)
        inner = self.tmp / "outer"
        self._indexed("aws-w3inner", inner / "sub", live=False)
        elsewhere = self.tmp / "unmounted"
        self._indexed("aws-w3away", elsewhere, live=False)
        shutil.rmtree(gone)
        shutil.rmtree(inner / "sub")
        paths.Env("aws", "w3new").set_workdir(gone)
        paths.Env("aws", "w3outer").set_workdir(inner)
        index = paths._load_index()
        self.assertEqual(index.get("aws-w3new"), str(gone.resolve()))
        self.assertNotIn("aws-w3gone", index, "the directory is someone else's now: the old claim is forgotten")
        self.assertNotIn("aws-w3inner", index, "a stale claim inside the new directory goes too")
        self.assertIn("aws-w3away", index, "stale entries elsewhere stay (an unmounted volume looks the same)")
        self.assertEqual(paths.Env("aws", "w3gone").dir, paths.ENVS_DIR / "aws-w3gone")

    def test_a_directory_that_still_holds_terraform_state_is_not_released(self):
        # config.json lost (deleted by hand), local state still there: taking the directory over would plan against
        # that state, so the claim stays and the directory (or one inside it) is refused, not silently reassigned
        kept = self.tmp / "kept"
        self._indexed("aws-w3state", kept, live=False)
        (kept / "stack").mkdir()
        (kept / "stack" / "terraform.tfstate").write_text("{}")
        self.assertFalse(paths.abandoned_workdir(kept))
        for target in (kept, kept / "sub"):
            with self.subTest(target=target):
                self.assertIn("of aws-w3state", paths.workdir_problem(target, "aws-w3taker") or "")
                with self.assertRaises(ui.Abort):
                    paths.Env("aws", "w3taker").set_workdir(target)
        index = paths._load_index()
        self.assertEqual(index.get("aws-w3state"), str(kept.resolve()))
        self.assertNotIn("aws-w3taker", index)
        shutil.rmtree(kept / "stack")                          # moved aside for real: now it is released
        self.assertTrue(paths.abandoned_workdir(kept))
        self.assertIsNone(paths.workdir_problem(kept, "aws-w3taker"))

    def test_live_environments_are_never_pruned(self):
        live = self.tmp / "live"
        self._indexed("aws-w3live", live, live=True)
        with self.assertRaises(ui.Abort):
            paths.Env("aws", "w3other").set_workdir(live)
        self.assertEqual(paths._load_index().get("aws-w3live"), str(live.resolve()))

    def test_broken_config_advice_names_the_index_entry(self):
        d = self.tmp / "broken"
        self._indexed("aws-w3broken", d, live=True)
        (d / "config.json").write_text("{not json")
        with self.assertRaises(paths.ConfigError) as cm:
            paths.Env("aws", "w3broken").load()
        self.assertIn(f'remove the "aws-w3broken" entry from {paths.WORKDIRS_INDEX}', str(cm.exception))
        plain = paths.Env("aws", "w3plainbroken")
        plain.dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, plain.dir, True)
        plain.config_path.write_text("[]")
        with self.assertRaises(paths.ConfigError) as cm:
            plain.load()
        self.assertNotIn("workdirs.json", str(cm.exception))

    def test_create_dirs_keeps_a_users_directory_permissions(self):
        d = self.tmp / "proj"
        d.mkdir()
        os.chmod(d, 0o755)
        e = paths.Env("aws", "w3perm")
        e.set_workdir(d)
        self.assertEqual(d.stat().st_mode & 0o777, 0o755)
        self.assertEqual((d / "ssh").stat().st_mode & 0o777, 0o700)


# ---------------------------------------------------------------- the ansible text scan (lead-dsstore)

class AnsibleTextScanTests(unittest.TestCase):
    def test_os_debris_and_binaries_are_skipped(self):
        sys.path.insert(0, str(ROOT / "tests"))
        try:
            mod = importlib.import_module("test_fix_ansible")
        finally:
            sys.path.remove(str(ROOT / "tests"))
        tmp = Path(tempfile.mkdtemp(prefix="cs-w3ans-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "ansible" / "roles" / "x").mkdir(parents=True)
        (tmp / "ansible" / "site.yml").write_text("- hosts: all\n")
        (tmp / "ansible" / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1\xff\xfe")
        (tmp / "ansible" / "roles" / "x" / "._main.yml").write_bytes(b"\x00\x05\x16\x07\xff")
        (tmp / "ansible" / "roles" / "x" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\xff")
        (tmp / "ansible" / "roles" / "x" / "bad.yml").write_bytes(b"\xff\xfe\x00")
        (tmp / "ansible" / "roles" / "x" / "files").mkdir()
        (tmp / "ansible" / "roles" / "x" / "files" / "sshd.conf").write_text("PermitRootLogin no\n")
        with mock.patch.object(mod, "REPO", tmp), mock.patch.object(mod, "ANSIBLE", tmp / "ansible"):
            files = mod.ansible_text_files()
        # text files with any suffix are still checked; only debris and binaries are skipped
        self.assertEqual(sorted(files), ["ansible/roles/x/files/sshd.conf", "ansible/site.yml"])


if __name__ == "__main__":
    unittest.main()
