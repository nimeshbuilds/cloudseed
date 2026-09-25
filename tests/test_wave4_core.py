"""Regression tests for the wave-4 core items: Terraform hints that name the working directory and the failing root
(state lock, marketplace import, lock-file checksums split from an inconsistent lock file), the AWS hints (Access
Analyzer quota, allowed_account_ids, the profile wording, a second environment's GuardDuty), plan_for_apply switching
off an existing default-on singleton and planning again, and questions that depend on another answer
(Question.depends_on / follows). Stdlib only; no network, no cloud."""
import contextlib
import inspect
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, reconcile, tf, troubleshoot, ui  # noqa: E402
from cloudseed.clouds import base  # noqa: E402


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        yield out, err


@contextlib.contextmanager
def non_interactive(flag: bool = True):
    old = ui.NON_INTERACTIVE
    ui.NON_INTERACTIVE = flag
    try:
        yield
    finally:
        ui.NON_INTERACTIVE = old


CHECKSUM = ("Error: Required plugins are not installed\n\nThe installed provider plugins are not consistent with the "
            "packages selected in the dependency lock file:\n  - registry.terraform.io/hashicorp/tls: the cached package "
            "for registry.terraform.io/hashicorp/tls 4.4.1 (in .terraform/providers) does not match any of the "
            "checksums recorded in the dependency lock file\n")
INCONSISTENT = ("Error: Inconsistent dependency lock file\n\nThe following dependency selections recorded in the lock "
                "file are inconsistent with the current configuration:\n  - provider registry.terraform.io/hashicorp/"
                "tls: required by this configuration but no version is selected\n")
STATE_LOCK = "Error: Error acquiring the state lock\n\nLock Info:\n  ID:        3a1c9d2e-1111-2222\n"


class _NoCache(unittest.TestCase):
    """No plugin cache from this machine's environment or ~/.terraformrc."""

    def setUp(self):
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for name in ("TF_PLUGIN_CACHE_DIR", "TF_CLI_CONFIG_FILE"):
            os.environ.pop(name, None)
        rc = mock.patch.object(tf, "user_cli_config", return_value=None)
        rc.start()
        self.addCleanup(rc.stop)
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4tf-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def env_dir(self, name="dev") -> Path:
        d = self.tmp / "envs" / f"aws-{name}"
        (d / "stack").mkdir(parents=True)
        (d / "bootstrap").mkdir()
        (d / "config.json").write_text(json.dumps({"cloud": "aws", "env": name}))
        return d


# ---------------------------------------------------------------- paths in the hints (a2-ops#11)

class HintPathTests(_NoCache):
    def test_no_hint_uses_the_old_placeholders(self):
        for _, what, fix in tf.HINTS:
            self.assertNotIn("<env dir>", what + fix)
            self.assertNotIn("<env>/", what + fix, "a path is <workdir>/..., never '<env name>/stack'")
            self.assertNotIn("another platform", what + fix)
        for what, fix in tf._WITHOUT_CACHE.values():
            self.assertNotIn("<env dir>", what + fix)
            self.assertNotIn("another platform", what + fix)

    def test_the_failing_root_is_named_at_failure_time(self):
        d = self.env_dir()
        for root in (d / "stack", d / "bootstrap"):
            with self.subTest(root=root.name):
                msg = tf.explain(CHECKSUM, "init", root)
                self.assertIn(f"delete .terraform.lock.hcl and .terraform in {root}, then re-run", msg)
                self.assertNotIn("<workdir>", msg)
                self.assertNotIn("Terraform root that failed", msg)
        lock = tf.explain(STATE_LOCK, "plan", d / "stack")
        self.assertIn(f"terraform -chdir={d / 'stack'} force-unlock 3a1c9d2e-1111-2222", lock)
        sub = "0f0e0d0c-0000-1111-2222-333344445555"
        market = tf.explain(f'Error: A resource with the ID "/subscriptions/{sub}/providers/Microsoft.MarketplaceOrdering/'
                            'agreements/canonical/offers/x/plans/y" already exists', "apply", d / "stack")
        self.assertIn(f"terraform -chdir={d / 'stack'} import", market)
        self.assertIn(f"/subscriptions/{sub}/providers/", market)

    def test_a_dry_run_copy_is_the_root_and_the_env_is_its_parent(self):
        d = self.env_dir("dry1")
        root = d / "dry-run" / "stack"
        root.mkdir(parents=True)
        self.assertEqual(tf._env_of(root), (d, "dry1"))
        self.assertIn(f"-chdir={root} force-unlock", tf.explain(STATE_LOCK, "plan", root))
        self.assertIn("--env dry1 --profile", tf.explain("SharedConfigProfileNotExist", "plan", root))
        self.assertEqual(tf._env_of(self.tmp / "nowhere" / "stack"), (self.tmp / "nowhere", None))

    def test_a_config_above_a_custom_workdir_never_names_the_env(self):
        # a custom --workdir inside a project whose own config.json has an "env": not this environment's
        project = self.tmp / "project"
        (project / "infra" / "stack").mkdir(parents=True)
        (project / "config.json").write_text(json.dumps({"env": "production"}))
        root = project / "infra" / "stack"
        self.assertEqual(tf._env_of(root), (project / "infra", None))
        msg = tf.explain("SharedConfigProfileNotExist", "plan", root)
        self.assertNotIn("--env production", msg)
        self.assertIn("--env <env>", msg)

    def test_a_root_with_spaces_is_quoted_in_commands_only(self):
        d = self.tmp / "my envs" / "aws-dev"
        (d / "stack").mkdir(parents=True)
        (d / "config.json").write_text(json.dumps({"cloud": "aws", "env": "dev"}))
        root = d / "stack"
        lock = tf.explain(STATE_LOCK, "plan", root)
        self.assertIn(f"terraform -chdir='{root}' force-unlock 3a1c9d2e-1111-2222", lock)
        market = tf.explain("Error: MarketplaceOrdering/agreements/canonical/offers/x already exists", "apply", root)
        self.assertIn(f"terraform -chdir='{root}' import", market)
        # prose names the plain path
        self.assertIn(f"delete .terraform.lock.hcl and .terraform in {root}, then re-run", tf.explain(CHECKSUM, "init", root))
        self.assertIn(f"not installed in {root}/.terraform", tf.explain('Error: unavailable provider "x"', "plan", root))

    def test_without_a_root_the_placeholders_read_well(self):
        msg = tf.explain(STATE_LOCK, "plan")
        self.assertIn("-chdir=<workdir>/stack force-unlock", msg)
        msg = tf.explain(CHECKSUM, "validate")
        self.assertIn("(<workdir>/stack or <workdir>/bootstrap)", msg)

    def test_troubleshoot_fills_the_working_directory(self):
        wd = self.tmp / "custom workdir"
        log = self.tmp / "x.log"
        log.write_text(CHECKSUM + "\n" + STATE_LOCK)
        hits = troubleshoot._scan_log(log, "aws", "dev", workdir=wd)
        text = " ".join(f.what + " " + f.fix for f in hits)
        self.assertIn(f"-chdir='{wd}/stack' force-unlock", text)        # a command quotes it (the path has a space)
        self.assertIn(f"({wd}/stack or {wd}/bootstrap)", text)       # prose names the plain path
        self.assertIn("plugin cache changed", text)
        self.assertNotIn("<workdir>", text)


# ---------------------------------------------------------------- the lock-file hints

class LockFileHintTests(_NoCache):
    def test_a_checksum_mismatch_is_not_called_a_missing_provider(self):
        # plan/validate report the mismatch under "Required plugins are not installed"
        msg = tf.explain(CHECKSUM, "validate", self.env_dir() / "stack")
        self.assertIn("no longer match the hashes in .terraform.lock.hcl", msg)
        self.assertIn("another OS/CPU", msg)
        self.assertNotIn("is not installed", msg)
        self.assertNotIn("parallel run", msg, "no plugin cache configured")
        with mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": "/cache/tf"}):
            shared = tf.explain(CHECKSUM, "validate", self.env_dir("dev2") / "stack")
        self.assertIn("Either the plugin cache changed - a parallel run sharing the provider plugin cache "
                      "(TF_PLUGIN_CACHE_DIR=/cache/tf) rewrote a cached provider - or the lock file", shared)
        self.assertIn("wait for it and re-run; if it fails the same way", shared)

    def test_the_hint_for_this_machine_is_shared_with_troubleshoot(self):
        entry = next(h for h in tf.HINTS if h[0] == tf.LOCK_MISMATCH)
        what, fix = tf._for_this_machine(*entry)
        self.assertNotIn("parallel run", what + fix, "no plugin cache configured: the variant without one")
        self.assertIn("another OS/CPU", what)
        with mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": "/cache/tf"}):
            what, fix = tf._for_this_machine(*entry)
        self.assertIn("(TF_PLUGIN_CACHE_DIR=/cache/tf)", what)
        self.assertNotIn(tf.ANY_CACHE, what + fix)
        plain = next(h for h in tf.HINTS if "AWS account ID" in h[0])
        self.assertEqual(tf._for_this_machine(*plain), plain[1:])

    def test_an_inconsistent_lock_file_has_its_own_hint(self):
        root = self.env_dir() / "bootstrap"
        msg = tf.explain(INCONSISTENT, "validate", root)
        self.assertIn(f"The dependency lock file (.terraform.lock.hcl) of {root} does not select a provider", msg)
        self.assertIn("cloudseed runs terraform init first", msg)
        self.assertNotIn("checksum", msg.lower())
        self.assertNotIn("hashes", msg)
        # the checksum text wins when both appear (terraform's validate wording)
        both = tf.explain("Error: Inconsistent dependency lock file\n" + CHECKSUM, "validate", root)
        self.assertIn("no longer match the hashes", both)

    def test_a_missing_provider_still_names_the_root(self):
        out = 'Error: unavailable provider "registry.local/cloudseed/vmdesktop"'
        self.assertIn("not installed in /w/stack/.terraform", tf.explain(out, "plan", "/w/stack"))
        missing = ("Error: Required plugins are not installed\n\nThe installed provider plugins are not consistent with "
                   "the packages selected in the dependency lock file:\n  - registry.terraform.io/hashicorp/aws: there is "
                   "no package for registry.terraform.io/hashicorp/aws 6.0.0 cached in .terraform/providers\n")
        self.assertIn("not installed in /w/stack/.terraform", tf.explain(missing, "plan", "/w/stack"))

    def test_troubleshoot_lists_only_the_checksum_finding_for_a_checksum_mismatch(self):
        # terraform reports the mismatch under "Required plugins are not installed"; troubleshoot lists every match
        log = self.tmp / "x.log"
        log.write_text(CHECKSUM)
        whats = [f.what for f in troubleshoot._scan_log(log, "aws", "dev", workdir=self.tmp)]
        self.assertTrue(any("no longer match the hashes" in w for w in whats), whats)
        self.assertFalse(any("is not installed" in w for w in whats), whats)


# ---------------------------------------------------------------- AWS hints (aws needs)

class AwsHintTests(_NoCache):
    def test_access_analyzer_quota(self):
        for err in ("Error: creating IAM Access Analyzer Analyzer (cs-dev): operation error AccessAnalyzer: "
                    "CreateAnalyzer, https response error StatusCode: 402, RequestID: 1, ServiceQuotaExceededException: "
                    "You have reached the maximum number of analyzers",
                    "Error: creating IAM Access Analyzer Analyzer (cs-dev): ConflictException: analyzer already exists"):
            with self.subTest(err=err[-30:]):
                msg = tf.explain(err, "apply")
                self.assertIn("only one account-level analyzer per region", msg)
                self.assertIn("--var enable_access_analyzer=false", msg)
                self.assertNotIn("service quota/limit was hit", msg)
                self.assertNotIn("same name already exists", msg)
        # other quotas keep the generic hint
        self.assertIn("service quota/limit was hit", tf.explain("Error: VcpuLimitExceeded: You have requested", "apply"))

    def test_another_account_is_named(self):
        d = self.env_dir("acct")
        msg = tf.explain("Error: AWS account ID not allowed: 111122223333", "plan", d / "stack")
        self.assertIn("another AWS account", msg)
        self.assertIn("allowed_account_ids", msg)
        self.assertIn("cloudseed setup aws --env acct --profile NAME", msg)
        self.assertIn("unset AWS_PROFILE", msg)
        self.assertNotIn("lacks permissions", msg)
        self.assertNotIn("credentials are missing", msg)

    def test_profile_hint_is_true_with_and_without_a_saved_profile(self):
        msg = tf.explain("failed to get shared config profile, prod", "plan", self.env_dir("prof") / "stack")
        self.assertIn("cloudseed setup aws --env prof --profile <existing>", msg)
        self.assertIn("A profile saved with the environment wins over AWS_PROFILE", msg)
        self.assertIn("the AWS_PROFILE set in your shell (or saved with `cloudseed creds`) is the one missing", msg)
        self.assertNotIn("exporting AWS_PROFILE does not change it", msg)

    def test_guardduty_names_the_second_environment_case(self):
        msg = tf.explain("Error: creating GuardDuty Detector: BadRequestException: The request is rejected because a "
                         "detector already exists", "apply")
        self.assertIn("--var enable_guardduty=false", msg)
        self.assertIn("--var enable_regional_baseline=false", msg)

    def test_defender_names_an_earlier_destroy(self):
        msg = tf.explain("Error: the pricing tier of this subscription is not Free", "apply")
        self.assertIn("left on by an earlier destroy of this environment", msg)


# ---------------------------------------------------------------- plan_for_apply and existing singletons (ops#10)

def _terraform(workdir: Path) -> tf.Terraform:
    t = tf.Terraform.__new__(tf.Terraform)
    t.workdir, t.binary = workdir, "terraform"
    t.plan = mock.Mock()
    return t


def _singleton(auto=True):
    found = [("aws_guardduty_detector", "module.stack.module.baseline.aws_guardduty_detector.this[0]", ["det-1"])]
    return reconcile.SingletonExists("GuardDuty is already enabled ... Nothing was applied.\n  Fix: cloudseed setup "
                                     "aws --env dev --var enable_guardduty=false",
                                     {"enable_guardduty": False}, auto=auto, found=found)


class PlanForApplyTests(unittest.TestCase):
    def setUp(self):
        self.wd = Path(tempfile.mkdtemp(prefix="cs-w4plan-"))
        self.addCleanup(shutil.rmtree, self.wd, True)

    def test_a_default_on_singleton_is_switched_off_and_planned_again(self):
        t = _terraform(self.wd)
        cfg = {"env": "dev", "vars": {}}
        rendered = []
        with mock.patch.object(reconcile, "planned_values", return_value={}), \
                mock.patch.object(reconcile, "preflight", side_effect=[_singleton(), []]) as preflight, quiet() as (out, _):
            t.plan_for_apply("aws", cfg, render=lambda c: rendered.append(dict(c.get("extra_vars") or {})))
        self.assertEqual(cfg["extra_vars"], {"enable_guardduty": False})
        self.assertEqual(rendered, [{"enable_guardduty": False}], "the stack is rendered with the switched-off variable")
        self.assertEqual(t.plan.call_count, 2, "planned again after rendering")
        self.assertEqual(preflight.call_count, 2, "the new plan is checked too")
        self.assertIn("det-1", out.getvalue())
        self.assertIn("enable_guardduty=false saved with the environment", out.getvalue())

    def test_without_render_or_when_asked_for_it_stops(self):
        for render, auto in ((None, True), (lambda c: None, False)):
            with self.subTest(render=render is not None, auto=auto):
                t = _terraform(self.wd)
                cfg = {"env": "dev", "vars": {}}
                with mock.patch.object(reconcile, "planned_values", return_value={}), \
                        mock.patch.object(reconcile, "preflight", side_effect=_singleton(auto)), quiet(), \
                        self.assertRaises(tf.TerraformError) as cm:
                    t.plan_for_apply("aws", cfg, render=render)
                self.assertIn("--var enable_guardduty=false", str(cm.exception))
                self.assertNotIn("extra_vars", cfg, "nothing is switched off behind the user's back")
                self.assertEqual(t.plan.call_count, 1)

    def test_switching_off_gives_up_after_the_limit(self):
        t = _terraform(self.wd)
        render = mock.Mock()
        with mock.patch.object(reconcile, "planned_values", return_value={}), \
                mock.patch.object(reconcile, "preflight", side_effect=lambda *a: (_ for _ in ()).throw(_singleton())), \
                quiet(), self.assertRaises(reconcile.SingletonExists):
            t.plan_for_apply("aws", {"env": "dev", "vars": {}}, render=render)
        self.assertEqual(render.call_count, tf.Terraform.SWITCH_OFF_ROUNDS)

    def test_adopted_objects_still_plan_again(self):
        t = _terraform(self.wd)
        with mock.patch.object(reconcile, "planned_values", return_value={}), \
                mock.patch.object(reconcile, "preflight", side_effect=[_singleton(), ["module.stack.x"]]), quiet():
            t.plan_for_apply("aws", {"env": "dev", "vars": {}}, render=lambda c: None)
        self.assertEqual(t.plan.call_count, 3)          # first plan, after the switch-off, after the adoption

    def test_apply_reconciled_passes_render_on_when_it_plans_itself(self):
        t = _terraform(self.wd)
        render = object()
        with mock.patch.object(t, "plan_for_apply") as pfa, \
                mock.patch.object(reconcile, "planned_values", return_value={}), \
                mock.patch.object(t, "run", return_value=mock.Mock(returncode=0)):
            t.apply_reconciled("aws", {}, render=render)
        self.assertIs(pfa.call_args.kwargs["render"], render)

    def test_callers_and_fakes_can_pass_render(self):
        self.assertIn("render", inspect.signature(tf.Terraform.plan_for_apply).parameters)
        self.assertIn("render", inspect.signature(tf.Terraform.apply_reconciled).parameters)
        self.assertFalse(hasattr(tf.Terraform, "has_state"), "has_state had no callers")


# ---------------------------------------------------------------- questions that depend on another answer (aws)

def _args(**kw):
    ns = mock.Mock(spec=[])
    for k in ("project_id", "zone", "ssh_username", "subscription_id", "admin_username", "profile"):
        setattr(ns, k, kw.get(k))
    return ns


class Probe(base.Cloud):
    key = "probe"
    questions = [
        base.Question("enable_baseline", "Manage the baseline?", True, kind="bool"),
        base.Question("enable_hub", "Enable the hub?", False, kind="bool", depends_on="enable_baseline"),
        base.Question("hub_level", "Hub level", "basic", choices=("basic", "full"), depends_on="enable_baseline"),
        base.Question("enable_vpn", "VPN?", False, kind="bool"),
        base.Question("vpn_type", "VPN type", "openvpn", choices=("openvpn", "tailscale")),
    ]


class DependsOnTests(unittest.TestCase):
    def collect(self, overrides=None, existing=None, advanced=False, answer=True):
        asked = []

        def ask_bool(q, d):
            asked.append(q)
            return answer

        def ask(q, d=None, **k):
            asked.append(q)
            return d
        with non_interactive(False), mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "ask", side_effect=ask), mock.patch.object(ui, "ask_bool", side_effect=ask_bool), \
                quiet():
            out = Probe().collect_vars(_args(), existing or {}, {"region": "r"}, advanced, overrides or {})
        return out, asked

    def test_a_dependent_question_is_asked_only_while_its_parent_is_yes(self):
        out, asked = self.collect(overrides={"enable_baseline": False, "enable_vpn": False})
        self.assertNotIn("Enable the hub?", asked)
        self.assertNotIn("Hub level", asked)
        self.assertEqual((out["enable_hub"], out["hub_level"]), (False, "basic"), "kept at the default, not dropped")
        out, asked = self.collect(overrides={"enable_baseline": True, "enable_vpn": False})
        self.assertIn("Enable the hub?", asked)
        self.assertIn("Hub level", asked)
        self.assertIs(out["enable_hub"], True)

    def test_a_saved_answer_of_an_unasked_question_is_kept(self):
        out, _ = self.collect(overrides={"enable_baseline": "no", "enable_vpn": "no"},
                              existing={"enable_hub": True, "hub_level": "full"})
        self.assertEqual((out["enable_hub"], out["hub_level"]), (True, "full"))

    def test_the_implied_parents_still_apply(self):
        _, asked = self.collect(overrides={"enable_baseline": False, "enable_vpn": False})
        self.assertNotIn("VPN type", asked)
        _, asked = self.collect(overrides={"enable_baseline": False, "enable_vpn": True})
        self.assertIn("VPN type", asked)
        q = base.Question("kubernetes_node_size", "size")
        self.assertEqual(q.parent(), "enable_kubernetes")
        self.assertTrue(q.unused({"enable_kubernetes": "false"}))
        self.assertFalse(q.unused({"enable_kubernetes": "yes"}))
        self.assertEqual(base.Question("enable_kubernetes", "k8s?", kind="bool").parent(), "")
        self.assertEqual(base.Question("x", "x", depends_on="x").parent(), "", "a question never depends on itself")

    def test_unused_reads_saved_strings(self):
        q = base.Question("enable_hub", "hub", False, kind="bool", depends_on="enable_baseline")
        for value, off in ((True, False), ("yes", False), ("1", False), (False, True), ("no", True), ("", True),
                           (None, True), ("maybe", True)):
            with self.subTest(value=value):
                self.assertEqual(q.unused({"enable_baseline": value}), off)
        self.assertTrue(q.unused({}))

    def test_a_missing_parent_answer_counts_as_the_parents_default(self):
        # a configuration saved before the parent question existed (enable_regional_baseline follows the account-wide
        # answer): the feature is on by default, so its sub-setting is in use
        class Follower(base.Cloud):
            key = "follower"
            questions = [
                base.Question("enable_account", "Account?", True, kind="bool"),
                base.Question("enable_regional", "Regional?",
                              lambda cfg: base.as_bool((cfg.get("vars") or {}).get("enable_account", True)),
                              kind="bool", follows="enable_account"),
                base.Question("enable_hub", "Hub?", False, kind="bool", depends_on="enable_regional"),
            ]
        cloud, hub = Follower(), Follower.questions[2]
        self.assertTrue(hub.unused({}), "Question.unused alone: an unknown parent is off")
        self.assertFalse(cloud.unused(hub, {"vars": {}}))
        self.assertFalse(cloud.unused(hub, {"vars": {"enable_account": "yes", "enable_regional": ""}}))
        self.assertTrue(cloud.unused(hub, {"vars": {"enable_account": False}}))
        self.assertTrue(cloud.unused(hub, {"vars": {"enable_account": True, "enable_regional": "no"}}))
        self.assertFalse(cloud.unused(Follower.questions[0], {"vars": {}}), "no parent: always in use")
        # the implied parents default to off, as before
        vpn = base.Question("vpn_type", "VPN type", "openvpn")
        self.assertTrue(Probe().unused(vpn, {"vars": {}}))
        self.assertFalse(Probe().unused(vpn, {"vars": {"enable_vpn": "true"}}))

    def test_follows_and_depends_on_are_constructor_fields(self):
        q = base.Question("enable_regional_baseline", "Regional?", True, kind="bool",
                          follows="enable_account_baseline")
        self.assertEqual((q.follows, q.depends_on), ("enable_account_baseline", ""))
        self.assertEqual(base.Question("a", "b").follows, "")
        # the AWS adapter's regional question still carries what it follows (set as an attribute or a field)
        self.assertEqual(clouds.get("aws").question("enable_regional_baseline").follows, "enable_account_baseline")

    def test_the_real_clouds_keep_their_behaviour(self):
        cfg = {"region": "us-east-1", "workdir": tempfile.mkdtemp()}
        with non_interactive(), quiet():
            out = clouds.get("aws").collect_vars(_args(), {}, cfg, False, {"enable_vpn": False})
        self.assertEqual(out["vpn_type"], "openvpn")
        self.assertIs(out["enable_security_hub"], False)


if __name__ == "__main__":
    unittest.main()
