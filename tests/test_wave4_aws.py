"""Regression tests for the wave-4 AWS changes other groups asked for, and the round-3 leftovers:

- a2-aws#3: AWS's own tag rules (AWS.tag_problem) refuse before anything is saved what IAM, S3 or GuardDuty would
  only refuse part-way through an apply; a --tag Environment=... reaches every resource (terraform/aws/main.tf).
- a2-aws#14: saved answers are read with Cloud.var_bool / var_int (a blank value is the default, never a silent
  False), and network_problems names an unreadable subnet_newbits / create_data_subnets instead of passing it.
- the questions carry their ranges (az_count 1-5, kubernetes_node_count >= 1), and the node group minimum is never
  lowered to fit a count; vpn_port and subnet_newbits are validated by the stack.
- (switching a baseline half off on a deployed environment: setup and apply forget the account/region settings the plan
  would delete instead of deleting them - cli._kept_deletes, from AWS.keep_on_destroy - so the adapter adds no warning
  of its own that would say otherwise.)

Fast and offline: the adapter is exercised directly, the Terraform is checked as text (the plan-level behaviour is in
terraform/aws/tests/*.tftest.hcl, run with CLOUDSEED_TF_TESTS=1: tests.test_fix_core.TerraformModuleTests).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, ui  # noqa: E402
from cloudseed.clouds import aws as aws_mod, base  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform" / "aws"


def _read(rel: str) -> str:
    return (TF / rel).read_text()


def _block(text: str, header: str) -> str:
    """The brace-balanced HCL block starting at `header`."""
    start = text.index(header)
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError(f"unbalanced block {header}")


def _cfg(workdir: str = "", extra=None, tags=None, **variables) -> dict:
    return {"cloud": "aws", "name": "acme", "env": "dev", "region": "us-west-2", "network_cidr": "10.0.0.0/16",
            "allowed_ssh_cidrs": ["203.0.113.5/32"], "ssh_public_key": "ssh-ed25519 AAAA test", "owner": "me",
            "workdir": workdir, "vars": variables, "extra_vars": dict(extra or {}), "tags": dict(tags or {}),
            "platform_prereqs": []}


@contextlib.contextmanager
def _captured():
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
        yield buf


class TagRules(unittest.TestCase):
    """a2-aws#3: the provider's default_tags put every --tag on every resource (IAM roles, S3 buckets, the GuardDuty
    detector): a tag one of them refuses must be refused before anything is created."""

    def setUp(self):
        self.aws = clouds.get("aws")

    def test_keys_use_the_set_every_tagged_service_accepts(self):
        # IAM's set; GuardDuty's narrower one (no space, @ or other letters) only applies where this environment
        # creates the detector: AWS.tags_problems (tests/test_wave5_clouds.py)
        for good in ("team", "Cost-Center", "app.kubernetes.io/name", "a:b/c=d+e_f", "k" * 128, "Environment", "Name",
                     "Cost Center", "owner@team", "Équipe"):
            self.assertIsNone(self.aws.tag_problem(good, "x"), good)
        for bad, shown in (("Cost#Center", "'#'"), ("R&D", "'&'"), ("tab\tkey", "tab"), ("a,b", "','")):
            problem = self.aws.tag_problem(bad, "x")
            self.assertIsNotNone(problem, bad)
            self.assertIn(shown, problem)
            self.assertIn("letters, digits, spaces and _ . : / = + - @", problem)
        self.assertIn("at most 128", self.aws.tag_problem("k" * 129, "x"))

    def test_the_aws_prefix_is_reserved_in_any_case(self):
        for key in ("aws:createdBy", "AWS:x", "Aws:cloudformation:stack-name"):
            self.assertIn("reserved by AWS", self.aws.tag_problem(key, "me"))
        self.assertIsNone(self.aws.tag_problem("awsome", "x"))

    def test_values(self):
        for good in ("", "alice@example.com", "Équipe données", "a b", "x" * 256, "1.2.3", "a+b=c/d:e_f-g",
                     "½ share", "Ⅻ", "東京"):          # IAM's \p{L} \p{N} \p{Z}: any letter or number, not only str.isdigit
            self.assertIsNone(self.aws.tag_problem("team", good), good)
        for bad in ("R&D (core)", "a,b", "tab\there", "50%", "#1", "e\u0301"):   # (a combining accent is no letter)
            self.assertIn("may only hold letters, digits, spaces", self.aws.tag_problem("team", bad), bad)
        self.assertIn("at most 256", self.aws.tag_problem("team", "x" * 257))

    def test_generic_rules_come_first(self):
        self.assertIn("set by cloudseed", self.aws.tag_problem("ManagedBy", "x"))
        self.assertIn("'${'", self.aws.tag_problem("team", "${oops}"))
        self.assertEqual(self.aws.tag_problem("", "x"), "the tag key is empty")

    def test_an_emptied_tag_drops_a_saved_one_whatever_its_key(self):
        # `--tag "Cost Center="` is the way out of a tag an older version saved: it is never rendered
        self.assertIsNone(self.aws.tag_problem("Cost Center", ""))
        self.assertIsNone(self.aws.tag_problem("aws:x", ""))
        self.assertIn("set by cloudseed", self.aws.tag_problem("ManagedBy", ""))    # generic rules still apply

    def test_setup_refuses_them_before_saving_and_drops_saved_ones(self):
        problems = self.aws.check_config(_cfg(tags={"Team": "R&D (core)", "aws:createdBy": "me", "ok": "fine"}))
        joined = "\n".join(problems)
        self.assertIn("--tag Team=R&D (core)", joined)
        self.assertIn("--tag aws:createdBy=me", joined)
        self.assertNotIn("--tag ok=", joined)
        with _captured() as out:
            kept = cli._saved_tags(self.aws, {"tags": {"Cost#Center": "x", "team": "a"}})
        self.assertEqual(kept, {"team": "a"})
        self.assertIn("Dropping the saved tag Cost#Center=x", out.getvalue())
        args = argparse.Namespace(tag=["Cost#Center=42"], name=None, cidr=None, region=None, allow_ip=None)
        with _captured(), self.assertRaises(ui.Abort) as e:
            cli._check_setup_flags(self.aws, args)
        self.assertIn("--tag Cost#Center=42", e.exception.msg)

    def test_other_clouds_keep_their_own_rules(self):
        self.assertIsNone(clouds.get("vmware").tag_problem("Cost Center", "R&D"))


class EnvironmentTag(unittest.TestCase):
    """a2-aws#3 part 3 / a2-gcp#11: Environment is a default in the stack, so a --tag Environment=... (Cloud.tags puts
    it in var.tags and the summary shows it) applies to every resource, not only to the untagged ones."""

    def test_merge_order(self):
        locals_block = _block(_read("main.tf"), "locals {")
        self.assertIn('tags = merge({ Environment = var.environment }, var.tags, { ManagedBy = "cloudseed" })', locals_block)
        self.assertNotIn("merge(var.tags, {", locals_block)

    def test_the_tag_reaches_var_tags(self):
        tags = clouds.get("aws").stack_vars(_cfg(tags={"Environment": "production"}))["tags"]
        self.assertEqual((tags["Environment"], tags["ManagedBy"]), ("production", "cloudseed"))

    def test_plan_level_check_exists(self):
        tests = _read("tests/inputs.tftest.hcl")
        run = _block(tests, 'run "environment_tag_is_a_default_a_tag_overrides"')
        self.assertIn('local.tags["Environment"] == "production"', run)
        self.assertIn('local.tags["ManagedBy"] == "cloudseed"', run)

    def test_the_bootstrap_bucket_keeps_managed_by_last(self):
        self.assertIn('merge(var.tags, { Name = local.bucket_name, ManagedBy = "cloudseed" })',
                      (ROOT / "terraform" / "aws-bootstrap" / "main.tf").read_text())


class SavedAnswers(unittest.TestCase):
    """a2-aws#14: one reader for saved answers (Cloud.var_bool / var_int)."""

    def setUp(self):
        self.aws = clouds.get("aws")

    def test_module_level_duplicates_are_gone(self):
        for name in ("_fix_hint", "parse_bool", "parse_int", "_az_count", "_node_count"):
            self.assertFalse(hasattr(aws_mod, name), name)
        self.assertIs(aws_mod.as_bool, base.as_bool)      # the value parser, not a cfg reader
        self.assertIs(aws_mod.as_int, base.as_int)

    def test_a_blank_value_is_the_default_never_a_silent_false(self):
        for blank in ("", "  ", None):
            v = self.aws.stack_vars(_cfg(enable_account_baseline=blank, single_nat_gateway=blank, az_count=blank,
                                         kubernetes_node_count=blank, fips_mode=blank))
            self.assertIs(v["enable_account_baseline"], True, repr(blank))
            self.assertIs(v["enable_regional_baseline"], True, repr(blank))   # follows the account answer's default
            self.assertIs(v["single_nat_gateway"], True, repr(blank))
            self.assertIs(v["fips_mode"], False, repr(blank))
            self.assertEqual((v["az_count"], v["kubernetes_node_count"]), (2, 2))
        self.assertIs(aws_mod._regional_default({"vars": {"enable_account_baseline": ""}}), True)

    def test_an_unreadable_value_aborts_with_the_fix(self):
        for key, bad in (("enable_account_baseline", "maybe"), ("az_count", "two"), ("az_count", 0)):
            with _captured(), self.assertRaises(ui.Abort) as e:
                self.aws.stack_vars(_cfg(**{key: bad}))
            self.assertIn(f"The saved setting {key}=", e.exception.msg)
            self.assertIn(f"cloudseed setup aws --env dev --var {key}=", e.exception.msg)
        with _captured(), self.assertRaises(ui.Abort):
            self.aws.provider_block(_cfg(fips_mode="perhaps"))

    def test_regional_answer_follows_a_blank_saved_account_answer(self):
        # AWS.collect_vars: a saved regional answer equal to the account one follows it (a blank account answer is its
        # default, on): switching the account half off now switches the regional half off with it
        def collect(existing, overrides=None):
            with mock.patch.object(ui, "interactive", return_value=False), \
                    mock.patch.dict(os.environ, {"AWS_PROFILE": ""}), _captured():
                return self.aws.collect_vars(argparse.Namespace(), existing, _cfg(), False, overrides=overrides)

        for blank in ("", "  ", None):
            out = collect({"enable_account_baseline": blank, "enable_regional_baseline": True},
                          {"enable_account_baseline": "false"})
            self.assertEqual((out["enable_account_baseline"], out["enable_regional_baseline"]), (False, False), repr(blank))
        # a deliberate difference (an environment alone in its region) is kept
        out = collect({"enable_account_baseline": False, "enable_regional_baseline": True})
        self.assertEqual((out["enable_account_baseline"], out["enable_regional_baseline"]), (False, True))


class NetworkChecks(unittest.TestCase):
    """a2-aws#14: an override the network check cannot read is reported by it (the CLI's own copy of the AWS rules then
    never runs on it), with the fix."""

    def setUp(self):
        self.aws = clouds.get("aws")

    def problems(self, extra=None, **variables):
        return self.aws.network_problems(_cfg(extra=extra, **variables))

    def test_unreadable_overrides_are_named(self):
        for bad in ("4.5", -1, 0, "x", True):
            p = self.problems({"subnet_newbits": bad})
            self.assertEqual(len(p), 1, bad)
            self.assertIn(f"subnet_newbits={bad!r} must be a whole number between 1 and 12 (fix: --var subnet_newbits=4)",
                          p[0])
        p = self.problems({"create_data_subnets": "maybe"})
        self.assertEqual(p, ["create_data_subnets='maybe' must be true or false (fix: --var create_data_subnets=true)"])

    def test_blank_or_null_overrides_are_the_defaults(self):
        for value in ("", None):
            self.assertEqual(self.problems({"subnet_newbits": value, "create_data_subnets": value}), [])
        self.assertEqual(self.problems(az_count=""), [])

    def test_too_many_newbits_is_explained(self):
        p = self.problems({"subnet_newbits": 13})
        self.assertIn("subnet_newbits=13 is too large", p[0])
        self.assertIn("at most 12", p[0])
        self.assertEqual(self.problems({"subnet_newbits": 12}, az_count=1), [])   # /28 subnets from a /16

    def test_the_stack_refuses_the_same_range(self):
        block = _block(_read("variables.tf"), 'variable "subnet_newbits"')
        self.assertIn("var.subnet_newbits >= 1 && var.subnet_newbits <= 12 && floor(var.subnet_newbits) == var.subnet_newbits",
                      block)
        tests = _read("tests/inputs.tftest.hcl")
        for run, value in (("refuses_subnet_newbits_zero", "subnet_newbits = 0"),
                           ("refuses_subnet_newbits_above_twelve", "subnet_newbits = 13"),
                           ("refuses_a_fractional_subnet_newbits", "subnet_newbits = 4.5")):
            text = _block(tests, f'run "{run}"')
            self.assertIn(value, text)
            self.assertIn("expect_failures = [var.subnet_newbits]", text)

    def test_a_setup_gets_one_message(self):
        cfg = _cfg(extra={"subnet_newbits": "4.5"})
        cfg["network_cidr"] = "10.0.0.0/8"
        problems = cli._config_problems(self.aws, cfg)
        self.assertEqual([p for p in problems if "subnet_newbits" in p],
                         ["subnet_newbits='4.5' must be a whole number between 1 and 12 (fix: --var subnet_newbits=4)"])


class QuestionRanges(unittest.TestCase):
    """core / a2-azure#7: the ranges live on the questions, so --var, the prompt and the console refuse the same values
    before anything is saved."""

    def setUp(self):
        self.aws = clouds.get("aws")

    def test_declared_ranges(self):
        az = self.aws.question("az_count")
        self.assertEqual((az.minimum, az.maximum, az.validate), (1, 5, None))
        nodes = self.aws.question("kubernetes_node_count")
        self.assertEqual((nodes.minimum, nodes.maximum, nodes.validate), (1, None, None))
        self.assertEqual(self.aws.question("vpn_type").choices, ("openvpn", "tailscale"))
        for value in (1, 5, "3"):
            self.assertIsNone(az.problem(value))
        for value in (0, 6, "-1", "two"):
            self.assertIsNotNone(az.problem(value))
        self.assertIsNone(nodes.problem(1))
        self.assertIn(">= 1", nodes.problem(0))

    def _collect(self, overrides):
        with mock.patch.object(ui, "interactive", return_value=False), mock.patch.dict(os.environ, {"AWS_PROFILE": ""}), \
                mock.patch.object(ui, "ask_bool", side_effect=lambda p, d: d), \
                mock.patch.object(ui, "ask", side_effect=lambda p, d=None, **k: d):
            return self.aws.collect_vars(argparse.Namespace(), {}, _cfg(), True, overrides=overrides)

    def test_var_values_out_of_range_are_refused_before_saving(self):
        for key, value in (("az_count", "0"), ("az_count", "6"), ("kubernetes_node_count", "0")):
            with _captured(), self.assertRaises(ui.Abort) as e:
                self._collect({key: value, "enable_kubernetes": "true"})
            self.assertIn(f"--var {key}", e.exception.msg)
        out = self._collect({"az_count": "3", "kubernetes_node_count": "1", "enable_kubernetes": "true"})
        self.assertEqual((out["az_count"], out["kubernetes_node_count"]), (3, 1))

    def test_a_saved_zero_node_count_is_replaced_when_not_asked(self):
        # (`cs node remove` of the last node saves 0; the node group ignores desired_size after creation)
        with mock.patch.object(ui, "interactive", return_value=False), mock.patch.dict(os.environ, {"AWS_PROFILE": ""}), \
                _captured() as buf:
            out = self.aws.collect_vars(argparse.Namespace(), {"kubernetes_node_count": 0}, _cfg(), False)
        self.assertEqual(out["kubernetes_node_count"], 2)
        self.assertIn("The saved kubernetes_node_count 0 is invalid", buf.getvalue())
        self.assertIn("kubernetes_node_count", self.aws.invalid_answers(_cfg(kubernetes_node_count=0)))


class NodeBounds(unittest.TestCase):
    """a2-azure#7 (AWS part): _node_bounds never lowers kubernetes_node_min to 0; only an explicit --var does."""

    def setUp(self):
        self.aws = clouds.get("aws")

    def test_minimum_is_never_lowered(self):
        for count in (0, 1, 2, 4):
            self.assertNotIn("kubernetes_node_min", self.aws.stack_vars(_cfg(enable_kubernetes=True, kubernetes_node_count=count)))
        self.assertEqual(self.aws.stack_vars(_cfg(kubernetes_node_count=7))["kubernetes_node_max"], 7)

    def test_eks_with_zero_nodes_is_refused_and_an_explicit_zero_minimum_is_kept(self):
        with _captured(), self.assertRaises(ui.Abort) as e:
            self.aws.check_vars(_cfg(enable_kubernetes=True, kubernetes_node_count=0))
        self.assertIn("kubernetes_node_count=1", e.exception.msg)
        cfg = _cfg(enable_kubernetes=True, kubernetes_node_count=1, extra={"kubernetes_node_min": 0})
        with _captured():
            self.aws.check_vars(cfg)
        self.assertEqual(self.aws.module_vars(cfg)["kubernetes_node_min"], 0)

    def test_unreadable_or_null_bounds(self):
        with _captured(), self.assertRaises(ui.Abort) as e:
            self.aws.check_vars(_cfg(enable_kubernetes=True, extra={"kubernetes_node_min": "one"}))
        self.assertIn("--var kubernetes_node_min=N", e.exception.msg)
        with _captured(), self.assertRaises(ui.Abort):
            self.aws.check_vars(_cfg(enable_kubernetes=True, extra={"kubernetes_node_max": 2.5}))
        # null / blank: the stack's defaults (1..4); an explicit max is never widened to the count
        with _captured():
            self.aws.check_vars(_cfg(enable_kubernetes=True, kubernetes_node_count=3,
                                     extra={"kubernetes_node_min": None, "kubernetes_node_max": ""}))
        with _captured(), self.assertRaises(ui.Abort) as e:
            self.aws.check_vars(_cfg(enable_kubernetes=True, kubernetes_node_count=6, extra={"kubernetes_node_max": None}))
        self.assertIn("(1..4)", e.exception.msg)
        with _captured():   # no max given: widened to the count
            self.aws.check_vars(_cfg(enable_kubernetes=True, kubernetes_node_count=6))


class VpnPort(unittest.TestCase):
    """a2-azure#13 (AWS part): the stack refuses a port the security group or OpenVPN cannot use."""

    def test_validation_and_description(self):
        block = _block(_read("variables.tf"), 'variable "vpn_port"')
        self.assertIn("var.vpn_port >= 1 && var.vpn_port <= 65535 && floor(var.vpn_port) == var.vpn_port", block)
        self.assertIn("vpn_port must be a whole number between 1 and 65535.", block)
        self.assertIn("41641", block)
        tests = _read("tests/inputs.tftest.hcl")
        for run, value in (("refuses_vpn_port_zero", "vpn_port = 0"), ("refuses_a_fractional_vpn_port", "vpn_port = 1194.5")):
            text = _block(tests, f'run "{run}"')
            self.assertIn(value, text)
            self.assertIn("expect_failures = [var.vpn_port]", text)

    def test_descriptions_other_groups_asked_for(self):
        from cloudseed import help as helpmod
        variables = {n: d for n, d, _ in helpmod._parse_variables("aws")}
        self.assertEqual(variables["vpn_instance_type"], "Instance type of the VPN host.")
        guardduty = variables["enable_guardduty"]
        self.assertIn("never adopted", guardduty)
        self.assertNotIn("is adopted", guardduty)
        self.assertIn("set false to leave it alone", guardduty)
        # when a detector exists (reconcile.preflight): only on by default, setup/apply leave it alone and save
        # enable_guardduty=false (SingletonExists.auto, cli._plan_for_apply); set true explicitly, they stop (tf hints)
        self.assertIn("while this is only on by default they leave it alone and save enable_guardduty=false", guardduty)
        self.assertIn("set true explicitly, they stop and name this variable", guardduty)
        self.assertIn("An Environment tag here replaces the default", variables["tags"])


class NoSwitchedOffWarningOfItsOwn(unittest.TestCase):
    """setup and apply forget (never delete) the account/region settings a switched-off baseline half would delete
    (w4/cli-setup: cli._kept_deletes, from AWS.keep_on_destroy), so the adapter's notes must not claim that the apply
    deletes them or send the user to a targeted destroy first."""

    def test_notes_do_not_claim_a_delete(self):
        aws = clouds.get("aws")
        base = "module.stack.module.security_baseline[0]"
        deployed = [f"{base}.aws_s3_account_public_access_block.this[0]", f"{base}.aws_iam_account_password_policy.this[0]",
                    f"{base}.aws_ebs_encryption_by_default.this", "module.stack.module.network.aws_vpc.this"]
        with tempfile.TemporaryDirectory() as tmp:
            rows = [{"address": a, "type": a.rsplit(".", 2)[-2].split("[")[0], "mode": "managed"} for a in deployed]
            (Path(tmp) / "inventory.json").write_text(
                json.dumps({"history": [{"action": "apply", "resources": 4}], "current": {"resources": rows}}))
            for variables in ({"enable_account_baseline": False},
                              {"enable_account_baseline": False, "enable_regional_baseline": True}):
                with _captured() as out:
                    aws.check_vars(_cfg(tmp, **variables))
                for claim in ("deletes", "switches", "cloudseed destroy"):
                    self.assertNotIn(claim, out.getvalue(), variables)
        # the settings that stay are the ones keep_on_destroy names (what cli._kept_deletes forgets)
        self.assertEqual([a for a, _ in aws.keep_on_destroy(_cfg(), deployed)], deployed[:3])


class TerraformUntouchedElsewhere(unittest.TestCase):
    """The tag merge swap changes only local.tags: every module still receives local.tags."""

    def test_modules_take_local_tags(self):
        root = _read("main.tf")
        for module in ("kms", "network", "bastion", "security_baseline", "kubernetes", "vpn"):
            self.assertIn("local.tags", _block(root, f'module "{module}"'), module)


if __name__ == "__main__":
    unittest.main()
