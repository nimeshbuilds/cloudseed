"""Regression tests for the AWS adapter and the AWS Terraform stack (no cloud, no network).

The Terraform-level behaviour (fresh EKS plans, the VPN login user, AWS Config with Security Hub, variable
validations) is covered by terraform/aws/tests/stack.tftest.hcl with mocked providers; test_terraform_mock_suite runs it
when CLOUDSEED_TF_TESTS=1 and terraform can initialise the providers offline (plugin cache).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cloudseed import cli, clouds, help as helpmod, reconcile, tf, ui

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


def _cfg(**variables) -> dict:
    extra = variables.pop("extra_vars", {})
    return {"cloud": "aws", "name": "acme", "env": "dev", "region": "us-east-1", "network_cidr": "10.0.0.0/16",
            "allowed_ssh_cidrs": ["203.0.113.5/32"], "ssh_public_key": "ssh-ed25519 AAAA test", "owner": "me",
            "vars": variables, "extra_vars": extra}


class StackVarsParsing(unittest.TestCase):
    """aws#10 / aws#17: string booleans and bad numbers from --var or an old config.json."""

    def setUp(self):
        quiet = mock.patch.object(ui, "err")
        quiet.start()
        self.addCleanup(quiet.stop)
        self.aws = clouds.get("aws")

    def test_string_booleans_render_false(self):
        # (a blank value means the setting's default, as Cloud.var_bool reads it: tests/test_wave4_aws.py)
        for off in ("False", "false", "no", "NO", "off", "0", "n"):
            v = self.aws.stack_vars(_cfg(enable_account_baseline=off, single_nat_gateway=off, fips_mode=off,
                                         enable_kubernetes=off, enable_vpn=off))
            for key in ("enable_account_baseline", "single_nat_gateway", "fips_mode", "enable_kubernetes", "enable_vpn"):
                self.assertIs(v[key], False, f"{key}={off!r}")

    def test_string_booleans_render_true(self):
        for on in ("True", "yes", "on", "1", "Y", 1, True):
            self.assertIs(self.aws.stack_vars(_cfg(enable_kubernetes=on))["enable_kubernetes"], True, repr(on))

    def test_missing_values_use_defaults(self):
        v = self.aws.stack_vars(_cfg())
        self.assertIs(v["enable_account_baseline"], True)
        self.assertIs(v["single_nat_gateway"], True)
        self.assertIs(v["enable_kubernetes"], False)
        self.assertEqual((v["az_count"], v["kubernetes_node_count"]), (2, 2))

    def test_fips_string_off_does_not_switch_endpoints_on(self):
        c = _cfg(fips_mode="no")
        self.assertNotIn("use_fips_endpoint", self.aws.provider_block(c)["aws"])
        self.assertNotIn("use_fips_endpoint", self.aws.backend_from_outputs(c, {"bucket": "b"})["s3"])
        self.assertTrue(self.aws.provider_block(_cfg(fips_mode="true"))["aws"]["use_fips_endpoint"])

    def test_unparseable_bool_is_a_clear_abort(self):
        with self.assertRaises(ui.Abort) as e:
            self.aws.stack_vars(_cfg(enable_vpn="maybe"))
        self.assertIn("enable_vpn", e.exception.msg)
        self.assertIn("cloudseed setup aws --env dev", e.exception.msg)
        self.assertIn("--var enable_vpn=", e.exception.msg)

    def test_bool_fix_hint_suggests_the_default(self):
        # suggesting "false" for a default-on setting would steer users to the costlier / weaker option
        with self.assertRaises(ui.Abort) as e:
            self.aws.stack_vars(_cfg(single_nat_gateway="maybe"))
        self.assertNotIn("--var single_nat_gateway=false", e.exception.msg)

    def test_numbers(self):
        v = self.aws.stack_vars(_cfg(az_count="3", kubernetes_node_count=" 4 "))
        self.assertEqual((v["az_count"], v["kubernetes_node_count"]), (3, 4))
        self.assertEqual(self.aws.stack_vars(_cfg(az_count=3.0))["az_count"], 3)

    def test_bad_numbers_abort_instead_of_crashing(self):
        for bad in ("two", "2.5", 2.5, True, 0, "-1"):   # (blank means the default: tests/test_wave4_aws.py)
            with self.assertRaises(ui.Abort, msg=repr(bad)) as e:
                self.aws.stack_vars(_cfg(az_count=bad))
            self.assertIn("az_count", e.exception.msg)
            self.assertIn("--var az_count=", e.exception.msg)

    def test_bad_saved_number_gives_clean_error_through_render(self):
        root = None
        with self.assertRaises(ui.Abort):
            root = self.aws.render_stack(_cfg(kubernetes_node_count="lots"), Path("/tf"))
        self.assertIsNone(root)


class NodeBounds(unittest.TestCase):
    """aws#24: node count vs min/max and EKS vs az_count are caught before Terraform/EKS reject them."""

    def setUp(self):
        quiet = mock.patch.object(ui, "err")
        quiet.start()
        self.addCleanup(quiet.stop)
        self.aws = clouds.get("aws")

    def test_count_above_default_max_widens_max(self):
        v = self.aws.stack_vars(_cfg(enable_kubernetes=True, kubernetes_node_count=9))
        self.assertEqual(v["kubernetes_node_max"], 9)
        self.assertNotIn("kubernetes_node_min", v)

    def test_count_zero_never_lowers_min(self):
        # a node group needs a node when it is created (the question and check_vars refuse 0): the minimum is never
        # lowered to fit a count; kubernetes_node_min=0 is only ever an explicit --var
        self.assertNotIn("kubernetes_node_min", self.aws.stack_vars(_cfg(kubernetes_node_count=0)))

    def test_count_within_defaults_leaves_bounds_alone(self):
        v = self.aws.stack_vars(_cfg(kubernetes_node_count=3))
        self.assertNotIn("kubernetes_node_max", v)
        self.assertNotIn("kubernetes_node_min", v)

    def test_explicit_bounds_win(self):
        c = _cfg(enable_kubernetes=True, kubernetes_node_count=9, extra_vars={"kubernetes_node_max": 12})
        self.assertNotIn("kubernetes_node_max", self.aws.stack_vars(c))
        mod = self.aws.render_stack(c, Path("/tf"))["module"]["stack"]
        self.assertEqual(mod["kubernetes_node_max"], 12)
        self.aws.check_vars(c)   # 9 within 1..12

    def test_explicit_bounds_conflict_is_rejected(self):
        c = _cfg(enable_kubernetes=True, kubernetes_node_count=6, extra_vars={"kubernetes_node_max": 5})
        with self.assertRaises(ui.Abort) as e:
            self.aws.check_vars(c)
        self.assertIn("kubernetes_node_count=6", e.exception.msg)

    def test_eks_needs_two_azs(self):
        with self.assertRaises(ui.Abort) as e:
            self.aws.prepare(_cfg(enable_kubernetes="true", az_count=1), dry_run=True)
        self.assertIn("az_count=2", e.exception.msg)
        self.aws.prepare(_cfg(enable_kubernetes=False, az_count=1), dry_run=True)   # no EKS: one AZ is fine

    def test_az_count_question_validator(self):
        q = next(q for q in self.aws.questions if q.key == "az_count")
        self.assertEqual((q.minimum, q.maximum), (1, 5))      # the range the CLI, the prompt and the console share
        self.assertIsNone(q.problem("3"))
        self.assertIsNotNone(q.problem("0"))
        self.assertIsNotNone(q.problem("6"))
        self.assertIsNotNone(q.problem("two"))

    def test_wizard_applies_the_az_count_range(self):
        # int prompts used to replace Question.validate with a bare isdigit() check, so 1-5 was never enforced
        seen = {}

        def ask(prompt, default=None, validate=None, **kw):
            seen[prompt] = validate
            return default

        args = argparse.Namespace()
        with mock.patch.object(ui, "ask", side_effect=ask), mock.patch.object(ui, "ask_bool", side_effect=lambda p, d: d):
            # a cluster is wanted, so its sizing is asked too (no kubernetes_* question is asked without one)
            out = self.aws.collect_vars(args, {"az_count": 3, "enable_kubernetes": True}, _cfg(), advanced=True)
        self.assertEqual(out["az_count"], 3)
        check = next(v for p, v in seen.items() if p.startswith("Number of availability zones"))
        self.assertIsNone(check("3"))
        self.assertEqual(check("two"), "Enter a number.")
        self.assertIn("<= 5", check("9"))
        self.assertIn(">= 1", check("0"))
        node_check = next(v for p, v in seen.items() if p == "Kubernetes node count")
        self.assertIsNone(node_check("9"))
        self.assertIn(">= 1", node_check("0"))   # the prompt asks again: a node group needs a node

    def test_saved_out_of_range_az_count_stops_a_non_interactive_advanced_setup(self):
        with mock.patch.object(ui, "interactive", return_value=False), mock.patch.dict(os.environ, {"AWS_PROFILE": ""}):
            with self.assertRaises(ui.Abort) as e:
                self.aws.collect_vars(argparse.Namespace(), {"az_count": 9}, _cfg(), advanced=True)
        self.assertIn("<= 5", e.exception.msg)


class KeepAccountSettingsOnDestroy(unittest.TestCase):
    """aws#20: a full destroy must not switch account-wide protections off."""

    BASE = "module.stack.module.security_baseline[0]"
    STATE = [
        "module.stack.module.network.aws_vpc.this",
        f"{BASE}.aws_s3_account_public_access_block.this",
        f"{BASE}.aws_ebs_encryption_by_default.this",
        f"{BASE}.aws_iam_account_password_policy.this",
        f"{BASE}.aws_iam_service_linked_role.config[0]",
        f"{BASE}.aws_guardduty_detector.this[0]",
        f"{BASE}.aws_cloudtrail.this[0]",
        "module.stack.module.bastion.aws_instance.bastion",
    ]
    KEPT = STATE[1:5]

    def test_keep_on_destroy_selects_only_account_settings(self):
        aws = clouds.get("aws")
        self.assertEqual([a for a, _ in aws.keep_on_destroy(_cfg(), self.STATE)], self.KEPT)
        self.assertEqual(aws.keep_on_destroy(_cfg(), ["module.stack.aws_iam_service_linked_role.x"]), [])

    def _destroy(self, cloud, auto_approve, typed_ok=True):
        calls = []
        state = list(self.STATE)

        class FakeTF:
            def __init__(self, workdir):
                pass

            def init(self, migrate=False, backend=True):
                calls.append(("init",))

            def state_list(self):
                return list(state)

            def plan(self, out="tfplan", destroy=False, targets=()):
                calls.append(("plan", destroy))

            def run(self, *args, capture=False, check=True):
                if args[:2] == ("state", "list"):   # cli-life: destroy reads the state strictly
                    return subprocess.CompletedProcess(args, 0, "\n".join(state) + "\n", "")
                calls.append(("run",) + args)
                if args[:2] == ("state", "rm"):
                    state.remove(args[2])
                return subprocess.CompletedProcess(args, 0, "", "")

            def outputs(self):
                return {}

            def apply(self, planfile=None, auto_approve=False, targets=()):
                calls.append(("apply", planfile, tuple(state)))

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        env = mock.Mock(id=f"{cloud.key}-dev", dir=tmp, stack_dir=tmp / "stack", bootstrap_dir=tmp / "bootstrap")
        env.name = "dev"
        env.stack_dir.mkdir()
        cfg = {"cloud": cloud.key, "env": "dev", "state": {"type": "local"}}
        args = argparse.Namespace(target=None, select=False, auto_approve=auto_approve, purge=False, purge_state=False)

        def typed(expected, prompt):
            if not typed_ok:
                raise ui.Abort("Confirmation did not match. Nothing was changed.")

        with mock.patch.object(cli, "_load_env", return_value=(cloud, env, cfg)), \
                mock.patch.object(cli, "_render", return_value=False), \
                mock.patch.object(cli, "Terraform", FakeTF), \
                mock.patch.object(cli.audit, "refresh"), mock.patch.object(cli.undo, "record"), \
                mock.patch.object(ui, "require_typed", side_effect=typed), \
                mock.patch.object(ui, "confirm", return_value=False):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    cli.cmd_destroy(args, {})
                except ui.Abort:
                    pass
        return calls

    def test_destroy_forgets_account_settings_before_applying(self):
        calls = self._destroy(clouds.get("aws"), auto_approve=True)
        removed = [c[3] for c in calls if c[:3] == ("run", "state", "rm")]
        self.assertEqual(removed, self.KEPT)
        replans = [c for c in calls if c[:2] == ("run", "plan") and "-destroy" in c]
        self.assertEqual(len(replans), 1, "the destroy plan must be rebuilt after the state rm")
        applied = [c for c in calls if c[0] == "apply"]
        self.assertEqual(len(applied), 1)
        self.assertFalse(set(self.KEPT) & set(applied[0][2]), "kept settings were still in the state at apply")
        order = [c[0] if c[0] != "run" else c[1] for c in calls]
        self.assertLess(order.index("state"), order.index("apply"))

    def test_cancelled_destroy_leaves_state_alone(self):
        with mock.patch.object(ui, "interactive", return_value=True):
            calls = self._destroy(clouds.get("aws"), auto_approve=False, typed_ok=False)
        self.assertFalse([c for c in calls if c[:3] == ("run", "state", "rm")])
        self.assertFalse([c for c in calls if c[0] == "apply"])

    def test_other_clouds_unchanged(self):
        calls = self._destroy(clouds.get("gcp"), auto_approve=True)
        self.assertFalse([c for c in calls if c[:3] == ("run", "state", "rm")])
        self.assertEqual(len([c for c in calls if c[0] == "apply"]), 1)


class ConfigServiceLinkedRole(unittest.TestCase):
    """aws#25: the account-wide AWS Config service-linked role is adopted, never a hard failure."""

    def test_import_id_and_conflict_detection(self):
        lookups = reconcile.CloudLookups("aws", {"region": "us-east-1", "vars": {}})
        arn = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
        with mock.patch.object(lookups, "_awscli", return_value={"Roles": [{"Arn": arn}]}) as cli_call:
            rule = reconcile.IMPORT_ID["aws_iam_service_linked_role"]
            self.assertEqual(rule({"aws_service_name": "config.amazonaws.com"}, lookups), arn)
        self.assertIn("/aws-service-role/config.amazonaws.com/", cli_call.call_args[0])
        with mock.patch.object(lookups, "_awscli", return_value={"Roles": []}):
            self.assertIsNone(rule({"aws_service_name": "config.amazonaws.com"}, lookups))
        out = ("Error: creating IAM Service Linked Role (config.amazonaws.com): InvalidInput: Service role name "
               "AWSServiceRoleForConfig has been taken in this account, please try a different suffix.\n\n"
               "  with module.stack.module.security_baseline[0].aws_iam_service_linked_role.config[0],\n")
        self.assertEqual(reconcile.conflicts(out), ["module.stack.module.security_baseline[0].aws_iam_service_linked_role.config[0]"])

    def test_preflight_adopts_existing_role(self):
        addr = "module.stack.module.security_baseline[0].aws_iam_service_linked_role.config[0]"
        planned = {addr: {"type": "aws_iam_service_linked_role", "values": {"aws_service_name": "config.amazonaws.com"}}}
        fake = mock.Mock()
        fake.state_list.return_value = []
        fake.run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(reconcile.CloudLookups, "aws_service_linked_role_arn", return_value="arn:x"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(reconcile.preflight(fake, "aws", {"region": "us-east-1", "vars": {}}, planned), [addr])
        fake.run.assert_called_with("import", "-input=false", addr, "arn:x", capture=True, check=False)

    def test_recorder_limit_has_a_fix_hint(self):
        msg = tf.explain("Error: putting ConfigService Configuration Recorder: MaxNumberOfConfigurationRecordersExceededException", "apply")
        self.assertIn("enable_aws_config=false", msg)


class TerraformSource(unittest.TestCase):
    """Static checks of the AWS Terraform that guard the confirmed defects."""

    def test_vpn_host_gets_the_ec2_user_login(self):   # aws#1
        vpn = _block(_read("modules/vpn/main.tf"), 'resource "aws_instance" "vpn"')
        self.assertIn("#cloud-config", vpn)
        self.assertRegex(vpn, r"default_user:\s*\n\s*name: ec2-user")
        self.assertIn('sudo: ["ALL=(ALL) NOPASSWD:ALL"]', vpn)
        self.assertRegex(vpn, r"user_data_replace_on_change\s*=\s*true")
        self.assertEqual(clouds.get("aws").ssh_user({}), "ec2-user")

    def test_region_default_ebs_key_is_not_the_env_cmk(self):   # aws#2
        base = _read("modules/security-baseline/main.tf")
        self.assertNotIn('resource "aws_ebs_default_kms_key"', base)
        self.assertIn('resource "aws_ebs_encryption_by_default"', base)

    def test_eks_for_each_keys_are_plan_time_known(self):   # aws#3
        k8s = _read("modules/kubernetes/main.tf")
        self.assertNotIn("toset(var.admin_role_arns)", k8s)
        self.assertNotIn("access_security_group_ids", k8s)
        self.assertEqual(k8s.count("for_each = var.admin_roles"), 2)
        root = _read("main.tf")
        admin = _block(root, "admin_roles = {")
        self.assertIn('role/${local.prefix}-bastion" = module.bastion.iam_role_arn', admin)
        self.assertNotIn("module.vpn", admin, "the internet-facing VPN host must not be cluster-admin (aws#23)")
        platform = _read("modules/kubernetes/platform.tf")
        self.assertNotIn("toset(var.private_subnet_ids)", platform)
        tag = _block(platform, 'resource "aws_ec2_tag" "karpenter_subnet"')
        self.assertIn("count", tag)
        removed = _block(platform, "removed {")
        self.assertIn("aws_ec2_tag.karpenter_subnets", removed)
        self.assertRegex(removed, r"destroy\s*=\s*false")

    def test_node_group_name_output(self):   # aws#8
        self.assertIn("kubernetes_node_group_name", clouds.get("aws").outputs)
        self.assertIn('output "node_group_name"', _read("modules/kubernetes/main.tf"))
        self.assertIn("ignore_changes = [scaling_config[0].desired_size]", _read("modules/kubernetes/main.tf"))

    def test_ebs_csi_brings_a_default_storage_class(self):   # aws#22
        addon = _block(_read("modules/kubernetes/main.tf"), 'resource "aws_eks_addon" "ebs_csi"')
        self.assertIn("defaultStorageClass = { enabled = true }", addon)

    def test_external_secrets_is_scoped_to_the_environment(self):   # aws#23
        doc = _block(_read("modules/kubernetes/main.tf"), 'data "aws_iam_policy_document" "external_secrets"')
        for stmt in re.findall(r"statement \{.*?\n  \}", doc, re.S):
            if '"secretsmanager:GetSecretValue"' in stmt or '"ssm:GetParameter"' in stmt:
                self.assertNotIn('resources = ["*"]', stmt)
            if '"kms:Decrypt"' in stmt:
                self.assertIn("kms:ViaService", stmt)
        self.assertIn('["${var.prefix}/"]', _read("modules/kubernetes/main.tf"))

    def test_karpenter_cannot_terminate_foreign_instances(self):   # aws#23
        doc = _block(_read("modules/kubernetes/platform.tf"), 'data "aws_iam_policy_document" "karpenter_controller"')
        statements = re.findall(r"statement \{.*?\n  \}", doc, re.S)
        destructive = ("ec2:TerminateInstances", "ec2:DeleteLaunchTemplate", "ec2:CreateTags", "iam:DeleteInstanceProfile",
                       "iam:RemoveRoleFromInstanceProfile", "iam:AddRoleToInstanceProfile", "iam:CreateInstanceProfile")
        seen = set()
        for stmt in statements:
            for action in destructive:
                if f'"{action}"' in stmt:
                    seen.add(action)
                    self.assertIn("condition", stmt, f"{action} must be tag-scoped")
                    self.assertNotIn('resources = ["*"]', stmt, action)
        self.assertEqual(seen, set(destructive))

    def test_variable_validations(self):   # aws#24
        variables = _read("variables.tf")
        self.assertIn("var.az_count >= 2", _block(variables, 'variable "enable_kubernetes"'))
        count = _block(variables, 'variable "kubernetes_node_count"')
        self.assertIn("var.kubernetes_node_min", count)
        self.assertIn("var.kubernetes_node_max", count)
        azs = _block(_read("main.tf"), 'data "aws_availability_zones" "available"')
        self.assertIn("exclude_zone_ids", azs)
        self.assertIn("postcondition", azs)
        self.assertIn('"use1-az3"', _read("main.tf"))

    def test_security_hub_gets_aws_config(self):   # aws#25
        base = _read("modules/security-baseline/main.tf")
        for resource in ("aws_config_configuration_recorder", "aws_config_delivery_channel",
                         "aws_config_configuration_recorder_status", "aws_iam_service_linked_role"):
            self.assertIn(f'resource "{resource}"', base)
        self.assertIn("aws_config_configuration_recorder_status.this", _block(base, 'resource "aws_securityhub_standards_subscription" "fsbp"'))
        self.assertIn("config.amazonaws.com", _block(base, 'data "aws_iam_policy_document" "trail_bucket"'))
        self.assertIn("config.amazonaws.com", _read("modules/kms/main.tf"))
        names = [n for n, _, _ in helpmod._parse_variables("aws")]
        self.assertIn("enable_aws_config", names)
        self.assertIn("external_secrets_prefixes", names)

    def test_every_rendered_output_exists_in_the_stack(self):
        declared = {n for n, _ in helpmod._parse_outputs("aws")}
        self.assertFalse(set(clouds.get("aws").outputs) - declared)


class OutputDescriptions(unittest.TestCase):
    """docs-skills#25: `cloudseed help outputs <cloud>` explains every output."""

    def test_every_output_has_a_description(self):
        for cloud in ("aws", "gcp", "azure", "vmware"):
            missing = [name for name, desc in helpmod._parse_outputs(cloud) if not desc]
            self.assertEqual(missing, [], cloud)


class TerraformMockSuite(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("CLOUDSEED_TF_TESTS") == "1" and shutil.which("terraform"),
                         "set CLOUDSEED_TF_TESTS=1 (needs terraform and cached providers)")
    def test_terraform_mock_suite(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        work = tmp / "aws"
        shutil.copytree(TF, work, ignore=shutil.ignore_patterns(".terraform", ".terraform.lock.hcl"))
        init = subprocess.run(["terraform", "init", "-backend=false", "-input=false", "-no-color"], cwd=work,
                              capture_output=True, text=True)
        if init.returncode != 0:
            self.skipTest("terraform init failed (providers not available offline)")
        for _ in range(3):   # a loaded machine can miss the provider plugin handshake; that is not a test failure
            run = subprocess.run(["terraform", "test", "-no-color"], cwd=work, capture_output=True, text=True)
            if "plugin failed to negotiate" not in run.stdout + run.stderr:
                break
        self.assertEqual(run.returncode, 0, run.stdout[-4000:] + run.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
