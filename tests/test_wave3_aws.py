"""Regression tests for the wave-3 AWS fixes (second audit): partition-aware ARNs (GovCloud), a vendored load balancer
controller policy, a subnet layout that survives az_count changes, the security baseline split into an account-wide
and a regional half, the account pin, and plan/apply-time value checks moved to setup.

Fast and offline: the adapter is exercised directly and the Terraform is checked as text. The plan-level behaviour
(GovCloud ARNs, subnet CIDRs per layout, the baseline halves, the new variable validations) is covered by
terraform/aws/tests/*.tftest.hcl with mock providers (CLOUDSEED_TF_TESTS=1: tests.test_fix_core.TerraformModuleTests).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, help as helpmod, ui  # noqa: E402
from cloudseed.clouds import aws as aws_mod  # noqa: E402

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


def _cfg(workdir: str = "", region: str = "us-east-1", extra=None, **variables) -> dict:
    return {"cloud": "aws", "name": "acme", "env": "dev", "region": region, "network_cidr": "10.0.0.0/16",
            "allowed_ssh_cidrs": ["203.0.113.5/32"], "ssh_public_key": "ssh-ed25519 AAAA test", "owner": "me",
            "workdir": workdir, "vars": variables, "extra_vars": dict(extra or {}), "tags": {}, "platform_prereqs": []}


@contextlib.contextmanager
def _captured():
    """stdout+stderr of ui messages (ui.Abort prints its message when it is created)."""
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
        yield buf


class _Workdir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.aws = clouds.get("aws")

    def write_outputs(self, **outputs):
        (self.dir / "outputs.json").write_text(json.dumps(outputs))

    def write_state(self, state: dict):
        (self.dir / "stack").mkdir(exist_ok=True)
        (self.dir / "stack" / "terraform.tfstate").write_text(json.dumps(state))


class Partition(unittest.TestCase):
    """a2-aws#0: GovCloud (offered for FIPS mode) needs every ARN in its own partition."""

    def test_no_commercial_arn_literal_in_the_stack(self):
        offenders = []
        for path in sorted(TF.rglob("*.tf")):
            if any(part.startswith(".") for part in path.relative_to(TF).parts):
                continue        # not ours: a .terraform/ cache, macOS ._*.tf debris
            for n, line in enumerate(path.read_text().splitlines(), 1):
                code = line.split("#", 1)[0]
                if re.search(r'"arn:aws:(?!")', code):
                    offenders.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
        self.assertEqual(offenders, [], "build ARNs with arn:${local.partition}: / data.aws_partition")

    def test_every_module_writing_arns_reads_the_partition(self):
        for module in ("kms", "bastion", "vpn", "security-baseline"):
            text = "\n".join(p.read_text() for p in (TF / "modules" / module).glob("*.tf") if not p.name.startswith("."))
            self.assertIn('data "aws_partition" "current"', text, module)
        self.assertIn("arn:${local.partition}:iam::${var.account_id}:root", _read("modules/kms/main.tf"))
        self.assertIn("arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
                      _read("modules/kubernetes/main.tf"))

    def test_node_policy_keys_stay_the_same_in_the_commercial_partition(self):
        # for_each keys of existing environments (arn:aws:iam::aws:policy/<name>) must not change: no re-attachment
        node = _block(_read("modules/kubernetes/main.tf"), 'resource "aws_iam_role_policy_attachment" "node"')
        self.assertIn('"arn:${local.partition}:iam::aws:policy/${p}"', node)
        for name in ("AmazonEKSWorkerNodePolicy", "AmazonEC2ContainerRegistryReadOnly", "AmazonEKS_CNI_Policy",
                     "AmazonSSMManagedInstanceCore"):
            self.assertIn(f'"{name}"', node)

    def test_china_and_isolated_regions_are_refused_before_anything_runs(self):
        aws = clouds.get("aws")
        for region in ("cn-north-1", "cn-northwest-1", "us-iso-east-1", "us-isob-east-1", "eu-isoe-west-1"):
            with _captured(), self.assertRaises(ui.Abort) as e:
                aws.check_vars(_cfg(region=region))
            self.assertIn("not supported", e.exception.msg, region)
            self.assertIn("GovCloud", e.exception.msg)
            with _captured(), self.assertRaises(ui.Abort):
                aws.prepare(_cfg(region=region), dry_run=True)
        for region in ("us-gov-west-1", "us-gov-east-1", "us-east-1", "ca-central-1", "eu-central-1"):
            with _captured():
                aws.check_vars(_cfg(region=region))
        self.assertIn('check "supported_partition"', _read("main.tf"))


class LoadBalancerPolicy(unittest.TestCase):
    """a2-aws#13: no plan, apply or destroy downloads the controller policy from GitHub."""

    def test_policy_is_vendored_and_partition_rewritten(self):
        k8s = _read("modules/kubernetes/main.tf")
        code = "\n".join(line.split("#", 1)[0] for line in k8s.splitlines())
        self.assertNotIn('data "http"', code)
        self.assertNotIn("raw.githubusercontent.com", code)
        policy = _block(k8s, 'resource "aws_iam_role_policy" "lb_controller"')
        self.assertIn('file("${path.module}/lb_controller_iam_policy.json")', policy)
        self.assertIn('"arn:aws:", "arn:${local.partition}:"', policy)
        doc = json.loads((TF / "modules/kubernetes/lb_controller_iam_policy.json").read_text())
        self.assertEqual(doc["Version"], "2012-10-17")
        self.assertEqual(len(doc["Statement"]), 16)
        actions = {a for s in doc["Statement"] for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
        for needed in ("elasticloadbalancing:CreateLoadBalancer", "ec2:AuthorizeSecurityGroupIngress",
                       "iam:CreateServiceLinkedRole", "elasticloadbalancing:AddTags"):
            self.assertIn(needed, actions)

    def test_http_provider_is_gone(self):
        self.assertNotIn("hashicorp/http", _read("versions.tf"))
        self.assertNotIn("http", clouds.get("aws").required_providers())
        for suite in (TF / "tests").glob("*.tftest.hcl"):
            if suite.name.startswith("."):
                continue
            self.assertNotIn('mock_provider "http"', suite.read_text(), suite.name)
        root = clouds.get("aws").render_stack(_cfg(), Path("/tf"))
        self.assertNotIn("http", root["terraform"]["required_providers"])


class SubnetLayout(_Workdir):
    """a2-aws#4: changing az_count on a deployed environment must not re-address its subnets."""

    @staticmethod
    def _module_blocks(azs: int, stride: int) -> list[list[int]]:
        # the same formula as terraform/aws/modules/network/main.tf local.blocks
        return [[t * stride + i if i < stride else 3 * stride + 3 * (i - stride) + t for i in range(azs)] for t in range(3)]

    def test_module_formula(self):
        network = _read("modules/network/main.tf")
        self.assertIn("i < local.stride ? tier * local.stride + i : 3 * local.stride + 3 * (i - local.stride) + tier", network)
        for tier, name in enumerate(("public", "private", "data")):
            self.assertIn(f"local.blocks[{tier}][count.index]", _block(network, f'resource "aws_subnet" "{name}"'))
        # stride == az_count is exactly the original layout: public i, private n+i, data 2n+i
        for n in range(1, 6):
            self.assertEqual(self._module_blocks(n, n), [list(range(n)), list(range(n, 2 * n)), list(range(2 * n, 3 * n))])
        # adding an AZ keeps every block of the existing ones
        self.assertEqual(self._module_blocks(3, 2), [[0, 1, 6], [2, 3, 7], [4, 5, 8]])

    def test_block_count_matches_the_module(self):
        for azs in range(1, 6):
            for stride in range(1, 6):
                blocks = self._module_blocks(azs, stride)
                self.assertEqual(aws_mod.subnet_blocks(azs, stride, 3), max(max(b) for b in blocks) + 1)
                self.assertEqual(aws_mod.subnet_blocks(azs, stride, 2), max(max(b) for b in blocks[:2]) + 1)

    def write_inventory(self, *counts):
        """inventory.json as audit.refresh leaves it: one history entry per Terraform run (resource count after it)."""
        (self.dir / "inventory.json").write_text(json.dumps(
            {"history": [{"action": "apply", "resources": n} for n in counts] + [{"action": "provision"}]}))

    def test_new_environment_pins_its_az_count(self):
        cfg = _cfg(str(self.dir), az_count=3)
        with _captured():
            self.aws.check_vars(cfg)
        self.assertEqual(cfg["subnet_stride"], 3)
        self.assertEqual(self.aws.stack_vars(cfg)["subnet_stride"], 3)
        self.write_inventory(42)                     # the first apply created resources
        cfg["vars"]["az_count"] = 4                  # later: one more AZ, the layout stays
        with _captured():
            self.aws.check_vars(cfg)
        self.assertEqual(cfg["subnet_stride"], 3)
        self.assertEqual(self.aws.stack_vars(cfg)["az_count"], 4)

    def test_layout_follows_az_count_until_something_is_deployed(self):
        # `setup --dry-run` of a new environment saves its configuration (and the pin) before anything exists: the
        # real setup with another az_count gets the plain layout, not the dry run's
        cfg = _cfg(str(self.dir), az_count=2)
        with _captured():
            self.aws.check_vars(cfg)
        cfg["vars"]["az_count"] = 3
        with _captured():
            self.aws.check_vars(cfg)
        self.assertEqual(cfg["subnet_stride"], 3)
        # a full destroy left nothing: the next setup starts over with its own az_count
        self.write_inventory(40, 0)
        cfg["vars"]["az_count"] = 2
        with _captured():
            self.aws.check_vars(cfg)
        self.assertEqual(cfg["subnet_stride"], 2)
        # a failed first apply left resources behind (no outputs cached yet): the pin stays
        self.write_inventory(40, 0, 7)
        cfg["vars"]["az_count"] = 3
        with _captured():
            self.aws.check_vars(cfg)
        self.assertEqual(cfg["subnet_stride"], 2)
        # an unreadable inventory, or no working directory at all, counts as deployed
        (self.dir / "inventory.json").write_text("{not json")
        with _captured():
            self.aws.check_vars(cfg)
        self.assertEqual(cfg["subnet_stride"], 2)
        blind = _cfg("", az_count=4)
        blind["subnet_stride"] = 2
        with _captured():
            self.aws.check_vars(blind)
        self.assertEqual(blind["subnet_stride"], 2)

    def test_eks_is_told_that_its_node_group_is_replaced(self):
        # the node group's subnets cannot change in place (EKS has no API for it)
        self.write_outputs(public_subnet_ids=["subnet-a", "subnet-b"], kubernetes_node_group_name="acme-dev-eks-default")
        cfg = _cfg(str(self.dir), az_count=3, enable_kubernetes=True)
        with _captured() as out:
            self.aws.check_vars(cfg)
        self.assertIn("Terraform replaces it", out.getvalue())
        with _captured() as out:                    # the cluster is being turned off
            self.aws.check_vars(_cfg(str(self.dir), az_count=3))
        self.assertNotIn("node group", out.getvalue())
        self.write_outputs(public_subnet_ids=["subnet-a", "subnet-b"], kubernetes_node_group_name=None)
        with _captured() as out:                    # EKS comes with this change: no node group exists yet
            self.aws.check_vars(_cfg(str(self.dir), az_count=3, enable_kubernetes=True))
        self.assertIn("az_count 2 -> 3", out.getvalue())
        self.assertNotIn("node group", out.getvalue())

    def test_legacy_deployed_environment_pins_what_is_deployed(self):
        # saved before the layout was pinned, deployed with 2 AZs; now set up with az_count=3
        self.write_outputs(public_subnet_ids=["subnet-a", "subnet-b"], account_id="123456789012")
        cfg = _cfg(str(self.dir), az_count=3)
        with _captured() as out:
            self.aws.check_vars(cfg)
        self.assertEqual(cfg["subnet_stride"], 2)
        self.assertIn("existing subnets stay where they are", out.getvalue())
        self.assertEqual(self.aws.stack_vars(cfg)["subnet_stride"], 2)

    def test_legacy_local_state_is_read_when_outputs_are_not_cached(self):
        self.write_state({"outputs": {"public_subnet_ids": {"value": ["s-1", "s-2", "s-3"]}}})
        cfg = _cfg(str(self.dir), az_count=2)
        cfg["state"] = {"type": "local", "backend": None}
        with _captured():
            self.aws.check_vars(cfg)
        self.assertEqual(cfg["subnet_stride"], 3)

    def test_unpinned_environment_renders_as_before(self):
        # apply/plan/destroy of a config saved by an older version: stride = az_count (the original layout)
        self.assertEqual(self.aws.stack_vars(_cfg(az_count=3))["subnet_stride"], 3)
        cfg = _cfg(az_count=2)
        cfg["subnet_stride"] = "junk"
        self.assertEqual(self.aws.stack_vars(cfg)["subnet_stride"], 2)

    def test_prepare_does_not_pin(self):
        cfg = _cfg(str(self.dir), az_count=3)
        self.aws.prepare(cfg)
        self.assertNotIn("subnet_stride", cfg)

    def test_capacity_check_follows_the_layout(self):
        cfg = _cfg(az_count=2, extra={"subnet_newbits": 3})          # 8 blocks
        self.assertEqual(self.aws.network_problems(cfg), [])        # 2 AZs x 3 tiers = 6
        cfg["subnet_stride"] = 3                                    # deployed with 3 AZs, now 2: data at 6, 7
        self.assertEqual(self.aws.network_problems(cfg), [])
        cfg["vars"]["az_count"] = 3
        cfg["extra_vars"]["create_data_subnets"] = False
        cfg["subnet_stride"] = 2                                    # 2-AZ layout + 1 appended AZ: blocks 0..7
        self.assertEqual(self.aws.network_problems(cfg), [])
        cfg["extra_vars"]["create_data_subnets"] = True             # needs block 8
        problems = self.aws.network_problems(cfg)
        self.assertEqual(len(problems), 1)
        self.assertIn("need 9 subnets", problems[0])

    def test_stride_is_managed_by_cloudseed(self):
        managed = self.aws.managed_vars()
        self.assertIn("subnet_stride", managed)
        self.assertIn("az_count", managed["subnet_stride"])
        self.assertIn("subnet_stride", {n for n, _, _ in helpmod._parse_variables("aws")})


class BaselineHalves(_Workdir):
    """a2-aws#6 / #9: the regional settings (EBS encryption, GuardDuty, Access Analyzer, Security Hub) have their own
    switch, and settings of a half this environment does not manage are reported instead of silently ignored."""

    def test_regional_half_follows_the_account_switch_unless_set(self):
        v = self.aws.stack_vars(_cfg())
        self.assertIs(v["enable_account_baseline"], True)
        self.assertIs(v["enable_regional_baseline"], True)
        self.assertIs(self.aws.stack_vars(_cfg(enable_account_baseline=False))["enable_regional_baseline"], False)
        v = self.aws.stack_vars(_cfg(enable_account_baseline="no", enable_regional_baseline="yes"))
        self.assertEqual((v["enable_account_baseline"], v["enable_regional_baseline"]), (False, True))

    def test_question_order_and_default(self):
        keys = [q.key for q in self.aws.questions]
        self.assertEqual(keys.index("enable_regional_baseline"), keys.index("enable_account_baseline") + 1)
        q = self.aws.question("enable_regional_baseline")
        self.assertFalse(q.advanced)
        self.assertIs(q.stock_default({"vars": {"enable_account_baseline": False}}), False)
        self.assertIs(q.stock_default({"vars": {"enable_account_baseline": True}}), True)
        self.assertIs(q.stock_default({}), True)
        self.assertIn("ONE env per account AND region", q.prompt)
        self.assertEqual(q.follows, "enable_account_baseline")    # for forms that show the default (web console)

    def _collect(self, existing: dict, overrides: dict) -> dict:
        import argparse
        with mock.patch.object(ui, "interactive", return_value=False), mock.patch.dict(os.environ, {"AWS_PROFILE": ""}), \
                mock.patch.object(ui, "ask_bool", side_effect=lambda p, d: d), mock.patch.object(ui, "ask", side_effect=lambda p, d=None, **k: d):
            return self.aws.collect_vars(argparse.Namespace(), existing, _cfg(), False, overrides=overrides)

    def test_a_following_answer_follows_a_changed_account_answer(self):
        out = self._collect({"enable_account_baseline": True, "enable_regional_baseline": True},
                            {"enable_account_baseline": False})
        self.assertEqual((out["enable_account_baseline"], out["enable_regional_baseline"]), (False, False))
        # a legacy second environment (no regional answer saved) keeps managing nothing
        out = self._collect({"enable_account_baseline": False}, {})
        self.assertIs(out["enable_regional_baseline"], False)

    def test_a_deliberate_difference_is_kept(self):
        # a second environment alone in its region: account half off, regional half on
        out = self._collect({"enable_account_baseline": False, "enable_regional_baseline": True}, {})
        self.assertEqual((out["enable_account_baseline"], out["enable_regional_baseline"]), (False, True))
        out = self._collect({}, {"enable_account_baseline": False, "enable_regional_baseline": True})
        self.assertIs(out["enable_regional_baseline"], True)

    def test_security_hub_without_the_regional_half_warns(self):
        cfg = _cfg(str(self.dir), enable_account_baseline=False, enable_security_hub=True,
                   extra={"enable_guardduty": "true", "enable_cloudtrail": True, "enable_access_analyzer": "maybe"})
        with _captured() as out:
            self.aws.check_vars(cfg)                   # a warning, never a refusal
        text = out.getvalue()
        self.assertIn("enable_security_hub=true, enable_guardduty=true have no effect: they are part of the regional", text)
        self.assertIn("--var enable_regional_baseline=true", text)
        self.assertIn("enable_cloudtrail=true has no effect", text)
        self.assertNotIn("enable_access_analyzer", text)            # unparsable: reported by its own check
        with _captured() as quiet:
            self.aws.prepare(cfg)                     # setup ran check_vars already: not repeated
        self.assertEqual(quiet.getvalue(), "")

    def test_defaults_alone_never_warn(self):
        for variables in ({"enable_account_baseline": False}, {"enable_account_baseline": False, "enable_regional_baseline": True},
                          {}, {"enable_security_hub": True}):
            with _captured() as out:
                self.aws.check_vars(_cfg(str(self.dir), **variables))
            self.assertNotIn("has no effect", out.getvalue(), variables)

    def test_an_environment_without_any_baseline_is_told_about_its_region(self):
        with _captured() as out:
            self.aws.check_vars(_cfg(str(self.dir), region="us-west-2", enable_account_baseline=False))
        self.assertIn("manages no security baseline", out.getvalue())
        self.assertIn("us-west-2", out.getvalue())
        with _captured() as out:
            self.aws.check_vars(_cfg(str(self.dir), enable_account_baseline=False, enable_regional_baseline=True))
        self.assertNotIn("manages no security baseline", out.getvalue())

    def test_terraform_wiring(self):
        root = _read("main.tf")
        self.assertIn("count  = var.enable_account_baseline || local.regional_baseline ? 1 : 0", root)
        self.assertIn("manage_region          = local.regional_baseline", root)
        self.assertIn("enable_aws_config = local.regional_baseline &&", root)
        base = _read("modules/security-baseline/main.tf")
        self.assertIn("count = var.manage_account ? 1 : 0", _block(base, 'resource "aws_s3_account_public_access_block" "this"'))
        self.assertIn("count = var.manage_account ? 1 : 0", _block(base, 'resource "aws_iam_account_password_policy" "this"'))
        self.assertNotIn("count", _block(base, 'resource "aws_ebs_encryption_by_default" "this"'))
        self.assertIn("count = local.guardduty ? 1 : 0", _block(base, 'resource "aws_guardduty_detector" "this"'))
        self.assertIn("count = local.log_bucket ? 1 : 0", _block(base, 'resource "aws_s3_bucket" "trail"'))
        self.assertIn("count = local.cloudtrail ? 1 : 0", _block(base, 'resource "aws_cloudtrail" "this"'))
        # Config no longer needs CloudTrail: it gets the log bucket of its own
        self.assertNotIn("keep enable_cloudtrail = true", _read("variables.tf"))

    def test_config_log_bucket_name_fits_without_the_account_half(self):
        # '<name>-<env>-cloudtrail-<account id>' <= 63 characters: 39 for the prefix. Without the account-wide half the
        # bucket still exists for AWS Config (Security Hub) in the regional half.
        cfg = _cfg(enable_account_baseline=False, enable_regional_baseline=True, enable_security_hub=True)
        cfg["name"], cfg["env"] = "a" * 30, "e" * 10                    # 41 characters
        problems = self.aws.check_config(cfg)
        self.assertEqual(len([p for p in problems if "AWS Config's log bucket" in p]), 1, problems)
        self.assertIn("at most 39", problems[-1])
        cfg["env"] = "e" * 8                                             # 39: fits
        self.assertEqual(self.aws.check_config(cfg), [])
        cfg["env"] = "e" * 10
        for change in ({"vars": {"enable_security_hub": False}}, {"extra": {"enable_aws_config": "false"}},
                       {"vars": {"enable_regional_baseline": False}}):
            probe = json.loads(json.dumps(cfg))
            probe["vars"].update(change.get("vars", {}))
            probe["extra_vars"].update(change.get("extra", {}))
            self.assertEqual(self.aws.check_config(probe), [], change)   # no Config bucket
        cfg["vars"]["enable_security_hub"] = False
        cfg["extra_vars"]["enable_aws_config"] = True                     # Config without Security Hub
        self.assertEqual(len(self.aws.check_config(cfg)), 1)

    def test_account_wide_settings_are_still_kept_on_destroy(self):
        state = ["module.stack.module.security_baseline[0].aws_s3_account_public_access_block.this[0]",
                 "module.stack.module.security_baseline[0].aws_iam_account_password_policy.this[0]",
                 "module.stack.module.security_baseline[0].aws_ebs_encryption_by_default.this",
                 "module.stack.module.security_baseline[0].aws_guardduty_detector.this[0]"]
        self.assertEqual([a for a, _ in self.aws.keep_on_destroy(_cfg(), state)], state[:3])


class AccountPin(_Workdir):
    """a2-aws#7: a deployed environment is pinned to its account (allowed_account_ids)."""

    def test_pinned_from_cached_outputs(self):
        self.write_outputs(account_id="111111111111")
        cfg = _cfg(str(self.dir))
        self.assertEqual(self.aws.provider_block(cfg)["aws"]["allowed_account_ids"], ["111111111111"])
        bootstrap = self.aws.render_bootstrap(cfg, Path("/tf"))
        self.assertEqual(bootstrap["provider"]["aws"]["allowed_account_ids"], ["111111111111"])

    def test_pinned_from_local_state_after_a_failed_first_apply(self):
        self.write_state({"outputs": {}, "resources": [
            {"mode": "data", "type": "aws_caller_identity", "name": "current",
             "instances": [{"attributes": {"account_id": "222222222222"}}]}]})
        cfg = _cfg(str(self.dir))
        cfg["state"] = {"type": "local", "backend": None}
        self.assertEqual(self.aws.provider_block(cfg)["aws"]["allowed_account_ids"], ["222222222222"])
        self.write_state({"outputs": {"account_id": {"value": "333333333333"}}})
        self.assertEqual(self.aws.deployed_account(cfg), "333333333333")
        # remote state: a local file is at most a leftover from before the migration (the bucket pins the account)
        cfg["state"] = {"type": "remote", "backend": {"s3": {}}}
        self.assertIsNone(self.aws.deployed_account(cfg))

    def test_not_pinned_when_nothing_is_deployed_or_the_value_is_odd(self):
        self.assertNotIn("allowed_account_ids", self.aws.provider_block(_cfg(str(self.dir)))["aws"])
        self.assertNotIn("allowed_account_ids", self.aws.provider_block(_cfg())["aws"])
        for bad in ("", "12345", "abcdefghijkl", None, 123456789012345):
            self.write_outputs(account_id=bad)
            self.assertIsNone(self.aws.deployed_account(_cfg(str(self.dir))), bad)
        (self.dir / "outputs.json").write_text("{not json")
        self.assertIsNone(self.aws.deployed_account(_cfg(str(self.dir))))

    def test_no_working_directory_never_reads_the_current_one(self):
        # a probe config (workdir "") must not pick up an outputs.json of whatever directory cloudseed runs in
        self.write_outputs(account_id="444444444444", public_subnet_ids=["a", "b", "c"])
        cwd = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, cwd)
        self.assertIsNone(self.aws.deployed_account(_cfg("")))
        self.assertIsNone(self.aws.deployed_az_count(_cfg("")))
        self.assertNotIn("allowed_account_ids", self.aws.provider_block(_cfg(""))["aws"])


class SetupTimeChecks(unittest.TestCase):
    """a2-aws#8: values AWS only rejects at plan or apply time are caught by setup / --dry-run."""

    def setUp(self):
        self.aws = clouds.get("aws")

    def test_instance_type_questions(self):
        for key in ("bastion_instance_type", "kubernetes_node_size"):
            q = self.aws.question(key)
            for good in ("t3.micro", "t4g.small", "m7g.2xlarge", "u-6tb1.56xlarge", "r7iz.metal-16xl"):
                self.assertIsNone(q.problem(good), (key, good))
            for bad in ("t3micro", "T3.MICRO", "t3 micro", ".micro", "t3."):
                self.assertIsNotNone(q.problem(bad), (key, bad))

    def test_node_count_question_and_check(self):
        q = self.aws.question("kubernetes_node_count")
        self.assertIsNone(q.problem(1))
        self.assertEqual(q.minimum, 1)
        self.assertIn(">= 1", q.problem(0))
        with _captured(), self.assertRaises(ui.Abort) as e:
            self.aws.check_vars(_cfg(enable_kubernetes=True, kubernetes_node_count=0,
                                     extra={"kubernetes_node_min": 0}))
        self.assertIn("kubernetes_node_count=1", e.exception.msg)
        with _captured():
            self.aws.check_vars(_cfg(enable_kubernetes=True, kubernetes_node_count=1, extra={"kubernetes_node_min": 0}))
            self.aws.check_vars(_cfg(enable_kubernetes=False, kubernetes_node_count=0))   # no cluster: irrelevant

    def test_ebs_optimized_is_left_to_the_instance_type(self):
        for module in ("bastion", "vpn"):
            code = "\n".join(line.split("#", 1)[0] for line in _read(f"modules/{module}/main.tf").splitlines())
            self.assertNotIn("ebs_optimized", code, module)

    def test_variable_validations(self):
        variables = _read("variables.tf")
        for name, needle in (("kms_deletion_window_in_days", ">= 7"), ("bastion_root_volume_size", ">= 8"),
                             ("vpn_port", "<= 65535"), ("flow_log_retention_days", "3653"),
                             ("log_retention_days", ">= 3653"), ("kubernetes_version", "^1\\\\.[0-9]+$"),
                             ("kubernetes_node_count", "var.kubernetes_node_count >= 1"),
                             ("bastion_instance_type", "regex"), ("kubernetes_node_size", "regex"),
                             ("vpn_instance_type", "regex"), ("subnet_stride", "<= 5")):
            block = _block(variables, f'variable "{name}"')
            self.assertIn("validation", block, name)
            self.assertIn(needle, block, name)

    def test_every_stack_variable_has_a_description(self):
        missing = [n for n, desc, _ in helpmod._parse_variables("aws") if not desc]
        self.assertEqual(missing, [])


class BastionClusterAccess(unittest.TestCase):
    """a2-aws#10: the bastion's cluster-admin access entry is usable with `aws eks update-kubeconfig`."""

    def test_describe_cluster_policy(self):
        policy = _block(_read("main.tf"), 'resource "aws_iam_role_policy" "bastion_eks"')
        self.assertIn("count = var.enable_kubernetes ? 1 : 0", policy)
        self.assertIn('"eks:DescribeCluster"', policy)
        self.assertIn("module.kubernetes[0].cluster_arn", policy)
        self.assertIn("module.bastion.iam_role_name", policy)
        self.assertIn('output "iam_role_name"', _read("modules/bastion/outputs.tf"))
        self.assertIn('output "cluster_arn"', _read("modules/kubernetes/main.tf"))


class RequestedByOtherGroups(unittest.TestCase):
    def test_vpn_instance_id_output(self):   # ansible: the VPN host's instance id (like bastion_instance_id)
        outputs = dict(helpmod._parse_outputs("aws"))
        self.assertIn("vpn_instance_id", outputs)
        self.assertTrue(outputs["vpn_instance_id"])
        self.assertIn("try(module.vpn[0].instance_id, null)", _block(_read("outputs.tf"), 'output "vpn_instance_id"'))
        self.assertIn("vpn_instance_id", clouds.get("aws").outputs)

    def test_vpn_type_is_an_enumerated_question(self):   # core: choices instead of a validate lambda
        q = clouds.get("aws").question("vpn_type")
        self.assertEqual(q.choices, ("openvpn", "tailscale"))
        self.assertIsNone(q.validate)
        self.assertEqual(q.coerce("Tailscale"), "tailscale")
        self.assertIsNotNone(q.problem("wireguard"))

    def test_variable_descriptions(self):   # docs: what `cs help variables aws` prints
        variables = {n: d for n, d, _ in helpmod._parse_variables("aws")}
        self.assertIn("RSA-4096 SSH keys", variables["fips_mode"])
        self.assertNotIn("ECDSA SSH keys", variables["fips_mode"])
        self.assertIn("never adopted", variables["enable_guardduty"])
        self.assertNotIn("deleted on destroy", variables["enable_guardduty"])
        self.assertIn("one per account and region", variables["enable_access_analyzer"])
        self.assertIn("ONE environment per AWS account AND region", variables["enable_regional_baseline"])


if __name__ == "__main__":
    unittest.main()
