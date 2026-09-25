"""Regression tests for the wave-2 cloud adapter / Terraform follow-ups (aws, gcp, azure).

Fast and offline: adapters are exercised directly and the Terraform files are checked as text. The plan-level suites in
terraform/<cloud>/tests (mock providers) run with CLOUDSEED_TF_TESTS=1 (tests.test_fix_core.TerraformModuleTests).
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, help as helpmod, scan, ui  # noqa: E402
from cloudseed.clouds import azure as azure_mod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform"
GUID = "0123abcd-0000-0000-0000-000000000000"


@contextlib.contextmanager
def _quiet():
    """ui.Abort prints its message when it is created."""
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        yield


@contextlib.contextmanager
def _non_interactive():
    old = ui.NON_INTERACTIVE
    ui.NON_INTERACTIVE = True
    try:
        yield
    finally:
        ui.NON_INTERACTIVE = old


def _azure_cfg(**vars_):
    base = {"subscription_id": GUID}
    base.update(vars_)
    return {"cloud": "azure", "env": "dev", "name": "cloudseed", "owner": "me", "region": "eastus",
            "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.7/32"],
            "ssh_public_key": "ssh-ed25519 AAAA test", "state": {"type": "local", "backend": None},
            "vars": base, "extra_vars": {}, "tags": {}, "platform_prereqs": []}


def _block(text: str, header: str) -> str:
    """The body of the HCL block that starts with `header` (brace matched)."""
    start = text.index(header)
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    raise AssertionError(f"unterminated block {header}")


def _code(text: str) -> str:
    """HCL without comments (so an explanation never satisfies a check)."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


# ---------------------------------------------------------------- azure (azure#16, azure#3)

class AzureAnswerTests(unittest.TestCase):
    def setUp(self):
        self.az = clouds.get("azure")

    def test_reserved_admin_names_are_refused_in_any_case(self):
        q = self.az.question("admin_username")
        for name in ("admin", "Admin", "ADMINISTRATOR", "test", "user1", "guest", "john", "support_388945a0", "a", "1"):
            problem = q.problem(name)
            self.assertIsNotNone(problem, name)
        self.assertIn("does not allow", q.problem("admin"))
        for name in ("azureuser", "alice", "ops-admin", "deploy_1"):
            self.assertIsNone(self.az.answer_problem(q, name, _azure_cfg()), name)

    def test_reserved_admin_flag_stops_before_anything_is_saved(self):
        args = SimpleNamespace(project_id=None, zone=None, ssh_username=None, subscription_id=GUID,
                               admin_username="admin", profile=None)
        with _quiet(), _non_interactive(), self.assertRaises(SystemExit) as cm:
            self.az.collect_vars(args, {}, {"region": "eastus", "workdir": tempfile.mkdtemp()}, False, {})
        self.assertIn("does not allow", str(getattr(cm.exception, "msg", cm.exception)))

    def test_reserved_names_match_the_terraform_validation(self):
        text = (TF / "azure" / "variables.tf").read_text()
        body = _block(text, 'variable "admin_username"')
        listed = set(re.findall(r'"([^"]+)"', body.split("contains([", 1)[1].split("]", 1)[0]))
        self.assertEqual(listed, set(azure_mod.RESERVED_ADMIN_NAMES))
        self.assertIn("lower(var.admin_username)", body)

    def test_subscription_must_be_a_guid(self):
        for bad in ("not-a-guid", "y", "0123abcd-0000-0000-0000-00000000000", "sub-1"):
            with _quiet(), self.assertRaises(ui.Abort, msg=bad) as cm:
                self.az.check_vars(_azure_cfg(subscription_id=bad))
            self.assertIn("--subscription-id <GUID>", cm.exception.msg)
            self.assertIn(repr(bad), cm.exception.msg)
        cfg = _azure_cfg(subscription_id=" 0123ABCD-0000-0000-0000-000000000000 ")
        self.az.check_vars(cfg)
        self.assertEqual(cfg["vars"]["subscription_id"], "0123ABCD-0000-0000-0000-000000000000")

    def test_strict_saved_values_use_the_shared_parsers(self):
        v = self.az.stack_vars(_azure_cfg(enable_activity_log=None, enable_defender=None, kubernetes_node_count=4.0))
        self.assertIs(v["enable_activity_log"], True)       # unset (null) means the default
        self.assertIs(v["enable_defender"], False)
        self.assertEqual(v["kubernetes_node_count"], 4)
        with _quiet(), self.assertRaises(ui.Abort) as cm:
            self.az.stack_vars(_azure_cfg(kubernetes_node_count="0"))
        self.assertIn("The saved setting kubernetes_node_count='0' of azure-dev is invalid", cm.exception.msg)
        self.assertIn("whole number >= 1", cm.exception.msg)
        self.assertIn("cloudseed setup azure --env dev --var kubernetes_node_count=VALUE", cm.exception.msg)
        with _quiet(), self.assertRaises(ui.Abort) as cm:
            self.az.stack_vars(_azure_cfg(fips_mode="sometimes"))
        self.assertIn("fips_mode='sometimes'", cm.exception.msg)

    def test_log_retention_is_bounded_in_terraform(self):
        body = _code(_block((TF / "azure" / "variables.tf").read_text(), 'variable "log_retention_days"'))
        self.assertIn("var.log_retention_days <= 730", body)
        self.assertIn("floor(var.log_retention_days)", body)
        baseline = _code((TF / "azure" / "modules" / "security-baseline" / "main.tf").read_text())
        self.assertIn("max(30, var.log_retention_days)", baseline)   # below 30 is still raised, not refused


class AzureIdentityOutputTests(unittest.TestCase):
    """azure#23: tenant_id / subscription_id are set with or without AKS."""

    def test_outputs_come_from_the_client_config(self):
        outputs = _code((TF / "azure" / "outputs.tf").read_text())
        for name in ("tenant_id", "subscription_id"):
            body = _block(outputs, f'output "{name}"')
            self.assertIn(f"data.azurerm_client_config.current.{name}", body)
            self.assertNotIn("module.kubernetes", body)
        self.assertRegex(_code((TF / "azure" / "main.tf").read_text()), r'data\s+"azurerm_client_config"\s+"current"\s*\{\s*\}')


# ---------------------------------------------------------------- gcp (docs-skills#28)

class GcpCredentialWarningTests(unittest.TestCase):
    def setUp(self):
        self.gcp = clouds.get("gcp")
        self.home = Path(tempfile.mkdtemp())
        (self.home / "keys").mkdir()
        self.key = self.home / "keys" / "proj.json"
        self.key.write_text("{}")

    def warnings(self, **env):
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CREDENTIALS")}
        clean.update(HOME=str(self.home), **env)
        with mock.patch.dict(os.environ, clean, clear=True):
            return self.gcp.credential_warnings({"vars": {}})

    def test_missing_key_file(self):
        w = self.warnings(GOOGLE_APPLICATION_CREDENTIALS=str(self.home / "keys" / "gone.json"))
        self.assertEqual(len(w), 1)
        self.assertIn("gone.json, which does not exist", w[0])
        self.assertIn("gcloud auth application-default login", w[0])

    def test_tilde_and_relative_paths_are_not_opened_by_google(self):
        w = self.warnings(GOOGLE_APPLICATION_CREDENTIALS="~/keys/proj.json")
        self.assertEqual(len(w), 1)
        self.assertIn("not an absolute path", w[0])
        self.assertIn(f"GOOGLE_APPLICATION_CREDENTIALS={self.key.resolve()}", w[0])
        cwd = os.getcwd()
        os.chdir(self.home)
        try:
            w = self.warnings(GOOGLE_APPLICATION_CREDENTIALS="keys/proj.json")
        finally:
            os.chdir(cwd)
        self.assertIn("not an absolute path", w[0])

    def test_absolute_existing_key_is_fine(self):
        self.assertEqual(self.warnings(GOOGLE_APPLICATION_CREDENTIALS=str(self.key)), [])

    def test_other_sources(self):
        self.assertEqual(self.warnings(GOOGLE_CREDENTIALS="{}"), [])
        self.assertIn("No Google credentials detected", self.warnings()[0])
        adc = self.home / ".config" / "gcloud"
        adc.mkdir(parents=True)
        (adc / "application_default_credentials.json").write_text("{}")
        self.assertEqual(self.warnings(), [])


class GcpVpnFipsImageTests(unittest.TestCase):
    """gcp#11 / gcp#23 / ansible#6: the FIPS VPN host boots Ubuntu Pro FIPS, and scan reads that from the module."""

    def test_vpn_module_switches_image_with_fips_mode(self):
        self.assertEqual(scan._gcp_vpn_image(True), "ubuntu-os-pro-cloud/ubuntu-pro-fips-2204-lts")
        self.assertEqual(scan._gcp_vpn_image(False), "ubuntu-os-cloud/ubuntu-2404-lts-amd64")
        vpn = _block(_code((TF / "gcp" / "main.tf").read_text()), 'module "vpn"')
        self.assertRegex(vpn, r"fips_mode\s*=\s*var\.fips_mode")
        self.assertRegex(vpn, r"region\s*=\s*var\.region")


# ---------------------------------------------------------------- all clouds (azure#23, aws#30)

class VpnPortOutputTests(unittest.TestCase):
    def test_tailscale_reports_its_port(self):
        for cloud in ("aws", "gcp", "azure"):
            body = _code(_block((TF / cloud / "outputs.tf").read_text(), 'output "vpn_port"'))
            self.assertIn('var.enable_vpn ? (var.vpn_type == "tailscale" ? 41641 : var.vpn_port) : null', body, cloud)
            desc = dict(helpmod._parse_outputs(cloud))["vpn_port"]
            self.assertIn("41641 for Tailscale", desc, cloud)

    def test_every_public_cloud_has_a_plan_level_suite(self):
        for cloud in ("aws", "gcp", "azure"):
            self.assertTrue(list((TF / cloud / "tests").glob("*.tftest.hcl")), cloud)
        gcp = (TF / "gcp" / "tests" / "stack.tftest.hcl").read_text()
        for run in ("fresh_kubernetes_vpn_velero", "vpn_fips_image", "tailscale_reports_its_port", "long_names",
                    "zone_outside_the_region_is_refused"):
            self.assertIn(f'run "{run}"', gcp)


# ---------------------------------------------------------------- aws (aws#6, platform-catalog#3, ansible#7)

class AwsNetworkTagTests(unittest.TestCase):
    def setUp(self):
        self.text = _code((TF / "aws" / "modules" / "network" / "main.tf").read_text())

    def test_load_balancer_roles_on_public_and_private_subnets(self):
        public = _block(self.text, 'resource "aws_subnet" "public"')
        private = _block(self.text, 'resource "aws_subnet" "private"')
        data = _block(self.text, 'resource "aws_subnet" "data"')
        self.assertRegex(public, r'"kubernetes\.io/role/elb"\s*=\s*"1"')
        self.assertNotIn("internal-elb", public)
        self.assertRegex(private, r'"kubernetes\.io/role/internal-elb"\s*=\s*"1"')
        self.assertNotIn('"kubernetes.io/role/elb"', private)
        self.assertNotIn("kubernetes.io/role", data)


class AwsBastionFirstBootTests(unittest.TestCase):
    def setUp(self):
        self.instance = _block((TF / "aws" / "modules" / "bastion" / "main.tf").read_text(),
                               'resource "aws_instance" "bastion"')

    def test_first_boot_upgrades_from_the_latest_release_after_locking_sshd(self):
        script = self.instance.split("<<-USERDATA", 1)[1].split("USERDATA", 1)[0]
        self.assertIn("dnf -y --releasever=latest upgrade", script)
        self.assertNotIn("dnf -y update", script)
        self.assertLess(script.index("systemctl restart sshd"), script.index("dnf -y --releasever=latest upgrade"))

    def test_changed_first_boot_script_does_not_restart_existing_bastions(self):
        lifecycle = _code(_block(self.instance, "lifecycle"))
        self.assertRegex(lifecycle, r"ignore_changes\s*=\s*\[\s*ami\s*,\s*user_data\s*\]")


if __name__ == "__main__":
    unittest.main()
