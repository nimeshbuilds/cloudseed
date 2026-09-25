"""Regression tests for the Azure adapter and the Azure Terraform stack (fix/azure).

Fast and offline: the Terraform files are checked as text, and the adapter is exercised directly. The plan/apply-level
suite in terraform/azure/tests (mock providers) runs with CLOUDSEED_TF_TESTS=1.
"""

from __future__ import annotations

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

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, paths, ui  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform" / "azure"


def _cfg(**vars_):
    base = {"subscription_id": "0123abcd-0000-0000-0000-000000000000"}
    base.update(vars_)
    return {"cloud": "azure", "env": "dev", "name": "cloudseed", "owner": "me", "region": "eastus",
            "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.7/32"],
            "ssh_public_key": "ssh-ed25519 AAAA test", "state": {"type": "local", "backend": None},
            "vars": base, "extra_vars": {}, "tags": {}, "platform_prereqs": []}


@contextlib.contextmanager
def _quiet():
    """ui.Abort prints its message when it is created."""
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        yield


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
    """HCL without comments (so explanations never satisfy or break a check)."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


class StrictVarsTests(unittest.TestCase):
    """azure#3 / azure#14: saved answers are parsed strictly; never bool("False") == True, never a ValueError."""

    def setUp(self):
        self.az = clouds.get("azure")

    def test_false_spellings_render_false(self):
        for text in ("False", "false", "no", "NO", "n", "off", "0", " false "):
            cfg = _cfg(enable_kubernetes=text, enable_defender=text, enable_vpn=text, fips_mode=text,
                       kubernetes_public_endpoint=text, enable_activity_log=text)
            v = self.az.stack_vars(cfg)
            for key in ("enable_kubernetes", "enable_defender", "enable_vpn", "fips_mode",
                        "kubernetes_public_endpoint", "enable_activity_log"):
                self.assertIs(v[key], False, f"{key}={text!r}")

    def test_true_spellings_render_true(self):
        for value in ("True", "yes", "Y", "on", "1", True, 1):
            v = self.az.stack_vars(_cfg(enable_kubernetes=value, enable_defender=value))
            self.assertIs(v["enable_kubernetes"], True, repr(value))
            self.assertIs(v["enable_defender"], True, repr(value))

    def test_defaults(self):
        v = self.az.stack_vars(_cfg())
        self.assertIs(v["enable_activity_log"], True)
        for key in ("enable_defender", "fips_mode", "enable_kubernetes", "kubernetes_public_endpoint", "enable_vpn"):
            self.assertIs(v[key], False, key)
        self.assertEqual(v["kubernetes_node_count"], 2)

    def test_unknown_bool_aborts_with_the_fix(self):
        with _quiet(), self.assertRaises(ui.Abort) as cm:
            self.az.stack_vars(_cfg(enable_defender="maybe"))
        msg = cm.exception.msg
        self.assertIn("enable_defender", msg)
        self.assertIn("'maybe'", msg)
        self.assertIn("cloudseed setup azure --env dev --var enable_defender=", msg)

    def test_node_count(self):
        # a blank (or null) saved value means the default: aborting would lock status and destroy out, because
        # invalid_answers skips blanks and nothing would ever repair it (Cloud._typed)
        for value, want in (("3", 3), (3, 3), (3.0, 3), (" 5 ", 5), ("", 2), (None, 2)):
            self.assertEqual(self.az.stack_vars(_cfg(kubernetes_node_count=value))["kubernetes_node_count"], want)
        for bad in ("three", "2.5", 2.5, True, 0, "0", "-1", "²"):
            with _quiet(), self.assertRaises(ui.Abort, msg=repr(bad)) as cm:
                self.az.stack_vars(_cfg(kubernetes_node_count=bad))
            self.assertIn("kubernetes_node_count", cm.exception.msg)
            self.assertIn("whole number", cm.exception.msg)

    def test_render_stack_uses_strict_values(self):
        root = self.az.render_stack(_cfg(enable_kubernetes="False", enable_defender="no", enable_vpn="0"),
                                    paths.tf_root())
        mod = root["module"]["stack"]
        self.assertEqual((mod["enable_kubernetes"], mod["enable_defender"], mod["enable_vpn"]), (False, False, False))


class ProviderVersionTests(unittest.TestCase):
    """azure#22: user_assigned_identity_id needs azurerm >= 4.65; the state root needs only 4.9 (a2-azure#14:
    azurerm_storage_container.storage_account_id), so a state root locked below 4.65 is not forced to upgrade."""

    def test_stack_and_module_require_4_65(self):
        az = clouds.get("azure")
        root = az.render_stack(_cfg(), paths.tf_root())
        self.assertEqual(root["terraform"]["required_providers"]["azurerm"]["version"], ">= 4.65, < 5.0")
        self.assertIn('version = ">= 4.65, < 5.0"', (TF / "versions.tf").read_text())

    def test_bootstrap_root_stays_loose(self):
        az = clouds.get("azure")
        boot = az.render_bootstrap(_cfg(), paths.tf_root())
        self.assertEqual(boot["terraform"]["required_providers"]["azurerm"]["version"], ">= 4.9, < 5.0")
        self.assertIn('version = ">= 4.9, < 5.0"', (ROOT / "terraform" / "azure-bootstrap" / "main.tf").read_text())
        # and rendering it does not leak into the stack's constraint
        self.assertEqual(az.required_providers()["azurerm"]["version"], ">= 4.65, < 5.0")

    def test_init_upgrades_a_lock_below_the_constraint(self):
        from cloudseed import tf
        with mock.patch.object(tf.deps, "find", return_value="/usr/bin/terraform"):
            t = tf.Terraform(Path(tempfile.mkdtemp()))
        calls = []

        def fake_run(*args, **kw):
            calls.append(args)
            if "-upgrade" in args:
                return subprocess.CompletedProcess(args, 0, "ok", "")
            return subprocess.CompletedProcess(args, 1, "", "Error: Failed to query available provider packages\n"
                                               "locked provider registry.terraform.io/hashicorp/azurerm 4.50.0 does "
                                               "not match configured version constraint >= 4.65.0, < 5.0.0; must "
                                               "use terraform init -upgrade to allow selection of new versions")
        with mock.patch.object(t, "run", side_effect=fake_run), mock.patch.object(t, "_platform_guard"):
            t.init()
        self.assertEqual(len(calls), 2)
        self.assertIn("-upgrade", calls[1])
        self.assertNotIn("-upgrade", calls[0])


class SharedResourcesTests(unittest.TestCase):
    """azure#10: subscription-wide objects are reported so destroy can leave them in place."""

    def test_keep_on_destroy(self):
        az = clouds.get("azure")
        state = [
            'module.stack.module.security_baseline.azurerm_security_center_subscription_pricing.this["VirtualMachines"]',
            'module.stack.module.security_baseline.azurerm_security_center_subscription_pricing.this["StorageAccounts"]',
            "module.stack.azurerm_marketplace_agreement.ubuntu_pro_fips[0]",
            "module.stack.module.security_baseline.data.azurerm_client_config.current",
            "module.stack.azurerm_resource_group.this",
            "module.stack.module.network.azurerm_network_security_rule.private_deny_all",
        ]
        kept = az.keep_on_destroy(_cfg(), state)
        self.assertEqual([a for a, _ in kept], state[:3])
        for _, notice in kept:
            self.assertIn("0123abcd-0000-0000-0000-000000000000", notice)
        self.assertIn("az security pricing create", kept[0][1])
        self.assertIn("az vm image terms cancel", kept[2][1])
        self.assertEqual(az.keep_on_destroy(_cfg(), []), [])

    def test_full_destroy_forgets_subscription_wide_objects(self):
        """cmd_destroy calls the hook with (cfg, resources): state rm, one notice per distinct text, re-plan, apply."""
        import argparse

        from cloudseed import cli
        state = [
            'module.stack.module.security_baseline.azurerm_security_center_subscription_pricing.this["VirtualMachines"]',
            'module.stack.module.security_baseline.azurerm_security_center_subscription_pricing.this["StorageAccounts"]',
            "module.stack.azurerm_marketplace_agreement.ubuntu_pro_fips[0]",
            "module.stack.azurerm_resource_group.this",
        ]
        kept = state[:3]
        calls = []

        class FakeTF:
            def __init__(self, workdir):
                pass

            def init(self, migrate=False, backend=True):
                pass

            def state_list(self):
                return list(state)

            def plan(self, out="tfplan", destroy=False, targets=()):
                calls.append(("plan",))

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
                calls.append(("apply", tuple(state)))

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        env = mock.Mock(id="azure-dev", dir=tmp, stack_dir=tmp / "stack", bootstrap_dir=tmp / "bootstrap")
        env.name = "dev"
        env.stack_dir.mkdir()
        args = argparse.Namespace(target=None, select=False, auto_approve=True, purge=False, purge_state=False)
        infos = []
        with mock.patch.object(cli, "_load_env", return_value=(clouds.get("azure"), env, _cfg())), \
                mock.patch.object(cli, "_render", return_value=False), mock.patch.object(cli, "Terraform", FakeTF), \
                mock.patch.object(cli.audit, "refresh"), mock.patch.object(cli.undo, "record"), \
                mock.patch.object(ui, "confirm", return_value=False), \
                mock.patch.object(ui, "info", side_effect=lambda msg, *a, **k: infos.append(msg)), _quiet():
            cli.cmd_destroy(args, {})
        self.assertEqual([c[3] for c in calls if c[:3] == ("run", "state", "rm")], kept)
        self.assertEqual(len([c for c in calls if c[:2] == ("run", "plan")]), 1, "destroy re-plans after the state rm")
        self.assertEqual([c[1] for c in calls if c[0] == "apply"], [("module.stack.azurerm_resource_group.this",)])
        self.assertEqual(sum("az security pricing create" in m for m in infos), 1, "the Defender notice is shown once")
        self.assertEqual(sum("az vm image terms cancel" in m for m in infos), 1)

    def test_resource_type(self):
        rt = clouds.get("azure")._resource_type
        self.assertEqual(rt("azurerm_marketplace_agreement.x[0]"), "azurerm_marketplace_agreement")
        self.assertIsNone(rt("data.azurerm_marketplace_agreement.x"))
        self.assertEqual(rt("module.data.azurerm_marketplace_agreement.x"), "azurerm_marketplace_agreement")
        self.assertIsNone(rt("module.stack"))


class QuestionTextTests(unittest.TestCase):
    def test_public_endpoint_warns_about_recreation(self):
        q = next(q for q in clouds.get("azure").questions if q.key == "kubernetes_public_endpoint")
        self.assertIn("re-creates the cluster", q.prompt)


class TerraformStackTextTests(unittest.TestCase):
    """The Terraform fixes, checked on the source (no terraform binary needed)."""

    @classmethod
    def setUpClass(cls):
        cls.root = _code((TF / "main.tf").read_text())
        cls.net = _code((TF / "modules" / "network" / "main.tf").read_text())
        cls.aks = _code((TF / "modules" / "kubernetes" / "main.tf").read_text())
        cls.plat = _code((TF / "modules" / "kubernetes" / "platform.tf").read_text())
        cls.variables = _code((TF / "variables.tf").read_text())

    def _priorities(self, text, nsg_ref):
        out = {}
        for m in re.finditer(r'resource "azurerm_network_security_rule" "(\w+)"', text):
            body = _block(text, m.group(0))
            if nsg_ref in body:
                out[m.group(1)] = int(re.search(r"priority\s*=\s*(\d+)", body).group(1))
        return out

    def test_private_nsg_allows_load_balancer_probes(self):  # azure#2
        body = _block(self.net, 'resource "azurerm_network_security_rule" "private_allow_azure_lb"')
        self.assertRegex(body, r'source_address_prefix\s*=\s*"AzureLoadBalancer"')
        self.assertRegex(body, r'destination_port_range\s*=\s*"\*"')
        self.assertIn("azurerm_network_security_group.private.name", body)
        prio = self._priorities(self.net, "azurerm_network_security_group.private.name")
        self.assertLess(prio["private_allow_azure_lb"], prio["private_deny_all"])

    def test_private_nsg_allows_pod_cidr_and_bastion_ingress(self):  # azure#1, azure#2
        pods = _block(self.aks, 'resource "azurerm_network_security_rule" "pods"')
        self.assertRegex(pods, r"source_address_prefix\s*=\s*var\.pod_cidr")
        self.assertIn("var.private_nsg_name", pods)
        self.assertRegex(_block(self.aks, "network_profile"), r"pod_cidr\s*=\s*var\.pod_cidr")
        bastion = _block(self.aks, 'resource "azurerm_network_security_rule" "ingress_from_bastion"')
        self.assertRegex(bastion, r"source_address_prefix\s*=\s*var\.bastion_private_ip")
        self.assertIn('"443"', bastion)
        # unique priorities on the private NSG, all before DenyAllInbound (4000); VPN uses 150
        prios = self._priorities(self.aks, "var.private_nsg_name")
        net = self._priorities(self.net, "azurerm_network_security_group.private.name")
        taken = list(prios.values()) + list(net.values()) + [150]
        self.assertEqual(len(taken), len(set(taken)), taken)
        self.assertTrue(all(p < 4000 for p in prios.values()))
        # the cluster waits for the pod rule; the root wires the NSG and the bastion in
        cluster = _block(self.aks, 'resource "azurerm_kubernetes_cluster" "this"')
        self.assertIn("azurerm_network_security_rule.pods", re.search(r"depends_on\s*=\s*\[[^\]]*\]", cluster).group(0))
        kube = _block(self.root, 'module "kubernetes"')
        self.assertRegex(kube, r"private_nsg_name\s*=\s*module\.network\.private_nsg_name")
        self.assertRegex(kube, r"bastion_private_ip\s*=\s*module\.bastion\.private_ip")

    def test_public_api_authorizes_nat_egress(self):  # azure#7
        kube = _block(self.root, 'module "kubernetes"')
        self.assertRegex(kube, r"authorized_ip_ranges\s*=\s*local\.kubernetes_authorized_ranges")
        local = _block(self.root, "locals")
        self.assertIn("var.allowed_ssh_cidrs", local)
        self.assertIn("module.network.nat_public_ip", local)

    def test_rotation_name(self):  # azure#9
        pool = _block(self.aks, "default_node_pool")
        name = re.search(r'temporary_name_for_rotation\s*=\s*"([^"]+)"', pool).group(1)
        self.assertRegex(name, r"^[a-z][a-z0-9]{0,11}$")

    def test_initial_node_count_is_clamped(self):  # azure#6 (Terraform side)
        pool = _block(self.aks, "default_node_pool")
        self.assertRegex(pool, r"node_count\s*=\s*local\.initial_node_count")
        self.assertRegex(self.aks, r"initial_node_count\s*=\s*max\(var\.node_count, var\.node_min\)")
        # a count above the maximum raises the maximum; it is never silently cut down to it
        self.assertRegex(self.aks, r"node_max\s*=\s*max\(var\.node_max, local\.initial_node_count\)")
        self.assertRegex(pool, r"max_count\s*=\s*local\.node_max")
        self.assertIn("default_node_pool[0].node_count", _block(self.aks, "lifecycle"))   # the autoscaler owns it
        for var in ("kubernetes_node_min", "kubernetes_node_max", "kubernetes_node_count"):
            self.assertIn("validation", _block(self.variables, f'variable "{var}"'))

    def test_velero_for_each_keys_known_at_plan(self):  # azure#5
        rg = _block(self.plat, 'resource "azurerm_role_assignment" "velero_rg"')
        for_each = re.search(r"for_each\s*=\s*(.+)", rg).group(1)
        self.assertNotIn("azurerm_kubernetes_cluster", for_each)
        node = _block(self.plat, 'resource "azurerm_role_assignment" "velero_node_rg"')
        self.assertIn("count", node)
        self.assertIn("node_resource_group", node)
        self.assertRegex(node, r"depends_on\s*=\s*\[azurerm_role_assignment\.velero_rg\]")

    def test_velero_storage_account_name(self):  # azure#4
        sa = _block(self.plat, 'resource "azurerm_storage_account" "velero"')
        self.assertIn('substr(replace(lower(var.prefix), "/[^a-z0-9]/", ""), 0, 12)}velero${random_id.velero[0].hex}', sa)
        self.assertIn("ignore_changes = [name]", sa)

        def name(prefix, hexpart):   # the expression above, in Python
            return re.sub(r"[^a-z0-9]", "", prefix.lower())[:12] + "velero" + hexpart
        longest = "a" * 24 + "-" + "b" * 24                  # NAME_RE allows 24 characters for name and env
        for prefix in ("cloudseed-dev", "cloudseed-production", longest):
            a, b = name(prefix, "a1b2c3"), name(prefix, "ffffff")
            self.assertLessEqual(len(a), 24)
            self.assertNotEqual(a, b, prefix)
            self.assertRegex(a, r"^[a-z0-9]{3,24}$")
        self.assertEqual(name("cloudseed-dev", "a1b2c3"), "cloudseeddevveleroa1b2c3")   # unchanged for short prefixes

    def test_velero_role_name_unique_per_subscription(self):  # azure#21
        rd = _block(self.plat, 'resource "azurerm_role_definition" "velero"')
        self.assertIn("data.azurerm_client_config.current.subscription_id", re.search(r"\n\s*name\s*=\s*(.+)", rd).group(1))

    def test_federated_credentials_not_deprecated(self):  # azure#22
        text = self.aks + self.plat
        blocks = [_block(text, m.group(0)) for m in
                  re.finditer(r'resource "azurerm_federated_identity_credential" "\w+"', text)]
        self.assertEqual(len(blocks), 3)
        for body in blocks:
            self.assertIn("user_assigned_identity_id", body)
            self.assertNotRegex(body, r"\bparent_id\b")
            self.assertNotRegex(body, r"\bresource_group_name\b")

    def test_control_plane_logging(self):  # azure#18
        diag = _block(self.aks, 'resource "azurerm_monitor_diagnostic_setting" "control_plane"')
        self.assertIn("azurerm_kubernetes_cluster.this.id", diag)
        self.assertIn("var.log_analytics_workspace_id", diag)
        for category in ("kube-apiserver", "kube-audit-admin"):
            self.assertIn(f'"{category}"', diag)
        self.assertNotRegex(diag, r"\blog\s*\{")      # azurerm 4.x: enabled_log, not log

    def test_creation_order(self):  # azure#19
        out = _block(self.net, 'output "private_subnet_id"')
        self.assertIn("azurerm_subnet_nat_gateway_association.private", out)
        self.assertIn("azurerm_subnet_network_security_group_association.private", out)
        for mod in ('module "bastion"', 'module "vpn"'):
            self.assertRegex(_block(self.root, mod), r"depends_on\s*=\s*\[azurerm_marketplace_agreement\.ubuntu_pro_fips\]")
        self.assertIn('output "private_ip"', (TF / "modules" / "bastion" / "main.tf").read_text())


@unittest.skipUnless(os.environ.get("CLOUDSEED_TF_TESTS") == "1",
                     "set CLOUDSEED_TF_TESTS=1 to run the Azure terraform test suite (mock providers)")
class AzureTerraformSuite(unittest.TestCase):
    """terraform/azure/tests/*.tftest.hcl: fresh plan with velero, FIPS plan, NSG rules, authorized ranges, node pool."""

    def test_terraform_test(self):
        terraform = shutil.which("terraform")
        if not terraform:
            self.skipTest("terraform not installed")
        work = Path(tempfile.mkdtemp()) / "terraform"
        shutil.copytree(ROOT / "terraform", work, ignore=shutil.ignore_patterns(".terraform", ".terraform.lock.hcl"))
        d = work / "azure"
        for args in (["init", "-backend=false", "-input=false", "-no-color"], ["test", "-no-color"],
                     ["validate", "-no-color"]):
            p = subprocess.run([terraform, f"-chdir={d}", *args], capture_output=True, text=True, timeout=1800)
            self.assertEqual(p.returncode, 0, f"terraform {args[0]}\n{(p.stdout + p.stderr)[-3000:]}")
            self.assertNotIn("Argument is deprecated", p.stdout + p.stderr)
        shutil.rmtree(work.parent, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
