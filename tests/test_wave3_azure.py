"""Regression tests for the wave-3 Azure fixes (second audit): the subscription ID checked at the question, the AKS node
count minimum, one Azure credential probe, Defender sub-plans, the published API name of a private AKS cluster and the
vpn_port range.

Fast and offline: the adapter is exercised directly and the Terraform files are checked as text. The plan-level suite
in terraform/azure/tests (mock providers) runs with CLOUDSEED_TF_TESTS=1 (tests.test_fix_azure.AzureTerraformSuite).
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
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, help as helpmod, ui  # noqa: E402
from cloudseed.clouds import azure as azure_mod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform" / "azure"
GUID = "0123abcd-0000-0000-0000-000000000000"
OTHER_GUID = "99999999-8888-7777-6666-555555555555"

# every variable the Azure credential probe and the subscription default read
_AZ_ENV = ("ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID", "ARM_CLIENT_ID", "ARM_CLIENT_ID_FILE_PATH",
           "ARM_CLIENT_SECRET", "ARM_CLIENT_SECRET_FILE_PATH", "ARM_CLIENT_CERTIFICATE_PATH", "ARM_CLIENT_CERTIFICATE",
           "ARM_USE_OIDC", "ARM_OIDC_TOKEN", "ARM_OIDC_TOKEN_FILE_PATH", "ARM_OIDC_REQUEST_TOKEN", "ARM_USE_MSI",
           "ARM_USE_AKS_WORKLOAD_IDENTITY", "ARM_USE_CLI", "ARM_TENANT_ID", "AZURE_CONFIG_DIR")


@contextlib.contextmanager
def _captured():
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        yield out, err


@contextlib.contextmanager
def _non_interactive(flag: bool = True):
    old = ui.NON_INTERACTIVE
    ui.NON_INTERACTIVE = flag
    try:
        yield
    finally:
        ui.NON_INTERACTIVE = old


@contextlib.contextmanager
def _clean_env(**values):
    """Only the given Azure variables are set (the others are removed for the duration)."""
    with mock.patch.dict(os.environ, {}, clear=False):
        for name in _AZ_ENV:
            os.environ.pop(name, None)
        os.environ.update(values)
        yield


def _args(**kw):
    ns = SimpleNamespace(project_id=None, zone=None, ssh_username=None, subscription_id=None, admin_username=None,
                         profile=None)
    ns.__dict__.update(kw)
    return ns


def _cfg():
    return {"region": "eastus", "workdir": tempfile.mkdtemp(), "env": "dev", "name": "cloudseed"}


class _AzureCase(unittest.TestCase):
    def setUp(self):
        self.az = clouds.get("azure")
        azure_mod._SUBSCRIPTION_CACHE.clear()
        azure_mod._WARNED_ENV.clear()
        self.addCleanup(azure_mod._SUBSCRIPTION_CACHE.clear)
        self.addCleanup(azure_mod._WARNED_ENV.clear)

    def q(self, key):
        return self.az.question(key)


# ---------------------------------------------------------------- a2-azure#3: subscription ID at the question

class SubscriptionAtTheQuestionTests(_AzureCase):
    def test_answers_are_checked_as_guids(self):
        q = self.q("subscription_id")
        self.assertIn("not an Azure subscription ID", self.az.answer_problem(q, "bad-guid", {}))
        self.assertIsNone(self.az.answer_problem(q, GUID, {}))
        self.assertIsNone(self.az.answer_problem(q, f"  {GUID}  ", {}))
        self.assertIsNone(self.az.answer_problem(q, "", {}))       # blank: the default decides (and required asks)
        # other questions keep their own rules only
        self.assertIsNone(self.az.answer_problem(self.q("bastion_vm_size"), "bad-guid", {}))

    def test_the_prompt_asks_again_for_a_non_guid(self):
        seen = {}

        def fake_ask(question, default=None, validate=None, required=False, flag=None):
            if "subscription" in question.lower():
                seen["problem"] = validate("bad-guid")
                seen["ok"] = validate(GUID)
                return GUID
            return default
        with _clean_env(), _non_interactive(False), mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "ask", side_effect=fake_ask), \
                mock.patch.object(ui, "ask_bool", side_effect=lambda q, d: d), \
                mock.patch.object(azure_mod.deps, "find", return_value=None), _captured():
            out = self.az.collect_vars(_args(), {}, _cfg(), False)
        self.assertIn("not an Azure subscription ID", seen["problem"])
        self.assertIsNone(seen["ok"])
        self.assertEqual(out["subscription_id"], GUID)

    def test_a_bad_flag_is_refused_before_the_first_question(self):
        for kw, over, shown in (({"subscription_id": "bad-guid"}, None, "--subscription-id bad-guid"),
                                ({}, {"subscription_id": "bad-guid"}, "--var subscription_id=bad-guid")):
            with self.subTest(shown=shown), _clean_env(), _non_interactive(False), \
                    mock.patch.object(ui, "interactive", return_value=True), \
                    mock.patch.object(ui, "ask", side_effect=AssertionError("asked")) as ask, \
                    mock.patch.object(ui, "ask_bool", side_effect=AssertionError("asked")) as ask_bool, \
                    _captured(), self.assertRaises(ui.Abort) as cm:
                self.az.collect_vars(_args(**kw), {}, _cfg(), False, over)
            self.assertIn(shown, cm.exception.msg)
            self.assertIn("--subscription-id <GUID>", cm.exception.msg)
            ask.assert_not_called()
            ask_bool.assert_not_called()

    def test_yes_mode_still_refuses_it_in_check_vars(self):
        with self.assertRaises(ui.Abort) as cm, _captured():
            self.az.check_vars({"vars": {"subscription_id": "bad-guid"}})
        self.assertIn("is not an Azure subscription ID", cm.exception.msg)

    def test_a_saved_non_guid_is_reported_with_the_fix(self):
        cfg = {"region": "eastus", "vars": {"subscription_id": "not-a-guid"}}
        bad = self.az.invalid_answers(cfg)
        self.assertIn("subscription_id", bad)
        problems = self.az.check_config(cfg)
        self.assertTrue(any("--subscription-id VALUE" in p for p in problems), problems)
        self.assertEqual(self.az.invalid_answers({"region": "eastus", "vars": {"subscription_id": GUID}}), {})

    def test_a_valid_env_variable_is_the_default_without_running_az(self):
        with _clean_env(AZURE_SUBSCRIPTION_ID=GUID), \
                mock.patch.object(azure_mod.subprocess, "run", side_effect=AssertionError("az ran")), \
                mock.patch.object(azure_mod.deps, "find", return_value="/usr/bin/az"):
            self.assertEqual(azure_mod._default_subscription({}), GUID)
            with _non_interactive(), _captured():
                out = self.az.collect_vars(_args(), {}, _cfg(), False)
        self.assertEqual(out["subscription_id"], GUID)

    def test_an_invalid_env_variable_never_falls_back_to_the_az_subscription(self):
        fake = SimpleNamespace(stdout=json.dumps({"id": OTHER_GUID}))
        secretish = "s3cr3t-value-not-a-guid"
        with _clean_env(ARM_SUBSCRIPTION_ID=secretish), \
                mock.patch.object(azure_mod.deps, "find", return_value="/usr/bin/az"), \
                mock.patch.object(azure_mod.subprocess, "run", return_value=fake) as run, \
                _non_interactive(), _captured() as (out, err), self.assertRaises(ui.Abort) as cm:
            self.az.collect_vars(_args(), {}, _cfg(), False)
        run.assert_not_called()                                       # az account show's subscription is not assumed
        self.assertIn("--subscription-id", cm.exception.msg)
        warned = err.getvalue()
        self.assertIn("ARM_SUBSCRIPTION_ID is set but not an Azure subscription ID", warned)
        self.assertNotIn(secretish, warned + cm.exception.msg)       # the value itself is never printed

    def test_an_invalid_arm_variable_is_reported_when_azure_subscription_id_is_used(self):
        secretish = "s3cr3t-value-not-a-guid"
        with _clean_env(ARM_SUBSCRIPTION_ID=secretish, AZURE_SUBSCRIPTION_ID=GUID), \
                mock.patch.object(azure_mod.deps, "find", return_value="/usr/bin/az"), \
                mock.patch.object(azure_mod.subprocess, "run", side_effect=AssertionError("az ran")), \
                _non_interactive(), _captured() as (out, err):
            got = self.az.collect_vars(_args(), {}, _cfg(), False)
        self.assertEqual(got["subscription_id"], GUID)
        warned = err.getvalue()
        self.assertIn("ARM_SUBSCRIPTION_ID is set but not an Azure subscription ID", warned)
        self.assertIn("using the subscription in AZURE_SUBSCRIPTION_ID instead", warned)
        self.assertNotIn(secretish, warned)

    def test_a_valid_arm_variable_or_a_saved_answer_wins_without_a_warning(self):
        for env, existing, expected in (({"ARM_SUBSCRIPTION_ID": OTHER_GUID, "AZURE_SUBSCRIPTION_ID": "nope"}, {}, OTHER_GUID),
                                        ({"ARM_SUBSCRIPTION_ID": "nope"}, {"subscription_id": GUID}, GUID)):
            with self.subTest(env=env), _clean_env(**env), \
                    mock.patch.object(azure_mod.subprocess, "run", side_effect=AssertionError("az ran")), \
                    _non_interactive(), _captured() as (out, err):
                got = self.az.collect_vars(_args(), existing, _cfg(), False)
            self.assertEqual(got["subscription_id"], expected)
            self.assertNotIn("SUBSCRIPTION_ID", err.getvalue())

    def test_the_env_warning_is_shown_once_per_process(self):
        with _clean_env(ARM_SUBSCRIPTION_ID="nope"), mock.patch.object(azure_mod.deps, "find", return_value=None), \
                _captured() as (out, err):
            self.assertEqual(azure_mod._default_subscription({}), "")
            self.assertEqual(azure_mod._default_subscription({}), "")
        self.assertEqual(err.getvalue().count("ARM_SUBSCRIPTION_ID"), 1)

    def test_the_web_console_gets_the_same_rules_as_data(self):
        pattern, hint = self.az.answer_patterns["subscription_id"]
        rx = re.compile(pattern)
        self.assertTrue(rx.match(GUID) and rx.match(GUID.upper()))
        for bad in ("bad-guid", "0000-secretish", GUID + "0", GUID[:-1]):
            self.assertIsNone(rx.match(bad), bad)
        self.assertIn("GUID", hint)
        # JavaScript-compatible: no Python-only constructs (named groups, inline flags, \A / \Z anchors)
        self.assertNotRegex(pattern, r"\(\?P<|\(\?[aiLmsux]|\\A|\\Z")
        reserved = self.az.answer_reserved["admin_username"]
        self.assertIn("admin", reserved)
        for name in reserved:
            self.assertIsNotNone(self.az.answer_problem(self.q("admin_username"), name.upper(), {}), name)

    def test_a_flag_wins_over_an_invalid_env_variable(self):
        with _clean_env(ARM_SUBSCRIPTION_ID="nope"), _non_interactive(), _captured():
            out = self.az.collect_vars(_args(subscription_id=GUID), {}, _cfg(), False)
        self.assertEqual(out["subscription_id"], GUID)


# ---------------------------------------------------------------- a2-azure#7: AKS node count minimum

class NodeCountTests(_AzureCase):
    def test_the_question_refuses_zero(self):
        q = self.q("kubernetes_node_count")
        for bad in (0, "0", -1):
            self.assertIsNotNone(q.problem(bad), bad)
        self.assertIn("at least one node", q.problem("0"))
        for good in (1, "2", 5):
            self.assertIsNone(q.problem(good), good)

    def test_var_zero_is_refused_before_anything_is_saved(self):
        with _clean_env(), _non_interactive(), _captured(), self.assertRaises(ui.Abort) as cm:
            self.az.collect_vars(_args(subscription_id=GUID), {}, _cfg(), False,
                                 {"enable_kubernetes": True, "kubernetes_node_count": "0"})
        self.assertIn("kubernetes_node_count", cm.exception.msg)
        self.assertIn("at least one node", cm.exception.msg)

    def test_the_prompt_asks_again_for_zero(self):
        seen = {}

        def fake_ask(question, default=None, validate=None, required=False, flag=None):
            if question == "Kubernetes node count":
                seen["zero"], seen["three"] = validate("0"), validate("3")
                return "3"
            return default
        with _clean_env(), _non_interactive(False), mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "ask", side_effect=fake_ask), \
                mock.patch.object(ui, "ask_bool", side_effect=lambda q, d: True if "Kubernetes" in q else d), \
                _captured():
            out = self.az.collect_vars(_args(subscription_id=GUID), {}, _cfg(), True)
        self.assertIn("at least one node", seen["zero"])
        self.assertIsNone(seen["three"])
        self.assertEqual(out["kubernetes_node_count"], 3)

    def test_a_saved_zero_is_reported_not_called_the_saved_setting_later(self):
        cfg = {"region": "eastus", "vars": {"subscription_id": GUID, "kubernetes_node_count": 0}}
        self.assertIn("kubernetes_node_count", self.az.invalid_answers(cfg))
        # an unasked (cluster off) saved zero heals to the default instead of blocking the run
        with _clean_env(), _non_interactive(), _captured():
            out = self.az.collect_vars(_args(subscription_id=GUID), {"kubernetes_node_count": 0}, _cfg(), False)
        self.assertEqual(out["kubernetes_node_count"], 2)


# ---------------------------------------------------------------- a2-azure#9 / core#38: one credential probe

class CredentialProbeTests(_AzureCase):
    def test_arm_credentials_follow_the_provider(self):
        cases = [
            ({}, False),
            ({"ARM_USE_MSI": "true"}, True),                         # system-assigned identity: no client ID needed
            ({"ARM_USE_MSI": "1"}, True),
            ({"ARM_USE_MSI": "false", "ARM_CLIENT_ID": "c"}, False),
            ({"ARM_USE_AKS_WORKLOAD_IDENTITY": "True"}, True),
            ({"ARM_CLIENT_ID": "c", "ARM_CLIENT_SECRET": "s"}, True),
            ({"ARM_CLIENT_ID_FILE_PATH": "/f", "ARM_CLIENT_SECRET_FILE_PATH": "/g"}, True),
            ({"ARM_CLIENT_ID": "c", "ARM_CLIENT_CERTIFICATE_PATH": "/cert.pfx"}, True),
            ({"ARM_CLIENT_ID": "c", "ARM_CLIENT_CERTIFICATE": "base64"}, True),
            ({"ARM_CLIENT_ID": "c", "ARM_USE_OIDC": "true"}, True),
            ({"ARM_CLIENT_ID": "c", "ARM_USE_OIDC": "false"}, False),   # any non-empty value used to count
            ({"ARM_CLIENT_ID": "c", "ARM_OIDC_TOKEN": "t"}, False),     # a token does nothing while use_oidc is off
            ({"ARM_CLIENT_SECRET": "s"}, False),                         # no client
            ({"ARM_CLIENT_ID": " ", "ARM_CLIENT_SECRET": "s"}, False),
        ]
        for env, expected in cases:
            with self.subTest(env=env):
                self.assertEqual(bool(azure_mod.arm_credentials(env)), expected)
        self.assertIn("ARM_USE_MSI", azure_mod.arm_credentials({"ARM_USE_MSI": "true"}))

    def _profile(self, directory: Path, subscriptions, bom=True) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "azureProfile.json"
        text = json.dumps({"installationId": "x", "subscriptions": subscriptions})
        path.write_text(("﻿" if bom else "") + text, encoding="utf-8")
        return path

    def test_the_profile_under_azure_config_dir_counts(self):
        tmp = Path(tempfile.mkdtemp())
        self._profile(tmp / "az", [{"id": GUID}])
        with _clean_env(AZURE_CONFIG_DIR=str(tmp / "az"), HOME=str(tmp / "home")), \
                mock.patch.object(azure_mod.deps, "find", return_value="/usr/bin/az"):
            self.assertEqual(azure_mod.az_profile_path(), tmp / "az" / "azureProfile.json")
            self.assertEqual(self.az.credential_warnings({"vars": {}}), [])

    def test_home_profile_and_logout(self):
        tmp = Path(tempfile.mkdtemp())
        with _clean_env(HOME=str(tmp)), mock.patch.object(azure_mod.deps, "find", return_value="/usr/bin/az"):
            self.assertIn("No Azure credentials detected", self.az.credential_warnings({"vars": {}})[0])
            self._profile(tmp / ".azure", [{"id": GUID}], bom=False)
            self.assertEqual(self.az.credential_warnings({"vars": {}}), [])
            self._profile(tmp / ".azure", [])                        # az logout leaves the file, without subscriptions
            self.assertIn("No Azure credentials detected", self.az.credential_warnings({"vars": {}})[0])
            (tmp / ".azure" / "azureProfile.json").write_text("{not json")   # unreadable: never a false warning
            self.assertEqual(self.az.credential_warnings({"vars": {}}), [])

    def test_env_credentials_need_no_az(self):
        with _clean_env(ARM_USE_MSI="true"), mock.patch.object(azure_mod.deps, "find", return_value=None):
            self.assertEqual(self.az.credential_warnings({"vars": {}}), [])
        with _clean_env(ARM_CLIENT_ID="c", ARM_USE_OIDC="false", HOME=tempfile.mkdtemp()), \
                mock.patch.object(azure_mod.deps, "find", return_value=None):
            self.assertIn("not installed", self.az.credential_warnings({"vars": {}})[0])

    def test_use_cli_false_without_arm_credentials(self):
        tmp = Path(tempfile.mkdtemp())
        self._profile(tmp / ".azure", [{"id": GUID}])
        with _clean_env(ARM_USE_CLI="false", HOME=str(tmp)), \
                mock.patch.object(azure_mod.deps, "find", return_value="/usr/bin/az"):
            warnings = self.az.credential_warnings({"vars": {}})
        self.assertEqual(len(warnings), 1)
        self.assertIn("ARM_USE_CLI", warnings[0])


# ---------------------------------------------------------------- Terraform (text; the tftest suite runs them for real)

def _block(text: str, header: str) -> str:
    start = text.index(header)
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise AssertionError(f"unbalanced block {header}")


class TerraformTextTests(unittest.TestCase):
    def test_defender_plans_name_their_subplan(self):                        # a2-azure#2
        text = (TF / "modules" / "security-baseline" / "main.tf").read_text()
        block = _block(text, 'resource "azurerm_security_center_subscription_pricing" "this"')
        self.assertIn("subplan       = each.value", block)
        self.assertIn("resource_type = each.key", block)
        self.assertRegex(block, r"ignore_changes\s*=\s*\[subplan, extension\]")
        self.assertRegex(text, r'defender_plans\s*=\s*\{\s*VirtualMachines\s*=\s*"P2",\s*StorageAccounts\s*=\s*'
                               r'"DefenderForStorageV2"\s*\}')
        # the instance keys (what keep_on_destroy / reconcile see) are unchanged
        az = clouds.get("azure")
        addr = 'module.stack.module.security_baseline.azurerm_security_center_subscription_pricing.this["VirtualMachines"]'
        self.assertEqual(len(az.keep_on_destroy({"vars": {"subscription_id": GUID}}, [addr])), 1)

    def test_private_aks_publishes_its_api_name(self):                       # a2-azure#5
        text = (TF / "modules" / "kubernetes" / "main.tf").read_text()
        cluster = _block(text, 'resource "azurerm_kubernetes_cluster" "this"')
        self.assertRegex(cluster, r"private_cluster_public_fqdn_enabled\s*=\s*!var\.public_endpoint\n")
        endpoint = _block(text, 'output "endpoint"')
        # the public FQDN first: the privatelink name resolves inside the VNet only (not over the VPN)
        self.assertRegex(endpoint, r"coalesce\(azurerm_kubernetes_cluster\.this\.fqdn, azurerm_kubernetes_cluster\.this\.private_fqdn\)")
        desc = dict(helpmod._parse_outputs("azure"))["kubernetes_endpoint"]
        self.assertIn("VPN", desc)

    def test_vpn_port_is_range_checked_and_described(self):                   # a2-azure#13
        variables = (TF / "variables.tf").read_text()
        var = _block(variables, 'variable "vpn_port"')
        self.assertIn("var.vpn_port >= 1 && var.vpn_port <= 65535 && floor(var.vpn_port) == var.vpn_port", var)
        parsed = {name: desc for name, desc, _ in helpmod._parse_variables("azure")}
        self.assertTrue(parsed["vpn_port"])
        tests = (TF / "tests" / "stack.tftest.hcl").read_text()
        for run in ("vpn_port_zero_is_refused", "vpn_port_above_65535_is_refused", "fractional_vpn_port_is_refused",
                    "defender_plans_name_their_subplan", "defender_off_creates_no_pricing"):
            self.assertIn(f'run "{run}"', tests)

    def test_node_count_minimum_matches_the_stack(self):
        # vpn_port is a plain stack variable (--var), not a wizard question
        keys = {q.key for q in clouds.get("azure").questions}
        self.assertNotIn("vpn_port", keys)
        # the stack's own node-count minimum matches the question's
        var = _block((TF / "variables.tf").read_text(), 'variable "kubernetes_node_count"')
        self.assertTrue(re.search(r"var\.kubernetes_node_count >= 1", var))


if __name__ == "__main__":
    unittest.main()
