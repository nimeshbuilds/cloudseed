"""Regression tests for the wave-4 Azure work (cross-file changes other groups needed in the Azure adapter/stack):
the VMs' instance IDs as outputs, Azure's own tag rules, the location check against the Azure cloud in effect, the
state root's provider constraint, the question order and vpn_type choices, and a credential probe that never says
'no credentials' next to a login az itself reports.

Fast and offline: the adapter is exercised directly (az is always mocked) and the Terraform files are checked as text.
The plan-level suite in terraform/azure/tests (mock providers) runs with CLOUDSEED_TF_TESTS=1
(tests.test_fix_azure.AzureTerraformSuite).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, help as helpmod, paths, provision, ui  # noqa: E402
from cloudseed.clouds import azure as azure_mod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform" / "azure"
GUID = "0123abcd-0000-0000-0000-000000000000"
_ENV_VARS = ("ARM_ENVIRONMENT", "ARM_METADATA_HOSTNAME", "AZURE_CONFIG_DIR", "ARM_SUBSCRIPTION_ID",
             "AZURE_SUBSCRIPTION_ID", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_USE_MSI", "ARM_USE_OIDC",
             "ARM_USE_AKS_WORKLOAD_IDENTITY", "ARM_USE_CLI", "ARM_CLIENT_ID_FILE_PATH", "ARM_CLIENT_SECRET_FILE_PATH",
             "ARM_CLIENT_CERTIFICATE_PATH", "ARM_CLIENT_CERTIFICATE")


@contextlib.contextmanager
def _captured():
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        yield out, err


@contextlib.contextmanager
def _env(**values):
    """Only the given Azure variables are set (the others are removed for the duration)."""
    with mock.patch.dict(os.environ, {}, clear=False):
        for name in _ENV_VARS:
            os.environ.pop(name, None)
        os.environ.update(values)
        yield


def _cfg(tags=None, **vars_):
    v = {"subscription_id": GUID}
    v.update(vars_)
    return {"cloud": "azure", "env": "dev", "name": "cloudseed", "owner": "me", "uid": "abc123", "region": "eastus",
            "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.7/32"],
            "ssh_public_key": "ssh-ed25519 AAAA test", "state": {"type": "local", "backend": None},
            "vars": v, "extra_vars": {}, "tags": dict(tags or {}), "platform_prereqs": []}


def _block(text: str, header: str) -> str:
    start = text.index(header)
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise AssertionError(f"unbalanced block {header}")


class _AzureCase(unittest.TestCase):
    def setUp(self):
        self.az = clouds.get("azure")
        for name in ("_SUBSCRIPTION_CACHE", "_LOCATIONS_CACHE", "_WARNED_LOCATIONS", "_WARNED_ENV"):
            cache = getattr(azure_mod, name, None)
            if cache is not None:
                cache.clear()
                self.addCleanup(cache.clear)


# ---------------------------------------------------------------- need-ansible: the VMs' instance IDs

class InstanceIdOutputTests(_AzureCase):
    def test_outputs_are_declared_rendered_and_described(self):
        for name in ("bastion_instance_id", "vpn_instance_id"):
            self.assertIn(name, self.az.outputs)
        described = dict(helpmod._parse_outputs("azure"))
        self.assertIn("re-created", described["bastion_instance_id"])
        self.assertIn("null when disabled", described["vpn_instance_id"])
        root = self.az.render_stack(_cfg(), paths.tf_root())
        self.assertEqual(root["output"]["bastion_instance_id"], {"value": "${module.stack.bastion_instance_id}"})
        self.assertEqual(root["output"]["vpn_instance_id"], {"value": "${module.stack.vpn_instance_id}"})
        # every output the adapter renders is declared by the stack (a missing one fails terraform validate)
        self.assertLessEqual(set(self.az.outputs), set(described))

    def test_they_come_from_the_vm_unique_id(self):
        outputs = (TF / "outputs.tf").read_text()
        self.assertIn("module.bastion.instance_id", _block(outputs, 'output "bastion_instance_id"'))
        self.assertIn("try(module.vpn[0].instance_id, null)", _block(outputs, 'output "vpn_instance_id"'))
        for mod, res in (("bastion", "bastion"), ("vpn", "vpn")):
            text = (TF / "modules" / mod / "main.tf").read_text()
            # vmId changes when the VM is re-created; the resource ID (its name) does not
            self.assertIn(f'output "instance_id" {{ value = azurerm_linux_virtual_machine.{res}.virtual_machine_id }}', text)
        tests = (TF / "tests" / "stack.tftest.hcl").read_text()
        for run in ("host_instance_ids", "no_vpn_no_vpn_instance_id"):
            self.assertIn(f'run "{run}"', tests)

    def test_a_replaced_vm_has_its_host_key_forgotten(self):
        before = {"bastion_public_ip": "20.1.2.3", "bastion_instance_id": "1111", "vpn_public_ip": "20.1.2.4",
                  "vpn_instance_id": "aaaa"}
        after = dict(before, bastion_instance_id="2222")
        with mock.patch.object(provision, "forget_host_key") as forget:
            self.assertEqual(provision.forget_replaced_hosts(object(), before, after), ["20.1.2.3"])
        forget.assert_called_once()


# ---------------------------------------------------------------- a2-azure#6: Azure's tag rules

class TagRuleTests(_AzureCase):
    def test_reserved_characters_are_refused_and_named(self):
        for key, shown in (("team/app", "/"), ("cost%center", "%"), ("a<b>c", "< >"), ("x&y", "&"), ("why?", "?"),
                           ("back\\slash", "\\")):
            with self.subTest(key=key):
                problem = self.az.tag_problem(key, "v")
                self.assertIsNotNone(problem)
                self.assertIn(f"cannot contain {shown}", problem)
                self.assertIn(". - _ or :", problem)
        self.assertIn("e.g. --tag team-app=v", self.az.tag_problem("team/app", "v"))
        self.assertIn("control characters", self.az.tag_problem("tab\there", "v"))
        self.assertIn("/ or control characters", self.az.tag_problem("a/\x01", "v"))

    def test_lengths(self):
        self.assertIsNone(self.az.tag_problem("k" * 128, "v" * 256))
        self.assertIn("at most 128", self.az.tag_problem("k" * 129, "v"))
        self.assertIn("at most 256", self.az.tag_problem("k", "v" * 257))

    def test_good_tags_and_generic_rules(self):
        for key in ("team", "app.kubernetes.io:name", "cost-center_1", "Owner", "with space"):
            self.assertIsNone(self.az.tag_problem(key, "any value <>%&?/ is fine"), key)
        self.assertIn("set by cloudseed", self.az.tag_problem("managedby", "x"))     # super() first
        self.assertIn("${", self.az.tag_problem("k", "${x}"))
        # --tag KEY= removes a saved tag: nothing is rendered, so it is never refused for Azure's characters
        self.assertIsNone(self.az.tag_problem("team/app", ""))

    def test_check_config_reports_the_tag_with_its_fix(self):
        problems = self.az.check_config(_cfg(tags={"team/app": "a<b", "ok": "1"}))
        self.assertEqual(len(problems), 1)
        self.assertIn("--tag team/app=a<b: Azure tag names cannot contain /", problems[0])
        self.assertIn("--tag team/app=)", problems[0])

    def test_setup_flag_is_refused_before_anything_is_saved(self):
        args = SimpleNamespace(name=None, region=None, allow_ip=None, cidr=None, tag=["team/app=1"],
                               **{k: None for k in clouds.Question.FLAG_KEYS})
        with _captured(), self.assertRaises(ui.Abort) as cm:
            cli._check_setup_flags(self.az, args)
        self.assertIn("--tag team/app=1: Azure tag names cannot contain /", cm.exception.msg)
        # a saved bad tag (from an older version) is dropped with a warning instead of blocking every later setup
        with _captured() as (_out, err):
            self.assertEqual(cli._saved_tags(self.az, {"tags": {"team/app": "1", "ok": "2"}}), {"ok": "2"})
        self.assertIn("Dropping the saved tag team/app=1", err.getvalue())

    def test_at_most_43_tags_of_your_own(self):
        tags = {f"t{i}": "x" for i in range(43)}
        tags.update({"Project": "p", "environment": "e", "role": "r"})       # built-in names do not count
        self.assertEqual(self.az.tags_problems(_cfg(tags=tags)), [])
        tags["one-more"] = "x"
        problems = self.az.tags_problems(_cfg(tags=tags))
        self.assertEqual(len(problems), 1)
        self.assertIn("at most 43 of your own; drop 1", problems[0])
        tags["gone"] = ""                                                      # an emptied tag renders nothing
        self.assertEqual(len(self.az.tags_problems(_cfg(tags=tags))), 1)

    def test_case_duplicates_are_still_refused(self):
        problems = self.az.tags_problems(_cfg(tags={"team": "a", "TEAM": "b"}))
        self.assertTrue(any("differ only in case" in p for p in problems), problems)

    def test_terraform_keeps_one_role_and_lets_environment_be_overridden(self):
        main = (TF / "main.tf").read_text()
        self.assertRegex(main, r'tags\s*=\s*merge\(\{ Environment = var\.environment \}, var\.tags, \{ ManagedBy = "cloudseed" \}\)')
        for mod in ("bastion", "vpn"):
            text = (TF / "modules" / mod / "main.tf").read_text()
            self.assertIn(f'merge({{ for k, v in var.tags : k => v if lower(k) != "role" }}, {{ Role = "{mod}" }})', text)
        tests = (TF / "tests" / "stack.tftest.hcl").read_text()
        for run in ("environment_tag_override_wins", "environment_tag_defaults_to_the_env", "vm_role_tag_is_not_duplicated"):
            self.assertIn(f'run "{run}"', tests)
        # Cloud.tags already folds any spelling of Environment onto that key, so the override reaches the stack
        self.assertEqual(self.az.stack_vars(_cfg(tags={"environment": "staging"}))["tags"]["Environment"], "staging")


# ---------------------------------------------------------------- a2-azure#12: the location

def _fake_az(names, calls=None):
    def run(argv, **kw):
        assert kw.get("stdin") is subprocess.DEVNULL, "az must never wait on (or read) cloudseed's stdin"
        if calls is not None:
            calls.append(argv)
        if argv[1:3] == ["account", "list-locations"]:
            return SimpleNamespace(stdout=json.dumps(names) if not isinstance(names, str) else names, returncode=0)
        return SimpleNamespace(stdout="", returncode=1)
    return run


class LocationTests(_AzureCase):
    def setUp(self):
        super().setUp()
        self.find = mock.patch.object(azure_mod.deps, "find", return_value=None)     # no az unless a test says so
        self.find.start()
        self.addCleanup(self.find.stop)

    def check(self, value, **env):
        with _env(**env), _captured() as (_out, err):
            problem = self.az.region_problem(value)
        return problem, err.getvalue()

    def test_known_locations_pass_silently(self):
        for value in ("eastus", "westeurope", "swedencentral", "East US 2", "australiacentral2"):
            self.assertEqual(self.check(value), (None, ""), value)

    def test_unknown_location_without_az_is_only_warned_about_once(self):
        problem, err = self.check("useast")
        self.assertIsNone(problem)                  # a location newer than the bundled list must still work
        self.assertIn("'useast' is not an Azure location cloudseed knows (did you mean eastus?)", err)
        self.assertIn("az account list-locations", err)
        self.assertEqual(self.check("useast"), (None, ""))                     # setup checks --region twice
        self.assertIn("did you mean westeurope?", self.check("westeurop")[1])
        self.assertIn("did you mean eastus2?", self.check("useast2")[1])
        self.assertNotIn("did you mean", self.check("mars")[1])

    def test_sovereign_locations_need_their_arm_environment(self):
        problem, _ = self.check("usgovvirginia")
        self.assertIn("Azure Government", problem)
        self.assertIn("export ARM_ENVIRONMENT=usgovernment", problem)
        self.assertIn("az cloud set --name AzureUSGovernment", problem)
        self.assertIn("such as eastus", problem)
        problem, _ = self.check("chinanorth3")
        self.assertIn("export ARM_ENVIRONMENT=china", problem)
        self.assertEqual(self.check("usgovvirginia", ARM_ENVIRONMENT="usgovernment"), (None, ""))
        self.assertEqual(self.check("usdodeast", ARM_ENVIRONMENT="AzureUSGovernment"), (None, ""))
        self.assertEqual(self.check("chinanorth3", ARM_ENVIRONMENT="china"), (None, ""))

    def test_public_location_in_a_sovereign_cloud(self):
        problem, _ = self.check("eastus", ARM_ENVIRONMENT="usgovernment")
        self.assertIn("ARM_ENVIRONMENT=usgovernment points Terraform at Azure Government", problem)
        self.assertIn("usgovvirginia", problem)
        self.assertIn("unset ARM_ENVIRONMENT", problem)
        problem, _ = self.check("chinaeast2", ARM_ENVIRONMENT="usgovernment")
        self.assertIn("export ARM_ENVIRONMENT=china", problem)

    def test_custom_or_unknown_clouds_are_not_checked(self):
        self.assertEqual(self.check("local", ARM_METADATA_HOSTNAME="management.azurestack.local"), (None, ""))
        self.assertEqual(self.check("usgovvirginia", ARM_ENVIRONMENT="something-else"), (None, ""))
        self.assertEqual(azure_mod.arm_cloud({}), "public")
        self.assertEqual(azure_mod.arm_cloud({"ARM_ENVIRONMENT": " Public "}), "public")
        self.assertEqual(azure_mod.arm_cloud({"ARM_ENVIRONMENT": "AzureChinaCloud"}), "china")

    def test_az_live_list_is_the_authority(self):
        live = sorted(azure_mod.PUBLIC_LOCATIONS + ("brandnewregion",))
        calls: list = []
        with mock.patch.object(azure_mod.deps, "find", return_value="/opt/az/bin/az"), \
                mock.patch.object(azure_mod.subprocess, "run", side_effect=_fake_az(live, calls)):
            problem, _ = self.check("mars")
            self.assertIn("'mars' is not an Azure location", problem)
            self.assertIn("az account list-locations -o table", problem)
            problem, _ = self.check("useast")
            self.assertIn("did you mean eastus?", problem)
            self.assertEqual(self.check("brandnewregion"), (None, ""))       # newer than the bundled list
            self.assertEqual(self.check("eastus"), (None, ""))               # bundled: az is not even asked
        self.assertEqual(len(calls), 1)                                      # cached
        self.assertIn("[?metadata.regionType=='Physical'].name", calls[0])

    def test_a_live_list_of_another_cloud_or_garbage_is_ignored(self):
        for answer in (list(azure_mod.USGOV_LOCATIONS), "not json", {"id": GUID}, [], ["East US"]):
            azure_mod._LOCATIONS_CACHE.clear()
            azure_mod._WARNED_LOCATIONS.clear()
            with self.subTest(answer=answer), mock.patch.object(azure_mod.deps, "find", return_value="/opt/az/bin/az"), \
                    mock.patch.object(azure_mod.subprocess, "run", side_effect=_fake_az(answer)):
                problem, err = self.check("mars")
                self.assertIsNone(problem)
                self.assertIn("not an Azure location cloudseed knows", err)

    def test_az_failure_is_cached_as_unknown(self):
        calls: list = []

        def boom(argv, **kw):
            calls.append(argv)
            raise OSError("az broke")
        with mock.patch.object(azure_mod.deps, "find", return_value="/opt/az/bin/az"), \
                mock.patch.object(azure_mod.subprocess, "run", side_effect=boom):
            self.assertIsNone(self.check("mars")[0])
            self.assertIsNone(self.check("venus")[0])
        self.assertEqual(len(calls), 1)

    def test_cli_uses_the_hook(self):
        with _env(), _captured():
            self.assertIn("export ARM_ENVIRONMENT=usgovernment", cli._region_problem(self.az, "usgovvirginia"))
            self.assertIsNone(cli._region_problem(self.az, "East US"))
            self.assertIn("is not a Microsoft Azure location name", cli._region_problem(self.az, "east-us"))
        args = SimpleNamespace(name=None, region="usgovtexas", allow_ip=None, cidr=None, tag=None,
                               **{k: None for k in clouds.Question.FLAG_KEYS})
        with _env(), _captured(), self.assertRaises(ui.Abort) as cm:
            cli._check_setup_flags(self.az, args)
        self.assertIn("--region: 'usgovtexas' is a location of Azure Government", cm.exception.msg)

    def test_the_default_location_belongs_to_the_cloud_in_effect(self):
        for env, want in (({}, "eastus"), ({"ARM_ENVIRONMENT": "usgovernment"}, "usgovvirginia"),
                          ({"ARM_ENVIRONMENT": "china"}, "chinanorth3"), ({"ARM_ENVIRONMENT": "bogus"}, "eastus")):
            with self.subTest(env=env), _env(**env):
                self.assertEqual(self.az.default_region, want)
                self.assertEqual(self.check(want, **env), (None, ""))

    def test_bundled_lists_are_well_formed(self):
        lists = (azure_mod.PUBLIC_LOCATIONS, azure_mod.USGOV_LOCATIONS, azure_mod.CHINA_LOCATIONS)
        seen: set = set()
        for names in lists:
            self.assertEqual(len(names), len(set(names)))
            for name in names:
                self.assertRegex(name, r"^[a-z][a-z0-9]+$")
                self.assertRegex(name, cli.REGION_RE["azure"])
            self.assertFalse(seen & set(names))
            seen |= set(names)
        for name in azure_mod.PUBLIC_LOCATIONS:
            self.assertFalse(name.startswith(("usgov", "usdod", "china")), name)


# ---------------------------------------------------------------- a2-azure#14: the state root's provider constraint

class BootstrapConstraintTests(_AzureCase):
    def test_bootstrap_needs_4_9_and_stays_below_the_stack(self):
        self.assertEqual(self.az.AZURERM_BOOTSTRAP_VERSION, ">= 4.9, < 5.0")
        boot = self.az.render_bootstrap(_cfg(), paths.tf_root())
        self.assertEqual(boot["terraform"]["required_providers"]["azurerm"]["version"], ">= 4.9, < 5.0")
        self.assertEqual(self.az.required_providers()["azurerm"]["version"], ">= 4.65, < 5.0")
        module = (ROOT / "terraform" / "azure-bootstrap" / "main.tf").read_text()
        self.assertIn('version = ">= 4.9, < 5.0"', module)
        self.assertNotIn("~> 4.0", module)
        self.assertIn("storage_account_id", module)       # the 4.9 attribute the constraint exists for


# ---------------------------------------------------------------- questions (a2-gcp#19 order, vpn_type choices)

class QuestionTests(_AzureCase):
    def test_cluster_settings_follow_their_switch(self):
        keys = [q.key for q in self.az.questions]
        k = keys.index("enable_kubernetes")
        self.assertEqual(keys[k + 1:k + 4], ["kubernetes_node_size", "kubernetes_node_count", "kubernetes_public_endpoint"])
        self.assertEqual(keys[k + 4:k + 6], ["enable_vpn", "vpn_type"])

    def test_vpn_type_is_a_choice(self):
        q = self.az.question("vpn_type")
        self.assertEqual(q.choices, ("openvpn", "tailscale"))
        self.assertEqual(q.coerce("Tailscale"), "tailscale")
        self.assertIn("is not one of: openvpn, tailscale", q.problem("wireguard"))

    def test_stack_vars_read_saved_answers_strictly(self):
        v = self.az.stack_vars(_cfg(vpn_type="Tailscale", enable_vpn="yes", enable_defender=None, fips_mode=" ",
                                    enable_activity_log="off"))
        self.assertEqual(v["vpn_type"], "tailscale")                  # as the stack's validation spells it
        self.assertEqual((v["enable_vpn"], v["enable_defender"], v["fips_mode"], v["enable_activity_log"]),
                         (True, False, False, False))
        self.assertEqual(self.az.stack_vars(_cfg())["vpn_type"], "openvpn")
        with _captured(), self.assertRaises(ui.Abort) as cm:
            self.az.stack_vars(_cfg(vpn_type="wireguard"))
        self.assertIn("vpn_type='wireguard'", cm.exception.msg)
        self.assertIn("--var vpn_type=VALUE", cm.exception.msg)

    def test_asked_in_order_with_advanced(self):
        asked: list = []

        def fake_ask(question, default=None, **kw):
            asked.append(question)
            return default

        def fake_bool(question, default):
            asked.append(question)
            return question.startswith("Create a private managed Kubernetes") or question.startswith("Create a VPN")
        args = SimpleNamespace(subscription_id=GUID, admin_username=None, project_id=None, zone=None, ssh_username=None,
                               profile=None)
        with _env(), mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "ask", side_effect=fake_ask), mock.patch.object(ui, "ask_bool", side_effect=fake_bool), \
                _captured():
            out = self.az.collect_vars(args, {}, {"region": "eastus", "workdir": tempfile.mkdtemp()}, True)
        order = [a.split("?")[0].split(" (")[0] for a in asked]
        self.assertLess(order.index("Kubernetes node count"), order.index("Create a VPN host"))
        self.assertEqual(order.index("Kubernetes node size"), order.index("Create a private managed Kubernetes cluster") + 1)
        self.assertEqual(out["vpn_type"], "openvpn")


# ---------------------------------------------------------------- remaining (cli/deps): one credential verdict

class CredentialVerdictTests(_AzureCase):
    def test_no_profile_but_az_reports_a_login(self):
        home = tempfile.mkdtemp()
        ok = SimpleNamespace(stdout=json.dumps({"id": GUID, "name": "sub"}), returncode=0)
        with _env(HOME=home), mock.patch.object(azure_mod.deps, "find", return_value="/opt/az/bin/az"), \
                mock.patch.object(azure_mod.subprocess, "run", return_value=ok) as run:
            self.assertEqual(self.az.credential_warnings({"vars": {}}), [])
            self.assertEqual(self.az.credential_warnings({"vars": {}}), [])
        self.assertEqual(run.call_count, 1)                           # the same cached `az account show`

    def test_no_profile_and_az_not_logged_in(self):
        home = tempfile.mkdtemp()
        with _env(HOME=home), mock.patch.object(azure_mod.deps, "find", return_value="/opt/az/bin/az"), \
                mock.patch.object(azure_mod.subprocess, "run", return_value=SimpleNamespace(stdout="", returncode=1)):
            warnings = self.az.credential_warnings({"vars": {}})
        self.assertEqual(len(warnings), 1)
        self.assertIn("No Azure credentials detected", warnings[0])

    def test_the_login_cache_follows_azure_config_dir(self):
        runs: list = []

        def run(argv, **kw):
            self.assertIs(kw.get("stdin"), subprocess.DEVNULL)
            runs.append(os.environ.get("AZURE_CONFIG_DIR"))
            return SimpleNamespace(stdout=json.dumps({"id": GUID}) if os.environ.get("AZURE_CONFIG_DIR") == "/a" else "")
        with mock.patch.object(azure_mod.subprocess, "run", side_effect=run):
            with _env(AZURE_CONFIG_DIR="/a"):
                self.assertEqual(azure_mod._az_subscription("/opt/az/bin/az"), GUID)
            with _env(AZURE_CONFIG_DIR="/b"):
                self.assertEqual(azure_mod._az_subscription("/opt/az/bin/az"), "")
            with _env(AZURE_CONFIG_DIR="/a"):
                self.assertEqual(azure_mod._az_subscription("/opt/az/bin/az"), GUID)
        self.assertEqual(runs, ["/a", "/b"])


# ---------------------------------------------------------------- variable descriptions (help variables azure)

class VariableDescriptionTests(unittest.TestCase):
    def test_every_plain_stack_variable_is_described(self):
        parsed = {name: desc for name, desc, _ in helpmod._parse_variables("azure")}
        for name in ("subnet_newbits", "vpn_vm_size", "vpn_port", "enable_vpn", "vpn_type"):
            self.assertTrue(parsed.get(name), name)
        self.assertIn("/24", parsed["subnet_newbits"])
        page = helpmod.variables_page("azure")
        self.assertRegex(page, r"vpn_vm_size[^\n]*\n\s+VM size of the VPN host")


if __name__ == "__main__":
    unittest.main()
