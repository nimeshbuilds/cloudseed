"""Wave 4 regression tests for the GCP adapter and stack: the shared strict bool/int parsers (no GCP copies), typed
saved answers in stack_vars, question order / choices / ranges, the zone prompt, unusable Google keys named by the
credential check, the owner label of environments made by earlier versions, OS Login keys that expire, machine-type
self-links, and the Terraform side (no unused fips_mode input on the GKE module, descriptions, the node-count rule).
Offline and fast: no cloud, no network, no terraform (the plan-level checks live in terraform/gcp/tests)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, creds, help as helpmod, paths, reconcile, ui  # noqa: E402
from cloudseed.clouds import base as cloudbase  # noqa: E402
from cloudseed.clouds import gcp as gcpmod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform"
GCP = clouds.get("gcp")
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEnvKey cloudseed-gcp-dev"


def _cfg(**over):
    cfg = {"cloud": "gcp", "env": "dev", "name": "acme", "owner": "me", "region": "us-central1",
           "network_cidr": "10.0.0.0/16", "allowed_ssh_cidrs": ["1.2.3.4/32"], "ssh_public_key": KEY,
           "state": {"type": "local", "backend": None}, "extra_vars": {}, "tags": {},
           "vars": {"project_id": "my-proj-123", "zone": "us-central1-a", "ssh_username": "alice"}}
    vars_ = over.pop("vars", {})
    cfg.update(over)
    cfg["vars"].update(vars_)
    return cfg


class _Quiet(unittest.TestCase):
    def setUp(self):
        self._ni = ui.NON_INTERACTIVE
        ui.NON_INTERACTIVE = True
        p = mock.patch.object(ui, "err"), mock.patch.object(ui, "warn"), mock.patch.object(ui, "info"), mock.patch.object(ui, "ok")
        self.err, self.warn, self.info, self.okm = (x.start() for x in p)
        for x in p:
            self.addCleanup(x.stop)

    def tearDown(self):
        ui.NON_INTERACTIVE = self._ni

    def said(self, m) -> str:
        return "\n".join(str(c.args[0]) for c in m.call_args_list)

    def problems(self, cfg) -> str:
        try:
            GCP.check_vars(cfg)
        except ui.Abort as e:
            return e.msg
        return ""


# ---------------------------------------------------------------- a2-gcp#14: one strict parser, typed saved answers
class SharedParserTests(_Quiet):
    def test_the_base_parsers_are_used(self):
        self.assertIs(gcpmod.as_bool, cloudbase.as_bool)
        self.assertIs(gcpmod.as_int, cloudbase.as_int)
        for gone in ("_TRUE", "_FALSE"):
            self.assertFalse(hasattr(gcpmod, gone), gone)
        self.assertFalse(hasattr(GCP, "_saved"))
        # the lenient reader stays lenient
        for value, want in ((None, False), ("", False), ("maybe", False), ("yes", True), (1, True)):
            self.assertIs(gcpmod._truthy(value), want, value)
        # --var numbers: Terraform numbers (20.0) and negative ones (the caller says why they are out of range)
        self.assertEqual((gcpmod._whole(20.0), gcpmod._whole(" -3 "), gcpmod._whole("7")), (20, -3, 7))
        with self.assertRaises(ValueError):
            gcpmod._whole(2.5)

    def test_blank_or_missing_saved_answers_mean_the_default(self):
        sv = GCP.stack_vars(_cfg(vars={"enable_kubernetes": None, "fips_mode": "", "enable_vpn": " ",
                                       "kubernetes_node_count": "", "bastion_machine_type": "",
                                       "kubernetes_node_size": None, "vpn_type": ""}))
        self.assertEqual((sv["enable_kubernetes"], sv["fips_mode"], sv["enable_vpn"]), (False, False, False))
        self.assertEqual(sv["kubernetes_node_count"], 2)
        self.assertEqual((sv["bastion_machine_type"], sv["kubernetes_node_size"], sv["vpn_type"]),
                         ("e2-micro", "e2-standard-2", "openvpn"))
        self.assertEqual(GCP.stack_vars(_cfg(vars={"vpn_type": "Tailscale"}))["vpn_type"], "tailscale")

    def test_other_bad_saved_answers_abort_with_the_fix(self):
        for key, value in (("enable_vpn", "maybe"), ("kubernetes_node_count", "abc"), ("kubernetes_node_count", -1)):
            with self.assertRaises(ui.Abort) as cm:
                GCP.stack_vars(_cfg(vars={key: value}))
            self.assertIn(f"cloudseed setup gcp --env dev --var {key}=VALUE", cm.exception.msg)
        # a saved 0 (Kubernetes off) still renders: status and destroy are never locked out by an unused value
        self.assertEqual(GCP.stack_vars(_cfg(vars={"kubernetes_node_count": 0}))["kubernetes_node_count"], 0)

    def test_heal_saved_only_heals_the_zone(self):
        saved = {"enable_vpn": "YES", "kubernetes_node_count": "abc", "zone": "us-central1-b"}
        healed = GCP._heal_saved(saved, {"region": "us-central1"})
        self.assertEqual(healed, saved)                       # typing is cli._saved_answers' job (Cloud._usable too)
        self.assertEqual(self.said(self.warn), "")
        out = GCP.collect_vars(SimpleNamespace(project_id="my-proj-123", zone=None, ssh_username="alice"),
                               {"enable_vpn": "YES", "kubernetes_node_count": "abc"},
                               {"region": "us-central1", "name": "acme", "env": "dev"}, False)
        self.assertIs(out["enable_vpn"], True)
        self.assertEqual(out["kubernetes_node_count"], 2)     # unusable: the built-in default, with a warning
        self.assertIn("kubernetes_node_count", self.said(self.warn))

    def test_kubernetes_module_has_no_unused_fips_input(self):
        k8s = (TF / "gcp" / "modules" / "kubernetes" / "main.tf").read_text()
        self.assertNotIn('variable "fips_mode"', k8s)
        self.assertNotIn("var.fips_mode", k8s)
        self.assertIn('image_type      = "COS_CONTAINERD"', k8s)          # FIPS-validated kernel crypto in every mode
        root = (TF / "gcp" / "main.tf").read_text()
        block = root[root.index('module "kubernetes"'):root.index('module "vpn"')]
        self.assertNotIn("fips_mode", block)


# ---------------------------------------------------------------- questions: order, choices, range, zone prompt
class QuestionTests(_Quiet):
    def test_cluster_settings_follow_enable_kubernetes(self):
        keys = [q.key for q in GCP.questions]
        k = keys.index("enable_kubernetes")
        self.assertEqual(keys[k + 1:k + 4], ["kubernetes_node_size", "kubernetes_node_count", "kubernetes_public_endpoint"])
        self.assertEqual(keys[k + 4:k + 6], ["enable_vpn", "vpn_type"])

    def test_zone_prompt_names_every_zonal_resource(self):
        q = next(q for q in GCP.questions if q.key == "zone")
        self.assertEqual(q.prompt, "Zone for the bastion, VPN host and GKE cluster")

    def test_vpn_type_is_an_enumerated_choice(self):
        q = next(q for q in GCP.questions if q.key == "vpn_type")
        self.assertEqual(q.choices, ("openvpn", "tailscale"))
        self.assertEqual(q.coerce("Tailscale"), "tailscale")
        self.assertIsNotNone(q.problem("wireguard"))
        cfg = _cfg(vars={"enable_vpn": True, "vpn_type": " TailScale "})
        self.assertEqual(self.problems(cfg), "")
        self.assertEqual(cfg["vars"]["vpn_type"], "tailscale")
        self.assertIn("--var vpn_type: 'wireguard' is not a VPN type: use openvpn or tailscale.",
                      self.problems(_cfg(vars={"vpn_type": "wireguard"})))

    def test_node_count_has_a_floor_of_one(self):
        q = next(q for q in GCP.questions if q.key == "kubernetes_node_count")
        self.assertEqual(q.minimum, 1)
        self.assertIsNotNone(q.problem(0))
        self.assertIsNone(q.problem("3"))
        with self.assertRaises(ui.Abort) as cm:                   # a --var 0 is refused before anything is saved
            cloudbase.coerce_answer(q, "0", "--var kubernetes_node_count")
        self.assertIn(">= 1", cm.exception.msg)
        on = self.problems(_cfg(vars={"enable_kubernetes": True, "kubernetes_node_count": 0}))
        self.assertIn("--var kubernetes_node_count: a node pool needs at least 1 node, got 0", on)
        off = _cfg(vars={"enable_kubernetes": False, "kubernetes_node_count": "0"})
        self.assertEqual(self.problems(off), "")                   # unused: reset, not a blocker
        self.assertEqual(off["vars"]["kubernetes_node_count"], 2)
        self.assertIn("Kubernetes is off, so it is reset to the default 2", self.said(self.warn))
        # not a number at all: refused whatever it is for
        self.assertIn("whole number", self.problems(_cfg(vars={"kubernetes_node_count": "two"})))

    def test_blank_booleans_and_numbers_are_the_default(self):
        cfg = _cfg(vars={"enable_vpn": None, "fips_mode": " ", "kubernetes_node_count": None})
        self.assertEqual(self.problems(cfg), "")
        self.assertEqual((cfg["vars"]["enable_vpn"], cfg["vars"]["fips_mode"], cfg["vars"]["kubernetes_node_count"]),
                         (False, False, 2))
        self.assertIn("enable_vpn", self.problems(_cfg(vars={"enable_vpn": "maybe"})))   # anything else: strict

    def test_the_range_and_choices_are_declared_for_every_front_end(self):
        rows = {q.key: q for q in GCP.questions}
        self.assertEqual((rows["kubernetes_node_count"].minimum, rows["kubernetes_node_count"].maximum), (1, None))
        self.assertEqual(rows["vpn_type"].choices, ("openvpn", "tailscale"))
        from cloudseed import webui
        sent = {q["key"]: q for q in webui.clouds_catalog()["gcp"]["questions"]}
        self.assertEqual(sent["vpn_type"]["choices"], ["openvpn", "tailscale"])     # the wizard renders a select


# ---------------------------------------------------------------- a2-agentic#1: an unusable Google key is named
class KeyCheckTests(unittest.TestCase):
    NAMES = ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN", "GCE_METADATA_HOST",
             "GCE_METADATA_IP", "K_SERVICE", "CLOUD_RUN_JOB", "FUNCTION_TARGET", "CLOUD_SHELL",
             "GOOGLE_CLOUD_KEYFILE_JSON", "GCLOUD_KEYFILE_JSON")
    GOOD = json.dumps({"type": "service_account", "project_id": "p", "private_key": "k", "client_email": "a@b"})

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="cs-w4cred-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.vault_file = self.home / "cs" / "gcp-credentials.json"
        self.vault_file.parent.mkdir()

    def key(self, text, name="key.json", mode="w"):
        p = self.home / name
        with open(p, mode) as fh:
            fh.write(text)
        return str(p)

    def warnings(self, applied=None, **env):
        clean = {k: v for k, v in os.environ.items() if k not in self.NAMES}
        clean.update(HOME=str(self.home), **env)
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(creds, "GCP_FILE", self.vault_file), \
                mock.patch.dict(creds.APPLIED, applied or {}, clear=True), \
                mock.patch.object(gcpmod, "_google_runtime", return_value=False):
            return GCP.credential_warnings({"vars": {}})

    def test_a_valid_key_file_or_json_is_quiet(self):
        self.assertEqual(self.warnings(GOOGLE_APPLICATION_CREDENTIALS=self.key(self.GOOD)), [])
        self.assertEqual(self.warnings(GOOGLE_CREDENTIALS=self.GOOD), [])
        self.assertEqual(self.warnings(GOOGLE_CREDENTIALS=self.key(self.GOOD)), [])            # a path works too
        self.assertEqual(self.warnings(GOOGLE_CREDENTIALS="{}"), [])                          # left to Terraform's error
        authorized = json.dumps({"type": "authorized_user", "client_id": "x", "refresh_token": "y"})
        self.assertEqual(self.warnings(GOOGLE_APPLICATION_CREDENTIALS=self.key("﻿" + authorized)), [])

    def test_a_key_file_that_is_not_a_key(self):
        cases = (("{", "cut short"), ('{"type": "service_account", "private_key": "-----BEGIN', "cut short"),
                 ("", "it is empty"), ("not json at all", "not valid JSON at line 1"),
                 ('["type"]', "not a JSON object"), ('{"email": "sa@p.iam.gserviceaccount.com"}', 'no "type"'),
                 ('{"type": 3}', 'no "type"'), ('{"type": " "}', 'no "type"'))
        for text, words in cases:
            w = self.warnings(GOOGLE_APPLICATION_CREDENTIALS=self.key(text))
            self.assertEqual(len(w), 1, text)
            self.assertIn("which is not a Google key file", w[0])
            self.assertIn(words, w[0], text)
            # exported in the shell: a vault value would not replace it, so the fix is the shell's
            self.assertIn("export GOOGLE_APPLICATION_CREDENTIALS=/path/key.json", w[0])
            self.assertNotIn("creds set GOOGLE_APPLICATION_CREDENTIALS", w[0])
            self.assertIn("unset it in your shell and store the key (cloudseed creds set GOOGLE_CREDENTIALS)", w[0])
        w = self.warnings(GOOGLE_APPLICATION_CREDENTIALS=self.key(b"0\x82\x09\xff\xfe binary", "key.p12", "wb"))
        self.assertIn(".p12 key", w[0])
        big = self.key("{" + " " * (gcpmod._KEY_FILE_MAX + 10) + "}")
        self.assertIn("far too large", self.warnings(GOOGLE_APPLICATION_CREDENTIALS=big)[0])

    def test_the_fix_matches_where_the_path_comes_from(self):
        bad, gone = self.key("{"), str(self.home / "gone.json")
        # stored in the vault (creds.apply put it there): the vault is where it is fixed
        for path, words in ((bad, "not a Google key file"), (gone, "does not exist")):
            w = self.warnings(applied={"GOOGLE_APPLICATION_CREDENTIALS": path}, GOOGLE_APPLICATION_CREDENTIALS=path)
            self.assertEqual(len(w), 1, w)
            self.assertIn(words, w[0])
            self.assertIn("cloudseed creds set GOOGLE_APPLICATION_CREDENTIALS=/path/key.json", w[0])
            self.assertIn("cloudseed creds unset GOOGLE_APPLICATION_CREDENTIALS", w[0])
            self.assertNotIn("export GOOGLE_APPLICATION_CREDENTIALS", w[0])
        # exported in the shell: `cloudseed creds set` would not replace it
        w = self.warnings(GOOGLE_APPLICATION_CREDENTIALS=gone)
        self.assertIn("export GOOGLE_APPLICATION_CREDENTIALS=/path/key.json", w[0])
        self.assertNotIn("creds set GOOGLE_APPLICATION_CREDENTIALS", w[0])
        # GOOGLE_CLOUD_KEYFILE_JSON: the vault's GOOGLE_CREDENTIALS takes JSON only, so a path is stored as a key path
        w = self.warnings(GOOGLE_CLOUD_KEYFILE_JSON="/k.json")
        self.assertNotIn("creds set GOOGLE_CREDENTIALS=", w[0])
        self.assertIn("cloudseed creds set GOOGLE_APPLICATION_CREDENTIALS=/path/key.json", w[0])

    def test_the_vaults_key_pasted_as_a_single_brace(self):
        # the vault stores GOOGLE_CREDENTIALS and materialises it as GOOGLE_APPLICATION_CREDENTIALS=<vault file>: one
        # warning, about the vault, with the command that re-enters it
        self.vault_file.write_text("{")
        w = self.warnings(applied={"GOOGLE_CREDENTIALS": "{", "GOOGLE_APPLICATION_CREDENTIALS": str(self.vault_file)},
                          GOOGLE_CREDENTIALS="{", GOOGLE_APPLICATION_CREDENTIALS=str(self.vault_file))
        self.assertEqual(len(w), 1, w)
        self.assertIn("The Google key stored in the vault (GOOGLE_CREDENTIALS) is not a whole key file", w[0])
        self.assertIn("cut short", w[0])
        self.assertIn("cloudseed creds set GOOGLE_CREDENTIALS", w[0])
        # a stored GOOGLE_CREDENTIALS is read before a key path: switching to a path means removing it first
        self.assertIn("cloudseed creds unset GOOGLE_CREDENTIALS, then cloudseed creds set GOOGLE_APPLICATION_CREDENTIALS", w[0])
        # only the materialised file is there (the variable itself not exported): still named as the vault's key
        w = self.warnings(GOOGLE_APPLICATION_CREDENTIALS=str(self.vault_file))
        self.assertIn("stored in the vault", w[0])

    def test_a_shell_exported_google_credentials(self):
        w = self.warnings(GOOGLE_CREDENTIALS="{")
        self.assertIn("GOOGLE_CREDENTIALS (exported in your shell) is not a Google key", w[0])
        self.assertIn("cut short", w[0])
        self.assertIn("does not exist", self.warnings(GOOGLE_CREDENTIALS=str(self.home / "gone.json"))[0])
        self.assertIn("absolute path", self.warnings(GOOGLE_CREDENTIALS="keys/k.json")[0])
        # GOOGLE_CREDENTIALS is read first: a valid one with a valid key file is quiet, a broken one is named even
        # when the key file is fine
        self.assertEqual(self.warnings(GOOGLE_CREDENTIALS=self.GOOD, GOOGLE_APPLICATION_CREDENTIALS=self.key(self.GOOD)), [])
        self.assertEqual(len(self.warnings(GOOGLE_CREDENTIALS="{", GOOGLE_APPLICATION_CREDENTIALS=self.key(self.GOOD))), 1)

    def test_unreadable_key_file(self):
        if os.geteuid() == 0:
            self.skipTest("root reads every file")
        path = self.key(self.GOOD)
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o600)
        self.assertIn("cannot be read", self.warnings(GOOGLE_APPLICATION_CREDENTIALS=path)[0])


# ---------------------------------------------------------------- the owner label of environments of earlier versions
class LegacyOwnerLabelTests(_Quiet):
    def test_old_environments_keep_the_ascii_owner_label(self):
        old = _cfg(tags={"Owner": "José Núñez", "team": "Données"})       # no uid: made before CloudseedEnvId
        labels = GCP.tags(old)
        self.assertEqual(labels["owner"], "jos--n--ez")                   # what those versions wrote
        self.assertEqual(labels["team"], "données")                        # other labels are international
        self.assertNotIn("cloudseedenvid", labels)
        new = _cfg(uid="0123456789abcdef", tags={"Owner": "José Núñez"})
        self.assertEqual(GCP.tags(new)["owner"], "josé-núñez")
        # ASCII owners are the same in both forms (the default owner is the sanitised local user name)
        self.assertEqual(GCP.tags(_cfg())["owner"], GCP.tags(_cfg(uid="u1"))["owner"])

    def test_reconcile_still_recognises_its_own_objects(self):
        old = _cfg(tags={"owner": "José"})
        expected = reconcile.expected_tags("gcp", old)
        found = {"cloudseedenv": "gcp-dev", "owner": "jos-", "managedby": "cloudseed"}   # labelled by an earlier version
        self.assertEqual(reconcile.ownership(found, expected)[0], "mine")
        self.assertEqual(reconcile.ownership({**found, "owner": "someone-else"}, expected)[0], "other")

    def test_the_warning_says_why(self):
        GCP.check_vars(_cfg(tags={"owner": "José"}))
        warned = self.said(self.warn)
        self.assertIn("--tag owner: the value becomes 'jos-' (this environment comes from an earlier cloudseed", warned)
        self.warn.reset_mock()
        GCP.check_vars(_cfg(uid="u1", tags={"owner": "José"}))
        self.assertNotIn("--tag owner", self.said(self.warn))            # applied as typed (lower case)

    def test_provider_default_labels_match(self):
        old = _cfg(tags={"Owner": "Zoë"})
        self.assertEqual(GCP.provider_block(old)["google"]["default_labels"]["owner"], "zo-")
        self.assertEqual(GCP.stack_vars(old)["labels"]["owner"], "zo-")
        self.assertEqual(GCP.bootstrap_vars(old)["labels"]["owner"], "zo-")


# ---------------------------------------------------------------- machine types given as self-links
class MachineTypeTests(unittest.TestCase):
    def test_a_self_link_gets_the_name_as_the_fix(self):
        for link in ("zones/us-central1-a/machineTypes/e2-small",
                     "https://www.googleapis.com/compute/v1/projects/p-123456/zones/us-central1-a/machineTypes/E2-Small"):
            problem = gcpmod._check_machine_type(link)
            self.assertIn("give the machine type's name, not its URL: e2-small", problem, link)
        self.assertIn("lower case: e2-micro", gcpmod._check_machine_type("E2-MICRO"))
        self.assertIsNone(gcpmod._check_machine_type("e2-micro"))


# ---------------------------------------------------------------- OS Login keys registered with an expiry
class OsLoginExpiryTests(_Quiet):
    def setUp(self):
        super().setUp()
        home = Path(tempfile.mkdtemp(prefix="cs-w4gcp-"))
        self.addCleanup(shutil.rmtree, home, True)
        for p in (mock.patch.object(paths, "ENVS_DIR", home / "envs"), mock.patch.object(paths, "_load_index", return_value={})):
            p.start()
            self.addCleanup(p.stop)

    def prepare(self, expires_in, calls):
        entry = {"key": KEY.replace("cloudseed-gcp-dev", "laptop"), "fingerprint": "fpold"}
        if expires_in is not None:
            entry["expirationTimeUsec"] = str(int((time.time() + expires_in) * 1_000_000))
        state = {"keys": {"fpold": entry}}

        def run(argv, **kw):
            calls.append(argv[1:])
            if argv[1:4] == ["config", "get-value", "account"]:
                return subprocess.CompletedProcess(argv, 0, "dev@example.com\n", "")
            if "describe-profile" in argv:
                return subprocess.CompletedProcess(argv, 0, json.dumps({
                    "posixAccounts": [{"accountId": "my-proj-123", "username": "dev_example_com"}],
                    "sshPublicKeys": state["keys"]}), "")
            if argv[1:5] == ["compute", "os-login", "ssh-keys", "remove"]:
                gone = gcpmod._key_id(Path(argv[argv.index("--key-file") + 1]).read_text())
                state["keys"] = {fp: e for fp, e in state["keys"].items() if gcpmod._key_id(e["key"]) != gone}
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[1:5] == ["compute", "os-login", "ssh-keys", "add"]:
                key = Path(argv[argv.index("--key-file") + 1]).read_text().strip()
                state["keys"]["fpnew"] = {"key": key, "fingerprint": "fpnew"}
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 1, "", "unexpected")
        cfg = _cfg(vars={"enable_os_login": True})
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run", side_effect=run):
            GCP.prepare(cfg)
        return cfg, state

    def verbs(self, calls):
        return [c[3] for c in calls if c[:3] == ["compute", "os-login", "ssh-keys"]]

    def test_an_expired_key_is_registered_again_and_owned(self):
        calls = []
        cfg, state = self.prepare(-86400, calls)
        self.assertEqual(self.verbs(calls), ["remove", "add"])
        remove = next(c for c in calls if c[:4] == ["compute", "os-login", "ssh-keys", "remove"])
        self.assertEqual(remove[remove.index("--account") + 1], "dev@example.com")
        self.assertTrue(cfg["os_login"]["added"])                           # cloudseed made it usable: it removes it too
        self.assertEqual(cfg["os_login"]["fingerprint"], "fpnew")
        self.assertNotIn("expirationTimeUsec", state["keys"]["fpnew"])
        self.assertIn("expired on", self.said(self.info))

    def test_a_key_about_to_expire_is_renewed_too(self):
        calls = []
        cfg, _ = self.prepare(600, calls)                                   # 10 minutes: setup would outlive it
        self.assertEqual(self.verbs(calls), ["remove", "add"])
        self.assertIn("expires on", self.said(self.info))

    def test_a_later_expiry_is_announced_not_changed(self):
        calls = []
        cfg, _ = self.prepare(30 * 86400, calls)
        self.assertEqual(self.verbs(calls), [])
        self.assertFalse(cfg["os_login"]["added"])                          # the user's key, as registered
        warned = self.said(self.warn)
        self.assertIn("expires on", warned)
        self.assertIn("cloudseed setup gcp --env dev", warned)

    def test_a_key_without_expiry_is_left_alone(self):
        calls = []
        cfg, _ = self.prepare(None, calls)
        self.assertEqual(self.verbs(calls), [])
        self.assertEqual(self.said(self.warn), "")

    def test_expiry_parsing(self):
        raw = json.dumps({"sshPublicKeys": {"a": {"key": KEY, "expirationTimeUsec": "1700000000000000"},
                                            "b": {"key": "ssh-rsa AAAAB other", "expirationTimeUsec": "junk"},
                                            "c": {"key": "ssh-ed25519 AAAAC third"}}})
        self.assertEqual(GCP._profile_key_expiry(raw), {gcpmod._key_id(KEY): 1700000000.0})
        self.assertEqual(GCP._profile_key_expiry("not json"), {})
        self.assertIn("2023-11-14", gcpmod._when(1700000000))
        self.assertEqual(gcpmod._when(1e20), "at an unreadable time")


# ---------------------------------------------------------------- Terraform: descriptions and the node-count rule
class TerraformTextTests(unittest.TestCase):
    def test_every_variable_and_output_is_described(self):
        for name, desc, _ in helpmod._parse_variables("gcp"):
            self.assertTrue(desc, f"variable {name} has no description")
        outputs = dict(helpmod._parse_outputs("gcp"))
        for name, desc in outputs.items():
            self.assertTrue(desc, f"output {name} has no description")
        for name in ("kubernetes_endpoint", "kubernetes_location", "kubernetes_node_pool",
                     "kubernetes_external_secrets_gsa", "kubernetes_external_dns_gsa", "kubernetes_velero_gsa",
                     "kubernetes_velero_bucket", "kubernetes_cluster_name", "kubernetes_master_cidr"):
            self.assertRegex(outputs[name], r"null (when|until)", name)
        self.assertIn("velero platform item", outputs["kubernetes_velero_bucket"])

    def test_node_count_rule_only_with_a_cluster(self):
        text = (TF / "gcp" / "variables.tf").read_text()
        block = dict(re.findall(r'variable "([^"]+)" \{(.*?)\n\}', text, re.S))["kubernetes_node_count"]
        self.assertIn("!var.enable_kubernetes ||", block)
        self.assertIn("var.kubernetes_node_count >= 1", block)
        tests = (TF / "gcp" / "tests" / "stack.tftest.hcl").read_text()
        for run in ("empty_node_pool_is_refused", "fractional_node_count_is_refused", "unused_node_count_does_not_block",
                    "vpn_port_zero"):
            self.assertIn(f'run "{run}"', tests)


# ---------------------------------------------------------------- through the real CLI
class CliTests(unittest.TestCase):
    def cs(self, *argv, env=None):
        home = tempfile.mkdtemp(prefix="cs-w4gcp-cli-")
        self.addCleanup(shutil.rmtree, home, True)
        full = {k: v for k, v in os.environ.items() if not k.startswith(("GOOGLE_", "CLOUDSDK_", "GCLOUD_"))}
        full.update(CLOUDSEED_HOME=home, HOME=home, NO_COLOR="1", **(env or {}))
        p = subprocess.run([sys.executable, str(ROOT / "bin" / "cloudseed"), *argv], env=full, capture_output=True,
                           text=True, timeout=120, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout + p.stderr, Path(home)

    def test_a_zero_node_count_is_refused_before_anything_is_saved(self):
        rc, out, home = self.cs("setup", "gcp", "-y", "--env", "w4", "--project-id", "my-proj-123", "--allow-ip",
                                "1.2.3.4", "--state", "local", "--dry-run", "--var", "enable_kubernetes=true",
                                "--var", "kubernetes_node_count=0")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("kubernetes_node_count", out)
        self.assertIn(">= 1", out)
        self.assertFalse((home / "envs" / "gcp-w4" / "config.json").exists())

    def test_doctor_names_a_key_cut_short(self):
        key = Path(tempfile.mkdtemp(prefix="cs-w4key-")) / "key.json"
        self.addCleanup(shutil.rmtree, key.parent, True)
        key.write_text("{")
        rc, out, _ = self.cs("doctor", "gcp", env={"GOOGLE_APPLICATION_CREDENTIALS": str(key)})
        self.assertIn("cut short", out)
        self.assertIn("GOOGLE_APPLICATION_CREDENTIALS", out)


if __name__ == "__main__":
    unittest.main()
