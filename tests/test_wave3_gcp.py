"""Wave 3 regression tests for the GCP adapter and stack: project-wide logging settings (kept on destroy, one owner per
project, retention preflight), OS Login key ownership and release, OS Login on the VPN host, Kubernetes-safe node
labels, international labels, apply-time value checks, zone messages, subnet ranges, the environment label, credential
detection, google-like bucket names and the instance-id outputs. Offline and fast: no cloud, no network, no terraform
(the plan-level checks live in terraform/gcp/tests and terraform/gcp-bootstrap/tests, run with CLOUDSEED_TF_TESTS=1)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, paths, provision, ui  # noqa: E402
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


class _Homes(_Quiet):
    """A private envs directory, so the scans over every saved environment see only this test's environments."""

    def setUp(self):
        super().setUp()
        self.home = Path(tempfile.mkdtemp(prefix="cs-w3gcp-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        for p in (mock.patch.object(paths, "ENVS_DIR", self.home / "envs"), mock.patch.object(paths, "_load_index", return_value={})):
            p.start()
            self.addCleanup(p.stop)

    def env(self, name, resources=None, **cfg):
        env = paths.Env("gcp", name)
        env.dir.mkdir(parents=True, exist_ok=True)
        full = _cfg(env=name, **cfg)
        env.config_path.write_text(json.dumps(full))
        if resources is not None:
            (env.dir / "inventory.json").write_text(json.dumps({"history": [{"action": "apply", "resources": resources}]}))
        return env, full


# ---------------------------------------------------------------- a2-gcp#2: project-wide logging settings
class ProjectBaselineTests(_Homes):
    RESOURCES = [
        "module.stack.module.security_baseline.google_project_iam_audit_config.all[0]",
        "module.stack.module.security_baseline.google_logging_project_bucket_config.default[0]",
        "module.stack.module.security_baseline.google_logging_project_bucket_config.default",
        "module.stack.module.bastion.google_compute_instance.bastion",
        "module.stack.google_project_service.apis[\"compute.googleapis.com\"]",
        "module.stack.module.kubernetes[0].google_project_iam_member.x",
    ]

    def test_destroy_keeps_the_project_wide_settings(self):
        keep = GCP.keep_on_destroy(_cfg(extra_vars={"log_retention_days": 365}), self.RESOURCES)
        self.assertEqual([a for a, _ in keep], self.RESOURCES[:3])
        notices = " ".join(n for _, n in keep)
        self.assertIn("Data Access audit logs (allServices) stay on for project my-proj-123", notices)
        self.assertIn("365 days", notices)
        self.assertEqual(GCP.keep_on_destroy(_cfg(), ["module.stack.module.bastion.google_compute_instance.bastion"]), [])
        # a destroy targeting the module keeps them too (cli._destroy_targets filters keep_on_destroy with _covered)
        from cloudseed import cli
        self.assertTrue(cli._covered(self.RESOURCES[0], ["module.stack.module.security_baseline"]))

    def test_second_environment_in_the_project_is_warned(self):
        self.env("prod", resources=12)
        self.assertIn("gcp-prod already manages the project-wide logging settings of my-proj-123",
                      " ".join(GCP._baseline_warnings(_cfg(env="stg"))))
        # opting out on this one, another project, or an opted-out / destroyed other environment: no warning
        self.assertEqual(GCP._baseline_warnings(_cfg(env="stg", extra_vars={"enable_project_baseline": False})), [])
        self.assertEqual(GCP._baseline_warnings(_cfg(env="stg", vars={"project_id": "other-proj-1"})), [])
        self.env("prod", resources=0)
        self.assertEqual(GCP._baseline_warnings(_cfg(env="stg")), [])
        self.env("prod", resources=3, extra_vars={"enable_project_baseline": "false"})
        self.assertEqual(GCP._baseline_warnings(_cfg(env="stg")), [])
        self.assertEqual(GCP._baseline_warnings(_cfg(env="prod")), [])          # never warned about itself
        self.env("dry", vars={"project_id": "my-proj-123"})                       # only dry-run so far: manages nothing
        self.assertEqual(GCP._baseline_warnings(_cfg(env="stg")), [])
        env, _ = self.env("local")                                                 # applied with local state
        (env.stack_dir).mkdir()
        (env.stack_dir / "terraform.tfstate").write_text(json.dumps({"resources": [{"type": "google_compute_network"}]}))
        self.assertIn("gcp-local already manages", " ".join(GCP._baseline_warnings(_cfg(env="stg"))))

    def test_audit_logs_without_the_baseline_are_explained(self):
        w = GCP._baseline_warnings(_cfg(vars={"enable_data_access_audit_logs": True},
                                        extra_vars={"enable_project_baseline": False}))
        self.assertIn("no effect", w[0])
        self.assertIn("enable_project_baseline", self.problems(_cfg(extra_vars={"enable_project_baseline": "maybe"})))

    def test_opting_out_where_the_audit_config_is_managed_says_how_to_keep_it(self):
        off = {"enable_project_baseline": False}
        env, _ = self.env("dev")
        self.assertEqual(GCP._baseline_warnings(_cfg(extra_vars=off)), [])            # nothing in the state yet
        (env.dir / "inventory.json").write_text(json.dumps({"history": [], "current": {"resources": [
            {"address": "module.stack.module.security_baseline.google_project_iam_audit_config.all[0]",
             "type": "google_project_iam_audit_config", "mode": "managed"}]}}))
        w = " ".join(GCP._baseline_warnings(_cfg(extra_vars=off)))
        self.assertIn("the next apply deletes it", w)
        self.assertIn("cloudseed destroy gcp --env dev --target module.stack.module.security_baseline", w)
        self.assertNotIn("next apply deletes", " ".join(GCP._baseline_warnings(_cfg())))  # still managed: kept as is

    def _gcloud(self, calls, retention="365", policy=None):
        def run(argv, **kw):
            calls.append(argv[1:])
            if argv[1:3] == ["logging", "buckets"]:
                return subprocess.CompletedProcess(argv, 0, retention + "\n", "")
            if argv[1:3] == ["projects", "get-iam-policy"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps(policy or {}), "")
            return subprocess.CompletedProcess(argv, 1, "", "unexpected")
        return run

    def test_preflight_warns_before_lowering_retention_or_replacing_an_audit_config(self):
        calls = []
        policy = {"auditConfigs": [{"service": "allServices", "auditLogConfigs": [
            {"logType": "ADMIN_READ"}, {"logType": "DATA_READ", "exemptedMembers": ["user:bot@example.com"]}]}]}
        cfg = _cfg(vars={"enable_data_access_audit_logs": True})
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run", side_effect=self._gcloud(calls, "365", policy)):
            GCP.prepare(cfg)
        warned = self.said(self.warn)
        self.assertIn("for 365 days; this environment sets 90", warned)
        self.assertIn("--var log_retention_days=365", warned)
        self.assertIn("exempted: user:bot@example.com", warned)
        self.assertIn("--var enable_project_baseline=false", warned)

    def test_preflight_is_quiet_when_nothing_is_lost(self):
        calls = []
        cfg = _cfg(extra_vars={"log_retention_days": 400})
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run", side_effect=self._gcloud(calls, "365")):
            GCP.prepare(cfg)
        self.assertEqual(self.warn.call_count, 0)
        self.assertFalse(any(c[:2] == ["projects", "get-iam-policy"] for c in calls))   # audit logs are off
        calls.clear()
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run", side_effect=self._gcloud(calls, "365")):
            GCP.prepare(_cfg(extra_vars={"enable_project_baseline": False}))       # not managed here: not asked
            GCP.prepare(_cfg(), dry_run=True)                                     # dry runs never call gcloud
        self.assertEqual(calls, [])
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run", side_effect=OSError("boom")):
            GCP.prepare(_cfg())                                                   # best effort: never fails setup

    def test_terraform_gates_both_settings(self):
        base = (TF / "gcp" / "modules" / "security-baseline" / "main.tf").read_text()
        self.assertIn("count = var.enable_project_baseline && var.enable_data_access_audit_logs ? 1 : 0", base)
        self.assertIn("count = var.enable_project_baseline ? 1 : 0", base)
        self.assertRegex(base, r"moved \{\s*from = google_logging_project_bucket_config\.default\s*to\s*= "
                               r"google_logging_project_bucket_config\.default\[0\]")
        self.assertIn("enable_project_baseline       = var.enable_project_baseline", (TF / "gcp" / "main.tf").read_text())
        self.assertIn('variable "enable_project_baseline"', (TF / "gcp" / "variables.tf").read_text())


# ---------------------------------------------------------------- a2-gcp#3: OS Login key ownership and release
class OsLoginKeyTests(_Homes):
    def gcloud(self, calls, profile_keys=(), fail_remove=False):
        state = {"keys": {f"fp{i}": {"key": k, "fingerprint": f"fp{i}"} for i, k in enumerate(profile_keys)}}

        def run(argv, **kw):
            calls.append(argv[1:])
            if argv[1:4] == ["config", "get-value", "account"]:
                return subprocess.CompletedProcess(argv, 0, "dev@example.com\n", "")
            if "describe-profile" in argv:
                return subprocess.CompletedProcess(argv, 0, json.dumps({
                    "posixAccounts": [{"accountId": "my-proj-123", "username": "dev_example_com"}],
                    "sshPublicKeys": state["keys"]}), "")
            if argv[1:5] == ["compute", "os-login", "ssh-keys", "add"]:
                key = Path(argv[argv.index("--key-file") + 1]).read_text().strip()
                state["keys"]["fpnew"] = {"key": key, "fingerprint": "fpnew"}
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[1:5] == ["compute", "os-login", "ssh-keys", "remove"]:
                if fail_remove:
                    return subprocess.CompletedProcess(argv, 1, "", "ERROR: (gcloud) permission denied")
                key = gcpmod._key_id(Path(argv[argv.index("--key-file") + 1]).read_text())
                state["keys"] = {fp: e for fp, e in state["keys"].items() if gcpmod._key_id(e["key"]) != key}
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 1, "", "unexpected")
        return run, state

    def prepare(self, cfg, calls, **kw):
        run, state = self.gcloud(calls, **kw)
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run", side_effect=run):
            GCP.prepare(cfg)
        return state

    def release(self, old, new, calls, **kw):
        run, state = self.gcloud(calls, **kw)
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run", side_effect=run):
            return GCP.release_os_login(old, new), state

    def test_a_new_key_is_recorded_as_added(self):
        cfg, calls = _cfg(vars={"enable_os_login": True}), []
        self.prepare(cfg, calls)
        rec = cfg["os_login"]
        self.assertEqual((rec["key"], rec["added"], rec["fingerprint"]), (gcpmod._key_id(KEY), True, "fpnew"))
        self.assertTrue(any(c[:4] == ["compute", "os-login", "ssh-keys", "add"] for c in calls))
        # re-running setup: the key is there already, but cloudseed added it, so it still owns it (no second add)
        calls.clear()
        self.prepare(cfg, calls, profile_keys=[KEY])
        self.assertTrue(cfg["os_login"]["added"])
        self.assertFalse(any("add" in c for c in calls))

    def test_a_key_already_in_the_profile_is_never_owned(self):
        cfg, calls = _cfg(vars={"enable_os_login": True}), []
        self.prepare(cfg, calls, profile_keys=[KEY.replace("cloudseed-gcp-dev", "my laptop")])   # the comment differs
        self.assertFalse(cfg["os_login"]["added"])
        self.assertFalse(any("add" in c for c in calls))
        removed, _ = self.release(cfg, None, calls)
        self.assertFalse(removed)
        self.assertFalse(any("remove" in c for c in calls))

    def test_rotation_removes_the_old_key_only(self):
        old = _cfg(vars={"enable_os_login": True})
        self.prepare(old, [])
        new = json.loads(json.dumps(old))
        new["ssh_public_key"] = "ssh-ed25519 AAAAnewkey rotated"
        self.prepare(new, [])
        self.assertTrue(new["os_login"]["added"])
        calls = []
        removed, state = self.release(old, new, calls, profile_keys=[KEY, new["ssh_public_key"]])
        self.assertTrue(removed)
        remove = next(c for c in calls if c[:4] == ["compute", "os-login", "ssh-keys", "remove"])
        self.assertEqual(remove[remove.index("--account") + 1], "dev@example.com")
        self.assertEqual([gcpmod._key_id(e["key"]) for e in state["keys"].values()], ["ssh-ed25519 AAAAnewkey"])
        self.assertIn("os_login", old)                    # only a destroy (new_cfg None) drops the record
        # the same key still in use (a setup that changed something else): nothing removed
        calls.clear()
        self.assertFalse(self.release(new, new, calls)[0])
        self.assertEqual(calls, [])

    def test_turning_os_login_off_removes_the_key(self):
        old = _cfg(vars={"enable_os_login": True})
        self.prepare(old, [])
        off = json.loads(json.dumps(old))
        off["vars"]["enable_os_login"] = False
        GCP.prepare(off)
        self.assertNotIn("os_login", off)
        self.assertTrue(self.release(old, off, [], profile_keys=[KEY])[0])

    def test_destroy_removes_and_forgets_the_record(self):
        cfg = _cfg(vars={"enable_os_login": True})
        self.prepare(cfg, [])
        removed, state = self.release(cfg, None, [], profile_keys=[KEY])
        self.assertTrue(removed)
        self.assertNotIn("os_login", cfg)                 # the next setup/apply registers again (cli._os_login_pending)
        self.assertEqual(state["keys"], {})

    def test_a_key_shared_with_another_environment_stays(self):
        _, other = self.env("prod", vars={"enable_os_login": True})
        other["os_login"] = {"account": "dev@example.com", "user": "dev_example_com", "member": "user:dev@example.com",
                             "key": gcpmod._key_id(KEY), "added": True}
        paths.Env("gcp", "prod").config_path.write_text(json.dumps(other))
        cfg = _cfg(vars={"enable_os_login": True})
        self.prepare(cfg, [], profile_keys=[KEY])
        self.assertTrue(cfg["os_login"]["added"])         # inherited: whichever environment goes last removes it
        calls = []
        self.assertFalse(self.release(cfg, None, calls, profile_keys=[KEY])[0])
        self.assertFalse(any("remove" in c for c in calls))
        self.assertIn("gcp-prod still use it", self.said(self.info))

    def test_failures_warn_with_the_manual_command(self):
        cfg = _cfg(vars={"enable_os_login": True})
        self.prepare(cfg, [])
        removed, _ = self.release(cfg, None, [], profile_keys=[KEY], fail_remove=True)
        self.assertFalse(removed)
        self.assertIn("os_login", cfg)                    # kept: a later destroy or setup can still release it
        warned = self.said(self.warn)
        self.assertIn("permission denied", warned)
        self.assertIn("gcloud compute os-login ssh-keys remove --key fpnew --account dev@example.com", warned)
        with mock.patch.object(gcpmod.deps, "find", return_value=None):
            self.assertFalse(GCP.release_os_login(cfg, None))
        self.assertIn("gcloud is not installed", self.said(self.warn))

    def test_records_of_older_versions_are_left_alone(self):
        cfg = _cfg(vars={"enable_os_login": True})
        cfg["os_login"] = {"account": "dev@example.com", "user": "u", "member": "user:dev@example.com"}
        with mock.patch.object(gcpmod.subprocess, "run") as run:
            self.assertFalse(GCP.release_os_login(cfg, None))
        run.assert_not_called()


# ---------------------------------------------------------------- a2-gcp#4: OS Login on the VPN host
class VpnOsLoginTests(unittest.TestCase):
    def test_vpn_module_mirrors_the_bastion(self):
        vpn = (TF / "gcp" / "modules" / "vpn" / "main.tf").read_text()
        self.assertNotIn('enable-oslogin         = "FALSE"', vpn)
        self.assertIn('enable-oslogin         = var.enable_os_login ? "TRUE" : "FALSE"', vpn)
        self.assertIn('var.enable_os_login ? {} : { ssh-keys = "${var.ssh_username}:${var.ssh_public_key}" }', vpn)
        self.assertIn('resource "google_compute_instance_iam_member" "os_admin_login"', vpn)
        self.assertIn('resource "google_service_account_iam_member" "os_login_act_as"', vpn)
        root = (TF / "gcp" / "main.tf").read_text()
        vpn_block = root[root.index('module "vpn"'):]
        self.assertIn("enable_os_login   = var.enable_os_login", vpn_block)
        self.assertIn("os_login_member   = var.os_login_member", vpn_block)

    def test_prompt_says_where_os_login_applies(self):
        q = next(q for q in GCP.questions if q.key == "enable_os_login")
        self.assertIn("bastion and VPN host", q.prompt)


# ---------------------------------------------------------------- a2-gcp#5 / #12: labels
class LabelTests(_Quiet):
    def test_international_labels_are_kept(self):
        labels = GCP.tags(_cfg(tags={"ключ": "значение", "цвет": "Синий", "team": "Données", "東京": "日本"}))
        self.assertEqual(labels["ключ"], "значение")
        self.assertEqual(labels["цвет"], "синий")            # two Cyrillic keys no longer collide
        self.assertEqual(labels["team"], "données")
        self.assertEqual(labels["東京"], "日本")
        self.assertEqual(gcpmod._label("été"), "été")   # decomposed accents are one letter
        self.assertEqual(gcpmod._label("R&D"), "r-d")
        self.assertEqual(gcpmod._label_key("1abc"), "t-1abc")
        self.assertEqual(gcpmod._label_key("ʰx"), "t--x")    # modifier letters are not label characters
        long = gcpmod._label("я" * 63)
        self.assertLessEqual(len(long.encode("utf-8")), 63)   # at most 63 bytes, whatever the service counts
        self.assertEqual(gcpmod._label("a" * 80), "a" * 63)
        for k, v in labels.items():
            self.assertTrue(all(c in "_-" or gcpmod.unicodedata.category(c) in gcpmod._LABEL_CATEGORIES for c in k + v))

    def test_warnings_say_what_changed(self):
        cfg = _cfg(tags={"ключ": "значение", "Cost Center": "R&D (EU)", "1abc": "x"})
        GCP.check_vars(cfg)
        warned = self.said(self.warn)
        self.assertNotIn("ключ", warned)                      # nothing changed: nothing to say
        self.assertIn("--tag Cost Center: the key becomes 'cost-center' (GCP label keys:", warned)
        self.assertIn("; the value becomes 'r-d--eu-' (GCP label values:", warned)
        self.assertEqual(len([w for w in warned.splitlines() if w.startswith("--tag Cost Center")]), 1)   # one line per tag
        self.assertIn("--tag 1abc: the key becomes 't-1abc'", warned)

    def test_node_labels_follow_the_kubernetes_grammar(self):
        self.assertEqual(gcpmod._node_label("platform-eng-"), "platform-eng")
        self.assertEqual(gcpmod._node_label("v1-2-"), "v1-2")
        self.assertEqual(gcpmod._node_label("значение"), "")
        self.assertEqual(gcpmod._node_label("données"), "donn-es")
        self.assertEqual(gcpmod._node_label("_x_"), "x")
        k8s = re.compile(r"^(([a-z0-9][-a-z0-9_.]*)?[a-z0-9])?$")
        for text in ("platform-eng-", "-internal-", "v1.2+", "a", "--", "ok_1"):
            self.assertRegex(gcpmod._node_label(text), k8s)
        cfg = _cfg(vars={"enable_kubernetes": True}, tags={"Team": "Platform Eng.", "ключ": "x"})
        GCP.check_vars(cfg)
        warned = self.said(self.warn)
        self.assertIn("--tag Team: the value becomes 'platform-eng-' (GCP label values: lowercase letters, digits, '_' "
                      "and '-', at most 63 characters); on the GKE nodes it is team=platform-eng", warned)
        self.assertIn("--tag ключ: it is left off the GKE nodes", warned)
        self.warn.reset_mock()
        GCP.check_vars(_cfg(tags={"Team": "Platform Eng."}))   # no cluster: nothing about nodes
        self.assertNotIn("GKE", self.said(self.warn))

    def test_node_pool_uses_the_kubernetes_safe_labels(self):
        k8s = (TF / "gcp" / "modules" / "kubernetes" / "main.tf").read_text()
        self.assertIn("labels          = local.node_labels", k8s)
        self.assertIn("resource_labels = var.labels", k8s)     # GCP labels on the cluster keep the GCP form
        self.assertIn('trim(replace(k, "/[^a-z0-9_.-]+/", "-"), "-_.")', k8s)   # the rule _node_label mirrors

    def test_environment_tag_override_applies_everywhere(self):
        main = (TF / "gcp" / "main.tf").read_text()
        self.assertRegex(main, r"labels = merge\(\{\s*environment = var\.environment\s*\}, var\.labels\)")


# ---------------------------------------------------------------- a2-gcp#7 / #13: values GCP refuses at apply time
class ApplyTimeValueTests(_Quiet):
    def test_extra_vars_out_of_range_are_refused(self):
        for key, value, words in (("log_retention_days", 0, "1 to 3650"), ("log_retention_days", 5000, "got 5000"),
                                  ("bastion_disk_size", 5, "10 to 65536"), ("vpn_port", 70000, "1 to 65535"),
                                  ("vpn_port", 0, "1 to 65535"), ("bastion_disk_size", 10.5, "whole number"),
                                  ("kubernetes_node_min", -1, "negative"), ("kubernetes_node_max", 0, "at least 1"),
                                  ("bastion_image", "", "cannot be empty"), ("bastion_image", "  ", "cannot be empty"),
                                  ("vpn_machine_type", "E2-MICRO", "lower case: e2-micro")):
            msg = self.problems(_cfg(extra_vars={key: value}))
            self.assertIn(f"--var {key}", msg, (key, value))
            self.assertIn(words, msg, (key, value))
        ok = _cfg(extra_vars={"log_retention_days": 3650, "bastion_disk_size": 20.0, "vpn_port": 443,
                              "bastion_image": "ubuntu-os-cloud/ubuntu-2404-lts-amd64", "vpn_machine_type": "e2-small",
                              "kubernetes_node_min": 0, "kubernetes_node_max": 10})
        self.assertEqual(self.problems(ok), "")

    def test_machine_type_answers_are_checked(self):
        self.assertIn("--var bastion_machine_type", self.problems(_cfg(vars={"bastion_machine_type": "E2-MICRO"})))
        self.assertIn("--var kubernetes_node_size", self.problems(_cfg(vars={"kubernetes_node_size": "e2 standard"})))
        for mt in ("e2-micro", "e2-custom-2-4096", "custom-2-4096", "n2-custom-4-8192-ext", "a2-highgpu-1g", "c4a-highcpu-4"):
            self.assertEqual(self.problems(_cfg(vars={"bastion_machine_type": mt, "kubernetes_node_size": mt})), "", mt)
        q = next(q for q in GCP.questions if q.key == "bastion_machine_type")
        self.assertIsNotNone(q.problem("E2-MICRO"))           # the interactive prompt refuses it too

    def test_unused_node_count_is_reset_not_refused(self):
        cfg = _cfg(vars={"kubernetes_node_count": 0, "enable_kubernetes": False})
        self.assertEqual(self.problems(cfg), "")
        self.assertEqual(cfg["vars"]["kubernetes_node_count"], 2)
        self.assertIn("reset to the default 2", self.said(self.warn))
        self.assertIn("at least 1 node", self.problems(_cfg(vars={"kubernetes_node_count": 0, "enable_kubernetes": "yes"})))

    def test_terraform_backstops_the_same_rules(self):
        text = (TF / "gcp" / "variables.tf").read_text()
        blocks = dict(re.findall(r'variable "([^"]+)" \{(.*?)\n\}', text, re.S))
        for name in ("log_retention_days", "bastion_disk_size", "vpn_port", "bastion_image", "bastion_machine_type",
                     "vpn_machine_type", "kubernetes_node_size", "kubernetes_node_min", "kubernetes_node_max"):
            self.assertIn("validation {", blocks[name], name)
        # cli._variable_types still reads every declared type through the validation blocks
        from cloudseed import cli
        types = cli._variable_types("gcp")
        self.assertEqual((types["log_retention_days"], types["enable_project_baseline"], types["bastion_image"]),
                         ("number", "bool", "string"))


# ---------------------------------------------------------------- a2-gcp#8: zone messages
class ZoneMessageTests(_Quiet):
    def collect(self, existing, region, zone=None, overrides=None):
        args = SimpleNamespace(project_id=None, zone=zone, ssh_username=None)
        return GCP.collect_vars(args, existing, {"region": region, "name": "acme", "env": "dev"}, False,
                                overrides=overrides or {})

    def test_a_given_zone_gets_no_contradicting_message(self):
        saved = {"project_id": "my-proj-123", "zone": "us-central1-b", "ssh_username": "alice"}
        self.assertEqual(self.collect(saved, "europe-west1", zone="europe-west1-c")["zone"], "europe-west1-c")
        self.assertEqual(self.collect(saved, "europe-west1", overrides={"zone": "europe-west1-d"})["zone"], "europe-west1-d")
        self.assertEqual(self.collect({**saved, "zone": "europe-west1-a"}, "europe-west1", zone="europe-west1-c")["zone"],
                         "europe-west1-c")
        self.assertNotIn("the zone becomes", self.said(self.info))
        with mock.patch.dict(os.environ, {"CLOUDSDK_COMPUTE_ZONE": "us-central1-f"}):
            self.collect({"project_id": "my-proj-123"}, "us-east1", zone="us-east1-c")
        self.assertNotIn("Ignoring CLOUDSDK_COMPUTE_ZONE", self.said(self.info))

    def test_without_a_zone_the_healing_still_explains_itself(self):
        out = self.collect({"project_id": "my-proj-123", "zone": "europe-west1-a"}, "europe-west1")
        self.assertEqual(out["zone"], "europe-west1-b")
        self.assertIn("Zone europe-west1-a does not exist; the zone becomes europe-west1-b", self.said(self.info))


# ---------------------------------------------------------------- a2-gcp#10: subnet ranges
class SubnetRangeTests(_Quiet):
    def test_class_e_is_allowed_with_a_warning(self):
        self.assertEqual(self.problems(_cfg(network_cidr="240.10.0.0/16")), "")
        self.assertIn("240.0.0.0/4 (Class E)", self.said(self.warn))

    def test_prohibited_ranges_are_refused_by_overlap(self):
        for cidr, words in (("0.10.0.0/16", "0.0.0.0/8"), ("169.254.0.0/15", "169.254.0.0/16"),
                            ("127.0.0.0/16", "loopback"), ("224.1.0.0/16", "multicast"),
                            ("199.36.152.0/22", "restricted.googleapis.com"), ("240.0.0.0/4", "broadcast")):
            msg = self.problems(_cfg(network_cidr=cidr))
            self.assertIn(words, msg, cidr)
            self.assertIn("GCP does not allow in subnets", msg, cidr)
        self.assertEqual(self.problems(_cfg(network_cidr="100.64.0.0/16")), "")
        self.assertEqual(self.problems(_cfg(network_cidr="192.168.0.0/16")), "")


# ---------------------------------------------------------------- a2-gcp#17: credentials
class CredentialTests(unittest.TestCase):
    def warnings(self, dmi=None, **env):
        home = tempfile.mkdtemp(prefix="cs-w3cred-")
        self.addCleanup(shutil.rmtree, home, True)
        names = ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN", "GCE_METADATA_HOST",
                 "GCE_METADATA_IP", "K_SERVICE", "CLOUD_RUN_JOB", "FUNCTION_TARGET", "CLOUD_SHELL",
                 "GOOGLE_CLOUD_KEYFILE_JSON", "GCLOUD_KEYFILE_JSON")
        clean = {k: v for k, v in os.environ.items() if k not in names}
        clean.update(HOME=home, **env)
        real_read = Path.read_text

        def read_text(p, *a, **kw):
            if str(p) == "/sys/class/dmi/id/product_name":
                if dmi is None:
                    raise FileNotFoundError(p)
                return dmi
            return real_read(p, *a, **kw)
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(Path, "read_text", read_text):
            return GCP.credential_warnings({"vars": {}})

    def test_valid_non_adc_sources_are_accepted(self):
        self.assertEqual(self.warnings(GOOGLE_OAUTH_ACCESS_TOKEN="ya29.token"), [])
        self.assertEqual(self.warnings(GCE_METADATA_HOST="127.0.0.1:7717"), [])
        self.assertEqual(self.warnings(CLOUD_SHELL="true"), [])
        self.assertEqual(self.warnings(K_SERVICE="svc"), [])
        self.assertEqual(self.warnings(dmi="Google Compute Engine\n"), [])

    def test_keyfile_variables_get_a_targeted_warning(self):
        w = self.warnings(GOOGLE_CLOUD_KEYFILE_JSON="/k.json")
        self.assertEqual(len(w), 1)
        self.assertIn("not by Terraform's GCS state backend", w[0])
        self.assertIn("GOOGLE_CREDENTIALS", w[0])

    def test_nothing_at_all(self):
        w = self.warnings(dmi="VMware Virtual Platform")
        self.assertIn("No Google credentials detected", w[0])
        self.assertIn("GOOGLE_OAUTH_ACCESS_TOKEN", w[0])


# ---------------------------------------------------------------- a2-gcp#20: google-like names
class GoogleLikeNameTests(_Quiet):
    def test_detection(self):
        for p in ("google-lab-dev", "goog-dev", "googly-dev", "lab-g00gle-dev", "my-goog1e"):
            self.assertTrue(gcpmod.google_like(p), p)
        for p in ("cloudseed-dev", "go-dev", "gogle-dev", "log-dev"):
            self.assertFalse(gcpmod.google_like(p), p)

    def test_setup_says_the_buckets_are_renamed(self):
        GCP.check_vars(_cfg(name="google-lab"))
        self.assertIn("named from a hash (cs-...) instead of 'google-lab-dev-...'", self.said(self.info))
        self.info.reset_mock()
        GCP.check_vars(_cfg())
        self.assertNotIn("named from a hash", self.said(self.info))

    def test_terraform_renames_them(self):
        boot = (TF / "gcp-bootstrap" / "main.tf").read_text()
        names = (TF / "gcp" / "modules" / "names" / "main.tf").read_text()
        for text in (boot, names):
            self.assertIn('startswith(lower(var.prefix), "goog") || can(regex("g[o0]{2,}g[l1]e", lower(var.prefix)))', text)
        self.assertIn('"cs-${substr(sha1(var.prefix), 0, 8)}"', boot)


# ---------------------------------------------------------------- need-ansible: instance ids of replaceable hosts
class InstanceIdOutputTests(unittest.TestCase):
    def test_outputs_are_declared_and_rendered(self):
        outputs = (TF / "gcp" / "outputs.tf").read_text()
        for name in ("bastion_instance_id", "vpn_instance_id"):
            self.assertIn(name, GCP.outputs)
            self.assertIn(f'output "{name}"', outputs)
        self.assertIn("module.bastion.instance_id", outputs)
        self.assertIn("google_compute_instance.bastion.instance_id", (TF / "gcp" / "modules" / "bastion" / "main.tf").read_text())
        self.assertIn("google_compute_instance.vpn.instance_id", (TF / "gcp" / "modules" / "vpn" / "main.tf").read_text())
        root = GCP.render_stack(_cfg(), TF)
        self.assertEqual(root["output"]["vpn_instance_id"], {"value": "${module.stack.vpn_instance_id}"})

    def test_replaced_hosts_forget_their_host_keys(self):
        env = SimpleNamespace()
        with mock.patch.object(provision, "forget_host_key") as forget:
            gone = provision.forget_replaced_hosts(env, {"bastion_instance_id": "111", "bastion_public_ip": "34.1.1.1",
                                                         "vpn_instance_id": "222", "vpn_public_ip": "34.2.2.2"},
                                                   {"bastion_instance_id": "333", "bastion_public_ip": "34.1.1.1",
                                                    "vpn_instance_id": "222", "vpn_public_ip": "34.2.2.2"})
        self.assertEqual(gone, ["34.1.1.1"])
        forget.assert_called_once_with(env, "34.1.1.1")


# ---------------------------------------------------------------- the real CLI: refused before anything is saved
class SetupCliTests(unittest.TestCase):
    def test_apply_time_values_abort_before_saving(self):
        home = tempfile.mkdtemp(prefix="cs-w3gcp-cli-")
        self.addCleanup(shutil.rmtree, home, True)
        env = dict(os.environ, CLOUDSEED_HOME=home, HOME=home, NO_COLOR="1")
        base = [sys.executable, str(ROOT / "bin" / "cloudseed"), "setup", "gcp", "-y", "--env", "bad",
                "--project-id", "my-proj-123", "--region", "us-central1", "--allow-ip", "1.2.3.4", "--state", "local",
                "--dry-run"]
        for extra, words in ((["--var", "log_retention_days=0"], "log_retention_days"),
                             (["--var", "bastion_machine_type=E2-MICRO"], "e2-micro"),
                             (["--cidr", "0.10.0.0/16"], "0.0.0.0/8")):
            p = subprocess.run(base + extra, env=env, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
            out = p.stdout + p.stderr
            self.assertEqual(p.returncode, 1, out)
            self.assertIn(words, out)
            self.assertFalse((Path(home) / "envs" / "gcp-bad" / "config.json").exists())


if __name__ == "__main__":
    unittest.main()
