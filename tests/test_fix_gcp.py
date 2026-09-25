"""Regression tests for the GCP adapter and stack (zone defaults, input validation, strict booleans, length-safe names,
Workload Identity ordering, Velero, FIPS VPN image, OS Login). Offline and fast: no cloud, no network."""
import ipaddress
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

from cloudseed import clouds, ui  # noqa: E402
from cloudseed.clouds import gcp as gcpmod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform"
GCP = clouds.get("gcp")
SA_RE = re.compile(r"^[a-z][-a-z0-9]{4,28}[a-z0-9]$")


def _cfg(**over):
    cfg = {"cloud": "gcp", "env": "dev", "name": "acme", "owner": "me", "region": "us-central1",
           "network_cidr": "10.0.0.0/16", "allowed_ssh_cidrs": ["1.2.3.4/32"], "ssh_public_key": "ssh-ed25519 AAAA key",
           "state": {"type": "local", "backend": None}, "extra_vars": {}, "tags": {},
           "vars": {"project_id": "my-proj-123", "zone": "us-central1-a", "ssh_username": "alice"}}
    vars_ = over.pop("vars", {})
    cfg.update(over)
    cfg["vars"].update(vars_)
    return cfg


class _Quiet(unittest.TestCase):
    def setUp(self):
        self._ni = ui.NON_INTERACTIVE
        ui.NON_INTERACTIVE = True          # never prompt, whatever the terminal
        p = mock.patch.object(ui, "err"), mock.patch.object(ui, "warn"), mock.patch.object(ui, "info"), mock.patch.object(ui, "ok")
        self.err, self.warn, self.info, self.okm = (x.start() for x in p)
        for x in p:
            self.addCleanup(x.stop)

    def tearDown(self):
        ui.NON_INTERACTIVE = self._ni


class ZoneTests(_Quiet):
    def test_default_zone_exists_in_every_region(self):
        self.assertEqual(gcpmod.default_zone("europe-west1"), "europe-west1-b")   # README example region: no -a zone
        self.assertEqual(gcpmod.default_zone("us-east1"), "us-east1-b")
        self.assertEqual(gcpmod.default_zone("us-central1"), "us-central1-a")
        zq = next(q for q in GCP.questions if q.key == "zone")
        self.assertEqual(zq.default({"region": "europe-west1"}), "europe-west1-b")
        self.assertEqual(zq.default({"region": "us-central1", "workdir": ""}), "us-central1-a")   # web catalog call shape

    def _collect(self, existing, region, **flags):
        args = SimpleNamespace(project_id=flags.get("project_id"), zone=flags.get("zone"), ssh_username=flags.get("ssh_username"))
        return GCP.collect_vars(args, existing, {"region": region, "name": "acme", "env": "dev"}, False)

    def test_region_change_rederives_zone(self):
        existing = {"project_id": "my-proj-123", "zone": "europe-west1-b", "ssh_username": "alice"}
        self.assertEqual(self._collect(existing, "us-west1")["zone"], "us-west1-a")
        self.assertEqual(self._collect(existing, "europe-west1")["zone"], "europe-west1-b")      # unchanged region keeps it
        self.assertEqual(self._collect(existing, "us-west1", zone="us-west1-c")["zone"], "us-west1-c")  # explicit wins

    def test_env_zone_of_another_region_is_ignored(self):
        with mock.patch.dict(os.environ, {"CLOUDSDK_COMPUTE_ZONE": "us-central1-f", "GOOGLE_PROJECT": "my-proj-123"}):
            self.assertEqual(self._collect({}, "us-east1")["zone"], "us-east1-b")
            self.assertEqual(self._collect({}, "us-central1")["zone"], "us-central1-f")

    def test_saved_poisoned_values_are_healed(self):
        existing = {"project_id": "my-proj-123", "zone": "us-central1-a", "enable_kubernetes": "no", "fips_mode": "False",
                    "kubernetes_node_count": "abc", "enable_vpn": "YES"}
        out = self._collect(existing, "us-central1")
        self.assertIs(out["enable_kubernetes"], False)
        self.assertIs(out["fips_mode"], False)
        self.assertIs(out["enable_vpn"], True)
        self.assertEqual(out["kubernetes_node_count"], 2)

    def test_missing_a_zones_of_older_defaults_are_healed_and_refused(self):
        # an env saved by an older version (default <region>-a) failed at apply; re-running setup must fix the zone
        existing = {"project_id": "my-proj-123", "zone": "europe-west1-a"}
        self.assertEqual(self._collect(existing, "europe-west1")["zone"], "europe-west1-b")
        self.assertEqual(self._collect({**existing, "zone": "us-east1-a"}, "us-east1")["zone"], "us-east1-b")
        self.assertEqual(self._collect({**existing, "zone": "us-central1-a"}, "us-central1")["zone"], "us-central1-a")
        with mock.patch.dict(os.environ, {"CLOUDSDK_COMPUTE_ZONE": "us-east1-a", "GOOGLE_PROJECT": "my-proj-123"}):
            self.assertEqual(self._collect({}, "us-east1")["zone"], "us-east1-b")
        with self.assertRaises(ui.Abort) as cm:                        # typed explicitly: refused before anything is saved
            GCP.check_vars(_cfg(region="us-east1", vars={"zone": "us-east1-a"}))
        self.assertIn("us-east1-b", cm.exception.msg)
        zq = next(q for q in GCP.questions if q.key == "zone")
        self.assertIn("does not exist", zq.validate("europe-west1-a"))    # the interactive prompt refuses it too

    def test_collect_vars_passes_extra_arguments_through(self):
        with mock.patch.object(clouds.base.Cloud, "collect_vars", return_value={}) as base:
            GCP.collect_vars(SimpleNamespace(), {"zone": "europe-west1-a"}, {"region": "europe-west1"}, False, overrides={"x": 1})
        args, kwargs = base.call_args
        self.assertEqual(kwargs, {"overrides": {"x": 1}})                 # e.g. a base that takes --var overrides
        self.assertEqual(args[1]["zone"], "europe-west1-b")

    def test_zone_outside_region_is_refused(self):
        cfg = _cfg(region="europe-west1", vars={"zone": "us-central1-a"})
        with self.assertRaises(ui.Abort) as cm:
            GCP.check_vars(cfg)
        self.assertIn("europe-west1-b", cm.exception.msg)
        GCP.check_vars(_cfg(region="europe-west1", vars={"zone": "europe-west1-c"}))


class CheckVarsTests(_Quiet):
    def _problems(self, cfg):
        try:
            GCP.check_vars(cfg)
        except ui.Abort as e:
            return e.msg
        return ""

    def test_strict_booleans_and_ints(self):
        cfg = _cfg(vars={"enable_kubernetes": "False", "fips_mode": "no", "enable_vpn": "on", "kubernetes_public_endpoint": 0,
                         "kubernetes_node_count": "3"})
        GCP.check_vars(cfg)
        v = cfg["vars"]
        self.assertEqual((v["enable_kubernetes"], v["fips_mode"], v["enable_vpn"], v["kubernetes_public_endpoint"]), (False, False, True, False))
        self.assertEqual(v["kubernetes_node_count"], 3)
        self.assertIn("enable_vpn", self._problems(_cfg(vars={"enable_vpn": "maybe"})))
        self.assertIn("whole number", self._problems(_cfg(vars={"kubernetes_node_count": "abc"})))
        self.assertIn("whole number", self._problems(_cfg(vars={"kubernetes_node_count": 2.5})))
        self.assertIn("at least 1", self._problems(_cfg(vars={"kubernetes_node_count": 0, "enable_kubernetes": True})))
        self.assertIn("VPN type", self._problems(_cfg(vars={"vpn_type": "wireguard"})))

    def test_project_id_and_username(self):
        self.assertIn("--project-id", self._problems(_cfg(vars={"project_id": "Bad Project!"})))
        self.assertIn("--project-id", self._problems(_cfg(vars={"project_id": "p1"})))            # < 6 characters
        self.assertEqual("", self._problems(_cfg(vars={"project_id": "example.com:my-proj"})))     # domain-scoped
        self.assertIn("--ssh-username", self._problems(_cfg(vars={"ssh_username": "bad user:x"})))
        self.assertIn("root", self._problems(_cfg(vars={"ssh_username": "root"})))
        self.assertEqual("", self._problems(_cfg(vars={"ssh_username": "_svc.deploy-1"})))

    def test_network_checks(self):
        self.assertIn("IPv6", self._problems(_cfg(allowed_ssh_cidrs=["1.2.3.4/32", "2001:db8::1/128"])))
        self.assertIn("/29", self._problems(_cfg(network_cidr="10.0.0.0/28")))
        self.assertEqual("", self._problems(_cfg(network_cidr="10.0.0.0/25")))
        self.assertIn("/29", self._problems(_cfg(network_cidr="10.0.0.0/24", extra_vars={"subnet_newbits": 6})))
        self.assertIn("subnet_newbits", self._problems(_cfg(extra_vars={"subnet_newbits": 0})))
        self.assertIn("not a network CIDR", self._problems(_cfg(network_cidr="garbage")))
        self.assertIn("reserved", self._problems(_cfg(network_cidr="127.0.0.0/16")))
        over = _cfg(network_cidr="172.16.0.0/16", vars={"enable_kubernetes": True}, extra_vars={"kubernetes_master_cidr": "172.16.5.0/28"})
        self.assertIn("overlaps", self._problems(over))
        self.assertIn("/28", self._problems(_cfg(vars={"enable_kubernetes": True}, extra_vars={"kubernetes_master_cidr": "192.168.0.0/24"})))
        self.assertEqual("", self._problems(_cfg(network_cidr="172.16.0.0/16", vars={"enable_kubernetes": True})))

    def test_label_keys_warn_and_are_made_valid(self):
        cfg = _cfg(tags={"1abc": "x", "project": "other"})
        GCP.check_vars(cfg)                                   # never blocks: saved tags cannot be removed
        warned = " ".join(str(c.args[0]) for c in self.warn.call_args_list)
        self.assertIn("t-1abc", warned)
        # a tag that spells a built-in key in another case sets that key (Cloud.tags): no collision to warn about
        self.assertNotIn("the same as the tag 'Project'", warned)
        labels = GCP.tags(cfg)
        self.assertEqual(labels["project"], "other")
        for k, v in labels.items():
            self.assertRegex(k, r"^[a-z][a-z0-9_-]{0,62}$")
            self.assertRegex(v, r"^[a-z0-9_-]{0,63}$")
        self.assertEqual(labels["t-1abc"], "x")


class StackVarsTests(_Quiet):
    def test_booleans_are_parsed_not_truthy(self):
        sv = GCP.stack_vars(_cfg(vars={"enable_kubernetes": "False", "fips_mode": "no", "enable_vpn": "true",
                                       "kubernetes_node_count": "4"}))
        self.assertEqual((sv["enable_kubernetes"], sv["fips_mode"], sv["enable_vpn"], sv["kubernetes_node_count"]), (False, False, True, 4))

    def test_poisoned_saved_value_gives_a_fix_command(self):
        with self.assertRaises(ui.Abort) as cm:
            GCP.stack_vars(_cfg(vars={"kubernetes_node_count": "abc"}))
        self.assertIn("cloudseed setup gcp --env dev --var kubernetes_node_count=", cm.exception.msg)

    def test_master_cidr_moves_out_of_an_overlapping_network(self):
        self.assertNotIn("kubernetes_master_cidr", GCP.stack_vars(_cfg()))                  # default kept: nothing changes
        picked = GCP.stack_vars(_cfg(network_cidr="172.16.0.0/12"))["kubernetes_master_cidr"]
        self.assertFalse(ipaddress.ip_network(picked).overlaps(ipaddress.ip_network("172.16.0.0/12")))
        cfg = _cfg(network_cidr="172.16.0.0/16", extra_vars={"kubernetes_master_cidr": "192.168.1.0/28"})
        mod = GCP.render_stack(cfg, TF)["module"]["stack"]
        self.assertEqual(mod["kubernetes_master_cidr"], "192.168.1.0/28")                    # explicit --var wins

    def test_setup_checks_accept_the_automatic_master_cidr(self):
        # setup's generic network checks (cli._config_problems) must not refuse a network the adapter already moves
        # the GKE control plane out of; an explicit overlapping --var kubernetes_master_cidr is still refused
        from cloudseed import cli
        gke = _cfg(network_cidr="172.16.0.0/16", vars={"enable_kubernetes": True})
        self.assertEqual([p for p in cli._config_problems(GCP, gke) if "overlaps" in p], [])
        over = _cfg(network_cidr="172.16.0.0/16", vars={"enable_kubernetes": True},
                    extra_vars={"kubernetes_master_cidr": "172.16.5.0/28"})
        self.assertTrue([p for p in cli._config_problems(GCP, over) if "overlaps" in p])

    def test_zone_fallback_and_provider(self):
        cfg = _cfg(region="us-east1")
        del cfg["vars"]["zone"]
        self.assertEqual(GCP.stack_vars(cfg)["zone"], "us-east1-b")
        self.assertEqual(GCP.provider_block(cfg)["google"]["zone"], "us-east1-b")

    def test_default_username_is_a_valid_linux_name(self):
        for local, want in (("alice", "alice"), ("1abc", "u1abc"), ("-x", "u-x"), ("root", "cloudseed")):
            with mock.patch.object(gcpmod.netutil, "local_username", return_value=local):
                self.assertEqual(gcpmod._default_ssh_username(), want)
                self.assertIsNone(gcpmod._check_ssh_username(gcpmod._default_ssh_username()))


class OsLoginTests(_Quiet):
    PROFILE = {"posixAccounts": [{"accountId": "other-proj", "primary": True, "username": "other_user"},
                                 {"accountId": "my-proj-123", "primary": False, "username": "dev_example_com"}]}

    def _run(self, calls):
        def fake(argv, **kw):
            calls.append(argv)
            if argv[1:4] == ["config", "get-value", "account"]:
                return subprocess.CompletedProcess(argv, 0, "dev@example.com\n", "")
            if "describe-profile" in argv:
                return subprocess.CompletedProcess(argv, 0, json.dumps(self.PROFILE), "")
            if "ssh-keys" in argv:
                key_file = argv[argv.index("--key-file") + 1]
                self.assertTrue(Path(key_file).read_text().startswith("ssh-ed25519 AAAA key"))
                return subprocess.CompletedProcess(argv, 0, "{}", "")
            return subprocess.CompletedProcess(argv, 1, "", "unexpected")
        return fake

    def test_prepare_registers_key_and_records_login(self):
        cfg, calls = _cfg(vars={"enable_os_login": True}), []
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run", side_effect=self._run(calls)):
            GCP.prepare(cfg)
        login = {k: cfg["os_login"][k] for k in ("account", "user", "member")}   # plus the key it registered (wave 3)
        self.assertEqual(login, {"account": "dev@example.com", "user": "dev_example_com", "member": "user:dev@example.com"})
        self.assertTrue(any("ssh-keys" in c and "add" in c for c in calls))
        self.assertEqual(GCP.ssh_user(cfg), "dev_example_com")
        sv = GCP.stack_vars(cfg)
        self.assertEqual((sv["ssh_username"], sv["os_login_member"], sv["enable_os_login"]), ("dev_example_com", "user:dev@example.com", True))
        cfg["vars"]["enable_os_login"] = False                   # turning it off goes back to the metadata-key user
        GCP.prepare(cfg)
        self.assertNotIn("os_login", cfg)
        self.assertEqual(GCP.ssh_user(cfg), "alice")
        self.assertEqual(GCP.stack_vars(cfg)["os_login_member"], "")

    def test_service_account_member_and_dry_run(self):
        cfg = _cfg(vars={"enable_os_login": "true"})
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(gcpmod.subprocess, "run") as run:
            GCP.prepare(cfg, dry_run=True)
            run.assert_not_called()                              # dry runs never call gcloud
        self.assertNotIn("os_login", cfg)
        self.assertEqual(GCP.ssh_user(cfg), "alice")

    def test_missing_gcloud_or_failures_abort_clearly(self):
        cfg = _cfg(vars={"enable_os_login": True})
        with mock.patch.object(gcpmod.deps, "find", return_value=None):
            GCP.prepare(cfg, dry_run=True)                       # warns only
            with self.assertRaises(ui.Abort) as cm:
                GCP.prepare(cfg)
            self.assertIn("gcloud", cm.exception.msg)
        fail = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "ERROR: (gcloud) not logged in")  # noqa: E731
        with mock.patch.object(gcpmod.deps, "find", return_value="/fake/gcloud"), mock.patch.object(gcpmod.subprocess, "run", side_effect=fail):
            with self.assertRaises(ui.Abort) as cm:
                GCP.prepare(cfg)
            self.assertIn("not logged in", cm.exception.msg)

    def test_posix_user_choice(self):
        self.assertEqual(GCP._posix_user(json.dumps(self.PROFILE), "my-proj-123"), "dev_example_com")
        self.assertEqual(GCP._posix_user(json.dumps(self.PROFILE), "nope-123"), "other_user")   # primary
        self.assertEqual(GCP._posix_user("not json", "p"), "")


class SetupCliTests(unittest.TestCase):
    """cmd_setup runs check_vars before saving: a bad value aborts with nothing written."""

    def test_invalid_input_aborts_before_config_is_saved(self):
        home = tempfile.mkdtemp(prefix="cs-fixgcp-")
        self.addCleanup(shutil.rmtree, home, True)
        env = dict(os.environ, CLOUDSEED_HOME=home, HOME=home, NO_COLOR="1")
        base = [sys.executable, str(ROOT / "bin" / "cloudseed"), "setup", "gcp", "-y", "--env", "bad",
                "--project-id", "my-proj-123", "--region", "europe-west1", "--allow-ip", "1.2.3.4", "--state", "local",
                "--dry-run"]
        # a bad --var value is refused up front (before any prompt); a zone of another region when the answers are
        # checked. Either way nothing is saved.
        for extra, words in ((["--zone", "us-central1-a", "--var", "kubernetes_node_count=abc"], ("kubernetes_node_count",)),
                             (["--zone", "us-central1-a"], ("us-central1-a", "region europe-west1"))):
            p = subprocess.run(base + extra, env=env, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
            out = p.stdout + p.stderr
            self.assertEqual(p.returncode, 1, out)
            for word in words:
                self.assertIn(word, out)
            self.assertFalse((Path(home) / "envs" / "gcp-bad" / "config.json").exists())


class VeleroValuesTests(unittest.TestCase):
    def test_backup_location_names_the_gsa(self):
        from cloudseed import paths, platform as pl
        env = paths.Env("gcp", "velero-fix")
        env.create_dirs()
        ctx = pl.Cluster(GCP, env, {"env": "velero-fix", "region": "us-central1", "network_cidr": "10.0.0.0/16", "vars": {"project_id": "p"}},
                         {"kubernetes_cluster_name": "c", "kubernetes_velero_gsa": "v@p.iam.gserviceaccount.com",
                          "kubernetes_velero_bucket": "b"}, env.dir / "kc")
        args = " ".join(pl._values_args(pl.CATALOG["velero"], ctx))
        self.assertIn("configuration.backupStorageLocation[0].config.serviceAccount=v@p.iam.gserviceaccount.com", args)


class TerraformTextTests(unittest.TestCase):
    """Static checks on the GCP Terraform (the stack cannot be planned without provider binaries in unit tests)."""

    def read(self, rel):
        return (TF / rel).read_text()

    def test_no_truncated_service_account_ids_left(self):
        for rel in ("gcp/modules/bastion/main.tf", "gcp/modules/vpn/main.tf", "gcp/modules/kubernetes/main.tf",
                    "gcp/modules/kubernetes/platform.tf"):
            self.assertNotIn("substr(\"${var.prefix}", self.read(rel), rel)
        self.assertIn('module.names.service_account_ids["bastion"]', self.read("gcp/main.tf"))
        self.assertIn('module.names.service_account_ids["vpn"]', self.read("gcp/main.tf"))

    def test_workload_identity_waits_for_the_cluster(self):
        k8s = self.read("gcp/modules/kubernetes/main.tf") + self.read("gcp/modules/kubernetes/platform.tf")
        self.assertIn("workload_pool = google_container_cluster.this.workload_identity_config[0].workload_pool", k8s)
        self.assertNotIn(".svc.id.goog[", k8s.replace("${local.workload_pool}[", ""))
        self.assertEqual(k8s.count("${local.workload_pool}["), 3)

    def test_velero_bucket_region_and_least_privilege(self):
        pf = self.read("gcp/modules/kubernetes/platform.tf")
        self.assertIn("location                    = var.region", pf)
        self.assertNotIn("storage.objects", pf)
        self.assertNotIn("google_project_iam_custom_role", pf)
        self.assertIn("roles/iam.serviceAccountTokenCreator", pf)
        self.assertIn("[velero/velero]", pf)             # matches serviceAccount.server.name=velero in the catalog
        self.assertIn("region              = var.region", self.read("gcp/main.tf"))

    def test_gke_cluster_hardening_and_pool_size(self):
        k8s = self.read("gcp/modules/kubernetes/main.tf")
        for comp in ("APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"):
            self.assertIn(f'"{comp}"', k8s)
        self.assertIn("service_account = google_service_account.nodes.email", k8s.split('resource "google_container_node_pool"')[0])
        self.assertIn("ignore_changes = [node_config]", k8s)
        self.assertIn("min_node_count = max(var.node_min, var.node_count)", k8s)
        self.assertIn("max_node_count = max(var.node_max, var.node_count, var.node_min)", k8s)

    def test_fips_vpn_image(self):
        vpn = self.read("gcp/modules/vpn/main.tf")
        self.assertIn('var.fips_mode ? "ubuntu-os-pro-cloud/ubuntu-pro-fips-2204-lts"', vpn)
        self.assertIn("image = local.image", vpn)
        self.assertRegex(self.read("gcp/main.tf"), r'module "vpn" \{[^}]*fips_mode\s+= var\.fips_mode')

    def test_apis_and_labels(self):
        main = self.read("gcp/main.tf")
        self.assertIn('"cloudresourcemanager.googleapis.com"', main)
        self.assertIn('"iamcredentials.googleapis.com"', main)
        self.assertNotIn("managed_by", main)
        self.assertNotIn("managed_by", self.read("gcp-bootstrap/main.tf"))

    def test_os_login_grants(self):
        b = self.read("gcp/modules/bastion/main.tf")
        self.assertIn('"roles/compute.osAdminLogin"', b)
        self.assertIn('"roles/iam.serviceAccountUser"', b)
        self.assertIn("os_login_member = var.os_login_member", self.read("gcp/main.tf"))
        self.assertIn("os_login_member", GCP.stack_vars(_cfg()))

    def test_every_output_is_declared(self):
        declared = set(re.findall(r'^output "([a-z_]+)"', self.read("gcp/outputs.tf"), re.M))
        self.assertLessEqual(set(GCP.outputs), declared)
        self.assertIn("kubernetes_node_pool", GCP.outputs)


@unittest.skipUnless(shutil.which("terraform"), "terraform not installed")
class NamesModuleTests(unittest.TestCase):
    """Evaluate the real naming module (no providers, so terraform works offline) over every prefix length the CLI
    allows (<name>-<env>: 5..49 characters) and check GCP's limits."""

    FW_SUFFIXES = ("-allow-ssh-from-bastion", "-allow-private-from-vpn", "-allow-ssh-to-bastion", "-allow-private-internal",
                   "-deny-all-ingress", "-allow-ssh-to-vpn", "-allow-vpn")

    @classmethod
    def setUpClass(cls):
        import random
        rnd = random.Random(7)
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
        prefixes = {"cloudseed-dev", "cloudseed-stage", "cloudseed-production", "cloudseed-production1",
                    "cloudseed-production-eu", "cloudseed-production-europe-west", "a--b-",
                    "acme-data-platform-prod-staging-europe-west1-app"}
        for n in range(5, 50):
            prefixes.add(rnd.choice("abcdefghijklmnopqrstuvwxyz") + "".join(rnd.choice(alphabet) for _ in range(n - 1)))
        cls.prefixes = sorted(prefixes)
        cls.tmp = tempfile.mkdtemp(prefix="cs-names-")
        root = {"module": {"n": {"source": str(TF / "gcp" / "modules" / "names"), "for_each": "${toset(%s)}" % json.dumps(cls.prefixes),
                                 "prefix": "${each.key}", "project_id": "my-proj-123"}},
                "output": {"all": {"value": "${module.n}"}}}
        (Path(cls.tmp) / "main.tf.json").write_text(json.dumps(root))
        env = dict(os.environ, CHECKPOINT_DISABLE="1", TF_IN_AUTOMATION="1", TF_DATA_DIR=str(Path(cls.tmp) / ".terraform"))
        for argv in (["init", "-input=false", "-no-color"], ["apply", "-auto-approve", "-input=false", "-no-color"]):
            p = subprocess.run(["terraform", *argv], cwd=cls.tmp, env=env, capture_output=True, text=True, timeout=300)
            if p.returncode != 0:
                raise AssertionError(p.stdout + p.stderr)
        p = subprocess.run(["terraform", "output", "-json", "all"], cwd=cls.tmp, env=env, capture_output=True, text=True, timeout=120)
        cls.names = json.loads(p.stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_limits_hold_for_every_prefix(self):
        self.assertEqual(set(self.names), set(self.prefixes))
        for prefix, n in self.names.items():
            ids = n["service_account_ids"]
            self.assertEqual(set(ids), {"bastion", "vpn", "gke_nodes", "external_secrets", "external_dns", "velero"})
            for key, sa in ids.items():
                self.assertRegex(sa, SA_RE, f"{prefix}: {key}")
            self.assertEqual(len(set(ids.values())), len(ids), f"{prefix}: duplicate service-account IDs {ids}")
            for suffix in self.FW_SUFFIXES:
                self.assertRegex(n["firewall_prefix"] + suffix, r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", prefix)
            self.assertLessEqual(len(n["gke_cluster_name"]), 40, prefix)
            self.assertLessEqual(len(n["gke_node_pool_name"]), 40, prefix)
            self.assertRegex(n["velero_bucket_name"], r"^[a-z0-9][-a-z0-9_]{1,61}[a-z0-9]$", prefix)

    def test_names_that_already_worked_are_unchanged(self):
        dev = self.names["cloudseed-dev"]
        self.assertEqual(dev["service_account_ids"], {
            "bastion": "cloudseed-dev-bastion", "vpn": "cloudseed-dev-vpn", "gke_nodes": "cloudseed-dev-gke-nodes",
            "external_secrets": "cloudseed-dev-external-secrets", "external_dns": "cloudseed-dev-external-dns",
            "velero": "cloudseed-dev-velero"})
        self.assertEqual((dev["firewall_prefix"], dev["gke_cluster_name"], dev["gke_node_pool_name"], dev["velero_bucket_name"]),
                         ("cloudseed-dev", "cloudseed-dev-gke", "cloudseed-dev-gke-default", "cloudseed-dev-gke-velero-my-proj-123"))
        # valid, unique truncations of existing environments are kept (account_id is ForceNew)
        self.assertEqual(self.names["cloudseed-stage"]["service_account_ids"]["external_secrets"], "cloudseed-stage-external-secre")

    def test_colliding_truncations_get_distinct_ids(self):
        prod = self.names["cloudseed-production"]["service_account_ids"]
        self.assertNotEqual(prod["external_secrets"], prod["external_dns"])        # used to be invalid ("...-external-")
        long = self.names["cloudseed-production-europe-west"]["service_account_ids"]
        self.assertEqual(len(set(long.values())), 6)                                 # used to be six copies of one ID


class WebConsoleZoneTests(unittest.TestCase):
    """Integration of fix/gcp with fix/web-logic: the wizard derives the zone from the chosen region and sends it on a
    region move, so it must follow default_zone() (europe-west1/us-east1 have no -a zone and setup refuses one)."""

    def test_catalog_lists_the_irregular_zone_defaults(self):
        from cloudseed import webui
        zone = {q["key"]: q for q in webui.clouds_catalog()["gcp"]["questions"]}["zone"]
        self.assertEqual(zone["default"], "us-central1-a")
        self.assertEqual(zone["region_defaults"], {"europe-west1": "europe-west1-b", "us-east1": "us-east1-b"})
        for region, val in zone["region_defaults"].items():
            self.assertEqual(val, gcpmod.default_zone(region))
            self.assertIsNone(gcpmod._check_zone(val))

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_wizard_derived_zone_matches_the_cli(self):
        from cloudseed import webui
        src = (Path(webui.WEB_ROOT) / "app.js").read_text()
        derived = re.search(r"const derivedDefault = .*;", src).group(0)
        cat = webui.clouds_catalog()["gcp"]
        zone = {q["key"]: q for q in cat["questions"]}["zone"]
        regions = ["us-central1", "europe-west1", "us-east1", "us-west1", "asia-southeast1"]
        code = (f"const CL = {json.dumps(cat)}; const c = () => CL; const data = {{}};\n{derived}\n"
                f"console.log(JSON.stringify({json.dumps(regions)}.map((r) => {{ data.region = r; return derivedDefault({json.dumps(zone)}); }})));")
        out = subprocess.run(["node", "-e", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), [gcpmod.default_zone(r) for r in regions])


if __name__ == "__main__":
    unittest.main()
