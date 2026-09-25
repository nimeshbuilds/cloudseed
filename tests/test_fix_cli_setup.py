"""Regression tests for `cloudseed setup` and its helpers: flag/--var validation and typing, cloudseed-managed
variables, network sizing, the SSH allow-list of existing environments, FIPS key selection, working-directory
safety, dry-run/plan-only/declined runs, state migration, undo records and provisioning bookkeeping.

No cloud, no network, no terraform: Terraform and key generation are replaced by in-process fakes."""
import base64
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, cli, clouds, netutil, paths, ui, undo  # noqa: E402
from cloudseed.cli import build_parser  # noqa: E402


# ---------------------------------------------------------------- fakes

def _blob(*fields: bytes) -> str:
    return base64.b64encode(b"".join(len(f).to_bytes(4, "big") + f for f in fields)).decode()


def fake_pub(algo: str) -> str:
    """A well-formed OpenSSH public key line of the given type (the wire format, so any parser accepts it)."""
    if algo == "ssh-ed25519":
        blob = _blob(b"ssh-ed25519", bytes(range(32)))
    elif algo == "ssh-rsa":
        blob = _blob(b"ssh-rsa", bytes([1, 0, 1]), bytes([0]) + bytes([0xC3]) * 512)
    else:
        algo = "ecdsa-sha2-nistp384"
        blob = _blob(b"ecdsa-sha2-nistp384", b"nistp384", bytes([4]) + bytes([0x11]) * 96)
    return algo + " " + blob + " test"


def fake_ensure_ssh_key(ssh_dir, comment, fips=False, **_):
    """netutil.ensure_ssh_key without ssh-keygen: reuses a pair only when it suits the mode, like the real one."""
    ssh_dir = Path(ssh_dir)
    ssh_dir.mkdir(parents=True, exist_ok=True)
    priv, pub = ssh_dir / "id_ed25519", ssh_dir / "id_ed25519.pub"
    if pub.exists() and priv.exists():
        return priv, pub
    pub.write_text(fake_pub("ecdsa-sha2-nistp384" if fips else "ssh-ed25519") + "\n")
    priv.write_text("PRIVATE\n")
    return priv, pub


class FakeTF:
    """Stands in for cli.Terraform: records calls; 'apply' puts resources in state."""
    calls: list = []
    state: dict = {}
    fail_apply = False

    def __init__(self, workdir):
        self.workdir = Path(workdir)

    def _log(self, *what):
        FakeTF.calls.append((self.workdir.name,) + what)

    def init(self, migrate=False, backend=True, **_):
        self._log("init", migrate, backend)

    def validate(self):
        self._log("validate")

    def plan(self, out="tfplan", destroy=False, targets=(), **_):
        (self.workdir / out).write_text("plan")
        self._log("plan")

    def apply(self, planfile=None, auto_approve=False, targets=(), **_):
        self._log("apply")
        FakeTF.state[str(self.workdir)] = ["module.state.bucket"]

    def plan_for_apply(self, cloud_key, cfg, out="tfplan", targets=(), render=None):
        self.plan(out, targets=targets)

    def apply_reconciled(self, cloud_key, cfg, targets=(), rounds=3, **_):
        self._log("apply")
        if FakeTF.fail_apply:
            FakeTF.state[str(self.workdir)] = ["module.stack.partial"]
            raise cli.TerraformError("apply failed")
        FakeTF.state[str(self.workdir)] = ["module.stack.module.network.aws_vpc.this"]

    def outputs(self):
        if self.workdir.name == "bootstrap":
            return {"bucket": "state-bucket", "region": "us-east-1", "resource_group_name": "rg",
                    "storage_account_name": "sa", "container_name": "c"}
        return {}

    def state_list(self):
        return list(FakeTF.state.get(str(self.workdir), []))

    def run(self, *args, capture=False, check=True):
        resources = [{"address": a, "mode": "managed", "type": "t", "name": "n"} for a in self.state_list()]
        return subprocess.CompletedProcess(args, 0, json.dumps({"values": {"root_module": {"resources": resources}}}), "")


class SetupHarness(unittest.TestCase):
    """Runs cmd_setup in-process with the fakes; every test uses its own environment names."""

    def setUp(self):
        FakeTF.calls, FakeTF.state, FakeTF.fail_apply = [], {}, False
        self.patches = [
            mock.patch.object(cli, "Terraform", FakeTF),
            mock.patch.object(netutil, "detect_public_ip", lambda timeout=5.0: "192.0.2.10"),
            mock.patch.object(netutil, "ensure_ssh_key", fake_ensure_ssh_key),
        ]
        for p in self.patches:
            p.start()
        self.was_non_interactive = ui.NON_INTERACTIVE
        ui.NON_INTERACTIVE = True
        self.envs: list = []

    def tearDown(self):
        for p in self.patches:
            p.stop()
        ui.NON_INTERACTIVE = self.was_non_interactive
        audit._state["purged"] = False
        for e in self.envs:
            undo.clear(e.id)
            import shutil
            shutil.rmtree(e.dir, ignore_errors=True)
            index = paths._load_index()
            if index.pop(e.id, None):
                paths._save_index(index)

    def env(self, cloud, name) -> paths.Env:
        e = paths.Env(cloud, name)
        self.envs.append(e)
        return e

    def setup(self, *argv):
        """(exit code, stdout+stderr) of `cloudseed setup ...`."""
        args = build_parser().parse_args(["setup", *argv])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                rc = cli.cmd_setup(args, {})
            except SystemExit as e:        # ui.Abort: quiet when raised, shown once by the dispatcher - do the same here
                if isinstance(e, ui.Abort):
                    ui.show_abort(e)
                rc = e.code
            except cli.TerraformError:     # main() reports it and exits 1
                rc = 1
        return rc, out.getvalue()

    @staticmethod
    def calls(kind):
        return [c for c in FakeTF.calls if c[1] == kind]


# ---------------------------------------------------------------- parsing and typing

class VarParsingTests(unittest.TestCase):
    def test_strict_booleans(self):
        for v in ("true", "True", "yes", "on", "1", 1, True):
            self.assertIs(cli._parse_bool(v), True, v)
        for v in ("false", "False", "no", "off", "0", 0, False):
            self.assertIs(cli._parse_bool(v), False, v)
        for v in ("maybe", "", "2", 2):
            with self.assertRaises(ValueError):
                cli._parse_bool(v)

    def test_question_answers_are_typed_and_validated(self):
        q = {x.key: x for x in clouds.get("aws").questions}
        self.assertIs(cli._coerce_answer(q["fips_mode"], "no"), False)
        self.assertEqual(cli._coerce_answer(q["az_count"], "3"), 3)
        self.assertEqual(cli._coerce_answer(q["vpn_type"], '"openvpn"'), "openvpn")
        for key, bad in (("az_count", "abc"), ("az_count", True), ("az_count", "-1"), ("fips_mode", "maybe"), ("vpn_type", "wireguard")):
            with self.assertRaises(ValueError):
                cli._coerce_answer(q[key], bad)

    def test_values_follow_the_declared_terraform_type(self):
        types = cli._variable_types("aws")
        self.assertEqual(types["kubernetes_version"], "string")
        self.assertEqual(cli._typed_var("kubernetes_version", "1.30", types["kubernetes_version"]), "1.30")
        self.assertEqual(cli._typed_var("kubernetes_version", '"1.30"', "string"), "1.30")
        self.assertEqual(cli._typed_var("subnet_newbits", "5", types["subnet_newbits"]), 5)
        self.assertIs(cli._typed_var("enable_flow_logs", "off", types["enable_flow_logs"]), False)
        self.assertEqual(cli._typed_var("x", "a, b", "list(string)"), ["a", "b"])
        self.assertEqual(cli._typed_var("x", '["a"]', "list(string)"), ["a"])
        for key, raw, ty in (("subnet_newbits", "four", "number"), ("enable_flow_logs", "perhaps", "bool"), ("m", "k=v", "map(string)")):
            with self.assertRaises(SystemExit):
                with contextlib.redirect_stderr(io.StringIO()):
                    cli._typed_var(key, raw, ty)

    def test_setup_vars_are_split_typed_and_refused(self):
        aws, vmware = clouds.get("aws"), clouds.get("vmware")
        g = cli._parse_setup_vars(aws, ["enable_kubernetes=on", "kubernetes_version=1.30", "log_retention_days=null"])
        self.assertEqual(g, {"answers": {"enable_kubernetes": True}, "extra": {"kubernetes_version": "1.30"},
                             "unset": ["log_retention_days"]})
        for cloud, bad, flag in ((aws, "name=Evil", "--name"), (aws, "environment=prod", "--env"), (aws, "tags={}", "--tag"),
                                 (aws, "ssh_public_key=x", "--ssh-public-key"), (aws, "platform_prereqs=[]", "platform install"),
                                 (aws, "vpc_cidr=10.7.0.0/16", "--cidr"), (vmware, "private_cidr=10.9.0.0/24", "--cidr"),
                                 (aws, 'allowed_ssh_cidrs=["0.0.0.0/1","128.0.0.0/1"]', "--allow-ip")):
            err = io.StringIO()
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(err):
                cli._parse_setup_vars(cloud, [bad])
            self.assertIn(flag, err.getvalue() + str(cm.exception), bad)   # a ui.Abort carries its message (cli-parser)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            cli._parse_setup_vars(clouds.get("gcp"), ["region=europe-west1"])
        self.assertEqual(cli._parse_setup_vars(aws, ["name=null"])["unset"], ["name"])   # a saved override can be dropped
        err = io.StringIO()
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(err):     # a typo: refused before any prompt
            cli._parse_setup_vars(aws, ["enable_flow_log=false"])
        self.assertIn("enable_flow_log: not a variable", err.getvalue() + str(cm.exception))

    def test_every_value_cloudseed_sets_is_managed(self):
        """Keys stack_vars computes outside the prompted settings must all be refused (or mapped) as --var."""
        for key, cloud in clouds.CLOUDS.items():
            cfg = {"name": "n", "env": "e", "region": "r", "network_cidr": "10.0.0.0/16", "allowed_ssh_cidrs": [], "tags": {},
                   "ssh_public_key": "k", "owner": "", "workdir": "/w", "platform_prereqs": [], "state": {},
                   "vars": {"project_id": "p", "zone": "r-a", "subscription_id": "s"}}
            owned = set(cloud.stack_vars(cfg)) - {q.key for q in cloud.questions}
            managed = set(cli._managed_vars(cloud, cli._variable_types(key)))
            self.assertEqual(owned - managed, set(), key)
            self.assertFalse(managed & {q.key for q in cloud.questions}, key)     # prompted settings stay settable


# ---------------------------------------------------------------- network

class NetworkTests(unittest.TestCase):
    def test_cidr_values(self):
        for bad in ("garbage", "10.1.2.3/33", "10.0.0.1/16", "fd00::/64", "0.0.0.0/4"):
            self.assertIsNotNone(cli._cidr_problem(bad), bad)
        self.assertIsNone(cli._cidr_problem("10.9.0.0/24"))

    def cfg(self, cidr, **vars_):
        return {"name": "n", "env": "e", "network_cidr": cidr, "vars": vars_, "extra_vars": {}}

    def test_network_sizing_per_cloud(self):
        aws, gcp, azure, vmware = (clouds.get(k) for k in ("aws", "gcp", "azure", "vmware"))
        self.assertTrue(cli._network_problems(aws, self.cfg("10.0.0.0/8")))              # VPC larger than /16
        self.assertFalse(cli._network_problems(aws, self.cfg("10.0.0.0/16")))
        self.assertTrue(cli._network_problems(aws, self.cfg("10.0.0.0/26")))             # /30 subnets
        self.assertTrue(cli._network_problems(aws, self.cfg("10.0.0.0/16", az_count=6)))  # 18 subnets > 16
        c = self.cfg("10.0.0.0/16", az_count=5)
        c["extra_vars"] = {"subnet_newbits": 3, "create_data_subnets": False}           # 10 subnets fit in 8? no
        self.assertTrue(cli._network_problems(aws, c))
        c["extra_vars"] = {"subnet_newbits": 4, "create_data_subnets": False}           # 10 of 16
        self.assertFalse(cli._network_problems(aws, c))
        self.assertTrue(cli._network_problems(azure, self.cfg("10.9.0.0/24")))           # /32 subnets
        self.assertFalse(cli._network_problems(azure, self.cfg("10.9.0.0/16")))
        self.assertTrue(cli._network_problems(azure, self.cfg("10.244.0.0/16", enable_kubernetes=True)))  # AKS pod range
        self.assertTrue(cli._network_problems(gcp, self.cfg("10.9.0.0/28")))
        # GKE master: the default 172.16.0.0/28 is moved out of the network by the GCP adapter (gcp#21), so only an
        # explicit overlapping --var kubernetes_master_cidr is a problem
        self.assertFalse(cli._network_problems(gcp, self.cfg("172.16.0.0/16", enable_kubernetes=True)))
        c = self.cfg("172.16.0.0/16", enable_kubernetes=True)
        c["extra_vars"] = {"kubernetes_master_cidr": "172.16.0.0/28"}
        self.assertTrue(cli._network_problems(gcp, c))
        c = self.cfg("10.9.0.0/16")
        c["extra_vars"] = {"subnet_newbits": 12}
        self.assertTrue(cli._network_problems(gcp, c) == [] and cli._network_problems(azure, c) == [])
        # vmware: the adapter's address plan (VMware.network_problems, a /29 at least; wave2 vmware#9 delegation)
        self.assertTrue(cli._network_problems(vmware, self.cfg("10.1.0.0/29", workload_count=2)))
        self.assertTrue(cli._network_problems(vmware, self.cfg("10.1.0.0/30")))
        self.assertFalse(cli._network_problems(vmware, self.cfg("10.1.0.0/29")))
        self.assertTrue(cli._network_problems(vmware, self.cfg("10.1.0.0/26", enable_kubernetes=True, kubernetes_workers=30)))
        self.assertFalse(cli._network_problems(vmware, self.cfg("10.1.0.0/24", enable_kubernetes=True, kubernetes_workers=3)))

    def test_config_problems(self):
        aws, gcp = clouds.get("aws"), clouds.get("gcp")
        long = {"name": "acme-platform-team-east", "env": "production-blue", "network_cidr": "10.0.0.0/16", "extra_vars": {}}
        self.assertTrue(cli._config_problems(aws, {**long, "vars": {"enable_kubernetes": True}}))
        self.assertFalse(cli._config_problems(aws, {**long, "vars": {"enable_account_baseline": False}}))
        g = {"name": "n", "env": "e", "region": "us-central1", "network_cidr": "10.0.0.0/16", "extra_vars": {}}
        self.assertTrue(cli._config_problems(gcp, {**g, "vars": {"zone": "europe-west1-b"}}))
        self.assertFalse(cli._config_problems(gcp, {**g, "vars": {"zone": "us-central1-b"}}))
        self.assertIsNotNone(cli._region_problem(aws, "narnia"))
        self.assertIsNone(cli._region_problem(aws, "us-gov-west-1"))
        self.assertEqual(cli._normalize_region(clouds.get("azure"), "East US"), "eastus")

    def test_allow_list(self):
        self.assertIsNotNone(cli._allow_list_problem("0.0.0.0/1,128.0.0.0/1"))   # 0.0.0.0/0 in two halves
        self.assertIsNotNone(cli._allow_list_problem(["2001:db8::1"]))
        self.assertIsNone(cli._allow_list_problem("203.0.113.7, 10.0.0.0/8"))
        self.assertEqual(cli._canonical_cidrs(["203.0.113.7", "203.0.113.7/32", "203.0.113.0/24", "198.51.100.1"]),
                         ["198.51.100.1/32", "203.0.113.0/24"])
        self.assertTrue(cli._ip_allowed("203.0.113.9", ["203.0.113.0/24"]))
        self.assertFalse(cli._ip_allowed("192.0.2.1", ["203.0.113.0/24"]))

    def test_fmt_uses_command_line_notation(self):
        self.assertEqual([cli._fmt(v) for v in (True, False, None, [1], {"a": 1}, "t3.micro", 3)],
                         ["true", "false", "null", "[1]", '{"a": 1}', "t3.micro", 3])


# ---------------------------------------------------------------- state migration decision

class WriteRootTests(unittest.TestCase):
    def root(self, backend=None):
        return {"terraform": ({"backend": backend} if backend else {}), "module": {}}

    def test_migration_follows_what_terraform_has_initialised(self):
        d = Path(tempfile.mkdtemp())
        s3 = {"s3": {"bucket": "b1", "key": "k"}}
        self.assertFalse(cli._write_root(d, self.root()))                      # fresh, local
        self.assertFalse(cli._write_root(d, self.root(s3)))                     # fresh, remote: nothing to move
        (d / "terraform.tfstate").write_text(json.dumps({"resources": [{"name": "x"}]}))
        self.assertTrue(cli._write_root(d, self.root(s3)))                      # local state -> remote backend
        self.assertTrue(cli._write_root(d, self.root(s3)))                      # still (a failed init is retried)
        (d / ".terraform").mkdir()
        (d / ".terraform" / "terraform.tfstate").write_text(json.dumps({"backend": {"type": "s3", "config": {"bucket": "b1", "key": "k", "region": None}}}))
        (d / "terraform.tfstate").write_text("")
        self.assertFalse(cli._write_root(d, self.root(s3)))                     # initialised as rendered
        self.assertTrue(cli._write_root(d, self.root({"s3": {"bucket": "b2", "key": "k"}})))
        (d / ".terraform" / "terraform.tfstate").write_text(json.dumps({"backend": {"type": "s3", "config": {
            "bucket": "b1", "key": "k", "use_fips_endpoint": True, "region": None}}}))
        self.assertTrue(cli._write_root(d, self.root(s3)))                      # a key dropped from the render
        self.assertTrue(cli._write_root(d, self.root()))                        # remote -> local
        self.assertEqual(json.loads((d / "main.tf.json").read_text()), self.root())


# ---------------------------------------------------------------- working directories

class WorkdirConflictTests(unittest.TestCase):
    def test_shared_nested_and_foreign_directories_are_refused(self):
        base = Path(tempfile.mkdtemp(prefix="cs-wd-")).resolve()
        other = paths.Env("azure", "fxwd-a", base / "a")
        other.save({"cloud": "azure", "env": "fxwd-a"})
        self.addCleanup(lambda: other.config_path.unlink())
        idx = paths._load_index()
        idx[other.id] = str(other.dir)
        paths._save_index(idx)
        self.addCleanup(lambda: paths._save_index({k: v for k, v in paths._load_index().items() if k != other.id}))
        self.assertIn("already", cli._workdir_conflict(base / "a", "gcp-fxwd-b"))
        self.assertIn("overlaps", cli._workdir_conflict(base / "a" / "sub", "gcp-fxwd-b"))
        self.assertIn("overlaps", cli._workdir_conflict(base, "gcp-fxwd-b"))
        self.assertIsNotNone(cli._workdir_conflict(Path.home().resolve(), "gcp-fxwd-b"))
        self.assertIsNotNone(cli._workdir_conflict(paths.ENVS_DIR.resolve(), "gcp-fxwd-b"))
        (base / "c").mkdir()
        (base / "c" / "config.json").write_text(json.dumps({"cloud": "aws", "env": "zz"}))
        self.assertIn("aws-zz", cli._workdir_conflict(base / "c", "gcp-fxwd-b"))
        self.assertIsNone(cli._workdir_conflict(base / "free", "gcp-fxwd-b"))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            cli._check_owner(paths.Env("gcp", "fxwd-b", base / "a"), other.load())


# ---------------------------------------------------------------- setup flows

class SetupValidationTests(SetupHarness):
    def test_bad_flags_are_refused_before_anything_is_written(self):
        e = self.env("aws", "fx-bad")
        for argv in (["--cidr", "garbage"], ["--cidr", "10.1.2.3/33"], ["--name", "Acme Corp"], ["--region", "narnia"],
                     ["--allow-ip", "0.0.0.0/1,128.0.0.0/1"], ["--allow-ip", "2001:db8::1"], ["--var", "fips_mode=maybe"],
                     ["--var", "az_count=abc"], ["--var", "name=Evil"], ["--var", "nosuch=1"], ["--cidr", "10.0.0.0/8"]):
            rc, out = self.setup("aws", "-y", "--env", "fx-bad", "--allow-ip", "203.0.113.7", "--dry-run", *argv)
            self.assertEqual(rc, 1, (argv, out))
            self.assertFalse(e.dir.exists(), argv)
        rc, out = self.setup("vmware", "-y", "--env", "fx-bad", "--cidr", "banana", "--dry-run")
        self.assertEqual(rc, 1)
        self.assertIn("--cidr", out)

    def test_failed_first_setup_leaves_no_orphan_directory(self):
        e = self.env("gcp", "fx-noproj")
        with mock.patch.dict(os.environ, {k: "" for k in ("GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT")}):
            rc, out = self.setup("gcp", "-y", "--env", "fx-noproj", "--allow-ip", "203.0.113.7", "--state", "local", "--dry-run")
        self.assertEqual(rc, 1, out)
        self.assertFalse(e.dir.exists())
        self.assertNotIn("gcp-fx-noproj", paths._load_index())

    def test_var_values_are_typed(self):
        e = self.env("gcp", "fx-types")
        rc, out = self.setup("gcp", "-y", "--env", "fx-types", "--project-id", "my-proj-1", "--allow-ip", "203.0.113.7",
                             "--state", "local", "--var", "fips_mode=no", "--var", "enable_kubernetes=off",
                             "--var", "kubernetes_version=1.30", "--dry-run")
        self.assertEqual(rc, 0, out)
        cfg = e.load()
        self.assertIs(cfg["vars"]["fips_mode"], False)
        self.assertIs(cfg["vars"]["enable_kubernetes"], False)
        self.assertEqual(cfg["extra_vars"]["kubernetes_version"], "1.30")
        mod = json.loads((e.stack_dir / "main.tf.json").read_text())["module"]["stack"]
        self.assertEqual((mod["fips_mode"], mod["enable_kubernetes"], mod["kubernetes_version"]), (False, False, "1.30"))

    def test_cloudseed_managed_vars_are_refused_with_the_flag(self):
        e = self.env("aws", "fx-cidrvar")
        for var, flag in (("vpc_cidr=10.77.0.0/16", "--cidr"), ('allowed_ssh_cidrs=["203.0.113.0/24"]', "--allow-ip"),
                          ("name=other", "--name")):
            rc, out = self.setup("aws", "-y", "--env", "fx-cidrvar", "--allow-ip", "203.0.113.7", "--var", var, "--dry-run")
            self.assertEqual(rc, 1, out)
            self.assertIn(flag, out)
            self.assertFalse(e.dir.exists())
        rc, out = self.setup("aws", "-y", "--env", "fx-cidrvar", "--allow-ip", "203.0.113.7", "--state", "local",
                             "--cidr", "10.77.0.0/16", "--dry-run")
        self.assertEqual(rc, 0, out)
        mod = json.loads((e.stack_dir / "main.tf.json").read_text())["module"]["stack"]
        self.assertEqual((e.load()["network_cidr"], mod["vpc_cidr"]), ("10.77.0.0/16", "10.77.0.0/16"))


class SetupExistingEnvTests(SetupHarness):
    def create(self, cloud, name, *extra):
        e = self.env(cloud, name)
        base = {"aws": ["--allow-ip", "203.0.113.0/24,198.51.100.7"], "gcp": ["--project-id", "my-proj-1", "--allow-ip", "203.0.113.0/24"]}[cloud]
        rc, out = self.setup(cloud, "-y", "--env", name, "--state", "local", *base, *extra, "--dry-run")
        self.assertEqual(rc, 0, out)
        return e

    def test_rerun_keeps_the_saved_allow_list(self):
        e = self.create("aws", "fx-allow")
        rc, out = self.setup("aws", "-y", "--env", "fx-allow", "--var", "bastion_instance_type=t3.small", "--plan-only")
        self.assertEqual(rc, 0, out)
        cfg = e.load()
        self.assertEqual(cfg["allowed_ssh_cidrs"], ["198.51.100.7/32", "203.0.113.0/24"])
        self.assertEqual(cfg["vars"]["bastion_instance_type"], "t3.small")
        self.assertIn("192.0.2.10 is not in the SSH allow-list", out)
        rc, out = self.setup("aws", "-y", "--env", "fx-allow", "--allow-ip", "192.0.2.10", "--plan-only")
        self.assertEqual(e.load()["allowed_ssh_cidrs"], ["192.0.2.10/32"])   # --allow-ip still replaces it

    def test_dry_run_of_an_existing_env_changes_nothing(self):
        e = self.create("aws", "fx-dry")
        before = (e.config_path.read_bytes(), (e.stack_dir / "main.tf.json").read_bytes())
        rc, out = self.setup("aws", "-y", "--env", "fx-dry", "--var", "enable_kubernetes=true", "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertEqual(before, (e.config_path.read_bytes(), (e.stack_dir / "main.tf.json").read_bytes()))
        preview = json.loads((e.dir / "dry-run" / "stack" / "main.tf.json").read_text())["module"]["stack"]
        self.assertTrue(preview["enable_kubernetes"])

    def test_unconfirmed_or_declined_setup_restores_the_previous_config(self):
        e = self.create("aws", "fx-decline")
        rc, out = self.setup("aws", "-y", "--env", "fx-decline", "--var", "enable_kubernetes=true")
        self.assertEqual(rc, 3, out)
        self.assertIs(e.load()["vars"]["enable_kubernetes"], False)
        self.assertEqual(self.calls("apply"), [])
        with mock.patch.object(ui, "interactive", lambda: True), mock.patch.object(ui, "confirm", lambda q, default=False: False), \
                mock.patch.object(ui, "ask", lambda q, default=None, **kw: default or ""), \
                mock.patch.object(ui, "choose", lambda q, options, default=None: default):
            rc, out = self.setup("aws", "--env", "fx-decline", "--var", "enable_kubernetes=true")
        self.assertEqual(rc, 0, out)
        self.assertIn("keeps its previous configuration", out)
        self.assertIs(e.load()["vars"]["enable_kubernetes"], False)
        rc, out = self.setup("aws", "-y", "--env", "fx-decline", "--var", "enable_kubernetes=true", "--plan-only")
        self.assertIs(e.load()["vars"]["enable_kubernetes"], True)                  # --plan-only saves on purpose

    def test_unconfirmed_switch_to_remote_state_keeps_the_local_state(self):
        e = self.create("aws", "fx-tolocal")
        rc, out = self.setup("aws", "-y", "--env", "fx-tolocal", "--state", "remote")
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.calls("apply"), [])
        self.assertEqual(e.load()["state"], {"type": "local", "backend": None})    # resources are still tracked locally
        self.assertIn("Re-run the same command with --auto-approve", out)

    def test_a_users_key_without_a_private_key_path_is_kept(self):
        key = Path(tempfile.mkdtemp()) / "mykey"                                  # no .pub suffix
        key.write_text(fake_pub("ssh-rsa") + "\n")
        e = self.create("aws", "fx-userkey", "--ssh-public-key", str(key))
        cfg = e.load()
        cfg["ssh_private_key_path"] = None          # older versions saved no private-key path for such a key
        e.save(cfg)
        rc, out = self.setup("aws", "-y", "--env", "fx-userkey", "--plan-only")
        self.assertEqual(rc, 0, out)
        self.assertTrue(e.load()["ssh_public_key"].startswith("ssh-rsa"))

    def test_first_real_setup_after_a_dry_run_is_recorded_as_created(self):
        e = self.create("aws", "fx-created")
        rc, out = self.setup("aws", "-y", "--env", "fx-created", "--auto-approve", "--no-provision")
        self.assertEqual(rc, 0, out)
        self.assertEqual(undo.latest(e.id)["kind"], "created")
        rc, out = self.setup("aws", "-y", "--env", "fx-created", "--var", "enable_vpn=true", "--auto-approve", "--no-provision")
        self.assertEqual(rc, 0, out)
        self.assertEqual(undo.latest(e.id)["kind"], "config")

    def test_retry_after_a_failed_first_apply_is_still_created(self):
        e = self.create("aws", "fx-retry")
        FakeTF.fail_apply = True
        rc, _ = self.setup("aws", "-y", "--env", "fx-retry", "--auto-approve", "--no-provision")
        self.assertEqual(rc, 1)
        FakeTF.fail_apply = False
        rc, out = self.setup("aws", "-y", "--env", "fx-retry", "--auto-approve", "--no-provision")
        self.assertEqual(rc, 0, out)
        self.assertEqual(undo.latest(e.id)["kind"], "created")

    def test_region_and_fips_cannot_change_on_a_deployed_env(self):
        e = self.create("aws", "fx-deployed")
        (e.stack_dir / "terraform.tfstate").write_text(json.dumps({"resources": [{"name": "vpc"}]}))
        before = e.config_path.read_bytes()
        rc, out = self.setup("aws", "-y", "--env", "fx-deployed", "--region", "us-west-2", "--dry-run")
        self.assertEqual(rc, 1)
        self.assertIn("region of an existing environment cannot be changed", out)
        rc, out = self.setup("aws", "-y", "--env", "fx-deployed", "--var", "fips_mode=true", "--dry-run")
        self.assertEqual(rc, 1)
        self.assertIn("FIPS mode cannot be turned on", out)
        self.assertEqual(before, e.config_path.read_bytes())

    def test_saved_legacy_overrides_are_migrated(self):
        e = self.create("aws", "fx-legacy")
        cfg = e.load()
        cfg["extra_vars"] = {"allowed_ssh_cidrs": ["198.51.100.0/24"], "vpc_cidr": "10.77.0.0/16", "tags": {},
                             "kubernetes_version": 1.3, "enable_flow_logs": "no"}
        cfg["vars"]["enable_security_hub"] = "False"
        e.save(cfg)
        rc, out = self.setup("aws", "-y", "--env", "fx-legacy", "--plan-only")
        self.assertEqual(rc, 0, out)
        cfg = e.load()
        self.assertEqual((cfg["network_cidr"], cfg["allowed_ssh_cidrs"]), ("10.77.0.0/16", ["198.51.100.0/24"]))
        self.assertEqual(cfg["extra_vars"], {"kubernetes_version": "1.3", "enable_flow_logs": False})
        self.assertIs(cfg["vars"]["enable_security_hub"], False)
        mod = json.loads((e.stack_dir / "main.tf.json").read_text())["module"]["stack"]
        self.assertEqual(mod["tags"]["ManagedBy"], "cloudseed")

    def test_workdir_cannot_fork_an_existing_env(self):
        e = self.create("aws", "fx-wd")
        target = Path(tempfile.mkdtemp(prefix="cs-fork-")) / "new"
        rc, out = self.setup("aws", "-y", "--env", "fx-wd", "--workdir", str(target), "--dry-run")
        self.assertEqual(rc, 1)
        self.assertIn("already lives in", out)
        self.assertFalse(target.exists())
        self.assertEqual(paths.Env("aws", "fx-wd").dir, e.dir)


class SetupPlanTests(SetupHarness):
    def test_plan_only_on_a_new_remote_env_creates_nothing(self):
        e = self.env("aws", "fx-plan")
        rc, out = self.setup("aws", "-y", "--env", "fx-plan", "--allow-ip", "203.0.113.7", "--plan-only")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.calls("apply"), [])
        self.assertEqual({c[0] for c in self.calls("plan")}, {"bootstrap", "stack"})
        self.assertEqual(e.load()["state"], {"type": "remote", "backend": None})
        self.assertFalse((e.stack_dir / "tfplan").exists() or (e.bootstrap_dir / "tfplan").exists())
        FakeTF.calls = []
        rc, out = self.setup("aws", "-y", "--env", "fx-plan")                      # -y without --auto-approve
        self.assertEqual(rc, 3)
        self.assertEqual(self.calls("apply"), [])
        self.assertIn("--auto-approve", out)
        FakeTF.calls = []
        args = build_parser().parse_args(["apply", "aws", "--env", "fx-plan", "-y", "--auto-approve"])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_apply(args, {}), 0)
        self.assertEqual([c[0] for c in self.calls("apply")], ["bootstrap", "stack"])   # storage first, then the stack
        self.assertEqual(e.load()["state"]["backend"]["s3"]["bucket"], "state-bucket")


class SetupVmwareTests(SetupHarness):
    def test_summary_shows_the_network_prepare_resolved(self):
        e = self.env("vmware", "fx-vmnet")
        vmware = clouds.get("vmware")

        def prepare(cfg, dry_run=False):
            if not dry_run and not cfg.get("cidr_explicit"):
                cfg["network_cidr"] = "192.168.160.0/24"      # VMware's host-only vmnet1

        with mock.patch.object(vmware, "prepare", prepare), mock.patch.object(vmware, "credential_warnings", lambda cfg: []):
            rc, out = self.setup("vmware", "-y", "--env", "fx-vmnet", "--plan-only")
        self.assertEqual(rc, 0, out)
        row = next(line for line in out.splitlines() if "Network CIDR" in line)
        self.assertIn("192.168.160.0/24", row)
        self.assertEqual(e.load()["network_cidr"], "192.168.160.0/24")


class SetupFipsKeyTests(SetupHarness):
    def test_key_type_follows_the_final_fips_answer(self):
        e = self.env("gcp", "fx-fips")
        e.ssh_dir.mkdir(parents=True)                                    # left by an aborted earlier attempt
        (e.ssh_dir / "id_ed25519.pub").write_text(fake_pub("ssh-ed25519"))
        (e.ssh_dir / "id_ed25519").write_text("PRIVATE")
        rc, out = self.setup("gcp", "-y", "--env", "fx-fips", "--project-id", "my-proj-1", "--allow-ip", "203.0.113.7",
                             "--state", "local", "--var", "fips_mode=true", "--dry-run")
        self.assertEqual(rc, 0, out)
        key = e.load()["ssh_public_key"]
        self.assertFalse(key.startswith("ssh-ed25519"))
        self.assertTrue(any(p.name.startswith("id_ed25519.pub.replaced-") for p in e.ssh_dir.iterdir()))

    def test_fips_chosen_at_the_prompt_gets_a_fips_key(self):
        e = self.env("gcp", "fx-fipsprompt")
        answers = lambda q, default=False: True if "FIPS" in q else default   # noqa: E731
        with mock.patch.object(ui, "interactive", lambda: True), mock.patch.object(ui, "confirm", answers), \
                mock.patch.object(ui, "ask", lambda q, default=None, **kw: default or ""), \
                mock.patch.object(ui, "choose", lambda q, options, default=None: default):
            rc, out = self.setup("gcp", "--env", "fx-fipsprompt", "--project-id", "my-proj-1", "--allow-ip", "203.0.113.7",
                                 "--state", "local", "--dry-run")
        self.assertEqual(rc, 0, out)
        cfg = e.load()
        self.assertIs(cfg["vars"]["fips_mode"], True)
        self.assertFalse(cfg["ssh_public_key"].startswith("ssh-ed25519"))

    def test_var_answers_are_not_prompted_again(self):
        e = self.env("aws", "fx-noprompt")
        asked = []
        confirm = lambda q, default=False: asked.append(q) or False   # noqa: E731
        with mock.patch.object(ui, "interactive", lambda: True), mock.patch.object(ui, "confirm", confirm), \
                mock.patch.object(ui, "ask", lambda q, default=None, **kw: default or ""), \
                mock.patch.object(ui, "choose", lambda q, options, default=None: default):
            rc, out = self.setup("aws", "--env", "fx-noprompt", "--allow-ip", "203.0.113.7", "--state", "local", "--advanced",
                                 "--var", "enable_kubernetes=true", "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertFalse([q for q in asked if "Kubernetes" in q and "EKS" in q])
        self.assertIs(e.load()["vars"]["enable_kubernetes"], True)

    def test_fips_rules(self):
        aws = clouds.get("aws")
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": ""}), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            cli._check_fips(aws, {"region": "us-east-1", "vars": {"fips_mode": True}})
            for bad in ({"region": "eu-west-1", "vars": {"fips_mode": True}},
                        {"region": "us-east-1", "vars": {"fips_mode": True, "enable_vpn": True}},      # Ubuntu VPN host: needs Pro
                        {"region": "us-east-1", "ssh_public_key": fake_pub("ssh-ed25519"), "vars": {"fips_mode": True}}):
                with self.assertRaises(SystemExit):
                    cli._check_fips(aws, bad)
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": "t"}), contextlib.redirect_stdout(io.StringIO()):
            cli._check_fips(aws, {"region": "us-east-1", "vars": {"fips_mode": True, "enable_vpn": True, "vpn_type": "openvpn"}})


# ---------------------------------------------------------------- provisioning and read-only commands

class ProvisionTests(SetupHarness):
    def test_missing_hosts_are_errors_and_undo_covers_every_provisioned_host(self):
        e = self.env("vmware", "fx-prov")
        e.save({"cloud": "vmware", "env": "fx-prov", "name": "n", "region": "local", "network_cidr": "10.100.0.0/24",
                "allowed_ssh_cidrs": ["127.0.0.1/32"], "ssh_public_key": fake_pub("ssh-ed25519"), "tags": {},
                "state": {"type": "local", "backend": None}, "vars": {"enable_kubernetes": True}, "extra_vars": {},
                "provisioned": {"bastion": {"harden": False, "firewall": True, "tools": False}}})
        (e.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "10.100.0.2", "kubernetes_control_plane_ips": ["10.100.0.20"]}))
        vmware = clouds.get("vmware")

        def provision(cloud, env, cfg, outputs, label="bastion", sync_only=False, **kw):
            if not sync_only:
                cfg.setdefault("provisioned", {})[label] = {"harden": True, "firewall": True, "tools": True}

        k8s_kw = []

        def k8s(cloud, env, cfg, outputs, limit=None, **kw):
            k8s_kw.append(kw)
            cfg.setdefault("provisioned", {})["kubernetes"] = {"distro": "rke2"}

        err = io.StringIO()
        with mock.patch.object(cli.prov, "provision", provision), mock.patch.object(cli.prov, "provision_local_kubernetes", k8s), \
                mock.patch.object(vmware, "prepare", lambda cfg, dry_run=False: None), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            cfg = e.load()
            with self.assertRaises(SystemExit):
                cli._provision_all(vmware, e, cfg, only="vpn")
            self.assertEqual(cli._provision_all(clouds.get("aws"), e, dict(cfg, cloud="aws"), only="k8s"), [])
            args = build_parser().parse_args(["provision", "vmware", "--env", "fx-prov"])
            self.assertEqual(cli.cmd_provision(args, {}), 0)
            self.assertEqual(k8s_kw[-1].get("harden"), True)                 # --no-harden reaches the k8s nodes (fix/ansible)
            entry = undo.latest(e.id)
            self.assertEqual(entry["kind"], "provision-prev")
            self.assertEqual(entry["data"]["hosts"], {"bastion": {"harden": False, "firewall": True, "tools": False}, "kubernetes": None})
            args = build_parser().parse_args(["provision", "vmware", "--env", "fx-prov", "--sync-only"])
            cli.cmd_provision(args, {})
            self.assertEqual(undo.latest(e.id)["kind"], "info")

            ran = []
            with mock.patch.object(undo, "_run_cli", lambda argv: ran.append(argv)):
                undo.perform({"scope": e.id, "kind": "provision-prev", "summary": "s", "data": entry["data"]}, {}, True)
            self.assertIn(["provision", "vmware", "--env", "fx-prov", "--host", "bastion", "--no-harden", "--no-tools"], ran)
            self.assertIn("--target", ran[1])
            self.assertEqual(ran[1][ran[1].index("--target") + 1], "module.stack.module.kubernetes")
            self.assertNotIn("kubernetes", e.load()["provisioned"])            # the re-created VMs are unprovisioned
            ran.clear()
            with mock.patch.object(undo, "_run_cli", lambda argv: ran.append(argv)):   # legacy entry of --host k8s
                undo.perform({"scope": e.id, "kind": "provision-prev", "summary": "s",
                              "data": {"label": "k8s", "prev": {"distro": "rke2"}}}, {}, True)
            self.assertEqual(ran, [])
        self.assertIn("reverts nothing", undo.describe({"scope": e.id, "kind": "provision-prev", "data": {"label": "k8s", "prev": {"x": 1}}}))

    def test_read_only_commands_do_not_rewrite_a_vmware_config(self):
        e = self.env("vmware", "fx-ro")
        e.save({"cloud": "vmware", "env": "fx-ro", "name": "n", "region": "local", "network_cidr": "10.100.0.0/24",
                "allowed_ssh_cidrs": ["127.0.0.1/32"], "ssh_public_key": "k", "tags": {}, "state": {"type": "local"},
                "vars": {}, "extra_vars": {}})
        before = e.config_path.read_bytes()
        vmware = clouds.get("vmware")

        def prepare(cfg, dry_run=False):
            cfg["vars"].setdefault("base_disk", "/dev/null" if dry_run else "/img/base.vmdk")

        with mock.patch.object(vmware, "prepare", prepare), contextlib.redirect_stdout(io.StringIO()):
            for argv in (["status", "vmware", "--env", "fx-ro"], ["inventory", "vmware", "--env", "fx-ro"]):
                cli._load_env(build_parser().parse_args(argv))
            self.assertEqual(before, e.config_path.read_bytes())
            cli._load_env(build_parser().parse_args(["plan", "vmware", "--env", "fx-ro"]))
        self.assertEqual(e.load()["vars"]["base_disk"], "/img/base.vmdk")         # real host facts are still saved


if __name__ == "__main__":
    unittest.main()
