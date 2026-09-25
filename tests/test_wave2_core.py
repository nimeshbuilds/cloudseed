"""Regression tests for the wave-2 core items: working-directory safety, the per-environment lock, environment ids and
identity tags, enumerated answers, the bundle's Terraform tree, Terraform hints, sensitive outputs, the fail-closed
re-plan check, quoted known_hosts paths and YAML-keyword login names. Stdlib only; no network, no cloud."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import netutil, paths, tf, ui  # noqa: E402
from cloudseed import clouds  # noqa: E402
from cloudseed.clouds import base  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_RUN = uuid.uuid4().hex[:4]   # per test run: a reused CLOUDSEED_HOME never hands back an earlier run's environment


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        yield out, err


def _cfg(cloud="aws", env="w2", **kw):
    cfg = {"cloud": cloud, "env": env, "name": "cs", "region": "us-east-1", "network_cidr": "10.9.0.0/16",
           "allowed_ssh_cidrs": ["203.0.113.7/32"], "owner": "alice", "tags": {}, "vars": {}, "state": {"type": "local"}}
    cfg.update(kw)
    return cfg


class _EnvCase(unittest.TestCase):
    """Each test gets its own environment ids and forgets the workdirs.json entries it made."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w2core-"))
        self.index_before = paths._load_index()
        self.made: list = []

    def tearDown(self):
        paths._save_index(self.index_before)
        for e in self.made:
            if str(e.dir).startswith(str(paths.ENVS_DIR)):
                shutil.rmtree(e.dir, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, cloud="aws", name=None, workdir=None):
        name = name or f"w2{len(self.made)}{_RUN}"
        e = paths.Env(cloud, name, workdir)
        self.made.append(e)
        return e


# ---------------------------------------------------------------- working directories (cli-lifecycle#1, #9)

class WorkdirSafetyTests(_EnvCase):
    def test_home_cloudseed_home_checkout_and_their_parents_are_refused(self):
        e = self.env()
        home = self.tmp / "home"
        (home / "Documents").mkdir(parents=True)
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            for target in (home, home.parent, paths.HOME, paths.HOME.parent, paths.REPO_ROOT, paths.REPO_ROOT.parent,
                           Path("/")):
                with self.subTest(target=target):
                    self.assertIsNotNone(paths.workdir_problem(target, e.id))
                    with self.assertRaises(ui.Abort):
                        e.set_workdir(target)
            self.assertNotIn(e.id, paths._load_index(), "a refused directory is never remembered")
            self.assertTrue((home / "Documents").is_dir())

    def test_inside_cloudseed_home_only_its_own_default(self):
        e = self.env()
        self.assertIsNone(paths.workdir_problem(paths.ENVS_DIR / e.id, e.id))
        self.assertIn("inside cloudseed's own directory", paths.workdir_problem(paths.HOME / "elsewhere", e.id))
        self.assertIsNotNone(paths.workdir_problem(paths.ENVS_DIR, e.id))

    def test_non_empty_directory_with_someone_elses_files_is_refused(self):
        e = self.env()
        project = self.tmp / "project"
        (project / "src").mkdir(parents=True)
        (project / "important.txt").write_text("precious")
        project.chmod(0o755)
        problem = paths.workdir_problem(project, e.id)
        self.assertIn("not empty", problem)
        self.assertIn("important.txt", problem)
        with self.assertRaises(ui.Abort):
            e.set_workdir(project)
        self.assertEqual(stat.S_IMODE(project.stat().st_mode), 0o755, "never made private")
        self.assertEqual((project / "important.txt").read_text(), "precious")

    def test_another_environments_directory_is_refused(self):
        other = self.env(name="w2other")
        other.set_workdir(self.tmp / "other")
        other.save(_cfg(env="w2other"))
        e = self.env()
        self.assertIn("aws-w2other", paths.workdir_problem(self.tmp / "other", e.id))
        with self.assertRaises(ui.Abort):
            e.set_workdir(self.tmp / "other")

    def test_new_empty_or_own_directory_is_accepted(self):
        e = self.env()
        for target in (self.tmp / "new" / "deep", self.tmp / "empty"):
            if target.name == "empty":
                target.mkdir()
                (target / ".DS_Store").write_text("")      # Finder debris does not make a directory "used"
            with self.subTest(target=target):
                self.assertIsNone(paths.workdir_problem(target, e.id))
        # a directory holding only cloudseed's own files (a setup of this env that created stack/, ssh/, logs/)
        own = self.tmp / "own"
        for name in ("stack", "ssh", "logs"):
            (own / name).mkdir(parents=True)
        self.assertIsNone(paths.workdir_problem(own, e.id))
        e.set_workdir(own)
        e.save(_cfg(env=e.name))
        self.assertEqual(paths._load_index()[e.id], str(own.resolve()))
        e.set_workdir(own)          # the same directory again: fine (it holds this environment)

    def test_create_dirs_keeps_the_mode_of_a_directory_the_user_made(self):
        mine = self.tmp / "made-by-user"
        mine.mkdir()
        mine.chmod(0o755)
        e = self.env(workdir=mine)
        e.create_dirs()
        self.assertEqual(stat.S_IMODE(mine.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(e.ssh_dir.stat().st_mode), 0o700, "ssh/ is always private")
        fresh = self.env(workdir=self.tmp / "fresh")
        fresh.create_dirs()
        self.assertEqual(stat.S_IMODE(fresh.dir.stat().st_mode), 0o700, "a directory cloudseed creates is private")
        default = self.env()
        default.create_dirs()
        default.dir.chmod(0o755)
        default.create_dirs()
        self.assertEqual(stat.S_IMODE(default.dir.stat().st_mode), 0o700, "cloudseed's own default stays private")


class SharedWorkdirTests(_EnvCase):
    """Older versions let two environments share a directory: gcp-sb overwrote azure-sa's config.json."""

    def setUp(self):
        super().setUp()
        self.shared = self.tmp / "shared"
        self.gcp = self.env("gcp", "w2sb", self.shared)
        self.gcp.create_dirs()
        self.gcp.save(_cfg("gcp", "w2sb"))
        self.azure = self.env("azure", "w2sa")
        index = paths._load_index()
        index.update({self.gcp.id: str(self.shared.resolve()), self.azure.id: str(self.shared.resolve())})
        paths._save_index(index)
        self.azure = paths.Env("azure", "w2sa")

    def test_list_all_shows_the_directory_once(self):
        ids = [e.id for e in paths.Env.list_all()]
        self.assertIn(self.gcp.id, ids)
        self.assertNotIn(self.azure.id, ids)

    def test_the_other_id_cannot_load_it(self):
        with self.assertRaises(paths.ConfigError) as cm:
            self.azure.load()
        msg = str(cm.exception)
        self.assertIn("gcp-w2sb", msg)
        self.assertIn(str(paths.WORKDIRS_INDEX), msg)
        cfg, problem = self.azure.try_load()
        self.assertEqual(cfg, {})
        self.assertIn("not of azure-w2sa", problem)
        self.assertEqual(self.gcp.load()["env"], "w2sb")          # the owner is unaffected

    def test_a_config_without_cloud_and_env_still_loads(self):
        e = self.env()
        e.create_dirs()
        e.config_path.write_text(json.dumps({"name": "x"}))
        self.assertEqual(e.load(), {"name": "x"})


# ---------------------------------------------------------------- the per-environment lock (webui-backend#14)

HOLDER = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
from cloudseed import paths
env = paths.Env("aws", sys.argv[2])
with env.lock("apply aws --env " + sys.argv[2]):
    print("held", flush=True)
    sys.stdin.readline()
"""

NESTED = r"""
import sys
sys.path.insert(0, sys.argv[1])
from cloudseed import paths
try:
    with paths.Env("aws", sys.argv[2]).lock("nested"):
        print("nested ok", flush=True)
except paths.EnvBusy as e:
    print(e)
    sys.exit(3)
"""


class EnvLockTests(_EnvCase):
    def spawn(self, name):
        env = dict(os.environ, CLOUDSEED_HOME=str(paths.HOME))
        env.pop(paths.LOCK_ENV_VAR, None)
        p = subprocess.Popen([sys.executable, "-c", HOLDER, str(ROOT), name], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, text=True, env=env)
        self.assertEqual(p.stdout.readline().strip(), "held")

        def done():
            if not p.stdin.closed:
                p.stdin.close()
            p.wait(10)
            p.stdout.close()
        self.addCleanup(done)
        return p

    def test_a_second_process_is_refused_with_the_holder_named(self):
        e = self.env()
        p = self.spawn(e.name)
        with self.assertRaises(paths.EnvBusy) as cm, e.lock("destroy"):
            pass
        msg = str(cm.exception)
        self.assertIn(f"{e.id} is busy", msg)
        self.assertIn(f"apply aws --env {e.name}", msg)
        self.assertIn(str(p.pid), msg)
        self.assertIsInstance(cm.exception, ui.Abort)          # the CLI prints it like any refusal
        p.stdin.close()
        p.wait(10)
        with e.lock("destroy"):                                # released when the holder ends
            self.assertEqual(e.lock_holder().get("action"), "destroy")

    def test_a_crashed_holder_never_leaves_it_locked(self):
        e = self.env()
        p = self.spawn(e.name)
        p.kill()
        p.wait(10)
        with e.lock("setup"):
            pass

    def test_reentrant_in_the_thread_but_exclusive_between_threads(self):
        e = self.env()
        seen = []
        with e.lock("setup"):
            with e.lock("provision"):                          # setup running provision in-process
                seen.append("nested")

            def other():
                try:
                    with e.lock("apply"):
                        seen.append("other got it")
                except paths.EnvBusy:
                    seen.append("other busy")
            t = threading.Thread(target=other)
            t.start()
            t.join(10)
        self.assertEqual(seen, ["nested", "other busy"])
        self.assertNotIn(e.id, os.environ.get(paths.LOCK_ENV_VAR, ""))

    def test_cloudseed_processes_started_under_the_lock_may_use_it(self):
        e = self.env()
        with e.lock("setup"):
            self.assertIn(f"{e.id}={os.getpid()}", os.environ.get(paths.LOCK_ENV_VAR, ""))
            out = subprocess.run([sys.executable, "-c", NESTED, str(ROOT), e.name], capture_output=True, text=True,
                                 env=dict(os.environ, CLOUDSEED_HOME=str(paths.HOME)), timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("nested ok", out.stdout)
        # a forged/stale variable does not let a process past someone else's lock
        p = self.spawn(e.name)
        forged = dict(os.environ, CLOUDSEED_HOME=str(paths.HOME), **{paths.LOCK_ENV_VAR: f"{e.id}=1"})
        out = subprocess.run([sys.executable, "-c", NESTED, str(ROOT), e.name], capture_output=True, text=True,
                             env=forged, timeout=30)
        self.assertEqual(out.returncode, 3, out.stderr)
        self.assertIn(f"{e.id} is busy", out.stdout)
        p.stdin.close()
        p.wait(10)

    def test_wait_gives_the_other_run_time_to_finish(self):
        e = self.env()
        p = self.spawn(e.name)
        threading.Timer(0.5, p.stdin.close).start()
        with e.lock("apply", wait=15):
            pass


# ---------------------------------------------------------------- environment id and identity tags (aws#4)

class IdentityTagTests(_EnvCase):
    def test_a_new_environment_gets_a_uid_once(self):
        e = self.env()
        cfg = _cfg(env=e.name)
        e.save(cfg)
        uid = e.load()["uid"]
        self.assertRegex(uid, r"^[0-9a-f]{16}$")
        again = e.load()
        again["region"] = "us-west-2"
        e.save(again)
        self.assertEqual(e.load()["uid"], uid, "kept on later saves")
        e.save(_cfg(env=e.name))                        # even when a caller rebuilds the dict
        self.assertNotIn("uid", e.load(), "an existing environment never gets a new id (it would retag everything)")

    def test_tags_carry_the_id_and_cloudseeds_identity_wins(self):
        aws = clouds.get("aws")
        cfg = _cfg(uid="abc123", tags={"team": "x", "managedby": "terraform", "CloudseedEnv": "aws-prod",
                                       "cloudseedenvid": "zzz", "Owner": "platform"})
        tags = aws.tags(cfg)
        self.assertEqual(tags["CloudseedEnvId"], "abc123")
        self.assertEqual(tags["ManagedBy"], "cloudseed")
        self.assertEqual(tags["CloudseedEnv"], "aws-w2")
        self.assertEqual(tags["team"], "x")
        self.assertEqual(tags["Owner"], "platform")            # not an identity tag: a --tag may set it
        self.assertFalse({"managedby", "cloudseedenvid"} & set(tags))
        self.assertNotIn("CloudseedEnvId", aws.tags(_cfg()), "old environments keep their tags")
        labels = clouds.get("gcp").tags(_cfg("gcp", uid="abc123"))
        self.assertEqual(labels.get("cloudseedenvid"), "abc123")
        from cloudseed import reconcile
        exp = reconcile.expected_tags("aws", cfg)
        self.assertEqual(reconcile.ownership(tags, exp)[0], "mine")
        self.assertEqual(reconcile.ownership({**tags, "CloudseedEnvId": "other"}, exp)[0], "other")

    def test_identity_tags_are_refused_as_tags_and_saved_ones_can_be_dropped(self):
        aws = clouds.get("aws")
        for key in ("ManagedBy", "cloudseedenv", "CloudseedEnvId"):
            self.assertIn("set by cloudseed", aws.tag_problem(key, "x"))
        problems = aws.check_config(_cfg(tags={"bad": "${oops}", "ManagedBy": "tf"}))
        self.assertTrue(any("--tag bad=" in p and "(to drop a saved tag: --tag bad=)" in p for p in problems), problems)
        self.assertTrue(any("ManagedBy" in p for p in problems), problems)
        # `--tag KEY=` empties a saved tag: not rendered, so not refused - the way out of a tag an old version saved
        self.assertEqual(aws.check_config(_cfg(tags={"bad": "", "ManagedBy": ""})), [])
        self.assertNotIn("bad", aws.tags(_cfg(tags={"bad": ""})))


# ---------------------------------------------------------------- enumerated answers (webui-visual#28)

class ChoicesTests(unittest.TestCase):
    Q = base.Question("vpn_type", "VPN type", "openvpn", choices=("openvpn", "tailscale"))

    def test_only_the_choices_are_accepted(self):
        self.assertEqual(self.Q.coerce("tailscale"), "tailscale")
        self.assertEqual(self.Q.coerce(" TailScale "), "tailscale")      # canonical spelling
        self.assertIn("openvpn, tailscale", self.Q.problem("wireguard"))
        self.assertIsNone(self.Q.problem(""))                             # blank still means "the default"

    def test_choices_run_before_validate_and_through_collect_vars(self):
        seen = []
        q = base.Question("distro", "Distro", "rke2", choices=("rke2", "kubeadm"),
                          validate=lambda v: seen.append(v) or None)
        self.assertEqual(q.coerce("KUBEADM"), "kubeadm")
        self.assertEqual(seen, ["kubeadm"])

        class Target(base.Cloud):
            key = "w2t"
            questions = [q]
        with mock.patch.object(ui, "interactive", return_value=False), quiet(), self.assertRaises(ui.Abort) as cm:
            Target().collect_vars(SimpleNamespace(), {}, {}, False, overrides={"distro": "k3s"})
        self.assertIn("--var distro", str(cm.exception))
        with mock.patch.object(ui, "interactive", return_value=False), quiet():
            out = Target().collect_vars(SimpleNamespace(), {}, {}, False, overrides={"distro": "Kubeadm"})
        self.assertEqual(out["distro"], "kubeadm")


# ---------------------------------------------------------------- the bundle's Terraform tree (aws#28, ops#9)

class BundleTreeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="cs-bundle-"))
        src = self.root / "bundle" / "terraform"
        (src / "aws" / ".terraform" / "providers").mkdir(parents=True)
        (src / "aws" / ".terraform" / "providers" / "huge-binary").write_bytes(b"\0" * 4096)
        (src / "aws" / "main.tf").write_text('variable "x" {}\n')
        (src / "aws" / ".terraform.lock.hcl").write_text("# lock\n")
        (src / "aws" / "terraform.tfstate").write_text("{}")
        (src / "aws" / "terraform.tfstate.backup").write_text("{}")
        (src / "aws" / "tfplan").write_text("plan")
        self.src = src
        self.home = self.root / "home"
        self.patches = [mock.patch.object(paths, "IS_BUNDLE", True), mock.patch.object(paths, "REPO_ROOT", self.root / "bundle"),
                        mock.patch.object(paths, "HOME", self.home), mock.patch.object(paths, "ENVS_DIR", self.home / "envs"),
                        mock.patch.object(paths, "BIN_DIR", self.home / "bin")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    def test_only_the_modules_are_copied_and_the_digest_ignores_debris(self):
        digest = paths._tree_digest(self.src)
        (self.src / "aws" / ".terraform.lock.hcl").write_text("# another lock\n")
        (self.src / "aws" / ".terraform" / "providers" / "huge-binary").write_bytes(b"\1")
        self.assertEqual(paths._tree_digest(self.src), digest, "provider caches/locks never change the digest")
        dst = paths.tf_root()
        self.assertEqual(dst, self.home / "terraform" / digest)
        self.assertTrue((dst / "aws" / "main.tf").is_file())
        for gone in (".terraform", ".terraform.lock.hcl", "terraform.tfstate", "terraform.tfstate.backup", "tfplan"):
            self.assertFalse((dst / "aws" / gone).exists(), gone)
        self.assertEqual([p.name for p in dst.parent.iterdir()], [digest], "no temporary copies left behind")
        self.assertEqual(paths.tf_root(), dst)
        (self.src / "aws" / "main.tf").write_text('variable "y" {}\n')
        self.assertNotEqual(paths.tf_root(), dst, "changed modules get a new tree")

    def test_a_half_copy_is_replaced(self):
        digest = paths._tree_digest(self.src)
        half = self.home / "terraform" / digest
        (half / "aws").mkdir(parents=True)            # Ctrl-C during an older version's copytree
        dst = paths.tf_root()
        self.assertEqual(dst, half)
        self.assertTrue((dst / "aws" / "main.tf").is_file())
        self.assertEqual(sorted(p.name for p in dst.parent.iterdir()), [digest])

    def test_a_failed_copy_leaves_nothing_under_the_final_name(self):
        with mock.patch.object(paths.shutil, "copytree", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                paths.tf_root()
        self.assertEqual(list((self.home / "terraform").iterdir()), [])


# ---------------------------------------------------------------- Terraform hints, outputs, re-plan check

class HintTests(unittest.TestCase):
    def test_dependency_violation(self):
        for text in ("Error: deleting EC2 Subnet (subnet-0abc): DependencyViolation: The subnet 'subnet-0abc' has "
                     "dependencies and cannot be deleted.",
                     "Error: waiting for Deleting Network: The network resource 'projects/p/global/networks/n' is "
                     "already being used by 'projects/p/global/firewalls/k8s-fw-a1'",
                     "code: InUseSubnetCannotBeDeleted"):
            with self.subTest(text=text[:40]):
                msg = tf.explain(text, "destroy")
                self.assertIn("still uses the network", msg)
                self.assertIn("re-run the destroy", msg)

    def test_azure_subscription_singletons(self):
        msg = tf.explain("Error: the pricing tier of this subscription is not Free - ImportAsExistsError", "apply")
        self.assertIn("Defender for Cloud is already enabled", msg)
        self.assertIn("--var enable_defender=false", msg)
        sub = "0f0e0d0c-0000-1111-2222-333344445555"
        msg = tf.explain(f'Error: A resource with the ID "/subscriptions/{sub}/providers/Microsoft.MarketplaceOrdering/'
                         'agreements/canonical/offers/0001-com-ubuntu-pro-jammy-fips/plans/pro-fips-22_04-gen2" '
                         "already exists - to be managed via Terraform this resource needs to be imported", "apply")
        self.assertIn("image terms are already accepted", msg)
        self.assertIn(f"/subscriptions/{sub}/providers/Microsoft.MarketplaceOrdering", msg)
        self.assertNotIn("A resource with the same name already exists", msg)

    def test_gcp_api_and_identity_pool(self):
        err = ("Error: Error creating Network: googleapi: Error 403: Compute Engine API has not been used in project "
               "123456789012 before or it is disabled. Enable it by visiting https://console.developers.google.com/"
               "apis/api/compute.googleapis.com/overview?project=123456789012 then retry.\nDetails:\n"
               '[{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED"}]')
        msg = tf.explain(err, "apply")
        self.assertIn("gcloud services enable compute.googleapis.com --project 123456789012", msg)
        msg = tf.explain('Error: googleapi: Error 403: Cloud Resource Manager API ... "service": '
                         '"cloudresourcemanager.googleapis.com", "reason": "SERVICE_DISABLED"', "apply")
        self.assertIn("enable cloudresourcemanager.googleapis.com --project <project>", msg)
        msg = tf.explain("Error 400: Identity Pool does not exist (my-proj-1.svc.id.goog). Please check", "apply")
        self.assertIn("my-proj-1.svc.id.goog", msg)
        self.assertIn("re-run the same setup/apply", msg)

    def test_hints_stay_three_tuples_and_the_generic_entry_stays_last(self):
        self.assertTrue(all(len(h) == 3 for h in tf.HINTS))      # troubleshoot unpacks (pattern, what, fix)
        self.assertIn("already ?exists?", tf.HINTS[-1][0])
        self.assertNotRegex(tf.HINTS[-1][0], r"(^|\|)Conflict(\||$)")


def _bare_tf(run):
    t = tf.Terraform.__new__(tf.Terraform)
    t.workdir, t.binary = Path(tempfile.mkdtemp()), "terraform"
    t.run = run
    return t


class OutputsTests(unittest.TestCase):
    def test_sensitive_outputs_are_redacted_unless_asked_for(self):
        raw = {"bastion_public_ip": {"value": "198.51.100.4", "sensitive": False, "type": "string"},
               "admin_password": {"value": "hunter2hunter2", "sensitive": True, "type": "string"}}
        t = _bare_tf(lambda *a, **k: subprocess.CompletedProcess(a, 0, json.dumps(raw), ""))
        self.assertEqual(t.outputs(), {"bastion_public_ip": "198.51.100.4", "admin_password": "<sensitive>"})
        self.assertEqual(t.outputs(sensitive=True)["admin_password"], "hunter2hunter2")
        bad = _bare_tf(lambda *a, **k: subprocess.CompletedProcess(a, 0, "[]", ""))
        self.assertEqual(bad.outputs(), {})


class ReplanCheckTests(unittest.TestCase):
    def test_an_unreadable_plan_after_adoption_is_never_applied(self):
        applies = []

        def run(*args, capture=False, check=True):
            if args[0] == "apply":
                applies.append(args)
                return subprocess.CompletedProcess(args, 1, "Error: x already exists\n  with aws_iam_role.r,", "")
            if args[0] == "show":
                return subprocess.CompletedProcess(args, 1 if len(applies) > 0 and t.plan.called else 0, "{}", "")
            return subprocess.CompletedProcess(args, 0, "{}", "")
        t = _bare_tf(run)
        (t.workdir / "tfplan").write_text("approved")
        t.plan = mock.Mock()
        approve = mock.Mock()
        with mock.patch("cloudseed.reconcile.planned_values", return_value={}), \
                mock.patch("cloudseed.reconcile.recover", return_value=["aws_iam_role.r"]), quiet(), \
                self.assertRaises(tf.TerraformError) as cm:
            t.apply_reconciled("aws", {}, approve=approve)
        self.assertIn("could not be read", str(cm.exception))
        approve.assert_not_called()
        self.assertEqual(len(applies), 1, "nothing applied after the adoption")

    def test_deleting_reports_unreadable_plans(self):
        t = _bare_tf(lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "boom"))
        self.assertIsNone(t._deleting("tfplan"))
        plan = {"resource_changes": [{"address": "a.b", "change": {"actions": ["delete", "create"]}},
                                     {"address": "c.d", "change": {"actions": ["update"]}}]}
        t = _bare_tf(lambda *a, **k: subprocess.CompletedProcess(a, 0, json.dumps(plan), ""))
        self.assertEqual(t._deleting("tfplan"), {"a.b"})


# ---------------------------------------------------------------- ssh options and login names

class SshOptionTests(unittest.TestCase):
    def test_known_hosts_path_with_a_space_is_one_file(self):
        with tempfile.TemporaryDirectory() as td:
            e = paths.Env("vmware", "kh", Path(td) / "work  dir" / "vmware-kh")
            opts = e.ssh_options()
            self.assertIn(f'UserKnownHostsFile="{e.known_hosts_path()}"', opts)
            if shutil.which("ssh"):
                # ssh reads the quoted value as one file; unquoted it splits it at the spaces into two files, which
                # `ssh -G` prints joined by ONE space - so the double space shows which way it was read
                p = subprocess.run(["ssh", "-G", *opts, "example.invalid"], capture_output=True, text=True, timeout=20)
                line = next((ln for ln in p.stdout.splitlines() if ln.startswith("userknownhostsfile ")), "")
                self.assertEqual(line, f"userknownhostsfile {e.known_hosts_path()}")


class LoginNameTests(unittest.TestCase):
    def test_yaml_keywords_are_refused_on_every_cloud(self):
        for name in ("yes", "No", "TRUE", "false", "on", "Off", "null"):
            with self.subTest(name=name):
                self.assertIn("YAML keyword", netutil.validate_login_username(name))
        for name in ("yessir", "nobody2", "onboard", "john.doe", "Admin"):
            self.assertIsNone(netutil.validate_login_username(name), name)
        gcp = clouds.get("gcp")
        self.assertIn("YAML", gcp.value_problem(gcp.question("ssh_username"), "yes", {"region": "us-central1"}))


if __name__ == "__main__":
    unittest.main()
