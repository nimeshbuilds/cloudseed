"""Regression tests for the environment lifecycle commands: destroy (gates, --select/--target, --purge, vmware sweep,
Kubernetes drain), update-ip, status, ssh argument handling, apply's undo, inventory, list and doctor output.
Stdlib only; Terraform, kubectl, vmrun and ssh are faked - nothing touches a cloud, a hypervisor or the network."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, cli, clouds, localvm, paths, services, ui, undo  # noqa: E402
from cloudseed.clouds.vmware import VMware  # noqa: E402

_counter = [0]
# a random token per test run: a CLOUDSEED_HOME reused across runs keeps earlier environments' state (undo journal,
# logs, the workdirs index), and pid-derived names repeat between runs
RUN_ID = uuid.uuid4().hex[:4]


def _legacy_workdir(env: paths.Env, path: Path) -> None:
    """Register `path` as env's working directory the way versions before paths.workdir_problem did (they took over a
    non-empty directory, or even the home directory): destroy must still treat such directories safely."""
    index = paths._load_index()
    index[env.id] = str(Path(path).resolve())
    paths._save_index(index)
    env.dir = Path(path).resolve()
    env._layout()
    env.create_dirs()


def _taken(name: str) -> bool:
    """Whether this CLOUDSEED_HOME already knows an environment called `name` (any target) or with that id: its
    directory, a custom working directory or undo history. A home reused across runs (CLOUDSEED_HOME set by the caller)
    keeps earlier runs' environments, and a later run whose pid-derived names repeat must not pick one up."""
    ids = set(paths._load_index()) | set(undo._load())
    try:
        ids.update(p.name for p in paths.ENVS_DIR.iterdir())
    except OSError:
        pass
    return any(i == name or i.endswith("-" + name) for i in ids)


def _uid(prefix: str) -> str:
    while True:
        _counter[0] += 1
        name = f"{prefix}{RUN_ID}x{_counter[0]}"
        if not _taken(name):
            return name


def _cp(rc: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], rc, out, err)


class FakeTF:
    """Stands in for tf.Terraform. Class attributes describe the scenario; every instance logs to `calls`."""
    state: list | None = []          # None: no state file yet; a list: `terraform state list`
    state_error = ""                 # non-empty: `state list` fails with this output
    changes: list | None = []        # resource_changes of the saved plan (None: `show -json tfplan` fails)
    targeted_changes: list | None = None
    outputs_value: dict = {}
    apply_error = False
    calls: list = []

    def __init__(self, workdir):
        self.workdir = Path(workdir)

    @classmethod
    def reset(cls, **kw):
        cls.state, cls.state_error, cls.changes, cls.targeted_changes = [], "", [], None
        cls.outputs_value, cls.apply_error, cls.calls = {}, False, []
        for k, v in kw.items():
            setattr(cls, k, v)

    def init(self, migrate=False, backend=True):
        FakeTF.calls.append(("init",))

    def run(self, *args, capture=False, check=True):
        if args[:2] == ("state", "list"):
            if FakeTF.state_error:
                return _cp(1, "", FakeTF.state_error)
            if FakeTF.state is None:
                return _cp(1, "", "No state file was found!")
            return _cp(0, "\n".join(FakeTF.state) + "\n")
        if args[:2] == ("show", "-json") and len(args) > 2:
            ch = FakeTF.changes
            if FakeTF.targeted_changes is not None and self._last_targets:
                ch = FakeTF.targeted_changes
            if ch is None:
                return _cp(1, "", "cannot read plan")
            return _cp(0, json.dumps({"resource_changes": ch}))
        if args[:2] == ("show", "-json"):
            return _cp(0, json.dumps({"values": {"root_module": {"resources": []}}}))
        return _cp(0)

    _last_targets: tuple = ()

    def plan(self, out="tfplan", destroy=False, targets=()):
        FakeTF.calls.append(("plan", destroy, tuple(targets)))
        FakeTF._last_targets = tuple(targets)
        (self.workdir / out).parent.mkdir(parents=True, exist_ok=True)
        (self.workdir / out).write_text("plan")

    def apply(self, planfile=None, auto_approve=False, targets=()):
        FakeTF.calls.append(("apply", planfile))
        if FakeTF.apply_error:
            raise cli.TerraformError("terraform apply failed")
        FakeTF.state = []

    def plan_for_apply(self, cloud_key, cfg, out="tfplan", targets=(), render=None):   # core: adopt singletons, then the reviewed plan
        self.plan(out, targets=targets)

    def apply_reconciled(self, cloud_key, cfg, targets=(), rounds=3, planfile="tfplan", approve=None, render=None):
        FakeTF.calls.append(("apply_reconciled",))

    def outputs(self):
        return dict(FakeTF.outputs_value)

    def state_list(self):
        return list(FakeTF.state or [])

    def validate(self):
        pass


def _raises(msg: str):
    def f(*a, **k):
        raise ui.Abort(msg)
    return f


def _names(calls, kind):
    return [c for c in calls if c[0] == kind]


class LifeBase(unittest.TestCase):
    cloud = "aws"

    def setUp(self):
        FakeTF.reset()
        self.env_name = _uid("lf")
        self.env = paths.Env(self.cloud, self.env_name)
        self.env.create_dirs()
        self.cfg = {"cloud": self.cloud, "env": self.env_name, "name": "cloudseed", "region": "us-east-1",
                    "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["198.51.100.7/32"],
                    "state": {"type": "local", "backend": None}, "vars": {}, "extra_vars": {}, "tags": {},
                    "ssh_public_key": "ssh-ed25519 AAAA test"}
        self.env.save(self.cfg)
        (self.env.ssh_dir / "id_ed25519").write_text("PRIVATE KEY")
        self.patches = [mock.patch.object(cli, "Terraform", FakeTF),
                        mock.patch.object(cli, "_render", lambda *a, **k: False),
                        mock.patch.object(VMware, "prepare", lambda self, cfg, dry_run=False: None),
                        mock.patch.object(localvm, "detect_host", lambda: None)]
        for p in self.patches:
            p.start()
        self.interactive = mock.patch.object(ui, "interactive", return_value=False)
        self.interactive.start()
        self.out = io.StringIO()

    def tearDown(self):
        for p in self.patches + [self.interactive]:
            p.stop()
        log = audit._state.get("log")
        if log:   # the per-command log _load_env opened (cli.main closes it; direct cmd_* calls do not)
            log.close()
            audit._state.update(log=None, env=None)

    def run_cmd(self, fn, argv, settings=None):
        args = cli.build_parser().parse_args(argv)
        with contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            try:
                return fn(args, settings if settings is not None else {})
            except SystemExit as e:  # ui.Abort: quiet when raised, shown once by the dispatcher - do the same here
                if isinstance(e, ui.Abort):
                    ui.show_abort(e)
                return e.code

    def destroy(self, *extra, settings=None):
        return self.run_cmd(cli.cmd_destroy, ["destroy", self.cloud, "--env", self.env_name, *extra], settings)


# ---------------------------------------------------------------- destroy: confirmation gates

class DestroyGateTests(LifeBase):
    def test_non_interactive_without_auto_approve_is_a_preview(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this", "module.stack.module.bastion.aws_instance.bastion"])
        (self.env.dir / "outputs.json").write_text('{"bastion_public_ip": "192.0.2.10"}')
        rc = self.destroy("-y")
        self.assertEqual(rc, 3)
        self.assertEqual(_names(FakeTF.calls, "apply"), [])
        self.assertIn("Nothing destroyed", self.out.getvalue())
        self.assertFalse((self.env.stack_dir / "tfplan").exists())
        self.assertTrue(self.env.exists())
        self.assertTrue((self.env.dir / "outputs.json").exists())

    def test_non_interactive_preview_does_not_purge(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        self.assertEqual(self.destroy("--purge"), 3)
        self.assertTrue(self.env.exists())

    def test_auto_approve_destroys_and_clears_the_output_cache(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        (self.env.dir / "outputs.json").write_text('{"bastion_public_ip": "192.0.2.10", "kubernetes_cluster_name": ""}')
        self.env.known_hosts_path().write_text("192.0.2.10 ssh-ed25519 AAAA\n")
        rc = self.destroy("-y", "--auto-approve")
        self.assertEqual(rc, 0)
        self.assertEqual(len(_names(FakeTF.calls, "apply")), 1)
        self.assertFalse((self.env.dir / "outputs.json").exists())
        self.assertFalse(self.env.known_hosts_path().exists())
        self.assertEqual(undo.latest(self.env.id)["kind"], "recreate")

    def test_interactive_asks_for_the_typed_env_id(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        with mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "require_typed", side_effect=_raises("Confirmation did not match.")) as typed:
            rc = self.destroy()
        self.assertEqual(rc, 1)
        typed.assert_called_once()
        self.assertEqual(_names(FakeTF.calls, "apply"), [])
        self.assertFalse((self.env.stack_dir / "tfplan").exists())

    def test_unreadable_state_is_an_error_not_an_empty_env(self):
        FakeTF.reset(state_error="Error: No valid credential sources found")
        with self.assertRaises(cli.TerraformError) as cm:   # main() turns it into exit 1 plus the explained error
            self.destroy("-y", "--auto-approve", "--purge")
        self.assertIn("AWS credentials", str(cm.exception))
        self.assertTrue(self.env.exists(), "the purge must not run when the state could not be read")
        self.assertEqual(_names(FakeTF.calls, "plan"), [])

    def test_empty_state_without_purge_records_no_undo(self):
        FakeTF.reset(state=None)
        before = len(undo.entries(self.env.id))
        self.assertEqual(self.destroy("-y", "--auto-approve"), 0)
        self.assertEqual(len(undo.entries(self.env.id)), before)


# ---------------------------------------------------------------- destroy --select / --target

class SelectTests(LifeBase):
    def test_parse_selection_rejects_bad_input(self):
        for raw in ("4-3", "0", "1-0", "0-2", "9", "5-100", "x", "3-2,5", ""):
            picked, problem = cli._parse_selection(raw, 7)
            self.assertIsNotNone(problem, raw)
            self.assertEqual(picked, [], raw)
        self.assertEqual(cli._parse_selection("1,3,5-6", 7), ([1, 3, 5, 6], None))

    def test_select_reasks_until_valid(self):
        resources = ["module.stack.module.bastion.aws_instance.bastion", "module.stack.module.network.aws_vpc.this"]
        with mock.patch.object(ui, "ask", side_effect=["0", "4-3", "3"]) as ask, \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            picked = cli._select_targets(resources)
        self.assertEqual(ask.call_count, 3)
        self.assertEqual(picked, ["module.stack.module.bastion.aws_instance.bastion"])

    def test_empty_target_is_a_usage_error(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        self.assertEqual(self.destroy("--target", "", "--auto-approve"), 2)
        self.assertEqual(_names(FakeTF.calls, "plan"), [])


class TargetTests(LifeBase):
    STATE = ["module.stack.module.bastion.aws_instance.bastion", "module.stack.module.bastion.aws_eip.bastion",
             "module.stack.module.network.aws_vpc.this", "module.stack.module.security_baseline[0].aws_guardduty_detector.this"]

    def test_typo_destroys_nothing(self):
        FakeTF.reset(state=list(self.STATE))
        rc = self.destroy("--target", "module.stack.module.bastionn", "-y", "--auto-approve")
        self.assertEqual(rc, 1)
        self.assertEqual(_names(FakeTF.calls, "plan"), [])
        self.assertIn("did you mean", self.out.getvalue())

    def test_unknown_targets_are_skipped_and_the_rest_destroyed(self):
        FakeTF.reset(state=list(self.STATE), changes=[
            {"address": "module.stack.module.bastion.aws_instance.bastion", "type": "aws_instance", "mode": "managed", "change": {"actions": ["delete"]}}])
        self.env.known_hosts_path().write_text("192.0.2.10 ssh-ed25519 AAAA\n")
        rc = self.destroy("--target", "module.stack.module.nothere,module.stack.module.bastion.aws_instance.bastion", "-y", "--auto-approve")
        self.assertEqual(rc, 0)
        self.assertEqual(_names(FakeTF.calls, "plan")[0][2], ("module.stack.module.bastion.aws_instance.bastion",))
        self.assertIn("Destroyed 1 resource(s)", self.out.getvalue())
        self.assertFalse(self.env.known_hosts_path().exists(), "a targeted destroy must forget the host keys too")

    def test_module_and_indexed_targets_match(self):
        self.assertTrue(cli._address_in_state("module.stack.module.security_baseline", self.STATE))
        self.assertTrue(cli._address_in_state("module.stack.module.security_baseline[0]", self.STATE))
        self.assertTrue(cli._address_in_state("module.stack.module.network.aws_vpc.this", self.STATE))
        self.assertFalse(cli._address_in_state("module.stack.module.net", self.STATE))

    def test_zero_deletes_is_reported_not_celebrated(self):
        FakeTF.reset(state=list(self.STATE), changes=[])
        before = len(undo.entries(self.env.id))
        rc = self.destroy("--target", "module.stack.module.bastion", "-y", "--auto-approve")
        self.assertEqual(rc, 1)
        self.assertEqual(_names(FakeTF.calls, "apply"), [])
        self.assertEqual(len(undo.entries(self.env.id)), before)
        self.assertNotIn("destroyed", self.out.getvalue().lower().replace("nothing to destroy", ""))

    def test_non_interactive_targeted_destroy_needs_auto_approve(self):
        FakeTF.reset(state=list(self.STATE), changes=[
            {"address": "module.stack.module.bastion.aws_eip.bastion", "type": "aws_eip", "mode": "managed", "change": {"actions": ["delete"]}}])
        self.assertEqual(self.destroy("--target", "module.stack.module.bastion", "-y"), 3)
        self.assertEqual(_names(FakeTF.calls, "apply"), [])

    def test_empty_state_is_nothing_to_do(self):
        FakeTF.reset(state=None)
        self.assertEqual(self.destroy("--target", "module.stack.module.bastion", "-y", "--auto-approve"), 0)


# ---------------------------------------------------------------- destroy --purge

class PurgeTests(LifeBase):
    def test_custom_workdir_keeps_unrelated_files(self):
        root = Path(tempfile.mkdtemp(prefix="cs-purge-"))
        wd = root / "project"
        wd.mkdir()
        (wd / "important.txt").write_text("precious")
        (wd / "src").mkdir()
        (wd / "src" / "main.py").write_text("print(1)")
        env = paths.Env(self.cloud, self.env_name)
        _legacy_workdir(env, wd)          # set_workdir now refuses a directory holding someone else's files
        env.save(dict(self.cfg))
        (env.ssh_dir / "id_ed25519").write_text("PRIVATE KEY")
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        self.assertEqual(self.destroy("-y", "--auto-approve", "--purge"), 0)
        self.assertEqual((wd / "important.txt").read_text(), "precious")
        self.assertTrue((wd / "src" / "main.py").exists())
        for gone in ("config.json", "ssh", "stack", "logs", "inventory.json"):
            self.assertFalse((wd / gone).exists(), gone)
        self.assertNotIn(env.id, paths._load_index())

    def test_default_workdir_is_removed_and_keys_live_with_the_undo_entry(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        settings = {"current_env": self.env.id}
        with mock.patch.object(paths, "save_settings"):
            self.assertEqual(self.destroy("-y", "--auto-approve", "--purge", settings=settings), 0)
        self.assertFalse(self.env.dir.exists())
        self.assertNotIn("current_env", settings)
        keep = paths.HOME / "logs" / "purged" / self.env.id
        self.assertFalse((keep / "ssh").exists(), "private keys must not be kept in the audit copy")
        entry = undo.latest(self.env.id)
        self.assertEqual(entry["kind"], "recreate")
        backup = Path(entry["data"]["backup_dir"])
        self.assertTrue(str(backup).startswith(str(undo.BACKUPS)))
        self.assertEqual((backup / "ssh" / "id_ed25519").read_text(), "PRIVATE KEY")
        undo.clear(self.env.id)
        self.assertFalse(backup.exists(), "the keys go when the undo entry goes")

    def test_protected_directory_is_never_cleared(self):
        home = Path(tempfile.mkdtemp(prefix="cs-home-"))
        (home / "Documents").mkdir()
        (home / "Documents" / "taxes.txt").write_text("x")
        env = paths.Env(self.cloud, self.env_name)
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            _legacy_workdir(env, home)    # set_workdir now refuses the home directory
            env.save(dict(self.cfg))
            FakeTF.reset(state=None)
            self.assertEqual(self.destroy("-y", "--auto-approve", "--purge"), 0)
            self.assertTrue((home / "Documents" / "taxes.txt").exists())
            self.assertTrue(home.exists())
            self.assertFalse((home / "config.json").exists())
        self.assertIn("delete them yourself", self.out.getvalue())

    def test_kept_state_storage_is_named_and_its_record_preserved(self):
        self.env.bootstrap_dir.mkdir(parents=True, exist_ok=True)
        (self.env.bootstrap_dir / "main.tf.json").write_text("{}")
        (self.env.bootstrap_dir / "terraform.tfstate").write_text(json.dumps(
            {"resources": [{"type": "aws_s3_bucket"}], "outputs": {"bucket": {"value": "cs-state-abc123"}}}))
        FakeTF.reset(state=None)
        self.assertEqual(self.destroy("-y", "--auto-approve", "--purge"), 0)
        out = self.out.getvalue()
        self.assertIn("cs-state-abc123 kept", out)
        keep = paths.HOME / "logs" / "purged" / self.env.id / "bootstrap"
        self.assertTrue((keep / "terraform.tfstate").exists())

    def test_purge_state_without_storage_says_so(self):
        cfg = dict(self.cfg, state={"type": "local", "backend": None})
        self.env.save(cfg)
        FakeTF.reset(state=None)
        self.assertEqual(self.destroy("-y", "--auto-approve", "--purge-state"), 0)
        self.assertIn("no record of state storage", self.out.getvalue())

    def test_never_deployed_purge_does_not_undo_into_a_setup(self):
        FakeTF.reset(state=None)
        self.assertEqual(self.destroy("-y", "--auto-approve", "--purge"), 0)
        entry = undo.latest(self.env.id)
        self.assertEqual(entry["kind"], "restore-files")


# ---------------------------------------------------------------- vmware teardown

class VmwareSweepTests(LifeBase):
    cloud = "vmware"

    def _bundle(self, d: Path, name: str) -> Path:
        b = d / f"{name}.vmwarevm"
        b.mkdir(parents=True)
        (b / f"{name}.vmx").write_text("x")
        return b

    def test_only_this_environments_vms_are_swept(self):
        vm_dir = Path(tempfile.mkdtemp(prefix="cs-vms-")) / "Virtual Machines.localized"
        vm_dir.mkdir()
        mine = [self._bundle(vm_dir, f"cloudseed-{self.env_name}-{s}") for s in ("bastion", "vm1", "cp1", "wk2")]
        other_env = self._bundle(vm_dir, f"cloudseed-{self.env_name}-2-bastion")
        user_vm = self._bundle(vm_dir, "Windows 11")
        (vm_dir / "notes.txt").write_text("keep me")
        cfg = dict(self.cfg, vars={"vm_dir": str(vm_dir)})
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return _cp(0, "Total running VMs: 1\n" + str(user_vm / "Windows 11.vmx") + "\n")
        host = {"found": True, "vmrun": "/fake/vmrun", "product": "fusion"}
        with mock.patch.object(localvm, "detect_host", lambda: host), mock.patch.object(cli.subprocess, "run", fake_run), \
                mock.patch.object(localvm, "remove_vmnet", return_value=False), \
                mock.patch.object(localvm, "stop_vmrest") as stop, \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            cli._destroy_local_leftovers(self.env, cfg, purge=True)
        deleted = [c[c.index("deleteVM") + 1] for c in calls if "deleteVM" in c]
        self.assertEqual(sorted(Path(d).parent.name for d in deleted), sorted(b.name for b in mine))
        self.assertFalse(any("stop" in c for c in calls), "the user's running VM must not be stopped")
        for b in mine:
            self.assertFalse(b.exists())
        self.assertTrue(other_env.exists())
        self.assertTrue(user_vm.exists())
        self.assertTrue((vm_dir / "notes.txt").exists())
        self.assertTrue(vm_dir.exists(), "a user-chosen vm_dir is never removed")
        stop.assert_not_called()

    def test_vmrest_is_stopped_only_when_this_home_manages_it_and_nothing_runs(self):
        host = {"found": True, "vmrun": "/fake/vmrun", "product": "fusion"}
        with mock.patch.object(localvm, "detect_host", lambda: host), \
                mock.patch.object(cli.subprocess, "run", lambda cmd, **kw: _cp(0, "Total running VMs: 0\n")), \
                mock.patch.object(localvm, "remove_vmnet", return_value=False), \
                mock.patch.object(localvm, "_port_open", return_value=True), \
                mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [])), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            with mock.patch.object(localvm, "load_creds", return_value=None), mock.patch.object(localvm, "stop_vmrest") as stop:
                cli._destroy_local_leftovers(self.env, self.cfg, purge=True)
                stop.assert_not_called()
            with mock.patch.object(localvm, "load_creds", return_value={"user": "u", "password": "p"}), \
                    mock.patch.object(localvm, "stop_vmrest", return_value=True) as stop:
                cli._destroy_local_leftovers(self.env, self.cfg, purge=True)
                stop.assert_called_once()

    def test_teardown_prepare_never_fetches_the_base_image(self):
        with mock.patch.object(localvm, "require_host", return_value={"found": True}), \
                mock.patch.object(localvm, "ensure_vmrest", return_value={"user": "u", "password": "p"}), \
                mock.patch.object(localvm, "ensure_image", side_effect=AssertionError("image download")), \
                mock.patch.dict(os.environ, {}):
            cli._prepare_local_teardown()
            self.assertEqual(os.environ.get("VMREST_USER"), "u")

    def test_destroy_with_resources_uses_the_teardown_prepare(self):
        FakeTF.reset(state=["module.stack.module.bastion.vmdesktop_vm.bastion"])
        with mock.patch.object(cli, "_prepare_local_teardown") as prep, \
                mock.patch.object(VMware, "prepare", side_effect=AssertionError("full prepare")):
            # _load_env's dry-run prepare is part of every command; patch it back for this call only
            with mock.patch.object(cli, "_load_env", lambda args: (clouds.get("vmware"), self.env, dict(self.cfg))):
                self.assertEqual(self.destroy("-y", "--auto-approve"), 0)
        prep.assert_called_once()

    def test_update_ip_is_not_applicable_and_touches_nothing(self):
        with mock.patch.object(cli, "_load_env", side_effect=AssertionError("must not load/prepare the env")):
            rc = self.run_cmd(cli.cmd_update_ip, ["update-ip", "vmware", "--env", self.env_name, "-y", "--auto-approve"])
        self.assertEqual(rc, 0)
        self.assertIn("does not apply to vmware", self.out.getvalue())
        self.assertFalse(cli._touches_vms(cli.build_parser().parse_args(["update-ip", "vmware"])))


# ---------------------------------------------------------------- Kubernetes drain and kubeconfig cleanup

class DrainTests(LifeBase):
    def test_only_eks_and_gke_are_drained(self):
        self.assertTrue(cli._needs_cluster_drain(clouds.get("aws"), {"kubernetes_cluster_name": "c"}))
        self.assertTrue(cli._needs_cluster_drain(clouds.get("gcp"), {"kubernetes_cluster_name": "c"}))
        self.assertFalse(cli._needs_cluster_drain(clouds.get("azure"), {"kubernetes_cluster_name": "c"}))
        self.assertFalse(cli._needs_cluster_drain(clouds.get("vmware"), {"kubernetes_cluster_name": "c"}))
        self.assertFalse(cli._needs_cluster_drain(clouds.get("aws"), {}))

    def test_drain_order_and_waits(self):
        log = []
        seq = {"nodeclaims": [["nodeclaim.karpenter.sh/a"], []], "svc": 0, "pv": 0}

        def fake_run(cmd, **kw):
            args = cmd[1:]
            log.append(args)
            if args[:2] == ["get", "namespaces"]:
                return _cp(0, "namespace/default\n")
            if args[:2] == ["get", "crd"]:
                return _cp(0, "customresourcedefinition.apiextensions.k8s.io/nodepools.karpenter.sh\n"
                              "customresourcedefinition.apiextensions.k8s.io/gateways.gateway.networking.k8s.io\n")
            if args[:2] == ["get", "nodeclaims.karpenter.sh"]:
                return _cp(0, "\n".join(seq["nodeclaims"].pop(0)) if seq["nodeclaims"] else "")
            if args[:2] == ["get", "svc"]:
                seq["svc"] += 1
                items = [{"spec": {"type": "LoadBalancer"}, "metadata": {"namespace": "envoy", "name": "gw"}},
                         {"spec": {"type": "ClusterIP"}, "metadata": {"namespace": "x", "name": "y"}}] if seq["svc"] == 1 else []
                return _cp(0, json.dumps({"items": items}))
            if args[:2] == ["get", "pv"]:
                seq["pv"] += 1
                items = [{"metadata": {"name": "pv-1"}, "spec": {"persistentVolumeReclaimPolicy": "Delete",
                                                                  "claimRef": {"namespace": "data", "name": "db"}}}] if seq["pv"] <= 2 else []
                return _cp(0, json.dumps({"items": items}))
            if args[:2] == ["get", "pods"]:
                return _cp(0, json.dumps({"items": [{"metadata": {"namespace": "data", "name": "db-0"},
                                                     "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": "db"}}]}}]}))
            return _cp(0)
        with mock.patch.object(services, "ensure_kubeconfig", return_value=Path("/tmp/kc")), \
                mock.patch.object(cli.deps, "find", return_value="/fake/kubectl"), \
                mock.patch.object(cli.subprocess, "run", fake_run), mock.patch.object(cli, "_DRAIN_POLL", 0), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            cli._drain_cluster_for_destroy(clouds.get("aws"), self.env, self.cfg, {"kubernetes_cluster_name": "c"})
        deletes = [a for a in log if a[0] == "delete"]
        kinds = [a[1] for a in deletes]
        self.assertLess(kinds.index("nodepools.karpenter.sh"), kinds.index("gateways.gateway.networking.k8s.io"))
        self.assertLess(kinds.index("gateways.gateway.networking.k8s.io"), kinds.index("svc"))
        self.assertIn(["delete", "svc", "-n", "envoy", "gw", "--wait=false"], deletes)
        self.assertNotIn("y", [a[4] for a in deletes if a[1] == "svc"])
        self.assertIn(["delete", "pvc", "-n", "data", "db", "--ignore-not-found", "--wait=false"], deletes)
        self.assertIn(["delete", "pod", "-n", "data", "db-0", "--wait=false"], deletes)

    def test_unreachable_cluster_never_blocks(self):
        with mock.patch.object(services, "ensure_kubeconfig", side_effect=_raises("no tunnel")), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            cli._drain_cluster_for_destroy(clouds.get("gcp"), self.env, self.cfg, {"kubernetes_cluster_name": "c"})
        self.assertIn("not reachable", self.out.getvalue())

    def test_full_destroy_drains_before_apply(self):
        FakeTF.reset(state=["module.stack.module.kubernetes[0].aws_eks_cluster.this"],
                     outputs_value={"kubernetes_cluster_name": "cloudseed-x-eks"})
        order = []
        with mock.patch.object(cli, "_drain_cluster_for_destroy", lambda *a: order.append("drain")), \
                mock.patch.object(FakeTF, "apply", lambda self, *a, **k: order.append("apply")):
            self.assertEqual(self.destroy("-y", "--auto-approve"), 0)
        self.assertEqual(order, ["drain", "apply"])

    def test_kubeconfig_entries_of_the_destroyed_cluster_are_removed(self):
        target = Path(tempfile.mkdtemp()) / "config"
        target.write_text("x")
        theirs = {"current-context": "aws-dev", "contexts": [{"name": "aws-dev", "context": {"cluster": "arn:c", "user": "arn:u"}},
                                                            {"name": "mine", "context": {"cluster": "other", "user": "me"}}],
                  "clusters": [{"name": "arn:c"}, {"name": "other"}], "users": [{"name": "arn:u"}, {"name": "me"}]}
        log = []

        def fake_run(cmd, **kw):
            log.append(cmd[2:])
            return _cp(0, json.dumps(theirs)) if cmd[2] == "view" else _cp(0)
        names = {"contexts": {"aws-dev"}, "clusters": {"arn:c"}, "users": {"arn:u"}}
        with mock.patch.object(cli.subprocess, "run", fake_run), contextlib.redirect_stdout(self.out):
            cli._drop_kubeconfig_entries("/fake/kubectl", target, names, "aws-dev")
        ops = [c[:2] for c in log if c[0] != "view"]
        self.assertIn(["delete-context", "aws-dev"], ops)
        self.assertIn(["delete-cluster", "arn:c"], ops)
        self.assertIn(["delete-user", "arn:u"], ops)
        self.assertIn(["unset", "current-context"], ops)
        self.assertFalse(any("mine" in c or "other" in c or "me" in c for c in ops))


# ---------------------------------------------------------------- update-ip

class UpdateIpTests(LifeBase):
    RULE_OLD = {"address": 'module.stack.module.bastion.aws_vpc_security_group_ingress_rule.ssh["198.51.100.7/32"]',
                "type": "aws_vpc_security_group_ingress_rule", "mode": "managed", "change": {"actions": ["delete"]}}
    RULE_NEW = {"address": 'module.stack.module.bastion.aws_vpc_security_group_ingress_rule.ssh["203.0.113.9/32"]',
                "type": "aws_vpc_security_group_ingress_rule", "mode": "managed", "change": {"actions": ["create"]}}

    def update_ip(self, *extra):
        return self.run_cmd(cli.cmd_update_ip, ["update-ip", self.cloud, "--env", self.env_name, "--allow-ip", "203.0.113.9", *extra])

    def saved(self):
        return self.env.load()["allowed_ssh_cidrs"]

    def test_failed_plan_leaves_the_config_alone_and_the_retry_applies(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        rendered = []
        with mock.patch.object(cli, "_render", lambda cloud, env, cfg: rendered.append(list(cfg["allowed_ssh_cidrs"])) or False), \
                mock.patch.object(FakeTF, "plan", side_effect=cli.TerraformError("terraform plan failed: AWS credentials are missing")):
            with self.assertRaises(cli.TerraformError), contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
                cli.cmd_update_ip(cli.build_parser().parse_args(["update-ip", "aws", "--env", self.env_name, "--allow-ip", "203.0.113.9", "--auto-approve"]), {})
        self.assertEqual(self.saved(), ["198.51.100.7/32"])
        self.assertEqual(rendered[-1], ["198.51.100.7/32"], "the rendered root must go back to the applied sources")
        self.assertFalse((self.env.stack_dir / "tfplan").exists())
        FakeTF.reset(state=["module.stack.aws_vpc.this"], changes=[self.RULE_OLD, self.RULE_NEW])
        self.assertEqual(self.update_ip("--auto-approve"), 0)
        self.assertEqual(self.saved(), ["203.0.113.9/32"])
        self.assertEqual(len(_names(FakeTF.calls, "apply")), 1)

    def test_preview_then_approve_really_applies(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"], changes=[self.RULE_OLD, self.RULE_NEW])
        self.assertEqual(self.update_ip("-y"), 3)
        self.assertEqual(self.saved(), ["198.51.100.7/32"])
        self.assertEqual(_names(FakeTF.calls, "apply"), [])
        self.assertEqual(self.update_ip("-y", "--auto-approve"), 0)
        self.assertEqual(self.saved(), ["203.0.113.9/32"])
        self.assertEqual(undo.latest(self.env.id)["kind"], "config")

    def test_no_changes_needs_no_approval(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"], changes=[])
        self.assertEqual(self.update_ip("-y"), 0)
        self.assertEqual(_names(FakeTF.calls, "apply"), [])
        self.assertEqual(self.saved(), ["203.0.113.9/32"])

    def test_unrelated_pending_changes_are_left_out(self):
        other = {"address": "module.stack.module.network.aws_nat_gateway.this[0]", "type": "aws_nat_gateway", "mode": "managed",
                 "change": {"actions": ["create"]}}
        FakeTF.reset(state=["module.stack.aws_vpc.this"], changes=[self.RULE_OLD, self.RULE_NEW, other],
                     targeted_changes=[self.RULE_OLD, self.RULE_NEW])
        self.assertEqual(self.update_ip("--auto-approve"), 0)
        plans = _names(FakeTF.calls, "plan")
        self.assertEqual(set(plans[-1][2]), {self.RULE_OLD["address"], self.RULE_NEW["address"]})
        self.assertEqual(len(_names(FakeTF.calls, "apply")), 1)

    def test_refuses_to_smuggle_unrelated_changes_under_auto_approve(self):
        other = {"address": "module.stack.aws_kms_key.this", "type": "aws_kms_key", "mode": "managed", "change": {"actions": ["update"]}}
        FakeTF.reset(state=["module.stack.aws_vpc.this"], changes=[self.RULE_NEW, other], targeted_changes=[self.RULE_NEW, other])
        self.assertEqual(self.update_ip("--auto-approve"), 1)
        self.assertEqual(_names(FakeTF.calls, "apply"), [])
        self.assertEqual(self.saved(), ["198.51.100.7/32"])

    def test_never_applied_env_is_refused(self):
        FakeTF.reset(state=None)
        self.assertEqual(self.update_ip("--auto-approve"), 1)
        self.assertEqual(self.saved(), ["198.51.100.7/32"])

    def test_same_address_is_nothing_to_do(self):
        rc = self.run_cmd(cli.cmd_update_ip, ["update-ip", "aws", "--env", self.env_name, "--allow-ip", "198.51.100.7"])
        self.assertEqual(rc, 0)
        self.assertIn("nothing to do", self.out.getvalue())

    def test_recovery_steps_when_ssh_still_fails(self):
        cfg = dict(self.cfg, provisioned={"bastion": {"at": "2026-01-01"}})
        (self.env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "192.0.2.10", "bastion_instance_id": "i-0abc"}))
        with mock.patch.object(cli.subprocess, "run", return_value=_cp(255)), mock.patch.object(cli.time, "sleep"), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            cli._check_bastion_ssh(clouds.get("aws"), self.env, cfg, ["203.0.113.9/32"])
        out = self.out.getvalue()
        self.assertIn("aws ssm send-command", out)
        self.assertIn("i-0abc", out)
        self.assertIn("nft add element inet filter ssh_allowed", out)


class HostFirewallTests(LifeBase):
    def test_cloud_hosts_leave_ssh_sources_to_the_cloud_firewall(self):
        (self.env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "192.0.2.10", "vpn_public_ip": "192.0.2.11",
                                                               "vpn_type": "openvpn"}))
        seen = []
        with mock.patch.object(cli.prov, "provision", lambda *a, **kw: seen.append(kw)), contextlib.redirect_stdout(self.out):
            cli._provision_all(clouds.get("aws"), self.env, self.cfg)
        self.assertEqual(len(seen), 2)
        for kw in seen:
            self.assertEqual(kw["extra_vars"]["allowed_ssh_cidrs"], [])
            self.assertTrue(kw["extra_vars"]["ssh_open_any"])


# ---------------------------------------------------------------- status

class StatusTests(LifeBase):
    def test_unreadable_state_is_not_reported_as_never_applied(self):
        FakeTF.reset(state_error="Error: No valid credential sources found")
        (self.env.dir / "outputs.json").write_text('{"bastion_public_ip": "192.0.2.10"}')
        rc = self.run_cmd(cli.cmd_status, ["status", "aws", "--env", self.env_name])
        out = self.out.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("unknown", out)
        self.assertIn("AWS credentials", out)
        self.assertIn("cs doctor aws", out)
        self.assertNotIn("not applied yet", out)
        self.assertNotIn(f"cs setup aws --env {self.env_name}\n", out)
        self.assertTrue((self.env.dir / "outputs.json").exists())

    def test_empty_state_heals_a_stale_output_cache(self):
        FakeTF.reset(state=None)
        (self.env.dir / "outputs.json").write_text('{"bastion_public_ip": "192.0.2.10"}')
        self.assertEqual(self.run_cmd(cli.cmd_status, ["status", "aws", "--env", self.env_name]), 0)
        self.assertFalse((self.env.dir / "outputs.json").exists())
        self.assertIn("not applied yet", self.out.getvalue())

    def test_resource_count_ignores_data_sources(self):
        FakeTF.reset(state=["data.aws_caller_identity.me", "module.stack.aws_vpc.this", "module.stack.module.x.data.aws_ami.al"])
        self.run_cmd(cli.cmd_status, ["status", "aws", "--env", self.env_name])
        self.assertRegex(self.out.getvalue(), r"Resources in state\s+1\b")


# ---------------------------------------------------------------- k8s info / vpn status wording

class PendingFeatureTests(LifeBase):
    def test_k8s_info_for_an_enabled_but_unapplied_cluster(self):
        self.env.save(dict(self.cfg, vars={"enable_kubernetes": True}))
        (self.env.dir / "outputs.json").write_text("{}")
        self.run_cmd(cli.cmd_k8s, ["k8s", "info", "aws", "--env", self.env_name])
        out = self.out.getvalue()
        self.assertIn("enabled in the configuration", out)
        self.assertNotIn("--var enable_kubernetes=true", out)

    def test_vpn_status_and_errors_for_an_enabled_but_unapplied_vpn(self):
        cfg = dict(self.cfg, vars={"enable_vpn": True, "enable_kubernetes": True})
        with contextlib.redirect_stdout(self.out):
            services.status(self.env, cfg, {})
        self.assertIn("not created yet", self.out.getvalue())
        self.assertNotIn("enable with --var", self.out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(ui.Abort) as cm:
                services.vpn_host(clouds.get("aws"), self.env, cfg, {})
            self.assertIn("not created yet", cm.exception.msg)
            with self.assertRaises(ui.Abort) as cm:
                services.kubeconfig_command("aws", cfg, {})
            self.assertIn("not created yet", cm.exception.msg)


# ---------------------------------------------------------------- apply's undo entry

class ApplyUndoTests(LifeBase):
    def test_first_apply_records_a_full_destroy(self):
        FakeTF.reset(state=None)
        created = [f"module.stack.aws_thing.r{i}" for i in range(70)]

        def after_apply(self_, *a, **k):
            FakeTF.state = created + ["data.aws_region.current"]
        with mock.patch.object(FakeTF, "apply_reconciled", after_apply), mock.patch.object(cli, "_finish", lambda *a: None):
            self.assertEqual(self.run_cmd(cli.cmd_apply, ["apply", "aws", "--env", self.env_name, "--auto-approve"]), 0)
        self.assertEqual(undo.latest(self.env.id)["kind"], "created")

    def test_later_apply_targets_every_created_resource(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this", "data.aws_region.current"])
        created = [f"module.stack.module.k8s.aws_thing.r{i}" for i in range(55)]

        def after_apply(self_, *a, **k):
            FakeTF.state = ["module.stack.aws_vpc.this", "data.aws_region.current", "module.stack.module.k8s.data.aws_ami.x"] + created
        with mock.patch.object(FakeTF, "apply_reconciled", after_apply), mock.patch.object(cli, "_finish", lambda *a: None):
            self.assertEqual(self.run_cmd(cli.cmd_apply, ["apply", "aws", "--env", self.env_name, "--auto-approve"]), 0)
        argv = undo.latest(self.env.id)["data"]["argv"]
        targets = [argv[i + 1] for i, a in enumerate(argv) if a == "--target"]
        self.assertEqual(targets, created)


# ---------------------------------------------------------------- ssh argument handling

class SshArgTests(LifeBase):
    def test_split_value_options(self):
        split = cli._split_ssh_args
        self.assertEqual(split(["--", "-F", "cfg", "uptime"]), (["-F", "cfg"], ["uptime"]))
        self.assertEqual(split(["-c", "aes128-ctr", "uname", "-a"]), (["-c", "aes128-ctr"], ["uname", "-a"]))
        self.assertEqual(split(["-E", "log", "x"]), (["-E", "log"], ["x"]))
        self.assertEqual(split(["-p2222", "-vL", "8080:h:80", "ls"]), (["-p2222", "-vL", "8080:h:80"], ["ls"]))
        self.assertEqual(split(["-N", "-T", "-e", "none"]), (["-N", "-T", "-e", "none"], []))
        self.assertEqual(split(["-o", "BatchMode=yes", "--", "ls", "-la"]), (["-o", "BatchMode=yes"], ["ls", "-la"]))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(ui.Abort):
            split(["--env", "dev"])

    def test_env_forms_after_the_cloud(self):
        for toks, env, rest in ((["--env=dz", "--", "-e", "none"], "dz", ["--", "-e", "none"]),
                                (["-edz", "uptime"], "dz", ["uptime"]),
                                (["-e", "dz"], "dz", []),
                                (["uptime", "--env", "x"], None, ["uptime", "--env", "x"])):
            a = cli.build_parser().parse_args(["ssh", "aws"])
            a.ssh_args = list(toks)
            cli._pull_env_from_remainder(a, "ssh_args")
            self.assertEqual((a.env, a.ssh_args), (env, rest), toks)

    def test_separator_right_after_the_cloud_is_kept(self):
        (self.env.dir / "outputs.json").write_text('{"bastion_public_ip": "203.0.113.5"}')
        captured = {}
        with mock.patch.object(cli.subprocess, "call", lambda cmd, **kw: captured.setdefault("cmd", cmd) and 255), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            before = len(undo.entries(self.env.id))
            rc = cli.main(["ssh", "aws", "--env", self.env_name, "--", "-e", "none", "-F", "cfg", "uptime"])
        cmd = captured["cmd"]
        dest = next(i for i, a in enumerate(cmd) if "@203.0.113.5" in a)
        self.assertEqual(cmd[dest - 4:dest], ["-e", "none", "-F", "cfg"])
        self.assertEqual(cmd[dest + 1:], ["uptime"])
        self.assertEqual(rc, 255)
        self.assertEqual(len(undo.entries(self.env.id)), before, "ssh exit 255 means the command never ran: no undo entry")

    def test_env_equals_form_targets_that_env(self):
        (self.env.dir / "outputs.json").write_text('{"bastion_public_ip": "203.0.113.6"}')
        captured = {}
        with mock.patch.object(cli.subprocess, "call", lambda cmd, **kw: captured.setdefault("cmd", cmd) and 0), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            cli.main(["ssh", "aws", f"--env={self.env_name}"])
        self.assertTrue(captured["cmd"][-1].endswith("@203.0.113.6"))
        self.assertNotIn(f"--env={self.env_name}", captured["cmd"])


# ---------------------------------------------------------------- output polish: inventory, list, doctor

class OutputTests(LifeBase):
    def test_inventory_hides_helpers_and_keeps_identifiers_whole(self):
        vmx = "/Users/someone/.cloudseed/envs/vmware-e2e/vms/cloudseed-e2e-cp1.vmwarevm/cloudseed-e2e-cp1.vmx"
        inv = audit.load(self.env)
        inv["current"] = {"updated_at": "now", "count": 3, "resources": [
            {"address": "module.stack.module.kubernetes[0].vmdesktop_vm.node[0]", "type": "vmdesktop_vm", "name": "cloudseed-e2e-cp1",
             "id": vmx, "vmx_path": vmx, "ip": "10.0.0.20"},
            {"address": "module.stack.module.kubernetes[0].random_integer.mac[0]", "type": "random_integer", "name": "mac", "id": "141"},
            {"address": "module.stack.module.kubernetes[0].random_integer.mac[1]", "type": "random_integer", "name": "mac", "id": "142"}]}
        audit.save(self.env, inv)
        self.run_cmd(cli.cmd_inventory, ["inventory", "aws", "--env", self.env_name])
        out = self.out.getvalue()
        self.assertIn("module.kubernetes[0].vmdesktop_vm.node[0]", out)
        self.assertIn("name=cloudseed-e2e-cp1", out)
        self.assertIn(f"vmx_path={vmx}", out)
        self.assertEqual(out.count(vmx), 1)
        self.assertNotIn("id=141", out)
        self.assertIn("2 helper resource(s) not listed", out)

    def test_fit_path(self):
        self.assertEqual(cli._fit_path("/a/b", 20), "/a/b")
        fitted = cli._fit_path("/very/long/path/to/some/working/directory/aws-dev", 24)
        self.assertEqual(len(fitted), 24)
        self.assertIn("…", fitted)
        self.assertTrue(fitted.endswith("aws-dev"))
        with mock.patch.dict(os.environ, {"HOME": "/Users/x"}):
            self.assertEqual(cli._fit_path("/Users/x/envs/a", 40), "~/envs/a")

    def test_list_fits_the_terminal(self):
        tmp = Path(tempfile.mkdtemp(prefix="cs-list-"))
        root = tmp / ("deep-" * 20)
        env = paths.Env(self.cloud, self.env_name)
        env.set_workdir(root)

        def forget():             # no workdirs.json claim (paths.workdir_problem reads them) or directory left behind
            index = paths._load_index()
            index.pop(env.id, None)
            paths._save_index(index)
            shutil.rmtree(tmp, ignore_errors=True)
        self.addCleanup(forget)
        env.save(dict(self.cfg))
        # a terminal 100 columns wide (piped output keeps whole paths: see test_wave3_cli_tools)
        with mock.patch.object(ui, "stdout_is_tty", return_value=True), mock.patch.object(ui, "cols", return_value=100):
            self.run_cmd(cli.cmd_list, ["list"])
        lines = [ln for ln in self.out.getvalue().splitlines() if ln.strip()]
        self.assertTrue(lines)
        self.assertLessEqual(max(len(ln.rstrip()) for ln in lines), 100)
        self.assertIn("…", self.out.getvalue())

    def test_doctor_provider_row_aligns_with_tool_rows(self):
        rows = [{"tool": "terraform", "path": "/usr/bin/terraform", "version": "1.16.0", "required": True, "desc": ""}]
        with mock.patch.object(cli.deps, "status", return_value=rows), mock.patch.object(cli.deps, "live_credential_check", return_value=None), \
                mock.patch.object(localvm, "detect_host", lambda: {}), \
                mock.patch.object(localvm, "provider_binary", return_value=Path("/nonexistent/provider")), \
                mock.patch.object(ui, "style", lambda s, *n: s), mock.patch.object(ui, "dim", lambda s: s):
            self.run_cmd(cli.cmd_doctor, ["doctor", "vmware"])
        lines = self.out.getvalue().splitlines()
        tool = next(ln for ln in lines if "terraform" in ln and "/usr/bin" in ln)
        prov_line = next(ln for ln in lines if "provider" in ln and "cloudseed install" in ln)
        self.assertEqual(tool.index("/usr/bin/terraform"), prov_line.index("cloudseed install vmware-provider"))



# ---------------------------------------------------------------- review follow-ups

class ReviewFollowUpTests(LifeBase):
    def test_project_dirs_named_like_cloudseeds_survive_a_purge(self):
        """A --workdir pointed at a project that already had k8s/ and logs/: those are the user's, not cloudseed's."""
        root = Path(tempfile.mkdtemp(prefix="cs-purge-"))
        wd = root / "project"
        (wd / "k8s").mkdir(parents=True)
        (wd / "k8s" / "app.yaml").write_text("kind: Deployment")
        (wd / "logs").mkdir()
        (wd / "logs" / "app.log").write_text("app output")
        old = 1_700_000_000   # 2023: long before cloudseed used the directory
        os.utime(wd / "k8s" / "app.yaml", (old, old))
        env = paths.Env(self.cloud, self.env_name)
        env.set_workdir(wd)
        env.save(dict(self.cfg))
        (env.ssh_dir / "id_ed25519").write_text("PRIVATE KEY")
        (env.ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 AAAA")
        (wd / "k8s" / "kubeconfig").write_text("cloudseed's")
        (wd / "scans").mkdir()
        (wd / "scans" / "cis-1.json").write_text("{}")
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        self.assertEqual(self.destroy("-y", "--auto-approve", "--purge"), 0)
        self.assertEqual((wd / "k8s" / "app.yaml").read_text(), "kind: Deployment")
        self.assertEqual((wd / "logs" / "app.log").read_text(), "app output")
        self.assertEqual([p.name for p in (wd / "logs").iterdir()], ["app.log"], "cloudseed's own logs go")
        self.assertFalse((wd / "ssh").exists(), "the private key always goes")
        self.assertFalse((wd / "scans").exists(), "a directory holding only cloudseed's files goes")
        self.assertFalse((wd / "config.json").exists())

    def test_targeted_destroy_drains_only_when_the_cluster_goes(self):
        FakeTF.reset(state=["module.stack.module.network.aws_nat_gateway.this[0]",
                            "module.stack.module.kubernetes[0].aws_eks_cluster.this"],
                     outputs_value={"kubernetes_cluster_name": "cloudseed-x-eks"},
                     changes=[{"address": "module.stack.module.network.aws_nat_gateway.this[0]", "type": "aws_nat_gateway",
                               "mode": "managed", "change": {"actions": ["delete"]}}])
        drained = []
        with mock.patch.object(cli, "_drain_cluster_for_destroy", lambda *a: drained.append(1)):
            self.assertEqual(self.destroy("--target", "module.stack.module.network.aws_nat_gateway.this[0]", "-y", "--auto-approve"), 0)
            self.assertEqual(drained, [], "the cluster stays: its load balancers and volumes must stay too")
            FakeTF.reset(state=["module.stack.module.kubernetes[0].aws_eks_cluster.this"],
                         outputs_value={"kubernetes_cluster_name": "cloudseed-x-eks"},
                         changes=[{"address": "module.stack.module.kubernetes[0].aws_eks_cluster.this", "type": "aws_eks_cluster",
                                   "mode": "managed", "change": {"actions": ["delete"]}}])
            self.assertEqual(self.destroy("--target", "module.stack.module.kubernetes", "-y", "--auto-approve"), 0)
        self.assertEqual(drained, [1])

    def test_drain_removes_statefulsets_before_their_claims(self):
        log = []
        seq = {"pv": 0}

        def fake_run(cmd, **kw):
            args = cmd[1:]
            log.append(args)
            if args[:2] == ["get", "namespaces"]:
                return _cp(0, "namespace/default\n")
            if args[:2] == ["get", "statefulsets"]:
                return _cp(0, json.dumps({"items": [
                    {"metadata": {"namespace": "data", "name": "db"}, "spec": {"volumeClaimTemplates": [{"metadata": {"name": "d"}}]}},
                    {"metadata": {"namespace": "x", "name": "cache"}, "spec": {}}]}))
            if args[:2] == ["get", "pv"]:
                seq["pv"] += 1
                items = [{"metadata": {"name": "pv-1"}, "spec": {"persistentVolumeReclaimPolicy": "Delete",
                                                                  "claimRef": {"namespace": "data", "name": "d-db-0"}}}] if seq["pv"] == 1 else []
                return _cp(0, json.dumps({"items": items}))
            if args[:1] == ["get"]:
                return _cp(0, json.dumps({"items": []}))
            return _cp(0)
        with mock.patch.object(services, "ensure_kubeconfig", return_value=Path("/tmp/kc")), \
                mock.patch.object(cli.deps, "find", return_value="/fake/kubectl"), \
                mock.patch.object(cli.subprocess, "run", fake_run), mock.patch.object(cli, "_DRAIN_POLL", 0), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            cli._drain_cluster_for_destroy(clouds.get("aws"), self.env, self.cfg, {"kubernetes_cluster_name": "c"})
        deletes = [a for a in log if a[0] == "delete"]
        sts = ["delete", "statefulset", "-n", "data", "db", "--wait=false"]
        self.assertIn(sts, deletes)
        self.assertNotIn(["delete", "statefulset", "-n", "x", "cache", "--wait=false"], deletes)
        self.assertLess(deletes.index(sts), deletes.index(["delete", "pvc", "-n", "data", "d-db-0", "--ignore-not-found", "--wait=false"]))
        self.assertIn("Kubernetes-created cloud resources removed", self.out.getvalue())

    def test_select_offers_managed_resources_only(self):
        FakeTF.reset(state=["module.stack.data.aws_availability_zones.available", "module.stack.module.bastion.aws_instance.bastion"])
        seen = []
        with mock.patch.object(cli, "_select_targets", lambda res: seen.append(list(res)) or ["module.stack.module.bastion.aws_instance.bastion"]):
            self.destroy("--select", "-y")
        self.assertEqual(seen, [["module.stack.module.bastion.aws_instance.bastion"]])

    def test_inventory_address_shadowed_by_an_ip_attribute(self):
        inv = audit.load(self.env)
        inv["current"] = {"updated_at": "now", "count": 1, "resources": [
            {"address": "34.1.2.3", "type": "google_compute_address", "name": "cloudseed-dev-bastion", "id": "projects/p/addresses/x"}]}
        audit.save(self.env, inv)
        self.run_cmd(cli.cmd_inventory, ["inventory", "aws", "--env", self.env_name])
        out = self.out.getvalue()
        self.assertIn("google_compute_address.cloudseed-dev-bastion", out)
        self.assertIn("address=34.1.2.3", out)

    def test_ssm_recovery_command_is_valid_json_and_plain_text(self):
        cfg = dict(self.cfg, provisioned={"bastion": {"at": "2026-01-01"}})
        (self.env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "192.0.2.10", "bastion_instance_id": "i-0abc"}))
        with mock.patch.object(cli.subprocess, "run", return_value=_cp(255)), mock.patch.object(cli.time, "sleep"), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            cli._check_bastion_ssh(clouds.get("aws"), self.env, cfg, ["203.0.113.9/32"])
        line = next(ln for ln in self.out.getvalue().splitlines() if "aws ssm send-command" in ln)
        self.assertNotIn("│", line, "a command to copy must not sit inside a box")
        params = json.loads(line.split("--parameters '", 1)[1].rstrip("'"))
        self.assertEqual(params, {"commands": ["nft add element inet filter ssh_allowed { 203.0.113.9/32 }"]})


    def test_data_source_detection_is_exact(self):
        self.assertTrue(cli._is_data("module.stack.module.kubernetes[0].data.aws_iam_policy_document.x"))
        self.assertTrue(cli._is_data("data.aws_region.current"))
        self.assertFalse(cli._is_data("module.stack.module.network.aws_route_table.data"))
        self.assertFalse(cli._is_data('module.stack.module.a["x.data.y"].aws_s3_bucket.b'))

    def test_purge_flags_on_a_partial_destroy_are_called_out(self):
        FakeTF.reset(state=["module.stack.module.bastion.aws_instance.bastion"], changes=[
            {"address": "module.stack.module.bastion.aws_instance.bastion", "type": "aws_instance", "mode": "managed",
             "change": {"actions": ["delete"]}}])
        self.assertEqual(self.destroy("--target", "module.stack.module.bastion", "--purge", "-y", "--auto-approve"), 0)
        self.assertIn("full destroy only", self.out.getvalue())
        self.assertTrue(self.env.config_path.exists())


    def test_troubleshoot_log_hint_for_unreachable_vmware_vm_is_not_update_ip(self):
        from cloudseed import troubleshoot
        env = paths.Env("vmware", self.env_name)
        env.create_dirs()
        env.save(dict(self.cfg, cloud="vmware"))
        log = env.dir / "logs" / "20260101-000000-provision.log"
        log.write_text("bastion did not accept SSH within 420s\n")
        (env.dir / "logs" / "audit.jsonl").write_text(json.dumps(
            {"at": "2026-01-01T00:00:00", "command": "provision", "argv": ["provision", "vmware"], "exit_code": 1, "log": str(log)}) + "\n")
        with mock.patch.object(troubleshoot.deps, "missing", return_value=([], [])), \
                mock.patch.object(troubleshoot.deps, "live_credential_check", return_value=None), \
                mock.patch.object(localvm, "detect_host", lambda: None), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            troubleshoot.run(clouds.get("vmware"), env, env.load())
        out = self.out.getvalue()
        self.assertIn("powered off or still booting", out)
        self.assertNotIn("update-ip", out)


    def test_undoing_a_purge_drops_the_key_backup(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        with mock.patch.object(paths, "save_settings"):
            self.assertEqual(self.destroy("-y", "--auto-approve", "--purge"), 0)
        entry = undo.latest(self.env.id)
        backup = Path(entry["data"]["backup_dir"])
        self.assertTrue((backup / "ssh" / "id_ed25519").exists())
        with mock.patch.object(undo, "_run_cli", lambda argv: None):
            rc = self.run_cmd(cli.cmd_undo, ["undo", "aws", "--env", self.env_name, "-y", "--auto-approve"])
        self.assertEqual(rc, 0)
        self.assertEqual((self.env.ssh_dir / "id_ed25519").read_text(), "PRIVATE KEY", "the keys are back in the environment")
        self.assertFalse(backup.exists(), "and no copy of the private key is left behind")


    def test_undoing_a_purge_brings_back_the_kept_state_storage_record(self):
        self.env.bootstrap_dir.mkdir(parents=True, exist_ok=True)
        (self.env.bootstrap_dir / "main.tf.json").write_text("{}")
        (self.env.bootstrap_dir / "terraform.tfstate").write_text(json.dumps(
            {"resources": [{"type": "aws_s3_bucket"}], "outputs": {"bucket": {"value": "cs-state-kept"}}}))
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        with mock.patch.object(paths, "save_settings"):
            self.assertEqual(self.destroy("-y", "--auto-approve", "--purge"), 0)
        self.assertFalse(self.env.bootstrap_dir.exists())
        with mock.patch.object(undo, "_run_cli", lambda argv: None):
            self.assertEqual(self.run_cmd(cli.cmd_undo, ["undo", "aws", "--env", self.env_name, "--auto-approve"]), 0)
        self.assertEqual(cli._state_storage(self.env, self.env.load()), "cs-state-kept")


if __name__ == "__main__":
    unittest.main()
