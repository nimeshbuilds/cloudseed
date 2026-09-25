"""Regression tests for the wave-4 undo items: config undos that drain local nodes first, keep account-wide settings
and the Velero bucket, re-register a GCP OS Login key; Velero undo points (created objects, whole-cluster scope,
progress); purge restores into a custom working directory; the per-kind history limit; the history list (UTC, paths).
Stdlib only, no network, no real Terraform, kubectl or velero."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, cli, clouds, dr, paths, platform as platformmod, provision, services, ui, undo  # noqa: E402


def _quiet():
    buf = io.StringIO()
    stack = contextlib.ExitStack()
    stack.enter_context(contextlib.redirect_stdout(buf))
    stack.enter_context(contextlib.redirect_stderr(buf))
    return stack, buf


def _run(fn, *a, **kw):
    """fn(*a, **kw) with its output captured: (result or raised exception, output)."""
    stack, buf = _quiet()
    try:
        with stack:
            return fn(*a, **kw), buf.getvalue()
    except (Exception, SystemExit) as e:  # noqa: BLE001 - the caller asserts on it
        return e, buf.getvalue()


class _Journal(unittest.TestCase):
    """Each test starts with its own empty journal and settings (the real ones are kept aside and put back)."""

    def setUp(self):
        self._saved = undo.JOURNAL.read_text() if undo.JOURNAL.exists() else None
        undo.JOURNAL.unlink(missing_ok=True)
        self._settings = paths.load_settings()
        self._index = paths.WORKDIRS_INDEX.read_text() if paths.WORKDIRS_INDEX.exists() else None

    def tearDown(self):
        if self._saved is None:
            undo.JOURNAL.unlink(missing_ok=True)
        else:
            undo.JOURNAL.write_text(self._saved)
        paths.save_settings(self._settings)
        if self._index is None:
            paths.WORKDIRS_INDEX.unlink(missing_ok=True)
        else:
            paths.WORKDIRS_INDEX.write_text(self._index)

    def env(self, cloud: str, name: str, cfg: dict, outputs: dict | None = None) -> paths.Env:
        env = paths.Env(cloud, name)
        shutil.rmtree(env.dir, ignore_errors=True)
        env.create_dirs()
        env.save(cfg)
        if outputs is not None:
            (env.dir / "outputs.json").write_text(json.dumps(outputs))
        self.addCleanup(shutil.rmtree, env.dir, True)
        return env


class FakeTf:
    """Terraform stand-in: records runs; `deleting` is what `show -json` of the saved plan deletes."""

    runs: list = []
    deleting: set = set()

    def __init__(self, workdir):
        self.workdir = workdir

    def init(self, migrate=False):
        pass

    def plan_for_apply(self, cloud_key, cfg, out="tfplan", targets=(), render=None):
        FakeTf.runs.append(("plan_for_apply",))

    def run(self, *args, capture=False, check=True):
        FakeTf.runs.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    def _deleting(self, planfile):
        return set(FakeTf.deleting)

    def apply_reconciled(self, cloud_key, cfg, approve=None, **kw):
        FakeTf.runs.append(("apply",))


@contextlib.contextmanager
def _config_undo(changes, cloud_key="vmware", approve=None):
    """The collaborators of a config undo, faked: no Terraform, no provider, no cluster."""
    FakeTf.runs, FakeTf.deleting = [], set()
    asked = []

    def _approve(q, auto):
        asked.append(q)
        if approve is not None:
            approve(q)

    with mock.patch("cloudseed.tf.Terraform", FakeTf), \
            mock.patch.object(cli, "_render", lambda c, e, cfg: False), \
            mock.patch.object(cli, "_approve", _approve), \
            mock.patch.object(cli, "_cache_outputs", lambda e, t: cli._cached_outputs(e)), \
            mock.patch.object(cli, "_plan_changes", lambda t, planfile="tfplan": changes), \
            mock.patch.object(audit, "refresh", lambda *a, **k: None), \
            mock.patch.object(clouds.get(cloud_key).__class__, "prepare", lambda self, cfg, dry_run=False: None):
        yield asked


def _node_change(key: str, actions: list) -> dict:
    return {"address": f'module.stack.module.kubernetes[0].vmdesktop_vm.node["{key}"]', "type": "vmdesktop_vm",
            "mode": "managed", "actions": actions}


# ---------------------------------------------------------------------------------------------------- node leave

class ConfigUndoNodesTests(_Journal):
    """a2-ops#0 / a2-platform-logic#1: a config undo that lowers the node count drains the nodes first."""

    OUT = {"kubernetes_control_plane_ips": ["10.0.0.20", "10.0.0.21", "10.0.0.22"],
           "kubernetes_worker_ips": ["10.0.0.40", "10.0.0.41", "10.0.0.42"]}

    def _setup(self, name, cur_vars, prev_vars, provisioned=None):
        base = {"cloud": "vmware", "env": name, "name": "lab", "state": {"type": "local"}}
        cur = dict(base, vars=dict({"enable_kubernetes": True}, **cur_vars))
        if provisioned is not None:
            cur["provisioned"] = provisioned
        env = self.env("vmware", name, cur, self.OUT)
        (env.dir / "k8s").mkdir(exist_ok=True)
        (env.dir / "k8s" / "kubeconfig").write_text("apiVersion: v1\n")
        prev = dict(base, vars=dict({"enable_kubernetes": True}, **prev_vars))
        entry = undo.record(env.id, "setup (changed: vars)", "config", {"prev_cfg": prev, "what": "vars", "rejoin_nodes": True})
        return env, entry

    def _perform(self, env, entry, changes, auto=True, leave=None, registered=True):
        left, forgotten = [], []

        def fake_leave(cloud, env_, cfg, outputs, kubectl, kenv, name, registered=True):
            left.append((name, registered, cfg["vars"]["kubernetes_workers"], kenv.get("KUBECONFIG")))
            if leave:
                leave(name)

        with _config_undo(changes) as asked, \
                mock.patch.object(services, "ensure_tool", lambda tool, why, **kw: "/bin/kubectl"), \
                mock.patch.object(cli, "_node_json_or_none", lambda k, e, n: {} if registered else None), \
                mock.patch.object(cli, "_leave_local_node", fake_leave), \
                mock.patch.object(provision, "forget_host_key", lambda e, ip: forgotten.append(ip)), \
                mock.patch.object(provision, "provision_local_kubernetes", lambda *a, **k: None):
            res, out = _run(undo.perform, entry, {}, auto)
        return res, out, left, forgotten, asked

    def test_removed_workers_leave_the_cluster_highest_first_before_the_apply(self):
        env, entry = self._setup("w4nodes1", {"kubernetes_workers": 3}, {"kubernetes_workers": 1})
        changes = [_node_change("wk2", ["delete"]), _node_change("wk3", ["delete"]), _node_change("wk1", ["update"])]
        res, out, left, forgotten, asked = self._perform(env, entry, changes)
        self.assertIsNone(res, out)
        self.assertEqual([n for n, *_ in left], ["lab-w4nodes1-wk3", "lab-w4nodes1-wk2"])
        self.assertEqual(left[0][2], 3)                                  # with the configuration the nodes were built with
        self.assertTrue(left[0][3].endswith("k8s/kubeconfig"))
        self.assertIn("lab-w4nodes1-wk3", asked[0])                      # the approval names them
        self.assertEqual(FakeTf.runs[-1], ("apply",))
        self.assertEqual(sorted(forgotten), ["10.0.0.41", "10.0.0.42"])
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 1)

    def test_a_node_that_never_registered_is_not_drained(self):
        env, entry = self._setup("w4nodes2", {"kubernetes_workers": 3}, {"kubernetes_workers": 2})
        res, out, left, _, _ = self._perform(env, entry, [_node_change("wk3", ["delete"])], registered=False)
        self.assertIsNone(res, out)
        self.assertEqual(left[0][:2], ("lab-w4nodes2-wk3", False))

    def test_a_failed_drain_applies_nothing_and_keeps_the_configuration(self):
        env, entry = self._setup("w4nodes3", {"kubernetes_workers": 3}, {"kubernetes_workers": 2})

        def boom(name):
            raise ui.Abort(f"Could not drain {name}")
        res, out, _, forgotten, _ = self._perform(env, entry, [_node_change("wk3", ["delete"])], leave=boom)
        self.assertIsInstance(res, ui.Abort)
        self.assertNotIn(("apply",), FakeTf.runs)
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 3)
        self.assertEqual(forgotten, [])

    def test_unreadable_plan_with_fewer_nodes_is_refused_under_auto_approve(self):
        env, entry = self._setup("w4nodes4", {"kubernetes_workers": 3}, {"kubernetes_workers": 2})
        res, out, left, _, _ = self._perform(env, entry, None, auto=True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("lab-w4nodes4-wk3", str(res))
        self.assertEqual((left, FakeTf.runs[-1]), ([], ("plan_for_apply",)))

    def test_unreadable_plan_at_a_terminal_names_the_nodes_above_the_previous_count(self):
        env, entry = self._setup("w4nodes5", {"kubernetes_workers": 3}, {"kubernetes_workers": 1})
        res, out, left, _, asked = self._perform(env, entry, None, auto=False)
        self.assertIsNone(res, out)
        self.assertEqual([n for n, *_ in left], ["lab-w4nodes5-wk3", "lab-w4nodes5-wk2"])

    def test_the_last_control_plane_is_never_deleted(self):
        env, entry = self._setup("w4nodes6", {"kubernetes_control_planes": 1}, {"kubernetes_control_planes": 0})
        res, out, left, _, _ = self._perform(env, entry, [_node_change("cp1", ["delete"])])
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("every control plane", str(res))
        self.assertEqual(left, [])

    def test_undoing_the_whole_cluster_drains_nothing(self):
        env, entry = self._setup("w4nodes7", {"kubernetes_workers": 2}, {"enable_kubernetes": False})
        changes = [_node_change("cp1", ["delete"]), _node_change("wk1", ["delete"]), _node_change("wk2", ["delete"])]
        res, out, left, _, _ = self._perform(env, entry, changes)
        self.assertIsNone(res, out)
        self.assertEqual(left, [])

    def test_rejoining_nodes_keep_the_clusters_hardening_choice(self):   # a2-ansible#4
        env, entry = self._setup("w4nodes8", {"kubernetes_workers": 2}, {"kubernetes_workers": 3},
                                 provisioned={"kubernetes": {"harden": False}})
        calls = []
        with _config_undo([_node_change("wk3", ["create"])]), \
                mock.patch.object(provision, "provision_local_kubernetes", lambda *a, **k: calls.append(k)):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertEqual(calls, [{"limit": ["lab-w4nodes8-wk3"], "harden": False}])
        with _config_undo(None), mock.patch.object(provision, "provision_local_kubernetes", lambda *a, **k: calls.append(k)):
            entry2 = undo.record(env.id, "setup (changed: again)", "config",
                                 {"prev_cfg": env.load(), "what": "x", "rejoin_nodes": True})
            res, out = _run(undo.perform, entry2, {}, True)
        self.assertEqual(calls[-1], {"harden": False})                  # unreadable plan: every node, same flags


# ---------------------------------------------------------------------------------------------------- account-wide

class ConfigUndoKeepsAccountSettingsTests(_Journal):
    """aws#20: a config undo that switches the account baseline off only drops those settings from the state."""

    ADDRS = ["module.stack.module.security_baseline[0].aws_s3_account_public_access_block.this",
             "module.stack.module.security_baseline[0].aws_ebs_encryption_by_default.this"]

    def _entry(self, name):
        cur = {"cloud": "aws", "env": name, "name": "cs", "region": "us-east-1", "state": {"type": "local"},
               "vars": {"enable_account_baseline": True}}
        env = self.env("aws", name, cur)
        prev = dict(cur, vars={"enable_account_baseline": False})
        return env, undo.record(env.id, "setup (changed: enable_account_baseline)", "config", {"prev_cfg": prev, "what": "x"})

    def test_account_settings_are_dropped_from_the_state_not_deleted(self):
        env, entry = self._entry("w4keep1")
        changes = [{"address": a, "mode": "managed", "actions": ["delete"]} for a in self.ADDRS] + \
                  [{"address": "module.stack.module.security_baseline[0].aws_cloudtrail.this[0]", "mode": "managed", "actions": ["delete"]}]
        with _config_undo(changes, "aws") as asked:
            FakeTf.deleting = {changes[-1]["address"]}               # the new plan deletes only the trail
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        rms = [r for r in FakeTf.runs if r[:2] == ("state", "rm")]
        self.assertEqual([r[2] for r in rms], self.ADDRS)
        order = [r[0] for r in FakeTf.runs]
        self.assertLess(order.index("state"), order.index("apply"))   # forgotten before anything is applied
        self.assertIn("Kept in place", out)
        self.assertIn("aws_s3_account_public_access_block", out)
        self.assertEqual(asked, ["Apply this plan (undo)?"])

    def test_a_replanned_delete_the_user_never_saw_stops_the_undo(self):
        env, entry = self._entry("w4keep2")
        changes = [{"address": self.ADDRS[0], "mode": "managed", "actions": ["delete"]}]
        with _config_undo(changes, "aws"):
            FakeTf.deleting = {"module.stack.module.network.aws_vpc.this"}
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("aws_vpc.this", str(res))
        self.assertNotIn(("apply",), FakeTf.runs)
        self.assertTrue(env.load()["vars"]["enable_account_baseline"])

    def test_an_unreadable_replan_stops_the_undo(self):
        env, entry = self._entry("w4keep4")
        changes = [{"address": self.ADDRS[0], "mode": "managed", "actions": ["delete"]}]
        with _config_undo(changes, "aws"), mock.patch.object(FakeTf, "_deleting", lambda self, planfile: None):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("could not be read", str(res))
        self.assertIn("config.json is unchanged", str(res))
        self.assertNotIn(("apply",), FakeTf.runs)

    def test_the_notice_names_what_the_current_configuration_set(self):
        cur = {"cloud": "gcp", "env": "w4keep5", "name": "cs", "region": "us-central1", "state": {"type": "local"},
               "vars": {"project_id": "p-123", "enable_os_login": False}, "extra_vars": {"log_retention_days": 30}}
        env = self.env("gcp", "w4keep5", cur)
        prev = dict(cur, extra_vars={"log_retention_days": 400})
        entry = undo.record(env.id, "setup (changed: extra)", "config", {"prev_cfg": prev, "what": "x"})
        addr = "module.stack.module.security_baseline.google_logging_project_bucket_config.default"
        with _config_undo([{"address": addr, "mode": "managed", "actions": ["delete"]}], "gcp"):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertIn(("state", "rm", addr), FakeTf.runs)
        self.assertIn("(30 days)", " ".join(out.split()))

    def test_a_replaced_setting_is_left_to_terraform(self):
        env, entry = self._entry("w4keep3")
        with _config_undo([{"address": self.ADDRS[0], "mode": "managed", "actions": ["delete", "create"]}], "aws"):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertFalse([r for r in FakeTf.runs if r[:2] == ("state", "rm")])


# ---------------------------------------------------------------------------------------------------- prerequisites

class ConfigUndoPrereqsTests(_Journal):
    """a2-platform-logic#11: platform prerequisites change only through their own entry; Velero's bucket never goes."""

    def _perform(self, name, cur_prereqs, prev_prereqs, what):
        cur = {"cloud": "aws", "env": name, "name": "cs", "region": "us-east-1", "state": {"type": "local"},
               "vars": {}, "allowed_ssh_cidrs": ["203.0.113.7/32"], "platform_prereqs": cur_prereqs}
        env = self.env("aws", name, cur)
        prev = dict(cur, allowed_ssh_cidrs=["198.51.100.1/32"], platform_prereqs=prev_prereqs)
        entry = undo.record(env.id, "x", "config", {"prev_cfg": prev, "what": what})
        with _config_undo([], "aws"):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        return env.load(), out

    def test_an_older_update_ip_entry_keeps_the_prerequisites(self):
        cfg, _ = self._perform("w4pre1", ["velero", "karpenter"], [], "allowed SSH sources")
        self.assertEqual(cfg["platform_prereqs"], ["velero", "karpenter"])
        self.assertEqual(cfg["allowed_ssh_cidrs"], ["198.51.100.1/32"])

    def test_the_prereqs_entry_removes_karpenter_but_never_velero(self):
        cfg, _ = self._perform("w4pre2", ["velero", "karpenter"], ["velero"], "cloud prerequisites of karpenter; kept")
        self.assertEqual(cfg["platform_prereqs"], ["velero"])

    def test_a_bucket_dropped_since_is_not_brought_back(self):
        cfg, out = self._perform("w4pre4", ["karpenter"], ["velero"], "cloud prerequisites of karpenter; kept")
        self.assertEqual(cfg["platform_prereqs"], [])
        self.assertNotIn("hold the backups", out)

    def test_an_old_velero_prereqs_entry_keeps_the_bucket_and_says_so(self):
        cfg, out = self._perform("w4pre3", ["velero"], [], "cloud prerequisites (bucket / identities / tags)")
        self.assertEqual(cfg["platform_prereqs"], ["velero"])
        self.assertIn("hold the backups", out)


# ---------------------------------------------------------------------------------------------------- GCP OS Login

class ConfigUndoOsLoginTests(_Journal):
    """a2-gcp#3: a GCP config undo registers the OS Login key again (prepare), and releases one nothing uses."""

    def _run(self, name, cur_on, prev_on, fail=False):
        rec = {"account": "me@example.com", "user": "me_example_com", "key": "ssh-ed25519 AAAA", "added": True}
        cur = {"cloud": "gcp", "env": name, "name": "cs", "region": "us-central1", "state": {"type": "local"},
               "ssh_public_key": "ssh-ed25519 AAAA me", "vars": {"project_id": "p-123", "enable_os_login": cur_on}}
        if cur_on:
            cur["os_login"] = dict(rec)
        env = self.env("gcp", name, cur)
        prev = dict(cur, vars=dict(cur["vars"], enable_os_login=prev_on))
        prev.pop("os_login", None)
        if prev_on:
            prev["os_login"] = dict(rec, key="ssh-ed25519 OLD")              # the record as it was back then
        entry = undo.record(env.id, "setup (changed: vars)", "config", {"prev_cfg": prev, "what": "vars"})
        prepared, released = [], []

        def prepare(self, cfg, dry_run=False):
            prepared.append(json.loads(json.dumps(cfg)))
            if cfg["vars"]["enable_os_login"]:
                cfg["os_login"] = dict(rec, added=True)
            else:
                cfg.pop("os_login", None)

        def approve(q):
            if fail:
                raise ui.Abort("Cancelled. Nothing was changed.", code=0)
        with _config_undo([], "gcp", approve=approve), \
                mock.patch.object(clouds.get("gcp").__class__, "prepare", prepare), \
                mock.patch.object(clouds.get("gcp").__class__, "release_os_login",
                                  lambda self, old, new=None: released.append((old.get("os_login"), (new or {}).get("os_login")))):
            res, out = _run(undo.perform, entry, {}, True)
        return env, res, out, prepared, released

    def test_undoing_os_login_off_registers_the_key_again(self):
        env, res, out, prepared, released = self._run("w4osl1", False, True)
        self.assertIsNone(res, out)
        self.assertEqual(len(prepared), 1)
        self.assertEqual(prepared[0]["os_login"]["key"], "ssh-ed25519 OLD")   # prepare re-checks what was recorded
        self.assertTrue(env.load()["os_login"]["added"])
        self.assertEqual(released, [(None, env.load()["os_login"])])           # nothing of cfg's to release

    def test_undoing_os_login_on_releases_the_key(self):
        env, res, out, prepared, released = self._run("w4osl2", True, False)
        self.assertIsNone(res, out)
        self.assertNotIn("os_login", env.load())
        self.assertEqual(released[-1][0]["key"], "ssh-ed25519 AAAA")           # old = the configuration before the undo
        self.assertIsNone(released[-1][1])

    def test_a_declined_undo_releases_what_prepare_registered(self):
        env, res, out, prepared, released = self._run("w4osl3", False, True, fail=True)
        self.assertIsInstance(res, ui.Abort)
        self.assertFalse(env.load()["vars"]["enable_os_login"])
        self.assertEqual(len(released), 1)                                    # old = what prepare registered, new = cfg
        self.assertEqual((released[0][0]["key"], released[0][0]["added"], released[0][1]), ("ssh-ed25519 AAAA", True, None))

    def test_a_prepare_that_failed_releases_nothing(self):
        rec = {"account": "me@example.com", "user": "me_example_com", "key": "ssh-ed25519 OLD", "added": True}
        cur = {"cloud": "gcp", "env": "w4osl5", "name": "cs", "region": "us-central1", "state": {"type": "local"},
               "ssh_public_key": "ssh-ed25519 AAAA me", "vars": {"project_id": "p-123", "enable_os_login": False}}
        env = self.env("gcp", "w4osl5", cur)
        prev = dict(cur, vars=dict(cur["vars"], enable_os_login=True), os_login=rec)   # a key released long ago
        entry = undo.record(env.id, "setup (changed: vars)", "config", {"prev_cfg": prev, "what": "vars"})
        released = []

        def prepare(self, cfg, dry_run=False):
            raise ui.Abort("enable_os_login=true needs the gcloud CLI")
        with _config_undo([], "gcp"), \
                mock.patch.object(clouds.get("gcp").__class__, "prepare", prepare), \
                mock.patch.object(clouds.get("gcp").__class__, "release_os_login",
                                  lambda self, old, new=None: released.append(old)):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertEqual(released, [])
        self.assertFalse(env.load()["vars"]["enable_os_login"])

    def test_the_current_record_follows_the_carried_key(self):
        env, res, out, prepared, released = self._run("w4osl4", True, True)
        self.assertIsNone(res, out)
        self.assertEqual(prepared[0]["os_login"]["key"], "ssh-ed25519 AAAA")  # not the stale record of the entry


# ---------------------------------------------------------------------------------------------------- Velero

class _Ctx(SimpleNamespace):
    def procenv(self):
        return {}


class VeleroRestoreTests(_Journal):
    """e2e2#1: objects the change created are deleted before the undo point is restored."""

    def _entry(self, created, new_ns=()):
        return {"id": "x1", "kind": "velero-restore", "scope": "vmware-w4vr", "summary": "kubectl apply -f app.yaml",
                "data": {"backup": "pre-kubectl-1", "new_namespaces": list(new_ns), "created": created}}

    def _perform(self, entry, kubectl_rc=0):
        calls = []

        def kubectl(ctx, *args, **kw):
            calls.append(("kubectl",) + args)
            return subprocess.CompletedProcess(args, kubectl_rc, "", "forbidden" if kubectl_rc else "")

        ctx = _Ctx(env=None, target="vmware")
        with mock.patch.object(undo, "_cluster", return_value=(None, None, {}, {}, ctx)), \
                mock.patch.object(dr, "_kubectl", kubectl), \
                mock.patch.object(dr, "restore", lambda c, b, ns, wait=True: calls.append(("restore", b))), \
                mock.patch.object(undo, "_verify_restored", lambda *a: None), \
                mock.patch.object(undo, "_audit_start", lambda e: None):
            res, out = _run(undo.perform, entry, {}, True)
        return res, out, calls

    def test_created_objects_are_deleted_before_the_restore(self):
        entry = self._entry([{"ns": "shop", "ref": "service/new"}, {"ns": "shop", "ref": "configmap/cfg"},
                             {"ns": None, "ref": "clusterrole.rbac.authorization.k8s.io/viewer"},
                             {"ns": "gone", "ref": "deployment.apps/x"}, {"ns": "shop", "ref": "--all"}], new_ns=["gone"])
        res, out, calls = self._perform(entry)
        self.assertIsNone(res, out)
        self.assertEqual(calls, [("kubectl", "delete", "ns", "gone", "--ignore-not-found", "--wait=false"),
                                 ("kubectl", "-n", "shop", "delete", "service/new", "configmap/cfg", "--ignore-not-found"),
                                 ("kubectl", "-n", "gone", "delete", "deployment.apps/x", "--ignore-not-found"),
                                 # cluster-scoped last: custom resources go before their definition
                                 ("kubectl", "delete", "clusterrole.rbac.authorization.k8s.io/viewer", "--ignore-not-found"),
                                 ("restore", "pre-kubectl-1")])
        text = undo.describe(entry)
        self.assertIn("service/new in shop", text)
        self.assertIn("delete the namespace(s) it created (gone)", text)
        self.assertTrue(text.endswith("then restore Velero backup pre-kubectl-1 (taken right before the change)"))

    def test_a_created_namespace_is_deleted_once(self):
        # -n gone on the command line: the manifest's Namespace and cluster-scoped objects carry it too
        entry = self._entry([{"ns": "gone", "ref": "namespace/gone"}, {"ns": None, "ref": "namespace/other"},
                             {"ns": "gone", "ref": "clusterrole.rbac.authorization.k8s.io/viewer"}], new_ns=["gone"])
        res, out, calls = self._perform(entry)
        self.assertIsNone(res, out)
        self.assertEqual(calls[0], ("kubectl", "delete", "ns", "gone", "--ignore-not-found", "--wait=false"))
        self.assertEqual(sorted(calls[1:3]), [("kubectl", "-n", "gone", "delete", "clusterrole.rbac.authorization.k8s.io/viewer",
                                               "--ignore-not-found"),
                                              ("kubectl", "delete", "namespace/other", "--ignore-not-found")])
        self.assertEqual(calls[3], ("restore", "pre-kubectl-1"))
        self.assertNotIn("namespace/gone", undo.describe(entry))

    def test_a_failed_delete_restores_nothing(self):
        res, out, calls = self._perform(self._entry([{"ns": "shop", "ref": "service/new"}]), kubectl_rc=1)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("forbidden", str(res))
        self.assertNotIn(("restore", "pre-kubectl-1"), calls)

    def test_an_object_whose_kind_is_gone_does_not_block_the_undo(self):
        # the CRD of widgets.example.com was removed since: kubectl refuses the whole call for that one kind
        calls = []

        def kubectl(ctx, *args, **kw):
            calls.append(args)
            if any("widget" in a for a in args):
                return subprocess.CompletedProcess(args, 1, "", 'error: the server doesn\'t have a resource type "widgets"')
            return subprocess.CompletedProcess(args, 0, "", "")

        entry = self._entry([{"ns": "shop", "ref": "widget.example.com/w1"}, {"ns": "shop", "ref": "service/new"}])
        ctx = _Ctx(env=None, target="vmware")
        restored = []
        with mock.patch.object(undo, "_cluster", return_value=(None, None, {}, {}, ctx)), \
                mock.patch.object(dr, "_kubectl", kubectl), \
                mock.patch.object(dr, "restore", lambda c, b, ns, wait=True: restored.append(b)), \
                mock.patch.object(undo, "_verify_restored", lambda *a: None), \
                mock.patch.object(undo, "_audit_start", lambda e: None):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertIn(("-n", "shop", "delete", "service/new", "--ignore-not-found"), calls)   # the rest one by one
        self.assertEqual(restored, ["pre-kubectl-1"])

    def test_an_entry_without_created_objects_reads_as_before(self):
        entry = self._entry(None)
        self.assertEqual(undo.describe(entry), "restore Velero backup pre-kubectl-1 (taken right before the change)")
        res, out, calls = self._perform(entry)
        self.assertEqual(calls, [("restore", "pre-kubectl-1")])


class _Velero:
    def __init__(self, rc=0, stderr="", phase="Completed", unknown_flag=False):
        self.rc, self.stderr, self.phase, self.unknown_flag, self.calls = rc, stderr, phase, unknown_flag, []

    def __call__(self, ctx, *args, check=True, stream=False, timeout=1800, quiet=False):
        self.calls.append(args)
        if args[:2] == ("backup", "create"):
            if self.unknown_flag and undo._FS_BACKUP_OFF in args:
                return subprocess.CompletedProcess(args, 1, "", "Error: unknown flag: --default-volumes-to-fs-backup")
            return subprocess.CompletedProcess(args, self.rc, "", self.stderr)
        if args[:2] == ("backup", "get"):
            return subprocess.CompletedProcess(args, 0, json.dumps({"status": {"phase": self.phase}}), "")
        return subprocess.CompletedProcess(args, 0, "", "")


class VeleroUndoPointTests(unittest.TestCase):
    """e2e2#2: whole-cluster undo points hold objects only, leave velero/minio out and show progress."""

    def _backup(self, fake, namespaces, **kw):
        ctx = _Ctx(env=None, target="vmware")
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_velero", fake), \
                mock.patch.object(dr, "_status", lambda c, kind, name: {"phase": fake.phase}):
            return _run(undo.velero_pre_backup, ctx, "restore", namespaces, **kw)

    def test_whole_cluster_point_skips_volumes_and_velero_minio(self):
        fake = _Velero()
        name, out = self._backup(fake, None)
        self.assertTrue(name.startswith("pre-restore-"), out)
        create = fake.calls[0]
        self.assertIn(undo._FS_BACKUP_OFF, create)
        self.assertEqual(create[create.index("--exclude-namespaces") + 1], "velero,minio")
        self.assertIn("objects only", out)
        self.assertRegex(out, r"undo point pre-restore-\S+ taken \(\d+s\)")     # the result with its duration

    def test_namespace_point_keeps_the_servers_volume_setting(self):
        fake = _Velero()
        name, _ = self._backup(fake, ["shop"])
        create = fake.calls[0]
        self.assertEqual(create[create.index("--include-namespaces") + 1], "shop")
        self.assertNotIn(undo._FS_BACKUP_OFF, create)
        self.assertNotIn("--exclude-namespaces", create)

    def test_a_whole_cluster_point_can_keep_volume_data(self):
        fake = _Velero()
        name, out = self._backup(fake, None, volumes=True)       # e.g. before `kubectl delete ns -l team=a`
        create = fake.calls[0]
        self.assertNotIn(undo._FS_BACKUP_OFF, create)
        self.assertEqual(create[create.index("--exclude-namespaces") + 1], "velero,minio")
        self.assertNotIn("objects only", out)
        fake = _Velero()
        self._backup(fake, ["shop"], volumes=False)
        self.assertIn(undo._FS_BACKUP_OFF, fake.calls[0])

    def test_an_old_velero_without_the_flag_still_gets_an_undo_point(self):
        fake = _Velero(unknown_flag=True)
        name, out = self._backup(fake, None)
        self.assertTrue(name, out)
        self.assertEqual(len([c for c in fake.calls if c[:2] == ("backup", "create")]), 2)
        self.assertNotIn(undo._FS_BACKUP_OFF, fake.calls[1])

    def test_a_failed_create_says_why_and_discards_the_backup(self):
        fake = _Velero(rc=1, stderr="BackupStorageLocation default is unavailable")
        name, out = self._backup(fake, ["shop"])
        self.assertIsNone(name)
        self.assertIn("unavailable", out)
        self.assertTrue(any(c[:2] == ("backup", "delete") for c in fake.calls))

    def test_the_spinner_shows_the_time_spent(self):
        import time
        updates = []
        real = ui.Spinner.update
        fake = _Velero()

        def slow(ctx, *args, **kw):
            if args[:2] == ("backup", "create"):
                time.sleep(1.3)
            return fake(ctx, *args, **kw)

        def update(sp, text):
            updates.append(text)
            real(sp, text)
        with mock.patch.object(ui.Spinner, "update", update):
            self._backup(slow, ["shop"])
        self.assertTrue(updates and updates[-1].endswith("- 1s"), updates)


# ---------------------------------------------------------------------------------------------------- helm / platform

class HelmToolTests(_Journal):
    """a2-resilience#0: a missing helm is installed with consent or refused with the command, never run as None."""

    def test_missing_helm_is_refused_with_the_install_command(self):
        entry = {"id": "h1", "kind": "helm", "scope": "vmware-w4helm", "summary": "helm upgrade web",
                 "data": {"release": "web", "ns": "shop", "revision": 2}}
        ctx = _Ctx(env=None, target="vmware")
        with mock.patch.object(undo, "_cluster", return_value=(None, None, {}, {}, ctx)), \
                mock.patch.object(undo, "_audit_start", lambda e: None), \
                mock.patch("cloudseed.deps.find", return_value=None), \
                mock.patch.object(ui, "interactive", return_value=False), \
                mock.patch.dict(os.environ, {"CLOUDSEED_AUTO_INSTALL": ""}), \
                mock.patch.object(services, "_install_approved", return_value=False):
            res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("cloudseed install helm", str(res))

    def test_platform_rollback_gets_its_tools_first_and_old_entries_install_quietly(self):
        env = SimpleNamespace(id="vmware-w4p")
        ctx = _Ctx(env=env, target="vmware")
        order = []
        steps = {"id": "p1", "kind": "platform", "scope": "vmware-w4p", "summary": "platform install keda",
                 "data": {"steps": [{"item": "keda", "ns": "keda", "release": "keda", "prev_revision": 1}]}}
        with mock.patch.object(undo, "_cluster", return_value=(None, env, {}, {}, ctx)), \
                mock.patch.object(undo, "_audit_start", lambda e: None), \
                mock.patch.object(platformmod, "ensure_tools", lambda: order.append("tools")), \
                mock.patch("cloudseed.deps.find", return_value="/bin/helm"), \
                mock.patch.object(platformmod, "_run", lambda cmd, c, check=True: order.append(cmd)), \
                mock.patch.object(platformmod, "install", lambda *a, **k: order.append(("install", k))):
            _run(undo.perform, steps, {}, True)
            old = {"id": "p2", "kind": "platform", "scope": "vmware-w4p", "summary": "platform uninstall keda",
                   "data": {"inverse": "install", "items": ["keda"]}}
            _run(undo.perform, old, {}, True)
        self.assertEqual(order[:2], ["tools", ["/bin/helm", "rollback", "keda", "1", "-n", "keda"]])
        self.assertEqual(order[-1], ("install", {"wait": True, "summary": False}))


# ---------------------------------------------------------------------------------------------------- purge restore

class PurgeIntoCustomWorkdirTests(_Journal):
    """a2-ops#14: a purge of a never-deployed environment in a custom --workdir goes back there and is registered."""

    def _purged(self, name, workdir: Path | None):
        env = paths.Env("aws", name)
        if workdir is not None:
            env.set_workdir(workdir)
        else:
            shutil.rmtree(env.dir, ignore_errors=True)
            env.create_dirs()
        env.save({"cloud": "aws", "env": name, "name": "lab", "vars": {}})
        (env.ssh_dir / "id_ed25519").write_text("KEY")
        ub = undo.BACKUPS / f"w4-{name}"
        shutil.rmtree(ub, ignore_errors=True)
        ub.mkdir(parents=True)
        shutil.copy2(env.config_path, ub / "config.json")
        shutil.copytree(env.ssh_dir, ub / "ssh")
        files = {str(env.config_path): str(ub / "config.json"), str(env.ssh_dir): str(ub / "ssh")}
        data = {"files": files, "backup_dir": str(ub)}
        if workdir is not None:
            data["workdir"] = str(env.dir)
        where = env.dir
        shutil.rmtree(where / "ssh")
        (where / "config.json").unlink()
        shutil.rmtree(where / "stack", ignore_errors=True)
        shutil.rmtree(where / "logs", ignore_errors=True)
        index = paths._load_index()
        index.pop(env.id, None)
        paths._save_index(index)
        self.addCleanup(shutil.rmtree, where, True)
        return undo.record(env.id, f"destroy {env.id} --purge (nothing was deployed)", "restore-files", data), where

    def _workdir(self) -> Path:
        d = Path(tempfile.mkdtemp(prefix="cs-w4wd-")) / "wd"
        self.addCleanup(shutil.rmtree, d.parent, True)
        return d

    def test_the_environment_comes_back_registered_in_its_directory(self):
        wd = self._workdir()
        entry, where = self._purged("w4wd1", wd)
        self.assertNotIn("aws-w4wd1", {e.id for e in paths.Env.list_all()})
        self.assertIn(f"before the purge in {where}", undo.describe(entry))
        res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        env = paths.Env("aws", "w4wd1")
        self.assertEqual(Path(os.path.realpath(env.dir)), Path(os.path.realpath(wd)))
        self.assertEqual((env.ssh_dir / "id_ed25519").read_text(), "KEY")
        self.assertIn("aws-w4wd1", {e.id for e in paths.Env.list_all()})
        self.assertEqual(env.load()["name"], "lab")

    def test_a_directory_that_got_foreign_files_is_refused_and_the_entry_kept(self):
        wd = self._workdir()
        entry, where = self._purged("w4wd2", wd)
        (where / "notes.txt").write_text("mine")
        res, out = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("cannot go back into", str(res))
        self.assertNotIn("aws-w4wd2", paths._load_index())
        self.assertFalse((where / "config.json").exists())

    def test_a_directory_now_used_by_another_environment_is_refused(self):
        wd = self._workdir()
        entry, where = self._purged("w4wd3", wd)
        other = paths.Env("aws", "w4wd3b")
        other.set_workdir(where)
        other.save({"cloud": "aws", "env": "w4wd3b", "name": "x", "vars": {}})
        res, _ = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertEqual(paths.config_owner(where / "config.json"), "aws-w4wd3b")

    def test_default_purge_then_set_up_again_in_a_custom_directory_is_refused(self):   # round-3 leftover
        entry, _where = self._purged("w4wd4", None)
        wd = self._workdir()
        again = paths.Env("aws", "w4wd4")
        again.set_workdir(wd)
        again.save({"cloud": "aws", "env": "w4wd4", "name": "new-one", "vars": {}})
        res, _ = _run(undo.perform, entry, {}, True)
        self.assertIsInstance(res, ui.Abort)
        self.assertIn("set up again", str(res))
        self.assertFalse((paths.ENVS_DIR / "aws-w4wd4" / "config.json").exists())
        self.assertEqual(paths.Env("aws", "w4wd4").load()["name"], "new-one")

    def test_a_stale_claim_elsewhere_does_not_hide_a_default_restore(self):
        entry, where = self._purged("w4wd5", None)
        index = paths._load_index()
        index["aws-w4wd5"] = str(self._workdir())            # a directory that was never set up (no config.json)
        paths._save_index(index)
        res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertNotIn("aws-w4wd5", paths._load_index())
        self.assertEqual(paths.Env("aws", "w4wd5").load()["name"], "lab")

    def test_a_retry_after_a_partial_restore_goes_ahead(self):
        wd = self._workdir()
        entry, where = self._purged("w4wd6", wd)
        paths.Env("aws", "w4wd6").set_workdir(where)
        shutil.copy2(Path(entry["data"]["backup_dir"]) / "config.json", where / "config.json")
        res, out = _run(undo.perform, entry, {}, True)
        self.assertIsNone(res, out)
        self.assertEqual((where / "ssh" / "id_ed25519").read_text(), "KEY")


# ---------------------------------------------------------------------------------------------------- history

class HistoryLimitTests(_Journal):
    """e2e#23: a burst of one kind of change no longer pushes the rest of a session out."""

    def test_a_burst_of_one_kind_keeps_the_other_changes(self):
        s = "aws-w4keep"
        undo.record(s, "setup (created)", "created")
        undo.record(s, "platform install basek8s", "platform", {"inverse": "uninstall", "items": ["basek8s"]})
        undo.record(s, "dr backup b1", "dr-delete", {"what": "backup", "name": "b1"})
        for i in range(8):
            undo.record(s, f"kubectl edit {i}", "argv-seq", {"argvs": [["kubectl", str(i)]]})
        summaries = [e["summary"] for e in undo.entries(s)]
        self.assertEqual(summaries[:3], ["setup (created)", "platform install basek8s", "dr backup b1"])
        self.assertEqual(summaries[3:], [f"kubectl edit {i}" for i in range(3, 8)])     # five of that kind

    def test_the_total_is_capped_oldest_first(self):
        s = "aws-w4total"
        kinds = ["argv", "argv-seq", "platform", "helm", "dr-delete"]
        for i in range(undo.KEEP_TOTAL + 3):
            undo.record(s, f"c{i}", kinds[i % len(kinds)], {"n": i})
        summaries = [e["summary"] for e in undo.entries(s)]
        self.assertEqual(summaries, [f"c{i}" for i in range(3, undo.KEEP_TOTAL + 3)])

    def test_trimmed_entries_lose_their_backups(self):
        s = "aws-w4bk"
        b = undo.backup_file(__file__)
        undo.record(s, "first", "restore-files", {"files": {"/nonexistent/x": b}})
        for i in range(undo.KEEP):
            undo.record(s, f"later {i}", "restore-files", {"files": {f"/nonexistent/{i}": None}})
        self.assertFalse(Path(b).exists())


class HistoryListTests(_Journal):
    def test_times_are_marked_utc(self):
        e = undo.record("aws-w4utc", "update-ip aws-w4utc", "argv", {"argv": ["x"]})
        self.assertRegex(undo.when(e), r"^\d{4}-\d\d-\d\d \d\d:\d\d UTC$")
        self.assertEqual(undo.when({"at": "2026-09-24T06:32:50+00:00"}), "2026-09-24 06:32 UTC")
        self.assertEqual(undo.when({"at": "2026-09-24T08:32:50+02:00"}), "2026-09-24 06:32 UTC")
        stack, buf = _quiet()
        with stack, mock.patch.object(ui, "cols", lambda: 120):
            undo.print_list("aws-w4utc")
        self.assertIn(undo.when(e), ui._strip(buf.getvalue()))

    def test_a_z_suffix_and_a_bad_stamp(self):
        self.assertEqual(undo.when({"at": "2026-09-24T06:32:50Z"}), "2026-09-24 06:32 UTC")
        self.assertEqual(undo.when({"at": "garbage-stamp"}), "garbage-stamp")
        self.assertEqual(undo.when({}), "-")

    def test_a_long_sequence_wraps_instead_of_being_cut(self):
        argvs = [["mcp", "setup", "--no-service", "--transport", "http"], ["mcp", "connect", "claude-code", "cursor", "codex"],
                 ["mcp", "start"]]
        e = undo.record(undo.GLOBAL, "mcp uninstall", "argv-seq", {"argvs": argvs})
        stack, buf = _quiet()
        with stack, mock.patch.object(ui, "cols", lambda: 80):
            undo.print_list(undo.GLOBAL)
        out = ui._strip(buf.getvalue())
        self.assertIn("cloudseed mcp start", " ".join(out.split()))    # the last command is not cut off
        self.assertIn("id " + e["id"], out)
        for line in out.splitlines():
            self.assertLessEqual(ui.vis_len(line), ui.width())

    def test_a_wide_terminal_shows_every_command_of_a_sequence(self):   # the `mcp uninstall` inverse
        argvs = [["mcp", "setup", "--no-service"], ["mcp", "connect", "claude", "cursor"]]
        undo.record(undo.GLOBAL, "mcp uninstall", "argv-seq", {"argvs": argvs})
        stack, buf = _quiet()
        with stack, mock.patch.object(ui, "cols", lambda: 160):
            undo.print_list(undo.GLOBAL)
        self.assertIn("then cloudseed mcp connect claude cursor", ui._strip(buf.getvalue()))


class FilesTextTests(unittest.TestCase):
    """a2-ops#27: paths in cloudseed's home are named relative to it; a name two paths share is told apart."""

    def test_paths_in_cloudseeds_home_are_relative(self):
        go = paths.HOME / "go"
        go.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, go, True)
        text = undo.describe({"kind": "restore-files", "scope": "global", "summary": "install go",
                              "data": {"files": {str(paths.BIN_DIR / "go"): None, str(go): None}}})
        self.assertEqual(text, "delete bin/go, go/")

    def test_a_link_is_named_by_its_own_path(self):
        target = paths.HOME / "go" / "bin" / "go"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/bin/sh\n")
        link = paths.BIN_DIR / "go"
        paths.BIN_DIR.mkdir(parents=True, exist_ok=True)
        link.unlink(missing_ok=True)
        link.symlink_to(target)
        self.addCleanup(shutil.rmtree, paths.HOME / "go", True)
        self.addCleanup(link.unlink, missing_ok=True)
        text = undo.describe({"kind": "restore-files", "scope": "global", "summary": "install go",
                              "data": {"files": {str(link): None, str(paths.HOME / "go"): None}}})
        self.assertEqual(text, "delete bin/go, go/")

    def test_shared_names_are_told_apart(self):
        a, b = Path(tempfile.mkdtemp()) / "mcp.json", Path(tempfile.mkdtemp()) / "mcp.json"
        text = undo.describe({"kind": "restore-files", "scope": "global", "summary": "x", "data": {"files": {str(a): None, str(b): None}}})
        self.assertIn(str(a.parent.name), text)
        self.assertIn(str(b.parent.name), text)

    def test_the_question_counts_files_and_directories(self):
        d = Path(tempfile.mkdtemp(prefix="cs-w4q-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "new").mkdir()
        (d / "f").write_text("x")
        asked = []
        entry = {"kind": "restore-files", "scope": "global", "summary": "install go",
                 "data": {"files": {str(d / "new"): None, str(d / "f"): None}}}
        with mock.patch.object(cli, "_approve", lambda q, auto: asked.append(q)):
            _run(undo.perform, entry, {}, False)
        self.assertEqual(asked, ["Delete the 2 file(s)/dir(s) 'install go' added?"])
        self.assertFalse((d / "new").exists())


if __name__ == "__main__":
    unittest.main()
