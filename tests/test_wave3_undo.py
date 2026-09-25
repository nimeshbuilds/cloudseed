"""Regression tests for the wave-3 undo items: key-limited settings restores, a total order of journal entries,
purge restores (private directory, history), retried node rejoins, files changed since a command recorded them,
delete-paths that only empty shared folders, kubeconfig unmerge, and the history list. Stdlib only, no network."""

import contextlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, clouds, paths, ui, undo  # noqa: E402


def _quiet():
    buf = io.StringIO()
    stack = contextlib.ExitStack()
    stack.enter_context(contextlib.redirect_stdout(buf))
    stack.enter_context(contextlib.redirect_stderr(buf))
    return stack, buf


def _outside_home() -> Path:
    """A scratch directory outside cloudseed's home (a user's project, ~/.kube, a skills folder)."""
    d = Path(tempfile.mkdtemp(prefix="cs-w3undo-"))
    assert not undo._inside_home(d)
    return d


class _Journal(unittest.TestCase):
    """Each test starts with its own empty journal (the real one is kept aside and put back)."""

    def setUp(self):
        self._saved = undo.JOURNAL.read_text() if undo.JOURNAL.exists() else None
        undo.JOURNAL.unlink(missing_ok=True)
        self._settings = paths.load_settings()

    def tearDown(self):
        if self._saved is None:
            undo.JOURNAL.unlink(missing_ok=True)
        else:
            undo.JOURNAL.write_text(self._saved)
        paths.save_settings(self._settings)


# ---------------------------------------------------------------------------------------------------- settings

def _perform(data: dict, summary: str) -> str:
    stack, buf = _quiet()
    with stack:
        undo.perform({"kind": "settings-restore", "data": data, "scope": "global", "summary": summary}, {}, True)
    return buf.getvalue()


class SettingsRestoreTests(_Journal):
    def test_only_the_keys_of_the_entry_are_restored(self):
        paths.save_settings({"headliner": True})
        snap = undo.snapshot_settings(["runtime", "engine"])
        paths.save_settings({"headliner": True, "runtime": "local", "mcp": True, "current_env": "aws-x"})
        _perform(snap, "deps runtime local")
        self.assertEqual(paths.load_settings(), {"headliner": True, "mcp": True, "current_env": "aws-x"})

    def test_a_purged_current_env_does_not_come_back(self):
        # a2-ops#6: env use -> deps runtime -> purge (pops current_env) -> undo of deps runtime
        paths.save_settings({"headliner": True, "current_env": "aws-t3"})
        snap = undo.snapshot_settings(["runtime", "engine"])
        paths.save_settings({"headliner": True, "runtime": "local"})       # the purge popped current_env
        _perform(snap, "deps runtime local")
        self.assertEqual(paths.load_settings(), {"headliner": True})

    def test_a_previous_value_is_put_back_and_a_new_key_removed(self):
        paths.save_settings({"agent": "claude", "models": {"claude": "a"}})
        snap = undo.snapshot_settings(["agent", "models", "custom_models"])
        self.assertEqual(snap["settings"], {"agent": "claude", "models": {"claude": "a"}})   # only those keys are kept
        paths.save_settings({"agent": "codex", "models": {"claude": "a", "codex": "b"}, "custom_models": {"codex": ["b"]}, "ui": True})
        _perform(snap, "use codex")
        self.assertEqual(paths.load_settings(), {"agent": "claude", "models": {"claude": "a"}, "ui": True})

    def test_entry_without_key_list_restores_the_whole_snapshot(self):
        paths.save_settings({"a": 1, "b": 2})
        _perform({"settings": {"a": 0}}, "x")
        self.assertEqual(paths.load_settings(), {"a": 0})
        self.assertIn("all of them", undo.describe({"kind": "settings-restore", "data": {"settings": {}}, "scope": "global"}))

    def test_restoring_a_vanished_current_env_warns(self):
        paths.save_settings({"current_env": "aws-now"})
        stack, buf = _quiet()
        with stack:
            undo.perform({"kind": "settings-restore", "data": {"settings": {"current_env": "aws-w3gone"}, "what": ["current_env"]},
                          "scope": "global", "summary": "env use aws-now"}, {}, True)
        self.assertEqual(paths.load_settings()["current_env"], "aws-w3gone")
        self.assertIn("no longer exists", buf.getvalue())


# ---------------------------------------------------------------------------------------------------- order

class EntryOrderTests(_Journal):
    def test_same_second_entries_in_other_scopes_keep_recording_order(self):
        # a2-ops#9: the journal lists 'aws-w3deep' after 'global', and both entries share a timestamp
        undo.record("aws-w3deep", "placeholder", "info", {"advice": "x"})
        undo.record(undo.GLOBAL, "placeholder", "info", {"advice": "y"})
        for e in undo.entries():
            undo.pop(e)
        undo.record("aws-w3t1", "first scope key", "argv", {"argv": ["a"]})
        undo.record(undo.GLOBAL, "global key", "argv", {"argv": ["b"]})
        undo.record("aws-w3deep", "OLDER env change", "argv", {"argv": ["c"]})
        undo.record(undo.GLOBAL, "NEWER global change", "argv", {"argv": ["d"]})
        j = json.loads(undo.JOURNAL.read_text())
        for st in j.values():                  # force the tie the one-second timestamps produce
            for e in st:
                e["at"] = "2026-09-24T07:34:27+00:00"
        undo.JOURNAL.write_text(json.dumps(j))
        self.assertEqual(undo.latest()["summary"], "NEWER global change")
        self.assertEqual([e["summary"] for e in undo.entries()],
                         ["first scope key", "global key", "OLDER env change", "NEWER global change"])

    def test_legacy_entries_without_seq_sort_first_by_time(self):
        j = {"aws-w3old": [{"id": "a", "at": "2026-01-01T00:00:02+00:00", "scope": "aws-w3old", "summary": "old-2", "kind": "info", "data": {}},
                           {"id": "b", "at": "2026-01-01T00:00:01+00:00", "scope": "aws-w3old", "summary": "old-1", "kind": "info", "data": {}}]}
        undo.JOURNAL.write_text(json.dumps(j))
        undo.record(undo.GLOBAL, "new", "argv", {"argv": ["x"]})
        self.assertEqual([e["summary"] for e in undo.entries()], ["old-1", "old-2", "new"])

    def test_a_repeated_or_coalesced_entry_becomes_the_newest(self):
        undo.record("aws-w3a", "vpn connect", "argv", {"argv": ["vpn", "disconnect"]})
        undo.record(undo.GLOBAL, "other", "argv", {"argv": ["x"]})
        undo.record("aws-w3a", "vpn connect", "argv", {"argv": ["vpn", "disconnect"]})     # same change: merged
        self.assertEqual(len(undo.entries("aws-w3a")), 1)
        self.assertEqual(undo.latest()["scope"], "aws-w3a")
        undo.record(undo.GLOBAL, "env use a", "settings-restore", {"settings": {}, "what": ["current_env"]}, coalesce="current_env")
        undo.record("aws-w3a", "later", "argv", {"argv": ["y"]})
        undo.record(undo.GLOBAL, "env use b", "settings-restore", {"settings": {}, "what": ["current_env"]}, coalesce="current_env")
        self.assertEqual(undo.latest()["summary"], "env use b")

    def test_seq_is_stamped_and_bad_scopes_are_skipped(self):
        e1 = undo.record("aws-w3s", "a", "argv", {"argv": ["a"]})
        e2 = undo.record("aws-w3s", "b", "argv", {"argv": ["b"]})
        self.assertLess(e1["seq"], e2["seq"])
        j = json.loads(undo.JOURNAL.read_text())
        j["junk"] = 3                           # not a list: neither a scope nor entries
        undo.JOURNAL.write_text(json.dumps(j))
        self.assertNotIn("junk", undo.scopes())
        self.assertEqual(len(undo.entries()), 2)
        undo.pop(e2)
        self.assertEqual(undo.latest()["summary"], "a")


# ---------------------------------------------------------------------------------------------------- purge restore

class PurgeRestoreTests(_Journal):
    def _purged(self, name="w3purge"):
        env = paths.Env("aws", name)
        shutil.rmtree(env.dir, ignore_errors=True)
        env.create_dirs()
        env.save({"cloud": "aws", "env": name, "name": "lab", "vars": {}})
        (env.ssh_dir / "id_ed25519").write_text("KEY")
        audit.save(env, {"history": [{"action": "apply", "resources": 12}, {"action": "destroy", "resources": 0}]})
        (env.dir / "logs" / "audit.jsonl").write_text('{"command": "setup"}\n')
        keep = paths.HOME / "logs" / "purged" / env.id          # what _purge_env_dir keeps
        shutil.rmtree(keep, ignore_errors=True)
        keep.mkdir(parents=True)
        shutil.copy2(env.dir / "inventory.json", keep / "inventory.json")
        shutil.copy2(env.dir / "logs" / "audit.jsonl", keep / "audit.jsonl")
        ub = undo.BACKUPS / f"w3-{env.id}"
        shutil.rmtree(ub, ignore_errors=True)
        ub.mkdir(parents=True)
        shutil.copy2(env.config_path, ub / "config.json")
        shutil.copytree(env.ssh_dir, ub / "ssh")
        files = {str(env.config_path): str(ub / "config.json"), str(env.ssh_dir): str(ub / "ssh")}
        shutil.rmtree(env.dir)
        entry = undo.record(env.id, f"destroy {env.id} --purge (nothing was deployed)", "restore-files",
                            {"files": files, "backup_dir": str(ub)})
        return env, keep, entry

    def _perform(self, entry):
        old = os.umask(0o022)
        stack, buf = _quiet()
        audit.begin(["undo", "aws", "--env", "w3purge"])
        try:
            with stack:
                undo.perform(entry, {}, True)
        finally:
            audit.end(0)
            os.umask(old)
        return buf.getvalue()

    def test_directory_is_private_and_history_comes_back(self):
        env, keep, entry = self._purged()
        self._perform(entry)
        self.assertEqual(stat.S_IMODE(env.dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(env.ssh_dir.stat().st_mode), 0o700)
        self.assertEqual((env.ssh_dir / "id_ed25519").read_text(), "KEY")
        self.assertEqual(audit.load(env)["history"][-1]["action"], "destroy")
        self.assertIn('"setup"', (env.dir / "logs" / "audit.jsonl").read_text())
        self.assertTrue((keep / "audit.jsonl").exists())                  # a copy: the kept trail stays
        self.assertTrue((keep / "inventory.json").exists())

    def test_history_in_the_backup_dir_wins(self):
        env, keep, entry = self._purged("w3purge2")
        ub = Path(entry["data"]["backup_dir"])
        (ub / "logs").mkdir()
        (ub / "logs" / "audit.jsonl").write_text('{"command": "from-backup"}\n')
        self._perform(entry)
        self.assertIn("from-backup", (env.dir / "logs" / "audit.jsonl").read_text())

    def test_a_re_created_environment_is_not_overwritten(self):
        env, _keep, entry = self._purged("w3purge3")
        env.create_dirs()
        env.save({"cloud": "aws", "env": "w3purge3", "name": "new-one", "vars": {}})
        with self.assertRaises(ui.Abort) as cm:
            self._perform(entry)
        self.assertIn("set up again", str(cm.exception))
        self.assertEqual(env.load()["name"], "new-one")

    def test_other_restore_files_entries_create_no_environment(self):
        d = _outside_home()
        f = d / "new.txt"
        f.write_text("x")
        undo.perform({"kind": "restore-files", "data": {"files": {str(f): None}}, "scope": "aws-w3nope", "summary": "x"}, {}, True)
        self.assertFalse(f.exists())
        self.assertFalse(paths.Env("aws", "w3nope").dir.exists())


# ---------------------------------------------------------------------------------------------------- node rejoin

class RejoinRetryTests(_Journal):
    def test_a_retry_joins_the_node_the_failed_attempt_created(self):
        joined, msg, kept = self._undo_twice([[{"address": 'module.stack.module.kubernetes[0].vmdesktop_vm.node["wk3"]',
                                                "actions": ["create"]}], []])
        self.assertIn("running the same `cs undo` again joins lab-w3rejoin-wk3", msg)
        self.assertEqual(kept["pending_rejoin"], ["lab-w3rejoin-wk3"])
        self.assertEqual(joined, [["lab-w3rejoin-wk3"], ["lab-w3rejoin-wk3"]])

    def test_a_retry_after_an_unreadable_plan_runs_the_install_on_every_node_again(self):
        # the first attempt could not read its plan (install on every node) and that install failed; the retry's plan
        # is readable but creates nothing: it must not report "Undone" without installing
        joined, msg, kept = self._undo_twice([None, []])
        self.assertIn("runs the Kubernetes install on every node again", msg)
        self.assertTrue(kept["rejoin_all"])
        self.assertEqual(joined, [None, None])

    def _undo_twice(self, plans):
        from cloudseed import cli, provision
        env = paths.Env("vmware", "w3rejoin")
        shutil.rmtree(env.dir, ignore_errors=True)
        env.create_dirs()
        cur = {"cloud": "vmware", "env": "w3rejoin", "name": "lab", "vars": {"enable_kubernetes": True, "kubernetes_workers": 2},
               "state": {"type": "local"}, "workdir": str(env.dir)}
        env.save(dict(cur))
        prev = dict(cur, vars={"enable_kubernetes": True, "kubernetes_workers": 3})
        entry = undo.record(env.id, "node remove lab-w3rejoin-wk3", "config",
                            {"prev_cfg": prev, "what": "node count", "rejoin_nodes": True})

        class FakeTf:
            def __init__(self, workdir):
                pass

            def init(self, migrate=False):
                pass

            def plan_for_apply(self, cloud_key, cfg, out="tfplan", targets=(), render=None):
                pass

            def apply_reconciled(self, cloud_key, cfg, approve=None, **kw):
                pass

        joined = []

        def provision_k8s(cloud, env_, cfg, outputs, limit=None, **kw):
            joined.append(limit)
            if len(joined) == 1:
                raise ui.Abort("Kubernetes installation failed (exit 2). Re-run: cloudseed provision vmware --env w3rejoin --host k8s")

        outputs = {"kubernetes_control_plane_ips": ["10.0.0.20"], "kubernetes_worker_ips": ["10.0.0.40", "10.0.0.41", "10.0.0.42"]}
        with mock.patch("cloudseed.tf.Terraform", FakeTf), \
                mock.patch.object(cli, "_render", lambda c, e, cfg: False), \
                mock.patch.object(cli, "_approve", lambda q, auto: None), \
                mock.patch.object(cli, "_cache_outputs", lambda e, t: outputs), \
                mock.patch.object(cli, "_plan_changes", lambda t, planfile="tfplan": plans.pop(0)), \
                mock.patch.object(audit, "refresh", lambda *a, **k: None), \
                mock.patch.object(clouds.get("vmware").__class__, "prepare", lambda self, cfg, dry_run=False: None), \
                mock.patch.object(provision, "provision_local_kubernetes", provision_k8s):
            stack, _ = _quiet()
            audit.begin(["undo", "vmware", "--env", "w3rejoin"])
            try:
                with stack:
                    with self.assertRaises(ui.Abort) as cm:
                        undo.perform(entry, {}, True)
                    kept = undo.latest(env.id)
                    undo.perform(kept, {}, True)            # the retry: the VM exists, the plan creates nothing
            finally:
                audit.end(0)
        return joined, str(cm.exception), kept["data"]


# ---------------------------------------------------------------------------------------------------- changed files

class ChangedSinceTests(_Journal):
    def test_template_edited_after_generation_is_kept_as_a_copy(self):
        d = _outside_home()
        f = d / ".gitlab-ci.yml"
        f.write_text("stages: [plan]\n")
        entry = undo.record(undo.GLOBAL, "platform template gitlab-ci in proj", "restore-files", {"files": {str(f): None}})
        self.assertIn(str(f), entry["data"]["written"])
        f.write_text("stages: [plan]\n# user edits after generating: added my jobs\n")
        stack, buf = _quiet()
        with stack:
            undo.perform(entry, {}, True)
        self.assertFalse(f.exists())
        copies = list(d.glob(".gitlab-ci.yml.cloudseed-undo-*"))
        self.assertEqual(len(copies), 1)
        self.assertIn("added my jobs", copies[0].read_text())
        self.assertIn("Changed since", buf.getvalue())

    def test_unchanged_file_is_undone_without_a_copy(self):
        d = _outside_home()
        f = d / "ci.yml"
        f.write_text("new")
        b = undo.backup_file(f)
        f.write_text("generated")
        entry = undo.record(undo.GLOBAL, "platform template x", "restore-files", {"files": {str(f): b}})
        stack, _ = _quiet()
        with stack:
            undo.perform(entry, {}, True)
        self.assertEqual(f.read_text(), "new")
        self.assertEqual(list(d.glob("*.cloudseed-undo-*")), [])

    def test_interactive_decline_changes_nothing(self):
        from cloudseed import cli
        d = _outside_home()
        f = d / "ci.yml"
        f.write_text("generated")
        entry = undo.record(undo.GLOBAL, "platform template y", "restore-files", {"files": {str(f): None}})
        f.write_text("edited")
        asked = []

        def decline(q, auto, **kw):
            asked.append(q)
            raise ui.Abort("Cancelled. Nothing was changed.", code=0)

        stack, _ = _quiet()
        with stack, mock.patch.object(cli, "_approve", decline), self.assertRaises(ui.Abort):
            undo.perform(entry, {}, False)
        self.assertEqual(f.read_text(), "edited")
        self.assertIn("copies of the changed files are kept", asked[0])
        self.assertEqual(list(d.glob("*.cloudseed-undo-*")), [])

    def test_changed_skill_folder_is_copied_into_cloudseed_home(self):
        d = _outside_home()
        skill = d / "skills" / "cloudseed"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: cloudseed\n---\n")
        entry = undo.record(undo.GLOBAL, "skill install -> x", "restore-files", {"files": {str(skill): None}})
        (skill / ".DS_Store").write_text("finder")          # not a change of the user's
        self.assertEqual(undo._changed(entry["data"], [(str(skill), skill)]), [])
        (skill / "notes.md").write_text("mine")
        stack, _ = _quiet()
        with stack:
            undo.perform(entry, {}, True)
        self.assertFalse(skill.exists())
        self.assertEqual(list((d / "skills").iterdir()), [])            # no second skill folder next to it
        kept = [p for p in (paths.HOME / "undo-kept").iterdir() if p.name.endswith("-cloudseed")]
        self.assertTrue(any((p / "notes.md").exists() for p in kept))

    def test_files_in_cloudseed_home_are_not_fingerprinted(self):
        tok = paths.HOME / "w3-token"
        tok.write_text("a")
        entry = undo.record(undo.GLOBAL, "ui token --rotate", "restore-files", {"files": {str(tok): undo.backup_file(tok)}})
        self.assertNotIn("written", entry["data"])       # cloudseed rewrites it itself (recorded before the rotation)
        tok.write_text("b")
        stack, _ = _quiet()
        with stack:
            undo.perform(entry, {}, True)
        self.assertEqual(tok.read_text(), "a")
        tok.unlink()

    def test_a_repeat_still_takes_one_slot(self):
        d = _outside_home()
        f = d / "r.md"
        f.write_text("v1")
        a = undo.record("aws-w3rep", "report", "delete-paths", {"paths": [str(f)]}, minor=True)
        f.write_text("v2")
        b = undo.record("aws-w3rep", "report", "delete-paths", {"paths": [str(f)]}, minor=True)
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(undo.latest("aws-w3rep")["data"]["written"][str(f)], undo._fingerprint(f))   # the newest write

    def test_delete_paths_keeps_a_copy_of_an_edited_report(self):
        d = _outside_home()
        f = d / "report.md"
        f.write_text("generated")
        entry = undo.record("aws-w3rep2", "finops report report.md", "delete-paths", {"paths": [str(f)]}, minor=True)
        f.write_text("annotated by me")
        stack, _ = _quiet()
        with stack:
            undo.perform(entry, {}, True)
        self.assertFalse(f.exists())
        self.assertEqual([p.read_text() for p in d.glob("report.md.cloudseed-undo-*")], ["annotated by me"])


# ---------------------------------------------------------------------------------------------------- delete-paths

class DeletePathsTests(_Journal):
    def test_a_shared_folder_keeps_files_of_later_runs(self):
        d = _outside_home()
        raw = d / "scans" / "raw"
        before = undo.listing(d / "scans")
        raw.mkdir(parents=True)
        (raw / "first.json").write_text("1")
        (d / "scans" / "first.md").write_text("r")
        produced = undo.new_files_since(d / "scans", before)
        self.assertIn(str(raw), produced)
        (raw / "later-aborted.json").write_text("2")        # a later scan that recorded nothing
        stack, buf = _quiet()
        with stack:
            undo.perform({"kind": "delete-paths", "data": {"paths": produced}, "scope": "aws-w3", "summary": "scan"}, {}, True)
        self.assertFalse((raw / "first.json").exists())
        self.assertFalse((d / "scans" / "first.md").exists())
        self.assertTrue((raw / "later-aborted.json").exists())
        self.assertIn("Kept 1 folder", buf.getvalue())

    def test_an_emptied_folder_goes_too_nested_first(self):
        d = _outside_home()
        before = undo.listing(d)
        (d / "a" / "b").mkdir(parents=True)
        (d / "a" / "b" / "x.txt").write_text("x")
        (d / "a" / ".DS_Store").write_text("finder")
        produced = undo.new_files_since(d, before)
        stack, _ = _quiet()
        with stack:
            undo.perform({"kind": "delete-paths", "data": {"paths": produced}, "scope": "aws-w3", "summary": "x"}, {}, True)
        self.assertEqual(list(d.iterdir()), [])

    def test_a_sub_folder_that_was_empty_when_recorded_keeps_later_files(self):
        d = _outside_home()
        before = undo.listing(d / "scans")
        (d / "scans" / "raw" / "trivy").mkdir(parents=True)            # this scan left it empty
        (d / "scans" / "raw" / "first.json").write_text("1")
        produced = undo.new_files_since(d / "scans", before)
        (d / "scans" / "raw" / "trivy" / "later.json").write_text("2")   # a later run, undone out of order (--id)
        stack, _ = _quiet()
        with stack:
            undo.perform({"kind": "delete-paths", "data": {"paths": produced}, "scope": "aws-w3", "summary": "scan"}, {}, True)
        self.assertTrue((d / "scans" / "raw" / "trivy" / "later.json").exists())
        self.assertFalse((d / "scans" / "raw" / "first.json").exists())

    def test_a_folder_recorded_on_its_own_goes_as_a_whole(self):
        d = _outside_home()
        tool = d / "tool"
        tool.mkdir()
        (tool / "bin").write_text("x")
        stack, _ = _quiet()
        with stack:
            undo.perform({"kind": "delete-paths", "data": {"paths": [str(tool)]}, "scope": "aws-w3", "summary": "x"}, {}, True)
        self.assertFalse(tool.exists())


# ---------------------------------------------------------------------------------------------------- kubeconfig

FAKE_KUBECTL = textwrap.dedent('''\
    #!{python}
    # `kubectl config view [--raw] [-o json] --kubeconfig FILE`: the test kubeconfigs are JSON (valid YAML)
    import json, sys
    a = sys.argv[1:]
    path = a[a.index("--kubeconfig") + 1]
    try:
        data = json.load(open(path))
    except FileNotFoundError:
        data = {{"kind": "Config", "apiVersion": "v1", "clusters": None, "users": None, "contexts": None, "current-context": ""}}
    print(json.dumps(data))
    ''')


def _kc(contexts, current):
    return {"apiVersion": "v1", "kind": "Config", "current-context": current,
            "clusters": [{"name": n, "cluster": {"server": f"https://{n}:6443"}} for n in contexts],
            "users": [{"name": n, "user": {"token": f"tok-{n}"}} for n in contexts],
            "contexts": [{"name": n, "context": {"cluster": n, "user": n}} for n in contexts]}


class KubeconfigUnmergeTests(_Journal):
    def setUp(self):
        super().setUp()
        self.bin = _outside_home()
        self.kubectl = self.bin / "kubectl"
        self.kubectl.write_text(FAKE_KUBECTL.format(python=sys.executable))
        self.kubectl.chmod(0o755)
        self.kube = _outside_home() / "config"

    def _merge(self, before, after, env_name="w3kdemo"):
        """What `cs k8s kubeconfig vmware --env <env_name>` records (cli.cmd_k8s)."""
        if before is not None:
            self.kube.write_text(json.dumps(before))
        bak = undo.backup_file(self.kube)
        self.kube.write_text(json.dumps(after))
        return undo.record(f"vmware-{env_name}", f"k8s kubeconfig vmware-{env_name} (merged into {self.kube})", "restore-files",
                           {"files": {str(self.kube): bak}})

    def _undo(self, entry, kubectl=True):
        from cloudseed import deps
        stack, buf = _quiet()
        with stack, mock.patch.object(deps, "find", lambda name: str(self.kubectl) if kubectl and name == "kubectl" else None):
            undo.perform(entry, {}, True)
        return buf.getvalue()

    def test_contexts_added_since_by_other_tools_stay(self):
        entry = self._merge(_kc(["prod"], "prod"), _kc(["prod", "vmware-w3kdemo"], "vmware-w3kdemo"))
        self.assertIn("take the cluster entries it merged out of", undo.describe(entry))
        later = _kc(["prod", "vmware-w3kdemo", "eks-staging"], "eks-staging")      # e.g. aws eks update-kubeconfig
        self.kube.write_text(json.dumps(later))
        self._undo(entry)
        now = json.loads(self.kube.read_text())
        self.assertEqual([c["name"] for c in now["contexts"]], ["prod", "eks-staging"])
        self.assertEqual([c["name"] for c in now["clusters"]], ["prod", "eks-staging"])
        self.assertEqual([c["name"] for c in now["users"]], ["prod", "eks-staging"])
        self.assertEqual(now["current-context"], "eks-staging")          # the user's own choice since is kept
        self.assertEqual(stat.S_IMODE(self.kube.stat().st_mode), 0o600)

    def test_current_context_goes_back_and_replaced_entries_are_restored(self):
        old = _kc(["prod", "vmware-w3kdemo"], "prod")
        old["clusters"][1]["cluster"]["server"] = "https://old:6443"
        entry = self._merge(old, _kc(["prod", "vmware-w3kdemo"], "vmware-w3kdemo"))
        self._undo(entry)
        now = json.loads(self.kube.read_text())
        self.assertEqual(now["current-context"], "prod")
        self.assertEqual(now["clusters"][1]["cluster"]["server"], "https://old:6443")

    def test_new_file_is_deleted_only_when_nothing_else_is_in_it(self):
        entry = self._merge(None, _kc(["vmware-w3kdemo"], "vmware-w3kdemo"))
        self.kube.write_text(json.dumps(_kc(["vmware-w3kdemo", "gke-prod"], "vmware-w3kdemo")))
        self._undo(entry)
        now = json.loads(self.kube.read_text())
        self.assertEqual([c["name"] for c in now["contexts"]], ["gke-prod"])
        self.assertEqual(now["current-context"], "")
        self.kube.unlink()
        entry = self._merge(None, _kc(["vmware-w3kdemo"], "vmware-w3kdemo"))
        self._undo(entry)
        self.assertFalse(self.kube.exists())

    def test_without_kubectl_the_file_is_put_back_and_the_changed_one_kept(self):
        entry = self._merge(_kc(["prod"], "prod"), _kc(["prod", "vmware-w3kdemo"], "vmware-w3kdemo"))
        self.kube.write_text(json.dumps(_kc(["prod", "vmware-w3kdemo", "eks"], "eks")))
        self._undo(entry, kubectl=False)
        self.assertEqual(json.loads(self.kube.read_text()), _kc(["prod"], "prod"))
        copies = list(self.kube.parent.glob("config.cloudseed-undo-*"))
        self.assertEqual(len(copies), 1)
        self.assertIn('"eks"', copies[0].read_text())

    def test_managed_cluster_without_any_record_is_left_alone(self):
        before = _kc(["prod"], "prod")
        self.kube.write_text(json.dumps(before))
        bak = undo.backup_file(self.kube)
        after = _kc(["prod", "arn:aws:eks:us-west-2:1:cluster/x"], "arn:aws:eks:us-west-2:1:cluster/x")
        self.kube.write_text(json.dumps(after))
        entry = undo.record("aws-w3nokc", f"k8s kubeconfig aws-w3nokc (merged into {self.kube})", "restore-files",
                            {"files": {str(self.kube): bak}})
        out = self._undo(entry)
        self.assertIn("no record", out)
        self.assertEqual(json.loads(self.kube.read_text()), after)       # nothing guessed, nothing lost

    def test_recorded_names_are_used_when_the_merge_gives_them(self):
        entry = self._merge(_kc(["prod"], "prod"), _kc(["prod", "gke_p_z_c"], "gke_p_z_c"))
        entry["data"]["kubeconfig"] = {"names": {"contexts": ["gke_p_z_c"], "clusters": ["gke_p_z_c"], "users": ["gke_p_z_c"]},
                                       "prev_current": "prod", "set_current": "gke_p_z_c"}
        self.assertIn("take gke_p_z_c out of", undo.describe(entry))
        self._undo(entry)
        self.assertEqual(json.loads(self.kube.read_text())["current-context"], "prod")
        self.assertEqual([c["name"] for c in json.loads(self.kube.read_text())["contexts"]], ["prod"])

    @unittest.skipUnless(shutil.which("kubectl"), "needs kubectl")
    def test_real_kubectl_round_trip_keeps_yaml(self):
        from cloudseed import deps
        self.kube.write_text(textwrap.dedent("""\
            apiVersion: v1
            kind: Config
            clusters:
            - cluster:
                certificate-authority: ca.crt
                server: https://1.2.3.4:6443
              name: prod
            contexts:
            - context:
                cluster: prod
                user: prod
              name: prod
            current-context: prod
            users:
            - name: prod
              user:
                token: t
            """))
        bak = undo.backup_file(self.kube)
        merged = _kc(["vmware-w3kdemo"], "vmware-w3kdemo")
        tmp = self.kube.with_name("add.json")
        tmp.write_text(json.dumps(merged))
        import subprocess
        out = subprocess.run([shutil.which("kubectl"), "config", "view", "--raw"], capture_output=True, text=True,
                             env=dict(os.environ, KUBECONFIG=f"{tmp}{os.pathsep}{self.kube}")).stdout
        tmp.unlink()
        self.kube.write_text(out)
        entry = undo.record("vmware-w3kdemo", f"k8s kubeconfig vmware-w3kdemo (merged into {self.kube})", "restore-files",
                            {"files": {str(self.kube): bak}})
        stack, _ = _quiet()
        with stack, mock.patch.object(deps, "find", lambda name: shutil.which(name)):
            undo.perform(entry, {}, True)
        text = self.kube.read_text()
        self.assertIn("current-context: prod", text)
        self.assertIn("certificate-authority: ca.crt", text)             # a relative path keeps its meaning
        self.assertNotIn("vmware-w3kdemo", text)
        self.assertFalse(text.lstrip().startswith("{"))                  # kubectl's YAML, not JSON


# ---------------------------------------------------------------------------------------------------- list

class HistoryListTests(_Journal):
    def test_descriptions_are_cut_at_a_word_and_ids_stay_whole(self):
        e = undo.record("aws-w3list", "platform install " + " ".join(f"item{i}" for i in range(30)), "platform",
                        {"inverse": "uninstall", "items": [f"velero-item-{i}" for i in range(30)]})
        for cols in (100, 50):
            stack, buf = _quiet()
            with stack, mock.patch.object(ui, "cols", lambda c=cols: c):
                undo.print_list("aws-w3list")
            out = ui._strip(buf.getvalue())
            self.assertIn("id " + e["id"], out)
            self.assertIn("…", out)
            for line in out.splitlines():
                self.assertLessEqual(ui.vis_len(line), ui.width())
                for word in re.findall(r"velero-\S*", line):          # never cut inside a name
                    self.assertRegex(word, r"^velero-item-\d+[,…]?$")

    def test_narrow_terminal_gives_the_summary_its_own_line(self):
        undo.record("aws-w3list2", "destroy aws-w3list2 --purge (nothing was deployed)", "info", {"advice": "x"})
        stack, buf = _quiet()
        with stack, mock.patch.object(ui, "cols", lambda: 60):
            undo.print_list("aws-w3list2")
        self.assertIn("destroy aws-w3list2 --purge (nothing was deployed)", ui._strip(buf.getvalue()))


if __name__ == "__main__":
    unittest.main()
