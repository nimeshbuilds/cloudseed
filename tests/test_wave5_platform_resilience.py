"""Wave-5 (final) platform + resilience regressions: `cs dr describe|logs` and the hints that point at them, the
kept-drill undo (dr-drill), the --no-wait restore an undo must not race, whole-cluster deletes whose undo point keeps
volume data, the host scan's own re-run advice, MinIO access keys generated per environment (older installs keep
theirs until they are re-applied), MetalLB's pool on networks smaller than /24, `--set mode=` as a chart value when no
mesh is in the request, the echoed managed-CLI line without Authorization headers, error hints that never offer a help
topic as a command, and the GKE control-plane version the bastion's kubectl follows. Stdlib only; every cluster, tool
and SSH call is faked."""

from __future__ import annotations

import contextlib
import io
import ipaddress
import itertools
import json
import os
import re
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, dr, managed, mcp, paths, provision as prov, scan, services, ui, undo  # noqa: E402
from cloudseed import help as helpmod  # noqa: E402
from cloudseed import platform as pl  # noqa: E402

_RUN = uuid.uuid4().hex[:4]   # per test run: a reused CLOUDSEED_HOME never hands back an earlier run's environment

_n = [0]


def cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


@contextlib.contextmanager
def silenced():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


def text_of(out, err) -> str:
    return ui._strip(out.getvalue() + err.getvalue())


def fresh_env(target: str = "vmware") -> paths.Env:
    _n[0] += 1
    env = paths.Env(target, f"w5p{_RUN}x{_n[0]}")
    env.create_dirs()
    return env


def make_ctx(target: str = "vmware", vars_: dict | None = None, outputs: dict | None = None, cidr: str = "10.0.0.0/24") -> pl.Cluster:
    env = fresh_env(target)
    cfg = {"env": env.name, "name": "t", "region": "us-east-1", "network_cidr": cidr, "vars": dict(vars_ or {})}
    out = dict(outputs if outputs is not None else ({"kubernetes_distro": "rke2"} if target == "vmware" else {"kubernetes_cluster_name": "c"}))
    return pl.Cluster(clouds.get(target), env, cfg, out, env.dir / "kubeconfig")


def locations(config) -> str:
    return json.dumps({"items": [{"metadata": {"name": "default"}, "spec": {"provider": "aws", "config": config}}]})


# ---------------------------------------------------------------- cs dr describe | logs (core e2e#20)

class DrShowTests(unittest.TestCase):
    def parse(self, *argv):
        return cli.build_parser().parse_args(["dr", *argv])

    def test_parser_takes_the_kind_and_the_name(self):
        a = self.parse("describe", "backup", "b1", "vmware", "--env", "lab", "--details")
        self.assertEqual((a.dr_cmd, a.kind, a.name, a.cloud, a.details), ("describe", "backup", "b1", "vmware", True))
        a = self.parse("logs", "restore", "r1")
        self.assertEqual((a.kind, a.name, a.cloud), ("restore", "r1", None))
        a = self.parse("describe", "backup", "aws", "--cloud", "vmware")   # a backup named like a cloud: --cloud
        self.assertEqual((a.kind, a.name, a.cloud), ("backup", "aws", "vmware"))
        for bad in (["describe", "b1"], ["logs", "schedule", "n"], ["describe", "backup", "a", "b"]):
            with silenced(), self.assertRaises(SystemExit) as cm:
                self.parse(*bad)
            self.assertEqual(cm.exception.code, 2, bad)
        a = self.parse("backup", "b1")
        self.assertIsNone(a.kind)

    def test_names_are_checked_before_any_cluster_work(self):
        with self.assertRaises(SystemExit) as cm:
            cli._check_dr_args(SimpleNamespace(dr_cmd="describe", kind="backup", name="Bad_Name", namespaces=None))
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("not a valid backup name", cm.exception.msg)
        cli._check_dr_args(SimpleNamespace(dr_cmd="logs", kind="restore", name="b1-restore-20260101000000", namespaces=None))
        with self.assertRaises(SystemExit):
            cli._check_dr_args(SimpleNamespace(dr_cmd="logs", kind=None, name="x", namespaces=None))

    def test_read_only_everywhere(self):
        for sub in ("describe", "logs"):
            self.assertTrue(cli._changes_nothing(SimpleNamespace(cmd="dr", dr_cmd=sub)))
        argv = mcp.TOOLS["cloudseed_dr"]["argv"]({"action": "describe", "kind": "backup", "name": "b1", "details": True, "cloud": "vmware"})
        self.assertEqual(argv[:4], ["dr", "describe", "backup", "b1"])
        self.assertIn("--details", argv)
        self.assertNotIn("--auto-approve", argv)
        self.assertFalse(mcp._is_destructive(mcp.TOOLS["cloudseed_dr"], {"action": "logs", "kind": "restore", "name": "r"}))
        self.assertNotIn("--details", mcp.TOOLS["cloudseed_dr"]["argv"]({"action": "logs", "kind": "restore", "name": "r", "details": True}))
        with self.assertRaises(ValueError):
            mcp.TOOLS["cloudseed_dr"]["argv"]({"action": "describe", "name": "b1"})
        ns = cli.build_parser().parse_args(argv)
        self.assertEqual((ns.kind, ns.name, ns.details), ("backup", "b1", True))

    def run_show(self, ctx, storage, cli_ok=True, verb="describe", details=True):
        calls = []

        def kubectl(ctx_, *args, **kw):
            return cp(0, locations(storage)) if "backupstoragelocations.velero.io" in args else cp(0)

        def call(cmd, env=None):
            calls.append(list(cmd))
            return 0
        ensure = mock.patch.object(dr, "ensure_cli", return_value="/home/.cloudseed/bin/velero") if cli_ok else \
            mock.patch.object(dr, "ensure_cli", side_effect=ui.Abort("not fetched in an agent session", code=2))
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_kubectl", kubectl), ensure, \
                mock.patch.object(dr, "kubectl_path", return_value="kubectl"), mock.patch.object(dr.subprocess, "call", call), \
                mock.patch.object(dr.audit, "write"), silenced() as (out, err):
            rc = dr.show(ctx, verb, "backup", "b1", details=details)
        return rc, calls, text_of(out, err)

    def test_the_cli_here_with_the_environments_kubeconfig(self):
        rc, calls, _ = self.run_show(make_ctx("aws"), {"region": "us-east-1"})
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [["/home/.cloudseed/bin/velero", "-n", "velero", "backup", "describe", "b1", "--details"]])

    def test_in_cluster_minio_runs_in_the_velero_pod(self):
        rc, calls, text = self.run_show(make_ctx("vmware"), {"s3Url": "http://minio.minio.svc:9000"}, verb="logs")
        self.assertEqual(calls, [["kubectl", "-n", "velero", "exec", "svc/velero", "-c", "velero", "--", "/velero", "-n", "velero",
                                  "backup", "logs", "b1"]])   # --details goes with describe only
        self.assertIn("-- /velero backup logs b1", text)

    def test_no_cli_here_falls_back_to_the_pod(self):
        rc, calls, text = self.run_show(make_ctx("aws"), {"region": "us-east-1"}, cli_ok=False)
        self.assertEqual(calls[0][:5], ["kubectl", "-n", "velero", "exec", "svc/velero"])
        self.assertIn("running velero in the velero pod", text)

    def test_missing_velero_is_never_installed(self):
        with mock.patch.object(dr, "installed", return_value=False), self.assertRaises(SystemExit) as cm:
            dr.show(make_ctx("aws"), "describe", "backup", "b1")
        self.assertIn("cs platform install velero", cm.exception.msg)

    def test_hints_name_the_commands_and_never_a_bare_velero(self):
        ctx = make_ctx("aws")
        name = ctx.env.name
        with mock.patch.object(dr, "_kubectl", side_effect=AssertionError("a hint reads nothing from the cluster")):
            self.assertEqual(dr.velero_hint(ctx, "backup", "describe", "b1", "--details"), f"cs dr describe backup b1 --details aws --env {name}")
            self.assertEqual(dr.velero_hint(ctx, "restore", "logs", "r1"), f"cs dr logs restore r1 aws --env {name}")
            self.assertEqual(dr.velero_hint(ctx, "backup", "describe", "vmware"), f"cs dr describe backup vmware --cloud aws --env {name}")
            self.assertTrue(dr.velero_hint(ctx, "backup", "delete", "b1", "--confirm").startswith(f"cs kubectl aws --env {name} -n velero exec"))
        a = cli.build_parser().parse_args(dr.velero_hint(ctx, "backup", "describe", "vmware").split()[1:])
        self.assertEqual((a.kind, a.name, a.cloud), ("backup", "vmware", "aws"))
        self.assertFalse(hasattr(dr, "require_restorable"))   # dead code: cli._restorable_backup is the check

    def test_help_and_docs_name_them(self):
        page = helpmod.COMMANDS["dr"]
        self.assertIn("dr describe backup|restore <name> [--details]", page)
        self.assertIn("--details", page)
        for f in ("docs/guides/manual.md", "skills/cloudseed-platform/SKILL.md"):
            self.assertIn("describe|logs backup|restore <name>", (paths.REPO_ROOT / f).read_text(), f)


# ---------------------------------------------------------------- dr-drill undo (a2-resilience#18 A)

class Kube:
    """dr._kubectl / dr._velero stand-ins recording the calls."""

    def __init__(self, ns_rc=0, velero=None, velero_raises=False):
        self.calls, self.ns_rc, self.velero_out, self.velero_raises = [], ns_rc, velero or cp(0), velero_raises

    def kubectl(self, ctx, *args, **kw):
        self.calls.append(("kubectl",) + args)
        if args[:2] == ("delete", "ns"):
            return cp(self.ns_rc, "", "" if not self.ns_rc else "Unable to connect to the server")
        return cp(0)

    def velero(self, ctx, *args, **kw):
        if self.velero_raises:
            raise ui.Abort("The velero CLI v1.18.2 is not installed", code=2)
        self.calls.append(("velero",) + args)
        return self.velero_out


class DrDrillUndoTests(unittest.TestCase):
    def perform(self, data, kube):
        ctx = make_ctx("vmware")
        entry = {"id": "x", "scope": ctx.env.id, "kind": "dr-drill", "summary": "dr test", "data": data}
        # (the kept backup's phase is read first: a backup still being written is refused, see test_wave5_ops_undo)
        with mock.patch.object(undo, "_cluster", return_value=(None, ctx.env, {}, {}, ctx)), \
                mock.patch.object(dr, "_kubectl", kube.kubectl), mock.patch.object(dr, "_velero", kube.velero), \
                mock.patch.object(dr, "_phase", return_value="Completed"), \
                mock.patch.object(undo, "_audit_start"), silenced():
            undo.perform(entry, {}, True)

    def test_describe(self):
        self.assertEqual(undo.describe({"kind": "dr-drill", "data": {"namespace": dr.DRILL_NS, "backup": "dr-test-1"}}),
                         f"delete the kept DR drill namespace {dr.DRILL_NS} and its Velero backup dr-test-1")
        self.assertEqual(undo.describe({"kind": "dr-drill", "data": {"namespace": dr.DRILL_NS, "backup": None}}),
                         f"delete the kept DR drill namespace {dr.DRILL_NS}")

    def test_namespace_then_backup_and_a_gone_backup_is_fine(self):
        kube = Kube(velero=cp(1, "", 'An error occurred: backups.velero.io "dr-test-1" not found'))
        self.perform({"namespace": dr.DRILL_NS, "backup": "dr-test-1"}, kube)
        self.assertEqual(kube.calls[0], ("kubectl", "delete", "ns", dr.DRILL_NS, "--ignore-not-found", "--wait=false"))
        self.assertEqual(kube.calls[1], ("velero", "backup", "delete", "dr-test-1", "--confirm"))

    def test_a_backup_gone_with_velero_is_fine(self):
        kube = Kube(velero=cp(1, "", "Error: the server could not find the requested resource (get backups.velero.io)"))
        self.perform({"namespace": dr.DRILL_NS, "backup": "dr-test-1"}, kube)
        self.assertEqual(kube.calls[-1][:3], ("velero", "backup", "delete"))

    def test_no_backup_no_velero(self):
        kube = Kube(velero_raises=True)
        self.perform({"namespace": dr.DRILL_NS, "backup": None}, kube)
        self.assertEqual([c[0] for c in kube.calls], ["kubectl"])

    def test_without_a_cli_the_pod_deletes_it(self):
        kube = Kube(velero_raises=True)
        self.perform({"namespace": dr.DRILL_NS, "backup": "dr-test-1"}, kube)
        self.assertIn("/velero", kube.calls[-1])
        self.assertEqual(kube.calls[-1][-3:], ("delete", "dr-test-1", "--confirm"))

    def test_without_a_cli_a_running_backup_is_still_refused(self):
        # (integration of the pod fallback with w5/ops-undo's running-backup refusal) no velero CLI means dr._phase
        # cannot read the phase: the Backup object is read instead, and the pod's delete (which Velero accepts, then
        # ignores for a backup in progress) is never sent
        ctx = make_ctx("vmware")
        entry = {"id": "x", "scope": ctx.env.id, "kind": "dr-drill", "summary": "dr test",
                 "data": {"namespace": dr.DRILL_NS, "backup": "dr-test-1"}}
        for phase, refused in (("InProgress", True), ("Completed", False), ("", False)):
            kube = Kube(velero_raises=True)
            real = kube.kubectl

            def kubectl(c, *args, **kw):
                if "get" in args and "backups.velero.io" in args:
                    kube.calls.append(("kubectl",) + args)
                    return cp(0, phase)
                return real(c, *args, **kw)
            with mock.patch.object(undo, "_cluster", return_value=(None, ctx.env, {}, {}, ctx)), \
                    mock.patch.object(dr, "_kubectl", kubectl), mock.patch.object(dr, "_velero", kube.velero), \
                    mock.patch.object(undo, "_audit_start"), silenced():
                if refused:
                    with self.assertRaises(SystemExit) as cm:
                        undo.perform(entry, {}, True)
                    self.assertIn("dr-test-1 is still InProgress", cm.exception.msg)
                    self.assertEqual([c[1:3] for c in kube.calls], [("-n", "velero")])   # only the read
                else:
                    undo.perform(entry, {}, True)
                    self.assertEqual(kube.calls[-1][-3:], ("delete", "dr-test-1", "--confirm"), phase)

    def test_failures_keep_the_entry(self):
        with self.assertRaises(SystemExit) as cm:
            self.perform({"namespace": dr.DRILL_NS, "backup": "b"}, Kube(ns_rc=1))
        self.assertIn("undo entry is kept", cm.exception.msg)
        with self.assertRaises(SystemExit) as cm:
            self.perform({"namespace": dr.DRILL_NS, "backup": "b"}, Kube(velero=cp(1, "", "An error occurred: connection refused")))
        self.assertIn("connection refused", cm.exception.msg)

    def test_cs_dr_test_keep_records_it(self):
        env = fresh_env("vmware")
        cfg = {"env": env.name, "name": "t", "region": "", "network_cidr": "10.0.0.0/24", "vars": {}}
        env.save(cfg)
        a = cli.build_parser().parse_args(["dr", "test", "--cloud", "vmware", "--env", env.name, "--keep"])

        def fake_test(ctx, keep=False, with_volume=None):
            ctx.dr_drill = {"namespace": dr.DRILL_NS, "backup": "dr-test-9", "kept": keep}
            return 0
        try:
            with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, cfg, {})), \
                    mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                    mock.patch.object(cli.dr, "installed", return_value=True), mock.patch.object(cli.dr, "test", fake_test), silenced():
                self.assertEqual(cli.cmd_dr(a, {}), 0)
            e = undo.latest(env.id)
            self.assertEqual((e["kind"], e["data"], e["minor"]), ("dr-drill", {"namespace": dr.DRILL_NS, "backup": "dr-test-9"}, True))
            self.assertIn("dr-drill", cli._UNDO_NEEDS_ENV)
            self.assertIn("dr-drill", cli._UNDO_TOOLCHAIN)
        finally:
            undo.clear(env.id)


# ---------------------------------------------------------------- dr restore --no-wait vs undo (a2-resilience#18 A)

class RestoreUndoRaceTests(unittest.TestCase):
    def perform(self, data, phase):
        ctx = make_ctx("vmware")
        entry = {"id": "x", "scope": ctx.env.id, "kind": "velero-restore", "summary": "dr restore b1", "data": data}
        restored = []
        with mock.patch.object(undo, "_cluster", return_value=(None, ctx.env, {}, {}, ctx)), \
                mock.patch.object(dr, "_phase", return_value=phase) as ph, mock.patch.object(dr, "_kubectl", return_value=cp(0)), \
                mock.patch.object(dr, "restore", side_effect=lambda *a, **k: restored.append(a[1])), \
                mock.patch.object(undo, "_verify_restored"), mock.patch.object(undo, "_audit_start"), silenced():
            undo.perform(entry, {}, True)
        return ph, restored

    def test_a_running_restore_is_not_undone(self):
        for phase in ("New", "InProgress"):
            with self.assertRaises(SystemExit) as cm:
                self.perform({"backup": "pre-restore-1", "new_namespaces": [], "restore": "b1-restore-1"}, phase)
            self.assertIn(f"Restore b1-restore-1 is still {phase}", cm.exception.msg)
            self.assertIn("cs dr describe restore b1-restore-1", cm.exception.msg)

    def test_finished_or_unknown_goes_ahead(self):
        for phase in ("Completed", "PartiallyFailed", None):
            ph, restored = self.perform({"backup": "pre-restore-1", "new_namespaces": [], "restore": "b1-restore-1"}, phase)
            self.assertEqual(restored, ["pre-restore-1"], phase)
        ph, restored = self.perform({"backup": "pre-restore-1", "new_namespaces": []}, "InProgress")   # an older entry
        ph.assert_not_called()
        self.assertEqual(restored, ["pre-restore-1"])

    def test_cs_dr_restore_stores_the_restore_name(self):
        recorded = []
        args = SimpleNamespace(name="b1", namespaces=None, no_wait=True, auto_approve=True)
        env = SimpleNamespace(id="vmware-x", name="x")
        with mock.patch.object(cli, "_restorable_backup", return_value={"spec": {"includedNamespaces": ["shop"]}}), \
                mock.patch.object(cli, "_approve_worded"), mock.patch.object(cli, "_namespaces_now", return_value={"shop"}), \
                mock.patch.object(cli.undo, "velero_pre_backup", return_value="pre-restore-1"), \
                mock.patch.object(cli, "_velero_names", return_value=set()), \
                mock.patch.object(cli.dr, "restore", return_value="b1-restore-20260101000000"), \
                mock.patch.object(cli.undo, "record", side_effect=lambda *a, **k: recorded.append(a)):
            cli._dr_restore(args, clouds.get("vmware"), env, None)
        self.assertEqual(recorded[0][2], "velero-restore")
        self.assertEqual(recorded[0][3]["restore"], "b1-restore-20260101000000")

    def test_ctrl_c_during_the_wait_keeps_the_running_restores_name(self):
        recorded = []
        args = SimpleNamespace(name="b1", namespaces=None, no_wait=False, auto_approve=True)
        env = SimpleNamespace(id="vmware-x", name="x")
        names = iter([set(), {"b1-restore-20260101000000"}])
        with mock.patch.object(cli, "_restorable_backup", return_value={"spec": {"includedNamespaces": ["shop"]}}), \
                mock.patch.object(cli, "_approve_worded"), mock.patch.object(cli, "_namespaces_now", return_value={"shop"}), \
                mock.patch.object(cli.undo, "velero_pre_backup", return_value="pre-restore-1"), \
                mock.patch.object(cli, "_velero_names", side_effect=lambda c, k: next(names)), \
                mock.patch.object(cli.dr, "_status", return_value={"phase": "InProgress"}), \
                mock.patch.object(cli.dr, "restore", side_effect=KeyboardInterrupt), \
                mock.patch.object(cli.undo, "record", side_effect=lambda *a, **k: recorded.append(a)), self.assertRaises(KeyboardInterrupt):
            cli._dr_restore(args, clouds.get("vmware"), env, None)
        self.assertEqual(recorded[0][3]["restore"], "b1-restore-20260101000000")
        self.assertIn("failed part-way", recorded[0][1])

    def test_velero_errors_are_worded_by_velero_error(self):
        usage = "Error: unknown flag: --bogus\nUsage:\n  velero backup get [flags]\n"
        with mock.patch.object(cli.dr, "_velero", return_value=cp(1, "", usage)), self.assertRaises(SystemExit) as cm:
            cli._restorable_backup(None, "b1")
        self.assertIn("unknown flag: --bogus", cm.exception.msg)
        self.assertNotIn("Usage", cm.exception.msg)


# ---------------------------------------------------------------- whole-cluster deletes keep volume data (undo review)

class WholeClusterDeleteVolumesTests(unittest.TestCase):
    def pre(self, rest):
        ctx = SimpleNamespace(procenv=lambda: {}, kubeconfig=Path("/tmp/kc"))
        env = SimpleNamespace(name="lab", id="vmware-lab")
        with mock.patch.object(cli.undo, "velero_pre_backup", return_value="pre-x") as vb, \
                mock.patch.object(cli, "_namespaces_now", return_value={"shop", "default"}), \
                mock.patch.object(cli.dr, "installed", return_value=True):
            cli._pre_change_undo("kubectl", rest, clouds.get("vmware"), env, {}, {}, Path("/tmp/kc"), ctx=ctx)
        return vb.call_args

    def test_deleting_across_the_cluster_keeps_volumes(self):
        for rest in (["delete", "pvc", "--all", "-A"], ["delete", "ns", "--all"], ["delete", "ns", "-l", "team=a"],
                     ["delete", "-f", "app.yaml"], ["delete", "crd", "things.example.com"], ["delete", "pv", "pv-1"],
                     ["delete", "clusterrole/x", "pvc/data"], ["delete", "clusterrole", "x", "-A"]):
            call = self.pre(rest)
            self.assertIsNone(call[0][2], rest)
            self.assertIs(call[1].get("volumes"), True, rest)

    def test_other_points_keep_the_default(self):
        # a delete of cluster-scoped kinds that hold no data is a whole-cluster point too, but objects only: copying
        # every volume in the cluster before removing a ClusterRole would only be slow
        for rest in (["-n", "shop", "delete", "pvc", "data"], ["label", "ns", "--all", "team=a"], ["delete", "ns", "shop"],
                     ["delete", "clusterrole", "x"], ["delete", "storageclass,clusterrolebinding", "a"],
                     ["delete", "validatingwebhookconfiguration/w"]):
            call = self.pre(rest)
            self.assertNotIn("volumes", call[1], rest)


# ---------------------------------------------------------------- scan host: its own re-run advice (a2-resilience#20f)

class ScanRerunAdviceTests(unittest.TestCase):
    def test_an_unreachable_host_says_to_re_run_the_scan(self):
        env = fresh_env("aws")
        cloud = clouds.get("aws")
        cfg = {"name": "t", "env": env.name, "vars": {}, "ssh_public_key": ""}
        timeout = cp(255, "", "ssh: connect to host 198.51.100.7 port 22: Operation timed out\n")
        clock = itertools.chain([0, 0], itertools.count(1000, 1000))   # one SSH attempt, then past the deadline
        with mock.patch.object(scan, "_hosts", return_value=[("bastion", "198.51.100.7")]), \
                mock.patch.object(prov.subprocess, "run", return_value=timeout), \
                mock.patch.object(prov.time, "time", lambda: next(clock)), mock.patch.object(prov.time, "sleep"), \
                silenced(), self.assertRaises(SystemExit) as cm:
            scan.host(cloud, env, cfg, {"bastion_public_ip": "198.51.100.7"}, ["bastion"], profile="stig")
        msg = cm.exception.msg
        self.assertIn(f"then re-run the scan (cs scan stig aws --env {env.name}).", msg)
        self.assertIn("did not accept SSH within 120s", msg)
        self.assertNotIn("cloudseed provision", msg)
        self.assertFalse(hasattr(scan, "_rerun_hint"))


# ---------------------------------------------------------------- MinIO access keys (a2-platform-catalog#23)

class MinioUserTests(unittest.TestCase):
    def test_older_installs_keep_their_well_known_names(self):
        ctx = make_ctx("vmware")
        ph = ctx.placeholders()
        self.assertEqual((ph["minio_root_user"], ph["minio_velero_user"], ph["minio_spark_user"]), ("admin", "velero", "spark"))
        self.assertTrue(all(ctx.minio_user_is_legacy(i) for i in pl.MINIO_USERS))
        self.assertNotIn("minio_root_user", json.loads((ctx.workdir / "secrets.json").read_text()))   # nothing generated

    def test_an_install_generates_them_once(self):
        ctx = make_ctx("vmware")
        for item in pl.MINIO_USERS:
            ctx.settle_minio_user(item)
        ph = ctx.placeholders()
        for key, prefix in (("minio_root_user", "admin"), ("minio_velero_user", "velero"), ("minio_spark_user", "spark")):
            self.assertRegex(ph[key], rf"^{prefix}-[0-9a-f]{{12}}$")
            self.assertLessEqual(len(ph[key]), 20)   # MinIO's access key limit
        first = dict(ph)
        for item in pl.MINIO_USERS:
            ctx.settle_minio_user(item)
        self.assertEqual(ctx.placeholders()["minio_velero_user"], first["minio_velero_user"])   # stable afterwards
        self.assertEqual(os.stat(ctx.workdir / "secrets.json").st_mode & 0o777, 0o600)

    def test_velero_on_a_cloud_gets_none(self):
        ctx = make_ctx("aws")
        ctx.settle_minio_user("velero")
        self.assertTrue(ctx.minio_user_is_legacy("velero"))
        self.assertFalse(pl._legacy_minio_user("velero", ctx))

    def test_undo_of_an_uninstall_records_the_restored_root_login(self):
        ctx = make_ctx("vmware")
        vf = ctx.workdir / "values.json"
        vf.write_text(json.dumps({"rootUser": "admin-0123456789ab", "rootPassword": "x"}))
        ctx.settle_minio_user("minio", str(vf))
        self.assertEqual(ctx.minio_user("minio"), "admin-0123456789ab")
        self.assertFalse(ctx.minio_user_is_legacy("minio"))

    def test_undo_of_an_older_installs_uninstall_keeps_the_rotation_open(self):
        # the release comes back as 'admin' (its values): recording that as generated would hide the rotation for good
        ctx = make_ctx("vmware")
        ctx.settle_minio_user("minio")                    # a key generated earlier (a later install that was undone)
        vf = ctx.workdir / "values.json"
        vf.write_text(json.dumps({"rootUser": "admin", "rootPassword": "x"}))
        ctx.settle_minio_user("minio", str(vf))
        self.assertEqual(ctx.minio_user("minio"), "admin")
        self.assertTrue(ctx.minio_user_is_legacy("minio"))
        self.assertTrue(pl._legacy_minio_user("minio", ctx))   # the plan offers `cs platform install minio --upgrade`
        ctx.settle_minio_user("minio")                    # ... which generates one
        self.assertRegex(ctx.minio_user("minio"), r"^admin-[0-9a-f]{12}$")

    def render(self, ctx, name):
        seen = {}

        def fake_run(cmd, _ctx, check=True):
            if "apply" in cmd and "-f" in cmd:
                seen["text"] = Path(cmd[cmd.index("-f") + 1]).read_text()
            seen.setdefault("cmds", []).append(cmd)
            return 0
        with mock.patch.object(pl, "_run", fake_run), silenced():
            pl._apply_manifest(ctx, "kubectl", name, "default", wait_ns=False)
        return seen

    def test_manifests_carry_the_names_and_drop_the_old_users(self):
        ctx = make_ctx("vmware")
        for item in pl.MINIO_USERS:
            ctx.settle_minio_user(item)
        ph = ctx.placeholders()
        creds = self.render(ctx, "velero-minio-credentials")["text"]
        self.assertIn(f"aws_access_key_id = {ph['minio_velero_user']}", creds)
        seen = self.render(ctx, "velero-minio-bucket")
        self.assertIn(f'user: "{ph["minio_velero_user"]}"', seen["text"])
        self.assertIn('mc admin user add m "$USER_NAME" "$USER_PASSWORD"', seen["text"])
        self.assertIn('if [ "$USER_NAME" != velero ]; then mc admin user remove m velero', seen["text"])
        # an earlier run's Job (its template is immutable) goes before the apply
        delete = next(i for i, c in enumerate(seen["cmds"]) if c[3:5] == ["delete", "job"])
        apply = next(i for i, c in enumerate(seen["cmds"]) if "apply" in c)
        self.assertEqual(seen["cmds"][delete], ["kubectl", "-n", "minio", "delete", "job", "velero-bucket", "--ignore-not-found"])
        self.assertLess(delete, apply)
        spark = self.render(ctx, "spark-history-server")["text"]
        self.assertIn(f'AWS_ACCESS_KEY_ID: "{ph["minio_spark_user"]}"', spark)
        self.assertIn('if [ "$USER_NAME" != spark ]; then mc admin user remove m spark', spark)
        self.assertIn(f'cloudseed.io/s3-credentials: "{ph["minio_spark_checksum"]}"', spark)
        self.assertNotIn("{minio_", creds + seen["text"] + spark)
        self.assertIn(f"rootUser={ph['minio_root_user']}", " ".join(pl._values_args(pl.CATALOG["minio"], ctx)))

    def test_a_new_key_restarts_velero(self):
        ctx = make_ctx("vmware")
        args = lambda: [a for a in pl._values_args(pl.CATALOG["velero"], ctx) if "minio-credentials" in a]  # noqa: E731
        before = args()
        self.assertEqual(len(before), 1)
        self.assertIn("podAnnotations.cloudseed\\.io/minio-credentials=sha256-", before[0])
        self.assertEqual(pl._values_args(pl.CATALOG["velero"], ctx)[pl._values_args(pl.CATALOG["velero"], ctx).index(before[0]) - 1],
                         "--set-string")
        ctx.settle_minio_user("velero")
        self.assertNotEqual(args(), before)
        self.assertEqual([a for a in pl._values_args(pl.CATALOG["velero"], make_ctx("aws")) if "minio-credentials" in a], [])

    def test_plan_says_what_happens_to_an_old_key(self):
        ctx = make_ctx("vmware")
        releases = {"minio/minio": {"status": "deployed", "chart": "minio-5.4.0", "revision": "1"}}
        with mock.patch.object(ctx, "node_archs", return_value=set()):
            entries = pl.plan(["minio"], ctx, releases=releases)
        e = next(x for x in entries if x["item"] == "minio")
        self.assertEqual(e["action"], "skip-installed")
        self.assertIn("well-known 'admin'", " ".join(e["reasons"]))
        self.assertIn("cs platform install minio --upgrade", " ".join(e["reasons"]))
        ctx.upgrade = True
        with mock.patch.object(ctx, "node_archs", return_value=set()):
            e = next(x for x in pl.plan(["minio"], ctx, releases=releases) if x["item"] == "minio")
        self.assertIn("re-applying rotates its well-known MinIO access key 'admin'", " ".join(e["reasons"]))
        ctx.settle_minio_user("minio")
        with mock.patch.object(ctx, "node_archs", return_value=set()):
            e = next(x for x in pl.plan(["minio"], ctx, releases=releases) if x["item"] == "minio")
        self.assertNotIn("well-known", " ".join(e["reasons"]))

    def test_the_login_hint_names_the_key(self):
        self.assertIn("minio_root_user / minio_password", pl.UIS["minio"][4])
        self.assertIn("minio_root_user", pl.CATALOG["minio"]["notes"])


# ---------------------------------------------------------------- MetalLB's pool on small networks (vmware leftover)

class LbPoolTests(unittest.TestCase):
    K8S = {"enable_kubernetes": True, "kubernetes_workers": 2}

    def pool(self, cidr, settings, dhcp=None):
        with mock.patch.object(pl, "_vmnet_dhcp", return_value=dhcp):
            return pl._lb_pool(cidr, {}, "vmware", settings)

    def test_a_24_keeps_its_block_quietly(self):
        self.assertEqual(self.pool("10.0.0.0/24", self.K8S), ("10.0.0.100-10.0.0.127", "", ""))
        self.assertEqual(pl._lb_pool("10.0.0.0/24", {}, "aws"), ("10.0.0.199-10.0.0.249", "", ""))

    def test_below_a_24_the_pool_among_future_workers_is_flagged(self):
        upper = (ipaddress.ip_address("10.0.0.64"), ipaddress.ip_address("10.0.0.126"))
        for dhcp, want in ((None, "10.0.0.71-10.0.0.121"),     # unknown: cloudseed's own vmnet, static addressing
                           (upper, "10.0.0.42-10.0.0.63")):     # a DHCP pool on the upper half: just below it
            rng, problem, warning = self.pool("10.0.0.0/25", self.K8S, dhcp=dhcp)
            self.assertEqual((rng, problem), (want, ""))
            self.assertIn("workers added later", warning)
            self.assertIn("10.0.0.40-10.0.0.126", warning)

    def test_no_room_is_refused(self):
        rng, problem, _ = self.pool("10.0.0.0/26", dict(self.K8S, kubernetes_workers=23))
        self.assertIn("no room for MetalLB's LoadBalancer pool on 10.0.0.0/26", problem)
        self.assertIn("--force", problem)
        dhcp = (ipaddress.ip_address("10.0.0.32"), ipaddress.ip_address("10.0.0.62"))
        rng, problem, _ = self.pool("10.0.0.0/26", self.K8S, dhcp=dhcp)
        self.assertIn("outside the vmnet's DHCP range (10.0.0.32-10.0.0.62)", problem)
        # no DHCP: the old upper range, but never below the static addresses
        rng, problem, _ = self.pool("10.0.0.0/26", dict(self.K8S, kubernetes_workers=20), dhcp=False)   # up to .59
        self.assertIn("above the VMs' static addresses (up to 10.0.0.59). Use", problem)   # .60-.61 are left: fewer than 4
        rng, problem, warning = self.pool("10.0.0.0/26", dict(self.K8S, kubernetes_workers=17), dhcp=False)   # up to .56
        self.assertEqual((rng, problem), ("10.0.0.57-10.0.0.61", ""))   # the old upper range, above the static addresses
        self.assertIn("workers added later", warning)

    def test_plan_skips_metallb_and_what_needs_it_unless_forced(self):
        ctx = make_ctx("vmware", vars_=dict(self.K8S, kubernetes_workers=23), cidr="10.0.0.0/26")
        with mock.patch.object(pl, "_vmnet_dhcp", return_value=None), mock.patch.object(ctx, "node_archs", return_value=set()):
            entries = {e["item"]: e for e in pl.plan(["metallb"], ctx, releases={})}
            self.assertEqual(entries["metallb"]["action"], "skip-conflict")
            self.assertIn("no room", entries["metallb"]["reasons"][0])
            entries = {e["item"]: e for e in pl.plan(["metallb"], ctx, releases={}, force=True)}
            self.assertEqual(entries["metallb"]["action"], "install")
            small = make_ctx("vmware", vars_=self.K8S, cidr="10.0.0.0/25")
            with mock.patch.object(small, "node_archs", return_value=set()):
                entries = {e["item"]: e for e in pl.plan(["metallb"], small, releases={})}
            self.assertEqual(entries["metallb"]["action"], "install")
            self.assertTrue(any(r.startswith("MetalLB: its pool 10.0.0.71-10.0.0.121") for r in entries["metallb"]["reasons"]))
            self.assertEqual(small.placeholders()["lb_range"], "10.0.0.71-10.0.0.121")


# ---------------------------------------------------------------- --set mode= (a2-platform-logic#14)

class SetModeTests(unittest.TestCase):
    def test_mode_is_the_mesh_mode_only_with_a_mesh_in_the_request(self):
        self.assertIsNone(cli._platform_mode(["minio"], ["mode=distributed"]))
        self.assertEqual(cli._platform_mode(["istio"], ["mode=sidecar"]), "sidecar")
        self.assertEqual(cli._platform_mode(["kiali"], ["mode=sidecar"]), "sidecar")   # needs istio
        with self.assertRaises(SystemExit):
            cli._platform_mode(["istio"], ["mode=sidcar"])
        self.assertIsNone(cli._platform_mode([], ["mode=sidecar"]))
        sets, target = pl.check_install_args(["minio"], None, ["mode=distributed"])
        self.assertEqual((sets, target), (["mode=distributed"], "minio"))


# ---------------------------------------------------------------- managed CLIs: the echoed line (ops leftover)

class ManagedEchoTests(unittest.TestCase):
    def test_authorization_headers_are_hidden_in_the_echo(self):
        args = ["api", "get", "/x", "-H", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123"]
        with mock.patch.object(managed.secrets, "strict", return_value=False):
            self.assertIn("abcdefghijklmnopqrstuvwxyz0123", " ".join(managed.mask_argv(args, "databricks")))
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz0123", " ".join(managed.mask_argv(args, "databricks", auth=True)))
        self.assertEqual(len(managed.mask_argv(args, "helm", auth=True)), len(args))

    def test_the_echoed_line_of_a_run_hides_them(self):
        token = "abcdefghijklmnopqrstuvwxyz0123"
        with mock.patch.object(managed.secrets, "strict", return_value=False), \
                mock.patch.object(managed.secrets, "redact_enabled", return_value=False), \
                mock.patch.object(managed, "ensure_tool", return_value="/usr/bin/true"), \
                mock.patch.object(managed, "profile", return_value={"host": "https://dbc.example.com"}), \
                mock.patch.object(managed, "env_for", return_value={}), \
                mock.patch.object(managed.subprocess, "call", return_value=0) as call, silenced() as (out, err):
            self.assertEqual(managed.run("databricks", "default", ["api", "get", "/x", "-H", f"Authorization: Bearer {token}"]), 0)
        text = text_of(out, err)
        self.assertIn("$ databricks api get /x -H", text)
        self.assertNotIn(token, text)
        self.assertIn(token, " ".join(call.call_args[0][0]))   # only the echo is masked, the CLI gets the header


# ---------------------------------------------------------------- error hints (docs leftover)

class ErrorHintTests(unittest.TestCase):
    def rows(self, word, command=None):
        text = ui._strip(helpmod.error_hint(command, "unknown command", word, width=0))
        return [ln.strip() for ln in text.splitlines() if "did you mean" in ln or "help topic" in ln]

    def test_a_topic_is_never_offered_as_a_command(self):
        self.assertEqual(self.rows("quickstrt"), ["help topic cloudseed help quickstart"])
        self.assertEqual(self.rows("securty"), ["help topic cloudseed help security"])
        self.assertIn("did you mean status", " ".join(self.rows("statsu")))
        self.assertEqual(self.rows("aw"), ["did you mean aws?"])
        self.assertIn("did you mean env?", self.rows("envs"))


# ---------------------------------------------------------------- GKE: the bastion's kubectl version (ansible review)

class ClusterVersionTests(unittest.TestCase):
    def test_gke_uses_the_running_control_plane(self):
        gcp, aws = clouds.get("gcp"), clouds.get("aws")
        cfg = {"vars": {"kubernetes_version": "1.31"}}
        self.assertEqual(prov.cluster_version(gcp, cfg, {"kubernetes_master_version": "1.33.5-gke.1080000"}), "1.33.5-gke.1080000")
        self.assertEqual(prov.cluster_version(gcp, cfg, {}), "1.31")
        self.assertEqual(prov.cluster_version(aws, cfg, {"kubernetes_master_version": "1.40"}), "1.31")
        self.assertIn("kubernetes_master_version", gcp.outputs)
        tf = (paths.REPO_ROOT / "terraform" / "gcp" / "outputs.tf").read_text()
        self.assertRegex(tf, r'output "kubernetes_master_version" \{\n  description = "[^"]*only a minimum')
        self.assertIn("google_container_cluster.this.master_version",
                      (paths.REPO_ROOT / "terraform" / "gcp" / "modules" / "kubernetes" / "main.tf").read_text())
        # the tools role takes the minor from such a version (1.33.5-gke... -> 1.33)
        role = (paths.REPO_ROOT / "ansible" / "roles" / "tools" / "tasks" / "main.yml").read_text()
        pattern = re.search(r"regex_search\('(\^v\?\[0-9\]\+\[\.\]\[0-9\]\+)'\)", role).group(1)
        self.assertEqual(re.search(pattern.replace("[.]", r"\."), "1.33.5-gke.1080000").group(0), "1.33")


if __name__ == "__main__":
    unittest.main()
