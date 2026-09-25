"""Wave-4 resilience regressions (changes other groups asked of dr.py / chaos.py / scan.py, and review leftovers):
dr._phase for `cs dr restore`, velero's real error line instead of its usage text, the --ttl check in dr.schedule,
the storage-location lookup with kubectl, the drill's backup name for `dr test --keep`; chaos reports that print
whatever fields they lack and name the run's own report; the scan claim collector; the RKE2 CIS-profile hint; the
default-namespace CIS audits decided from this machine; FIPS checks for crypto-restricted items and the live AWS
endpoints / node images. Stdlib only; every cluster/tool call is faked."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import chaos, clouds, dr, paths, scan, ui  # noqa: E402
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


def fresh_env(target: str = "aws") -> paths.Env:
    _n[0] += 1
    env = paths.Env(target, f"w4r{_RUN}x{_n[0]}")
    env.create_dirs()
    return env


def make_ctx(target: str = "vmware", env: paths.Env | None = None, distro: str | None = None, vars_: dict | None = None,
             fips: bool = False) -> pl.Cluster:
    env = env or fresh_env(target)
    cfg = {"env": env.name, "name": "t", "region": "us-east-1", "network_cidr": "10.0.0.0/16", "vars": dict(vars_ or {})}
    if fips:
        cfg["vars"]["fips_mode"] = True
    outputs = {"kubernetes_distro": distro or "rke2"} if target == "vmware" else {"kubernetes_cluster_name": "c"}
    if distro and target != "vmware":
        outputs["kubernetes_distro"] = distro
    return pl.Cluster(clouds.get(target), env, cfg, outputs, env.dir / "kc")


class FakeClock:
    def __init__(self):
        self.now = 1_000_000.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += max(float(s), 0.01)

    def strftime(self, *a):
        return time.strftime(*a)

    def gmtime(self, *a):
        return time.gmtime(*a)


# ---------------------------------------------------------------- dr: _phase (cs dr restore asks whether a restore started)

class DrPhaseTests(unittest.TestCase):
    def phase(self, proc=None, raises=None):
        ctx = make_ctx()
        velero = mock.Mock(side_effect=raises) if raises else mock.Mock(return_value=proc)
        with mock.patch.object(dr, "_velero", velero):
            return dr._phase(ctx, "restore", "b1-restore-20260101000000"), velero

    def test_phase_of_a_restore(self):
        got, velero = self.phase(cp(0, json.dumps({"metadata": {"name": "r"}, "status": {"phase": "FailedValidation"}})))
        self.assertEqual(got, "FailedValidation")
        self.assertEqual(velero.call_args[0][1:4], ("restore", "get", "b1-restore-20260101000000"))
        self.assertTrue(velero.call_args[1]["quiet"])
        self.assertFalse(velero.call_args[1]["check"])

    def test_no_phase_yet_is_new_and_unknown_is_none(self):
        self.assertEqual(self.phase(cp(0, json.dumps({"metadata": {"name": "r"}})))[0], "New")
        self.assertEqual(self.phase(cp(0, json.dumps({"items": [{"metadata": {"name": "r"}, "status": {"phase": "InProgress"}}]})))[0], "InProgress")
        self.assertIsNone(self.phase(cp(1, "", 'An error occurred: restores.velero.io "x" not found'))[0])
        self.assertEqual(self.phase(cp(0, "not json"))[0], "New")
        self.assertIsNone(self.phase(cp(0, json.dumps({"kind": "RestoreList", "items": []})))[0])   # an empty List names nothing
        # no velero CLI here (an agent session may not fetch it): unknown, never a crash
        self.assertIsNone(self.phase(raises=ui.Abort("The velero CLI v1.18.2 is not installed", code=2))[0])

    def test_backup_phase_is_the_same_reading(self):
        ctx = make_ctx()
        with mock.patch.object(dr, "_velero", return_value=cp(0, json.dumps({"status": {"phase": "Completed"}}))) as v:
            self.assertEqual(dr._backup_phase(ctx, "b"), "Completed")
        self.assertEqual(v.call_args[0][1:4], ("backup", "get", "b"))


# ---------------------------------------------------------------- dr: velero's error line (a2-resilience#15)

USAGE = """Error: unknown flag: --include-namespace
Usage:
  velero backup create NAME [flags]

Examples:
  # Create a backup containing all resources.
  velero backup create backup1

Flags:
      --exclude-namespaces stringArray   Namespaces to exclude from the backup.
  -h, --help                             help for create
      --include-namespaces stringArray   Namespaces to include in the backup (use '*' for all namespaces). (default *)
      --wait                             Wait for the operation to complete.
"""


class VeleroErrorTests(unittest.TestCase):
    def test_the_error_line_not_the_usage_text(self):
        self.assertEqual(dr.velero_error(cp(1, "", USAGE)), "unknown flag: --include-namespace")
        self.assertEqual(dr.velero_error(cp(1, "", 'An error occurred: backups.velero.io "b1" already exists\n')),
                         'backups.velero.io "b1" already exists')
        # streamed runs merge stderr into stdout; the LAST error line wins
        self.assertEqual(dr.velero_error(cp(1, "Backup request submitted\nAn error occurred: first\nAn error occurred: second\n", "")), "second")

    def test_without_an_error_line_the_tail_is_kept(self):
        self.assertEqual(dr.velero_error(cp(1, "", "line one\nsomething broke\n")), "line one · something broke")
        self.assertEqual(dr.velero_error(cp(3, "", "")), "exit code 3")

    def test_velero_abort_carries_the_error_line(self):
        ctx = make_ctx()
        with mock.patch.object(dr, "ensure_cli", return_value="/fake/velero"), mock.patch.object(dr, "audit"), \
                mock.patch.object(dr.subprocess, "run", return_value=cp(1, "", USAGE)), silenced(), self.assertRaises(SystemExit) as cm:
            dr._velero(ctx, "backup", "create", "b1", "--include-namespace", "x")
        self.assertEqual(cm.exception.msg, "velero backup create failed: unknown flag: --include-namespace")
        self.assertNotIn("Flags:", cm.exception.msg)


# ---------------------------------------------------------------- dr: --ttl in dr.schedule (a2-resilience#15)

class ScheduleTtlTests(unittest.TestCase):
    def test_ttl_duration(self):
        self.assertEqual(dr.ttl_duration("30d"), "720h")
        self.assertEqual(dr.ttl_duration(" 7d "), "168h")
        for ok in ("720h", "1.5h", "90m30s", "500ms", "0", "72h30m"):
            self.assertEqual(dr.ttl_duration(ok), ok)
        self.assertEqual(dr.ttl_duration(None), dr.TTL_DEFAULT)
        self.assertEqual(dr.ttl_duration(""), "720h")
        for bad in ("forever", "30 days", "-1h", "1w", "h"):
            with self.assertRaises(SystemExit) as cm:
                dr.ttl_duration(bad)
            self.assertEqual(cm.exception.code, 2, bad)
            self.assertIn("not a duration", cm.exception.msg)

    def schedule(self, ttl):
        ctx = make_ctx()
        calls = []

        def velero(ctx_, *args, **kw):
            calls.append(args)
            if args[:2] == ("schedule", "get"):
                return cp(0, json.dumps({"status": {"phase": "Enabled"}}))
            return cp(0)
        with mock.patch.object(dr, "require") as req, mock.patch.object(dr, "_velero", velero), mock.patch.object(dr, "time", FakeClock()), \
                silenced() as (out, err):
            try:
                dr.schedule(ctx, "nightly", "0 2 * * *", None, ttl)
                res = None
            except SystemExit as e:
                res = e
        return res, calls, req, text_of(out, err)

    def test_bad_ttl_stops_before_any_cluster_work(self):
        res, calls, req, _ = self.schedule("forever")
        self.assertEqual(res.code, 2)
        self.assertEqual(calls, [])
        req.assert_not_called()

    def test_days_reach_velero_as_hours(self):
        res, calls, _, text = self.schedule("14d")
        self.assertIsNone(res)
        create = next(c for c in calls if c[:2] == ("schedule", "create"))
        self.assertEqual(create[create.index("--ttl") + 1], "336h")
        self.assertIn("keep 336h", text)


# ---------------------------------------------------------------- dr: the storage location through kubectl (review leftover)

def locations(config) -> str:
    return json.dumps({"items": [{"metadata": {"name": "default"}, "spec": {"provider": "aws", "config": config}}]})


class StorageConfigTests(unittest.TestCase):
    # (wave 5) the hints no longer depend on the location (they name `cs dr describe|logs`); where `cs dr describe|logs`
    # runs velero - here or in the velero pod - still does: dr.in_cluster_storage
    def test_the_location_is_read_with_kubectl_once(self):
        ctx = make_ctx("vmware")
        with mock.patch.object(dr, "_kubectl", return_value=cp(0, locations({"s3Url": "http://minio.minio.svc:9000"}))) as k, \
                mock.patch.object(dr, "_velero", side_effect=AssertionError("no velero CLI to read the location")):
            self.assertTrue(dr.in_cluster_storage(ctx))
            self.assertTrue(dr.in_cluster_storage(ctx))
        self.assertEqual(k.call_count, 1)
        self.assertIn("backupstoragelocations.velero.io", k.call_args[0])

    def test_unreadable_location(self):
        for target, inside in (("vmware", True), ("aws", False)):
            ctx = make_ctx(target)
            with mock.patch.object(dr, "_kubectl", return_value=cp(1, "", "Unable to connect to the server")), \
                    mock.patch.object(dr, "_velero", side_effect=AssertionError("velero CLI")):
                self.assertIs(dr.in_cluster_storage(ctx), inside)
        ctx = make_ctx("vmware")
        with mock.patch.object(dr, "_kubectl", side_effect=ui.Abort("kubectl is needed: cloudseed install kubectl", code=2)):
            self.assertEqual(dr._storage_config(ctx), {})

    def test_a_public_url_is_reachable_from_here(self):
        ctx = make_ctx("vmware")
        with mock.patch.object(dr, "_kubectl", return_value=cp(0, locations({"s3Url": "http://minio.minio.svc:9000",
                                                                              "publicUrl": "https://minio.example.com"}))):
            self.assertFalse(dr.in_cluster_storage(ctx))


# ---------------------------------------------------------------- dr: the drill names what it kept (a2-resilience#18)

class Drill:
    """kubectl + velero for a drill run; `fail_create` makes step 1 fail (no backup is ever started)."""

    def __init__(self, fail_create=False):
        self.fail_create = fail_create
        self.token = None
        self.velero_calls = []

    def kubectl(self, ctx, *args, input=None, timeout=180):
        a = list(args)
        if "apply" in a:
            if self.fail_create:
                return cp(1, "", "admission webhook denied the request")
            self.token = re.search(r'token: "([^"]+)"', input).group(1)
            return cp(0)
        if a[:2] == ["get", "ns"]:
            return cp(1)
        if a[:2] == ["get", "sc"]:
            return cp(0, "")
        if "cm" in a:
            return cp(0, self.token)
        if "secret" in a:
            import base64
            return cp(0, base64.b64encode(self.token.encode()).decode())
        return cp(0)

    def velero(self, ctx, *args, check=True, stream=False, timeout=1800, quiet=False):
        self.velero_calls.append(args)
        if len(args) >= 2 and args[1] == "get":
            return cp(0, json.dumps({"status": {"phase": "Completed"}}))
        return cp(0)


def run_drill(fake, keep):
    ctx = make_ctx("vmware")
    with mock.patch.object(dr, "require"), mock.patch.object(dr, "_kubectl", fake.kubectl), mock.patch.object(dr, "_velero", fake.velero), \
            mock.patch.object(dr, "server_version", return_value="v1.18.2"), mock.patch.object(dr, "time", FakeClock()), silenced() as (out, err):
        rc = dr.test(ctx, keep=keep, with_volume=False)
    return rc, ctx, json.loads(dr.last_report(ctx.env).read_text()), text_of(out, err)


class DrillKeepTests(unittest.TestCase):
    def test_kept_drill_exposes_its_backup_and_says_how_to_remove_it(self):
        rc, ctx, rep, text = run_drill(Drill(), keep=True)
        self.assertEqual(rc, 0, text)
        self.assertTrue(rep["backup"].startswith("dr-test-"))
        self.assertEqual(rep["namespace"], dr.DRILL_NS)
        drill = ctx.dr_drill
        self.assertEqual((drill["backup"], drill["namespace"], drill["kept"], drill["verdict"]), (rep["backup"], dr.DRILL_NS, True, "PASS"))
        self.assertEqual(Path(drill["report"]), dr.last_report(ctx.env))
        self.assertIn(f"Kept for inspection: namespace {dr.DRILL_NS} and backup {rep['backup']}", text)
        self.assertIn(f"/velero backup delete {rep['backup']} --confirm", text)
        self.assertIn(f"delete ns {dr.DRILL_NS}", text)

    def test_drill_without_keep_says_nothing_about_kept_objects(self):
        rc, ctx, rep, text = run_drill(Drill(), keep=False)
        self.assertEqual(rc, 0, text)
        self.assertFalse(ctx.dr_drill["kept"])
        self.assertNotIn("Kept for inspection", text)

    def test_removal_commands_work_without_a_velero_cli_on_local_clusters(self):
        # (wave 5) the delete runs in the velero pod on every cluster: no velero CLI on PATH, no reliance on the current
        # kube context (a bare `velero backup delete` could hit another cluster)
        for target, config in (("vmware", {"s3Url": "http://minio.minio.svc:9000"}), ("aws", {"region": "us-east-1"})):
            ctx = make_ctx(target)
            with mock.patch.object(dr, "_kubectl", return_value=cp(0, locations(config))), silenced() as (out, err):
                dr._kept_hint(ctx, "b1")
            text = text_of(out, err)
            self.assertIn(f"cs kubectl {target} --env {ctx.env.name} -n velero exec svc/velero -c velero -- /velero backup delete b1 --confirm", text)

    def test_a_drill_that_stops_early_leaves_no_previous_drill_behind(self):
        ctx = make_ctx("vmware")
        ctx.dr_drill = {"backup": "dr-test-old", "namespace": dr.DRILL_NS}   # a context reused after an earlier drill
        with mock.patch.object(dr, "require", side_effect=ui.Abort("Velero is not installed on this cluster")), \
                self.assertRaises(SystemExit):
            dr.test(ctx, keep=True)
        self.assertIsNone(ctx.dr_drill)

    def test_no_backup_is_named_when_none_was_started(self):
        fake = Drill(fail_create=True)
        rc, ctx, rep, text = run_drill(fake, keep=True)
        self.assertEqual(rc, 1)
        self.assertIsNone(rep["backup"])
        self.assertIsNone(ctx.dr_drill["backup"])
        self.assertFalse(any(c[:2] == ("backup", "create") for c in fake.velero_calls))
        self.assertIn(f"Kept for inspection: namespace {dr.DRILL_NS}.", text)
        self.assertNotIn("velero backup delete", text)


# ---------------------------------------------------------------- chaos: robust reports, the run's own report, no mid-run panel

class ChaosReportTests(unittest.TestCase):
    def test_print_report_tolerates_missing_and_odd_fields(self):
        for rep in ({}, {"results": None, "summary": None}, {"results": [{"experiment": "pod-kill"}]},
                    {"results": [{"experiment": 5, "verdict": "PASS", "availability": "0.9", "min_availability": 0.8}], "summary": {"PASS": "x"}},
                    {"results": [{"experiment": "a", "verdict": "FAIL", "availability": "n/a", "min_availability": None, "reason": ["odd"]}]},
                    {"results": [{"experiment": "a", "verdict": "PASS", "availability": True, "min_availability": 0.5}], "env": None}):
            with silenced() as (out, err):
                chaos.print_report(rep, Path("/tmp/report-20260101-000000.json"))
            self.assertIn("Chaos results", text_of(out, err), rep)
        with silenced() as (out, err):
            chaos.print_report([], None)   # not even a dict
        self.assertIn("no experiment ran", text_of(out, err))
        with silenced() as (out, err):
            chaos.print_report({"results": [{"experiment": "a", "verdict": "PASS", "availability": "0.9", "min_availability": "0.5",
                                             "recovery_s": 3, "recovery_bound_s": 90}]})
        self.assertIn("availability  90%  (min 50%)", text_of(out, err))

    def test_save_report_is_atomic_and_tolerates_missing_fields(self):
        env = fresh_env("vmware")
        ctx = make_ctx("vmware", env=env)
        replaced = []
        real = os.replace

        def replace(src, dst):
            replaced.append((Path(src).parent, Path(dst)))
            return real(src, dst)
        with mock.patch.object(paths.os, "replace", replace):
            path = chaos.save_report(ctx, {"run": "20260101-000000", "results": [{"experiment": "pod-kill", "verdict": "SKIP"}]})
        self.assertEqual(replaced[0], (path.parent, path))   # a temp file in the same directory, renamed onto the claimed name
        self.assertEqual(json.loads(path.read_text())["results"][0]["experiment"], "pod-kill")
        self.assertIn("| pod-kill | SKIP |", path.with_suffix(".md").read_text())
        self.assertEqual([p.name for p in path.parent.iterdir() if p.name.endswith(".tmp")], [])

    def test_last_report_row_survives_a_report_that_is_not_an_object(self):
        env = fresh_env("vmware")
        d = env.dir / "chaos"
        d.mkdir(parents=True, exist_ok=True)
        (d / "report-20260101-000000.json").write_text("[1, 2]")
        self.assertIn("is unreadable", ui._strip(chaos._last_report_row(env)))

    def test_run_names_its_own_report(self):
        ctx = make_ctx("vmware")
        t = chaos.Target(chaos.CANARY_NS, chaos.CANARY_NAME, chaos.CANARY_NAME, chaos.CANARY_NAME, 8080, True)
        d = ctx.env.dir / "chaos"

        def experiment(ctx_, name, t_, duration_s, run_id):
            d.mkdir(parents=True, exist_ok=True)
            (d / "report-29990101-000000.json").write_text("{}")   # a parallel run's report, newer by name
            return {"experiment": name, "verdict": "PASS", "availability": 1.0, "min_availability": 0.5, "recovery_s": 1, "recovery_bound_s": 90}
        with mock.patch.object(chaos, "ensure_chaos_mesh"), mock.patch.object(chaos, "resolve_target", return_value=t), \
                mock.patch.object(chaos, "steady", return_value=True), mock.patch.object(chaos, "run_experiment", experiment), \
                mock.patch.object(chaos, "_kubectl", return_value=cp(0)), silenced():
            rc = chaos.run(ctx, ["pod-kill"], None, None, 45, 3, False)
        self.assertEqual(rc, 0)
        self.assertNotEqual(ctx.chaos_report.name, "report-29990101-000000.json")
        self.assertEqual(json.loads(ctx.chaos_report.read_text())["verdict"], "PASS")

    def test_a_run_that_stops_early_names_no_report(self):
        ctx = make_ctx("vmware")
        ctx.chaos_report = Path("/tmp/report-20200101-000000.json")   # a context reused after an earlier run
        with mock.patch.object(chaos, "ensure_chaos_mesh", side_effect=ui.Abort("helm is needed")), self.assertRaises(SystemExit):
            chaos.run(ctx, ["pod-kill"], None, None, 45, 3, False)
        self.assertIsNone(ctx.chaos_report)

    def test_implicit_install_asks_for_no_platform_summary(self):
        ctx = make_ctx()
        with mock.patch.object(chaos, "chaos_mesh_ready", return_value=False), mock.patch.object(pl, "install") as inst, \
                mock.patch.object(chaos, "_kubectl", return_value=cp(0)), silenced():
            chaos.ensure_chaos_mesh(ctx)
        inst.assert_called_once_with(["chaos-mesh"], ctx, wait=True, summary=False)


# ---------------------------------------------------------------- scan: the claim collector (a2-resilience#6)

class ClaimCollectorTests(unittest.TestCase):
    def test_collects_what_this_block_claimed_and_wrote(self):
        env = fresh_env("vmware")
        d = scan._reports_dir(env)
        outside, _ = scan.claim_run_path(d, "cis-", ".json", "20260101-000000")
        with scan.collect() as made:
            raw, _ = scan.claim_run_path(scan._raw_dir(env), "trivy-", ".json", "20260101-000001")
            out_dir, _ = scan.claim_run_path(d, "openscap-", "", "20260101-000002", directory=True)
            rep = scan.save_report(env, "fips", {"run": "20260101-000003", "summary": {}, "verdict": "PASS"})
            scan.save_report(env, "fips", {"run": rep.stem.split("-", 1)[1], "summary": {}, "verdict": "PASS"})   # same second: next free
        self.assertEqual(made[:4], [raw, out_dir, rep, rep.with_suffix(".md")])
        self.assertEqual(len(made), 6)
        self.assertEqual(len(set(made)), 6)
        self.assertNotIn(outside, made)
        self.assertIsNone(scan._CLAIMS.get())   # nothing is collected after the block
        scan.claim_run_path(d, "cis-", ".json", "20260101-000009")

    def test_a_scan_that_fails_part_way_leaves_its_claims(self):
        env = fresh_env("vmware")
        with self.assertRaises(RuntimeError), scan.collect() as made:
            scan.claim_run_path(scan._reports_dir(env), "openscap-", "", scan.run_stamp(), directory=True)
            raise RuntimeError("ansible died")
        self.assertEqual(len(made), 1)
        self.assertTrue(made[0].is_dir())

    def test_parallel_threads_never_mix(self):
        env = fresh_env("vmware")
        seen = {}

        def worker(tag):
            with scan.collect() as made:
                for i in range(5):
                    scan.claim_run_path(scan._raw_dir(env), f"{tag}-", ".json", "20260101-000000")
                    time.sleep(0.001)
            seen[tag] = made
        threads = [threading.Thread(target=worker, args=(t,)) for t in ("a", "b")]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertTrue(all(p.name.startswith("a-") for p in seen["a"]) and len(seen["a"]) == 5)
        self.assertTrue(all(p.name.startswith("b-") for p in seen["b"]) and len(seen["b"]) == 5)


# ---------------------------------------------------------------- scan cis: RKE2 CIS profile hint (e2e2#0) + default-namespace audits

def cis_run(ctx, results, kubectl=None):
    def run(ctx_, role, benchmark, targets, timeout=300, version=""):
        return {"Controls": [{"version": benchmark or "cis-1.12", "node_type": role, "tests": [{"section": "5.1", "results": results}]}]}

    def default_kubectl(ctx_, *args, input=None, timeout=300):
        if args[:1] == ("version",):
            return cp(0, json.dumps({"serverVersion": {"gitVersion": "v1.35.1"}}))
        return cp(0)
    with mock.patch.object(scan, "_ensure_kubectl"), mock.patch.object(scan, "_kube_bench_run", run), \
            mock.patch.object(scan, "_kubectl", kubectl or default_kubectl), silenced() as (out, err):
        path = scan.cis(ctx)
    return json.loads(path.read_text()), text_of(out, err)


FAILING = [{"test_number": "1.1.1", "test_desc": "file perms", "audit": "stat -c %a /etc/x", "status": "FAIL", "actual_value": "777",
            "remediation": "chmod 600"}]


class CisProfileHintTests(unittest.TestCase):
    def test_rke2_without_the_profile_says_how_to_enable_it(self):
        ctx = make_ctx("vmware", distro="rke2", vars_={"kubernetes_cis_profile": False})
        rep, text = cis_run(ctx, FAILING)
        env = ctx.env.name
        self.assertIn(f"cs setup vmware --env {env} --var kubernetes_cis_profile=true", rep["hint"])
        self.assertIn(f"cs provision vmware --env {env} --host k8s", rep["hint"])
        self.assertIn("kubernetes_cis_profile=true", text)
        self.assertIn("RKE2's CIS hardening profile is off", text)
        md = sorted((ctx.env.dir / "scans").glob("cis-*.md"))[-1].read_text()   # the saved report says it too
        self.assertIn("**Next step:** RKE2's CIS hardening profile is off", md)
        self.assertIn(f"cs provision vmware --env {env} --host k8s", md)

    def test_no_hint_when_it_is_on_passing_or_not_rke2(self):
        for ctx, results in ((make_ctx("vmware", distro="rke2", vars_={"kubernetes_cis_profile": True}), FAILING),
                             (make_ctx("vmware", distro="rke2"), []),
                             (make_ctx("vmware", distro="kubeadm"), FAILING),
                             (make_ctx("aws", distro="eks"), FAILING)):
            rep, text = cis_run(ctx, results)
            self.assertNotIn("hint", rep)
            self.assertNotIn("kubernetes_cis_profile", text)
        rep, _ = cis_run(make_ctx("vmware", distro="rke2", vars_={"kubernetes_cis_profile": "yes"}), FAILING)
        self.assertNotIn("hint", rep)


EKS_452 = {"test_number": "4.5.2", "test_desc": "The default namespace should not be used (Automated)", "status": "FAIL", "scored": True,
           "audit": 'output=$(kubectl get $(kubectl api-resources --verbs=list --namespaced=true -o name | paste -sd, -) --ignore-not-found '
                    '-n default 2>/dev/null | grep -v "^kubernetes ")\nif [ -z "$output" ]; then\n  echo "NO_USER_RESOURCES_IN_DEFAULT"\n'
                    'else\n  echo "USER_RESOURCES_IN_DEFAULT_FOUND: $output"\nfi\n',
           "actual_value": "USER_RESOURCES_IN_DEFAULT_FOUND: NAME TYPE service/kubernetes ClusterIP serviceaccount/default 0",
           "remediation": "Create and use dedicated namespaces"}
GKE_464 = {"test_number": "4.6.4", "test_desc": "The default namespace should not be used (Manual)", "status": "WARN", "scored": False,
           "audit": "output=$(kubectl get all -n default --no-headers 2>/dev/null | grep -v '^service\\s\\+kubernetes\\s' || true)\n"
                    'if [ -z "$output" ]; then echo "DEFAULT_NAMESPACE_UNUSED"; else echo "DEFAULT_NAMESPACE_IN_USE"; fi\n',
           "actual_value": "DEFAULT_NAMESPACE_IN_USE"}


def listing(objects, types="pods\nservices\nserviceaccounts\nconfigmaps\nsecrets\nevents\nevents.events.k8s.io\npods.metrics.k8s.io\n"
                           "deployments.apps\nendpointslices.discovery.k8s.io\nleases.coordination.k8s.io", fail=False):
    calls = []

    def kubectl(ctx_, *args, input=None, timeout=300):
        calls.append(args)
        if args[:1] == ("api-resources",):
            return cp(0, types)
        if args[:1] == ("get",) and "-n" in args and args[args.index("-n") + 1] == "default":
            return cp(1, "", "Unable to connect") if fail else cp(0, "\n".join(objects) + "\n")
        return cp(0)
    return kubectl, calls


BUILTINS = ["service/kubernetes", "serviceaccount/default", "configmap/kube-root-ca.crt", "endpointslice.discovery.k8s.io/kubernetes",
            "event/ip-10-0-1-5.ec2.internal.17f0a", "event.events.k8s.io/ip-10-0-1-5.17f0a", "lease.coordination.k8s.io/x"]


class DefaultNamespaceTests(unittest.TestCase):
    def test_objects_every_cluster_has_do_not_fail_it(self):
        kubectl, calls = listing(BUILTINS)
        rep, _ = cis_run(make_ctx("aws", distro="eks"), [EKS_452], kubectl)
        self.assertEqual((rep["summary"]["fail"], rep["summary"]["pass"]), (0, 1))
        what = next(c for c in calls if c[:1] == ("get",))[1]
        self.assertIn("secrets", what)   # listed with the environment's own credentials: the scan pod's role never reads secrets
        self.assertNotIn("metrics.k8s.io", what)
        self.assertEqual(sum(1 for c in calls if c[:1] == ("api-resources",)), 1)

    def test_user_objects_fail_it_by_name(self):
        kubectl, _ = listing(BUILTINS + ["deployment.apps/web", "secret/db-password"])
        rep, _ = cis_run(make_ctx("aws", distro="eks"), [EKS_452], kubectl)
        self.assertEqual(rep["summary"]["fail"], 1)
        f = rep["findings"][0]
        self.assertTrue(f["detail"].startswith("deployment.apps/web, secret/db-password in the default namespace"), f["detail"])
        self.assertNotIn("service/kubernetes", f["detail"])

    def test_unlistable_namespace_is_not_evaluated(self):
        kubectl, _ = listing([], fail=True)
        rep, _ = cis_run(make_ctx("aws", distro="eks"), [EKS_452], kubectl)
        self.assertEqual((rep["summary"]["fail"], rep["summary"]["warn"]), (0, 1))
        self.assertIn("not evaluated", rep["findings"][0]["detail"])
        self.assertIn("cs kubectl aws --env ", rep["findings"][0]["detail"])
        self.assertEqual(rep["summary"]["not evaluated"], 1)   # counted with the checks kube-bench could not evaluate

    def test_a_partial_listing_counts_only_what_it_found(self):
        ctx = make_ctx("aws", distro="eks")
        down = "error: unable to retrieve the complete list of server APIs: metrics.k8s.io/v1beta1: the server is currently unable"

        def kubectl(objects):
            def run(ctx_, *args, input=None, timeout=300):
                if args[:1] == ("api-resources",):   # one aggregated API is down: the rest are still listed
                    return cp(1, "pods\nservices\nserviceaccounts\n", down)
                if args[:1] == ("get",):
                    return cp(1, "\n".join(objects) + "\n", "Error from server (ServiceUnavailable): the server is currently unable")
                return cp(0)
            return run
        with mock.patch.object(scan, "_kubectl", kubectl(["service/kubernetes", "pod/debug"])):
            self.assertEqual(scan._default_ns_objects(ctx, "every"), ["pod/debug"])   # found despite the failing group
        with mock.patch.object(scan, "_kubectl", kubectl(["service/kubernetes"])):
            self.assertIsNone(scan._default_ns_objects(ctx, "every"))   # incomplete and nothing found: proves nothing

    def test_gke_manual_variant_lists_the_all_category(self):
        kubectl, calls = listing(["service/kubernetes"])
        rep, _ = cis_run(make_ctx("gcp", distro="gke"), [GKE_464], kubectl)
        self.assertEqual((rep["summary"]["pass"], rep["summary"]["warn"]), (1, 0))
        self.assertFalse(any(c[:1] == ("api-resources",) for c in calls))
        self.assertIn(("get", "all", "-n", "default", "-o", "name", "--ignore-not-found"), calls)
        kubectl, _ = listing(["service/kubernetes", "pod/debug"])
        rep, _ = cis_run(make_ctx("gcp", distro="gke"), [GKE_464], kubectl)
        self.assertEqual((rep["summary"]["fail"], rep["summary"]["warn"]), (0, 1))   # unscored: a review item, not a FAIL
        self.assertIn("pod/debug", rep["findings"][0]["detail"])

    def test_other_checks_are_untouched(self):
        self.assertIsNone(scan._default_ns_scope({"audit": "kubectl get pods -A"}))
        self.assertIsNone(scan._default_ns_scope({"audit": "stat /etc/kubernetes"}))
        self.assertEqual(scan._default_ns_scope(EKS_452), "every")
        self.assertEqual(scan._default_ns_scope(GKE_464), "all")


# ---------------------------------------------------------------- scan fips: crypto-restricted items, live AWS checks (a2-platform-catalog#9/#10, a2-aws#5)

def deploy(name, fips_env=True, value="true"):
    env = [{"name": "AWS_USE_FIPS_ENDPOINT", "value": value}] if fips_env else [{"name": "OTHER", "value": "x"}]
    return {"metadata": {"name": name}, "spec": {"template": {"spec": {"containers": [{"name": "c", "env": env}]}}}}


class FakeAwsCluster:
    def __init__(self, nodes="", deployments=None, bsl_url="https://s3-fips.us-east-1.amazonaws.com", nodeclass_terms=None, unreadable=()):
        self.nodes, self.deployments = nodes, deployments or {}
        self.bsl_url, self.terms, self.unreadable = bsl_url, nodeclass_terms, set(unreadable)

    def kubectl(self, ctx, *args, input=None, timeout=300):
        a = list(args)
        if "nodes" in a and any("osImage" in x for x in a):
            return cp(0, self.nodes)
        if "deploy" in a and "-l" in a:
            if "deploy" in self.unreadable:
                return cp(1, "", "forbidden")
            release = a[a.index("-l") + 1].split("=", 1)[1]
            return cp(0, json.dumps({"items": self.deployments.get(release, [])}))
        if "backupstoragelocations.velero.io" in a:
            return cp(0, json.dumps({"items": [{"metadata": {"name": "default"}, "spec": {"provider": "aws", "config": {"s3Url": self.bsl_url}}}]}))
        if "ec2nodeclasses.karpenter.k8s.aws" in a:
            if self.terms is None:
                return cp(1, "", "the server doesn't have a resource type")
            return cp(0, json.dumps({"items": [{"metadata": {"name": "default"}, "spec": {"amiSelectorTerms": self.terms}}]}))
        return cp(1)


def fips_checks(cloud_key, fake, releases, wanted=True, distro=None):
    env = fresh_env(cloud_key)
    ctx = make_ctx(cloud_key, env=env, distro=distro or {"aws": "eks", "gcp": "gke", "azure": "aks"}[cloud_key], fips=wanted)
    cfg = {"vars": {"fips_mode": wanted}, "ssh_public_key": ""}
    with mock.patch.object(scan, "_kubectl", fake.kubectl), mock.patch.object(scan, "_hosts", return_value=[]), \
            mock.patch.object(pl, "installed_releases", return_value=releases), silenced() as (out, err):
        path = scan.fips(clouds.get(cloud_key), env, cfg, {"kubernetes_cluster_name": "c", "fips_mode": wanted}, ctx=ctx)
    return {c["check"]: c for c in json.loads(path.read_text())["checks"]}, json.loads(path.read_text()), text_of(out, err)


def rel(*keys):
    return {k: {"status": "deployed"} for k in keys}


class FipsCryptoRestrictedTests(unittest.TestCase):
    def test_crypto_restricted_items_are_not_a_pass(self):
        items = [n for n, spec in pl.CATALOG.items() if spec.get("fips") == "crypto-restricted" and not spec.get("hidden")]
        self.assertTrue({"cert-manager", "sealed-secrets", "velero", "cloudnative-pg"} <= set(items), items)
        releases = rel(*(pl._release_key(pl.CATALOG[n], n) for n in items), "kube-system/metrics-server")
        checks, rep, _ = fips_checks("gcp", FakeAwsCluster(nodes="n1=Container-Optimized OS from Google|6.1|\n"), releases)
        for item in items:
            row = checks[f"{item}: key generation/encryption uses non-FIPS-validated crypto"]
            self.assertEqual(row["status"], "FAIL", item)
            self.assertNotIn(f"{item}: FIPS-compatible", checks)
        self.assertEqual(checks["metrics-server: FIPS-compatible"]["status"], "PASS")
        self.assertEqual(rep["verdict"], "FAIL")
        checks, rep, _ = fips_checks("gcp", FakeAwsCluster(nodes="n1=Container-Optimized OS from Google|6.1|\n"), releases, wanted=False)
        self.assertEqual(checks["velero: key generation/encryption uses non-FIPS-validated crypto"]["status"], "INFO")
        self.assertEqual(rep["verdict"], "N/A")


class FipsAwsLiveTests(unittest.TestCase):
    NODES = "a=Bottlerocket OS 1.26.1 (aws-k8s-1.31-fips)|6.1||\nb=Bottlerocket OS 1.26.1 (aws-k8s-1.31)|6.1||default\n"

    def test_controllers_must_use_fips_endpoints(self):
        deployments = {"external-secrets": [deploy("external-secrets"), deploy("external-secrets-webhook", False),
                                            deploy("external-secrets-cert-controller", False)],
                       "karpenter": [deploy("karpenter", False)],
                       "external-dns": [deploy("external-dns", value="false")],
                       "aws-load-balancer-controller": [deploy("aws-load-balancer-controller")]}
        releases = rel("external-secrets/external-secrets", "kube-system/karpenter", "external-dns/external-dns",
                       "kube-system/aws-load-balancer-controller", "kube-system/cluster-autoscaler")
        fake = FakeAwsCluster(nodes=self.NODES, deployments=deployments, nodeclass_terms=[{"alias": "bottlerocket@latest"}])
        checks, _, _ = fips_checks("aws", fake, releases)
        row = lambda item: checks[f"{item}: AWS API calls go through FIPS endpoints (AWS_USE_FIPS_ENDPOINT=true)"]  # noqa: E731
        self.assertEqual(row("external-secrets")["status"], "PASS")   # its webhook and cert-controller call no AWS API
        self.assertEqual(row("aws-load-balancer-controller")["status"], "PASS")
        for item in ("karpenter", "external-dns"):
            self.assertEqual(row(item)["status"], "FAIL", item)
            self.assertIn(f"cs platform install {item} --upgrade", row(item)["detail"])
        self.assertEqual(row("cluster-autoscaler")["status"], "INFO")   # no Deployment found for its release
        nc = checks["karpenter: EC2NodeClass default selects Bottlerocket FIPS AMIs"]
        self.assertEqual(nc["status"], "FAIL")
        self.assertIn("bottlerocket@latest", nc["detail"])
        self.assertIn("cs platform install karpenter --upgrade", nc["detail"])

    def test_nodes_velero_and_a_fips_nodeclass(self):
        ssm = [{"ssmParameter": f"/aws/service/bottlerocket/aws-k8s-1.31-fips/{a}/latest/image_id"} for a in ("x86_64", "arm64")]
        fake = FakeAwsCluster(nodes=self.NODES, nodeclass_terms=ssm, bsl_url="https://s3.us-east-1.amazonaws.com")
        checks, _, _ = fips_checks("aws", fake, rel("velero/velero", "kube-system/karpenter"))
        self.assertEqual(checks["karpenter: EC2NodeClass default selects Bottlerocket FIPS AMIs"]["status"], "PASS")
        bsl = checks["velero: backup location default reaches S3 through its FIPS endpoint"]
        self.assertEqual(bsl["status"], "FAIL")
        self.assertIn("cs platform install velero --upgrade", bsl["detail"])
        eks = checks["EKS nodes run a Bottlerocket FIPS variant"]   # derived from the live nodes, not from fips_mode
        self.assertEqual(eks["status"], "FAIL")
        self.assertIn("1 of 2 node(s) run a standard image: b", eks["detail"])
        self.assertIn("Karpenter", eks["detail"])
        node_b = checks["node b: Bottlerocket OS 1.26.1 (aws-k8s-1.31)"]
        self.assertEqual(node_b["status"], "FAIL")
        self.assertIn("NodePool default", node_b["detail"])
        fake = FakeAwsCluster(nodes="a=Bottlerocket OS 1.26.1 (aws-k8s-1.31-fips)|6.1||\n")
        checks, _, _ = fips_checks("aws", fake, rel("velero/velero"))
        self.assertEqual(checks["EKS nodes run a Bottlerocket FIPS variant"]["status"], "PASS")
        self.assertEqual(checks["velero: backup location default reaches S3 through its FIPS endpoint"]["status"], "PASS")

    def test_a_node_image_needs_the_fips_suffix(self):
        aws = clouds.get("aws")
        for osi, ok in (("Bottlerocket OS 1.26.1 (aws-k8s-1.31-fips)", True), ("Bottlerocket OS 1.26.1 (aws-k8s-1.31)", False),
                        ("Bottlerocket OS 1.26.1 (aws-k8s-1.31-nvidia)", False), ("Amazon Linux 2023.5 (fipsmode)", False)):
            self.assertEqual(scan._node_fips(aws, {"os": osi, "aks_fips": "", "karpenter": ""})[0], ok, osi)

    def test_nothing_extra_outside_fips_environments_or_when_unreadable(self):
        fake = FakeAwsCluster(nodes=self.NODES, deployments={"karpenter": [deploy("karpenter", False)]}, unreadable=("deploy",))
        checks, _, _ = fips_checks("aws", fake, rel("kube-system/karpenter"), wanted=False)
        self.assertFalse([c for c in checks if "AWS API calls go through FIPS endpoints" in c or "EC2NodeClass" in c or "backup location" in c])
        checks, _, _ = fips_checks("aws", fake, rel("kube-system/karpenter"))
        row = checks["karpenter: AWS API calls go through FIPS endpoints (AWS_USE_FIPS_ENDPOINT=true)"]
        self.assertEqual(row["status"], "INFO")
        self.assertIn("could not be read", row["detail"])
        self.assertEqual(checks["karpenter: EC2NodeClasses select Bottlerocket FIPS AMIs"]["status"], "INFO")


if __name__ == "__main__":
    unittest.main()
