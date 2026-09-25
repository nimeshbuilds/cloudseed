"""Regression tests for the resilience fixes: chaos (injection checks, selectors, verdicts), DR (Velero phases, the drill's
volume check, Ctrl-C cleanup, CLI download), scans (kube-bench, prowler, kubescape/trivy installs, FIPS, reports) and
Python 3.9 compatibility. Stdlib only: every cluster, Velero and download call is faked."""

import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
import uuid
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import chaos, clouds, dr, paths, scan, ui, undo  # noqa: E402
from cloudseed import platform as pl  # noqa: E402

_RUN = uuid.uuid4().hex[:4]   # per test run: a reused CLOUDSEED_HOME never hands back an earlier run's environment

ROOT = Path(__file__).resolve().parent.parent


class FakeClock:
    """time replacement: sleep() advances the clock instantly."""

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


def cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


_n = [0]


def make_ctx(target="vmware", outputs=None):
    _n[0] += 1
    env = paths.Env(target, f"rs{_RUN}x{_n[0]}")
    env.create_dirs()
    cfg = {"env": env.name, "name": "t", "region": "r", "network_cidr": "10.0.0.0/16", "vars": {}}
    if outputs is None:
        outputs = {"kubernetes_distro": "rke2"} if target == "vmware" else {"kubernetes_cluster_name": "c"}
    return pl.Cluster(clouds.get(target), env, cfg, outputs, env.dir / "kc")


@contextlib.contextmanager
def silenced():
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


def _old_pythons() -> list:
    found = []
    for c in [shutil.which(n) for n in ("python3.9", "python3.10", "python3.11")] + ["/usr/bin/python3"]:
        if c and os.path.exists(c):
            try:
                v = subprocess.run([c, "-c", "import sys; print(sys.version_info[:2] < (3, 12))"], capture_output=True, text=True, timeout=30).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                continue
            if v == "True":
                found.append(c)
    return list(dict.fromkeys(found))


# ---------------------------------------------------------------- Python compatibility

class PythonCompatTests(unittest.TestCase):
    def test_every_module_compiles_on_old_python(self):
        olds = _old_pythons()
        if not olds:
            self.skipTest("no Python < 3.12 on this machine")
        files = [str(p) for p in sorted((ROOT / "cloudseed").rglob("*.py"))
                 if not p.name.startswith(".")] + [str(ROOT / "bin" / "cloudseed")]   # not AppleDouble ._*.py debris
        code = ("import sys\nbad = []\nfor p in sys.argv[1:]:\n    try:\n        compile(open(p, encoding='utf-8').read(), p, 'exec')\n"
                "    except SyntaxError as e:\n        bad.append('%s: %s' % (p, e))\nprint('\\n'.join(bad))\nsys.exit(1 if bad else 0)\n")
        for py in olds:
            r = subprocess.run([py, "-c", code, *files], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, f"{py}: {r.stdout}{r.stderr}")

    def test_cli_imports_and_parses_on_old_python(self):
        olds = _old_pythons()
        if not olds:
            self.skipTest("no Python < 3.12 on this machine")
        prog = ("import sys; sys.path.insert(0, %r); from cloudseed.cli import build_parser; p = build_parser(); "
                "a = p.parse_args(['vpn', 'add-user', 'aws', '--env', 'dev', 'alice']); "
                "b = p.parse_args(['node', 'add', '--count', '2', '--role', 'worker', 'vmware', '--env', 'dev']); "
                "c = p.parse_args(['chaos', 'run', '--env', 'dev', 'pod-kill', 'network']); "
                "print(a.name, b.cloud, b.count, ','.join(c.items))") % str(ROOT)
        for py in olds:
            r = subprocess.run([py, "-c", prog], capture_output=True, text=True, timeout=120, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            self.assertEqual(r.stdout.strip(), "alice vmware 2 pod-kill,network", f"{py}: {r.stderr[-800:]}")

    def test_optional_positional_after_options(self):
        from cloudseed.cli import build_parser
        p = build_parser()
        a = p.parse_args(["vpn", "add-user", "aws", "--env", "dev", "alice"])
        self.assertEqual((a.vpn_cmd, a.cloud, a.name), ("add-user", "aws", "alice"))
        a = p.parse_args(["node", "add", "--count", "2", "--role", "worker", "vmware", "--env", "dev"])
        self.assertEqual((a.cloud, a.count), ("vmware", 2))
        a = p.parse_args(["ui", "--port", "7760", "start"])
        self.assertEqual((a.ui_cmd, a.port), ("start", 7760))
        a = p.parse_args(["chaos", "run", "--env", "dev", "--duration", "30", "pod-kill", "network"])  # nargs="*" after options
        self.assertEqual((a.items, a.env, a.duration), (["pod-kill", "network"], "dev", 30))   # --duration is typed (cli-cluster)
        a = p.parse_args(["platform", "install", "--env", "dev", "velero"])
        self.assertEqual(a.items, ["velero"])
        a = p.parse_args(["chaos", "run", "--env", "dev"])
        self.assertFalse(a.items)
        with silenced(), self.assertRaises(SystemExit):
            p.parse_args(["node", "add", "--count", "2", "notacloud", "--env", "dev"])  # still validated against choices
        with silenced(), self.assertRaises(SystemExit):
            p.parse_args(["vpn", "add-user", "aws", "alice", "--env", "dev", "extra"])  # real leftovers still rejected

    def test_version_guard_runs_before_any_import(self):
        for rel, marker in (("bin/cloudseed", "from cloudseed.cli import main"), ("cloudseed/__main__.py", "from .cli import main")):
            src = (ROOT / rel).read_text()
            self.assertIn("sys.version_info < (3, 9)", src, rel)
            self.assertLess(src.index("sys.version_info < (3, 9)"), src.index(marker), rel)


# ---------------------------------------------------------------- chaos

def _status(injected=True, selected=True):
    conds = [{"type": "Selected", "status": "True" if selected else "False", "reason": "" if selected else "NoPodSelected"},
             {"type": "AllInjected", "status": "True" if injected else "False"}]
    recs = [{"id": "ns/pod", "phase": "Injected" if injected else "Not Injected", "injectedCount": 1 if injected else 0}] if selected else []
    return json.dumps({"status": {"conditions": conds, "experiment": {"containerRecords": recs}}})


class FakeChaosCluster:
    """kubectl stand-in for chaos: steady workload, probe answers per `probe_ok`, chaos objects report `status`."""

    def __init__(self, status=None, probe_ok=True, delete_rc=0, replicas="3,3", rollout_rc=0, deploy=None, svc=None, pods=None):
        self.status, self.probe_ok, self.delete_rc, self.replicas, self.rollout_rc = status or _status(), probe_ok, delete_rc, replicas, rollout_rc
        self.deploy, self.svc, self.pods = deploy, svc, pods or {"items": []}
        self.calls, self.applied = [], []

    def __call__(self, ctx, *args, input=None, check=False, timeout=120):
        self.calls.append(args)
        a = list(args)
        if "exec" in a:
            return cp(0, "ok\n" if self.probe_ok else "fail\n")
        if "apply" in a:
            self.applied.append(input)
            return cp(0)
        if "rollout" in a:
            return cp(self.rollout_rc, "", "" if self.rollout_rc == 0 else "error: deployment exceeded its progress deadline")
        if "wait" in a:
            return cp(0)
        if "delete" in a:
            chaos_kind = any(k in a for k in chaos.CHAOS_KINDS)
            return cp(self.delete_rc if chaos_kind and "-l" not in a else 0, "", "timed out waiting for the condition" if self.delete_rc else "")
        if "get" in a:
            if "events" in a:
                return cp(0, json.dumps({"items": [{"reason": "Failed", "message": "no pod is selected", "lastTimestamp": "2026-01-01T00:00:00Z"}]}))
            if any(k in a for k in chaos.CHAOS_KINDS) and "json" in a:
                return cp(0, self.status)
            if "pods" in a:
                return cp(0, json.dumps(self.pods))
            if "deploy" in a and "json" in a:
                return cp(0 if self.deploy else 1, json.dumps(self.deploy or {}))
            if "svc" in a:
                return cp(0 if self.svc else 1, json.dumps(self.svc or {}))
            if "deploy" in a:
                return cp(0, self.replicas)
        return cp(0)


class ChaosTests(unittest.TestCase):
    def _run_exp(self, name, fake, t=None, duration=10):
        ctx = make_ctx()
        t = t or chaos.Target(chaos.CANARY_NS, "canary", "canary", "canary", 8080, True)
        with mock.patch.object(chaos, "_kubectl", fake), mock.patch.object(chaos, "time", FakeClock()), silenced():
            return chaos.run_experiment(ctx, name, t, duration, "r1")

    def test_fault_never_injected_is_error_not_pass(self):
        fake = FakeChaosCluster(status=_status(injected=False, selected=False))
        r = self._run_exp("pod-kill", fake)
        self.assertEqual(r["verdict"], "ERROR")
        self.assertIn("not injected", r["reason"])
        self.assertIn("no pod is selected", r["reason"])

    def test_injected_fault_that_holds_passes(self):
        r = self._run_exp("pod-failure", FakeChaosCluster())
        self.assertEqual(r["verdict"], "PASS", r)
        self.assertTrue(r["injected"])

    def test_expected_outage_must_be_observed(self):
        r = self._run_exp("network-partition", FakeChaosCluster(probe_ok=True))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertIn("expected outage not observed", r["reason"])

    def test_fault_that_cannot_be_removed_is_error_and_stuck(self):
        r = self._run_exp("cpu-stress", FakeChaosCluster(delete_rc=124))
        self.assertEqual(r["verdict"], "ERROR")
        self.assertTrue(r.get("stuck"))
        self.assertIn("not removed", r["reason"])

    def test_kubectl_timeout_becomes_rc_124(self):
        ctx = make_ctx()
        with mock.patch.object(chaos.subprocess, "run", side_effect=subprocess.TimeoutExpired(["kubectl"], 20)), mock.patch.object(chaos.deps, "find", return_value="kubectl"):
            self.assertEqual(chaos._kubectl(ctx, "get", "pods").returncode, 124)
            with silenced(), self.assertRaises(SystemExit):
                chaos._kubectl(ctx, "get", "pods", check=True)

    def test_dns_patterns_only_trailing_wildcards(self):
        for t in (chaos.Target(chaos.CANARY_NS, "canary", "canary", "canary", 8080, True),
                  chaos.Target("shop", "api", "api-x", "api", 80, False, labels={"tier": "web", "app": "api-x"})):
            spec = chaos._experiment_manifest("dns-error", chaos.EXPERIMENTS["dns-error"], t, "30s", "r")["spec"]
            self.assertTrue(spec["patterns"])
            for p in spec["patterns"]:
                self.assertNotIn("*", p[:-1], p)
                self.assertTrue(p.startswith(t.svc), p)

    def test_resolve_names_validates_before_the_cluster(self):
        self.assertEqual(chaos.resolve_names(["basic", "pod-kill"]), chaos.SUITES["basic"])
        self.assertEqual(chaos.resolve_names(None, "network"), chaos.SUITES["network"])
        ctx = make_ctx()
        with mock.patch.object(chaos, "ensure_chaos_mesh") as ecm, mock.patch.object(pl, "ensure_tools") as et, silenced():
            with self.assertRaises(SystemExit):
                chaos.run(ctx, ["pod-kil"], None, None, 10, 2, False)
            with self.assertRaises(SystemExit):
                chaos.run(ctx, ["pod-kill"], None, "bad target/x:y:z", 10, 2, False)
        ecm.assert_not_called()
        et.assert_not_called()

    def _user_target(self, selector, ports, target="shop/api"):
        deploy = {"spec": {"selector": selector, "template": {"spec": {"containers": [{"name": "server"}]}}}}
        pods = {"items": [{"metadata": {"name": "api-7d9-abc", "labels": {"pod-template-hash": "7d9"}, "ownerReferences": [{"kind": "ReplicaSet", "name": "api-7d9"}]}},
                          {"metadata": {"name": "other-1", "labels": {"pod-template-hash": "55"}, "ownerReferences": [{"kind": "ReplicaSet", "name": "other-55"}]}}]}
        fake = FakeChaosCluster(deploy=deploy, svc={"spec": {"ports": ports}}, pods=pods)
        with mock.patch.object(chaos, "_kubectl", fake), silenced() as (out, err):
            t = chaos.resolve_target(make_ctx(), target, 2)
        return t, fake, err.getvalue()

    def test_target_uses_the_full_selector_without_global_state(self):
        labels = {"app.kubernetes.io/instance": "argocd", "app.kubernetes.io/name": "argocd-server"}
        t, fake, err = self._user_target({"matchLabels": labels}, [{"name": "https", "port": 443}])
        for name in ("pod-kill", "network-delay", "cpu-stress", "time-skew"):
            sel = chaos._experiment_manifest(name, chaos.EXPERIMENTS[name], t, "30s", "r")["spec"]["selector"]
            self.assertEqual(sel["labelSelectors"], labels, name)
        self.assertEqual(chaos._experiment_manifest("container-kill", chaos.EXPERIMENTS["container-kill"], t, "30s", "r")["spec"]["containerNames"], ["server"])
        self.assertFalse(any("_label_key" in e for e in chaos.EXPERIMENTS.values()))
        self.assertEqual(t.port, 443)
        self.assertIn("other-1", err)  # pods of other workloads matched by the selector are called out
        probe = [m for m in fake.applied if m and "kind: Pod" in m]
        self.assertTrue(probe and "runAsNonRoot: true" in probe[0])

    def test_target_with_match_expressions_and_named_port(self):
        exprs = [{"key": "tier", "operator": "In", "values": ["web"]}]
        t, _, _ = self._user_target({"matchExpressions": exprs}, [{"name": "metrics", "port": 9090}, {"name": "http", "port": 8081}], "shop/api:http")
        sel = t.selector()
        self.assertEqual(sel["expressionSelectors"], exprs)
        self.assertNotIn("labelSelectors", sel)
        self.assertEqual(t.port, 8081)
        self.assertEqual(t.selector_text(), "tier in (web)")
        with self.assertRaises(SystemExit) as cm:
            self._user_target({"matchLabels": {"app": "api"}}, [{"name": "http", "port": 80}], "shop/api:grpc")
        self.assertIn("no port named 'grpc'", cm.exception.msg)

    def test_canary_rollout_failure_aborts_and_cleans_up(self):
        fake = FakeChaosCluster(rollout_rc=1)
        ctx = make_ctx()
        with mock.patch.object(chaos, "_kubectl", fake), silenced(), self.assertRaises(SystemExit) as cm:
            chaos.deploy_canary(ctx, 3)
        self.assertIn("did not become ready", cm.exception.msg)
        self.assertIn(("delete", "ns", chaos.CANARY_NS, "--ignore-not-found", "--wait=false"), fake.calls)

    def _run(self, fake, run_exp=None, names=("basic",)):
        ctx = make_ctx()
        t = chaos.Target(chaos.CANARY_NS, "canary", "canary", "canary", 8080, True)
        patches = [mock.patch.object(chaos, "_kubectl", fake), mock.patch.object(chaos, "time", FakeClock()),
                   mock.patch.object(chaos, "ensure_chaos_mesh"), mock.patch.object(pl, "ensure_tools"),
                   mock.patch.object(chaos, "dns_chaos_available", return_value=True), mock.patch.object(chaos, "resolve_target", return_value=t)]
        if run_exp:
            patches.append(mock.patch.object(chaos, "run_experiment", side_effect=run_exp))
        with contextlib.ExitStack() as st, silenced():
            for p in patches:
                st.enter_context(p)
            rc = chaos.run(ctx, list(names), None, None, 10, 2, False)
        return rc, json.loads(chaos.last_report(ctx.env).read_text())

    def test_unsteady_target_is_inconclusive_not_pass(self):
        rc, rep = self._run(FakeChaosCluster(replicas="0,3"))
        self.assertEqual(rc, 1)
        self.assertEqual(rep["verdict"], "INCONCLUSIVE")
        self.assertEqual(rep["summary"]["SKIP"], len(chaos.SUITES["basic"]))

    def test_run_survives_an_unexpected_error_and_saves_the_report(self):
        def exp(ctx, name, t, d, run_id):
            if name == "pod-kill":
                return {"experiment": name, "verdict": "PASS", "availability": 1.0, "min_availability": 0.5, "recovery_s": 1, "recovery_bound_s": 90, "reason": ""}
            raise subprocess.TimeoutExpired(["kubectl", "exec"], 20)
        fake = FakeChaosCluster()
        rc, rep = self._run(fake, run_exp=exp)
        self.assertEqual(rc, 1)
        verdicts = {r["experiment"]: r["verdict"] for r in rep["results"]}
        self.assertEqual(verdicts["pod-kill"], "PASS")
        self.assertEqual(verdicts["pod-failure"], "ERROR")
        self.assertEqual(verdicts["container-kill"], "SKIP")
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertTrue(any("delete" in c and "ns" in c for c in fake.calls))  # cleanup still ran

    def test_all_pass_is_pass_and_empty_is_not(self):
        def exp(ctx, name, t, d, run_id):
            return {"experiment": name, "verdict": "PASS", "availability": 1.0, "min_availability": 0.5, "recovery_s": 1, "recovery_bound_s": 90, "reason": ""}
        rc, rep = self._run(FakeChaosCluster(), run_exp=exp)
        self.assertEqual((rc, rep["verdict"]), (0, "PASS"))
        self.assertEqual(chaos.overall_verdict({"results": [], "summary": {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}}), "INCONCLUSIVE")

    def test_workloads_are_hardened_and_have_no_shell_endpoint(self):
        for m in (chaos.CANARY_MANIFEST, dr.DRILL_MANIFEST):
            self.assertNotIn("netexec", m)
            self.assertIn("serve-hostname", m)
            self.assertIn("runAsNonRoot: true", m)
            self.assertIn("automountServiceAccountToken: false", m)
            self.assertIn("drop: [ALL]", m)
        rendered = chaos.CANARY_MANIFEST % {"ns": "x", "name": "canary", "replicas": 2, "probe": "p", "label": chaos.LABEL}
        self.assertIn("name: p", rendered)

    def test_list_shows_full_descriptions(self):
        with silenced() as (out, _):
            chaos.list_experiments()
        text = re.sub(r"\s+", " ", ui._strip(out.getvalue()))
        self.assertIn("they must keep serving", text)
        self.assertIn("recover <= 90s", text)


# ---------------------------------------------------------------- DR

class FakeVelero:
    """velero stand-in: phases per (kind, name) prefix."""

    def __init__(self, phases, extra=None):
        self.phases, self.extra, self.calls = phases, extra or {}, []

    def __call__(self, ctx, *args, check=True, stream=False, timeout=1800, quiet=False):
        self.calls.append(args)
        if len(args) >= 3 and args[1] == "get" and "json" in args:
            st = {"phase": self.phases.get(args[0], "")}
            st.update(self.extra.get(args[0], {}))
            return cp(0, json.dumps({"status": st}))
        return cp(0, "Backup completed with status: whatever.")


class DrTests(unittest.TestCase):
    def _call(self, fn, velero, *args):
        ctx = make_ctx()
        with mock.patch.object(dr, "require"), mock.patch.object(dr, "_velero", velero), mock.patch.object(dr, "time", FakeClock()), \
                mock.patch.object(dr, "_kubectl", return_value=cp(1, "", "no cluster in unit tests")), silenced() as (out, err):
            try:
                return fn(ctx, *args), out.getvalue() + err.getvalue()
            except SystemExit as e:
                return e, out.getvalue() + err.getvalue()

    def test_backup_reports_the_real_phase(self):
        res, _ = self._call(dr.backup, FakeVelero({"backup": "Failed"}, {"backup": {"failureReason": "bucket gone"}}), "b1", None)
        self.assertIsInstance(res, SystemExit)
        self.assertIn("bucket gone", res.msg)
        res, _ = self._call(dr.backup, FakeVelero({"backup": "PartiallyFailed"}, {"backup": {"errors": 2}}), "b1", None)
        self.assertIsInstance(res, SystemExit)
        self.assertIn("PartiallyFailed", res.msg)
        res, text = self._call(dr.backup, FakeVelero({"backup": "Completed"}), "b1", None)
        self.assertEqual(res, "b1")
        self.assertIn("Completed", text)

    def test_restore_phases(self):
        res, _ = self._call(dr.restore, FakeVelero({"restore": "FailedValidation"}, {"restore": {"validationErrors": ["backup not found"]}}), "nope", None)
        self.assertIsInstance(res, SystemExit)
        self.assertIn("backup not found", res.msg)
        res, text = self._call(dr.restore, FakeVelero({"restore": "PartiallyFailed"}), "b1", None)
        self.assertTrue(str(res).startswith("b1-restore-"))
        self.assertIn("PartiallyFailed", text)
        self.assertNotIn("✔", text)

    def test_schedule_rejects_bad_cron_and_failed_validation(self):
        for good in ("0 2 * * *", "@daily", "@every 6h", "CRON_TZ=Europe/Berlin 0 2 * * *", "TZ=UTC @weekly"):
            self.assertTrue(dr.CRON_RE.match(good), good)
        for bad in ("bogus", "0 2 * *", "0 2 * * * *", "CRON_TZ=UTC", "@often"):
            self.assertFalse(dr.CRON_RE.match(bad), bad)
        v = FakeVelero({})
        res, _ = self._call(dr.schedule, v, "nightly", "bogus", None, "720h")
        self.assertIsInstance(res, SystemExit)
        self.assertEqual(v.calls, [])
        v = FakeVelero({"schedule": "FailedValidation"}, {"schedule": {"validationErrors": ["invalid schedule"]}})
        res, _ = self._call(dr.schedule, v, "nightly", "61 * * * *", None, "720h")
        self.assertIsInstance(res, SystemExit)
        self.assertIn("invalid schedule", res.msg)
        self.assertIn(("schedule", "delete", "nightly", "--confirm"), v.calls)
        res, text = self._call(dr.schedule, FakeVelero({"schedule": "Enabled"}), "nightly", "@daily", None, "720h")
        self.assertIsNone(res)
        self.assertIn("Schedule nightly", text)

    def test_image_version_parsing(self):
        cases = {"velero/velero:v1.18.2": "v1.18.2", "velero/velero@sha256:" + "a" * 64: None, "velero/velero:v1.18.2@sha256:" + "b" * 64: "v1.18.2",
                 "registry.local:5000/velero/velero": None, "registry.local:5000/velero/velero:v1.17.1-fips": "v1.17.1", "velero/velero:latest": None}
        for img, want in cases.items():
            self.assertEqual(dr.image_version(img), want, img)

    def _tarball(self, member="velero-v1.18.2-darwin-arm64/velero"):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"#!/bin/sh\necho 'Client:'\necho '\tVersion: v1.18.2'\n"
            info = tarfile.TarInfo(member)
            info.size, info.mode = len(data), 0o755
            tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def _ensure(self, get, existing=None):
        d = Path(tempfile.mkdtemp())
        if existing:
            (d / "velero").write_text(existing)
            (d / "velero").chmod(0o755)
        ctx = make_ctx()
        with mock.patch.object(paths, "BIN_DIR", d), mock.patch.object(dr, "server_version", return_value="v1.18.2"), \
                mock.patch.object(dr, "_get", side_effect=get), mock.patch.object(dr._platform, "system", return_value="Darwin"), \
                mock.patch.object(dr._platform, "machine", return_value="arm64"), mock.patch.object(dr, "_fetch_refusal", return_value=""), \
                silenced() as (out, err):
            try:
                return dr.ensure_cli(ctx), d, err.getvalue()
            except SystemExit as e:
                return e, d, err.getvalue()

    def test_ensure_cli_verifies_the_checksum(self):
        blob = self._tarball()
        good = f"{hashlib.sha256(blob).hexdigest()}  velero-v1.18.2-darwin-arm64.tar.gz\n".encode()
        res, d, _ = self._ensure(lambda url, t: blob if url.endswith(".tar.gz") else good)
        self.assertEqual(res, str(d / "velero"))
        self.assertTrue(os.access(d / "velero", os.X_OK))
        bad = f"{'0' * 64}  velero-v1.18.2-darwin-arm64.tar.gz\n".encode()
        res, d, _ = self._ensure(lambda url, t: blob if url.endswith(".tar.gz") else bad)
        self.assertIsInstance(res, SystemExit)
        self.assertIn("Checksum mismatch", res.msg)
        self.assertFalse((d / "velero").exists())

    def test_ensure_cli_offline(self):
        def down(url, t):
            raise urllib.error.URLError("no route to host")
        res, _, _ = self._ensure(down)
        self.assertIsInstance(res, SystemExit)
        self.assertIn("Could not download the velero CLI", res.msg)
        res, d, err = self._ensure(down, existing="#!/bin/sh\necho 'Version: v1.17.0'\n")
        self.assertEqual(res, str(d / "velero"))
        self.assertIn("using the installed v1.17.0", err)

    def test_status_never_waits_and_shows_the_location_error(self):
        ctx = make_ctx()
        bsl = {"items": [{"metadata": {"name": "default"}, "spec": {"provider": "aws", "objectStorage": {"bucket": "b"}},
                          "status": {"phase": "Unavailable", "message": "AccessDenied: bucket policy", "lastValidationTime": "2026-01-01T00:00:00Z"}}]}
        sched = {"items": [{"metadata": {"name": "nightly"}, "spec": {"schedule": "0 2 * * *", "template": {"ttl": "720h0m0s"}}, "status": {"phase": "Enabled", "lastBackup": "2026-01-02T02:00:00Z"}},
                           {"metadata": {"name": "weekly"}, "spec": {"schedule": "0 3 * * 0"}, "status": {"phase": "Enabled"}}]}

        def kubectl(ctx_, *args, input=None, timeout=180):   # status reads Velero's objects with kubectl: no velero CLI
            kinds = {"backupstoragelocations.velero.io": bsl, "backups.velero.io": {"items": []}, "schedules.velero.io": sched}
            return cp(0, json.dumps(kinds[args[3]])) if len(args) > 3 and args[3] in kinds else cp(0, "2/2")
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_velero", side_effect=AssertionError("no velero CLI")), \
                mock.patch.object(dr, "_kubectl", kubectl), mock.patch.object(dr, "server_version", return_value="v1.18.2"), \
                mock.patch.object(dr, "ensure_cli", side_effect=AssertionError("status needs no velero CLI")), \
                mock.patch.object(dr, "wait_location", side_effect=AssertionError("status must not wait")), silenced() as (out, _):
            dr.status(ctx)
        text = ui._strip(out.getvalue())
        self.assertIn("AccessDenied", text)
        self.assertIn("schedule nightly", text)
        self.assertIn("schedule weekly", text)
        self.assertNotIn("$ velero", text)


class FakeDrillCluster:
    """A cluster for the DR drill: tracks the drill volume, what the backup captured and what a restore brings back."""

    def __init__(self, backs_up_volume=True, restores_volume=True):
        self.backs_up_volume, self.restores_volume = backs_up_volume, restores_volume
        self.volume, self.snapshot, self.token, self.calls, self.velero_calls = None, None, None, [], []
        self.interrupt_on = None

    def kubectl(self, ctx, *args, input=None, timeout=180):
        self.calls.append(args)
        a = list(args)
        if "apply" in a:
            self.token = re.search(r'token: "([^"]+)"', input).group(1)
            self.assertion_pod_cmd = input
            return cp(0)
        if "exec" in a:
            cmd = a[-1]
            m = re.match(r"echo (\w+) > /data/token", cmd)
            if m:
                self.volume = m.group(1)
                return cp(0, self.volume + "\n")
            return cp(0 if self.volume else 1, (self.volume or "") + "\n", "" if self.volume else "cat: can't open '/data/token'")
        if a[:2] == ["delete", "ns"] and "--wait=true" in a:
            self.volume = None
            return cp(0)
        if a[:2] == ["get", "ns"]:
            return cp(1)
        if "sc" in a:
            return cp(0, "local-path")
        if "podvolumebackups" in a:
            return cp(0, "Completed\n" if self.backs_up_volume else "")
        if "podvolumerestores" in a:
            return cp(0, "Completed\n")
        if "cm" in a:
            return cp(0, self.token)
        if "secret" in a:
            return cp(0, base64.b64encode(self.token.encode()).decode())
        return cp(0)

    def velero(self, ctx, *args, check=True, stream=False, timeout=1800, quiet=False):
        self.velero_calls.append(args)
        if self.interrupt_on and args[:2] == self.interrupt_on:
            raise KeyboardInterrupt
        if args[:2] == ("backup", "create"):
            self.snapshot = self.volume if self.backs_up_volume else None
        if args[:2] == ("restore", "create") and self.restores_volume:
            self.volume = self.snapshot
        if len(args) >= 2 and args[1] == "get":
            return cp(0, json.dumps({"status": {"phase": "Completed"}}))
        return cp(0)


class DrillTests(unittest.TestCase):
    def _drill(self, fake):
        ctx = make_ctx()
        with mock.patch.object(dr, "require"), mock.patch.object(dr, "_kubectl", fake.kubectl), mock.patch.object(dr, "_velero", fake.velero), \
                mock.patch.object(dr, "server_version", return_value="v1.18.2"), silenced():
            rc = dr.test(ctx)
        return rc, json.loads(dr.last_report(ctx.env).read_text())

    def test_writer_pod_never_writes_the_token(self):
        pvc = dr.DRILL_PVC % {"ns": dr.DRILL_NS}
        self.assertNotIn("echo", pvc)
        self.assertNotIn("token", pvc)

    def test_restored_volume_passes(self):
        fake = FakeDrillCluster()
        rc, rep = self._drill(fake)
        self.assertEqual((rc, rep["verdict"]), (0, "PASS"), rep)
        self.assertNotIn(fake.volume, fake.assertion_pod_cmd)  # the volume token never appears in any manifest
        self.assertIn(("backup", "delete", rep["steps"][1]["detail"].split()[0], "--confirm"), fake.velero_calls)

    def test_volume_that_was_not_backed_up_fails(self):
        rc, rep = self._drill(FakeDrillCluster(backs_up_volume=False))
        self.assertEqual((rc, rep["verdict"]), (1, "FAIL"))
        self.assertIn("NOT backed up", rep["steps"][-1]["detail"])

    def test_empty_restored_volume_fails_verification(self):
        fake = FakeDrillCluster(restores_volume=False)
        rc, rep = self._drill(fake)
        self.assertEqual((rc, rep["verdict"]), (1, "FAIL"))
        self.assertEqual(rep["steps"][-1]["step"], "5. verify")
        self.assertIn("volume content not restored", rep["steps"][-1]["detail"])

    def test_ctrl_c_cleans_up_and_reports(self):
        fake = FakeDrillCluster()
        fake.interrupt_on = ("restore", "create")
        rc, rep = self._drill(fake)
        self.assertEqual((rc, rep["verdict"]), (130, "INTERRUPTED"))
        self.assertTrue(any(c[:2] == ("backup", "delete") for c in fake.velero_calls))
        self.assertTrue(any(c[:2] == ("restore", "delete") for c in fake.velero_calls))
        self.assertIn(("delete", "ns", dr.DRILL_NS, "--ignore-not-found", "--wait=false"), fake.calls)

    def test_undo_pre_backup_rejects_failed_backups_and_never_blocks(self):
        ctx = make_ctx()
        # (the unusable-backup hint reads the storage location with kubectl: no cluster in unit tests)
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_velero", FakeVelero({"backup": "Failed"})), \
                mock.patch.object(dr, "_kubectl", return_value=cp(1, "", "no cluster in unit tests")), silenced():
            self.assertIsNone(undo.velero_pre_backup(ctx, "kubectl", ["shop"]))
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_velero", FakeVelero({"backup": "Completed"})), silenced():
            self.assertTrue(undo.velero_pre_backup(ctx, "kubectl", ["shop"]).startswith("pre-kubectl-"))

        def boom(*a, **k):
            raise ui.Abort("Could not download the velero CLI")
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_velero", boom), silenced():
            self.assertIsNone(undo.velero_pre_backup(ctx, "helm", ["shop"]))

    def test_local_path_storage_class_makes_backup_able_volumes(self):
        self.assertIn("defaultVolumeType: local", pl.POST_MANIFESTS["local-path-default"])


# ---------------------------------------------------------------- scans

class ScanTests(unittest.TestCase):
    def test_reports_skip_raw_tool_output_and_sort_by_time(self):
        env = paths.Env("aws", "scanrep")
        env.create_dirs()
        d = env.dir / "scans"
        d.mkdir(parents=True, exist_ok=True)
        for stem, md in (("cis-20260101-000000", True), ("kubescape-20260101-000001", False), ("trivy-20260101-000002", False),
                         ("fips-20250101-000000", True), ("host-cis-20260102-000000", True)):
            (d / f"{stem}.json").write_text("{}")
            if md:
                (d / f"{stem}.md").write_text("")
        self.assertEqual([p.stem for p in scan.reports(env)], ["fips-20250101-000000", "cis-20260101-000000", "host-cis-20260102-000000"])

    def test_kube_bench_mounts_per_distro(self):
        for distro in ("eks", "gke", "aks", "rke2", "kubeadm"):
            for role in ("master", "node"):
                m = scan._kube_bench_manifest(distro, role, "", ["kube-bench", "run", "--json"])
                self.assertNotIn("DirectoryOrCreate", m)
                self.assertNotIn(":latest", m)
                self.assertIn("activeDeadlineSeconds", m)
                self.assertEqual(m.count("mountPath:"), m.count("hostPath:"))
                if distro in ("gke", "eks"):
                    self.assertNotIn("/srv/kubernetes", m)
                    self.assertNotIn("/opt/cni/bin", m)
        self.assertIn("path: /home/kubernetes", scan._kube_bench_manifest("gke", "node", "", ["kube-bench"]))
        self.assertIn("path: /etc/default", scan._kube_bench_manifest("aks", "node", "", ["kube-bench"]))
        self.assertIn("path: /var/lib/rancher", scan._kube_bench_manifest("rke2", "master", "", ["kube-bench"]))
        self.assertNotIn("/var/lib/etcd", scan._kube_bench_manifest("kubeadm", "node", "", ["kube-bench"]))

    def _kb(self, rounds):
        """Fake kubectl for kube-bench: `rounds` is a list of (job status, pods, logs) per Job created."""
        state = {"n": -1, "applied": [], "deletes": []}

        def fake(ctx, *args, input=None, timeout=300):
            a = list(args)
            if "delete" in a:
                state["deletes"].append(a)
            if "apply" in a:
                state["n"] += 1
                state["applied"].append(input)
                return cp(0)
            job, pods, logs = rounds[min(state["n"], len(rounds) - 1)]
            if "job" in a and "get" in a:
                return cp(0, json.dumps({"status": job}))
            if "pods" in a:
                return cp(0, json.dumps({"items": pods}))
            if "logs" in a:
                return cp(0, logs)
            if "events" in a:
                return cp(0, "LAST SEEN   TYPE   REASON\n1m   Warning   Failed   pull failed")
            return cp(0)
        return fake, state

    def test_kube_bench_image_pull_failure_fails_fast_without_retry(self):
        pod = {"status": {"phase": "Pending", "containerStatuses": [{"state": {"waiting": {"reason": "ImagePullBackOff", "message": "toomanyrequests"}}}]}}
        fake, state = self._kb([({}, [pod], "")])
        ctx = make_ctx()
        with mock.patch.object(scan, "_kubectl", fake), mock.patch.object(scan, "time", FakeClock()), silenced() as (out, _), self.assertRaises(SystemExit) as cm:
            scan._kube_bench_run(ctx, "master", "rke2-cis-1.9", "master")
        self.assertIn("ImagePullBackOff", cm.exception.msg)
        self.assertEqual(len(state["applied"]), 1)
        # the previous run's Job is removed with its pods before the new one starts (no stale pod state on the first poll)
        self.assertIn("--cascade=foreground", state["deletes"][0])
        self.assertNotIn("kube-bench master finished", out.getvalue())

    def test_kube_bench_retries_auto_detection_only_when_it_ran(self):
        failed = ({"conditions": [{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}]},
                  [{"status": {"containerStatuses": [{"state": {"terminated": {"exitCode": 1}}}]}}], "unable to find benchmark rke2-cis-1.9")
        done = ({"succeeded": 1}, [{"status": {"containerStatuses": [{"state": {"terminated": {"exitCode": 0}}}]}}], 'noise {"Controls": [{"tests": []}]}')
        fake, state = self._kb([failed, done])
        ctx = make_ctx()
        with mock.patch.object(scan, "_kubectl", fake), mock.patch.object(scan, "time", FakeClock()), silenced():
            data = scan._kube_bench_run(ctx, "master", "rke2-cis-1.9", "master")
        self.assertEqual(data, {"Controls": [{"tests": []}]})
        self.assertEqual(len(state["applied"]), 2)
        self.assertIn("--benchmark", state["applied"][0])
        self.assertNotIn("--benchmark", state["applied"][1])

    def test_host_scan_keeps_host_key_checking_and_skips_blank_lines(self):
        env = paths.Env("aws", "hostscan")
        env.create_dirs()
        seen = {}

        class Child:
            stdout = iter(["PLAY [scan]\n", "\n", "   \n", "fatal: [bastion]: FAILED!\n"])

            def wait(self):
                return 0

        def popen(cmd, env=None, **kw):
            seen["env"] = env
            return Child()
        with mock.patch.object(scan, "_hosts", return_value=[("bastion", "192.0.2.10")]), mock.patch.object(scan.prov, "Host"), \
                mock.patch.object(scan, "_ssg_version", return_value="0.1.82"), mock.patch.object(scan.deps, "ensure_local_ansible", return_value=Path("/bin/true")), \
                mock.patch.object(scan.subprocess, "Popen", popen), silenced() as (out, _):
            scan.host(clouds.get("aws"), env, {"vars": {}}, {}, ["bastion"])
        self.assertEqual(seen["env"]["ANSIBLE_HOST_KEY_CHECKING"], "True")
        lines = out.getvalue().splitlines()
        self.assertEqual([ln for ln in lines if ln and not ln.strip()], [])  # no whitespace-only lines from ansible's blank output
        self.assertIn("FAILED", out.getvalue())
        self.assertNotIn('ANSIBLE_HOST_KEY_CHECKING="False"', (ROOT / "cloudseed" / "provision.py").read_text())

    def test_images_keep_every_critical_and_say_when_truncated(self):
        items = []
        for i in range(3):
            vulns = [{"severity": "HIGH", "vulnerabilityID": f"CVE-H-{i}-{j}"} for j in range(10)] + [{"severity": "CRITICAL", "vulnerabilityID": f"CVE-C-{i}"}]
            items.append({"metadata": {"namespace": "ns", "name": f"w{i}"}, "report": {"summary": {"criticalCount": 1, "highCount": 10}, "vulnerabilities": vulns}})
        ctx = make_ctx()
        with mock.patch.object(scan, "_kubectl", return_value=cp(0, json.dumps({"items": items}))), mock.patch.object(scan, "_ensure_kubectl"), \
                mock.patch.object(scan, "IMAGE_FINDINGS_MAX", 5), silenced() as (out, _):
            path = scan.images(ctx)
        rep = json.loads(path.read_text())
        self.assertEqual(rep["findings_total"], 33)
        self.assertEqual(len(rep["findings"]), 5)
        self.assertEqual([f["severity"] for f in rep["findings"][:3]], ["CRITICAL"] * 3)
        self.assertIn("first 5 of 33", ui._strip(out.getvalue()))
        self.assertEqual(rep["verdict"], "FAIL")

    def test_prowler_python_choice(self):
        fake_sys = SimpleNamespace(executable="/opt/py314", version_info=(3, 14, 0), version="3.14.0 (main)")
        which = {"python3.13": "/opt/py313", "python3": "/opt/py314"}
        vers = {"/opt/py313": (3, 13), "/opt/py314": (3, 14)}
        with mock.patch.object(scan, "sys", fake_sys), mock.patch.object(scan.shutil, "which", side_effect=which.get), \
                mock.patch.object(scan, "_py_version", side_effect=vers.get), mock.patch.object(scan.paths, "IS_BUNDLE", False):
            self.assertEqual(scan._prowler_python(), ("/opt/py313", (3, 13)))
        with mock.patch.object(scan, "sys", fake_sys), mock.patch.object(scan.shutil, "which", return_value=None), \
                mock.patch.object(scan.paths, "IS_BUNDLE", False), silenced(), self.assertRaises(SystemExit) as cm:
            scan._prowler_python()
        self.assertIn("3.10-3.13", cm.exception.msg)

    def test_broken_prowler_venv_is_detected(self):
        venv = Path(tempfile.mkdtemp())
        (venv / "bin").mkdir()
        (venv / "bin" / "python").write_text("")
        with mock.patch.object(scan, "_py_version", return_value=(3, 14)):
            self.assertIn("3.14", scan._prowler_problem(venv))
        with mock.patch.object(scan, "_py_version", return_value=(3, 12)), mock.patch.object(scan.subprocess, "run", return_value=cp(0, "3.11.3\n")):
            self.assertIn("3.11.3", scan._prowler_problem(venv))
        with mock.patch.object(scan, "_py_version", return_value=(3, 12)), mock.patch.object(scan.subprocess, "run", return_value=cp(0, "5.43.0\n")):
            self.assertEqual(scan._prowler_problem(venv), "")

    def _cloud_scan(self, cloud_key, cfg, main_run):
        env = paths.Env(cloud_key, f"cs{_RUN}x{_n[0]}")
        _n[0] += 1
        env.create_dirs()
        seen = {}

        def run(cmd, **kw):
            if "--list-compliance" in cmd:
                return cp(0, f"cis_2.0_{cloud_key} cis_6.0_{cloud_key} cis_10.0_{cloud_key} other")
            seen["cmd"] = cmd
            return main_run(cmd)
        with mock.patch.object(scan, "_prowler", return_value="/fake/prowler"), mock.patch.object(scan.subprocess, "run", side_effect=run), silenced() as (out, err):
            try:
                res = scan.cloud_scan(clouds.get(cloud_key), env, cfg)
            except SystemExit as e:
                res = e
        return res, seen.get("cmd", []), out.getvalue() + err.getvalue(), env

    def test_cloud_scan_scopes_azure_and_picks_the_newest_cis(self):
        def main_run(cmd):
            outdir = Path(cmd[cmd.index("-o") + 1])
            (outdir / "prowler-output.ocsf.json").write_text(json.dumps([{"status_code": "FAIL", "severity": "High", "finding_info": {"title": "t"}}]))
            return cp(0)
        with mock.patch.object(scan, "_azure_auth", return_value=["--az-cli-auth"]):
            res, cmd, _, _ = self._cloud_scan("azure", {"vars": {"subscription_id": "1111-2222"}}, main_run)
        self.assertIsInstance(res, Path)
        self.assertEqual(cmd[cmd.index("--subscription-ids") + 1], "1111-2222")
        self.assertEqual(cmd[cmd.index("--compliance") + 1], "cis_10.0_azure")
        self.assertEqual(json.loads(res.read_text())["verdict"], "FAIL")

    def test_cloud_scan_failure_is_explained_and_cleaned_up(self):
        res, cmd, text, env = self._cloud_scan("aws", {"vars": {}}, lambda cmd: cp(1, "", "2026 CRITICAL: NoCredentialsError: Unable to locate credentials"))
        self.assertIsInstance(res, SystemExit)
        self.assertIn("aws configure", res.msg)
        self.assertNotIn("prowler finished", text)
        self.assertEqual(list((env.dir / "scans").glob("prowler-*")), [])

    def test_fips_gcp_images_and_non_fips_verdict(self):
        env = paths.Env("gcp", "fipsg")
        env.create_dirs()
        gcp = clouds.get("gcp")
        with mock.patch.object(scan, "_hosts", return_value=[]), silenced():
            p = scan.fips(gcp, env, {"vars": {"fips_mode": True}, "extra_vars": {"bastion_image": "ubuntu-os-cloud/ubuntu-2404-lts-amd64"}, "ssh_public_key": "ecdsa-sha2-nistp384 AAAA"}, {})
            chk = {c["check"]: c for c in json.loads(p.read_text())["checks"]}
            self.assertEqual(chk["bastion image is Ubuntu Pro FIPS"]["status"], "FAIL")
            self.assertEqual(chk["bastion image is Ubuntu Pro FIPS"]["detail"], "ubuntu-os-cloud/ubuntu-2404-lts-amd64")
            p = scan.fips(gcp, env, {"vars": {"fips_mode": True}, "ssh_public_key": "ecdsa-sha2-nistp384 AAAA"}, {})
            rep = json.loads(p.read_text())
            self.assertEqual({c["check"]: c["status"] for c in rep["checks"]}["bastion image is Ubuntu Pro FIPS"], "PASS")
            self.assertEqual(rep["verdict"], "PASS")
            p = scan.fips(gcp, env, {"vars": {}}, {})
            rep = json.loads(p.read_text())
            self.assertEqual(rep["verdict"], "N/A")
            self.assertEqual({c["check"]: c["status"] for c in rep["checks"]}["environment SSH key is FIPS-approved (RSA-4096; ECDSA only on GCP/VMware)"], "INFO")

    def test_gcp_vpn_image_follows_the_terraform_module(self):
        root = Path(tempfile.mkdtemp())
        mod = root / "terraform" / "gcp" / "modules" / "vpn"
        mod.mkdir(parents=True)
        (mod / "main.tf").write_text('  boot_disk {\n    initialize_params {\n      image = var.fips_mode ? "ubuntu-os-pro-cloud/ubuntu-pro-fips-2204-lts" : "ubuntu-os-cloud/ubuntu-2404-lts-amd64"\n')
        with mock.patch.object(scan.paths, "REPO_ROOT", root):
            self.assertIn("ubuntu-pro-fips", scan._gcp_vpn_image(True))
            self.assertEqual(scan._gcp_vpn_image(False), "ubuntu-os-cloud/ubuntu-2404-lts-amd64")
        (mod / "main.tf").write_text('      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"\n')
        with mock.patch.object(scan.paths, "REPO_ROOT", root):
            self.assertEqual(scan._gcp_vpn_image(True), "ubuntu-os-cloud/ubuntu-2404-lts-amd64")

    def test_scan_all_runs_fips_only_on_fips_environments(self):
        env = paths.Env("vmware", "allscan")
        env.create_dirs()
        rep = env.dir / "fips-report.json"
        rep.write_text(json.dumps({"verdict": "FAIL"}))
        with mock.patch.object(scan, "_hosts", return_value=[]), mock.patch.object(scan, "fips", return_value=rep) as f, silenced() as (out, _):
            self.assertEqual(scan.run_all(clouds.get("vmware"), env, {"vars": {}}, {}, None, ["bastion"]), [])
            f.assert_not_called()
            self.assertEqual(scan.run_all(clouds.get("vmware"), env, {"vars": {}}, {"fips_mode": True}, None, ["bastion"]), [rep])
            f.assert_called_once()
        self.assertIn("FAIL", ui._strip(out.getvalue()))

    def _release(self, name="kubescape"):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"#!/bin/sh\necho ok\n"
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def test_release_install_is_checksum_verified(self):
        blob = self._release()
        asset = "kubescape_4.0.14_linux_amd64.tar.gz"
        d = Path(tempfile.mkdtemp())
        for sums, ok in ((f"{hashlib.sha256(blob).hexdigest()}  {asset}\n", True), (f"{'1' * 64}  {asset}\n", False)):
            fetch = lambda url, t=60, s=sums: blob if url.endswith(asset) else s.encode()  # noqa: E731
            with mock.patch.object(scan.paths, "BIN_DIR", d), mock.patch.object(scan, "_fetch", side_effect=fetch), silenced():
                if ok:
                    self.assertEqual(scan._install_release("kubescape", "kubescape/kubescape", asset, "checksums.sha256", "v4.0.14"), d / "kubescape")
                    self.assertTrue(os.access(d / "kubescape", os.X_OK))
                    (d / "kubescape").unlink()
                else:
                    with self.assertRaises(SystemExit):
                        scan._install_release("kubescape", "kubescape/kubescape", asset, "checksums.sha256", "v4.0.14")
                    self.assertFalse((d / "kubescape").exists())

    def test_tool_install_failure_is_a_clear_abort(self):
        def offline():
            raise urllib.error.URLError("no route to host")
        with mock.patch.object(scan.deps, "find", return_value=None), mock.patch.object(scan.shutil, "which", return_value=None), silenced(), \
                self.assertRaises(SystemExit) as cm:
            scan._tool("kubescape", "kubescape", offline)
        self.assertIn("Could not install kubescape", cm.exception.msg)
        self.assertIn("no route to host", cm.exception.msg)


if __name__ == "__main__":
    unittest.main()
