"""Wave-3 resilience regressions: a missing kubectl is an install offer / exit 2 (never a TypeError), kube-bench's
`policies` checks get read-only API access (and PSA-exempt namespace), kubeadm picks its benchmark by the server
version, robust kube-bench JSON parsing, no velero CLI download from agent sessions (status/backups read with
kubectl), honest RTO for failed drills, drill volume wording and --volume pre-check, --target / --host validation,
FIPS endpoints and Azure service principals for prowler, the sshd/AKS/EKS FIPS checks, and the output glitches of
the scan/dr/chaos commands. Stdlib only; every cluster/tool call is faked."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import re
import signal
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import chaos, clouds, dr, paths, scan, services, ui  # noqa: E402
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


def fresh_env(target: str = "aws") -> paths.Env:
    _n[0] += 1
    env = paths.Env(target, f"w3r{_RUN}x{_n[0]}")
    env.create_dirs()
    return env


def make_ctx(target: str = "vmware", env: paths.Env | None = None, distro: str | None = None) -> pl.Cluster:
    env = env or fresh_env(target)
    cfg = {"env": env.name, "name": "t", "region": "r", "network_cidr": "10.0.0.0/16", "vars": {}}
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


def text_of(out, err=None) -> str:
    return ui._strip(out.getvalue() + (err.getvalue() if err is not None else ""))


# ---------------------------------------------------------------- a2-resilience#0: kubectl missing

class MissingKubectlTests(unittest.TestCase):
    def test_dr_chaos_and_scan_stop_with_the_install_command(self):
        ctx = make_ctx()
        with mock.patch.object(dr.deps, "find", return_value=None), mock.patch.object(services.deps, "find", return_value=None), \
                mock.patch.object(ui, "interactive", return_value=False), mock.patch.object(services, "_install_approved", return_value=False), \
                mock.patch.object(services.deps, "install") as inst, silenced():
            for fn in (lambda: dr.installed(ctx), lambda: chaos.status(ctx), lambda: chaos.stop(ctx), lambda: scan.images(ctx)):
                with self.assertRaises(SystemExit) as cm:
                    fn()
                self.assertEqual(cm.exception.code, 2)
                self.assertIn("cloudseed install kubectl", cm.exception.msg)
                self.assertNotIn("TypeError", cm.exception.msg)
            inst.assert_not_called()
        # a scan has no --auto-approve: its hint must not offer one
        with mock.patch.object(services.deps, "find", return_value=None), mock.patch.object(ui, "interactive", return_value=False), \
                mock.patch.object(services, "_install_approved", return_value=False), silenced(), self.assertRaises(SystemExit) as cm:
            scan._ensure_kubectl()
        self.assertNotIn("--auto-approve", cm.exception.msg)

    def test_approved_run_installs_kubectl_once(self):
        found = {"kubectl": None}

        def install(tool):
            found[tool] = "/fake/kubectl"
        with mock.patch.object(dr.deps, "find", side_effect=lambda t: found.get(t)), mock.patch.object(services.deps, "find", side_effect=lambda t: found.get(t)), \
                mock.patch.object(ui, "interactive", return_value=False), mock.patch.object(services, "_install_approved", return_value=True), \
                mock.patch.object(services.deps, "install", side_effect=install) as inst, silenced():
            self.assertEqual(dr.kubectl_path(), "/fake/kubectl")
        inst.assert_called_once_with("kubectl")


# ---------------------------------------------------------------- a2-resilience#4 / #5 / #12: kube-bench

class KubeBenchTests(unittest.TestCase):
    def test_policies_job_gets_read_only_api_access_and_others_do_not(self):
        with_api = scan._kube_bench_manifest("rke2", "master", "", ["kube-bench"], api=True)
        without = scan._kube_bench_manifest("rke2", "node", "", ["kube-bench"], api=False)
        self.assertIn("automountServiceAccountToken: true", with_api.split("kind: Job", 1)[1].split("containers:", 1)[0])
        self.assertIn("automountServiceAccountToken: false", without.split("kind: Job", 1)[1].split("containers:", 1)[0])
        for m in (with_api, without):
            self.assertIn("serviceAccountName: kube-bench", m)
            self.assertIn("kind: ServiceAccount", m)
        self.assertIn("kind: ClusterRoleBinding", with_api)
        self.assertNotIn("ClusterRole", without)
        rules = with_api.split("kind: ClusterRole\n", 1)[1].split("---", 1)[0]
        self.assertNotIn("secrets", rules)
        self.assertNotIn("impersonate", rules)
        for verb in re.findall(r"verbs: \[([^\]]*)\]", rules):
            self.assertEqual(verb, "get, list")
        # (GKE 5.6.7 lists ingresses and ManagedCertificates; without them it FAILs on its own "..._FORBIDDEN" marker)
        for res in ("clusterrolebindings", "serviceaccounts", "pods", "networkpolicies", "namespaces", "certificatesigningrequests",
                    "ingresses", "managedcertificates"):
            self.assertIn(res, rules)
        self.assertTrue(scan._runs_policies(None))
        self.assertTrue(scan._runs_policies("master,etcd,controlplane,policies"))
        self.assertFalse(scan._runs_policies("node"))

    def test_scan_namespace_is_exempt_from_restricted_pod_security(self):
        m = scan._kube_bench_manifest("rke2", "master", "", ["kube-bench"])
        ns = m.split("---", 1)[0]
        for mode in ("enforce", "audit", "warn"):
            self.assertIn(f"pod-security.kubernetes.io/{mode}: privileged", ns)
        # the template keeps its public placeholders
        self.assertIn("hostPID: true", scan.KUBE_BENCH_JOB % {"ns": "n", "role": "node", "placement": "", "command": '["kube-bench"]'})

    def _cis(self, distro, results, versions=("cis-1.12",), server="v1.35.1"):
        ctx = make_ctx("vmware", distro=distro)
        calls, applied = [], []

        def run(ctx_, role, benchmark, targets, timeout=300, version=""):
            calls.append((role, benchmark, targets, version))
            return {"Controls": [{"version": versions[0], "node_type": role, "tests": [{"section": "5.1", "results": results}]}]}

        def kubectl(ctx_, *args, input=None, timeout=300):
            applied.append(args)
            if args[:1] == ("version",):
                return cp(0, json.dumps({"serverVersion": {"gitVersion": server}}))
            return cp(0)
        with mock.patch.object(scan, "_ensure_kubectl"), mock.patch.object(scan, "_kube_bench_run", run), mock.patch.object(scan, "_kubectl", kubectl), \
                silenced() as (out, err):
            path = scan.cis(ctx)
        return json.loads(path.read_text()), calls, applied, text_of(out, err)

    def test_kubeadm_uses_the_server_version_and_rbac_is_removed(self):
        rep, calls, applied, _ = self._cis("kubeadm", [])
        self.assertEqual([c[3] for c in calls], ["1.35", "1.35"])
        self.assertEqual([c[1] for c in calls], ["", ""])
        self.assertEqual(rep["summary"]["benchmark"], "cis-1.12")
        self.assertTrue(any(a[:2] == ("delete", "clusterrolebinding,clusterrole") and scan.KUBE_BENCH_RBAC in a for a in applied))
        rep, calls, _, _ = self._cis("rke2", [], versions=("rke2-cis-1.9",))
        self.assertEqual([c[1] for c in calls], ["rke2-cis-1.9", "rke2-cis-1.9"])
        self.assertEqual([c[3] for c in calls], ["", ""])

    def test_checks_that_could_not_reach_the_api_are_not_evaluated(self):
        no_api = 'E0924 memcache.go:381] "Couldn\'t get current server API group list" err="dial tcp [::1]:8080: connect: connection refused"'
        results = [
            {"test_number": "5.1.1", "test_desc": "cluster-admin", "audit": "kubectl get clusterrolebindings", "status": "FAIL", "actual_value": "",
             "reason": f'failed to run: "kubectl get clusterrolebindings", output: "{no_api}"'},
            {"test_number": "4.1.2", "test_desc": "secrets", "audit": "kubectl get roles -A -o json", "status": "PASS", "actual_value": no_api},
            {"test_number": "5.1.6", "test_desc": "sa tokens", "audit": "kubectl get pods", "status": "FAIL",
             "actual_value": "Error from server (Forbidden): pods is forbidden: User \"system:serviceaccount:x\" cannot list"},
            {"test_number": "1.1.1", "test_desc": "file perms", "audit": "stat -c %a /etc/x", "status": "FAIL", "actual_value": "777", "remediation": "chmod"},
            {"test_number": "5.1.3", "test_desc": "wildcards", "audit": "kubectl get roles", "status": "FAIL", "actual_value": "role x uses *"},
        ]
        rep, _, _, text = self._cis("rke2", results, versions=("rke2-cis-1.9",))
        s = rep["summary"]
        self.assertEqual((s["fail"], s["pass"], s["not evaluated"]), (4, 0, 6))   # 2 real FAILs per run, 3 not evaluated per run
        self.assertTrue(all("not evaluated" in f["detail"] for f in rep["findings"] if f["title"].startswith(("5.1.1", "4.1.2", "5.1.6"))))
        self.assertIn("6 could not query the", text)
        # audits that swallow kubectl's error print their own marker (GKE 5.6.7), and klog's lowercase form
        for value in ("ERROR_KUBECTL_LIST:INGRESS_FORBIDDEN,MC_FORBIDDEN",
                      'E0924 memcache.go:265] couldn\'t get current server API group list: Get "https://10.0.0.1:443/api"'):
            self.assertTrue(scan._not_evaluated({"audit": "kubectl get svc -A -o json", "actual_value": value}), value)
        self.assertFalse(scan._not_evaluated({"audit": "kubectl get svc -A -o json", "actual_value": "ALL_INGRESSES_USE_MANAGED_CERTS_AND_NO_PUBLIC_LB_SERVICES"}))

    def test_result_json_is_found_whatever_surrounds_it(self):
        good = json.dumps({"Controls": [{"version": "rke2-cis-1.9", "tests": []}], "Totals": {}})
        for logs in (good + "\nfailed to load YAML or JSON from input \"{broken\"",       # trailing stderr without newline
                     "W0924 input {\"a\": 1} is odd\n" + good + "\n",                    # a brace before the result
                     "noise " + good):                                                  # glued to a prefix
            data, started = scan._kube_bench_json(logs)
            self.assertTrue(started, logs)
            self.assertEqual(data["Controls"][0]["version"], "rke2-cis-1.9", logs)
        self.assertEqual(scan._kube_bench_json('{"Controls": [ {"cut'), ({}, True))
        self.assertEqual(scan._kube_bench_json('{"a": 1}'), ({}, False))

    def _kb(self, rounds):
        state = {"n": -1, "applied": []}

        def fake(ctx, *args, input=None, timeout=300):
            a = list(args)
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
            return cp(0)
        return fake, state

    def test_retry_only_when_kube_bench_rejected_the_benchmark(self):
        done = {"succeeded": 1}
        pods = [{"status": {"containerStatuses": [{"state": {"terminated": {"exitCode": 0}}}]}}]
        good = json.dumps({"Controls": [{"tests": []}]})
        ctx = make_ctx()
        # a complete result followed by a stray line: parsed, no retry
        fake, state = self._kb([(done, pods, good + "\nfailed to load YAML or JSON from input")])
        with mock.patch.object(scan, "_kubectl", fake), mock.patch.object(scan, "time", FakeClock()), silenced():
            self.assertEqual(scan._kube_bench_run(ctx, "master", "rke2-cis-1.9", "master"), {"Controls": [{"tests": []}]})
        self.assertEqual(len(state["applied"]), 1)
        # finished without any result and without a benchmark complaint: abort, never fall back to the generic benchmark
        fake, state = self._kb([(done, pods, "kube-bench crashed")])
        with mock.patch.object(scan, "_kubectl", fake), mock.patch.object(scan, "time", FakeClock()), silenced(), self.assertRaises(SystemExit) as cm:
            scan._kube_bench_run(ctx, "master", "rke2-cis-1.9", "master")
        self.assertEqual(len(state["applied"]), 1)
        self.assertIn("produced no results", cm.exception.msg)
        # a truncated result: reported as such, no retry
        fake, state = self._kb([(done, pods, '{"Controls": [{"tests": [')])
        with mock.patch.object(scan, "_kubectl", fake), mock.patch.object(scan, "time", FakeClock()), silenced(), self.assertRaises(SystemExit) as cm:
            scan._kube_bench_run(ctx, "master", "rke2-cis-1.9", "master")
        self.assertIn("cut off or unreadable", cm.exception.msg)
        self.assertEqual(len(state["applied"]), 1)
        # --version is passed for a distro without its own benchmark
        fake, state = self._kb([(done, pods, good)])
        with mock.patch.object(scan, "_kubectl", fake), mock.patch.object(scan, "time", FakeClock()), silenced():
            scan._kube_bench_run(ctx, "node", "", "node", version="1.35")
        self.assertIn('"--version", "1.35"', state["applied"][0])
        self.assertNotIn("--benchmark", state["applied"][0])


# ---------------------------------------------------------------- a2-resilience#5: restricted drill pods

class DrillManifestTests(unittest.TestCase):
    def test_drill_pods_pass_the_restricted_profile(self):
        pvc = dr.DRILL_PVC % {"ns": dr.DRILL_NS}
        pod = pvc.split("kind: Pod", 1)[1]
        for needle in ("runAsNonRoot: true", "seccompProfile: {type: RuntimeDefault}", "allowPrivilegeEscalation: false",
                       "capabilities: {drop: [ALL]}", "fsGroup: 1000"):
            self.assertIn(needle, pod)
        dep = (dr.DRILL_MANIFEST % {"ns": "n", "token": "t", "created": "c"}).split("kind: Deployment", 1)[1]
        for needle in ("runAsNonRoot: true", "seccompProfile: {type: RuntimeDefault}", "allowPrivilegeEscalation: false", "capabilities: {drop: [ALL]}"):
            self.assertIn(needle, dep)


# ---------------------------------------------------------------- drill fakes (RTO, volume wording)

class FakeDrill:
    def __init__(self, sc="local-path", backup_phase="Completed", pvs=None, errors=0):
        self.sc, self.backup_phase, self.pvs, self.errors = sc, backup_phase, pvs or [], errors
        self.token, self.volume, self.kubectl_calls, self.velero_calls = None, None, [], []

    def kubectl(self, ctx, *args, input=None, timeout=180):
        self.kubectl_calls.append(args)
        a = list(args)
        if "apply" in a:
            self.token = re.search(r'token: "([^"]+)"', input).group(1)
            return cp(0)
        if "exec" in a:
            m = re.match(r"echo (\w+) > /data/token", a[-1])
            if m:
                self.volume = m.group(1)
            return cp(0, (self.volume or "") + "\n")
        if a[:2] == ["get", "ns"]:
            return cp(1)
        if a[:2] == ["get", "pv"]:
            return cp(0, json.dumps({"items": self.pvs}))
        if a[:2] == ["get", "sc"]:
            return cp(0, self.sc or "")
        if "podvolumebackups" in a or "podvolumerestores" in a:
            return cp(0, "Completed\n")
        if "cm" in a:
            return cp(0, self.token)
        if "secret" in a:
            return cp(0, base64.b64encode(self.token.encode()).decode())
        return cp(0)

    def velero(self, ctx, *args, check=True, stream=False, timeout=1800, quiet=False):
        self.velero_calls.append(args)
        if args[:2] == ("backup", "get"):
            return cp(0, json.dumps({"status": {"phase": self.backup_phase, "errors": self.errors}}))
        if len(args) >= 2 and args[1] == "get":
            return cp(0, json.dumps({"status": {"phase": "Completed"}}))
        return cp(0)


def drill(fake, target="vmware", keep=False, with_volume=None):
    ctx = make_ctx(target)
    with mock.patch.object(dr, "require"), mock.patch.object(dr, "_kubectl", fake.kubectl), mock.patch.object(dr, "_velero", fake.velero), \
            mock.patch.object(dr, "server_version", return_value="v1.18.2"), mock.patch.object(dr, "time", FakeClock()), silenced() as (out, err):
        try:
            rc = dr.test(ctx, keep=keep, with_volume=with_volume)
        except SystemExit as e:
            return e, None, text_of(out, err), ctx
    return rc, json.loads(dr.last_report(ctx.env).read_text()), text_of(out, err), ctx


class RtoTests(unittest.TestCase):
    def test_failed_drill_has_no_rto_anywhere(self):
        rc, rep, text, ctx = drill(FakeDrill(backup_phase="PartiallyFailed", errors=1))
        self.assertEqual((rc, rep["verdict"]), (1, "FAIL"))
        self.assertIsNone(rep["rto_s"])
        self.assertFalse(rep["volume_verified"])
        self.assertNotIn("RTO 0", text)
        self.assertIn("RTO not measured", text)
        self.assertIn("volume included, not verified", text)
        row = ui._strip(dr._drill_row(ctx.env))
        self.assertIn("RTO not measured", row)
        self.assertNotIn("with a volume", row)
        md = dr.last_report(ctx.env).with_suffix(".md").read_text()
        self.assertIn("RTO not measured", md)
        self.assertNotIn("RTO None", md)

    def test_passing_drill_reports_its_rto_and_old_failed_reports_do_not(self):
        rc, rep, text, ctx = drill(FakeDrill())
        self.assertEqual((rc, rep["verdict"]), (0, "PASS"), rep)
        self.assertIsInstance(rep["rto_s"], float)
        self.assertTrue(rep["volume_verified"])
        self.assertIn(f"measured RTO (restore + verify) {rep['rto_s']}s", text)
        self.assertIn("with a volume", ui._strip(dr._drill_row(ctx.env)))
        self.assertIsNone(dr.rto_text({"verdict": "FAIL", "rto_s": 0}))            # written before the rule
        self.assertIsNone(dr.rto_text({"verdict": "INTERRUPTED", "rto_s": 3.5}))
        self.assertIsNone(dr.rto_text({"verdict": "PASS", "rto_s": True}))
        self.assertEqual(dr.rto_text({"verdict": "PASS", "rto_s": 34.5}), "34.5s")


class DrillVolumeWordingTests(unittest.TestCase):
    def test_no_volume_says_why_it_was_skipped(self):
        rc, rep, _, _ = drill(FakeDrill(sc="local-path"), with_volume=False)
        self.assertEqual(rc, 0, rep)
        self.assertIn("volume test skipped: --no-volume", rep["steps"][0]["detail"])
        self.assertNotIn("no default StorageClass", rep["steps"][0]["detail"])
        rc, rep, _, _ = drill(FakeDrill(sc=""))
        self.assertIn("no default StorageClass: volume test skipped", rep["steps"][0]["detail"])

    def test_volume_without_a_default_class_needs_a_pv_or_stops_before_anything(self):
        fake = FakeDrill(sc="")
        res, rep, _, _ = drill(fake, with_volume=True)
        self.assertIsInstance(res, SystemExit)
        self.assertEqual(res.code, 2)
        self.assertIn("default StorageClass", res.msg)
        self.assertFalse(any("apply" in c for c in fake.kubectl_calls))
        self.assertEqual(fake.velero_calls, [])
        pv = {"metadata": {"name": "nfs-1"}, "spec": {"capacity": {"storage": "5Gi"}, "accessModes": ["ReadWriteOnce", "ReadWriteMany"]},
              "status": {"phase": "Available"}}
        rc, rep, text, _ = drill(FakeDrill(sc="", pvs=[pv]), with_volume=True)
        self.assertEqual(rc, 0, rep)
        self.assertIn("pre-provisioned PV such as nfs-1", rep["steps"][0]["detail"])
        self.assertNotIn("None", text)
        # PVs that cannot be listed (no RBAC for them, API timeout) are not "no PV": the drill goes ahead with a warning
        fake = FakeDrill(sc="")
        listing_fails = fake.kubectl

        def kubectl(ctx_, *args, input=None, timeout=180):
            return cp(1, "", "Error from server (Forbidden): persistentvolumes is forbidden") if list(args[:2]) == ["get", "pv"] else listing_fails(ctx_, *args, input=input, timeout=timeout)
        fake.kubectl = kubectl
        rc, rep, text, _ = drill(fake, with_volume=True)
        self.assertEqual(rc, 0, rep)
        self.assertIn("could not be listed", text)
        self.assertIn("pre-provisioned PV)", rep["steps"][0]["detail"])
        self.assertNotIn("None", text)

    def test_volume_the_non_root_writer_cannot_write_is_explained(self):
        fake = FakeDrill()
        base = fake.kubectl

        def kubectl(ctx_, *args, input=None, timeout=180):
            if "exec" in args and "echo" in args[-1]:
                return cp(1, "", "sh: can't create /data/token: Permission denied\ncommand terminated with exit code 1")
            return base(ctx_, *args, input=input, timeout=timeout)
        fake.kubectl = kubectl
        rc, rep, _, _ = drill(fake)
        self.assertEqual((rc, rep["verdict"]), (1, "FAIL"))
        self.assertIn("uid/gid 1000", rep["steps"][0]["detail"])
        self.assertIn("Permission denied", rep["steps"][0]["detail"])

    def test_quantities(self):
        self.assertEqual(dr._bytes("1Gi"), 2 ** 30)
        self.assertEqual(dr._bytes("500Mi"), 500 * 2 ** 20)
        self.assertEqual(dr._bytes("2G"), 2e9)
        self.assertEqual(dr._bytes("1Ki"), 1024)
        self.assertEqual(dr._bytes("bogus"), 0)


# ---------------------------------------------------------------- a2-resilience#9: no velero download from agent sessions

class VeleroCliTests(unittest.TestCase):
    def _ensure(self, agent, approved, interactive=False, existing=None, on_path=None):
        d = Path(tempfile.mkdtemp())
        if existing:
            (d / "velero").write_text(existing)
            (d / "velero").chmod(0o755)
        other = Path(tempfile.mkdtemp())   # stands for PATH (a Homebrew velero), so a velero on this machine plays no part
        if on_path:
            (other / "velero").write_text(on_path)
            (other / "velero").chmod(0o755)
        ctx = make_ctx()
        env = {"CLOUDSEED_AGENT": agent} if agent else {}
        with mock.patch.dict(os.environ, env), mock.patch.object(paths, "BIN_DIR", d), mock.patch.object(dr, "server_version", return_value="v1.18.2"), \
                mock.patch.object(dr.deps, "path_env", return_value={"PATH": os.pathsep.join([str(d), str(other)])}), \
                mock.patch.object(dr, "_download_cli") as dl, mock.patch.object(ui, "interactive", return_value=interactive), \
                mock.patch.object(services, "_install_approved", return_value=approved), silenced() as (out, err):
            if not agent:
                os.environ.pop("CLOUDSEED_AGENT", None)
                os.environ.pop("CLOUDSEED_REDACT", None)
            try:
                res = dr.ensure_cli(ctx)
            except SystemExit as e:
                res = e
        return res, dl, text_of(out, err)

    def test_read_only_mcp_call_never_downloads(self):
        res, dl, _ = self._ensure("mcp", approved=False)
        self.assertIsInstance(res, SystemExit)
        self.assertEqual(res.code, 2)
        self.assertIn("own terminal", res.msg)
        dl.assert_not_called()

    def test_agent_session_never_downloads_even_when_approved(self):
        res, dl, _ = self._ensure("claude", approved=True)
        self.assertIsInstance(res, SystemExit)
        self.assertIn("agent session", res.msg)
        dl.assert_not_called()

    def test_confirmed_mcp_action_and_own_terminal_download(self):
        res, dl, _ = self._ensure("mcp", approved=True)
        dl.assert_called_once()
        res, dl, _ = self._ensure(None, approved=False, interactive=True)
        dl.assert_called_once()

    def test_mismatched_cli_is_used_instead_of_a_refused_download(self):
        res, dl, text = self._ensure("mcp", approved=False, existing="#!/bin/sh\necho 'Version: v1.17.0'\n")
        self.assertTrue(str(res).endswith("velero"))
        self.assertIn("using it anyway", text)
        dl.assert_not_called()

    def test_refused_download_uses_a_matching_velero_on_path(self):
        res, dl, _ = self._ensure("mcp", approved=False, on_path="#!/bin/sh\necho 'Version: v1.18.0'\n")
        self.assertIn("v1.18.0", Path(str(res)).read_text())   # the PATH one (none in ~/.cloudseed/bin here)
        dl.assert_not_called()
        res, dl, _ = self._ensure("mcp", approved=False, on_path="#!/bin/sh\necho 'Version: v1.16.1'\n")   # another minor: not used
        self.assertIsInstance(res, SystemExit)
        dl.assert_not_called()

    def test_backups_lists_newest_first_without_the_cli(self):
        ctx = make_ctx("aws")
        items = [{"metadata": {"name": "a-old", "creationTimestamp": "2026-01-01T00:00:00Z"}, "status": {"phase": "Completed", "startTimestamp": "2026-01-01T00:00:00Z"}},
                 {"metadata": {"name": "pre-kubectl-1", "labels": {"cloudseed.io/undo-point": "true"}}, "status": {"phase": "Completed", "startTimestamp": "2026-03-01T00:00:00Z"}},
                 {"metadata": {"name": "z-new"}, "spec": {"includedNamespaces": ["shop"]}, "status": {"phase": "PartiallyFailed", "errors": 1, "startTimestamp": "2026-02-01T10:20:30Z"}}]

        def kubectl(ctx_, *args, input=None, timeout=180):
            if "backups.velero.io" in args:
                return cp(0, json.dumps({"items": items}))
            if "backupstoragelocations.velero.io" in args:
                return cp(0, json.dumps({"items": [{"metadata": {"name": "default"}, "spec": {"provider": "aws", "config": {"region": "r"}}, "status": {"phase": "Available"}}]}))
            if "schedules.velero.io" in args:
                return cp(0, json.dumps({"items": []}))
            return cp(0, "1/1")
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_kubectl", kubectl), \
                mock.patch.object(dr, "ensure_cli", side_effect=AssertionError("no CLI")), mock.patch.object(dr, "_velero", side_effect=AssertionError("no CLI")), \
                mock.patch.object(dr, "server_version", return_value="v1.18.2"), silenced() as (out, _):
            dr.backups(ctx)
            dr.status(ctx)
        text = text_of(out)
        table = text.split("NAME", 1)[1].split("details:", 1)[0]
        self.assertLess(table.index("pre-kubectl-1"), table.index("z-new"))
        self.assertLess(table.index("z-new"), table.index("a-old"))
        self.assertIn("(undo point)", table)
        self.assertIn("2026-02-01 10:20 UTC", table)
        panel = text.split("Disaster recovery", 1)[1]
        backups_row = next(ln for ln in panel.splitlines() if re.match(r"^\s*│ backups\s", ln))
        self.assertIn("z-new", backups_row)
        self.assertNotIn("pre-kubectl", backups_row)
        self.assertLess(backups_row.index("z-new"), backups_row.index("a-old"))
        self.assertIn("undo points", panel)


# ---------------------------------------------------------------- e2e2#4: backup namespaces and PartiallyFailed reasons

DESCRIBE = """Name:         [1me2e-bk1[22m
Phase:  [31mPartiallyFailed[0m (run `velero backup logs e2e-bk1` for more information)

Errors:
  Velero:     fail to get the namespace does-not-exist specified in backup.Spec.IncludedNamespaces
              second velero message
  Cluster:    <none>
  Namespaces:
    shop:     error backing up item: pods "x" not found

Namespaces:
  Included:  default, does-not-exist
"""


class BackupDiagnosticsTests(unittest.TestCase):
    def test_describe_errors_are_parsed(self):
        self.assertEqual(dr.parse_result_errors(DESCRIBE), [
            "fail to get the namespace does-not-exist specified in backup.Spec.IncludedNamespaces", "second velero message",
            'shop: error backing up item: pods "x" not found'])
        self.assertEqual(dr.parse_result_errors("Errors:  <error getting errors: lookup minio.minio.svc: no such host>"), [])
        self.assertEqual(dr.parse_result_errors("Phase: Completed\n"), [])

    def test_unknown_namespace_stops_the_backup_before_velero(self):
        ctx = make_ctx()
        velero = mock.Mock()
        with mock.patch.object(dr, "_kubectl", return_value=cp(0, "default kube-system shop")), mock.patch.object(dr, "_velero", velero), \
                mock.patch.object(dr, "require") as req, silenced(), self.assertRaises(SystemExit) as cm:
            dr.backup(ctx, "b1", "default, shp")
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("shp (did you mean shop?)", cm.exception.msg)
        req.assert_not_called()
        velero.assert_not_called()

    def test_partially_failed_backup_names_its_errors_on_vmware(self):
        ctx = make_ctx("vmware")
        calls = []

        def velero(ctx_, *args, check=True, stream=False, timeout=1800, quiet=False):
            calls.append(args)
            if args[0] == "backup-location":
                return cp(0, json.dumps({"spec": {"config": {"s3Url": "http://minio.minio.svc:9000"}}}))
            if args[:2] == ("backup", "get"):
                return cp(0, json.dumps({"status": {"phase": "PartiallyFailed", "errors": 1}}))
            return cp(0)

        def kubectl(ctx_, *args, input=None, timeout=180):
            if "exec" in args:   # describe runs inside the Velero pod: the MinIO URL only resolves in the cluster
                self.assertIn("/velero", args)
                return cp(0, DESCRIBE)
            return cp(0, "default does-not-exist-not kube-system")
        with mock.patch.object(dr, "require"), mock.patch.object(dr, "_velero", velero), mock.patch.object(dr, "_kubectl", kubectl), \
                silenced(), self.assertRaises(SystemExit) as cm:
            dr.backup(ctx, "e2e-bk1", "default")
        self.assertIn("First error(s): fail to get the namespace does-not-exist", cm.exception.msg)
        # (wave 5) the details hint is `cs dr describe`, which runs velero in the pod on such a cluster
        self.assertIn("cs dr describe backup e2e-bk1 --details vmware --env", cm.exception.msg)


# ---------------------------------------------------------------- need-core: Ctrl-C while velero streams

class VeleroStreamInterruptTests(unittest.TestCase):
    def test_interrupt_drains_the_output_and_waits_for_velero(self):
        class Out:
            def __init__(self):
                self.items = ["one\n", KeyboardInterrupt, "two\n", "three\n"]
                self.closed = False

            def __iter__(self):
                return self

            def __next__(self):
                if not self.items:
                    raise StopIteration
                x = self.items.pop(0)
                if x is KeyboardInterrupt:
                    raise KeyboardInterrupt
                return x

            def close(self):
                self.closed = True

        child = mock.Mock()
        child.stdout = Out()
        child.returncode = 130
        ctx = make_ctx()
        with mock.patch.object(dr, "ensure_cli", return_value="/fake/velero"), mock.patch.object(dr.subprocess, "Popen", return_value=child), \
                mock.patch.object(dr, "audit"), silenced() as (out, _), self.assertRaises(KeyboardInterrupt):
            dr._velero(ctx, "backup", "create", "b", "--wait", stream=True)
        child.send_signal.assert_called_once_with(signal.SIGINT)
        child.wait.assert_called()
        self.assertTrue(child.stdout.closed)
        self.assertIn("three", out.getvalue())   # read to the end, so velero never dies on a broken pipe


# ---------------------------------------------------------------- a2-resilience#13: --target

class ChaosTargetTests(unittest.TestCase):
    def test_target_forms(self):
        self.assertEqual(chaos.parse_target("api"), ("default", "api", ""))
        self.assertEqual(chaos.parse_target("shop/api"), ("shop", "api", ""))
        self.assertEqual(chaos.parse_target("shop/api.v2:8080"), ("shop", "api.v2", "8080"))
        self.assertEqual(chaos.parse_target("shop/api:grpc-web"), ("shop", "api", "grpc-web"))
        self.assertEqual(chaos.parse_target("shop/api:08080"), ("shop", "api", "8080"))
        for bad, why in (("shop/", "give the deployment"), ("/api", "namespace before '/' is empty"), ("shop/api:99999", "1..65535"),
                         ("shop/api:0", "1..65535"), ("shop/api:", "nothing after ':'"), ("a.b/api", "not a namespace"),
                         ("Shop/api", "not a namespace"), ("shop/API", "not a Deployment"), ("shop/api:http_x", "not a port")):
            with self.assertRaises(SystemExit, msg=bad) as cm:
                chaos.parse_target(bad)
            self.assertIn(why, cm.exception.msg, bad)

    def test_header_tells_one_shot_windows(self):
        self.assertEqual(chaos.windows_text(["pod-kill", "pod-failure", "container-kill"], 45),
                         "3 experiment(s), 45s each (one-shot 15s: pod-kill, container-kill)")
        self.assertEqual(chaos.windows_text(["network-delay"], 60), "1 experiment(s), 60s each")
        self.assertEqual(chaos.windows_text(["pod-kill"], 60), "1 one-shot experiment(s), 15s each")
        # the header form stays short enough for the header line (it was cut off mid-name on a 100-column terminal)
        self.assertEqual(chaos.windows_text(["pod-kill", "network-delay"], 45, detail=False), "2 experiment(s), 45s each (one-shot: 15s)")
        self.assertEqual(chaos.windows_text(["pod-kill", "network-delay"], 15), "2 experiment(s), 15s each")

    def test_implicit_chaos_mesh_install_skips_the_platform_summary(self):
        ctx = make_ctx()
        seen = {}

        def install(names, ctx_, wait=True, version=None, extra_sets=None, upgrade=False, force=False, summary=True):
            seen.update(names=names, summary=summary)
        with mock.patch.object(chaos, "chaos_mesh_ready", return_value=False), mock.patch.object(pl, "install", install), \
                mock.patch.object(chaos, "_kubectl", return_value=cp(0)), silenced():
            chaos.ensure_chaos_mesh(ctx)
        self.assertEqual(seen, {"names": ["chaos-mesh"], "summary": False})
        with mock.patch.object(chaos, "chaos_mesh_ready", return_value=False), mock.patch.object(pl, "install") as inst, \
                mock.patch.object(chaos, "_kubectl", return_value=cp(0)), silenced():
            chaos.ensure_chaos_mesh(ctx)   # a platform.install without the parameter still works
        inst.assert_called_once()


# ---------------------------------------------------------------- a2-resilience#8: scans need kubectl, not helm

class ScanToolTests(unittest.TestCase):
    def test_cluster_scans_never_require_helm(self):
        ctx = make_ctx("aws", distro="eks")
        found = {"kubectl": "/fake/kubectl"}
        items = [{"metadata": {"namespace": "ns", "name": "w"}, "report": {"summary": {"criticalCount": 0}, "vulnerabilities": []}}]

        def run(cmd, **kw):
            Path(cmd[cmd.index("--output") + 1]).write_text(json.dumps({"summaryDetails": {"controls": {}}}))
            return cp(0)
        with mock.patch.object(scan.deps, "find", side_effect=lambda t: found.get(t)), mock.patch.object(pl, "ensure_tools", side_effect=AssertionError("helm")), \
                mock.patch.object(services, "ensure_tool", side_effect=AssertionError("nothing to install")), \
                mock.patch.object(scan, "_kubectl", return_value=cp(0, json.dumps({"items": items}))), mock.patch.object(scan, "_tool", return_value="/fake/ks"), \
                mock.patch.object(scan.subprocess, "run", side_effect=run), mock.patch.object(scan, "_kube_bench_run", return_value={"Controls": []}), silenced():
            self.assertTrue(scan.images(ctx).exists())
            self.assertTrue(scan.kube(ctx).exists())
            self.assertTrue(scan.cis(ctx).exists())


class ChaosToolTests(unittest.TestCase):
    def test_chaos_run_needs_helm_only_to_install_chaos_mesh(self):
        ctx = make_ctx()
        with mock.patch.object(pl, "ensure_tools", side_effect=AssertionError("helm is not needed")), \
                mock.patch.object(chaos, "chaos_mesh_ready", return_value=True), mock.patch.object(chaos, "dns_chaos_available", return_value=True), \
                mock.patch.object(chaos, "resolve_target", side_effect=ui.Abort("stop after the tool checks")), silenced(), self.assertRaises(SystemExit) as cm:
            chaos.run(ctx, ["pod-kill"], None, None, 45, 3, False)
        self.assertEqual(cm.exception.msg, "stop after the tool checks")


# ---------------------------------------------------------------- a2-resilience#14: --host

class HostSelectionTests(unittest.TestCase):
    def test_parse_hosts(self):
        self.assertEqual(scan.parse_hosts(None), ["bastion", "vpn", "k8s"])
        self.assertEqual(scan.parse_hosts(["bastion, vpn", "K8S", "bastion,"]), ["bastion", "vpn", "k8s"])
        self.assertEqual(scan.parse_hosts(" vpn"), ["vpn"])
        with self.assertRaises(SystemExit) as cm:
            scan.parse_hosts(["bastoin"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("did you mean bastion?", cm.exception.msg)
        with self.assertRaises(SystemExit):
            scan.parse_hosts([" , "])

    def test_missing_kind_is_named_and_scan_all_reports_it(self):
        env = fresh_env("vmware")
        cloud = clouds.get("vmware")
        outputs = {"bastion_public_ip": "10.0.0.5"}
        cfg = {"name": "t", "env": env.name, "vars": {}}
        with silenced(), self.assertRaises(SystemExit) as cm:
            scan.host(cloud, env, cfg, outputs, ["vpn"])
        self.assertIn("--host vpn", cm.exception.msg)
        self.assertIn("it has: bastion", cm.exception.msg)
        self.assertNotIn("yet", cm.exception.msg)
        errors: list = []
        with mock.patch.object(scan, "cloud_scan"), silenced() as (out, err):
            self.assertEqual(scan.run_all(cloud, env, cfg, outputs, None, ["vpn"], errors=errors, explicit_hosts=True), [])
        self.assertEqual(errors, ["host"])
        self.assertIn("ERROR", text_of(out, err))
        errors = []
        with silenced() as (out, err):
            scan.run_all(cloud, env, cfg, {}, None, ["bastion", "vpn", "k8s"], errors=errors)
        self.assertEqual(errors, [])
        self.assertIn("Host scans skipped", text_of(out, err))

    def test_scan_all_notes_managed_nodes_once_and_waits_for_a_down_host_once(self):
        env = fresh_env("aws")
        cloud = clouds.get("aws")
        cfg = {"name": "t", "env": env.name, "vars": {"fips_mode": True}, "ssh_public_key": ""}
        outputs = {"bastion_public_ip": "198.51.100.7", "kubernetes_cluster_name": "c", "fips_mode": True}
        waits = []

        class DownHost:
            def __init__(self, ip, user, key, name, env=None):
                self.name = name

            def wait(self, timeout=420, retry=None):   # retry: the closing advice (the scan passes its own)
                waits.append(self.name)
                raise ui.Abort(f"{self.name} did not accept SSH within {timeout}s. Check `cloudseed status aws --env x`, "
                               + (retry or "then re-run `cloudseed provision aws --env x`."))

            def ssh(self, cmd):
                return ["true"]
        with mock.patch.object(scan.prov, "Host", DownHost), mock.patch.object(scan, "cloud_scan", side_effect=ui.Abort("no creds")), \
                mock.patch.object(scan.subprocess, "run", return_value=cp(255, "", "Warning: key\nssh: connect to host 198.51.100.7 port 22: Operation timed out\n")), \
                silenced() as (out, err):
            scan.run_all(cloud, env, cfg, outputs, None, ["bastion", "vpn", "k8s"], errors=[])
        text = text_of(out, err)
        self.assertEqual(text.count("Managed Kubernetes nodes"), 1)
        self.assertEqual(waits, ["bastion"])                      # the STIG scan did not wait for it again
        self.assertIn("re-run the scan (cs scan host aws", text)
        self.assertNotIn("re-run `cloudseed provision`", text)
        fips_row = next(ln for ln in text.splitlines() if "bastion: reachable over SSH" in ln)
        self.assertIn("Warning: key · ssh: connect to host", fips_row)   # both lines, one panel row

    def test_unscanned_hosts_give_an_error_verdict_not_a_score(self):
        d = Path(tempfile.mkdtemp())
        env = mock.Mock(id="aws-w3", dir=d)
        env.private_key_path.return_value = d / "key"
        cloud = mock.Mock(key="aws")
        cloud.ssh_user.return_value = "ops"

        class Proc:
            def __init__(self, cmd, **kw):
                self.stdout = iter(["fatal: [bastion]: UNREACHABLE!\n"])

            def wait(self):
                return 4
        with mock.patch.object(scan, "_hosts", return_value=[("bastion", "1.2.3.4"), ("vpn", "5.6.7.8")]), mock.patch.object(scan.prov, "Host"), \
                mock.patch.object(scan, "_ssg_version", return_value="0.1.82"), mock.patch.object(scan.deps, "ensure_local_ansible", return_value=Path("/usr/bin/true")), \
                mock.patch.object(scan.subprocess, "Popen", Proc), mock.patch.object(scan, "audit"), silenced() as (out, _):
            path = scan.host(cloud, env, {"name": "a", "env": "w3"}, {}, ["bastion", "vpn"], "cis")
        text = text_of(out)
        self.assertIn("ERROR - no host could be scanned", text)
        self.assertNotIn("lowest score", text)
        self.assertNotIn("report.html", text)
        self.assertEqual(json.loads(Path(path).read_text())["verdict"], "FAIL")   # still fails the command


# ---------------------------------------------------------------- a2-resilience#17 + a2-azure#11: prowler environment

class ProwlerEnvTests(unittest.TestCase):
    def _run(self, cloud_key, cfg, environ):
        env = fresh_env(cloud_key)
        seen = {}

        def run(cmd, env=None, **kw):
            if "account" in cmd:
                return cp(0, '{"id": "sub"}')
            if "--list-compliance" in cmd:
                seen["list_env"] = env
                return cp(0, f"cis_4.0_{cloud_key}")
            seen["cmd"], seen["env"] = cmd, env
            outdir = Path(cmd[cmd.index("-o") + 1])
            (outdir / "prowler-x.ocsf.json").write_text("[]")
            return cp(0, "", 'botocore.exceptions.EndpointConnectionError: Could not connect to the endpoint URL: "https://account-fips.us-east-1.amazonaws.com/"')
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("AZURE_", "ARM_", "AWS_"))}
        clean.update(environ)
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(scan, "_prowler", return_value="/fake/prowler"), \
                mock.patch.object(scan.subprocess, "run", side_effect=run), silenced() as (out, err):
            try:
                res = scan.cloud_scan(clouds.get(cloud_key), env, cfg)
            except SystemExit as e:
                res = e
        return res, seen, text_of(out, err)

    def test_fips_aws_environment_scans_fips_endpoints_of_its_region(self):
        res, seen, text = self._run("aws", {"region": "us-east-2", "vars": {"fips_mode": True, "profile": "prod"}}, {})
        self.assertEqual(seen["env"]["AWS_USE_FIPS_ENDPOINT"], "true")
        self.assertEqual(seen["list_env"]["AWS_USE_FIPS_ENDPOINT"], "true")
        self.assertEqual(seen["env"]["AWS_PROFILE"], "prod")
        self.assertEqual(seen["cmd"][seen["cmd"].index("-f") + 1], "us-east-2")
        self.assertEqual(json.loads(res.read_text())["summary"]["endpoints"], "FIPS (regions: us-east-2)")
        self.assertIn("could not reach 1 service endpoint", text)
        res, seen, _ = self._run("aws", {"region": "us-east-2", "vars": {}}, {})
        self.assertNotIn("AWS_USE_FIPS_ENDPOINT", seen["env"])
        self.assertNotIn("-f", seen["cmd"])

    def test_azure_service_principal_from_arm_variables(self):
        arm = {"ARM_CLIENT_ID": "id", "ARM_CLIENT_SECRET": "s3cret", "ARM_TENANT_ID": "tn"}
        with mock.patch.object(scan.deps, "find", return_value=None):
            res, seen, _ = self._run("azure", {"vars": {"subscription_id": "sub"}}, arm)
        self.assertIn("--sp-env-auth", seen["cmd"])
        self.assertEqual((seen["env"]["AZURE_CLIENT_ID"], seen["env"]["AZURE_CLIENT_SECRET"], seen["env"]["AZURE_TENANT_ID"]), ("id", "s3cret", "tn"))
        self.assertNotIn("AZURE_CLIENT_ID", os.environ)   # only the child's environment
        # a managed identity's AZURE_CLIENT_ID alone is not a service principal
        with mock.patch.object(scan.deps, "find", return_value=None):
            res, seen, _ = self._run("azure", {"vars": {}}, {"AZURE_CLIENT_ID": "mi"})
        self.assertIsInstance(res, SystemExit)
        self.assertIn("az login", res.msg)
        self.assertIn("ARM_CLIENT_ID", res.msg)
        with mock.patch.object(scan.deps, "find", return_value="/fake/az"):
            res, seen, _ = self._run("azure", {"vars": {}}, {"AZURE_CLIENT_ID": "mi"})
        self.assertIn("--az-cli-auth", seen["cmd"])
        with mock.patch.object(scan.deps, "find", return_value=None):
            res, seen, _ = self._run("azure", {"vars": {}}, {"ARM_USE_MSI": "true"})
        self.assertIn("--managed-identity-auth", seen["cmd"])


# ---------------------------------------------------------------- a2-resilience#19 + a2-azure#10: FIPS verifier

TEMPLATE_SSHD = """kexalgorithms ecdh-sha2-nistp384,ecdh-sha2-nistp256,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
hostkeyalgorithms ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
pubkeyacceptedalgorithms ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
"""


class FipsVerifierTests(unittest.TestCase):
    def test_sshd_algorithms(self):
        self.assertEqual(scan.sshd_fips_problems(TEMPLATE_SSHD)[0], [])
        hybrid = TEMPLATE_SSHD.replace("kexalgorithms ecdh-sha2-nistp384", "kexalgorithms mlkem768x25519-sha256,mlkem768nistp256-sha256,ecdh-sha2-nistp384")
        self.assertEqual(scan.sshd_fips_problems(hybrid)[0], ["kexalgorithms: mlkem768x25519-sha256"])
        unpinned = TEMPLATE_SSHD.replace("hostkeyalgorithms ecdsa-sha2-nistp384", "hostkeyalgorithms ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp384")
        self.assertEqual(scan.sshd_fips_problems(unpinned)[0], ["hostkeyalgorithms: ssh-ed25519", "hostkeyalgorithms: ssh-rsa"])
        sha1 = TEMPLATE_SSHD.replace("kexalgorithms ", "kexalgorithms diffie-hellman-group14-sha1,")
        self.assertEqual(scan.sshd_fips_problems(sha1)[0], ["kexalgorithms: diffie-hellman-group14-sha1"])
        self.assertEqual(scan.sshd_fips_problems(""), ([], {}))

    def _fips(self, cloud_key, nodes_out, rc=0, outputs=None):
        env = fresh_env(cloud_key)
        ctx = make_ctx(cloud_key, env=env, distro={"aws": "eks", "azure": "aks"}[cloud_key])

        def kubectl(ctx_, *args, input=None, timeout=300):
            if "nodes" in args and any("osImage" in a for a in args):
                return cp(rc, nodes_out)
            return cp(1)
        cfg = {"vars": {"fips_mode": True}, "ssh_public_key": ""}
        with mock.patch.object(scan, "_kubectl", kubectl), mock.patch.object(scan, "_hosts", return_value=[]), \
                mock.patch.object(pl, "installed_releases", return_value={}), silenced():
            path = scan.fips(clouds.get(cloud_key), env, cfg, outputs or {"kubernetes_cluster_name": "c", "fips_mode": True}, ctx=ctx)
        return {c["check"]: c for c in json.loads(path.read_text())["checks"]}

    def test_aks_nodes_are_judged_by_their_fips_label(self):
        checks = self._fips("azure", "n1=Azure Linux 2.0|5.15|true\nn2=Azure Linux 2.0|5.15|\n")
        self.assertEqual(checks["node n1: Azure Linux 2.0"]["status"], "PASS")
        self.assertEqual(checks["node n2: Azure Linux 2.0"]["status"], "FAIL")
        self.assertIn("label absent", checks["node n2: Azure Linux 2.0"]["detail"])
        self.assertNotIn("AKS node pool is fips_enabled", checks)          # the node rows are the live check
        checks = self._fips("azure", "", rc=1)
        self.assertEqual(checks["AKS node pool is fips_enabled"]["status"], "INFO")   # never PASS from the config alone
        self.assertIn("not verified live", checks["AKS node pool is fips_enabled"]["detail"])

    def test_eks_nodes_need_a_fips_bottlerocket_variant(self):
        checks = self._fips("aws", "a=Bottlerocket OS 1.26.1 (aws-k8s-1.31-fips)|6.1|\nb=Bottlerocket OS 1.26.1 (aws-k8s-1.31)|6.1|\n")
        self.assertEqual(checks["node a: Bottlerocket OS 1.26.1 (aws-k8s-1.31-fips)"]["status"], "PASS")
        self.assertEqual(checks["node b: Bottlerocket OS 1.26.1 (aws-k8s-1.31)"]["status"], "FAIL")
        self.assertIn("environment SSH key is FIPS-approved (RSA-4096; ECDSA only on GCP/VMware)", checks)

    def test_missing_kubectl_keeps_the_other_checks(self):
        env = fresh_env("aws")
        ctx = make_ctx("aws", env=env, distro="eks")
        with mock.patch.object(scan, "_kubectl", side_effect=ui.Abort("kubectl is needed ... cloudseed install kubectl", code=2)), \
                mock.patch.object(scan, "_hosts", return_value=[]), silenced():
            path = scan.fips(clouds.get("aws"), env, {"vars": {"fips_mode": True}, "ssh_public_key": ""}, {"kubernetes_cluster_name": "c"}, ctx=ctx)
        checks = {c["check"]: c for c in json.loads(path.read_text())["checks"]}
        self.assertEqual(checks["cluster not checked"]["status"], "INFO")
        self.assertIn("fips_mode enabled for the environment", checks)


# ---------------------------------------------------------------- a2-resilience#20: output glitches

class OutputTests(unittest.TestCase):
    def test_tail_text(self):
        self.assertEqual(scan.tail_text("line one\n\n  last   line  \n"), "last line")
        self.assertEqual(scan.tail_text("a\nb\nc", lines=2), "b · c")
        long = "Error: " + "failing Kubernetes API server config word " * 20
        cut = scan.tail_text(long, 60)
        self.assertTrue(cut.startswith("Error: failing"))
        self.assertLessEqual(len(cut), 60)
        self.assertEqual(scan.tail_text(None), "")

    def test_kubescape_that_wrote_nothing_is_not_finished(self):
        ctx = make_ctx("aws")
        with mock.patch.object(scan, "_ensure_kubectl"), mock.patch.object(scan, "_tool", return_value="/fake/ks"), \
                mock.patch.object(scan.subprocess, "run", return_value=cp(1, "", "Error: failed connecting to Kubernetes cluster\n")), \
                silenced() as (out, err), self.assertRaises(SystemExit) as cm:
            scan.kube(ctx)
        self.assertNotIn("kubescape finished", text_of(out, err))
        self.assertIn("failed connecting to Kubernetes cluster", cm.exception.msg)

    def test_kubescape_timeout_hint_is_runnable(self):
        ctx = make_ctx("aws")
        with mock.patch.object(scan, "_ensure_kubectl"), mock.patch.object(scan, "_tool", return_value="/fake/ks"), \
                mock.patch.object(scan.subprocess, "run", side_effect=subprocess.TimeoutExpired("ks", 1800)), silenced(), self.assertRaises(SystemExit) as cm:
            scan.kube(ctx)
        self.assertNotIn("cs k8s status", cm.exception.msg)
        self.assertIn(f"cs scan kube aws --env {ctx.env.name}", cm.exception.msg)
        self.assertIn("cs k8s tunnel aws", cm.exception.msg)

    def test_trivy_failure_is_said_once(self):
        ctx = make_ctx("aws")
        with mock.patch.object(scan, "_ensure_kubectl"), mock.patch.object(scan, "_kubectl", return_value=cp(1, "", "no crd")), \
                mock.patch.object(scan, "_tool", return_value="/fake/trivy"), \
                mock.patch.object(scan.subprocess, "run", return_value=cp(1, "", "2026 FATAL cluster unreachable\n")), \
                silenced() as (out, err), self.assertRaises(SystemExit) as cm:
            scan.images(ctx)
        self.assertNotIn("FATAL", text_of(out, err))
        self.assertIn("FATAL cluster unreachable", cm.exception.msg)
        self.assertFalse(cm.exception.msg.endswith(("\n", " ")))

    def test_dr_status_location_error_is_not_cut_mid_word(self):
        ctx = make_ctx("aws")
        err = "E0924 error loading config file\n" + "Error: invalid configuration: no configuration has been provided, try setting KUBERNETES_MASTER " * 4

        def kubectl(ctx_, *args, input=None, timeout=180):
            if "backupstoragelocations.velero.io" in args:
                return cp(1, "", err)
            return cp(0, "")
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_kubectl", kubectl), \
                mock.patch.object(dr, "server_version", return_value="v1.18.2"), silenced() as (out, _):
            dr.status(ctx)
        row = next(ln for ln in text_of(out).splitlines() if "locations" in ln)
        self.assertIn("Error: invalid configuration", row)


# ---------------------------------------------------------------- helpers for the CLI (cli-cluster: chaos report, restore check)

class ReportFileTests(unittest.TestCase):
    def test_chaos_report_survives_damaged_and_partial_reports(self):
        env = fresh_env("vmware")
        d = env.dir / "chaos"
        d.mkdir(parents=True, exist_ok=True)
        good = {"run": "20260101-000000", "env": env.id, "target": "x/y", "results": [{"experiment": "pod-kill", "verdict": "PASS"}],
                "summary": {"PASS": 1, "FAIL": 0, "SKIP": 0, "ERROR": 0}}
        (d / "report-20260101-000000.json").write_text(json.dumps(good))
        (d / "report-20260102-000000.json").write_text("")                  # an interrupted save
        (d / "report-20260103-000000.json").write_text('{"results": "x"}')   # not a report
        with silenced() as (out, err):
            rep, path = chaos.load_last_report(env)
        self.assertEqual(path.name, "report-20260101-000000.json")
        self.assertEqual(text_of(out, err).count("Skipping unreadable chaos report"), 2)
        with silenced() as (out, _):
            chaos.print_report({"results": [{"verdict": "PASS", "availability": 1, "min_availability": 0.5}]})   # fields missing
        self.assertIn("PASS", text_of(out))
        self.assertIsNone(chaos.load_last_report(fresh_env("vmware")))
        with silenced():
            row = ui._strip(chaos._last_report_row(env))   # the newest files are damaged: the last good one, no crash
        self.assertIn("PASS · 1/1 passed · run 20260101-000000", row)

    def test_reports_are_written_atomically(self):
        ctx = make_ctx()
        report = {"run": "20260301-101010", "env": ctx.env.id, "target": "x/canary", "canary": True, "duration_s": 45, "distro": "rke2",
                  "cloud": "vmware", "results": [], "summary": {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}}
        with mock.patch.object(chaos.paths, "atomic_write", wraps=chaos.paths.atomic_write) as aw:
            path = chaos.save_report(ctx, report)
        self.assertEqual({Path(c.args[0]).suffix for c in aw.call_args_list}, {".json", ".md"})
        self.assertEqual(json.loads(path.read_text())["run"], "20260301-101010")
        self.assertEqual([p.name for p in path.parent.iterdir() if p.name.startswith(".")], [])


# ---------------------------------------------------------------- a2-resilience#22: dead code, release URL

class VeleroReleaseTests(unittest.TestCase):
    def test_release_url_and_dead_code(self):
        self.assertTrue(dr.RELEASES.startswith("https://github.com/velero-io/velero/"))
        # (wave 4) _phase is used again: `cs dr restore` asks whether a failed restore ever started (tests/test_wave4_resilience.py)
        self.assertTrue(callable(dr._phase))


if __name__ == "__main__":
    unittest.main()
