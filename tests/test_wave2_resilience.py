"""Wave-2 resilience regressions: collision-free report and output names (parallel runs), Markdown cells that cannot
break a table, no scanner installs from agent/MCP sessions, prowler venvs from another system, the FIPS SSH-key check by
setup's rules, Velero describe/logs hints that work with an in-cluster MinIO, the drill's Ctrl-C while its backup still
runs, the AKS node-agent identity check and chaos.run's input checks. Stdlib only; every cluster/tool call is faked."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
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


def fresh_env(target: str = "aws") -> paths.Env:
    _n[0] += 1
    env = paths.Env(target, f"w2r{_RUN}x{_n[0]}")
    env.create_dirs()
    return env


def make_ctx(target: str = "vmware", env: paths.Env | None = None) -> pl.Cluster:
    env = env or fresh_env(target)
    cfg = {"env": env.name, "name": "t", "region": "r", "network_cidr": "10.0.0.0/16", "vars": {}}
    outputs = {"kubernetes_distro": "rke2"} if target == "vmware" else {"kubernetes_cluster_name": "c"}
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


def _blob(*parts: bytes) -> str:
    return base64.b64encode(b"".join(len(p).to_bytes(4, "big") + p for p in parts)).decode()


def rsa_pub(bits: int) -> str:
    n = (1 << (bits - 1)) | 1
    return "ssh-rsa " + _blob(b"ssh-rsa", b"\x01\x00\x01", b"\x00" + n.to_bytes((bits + 7) // 8, "big")) + " t"


def ecdsa_pub() -> str:
    return "ecdsa-sha2-nistp384 " + _blob(b"ecdsa-sha2-nistp384", b"nistp384", b"\x04" + b"\x01" * 96) + " t"


def ed25519_pub() -> str:
    return "ssh-ed25519 " + _blob(b"ssh-ed25519", b"\x02" * 32) + " t"


# ---------------------------------------------------------------- unique names (ops#8)

class UniqueRunNameTests(unittest.TestCase):
    def test_claim_moves_to_the_next_free_second(self):
        d = Path(tempfile.mkdtemp())
        a, ra = scan.claim_run_path(d, "cis-", ".json", "20260101-235959")
        b, rb = scan.claim_run_path(d, "cis-", ".json", "20260101-235959")
        c, rc_ = scan.claim_run_path(d, "cis-", ".json", "20260101-235959")
        self.assertEqual((ra, rb, rc_), ("20260101-235959", "20260102-000000", "20260102-000001"))
        self.assertEqual(len({a, b, c}), 3)
        self.assertTrue(all(p.is_file() for p in (a, b, c)))
        d1, r1 = scan.claim_run_path(d, "openscap-", "", "20260101-000000", directory=True)
        d2, r2 = scan.claim_run_path(d, "openscap-", "", "20260101-000000", directory=True)
        self.assertTrue(d1.is_dir() and d2.is_dir() and d1 != d2)
        self.assertEqual(r2, "20260101-000001")
        # an id that is not a run stamp is used as given (and rewritten, as before)
        p, r = scan.claim_run_path(d, "report-", ".json", "r1")
        self.assertEqual((p.name, r), ("report-r1.json", "r1"))

    def test_parallel_scan_reports_in_the_same_second_both_survive(self):
        env = fresh_env("aws")
        stamp = "20260301-101010"
        p1 = scan.save_report(env, "fips", {"run": stamp, "summary": {"pass": 1}, "findings": [], "verdict": "PASS"})
        p2 = scan.save_report(env, "fips", {"run": stamp, "summary": {"pass": 0}, "findings": [], "verdict": "FAIL"})
        self.assertNotEqual(p1, p2)
        self.assertEqual(json.loads(p1.read_text())["verdict"], "PASS")
        self.assertEqual(json.loads(p2.read_text())["run"], "20260301-101011")
        self.assertEqual(scan.reports(env)[-2:], [p1, p2])
        self.assertIn("20260301-101011", p2.with_suffix(".md").read_text())

    def test_chaos_and_dr_reports_never_overwrite_each_other(self):
        ctx = make_ctx()
        base = {"env": ctx.env.id, "target": "x/canary", "canary": True, "duration_s": 30, "distro": "rke2", "cloud": "vmware",
                "results": [], "summary": {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}, "verdict": "INCONCLUSIVE"}
        a = chaos.save_report(ctx, dict(base, run="20260301-101010"))
        b = chaos.save_report(ctx, dict(base, run="20260301-101010"))
        self.assertNotEqual(a, b)
        self.assertEqual(chaos.last_report(ctx.env), b)
        self.assertEqual(json.loads(b.read_text())["run"], "20260301-101011")
        drep = {"env": ctx.env.id, "cloud": "vmware", "distro": "rke2", "velero": "v1.18.2", "volume_tested": False, "steps": [],
                "verdict": "FAIL", "total_s": 0, "rto_s": 0}
        x = dr.save_report(ctx, dict(drep, run="20260301-101010"))
        y = dr.save_report(ctx, dict(drep, run="20260301-101010"))
        self.assertNotEqual(x, y)
        self.assertEqual(dr.last_report(ctx.env), y)

    def test_kube_raw_output_and_report_share_a_unique_run(self):
        ctx = make_ctx("aws")
        raw = ctx.env.dir / "scans" / "raw"
        raw.mkdir(parents=True, exist_ok=True)

        def run(cmd, **kw):
            Path(cmd[cmd.index("--output") + 1]).write_text(json.dumps({"summaryDetails": {"controls": {}, "complianceScore": 90}}))
            return cp(0)
        with mock.patch.object(scan, "_ensure_kubectl"), mock.patch.object(scan, "_tool", return_value="/fake/kubescape"), \
                mock.patch.object(scan.subprocess, "run", side_effect=run), mock.patch.object(scan, "run_stamp", return_value="20260301-101010"), silenced():
            (raw / "kubescape-20260301-101010.json").write_text("{}")   # a parallel scan got this second first
            path = scan.kube(ctx)
        rep = json.loads(path.read_text())
        self.assertEqual(rep["run"], "20260301-101011")
        self.assertEqual(rep["raw"], str(raw / "kubescape-20260301-101011.json"))
        self.assertEqual((raw / "kubescape-20260301-101010.json").read_text(), "{}")   # the other scan's output is untouched

    def test_failed_tools_leave_no_empty_reserved_file(self):
        ctx = make_ctx("aws")
        with mock.patch.object(scan, "_ensure_kubectl"), mock.patch.object(scan, "_tool", return_value="/fake/kubescape"), \
                mock.patch.object(scan.subprocess, "run", return_value=cp(2, "", "connection refused")), silenced(), \
                self.assertRaises(SystemExit) as cm:
            scan.kube(ctx)
        self.assertIn("kubescape failed", cm.exception.msg)
        self.assertEqual(list((ctx.env.dir / "scans" / "raw").glob("kubescape-*")), [])
        with mock.patch.object(scan, "_ensure_kubectl"), mock.patch.object(scan, "_kubectl", return_value=cp(1, "", "no crd")), \
                mock.patch.object(scan, "_tool", return_value="/fake/trivy"), \
                mock.patch.object(scan.subprocess, "run", return_value=cp(1, "", "trivy: cluster unreachable")), silenced(), \
                self.assertRaises(SystemExit) as cm:
            scan.images(ctx)
        self.assertIn("trivy failed", cm.exception.msg)
        self.assertEqual(list((ctx.env.dir / "scans" / "raw").glob("trivy-*")), [])

    def test_parallel_host_scans_get_their_own_result_directory(self):
        env = fresh_env("aws")
        (env.dir / "scans").mkdir(parents=True, exist_ok=True)
        (env.dir / "scans" / "openscap-20260301-101010").mkdir()

        class Child:
            stdout = iter(["PLAY [scan]\n"])

            def wait(self):
                return 0
        seen = {}

        def popen(cmd, **kw):
            seen["cmd"] = cmd
            return Child()
        with mock.patch.object(scan, "_hosts", return_value=[("bastion", "192.0.2.10")]), mock.patch.object(scan.prov, "Host"), \
                mock.patch.object(scan, "_ssg_version", return_value="0.1.82"), mock.patch.object(scan, "run_stamp", return_value="20260301-101010"), \
                mock.patch.object(scan.deps, "ensure_local_ansible", return_value=Path("/bin/true")), \
                mock.patch.object(scan.subprocess, "Popen", popen), silenced():
            path = scan.host(clouds.get("aws"), env, {"vars": {}}, {}, ["bastion"])
        rep = json.loads(path.read_text())
        self.assertEqual(rep["raw"], str(env.dir / "scans" / "openscap-20260301-101011"))
        self.assertIn("openscap-20260301-101011", seen["cmd"][-1])


# ---------------------------------------------------------------- Markdown tables (resilience#36)

class MarkdownTests(unittest.TestCase):
    def test_cells_escape_pipes_and_newlines(self):
        self.assertEqual(scan.md_cell("a | b\nc"), "a \\| b c")
        self.assertEqual(scan.md_cell(None), "")
        self.assertEqual(scan.md_cell("x" * 10, 5), "xxxx…")

    def test_chaos_markdown_keeps_one_row_per_experiment(self):
        ctx = make_ctx()
        rep = {"run": "20260301-111111", "env": ctx.env.id, "target": "x/canary", "canary": True, "duration_s": 30, "distro": "rke2", "cloud": "vmware",
               "results": [{"experiment": "pod-kill", "verdict": "ERROR", "reason": "kubectl failed: a|b\nline two"},
                           {"experiment": "pod-failure", "verdict": "SKIP", "reason": "not run"}],
               "summary": {"PASS": 0, "FAIL": 0, "SKIP": 1, "ERROR": 1}, "verdict": "FAIL"}
        md = chaos.save_report(ctx, rep).with_suffix(".md").read_text()
        rows = [ln for ln in md.splitlines() if ln.startswith("| pod-")]
        self.assertEqual(len(rows), 2)
        self.assertIn("kubectl failed: a\\|b line two", rows[0])
        self.assertEqual(len(re.findall(r"(?<!\\)\|", rows[0])), 8)            # 7 columns, no stray separator
        self.assertIn("| pod-failure | SKIP | - | - | - | - |", md)           # missing values: '-' with no unit
        self.assertIn("1 error", md)
        self.assertNotIn("1 errors", md)
        with silenced() as (out, _):
            chaos.print_report(dict(rep, summary={"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 2}))
        self.assertIn("2 errors", ui._strip(out.getvalue()))

    def test_dr_and_scan_markdown_escape_details(self):
        ctx = make_ctx()
        rep = {"run": "20260301-121212", "env": ctx.env.id, "cloud": "vmware", "distro": "rke2", "velero": "v1.18.2", "volume_tested": False,
               "steps": [{"step": "2. backup", "ok": False, "seconds": 1.0, "detail": "phase Failed | see\nlogs"}], "verdict": "FAIL", "total_s": 1, "rto_s": 0}
        md = dr.save_report(ctx, rep).with_suffix(".md").read_text()
        self.assertIn("| 2. backup | FAILED | 1.0 | phase Failed \\| see logs |", md)
        env = fresh_env("aws")
        p = scan.save_report(env, "kube", {"summary": {}, "findings": [{"status": "FAIL", "severity": "HIGH", "title": "C-1 a|b", "detail": "x\ny"}]})
        self.assertIn("| FAIL | HIGH | C-1 a\\|b | x y |", p.with_suffix(".md").read_text())


# ---------------------------------------------------------------- agent sessions never install scanners (mcp#1)

class AgentInstallTests(unittest.TestCase):
    def test_tool_is_not_installed_from_an_agent_session(self):
        installer = mock.Mock()
        for agent in ("mcp", "claude"):
            with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": agent}), mock.patch.object(scan.deps, "find", return_value=None), \
                    mock.patch.object(scan.shutil, "which", return_value="/opt/homebrew/bin/brew"), \
                    mock.patch.object(scan.subprocess, "run", side_effect=AssertionError("must not run brew")), silenced(), \
                    self.assertRaises(SystemExit) as cm:
                scan._tool("kubescape", "kubescape", installer)
            self.assertEqual(cm.exception.code, 2)
            self.assertIn(f"kubescape is not installed, and cloudseed does not install software from an agent session ({agent})", cm.exception.msg)
            self.assertIn("brew install kubescape", cm.exception.msg)
            self.assertIn("cs scan kube", cm.exception.msg)
        installer.assert_not_called()
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "mcp"}), mock.patch.object(scan.deps, "find", return_value="/usr/local/bin/trivy"):
            self.assertEqual(scan._tool("trivy", "trivy", installer), "/usr/local/bin/trivy")   # an installed tool is fine

    def test_prowler_is_not_installed_or_rebuilt_from_an_agent_session(self):
        home = Path(tempfile.mkdtemp())
        with mock.patch.object(scan.paths, "HOME", home), mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "mcp"}), \
                mock.patch.object(scan, "_prowler_python", side_effect=AssertionError("must not build a venv")), silenced(), \
                self.assertRaises(SystemExit) as cm:
            scan._prowler()
        self.assertIn("cs scan cloud", cm.exception.msg)
        venv = home / "venv-prowler"
        (venv / "bin").mkdir(parents=True)
        (venv / "bin" / "prowler").write_text("#!/root/.cloudseed/venv-prowler/bin/python\n")
        with mock.patch.object(scan.paths, "HOME", home), mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "mcp"}), \
                mock.patch.object(scan.deps, "venv_usable", return_value=False), silenced(), self.assertRaises(SystemExit) as cm:
            scan._prowler()
        self.assertIn("does not run on this machine", cm.exception.msg)
        self.assertTrue(venv.exists())   # nothing removed either


# ---------------------------------------------------------------- prowler venv from another system (ops#8)

class ProwlerVenvTests(unittest.TestCase):
    def _home_with_venv(self, shebang: str) -> Path:
        home = Path(tempfile.mkdtemp())
        venv = home / "venv-prowler"
        (venv / "bin").mkdir(parents=True)
        (venv / "bin" / "prowler").write_text(f"#!{shebang}\n")
        (venv / "bin" / "python").write_text("")
        return home

    def _prowler(self, home, usable: bool):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            if cmd[1:3] == ["-m", "venv"]:
                (Path(cmd[3]) / "bin").mkdir(parents=True, exist_ok=True)
            elif "install" in cmd:
                (home / "venv-prowler" / "bin" / "prowler").write_text("#!/bin/sh\n")
            return cp(0)
        env = {k: v for k, v in os.environ.items() if k != "CLOUDSEED_AGENT"}
        with mock.patch.object(scan.paths, "HOME", home), mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(scan.deps, "venv_usable", return_value=usable), mock.patch.object(scan, "_prowler_problem", return_value=""), \
                mock.patch.object(scan, "_prowler_python", return_value=("/opt/py312", (3, 12))), \
                mock.patch.object(scan.subprocess, "run", side_effect=run), silenced() as (_, err):
            return scan._prowler(), calls, err.getvalue()

    def test_venv_built_by_another_system_is_rebuilt(self):
        home = self._home_with_venv("/root/.cloudseed/venv-prowler/bin/python")   # made inside the container
        path, calls, err = self._prowler(home, usable=True)
        self.assertEqual(path, str(home / "venv-prowler" / "bin" / "prowler"))
        self.assertTrue(any(c[1:3] == ["-m", "venv"] for c in calls))
        self.assertIn("does not run on this machine", err)

    def test_usable_venv_is_kept(self):
        home = self._home_with_venv("/bin/sh")
        path, calls, _ = self._prowler(home, usable=True)
        self.assertEqual(calls, [])
        self.assertTrue(path.endswith("prowler"))
        _, calls, _ = self._prowler(home, usable=False)   # its interpreter does not run here: rebuilt
        self.assertTrue(any(c[1:3] == ["-m", "venv"] for c in calls))


# ---------------------------------------------------------------- FIPS SSH key check (azure#0)

class FipsKeyTests(unittest.TestCase):
    def _key_check(self, cloud_key: str, pub: str) -> dict:
        env = fresh_env(cloud_key)
        cfg = {"vars": {"fips_mode": True, "project_id": "p"}, "ssh_public_key": pub}
        with mock.patch.object(scan, "_hosts", return_value=[]), silenced():
            rep = json.loads(scan.fips(clouds.get(cloud_key), env, cfg, {}).read_text())
        return next(c for c in rep["checks"] if c["area"] == "ssh")

    def test_setup_rules_decide(self):
        self.assertEqual(self._key_check("aws", rsa_pub(4096))["status"], "PASS")
        self.assertIn("4096", self._key_check("aws", rsa_pub(4096))["detail"])
        for cloud_key, pub, why in (("aws", ecdsa_pub(), "EC2"), ("azure", ecdsa_pub(), "Azure"), ("gcp", rsa_pub(2048), "FIPS"),
                                    ("gcp", ed25519_pub(), "ed25519"), ("aws", rsa_pub(3072), "EC2")):
            chk = self._key_check(cloud_key, pub)
            self.assertEqual(chk["status"], "FAIL", (cloud_key, pub[:20]))
            self.assertIn(why, chk["detail"])
        self.assertEqual(self._key_check("gcp", ecdsa_pub())["status"], "PASS")
        self.assertEqual(self._key_check("gcp", "")["status"], "INFO")

    def test_config_hint_names_the_key_type_setup_generates(self):
        env = fresh_env("aws")
        with mock.patch.object(scan, "_hosts", return_value=[]), silenced():
            rep = json.loads(scan.fips(clouds.get("aws"), env, {"vars": {}}, {}).read_text())
        detail = next(c for c in rep["checks"] if c["area"] == "config")["detail"]
        self.assertIn("RSA-4096", detail)
        self.assertNotIn("ECDSA", detail)


# ---------------------------------------------------------------- Velero hints with an in-cluster MinIO (e2e#19)

def bsl(config: dict) -> str:
    return json.dumps({"metadata": {"name": "default"}, "spec": {"provider": "aws", "config": config}, "status": {"phase": "Available"}})


class VeleroHintTests(unittest.TestCase):
    def _hint(self, target, config):
        ctx = make_ctx(target)
        # (wave 4) the location is read with kubectl, like `cs dr status`: a hint never needs the velero CLI
        locations = cp(0, json.dumps({"items": [json.loads(bsl(config))]}))
        with mock.patch.object(dr, "_kubectl", return_value=locations), mock.patch.object(dr, "_velero", side_effect=AssertionError("velero CLI")):
            return ctx, dr.velero_hint(ctx, "backup", "describe", "b1", "--details")

    def test_in_cluster_minio_runs_inside_the_velero_pod(self):
        # (wave 5) the describe/logs hints are `cs dr describe|logs`, which pick the CLI here or the velero pod
        # themselves (dr.show); every other velero command runs in the velero pod
        for target, config in (("vmware", {"region": "minio", "s3Url": "http://minio.minio.svc:9000", "s3ForcePathStyle": "true"}),
                               ("vmware", {"s3Url": "http://minio.minio.svc:9000", "publicUrl": "https://minio.example.com"}),
                               ("aws", {"region": "eu-west-1"}), ("vmware", {})):
            ctx, hint = self._hint(target, config)
            self.assertEqual(hint, f"cs dr describe backup b1 --details {target} --env {ctx.env.name}")
        ctx = make_ctx("aws")
        self.assertEqual(dr.velero_hint(ctx, "backup", "delete", "b1", "--confirm"),
                         f"cs kubectl aws --env {ctx.env.name} -n velero exec svc/velero -c velero -- /velero backup delete b1 --confirm")

    def test_location_check_remembers_the_config(self):
        ctx = make_ctx("vmware")
        calls = []

        def velero(ctx_, *args, **kw):
            calls.append(args)
            return cp(0, bsl({"s3Url": "http://minio.minio.svc:9000"}))
        with mock.patch.object(dr, "_velero", velero), mock.patch.object(dr, "ensure_cli"):
            dr.wait_location(ctx)
            dr.velero_hint(ctx, "backup", "logs", "b1")
            dr.velero_hint(ctx, "restore", "logs", "r1")
        self.assertEqual(len(calls), 1)

    def test_failed_backup_and_drill_hints_work_on_vmware(self):
        ctx = make_ctx("vmware")

        def velero(ctx_, *args, **kw):
            if args[0] == "backup-location":
                return cp(0, bsl({"s3Url": "http://minio.minio.svc:9000"}))
            return cp(0, json.dumps({"status": {"phase": "Failed", "failureReason": "unable to reach bucket"}}))
        locations = cp(0, json.dumps({"items": [json.loads(bsl({"s3Url": "http://minio.minio.svc:9000"}))]}))
        with mock.patch.object(dr, "_velero", velero), mock.patch.object(dr, "_kubectl", return_value=locations), \
                silenced(), self.assertRaises(SystemExit) as cm:
            dr._finish(ctx, "backup", "b1", allow_partial=False)
        self.assertIn("cs dr describe backup b1 --details vmware --env", cm.exception.msg)
        self.assertIn("cs dr logs backup b1 vmware --env", cm.exception.msg)
        self.assertNotIn(" velero backup describe", cm.exception.msg)   # never a bare velero (PATH, kube context)


# ---------------------------------------------------------------- the drill: Ctrl-C while the backup runs, AKS identity

class FakeDrill:
    """kubectl + velero for the drill: the backup stays InProgress for `running_polls` status reads after an interrupt."""

    def __init__(self, running_polls=2, interrupt_backup=True, node_agent_env=None):
        self.running_polls, self.interrupt_backup = running_polls, interrupt_backup
        self.node_agent_env = node_agent_env
        self.token, self.volume, self.velero_calls, self.kubectl_calls = None, None, [], []

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
        if "sc" in a:
            return cp(0, "managed-csi")
        if "pods" in a and "name=node-agent" in a:
            env = [{"name": "AZURE_FEDERATED_TOKEN_FILE", "value": "/var/run/secrets/token"}] if self.node_agent_env else []
            return cp(0, json.dumps({"items": [{"metadata": {"name": "node-agent-x1"}, "spec": {"containers": [{"name": "node-agent", "env": env}]}}]}))
        if "podvolumebackups" in a or "podvolumerestores" in a:
            return cp(0, "Completed\n")
        if "cm" in a:
            return cp(0, self.token)
        if "secret" in a:
            return cp(0, base64.b64encode(self.token.encode()).decode())
        return cp(0)

    def velero(self, ctx, *args, check=True, stream=False, timeout=1800, quiet=False):
        self.velero_calls.append(args)
        if args[:2] == ("backup", "create") and self.interrupt_backup:
            raise KeyboardInterrupt
        if args[:2] == ("backup", "get"):
            if self.running_polls > 0:
                self.running_polls -= 1
                return cp(0, json.dumps({"status": {"phase": "InProgress"}}))
            return cp(0, json.dumps({"status": {"phase": "Completed"}}))
        if len(args) >= 2 and args[1] == "get":
            return cp(0, json.dumps({"status": {"phase": "Completed"}}))
        return cp(0)


class DrillTests(unittest.TestCase):
    def _drill(self, fake, target="vmware", keep=False, with_volume=None):
        ctx = make_ctx(target)
        with mock.patch.object(dr, "require"), mock.patch.object(dr, "_kubectl", fake.kubectl), mock.patch.object(dr, "_velero", fake.velero), \
                mock.patch.object(dr, "server_version", return_value="v1.18.2"), mock.patch.object(dr, "time", FakeClock()), silenced() as (out, err):
            rc = dr.test(ctx, keep=keep, with_volume=with_volume)
        return rc, json.loads(dr.last_report(ctx.env).read_text()), ui._strip(out.getvalue() + err.getvalue())

    def test_interrupted_backup_is_waited_for_then_deleted(self):
        fake = FakeDrill(running_polls=3)
        rc, rep, _ = self._drill(fake)
        self.assertEqual((rc, rep["verdict"]), (130, "INTERRUPTED"))
        create = next(c for c in fake.velero_calls if c[:2] == ("backup", "create"))
        self.assertEqual(create[create.index("--ttl") + 1], dr.DRILL_BACKUP_TTL)   # an orphan still expires
        polls = [i for i, c in enumerate(fake.velero_calls) if c[:2] == ("backup", "get")]
        delete = next(i for i, c in enumerate(fake.velero_calls) if c[:2] == ("backup", "delete"))
        self.assertEqual(len(polls), 4)
        self.assertLess(polls[-1], delete)   # deleted only once it finished

    def test_backup_still_running_after_the_wait_is_left_to_its_ttl(self):
        fake = FakeDrill(running_polls=10_000)
        rc, rep, text = self._drill(fake)
        self.assertEqual(rc, 130)
        self.assertIn("still InProgress", text)
        self.assertIn(f"expires by itself after {dr.DRILL_BACKUP_TTL}", text)
        self.assertIn("cleaned up except backup dr-test-", rep["steps"][-1]["detail"])   # the report does not claim it was removed
        self.assertLessEqual(sum(1 for c in fake.velero_calls if c[:2] == ("backup", "get")), dr.SETTLE_S // 3 + 2)

    def test_kept_drill_backup_has_no_ttl_and_failures_point_at_keep(self):
        fake = FakeDrill(running_polls=0, interrupt_backup=False)
        rc, rep, _ = self._drill(fake, keep=True, with_volume=False)
        self.assertEqual(rc, 0, rep)
        create = next(c for c in fake.velero_calls if c[:2] == ("backup", "create"))
        self.assertNotIn("--ttl", create)
        with silenced() as (out, _):
            dr.print_report(dict(rep, verdict="FAIL", kept=False))
        self.assertIn("cs dr test --keep", ui._strip(out.getvalue()))
        with silenced() as (out, _):
            dr.print_report(dict(rep, verdict="FAIL", kept=True))
        self.assertNotIn("--keep", ui._strip(out.getvalue()))

    def test_aks_node_agent_without_workload_identity_fails_before_the_backup(self):
        fake = FakeDrill(running_polls=0, interrupt_backup=False, node_agent_env=False)
        rc, rep, _ = self._drill(fake, target="azure")
        self.assertEqual((rc, rep["verdict"]), (1, "FAIL"))
        self.assertEqual(rep["steps"][-1]["step"], "2. backup")
        self.assertIn("AZURE_FEDERATED_TOKEN_FILE", rep["steps"][-1]["detail"])
        self.assertFalse(any(c[:2] == ("backup", "create") for c in fake.velero_calls))
        self.assertFalse(any(c[:2] == ("backup", "delete") for c in fake.velero_calls))   # nothing was created
        fake = FakeDrill(running_polls=0, interrupt_backup=False, node_agent_env=True)
        rc, rep, _ = self._drill(fake, target="azure")
        self.assertEqual((rc, rep["verdict"]), (0, "PASS"), rep)


# ---------------------------------------------------------------- chaos.run input checks (resilience#10)

class ChaosRunInputTests(unittest.TestCase):
    def test_nonsense_duration_or_replicas_abort_before_anything_is_installed(self):
        ctx = make_ctx()
        with mock.patch.object(pl, "ensure_tools") as et, mock.patch.object(chaos, "ensure_chaos_mesh") as ecm, silenced():
            for duration, replicas, target in ((0, 3, None), (-5, 3, None), (7200, 3, None), (45, 1, None), (45, 0, None), (45, 21, None)):
                with self.assertRaises(SystemExit, msg=(duration, replicas)):
                    chaos.run(ctx, ["pod-kill"], None, target, duration, replicas, False)
        et.assert_not_called()
        ecm.assert_not_called()

    def test_replicas_only_matter_for_the_canary(self):
        ctx = make_ctx()
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(chaos, "ensure_chaos_mesh", side_effect=ui.Abort("stop here")), \
                silenced(), self.assertRaises(SystemExit) as cm:
            chaos.run(ctx, ["pod-kill"], None, "shop/api", 45, 1, False)
        self.assertEqual(cm.exception.msg, "stop here")   # got past the checks


if __name__ == "__main__":
    unittest.main()
