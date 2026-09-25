"""Regression tests for the cluster-facing CLI commands: env resolution, nodes, platform, chaos, dr, scan, kubectl/helm
passthrough, undo journaling, finops, explain and managed data platforms. No network, no cloud, no cluster: every
external tool is mocked."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import secrets as pysecrets
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, help as helpmod, paths, platform as platformmod, scan, services, ui, undo  # noqa: E402

BASE_CFG = {"name": "acme", "owner": "me", "region": "us-east-1", "network_cidr": "10.0.0.0/16", "allowed_ssh_cidrs": ["203.0.113.7/32"],
            "ssh_public_key": "ssh-ed25519 AAAA test", "state": {"type": "local", "backend": None}, "tags": {},
            "vars": {"profile": "", "enable_kubernetes": False, "kubernetes_node_count": 2}, "extra_vars": {}}


def exits(fn, *a, **kw) -> int:
    """The SystemExit code of fn (argparse errors, ui.Abort), output captured; fails when fn returns normally."""
    res = run_quiet(fn, *a, **kw)[0]
    if not (isinstance(res, tuple) and res[:1] == ("exit",)):
        raise AssertionError(f"expected SystemExit, got {res!r}")
    return res[1]


def run_quiet(fn, *a, **kw):
    """Call fn capturing stdout/stderr; returns (result or the SystemExit code, out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            res = fn(*a, **kw)
        except SystemExit as e:
            if isinstance(e, ui.Abort):   # quiet when raised, shown once by the dispatcher (cli-parser): do the same here
                ui.show_abort(e)
            res = ("exit", e.code)
    return res, out.getvalue(), err.getvalue()


class Fixture(unittest.TestCase):
    """Environments with unique names under the test home; list_all() sees only these."""

    def setUp(self):
        self._ni = ui.NON_INTERACTIVE
        ui.NON_INTERACTIVE = True
        self.tag = "t" + pysecrets.token_hex(3)
        self.envs: list[paths.Env] = []
        p = mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [paths.Env(e.cloud, e.name) for e in self.envs]))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        ui.NON_INTERACTIVE = self._ni
        for e in self.envs:
            shutil.rmtree(e.dir, ignore_errors=True)
            undo.clear(e.id)

    def env(self, cloud: str, suffix: str, outputs: dict | None = None, name: str | None = None, **vars_) -> paths.Env:
        env = paths.Env(cloud, name or f"{self.tag}{suffix}")
        cfg = copy.deepcopy(BASE_CFG)
        cfg.update(cloud=cloud, env=env.name)
        cfg["vars"].update(vars_)
        env.save(cfg)
        if outputs is not None:
            (env.dir / "outputs.json").write_text(json.dumps(outputs))
        self.envs.append(env)
        return env


CLUSTER = {"kubernetes_cluster_name": "c1"}


# ---------------------------------------------------------------- environment resolution (platform-logic#17, #31)

class ClusterEnvResolutionTests(Fixture):
    def test_current_env_without_cluster_is_not_silently_replaced(self):
        cur = self.env("aws", "a")
        self.env("vmware", "b", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        env, problem, kind = cli._pick_cluster_env(None, None, {"current_env": cur.id})
        self.assertIsNone(env)
        self.assertEqual(kind, "no-cluster")
        self.assertIn(cur.id, problem)
        self.assertIn("enable_kubernetes=true", problem)

    def test_stale_current_env_is_ignored_with_a_warning(self):
        only = self.env("gcp", "c", CLUSTER)
        (env, problem, _), _, err = run_quiet(cli._pick_cluster_env, None, None, {"current_env": "aws-gone"})
        self.assertEqual(env.id, only.id)
        self.assertIsNone(problem)
        self.assertIn("no longer exists", err)

    def test_cloud_alone_prefers_the_env_with_a_cluster(self):
        self.env("vmware", "dev")
        lab = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        env, problem, _ = cli._pick_cluster_env("vmware", None, {})
        self.assertEqual(env.id, lab.id)

    def test_env_name_without_cluster_names_the_problem(self):
        self.env("gcp", "c", CLUSTER)
        dr = self.env("aws", "dr")
        env, problem, kind = cli._pick_cluster_env(None, dr.name, {})
        self.assertEqual(kind, "no-cluster")
        self.assertIn(dr.id, problem)
        _, problem, kind = cli._pick_cluster_env(None, "nope", {})
        self.assertEqual(kind, "unknown")
        self.assertIn("No environment named 'nope'", problem)

    def test_several_clusters_non_interactive(self):
        self.env("gcp", "c", CLUSTER)
        self.env("aws", "k", CLUSTER)
        env, problem, kind = cli._pick_cluster_env(None, None, {})
        self.assertEqual(kind, "several")

    def test_env_use_needs_an_id(self):
        args = SimpleNamespace(env_cmd="use", id=None)
        res, _, err = run_quiet(cli.cmd_env, args, {})
        self.assertEqual(res, ("exit", 2))            # a missing argument is a usage error (cli-parser: exit 2)
        self.assertIn("cs env use <id>", err)

    def test_invalid_env_name_is_refused(self):
        self.assertEqual(exits(cli._check_env_name, "../../../escaped"), 1)
        cli._check_env_name("lab-2")


class PlainEnvResolutionTests(Fixture):
    """scan host/cloud/fips/stig/all and finops (resilience#12, #13)."""

    def args(self, **kw):
        return SimpleNamespace(**{"cloud": None, "env": None, **kw})

    def test_current_env_wins_over_the_only_cluster(self):
        dr = self.env("aws", "dr")
        self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        a = self.args()
        cli._resolve_plain_env(a, {"current_env": dr.id}, "scan fips", prefer_cluster=True)
        self.assertEqual((a.cloud, a.env), ("aws", dr.name))

    def test_env_name_is_resolved_by_name(self):
        dr = self.env("aws", "dr")
        cur = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        a = self.args(env=dr.name)
        cli._resolve_plain_env(a, {"current_env": cur.id}, "scan reports")
        self.assertEqual((a.cloud, a.env), ("aws", dr.name))

    def test_several_clusters_abort_cleanly_instead_of_keyerror(self):
        self.env("aws", "a", CLUSTER)
        self.env("gcp", "b", CLUSTER)
        res, _, err = run_quiet(cli._resolve_plain_env, self.args(), {}, "scan fips", True)
        self.assertEqual(res, ("exit", 1))
        self.assertIn("Pass <cloud> --env <name>", err)

    def test_only_cluster_fallback_kept_for_fips(self):
        self.env("aws", "a")
        lab = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        a = self.args()
        cli._resolve_plain_env(a, {}, "scan fips", prefer_cluster=True)
        self.assertEqual(a.cloud + "-" + a.env, lab.id)


# ---------------------------------------------------------------- scan (resilience#12, #13, #30, e2e#10)

class ScanTests(Fixture):
    def _fake_report(self, env, verdict):
        def fake(*a, **kw):
            d = env.dir / "scans"
            d.mkdir(parents=True, exist_ok=True)
            p = d / f"fips-{pysecrets.token_hex(3)}.json"
            p.write_text(json.dumps({"verdict": verdict}))
            return p
        return fake

    def test_fips_scans_the_current_env_and_exits_1_on_fail(self):
        dr = self.env("aws", "dr")
        self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        args = SimpleNamespace(scan_cmd="fips", cloud=None, env=None, host=None, profile=None, framework=None, last=10)
        with mock.patch.object(scan, "fips", side_effect=self._fake_report(dr, "FAIL")) as f:
            rc, _, _ = run_quiet(cli.cmd_scan, args, {"current_env": dr.id})
        self.assertEqual(rc, 1)
        self.assertEqual(f.call_args[0][1].id, dr.id)
        self.assertIsNone(f.call_args[0][4])   # no cluster ctx: aws-dr has none
        e = undo.latest(dr.id)
        self.assertTrue(e["minor"])

    def test_pass_exits_0(self):
        dr = self.env("aws", "dr")
        args = SimpleNamespace(scan_cmd="fips", cloud="aws", env=dr.name, host=None, profile=None, framework=None, last=10)
        with mock.patch.object(scan, "fips", side_effect=self._fake_report(dr, "PASS")):
            rc, _, _ = run_quiet(cli.cmd_scan, args, {})
        self.assertEqual(rc, 0)

    def test_unreachable_cluster_degrades_to_host_checks(self):
        lab = self.env("aws", "lab", CLUSTER)
        args = SimpleNamespace(scan_cmd="fips", cloud="aws", env=lab.name, host=None, profile=None, framework=None, last=10)
        with mock.patch.object(services, "ensure_kubeconfig", side_effect=lambda *a: (_ for _ in ()).throw(ui.Abort("Could not fetch the kubeconfig: x"))), \
                mock.patch.object(scan, "fips", side_effect=self._fake_report(lab, "PASS")) as f:
            rc, _, err = run_quiet(cli.cmd_scan, args, {})
        self.assertEqual(rc, 0)
        self.assertIsNone(f.call_args[0][4])
        self.assertIn("Cluster checks skipped", err)
        self.assertNotIn("✖", err)

    def test_run_all_reports_errors_and_verdicts(self):
        env = self.env("vmware", "x")
        cloud = clouds.get("vmware")
        errors: list = []

        def boom(*a, **kw):
            raise ui.Abort("no host")
        with mock.patch.object(scan, "_hosts", return_value=[]), mock.patch.object(scan, "fips", side_effect=boom):
            # (FIPS is verified in `scan all` of a FIPS environment only - resilience)
            done, out, err = run_quiet(scan.run_all, cloud, env, env.load(), {"fips_mode": True}, None, ["bastion"], errors=errors)
        self.assertEqual(done, [])
        self.assertEqual(errors, ["fips"])
        self.assertIn("ERROR", out)

    def test_fips_report_persists_its_verdict(self):
        env = self.env("aws", "v")
        path, _, _ = run_quiet(scan.fips, clouds.get("aws"), env, env.load(), {}, None)
        self.assertEqual(json.loads(Path(path).read_text())["verdict"], "N/A")    # fips_mode off: not a FIPS environment
        cfg = dict(env.load(), vars={"fips_mode": True}, ssh_public_key="ssh-ed25519 AAAA")
        path, _, _ = run_quiet(scan.fips, clouds.get("aws"), env, cfg, {}, None)
        self.assertEqual(json.loads(Path(path).read_text())["verdict"], "FAIL")   # fips_mode on, ed25519 key


# ---------------------------------------------------------------- chaos (resilience#10, #17, #27, docs-skills#9)

class ChaosTests(Fixture):
    def test_documented_positional_cloud_is_the_target(self):
        a = cli.build_parser().parse_args(["chaos", "run", "network-loss", "cpu-stress", "vmware", "--env", "lab"])
        cli._pop_cloud_from_items(a)
        self.assertEqual((a.cloud, a.items), ("vmware", ["network-loss", "cpu-stress"]))
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "vmware", "--cloud", "vmware"])
        cli._pop_cloud_from_items(a)
        self.assertEqual((a.cloud, a.items), ("vmware", ["pod-kill"]))
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "vmware", "--cloud", "aws"])
        self.assertEqual(exits(cli._pop_cloud_from_items, a), 1)

    def test_typo_fails_before_any_cluster_work(self):
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kil", "vmware", "--env", "lab"])
        with mock.patch.object(cli, "_resolve_cluster_env") as resolve:
            res, _, err = run_quiet(cli.cmd_chaos, a, {})
        self.assertEqual(res, ("exit", 1))
        resolve.assert_not_called()
        self.assertIn("did you mean pod-kill", err)

    def test_duration_and_replicas_are_validated_at_parse_time(self):
        p = cli.build_parser()
        self.assertEqual(p.parse_args(["chaos", "run", "--duration", "45s"]).duration, 45)
        self.assertEqual(p.parse_args(["chaos", "run", "--duration", "2m"]).duration, 120)
        self.assertEqual(p.parse_args(["chaos", "run"]).duration, 45)
        self.assertIsNone(p.parse_args(["chaos", "run"]).replicas)
        for bad in (["--duration", "abc"], ["--duration", "3"], ["--duration", "1.5"], ["--replicas", "0"], ["--replicas", "two"]):
            self.assertEqual(exits(p.parse_args, ["chaos", "run", *bad]), 2, bad)

    def test_run_records_one_minor_entry(self):
        env = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        rep = env.dir / "chaos" / "report-1.json"
        rep.parent.mkdir(parents=True, exist_ok=True)
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "--cloud", "vmware", "--env", env.name])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), {})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli, "_ensure_chaos_mesh"), \
                mock.patch.object(cli.chaos, "run", side_effect=lambda ctx, *a, **kw: rep.write_text("{}") and
                                  setattr(ctx, "chaos_report", rep) or 0) as run:   # chaos.run names the report it saved
            rc, _, _ = run_quiet(cli.cmd_chaos, a, {})
        self.assertEqual(rc, 0)
        self.assertEqual(run.call_args[0][4:6], (45, 3))
        entries = undo.entries(env.id)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["kind"], "delete-paths")
        self.assertTrue(entries[0]["minor"])


# ---------------------------------------------------------------- undo history (resilience#27)

class UndoMinorTests(unittest.TestCase):
    def test_minor_entries_never_evict_real_undo_points(self):
        scope = "aws-t" + pysecrets.token_hex(3)
        self.addCleanup(undo.clear, scope)
        # real undo points are state-changing kinds ("info" entries count as minor with the ops journal: nothing to revert)
        for i in range(5):
            undo.record(scope, f"real {i}", "argv", {"argv": ["disable", str(i)]})
        n = undo.KEEP_LIGHT + 2
        for i in range(n):
            undo.record(scope, f"report {i}", "delete-paths", {"paths": []}, minor=True)
        summaries = [e["summary"] for e in undo.entries(scope)]
        for i in range(5):
            self.assertIn(f"real {i}", summaries)
        self.assertEqual([s for s in summaries if s.startswith("report")], [f"report {i}" for i in range(2, n)])   # newest minors only
        self.assertEqual(undo.latest(scope)["summary"], f"report {n - 1}")
        undo.record(scope, "real 5", "argv", {"argv": ["disable", "5"]})
        self.assertNotIn("real 0", [e["summary"] for e in undo.entries(scope)])

    def test_undo_replays_take_no_safety_backup(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_UNDOING": "1"}):
            self.assertIsNone(cli._pre_change_undo("kubectl", ["delete", "ns", "x"], None, None, None, None, None, ctx=object()))


class DrTests(Fixture):
    def _run(self, keep):
        env = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        a = cli.build_parser().parse_args(["dr", "test", "--cloud", "vmware", "--env", env.name] + (["--keep"] if keep else []))
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), {})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli.dr, "installed", return_value=True), mock.patch.object(cli.dr, "test", return_value=0):
            run_quiet(cli.cmd_dr, a, {})
        return undo.entries(env.id)

    def test_self_cleaning_drill_records_nothing(self):
        self.assertEqual(self._run(False), [])

    def test_kept_drill_is_a_minor_entry(self):
        entries = self._run(True)
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["minor"])


# ---------------------------------------------------------------- kubectl / helm passthrough (platform-logic#5, #11, #18)

class PassthroughTests(Fixture):
    def setUp(self):
        super().setUp()
        docker = tempfile.mkdtemp()   # never read the real ~/.docker in tests
        self.addCleanup(shutil.rmtree, docker, True)
        p = mock.patch.dict(os.environ, {"DOCKER_CONFIG": docker})
        p.start()
        self.addCleanup(p.stop)

    def _ktool(self, tool, tool_args, env=None):
        env = env or self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        a = SimpleNamespace(cmd=tool, tool_args=tool_args, cloud=None, env=None)
        seen = {}

        def resolve(args, settings):
            seen["cloud"], seen["env"] = args.cloud, args.env
            return clouds.get("vmware"), env, env.load(), {}
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=resolve), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli.deps, "find", return_value="/bin/" + tool), \
                mock.patch.object(cli, "_pre_change_undo", return_value=None), \
                mock.patch.object(cli.subprocess, "call", return_value=0) as call:
            run_quiet(cli.cmd_ktool, a, {})
        seen["argv"], seen["env_vars"] = call.call_args[0][0][1:], call.call_args[1]["env"]
        return seen

    def test_separators_after_the_first_belong_to_kubectl(self):
        self.assertEqual(self._ktool("kubectl", ["exec", "bb", "--", "ls", "-la"])["argv"], ["exec", "bb", "--", "ls", "-la"])
        self.assertEqual(self._ktool("kubectl", ["--", "exec", "bb", "--", "sh", "-c", "x"])["argv"], ["exec", "bb", "--", "sh", "-c", "x"])
        s = self._ktool("kubectl", ["aws", "--env", "dev", "--", "get", "pods"])
        self.assertEqual((s["cloud"], s["env"], s["argv"]), ("aws", "dev", ["get", "pods"]))
        s = self._ktool("kubectl", ["vmware", "--env=lab", "get", "ns"])
        self.assertEqual((s["cloud"], s["env"], s["argv"]), ("vmware", "lab", ["get", "ns"]))
        self.assertEqual(self._ktool("kubectl", ["get", "pods", "-A"])["argv"], ["get", "pods", "-A"])

    def test_helm_gets_the_installer_environment(self):
        explicit = os.environ.pop("DOCKER_CONFIG")
        with mock.patch.object(platformmod, "_docker_config_without_missing_helpers"):
            s = self._ktool("helm", ["show", "chart", "oci://x/y"])
        self.assertTrue(s["env_vars"]["DOCKER_CONFIG"].endswith("/helm/docker"))
        self.assertTrue(s["env_vars"]["HELM_REGISTRY_CONFIG"].endswith("registry.json"))
        os.environ["DOCKER_CONFIG"] = explicit   # a caller's explicit choice wins
        self.assertEqual(self._ktool("helm", ["list"])["env_vars"]["DOCKER_CONFIG"], explicit)

    def test_old_registry_login_is_carried_over(self):
        old = paths.HOME / "helm" / "config" / "registry" / "config.json"
        old.parent.mkdir(parents=True, exist_ok=True)
        old.write_text('{"auths": {"r.io": {"auth": "x"}}}')
        self.addCleanup(old.unlink)
        with tempfile.TemporaryDirectory() as td:
            reg = Path(td) / "registry.json"
            reg.write_text("{}\n")
            cli._migrate_helm_registry_login(reg)
            self.assertIn("r.io", reg.read_text())

    def test_docker_config_keeps_logins_and_drops_missing_helpers(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "user"
            src.mkdir()
            (src / "config.json").write_text(json.dumps({"auths": {"ghcr.io": {"auth": "eDp5"}}, "credsStore": "cs-missing-helper",
                                                         "credHelpers": {"gcr.io": "present", "x.io": "absent"}}))
            bindir = Path(td) / "bin"
            bindir.mkdir()
            (bindir / "docker-credential-present").write_text("#!/bin/sh\n")
            os.chmod(bindir / "docker-credential-present", 0o755)
            target = Path(td) / "out.json"
            with mock.patch.dict(os.environ, {"DOCKER_CONFIG": str(src)}):
                platformmod._docker_config_without_missing_helpers(target, str(bindir))
            out = json.loads(target.read_text())
        self.assertEqual(out["auths"], {"ghcr.io": {"auth": "eDp5"}})
        self.assertNotIn("credsStore", out)
        self.assertEqual(out["credHelpers"], {"gcr.io": "present"})

    def test_ssh_keeps_later_separators(self):
        self.assertEqual(cli._strip_leading_sep(["--", "grep", "--", "-v", "f"]), ["grep", "--", "-v", "f"])
        self.assertEqual(cli._strip_leading_sep(None), [])


class PreChangeUndoTests(unittest.TestCase):
    def setUp(self):
        self.cloud = clouds.get("vmware")
        self.env = SimpleNamespace(name="lab", id="vmware-lab")
        self.ctx = SimpleNamespace(procenv=lambda: {})

    def pre(self, tool, rest, history=None, backup="pre-x"):
        hist = subprocess.CompletedProcess([], 0 if history else 1, json.dumps([{"revision": r} for r in history or []]), "")
        with mock.patch.object(cli.subprocess, "run", return_value=hist) as run, \
                mock.patch.object(undo, "velero_pre_backup", return_value=backup) as vb, \
                mock.patch.object(cli.deps, "find", return_value="/bin/x"):
            res = cli._pre_change_undo(tool, rest, self.cloud, self.env, {}, {}, None, ctx=self.ctx)
        return res, run, vb

    def test_helm_release_and_namespace_are_read_flag_aware(self):
        (kind, data, _), run, _ = self.pre("helm", ["install", "-n", "stubns", "stubrel", "./stub"])
        self.assertEqual((kind, data), ("helm", {"release": "stubrel", "ns": "stubns"}))
        (kind, data, _), _, _ = self.pre("helm", ["upgrade", "stubrel", "./stub", "--namespace=stubns"], history=[1, 2])
        self.assertEqual(data, {"release": "stubrel", "ns": "stubns", "revision": 2})
        (kind, data, _), _, _ = self.pre("helm", ["install", "-f", "v.yaml", "rel", "chart"])
        self.assertEqual(data["release"], "rel")
        (kind, data, notes), _, _ = self.pre("helm", ["install", "./chart", "--generate-name"])
        self.assertIn("generated_from", notes)
        self.assertNotIn("release", data)
        self.assertIsNone(self.pre("helm", ["upgrade", "r", "c", "--dry-run"])[0])

    def test_kubectl_scope(self):
        _, _, vb = self.pre("kubectl", ["delete", "ns", "prod"])
        self.assertEqual(vb.call_args[0][2], ["prod"])
        _, _, vb = self.pre("kubectl", ["delete", "clusterrole", "foo"])
        self.assertIsNone(vb.call_args[0][2])
        _, _, vb = self.pre("kubectl", ["-n", "x", "delete", "pod", "p"])
        self.assertEqual(vb.call_args[0][2], ["x"])
        _, _, vb = self.pre("kubectl", ["apply", "-f", "m.yaml"])
        self.assertIsNone(vb.call_args[0][2])
        _, _, vb = self.pre("kubectl", ["rollout", "restart", "deploy/x", "-nshop"])
        self.assertEqual(vb.call_args[0][2], ["shop"])

    def test_read_only_and_dry_runs_record_nothing(self):
        for rest in (["rollout", "status", "deploy/x"], ["rollout", "history", "deploy/x"], ["apply", "-f", "x", "--dry-run=client"],
                     ["get", "pods"], ["label", "pods", "--list"], ["exec", "bb", "--", "kubectl", "delete", "ns", "x"]):
            self.assertIsNone(self.pre("kubectl", rest)[0], rest)

    def test_cordon_undo_is_uncordon_and_no_velero_is_minor(self):
        (kind, data, _), _, _ = self.pre("kubectl", ["cordon", "n1"])
        self.assertEqual((kind, data["argvs"][0][-2:]), ("argv-seq", ["uncordon", "n1"]))
        (kind, _, notes), _, _ = self.pre("kubectl", ["delete", "pod", "p"], backup=None)
        self.assertEqual(kind, "info")
        self.assertTrue(notes["minor"])


# ---------------------------------------------------------------- nodes (platform-logic#6, #7, #28)

class ManagedNodeTests(Fixture):
    def pool_cli(self, cloud_key, size=2, lo=1, hi=4):
        calls = []

        def fake(cmd, what, parse=False, show=True, env=None):
            calls.append(cmd[1:])
            if "list-nodegroups" in cmd:
                return {"nodegroups": ["c1-default"]}
            if "describe-nodegroup" in cmd:
                return {"nodegroup": {"scalingConfig": {"desiredSize": size, "minSize": lo, "maxSize": hi}}}
            if cmd[1:4] == ["container", "node-pools", "list"]:
                return [{"name": "c1-default", "autoscaling": {"minNodeCount": lo, "maxNodeCount": hi},
                         "instanceGroupUrls": ["https://x/projects/p/zones/us-central1-a/instanceGroupManagers/gke-c1-grp"]}]
            if "instance-groups" in cmd and "describe" in cmd:
                return {"targetSize": size}
            if cmd[1:4] == ["aks", "nodepool", "show"]:
                return {"count": size, "minCount": lo, "maxCount": hi}
            return {} if parse else ""
        return calls, fake

    def run_node(self, env, argv, node=None, **pool):
        calls, fake = self.pool_cli(env.cloud, **pool)
        a = cli.build_parser().parse_args(["node"] + argv + ["--env", env.name, "--auto-approve"])
        node_json = subprocess.CompletedProcess([], 0, json.dumps(node or {}), "")
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get(env.cloud), env, env.load(), json.loads((env.dir / "outputs.json").read_text()))), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(platformmod, "ensure_tools"), mock.patch.object(cli.deps, "find", return_value="/bin/tool"), \
                mock.patch.object(cli, "_cloud_cli", side_effect=fake), \
                mock.patch.object(cli.subprocess, "run", return_value=node_json), \
                mock.patch.object(cli.subprocess, "call", return_value=0) as call, \
                mock.patch.object(cli, "_wait_ready_nodes", side_effect=lambda k, e, want, sel: want):
            rc, out, err = run_quiet(cli.cmd_node, a, {})
        return rc, calls, call, out + err

    def test_aws_add_scales_the_node_group_and_keeps_config_in_step(self):
        env = self.env("aws", "k", CLUSTER)
        rc, calls, _, _ = self.run_node(env, ["add", "aws"])
        self.assertEqual(rc, 0)
        upd = next(c for c in calls if "update-nodegroup-config" in c)
        self.assertIn("minSize=3,maxSize=4,desiredSize=3", upd)
        cfg = env.load()
        self.assertEqual((cfg["vars"]["kubernetes_node_count"], cfg["extra_vars"]["kubernetes_node_min"]), (3, 3))
        e = undo.latest(env.id)
        self.assertEqual(e["data"]["argv"][:3], ["node", "scale", "aws"])
        self.assertIn("--count", e["data"]["argv"])
        self.assertEqual(e["data"]["argv"][e["data"]["argv"].index("--count") + 1], "2")

    def test_gcp_add_updates_limits_then_resizes(self):
        env = self.env("gcp", "k", {"kubernetes_cluster_name": "c1", "kubernetes_location": "us-central1-a"}, project_id="p")
        rc, calls, _, _ = self.run_node(env, ["add", "gcp", "--count", "2"])
        self.assertEqual(rc, 0)
        i_upd = next(i for i, c in enumerate(calls) if c[:3] == ["container", "clusters", "update"])
        i_res = next(i for i, c in enumerate(calls) if c[:3] == ["container", "clusters", "resize"])
        self.assertLess(i_upd, i_res)
        self.assertEqual(calls[i_res][calls[i_res].index("--num-nodes") + 1], "4")

    def test_azure_add_raises_the_autoscaler_floor(self):
        env = self.env("azure", "k", {"kubernetes_cluster_name": "c1", "resource_group_name": "rg"}, subscription_id="s")
        rc, calls, _, _ = self.run_node(env, ["add", "azure"])
        upd = next(c for c in calls if c[:3] == ["aks", "nodepool", "update"])
        self.assertEqual(upd[upd.index("--min-count") + 1], "3")

    def test_remove_terminates_exactly_that_instance_and_lowers_the_floor_first(self):
        env = self.env("aws", "k", CLUSTER)
        node = {"spec": {"providerID": "aws:///us-east-1a/i-0abc"}}
        rc, calls, call, _ = self.run_node(env, ["remove", "aws", "ip-10-0-1-5"], node=node, size=3, lo=3, hi=4)
        self.assertEqual(rc, 0)
        i_min = next(i for i, c in enumerate(calls) if "update-nodegroup-config" in c)
        i_term = next(i for i, c in enumerate(calls) if "terminate-instance-in-auto-scaling-group" in c)
        self.assertLess(i_min, i_term)
        self.assertIn("minSize=2,maxSize=4,desiredSize=3", calls[i_min])
        self.assertIn("i-0abc", calls[i_term])
        self.assertIn("--should-decrement-desired-capacity", calls[i_term])
        self.assertEqual(env.load()["vars"]["kubernetes_node_count"], 2)

    def test_remove_refuses_the_last_node(self):
        env = self.env("aws", "k", CLUSTER)
        rc, calls, call, out = self.run_node(env, ["remove", "aws", "n1"], node={"spec": {"providerID": "aws:///a/i-1"}}, size=1, lo=1)
        self.assertEqual(rc, ("exit", 1))
        self.assertFalse(any("terminate-instance-in-auto-scaling-group" in c for c in calls))
        call.assert_not_called()   # not even drained

    def test_count_must_be_positive(self):
        for bad in ("-1", "0", "x"):
            self.assertEqual(exits(cli.build_parser().parse_args, ["node", "add", "--count", bad]), 2, bad)

    def test_the_pool_named_by_the_stack_output_wins(self):
        # aws#8 / gcp#10 outputs: EKS kubernetes_node_group_name, GKE kubernetes_node_pool ('default' for long names)
        self.assertEqual(cli._pick_pool(["default", "gpu"], "c1", "default"), "default")
        self.assertEqual(cli._pick_pool(["c1-default", "extra"], "c1", None), "c1-default")
        self.assertEqual(cli._pick_pool(["c1-default", "extra"], "c1", "gone"), "c1-default")   # stale output: discovery
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                cli._pick_pool(["default", "gpu"], "c1", None)


class LocalNodeTests(Fixture):
    def setUp(self):
        super().setUp()
        # the env name starts with "cp": the old `"-cp" in name` test took every worker of it for a control plane
        self.cp_env = self.env("vmware", "", {"kubernetes_control_plane_ips": ["10.0.0.20"], "kubernetes_worker_ips": ["10.0.0.40", "10.0.0.41"]},
                               name="cp" + self.tag, kubernetes_control_planes=1, kubernetes_workers=2)

    def run_remove(self, name, get_rc=0, drain_rc=0, backend_changed=False):
        env = self.cp_env
        a = cli.build_parser().parse_args(["node", "remove", "vmware", name, "--env", env.name, "--auto-approve"])
        get = subprocess.CompletedProcess([], get_rc, "{}", "" if get_rc == 0 else 'Error from server (NotFound): nodes "x" not found')
        tf = mock.MagicMock()
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), json.loads((env.dir / "outputs.json").read_text()))), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(platformmod, "ensure_tools"), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"), \
                mock.patch.object(cli.subprocess, "run", return_value=get), \
                mock.patch.object(cli.subprocess, "call", side_effect=lambda cmd, **kw: drain_rc if "drain" in cmd else 0) as call, \
                mock.patch.object(cli, "Terraform", return_value=tf), mock.patch.object(cli, "_render", return_value=backend_changed), \
                mock.patch.object(cli, "_cache_outputs", return_value={}), mock.patch.object(cli.audit, "refresh"), \
                mock.patch.object(cli, "_prepare_local_teardown"), \
                mock.patch.object(cli, "_plan_changes", side_effect=lambda t: [
                    {"address": f'module.stack.module.kubernetes[0].vmdesktop_vm.node["{name.rsplit("-", 1)[-1]}"]',
                     "type": "vmdesktop_vm", "mode": "managed", "actions": ["delete"]}]):
            rc, out, err = run_quiet(cli.cmd_node, a, {})
        return rc, call, tf, out + err

    def test_typo_aborts_before_anything(self):
        rc, call, tf, out = self.run_remove("nope", get_rc=1)
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("No node 'nope'", out)
        call.assert_not_called()
        tf.apply.assert_not_called()

    def test_only_control_plane_is_refused(self):
        rc, call, tf, out = self.run_remove(f"acme-{self.cp_env.name}-cp1")
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("only control plane", out)
        call.assert_not_called()

    def test_failed_drain_uncordons_and_changes_nothing(self):
        before = self.cp_env.load()["vars"]["kubernetes_workers"]
        rc, call, tf, out = self.run_remove(f"acme-{self.cp_env.name}-wk2", drain_rc=1)
        self.assertEqual(rc, ("exit", 1))
        self.assertTrue(any("uncordon" in c.args[0] for c in call.call_args_list))
        self.assertFalse(any(c.args[0][1:3] == ["delete", "node"] for c in call.call_args_list))
        tf.apply.assert_not_called()
        self.assertEqual(self.cp_env.load()["vars"]["kubernetes_workers"], before)

    def test_last_worker_is_planned_before_the_drain_and_applied_after(self):
        rc, call, tf, out = self.run_remove(f"acme-{self.cp_env.name}-wk2")
        self.assertEqual(rc, 0)
        tf.plan.assert_called_once()
        tf.apply.assert_called_once_with("tfplan")
        self.assertEqual(self.cp_env.load()["vars"]["kubernetes_workers"], 1)

    def test_last_vm_remove_migrates_a_changed_backend(self):
        # integration with cli-setup: _write_root reports a pending backend migration until it happened, so the
        # init before the plan must pass it on (a bare init fails with 'Backend configuration changed')
        rc, call, tf, out = self.run_remove(f"acme-{self.cp_env.name}-wk2", backend_changed=True)
        self.assertEqual(rc, 0)
        tf.init.assert_called_once_with(migrate=True)

    def test_env_named_cp_does_not_turn_workers_into_control_planes(self):
        # the env name contains "cp": the old `"-cp" in name` test took every worker for a control plane
        rc, call, tf, out = self.run_remove(f"acme-{self.cp_env.name}-wk1")
        self.assertEqual(rc, 0)
        self.assertNotIn("only control plane", out)
        self.assertEqual(self.cp_env.load()["vars"]["kubernetes_control_planes"], 1)


class LocalNodeAddRollbackTests(Fixture):
    def test_declined_add_restores_config_and_render(self):
        env = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]}, kubernetes_workers=2)
        rendered = []
        tf = mock.MagicMock()

        def declined(*a, **kw):
            raise ui.Abort("Nothing applied.", code=3)
        tf.plan.side_effect = tf.plan_for_apply.side_effect = declined   # core: the add shows plan_for_apply's plan
        a = cli.build_parser().parse_args(["node", "add", "vmware", "--env", env.name])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), {})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"), mock.patch.object(cli, "_prepare_local_vms"), \
                mock.patch.object(cli, "_render", side_effect=lambda c, e, cfg: rendered.append(cfg["vars"]["kubernetes_workers"])), \
                mock.patch.object(cli, "Terraform", return_value=tf):
            rc, _, _ = run_quiet(cli.cmd_node, a, {})
        self.assertEqual(rc, ("exit", 3))
        self.assertEqual(rendered, [3, 2])   # rendered with the new count, then back to the old one
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 2)


class ChangeUndoFinishTests(Fixture):
    def test_namespace_created_without_velero_is_removed_by_undo(self):
        env = self.env("vmware", "lab")
        ctx = SimpleNamespace(procenv=lambda: {})
        now = subprocess.CompletedProcess([], 0, "default shop", "")
        with mock.patch.object(cli.subprocess, "run", return_value=now), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"):
            cli._finish_change_undo(("info", {"advice": "x"}, {"minor": True, "ns_before": {"default"}}), 0, "kubectl", "create ns shop",
                                    clouds.get("vmware"), env, ctx)
        e = undo.latest(env.id)
        self.assertEqual(e["kind"], "argv-seq")
        self.assertNotIn("minor", e)
        self.assertEqual(e["data"]["argvs"][0], ["kubectl", "vmware", "--env", env.name, "delete", "ns", "shop", "--ignore-not-found"])

    def test_failed_change_keeps_its_safety_backup(self):
        # ops#7 (wave 3): a failed kubectl call may have changed objects before it failed; its undo point stays
        env = self.env("vmware", "lab")
        with mock.patch.object(cli.dr, "_velero") as velero:
            cli._finish_change_undo(("velero-restore", {"backup": "pre-1"}, {"backup": "pre-1"}), 1, "kubectl", "delete ns x",
                                    clouds.get("vmware"), env, SimpleNamespace())
        velero.assert_not_called()
        e = undo.latest(env.id)
        self.assertEqual((e["kind"], e["data"]["backup"]), ("velero-restore", "pre-1"))
        self.assertIn("(failed part-way)", e["summary"])


class PrereqRollbackTests(Fixture):
    def test_failed_prereq_apply_restores_the_render(self):
        env = self.env("aws", "p", CLUSTER, enable_kubernetes=True)
        cloud = clouds.get("aws")
        cfg = env.load()
        tf = mock.MagicMock()
        tf.plan.side_effect = tf.plan_for_apply.side_effect = RuntimeError("no credentials")   # core: plan_for_apply
        with mock.patch.object(cli, "Terraform", return_value=tf):
            with self.assertRaises(RuntimeError):
                run_quiet(cli._apply_prereqs, cloud, env, cfg, ["velero"], True)
        rendered = json.loads((env.stack_dir / "main.tf.json").read_text())
        self.assertEqual(rendered["module"]["stack"]["platform_prereqs"], [])
        self.assertNotIn("platform_prereqs", cfg)

    def test_pending_remote_backend_is_created_first_and_kept_on_rollback(self):
        # integration with cli-setup: like cmd_apply, the prereq apply never goes into a stray local state of a
        # 'remote' env whose storage was never created
        env = self.env("aws", "rb", CLUSTER, enable_kubernetes=True)
        cfg = env.load()
        cfg["state"] = {"type": "remote", "backend": None}
        env.save(cfg)
        backend = {"s3": {"bucket": "b", "key": "k", "region": "us-east-1"}}
        tf = mock.MagicMock()
        tf.plan.side_effect = tf.plan_for_apply.side_effect = RuntimeError("no credentials")
        with mock.patch.object(cli, "_bootstrap_state", return_value=backend) as boot, \
                mock.patch.object(cli, "_render", return_value=False), mock.patch.object(cli, "Terraform", return_value=tf):
            with self.assertRaises(RuntimeError):
                run_quiet(cli._apply_prereqs, clouds.get("aws"), env, cfg, ["velero"], True)
        boot.assert_called_once()
        self.assertEqual(cfg["state"]["backend"], backend)            # the created storage survives the rollback
        self.assertEqual(env.load()["state"]["backend"], backend)
        self.assertNotIn("platform_prereqs", cfg)


# ---------------------------------------------------------------- platform (platform-catalog#24, platform-logic#10, #31, e2e#9)

class PlatformCliTests(Fixture):
    def pargs(self, argv):
        a = cli.build_parser().parse_args(["platform"] + argv)
        return a

    def test_catalog_browsing_survives_a_cluster_without_credentials(self):
        env = self.env("aws", "k", CLUSTER)

        def no_creds(*a):
            raise ui.Abort("Could not fetch the kubeconfig: NoCredentials")
        with mock.patch.object(services, "ensure_kubeconfig", side_effect=no_creds):
            rc, out, err = run_quiet(cli.cmd_platform, self.pargs(["info", "keda", "aws", "--env", env.name]), {})
            self.assertEqual(rc, 0)
            self.assertIn("platform item · keda", out)
            self.assertIn("Install state unknown", err)
            self.assertNotIn("✖", err)
            with mock.patch.object(platformmod, "status") as status:
                rc, _, _ = run_quiet(cli.cmd_platform, self.pargs(["list", "aws", "--env", env.name]), {})
            self.assertEqual(rc, 0)
            self.assertTrue(status.call_args[1]["unknown"])

    def test_current_env_without_cluster_still_browses_offline(self):
        cur = self.env("aws", "a")
        with mock.patch.object(platformmod, "status") as status:
            rc, _, _ = run_quiet(cli.cmd_platform, self.pargs(["list"]), {"current_env": cur.id})
        self.assertEqual(rc, 0)
        self.assertIsNone(status.call_args[0][0])
        self.assertFalse(status.call_args[1]["unknown"])
        rc, out, _ = run_quiet(cli.cmd_platform, self.pargs(["plan", "keda"]), {"current_env": cur.id})
        self.assertEqual(rc, 0)
        self.assertIn(f"Plan for {cur.id}", out)

    def test_offline_plan_creates_nothing(self):
        before = set(os.listdir(paths.ENVS_DIR)) if paths.ENVS_DIR.exists() else set()
        rc, out, _ = run_quiet(cli.cmd_platform, self.pargs(["plan", "metrics-server", "azure"]), {})
        self.assertEqual(rc, 0)
        self.assertEqual(set(os.listdir(paths.ENVS_DIR)) if paths.ENVS_DIR.exists() else set(), before)

    def test_usage_did_you_mean_and_mode(self):
        rc, _, err = run_quiet(cli.cmd_platform, self.pargs(["uninstall", "vmware", "--env", "lab"]), {})
        self.assertIn("cs platform uninstall <group|item", err)
        rc, _, err = run_quiet(cli.cmd_platform, self.pargs(["install", "kedaa"]), {})
        self.assertIn("did you mean keda", err)
        rc, _, err = run_quiet(cli.cmd_platform, self.pargs(["plan", "istio", "--set", "mode=sidcar"]), {})
        self.assertIn("Unknown mode 'sidcar'", err)
        rc, _, err = run_quiet(cli.cmd_platform, self.pargs(["plan", "keda", "--env", "../../x"]), {})
        self.assertIn("Invalid environment name", err)

    def test_items_after_options_are_items(self):
        seen = {}
        with mock.patch.dict(cli.HANDLERS, {"platform": lambda a, s: seen.setdefault("items", a.items) and 0}):
            rc, _, _ = run_quiet(cli._dispatch, ["platform", "plan", "vmware", "--env", "lab", "goldilocks"])
        self.assertEqual(seen["items"], ["vmware", "goldilocks"])
        rc, _, err = run_quiet(cli._dispatch, ["status", "aws", "extra"])
        self.assertEqual(rc, 2)

    def test_template_listing_and_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "repo"
            (root / "templates" / "gitlab-ci").mkdir(parents=True)
            (root / "templates" / "gitlab-ci" / ".gitlab-ci.yml").write_text("x: 1\n")
            (root / "templates" / ".DS_Store").write_text("junk")
            work = Path(td) / "work"
            work.mkdir()
            cwd = os.getcwd()
            os.chdir(work)
            try:
                with mock.patch.object(paths, "REPO_ROOT", root):
                    _, _, err = run_quiet(cli.cmd_platform, self.pargs(["template", "nope"]), {})
                    self.assertIn("Available: gitlab-ci", err)
                    self.assertNotIn(".DS_Store", err)
                    _, _, err = run_quiet(cli.cmd_platform, self.pargs(["template", "../templates"]), {})
                    self.assertIn("Unknown template", err)
                    run_quiet(cli.cmd_platform, self.pargs(["template", "gitlab-ci"]), {})
                    self.assertTrue((work / ".gitlab-ci.yml").exists())
                    _, _, err = run_quiet(cli.cmd_platform, self.pargs(["template", "gitlab-ci"]), {})
                    self.assertIn("kept", err)
            finally:
                os.chdir(cwd)
                for e in undo.entries(undo.GLOBAL):
                    if e["summary"] == "platform template gitlab-ci in work":
                        undo.pop(e)

    def test_missing_local_kubeconfig_points_at_provisioning(self):
        env = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        _, _, err = run_quiet(services.ensure_kubeconfig, clouds.get("vmware"), env, env.load(), {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        self.assertIn("--host k8s", err)


def rel(ns, name, rev, chart="x-1.0.0"):
    return {f"{ns}/{name}": {"name": name, "namespace": ns, "revision": str(rev), "chart": chart, "status": "deployed"}}


class PlatformUndoJournalTests(Fixture):
    def ctx(self, env):
        return SimpleNamespace(env=env, target="vmware", distro="rke2", procenv=lambda: {})

    def test_existing_dependency_is_never_journaled(self):
        env = self.env("vmware", "lab")
        before = rel("vpa", "vpa", 1)
        after = {**before, **rel("goldilocks", "goldilocks", 1)}
        steps = [{"item": "goldilocks", "ns": "goldilocks", "release": "goldilocks", "prev_revision": None, "existed": False}]
        with mock.patch.object(platformmod, "installed_releases", return_value=after):
            run_quiet(cli._journal_install, env, self.ctx(env), steps, False)
        e = undo.latest(env.id)
        self.assertEqual(e["data"]["items"], ["goldilocks"])
        self.assertIn("uninstall platform item(s): goldilocks", undo.describe(e))

    def test_upgrade_is_rolled_back_not_uninstalled(self):
        env = self.env("vmware", "lab")
        steps = [{"item": "keda", "ns": "keda", "release": "keda", "prev_revision": 1, "existed": True}]
        with mock.patch.object(platformmod, "installed_releases", return_value=rel("keda", "keda", 2)):
            run_quiet(cli._journal_install, env, self.ctx(env), steps, False)
        e = undo.latest(env.id)
        self.assertEqual(e["data"]["steps"], [{"item": "keda", "ns": "keda", "release": "keda", "prev_revision": 1}])
        with mock.patch.object(undo, "_cluster", return_value=(None, env, {}, {}, self.ctx(env))), \
                mock.patch.object(platformmod, "_run") as run, mock.patch.object(platformmod, "uninstall") as uninstall, \
                mock.patch.object(cli.deps, "find", return_value="/bin/helm"):
            run_quiet(undo.perform, e, {}, True)
        self.assertEqual(run.call_args[0][0], ["/bin/helm", "rollback", "keda", "1", "-n", "keda"])
        uninstall.assert_not_called()

    def test_partial_install_leaves_an_undo_point(self):
        env = self.env("vmware", "lab")
        steps = [{"item": "cert-manager", "ns": "cert-manager", "release": "cert-manager", "prev_revision": None, "existed": False},
                 {"item": "metallb", "ns": "metallb-system", "release": "metallb", "prev_revision": None, "existed": False},
                 {"item": "envoy-gateway", "ns": "envoy-gateway-system", "release": "eg", "prev_revision": None, "existed": False}]
        with mock.patch.object(platformmod, "installed_releases", return_value=rel("cert-manager", "cert-manager", 1)):
            run_quiet(cli._journal_install, env, self.ctx(env), steps, True)
        e = undo.latest(env.id)
        self.assertEqual(e["data"]["items"], ["cert-manager"])
        self.assertIn("stopped part-way", e["summary"])

    def test_install_journals_through_a_failure(self):
        env = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        a = cli.build_parser().parse_args(["platform", "install", "keda", "--cloud", "vmware", "--env", env.name])
        ctx = platformmod.Cluster(clouds.get("vmware"), env, env.load(), {}, env.dir / "kc")
        states = iter([{}, rel("keda", "keda", 1)])

        order = []

        def failing_install(*a, **kw):
            raise ui.Abort("helm timed out")

        def releases(c):
            order.append("releases")
            return next(states)
        with mock.patch.object(platformmod, "installed_releases", side_effect=releases), \
                mock.patch.object(platformmod, "ensure_tools", side_effect=lambda: order.append("tools")), \
                mock.patch.object(platformmod, "install", side_effect=failing_install):
            res, _, _ = run_quiet(cli._platform_install, a, clouds.get("vmware"), env, env.load(), env.dir / "kc", ctx, None)
        self.assertEqual(res, ("exit", 1))
        self.assertEqual(undo.latest(env.id)["data"]["items"], ["keda"])
        self.assertEqual(order[:2], ["tools", "releases"])   # helm is there before "what exists" is read

    def test_uninstall_records_only_what_was_removed_with_its_values(self):
        env = self.env("vmware", "lab", {"kubernetes_control_plane_ips": ["10.0.0.20"]})
        a = cli.build_parser().parse_args(["platform", "uninstall", "keda", "airflow", "--cloud", "vmware", "--env", env.name, "--auto-approve"])
        ctx = platformmod.Cluster(clouds.get("vmware"), env, env.load(), {}, env.dir / "kc")
        states = iter([rel("keda", "keda", 3, chart="keda-2.14.0"), {}])
        values = subprocess.CompletedProcess([], 0, json.dumps({"foo": "bar"}), "")
        with mock.patch.object(platformmod, "installed_releases", side_effect=lambda c: next(states)), \
                mock.patch.object(platformmod, "ensure_tools"), \
                mock.patch.object(platformmod, "uninstall", return_value=["keda", "airflow", "local-path-provisioner"]), \
                mock.patch.object(cli.deps, "find", return_value="/bin/helm"), mock.patch.object(cli.subprocess, "run", return_value=values):
            rc, _, _ = run_quiet(cli._platform_uninstall, a, env, ctx)
        e = undo.latest(env.id)
        self.assertEqual(e["data"]["items"], ["keda"])
        self.assertEqual(e["data"]["restore"]["keda"]["version"], "2.14.0")
        self.assertEqual(json.loads(Path(e["data"]["restore"]["keda"]["values"]).read_text()), {"foo": "bar"})
        with mock.patch.object(undo, "_cluster", return_value=(None, env, {}, {}, ctx)), \
                mock.patch.object(platformmod, "ensure_tools"), mock.patch.object(platformmod, "installed_releases", return_value={}), \
                mock.patch.object(platformmod, "install_one") as install_one:
            run_quiet(undo.perform, e, {}, True)
        self.assertEqual(install_one.call_args[0][:4], ("keda", ctx, True, "2.14.0"))
        self.assertEqual(install_one.call_args[1]["values_file"], e["data"]["restore"]["keda"]["values"])
        undo.clear(env.id)

    def test_exact_uninstall_never_resolves_dependencies(self):
        # the undo of an install removes exactly the items that run installed: uninstall never takes the dependencies
        # an item was resolved with (goldilocks needs vpa; vpa stays)
        env = self.env("vmware", "lab")
        ctx = platformmod.Cluster(clouds.get("vmware"), env, env.load(), {}, env.dir / "kc")
        calls = []

        def fake_run(cmd, c, check=True):
            calls.append(list(cmd))
            c.last_output = f'release "{cmd[2]}" uninstalled\n' if cmd[1:2] == ["uninstall"] else ""
            return 0

        rel = {"vpa/vpa": {"status": "deployed", "chart": "vpa-1"}, "goldilocks/goldilocks": {"status": "deployed", "chart": "g-1"}}
        with mock.patch.object(platformmod, "ensure_tools"), mock.patch.object(platformmod, "_run", side_effect=fake_run), \
                mock.patch.object(platformmod, "installed_releases", return_value=rel), \
                mock.patch.object(platformmod.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                mock.patch.object(platformmod.deps, "find", side_effect=lambda t: "/bin/" + t):
            removed, _, _ = run_quiet(platformmod.uninstall, ["goldilocks"], ctx)
        self.assertEqual(removed, ["goldilocks"])
        helm_calls = [c for c in calls if c[:2] == ["/bin/helm", "uninstall"]]
        self.assertEqual([c[2] for c in helm_calls], ["goldilocks"])


# ---------------------------------------------------------------- finops (ops#16, e2e#21)

class FinopsTests(Fixture):
    def fargs(self, argv):
        return cli.build_parser().parse_args(["finops"] + argv)

    def test_k8s_without_cluster_warns_exits_1_and_never_overwrites_latest(self):
        env = self.env("aws", "d")
        (env.dir / "finops").mkdir()
        (env.dir / "finops" / "latest.json").write_text('{"env": "real"}')
        rc, _, err = run_quiet(cli.cmd_finops, self.fargs(["k8s", "aws", "--env", env.name, "--save"]), {})
        self.assertEqual(rc, 1)
        self.assertIn("No Kubernetes cluster", err)
        self.assertEqual(json.loads((env.dir / "finops" / "latest.json").read_text()), {"env": "real"})

    def test_cloud_bill_of_a_local_env_is_an_answer(self):
        env = self.env("vmware", "d")
        with mock.patch.object(clouds.get("vmware").__class__, "prepare"):
            rc, out, _ = run_quiet(cli.cmd_finops, self.fargs(["cloud", "vmware", "--env", env.name]), {})
        self.assertEqual(rc, 0)
        self.assertIn("no cloud bill", out)

    def test_opencost_rows_are_formatted(self):
        env = self.env("aws", "k", CLUSTER)
        oc = {"rows": {"goldilocks": {"cpu": -0.0, "ram": -0.004, "pv": 0.0, "total": -0.0, "efficiency": 0},
                       "monitoring": {"cpu": 1.0, "ram": 2.0, "pv": 0.0, "total": 3.0, "efficiency": 519}}, "total": 3.0}
        with mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), mock.patch.object(cli.finops, "opencost", return_value=oc):
            rc, out, _ = run_quiet(cli.cmd_finops, self.fargs(["k8s", "aws", "--env", env.name]), {})
        self.assertEqual(rc, 0)
        self.assertNotIn("$-0.00", out)
        self.assertIn("eff 519%*", out)
        self.assertIn("uses more than it requests", out)
        with mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli.finops, "opencost", return_value={"error": "OpenCost is not installed: cs platform install finops"}):
            rc, _, _ = run_quiet(cli.cmd_finops, self.fargs(["k8s", "aws", "--env", env.name]), {})
        self.assertEqual(rc, 1)

    def test_money_and_days(self):
        self.assertEqual(cli._usd(-0.001), "$0.00")
        self.assertEqual(cli._usd(-1.5), "-$1.50")
        self.assertEqual(cli._usd(1234.5), "$1,234.50")
        for bad in ("-5", "0", "400"):
            self.assertEqual(exits(cli.build_parser().parse_args, ["finops", "cloud", "--days", bad]), 2, bad)


# ---------------------------------------------------------------- explain (ops#25, cli-ux#2, docs-skills#13)

class ExplainTests(unittest.TestCase):
    def explain(self, *words):
        a = SimpleNamespace(feature=words[0] if words else None, more=list(words[1:]))
        return run_quiet(cli.cmd_explain, a, {})

    def test_platform_group_and_item(self):
        rc, out, _ = self.explain("platform", "security")
        self.assertEqual(rc, 0)
        self.assertIn("group · security", out)
        self.assertNotEqual(out, self.explain("platform")[1])
        self.assertIn("platform item · istio", self.explain("platform", "istio")[1])
        rc, _, err = self.explain("platform", "nonsense-xyz")
        self.assertEqual(rc, ("exit", 1))

    def test_vmware_shows_feature_and_target(self):
        rc, out, _ = self.explain("vmware")
        self.assertIn("STACK VARIABLES FOR VMWARE", out)
        self.assertIn("also: cs explain topic vmware", out)
        self.assertIn("STACK VARIABLES FOR VMWARE", helpmod.page("vmware-skill", None))

    def test_explicit_namespaces_and_hints(self):
        self.assertIn("SECURITY MODEL", self.explain("topic", "security")[1])
        self.assertIn("also: cs explain topic security", self.explain("security")[1])
        self.assertIn("STACK VARIABLES FOR AWS", self.explain("variables", "aws")[1])
        rc, _, err = self.explain("topic", "nope")
        self.assertEqual(rc, ("exit", 1))


# ---------------------------------------------------------------- managed data platforms (platform-logic#33)

class ManagedProfileTests(Fixture):
    def test_default_profile_is_used_when_the_env_has_none(self):
        with mock.patch.object(cli.managed, "profile", side_effect=lambda s, n: {"host": "h"} if n == "default" else {}):
            name, note = cli._managed_profile("databricks", None, "vmware-lab")
            self.assertEqual(name, "default")
            self.assertIn("using the 'default' profile", note)
            self.assertEqual(cli._managed_profile("databricks", "x", "vmware-lab"), ("x", None))
        with mock.patch.object(cli.managed, "profile", return_value={"host": "h"}):
            self.assertEqual(cli._managed_profile("databricks", None, "vmware-lab"), ("vmware-lab", None))

    def test_profile_flag_after_the_subcommand_and_separators(self):
        self.assertEqual(cli._pull_profile_arg(["connect", "account=a", "--profile", "p"]), (["connect", "account=a"], "p"))
        self.assertEqual(cli._pull_profile_arg(["--", "clusters", "list", "--profile", "X"]), (["--", "clusters", "list", "--profile", "X"], None))
        a = SimpleNamespace(cmd="databricks", svc_args=["bundle", "run", "job", "--", "--param", "x"], profile="p")
        with mock.patch.object(cli.managed, "run", return_value=0) as run:
            run_quiet(cli.cmd_managed, a, {})
        self.assertEqual(run.call_args[0][2], ["bundle", "run", "job", "--", "--param", "x"])

    def test_connect_writes_the_current_env_profile_not_default(self):
        a = SimpleNamespace(cmd="snowflake", svc_args=["connect", "account=a"], profile=None)
        with mock.patch.object(cli.managed, "connect") as connect, mock.patch.object(cli.managed, "test", return_value=0):
            run_quiet(cli.cmd_managed, a, {"current_env": "vmware-lab"})
        self.assertEqual(connect.call_args[0][1], "vmware-lab")


# ---------------------------------------------------------------- review follow-ups

class ReviewFollowupTests(Fixture):
    def test_node_scale_needs_a_count_before_any_cluster_work(self):
        a = cli.build_parser().parse_args(["node", "scale", "aws", "--env", "k"])
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=AssertionError("resolved")):
            self.assertEqual(exits(cli.cmd_node, a, {}), 1)

    def test_docker_config_copy_is_private_even_when_it_existed(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "user"
            src.mkdir()
            (src / "config.json").write_text(json.dumps({"auths": {"ghcr.io": {"auth": "eDp5"}}}))
            (Path(td) / "cs").mkdir()
            target = Path(td) / "cs" / "config.json"
            target.write_text('{"auths": {}}\n')
            os.chmod(target, 0o644)   # written by an older cloudseed
            with mock.patch.dict(os.environ, {"DOCKER_CONFIG": str(src)}):
                platformmod._docker_config_without_missing_helpers(target, "")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertIn("ghcr.io", target.read_text())
            with mock.patch.dict(os.environ, {"DOCKER_CONFIG": str(target.parent)}):   # a child started with the filtered config
                platformmod._docker_config_without_missing_helpers(target, "")
            self.assertIn("ghcr.io", target.read_text())

    def test_catalog_browsing_survives_an_unreadable_config(self):
        # integration with core: env.load() raises ConfigError for a broken config.json; browsing still never aborts
        env = self.env("aws", "u", CLUSTER)
        env.config_path.write_text("{not json")
        ctx, problem = cli._catalog_ctx(SimpleNamespace(cloud="aws", env=env.name), {})
        self.assertIsNone(ctx)
        self.assertIn("config.json", problem)

    def test_catalog_browsing_never_installs_a_cloud_cli(self):
        env = self.env("gcp", "g", {"kubernetes_cluster_name": "g1", "kubernetes_location": "us-central1-a"}, project_id="p1")
        a = cli.build_parser().parse_args(["platform", "info", "keda", "gcp", "--env", env.name])
        with mock.patch.object(cli.deps, "find", return_value=None), \
                mock.patch.object(services, "ensure_kubeconfig", side_effect=AssertionError("would install gcloud")):
            rc, out, err = run_quiet(cli.cmd_platform, a, {})
        self.assertEqual(rc, 0)
        self.assertIn("gcloud is not installed", err)
        self.assertIn("platform item · keda", out)


if __name__ == "__main__":
    unittest.main()
