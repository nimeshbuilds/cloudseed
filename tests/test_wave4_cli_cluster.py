"""Round-4 regression tests for the cluster commands of cloudseed/cli.py: cs env, cs node, cs platform, cs chaos,
cs dr, cs scan and the kubectl/helm passthrough (cmd_ktool and its undo points)."""
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

from cloudseed import chaos, cli, clouds, managed, paths, platform as platformmod, scan, services, ui, undo  # noqa: E402

BASE_CFG = {"name": "acme", "owner": "me", "region": "local", "network_cidr": "10.100.0.0/24", "allowed_ssh_cidrs": ["203.0.113.7/32"],
            "ssh_public_key": "ssh-ed25519 AAAA test", "state": {"type": "local", "backend": None}, "tags": {},
            "vars": {"enable_kubernetes": True, "kubernetes_control_planes": 1, "kubernetes_workers": 2,
                     "base_disk": "/images/ubuntu.vmdk", "guest_os_id": "ubuntu-64"}, "extra_vars": {}}
CP_OUT = {"kubernetes_control_plane_ips": ["10.100.0.20"], "kubernetes_worker_ips": ["10.100.0.40", "10.100.0.41"]}


def run_quiet(fn, *a, **kw):
    """Call fn capturing stdout/stderr; returns (result or ("exit", code), out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            res = fn(*a, **kw)
        except SystemExit as e:
            if isinstance(e, ui.Abort):
                ui.show_abort(e)
            res = ("exit", e.code)
    return res, out.getvalue(), err.getvalue()


def proc(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


class Isolated(unittest.TestCase):
    """A private undo journal and settings file, and environments that only this test sees."""

    def setUp(self):
        self._ni = ui.NON_INTERACTIVE
        ui.NON_INTERACTIVE = True
        self.addCleanup(setattr, ui, "NON_INTERACTIVE", self._ni)
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4cc-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for target, attr, value in ((undo, "JOURNAL", self.tmp / "undo.json"), (undo, "LOCK", self.tmp / "undo.lock"),
                                    (paths, "SETTINGS_PATH", self.tmp / "settings.json")):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.tag = "v" + pysecrets.token_hex(3)
        self.envs: list[paths.Env] = []
        p = mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [paths.Env(e.cloud, e.name) for e in self.envs]))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(lambda: [shutil.rmtree(e.dir, ignore_errors=True) for e in self.envs])
        os.environ.pop("CLOUDSEED_UNDOING", None)

    def env(self, cloud: str = "vmware", suffix: str = "lab", outputs: dict | None = None, **vars_) -> paths.Env:
        env = paths.Env(cloud, f"{self.tag}{suffix}")
        cfg = copy.deepcopy(BASE_CFG)
        cfg.update(cloud=cloud, env=env.name)
        cfg["vars"].update(vars_)
        env.save(cfg)
        if outputs is not None:
            (env.dir / "outputs.json").write_text(json.dumps(outputs))
        self.envs.append(env)
        return env


# ---------------------------------------------------------------- cs kubectl|helm: selectors and echo (mcp#1, services)

class KubePassthroughTests(Isolated):
    def run_tool(self, argv, env):
        a = cli.build_parser().parse_args(argv)
        seen = {}

        def resolve(args, settings):
            seen["cloud"], seen["env"] = args.cloud, args.env
            return clouds.get("vmware"), env, env.load(), CP_OUT
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=resolve), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(services, "ensure_tool", return_value="/bin/" + a.cmd), \
                mock.patch.object(cli, "_pre_change_undo", return_value=None), \
                mock.patch.object(cli.subprocess, "call", return_value=0) as call:
            rc, out, err = run_quiet(cli.cmd_ktool, a, {})
        seen.update(rc=rc, err=err, argv=call.call_args[0][0][1:] if call.called else None, ns=a)
        return seen

    def test_words_after_an_explicit_separator_never_reselect_the_cluster(self):
        env = self.env()
        s = self.run_tool(["kubectl", "vmware", "--env", "prod", "--", "--env", "lab", "get", "pods"], env)
        self.assertTrue(s["ns"].tool_verbatim)
        self.assertEqual((s["cloud"], s["env"]), ("vmware", "prod"))
        self.assertEqual(s["argv"], ["--env", "lab", "get", "pods"])   # the tool's own words, verbatim
        s = self.run_tool(["kubectl", "--", "aws", "get", "pods"], env)
        self.assertIsNone(s["cloud"])
        self.assertEqual(s["argv"], ["aws", "get", "pods"])

    def test_selectors_without_a_separator_still_work(self):
        env = self.env()
        s = self.run_tool(["kubectl", "--env", "lab", "get", "pods"], env)
        self.assertFalse(s["ns"].tool_verbatim)
        self.assertEqual((s["env"], s["argv"]), ("lab", ["get", "pods"]))
        # a namespace built by hand (tests, older callers) has no tool_verbatim: the selectors are read again
        a = SimpleNamespace(cmd="kubectl", tool_args=["aws", "--env", "dev", "get", "pods"], cloud=None, env=None)
        seen = {}
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=lambda args, st: seen.update(c=args.cloud, e=args.env) or
                               (clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"), \
                mock.patch.object(cli, "_pre_change_undo", return_value=None), \
                mock.patch.object(cli.subprocess, "call", return_value=0):
            run_quiet(cli.cmd_ktool, a, {})
        self.assertEqual((seen["c"], seen["e"]), ("aws", "dev"))

    def test_echo_masks_by_tool(self):
        env = self.env()
        s = self.run_tool(["kubectl", "logs", "-p", "web-0"], env)
        self.assertIn("logs -p web-0", s["err"])                 # kubectl's -p is --previous: nothing secret
        s = self.run_tool(["helm", "registry", "login", "r.example.com", "-u", "me", "-p", "hunter2"], env)
        self.assertNotIn("hunter2", s["err"])                     # helm's -p is a password
        self.assertEqual(managed.mask_argv(["patch", "deploy", "w", "-p", "{}"], "kubectl")[-1], "{}")


class HelmPagingTests(unittest.TestCase):
    def test_every_page_is_read(self):
        ctx = SimpleNamespace(procenv=lambda: {})
        first = "\n".join(f"r{i}" for i in range(cli._HELM_PAGE))
        pages = iter([proc(0, first), proc(0, "x\ny\nz\n")])
        with mock.patch.object(cli.deps, "find", return_value="/bin/helm"), \
                mock.patch.object(cli.subprocess, "run", side_effect=lambda *a, **k: next(pages)) as run:
            got = cli._helm_releases_in(ctx, "demo")
        self.assertEqual(len(got), cli._HELM_PAGE + 3)
        second = run.call_args_list[1][0][0]
        self.assertEqual(second[second.index("--offset") + 1], str(cli._HELM_PAGE))
        self.assertIn("--max", second)
        self.assertNotIn("-a", second)

    def test_a_helm_that_ignores_the_offset_ends_the_loop(self):
        ctx = SimpleNamespace(procenv=lambda: {})
        page = "\n".join(f"r{i}" for i in range(cli._HELM_PAGE))
        with mock.patch.object(cli.deps, "find", return_value="/bin/helm"), \
                mock.patch.object(cli.subprocess, "run", return_value=proc(0, page)) as run:
            self.assertEqual(len(cli._helm_releases_in(ctx, "demo")), cli._HELM_PAGE)
        self.assertEqual(run.call_count, 2)
        with mock.patch.object(cli.deps, "find", return_value="/bin/helm"), \
                mock.patch.object(cli.subprocess, "run", side_effect=subprocess.TimeoutExpired("helm", 120)):
            self.assertIsNone(cli._helm_releases_in(ctx, "demo"))


# ---------------------------------------------------------------- undo points of kubectl/helm calls

class NodeLabelPartialTests(Isolated):
    def setUp(self):
        super().setUp()
        self.cloud = clouds.get("vmware")
        self.envx = self.env("vmware", "k", CP_OUT)
        self.ctx = SimpleNamespace(procenv=lambda: {})

    def nodes(self, **labels):
        """subprocess.run answering `kubectl get node N -o json` from `labels` (None: NotFound)."""
        def run(cmd, **kw):
            name = cmd[3]
            if labels.get(name) is None:
                return proc(1, "", f'Error from server (NotFound): nodes "{name}" not found')
            return proc(0, json.dumps({"metadata": {"labels": labels[name]}}))
        return mock.patch.object(cli.subprocess, "run", side_effect=run)

    def test_a_missing_node_leaves_the_inverse_of_the_others(self):
        with self.nodes(a={"team": "old"}, b=None), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"):
            kind, data, notes = cli._pre_change_undo("kubectl", ["label", "node", "a", "b", "team=new", "--overwrite"],
                                                     self.cloud, self.envx, {}, {}, None, ctx=self.ctx)
        self.assertEqual(kind, "argv-seq")
        self.assertEqual(data["argvs"], [["kubectl", "vmware", "--env", self.envx.name, "label", "node", "a", "team=old", "--overwrite"]])
        self.assertIn("node_values", notes)
        # the call failed on b; a was labelled: its inverse is kept
        with self.nodes(a={"team": "new"}), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"), \
                mock.patch.object(undo, "discard_velero_backup"):
            cli._finish_change_undo((kind, data, notes), 1, "kubectl", "label node a b team=new --overwrite", self.cloud, self.envx, self.ctx)
        e = undo.latest(self.envx.id)
        self.assertEqual(e["data"]["argvs"], data["argvs"])
        self.assertIn("(failed part-way)", e["summary"])

    def test_a_failed_call_that_changed_nothing_records_nothing(self):
        with self.nodes(a={"team": "old"}, b={}), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"):
            pre = cli._pre_change_undo("kubectl", ["label", "node", "a", "b", "team=new"], self.cloud, self.envx, {}, {}, None, ctx=self.ctx)
        self.assertEqual(len(pre[1]["argvs"]), 2)
        # refused on a (no --overwrite) and b stayed as it was: nothing to revert
        with self.nodes(a={"team": "old"}, b={}), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"), \
                mock.patch.object(undo, "discard_velero_backup"):
            cli._finish_change_undo(pre, 1, "kubectl", "label node a b team=new", self.cloud, self.envx, self.ctx)
        self.assertEqual(undo.entries(self.envx.id), [])
        # ... but b did get the label: only b's inverse
        with self.nodes(a={"team": "old"}, b={"team": "new"}), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"), \
                mock.patch.object(undo, "discard_velero_backup"):
            cli._finish_change_undo(pre, 1, "kubectl", "label node a b team=new", self.cloud, self.envx, self.ctx)
        argvs = undo.latest(self.envx.id)["data"]["argvs"]
        self.assertEqual([a[6] for a in argvs], ["b"])
        self.assertEqual(argvs[0][7], "team-")

    def test_every_node_missing_records_nothing(self):
        with self.nodes(), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"):
            self.assertIsNone(cli._pre_change_undo("kubectl", ["label", "node", "x", "t=1"], self.cloud, self.envx, {}, {}, None, ctx=self.ctx))


class ForeignClusterUndoTests(Isolated):
    def setUp(self):
        super().setUp()
        self.cloud = clouds.get("vmware")
        self.envx = SimpleNamespace(name="lab", id="vmware-lab")
        self.ctx = SimpleNamespace(procenv=lambda: {}, kubeconfig=self.tmp / "kc")

    def pre(self, tool, rest):
        with mock.patch.object(cli.subprocess, "run", return_value=proc(1, "", "")), \
                mock.patch.object(undo, "velero_pre_backup", return_value="pre-x") as vb, \
                mock.patch.object(cli.dr, "installed", return_value=True), \
                mock.patch.object(cli.deps, "find", return_value="/bin/x"):
            return cli._pre_change_undo(tool, rest, self.cloud, self.envx, {}, {}, self.tmp / "kc", ctx=self.ctx), vb

    def test_a_call_on_another_cluster_gets_no_automatic_undo(self):
        for tool, rest in (("kubectl", ["--kubeconfig", "/other/kc", "cordon", "n1"]),
                           ("kubectl", ["--server=https://10.9.9.9:6443", "-n", "shop", "delete", "pod", "x"]),
                           ("kubectl", ["-s", "https://x", "create", "ns", "shop"]),
                           ("helm", ["--kube-apiserver", "https://x", "install", "web", "./chart"]),
                           ("helm", ["--kubeconfig=/other/kc", "-n", "keda", "uninstall", "keda"])):
            (kind, data, notes), vb = self.pre(tool, rest)
            self.assertEqual(kind, "info", rest)
            self.assertIn("chose its cluster itself", data["advice"])
            self.assertTrue(notes["success_only"])
            vb.assert_not_called()   # never a backup of a cluster the call may not touch

    def test_the_environments_own_kubeconfig_and_contexts_keep_their_undo(self):
        (kind, _, _), vb = self.pre("kubectl", ["--kubeconfig", str(self.tmp / "kc"), "-n", "shop", "delete", "pod", "x"])
        self.assertEqual(kind, "velero-restore")
        (kind, _, _), vb = self.pre("kubectl", ["--context", "c1", "-n", "shop", "delete", "pod", "x"])
        self.assertEqual(kind, "velero-restore")
        res, _ = self.pre("kubectl", ["--kubeconfig", "/other/kc", "get", "pods"])   # a read: nothing at all
        self.assertIsNone(res)

    def test_summaries_are_cut_at_a_word(self):
        env = self.env("vmware", "s", CP_OUT)
        shown = "rollout restart deployment web api worker scheduler frontend backend cache"
        with mock.patch.object(undo, "discard_velero_backup"):
            cli._finish_change_undo(("velero-restore", {"backup": "b", "new_namespaces": []}, {"backup": "b"}), 0,
                                    "kubectl", shown, self.cloud, env, self.ctx)
        summary = undo.latest(env.id)["summary"]
        self.assertTrue(summary.startswith("kubectl ") and summary.endswith("…"), summary)
        kept = summary[len("kubectl "):-1]
        self.assertTrue(shown.startswith(kept), summary)
        self.assertEqual(shown[len(kept)], " ")   # the next character of the command is a space: never cut mid-word


# ---------------------------------------------------------------- cs node

class PoolConfigTests(unittest.TestCase):
    def test_saved_count_is_never_zero(self):
        cfg = {"vars": {"kubernetes_node_min": 0}}
        cli._sync_pool_cfg(cfg, {"size": 0, "min": 0, "max": 5})
        self.assertEqual(cfg["vars"]["kubernetes_node_count"], 1)
        cli._sync_pool_cfg(cfg, {"size": 0, "min": 2, "max": 5})
        self.assertEqual(cfg["vars"]["kubernetes_node_count"], 2)
        cli._sync_pool_cfg(cfg, {"size": 4, "min": 1, "max": 5})
        self.assertEqual(cfg["vars"]["kubernetes_node_count"], 4)

    def test_scale_undo_of_an_empty_pool_parses(self):
        argv = cli._scale_undo(clouds.get("gcp"), SimpleNamespace(name="dev"), {"size": 0, "min": 0, "max": 3})
        a = cli.build_parser().parse_args(argv)
        self.assertEqual((a.count, a.min, a.max), (1, 0, 3))


class MetalLBPoolTests(unittest.TestCase):
    POOLS = {"items": [{"spec": {"addresses": ["10.100.0.100-10.100.0.127"]}}, {"spec": {"addresses": ["10.100.0.200/30"]}}]}

    def check(self, before, n, pools=None, rc=0, cp=False):
        cfg = {"network_cidr": "10.100.0.0/24"}
        out = json.dumps(self.POOLS if pools is None else pools)
        with mock.patch.object(cli.subprocess, "run", return_value=proc(rc, out, "" if rc == 0 else "no such resource")):
            return run_quiet(cli._check_node_addresses, cfg, cp, before, n, "/bin/kubectl", {})

    def test_ranges_and_cidrs_are_read(self):
        with mock.patch.object(cli.subprocess, "run", return_value=proc(0, json.dumps(self.POOLS))):
            got = cli._metallb_ranges("/bin/kubectl", {})
        self.assertEqual([t for t, _, _ in got], ["10.100.0.100-10.100.0.127", "10.100.0.200/30"])
        self.assertEqual(got[1][2] - got[1][1], 3)

    def test_a_worker_inside_the_pool_is_refused(self):
        rc, out, err = self.check(59, 2)   # wk60 = .99 fits, wk61 = .100 is the pool's first address
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("10.100.0.100", err)
        self.assertIn("At most 60 worker(s)", err)
        self.assertIn("add at most 1 (--count 1)", err)   # what the user can still do: the cluster has 59 already
        self.assertIn("Nothing was changed", err)

    def test_a_pool_reaching_below_the_workers_leaves_no_room(self):
        pools = {"items": [{"spec": {"addresses": ["10.100.0.30-10.100.0.60"]}}]}
        rc, _, err = self.check(2, 1, pools=pools)   # wk3 = .42 is inside a pool that starts below .40
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("No more workers fit below the pool (kubernetes_workers is 2)", err)
        self.assertNotIn("--count", err)

    def test_ipv6_pools_are_never_compared_with_the_ipv4_network(self):
        # ::a64:64 is the same integer as 10.100.0.100: an IPv6 pool must not refuse an IPv4 node
        pools = {"items": [{"spec": {"addresses": ["::a64:0/112", "fd00::/64"]}}]}
        with mock.patch.object(cli.subprocess, "run", return_value=proc(0, json.dumps(pools))):
            self.assertEqual(cli._metallb_ranges("/bin/kubectl", {}), [])
        self.assertIsNone(self.check(59, 5, pools=pools)[0])

    def test_below_the_pool_or_without_metallb_passes(self):
        self.assertIsNone(self.check(2, 3)[0])
        self.assertIsNone(self.check(70, 1, rc=1)[0])        # MetalLB not installed: no pool to hit
        self.assertIsNone(self.check(70, 1, pools={"items": []})[0])
        self.assertIsNone(self.check(1, 1, cp=True)[0])      # control planes live at .20+


class NodeRaceTests(Isolated):
    def test_a_change_before_the_lock_is_read_again(self):
        env = self.env("aws", "r", {"kubernetes_cluster_name": "c1"})
        a = cli.build_parser().parse_args(["node", "scale", "aws", "--env", env.name, "--count", "3", "--auto-approve"])
        stale, fresh = env.load(), env.load()
        fresh["vars"]["kubernetes_node_count"] = 7
        calls = iter([(clouds.get("aws"), env, stale, {"kubernetes_cluster_name": "c1"}),
                      (clouds.get("aws"), env, fresh, {"kubernetes_cluster_name": "c1"})])
        real_lock = paths.Env.lock

        @contextlib.contextmanager
        def racing_lock(self_, action="", wait=0.0):
            cfg = env.load()
            cfg["vars"]["kubernetes_node_count"] = 7   # another run finished just before this one got the lock
            env.save(cfg)
            with real_lock(self_, action, wait):
                yield self_
        seen = {}
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=lambda *x, **k: next(calls)) as res, \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"), \
                mock.patch.object(services, "cloud_cli_env", return_value={}), \
                mock.patch.object(paths.Env, "lock", racing_lock), \
                mock.patch.object(cli, "_node_managed", side_effect=lambda ar, c, e, cfg, *r: seen.update(cfg=cfg) or 0):
            rc, out, err = run_quiet(cli.cmd_node, a, {})
        self.assertEqual(rc, 0, err)
        self.assertEqual(res.call_count, 2)
        self.assertIs(seen["cfg"], fresh)
        self.assertIn("changed while this command started", out + err)

    def test_a_change_during_the_kubeconfig_fetch_is_read_again(self):
        # the stamp is taken as soon as the configuration was read: a write that lands while the kubeconfig is fetched
        # (or kubectl installed) is not mistaken for the state this run started from
        env = self.env("aws", "k", {"kubernetes_cluster_name": "c1"})
        a = cli.build_parser().parse_args(["node", "scale", "aws", "--env", env.name, "--count", "3", "--auto-approve"])
        fetches = []

        def fetch(*_a, **_k):
            if not fetches:
                cfg = env.load()
                cfg["vars"]["kubernetes_node_count"] = 9
                env.save(cfg)
            fetches.append(1)
            return env.dir / "kc"
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=lambda *x, **k: (clouds.get("aws"), env, env.load(), {})) as res, \
                mock.patch.object(services, "ensure_kubeconfig", side_effect=fetch), \
                mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"), \
                mock.patch.object(services, "cloud_cli_env", return_value={}), \
                mock.patch.object(cli, "_node_managed", side_effect=lambda ar, c, e, cfg, *r: 0 if cfg["vars"].get("kubernetes_node_count") == 9 else 5):
            rc, out, err = run_quiet(cli.cmd_node, a, {})
        self.assertEqual((rc, res.call_count), (0, 2), err)
        self.assertIn("changed while this command started", out + err)

    def test_no_change_resolves_once(self):
        env = self.env("aws", "q", {"kubernetes_cluster_name": "c1"})
        a = cli.build_parser().parse_args(["node", "scale", "aws", "--env", env.name, "--count", "3", "--auto-approve"])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("aws"), env, env.load(), {})) as res, \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"), \
                mock.patch.object(services, "cloud_cli_env", return_value={}), \
                mock.patch.object(cli, "_node_managed", return_value=0):
            rc, _, err = run_quiet(cli.cmd_node, a, {})
        self.assertEqual((rc, res.call_count), (0, 1), err)


# ---------------------------------------------------------------- cs env

class EnvCommandTests(Isolated):
    def env_cmd(self, cmd, id_=None, settings=None):
        settings = {} if settings is None else settings
        return run_quiet(cli.cmd_env, SimpleNamespace(env_cmd=cmd, id=id_), settings), settings

    def test_show_with_an_id_is_refused(self):
        e = self.env("aws", "p")
        (rc, _, err), _ = self.env_cmd("show", e.id)
        self.assertEqual(rc, ("exit", 2))
        self.assertIn(f"cs env use {e.id}", err)

    def test_clear_only_takes_the_current_environment(self):
        a, b = self.env("aws", "p"), self.env("aws", "q")
        with mock.patch.object(paths, "save_settings"):
            (rc, _, err), st = self.env_cmd("clear", b.id, {"current_env": a.id})
        self.assertEqual(rc, ("exit", 2))
        self.assertIn(f"{b.id} is not the current environment", err)
        self.assertEqual(st["current_env"], a.id)
        self.assertEqual(undo.entries(undo.GLOBAL), [])   # refused before the undo record
        with mock.patch.object(paths, "save_settings"):
            (rc, _, _), st = self.env_cmd("clear", a.id, {"current_env": a.id})
        self.assertEqual(rc, 0)
        self.assertNotIn("current_env", st)
        self.assertEqual(undo.latest(undo.GLOBAL)["summary"], "env clear")

    def test_clear_takes_the_current_environments_unique_name(self):
        a, b = self.env("aws", "p"), self.env("gcp", "q")
        with mock.patch.object(paths, "save_settings"):
            (rc, _, err), st = self.env_cmd("clear", a.name, {"current_env": a.id})
        self.assertEqual(rc, 0, err)
        self.assertNotIn("current_env", st)
        # a name the current environment shares with another one is not taken for it
        self.env("gcp", "p")
        with mock.patch.object(paths, "save_settings"):
            (rc, _, err), st = self.env_cmd("clear", a.name, {"current_env": a.id})
        self.assertEqual(rc, ("exit", 2))
        self.assertEqual(st["current_env"], a.id)
        # the name of another environment is refused as before
        with mock.patch.object(paths, "save_settings"):
            (rc, _, err), st = self.env_cmd("clear", b.name, {"current_env": a.id})
        self.assertEqual(rc, ("exit", 2))
        self.assertIn(f"{b.name} is not the current environment", err)
        self.assertEqual(st["current_env"], a.id)

    def test_use_takes_a_unique_name(self):
        e = self.env("aws", "p")
        with mock.patch.object(paths, "save_settings"):
            (rc, out, err), st = self.env_cmd("use", e.name)
        self.assertEqual(rc, 0, err)
        self.assertEqual(st["current_env"], e.id)
        self.assertEqual(undo.latest(undo.GLOBAL)["summary"], f"env use {e.id}")

    def test_use_of_an_ambiguous_name_or_a_typo(self):
        a, b = self.env("aws", "p"), self.env("gcp", "p")
        (rc, _, err), st = self.env_cmd("use", a.name)
        self.assertEqual(rc, ("exit", 2))
        self.assertIn(a.id, err)
        self.assertIn(b.id, err)
        self.assertNotIn("current_env", st)
        (rc, _, err), _ = self.env_cmd("use", a.id[:-1] + "x")
        self.assertEqual(rc, ("exit", 2))
        self.assertIn("did you mean", err)

    def test_a_vanished_current_environment_keeps_the_columns(self):
        self.env("aws", "p")
        (rc, out, _), _ = self.env_cmd("show", None, {"current_env": "aws-gone"})
        self.assertEqual(rc, 0)
        line = next(ln for ln in out.splitlines() if "aws-gone" in ln)
        self.assertIn("no longer exists", line)
        self.assertNotIn("current, but", out)


# ---------------------------------------------------------------- cs scan --host (resilience#14)

class ScanHostTests(Isolated):
    def test_a_host_typo_stops_before_the_environment_is_resolved(self):
        a = SimpleNamespace(scan_cmd="host", cloud=None, env=None, host=["bastoin"], profile=None, framework=None, last=10, cmd="scan")
        with mock.patch.object(cli, "_resolve_plain_env", side_effect=AssertionError("resolved")), \
                mock.patch.object(cli, "_resolve_cluster_env", side_effect=AssertionError("resolved")):
            rc, _, err = run_quiet(cli.cmd_scan, a, {})
        self.assertEqual(rc, ("exit", 2))
        self.assertIn("did you mean bastion", err)

    def run_all(self, host):
        env = self.env("aws", "s", {})
        a = SimpleNamespace(scan_cmd="all", cloud="aws", env=env.name, host=host, profile=None, framework=None, last=10, cmd="scan")
        with mock.patch.object(scan, "run_all", return_value=[]) as run_all:
            rc, _, err = run_quiet(cli.cmd_scan, a, {})
        return rc, run_all

    def test_named_hosts_are_explicit(self):
        _, run_all = self.run_all(["VPN, bastion"])
        self.assertEqual(run_all.call_args[0][5], ["vpn", "bastion"])
        self.assertTrue(run_all.call_args[1]["explicit_hosts"])
        _, run_all = self.run_all(None)
        self.assertEqual(run_all.call_args[0][5], list(scan.HOST_KINDS))
        self.assertFalse(run_all.call_args[1]["explicit_hosts"])


# ---------------------------------------------------------------- cs chaos / cs dr wording and implicit installs

class ApprovalWordingTests(Isolated):
    def test_chaos_target_without_a_terminal(self):
        env = self.env("vmware", "c", CP_OUT)
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "--target", "shop/api", "vmware", "--env", env.name, "-y"])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli, "_chaos_target_preview", return_value="shop/api"), \
                mock.patch.object(cli, "_ensure_chaos_mesh") as mesh, mock.patch.object(chaos, "run") as run:
            rc, out, err = run_quiet(cli.cmd_chaos, a, {})
        self.assertEqual(rc, ("exit", 3))
        self.assertIn("No fault injected into shop/api", err)
        self.assertIn("-y alone never approves", err)
        mesh.assert_not_called()
        run.assert_not_called()

    def test_dr_restore_without_a_terminal(self):
        env = self.env("vmware", "d", CP_OUT)
        a = cli.build_parser().parse_args(["dr", "restore", "b1", "vmware", "--env", env.name])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli.dr, "installed", return_value=True), \
                mock.patch.object(cli, "_restorable_backup", return_value={"status": {"phase": "Completed"}}), \
                mock.patch.object(undo, "velero_pre_backup") as pre, mock.patch.object(cli.dr, "restore") as restore:
            rc, out, err = run_quiet(cli.cmd_dr, a, {})
        self.assertEqual(rc, ("exit", 3))
        self.assertIn(f"Nothing restored into {env.id}", err)
        pre.assert_not_called()
        restore.assert_not_called()

    def test_declined_prompt_keeps_its_own_words(self):
        with mock.patch.object(ui, "interactive", return_value=True), mock.patch.object(ui, "confirm", return_value=False):
            rc, out, err = run_quiet(cli._approve_worded, "Go?", False, "Cancelled. No fault was injected.", "x")
        self.assertEqual(rc, ("exit", 0))
        self.assertIn("No fault was injected", out + err)

    def test_implicit_installs_print_no_platform_summary(self):
        env = self.env("vmware", "v", CP_OUT)
        a = cli.build_parser().parse_args(["dr", "backup", "b1", "vmware", "--env", env.name, "--auto-approve"])
        releases = iter([{}, {"velero/velero": {"revision": "1", "status": "deployed"}}])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli.dr, "installed", return_value=False), mock.patch.object(platformmod, "ensure_tools"), \
                mock.patch.object(platformmod, "installed_releases", side_effect=lambda c: next(releases)), \
                mock.patch.object(platformmod, "install", return_value=["velero"]) as install, \
                mock.patch.object(cli.dr, "backup", return_value="b1"):
            rc, _, err = run_quiet(cli.cmd_dr, a, {})
        self.assertEqual(rc, 0, err)
        self.assertIs(install.call_args[1]["summary"], False)
        ctx = SimpleNamespace(env=env)
        with mock.patch.object(platformmod, "ensure_tools"), mock.patch.object(chaos, "chaos_mesh_ready", return_value=False), \
                mock.patch.object(platformmod, "installed_releases", return_value={}), \
                mock.patch.object(cli, "_journaled_install") as journaled, mock.patch.object(chaos, "_kubectl"):
            run_quiet(cli._ensure_chaos_mesh, SimpleNamespace(auto_approve=True), env, ctx)
        self.assertIs(journaled.call_args[1]["summary"], False)


class RestoreStartedTests(unittest.TestCase):
    def test_the_restore_phase_is_read_from_its_status(self):
        names = iter([{"b1-restore-20260101000000"}])
        with mock.patch.object(cli, "_velero_names", side_effect=lambda c, k: next(names)), \
                mock.patch.object(cli.dr, "_status", return_value={"phase": "FailedValidation"}):
            self.assertFalse(cli._restore_started(None, "b1", set()))
        names = iter([{"b1-restore-20260101000000"}])
        with mock.patch.object(cli, "_velero_names", side_effect=lambda c, k: next(names)), \
                mock.patch.object(cli.dr, "_status", return_value={"phase": "Failed"}):
            self.assertTrue(cli._restore_started(None, "b1", set()))


# ---------------------------------------------------------------- cs platform uninstall journal

class PlatformUninstallJournalTests(Isolated):
    def test_probe_items_are_journaled_by_their_probe_and_the_mode_is_the_installed_one(self):
        env = self.env("vmware", "u", CP_OUT)
        a = cli.build_parser().parse_args(["platform", "uninstall", "istio", "--cloud", "vmware", "--env", env.name, "--auto-approve"])
        ctx = platformmod.Cluster(clouds.get("vmware"), env, env.load(), {}, env.dir / "kc")
        before = {"probe:istio": {"status": "present"}, "istio-system/istiod": {"revision": "1", "status": "deployed"},
                  "istio-system/istio-base": {"revision": "1", "status": "deployed"}}
        states = iter([before, {}])
        with mock.patch.object(platformmod, "ensure_tools"), \
                mock.patch.object(platformmod, "installed_releases", side_effect=lambda c: next(states)), \
                mock.patch.object(platformmod, "resolve", return_value=["istio-base", "istiod", "istio"]), \
                mock.patch.object(platformmod, "_installed_mode", return_value="ambient") as mode, \
                mock.patch.object(cli, "_platform_restore_info", return_value={}), \
                mock.patch.object(platformmod, "uninstall", return_value=["istio"]):
            rc, _, err = run_quiet(cli._platform_uninstall, a, env, ctx)
        self.assertEqual(rc, 0, err)
        e = undo.latest(env.id)
        self.assertIn("istio", e["data"]["items"])        # a meta item with a probe: gone when its probe is
        self.assertEqual(e["data"]["mode"], "ambient")    # a failed ztunnel still means ambient
        mode.assert_called()

    def test_no_git_method_is_left(self):
        self.assertFalse([k for k, v in platformmod.CATALOG.items() if v["method"] == "git"])
        without_probe = [k for k, v in platformmod.CATALOG.items() if v["method"] not in ("helm", "oci") and not v.get("probe")]
        self.assertEqual(without_probe, [])   # _is_present and the uninstall journal rely on a probe for these


if __name__ == "__main__":
    unittest.main()
