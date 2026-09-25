"""Wave-2 regression tests for the cluster-facing CLI (cli-cluster): env switches, node add/remove safety on vmware,
chaos --target checks, scan reports --last, kubectl/helm passthrough in agent sessions and the flag-aware undo points.
No network, no cloud, no cluster, no hypervisor: every external tool is mocked."""

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

from cloudseed import chaos, cli, clouds, paths, platform as platformmod, secrets, services, ui, undo  # noqa: E402

BASE_CFG = {"name": "acme", "owner": "me", "region": "local", "network_cidr": "10.100.0.0/24", "allowed_ssh_cidrs": ["203.0.113.7/32"],
            "ssh_public_key": "ssh-ed25519 AAAA test", "state": {"type": "local", "backend": None}, "tags": {},
            "vars": {"enable_kubernetes": True, "kubernetes_control_planes": 1, "kubernetes_workers": 2,
                     "base_disk": "/images/ubuntu.vmdk", "guest_os_id": "ubuntu-64"}, "extra_vars": {}}


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


class Isolated(unittest.TestCase):
    """A private undo journal and settings file, and environments that only this test sees."""

    def setUp(self):
        self._ni = ui.NON_INTERACTIVE
        ui.NON_INTERACTIVE = True
        self.addCleanup(setattr, ui, "NON_INTERACTIVE", self._ni)
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w2cc-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for target, attr, value in ((undo, "JOURNAL", self.tmp / "undo.json"), (undo, "LOCK", self.tmp / "undo.lock"),
                                    (paths, "SETTINGS_PATH", self.tmp / "settings.json")):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.tag = "w" + pysecrets.token_hex(3)
        self.envs: list[paths.Env] = []
        p = mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [paths.Env(e.cloud, e.name) for e in self.envs]))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(lambda: [shutil.rmtree(e.dir, ignore_errors=True) for e in self.envs])

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


# ---------------------------------------------------------------- cs env use / clear (webui-backend#17)

class EnvSwitchTests(Isolated):
    def use(self, env_id, settings):
        a = SimpleNamespace(env_cmd="use", id=env_id)
        return run_quiet(cli.cmd_env, a, settings)

    def test_noops_record_nothing(self):
        a = self.env("aws", "a")
        settings = {"current_env": a.id}
        rc, out, _ = self.use(a.id, settings)
        self.assertEqual(rc, 0)
        self.assertIn("unchanged", out)
        rc, out, _ = run_quiet(cli.cmd_env, SimpleNamespace(env_cmd="clear", id=None), {})
        self.assertEqual(rc, 0)
        self.assertIn("nothing to clear", out)
        self.assertEqual(undo.entries(undo.GLOBAL), [])

    def test_a_run_of_switches_takes_one_undo_slot_back_to_the_start(self):
        a, b, c = self.env("aws", "a"), self.env("aws", "b"), self.env("gcp", "c")
        settings = {"current_env": a.id}
        paths.save_settings(settings)
        self.use(b.id, settings)
        self.use(c.id, settings)
        run_quiet(cli.cmd_env, SimpleNamespace(env_cmd="clear", id=None), settings)
        entries = undo.entries(undo.GLOBAL)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["coalesce"], "current_env")
        self.assertEqual(entries[0]["summary"], "env clear")
        self.assertEqual(entries[0]["data"]["settings"].get("current_env"), a.id)   # undo goes back to before the run
        self.assertNotIn("current_env", paths.load_settings())


# ---------------------------------------------------------------- node add / remove on vmware (vmware#2, #9, #15, cli-lifecycle#37, ansible#35)

class LocalNodeAddTests(Isolated):
    def add(self, env, argv, changes=(), problems=None):
        a = cli.build_parser().parse_args(["node", "add", "vmware", "--env", env.name, *argv])
        tf = mock.MagicMock()
        tf.outputs.return_value = {}
        rendered = []
        cloud = clouds.get("vmware")
        patches = [mock.patch.object(cli, "_resolve_cluster_env", return_value=(cloud, env, env.load(), {})),
                   mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"),
                   mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"),
                   mock.patch.object(cli, "_prepare_local_vms"),
                   mock.patch.object(cli, "_render", side_effect=lambda c, e, cfg: rendered.append(dict(cfg["vars"])) or False),
                   mock.patch.object(cli, "Terraform", return_value=tf),
                   mock.patch.object(cli, "_plan_changes", return_value=None if changes is None else list(changes)),
                   mock.patch.object(cli, "_cache_outputs", return_value={}), mock.patch.object(cli.audit, "refresh"),
                   mock.patch.object(cli.prov, "provision_local_kubernetes")]
        if problems is not None:
            patches.append(mock.patch.object(type(cloud), "address_problems", return_value=problems))
        with contextlib.ExitStack() as stack:
            mocks = [stack.enter_context(p) for p in patches]
            rc, out, err = run_quiet(cli.cmd_node, a, {})
        return rc, out + err, tf, rendered, mocks[-1] if problems is None else mocks[-2]

    def test_address_plan_overflow_is_refused_before_anything_is_rendered(self):
        env = self.env()
        rc, out, tf, rendered, _ = self.add(env, ["--count", "3", "--auto-approve"],
                                            problems=["kubernetes_workers=5: at most 4 on 10.100.0.0/24"])
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("no room for 3 more worker(s)", out)
        self.assertIn("Nothing was changed", out)
        self.assertEqual(rendered, [])
        tf.plan_for_apply.assert_not_called()
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 2)

    def test_real_address_plan_rejects_workers_in_the_dhcp_pool(self):
        env = self.env()
        cfg = env.load()
        cfg["network_cidr"] = "10.100.0.0/26"   # 62 hosts: workers start at .40 and may not pass the last host
        env.save(cfg)
        rc, out, tf, rendered, _ = self.add(env, ["--count", "40", "--auto-approve"])
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("kubernetes_workers=42", out)
        self.assertEqual(rendered, [])

    def test_a_plan_that_replaces_a_vm_is_refused_and_rolled_back_even_with_auto_approve(self):
        env = self.env()
        changes = [{"address": 'module.stack.module.kubernetes[0].vmdesktop_vm.node["acme-lab-wk1"]', "type": "vmdesktop_vm",
                    "mode": "managed", "actions": ["delete", "create"]},
                   {"address": 'module.stack.module.kubernetes[0].vmdesktop_vm.node["acme-lab-wk3"]', "type": "vmdesktop_vm",
                    "mode": "managed", "actions": ["create"]}]
        rc, out, tf, rendered, prov_mock = self.add(env, ["--auto-approve"], changes=changes)
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("would delete or re-create", out)
        self.assertIn("wk1", out)
        tf.apply_reconciled.assert_not_called()
        prov_mock.assert_not_called()
        self.assertEqual([r["kubernetes_workers"] for r in rendered], [3, 2])   # rendered with the new count, then back
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 2)
        self.assertEqual(undo.entries(env.id), [])

    def test_an_unreadable_plan_is_not_applied_unreviewed(self):
        env = self.env()
        rc, out, tf, _, _ = self.add(env, ["--auto-approve"], changes=None)
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("Could not read the plan", out)
        tf.apply_reconciled.assert_not_called()

    def test_a_create_only_plan_is_applied_and_joins_just_the_new_node(self):
        env = self.env()
        changes = [{"address": 'vmdesktop_vm.node["acme-x-wk3"]', "type": "vmdesktop_vm", "mode": "managed", "actions": ["create"]},
                   {"address": "random_integer.mac", "type": "random_integer", "mode": "managed", "actions": ["create"]}]
        rc, out, tf, _, prov_mock = self.add(env, ["--auto-approve"], changes=changes)
        self.assertEqual(rc, 0, out)
        tf.apply_reconciled.assert_called_once()
        self.assertEqual(prov_mock.call_args[1]["limit"], [f"acme-{env.name}-wk3"])
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 3)


class LocalNodeRemoveTests(Isolated):
    OUT = {"kubernetes_control_plane_ips": ["10.100.0.20"], "kubernetes_worker_ips": ["10.100.0.40", "10.100.0.41"]}

    def remove(self, env, name):
        a = cli.build_parser().parse_args(["node", "remove", name, "vmware", "--env", env.name, "--auto-approve"])
        tf = mock.MagicMock()
        get = subprocess.CompletedProcess([], 0, "{}", "")
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), json.loads((env.dir / "outputs.json").read_text()))) as resolve, \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(platformmod, "ensure_tools"), mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"), \
                mock.patch.object(cli.subprocess, "run", return_value=get), mock.patch.object(cli.subprocess, "call", return_value=0), \
                mock.patch.object(cli, "Terraform", return_value=tf), mock.patch.object(cli, "_render", return_value=False), \
                mock.patch.object(cli, "_cache_outputs", return_value={}), mock.patch.object(cli.audit, "refresh"), \
                mock.patch.object(cli, "_prepare_local_teardown"), \
                mock.patch.object(cli, "_plan_changes", return_value=[
                    {"address": f'module.stack.module.kubernetes[0].vmdesktop_vm.node["{name.rsplit("-", 1)[-1]}"]',
                     "type": "vmdesktop_vm", "mode": "managed", "actions": ["delete"]}]), \
                mock.patch.object(cli.prov, "forget_host_key") as forget:
            rc, out, err = run_quiet(cli.cmd_node, a, {})
        return rc, out + err, tf, forget, resolve

    def test_removed_vm_forgets_its_host_key_and_skips_the_image(self):
        env = self.env(outputs=self.OUT)
        rc, out, tf, forget, resolve = self.remove(env, f"acme-{env.name}-wk2")
        self.assertEqual(rc, 0, out)
        tf.apply.assert_called_once_with("tfplan")
        forget.assert_called_once_with(env, "10.100.0.41")
        self.assertIs(resolve.call_args[1].get("vm_image"), False)
        self.assertNotIn("last worker", out)

    def test_a_node_that_keeps_its_vm_keeps_its_host_key(self):
        env = self.env(outputs=self.OUT)
        rc, out, tf, forget, _ = self.remove(env, f"acme-{env.name}-wk1")   # not the highest number: only drained
        self.assertEqual(rc, 0, out)
        tf.apply.assert_not_called()
        forget.assert_not_called()

    def test_last_worker_warns_and_points_at_provisioning(self):
        env = self.env(outputs={"kubernetes_control_plane_ips": ["10.100.0.20"], "kubernetes_worker_ips": ["10.100.0.40"]},
                       kubernetes_workers=1)
        rc, out, tf, forget, _ = self.remove(env, f"acme-{env.name}-wk1")
        self.assertEqual(rc, 0, out)
        self.assertIn("last worker", out)
        self.assertIn(f"cs provision vmware --env {env.name} --host k8s", out)
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 0)
        forget.assert_called_once_with(env, "10.100.0.40")

    def test_only_control_plane_is_still_refused(self):
        env = self.env(outputs=self.OUT)
        rc, out, tf, _, _ = self.remove(env, f"acme-{env.name}-cp1")
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("only control plane", out)
        tf.apply.assert_not_called()


class ResolveForRemoveTests(Isolated):
    """node remove loads a vmware env without the full prepare (which re-downloads a cleaned base image)."""

    def resolve(self, env, node_cmd, vm_image):
        cloud = clouds.get("vmware")
        a = SimpleNamespace(cmd="node", node_cmd=node_cmd, cloud="vmware", env=env.name)
        with mock.patch.object(type(cloud), "prepare") as prepare, \
                mock.patch.object(cli, "_prepare_local_teardown") as teardown, \
                mock.patch.object(cli, "_outputs_fresh", return_value={}):
            res = cli._resolve_cluster_env(a, {}, vm_image=vm_image)
        return res, prepare, teardown, a

    def test_remove_prepares_like_a_teardown(self):
        env = self.env(outputs={"kubernetes_control_plane_ips": ["10.100.0.20"]})
        (_, got, cfg, _), prepare, teardown, a = self.resolve(env, "remove", vm_image=False)
        self.assertEqual(got.id, env.id)
        self.assertTrue(prepare.call_args[1]["dry_run"])      # no image download, no vmnet/vmrest work in prepare
        teardown.assert_not_called()                          # (wave 3) vmrest only on the path that deletes a VM
        self.assertEqual(a.node_cmd, "remove")                # the caller's arguments are untouched
        self.assertEqual(cfg["vars"]["base_disk"], "/images/ubuntu.vmdk")   # the saved image path is kept

    def test_add_still_prepares_fully(self):
        env = self.env(outputs={"kubernetes_control_plane_ips": ["10.100.0.20"]})
        _, prepare, teardown, _ = self.resolve(env, "add", vm_image=True)
        self.assertFalse(prepare.call_args[1]["dry_run"])
        teardown.assert_not_called()


# ---------------------------------------------------------------- chaos (resilience#14)

class ChaosTargetTests(Isolated):
    def test_bad_target_fails_before_any_cluster_work(self):
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "--target", "Shop/API!", "--cloud", "vmware", "--env", "lab"])
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=AssertionError("resolved")):
            rc, out, err = run_quiet(cli.cmd_chaos, a, {})
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("Bad --target", out + err)

    def _preview(self, proc):
        with mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"), mock.patch.object(chaos, "_kubectl", return_value=proc) as k:
            res = run_quiet(cli._chaos_target_preview, SimpleNamespace(procenv=lambda: {}), "shop/api:http")
        return res, k

    def test_preview_shows_the_full_selector(self):
        dep = {"spec": {"selector": {"matchLabels": {"app.kubernetes.io/name": "nginx", "app.kubernetes.io/instance": "shop-api"},
                                     "matchExpressions": [{"key": "tier", "operator": "In", "values": ["web"]}]}}}
        (text, _, _), k = self._preview(subprocess.CompletedProcess([], 0, json.dumps(dep), ""))
        self.assertEqual(k.call_args[0][1:6], ("-n", "shop", "get", "deploy", "api"))
        self.assertEqual(text, "shop/api (pods in shop matching app.kubernetes.io/name=nginx,app.kubernetes.io/instance=shop-api,tier in (web))")

    def test_missing_deployment_aborts_before_chaos_mesh(self):
        (res, out, err), _ = self._preview(subprocess.CompletedProcess([], 1, "", 'Error from server (NotFound): deployments.apps "api" not found'))
        self.assertEqual(res, ("exit", 1))
        self.assertIn("Deployment shop/api not found", out + err)

    def test_unreachable_cluster_leaves_the_check_to_the_run(self):
        (text, _, _), _ = self._preview(subprocess.CompletedProcess([], 1, "", "Unable to connect to the server"))
        self.assertEqual(text, "shop/api")

    def test_approval_names_the_selected_pods(self):
        env = self.env(outputs={"kubernetes_control_plane_ips": ["10.100.0.20"]})
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "--target", "shop/api", "--cloud", "vmware", "--env", env.name])
        asked = []
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), {})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli, "_chaos_target_preview", return_value="shop/api (pods in shop matching app=api)"), \
                mock.patch.object(cli, "_approve", side_effect=lambda q, auto: asked.append(q)), mock.patch.object(cli, "_ensure_chaos_mesh"), \
                mock.patch.object(cli.chaos, "run", return_value=0) as run, mock.patch.object(cli.chaos, "last_report", return_value=None):
            rc, _, _ = run_quiet(cli.cmd_chaos, a, {})
        self.assertEqual(rc, 0)
        self.assertIn("pods in shop matching app=api", asked[0])
        run.assert_called_once()


# ---------------------------------------------------------------- scan reports --last (ops#40)

class ScanLastTests(Isolated):
    def test_last_must_be_positive(self):
        for bad in ("0", "-3"):     # refused by the parser now (type=_positive_int), before any environment is resolved
            with mock.patch.object(cli, "_resolve_plain_env", side_effect=AssertionError("resolved")):
                rc, out, err = run_quiet(cli.build_parser().parse_args, ["scan", "reports", "--last", bad])
            self.assertEqual(rc, ("exit", 2), bad)
            self.assertIn("--last: must be 1 or more", out + err)
        a = cli.build_parser().parse_args(["scan", "reports"])
        a.last = 0                  # a namespace built without the parser (the console, MCP) is still checked
        with mock.patch.object(cli, "_resolve_plain_env", side_effect=AssertionError("resolved")):
            rc, out, err = run_quiet(cli.cmd_scan, a, {})
        self.assertEqual(rc, ("exit", 2))
        self.assertIn("--last must be 1 or more", out + err)


# ---------------------------------------------------------------- kubectl / helm / k9s passthrough (agentic#10, platform-logic#4, cli-lifecycle#25)

class PassthroughTests(Isolated):
    def setUp(self):
        super().setUp()
        docker = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, docker, True)
        p = mock.patch.dict(os.environ, {"DOCKER_CONFIG": docker})
        p.start()
        self.addCleanup(p.stop)

    def ktool(self, argv, redact=False):
        env = self.env(outputs={"kubernetes_control_plane_ips": ["10.100.0.20"]})
        a = cli.build_parser().parse_args(argv)
        seen = {}

        def resolve(args, settings):
            seen["cloud"], seen["env"] = args.cloud, args.env
            return clouds.get("vmware"), env, env.load(), {}
        environ = {"CLOUDSEED_REDACT": "1"} if redact else {}
        with mock.patch.dict(os.environ, environ), \
                mock.patch.object(cli, "_resolve_cluster_env", side_effect=resolve) as res, \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli.deps, "find", return_value="/bin/" + a.cmd), \
                mock.patch.object(cli, "_pre_change_undo", return_value=None), \
                mock.patch.object(cli.subprocess, "call", return_value=0) as call, \
                mock.patch.object(secrets, "run_redacted", return_value=0) as red:
            if not redact:
                os.environ.pop("CLOUDSEED_REDACT", None)
            rc, out, err = run_quiet(cli.cmd_ktool, a, {})
        seen.update(rc=rc, out=out, err=err, call=call, red=red, resolved=res.called)
        return seen

    def test_env_selectors_in_every_form(self):
        for argv in (["kubectl", "aws", "--env=dz", "get", "ns"], ["kubectl", "aws", "-edz", "get", "ns"],
                     ["kubectl", "aws", "-e", "dz", "get", "ns"], ["kubectl", "--env", "dz", "get", "ns"]):
            s = self.ktool(argv)
            self.assertEqual(s["env"], "dz", argv)
            self.assertEqual(s["call"].call_args[0][0][1:], ["get", "ns"], argv)

    def test_leading_flags_and_later_separators_reach_the_tool(self):
        s = self.ktool(["kubectl", "-n", "kube-system", "exec", "bb", "--", "sh", "-c", "ls -- x"])
        self.assertEqual(s["call"].call_args[0][0][1:], ["-n", "kube-system", "exec", "bb", "--", "sh", "-c", "ls -- x"])

    def test_echo_goes_to_stderr_without_styling_when_redirected(self):
        s = self.ktool(["kubectl", "get", "pods"])
        self.assertIn("$ kubectl get pods", s["err"])
        self.assertNotIn("\x1b[", s["err"])
        self.assertNotIn("$ kubectl", s["out"])

    def test_agent_sessions_run_the_tool_redacted(self):
        s = self.ktool(["kubectl", "get", "secret", "x", "-o", "yaml"], redact=True)
        self.assertEqual(s["rc"], 0)
        s["call"].assert_not_called()
        self.assertEqual(s["red"].call_args[0][0][1:], ["get", "secret", "x", "-o", "yaml"])
        self.assertIn("KUBECONFIG", s["red"].call_args[1]["env"])

    def test_agent_sessions_refuse_interactive_tools(self):
        for argv in (["k9s"], ["kubectl", "exec", "-it", "bb", "--", "sh"], ["kubectl", "edit", "deploy/x"],
                     ["kubectl", "run", "t", "--image=busybox", "--stdin", "--tty", "--", "sh"]):
            s = self.ktool(argv, redact=True)
            self.assertEqual(s["rc"], ("exit", 2), argv)
            self.assertIn("agent session", s["out"] + s["err"])
            self.assertFalse(s["resolved"], argv)
            s["red"].assert_not_called()
        s = self.ktool(["kubectl", "exec", "bb", "--", "cat", "/etc/hostname"], redact=True)   # no -i/-t: fine
        self.assertEqual(s["rc"], 0)

    def test_outside_agent_sessions_nothing_is_refused(self):
        s = self.ktool(["kubectl", "exec", "-it", "bb", "--", "sh"])
        self.assertEqual(s["rc"], 0)
        s["red"].assert_not_called()
        s["call"].assert_called_once()


# ---------------------------------------------------------------- undo points of kubectl / helm (ops#20, resilience#4, platform-logic#4)

class PreChangeUndoTests(unittest.TestCase):
    def setUp(self):
        self.cloud = clouds.get("vmware")
        self.env = SimpleNamespace(name="lab", id="vmware-lab")
        self.ctx = SimpleNamespace(procenv=lambda: {})

    def pre(self, tool, rest, backup="pre-x", velero_installed=False):
        none = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(cli.subprocess, "run", return_value=none), \
                mock.patch.object(undo, "velero_pre_backup", return_value=backup) as vb, \
                mock.patch.object(cli.dr, "installed", return_value=velero_installed), \
                mock.patch.object(cli.deps, "find", return_value="/bin/x"):
            res = cli._pre_change_undo(tool, rest, self.cloud, self.env, {}, {}, None, ctx=self.ctx)
        return res, vb

    def test_flag_values_are_never_the_verb(self):
        (kind, _, _), vb = self.pre("kubectl", ["-n", "shop", "delete", "pod", "x"])
        self.assertEqual(kind, "velero-restore")
        self.assertEqual(vb.call_args[0][2], ["shop"])
        (kind, _, _), vb = self.pre("kubectl", ["--context", "c1", "--namespace=shop", "scale", "deploy/web", "--replicas", "0"])
        self.assertEqual(vb.call_args[0][2], ["shop"])
        (kind, _, _), vb = self.pre("helm", ["-n", "keda", "uninstall", "keda"])
        self.assertEqual((kind, vb.call_args[0][1:]), ("velero-restore", ("helm", ["keda"])))
        (kind, data, _), _ = self.pre("helm", ["--kube-context", "c", "install", "-n", "shop", "front", "./chart"])
        self.assertEqual((kind, data), ("helm", {"release": "front", "ns": "shop"}))

    def test_namespace_deletes_back_up_those_namespaces(self):
        _, vb = self.pre("kubectl", ["delete", "namespace", "shop", "cart"])
        self.assertEqual(vb.call_args[0][2], ["cart", "shop"])
        _, vb = self.pre("kubectl", ["delete", "crd", "widgets.example.com"])
        self.assertIsNone(vb.call_args[0][2])

    def test_node_operations_record_their_inverse_not_a_backup(self):
        (kind, data, _), vb = self.pre("kubectl", ["drain", "node/n2", "--ignore-daemonsets", "--delete-emptydir-data"])
        self.assertEqual((kind, data["argvs"][0]), ("argv-seq", ["kubectl", "vmware", "--env", "lab", "uncordon", "n2"]))
        vb.assert_not_called()
        (kind, data, _), _ = self.pre("kubectl", ["uncordon", "n1"])
        self.assertEqual(data["argvs"][0][-2:], ["cordon", "n1"])

    def test_read_only_and_dry_runs_record_nothing(self):
        for tool, rest in (("kubectl", ["-n", "x", "get", "pods"]), ("kubectl", ["rollout", "status", "deploy/x"]),
                           ("kubectl", ["delete", "pod", "x", "--dry-run=client"]), ("helm", ["-n", "keda", "list"]),
                           ("helm", ["upgrade", "r", "c", "--dry-run"]), ("kubectl", ["exec", "bb", "--", "kubectl", "delete", "ns", "x"])):
            self.assertIsNone(self.pre(tool, rest)[0], rest)

    def test_failed_backup_with_velero_installed_says_so(self):
        (kind, data, notes), _ = self.pre("kubectl", ["delete", "pod", "x"], backup=None, velero_installed=True)
        self.assertEqual(kind, "info")
        self.assertIn("pre-change backup failed", data["advice"])
        self.assertNotIn("install Velero", data["advice"])
        self.assertTrue(notes["minor"])
        (kind, data, _), _ = self.pre("helm", ["uninstall", "r"], backup=None, velero_installed=False)
        self.assertIn("install Velero", data["advice"])

    def test_failed_change_keeps_its_backup(self):
        # (wave 3, ops#7) kubectl goes on through several objects before it fails: the undo point is kept and recorded
        with mock.patch.object(undo, "discard_velero_backup") as discard, \
                mock.patch.object(undo, "record", return_value={"data": {"backup": "pre-1"}}) as record:
            cli._finish_change_undo(("velero-restore", {"backup": "pre-1"}, {"backup": "pre-1"}), 1, "kubectl", "delete ns x",
                                    self.cloud, self.env, self.ctx)
        discard.assert_not_called()
        self.assertEqual(record.call_args[0][1:3], ("kubectl delete ns x (failed part-way)", "velero-restore"))


# ---------------------------------------------------------------- managed data platforms (platform-logic#4)

class ManagedEnvTests(Isolated):
    def test_only_a_leading_env_is_cloudseeds(self):
        env = self.env("vmware", "lab")
        a = SimpleNamespace(cmd="snowflake", svc_args=["--env", env.name, "sql", "-q", "select 1", "--env", "k=v"], profile=None, env=None)
        with mock.patch.object(cli.managed, "profile", return_value={"account": "a"}), \
                mock.patch.object(cli.managed, "run", return_value=0) as run:
            rc, _, _ = run_quiet(cli.cmd_managed, a, {})
        self.assertEqual(rc, 0)
        self.assertEqual(run.call_args[0][1], env.id)                                       # that environment's profile
        self.assertEqual(run.call_args[0][2], ["sql", "-q", "select 1", "--env", "k=v"])   # the CLI's own --env kept


if __name__ == "__main__":
    unittest.main()
