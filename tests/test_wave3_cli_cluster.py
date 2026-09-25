"""Wave-3 regression tests for the cluster-facing CLI (cli-cluster): no-cluster advice, node add/remove/scale safety and
undo, platform plan/list/ui, implicit Velero / Chaos Mesh installs, dr argument checks and restore undo points, chaos
reports without a cluster, scan undo entries, kubectl/helm undo points (failed calls, node metadata, created objects)
and explain. No network, no cloud, no cluster, no hypervisor: every external tool is mocked."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import secrets as pysecrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import chaos, cli, clouds, paths, platform as platformmod, scan, services, ui, undo  # noqa: E402

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
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w3cc-"))
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


# ---------------------------------------------------------------- no-cluster advice (platform-logic#17, #18)

class NoClusterAdviceTests(Isolated):
    def test_enabled_but_not_created_is_not_told_to_enable_again(self):
        cur = self.env("aws", "k", enable_kubernetes=True)
        _, problem, kind = cli._pick_cluster_env(None, None, {"current_env": cur.id})
        self.assertEqual(kind, "no-cluster")
        self.assertIn("enabled for", problem)
        self.assertIn("not created yet", problem)
        self.assertNotIn("--var enable_kubernetes=true", problem)
        off = self.env("aws", "p", enable_kubernetes="false")   # an older version saved the string: it is off
        _, problem, _ = cli._pick_cluster_env(None, off.name, {})
        self.assertIn("--var enable_kubernetes=true", problem)

    def test_cloud_alone_with_several_envs_without_cluster(self):
        a, b = self.env("aws", "k", enable_kubernetes=True), self.env("aws", "p", enable_kubernetes=False)
        env, problem, kind = cli._pick_cluster_env("aws", None, {})
        self.assertIsNone(env)
        self.assertEqual(kind, "no-cluster")
        self.assertIn(f"No aws environment has a Kubernetes cluster yet ({a.id}, {b.id})", problem)
        self.assertIn(f"cs setup aws --env {a.name}", problem)
        self.assertNotIn("aws-dev", problem)
        env, problem, _ = cli._pick_cluster_env("aws", None, {"current_env": b.id})   # cs env use is honoured
        self.assertEqual((env.id, problem), (b.id, None))

    def test_cloud_alone_with_one_env_leaves_it_to_the_usual_resolution(self):
        self.env("aws", "only")
        self.assertEqual(cli._pick_cluster_env("aws", None, {}), (None, None, ""))

    def test_resolution_reports_it_instead_of_aws_dev(self):
        self.env("aws", "k")
        self.env("aws", "p")
        a = SimpleNamespace(cloud="aws", env=None, cmd="kubectl")
        res, out, err = run_quiet(cli._resolve_cluster_env, a, {})
        self.assertEqual(res, ("exit", 1))
        self.assertIn("No aws environment has a Kubernetes cluster yet", err)
        self.assertNotIn("does not exist", err)

    def test_env_use_advice_follows_the_saved_setting(self):
        on, off = self.env("aws", "on", enable_kubernetes=True), self.env("aws", "off", enable_kubernetes=False)
        _, out, _ = run_quiet(cli.cmd_env, SimpleNamespace(env_cmd="use", id=on.id), {})
        self.assertIn("enabled but not created yet", out)
        self.assertNotIn("--var enable_kubernetes=true", out)
        _, out, _ = run_quiet(cli.cmd_env, SimpleNamespace(env_cmd="use", id=off.id), {})
        self.assertIn("--var enable_kubernetes=true", out)

    def test_finops_k8s_advice(self):
        env = self.env("aws", "f", enable_kubernetes=True)
        a = cli.build_parser().parse_args(["finops", "k8s", "aws", "--env", env.name])
        rc, out, err = run_quiet(cli.cmd_finops, a, {})
        self.assertEqual(rc, 1)
        self.assertIn("enabled for", err)
        self.assertNotIn("--var enable_kubernetes=true", err)


# ---------------------------------------------------------------- cs node (platform-logic#9, #21, #25, #26, vmware#6, ops#0)

class NodeHarness(Isolated):
    def node(self, env, argv, *, outputs=None, get_rc=0, plan=None, call_rc=0, kubeconfig=True, extra=(), order=None):
        """Run cs node with Terraform, kubectl and the hypervisor mocked. Returns a namespace of the mocks."""
        a = cli.build_parser().parse_args(["node", *argv, "--env", env.name])
        outputs = CP_OUT if outputs is None else outputs
        tf = mock.MagicMock()
        order = [] if order is None else order
        tf.plan.side_effect = lambda *a, **k: order.append("plan")
        get = proc(get_rc, "{}", "" if get_rc == 0 else 'Error from server (NotFound): nodes "x" not found')
        calls = []

        def call(cmd, **kw):
            calls.append(list(cmd))
            return call_rc if "drain" in cmd else 0
        kc = (lambda *a, **k: env.dir / "kc") if kubeconfig else services.ensure_kubeconfig
        with contextlib.ExitStack() as st:
            m = SimpleNamespace(tf=tf, calls=calls)
            m.resolve = st.enter_context(mock.patch.object(cli, "_resolve_cluster_env",
                                                           return_value=(clouds.get(env.cloud), env, env.load(), outputs)))
            st.enter_context(mock.patch.object(services, "ensure_kubeconfig", side_effect=kc))
            m.tool = st.enter_context(mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"))
            m.tools = st.enter_context(mock.patch.object(platformmod, "ensure_tools"))
            st.enter_context(mock.patch.object(cli.subprocess, "run", return_value=get))
            st.enter_context(mock.patch.object(cli.subprocess, "call", side_effect=call))
            st.enter_context(mock.patch.object(cli, "Terraform", return_value=tf))
            m.render = st.enter_context(mock.patch.object(cli, "_render", return_value=False))
            st.enter_context(mock.patch.object(cli, "_cache_outputs", return_value=outputs))
            st.enter_context(mock.patch.object(cli.audit, "refresh"))
            m.teardown = st.enter_context(mock.patch.object(cli, "_prepare_local_teardown", side_effect=lambda: order.append("vmrest")))
            m.prepare = st.enter_context(mock.patch.object(cli, "_prepare_local_vms"))
            m.plan_changes = st.enter_context(mock.patch.object(cli, "_plan_changes", return_value=plan))
            m.prov = st.enter_context(mock.patch.object(cli.prov, "provision_local_kubernetes"))
            st.enter_context(mock.patch.object(cli.prov, "forget_host_key"))
            m.host = st.enter_context(mock.patch.object(cli.prov, "Host"))
            for p in extra:
                st.enter_context(p)
            m.rc, out, err = run_quiet(cli.cmd_node, a, {})
        m.out = out + err
        return m


def vm(key, actions=("delete",), kind="node"):
    if kind == "mac":
        return {"address": f'module.stack.module.kubernetes[0].random_integer.mac["{key}"]', "type": "random_integer",
                "mode": "managed", "actions": list(actions)}
    return {"address": f'module.stack.module.kubernetes[0].vmdesktop_vm.node["{key}"]', "type": "vmdesktop_vm",
            "mode": "managed", "actions": list(actions)}


class NodeClusterCheckTests(NodeHarness):
    def test_add_on_an_env_without_cluster_is_refused_before_any_vm_work(self):
        env = self.env(enable_kubernetes=False)
        m = self.node(env, ["add", "vmware", "--auto-approve"], outputs={}, kubeconfig=False)
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn("No cluster yet", m.out)
        m.prepare.assert_not_called()
        m.render.assert_not_called()
        m.tf.plan_for_apply.assert_not_called()
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 2)
        self.assertEqual(undo.entries(env.id), [])
        self.assertIs(m.resolve.call_args[1].get("vm_image"), False)   # loaded without hypervisor work

    def test_enabled_but_never_created(self):
        env = self.env(enable_kubernetes=True)
        m = self.node(env, ["add", "vmware", "--auto-approve"], outputs={}, kubeconfig=False)
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn("not created yet", m.out)

    def test_node_commands_need_kubectl_not_helm(self):
        env = self.env()
        m = self.node(env, ["list", "vmware"])
        self.assertEqual(m.rc, 0)
        m.tools.assert_not_called()
        self.assertEqual(m.tool.call_args[0], ("kubectl", "to manage the cluster's nodes"))


class LocalNodeAddUndoTests(NodeHarness):
    def test_undo_of_an_add_removes_the_nodes_the_careful_way(self):
        env = self.env()
        m = self.node(env, ["add", "vmware", "--count", "2", "--auto-approve"], plan=[vm("wk3", ("create",)), vm("wk4", ("create",))])
        self.assertEqual(m.rc, 0, m.out)
        m.prepare.assert_called_once()
        e = undo.latest(env.id)
        self.assertEqual(e["kind"], "argv-seq")
        names = [a[2] for a in e["data"]["argvs"]]
        self.assertEqual(names, [f"acme-{env.name}-wk4", f"acme-{env.name}-wk3"])   # highest number first
        self.assertEqual(e["data"]["argvs"][0][:2], ["node", "remove"])
        self.assertIn("--auto-approve", e["data"]["argvs"][0])
        self.assertTrue(cli.build_parser().parse_args(e["data"]["argvs"][0]).auto_approve)

    def test_a_failed_join_still_leaves_the_undo(self):
        env = self.env()
        m = self.node(env, ["add", "vmware", "--auto-approve"], plan=[vm("wk3", ("create",))],
                      extra=[mock.patch.object(cli.prov, "provision_local_kubernetes", side_effect=ui.Abort("join failed"))])
        self.assertEqual(m.rc, ("exit", 1))
        self.assertEqual(undo.latest(env.id)["kind"], "argv-seq")

    def test_add_keeps_the_clusters_no_harden_choice(self):
        env = self.env()
        cfg = env.load()
        cfg["provisioned"] = {"bastion": {"harden": False, "firewall": True, "tools": True}}
        env.save(cfg)
        m = self.node(env, ["add", "vmware", "--auto-approve"], plan=[vm("wk3", ("create",))])
        self.assertEqual(m.rc, 0, m.out)
        self.assertIs(m.prov.call_args[1]["harden"], False)
        self.assertIn("without OS hardening", m.out)
        self.assertTrue(cli._saved_harden({}))
        self.assertFalse(cli._saved_harden({"provisioned": {"kubernetes": {"harden": False}, "bastion": {"harden": True}}}))


class LocalNodeRemoveTests(NodeHarness):
    def test_pending_changes_that_replace_other_vms_are_refused_even_with_auto_approve(self):
        env = self.env(outputs=CP_OUT)
        plan = [vm("wk2"), vm("wk2-0", kind="mac"),
                {"address": "module.stack.module.bastion.vmdesktop_vm.bastion", "type": "vmdesktop_vm", "mode": "managed",
                 "actions": ["delete", "create"]}]
        m = self.node(env, ["remove", f"acme-{env.name}-wk2", "vmware", "--auto-approve"], plan=plan)
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn("vmdesktop_vm.bastion", m.out)
        self.assertIn("nothing was drained", m.out)
        m.tf.apply.assert_not_called()
        self.assertFalse(any("drain" in c for c in m.calls))
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 2)
        self.assertEqual(undo.entries(env.id), [])

    def test_pending_updates_are_refused_under_auto_approve(self):
        env = self.env(outputs=CP_OUT)
        plan = [vm("wk2"), {"address": "module.stack.module.workloads.vmdesktop_vm.vm[0]", "type": "vmdesktop_vm",
                            "mode": "managed", "actions": ["update"]}]
        m = self.node(env, ["remove", f"acme-{env.name}-wk2", "vmware", "--auto-approve"], plan=plan)
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn("also changes", m.out)
        m.tf.apply.assert_not_called()

    def test_a_plan_that_does_not_delete_the_vm_drains_nothing(self):
        env = self.env(outputs=CP_OUT)
        m = self.node(env, ["remove", f"acme-{env.name}-wk2", "vmware", "--auto-approve"], plan=[])
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn("does not delete the VM", m.out)
        self.assertFalse(any("drain" in c for c in m.calls))

    def test_unreadable_plan_under_auto_approve(self):
        env = self.env(outputs=CP_OUT)
        m = self.node(env, ["remove", f"acme-{env.name}-wk2", "vmware", "--auto-approve"], plan=None)
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn("Could not read the plan", m.out)

    def test_exactly_the_node_is_applied_and_vmrest_starts_only_for_it(self):
        env = self.env(outputs=CP_OUT)
        order: list = []
        m = self.node(env, ["remove", f"acme-{env.name}-wk2", "vmware", "--auto-approve"], order=order,
                      plan=[vm("wk2"), vm("wk2-0", kind="mac"), vm("wk2-1", kind="mac"), vm("wk2-2", kind="mac")])
        self.assertEqual(m.rc, 0, m.out)
        self.assertEqual(order, ["vmrest", "plan"])   # vmrest is up before the plan refreshes through the provider
        m.tf.apply.assert_called_once_with("tfplan")
        self.assertTrue(any("drain" in c for c in m.calls))
        self.assertEqual(env.load()["vars"]["kubernetes_workers"], 1)

    def test_typo_never_starts_vmrest(self):
        env = self.env(outputs=CP_OUT)
        m = self.node(env, ["remove", "nosuch", "vmware", "--auto-approve"], get_rc=1)
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn("No node 'nosuch'", m.out)
        m.teardown.assert_not_called()
        m = self.node(env, ["remove", f"acme-{env.name}-wk9", "vmware", "--auto-approve"], get_rc=1)
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn(f"No node 'acme-{env.name}-wk9'", m.out)
        m.teardown.assert_not_called()

    def test_node_that_keeps_its_vm_records_how_to_bring_it_back(self):
        env = self.env(outputs=CP_OUT)
        m = self.node(env, ["remove", f"acme-{env.name}-wk1", "vmware", "--auto-approve"])
        self.assertEqual(m.rc, 0, m.out)
        m.teardown.assert_not_called()
        m.tf.apply.assert_not_called()
        e = undo.latest(env.id)
        self.assertEqual(e["kind"], "info")
        self.assertIn("rke2-agent", e["data"]["advice"])
        self.assertIn("10.100.0.40", e["data"]["advice"])

    def test_foreign_node_records_an_info_entry(self):
        env = self.env(outputs=CP_OUT)
        m = self.node(env, ["remove", "some-other-node", "vmware", "--auto-approve"])
        self.assertEqual(m.rc, 0, m.out)
        m.teardown.assert_not_called()
        e = undo.latest(env.id)
        self.assertEqual(e["kind"], "info")
        self.assertIn("some-other-node", e["summary"])

    def test_highest_vm_that_never_registered_is_deleted_without_a_drain(self):
        env = self.env(outputs=CP_OUT)
        m = self.node(env, ["remove", f"acme-{env.name}-wk2", "vmware", "--auto-approve"], get_rc=1, plan=[vm("wk2")])
        self.assertEqual(m.rc, 0, m.out)
        self.assertFalse(any("drain" in c for c in m.calls))
        m.tf.apply.assert_called_once_with("tfplan")
        self.assertIn("VM deleted", m.out)

    def test_only_the_api_servers_not_found_means_never_registered(self):   # (review)
        get = proc(1, "", 'error: exec: "kubectl-oidc_login": executable file not found in $PATH')
        with mock.patch.object(cli.subprocess, "run", return_value=get):
            res, out, err = run_quiet(cli._node_json_or_none, "/bin/kubectl", {}, "acme-lab-wk2")
        self.assertEqual(res, ("exit", 1))   # a VM is never deleted without a drain because kubectl could not ask
        self.assertIn("Could not read node", err)
        with mock.patch.object(cli.subprocess, "run", return_value=proc(1, "", 'Error from server (NotFound): nodes "acme-lab-wk2" not found')):
            self.assertIsNone(cli._node_json_or_none("/bin/kubectl", {}, "acme-lab-wk2"))

    def test_undo_retry_of_a_node_already_gone_is_a_no_op(self):
        env = self.env(outputs=CP_OUT)
        with mock.patch.dict(os.environ, {"CLOUDSEED_UNDOING": "1"}):
            m = self.node(env, ["remove", f"acme-{env.name}-wk3", "vmware", "-y", "--auto-approve"], get_rc=1)
        self.assertEqual(m.rc, 0, m.out)
        self.assertIn("already gone", m.out)
        m.teardown.assert_not_called()

    def test_remove_takes_the_environment_lock(self):
        env = self.env(outputs=CP_OUT)
        with env.lock("test"):   # held by this thread (an undo replaying it): re-entrant
            m = self.node(env, ["remove", f"acme-{env.name}-wk1", "vmware", "--auto-approve"])
        self.assertEqual(m.rc, 0, m.out)
        lock = env.lock_path()
        lock.parent.mkdir(parents=True, exist_ok=True)
        holder = subprocess.Popen(
            [sys.executable, "-c", "import fcntl, json, os, sys, time\n"
             f"f = open({str(lock)!r}, 'a+'); fcntl.flock(f.fileno(), fcntl.LOCK_EX)\n"
             "f.seek(0); f.truncate(); f.write(json.dumps({'pid': os.getpid(), 'action': 'apply vmware'})); f.flush()\n"
             "print('held', flush=True); time.sleep(30)"], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (holder.kill(), holder.wait(), holder.stdout.close()))
        self.assertEqual(holder.stdout.readline().strip(), "held")
        m = self.node(env, ["remove", f"acme-{env.name}-wk1", "vmware", "--auto-approve"])
        self.assertEqual(m.rc, ("exit", 1))
        self.assertIn("is busy", m.out)
        self.assertFalse(any("drain" in c for c in m.calls))


class ManagedNodeTests(Isolated):
    def pool(self, cloud_key, size, lo, hi):
        calls = []

        def fake(cmd, what, parse=False, show=True, env=None):
            calls.append((cmd[1:], env))
            if "list-nodegroups" in cmd:
                return {"nodegroups": ["c1-default"]}
            if "describe-nodegroup" in cmd:
                return {"nodegroup": {"scalingConfig": {"desiredSize": size, "minSize": lo, "maxSize": hi}}}
            if cmd[1:4] == ["aks", "nodepool", "show"]:
                return {"count": size, "minCount": lo, "maxCount": hi}
            return {} if parse else ""
        return calls, fake

    def run_node(self, env, argv, size, lo, hi, cfg=None):
        calls, fake = self.pool(env.cloud, size, lo, hi)
        a = cli.build_parser().parse_args(["node", *argv, "--env", env.name, "--auto-approve"])
        waits = []
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get(env.cloud), env, cfg or env.load(), json.loads((env.dir / "outputs.json").read_text()))), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(services, "ensure_tool", return_value="/bin/kubectl"), mock.patch.object(cli.deps, "find", return_value="/bin/tool"), \
                mock.patch.object(cli, "_cloud_cli", side_effect=fake), mock.patch.object(cli.subprocess, "call", return_value=0), \
                mock.patch.object(cli, "_wait_ready_nodes", side_effect=lambda k, e, want, sel: waits.append(want) or want):
            rc, out, err = run_quiet(cli.cmd_node, a, {})
        return rc, calls, waits, out + err

    def test_aks_scale_above_the_floor_waits_for_nothing_it_will_not_add(self):
        env = self.env("azure", "k", {"kubernetes_cluster_name": "c1", "resource_group_name": "rg"}, subscription_id="s")
        rc, calls, waits, out = self.run_node(env, ["scale", "azure", "--count", "5", "--min", "2", "--max", "5"], 2, 2, 5)
        self.assertEqual(rc, 0, out)
        self.assertEqual(waits, [])
        self.assertFalse(any(c[:3] == ["aks", "nodepool", "update"] for c, _ in calls))
        self.assertIn("already has 2 node(s)", out)
        self.assertEqual(env.load()["vars"].get("kubernetes_node_count"), None)   # nothing changed, nothing written

    def test_aks_raised_floor_waits_for_it_and_records_it(self):
        env = self.env("azure", "k", {"kubernetes_cluster_name": "c1", "resource_group_name": "rg"}, subscription_id="s")
        rc, calls, waits, out = self.run_node(env, ["scale", "azure", "--count", "5", "--min", "3"], 1, 1, 5)
        self.assertEqual(rc, 0, out)
        self.assertEqual(waits, [3])
        self.assertEqual(env.load()["vars"]["kubernetes_node_count"], 3)
        self.assertIn("3 node(s)", out)

    def test_aws_fips_calls_use_the_fips_endpoints(self):
        env = self.env("aws", "f", {"kubernetes_cluster_name": "c1"}, fips_mode=True, profile="")
        cfg = env.load()
        cfg["region"] = "us-east-1"
        rc, calls, _, out = self.run_node(env, ["add", "aws"], 2, 1, 4, cfg=cfg)
        self.assertEqual(rc, 0, out)
        self.assertTrue(calls)
        for cmd, penv in calls:
            self.assertEqual((penv or {}).get("AWS_USE_FIPS_ENDPOINT"), "true", cmd)


# ---------------------------------------------------------------- platform (platform-logic#10, #19, #20, catalog#17)

class PlatformTests(Isolated):
    def pargs(self, argv):
        return cli.build_parser().parse_args(["platform"] + argv)

    def test_plan_refuses_what_install_refuses(self):
        rc, out, err = run_quiet(cli.cmd_platform, self.pargs(["plan", "basek8s", "vmware", "--version", "1.0"]), {})
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("exactly one named item", err)
        rc, out, err = run_quiet(cli.cmd_platform, self.pargs(["plan", "keda", "vpa", "vmware", "--set", "foo=bar"]), {})
        self.assertEqual(rc, ("exit", 1))

    def test_plan_shows_the_flags_install_would_use(self):
        rc, out, err = run_quiet(cli.cmd_platform, self.pargs(["plan", "keda", "vmware", "--version", "9.9.9", "--set", "foo=bar"]), {})
        self.assertEqual(rc, 0, err)
        self.assertIn("--version 9.9.9", out)
        self.assertIn("--set foo=bar", out)

    def test_plan_warns_like_install_for_a_non_helm_item(self):
        rc, out, err = run_quiet(cli.cmd_platform, self.pargs(["plan", "kubeflow-trainer", "vmware", "--set", "foo=bar"]), {})
        self.assertEqual(rc, 0, err)
        self.assertIn("not a Helm chart", err)

    def test_list_degrades_when_helm_cannot_answer(self):
        env = self.env("vmware", "l", CP_OUT)
        ctx = platformmod.Cluster(clouds.get("vmware"), env, env.load(), CP_OUT, env.dir / "kc")
        states = []

        def status(c, charts=False, unknown=False, releases=None):
            states.append(unknown)
        no_helm = platformmod.ClusterUnreachable("cannot tell what is installed: helm is not installed (cloudseed install helm)")
        # one helm list (platform._releases_for_view), handed to status(): no catch-and-retry (a2-platform-logic#20)
        with mock.patch.object(cli, "_catalog_ctx", return_value=(ctx, None)), mock.patch.object(platformmod, "status", side_effect=status), \
                mock.patch.object(platformmod, "installed_releases", side_effect=no_helm) as listed:
            rc, out, err = run_quiet(cli.cmd_platform, self.pargs(["list", "vmware", "--env", env.name]), {})
        self.assertEqual(rc, 0)
        self.assertEqual(states, [True])
        self.assertEqual(listed.call_count, 1)
        self.assertIn("Install state unknown", err)
        self.assertIn("helm is not installed", err)

    def test_ui_on_vmware_never_sends_the_user_to_a_vpn(self):
        env = self.env("vmware", "u", CP_OUT)
        a = self.pargs(["ui", "vmware", "--env", env.name])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(platformmod, "expose_uis", return_value=[("grafana", "https://grafana.cs.local", "admin")]), \
                mock.patch.object(platformmod, "ingress_address", return_value="10.100.0.200"):
            rc, out, err = run_quiet(cli.cmd_platform, a, {})
        self.assertEqual(rc, 0, err)
        self.assertIn("host-only network 10.100.0.0/24", out)
        self.assertNotIn("vpn connect", out)

    def test_ui_on_a_cloud_without_vpn_points_at_the_bastion(self):
        env = self.env("aws", "u", {"kubernetes_cluster_name": "c1"}, enable_vpn=False)
        a = self.pargs(["ui", "aws", "--env", env.name])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("aws"), env, env.load(), {"kubernetes_cluster_name": "c1"})), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(platformmod, "expose_uis", return_value=[("grafana", "https://grafana.cs.local", "admin")]), \
                mock.patch.object(platformmod, "ingress_address", return_value="10.0.1.9"):
            rc, out, err = run_quiet(cli.cmd_platform, a, {})
        self.assertIn("-L 8443:10.0.1.9:443", out)
        self.assertNotIn("vpn connect", out)
        self.assertIn("127.0.0.1 grafana.cs.local", out)   # (review) through the forward, not the private ingress IP
        self.assertNotIn("10.0.1.9 grafana", out)


class PrereqUndoTests(Isolated):
    def record(self, added, have=()):
        env = self.env("aws", "p", {"kubernetes_cluster_name": "c1"})
        cfg = env.load()
        prev = copy.deepcopy(cfg)
        prev["platform_prereqs"] = list(have)
        cfg["platform_prereqs"] = list(have) + list(added)
        cli._record_prereqs_undo(clouds.get("aws"), env, cfg, prev, list(added), {"kubernetes_velero_bucket": "acme-velero"})
        return undo.latest(env.id)

    def test_velero_bucket_is_never_removed_by_undo(self):
        e = self.record(["velero"])
        self.assertEqual(e["kind"], "info")
        self.assertIn("acme-velero", e["data"]["advice"])
        self.assertIn("kept", e["data"]["advice"])

    def test_other_prereqs_are_undone_with_velero_kept(self):
        e = self.record(["velero", "karpenter"])
        self.assertEqual(e["kind"], "config")
        self.assertEqual(e["data"]["prev_cfg"]["platform_prereqs"], ["velero"])
        e = self.record(["karpenter"], have=["velero"])
        self.assertEqual((e["kind"], e["data"]["prev_cfg"]["platform_prereqs"]), ("config", ["velero"]))


class ImplicitInstallTests(Isolated):
    def test_dr_first_use_journals_the_velero_install(self):
        env = self.env("vmware", "d", CP_OUT)
        a = cli.build_parser().parse_args(["dr", "backup", "b1", "vmware", "--env", env.name, "--auto-approve"])
        releases = iter([{}, {"velero/velero": {"revision": "1", "status": "deployed"}}])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli.dr, "installed", return_value=False), mock.patch.object(platformmod, "ensure_tools"), \
                mock.patch.object(platformmod, "installed_releases", side_effect=lambda c: next(releases)), \
                mock.patch.object(platformmod, "install", return_value=["velero"]) as install, \
                mock.patch.object(cli.dr, "backup", return_value="b1"):
            rc, out, err = run_quiet(cli.cmd_dr, a, {})
        self.assertEqual(rc, 0, err)
        install.assert_called_once()
        kinds = [(e["kind"], e["summary"]) for e in undo.entries(env.id)]
        self.assertEqual(kinds[0], ("platform", "platform install velero"))
        self.assertEqual(kinds[-1], ("dr-delete", "dr backup b1"))

    def chaos_run(self, env, argv, ready):
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "vmware", "--env", env.name, *argv])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(platformmod, "ensure_tools"), mock.patch.object(chaos, "chaos_mesh_ready", return_value=ready), \
                mock.patch.object(platformmod, "installed_releases", return_value={}), \
                mock.patch.object(cli, "_journaled_install") as journaled, mock.patch.object(chaos, "_kubectl"), \
                mock.patch.object(chaos, "run", return_value=0) as run:
            rc, out, err = run_quiet(cli.cmd_chaos, a, {})
        return rc, journaled, run, out + err

    def test_chaos_mesh_is_asked_for_and_journaled(self):
        env = self.env("vmware", "c", CP_OUT)
        rc, journaled, run, out = self.chaos_run(env, [], ready=False)
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("--auto-approve", out)
        journaled.assert_not_called()
        run.assert_not_called()
        rc, journaled, run, out = self.chaos_run(env, ["--auto-approve"], ready=False)
        self.assertEqual(rc, 0, out)
        self.assertEqual(journaled.call_args[0][2], ["chaos-mesh"])
        rc, journaled, run, out = self.chaos_run(env, [], ready=True)   # installed already: nothing asked
        self.assertEqual(rc, 0, out)
        journaled.assert_not_called()


# ---------------------------------------------------------------- chaos report / run undo (resilience#10, #6)

class ChaosReportTests(Isolated):
    def report(self, env, argv=()):
        a = cli.build_parser().parse_args(["chaos", "report", "vmware", "--env", env.name, *argv])
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=AssertionError("cluster resolved")), \
                mock.patch.object(services, "ensure_kubeconfig", side_effect=AssertionError("kubeconfig")):
            return run_quiet(cli.cmd_chaos, a, {})

    def test_report_needs_no_cluster_and_skips_damaged_files(self):
        env = self.env("vmware", "r", {})
        d = env.dir / "chaos"
        d.mkdir(parents=True)
        (d / "report-20260101-000000.json").write_text(json.dumps({"results": [{"verdict": "PASS"}], "run": "old"}))
        (d / "report-20260102-000000.json").write_text('{"run": "x"')   # cut short
        (d / "report-20260103-000000.json").write_text("")               # claimed, never written
        rc, out, err = self.report(env)
        self.assertEqual(rc, 0, err)
        self.assertIn("Skipping the unreadable chaos report report-20260103-000000.json", err)
        self.assertIn("Chaos results", out)
        self.assertIn("run old", out)

    def test_no_report(self):
        env = self.env("vmware", "r2", {})
        rc, out, err = self.report(env)
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("No chaos report yet", err)

    def test_loader_fills_what_print_report_reads(self):
        p = self.tmp / "report-1.json"
        p.write_text(json.dumps({"results": [{"verdict": "PASS", "availability": 1, "min_availability": 0.9}], "summary": {"PASS": 1}}))
        rep = cli._load_chaos_report(p, "vmware-x")
        self.assertEqual(rep["summary"], {"PASS": 1, "FAIL": 0, "SKIP": 0, "ERROR": 0})
        self.assertEqual(rep["results"][0]["recovery_s"], "?")
        run_quiet(chaos.print_report, rep, p)   # no KeyError
        p.write_text("[]")
        self.assertIsNone(cli._load_chaos_report(p, "vmware-x"))
        # (review) a hand-edited file: text and numbers where print_report needs them
        p.write_text(json.dumps({"results": [{"experiment": 5, "verdict": ["x"], "availability": "0.9", "min_availability": 0.8}],
                                 "summary": {"PASS": "many"}}))
        rep = cli._load_chaos_report(p, "vmware-x")
        self.assertEqual((rep["results"][0]["experiment"], rep["results"][0]["availability"], rep["summary"]["PASS"]), ("5", 0.9, 0))
        run_quiet(chaos.print_report, rep, p)

    def test_run_records_only_its_own_report(self):
        env = self.env("vmware", "cr", CP_OUT)
        d = env.dir / "chaos"
        d.mkdir(parents=True)
        (d / "report-20260101-000000.json").write_text("{}")   # an older run
        a = cli.build_parser().parse_args(["chaos", "run", "pod-kill", "vmware", "--env", env.name])

        def two_runs(*_a, **_k):   # this run's report and one of a parallel run
            (d / "report-20260102-000000.json").write_text("{}")
            (d / "report-20260102-000001.json").write_text("{}")
            return 0
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli, "_ensure_chaos_mesh"), mock.patch.object(chaos, "run", side_effect=two_runs):
            rc, _, _ = run_quiet(cli.cmd_chaos, a, {})
        self.assertEqual(rc, 0)
        self.assertEqual(undo.entries(env.id), [])   # which one is ours cannot be told: nothing is taken


# ---------------------------------------------------------------- dr (resilience#3, #15, #18, e2e2#2)

class DrArgTests(Isolated):
    def check(self, argv):
        a = cli.build_parser().parse_args(["dr", *argv])
        with mock.patch.object(cli, "_resolve_cluster_env", side_effect=AssertionError("resolved")):
            return run_quiet(cli.cmd_dr, a, {}), a

    def test_bad_arguments_stop_before_any_cluster_work(self):
        for argv, text in ((["restore"], "cs dr restore <backup-name>"), (["schedule"], "cs dr schedule <name>"),
                           (["backup", "Bad_Name"], "not a valid backup name"),
                           (["schedule", "n", "--ttl", "forever"], "not a duration"),
                           (["schedule", "n", "--cron", "every night"], "not a cron expression"),
                           (["backup", "--namespaces", "shop,,Bad"], "not a namespace name")):
            (res, out, err), _ = self.check(argv)
            self.assertEqual(res, ("exit", 2), argv)
            self.assertIn(text, err, argv)

    def test_day_ttl_becomes_hours_and_go_durations_pass(self):
        a = SimpleNamespace(dr_cmd="schedule", name="nightly", namespaces=None, cron="0 2 * * *", ttl="30d")
        run_quiet(cli._check_dr_args, a)
        self.assertEqual(a.ttl, "720h")
        for ttl in ("720h", "1.5h", "90m30s", "500ms", "0"):
            cli._check_dr_args(SimpleNamespace(dr_cmd="schedule", name="n", namespaces=None, cron="@daily", ttl=ttl))

    def test_namespace_patterns_pass(self):   # (review) Velero matches namespace globs: never refuse them here
        a = SimpleNamespace(dr_cmd="backup", name=None, namespaces="app-*, shop,team-?", cron=None, ttl=None)
        cli._check_dr_args(a)
        self.assertEqual(a.namespaces, "app-*,shop,team-?")


class DrRestoreTests(Isolated):
    def restore(self, argv, backup, ns_now=("default", "kube-system"), restore_fails=None, restored=("default",)):
        env = self.env("vmware", "dr", CP_OUT)
        a = cli.build_parser().parse_args(["dr", "restore", *argv, "vmware", "--env", env.name, "--auto-approve"])
        calls = []

        def velero(ctx, *args, check=True, quiet=False, **kw):
            calls.append(args)
            if args[:2] == ("backup", "get") and len(args) > 2 and args[2] != "-o":
                if backup is None:
                    return proc(1, "", f'An error occurred: backups.velero.io "{args[2]}" not found')
                return proc(0, json.dumps(backup))
            if args[:3] == ("restore", "get", "-o"):
                names = [] if len([c for c in calls if c[:2] == ("restore", "get")]) == 1 else list(restored)
                return proc(0, json.dumps({"items": [{"metadata": {"name": n}} for n in names]}))
            return proc(0, "{}")
        namespaces = iter([set(ns_now), set(ns_now) | {"shop"}])
        with mock.patch.object(cli, "_resolve_cluster_env", return_value=(clouds.get("vmware"), env, env.load(), CP_OUT)), \
                mock.patch.object(services, "ensure_kubeconfig", return_value=env.dir / "kc"), \
                mock.patch.object(cli.dr, "installed", return_value=True), mock.patch.object(cli.dr, "_velero", side_effect=velero), \
                mock.patch.object(cli.dr, "_phase", return_value="Failed"), \
                mock.patch.object(cli, "_namespaces_now", side_effect=lambda c: next(namespaces)), \
                mock.patch.object(undo, "velero_pre_backup", return_value="pre-restore-1") as pre, \
                mock.patch.object(undo, "discard_velero_backup") as discard, \
                mock.patch.object(cli.dr, "restore", side_effect=restore_fails) as run:
            rc, out, err = run_quiet(cli.cmd_dr, a, {})
        return SimpleNamespace(rc=rc, out=out + err, pre=pre, discard=discard, run=run, env=env)

    def test_missing_source_backup_stops_before_the_undo_point(self):
        r = self.restore(["nosuch"], None)
        self.assertEqual(r.rc, ("exit", 1))
        self.assertIn("No backup named nosuch", r.out)
        r.pre.assert_not_called()
        r.run.assert_not_called()

    def test_unfinished_source_backup_is_refused(self):
        r = self.restore(["b1"], {"metadata": {"name": "b1"}, "status": {"phase": "InProgress"}})
        self.assertEqual(r.rc, ("exit", 1))
        self.assertIn("is InProgress", r.out)
        r.pre.assert_not_called()

    def test_undo_point_is_scoped_to_the_backups_namespaces(self):
        src = {"metadata": {"name": "b1"}, "spec": {"includedNamespaces": ["default", "shop"]}, "status": {"phase": "Completed"}}
        r = self.restore(["b1"], src)
        self.assertEqual(r.rc, 0, r.out)
        self.assertEqual(r.pre.call_args[0][2], ["default"])   # shop does not exist yet: the undo deletes it instead
        e = undo.latest(r.env.id)
        self.assertEqual((e["kind"], e["data"]["new_namespaces"]), ("velero-restore", ["shop"]))

    def test_a_namespace_pattern_backs_up_the_whole_cluster(self):   # (review) app-* cannot be matched here
        src = {"metadata": {"name": "b1"}, "spec": {"includedNamespaces": ["app-*"]}, "status": {"phase": "Completed"}}
        r = self.restore(["b1"], src)
        self.assertEqual(r.rc, 0, r.out)
        self.assertIsNone(r.pre.call_args[0][2])
        self.assertEqual(undo.latest(r.env.id)["kind"], "velero-restore")

    def test_restore_of_only_new_namespaces_needs_no_backup(self):
        src = {"metadata": {"name": "b1"}, "spec": {"includedNamespaces": ["shop"]}, "status": {"phase": "Completed"}}
        r = self.restore(["b1"], src)
        self.assertEqual(r.rc, 0, r.out)
        r.pre.assert_not_called()
        e = undo.latest(r.env.id)
        self.assertEqual(e["kind"], "argv-seq")
        self.assertIn("shop", e["data"]["argvs"][0])

    def test_restore_that_never_started_drops_its_undo_point(self):
        src = {"metadata": {"name": "b1"}, "status": {"phase": "Completed"}}
        r = self.restore(["b1"], src, restore_fails=ui.Abort("velero restore create failed"), restored=())
        self.assertEqual(r.rc, ("exit", 1))
        r.discard.assert_called_once()
        self.assertEqual(undo.entries(r.env.id), [])

    def test_restore_that_failed_part_way_keeps_its_undo_point(self):
        src = {"metadata": {"name": "b1"}, "status": {"phase": "Completed"}}
        r = self.restore(["b1"], src, restore_fails=ui.Abort("Restore Failed"), restored=("b1-restore-20260101000000",))
        self.assertEqual(r.rc, ("exit", 1))
        r.discard.assert_not_called()
        e = undo.latest(r.env.id)
        self.assertEqual(e["kind"], "velero-restore")
        self.assertIn("(failed part-way)", e["summary"])

    def test_no_wait_records_the_namespaces_the_restore_will_create(self):
        src = {"metadata": {"name": "b1"}, "spec": {"includedNamespaces": ["default", "shop"]}, "status": {"phase": "Completed"}}
        r = self.restore(["b1", "--no-wait"], src)
        self.assertEqual(r.rc, 0, r.out)
        self.assertEqual(undo.latest(r.env.id)["data"]["new_namespaces"], ["shop"])


# ---------------------------------------------------------------- scan (resilience#2, #6)

class ScanTests(Isolated):
    def test_scan_all_fails_when_the_cluster_checks_could_not_run(self):
        env = self.env("vmware", "s", CP_OUT)
        a = SimpleNamespace(scan_cmd="all", cloud="vmware", env=env.name, host=["bastion"], profile=None, framework=None, last=10, cmd="scan")
        with mock.patch.object(services, "ensure_kubeconfig", side_effect=ui.Abort("No kubeconfig yet")), \
                mock.patch.object(scan, "_hosts", return_value=[]):
            rc, out, err = run_quiet(cli.cmd_scan, a, {})
        self.assertEqual(rc, 1)
        self.assertIn("Cluster checks skipped", err)
        self.assertIn("ERROR", out)
        self.assertIn("cluster checks (cis/kube/images)", out)

    def test_undo_deletes_only_what_this_scan_wrote(self):
        env = self.env("aws", "s2")
        d = env.dir / "scans"
        d.mkdir(parents=True)
        raw = d / "raw"
        raw.mkdir()

        def fips(*_a, **_k):
            (d / "cis-20260101-000000.json").write_text("{}")   # a parallel scan's report, written meanwhile
            (d / "cis-20260101-000000.md").write_text("")
            (raw / "trivy-20260101-000001.json").write_text("[]")
            p = d / "fips-20260101-000001.json"
            p.write_text(json.dumps({"verdict": "PASS", "raw": str(raw / "trivy-20260101-000001.json")}))
            p.with_suffix(".md").write_text("")
            return p
        a = SimpleNamespace(scan_cmd="fips", cloud="aws", env=env.name, host=None, profile=None, framework=None, last=10, cmd="scan")
        with mock.patch.object(scan, "fips", side_effect=fips):
            rc, _, _ = run_quiet(cli.cmd_scan, a, {})
        self.assertEqual(rc, 0)
        names = sorted(Path(p).name for p in undo.latest(env.id)["data"]["paths"])
        self.assertEqual(names, ["fips-20260101-000001.json", "fips-20260101-000001.md", "trivy-20260101-000001.json"])


# ---------------------------------------------------------------- kubectl / helm (mcp#8, ops#7, platform-logic#22, #24, e2e2#1-3)

class NeverEndsTests(Isolated):
    def test_follow_and_watch_are_recognised(self):
        for rest in (["logs", "-f", "pod/x"], ["logs", "pod/x", "-f"], ["logs", "--follow", "deploy/x"], ["get", "pods", "-Aw"],
                     ["get", "pods", "--watch-only"], ["events", "--watch"], ["events", "-w"], ["-n", "x", "port-forward", "svc/a", "8080:80"],
                     ["proxy"], ["get", "--raw", "/api/v1/pods?watch=true"]):
            self.assertTrue(cli._never_ends("kubectl", rest), rest)
        for rest in (["logs", "--follow=false", "pod/x"], ["logs", "-f=false", "pod/x"], ["logs", "--tail=200", "pod/x"],
                     ["get", "pods", "-A"], ["get", "pods", "--watch=false"], ["get", "pods", "-w=false"], ["events"]):
            self.assertIsNone(cli._never_ends("kubectl", rest), rest)
        self.assertIsNone(cli._never_ends("helm", ["list"]))

    def test_agent_sessions_refuse_them_before_any_cluster_work(self):
        a = cli.build_parser().parse_args(["kubectl", "logs", "-f", "pod/x"])
        with mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": "1"}), \
                mock.patch.object(cli, "_resolve_cluster_env", side_effect=AssertionError("resolved")):
            rc, out, err = run_quiet(cli.cmd_ktool, a, {})
        self.assertEqual(rc, ("exit", 2))
        self.assertIn("--tail=200", err)


class HelmListTests(unittest.TestCase):
    def test_helm4_compatible_listing(self):
        ctx = SimpleNamespace(procenv=lambda: {})
        with mock.patch.object(cli.deps, "find", return_value="/bin/helm"), \
                mock.patch.object(cli.subprocess, "run", return_value=proc(0, "a\nb\n")) as run:
            self.assertEqual(cli._helm_releases_in(ctx, "demo"), {"a", "b"})
        argv = run.call_args[0][0]
        self.assertIn("--deployed", argv)
        self.assertNotIn("-a", argv)
        self.assertNotIn("--all", argv)
        with mock.patch.object(cli.deps, "find", return_value="/bin/helm"), \
                mock.patch.object(cli.subprocess, "run", return_value=proc(1, "", "Error")):
            self.assertIsNone(cli._helm_releases_in(ctx, "demo"))


class FinishChangeTests(Isolated):
    def setUp(self):
        super().setUp()
        self.env_ = self.env("vmware", "k", CP_OUT)
        self.cloud = clouds.get("vmware")
        self.ctx = SimpleNamespace(procenv=lambda: {})

    def finish(self, pre, rc, shown="x", revs=None, releases=None):
        with mock.patch.object(cli, "_helm_revisions", return_value=revs or []), \
                mock.patch.object(cli, "_helm_releases_in", return_value=releases), \
                mock.patch.object(undo, "discard_velero_backup") as discard:
            cli._finish_change_undo(pre, rc, "helm" if pre[0] == "helm" else "kubectl", shown, self.cloud, self.env_, self.ctx)
        return discard

    def test_failed_helm_upgrade_without_a_new_revision_records_nothing(self):
        self.finish(("helm", {"release": "r", "ns": "n", "revision": 3}, {}), 1, revs=[1, 2, 3])
        self.assertEqual(undo.entries(self.env_.id), [])

    def test_failed_helm_upgrade_that_left_a_revision_rolls_back(self):
        self.finish(("helm", {"release": "r", "ns": "n", "revision": 3}, {}), 1, "upgrade r c --wait", revs=[1, 2, 3, 4])
        e = undo.latest(self.env_.id)
        self.assertEqual((e["kind"], e["data"]["revision"]), ("helm", 3))
        self.assertIn("(failed part-way)", e["summary"])

    def test_failed_install_that_left_a_failed_release_is_uninstalled(self):
        self.finish(("helm", {"release": "r", "ns": "n"}, {}), 1, revs=[1])
        self.assertEqual(undo.latest(self.env_.id)["kind"], "helm")

    def test_generated_name_unreadable_says_so(self):
        self.finish(("helm", {"ns": "n"}, {"generated_from": None}), 0, releases={"x"})
        e = undo.latest(self.env_.id)
        self.assertEqual(e["kind"], "info")
        self.assertIn("uninstall it by hand", e["data"]["advice"])

    def test_failed_drain_leaves_the_uncordon_but_a_failed_cordon_nothing(self):
        argv = [["kubectl", "vmware", "--env", self.env_.name, "uncordon", "n1"]]
        self.finish(("argv-seq", {"argvs": argv}, {"success_only": True}), 1)
        self.assertEqual(undo.entries(self.env_.id), [])
        self.finish(("argv-seq", {"argvs": argv}, {"success_only": False}), 1, "drain n1")
        self.assertIn("(failed part-way)", undo.latest(self.env_.id)["summary"])

    def test_retries_of_a_failing_call_keep_the_first_undo_point(self):
        self.finish(("velero-restore", {"backup": "pre-1", "new_namespaces": []}, {"backup": "pre-1"}), 1, "apply -f d/")
        discard = self.finish(("velero-restore", {"backup": "pre-2", "new_namespaces": []}, {"backup": "pre-2"}), 1, "apply -f d/")
        entries = undo.entries(self.env_.id)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["data"]["backup"], "pre-1")
        discard.assert_called_once_with(self.ctx, "pre-2")


class PreChangeTests(Isolated):
    def setUp(self):
        super().setUp()
        self.cloud = clouds.get("vmware")
        self.envx = SimpleNamespace(name="lab", id="vmware-lab")
        self.ctx = SimpleNamespace(procenv=lambda: {})

    def pre(self, rest, runs=None, backup="pre-x"):
        runs = runs or {}

        def run(cmd, **kw):
            key = " ".join(cmd[1:])
            for k, v in runs.items():
                if k in key:
                    return v
            return proc(1, "", "")
        with mock.patch.object(cli.subprocess, "run", side_effect=run), \
                mock.patch.object(undo, "velero_pre_backup", return_value=backup) as vb, \
                mock.patch.object(cli.dr, "installed", return_value=bool(backup)), \
                mock.patch.object(cli.deps, "find", return_value="/bin/kubectl"):
            res = cli._pre_change_undo("kubectl", rest, self.cloud, self.envx, {}, {}, None, ctx=self.ctx)
        return res, vb

    def test_node_labels_record_their_previous_values(self):
        node = {"metadata": {"labels": {"team": "b"}, "annotations": {"note": "old value"}}}
        runs = {"get node n1 -o json": proc(0, json.dumps(node))}
        (kind, data, notes), vb = self.pre(["label", "node", "n1", "team=a", "tier=web"], runs)
        vb.assert_not_called()
        self.assertEqual(kind, "argv-seq")
        self.assertEqual(data["argvs"], [["kubectl", "vmware", "--env", "lab", "label", "node", "n1", "team=b", "tier-", "--overwrite"]])
        self.assertTrue(notes["success_only"])
        (kind, data, _), _ = self.pre(["annotate", "node/n1", "note-", "example.com/x-"], runs)
        self.assertEqual(data["argvs"][0][5:], ["node", "n1", "note=old value", "--overwrite"])

    def test_other_node_changes_say_how_to_revert_by_hand(self):
        for rest in (["label", "nodes", "--all", "team=a"], ["patch", "node", "n1", "-p", "{}"], ["delete", "node", "n1"],
                     ["label", "node", "-l", "role=x", "team=a"]):
            (kind, data, _), vb = self.pre(rest)
            self.assertEqual(kind, "info", rest)
            self.assertIn("Velero does not restore Node objects", data["advice"])
            vb.assert_not_called()

    def test_named_creations_are_undone_by_deleting_them(self):
        cases = ((["-n", "e2e", "create", "configmap", "keepme", "--from-literal=k=v"], ["-n", "e2e", "delete", "configmap/keepme"]),
                 (["create", "secret", "generic", "s1", "--from-literal=a=b"], ["delete", "secret/s1"]),
                 (["run", "p", "--image=busybox", "--expose", "--port=80"], ["delete", "pod/p", "service/p"]),
                 (["expose", "deploy/web", "--port", "80", "--name", "websvc"], ["delete", "service/websvc"]),
                 (["autoscale", "deployment", "web", "--min=2", "--max=5"], ["delete", "horizontalpodautoscaler/web"]))
        for rest, want in cases:
            (kind, data, notes), vb = self.pre(rest)
            self.assertEqual(kind, "argv-seq", rest)
            self.assertEqual(data["argvs"][0][4:-1], want, rest)
            self.assertTrue(notes["success_only"])
            vb.assert_not_called()
        (kind, data, _), vb = self.pre(["create", "ns", "shop"])   # e2e2#3: nothing to back up
        self.assertEqual(data["argvs"], [["kubectl", "vmware", "--env", "lab", "delete", "ns", "shop", "--ignore-not-found"]])
        vb.assert_not_called()
        self.assertIsNone(self.pre(["create", "token", "sa1"])[0])
        # (review) options with a value before the name: known ones are skipped, an unknown one leaves the name unsure
        (kind, data, _), _ = self.pre(["create", "cronjob", "--schedule", "*/5 * * * *", "--image", "busybox", "nightly"])
        self.assertEqual(data["argvs"][0][4:-1], ["delete", "cronjob/nightly"])
        (kind, data, _), vb = self.pre(["-n", "shop", "create", "deployment", "--some-new-flag", "nginx", "web"])
        self.assertEqual(kind, "velero-restore")   # never `delete deployment/nginx`, which may be someone else's
        self.assertEqual(vb.call_args[0][2], ["shop"])

    def test_create_of_several_objects_prints_one_document_each(self):   # (review) kubectl create -o json
        docs = "\n".join(json.dumps({"kind": k, "apiVersion": "v1", "metadata": {"name": n, "namespace": "shop"}})
                         for k, n in (("ConfigMap", "a"), ("Secret", "b")))
        runs = {"--dry-run=client -o json": proc(0, docs), "get ns -o jsonpath": proc(0, "shop"),
                "--ignore-not-found -o json": proc(0, "")}
        (kind, data, _), vb = self.pre(["create", "-f", "two.yaml"], runs)
        vb.assert_not_called()
        self.assertEqual(data["argvs"], [["kubectl", "vmware", "--env", "lab", "-n", "shop", "delete", "configmap/a", "secret/b",
                                          "--ignore-not-found"]])

    def test_apply_of_new_objects_deletes_exactly_them(self):
        objs = {"kind": "List", "items": [
            {"kind": "Namespace", "apiVersion": "v1", "metadata": {"name": "shop"}},
            {"kind": "Deployment", "apiVersion": "apps/v1", "metadata": {"name": "web", "namespace": "shop"}},
            {"kind": "ConfigMap", "apiVersion": "v1", "metadata": {"name": "cfg", "namespace": "shop"}}]}
        runs = {"--dry-run=client -o json": proc(0, json.dumps(objs)), "get ns -o jsonpath": proc(0, "default"),
                "--ignore-not-found -o json": proc(0, "")}
        (kind, data, notes), vb = self.pre(["apply", "-f", "app.yaml"], runs)
        vb.assert_not_called()
        self.assertEqual(kind, "argv-seq")
        self.assertEqual(data["argvs"], [["kubectl", "vmware", "--env", "lab", "-n", "shop", "delete", "deployment.apps/web", "configmap/cfg", "--ignore-not-found"],
                                         ["kubectl", "vmware", "--env", "lab", "delete", "ns", "shop", "--ignore-not-found"]])
        self.assertFalse(notes.get("success_only"))   # also right after a run that failed part-way

    def test_apply_changing_existing_objects_backs_up_only_their_namespaces(self):
        objs = {"kind": "List", "items": [
            {"kind": "Deployment", "apiVersion": "apps/v1", "metadata": {"name": "web", "namespace": "shop"}},
            {"kind": "Service", "apiVersion": "v1", "metadata": {"name": "new", "namespace": "shop"}}]}
        live = {"kind": "List", "items": [{"kind": "Deployment", "metadata": {"name": "web", "namespace": "shop"}}]}
        runs = {"--dry-run=client -o json": proc(0, json.dumps(objs)), "get ns -o jsonpath": proc(0, "default shop"),
                "--ignore-not-found -o json": proc(0, json.dumps(live))}
        (kind, data, _), vb = self.pre(["apply", "-f", "app.yaml"], runs)
        self.assertEqual(kind, "velero-restore")
        self.assertEqual(vb.call_args[0][2], ["shop"])
        self.assertEqual(data["created"], [{"ns": "shop", "ref": "service/new"}])

    def test_create_of_objects_that_all_exist_records_nothing(self):
        objs = {"kind": "ConfigMap", "apiVersion": "v1", "metadata": {"name": "cfg", "namespace": "shop"}}
        runs = {"--dry-run=client -o json": proc(0, json.dumps(objs)), "get ns -o jsonpath": proc(0, "shop"),
                "--ignore-not-found -o json": proc(0, json.dumps(objs))}
        self.assertIsNone(self.pre(["create", "-f", "cm.yaml"], runs)[0])

    def test_stdin_manifests_fall_back_to_the_namespace_backup(self):
        (kind, _, _), vb = self.pre(["apply", "-f", "-", "-n", "shop"], {"get ns -o jsonpath": proc(0, "shop")})
        self.assertEqual((kind, vb.call_args[0][2]), ("velero-restore", ["shop"]))

    def test_a_namespace_that_does_not_exist_yet_is_not_backed_up(self):
        (kind, data, notes), vb = self.pre(["apply", "-f", "-", "-n", "fresh"], {"get ns -o jsonpath": proc(0, "default")})
        vb.assert_not_called()
        self.assertEqual(kind, "info")
        self.assertTrue(notes["nothing_before"])

    def test_label_ns_tokens_are_not_namespaces(self):   # ops: undo.kubectl_namespaces delegates here
        self.assertEqual(undo.kubectl_namespaces(["label", "ns", "shop", "team=a"]), ["shop"])
        self.assertEqual(undo.kubectl_namespaces(["annotate", "ns", "shop", "note-"]), ["shop"])


# ---------------------------------------------------------------- explain (cli-ux#23)

class ExplainTests(unittest.TestCase):
    def explain(self, *words):
        a = cli.build_parser().parse_args(["explain", *words])
        return run_quiet(cli.cmd_explain, a, {})

    def test_no_link_to_the_same_page(self):
        rc, out, _ = self.explain("deps")
        self.assertEqual(rc, 0)
        self.assertNotIn("topic deps", out)
        rc, out, _ = self.explain("agentic")   # a feature, command and topic: the command page carries the topic
        self.assertIn("cs explain command agentic", out)
        self.assertNotIn("topic agentic", out)
        rc, out, _ = self.explain("vmware")    # a topic that is no command keeps its link
        self.assertIn("cs explain topic vmware", out)

    def test_variables_needs_a_target(self):
        for words in (("variables",), ("variables", "foo"), ("outputs",)):
            rc, _, err = self.explain(*words)
            self.assertEqual(rc, ("exit", 1), words)
            self.assertIn(f"cs explain {words[0]} <aws|gcp|azure|vmware>", err)
        rc, out, _ = self.explain("variables", "aws")
        self.assertEqual(rc, 0)

    def test_namespace_without_a_name_lists_the_names(self):
        rc, _, err = self.explain("feature")
        self.assertEqual(rc, ("exit", 1))
        self.assertIn("Features:", err)
        self.assertIn("kubernetes", err)
        rc, _, err = self.explain("item")
        self.assertIn("Items:", err)


if __name__ == "__main__":
    unittest.main()
