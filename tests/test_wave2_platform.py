"""Wave 2 regression tests for the platform engine, services and managed CLIs: cross-group handoffs (uninstall drains
cloud-backed objects first, stale BackendTLSPolicies, deployment waits, FIPS endpoints for the AWS token command, VPN
routes, managed-CLI install consent ...). Offline, stdlib only: helm/kubectl/ssh/openvpn are answered by fakes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, managed, paths, platform as pl, services, ui  # noqa: E402

PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + "\n".join(["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB"] * 12) + \
      "\n-----END OPENSSH PRIVATE KEY-----"


def _ctx(target="vmware", distro="rke2", outputs=None, fips=False, name="w2pl", vars_=None):
    env = paths.Env(target, name)
    env.create_dirs()
    cfg = {"env": name, "region": "us-east-1", "network_cidr": "10.100.0.0/24",
           "vars": dict({"fips_mode": fips, "project_id": "p", "subscription_id": "s"}, **(vars_ or {})), "platform_prereqs": []}
    if outputs is None:
        outputs = {"kubernetes_distro": distro} if target == "vmware" else {"kubernetes_cluster_name": "c1"}
    return pl.Cluster(clouds.get(target), env, cfg, outputs, env.dir / "k8s" / "kubeconfig")


def _rel(status="deployed"):
    return {"status": status, "chart": "c-1", "revision": "1"}


def _cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


@contextlib.contextmanager
def _silenced():
    """stdout and stderr (ui.warn) into one buffer."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield buf


class Kube:
    """Stands in for helm/kubectl: `_run` calls are recorded; read-only `subprocess.run` queries are answered from
    `answers` (a list of (predicate, CompletedProcess or callable) pairs, first match wins)."""

    def __init__(self, answers=(), run_rc=None):
        self.calls: list[list[str]] = []
        self.queries: list[list[str]] = []
        self.answers = list(answers)
        self.run_rc = run_rc or (lambda cmd: 0)

    def run(self, cmd, ctx, check=True):
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        rc = self.run_rc(cmd)
        if cmd[:2] == ["helm", "uninstall"]:
            ctx.last_output = f'release "{cmd[2]}" uninstalled\n'
        elif "delete" in cmd:
            ctx.last_output = 'thing "x" deleted\n'
        else:
            ctx.last_output = ""
        if check and rc != 0:
            raise ui.Abort(f"command failed (exit {rc})")
        return rc

    def sub(self, cmd, **kw):
        cmd = [str(c) for c in cmd]
        self.queries.append(cmd)
        for pred, ans in self.answers:
            if pred(cmd):
                return ans(cmd) if callable(ans) else ans
        if cmd[1:3] == ["get", "namespace"]:
            return _cp(1, "", "not found")          # namespaces are gone: no cleanup noise
        return _cp(0, "", "")

    def patches(self, releases):
        return [mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value=releases),
                mock.patch.object(pl, "_run", self.run), mock.patch.object(pl.subprocess, "run", self.sub),
                mock.patch.object(pl.deps, "find", side_effect=lambda t: t)]

    def did(self, text):
        return [i for i, c in enumerate(self.calls) if text in " ".join(c)]


def _with(patches):
    stack = contextlib.ExitStack()
    for p in patches:
        stack.enter_context(p)
    return stack


class DrainBeforeControllerTests(unittest.TestCase):
    """aws#9 / platform-catalog#33: an item's own objects go first, then what its controller made from them in the cloud
    (the Gateway's load balancer, Karpenter's EC2 nodes) must be gone before the controller is uninstalled."""

    GW = {"envoy-gateway-system/eg": _rel(), "cert-manager/cert-manager": _rel(), "probe:gateway-api": {"status": "present"},
          "probe:cert-manager-issuer": {"status": "present"}}

    def _lb_answers(self, script):
        """`kubectl get services -l owning-gateway...` answers in turn from `script` (a list of stdout strings)."""
        seq = list(script)

        def answer(cmd):
            return _cp(0, seq.pop(0) if seq else "")
        return [(lambda c: c[1:3] == ["get", "services"] and "gateway.envoyproxy.io/owning-gateway-name=cloudseed" in " ".join(c), answer)]

    def test_gateway_load_balancer_is_waited_for_before_helm_uninstall(self):
        vm = _ctx("aws", "eks", name="w2gw")
        kube = Kube(self._lb_answers(["service/envoy-cloudseed-cloudseed-1a2b\n", ""]))
        with _with(kube.patches(self.GW)), _silenced():
            removed = pl.uninstall(["envoy-gateway"], vm)
        self.assertEqual(removed, ["envoy-gateway"])
        post = kube.did("cloudseed-gateway.delete.yaml")[0]
        wait = kube.did("wait --for=delete services -n envoy-gateway-system")[0]
        helm = kube.did("helm uninstall eg")[0]
        self.assertLess(post, wait)
        self.assertLess(wait, helm)
        self.assertIn("--timeout=600s", kube.calls[post])       # long enough for the cloud LB to be released

    def test_controller_stays_while_its_load_balancer_is_still_there(self):
        vm = _ctx("aws", "eks", name="w2gw2")
        kube = Kube(self._lb_answers(["service/envoy-x\n", "service/envoy-x\n"]))
        with _with(kube.patches(self.GW)), _silenced():
            removed = pl.uninstall(["envoy-gateway"], vm, strict=False)
        self.assertEqual(removed, [])
        self.assertEqual(vm.failures, ["envoy-gateway"])
        self.assertFalse(kube.did("helm uninstall"))

    def test_unrelated_objects_in_the_namespace_do_not_count(self):
        vm = _ctx("vmware", name="w2gw3")
        kube = Kube(self._lb_answers(["configmap/kube-root-ca.crt\n"]))
        with _with(kube.patches(dict(self.GW, **{"metallb-system/metallb": _rel()}))), _silenced():
            self.assertEqual(pl.uninstall(["envoy-gateway"], vm), ["envoy-gateway"])
        self.assertFalse(kube.did("wait --for=delete"))

    def test_karpenter_waits_for_its_nodes_and_refuses_with_user_nodepools(self):
        rel = {"kube-system/karpenter": _rel()}
        aws = _ctx("aws", "eks", name="w2karp")
        claims = ["nodeclaim.karpenter.sh/default-abc\n", ""]
        kube = Kube([(lambda c: c[1:3] == ["get", "nodepools.karpenter.sh"], _cp(0, "nodepool.karpenter.sh/default\n")),
                     (lambda c: c[1:3] == ["get", "nodeclaims.karpenter.sh"] and "-l" in c, lambda c: _cp(0, claims.pop(0) if claims else "")),
                     (lambda c: c[1:3] == ["get", "nodeclaims.karpenter.sh"], _cp(0, ""))])
        with _with(kube.patches(rel)), _silenced():
            self.assertEqual(pl.uninstall(["karpenter"], aws), ["karpenter"])
        post = kube.did("karpenter-default.delete.yaml")[0]
        wait = kube.did("wait --for=delete nodeclaims.karpenter.sh -l karpenter.sh/nodepool=default")[0]
        self.assertLess(post, wait)
        self.assertLess(wait, kube.did("helm uninstall karpenter")[0])
        self.assertIn("--timeout=900s", kube.calls[post])

        mine = Kube([(lambda c: c[1:3] == ["get", "nodepools.karpenter.sh"], _cp(0, "nodepool.karpenter.sh/default\nnodepool.karpenter.sh/gpu\n"))])
        with _with(mine.patches(rel)), _silenced() as out:
            self.assertEqual(pl.uninstall(["karpenter"], _ctx("aws", "eks", name="w2karp2"), strict=False), [])
        self.assertEqual(mine.calls, [])                     # nothing deleted: the user's NodePool keeps its controller
        self.assertIn("nodepool.karpenter.sh/gpu", out.getvalue())

    def test_karpenter_crds_gone_means_nothing_left(self):
        kube = Kube([(lambda c: c[1] == "get" and "karpenter.sh" in c[2],
                      _cp(1, "", "error: the server doesn't have a resource type \"nodepools\""))])
        with _with(kube.patches({"kube-system/karpenter": _rel()})), _silenced():
            self.assertEqual(pl.uninstall(["karpenter"], _ctx("aws", "eks", name="w2karp3")), ["karpenter"])

    def test_pre_and_post_manifests_of_the_new_items_are_deleted(self):
        vm = _ctx("vmware", name="w2pre")
        kube = Kube()
        rel = {"polaris/polaris": _rel(), "cnpg-system/cloudnative-pg": _rel(), "monitoring/loki": _rel(), "monitoring/alloy-logs": _rel(),
               "artifactory/artifactory": _rel(), "nexus/nexus": _rel(), "minio/minio": _rel(), "spark-operator/spark-operator": _rel(),
               "velero/velero": _rel()}
        with _with(kube.patches(rel)), _silenced():
            pl.uninstall(["polaris", "cloudnative-pg", "loki", "alloy", "artifactory", "nexus", "velero"], vm, force=True)
        for name in ("polaris-db", "loki-datasource", "alloy-logs-config", "artifactory-keys", "nexus-root-password",
                     "velero-minio-bucket", "velero-minio-credentials"):
            self.assertTrue(kube.did(f"{name}.delete.yaml"), name)
        self.assertLess(kube.did("polaris-db.delete.yaml")[0], kube.did("helm uninstall cloudnative-pg")[0])
        bucket = (vm.workdir / "velero-minio-bucket.delete.yaml").read_text()
        self.assertIn("minio-user-velero", bucket)
        self.assertNotIn("kind: Namespace", bucket)


class StaleBackendTlsTests(unittest.TestCase):
    """platform-catalog#22: NeuVector is plain HTTP now; a BackendTLSPolicy an earlier `cs platform ui` made would keep
    Envoy speaking TLS to it."""

    def test_only_cloudseeds_policies_for_http_uis_are_removed(self):
        vm = _ctx("vmware", name="w2btls")
        listing = "neuvector/cloudseed-neuvector\nshop/cloudseed-neuvector\nneuvector/their-policy\nargocd/cloudseed-argocd\n"
        kube = Kube([(lambda c: c[1:3] == ["get", pl._BACKEND_TLS], _cp(0, listing))])
        with _with(kube.patches({})), _silenced():
            dropped = pl._drop_stale_backend_tls(vm, "kubectl")
        self.assertEqual(sorted(dropped), ["argocd", "neuvector"])
        deleted = [c for c in kube.calls if "delete" in c]
        self.assertEqual(sorted(c[2] for c in deleted), ["argocd", "neuvector"])
        self.assertTrue(all(c[-3] == f"cloudseed-{c[2]}" for c in deleted))
        self.assertEqual(pl.UIS["neuvector"][3], "http")

    def test_expose_uis_on_the_gateway_cleans_up_and_routes_over_http(self):
        vm = _ctx("vmware", name="w2btls2")
        rel = {"neuvector/core": _rel(), "neuvector/neuvector": _rel()}
        kube = Kube([(lambda c: c[1:3] == ["get", "gateway"], _cp(0)),
                     (lambda c: c[1:3] == ["get", pl._BACKEND_TLS], _cp(0, "neuvector/cloudseed-neuvector\n")),
                     (lambda c: c[1:3] == ["get", "svc"], lambda c: _cp(0 if c[3] == "neuvector-service-webui" else 1))])
        with _with(kube.patches(rel)), _silenced():
            out = pl.expose_uis(vm)
        self.assertEqual([o[0] for o in out], ["neuvector"])
        self.assertTrue(kube.did(f"delete {pl._BACKEND_TLS} cloudseed-neuvector"))
        self.assertNotIn("BackendTLSPolicy", (vm.workdir / "httproute-neuvector.yaml").read_text())

    def test_no_such_kind_is_not_an_error(self):
        kube = Kube([(lambda c: c[1:3] == ["get", pl._BACKEND_TLS], _cp(1, "", "error: the server doesn't have a resource type"))])
        with _with(kube.patches({})), _silenced():
            self.assertEqual(pl._drop_stale_backend_tls(_ctx("vmware", name="w2btls3"), "kubectl"), [])
        self.assertEqual(kube.calls, [])


class InstalledStateViewTests(unittest.TestCase):
    """platform-catalog#32: info and group views agree with status - probes, istio via istiod, and items the distro ships."""

    def _show(self, fn, *args):
        with mock.patch.object(pl, "installed_releases", return_value={"probe:gateway-api": {"status": "present", "chart": "crd/x"},
                                                                    "istio-system/istiod": _rel()}), \
                mock.patch.object(pl.ui, "width", return_value=110), _silenced() as out:
            fn(*args)
        return ui._strip(out.getvalue())

    def test_distro_built_ins_probes_and_istio(self):
        vm = _ctx("vmware", "rke2", name="w2view")
        text = self._show(pl.info, "metrics-server", vm)
        self.assertIn("built into rke2", text)
        self.assertIn("installed", self._show(pl.info, "gateway-api", vm))
        self.assertNotIn("installed  no", self._show(pl.info, "gateway-api", vm).replace("│", " "))
        group = self._show(pl.group_info, "finops", vm)
        line = next(line for line in group.splitlines() if " metrics-server " in line)
        self.assertIn("✔", line)
        self.assertIn("built into rke2", line)
        sec = self._show(pl.group_info, "security", vm)
        self.assertIn("✔", next(line for line in sec.splitlines() if " istio " in line))
        eks = _ctx("aws", "eks", name="w2view2")
        self.assertNotIn("built into", self._show(pl.info, "metrics-server", eks))


class DeploymentWaitTests(unittest.TestCase):
    """platform-catalog#9: a post manifest's Deployment and a kustomize/manifest item's Deployments must be available
    before the item counts as installed; --no-wait skips that (Jobs are always waited for)."""

    def test_post_manifest_deployment_rolls_out_after_its_job(self):
        vm = _ctx("vmware", name="w2dep")
        kube = Kube()
        with _with(kube.patches({})), _silenced():
            pl._apply_manifest(vm, "kubectl", "spark-history-server", "spark-operator", wait_ns=True)
        job = kube.did("wait --for=condition=complete job/spark-logs-bucket")[0]
        roll = kube.did("rollout status deployment/spark-history-server")[0]
        self.assertLess(job, roll)
        self.assertEqual(kube.calls[roll][:3], ["kubectl", "-n", "spark-operator"])
        kube2 = Kube()
        with _with(kube2.patches({})), _silenced():
            pl._apply_manifest(vm, "kubectl", "spark-history-server", "spark-operator", wait_ns=True, wait=False)
        self.assertFalse(kube2.did("rollout status"))
        self.assertTrue(kube2.did("job/spark-logs-bucket"))

    def test_a_deployment_that_never_gets_ready_fails_the_install(self):
        vm = _ctx("vmware", name="w2dep2")
        kube = Kube(run_rc=lambda c: 1 if "rollout" in c else 0)
        with _with(kube.patches({})), _silenced():
            with self.assertRaises(SystemExit) as cm:
                pl._apply_manifest(vm, "kubectl", "spark-history-server", "spark-operator", wait_ns=True)
        self.assertIn("spark-operator/spark-history-server", str(cm.exception))
        self.assertTrue(kube.did("describe deployment/spark-history-server"))

    def test_kustomize_items_wait_for_their_deployments(self):
        vm = _ctx("vmware", name="w2dep3")
        kube = Kube()
        with _with(kube.patches({})), mock.patch.object(pl.shutil, "which", return_value="/usr/bin/git"), \
                mock.patch.object(pl, "audit"), _silenced():
            pl.install_one("kubeflow-trainer", vm, wait=True, releases={})
        apply = kube.did("apply -k")[0]
        wait = kube.did("wait --for=condition=Available deployment --all")
        self.assertTrue(wait and wait[-1] > apply)
        self.assertEqual(kube.calls[wait[-1]][:3], ["kubectl", "-n", "kubeflow"])
        failing = Kube(run_rc=lambda c: 1 if "--for=condition=Available" in c else 0)
        with _with(failing.patches({})), mock.patch.object(pl.shutil, "which", return_value="/usr/bin/git"), \
                mock.patch.object(pl, "audit"), _silenced():
            with self.assertRaises(SystemExit) as cm:
                pl.install_one("kubeflow-trainer", vm, wait=True, releases={})
        self.assertIn("--upgrade", str(cm.exception))
        quick = Kube()
        with _with(quick.patches({})), mock.patch.object(pl.shutil, "which", return_value="/usr/bin/git"), \
                mock.patch.object(pl, "audit"), _silenced():
            pl.install_one("kubeflow-trainer", vm, wait=False, releases={})
        self.assertFalse(quick.did("--for=condition=Available"))

    def test_manifest_items_in_shared_namespaces_are_not_waited_on(self):
        vm = _ctx("vmware", name="w2dep4")
        kube = Kube()
        with _with(kube.patches({})), mock.patch.object(pl, "gateway_api_installed", return_value=None), \
                mock.patch.object(pl, "audit"), _silenced():
            pl.install_one("gateway-api", vm, wait=True, releases={})
        self.assertFalse(kube.did("--for=condition=Available"))     # ns "default": other people's Deployments

    def test_manifest_objects_reads_flow_and_block_metadata(self):
        objs = pl._manifest_objects(pl.POST_MANIFESTS["karpenter-default"] + "---\n" + pl.POST_MANIFESTS["metallb-pool"])
        self.assertIn(("EC2NodeClass", "default", ""), objs)
        self.assertIn(("L2Advertisement", "cloudseed", "metallb-system"), objs)
        self.assertEqual(pl._manifest_objects("kind: Deployment\nmetadata:\n  labels:\n    name: no\n  name: yes-1\n  namespace: n\n"),
                         [("Deployment", "yes-1", "n")])
        self.assertEqual(pl._manifest_objects("kind: Job\nmetadata: {labels: {name: no}, name: j1, namespace: m}\n"), [("Job", "j1", "m")])


class GitOnlyWhereNeededTests(unittest.TestCase):
    """platform-catalog#17: git matters only for the kustomize items fetched from GitHub."""

    def test_no_git_warning_on_every_command_but_kustomize_stops_early(self):
        with mock.patch("cloudseed.services.ensure_tool"), mock.patch.object(pl.shutil, "which", return_value=None), _silenced() as out:
            pl.ensure_tools()
        self.assertNotIn("git", out.getvalue())
        vm = _ctx("vmware", name="w2git")
        kube = Kube()
        with _with(kube.patches({})), mock.patch.object(pl.shutil, "which", return_value=None), _silenced():
            with self.assertRaises(SystemExit) as cm:
                pl.install_one("kubeflow-pipelines", vm, wait=True, releases={})
        self.assertIn("git", str(cm.exception))
        self.assertFalse(kube.did("apply -k"))


class PartialInstallTests(unittest.TestCase):
    """platform-catalog#25: a batch that stops part-way says what was installed, what failed and what was not tried."""

    def test_stopped_panel(self):
        vm = _ctx("vmware", name="w2part")

        def fake_one(item, ctx, *a, **kw):
            if item == "vpa":
                raise ui.Abort("command failed (exit 1)")
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value={}), \
                mock.patch.object(pl, "install_one", fake_one), mock.patch.object(pl.ui, "width", return_value=110), _silenced() as out:
            with self.assertRaises(SystemExit):
                pl.install(["keda", "goldilocks"], vm)
        text = ui._strip(out.getvalue())
        self.assertIn("Stopped at vpa", text)
        stopped = text[text.index("Stopped at vpa"):]
        self.assertRegex(stopped, r"installed\s+│?\s*keda|installed\s+keda")
        self.assertIn("not attempted", stopped)
        self.assertIn("goldilocks", stopped.split("not attempted", 1)[1].splitlines()[0])
        self.assertIn("cs platform install vpa --upgrade", stopped)
        self.assertIn("cs platform install keda goldilocks", " ".join(stopped.replace("│", " ").split()))
        self.assertEqual(vm.done, ["keda"])


class OffTargetTests(unittest.TestCase):
    """platform-catalog#40: an item named explicitly that does not run on this target says why instead of vanishing."""

    def test_named_item_for_another_cloud_is_reported(self):
        vm = _ctx("vmware", name="w2off")
        entries = pl.plan(["karpenter", "keda"], vm, releases={})
        by = {e["item"]: e for e in entries}
        self.assertEqual(by["karpenter"]["action"], "skip-target")
        self.assertIn("aws only", by["karpenter"]["reasons"][0])
        self.assertEqual(by["keda"]["action"], "install")
        self.assertNotIn("metallb", [e["item"] for e in pl.plan(["basek8s"], _ctx("aws", "eks", name="w2off2"), releases={})
                                     if e["action"] == "skip-target"])   # group members stay quiet
        with mock.patch.object(pl.ui, "width", return_value=60), _silenced() as out:
            pl.print_plan(entries, vm)
        self.assertTrue(all(len(line) <= 60 for line in ui._strip(out.getvalue()).splitlines()))

    def test_install_of_only_off_target_items_installs_nothing(self):
        vm = _ctx("vmware", name="w2off3")
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value={}), \
                mock.patch.object(pl, "install_one") as one, _silenced() as out:
            self.assertEqual(pl.install(["karpenter"], vm), [])
        one.assert_not_called()
        self.assertIn("aws only", out.getvalue())


class DidYouMeanTests(unittest.TestCase):
    """platform-logic#31: direct callers (web console, undo, chaos) get the same did-you-mean as the CLI."""

    def test_typos(self):
        vm = _ctx("vmware", name="w2dym")
        for call in (lambda: pl.resolve(["kedaa"], vm), lambda: pl.info("kedaa", None),
                     lambda: pl.removal_plan(["kedaa"], vm, {})):
            with self.assertRaises(SystemExit) as cm:
                call()
            self.assertIn("did you mean keda", str(cm.exception))
        with self.assertRaises(SystemExit) as cm:
            pl.resolve(["zzzz"], vm)
        self.assertNotIn("did you mean", str(cm.exception))


class CatalogTextTests(unittest.TestCase):
    def test_group_and_notes_say_what_happens(self):
        # docs-skills#19: the security group brings the cluster CA issuer, and says so without the old 'dev CA' wording
        self.assertNotIn("dev CA", pl.GROUPS["security"])
        self.assertIn("cluster CA issuer", pl.GROUPS["security"])
        self.assertIn("cert-manager-issuer", pl.GROUP_EXTRA_MEMBERS["security"])
        # aws#5: external-secrets is scoped to the environment's prefix on AWS; EKS gets its default class from cloudseed
        self.assertIn("external_secrets_prefixes", pl.CATALOG["external-secrets"]["notes"])
        self.assertIn("<name>-<env>/", pl.CATALOG["external-secrets"]["notes"])
        self.assertIn("ebs-csi-default-sc", pl.CATALOG["local-path-provisioner"]["notes"])
        self.assertEqual(pl.CATALOG["velero"]["values"]["default"]["serviceAccount.server.name"], "velero")

    def test_unreachable_hint_names_the_environment(self):   # docs-skills#27
        hint = pl._unreachable_hint(_ctx("aws", "eks", name="w2hint"))
        self.assertIn("cs vpn connect aws --env w2hint", hint)
        self.assertIn("cs k8s tunnel aws --env w2hint", hint)

    def test_labels_and_annotations_are_strings(self):   # platform-catalog#3 / aws#6
        for item, target, distro, key in (("istio-gateway", "aws", "eks", "aws-load-balancer-internal=true"),
                                          ("ingress-nginx", "aws", "eks", "aws-load-balancer-internal=true"),
                                          ("velero", "azure", "aks", "nodeAgent.podLabels.azure"),
                                          ("external-secrets", "azure", "aks", "podLabels.azure"),
                                          ("external-dns", "azure", "aks", "podLabels.azure")):
            c = _ctx(target, distro, outputs={"kubernetes_cluster_name": "c1", "kubernetes_distro": distro}, name=f"w2s{target}")
            args = pl._values_args(pl.CATALOG[item], c)
            hit = [i for i, a in enumerate(args) if key in a]
            self.assertTrue(hit, (item, key))
            self.assertTrue(all(args[i - 1] == "--set-string" for i in hit), (item, args))


class LbRangePlanTests(unittest.TestCase):
    """vmware#3: the MetalLB pool also clears the workers the settings plan (not only those the stack reported)."""

    def test_planned_workers_move_the_pool_up(self):
        with mock.patch.object(pl, "VMWARE_PREFS", (Path("/nonexistent-cloudseed"),)):
            self.assertEqual(pl._lb_range("10.100.0.0/24", {}, "vmware"), "10.100.0.100-10.100.0.127")
            lo = pl._lb_range("10.100.0.0/24", {"kubernetes_worker_ips": ["10.100.0.40"]}, "vmware",
                              {"enable_kubernetes": True, "kubernetes_workers": 70}).split("-")[0]
            self.assertEqual(lo, "10.100.0.110")
            self.assertEqual(pl._planned_top({"enable_kubernetes": "true", "kubernetes_control_planes": 3, "kubernetes_workers": 0,
                                              "workload_count": 2}), 22)
            vm = _ctx("vmware", name="w2lb", vars_={"enable_kubernetes": True, "kubernetes_workers": 65})
            self.assertEqual(vm.placeholders()["lb_range"], "10.100.0.105-10.100.0.127")


class AwsFipsEndpointTests(unittest.TestCase):
    """aws#7: in FIPS mode the kubeconfig fetch and the token command it installs use the FIPS endpoints."""

    KC = {"users": [{"name": "arn:aws:eks:us-east-1:1:cluster/c1",
                     "user": {"exec": {"command": "aws", "args": ["--region", "us-east-1", "eks", "get-token", "--cluster-name", "c1"]}}},
                    {"name": "other", "user": {"exec": {"command": "aws", "args": ["eks", "get-token", "--cluster-name", "c2"]}}},
                    {"name": "gke", "user": {"exec": {"command": "gke-gcloud-auth-plugin"}}}]}

    def test_platform_tools_run_with_the_fips_endpoint(self):
        self.assertEqual(_ctx("aws", "eks", fips=True, name="w2f1").procenv().get("AWS_USE_FIPS_ENDPOINT"), "true")
        self.assertNotIn("AWS_USE_FIPS_ENDPOINT", _ctx("aws", "eks", fips=False, name="w2f2").procenv())
        self.assertNotIn("AWS_USE_FIPS_ENDPOINT", _ctx("gcp", "gke", fips=True, name="w2f3").procenv())
        self.assertEqual(services.cloud_cli_env("aws", {"vars": {"fips_mode": "true"}}).get("AWS_USE_FIPS_ENDPOINT"), "true")
        self.assertNotIn("AWS_USE_FIPS_ENDPOINT", services.cloud_cli_env("aws", {"vars": {"fips_mode": False}}))

    def test_only_this_clusters_token_user_is_pinned(self):
        self.assertEqual(services._eks_token_users(self.KC, "c1"), ["arn:aws:eks:us-east-1:1:cluster/c1"])
        calls = []

        def fake(cmd, **kw):
            calls.append(cmd)
            return _cp(0, json.dumps(self.KC)) if cmd[1:3] == ["config", "view"] else _cp(0)
        with mock.patch.object(services.deps, "find", return_value="kubectl"), mock.patch.object(services.subprocess, "run", fake):
            self.assertTrue(services.pin_fips_token_endpoint(Path("/tmp/kc"), "c1"))
        sets = [c for c in calls if c[1:3] == ["config", "set-credentials"]]
        self.assertEqual(sets, [["kubectl", "config", "set-credentials", "arn:aws:eks:us-east-1:1:cluster/c1",
                                 "--exec-env=AWS_USE_FIPS_ENDPOINT=true"]])
        with mock.patch.object(services.deps, "find", return_value=None):
            self.assertFalse(services.pin_fips_token_endpoint(Path("/tmp/kc"), "c1"))

    def test_fetch_uses_the_fips_endpoint_and_pins_once(self):
        env = paths.Env("aws", "w2fips")
        shutil.rmtree(env.dir, ignore_errors=True)            # a stamp from an earlier run would skip the fetch
        env.create_dirs()
        cfg = {"env": "w2fips", "region": "us-east-1", "workdir": str(env.dir), "vars": {"fips_mode": True}}
        outputs = {"kubernetes_cluster_name": "c1", "kubernetes_endpoint": "https://abc.eks.amazonaws.com"}
        seen = {"fetch_env": None, "pins": 0}

        def fake(cmd, **kw):
            if cmd[1:3] == ["eks", "update-kubeconfig"]:
                seen["fetch_env"] = kw["env"]
                Path(kw["env"]["KUBECONFIG"]).write_text("{}")
            return _cp(0)

        def pin(kc, cluster):
            seen["pins"] += 1
            return True
        with mock.patch.object(services, "ensure_tool", return_value="aws"), mock.patch.object(services.subprocess, "run", fake), \
                mock.patch.object(services, "_tcp_open", return_value=True), mock.patch.object(services, "pin_fips_token_endpoint", pin):
            services.ensure_kubeconfig(clouds.get("aws"), env, cfg, outputs)
            services.ensure_kubeconfig(clouds.get("aws"), env, cfg, outputs)
        self.assertEqual(seen["fetch_env"].get("AWS_USE_FIPS_ENDPOINT"), "true")
        self.assertEqual(seen["pins"], 1)                     # remembered in the stamp; a re-fetch pins again


class ServicesOutputTests(unittest.TestCase):
    def _vpn_env(self, name, vpn_type="openvpn", outputs=None):
        env = paths.Env("gcp", name)
        env.create_dirs()
        cfg = {"env": name, "cloud": "gcp", "network_cidr": "10.0.0.0/16", "vars": {"vpn_type": vpn_type}, "workdir": str(env.dir)}
        out = dict({"vpn_public_ip": "203.0.113.7", "vpn_type": vpn_type}, **(outputs or {}))
        return env, cfg, out

    def test_redaction_sees_the_whole_key_before_the_tail_is_kept(self):   # agentic#9
        env = paths.Env("aws", "w2red")
        env.create_dirs()
        cfg = {"env": "w2red", "region": "us-east-1", "vars": {}}
        err = "An error occurred\n" + PEM + "\nerror: boom\n"
        with mock.patch.object(services, "ensure_tool", return_value="aws"), \
                mock.patch.object(services.subprocess, "run", return_value=_cp(1, "", err)):
            with self.assertRaises(SystemExit) as cm:
                services._fetch_kubeconfig(clouds.get("aws"), cfg, {"kubernetes_cluster_name": "c1"}, env.dir / "k8s" / "kc")
        self.assertNotIn("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB", str(cm.exception))

    def test_vpn_users_failing_ssh_is_an_error(self):   # aws#1
        env, cfg, out = self._vpn_env("w2users")
        with mock.patch.object(services.subprocess, "run", return_value=_cp(255, "", "ssh: connect to host 203.0.113.7 port 22: Operation timed out")):
            with self.assertRaises(SystemExit) as cm:
                services.list_users(clouds.get("gcp"), env, cfg, out)
        self.assertIn("update-ip gcp --env w2users", str(cm.exception))
        with mock.patch.object(services.subprocess, "run", return_value=_cp(0, "alice\nbob\n")):
            self.assertEqual(services.list_users(clouds.get("gcp"), env, cfg, out), ["alice", "bob"])
        env, cfg, out = self._vpn_env("w2users2", vpn_type="tailscale")
        with mock.patch.object(services.subprocess, "run") as run:
            with self.assertRaises(SystemExit):
                services.list_users(clouds.get("gcp"), env, cfg, out)
        run.assert_not_called()

    def test_vpn_connect_names_the_gke_api_route(self):   # gcp#17
        env, cfg, out = self._vpn_env("w2route", outputs={"kubernetes_master_cidr": "172.16.0.0/28"})
        profile = services.vpn_dir(env) / "me.ovpn"
        profile.write_text("client\n")
        log = services.vpn_dir(env) / "openvpn.log"

        def start(cmd, **kw):
            with open(log, "a") as fh:
                fh.write("Initialization Sequence Completed\n")
            return 0
        with mock.patch.object(services, "_running", return_value=None), mock.patch.object(services, "ensure_openvpn_client", return_value="openvpn"), \
                mock.patch.object(services.subprocess, "call", start), mock.patch.object(services.time, "sleep"), _silenced() as o:
            self.assertEqual(services.connect(clouds.get("gcp"), env, cfg, out, None), 0)
        self.assertIn("10.0.0.0/16 and the GKE API (172.16.0.0/28) are reachable", o.getvalue())
        with mock.patch.object(services, "_running", return_value=4242), _silenced() as o:
            services.connect(clouds.get("gcp"), env, cfg, out, None)
        self.assertIn("cloudseed vpn disconnect gcp --env w2route", o.getvalue())
        env2, cfg2, out2 = self._vpn_env("w2route2")
        with mock.patch.object(services, "_running", return_value=4242), _silenced() as o:
            services.connect(clouds.get("gcp"), env2, cfg2, out2, None)
        self.assertNotIn("GKE", o.getvalue())


class ManagedInstallConsentTests(unittest.TestCase):
    """mcp#1: the Databricks/Snowflake CLIs are never installed from an agent/MCP session, nor because the passthrough
    command happens to carry --auto-approve."""

    def test_agent_sessions_never_install(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "mcp"}), mock.patch.object(managed.deps, "find", return_value=None), \
                mock.patch.object(services.deps, "install") as inst, mock.patch.object(services.ui, "interactive", return_value=True):
            with self.assertRaises(SystemExit) as cm:
                managed.ensure_tool("snowflake")
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("cloudseed install snow", str(cm.exception))
        inst.assert_not_called()

    def test_vendor_auto_approve_is_not_consent(self):
        clean = {k: v for k, v in os.environ.items() if k not in ("CLOUDSEED_AGENT", "CLOUDSEED_AUTO_INSTALL")}
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(managed.deps, "find", return_value=None), \
                mock.patch.object(services.deps, "find", return_value=None), mock.patch.object(services.deps, "install") as inst, \
                mock.patch.object(services.ui, "interactive", return_value=False), \
                mock.patch.object(services.sys, "argv", ["cloudseed", "databricks", "bundle", "deploy", "--auto-approve"]):
            with self.assertRaises(SystemExit) as cm:
                managed.ensure_tool("databricks")
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("cloudseed install databricks", str(cm.exception))
        inst.assert_not_called()
        # the explicit opt-in still works, and so does kubectl/helm's own --auto-approve
        with mock.patch.dict(os.environ, dict(clean, CLOUDSEED_AUTO_INSTALL="1"), clear=True), \
                mock.patch.object(managed.deps, "find", side_effect=[None, None, "/bin/snow"]), \
                mock.patch.object(services.deps, "install") as inst, mock.patch.object(services.ui, "interactive", return_value=False), _silenced():
            self.assertEqual(managed.ensure_tool("snowflake"), "/bin/snow")
        inst.assert_called_once_with("snow")
        with mock.patch.object(services.deps, "find", side_effect=[None, "/bin/helm"]), mock.patch.object(services.deps, "install"), \
                mock.patch.object(services.ui, "interactive", return_value=False), \
                mock.patch.object(services.sys, "argv", ["cloudseed", "platform", "install", "keda", "--auto-approve"]), _silenced():
            self.assertEqual(services.ensure_tool("helm", "x"), "/bin/helm")


if __name__ == "__main__":
    unittest.main()
