"""Regression tests for the platform engine, kubeconfig/tunnel/VPN services and managed data platforms.

Offline and fast: helm/kubectl/ssh/snow are never run against anything real (calls are recorded or answered by fakes).
"""

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, paths, ui  # noqa: E402
from cloudseed import managed, platform as pl, services  # noqa: E402


def _ctx(target="vmware", distro="rke2", outputs=None, fips=False, name="pl"):
    env = paths.Env(target, name)
    env.create_dirs()
    cfg = {"env": name, "region": "r", "network_cidr": "10.100.0.0/24",
           "vars": {"fips_mode": fips, "project_id": "p", "subscription_id": "s"}, "platform_prereqs": []}
    if outputs is None:
        outputs = {"kubernetes_distro": distro} if target == "vmware" else {"kubernetes_cluster_name": "c"}
    return pl.Cluster(clouds.get(target), env, cfg, outputs, env.dir / "k8s" / "kubeconfig")


def _quiet():
    return contextlib.redirect_stdout(io.StringIO())


def _flow_balanced(text):
    """Every line's {} and [] must balance (all cloudseed manifests keep flow collections on one line). The contents of
    block scalars (`config.alloy: |` - an Alloy config) are not YAML and are skipped."""
    block = None
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip())
        if block is not None:
            if not line.strip() or indent > block:
                continue
            block = None
        if re.search(r":\s*[|>][-+]?\s*$", line):
            block = indent
            continue
        body = re.sub(r'"[^"]*"', '""', line)
        if body.count("{") != body.count("}") or body.count("[") != body.count("]"):
            return line
    return None


def _shape(text):
    """A manifest's structure without its YAML style: flow ({a: {b: c}}) and block (a:\n  b: c) forms compare equal."""
    t = re.sub(r"(?m)^(\s*)- ", r"\1", text)
    t = re.sub(r'[\[\]{}",]', " ", t)
    return re.sub(r"\s+", " ", t)


class RenderTests(unittest.TestCase):
    def test_every_post_manifest_renders_valid_flow_yaml_on_every_target(self):
        for target, distro in (("vmware", "rke2"), ("aws", "eks"), ("gcp", "gke"), ("azure", "aks")):
            ctx = _ctx(target, distro)
            for name in pl.POST_MANIFESTS:
                text = pl.render_manifest(name, ctx)
                self.assertIsNone(_flow_balanced(text), f"{name} on {target}: unbalanced flow collection")
                self.assertNotRegex(text, r"\{(" + "|".join(ctx.placeholders()) + r")\}", f"{name} on {target}: unresolved placeholder")
        vm = _ctx("vmware")
        self.assertIn("selfSigned: {}", pl.render_manifest("selfsigned-issuer", vm))   # (block style since platform-catalog)
        # (platform-catalog writes several of these in block style: compare the structure, not the style)
        self.assertIn(_shape("allowedRoutes: {namespaces: {from: All}}"), _shape(pl.render_manifest("cloudseed-gateway", vm)))
        self.assertIn(_shape("selector: {matchLabels: {app: spark-history-server}}"), _shape(pl.render_manifest("spark-history-server", vm)))
        aws = _ctx("aws", "eks", {"kubernetes_cluster_name": "c"})
        self.assertIn(_shape("subnetSelectorTerms: [{tags: {karpenter.sh/discovery: c}}]"), _shape(pl.render_manifest("karpenter-default", aws)))
        az = _ctx("azure", "aks", {"kubernetes_cluster_name": "c", "tenant_id": "t", "subscription_id": "s", "resource_group_name": "rg"})
        line = [l for l in pl.render_manifest("external-dns-azure-config", az).splitlines() if "tenantId" in l][0]
        self.assertEqual(json.loads(line), {"tenantId": "t", "subscriptionId": "s", "resourceGroup": "rg", "useWorkloadIdentityExtension": True})

    def test_pyyaml_parses_every_rendered_manifest_when_available(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed (the flow-balance test above still covers the regression)")
        for target, distro in (("vmware", "rke2"), ("aws", "eks"), ("azure", "aks")):
            ctx = _ctx(target, distro)
            for name in pl.POST_MANIFESTS:
                docs = [d for d in yaml.safe_load_all(pl.render_manifest(name, ctx)) if d]
                self.assertTrue(all("kind" in d for d in docs), name)

    def test_substitution_is_single_pass_and_leaves_unknown_braces(self):
        out = pl._substitute("a {x} {y} {mon,tue} {} {z}", {"x": "{y}", "y": "Y"})
        self.assertEqual(out, "a {y} Y {mon,tue} {} {z}")

    def test_apply_manifest_applies_the_rendered_file(self):
        ctx = _ctx("vmware")
        calls = []

        def fake_run(cmd, c, check=True):
            calls.append(cmd)
            c.last_output = ""
            return 0
        with mock.patch.object(pl, "_run", fake_run), mock.patch.object(pl.subprocess, "run",
                                                                        return_value=subprocess.CompletedProcess([], 0, "", "")), _quiet():
            pl._apply_manifest(ctx, "kubectl", "selfsigned-issuer", "cert-manager", wait_ns=False)
        path = ctx.workdir / "selfsigned-issuer.yaml"
        self.assertIn(["kubectl", "apply", "-f", str(path)], calls)
        self.assertIn("selfSigned: {}", path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class ValuesTests(unittest.TestCase):
    def test_brace_lists_survive_and_labels_annotations_stay_strings(self):
        vm = _ctx("vmware")
        args = pl._values_args(pl.CATALOG["kured"], vm)
        self.assertIn("configuration.rebootDays[4]=fri", args)       # kured's days are indexed values (platform-catalog)
        brace = pl._values_args({"values": {"default": {"configuration.rebootDays": "{mon,tue,wed,thu,fri}"}}}, vm)
        self.assertIn("configuration.rebootDays={mon,tue,wed,thu,fri}", brace)   # a Helm brace list is never taken for a placeholder
        az = _ctx("azure", "aks", {"kubernetes_cluster_name": "c", "kubernetes_velero_client_id": "cid"})
        args = pl._values_args(pl.CATALOG["velero"], az)
        pairs = list(zip(args[::2], args[1::2]))
        self.assertIn(("--set-string", "podLabels.azure\\.workload\\.identity/use=true"), pairs)
        self.assertIn(("--set-string", "nodeAgent.podLabels.azure\\.workload\\.identity/use=true"), pairs)
        self.assertIn(("--set", "serviceAccount.server.name=velero"), pairs)
        self.assertIn(("--set", "deployNodeAgent=true"), pairs)          # real booleans stay booleans
        aws = _ctx("aws", "eks", {"kubernetes_cluster_name": "c"})
        pairs = list(zip(*[iter(pl._values_args(pl.CATALOG["ingress-nginx"], aws))] * 2))
        self.assertIn(("--set-string", "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-internal=true"), pairs)
        self.assertIn("aws-load-balancer-internal", aws.placeholders()["lb_annotations"])
        self.assertIn("aws-load-balancer-scheme", aws.placeholders()["lb_annotations"])

    def test_chaos_dashboard_is_token_protected_and_not_a_nodeport(self):
        args = " ".join(pl._values_args(pl.CATALOG["chaos-mesh"], _ctx("vmware")))
        self.assertIn("dashboard.securityMode=true", args)
        self.assertIn("dashboard.service.type=ClusterIP", args)
        self.assertIn("chaos-dashboard-admin", pl.CATALOG["chaos-mesh"]["post"])
        self.assertIn("create token cloudseed-chaos-admin", pl.UIS["chaos-mesh"][4])

    def test_ui_routes_are_https_only_with_a_redirect(self):
        text = pl.HTTPROUTE_TEMPLATE.format(name="x", ns="n", host="x.d", svc="s", port=80)
        self.assertIn("sectionName: https", text)
        self.assertIn("RequestRedirect", text)
        self.assertIsNone(_flow_balanced(text))

    def test_platform_secrets_are_redacted_by_value(self):
        ctx = _ctx("vmware")
        pw = ctx.placeholders()["sonar_passcode"]
        self.assertNotIn(pw, pl._redact(f"--set monitoringPasscode={pw}"))
        self.assertNotIn(ctx.secret("minio_password"), pl._redact(f"mc alias set m http://x admin '{ctx.secret('minio_password')}'"))


class LbRangeTests(unittest.TestCase):
    def _prefs(self, dhcp="yes", rng="192.168.160.128 192.168.160.254"):
        d = Path(tempfile.mkdtemp())
        (d / "vmnet1").mkdir()
        (d / "networking").write_text(f"VERSION=1,0\nanswer VNET_1_DHCP {dhcp}\n")
        (d / "vmnet1" / "dhcpd.conf").write_text(f"subnet 192.168.160.0 netmask 255.255.255.0 {{\n\trange {rng};\n}}\n")
        return (d,)

    def test_pool_stays_below_the_vmnet_dhcp_range_and_above_static_ips(self):
        out = {"private_vmnet": "vmnet1", "kubernetes_worker_ips": ["192.168.160.40", "192.168.160.41"]}
        with mock.patch.object(pl, "VMWARE_PREFS", self._prefs()):
            self.assertEqual(pl._lb_range("192.168.160.0/24", out, "vmware"), "192.168.160.100-192.168.160.127")
            many = dict(out, kubernetes_worker_ips=[f"192.168.160.{40 + i}" for i in range(70)])
            lo, hi = pl._lb_range("192.168.160.0/24", many, "vmware").split("-")
            self.assertGreater(int(lo.split(".")[-1]), 109)
            self.assertLess(int(hi.split(".")[-1]), 128)
        with mock.patch.object(pl, "VMWARE_PREFS", self._prefs(dhcp="no")):
            self.assertEqual(pl._lb_range("192.168.160.0/24", out, "vmware"), "192.168.160.199-192.168.160.249")
        with mock.patch.object(pl, "VMWARE_PREFS", (Path("/nonexistent-cloudseed"),)):
            self.assertEqual(pl._lb_range("10.100.0.0/24", {}, "vmware"), "10.100.0.100-10.100.0.127")


def _rel(status="deployed", chart="c-1", revision="1"):
    return {"status": status, "chart": chart, "revision": revision}


class ReleaseStateTests(unittest.TestCase):
    def test_failed_is_retried_and_pending_blocks_with_a_remedy(self):
        vm = _ctx("vmware")
        self.assertFalse(pl._already_installed(pl.CATALOG["trino"], "trino", {"trino/trino": _rel("failed")}))
        self.assertTrue(pl._already_installed(pl.CATALOG["trino"], "trino", {"trino/trino": _rel()}))
        e = {x["item"]: x for x in pl.plan(["trino"], vm, releases={"trino/trino": _rel("failed")})}
        self.assertEqual(e["trino"]["action"], "install")
        self.assertTrue(any("failed" in r for r in e["trino"]["reasons"]))
        e = {x["item"]: x for x in pl.plan(["trino"], vm, releases={"trino/trino": _rel("pending-install")})}
        self.assertEqual(e["trino"]["action"], "blocked-pending")
        self.assertIn("cs helm uninstall trino -n trino", e["trino"]["reasons"][0])
        e = {x["item"]: x for x in pl.plan(["trino"], vm, releases={"trino/trino": _rel("pending-upgrade", revision="3")})}
        self.assertIn("cs helm rollback trino -n trino", e["trino"]["reasons"][0])
        with _quiet():
            pl.print_plan(pl.plan(["trino"], vm, releases={"trino/trino": _rel("pending-install")}), vm)   # no KeyError

    def test_install_refuses_while_a_release_is_pending(self):
        vm = _ctx("vmware")
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value={"trino/trino": _rel("pending-install")}), \
                mock.patch.object(pl, "install_one") as one, _quiet(), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                pl.install(["trino"], vm)
            one.assert_not_called()

    def test_install_one_skip_branch_handles_probe_items(self):
        vm = _ctx("vmware")
        with _quiet():   # used to raise KeyError 'cert-manager/cert-manager-issuer'
            pl.install_one("cert-manager-issuer", vm, wait=True, releases={"probe:cert-manager-issuer": {"status": "present", "chart": "clusterissuer/cloudseed-ca"}})

    def test_status_marks_failed_and_pending(self):
        vm = _ctx("vmware")
        buf = io.StringIO()
        with mock.patch.object(pl, "installed_releases", return_value={"trino/trino": _rel("failed"), "keda/keda": _rel("pending-install")}), \
                contextlib.redirect_stdout(buf):
            pl.status(vm)
        out = buf.getvalue()
        self.assertIn("repair: cs platform install trino", out)
        self.assertIn("cs helm uninstall keda -n keda", out)
        self.assertIn("then cs platform install keda", re.sub(r"[\s│]+", " ", out))


class UnreachableTests(unittest.TestCase):
    def test_helm_failure_is_never_nothing_installed(self):
        vm = _ctx("vmware")
        failing = subprocess.CompletedProcess([], 1, "", "Error: Kubernetes cluster unreachable: dial tcp 127.0.0.1:7579: connect: connection refused\n")
        with mock.patch.object(pl.deps, "find", return_value="helm"), mock.patch.object(pl.subprocess, "run", return_value=failing):
            with self.assertRaises(pl.ClusterUnreachable) as cm:
                pl.installed_releases(vm)
            self.assertIn("not reachable", str(cm.exception))
            with contextlib.redirect_stderr(io.StringIO()), _quiet():
                with self.assertRaises(SystemExit):
                    pl.status(vm)
                with self.assertRaises(SystemExit):
                    pl.plan(["keda"], vm)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                pl.info("keda", vm)
            self.assertIn("unknown", buf.getvalue())

    def test_helm_list_asks_for_every_status(self):
        vm = _ctx("vmware")
        seen = []

        def fake(cmd, **kw):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 0 if cmd[1] == "list" else 1, "[]", "")
        with mock.patch.object(pl.deps, "find", side_effect=lambda t: t), mock.patch.object(pl.subprocess, "run", side_effect=fake):
            pl.installed_releases(vm)
        self.assertTrue({"--deployed", "--failed", "--pending"} <= set(seen[0]))


class PlanPruneTests(unittest.TestCase):
    def test_dependencies_of_skipped_items_are_not_installed(self):
        vm = _ctx("vmware")
        a = {e["item"]: e["action"] for e in pl.plan(["opencost"], vm, releases={"kubecost/kubecost-cost-analyzer": _rel()})}
        self.assertEqual(a["opencost"], "skip-conflict")
        self.assertEqual(a["kube-prometheus-stack"], "skip-unneeded")
        entries = pl.plan(["kubecost-cost-analyzer", "opencost"], vm, releases={})
        a = {e["item"]: e for e in entries}
        self.assertEqual(a["kube-prometheus-stack"]["action"], "skip-unneeded")
        self.assertEqual(a["kubecost-cost-analyzer"]["sets"], {})          # not wired to a Prometheus that is not coming
        a = {e["item"]: e for e in pl.plan(["kube-prometheus-stack", "kubecost-cost-analyzer", "opencost"], vm, releases={})}
        self.assertEqual(a["kube-prometheus-stack"]["action"], "install")   # named explicitly: kept
        self.assertIn("prometheus.enabled", a["kubecost-cost-analyzer"]["sets"])
        with _quiet():
            pl.print_plan(entries, vm)

    def test_fips_skips_free_their_dependencies(self):
        fvm = _ctx("vmware", fips=True)
        a = {e["item"]: e["action"] for e in pl.plan(["airflow"], fvm, releases={})}
        self.assertEqual(a["airflow"], "skip-fips")
        self.assertEqual(a["local-path-provisioner"], "skip-unneeded")
        faws = _ctx("aws", "eks", {"kubernetes_cluster_name": "c"}, fips=True)
        a = {e["item"]: e["action"] for e in pl.plan(["ai"], faws, releases={})}
        self.assertNotEqual(a.get("gateway-api"), "install")
        self.assertNotEqual(a.get("cert-manager"), "install")


class SetVersionTests(unittest.TestCase):
    def _install(self, names, ctx, **kw):
        calls = []
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value={}), \
                mock.patch.object(pl, "install_one", side_effect=lambda item, c, wait, version=None, sets=None, rel=None: calls.append((item, version, sets))), \
                _quiet(), contextlib.redirect_stderr(io.StringIO()):
            pl.install(names, ctx, **kw)
        return calls

    def test_set_and_version_go_to_the_named_item_only(self):
        vm = _ctx("vmware")
        calls = self._install(["goldilocks"], vm, version="0.0.1", extra_sets=["dashboard.replicaCount=3"])
        by = {c[0]: c for c in calls}
        self.assertEqual(by["vpa"][1], None)
        self.assertEqual(by["vpa"][2], [])
        self.assertEqual(by["goldilocks"][1], "0.0.1")
        self.assertEqual(by["goldilocks"][2], ["dashboard.replicaCount=3"])
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):   # kagent needs an LLM key (platform-catalog)
            calls = self._install(["kagent"], vm, extra_sets=["providers.default=openAI"])
        by = {c[0]: c for c in calls}
        self.assertIn("providers.default=openAI", by["kagent"][2])
        self.assertNotIn("providers.default=openAI", by["kagent-crds"][2])

    def test_set_with_a_group_is_refused_but_mode_is_fine(self):
        vm = _ctx("vmware")
        with self.assertRaises(SystemExit):
            self._install(["scaling"], vm, version="1.0")
        calls = self._install(["security"], vm, extra_sets=["mode=sidecar"])
        self.assertNotIn("ztunnel", [c[0] for c in calls])


class FakeCluster:
    """Stands in for helm/kubectl: records every _run, answers the read-only kubectl queries."""

    def __init__(self, leftovers=None, helm_fail=None, gateway_objects="", children=None, delete_fail=()):
        self.calls = []
        self.leftovers = leftovers or {}
        self.helm_fail = helm_fail or {}
        self.gateway_objects = gateway_objects
        self.children = children or {}      # ns -> jsonpath lines "apiVersion|Kind|name|deletionTimestamp|ownerKinds"
        self.delete_fail = delete_fail      # manifest names whose delete times out

    def run(self, cmd, ctx, check=True):
        self.calls.append(list(cmd))
        rc, out = 0, ""
        if cmd[0] == "helm" and cmd[1] == "uninstall":
            rc, out = self.helm_fail.get(cmd[2], (0, f'release "{cmd[2]}" uninstalled\n'))
        elif "delete" in cmd:
            out = 'thing "x" deleted\n'
            if any(f"/{m}.delete.yaml" in " ".join(cmd) for m in self.delete_fail):
                rc, out = 1, "error: timed out waiting for the condition\n"
        ctx.last_output = out
        return rc

    def sub(self, cmd, **kw):
        if cmd[1:3] == ["get", "namespace"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[1] == "api-resources":
            names = "gatewayclasses.gateway.networking.k8s.io httproutes.gateway.networking.k8s.io" if "--api-group=gateway.networking.k8s.io" in cmd else "pods configmaps persistentvolumeclaims"
            return subprocess.CompletedProcess(cmd, 0, names, "")
        if cmd[1] == "get" and "-n" in cmd and any(c.startswith("jsonpath=") for c in cmd):
            return subprocess.CompletedProcess(cmd, 0, self.children.get(cmd[cmd.index("-n") + 1], ""), "")
        if cmd[1] == "get" and "-n" in cmd and "name" in cmd:
            ns = cmd[cmd.index("-n") + 1]
            return subprocess.CompletedProcess(cmd, 0, self.leftovers.get(ns, "configmap/kube-root-ca.crt\n"), "")
        if cmd[1] == "get" and "-A" in cmd:
            return subprocess.CompletedProcess(cmd, 0, self.gateway_objects, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def uninstall(self, names, ctx, releases, **kw):
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value=releases), \
                mock.patch.object(pl, "_run", self.run), mock.patch.object(pl.subprocess, "run", self.sub), \
                mock.patch.object(pl.deps, "find", side_effect=lambda t: t), _quiet(), contextlib.redirect_stderr(io.StringIO()):
            return pl.uninstall(names, ctx, **kw)

    def touched(self, what):
        return [c for c in self.calls if what in " ".join(c)]


class UninstallTests(unittest.TestCase):
    def test_only_the_named_item_goes_and_not_its_dependencies(self):
        vm = _ctx("vmware")
        fake = FakeCluster()
        removed = fake.uninstall(["goldilocks"], vm, {"vpa/vpa": _rel(), "goldilocks/goldilocks": _rel()})
        self.assertEqual(removed, ["goldilocks"])
        self.assertTrue(fake.touched("helm uninstall goldilocks"))
        self.assertFalse(fake.touched("uninstall vpa"))

    def test_items_that_are_not_installed_are_reported_not_removed(self):
        vm = _ctx("vmware")
        fake = FakeCluster()
        removed = fake.uninstall(["airflow"], vm, {"probe:local-path-provisioner": {"status": "present"}})
        self.assertEqual(removed, [])
        self.assertEqual(fake.calls, [])       # the default StorageClass is never touched

    def test_refuses_to_pull_a_dependency_from_under_an_installed_item(self):
        vm = _ctx("vmware")
        fake = FakeCluster()
        rel = {"cert-manager/cert-manager": _rel(), "probe:cert-manager-issuer": {"status": "present"}}
        with self.assertRaises(SystemExit):
            fake.uninstall(["cert-manager"], vm, rel)
        self.assertEqual(fake.calls, [])
        removed = fake.uninstall(["cert-manager"], vm, rel, force=True)
        self.assertEqual(removed, ["cert-manager"])

    def test_gateway_objects_go_before_the_controller_and_shared_deps_stay(self):
        vm = _ctx("vmware")
        fake = FakeCluster()
        rel = {"envoy-gateway-system/eg": _rel(), "cert-manager/cert-manager": _rel(), "metallb-system/metallb": _rel(),
               "probe:gateway-api": {"status": "present"}, "probe:cert-manager-issuer": {"status": "present"}}
        removed = fake.uninstall(["envoy-gateway"], vm, rel)
        self.assertEqual(removed, ["envoy-gateway"])
        flat = [" ".join(c) for c in fake.calls]
        gw = next(i for i, c in enumerate(flat) if "cloudseed-gateway.delete.yaml" in c and "delete" in c)
        eg = next(i for i, c in enumerate(flat) if c.startswith("helm uninstall eg"))
        self.assertLess(gw, eg)
        self.assertTrue(all("--timeout" in c or "--wait=false" in c for c in flat if " delete " in c))
        for dep in ("uninstall cert-manager", "uninstall metallb", "experimental-install.yaml"):
            self.assertFalse(fake.touched(dep), dep)

    def test_crd_bundle_removal_is_refused_while_foreign_gateway_objects_exist(self):
        vm = _ctx("vmware")
        fake = FakeCluster(gateway_objects="HTTPRoute   shop   web\nHTTPRoute   argocd   cloudseed-argocd\n")
        with self.assertRaises(SystemExit):
            fake.uninstall(["gateway-api"], vm, {"probe:gateway-api": {"status": "present"}})
        self.assertFalse(fake.touched("experimental-install.yaml"))

    def test_helm_failures_are_reported_and_not_recorded(self):
        vm = _ctx("vmware")
        fake = FakeCluster(helm_fail={"keda": (1, "Error: uninstall: timed out waiting\n"), "vpa": (1, "Error: uninstall: Release not loaded: vpa: release: not found\n")})
        rel = {"keda/keda": _rel(), "vpa/vpa": _rel(), "reloader/reloader": _rel()}
        removed = fake.uninstall(["keda", "vpa", "reloader"], vm, rel, strict=False)     # the CLI: report, exit 1
        self.assertEqual(removed, ["reloader"])
        self.assertEqual(vm.failures, ["keda"])
        with self.assertRaises(SystemExit):                  # undo and other internal callers: never "done"
            FakeCluster(helm_fail={"keda": (1, "Error: uninstall: timed out waiting\n")}).uninstall(["keda"], vm, rel)

    def test_dependencies_of_an_item_that_could_not_be_removed_stay(self):
        vm = _ctx("vmware")
        fake = FakeCluster(delete_fail=("cloudseed-gateway",))
        rel = {"envoy-gateway-system/eg": _rel(), "cert-manager/cert-manager": _rel(), "metallb-system/metallb": _rel(),
               "probe:cert-manager-issuer": {"status": "present"}}
        removed = fake.uninstall(["envoy-gateway", "metallb", "cert-manager-issuer", "cert-manager"], vm, rel, strict=False)
        self.assertEqual(removed, [])
        self.assertEqual(vm.failures, ["envoy-gateway", "metallb", "cert-manager-issuer", "cert-manager"])
        self.assertFalse(fake.touched("helm uninstall"))     # nothing pulled from under the Gateway that is still there

    def test_chart_namespaces_in_manifests_are_not_deleted_wholesale(self):
        vm = _ctx("vmware")
        fake = FakeCluster(leftovers={"velero": "schedule.velero.io/daily\nbackup.velero.io/daily-1\n"})
        fake.uninstall(["velero"], vm, {"velero/velero": _rel()})
        text = (vm.workdir / "velero-minio-credentials.delete.yaml").read_text()
        self.assertNotIn("kind: Namespace", text)            # the Secret goes, the namespace (with backups) stays
        self.assertIn("kind: Secret", text)
        self.assertFalse(fake.touched("delete namespace velero"))
        self.assertIn("kind: Namespace", pl._deletion_file(vm, "cloudseed-gateway").read_text())   # cloudseed's own

    def test_terminating_and_owned_pods_do_not_keep_a_namespace(self):
        vm = _ctx("vmware")
        fake = FakeCluster(
            leftovers={"reloader": "pod/reloader-7d9-x\nreplicaset.apps/reloader-7d9\n", "keda": "pod/debug\n"},
            children={"reloader": "v1|Pod|reloader-7d9-x|2026-09-24T01:00:00Z|ReplicaSet\napps/v1|ReplicaSet|reloader-7d9||Deployment\n",
                      "keda": "v1|Pod|debug||\n"})
        fake.uninstall(["reloader", "keda"], vm, {"reloader/reloader": _rel(), "keda/keda": _rel()})
        self.assertTrue(fake.touched("delete namespace reloader"))
        self.assertFalse(fake.touched("delete namespace keda"))   # a bare pod someone started there

    def test_empty_namespaces_are_deleted_and_used_ones_kept(self):
        vm = _ctx("vmware")
        fake = FakeCluster(leftovers={"minio": "persistentvolumeclaim/export-minio-0\nconfigmap/kube-root-ca.crt\n"})
        fake.uninstall(["reloader", "minio"], vm, {"reloader/reloader": _rel(), "minio/minio": _rel()})
        self.assertTrue(fake.touched("delete namespace reloader"))
        self.assertFalse(fake.touched("delete namespace minio"))

    def test_groups_keep_shared_members_and_hidden_companions_follow(self):
        vm = _ctx("vmware")
        quiet_kubectl = mock.patch.object(pl.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", ""))
        quiet_kubectl.start()
        self.addCleanup(quiet_kubectl.stop)
        rp = pl.removal_plan(["finops"], vm, {"opencost/opencost": _rel(), "monitoring/monitoring": _rel(), "kube-system/metrics-server": _rel()})
        self.assertEqual(rp["remove"], ["opencost"])
        self.assertIn("metrics-server", rp["kept"])
        istio = {f"istio-system/{m}": _rel() for m in ("istio-base", "istiod", "istio-cni", "ztunnel")}
        rp = pl.removal_plan(["istiod"], vm, istio)
        self.assertEqual(rp["blocked"], {"istiod": ["istio", "istio-cni"]})   # each dependent once
        rp = pl.removal_plan(["kagent"], vm, {"kagent/kagent": _rel(), "kagent/kagent-crds": _rel()})
        self.assertEqual(rp["remove"], ["kagent", "kagent-crds"])
        with _quiet():
            pl.print_removal(rp, vm)


class LayoutTests(unittest.TestCase):
    def test_plan_rows_fit_a_narrow_terminal_and_never_cut_words(self):
        vm = _ctx("vmware")
        rel = {"vpa/vpa": _rel()}
        entries = pl.plan(["goldilocks", "scaling", "aws-load-balancer-controller", "metrics-server"], vm, releases=rel)
        for cols in (60, 110):
            buf = io.StringIO()
            with mock.patch.object(pl.ui, "width", return_value=cols), contextlib.redirect_stdout(buf):
                pl.print_plan(entries, vm)
                pl.status(None)
            lines = [ui._strip(line) for line in buf.getvalue().splitlines()]
            for line in lines:
                self.assertLessEqual(len(line), cols, line)
            # no row wrapped: each item's row still carries its decision / state on the same line
            self.assertTrue(any("vpa" in l and "already installed - skip" in l for l in lines), cols)
            self.assertTrue(any("aws-load-balancer-controller" in l and "aws only" in l for l in lines), cols)
            self.assertTrue(any(" keda " in l and "install" in l for l in lines), cols)
        self.assertEqual(pl._shorten("Vertical Pod Autoscaler (experimental)", 20), "Vertical Pod…")
        self.assertNotIn("＋", json.dumps(pl._PLAN_LOOK))

    def test_run_does_not_leave_the_child_running_when_output_breaks(self):
        vm = _ctx("vmware")
        cmd = [sys.executable, "-c", "import time; print('x', flush=True); time.sleep(30)"]
        real_print = print

        def broken(*a, **k):
            if a and str(a[0]).startswith("    x"):
                raise BrokenPipeError
            return real_print(*a, **k)
        start = time.time()
        with mock.patch("builtins.print", broken), _quiet():
            with self.assertRaises(BrokenPipeError):
                pl._run(cmd, vm, check=False)
        self.assertLess(time.time() - start, 10)


class ExposeUiTests(unittest.TestCase):
    def test_ingress_mode_rerun_needs_no_install_and_no_keyerror(self):
        vm = _ctx("vmware")
        rel = {"ingress-nginx/ingress-nginx": _rel(), "probe:cert-manager-issuer": {"status": "present"}, "argocd/argocd": _rel()}
        applied = []

        def sub(cmd, **kw):
            if cmd[1:3] == ["get", "gateway"]:
                return subprocess.CompletedProcess(cmd, 1, "", "")
            if cmd[1:3] == ["get", "svc"]:
                return subprocess.CompletedProcess(cmd, 0 if cmd[3] == "argocd-server" else 1, "", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        def run(cmd, ctx, check=True):
            applied.append(cmd)
            return 0
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value=rel), \
                mock.patch.object(pl.subprocess, "run", sub), mock.patch.object(pl, "_run", run), \
                mock.patch.object(pl, "install") as inst, mock.patch.object(pl.deps, "find", side_effect=lambda t: t), _quiet():
            out = pl.expose_uis(vm)
        inst.assert_not_called()
        self.assertEqual([o[0] for o in out], ["argocd"])
        self.assertTrue(any("ingress-argocd.yaml" in " ".join(c) for c in applied))

    def test_missing_gateway_stack_needs_approval(self):
        vm = _ctx("vmware")
        rel = {"argocd/argocd": _rel()}
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value=rel), \
                mock.patch.object(pl.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "")), \
                mock.patch.object(pl, "install") as inst, mock.patch.object(pl.deps, "find", side_effect=lambda t: t), \
                mock.patch.object(pl.ui, "interactive", return_value=False), _quiet(), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                pl.expose_uis(vm)
        self.assertEqual(cm.exception.code, 3)
        inst.assert_not_called()


class KubeconfigLocalTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("kubectl"):
            self.skipTest("kubectl not installed")
        self.tmp = Path(tempfile.mkdtemp())
        self.home_kc = self.tmp / "home-config"
        self.patch = mock.patch.dict(os.environ, {"KUBECONFIG": str(self.home_kc)})
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _kc(self, cluster, user, context, server, token):
        return {"apiVersion": "v1", "kind": "Config", "current-context": context,
                "clusters": [{"name": cluster, "cluster": {"server": server}}],
                "users": [{"name": user, "user": {"token": token}}],
                "contexts": [{"name": context, "context": {"cluster": cluster, "user": user}}]}

    def _env(self, name, kc):
        wd = self.tmp / name
        (wd / "k8s").mkdir(parents=True)
        (wd / "k8s" / "kubeconfig").write_text(json.dumps(kc))
        return {"env": name, "workdir": str(wd)}

    def test_merge_never_overwrites_the_users_entries_and_selects_its_own_context(self):
        mine = self._kc("kubernetes", "kubernetes-admin", "default", "https://my-other-cluster.example:6443", "my-precious-work-token")
        mine["contexts"].append({"name": "work", "context": {"cluster": "kubernetes", "user": "kubernetes-admin"}})
        self.home_kc.write_text(json.dumps(mine))
        with _quiet():
            self.assertEqual(services.kubeconfig_local(self._env("lab", self._kc("kubernetes", "kubernetes-admin", "kubernetes-admin@kubernetes", "https://127.0.0.1:7581", "cs-lab")), {}), 0)
            self.assertEqual(services.kubeconfig_local(self._env("kb", self._kc("default", "default", "default", "https://127.0.0.1:7582", "cs-kb")), {}), 0)
        view = json.loads(subprocess.run(["kubectl", "config", "view", "--raw", "-o", "json"], capture_output=True, text=True,
                                         env=dict(os.environ, KUBECONFIG=str(self.home_kc))).stdout)
        clusters = {c["name"]: c["cluster"]["server"] for c in view["clusters"]}
        self.assertEqual(clusters["kubernetes"], "https://my-other-cluster.example:6443")
        self.assertEqual(clusters["vmware-lab"], "https://127.0.0.1:7581")
        self.assertEqual(clusters["vmware-kb"], "https://127.0.0.1:7582")
        self.assertIn("my-precious-work-token", json.dumps(view))
        self.assertEqual(view["current-context"], "vmware-kb")
        self.assertEqual({x["name"] for x in view["contexts"]} >= {"default", "work", "vmware-lab", "vmware-kb"}, True)
        self.assertEqual(self.home_kc.stat().st_mode & 0o777, 0o600)
        self.assertEqual(services.home_kubeconfig(), self.home_kc)

    def test_a_symlinked_kubeconfig_stays_a_symlink(self):
        real = self.tmp / "dotfiles-kubeconfig"
        real.write_text(json.dumps(self._kc("work", "me", "work", "https://w.example:6443", "tok-work-123")))
        self.home_kc.symlink_to(real)
        with _quiet():
            self.assertEqual(services.kubeconfig_local(self._env("sl", self._kc("default", "default", "default", "https://127.0.0.1:7583", "cs-sl")), {}), 0)
        self.assertTrue(self.home_kc.is_symlink())
        self.assertIn("vmware-sl", real.read_text())


class VpnTests(unittest.TestCase):
    def test_client_names_are_validated_before_anything_runs(self):
        for bad in ("x;id", "a b", "$(id)", "../x", "-x", "..", "server", "SERVER", "", "a" * 65, "x\ny"):
            with contextlib.redirect_stderr(io.StringIO()), _quiet():
                with self.assertRaises(SystemExit, msg=bad):
                    services.check_client_name(bad)
        for good in ("alice", "bob.smith", "ci_runner-1"):
            self.assertEqual(services.check_client_name(good), good)
        env = paths.Env("aws", "vpnt")
        env.create_dirs()
        with mock.patch.object(services.subprocess, "run") as run, _quiet(), contextlib.redirect_stderr(io.StringIO()):
            for fn in (services.add_user, services.revoke_user):
                with self.assertRaises(SystemExit):
                    fn(clouds.get("aws"), env, {"vars": {}}, {"vpn_public_ip": "203.0.113.9"}, "alice;touch${IFS}/tmp/pwned")
            run.assert_not_called()

    def test_add_user_quotes_the_name_for_the_remote_shell(self):
        env = paths.Env("aws", "vpnq")
        env.create_dirs()
        seen = []

        def fake(cmd, **kw):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "<ca>x</ca>", "")
        with mock.patch.object(services.subprocess, "run", fake), mock.patch.object(services.audit, "note"):
            services.add_user(clouds.get("aws"), env, {"vars": {}, "ssh_key": ""}, {"vpn_public_ip": "203.0.113.9"}, "bob.smith")
        self.assertEqual(seen[0][-1], "sudo /usr/local/sbin/cloudseed-vpn-client add bob.smith")

    def test_root_owned_openvpn_counts_as_running_but_a_reused_pid_does_not(self):
        env = paths.Env("aws", "vpnr")
        env.create_dirs()
        pf = services._pidfile(env)
        pf.write_text("4242\n")
        ours = f"openvpn --config x --daemon cloudseed-vpn --writepid {pf} --log-append y"
        with mock.patch.object(services.os, "kill", side_effect=PermissionError), mock.patch.object(services, "_cmdline", return_value=ours):
            self.assertEqual(services._running(env), 4242)
        with mock.patch.object(services.os, "kill", side_effect=PermissionError), mock.patch.object(services, "_cmdline", return_value="/usr/sbin/cupsd"):
            self.assertIsNone(services._running(env))
        with mock.patch.object(services.os, "kill", side_effect=ProcessLookupError), _quiet():
            self.assertIsNone(services._running(env))
            services.disconnect(env)
        self.assertFalse(pf.exists())              # stale pidfile cleaned
        pf.write_text("4242\n")
        # the daemon is gone once the kill went through (disconnect waits for that before it reports success)
        cmdlines = iter([ours])          # first look: our openvpn; after the kill: no such process
        with mock.patch.object(services.os, "kill", side_effect=PermissionError), \
                mock.patch.object(services, "_cmdline", side_effect=lambda pid: next(cmdlines, "")), \
                mock.patch.object(services, "_has_tty", return_value=True), mock.patch.object(services.os, "geteuid", return_value=501), \
                mock.patch.object(services.subprocess, "call", return_value=0) as call, _quiet():
            services.disconnect(env)
        call.assert_called_once_with(["sudo", "kill", "-TERM", "4242"])
        self.assertFalse(pf.exists())


class TunnelTests(unittest.TestCase):
    def _env(self, name):
        env = paths.Env("aws", name)
        env.create_dirs()
        (env.dir / "k8s").mkdir(parents=True, exist_ok=True)
        return env

    def test_tunnel_has_timeouts_uses_the_endpoint_port_and_a_free_local_port(self):
        env = self._env("tun")
        seen = []

        def fake_run(cmd, **kw):
            seen.append(cmd)
            if cmd[0] == "pgrep":
                return subprocess.CompletedProcess(cmd, 0, "999\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        outputs = {"kubernetes_endpoint": "https://10.0.1.5:6443", "bastion_public_ip": "203.0.113.9"}
        with mock.patch.object(services, "_tcp_open", return_value=False), mock.patch.object(services.subprocess, "run", fake_run), \
                mock.patch.object(services, "_free_port", return_value=7745), \
                mock.patch.object(services, "_point_kubeconfig", return_value=True), _quiet():
            via = services._ensure_reachable(clouds.get("aws"), env, {"vars": {}}, outputs, env.dir / "k8s" / "kubeconfig")
        ssh = next(c for c in seen if c[0] == "ssh")
        joined = " ".join(ssh)
        for opt in ("ConnectTimeout=10", "BatchMode=yes", "ServerAliveCountMax=3", "ExitOnForwardFailure=yes"):
            self.assertIn(opt, joined)
        self.assertIn("-L 127.0.0.1:7745:10.0.1.5:6443", joined)
        info = json.loads(services._tunnel_file(env).read_text())
        self.assertEqual((info["pid"], info["host"], info["rport"]), (999, "10.0.1.5", 6443))
        self.assertEqual(via, (info["port"], "10.0.1.5"))

    def test_tunnel_info_rejects_a_reused_pid(self):
        env = self._env("tun2")
        services._tunnel_file(env).write_text(json.dumps({"pid": os.getpid(), "port": 17001, "host": "10.0.0.1", "rport": 443}))
        self.assertIsNone(services.tunnel_info(env))          # this python process is not the ssh forward
        with mock.patch.object(services, "_cmdline", return_value="ssh -fN -L 127.0.0.1:17001:10.0.0.1:443 ec2-user@x"):
            self.assertEqual(services.tunnel_info(env)["port"], 17001)

    @unittest.skipIf(os.name == "nt", "ps-based process discovery is POSIX only")
    def test_a_tunnel_behind_a_long_command_line_is_still_recognised(self):
        # procps' ps (Linux) cuts `-o command=` at $COLUMNS even into a pipe: the -L spec after a long key path and
        # the ssh options fell off, and the live tunnel was taken for a reused PID (a second tunnel, or none closed)
        env = self._env("tun-long")
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "ssh", "-i", "/" + "k" * 2048,
                                  "-fN", "-L", "127.0.0.1:17003:10.0.0.1:443", "ec2-user@x"])
        self.addCleanup(lambda: (child.kill(), child.wait()))
        services._tunnel_file(env).write_text(json.dumps({"pid": child.pid, "port": 17003, "host": "10.0.0.1", "rport": 443}))
        with mock.patch.dict(os.environ, {"COLUMNS": "80"}):
            info, seen = services.tunnel_info(env), services._cmdline(child.pid)
        self.assertEqual((info or {}).get("port"), 17003, seen[-120:])

    def test_kubeconfig_is_fetched_once_then_cached(self):
        env = self._env("cache")
        env.save({"env": "cache", "region": "us-east-1", "vars": {"kubernetes_public_endpoint": True}})
        cfg = env.load()
        outputs = {"kubernetes_cluster_name": "c", "kubernetes_endpoint": "https://abc.eks.amazonaws.com"}
        fetches = []

        def fake_run(cmd, **kw):
            if cmd[1:3] == ["eks", "update-kubeconfig"]:
                fetches.append(cmd)
                Path(kw["env"]["KUBECONFIG"]).write_text("{}")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with mock.patch.object(services, "ensure_tool", return_value="aws"), mock.patch.object(services.subprocess, "run", fake_run), \
                mock.patch.object(services, "_tcp_open", return_value=True):
            services.ensure_kubeconfig(clouds.get("aws"), env, cfg, outputs)
            services.ensure_kubeconfig(clouds.get("aws"), env, cfg, outputs)
            self.assertEqual(len(fetches), 1)
            self.assertIn("--kubeconfig", fetches[0])
            services.ensure_kubeconfig(clouds.get("aws"), env, cfg, dict(outputs, kubernetes_endpoint="https://new.eks.amazonaws.com"))
            self.assertEqual(len(fetches), 2)

    def test_a_tunnel_from_an_older_version_is_recognised_and_closed(self):
        env = self._env("tun3")
        services._tunnel_file(env).write_text("4242")
        ssh = "ssh -i k -o ExitOnForwardFailure=yes -fN -L 127.0.0.1:17138:10.0.1.5:443 ec2-user@203.0.113.9"
        with mock.patch.object(services.os, "kill") as kill, mock.patch.object(services, "_cmdline", return_value=ssh), _quiet():
            info = services.tunnel_info(env)
            self.assertEqual((info["port"], info["host"], info["rport"]), (17138, "10.0.1.5", 443))
            services.close_tunnel(env)
        kill.assert_any_call(4242, 15)
        self.assertFalse(services._tunnel_file(env).exists())

    def test_az_writes_the_named_file(self):
        cmd = services.kubeconfig_command("azure", {"env": "d", "vars": {"subscription_id": "s"}},
                                          {"kubernetes_cluster_name": "c", "resource_group_name": "rg"}, kubeconfig=Path("/x/kc"))
        self.assertEqual(cmd[-2:], ["--file", "/x/kc"])


class ToolConsentTests(unittest.TestCase):
    def test_no_silent_installs_in_non_interactive_mode(self):
        with mock.patch.object(services.deps, "find", return_value=None), mock.patch.object(services.deps, "install") as inst, \
                mock.patch.object(services.ui, "interactive", return_value=False), mock.patch.object(services.sys, "argv", ["cloudseed", "-y", "kubectl"]), \
                contextlib.redirect_stderr(io.StringIO()), _quiet():
            with self.assertRaises(SystemExit) as cm:
                services.ensure_tool("gcloud", "to fetch the kubeconfig")
            self.assertEqual(cm.exception.code, 2)
            inst.assert_not_called()
        with mock.patch.object(services.deps, "find", side_effect=[None, "/bin/helm"]), mock.patch.object(services.deps, "install") as inst, \
                mock.patch.object(services.ui, "interactive", return_value=False), mock.patch.object(services, "AUTO_INSTALL", True), _quiet():
            self.assertEqual(services.ensure_tool("helm", "x"), "/bin/helm")
            inst.assert_called_once_with("helm")

    def test_gke_plugin_is_required_and_checked(self):
        with mock.patch.object(services.deps, "find", return_value=None), mock.patch.object(services, "_gcloud_sdk_root", return_value=None), \
                mock.patch.object(services.ui, "interactive", return_value=False), mock.patch.object(services.sys, "argv", ["cloudseed"]), \
                mock.patch.object(services.subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()), _quiet():
            with self.assertRaises(SystemExit):
                services.ensure_gke_auth_plugin("gcloud")
            run.assert_not_called()
        with contextlib.redirect_stderr(io.StringIO()), _quiet():
            with self.assertRaises(SystemExit):
                services._check_exec_plugins(Path("/nonexistent"), "CRITICAL: ACTION REQUIRED: gke-gcloud-auth-plugin, which is needed for continued use of kubectl, was not found", "")


class ManagedTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.patches = [mock.patch.object(managed, "PROFILES", self.home / "managed.json"), mock.patch.object(managed.paths, "HOME", self.home)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def test_connect_accepts_the_documented_flags(self):
        values, prof = managed.parse_connect_args("snowflake", ["--account", "myorg-acct", "--user=me", "role=SYSADMIN", "--profile", "prod"])
        self.assertEqual(values, {"account": "myorg-acct", "user": "me", "role": "SYSADMIN"})
        self.assertEqual(prof, "prod")
        self.assertEqual(managed.parse_connect_args("databricks", ["--host", "https://acme.cloud.databricks.com"])[0],
                         {"host": "https://acme.cloud.databricks.com"})
        with contextlib.redirect_stderr(io.StringIO()), _quiet():
            with self.assertRaises(SystemExit):
                managed.parse_connect_args("snowflake", ["acount=typo"])

    def test_connect_without_required_values_saves_nothing(self):
        with mock.patch.object(managed.ui, "interactive", return_value=False), contextlib.redirect_stderr(io.StringIO()), _quiet():
            with self.assertRaises(SystemExit):
                managed.connect("databricks", "default", {})
        self.assertEqual(managed.profile("databricks", "default"), {})
        with mock.patch.object(managed.ui, "interactive", return_value=False), _quiet():
            managed.connect("snowflake", "default", {"account": "a1", "user": "u1"})
        self.assertEqual(managed.profile("snowflake", "default"), {"account": "a1", "user": "u1"})   # no "" placeholders

    def test_snowflake_commands_get_the_profile_as_default_connection(self):
        with mock.patch.object(managed.ui, "interactive", return_value=False), _quiet():
            managed.connect("snowflake", "default", {"account": "myorg-acct", "user": "bob", "password": "pw-123456"})
        with mock.patch.object(managed, "ensure_tool", return_value="snow"), mock.patch.object(managed.subprocess, "call", return_value=0) as call, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            managed.run("snowflake", "default", ["sql", "-q", "select 1"])
            cmd = call.call_args[0][0]
            self.assertEqual(cmd[:2], ["snow", "--config-file"])
            self.assertEqual(cmd[3:], ["sql", "-q", "select 1"])
            conf = Path(cmd[2])
            self.assertEqual(conf.stat().st_mode & 0o777, 0o600)
            text = conf.read_text()
            self.assertIn('default_connection_name = "cloudseed-default"', text)
            self.assertIn('account = "myorg-acct"', text)
            self.assertEqual(call.call_args[1]["env"]["SNOWFLAKE_USER"], "bob")
            managed.run("snowflake", "default", ["sql", "-c", "mine", "-q", "select 1"])
            self.assertEqual(call.call_args[0][0], ["snow", "sql", "-c", "mine", "-q", "select 1"])
            self.assertNotIn("SNOWFLAKE_PASSWORD", call.call_args[1]["env"])   # never merged into their connection
        self.assertIn("'select 1'", out.getvalue())            # echoed with its quotes

    def test_generated_snow_config_is_valid_toml_for_any_password(self):
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        pw = 'p w"x\\ \U0001F600 \x7f \t é'
        with mock.patch.object(managed.ui, "interactive", return_value=False), _quiet():
            managed.connect("snowflake", "prod", {"account": "a1", "user": "u1", "password": pw})
        conf = tomllib.loads(managed.snowflake_config("prod").read_text())
        self.assertEqual(conf["default_connection_name"], "cloudseed-prod")
        self.assertEqual(conf["connections"]["cloudseed-prod"]["password"], pw)

    def test_secrets_are_masked_in_the_echo(self):
        masked = managed.mask_argv(["secrets", "put-secret", "s", "k", "--string-value", "TopSecretValue123", "--password=abc12345",
                                    "--from-literal=pw=a=b"])
        self.assertNotIn("TopSecretValue123", masked)
        self.assertNotIn("--password=abc12345", masked)
        self.assertIn("--from-literal=pw=[REDACTED]", masked)


if __name__ == "__main__":
    unittest.main()
