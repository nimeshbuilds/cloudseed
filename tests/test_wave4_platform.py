"""Wave 4 regression tests for the platform engine and catalog (cloudseed/platform.py): `--set mode=` only picks the
Istio mode when a meta item is part of the request, --set/--version shown and warned about the same way by plan and
install, status() with releases handed in, CRD-only items reported as cluster-scoped, Pod Security labels under the
RKE2 CIS profile, kept operators shown as kept, Karpenter's encrypted root volume and catalog texts that match the
stacks. Offline, stdlib only: helm/kubectl are fakes."""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, paths, platform as pl, ui  # noqa: E402

_RUN = uuid.uuid4().hex[:4]   # per test run: a reused CLOUDSEED_HOME never hands back an earlier run's environment

REPO = Path(__file__).resolve().parents[1]
_N = [0]


def _ctx(target="vmware", distro="rke2", outputs=None, fips=False, vars_=None):
    _N[0] += 1
    env = paths.Env(target, f"w4pl{_RUN}x{_N[0]}")
    env.create_dirs()
    shutil.rmtree(env.dir / "platform", ignore_errors=True)   # a reused CLOUDSEED_HOME: no state from an earlier run
    cfg = {"env": env.name, "region": "us-east-1", "network_cidr": "10.100.0.0/24",
           "vars": dict({"fips_mode": fips, "project_id": "p", "subscription_id": "s"}, **(vars_ or {})), "platform_prereqs": ["velero", "karpenter"]}
    if outputs is None:
        outputs = {"kubernetes_distro": distro, "kubernetes_cluster_name": "c1"} if target == "vmware" else {"kubernetes_cluster_name": "c1"}
    return pl.Cluster(clouds.get(target), env, cfg, outputs, env.dir / "k8s" / "kubeconfig")


def _cis(**kw):
    return _ctx(vars_={"kubernetes_cis_profile": True}, **kw)


def _rel(status="deployed", chart="c-1", revision="1"):
    return {"status": status, "chart": chart, "revision": revision}


def _cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


@contextlib.contextmanager
def _silenced():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield buf


class Kube:
    """helm/kubectl stand-in: `_run` calls recorded, read-only `subprocess.run` queries answered from `answers`
    ((predicate, CompletedProcess or callable) pairs, first match wins)."""

    def __init__(self, answers=(), run_rc=None):
        self.calls, self.queries = [], []
        self.answers = list(answers)
        self.run_rc = run_rc or (lambda cmd: 0)

    def run(self, cmd, ctx, check=True):
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        rc = self.run_rc(cmd)
        ctx.last_output = (f'release "{cmd[2]}" uninstalled\n' if cmd[:2] == ["helm", "uninstall"]
                           else 'thing "x" deleted\n' if "delete" in cmd else "")
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
            return _cp(1, "", "not found")
        return _cp(0, "", "")

    def patches(self, releases):
        return [mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value=releases),
                mock.patch.object(pl, "_run", self.run), mock.patch.object(pl.subprocess, "run", self.sub),
                mock.patch.object(pl.deps, "find", side_effect=lambda t: t), mock.patch.object(pl, "audit"),
                mock.patch.object(pl, "_helm_apply_flags", return_value=[])]

    def did(self, text):
        return [i for i, c in enumerate(self.calls) if text in " ".join(c)]


def _with(patches):
    stack = contextlib.ExitStack()
    for p in patches:
        stack.enter_context(p)
    return stack


def _helm_upgrade(kube, release):
    return next(c for c in kube.calls if c[:4] == ["helm", "upgrade", "--install", release])


class MetaModeTests(unittest.TestCase):
    """a2-platform-logic#14: mode=... is Istio's mode only when a meta item is part of the request."""

    def test_which_requests_carry_a_mesh_mode(self):
        for names in (["istio"], ["security"], ["kiali"], ["istio-gateway"], ["minio", "istio"]):
            self.assertTrue(pl.meta_mode_applies(names), names)
        for names in (["minio"], ["data"], ["keda", "vpa"], []):
            self.assertFalse(pl.meta_mode_applies(names), names)
        # the mesh members named on their own: their values depend on the mode (istiod's profile=ambient)
        for names in (["istiod"], ["istio-base"], ["istio-cni"], ["ztunnel"]):
            self.assertTrue(pl.meta_mode_applies(names), names)
            self.assertEqual(pl.split_mode(names, ["mode=sidecar", "pilot.x=1"]), ("sidecar", ["pilot.x=1"]))

    def test_split_mode(self):
        self.assertEqual(pl.split_mode(["minio"], ["mode=distributed", "replicas=4"]), (None, ["mode=distributed", "replicas=4"]))
        self.assertEqual(pl.split_mode(["security"], ["mode=ambient", "mode=sidecar"]), ("sidecar", []))
        self.assertEqual(pl.split_mode(["kiali"], None), (None, []))
        with self.assertRaises(ui.Abort) as cm:
            pl.split_mode(["istio"], ["mode=sidcar"])
        self.assertIn("Unknown mode 'sidcar'", str(cm.exception))
        self.assertEqual(pl.meta_modes(), ["ambient", "sidecar"])

    def test_check_install_args(self):
        self.assertEqual(pl.check_install_args(["minio"], None, ["mode=distributed"]), (["mode=distributed"], "minio"))
        self.assertEqual(pl.check_install_args(["security"], None, ["mode=sidecar"]), ([], None))
        self.assertEqual(pl.check_install_args(["istio"], None, ["mode=sidecar", "pilot.x=1"]), (["pilot.x=1"], "istio"))
        with self.assertRaises(ui.Abort) as cm:     # a chart value with a group: refused like any other --set
            pl.check_install_args(["data"], None, ["mode=distributed"])
        self.assertIn("exactly one named item", str(cm.exception))

    def _install(self, names, sets, releases=None, c=None):
        c = c or _ctx()
        kube = Kube()
        with _with(kube.patches(releases or {})), _silenced() as out:
            done = pl.install(names, c, wait=False, extra_sets=sets)
        return c, kube, done, out.getvalue()

    def test_minio_mode_reaches_the_chart_and_is_remembered(self):
        c, kube, done, out = self._install(["minio"], ["mode=distributed"])
        self.assertIn("minio", done)
        cmd = _helm_upgrade(kube, "minio")
        sets = [cmd[i + 1] for i, a in enumerate(cmd) if a in ("--set", "--set-string")]
        self.assertEqual(sets[-1], "mode=distributed")                  # after the catalog's mode=standalone: it wins
        self.assertIn("mode=standalone", sets)
        self.assertNotIn("mode", c.options)
        self.assertEqual(pl.user_values(c, "minio"), {"mode": "distributed"})
        self.assertIn("--set mode=distributed", out)                   # the plan shows it

    def test_istio_mode_is_not_a_chart_value(self):
        c, kube, _, _ = self._install(["istio"], ["mode=sidecar"])
        self.assertEqual(c.options["mode"], "sidecar")
        self.assertFalse(kube.did("ztunnel"))
        for cmd in kube.calls:
            self.assertNotIn("mode=sidecar", cmd)
        self.assertEqual(pl.user_values(c, "istiod"), {})


class FlagRowsAndWarningsTests(unittest.TestCase):
    """a2-platform-logic#10/#20: one helper for the '--set/--version not applied' warnings; the plan lists --set and
    --version only under the Helm chart they go to."""

    def _plan(self, item, sets, version):
        c = _ctx()
        entries = pl.plan([item], c, releases={})
        with _silenced() as out:
            pl.print_plan(entries, c, user_sets=sets, version=version, target=item)
            pl.target_flag_warnings(entries, c, item, sets, version)
        return out.getvalue()

    def test_non_helm_target_has_no_flag_rows_and_a_warning(self):
        out = self._plan("kubeflow-trainer", ["a=b"], "9.9.9")
        self.assertNotIn("--version 9.9.9", out)
        self.assertNotIn("--set a=b", out)
        self.assertIn("--set and --version not applied: kubeflow-trainer is not a Helm chart", out)
        self.assertIn("applied from manifests", out)
        self.assertNotIn("only --set mode", out)

    def test_meta_target_says_only_mode_is_used(self):
        out = self._plan("istio", ["pilot.x=1"], None)
        self.assertIn("--set not applied: istio is not a Helm chart (only --set mode=... is used by it)", out)
        self.assertNotIn("--set pilot.x=1", out)

    def test_helm_target_shows_its_flags_and_no_warning(self):
        out = self._plan("keda", ["a=b"], "2.21.0")
        self.assertIn("--version 2.21.0", out)
        self.assertIn("--set a=b", out)
        self.assertNotIn("not applied", out)

    def test_skipped_target_is_warned_about(self):
        c = _ctx()
        entries = pl.plan(["keda"], c, releases={"keda/keda": _rel()})
        with _silenced() as out:
            pl.target_flag_warnings(entries, c, "keda", ["a=b"], None)
        self.assertIn("--set not applied: keda is already installed; re-run with --upgrade", out.getvalue())
        with _silenced() as out:
            pl.target_flag_warnings(entries, c, "keda", [], None)       # nothing given: nothing to say
        self.assertEqual(out.getvalue(), "")

    def test_other_skips_say_why_in_words(self):
        c = _ctx()                                                        # vmware/rke2: RKE2 ships metrics-server
        entries = pl.plan(["metrics-server"], c, releases={})
        with _silenced() as out:
            pl.target_flag_warnings(entries, c, "metrics-server", ["a=b"], None)
        self.assertIn("--set not applied: metrics-server is skipped (already provided by rke2 out of the box)", out.getvalue())
        self.assertNotIn("skip-provided", out.getvalue())

    def test_installed_non_helm_target_is_not_sent_to_upgrade(self):
        # --upgrade would not apply them either: the warning must not suggest it
        c = _ctx()
        entries = pl.plan(["kubeflow-trainer"], c, releases={"probe:kubeflow-trainer": {"chart": "", "status": "present"}})
        self.assertEqual(next(e for e in entries if e["item"] == "kubeflow-trainer")["action"], "skip-installed")
        with _silenced() as out:
            pl.target_flag_warnings(entries, c, "kubeflow-trainer", [], "1.0.0")
        self.assertIn("--version not applied: kubeflow-trainer is not a Helm chart", out.getvalue())
        self.assertNotIn("--upgrade", out.getvalue())

    def test_install_warns_through_the_same_helper(self):
        kube = Kube()
        with _with(kube.patches({})), _silenced(), mock.patch.object(pl, "target_flag_warnings") as warn:
            pl.install(["kubeflow-trainer"], _ctx(), wait=False, version="1.0.0")
        self.assertEqual(warn.call_args[0][2:], ("kubeflow-trainer", [], "1.0.0"))
        self.assertFalse([c for c in kube.calls if "--version" in c])


class StatusReleasesTests(unittest.TestCase):
    """a2-platform-logic#20: `platform list` can hand status() the releases it already read."""

    def test_given_releases_are_used(self):
        c = _ctx()
        with mock.patch.object(pl, "installed_releases", side_effect=AssertionError("asked helm again")), _silenced() as out:
            pl.status(c, releases={"keda/keda": _rel(chart="keda-2.21.0")})
        self.assertIn("keda-2.21.0", out.getvalue())

    def test_unknown_wins_over_releases(self):
        with mock.patch.object(pl, "installed_releases", side_effect=AssertionError("asked helm")), _silenced() as out:
            pl.status(_ctx(), unknown=True, releases={"keda/keda": _rel(chart="keda-2.21.0")})
        self.assertNotIn("keda-2.21.0", out.getvalue())
        self.assertIn("unknown", out.getvalue())


class ClusterScopedTests(unittest.TestCase):
    """e2e2#9: CRD-only items are cluster-scoped, not 'installed in namespace default'."""

    def test_install_messages(self):
        for item, want in (("gateway-api", "gateway-api installed (cluster-scoped CRDs)"),
                           ("kagent-crds", "kagent-crds installed (cluster-scoped CRDs; Helm release record in namespace kagent)")):
            kube = Kube()
            with _with(kube.patches({})), _silenced() as out:
                pl.install_one(item, _ctx(), wait=False, releases={})
            self.assertIn(want, out.getvalue())
            self.assertNotIn("installed in namespace", out.getvalue())
        kube = Kube()
        with _with(kube.patches({})), _silenced() as out:
            pl.install_one("keda", _ctx(), wait=False, releases={})
        self.assertIn("keda installed in namespace keda", out.getvalue())

    def test_info_namespace_row(self):
        with _silenced() as out:
            pl.info("gateway-api", None)
        self.assertRegex(out.getvalue(), r"namespace\s+cluster-scoped \(CRDs only\)")
        self.assertTrue(all(pl.CATALOG[n].get("hidden") or n == "gateway-api" for n, s in pl.CATALOG.items() if s.get("crds_only")))


class PodSecurityTests(unittest.TestCase):
    """a2-resilience#5: under RKE2's CIS profile (restricted Pod Security everywhere but kube-system) the namespaces of
    items whose pods need more are labelled before the install."""

    def test_cis_profile_detection(self):
        self.assertTrue(_cis().cis_profile)
        self.assertTrue(_ctx(vars_={"kubernetes_cis_profile": "true"}).cis_profile)
        self.assertFalse(_ctx().cis_profile)
        self.assertFalse(_ctx(outputs={"kubernetes_distro": "kubeadm"}, vars_={"kubernetes_cis_profile": True}).cis_profile)
        self.assertFalse(_ctx("aws", vars_={"kubernetes_cis_profile": True}).cis_profile)

    def test_catalog_tags(self):
        for n, spec in pl.CATALOG.items():
            for ns, lv in pl._pod_security_needs(spec).items():
                self.assertIn(lv, pl.POD_SECURITY_LEVELS[1:], n)
                self.assertNotIn(ns, pl._PROTECTED_NS, n)
        for n in ("velero", "local-path-provisioner", "chaos-mesh", "metallb", "kube-prometheus-stack", "falco", "kured", "istio-cni", "ztunnel"):
            self.assertIn("privileged", pl._pod_security_needs(pl.CATALOG[n]).values(), n)
        self.assertEqual(pl._pod_security_needs(pl.CATALOG["minio"]), {"minio": "baseline"})
        self.assertEqual(pl._pod_security_needs(pl.CATALOG["keda"]), {})
        # kagent's controller creates the chart's agents (k8s-agent, helm-agent ...) as Deployments with no securityContext
        self.assertEqual(pl._pod_security_needs(pl.CATALOG["kagent"]), {"kagent": "baseline"})

    def test_labels_only_under_the_profile(self):
        self.assertEqual(pl.pod_security_labels("velero", _cis()), [("velero", "privileged"), ("minio", "baseline")])
        self.assertEqual(pl.pod_security_labels("velero", _ctx()), [])
        self.assertEqual(pl.pod_security_labels("keda", _cis()), [])
        self.assertEqual(pl.pod_security_labels("descheduler", _cis()), [])     # kube-system is exempt anyway

    def test_velero_namespaces_are_labelled_before_anything_is_applied(self):
        c = _cis()
        kube = Kube()
        with _with(kube.patches({})), _silenced() as out:
            pl.install_one("velero", c, wait=False, releases={})
        labels = kube.did("--field-manager=cloudseed-pod-security")
        self.assertEqual(len(labels), 2)
        first_other = min(kube.did("velero-minio-credentials.yaml") + kube.did("helm upgrade"))
        self.assertLess(max(labels), first_other)
        text = (c.workdir / "pod-security-velero.yaml").read_text()
        for mode in ("enforce", "audit", "warn"):
            self.assertIn(f"pod-security.kubernetes.io/{mode}: privileged", text)
        self.assertIn("pod-security.kubernetes.io/enforce: baseline", (c.workdir / "pod-security-minio.yaml").read_text())
        self.assertIn("RKE2 CIS profile: namespace velero now admits privileged pods", out.getvalue())
        self.assertTrue(all("--server-side" in kube.calls[i] for i in labels))

    def test_a_label_is_never_lowered(self):
        c = _cis()
        kube = Kube([(lambda cmd: cmd[1:4] == ["get", "namespace", "monitoring"], _cp(0, "privileged"))])
        with _with(kube.patches({})), _silenced():
            pl.install_one("loki", c, wait=False, releases={})
        self.assertFalse(kube.did("cloudseed-pod-security"))
        raise_it = Kube([(lambda cmd: cmd[1:4] == ["get", "namespace", "monitoring"], _cp(0, "restricted"))])
        with _with(raise_it.patches({})), _silenced():
            pl.install_one("loki", c, wait=False, releases={})
        self.assertEqual(len(raise_it.did("cloudseed-pod-security")), 1)

    def test_no_labels_without_the_profile(self):
        kube = Kube()
        with _with(kube.patches({})), _silenced():
            pl.install_one("velero", _ctx(), wait=False, releases={})
        self.assertFalse(kube.did("cloudseed-pod-security"))
        self.assertFalse([q for q in kube.queries if "pod-security" in " ".join(q)])

    def test_a_label_that_cannot_be_applied_stops_the_install(self):
        kube = Kube(run_rc=lambda cmd: 1 if "--field-manager=cloudseed-pod-security" in cmd else 0)
        with _with(kube.patches({})), _silenced(), self.assertRaises(ui.Abort) as cm:
            pl.install_one("chaos-mesh", _cis(), wait=False, releases={})
        self.assertIn("could not label namespace chaos-mesh", str(cm.exception))
        self.assertFalse(kube.did("helm upgrade"))

    def test_plan_and_info_say_so(self):
        by = {e["item"]: e for e in pl.plan(["velero"], _cis(), releases={})}
        self.assertTrue(any(r.startswith("RKE2 CIS profile") and "velero at privileged" in r for r in by["velero"]["reasons"]))
        self.assertTrue(any("local-path-storage at privileged" in r for r in by["local-path-provisioner"]["reasons"]))
        plain = {e["item"]: e for e in pl.plan(["velero"], _ctx(), releases={})}
        self.assertFalse(any("CIS" in r for r in plain["velero"]["reasons"]))
        with _silenced() as out:
            pl.info("velero", None)
        self.assertIn("privileged (namespace velero), baseline (namespace minio)", out.getvalue())


class KeptOperatorPanelTests(unittest.TestCase):
    """a2-platform-logic#32: an operator uninstall keeps (Postgres clusters still there) is shown as kept, not '−'."""

    RUNNING = [(lambda c: "clusters.postgresql.cnpg.io" in c, _cp(0, "polaris polaris-db\n"))]

    def test_panel_and_approval(self):
        c = _ctx()
        kube = Kube(self.RUNNING)
        asked = []
        with _with(kube.patches({"cnpg-system/cloudnative-pg": _rel()})), _silenced() as out:
            removed = pl.uninstall(["cloudnative-pg"], c, force=True, approve=asked.append)
        self.assertEqual((removed, c.kept, asked), ([], ["cloudnative-pg"], []))   # nothing changes: nothing to approve
        text = out.getvalue()
        self.assertRegex(text, r"✔ cloudnative-pg\s+kept: it still runs 1 Postgres cluster\(s\) \(polaris/polaris-db\)")
        self.assertNotRegex(text, r"− cloudnative-pg")
        self.assertFalse(kube.did("helm uninstall"))

    def test_the_other_items_are_still_approved_and_removed(self):
        c = _ctx()
        kube = Kube(self.RUNNING)
        asked = []
        rel = {"cnpg-system/cloudnative-pg": _rel(), "keda/keda": _rel()}
        with _with(kube.patches(rel)), _silenced():
            removed = pl.uninstall(["cloudnative-pg", "keda"], c, approve=asked.append)
        self.assertEqual(removed, ["keda"])
        self.assertEqual(asked, [f"Uninstall keda from {c.env.id}?"])

    def test_kept_operator_stays_although_its_clusters_are_gone_by_then(self):
        # the panel said kept and nobody approved its removal: a later check that finds no cluster must not remove it
        c = _ctx()
        answers = iter([_cp(0, "polaris polaris-db\n")])
        kube = Kube([(lambda cmd: "clusters.postgresql.cnpg.io" in cmd, lambda cmd: next(answers, _cp(0, "")))])
        asked = []
        with _with(kube.patches({"cnpg-system/cloudnative-pg": _rel()})), _silenced() as out:
            removed = pl.uninstall(["cloudnative-pg"], c, force=True, approve=asked.append)
        self.assertEqual((removed, c.kept, asked), ([], ["cloudnative-pg"], []))
        self.assertFalse(kube.did("helm uninstall"))
        self.assertIn("then cs platform uninstall cloudnative-pg", out.getvalue())

    def test_free_operator_is_listed_for_removal(self):
        c = _ctx()
        kube = Kube()
        with _with(kube.patches({"cnpg-system/cloudnative-pg": _rel()})):
            rp = pl.removal_plan(["cloudnative-pg"], c, {"cnpg-system/cloudnative-pg": _rel()})
        self.assertEqual((rp["remove"], rp["keeping"]), (["cloudnative-pg"], {}))


class CatalogTextTests(unittest.TestCase):
    """Catalog texts and manifests that must agree with the stacks and the docs."""

    def test_autoscaler_floor_on_gke(self):
        spec = pl.CATALOG["cluster-autoscaler"]
        self.assertIn("never below kubernetes_node_count", spec["desc"])
        self.assertIn("max(kubernetes_node_min, kubernetes_node_count)", spec["notes"])
        self.assertIn("GKE/AKS raise it to kubernetes_node_count", spec["notes"])       # AWS validates min <= count <= max
        aws = (REPO / "terraform/aws/variables.tf").read_text()
        self.assertIn("var.kubernetes_node_count <= var.kubernetes_node_max", aws)
        gke = (REPO / "terraform/gcp/modules/kubernetes/main.tf").read_text()
        self.assertIn("min_node_count = max(var.node_min, var.node_count)", gke)   # what the text describes

    def test_ingress_notes_know_vmware(self):
        self.assertIn("on vmware a MetalLB address on the host-only network, reachable from this machine directly",
                      pl.CATALOG["ingress-nginx"]["notes"])
        self.assertNotIn("reachable over VPN)", pl.CATALOG["istio-gateway"]["desc"])

    def test_karpenter_encrypts_both_bottlerocket_volumes(self):
        for c in (_ctx("aws", "eks"), _ctx("aws", "eks", fips=True)):
            with mock.patch.object(c, "kubernetes_version", return_value="1.34"):
                text = pl.render_manifest("karpenter-default", c)
            self.assertRegex(text, r"deviceName: /dev/xvda\n\s+ebs: \{volumeSize: 4Gi, volumeType: gp3, encrypted: true\}")
            self.assertRegex(text, r"deviceName: /dev/xvdb\n\s+ebs: \{volumeSize: 50Gi, volumeType: gp3, encrypted: true\}")
            self.assertEqual(pl._manifest_objects(text)[0][:2], ("EC2NodeClass", "default"))

    def test_lb_controller_chart_matches_the_vendored_policy(self):
        main = (REPO / "terraform/aws/modules/kubernetes/main.tf").read_text()
        m = re.search(r"iam_policy\.json of controller v(\d+\.\d+\.\d+)", main)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), pl.CATALOG["aws-load-balancer-controller"]["version"])
        src = (REPO / "cloudseed/platform.py").read_text()
        self.assertRegex(src, r"lb_controller_iam_policy\.json: bump both together")


if __name__ == "__main__":
    unittest.main()
