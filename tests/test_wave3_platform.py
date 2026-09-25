"""Wave 3 regression tests for the platform engine and catalog (cloudseed/platform.py, templates/): shared-namespace
kustomize removal, remembered --set values, the installed istio mode, CRD guards, honest install results, paging,
CRD refresh on --upgrade, info/group views, kept data, FIPS classes and endpoints, architecture awareness, catalog
values that make items actually work, UI login and route cleanup. Offline, stdlib only: helm/kubectl are fakes."""

from __future__ import annotations

import contextlib
import io
import json
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
    env = paths.Env(target, f"w3pl{_RUN}x{_N[0]}")
    env.create_dirs()
    shutil.rmtree(env.dir / "platform", ignore_errors=True)   # a CLOUDSEED_HOME reused across runs: no state from an earlier one
    cfg = {"env": env.name, "region": "us-east-1", "network_cidr": "10.100.0.0/24",
           "vars": dict({"fips_mode": fips, "project_id": "p", "subscription_id": "s"}, **(vars_ or {})), "platform_prereqs": ["velero", "karpenter"]}
    if outputs is None:
        outputs = {"kubernetes_distro": distro, "kubernetes_cluster_name": "c1"} if target == "vmware" else {"kubernetes_cluster_name": "c1"}
    return pl.Cluster(clouds.get(target), env, cfg, outputs, env.dir / "k8s" / "kubeconfig")


def _rel(status="deployed", chart="c-1", revision="1"):
    return {"status": status, "chart": chart, "revision": revision}


def _cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


def _args(item, c):
    return " ".join(pl._values_args(pl.CATALOG[item], c))


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
                mock.patch.object(pl.deps, "find", side_effect=lambda t: t), mock.patch.object(pl, "audit")]

    def did(self, text):
        return [i for i, c in enumerate(self.calls) if text in " ".join(c)]

    def asked(self, text):
        return [c for c in self.queries if text in " ".join(c)]


def _with(patches):
    stack = contextlib.ExitStack()
    for p in patches:
        stack.enter_context(p)
    return stack


TRAINER = """apiVersion: v1
kind: Namespace
metadata:
  name: kubeflow
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: training-operator
  namespace: kubeflow
"""
KFP_CSR = """apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: baseline
  name: kubeflow
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: workflows.argoproj.io
"""


class SharedKustomizeNamespaceTests(unittest.TestCase):
    """a2-platform-logic#0 / a2-platform-catalog#3: removing one kubeflow item must not delete namespace kubeflow."""

    def _kube(self):
        def render(cmd):
            return _cp(0, TRAINER if "training-operator" in cmd[2] else KFP_CSR if "cluster-scoped" in cmd[2] else "kind: Deployment\nmetadata:\n  name: ml-pipeline\n  namespace: kubeflow\n")
        return Kube([(lambda c: c[1] == "kustomize", render)])

    def test_removing_the_trainer_keeps_the_shared_namespace(self):
        vm = _ctx()
        kube = self._kube()
        rel = {"probe:kubeflow-trainer": {"status": "present"}, "probe:kubeflow-pipelines": {"status": "present"}}
        with _with(kube.patches(rel)), mock.patch.object(pl.shutil, "which", return_value="/usr/bin/git"), _silenced():
            removed = pl.uninstall(["kubeflow-trainer"], vm)
        self.assertEqual(removed, ["kubeflow-trainer"])
        self.assertFalse(kube.did("delete -k"))
        deletes = [c for c in kube.calls if c[1:3] == ["delete", "-f"]]
        self.assertEqual(len(deletes), 1)
        text = Path(deletes[0][3]).read_text()
        self.assertNotIn("kind: Namespace", text)
        self.assertIn("training-operator", text)
        self.assertFalse(kube.did("delete namespace kubeflow"))

    def test_pipelines_removal_renders_both_sources_without_the_namespace(self):
        vm = _ctx()
        kube = self._kube()
        rel = {"probe:kubeflow-pipelines": {"status": "present"}}
        with _with(kube.patches(rel)), mock.patch.object(pl.shutil, "which", return_value="/usr/bin/git"), _silenced():
            pl.uninstall(["kubeflow-pipelines"], vm)
        self.assertEqual(len(kube.asked("kustomize")), 2)
        for c in [c for c in kube.calls if c[1:3] == ["delete", "-f"]]:
            self.assertNotIn("kind: Namespace", Path(c[3]).read_text())

    def test_an_unrenderable_source_removes_nothing(self):
        vm = _ctx()
        kube = Kube([(lambda c: c[1] == "kustomize", _cp(1, "", "error: git fetch failed"))])
        with _with(kube.patches({"probe:kubeflow-trainer": {"status": "present"}})), \
                mock.patch.object(pl.shutil, "which", return_value="/usr/bin/git"), _silenced():
            removed = pl.uninstall(["kubeflow-trainer"], vm, strict=False)
        self.assertEqual(removed, [])
        self.assertEqual(vm.failures, ["kubeflow-trainer"])
        self.assertFalse([c for c in kube.calls if "delete" in c])

    def test_kustomize_applies_use_their_own_field_manager(self):
        vm = _ctx()
        kube = Kube()
        with _with(kube.patches({})), mock.patch.object(pl.shutil, "which", return_value="/usr/bin/git"), _silenced():
            pl.install_one("kubeflow-trainer", vm, wait=False, releases={})
        self.assertIn("--field-manager=cloudseed-kubeflow-trainer", kube.calls[kube.did("apply -k")[0]])


class RememberedSetTests(unittest.TestCase):
    """a2-platform-logic#6: --set values survive --upgrade and the undo of an uninstall."""

    def _install(self, vm, names, releases, **kw):
        kube = Kube()
        with _with(kube.patches(releases)), mock.patch.object(pl, "_helm_apply_flags", return_value=[]), _silenced():
            pl.install(names, vm, **kw)
        return kube

    def test_a_group_upgrade_keeps_an_items_earlier_set(self):
        vm = _ctx()
        self._install(vm, ["kured"], {}, extra_sets=["configuration.timeZone=Europe/Berlin"])
        self.assertEqual(pl.user_values(vm, "kured"), {"configuration.timeZone": "Europe/Berlin"})
        self.assertEqual(oct((vm.workdir / "user-values.json").stat().st_mode & 0o777), "0o600")
        kube = self._install(vm, ["resilience"], {"kured/kured": _rel()}, upgrade=True)
        helm = kube.calls[kube.did("helm upgrade --install kured")[0]]
        self.assertIn("configuration.timeZone=Europe/Berlin", helm)
        self.assertLess(helm.index("configuration.period=1h"), helm.index("configuration.timeZone=Europe/Berlin"))

    def test_a_new_set_wins_and_key_minus_forgets(self):
        vm = _ctx()
        self._install(vm, ["trino"], {}, extra_sets=["server.workers=3"])
        kube = self._install(vm, ["trino"], {"trino/trino": _rel()}, upgrade=True, extra_sets=["server.workers=4"])
        helm = kube.calls[kube.did("helm upgrade --install trino")[0]]
        self.assertIn("server.workers=4", helm)
        self.assertNotIn("server.workers=3", helm)
        kube = self._install(vm, ["trino"], {"trino/trino": _rel()}, upgrade=True, extra_sets=["server.workers-"])
        helm = kube.calls[kube.did("helm upgrade --install trino")[0]]
        self.assertEqual([a for a in helm if a.startswith("server.workers=")], ["server.workers=1"])   # the catalog's
        self.assertNotIn("server.workers-", helm)
        self.assertEqual(pl.user_values(vm, "trino"), {})

    def test_uninstall_stashes_and_the_undo_restore_brings_them_back(self):
        vm = _ctx()
        self._install(vm, ["trino"], {}, extra_sets=["server.workers=3"])
        kube = Kube()
        with _with(kube.patches({"trino/trino": _rel()})), _silenced():
            pl.uninstall(["trino"], vm)
        self.assertEqual(pl.user_values(vm, "trino"), {})
        values = vm.workdir / "trino.values.json"
        values.write_text(json.dumps({"server": {"workers": 3}, "coordinator": {"jvm": {"maxHeapSize": "1G"}}}))
        kube = Kube()
        with _with(kube.patches({})), mock.patch.object(pl, "_helm_apply_flags", return_value=[]), _silenced():
            pl.install_one("trino", vm, True, "1.42.2", None, {}, values_file=str(values))
        helm = kube.calls[kube.did("helm upgrade --install trino")[0]]
        self.assertIn(str(values), helm)
        self.assertNotIn("server.workers=1", helm)                      # the file's 3 must win
        self.assertNotIn("coordinator.jvm.maxHeapSize=1G", helm)        # in the file already
        self.assertIn("worker.jvm.maxHeapSize=1536M", helm)             # a catalog key the file lacks
        self.assertEqual(pl.user_values(vm, "trino"), {"server.workers": "3"})

    def test_the_plan_shows_remembered_values(self):
        vm = _ctx()
        self._install(vm, ["kured"], {}, extra_sets=["configuration.timeZone=Europe/Berlin"])
        with _silenced() as out:
            pl.print_plan(pl.plan(["kured"], vm, releases={}), vm)
        self.assertIn("configuration.timeZone=Europe/Berlin", out.getvalue())
        self.assertIn("kept from an earlier install", out.getvalue())

    def test_info_redacts_remembered_secrets_and_bad_sets_are_refused(self):
        vm = _ctx()
        pl.remember_sets(vm, "trino", ["auth.password=hunter2secret", "server.workers=2"])
        with mock.patch.object(pl, "installed_releases", return_value={"trino/trino": _rel()}), \
                mock.patch.object(pl.ui, "width", return_value=200), _silenced() as out:
            pl.info("trino", vm)
        self.assertNotIn("hunter2secret", out.getvalue())
        self.assertIn("server.workers=2", out.getvalue())
        with self.assertRaises(SystemExit):
            pl.check_install_args(["trino"], None, ["server.workers"])
        self.assertEqual(pl.check_install_args(["trino"], None, ["server.workers-"])[0], ["server.workers-"])

    def test_flat_keys(self):
        self.assertEqual(pl._flat_keys({"a": {"b.c": 1, "l": [{"x": 1}]}}), {"a", "a.b\\.c", "a.l", "a.l[0]", "a.l[0].x"})


class IstioModeTests(unittest.TestCase):
    """a2-platform-logic#7: an installed sidecar mesh stays sidecar."""

    SIDECAR = {"istio-system/istio-base": _rel(), "istio-system/istiod": _rel(), "probe:istio": {"status": "present"}}

    def test_sidecar_mesh_does_not_grow_the_ambient_data_plane(self):
        vm = _ctx()
        kube = Kube()
        with _with(kube.patches(self.SIDECAR)):
            entries = pl.plan(["kiali"], vm, releases=self.SIDECAR)
        by = {e["item"]: e for e in entries}
        self.assertNotIn("istio-cni", by)
        self.assertNotIn("ztunnel", by)
        self.assertEqual(vm.options["mode"], "sidecar")
        self.assertNotIn("profile=ambient", " ".join(pl._values_args(pl.CATALOG["istiod"], vm)))
        with _with(kube.patches(self.SIDECAR)):          # the CLI plans before install() plans again: still said
            again = {e["item"]: e for e in pl.plan(["security"], vm, releases=self.SIDECAR)}
        self.assertIn("mode: sidecar (as installed", again["istio"]["reasons"][0])

    def test_istiod_profile_decides_when_only_shared_members_exist(self):
        vm = _ctx()
        kube = Kube([(lambda c: c[1:3] == ["get", "values"], _cp(0, '{"profile": "ambient"}'))])
        with _with(kube.patches({})):
            self.assertEqual(pl._installed_mode("istio", vm, self.SIDECAR), "ambient")

    def test_ambient_members_mean_ambient_even_when_failed(self):
        rel = dict(self.SIDECAR, **{"istio-system/ztunnel": _rel("failed")})
        self.assertEqual(pl._installed_mode("istio", _ctx(), rel), "ambient")
        self.assertIsNone(pl._installed_mode("istio", _ctx(), {}))

    def test_ambient_to_sidecar_is_refused_without_force(self):
        rel = {f"istio-system/{m}": _rel() for m in ("istio-base", "istiod", "istio-cni", "ztunnel")}
        vm = _ctx()
        vm.options["mode"] = "sidecar"
        with self.assertRaises(SystemExit) as cm:
            pl.plan(["istio"], vm, releases=rel)
        self.assertIn("ambient mode", str(cm.exception))
        vm2 = _ctx()
        vm2.options["mode"] = "sidecar"
        pl.plan(["istio"], vm2, releases=rel, force=True)
        vm3 = _ctx()
        vm3.options["mode"] = "ambient"
        kube = Kube()
        with _with(kube.patches(self.SIDECAR)):
            entries = pl.plan(["istio"], vm3, releases=self.SIDECAR)
        istio = next(e for e in entries if e["item"] == "istio")
        self.assertIn("sidecar -> ambient", istio["reasons"][0])
        self.assertIn("ztunnel", [e["item"] for e in entries if e["action"] == "install"])
        istiod = next(e for e in entries if e["item"] == "istiod")        # profile=ambient, or istiod serves no ztunnel
        self.assertEqual((istiod["action"], istiod.get("reapply")), ("install", True))
        self.assertEqual(next(e for e in entries if e["item"] == "istio-base")["action"], "skip-installed")

    def test_the_mode_switch_reapplies_istiod_with_the_ambient_profile(self):
        vm = _ctx()
        vm.options["mode"] = "ambient"
        kube = Kube()
        with _with(kube.patches(self.SIDECAR)), mock.patch.object(pl, "_helm_apply_flags", return_value=[]), _silenced():
            done = pl.install(["istio"], vm, extra_sets=["mode=ambient"])
        self.assertEqual(done, ["istiod", "istio-cni", "ztunnel"])
        self.assertIn("profile=ambient", kube.calls[kube.did("helm upgrade --install istiod")[0]])
        self.assertFalse(kube.did("helm upgrade --install istio-base"))


class CrdGuardTests(unittest.TestCase):
    """a2-platform-logic#8: a CRD chart is not removed while its CRDs hold objects nothing in the removal made."""

    MANIFEST = ("---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: agents.kagent.dev\n"
                "---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: kept.kagent.dev\n"
                "  annotations:\n    helm.sh/resource-policy: keep\n")
    REL = {"kagent/kagent": _rel(), "kagent/kagent-crds": _rel()}

    def _kube(self, objects, fail=None):
        def get(c):
            if fail and fail(c):
                return _cp(1, "", 'error: the server doesn\'t have a resource type "kept"')
            return _cp(0, objects)
        return Kube([(lambda c: c[:3] == ["helm", "get", "manifest"], lambda c: _cp(0, self.MANIFEST if c[3] == "kagent-crds" else "")),
                     (lambda c: c[1] == "get" and "agents.kagent.dev" in " ".join(c), get)])

    def _plan(self, objects, names=("kagent",), fail=None):
        kube = self._kube(objects, fail)
        with _with(kube.patches(self.REL)):
            rp = pl.removal_plan(list(names), _ctx(), self.REL)
        return rp, kube

    def test_user_objects_keep_the_companion_and_own_ones_do_not(self):
        rp, kube = self._plan("Agent default my-agent <none> <none>\nAgent kagent k8s-agent kagent <none>\n")
        self.assertEqual(rp["remove"], ["kagent"])                      # the controller goes, the user's agents stay
        self.assertEqual(rp["blocked"], {})
        self.assertIn("kagent-crds", rp["kept"])
        self.assertIn("Agent default/my-agent", rp["kept_notes"]["kagent-crds"])
        self.assertNotIn("kept.kagent.dev", " ".join(" ".join(q) for q in kube.queries))   # resource-policy keep: not deleted
        with mock.patch.object(pl.ui, "width", return_value=200), _silenced() as out:
            pl.print_removal(rp, _ctx())
        self.assertIn("Agent default/my-agent", out.getvalue())
        rp, _ = self._plan("Agent kagent k8s-agent kagent <none>\nMemory x m1 <none> Agent\n")
        self.assertEqual(rp["blocked"], {})
        self.assertEqual(rp["remove"], ["kagent", "kagent-crds"])

    def test_a_named_companion_is_refused_and_force_overrides(self):
        rp, _ = self._plan("Agent default my-agent <none> <none>\n", names=("kagent", "kagent-crds"))
        self.assertIn("Agent default/my-agent", rp["blocked"]["kagent-crds"][0])
        vm = _ctx()
        kube = self._kube("Agent default mine <none> <none>\n")
        with _with(kube.patches(self.REL)), _silenced():
            self.assertEqual(pl.uninstall(["kagent"], vm), ["kagent"])
            self.assertFalse(kube.did("helm uninstall kagent-crds"))
            with self.assertRaises(SystemExit):
                pl.uninstall(["kagent", "kagent-crds"], vm)
            pl.uninstall(["kagent", "kagent-crds"], vm, force=True)
        self.assertTrue(kube.did("helm uninstall kagent-crds"))

    def test_one_crd_already_gone_still_lists_the_others(self):
        two = self.MANIFEST + "---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: memories.kagent.dev\n"
        gone = _cp(1, "", 'error: the server doesn\'t have a resource type "memories"')
        kube = Kube([(lambda c: c[:3] == ["helm", "get", "manifest"], lambda c: _cp(0, two if c[3] == "kagent-crds" else "")),
                     (lambda c: c[1] == "get" and "memories.kagent.dev" in c[2], gone),
                     (lambda c: c[1] == "get" and c[2] == "agents.kagent.dev", _cp(0, "Agent default my-agent <none> <none>\n"))])
        with _with(kube.patches(self.REL)):
            rp = pl.removal_plan(["kagent", "kagent-crds"], _ctx(), self.REL)
        self.assertIn("Agent default/my-agent", rp["blocked"]["kagent-crds"][0])

    def test_unlistable_objects_block(self):
        kube = Kube([(lambda c: c[:3] == ["helm", "get", "manifest"], _cp(0, self.MANIFEST.replace("kagent.dev", "keda.sh"))),
                     (lambda c: c[1] == "get" and "agents.keda.sh" in c[2], _cp(1, "", "Unable to connect to the server"))])
        rel = {"keda/keda": _rel()}
        with _with(kube.patches(rel)):
            rp = pl.removal_plan(["keda"], _ctx(), rel)
        self.assertIn("could not be listed", rp["blocked"]["keda"][0])

    def test_guarded_items(self):
        self.assertTrue(pl.CATALOG["keda"].get("guard_crds"))
        self.assertTrue(pl.CATALOG["external-secrets"].get("guard_crds"))


class InstallResultTests(unittest.TestCase):
    """a2-platform-logic#13: an install that installs nothing it was asked for fails; 'Done' only when it did something."""

    def _install(self, names, releases, **kw):
        kube = Kube()
        with _with(kube.patches(releases)), mock.patch.object(pl, "_helm_apply_flags", return_value=[]), \
                mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": ""}), _silenced() as out:
            try:
                done = pl.install(names, _ctx(), **kw)
                code = 0
            except SystemExit as e:
                done, code = None, e.code
        return done, code, out.getvalue(), kube

    def test_missing_key_is_a_failure(self):
        done, code, out, kube = self._install(["kagent"], {})
        self.assertEqual(code, 1)
        self.assertNotIn("Done", out)
        self.assertFalse(kube.did("helm upgrade"))

    def test_conflict_is_a_failure(self):
        _, code, _, _ = self._install(["kubecost-cost-analyzer"], {"opencost/opencost": _rel(), "monitoring/monitoring": _rel()})
        self.assertEqual(code, 1)

    def test_a_group_reports_its_skipped_member(self):
        done, code, out, _ = self._install(["agentic"], {})
        self.assertEqual(code, 0)
        self.assertIn("qdrant", done)
        self.assertIn("skipped", out)
        self.assertIn("kagent", out)

    def test_a_group_with_nothing_installable_fails(self):
        kube = Kube()
        fips = _ctx(fips=True)
        with _with(kube.patches({})), _silenced():
            with self.assertRaises(SystemExit) as cm:
                pl.install(["ai"], fips)
        self.assertEqual(cm.exception.code, 1)
        self.assertFalse(kube.did("helm upgrade"))

    def test_everything_installed_says_so_and_summary_false_is_silent(self):
        done, code, out, _ = self._install(["reloader"], {"reloader/reloader": _rel()})
        self.assertEqual((done, code), ([], 0))
        self.assertIn("Nothing to do", out)
        self.assertNotIn("Done", out)
        done, _, out, _ = self._install(["reloader"], {}, summary=False)
        self.assertEqual(done, ["reloader"])
        self.assertNotIn("Done", out)

    def test_expose_uis_installs_its_stack_without_a_done_panel(self):
        vm = _ctx()
        with mock.patch.object(pl, "ensure_tools"), mock.patch.object(pl, "installed_releases", return_value={"argocd/argocd": _rel()}), \
                mock.patch.object(pl, "gateway_present", side_effect=[False, True]), mock.patch.object(pl, "plan", return_value=[{"item": "envoy-gateway", "action": "install"}]), \
                mock.patch.object(pl, "install") as inst, mock.patch.object(pl, "_drop_stale_backend_tls"), \
                mock.patch.object(pl.subprocess, "run", return_value=_cp(1)), mock.patch.object(pl.deps, "find", side_effect=lambda t: t), _silenced():
            pl.expose_uis(vm, auto_approve=True)
        self.assertEqual(inst.call_args.kwargs.get("summary"), False)


class DistroTests(unittest.TestCase):
    """a2-platform-logic#15: an offline plan uses the environment's distro."""

    def test_offline_kubeadm(self):
        vm = _ctx("vmware", outputs={}, vars_={"kubernetes_distro": "kubeadm"})
        self.assertEqual(vm.distro, "kubeadm")
        by = {e["item"]: e for e in pl.plan(["metrics-server"], vm, releases={})}
        self.assertEqual(by["metrics-server"]["action"], "install")
        self.assertEqual(_ctx("vmware", outputs={}).distro, "rke2")
        self.assertEqual(_ctx("aws", vars_={"kubernetes_distro": "kubeadm"}).distro, "eks")
        self.assertEqual(_ctx("vmware", outputs={"kubernetes_distro": "rke2"}, vars_={"kubernetes_distro": "kubeadm"}).distro, "rke2")


class PagingTests(unittest.TestCase):
    """a2-platform-logic#23: every release is read, not the first 256."""

    def test_pages_until_short(self):
        vm = _ctx()
        pages = {0: [{"namespace": f"n{i}", "name": f"r{i}", "status": "deployed"} for i in range(256)],
                 256: [{"namespace": "velero", "name": "velero", "status": "deployed"}]}
        seen = []

        def sub(cmd, **kw):
            if cmd[1] == "list":
                off = int(cmd[cmd.index("--offset") + 1]) if "--offset" in cmd else 0
                seen.append((cmd[cmd.index("--max") + 1], off))
                return _cp(0, json.dumps(pages.get(off, [])))
            return _cp(1)
        with mock.patch.object(pl.subprocess, "run", sub), mock.patch.object(pl.deps, "find", side_effect=lambda t: t):
            out = pl.installed_releases(vm)
        self.assertEqual(seen, [("256", 0), ("256", 256)])
        self.assertIn("velero/velero", out)
        self.assertEqual(len([k for k in out if not k.startswith("probe:")]), 257)

    def test_a_helm_that_ignores_offset_does_not_loop(self):
        vm = _ctx()
        page = json.dumps([{"namespace": f"n{i}", "name": f"r{i}", "status": "deployed"} for i in range(256)])
        calls = []

        def sub(cmd, **kw):
            calls.append(cmd)
            return _cp(0, page) if cmd[1] == "list" else _cp(1)
        with mock.patch.object(pl.subprocess, "run", sub), mock.patch.object(pl.deps, "find", side_effect=lambda t: t):
            out = pl.installed_releases(vm)
        self.assertEqual(len([c for c in calls if c[1] == "list"]), 2)
        self.assertEqual(len([k for k in out if not k.startswith("probe:")]), 256)


class CrdRefreshTests(unittest.TestCase):
    """a2-platform-logic#28: --upgrade re-applies the chart's own CRDs (never other groups, never a downgrade)."""

    CRDS = ("---\n# Source: x/crds/a.yaml\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n"
            "  name: prometheuses.monitoring.coreos.com\nspec:\n  group: monitoring.coreos.com\n"
            "---\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: other.example.com\n")

    def _upgrade(self, chart, upgrade=True):
        vm = _ctx()
        vm.upgrade = upgrade
        rel = {"monitoring/monitoring": _rel(chart=chart)} if chart else {}
        kube = Kube([(lambda c: c[:3] == ["helm", "show", "crds"], _cp(0, self.CRDS))])
        with _with(kube.patches(rel)), mock.patch.object(pl, "_helm_apply_flags", return_value=[]), _silenced():
            pl.install_one("kube-prometheus-stack", vm, wait=False, releases=rel)
        return kube

    def test_upgrade_applies_only_its_groups_first(self):
        kube = self._upgrade("kube-prometheus-stack-90.0.0")
        apply = kube.did("apply --server-side --force-conflicts --field-manager=cloudseed-crds")
        helm = kube.did("helm upgrade --install monitoring")
        self.assertTrue(apply and apply[0] < helm[0])
        text = Path(kube.calls[apply[0]][-1]).read_text()
        self.assertIn("prometheuses.monitoring.coreos.com", text)
        self.assertNotIn("other.example.com", text)

    def test_not_on_a_first_install_nor_a_downgrade(self):
        self.assertFalse(self._upgrade(None).asked("show crds"))
        self.assertFalse(self._upgrade("kube-prometheus-stack-99.0.0").asked("show crds"))
        self.assertFalse(self._upgrade("kube-prometheus-stack-90.0.0", upgrade=False).asked("show crds"))

    def test_groups_are_the_items_own(self):
        self.assertEqual(pl.CATALOG["envoy-gateway"]["upgrade_crds"], ["gateway.envoyproxy.io"])   # not the Gateway API bundle
        for n, sp in pl.CATALOG.items():
            if sp.get("upgrade_crds"):
                self.assertIn(sp["method"], ("helm", "oci"), n)


class InfoViewTests(unittest.TestCase):
    """a2-platform-logic#29, a2-platform-catalog#15/#16: info and group views show what install does."""

    def _show(self, fn, *args):
        with mock.patch.object(pl.ui, "width", return_value=160), _silenced() as out:
            fn(*args)
        return out.getvalue()

    def test_group_footer_suggests_only_fitting_extras(self):
        res = self._show(pl.group_info, "resilience", None)
        self.assertNotIn("cs platform install resilience   ·   cs platform install resilience", res)
        self.assertIn("minio", res)                       # velero's vmware dependency
        self.assertIn("vmware only", res)
        fin = self._show(pl.group_info, "finops", None)
        self.assertIn("cs platform install finops kube-green", fin)
        self.assertNotIn("finops kube-green kubecost", fin)
        base = self._show(pl.group_info, "basek8s", None)
        self.assertNotIn("install basek8s aws-load-balancer-controller", base)
        self.assertNotIn("install basek8s ingress-nginx", base)
        self.assertEqual(pl._suggested_extras(["karpenter"], set(), _ctx("aws")), ["karpenter"])

    def test_group_info_with_a_cluster_resolves_like_install(self):
        vm = _ctx()
        with mock.patch.object(pl, "installed_releases", return_value={}):
            res = self._show(pl.group_info, "resilience", vm)
        self.assertIn("local-path-provisioner", res)
        self.assertIn("minio", res)

    def test_item_info_rows(self):
        velero = self._show(pl.info, "velero", None)
        for row in ("needs[vmware]", "applies first[azure]", "also applies[vmware]", "cloud prereqs", "crypto-restricted"):
            self.assertIn(row, velero)
        istio = self._show(pl.info, "istio", None)
        self.assertNotIn("release ", istio.replace("releases", ""))
        self.assertIn("state from", istio)
        eg = self._show(pl.info, "envoy-gateway", None)
        self.assertIn("also applies[fips]", eg)
        self.assertIn("tls-restricted", eg)
        self.assertIn("conflicts", self._show(pl.info, "opencost", None))
        self.assertIn("not FIPS-capable", self._show(pl.info, "harbor", None))


class CatalogInvariantTests(unittest.TestCase):
    """a2-platform-logic#30: no git items; every item without a release has a probe (the fallbacks were removed)."""

    def test_methods_and_probes(self):
        for n, sp in pl.CATALOG.items():
            self.assertIn(sp["method"], ("helm", "oci", "kustomize", "manifest", "meta", "post-only"), n)
            if sp["method"] not in ("helm", "oci"):
                self.assertTrue(sp.get("probe"), n)
            self.assertIn(sp.get("fips", "compatible"), pl.FIPS_CLASSES, n)


class KeptDataTests(unittest.TestCase):
    """a2-platform-logic#32: the Polaris database outlives an uninstall; its operator stays while it runs."""

    def test_polaris_db_cluster_is_not_deleted(self):
        vm = _ctx()
        kube = Kube()
        with _with(kube.patches({"polaris/polaris": _rel()})), _silenced() as out:
            pl.uninstall(["polaris"], vm)
        deletion = (vm.workdir / "polaris-db.delete.yaml").read_text()
        self.assertNotIn("kind: Cluster", deletion)
        self.assertIn("polaris-root", deletion)
        self.assertIn("its data is kept", out.getvalue())

    def test_operator_kept_while_clusters_exist(self):
        vm = _ctx()
        kube = Kube([(lambda c: "clusters.postgresql.cnpg.io" in c, _cp(0, "polaris polaris-db\n"))])
        with _with(kube.patches({"cnpg-system/cloudnative-pg": _rel()})), _silenced():
            removed = pl.uninstall(["cloudnative-pg"], vm)     # strict: a deliberate keep is not a failure
        self.assertEqual(removed, [])
        self.assertEqual(vm.kept, ["cloudnative-pg"])
        self.assertFalse(kube.did("helm uninstall"))
        free = Kube()
        with _with(free.patches({"cnpg-system/cloudnative-pg": _rel()})), _silenced():
            self.assertEqual(pl.uninstall(["cloudnative-pg"], _ctx()), ["cloudnative-pg"])

    def test_minio_keeps_its_volume(self):
        self.assertIn("--set-string persistence.annotations.helm\\.sh/resource-policy=keep", _args("minio", _ctx()))


class FipsTests(unittest.TestCase):
    """a2-aws#5, a2-platform-catalog#9/#10: FIPS end to end for the AWS controllers and Karpenter nodes; crypto classes."""

    def test_karpenter_nodes_use_bottlerocket_fips_amis(self):
        aws = _ctx("aws", fips=True)
        with mock.patch.object(pl.subprocess, "run", return_value=_cp(0, json.dumps({"serverVersion": {"gitVersion": "v1.31.4-eks-1"}}))), \
                mock.patch.object(pl.deps, "find", side_effect=lambda t: t):
            text = pl.render_manifest("karpenter-default", aws)
        self.assertNotIn("alias:", text)
        self.assertIn("amiFamily: Bottlerocket", text)
        self.assertIn("/aws/service/bottlerocket/aws-k8s-1.31-fips/x86_64/latest/image_id", text)
        self.assertIn("/aws/service/bottlerocket/aws-k8s-1.31-fips/arm64/latest/image_id", text)
        self.assertIn("alias: bottlerocket@latest", pl.render_manifest("karpenter-default", _ctx("aws")))

    def test_unknown_version_stops_the_apply(self):
        aws = _ctx("aws", fips=True)
        with mock.patch.object(pl.subprocess, "run", return_value=_cp(1)), mock.patch.object(pl.deps, "find", side_effect=lambda t: t), \
                mock.patch.object(pl, "_run") as run:
            with self.assertRaises(SystemExit):
                pl._apply_manifest(aws, "kubectl", "karpenter-default", "kube-system", wait_ns=False)
        run.assert_not_called()

    def test_aws_controllers_use_fips_endpoints_as_strings(self):
        aws = _ctx("aws", fips=True)
        for item, key in (("external-secrets", "extraEnv[0].value=true"), ("karpenter", "controller.env[0].value=true"),
                          ("cluster-autoscaler", "extraEnv.AWS_USE_FIPS_ENDPOINT=true"), ("external-dns", "env[0].value=true"),
                          ("aws-load-balancer-controller", "env.AWS_USE_FIPS_ENDPOINT=true")):
            self.assertIn("--set-string " + key, _args(item, aws), item)
        velero = _args("velero", aws)
        self.assertIn("s3Url=https://s3-fips.us-east-1.amazonaws.com", velero)
        self.assertIn("AWS_ENDPOINT_URL_STS", velero)
        self.assertNotIn("AWS_USE_FIPS_ENDPOINT", velero)
        self.assertNotIn("AWS_USE_FIPS_ENDPOINT", _args("external-secrets", _ctx("aws")))
        vm = _args("velero", _ctx("vmware", fips=True))
        self.assertNotIn("s3-fips", vm)
        self.assertIn("s3Url=http://minio.minio.svc:9000", vm)
        self.assertIn("--set manager.env.ssl=false", _args("neuvector", _ctx()))    # a chart value, not a container env

    def test_crypto_restricted_items_install_and_are_flagged(self):
        for n in ("cert-manager", "sealed-secrets", "velero", "cloudnative-pg"):
            self.assertEqual(pl.CATALOG[n]["fips"], "crypto-restricted", n)
        self.assertEqual(pl.CATALOG["metrics-server"]["fips"], "compatible")
        by = {e["item"]: e for e in pl.plan(["sealed-secrets"], _ctx(fips=True), releases={})}
        self.assertEqual(by["sealed-secrets"]["action"], "install")
        self.assertTrue(any("not a FIPS-validated module" in r for r in by["sealed-secrets"]["reasons"]))


class ArchTests(unittest.TestCase):
    """a2-platform-catalog#2: amd64-only items on arm64 clusters."""

    def test_skipped_on_arm64_guests_unless_forced(self):
        arm = _ctx(outputs={"kubernetes_distro": "rke2", "guest_arch": "arm64"})
        by = {e["item"]: e for e in pl.plan(["devsecops", "harbor", "litmus", "kubeflow-pipelines"], arm, releases={})}
        for n in ("gitlab", "harbor", "litmus", "kubeflow-pipelines"):
            self.assertEqual(by[n]["action"], "skip-arch", n)
        self.assertNotEqual(by["gitlab-runner"]["action"], "install")      # needs gitlab (and a runner token)
        self.assertEqual(by["trivy-operator"]["action"], "install")
        forced = {e["item"]: e for e in pl.plan(["harbor"], _ctx(outputs={"guest_arch": "arm64"}), releases={}, force=True)}
        self.assertEqual(forced["harbor"]["action"], "install")
        guest = _ctx(outputs={}, vars_={"guest_os_id": "arm-ubuntu-64"})
        self.assertEqual(guest.node_archs(), {"arm64"})
        self.assertEqual({e["item"]: e["action"] for e in pl.plan(["harbor"], _ctx(outputs={"guest_arch": "amd64"}), releases={})}["harbor"], "install")

    def test_karpenter_can_provide_amd64_nodes(self):
        aws = _ctx("aws")
        aws._archs = {"arm64"}
        by = {e["item"]: e for e in pl.plan(["harbor"], aws, releases={"kube-system/karpenter": _rel()})}
        self.assertEqual(by["harbor"]["action"], "install")

    def test_pinned_to_amd64_nodes(self):
        self.assertIn("core.nodeSelector.kubernetes\\.io/arch=amd64", _args("harbor", _ctx()))
        self.assertIn("mongodb.nodeSelector.kubernetes\\.io/arch=amd64", _args("litmus", _ctx()))
        self.assertIn("minio.nodeSelector.kubernetes\\.io/arch=amd64", _args("gitlab", _ctx()))
        self.assertIn("routerSpec.nodeSelectorTerms[0].matchExpressions[0].values[0]=amd64", _args("vllm-stack", _ctx("aws")))
        kube = Kube()
        with _with(kube.patches({})), mock.patch.object(pl.shutil, "which", return_value="/usr/bin/git"), _silenced():
            pl.install_one("kubeflow-pipelines", _ctx(), wait=False, releases={})
        patches = [c for c in kube.calls if "patch" in c]
        self.assertEqual([c[5] for c in patches], ["metadata-grpc-deployment", "metadata-writer"])
        self.assertIn('"kubernetes.io/arch":"amd64"', patches[0][-1])
        json.loads(patches[0][-1])


class CatalogValueTests(unittest.TestCase):
    """The catalog values that make items work (a2-platform-catalog#0,#1,#4-#8,#11,#12,#14,#18-#25, a2-platform-logic#10)."""

    def test_airflow_jobs_are_not_post_install_hooks(self):
        a = _args("airflow", _ctx())
        for k in ("migrateDatabaseJob.useHelmHooks", "migrateDatabaseJob.applyCustomEnv", "createUserJob.useHelmHooks", "createUserJob.applyCustomEnv"):
            self.assertIn(f"--set {k}=false", a)

    def test_starrocks_is_schedulable_persistent_and_waited_for(self):
        a = _args("starrocks", _ctx())
        self.assertIn("starrocks.starrocksFESpec.resources.requests.cpu=500m", a)
        self.assertIn("starrocks.starrocksBeSpec.storageSpec.storageSize=20Gi", a)
        self.assertIn("-Xmx1536m", a)
        self.assertNotIn("4.1-latest", a)
        vm = _ctx()
        kube = Kube(run_rc=lambda c: 1 if "--for=jsonpath={.status.phase}=running" in c else 0)
        with _with(kube.patches({})), mock.patch.object(pl, "_helm_apply_flags", return_value=[]), _silenced():
            with self.assertRaises(SystemExit) as cm:
                pl.install_one("starrocks", vm, wait=True, releases={})
        self.assertIn("starrocksclusters.starrocks.com/kube-starrocks", str(cm.exception))
        self.assertTrue(kube.did("get pods -o wide"))
        quick = Kube()
        with _with(quick.patches({})), mock.patch.object(pl, "_helm_apply_flags", return_value=[]), _silenced():
            pl.install_one("starrocks", _ctx(), wait=False, releases={})
        self.assertFalse(quick.did("jsonpath"))

    def test_trino_behind_the_gateway_and_sized(self):
        a = _args("trino", _ctx())
        self.assertIn("additionalConfigProperties[0]=http-server.process-forwarded=true", a)
        self.assertIn("worker.jvm.maxHeapSize=1536M", a)
        self.assertIn("coordinator.resources.limits.memory=2Gi", a)

    def test_external_urls_match_platform_ui(self):
        vm = _ctx()
        dom = vm.placeholders()["platform_domain"]
        self.assertIn(f"langfuse.nextauth.url=https://langfuse.{dom}", _args("langfuse", vm))
        self.assertIn(f"externalURL=https://harbor.{dom}", _args("harbor", vm))
        self.assertIn(f"global.hosts.minio.name=gitlab-minio.{dom}", _args("gitlab", vm))

    def test_runner_clones_through_the_service(self):
        self.assertIn("--set-string extraEnv.CLONE_URL=http://gitlab-webservice-default.gitlab.svc:8181", _args("gitlab-runner", _ctx()))

    def test_external_dns_publishes_httproutes(self):
        a = _args("external-dns", _ctx("aws"))
        self.assertIn("sources[0]=service", a)
        self.assertIn("sources[2]=gateway-httproute", a)
        self.assertIn("gateway-api", pl.CATALOG["external-dns"]["needs"])

    def test_rke2_control_plane_is_covered(self):
        rke2, kubeadm = _ctx(), _ctx(distro="kubeadm")
        self.assertIn("tolerations[0].operator=Exists", _args("kured", rke2))
        self.assertIn("tolerations[0].operator=Exists", _args("falco", rke2))
        self.assertIn("enforcer.tolerations[0].operator=Exists", _args("neuvector", rke2))
        self.assertIn("prometheus-node-exporter.tolerations[0].operator=Exists", _args("kube-prometheus-stack", rke2))
        self.assertIn("nodeAgent.tolerations[0].operator=Exists", _args("kubescape-operator", kubeadm))
        self.assertNotIn("tolerations", _args("kured", _ctx("aws")))

    def test_no_forever_firing_control_plane_alerts(self):
        for target, distro in (("aws", "eks"), ("gcp", "gke"), ("azure", "aks"), ("vmware", "rke2"), ("vmware", "kubeadm")):
            a = _args("kube-prometheus-stack", _ctx(target, distro, outputs={"kubernetes_distro": distro} if target == "vmware" else None))
            self.assertIn("kubeControllerManager.enabled=false", a, distro)
            self.assertIn("kubeEtcd.enabled=false", a, distro)
        self.assertIn("kubeProxy.enabled=false", _args("kube-prometheus-stack", _ctx("gcp")))
        self.assertNotIn("kubeProxy.enabled", _args("kube-prometheus-stack", _ctx("aws")))

    def test_cluster_ca_is_long_lived_and_keeps_its_key(self):
        ca = pl.POST_MANIFESTS["selfsigned-issuer"]
        self.assertIn("duration: 87600h", ca)
        self.assertIn("rotationPolicy: Never", ca)

    def test_misc_values(self):
        self.assertIn("fullnameOverride=sealed-secrets-controller", _args("sealed-secrets", _ctx()))
        j = _args("jupyterhub", _ctx())
        self.assertIn("authenticator_class=shared-password", j)
        self.assertIn("SharedPasswordAuthenticator.allow_all=true", j)
        self.assertNotIn("DummyAuthenticator", j)
        self.assertIn("deploymentMode=Standard", _args("kserve", _ctx()))
        self.assertIn("falcosidekick.webui.user=admin:", _args("falco", _ctx()))
        self.assertNotIn("k8s audit", pl.CATALOG["falco"]["desc"])
        self.assertEqual(pl.UIS["falco"][1:3], ("falco-falcosidekick-ui", 2802))

    def test_pinned_images(self):
        self.assertIn(f"image.tag={pl.MINIO_IMAGE[1]}", _args("minio", _ctx()))       # a pinned public build (tests/test_release_fixes)
        self.assertIn("routerSpec.tag=v0.1.12", _args("vllm-stack", _ctx("aws")))
        self.assertRegex(_args("kagent", _ctx()), r"grafana-mcp\.image\.tag=latest@sha256:[0-9a-f]{64}")
        self.assertRegex(_args("open-webui", _ctx()), r"pipelines\.image\.tag=main@sha256:[0-9a-f]{64}")
        self.assertIn("crdHook.image.tag=1.37.0", _args("clickhouse-operator", _ctx()))

    def test_overlaps_and_group_members(self):
        by = {e["item"]: e for e in pl.plan(["scaling", "karpenter"], _ctx("aws"), releases={})}
        self.assertTrue(any("overlaps with karpenter" in r for r in by["cluster-autoscaler"]["reasons"]))
        self.assertTrue(any("overlaps with cluster-autoscaler" in r for r in by["karpenter"]["reasons"]))
        self.assertNotIn("kube-prometheus-stack", pl.resolve(["resilience"], _ctx()))

    def test_env_values_are_strings_but_chart_flags_are_not(self):
        k = pl._STRING_VALUE_KEY
        self.assertTrue(k.search("controller.env[0].value"))
        self.assertTrue(k.search("extraEnv.AWS_USE_FIPS_ENDPOINT"))
        self.assertTrue(k.search("podLabels.azure\\.workload\\.identity/use"))
        self.assertFalse(k.search("manager.env.ssl"))
        self.assertFalse(k.search("env[0].name"))


class UiLoginAndCleanupTests(unittest.TestCase):
    """a2-platform-catalog#13 / #19 and e2e2#5: kagent behind a login, GitLab's own Ingress, UI objects and runtime
    leftovers do not keep a namespace alive."""

    def test_kagent_route_gets_basic_auth_on_the_gateway(self):
        vm = _ctx()
        kube = Kube([(lambda c: c[1:3] == ["get", "gateway"], _cp(0)), (lambda c: c[1:3] == ["get", "svc"], _cp(0))])
        with _with(kube.patches({"kagent/kagent": _rel()})), _silenced():
            out = pl.expose_uis(vm)
        self.assertEqual([o[0] for o in out], ["kagent"])
        route = vm.workdir / "httproute-kagent.yaml"
        text = route.read_text()
        self.assertIn("kind: SecurityPolicy", text)
        self.assertIn("name: cloudseed-kagent-basic-auth", text)
        pw = json.loads((vm.workdir / "secrets.json").read_text())["kagent_password"]
        self.assertIn(pl._htpasswd("admin", pw), text)
        self.assertNotIn(pw, text)
        self.assertEqual(oct(route.stat().st_mode & 0o777), "0o600")
        self.assertIn("kagent_password", out[0][2])

    def test_ingress_mode_basic_auth_and_gitlab_own_ingress(self):
        vm = _ctx()
        rel = {"ingress-nginx/ingress-nginx": _rel(), "probe:cert-manager-issuer": {"status": "present"}, "kagent/kagent": _rel(), "gitlab/gitlab": _rel()}
        kube = Kube([(lambda c: c[1:3] == ["get", "gateway"], _cp(1)), (lambda c: c[1:3] == ["get", "svc"], _cp(0))])
        with _with(kube.patches(rel)), _silenced():
            out = pl.expose_uis(vm)
        self.assertEqual(sorted(o[0] for o in out), ["gitlab", "kagent"])
        self.assertFalse((vm.workdir / "ingress-gitlab.yaml").exists())
        text = (vm.workdir / "ingress-kagent.yaml").read_text()
        self.assertIn("nginx.ingress.kubernetes.io/auth-type: basic", text)
        self.assertIn("auth: ", text)
        self.assertIn("own Ingress", dict((o[0], o[2]) for o in out)["gitlab"])

    def test_htpasswd_sha(self):
        self.assertEqual(pl._htpasswd("admin", "secret"), "admin:{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=")

    def test_uninstall_drops_the_ui_route_and_runtime_objects_do_not_keep_the_namespace(self):
        vm = _ctx()
        kube = Kube([(lambda c: c[1:3] == ["get", "namespace"], _cp(0)),
                     (lambda c: c[1] == "api-resources", _cp(0, "configmaps secrets httproutes.gateway.networking.k8s.io")),
                     (lambda c: c[1:4] == ["-n", "reloader", "get"] and c[4] == "configmaps", _cp(0, "configmap/reloader-meta-info\n")),
                     (lambda c: c[1:4] == ["-n", "argocd", "get"] and c[4].startswith("httproutes"),
                      _cp(0, "httproute.gateway.networking.k8s.io/cloudseed-argocd\nhttproute.gateway.networking.k8s.io/cloudseed-argocd-redirect\nhttproute.gateway.networking.k8s.io/app\n")),
                     (lambda c: c[1] == "get" and "-n" in c and c[c.index("-n") + 1] == "reloader", _cp(0, "configmap/reloader-meta-info\nconfigmap/kube-root-ca.crt\n")),
                     (lambda c: c[1] == "get" and "-n" in c and c[c.index("-n") + 1] == "argocd", _cp(0, "httproute.gateway.networking.k8s.io/app\n"))])
        with _with(kube.patches({"reloader/reloader": _rel(), "argocd/argocd": _rel()})), _silenced():
            pl.uninstall(["reloader", "argocd"], vm)
        self.assertTrue(kube.did("delete namespace reloader"))
        drop = [c for c in kube.calls if c[1:4] == ["-n", "argocd", "delete"]]
        self.assertEqual(len(drop), 1)
        self.assertIn("httproute.gateway.networking.k8s.io/cloudseed-argocd", drop[0])
        self.assertIn("httproute.gateway.networking.k8s.io/cloudseed-argocd-redirect", drop[0])
        self.assertNotIn("httproute.gateway.networking.k8s.io/app", drop[0])
        self.assertFalse(kube.did("delete namespace argocd"))                # the user's own route keeps it

    def test_runtime_objects(self):
        self.assertIn("configmap/reloader-meta-info", pl.CATALOG["reloader"]["runtime_objects"])
        self.assertIn("secret/kedaorg-certs", pl.CATALOG["keda"]["runtime_objects"])


class TemplateTests(unittest.TestCase):
    """a2-platform-catalog#4: the CI template can push to cloudseed's own GitLab registry."""

    def test_registry_insecure_switch(self):
        text = (REPO / "templates" / "gitlab-ci" / ".gitlab-ci.yml").read_text()
        self.assertIn('REGISTRY_INSECURE: "false"', text)
        self.assertIn("--skip-tls-verify-registry=$CI_REGISTRY", text)
        self.assertIn("TRIVY_USERNAME: $CI_REGISTRY_USER", text)
        self.assertEqual(text.count('if [ "$REGISTRY_INSECURE" = "true" ]'), 3)
        for image in re.findall(r"image: \{name: (\S+),", text) + re.findall(r"image: (\S+)$", text, re.M):
            self.assertNotRegex(image, r":latest$", image)


if __name__ == "__main__":
    unittest.main()
