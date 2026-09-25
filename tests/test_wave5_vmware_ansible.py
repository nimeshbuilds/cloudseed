"""Wave-5 regression tests (vmware / ansible closing pass): relative vmx paths recorded by older versions resolved from
the working directory in destroy and troubleshoot, the RKE2 CIS profile question, vmrest requests that never go through
a proxy, a Go older than go.mod needs (provider build, ensure_tool), doctor's exit code for a named cloud, the
--no-harden / --no-firewall help, the record of a local cluster whose VMs are gone, the custom resources a forced
removal of CRD charts deletes (kept for the undo), and the e2e battery's temporary directories.
Stdlib only; no VMware, no network, no Go, no cluster: every external command is faked."""
from __future__ import annotations

import argparse
import contextlib
import http.server
import io
import json
import os
import shutil
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, cli, clouds, deps, localvm, paths, provision, services, troubleshoot, ui, undo  # noqa: E402
from cloudseed import platform as pl  # noqa: E402

import test_fix_cli_life as life  # noqa: E402  (tests/ is on sys.path under unittest discovery)
import test_wave3_platform as w3p  # noqa: E402  (tests/ is on sys.path under unittest discovery)

_n = [0]


def _uid(prefix: str) -> str:
    while True:
        _n[0] += 1
        name = f"{prefix}{life.RUN_ID}v{_n[0]}"
        if not life._taken(name):   # not an environment an earlier run left in a reused CLOUDSEED_HOME
            return name


def _tmp(test) -> Path:
    d = Path(tempfile.mkdtemp(prefix="cs-w5va-"))
    test.addCleanup(shutil.rmtree, d, True)
    return d


def _capture(fn, *a, **k):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            result = fn(*a, **k)
        except SystemExit as e:
            if isinstance(e, ui.Abort):
                ui.show_abort(e)
            result = e.code
    return result, out.getvalue()


class _Envs(unittest.TestCase):
    """Environments made by a test are removed again."""

    def setUp(self):
        self.made: list = []
        self.ni = mock.patch.object(ui, "interactive", return_value=False)
        self.ni.start()

    def tearDown(self):
        self.ni.stop()
        for e in self.made:
            undo.clear(e.id)
            shutil.rmtree(e.dir, ignore_errors=True)
        log = audit._state.get("log")
        if log:
            log.close()

    def env(self, cloud: str = "vmware", **extra) -> paths.Env:
        e = paths.Env(cloud, _uid("w5v"))
        e.create_dirs()
        cfg = {"cloud": cloud, "env": e.name, "name": "cloudseed", "network_cidr": "192.168.160.0/24",
               "ssh_public_key": "ssh-ed25519 AAAA x", "vars": {}, "extra_vars": {}, "tags": {}}
        cfg.update(extra)
        e.save(cfg)
        self.made.append(e)
        return e


# ---------------------------------------------------------------- vmware#10: relative vmx paths, any CWD

class RecordedVmxTests(_Envs):
    """A vmx path an older version recorded relative to <workdir>/stack is found from any directory."""

    REL = "vms/renamed.vmwarevm/renamed.vmx"

    def setUp(self):
        super().setUp()
        self.e = self.env()
        self.bundle = self.e.stack_dir / "vms" / "renamed.vmwarevm"   # not named like the env's VMs: found by its vmx
        self.bundle.mkdir(parents=True)
        (self.bundle / "renamed.vmx").write_text("x")
        elsewhere = _tmp(self)
        cwd = os.getcwd()
        os.chdir(elsewhere)
        self.addCleanup(os.chdir, cwd)
        self.inv = {"current": {"count": 1, "updated_at": "2026-09-24T00:00:00Z",
                                "resources": [{"type": "vmdesktop_vm", "name": "bastion", "vmx_path": self.REL}]}}

    def test_destroy_resolves_them_against_the_working_directory(self):
        seen = {}

        def leftovers(env, cfg, purge, known_vmx=(), **k):
            seen["known"] = list(known_vmx)
            seen["bundles"] = cli._env_vm_bundles(self.e.stack_dir / "vms", "cloudseed-nomatch", known_vmx)

        args = SimpleNamespace(auto_approve=True, purge=False)
        with mock.patch.object(audit, "load", return_value=self.inv), \
                mock.patch.object(cli, "_destroy_local_leftovers", leftovers), \
                mock.patch.object(cli, "_handle_state_storage", return_value=None), \
                mock.patch.object(cli, "_release_os_login"), mock.patch.object(ui, "confirm", return_value=False):
            rc, out = _capture(cli._destroy_everything, clouds.get("vmware"), self.e, self.e.load(), None, [], args, {})
        self.assertEqual(rc, 0, out)
        self.assertEqual(seen["known"], [os.path.realpath(self.bundle / "renamed.vmx")])
        mine, foreign = seen["bundles"]
        self.assertEqual([b.name for b in mine], ["renamed.vmwarevm"])
        self.assertEqual(foreign, [])

    def test_the_sweep_looks_where_they_were_once_the_state_is_empty(self):
        # the destroy just emptied the state (or it was lost), so the adapter no longer knows that the old relative
        # vm_dir meant <workdir>/stack/vms: the VMs recorded before say it
        cfg = self.e.load()
        cfg["vars"]["vm_dir"] = "vms"
        known = [localvm.recorded_vmx_path(self.REL, str(self.e.dir))]
        self.assertEqual(cli._vm_dir(self.e, cfg), self.e.dir / "vms")
        self.assertEqual(cli._vm_dir(self.e, cfg, known), Path(os.path.realpath(self.bundle.parent)))
        # recorded VMs in the directory the adapter names (or none): its answer stands
        self.assertEqual(cli._vm_dir(self.e, cfg, [str(self.e.dir / "vms" / "x.vmwarevm" / "x.vmx")]), self.e.dir / "vms")
        host = {"found": True, "vmrun": "/nonexistent/vmrun", "product": "fusion"}
        with mock.patch.object(localvm, "detect_host", return_value=host), \
                mock.patch.object(localvm, "vmrun_list", return_value=[]), \
                mock.patch.object(localvm.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run:
            _capture(cli._destroy_local_leftovers, self.e, cfg, purge=False, known_vmx=known)
        self.assertFalse(self.bundle.exists())
        self.assertTrue(any("deleteVM" in c.args[0] for c in run.call_args_list))

    def _troubleshoot(self):
        binary = _tmp(self) / "provider"
        binary.write_text("x")
        host = {"found": True, "product": "fusion", "version": "13.6.0", "guest_arch": "arm64", "os": "darwin", "arch": "arm64"}
        with mock.patch.object(audit, "read_audit", return_value=[]), mock.patch.object(audit, "load", return_value=self.inv), \
                mock.patch.object(troubleshoot, "_state_finding", return_value=None), \
                mock.patch.object(deps, "missing", return_value=([], [])), \
                mock.patch.object(deps, "live_credential_check", return_value=None), \
                mock.patch.object(localvm, "detect_host", return_value=host), \
                mock.patch.object(localvm, "version_problem", return_value=None), \
                mock.patch.object(localvm, "provider_binary", return_value=binary), \
                mock.patch.object(localvm, "_port_open", return_value=True):
            return _capture(troubleshoot.run, clouds.get("vmware"), self.e, self.e.load())

    def test_troubleshoot_does_not_report_them_missing(self):
        rc, out = self._troubleshoot()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("VM files missing", out)
        shutil.rmtree(self.bundle)          # really gone: reported
        self.assertIn("VM files missing", self._troubleshoot()[1])


# ---------------------------------------------------------------- a2-resilience#5: the CIS profile question

class CisQuestionTests(unittest.TestCase):
    def test_the_prompt_names_the_exemptions_and_the_labels(self):
        prompt = clouds.get("vmware").question("kubernetes_cis_profile").prompt
        for part in ("restricted Pod Security Standard", "cloudseed-scan, velero, local-path-storage, minio, chaos-mesh",
                     "`cs platform install` labels the namespaces", "privileged namespace label"):
            self.assertIn(part, prompt)
        # the exempt list is the one the rke2 role writes
        role = (Path(__file__).resolve().parents[1] / "ansible" / "roles" / "rke2" / "tasks" / "main.yml").read_text()
        self.assertIn("rke2_psa_cloudseed_namespaces: [cloudseed-scan, velero, local-path-storage, minio, chaos-mesh]", role)


# ---------------------------------------------------------------- webui-backend#7: vmrest never through a proxy

class _Recorder(http.server.BaseHTTPRequestHandler):
    hits: list = []
    body = b'{"vmnets": [{"name": "vmnet1", "type": "hostOnly", "subnet": "172.16.1.0", "mask": "255.255.255.0"}]}'

    def do_GET(self):   # noqa: N802 - http.server's name
        type(self).hits.append((self.path, self.headers.get("Authorization")))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


class VmrestProxyTests(unittest.TestCase):
    def _serve(self, name: str):
        """A recording server on a free port the OS picks (never a fixed one another run may hold)."""
        handler = type(name, (_Recorder,), {"hits": []})
        srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return handler, f"http://127.0.0.1:{srv.server_address[1]}"

    def test_the_credentials_never_reach_a_proxy(self):
        (vmrest, vmrest_url), (proxy, proxy_url) = self._serve("VmrestH"), self._serve("ProxyH")
        env = {"http_proxy": proxy_url, "HTTP_PROXY": proxy_url, "https_proxy": proxy_url, "HTTPS_PROXY": proxy_url,
               "no_proxy": "", "NO_PROXY": ""}
        creds = {"user": "u", "password": "p"}
        with mock.patch.dict(os.environ, env), mock.patch.object(localvm, "VMREST_URL", vmrest_url):
            self.assertEqual(localvm._rest_status(creds, timeout=5), 200)
            nets = localvm.list_vmnets(creds)
        self.assertEqual([n["name"] for n in nets], ["vmnet1"])
        self.assertEqual(proxy.hits, [])
        self.assertEqual(len(vmrest.hits), 2)
        self.assertTrue(all(h[1] and h[1].startswith("Basic ") for h in vmrest.hits))


# ---------------------------------------------------------------- a2-vmware#2: a Go older than go.mod needs

class OldGoTests(unittest.TestCase):
    def setUp(self):
        d = _tmp(self)
        self.binary = d / "registry.local" / "cloudseed" / "vmdesktop" / "0.0.0" / "darwin_arm64" / "terraform-provider-vmdesktop"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text("old build")
        self.go = d / "go"
        self.patches = contextlib.ExitStack()
        self.patches.enter_context(mock.patch.object(localvm, "provider_binary", return_value=self.binary))
        self.patches.enter_context(mock.patch.object(localvm, "write_terraform_rc"))
        self.patches.enter_context(mock.patch.object(localvm, "_provider_stale", return_value=True))
        self.patches.enter_context(mock.patch.object(deps, "find", side_effect=lambda t: str(self.go) if t == "go" else None))
        self.patches.enter_context(mock.patch.object(deps, "version_of", side_effect=lambda t: "1.22.5" if t == "go" else ""))
        self.addCleanup(self.patches.close)

    def test_an_existing_build_is_kept_with_a_warning(self):
        with mock.patch.object(localvm, "_ensure_tool", side_effect=AssertionError("no install on the implicit path")), \
                mock.patch.object(localvm.subprocess, "run", side_effect=AssertionError("no build")):
            got, out = _capture(localvm.ensure_provider)
        self.assertEqual(got, self.binary)
        self.assertIn("Go 1.22.5 is older than 1.25; using the existing build", out)
        self.assertIn("cloudseed install go && cloudseed install vmware-provider --rebuild", out)

    def test_without_a_build_or_on_an_explicit_rebuild_go_is_offered(self):
        for rebuild, keep in ((True, True), (None, False)):
            if not keep:
                self.binary.unlink()
            with mock.patch.object(localvm, "_ensure_tool", side_effect=ui.Abort("stop here")) as ensure:
                rc, out = _capture(localvm.ensure_provider, rebuild)
            self.assertEqual(ensure.call_count, 1, (rebuild, out))
            self.assertEqual(ensure.call_args[0][0], "go")

    def test_ensure_tool_updates_an_old_tool_only_with_consent(self):
        with mock.patch.object(ui, "interactive", return_value=False), \
                mock.patch.object(services, "_install_approved", return_value=False), \
                mock.patch.object(deps, "refuse_install_in_agent_session"), \
                mock.patch.object(deps, "install", side_effect=AssertionError("no consent")):
            rc, out = _capture(services.ensure_tool, "go", "to build the provider")
        self.assertEqual(rc, 2)
        self.assertIn(f"the one at {self.go} is 1.22.5, older than 1.25", out)
        self.assertIn("Update it first: cloudseed install go", out)
        new = str(self.go) + "-new"
        versions = iter(["1.22.5", "1.25.1"])
        with mock.patch.object(ui, "interactive", return_value=False), \
                mock.patch.object(services, "_install_approved", return_value=True), \
                mock.patch.object(deps, "refuse_install_in_agent_session"), \
                mock.patch.object(deps, "version_of", side_effect=lambda t: next(versions)), \
                mock.patch.object(deps, "install") as install:
            deps.find.side_effect = [str(self.go), new]
            got, out = _capture(services.ensure_tool, "go", "to build the provider")
        install.assert_called_once_with("go")
        self.assertEqual(got, new)
        self.assertIn("updating it (cloudseed install go)", out)

    def test_an_agent_session_is_told_the_go_is_too_old_not_missing(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "claude"}), \
                mock.patch.object(deps, "install", side_effect=AssertionError("never for an agent")):
            with self.assertRaises(ui.Abort) as e:
                localvm._ensure_tool("go", "to build the provider")
        self.assertEqual(e.exception.code, 2)
        self.assertIn(f"the one at {self.go} is 1.22.5, older than 1.25", e.exception.msg)
        self.assertIn("ask the user to run: cloudseed install go", e.exception.msg)
        self.assertNotIn("Missing", e.exception.msg)

    def test_ensure_tool_leaves_a_current_tool_and_tools_without_a_minimum_alone(self):
        with mock.patch.object(deps, "version_of", return_value="1.25.0"), mock.patch.object(deps, "install") as install:
            self.assertEqual(services.ensure_tool("go", "x"), str(self.go))
        deps.find.side_effect = lambda t: "/usr/bin/kubectl"
        with mock.patch.object(deps, "version_of", side_effect=AssertionError("no version check")):
            self.assertEqual(services.ensure_tool("kubectl", "x"), "/usr/bin/kubectl")
        install.assert_not_called()


# ---------------------------------------------------------------- a2-cli-lifecycle#25: doctor's exit code

class DoctorExitTests(unittest.TestCase):
    def run_doctor(self, cloud, rows, live=(True, "ok")):
        with mock.patch.object(deps, "status", return_value=rows), \
                mock.patch.object(deps, "live_credential_check", return_value=live), \
                mock.patch.object(localvm, "detect_host", return_value={}):
            return _capture(cli.cmd_doctor, argparse.Namespace(cloud=cloud), {})

    @staticmethod
    def row(tool, path="/x", required=True):
        return {"tool": tool, "path": path, "required": required, "desc": "d", "version": "1.0", "outdated": False}

    def test_a_named_cloud_that_is_not_ready_exits_1(self):
        rc, out = self.run_doctor("aws", [self.row("terraform", path=None), self.row("aws")])
        self.assertEqual(rc, 1, out)
        self.assertIn("is not ready: terraform is missing", out)
        self.assertEqual(self.run_doctor("aws", [self.row("terraform")], live=(False, "expired"))[0], 1)
        self.assertEqual(self.run_doctor("aws", [self.row("terraform"), self.row("aws")])[0], 0)

    def test_the_overview_always_exits_0(self):
        rc, out = self.run_doctor(None, [self.row("terraform", path=None)], live=(False, "expired"))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("is not ready", out)

    def test_the_docs_say_so(self):
        from cloudseed import help as h
        page = " ".join(h.COMMANDS["doctor"].split())
        self.assertIn("and exits 1. The overview (no cloud) always exits 0", page)
        self.assertNotIn("exit code stays 0", page)
        readme = " ".join((Path(__file__).resolve().parents[1] / "docs" / "guides" / "manual.md").read_text().split())   # (was README.md)
        self.assertIn("exits 1 when that cloud is not ready", readme)


# ---------------------------------------------------------------- a2-ansible#3: --no-harden / --no-firewall help

class HardenHelpTests(unittest.TestCase):
    def test_setup_and_provision_describe_what_an_earlier_run_loses(self):
        parser = cli.build_parser()
        subs = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction)).choices
        for cmd in ("setup", "provision"):
            opts = {o: a.help for a in subs[cmd]._actions for o in a.option_strings}
            self.assertIn("from an earlier run are removed (PAM and umask edits stay; automatic updates are left as they are)",
                          opts["--no-harden"])
            self.assertIn("an earlier run's is removed; VPN/NAT hosts keep their NAT rule", opts["--no-firewall"])
        from cloudseed import mcp
        self.assertIn("automatic updates are left as they are", mcp._NO_HARDEN[2])
        self.assertIn("keep their NAT rule", mcp._NO_FIREWALL[2])


# ---------------------------------------------------------------- vmware reviewer: the record of a cluster that went

class RemovedClusterTests(_Envs):
    REC = {"at": "2026-09-01T00:00:00Z", "distro": "rke2", "control_planes": 1, "workers": 2, "harden": False}

    def test_the_helper(self):
        cfg = {"provisioned": {"bastion": {"harden": True}, "kubernetes": dict(self.REC)}}
        self.assertFalse(provision.forget_removed_cluster(cfg, {"kubernetes_control_plane_ips": ["10.0.0.20"]}))
        self.assertIn("kubernetes", cfg["provisioned"])
        self.assertTrue(provision.forget_removed_cluster(cfg, {"bastion_public_ip": "10.0.0.10"}))
        self.assertEqual(cfg["provisioned"], {"bastion": {"harden": True}})
        self.assertFalse(provision.forget_removed_cluster(cfg, {}))           # nothing (left) to forget
        self.assertFalse(provision.forget_removed_cluster({"provisioned": "junk"}, {}))

    def _finish(self, e, outputs, cloud="vmware"):
        t = SimpleNamespace(outputs=lambda: dict(outputs), state_list=lambda: [])
        cfg = e.load()
        cfg["vars"]["workload_count"] = "stand-in"             # the command's copy: never saved
        with mock.patch.object(audit, "refresh"), mock.patch.object(cli, "_print_outputs"), \
                mock.patch.object(cli, "_ssh_command", return_value=None):
            _capture(cli._finish, clouds.get(cloud), e, cfg, t, explain_missing_ip=False)
        return cfg

    def test_an_apply_without_the_cluster_forgets_it(self):
        e = self.env(provisioned={"bastion": {"harden": True}, "kubernetes": dict(self.REC)})
        self._finish(e, {"bastion_public_ip": "192.168.160.10", "kubernetes_control_plane_ips": ["192.168.160.20"]})
        self.assertIn("kubernetes", e.load()["provisioned"])                 # still there: kept
        cfg = self._finish(e, {"bastion_public_ip": "192.168.160.10"})       # enable_kubernetes=false applied
        saved = e.load()
        self.assertNotIn("kubernetes", saved["provisioned"])
        self.assertNotIn("kubernetes", cfg["provisioned"])
        self.assertEqual(saved["provisioned"], {"bastion": {"harden": True}})
        self.assertNotIn("workload_count", saved["vars"])                    # the stand-in stayed in the command's copy

    def test_outputs_that_could_not_be_read_forget_nothing(self):
        e = self.env(provisioned={"kubernetes": dict(self.REC)})
        self._finish(e, {})                  # `terraform output` failed: no sign that the cluster went
        self.assertIn("kubernetes", e.load()["provisioned"])

    def test_a_new_cluster_on_a_clashing_network_is_refused_again(self):
        e = self.env(network_cidr="10.42.0.0/24", provisioned={"kubernetes": dict(self.REC)})
        self._finish(e, {"bastion_public_ip": "10.42.0.10"})
        cfg = e.load()
        cfg["vars"]["kubernetes_distro"] = "rke2"
        with mock.patch.object(provision, "Host", side_effect=AssertionError("nothing is installed")):
            rc, out = _capture(provision.provision_local_kubernetes, clouds.get("vmware"), e, cfg,
                               {"kubernetes_control_plane_ips": ["10.42.0.20"], "kubernetes_distro": "rke2"})
        self.assertEqual(rc, 1, out)
        self.assertIn("Kubernetes cannot run on", out)

    def test_undoing_the_change_that_made_the_cluster_forgets_it(self):
        import test_wave4_undo as w4u
        e = self.env(vars={"enable_kubernetes": True}, provisioned={"bastion": {"harden": True}, "kubernetes": dict(self.REC)})
        entry = undo.record(e.id, "setup (changed: vars)", "config",
                            {"prev_cfg": dict(e.load(), vars={"enable_kubernetes": False}), "what": "vars"})
        # the outputs the undo's apply leaves: the bastion, no control plane
        (e.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "192.168.160.10"}))
        with w4u._config_undo([]):
            rc, out = _capture(undo.perform, entry, {}, True)
        self.assertIsNone(rc, out)
        saved = e.load()
        self.assertFalse(saved["vars"]["enable_kubernetes"])
        self.assertEqual(saved["provisioned"], {"bastion": {"harden": True}})

    def test_managed_clouds_are_left_alone(self):
        e = self.env("aws", provisioned={"kubernetes": {"x": 1}})
        self._finish(e, {"bastion_public_ip": "1.2.3.4"}, cloud="aws")
        self.assertIn("kubernetes", e.load()["provisioned"])


# ---------------------------------------------------------------- a2-platform-logic#8: undo of a forced CRD removal

class ForcedCrdRemovalTests(unittest.TestCase):
    MANIFEST = w3p.CrdGuardTests.MANIFEST
    REL = w3p.CrdGuardTests.REL
    OBJECTS = {"items": [
        {"apiVersion": "kagent.dev/v1alpha2", "kind": "Agent",
         "metadata": {"name": "mine", "namespace": "default", "uid": "u1", "resourceVersion": "7", "generation": 2,
                      "creationTimestamp": "2026-09-01T00:00:00Z", "managedFields": [{"manager": "kubectl"}]},
         "spec": {"description": "my agent"}, "status": {"ready": True}},
        {"apiVersion": "kagent.dev/v1alpha2", "kind": "Agent",   # made by the kagent release: it comes back with it
         "metadata": {"name": "k8s-agent", "namespace": "kagent", "annotations": {"meta.helm.sh/release-name": "kagent"}}},
        {"apiVersion": "kagent.dev/v1alpha2", "kind": "Agent",   # owned by another object: its controller makes it again
         "metadata": {"name": "child", "namespace": "default", "ownerReferences": [{"kind": "Team", "name": "t"}]}}]}

    def _kube(self):
        self.read_at: list = []     # how many helm/kubectl changes (_run) had been made when the objects were read

        def get(c):
            if "json" in c:
                self.read_at.append(len(kube.calls))
                return w3p._cp(0, json.dumps(self.OBJECTS))
            return w3p._cp(0, "Agent default mine <none> <none>\n")
        kube = w3p.Kube([(lambda c: c[:3] == ["helm", "get", "manifest"],
                          lambda c: w3p._cp(0, self.MANIFEST if c[3] == "kagent-crds" else "")),
                         (lambda c: c[1] == "get" and "agents.kagent.dev" in " ".join(c), get)])
        return kube

    def test_force_keeps_the_user_objects_for_the_undo(self):
        ctx, kube, keep = w3p._ctx(), self._kube(), _tmp(self) / "undo-dir"
        with w3p._with(kube.patches(self.REL)), w3p._silenced() as out:
            pl.uninstall(["kagent", "kagent-crds"], ctx, force=True, keep_objects=keep)
        saved = ctx.saved_objects["kagent-crds"]
        self.assertEqual(saved["count"], 1)
        path = Path(saved["objects"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        data = json.loads(path.read_text())
        self.assertEqual(data["kind"], "List")
        [obj] = data["items"]
        self.assertEqual(obj["metadata"], {"name": "mine", "namespace": "default"})   # server fields dropped
        self.assertNotIn("status", obj)
        self.assertEqual(obj["spec"], {"description": "my agent"})
        self.assertIn("saved 1 custom resource(s)", out.getvalue())
        # saved before anything was removed - above all before the chart whose CRDs take them along
        self.assertEqual(len(kube.did("helm uninstall kagent-crds")), 1)
        self.assertEqual(self.read_at, [0])

    def test_nothing_is_saved_without_force_or_without_a_directory(self):
        ctx, kube = w3p._ctx(), self._kube()
        with w3p._with(kube.patches(self.REL)), w3p._silenced():
            pl.uninstall(["kagent", "kagent-crds"], ctx, force=True)
            self.assertEqual(ctx.saved_objects, {})
            pl.uninstall(["kagent"], ctx, keep_objects=_tmp(self))   # the companion stays: nothing is deleted
            self.assertEqual(ctx.saved_objects, {})
        self.assertFalse([q for q in kube.queries if "json" in q])

    def test_the_cli_records_them_and_the_undo_creates_them_again(self):
        ctx, kube = w3p._ctx(), self._kube()
        env = ctx.env
        self.addCleanup(undo.clear, env.id)
        before = {"kagent/kagent": w3p._rel(chart="kagent-0.7.0"), "kagent/kagent-crds": w3p._rel(chart="kagent-crds-0.7.0")}
        args = SimpleNamespace(items=["kagent", "kagent-crds"], force=True, auto_approve=True)
        # the releases as helm lists them: gone once `helm uninstall` ran
        with w3p._with(kube.patches(self.REL)), \
                mock.patch.object(pl, "installed_releases", side_effect=lambda c: {} if kube.did("helm uninstall") else before), \
                mock.patch.object(cli, "_approve"), w3p._silenced():
            self.assertEqual(cli._platform_uninstall(args, env, ctx), 0)
        entry = undo.entries(env.id)[-1]
        d = entry["data"]
        self.assertEqual(d["restore"]["kagent-crds"]["count"], 1)
        objects = d["restore"]["kagent-crds"]["objects"]
        self.assertTrue(Path(objects).exists())
        self.assertIn("then create the 1 custom resource(s) the forced removal deleted", undo._describe_platform(d))
        installed = []
        with w3p._with(kube.patches({})), mock.patch.object(undo, "_cluster", return_value=(None, env, {}, {}, ctx)), \
                mock.patch.object(cli, "_approve"), \
                mock.patch.object(pl, "install_one", side_effect=lambda item, *a, **k: installed.append(item)), \
                mock.patch.object(undo, "_audit_start"), w3p._silenced():
            undo.perform(entry, {}, True)
        self.assertEqual(installed, ["kagent-crds", "kagent"])
        applied = kube.did(f"kubectl apply --server-side --force-conflicts --field-manager=cloudseed-undo -f {objects}")
        self.assertEqual(len(applied), 1)

    def test_restore_failure_says_how_to_apply_by_hand(self):
        ctx = w3p._ctx()
        path = _tmp(self) / "x.objects.json"
        path.write_text("{}")
        kube = w3p.Kube(run_rc=lambda cmd: 1)
        with w3p._with(kube.patches({})), w3p._silenced() as out:
            self.assertFalse(pl.restore_crd_objects(ctx, str(path)))
        self.assertIn(f"kubectl apply --server-side -f {path}", out.getvalue())


# ---------------------------------------------------------------- the e2e battery cleans up after itself

class E2ETempDirTests(unittest.TestCase):
    def test_its_directories_are_removed_at_exit(self):
        import test_cli_e2e as e2e
        self.assertIn(e2e.HOME, e2e._TEMP_DIRS)
        self.assertIn(e2e.NO_VMWARE, e2e._TEMP_DIRS)
        d = e2e._tmp("cs-e2e-w5check-")
        e2e._TEMP_DIRS.remove(d)          # this one is removed here; the module's own at interpreter exit
        with mock.patch.object(e2e, "_TEMP_DIRS", [d]), mock.patch.dict(os.environ, {"CS_E2E_KEEP": ""}):
            e2e._remove_temp_dirs()
        self.assertFalse(Path(d).exists())


if __name__ == "__main__":
    unittest.main()
