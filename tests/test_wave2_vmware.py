"""Wave-2 regression tests for the VMware target: typed stack variables, the kubernetes_version / CIS profile setup
inputs, vm_dir sharing checks at setup, the bastion's NAT source range, the Terraform count validations, image download
error handling and the vmrest ownership rules. No VMware, no network, no real vmrest: every external command is faked."""
from __future__ import annotations

import http.client
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import localvm, paths, ui  # noqa: E402
from cloudseed.clouds import vmware as vmw  # noqa: E402
from cloudseed.clouds.vmware import VMware  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _tmp(test) -> Path:
    d = Path(tempfile.mkdtemp(prefix="cs-w2vmw-"))
    test.addCleanup(shutil.rmtree, d, True)
    return d


def _cfg(workdir: Path, env: str = "lab", name: str = "cloudseed", **vars_) -> dict:
    return {"cloud": "vmware", "env": env, "name": name, "network_cidr": "192.168.160.0/24", "workdir": str(workdir),
            "ssh_public_key": "ssh-ed25519 AAAA x", "vars": dict(vars_), "extra_vars": {}, "tags": {}}


# ---------------------------------------------------------------- stack variables (vmware#4 handoff)

class StackVarsTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)

    def test_saved_strings_are_read_by_kind(self):
        # configs written by older versions hold strings; bool("no") would have switched FIPS/Kubernetes on
        v = VMware().stack_vars(_cfg(self.d, fips_mode="no", enable_kubernetes="false", workload_count="3",
                                     kubernetes_workers="0", bastion_cpus=4.0))
        self.assertIs(v["fips_mode"], False)
        self.assertIs(v["enable_kubernetes"], False)
        self.assertEqual((v["workload_count"], v["kubernetes_workers"], v["bastion_cpus"]), (3, 0, 4))
        self.assertIsInstance(v["bastion_cpus"], int)
        on = VMware().stack_vars(_cfg(self.d, fips_mode="yes", enable_kubernetes=True))
        self.assertIs(on["fips_mode"], True)
        self.assertIs(on["enable_kubernetes"], True)

    def test_defaults(self):
        v = VMware().stack_vars(_cfg(self.d))
        self.assertEqual((v["workload_count"], v["kubernetes_control_planes"], v["kubernetes_workers"], v["kubernetes_disk_gb"]),
                         (0, 1, 2, 40))
        self.assertIs(v["fips_mode"], False)

    def test_bad_saved_value_names_the_fix(self):
        for key, bad in (("workload_count", "abc"), ("fips_mode", "maybe"), ("kubernetes_workers", -1)):
            with self.assertRaises(ui.Abort) as e:
                VMware().stack_vars(_cfg(self.d, **{key: bad}))
            self.assertIn(f"--var {key}=VALUE", e.exception.msg, key)
            self.assertIn("vmware-lab", e.exception.msg)

    def test_setup_inputs_are_not_terraform_variables(self):
        v = VMware().stack_vars(_cfg(self.d, kubernetes_version="1.35", kubernetes_cis_profile=True))
        self.assertNotIn("kubernetes_version", v)
        self.assertNotIn("kubernetes_cis_profile", v)
        declared = (ROOT / "terraform" / "vmware" / "variables.tf").read_text()
        for key in v:   # every stack variable the adapter passes is declared by the module
            self.assertIn(f'variable "{key}"', declared, key)


# ---------------------------------------------------------------- kubernetes_version / CIS profile (ansible#23 handoff)

class KubernetesInputsTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.c = VMware()
        self.q = {q.key: q for q in VMware.questions}

    def test_questions_exist_and_are_advanced(self):
        ver, cis = self.q["kubernetes_version"], self.q["kubernetes_cis_profile"]
        self.assertEqual((ver.kind, ver.default, ver.advanced), ("str", "", True))
        self.assertEqual((cis.kind, cis.default, cis.advanced), ("bool", False, True))
        keys = [q.key for q in VMware.questions]
        self.assertLess(keys.index("kubernetes_distro"), keys.index("kubernetes_version"))   # validated against the distro
        self.assertLess(keys.index("kubernetes_distro"), keys.index("kubernetes_cis_profile"))
        # provision.py reads exactly these keys
        text = (ROOT / "cloudseed" / "provision.py").read_text()
        self.assertIn('cfg["vars"].get("kubernetes_version")', text)
        self.assertIn('cfg["vars"].get("kubernetes_cis_profile"', text)

    def test_version_shapes(self):
        p = vmw.kubernetes_version_problem
        for good, distro in (("", "rke2"), ("v1.36.4+rke2r1", "rke2"), ("1.35", "kubeadm"), ("v1.35", "kubeadm"),
                             ("v1.35.2", "kubeadm"), ("1.35", ""), ("v1.36.4+rke2r1", "")):
            self.assertIsNone(p(good, distro), (good, distro))
        for bad, distro in (("1.35", "rke2"), ("v1.36.4", "rke2"), ("v1.36.4+rke2r1", "kubeadm"), ("latest", ""),
                            ("v1.36.4+rke2r1; curl x|sh", "rke2"), ("v1.36.4+rke2r1\nid", "rke2"), ("1.35 1.36", "kubeadm"),
                            ("$(id)", "")):
            self.assertIsNotNone(p(bad, distro), (bad, distro))
        self.assertIn("v1.36.4+rke2r1", p("1.35", "rke2"))

    def test_value_problem_follows_the_distro(self):
        q = self.q["kubernetes_version"]
        rke2 = {"vars": {"kubernetes_distro": "rke2"}}
        kubeadm = {"vars": {"kubernetes_distro": "kubeadm"}}
        self.assertIsNotNone(self.c.answer_problem(q, "1.35", rke2))
        self.assertIsNone(self.c.answer_problem(q, "1.35", kubeadm))
        self.assertIsNone(self.c.answer_problem(q, "", rke2))
        cis = self.q["kubernetes_cis_profile"]
        self.assertIsNotNone(self.c.answer_problem(cis, True, kubeadm))
        self.assertIsNone(self.c.answer_problem(cis, True, rke2))
        self.assertIsNone(self.c.answer_problem(cis, False, kubeadm))

    def _collect(self, overrides, existing=None):
        args = mock.Mock(spec=[])
        with mock.patch.object(ui, "interactive", return_value=False), mock.patch.object(ui, "info"), \
                mock.patch.object(ui, "warn"):
            return self.c.collect_vars(args, existing or {}, _cfg(self.d), advanced=False, overrides=overrides)

    def test_var_overrides_are_accepted_and_checked(self):
        out = self._collect({"enable_kubernetes": True, "kubernetes_distro": "kubeadm", "kubernetes_version": "1.35"})
        self.assertEqual(out["kubernetes_version"], "1.35")
        self.assertIs(out["kubernetes_cis_profile"], False)
        out = self._collect({"enable_kubernetes": True, "kubernetes_version": "v1.36.4+rke2r1", "kubernetes_cis_profile": "yes"})
        self.assertEqual((out["kubernetes_version"], out["kubernetes_cis_profile"]), ("v1.36.4+rke2r1", True))
        with self.assertRaises(ui.Abort) as e:
            self._collect({"enable_kubernetes": True, "kubernetes_version": "1.35"})   # rke2 needs a release name
        self.assertIn("kubernetes_version", e.exception.msg)
        with self.assertRaises(ui.Abort):
            self._collect({"enable_kubernetes": True, "kubernetes_distro": "kubeadm", "kubernetes_cis_profile": True})

    def test_switching_distro_drops_a_saved_version_that_no_longer_fits(self):
        out = self._collect({"enable_kubernetes": True, "kubernetes_distro": "kubeadm"},
                            existing={"kubernetes_version": "v1.36.4+rke2r1", "kubernetes_cis_profile": True})
        self.assertEqual(out["kubernetes_version"], "")
        self.assertIs(out["kubernetes_cis_profile"], False)

    def test_control_plane_count_is_checked_even_without_kubernetes(self):
        q = self.q["kubernetes_control_planes"]
        self.assertIsNotNone(q.problem(0))
        self.assertIsNotNone(q.problem(vmw.MAX_CONTROL_PLANES + 1))
        self.assertIsNone(q.problem(3))
        self.assertIsNone(self.q["kubernetes_workers"].problem(0))   # zero workers is a valid (single-node) cluster
        problems = self.c.check_config(_cfg(self.d, kubernetes_control_planes=0))
        self.assertTrue(any("kubernetes_control_planes" in p for p in problems), problems)

    def test_check_config_reports_a_bad_version(self):
        problems = self.c.check_config(_cfg(self.d, enable_kubernetes=True, kubernetes_distro="rke2", kubernetes_version="1.35"))
        self.assertTrue(any(p.startswith("kubernetes_version=") for p in problems), problems)


# ---------------------------------------------------------------- vm_dir shared with others (cli-lifecycle#3 handoff)

class VmDirSharingTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.shared = self.d / "Virtual Machines.localized"
        self.shared.mkdir()
        self.envs: list[paths.Env] = []
        p = mock.patch.object(paths.Env, "list_all", staticmethod(lambda: list(self.envs)))
        p.start()
        self.addCleanup(p.stop)
        self.me = self.d / "me"
        (self.me / "stack").mkdir(parents=True)

    def _bundle(self, name):
        b = self.shared / f"{name}.vmwarevm"
        b.mkdir()
        (b / f"{name}.vmx").write_text("x")
        return b

    def _other(self, env, name="cloudseed", vm_dir=None):
        e = paths.Env("vmware", env, self.d / env)
        e.dir.mkdir(parents=True)
        cfg = {"name": name, "env": env, "workdir": str(e.dir), "vars": {"vm_dir": str(vm_dir)} if vm_dir else {}}
        (e.dir / "config.json").write_text(json.dumps(cfg))
        self.envs.append(e)
        return e

    def _mine(self, **kw):
        return _cfg(self.me, vm_dir=str(self.shared), **kw)

    def test_foreign_vms_are_reported(self):
        for name in ("Windows 11", "cloudseed-lab-bastion", "cloudseed-lab-2-bastion", "renamed"):
            self._bundle(name)
        state = {"resources": [{"mode": "managed", "type": "vmdesktop_vm", "name": "bastion", "instances": [
            {"attributes": {"vmx_path": str(self.shared / "renamed.vmwarevm" / "renamed.vmx")}}]}]}
        (self.me / "stack" / "terraform.tfstate").write_text(json.dumps(state))
        report = VMware().vm_dir_report(self._mine())
        self.assertEqual(report["foreign"], ["Windows 11.vmwarevm", "cloudseed-lab-2-bastion.vmwarevm"])
        self.assertEqual(report["shared"], [])
        with mock.patch.object(ui, "warn") as warn:
            VMware().check_vars(self._mine())
        text = " ".join(c.args[0] for c in warn.call_args_list)
        self.assertIn("Windows 11.vmwarevm", text)
        self.assertIn("never touches them", text)

    def test_another_env_in_the_same_directory(self):
        self._other("dev", vm_dir=self.shared)
        self._bundle("cloudseed-dev-bastion")     # dev's own VM: reported as the shared env, not as a foreign VM
        self._other("far")                        # its own default <workdir>/vms: not shared
        report = VMware().vm_dir_report(self._mine())
        self.assertEqual(report["shared"], [("vmware-dev", "cloudseed-dev")])
        self.assertEqual(report["foreign"], [])
        with mock.patch.object(ui, "warn") as warn:
            VMware().check_vars(self._mine())
        self.assertEqual(len(warn.call_args_list), 1)
        self.assertIn("also used by vmware-dev", warn.call_args[0][0])

    def test_relative_and_tilde_spellings_are_the_same_directory(self):
        self._other("dev", vm_dir=self.shared)
        rel = os.path.relpath(self.shared, self.me)
        self.assertEqual(VMware().vm_dir_report(_cfg(self.me, vm_dir=rel))["shared"], [("vmware-dev", "cloudseed-dev")])

    def test_default_directories_are_never_shared(self):
        self._other("dev")
        report = VMware().vm_dir_report(_cfg(self.me))
        self.assertEqual((report["shared"], report["foreign"]), ([], []))
        with mock.patch.object(ui, "warn") as warn:
            VMware().check_vars(_cfg(self.me))
        warn.assert_not_called()

    def test_same_vm_names_in_one_directory_are_refused_for_a_new_env(self):
        # name "cloudseed-lab" + env "x" and name "cloudseed" + env "lab-x" both give cloudseed-lab-x-bastion
        self._other("lab-x", vm_dir=self.shared)
        mine = _cfg(self.me, env="x", name="cloudseed-lab", vm_dir=str(self.shared))
        with self.assertRaises(ui.Abort) as e:
            VMware().check_vars(mine)
        self.assertIn("vmware-lab-x", e.exception.msg)
        self.assertIn("vm_dir", e.exception.msg)
        # an environment that already has VMs is only warned: it must stay manageable (and destroyable)
        state = {"resources": [{"mode": "managed", "type": "vmdesktop_vm", "name": "bastion", "instances": [{"attributes": {}}]}]}
        (self.me / "stack" / "terraform.tfstate").write_text(json.dumps(state))
        with mock.patch.object(ui, "warn") as warn:
            VMware().check_vars(mine)
        self.assertIn("take over each other's VM files", warn.call_args_list[0].args[0])

    def test_unreadable_neighbour_config_is_skipped(self):
        e = self._other("dev", vm_dir=self.shared)
        (e.dir / "config.json").write_text("{broken")
        self.assertEqual(VMware().vm_dir_report(self._mine())["shared"], [])


# ---------------------------------------------------------------- the bastion's NAT sources (vmware#3 remaining)

class NatSourceTests(unittest.TestCase):
    def test_static_zone_only(self):
        c = VMware()
        for cidr, want in (("192.168.160.0/24", "192.168.160.0/25"), ("10.9.0.0/16", "10.9.0.0/25"),
                           ("10.0.0.0/26", "10.0.0.0/26"), ("10.0.0.0/25", "10.0.0.0/25"), ("10.0.0.5/24", "10.0.0.0/25")):
            self.assertEqual(c.nat_source_cidrs({"network_cidr": cidr}), [want], cidr)
        # every static address of the plan (bastion .2 ... workers up to .127) is inside it
        import ipaddress
        net = ipaddress.ip_network(c.nat_source_cidrs({"network_cidr": "192.168.160.0/24"})[0])
        self.assertIn(ipaddress.ip_address(f"192.168.160.{vmw.MAX_STATIC_HOST}"), net)
        self.assertNotIn(ipaddress.ip_address("192.168.160.128"), net)   # VMware's DHCP pool


# ---------------------------------------------------------------- terraform/vmware count validations (ansible#35 handoff)

@unittest.skipUnless(shutil.which("terraform"), "terraform not installed")
class TerraformValidationTests(unittest.TestCase):
    """Plan only the module's variables.tf (no providers, no resources): the validation blocks are what is tested."""

    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp(prefix="cs-w2vmw-tf-"))
        shutil.copy(ROOT / "terraform" / "vmware" / "variables.tf", cls.d / "variables.tf")
        cls.env = {**os.environ, "TF_IN_AUTOMATION": "1", "TF_CLI_CONFIG_FILE": os.devnull, "CHECKPOINT_DISABLE": "1"}
        subprocess.run(["terraform", "init", "-input=false", "-no-color"], cwd=cls.d, env=cls.env, capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _plan(self, **values) -> subprocess.CompletedProcess:
        base = {"name": "n", "environment": "e", "base_disk": "/dev/null", "guest_os_id": "ubuntu-64", "vm_dir": "/tmp",
                "ssh_public_key": "k"}
        base.update(values)
        args = []
        for k, v in base.items():
            args += ["-var", f"{k}={json.dumps(v) if isinstance(v, bool) else v}"]
        return subprocess.run(["terraform", "plan", "-input=false", "-no-color", "-lock=false", *args], cwd=self.d,
                              env=self.env, capture_output=True, text=True)

    def test_counts(self):
        self.assertEqual(self._plan(enable_kubernetes=True, kubernetes_workers=0).returncode, 0)
        self.assertEqual(self._plan(enable_kubernetes=False, kubernetes_control_planes=0).returncode, 0)   # no cluster
        for bad in ({"kubernetes_workers": -1}, {"kubernetes_workers": 1.5}, {"workload_count": -2},
                    {"enable_kubernetes": True, "kubernetes_control_planes": 0}, {"kubernetes_control_planes": 1.5}):
            proc = self._plan(**bad)
            self.assertNotEqual(proc.returncode, 0, bad)
            self.assertIn("Invalid value for variable", proc.stdout + proc.stderr, bad)


# ---------------------------------------------------------------- image downloads (vmware#15 hardening)

class _Resp(io.BytesIO):
    def __init__(self, data: bytes, length="auto", fail_after: int | None = None):
        super().__init__(data)
        self.status = 200
        self.headers = {"Content-Length": str(len(data)) if length == "auto" else length}
        self.fail_after = fail_after

    def read(self, n=-1):
        if self.fail_after is not None and self.tell() >= self.fail_after:
            raise http.client.IncompleteRead(b"", 10)
        return super().read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class DownloadErrorTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        p = mock.patch.object(localvm.ui, "info")
        p.start()
        self.addCleanup(p.stop)

    def test_connection_cut_mid_body_is_a_fetch_error_and_leaves_nothing(self):
        dest = self.d / "img.vmdk"
        resp = _Resp(b"x" * (3 * 1024 * 1024), fail_after=1024 * 1024)
        with mock.patch.object(localvm.urllib.request, "urlopen", return_value=resp):
            with self.assertRaises(localvm._FetchError) as e:
                localvm._download("https://example.invalid/img.vmdk", dest)
        self.assertIn("example.invalid", str(e.exception))
        self.assertEqual(list(self.d.iterdir()), [])   # neither the image nor its .part

    def test_malformed_length_is_a_fetch_error(self):
        with mock.patch.object(localvm.urllib.request, "urlopen", return_value=_Resp(b"abc", length="lots")):
            with self.assertRaises(localvm._FetchError):
                localvm._download("https://example.invalid/img.vmdk", self.d / "img.vmdk")
        self.assertEqual(list(self.d.iterdir()), [])

    def test_checksum_list_errors(self):
        for exc in (http.client.RemoteDisconnected("closed"), http.client.BadStatusLine("x"), urllib.error.URLError("dns")):
            with mock.patch.object(localvm.urllib.request, "urlopen", side_effect=exc):
                with self.assertRaises(localvm._FetchError, msg=repr(exc)):
                    localvm._expected_sum("https://example.invalid/SHA256SUMS", "img")

    def test_ensure_image_turns_it_into_a_clean_abort(self):
        sums = b"%s *ubuntu-24.04-server-cloudimg-arm64.img\n" % (b"a" * 64)
        calls = iter([_Resp(sums), _Resp(b"x" * (2 * 1024 * 1024), fail_after=1024 * 1024)])
        with mock.patch.object(localvm, "IMAGES_DIR", self.d), \
                mock.patch.object(localvm.urllib.request, "urlopen", side_effect=lambda *a, **k: next(calls)):
            with self.assertRaises(ui.Abort) as e:
                localvm.ensure_image("ubuntu-24.04", "arm64")
        self.assertIn("Could not download", e.exception.msg)
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), [".lock"])


# ---------------------------------------------------------------- vmrest ownership (cli-lifecycle#26 / vmware#5 handoff)

@unittest.skipIf(os.name == "nt", "POSIX process handling")
class ListenerTests(unittest.TestCase):
    def test_lsof_output(self):
        out = subprocess.CompletedProcess([], 0, "4242\n4243\n", "")
        with mock.patch.object(localvm.shutil, "which", side_effect=lambda n: "/usr/sbin/lsof" if n == "lsof" else None), \
                mock.patch.object(localvm.subprocess, "run", return_value=out) as run:
            self.assertEqual(localvm._listener_pids(8697), [4242, 4243])
        self.assertIn("-iTCP:8697", run.call_args.args[0])

    def test_ss_output_when_lsof_is_missing(self):
        line = 'LISTEN 0 4096 127.0.0.1:8697 0.0.0.0:* users:(("vmrest",pid=5151,fd=3))\n'
        with mock.patch.object(localvm.shutil, "which", side_effect=lambda n: "/usr/bin/ss" if n == "ss" else None), \
                mock.patch.object(localvm.os.path, "exists", return_value=False), \
                mock.patch.object(localvm.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, line, "")):
            self.assertEqual(localvm._listener_pids(8697), [5151])

    def test_no_tool_no_pids(self):
        with mock.patch.object(localvm.shutil, "which", return_value=None), \
                mock.patch.object(localvm.os.path, "exists", return_value=False), \
                mock.patch.object(localvm.subprocess, "run") as run:
            self.assertEqual(localvm._listener_pids(8697), [])
        run.assert_not_called()

    def test_consented_stop_kills_only_the_port_holder(self):
        with mock.patch.object(localvm, "_listener_pids", return_value=[4242, 99]), \
                mock.patch.object(localvm, "_is_vmrest", side_effect=lambda pid: pid == 4242), \
                mock.patch.object(localvm, "_kill") as kill, mock.patch.object(localvm.subprocess, "run") as run:
            localvm._stop_users_vmrest()
        kill.assert_called_once_with(4242)
        run.assert_not_called()   # no pkill: another vmrest of this user (another port, another tool) keeps running

    def test_consented_stop_falls_back_when_the_holder_is_unknown(self):
        with mock.patch.object(localvm, "_listener_pids", return_value=[]), mock.patch.object(localvm, "_kill") as kill, \
                mock.patch.object(localvm.subprocess, "run") as run:
            localvm._stop_users_vmrest()
        kill.assert_not_called()
        self.assertEqual(run.call_args.args[0][:2], ["pkill", "-x"])


class VmrestOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.host = {"vmrest": "/fake/vmrest", "vmrun": "/fake/vmrun", "product": "fusion"}
        self.clock = [0.0]

        def sleep(seconds):
            self.clock[0] += seconds

        for p in (mock.patch.object(localvm, "VMREST_CREDS", self.d / "vmware.json"),
                  mock.patch.object(localvm, "VMREST_PID", self.d / "vmrest.pid"),
                  mock.patch.object(localvm, "VMREST_LOCK", self.d / "vmrest.lock"),
                  mock.patch.object(localvm.paths, "ensure_home"),
                  mock.patch.dict(os.environ, {"VMREST_USER": "", "VMREST_PASSWORD": ""}),
                  mock.patch.object(localvm.time, "sleep", sleep),
                  mock.patch.object(localvm.time, "monotonic", lambda: self.clock[0]),
                  mock.patch.object(localvm.ui, "warn"), mock.patch.object(localvm.ui, "ok"), mock.patch.object(localvm.ui, "info")):
            p.start()
            self.addCleanup(p.stop)

    def _run(self, statuses, own_pid, interactive=False, consent=False):
        ports = {"open": True}
        calls = {"configure": 0, "kill": [], "stop_users": 0, "run": []}

        def kill(pid):
            calls["kill"].append(pid)
            ports["open"] = False

        def stop_users():
            calls["stop_users"] += 1
            ports["open"] = False

        def configure(host, user, password, timeout=60):
            calls["configure"] += 1
            return True

        def run(cmd, **kw):   # never reaches a real process
            calls["run"].append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(localvm, "_rest_status", side_effect=list(statuses)), \
                mock.patch.object(localvm, "configure_vmrest", configure), \
                mock.patch.object(localvm, "_start_vmrest", lambda host: ports.update(open=True)), \
                mock.patch.object(localvm, "_kill", kill), mock.patch.object(localvm, "_stop_users_vmrest", stop_users), \
                mock.patch.object(localvm, "_own_vmrest_pid", return_value=own_pid), \
                mock.patch.object(localvm, "_port_open", lambda port=8697: ports["open"]), \
                mock.patch.object(localvm.subprocess, "run", run), \
                mock.patch.object(localvm.ui, "interactive", return_value=interactive), \
                mock.patch.object(localvm.ui, "confirm", return_value=consent):
            try:
                return localvm.ensure_vmrest(self.host), calls
            except ui.Abort as e:
                return e, calls

    def test_users_own_credentials_are_never_replaced_silently(self):
        # the user once exported VMREST_USER/VMREST_PASSWORD (saved as managed: false) and later re-ran `vmrest -C`
        localvm.save_creds("me", "Mine-pw1!", managed=False)
        result, calls = self._run([401], own_pid=4242)
        self.assertIsInstance(result, ui.Abort)
        self.assertIn("VMREST_USER", result.msg)
        self.assertEqual((calls["kill"], calls["stop_users"], calls["configure"], calls["run"]), ([], 0, 0, []))
        self.assertEqual(localvm.load_creds()["password"], "Mine-pw1!")

    def test_with_consent_only_the_recorded_process_is_stopped(self):
        localvm.save_creds("me", "Mine-pw1!", managed=False)
        result, calls = self._run([401, 200], own_pid=4242, interactive=True, consent=True)
        self.assertIsInstance(result, dict)
        self.assertEqual((calls["kill"], calls["stop_users"], calls["configure"]), ([4242], 0, 1))
        self.assertIs(localvm.load_creds()["managed"], True)

    def test_cloudseeds_own_configuration_is_still_repaired(self):
        localvm.save_creds("cloudseed", "Stored-pw1!")          # managed: generated by cloudseed
        result, calls = self._run([401, 200], own_pid=4242)
        self.assertIsInstance(result, dict)
        self.assertEqual((calls["kill"], calls["configure"]), ([4242], 1))

    def test_older_credentials_file_without_the_flag_counts_as_cloudseeds(self):
        (self.d / "vmware.json").write_text(json.dumps({"user": "cloudseed", "password": "Old-pw1!"}))
        result, calls = self._run([401, 200], own_pid=4242)
        self.assertEqual((calls["kill"], calls["configure"]), ([4242], 1))


# ---------------------------------------------------------------- the real CLI (dry runs, isolated home)

class CliDryRunTests(unittest.TestCase):
    """setup --dry-run through bin/cloudseed with an isolated home and no VMware (VMWARE_HOME points nowhere)."""

    def setUp(self):
        self.d = _tmp(self)
        self.env = {**os.environ, "CLOUDSEED_HOME": str(self.d / "cs"), "HOME": str(self.d / "home"),
                    "VMWARE_HOME": str(self.d / "no-vmware"), "NO_COLOR": "1", "CLOUDSEED_NO_UPDATE_CHECK": "1"}
        (self.d / "home").mkdir()

    def _setup(self, *args) -> subprocess.CompletedProcess:
        # refused configurations stop before any Terraform or provider build, so this stays fast and offline
        return subprocess.run([sys.executable, str(ROOT / "bin" / "cloudseed"), "setup", "vmware",
                               "--env", "w2", "-y", "--dry-run", *args], env=self.env, capture_output=True, text=True,
                              timeout=120, stdin=subprocess.DEVNULL)

    def test_refusals(self):
        cases = [
            (["--var", "enable_kubernetes=true", "--var", "kubernetes_version=1.35"], "kubernetes_version"),
            (["--var", "enable_kubernetes=true", "--var", "kubernetes_distro=kubeadm", "--var", "kubernetes_cis_profile=true"],
             "CIS profile"),
            (["--var", "kubernetes_version=v1.36.4+rke2r1;id"], "kubernetes_version"),
            (["--ssh-username", "yes"], "YAML"),
            (["--var", "enable_kubernetes=true", "--var", "workload_count=11"], "workload_count=11"),
            (["--var", "kubernetes_control_planes=0"], "kubernetes_control_planes"),
        ]
        for args, needle in cases:
            proc = self._setup(*args)
            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, (args, out[-2000:]))
            self.assertIn(needle, out, args)
            self.assertNotIn("Traceback", out, args)
            self.assertNotIn("not a variable of the vmware stack", out, args)   # a setup input, not an unknown --var
            self.assertFalse((self.d / "cs" / "envs" / "vmware-w2" / "config.json").exists(), args)


if __name__ == "__main__":
    unittest.main()
