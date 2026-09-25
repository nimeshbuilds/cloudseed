"""Wave-3 regression tests for the VMware target: Debian's image choice and cache name, install consent for qemu-img and
Go, the provider build fallback, terraform.rc writes, vmrest that exits at once, partly built environments, VM size and
host limits, public --cidr ranges, bundles that the Terraform state does not know, the hardware-version floor,
VMWARE_HOME, and the cloud-init templates (quoted SSH keys, first-boot-only apt masking, frozen previous template).
No VMware, no network, no real vmrest: every external command is faked."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import localvm, paths, secrets, services, ui  # noqa: E402
from cloudseed.clouds import vmware as vmw  # noqa: E402
from cloudseed.clouds.vmware import VMware  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "terraform" / "vmware"


def _tmp(test) -> Path:
    d = Path(tempfile.mkdtemp(prefix="cs-w3vmw-"))
    test.addCleanup(shutil.rmtree, d, True)
    return d


def _cfg(workdir: Path, env: str = "lab", name: str = "cloudseed", **vars_) -> dict:
    return {"cloud": "vmware", "env": env, "name": name, "network_cidr": "192.168.160.0/24", "workdir": str(workdir),
            "ssh_public_key": "ssh-ed25519 AAAA x", "vars": dict(vars_), "extra_vars": {}, "tags": {}}


def _state(workdir: Path, resources: list) -> None:
    (workdir / "stack").mkdir(parents=True, exist_ok=True)
    (workdir / "stack" / "terraform.tfstate").write_text(json.dumps({"version": 4, "resources": resources}))


def _vm(name: str, status: str | None = None, **attrs) -> dict:
    inst = {"attributes": {"name": name, **attrs}}
    if status:
        inst["status"] = status
    return {"mode": "managed", "type": "vmdesktop_vm", "name": "x", "instances": [inst]}


# ---------------------------------------------------------------- Debian image (a2-vmware#1)

class DebianImageTests(unittest.TestCase):
    def test_debian_uses_the_generic_images_under_their_own_cache_name(self):
        for arch in ("amd64", "arm64"):
            spec = localvm.IMAGES["debian-12"][arch]
            self.assertEqual(spec["file"], f"debian-12-generic-{arch}.qcow2")   # the cloud kernel has no AHCI (seed CD-ROM)
            self.assertNotIn("genericcloud", spec["file"])
            self.assertEqual(localvm.image_vmdk("debian-12", arch).name, f"debian-12-generic-{arch}.vmdk")

    def test_ubuntu_cache_names_are_unchanged(self):
        # base_disk forces a rebuild when its path changes: existing Ubuntu VMs must keep theirs
        for arch in ("amd64", "arm64"):
            self.assertEqual(localvm.image_vmdk("ubuntu-24.04", arch).name, f"ubuntu-24.04-{arch}.vmdk")

    def test_a_disk_built_from_genericcloud_is_not_reused_and_is_cleaned_up(self):
        d = _tmp(self)
        payload = b"qcow2 bytes"
        old = {"debian-12-arm64.vmdk": b"old disk", "debian-12-arm64.vmdk.ok": b"sha512:x\n",
               "debian-12-genericcloud-arm64.qcow2": b"old", "debian-12-genericcloud-arm64.qcow2.sha": b"sha512:y\n"}
        for name, data in old.items():
            (d / name).write_bytes(data)

        def download(url, dest, expected=None):
            dest.write_bytes(payload)

        def run(cmd, **kw):
            Path(cmd[-1]).write_bytes(b"vmdk")
            return subprocess.CompletedProcess(cmd, 0)

        with mock.patch.object(localvm, "IMAGES_DIR", d), \
                mock.patch.object(localvm, "_expected_sum", return_value=("sha512", hashlib.sha512(payload).hexdigest())), \
                mock.patch.object(localvm, "_download", download), mock.patch.object(localvm.deps, "find", return_value="/bin/qemu-img"), \
                mock.patch.object(localvm.subprocess, "run", run), mock.patch.object(ui, "info"), mock.patch.object(ui, "ok"):
            vmdk = localvm.ensure_image("debian-12", "arm64")
        self.assertEqual(vmdk, d / "debian-12-generic-arm64.vmdk")
        self.assertEqual(vmdk.read_bytes(), b"vmdk")
        for name in old:
            self.assertFalse((d / name).exists(), name)


# ---------------------------------------------------------------- qemu-img / Go only with consent (agentic#7, agentic#1)

class ToolConsentTests(unittest.TestCase):
    def setUp(self):
        for p in (mock.patch.object(localvm.deps, "find", return_value=None),
                  mock.patch.object(localvm.deps, "install", side_effect=AssertionError("must not install")),
                  mock.patch.object(services, "AUTO_INSTALL", False),
                  mock.patch.object(sys, "argv", ["cloudseed", "setup", "vmware", "-y"])):
            p.start()
            self.addCleanup(p.stop)
        env = {k: v for k, v in os.environ.items() if k not in ("CLOUDSEED_AGENT", "CLOUDSEED_REDACT", "CLOUDSEED_AUTO_INSTALL")}
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)

    def test_agent_session_stops_with_the_command_for_the_user(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "claude"}):
            for tool in ("qemu-img", "go"):
                with self.assertRaises(ui.Abort) as e:
                    localvm._ensure_tool(tool, "for a test")
                self.assertIn(f"cloudseed install {tool}", e.exception.msg)

    def test_non_interactive_run_without_approval_does_not_install(self):
        with mock.patch.object(ui, "interactive", return_value=False):
            with self.assertRaises(ui.Abort) as e:
                localvm._ensure_tool("qemu-img", "to convert the image")
        self.assertIn("cloudseed install qemu-img", e.exception.msg)
        self.assertEqual(e.exception.code, 2)

    def test_declined_at_a_terminal(self):
        with mock.patch.object(ui, "interactive", return_value=True), mock.patch.object(ui, "confirm", return_value=False):
            with self.assertRaises(ui.Abort) as e:
                localvm._ensure_tool("go", "to build the provider")
        self.assertIn("cloudseed install go", e.exception.msg)

    def test_approved_up_front_installs(self):
        found = iter([None, "/usr/local/bin/qemu-img"])
        with mock.patch.object(ui, "interactive", return_value=False), mock.patch.object(services, "AUTO_INSTALL", True), \
                mock.patch.object(localvm.deps, "install", return_value=True) as install, \
                mock.patch.object(localvm.deps, "find", side_effect=lambda t: next(found)), mock.patch.object(ui, "info"):
            self.assertEqual(localvm._ensure_tool("qemu-img", "to convert"), "/usr/local/bin/qemu-img")
        install.assert_called_once_with("qemu-img")

    def test_provider_build_without_go_asks_the_same_way(self):
        d = _tmp(self)
        src = d / "repo" / "providers" / "vmdesktop"
        src.mkdir(parents=True)
        (src / "go.mod").write_text("module x\n")
        binary = d / "p" / "0.1.0" / "darwin_arm64" / "terraform-provider-vmdesktop_v0.1.0"   # not built yet
        with mock.patch.object(localvm.paths, "REPO_ROOT", d / "repo"), mock.patch.object(localvm, "provider_binary", lambda: binary), \
                mock.patch.object(localvm, "write_terraform_rc"), mock.patch.object(ui, "interactive", return_value=False):
            with self.assertRaises(ui.Abort) as e:
                localvm.ensure_provider()
        self.assertIn("cloudseed install go", e.exception.msg)


# ---------------------------------------------------------------- provider build fallback (a2-vmware#2)

class ProviderFallbackTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.src = self.d / "repo" / "providers" / "vmdesktop"
        self.src.mkdir(parents=True)
        (self.src / "go.mod").write_text("module x\n")
        (self.src / "main.go").write_text("package main\n")
        self.binary = self.d / "p" / "0.1.0" / "darwin_arm64" / "terraform-provider-vmdesktop_v0.1.0"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text("working build")
        localvm._provider_stamp(self.binary).write_text("digest of older sources\n")   # an upgrade changed the sources
        for p in (mock.patch.object(localvm.paths, "REPO_ROOT", self.d / "repo"),
                  mock.patch.object(localvm, "provider_binary", lambda: self.binary),
                  mock.patch.object(localvm, "write_terraform_rc"),
                  mock.patch.object(localvm.deps, "find", return_value="/usr/bin/go"),
                  mock.patch.object(localvm.deps, "version_of", return_value="1.25.0"),   # new enough for go.mod
                  mock.patch.object(localvm.deps, "path_env", return_value={}),
                  mock.patch.object(ui, "info")):
            p.start()
            self.addCleanup(p.stop)

    def _failing(self, cmd, **kw):
        Path(cmd[cmd.index("-o") + 1]).write_text("half")
        return subprocess.CompletedProcess(cmd, 1)

    def test_failed_rebuild_keeps_using_the_working_build(self):
        with mock.patch.object(localvm.subprocess, "run", self._failing), mock.patch.object(ui, "warn") as warn:
            self.assertEqual(localvm.ensure_provider(stale_ok=True), self.binary)
        self.assertIn("using the existing build", warn.call_args[0][0])
        self.assertIn("install vmware-provider --rebuild", warn.call_args[0][0])
        self.assertEqual(self.binary.read_text(), "working build")
        self.assertTrue(localvm._provider_stale(self.binary, self.src))   # retried next time
        self.assertEqual(list(self.binary.parent.glob("*.tmp")), [])

    def test_broken_go_is_a_failed_build_too(self):
        with mock.patch.object(localvm.subprocess, "run", side_effect=PermissionError("not executable")), \
                mock.patch.object(ui, "warn") as warn:
            self.assertEqual(localvm.ensure_provider(stale_ok=True), self.binary)
        self.assertIn("not executable", warn.call_args[0][0])

    def test_explicit_rebuild_and_a_missing_build_still_fail(self):
        with mock.patch.object(localvm.subprocess, "run", self._failing):
            with self.assertRaises(ui.Abort) as e:
                localvm.ensure_provider(rebuild=True)
            self.assertIn("Building the VMware provider failed", e.exception.msg)
            with self.assertRaises(ui.Abort):   # `cloudseed install vmware-provider`: asked for, so a failure is one
                localvm.ensure_provider(rebuild=False, announce=True, stale_ok=True)
            self.binary.unlink()
            with self.assertRaises(ui.Abort):
                localvm.ensure_provider(stale_ok=True)

    def test_commands_that_change_vms_never_use_a_stale_build(self):
        # the stale build predates the stack being rendered (this very change: it deletes unknown VM bundles)
        with mock.patch.object(localvm.subprocess, "run", self._failing):
            with self.assertRaises(ui.Abort) as e:
                localvm.ensure_provider()
        self.assertIn("commands that change no VM", e.exception.msg)
        self.assertEqual(self.binary.read_text(), "working build")
        for dry_run in (True, False):
            with mock.patch.object(localvm, "ensure_provider", side_effect=ui.Abort("stop")) as ensure:
                with self.assertRaises(ui.Abort):
                    VMware().prepare(_cfg(self.d), dry_run=dry_run)
            ensure.assert_called_once_with(stale_ok=dry_run)


# ---------------------------------------------------------------- terraform.rc (a2-vmware#15)

class TerraformRcTests(unittest.TestCase):
    def test_written_atomically_and_only_when_it_changes(self):
        d = _tmp(self)
        rc = d / "terraform.rc"
        with mock.patch.object(localvm, "TERRAFORM_RC", rc), mock.patch.object(localvm, "PROVIDERS_DIR", d / "providers"), \
                mock.patch.object(localvm.paths, "ensure_home"):
            with mock.patch.object(localvm.paths, "atomic_write", wraps=paths.atomic_write) as atomic:
                localvm.write_terraform_rc()
                self.assertEqual(atomic.call_count, 1)
                inode = rc.stat().st_ino
                localvm.write_terraform_rc()   # every vmware command: nothing rewritten
                self.assertEqual(atomic.call_count, 1)
                self.assertEqual(rc.stat().st_ino, inode)
            self.assertIn(json.dumps((d / "providers").as_posix()), rc.read_text())
            self.assertEqual(oct(rc.stat().st_mode & 0o777), "0o644")
            with mock.patch.object(localvm, "PROVIDERS_DIR", d / "moved"):   # CLOUDSEED_HOME moved: replaced, not truncated
                localvm.write_terraform_rc()
            self.assertNotEqual(rc.stat().st_ino, inode)
            self.assertIn("moved", rc.read_text())


# ---------------------------------------------------------------- vmrest that exits at once (a2-vmware#4, cli-lifecycle#24)

class _Proc:
    def __init__(self, code):
        self.pid, self.returncode, self._code = 4242, code, code

    def poll(self):
        return self._code


class VmrestEarlyExitTests(unittest.TestCase):
    NOT_CONFIGURED = b"To listen on TCP port, Please use -C to update credential\nNot listening to either Unix Socket or TCP port, exiting\n"

    def setUp(self):
        self.d = _tmp(self)
        self.host = {"vmrest": "/fake/vmrest", "vmrun": "/fake/vmrun", "product": "fusion"}
        (self.d / "userhome").mkdir()
        for p in (mock.patch.object(localvm, "VMREST_CREDS", self.d / "vmware.json"),
                  mock.patch.object(localvm, "VMREST_PID", self.d / "vmrest.pid"),
                  mock.patch.object(localvm, "VMREST_LOCK", self.d / "vmrest.lock"),
                  mock.patch.object(localvm.paths, "HOME", self.d),
                  mock.patch.object(localvm.paths, "ensure_home"),
                  mock.patch.object(localvm.Path, "home", staticmethod(lambda: self.d / "userhome")),   # no ~/.vmrestCfg
                  mock.patch.dict(os.environ, {"VMREST_USER": "", "VMREST_PASSWORD": ""}),
                  mock.patch.object(localvm.time, "sleep"),
                  mock.patch.object(ui, "info"), mock.patch.object(ui, "ok"), mock.patch.object(ui, "warn")):
            p.start()
            self.addCleanup(p.stop)

    def _popen(self, *outputs):
        """Popen that writes `output` into the log it is given and exits with 1 (or keeps running for None)."""
        runs = list(outputs)

        def popen(cmd, stdout=None, stderr=None, **kw):
            out = runs.pop(0)
            if out is None:
                return _Proc(None)
            stdout.write(out)
            stdout.flush()
            return _Proc(1)
        return popen

    def test_start_reports_only_this_runs_exit(self):
        (self.d / "vmrest.log").write_bytes(b"an older run: Please use -C to update credential\n")
        with mock.patch.object(localvm.subprocess, "Popen", self._popen(b"Error: port 8697 in use\n")), \
                mock.patch.object(localvm, "_port_open", return_value=False), mock.patch.object(ui, "info") as info:
            exited = localvm._start_vmrest(self.host)
        self.assertEqual(exited["code"], 1)
        self.assertIn("port 8697 in use", exited["tail"])
        self.assertNotIn("older run", exited["tail"])
        self.assertFalse((self.d / "vmrest.pid").exists())
        self.assertIn(str(self.d / "vmrest.log"), info.call_args[0][0])   # the real log path, not ~/.cloudseed

    def _ensure(self, popen, configure=True, statuses=(200,)):
        calls = {"configure": [], "status": 0}
        ports = {"open": False}
        answers = list(statuses)

        def configure_vmrest(host, user, password, timeout=60):
            calls["configure"].append((user, password))
            return configure

        def rest_status(creds, timeout=15):
            calls["status"] += 1
            return answers.pop(0) if answers else 200

        def start_popen(cmd, **kw):
            proc = popen(cmd, **kw)
            ports["open"] = proc.poll() is None
            return proc

        with mock.patch.object(localvm.subprocess, "Popen", start_popen), mock.patch.object(localvm, "configure_vmrest", configure_vmrest), \
                mock.patch.object(localvm, "_rest_status", rest_status), \
                mock.patch.object(localvm, "_port_open", lambda port=8697: ports["open"]):
            try:
                return localvm.ensure_vmrest(self.host), calls
            except ui.Abort as e:
                return e, calls

    def test_unconfigured_vmrest_is_configured_with_cloudseeds_stored_credentials(self):
        localvm.save_creds("cloudseed", "Stored-pw1!", managed=True)
        result, calls = self._ensure(self._popen(self.NOT_CONFIGURED, None))
        self.assertEqual(result["password"], "Stored-pw1!")
        self.assertEqual(calls["configure"], [("cloudseed", "Stored-pw1!")])
        self.assertEqual(calls["status"], 1)   # no 45 s wait for a vmrest that had already exited
        self.assertEqual(localvm.load_creds()["password"], "Stored-pw1!")

    def test_users_own_credentials_are_not_written_into_vmrest(self):
        with mock.patch.dict(os.environ, {"VMREST_USER": "me", "VMREST_PASSWORD": "Mine-pw1!"}):
            result, calls = self._ensure(self._popen(self.NOT_CONFIGURED))
        self.assertIsInstance(result, ui.Abort)
        self.assertIn("vmrest -C", result.msg)
        self.assertIn("VMREST_USER/VMREST_PASSWORD", result.msg)
        self.assertEqual((calls["configure"], calls["status"]), ([], 0))
        localvm.save_creds("me", "Mine-pw1!", managed=False)
        result, calls = self._ensure(self._popen(self.NOT_CONFIGURED))
        self.assertIsInstance(result, ui.Abort)
        self.assertIn(str(localvm.VMREST_CREDS), result.msg)
        self.assertEqual(calls["configure"], [])

    def test_any_other_early_exit_is_reported_at_once(self):
        (self.d / "userhome" / ".vmrestCfg").write_text("configured")
        localvm.save_creds("cloudseed", "Stored-pw1!", managed=True)
        result, calls = self._ensure(self._popen(b"Error: something else went wrong\n"))
        self.assertIsInstance(result, ui.Abort)
        self.assertIn("exited at once", result.msg)
        self.assertIn("something else went wrong", result.msg)
        self.assertIn(str(self.d / "vmrest.log"), result.msg)
        self.assertEqual((calls["configure"], calls["status"]), ([], 0))

    def test_not_responding_names_the_real_log(self):
        localvm.save_creds("cloudseed", "Stored-pw1!", managed=True)
        with mock.patch.object(localvm.time, "monotonic", side_effect=[0, 0, 100, 100, 100, 100]):
            result, _ = self._ensure(self._popen(None), statuses=[None, None, None])
        self.assertIsInstance(result, ui.Abort)
        self.assertIn(str(self.d / "vmrest.log"), result.msg)
        self.assertNotIn("~/.cloudseed", result.msg)


class ConfigureRedactionTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "pty")
    def test_output_is_redacted_before_it_is_cut(self):
        secret = "Sup3r-Secret-Pw9"
        secrets.register(secret)
        r, w = os.pipe()
        os.write(w, ("x" * 50 + secret + "y" * 295).encode())   # the last 300 characters start inside the secret
        os.close(w)
        with mock.patch("pty.fork", return_value=(4242, r)), \
                mock.patch.object(localvm.os, "waitpid", return_value=(4242, 1 << 8)), mock.patch.object(ui, "warn") as warn:
            self.assertFalse(localvm.configure_vmrest({"vmrest": "/fake/vmrest"}, "u", "p", timeout=5))
        self.assertNotIn(secret[-4:], warn.call_args[0][0])


# ---------------------------------------------------------------- partly built environments (a2-vmware#7)

class PartlyBuiltEnvTests(unittest.TestCase):
    def test_only_vms_make_an_environment_existing(self):
        d = _tmp(self)
        _state(d, [{"mode": "managed", "type": "vmdesktop_network", "name": "private", "instances": [{"attributes": {}}]},
                   {"mode": "managed", "type": "random_integer", "name": "mac", "instances": [{"attributes": {}}]}])
        self.assertTrue(VMware().is_new(_cfg(d)))
        _state(d, [_vm("cloudseed-lab-bastion", status="tainted")])   # half-created: the next apply replaces it
        self.assertTrue(VMware().is_new(_cfg(d)))
        _state(d, [_vm("cloudseed-lab-bastion")])
        self.assertFalse(VMware().is_new(_cfg(d)))


# ---------------------------------------------------------------- VM sizes (a2-vmware#8)

class SizeTests(unittest.TestCase):
    def _problem(self, key, value, **vars_):
        c = VMware()
        return c.answer_problem(c.question(key), value, {"vars": vars_})

    def test_sizes_that_only_fail_at_power_on_are_refused(self):
        for key, bad in (("bastion_cpus", 0), ("workload_cpus", 0), ("kubernetes_cpus", 0), ("bastion_memory_mb", 0),
                         ("bastion_memory_mb", 2050), ("workload_memory_mb", 64), ("kubernetes_memory_mb", 511),
                         ("bastion_disk_gb", 0), ("workload_disk_gb", 5), ("kubernetes_disk_gb", 10)):
            self.assertIsNotNone(self._problem(key, bad), (key, bad))
        self.assertIn("2048", self._problem("bastion_memory_mb", 2050))   # the nearest valid size is suggested

    def test_saved_working_sizes_still_pass(self):
        cfg = _cfg(Path("/tmp/x"), bastion_cpus=2, bastion_memory_mb=2048, bastion_disk_gb=20, workload_cpus=1,
                   workload_memory_mb=512, workload_disk_gb=10, enable_kubernetes=True, kubernetes_cpus=2,
                   kubernetes_memory_mb=4096, kubernetes_disk_gb=40)
        self.assertEqual(VMware().invalid_answers(cfg), {})

    def test_kubernetes_minimums_follow_the_distribution(self):
        self.assertIn("kubeadm", self._problem("kubernetes_cpus", 1, enable_kubernetes=True, kubernetes_distro="kubeadm"))
        self.assertIsNone(self._problem("kubernetes_cpus", 1, enable_kubernetes=True, kubernetes_distro="rke2"))
        self.assertIn("RKE2", self._problem("kubernetes_memory_mb", 1024, enable_kubernetes=True, kubernetes_distro="rke2"))
        self.assertIn("kubeadm", self._problem("kubernetes_memory_mb", 1024, enable_kubernetes=True, kubernetes_distro="kubeadm"))
        self.assertIsNone(self._problem("kubernetes_memory_mb", 1024, enable_kubernetes=False))   # no cluster: not used

    def test_host_limits(self):
        c = VMware()
        with mock.patch.object(vmw.os, "cpu_count", return_value=4), mock.patch.object(vmw, "_host_memory_mb", return_value=8192):
            self.assertEqual(c.host_problems(_cfg(Path("/tmp/x"))), [])
            problems = c.host_problems(_cfg(Path("/tmp/x"), bastion_cpus=8, bastion_memory_mb=16384))
            self.assertEqual(len(problems), 2)
            self.assertIn("4 logical CPUs", problems[0])
            self.assertIn("--var bastion_cpus=2", problems[0])
            self.assertIn("8192 MB", problems[1])
            # workload / Kubernetes sizes only count when those VMs exist
            self.assertEqual(c.host_problems(_cfg(Path("/tmp/x"), workload_cpus=64, kubernetes_memory_mb=65536)), [])
            self.assertEqual(len(c.host_problems(_cfg(Path("/tmp/x"), workload_count=1, workload_cpus=64))), 1)
            self.assertTrue(any("bastion_cpus=8" in p for p in c.network_problems(_cfg(Path("/tmp/x"), bastion_cpus=8))))


# ---------------------------------------------------------------- the private network (a2-vmware#12, cli-lifecycle#20)

class NetworkRuleTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)

    def test_workloads_on_a_29(self):
        cfg = _cfg(self.d, workload_count=1)
        cfg["network_cidr"] = "10.123.0.0/29"
        problem = VMware().address_problems(cfg)[0]
        self.assertIn("at most 0", problem)
        self.assertIn("last usable address is .6", problem)
        self.assertNotIn(".10-.6", problem)

    def test_an_explicit_public_range_is_refused_for_a_new_environment(self):
        for cidr in ("8.8.8.0/24", "127.0.0.0/24", "100.64.0.0/24", "169.254.0.0/24"):
            cfg = _cfg(self.d)
            cfg.update(network_cidr=cidr, cidr_explicit=True)
            self.assertTrue(any("RFC 1918" in p for p in VMware().address_problems(cfg)), cidr)
        for cidr in ("10.123.0.0/24", "172.20.0.0/24", "192.168.200.0/24"):
            cfg = _cfg(self.d)
            cfg.update(network_cidr=cidr, cidr_explicit=True)
            self.assertEqual(VMware().address_problems(cfg), [], cidr)
        cfg = _cfg(self.d)
        cfg.update(network_cidr="100.64.0.0/24")   # assigned by VMware, not typed: never second-guessed
        self.assertEqual(VMware().address_problems(cfg), [])

    def test_an_existing_environment_on_a_public_range_is_only_warned(self):
        _state(self.d, [_vm("cloudseed-lab-bastion")])
        cfg = _cfg(self.d)
        cfg.update(network_cidr="8.8.8.0/24", cidr_explicit=True)
        vmw._WARNED.clear()
        with mock.patch.object(ui, "warn") as warn:   # setup: warned, not refused
            self.assertEqual(VMware().address_problems(cfg), [])
        self.assertIn("RFC 1918", warn.call_args[0][0])
        vmw._WARNED.clear()                           # (each warning is shown once per run)
        with mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [])), mock.patch.object(localvm, "list_vmnets", return_value=[]), \
                mock.patch.object(ui, "warn") as warn:
            VMware()._check_network(cfg, {}, None)
        self.assertIn("RFC 1918", warn.call_args[0][0])


# ---------------------------------------------------------------- bundles the state does not know (a2-vmware#0)

class StrayBundleTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.vms = self.d / "vms"
        p = mock.patch.object(paths.Env, "list_all", staticmethod(lambda: []))
        p.start()
        self.addCleanup(p.stop)
        vmw._STRAYS_REPORTED.clear()

    def _bundle(self, name, marker=False):
        b = self.vms / f"{name}.vmwarevm"
        b.mkdir(parents=True)
        (b / f"{name}.vmx").write_text('numvcpus = "2"\n')
        (b / "disk.vmdk").write_text("data")
        if marker:
            (b / localvm.INCOMPLETE_MARKER).write_text("")
        return b

    def test_report(self):
        self._bundle("cloudseed-lab-bastion")                  # an earlier env of this name, or lost state
        self._bundle("cloudseed-lab-vm1", marker=True)         # this env's own failed create: replaced silently
        known = self._bundle("cloudseed-lab-vm2")              # in the state
        self._bundle("someone-else")
        _state(self.d, [_vm("cloudseed-lab-vm2", vmx_path=str(known / "cloudseed-lab-vm2.vmx"))])
        report = VMware().vm_dir_report(_cfg(self.d))
        self.assertEqual(report["stray"], ["cloudseed-lab-bastion.vmwarevm"])
        self.assertEqual(report["foreign"], ["someone-else.vmwarevm"])

    def test_setup_warns_and_apply_refuses_a_running_one(self):
        b = self._bundle("cloudseed-lab-bastion")
        c = VMware()
        with mock.patch.object(ui, "warn") as warn:
            c.check_vars(_cfg(self.d))
        text = " ".join(str(call[0][0]) for call in warn.call_args_list)
        self.assertIn("cloudseed-lab-bastion.vmwarevm", text)
        self.assertIn("not in its Terraform state", text)
        self.assertIn("never deletes them", text)
        with mock.patch.object(localvm, "vmrun_list", return_value=[str(b / "cloudseed-lab-bastion.vmx")]):
            with self.assertRaises(ui.Abort) as e:
                c._report_strays(_cfg(self.d), c.vm_dir_report(_cfg(self.d)), host={"vmrun": "x", "product": "fusion"})
        self.assertIn("running", e.exception.msg)
        with mock.patch.object(localvm, "vmrun_list", return_value=[]), mock.patch.object(ui, "warn") as warn:
            c._report_strays(_cfg(self.d), c.vm_dir_report(_cfg(self.d)), host={"vmrun": "x", "product": "fusion"})
        warn.assert_not_called()   # already reported by this run

    def test_vms_recorded_with_a_relative_path_are_not_strays(self):
        # older versions kept a relative vm_dir as typed: the provider recorded paths relative to <workdir>/stack
        self.vms = self.d / "stack" / "vms"
        b = self._bundle("cloudseed-lab-bastion")
        _state(self.d, [_vm("cloudseed-lab-bastion", path="vms",
                            vmx_path="vms/cloudseed-lab-bastion.vmwarevm/cloudseed-lab-bastion.vmx")])
        cfg = _cfg(self.d, vm_dir="vms")
        self.assertEqual(VMware().vm_dir_report(cfg)["stray"], [])
        with mock.patch.object(localvm, "vmrun_list", return_value=[str(b / "cloudseed-lab-bastion.vmx")]):
            VMware()._report_strays(cfg, VMware().vm_dir_report(cfg), host={"vmrun": "x", "product": "fusion"})   # running: fine


class MissingVmDirTests(unittest.TestCase):
    """An apply must not create an empty vm_dir where this environment's VMs are recorded (an unmounted volume): the
    provider would then drop them from the state and create new ones."""

    def setUp(self):
        self.d = _tmp(self)
        self.vm_dir = self.d / "external" / "vms"
        _state(self.d, [_vm("cloudseed-lab-bastion",
                            vmx_path=str(self.vm_dir / "cloudseed-lab-bastion.vmwarevm" / "cloudseed-lab-bastion.vmx"))])

    def test_apply_stops_before_anything_when_the_vm_dir_is_gone(self):
        with mock.patch.object(localvm, "ensure_provider"), mock.patch.object(localvm, "require_host") as host, \
                mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [])):
            with self.assertRaises(ui.Abort) as e:
                VMware().prepare(_cfg(self.d, vm_dir=str(self.vm_dir)))
        self.assertIn("unmounted", e.exception.msg)
        self.assertIn(f"mkdir -p '{self.vm_dir}'", e.exception.msg)
        host.assert_not_called()
        self.assertFalse(self.vm_dir.exists())

    def test_only_when_the_recorded_vms_live_there(self):
        c = VMware()
        c._refuse_missing_vm_dir(_cfg(self.d, vm_dir=str(self.d / "moved")))   # vm_dir changed: VMs are rebuilt there
        self.vm_dir.mkdir(parents=True)
        c._refuse_missing_vm_dir(_cfg(self.d, vm_dir=str(self.vm_dir)))        # there: the provider finds out the rest
        _state(self.d, [_vm("cloudseed-lab-bastion", status="tainted",
                            vmx_path=str(self.d / "gone" / "cloudseed-lab-bastion.vmwarevm" / "cloudseed-lab-bastion.vmx"))])
        c._refuse_missing_vm_dir(_cfg(self.d, vm_dir=str(self.d / "gone")))    # replaced anyway


# ---------------------------------------------------------------- VMware release floor (a2-vmware#13)

class VersionTests(unittest.TestCase):
    def test_version_problem(self):
        self.assertEqual(localvm.version_tuple("13.6.4"), (13, 6))
        self.assertEqual(localvm.version_tuple("25H2"), (25, 0))
        self.assertIsNone(localvm.version_tuple("unknown"))
        for product, version in (("fusion", "12.2.5"), ("fusion", "11.5"), ("workstation", "16.2.5")):
            problem = localvm.version_problem({"product": product, "version": version, "arch": "arm64"})
            self.assertIn("too old", problem)
            self.assertIn("broadcom", problem)
        for product, version in (("fusion", "13.0.2"), ("fusion", "13.6.4"), ("workstation", "17.0.2"),
                                 ("workstation", "25H2"), ("fusion", "unknown")):
            self.assertIsNone(localvm.version_problem({"product": product, "version": version}), (product, version))

    def test_linux_version_is_detected(self):
        out = subprocess.CompletedProcess(["vmware", "-v"], 0, "VMware Workstation 17.5.2 build-23775571\n", "")
        with mock.patch.object(localvm.platform, "system", return_value="Linux"), \
                mock.patch.object(localvm.shutil, "which", return_value="/usr/bin/vmware"), \
                mock.patch.object(localvm.subprocess, "run", return_value=out), mock.patch.dict(os.environ, {"VMWARE_HOME": ""}):
            self.assertEqual(localvm.detect_host()["version"], "17.5.2")

    def test_prepare_refuses_a_new_environment_on_a_too_old_release(self):
        d = _tmp(self)
        host = {"product": "fusion", "version": "12.2.5", "os": "darwin", "arch": "amd64", "guest_arch": "amd64"}
        with mock.patch.object(localvm, "ensure_provider"), mock.patch.object(localvm, "require_host", return_value=host), \
                mock.patch.object(localvm, "ensure_vmrest") as vmrest, mock.patch.object(ui, "info"), \
                mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [])):
            with self.assertRaises(ui.Abort) as e:
                VMware().prepare(_cfg(d))
        self.assertIn("too old", e.exception.msg)
        vmrest.assert_not_called()


# ---------------------------------------------------------------- VMWARE_HOME (a2-vmware#12 item 5)

class VmwareHomeTests(unittest.TestCase):
    def test_tool_base_uses_vmware_home_only_when_it_exists(self):
        d = _tmp(self)
        home, default = d / "home", d / "default"
        default.mkdir()
        self.assertEqual(localvm._tool_base(str(home), [default]), default)   # missing: the default install
        home.mkdir()
        self.assertEqual(localvm._tool_base(str(home), [default]), home)      # exists: used (like the provider)
        self.assertEqual(localvm._tool_base(None, [d / "nope", default]), default)

    def test_problem_names_vmware_home_instead_of_a_download(self):
        d = _tmp(self)
        self.assertIn("has no vmrun", localvm.vmware_home_problem({"vmware_home": str(d), "found": False, "os": "darwin"}))
        self.assertIn("does not exist", localvm.vmware_home_problem({"vmware_home": str(d / "x"), "found": False}))
        self.assertIsNone(localvm.vmware_home_problem({"vmware_home": str(d), "found": True}))
        self.assertIsNone(localvm.vmware_home_problem({"found": False}))

    def test_install_and_require_do_not_send_the_user_to_download(self):
        d = _tmp(self)
        host = {"vmware_home": str(d), "found": False, "os": "darwin"}
        with mock.patch.object(localvm, "detect_host", return_value=host), \
                mock.patch.object(localvm.ui, "interactive", return_value=True), \
                mock.patch.object(localvm.time, "sleep", side_effect=AssertionError("must not wait for a download")), \
                mock.patch.object(localvm.subprocess, "run", side_effect=AssertionError("must not open a browser")), \
                mock.patch.dict(localvm.DRY_RUN_OK, {}, clear=True):
            for call in (localvm.install_hypervisor, localvm.require_host):
                with self.assertRaises(ui.Abort) as e:
                    call()
                self.assertIn(f"VMWARE_HOME={d}", e.exception.msg)


# ---------------------------------------------------------------- cloud-init templates (a2-vmware#3, a2-ansible#6)

# The first-boot template every bastion / workload VM created before this change was rendered from: the frozen copies
# in the modules must stay byte-identical to it, or upgrading cloudseed would rebuild those VMs.
_OLD_BASTION = '''#cloud-config
bootcmd:
  - [systemctl, disable, --now, apt-daily.timer, apt-daily-upgrade.timer]
  - [systemctl, mask, apt-daily.service, apt-daily-upgrade.service]
hostname: ${var.prefix}-bastion
manage_etc_hosts: true
users:
  - name: ${var.ssh_username}
    groups: [sudo]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${var.ssh_public_key}
ssh_pwauth: false
disable_root: true
package_update: true
packages: ${jsonencode(concat(["open-vm-tools", "nftables"], var.packages))}
write_files:
  - path: /etc/sysctl.d/90-cloudseed-forward.conf
    content: |
      net.ipv4.ip_forward = 1
  - path: /etc/nftables.conf
    permissions: "0600"
    content: |
      #!/usr/sbin/nft -f
      flush ruleset
      table inet filter {
        chain input { type filter hook input priority 0; policy accept; }
        chain forward {
          type filter hook forward priority 0; policy drop;
          ct state established,related accept
          ip saddr ${var.private_cidr} accept
        }
      }
      table ip nat {
        chain postrouting {
          type nat hook postrouting priority 100; policy accept;
          ip saddr ${var.private_cidr} oifname "eth0" masquerade
        }
      }
runcmd:
  - sysctl --system
  - systemctl enable --now nftables
  - nft -f /etc/nftables.conf
'''
_OLD_WORKLOAD = '''#cloud-config
bootcmd:
  - [systemctl, disable, --now, apt-daily.timer, apt-daily-upgrade.timer]
  - [systemctl, mask, apt-daily.service, apt-daily-upgrade.service]
hostname: ${local.names[count.index]}
manage_etc_hosts: true
users:
  - name: ${var.ssh_username}
    groups: [sudo]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${var.ssh_public_key}
ssh_pwauth: false
disable_root: true
package_update: true
packages: ${jsonencode(concat(["open-vm-tools"], var.packages))}
'''


def _heredoc(text: str, local: str) -> str:
    m = re.search(rf"\n  {local} = (?:\[for i in range\(var\.count_vms\) : )?<<-EOT\n(.*?)\n\s*EOT\n", text, re.S)
    return textwrap.dedent(m.group(1)) + "\n"


class TemplateTests(unittest.TestCase):
    def test_frozen_templates_are_byte_identical_to_the_previous_ones(self):
        bastion = (TF / "modules" / "bastion" / "main.tf").read_text()
        self.assertEqual(_heredoc(bastion, "user_data_legacy").replace("${local.ssh_key_yaml}", "${var.ssh_public_key}"),
                         _OLD_BASTION)
        workloads = (TF / "modules" / "workloads" / "main.tf").read_text()
        self.assertEqual(_heredoc(workloads, "user_data_legacy").replace("${local.ssh_key_yaml}", "${var.ssh_public_key}")
                         .replace("${local.names[i]}", "${local.names[count.index]}"), _OLD_WORKLOAD)

    def test_new_templates_mask_apt_on_the_first_boot_only_and_quote_the_key(self):
        for module in ("bastion", "workloads"):
            text = (TF / "modules" / module / "main.tf").read_text()
            current = _heredoc(text, "user_data")
            self.assertIn("[cloud-init-per, instance, cloudseed-apt-off,", current, module)
            self.assertNotIn("- [systemctl, mask, apt-daily", current, module)
            self.assertIn("- ${jsonencode(var.ssh_public_key)}", current, module)
            self.assertIn("lookup(var.legacy_user_data,", text, module)
        workloads = _heredoc((TF / "modules" / "workloads" / "main.tf").read_text(), "user_data")
        self.assertIn("[systemctl, enable, --now, apt-daily.timer, apt-daily-upgrade.timer]", workloads)   # never provisioned
        self.assertIn("unattended-upgrades", workloads)
        for module in ("bastion", "workloads", "kubernetes"):
            self.assertNotIn("- ${var.ssh_public_key}", (TF / "modules" / module / "main.tf").read_text(), module)

    def test_legacy_user_data_comes_from_the_state(self):
        d = _tmp(self)
        old = "#cloud-config\nbootcmd:\n  - [systemctl, mask, apt-daily.service, apt-daily-upgrade.service]\n"
        new = '#cloud-config\nbootcmd:\n  - [cloud-init-per, instance, cloudseed-apt-off, sh, -c, "systemctl mask apt-daily.service"]\n'
        _state(d, [_vm("cloudseed-lab-bastion", cloud_init={"user_data": old}),
                   _vm("cloudseed-lab-vm1", cloud_init={"user_data": old}),
                   _vm("cloudseed-lab-vm2", cloud_init={"user_data": new}),                     # already current
                   _vm("cloudseed-lab-vm3", status="tainted", cloud_init={"user_data": old}),   # replaced anyway
                   _vm("cloudseed-lab-cp1", cloud_init={"user_data": old})])                    # node template unchanged
        root = VMware().render_stack(_cfg(d), ROOT / "terraform")
        self.assertEqual(root["module"]["stack"]["legacy_user_data"], {"cloudseed-lab-bastion": old, "cloudseed-lab-vm1": old})
        self.assertEqual(VMware().render_stack(_cfg(self._fresh()), ROOT / "terraform")["module"]["stack"]["legacy_user_data"], {})
        # internal: no stack variable a user could set, and declared by the module itself
        self.assertNotIn("legacy_user_data", VMware().stack_vars(_cfg(d)))
        self.assertNotIn('variable "legacy_user_data"', (TF / "variables.tf").read_text())
        self.assertIn('variable "legacy_user_data"', (TF / "main.tf").read_text())

    def _fresh(self) -> Path:
        return _tmp(self)

    def test_variables_document_the_rebuilds(self):
        text = (TF / "variables.tf").read_text()
        packages = re.search(r'variable "packages" \{(.*?)\n\}', text, re.S).group(1)
        self.assertIn("rebuilds the bastion and every workload VM", packages)
        self.assertIn("rebuilds every VM", re.search(r'variable "ssh_username" \{(.*?)\n\}', text, re.S).group(1))


@unittest.skipUnless(shutil.which("terraform"), "terraform not installed")
class TerraformTemplateTests(unittest.TestCase):
    """Evaluates the modules' own expressions with terraform (no providers, no resources)."""

    def _apply(self, d: Path, text: str) -> dict:
        (d / "main.tf").write_text(text)
        env = {**os.environ, "TF_IN_AUTOMATION": "1", "TF_CLI_CONFIG_FILE": os.devnull, "CHECKPOINT_DISABLE": "1"}
        for cmd in (["init", "-input=false"], ["apply", "-auto-approve", "-input=false", "-lock=false"]):
            proc = subprocess.run(["terraform", *cmd, "-no-color"], cwd=d, env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        out = subprocess.run(["terraform", "output", "-json"], cwd=d, env=env, capture_output=True, text=True, timeout=60)
        return {k: v["value"] for k, v in json.loads(out.stdout).items()}

    def test_key_is_quoted_exactly_where_the_plain_form_breaks(self):
        src = (TF / "modules" / "kubernetes" / "main.tf").read_text()
        head = re.search(r"  ssh_key_head = (.*)\n", src).group(1)
        expr = re.search(r"  ssh_key_yaml = (\(.*?\))\n", src, re.S).group(1)
        for module in ("bastion", "workloads"):   # one rule everywhere
            other = (TF / "modules" / module / "main.tf").read_text()
            self.assertIn(f"  ssh_key_head = {head}\n", other)
            self.assertIn(f"  ssh_key_yaml = {expr}\n", other)
        expr = expr.replace("local.ssh_key_head", "(" + head.replace("var.ssh_public_key", "k") + ")").replace("var.ssh_public_key", "k")
        keys = {"ssh-ed25519 AAAA alice@mac": False, "ssh-ed25519 AAAA work laptop: me": True, "ssh-ed25519 AAAA me@mac:": True,
                "ssh-ed25519 AAAA a #b: c": False, "ssh-ed25519 AAAA a: #c": True, "ssh-ed25519 AAAA\tx": True,
                "ssh-ed25519 AAAA": False, "ssh-ed25519 AAAA a:b": False}
        got = self._apply(_tmp(self), f'variable "keys" {{\n  default = {json.dumps(list(keys))}\n}}\n'
                                      f'output "r" {{\n  value = {{ for k in var.keys : k => {expr} }}\n}}\n')["r"]
        for key, quoted in keys.items():
            self.assertEqual(got[key], json.dumps(key) if quoted else key, key)

    def test_size_validations(self):
        d = _tmp(self)
        shutil.copy(TF / "variables.tf", d / "variables.tf")
        env = {**os.environ, "TF_IN_AUTOMATION": "1", "TF_CLI_CONFIG_FILE": os.devnull, "CHECKPOINT_DISABLE": "1"}
        subprocess.run(["terraform", "init", "-input=false", "-no-color"], cwd=d, env=env, capture_output=True, check=True)

        def plan(**values):
            base = {"name": "n", "environment": "e", "base_disk": "/dev/null", "guest_os_id": "ubuntu-64", "vm_dir": "/tmp",
                    "ssh_public_key": "k", **values}
            args = [a for k, v in base.items() for a in ("-var", f"{k}={json.dumps(v) if isinstance(v, bool) else v}")]
            return subprocess.run(["terraform", "plan", "-input=false", "-no-color", "-lock=false", *args], cwd=d, env=env,
                                  capture_output=True, text=True, timeout=120)
        self.assertEqual(plan().returncode, 0)
        self.assertEqual(plan(kubernetes_cpus=0).returncode, 0)   # no cluster: a leftover value never blocks
        for bad in ({"bastion_cpus": 0}, {"bastion_memory_mb": 2050}, {"workload_disk_gb": 0}, {"workload_cpus": 1.5},
                    {"enable_kubernetes": True, "kubernetes_memory_mb": 1022}):
            proc = plan(**bad)
            self.assertNotEqual(proc.returncode, 0, bad)
            self.assertIn("Invalid value for variable", proc.stdout + proc.stderr, bad)


# ---------------------------------------------------------------- the real CLI (setup --dry-run refusals)

class CliRefusalTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        (self.d / "home").mkdir()
        self.env = {**os.environ, "CLOUDSEED_HOME": str(self.d / "cs"), "HOME": str(self.d / "home"),
                    "NO_COLOR": "1", "CLOUDSEED_NO_UPDATE_CHECK": "1"}

    def test_refusals(self):
        cases = [
            (["--var", "bastion_cpus=0"], "bastion_cpus"),
            (["--var", "bastion_memory_mb=2050"], "multiple of 4"),
            (["--var", "workload_memory_mb=64"], "workload_memory_mb"),
            (["--var", "bastion_disk_gb=0"], "bastion_disk_gb"),
            (["--var", "enable_kubernetes=true", "--var", "kubernetes_distro=kubeadm", "--var", "kubernetes_cpus=1"], "kubeadm"),
            (["--var", "bastion_memory_mb=100000000"], "memory"),
            (["--cidr", "8.8.8.0/24"], "RFC 1918"),
            (["--cidr", "10.123.0.0/29", "--var", "workload_count=1"], "last usable address is .6"),
        ]
        for args, needle in cases:
            proc = subprocess.run([sys.executable, str(ROOT / "bin" / "cloudseed"), "setup", "vmware", "--env", "w3", "-y",
                                   "--dry-run", *args], env=self.env, capture_output=True, text=True, timeout=120,
                                  stdin=subprocess.DEVNULL)
            out = proc.stdout + proc.stderr
            self.assertNotEqual(proc.returncode, 0, (args, out[-2000:]))
            self.assertIn(needle, out, (args, out[-2000:]))
            self.assertNotIn("Traceback", out, args)
            self.assertFalse((self.d / "cs" / "envs" / "vmware-w3" / "config.json").exists(), args)


if __name__ == "__main__":
    unittest.main()
