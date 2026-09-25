"""Regression tests for the VMware target: localvm (vmrest, images, provider build, teardown helpers) and the vmware
cloud adapter (address plan, vm_dir, shared networks, Terraform state migration). No VMware, no network, no real vmrest:
every external command and HTTP call is faked."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import urllib.error
from pathlib import Path, PureWindowsPath
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import localvm, netutil, paths, ui  # noqa: E402
from cloudseed.clouds.vmware import VMware  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _tmp(test) -> Path:
    d = Path(tempfile.mkdtemp(prefix="cs-vmw-"))
    test.addCleanup(shutil.rmtree, d, True)
    return d


class _Resp(io.BytesIO):
    """Minimal urlopen() response."""

    def __init__(self, data: bytes, status: int = 200, length: int | None = None):
        super().__init__(data)
        self.status = status
        self.headers = {"Content-Length": str(len(data) if length is None else length)}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# ---------------------------------------------------------------- terraform.rc (Windows paths)

class TerraformRcTests(unittest.TestCase):
    def test_windows_path_is_escaped(self):
        d = _tmp(self)
        rc = d / "terraform.rc"
        with mock.patch.object(localvm, "PROVIDERS_DIR", PureWindowsPath(r"C:\Users\alice\.cloudseed\providers")), \
                mock.patch.object(localvm, "TERRAFORM_RC", rc), mock.patch.object(localvm.paths, "ensure_home"):
            localvm.write_terraform_rc()
        text = rc.read_text()
        self.assertIn('path    = "C:/Users/alice/.cloudseed/providers"', text)
        self.assertNotIn("\\", text)   # no (illegal) HCL escape left

    def test_quotes_in_path_are_escaped(self):
        d = _tmp(self)
        rc = d / "terraform.rc"
        with mock.patch.object(localvm, "PROVIDERS_DIR", Path('/tmp/we"ird/providers')), \
                mock.patch.object(localvm, "TERRAFORM_RC", rc), mock.patch.object(localvm.paths, "ensure_home"):
            localvm.write_terraform_rc()
        line = next(ln for ln in rc.read_text().splitlines() if ln.strip().startswith("path"))
        self.assertEqual(json.loads(line.split("=", 1)[1].strip()), '/tmp/we"ird/providers')


# ---------------------------------------------------------------- provider build

class ProviderBuildTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.src = self.d / "repo" / "providers" / "vmdesktop"
        (self.src / "internal").mkdir(parents=True)
        (self.src / "go.mod").write_text("module x\n")
        (self.src / "go.sum").write_text("")
        (self.src / "main.go").write_text("package main\n")
        (self.src / "internal" / "a_test.go").write_text("package internal\n")
        self.binary = self.d / "providers" / "0.1.0" / "darwin_arm64" / "terraform-provider-vmdesktop_v0.1.0"
        for p in (mock.patch.object(localvm.paths, "REPO_ROOT", self.d / "repo"),
                  mock.patch.object(localvm, "provider_binary", lambda: self.binary),
                  mock.patch.object(localvm, "write_terraform_rc")):
            p.start()
            self.addCleanup(p.stop)

    def _stamp(self):
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.binary.write_text("bin")
        localvm._provider_stamp(self.binary).write_text(localvm._provider_digest(self.src) + "\n")

    def test_stale_by_content_not_mtime(self):
        self._stamp()
        self.assertFalse(localvm._provider_stale(self.binary, self.src))
        future = time.time() + 3600   # a bundle extracts its sources with fresh mtimes on every run
        for f in self.src.rglob("*"):
            os.utime(f, (future, future))
        self.assertFalse(localvm._provider_stale(self.binary, self.src))
        (self.src / "internal" / "a_test.go").write_text("package internal // changed test\n")
        self.assertFalse(localvm._provider_stale(self.binary, self.src))   # tests do not change the binary
        (self.src / "go.sum").write_text("changed\n")
        self.assertTrue(localvm._provider_stale(self.binary, self.src))

    def test_missing_stamp_is_stale(self):
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.binary.write_text("bin")
        self.assertTrue(localvm._provider_stale(self.binary, self.src))

    def test_up_to_date_is_announced_only_on_request(self):
        self._stamp()
        with mock.patch.object(localvm.subprocess, "run") as run, mock.patch.object(localvm.ui, "ok") as ok:
            self.assertEqual(localvm.ensure_provider(), self.binary)   # every vmware command: silent
            ok.assert_not_called()
            localvm.ensure_provider(rebuild=False)   # `cloudseed install vmware-provider`
            self.assertIn("already built", ok.call_args[0][0])
            ok.reset_mock()
            localvm.ensure_provider(announce=True)
            self.assertIn("already built", ok.call_args[0][0])
        run.assert_not_called()

    def test_stale_without_go_keeps_the_existing_build(self):
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.binary.write_text("bin")   # built by an older version (no stamp)
        with mock.patch.object(localvm.deps, "find", return_value=None), \
                mock.patch.object(localvm.deps, "install") as install, mock.patch.object(localvm.subprocess, "run") as run:
            self.assertEqual(localvm.ensure_provider(), self.binary)
        install.assert_not_called()   # never downloads Go just to rebuild a binary that exists
        run.assert_not_called()

    def test_build_is_readonly_trimpath_atomic_and_stamped(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            Path(cmd[cmd.index("-o") + 1]).write_text("new binary")
            return subprocess.CompletedProcess(cmd, 0)

        with mock.patch.object(localvm.deps, "find", return_value="/usr/bin/go"), \
                mock.patch.object(localvm.deps, "version_of", return_value="1.25.0"), \
                mock.patch.object(localvm.deps, "path_env", return_value={}), mock.patch.object(localvm.subprocess, "run", fake_run):
            self.assertEqual(localvm.ensure_provider(), self.binary)
        self.assertEqual(len(calls), 1)   # no `go mod tidy`
        self.assertEqual(calls[0][:5], ["/usr/bin/go", "build", "-mod=readonly", "-trimpath", "-o"])
        self.assertEqual(self.binary.read_text(), "new binary")
        self.assertEqual(list(self.binary.parent.glob("*.tmp")), [])
        self.assertFalse(localvm._provider_stale(self.binary, self.src))
        # the package directory holds only the binary: Terraform's lock-file checksum covers all of it
        self.assertEqual([p.name for p in self.binary.parent.iterdir()], [self.binary.name])

    def test_failed_build_leaves_the_old_binary(self):
        self.binary.parent.mkdir(parents=True, exist_ok=True)
        self.binary.write_text("old")

        def fake_run(cmd, **kw):
            Path(cmd[cmd.index("-o") + 1]).write_text("half")
            return subprocess.CompletedProcess(cmd, 1)

        with mock.patch.object(localvm.deps, "find", return_value="/usr/bin/go"), \
                mock.patch.object(localvm.deps, "version_of", return_value="1.25.0"), \
                mock.patch.object(localvm.deps, "path_env", return_value={}), mock.patch.object(localvm.subprocess, "run", fake_run):
            with self.assertRaises(ui.Abort):
                localvm.ensure_provider(rebuild=True)
        self.assertEqual(self.binary.read_text(), "old")
        self.assertEqual(list(self.binary.parent.glob("*.tmp")), [])


# ---------------------------------------------------------------- hypervisor install messages

class InstallHypervisorTests(unittest.TestCase):
    def test_already_installed_says_so(self):
        host = {"found": True, "version": "13.6.4", "vmrun": "/Applications/VMware Fusion.app/Contents/Library/vmrun"}
        with mock.patch.object(localvm, "detect_host", return_value=host), mock.patch.object(localvm.ui, "ok") as ok, \
                mock.patch.object(localvm.ui, "info") as info:
            self.assertTrue(localvm.install_hypervisor("/nonexistent.dmg"))
        self.assertIn("already installed", ok.call_args[0][0])
        self.assertIn("13.6.4", ok.call_args[0][0])
        self.assertIn("ignored", info.call_args[0][0])

    def test_missing_from_file_is_reported_before_any_wait(self):
        with mock.patch.object(localvm, "detect_host", return_value={"found": False}), \
                mock.patch.object(localvm.ui, "interactive", return_value=True), \
                mock.patch.object(localvm.time, "sleep", side_effect=AssertionError("must not wait for a download")):
            with self.assertRaises(ui.Abort):
                localvm.install_hypervisor("/nonexistent/VMware-Fusion-13.dmg")

    def test_find_installer_rejects_directories(self):
        d = _tmp(self)
        self.assertIsNone(localvm.find_installer(str(d)))


# ---------------------------------------------------------------- vmrest

class VmrestTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.host = {"vmrest": "/fake/vmrest", "vmrun": "/fake/vmrun", "product": "fusion"}
        self.clock = [1000.0]   # a fake clock: waiting takes no real time

        def sleep(seconds):
            self.clock[0] += seconds

        for p in (mock.patch.object(localvm, "VMREST_CREDS", self.d / "vmware.json"),
                  mock.patch.object(localvm, "VMREST_PID", self.d / "vmrest.pid"),
                  mock.patch.object(localvm, "VMREST_LOCK", self.d / "vmrest.lock"),
                  mock.patch.object(localvm.paths, "ensure_home"),
                  mock.patch.dict(os.environ, {"VMREST_USER": "", "VMREST_PASSWORD": ""}),
                  mock.patch.object(localvm.time, "sleep", sleep),
                  mock.patch.object(localvm.time, "monotonic", lambda: self.clock[0]),
                  mock.patch.object(localvm.ui, "interactive", return_value=False)):
            p.start()
            self.addCleanup(p.stop)
        localvm.save_creds("cloudseed", "Stored-pw1!")

    def _run(self, status, own_pid=None, port_open=True, port_after_kill=False):
        """ensure_vmrest with vmrest answering `status` (a value or a list, one per call)."""
        statuses = list(status) if isinstance(status, list) else None
        ports = {"open": port_open}
        calls = {"configure": [], "start": 0, "kill": [], "pkill": 0, "asked": 0}

        def rest_status(creds, timeout=15):
            calls["asked"] += 1
            return statuses.pop(0) if statuses is not None else status

        def configure(host, user, password, timeout=60):
            calls["configure"].append((user, password))
            return True

        def start(host):
            calls["start"] += 1
            ports["open"] = True

        def kill(pid):
            calls["kill"].append(pid)
            ports["open"] = port_after_kill

        def run(cmd, **kw):
            if cmd and cmd[0] == "pkill":
                calls["pkill"] += 1
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(localvm, "_rest_status", rest_status), \
                mock.patch.object(localvm, "configure_vmrest", configure), mock.patch.object(localvm, "_start_vmrest", start), \
                mock.patch.object(localvm, "_kill", kill), mock.patch.object(localvm, "_own_vmrest_pid", return_value=own_pid), \
                mock.patch.object(localvm, "_port_open", lambda port=8697: ports["open"]), \
                mock.patch.object(localvm.subprocess, "run", run):
            try:
                result = localvm.ensure_vmrest(self.host)
            except ui.Abort as e:
                result = e
        return result, calls

    def test_ok(self):
        creds, calls = self._run(200)
        self.assertEqual(creds["password"], "Stored-pw1!")
        self.assertEqual((calls["configure"], calls["start"], calls["kill"], calls["pkill"], calls["asked"]), ([], 0, [], 0, 1))

    def test_slow_or_failing_vmrest_is_not_a_credential_problem(self):
        for status in (None, 500, 503):
            result, calls = self._run(status, own_pid=4242)
            self.assertIsInstance(result, ui.Abort, status)
            self.assertIn("not responding", result.msg)
            self.assertEqual(calls["kill"], [])
            self.assertEqual(calls["pkill"], 0)
            self.assertEqual(calls["configure"], [])
            self.assertGreater(calls["asked"], 2)   # retried with backoff before giving up
            self.assertEqual(localvm.load_creds()["password"], "Stored-pw1!")   # credentials never rotated

    def test_busy_vmrest_is_waited_for(self):
        creds, calls = self._run([None, 503, 200])
        self.assertEqual(creds["password"], "Stored-pw1!")
        self.assertEqual(calls["configure"], [])

    def test_401_from_our_vmrest_resets_it(self):
        result, calls = self._run([401, 200], own_pid=4242)
        self.assertEqual(calls["kill"], [4242])
        self.assertEqual(calls["pkill"], 0)
        self.assertEqual(len(calls["configure"]), 1)
        self.assertEqual(calls["start"], 1)
        saved = localvm.load_creds()
        self.assertEqual((saved["user"], saved["password"], saved["managed"]), ("cloudseed", result["password"], True))

    def test_401_from_a_foreign_vmrest_is_left_alone(self):
        result, calls = self._run(401, own_pid=None)
        self.assertIsInstance(result, ui.Abort)
        self.assertIn("VMREST_USER", result.msg)
        self.assertEqual((calls["kill"], calls["pkill"], calls["configure"]), ([], 0, []))
        self.assertEqual(localvm.load_creds()["password"], "Stored-pw1!")

    def test_foreign_vmrest_replaced_only_with_consent_and_only_when_it_stops(self):
        with mock.patch.object(localvm.ui, "interactive", return_value=True), \
                mock.patch.object(localvm.ui, "confirm", return_value=True):
            result, calls = self._run(401, own_pid=None, port_after_kill=True)
        # the user's pkill could not stop it (e.g. root's `sudo vmrest`): its configuration is not touched
        self.assertEqual(calls["pkill"], 1)
        self.assertIsInstance(result, ui.Abort)
        self.assertEqual(calls["configure"], [])

    def test_rejected_env_credentials_abort(self):
        with mock.patch.dict(os.environ, {"VMREST_USER": "me", "VMREST_PASSWORD": "Wrong-pw1!"}):
            result, calls = self._run(401, own_pid=4242)
        self.assertIsInstance(result, ui.Abort)
        self.assertIn("VMREST_USER/VMREST_PASSWORD", result.msg)
        self.assertEqual((calls["kill"], calls["configure"]), ([], []))

    def test_env_credentials_that_work_are_remembered_unmanaged(self):
        with mock.patch.dict(os.environ, {"VMREST_USER": "me", "VMREST_PASSWORD": "Mine-pw1!"}):
            creds, _ = self._run(200)
        self.assertEqual(creds["user"], "me")
        self.assertEqual(localvm.load_creds()["managed"], False)

    def test_rest_status_distinguishes_401_from_no_answer(self):
        creds = {"user": "u", "password": "p"}
        err401 = urllib.error.HTTPError(localvm.VMREST_URL, 401, "Unauthorized", {}, None)
        with mock.patch.object(localvm, "_vmrest_open", side_effect=err401):
            self.assertEqual(localvm._rest_status(creds), 401)
        with mock.patch.object(localvm, "_vmrest_open", side_effect=TimeoutError("timed out")):
            self.assertIsNone(localvm._rest_status(creds))
        with mock.patch.object(localvm, "_vmrest_open", side_effect=urllib.error.URLError("refused")):
            self.assertIsNone(localvm._rest_status(creds))
        with mock.patch.object(localvm, "_vmrest_open", return_value=_Resp(b"{}")):
            self.assertEqual(localvm._rest_status(creds), 200)

    def test_start_records_the_pid(self):
        proc = mock.Mock(pid=31337)
        proc.poll.return_value = None
        with mock.patch.object(localvm.subprocess, "Popen", return_value=proc), mock.patch.object(localvm.paths, "HOME", self.d), \
                mock.patch.object(localvm, "_port_open", return_value=True):
            localvm._start_vmrest(self.host)
        self.assertEqual(json.loads((self.d / "vmrest.pid").read_text())["pid"], 31337)
        self.assertEqual(oct((self.d / "vmrest.pid").stat().st_mode & 0o777), "0o600")


@unittest.skipIf(os.name == "nt", "POSIX process handling")
class StopVmrestTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        p = mock.patch.object(localvm, "VMREST_PID", self.d / "vmrest.pid")
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(localvm, "_port_open", return_value=False)
        p.start()
        self.addCleanup(p.stop)

    def test_nothing_recorded_stops_nothing(self):
        with mock.patch.object(localvm.os, "kill") as kill, mock.patch.object(localvm.subprocess, "run") as run:
            self.assertFalse(localvm.stop_vmrest())
        kill.assert_not_called()
        self.assertFalse(any(c.args and c.args[0][:1] == ["pkill"] for c in run.call_args_list))

    def test_recycled_pid_is_not_killed(self):
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(lambda: (other.kill(), other.wait()))
        (self.d / "vmrest.pid").write_text(json.dumps({"pid": other.pid}))
        self.assertFalse(localvm.stop_vmrest())
        self.assertIsNone(other.poll())   # still running: it is not a vmrest
        self.assertFalse((self.d / "vmrest.pid").exists())

    def test_our_vmrest_is_stopped(self):
        fake = self.d / "vmrest"   # a process whose name is vmrest
        os.symlink(shutil.which("sleep"), fake)
        proc = subprocess.Popen([str(fake), "30"])
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        (self.d / "vmrest.pid").write_text(json.dumps({"pid": proc.pid}))
        self.assertTrue(localvm.stop_vmrest())
        self.assertIsNotNone(proc.wait(timeout=10))


@unittest.skipIf(os.name == "nt", "pty")
class ConfigureVmrestTests(unittest.TestCase):
    def _fake(self, body: str) -> dict:
        d = _tmp(self)
        exe = d / "vmrest"
        exe.write_text("#!" + sys.executable + "\n" + textwrap.dedent(body))
        exe.chmod(0o755)
        return {"vmrest": str(exe)}

    def test_answers_the_prompts(self):
        host = self._fake('''
            u = input("Username:"); p = input("New password:"); q = input("Retype new password:")
            print("Credential updated successfully" if p == q else "mismatch")
        ''')
        self.assertTrue(localvm.configure_vmrest(host, "cloudseed", "Aa1!aaaaaaaa"))

    def test_re_prompting_vmrest_does_not_hang(self):
        host = self._fake('''
            input("Username:")
            while True:
                input("New password:"); input("Retype new password:")
                print("Password does not meet complexity requirements:")
        ''')
        start = time.time()
        with mock.patch.object(localvm.ui, "warn"):
            self.assertFalse(localvm.configure_vmrest(host, "cloudseed", "Aa1!aaaaaaaa", timeout=3))
        self.assertLess(time.time() - start, 15)


# ---------------------------------------------------------------- images

class ImageCacheTests(unittest.TestCase):
    PAYLOAD = b"qcow2-image-bytes" * 1000

    def setUp(self):
        import hashlib
        self.d = _tmp(self)
        self.sha = hashlib.sha256(self.PAYLOAD).hexdigest()
        self.spec = {"file": "test.img", "base": "https://example.invalid/", "sums": "SHA256SUMS", "convert": True}
        images = {"t-os": {"label": "Test OS", "guest_os": {"arm64": "x"}, "arm64": self.spec}}
        for p in (mock.patch.object(localvm, "IMAGES_DIR", self.d), mock.patch.dict(localvm.IMAGES, images),
                  mock.patch.object(localvm.deps, "find", return_value="/fake/qemu-img"),
                  mock.patch.object(localvm.sys.stdout, "isatty", return_value=False)):
            p.start()
            self.addCleanup(p.stop)
        self.src, self.vmdk = self.d / "test.img", self.d / "t-os-arm64.vmdk"

    def _urlopen(self, payload=None, fail_sums=False, cut=None):
        def urlopen(req, timeout=0):
            url = req.full_url if hasattr(req, "full_url") else req
            if url.endswith("SHA256SUMS"):
                if fail_sums:
                    raise urllib.error.URLError("network is unreachable")
                return _Resp(f"{self.sha} *test.img\n".encode())
            data = self.PAYLOAD if payload is None else payload
            if cut is not None:
                return _Resp(data[:cut], length=len(data))
            return _Resp(data)
        return urlopen

    def _convert(self, rc=0):
        def run(cmd, **kw):
            Path(cmd[-1]).write_bytes(b"VMDK" if rc == 0 else b"PARTIAL")
            return subprocess.CompletedProcess(cmd, rc)
        return run

    def test_fresh_download_is_verified_converted_and_marked(self):
        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen()), \
                mock.patch.object(localvm.subprocess, "run", self._convert()) as _:
            self.assertEqual(localvm.ensure_image("t-os", "arm64"), self.vmdk)
        self.assertEqual(self.vmdk.read_bytes(), b"VMDK")
        self.assertTrue((self.d / "t-os-arm64.vmdk.ok").exists())
        self.assertEqual(sorted(p.name for p in self.d.iterdir() if p.name.endswith((".part", ".tmp"))), [])
        # the next run trusts the marked result without any network
        with mock.patch.object(localvm.urllib.request, "urlopen", side_effect=AssertionError("no network needed")):
            self.assertEqual(localvm.ensure_image("t-os", "arm64"), self.vmdk)

    def test_partials_of_killed_runs_are_cleaned_up(self):
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()   # its PID names files no process will ever finish
        live = os.getppid()
        stale = [self.d / f"test.img.{dead.pid}.part", self.d / "test.img.part", self.d / f"t-os-arm64.vmdk.{dead.pid}.tmp"]
        kept = self.d / f"test.img.{live}.part"   # another run's download in progress
        for f in stale + [kept]:
            f.write_bytes(b"x" * 10)
        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen()), \
                mock.patch.object(localvm.subprocess, "run", self._convert()):
            localvm.ensure_image("t-os", "arm64")
        self.assertEqual([f for f in stale if f.exists()], [])
        self.assertTrue(kept.exists())

    def test_corrupt_download_never_gets_its_final_name(self):
        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen(payload=b"tampered")), \
                mock.patch.object(localvm.subprocess, "run", self._convert()):
            with self.assertRaises(ui.Abort):
                localvm.ensure_image("t-os", "arm64")
        self.assertEqual(list(self.d.glob("test.img*")), [])

    def test_truncated_download_is_discarded(self):
        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen(cut=100)), \
                mock.patch.object(localvm.subprocess, "run", self._convert()):
            with self.assertRaises(ui.Abort):
                localvm.ensure_image("t-os", "arm64")
        self.assertEqual(list(self.d.glob("test.img*")), [])

    def test_unreachable_checksums_download_nothing(self):
        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen(fail_sums=True)):
            with self.assertRaises(ui.Abort):
                localvm.ensure_image("t-os", "arm64")
        self.assertEqual(list(self.d.iterdir()), [p for p in self.d.iterdir() if p.name == ".lock"])

    def test_interrupted_conversion_leaves_no_base_disk(self):
        self.src.write_bytes(self.PAYLOAD)

        def interrupted(cmd, **kw):
            Path(cmd[-1]).write_bytes(b"PARTIAL")
            raise KeyboardInterrupt

        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen()), \
                mock.patch.object(localvm.subprocess, "run", interrupted):
            with self.assertRaises(KeyboardInterrupt):
                localvm.ensure_image("t-os", "arm64")
        self.assertFalse(self.vmdk.exists())
        self.assertEqual(list(self.d.glob("*.tmp")), [])

    def test_failed_conversion_keeps_the_previous_disk(self):
        self.src.write_bytes(self.PAYLOAD)
        self.vmdk.write_bytes(b"OLD")   # unmarked: built by an older version, so it is rebuilt
        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen()), \
                mock.patch.object(localvm.subprocess, "run", self._convert(rc=1)):
            with self.assertRaises(ui.Abort):
                localvm.ensure_image("t-os", "arm64")
        self.assertEqual(self.vmdk.read_bytes(), b"OLD")
        self.assertFalse((self.d / "t-os-arm64.vmdk.ok").exists())

    def test_unmarked_disk_and_corrupt_cache_are_rebuilt(self):
        self.src.write_bytes(b"truncated")        # an unverified cached download (old version, or cut short)
        self.vmdk.write_bytes(b"HALF-CONVERTED")  # and a VMDK without the completion record
        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen()), \
                mock.patch.object(localvm.subprocess, "run", self._convert()):
            self.assertEqual(localvm.ensure_image("t-os", "arm64"), self.vmdk)
        self.assertEqual(self.src.read_bytes(), self.PAYLOAD)
        self.assertEqual(self.vmdk.read_bytes(), b"VMDK")

    def test_offline_with_an_old_cache_keeps_working(self):
        self.vmdk.write_bytes(b"OLD")
        with mock.patch.object(localvm.urllib.request, "urlopen", self._urlopen(fail_sums=True)), \
                mock.patch.object(localvm.ui, "warn") as warn:
            self.assertEqual(localvm.ensure_image("t-os", "arm64"), self.vmdk)
        self.assertIn("as is", warn.call_args[0][0])
        self.assertFalse((self.d / "t-os-arm64.vmdk.ok").exists())   # verified on the next online run


# ---------------------------------------------------------------- teardown helpers

class SweepTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.host = {"vmrun": "/fake/vmrun", "product": "fusion", "os": "darwin"}
        for name in ("user-win11", "cloudseed-a-bastion", "cloudseed-a-wk1", "cloudseed-a-2-bastion", "cloudseed-b-cp1", "renamed"):
            b = self.d / f"{name}.vmwarevm"
            b.mkdir()
            (b / f"{name}.vmx").write_text("x")
        (self.d / "thesis.docx").write_text("precious")
        self.calls = []
        self.running = {str(self.d / "user-win11.vmwarevm" / "user-win11.vmx"),
                        str(self.d / "cloudseed-a-bastion.vmwarevm" / "cloudseed-a-bastion.vmx")}

    def _run(self, cmd, **kw):
        self.calls.append(cmd)
        if "stop" in cmd:
            stopped = os.path.realpath(cmd[cmd.index("stop") + 1])
            self.running = {p for p in self.running if os.path.realpath(p) != stopped}
        out = f"Total running VMs: {len(self.running)}\n" + "\n".join(sorted(self.running)) + "\n"
        return subprocess.CompletedProcess(cmd, 0, out if "list" in cmd else "", "")

    def test_only_this_environments_vms_are_removed(self):
        known = [str(self.d / "renamed.vmwarevm" / "renamed.vmx")]
        with mock.patch.object(localvm.subprocess, "run", self._run):
            removed = localvm.sweep_vms(self.host, self.d, prefix="cloudseed-a", known_vmx=known, remove_dir=True)
        self.assertEqual(sorted(removed), ["cloudseed-a-bastion.vmwarevm", "cloudseed-a-wk1.vmwarevm", "renamed.vmwarevm"])
        left = sorted(p.name for p in self.d.iterdir())
        self.assertEqual(left, ["cloudseed-a-2-bastion.vmwarevm", "cloudseed-b-cp1.vmwarevm", "thesis.docx", "user-win11.vmwarevm"])
        stopped = [c for c in self.calls if "stop" in c]
        self.assertEqual(len(stopped), 1)
        self.assertIn("cloudseed-a-bastion.vmx", stopped[0][4])   # the user's running VM was never stopped

    def test_no_identity_removes_nothing(self):
        with mock.patch.object(localvm.subprocess, "run", self._run):
            self.assertEqual(localvm.sweep_vms(self.host, self.d), [])
        self.assertEqual(len(list(self.d.iterdir())), 7)

    def test_empty_own_dir_is_removed(self):
        own = self.d / "vms"
        (own / "cloudseed-a-vm1.vmwarevm").mkdir(parents=True)
        with mock.patch.object(localvm.subprocess, "run", self._run):
            localvm.sweep_vms(self.host, own, prefix="cloudseed-a", remove_dir=True)
        self.assertFalse(own.exists())

    def test_bundle_pattern_is_exact(self):
        self.assertTrue(localvm.env_vm_bundle("cloudseed-dev-wk12.vmwarevm", "cloudseed-dev"))
        self.assertFalse(localvm.env_vm_bundle("cloudseed-dev-2-bastion.vmwarevm", "cloudseed-dev"))
        self.assertFalse(localvm.env_vm_bundle("cloudseed-dev-bastion.vmwarevm", ""))


class RemoveVmnetTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        (self.d / "bin").mkdir()
        (self.d / "bin" / "vmnet-cli").write_text("")
        self.netfile = self.d / "networking"
        self.netfile.write_text("answer VNET_1_DHCP yes\nanswer VNET_2_DHCP no\nanswer VNET_2_HOSTONLY_SUBNET 10.9.0.0\n")
        self.host = {"vmrun": str(self.d / "bin" / "vmrun"), "os": "darwin"}
        for p in (mock.patch.dict(localvm.NETWORKING_FILE, {"darwin": self.netfile}),
                  mock.patch.object(localvm.paths, "HOME", self.d), mock.patch.object(localvm.ui, "interactive", return_value=False)):
            p.start()
            self.addCleanup(p.stop)

    def test_adopted_or_unknown_networks_are_kept(self):
        with mock.patch.object(localvm.subprocess, "run") as run:
            self.assertFalse(localvm.remove_vmnet(self.host, "vmnet2"))                      # unknown (older state)
            self.assertFalse(localvm.remove_vmnet(self.host, "vmnet2", adopted=True, env_id="vmware-a"))
            self.assertFalse(localvm.remove_vmnet(self.host, "vmnet1", adopted=False, env_id="vmware-a"))
        run.assert_not_called()

    def test_network_another_env_uses_is_kept(self):
        with mock.patch.object(localvm, "vmnet_users", return_value=["vmware-b"]), mock.patch.object(localvm.subprocess, "run") as run:
            self.assertFalse(localvm.remove_vmnet(self.host, "vmnet2", adopted=False, env_id="vmware-a"))
        run.assert_not_called()

    def test_unattended_removal_never_waits_for_a_password(self):
        with mock.patch.object(localvm, "vmnet_users", return_value=[]), \
                mock.patch.object(localvm.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertTrue(localvm.remove_vmnet(self.host, "vmnet2", adopted=False, env_id="vmware-a", auto_approve=True))
        self.assertTrue(all(c.args[0][:2] == ["sudo", "-n"] for c in run.call_args_list))

    def test_vmnet_users_reads_other_envs_outputs(self):
        a, b = paths.Env("vmware", "a", self.d / "a"), paths.Env("vmware", "b", self.d / "b")
        for e, net in ((a, "vmnet2"), (b, "vmnet2")):
            e.dir.mkdir(parents=True)
            (e.dir / "outputs.json").write_text(json.dumps({"private_vmnet": net}))
        with mock.patch.object(localvm.paths.Env, "list_all", staticmethod(lambda: [a, b])):
            self.assertEqual(localvm.vmnet_users("vmnet2", exclude="vmware-a"), ["vmware-b"])


# ---------------------------------------------------------------- the vmware adapter

def _cfg(tmp: Path, **vars_) -> dict:
    return {"cloud": "vmware", "env": "lab", "name": "cloudseed", "network_cidr": "192.168.160.0/24", "workdir": str(tmp),
            "ssh_public_key": "ssh-ed25519 AAAA x", "vars": dict(vars_), "extra_vars": {}, "tags": {}}


class AddressPlanTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.c = VMware()

    def test_workloads_may_not_reach_the_control_planes(self):
        self.assertTrue(self.c.address_problems(_cfg(self.d, workload_count=11, enable_kubernetes=True)))
        self.assertEqual(self.c.address_problems(_cfg(self.d, workload_count=10, enable_kubernetes=True)), [])
        self.assertEqual(self.c.address_problems(_cfg(self.d, workload_count=11)), [])   # no cluster: no overlap

    def test_node_limits(self):
        self.assertTrue(self.c.address_problems(_cfg(self.d, enable_kubernetes=True, kubernetes_control_planes=21)))
        self.assertTrue(self.c.address_problems(_cfg(self.d, enable_kubernetes=True, kubernetes_control_planes=0)))
        self.assertTrue(self.c.address_problems(_cfg(self.d, enable_kubernetes=True, kubernetes_workers=89)))   # .128 = DHCP
        # .100-.127 are MetalLB's LoadBalancer pool (platform._lb_range): workers stop at .99
        self.assertTrue(self.c.address_problems(_cfg(self.d, enable_kubernetes=True, kubernetes_workers=61)))
        self.assertEqual(self.c.address_problems(_cfg(self.d, enable_kubernetes=True, kubernetes_workers=60)), [])
        self.assertEqual(self.c.address_problems(_cfg(self.d, enable_kubernetes=False, kubernetes_control_planes=99)), [])

    def test_small_network(self):
        cfg = _cfg(self.d, enable_kubernetes=True)
        cfg["network_cidr"] = "10.0.0.0/26"   # hosts .1-.62
        problems = self.c.address_problems(cfg)
        self.assertEqual(problems, [])
        cfg["vars"]["kubernetes_workers"] = 24
        self.assertTrue(self.c.address_problems(cfg))
        cfg["network_cidr"] = "10.0.0.0/30"
        self.assertTrue(self.c.address_problems(cfg))

    def test_network_too_small_for_workers_or_kubernetes(self):
        cfg = _cfg(self.d, enable_kubernetes=True, kubernetes_workers=0)
        cfg["network_cidr"] = "10.0.0.0/27"   # hosts .1-.30: control planes fit, workers (.40+) cannot
        self.assertEqual(self.c.address_problems(cfg), [])
        cfg["vars"]["kubernetes_workers"] = 1
        self.assertIn("kubernetes_workers=1: at most 0", self.c.address_problems(cfg)[0])
        cfg["network_cidr"] = "10.0.0.0/28"   # hosts .1-.14: no room for a control plane at all
        problems = self.c.address_problems(cfg)
        self.assertEqual(len(problems), 1)
        self.assertIn("needs a larger network", problems[0])

    def test_network_problems_hook_includes_the_plan(self):
        self.assertTrue(self.c.network_problems(_cfg(self.d, workload_count=11, enable_kubernetes=True)))

    def test_login_names(self):
        for bad in ("root", "yes", "no", "on", "off", "true", "false", "null", "Bad: Name", "", "1abc",
                    "Yes", "NO", "True", "Null", "OFF"):   # PyYAML reads these spellings as booleans/null too
            self.assertIsNotNone(netutil.validate_login_username(bad), bad)
            q = next(q for q in VMware.questions if q.key == "ssh_username")
            if bad:
                self.assertIsNotNone(VMware().answer_problem(q, bad, {}), bad)
        for good in ("alice", "cloudseed", "_svc", "a-b_c", "John.Doe"):   # upper case and '.' are fine on Debian/Ubuntu
            self.assertIsNone(netutil.validate_login_username(good), good)
            self.assertIsNone(VMware().answer_problem(q, good, {}), good)
        self.assertIsNotNone(q.validate("yes"))


class VmDirTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.c = VMware()

    def test_tilde_and_relative_become_absolute(self):
        home_vms = os.path.normpath(os.path.expanduser("~/VMs"))
        self.assertEqual(self.c.vm_dir_value(_cfg(self.d, vm_dir="~/VMs")), home_vms)
        self.assertEqual(self.c.vm_dir_value(_cfg(self.d, vm_dir="vms-here")), str(self.d / "vms-here"))
        self.assertEqual(self.c.vm_dir_value(_cfg(self.d)), str(self.d / "vms"))
        self.assertEqual(self.c.stack_vars(_cfg(self.d, vm_dir="~/VMs"))["vm_dir"], home_vms)

    def test_existing_relative_vms_keep_their_path(self):
        (self.d / "stack").mkdir()
        state = {"version": 4, "serial": 1, "resources": [{"module": "module.stack.module.bastion", "mode": "managed",
                 "type": "vmdesktop_vm", "name": "bastion", "instances": [{"attributes": {"path": "~/VMs", "name": "b"}}]}]}
        (self.d / "stack" / "terraform.tfstate").write_text(json.dumps(state))
        cfg = _cfg(self.d, vm_dir="~/VMs")
        self.assertEqual(self.c.vm_dir_value(cfg), "~/VMs")   # changing it would rebuild the VMs
        self.assertEqual(self.c.vm_dir_path(cfg), self.d / "stack" / "~" / "VMs")

    def test_existing_absolute_vms_keep_their_spelling(self):
        # `path` forces a rebuild on any change of the string: a trailing '/' typed at setup must not be "normalized" away
        (self.d / "stack").mkdir()
        state = {"version": 4, "resources": [{"mode": "managed", "type": "vmdesktop_vm", "name": "bastion",
                                              "instances": [{"attributes": {"path": "/Volumes/ext/VMs/", "name": "b"}}]}]}
        (self.d / "stack" / "terraform.tfstate").write_text(json.dumps(state))
        self.assertEqual(self.c.vm_dir_value(_cfg(self.d, vm_dir="/Volumes/ext/VMs/")), "/Volumes/ext/VMs/")
        self.assertEqual(self.c.vm_dir_value(_cfg(self.d, vm_dir="/Volumes/other//VMs/")), "/Volumes/other/VMs")   # a new value


def _node(idx, name):
    return {"index_key": idx, "schema_version": 0, "attributes": {"name": name, "path": "/vms"}}


class NodeStateMigrationTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        (self.d / "stack").mkdir()
        self.state = self.d / "stack" / "terraform.tfstate"
        mod = "module.stack.module.kubernetes[0]"
        # two control planes: positions 0,1 are cp1,cp2 and the workers follow - any index mapping by count would be wrong
        self.data = {"version": 4, "serial": 7, "lineage": "l", "outputs": {}, "resources": [
            {"module": mod, "mode": "managed", "type": "vmdesktop_vm", "name": "node", "provider": "p",
             "instances": [_node(0, "cloudseed-lab-cp1"), _node(1, "cloudseed-lab-cp2"), _node(2, "cloudseed-lab-wk1")]},
            {"module": mod, "mode": "managed", "type": "random_integer", "name": "mac", "provider": "p",
             "instances": [{"index_key": i, "attributes": {"result": i}} for i in range(12)]},
            {"module": "module.stack.module.workloads", "mode": "managed", "type": "vmdesktop_vm", "name": "workload",
             "provider": "p", "instances": [_node(0, "cloudseed-lab-vm1")]}]}
        self.state.write_text(json.dumps(self.data))

    def test_rekeys_nodes_and_macs_by_name(self):
        self.assertTrue(VMware().migrate_state({"workdir": str(self.d)}))
        data = json.loads(self.state.read_text())
        node, mac, wl = data["resources"]
        self.assertEqual([i["index_key"] for i in node["instances"]], ["cp1", "cp2", "wk1"])
        self.assertEqual([i["attributes"]["name"] for i in node["instances"]], ["cloudseed-lab-cp1", "cloudseed-lab-cp2", "cloudseed-lab-wk1"])
        keys = {i["index_key"]: i["attributes"]["result"] for i in mac["instances"]}
        self.assertEqual(keys, {"cp1-0": 0, "cp1-1": 1, "cp1-2": 2, "cp2-0": 3, "cp2-1": 4, "cp2-2": 5,
                                "wk1-0": 6, "wk1-1": 7, "wk1-2": 8})   # same MAC numbers, the orphan 9-11 dropped
        self.assertEqual([i["index_key"] for i in wl["instances"]], [0])   # workloads untouched
        self.assertEqual(data["serial"], 8)
        self.assertEqual(json.loads((self.d / "stack" / "terraform.tfstate.backup").read_text()), self.data)
        self.assertFalse(VMware().migrate_state({"workdir": str(self.d)}))   # idempotent

    def test_leaves_state_alone_while_terraform_runs(self):
        (self.d / "stack" / ".terraform.tfstate.lock.info").write_text("{}")
        self.assertFalse(VMware().migrate_state({"workdir": str(self.d)}))
        self.assertEqual(json.loads(self.state.read_text()), self.data)

    def test_unexpected_names_are_not_guessed(self):
        self.data["resources"][0]["instances"][1]["attributes"]["name"] = "something-else"
        self.state.write_text(json.dumps(self.data))
        with mock.patch.object(ui, "warn"):
            self.assertFalse(VMware().migrate_state({"workdir": str(self.d)}))
        self.assertEqual(json.loads(self.state.read_text()), self.data)


class SharedNetworkTests(unittest.TestCase):
    def setUp(self):
        self.d = _tmp(self)
        self.other = paths.Env("vmware", "first", self.d / "first")
        (self.other.stack_dir).mkdir(parents=True)
        (self.other.dir / "config.json").write_text(json.dumps({"network_cidr": "192.168.160.0/24"}))
        p = mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [self.other]))
        p.start()
        self.addCleanup(p.stop)
        self.me = self.d / "me"
        (self.me / "stack").mkdir(parents=True)

    def _other_has_vms(self):
        state = {"resources": [{"mode": "managed", "type": "vmdesktop_vm", "name": "bastion", "instances": [{"attributes": {"name": "b"}}]}]}
        (self.other.stack_dir / "terraform.tfstate").write_text(json.dumps(state))

    def test_second_env_on_the_same_network_is_refused(self):
        self._other_has_vms()
        with self.assertRaises(ui.Abort) as e:
            VMware()._check_network(_cfg(self.me), {}, {"name": "vmnet1", "cidr": "192.168.160.0/24"})
        self.assertIn("vmware-first", e.exception.msg)
        self.assertIn("--cidr", e.exception.msg)

    def test_env_without_vms_does_not_block(self):
        VMware()._check_network(_cfg(self.me), {}, {"name": "vmnet1", "cidr": "192.168.160.0/24"})

    def test_existing_env_is_only_warned(self):
        self._other_has_vms()
        (self.me / "stack" / "terraform.tfstate").write_text((self.other.stack_dir / "terraform.tfstate").read_text())
        with mock.patch.object(ui, "warn") as warn:
            VMware()._check_network(_cfg(self.me), {}, {"name": "vmnet1", "cidr": "192.168.160.0/24"})
        self.assertIn("vmware-first", warn.call_args[0][0])

    def test_env_with_only_its_network_is_held_to_the_new_env_rules(self):
        # the first apply failed after the network, another environment took vmnet1 meanwhile: a retry must not create
        # VMs on the other one's fixed addresses (destroy never reaches this check: it runs prepare(dry_run=True))
        self._other_has_vms()
        state = {"resources": [{"mode": "managed", "type": "vmdesktop_network", "name": "private",
                                "instances": [{"attributes": {"name": "vmnet1"}}]}]}
        (self.me / "stack" / "terraform.tfstate").write_text(json.dumps(state))
        cfg = _cfg(self.me)
        self.assertTrue(VMware().is_new(cfg))
        with self.assertRaises(ui.Abort) as e:
            VMware()._check_network(cfg, {}, {"name": "vmnet1", "cidr": "192.168.160.0/24"})
        self.assertIn("vmware-first", e.exception.msg)
        self.assertIn("remove what a failed apply left", e.exception.msg)
        self.assertTrue(VMware().is_new(_cfg(self.d / "fresh")))

    def test_explicit_cidr_overlapping_the_nat_network_is_refused(self):
        cfg = _cfg(self.me)
        cfg.update(network_cidr="172.16.128.0/25", cidr_explicit=True)
        nets = [{"name": "vmnet8", "type": "nat", "subnet": "172.16.128.0", "mask": "255.255.255.0"}]
        with mock.patch.object(localvm, "list_vmnets", return_value=nets):
            with self.assertRaises(ui.Abort) as e:
                VMware()._check_network(cfg, {}, None)
        self.assertIn("vmnet8", e.exception.msg)
        cfg["network_cidr"] = "10.55.0.0/24"
        with mock.patch.object(localvm, "list_vmnets", return_value=nets):
            VMware()._check_network(cfg, {}, None)

    def test_existing_env_on_an_overlapping_cidr_stays_manageable(self):
        # built by an older version on the NAT range, with its VMs: warn, never block its apply
        state = {"resources": [{"mode": "managed", "type": "vmdesktop_network", "name": "private",
                                "instances": [{"attributes": {"name": "vmnet8"}}]},
                               {"mode": "managed", "type": "vmdesktop_vm", "name": "bastion",
                                "instances": [{"attributes": {"name": "b"}}]}]}
        (self.me / "stack" / "terraform.tfstate").write_text(json.dumps(state))
        cfg = _cfg(self.me)
        cfg.update(network_cidr="172.16.128.0/24", cidr_explicit=True)
        nets = [{"name": "vmnet8", "type": "nat", "subnet": "172.16.128.0", "mask": "255.255.255.0"}]
        with mock.patch.object(localvm, "list_vmnets", return_value=nets), mock.patch.object(ui, "warn") as warn:
            VMware()._check_network(cfg, {}, None)
        self.assertIn("vmnet8", warn.call_args[0][0])


class PrepareTests(unittest.TestCase):
    """prepare() end to end with every host interaction faked."""

    def setUp(self):
        self.d = _tmp(self)
        self.other = paths.Env("vmware", "first", self.d / "first")
        self.other.stack_dir.mkdir(parents=True)
        (self.other.dir / "config.json").write_text(json.dumps({"network_cidr": "192.168.160.0/24"}))
        vm = {"resources": [{"mode": "managed", "type": "vmdesktop_vm", "name": "bastion", "instances": [{"attributes": {"name": "b"}}]}]}
        (self.other.stack_dir / "terraform.tfstate").write_text(json.dumps(vm))
        host = {"product": "fusion", "version": "13", "os": "darwin", "arch": "arm64", "guest_arch": "arm64"}
        for p in (mock.patch.object(paths.Env, "list_all", staticmethod(lambda: [self.other])),
                  mock.patch.object(localvm, "ensure_provider"), mock.patch.object(localvm, "require_host", return_value=host),
                  mock.patch.object(localvm, "ensure_vmrest", return_value={"user": "u", "password": "p"}),
                  mock.patch.object(localvm, "hostonly_vmnet", return_value={"name": "vmnet1", "cidr": "192.168.160.0/24"}),
                  mock.patch.object(localvm, "ensure_image", return_value=self.d / "base.vmdk"),
                  mock.patch.dict(os.environ, {}), mock.patch.object(ui, "info"), mock.patch.object(ui, "warn")):
            p.start()
            self.addCleanup(p.stop)

    def _cfg(self, name, state=None, **vars_):
        work = self.d / name
        (work / "stack").mkdir(parents=True)
        if state is not None:
            (work / "stack" / "terraform.tfstate").write_text(json.dumps(state))
        cfg = _cfg(work, **vars_)
        cfg.update(env=name, network_cidr="10.100.0.0/24")
        return cfg

    def test_new_env_on_the_shared_network_is_refused(self):
        with self.assertRaises(ui.Abort) as e:
            VMware().prepare(self._cfg("second"))
        self.assertIn("vmware-first", e.exception.msg)
        localvm.ensure_image.assert_not_called()

    def test_new_env_with_an_impossible_layout_is_refused_before_touching_vmware(self):
        self.other.stack_dir.joinpath("terraform.tfstate").unlink()   # no neighbour
        with self.assertRaises(ui.Abort) as e:
            VMware().prepare(self._cfg("big", workload_count=11, enable_kubernetes=True))
        self.assertIn("workload_count=11", e.exception.msg)
        localvm.require_host.assert_not_called()

    def test_partly_built_env_is_refused_like_a_new_one(self):
        # the first apply created the network, then failed: a retry is checked like a new environment
        state = {"resources": [{"mode": "managed", "type": "vmdesktop_network", "name": "private",
                                "instances": [{"attributes": {"name": "vmnet1"}}]}]}
        cfg = self._cfg("half", state=state, workload_count=11, enable_kubernetes=True)
        with self.assertRaises(ui.Abort) as e:
            VMware().prepare(cfg)
        self.assertIn("workload_count=11", e.exception.msg)
        localvm.ensure_image.assert_not_called()

    def test_partly_built_env_stays_destroyable(self):
        # destroy loads the environment with prepare(dry_run=True): no layout or network check can block it
        state = {"resources": [{"mode": "managed", "type": "vmdesktop_network", "name": "private",
                                "instances": [{"attributes": {"name": "vmnet1"}}]}]}
        cfg = self._cfg("half", state=state, workload_count=11, enable_kubernetes=True)
        VMware().prepare(cfg, dry_run=True)
        localvm.require_host.assert_not_called()


class TerraformModuleTests(unittest.TestCase):
    """Static checks of the vmware stack (terraform validate/plan are exercised by the e2e battery)."""

    def test_kubernetes_nodes_are_keyed_by_name(self):
        text = (ROOT / "terraform" / "vmware" / "modules" / "kubernetes" / "main.tf").read_text()
        self.assertIn("for_each = local.nodes", text)
        self.assertNotIn("count.index", text)

    def test_adopted_flag_is_an_output(self):
        self.assertIn("private_vmnet_adopted", VMware.outputs)
        self.assertIn('output "private_vmnet_adopted"', (ROOT / "terraform" / "vmware" / "outputs.tf").read_text())


if __name__ == "__main__":
    unittest.main()
