"""Teardown failures retain VM files and environment configuration for a retry.

All commands are mocked and every bundle is in a temporary directory.
"""
from __future__ import annotations

import contextlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, localvm, paths, ui  # noqa: E402


class CleanupSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = paths.Env("vmware", "lab", workdir=Path(self.temp.name))
        self.cfg = {"name": "cloudseed", "env": "lab", "vars": {}}
        self.env.save(self.cfg)
        self.bundle = self.env.vms_dir / "cloudseed-lab-bastion.vmwarevm"
        self.bundle.mkdir(parents=True)
        self.vmx = self.bundle / "cloudseed-lab-bastion.vmx"
        self.vmx.write_text("VM configuration")
        self.disk = self.bundle / "disk.vmdk"
        self.disk.write_bytes(b"disk data")
        self.host = {"found": True, "vmrun": "/fake/vmrun", "product": "fusion"}
        self.running = {str(self.vmx)}
        self.fail = ""
        self.calls = []
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(mock.patch.object(localvm, "detect_host", return_value=self.host))
        self.patches.enter_context(mock.patch.object(localvm.subprocess, "run", side_effect=self.run_vmrun))

    def run_vmrun(self, cmd, **kwargs):
        operation = cmd[3]
        self.calls.append(operation)
        if operation == self.fail:
            return subprocess.CompletedProcess(cmd, 1, "", f"{operation} failed")
        if operation == "list":
            out = f"Total running VMs: {len(self.running)}\n" + "\n".join(sorted(self.running))
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if operation == "stop" and self.fail != "ineffective stop":
            self.running.discard(cmd[4])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def sweep(self):
        return localvm.sweep_vms(self.host, self.env.vms_dir, prefix="cloudseed-lab", remove_dir=True)

    def test_status_stop_delete_and_ineffective_stop_failures_preserve_files(self):
        for failure in ("list", "stop", "deleteVM", "ineffective stop"):
            with self.subTest(failure=failure):
                self.fail = failure
                self.running = {str(self.vmx)}
                self.calls.clear()
                with self.assertRaises(ui.Abort):
                    self.sweep()
                self.assertEqual(self.disk.read_bytes(), b"disk data")
                self.assertTrue(self.vmx.exists())
                if failure != "deleteVM":
                    self.assertNotIn("deleteVM", self.calls)
        self.fail = ""
        self.assertEqual(self.sweep(), [self.bundle.name])
        self.assertFalse(self.bundle.exists())

    def test_filesystem_failure_aborts_cli_before_false_success_and_preserves_config(self):
        with mock.patch.object(localvm.shutil, "rmtree", side_effect=PermissionError("disk is locked")), \
                mock.patch.object(ui, "ok") as success, mock.patch.object(localvm, "remove_vmnet") as remove_network:
            with self.assertRaisesRegex(ui.Abort, "retry destroy"):
                cli._destroy_local_leftovers(self.env, self.cfg, purge=True, vmnet="vmnet4", adopted=False)
        success.assert_not_called()
        remove_network.assert_not_called()
        self.assertEqual(self.env.load(), self.cfg)
        self.assertTrue(self.disk.exists())
        self.assertEqual(self.sweep(), [self.bundle.name])

    def test_known_bundle_without_vmx_can_finish_partial_cleanup(self):
        renamed = self.bundle.with_name("renamed.vmwarevm")
        self.bundle.rename(renamed)
        known = renamed / self.vmx.name
        known.unlink()
        self.running.clear()
        removed = localvm.sweep_vms(self.host, self.env.vms_dir, known_vmx=[str(known)])
        self.assertEqual(removed, [renamed.name])
        self.assertFalse(renamed.exists())

    def test_running_vm_with_missing_vmx_is_stopped_before_removal(self):
        self.vmx.unlink()
        self.assertEqual(self.sweep(), [self.bundle.name])
        self.assertIn("stop", self.calls)
        self.assertFalse(self.running)

    def test_missing_bundle_is_already_clean(self):
        import shutil
        shutil.rmtree(self.env.vms_dir)
        self.assertEqual(self.sweep(), [])
        self.assertEqual(self.calls, [])

    def test_uncertain_list_never_becomes_an_empty_list_in_destructive_mode(self):
        failures = [OSError("no vmrun"), subprocess.TimeoutExpired(["vmrun", "list"], 60),
                    subprocess.CompletedProcess([], 1, "Error: unavailable", ""),
                    subprocess.CompletedProcess([], 0, "unexpected output", ""),
                    subprocess.CompletedProcess([], 0, "Total running VMs: 1\n", "")]
        for failure in failures:
            with self.subTest(failure=repr(failure)):
                kw = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                with mock.patch.object(localvm.subprocess, "run", **kw):
                    with self.assertRaises(ui.Abort):
                        self.sweep()
                self.assertTrue(self.disk.exists())

    def test_vmrun_timeout_retains_bundle_and_names_retry(self):
        with mock.patch.object(localvm, "vmrun_list", return_value=[str(self.vmx)]), \
                mock.patch.object(localvm.subprocess, "run", side_effect=subprocess.TimeoutExpired(["vmrun"], 300)):
            with self.assertRaisesRegex(ui.Abort, "retry destroy"):
                self.sweep()
        self.assertTrue(self.disk.exists())


if __name__ == "__main__":
    unittest.main()
