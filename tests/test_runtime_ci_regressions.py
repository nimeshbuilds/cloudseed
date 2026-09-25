"""Process discovery and credential diagnostics that differ between developer machines and CI runners."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cloudseed import deps, mcp, scan, ui


class ProcessDiscoveryTests(unittest.TestCase):
    def test_mcp_loopback_bind_does_not_need_reverse_dns(self):
        with mock.patch("socket.getfqdn", side_effect=AssertionError("loopback binding must not query DNS")):
            server = mcp._HTTPServer(("127.0.0.1", 0), mcp._Handler)
        try:
            self.assertEqual(server.server_name, "127.0.0.1")
            self.assertGreater(server.server_port, 0)
        finally:
            server.server_close()

    @unittest.skipIf(os.name == "nt", "ps-based process discovery is POSIX only")
    def test_long_command_is_visible_with_narrow_columns(self):
        marker = "cloudseed-command-line-end"
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "x" * 2048, marker])
        try:
            with mock.patch.dict(os.environ, {"COLUMNS": "80"}):
                self.assertIn(marker, mcp._cmdline(child.pid) or "")
        finally:
            child.kill()
            child.wait()


class GcpCredentialDiagnosticsTests(unittest.TestCase):
    def check_key(self, contents):
        temporary = tempfile.TemporaryDirectory(prefix="cloudseed-key-diagnostic-")
        self.addCleanup(temporary.cleanup)
        key = Path(temporary.name) / "key.json"
        key.write_text(contents)
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("GOOGLE_", "GCLOUD_"))}
        clean["GOOGLE_APPLICATION_CREDENTIALS"] = str(key)
        return clean

    def test_cut_short_key_is_diagnosed_before_gcloud_login(self):
        with mock.patch.dict(os.environ, self.check_key("{"), clear=True), \
                mock.patch.object(deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(deps.subprocess, "run") as run:
            ok, message = deps.live_credential_check("gcp")
        self.assertFalse(ok)
        self.assertIn("GOOGLE_APPLICATION_CREDENTIALS", message)
        self.assertIn("cut short", message)
        self.assertIn("export GOOGLE_APPLICATION_CREDENTIALS", message)
        run.assert_not_called()

    def test_well_formed_key_still_gets_live_validation(self):
        key = json.dumps({"type": "authorized_user", "client_id": "client", "client_secret": "secret", "refresh_token": "token"})
        with mock.patch.dict(os.environ, self.check_key(key), clear=True), \
                mock.patch.object(deps, "find", return_value="/fake/gcloud"), \
                mock.patch.object(deps.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "token", "")) as run:
            self.assertEqual(deps.live_credential_check("gcp"), (True, "Google application-default credentials valid"))
        self.assertIn("print-access-token", run.call_args.args[0])


class AzureScanPreflightTests(unittest.TestCase):
    def test_installed_cli_without_login_is_refused_before_prowler_install(self):
        for response in (subprocess.CompletedProcess([], 1, "", "az login required"),
                         subprocess.CompletedProcess([], 0, "{}", ""),
                         subprocess.CompletedProcess([], 0, "not json", "")):
            with self.subTest(response=response), mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(deps, "find", return_value="/fake/az"), \
                    mock.patch.object(scan.subprocess, "run", return_value=response), \
                    mock.patch.object(scan, "_prowler") as install:
                with self.assertRaises(ui.Abort) as error:
                    scan.cloud_scan(SimpleNamespace(key="azure", local=False), None, {"vars": {}})
                self.assertEqual(error.exception.code, 2)
                self.assertIn("prowler needs Azure credentials", error.exception.msg)
                install.assert_not_called()

    def test_logged_in_cli_keeps_azure_cli_auth(self):
        with mock.patch.object(deps, "find", return_value="/fake/az"), \
                mock.patch.object(scan.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, '{"id":"sub"}', "")):
            self.assertEqual(scan._azure_auth({}), ["--az-cli-auth"])


if __name__ == "__main__":
    unittest.main()
