"""Usage parity across the real CLI, MCP tools and authenticated console routes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-usage-interface-import-"))
from cloudseed import cli, mcp, paths, ui, usage, webui

ROOT = Path(__file__).resolve().parent.parent


class UsageInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cs-usage-interfaces-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        patch = mock.patch.object(paths, "HOME", self.home / "state")
        patch.start()
        self.addCleanup(patch.stop)
        self.run = usage.start_run("builtin", model="requested-model", mode="builtin")
        self.run.observe_anthropic({"id": "msg-fixture", "model": "observed-model", "usage": {
            "input_tokens": 80, "output_tokens": 20, "cache_read_input_tokens": 15, "cache_creation_input_tokens": 5}})
        self.run.finish(0)
        usage.record_mcp("cloudseed_list", 12.5, True, 123)
        self.env = {"HOME": str(self.home), "CLOUDSEED_HOME": str(paths.HOME), "NO_COLOR": "1",
                    "PATH": os.environ.get("PATH", ""), "CLOUDSEED_MCP_FORCE": "1"}

    def command(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "bin/cloudseed"), *args], env=self.env,
                              cwd=self.home, capture_output=True, text=True, timeout=30)

    def test_cli_reports_real_ledger_and_filters_without_cloud_preparation(self):
        proc = self.command("usage", "--json")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["summary"]["usage"]["input_tokens"], 100)
        self.assertEqual(report["summary"]["usage"]["total_tokens"], 120)
        self.assertEqual(report["mcp"]["call_count"], 1)
        self.assertIsNone(report["mcp"]["model_tokens"])
        filtered = json.loads(self.command("usage", "--run-id", self.run.id, "--json").stdout)
        self.assertEqual(len(filtered["runs"]), 1)
        self.assertEqual(filtered["mcp"]["call_count"], 0)
        self.assertEqual(list((paths.HOME / "envs").iterdir()), [])

    def test_usage_engine_does_not_break_container_engine_parser(self):
        parser = cli.build_parser()
        self.assertEqual(parser.parse_args(["usage", "--engine", "ccusage"]).usage_engine, "ccusage")
        self.assertEqual(parser.parse_args(["doctor", "--engine", "podman"]).engine, "podman")
        self.assertTrue(cli._changes_nothing(parser.parse_args(["usage"])))
        self.assertFalse(cli._changes_nothing(parser.parse_args(["usage", "install"])))

    def test_cli_text_uses_observed_model_and_specific_limits(self):
        proc = self.command("usage")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("observed-model", proc.stdout)
        self.assertIn("host model", proc.stdout)

    def test_invalid_filters_and_uninstalled_engine_fail_cleanly(self):
        for args in (("--run-id", "../../secrets"), ("--offset", "-1"), ("--limit", "1001"), ("--engine", "ccusage")):
            with self.subTest(args=args):
                proc = self.command("usage", *args, "--json")
                self.assertEqual(proc.returncode, 2)
                self.assertNotIn("Traceback", proc.stderr)

    def test_agent_cannot_install_and_gets_correct_human_command(self):
        args = cli.build_parser().parse_args(["usage", "install"])
        with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "claude"}), mock.patch.object(usage, "install_ccusage") as install:
            with self.assertRaises(ui.Abort) as raised:
                cli.cmd_usage(args, {})
        install.assert_not_called()
        self.assertIn("cs usage install", str(raised.exception))

    def test_mcp_real_child_returns_complete_structured_report(self):
        result = mcp.call_tool("cloudseed_usage", {"run_id": self.run.id}, self.env)
        self.assertFalse(result["isError"], result)
        self.assertEqual(result["structuredContent"]["runs"][0]["id"], self.run.id)
        self.assertEqual(result["structuredContent"]["summary"]["usage"]["total_tokens"], 120)
        # Reading usage itself must not recursively create more activity records.
        self.assertEqual(usage.report()["mcp"]["call_count"], 1)

    def test_mcp_install_requires_confirmation_and_report_is_readonly(self):
        tools = {item["name"]: item for item in mcp.tool_list()}
        self.assertTrue(tools["cloudseed_usage"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["cloudseed_usage_install"]["annotations"]["readOnlyHint"])
        with mock.patch.object(mcp, "_run") as runner:
            result = mcp.call_tool("cloudseed_usage_install", {}, self.env)
        runner.assert_not_called()
        self.assertTrue(result["isError"])
        self.assertIn("confirm", json.dumps(result))

    def test_tool_recording_failure_cannot_change_the_tool_result(self):
        result = {"content": [{"type": "text", "text": "a private tool answer"}], "isError": False}
        with mock.patch.object(mcp, "_call_tool", return_value=result), mock.patch.object(usage, "record_mcp", side_effect=OSError("unwritable")), mock.patch.object(mcp, "_log"):
            self.assertIs(mcp.call_tool("cloudseed_list", {"private": "not retained"}, {}), result)
        with mock.patch.object(mcp, "_call_tool", return_value=result), mock.patch.object(usage, "record_mcp") as record:
            mcp.call_tool("cloudseed_list", {"private": "not retained"}, {})
        self.assertEqual(record.call_args.args[0], "cloudseed_list")
        self.assertEqual(record.call_args.args[2], True)
        self.assertIsInstance(record.call_args.args[3], int)
        self.assertNotIn("private", str(record.call_args))

    def get(self, path, authorized=True):
        handler = webui._Handler.__new__(webui._Handler)
        handler.path = path
        with mock.patch.object(handler, "_authed", return_value=authorized), mock.patch.object(handler, "_json") as respond:
            handler._get()
        return respond.call_args.args if respond.called else None

    def test_console_route_requires_auth_and_returns_same_filtered_counts(self):
        self.assertIsNone(self.get("/api/usage", False))
        code, report = self.get("/api/usage?run_id=" + self.run.id)
        self.assertEqual(code, 200)
        self.assertEqual(report["summary"]["usage"]["total_tokens"], 120)
        for query in ("engine=bogus", "offset=-2", "limit=no", "run_id=invalid"):
            self.assertEqual(self.get("/api/usage?" + query)[0], 400)

    def test_console_report_and_install_preserve_confirmation_boundary(self):
        self.assertIn("--json", webui.build_argv("cloudseed_usage", {}))
        self.assertIn("usage", webui.raw_argv({"argv": ["usage", "--engine", "ccusage"]}))
        with self.assertRaises(webui.NeedsConfirm):
            webui.build_argv("cloudseed_usage_install", {})
        with self.assertRaises(webui.NeedsConfirm):
            webui.raw_argv({"argv": ["usage", "install"]})
        self.assertEqual(webui.build_argv("cloudseed_usage_install", {"confirm": True})[-3:], ["usage", "install", "--json"])


if __name__ == "__main__":
    unittest.main()
