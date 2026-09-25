"""Actual scanner entrypoints in isolated homes, also run against containers and frozen executables."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BINARY = os.environ.get("CLOUDSEED_TEST_BINARY")
COMMAND = [BINARY] if BINARY else [sys.executable, str(ROOT / "bin" / "cloudseed")]


class ArchitectureCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cs-architecture-cli-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        empty_bin = self.home / "empty-bin"
        empty_bin.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("CLOUDSEED_", "XDG_"))}
        self.env.update(HOME=str(self.home), CLOUDSEED_HOME=str(self.home / "cs"),
                        XDG_CONFIG_HOME=str(self.home / "config"), XDG_DATA_HOME=str(self.home / "data"),
                        NO_COLOR="1", CLOUDSEED_NONINTERACTIVE="1", PATH=str(empty_bin))

    def fixture(self, cloud="aws", name="review", **overrides):
        directory = Path(self.env["CLOUDSEED_HOME"]) / "envs" / f"{cloud}-{name}"
        directory.mkdir(parents=True, exist_ok=True)
        cfg = {"cloud": cloud, "env": name, "allowed_ssh_cidrs": ["203.0.113.4/32"],
               "vars": {"enable_kubernetes": False}, "extra_vars": {}, **overrides}
        text = json.dumps(cfg)
        (directory / "config.json").write_text(text)
        return directory, text

    def run_cli(self, *args, input=None):
        return subprocess.run(COMMAND + list(args), env=self.env, input=input, capture_output=True,
                              text=True, timeout=60, cwd=str(ROOT))

    def test_each_target_scans_without_any_external_tools_or_config_changes(self):
        for cloud in ("aws", "gcp", "azure", "vmware"):
            with self.subTest(cloud=cloud):
                directory, original = self.fixture(cloud)
                result = self.run_cli("scan", "architecture", cloud, "--env", "review", "--profile", "lab", "--json")
                self.assertIn(result.returncode, (1, 3), result.stdout + result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(result.returncode, {"FAIL": 1, "INCOMPLETE": 3}[report["verdict"]])
                self.assertTrue(report["findings"])
                self.assertEqual((directory / "config.json").read_text(), original)
                files = list((directory / "scans").glob("architecture-*.json"))
                self.assertEqual(len(files), 1)
                self.assertTrue(files[0].with_suffix(".md").exists())
                self.assertEqual(json.loads(files[0].read_text())["verdict"], report["verdict"])
                self.assertFalse((directory / "stack").exists())
                self.assertNotIn("Unexpected error", result.stderr)

    def test_current_environment_json_and_report_discovery(self):
        directory, original = self.fixture("gcp")
        (Path(self.env["CLOUDSEED_HOME"]) / "settings.json").write_text(json.dumps({"current_env": "gcp-review"}))
        result = self.run_cli("scan", "architecture", "--profile", "lab", "--max-age-days", "7", "--json")
        self.assertIn(result.returncode, (1, 3), result.stderr)
        self.assertTrue(json.loads(result.stdout)["findings"])
        listed = self.run_cli("scan", "reports", "gcp", "--env", "review")
        self.assertEqual(listed.returncode, 0, listed.stdout + listed.stderr)
        self.assertIn("architecture-", listed.stdout)
        self.assertEqual(len(list((directory / "scans").glob("architecture-*.md"))), 1)
        self.assertEqual((directory / "config.json").read_text(), original)

    def test_bad_options_stop_before_creating_an_assessment(self):
        directory, _ = self.fixture()
        for options in (("--profile", "cis"), ("--max-age-days", "0"), ("--max-age-days", "3651"),
                        ("--max-age-days", "1.5"), ("--host", "bastion"), ("--framework", "anything")):
            with self.subTest(options=options):
                result = self.run_cli("scan", "architecture", "aws", "--env", "review", *options)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse((directory / "scans").exists())

    def test_agent_sessions_can_run_it_and_sensitive_config_is_not_copied(self):
        secret = "architecture-fixture-password-8675309"
        directory, original = self.fixture(extra_vars={"unused_password": secret})
        self.env["CLOUDSEED_AGENT"] = "builtin"
        result = self.run_cli("scan", "architecture", "aws", "--env", "review", "--profile", "lab", "--json")
        self.assertIn(result.returncode, (1, 3), result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["findings"])
        self.assertNotIn(secret, result.stdout + result.stderr)
        for report in (directory / "scans").glob("architecture-*.*"):
            self.assertNotIn(secret, report.read_text())
        self.assertEqual((directory / "config.json").read_text(), original)

    def test_real_mcp_stdio_call_returns_structured_assessment_without_confirmation(self):
        self.fixture()
        self.env["CLOUDSEED_MCP_FORCE"] = "1"
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "architecture-test", "version": "1"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "cloudseed_scan", "arguments": {
                "kind": "architecture", "cloud": "aws", "env": "review", "profile": "lab", "json": True}}},
        ]
        result = self.run_cli("mcp", "serve", input="".join(json.dumps(m) + "\n" for m in messages))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        responses = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        response = next(r for r in responses if r.get("id") == 2)
        self.assertNotIn("error", response)
        report = response["result"]["structuredContent"]
        self.assertIn(report["verdict"], ("INCOMPLETE", "FAIL"))
        self.assertTrue(report["findings"])

    def test_architecture_skill_is_available_in_the_runtime(self):
        result = self.run_cli("skill", "show", "architecture")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scan architecture", result.stdout)
        self.assertIn("INCOMPLETE", result.stdout)


if __name__ == "__main__":
    unittest.main()
