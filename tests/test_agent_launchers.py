"""External agents use the running installation even when the user's PATH cannot find it."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import agents, paths


class AgentLauncherTests(unittest.TestCase):
    def test_source_aliases_use_exact_python_and_preserve_arguments_without_path(self):
        with tempfile.TemporaryDirectory(prefix="source with space '") as td:
            root = Path(td)
            (root / "bin").mkdir()
            (root / "bin/cloudseed").write_text("import json,sys; print(json.dumps(sys.argv[1:]))\n")
            env = {"PATH": "/does-not-exist", "HOME": td}
            with mock.patch.object(paths, "IS_BUNDLE", False), mock.patch.object(paths, "REPO_ROOT", root), \
                    mock.patch.object(paths, "HOME", root / "state"):
                with agents.command_launchers(env) as (child, launcher):
                    for name in ("cloudseed", "cs", str(launcher)):
                        args = ["one two", "$(touch forbidden)", "'quoted'", "--env", "demo"]
                        result = subprocess.run([name, *args], env=child, text=True, capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(json.loads(result.stdout), args)
                    self.assertEqual(child["CLOUDSEED_HOME"], str((root / "state").resolve()))
                    self.assertEqual(launcher.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(launcher.parent.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(env["PATH"], "/does-not-exist")
                self.assertFalse(launcher.parent.exists())

    def test_renamed_frozen_binary_wins_over_another_installed_version(self):
        with tempfile.TemporaryDirectory(prefix="renamed bundle '") as td:
            root = Path(td)
            binary = root / "cloudseed-darwin-arm64"
            binary.write_text("#!/bin/sh\nprintf 'exact-release\\n'\n")
            binary.chmod(0o700)
            stale = root / "cloudseed"
            stale.write_text("#!/bin/sh\nprintf 'stale-release\\n'\n")
            stale.chmod(0o700)
            with mock.patch.object(paths, "IS_BUNDLE", True), mock.patch.object(agents.sys, "executable", str(binary)):
                with agents.command_launchers({"PATH": str(root)}) as (env, launcher):
                    for command in ("cs", "cloudseed"):
                        out = subprocess.run([command, "--version"], env=env, capture_output=True, text=True, timeout=10)
                        self.assertEqual(out.stdout.strip(), "exact-release")
                    # Absolute fallback also works when a nested shell discards PATH.
                    out = subprocess.run([str(launcher), "--version"], env={"PATH": "/missing"}, capture_output=True, text=True)
                    self.assertEqual(out.stdout.strip(), "exact-release")

    def test_cleanup_on_agent_failure(self):
        with self.assertRaisesRegex(RuntimeError, "agent failed"):
            with agents.command_launchers({"PATH": ""}) as (_, launcher):
                raise RuntimeError("agent failed")
        self.assertFalse(launcher.parent.exists())

    def test_runtime_contract_is_injected_with_context_brief_disabled(self):
        seen = {}

        class Process:
            def __init__(self, cmd, **kwargs):
                seen.update(cmd=cmd, env=kwargs["env"])
                seen["launcher"] = Path(kwargs["env"]["PATH"].split(os.pathsep)[0]) / "cloudseed"
                self.assert_exists = seen["launcher"].is_file()
                seen["exists"] = self.assert_exists
            def wait(self):
                return 0

        spec = agents.get("claude")
        with mock.patch.object(agents, "installed", return_value="/agent/claude"), \
                mock.patch.object(agents, "readiness", return_value=(True, "ready")), \
                mock.patch.object(agents, "_agent_keys", return_value=((), None)), \
                mock.patch.object(agents.secrets, "open_session", return_value=("test", {"PATH": "/missing"})), \
                mock.patch.object(agents.secrets, "close_session") as close, \
                mock.patch.object(agents.subprocess, "Popen", Process), \
                mock.patch.object(agents, "_wait_usage", return_value=0), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agents.run(spec, "Inspect saved report", None, False), 0)
        self.assertTrue(seen["exists"])
        self.assertFalse(seen["launcher"].parent.exists())
        prompt = seen["cmd"][seen["cmd"].index("-p") + 1]
        self.assertIn("cloudseed evidence read", prompt)
        self.assertIn("until complete=true", prompt)
        self.assertIn(str(seen["launcher"]), prompt)
        allowed = seen["cmd"][seen["cmd"].index("--allowedTools") + 1]
        self.assertIn("Bash(" + str(seen["launcher"]) + ":*)", allowed)
        self.assertNotIn("Bash(*)", allowed)
        self.assertIn("Read(**/*.tfstate*)", seen["cmd"][seen["cmd"].index("--disallowedTools") + 1])
        close.assert_called_once_with("test")


if __name__ == "__main__":
    unittest.main()
