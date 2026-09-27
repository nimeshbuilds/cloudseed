"""Exercise usage in source, released binaries and containers without a model API."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class UsageE2ETests(unittest.TestCase):
    def test_native_agent_run_is_scoped_and_available_to_cli(self):
        with tempfile.TemporaryDirectory(prefix="cloudseed-usage-e2e-") as td:
            home = Path(td)
            bindir = home / "bin"
            bindir.mkdir()
            stub = bindir / "claude"
            stub.write_text("#!" + sys.executable + "\n" + '''import json,sys
if '--version' in sys.argv:
    print('2.1.283 (fixture)'); sys.exit(0)
assert '--output-format' in sys.argv and 'stream-json' in sys.argv
sid=sys.argv[sys.argv.index('--session-id')+1]
print(json.dumps({'type':'system','subtype':'init','session_id':sid}))
print(json.dumps({'type':'assistant','session_id':sid,'message':{'id':'msg-test','model':'claude-sonnet-4-5-20250929','content':[{'type':'text','text':'USAGE_E2E_OK: simulated agent answer'}],'usage':{'input_tokens':80,'cache_read_input_tokens':15,'cache_creation_input_tokens':5,'output_tokens':20}}}))
print(json.dumps({'type':'result','session_id':sid,'is_error':False,'usage':{'input_tokens':80,'cache_read_input_tokens':15,'cache_creation_input_tokens':5,'output_tokens':20},'result':'USAGE_E2E_OK'}))
''')
            stub.chmod(0o700)
            state = home / "state"
            # A recognizable global transcript must never enter Cloudseed's report.
            outside = home / ".claude/projects/unrelated"
            outside.mkdir(parents=True)
            (outside / "other.jsonl").write_text('{"secret":"UNRELATED_HISTORY_MUST_NOT_APPEAR","usage":{"input_tokens":999999}}')
            env = {"HOME": str(home), "CLOUDSEED_HOME": str(state), "NO_COLOR": "1", "PATH": str(bindir) + os.pathsep + os.defpath,
                   "ANTHROPIC_API_KEY": "synthetic-offline-auth-marker"}
            binary = os.environ.get("CLOUDSEED_TEST_BINARY")
            command = [str(Path(binary).resolve())] if binary else [sys.executable, str(ROOT / "bin/cloudseed")]
            task = subprocess.run([*command, "agentic", "--agent", "claude", "--force", "--no-headliner", "task-text-not-for-ledger"],
                                  env=env, cwd=home, text=True, capture_output=True, timeout=90)
            self.assertEqual(task.returncode, 0, task.stdout + task.stderr)
            self.assertIn("USAGE_E2E_OK", task.stdout)
            proc = subprocess.run([*command, "usage", "--json"], env=env, cwd=home, text=True, capture_output=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["summary"]["run_count"], 1)
            run = report["runs"][0]
            self.assertEqual(run["status"], "complete")
            self.assertEqual(run["id"], run["native_session_id"])
            self.assertEqual(run["usage"]["input_tokens"], 100)
            self.assertEqual(run["usage"]["total_tokens"], 120)
            self.assertEqual(run["models"], ["claude-sonnet-4-5-20250929"])
            self.assertIsNone(report["mcp"]["model_tokens"])
            ledger = next((state / "usage/runs").glob("*.json")).read_text()
            for marker in ("task-text-not-for-ledger", "simulated agent answer", "UNRELATED_HISTORY_MUST_NOT_APPEAR"):
                self.assertNotIn(marker, ledger + proc.stdout)


if __name__ == "__main__":
    unittest.main()
