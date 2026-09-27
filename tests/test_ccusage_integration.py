"""Opt-in native ccusage proof using synthetic Cloudseed metadata only.

Prepare an isolated state directory with `cs usage install`, then set
CLOUDSEED_CCUSAGE_TEST_HOME to it. CLOUDSEED_TEST_BINARY optionally selects the
exact built executable. These tests never install or download anything.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
TEST_HOME = os.environ.get("CLOUDSEED_CCUSAGE_TEST_HOME")


@unittest.skipUnless(TEST_HOME, "Set CLOUDSEED_CCUSAGE_TEST_HOME to an isolated, already-installed ccusage fixture")
class NativeCcusageIntegrationTests(unittest.TestCase):
    def setUp(self):
        from cloudseed import usage
        self.usage = usage
        self.state = Path(TEST_HOME).expanduser().resolve()
        self.assertTrue(self.state.is_dir(), "The provided ccusage fixture directory must already exist")
        self.assertNotIn(self.state, (Path.home().resolve(), (Path.home() / ".cloudseed").resolve()),
                         "Refusing to use the actual user home or default Cloudseed state")
        self.assertFalse((self.state / "credentials.json").exists(), "Use a synthetic fixture without credentials")
        patch = mock.patch.object(usage.paths, "HOME", self.state)
        patch.start()
        self.addCleanup(patch.stop)
        self.assertTrue(usage.ccusage_status()["installed"], "Install the pinned engine in the provided fixture first")
        self.created = []
        self.addCleanup(self.remove_records)
        temporary = tempfile.TemporaryDirectory(prefix="native-ccusage-test-", dir=self.state)
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        (self.home / "tmp").mkdir()
        self.env = {"HOME": str(self.home), "USERPROFILE": str(self.home), "CLOUDSEED_HOME": str(self.state),
                    "CLAUDE_CONFIG_DIR": str(self.home / ".claude"), "CODEX_HOME": str(self.home / ".codex"),
                    "GEMINI_DATA_DIR": str(self.home / ".gemini"), "XDG_CONFIG_HOME": str(self.home / ".config"),
                    "XDG_CACHE_HOME": str(self.home / ".cache"), "PATH": os.defpath, "NO_COLOR": "1",
                    "TMPDIR": str(self.home / "tmp"), "TMP": str(self.home / "tmp"), "TEMP": str(self.home / "tmp"),
                    # Any accidental network access must fail rather than reach a model or pricing endpoint.
                    "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
                    "ALL_PROXY": "http://127.0.0.1:9"}
        for name in ("SYSTEMROOT", "WINDIR"):
            if name in os.environ:
                self.env[name] = os.environ[name]
        binary = os.environ.get("CLOUDSEED_TEST_BINARY")
        self.command = [str(Path(binary).resolve())] if binary else [sys.executable, str(ROOT / "bin" / "cloudseed")]
        self.decoys = []
        timestamp = "2026-09-27T00:00:00Z"
        for relative, content in (
            (".claude/projects/unrelated/session.jsonl", {"timestamp": timestamp, "sessionId": "unrelated-history",
                "message": {"id": "unrelated-message", "model": "claude-opus-4-20250514", "content": "UNRELATED_TRANSCRIPT_SENTINEL",
                    "usage": {"input_tokens": 900000000, "output_tokens": 900000000}}}),
            (".codex/sessions/unrelated.jsonl", {"timestamp": timestamp, "type": "event_msg", "payload":
                {"type": "token_count", "info": {"last_token_usage": {"input_tokens": 900000000, "output_tokens": 900000000,
                    "total_tokens": 1800000000}}}, "sentinel": "UNRELATED_TRANSCRIPT_SENTINEL"}),
            (".gemini/chats/unrelated.jsonl", {"type": "gemini", "id": "unrelated-message", "timestamp": timestamp,
                "model": "gemini-2.5-flash", "content": "UNRELATED_TRANSCRIPT_SENTINEL",
                "tokens": {"input": 900000000, "output": 900000000, "total": 1800000000}}),
        ):
            path = self.home / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            text = json.dumps(content) + "\n"
            path.write_text(text)
            self.decoys.append((path, text))

    def remove_records(self):
        for run in self.created:
            path = self.state / "usage" / "runs" / (run.id + ".json")
            if path.is_file() and not path.is_symlink():
                path.unlink()

    def start(self, agent, model):
        run = self.usage.start_run(agent, model=model, mode="builtin" if agent == "builtin" else "exec")
        self.created.append(run)
        return run

    def report(self, run):
        proc = subprocess.run([*self.command, "usage", "report", "--engine", "ccusage", "--run-id", run.id, "--json"],
                              env=self.env, cwd=self.home, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, (proc.stdout + proc.stderr)[-4000:])
        result = json.loads(proc.stdout)
        self.assertEqual([row["id"] for row in result["runs"]], [run.id])
        self.assertEqual(result["summary"]["run_count"], 1)
        self.assertEqual(result["mcp"]["call_count"], 0)
        self.assertTrue(result["ccusage"]["offline"])
        self.assertEqual(result["ccusage"]["version"], self.usage.VERSION)
        self.assertNotIn("UNRELATED_TRANSCRIPT_SENTINEL", proc.stdout)
        self.assertNotIn("unrelated-history", proc.stdout)
        self.assertNotIn("SYNTHETIC_PROMPT_NOT_METADATA", proc.stdout)
        for path, original in self.decoys:
            self.assertEqual(path.read_text(), original, "Global agent fixture histories must remain untouched")
        return result

    def assert_priced(self, result, model, total=1200):
        self.assertEqual(result["summary"]["usage"]["total_tokens"], total)
        self.assertEqual(result["runs"][0]["status"], "complete")
        estimate = result["ccusage"]
        self.assertEqual(estimate["status"], "complete", estimate)
        self.assertGreater(estimate["estimated_cost_usd"], 0)
        self.assertEqual(estimate["models"], [model])
        self.assertEqual(estimate["unpriced_models"], [])
        self.assertEqual(estimate["reasons"], [])

    def anthropic(self, model, writes=50, ttl="5m"):
        run = self.start("builtin", model)
        run.observe_anthropic({"id": "msg-" + run.id, "model": model,
            "content": [{"type": "text", "text": "SYNTHETIC_PROMPT_NOT_METADATA"}],
            "usage": {"input_tokens": 800, "cache_read_input_tokens": 150, "cache_creation_input_tokens": writes,
                "cache_creation": {"ephemeral_5m_input_tokens": writes if ttl == "5m" else 0,
                                   "ephemeral_1h_input_tokens": writes if ttl == "1h" else 0}, "output_tokens": 200}})
        run.finish(0)
        return run

    def test_claude_known_model_cache_counts_and_unrelated_history_excluded(self):
        model = "claude-sonnet-4-20250514"
        result = self.report(self.anthropic(model))
        self.assert_priced(result, model)
        self.assertEqual(result["runs"][0]["usage"]["input_tokens"], 1000)
        self.assertEqual(result["runs"][0]["usage"]["cache_read_tokens"], 150)
        self.assertEqual(result["runs"][0]["usage"]["cache_write_tokens"], 50)

    def test_codex_verified_model_and_cached_reasoning_subsets(self):
        model = "gpt-5"
        run = self.start("codex", model)
        run.observe_codex({"type": "thread.started", "thread_id": "thread-" + run.id})
        run.observe_codex({"type": "turn.started"})
        # Explicit observed-model metadata is required; a requested model alone is not priced.
        run.observe_codex({"type": "turn.completed", "model": model, "usage": {"input_tokens": 1000,
            "cached_input_tokens": 250, "output_tokens": 200, "reasoning_output_tokens": 50}})
        run.finish(0)
        result = self.report(run)
        self.assert_priced(result, model)
        self.assertEqual(result["runs"][0]["usage"]["reasoning_tokens"], 50)

    def test_gemini_actual_stream_schema_known_model(self):
        model = "gemini-2.5-pro"
        run = self.start("gemini", model)
        run.observe_gemini({"type": "init", "session_id": "session-" + run.id, "model": model})
        stats = {"input_tokens": 1000, "output_tokens": 200, "total_tokens": 1200, "cached": 250, "input": 750}
        run.observe_gemini({"type": "result", "status": "success", "stats": {**stats, "models": {model: stats}}})
        run.finish(0)
        result = self.report(run)
        self.assert_priced(result, model)
        self.assertEqual(result["runs"][0]["usage"]["input_tokens"], 1000)
        self.assertEqual(result["runs"][0]["usage"]["cache_read_tokens"], 250)

    def test_unknown_model_cost_is_explicitly_unavailable(self):
        model = "unpriced-cloudseed-fixture-model-2099"
        result = self.report(self.anthropic(model, writes=0))
        self.assertEqual(result["summary"]["usage"]["total_tokens"], 1150)
        self.assertIsNone(result["ccusage"]["estimated_cost_usd"])
        self.assertIn(model, result["ccusage"]["unpriced_models"])
        self.assertIn("pricing", " ".join(result["ccusage"]["reasons"]).lower())
        self.assertNotEqual(result["ccusage"]["status"], "complete")

    def test_one_hour_cache_pricing_is_correct_or_explicitly_unsupported(self):
        model = "claude-sonnet-4-20250514"
        five = self.report(self.anthropic(model, writes=1000, ttl="5m"))
        hour = self.report(self.anthropic(model, writes=1000, ttl="1h"))
        self.assertEqual(hour["summary"]["usage"]["cache_write_tokens"], 1000)
        cost = hour["ccusage"]["estimated_cost_usd"]
        if cost is None:
            self.assertNotEqual(hour["ccusage"]["status"], "complete")
            self.assertTrue(hour["ccusage"]["reasons"])
        else:
            # With everything else equal, 1-hour writes must not be silently charged
            # at the cheaper 5-minute rate. Do not hard-code mutable model prices.
            self.assertGreater(cost, five["ccusage"]["estimated_cost_usd"])


if __name__ == "__main__":
    unittest.main()
