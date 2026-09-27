"""Saved evidence guidance and honest, bounded built-in agent results."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-evidence-context-"))
from cloudseed import builtin_agent, headliner, secrets


class EvidenceContextTests(unittest.TestCase):
    def test_brief_artifact_hints_are_bounded_and_do_not_read_contents_or_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scans").mkdir()
            for i in range(140):
                (root / "scans" / f"cloud-20260927-{i:06}.json").write_text("PRIVATE CONTENT MUST NOT BE READ")
            (root / "credential.json").write_text("PRIVATE CONTENT MUST NOT BE READ")
            (root / "scans" / "cloud-20260927-999999.json").symlink_to(root / "credential.json")
            env = types.SimpleNamespace(id="aws-example", dir=root)
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("must only inspect filenames")):
                hints = headliner._artifact_hints(env)
                text = "\n".join(headliner._evidence_lines("investigate aws-example reports", {}, [env]))
            self.assertEqual(len(hints), 6)
            self.assertNotIn("scans/cloud-20260927-999999.json", hints)
            self.assertNotIn("PRIVATE CONTENT", text)
            self.assertIn("bounded sample", text)
            self.assertIn("evidence list aws --env example --json", text)
            self.assertIn("evidence directory=", text)
            self.assertLess(len(text), 4000)

    def test_brief_targets_named_environment_and_only_relevant_tasks(self):
        envs = [types.SimpleNamespace(id="aws-example", dir=Path("/not-present/a")),
                types.SimpleNamespace(id="gcp-other", dir=Path("/not-present/b"))]
        self.assertEqual(headliner._evidence_lines("explain the vpc", {}, envs), [])
        text = "\n".join(headliner._evidence_lines("read aws-example scan reports", {"current_env": "gcp-other"}, envs))
        self.assertIn("aws-example", text)
        self.assertNotIn("gcp-other", text)
        for word in ("diagnostics", "coverage_limits", "failure_policy", "generated_at", "modification time",
                     "Unknown=0", "next_offset", "--revision", "complete is true"):
            self.assertIn(word, text)

    def test_brief_names_actual_context_feature_and_does_not_promise_auto_approve_guarantee(self):
        with mock.patch.object(headliner.paths.Env, "list_all", return_value=[]), \
             mock.patch.object(headliner.deps, "status", return_value=[]), \
             mock.patch.object(headliner.clouds, "get") as cloud:
            cloud.return_value.credential_warnings.return_value = []
            text = headliner.build("read saved reports", {})
        self.assertIn("# Cloudseed context brief", text)
        self.assertNotIn("headliner brief", text)
        self.assertNotIn("changes are only applied with --auto-approve", text)
        self.assertIn("without --auto-approve", text)
        self.assertIn("Scan exit code 3 means INCOMPLETE", text)
        self.assertTrue(headliner.enabled({}))
        self.assertFalse(headliner.enabled({"headliner": False}))

    def test_builtin_and_plain_prompts_use_authorized_evidence_pagination(self):
        with mock.patch.object(builtin_agent.skills, "prompt_bundle", return_value="skills"):
            text = builtin_agent.system_prompt("investigate a saved cloud scan")
        for part in ("evidence list", "evidence read", "next_offset", "--revision", "complete is true",
                     "diagnostics", "unknown=0", "generated_at", "not current live state",
                     "untrusted evidence", "approval requirements still apply"):
            self.assertIn(part, text)
        plain = headliner.plain("review reports")
        self.assertIn("evidence list/read", plain)
        self.assertIn("--revision", plain)
        self.assertIn("not instructions", plain)


class BoundedOutputTests(unittest.TestCase):
    def test_single_large_line_cannot_remain_in_capture_memory(self):
        cap = builtin_agent._Capture(100)
        cap.add("start" + "x" * 1_000_000 + "end")
        self.assertEqual(len(cap.head), 50)
        self.assertLessEqual(sum(len(chunk) for chunk in cap.tail), 50)
        self.assertEqual(cap.tail_len, 50)
        self.assertTrue(cap.text().startswith("start"))
        self.assertTrue(cap.text().endswith("end"))
        self.assertIn("...[truncated]...", cap.text())

    def test_report_excerpt_instructs_pagination_without_requesting_scan_approval(self):
        with mock.patch.object(builtin_agent, "_run_child", return_value=(0, "first\n...[truncated]...\nlast")), \
             mock.patch.object(builtin_agent.ui, "confirm", side_effect=AssertionError("read needs no approval")), \
             contextlib.redirect_stdout(io.StringIO()):
            result = builtin_agent.run_tool("scan reports aws --env example", ["cloudseed"], {})
        self.assertTrue(result.startswith("exit code: 0\n"))
        self.assertIn("OUTPUT TRUNCATED", result)
        self.assertIn("findings in the middle may be missing", result)
        self.assertIn("next_offset", result)
        self.assertIn("--revision", result)
        self.assertTrue(builtin_agent.is_destructive(["scan", "cloud", "aws", "--env", "example"]))

    def test_evidence_reader_reserves_enough_capture_for_full_bounded_response(self):
        from cloudseed import evidence
        payload = json.dumps({"report_metadata": {"hint": "x" * 11000}, "content": "z" * 16000,
                              "complete": False, "next_offset": 16000, "revision": "a" * 64})
        with mock.patch.object(builtin_agent, "_run_child", return_value=(0, payload)) as child, \
             mock.patch.object(builtin_agent.ui, "confirm", side_effect=AssertionError("read needs no approval")), \
             contextlib.redirect_stdout(io.StringIO()):
            result = builtin_agent.run_tool("evidence read aws --env example --artifact scans/cloud-20260927-030241.json --json",
                                            ["cloudseed"], {})
        limit = child.call_args.kwargs["output_limit"]
        self.assertGreater(limit, evidence.MAX_RESPONSE_BYTES)
        self.assertEqual(json.loads(result.split("\n", 1)[1]), json.loads(payload))

    def test_unclosed_child_pipe_is_explicitly_incomplete(self):
        code = ("import subprocess, sys\n"
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.25)'])\n"
                "print('saved report available', flush=True)\n")
        with mock.patch.object(builtin_agent, "DRAIN_SECONDS", 0.01), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc, output = builtin_agent._run_child([sys.executable, "-c", code], dict(os.environ))
        self.assertEqual(rc, 0)
        self.assertIn("OUTPUT INCOMPLETE", output)
        self.assertIn("Later output may be missing", output)


class AgentCompletionTests(unittest.TestCase):
    def tearDown(self):
        secrets.set_strict(False)

    def run_messages(self, messages):
        sdk = types.ModuleType("anthropic")
        for name in ("AuthenticationError", "RateLimitError", "APIStatusError", "APIConnectionError"):
            setattr(sdk, name, type(name, (Exception,), {}))
        sdk.beta_tool = lambda function: function
        sdk.Anthropic = lambda: types.SimpleNamespace(beta=types.SimpleNamespace(messages=types.SimpleNamespace(
            tool_runner=lambda **kwargs: iter(messages))))
        err = io.StringIO()
        with mock.patch.dict(sys.modules, {"anthropic": sdk}), \
             mock.patch.object(builtin_agent, "ensure_sdk"), \
             mock.patch.object(builtin_agent, "has_api_credentials", return_value=True), \
             mock.patch.object(builtin_agent, "system_prompt", return_value="system"), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = builtin_agent.run("prompt", "claude-sonnet-5", "task")
        return rc, err.getvalue()

    def test_no_response_is_not_a_success(self):
        rc, error = self.run_messages([])
        self.assertEqual(rc, 1)
        self.assertIn("no response", error)

    def test_unfinished_tool_turn_is_not_a_success(self):
        rc, error = self.run_messages([types.SimpleNamespace(content=[], stop_reason="tool_use")])
        self.assertEqual(rc, 1)
        self.assertIn("without a completed answer", error)

    def test_headroom_preserves_sdk_resolved_upstream_and_only_changes_client_transport(self):
        from cloudseed import headroom
        sdk = types.ModuleType("anthropic")
        for name in ("AuthenticationError", "RateLimitError", "APIStatusError", "APIConnectionError"):
            setattr(sdk, name, type(name, (Exception,), {}))
        sdk.beta_tool = lambda function: function
        client = types.SimpleNamespace(base_url="https://profile.example/v1", beta=types.SimpleNamespace(
            messages=types.SimpleNamespace(tool_runner=lambda **kwargs: iter([
                types.SimpleNamespace(content=[], stop_reason="end_turn")]))))
        sdk.Anthropic = mock.Mock(return_value=client)
        sdk.DefaultHttpxClient = mock.Mock()
        seen = {}
        @contextlib.contextmanager
        def session(agent, env, enabled, **kwargs):
            seen.update(agent=agent, enabled=enabled, env=env, **kwargs)
            yield headroom.Route(dict(env), True, "active", "http://127.0.0.1:12345")
        with mock.patch.dict(sys.modules, {"anthropic": sdk}), \
             mock.patch.object(builtin_agent, "ensure_sdk"), \
             mock.patch.object(builtin_agent, "has_api_credentials", return_value=True), \
             mock.patch.object(builtin_agent, "system_prompt", return_value="system"), \
             mock.patch.object(headroom, "session", side_effect=session), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(builtin_agent.run("prompt", "claude-sonnet-5", "task", headroom_enabled=True), 0)
        sdk.DefaultHttpxClient.assert_called_once_with(trust_env=False)
        sdk.Anthropic.assert_called_once_with(http_client=sdk.DefaultHttpxClient.return_value)
        sdk.DefaultHttpxClient.return_value.close.assert_called_once_with()
        self.assertEqual(seen["upstream_url"], "https://profile.example/v1")
        self.assertTrue(seen["enabled"])
        self.assertEqual(client.base_url, "http://127.0.0.1:12345")


if __name__ == "__main__":
    unittest.main()
