"""Native per-run accounting preserves output, credentials, permissions and cleanup."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
import uuid
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-agent-usage-"))
from cloudseed import agents, builtin_agent, secrets, usage


class Record:
    def __init__(self):
        self.id = str(uuid.uuid4())
        self.events = []
        self.reasons = []
        self.exits = []

    def observe_claude(self, event):
        self.events.append(("claude", event))

    def observe_codex(self, event):
        self.events.append(("codex", event))

    def observe_gemini(self, event):
        self.events.append(("gemini", event))

    def observe_anthropic(self, event):
        self.events.append(("anthropic", event))

    def unavailable(self, reason):
        self.reasons.append(reason)

    def finish(self, code):
        self.exits.append(code)


class NativeUsageTests(unittest.TestCase):
    def tearDown(self):
        secrets.set_strict(False)

    def launch(self, agent, events=(), extra_code="", interactive=False, custom=False, record=None):
        record = record or Record()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / agent
            capture = root / "child.json"
            binary.write_text("#!" + sys.executable + "\n" +
                "import json, os, subprocess, sys\n" +
                "from pathlib import Path\n" +
                "Path(os.environ['TEST_CHILD']).write_text(json.dumps({'argv':sys.argv[1:],"
                "'environment':{k:os.environ.get(k) for k in ['ANTHROPIC_BASE_URL','HTTPS_PROXY',"
                "'SSL_CERT_FILE','CODEX_API_KEY','CLOUDSEED_SESSION']}}))\n" +
                "events = " + repr(list(events)) + "\n" +
                "for event in events: print(json.dumps(event), flush=True)\n" + extra_code)
            binary.chmod(0o700)
            spec = dict(copy.deepcopy(agents.DEFAULT_AGENTS[agent]), key=agent)
            if custom:
                spec["exec"] = [agent, "--custom", "{prompt}"]
            child_env = {"PATH": os.defpath, "TEST_CHILD": str(capture),
                         "ANTHROPIC_BASE_URL": "https://synthetic-provider.invalid/v1",
                         "HTTPS_PROXY": "https://synthetic-proxy.invalid:8443",
                         "SSL_CERT_FILE": "/synthetic/ca.pem", "CODEX_API_KEY": "synthetic-auth-value",
                         "CLOUDSEED_SESSION": "synthetic-broker-capability-not-a-uuid"}
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(agents, "installed", return_value=str(binary)), \
                 mock.patch.object(agents, "readiness", return_value=(True, "ready")), \
                 mock.patch.object(agents, "_agent_keys", return_value=((), None)), \
                 mock.patch.object(secrets, "open_session", return_value=("broker-handle", child_env)), \
                 mock.patch.object(secrets, "close_session") as close, \
                 mock.patch.object(usage, "start_run", return_value=record) as start, \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = agents.run(spec, "inspect evidence", "synthetic-model", interactive)
            close.assert_called_once_with("broker-handle")
            start.assert_called_once_with(agent, model="synthetic-model", mode="interactive" if interactive else "exec")
            data = json.loads(capture.read_text())
        return code, record, data, out.getvalue(), err.getvalue()

    def test_claude_native_events_uuid_and_existing_permissions(self):
        events = [{"type": "system", "subtype": "init", "session_id": "native-fixture"},
                  {"type": "assistant", "message": {"id": "msg-fixture", "model": "actual-model",
                   "content": [{"type": "text", "text": "Assistant answer"},
                               {"type": "tool_use", "input": {"private": "not-visible-tool-input"}}],
                   "usage": {"input_tokens": 12, "output_tokens": 3}}},
                  {"type": "result", "result": "Assistant answer", "usage": {"input_tokens": 12, "output_tokens": 3}}]
        code, record, data, out, _ = self.launch("claude", events)
        self.assertEqual(code, 0)
        self.assertEqual(record.events, [("claude", event) for event in events])
        self.assertEqual(record.exits, [0])
        argv = data["argv"]
        self.assertEqual(argv[argv.index("--session-id") + 1], record.id)
        self.assertNotEqual(record.id, data["environment"]["CLOUDSEED_SESSION"])
        self.assertEqual(argv[argv.index("--output-format") + 1], "stream-json")
        self.assertIn("--verbose", argv)
        self.assertIn("--allowedTools", argv)
        self.assertIn("Bash(cloudseed:*)", argv[argv.index("--allowedTools") + 1])
        self.assertIn("Bash(cat:*)", argv[argv.index("--disallowedTools") + 1])
        self.assertEqual(out.count("Assistant answer"), 1)
        self.assertNotIn("not-visible-tool-input", out)
        self.assertEqual(data["environment"]["HTTPS_PROXY"], "https://synthetic-proxy.invalid:8443")
        self.assertEqual(data["environment"]["ANTHROPIC_BASE_URL"], "https://synthetic-provider.invalid/v1")
        self.assertEqual(data["environment"]["SSL_CERT_FILE"], "/synthetic/ca.pem")

    def test_codex_turn_sequence_and_errors_keep_exit_status(self):
        events = [{"type": "thread.started", "thread_id": "native-thread"},
                  {"type": "turn.started"},
                  {"type": "item.completed", "item": {"type": "agent_message", "text": "Codex answer"}},
                  {"type": "turn.completed", "usage": {"input_tokens": 12, "output_tokens": 3}},
                  {"type": "turn.failed", "error": {"message": "Synthetic provider failure"}}]
        code, record, data, out, err = self.launch("codex", events,
            "print('Synthetic stderr diagnostic', file=sys.stderr)\nsys.exit(7)\n")
        self.assertEqual(code, 7)
        self.assertEqual(record.exits, [7])
        self.assertEqual(record.events, [("codex", event) for event in events])
        self.assertEqual(data["argv"][:2], ["exec", "--json"])
        self.assertEqual(data["environment"]["CODEX_API_KEY"], "synthetic-auth-value")
        self.assertIn("Codex answer", out)
        self.assertIn("Synthetic provider failure", out)
        self.assertIn("Synthetic stderr diagnostic", err)

    def test_gemini_deltas_are_redacted_across_event_boundaries(self):
        value = "synthetic-long-secret-value"
        secrets.register(value)
        events = [{"type": "init", "session_id": "native-gemini", "model": "model"},
                  {"type": "message", "role": "user", "content": "hidden-input"},
                  {"type": "message", "role": "assistant", "delta": True, "content": "Answer " + value[:10]},
                  {"type": "message", "role": "assistant", "delta": True, "content": value[10:] + " complete"},
                  {"type": "result", "status": "success", "stats": {"total_tokens": 12, "input_tokens": 10,
                   "output_tokens": 2, "cached": 3, "input": 7, "models": {"model": {"total_tokens": 12,
                       "input_tokens": 10, "output_tokens": 2, "cached": 3, "input": 7}}}}]
        code, record, data, out, _ = self.launch("gemini", events)
        self.assertEqual(code, 0)
        self.assertEqual(record.events, [("gemini", event) for event in events])
        self.assertEqual(data["argv"][:2], ["--output-format", "stream-json"])
        self.assertIn("Answer [REDACTED] complete", out)
        self.assertNotIn(value, out)
        self.assertNotIn("hidden-input", out)

    def test_gemini_terminal_and_tool_errors_remain_visible(self):
        events = [{"type": "tool_result", "status": "error", "error": {"message": "Synthetic tool error"}},
                  {"type": "result", "status": "error", "error": {"message": "Synthetic terminal error"}}]
        code, record, _, out, _ = self.launch("gemini", events, "sys.exit(1)\n")
        self.assertEqual(code, 1)
        self.assertIn("Synthetic tool error", out)
        self.assertIn("Synthetic terminal error", out)
        self.assertEqual(record.events, [("gemini", event) for event in events])

    def test_bad_and_oversized_events_do_not_block_or_expose_json(self):
        with mock.patch.object(agents, "MAX_USAGE_EVENT", 2048):
            code, record, _, out, _ = self.launch("codex", extra_code=
                "print('{\\\"private\\\":\\\"malformed-private-input', flush=True)\n"
                "print('x' * 10000, flush=True)\n"
                "print('Unsupported CLI option diagnostic', flush=True)\n"
                "print(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':'Still running'}}))\n")
        self.assertEqual(code, 0)
        self.assertTrue(any("parser limit" in reason for reason in record.reasons))
        self.assertTrue(any("unrecognized" in reason for reason in record.reasons))
        self.assertNotIn("malformed-private-input", out)
        self.assertNotIn("x" * 100, out)
        self.assertIn("Unsupported CLI option diagnostic", out)
        self.assertIn("Still running", out)
        self.assertLess(len(out), 3000)

    def test_custom_and_interactive_templates_remain_unchanged(self):
        for interactive, custom in ((False, True), (True, False)):
            with self.subTest(interactive=interactive):
                _, record, data, _, _ = self.launch("claude", interactive=interactive, custom=custom)
                self.assertNotIn("--session-id", data["argv"])
                self.assertNotIn("--output-format", data["argv"])
                self.assertTrue(record.reasons)
                self.assertEqual(record.events, [])
                self.assertEqual(record.exits, [0])

    def test_recording_errors_do_not_break_agent_or_leak_exception(self):
        record = Record()
        record.observe_codex = mock.Mock(side_effect=OSError("PRIVATE backend error"))
        record.finish = mock.Mock(side_effect=OSError("PRIVATE finish error"))
        code, record, _, out, err = self.launch("codex", [{"type": "item.completed", "item":
            {"type": "agent_message", "text": "Normal answer"}}], record=record)
        self.assertEqual(code, 0)
        self.assertIn("Normal answer", out)
        self.assertNotIn("PRIVATE", out + err)
        self.assertEqual((out + err).count("Usage could not be recorded"), 1)

    def test_start_failure_still_allows_agent_capture_and_finish_is_idempotent_for_late_events(self):
        with mock.patch.object(usage, "start_run", side_effect=OSError("PRIVATE start error")), \
             contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            with agents._UsageCapture("codex", None, "exec") as record:
                uuid.UUID(record.id)
                record.observe("observe_codex", {"type": "turn.started"})
                record.exit_code = 0
        self.assertNotIn("PRIVATE", err.getvalue())
        fake = Record()
        with mock.patch.object(usage, "start_run", return_value=fake):
            with agents._UsageCapture("codex", None, "exec") as record:
                record.exit_code = 0
            record.observe("observe_codex", {"type": "turn.started"})
            record.unavailable("late update")
        self.assertEqual(fake.events, [])
        self.assertEqual(fake.reasons, [])
        self.assertEqual(fake.exits, [0])

    def test_detached_pipe_is_bounded_and_marked_partial(self):
        started = time.monotonic()
        with mock.patch.object(agents, "USAGE_DRAIN_SECONDS", 0.01):
            code, record, _, _, _ = self.launch("codex", extra_code=
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.25)'])\n")
        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(any("pipes closed" in reason for reason in record.reasons))

    def test_interruption_stops_child_and_records_partial(self):
        record = Record()
        with mock.patch.object(usage, "start_run", return_value=record), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                    start_new_session=os.name == "posix", stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            try:
                with self.assertRaises(KeyboardInterrupt):
                    with agents._UsageCapture("codex", None, "exec") as capture:
                        # The existing wait helper must still own process-group cleanup.
                        real_wait = proc.wait
                        with mock.patch.object(proc, "wait", side_effect=[KeyboardInterrupt, 0]):
                            agents._wait_usage(proc, os.name == "posix", "codex", capture)
                        real_wait(timeout=2)
                self.assertIsNotNone(proc.poll())
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
        self.assertEqual(record.exits, [130])
        self.assertTrue(any("normal completion" in reason for reason in record.reasons))


class BuiltinUsageTests(unittest.TestCase):
    def tearDown(self):
        secrets.set_strict(False)

    def test_every_yielded_sdk_message_is_observed_and_client_closed(self):
        sdk = types.ModuleType("anthropic")
        for name in ("AuthenticationError", "RateLimitError", "APIStatusError", "APIConnectionError"):
            setattr(sdk, name, type(name, (Exception,), {}))
        sdk.beta_tool = lambda function: function
        messages = [types.SimpleNamespace(id="msg-one", model="actual-model", usage=types.SimpleNamespace(
            input_tokens=100, output_tokens=5), content=[], stop_reason="tool_use"),
            types.SimpleNamespace(id="msg-two", model="actual-model", usage=types.SimpleNamespace(
            input_tokens=150, output_tokens=9), content=[], stop_reason="end_turn")]
        client = types.SimpleNamespace(close=mock.Mock(), beta=types.SimpleNamespace(messages=types.SimpleNamespace(
            tool_runner=lambda **kwargs: iter(messages))))
        sdk.Anthropic = mock.Mock(return_value=client)
        record = Record()
        with mock.patch.dict(sys.modules, {"anthropic": sdk}), \
             mock.patch.object(builtin_agent, "ensure_sdk"), \
             mock.patch.object(builtin_agent, "has_api_credentials", return_value=True), \
             mock.patch.object(builtin_agent, "system_prompt", return_value="system"), \
             mock.patch.object(usage, "start_run", return_value=record) as start, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(builtin_agent.run("prompt", "requested-model", "task"), 0)
        start.assert_called_once_with("builtin", model="requested-model", mode="builtin")
        self.assertEqual(record.events, [("anthropic", message) for message in messages])
        self.assertEqual(record.exits, [0])
        sdk.Anthropic.assert_called_once_with()
        client.close.assert_called_once_with()

    def test_usage_readonly_commands_allowed_install_and_ambiguous_options_refused(self):
        builtin_agent._PARSER.clear()
        for args in (["usage"], ["usage", "report", "--engine", "ccusage", "--json"],
                     ["usage", "--engine", "native", "report", "--agent", "claude", "--limit", "2"],
                     ["-y", "usage", "--json"]):
            with self.subTest(args=args):
                self.assertIsNone(builtin_agent.guard(args))
                self.assertFalse(builtin_agent.is_destructive(args))
        for args in (["usage", "install"], ["usage", "--engine", "ccusage", "install"],
                     ["--engine", "docker", "usage"], ["usage", "--eng", "native"],
                     ["usage", "--", "install"]):
            with self.subTest(args=args):
                self.assertIsNotNone(builtin_agent.guard(args))


if __name__ == "__main__":
    unittest.main()
