"""Managed Headroom isolation and real loopback-only proxy contract.

Optional integration test: CLOUDSEED_HEADROOM_TEST_VENV=/path/to/pinned/venv.
Its only inference upstream is a local synthetic server; no provider keys.
"""
import contextlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import types
import unittest
import urllib.request
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-headroom-tests-"))
from cloudseed import agents, headroom, ui


class HeadroomContractTests(unittest.TestCase):
    def test_proxy_environment_contains_no_provider_credentials_or_inherited_settings(self):
        source = {"PATH": "/bin", "ANTHROPIC_API_KEY": "private", "OPENAI_API_KEY": "private",
                  "AWS_ACCESS_KEY_ID": "private", "AWS_SECRET_ACCESS_KEY": "private", "ARM_CLIENT_SECRET": "private",
                  "GOOGLE_APPLICATION_CREDENTIALS": "/private/credentials", "HEADROOM_LOG_MESSAGES": "true",
                  "HEADROOM_SETTINGS_PATH": "/private/settings", "OTEL_EXPORTER_OTLP_ENDPOINT": "https://example.com",
                  "PYTHONPATH": "/private/import", "HTTPS_PROXY": "http://approved-proxy:8080"}
        result = headroom._proxy_env(Path("/private/session"), source)
        self.assertFalse(any(value == "private" for value in result.values()))
        for key in ("PYTHONPATH", "HEADROOM_LOG_MESSAGES", "OTEL_EXPORTER_OTLP_ENDPOINT", "GOOGLE_APPLICATION_CREDENTIALS"):
            self.assertNotIn(key, result)
        self.assertEqual(result["HTTPS_PROXY"], source["HTTPS_PROXY"])
        self.assertEqual(result["HEADROOM_SETTINGS_PATH"], "/private/session/settings.json")
        self.assertEqual(result["HOME"], "/private/session")
        self.assertEqual(result["USERPROFILE"], "/private/session")
        self.assertEqual(result["HEADROOM_BEACON"], "off")
        self.assertEqual(result["HEADROOM_OFFLINE"], "1")

    def test_unsupported_and_disabled_routes_do_not_start_or_install(self):
        original = {"OPENAI_BASE_URL": "https://custom.example/v1"}
        with mock.patch.object(headroom, "status", side_effect=AssertionError("must not inspect dependency")):
            for agent, enabled in (("builtin", False), ("gemini", True), ("grok", True), ("codex", True)):
                with headroom.session(agent, original, enabled) as route:
                    self.assertFalse(route.active)
                    self.assertEqual(route.env, original)
                    self.assertIsNot(route.env, original)
                    self.assertTrue(route.reason)

    def test_claude_cloud_routes_are_truthfully_unsupported(self):
        with headroom.session("claude", {"CLAUDE_CODE_USE_BEDROCK": "1"}) as route:
            self.assertFalse(route.active)
            self.assertIn("cloud-provider", route.reason)

    def test_custom_base_url_rejects_ambiguous_credentials_and_paths(self):
        self.assertEqual(headroom._target_url("https://custom.example:443/v1/"), "https://custom.example:443")
        self.assertEqual(headroom._target_url("http://127.0.0.1:1234/v1"), "http://127.0.0.1:1234")
        for value in ("http://remote.example", "https://key:secret@remote.example", "https://remote.example?key=secret",
                      "https://remote.example/custom/v1", "https://remote.example/#fragment", "not-a-url"):
            with self.subTest(value=value), self.assertRaises(ui.Abort):
                headroom._target_url(value)

    def test_requested_missing_dependency_fails_instead_of_claiming_active(self):
        with mock.patch.object(headroom, "status", return_value={"ready": False, "reason": "missing dependency"}):
            with self.assertRaisesRegex(ui.Abort, "missing dependency"):
                with headroom.session("builtin", {}):
                    self.fail("must not enter")

    def test_owned_process_and_private_directory_cleaned_when_agent_fails(self):
        process = mock.Mock(pid=12345)
        captured = []
        def launch(cmd, **kwargs):
            captured.append((cmd, kwargs))
            return process
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(headroom.paths, "HOME", Path(tmp)), \
             mock.patch.object(headroom.paths, "ensure_home"), mock.patch.object(headroom, "status", return_value={"ready": True}), \
             mock.patch.object(headroom.subprocess, "Popen", side_effect=launch), mock.patch.object(headroom, "_wait_ready"), \
             mock.patch.object(headroom, "_stop") as stop:
            original = {"ANTHROPIC_API_KEY": "synthetic-only", "ANTHROPIC_BASE_URL": "https://custom.example/v1",
                        "HTTPS_PROXY": "http://corporate-proxy:8080", "NO_PROXY": "internal.example",
                        "no_proxy": "another.internal"}
            with self.assertRaisesRegex(RuntimeError, "agent failure"):
                with headroom.session("builtin", original) as route:
                    self.assertTrue(route.active)
                    self.assertEqual(route.env["ANTHROPIC_API_KEY"], "synthetic-only")
                    self.assertTrue(route.env["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:"))
                    self.assertEqual(route.env["NO_PROXY"], route.env["no_proxy"])
                    for host in ("internal.example", "another.internal", "127.0.0.1", "localhost", "::1"):
                        self.assertIn(host, route.env["NO_PROXY"].split(","))
                    self.assertEqual(Path(captured[0][1]["cwd"]).stat().st_mode & 0o777, 0o700)
                    raise RuntimeError("agent failure")
            stop.assert_called_once_with(process)
            self.assertEqual(list(Path(tmp).iterdir()), [])
            cmd, kwargs = captured[0]
            self.assertIn("--lossless", cmd)
            self.assertIn("--disable-kompress-fallback", cmd)
            self.assertEqual(cmd[-1], "https://custom.example")
            self.assertNotIn("ANTHROPIC_API_KEY", kwargs["env"])
            self.assertEqual(kwargs["env"]["HTTPS_PROXY"], "http://corporate-proxy:8080")
            self.assertEqual(kwargs["env"]["NO_PROXY"], "internal.example")
            self.assertNotIn("--no-optimize", cmd)
            self.assertEqual(original["ANTHROPIC_BASE_URL"], "https://custom.example/v1")

    def test_codex_per_process_override_and_auth_preserved(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(headroom.paths, "HOME", Path(tmp)), \
             mock.patch.object(headroom.paths, "ensure_home"), mock.patch.object(headroom, "status", return_value={"ready": True}), \
             mock.patch.object(headroom.subprocess, "Popen") as start, mock.patch.object(headroom, "_wait_ready"), \
             mock.patch.object(headroom, "_stop"):
            original = {"CODEX_API_KEY": "synthetic-only", "CODEX_CA_CERTIFICATE": "/test/codex-ca.pem",
                        "SSL_CERT_FILE": "/test/fallback-ca.pem"}
            with headroom.session("codex", original) as route:
                self.assertTrue(route.active)
                self.assertEqual(route.env["CODEX_API_KEY"], "synthetic-only")
                self.assertEqual(route.command_args, ["--config", "openai_base_url=" + json.dumps(route.base_url + "/v1")])
                self.assertEqual(start.call_args.kwargs["env"]["SSL_CERT_FILE"], "/test/codex-ca.pem")
                self.assertEqual(route.env["SSL_CERT_FILE"], "/test/fallback-ca.pem")

    def test_readiness_requires_owned_pid_native_core_and_optimization(self):
        process = mock.Mock(pid=13)
        process.poll.return_value = None
        health = {"service": "headroom-proxy", "version": headroom.VERSION, "ready": True,
                  "rust_core": "loaded", "config": {"pid": 13, "optimize": True}}
        for change in ({"config": {"pid": 12, "optimize": True}}, {"rust_core": "missing"},
                       {"config": {"pid": 13, "optimize": False}}, {"ready": False}):
            with mock.patch.object(headroom, "_read_health", return_value=dict(health, **change)), \
                 mock.patch.object(headroom.time, "monotonic", side_effect=[0, 0, 100]), \
                 mock.patch.object(headroom.time, "sleep"), self.assertRaises(ui.Abort):
                headroom._wait_ready(process, "http://127.0.0.1:1")
        with mock.patch.object(headroom, "_read_health", return_value=health):
            headroom._wait_ready(process, "http://127.0.0.1:1")

    def test_startup_failure_still_cleans_child(self):
        with mock.patch.object(headroom, "status", return_value={"ready": True}), \
             mock.patch.object(headroom.subprocess, "Popen") as start, \
             mock.patch.object(headroom, "_wait_ready", side_effect=ui.Abort("not ready")), \
             mock.patch.object(headroom, "_stop") as stop:
            with self.assertRaises(ui.Abort):
                with headroom.session("builtin", {}):
                    self.fail("must not enter")
            stop.assert_called_once_with(start.return_value)


class AgentRoutingGuardTests(unittest.TestCase):
    def spec(self, key):
        return dict(agents.DEFAULT_AGENTS[key], key=key)

    def test_claude_user_project_and_managed_routing_overrides_are_not_forced(self):
        for relative, data in (("user/.claude/settings.json", {"env": {"ANTHROPIC_BASE_URL": "https://private.example"}}),
                               ("project/.claude/settings.local.json", {"env": {"CLAUDE_CODE_USE_VERTEX": "1"}}),
                               ("managed/managed-settings.json", {"forceLoginGatewayUrl": "https://private.example"}),
                               ("managed/managed-settings.d/team.json", {"env": {"ANTHROPIC_CUSTOM_HEADERS": "Host: private.example"}})):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(data))
                actual_path = Path
                def path(value):
                    if value in ("/etc/claude-code", "/Library/Application Support/ClaudeCode"):
                        return root / "managed"
                    if value == "/Library/Managed Preferences":
                        return root / "managed-preferences"
                    return actual_path(value)
                with mock.patch.object(agents, "Path", side_effect=path) as path_class:
                    path_class.home.return_value = root / "user"
                    path_class.cwd.return_value = root / "project"
                    reason = agents.headroom_unsupported(self.spec("claude"), env={})
                self.assertIsNotNone(reason)
                self.assertNotIn("private.example", reason)

    def test_claude_malformed_remote_and_harmless_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            user = root / "user"
            user.mkdir()
            settings = user / "settings.json"
            with mock.patch.object(agents.Path, "cwd", return_value=root), \
                 mock.patch.object(agents.Path, "home", return_value=root):
                settings.write_text('{"permissions":{"deny":["Read(private)"]},"env":{"API_TIMEOUT_MS":"30000"}}')
                self.assertIsNone(agents.headroom_unsupported(self.spec("claude"), env={"CLAUDE_CONFIG_DIR": str(user)}))
                settings.write_text('{"env":')
                self.assertIn("parsed", agents.headroom_unsupported(self.spec("claude"), env={"CLAUDE_CONFIG_DIR": str(user)}))
                settings.write_text('{}')
                (user / "remote-settings.json").write_text('{}')
                self.assertIn("managed policy", agents.headroom_unsupported(self.spec("claude"), env={"CLAUDE_CONFIG_DIR": str(user)}))

    def test_codex_requires_explicit_exec_key_and_rejects_alternative_auth(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(agents.Path, "cwd", return_value=Path(tmp)), \
             mock.patch.object(agents.Path, "home", return_value=Path(tmp)):
            spec = self.spec("codex")
            self.assertIn("CODEX_API_KEY", agents.headroom_unsupported(spec, env={"OPENAI_API_KEY": "synthetic"}))
            self.assertIsNone(agents.headroom_unsupported(spec, env={"CODEX_API_KEY": "synthetic"}))
            self.assertIn("noninteractive", agents.headroom_unsupported(spec, interactive=True, env={"CODEX_API_KEY": "synthetic"}))
            for key in ("CODEX_ACCESS_TOKEN", "OPENAI_FEDERATION_RULE_ID", "OPENAI_IDENTITY_TOKEN_FILE"):
                self.assertIn("authentication", agents.headroom_unsupported(spec, env={"CODEX_API_KEY": "synthetic", key: "synthetic"}))


@unittest.skipUnless(os.environ.get("CLOUDSEED_HEADROOM_TEST_VENV"), "explicit isolated Headroom test dependency required")
class RealHeadroomLoopbackTests(unittest.TestCase):
    def test_real_proxy_preserves_auth_findings_and_compresses_without_paid_calls(self):
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append((self.path, dict(self.headers), data))
                body = ({"id": "msg_synthetic", "type": "message", "role": "assistant", "model": "claude-sonnet-4-20250514",
                         "content": [{"type": "text", "text": "Synthetic local response"}], "stop_reason": "end_turn",
                         "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 5}}
                        if self.path == "/v1/messages" else
                         {"id": "resp_synthetic", "object": "response", "status": "completed", "model": "gpt-4.1",
                         "output": [], "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}})
                if data.get("stream"):
                    if self.path == "/v1/messages":
                        events = [
                            ("message_start", {"type": "message_start", "message": dict(body, content=[], stop_reason=None)}),
                            ("content_block_start", {"type": "content_block_start", "index": 0,
                                                     "content_block": {"type": "text", "text": ""}}),
                            ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                     "delta": {"type": "text_delta", "text": "synthetic stream answer"}}),
                            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                               "usage": {"output_tokens": 5}}),
                            ("message_stop", {"type": "message_stop"}),
                        ]
                    else:
                        events = [
                            ("response.created", {"type": "response.created", "response": dict(body, status="in_progress")}),
                            ("response.output_text.delta", {"type": "response.output_text.delta", "output_index": 0,
                                                            "content_index": 0, "item_id": "msg_synthetic",
                                                            "delta": "synthetic stream answer"}),
                            ("response.completed", {"type": "response.completed", "response": body}),
                        ]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    for event, payload in events:
                        self.wfile.write(("event: " + event + "\ndata: " + json.dumps(payload) + "\n\n").encode())
                        self.wfile.flush()
                    return
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        upstream = f"http://127.0.0.1:{server.server_address[1]}"
        findings = [{"finding_id": f"unique-finding-{i:04d}", "status": "FAIL", "severity": "HIGH",
                     "region": "synthetic-region", "service": "synthetic-service",
                     "reason": "Required protection is disabled", "remediation": "Enable the required protection"}
                    for i in range(180)]
        evidence = json.dumps(findings, indent=2)
        log_evidence = "\n".join(["2026-01-01 00:00:00 INFO synthetic repeat"] * 60 +
                                  ["2026-01-01 00:01:00 ERROR unique-log-finding required protection missing"])
        try:
            with mock.patch.object(headroom, "VENV", Path(os.environ["CLOUDSEED_HEADROOM_TEST_VENV"])):
                for agent, stream in (("builtin", False), ("codex", False), ("builtin", True), ("codex", True)):
                    # Never copy os.environ here: upstream tests use synthetic auth only.
                    env = {"PATH": os.environ.get("PATH", ""), "CODEX_API_KEY": "synthetic-test-key"}
                    with headroom.session(agent, env, upstream_url=upstream) as route:
                        if agent == "builtin":
                            request_body = {"model": "claude-sonnet-4-20250514", "max_tokens": 32, "stream": stream,
                                "tools": [{"name": "run_cloudseed", "description": "Read evidence", "input_schema": {"type": "object"}}],
                                "messages": [{"role": "user", "content": "Review this saved scan"},
                                    {"role": "assistant", "content": [
                                        {"type": "tool_use", "id": "tool_test", "name": "run_cloudseed", "input": {}},
                                        {"type": "tool_use", "id": "tool_logs", "name": "run_cloudseed", "input": {}}]},
                                    {"role": "user", "content": [
                                        {"type": "tool_result", "tool_use_id": "tool_test", "content": evidence},
                                        {"type": "tool_result", "tool_use_id": "tool_logs", "content": log_evidence}]}]}
                            endpoint, headers = "/v1/messages", {"x-api-key": "synthetic-test-key", "anthropic-version": "2023-06-01"}
                        else:
                            request_body = {"model": "gpt-4.1", "stream": stream, "input": [
                                {"role": "user", "content": "Review this saved scan"},
                                {"type": "function_call", "call_id": "tool_test", "name": "run_cloudseed", "arguments": "{}"},
                                {"type": "function_call_output", "call_id": "tool_test", "output": evidence},
                                {"type": "function_call", "call_id": "tool_logs", "name": "run_cloudseed", "arguments": "{}"},
                                {"type": "function_call_output", "call_id": "tool_logs", "output": log_evidence}]}
                            endpoint, headers = "/v1/responses", {"Authorization": "Bearer synthetic-test-key"}
                        headers["Content-Type"] = "application/json"
                        request = urllib.request.Request(route.base_url + endpoint, data=json.dumps(request_body).encode(), headers=headers)
                        with urllib.request.urlopen(request, timeout=90) as response:
                            self.assertEqual(response.status, 200)
                            result = response.read().decode()
                            self.assertIn("synthetic", result)
                            if stream:
                                self.assertIn("text/event-stream", response.headers["Content-Type"])
                                self.assertIn("synthetic stream answer", result)
                                self.assertIn("event: message_stop" if agent == "builtin" else "event: response.completed", result)
                    path, forwarded_headers, forwarded_body = requests[-1]
                    self.assertEqual(path, endpoint)
                    lowered_headers = {k.lower(): v for k, v in forwarded_headers.items()}
                    self.assertEqual(lowered_headers["x-api-key" if agent == "builtin" else "authorization"],
                                     "synthetic-test-key" if agent == "builtin" else "Bearer synthetic-test-key")
                    forwarded = json.dumps(forwarded_body)
                    for item in findings:
                        self.assertIn(item["finding_id"], forwarded)
                    self.assertIn("Required protection is disabled", forwarded)
                    self.assertIn("Enable the required protection", forwarded)
                    self.assertIn("unique-log-finding", forwarded)
                    self.assertIn("repeated 60 times", forwarded)
                    self.assertLess(len(forwarded), len(json.dumps(request_body)), "real proxy must actually compact eligible content")
                    self.assertNotIn("<<ccr:", forwarded)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
