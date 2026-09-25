"""Wave-2 regression tests for the agentic group: kubeadm certificate-key redaction, signal-safe built-in agent runs
with streamed child output, the venv-agent usability check, atomic vault writes and the headliner cheat sheet."""

import contextlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import agents, builtin_agent, creds, headliner, paths, secrets, ui  # noqa: E402
from cloudseed import platform as platformmod  # noqa: E402

R = secrets.REDACTED
CERT_KEY = "f5d5e2d3a1b2c3d4" * 4          # 64 hex characters, the shape of a kubeadm certificate key


# ------------------------------------------------------------------------------------------------ redaction

class CertificateKeyRedactionTests(unittest.TestCase):
    def test_kubeadm_certificate_key_forms_are_redacted(self):
        cases = [
            f"kubeadm join 10.0.0.1:6443 --token abcdef.0123456789abcdef --control-plane --certificate-key {CERT_KEY}",
            f"kubeadm join --certificate-key={CERT_KEY}",
            f'"cmd": ["kubeadm", "join", "--certificate-key", "{CERT_KEY}"]',      # Ansible's JSON argv
            f"[upload-certs] Using certificate key:\n{CERT_KEY}",                  # multi-line text
            f'"stdout": "[upload-certs] Using certificate key:\\n{CERT_KEY}"',      # the same inside Ansible's JSON
            f"certificate_key: {CERT_KEY}",
            f'{{"k8s_certificate_key": "{CERT_KEY}"}}',
            f"K8S_CERT_KEY={CERT_KEY}",
        ]
        for text in cases:
            out = secrets.redact(text)
            self.assertNotIn(CERT_KEY, out, text)
            self.assertIn(R, out, text)
        # the flag itself stays readable
        self.assertIn("--certificate-key", secrets.redact(cases[0]))
        self.assertIn("Using certificate key:", secrets.redact(cases[3]))

    def test_public_hashes_and_key_paths_are_left_alone(self):
        for text in ("--discovery-token-ca-cert-hash sha256:" + "ab" * 32,
                     "image@sha256:" + "cd" * 32,
                     "--certificate-key-file /etc/kubernetes/cert.key",
                     "certificate_key_path: /etc/kubernetes/pki/x.key",
                     "commit " + "0123456789abcdef" * 4):
            self.assertEqual(secrets.redact(text), text)

    def test_stream_redactor_hides_the_key_on_the_line_after_the_intro(self):
        red = secrets.StreamRedactor()
        out = [red.feed(x) for x in ("[upload-certs] Using certificate key:\n", CERT_KEY + "\n", "next line\n")]
        self.assertEqual(out, ["[upload-certs] Using certificate key:\n", R + "\n", "next line\n"])
        # only the line right after the intro: an unrelated hex line elsewhere is not touched
        red = secrets.StreamRedactor()
        self.assertEqual(red.feed(CERT_KEY + "\n"), CERT_KEY + "\n")
        # the key may be followed by more text on its line (quoted in an error message)
        red = secrets.StreamRedactor()
        red.feed("No help for 'Using certificate key:\n")
        self.assertEqual(red.feed(CERT_KEY + "'. password=hunter2hunter2\n"), R + "'. password=" + R + "\n")

    def test_secret_env_names_cover_certificate_keys(self):
        for name in ("K8S_CERT_KEY", "KUBEADM_CERTIFICATE_KEY"):
            self.assertTrue(secrets.is_secret_env(name), name)
        for name in ("SSL_CERT_FILE", "CERT_DIR"):
            self.assertFalse(secrets.is_secret_env(name), name)

    def test_secrets_named_on_another_line_are_redacted(self):
        # mcp#14: `helm get values` of charts that take {value: ...} (the password stayed visible before)
        text = "auth:\n  rootPassword:\n    value: N3xusS3cretPw  # set by cloudseed\n  rootUser: admin\nother:\n  value: visible1\n"
        out = secrets.redact(text)
        self.assertNotIn("N3xusS3cretPw", out)
        self.assertIn("value: %s  # set by cloudseed" % R, out)
        self.assertIn("rootUser: admin", out)
        self.assertIn("value: visible1", out)                    # a `value` outside a secret-named mapping
        # env name/value pairs (`kubectl get pod -o yaml` is read-only, so it needs no approval)
        pod = ("      env:\n      - name: DB_PASSWORD\n        value: \"hunter 2 with spaces\"\n      - name: LOG_LEVEL\n"
               "        value: debug\n      - name: API_TOKEN\n        valueFrom:\n          secretKeyRef:\n"
               "            name: t\n            key: token\n      - name: REGION\n        value: us-east-1\n")
        out = secrets.redact(pod)
        self.assertNotIn("hunter", out)
        self.assertIn('value: "%s"' % R, out)
        for kept in ("value: debug", "value: us-east-1", "name: t", "key: token"):
            self.assertIn(kept, out)
        js = '[\n  {\n    "name": "SLACK_WEBHOOK_URL",\n    "value": "https://example.com/hook/abc"\n  },\n  {\n    "name": "MODE",\n    "value": "prod"\n  }\n]\n'
        out = secrets.redact(js)
        self.assertNotIn("hook/abc", out)
        self.assertIn('"value": "prod"', out)

    def test_kubernetes_secret_data_blocks(self):
        yaml_secret = ("apiVersion: v1\ndata:\n  api-endpoint: aHR0cHM6Ly9leGFtcGxlLmNvbQ==\n  flag: dHJ1ZQ==\n"
                       "kind: Secret\nmetadata:\n  name: s1\n")
        out = secrets.redact(yaml_secret)
        self.assertNotIn("aHR0cHM6", out)
        self.assertNotIn("dHJ1ZQ", out)
        self.assertIn("name: s1", out)
        json_secret = '{\n    "data": {\n        "conn": "cG9zdGdyZXM6Ly94",\n        "user": "YWRtaW4="\n    },\n    "kind": "Secret"\n}\n'
        out = secrets.redact(json_secret)
        self.assertNotIn("cG9zdGdy", out)
        self.assertNotIn("YWRtaW4", out)
        self.assertIn('"kind": "Secret"', out)
        string_data = "stringData:\n  conn: postgres-host\n  cfg: |\n    user=a\n    pass=b\n  after: z z\nkind: Secret\n"
        out = secrets.redact(string_data)
        for leaked in ("postgres-host", "user=a", "pass=b", "z z"):
            self.assertNotIn(leaked, out)
        self.assertIn("kind: Secret", out)
        # a ConfigMap's plain values and files are left readable
        cm = "apiVersion: v1\ndata:\n  LOG_LEVEL: info\n  DB: database\n  config.yaml: |\n    a: 1\nkind: ConfigMap\n"
        self.assertEqual(secrets.redact(cm), cm)

    def test_structured_redaction_streams_line_by_line(self):
        pod = "- name: DB_PASSWORD\n  value: hunter2hunter2\n- name: X\n  value: y\n"
        red = secrets.StreamRedactor()
        self.assertEqual("".join(red.feed(ln) for ln in pod.splitlines(True)),
                         "- name: DB_PASSWORD\n  value: %s\n- name: X\n  value: y\n" % R)
        red = secrets.RedactingWriter(io.StringIO())
        red.write("rootPassword:\n")
        red.write("  value: S3cr3tValue9\n")
        red.flush()
        self.assertNotIn("S3cr3tValue9", red._stream.getvalue())
        # Terraform plans and ordinary logs are untouched
        plan = '  + resource "aws_db_instance" "x" {\n      + password = (sensitive value)\n      + name     = "db"\n    }\n'
        self.assertEqual(secrets.redact(plan), plan)
        self.assertEqual(secrets.redact(plan, kv=False), plan)

    def test_earlier_handoffs_still_hold(self):
        # webui-backend#9 / agentic#8: JSON-quoted keys; platform-logic#22: passcode / passphrase / access keys
        self.assertEqual(secrets.redact('{"grafana_password": "' + 'Px3hWvc18IPGajg0U-8nvrhL"}'), '{"grafana_password": "%s"}' % R)
        self.assertNotIn("Abc123XYZ", secrets.redact("--set monitoringPasscode=Abc123XYZ_def456ghi789"))
        self.assertNotIn("s3cr3tphrase", secrets.redact("ssh_passphrase: s3cr3tphrase"))
        self.assertNotIn("zzzzAccessKey", secrets.redact('"storage_access_key": "zzzzAccessKey"'))


# ------------------------------------------------------------------------------------------------ signals

@unittest.skipIf(os.name != "posix", "POSIX signals")
class ExitOnSignalsTests(unittest.TestCase):
    def setUp(self):
        if signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
            self.skipTest("the test runner has its own SIGTERM handler")

    def tearDown(self):
        secrets.close_all_sessions()
        secrets.set_strict(False)
        secrets._REGISTERED.clear()

    def test_sigterm_becomes_systemexit_inside_the_block_only(self):
        with self.assertRaises(SystemExit) as cm:
            with secrets.exit_on_signals():
                self.assertIsNot(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(2)   # the handler raises before this ends
        self.assertEqual(cm.exception.code, 128 + signal.SIGTERM)
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        self.assertIs(signal.getsignal(signal.SIGHUP), signal.SIG_DFL)

    def test_handlers_stay_while_a_session_or_another_block_needs_them(self):
        with secrets.exit_on_signals():
            sid, _env = secrets.open_session()
            with secrets.exit_on_signals():
                pass
            self.assertIsNot(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)   # the outer block is still open
            secrets.close_session(sid)
            self.assertIsNot(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)   # ... even with no session left
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        sid, _env = secrets.open_session()
        with secrets.exit_on_signals():
            pass
        self.assertIsNot(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)       # the session still needs them
        secrets.close_session(sid)
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)

    def test_stale_session_files_are_swept_by_owner_pid(self):
        secrets.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        dead = subprocess.Popen([sys.executable, "-c", "0"])
        dead.wait()
        stale = secrets.SESSIONS_DIR / "00000000000000aa.json"
        live = secrets.SESSIONS_DIR / "00000000000000bb.json"
        stale.write_text(json.dumps({"pid": dead.pid, "env": {"X_TOKEN": "x" * 12}}))
        live.write_text(json.dumps({"pid": os.getpid(), "env": {"X_TOKEN": "y" * 12}}))
        try:
            sid, _env = secrets.open_session()
            secrets.close_session(sid)
            self.assertFalse(stale.exists())
            self.assertTrue(live.exists())
        finally:
            for f in (stale, live):
                f.unlink(missing_ok=True)


# ------------------------------------------------------------------------------------------------ built-in agent child runs

def _py(code: str) -> list:
    return [sys.executable, "-c", code]


class RunChildTests(unittest.TestCase):
    def _run(self, cmd, env=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc, out = builtin_agent._run_child(cmd, dict(os.environ, **(env or {})))
        return rc, out, buf.getvalue()

    def test_output_is_streamed_redacted_and_returned(self):
        code = ("import sys, time\n"
                "print('step one', flush=True)\n"
                "sys.stderr.write('warn password=hunter2hunter2\\n'); sys.stderr.flush()\n"
                "print('stdin says', repr(sys.stdin.read()))\n"
                "print('-----BEGIN " "OPENSSH PRIVATE KEY-----'); print('b3BlbnNzaC1rZXktdjEAAAA'); "
                "print('-----END OPENSSH PRIVATE KEY-----')\n"
                "sys.exit(3)\n")
        rc, out, shown = self._run(_py(code))
        self.assertEqual(rc, 3)
        for text in (out, shown):
            self.assertIn("step one", text)
            self.assertIn("warn password=" + R, text)          # stderr is merged, in order
            self.assertIn("stdin says ''", text)                # stdin is closed: nothing can prompt
            self.assertNotIn("hunter2hunter2", text)
            self.assertNotIn("b3BlbnNzaC1rZXktdjEAAAA", text)   # multi-line keys too
        self.assertLess(out.index("step one"), out.index("warn password"))
        self.assertIn("    step one", shown)                    # shown indented while it runs

    def test_long_output_keeps_head_and_tail_only(self):
        code = "for i in range(20000): print('line %05d' % i)"
        rc, out, _ = self._run(_py(code))
        self.assertEqual(rc, 0)
        self.assertIn("...[truncated]...", out)
        self.assertIn("line 00000", out)
        self.assertIn("line 19999", out)
        self.assertLessEqual(len(out), builtin_agent.MAX_OUTPUT + 40)

    def test_capture_bounds(self):
        cap = builtin_agent._Capture(20)
        cap.add("short\n")
        self.assertEqual(cap.text(), "short\n")
        cap = builtin_agent._Capture(20)
        for i in range(1000):
            cap.add(f"{i:04d}\n")
        self.assertLessEqual(len(cap.tail), 3)                  # memory stays bounded
        text = cap.text()
        self.assertTrue(text.startswith("0000\n0001\n"))
        self.assertTrue(text.endswith("0998\n0999\n"))
        self.assertIn("[truncated]", text)
        cap = builtin_agent._Capture(20)
        cap.add("x" * 50)                                       # one long line
        self.assertEqual(cap.text(), "x" * 10 + "\n...[truncated]...\n" + "x" * 10)

    def test_background_process_holding_the_pipe_does_not_hang_the_agent(self):
        code = ("import subprocess, sys\n"
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(4)'])\n"
                "print('started', flush=True)\n")
        t0 = time.time()
        with mock.patch.object(builtin_agent, "DRAIN_SECONDS", 0.5):
            rc, out, _ = self._run(_py(code))
        self.assertEqual(rc, 0)
        self.assertIn("started", out)
        self.assertLess(time.time() - t0, 3.5)                 # did not wait for the left-behind process

    @unittest.skipIf(os.name != "posix", "POSIX signals")
    def test_sigterm_stops_the_running_command(self):
        if signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
            self.skipTest("the test runner has its own SIGTERM handler")
        started = []
        real = subprocess.Popen

        def spy(*a, **kw):
            p = real(*a, **kw)
            started.append(p)
            return p

        timer = threading.Timer(0.5, os.kill, (os.getpid(), signal.SIGTERM))
        t0 = time.time()
        with mock.patch.object(builtin_agent.subprocess, "Popen", side_effect=spy):
            with self.assertRaises(SystemExit):
                with secrets.exit_on_signals():
                    timer.start()
                    self._run(_py("import time; print('working', flush=True); time.sleep(60)"))
        timer.cancel()
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].poll())                 # the command did not outlive the agent
        self.assertLess(time.time() - t0, 30)

    @unittest.skipIf(os.name != "posix", "POSIX signals")
    def test_ctrl_c_lets_the_command_finish_stopping_on_its_own(self):
        if signal.getsignal(signal.SIGINT) is not signal.default_int_handler:
            self.skipTest("the test runner has its own SIGINT handler")
        started = []
        real = subprocess.Popen

        def spy(*a, **kw):
            p = real(*a, **kw)
            started.append(p)
            return p

        timer = threading.Timer(0.3, os.kill, (os.getpid(), signal.SIGINT))
        with mock.patch.object(builtin_agent.subprocess, "Popen", side_effect=spy):
            with self.assertRaises(KeyboardInterrupt):
                timer.start()
                self._run(_py("import time; time.sleep(1.5); print('cleaned up')"))
        timer.cancel()
        self.assertEqual(started[0].returncode, 0)             # waited for it instead of killing it


class _FakeAnthropic(types.ModuleType):
    """Stand-in for the SDK: replays scripted tool calls through the real run_cloudseed tool."""

    def __init__(self, calls, results):
        super().__init__("anthropic")
        for n in ("AuthenticationError", "RateLimitError", "APIStatusError", "APIConnectionError"):
            setattr(self, n, type(n, (Exception,), {"status_code": 500}))
        self.beta_tool = lambda fn: fn

        class _Msg:
            content, stop_reason = [], "end_turn"

        class _Messages:
            def tool_runner(self, **kw):
                for c in calls:
                    results.append((c, kw["tools"][0](c)))
                    yield _Msg()

        class Anthropic:
            def __init__(self):
                self.beta = types.SimpleNamespace(messages=_Messages())

        self.Anthropic = Anthropic


class BuiltinAgentWave2Tests(unittest.TestCase):
    def tearDown(self):
        secrets.set_strict(False)
        secrets._REGISTERED.clear()

    def test_real_child_command_runs_with_minus_y_first_and_streams(self):
        results = []
        env = {k: v for k, v in os.environ.items() if k != "CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE"}
        env["ANTHROPIC_API_KEY"] = "sk-ant-" + "test-000000000000000000000"
        buf = io.StringIO()
        with mock.patch.dict(sys.modules, {"anthropic": _FakeAnthropic(["cloudseed explain undo", "list -y"], results)}), \
                mock.patch.dict(os.environ, env, clear=True), mock.patch.object(ui, "interactive", return_value=False), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = builtin_agent.run("prompt", "claude-sonnet-5", "task")
        self.assertEqual(rc, 0)
        self.assertTrue(results[0][1].startswith("exit code: 0\n"), results[0][1][:300])
        self.assertIn("undo.json", results[0][1])
        self.assertTrue(results[1][1].startswith("exit code: 0\n"), results[1][1][:300])
        self.assertIn("⚙ cloudseed explain undo", buf.getvalue())
        self.assertIn("    ", buf.getvalue())                    # the command's own lines were shown as they came

    def test_node_scale_needs_approval(self):
        self.assertTrue(builtin_agent.is_destructive(["node", "scale", "aws", "--env", "dev", "--count", "3", "--auto-approve"]))
        # without --auto-approve it only previews (exit 3): the approval comes with the --auto-approve call
        self.assertFalse(builtin_agent.is_destructive(["node", "scale", "aws", "--env", "dev", "--count", "3"]))
        self.assertFalse(builtin_agent.is_destructive(["node", "list", "aws", "--env", "dev"]))

    def test_leading_yes_cannot_smuggle_a_human_only_command(self):
        for argv in (["-y", "use", "codex"], ["--yes", "creds", "set", "X=y"], ["-y", "-y", "mcp", "token"]):
            self.assertIsNotNone(builtin_agent.guard(argv), argv)
        ns, final = builtin_agent._parse(["status", "aws", "--env", "dev", "-y"])
        self.assertEqual(final, ["-y", "status", "aws", "--env", "dev"])


# ------------------------------------------------------------------------------------------------ venv-agent

class VenvAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-venv-agent-"))
        self.venv = self.tmp / "venv-agent"
        self.patch = mock.patch.object(builtin_agent, "VENV", self.venv)
        self.patch.start()
        self.path_before = list(sys.path)
        self.mods = mock.patch.dict(sys.modules)
        self.mods.start()
        sys.modules.pop("anthropic", None)

    def tearDown(self):
        self.mods.stop()
        sys.path[:] = self.path_before
        self.patch.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_venv(self, version: str, marker: str) -> Path:
        sp = self.venv / "lib" / f"python{'.'.join(version.split('.')[:2])}" / "site-packages"
        (sp / "anthropic").mkdir(parents=True)
        (sp / "anthropic" / "__init__.py").write_text(f"MARK = {marker!r}\n")
        (self.venv / "bin").mkdir(parents=True, exist_ok=True)
        (self.venv / "pyvenv.cfg").write_text(f"home = /nowhere\ninclude-system-site-packages = false\nversion = {version}\n")
        return sp

    def _fake_run(self, calls):
        cur = "%d.%d.0" % sys.version_info[:2]

        def run(cmd, **kw):
            calls.append([str(c) for c in cmd])
            if cmd[1:3] == ["-m", "venv"]:
                self.assertFalse(self.venv.exists(), "the unusable venv is removed before it is rebuilt")
                sp = self.venv / "lib" / ("python%d.%d" % sys.version_info[:2]) / "site-packages"
                sp.mkdir(parents=True)
                (self.venv / "pyvenv.cfg").write_text(f"version = {cur}\n")
            elif "pip" in cmd:
                sp = builtin_agent._venv_site_packages()
                (sp / "anthropic").mkdir()
                (sp / "anthropic" / "__init__.py").write_text("MARK = 'rebuilt'\n")
            return subprocess.CompletedProcess(cmd, 0)
        return run

    def test_venv_from_another_python_is_rebuilt(self):
        self._make_venv("2.7.18", "old")
        calls = []
        out = io.StringIO()
        with mock.patch.object(builtin_agent.subprocess, "run", side_effect=self._fake_run(calls)), \
                mock.patch.object(paths, "IS_BUNDLE", False), contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            self.assertFalse(builtin_agent._venv_matches())
            builtin_agent.ensure_sdk()
        import anthropic
        self.assertEqual(anthropic.MARK, "rebuilt")
        self.assertIn("built by Python 2.7", out.getvalue())
        self.assertEqual(calls[0][:3], [sys.executable, "-m", "venv"])
        self.assertEqual(calls[1][1:4], ["-m", "pip", "install"])
        self.assertFalse(any("python2.7" in p for p in sys.path))

    def test_venv_whose_interpreter_does_not_run_here_is_rebuilt(self):
        self._make_venv("%d.%d.1" % sys.version_info[:2], "foreign")
        calls = []
        with mock.patch.object(builtin_agent.subprocess, "run", side_effect=self._fake_run(calls)), \
                mock.patch("cloudseed.deps.venv_usable", return_value=False) as usable, \
                mock.patch.object(paths, "IS_BUNDLE", False), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            builtin_agent.ensure_sdk()
        usable.assert_called_once_with(self.venv)
        import anthropic
        self.assertEqual(anthropic.MARK, "rebuilt")
        self.assertEqual(len(calls), 2)

    def test_matching_venv_is_used_without_reinstalling(self):
        sp = self._make_venv("%d.%d.4" % sys.version_info[:2], "current")
        with mock.patch.object(builtin_agent.subprocess, "run") as run, \
                mock.patch("cloudseed.deps.venv_usable", return_value=True):
            builtin_agent.ensure_sdk()
        run.assert_not_called()
        import anthropic
        self.assertEqual(anthropic.MARK, "current")
        self.assertEqual(sys.path[0], str(sp))

    def test_no_auto_install_and_bundle_refuse_cleanly(self):
        self._make_venv("2.7.18", "old")
        with self.assertRaises(ui.Abort):
            builtin_agent.ensure_sdk(auto=False)
        with mock.patch.object(paths, "IS_BUNDLE", True), self.assertRaises(ui.Abort):
            builtin_agent.ensure_sdk()
        self.assertTrue((self.venv / "pyvenv.cfg").exists())      # nothing was deleted

    def test_failed_install_is_an_abort_not_a_traceback(self):
        def run(cmd, **kw):
            if cmd[1:3] == ["-m", "venv"]:
                return subprocess.CompletedProcess(cmd, 1)
            raise AssertionError("pip must not run after a failed venv")
        with mock.patch.object(builtin_agent.subprocess, "run", side_effect=run), \
                mock.patch.object(paths, "IS_BUNDLE", False), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(ui.Abort) as cm:
                builtin_agent.ensure_sdk()
        self.assertIn(str(self.venv), str(cm.exception))


# ------------------------------------------------------------------------------------------------ vault writes

class AtomicVaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-vault-"))
        self.store = self.tmp / "credentials.json"
        self.gcp = self.tmp / "gcp-credentials.json"
        self.patches = [mock.patch.object(creds, "STORE", self.store), mock.patch.object(creds, "GCP_FILE", self.gcp)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_is_atomic_and_private(self):
        creds.set_("MY_TOKEN", "first-value-123")
        self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), 0o600)
        with mock.patch("os.fsync", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                creds.set_("MY_TOKEN", "second-value-456")
        self.assertEqual(creds.load(), {"MY_TOKEN": "first-value-123"})   # the old vault survives the failed write
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["credentials.json"])   # no temp file left

    def test_symlinked_vault_is_written_through_the_link(self):
        real = self.tmp / "elsewhere" / "vault.json"
        real.parent.mkdir()
        real.write_text("{}")
        self.store.symlink_to(real)
        creds.set_("MY_TOKEN", "linked-value-123")
        self.assertTrue(self.store.is_symlink())
        self.assertEqual(json.loads(real.read_text()), {"MY_TOKEN": "linked-value-123"})

    def test_gcp_key_file_is_rewritten_only_on_change_and_atomically(self):
        key = json.dumps({"type": "service_account", "private_key": "x"})
        creds.save({"GOOGLE_CREDENTIALS": key})
        env = creds.env()
        self.assertEqual(env["GOOGLE_APPLICATION_CREDENTIALS"], str(self.gcp))
        self.assertEqual(self.gcp.read_text(), key)
        self.assertEqual(stat.S_IMODE(self.gcp.stat().st_mode), 0o600)
        ino = self.gcp.stat().st_ino
        os.chmod(self.gcp, 0o644)
        creds.env()
        self.assertEqual(self.gcp.stat().st_ino, ino)                       # unchanged: not rewritten
        self.assertEqual(stat.S_IMODE(self.gcp.stat().st_mode), 0o600)       # but the mode is fixed
        key2 = json.dumps({"type": "service_account", "private_key": "y"})
        creds.save({"GOOGLE_CREDENTIALS": key2})
        creds.env()
        self.assertEqual(self.gcp.read_text(), key2)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["credentials.json", "gcp-credentials.json"])


# ------------------------------------------------------------------------------------------------ headliner / deny list

class HeadlinerWave2Tests(unittest.TestCase):
    def test_cheatsheet_lists_every_platform_group_and_current_commands(self):
        groups_line = next(ln for ln in headliner.CHEATSHEET.splitlines() if "# groups:" in ln)
        self.assertEqual(groups_line.split("# groups:")[1].split(), list(platformmod.GROUPS))
        for text in ("setup <aws|gcp|azure|vmware>", "node add|list|remove|scale", "platform ui", "undo", "creds",
                     "finops", "dr status", "chaos", "scan", "explain"):
            self.assertIn(text, headliner.CHEATSHEET)
        self.assertIn("resilience chaos", headliner.build("x", {}))


class ClaudeDenyListTests(unittest.TestCase):
    def test_vault_and_undo_copies_are_denied(self):
        home = os.path.abspath(paths.HOME).replace("\\", "/")
        rules = agents.claude_deny_rules()
        for part in ("credentials.json", "gcp-credentials.json", "undo.json", "undo/**"):
            self.assertIn(f"Read(/{home}/{part})", rules, part)


if __name__ == "__main__":
    unittest.main()
