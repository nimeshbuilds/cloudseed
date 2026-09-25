"""Wave-4 regression tests for the agentic group: the built-in agent follows the one human-only policy every agent
session shares (cli.human_only_reason, plus ssh/k9s), the vault's value checks (GCP project ids, JSON keys) and its
wider name denylist, masked hints without a 'stored' prefix, the session broker's SIGTERM window, skills.state_text,
Claude Code billing notes for a shell key and the brief-less prompt of agents that get the skills in their prompt."""

import contextlib
import io
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import agents, builtin_agent, cli, creds, headliner, secrets, skills, ui  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _parse_cli(*argv):
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        return cli.build_parser().parse_args(cli.normalize_argv(list(argv)))


class _TmpHome(unittest.TestCase):
    """A throw-away HOME and vault (and a clean Anthropic/Grok environment) for each test."""

    def setUp(self):
        self.addCleanup(secrets.set_strict, False)
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4-agentic-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "GROK_", "CLAUDE_CODE_"))}
        env["HOME"] = str(self.tmp)
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        for target, value in ((creds, {"STORE": self.tmp / "credentials.json", "GCP_FILE": self.tmp / "gcp.json"}),):
            for name, v in value.items():
                q = mock.patch.object(target, name, v)
                q.start()
                self.addCleanup(q.stop)
        agents._CLAUDE_AUTH_CACHE.clear()
        self.addCleanup(agents._CLAUDE_AUTH_CACHE.clear)


# ------------------------------------------------------------------------------------------------ one human-only policy

class BuiltinHumanOnlyPolicyTests(unittest.TestCase):
    # (the lists of test_wave3_cli_tools.HumanOnlyPolicyTest: what the CLI gate refuses and allows in agent sessions)
    CLI_REFUSED = [
        ("creds", "set", "ANTHROPIC_BASE_URL=https://evil.example"), ("creds", "unset", "X"), ("creds", "clear", "--forget"),
        ("use", "codex"), ("use",), ("model", "claude-opus-4-1"), ("model", "--forget", "x"), ("enable", "agentic"),
        ("disable", "headliner"), ("ui",), ("ui", "start"), ("ui", "stop"), ("ui", "serve"), ("ui", "token"),
        ("ui", "token", "--rotate"), ("mcp", "connect", "cursor"), ("mcp", "start"), ("mcp", "token"), ("mcp", "uninstall"),
        ("setup", "mcp"), ("destroy", "mcp"), ("install", "terraform"), ("install", "skills"), ("skill", "install"),
        ("deps", "install", "terraform"), ("deps", "image"), ("deps", "bundle"), ("deps", "runtime", "local"),
        ("agentic", "list", "envs"), ("do", "hi"),
    ]
    CLI_ALLOWED = [
        ("creds",), ("creds", "list"), ("model",), ("model", "--agent", "codex"), ("use", "list"), ("ui", "status"),
        ("ui", "logs"), ("mcp",), ("mcp", "status"), ("status", "mcp"), ("mcp", "guide"), ("mcp", "tools"),
        ("mcp", "config"), ("mcp", "test"), ("mcp", "logs"), ("deps", "status"), ("skill", "list"),
        ("skill", "show", "aws"), ("install",), ("install", "list"), ("list",), ("status", "aws", "--env", "dev"),
        ("undo", "--list"), ("help", "creds"), ("explain", "mcp"), ("doctor",),
    ]

    def test_the_built_in_agent_refuses_exactly_what_the_cli_gate_refuses(self):
        for argv in self.CLI_REFUSED:
            with self.subTest(argv=argv):
                self.assertIsNotNone(cli.human_only_reason(_parse_cli(*argv)))       # (the lists are the CLI's)
                self.assertIsNotNone(builtin_agent.guard(list(argv)))
                self.assertIsNotNone(builtin_agent.guard(["-y"] + list(argv)))
        for argv in self.CLI_ALLOWED:
            with self.subTest(argv=argv):
                self.assertIsNone(cli.human_only_reason(_parse_cli(*argv)))
                self.assertIsNone(builtin_agent.guard(list(argv)))
                self.assertFalse(builtin_agent.is_destructive(list(argv)))           # read-only: no approval either

    def test_terminal_commands_and_the_mcp_server_stay_refused(self):
        for argv in (["ssh", "aws", "--env", "dev"], ["-y", "ssh", "aws", "--", "id"], ["k9s"], ["k9s", "aws"]):
            with self.subTest(argv=argv):
                self.assertIn("terminal", builtin_agent.guard(argv))
                self.assertIsNone(cli.human_only_reason(_parse_cli(*[a for a in argv if a != "-y"])))  # fine elsewhere
        for argv in (["mcp", "serve"], ["mcp", "serve", "--http"]):
            self.assertIn("mcp status", builtin_agent.guard(argv))

    def test_status_mcp_runs_as_the_mcp_command(self):
        ns, final = builtin_agent._parse(["status", "mcp"])
        self.assertEqual((ns.cmd, ns.mcp_cmd), ("mcp", "status"))
        self.assertEqual(final, ["-y", "mcp", "status"])
        self.assertIn("human-only", builtin_agent.guard(["setup", "mcp"]))

    def test_the_refusal_names_the_command_without_a_value(self):
        for argv, shown in ((["creds", "set", "MY_SECRET=hunter2hunter2"], "`cloudseed creds set MY_SECRET`"),
                            (["creds", "set", "MY_SECRET", "hunter2hunter2"], "`cloudseed creds set MY_SECRET`"),
                            (["-y", "creds", "set", "'p@ss word!'"], "`cloudseed creds set`"),
                            (["mcp", "token", "--rotate"], "`cloudseed mcp token --rotate`"),
                            (["use", "codex"], "`cloudseed use codex`")):
            with self.subTest(argv=argv):
                msg = builtin_agent.guard(argv)
                self.assertIn(shown, msg)
                self.assertNotIn("hunter2", msg)
                self.assertNotIn("p@ss", msg)
                self.assertNotIn(" -y", msg)
        self.assertIn("credential vault", builtin_agent.guard(["creds", "unset", "X"]))   # the CLI's own reason

    def test_unknown_commands_list_what_the_agent_can_use(self):
        msg = builtin_agent.guard(["frobnicate"])
        self.assertIn("unknown command", msg)
        listed = msg.split("Commands: ", 1)[1].split(", ")
        self.assertIn("creds", listed)                 # (its list form works)
        for never in ("agentic", "do", "enable", "disable", "ssh", "k9s"):
            self.assertNotIn(never, listed)

    def test_system_prompt_names_the_refused_forms_and_the_read_only_ones(self):
        sp = builtin_agent.system_prompt("list my environments")
        for part in ("creds set|unset|clear", "ssh, k9s", "Their read-only forms work", "mcp status|guide|tools",
                     "deps status", "skill list|show", "use list"):
            self.assertIn(part, sp)
        for cmd, forms in cli._AGENT_READ_FORMS.items():   # every read form the CLI allows is named (serve aside)
            for form in forms:
                if (cmd, form) == ("mcp", "serve"):
                    continue
                self.assertRegex(builtin_agent._HUMAN_ONLY_TEXT, r"%s[^,.]*\b%s\b" % (cmd, form), (cmd, form))

    def test_helm_status_reason_names_live_secrets(self):
        ns, _ = builtin_agent._parse(shlex.split("helm status x -o json"))
        self.assertIn("live Secrets", builtin_agent._approval_reason(ns))
        for args in ("helm status x --output=yaml", "helm status x -o", "helm status x -o table -o json",
                     "helm -n mon status x -ojson"):
            self.assertTrue(builtin_agent.is_destructive(shlex.split(args)), args)
        for args in ("helm status x", "helm status x -o table", "helm history x -o json", "helm get metadata x -o json"):
            self.assertFalse(builtin_agent.is_destructive(shlex.split(args)), args)


# ------------------------------------------------------------------------------------------------ vault

class VaultValueTests(_TmpHome):
    def test_custom_group_has_a_title(self):
        self.assertEqual(creds.GROUPS["custom"], "Custom variables")
        self.assertIn("Claude Code", creds.KNOWN["ANTHROPIC_API_KEY"][1])

    def test_gcp_project_variables_must_hold_a_project_id(self):
        from cloudseed.clouds import gcp
        q = next(q for q in gcp.GCP().questions if q.key == "project_id")
        self.assertEqual(set(creds.GCP_PROJECT_KEYS), set(q.env))           # the variables setup reads
        for key in creds.GCP_PROJECT_KEYS:
            for bad in ("My_Project", "proj", "1abcdef", "my-proj-", "my proj 123"):
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError) as cm:
                    creds.check_value(key.lower(), bad)
                self.assertIn("not a GCP project ID", str(cm.exception))
            for good in ("my-proj-123", "google.com:my-proj", "  my-proj-123  ", ""):
                self.assertEqual(creds.check_value(key, good), good)
        self.assertEqual(creds.check_value("MY_TOKEN", "My_Project"), "My_Project")   # other names: anything

    def test_masked_hints_say_what_is_wrong_without_a_stored_prefix(self):
        creds.save({"GOOGLE_PROJECT": "My_Project", "GOOGLE_CLOUD_PROJECT": "Bad_Project_Name_Long",
                    "CLOUDSDK_CORE_PROJECT": "fine-proj-1",
                    "GOOGLE_CREDENTIALS": json.dumps({"type": "service_account", "project_id": "p-123",
                                                      "private_key": "-----BEGIN " + "PRIVATE KEY-----abc"})})
        rows = {r["key"]: r for r in creds.masked()}
        self.assertEqual(rows["GOOGLE_CREDENTIALS"]["hint"], "JSON key (service_account, project p-123)")
        self.assertNotIn("PRIVATE", json.dumps(rows))
        self.assertIn("not a GCP project ID", rows["GOOGLE_PROJECT"]["hint"])
        self.assertTrue(rows["GOOGLE_PROJECT"]["hint"].startswith("My_Project"))
        self.assertIn("not a GCP project ID", rows["GOOGLE_CLOUD_PROJECT"]["hint"])          # a custom row: masked
        self.assertNotIn("Bad_Project", rows["GOOGLE_CLOUD_PROJECT"]["hint"])
        self.assertNotIn("not a GCP", rows["CLOUDSDK_CORE_PROJECT"]["hint"])
        self.assertEqual(rows["GOOGLE_CLOUD_PROJECT"]["group"], "custom")
        creds.save({"GOOGLE_CREDENTIALS": json.dumps({"type": "service_account\x1b[31m", "project_id": "x\ny"})})
        hint = {r["key"]: r for r in creds.masked()}["GOOGLE_CREDENTIALS"]["hint"]
        self.assertEqual(hint, "JSON key (unknown type)")                           # nothing odd reaches the list
        for value, want in (("{", "not valid JSON"), ('{"private_key": "x"}', "without a \"type\"")):
            creds.save({"GOOGLE_CREDENTIALS": value})
            hint = {r["key"]: r for r in creds.masked()}["GOOGLE_CREDENTIALS"]["hint"]
            self.assertIn(want, hint)
            self.assertFalse(hint.lower().startswith("stored"), hint)   # (the console hides hints that start so)

    def test_more_redirecting_names_are_refused(self):
        for k in ("SOCKS_PROXY", "socks5_proxy", "OPENAI_API_BASE", "AZURE_API_BASE", "GOOGLE_CLOUD_UNIVERSE_DOMAIN",
                  "CODEX_HOME", "JAVA_HOME", "CLOUDSDK_PROXY_ADDRESS", "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE",
                  "CLOUDSDK_AUTH_DISABLE_SSL_VALIDATION", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
                  "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "HTTPLIB2_CA_CERTS",
                  "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION", "ARM_OIDC_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_URL",
                  "ANTHROPIC_BASE_URL", "HTTP_PROXY", "NO_PROXY", "AWS_ENDPOINT_URL_STS"):
            with self.subTest(key=k):
                self.assertFalse(creds.valid_key(k))
        for k in ("AWS_USE_FIPS_ENDPOINT", "aws_use_dualstack_endpoint", "VMWARE_HOME", "CLOUDSDK_CORE_PROJECT", "CLOUDSDK_COMPUTE_ZONE",
                  "GOOGLE_CLOUD_PROJECT", "DATABRICKS_HOST", "ARM_USE_OIDC", "GITLAB_RUNNER_TOKEN", "TF_VAR_REGION"):
            with self.subTest(key=k):
                self.assertTrue(creds.valid_key(k))

    def test_a_bad_project_id_is_flagged_right_after_it_is_stored(self):
        # (cs creds set and the console show path_warning after writing; check_value refuses it up front)
        warn = creds.path_warning("GOOGLE_PROJECT", "Bad_X")
        self.assertIn("not a GCP project ID", warn)
        self.assertIn("cs creds unset GOOGLE_PROJECT", warn)
        self.assertIsNone(creds.path_warning("GOOGLE_PROJECT", "good-proj-1"))
        self.assertIsNone(creds.path_warning("MY_TOKEN", "Bad_X"))

    def test_names_refused_now_are_ignored_when_stored_earlier(self):
        creds.save({"CODEX_HOME": "/tmp/evil", "SOCKS_PROXY": "socks5://evil:1080", "OK_TOKEN": "abcdefgh"})
        self.assertEqual(creds.env(), {"OK_TOKEN": "abcdefgh"})
        rows = {r["key"]: r for r in creds.masked()}
        self.assertTrue(rows["CODEX_HOME"].get("ignored"))
        self.assertTrue(rows["SOCKS_PROXY"].get("ignored"))


# ------------------------------------------------------------------------------------------------ session broker

@unittest.skipUnless(os.name == "posix", "signals")
class SessionSignalWindowTests(unittest.TestCase):
    def test_sigterm_while_the_session_file_is_written_leaves_nothing(self):
        """The handlers are in place, and the session known, before the plaintext file exists: a SIGTERM that lands
        right after the write (before open_session returns) still removes it."""
        home = Path(tempfile.mkdtemp(prefix="cs-w4-sess-"))
        self.addCleanup(shutil.rmtree, home, True)
        code = ("import os, signal\n"
                "from cloudseed import secrets\n"
                "os.environ['MY_DB_PASS'] = 'hunter2hunter2'\n"
                "secrets._start_broker = lambda parked: None\n"
                "real = secrets._write_session_file\n"
                "def write(sid, parked):\n"
                "    rec = real(sid, parked)\n"
                "    print(rec['path'], flush=True)\n"
                "    os.kill(os.getpid(), signal.SIGTERM)\n"
                "    for _ in range(1000): pass\n"
                "    return rec\n"
                "secrets._write_session_file = write\n"
                "secrets.open_session()\n"
                "print('survived', flush=True)\n")
        env = dict(os.environ, PYTHONPATH=str(REPO), CLOUDSEED_HOME=str(home))
        out = subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(out.returncode, 128 + signal.SIGTERM, out.stderr)
        lines = out.stdout.split()
        self.assertTrue(lines and lines[0].endswith(".json"), out.stdout)
        self.assertNotIn("survived", out.stdout)
        self.assertFalse(Path(lines[0]).exists(), "SIGTERM left the plaintext session file behind")

    def test_a_failed_start_leaves_no_session_and_no_handlers(self):
        if signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
            self.skipTest("a SIGTERM handler is already installed")
        # (sessions another test left open would rightly keep the handlers: this test starts from none)
        with mock.patch.dict(secrets._OPEN, {}, clear=True), \
                mock.patch.object(secrets, "_start_broker", return_value=None), \
                mock.patch.object(secrets, "_write_session_file", side_effect=OSError("disk full")), \
                mock.patch.dict(os.environ, {"MY_DB_PASS": "hunter2hunter2"}):
            with self.assertRaises(OSError):
                secrets.open_session()
            self.assertEqual(secrets._OPEN, {})
            self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        self.addCleanup(secrets.set_strict, False)

    def test_close_keeps_the_record_until_the_cleanup_is_done(self):
        seen = []
        with mock.patch.object(secrets, "_start_broker", return_value=None), \
                mock.patch.dict(os.environ, {"MY_DB_PASS": "hunter2hunter2"}):
            sid, _env = secrets.open_session()
        self.addCleanup(secrets.set_strict, False)
        path = secrets.SESSIONS_DIR / f"{sid}.json"
        real_unlink = Path.unlink

        def unlink(p, *a, **kw):
            seen.append(sid in secrets._OPEN)      # a signal here would still find the session
            return real_unlink(p, *a, **kw)
        with mock.patch.object(Path, "unlink", unlink):
            secrets.close_session(sid)
        self.assertEqual(seen, [True])
        self.assertFalse(path.exists())
        self.assertNotIn(sid, secrets._OPEN)


# ------------------------------------------------------------------------------------------------ skills

class SkillStateTextTests(_TmpHome):
    def test_every_state_in_words(self):
        self.assertIn("run time", skills.state_text("builtin"))
        self.assertIn("prompt", skills.state_text("grok"))
        self.assertNotIn("--dir", skills.state_text("grok"))
        self.assertIn("not installed - run: cloudseed skill install --agent claude", skills.state_text("claude"))
        dest = skills.target_dir("claude", None, False)
        with contextlib.redirect_stderr(io.StringIO()):
            skills.install(None, dest)
        self.assertTrue(skills.state_text("claude").startswith("installed  ("))
        self.assertIn("~/.claude/skills", skills.state_text("claude"))
        (dest / "cloudseed-aws" / skills.MARKER).write_text("old\n")
        self.assertIn("outdated", skills.state_text("claude"))
        shutil.rmtree(dest / "cloudseed-aws")
        (dest / "cloudseed-aws").mkdir()
        (dest / "cloudseed-aws" / "SKILL.md").write_text("---\nname: mine\n---\n")
        self.assertEqual(skills.state("claude"), "partial")
        text = skills.state_text("claude")
        self.assertIn("installed, except cloudseed-aws", text)
        self.assertIn("left alone", text)
        with self.assertRaises(ui.Abort) as cm:     # an explicit install still stops, and --dir is its way out
            skills.install(["aws"], dest)
        self.assertIn("--dir", str(cm.exception))


# ------------------------------------------------------------------------------------------------ agents

class ClaudeKeyNoteTests(_TmpHome):
    def _keys(self, logged_in: bool, applied: dict):
        import types
        agents._CLAUDE_AUTH_CACHE.clear()
        with mock.patch.dict(creds.APPLIED, applied, clear=True), \
                mock.patch.object(agents.subprocess, "run",
                                  return_value=types.SimpleNamespace(stdout=json.dumps({"loggedIn": logged_in}),
                                                                     returncode=0)):
            return agents._agent_keys(agents.get("claude"), "/usr/local/bin/claude")

    def test_a_shell_key_is_kept_and_named_when_claude_code_has_its_own_login(self):
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-" + "shell-00000000000000000000"
        keep, note = self._keys(True, {})
        self.assertIn("ANTHROPIC_API_KEY", keep)
        self.assertIn("exported in your shell", note)
        self.assertIn("billed", note)
        keep, note = self._keys(False, {})              # its only way in: nothing to explain
        self.assertIn("ANTHROPIC_API_KEY", keep)
        self.assertIsNone(note)
        # a shell key next to a vault token: the vault's is dropped for a logged-in Claude Code, the shell's stays
        os.environ["ANTHROPIC_AUTH_TOKEN"] = "vault-token-0000000000000000"
        keep, note = self._keys(True, {"ANTHROPIC_AUTH_TOKEN": "vault-token-0000000000000000"})
        self.assertIn("ANTHROPIC_API_KEY", keep)
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", keep)
        self.assertIn("ANTHROPIC_API_KEY exported", note)

    def test_haiku_has_its_canonical_id(self):
        self.assertIn("claude-haiku-4-5", agents.get("claude")["models"])


class SkillsInPromptWordingTests(_TmpHome):
    def test_the_plain_prompt_is_reworded_for_an_agent_that_gets_the_skills_in_it(self):
        seen = []

        class _P:
            pid, returncode = 1, 0

            def __init__(self, cmd, **kw):
                seen.append(cmd)

            def wait(self, *a):
                return 0

            def poll(self):
                return 0
        os.environ["GROK_API_KEY"] = "xai-abc"
        task = "list my environments"
        with mock.patch.object(agents, "installed", return_value="/usr/local/bin/grok"), \
                mock.patch.object(agents.subprocess, "Popen", _P), contextlib.redirect_stdout(io.StringIO()):
            agents.run(agents.get("grok"), headliner.plain(task), None, interactive=False, task=task)
            agents.run(agents.get("grok"), "custom words: " + task, None, interactive=False, task=task)
        sent = seen[0][seen[0].index("-p") + 1]
        self.assertIn("Follow the cloudseed skill included above", sent)
        self.assertNotIn("Use the `cloudseed` skill", sent)
        self.assertTrue(sent.rstrip().endswith("Task: " + task))
        self.assertTrue(seen[1][seen[1].index("-p") + 1].rstrip().endswith("custom words: " + task))   # left alone


# ------------------------------------------------------------------------------------------------ review follow-ups

class ReviewFollowUpTests(_TmpHome):
    def test_credential_source_switches_are_refused(self):
        # an external_account key from the vault would run its command; container / metadata / authority hosts hand
        # out credentials or receive secrets
        for k in ("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "aws_container_credentials_full_uri", "AZURE_AUTHORITY_HOST",
                  "GCE_METADATA_HOST", "GCE_METADATA_IP", "GCE_METADATA_ROOT"):
            with self.subTest(key=k):
                self.assertFalse(creds.valid_key(k))
        for k in ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "ARM_ENVIRONMENT", "GOOGLE_CLOUD_QUOTA_PROJECT"):
            with self.subTest(key=k):
                self.assertTrue(creds.valid_key(k))

    def test_the_refusal_names_every_variable_and_never_a_value(self):
        for argv, shown in ((["creds", "set", "my_secret=hunter2hunter2"], "`cloudseed creds set MY_SECRET`"),
                            (["creds", "set", "my_secret"], "`cloudseed creds set MY_SECRET`"),
                            (["creds", "unset", "my_token", "OTHER"], "`cloudseed creds unset MY_TOKEN OTHER`"),
                            # a value that looks like a name is still the value of the name before it
                            (["creds", "set", "MY_TOKEN", "HUNTER2HUNTER2"], "`cloudseed creds set MY_TOKEN`"),
                            (["creds", "set", "MY_TOKEN", "hunter2", "B=hunter2", "C"], "`cloudseed creds set MY_TOKEN B C`")):
            with self.subTest(argv=argv):
                msg = builtin_agent.guard(argv)
                self.assertIn(shown, msg)
                self.assertNotIn("hunter2", msg.lower())

    def test_the_refused_call_is_shown_without_its_values(self):
        for args, shown in (("creds set MY_TOKEN HUNTER2HUNTER2", "creds set MY_TOKEN [REDACTED]"),
                            ("-y creds set my_token=hunter2 --forget", "-y creds set my_token=[REDACTED] --forget"),
                            ("creds set 'a b=c'", "creds set [REDACTED]"),
                            ("creds unset my_token", "creds unset my_token")):
            with self.subTest(args=args):
                self.assertEqual(builtin_agent._shown_args(args), shown)

    def test_the_install_hint_leaves_a_directory_that_is_not_cloudseeds_alone(self):
        dest = skills.target_dir("claude", None, False)
        with contextlib.redirect_stderr(io.StringIO()):
            skills.install(None, dest)
        shutil.rmtree(dest / "cloudseed-aws")
        (dest / "cloudseed-aws").mkdir()
        (dest / "cloudseed-aws" / "SKILL.md").write_text("---\nname: mine\n---\n")
        (dest / "cloudseed-gcp" / skills.MARKER).write_text("old\n")
        shutil.rmtree(dest / "cloudseed-azure")
        self.assertEqual(skills.state("claude"), "stale")
        self.assertEqual(skills.pending("claude"), ["cloudseed-azure", "cloudseed-gcp"])
        text = skills.state_text("claude")
        self.assertIn("outdated - run: cloudseed skill install azure gcp --agent claude", text)
        self.assertIn("cloudseed-aws there is not cloudseed's (left alone)", text)
        with self.assertRaises(ui.Abort):     # (installing them all would stop at that directory)
            skills.install(None, dest)
        with contextlib.redirect_stderr(io.StringIO()):
            skills.install(["azure", "gcp"], dest)     # what the hint says: works, and the directory stays
        self.assertEqual(skills.state("claude"), "partial")
        self.assertEqual((dest / "cloudseed-aws" / "SKILL.md").read_text(), "---\nname: mine\n---\n")
        self.assertEqual(skills.pending("claude"), [])


if __name__ == "__main__":
    unittest.main()
