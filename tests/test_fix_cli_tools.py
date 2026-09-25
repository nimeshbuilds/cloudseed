"""Regression tests for the cli-tools fixes: credentials vault + undo, the undo scope/drop/global handling, agent
selection and consent for installs, models, skills, `cloudseed install`, the MCP server lifecycle and client wiring,
the web console lifecycle guards, and the argument-parser error messages.

Every CLI test runs `bin/cloudseed` in a fresh CLOUDSEED_HOME and HOME (no cloud, no agents, no global installs: a fake
`npm` records what would have been installed). MCP/UI servers only ever run as background processes on a free
ephemeral loopback port and are stopped again."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
CS = str(ROOT / "bin" / "cloudseed")
sys.path.insert(0, str(ROOT))


def _free_port() -> int:
    """A port nothing listens on now, chosen by the OS (bind to port 0): an ephemeral port, so suites running at the
    same time (other checkouts, CI) never collide on a fixed range."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _health(port: int) -> dict | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as r:
            return json.loads(r.read().decode())
    except Exception:  # noqa: BLE001
        return None


class Sandbox(unittest.TestCase):
    """A fresh cloudseed home + user home per test, and a minimal PATH (python + system dirs + fake tools)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-fix-tools-"))
        self.home = self.tmp / "cs"
        self.user = self.tmp / "home"
        self.bin = self.tmp / "bin"
        for d in (self.home, self.user, self.bin):
            d.mkdir()
        os.symlink(sys.executable, self.bin / "python3")
        tf = shutil.which("terraform")                 # `cs undo <cloud>` checks the Terraform runtime first
        if tf:
            os.symlink(tf, self.bin / "terraform")
        self.env = {"CLOUDSEED_HOME": str(self.home), "HOME": str(self.user), "NO_COLOR": "1", "COLUMNS": "100",
                    "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"}
        self.ports: list[int] = []
        # what this home's MCP server reports in /health (mcp._home_id): other runs may use the same ports
        self.home_id = hashlib.sha256(str(self.home.expanduser().resolve()).encode()).hexdigest()[:12]

    def tearDown(self):
        for port in self.ports:        # never leave a server behind (and never signal another run's server)
            info = _health(port)
            if info and info.get("pid") and info.get("home") == self.home_id:
                try:
                    os.kill(int(info["pid"]), 15)
                except OSError:
                    pass
            self.cs("mcp", "stop")
            self.cs("ui", "stop")
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cs(self, *args, extra_env: dict | None = None, timeout: int = 120):
        env = dict(self.env, **(extra_env or {}))
        p = subprocess.run([sys.executable, CS, *args], env=env, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout + p.stderr

    def vault(self) -> dict:
        try:
            return json.loads((self.home / "credentials.json").read_text())
        except OSError:
            return {}

    def journal(self) -> dict:
        try:
            return json.loads((self.home / "undo.json").read_text())
        except OSError:
            return {}

    def settings(self) -> dict:
        try:
            return json.loads((self.home / "settings.json").read_text())
        except OSError:
            return {}

    def write_settings(self, data: dict) -> None:
        (self.home / "settings.json").write_text(json.dumps(data))

    def make_env(self, env_id: str) -> None:
        d = self.home / "envs" / env_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "config.json").write_text(json.dumps({"name": "t", "region": "r"}))

    def write_journal(self, entries: list[dict]) -> None:
        j: dict = {}
        for i, e in enumerate(entries):
            e = dict({"id": f"e{i}", "at": f"2026-01-01T00:00:{i:02d}+00:00", "data": {}}, **e)
            j.setdefault(e["scope"], []).append(e)
        (self.home / "undo.json").write_text(json.dumps(j))

    def fake_tool(self, name: str, body: str = "exit 0") -> Path:
        p = self.bin / name
        p.write_text("#!/bin/bash\n" + body + "\n")
        p.chmod(0o755)
        return p


# ------------------------------------------------------------------------------------------------ credentials

class CredsTest(Sandbox):
    def test_undo_of_an_overwrite_restores_the_previous_value(self):
        self.assertEqual(self.cs("creds", "set", "OPENAI_API_KEY=AAAA1111")[0], 0)
        self.assertEqual(self.cs("creds", "set", "OPENAI_API_KEY=BBBB2222")[0], 0)
        rc, out = self.cs("-y", "undo", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.vault(), {"OPENAI_API_KEY": "AAAA1111"})
        rc, out = self.cs("-y", "undo", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.vault(), {})

    def test_one_set_of_new_and_overwritten_keys_is_one_undo_step(self):
        self.cs("creds", "set", "OLD_KEY=1")
        self.cs("creds", "set", "NEW_KEY=2", "OLD_KEY=3")
        self.assertEqual(len(self.journal()["global"]), 2)
        rc, out = self.cs("-y", "undo")                 # a vault change is approved like every other undo
        self.assertEqual(rc, 3, out)
        self.assertIn("--auto-approve", out)
        self.assertEqual(self.vault(), {"OLD_KEY": "3", "NEW_KEY": "2"})
        self.assertEqual(len(self.journal()["global"]), 2)
        rc, out = self.cs("-y", "undo", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.vault(), {"OLD_KEY": "1"})

    def test_bare_key_without_a_terminal_never_deletes(self):
        self.cs("creds", "set", "GROK_API_KEY=secret-value")
        before = self.journal()
        for argv in (("-y", "creds", "set", "GROK_API_KEY"), ("creds", "set", "GROK_API_KEY")):
            rc, out = self.cs(*argv)
            self.assertEqual(rc, 2, out)
            self.assertIn("Nothing was changed", out)
            self.assertNotIn("removed", out)
        self.assertEqual(self.vault(), {"GROK_API_KEY": "secret-value"})
        self.assertEqual(self.journal(), before)

    def test_empty_value_and_bad_names_change_nothing(self):
        rc, out = self.cs("creds", "set", "A_KEY=")
        self.assertEqual(rc, 2, out)
        self.assertIn("cs creds unset A_KEY", out)
        rc, out = self.cs("creds", "set", "GOOD=1", "bad-key=2")
        self.assertEqual(rc, 2, out)
        self.assertNotIn("Unexpected error", out)
        self.assertEqual(self.vault(), {})
        self.assertEqual(self.journal(), {})

    def test_removing_google_credentials_removes_the_key_file(self):
        gcp = self.home / "gcp-credentials.json"
        self.cs("creds", "set", 'GOOGLE_CREDENTIALS={"type":"service_account","private_key":"k"}')
        self.cs("creds")                               # any start materialises the key file
        self.assertTrue(gcp.exists())
        self.cs("creds", "unset", "GOOGLE_CREDENTIALS")
        self.assertFalse(gcp.exists())
        self.cs("-y", "undo", "--auto-approve")
        self.cs("creds")
        self.assertTrue(gcp.exists())
        rc, out = self.cs("creds", "clear")
        self.assertEqual(rc, 0, out)
        self.assertFalse(gcp.exists())
        self.assertIn("--forget", out)                 # says that a copy is kept for undo
        self.assertIn("service_account", (self.home / "undo.json").read_text())

    def test_clear_forget_keeps_no_copy(self):
        self.cs("creds", "set", "TS_AUTHKEY=tskey-secret-1", "DB_PASS=hunter2x")
        self.cs("creds", "set", "DB_PASS=hunter3x")   # the overwrite journals the old value
        rc, out = self.cs("creds", "clear", "--forget")
        self.assertEqual(rc, 0, out)
        text = (self.home / "undo.json").read_text()
        self.assertNotIn("hunter2x", text)
        self.assertNotIn("tskey-secret-1", text)
        self.assertEqual(self.vault(), {})

    def test_stale_gcp_key_file_is_removed_at_start(self):
        from cloudseed import creds
        tmp = self.tmp / "vault"
        tmp.mkdir()
        with mock.patch.object(creds, "STORE", tmp / "credentials.json"), mock.patch.object(creds, "GCP_FILE", tmp / "gcp.json"):
            creds.set_("GOOGLE_CREDENTIALS", "{}")
            creds.env()
            self.assertTrue((tmp / "gcp.json").exists())
            creds.save({})                             # removed behind cloudseed's back (web UI, undo, by hand)
            creds.env()
            self.assertFalse((tmp / "gcp.json").exists())


# ------------------------------------------------------------------------------------------------ undo

class UndoTest(Sandbox):
    def setUp(self):
        super().setUp()
        if not (self.bin / "terraform").exists():
            self.skipTest("terraform is not installed (cloud-scoped undo checks the runtime)")

    def test_cloud_scope_never_falls_back_to_other_scopes(self):
        for e in ("aws-dev", "aws-prod", "gcp-dev"):
            self.make_env(e)
        self.write_journal([
            {"scope": "aws-dev", "summary": "dev change", "kind": "info", "data": {"advice": "by hand"}},
            {"scope": "gcp-dev", "summary": "gcp change", "kind": "info", "data": {"advice": "by hand"}},
            {"scope": "global", "summary": "model x", "kind": "settings-restore", "data": {"settings": {"ui": True}, "what": ["models"]}},
        ])
        rc, out = self.cs("undo", "aws", "--list")
        self.assertIn("dev change", out)
        self.assertNotIn("gcp change", out)
        self.assertNotIn("model x", out)
        rc, out = self.cs("undo", "aws")
        self.assertEqual(rc, 0, out)
        self.assertIn("dev change", out)
        j = self.journal()
        self.assertNotIn("aws-dev", j)
        self.assertEqual(len(j["global"]), 1)          # the global entry was not touched
        self.assertEqual(self.settings(), {})

    def test_ambiguous_cloud_aborts_without_a_terminal(self):
        for e in ("aws-dev", "aws-prod"):
            self.make_env(e)
        self.write_journal([{"scope": "aws-dev", "summary": "a", "kind": "info", "data": {}},
                            {"scope": "aws-prod", "summary": "b", "kind": "info", "data": {}}])
        rc, out = self.cs("undo", "aws", "--auto-approve")
        self.assertEqual(rc, 2, out)
        self.assertIn("Several environments match aws", out)
        self.assertEqual(len(self.journal()), 2)

    def test_env_without_cloud_and_global_flag(self):
        self.make_env("aws-dev")
        self.write_journal([{"scope": "global", "summary": "older global", "kind": "info", "data": {}},
                            {"scope": "aws-dev", "summary": "newer env", "kind": "info", "data": {}}])
        rc, out = self.cs("undo", "--global")
        self.assertIn("older global", out)
        self.assertIn("aws-dev", self.journal())
        rc, out = self.cs("undo", "--env", "dev")
        self.assertIn("newer env", out)
        self.assertEqual(self.journal(), {})

    def test_drop_and_id(self):
        self.write_journal([{"scope": "global", "summary": "first", "kind": "argv", "data": {"argv": ["enable", "headliner"]}},
                            {"scope": "global", "summary": "second", "kind": "argv", "data": {"argv": ["enable", "nonsense"]}}])
        rc, out = self.cs("undo", "--id", "e0", "--auto-approve")
        self.assertEqual(rc, 1, out)
        self.assertIn("newer action", out)
        rc, out = self.cs("undo", "--global", "--auto-approve")    # the stuck entry fails and says how to skip it
        self.assertEqual(rc, 1, out)
        self.assertIn("--drop", out)
        rc, out = self.cs("undo", "--global", "--drop")
        self.assertEqual(rc, 0, out)
        self.assertIn("nothing was changed", out)
        self.assertEqual([e["summary"] for e in self.journal()["global"]], ["first"])

    def test_id_is_checked_against_the_filters_not_resolved_through_them(self):
        for e in ("aws-dev", "aws-prod"):
            self.make_env(e)
        self.write_journal([{"scope": "aws-dev", "summary": "a", "kind": "info", "data": {}},
                            {"scope": "aws-prod", "summary": "b", "kind": "info", "data": {}},
                            {"scope": "global", "summary": "g", "kind": "info", "data": {}}])
        rc, out = self.cs("undo", "aws", "--id", "e2")
        self.assertEqual(rc, 2, out)
        self.assertIn("belongs to global, which does not match aws", out)
        self.assertNotIn("Several environments", out)
        rc, out = self.cs("undo", "azure", "--env", "dev", "--id", "e0")
        self.assertEqual(rc, 2, out)
        self.assertNotIn("[]", out)
        rc, out = self.cs("undo", "aws", "--id", "e0")             # several aws envs, but the entry is exact
        self.assertEqual(rc, 0, out)
        self.assertIn("Undo: a", out)
        rc, out = self.cs("undo", "--global", "--id", "e2")
        self.assertEqual(rc, 0, out)
        self.assertEqual(list(self.journal()), ["aws-prod"])

    def test_info_entries_do_not_claim_success(self):
        self.write_journal([{"scope": "global", "summary": "helm uninstall foo", "kind": "info", "data": {"advice": "restore it by hand"}}])
        rc, out = self.cs("undo")
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing automatic to undo", out)
        self.assertNotIn("Undone", out)
        self.assertNotIn("This will", out)

    def test_missing_environment(self):
        self.make_env("aws-dev")
        rc, out = self.cs("undo", "aws", "--env", "nonexistent")
        self.assertIn("does not exist", out)
        self.assertNotIn("cs destroy aws --env nonexistent", out)
        self.write_journal([{"scope": "aws-gone", "summary": "change", "kind": "config", "data": {"prev_cfg": {}}}])
        rc, out = self.cs("undo", "aws", "--env", "gone")
        self.assertEqual(rc, 0, out)
        self.assertIn("no longer exists", out)
        self.assertEqual(self.journal(), {})

    def test_disable_ui_records_an_inverse_that_parses(self):
        from cloudseed.cli import build_parser
        self.write_settings({"ui": True})
        (self.home / "ui").mkdir()
        (self.home / "ui" / "server.json").write_text(json.dumps({"service": "background", "port": 7579, "host": "127.0.0.1"}))
        rc, out = self.cs("disable", "ui")
        self.assertEqual(rc, 0, out)
        argv = self.journal()["global"][-1]["data"]["argv"]
        self.assertEqual(argv, ["ui", "start", "--no-open"])
        a = build_parser().parse_args(argv)
        self.assertTrue(a.no_open)
        a = build_parser().parse_args(["enable", "ui", "--no-open"])   # entries recorded by older versions
        self.assertTrue(a.no_open)

    def test_disable_ui_undo_starts_the_console_again(self):
        port = _free_port()
        self.ports.append(port)
        self.write_settings({"ui": True})
        (self.home / "ui").mkdir()
        (self.home / "ui" / "server.json").write_text(json.dumps({"service": "background", "port": port, "host": "127.0.0.1"}))
        self.cs("disable", "ui")
        rc, out = self.cs("-y", "undo", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertTrue(self.settings().get("ui"))
        # (a port another run took meanwhile is replaced by a free one, which the console saves)
        port = json.loads((self.home / "ui" / "server.json").read_text()).get("port") or port
        self.ports.append(port)
        self.assertEqual((_health(port) or {}).get("server"), "cloudseed-ui")
        self.assertEqual((_health(port) or {}).get("home"), self.home_id)      # this home's console, not another run's
        self.assertEqual(self.journal(), {})

    def test_restore_files_runs_follow_up_commands(self):
        from cloudseed import undo
        target = self.tmp / "f.txt"
        target.write_text("new")
        backup = self.tmp / "b.txt"
        backup.write_text("old")
        entry = {"kind": "restore-files", "scope": "global", "summary": "x",
                 "data": {"files": {str(target): str(backup), str(self.tmp / "added.txt"): None}, "then": [["mcp", "restart"]]}}
        self.assertIn("then run: cloudseed mcp restart", undo.describe(entry))
        self.assertIn("delete added.txt", undo.describe(entry))
        with mock.patch.object(undo, "_run_cli") as run:
            undo.perform(entry, {}, True)
        self.assertEqual(target.read_text(), "old")
        run.assert_called_once_with(["mcp", "restart"])
        e2 = {"kind": "creds-restore", "scope": "global", "summary": "x", "data": {"values": {"A": "1"}, "unset": ["B"]}}
        self.assertEqual(undo.describe(e2), "put back the previous value of stored credential(s): A; remove stored credential(s): B")

    def test_noop_installs_leave_no_entry(self):
        from cloudseed import cli, deps, undo
        journal = self.tmp / "undo.json"
        with mock.patch.object(undo, "JOURNAL", journal), mock.patch.object(deps, "find", return_value="/usr/bin/true"), \
                mock.patch.object(deps, "install", return_value=True):
            import argparse
            cli.cmd_deps(argparse.Namespace(deps_cmd="install", tools=["terraform"]), {})
            self.assertEqual(undo.entries(), [])
            cli._record_installed("install go", undo.listing(cli.paths.BIN_DIR), changed=["go"])
            self.assertEqual(undo.entries()[-1]["kind"], "info")
            self.assertIn("brew uninstall go", undo.entries()[-1]["data"]["advice"])


# ------------------------------------------------------------------------------------------------ agents & models

class AgentsTest(Sandbox):
    def setUp(self):
        super().setUp()
        self.npm_log = self.tmp / "npm.log"
        self.fake_tool("npm", f'echo "$@" >> {self.npm_log}\n'
                              f'if [ "$1" = install ]; then printf \'#!/bin/bash\\necho fake-agent "$@"\\n\' > {self.bin}/codex; chmod +x {self.bin}/codex; fi')
        self.env.update(ANTHROPIC_API_KEY="", ANTHROPIC_AUTH_TOKEN="")

    def test_no_global_install_without_consent(self):
        for argv in (("-y", "use", "codex"), ("use", "codex"), ("enable", "agentic", "--agent", "codex")):
            rc, out = self.cs(*argv)
            self.assertEqual(rc, 1, out)
            self.assertIn("cloudseed install codex", out)
        self.assertFalse(self.npm_log.exists())
        self.assertNotIn("agentic", self.settings())
        self.assertEqual(self.journal(), {})             # failed use/enable leave no undo entry

    def test_explicit_install_and_agent_sessions(self):
        rc, out = self.cs("install", "codex", "-y", extra_env={"CLOUDSEED_AGENT": "builtin"})
        self.assertEqual(rc, 2, out)                     # refused before anything runs (human-only in agent sessions)
        self.assertIn("agent sessions never install software", out)
        self.assertFalse(self.npm_log.exists())
        rc, out = self.cs("install", "codex", "-y")
        self.assertEqual(rc, 0, out)
        self.assertIn("install -g @openai/codex", self.npm_log.read_text())
        self.assertIn("Installing OpenAI Codex CLI", out)
        self.assertEqual(self.settings().get("agent"), "codex")      # nothing was selected yet
        self.assertTrue((self.user / ".codex" / "skills" / "cloudseed" / "SKILL.md").exists())

    def test_installer_that_leaves_no_binary_on_path(self):
        self.fake_tool("npm", f'echo "$@" >> {self.npm_log}')      # "succeeds" but installs nothing we can find
        rc, out = self.cs("install", "codex", "-y")
        self.assertEqual(rc, 1, out)
        self.assertIn("still not on PATH", out)
        self.assertNotIn("exit 0", out)

    def test_install_agent_puts_replaced_skills_back_on_undo(self):
        skills_dir = self.user / ".codex" / "skills"
        (skills_dir / "cloudseed-aws").mkdir(parents=True)
        # an earlier cloudseed install the user edited (a directory that is not a cloudseed skill is never replaced)
        mine = "---\nname: cloudseed-aws\n---\nmy own edited copy\n"
        (skills_dir / "cloudseed-aws" / "SKILL.md").write_text(mine)
        rc, out = self.cs("install", "codex", "-y")
        self.assertEqual(rc, 0, out)
        self.assertNotEqual((skills_dir / "cloudseed-aws" / "SKILL.md").read_text(), mine)
        rc, out = self.cs("-y", "undo", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertEqual((skills_dir / "cloudseed-aws" / "SKILL.md").read_text(), mine)
        self.assertFalse((skills_dir / "cloudseed").exists())

    def test_do_agent_is_a_one_off(self):
        self.fake_tool("codex", "echo fake-codex-ran")
        self.write_settings({"agent": "builtin", "agentic": True})
        rc, out = self.cs("do", "--agent", "codex", "list my environments", extra_env={"OPENAI_API_KEY": "sk-test"})
        self.assertEqual(rc, 0, out)
        self.assertIn("fake-codex-ran", out)
        self.assertEqual(self.settings()["agent"], "builtin")

    def test_builtin_without_key_stays_selected_and_runs_through_claude(self):
        self.fake_tool("claude", 'echo "fake-claude $*"')
        # a logged-in Claude Code (a bare {} is not a login: agents checks for an account)
        (self.user / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "t@example.com"}}))
        rc, out = self.cs("use", "builtin", "--model", "claude-sonnet-5")
        self.assertEqual(rc, 0, out)
        s = self.settings()
        self.assertEqual(s["agent"], "builtin")
        self.assertEqual(s["models"], {"builtin": "claude-sonnet-5"})
        self.assertTrue((self.user / ".claude" / "skills" / "cloudseed" / "SKILL.md").exists())
        rc, out = self.cs("do", "--force", "list envs")
        self.assertEqual(rc, 0, out)
        self.assertIn("runs through your Claude Code CLI", out)
        self.assertIn("fake-claude -p", out)
        self.assertIn("claude-sonnet-5", out)
        self.assertEqual(self.settings()["agent"], "builtin")

    def test_no_credentials_and_no_claude_fails_once_before_the_header(self):
        rc, out = self.cs("do", "--force", "list envs")
        self.assertEqual(rc, 1, out)
        self.assertEqual(out.count("needs Anthropic API credentials"), 1)
        self.assertNotIn("cloudseed · agentic", out)
        self.assertNotIn("\n    cloudseed use claude ", out)    # not advised while Claude Code is not installed
        self.assertIn("npm install -g @anthropic-ai/claude-code", out)
        self.assertIn("Examples for cloudseed agentic", out)

    def test_model_default_typo_and_forget(self):
        rc, out = self.cs("model")
        self.assertEqual(rc, 0, out)
        self.assertIn("showing the default (builtin)", out)
        rc, out = self.cs("model", "claude-sonet-5", "--agent", "builtin")
        self.assertEqual(rc, 0, out)
        self.assertIn("did you mean claude-sonnet-5", out)
        self.assertEqual(self.settings()["custom_models"], {"builtin": ["claude-sonet-5"]})
        rc, out = self.cs("model", "--forget", "claude-sonet-5", "--agent", "builtin")
        self.assertEqual(rc, 0, out)
        s = self.settings()
        self.assertNotIn("builtin", s.get("custom_models", {}))
        self.assertNotIn("builtin", s.get("models", {}))
        rc, out = self.cs("model", "--forget", "never-there", "--agent", "builtin")
        self.assertEqual(rc, 2, out)

    def test_model_lists_and_thinking(self):
        from cloudseed import agents, builtin_agent
        self.assertIn("claude-opus-5-5", agents.DEFAULT_AGENTS["builtin"]["models"])
        self.assertIn("claude-opus-5-5", agents.DEFAULT_AGENTS["claude"]["models"])
        self.assertEqual(agents.DEFAULT_AGENTS["builtin"]["default_model"], "claude-opus-5")
        for m in ("claude-haiku-4-5-20251001", "claude-haiku-4-5", "claude-sonnet-4-5", "claude-opus-4-1"):
            self.assertTrue(m.startswith(builtin_agent._NO_ADAPTIVE_THINKING), m)
        for m in ("claude-opus-4-0", "claude-sonnet-4-0", "claude-opus-4-20250514", "claude-3-7-sonnet-latest"):
            self.assertTrue(m.startswith(builtin_agent._NO_ADAPTIVE_THINKING), m)
        for m in ("claude-opus-5", "claude-opus-5-5", "claude-fable-5-1", "claude-sonnet-5", "claude-opus-4-8", "claude-opus-4-6",
                  "claude-sonnet-4-6"):
            self.assertFalse(m.startswith(builtin_agent._NO_ADAPTIVE_THINKING), m)


# ------------------------------------------------------------------------------------------------ skills & install

class SkillsInstallTest(Sandbox):
    def test_short_names_everywhere(self):
        rc, out = self.cs("skill", "install", "aws", "destroy", "--agent", "codex")
        self.assertEqual(rc, 0, out)
        dest = self.user / ".codex" / "skills"
        self.assertEqual(sorted(p.name for p in dest.iterdir()), ["cloudseed-aws", "cloudseed-destroy"])
        rc, out = self.cs("skill", "show", "aws")
        self.assertEqual(rc, 0, out)
        self.assertIn("name: cloudseed-aws", out)

    def test_unknown_names_abort_before_anything_is_copied(self):
        rc, out = self.cs("skill", "show", "bogus")
        self.assertEqual(rc, 2, out)
        self.assertIn("Unknown skill 'bogus'", out)
        self.assertNotIn("Unexpected error", out)
        rc, out = self.cs("skill", "install", "aws", "bogus", "--agent", "gemini")
        self.assertEqual(rc, 2, out)
        self.assertFalse((self.user / ".gemini").exists())

    def test_builtin_installs_go_to_claude_code_also_with_project(self):
        self.write_settings({"agent": "builtin"})
        proj = self.tmp / "proj"
        proj.mkdir()
        p = subprocess.run([sys.executable, CS, "skill", "install", "--project", "cloudseed"], env=self.env, cwd=proj,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue((proj / ".claude" / "skills" / "cloudseed" / "SKILL.md").exists())
        self.assertFalse((proj / ".builtin").exists())
        rc, out = self.cs("skill", "install", "vmware")
        self.assertEqual(rc, 0, out)
        self.assertTrue((self.user / ".claude" / "skills" / "cloudseed-vmware").exists())

    def test_install_plan(self):
        from cloudseed import cli, ui
        self.assertEqual(cli._install_plan(["skills", "vmware"]), [("skills", ("cloudseed-vmware",))])
        self.assertEqual(cli._install_plan(["skills", "platform", "finops", "terraform"]),
                         [("skills", ("cloudseed-platform", "cloudseed-finops")), ("tool", "terraform")])
        self.assertEqual(cli._install_plan(["skills", "all"]), [("skills", ())])
        plan = cli._install_plan(["all"])
        for t in ("kubectl", "helm", "terraform"):
            self.assertIn(("tool", t), plan)
        self.assertIn(("provider", None), plan)
        self.assertIn(("skills", ()), plan)
        with self.assertRaises(ui.Abort):
            cli._install_plan(["terraform", "nonsense"])

    def test_install_skills_records_a_precise_undo(self):
        d = self.tmp / "skills"
        rc, out = self.cs("install", "skills", "platform", "--dir", str(d))
        self.assertEqual(rc, 0, out)
        self.assertEqual([p.name for p in d.iterdir()], ["cloudseed-platform"])
        rc, out = self.cs("install", "bogus", "skills", "aws", "--dir", str(d))
        self.assertEqual(rc, 1, out)
        self.assertIn("Nothing was installed", out)
        self.assertFalse((d / "cloudseed-aws").exists())
        rc, out = self.cs("-y", "undo", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertFalse((d / "cloudseed-platform").exists())

    def test_one_install_touching_a_skill_twice_undoes_to_before_the_command(self):
        d = self.tmp / "skills"
        (d / "cloudseed-aws").mkdir(parents=True)
        mine = "---\nname: cloudseed-aws\n---\nmy own copy\n"      # an earlier (edited) cloudseed install
        (d / "cloudseed-aws" / "SKILL.md").write_text(mine)
        rc, out = self.cs("install", "skills", "aws", "skills", "--dir", str(d))   # aws first, then all of them
        self.assertEqual(rc, 0, out)
        self.assertNotIn("Unexpected error", out)
        self.assertNotIn("my own copy", (d / "cloudseed-aws" / "SKILL.md").read_text())
        rc, out = self.cs("-y", "undo", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertEqual([p.name for p in d.iterdir()], ["cloudseed-aws"])
        self.assertEqual((d / "cloudseed-aws" / "SKILL.md").read_text(), mine)
        self.assertEqual(len(list((self.home / "undo").iterdir())), 0)    # every backup was used or discarded


# ------------------------------------------------------------------------------------------------ MCP

class MCPArgsTest(unittest.TestCase):
    def test_clients_arg(self):
        from cloudseed import cli, mcp, ui
        present = {"cursor", "codex"}
        with mock.patch.object(mcp, "client_present", side_effect=lambda k: k in present):
            self.assertEqual(sorted(cli._mcp_clients_arg(["all"], need_present=True)), ["codex", "cursor"])
            self.assertEqual(cli._mcp_clients_arg([], need_present=True), ["codex", "cursor"])
            self.assertEqual(cli._mcp_clients_arg(["all"], need_present=False), list(mcp.CLIENTS))
            self.assertEqual(sorted(cli._mcp_clients_arg(["all", "windsurf"], need_present=True)), ["codex", "cursor", "windsurf"])
            self.assertEqual(cli._mcp_clients_arg(["cursor,codex", "cursor"], need_present=True), ["cursor", "codex"])
            self.assertEqual(cli._mcp_clients_arg(["none"], need_present=True), [])
            for bad in (["none", "codex"], ["bogus"]):
                with self.assertRaises(ui.Abort) as cm:
                    cli._mcp_clients_arg(bad, need_present=True)
                self.assertEqual(cm.exception.code, 2)
                self.assertNotIn("Unknown client(s): all", cm.exception.msg)

    def test_status_probes_are_not_logged(self):
        from cloudseed import mcp
        with mock.patch.object(mcp, "_log") as log:
            mcp.handle({"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "cloudseed-status"}}}, mcp.Session({}))
            log.assert_not_called()
            mcp.handle({"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "cursor"}}}, mcp.Session({}))
            log.assert_called_once()

    def test_config_variants_are_valid_on_their_own(self):
        from cloudseed import mcp
        state = {"transport": "http", "host": "127.0.0.1", "port": 7571, "auth": "token"}
        with mock.patch.object(mcp, "load_token", return_value="tok123"), mock.patch.object(mcp, "ensure_token", return_value="tok123"):
            blocks = mcp.client_config_variants(state)
        for b in blocks:
            for label, snippet in b["variants"]:
                if snippet.startswith("{"):
                    json.loads(snippet)
                elif snippet.startswith("["):
                    self.assertEqual(snippet.count("[mcp_servers.cloudseed]"), 1)
        codex = next(b for b in blocks if b["key"] == "codex")
        self.assertEqual([lab.split()[0] for lab, _ in codex["variants"]], ["HTTP", "stdio"])

    def test_guide_rows_are_whole_sentences(self):
        from cloudseed import mcp
        with mock.patch.object(mcp, "connected", return_value=None), mock.patch.object(mcp, "client_present", return_value=False):
            sections = dict(mcp.guide_lines(None))
        safety = next(v for k, v in sections.items() if k.startswith("5."))
        self.assertFalse(any(isinstance(r, str) and r.startswith(" ") for r in safety))
        self.assertTrue(all(isinstance(r, tuple) or r == "" or r.startswith("“") for r in sections["4. What you can ask"]))


class MCPLifecycleTest(Sandbox):
    """A real background MCP server (never launchd/systemd: --no-service) on a free ephemeral port."""

    def deploy(self, *extra) -> int:
        for _ in range(5):
            port = _free_port()
            rc, out = self.cs("setup", "mcp", "-y", "--no-service", "--port", str(port), *extra)
            if not (rc == 2 and "in use by another program" in out):
                break          # (otherwise a parallel run took the port after _free_port looked: another one)
        self.ports.append(port)
        self.assertEqual(rc, 0, out)
        self.assertEqual((_health(port) or {}).get("server"), "cloudseed")
        self.assertEqual((_health(port) or {}).get("home"), self.home_id)      # this home's server, not another run's
        return port

    def test_rotate_then_undo_keeps_server_and_clients_in_step(self):
        port = self.deploy("--client", "cursor")
        cursor = self.user / ".cursor" / "mcp.json"
        old = (self.home / "mcp" / "token").read_text().strip()
        rc, out = self.cs("mcp", "token", "--rotate")
        self.assertEqual(rc, 0, out)
        new = (self.home / "mcp" / "token").read_text().strip()
        self.assertNotEqual(old, new)
        self.assertIn(new, cursor.read_text())
        self.assertNotIn(old, (self.home / "mcp" / "CONNECT.md").read_text())
        rc, out = self.cs("-y", "undo", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertEqual((self.home / "mcp" / "token").read_text().strip(), old)
        self.assertIn(old, cursor.read_text())
        rc, out = self.cs("mcp", "status")
        self.assertIn("running  protocol", out)
        self.assertNotIn("out of date", out)
        self.assertEqual((_health(port) or {}).get("server"), "cloudseed")

    def test_token_mismatch_orphans_and_port_changes(self):
        port = self.deploy("--client", "cursor")
        (self.home / "mcp" / "token").write_text("some-other-token\n")
        rc, out = self.cs("mcp", "status")
        self.assertIn("rejects the saved token", out)
        rc, out = self.cs("mcp", "start")
        self.assertEqual(rc, 1, out)
        self.assertIn("cs mcp restart", out)
        rc, out = self.cs("mcp", "restart")
        self.assertEqual(rc, 0, out)
        self.assertIn("running  protocol", self.cs("mcp", "status")[1])
        (self.home / "mcp" / "server.pid").unlink()     # the pid file lost track of the server
        rc, out = self.cs("mcp", "stop")
        self.assertIn("MCP server stopped", out)
        self.assertIsNone(_health(port))
        port2 = self.deploy("--client", "none")
        self.assertIn(f"127.0.0.1:{port2}/mcp", (self.user / ".cursor" / "mcp.json").read_text())

    def test_stdio_switch_removes_service_and_token_and_is_kept(self):
        port = self.deploy("--client", "cursor")
        rc, out = self.cs("setup", "mcp", "-y", "--transport", "stdio", "--client", "none")
        self.assertEqual(rc, 0, out)
        self.assertIsNone(_health(port))
        self.assertFalse((self.home / "mcp" / "token").exists())
        entry = json.loads((self.user / ".cursor" / "mcp.json").read_text())["mcpServers"]["cloudseed"]
        self.assertEqual(entry["args"][-2:], ["mcp", "serve"])        # re-wired to stdio, not left on a dead URL
        rc, out = self.cs("setup", "mcp", "-y", "--client", "none")    # a plain re-run keeps stdio
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads((self.home / "mcp" / "server.json").read_text()), {"transport": "stdio"})
        self.assertNotIn("MCP server up", out)

    def test_bad_client_is_rejected_before_anything_changes(self):
        port = _free_port()
        rc, out = self.cs("setup", "mcp", "-y", "--no-service", "--port", str(port), "--client", "bogus")
        self.assertEqual(rc, 2, out)
        self.assertFalse((self.home / "mcp").exists())
        self.assertNotIn("mcp", self.settings())
        self.assertNotEqual((_health(port) or {}).get("home"), self.home_id)   # no server of this home was started

    def test_client_all_means_detected_clients_only(self):
        rc, out = self.cs("setup", "mcp", "-y", "--transport", "stdio", "--client", "all")
        self.assertEqual(rc, 0, out)
        for missing in (".codeium", ".codex", ".gemini"):  # none of these apps exists in this home / on this PATH
            self.assertFalse((self.user / missing).exists(), missing)
        self.assertNotIn("Claude Code: 1", out)

    def test_small_cli_edges(self):
        rc, out = self.cs("destroy", "mcp")
        self.assertEqual(rc, 3, out)
        self.assertIn("--auto-approve", out)
        rc, out = self.cs("mcp", "logs", "-n", "0")
        self.assertEqual(rc, 2, out)
        rc, out = self.cs("mcp")
        self.assertEqual(rc, 0, out)
        self.assertIn("cloudseed MCP server", out)
        rc, out = self.cs("mcp", "connect", "cursor", "--transport", "http")
        self.assertIn("No HTTP server is deployed", out)

    def test_config_is_raw_and_tools_fit_the_width(self):
        (self.home / "mcp").mkdir()
        (self.home / "mcp" / "server.json").write_text(json.dumps({"transport": "http", "host": "127.0.0.1", "port": 7578, "auth": "token"}))
        (self.home / "mcp" / "token").write_text("T" * 64 + "\n")
        rc, out = self.cs("mcp", "config")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("│", out)
        self.assertIn('"Authorization": "Bearer ' + "T" * 64 + '"', out)
        self.assertIn("-- HTTP", out)
        rc, out = self.cs("mcp", "tools")
        self.assertEqual(rc, 0, out)
        from cloudseed import mcp
        rows = [l for l in out.splitlines() if l.startswith("  │ cloudseed_")]
        self.assertEqual(len(rows), len(mcp.TOOLS))                     # one row per tool: nothing wrapped
        self.assertTrue(all(len(l) <= 100 for l in out.splitlines()))


# ------------------------------------------------------------------------------------------------ web console

class UITest(Sandbox):
    def test_guards(self):
        rc, out = self.cs("ui", "token")
        self.assertEqual(rc, 1, out)
        self.assertIn("cs enable ui", out)
        rc, out = self.cs("ui", "restart")
        self.assertEqual(rc, 1, out)
        self.assertIn("disabled", out)
        self.assertFalse((self.home / "ui" / "server.pid").exists())
        rc, out = self.cs("ui", "logs", "-n", "0")
        self.assertEqual(rc, 2, out)

    def test_busy_port_changes_nothing(self):
        port = _free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            (self.home / "ui").mkdir()
            (self.home / "ui" / "server.json").write_text(json.dumps({"service": "background"}))
            rc, out = self.cs("enable", "ui", "--port", str(port), "--no-open")
        self.assertEqual(rc, 2, out)
        self.assertIn("in use by another program", out)
        self.assertNotIn("ui", self.settings())
        self.assertEqual(self.journal(), {})


# ------------------------------------------------------------------------------------------------ parser

class ParserTest(Sandbox):
    def test_messages(self):
        rc, out = self.cs("status")
        self.assertEqual(rc, 2, out)
        self.assertIn("aws, gcp, azure or vmware", out)
        rc, out = self.cs("deps")
        self.assertIn("needs a subcommand: status | install", out)
        self.assertNotIn("deps_cmd", out)
        rc, out = self.cs("k8s")
        self.assertIn("a subcommand: info | kubeconfig", out)
        self.assertIn("a cloud", out)
        self.assertNotIn("k8s_cmd", out)
        rc, out = self.cs("--foo")
        self.assertIn("unknown option '--foo'", out)
        rc, out = self.cs("deps", "install", "--bogus", "terraform")
        self.assertIn("usage: cloudseed deps install", out)
        rc, out = self.cs("-y")
        self.assertEqual(rc, 0, out)
        self.assertIn("USAGE", out)
        rc, out = self.cs("enable", "bogus")
        self.assertNotIn("did you mean", out)
        rc, out = self.cs("enable", "agentc")
        self.assertIn("did you mean agentic", out)
        rc, out = self.cs("do")
        self.assertIn("Examples for cloudseed agentic", out)

    def test_default_environment_hint_only_where_it_applies(self):
        rc, out = self.cs("status")
        self.assertIn("cloudseed env use <id>", out)
        rc, out = self.cs("setup")
        self.assertEqual(rc, 2, out)
        self.assertIn("aws, gcp, azure or vmware", out)
        self.assertNotIn("env use", out)                    # setup never picks an existing environment

    def test_orphan_kill_only_targets_our_http_server(self):
        from cloudseed import cli
        cases = {"/usr/bin/python3 /x/bin/cloudseed mcp serve --http --host 127.0.0.1 --port 7434": True,
                 "/opt/cloudseed mcp serve --http": True,
                 "node /y/some-mcp-server.js serve --stdio": False,
                 "/x/bin/cloudseed mcp serve": False,
                 "python3 mcp_tool.py --http serve": False}
        for cmdline, want in cases.items():   # one check for the CLI and mcp.stop(): mcp._is_our_server
            with mock.patch.object(cli.mcp, "_cmdline", return_value=cmdline), mock.patch.object(cli.mcp.os, "kill"):
                self.assertEqual(cli._pid_is_mcp_server(4242), want, cmdline)

    def test_env_use_without_id(self):
        self.make_env("aws-dev")
        rc, out = self.cs("env", "use")
        self.assertEqual(rc, 2, out)
        self.assertIn("Usage: cs env use <id>", out)
        self.assertNotIn("'None'", out)

    def test_commands_default_to_the_current_or_only_environment(self):
        from cloudseed import cli, paths
        dev = paths.Env("aws", "dev")
        with mock.patch.object(paths.Env, "list_all", return_value=[dev]), mock.patch.object(paths, "load_settings", return_value={}):
            self.assertEqual(cli._default_env_argv(["status"]), ["status", "aws", "--env", "dev"])
            self.assertEqual(cli._default_env_argv(["-y", "vpn", "add-user", "bob"]), ["-y", "vpn", "add-user", "aws", "--env", "dev", "bob"])
            self.assertEqual(cli._default_env_argv(["ssh", "--", "uname"]), ["ssh", "aws", "--env", "dev", "--", "uname"])
            self.assertEqual(cli._default_env_argv(["status", "gcp"]), ["status", "gcp"])
            self.assertEqual(cli._default_env_argv(["status", "mcp"]), ["status", "mcp"])
            self.assertEqual(cli._default_env_argv(["setup"]), ["setup"])      # creating is never implicit
        two = [dev, paths.Env("gcp", "dev")]
        with mock.patch.object(paths.Env, "list_all", return_value=two), mock.patch.object(paths, "load_settings", return_value={}):
            self.assertEqual(cli._default_env_argv(["status"]), ["status"])    # ambiguous: the parser asks
        with mock.patch.object(paths.Env, "list_all", return_value=two), \
                mock.patch.object(paths, "load_settings", return_value={"current_env": "gcp-dev"}):
            self.assertEqual(cli._default_env_argv(["inventory"]), ["inventory", "gcp", "--env", "dev"])


if __name__ == "__main__":
    unittest.main()
