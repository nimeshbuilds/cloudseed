"""Regression tests for the wave-2 cli-tools items: global options that are malformed are usage errors (not the
overview), the built-in agent only falls back to a Claude Code that is installed AND logged in, `creds set` reports the
stored (normalised) value and warns about a path that does not exist, `undo --drop` needs no Terraform, stderr hints
drop ANSI codes when redirected, a parse-time Abort is shown, and the argparse help texts the handoffs asked for.

CLI runs use a fresh CLOUDSEED_HOME and HOME and a PATH without terraform or real agent CLIs; nothing is installed,
no server is started, and no network is used."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

ROOT = Path(__file__).resolve().parent.parent
CS = str(ROOT / "bin" / "cloudseed")
sys.path.insert(0, str(ROOT))

from cloudseed import agents, builtin_agent, cli, ui  # noqa: E402


def _parse(*argv):
    with contextlib.redirect_stderr(io.StringIO()):
        return cli.build_parser().parse_args(cli.normalize_argv(list(argv)))


def _help_text(*argv) -> str:
    """`cloudseed <argv> --help`, whitespace-normalised (argparse wraps long help strings)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            cli.build_parser().parse_args(list(argv) + ["--help"])
        except SystemExit:
            pass
    return " ".join(out.getvalue().split())


@contextlib.contextmanager
def _colour_on():
    saved = (ui._COLOR, ui._TRUECOLOR, ui._256, ui.RESET, ui.BOLD)
    ui._COLOR, ui._TRUECOLOR, ui._256, ui.RESET, ui.BOLD = True, True, True, "\033[0m", "\033[1m"
    try:
        yield
    finally:
        ui._COLOR, ui._TRUECOLOR, ui._256, ui.RESET, ui.BOLD = saved


class Sandbox(unittest.TestCase):
    """A fresh cloudseed home and user home, and a PATH with only python and the system dirs (no terraform)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w2-tools-"))
        self.home, self.user, self.bin = self.tmp / "cs", self.tmp / "home", self.tmp / "bin"
        for d in (self.home, self.user, self.bin):
            d.mkdir()
        os.symlink(sys.executable, self.bin / "python3")
        self.env = {"CLOUDSEED_HOME": str(self.home), "HOME": str(self.user), "NO_COLOR": "1", "COLUMNS": "100",
                    "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
                    "ANTHROPIC_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": "", "CLAUDE_CODE_OAUTH_TOKEN": ""}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cs(self, *args, cwd: Path | None = None):
        p = subprocess.run([sys.executable, CS, *args], env=self.env, capture_output=True, text=True, timeout=120,
                           stdin=subprocess.DEVNULL, cwd=str(cwd or self.tmp))
        return p.returncode, p.stdout + p.stderr

    def fake_tool(self, name: str, body: str) -> None:
        p = self.bin / name
        p.write_text("#!/bin/bash\n" + body + "\n")
        p.chmod(0o755)

    def journal(self) -> dict:
        try:
            return json.loads((self.home / "undo.json").read_text())
        except OSError:
            return {}

    def vault(self) -> dict:
        try:
            return json.loads((self.home / "credentials.json").read_text())
        except OSError:
            return {}


# ---------------------------------------------------------------- global options (cli-parser remaining item)

class GlobalOptionsTest(unittest.TestCase):
    def test_only_well_formed_global_options_count(self):
        self.assertTrue(cli._only_global_flags(["-y"]))
        self.assertTrue(cli._only_global_flags(["--runtime", "local", "-y"]))
        self.assertTrue(cli._only_global_flags(["--engine=podman", "--yes"]))
        for argv in (["--runtime"], ["--runtime", "bogus"], ["--runtime=bogus"], ["--engine", "lxc"], ["-y", "list"], []):
            self.assertFalse(cli._only_global_flags(argv), argv)
        self.assertEqual(cli._skip_global_options(["-y", "--runtime", "local", "setup", "mcp"]), 3)
        self.assertEqual(cli._skip_global_options(["--runtime", "bogus", "list"]), 0)

    def test_mcp_alias_still_skips_leading_global_options(self):
        self.assertEqual(cli.normalize_argv(["-y", "--runtime", "local", "setup", "mcp"]),
                         ["-y", "--runtime", "local", "mcp", "setup"])
        self.assertEqual(cli.normalize_argv(["--engine=docker", "destroy", "-y", "mcp"]),
                         ["--engine=docker", "mcp", "uninstall", "-y"])

    def _dispatch(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli._dispatch(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_bad_global_option_value_is_a_usage_error_not_the_overview(self):
        for argv, why in ((["--runtime", "bogus"], "invalid choice: 'bogus'"), (["--runtime=bogus"], "invalid choice: 'bogus'"),
                          (["--runtime"], "expected one argument"), (["-y", "--engine", "lxc"], "invalid choice: 'lxc'")):
            rc, out, err = self._dispatch(*argv)
            self.assertEqual(rc, 2, (argv, out, err))
            self.assertIn(why, err)
            self.assertNotIn("unknown command", err)          # it is an option value, not a command typo
            self.assertNotIn("USAGE", out)                    # and not the overview either

    def test_global_options_alone_still_show_the_overview(self):
        rc, out, _ = self._dispatch("--runtime", "local", "-y")
        self.assertEqual(rc, 0)
        self.assertIn("USAGE", out)

    def test_command_typo_is_still_an_unknown_command(self):
        rc, _, err = self._dispatch("lisst")
        self.assertEqual(rc, 2)
        self.assertIn("unknown command 'lisst'", err)

    def test_trailing_yes_is_accepted_by_every_simple_command(self):
        for argv in (["list"], ["agents"], ["env"], ["explain", "agentic"], ["help", "list"], ["skill", "list"],
                     ["skill", "show", "aws"], ["deps", "status"], ["deps", "runtime", "local"], ["deps", "image"],
                     ["model"], ["use", "builtin"], ["enable", "headliner"], ["disable", "headliner"], ["creds"],
                     ["undo", "--list"], ["doctor", "aws"], ["ssh", "aws"]):
            ns = _parse(*argv, "-y")
            self.assertTrue(ns.yes, argv)

    def test_parse_time_abort_is_shown(self):
        class Boom:
            def parse_args(self, argv):
                raise ui.Abort("the post-parse hook said no", code=2)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "build_parser", return_value=Boom()), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            rc = cli._dispatch(["list"])
        self.assertEqual(rc, 2)
        self.assertIn("the post-parse hook said no", err.getvalue())


# ---------------------------------------------------------------- stderr hints drop ANSI when redirected (cli-ux#25)

class StderrHintsTest(unittest.TestCase):
    def test_unknown_help_topic_is_plain_on_a_redirected_stderr(self):
        err = io.StringIO()                                   # not a terminal: like `cs help nope 2>err.log`
        with _colour_on(), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli.cmd_help(argparse.Namespace(topic="nosuchtopicxyz", cloud=None), {})
        self.assertEqual(rc, 2)
        self.assertTrue(err.getvalue().strip())
        self.assertNotIn("\x1b[", err.getvalue())

    def test_default_env_note_is_plain_on_a_redirected_stderr(self):
        env = mock.Mock(id="aws-dev", cloud="aws")
        env.name = "dev"
        err = io.StringIO()
        with _colour_on(), contextlib.redirect_stderr(err), \
                mock.patch.object(cli.paths.Env, "list_all", return_value=[env]), \
                mock.patch.object(cli.paths, "load_settings", return_value={}):
            argv = cli._default_env_argv(["status"])
        self.assertEqual(argv, ["status", "aws", "--env", "dev"])
        self.assertIn("(status: aws-dev, the only environment)", err.getvalue())
        self.assertNotIn("\x1b[", err.getvalue())


# ---------------------------------------------------------------- built-in agent's Claude Code fallback (agentic#13)

class ClaudeFallbackTest(unittest.TestCase):
    def ready(self, claude_state: str, **kw):
        """_ensure_agent_ready('builtin') with no API key and Claude Code in the given state."""
        installed = claude_state != "missing"
        calls = []
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(builtin_agent, "has_api_credentials", return_value=False), \
                mock.patch.object(agents, "installed", side_effect=lambda s: ("/x/claude" if installed else None)
                                  if s.get("key") == "claude" else "builtin"), \
                mock.patch.object(agents, "auth_ok", side_effect=lambda s: claude_state == "ready"), \
                mock.patch.object(cli, "_ensure_agent_skills", side_effect=lambda k, s: calls.append(k)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                spec = cli._ensure_agent_ready("builtin", {}, persist=False, **kw)
                exc = None
            except ui.Abort as e:
                spec, exc = None, e
        return spec, exc, calls, out.getvalue() + err.getvalue()

    def test_not_logged_in_claude_is_never_used(self):
        spec, exc, calls, _ = self.ready("login", require_creds=True)
        self.assertIsNotNone(exc)
        self.assertIn("installed but not logged in", str(exc))
        self.assertNotIn("cloudseed use claude ", str(exc))   # would not work until it is logged in
        self.assertEqual(calls, [])                           # ~/.claude is not touched for a CLI we will not use
        spec, exc, calls, text = self.ready("login")
        self.assertIsNone(exc)
        self.assertTrue(spec.get("builtin"))                  # the choice is kept ...
        self.assertIn("installed but not logged in", text)    # ... with a warning saying how to make it work
        self.assertNotIn("logged-in Claude Code CLI until", text)
        self.assertEqual(calls, [])

    def test_logged_in_claude_is_the_fallback(self):
        spec, exc, calls, text = self.ready("ready")
        self.assertIsNone(exc)
        self.assertIn("run through your logged-in Claude Code CLI", text)
        self.assertEqual(calls, ["claude"])
        _, exc, calls, text = self.ready("ready", require_creds=True)
        self.assertIsNone(exc)
        self.assertNotIn("run through your logged-in", text)  # `do` says it itself, right before running
        self.assertEqual(calls, ["claude"])

    def test_missing_claude_advises_installing_it(self):
        _, exc, calls, _ = self.ready("missing", require_creds=True)
        self.assertIn("npm install -g @anthropic-ai/claude-code", str(exc))
        self.assertEqual(calls, [])

    def test_do_routes_to_claude_only_when_it_is_logged_in(self):
        args = argparse.Namespace(agent=None, task=["list", "envs"], force=True, model=None, no_headliner=True,
                                  show_prompt=False, interactive=False)
        builtin = agents.get("builtin")
        for state, routed in (("ready", "claude"), ("login", None)):
            run = mock.Mock(return_value=0)
            with mock.patch.object(cli, "_ensure_agent_ready", return_value=builtin), \
                    mock.patch.object(builtin_agent, "has_api_credentials", return_value=False), \
                    mock.patch.object(builtin_agent, "claude_fallback", return_value=(agents.get("claude"), state)), \
                    mock.patch.object(agents, "describe"), mock.patch.object(agents, "run", run), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                if routed:
                    self.assertEqual(cli.cmd_do(args, {"agent": "builtin", "agentic": True}), 0)
                    self.assertEqual(run.call_args[0][0]["key"], "claude")
                else:
                    with self.assertRaises(ui.Abort):
                        cli.cmd_do(args, {"agent": "builtin", "agentic": True})
                    run.assert_not_called()


class ClaudeFallbackCliTest(Sandbox):
    def test_use_and_do_with_a_claude_that_is_not_logged_in(self):
        ran = self.tmp / "claude-ran.log"
        # `claude auth status --json` prints nothing useful and there is no login file: not logged in
        self.fake_tool("claude", f'if [ "$1" = -p ]; then echo "$@" >> {ran}; fi\necho "fake-claude $*"')
        rc, out = self.cs("use", "builtin")
        self.assertEqual(rc, 0, out)
        self.assertIn("installed but not logged in", out)
        self.assertNotIn("✔ no API key; will use your logged-in Claude Code", out)
        self.assertFalse((self.user / ".claude" / "skills").exists())
        self.assertEqual(json.loads((self.home / "settings.json").read_text())["agent"], "builtin")
        rc, out = self.cs("do", "--force", "list envs")
        self.assertEqual(rc, 1, out)
        self.assertEqual(out.count("needs Anthropic API credentials"), 1)
        self.assertFalse(ran.exists())                        # the task never went to a Claude Code that cannot run it
        # once Claude Code is logged in, the same command runs through it
        (self.user / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "t@example.com"}}))
        rc, out = self.cs("do", "--force", "list envs")
        self.assertEqual(rc, 0, out)
        self.assertIn("runs through your Claude Code CLI", out)
        self.assertTrue(ran.exists())


# ---------------------------------------------------------------- creds set (agentic#24 / docs-skills#28)

class CredsSetTest(Sandbox):
    KEY = "GOOGLE_APPLICATION_CREDENTIALS"

    def test_path_values_are_reported_as_stored_and_checked(self):
        rc, out = self.cs("creds", "set", f"{self.KEY}=missing.json", cwd=self.user)
        self.assertEqual(rc, 0, out)
        stored = self.vault()[self.KEY]
        self.assertTrue(os.path.isabs(stored))
        self.assertIn(f"as {stored}", " ".join(out.split()))  # the user sees where it really points
        self.assertIn("does not exist (yet)", out)
        (self.user / "key.json").write_text("{}")
        rc, out = self.cs("creds", "set", f"{self.KEY}=key.json", cwd=self.user)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("does not exist", out)
        # the same file given another way is the same stored value: no change, no second undo entry
        rc, out = self.cs("creds", "set", f"{self.KEY}=./key.json", cwd=self.user)
        self.assertEqual(rc, 0, out)
        self.assertIn("unchanged", out)
        self.assertEqual(len(self.journal().get("global", [])), 2)
        rc, out = self.cs("-y", "undo", "--global", "--auto-approve")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.vault()[self.KEY], stored)      # back to the previous (normalised) value

    def test_refused_names_change_nothing(self):
        rc, out = self.cs("creds", "set", "MY_TOKEN=abc", "PYTHONPATH=/x")
        self.assertEqual(rc, 2, out)
        self.assertIn("cannot be stored in the vault", out)
        self.assertNotIn("Unexpected error", out)
        self.assertEqual(self.vault(), {})
        self.assertEqual(self.journal(), {})
        rc, out = self.cs("creds", "set", "BAD KEY=v")
        self.assertEqual(rc, 2, out)
        self.assertIn("not a variable name", out.lower())


# ---------------------------------------------------------------- undo --drop needs no Terraform (cli-lifecycle#33)

class UndoDropWithoutTerraformTest(Sandbox):
    def test_drop_is_not_gated_on_the_runtime(self):
        self.assertIsNone(shutil.which("terraform", path=self.env["PATH"]))
        entry = {"id": "e1", "scope": "aws-gone", "kind": "config", "summary": "setup aws-gone",
                 "at": "2026-01-01T00:00:00+00:00", "data": {"prev_cfg": {}}}
        (self.home / "undo.json").write_text(json.dumps({"aws-gone": [entry]}))
        rc, out = self.cs("-y", "undo", "aws", "--env", "gone")          # a real undo still checks the tools first
        self.assertEqual(rc, 2, out)
        self.assertIn("Missing required tools", out)
        rc, out = self.cs("-y", "undo", "aws", "--env", "gone", "--drop")
        self.assertEqual(rc, 0, out)
        self.assertIn("Dropped from the undo history", out)
        self.assertNotIn("Missing required tools", out)
        self.assertFalse(self.journal().get("aws-gone"))


# ---------------------------------------------------------------- skill show (cli-ux#17 / mcp#31)

class SkillShowTest(Sandbox):
    def test_show_needs_one_known_skill(self):
        for name in ("all", "../cloudseed", "nope"):
            rc, out = self.cs("skill", "show", name)
            self.assertEqual(rc, 2, (name, out))
            self.assertIn("aws", out)                         # the available skills are listed
            self.assertNotIn("Unexpected error", out)
        rc, out = self.cs("skill", "show", "aws")
        self.assertEqual(rc, 0, out)
        self.assertIn("name: cloudseed-aws", out)


# ---------------------------------------------------------------- argparse help texts (vmware#11, ansible#31, agentic#2)

class HelpTextTest(unittest.TestCase):
    def test_setup_and_provision_help(self):
        setup = _help_text("setup")
        self.assertIn("first free private /16; vmware: VMware's host-only vmnet", setup)
        self.assertIn("an existing one keeps its list", setup)
        self.assertIn("an existing environment is left unchanged", setup)
        harden = "the host firewall and IP forwarding stay (use --no-firewall)"
        self.assertIn(harden, setup)
        provision = _help_text("provision")
        self.assertIn(harden, provision)
        self.assertIn("without the nftables host firewall", provision)
        self.assertIn("without installing terraform / cloud CLI", provision)
        self.assertIn("instead of your detected public IP", _help_text("update-ip"))

    def test_interactive_flag_says_external_agents_only(self):
        self.assertIn("(external agents only)", _help_text("agentic"))


# ---------------------------------------------------------------- install vmware-provider announces (vmware#26)

class InstallProviderTest(unittest.TestCase):
    def test_provider_install_always_reports(self):
        from cloudseed import localvm
        args = argparse.Namespace(what=["vmware-provider"], rebuild=False, agent=None, dir=None, project=False,
                                  engine=None, from_path=None)
        with mock.patch.object(localvm, "ensure_provider") as ensure, \
                mock.patch.object(cli, "_record_installed"), \
                mock.patch.object(cli.undo, "listing", return_value=set()), \
                mock.patch.object(cli.undo, "new_files_since", return_value=[]):
            self.assertEqual(cli.cmd_install(args, {}), 0)
        ensure.assert_called_once_with(rebuild=False, announce=True)


if __name__ == "__main__":
    unittest.main()
