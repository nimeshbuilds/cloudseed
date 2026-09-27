"""Regression tests for the wave-4 cli-tools items: argparse help and types (--last, platform/mcp/ui actions, --var,
--env, chaos --target, agentic task), choice groups at 60 columns, exit 141 on a cut pipe, status/output without
terraform, the container engine asked for (deps runtime/image, the runtime gate), `deps install all <tool>`, undoable
install directories and terraform upgrades, `install` failures, skill listing, the shared Claude fallback text,
credential values (strip + check_value), `ui status/stop` with a leftover login item, the undo --drop hint, the MCP
status/tools/test/connect/start/setup changes (auth and service kept, was_enabled, --no-auth), MCP prompt hints,
typed confirmations, and the did-you-mean fixes.

Nothing here installs software, starts a server or touches the network: installers, services and servers are mocked,
and CLI runs use a fresh CLOUDSEED_HOME and HOME."""
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

from cloudseed import agents, builtin_agent, cli, creds, mcp, skills, ui, webui  # noqa: E402


def _capture(fn, *a, **k):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            result = fn(*a, **k)
        except SystemExit as e:
            if isinstance(e, ui.Abort):
                ui.show_abort(e)
            result = e.code
    return result, out.getvalue()


def _parse(*argv):
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        return cli.build_parser().parse_args(cli.normalize_argv(list(argv)))


def _parse_error(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(io.StringIO()), \
            mock.patch.object(sys, "argv", ["cloudseed", *argv]):
        try:
            cli.build_parser().parse_args(argv)
        except SystemExit as e:
            return e.code, buf.getvalue()
    return 0, buf.getvalue()


def _help(*argv) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            cli.build_parser().parse_args(list(argv) + ["-h"])
        except SystemExit:
            pass
    return " ".join(out.getvalue().split())


class Sandbox(unittest.TestCase):
    """A fresh cloudseed home and user home, and a PATH with only python and the system dirs."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4-tools-"))
        self.home, self.user, self.bin = self.tmp / "cs", self.tmp / "home", self.tmp / "bin"
        for d in (self.home, self.user, self.bin):
            d.mkdir()
        os.symlink(sys.executable, self.bin / "python3")
        for tool in ("launchctl", "systemctl"):   # never a real login service
            (self.bin / tool).write_text("#!/bin/sh\nexit 1\n")
            (self.bin / tool).chmod(0o755)
        self.env = {"CLOUDSEED_HOME": str(self.home), "HOME": str(self.user), "NO_COLOR": "1", "COLUMNS": "100",
                    "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cs(self, *args, env: dict | None = None):
        p = subprocess.run([sys.executable, CS, *args], env=dict(self.env, **(env or {})), capture_output=True, text=True,
                           timeout=120, stdin=subprocess.DEVNULL, cwd=str(self.tmp))
        return p.returncode, p.stdout + p.stderr


# ---------------------------------------------------------------- build_parser: help text and types

class ParserHelpTest(unittest.TestCase):
    def test_last_must_be_positive(self):
        for argv in (["troubleshoot", "aws", "--last", "0"], ["inventory", "aws", "--last", "-3"],
                     ["scan", "reports", "--last", "0"]):
            rc, err = _parse_error(argv)
            self.assertEqual(rc, 2, argv)
            self.assertIn("must be 1 or more", err, argv)
        self.assertEqual(_parse("inventory", "aws", "--last", "3").last, 3)

    def test_action_lists_come_from_the_choices(self):
        top = _help()
        for word in ("list|info|plan|install|uninstall|status|ui|template",      # platform: every action
                     "status|guide|connect|disconnect|tools|config|test",          # mcp: config included
                     "open|start|status|stop|restart|logs|token|serve"):           # ui: start included
            self.assertIn(word, top, word)

    def test_option_help_says_what_the_code_does(self):
        setup = _help("setup", "aws")
        self.assertIn("answer a setup question", setup)
        self.assertIn("declared type", setup)
        self.assertIn("refused with the flag to use", setup)
        self.assertNotIn("override any stack variable", setup)
        self.assertIn("read-only commands use the current environment", setup)
        self.assertIn("the private half of --ssh-public-key", setup)
        self.assertIn("only cloudseed's files", _help("destroy", "aws"))
        self.assertIn("[:port|port-name]", _help("chaos", "run"))
        plat = _help("platform", "install")
        self.assertIn("for the one named item (not its dependencies)", plat)
        self.assertIn("works with groups", plat)
        self.assertIn("-- makes the rest literal", _help("agentic"))
        self.assertNotIn("flags go before it", _help("agentic"))

    def test_mcp_auth_and_service_are_tri_state(self):
        self.assertIsNone(_parse("mcp", "setup").auth)             # None: keep what is deployed
        self.assertIsNone(_parse("mcp", "setup").service)
        self.assertIs(_parse("setup", "mcp", "--no-auth").auth, False)
        self.assertIs(_parse("mcp", "setup", "--no-service").service, False)
        self.assertIs(_parse("mcp", "serve", "--http", "--no-auth").auth, False)


@unittest.skipUnless(os.name == "posix", "needs a subprocess with COLUMNS")
class NarrowHelpTest(Sandbox):
    def test_choice_groups_fit_60_columns(self):
        for argv in (["vpn", "-h"], ["dr", "-h"], ["scan", "-h"], ["platform", "-h"]):
            rc, out = self.cs(*argv, env={"COLUMNS": "60"})
            self.assertEqual(rc, 0, out)
            wide = [line for line in out.splitlines() if len(line) > 60]
            self.assertEqual(wide, [], argv)
        rc, out = self.cs("vpn", "-h", env={"COLUMNS": "60"})
        self.assertIn("provision}", out)                      # nothing of the group is lost
        self.assertIn("{status,add-user,", out)

    def test_break_keeps_short_lines_and_piped_output(self):
        text = "usage: x {a,b}\n" + " " * 20 + "{status,add-user,revoke,users,connect,disconnect,provision}"
        got = cli._break_choice_groups(text, 58)
        self.assertTrue(all(len(line) <= 58 for line in got.splitlines()), got)
        self.assertEqual(got.replace("\n", "").replace(" ", ""), text.replace("\n", "").replace(" ", ""))
        self.assertEqual(cli._break_choice_groups("usage: short {a,b}", 58), "usage: short {a,b}")
        example = "  cs setup aws --var 'tags=" + json.dumps({f"k{i}": "v" for i in range(12)}, separators=(",", ":")) + "'"
        self.assertEqual(cli._break_choice_groups(example, 58), example)       # a JSON value in an example stays whole


# ---------------------------------------------------------------- _dispatch: pipes, runtime gate, engine

class DispatchTest(unittest.TestCase):
    def dispatch(self, argv, handler, ensure=None, choose=None):
        seen = {}

        def h(args, settings):
            seen["settings"] = dict(settings)
            return handler(args, settings)

        with mock.patch.dict(cli.HANDLERS, {argv[cli._command_index(argv)]: h}), \
                mock.patch.object(cli.deps, "ensure_runtime", side_effect=ensure or (lambda *a, **k: "local")) as er, \
                mock.patch.object(cli.container, "choose_engine", side_effect=choose or (lambda s, explicit=None: explicit or "docker")) as ce, \
                mock.patch.object(cli.container, "reexec", return_value=0) as rx, \
                mock.patch.object(cli, "_silence_stdout"), mock.patch.object(cli.paths, "IN_CONTAINER", False), \
                mock.patch.object(cli.paths, "load_settings", return_value={}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli._dispatch(list(argv))
        return rc, seen, er, ce, rx

    def test_a_cut_pipe_fails_a_changing_command_but_not_a_view(self):
        def broken(args, settings):
            raise BrokenPipeError
        self.assertEqual(self.dispatch(["creds", "unset", "X"], broken)[0], 141)
        self.assertEqual(self.dispatch(["list"], broken)[0], 0)
        self.assertEqual(self.dispatch(["creds", "list"], broken)[0], 0)
        self.assertEqual(self.dispatch(["install", "list"], broken)[0], 0)
        self.assertEqual(self.dispatch(["install", "go"], broken)[0], 141)

    def test_changes_nothing(self):
        ns = argparse.Namespace
        self.assertTrue(cli._changes_nothing(ns(cmd="mcp", mcp_cmd="status")))
        self.assertFalse(cli._changes_nothing(ns(cmd="mcp", mcp_cmd="setup")))
        self.assertTrue(cli._changes_nothing(ns(cmd="undo", list=True)))
        self.assertFalse(cli._changes_nothing(ns(cmd="undo", list=False)))
        self.assertTrue(cli._changes_nothing(ns(cmd="model", model=None, forget=None)))
        self.assertFalse(cli._changes_nothing(ns(cmd="setup")))
        self.assertFalse(cli._changes_nothing(ns(cmd="platform", platform_cmd="install")))

    def test_status_and_output_run_without_terraform_unless_the_container_is_wanted(self):
        refuse = mock.Mock(side_effect=ui.Abort("Missing required tools: terraform", code=2))
        for cmd in ("status", "output"):
            rc, _, er, _, rx = self.dispatch([cmd, "aws", "--env", "dev"], lambda a, s: 0, ensure=refuse)
            self.assertEqual(rc, 0, cmd)
            er.assert_not_called()
        rc, _, er, _, rx = self.dispatch(["status", "aws", "--env", "dev", "--runtime", "container"], lambda a, s: 0,
                                         ensure=lambda *a, **k: "container")
        er.assert_called_once()
        rx.assert_called_once()                                    # a container user still runs it in the container

    def test_boolean_switches_are_read_like_every_other(self):
        seen = {}

        def h(args, settings):
            seen["ni"] = ui.NON_INTERACTIVE
            return 0
        for value, want in (("1", True), ("yes", True), ("on", True), ("false", False), ("0", False), ("no", False)):
            with mock.patch.dict(os.environ, {"CLOUDSEED_NONINTERACTIVE": value}), mock.patch.object(ui, "NON_INTERACTIVE", False):
                self.dispatch(["list"], h)
            self.assertIs(seen["ni"], want, value)

    def test_a_dry_run_is_not_asked_to_install_the_optional_cloud_cli(self):
        from cloudseed import localvm
        for argv, nag in ((["setup", "azure", "--env", "dev", "--dry-run"], False), (["setup", "azure", "--env", "dev"], True),
                          (["plan", "azure", "--env", "dev"], False)):
            with mock.patch.dict(localvm.DRY_RUN_OK, {}):
                rc, _, er, _, _ = self.dispatch(argv, lambda a, s: 0)
            self.assertIs(er.call_args.kwargs.get("nag_optional"), nag, argv)

    def test_a_one_off_engine_reaches_the_gate_but_not_other_commands_settings(self):
        rc, seen, _, ce, _ = self.dispatch(["--engine", "podman", "setup", "aws", "--env", "dev", "--runtime", "container"],
                                           lambda a, s: 0, ensure=lambda *a, **k: "container")
        self.assertEqual(ce.call_args.kwargs.get("explicit"), "podman")
        rc, seen, _, _, _ = self.dispatch(["--engine", "podman", "creds", "list"], lambda a, s: 0)
        self.assertNotIn("engine", seen["settings"])                # `use`, `enable` ... would otherwise save it


# ---------------------------------------------------------------- deps / install

class DepsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4-deps-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        p = [mock.patch.object(cli.paths, "HOME", self.tmp), mock.patch.object(cli.paths, "BIN_DIR", self.bin),
             mock.patch.object(cli.undo, "BACKUPS", self.tmp / "undo-backups")]
        for x in p:
            x.start()
            self.addCleanup(x.stop)

    def test_runtime_checks_an_explicit_engine_before_saving_or_recording(self):
        ns = argparse.Namespace(deps_cmd="runtime", mode="local", engine="podman")
        missing = mock.Mock(side_effect=ui.Abort("Install podman first"))
        with mock.patch.object(cli.container, "choose_engine", missing), mock.patch.object(cli.paths, "save_settings") as save, \
                mock.patch.object(cli.undo, "record") as rec, \
                mock.patch.object(cli.undo, "snapshot_settings", return_value={"settings": {}, "what": ["runtime", "engine"]}):
            rc, out = _capture(cli.cmd_deps, ns, {})
        self.assertEqual(rc, 1, out)
        self.assertEqual(missing.call_args.kwargs.get("explicit"), "podman")
        save.assert_not_called()
        rec.assert_not_called()

    def test_image_passes_the_asked_for_engine(self):
        ns = argparse.Namespace(deps_cmd="image", engine="podman", rebuild=False)
        with mock.patch.object(cli.container, "choose_engine", return_value="podman") as ce, \
                mock.patch.object(cli.container, "image_exists", return_value=True), mock.patch.object(cli.paths, "save_settings"):
            rc, out = _capture(cli.cmd_deps, ns, {})
        self.assertEqual(rc, 0, out)
        self.assertEqual(ce.call_args.kwargs.get("explicit"), "podman")

    def run_deps_install(self, tools, installed=True):
        ns = argparse.Namespace(deps_cmd="install", tools=tools)
        calls = []
        with mock.patch.object(cli.deps, "install", side_effect=lambda t: calls.append(t) or installed), \
                mock.patch.object(cli.deps, "find", return_value=None), \
                mock.patch.object(cli, "_record_installed") as rec:
            rc, out = _capture(cli.cmd_deps, ns, {})
        return rc, out, calls, rec

    def test_all_is_expanded_in_place(self):
        rc, out, calls, _ = self.run_deps_install(["all", "openvpn"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(calls, ["terraform", "aws", "gcloud", "az", "openvpn"])
        rc, out, calls, rec = self.run_deps_install(["all", "bogus"])
        self.assertEqual(rc, 2, out)
        self.assertIn("bogus", out)
        self.assertEqual(calls, [])
        rc, out, calls, rec = self.run_deps_install(["go"], installed=False)
        self.assertEqual(rc, 1, out)
        rec.assert_called_once()                                     # recorded also when a tool failed

    def test_install_directories_are_undoable(self):
        (self.tmp / "go").mkdir()                                    # pre-created empty (the container runtime does it)

        def fake_install(tool):
            (self.tmp / "go" / "bin").mkdir(parents=True)
            (self.tmp / "go" / "bin" / "go").write_text("go")
            return True

        files: dict = {}
        with mock.patch.object(cli.deps, "install", side_effect=fake_install), mock.patch.object(cli.deps, "version_of", return_value=""):
            self.assertTrue(cli._install_tool("go", files))
        self.assertEqual(files, {str(self.tmp / "go"): None})
        files = {}
        (self.tmp / "venv-az").mkdir()
        (self.tmp / "venv-az" / "x").write_text("an older install")  # not ours to remove
        with mock.patch.object(cli.deps, "install", return_value=True), mock.patch.object(cli.deps, "version_of", return_value=""):
            cli._install_tool("az", files)
        self.assertEqual(files, {})

    def test_a_terraform_upgrade_keeps_the_old_binary_for_undo(self):
        old = self.bin / "terraform"
        old.write_text("terraform 1.5.0")

        def upgrade(tool):
            old.unlink()
            old.write_text("terraform 1.9.8 (new)")
            return True

        files: dict = {}
        with mock.patch.object(cli.deps, "version_of", return_value="1.5.0"), \
                mock.patch.object(cli.deps, "too_old", return_value=True), mock.patch.object(cli.deps, "install", side_effect=upgrade):
            self.assertTrue(cli._install_tool("terraform", files))
        backup = files[str(old)]
        self.assertEqual(Path(backup).read_text(), "terraform 1.5.0")
        # nothing replaced (the install failed): the copy is not kept
        files = {}
        with mock.patch.object(cli.deps, "version_of", return_value="1.5.0"), \
                mock.patch.object(cli.deps, "too_old", return_value=True), mock.patch.object(cli.deps, "install", return_value=False):
            self.assertFalse(cli._install_tool("terraform", files))
        self.assertEqual(files, {})
        self.assertEqual(sorted(p.name for p in (self.tmp / "undo-backups").iterdir()), [Path(backup).name])

    def test_install_fails_when_any_target_failed(self):
        ns = argparse.Namespace(what=["k9s", "tailscale"], agent=None, dir=None, project=False, rebuild=False, from_path=None,
                                engine=None)
        with mock.patch.object(cli.deps, "install", side_effect=lambda t: t == "k9s"), \
                mock.patch.object(cli.deps, "find", return_value=None), mock.patch.object(cli, "_record_installed") as rec:
            rc, out = _capture(cli.cmd_install, ns, {})
        self.assertEqual(rc, 1, out)
        self.assertIn("Failed to install: tailscale", out)
        self.assertIn("1 other target(s) installed", out)
        rec.assert_called_once()


# ---------------------------------------------------------------- agentic: skills, fallback, do

class SkillAndAgentTest(unittest.TestCase):
    def test_skill_list_describes_prompt_skills_and_partial_installs(self):
        def state(key):
            return {"claude": "partial", "grok": "n/a"}.get(key, "missing")    # grok has no skills_dir: state() says n/a
        with mock.patch.object(skills, "state", side_effect=state), mock.patch.object(skills, "foreign", return_value=["cloudseed-aws"]), \
                mock.patch.dict(os.environ, {"COLUMNS": "80"}):
            rc, out = _capture(cli.cmd_skill, argparse.Namespace(skill_cmd="list"), {})
        self.assertEqual(rc, 0, out)
        self.assertIn("sent in each task's prompt", out)
        self.assertNotIn("grok skills         n/a", out)
        self.assertIn("installed, except cloudseed-aws", out)                 # skills.state_text (a2-agentic)
        self.assertIn("left alone", out)
        rows = [line for line in out.splitlines() if line.startswith("  cloudseed")]
        self.assertTrue(rows and all(ui.vis_len(line) <= 80 for line in rows), rows)

    def test_automatic_skill_installs_skip_foreign_directories(self):
        dest = Path(tempfile.mkdtemp(prefix="cs-w4-skills-"))
        self.addCleanup(shutil.rmtree, dest, True)
        with mock.patch.object(skills, "installed", return_value=False), mock.patch.object(skills, "target_dir", return_value=dest), \
                mock.patch.object(skills, "install", return_value=[]) as inst:
            _capture(cli._ensure_agent_skills, "claude", {"skills_dir": str(dest), "display": "Claude Code"})
        self.assertEqual(inst.call_args.args[0], None)
        self.assertTrue(inst.call_args.kwargs.get("skip_foreign"))

    def test_the_fallback_text_is_builtin_agents(self):
        self.assertFalse(hasattr(cli, "_claude_fallback"))
        self.assertFalse(hasattr(cli, "_no_creds_msg"))
        with mock.patch.object(builtin_agent, "has_api_credentials", return_value=False), \
                mock.patch.object(builtin_agent, "claude_fallback", return_value=({}, "missing")):
            rc, out = _capture(cli._ensure_agent_ready, "builtin", {}, persist=False, require_creds=True)
        self.assertEqual(out.count("needs Anthropic API credentials"), 1)
        self.assertIn("npm install -g @anthropic-ai/claude-code", out)

    def run_do(self, spec, settings, task, argv=None):
        args = argparse.Namespace(agent=None, task=task, force=False, model=None, no_headliner=True, show_prompt=False,
                                  interactive=False, cmd="agentic")
        run = mock.Mock(return_value=0)
        with mock.patch.object(cli, "_ensure_agent_ready", return_value=spec), mock.patch.object(agents, "describe"), \
                mock.patch.object(agents, "run", run), mock.patch.object(agents, "selected_model", return_value=None), \
                mock.patch.object(cli, "_ARGV", argv):
            rc, out = _capture(cli.cmd_do, args, settings)
        return rc, out, run

    def test_a_prompt_skills_agent_is_told_to_follow_the_included_skill(self):
        rc, out, run = self.run_do(dict(agents.get("grok")), {"agentic": True}, ["list", "envs"])
        self.assertEqual(rc, 0, out)
        self.assertIn("Follow the cloudseed skill included above", run.call_args.args[1])
        rc, out, run = self.run_do(dict(agents.get("codex")), {"agentic": True}, ["list", "envs"])
        self.assertIn("Use the `cloudseed` skill", run.call_args.args[1])

    def test_a_flag_inside_the_task_is_explained(self):
        rc, out, run = self.run_do(dict(agents.get("codex")), {}, ["list", "--force", "envs"], argv=["do", "list", "--force", "envs"])
        self.assertEqual(rc, 1)
        self.assertIn("'--force' inside the task is read as task text", out)
        self.assertNotIn("pass --force for a one-off", out)
        rc, out, run = self.run_do(dict(agents.get("codex")), {}, ["list", "envs"], argv=["do", "list", "envs"])
        self.assertIn("pass --force for a one-off", out)
        run.assert_not_called()


# ---------------------------------------------------------------- creds

class CredsTest(unittest.TestCase):
    def set_(self, *items, typed=None):
        stored = {}
        with mock.patch.object(creds, "load", return_value={}), \
                mock.patch.object(creds, "set_", side_effect=lambda k, v: stored.__setitem__(k, v) or v), \
                mock.patch.object(creds, "save"), mock.patch.object(cli.undo, "record"), \
                mock.patch.object(creds, "path_warning", return_value=None), \
                mock.patch.object(cli.ui, "interactive", return_value=typed is not None), \
                mock.patch("getpass.getpass", return_value=typed or ""):
            rc, out = _capture(cli.cmd_creds, argparse.Namespace(creds_cmd="set", items=list(items), forget=False), {})
        return rc, out, stored

    def test_values_are_stripped_and_blank_ones_refused(self):
        rc, out, stored = self.set_("AWS_PROFILE= prod ")
        self.assertEqual(rc, 0, out)
        self.assertEqual(stored, {"AWS_PROFILE": "prod"})
        rc, out, stored = self.set_("AWS_PROFILE= ")
        self.assertEqual(rc, 2, out)
        self.assertIn("has no value", out)
        self.assertEqual(stored, {})
        rc, out, stored = self.set_("ANTHROPIC_API_KEY", typed="  sk-typed  ")
        self.assertEqual(stored, {"ANTHROPIC_API_KEY": "sk-typed"})
        rc, out, stored = self.set_("ANTHROPIC_API_KEY", typed="   ")
        self.assertEqual(stored, {})
        self.assertIn("empty input", out)

    def test_values_go_through_creds_check_value(self):
        with mock.patch.object(creds, "check_value", side_effect=ValueError("X is not a valid value")) as cv:
            rc, out, stored = self.set_("AWS_PROFILE=prod")
        self.assertEqual(rc, 2, out)
        self.assertIn("X is not a valid value", out)
        cv.assert_called()
        rc, out, stored = self.set_('GOOGLE_CREDENTIALS={"no": "type"}')
        self.assertEqual(rc, 2, out)
        self.assertIn("Google key file", out)


# ---------------------------------------------------------------- ui status / stop, undo hint

class UiCommandTest(unittest.TestCase):
    def ui(self, sub, settings, **patches):
        ns = argparse.Namespace(ui_cmd=sub, port=None, host=None, no_open=True, lines=50, rotate=False)
        with mock.patch.object(webui, "load_state", return_value={"host": "127.0.0.1", "port": 7560}), \
                mock.patch.object(webui, "running_pid", return_value=None), mock.patch.object(webui, "health", return_value=None), \
                mock.patch.multiple(webui, **patches) if patches else contextlib.nullcontext(), \
                mock.patch.object(cli.undo, "record") as rec:
            rc, out = _capture(cli.cmd_ui, ns, settings)
        return rc, out, rec

    def test_status_shows_a_leftover_login_item(self):
        rc, out, _ = self.ui("status", {"ui": False}, leftover_service=mock.Mock(
            return_value="a login item is still installed although the console is disabled: /x.plist  (remove it: cs disable ui)"))
        self.assertIn("Leftover", out)
        self.assertIn("cs disable ui", out)
        rc, out, _ = self.ui("status", {"ui": True}, leftover_service=mock.Mock(return_value=None))
        self.assertNotIn("Leftover", out)

    def test_stop_removes_a_disabled_consoles_login_item(self):
        remove = mock.Mock()
        with mock.patch.object(cli, "_ui_login_item", return_value="launchd"):
            rc, out, rec = self.ui("stop", {"ui": False}, stop=mock.Mock(return_value=False), remove_service=remove)
        self.assertEqual(rc, 0)
        remove.assert_called_once()
        self.assertIn("Removed the launchd login item the disabled console left behind", out)
        rec.assert_not_called()
        with mock.patch.object(cli, "_ui_login_item", return_value=None):
            rc, out, rec = self.ui("stop", {"ui": False}, stop=mock.Mock(return_value=False), remove_service=remove,
                                   leftover_service=mock.Mock(return_value=None))
        self.assertIn("console is disabled", out)
        self.assertEqual(remove.call_count, 1)                     # nothing left behind: nothing removed

    def test_stop_also_removes_a_login_item_an_older_version_left(self):
        # a disabled console's item under the old shared label: _ui_login_item only knows this home's own label
        remove = mock.Mock()
        with mock.patch.object(cli, "_ui_login_item", return_value=None):
            rc, out, rec = self.ui("stop", {"ui": False}, stop=mock.Mock(return_value=False), remove_service=remove,
                                   leftover_service=mock.Mock(return_value="a login item is still installed ..."))
        self.assertEqual(rc, 0)
        remove.assert_called_once()
        self.assertIn("Removed the login item the disabled console left behind", out)


class UndoHintTest(unittest.TestCase):
    def run_undo(self, code):
        entry = {"id": "e1", "scope": "global", "summary": "s", "at": "2026-09-24T10:00:00", "kind": "argv", "data": {"argv": ["x"]}}
        ns = argparse.Namespace(global_scope=False, cloud=None, env=None, list=False, drop=False, id=None, auto_approve=False,
                                undo_pick=(None, entry))
        with mock.patch.object(cli.undo, "perform", side_effect=ui.Abort("Nothing applied. Re-run with --auto-approve", code=code)), \
                mock.patch.object(cli.undo, "describe", return_value="run x"), mock.patch.object(cli.undo, "entries", return_value=[entry]):
            return _capture(cli.cmd_undo, ns, {})

    def test_the_drop_hint_follows_real_failures_only(self):
        rc, out = self.run_undo(3)
        self.assertEqual(rc, 3)
        self.assertNotIn("--drop", out)
        rc, out = self.run_undo(1)
        self.assertEqual(rc, 1)
        self.assertIn("To skip this step instead: cs undo --id e1 --drop", out)
        self.assertLess(out.index("Nothing applied"), out.index("To skip"))    # after the error, not before it


class UndoTailTest(unittest.TestCase):
    """a2-ops#16: 'cs destroy' is offered only when the environment still holds resources (and never right after
    undoing a `created` step, which destroyed everything itself)."""

    def run_undo(self, kind, has_resources, remaining=0):
        entry = {"id": "e1", "scope": "aws-dev", "summary": "setup aws-dev", "at": "2026-09-24T10:00:00", "kind": kind,
                 "data": {}}
        env = mock.Mock(cloud="aws", exists=mock.Mock(return_value=True))
        env.name = "dev"
        ns = argparse.Namespace(global_scope=False, cloud="aws", env="dev", list=False, drop=False, id=None,
                                auto_approve=True, undo_pick=("aws-dev", entry))
        with mock.patch.object(cli.undo, "perform"), mock.patch.object(cli.undo, "drop"), \
                mock.patch.object(cli.undo, "describe", return_value="x"), \
                mock.patch.object(cli.undo, "entries", return_value=[entry] * (remaining + 1)), \
                mock.patch.object(cli, "_env_of_scope", return_value=env), \
                mock.patch.object(cli, "_env_has_resources", return_value=has_resources), \
                mock.patch.object(cli.audit, "write"), mock.patch.dict(os.environ, {"COLUMNS": "200"}):
            return _capture(cli.cmd_undo, ns, {})

    def test_destroy_is_offered_only_for_deployed_resources(self):
        rc, out = self.run_undo("config", True)
        self.assertEqual(rc, 0, out)
        self.assertIn("No more undo steps for aws-dev; to go back further: cs destroy aws --env dev", out)
        rc, out = self.run_undo("config", False)                     # nothing deployed: nothing to destroy
        self.assertNotIn("cs destroy", out)
        self.assertIn("0 more undo step(s) for aws-dev", out)
        rc, out = self.run_undo("created", True)                     # its undo was the destroy
        self.assertNotIn("cs destroy", out)
        rc, out = self.run_undo("config", True, remaining=2)
        self.assertIn("2 more undo step(s)", out)
        self.assertNotIn("cs destroy", out)


@unittest.skipUnless(os.name == "posix", "runs the CLI")
class UndoCopiesTest(Sandbox):
    """a2-ops#14/#15: an 'info' step whose advice restores from a kept copy keeps the step (and the copy) until it is
    dropped; dropping any step says which copies went with it."""

    def journal(self, entry):
        (self.home / "undo.json").write_text(json.dumps({entry["scope"]: [entry]}))

    def test_info_step_with_a_copy_is_kept_and_its_drop_deletes_the_copy(self):
        copy = self.home / "undo" / "20260924-aws-gone"
        copy.mkdir(parents=True)
        (copy / "config.json").write_text("{}")
        self.journal({"id": "u1", "scope": "aws-gone", "summary": "destroy aws-gone --purge (nothing was deployed)",
                      "kind": "info", "at": "2026-09-24T10:00:00+00:00",
                      "data": {"advice": f"the configuration of aws-gone is in {copy}; copy it back", "backup_dir": str(copy)}})
        rc, out = self.cs("undo", "aws", "--env", "gone")
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing automatic to undo", out)
        self.assertIn("cs undo --id u1 --drop", out)
        self.assertTrue(copy.exists())                              # never orphaned, never deleted behind the advice
        self.assertIn("aws-gone", json.loads((self.home / "undo.json").read_text()))
        rc, out = self.cs("-y", "undo", "--id", "u1", "--drop")
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing was reverted", out)
        self.assertIn("were deleted", out)
        self.assertFalse(copy.exists())

    def test_info_step_without_a_copy_is_removed(self):
        self.journal({"id": "u2", "scope": "global", "summary": "install go", "kind": "info",
                      "at": "2026-09-24T10:00:00+00:00", "data": {"advice": "brew uninstall go"}})
        rc, out = self.cs("undo", "--global")
        self.assertEqual(rc, 0, out)
        self.assertIn("Removed 'install go' from the undo history (nothing was reverted)", out)
        self.assertFalse(json.loads((self.home / "undo.json").read_text()).get("global"))


# ---------------------------------------------------------------- MCP

class McpStatusTest(unittest.TestCase):
    def status(self, state, leftover, pid=None):
        with mock.patch.object(mcp, "load_state", return_value=state), mock.patch.object(mcp, "leftover_services", return_value=leftover), \
                mock.patch.object(mcp, "running_pid", return_value=pid), mock.patch.object(mcp, "health", return_value={"protocolVersion": "x"}), \
                mock.patch.object(cli, "_mcp_health_info", return_value={"pid": 5}), mock.patch.object(mcp, "connected", return_value=None), \
                mock.patch.object(mcp, "client_present", return_value=False), mock.patch.object(mcp, "enabled", return_value=True), \
                mock.patch.dict(os.environ, {"COLUMNS": "200"}):
            return _capture(cli._mcp_status, {"mcp": True})[1]

    def test_leftover_services_show_for_every_transport(self):
        out = self.status({"transport": "http", "port": 7560, "service": "background"}, ["/h/Library/LaunchAgents/io.cloudseed.mcp.plist"])
        self.assertIn("a launchd/systemd service of another kind is still installed", out)
        self.assertIn("cs mcp restart", out)
        out = self.status({"transport": "stdio"}, ["/h/.config/systemd/user/cloudseed-mcp.service"])
        self.assertIn("an HTTP server service is still installed", out)
        self.assertIn("cs setup mcp --transport stdio", out)
        self.assertNotIn("Leftover", self.status({"transport": "http", "port": 7560, "service": "launchd"}, []))

    def test_footer_follows_the_transport(self):
        out = self.status({"transport": "stdio"}, [])
        self.assertIn("cs mcp connect <client>|all", out)
        self.assertNotIn("cs mcp restart", out)
        self.assertIn("cs mcp restart", self.status({"transport": "http", "port": 7560, "service": "launchd"}, []))

    def test_no_auth_is_flagged(self):
        out = self.status({"transport": "http", "port": 7560, "service": "background", "auth": "none"}, [])
        self.assertIn("any local process can call every tool", out)


class McpToolsAndTestTest(unittest.TestCase):
    def test_tools_page_tags_always_and_sometimes_destructive_tools(self):
        with mock.patch.dict(os.environ, {"COLUMNS": "160"}):
            rc, out = _capture(cli._mcp_tools_page)
        self.assertIn("[confirm*] = only some uses do", out)
        rows = {line.split()[1]: line for line in out.splitlines() if "cloudseed_" in line and line.startswith("  │")}
        self.assertIn("[confirm]", rows["cloudseed_destroy"])
        self.assertIn("[confirm*]", rows["cloudseed_kubectl"])
        self.assertNotIn("[confirm", rows["cloudseed_list"])
        with mock.patch.dict(os.environ, {"COLUMNS": "80"}):          # the legend is never cut off with a panel title
            rc, out = _capture(cli._mcp_tools_page)
        self.assertIn("[confirm] = always needs confirm=true · [confirm*] = only some uses do", out)

    def test_one_check_for_our_server(self):
        with mock.patch.object(mcp, "_is_our_server", return_value=True) as check:
            self.assertTrue(cli._pid_is_mcp_server(4242))
        check.assert_called_once_with(4242)

    def test_replies_are_matched_by_id(self):
        replies = [{"jsonrpc": "2.0", "id": 4, "result": {"content": []}}, {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{}, {}, {}]}},
                   {"jsonrpc": "2.0", "id": 1, "result": {}}, {"jsonrpc": "2.0", "id": 3, "result": {"contents": []}}]
        out = "log line that is not json\n" + "\n".join(json.dumps(r) for r in replies) + "\n"
        with mock.patch.object(mcp, "enabled", return_value=True), \
                mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, out, "")):
            rc, text = _capture(cli._mcp_test, argparse.Namespace(http=False))
        self.assertEqual(rc, 0, text)
        self.assertIn("tools/list (3 tools)", text)


class McpConnectStartTest(unittest.TestCase):
    def connect(self, clients, transport, wiring, state):
        calls = []

        def fake_connect(k, want, st):
            calls.append((k, want))
            return f"wrote x ({want})"

        ns = argparse.Namespace(mcp_cmd="connect", clients=clients, transport=transport)
        with mock.patch.object(mcp, "load_state", return_value=state), mock.patch.object(cli, "_mcp_clients_wiring", return_value=wiring), \
                mock.patch.object(mcp, "connect", side_effect=fake_connect), mock.patch.object(mcp, "client_present", return_value=True), \
                mock.patch.object(mcp, "save_guide"), mock.patch.object(cli.undo, "record") as rec:
            rc, out = _capture(cli.cmd_mcp, ns, {"mcp": True})
        return rc, calls, rec

    def test_a_connected_client_keeps_its_transport(self):
        http = {"transport": "http", "port": 7560}
        rc, calls, rec = self.connect(["cursor", "codex"], None, {"cursor": "stdio"}, http)
        self.assertEqual(dict(calls), {"cursor": "stdio", "codex": "http"})
        self.assertEqual(rec.call_args.args[3], {"argv": ["mcp", "disconnect", "codex"]})   # only codex was new
        rc, calls, rec = self.connect(["cursor"], "http", {"cursor": "stdio"}, http)
        self.assertEqual(calls, [("cursor", "http")])
        self.assertEqual(rec.call_args.args[3], {"argv": ["mcp", "connect", "cursor", "--transport", "stdio"]})
        rc, calls, rec = self.connect(["cursor"], None, {"cursor": "http"}, {})            # its server is gone: stdio
        self.assertEqual(calls, [("cursor", "stdio")])

    def test_bare_connect_without_a_terminal_is_a_usage_error(self):
        with mock.patch.object(cli.ui, "interactive", return_value=False), mock.patch.object(mcp, "client_present", return_value=False), \
                mock.patch.object(mcp, "load_state", return_value={}):
            rc, out = _capture(cli.cmd_mcp, argparse.Namespace(mcp_cmd="connect", clients=[], transport=None), {"mcp": True})
        self.assertEqual(rc, 2)
        self.assertIn("cs mcp connect <client>... | all", out)

    def test_start_refuses_while_disabled(self):
        with mock.patch.object(mcp, "load_state", return_value={"transport": "http", "port": 7560}), \
                mock.patch.object(cli, "_mcp_start_checked") as start, mock.patch.object(cli.paths, "save_settings") as save:
            rc, out = _capture(cli.cmd_mcp, argparse.Namespace(mcp_cmd="start"), {"mcp": False})
        self.assertEqual(rc, 1)
        self.assertIn("cs enable mcp", out)
        start.assert_not_called()
        save.assert_not_called()


class McpSetupTest(unittest.TestCase):
    """cmd_mcp_setup with every service, server and client call mocked."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4-mcp-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.token = self.tmp / "token"
        self.saved_state: dict = {}
        self.records: list = []
        self.started: list = []

    def setup_mcp(self, prev, settings, *argv, healthy=True, interactive=False, confirm=True):
        args = _parse("mcp", "setup", "--client", "none", *argv)
        saved = {}

        def start(state):
            self.started.append(dict(state))
            return state.get("service") or "launchd"

        patches = [
            mock.patch.object(mcp, "load_state", return_value=dict(prev)),
            mock.patch.object(mcp, "save_state", side_effect=lambda s: self.saved_state.update(s)),
            mock.patch.object(mcp, "STATE_PATH", self.tmp / "server.json"), mock.patch.object(mcp, "TOKEN_PATH", self.token),
            mock.patch.object(mcp, "GUIDE_PATH", self.tmp / "CONNECT.md"),
            mock.patch.object(mcp, "ensure_token", side_effect=lambda rotate=False: self.token.write_text("tok\n")),
            mock.patch.object(mcp, "remove_service"), mock.patch.object(mcp, "start", side_effect=start),
            mock.patch.object(mcp, "health", return_value={"protocolVersion": "x"} if healthy else None),
            mock.patch.object(mcp, "print_guide"), mock.patch.object(mcp, "client_present", return_value=False),
            mock.patch.object(cli, "_mcp_kill_orphan"), mock.patch.object(cli, "_mcp_refresh", return_value=[]),
            mock.patch.object(cli, "_mcp_clients_wiring", return_value={}), mock.patch.object(cli, "_can_bind", return_value=True),
            mock.patch.object(cli, "_mcp_health_info", return_value=None), mock.patch.object(cli, "_log_tail", return_value=""),
            mock.patch.object(cli.paths, "save_settings", side_effect=lambda s: saved.update(s)),
            mock.patch.object(cli.undo, "BACKUPS", self.tmp / "backups"),
            mock.patch.object(cli.undo, "record", side_effect=lambda *a, **k: self.records.append(a)),
            mock.patch.object(cli.ui, "interactive", return_value=interactive),
            mock.patch.object(cli.ui, "confirm", return_value=confirm), mock.patch.object(cli.ui, "banner")]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            rc, out = _capture(cli.cmd_mcp_setup, args, settings)
        return rc, out, saved

    def test_auth_and_service_are_kept_on_a_rerun(self):
        prev = {"transport": "http", "host": "127.0.0.1", "port": 7561, "auth": "none", "service": "background", "no_service": True}
        rc, out, saved = self.setup_mcp(prev, {"mcp": True})
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.started[-1]["auth"], "none")
        self.assertEqual(self.started[-1]["service"], "background")
        self.assertTrue(self.started[-1]["no_service"])
        self.assertNotIn("changes", out)
        self.assertIn("Kept as a detached background process", out)
        rc, out, saved = self.setup_mcp(prev, {"mcp": True}, "--rotate-token")       # a token is required again
        self.assertEqual(self.started[-1]["auth"], "token")
        self.assertTrue(self.started[-1]["no_service"])
        self.assertIn("Auth changes: none -> bearer token", out)
        # at a terminal both opt-outs are offered back ("keep it that way?" - no)
        rc, out, saved = self.setup_mcp(prev, {"mcp": True}, "--transport", "http", interactive=True, confirm=False)
        self.assertEqual(self.started[-1]["auth"], "token")
        self.assertIsNone(self.started[-1]["service"])
        self.assertFalse(self.started[-1]["no_service"])
        self.assertIn("Service changes", out)

    def test_a_launchd_fallback_is_not_an_opt_out(self):
        self.assertFalse(cli._mcp_no_service({"transport": "http", "service": "background", "no_service": False}))
        self.assertTrue(cli._mcp_no_service({"transport": "http", "service": "background"}))     # an older state.json
        self.assertEqual(cli._mcp_restore_argvs({"transport": "http", "port": 7705, "service": "background", "no_service": False}, {}, True),
                         [["mcp", "setup", "-y", "--transport", "http", "--client", "none", "--port", "7705"]])

    def test_no_auth_warns_asks_and_drops_the_token(self):
        self.token.write_text("old\n")
        rc, out, saved = self.setup_mcp({}, {"mcp": False}, "--no-auth")
        self.assertEqual(rc, 0, out)
        self.assertIn("any local process or user", out)
        self.assertFalse(self.token.exists())                      # the server uses none: no token that looks valid
        rc, out, saved = self.setup_mcp({}, {"mcp": False}, "--no-auth", "--transport", "http", interactive=True, confirm=False)
        self.assertEqual(rc, 0, out)
        self.assertIn("Cancelled. Nothing was changed.", out)
        self.assertEqual(saved, {})                                # MCP was not switched on

    def test_a_failed_start_leaves_mcp_as_it_was(self):
        rc, out, saved = self.setup_mcp({}, {"mcp": False}, healthy=False)
        self.assertEqual(rc, 1, out)
        self.assertEqual(saved.get("mcp"), False)                  # switched on to start, then back off
        self.assertFalse(self.token.exists())                      # the token it created is gone again
        self.assertEqual(self.records, [])

    def test_undo_of_a_rerun_switches_a_disabled_mcp_off_again(self):
        prev = {"transport": "http", "host": "127.0.0.1", "port": 7561, "auth": "token", "service": "launchd", "no_service": False}
        rc, out, saved = self.setup_mcp(prev, {"mcp": False})
        self.assertEqual(rc, 0, out)
        then = self.records[-1][3]["then"]
        self.assertNotIn(["mcp", "restart"], then)
        self.assertEqual(then[-1], ["disable", "mcp"])
        rc, out, saved = self.setup_mcp(prev, {"mcp": True})
        self.assertEqual(self.records[-1][3]["then"][0], ["mcp", "restart"])

    def test_settings_are_not_touched_by_a_refused_host(self):
        rc, out, saved = self.setup_mcp({}, {"mcp": False}, "--host", "0.0.0.0")
        self.assertEqual(rc, 2, out)
        self.assertEqual(saved, {})


# ---------------------------------------------------------------- ui.py: prompts

class PromptTest(unittest.TestCase):
    def test_mcp_callers_are_told_the_tool_argument(self):
        with mock.patch.object(ui, "interactive", return_value=False), mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": "mcp"}):
            with self.assertRaises(ui.Abort) as cm:
                ui.ask("GCP project ID", None, flag="--project-id VALUE")
            self.assertIn("pass project_id in the tool call's arguments", str(cm.exception))
            self.assertNotIn("without -y", str(cm.exception))
            with self.assertRaises(ui.Abort) as cm:
                ui.ask("Zones", None, flag="--var az_count=VALUE")
            self.assertIn('vars {"az_count": ...}', str(cm.exception))
            # cloudseed_setup takes no zone argument: a question with its own CLI flag is answered through vars
            with self.assertRaises(ui.Abort) as cm:
                ui.ask("Zone", None, flag="--zone VALUE")
            self.assertIn('pass vars {"zone": ...}', str(cm.exception))
            with self.assertRaises(ui.Abort) as cm:
                ui.ask("Environment name", None, flag="--name")
            self.assertIn("pass name in the tool call's arguments", str(cm.exception))
            with self.assertRaises(ui.Abort) as cm:                  # databricks connect: an option inside args
                ui.ask("Workspace host", None, required=True, flag="--host")
            self.assertIn('args "... --host VALUE"', str(cm.exception))
            with self.assertRaises(ui.Abort) as cm:
                ui.ask("Zone", "bad zone", validate=lambda v: "not a zone", flag="--zone VALUE")
            self.assertIn('(argument: vars {"zone": ...})', str(cm.exception))
        with mock.patch.object(ui, "interactive", return_value=False), mock.patch.dict(os.environ, {"CLOUDSEED_AGENT": ""}):
            with self.assertRaises(ui.Abort) as cm:
                ui.ask("GCP project ID", None, flag="--project-id VALUE")
            self.assertIn("run without -y to be prompted", str(cm.exception))

    def typed(self, text):
        out = io.StringIO()
        with mock.patch.object(ui, "interactive", return_value=True), mock.patch.object(ui, "_prompt_stream", return_value=out), \
                mock.patch("builtins.input", return_value=text):
            try:
                ui.require_typed("aws-f1", "Type 'aws-f1' to confirm")
                return None, out.getvalue()
            except ui.Abort as e:
                return e, out.getvalue()

    def test_typed_confirmation(self):
        e, shown = self.typed("aws-f1")
        self.assertIsNone(e)
        e, shown = self.typed("aws-f2")
        self.assertEqual(e.code, 1)
        self.assertIn("Confirmation did not match", str(e))
        self.assertNotIn("✔", shown)                               # never a green tick before the refusal
        e, shown = self.typed("   ")
        self.assertEqual(e.code, 0)
        self.assertIn("Cancelled", str(e))


# ---------------------------------------------------------------- did you mean

class DidYouMeanTest(unittest.TestCase):
    def test_an_option_before_the_command_gets_the_corrected_line(self):
        rc, err = _parse_error(["--env", "w1", "status"])
        self.assertEqual(rc, 2)
        self.assertIn("did you mean cloudseed status --env w1?", err)

    def test_the_rejected_option_is_never_its_own_suggestion(self):
        rc, err = _parse_error(["skill", "list", "--project"])
        self.assertEqual(rc, 2)
        self.assertNotIn("did you mean --project", err)
        self.assertIn("--project belongs to cloudseed skill install", err)

    def test_exact_topics_and_their_close_commands(self):
        rc, err = _parse_error(["envs"])
        self.assertIn("help topic cloudseed help envs", err)
        self.assertIn("did you mean env?", err)
        rc, err = _parse_error(["outputs", "gcp"])
        self.assertIn("did you mean cloudseed help outputs gcp?", err)


if __name__ == "__main__":
    unittest.main()
