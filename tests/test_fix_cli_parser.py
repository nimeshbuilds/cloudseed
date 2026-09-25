"""Regression tests for the CLI parser, dispatcher and terminal UI fixes (group cli-parser)."""

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, cli, mcp, paths, ui  # noqa: E402
from cloudseed.cli import build_parser, normalize_argv  # noqa: E402
from cloudseed.tf import TerraformError  # noqa: E402


def parse(*argv):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        return build_parser().parse_args(normalize_argv(list(argv)))


def parse_fails(testcase, *argv) -> str:
    err, out = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out), testcase.assertRaises(SystemExit) as cm:
        build_parser().parse_args(normalize_argv(list(argv)))
    testcase.assertEqual(cm.exception.code, 2)
    return err.getvalue()


def run_main(*argv):
    """cli.main with stdout/stderr captured and the terminal/runtime side effects neutralised."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(cli.deps, "ensure_runtime", return_value="local"):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class TTYBuf(io.StringIO):
    def isatty(self):
        return True


@contextlib.contextmanager
def colour_on():
    saved = (ui._COLOR, ui._TRUECOLOR, ui._256, ui.RESET, ui.BOLD)
    ui._COLOR, ui._TRUECOLOR, ui._256, ui.RESET, ui.BOLD = True, True, True, "\033[0m", "\033[1m"
    try:
        yield
    finally:
        ui._COLOR, ui._TRUECOLOR, ui._256, ui.RESET, ui.BOLD = saved


# ------------------------------------------------------------------------------------------------ parser

class NodeParsingTests(unittest.TestCase):
    """cs node remove <node-name> [cloud] (documented) failed: the name was parsed as the cloud."""

    def test_documented_forms(self):
        for argv, cloud, env in ((["node", "remove", "acme-dev-wk3"], None, None),
                                 (["node", "remove", "acme-dev-wk3", "vmware", "--env", "dev"], "vmware", "dev"),
                                 (["node", "remove", "vmware", "acme-dev-wk3"], "vmware", None),
                                 (["node", "remove", "--env", "dev", "acme-dev-wk3"], None, "dev"),
                                 (["-y", "node", "remove", "acme-dev-wk3", "--env", "dev"], None, "dev"),
                                 (["node", "remove", "acme-dev-wk3", "--cloud", "vmware"], "vmware", None)):
            a = parse(*argv)
            self.assertEqual((a.node_cmd, a.name, a.cloud, a.env), ("remove", "acme-dev-wk3", cloud, env), argv)

    def test_add_and_list_keep_working(self):
        a = parse("node", "add", "--count", "2", "--role", "worker", "vmware", "--env", "dev")
        self.assertEqual((a.node_cmd, a.count, a.cloud, a.env, a.name), ("add", 2, "vmware", "dev", None))
        self.assertEqual(parse("node", "add", "--cloud", "gcp").cloud, "gcp")
        a = parse("node", "list")
        self.assertEqual((a.cloud, a.name), (None, None))
        self.assertFalse(hasattr(a, "targets"))

    def test_runtime_gate_sees_the_cloud(self):
        self.assertTrue(cli._touches_vms(parse("node", "remove", "acme-dev-wk3", "vmware")))
        self.assertEqual(parse("node", "remove", "acme-dev-wk3", "vmware").cloud, "vmware")

    def test_bad_combinations_are_usage_errors(self):
        self.assertIn("takes no node name", parse_fails(self, "node", "add", "acme"))
        self.assertIn("expected one node name", parse_fails(self, "node", "remove", "a", "b"))
        self.assertIn("more than one cloud", parse_fails(self, "node", "remove", "aws", "gcp", "x"))
        self.assertIn("two different clouds", parse_fails(self, "node", "remove", "x", "aws", "--cloud", "gcp"))

    def test_mcp_node_remove_without_cloud_parses(self):
        argv = mcp.TOOLS["cloudseed_node"]["argv"]({"action": "remove", "name": "acme-dev-wk3", "env": "dev"})
        a = parse(*argv)
        self.assertEqual((a.name, a.cloud, a.env, a.yes, a.auto_approve), ("acme-dev-wk3", None, "dev", True, True))


class DrParsingTests(unittest.TestCase):
    """cs dr backup vmware --env lab created a backup named 'vmware'."""

    def test_cloud_key_selects_the_target(self):
        a = parse("dr", "backup", "vmware", "--env", "lab")
        self.assertEqual((a.cloud, a.name, a.env), ("vmware", None, "lab"))
        a = parse("dr", "restore", "mybk", "aws", "--env", "lab")
        self.assertEqual((a.cloud, a.name), ("aws", "mybk"))
        a = parse("dr", "restore", "--env", "lab", "aws", "mybk")
        self.assertEqual((a.cloud, a.name, a.env), ("aws", "mybk", "lab"))
        self.assertEqual(parse("dr", "schedule", "nightly", "--cron", "0 2 * * *").name, "nightly")

    def test_explicit_cloud_flag_keeps_the_word_literal(self):
        a = parse("dr", "backup", "aws", "--cloud", "aws")
        self.assertEqual((a.cloud, a.name), ("aws", "aws"))

    def test_mistakes_are_usage_errors(self):
        self.assertIn("takes no name", parse_fails(self, "dr", "status", "vmwre"))
        self.assertIn("at most one", parse_fails(self, "dr", "restore", "a", "b"))


class PassthroughTests(unittest.TestCase):
    """cs kubectl -n NS get pods (and helm/k9s/snowflake/databricks leading flags) failed in argparse."""

    def test_leading_tool_flags_reach_the_tool(self):
        for argv, want in ((["kubectl", "-n", "kube-system", "get", "pods"], ["-n", "kube-system", "get", "pods"]),
                           (["kubectl", "--namespace", "x", "get", "pods"], ["--namespace", "x", "get", "pods"]),
                           (["kubectl", "-A", "get", "pods"], ["-A", "get", "pods"]),
                           (["helm", "-n", "keda", "list"], ["-n", "keda", "list"]),
                           (["k9s", "-n", "foo"], ["-n", "foo"]),
                           (["kubectl", "get", "pods", "-A"], ["get", "pods", "-A"])):
            self.assertEqual(parse(*argv).tool_args, want, argv)
        a = parse("-y", "kubectl", "-n", "kube-system", "get", "pods")
        self.assertTrue(a.yes)
        self.assertEqual(a.tool_args, ["-n", "kube-system", "get", "pods"])

    def test_cloudseed_selectors_and_separator(self):
        a = parse("kubectl", "aws", "--env", "dev", "-n", "x", "get", "pods")
        self.assertEqual((a.cloud, a.env, a.tool_args), ("aws", "dev", ["-n", "x", "get", "pods"]))
        a = parse("kubectl", "--env=dev", "get", "pods")
        self.assertEqual((a.cloud, a.env, a.tool_args), (None, "dev", ["get", "pods"]))
        self.assertEqual(parse("kubectl", "--", "-n", "x", "get", "pods").tool_args, ["-n", "x", "get", "pods"])
        # a later `--` belongs to kubectl (exec POD -- CMD) and nothing after it is touched
        self.assertEqual(parse("kubectl", "exec", "-it", "pod", "--", "sh", "-y").tool_args, ["exec", "-it", "pod", "--", "sh", "-y"])

    def test_trailing_global_yes_is_cloudseeds(self):
        a = parse("kubectl", "get", "pods", "-y")
        self.assertEqual((a.yes, a.tool_args), (True, ["get", "pods"]))

    def test_help_alone_is_cloudseeds_help(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            build_parser().parse_args(["kubectl", "-h"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("usage: cloudseed kubectl", out.getvalue())
        self.assertEqual(parse("kubectl", "get", "-h").tool_args, ["get", "-h"])

    def test_managed_services(self):
        self.assertEqual(parse("snowflake", "--version").svc_args, ["--version"])
        a = parse("databricks", "--profile", "p", "--debug", "clusters", "list")
        self.assertEqual((a.profile, a.svc_args), ("p", ["--debug", "clusters", "list"]))
        a = parse("databricks", "--profile=p", "clusters", "list", "-y")
        self.assertEqual((a.profile, a.svc_args, a.yes), ("p", ["clusters", "list"], True))
        # an explicit `--` stays until cmd_managed, so the service CLI's own -e/--env is never taken as cloudseed's
        a = parse("snowflake", "--", "sql", "-e", "x", "-y")
        self.assertEqual((a.svc_args, a.yes), (["--", "sql", "-e", "x", "-y"], False))
        a.env = None
        seen = {}

        def fake_run(service, name, rest):
            seen["rest"] = rest
            return 0
        with mock.patch.object(cli.managed, "run", fake_run):
            cli.cmd_managed(a, {})
        self.assertEqual((seen["rest"], a.env), (["sql", "-e", "x", "-y"], None))

    def test_mcp_tool_argv_with_leading_flags_parses(self):
        for tool, args in (("cloudseed_kubectl", {"args": "-n kube-system get pods"}), ("cloudseed_helm", {"args": "-n keda list"})):
            a = parse(*mcp.TOOLS[tool]["argv"](args))
            self.assertEqual(a.tool_args[0], "-n", tool)
        a = parse(*mcp.TOOLS["cloudseed_managed"]["argv"]({"service": "snowflake", "args": "--version"}))
        self.assertEqual(a.svc_args, ["--version"])


# a minimal valid argv for every command, to prove the global options are accepted after each of them
MINIMAL = {
    "setup": ["aws"], "provision": ["aws"], "k8s": ["info", "aws"], "vpn": ["status", "aws"], "plan": ["aws"],
    "apply": ["aws"], "destroy": ["aws"], "status": ["aws"], "troubleshoot": ["aws"], "inventory": ["aws"],
    "output": ["aws"], "ssh": ["aws"], "update-ip": ["aws"], "list": [], "doctor": [], "deps": ["status"],
    "enable": ["headliner"], "disable": ["headliner"], "use": ["builtin"], "agents": [], "model": [],
    "agentic": ["hi"], "do": ["hi"], "skill": ["list"], "install": ["terraform"], "env": [], "node": ["list"],
    "platform": ["list"], "finops": ["estimate"], "chaos": ["list"], "dr": ["status"], "scan": ["reports"],
    "databricks": ["status"], "snowflake": ["status"], "kubectl": ["get", "pods"], "helm": ["list"], "k9s": [],
    "explain": [], "mcp": ["status"], "ui": ["status"], "undo": [], "creds": [], "help": [],
}
CATCH_ALL = {"agentic", "do", "databricks", "snowflake", "kubectl", "helm", "k9s"}


class GlobalFlagTests(unittest.TestCase):
    """-y / --runtime / --engine are documented as global flags but were rejected after most commands."""

    def test_every_command_is_covered(self):
        self.assertEqual(set(MINIMAL), set(cli.HANDLERS))

    def test_trailing_yes_after_every_command(self):
        for cmd, rest in MINIMAL.items():
            a = parse(cmd, *rest, "-y")
            self.assertTrue(a.yes, cmd)
            self.assertTrue(parse("-y", cmd, *rest).yes, cmd)

    def test_trailing_runtime_and_engine(self):
        for cmd, rest in MINIMAL.items():
            if cmd in CATCH_ALL:
                continue
            a = parse(cmd, *rest, "--runtime", "local", "--engine", "podman")
            self.assertEqual((a.runtime, a.engine), ("local", "podman"), cmd)
        self.assertEqual(parse("doctor", "--engine", "docker").engine, "docker")

    def test_nested_commands(self):
        for argv in (["deps", "status", "-y"], ["deps", "install", "terraform", "-y"], ["deps", "bundle", "-y"],
                     ["deps", "image", "-y"], ["deps", "runtime", "local", "-y"], ["skill", "list", "-y"],
                     ["skill", "install", "-y"], ["skill", "show", "cloudseed", "-y"], ["deps", "-y", "status"]):
            self.assertTrue(parse(*argv).yes, argv)

    def test_engine_before_deps_subcommands_is_kept(self):
        self.assertEqual(parse("--engine", "podman", "deps", "image").engine, "podman")
        self.assertEqual(parse("--engine", "podman", "deps", "runtime", "container").engine, "podman")
        self.assertEqual(parse("deps", "image", "--engine", "podman").engine, "podman")
        self.assertEqual(parse("--engine", "docker", "deps", "image", "--engine", "podman").engine, "podman")
        self.assertIsNone(parse("deps", "image").engine)

    def test_ssh_takes_cloudseed_options_before_the_separator(self):
        a = parse("ssh", "aws", "-y")
        self.assertEqual((a.yes, a.ssh_args), (True, []))
        a = parse("ssh", "aws", "--env=dev", "-L", "8080:10.0.0.1:80", "--", "uptime", "-y")
        self.assertEqual((a.env, a.yes, a.ssh_args), ("dev", False, ["-L", "8080:10.0.0.1:80", "--", "uptime", "-y"]))
        a = parse("ssh", "aws", "--runtime", "local")
        self.assertEqual((a.runtime, a.ssh_args), ("local", []))

    def test_agentic_trailing_yes_is_not_part_of_the_task(self):
        a = parse("agentic", "set", "up", "aws", "-y")
        self.assertEqual((a.task, a.yes), (["set", "up", "aws"], True))
        a = parse("do", "--model", "m", "make", "an", "env")
        self.assertEqual((a.task, a.model), (["make", "an", "env"], "m"))

    def test_words_after_options_still_count(self):
        # positionals after options parse the same on every Python version (intermixed parsing)
        self.assertEqual(parse("platform", "install", "--env", "dev", "keda").items, ["keda"])
        self.assertEqual(parse("mcp", "connect", "--transport", "stdio", "claude-code").clients, ["claude-code"])
        a = parse("vpn", "add-user", "aws", "--env", "dev", "alice")
        self.assertEqual((a.cloud, a.env, a.name), ("aws", "dev", "alice"))
        a = parse("env", "use", "-y", "aws-dev")
        self.assertEqual((a.env_cmd, a.id, a.yes), ("use", "aws-dev", True))
        self.assertEqual(parse("finops", "estimate", "--env", "dev", "aws").cloud, "aws")
        self.assertEqual(parse("env").env_cmd, "show")
        self.assertEqual(parse("ui").ui_cmd, "open")

    def test_platform_help_lists_every_group(self):
        from cloudseed import platform as platformmod
        sub = next(a for a in build_parser()._actions if isinstance(a, cli.argparse._SubParsersAction))
        text = " ".join(sub.choices["platform"].format_help().split())
        for group in platformmod.GROUPS:
            self.assertIn(group, text)


class McpAliasTests(unittest.TestCase):
    def test_alias_after_global_options(self):
        self.assertEqual(normalize_argv(["-y", "setup", "mcp", "--client", "none"]), ["-y", "mcp", "setup", "--client", "none"])
        self.assertEqual(normalize_argv(["--runtime", "local", "-y", "destroy", "mcp"]), ["--runtime", "local", "-y", "mcp", "uninstall"])
        self.assertEqual(normalize_argv(["--engine=docker", "status", "mcp"]), ["--engine=docker", "mcp", "status"])
        self.assertEqual(normalize_argv(["setup", "-y", "mcp"]), ["mcp", "setup", "-y"])
        self.assertEqual(normalize_argv(["setup", "aws", "--dry-run"]), ["setup", "aws", "--dry-run"])
        a = parse("-y", "setup", "mcp", "--client", "none")
        self.assertEqual((a.cmd, a.mcp_cmd, a.yes, a.client), ("mcp", "setup", True, ["none"]))


# ------------------------------------------------------------------------------------------------ dispatcher

class DispatchTests(unittest.TestCase):
    def tearDown(self):
        ui.NON_INTERACTIVE = False

    def test_abort_messages_are_printed_once_by_the_dispatcher(self):
        def cancel(args, settings):
            raise ui.Abort("Cancelled. Nothing was changed.", code=0)
        with mock.patch.dict(cli.HANDLERS, {"list": cancel}):
            rc, out, err = run_main("list")
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("Cancelled. Nothing was changed."), 1)
        self.assertNotIn("✖", out + err)
        self.assertNotIn("Examples", err)

        def fail(args, settings):
            raise ui.Abort("something broke")
        with mock.patch.dict(cli.HANDLERS, {"list": fail}):
            rc, out, err = run_main("list")
        self.assertEqual(rc, 1)
        self.assertEqual(err.count("✖ something broke"), 1)
        self.assertIn("more: cloudseed help list", err)

        def user_cancel(args, settings):
            raise ui.Abort("Cancelled.", code=130)
        with mock.patch.dict(cli.HANDLERS, {"list": user_cancel}):
            rc, out, err = run_main("list")
        self.assertEqual(rc, 130)
        self.assertIn("▲ Cancelled.", err)
        self.assertNotIn("more: cloudseed help", err)

    def test_terraform_error_hint_without_a_cloud(self):
        def boom(args, settings):
            raise TerraformError("terraform apply failed")
        with mock.patch.dict(cli.HANDLERS, {"undo": boom}):
            rc, out, err = run_main("undo")
        self.assertEqual(rc, 1)
        self.assertIn("Next: cloudseed doctor", err)
        self.assertNotIn("None", err)

    def test_crash_without_an_environment_keeps_the_traceback(self):
        def crash(args, settings):
            raise RuntimeError("boom AKIA" + "IOSFODNN7EXAMPLE")
        before = set((paths.HOME / "logs").glob("*-crash.log")) if (paths.HOME / "logs").exists() else set()
        with mock.patch.dict(cli.HANDLERS, {"list": crash}):
            rc, out, err = run_main("list")
        self.assertEqual(rc, 1)
        new = set((paths.HOME / "logs").glob("*-crash.log")) - before
        self.assertEqual(len(new), 1, err)
        log = new.pop()
        try:
            text = log.read_text()
            self.assertIn("Traceback", text)
            self.assertIn("RuntimeError", text)
            self.assertNotIn("AKIA" + "IOSFODNN7EXAMPLE", text)
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
            self.assertIn(str(log), err)
            self.assertNotIn("environment log", err)
            self.assertNotIn("troubleshoot <cloud>", err)
            last = json.loads((paths.HOME / "logs" / "audit.jsonl").read_text().splitlines()[-1])
            self.assertEqual(last["log"], str(log))
        finally:
            log.unlink()

    def test_unusable_home_is_a_friendly_error(self):
        with mock.patch.object(cli.paths, "ensure_home", side_effect=PermissionError(13, "Permission denied")):
            rc, out, err = run_main("list")
            self.assertEqual(rc, 1)
            self.assertIn("is not usable: Permission denied", err)
            self.assertNotIn("Traceback", err)
            rc, out, err = run_main("help")
            self.assertEqual(rc, 0)

    def test_noninteractive_env_var(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_NONINTERACTIVE": "1"}):
            with mock.patch.dict(cli.HANDLERS, {"list": lambda args, settings: 0}):
                run_main("list")
        self.assertTrue(ui.NON_INTERACTIVE)

    def test_only_global_options_shows_the_overview(self):
        for argv in (["-y"], ["--runtime", "local"], []):
            rc, out, err = run_main(*argv)
            self.assertEqual(rc, 0, (argv, err))
            self.assertIn("USAGE", out)

    def test_global_yes_after_command_reaches_the_handler(self):
        seen = {}

        def rec(args, settings):
            seen["ni"] = ui.NON_INTERACTIVE
            return 0
        with mock.patch.dict(cli.HANDLERS, {"list": rec}):
            rc, _, err = run_main("list", "-y")
        self.assertEqual((rc, seen.get("ni")), (0, True), err)


class FullDestroyConfirmationTests(unittest.TestCase):
    """A full destroy without --auto-approve must never apply unless someone typed the env id."""

    def setUp(self):
        self.name = "t" + uuid.uuid4().hex[:8]
        self.env = paths.Env("aws", self.name)
        self.env.create_dirs()
        self.env.config_path.write_text(json.dumps({"name": "cs", "env": self.name, "region": "us-east-1",
                                                    "state": {"type": "local"}, "vars": {}}))
        self.calls = []
        calls = self.calls

        class FakeTF:
            def __init__(self, d):
                pass

            def init(self, **k):
                calls.append("init")

            def state_list(self):
                return ["module.stack.aws_vpc.this", "module.stack.module.bastion.aws_instance.this"]

            def run(self, *args, capture=False, check=True):   # destroy reads the state strictly (`state list`)
                if args[:2] == ("state", "list"):
                    return subprocess.CompletedProcess(args, 0, "\n".join(self.state_list()) + "\n", "")
                return subprocess.CompletedProcess(args, 1, "", "not faked")

            def plan(self, out, destroy=False, targets=()):
                calls.append("plan")

            def apply(self, planfile=None, **k):
                calls.append("APPLY")

            def outputs(self):
                return {}
        self.patches = [mock.patch.object(cli, "Terraform", FakeTF), mock.patch.object(cli, "_render", lambda *a: False),
                        mock.patch.object(cli.audit, "refresh", lambda *a, **k: None),
                        mock.patch.object(cli.undo, "record", lambda *a, **k: None),
                        mock.patch.object(paths.Env, "forget_host_keys", lambda self: None)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.env.dir, ignore_errors=True)
        ui.NON_INTERACTIVE = False

    def test_yes_without_auto_approve_is_a_preview(self):
        rc, out, err = run_main("destroy", "aws", "--env", self.name, "-y")
        self.assertEqual(rc, 3, out + err)
        self.assertNotIn("APPLY", self.calls)
        self.assertIn("--auto-approve", err)

    def test_no_terminal_without_auto_approve_is_a_preview(self):
        with mock.patch.object(ui, "_isatty", return_value=False):
            rc, out, err = run_main("destroy", "aws", "--env", self.name)
        self.assertEqual(rc, 3, out + err)
        self.assertNotIn("APPLY", self.calls)

    def test_auto_approve_destroys(self):
        rc, out, err = run_main("destroy", "aws", "--env", self.name, "-y", "--auto-approve")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("APPLY", self.calls)


# ------------------------------------------------------------------------------------------------ ui

def captured(fn, *a, **k) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        fn(*a, **k)
    return out.getvalue()


class PanelTests(unittest.TestCase):
    def widths(self, title, rows):
        with mock.patch.object(ui, "cols", return_value=100):
            text = captured(ui.panel, title, rows)
        return [ui.vis_len(line) for line in text.splitlines() if line.strip()]

    def test_every_line_has_the_same_width(self):
        long_value = "word " * 80
        for title, rows in (("Title", [("key", "value"), "plain line"]),
                            ("T" * 300, [("k", "v")]),
                            ("Wrapped", [("key", long_value), ("multi", "line one\nline two"), "x" * 400,
                                         "route    " + long_value, ("GuardDuty + CloudTrail (low volume) extra words", "$8.00")])):
            w = self.widths(title, rows)
            self.assertEqual(set(w), {100}, (title[:20], w))

    def test_styled_keys_align_like_plain_ones(self):
        with colour_on(), mock.patch.object(ui, "cols", return_value=100):
            text = captured(ui.panel, "t", [("a", "1"), (ui.style("bb", "brand") + ui.style("  ◀ current", "brand"), "2"),
                                            (ui.style("total", "bold"), ui.style("3", "leaf"))])
        lines = [ui._strip(l) for l in text.splitlines() if "│" in l]
        cols_ = {l.index(v) for l, v in zip(lines, "123")}
        self.assertEqual(len(cols_), 1, lines)
        self.assertEqual(len({ui.vis_len(l) for l in text.splitlines() if l.strip()}), 1)

    def test_kv_pads_by_visible_width(self):
        with colour_on():
            a = ui._strip(captured(ui.kv, ui.style("key", "bold"), "v"))
        self.assertEqual(a, ui._strip(captured(ui.kv, "key", "v")))


class TableTests(unittest.TestCase):
    rows = [["aws-dev", "/a/very/long/path/" + "x" * 90], ["gcp-prod", "short"]]

    def test_piped_output_keeps_whole_values(self):
        text = captured(ui.table, ["ENV", "WORKDIR"], self.rows)
        self.assertIn(self.rows[0][1], text)
        self.assertNotIn("…", text)
        self.assertFalse(any(line != line.rstrip() for line in text.splitlines()))

    def test_terminal_output_fits_and_marks_cuts(self):
        with mock.patch.object(ui, "_isatty", return_value=True), mock.patch.object(ui, "cols", return_value=50):
            text = captured(ui.table, ["ENV", "WORKDIR"], self.rows)
        self.assertIn("…", text)
        self.assertTrue(all(ui.vis_len(line) <= 50 for line in text.splitlines()), text)


class AbortTests(unittest.TestCase):
    def test_str_is_the_message_and_nothing_prints_on_construction(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            e = ui.Abort("Claude Code ('claude') is not on PATH")
        self.assertEqual(out.getvalue() + err.getvalue(), "")
        self.assertEqual(str(e), "Claude Code ('claude') is not on PATH")
        self.assertEqual(f"{'Claude Code'}: {e}", "Claude Code: Claude Code ('claude') is not on PATH")
        self.assertEqual(str(ui.Abort("", 0)), "exit code 0")

    def test_show_abort_by_code(self):
        for code, stream, glyph in ((0, "out", "●"), (130, "err", "▲"), (3, "err", "▲"), (1, "err", "✖")):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                ui.show_abort(ui.Abort("msg", code))
            self.assertIn(glyph + " msg", (out if stream == "out" else err).getvalue(), code)

    def test_multiline_messages_are_indented(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ui.err("Unknown --var for vmware:\n  x: nope\nValid variables: cloudseed help variables vmware")
        lines = err.getvalue().splitlines()
        self.assertTrue(lines[1].startswith("      x"), lines)
        self.assertTrue(lines[2].startswith("    Valid"), lines)


class PromptTests(unittest.TestCase):
    def interactive(self, stdin_text):
        return [mock.patch.object(ui, "interactive", return_value=True), mock.patch("sys.stdin", io.StringIO(stdin_text))]

    def run_with(self, stdin_text, fn, *a, **k):
        prompt = io.StringIO()
        err = io.StringIO()
        with contextlib.ExitStack() as st:
            for p in self.interactive(stdin_text):
                st.enter_context(p)
            st.enter_context(mock.patch.object(ui, "_prompt_stream", return_value=prompt))
            st.enter_context(contextlib.redirect_stderr(err))
            st.enter_context(contextlib.redirect_stdout(io.StringIO()))
            result = fn(*a, **k)
        return result, prompt.getvalue(), err.getvalue()

    def test_require_typed_fails_closed_without_a_terminal(self):
        with mock.patch.object(ui, "interactive", return_value=False), self.assertRaises(ui.Abort) as cm:
            ui.require_typed("aws-dev", "Type 'aws-dev' to confirm")
        self.assertEqual(cm.exception.code, 3)
        self.assertIn("--auto-approve", cm.exception.msg)

    def test_confirm_warns_on_an_invalid_answer(self):
        result, prompt, err = self.run_with("maybe\ny\n", ui.confirm, "Install gcloud now?")
        self.assertTrue(result)
        self.assertIn("Please answer y or n.", err)
        self.assertIn("Install gcloud now?", prompt)

    def test_eof_at_a_prompt_is_a_clean_cancel(self):
        with self.assertRaises(ui.Abort) as cm:
            self.run_with("", ui.ask, "Environment name", "dev")
        self.assertEqual((cm.exception.code, cm.exception.msg), (130, "Input closed."))

    def test_numbered_menu(self):
        opts = [("local", "Local: /tmp/x/terraform.tfstate"), ("remote", "Remote: a hardened bucket (recommended)")]
        result, prompt, _ = self.run_with("2\n", ui.choose, "Where should Terraform state live?", opts, "remote")
        self.assertEqual(result, "remote")
        self.assertIn("type a number", prompt)
        self.assertNotIn("↑/↓", prompt)
        self.assertIn("✔", prompt)
        result, _, _ = self.run_with("\n", ui.choose, "q", opts, "local")
        self.assertEqual(result, "local")
        with self.assertRaises(ui.Abort) as cm:
            self.run_with("", ui.choose, "q", opts, "local")
        self.assertEqual(cm.exception.code, 130)

    def test_no_terminal_to_prompt_on_is_not_interactive(self):
        with mock.patch.object(ui, "_isatty", side_effect=lambda s: s is sys.stdin):
            self.assertFalse(ui.interactive())

    def test_answer_line_fits_the_terminal(self):
        with mock.patch.object(ui, "cols", return_value=40):
            line = ui._answer_line("Infrastructure name (prefix + Project tag on every resource)", "cloudseed")
        self.assertLessEqual(ui.vis_len(line), 40)
        self.assertIn("cloudseed", line)


class ReadKeyTests(unittest.TestCase):
    def key(self, data: bytes) -> str:
        r, w = os.pipe()
        try:
            os.write(w, data)
            return ui._read_key(r)
        finally:
            os.close(r)
            os.close(w)

    def test_keys(self):
        t = time.time()
        self.assertEqual(self.key(b"\x1b"), "esc")          # a lone Esc cancels at once (no waiting for 2 more keys)
        self.assertLess(time.time() - t, 1.0)
        self.assertEqual(self.key(b"\x1b[A"), "up")
        self.assertEqual(self.key(b"\x1bOB"), "down")
        self.assertEqual(self.key(b"\x1b[5~"), "pgup")      # PgUp pages a long menu; it no longer cancels it
        self.assertEqual(self.key(b"\x1b[2~"), "ignore")    # Insert & co. do nothing
        self.assertEqual(self.key(b"\r"), "enter")
        self.assertEqual(self.key(b"3"), "3")
        self.assertEqual(self.key("é".encode()), "ignore")

    def test_fit_label_keeps_the_useful_part(self):
        label = "Local: /Users/someone/.cloudseed/envs/aws-dev/stack/terraform.tfstate"
        short = ui._fit_label(label, 40)
        self.assertLessEqual(ui.vis_len(short), 40)
        self.assertTrue(short.endswith("terraform.tfstate"))
        short = ui._fit_label("Remote: a hardened, versioned bucket in your account, shared by the team (recommended)", 50)
        self.assertLessEqual(ui.vis_len(short), 50)
        self.assertTrue(short.endswith("(recommended)"))


class SpinnerTests(unittest.TestCase):
    def test_output_during_a_spin_lands_on_a_clean_line(self):
        out, err = TTYBuf(), TTYBuf()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), mock.patch.object(ui, "cols", return_value=40):
            with ui.Spinner("Installing prowler into ~/.cloudseed/venv-prowler (first time only; a few minutes)"):
                time.sleep(0.3)
                print("Initializing the backend...")
                ui.warn("careful")
                time.sleep(0.2)
            self.assertIs(sys.stdout, out)
            self.assertIs(sys.stderr, err)
        text = out.getvalue()
        self.assertIn("\r\x1b[2KInitializing the backend...\n", text)
        self.assertNotIn("minutes)Initializing", text)
        frames = [ui._strip(f) for f in text.split("\r") if "Installing" in f]
        self.assertTrue(frames)
        self.assertTrue(all(ui.vis_len(f) <= 40 for f in frames), frames[:2])
        self.assertTrue(text.endswith("\r\x1b[2K") or text.endswith("\n"), repr(text[-30:]))

    def test_abort_inside_a_spinner_is_not_glued(self):
        out = TTYBuf()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", TTYBuf()):
            with self.assertRaises(ui.Abort):
                with ui.Spinner("Waiting for SSH"):
                    time.sleep(0.1)
                    raise ui.Abort("bastion did not accept SSH")
        self.assertNotIn("bastion did not accept SSH", out.getvalue())
        self.assertTrue(out.getvalue().endswith("\r\x1b[2K"))

    def test_piped_spinner_is_one_logged_line(self):
        sink = []
        ui.set_sink(sink.append)
        try:
            text = captured(ui.Spinner("Reading state").__enter__)
        finally:
            ui.set_sink(None)
        self.assertEqual(text.count("\n"), 1)
        self.assertTrue(any("Reading state" in s for s in sink))


class LogTeeTests(unittest.TestCase):
    def test_panels_kv_and_tables_reach_the_command_log(self):
        sink = []
        ui.set_sink(sink.append)
        try:
            with colour_on():
                captured(ui.panel, "Findings", [("Region", ui.style("us-east-1", "bold")), "● Nothing applied yet"])
                captured(ui.kv, "Target", "shop/api")
                captured(ui.table, ["ENV", "IP"], [["aws-dev", "1.2.3.4"]])
                captured(ui.line, "Recent runs: 2")
        finally:
            ui.set_sink(None)
        log = "\n".join(sink)
        for want in ("== Findings", "Region: us-east-1", "● Nothing applied yet", "Target: shop/api", "aws-dev  1.2.3.4", "Recent runs: 2"):
            self.assertIn(want, log)
        self.assertNotIn("\x1b", log)
        self.assertNotIn("│", log)


class StderrColourTests(unittest.TestCase):
    def test_redirected_stderr_gets_no_ansi(self):
        err = io.StringIO()
        with colour_on(), contextlib.redirect_stderr(err):
            ui.warn("The gcloud CLI is not installed")
            ui.eprint(ui.dim("hint"))
        self.assertNotIn("\x1b", err.getvalue())
        self.assertIn("▲ The gcloud CLI is not installed", err.getvalue())

    def test_usage_errors_on_redirected_stderr_get_no_ansi(self):
        err = io.StringIO()
        with colour_on(), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit):
            build_parser().parse_args(["node", "remove", "a", "b"])
        self.assertIn("✖ expected one node name", err.getvalue())
        self.assertIn("Examples for cloudseed node", err.getvalue())
        self.assertNotIn("\x1b", err.getvalue())

    def test_missing_cloud_names_every_target(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            build_parser().parse_args(["setup"])
        self.assertIn("needs a cloud: aws, gcp, azure or vmware", err.getvalue())


class TextHelperTests(unittest.TestCase):
    def test_fit_and_clip(self):
        self.assertEqual(ui.fit("abcdef", 4), "abc…")
        self.assertEqual(ui.fit("abc", 4), "abc")
        self.assertEqual(ui.clip("Kubernetes Gateway API CRDs (experimental channel)", 30), "Kubernetes Gateway API CRDs…")
        self.assertEqual(ui.vis_len(ui.style("日本", "bold")), 4)

    def test_audit_crash_log_goes_to_the_attached_env_log(self):
        d = Path(tempfile.mkdtemp())
        try:
            fh = open(d / "x.log", "a", encoding="utf-8")
            saved = dict(audit._state)
            audit._state.update(log=fh, logpath=d / "x.log", env=paths.Env("aws", "zz"))
            try:
                self.assertEqual(audit.record_crash("Traceback: boom"), d / "x.log")
                env, log = audit.attached()
                self.assertEqual((env.id, log), ("aws-zz", d / "x.log"))
            finally:
                fh.close()
                audit._state.clear()
                audit._state.update(saved)
            self.assertIn("Traceback: boom", (d / "x.log").read_text())
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
