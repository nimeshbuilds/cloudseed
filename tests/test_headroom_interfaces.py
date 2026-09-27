"""Headroom selection is independent of the context brief, with honest routing status."""
import argparse
import contextlib
import copy
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-headroom-ui-"))
from cloudseed import agents, cli, headroom, ui, webui


class HeadroomInterfaces(unittest.TestCase):
    def run_task(self, *, settings=None, opt_out=False, agent="claude", unsupported=None):
        args = argparse.Namespace(agent=agent, task=["Inspect saved evidence"], force=True,
                                  interactive=False, model=None, no_headliner=True,
                                  no_headroom=opt_out, show_prompt=False)
        spec = agents.get(agent)
        output = io.StringIO()
        with mock.patch.object(cli, "_ensure_agent_ready", return_value=spec), \
                mock.patch.object(agents, "headroom_unsupported", return_value=unsupported), \
                mock.patch.object(agents, "describe"), \
                mock.patch.object(agents, "selected_model", return_value="test-model"), \
                mock.patch.object(agents, "run", return_value=0) as run, \
                mock.patch.object(headroom, "install") as install, \
                contextlib.redirect_stdout(output):
            result = cli.cmd_do(args, settings or {})
        return result, install, run, output.getvalue()

    def test_supported_default_installs_and_requests_headroom_without_brief(self):
        result, install, run, output = self.run_task()
        self.assertEqual(result, 0)
        install.assert_called_once_with()
        self.assertTrue(run.call_args.kwargs["headroom_enabled"])
        self.assertIn("ready", output)
        self.assertNotIn("Headliner", output)
        self.assertNotIn("active", output)  # only a running proxy may claim active

    def test_opt_out_and_saved_setting_do_not_install_or_request_compression(self):
        for kwargs in ({"opt_out": True}, {"settings": {"headroom": False}}):
            with self.subTest(kwargs=kwargs):
                result, install, run, _ = self.run_task(**kwargs)
                self.assertEqual(result, 0)
                install.assert_not_called()
                self.assertFalse(run.call_args.kwargs["headroom_enabled"])

    def test_unsupported_agent_still_runs_and_explains_why_without_install(self):
        result, install, run, output = self.run_task(agent="gemini", unsupported="Gemini adapter is not verified")
        self.assertEqual(result, 0)
        install.assert_not_called()
        self.assertTrue(run.call_args.kwargs["headroom_enabled"])
        self.assertIn("unsupported", output)
        self.assertIn("Gemini adapter is not verified", output)

    def test_install_failure_stops_before_agent_run(self):
        args = argparse.Namespace(agent="claude", task=["review"], force=True, interactive=False,
                                  model=None, no_headliner=True, no_headroom=False, show_prompt=False)
        with mock.patch.object(cli, "_ensure_agent_ready", return_value=agents.get("claude")), \
                mock.patch.object(agents, "headroom_unsupported", return_value=None), \
                mock.patch.object(headroom, "install", side_effect=ui.Abort("install failed")), \
                mock.patch.object(agents, "run") as run, self.assertRaises(ui.Abort):
            cli.cmd_do(args, {})
        run.assert_not_called()

    def test_web_task_routes_opt_out_independently_of_context_brief(self):
        argv = webui.UI_ACTIONS["cloudseed_agentic"]["argv"]({"task": "review", "no_headroom": True})
        self.assertIn("--no-headroom", argv)
        self.assertNotIn("--no-headliner", argv)
        parsed = cli.build_parser().parse_args(argv)
        self.assertTrue(parsed.no_headroom)
        self.assertEqual(parsed.task, ["review"])
        self.assertIn("headroom", webui.UI_ACTIONS["cloudseed_enable"]["schema"]["properties"]["feature"]["enum"])

    def test_custom_launches_and_provider_modes_do_not_claim_supported(self):
        for name in ("claude", "codex"):
            original = copy.deepcopy(agents.DEFAULT_AGENTS[name])
            original["key"] = name
            for field, value in (("binary", "custom-agent"), ("exec", [name, "--oss", "{prompt}"])):
                spec = dict(original, **{field: value})
                self.assertIn("customized", agents.headroom_unsupported(spec, env={"CODEX_API_KEY": "synthetic"}))
        claude = dict(agents.DEFAULT_AGENTS["claude"], key="claude")
        self.assertIn("cloud-provider", agents.headroom_unsupported(claude, env={"CLAUDE_CODE_USE_BEDROCK": "1"}))
        codex = dict(agents.DEFAULT_AGENTS["codex"], key="codex")
        self.assertIn("subscription", agents.headroom_unsupported(codex, env={}))

    def test_codex_auth_and_project_configuration_are_not_silently_overridden(self):
        spec = dict(agents.DEFAULT_AGENTS["codex"], key="codex")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfgdir = root / "user"
            project = root / "project"
            cfgdir.mkdir()
            project.mkdir()
            env = {"CODEX_HOME": str(cfgdir), "CODEX_API_KEY": "synthetic"}
            with mock.patch.object(agents.Path, "cwd", return_value=project):
                self.assertIsNone(agents.headroom_unsupported(spec, env=env))
                (cfgdir / "config.toml").write_text('forced_login_method = "chatgpt"\n')
                self.assertIn("configuration", agents.headroom_unsupported(spec, env=env))
                (cfgdir / "config.toml").write_text('model = "test-model"\n')
                self.assertIsNone(agents.headroom_unsupported(spec, env=env))
                (project / ".codex").mkdir()
                (project / ".codex/config.toml").write_text('model_provider = "local"\n')
                self.assertIn("project configuration", agents.headroom_unsupported(spec, env=env))


if __name__ == "__main__":
    unittest.main()
