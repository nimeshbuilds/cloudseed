"""Automatic SSH-source discovery in every cloud and interface, without writing an environment or contacting a cloud."""

import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-public-ip-test-"))

from cloudseed import cli, clouds, mcp, netutil, paths, ui, webui  # noqa: E402


CLOUDS = ("aws", "gcp", "azure")
DETECTED_IP = "8.8.8.8"
DIAGNOSTIC = "HTTPS certificate verification failed. Check the system CA certificates or SSL_CERT_FILE."


class PublicIPSetupTests(unittest.TestCase):
    def setUp(self):
        self.stdout = io.StringIO()
        self.contexts = contextlib.ExitStack()
        self.addCleanup(self.contexts.close)
        self.contexts.enter_context(contextlib.redirect_stdout(self.stdout))
        self.contexts.enter_context(contextlib.redirect_stderr(self.stdout))
        self.contexts.enter_context(mock.patch.object(ui, "NON_INTERACTIVE", True))

    def _args(self, cloud, *extra):
        return cli.build_parser().parse_args(["setup", cloud, "--env", "public-ip-test", "-y", *extra])

    def _allow_list(self, cloud, *, existing=None, extra=()):
        env = paths.Env(cloud, "public-ip-test")
        try:
            return cli._setup_allow_list(self._args(cloud, *extra), clouds.get(cloud), env,
                                         existing or {}, {"unset": []}, {})
        finally:
            self.assertFalse(env.exists(), "the access helper must not create configuration")

    @staticmethod
    def _failed_detector(timeout=5.0, *, diagnostics=None):
        if diagnostics is not None:
            diagnostics.append(DIAGNOSTIC)
        return None

    def test_first_setup_detects_an_ipv4_host_rule_for_every_cloud(self):
        for cloud in CLOUDS:
            with self.subTest(cloud=cloud), mock.patch.object(netutil, "detect_public_ip", return_value=DETECTED_IP) as detect:
                self.assertEqual(self._allow_list(cloud), [f"{DETECTED_IP}/32"])
                detect.assert_called_once_with(diagnostics=[])

    def test_first_setup_failure_explains_cause_and_manual_override_for_every_cloud(self):
        for cloud in CLOUDS:
            with self.subTest(cloud=cloud), mock.patch.object(netutil, "detect_public_ip", side_effect=self._failed_detector):
                with self.assertRaises(ui.Abort) as caught:
                    self._allow_list(cloud)
                self.assertEqual(str(caught.exception),
                                 "Could not detect your public IP and none was given: pass --allow-ip <your-ip>. " + DIAGNOSTIC)

    def test_failed_detection_without_details_keeps_existing_error(self):
        with mock.patch.object(netutil, "detect_public_ip", return_value=None):
            with self.assertRaises(ui.Abort) as caught:
                self._allow_list("aws")
        self.assertEqual(str(caught.exception),
                         "Could not detect your public IP and none was given: pass --allow-ip <your-ip>.")

    def test_interactive_failure_explains_cause_before_manual_prompt(self):
        with mock.patch.object(netutil, "detect_public_ip", side_effect=self._failed_detector), \
                mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "ask_list", return_value=[DETECTED_IP]) as ask, \
                mock.patch.object(ui, "warn") as warn:
            self.assertEqual(self._allow_list("aws"), [f"{DETECTED_IP}/32"])
        warn.assert_called_once_with("Could not auto-detect your public IP; enter it manually. " + DIAGNOSTIC)
        self.assertEqual(ask.call_args.args[1], [])

    def test_saved_allow_list_survives_detection_failure_without_extra_warning(self):
        saved = ["9.9.9.0/24", "8.8.8.8/32"]
        for cloud in CLOUDS:
            with self.subTest(cloud=cloud), mock.patch.object(netutil, "detect_public_ip", side_effect=self._failed_detector), \
                    mock.patch.object(ui, "warn") as warn:
                self.assertEqual(self._allow_list(cloud, existing={"allowed_ssh_cidrs": saved}), saved)
                warn.assert_not_called()

    def test_explicit_allow_ip_never_uses_automatic_detection(self):
        for cloud in CLOUDS:
            with self.subTest(cloud=cloud), mock.patch.object(netutil, "detect_public_ip") as detect:
                self.assertEqual(self._allow_list(cloud, extra=("--allow-ip", DETECTED_IP)), [f"{DETECTED_IP}/32"])
                detect.assert_not_called()

    def test_mcp_and_ui_leave_blank_allow_ip_for_shared_cli_detection(self):
        for cloud in CLOUDS:
            with self.subTest(cloud=cloud):
                request = {"cloud": cloud, "env": "public-ip-test", "dry_run": True}
                mcp_argv = mcp.TOOLS["cloudseed_setup"]["argv"](request)
                ui_argv = webui.registry()["cloudseed_setup"]["argv"](request)
                self.assertEqual(ui_argv, mcp_argv)
                args = cli.build_parser().parse_args(ui_argv)
                self.assertFalse(args.allow_ip)
                self.assertTrue(args.yes)
                with mock.patch.object(netutil, "detect_public_ip", return_value=DETECTED_IP):
                    self.assertEqual(cli._setup_allow_list(args, clouds.get(cloud), paths.Env(cloud, args.env),
                                                          {}, {"unset": []}, {}), [f"{DETECTED_IP}/32"])
                self.assertFalse(paths.Env(cloud, args.env).exists())


class PublicIPUpdateTests(unittest.TestCase):
    def setUp(self):
        self.stdout = io.StringIO()
        self.contexts = contextlib.ExitStack()
        self.addCleanup(self.contexts.close)
        self.contexts.enter_context(contextlib.redirect_stdout(self.stdout))
        self.contexts.enter_context(contextlib.redirect_stderr(self.stdout))

    def test_failed_update_reports_cause_before_rendering_or_changing_sources(self):
        for cloud in CLOUDS:
            with self.subTest(cloud=cloud):
                cfg = {"allowed_ssh_cidrs": [f"{DETECTED_IP}/32"]}
                args = cli.build_parser().parse_args(["update-ip", cloud, "--env", "public-ip-test", "-y"])
                env = paths.Env(cloud, args.env)
                with mock.patch.object(cli, "_load_env", return_value=(clouds.get(cloud), env, cfg)), \
                        mock.patch.object(netutil, "detect_public_ip", side_effect=PublicIPSetupTests._failed_detector), \
                        mock.patch.object(cli, "_render") as render:
                    with self.assertRaises(ui.Abort) as caught:
                        cli.cmd_update_ip(args, {})
                self.assertEqual(str(caught.exception), "Could not detect your public IP. Pass it with --allow-ip. " + DIAGNOSTIC)
                self.assertEqual(cfg, {"allowed_ssh_cidrs": [f"{DETECTED_IP}/32"]})
                render.assert_not_called()
                self.assertFalse(env.exists())

    def test_vmware_update_never_loads_environment_or_detects_public_ip(self):
        args = cli.build_parser().parse_args(["update-ip", "vmware", "--env", "public-ip-test", "-y"])
        with mock.patch.object(cli, "_load_env") as load, mock.patch.object(netutil, "detect_public_ip") as detect:
            self.assertEqual(cli.cmd_update_ip(args, {}), 0)
        load.assert_not_called()
        detect.assert_not_called()
