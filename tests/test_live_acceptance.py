"""No real provider calls: guarded lifecycle orchestration, identity refusal and durable cleanup contracts."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cloudseed import acceptance, ui


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = SimpleNamespace(dir=Path(self.tmp.name), id="aws-existing")
        self.cfg = {"name": "user-production", "vars": {"profile": "sandbox"}}
        self.params = {"live": True, "allow_cloud_changes": True, "identity": "123456789012", "region": "us-east-1",
                       "allow_ip": "8.8.8.8/32", "max_budget_usd": 30, "estimated_hourly_usd": 5, "max_duration_minutes": 120}

    def execute(self, target="aws", params=None):
        return acceptance.execute("acceptance", target, self.env, self.cfg, params if params is not None else self.params)

    def test_default_preview_has_complete_lifecycle_and_no_side_effects_for_every_cloud(self):
        cfg = copy.deepcopy(self.cfg)
        with mock.patch.object(acceptance.health, "_run", side_effect=AssertionError("no cloud call")), \
                mock.patch.object(acceptance.deps, "find", side_effect=AssertionError("no tool lookup")):
            for target in acceptance.CLOUDS:
                report = self.execute(target, {})
                self.assertEqual(report["verdict"], "INCOMPLETE")
                self.assertEqual([x["id"] for x in report["plan"]], ["create", "readiness", "chart", "change", "restore", "destroy"])
                self.assertTrue(report["acceptance_env"].startswith(target + "-accept-"))
                self.assertFalse(report["live"])
                self.assertNotIn("user-production", json.dumps(report))
        self.assertEqual(self.cfg, cfg)
        self.assertEqual(list(self.env.dir.iterdir()), [])

    def test_live_refuses_every_missing_guard_before_provider_contact(self):
        keys = ("allow_cloud_changes", "identity", "region", "allow_ip", "max_budget_usd", "estimated_hourly_usd")
        with mock.patch.object(acceptance.health, "_run", side_effect=AssertionError("no cloud call")):
            for key in keys:
                p = dict(self.params)
                p.pop(key)
                with self.subTest(key=key), self.assertRaises(ui.Abort):
                    self.execute(params=p)

    def test_global_preview_needs_no_existing_environment_and_cloud_is_required(self):
        with mock.patch.object(acceptance.health, "_run", side_effect=AssertionError("no cloud call")):
            report = acceptance.execute("acceptance", "aws", None, {}, {})
            self.assertEqual(report["env"], "acceptance-harness")
            with self.assertRaises(ui.Abort):
                acceptance.execute("acceptance", None, None, {}, {})

    def test_generated_lifecycle_commands_parse_on_every_provider(self):
        from cloudseed import cli
        parser = cli.build_parser()
        for target, identity in (("aws", "123456789012"), ("gcp", "sandbox-project"), ("azure", "11111111-2222-3333-4444-555555555555")):
            steps = acceptance._plan(target, "accept-123456abcdef", {**self.params, "identity": identity})
            for step in steps:
                with self.subTest(cloud=target, step=step["id"]):
                    parser.parse_args(["--runtime", "local", "-y", *step["argv"]])
            create = steps[0]["argv"]
            self.assertLessEqual(len(create[create.index("--name") + 1] + "-" + create[create.index("--env") + 1]), 33)

    def test_nonfinite_negative_budget_and_overbudget_run_refused(self):
        for budget in (False, -1, 0, "20", float("nan"), float("inf"), 10 ** 1000, 1):
            with self.subTest(budget=budget), self.assertRaises(ui.Abort):
                self.execute(params={**self.params, "max_budget_usd": budget})
        for time in (True, 1, 361, "120"):
            with self.subTest(time=time), self.assertRaises(ui.Abort):
                self.execute(params={**self.params, "max_duration_minutes": time})

    def test_public_bastion_source_must_be_explicit_single_ipv4(self):
        for source in ("0.0.0.0/0", "8.8.8.0/24", "127.0.0.1/32", "169.254.169.254/32", "8.8.8.8", "::1/128", "1.2.3.4; rm"):
            with self.subTest(source=source), mock.patch.object(acceptance.deps, "find", side_effect=AssertionError("guard before tool lookup")), self.assertRaises(ui.Abort):
                self.execute(params={**self.params, "allow_ip": source})

    def test_unavailable_tools_refuse_without_installing_or_creating_directory(self):
        with mock.patch.object(acceptance.deps, "find", return_value=None), mock.patch.object(acceptance.health, "_run") as run:
            with self.assertRaises(ui.Abort):
                self.execute()
        run.assert_not_called()
        self.assertEqual(list(self.env.dir.iterdir()), [])

    def test_wrong_provider_identity_refuses_before_creating_any_environment(self):
        with mock.patch.object(acceptance.deps, "find", side_effect=lambda t: "/mock/" + t), \
                mock.patch.object(acceptance.health, "_run", return_value=subprocess.CompletedProcess([], 0, '{"Account":"999999999999"}', "")) as run:
            with self.assertRaises(ui.Abort):
                self.execute()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(list(self.env.dir.iterdir()), [])

    def fake_lifecycle(self, fail_step=None, foreign=False, destroy_fails=False):
        called = []
        def run(argv, **kwargs):
            if "get-caller-identity" in argv:
                return subprocess.CompletedProcess(argv, 0, '{"Account":"123456789012"}', "")
            called.append(argv)
            procenv = kwargs["env"]
            self.assertEqual(procenv["CLOUDSEED_AGENT"], "acceptance")
            self.assertEqual(procenv["CLOUDSEED_AUTO_INSTALL"], "0")
            self.assertEqual(procenv["AWS_PROFILE"], "sandbox")
            home = Path(procenv["CLOUDSEED_HOME"])
            name = argv[argv.index("--env") + 1]
            child = home / "envs" / ("aws-" + name)
            self.assertNotEqual(child, self.env.dir)
            if "setup" in argv and "--name" in argv:
                child.mkdir(parents=True)
                (child / "config.json").write_text(json.dumps({"cloud": "aws", "env": name, "name": "foreign" if foreign else "accept"}))
                (child / "stack").mkdir()
                (child / "stack" / "terraform.tfstate").write_text(json.dumps({"resources": [{"mode": "managed", "type": "aws_vpc"}]}))
            if "destroy" in argv and not destroy_fails:
                (child / "stack" / "terraform.tfstate").write_text('{"resources":[]}')
            rc = 1 if (fail_step and fail_step in argv) or ("destroy" in argv and destroy_fails) else 0
            return subprocess.CompletedProcess(argv, rc, "secret-output-is-not-in-report", "secret-error")
        return run, called

    def test_success_keeps_manifest_and_verifies_empty_state_without_claiming_provider_inventory(self):
        runner, called = self.fake_lifecycle()
        with mock.patch.object(acceptance.deps, "find", side_effect=lambda x: "/mock/" + x), \
                mock.patch.object(acceptance.health, "_run", side_effect=runner):
            report = self.execute()
        manifest = json.loads(Path(report["manifest"]).read_text())
        self.assertEqual(len(called), 6)
        self.assertEqual(manifest["cleanup"], "state_empty")
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertEqual(report["summary"]["completed_steps"], 6)
        self.assertNotIn("secret-output", json.dumps(report))
        self.assertTrue((Path(manifest["home"]) / "envs" / manifest["env"] / "stack" / "terraform.tfstate").exists())
        self.assertTrue(all("--purge" not in c for c in called))
        self.assertEqual(Path(report["manifest"]).stat().st_mode & 0o777, 0o600)

    def test_chart_failure_stops_next_steps_and_still_destroys_owned_environment(self):
        runner, called = self.fake_lifecycle(fail_step="platform")
        with mock.patch.object(acceptance.deps, "find", return_value="/mock/tool"), mock.patch.object(acceptance.health, "_run", side_effect=runner):
            report = self.execute()
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(len(called), 4)
        self.assertIn("destroy", called[-1])
        self.assertFalse(any("dr" in c for c in called))

    def test_interrupt_still_attempts_cleanup_and_restores_signal_handler(self):
        import signal
        runner, called = self.fake_lifecycle()
        def interrupt(argv, **kwargs):
            if "platform" in argv:
                raise KeyboardInterrupt
            return runner(argv, **kwargs)
        before = signal.getsignal(signal.SIGTERM)
        with mock.patch.object(acceptance.deps, "find", return_value="/mock/tool"), mock.patch.object(acceptance.health, "_run", side_effect=interrupt):
            report = self.execute()
        self.assertTrue(report["summary"]["interrupted"])
        self.assertEqual(report["summary"]["cleanup"], "state_empty")
        self.assertIn("destroy", called[-1])
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_failed_destroy_is_durable_and_never_purges_recovery_state(self):
        runner, called = self.fake_lifecycle(destroy_fails=True)
        with mock.patch.object(acceptance.deps, "find", return_value="/mock/tool"), mock.patch.object(acceptance.health, "_run", side_effect=runner):
            report = self.execute()
        manifest = json.loads(Path(report["manifest"]).read_text())
        self.assertEqual(manifest["cleanup"], "failed")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertNotIn("--purge", called[-1])

    def test_never_destroys_environment_with_mismatched_ownership(self):
        runner, called = self.fake_lifecycle(foreign=True)
        with mock.patch.object(acceptance.deps, "find", return_value="/mock/tool"), mock.patch.object(acceptance.health, "_run", side_effect=runner):
            report = self.execute()
        self.assertFalse(any("destroy" in c for c in called))
        self.assertEqual(report["summary"]["cleanup"], "unknown")

    def test_template_disables_shared_baselines_and_uses_local_state(self):
        for cloud, identity in (("aws", "123456789012"), ("gcp", "sandbox-project"), ("azure", "11111111-2222-3333-4444-555555555555")):
            report = self.execute(cloud, {**self.params, "identity": identity, "live": False})
            args = report["plan"][0]["argv"]
            self.assertIn("local", args)
            self.assertIn({"aws": "enable_account_baseline=false", "gcp": "enable_project_baseline=false", "azure": "enable_defender=false"}[cloud], args)
            if cloud == "gcp":
                self.assertIn("enable_apis=false", args)
                self.assertIn("enable_os_login=false", args)

    def test_script_preview_is_real_json_without_credentials_or_tools(self):
        proc = subprocess.run([sys.executable, "scripts/live-acceptance.py", "aws", "--output-dir", str(self.env.dir / "unused")],
                              capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1]), timeout=10)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["summary"]["preview"], True)
        self.assertFalse((self.env.dir / "unused").exists())


if __name__ == "__main__":
    unittest.main()
