"""Regression tests for the final core pass: the IAM Access Analyzer hint across a wrapped diagnostic (either order,
never into another resource's error), a checksum mismatch in a dry run's bootstrap root explained as a lock-file
mismatch (not as a missing provider), FIPS verification only through provision.await_fips (the superseded
cli._await_fips is gone), and the end-to-end battery removing the directories it creates. Stdlib only; no network,
no cloud."""
import ast
import atexit
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, paths, tf, troubleshoot  # noqa: E402

TESTS = Path(__file__).resolve().parent


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        yield out, err


class _NoCache(unittest.TestCase):
    """No plugin cache from this machine's environment or ~/.terraformrc (the hint texts depend on it)."""

    def setUp(self):
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for name in ("TF_PLUGIN_CACHE_DIR", "TF_CLI_CONFIG_FILE"):
            os.environ.pop(name, None)
        rc = mock.patch.object(tf, "user_cli_config", return_value=None)
        rc.start()
        self.addCleanup(rc.stop)
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w5core-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)


ANALYZER = "only one account-level analyzer per region"


class AccessAnalyzerHintTests(_NoCache):
    def test_a_wrapped_quota_error_is_the_analyzer_hint(self):
        wrapped = ("╷\n│ Error: creating IAM Access Analyzer Analyzer (cloudseed-dev)\n│ \n│   with module.stack.module."
                   "baseline.aws_accessanalyzer_analyzer.this[0],\n│ \n│ operation error AccessAnalyzer: CreateAnalyzer, https "
                   "response error StatusCode: 402, RequestID: 1,\n│ ServiceQuotaExceededException: You have reached your "
                   "quota\n╵\n")
        msg = tf.explain(wrapped, "apply")
        self.assertIn(ANALYZER, msg)
        self.assertIn("--var enable_access_analyzer=false", msg)
        self.assertNotIn("service quota/limit was hit", msg)

    def test_the_quota_named_before_the_analyzer_is_the_analyzer_hint(self):
        msg = tf.explain("Error: ServiceQuotaExceededException: You have reached the maximum number of\naccount-level "
                         "analyzers for this Region", "apply")
        self.assertIn(ANALYZER, msg)

    def test_another_resources_error_is_not_taken_for_the_analyzer(self):
        # the quota belongs to a Lambda function; the analyzer failed for another reason in the next diagnostic
        text = ("Error: creating Lambda Function (x): ServiceQuotaExceededException: code storage limit\n\n"
                "Error: creating IAM Access Analyzer Analyzer (cs-dev): AccessDeniedException: not authorized\n")
        msg = tf.explain(text, "apply")
        self.assertNotIn(ANALYZER, msg)
        self.assertIn("lacks permissions", msg)
        # and an analyzer that is throttled is not a quota
        self.assertIn("throttling", tf.explain("Error: creating IAM Access Analyzer Analyzer (x): ThrottlingException: "
                                               "Rate exceeded\n\nError: creating S3 Bucket (y): BucketAlreadyExists", "apply"))
        # other quotas keep the generic hint
        self.assertIn("service quota/limit was hit", tf.explain("Error: VcpuLimitExceeded: You have requested", "apply"))

    def test_a_warning_or_a_flattened_error_ends_the_diagnostic(self):
        # a Lambda quota followed by a deprecation warning that names the analyzer resource is not the analyzer's
        text = ("Error: creating Lambda Function (x): ServiceQuotaExceededException: code storage limit\n\n  with "
                "module.stack.aws_lambda_function.x,\n\nWarning: Argument is deprecated\n\n  with module.stack.module."
                "baseline.aws_accessanalyzer_analyzer.this[0],\n")
        self.assertIn("service quota/limit was hit", tf.explain(text, "apply"))
        # nor is it when the log has both errors on one line
        text = ("Error: creating Lambda Function (x): ServiceQuotaExceededException: code storage limit Error: creating "
                "IAM Access Analyzer Analyzer (cs-dev): AccessDeniedException: not authorized")
        self.assertIn("lacks permissions", tf.explain(text, "apply"))

    def test_an_error_quoted_inside_the_message_does_not_end_it(self):
        msg = tf.explain("Error: creating IAM Access Analyzer Analyzer (cs-dev): timeout while waiting for state (last "
                         "error: ServiceQuotaExceededException: You have reached your quota)", "apply")
        self.assertIn(ANALYZER, msg)

    def test_troubleshoot_reports_the_wrapped_analyzer_error(self):
        log = self.tmp / "setup.log"
        log.write_text("$ terraform apply -no-color\n\nError: creating IAM Access Analyzer Analyzer (cloudseed-dev)\n\n"
                       "operation error AccessAnalyzer: CreateAnalyzer, https response error StatusCode: 402,\n"
                       "ServiceQuotaExceededException: You have reached your quota\n")
        whats = [f.what for f in troubleshoot._scan_log(log, "aws", "dev", workdir=self.tmp)]
        self.assertTrue(any(ANALYZER in w for w in whats), whats)


class ChecksumInDryRunTests(_NoCache):
    """ops: `terraform validate failed: A provider this root needs is not installed in .../dry-run/bootstrap/.terraform`
    was printed for a package that is there but does not match the lock file."""

    TEXT = ("╷\n│ Error: Required plugins are not installed\n│ \n│ The installed provider plugins are not consistent with "
            "the packages\n│ selected in the dependency lock file:\n│   - registry.terraform.io/hashicorp/aws: the cached "
            "package for\n│ registry.terraform.io/hashicorp/aws 6.66.0 (in .terraform/providers) does not\n│ match any of "
            "the checksums recorded in the dependency lock file\n│ \n│ Terraform uses external plugins to integrate with a "
            "variety of different\n│ infrastructure services. To download the plugins required for this\n│ "
            "configuration, run:\n│   terraform init\n╵\n")

    def test_validate_in_a_dry_run_bootstrap_names_the_lock_file(self):
        env = self.tmp / "envs" / "aws-dev"
        root = env / "dry-run" / "bootstrap"
        root.mkdir(parents=True)
        (env / "config.json").write_text(json.dumps({"cloud": "aws", "env": "dev"}))
        msg = tf.explain(self.TEXT, "validate", root)
        self.assertIn("no longer match the hashes in .terraform.lock.hcl", msg)
        self.assertIn(f"delete .terraform.lock.hcl and .terraform in {root}", msg)
        self.assertNotIn("is not installed", msg)

    def test_the_checksum_entry_comes_before_the_not_installed_one(self):
        keys = [p for p, _w, _f in tf.HINTS]
        missing = next(i for i, p in enumerate(keys) if "Required plugins are not installed" in p)
        self.assertLess(keys.index(tf.LOCK_MISMATCH), missing)
        self.assertIn(tf.LOCK_MISMATCH, tf._WITHOUT_CACHE)
        # a provider that really is missing keeps its own hint
        msg = tf.explain("Error: Required plugins are not installed\n\n  - registry.terraform.io/hashicorp/aws: there is "
                         "no package for registry.terraform.io/hashicorp/aws 6.66.0 cached in .terraform/providers\n",
                         "validate", self.tmp / "stack")
        self.assertIn("is not installed", msg)


class FipsVerificationTests(unittest.TestCase):
    def host(self):
        return SimpleNamespace(label="bastion", env=paths.Env("aws", "w5fips"), ssh=lambda cmd: ["ssh", cmd],
                               wait=mock.Mock())

    def run_checks(self, *answers):
        replies = iter(answers)
        seen = []

        def fake(argv, **kw):
            seen.append(argv[-1])
            return subprocess.CompletedProcess(argv, 0, next(replies), "")
        with mock.patch.object(cli.prov.subprocess, "run", side_effect=fake), \
                mock.patch.object(cli.prov.time, "sleep", side_effect=AssertionError("no reboot is pending")), quiet():
            cli._verify_fips(self.host())
        return seen

    def test_the_superseded_helper_is_gone(self):
        self.assertFalse(hasattr(cli, "_await_fips"))
        self.assertTrue(callable(cli.prov.await_fips))

    def test_no_pending_reboot_and_fips_on(self):
        seen = self.run_checks("no\n", "1\n")
        self.assertEqual(len(seen), 2)
        self.assertIn("/etc/cloudseed-fips-pending", seen[0])
        self.assertIn("fips_enabled", seen[1])

    def test_fips_off_names_the_command_that_provisions_that_host_again(self):
        with self.assertRaises(SystemExit) as cm:
            self.run_checks("no\n", "0\n")
        self.assertIn("fips_enabled=0", cm.exception.msg)
        argv = cm.exception.msg.split("re-run: cloudseed ")[1].split()
        with contextlib.redirect_stderr(io.StringIO()):
            ns = cli.build_parser().parse_args(argv)
        self.assertEqual((ns.cmd, ns.cloud, ns.env, ns.host), ("provision", "aws", "w5fips", "bastion"))


class E2eBatteryCleanupTests(unittest.TestCase):
    """The end-to-end battery inits every target (gigabytes of providers per run without a plugin cache): every
    directory it creates goes through one helper, and the module removes them all (after its tests and at exit)."""

    MAKERS = ("mkdtemp", "TemporaryDirectory", "mkstemp", "mktemp")

    def test_every_temporary_directory_goes_through_one_helper(self):
        tree = ast.parse((TESTS / "test_cli_e2e.py").read_text())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr in self.MAKERS]
        self.assertEqual(len(calls), 1, "only the battery's helper calls tempfile.mkdtemp")

    def test_the_directories_it_made_are_removed(self):
        path = TESTS / "test_cli_e2e.py"
        tree = ast.parse(path.read_text())
        helper = next(f.name for f in tree.body if isinstance(f, ast.FunctionDef) and any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in self.MAKERS
            for n in ast.walk(f)))
        tmp = tempfile.mkdtemp(prefix="cs-w5core-e2e-")
        self.addCleanup(shutil.rmtree, tmp, True)
        real, made, hooks = tempfile.mkdtemp, [], []

        def mkdtemp(*a, **kw):            # the battery's directories, made under tmp instead of $TMPDIR
            kw["dir"] = tmp
            made.append(real(*a, **kw))
            return made[-1]

        def register(fn, *a, **kw):       # an atexit hook of the loaded copy is called here, not at interpreter exit
            hooks.append(fn)
            return fn
        # a private copy of the module: its tests are not collected again and its own HOME is not touched
        spec = importlib.util.spec_from_file_location("_cs_e2e_cleanup_probe", path)
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.object(tempfile, "mkdtemp", mkdtemp), mock.patch.object(atexit, "register", register), \
                mock.patch.dict(os.environ, {"CS_E2E_KEEP": ""}):
            spec.loader.exec_module(mod)
            self.assertIn(mod.HOME, made)
            self.assertIn(mod.NO_VMWARE, made)
            made_by_a_test = getattr(mod, helper)()
            self.assertTrue(os.path.isdir(made_by_a_test))
            teardown = getattr(mod, "tearDownModule", None)
            self.assertTrue(teardown is not None or hooks, "the module removes its directories")
            if teardown is not None:      # after the battery's tests: a full suite does not keep its gigabytes
                teardown()
                self.assertEqual([d for d in made if os.path.exists(d)], [])
            for fn in hooks:              # and at exit (an interrupted run)
                fn()
        self.assertEqual([d for d in made if os.path.exists(d)], [])

if __name__ == "__main__":
    unittest.main()
