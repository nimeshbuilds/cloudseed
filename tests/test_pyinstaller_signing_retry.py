"""Signing retries preserve security arguments and fail closed; no keychain access."""
import builtins
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pyinstaller-signing-retry.py"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("pyinstaller_signing_retry", SCRIPT)
    wrapper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wrapper)
    return wrapper


retry = load_wrapper()


def codesign_error(message):
    return SystemError("codesign command (['/usr/bin/codesign', '--timestamp']) failed with error code 1!\n"
                       "output: /tmp/library.so: replacing existing signature\n"
                       "/tmp/library.so: " + message + "\n")


class SigningRetryTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        redirect = contextlib.redirect_stderr(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def test_success_is_returned_once_without_delay(self):
        result = object()
        original = mock.Mock(return_value=result)
        with mock.patch.object(retry.time, "sleep") as sleep:
            self.assertIs(retry.signing_with_retry(original)("binary"), result)
        original.assert_called_once_with("binary")
        sleep.assert_not_called()
        self.assertEqual(self.output.getvalue(), "")

    def test_two_transient_failures_preserve_every_argument_and_call_order(self):
        calls = []
        args = (Path("/tmp/embedded library.so"), "Developer ID Application: fixture")
        kwargs = {"entitlements_file": Path("/tmp/custom entitlements.plist"), "deep": True}
        result = object()

        def original(*given_args, **given_kwargs):
            calls.append(("sign", given_args, given_kwargs.copy()))
            attempt = sum(call[0] == "sign" for call in calls)
            if attempt <= 2:
                raise codesign_error(retry.TIMESTAMP_ERRORS[attempt - 1])
            return result

        with mock.patch.object(retry.time, "sleep", side_effect=lambda delay: calls.append(("sleep", delay))):
            self.assertIs(retry.signing_with_retry(original)(*args, **kwargs), result)
        self.assertEqual(calls, [("sign", args, kwargs), ("sleep", 1), ("sign", args, kwargs),
                                 ("sleep", 2), ("sign", args, kwargs)])
        self.assertIn("attempt 2/3", self.output.getvalue())
        self.assertIn("attempt 3/3", self.output.getvalue())
        self.assertNotIn("Developer ID", self.output.getvalue())
        self.assertNotIn("/tmp/", self.output.getvalue())

    def test_exhaustion_raises_last_failure_without_a_fourth_call(self):
        errors = [codesign_error(retry.TIMESTAMP_ERRORS[0]) for _ in range(3)]
        original = mock.Mock(side_effect=errors)
        with mock.patch.object(retry.time, "sleep") as sleep:
            with self.assertRaises(SystemError) as caught:
                retry.signing_with_retry(original)("binary", None, None, False)
        self.assertIs(caught.exception, errors[-1])
        self.assertEqual(original.call_args_list, [mock.call("binary", None, None, False)] * 3)
        self.assertEqual(sleep.call_args_list, [mock.call(1), mock.call(2)])

    def test_nontransient_and_non_codesign_failures_are_not_retried(self):
        errors = [codesign_error(text) for text in (
            "The specified item could not be found in the keychain.",
            "The timestamp is not trusted.", "The timestamp is not valid.",
            "CSSMERR_TP_CERT_REVOKED", "resource fork, Finder information, or similar detritus not allowed",
        )]
        errors += [ValueError(retry.TIMESTAMP_ERRORS[0]), SystemError(retry.TIMESTAMP_ERRORS[0]),
                   SystemError("codesign command (['" + retry.TIMESTAMP_ERRORS[0] + "']) failed!\noutput: invalid signature"),
                   codesign_error(retry.TIMESTAMP_ERRORS[0] + " Unexpected unrelated diagnostic")]
        for error in errors:
            with self.subTest(error=str(error)), mock.patch.object(retry.time, "sleep") as sleep:
                original = mock.Mock(side_effect=error)
                with self.assertRaises(type(error)) as caught:
                    retry.signing_with_retry(original)("binary")
                self.assertIs(caught.exception, error)
                original.assert_called_once_with("binary")
                sleep.assert_not_called()

    def test_nontransient_failure_after_retry_stops_immediately(self):
        failure = codesign_error("The timestamp is not trusted.")
        original = mock.Mock(side_effect=[codesign_error(retry.TIMESTAMP_ERRORS[0]), failure])
        with mock.patch.object(retry.time, "sleep") as sleep, self.assertRaises(SystemError) as caught:
            retry.signing_with_retry(original)("binary", identity="fixture")
        self.assertIs(caught.exception, failure)
        self.assertEqual(original.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_import_requires_only_standard_library(self):
        actual_import = builtins.__import__

        def guarded(name, *args, **kwargs):
            if name.startswith("PyInstaller"):
                raise AssertionError("PyInstaller imported before main")
            return actual_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=guarded):
            self.assertTrue(callable(load_wrapper().main))

    def fake_modules(self, run, original):
        package = ModuleType("PyInstaller")
        package.__main__ = SimpleNamespace(run=run, compat=SimpleNamespace(check_requirements=mock.Mock()))
        utils = ModuleType("PyInstaller.utils")
        utils.osx = SimpleNamespace(sign_binary=original)
        return {"PyInstaller": package, "PyInstaller.utils": utils}

    def test_mac_main_wraps_before_build_and_restores_after_failure(self):
        original = mock.Mock(side_effect=[codesign_error(retry.TIMESTAMP_ERRORS[0]), None])
        args = ["--onefile", "--codesign-identity", "fixture", "--", "literal spec arg"]
        failure = RuntimeError("later build failed")
        modules = self.fake_modules(None, original)
        osx = modules["PyInstaller.utils"].osx
        entry = modules["PyInstaller"].__main__

        def run(given):
            self.assertIs(given, args)
            entry.compat.check_requirements.assert_called_once_with()
            self.assertIsNot(osx.sign_binary, original)
            osx.sign_binary("library", identity="fixture", entitlements_file="entitlements", deep=True)
            raise failure

        entry.run = run
        with mock.patch.dict(sys.modules, modules), mock.patch.object(sys, "platform", "darwin"), \
                mock.patch.object(retry.time, "sleep") as sleep, self.assertRaises(RuntimeError) as caught:
            retry.main(args)
        self.assertIs(caught.exception, failure)
        self.assertIs(osx.sign_binary, original)
        self.assertEqual(original.call_args_list, [mock.call("library", identity="fixture", entitlements_file="entitlements", deep=True)] * 2)
        sleep.assert_called_once_with(1)

    def test_other_platform_passes_all_cli_arguments_without_mac_patch(self):
        original, run = mock.Mock(), mock.Mock(return_value=17)
        modules = self.fake_modules(run, original)
        args = ["--onefile", "--clean", "--noconfirm", "source.py"]
        with mock.patch.dict(sys.modules, modules), mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(sys, "argv", ["wrapper.py", *args]):
            self.assertEqual(retry.main(), 17)
        run.assert_called_once_with(args)
        self.assertIs(modules["PyInstaller.utils"].osx.sign_binary, original)
        modules["PyInstaller"].__main__.compat.check_requirements.assert_not_called()
        original.assert_not_called()

    def test_bundle_uses_wrapper_and_retains_final_signature_verification(self):
        script = (ROOT / "scripts" / "build-bundle.sh").read_text()
        self.assertIn('"$BUILD/venv/bin/python" "$ROOT/scripts/pyinstaller-signing-retry.py" --onefile --clean --noconfirm', script)
        self.assertIn('SIGN_ARGS=(--codesign-identity "$CLOUDSEED_CODESIGN_IDENTITY")', script)
        self.assertIn('codesign --verify --strict --verbose=2 "$BIN"', script)
        self.assertIn('"pyinstaller==6.22.3"', script)


if __name__ == "__main__":
    unittest.main()
