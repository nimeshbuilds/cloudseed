"""Exercise release signing guards without reading a real keychain or certificate."""
import base64
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("apple_signing", ROOT / "scripts" / "apple-signing.py")
signing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signing)
IDENTITY = "869292F8056C3005820396133C2E656C825582FD"
TEAM = "QPF2VF2885"


class AppleReleaseSigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cloudseed-signing-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env_file = self.root / "github-env"
        self.env_file.touch()
        self.env = {"RUNNER_TEMP": str(self.root), "GITHUB_ENV": str(self.env_file),
                    "CLOUDSEED_APPLE_TEAM_ID": TEAM, "CLOUDSEED_REQUIRE_APPLE_SIGNING": "true"}
        patch = mock.patch.dict(os.environ, self.env, clear=True)
        patch.start()
        self.addCleanup(patch.stop)
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        self.calls = []

    def credentials(self):
        os.environ["APPLE_SIGNING_CERTIFICATE_P12"] = base64.b64encode(b"fake-pkcs12-private-material").decode()
        os.environ["APPLE_SIGNING_PASSWORD"] = "fake-private-password"

    def command(self, args, purpose):
        self.calls.append(args)
        if args[:2] == ["security", "create-keychain"]:
            Path(args[-1]).write_text("fake-keychain")
        if args[:2] == ["security", "import"]:
            certificate = Path(args[2])
            self.assertEqual(certificate.read_bytes(), b"fake-pkcs12-private-material")
            self.assertEqual(certificate.stat().st_mode & 0o777, 0o600)
        output = '"/Users/runner/Library/Keychains/login.keychain-db"\n' if args == ["security", "list-keychains", "-d", "user"] else ""
        if args[:2] == ["security", "find-identity"]:
            output = f'  1) {IDENTITY} "Developer ID Application: Nimesh Pandeya ({TEAM})"\n  1 valid identities found\n'
        return subprocess.CompletedProcess(args, 0, output, "")

    def import_identity(self):
        self.credentials()
        with mock.patch.object(signing, "run", side_effect=self.command):
            signing.prepare()
        values = dict(line.split("=", 1) for line in self.env_file.read_text().splitlines())
        os.environ.update(values)
        return Path(values["CLOUDSEED_SIGNING_DIR"])

    def test_tagged_and_partially_configured_releases_require_both_secrets(self):
        for certificate, password, required in (("", "", "true"), ("present", "", "false"), ("", "present", "false")):
            with self.subTest(certificate=bool(certificate), password=bool(password)), \
                    mock.patch.dict(os.environ, {"APPLE_SIGNING_CERTIFICATE_P12": certificate, "APPLE_SIGNING_PASSWORD": password,
                                                 "CLOUDSEED_REQUIRE_APPLE_SIGNING": required}), \
                    mock.patch.object(signing, "run") as run:
                with self.assertRaises(signing.SigningError):
                    signing.prepare()
                run.assert_not_called()

    def test_manual_unconfigured_build_is_explicitly_unsigned(self):
        os.environ["CLOUDSEED_REQUIRE_APPLE_SIGNING"] = "false"
        with mock.patch.object(signing, "run") as run:
            signing.prepare()
            signing.verify(self.root / "binary")
        run.assert_not_called()
        self.assertIn("cannot publish", self.output.getvalue())
        self.assertEqual(self.env_file.read_text(), "")

    def test_malformed_base64_is_rejected_before_keychain_access(self):
        self.credentials()
        os.environ["APPLE_SIGNING_CERTIFICATE_P12"] = "not base64!"
        with mock.patch.object(signing, "run") as run, self.assertRaises(signing.SigningError):
            signing.prepare()
        run.assert_not_called()

    def test_identity_is_available_to_build_without_persisting_p12_or_password(self):
        folder = self.import_identity()
        self.assertTrue((folder / "signing.keychain-db").exists())
        self.assertFalse((folder / "certificate.p12").exists())
        self.assertEqual(os.environ["CLOUDSEED_CODESIGN_IDENTITY"], IDENTITY)
        shared = self.env_file.read_text() + self.output.getvalue()
        for secret in ("fake-private-password", "fake-pkcs12-private-material", os.environ["APPLE_SIGNING_CERTIFICATE_P12"]):
            self.assertNotIn(secret, shared)
        partition = next(c for c in self.calls if c[1] == "set-key-partition-list")
        self.assertIn("apple-tool:,apple:", partition)
        imported = next(c for c in self.calls if c[1] == "import")
        self.assertIn("/usr/bin/codesign", imported)
        self.assertNotIn("-A", imported)
        with mock.patch.object(signing, "run", side_effect=self.command):
            signing.cleanup()
        self.assertFalse(folder.exists())
        self.assertIn(["security", "list-keychains", "-d", "user", "-s", "/Users/runner/Library/Keychains/login.keychain-db"], self.calls)

    def test_wrong_or_ambiguous_identity_fails_and_cleans_up(self):
        self.credentials()
        for result in (f'{IDENTITY} "Developer ID Application: Other (OTHERTEAM1)"',
                       f'{IDENTITY} "Developer ID Application: One ({TEAM})"\n{IDENTITY} "Developer ID Application: Two ({TEAM})"'):
            def command(args, purpose):
                response = self.command(args, purpose)
                return subprocess.CompletedProcess(args, 0, result, "") if args[1] == "find-identity" else response
            with self.subTest(result=result), mock.patch.object(signing, "run", side_effect=command):
                with self.assertRaises(signing.SigningError):
                    signing.prepare()
            self.assertFalse(list(self.root.glob("cloudseed-signing-*")))

    def test_tool_failure_never_echoes_secret_arguments_or_output(self):
        self.credentials()
        with mock.patch.object(signing.subprocess, "run", side_effect=subprocess.CalledProcessError(
                1, ["security", "-P", "fake-private-password"], output="fake-pkcs12-private-material")):
            with self.assertRaises(signing.SigningError) as caught:
                signing.run(["security", "-P", "fake-private-password"], "importing the identity")
        self.assertNotIn("fake-private", str(caught.exception))
        self.assertNotIn("fake-pkcs12", str(caught.exception))
        with mock.patch.object(signing.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                ["security", "-P", "fake-private-password"], 90)) as run:
            with self.assertRaises(signing.SigningError) as caught:
                signing.run(["security", "-P", "fake-private-password"], "importing the identity")
            self.assertEqual(run.call_args.kwargs["timeout"], 90)
            self.assertNotIn("APPLE_SIGNING_PASSWORD", run.call_args.kwargs["env"])
        self.assertNotIn("fake-private-password", str(caught.exception))

    def test_finished_binary_requires_valid_signature_and_expected_team(self):
        os.environ["CLOUDSEED_CODESIGN_IDENTITY"] = IDENTITY
        valid = f"Authority=Developer ID Application: Nimesh Pandeya ({TEAM})\nTeamIdentifier={TEAM}\nCodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=1\nTimestamp=Sep 26, 2026 at 12:00:00 PM\n"
        for output, succeeds in ((valid, True),
                                 (valid.replace("Timestamp=Sep 26, 2026 at 12:00:00 PM\n", ""), False),
                                 (valid.replace("flags=0x10000(runtime)", "flags=0x0(none)"), False),
                                 ("Signature=adhoc\nTeamIdentifier=not set\n", False),
                                 ("Authority=Developer ID Application: Other (OTHERTEAM1)\nTeamIdentifier=OTHERTEAM1\n", False)):
            with self.subTest(output=output), mock.patch.object(signing, "run", return_value=subprocess.CompletedProcess([], 0, "", output)) as run:
                if succeeds:
                    signing.verify(self.root / "binary")
                    self.assertIn("--strict", run.call_args_list[0].args[0])
                else:
                    with self.assertRaises(signing.SigningError):
                        signing.verify(self.root / "binary")
        with mock.patch.object(signing, "run", side_effect=signing.SigningError("signature is invalid")), self.assertRaises(signing.SigningError):
            signing.verify(self.root / "binary")

    def test_missing_identity_cannot_verify_tagged_release(self):
        with self.assertRaises(signing.SigningError):
            signing.verify(self.root / "binary")

    def test_cleanup_removes_files_even_if_keychain_tool_fails_and_refuses_other_paths(self):
        folder = self.import_identity()
        with mock.patch.object(signing, "run", side_effect=signing.SigningError("unavailable")), self.assertRaises(signing.SigningError):
            signing.cleanup()
        self.assertFalse(folder.exists())
        with self.assertRaises(signing.SigningError):
            signing.cleanup(self.root.parent)

    def test_workflow_signs_before_testing_and_cleanup_always_runs_before_inventory(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text().split("  binary:", 1)[1].split("  container:", 1)[0]
        self.assertIn("CLOUDSEED_REQUIRE_APPLE_SIGNING: ${{ github.event_name == 'push' && github.ref_type == 'tag' }}", workflow)
        self.assertIn("APPLE_SIGNING_CERTIFICATE_P12: ${{ secrets.APPLE_SIGNING_CERTIFICATE_P12 }}", workflow)
        self.assertIn("APPLE_SIGNING_PASSWORD: ${{ secrets.APPLE_SIGNING_PASSWORD }}", workflow)
        positions = [workflow.index(s) for s in ("scripts/apple-signing.py prepare", "bash scripts/build-bundle.sh", "scripts/apple-signing.py verify",
                    "python3 -m unittest", "scripts/apple-signing.py cleanup", "scripts/generate-sbom.py", "scripts/release-manifest.py", "Attest tested release bytes")]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("if: always() && runner.os == 'macOS'", workflow)
        self.assertIn("path: dist/*", workflow)
        self.assertNotIn("path: ${{ runner.temp }}", workflow)


if __name__ == "__main__":
    unittest.main()
