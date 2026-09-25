"""Release integrity/provenance are distinct; publishing is restricted to tested version tags."""
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cloudseed import releases, ui

ROOT = Path(__file__).resolve().parents[1]


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.artifact = Path(self.temp.name) / "cloudseed-linux-amd64"
        self.artifact.write_bytes(b"not executable, just artifact bytes")
        self.sha = hashlib.sha256(self.artifact.read_bytes()).hexdigest()

    def execute(self, **params):
        return releases.execute("release-verify", None, None, {}, {"artifact": str(self.artifact), "sha256": self.sha, **params})

    def test_digest_alone_never_claims_publisher_authenticity_or_executes_file(self):
        with mock.patch.object(releases.health, "_run", side_effect=AssertionError("no child")):
            report = self.execute()
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertTrue(report["summary"]["integrity"])
        self.assertFalse(report["summary"]["provenance_verified"])

    def test_digest_mismatch_is_fail_and_skips_network_verification(self):
        with mock.patch.object(releases.health, "_run") as run:
            report = self.execute(sha256="0" * 64, verify_attestation=True)
        self.assertEqual(report["verdict"], "FAIL")
        run.assert_not_called()

    def test_missing_gh_does_not_install_and_reports_unknown(self):
        with mock.patch.object(releases.deps, "find", return_value=None), mock.patch.object(releases.health, "_run") as run:
            report = self.execute(verify_attestation=True)
        self.assertEqual(report["verdict"], "INCOMPLETE")
        run.assert_not_called()

    def test_provenance_pins_repo_release_workflow_tags_and_hosted_runners(self):
        with mock.patch.object(releases.deps, "find", return_value="/mock/gh"), \
                mock.patch.object(releases.health, "_run", return_value=subprocess.CompletedProcess([], 0, "[]", "")) as run:
            report = self.execute(verify_attestation=True)
        self.assertEqual(report["verdict"], "PASS")
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["/mock/gh", "attestation", "verify"])
        self.assertEqual(argv[argv.index("--repo") + 1], "nimeshbuilds/cloudseed")
        self.assertEqual(argv[argv.index("--signer-workflow") + 1], "nimeshbuilds/cloudseed/.github/workflows/release.yml")
        self.assertIn("--deny-self-hosted-runners", argv)
        regex = argv[argv.index("--cert-identity-regex") + 1]
        self.assertRegex("https://github.com/nimeshbuilds/cloudseed/.github/workflows/release.yml@refs/tags/v0.1.0", regex)
        self.assertIsNone(re.match(regex, "https://github.com/nimeshbuilds/cloudseed/.github/workflows/release.yml@refs/heads/main"))
        self.assertLessEqual(run.call_args.kwargs["timeout"], 60)

    def test_failed_or_changed_artifact_provenance_cannot_pass(self):
        with mock.patch.object(releases.deps, "find", return_value="gh"), \
                mock.patch.object(releases.health, "_run", return_value=subprocess.CompletedProcess([], 1, "token-secret", "")):
            report = self.execute(verify_attestation=True)
            self.assertEqual(report["verdict"], "FAIL")
            self.assertNotIn("token-secret", json.dumps(report))
        def change(*args, **kwargs):
            self.artifact.write_bytes(b"different artifact after checksum")
            return subprocess.CompletedProcess([], 0, "[]", "")
        with mock.patch.object(releases.deps, "find", return_value="gh"), mock.patch.object(releases.health, "_run", side_effect=change):
            self.assertEqual(self.execute(verify_attestation=True)["verdict"], "FAIL")

    def test_invalid_hash_nonregular_and_symlink_are_refused(self):
        for digest in ("", "xyz", "0" * 63, None):
            with self.subTest(digest=digest), self.assertRaises(ui.Abort):
                self.execute(sha256=digest)
        linked = self.artifact.with_name("linked")
        linked.symlink_to(self.artifact)
        for path in (linked, self.artifact.parent, self.artifact.with_name("missing")):
            with self.subTest(path=path), self.assertRaises(ui.Abort):
                self.execute(artifact=str(path))

    def test_release_manifest_is_deterministic_and_checksum_covers_metadata(self):
        spec = importlib.util.spec_from_file_location("release_manifest", ROOT / "scripts" / "release-manifest.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        manifest = self.artifact.with_suffix(".manifest.json")
        checksums = self.artifact.with_suffix(".SHA256SUMS")
        args = ["--artifact", str(self.artifact), "--revision", "a" * 40, "--output", str(manifest), "--checksums", str(checksums)]
        module.main(args)
        previous = manifest.read_bytes(), checksums.read_bytes()
        module.main(args)
        self.assertEqual((manifest.read_bytes(), checksums.read_bytes()), previous)
        data = json.loads(manifest.read_text())
        self.assertEqual(data["artifacts"][0]["sha256"], self.sha)
        self.assertEqual(data["source_revision"], "a" * 40)
        for line in checksums.read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(releases.digest(self.artifact.parent / name)[0], digest)

    def test_bundle_dynamic_modules_and_build_dependencies_are_pinned(self):
        script = (ROOT / "scripts" / "build-bundle.sh").read_text()
        self.assertIn('--collect-submodules cloudseed', script)
        self.assertIn('PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"', script)
        self.assertIn('["health", "aws", "--env", "bundle"]', script)
        self.assertIn('--collect-submodules keyring.backends', script)
        self.assertIn('TF_VERSION="${TF_VERSION:-1.16.4}"', script)
        self.assertIn('"pyinstaller==6.22.3"', script)
        self.assertIn('"keyring==25.7.0"', script)
        self.assertNotIn("checkpoint-api", script)
        self.assertEqual(subprocess.run(["bash", "-n", str(ROOT / "scripts" / "build-bundle.sh")]).returncode, 0)

    def test_workflow_pins_actions_and_tag_only_publish_waits_for_all_tests(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        refs = re.findall(r"uses:\s*(\S+)", workflow)
        self.assertTrue(refs)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) for ref in refs))
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("git merge-base --is-ancestor HEAD origin/main", workflow)
        self.assertIn("needs: [checks, binary, container]", workflow)
        self.assertIn("needs: [checks, binary, container, publish-images]", workflow)
        publish = workflow.split("  publish-images:", 1)[1]
        self.assertGreaterEqual(publish.count("if: github.event_name == 'push' && github.ref_type == 'tag'"), 2)
        self.assertIn("docker load -i release-image/container.tar", publish)
        self.assertIn("--verify-tag", publish)
        self.assertIn("subject-checksums:", workflow)
        self.assertIn("sbom-path:", workflow)
        for platform in ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"):
            self.assertIn(platform, workflow)


if __name__ == "__main__":
    unittest.main()
