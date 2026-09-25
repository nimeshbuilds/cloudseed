"""The container release manifest binds inventory bytes to one immutable image."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-manifest.py"


class ContainerReleaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.sbom = self.folder / "container-amd64.sbom.spdx.json"
        self.manifest = self.folder / "container-amd64.manifest.json"
        self.checksums = self.folder / "container-amd64.SHA256SUMS"
        self.sbom.write_bytes(b'{"spdxVersion":"SPDX-2.3","packages":[]}\n')
        self.reference = "ghcr.io/nimeshbuilds/cloudseed@sha256:" + "a" * 64

    def generate(self, reference=None):
        args = [sys.executable, str(SCRIPT), "--revision", "b" * 40, "--artifact", str(self.sbom),
                "--output", str(self.manifest), "--checksums", str(self.checksums)]
        if reference is not None:
            args += ["--image-reference", reference]
        environment = dict(os.environ, CLOUDSEED_HOME=str(self.folder / "home"))
        return subprocess.run(args, capture_output=True, text=True, env=environment, timeout=15)

    def checksum_records(self):
        return {name: sha for sha, name in (line.split("  ", 1) for line in self.checksums.read_text().splitlines())}

    def test_manifest_and_checksums_bind_exact_image_and_inventory_bytes(self):
        result = self.generate(self.reference)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.manifest.read_text())
        self.assertEqual(data["image_reference"], self.reference)
        self.assertEqual(data["source_revision"], "b" * 40)
        self.assertEqual(data["compatibility"]["operating_systems"], ["linux"])
        self.assertEqual(data["artifacts"], [{"file": self.sbom.name, "bytes": len(self.sbom.read_bytes()),
                                             "sha256": hashlib.sha256(self.sbom.read_bytes()).hexdigest()}])
        for filename, sha in self.checksum_records().items():
            self.assertEqual(hashlib.sha256((self.folder / filename).read_bytes()).hexdigest(), sha)
        self.assertEqual(set(self.checksum_records()), {self.sbom.name, self.manifest.name})
        original = self.manifest.read_bytes(), self.checksums.read_bytes()
        self.assertEqual(self.generate(self.reference).returncode, 0)
        self.assertEqual((self.manifest.read_bytes(), self.checksums.read_bytes()), original)

    def test_changing_only_image_digest_changes_attestable_manifest_digest(self):
        self.assertEqual(self.generate(self.reference).returncode, 0)
        before = self.checksum_records()
        changed = self.reference.rsplit(":", 1)[0] + ":" + "c" * 64
        self.assertEqual(self.generate(changed).returncode, 0)
        after = self.checksum_records()
        self.assertEqual(before[self.sbom.name], after[self.sbom.name])
        self.assertNotEqual(before[self.manifest.name], after[self.manifest.name])
        self.assertEqual(json.loads(self.manifest.read_text())["image_reference"], changed)

    def test_changing_inventory_bytes_changes_both_attested_digests(self):
        self.assertEqual(self.generate(self.reference).returncode, 0)
        before = self.checksum_records()
        self.sbom.write_bytes(self.sbom.read_bytes() + b"\n")
        self.assertEqual(self.generate(self.reference).returncode, 0)
        after = self.checksum_records()
        self.assertNotEqual(before[self.sbom.name], after[self.sbom.name])
        self.assertNotEqual(before[self.manifest.name], after[self.manifest.name])
        self.assertEqual(json.loads(self.manifest.read_text())["image_reference"], self.reference)

    def test_inventory_larger_than_embedded_attestation_limit_is_fully_hashed(self):
        # Full inventories are release artifacts, not size-limited predicates.
        block = b" " * (1024 * 1024)
        expected = hashlib.sha256(self.sbom.read_bytes())
        with self.sbom.open("ab") as stream:
            for _ in range(17):
                stream.write(block)
                expected.update(block)
        result = self.generate(self.reference)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.manifest.read_text())
        self.assertGreater(data["artifacts"][0]["bytes"], 16 * 1024 * 1024)
        self.assertEqual(data["artifacts"][0]["bytes"], self.sbom.stat().st_size)
        self.assertEqual(data["artifacts"][0]["sha256"], expected.hexdigest())
        self.assertEqual(self.checksum_records()[self.sbom.name], expected.hexdigest())

    def test_native_manifest_preserves_existing_contract(self):
        result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.manifest.read_text())
        self.assertNotIn("image_reference", data)
        self.assertEqual(data["compatibility"]["operating_systems"], ["linux", "darwin"])

    def test_explicit_registry_ports_and_ipv6_are_accepted(self):
        for name in ("registry.example.test:5000/team/image", "localhost:5000/cloudseed", "[2001:db8::1]:5000/team/image"):
            with self.subTest(name=name):
                reference = name + "@sha256:" + "a" * 64
                result = self.generate(reference)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(self.manifest.read_text())["image_reference"], reference)

    def test_malformed_or_mutable_references_fail_before_writing_metadata(self):
        invalid = ("", "cloudseed", "cloudseed@sha256:" + "a" * 64, "nimeshbuilds/cloudseed@sha256:" + "a" * 64,
                   "ghcr.io/nimeshbuilds/cloudseed:latest", self.reference.replace("@", ":latest@"),
                   self.reference + "\n", " " + self.reference, self.reference.replace("cloudseed", "cloud seed"),
                   "https://" + self.reference, self.reference.replace("/cloudseed", "/Cloudseed"),
                   self.reference.replace("sha256:", "sha512:"), self.reference[:-1], self.reference + "a",
                   self.reference.rsplit(":", 1)[0] + ":" + "A" * 64,
                   self.reference.replace("ghcr.io/", "ghcr.io:0/"), self.reference.replace("ghcr.io/", "ghcr.io:65536/"),
                   self.reference.replace("ghcr.io/", "[:::]/"), self.reference.replace("/nimeshbuilds/", "//nimeshbuilds/"))
        for reference in invalid:
            with self.subTest(reference=reference):
                result = self.generate(reference)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("image reference", result.stderr)
                self.assertFalse(self.manifest.exists())
                self.assertFalse(self.checksums.exists())


if __name__ == "__main__":
    unittest.main()
