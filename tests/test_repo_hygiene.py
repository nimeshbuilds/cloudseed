"""Hygiene of the published tree: no file holds a literal in a format secret scanners and GitHub push protection
flag (the redaction tests assemble their fake keys from parts at runtime), no build or run artifact is tracked,
.gitignore keeps them out, and the tracked Terraform lock files work on every platform.

Stdlib only, no network. The checks on tracked files need a git checkout (skipped in a bundle or a source archive)."""
from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Formats GitHub secret scanning / push protection and common scanners (gitleaks, detect-secrets) report. Each regex
# is written so that it does not match its own source text.
SCANNER_PATTERNS = {
    "private key block": r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY",
    "AWS access key id": r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
    "GitHub token": r"(?<![\w-])gh[pousr]_[A-Za-z0-9]{36}",
    "GitHub fine-grained token": r"github_pat_[A-Za-z0-9_]{22,}",
    "GitLab token": r"(?<![\w-])gl(?:pat|rt|dt|ptt|cbt|soat)-[A-Za-z0-9_-]{20}",
    "Slack token": r"(?<![\w-])xox[baprs]-[A-Za-z0-9-]{10,}",
    "Slack webhook": r"hooks\.slack\.com/services/",
    "Anthropic key": r"sk-ant-[A-Za-z0-9_-]{20,}",
    "Google API key": r"AIza[0-9A-Za-z_-]{35}",
    "Google OAuth secret or token": r"GOCSPX-[A-Za-z0-9_-]{20,}|ya29\.[A-Za-z0-9_-]{20,}",
    "npm token": r"(?<![\w-])npm_[A-Za-z0-9]{36}",
    "Stripe key": r"(?<![\w-])[rs]k_live_[A-Za-z0-9]{16,}",
    "Databricks token": r"(?<![\w-])dapi[0-9a-f]{32}",
    "Vault token": r"(?<![\w-])hv[sbr]\.[A-Za-z0-9_-]{24,}",
    "Tailscale key": r"tskey-[A-Za-z0-9-]{16,}",
    "Azure storage key": r"AccountKey=[A-Za-z0-9+/]{20,}",
}

# never part of the repository: caches, build output, Terraform working state, logs, OS debris
ARTIFACT = re.compile(r"(^|/)(__pycache__|\.terraform|\.ruff_cache|\.venv|\.pytest_cache)/|^(build|dist|site)/|\.py[co]$|"
                      r"(^|/)\.DS_Store$|(^|/)\._|\.tfstate(\.|$)|(^|/)tfplan$|\.log$|\.tfvars(\.json)?$")
# pins the checksum of a provider built on the developer's machine: no other build validates against it
LOCAL_LOCK = "terraform/vmware/.terraform.lock.hcl"


def _git(*args: str) -> subprocess.CompletedProcess | None:
    git = shutil.which("git")
    if not git or not (ROOT / ".git").exists():
        return None
    try:
        return subprocess.run([git, "-C", str(ROOT), *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None


def _tracked() -> list[str] | None:
    r = _git("ls-files", "-z")
    if r is None or r.returncode != 0:
        return None
    return [f for f in r.stdout.split("\0") if f]


def _source_files() -> list[str]:
    """The tracked files; outside a git checkout, the tree without dot directories, caches and build output."""
    files = _tracked()
    if files is not None:
        return files
    skip = {"__pycache__", "build", "dist", "site", "node_modules"}
    return sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file()
                  and not any(part.startswith(".") or part in skip for part in p.relative_to(ROOT).parts))


class RepoHygieneTests(unittest.TestCase):
    def test_no_literal_in_a_secret_scanner_format(self):
        patterns = {name: re.compile(rx) for name, rx in SCANNER_PATTERNS.items()}
        hits = []
        for rel in _source_files():
            try:
                text = (ROOT / rel).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue                 # images and other binaries
            for name, rx in patterns.items():
                for m in rx.finditer(text):
                    hits.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}: {name}")
        self.assertEqual(hits, [], "build fake credentials from parts at runtime (a prefix + the rest), so the source "
                                   "never holds a literal secret scanners or GitHub push protection would report")

    def test_the_scanner_patterns_still_catch_what_they_are_for(self):
        samples = {"private key block": "-----BEGIN " + "RSA PRIVATE KEY-----", "AWS access key id": "AKIA" + "ABCDEFGHIJKLMNOP",
                   "GitHub token": "ghp_" + "a" * 36, "Slack webhook": "https://hooks.slack.com" + "/services/T0/B0/x",
                   "Tailscale key": "tskey-" + "auth-k0123456789-abcdef", "Azure storage key": "AccountKey=" + "A" * 40}
        for name, sample in samples.items():
            self.assertRegex(sample, SCANNER_PATTERNS[name], name)

    def test_no_build_or_run_artifact_is_tracked(self):
        files = _tracked()
        if files is None:
            self.skipTest("not a git checkout")
        self.assertEqual([f for f in files if ARTIFACT.search(f)], [])
        self.assertNotIn(LOCAL_LOCK, files)

    def test_gitignore_keeps_artifacts_out_and_the_registry_locks_in(self):
        if _tracked() is None:
            self.skipTest("not a git checkout")
        ignored = ["x/__pycache__/m.cpython-312.pyc", "m.pyc", ".DS_Store", "tests/.DS_Store", ".ruff_cache/0.1/x",
                   "site/index.html", "terraform/aws/.terraform/providers/x", "terraform/aws/terraform.tfstate",
                   "terraform/aws/tfplan", "tests/tf_calls.log", "terraform/aws/.terraform.lock.hcl", LOCAL_LOCK, ".env"]
        for path in ignored:
            self.assertEqual(_git("check-ignore", "-q", "--no-index", path).returncode, 0, f"{path} is not ignored")
        for path in [f for f in _tracked() if f.endswith(".terraform.lock.hcl")] + ["cloudseed/cli.py", "README.md"]:
            self.assertEqual(_git("check-ignore", "-q", "--no-index", path).returncode, 1, f"{path} is ignored")
        r = _git("ls-files", "-ci", "--exclude-standard")
        self.assertEqual(r.stdout.split(), [], "tracked files that .gitignore excludes")

    def test_tracked_lock_files_hash_every_platform(self):
        # `terraform providers lock -platform=linux_amd64 -platform=linux_arm64 -platform=darwin_amd64
        # -platform=darwin_arm64`: one h1: hash per platform, so `terraform init` verifies on any of them
        locks = [f for f in (_tracked() or []) if f.endswith(".terraform.lock.hcl")]
        if not locks:
            self.skipTest("no tracked lock file (or not a git checkout)")
        for rel in locks:
            text = (ROOT / rel).read_text(encoding="utf-8")
            for block in re.findall(r'^provider "([^"]+)" \{(.*?)^\}', text, re.S | re.M):
                self.assertTrue(block[0].startswith("registry.terraform.io/"), f"{rel}: {block[0]} is not a registry provider")
                self.assertGreaterEqual(block[1].count('"h1:'), 4, f"{rel}: {block[0]} is not locked for 4 platforms")


if __name__ == "__main__":
    unittest.main()
