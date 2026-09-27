"""Portable bastion payload and install guarantees; no SSH, package manager or cloud calls."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from tests.test_fix_ansible import _task
from cloudseed import provision


ROOT = Path(__file__).resolve().parents[1]
BUILD = (ROOT / "scripts/build-bundle.sh").read_text()
STAGE_SCRIPT = BUILD.split('python3 - "$ROOT" "$STAGE" <<\'PY\'\n', 1)[1].split("\nPY\n", 1)[0]


class BastionPayloadTests(unittest.TestCase):
    def stage(self, root, destination):
        result = subprocess.run([sys.executable, "-", str(root), str(destination)], input=STAGE_SCRIPT,
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_portable_source_payload_runs_independently_of_the_checkout(self):
        with tempfile.TemporaryDirectory(prefix="cs-bastion-source-") as tmp:
            home = Path(tmp)
            stage = home / "payload"
            self.stage(ROOT, stage)
            env = dict(os.environ, HOME=str(home), CLOUDSEED_HOME=str(home / "state"), PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1")
            for args in (("--version",), ("help",), ("scan", "cloud", "--help"), ("mcp", "--help"), ("ui", "--help")):
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, "-I", str(stage / "bin/cloudseed"), *args], env=env, cwd=home,
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for source in (ROOT / "cloudseed").glob("*.py"):
                self.assertEqual((stage / "cloudseed" / source.name).read_bytes(), source.read_bytes())
            self.assertTrue((stage / "bin/cloudseed").stat().st_mode & 0o111)
            self.assertFalse((stage / ".cloudseed").exists())
            self.assertIn('--add-data "$STAGE/bin:bin"', BUILD)
            self.assertIn('--add-data "$STAGE/cloudseed:cloudseed"', BUILD)

    def test_source_staging_excludes_credentials_state_and_nonportable_files(self):
        with tempfile.TemporaryDirectory(prefix="cs-bastion-filter-") as tmp:
            root, stage = Path(tmp) / "source", Path(tmp) / "stage"
            for name in ("terraform", "skills", "ansible", "providers", "templates", "assets", "cloudseed/web", "bin"):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / "bin/cloudseed").write_text("#!/usr/bin/env python3\n")
            for name in ("__init__.py", "cli.py", "credentials.json", ".env", "private.key", "native.so", "bytecode.pyc"):
                (root / "cloudseed" / name).write_text("fixture")
            (root / "cloudseed/.private").mkdir()
            (root / "cloudseed/.private/config.py").write_text("private fixture")
            (root / "cloudseed/environment/ssh").mkdir(parents=True)
            (root / "cloudseed/environment/config.json").write_text("{}")
            (root / "cloudseed/environment/local.py").write_text("private fixture")
            (root / "cloudseed/linked.py").symlink_to(root / "cloudseed/cli.py")
            self.stage(root, stage)
            self.assertEqual(sorted(p.name for p in (stage / "cloudseed").iterdir()), ["__init__.py", "cli.py", "web"])

    def test_common_role_requires_payload_preserves_aliases_and_checks_commands(self):
        common = (ROOT / "ansible/roles/common/tasks/main.yml").read_text()
        required = _task(common, "Require the portable Cloudseed launcher and source payload")
        for path in ("/bin/cloudseed", "/cloudseed/__init__.py", "/cloudseed/cli.py"):
            self.assertIn(path, required)
        self.assertIn("not this Cloudseed install", _task(common, "Keep unrelated commands intact"))
        self.assertIn("item.stat.lnk_source", _task(common, "Keep unrelated commands intact"))
        self.assertIn("((repo_dir + '/bin/cloudseed') | realpath)", _task(common, "Keep unrelated commands intact"))
        path = _task(common, "PATH includes ~/.local/bin before noninteractive shell guards")
        self.assertIn("ansible.builtin.blockinfile", path)
        self.assertIn("insertbefore: BOF", path)
        self.assertIn(".profile, .bashrc", path)
        self.assertIn("$HOME/.cloudseed/bin", path)
        smoke = _task(common, "Verify both Cloudseed commands without using the login user's configuration")
        self.assertIn('CLOUDSEED_HOME="$check_home"', smoke)
        self.assertIn('"/home/{{ ssh_user }}/.local/bin/cs" --version', smoke)
        self.assertIn("become: false", smoke)
        self.assertIn("changed_when: false", smoke)
        self.assertNotIn("when:", _task(common, "Link cloudseed and cs into ~/.local/bin"))

    def test_cluster_clients_share_checked_installers_and_honor_no_tools(self):
        bastion = (ROOT / "ansible/bastion.yml").read_text()
        self.assertIn("cloud in ['aws', 'gcp', 'azure', 'vmware']", bastion)
        tools = (ROOT / "ansible/roles/tools/tasks/main.yml").read_text()
        clients = _task(tools, "Helm and k9s using Cloudseed's checksum-verified installers")
        self.assertIn("loop: [helm, k9s]", clients)
        self.assertIn("become: false", clients)
        self.assertIn("when: install_kubectl | bool", clients)
        self.assertIn("already installed:", clients)
        self.assertIn('"{{ repo_dir }}/bin/cloudseed", -y, install', clients)
        self.assertNotIn("curl", clients)
        checks = _task(tools, "Verify native cluster administration clients")
        for command in ("[kubectl, version, --client]", "[helm, version, --short]", "[k9s, version]"):
            self.assertIn(command, checks)

    def test_vmware_kubectl_matches_explicit_versions_or_the_kubeadm_default(self):
        cloud = SimpleNamespace(key="vmware")
        self.assertEqual(provision.cluster_version(cloud, {"vars": {"kubernetes_distro": "kubeadm"}}, {}), "1.35")
        self.assertIn("or '1.35'", (ROOT / "ansible/roles/kubeadm/tasks/main.yml").read_text())
        self.assertEqual(provision.cluster_version(cloud, {"vars": {"kubernetes_distro": "rke2"}}, {}), "")
        for value in ("v1.36.4+rke2r1", "1.36"):
            self.assertEqual(provision.cluster_version(cloud, {"vars": {"kubernetes_version": value}}, {}), value)


if __name__ == "__main__":
    unittest.main()
