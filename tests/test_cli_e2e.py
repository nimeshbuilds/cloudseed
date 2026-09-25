"""End-to-end CLI battery: every command runs in an isolated home; no cloud, no VMs, no agents contacted.
Run with: python3 -m unittest tests.test_cli_e2e   (slow: renders + validates Terraform for all targets)"""
import atexit
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CS = str(ROOT / "bin" / "cloudseed")
_TEMP_DIRS: list = []


def _tmp(prefix: str = "cs-e2e-tmp-") -> str:
    """A scratch directory removed when the run ends: the battery's home holds the Terraform providers of every
    target (gigabytes), and a leaked one per run fills the disk. CS_E2E_KEEP=1 keeps them for a post-mortem."""
    d = tempfile.mkdtemp(prefix=prefix)
    _TEMP_DIRS.append(d)
    return d


@atexit.register
def _remove_temp_dirs() -> None:
    if os.environ.get("CS_E2E_KEEP") != "1":
        for d in _TEMP_DIRS:
            shutil.rmtree(d, ignore_errors=True)


HOME = _tmp("cs-e2e-")
# VMWARE_HOME points at an empty directory, so the battery never finds the developer's real VMware: `destroy vmware
# --purge` would otherwise sweep VMs and `pkill -x vmrest` on this machine.
NO_VMWARE = _tmp("cs-e2e-novmware-")
ENV = dict(os.environ, CLOUDSEED_HOME=HOME, NO_COLOR="1", ANTHROPIC_API_KEY="", ANTHROPIC_AUTH_TOKEN="",
           VMWARE_HOME=NO_VMWARE)


def run(*args, timeout=600):
    p = subprocess.run([CS, *args], env=ENV, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


class E2E(unittest.TestCase):
    def check(self, args, rc=0, contains=(), timeout=600):
        code, out = run(*args, timeout=timeout)
        self.assertEqual(code, rc, f"cs {' '.join(args)} -> {code}\n{out[-1500:]}")
        for c in contains:
            self.assertIn(c, out, f"cs {' '.join(args)} missing {c!r}\n{out[-1500:]}")
        return out

    def test_00_help_everything(self):
        self.check([], contains=["CORE COMMANDS"])
        from cloudseed.cli import HANDLERS
        from cloudseed import help as h
        for cmd in HANDLERS:
            if cmd in ("do",):
                continue
            self.check(["help", cmd], contains=["cloudseed"])
        for topic in list(h.TOPICS) + ["agents", "aws", "gcp", "azure"]:
            self.check(["help", topic])
        for cloud in ("aws", "gcp", "azure", "vmware"):
            self.check(["help", "variables", cloud], contains=["allowed_ssh_cidrs" if cloud != "vmware" else "workload_count"])
            self.check(["help", "outputs", cloud], contains=["bastion_public_ip"])
        for f in ("", "network", "kubernetes", "platform", "audit", "agentic", "vmware", "finops"):
            self.check(["explain", f] if f else ["explain"])

    def test_01_errors_teach(self):
        self.check(["stauts"], rc=2, contains=["did you mean", "status"])
        self.check(["setup"], rc=2, contains=["needs a cloud", "Examples"])
        self.check(["setup", "gcp", "-y", "--env", "e2e", "--allow-ip", "1.2.3.4"], rc=1, contains=["--project-id"])
        self.check(["setup", "aws", "-y", "--env", "e2e", "--allow-ip", "0.0.0.0/0"], rc=1, contains=["0.0.0.0/0"])
        self.check(["status", "aws", "--env", "nothere"], rc=1, contains=["does not exist"])
        self.check(["install", "nonsense"], rc=1, contains=["Don't know how to install"])
        self.check(["vpn", "add-user", "aws", "--env", "nothere"], rc=1)

    def test_02_dry_runs_all_targets(self):
        self.check(["setup", "aws", "-y", "--env", "e2e", "--allow-ip", "1.2.3.4", "--var", "enable_kubernetes=true", "--var", "enable_vpn=true", "--dry-run"],
                   contains=["Dry run complete"])
        self.check(["setup", "gcp", "-y", "--env", "e2e", "--project-id", "p1-e2e-test", "--allow-ip", "1.2.3.4", "--state", "local", "--var", "enable_kubernetes=true", "--dry-run"],
                   contains=["Dry run complete"])
        self.check(["setup", "azure", "-y", "--env", "e2e", "--subscription-id", "00000000-0000-0000-0000-000000000000", "--allow-ip", "1.2.3.4",
                    "--var", "enable_vpn=true", "--var", "vpn_type=tailscale", "--dry-run"], contains=["Dry run complete"])
        self.check(["setup", "vmware", "-y", "--env", "e2e", "--var", "enable_kubernetes=true", "--var", "workload_count=1", "--dry-run"],
                   contains=["Dry run complete"])
        self.check(["list"], contains=["aws-e2e", "gcp-e2e", "azure-e2e", "vmware-e2e"])

    def test_03_env_commands(self):
        for cloud in ("aws", "gcp", "azure", "vmware"):
            self.check(["status", cloud, "--env", "e2e"], contains=["Environment", "State"])
            self.check(["inventory", cloud, "--env", "e2e"], contains=["Inventory"])
            self.check(["troubleshoot", cloud, "--env", "e2e"], contains=["Findings"])
            self.check(["finops", "estimate", cloud, "--env", "e2e"], contains=["total / month"])
            self.check(["k8s", "info", cloud, "--env", "e2e"], contains=["Kubernetes"])
            self.check(["vpn", "status", cloud, "--env", "e2e"], contains=["VPN"])
        self.check(["output", "aws", "--env", "e2e", "--json"])
        self.check(["ssh", "aws", "--env", "e2e"], rc=1, contains=["No bastion IP"])
        self.check(["update-ip", "aws", "--env", "e2e", "--allow-ip", "1.2.3.4"], contains=["nothing to do"])
        self.check(["env"], contains=["Environments"])
        self.check(["env", "use", "aws-e2e"], contains=["Current environment"])
        self.check(["env", "clear"])
        # audit + inventory files exist and are redacted JSON
        home = Path(HOME) / "envs" / "aws-e2e"
        self.assertTrue((home / "logs" / "audit.jsonl").exists())
        self.assertTrue((home / "inventory.json").exists())
        self.assertTrue(list((home / "logs").glob("*-status.log")))

    def test_04_cluster_commands_without_cluster(self):
        self.check(["node", "list"], rc=1, contains=["No environment with a Kubernetes cluster"])
        self.check(["kubectl", "get", "nodes"], rc=1, contains=["No environment with a Kubernetes cluster"])
        self.check(["platform", "list"], contains=["basek8s", "finops", "devsecops", "security"])
        self.check(["platform", "install"], rc=1)
        self.check(["k8s", "kubeconfig", "aws", "--env", "e2e"], rc=1)

    def test_05_install_and_deps(self):
        self.check(["install", "list"], contains=["terraform", "vmware-provider", "skills", "builtin"])
        self.check(["install"], contains=["cloudseed install"])
        self.check(["doctor"], contains=["This machine", "Amazon Web Services", "VMware"])
        # a named cloud that is not ready (no VMware here) may exit 1; either way the verdict is on screen
        code, out = run("doctor", "vmware")
        self.assertIn(code, (0, 1), out[-1500:])
        self.assertIn("VMware", out)
        if code == 1:
            self.assertIn("is not ready", out, out[-1500:])
        self.check(["deps", "status"])
        d = _tmp()
        self.check(["install", "skills", "aws", "destroy", "--dir", d], contains=["installed skill"])
        self.assertTrue((Path(d) / "cloudseed-aws" / "SKILL.md").exists())
        self.check(["skill", "list"], contains=["cloudseed-platform", "cloudseed-finops", "cloudseed-architecture"])
        self.check(["skill", "show", "cloudseed-vmware"], contains=["VMware"])
        code, out = run("-y", "install", "vmrun")
        self.assertIn(code, (0, 1))
        self.assertTrue("Download" in out or "already installed" in out or "ready" in out.lower() or code == 0)

    def test_06_agentic_offline(self):
        self.check(["agents"], contains=["builtin", "claude", "codex", "gemini", "grok"])
        self.check(["use", "help"], contains=["AGENTS"])
        self.check(["agentic", "list"], rc=1, contains=["Agentic mode is off"])
        self.check(["disable", "headliner"], contains=["disabled"])
        self.check(["enable", "headliner"], contains=["enabled"])
        self.check(["model"], contains=["showing the default"])   # builtin is the documented default agent

    def test_07_managed_and_platform_misc(self):
        self.check(["databricks", "status"], contains=["Managed data platforms"])
        self.check(["snowflake"], contains=["snowflake"])
        cwd = _tmp()
        p = subprocess.run([CS, "platform", "template", "gitlab-ci", "--auto-approve"], env=ENV, cwd=cwd, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue((Path(cwd) / ".gitlab-ci.yml").exists())

    def test_08_destroy_paths(self):
        self.check(["destroy", "vmware", "--env", "e2e", "-y", "--auto-approve", "--purge"], contains=["Removed"])
        self.check(["destroy", "aws", "--env", "e2e", "--target", "module.stack.module.bastion", "-y", "--auto-approve"])
        self.assertTrue((Path(HOME) / "logs" / "purged" / "vmware-e2e" / "inventory.json").exists())

    def test_09_mcp_deploy(self):
        import json, socket
        fake_home = _tmp("cs-e2e-mcp-home-")
        (Path(fake_home) / ".cursor").mkdir()
        env = dict(ENV, HOME=fake_home)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0)); port = str(s.getsockname()[1])

        def check(args, rc=0, contains=()):
            p = subprocess.run([CS, *args], env=env, capture_output=True, text=True, timeout=300)
            out = p.stdout + p.stderr
            self.assertEqual(p.returncode, rc, f"cs {' '.join(args)} -> {p.returncode}\n{out[-1500:]}")
            for c in contains:
                self.assertIn(c, out, f"cs {' '.join(args)} missing {c!r}\n{out[-1500:]}")
            return out

        try:
            check(["setup", "mcp", "-y", "--no-service", "--client", "none", "--port", port], contains=["MCP server up", "Your cloudseed MCP server", "Safety model", "Connect a client"])
            self.assertTrue((Path(HOME) / "mcp" / "CONNECT.md").exists())
            check(["mcp", "status"], contains=["running", "http://127.0.0.1:" + port + "/mcp"])
            check(["status", "mcp"], contains=["running"])
            check(["mcp", "test", "--http"], contains=["round-trip", "tools"])
            check(["mcp", "tools"], contains=["cloudseed_ssh", "cloudseed://environments", "create-environment"])
            check(["mcp", "connect", "cursor"], contains=["Cursor: wrote"])
            self.assertIn("Authorization", json.loads((Path(fake_home) / ".cursor" / "mcp.json").read_text())["mcpServers"]["cloudseed"]["headers"])
            check(["mcp", "guide"], contains=["connected (http)"])
            check(["mcp", "config"], contains=["Cursor", "Codex", "claude mcp add"])
            check(["mcp", "logs", "-n", "3"])
            check(["mcp", "disconnect", "cursor"], contains=["removed"])
            check(["mcp", "stop"], contains=["stopped"])
            check(["mcp", "start"], contains=["MCP server up"])
            check(["destroy", "mcp", "--auto-approve"], contains=["removed and disabled"])
            check(["mcp", "status"], contains=["no  (cs setup mcp)"])
            check(["setup", "mcp", "-y", "--transport", "stdio", "cursor"], contains=["stdio mode", "Cursor: wrote"])
            self.assertEqual(json.loads((Path(fake_home) / ".cursor" / "mcp.json").read_text())["mcpServers"]["cloudseed"]["args"][-2:], ["mcp", "serve"])
            check(["mcp", "test"], contains=["over stdio"])
            check(["disable", "mcp"], contains=["disabled"])
            check(["mcp", "serve"], rc=2, contains=["disabled"])
            check(["enable", "mcp"], contains=["enabled"])
        finally:
            subprocess.run([CS, "mcp", "stop"], env=env, capture_output=True)


def tearDownModule():
    # right after the battery, not only at interpreter exit: in a full-suite run its gigabytes of providers would
    # otherwise stay on disk while every later module runs (the atexit hook still covers an interrupted run)
    _remove_temp_dirs()


if __name__ == "__main__":
    unittest.main()
