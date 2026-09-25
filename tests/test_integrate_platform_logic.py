"""Integration of fix/platform-logic with the agentic, mcp, ops and webui-backend fixes.

Offline: no cluster, no network; the only child process is a local python that prints a fake private key.
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, clouds, managed, mcp, paths, platform as pl, secrets  # noqa: E402


def _ctx(name="intpl"):
    env = paths.Env("vmware", name)
    env.create_dirs()
    cfg = {"env": name, "region": "r", "network_cidr": "10.100.0.0/24", "vars": {}, "platform_prereqs": []}
    return pl.Cluster(clouds.get("vmware"), env, cfg, {"kubernetes_distro": "rke2"}, env.dir / "k8s" / "kubeconfig")


class McpConsentTests(unittest.TestCase):
    """services.ensure_tool treats --auto-approve as consent to install kubectl/helm: read-only MCP/console actions
    (which need no confirm) must not carry it, the confirmed ones still do."""

    def test_read_only_actions_do_not_pre_approve_installs(self):
        cases = {"cloudseed_platform": (["list", "status", "plan", "info"], ["install", "uninstall", "ui"]),
                 "cloudseed_chaos": (["list", "status", "report"], ["run", "stop"]),
                 "cloudseed_dr": (["status", "backups"], ["backup", "restore", "schedule", "test"]),
                 "cloudseed_node": (["list"], ["add", "remove"])}
        for tool, (read_only, mutating) in cases.items():
            t = mcp.TOOLS[tool]
            for action in read_only:
                a = {"action": action}
                self.assertFalse(mcp._is_destructive(t, a), (tool, action))
                argv = t["argv"](a)
                self.assertIn("-y", argv)
                self.assertNotIn("--auto-approve", argv, (tool, action))
            for action in mutating:
                a = {"action": action, "confirm": True}
                self.assertTrue(mcp._is_destructive(t, a), (tool, action))
                self.assertIn("--auto-approve", t["argv"](a), (tool, action))


class SharedMaskingTests(unittest.TestCase):
    def test_managed_echo_uses_the_shared_mask_plus_its_own_flags(self):
        out = managed.mask_argv(["sql", "-p", "SnowPass99", "--api-key", "k3y-value-123", "--pat=dapi0123456789",
                                 "--private-key-passphrase", "phrase-1234", "--string-value", "TopSecretValue123", "-q", "select 1"])
        joined = " ".join(out)
        for s in ("SnowPass99", "k3y-value-123", "dapi0123456789", "phrase-1234", "TopSecretValue123"):
            self.assertNotIn(s, joined)
        self.assertEqual(len(out), 12)
        self.assertEqual(out[-2:], ["-q", "select 1"])

    def test_audit_argv_masks_secret_flag_values(self):
        out = audit.safe_argv(["databricks", "secrets", "put-secret", "s", "k", "--string-value", "PlainLookingValue1"])
        self.assertNotIn("PlainLookingValue1", " ".join(out))
        self.assertEqual(out[:6], ["databricks", "secrets", "put-secret", "s", "k", "--string-value"])
        out = audit.safe_argv(["kubectl", "vmware", "create", "secret", "generic", "x", "--from-literal=pw=AnotherValue22",
                               "--password", "Pl41nValue77"])
        self.assertNotIn("AnotherValue22", " ".join(out))
        self.assertNotIn("Pl41nValue77", " ".join(out))
        self.assertIn("--from-literal=pw=[REDACTED]", out)
        snow = audit.safe_argv(["-y", "snowflake", "sql", "-p", "Secr3tPw99", "-q", "select 1"])
        self.assertNotIn("Secr3tPw99", " ".join(snow))
        self.assertEqual(snow[-2:], ["-q", "select 1"])

    def test_generated_platform_secrets_reach_the_shared_redactor(self):
        value = "Gen3ratedPlatformPw"
        pl._remember_secret(value)
        self.assertNotIn(value, secrets.redact(f"mc alias set m http://x admin {value}"))
        self.assertNotIn(value, pl._redact(f"--set x={value}"))


class RunStreamTests(unittest.TestCase):
    def test_a_private_key_over_several_lines_is_hidden_whole(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
        script = ("print('before'); print('-----BEGIN " "PRIVATE KEY-----'); print(%r); print(%r); "
                  "print('-----END PRIVATE KEY-----'); print('after'); import sys; sys.stdout.buffer.write(b'bad \\xff byte\\n')") % (body, body[::-1])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = pl._run([sys.executable, "-c", script], _ctx(), check=False)
        out = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("before", out)
        self.assertIn("after", out)
        self.assertIn("bad", out)            # undecodable output does not crash the stream
        self.assertNotIn(body, out)
        self.assertNotIn(body[::-1], out)


if __name__ == "__main__":
    unittest.main()
