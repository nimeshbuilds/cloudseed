"""Real bounded capture and credential isolation/migration security regressions."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-operations-test-"))

from cloudseed import capture, credential_scope, credential_store, creds, secrets


class CaptureSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)

    def collect(self, code, split=False):
        environment = dict(os.environ, CLOUDSEED_HOME=str(self.folder / "home"), CLOUDSEED_AGENT="mcp", PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        environment.pop("CLOUDSEED_SESSION", None)
        spec = json.dumps({"argv": [sys.executable, "-c", code], "split": split})
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            child = subprocess.run([sys.executable, str(Path(capture.__file__)), spec], env=environment,
                                   stdout=stdout, stderr=stderr, timeout=10)
            stdout.seek(0)
            stderr.seek(0)
            out, err = stdout.read(), stderr.read()
            self.assertLessEqual(len(out), capture.LIMIT)
            self.assertLessEqual(len(err), capture.LIMIT)
            return child.returncode, out.decode(), err.decode()

    def test_real_capture_preserves_json_and_child_exit_code(self):
        rc, out, err = self.collect("import sys;print('{\"verdict\":\"INCOMPLETE\",\"checks\":[]}');print('note',file=sys.stderr);sys.exit(3)", split=True)
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(out)["verdict"], "INCOMPLETE")
        self.assertEqual(err.strip(), "note")

    def test_nested_secret_context_redacted_before_tail_truncation(self):
        # The secret name is deliberately outside the retained tail. Line-only
        # truncation without streaming redaction would expose the final values.
        code = "print('prefix\\n'*20000);print('stringData:');print('  ordinary: confidential-value\\n'*18000);print('safe: done')"
        rc, out, _ = self.collect(code)
        self.assertEqual(rc, 0)
        self.assertIn("output truncated", out)
        self.assertNotIn("confidential-value", out)
        self.assertIn("safe: done", out)

    def test_key_spanning_chunks_does_not_leak_in_tail(self):
        code = "import sys;sys.stdout.write('-----BEGIN PRIVATE KEY-----\\n');sys.stdout.write('secretkeyfragment\\n'*250);sys.stdout.write('-----END PRIVATE KEY-----\\n')"
        rc, out, _ = self.collect(code)
        self.assertEqual(rc, 0)
        self.assertNotIn("secretkeyfragment", out)
        self.assertIn("REDACTED", out)

    def test_oversize_unbroken_line_is_drained_and_never_partially_leaked(self):
        code = "import sys;sys.stdout.write('x'*2000000);sys.stdout.write('secret-fragment\\n')"
        rc, out, _ = self.collect(code)
        self.assertEqual(rc, 0)
        self.assertIn("remaining output omitted", out)
        self.assertNotIn("secret-fragment", out)
        self.assertNotIn("x" * 100, out)

    def test_literal_credential_is_hidden_when_split_across_writes(self):
        with patch.dict(os.environ, {"TEST_PASSWORD": "literal-secret-value-123"}):
            rc, out, _ = self.collect("import sys,time;sys.stdout.write('literal-secret-');sys.stdout.flush();time.sleep(.02);print('value-123')")
        self.assertEqual(rc, 0)
        self.assertNotIn("literal-secret-value", out)
        self.assertIn("REDACTED", out)

    def test_split_streams_do_not_share_secret_context(self):
        code = "import sys;print('stringData:');print('  value: hidden');print('value: ordinary',file=sys.stderr)"
        rc, out, err = self.collect(code, split=True)
        self.assertEqual(rc, 0)
        self.assertNotIn("hidden", out)
        self.assertIn("ordinary", err)

    def test_source_collector_does_not_shadow_stdlib_secrets(self):
        rc, out, err = self.collect("import secrets;print(len(secrets.token_hex(4)))")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "8")


class CredentialScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.store = self.folder / "credentials.json"
        self.gcp = self.folder / "gcp-credentials.json"
        self.addCleanup(patch.stopall)
        patch.object(creds, "STORE", self.store).start()
        patch.object(creds, "GCP_FILE", self.gcp).start()
        patch.object(secrets, "_STRICT", {"on": False}).start()
        patch.object(secrets, "_REGISTERED", set()).start()
        patch.object(secrets, "_LIT_CACHE", {"stamp": None, "values": ()}).start()

    def test_cloud_scope_excludes_other_clouds_and_agents(self):
        scope = {"cloud": "aws", "services": []}
        self.assertTrue(credential_scope.permitted("AWS_SECRET_ACCESS_KEY", scope, True))
        for key in ("GOOGLE_CREDENTIALS", "AZURE_CLIENT_SECRET", "OPENAI_API_KEY", "CUSTOM_PASSWORD", "UBUNTU_PRO_TOKEN"):
            self.assertFalse(credential_scope.permitted(key, scope, True), key)
        self.assertTrue(credential_scope.permitted("PATH", scope, False))

    def test_explicit_platform_model_key_scope_preserves_kagent(self):
        scope = credential_scope.for_argv(["platform", "install", "kagent", "--cloud", "aws"])
        self.assertIsNotNone(scope)
        self.assertTrue(credential_scope.permitted("OPENAI_API_KEY", scope, True))
        limited = credential_scope.for_argv(["platform", "install", "grafana", "--cloud", "aws"])
        self.assertFalse(credential_scope.permitted("OPENAI_API_KEY", limited, True))

    def test_scope_parser_rejects_unknown_or_unhashable_services(self):
        for services in (["ARBITRARY_KEY"], [{}], "bad"):
            with self.assertRaises(ValueError):
                credential_scope.parse(json.dumps({"cloud": "aws", "services": services}))

    def test_aws_scope_does_not_remove_concurrent_gcp_key_file(self):
        self.store.write_text(json.dumps({"GOOGLE_CREDENTIALS": '{"private_key":"fake-secret"}', "AWS_SECRET_ACCESS_KEY": "aws-secret"}))
        self.gcp.write_text("key-in-use-by-gcp")
        with patch.dict(os.environ, {credential_scope.MARKER: json.dumps({"cloud": "aws", "services": []})}):
            out = creds.env()
        self.assertEqual(self.gcp.read_text(), "key-in-use-by-gcp")
        self.assertNotIn("GOOGLE_CREDENTIALS", out)
        self.assertEqual(out["AWS_SECRET_ACCESS_KEY"], "aws-secret")

    def test_explicit_gcp_scope_can_retire_removed_key(self):
        self.store.write_text("{}")
        self.gcp.write_text("stale-key")
        env = {credential_scope.MARKER: json.dumps({"cloud": "gcp", "services": []})}
        with patch.dict(os.environ, env, clear=True):
            creds.env()
        self.assertFalse(self.gcp.exists())

    def test_scoped_credential_session_parks_only_needed_values(self):
        captured = {}
        def broker(values):
            captured.update(values)
            return {"kind": "file", "path": self.folder / "not-created", "handle": "1234567890abcdef"}
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "aws-secret", "GOOGLE_CREDENTIALS": "google-secret", "OPENAI_API_KEY": "model-secret"}, clear=True), \
             patch.object(secrets, "_start_broker", side_effect=broker), patch.object(secrets, "_sweep_stale"), \
             patch.object(secrets, "_vault_secret_keys", return_value=set()), patch.object(secrets, "_install_signal_handlers"):
            sid, environment = secrets.open_session(scope={"cloud": "aws", "services": []})
        try:
            self.assertEqual(captured, {"AWS_SECRET_ACCESS_KEY": "aws-secret"})
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
            self.assertNotIn("GOOGLE_CREDENTIALS", environment)
            self.assertEqual(json.loads(environment[credential_scope.MARKER])["cloud"], "aws")
        finally:
            secrets.close_session(sid)


class KeychainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.store = self.folder / "credentials.json"
        self.data = {"AWS_SECRET_ACCESS_KEY": "a-long-private-test-value"}
        self.store.write_text(json.dumps(self.data))
        self.addCleanup(patch.stopall)
        patch.object(creds, "STORE", self.store).start()
        patch.object(secrets, "_LIT_CACHE", {"stamp": None, "values": ()}).start()
        self.native = {}
        class Backend:
            def get_password(inner, service, account):
                return self.native.get((service, account))
            def set_password(inner, service, account, data):
                self.native[(service, account)] = data
            def delete_password(inner, service, account):
                self.native.pop((service, account), None)
        patch.object(credential_store, "_native", return_value=Backend()).start()

    def test_migration_verifies_keychain_before_retiring_plaintext(self):
        report = credential_store.execute("credentials-backend", None, None, {}, {"backend": "os-keychain", "approve": True})
        self.assertTrue(report["changed"])
        self.assertFalse(self.store.exists())
        self.assertEqual(creds.load(), self.data)
        self.assertNotIn(self.data["AWS_SECRET_ACCESS_KEY"], json.dumps(report))
        back = credential_store.execute("credentials-backend", None, None, {}, {"backend": "file", "approve": True})
        self.assertTrue(back["changed"])
        self.assertEqual(creds.load(), self.data)
        self.assertFalse(self.native)
        self.assertEqual(self.store.stat().st_mode & 0o777, 0o600)

    def test_failed_verification_preserves_original_selection_and_file(self):
        with patch.object(credential_store, "read", return_value={}):
            with self.assertRaises(ValueError):
                credential_store.execute("credentials-backend", None, None, {}, {"backend": "os-keychain", "approve": True})
        self.assertEqual(json.loads(self.store.read_text()), self.data)
        self.assertEqual(credential_store.metadata(self.store)["backend"], "file")

    def test_preview_does_not_write_keychain_or_retire_file(self):
        report = credential_store.execute("credentials-backend", None, None, {}, {"backend": "os-keychain"})
        self.assertEqual(report["verdict"], "PLAN")
        self.assertFalse(self.native)
        self.assertTrue(self.store.exists())

    def test_symlinked_plaintext_vault_refused_without_touching_target(self):
        target = self.folder / "external.json"
        self.store.rename(target)
        self.store.symlink_to(target)
        with self.assertRaises(ValueError):
            credential_store.execute("credentials-backend", None, None, {}, {"backend": "os-keychain", "approve": True})
        self.assertEqual(json.loads(target.read_text()), self.data)
        self.assertTrue(self.store.is_symlink())
        self.assertFalse(self.native)

    def test_keychain_writes_invalidate_redaction_literal_cache(self):
        secrets._LIT_CACHE["stamp"] = ("sentinel",)
        credential_store.write(self.store, self.data)
        self.assertIsNone(secrets._LIT_CACHE["stamp"])
        secrets._LIT_CACHE["stamp"] = ("sentinel",)
        credential_store.clear(self.store)
        self.assertIsNone(secrets._LIT_CACHE["stamp"])

    def test_invalid_backend_metadata_never_falls_back_to_plaintext(self):
        self.store.with_name("credential-backend.json").write_text('{"backend":"plaintext-fallback"}')
        with self.assertRaises(ValueError):
            creds.load()


if __name__ == "__main__":
    unittest.main()
