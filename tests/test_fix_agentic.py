"""Regression tests for the agentic layer: redaction, the session broker, the credential vault, skills installs,
agent registry/login detection and the built-in agent's command policy."""

import base64
import contextlib
import io
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import agents, builtin_agent, creds, headliner, paths, secrets, skills, ui, undo  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
R = secrets.REDACTED


def _cli(args, home, extra_env=None, stdin=subprocess.DEVNULL):
    env = dict(os.environ, CLOUDSEED_HOME=str(home), HOME=str(home), NO_COLOR="1")
    env.pop("CLOUDSEED_REDACT", None)
    env.pop("CLOUDSEED_SESSION", None)
    env.update(extra_env or {})
    return subprocess.run([sys.executable, str(REPO / "bin" / "cloudseed")] + list(args), env=env, text=True,
                          capture_output=True, stdin=stdin, timeout=120)


# ------------------------------------------------------------------------------------------------ redaction

class RedactorTests(unittest.TestCase):
    # secret-shaped values are assembled from parts ("glpat-" + "..."): the source never holds a literal secret
    # scanners or GitHub push protection would report (test_repo_hygiene checks the whole tree)
    LEAKS = [
        ('{"SecretAccessKey": "' + 'wJalrXUtnFEMI/K7MDENG' + '/bPxRfiCYzzzz"}', "wJalr"),
        ('{"password": "hunter2hunter2"}', "hunter2"),
        ('{"client_secret": "zzzzzzzz9"}', "zzzzzzzz9"),
        ("{'k8s_token': 'abcdefgh'}", "abcdefgh"),
        ('password: "correct horse battery staple"', "horse"),
        ("postgres://admin:" + "S3cr3tP4ss@db:5432/x", "S3cr3tP4ss"),
        ("https://deploy:" + "hunter2hunter2@git.example.com/r", "hunter2hunter2"),
        ("mongodb+srv://root:" + "P4ssw0rd!@c0.mongodb.net", "P4ssw0rd!"),
        ("DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + "abcDEF123==;EndpointSuffix=core", "abcDEF123"),
        ("https://x.blob.core.windows.net/c?sv=2020&sig=AbCdEf%2Bgh&se=1", "AbCdEf"),
        ("github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF", "github_pat_11"),
        ("glpat-" + "abcdefghijklmnopqrst12", "glpat-"),
        ("dapi" + "0123456789abcdef0123456789abcdef", "dapi01"),
        ("hvs." + "CAESIabcdefghijklmnopqrstuvwxyz", "hvs.CAE"),
        ("npm_" + "abcdefghijklmnopqrstuvwxyz0123456789", "npm_abc"),
        ("sk_live_" + "abcdefghijklmnop1234", "sk_live"),
        ("TS_AUTHKEY=tskey-" + "auth-kABCDEF1CNTRL-abcdefghijklmnop", "tskey-auth"),
        ('tailscale_auth_key = "tskey-9999"', "tskey-9999"),
        ("client-key-data: " + base64.b64encode(b"-----BEGIN " + b"RSA PRIVATE KEY-----\n").decode(), "LS0tLS1CRUdJTi"),
        ("rootPassword:\n  value: N3xusS3cretPw", "N3xusS3cretPw"),   # nested (helm get values): not mangled, hidden
        ("password=abc12", "abc12"),
        ("DB_PWD=abcd1234", "abcd1234"),
        ("passphrase=correcthorse", "correcthorse"),
        ("--set monitoringPasscode=Abc123XYZ_def456", "Abc123XYZ"),
        ('"cmd": ["kubeadm", "join", "--token", "abcdef.' + '0123456789abcdef"]', "abcdef.0123456789abcdef"),
        ("kubeadm join 10.0.0.1:6443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:1", "abcdef.01"),
        ("secret_id=abcdef0123", "abcdef0123"),
        ("ARM_SAS_TOKEN=sv2020abc", "sv2020abc"),
        ("aws_secret_access_key=" + "wJalrXUtnFEMI/K7MDENG", "wJalr"),
        ("-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\nabcSECRET\n-----END PGP PRIVATE KEY BLOCK-----", "abcSECRET"),
        ("hook https://hooks.slack.com" + "/services/T000/B000/XXXXXXXX", "XXXXXXXX"),
        ("AKIA" + "IOSFODNN7EXAMPLE", "AKIA" + "IOSFODNN7EXAMPLE"),
        ("redis://:p4ssw0rdp4ss@redis:6379/0", "p4ssw0rd"),
        ("API_KEYS=" + "abcdef123456", "abcdef123456"),
        ("db_passwords: hunter2x", "hunter2x"),
    ]
    KEEP = [
        "module.stack.module.security_baseline[0].aws_iam_account_password_policy.this: Creating...",
        "aws_iam_account_password_policy.this: Creation complete after 1s [id=iam-account-password-policy]",
        "aws_iam_role_policy.external_secrets: Destroying... [id=abc]",
        "google_secret_manager_secret.db: Still creating... [10s elapsed]",
        'kubernetes_external_secrets_client_id = "0000-1111-2222"',
        'external_secrets_gsa = "x@p.iam.gserviceaccount.com"',
        "sasl.mechanism=SCRAM-SHA-512",
        "+ password = (sensitive value)",
        "external-secrets: install it",
        "token: true",
        '"password": null',
        '"password": ""',
        "design=foo",
        "oci://registry:5000/x@sha256:abcdef",
        "Basic authentication",
        "--discovery-token-ca-cert-hash sha256:0123456789",
        'secret_arn = "arn:aws:secretsmanager:us-east-1:1:secret:x"',
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-AbCd",
        "kubernetes_secret_name: my-secret",
        "secretName: grafana-tls",
        "task-sk-abcdefghijklmnopqrstuvwxyz",
        "max_tokens=16000",
        "credentials: detected",
        "Enter passphrase for key '/x/id':",
        "minimum_password_length = 14",
        "http://127.0.0.1:7434/",
        "PWD=/Users/x",
        "docker login --password-stdin -u x",
        "ssh://git@github.com:22/x.git",
        "rootUser:\n  value: plain",
        "other:\n  value: plain",
    ]

    def test_leaks_are_redacted(self):
        for text, secret in self.LEAKS:
            with self.subTest(text=text):
                self.assertNotIn(secret, secrets.redact(text))

    def test_non_secrets_are_left_alone(self):
        for text in self.KEEP:
            with self.subTest(text=text):
                self.assertEqual(secrets.redact(text), text)

    def test_value_that_starts_like_a_keyword_is_still_redacted(self):
        self.assertNotIn("readonly123", secrets.redact("password: readonly123"))
        self.assertNotIn("nomore123", secrets.redact("token=nomore123"))

    def test_quoted_value_keeps_quotes_and_is_idempotent(self):
        out = secrets.redact('{"password": "hunter2hunter2"}')
        self.assertEqual(out, '{"password": "[REDACTED]"}')
        for t in ('password=[REDACTED]', '--token [REDACTED]', out, "http://h/?token=[REDACTED]"):
            self.assertEqual(secrets.redact(t), t)

    def test_existing_pattern_test_still_holds(self):
        key_id, secret = "AKIA" + "IOSFODNN7EXAMPLE", "wJalr" + "XUtnFEMI/K7MDENG" + "/bPxRfiCYEXAMPLEKEY"   # AWS docs' pair
        text = (f"{key_id} aws_secret_access_key={secret} "
                "-----BEGIN " "RSA PRIVATE KEY-----\nxx\n-----END RSA PRIVATE KEY----- sk-ant-" "abcdefghijklmnopqrstuvwxyz "
                "password: hunter2secret plain text stays")
        out = secrets.redact(text)
        for s in (key_id, "wJalrXUtnFEMI", "BEGIN RSA", "sk-ant-", "hunter2secret"):
            self.assertNotIn(s, out)
        self.assertIn("plain text stays", out)

    def test_linear_time_on_pathological_input(self):
        blob = base64.urlsafe_b64encode(os.urandom(225000)).decode()
        for text in ("a." * 50000, blob, "-".join("abcd" for _ in range(40000)), "token" * 20000, "a:" * 50000,
                     ("-----BEGIN " + "RSA PRIVATE KEY-----") * 4000, "-----BEGIN " + "A" * 200000):
            t = time.time()
            secrets.redact(text)
            self.assertLess(time.time() - t, 3.0, text[:20])

    def test_vault_values_are_redacted_literally(self):
        saved = creds.load()
        try:
            creds.set_("MY_ODD_SECRET", "zq9-plain-looking-value")
            creds.set_("AWS_PROFILE", "prodprofile")
            out = secrets.redact("connecting with zq9-plain-looking-value as prodprofile")
            self.assertNotIn("zq9-plain-looking-value", out)
            self.assertIn("prodprofile", out)   # text-kind values are not secrets
        finally:
            creds.save(saved)

    def test_tokens_and_bearer_only_hidden_in_agent_contexts(self):
        tok_path = paths.HOME / "mcp" / "token"
        tok_path.parent.mkdir(parents=True, exist_ok=True)
        tok = "f" * 20 + "0123456789abcdef0123456789abcdef"
        tok_path.write_text(tok + "\n")
        line = f"Authorization: Bearer {tok}"
        try:
            with mock.patch.dict(secrets._STRICT, {"on": False}), mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": ""}):
                self.assertIn(tok, secrets.redact(line))           # web console / terminal show the user their config
            with mock.patch.dict(secrets._STRICT, {"on": True}):
                self.assertNotIn(tok, secrets.redact(line))
                self.assertNotIn(tok, secrets.redact(tok))          # bare token (cs mcp token)
        finally:
            tok_path.unlink()

    def test_mask_argv(self):
        out = secrets.mask_argv(["secrets", "put-secret", "s", "k", "--string-value", "X1234567", "--password=abcdefgh",
                                 "--from-literal=pw=Secret123", "--set", "grafana.adminPassword=zzzzzzzz"])
        joined = " ".join(out)
        for s in ("X1234567", "abcdefgh", "Secret123", "zzzzzzzz"):
            self.assertNotIn(s, joined)
        self.assertIn("--from-literal=pw=[REDACTED]", out)

    def test_env_flag(self):
        for val, want in (("1", True), ("true", True), (" YES ", True), ("on", True), ("0", False), ("false", False),
                          ("no", False), ("", False)):
            with mock.patch.dict(os.environ, {"X_FLAG": val}):
                self.assertEqual(secrets.env_flag("X_FLAG"), want, val)


class StreamRedactorTests(unittest.TestCase):
    KEY = ["prefix -----BEGIN " + "OPENSSH PRIVATE KEY-----\n", "b3BlbnNzaC1rZXktdjEAAAAA\n", "AAAAbm9uZQAAAARub25l\n",
           "-----END OPENSSH PRIVATE KEY----- tail password=hunter2hunter2\n", "after\n"]

    def test_multiline_private_key_is_swallowed(self):
        r = secrets.StreamRedactor()
        out = "".join(r.feed(line) for line in self.KEY)
        self.assertNotIn("b3BlbnNz", out)
        self.assertNotIn("AAAAbm9u", out)
        self.assertNotIn("hunter2", out)
        self.assertIn("prefix [REDACTED]", out)
        self.assertIn("after", out)
        self.assertIn("tail", out)

    def test_key_after_a_secret_looking_key_name_is_swallowed(self):
        for first in ("private_key: -----BEGIN " + "RSA PRIVATE KEY-----", '  "private_key": "-----BEGIN ' + 'PRIVATE KEY-----',
                      "tls.key: -----BEGIN " + "EC PRIVATE KEY-----"):
            r = secrets.StreamRedactor()
            out = "".join(r.feed(line + "\n") for line in (first, "MIIEpAIBAAKCAQEAsecretbody", "-----END RSA PRIVATE KEY-----", "ok"))
            self.assertNotIn("MIIEpAIBAAKCAQEAsecretbody", out)
            self.assertIn("ok", out)
            self.assertFalse(r.in_key)

    def test_single_line_block_and_stray_begin(self):
        r = secrets.StreamRedactor()
        self.assertEqual(r.feed("k -----BEGIN " + "RSA PRIVATE KEY-----\\nxx\\n-----END RSA PRIVATE KEY----- ok\n"), f"k {R} ok\n")
        self.assertFalse(r.in_key)
        r.feed("-----BEGIN " + "EC PRIVATE KEY-----\n")
        for _ in range(r.MAX_KEY_LINES + 5):
            r.feed("line\n")
        self.assertFalse(r.in_key)
        self.assertEqual(r.feed("visible again\n"), "visible again\n")

    def test_redacting_writer(self):
        buf = io.StringIO()
        w = secrets.RedactingWriter(buf)
        w.write("token=abcdefgh123 ")
        w.write("more\n")
        for line in self.KEY:
            w.write(line)
        w.write("partial password=zzzzzzzz")
        w.flush()
        out = buf.getvalue()
        for s in ("abcdefgh123", "b3BlbnNz", "zzzzzzzz"):
            self.assertNotIn(s, out)
        self.assertIn("more", out)
        self.assertEqual(w.getvalue(), out)   # attribute access falls through to the wrapped stream


# ------------------------------------------------------------------------------------------------ session broker

class SessionBrokerTests(unittest.TestCase):
    def setUp(self):
        self.saved = creds.load()

    def tearDown(self):
        creds.save(self.saved)
        secrets.close_all_sessions()
        secrets.set_strict(False)
        secrets._REGISTERED.clear()

    def _restore_in_child(self, env):
        code = ("import os,json; from cloudseed import secrets; secrets.restore_session_env(); "
                "print(json.dumps({k: os.environ.get(k) for k in ('TS_AUTHKEY','MY_DB_PASS','AWS_SECRET_ACCESS_KEY')}))")
        env = dict(env, PYTHONPATH=str(REPO))
        out = subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True, timeout=30)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_secret_env_names(self):
        for n in ("TS_AUTHKEY", "MY_DB_PASS", "SLACK_WEBHOOK_URL", "SENTRY_DSN", "DATABASE_URL", "ARM_ACCESS_KEY",
                  "SNOWFLAKE_PASSWORD", "MY_PASSPHRASE", "AZURE_STORAGE_CONNECTION_STRING", "DB_PWD"):
            self.assertTrue(secrets.is_secret_env(n), n)
        for n in ("PATH", "PWD", "OLDPWD", "GIT_ASKPASS", "SSH_AUTH_SOCK", "AWS_REGION", "BYPASS_PROXY", "HOME"):
            self.assertFalse(secrets.is_secret_env(n), n)

    def test_vault_secrets_are_parked_and_served_to_children_only(self):
        creds.set_("TS_AUTHKEY", "tskey-" + "auth-abc123xyzdefghijkl")
        creds.set_("MY_CUSTOM_THING", "custom-value-123")
        env_before = dict(os.environ)
        try:
            os.environ.update({"TS_AUTHKEY": "tskey-" + "auth-abc123xyzdefghijkl", "MY_CUSTOM_THING": "custom-value-123",
                               "MY_DB_PASS": "hunter2hunter2", "OPENAI_API_KEY": "sk-" + "keepme-000000000000000000"})
            sid, env = secrets.open_session(keep=("OPENAI_API_KEY",))
            for k in ("TS_AUTHKEY", "MY_CUSTOM_THING", "MY_DB_PASS"):
                self.assertNotIn(k, env)
            self.assertEqual(env["OPENAI_API_KEY"], "sk-" + "keepme-000000000000000000")
            self.assertEqual(env["CLOUDSEED_REDACT"], "1")
            handle = env["CLOUDSEED_SESSION"]
            got = self._restore_in_child(env)
            self.assertEqual(got["TS_AUTHKEY"], "tskey-" + "auth-abc123xyzdefghijkl")
            self.assertEqual(got["MY_DB_PASS"], "hunter2hunter2")
            if handle.startswith("sock:"):   # nothing on disk while the session is open
                self.assertFalse(any(secrets.SESSIONS_DIR.glob("*.json")) if secrets.SESSIONS_DIR.exists() else False)
                sock_dir = Path(handle[5:].rpartition("#")[0]).parent
                self.assertTrue(sock_dir.exists())
            secrets.close_session(sid)
            if handle.startswith("sock:"):
                self.assertFalse(sock_dir.exists())
            self.assertIsNone(self._restore_in_child(env)["TS_AUTHKEY"])   # gone with the session
        finally:
            os.environ.clear()
            os.environ.update(env_before)

    def test_wrong_nonce_gets_nothing(self):
        with mock.patch.dict(os.environ, {"MY_DB_PASS": "hunter2hunter2"}):
            sid, env = secrets.open_session()
        try:
            if not env["CLOUDSEED_SESSION"].startswith("sock:"):
                self.skipTest("no unix sockets here")
            forged = env["CLOUDSEED_SESSION"].rpartition("#")[0] + "#" + "0" * 64
            self.assertIsNone(self._restore_in_child(dict(env, CLOUDSEED_SESSION=forged))["MY_DB_PASS"])
        finally:
            secrets.close_session(sid)

    def test_file_fallback_and_stale_sweep(self):
        with mock.patch.object(secrets, "_start_broker", return_value=None), \
                mock.patch.dict(os.environ, {"MY_DB_PASS": "hunter2hunter2"}):
            sid, env = secrets.open_session()
        f = secrets.SESSIONS_DIR / f"{sid}.json"
        self.assertTrue(f.exists())
        self.assertEqual(oct(f.stat().st_mode & 0o777), "0o600")
        self.assertEqual(json.loads(f.read_text())["pid"], os.getpid())
        self.assertEqual(self._restore_in_child(env)["MY_DB_PASS"], "hunter2hunter2")
        secrets.close_session(sid)
        self.assertFalse(f.exists())
        # stale files: owner process gone, legacy flat file older than a week; a fresh legacy file is kept
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        stale = secrets.SESSIONS_DIR / "aaaaaaaaaaaaaaaa.json"
        stale.write_text(json.dumps({"pid": dead.pid, "env": {"X": "y"}}))
        old = secrets.SESSIONS_DIR / "bbbbbbbbbbbbbbbb.json"
        old.write_text(json.dumps({"X_TOKEN": "y"}))
        os.utime(old, (time.time() - 8 * 86400,) * 2)
        fresh = secrets.SESSIONS_DIR / "cccccccccccccccc.json"
        fresh.write_text(json.dumps({"X_TOKEN": "y"}))
        secrets._sweep_stale()
        self.assertFalse(stale.exists())
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())
        fresh.unlink()

    @unittest.skipUnless(os.name == "posix", "signals")
    def test_sigterm_ends_the_session(self):
        code = ("import os,signal,sys; from cloudseed import secrets\n"
                "os.environ['MY_DB_PASS']='hunter2hunter2'\n"
                "sid, env = secrets.open_session()\n"
                "print(env['CLOUDSEED_SESSION'], flush=True)\n"
                "os.kill(os.getpid(), signal.SIGTERM)\n"
                "import time; time.sleep(5)\n")
        env = dict(os.environ, PYTHONPATH=str(REPO))
        out = subprocess.run([sys.executable, "-c", code], env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(out.returncode, 128 + signal.SIGTERM)
        handle = out.stdout.strip()
        if handle.startswith("sock:"):
            self.assertFalse(Path(handle[5:].rpartition("#")[0]).parent.exists())
        else:
            self.assertFalse((secrets.SESSIONS_DIR / f"{handle}.json").exists())


# ------------------------------------------------------------------------------------------------ vault

class CredsVaultTests(unittest.TestCase):
    def setUp(self):
        self.saved = creds.load()

    def tearDown(self):
        creds.save(self.saved)

    def test_names(self):
        for bad in ("PYTHONPATH", "1ABC", "BAD KEY", "", "CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE", "BASH_ENV", "PATH",
                    "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "AWS_CONFIG_FILE", "KUBECONFIG", "NODE_OPTIONS", "É",
                    "GIT_SSH_COMMAND", "SSL_CERT_FILE", "TF_CLI_ARGS", "AWS_SHARED_CREDENTIALS_FILE", "PIP_INDEX_URL",
                    "GOFLAGS", "XDG_CONFIG_HOME"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                creds.set_(bad, "x")
        self.assertEqual(creds.check_key(" my_token "), "MY_TOKEN")
        self.assertEqual(creds.check_key("aws_profile"), "AWS_PROFILE")
        self.assertEqual(creds.check_key("TF_VAR_region"), "TF_VAR_REGION")

    def test_hand_edited_unsafe_names_are_never_injected(self):
        creds.save({"PYTHONPATH": "/evil", "CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE": "1", "OK_TOKEN": "abcdefghij"})
        env = creds.env()
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE", env)
        self.assertEqual(env["OK_TOKEN"], "abcdefghij")
        rows = {r["key"]: r for r in creds.masked()}
        self.assertTrue(rows["PYTHONPATH"].get("ignored"))
        self.assertIn("unsafe", rows["PYTHONPATH"]["hint"])
        # an undo that restores such a snapshot must not crash
        with contextlib.redirect_stderr(io.StringIO()):
            undo.perform({"kind": "creds-restore", "data": {"values": {"PYTHONPATH": "/x", "OK2_TOKEN": "v2v2v2v2"}},
                          "scope": "global", "summary": "x"}, {}, True)
        self.assertEqual(creds.load()["OK2_TOKEN"], "v2v2v2v2")

    def test_mask_is_fixed_length(self):
        self.assertEqual(creds._mask("abcdefghi"), creds._mask("abcdefghijk"))
        self.assertFalse(set("abcdefghijk") & set(creds._mask("abcdefghijk")))
        long = creds._mask("x" * 20 + "WXYZ")
        self.assertTrue(long.endswith("WXYZ"))
        self.assertEqual(len(long), len(creds._mask("y" * 40 + "WXYZ")))
        creds.set_("SNOWFLAKE_PASSWORD", "hunter2hunter2")
        creds.set_("GOOGLE_CREDENTIALS", '{"type": "service_account"}')
        rows = {r["key"]: r for r in creds.masked()}
        self.assertNotIn("hun", rows["SNOWFLAKE_PASSWORD"]["hint"])
        self.assertEqual(rows["GOOGLE_CREDENTIALS"]["hint"], "JSON key (service_account)")   # no "stored" prefix: the row says so

    def test_path_values_are_absolute(self):
        with mock.patch.dict(os.environ, {"HOME": "/Users/someone"}):
            stored = creds.set_("GOOGLE_APPLICATION_CREDENTIALS", "~/keys/proj.json")
        self.assertEqual(stored, "/Users/someone/keys/proj.json")
        self.assertEqual(creds.load()["GOOGLE_APPLICATION_CREDENTIALS"], "/Users/someone/keys/proj.json")
        stored = creds.set_("GOOGLE_APPLICATION_CREDENTIALS", "rel/key.json")
        self.assertTrue(os.path.isabs(stored))
        self.assertIsNotNone(creds.path_warning("GOOGLE_APPLICATION_CREDENTIALS", stored))
        creds.save({"GOOGLE_APPLICATION_CREDENTIALS": "~/legacy.json"})   # written by an older version
        with mock.patch.dict(os.environ, {"HOME": "/Users/someone"}):
            self.assertEqual(creds.env()["GOOGLE_APPLICATION_CREDENTIALS"], "/Users/someone/legacy.json")

    def test_gcp_key_copy_does_not_outlive_the_key(self):
        creds.save({})
        creds.set_("GOOGLE_CREDENTIALS", '{"type": "service_account", "private_key": "x"}')
        self.assertEqual(creds.env()["GOOGLE_APPLICATION_CREDENTIALS"], str(creds.GCP_FILE))
        self.assertTrue(creds.GCP_FILE.exists())
        creds.unset("GOOGLE_CREDENTIALS")
        self.assertFalse(creds.GCP_FILE.exists())
        creds.set_("GOOGLE_CREDENTIALS", '{"type": "service_account"}')
        creds.env()
        creds.clear()
        self.assertFalse(creds.GCP_FILE.exists())


# ------------------------------------------------------------------------------------------------ skills

class SkillsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-skills-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_resolve(self):
        self.assertEqual(skills.resolve("aws").name, "cloudseed-aws")
        self.assertEqual(skills.resolve("cloudseed").name, "cloudseed")
        self.assertEqual(skills.resolve("CLOUDSEED-VMWARE").name, "cloudseed-vmware")
        for bad in ("nope", "../../etc", "/etc", ".hidden", ""):
            with self.subTest(bad=bad), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                skills.resolve(bad)
        self.assertEqual({p.name for p in skills.resolve_names(["aws", "cloudseed-aws", "destroy"])},
                         {"cloudseed-aws", "cloudseed-destroy"})
        self.assertEqual(len(skills.resolve_names(None)), len(skills.available()))
        self.assertIn("vmware", skills.short_names())

    def test_unknown_name_writes_nothing(self):
        dest = self.tmp / "d"
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            skills.install(["aws", "bogus"], dest)
        self.assertFalse(dest.exists())

    def test_unrelated_directory_is_never_deleted(self):
        (self.tmp / "cloudseed" / "src").mkdir(parents=True)
        (self.tmp / "cloudseed" / "src" / "main.py").write_text("keep")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            skills.install(["cloudseed"], self.tmp)
        self.assertEqual((self.tmp / "cloudseed" / "src" / "main.py").read_text(), "keep")

    def test_source_tree_is_never_a_target(self):
        checkout = self.tmp / "cloudseed"
        shutil.copytree(skills.SKILLS_SRC, checkout / "skills")
        (checkout / "README.md").write_text("repo")
        with mock.patch.object(skills, "SKILLS_SRC", checkout / "skills"), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                skills.install(None, self.tmp)              # --dir <parent of the checkout>
            with self.assertRaises(SystemExit):
                skills.install(["aws"], checkout / "skills")  # --dir <repo>/skills
        self.assertTrue((checkout / "README.md").exists())
        self.assertTrue((checkout / "skills" / "cloudseed-aws" / "SKILL.md").exists())

    def test_symlinks(self):
        (self.tmp / "L").mkdir()
        os.symlink(skills.SKILLS_SRC / "cloudseed", self.tmp / "L" / "cloudseed")
        done = skills.install(["cloudseed"], self.tmp / "L")
        self.assertTrue((self.tmp / "L" / "cloudseed").is_symlink())
        self.assertEqual(len(done), 1)
        (self.tmp / "L2").mkdir()
        (self.tmp / "other").mkdir()
        (self.tmp / "other" / "mine.txt").write_text("keep")
        os.symlink(self.tmp / "other", self.tmp / "L2" / "cloudseed")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            done = skills.install(["cloudseed", "aws"], self.tmp / "L2")   # a hand-made link is left alone
        self.assertIn("Left", err.getvalue())
        self.assertEqual([p.name for p in done], ["cloudseed-aws"])
        self.assertTrue((self.tmp / "L2" / "cloudseed").is_symlink())
        self.assertEqual((self.tmp / "other" / "mine.txt").read_text(), "keep")
        self.assertEqual(sorted(os.listdir(self.tmp / "other")), ["mine.txt"])

    def test_linked_dev_checkout_does_not_block_the_refresh(self):
        # ~/.claude/skills/cloudseed -> another checkout (a dev setup): `use`/`agentic` must keep working
        other = self.tmp / "checkout" / "skills"
        shutil.copytree(skills.SKILLS_SRC, other)
        with mock.patch.dict(os.environ, {"HOME": str(self.tmp)}):
            dest = skills.target_dir("claude", None, False)
            dest.mkdir(parents=True)
            os.symlink(other / "cloudseed", dest / "cloudseed")
            self.assertEqual(skills.state("claude"), "stale")          # the other skills are missing
            with contextlib.redirect_stderr(io.StringIO()):
                skills.install(None, dest)                             # _ensure_agent_ready's refresh
            self.assertEqual(skills.state("claude"), "current")
            self.assertTrue((dest / "cloudseed").is_symlink())
            self.assertTrue(skills.installed("claude"))

    def test_reinstall_backs_up_and_undo_restores(self):
        dest = self.tmp / "D"
        first: dict = {}
        skills.install(["aws"], dest, backups=first)
        self.assertEqual(first, {str(dest / "cloudseed-aws"): None})
        self.assertTrue((dest / "cloudseed-aws" / skills.MARKER).exists())
        with open(dest / "cloudseed-aws" / "SKILL.md", "a") as fh:
            fh.write("MY EDIT\n")
        second: dict = {}
        skills.install(["aws"], dest, backups=second)
        self.assertNotIn("MY EDIT", (dest / "cloudseed-aws" / "SKILL.md").read_text())
        self.assertTrue(second[str(dest / "cloudseed-aws")])
        with contextlib.redirect_stdout(io.StringIO()):
            undo.perform({"kind": "restore-files", "data": {"files": second}, "scope": "global", "summary": "x"}, {}, True)
        self.assertIn("MY EDIT", (dest / "cloudseed-aws" / "SKILL.md").read_text())
        self.assertIn("put back", undo.describe({"kind": "restore-files", "data": {"files": second}}))
        self.assertIn("delete cloudseed-aws", undo.describe({"kind": "restore-files", "data": {"files": first}}))   # new: removed on undo

    def test_state_detects_stale_and_missing(self):
        with mock.patch.dict(os.environ, {"HOME": str(self.tmp)}):
            self.assertEqual(skills.state("claude"), "missing")
            self.assertFalse(skills.installed("claude"))
            dest = skills.target_dir("claude", None, False)
            skills.install(None, dest)
            self.assertEqual(skills.state("claude"), "current")
            self.assertTrue(skills.installed("claude"))
            with open(dest / "cloudseed" / skills.MARKER, "w") as fh:
                fh.write("old\n")
            self.assertEqual(skills.state("claude"), "stale")
            self.assertFalse(skills.installed("claude"))
            skills.install(None, dest)                      # _ensure_agent_ready's refresh path
            shutil.rmtree(dest / "cloudseed-finops")
            self.assertEqual(skills.state("claude"), "stale")
            self.assertEqual(skills.state("builtin"), "builtin")
            self.assertEqual(skills.target_dir("builtin", None, False), dest)   # builtin installs go to Claude Code
            with mock.patch.object(Path, "cwd", return_value=self.tmp / "proj"):
                self.assertEqual(skills.target_dir("builtin", None, True), self.tmp / "proj" / ".claude" / "skills")

    def test_cli_skill_commands(self):
        home = self.tmp / "home"
        home.mkdir()
        r = _cli(["skill", "show", "aws"], home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("name: cloudseed-aws", r.stdout)
        r = _cli(["skill", "show", "nope"], home)
        self.assertEqual(r.returncode, 2)            # a usage error, like an unknown choice
        self.assertIn("Unknown skill 'nope'", r.stderr)
        self.assertNotIn("Unexpected error", r.stderr)
        r = _cli(["skill", "install", "aws", "destroy", "--dir", str(self.tmp / "d")], home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(os.listdir(self.tmp / "d")), ["cloudseed-aws", "cloudseed-destroy"])
        r = _cli(["install", "skills", "platform", "vmware", "--dir", str(self.tmp / "p")], home)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(sorted(os.listdir(self.tmp / "p")), ["cloudseed-platform", "cloudseed-vmware"])
        self.assertNotIn("terraform", r.stdout.lower())    # the skill, not the vmware tool group
        r = _cli(["install", "skills", "aws", "bogus-tool", "--dir", str(self.tmp / "q")], home)
        self.assertEqual(r.returncode, 1)
        self.assertIn("bogus-tool", r.stderr)
        self.assertFalse((self.tmp / "q").exists())         # nothing installed when a word is unknown
        r = _cli(["skill", "list"], home)
        rows = [line for line in r.stdout.splitlines() if line.startswith("  cloudseed")]
        widths = {len(line) - len(line[2 + len(line.split()[0]):].lstrip()) for line in rows}
        self.assertEqual(len(rows), len(skills.available()))
        self.assertEqual(len(widths), 1, r.stdout)          # descriptions aligned (cloudseed-architecture is 22 chars)


# ------------------------------------------------------------------------------------------------ agents

class AgentRegistryTests(unittest.TestCase):
    def tearDown(self):
        try:
            agents.AGENTS_FILE.unlink()
        except OSError:
            pass
        agents._WARNED.clear()
        agents._CLAUDE_AUTH_CACHE.clear()

    def _write(self, obj):
        agents.AGENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        agents.AGENTS_FILE.write_text(obj if isinstance(obj, str) else json.dumps(obj))

    def test_partial_custom_agent_gets_defaults(self):
        self._write({"myagent": {"display": "My Agent", "binary": "echo", "exec": ["echo", "{prompt}"]}})
        spec = agents.get("myagent")
        for field in ("auth", "install_hint", "auth_env", "auth_files", "models", "skills_dir"):
            self.assertIn(field, spec)
        self.assertTrue(agents.auth_ok(spec))             # nothing to check = ready
        self.assertEqual(agents.readiness(spec), (True, "ready"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIn("myagent", agents.agents_page({}))
        self.assertEqual(skills.state("myagent"), "n/a")
        self.assertTrue(skills.installed("myagent"))

    def test_malformed_files_do_not_crash(self):
        for content in ("[1, 2]", "{bad json", json.dumps({"x": "y"}), json.dumps({"z": {"exec": "notalist", "binary": "echo"}})):
            with self.subTest(content=content):
                self._write(content)
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    reg = agents.registry()
                self.assertIn("claude", reg)
                self.assertNotIn("x", reg)
                self.assertIn("agents.json", err.getvalue())
        spec = agents.get("z")
        self.assertFalse(agents.readiness(spec)[0])
        self.assertIn("exec", agents.readiness(spec)[1])

    def test_builtin_overrides_merge(self):
        self._write({"claude": {"models": ["m1"]}})
        self.assertEqual(agents.get("claude")["models"], ["m1"])
        self.assertEqual(agents.get("claude")["binary"], "claude")

    def test_claude_login_detection(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / ".claude" / "skills" / "x").mkdir(parents=True)          # cloudseed's own skill install
        (tmp / ".claude.json").write_text(json.dumps({"firstStartTime": "x"}))
        spec = agents.get("claude")
        clean = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")}
        clean["HOME"] = str(tmp)
        out = subprocess.CompletedProcess([], 1, json.dumps({"loggedIn": False, "authMethod": "none"}), "")
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(agents, "installed", return_value="/x/claude"), \
                mock.patch.object(agents.subprocess, "run", return_value=out) as run:
            self.assertFalse(agents.auth_ok(spec))
            self.assertEqual(run.call_args[0][0], ["/x/claude", "auth", "status", "--json"])
            ok, msg = agents.readiness(agents.get("builtin"))
            self.assertFalse(ok)
            self.assertNotIn("logged-in Claude Code instead", msg)
        agents._CLAUDE_AUTH_CACHE.clear()
        out = subprocess.CompletedProcess([], 0, json.dumps({"loggedIn": True}), "")
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(agents, "installed", return_value="/x/claude"), \
                mock.patch.object(agents.subprocess, "run", return_value=out):
            self.assertTrue(agents.auth_ok(spec))
        agents._CLAUDE_AUTH_CACHE.clear()
        (tmp / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "a@b"}}))
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(agents, "installed", return_value="/x/claude"), \
                mock.patch.object(agents.subprocess, "run", side_effect=FileNotFoundError):
            self.assertTrue(agents.auth_ok(spec))           # old CLI without `auth status`: account in ~/.claude.json
        with mock.patch.dict(os.environ, dict(clean, CLAUDE_CODE_OAUTH_TOKEN="t"), clear=True):
            self.assertTrue(agents.auth_ok(spec))
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", spec["auth_env"])
        shutil.rmtree(tmp, ignore_errors=True)

    def test_templates_carry_the_prompt(self):
        for key, spec in agents.DEFAULT_AGENTS.items():
            if spec.get("builtin"):
                continue
            for mode in ("exec", "interactive"):
                with self.subTest(agent=key, mode=mode):
                    self.assertIn("TASK", " ".join(agents._fill(spec[mode], "TASK", "m")))

    def test_claude_deny_rules(self):
        rules = agents.claude_deny_rules()
        self.assertIn("Read(/" + str(paths.HOME / "credentials.json") + ")", rules)
        self.assertTrue(all(r.startswith("Read(//") or r.startswith("Read(**") or r.startswith("Read(~") for r in rules))
        for name in ("sessions", "gcp-credentials.json", "undo.json", "managed.json", "mcp", "ui"):
            self.assertTrue(any(str(paths.HOME / name) in r for r in rules), name)
        with mock.patch.object(paths, "HOME", Path("rel-home")):          # CLOUDSEED_HOME=rel-home
            rel = agents.claude_deny_rules()
        self.assertIn("Read(/" + os.path.abspath("rel-home") + "/credentials.json)", rel)
        self.assertFalse(any(r.startswith("Read(/rel-home") for r in rel))
        cmd = agents._with_claude_denies(agents._fill(agents.DEFAULT_AGENTS["claude"]["exec"], "P", "m"))
        i = cmd.index("--disallowedTools")
        self.assertIn("Bash(env:*)", cmd[i + 1])
        self.assertIn(str(paths.HOME / "credentials.json"), cmd[i + 1])
        self.assertEqual(cmd.count("--disallowedTools"), 1)
        icmd = agents._with_claude_denies(agents._fill(agents.DEFAULT_AGENTS["claude"]["interactive"], "P", None))
        self.assertTrue(icmd[1].startswith("--disallowedTools="))   # = form: the variadic flag must not eat the prompt
        self.assertEqual(icmd[-1], "P")

    def test_builtin_interactive_warns(self):
        with mock.patch.object(builtin_agent, "run", return_value=0) as brun, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(agents.run(agents.get("builtin"), "p", None, interactive=True, task="t"), 0)
        self.assertIn("--interactive only applies", err.getvalue())
        brun.assert_called_once()

    @unittest.skipUnless(os.name == "posix", "process groups")
    def test_stop_kills_the_agent_process_group(self):
        proc = subprocess.Popen(["/bin/sh", "-c", "sleep 30 & sleep 30; wait"], start_new_session=True)
        time.sleep(0.3)
        agents._stop(proc, group=True, grace=2)
        self.assertIsNotNone(proc.poll())
        self.assertFalse(agents._group_alive(proc.pid))


# ------------------------------------------------------------------------------------------------ built-in agent

class BuiltinAgentPolicyTests(unittest.TestCase):
    REFUSED = ["-y use codex", "--ye use codex", "--yes enable agentic", "-y mcp token", "setup mcp", "mcp serve",
               "destroy mcp", "ui start", "ui token", "creds set X=y", "ui", "creds clear", "--ru container status aws",
               "--runtime container status aws", "setup aws --runtime container", "setup aws --ssh-priv /x",
               "setup aws --ssh-private-key=/x", "setup aws --ssh-public-key /x", "-y ssh aws -- id", "--yes install all",
               "skill install", "deps install terraform", "k9s", "model x", "agentic x", "do x", "undo aws --env dev --auto",
               "apply aws --env dev --auto", "destroy aws --purge-s", "frobnicate"]
    ALLOWED = ["status aws --env dev", "undo --list", "kubectl get pods", "list -y", "doctor aws", "skill show vmware",
               "skill list", "deps status", "explain agentic", "help agentic", "env", "agents", "--help", "setup aws --help",
               "setup aws --env dev --dry-run", "platform status", "databricks status",
               # read-only forms of human-only commands: the policy every agent session shares (cli.human_only_reason)
               "status mcp", "creds", "creds list", "model", "use list", "install list", "ui status", "mcp guide"]
    # destroy / undo / node add|remove|scale / platform uninstall / dr restore / chaos run --target only preview
    # without --auto-approve (exit 3, nothing changed): their --auto-approve form is what the user approves
    # (see test_wave3_agentic)
    APPROVAL = ["destroy aws --env dev --auto-approve", "apply aws --env dev --auto-approve", "undo --drop",
                "kubectl delete ns x", "kubectl get secret x -o yaml", "kubectl get secrets -A", "kubectl config view --raw",
                "helm get values monitoring", "helm uninstall x", "node add aws --auto-approve",
                "node remove aws n1 --auto-approve", "platform install basek8s", "platform uninstall x --auto-approve",
                "chaos run", "dr restore b1 --auto-approve", "vpn revoke aws bob",
                "databricks clusters list", "snowflake sql -q x", "destroy aws --purge-state", "update-ip aws --auto-approve",
                "helm get hooks x", "vpn connect aws", "vpn disconnect aws"]
    NO_APPROVAL = ["status aws", "undo --list", "kubectl get pods", "kubectl describe secret x", "helm list -A",
                   "helm get notes x", "node list", "platform status", "dr status", "vpn users aws", "vpn status aws", "list",
                   "destroy aws --env dev", "node add aws", "dr restore b1", "platform uninstall x"]

    def test_refused(self):
        for c in self.REFUSED:
            with self.subTest(cmd=c):
                self.assertIsNotNone(builtin_agent.guard(shlex.split(c)))
                self.assertTrue(builtin_agent.is_destructive(shlex.split(c)))

    def test_allowed(self):
        for c in self.ALLOWED:
            with self.subTest(cmd=c):
                self.assertIsNone(builtin_agent.guard(shlex.split(c)))

    def test_approval(self):
        for c in self.APPROVAL:
            with self.subTest(cmd=c):
                self.assertIsNone(builtin_agent.guard(shlex.split(c)))
                self.assertTrue(builtin_agent.is_destructive(shlex.split(c)))
        for c in self.NO_APPROVAL:
            with self.subTest(cmd=c):
                self.assertFalse(builtin_agent.is_destructive(shlex.split(c)))

    def test_yes_goes_first_and_never_into_passthrough_args(self):
        self.assertEqual(builtin_agent._parse(["list", "-y"])[1], ["-y", "list"])
        self.assertEqual(builtin_agent._parse(["kubectl", "get", "pods"])[1], ["-y", "kubectl", "get", "pods"])
        self.assertEqual(builtin_agent._parse(["-y", "status", "aws", "--yes"])[1], ["-y", "status", "aws"])
        self.assertEqual(builtin_agent._parse(["cloudseed", "status", "aws"])[1], ["-y", "status", "aws"])
        self.assertIsNotNone(builtin_agent.guard(["cloudseed", "-y", "use", "codex"]))
        from cloudseed import cli
        for cmd in sorted(builtin_agent._commands() - set(builtin_agent.HUMAN_ONLY) - set(builtin_agent._PASSTHROUGH)):
            argv = {"setup": ["setup", "aws"], "provision": ["provision", "aws"], "k8s": ["k8s", "info", "aws"],
                    "vpn": ["vpn", "status", "aws"], "plan": ["plan", "aws"], "apply": ["apply", "aws"],
                    "destroy": ["destroy", "aws"], "status": ["status", "aws"], "troubleshoot": ["troubleshoot", "aws"],
                    "inventory": ["inventory", "aws"], "output": ["output", "aws"], "update-ip": ["update-ip", "aws"],
                    "deps": ["deps", "status"], "skill": ["skill", "list"], "node": ["node", "list"],
                    "platform": ["platform", "list"], "finops": ["finops", "estimate"], "chaos": ["chaos", "list"],
                    "dr": ["dr", "status"], "scan": ["scan", "reports"]}.get(cmd, [cmd])
            with self.subTest(cmd=cmd):
                ns, final = builtin_agent._parse(argv + ["-y"])
                self.assertEqual(final[0], "-y")
                self.assertEqual(cli.build_parser().parse_args(final).cmd, ns.cmd)

    def test_unattended_switch_is_strict(self):
        for val, want in (("0", False), ("false", False), ("no", False), ("", False), ("1", True), ("true", True)):
            with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE": val}):
                self.assertEqual(builtin_agent._allow_unattended(), want, val)

    def test_system_prompt_skills(self):
        def loaded(task):
            sp = builtin_agent.system_prompt(task)
            return {line[len('<skill name="'):-2] for line in sp.splitlines() if line.startswith("<skill name=")}
        self.assertIn("cloudseed-vmware", loaded("set up 3 local VMs on vmware with kubernetes"))
        self.assertNotIn("cloudseed-aws", loaded("set up 3 local VMs on vmware"))
        self.assertIn("cloudseed-platform", loaded("install the basek8s platform group and kagent"))
        self.assertIn("cloudseed-finops", loaded("why is my bill so high? analyze finops"))
        self.assertIn("cloudseed-managed", loaded("connect databricks"))
        self.assertIn("cloudseed-architecture", loaded("how does cloudseed build the bastion?"))
        self.assertNotIn("cloudseed-architecture", loaded("show my envs"))
        s = loaded("destroy the aws dev env")
        self.assertTrue({"cloudseed", "cloudseed-aws", "cloudseed-destroy"} <= s)
        self.assertNotIn("cloudseed-gcp", s)
        self.assertNotIn("cloudseed-aws", loaded("the laws of gcp billing"))
        sp = builtin_agent.system_prompt("status of aws dev")
        self.assertIn("<skill-index>", sp)
        self.assertIn("cloudseed-vmware:", sp)
        self.assertIn("human-only", sp)


class _FakeAnthropic(types.ModuleType):
    """Stand-in for the SDK: replays scripted tool calls through the real run_cloudseed tool."""

    def __init__(self, calls, results):
        super().__init__("anthropic")
        self.calls, self.results = calls, results
        for n in ("AuthenticationError", "RateLimitError", "APIStatusError", "APIConnectionError"):
            setattr(self, n, type(n, (Exception,), {"status_code": 500}))
        self.beta_tool = lambda fn: fn
        outer = self

        class _Msg:
            def __init__(self):
                self.content, self.stop_reason = [], "end_turn"

        class _Messages:
            def tool_runner(self, **kw):
                for c in outer.calls:
                    outer.results.append((c, kw["tools"][0](c)))
                    yield _Msg()

        class Anthropic:
            def __init__(self):
                self.beta = types.SimpleNamespace(messages=_Messages())

        self.Anthropic = Anthropic


class BuiltinAgentRunTests(unittest.TestCase):
    def tearDown(self):
        secrets.set_strict(False)
        secrets._REGISTERED.clear()

    def _run(self, calls, env):
        results = []
        fake = _FakeAnthropic(calls, results)
        executed = []

        def fake_popen(cmd, **kw):   # run_cloudseed streams the child's output (builtin_agent._run_child)
            executed.append((cmd, kw))
            return types.SimpleNamespace(stdout=io.StringIO("done password=hunter2hunter2 AKIA" + "IOSFODNN7EXAMPLE\n"),
                                         returncode=0, wait=lambda timeout=None: 0, poll=lambda: 0)

        base = {k: v for k, v in os.environ.items() if k != "CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE"}
        base.update(env, ANTHROPIC_API_KEY="sk-ant-" + "test-000000000000000000000")
        with mock.patch.dict(sys.modules, {"anthropic": fake}), mock.patch.dict(os.environ, base, clear=True), \
                mock.patch.object(builtin_agent.subprocess, "Popen", side_effect=fake_popen), \
                mock.patch.object(ui, "interactive", return_value=False), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = builtin_agent.run("prompt", "claude-sonnet-5", "task")
        self.assertEqual(rc, 0)
        return results, executed

    def test_refusals_never_execute_and_output_is_redacted(self):
        results, executed = self._run(["-y use codex", "-y mcp token", "creds set X=y", "status aws --env dev"],
                                      {"CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE": "1"})
        self.assertEqual(len(executed), 1)
        cmd, kw = executed[0]
        self.assertEqual(cmd[-5:], ["-y", "status", "aws", "--env", "dev"])
        self.assertIs(kw["stdin"], subprocess.DEVNULL)
        self.assertEqual(kw["env"]["CLOUDSEED_REDACT"], "1")
        self.assertEqual(kw["env"]["CLOUDSEED_AGENT"], "builtin")
        self.assertNotIn("CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE", kw["env"])
        for call, res in results[:3]:
            self.assertTrue(res.startswith("REFUSED"), call)
        self.assertNotIn("hunter2hunter2", results[3][1])
        self.assertNotIn("AKIA" + "IOSFODNN7EXAMPLE", results[3][1])

    def test_destructive_needs_a_human_unless_explicitly_allowed(self):
        for val in ("0", "false", ""):
            results, executed = self._run(["destroy aws --env dev --auto-approve"], {"CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE": val})
            self.assertEqual(executed, [], val)
            self.assertTrue(results[0][1].startswith("REFUSED: this needs a human"), val)
        results, executed = self._run(["destroy aws --env dev --auto-approve"], {"CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE": "true"})
        self.assertEqual(len(executed), 1)
        self.assertEqual(executed[0][0][-6:], ["-y", "destroy", "aws", "--env", "dev", "--auto-approve"])


# ------------------------------------------------------------------------------------------------ headliner / CLI

class HeadlinerTests(unittest.TestCase):
    def test_cheatsheet_and_features(self):
        from cloudseed import explain
        for word in ("vmware", "undo", "finops", "chaos", "dr ", "scan", "explain", "creds", "k8s", "platform", "node"):
            self.assertIn(word, headliner.CHEATSHEET)
        brief = headliner.build("do something", {})
        for feature in explain.FEATURES:
            self.assertIn(feature, brief)
        self.assertIn("-y BEFORE the command", brief)

    def test_corrupt_environment_does_not_break_the_brief(self):
        env = paths.Env("aws", "brokenbrief")
        env.dir.mkdir(parents=True, exist_ok=True)
        (env.dir / "config.json").write_text("{not json")
        try:
            self.assertIn("unreadable", headliner.build("x", {}))
        finally:
            shutil.rmtree(env.dir, ignore_errors=True)


class AgentSessionOutputTests(unittest.TestCase):
    def test_cli_output_is_redacted_in_agent_sessions(self):
        home = Path(tempfile.mkdtemp(prefix="cs-redact-"))
        try:
            (home / "mcp").mkdir()
            tok = "ab" * 32
            (home / "mcp" / "token").write_text(tok + "\n")
            r = _cli(["mcp", "token"], home)
            self.assertIn(tok, r.stdout)                         # the human sees it
            r = _cli(["mcp", "token"], home, {"CLOUDSEED_REDACT": "1"})
            self.assertNotIn(tok, r.stdout + r.stderr)           # an agent does not
            _cli(["creds", "set", "AWS_ACCESS_KEY_ID=AKIA" + "IOSFODNN7EXAMPLE"], home)
            r = _cli(["creds"], home, {"CLOUDSEED_REDACT": "1"})
            self.assertNotIn("AKIA" + "IOSFODNN7EXAMPLE", r.stdout)
        finally:
            shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
