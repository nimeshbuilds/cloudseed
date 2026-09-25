"""Regression tests for the wave-3 ops items: the audit trail (Authorization headers never persisted, one log file per
run), troubleshoot (which failure is diagnosed, which later run settles it, path hints, apt/dnf egress signatures, a
notes-only inventory, an unreadable local state), reconcile (Security Hub stops before apply, singletons an
environment's own destroy left on are adopted again, FIPS endpoints for lookups, the switch-off signal), finops (the
OpenCost port-forward and its errors, the paid opt-in features in the estimate), deps (aws CLI failures without
output, download errors, Python 3.10+ for the pip-installed CLIs, Homebrew never unattended), the container engine and
the Makefile. Stdlib only, no network, no cloud."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, clouds, container, deps, finops, paths, reconcile, secrets, troubleshoot, ui  # noqa: E402
from cloudseed.tf import TerraformError  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
TOKEN = "abcdefghijklmnopqrstuvwxyz0123456789"


def _quiet():
    buf = io.StringIO()
    stack = contextlib.ExitStack()
    stack.enter_context(contextlib.redirect_stdout(buf))
    stack.enter_context(contextlib.redirect_stderr(buf))
    return stack, buf


# ---------------------------------------------------------------------------------------------------- audit

class AuditAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self._strict = dict(secrets._STRICT)
        secrets._STRICT["on"] = False
        self._env = mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": ""})
        self._env.start()

    def tearDown(self):
        secrets._STRICT.update(self._strict)
        self._env.stop()

    def test_argv_never_keeps_an_authorization_header(self):
        cases = [
            ["ssh", "aws", "--env", "t1", "--", "curl", "-sH", f"Authorization: Bearer {TOKEN}", "https://api"],
            ["helm", "upgrade", "x", "c", "--set", f"grafana.datasource.headers.Authorization=Basic {TOKEN}"],
            ["kubectl", "exec", "p", "--", "curl", f"-HAuthorization: Bearer {TOKEN}", "http://svc"],
            ["ssh", "aws", "--", "curl", f"--header=Authorization: Token {TOKEN}"],
            ["ssh", "aws", "--", "curl", "-H", f"Proxy-Authorization: Basic {TOKEN}"],
            ["ssh", "aws", "--", "curl", "-H", f"Authorization: apikey-{TOKEN}"],          # no scheme: an API key
        ]
        self.assertFalse(secrets.strict())
        for argv in cases:
            out = " ".join(audit.safe_argv(argv))
            self.assertNotIn(TOKEN, out, argv)
            self.assertIn(secrets.REDACTED, out)

    def test_log_body_and_inventory_are_scrubbed_too(self):
        self.assertNotIn(TOKEN, audit._KeyFilter().feed(f"> Authorization: Bearer {TOKEN}\n< HTTP/1.1 200\n"))
        self.assertNotIn(TOKEN, json.dumps(audit.secrets_free({"notes": {"cmd": f"curl -H 'Authorization: Basic {TOKEN}'"}})))

    def test_ordinary_words_after_authorization_stay(self):
        for text in ("Authorization: failed for user bob", "authorization=required", "Authorization: Bearer [REDACTED]",
                     "Authorization: AWS4-HMAC-SHA256 Credential=x"):
            self.assertEqual(audit.scrub_auth(text), text)

    def test_terminal_redaction_is_unchanged(self):
        # the console and the terminal still show users their own MCP config (only files on disk are scrubbed)
        self.assertIn(TOKEN, secrets.redact(f"Authorization: Bearer {TOKEN}"))

    def test_end_to_end_the_audit_line_and_log_hold_no_token(self):
        env = paths.Env("aws", "w3auth")
        env.create_dirs()
        audit.begin(["ssh", "aws", "--env", "w3auth", "--", "curl", "-H", f"Authorization: Bearer {TOKEN}", "https://x"])
        audit.attach(env)
        audit.write(f"> Authorization: Bearer {TOKEN}")
        audit.end(0)
        rec = audit.read_audit(env)[-1]
        self.assertNotIn(TOKEN, json.dumps(rec))
        self.assertNotIn(TOKEN, Path(rec["log"]).read_text())
        self.assertNotIn(TOKEN, (paths.HOME / "logs" / "audit.jsonl").read_text())


class AuditLogFileTests(unittest.TestCase):
    def _run(self, env, cmd):
        audit.begin([cmd, "aws", "--env", env.name])
        audit.attach(env)
        audit.write(f"output of run {cmd}")
        path = audit._state["logpath"]
        audit.end(0)
        return Path(path)

    def test_runs_in_the_same_second_get_their_own_file(self):
        env = paths.Env("aws", "w3logs")
        env.create_dirs()
        for old in (env.dir / "logs").glob("20260101-000000-*"):     # a previous run of this test
            old.unlink()
        with mock.patch.object(audit, "_ts", return_value="20260101-000000"):
            a, b, c = (self._run(env, "status") for _ in range(3))
        self.assertEqual(a.name, "20260101-000000-status.log")      # the documented name stays the usual one
        self.assertEqual(len({a, b, c}), 3)
        for p in (a, b, c):
            text = p.read_text()
            self.assertEqual(text.count("# cloudseed status"), 1, p)
            self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")
            self.assertRegex(p.name, r"^\d{8}-\d{6}-.*\.log$")      # destroy --purge still knows it is cloudseed's
        logs = [r["log"] for r in audit.read_audit(env, 3)]
        self.assertEqual(sorted(logs), sorted(str(p) for p in (a, b, c)))

    def test_crash_logs_in_the_same_second_are_separate(self):
        made = []
        with mock.patch.object(audit, "_ts", return_value="20260101-000001"):
            for i in range(2):
                audit.begin(["w3crash"])
                made.append(audit.record_crash(f"Traceback {i}\n"))
                audit.end(1)
        self.assertEqual(len(set(made)), 2)
        for p in made:
            self.assertTrue(p.name.endswith("-crash.log"), p.name)
            self.assertEqual(p.read_text().count("Traceback"), 1)

    def test_shared_mutating_sets(self):
        self.assertIn("setup", audit.MUTATING)
        self.assertEqual(audit.SUB_MUTATING["platform"], ("install", "uninstall", "ui"))
        self.assertIn("scale", audit.SUB_MUTATING["node"])


# ---------------------------------------------------------------------------------------------------- troubleshoot

def _rec(argv, rc, log=None, **extra):
    return {"argv": argv, "command": argv[0], "exit_code": rc, "log": log, "at": "2026-01-01T00:00:00Z", **extra}


class SupersedeTests(unittest.TestCase):
    def ok(self, argv, fail, **extra):
        return troubleshoot._supersedes(_rec(argv, 0, **extra), fail)

    def test_a_partial_destroy_never_settles_a_full_one(self):
        full = _rec(["destroy", "aws", "--env", "dev"], 1)
        for argv in (["destroy", "aws", "--env", "dev", "--target", "module.stack.module.bastion", "-y", "--auto-approve"],
                     ["destroy", "aws", "--env", "dev", "--target=module.stack.module.bastion"],
                     ["destroy", "aws", "--env", "dev", "--select"],
                     ["destroy", "aws", "--env", "dev", "--targ", "module.stack.module.bastion"],
                     ["destroy", "aws", "--env", "dev", "--sel"]):
            self.assertFalse(self.ok(argv, full), argv)
        self.assertTrue(self.ok(["destroy", "aws", "--env", "dev", "-y"], full))

    def test_targeted_destroys_settle_only_what_they_cover(self):
        fail_a = _rec(["destroy", "aws", "--env", "dev", "--target", "module.stack.module.a"], 1)
        self.assertFalse(self.ok(["destroy", "aws", "--env", "dev", "--target", "module.stack.module.b"], fail_a))
        self.assertTrue(self.ok(["destroy", "aws", "--env", "dev", "--target", "module.stack.module.a,module.stack.module.b"], fail_a))
        self.assertTrue(self.ok(["destroy", "aws", "--env", "dev", "--target", "module.stack"], fail_a))   # a parent module
        self.assertTrue(self.ok(["destroy", "aws", "--env", "dev"], fail_a))                               # a full destroy

    def test_a_partial_destroy_settles_nothing_else(self):
        for fail in (_rec(["apply", "aws", "--env", "dev"], 1), _rec(["platform", "install", "velero", "--env", "dev"], 1)):
            self.assertFalse(self.ok(["destroy", "aws", "--env", "dev", "--select"], fail))
            self.assertFalse(self.ok(["destroy", "aws", "--env", "dev", "--target", "x"], fail))

    def test_the_destroy_command_tag_is_authoritative(self):
        full = _rec(["destroy", "aws", "--env", "dev"], 1)
        self.assertFalse(self.ok(["destroy", "aws", "--env", "dev", "--select"], full, destroy_scope=["module.x"]))
        self.assertTrue(self.ok(["destroy", "aws", "--env", "dev", "--select"], full, destroy_scope="all"))

    def test_undo_list_settles_nothing(self):
        fail = _rec(["undo", "aws", "--env", "dev"], 1)
        self.assertFalse(self.ok(["undo", "--list"], fail))
        self.assertFalse(self.ok(["undo", "aws", "--env", "dev", "--drop", "2"], fail))
        self.assertFalse(self.ok(["undo", "aws", "--env", "dev", "--li"], fail))       # argparse abbreviations
        self.assertFalse(self.ok(["undo", "aws", "--env", "dev", "--dr=2"], fail))
        self.assertTrue(self.ok(["undo", "aws", "--env", "dev"], fail))


class FailureChoiceTests(unittest.TestCase):
    DIAG = {"troubleshoot", "inventory", "status", "output", "doctor", "help", "list", "explain"}

    def test_a_failed_change_wins_over_newer_read_only_failures(self):
        runs = [_rec(["setup", "aws", "--env", "t1"], 1), _rec(["finops", "k8s", "aws", "--env", "t1"], 1),
                _rec(["kubectl", "aws", "--env", "t1", "-n", "kube-system", "get", "pods"], 1),
                _rec(["ssh", "aws", "--env", "t1", "--", "true"], 1)]
        chosen, settled, newer = troubleshoot._pick_failure(runs, self.DIAG)
        self.assertIs(chosen, runs[0])
        self.assertIsNone(settled)
        self.assertEqual(newer, runs[1:])

    def test_checks_failing_by_design_do_not_hide_a_failed_change(self):
        # scan exits 1 on a FAIL verdict, chaos run when the app does not recover, dr test when the drill fails
        runs = [_rec(["apply", "aws", "--env", "t1"], 1), _rec(["scan", "cis", "aws", "--env", "t1"], 1),
                _rec(["chaos", "run", "pod-kill", "--env", "t1"], 1), _rec(["dr", "test", "--env", "t1"], 1)]
        chosen, _, newer = troubleshoot._pick_failure(runs, self.DIAG)
        self.assertIs(chosen, runs[0])
        self.assertEqual(newer, runs[1:])
        self.assertIs(troubleshoot._pick_failure(runs[1:2], self.DIAG)[0], runs[1])      # alone: still diagnosed
        self.assertTrue(troubleshoot._is_operation(_rec(["node", "scale", "aws", "--env", "t1", "--count", "3"], 1)))
        self.assertTrue(troubleshoot._is_operation(_rec(["dr", "restore", "b1", "--env", "t1"], 1)))

    def test_a_read_only_failure_alone_is_still_diagnosed(self):
        runs = [_rec(["setup", "aws", "--env", "t1"], 0), _rec(["ssh", "aws", "--env", "t1", "--", "true"], 1)]
        self.assertIs(troubleshoot._pick_failure(runs, self.DIAG)[0], runs[1])

    def test_mutating_kubectl_and_helm_are_changes(self):
        op = troubleshoot._is_operation
        self.assertTrue(op(_rec(["kubectl", "aws", "--env", "t1", "-n", "shop", "delete", "pod", "x"], 1)))
        self.assertFalse(op(_rec(["kubectl", "aws", "--env", "t1", "-n", "delete", "get", "pods"], 1)))   # -n's value
        self.assertTrue(op(_rec(["helm", "upgrade", "x", "chart", "--set", "a=b"], 1)))
        self.assertFalse(op(_rec(["helm", "list", "-A"], 1)))
        self.assertTrue(op(_rec(["platform", "install", "velero", "--env", "t1"], 1)))
        self.assertFalse(op(_rec(["platform", "list"], 1)))
        self.assertFalse(op(_rec(["undo", "--list"], 1)))
        self.assertFalse(op(_rec(["finops", "cloud", "aws", "--env", "t1"], 1)))

    def test_settled_failure_is_history(self):
        runs = [_rec(["setup", "aws", "--env", "t1"], 1), _rec(["setup", "aws", "--env", "t1"], 0)]
        chosen, settled, _ = troubleshoot._pick_failure(runs, self.DIAG)
        self.assertIsNone(chosen)
        self.assertEqual(settled, (runs[0], runs[1]))

    def test_an_older_open_change_is_not_hidden_by_a_newer_settled_one(self):
        runs = [_rec(["platform", "install", "velero", "--env", "t1"], 1), _rec(["setup", "aws", "--env", "t1"], 1),
                _rec(["setup", "aws", "--env", "t1"], 0)]
        self.assertIs(troubleshoot._pick_failure(runs, self.DIAG)[0], runs[0])


class TroubleshootRunTests(unittest.TestCase):
    def _run(self, env_name, runs=None, inventory=None, state=None, backup=None, logs=None):
        env = paths.Env("aws", env_name)
        env.create_dirs()
        cfg = {"cloud": "aws", "env": env_name, "name": "lab", "vars": {}, "workdir": str(env.dir)}
        env.save(cfg)
        for name, text in (logs or {}).items():
            (env.dir / "logs" / name).write_text(text)
        if runs is not None:
            (env.dir / "logs" / "audit.jsonl").write_text("".join(json.dumps(r) + "\n" for r in runs))
        if inventory is not None:
            (env.dir / "inventory.json").write_text(json.dumps(inventory))
        for name, text in (("terraform.tfstate", state), ("terraform.tfstate.backup", backup)):
            if text is not None:
                (env.stack_dir / name).write_text(text)
        stack, buf = _quiet()
        with stack, mock.patch.object(troubleshoot.deps, "missing", return_value=([], [])), \
                mock.patch.object(troubleshoot.deps, "live_credential_check", return_value=None), \
                mock.patch.object(troubleshoot.netutil, "detect_public_ip", return_value=None):
            troubleshoot.run(clouds.get("aws"), env, env.load())
        return env, " ".join(buf.getvalue().split())

    def test_the_setup_failure_survives_failing_read_only_runs(self):
        env = paths.Env("aws", "w3ts1")
        setup_log = str(env.dir / "logs" / "20260101-000000-setup.log")
        ssh_log = str(env.dir / "logs" / "20260101-000003-ssh.log")
        runs = [_rec(["setup", "aws", "--env", "w3ts1"], 1, setup_log),
                _rec(["finops", "k8s", "aws", "--env", "w3ts1"], 1),
                _rec(["kubectl", "aws", "--env", "w3ts1", "get", "pods"], 1),
                _rec(["ssh", "aws", "--env", "w3ts1", "--", "true"], 1, ssh_log)]
        _, out = self._run("w3ts1", runs, logs={
            "20260101-000000-setup.log": "Error: creating EC2 Instance: VcpuLimitExceeded: You have requested more vCPU capacity\n",
            "20260101-000003-ssh.log": "exit 1\n"})
        self.assertIn("quota", out)
        self.assertIn("20260101-000000-setup.log", out)
        self.assertIn("Read-only runs or checks after that failure also failed", out)
        self.assertNotIn("has no recognised error signature", out)

    def test_notes_alone_are_not_an_applied_environment(self):
        inv = {"current": {"notes": {"finops-report": {"at": "2026-01-01T00:00:00Z"}}}, "history": [{"action": "finops-report"}]}
        _, out = self._run("w3ts2", [], inventory=inv)
        self.assertIn("Nothing has been applied yet", out)
        _, out = self._run("w3ts3", [], inventory={"current": {"updated_at": "2026-01-01T00:00:00Z", "count": 0}})
        self.assertNotIn("Nothing has been applied yet", out)

    def test_an_unreadable_local_state_is_a_finding(self):
        _, out = self._run("w3ts4", [], state='{"version": 4, "resources": [', backup='{"version": 4, "resources": []}')
        self.assertIn("The Terraform state file is unreadable", out)
        self.assertIn("terraform.tfstate.backup", out)
        _, out = self._run("w3ts5", [], state='{"version": 4}')
        self.assertNotIn("unreadable", out)
        _, out = self._run("w3ts6", [], state="")
        self.assertNotIn("unreadable", out)


class TroubleshootHintTests(unittest.TestCase):
    def _scan(self, text, cloud="aws", **kw):
        log = Path(tempfile.mkdtemp()) / "x.log"
        log.write_text(text)
        return troubleshoot._scan_log(log, cloud, "t3", **kw)

    def test_paths_are_the_working_directory(self):
        wd = Path(tempfile.mkdtemp()) / "envs" / "aws-t3"
        lock = self._scan("Error: Error acquiring the state lock\n\nLock Info:\n  ID: 123\n", workdir=wd)
        fixes = " ".join(f.fix for f in lock)
        self.assertIn(f"-chdir={wd}/stack force-unlock", fixes)
        self.assertNotIn("-chdir=t3/", fixes)
        token = self._scan("level=fatal msg=\"must be in format K10<CA-HASH>::<USERNAME>:<PASSWORD>\"\n", "vmware", workdir=wd)
        self.assertTrue(any(f"delete {wd}/k8s/token" in f.fix for f in token))
        for f in lock + token:
            self.assertNotIn("<workdir>", f.fix + f.what)
            self.assertNotIn("<env>", f.fix + f.what)

    def test_without_a_working_directory_the_placeholder_stays(self):
        lock = self._scan("Error: Error acquiring the state lock\n")
        self.assertTrue(any("-chdir=<workdir>/stack" in f.fix for f in lock))

    def test_checksum_mismatch_no_longer_blames_the_platform(self):
        wd = Path("/w/envs/aws-t3")
        hits = self._scan("Error: Required plugins are not installed\n\nthe cached package for registry.terraform.io/hashicorp/"
                          "tls 4.4.1 (in .terraform/providers) does not match any of the checksums recorded in the "
                          "dependency lock file\n", workdir=wd)
        what = " ".join(f.what for f in hits)
        self.assertNotIn("another platform.", what.replace("another OS/CPU", ""))
        self.assertIn("plugin cache changed", what)
        self.assertTrue(any("/w/envs/aws-t3/stack or /w/envs/aws-t3/bootstrap" in f.fix for f in hits))

    def test_apt_and_dnf_network_failures_are_egress(self):
        egress = "no working internet egress"
        for text in (
                "W: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/jammy/InRelease  Temporary failure resolving 'archive.ubuntu.com'\n",
                'fatal: [localhost]: FAILED! => {"changed": false, "msg": "Failed to update apt cache: W:Failed to fetch '
                "http://archive.ubuntu.com/ubuntu/dists/jammy/InRelease  Temporary failure resolving 'archive.ubuntu.com'\"}\n",
                "E: Failed to fetch http://deb.debian.org/x.deb  Could not connect to deb.debian.org:80 (1.2.3.4), connection timed out\n",
                "Error: Failed to download metadata for repo 'baseos': Curl error (6): Couldn't resolve host name\n"):
            self.assertTrue(any(egress in f.what for f in self._scan(text)), text)
        for text in (
                "E: Failed to fetch https://packages.cloud.google.com/apt/dists/x/InRelease  404  Not Found [IP: 1.2.3.4 443]\n",
                "E: Failed to fetch http://archive.ubuntu.com/x.deb  Hash Sum mismatch\n",
                'fatal: [localhost]: FAILED! => {"msg": "Failed to update apt cache: W:GPG error: https://x NO_PUBKEY ABC"}\n'):
            self.assertFalse(any(egress in f.what for f in self._scan(text)), text)


# ---------------------------------------------------------------------------------------------------- reconcile

class _TF:
    def __init__(self, state=()):
        self.state, self.calls = list(state), []

    def state_list(self):
        return self.state

    def run(self, *args, **kw):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")


HUB = "module.stack.module.security_baseline[0].aws_securityhub_account.this[0]"
GD = "module.stack.module.security_baseline[0].aws_guardduty_detector.this[0]"
DEF_VM = 'module.stack.module.security_baseline.azurerm_security_center_subscription_pricing.this["VirtualMachines"]'
DEF_ST = 'module.stack.module.security_baseline.azurerm_security_center_subscription_pricing.this["StorageAccounts"]'
SUB = "00000000-0000-0000-0000-000000000001"


class SecurityHubTests(unittest.TestCase):
    CFG = {"cloud": "aws", "env": "dev", "name": "acme", "owner": "alice", "region": "us-east-1", "vars": {}}
    PLANNED = {HUB: {"type": "aws_securityhub_account", "values": {}}}

    def test_an_existing_hub_stops_before_anything_changes(self):
        tf = _TF()
        arn = "arn:aws:securityhub:us-east-1:123456789012:hub/default"
        with mock.patch.object(reconcile.CloudLookups, "_awscli", lambda self, *a: {"HubArn": arn} if a[:2] == ("securityhub", "describe-hub") else None):
            with self.assertRaises(TerraformError) as cm:
                reconcile.preflight(tf, "aws", self.CFG, self.PLANNED)
        self.assertIn("--var enable_security_hub=false", str(cm.exception))
        self.assertIn(f"(existing: {arn}). Nothing was applied.", str(cm.exception))
        self.assertIn("Nothing was applied", str(cm.exception))
        self.assertEqual(tf.calls, [])
        # not subscribed (describe-hub fails) or already this environment's: nothing to stop for
        with mock.patch.object(reconcile.CloudLookups, "_awscli", lambda self, *a: None):
            self.assertEqual(reconcile.preflight(_TF(), "aws", self.CFG, self.PLANNED), [])
        self.assertEqual(reconcile.preflight(_TF(state=[HUB]), "aws", self.CFG, self.PLANNED), [])

    def test_the_conflict_text_is_recognised_and_never_adopted(self):
        out = ("Error: creating Security Hub CSPM Account: operation error SecurityHub: EnableSecurityHub, https response "
               "error StatusCode: 409, RequestID: x, ResourceConflictException: Account is already subscribed to Security "
               f"Hub\n\n  with {HUB},\n  on main.tf line 331\n")
        self.assertEqual(reconcile.conflicts(out), [HUB])
        tf = _TF()
        stack, buf = _quiet()
        with stack:
            self.assertEqual(reconcile.recover(tf, "aws", self.CFG, out, self.PLANNED), [])
        self.assertEqual(tf.calls, [])
        self.assertIn("enable_security_hub=false", buf.getvalue())
        self.assertIsNone(reconcile.CONFLICT_RE.search("ResourceConflictException: update in progress"))


class SingletonSignalTests(unittest.TestCase):
    CFG = {"cloud": "aws", "env": "dev", "name": "acme", "owner": "alice", "region": "us-east-1", "vars": {}}
    PLANNED = {GD: {"type": "aws_guardduty_detector", "values": {}}, HUB: {"type": "aws_securityhub_account", "values": {}}}

    def _preflight(self, cfg):
        def awscli(self, *a):
            if a[:2] == ("guardduty", "list-detectors"):
                return {"DetectorIds": ["b2c3d4"]}
            if a[:2] == ("securityhub", "describe-hub"):
                return {"HubArn": "arn:hub"}
            if a[:2] == ("guardduty", "get-detector"):
                return {"Tags": {"CloudseedEnv": "aws-prod", "Owner": "bob"}}
            return None
        with mock.patch.object(reconcile.CloudLookups, "_awscli", awscli):
            with self.assertRaises(reconcile.SingletonExists) as cm:
                reconcile.preflight(_TF(), "aws", cfg, self.PLANNED)
            e = cm.exception
            lines = e.switch_off(cfg) if e.auto else []
        return e, lines

    def test_every_existing_singleton_is_named_once(self):
        cfg = json.loads(json.dumps(self.CFG))
        cfg["vars"]["enable_security_hub"] = True            # asked for explicitly: not switched off silently
        e, _ = self._preflight(cfg)
        self.assertIsInstance(e, TerraformError)              # callers that do not know the signal stop as before
        self.assertIn("--var enable_guardduty=false --var enable_security_hub=false", str(e))
        self.assertEqual(e.disable, {"enable_guardduty": False, "enable_security_hub": False})
        self.assertFalse(e.auto)

    def test_a_default_on_singleton_can_be_switched_off(self):
        cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in self.CFG.items()}
        planned = {GD: self.PLANNED[GD]}
        with mock.patch.object(reconcile.CloudLookups, "_awscli", lambda self, *a: {"DetectorIds": ["b2c3d4"]}
                               if a[:2] == ("guardduty", "list-detectors") else {"Tags": {"CloudseedEnv": "aws-prod", "Owner": "bob"}}):
            with self.assertRaises(reconcile.SingletonExists) as cm:
                reconcile.preflight(_TF(), "aws", cfg, planned)
            self.assertTrue(cm.exception.auto)
            lines = cm.exception.switch_off(cfg)
        self.assertEqual(cfg["extra_vars"], {"enable_guardduty": False})
        self.assertEqual(len(lines), 1)
        self.assertIn("b2c3d4", lines[0])
        self.assertIn("cloudseedenv=aws-prod", lines[0])          # who owns it, from its tags
        self.assertIn("enable_guardduty=false saved", lines[0])

    def test_guardduty_owner_tags_are_readable(self):
        c = reconcile.CloudLookups("aws", self.CFG)
        with mock.patch.object(reconcile.CloudLookups, "_awscli", lambda self, *a: {"Tags": {"Owner": "bob"}} if a[1] == "get-detector" else None):
            self.assertEqual(c.tags("aws_guardduty_detector", {}, "b2c3d4"), {"Owner": "bob"})


class KeptSingletonTests(unittest.TestCase):
    CFG = {"cloud": "azure", "env": "d1", "name": "acme", "vars": {"subscription_id": SUB}}

    def _cfg(self):
        return json.loads(json.dumps(self.CFG))

    def test_destroy_records_what_it_leaves_on(self):
        cfg = self._cfg()
        self.assertTrue(reconcile.remember_kept(cfg, [DEF_VM, DEF_ST, "module.stack.azurerm_marketplace_agreement.x[0]"]))
        self.assertEqual(cfg["kept_shared"], {
            DEF_VM: f"/subscriptions/{SUB}/providers/Microsoft.Security/pricings/VirtualMachines",
            DEF_ST: f"/subscriptions/{SUB}/providers/Microsoft.Security/pricings/StorageAccounts"})
        self.assertFalse(reconcile.remember_kept(cfg, [DEF_VM]))       # nothing new

    def test_re_creating_the_environment_adopts_them_again(self):
        cfg = self._cfg()
        reconcile.remember_kept(cfg, [DEF_VM])
        planned = {DEF_VM: {"type": "azurerm_security_center_subscription_pricing", "values": {"resource_type": "VirtualMachines"}}}
        pricing = {"pricingTier": "Standard", "id": f"/subscriptions/{SUB}/providers/Microsoft.Security/pricings/VirtualMachines"}
        tf = _TF()
        stack, _ = _quiet()
        with stack, mock.patch.object(reconcile.CloudLookups, "_az", lambda self, *a: pricing):
            self.assertEqual(reconcile.preflight(tf, "azure", cfg, planned), [DEF_VM])
        self.assertEqual(tf.calls, [("import", "-input=false", DEF_VM, pricing["id"])])
        # without the record it is someone else's, and the run stops
        with mock.patch.object(reconcile.CloudLookups, "_az", lambda self, *a: pricing):
            with self.assertRaises(TerraformError) as cm:
                reconcile.preflight(_TF(), "azure", self._cfg(), planned)
        self.assertIn("enable_defender=false", str(cm.exception))

    def test_recover_adopts_a_kept_object_without_the_cli(self):
        cfg = self._cfg()
        reconcile.remember_kept(cfg, [DEF_VM])
        planned = {DEF_VM: {"type": "azurerm_security_center_subscription_pricing", "values": {"resource_type": "VirtualMachines"}}}
        out = (f'Error: A resource with the ID "/subscriptions/{SUB}/providers/Microsoft.Security/pricings/VirtualMachines" '
               f"already exists - to be managed via Terraform this resource needs to be imported into the State.\n\n  with {DEF_VM},\n")
        tf = _TF()
        stack, _ = _quiet()
        with stack:
            self.assertEqual(reconcile.recover(tf, "azure", cfg, out, planned), [DEF_VM])
        self.assertEqual(tf.calls[0][2], DEF_VM)

    def test_settle_forgets_what_no_longer_matters(self):
        cfg = self._cfg()
        reconcile.remember_kept(cfg, [DEF_VM, DEF_ST])
        self.assertTrue(reconcile.settle_kept(cfg, [DEF_VM]))
        self.assertEqual(list(cfg["kept_shared"]), [DEF_ST])
        cfg["extra_vars"] = {"enable_defender": False}
        self.assertTrue(reconcile.settle_kept(cfg, []))
        self.assertNotIn("kept_shared", cfg)
        self.assertFalse(reconcile.settle_kept(cfg, []))


class LookupEnvTests(unittest.TestCase):
    def test_fips_lookups_use_fips_endpoints(self):
        for cfg in ({"vars": {"fips_mode": True}}, {"vars": {}, "extra_vars": {"fips_mode": "true"}}):
            self.assertEqual(reconcile.CloudLookups("aws", cfg)._cli_env().get("AWS_USE_FIPS_ENDPOINT"), "true", cfg)
        self.assertNotIn("AWS_USE_FIPS_ENDPOINT", reconcile.CloudLookups("aws", {"vars": {}})._cli_env())
        seen = {}
        c = reconcile.CloudLookups("aws", {"vars": {"fips_mode": True}})
        with mock.patch.object(reconcile.subprocess, "run", side_effect=lambda cmd, **k: seen.update(k["env"]) or
                               subprocess.CompletedProcess(cmd, 0, "{}", "")):
            c._run_json(["aws", "sts", "get-caller-identity"])
        self.assertEqual(seen.get("AWS_USE_FIPS_ENDPOINT"), "true")


# ---------------------------------------------------------------------------------------------------- finops

FAKE_KUBECTL = r'''#!PYTHON
import json, os, sys, urllib.parse
from socketserver import TCPServer
from http.server import BaseHTTPRequestHandler, HTTPServer
mode = os.environ.get("FAKE_MODE", "ok")
args = sys.argv[1:]
if "get" in args:
    if mode == "missing":
        sys.stderr.write('Error from server (NotFound): services "opencost" not found\n'); sys.exit(1)
    if mode == "noauth":
        sys.stderr.write("Unable to connect to the server: getting credentials: exec: executable aws not found\n"); sys.exit(1)
    print("opencost   ClusterIP   10.0.0.1   <none>   9003/TCP"); sys.exit(0)
if "port-forward" not in args or args[-1] != ":9003":
    sys.stderr.write("unexpected: %r\n" % (args,)); sys.exit(2)
if mode == "pffail":
    sys.stderr.write("error: unable to forward port because pod is not running. Current status=Pending\n"); sys.exit(1)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        with open(os.environ["FAKE_LOG"], "a") as fh:
            fh.write(json.dumps(q) + "\n")
        if q.get("window") == ["bad window"]:
            body, code = {"code": 400, "message": "error parsing window (bad window)"}, 400
        else:
            body, code = {"code": 200, "data": [{os.environ.get("FAKE_CLUSTER", "c") + "-ns1": {"cpuCost": 1.0, "ramCost": 2.0,
                         "pvCost": 0.0, "totalCost": 3.0, "totalEfficiency": 0.5}}]}, 200
        data = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

# Match kubectl: the forwarding fixture must not wait for host reverse DNS.
class LocalServer(HTTPServer):
    def server_bind(self):
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

srv = LocalServer(("127.0.0.1", 0), H)
print("Forwarding from 127.0.0.1:%d -> 9003" % srv.server_address[1], flush=True)
srv.serve_forever()
'''


class OpenCostTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.kubectl = self.dir / "kubectl"
        self.kubectl.write_text(FAKE_KUBECTL.replace("#!PYTHON", "#!" + sys.executable))
        self.kubectl.chmod(0o755)
        self.log = self.dir / "requests.log"
        self.log.write_text("")

    def _run(self, mode="ok", window="7d", by="namespace", cluster="clusterA"):
        env = dict(os.environ, FAKE_MODE=mode, FAKE_LOG=str(self.log), FAKE_CLUSTER=cluster)
        ctx = SimpleNamespace(procenv=lambda: env)
        with mock.patch.object(finops.deps, "find", return_value=str(self.kubectl)):
            return finops.opencost(ctx, window, by)

    def test_rows_come_from_the_forward_kubectl_reports(self):
        # the fake kubectl only forwards `:9003` (a local port of its choosing, here a free one) and answers from its
        # own cluster: nothing else listening anywhere can be asked instead
        got = self._run(cluster="clusterB")
        self.assertEqual(list(got["rows"]), ["clusterB-ns1"], got)
        self.assertEqual(got["total"], 3.0)
        self.assertEqual(json.loads(self.log.read_text().splitlines()[0])["aggregate"], ["namespace"])

    def test_query_values_are_encoded_and_a_rejection_is_reported_at_once(self):
        start = time.monotonic()
        got = self._run(window="bad window", by="label:team,app")
        self.assertLess(time.monotonic() - start, 8)
        self.assertIn("OpenCost rejected the query (HTTP 400)", got["error"])
        self.assertIn("error parsing window", got["error"])
        self.assertIn("--window", got["error"])
        asked = [json.loads(x) for x in self.log.read_text().splitlines()]
        self.assertEqual(len(asked), 1)                                  # no retries for a 4xx
        self.assertEqual(asked[0]["aggregate"], ["label:team,app"])

    def test_a_failed_port_forward_shows_kubectl_error(self):
        got = self._run(mode="pffail")
        self.assertIn("port-forward", got["error"])
        self.assertIn("pod is not running", got["error"])

    def test_missing_service_means_not_installed(self):
        self.assertEqual(self._run(mode="missing")["error"], "OpenCost is not installed: cs platform install finops")
        got = self._run(mode="noauth")["error"]           # the kubeconfig's exec plugin is missing, not OpenCost
        self.assertNotIn("not installed", got)
        self.assertIn("executable aws not found", got)


class EstimateTests(unittest.TestCase):
    def _est(self, cloud, name, cfg):
        e = paths.Env(cloud, name)
        e.create_dirs()
        return finops.estimate(clouds.get(cloud), e, cfg)

    def names(self, est):
        return [n for n, _ in est["lines"]]

    def test_cloudtrail_follows_its_own_switch(self):
        est = self._est("aws", "w3e1", {"vars": {}, "extra_vars": {"enable_cloudtrail": False}})
        self.assertFalse(any(n.startswith("CloudTrail") for n in self.names(est)))
        self.assertTrue(any(n.startswith("CloudTrail") for n in self.names(self._est("aws", "w3e2", {"vars": {}}))))

    def test_security_hub_and_config_follow_the_stack_rules(self):
        both = self.names(self._est("aws", "w3e3", {"vars": {"enable_security_hub": True}}))
        self.assertIn("Security Hub checks (low volume)", both)
        self.assertIn("AWS Config recorder (low volume)", both)
        hub_only = self.names(self._est("aws", "w3e4", {"vars": {"enable_security_hub": True}, "extra_vars": {"enable_aws_config": False}}))
        self.assertIn("Security Hub checks (low volume)", hub_only)
        self.assertNotIn("AWS Config recorder (low volume)", hub_only)
        cfg_only = self._est("aws", "w3e5", {"vars": {}, "extra_vars": {"enable_aws_config": True}})
        self.assertEqual([n for n in self.names(cfg_only) if "Security Hub" in n or "Config" in n], ["AWS Config recorder (low volume)"])
        self.assertTrue(any(n.startswith("AWS Config is billed per recorded") for n in cfg_only["notes"]))
        off = self.names(self._est("aws", "w3e6", {"vars": {"enable_security_hub": True}, "extra_vars": {"enable_account_baseline": False}}))
        self.assertFalse(any("Security Hub" in n or "Config" in n or "GuardDuty" in n for n in off))

    def test_eks_and_flow_logs_are_named(self):
        est = self._est("aws", "w3e7", {"vars": {"enable_kubernetes": True}})
        self.assertTrue(any("EKS control-plane logs" in n and "365-day" in n for n in est["notes"]))
        self.assertTrue(any("VPC flow logs" in n for n in est["notes"]))

    def test_azure_defender_and_fips(self):
        base = self._est("azure", "w3e8", {"vars": {"subscription_id": SUB}})
        est = self._est("azure", "w3e9", {"vars": {"subscription_id": SUB, "enable_defender": True, "enable_vpn": True,
                                                   "fips_mode": True}, "state": {"type": "remote"}})
        names = self.names(est)
        self.assertIn("Defender for Servers P2 x2", names)            # bastion + VPN host
        self.assertIn("Defender for Storage x1 account", names)       # the remote-state storage account
        self.assertGreater(est["total"], base["total"] + 29)
        self.assertTrue(any("subscription-wide" in n for n in est["notes"]))
        self.assertTrue(any("Ubuntu Pro FIPS" in n for n in est["notes"]))
        local = self.names(self._est("azure", "w3e10", {"vars": {"subscription_id": SUB, "enable_defender": True},
                                                        "state": {"type": "local"}}))
        self.assertFalse(any(n.startswith("Defender for Storage") for n in local))
        aks = self._est("azure", "w3e11", {"vars": {"subscription_id": SUB, "enable_kubernetes": True}})
        self.assertTrue(any("Container Insights" in n for n in aks["notes"]))

    def test_gcp_fips_images_are_named(self):
        est = self._est("gcp", "w3e12", {"vars": {"fips_mode": True}})
        self.assertTrue(any("Ubuntu Pro FIPS" in n for n in est["notes"]))


# ---------------------------------------------------------------------------------------------------- deps

class CredentialCheckTests(unittest.TestCase):
    def _check(self, rc, stdout="", stderr=""):
        with mock.patch.object(deps, "find", return_value="/x/aws"), \
                mock.patch.object(deps.subprocess, "run", return_value=subprocess.CompletedProcess([], rc, stdout, stderr)):
            return deps.live_credential_check("aws")

    def test_a_silent_failure_is_a_finding_not_a_crash(self):
        ok, msg = self._check(255)
        self.assertFalse(ok)
        self.assertIn("exited 255 with no output", msg)
        self.assertEqual(self._check(255, "  \n\t")[0], False)

    def test_no_credentials_is_not_expired(self):
        ok, msg = self._check(255, stderr="\nUnable to locate credentials. You can configure credentials by running \"aws configure\".\n")
        self.assertFalse(ok)
        self.assertTrue(msg.startswith("No AWS credentials found"))
        ok, msg = self._check(255, stderr="\nThe config profile (work) could not be found\n")
        self.assertIn("The AWS profile 'work' does not exist", msg)
        ok, msg = self._check(254, stderr="An error occurred (ExpiredToken) when calling the GetCallerIdentity operation: expired\n")
        self.assertIn("invalid/expired", msg)
        self.assertIn("ExpiredToken", msg)


class DownloadFailureTests(unittest.TestCase):
    def test_network_errors_are_install_failures(self):
        refused = urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
        stack, buf = _quiet()
        with stack, mock.patch.object(deps.urllib.request, "urlopen", side_effect=refused), \
                mock.patch.object(deps, "_brew_install", return_value=False), mock.patch.object(deps, "find", return_value=None):
            with self.assertRaises(deps.DownloadError):
                deps._download("https://dl.k8s.io/release/stable.txt")
            self.assertFalse(deps.install("kubectl"))
            self.assertFalse(deps.install("helm"))
        out = buf.getvalue()
        self.assertIn("Download of https://dl.k8s.io/release/stable.txt failed", out)
        self.assertIn("HTTPS_PROXY", out)
        self.assertNotIn("Unexpected error", out)

    def test_only_a_blocked_version_check_falls_back(self):
        with mock.patch.object(deps, "_download", side_effect=deps.DownloadError("blocked")):
            self.assertEqual(deps.latest_terraform_version(), deps.TERRAFORM_FALLBACK_VERSION)

    def test_scanner_downloads_are_install_failures_too(self):
        def boom():
            raise urllib.error.URLError("timed out")
        stack, buf = _quiet()
        with stack, mock.patch.object(deps, "_brew_install", return_value=False), mock.patch.object(deps, "find", return_value=None), \
                mock.patch("cloudseed.scan._install_kubescape", boom):
            self.assertFalse(deps.install("kubescape"))
        self.assertIn("Could not download kubescape", buf.getvalue())

    def test_cli_install_continues_after_a_network_failure(self):
        from cloudseed import cli
        refused = urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
        tried = []
        real = deps._install

        def spy(tool):
            tried.append(tool)
            return real(tool)
        stack, buf = _quiet()
        with stack, mock.patch.object(deps.urllib.request, "urlopen", side_effect=refused), \
                mock.patch.object(deps, "_brew_install", return_value=False), mock.patch.object(deps, "find", return_value=None), \
                mock.patch.object(deps, "_install", side_effect=spy), mock.patch.object(ui, "interactive", return_value=False):
            rc = cli.main(["install", "kubectl", "helm", "-y"])
        self.assertEqual(rc, 1)
        self.assertEqual(tried, ["kubectl", "helm"])
        self.assertIn("Could not install kubectl; continuing with the rest", buf.getvalue())
        self.assertNotIn("Unexpected error", buf.getvalue())


class PipCliTests(unittest.TestCase):
    def test_az_and_snow_need_python_310(self):
        asked = []

        def vp(min_version=(3, 10), purpose=""):
            asked.append((tuple(min_version), purpose))
            raise ui.Abort("Installing x needs Python 3.10+ with venv, and none was found.")
        for fn, pkg in ((deps.install_az, "azure-cli"), (deps.install_snow, "snowflake-cli")):
            asked.clear()
            with mock.patch.object(deps, "venv_python", vp), mock.patch.object(deps, "_brew_install", return_value=False):
                with self.assertRaises(deps.InstallError) as cm:
                    fn()
            self.assertEqual(asked, [((3, 10), pkg)])
            self.assertIn("Python 3.10+", str(cm.exception))

    def test_a_venv_built_with_python_39_is_rebuilt(self):
        home = Path(tempfile.mkdtemp())
        venv = home / "venv-az"
        (venv / "bin").mkdir(parents=True)
        az = venv / "bin" / "az"
        az.write_text("#!/bin/sh\n")
        az.chmod(0o755)
        rebuilt = []
        stack, _ = _quiet()
        with stack, mock.patch.object(paths, "HOME", home), mock.patch.object(deps, "find", return_value=str(az)), \
                mock.patch.object(deps, "_venv_version", return_value=(3, 9)), \
                mock.patch.object(deps, "_pip_cli", side_effect=lambda t: rebuilt.append(t) or True):
            self.assertTrue(deps.install("az"))
        self.assertEqual(rebuilt, ["az"])
        stack, _ = _quiet()
        with stack, mock.patch.object(paths, "HOME", home), mock.patch.object(deps, "find", return_value=str(az)), \
                mock.patch.object(deps, "_venv_version", return_value=(3, 12)), \
                mock.patch.object(deps, "_pip_cli", side_effect=lambda t: rebuilt.append(t) or True):
            self.assertTrue(deps.install("az"))
        self.assertEqual(rebuilt, ["az"])                              # a current one is left alone

    def test_a_failed_rebuild_keeps_the_previous_cli(self):
        for pip_rc in (1, 0):
            home = Path(tempfile.mkdtemp())
            venv = home / "venv-az"
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "az").write_text("#!/bin/sh\n# the old one\n")

            def run(cmd, **kw):
                if cmd[1:3] == ["-m", "venv"]:
                    (Path(cmd[3]) / "bin").mkdir(parents=True, exist_ok=True)
                    (Path(cmd[3]) / "bin" / "az").write_text("#!/bin/sh\n# new\n")
                    return subprocess.CompletedProcess(cmd, 0)
                return subprocess.CompletedProcess(cmd, pip_rc)
            linked = []
            stack, _ = _quiet()
            with stack, mock.patch.object(paths, "HOME", home), mock.patch.object(deps, "venv_python", return_value="/py3.12"), \
                    mock.patch.object(deps, "_venv_version", return_value=(3, 9)), \
                    mock.patch.object(deps.subprocess, "run", side_effect=run), \
                    mock.patch.object(deps, "_link", side_effect=lambda t, n: linked.append(n)):
                self.assertEqual(deps._pip_cli("az"), bool(pip_rc == 0))
            self.assertEqual((venv / "bin" / "az").read_text().endswith("# the old one\n"), pip_rc != 0, pip_rc)
            self.assertFalse((home / "venv-az.outdated").exists())
            self.assertEqual(linked, [] if pip_rc else ["az"])

    def test_newest_pythons_are_found(self):
        # the single-binary build (or an old running Python) looks on PATH: a python3.14 alone is enough
        with mock.patch.object(deps.paths, "IS_BUNDLE", True), \
                mock.patch.object(deps.shutil, "which", side_effect=lambda n, path=None: "/opt/py/bin/python3.14" if n == "python3.14" else None), \
                mock.patch.object(deps.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            self.assertEqual(deps.venv_python((3, 10), "azure-cli"), "/opt/py/bin/python3.14")


class HomebrewConsentTests(unittest.TestCase):
    def test_never_unattended(self):
        with mock.patch.object(deps, "_brew", return_value=None), mock.patch.object(deps.platform, "system", return_value="Darwin"), \
                mock.patch.object(deps, "agent_session", return_value=False), mock.patch.object(ui, "interactive", return_value=False), \
                mock.patch.object(ui, "confirm", side_effect=AssertionError("asked")), \
                mock.patch.object(deps.subprocess, "call", side_effect=AssertionError("ran the script")):
            self.assertFalse(deps.install_homebrew())


# ---------------------------------------------------------------------------------------------------- container

class EngineChoiceTests(unittest.TestCase):
    def test_an_asked_for_engine_is_never_swapped(self):
        which = {"docker": "/usr/bin/docker"}
        stack, _ = _quiet()
        with stack, mock.patch.object(container.shutil, "which", side_effect=lambda e: which.get(e)), \
                mock.patch.object(ui, "interactive", return_value=False):
            with self.assertRaises(ui.Abort) as cm:
                container.choose_engine({"engine": "podman"})
            self.assertIn("Install podman first", str(cm.exception))
            self.assertIn("--engine docker", str(cm.exception))
            with self.assertRaises(ui.Abort):
                container.choose_engine({}, explicit="podman")
            self.assertEqual(container.choose_engine({"engine": "docker"}), "docker")
            self.assertEqual(container.choose_engine({}), "docker")              # no preference: the one installed
            with self.assertRaises(ui.Abort) as cm:
                container.choose_engine({"engine": "rkt"})
            self.assertEqual(cm.exception.code, 2)


# ---------------------------------------------------------------------------------------------------- build files

class MakefileTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("make"), "make not installed")
    def test_tftest_runs_every_suite(self):
        r = subprocess.run(["make", "-n", "tftest"], cwd=REPO, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        suites = sorted(p.parent.parent.name for p in REPO.glob("terraform/*/tests/*.tftest.hcl"))
        self.assertIn("gcp", suites)
        loop = next(line for line in r.stdout.splitlines() if line.lstrip().startswith("for d in"))
        for cloud in suites:
            self.assertIn(f" {cloud}", loop)
        self.assertIn("build/tfdata", r.stdout)


if __name__ == "__main__":
    unittest.main()
