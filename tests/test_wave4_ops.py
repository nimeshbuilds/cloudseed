"""Regression tests for the wave-4 ops items: the audit trail (Authorization headers hidden before the key=value rule,
the passthrough tool's own secret flags, `via` on every record, audit.record for the console), troubleshoot (checksum
mismatches wrapped over lines and blamed on the VMware provider only when it is named, tf.HINTS' <env dir> filled
with the working directory, the vmrest and provider-rebuild signatures, VMWARE_HOME and old VMware releases),
reconcile (GovCloud partitions, an account-level IAM Access Analyzer under another name stops before apply), finops
(GuardDuty / Security Hub / AWS Config follow the regional baseline switch) and deps (the clouds of each tool in
deps.status, Go >= 1.25 and its upgrade, the Azure note built on arm_credentials). Stdlib only, no network, no cloud."""

import contextlib
import io
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, clouds, deps, finops, paths, reconcile, secrets, tf, troubleshoot  # noqa: E402

TOKEN = "abcdefghijklmnopqrstuvwxyz0123456789"


def _quiet():
    buf = io.StringIO()
    stack = contextlib.ExitStack()
    stack.enter_context(contextlib.redirect_stdout(buf))
    stack.enter_context(contextlib.redirect_stderr(buf))
    return stack, buf


class _NotStrict(unittest.TestCase):
    """Runs with the terminal's redaction mode (not an agent session): only what goes to disk hides headers."""

    def setUp(self):
        self._strict = dict(secrets._STRICT)
        secrets._STRICT["on"] = False
        self._env = mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": ""})
        self._env.start()

    def tearDown(self):
        secrets._STRICT.update(self._strict)
        self._env.stop()


# ---------------------------------------------------------------------------------------------------- audit

class AuditMaskingTests(_NotStrict):
    def test_a_bearer_token_behind_a_secret_looking_header_is_hidden(self):
        # the key=value rule alone takes "X-Auth-Token: Bearer" and leaves the token: headers go first on disk
        header = f"X-Auth-Token: Bearer {TOKEN}"
        for argv in (["ssh", "aws", "--", "curl", "-H", header],
                     ["databricks", "api", "get", "/x", "-H", header],
                     ["helm", "aws", "--", "upgrade", "x", "c", "--set", f"h={header}"]):
            self.assertNotIn(TOKEN, json.dumps(audit.safe_argv(argv)), argv)

    def test_the_log_and_inventory_hide_it_too(self):
        self.assertNotIn(TOKEN, audit._KeyFilter().feed(f"> X-Auth-Token: Bearer {TOKEN}\n"))
        self.assertNotIn(TOKEN, json.dumps(audit.secrets_free({"note": f"X-Auth-Token: Bearer {TOKEN}",
                                                               "arn": f"arn:aws:iam::1:role/x Bearer {TOKEN}"})))
        # identifiers keep their shape
        self.assertEqual(audit.secrets_free({"arn": "arn:aws:iam::1:role/token-reader"})["arn"],
                         "arn:aws:iam::1:role/token-reader")

    def test_each_passthrough_tool_masks_its_own_secret_flags(self):
        R = secrets.REDACTED
        self.assertEqual(audit.safe_argv(["databricks", "--", "clusters", "list", "-p", "myprof"])[-1], "myprof")
        self.assertEqual(audit.safe_argv(["helm", "aws", "--env", "d", "--", "registry", "login", "r.io", "-p", "pw1234"])[-1], R)
        self.assertEqual(audit.safe_argv(["snowflake", "--", "connection", "add", "-p", "pw1234"])[-1], R)
        self.assertEqual(audit.safe_argv(["kubectl", "aws", "--", "logs", "-p", "web-0"])[-1], "web-0")     # --previous
        self.assertEqual(audit.safe_argv(["k9s", "aws", "--", "-p", "x"])[-1], "x")
        # a global option before the command does not hide which tool it is
        self.assertEqual(audit.safe_argv(["--runtime", "local", "helm", "aws", "--", "registry", "login", "-p", "pw1234"])[-1], R)
        # other commands: the generic secret flags only (-p is nobody's password there)
        self.assertEqual(audit.safe_argv(["ssh", "aws", "--", "mysql", "--password", "pw1234"])[-1], R)
        self.assertEqual(audit.safe_argv(["ssh", "aws", "--", "ssh", "-p", "2222"])[-1], "2222")


class AuditViaTests(_NotStrict):
    def _end(self, env_vars):
        env = paths.Env("aws", "w4via")
        env.create_dirs()
        with mock.patch.dict(os.environ, env_vars):
            for k in ("CLOUDSEED_UI", "CLOUDSEED_AGENT"):
                if k not in env_vars:
                    os.environ.pop(k, None)
            audit.begin(["status", "aws", "--env", env.name])
            audit.attach(env)
            audit.end(0)
        return audit.read_audit(env)[-1]

    def test_every_record_says_who_ran_it(self):
        self.assertEqual(self._end({})["via"], "cli")
        self.assertEqual(self._end({"CLOUDSEED_AGENT": "mcp"})["via"], "mcp")
        self.assertEqual(self._end({"CLOUDSEED_AGENT": "builtin"})["via"], "builtin")
        # a console job is the console's, whoever started it
        self.assertEqual(self._end({"CLOUDSEED_UI": "1", "CLOUDSEED_AGENT": "claude"})["via"], "ui")
        self.assertEqual(self._end({"CLOUDSEED_AGENT": " odd name/x\n"})["via"], "odd_name_x")

    def test_record_writes_the_console_s_own_changes(self):
        target = paths.HOME / "logs" / "audit.jsonl"
        before = target.read_text().count("\n") if target.exists() else 0
        rec = audit.record(["creds", "set", "AWS_DEFAULT_REGION=eu-west-1", f"AWS_SECRET_ACCESS_KEY={TOKEN}"], 0, via="ui",
                           note=f"Authorization: Bearer {TOKEN}")
        self.assertEqual(rec["via"], "ui")
        self.assertEqual(rec["argv"][-1], f"AWS_SECRET_ACCESS_KEY={secrets.REDACTED}")
        lines = target.read_text().splitlines()
        self.assertEqual(len(lines), before + 1)
        self.assertEqual(json.loads(lines[-1])["command"], "creds")
        self.assertNotIn(TOKEN, lines[-1])
        self.assertEqual(oct(target.stat().st_mode & 0o777), "0o600")

    def test_record_is_safe_from_many_threads(self):
        target = paths.HOME / "logs" / "audit.jsonl"
        before = target.read_text().count("\n") if target.exists() else 0
        threads = [threading.Thread(target=audit.record, args=(["env", "use", f"aws-t{i}"],), kwargs={"via": "ui"})
                   for i in range(24)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        lines = target.read_text().splitlines()[before:]
        self.assertEqual(len(lines), 24)
        self.assertEqual(sorted(json.loads(x)["argv"][-1] for x in lines), sorted(f"aws-t{i}" for i in range(24)))

    def test_record_into_an_environment_trail(self):
        env = paths.Env("aws", "w4rec")
        env.create_dirs()
        audit.record(["env", "use", env.id], 0, env=env)
        rec = audit.read_audit(env)[-1]
        self.assertEqual((rec["env"], rec["via"]), (env.id, audit.origin()))

    def test_record_never_creates_an_environment_directory(self):
        ghost = paths.Env("aws", "w4ghost")
        rec = audit.record(["env", "use", ghost.id], 0, env=ghost)
        self.assertEqual(rec["env"], ghost.id)
        self.assertFalse(ghost.dir.exists())
        self.assertEqual(json.loads((paths.HOME / "logs" / "audit.jsonl").read_text().splitlines()[-1])["env"], ghost.id)

    def test_record_never_raises(self):
        with mock.patch.object(audit, "_append", side_effect=OSError("disk full")):
            self.assertEqual(audit.record(["env", "clear"])["command"], "env")
        self.assertEqual(audit.record(42), {})                   # not an argv at all: nothing, and no exception

    def test_record_with_an_environment_id_instead_of_an_environment(self):
        rec = audit.record(["env", "use", "aws-w4str"], 0, env="aws-w4str")
        self.assertEqual(rec["env"], "aws-w4str")
        last = json.loads((paths.HOME / "logs" / "audit.jsonl").read_text().splitlines()[-1])
        self.assertEqual((last["env"], last["argv"]), ("aws-w4str", ["env", "use", "aws-w4str"]))


# ---------------------------------------------------------------------------------------------------- troubleshoot

WRAPPED_TLS = ("Error: Required plugins are not installed\n\nThe installed provider plugins are not consistent with the "
               "packages\nselected in the dependency lock file:\n  - registry.terraform.io/hashicorp/tls: the cached "
               "package for registry.terraform.io/hashicorp/tls 4.4.1 (in .terraform/providers) does not\nmatch any of "
               "the checksums recorded in the dependency lock file\n")
WRAPPED_VM = ("Error: Failed to install provider\n\nError while installing registry.local/cloudseed/vmdesktop v0.1.0: the "
              "local package for\nregistry.local/cloudseed/vmdesktop 0.1.0 doesn't match any of the checksums\npreviously "
              "recorded in the dependency lock file (for this platform)\n")


class TroubleshootTests(unittest.TestCase):
    def _scan(self, text, cloud="aws", **kw):
        log = Path(tempfile.mkdtemp()) / "x.log"
        log.write_text(text)
        return troubleshoot._scan_log(log, cloud, "t4", **kw)

    def test_a_wrapped_checksum_mismatch_is_the_lock_file_not_a_missing_provider(self):
        wd = Path("/w/envs/aws-t4")
        hits = self._scan(WRAPPED_TLS, workdir=wd)
        what = " ".join(f.what for f in hits)
        self.assertIn("plugin cache changed", what)
        self.assertNotIn("not installed", what)
        self.assertNotIn("VMware", what)
        self.assertTrue(any(f"{wd}/stack or {wd}/bootstrap" in f.fix for f in hits))

    def test_the_root_that_failed_is_named_when_the_log_says_which(self):
        wd = Path("/w/envs/aws-t4")
        hits = self._scan(WRAPPED_TLS + f"  ✖ terraform validate failed: A provider this root needs is not installed in "
                          f"{wd}/dry-run/bootstrap/.terraform (terraform init did not finish).\n", workdir=wd)
        fix = next(f.fix for f in hits if "plugin cache changed" in f.what)
        self.assertIn(f"the Terraform root that failed ({wd}/dry-run/bootstrap)", fix)
        self.assertNotIn(f"{wd}/stack", fix)

    def test_the_vmware_provider_is_blamed_only_when_it_is_named(self):
        wd = Path("/w/envs/vmware-t4")
        hits = self._scan(WRAPPED_VM, "vmware", workdir=wd)
        self.assertEqual(len(hits), 1, [h.what for h in hits])
        self.assertIn("locally built VMware provider", hits[0].what)
        self.assertIn(f"{wd}/stack/.terraform.lock.hcl", hits[0].fix)
        required = WRAPPED_VM.replace("Failed to install provider", "Required plugins are not installed")
        self.assertFalse(any("not installed" in f.what for f in self._scan(required, "vmware", workdir=wd)))
        # a genuinely missing VMware provider is still that
        missing = self._scan("Error: Required plugins are not installed\n  - registry.local/cloudseed/vmdesktop: there is "
                             "no package for registry.local/cloudseed/vmdesktop 0.1.0 cached in .terraform/providers\n", "vmware")
        self.assertTrue(any(f.fix == "cloudseed install vmware-provider" for f in missing))

    def test_another_provider_s_mismatch_next_to_a_missing_vmware_provider(self):
        # one "Required plugins are not installed" list (or two diagnostics) with a VMware provider that is simply
        # missing and another provider whose package does not match the lock: each is itself, in either order
        missing = ("  - registry.local/cloudseed/vmdesktop: there is no package for registry.local/cloudseed/vmdesktop "
                   "0.1.0 cached in\n.terraform/providers\n")
        tls = ("  - registry.terraform.io/hashicorp/tls: the cached package for registry.terraform.io/hashicorp/tls "
               "4.0.5 (in\n.terraform/providers) does not match any of the checksums recorded in the dependency lock file\n")
        head = "Error: Required plugins are not installed\n\nThe installed provider plugins are not consistent:\n"
        two = ("Error: Failed to install provider\n\nError while installing registry.local/cloudseed/vmdesktop v0.1.0: "
               "provider registry.local/cloudseed/vmdesktop 0.1.0 is not available\n\nError: Failed to install provider\n\n"
               "Error while installing hashicorp/tls v4.0.5: the local package for registry.terraform.io/hashicorp/tls "
               "4.0.5 doesn't match any of the checksums previously recorded in the dependency lock file\n")
        for text in (head + missing + tls, head + tls + missing, two):
            hits = self._scan(text, "vmware", workdir=Path("/w/envs/vmware-t4"))
            what = " ".join(f.what for f in hits)
            self.assertNotIn("locally built VMware provider", what, text)
            self.assertIn("plugin cache changed", what, text)
            if text != two:
                self.assertTrue(any(f.fix == "cloudseed install vmware-provider" for f in hits), (text, what))

    def test_env_dir_paths_are_filled(self):
        self.assertEqual("<workdir>/stack", tf.ROOT)      # tf.HINTS name the stack root inside the working directory
        wd = Path(tempfile.mkdtemp()) / "envs" / "aws-t4"
        hits = self._scan("Error: Required plugins are not installed\n  - registry.terraform.io/hashicorp/aws: there is no "
                          "package cached in .terraform/providers\n", workdir=wd)
        text = " ".join(f.what + " " + f.fix for f in hits)
        self.assertIn(f"{wd}/stack/.terraform", text)
        self.assertNotIn("<env dir>", text)
        plain = self._scan("Error: Error acquiring the state lock\n")
        self.assertFalse(any("<env dir>" in f.fix or "t4/stack" in f.fix for f in plain))
        # the one root the log names (cloudseed's explanation quotes the root terraform ran in) is that root
        boot = self._scan("Error: Required plugins are not installed\n  - registry.terraform.io/hashicorp/aws: there is "
                          "no package cached in .terraform/providers\n  ✖ terraform init failed: A provider this root "
                          f"needs is not installed in {wd}/dry-run/bootstrap/.terraform (terraform init did not "
                          "finish).\n", workdir=wd)
        text = " ".join(f.what for f in boot)
        self.assertIn(f"{wd}/dry-run/bootstrap/.terraform", text)
        self.assertNotIn(f"{wd}/stack", text)

    def test_vmrest_signatures(self):
        home = Path(tempfile.mkdtemp())
        with mock.patch.object(paths, "HOME", home):
            quit_ = self._scan("  ✖ vmrest exited at once (exit code 1): Please use -C to update credential\n"
                               f"  Full log: {home}/vmrest.log\n", "vmware")
            unconf = self._scan("  ✖ vmrest is not configured for this OS user (it exited: no output). Run `vmrest -C` ...\n",
                                "vmware")
            rejected = self._scan("  ✖ vmrest rejected VMREST_USER/VMREST_PASSWORD. Set them to ...\n", "vmware")
        self.assertIn("exit code 1", quit_[0].what)
        self.assertIn("Please use -C to update credential", quit_[0].what)
        self.assertIn(f"{home}/vmrest.log", quit_[0].fix)
        self.assertIn("8697", quit_[0].fix)
        self.assertIn("vmrest -C", unconf[0].fix)
        self.assertIn("VMREST_USER", unconf[0].fix)
        self.assertIn(f"{home}/vmware.json", unconf[0].fix)
        self.assertEqual(len(rejected), 1)
        self.assertIn("VMREST_USER/VMREST_PASSWORD", rejected[0].fix)
        provider = self._scan("  ✖ vmrest GET /api/vms: dial tcp 127.0.0.1:8697: connect: connection refused (is `vmrest` "
                              "running? ...)\n", "vmware")
        self.assertIn("not running", provider[0].what)

    def test_a_vmrest_cloudseed_did_not_start(self):
        foreign = self._scan("  ✖ The vmrest running on port 8697 was not started by cloudseed, and cloudseed has no "
                             "credentials for it.\n", "vmware")
        self.assertEqual(len(foreign), 1, [f.what for f in foreign])
        self.assertIn("VMREST_USER/VMREST_PASSWORD", foreign[0].fix)
        self.assertIn("8697", foreign[0].fix)
        other = self._scan("  ✖ Unexpected HTTP 404 from http://127.0.0.1:8697/api/vmnet: is another service using port "
                           "8697?\n", "vmware")
        self.assertEqual(len(other), 1, [f.what for f in other])
        self.assertIn("lsof", other[0].fix)

    def test_a_failed_provider_rebuild_is_a_warning_with_the_retry(self):
        hits = self._scan("  ▲ Rebuilding the VMware provider from the updated sources failed (see the Go output above); "
                          "using the existing build. Retry once Go can reach its module proxy: cloudseed install "
                          "vmware-provider --rebuild\n", "vmware")
        self.assertEqual([h.level for h in hits], ["warn"])
        self.assertIn("cloudseed install vmware-provider --rebuild", hits[0].fix)
        no_go = self._scan("  ▲ The VMware provider sources changed since it was built, but Go is not installed; using the "
                           "existing build.\n", "vmware")
        self.assertEqual([h.level for h in no_go], ["warn"])
        self.assertIn("cloudseed install go", no_go[0].fix)

    def test_the_cloudseed_home_in_fixes_is_this_one(self):
        home = Path(tempfile.mkdtemp())
        with mock.patch.object(paths, "HOME", home):
            hits = self._scan('Error: exec: "docker-credential-desktop": executable file not found in $PATH\n')
        self.assertTrue(any(f"{home}/helm/docker" in f.fix for f in hits), [f.fix for f in hits])
        with mock.patch.object(paths, "HOME", Path.home() / ".cloudseed"):
            hits = self._scan('Error: exec: "docker-credential-desktop": executable file not found in $PATH\n')
        self.assertTrue(any("~/.cloudseed/helm/docker" in f.fix for f in hits))

    def test_vmware_home_and_version_problems_are_findings(self):
        env = paths.Env("vmware", "w4vm")
        env.create_dirs()
        cloud = clouds.get("vmware")
        cfg = {"vars": {}, "env": env.name}
        seen = []

        def panel(title, lines, accent=None):
            seen.extend(lines)
        from cloudseed import localvm, ui
        patches = [mock.patch.object(deps, "missing", return_value=([], [])),
                   mock.patch.object(deps, "live_credential_check", return_value=None),
                   mock.patch.object(localvm, "provider_binary", return_value=Path(__file__)),
                   mock.patch.object(localvm, "_port_open", return_value=True),
                   mock.patch.object(ui, "panel", panel)]
        stack, _ = _quiet()
        with stack, contextlib.ExitStack() as ps:
            for p in patches:
                ps.enter_context(p)
            with mock.patch.object(localvm, "detect_host", return_value={"found": False, "vmware_home": "/nope/vmw"}):
                troubleshoot.run(cloud, env, cfg)
            with mock.patch.object(localvm, "detect_host", return_value={
                    "found": True, "product": "fusion", "version": "12.2.5", "arch": "arm64", "guest_arch": "arm64",
                    "os": "darwin"}):
                troubleshoot.run(cloud, env, cfg)
        text = "\n".join(seen)
        self.assertIn("VMWARE_HOME=/nope/vmw", text)
        self.assertIn("12.2.5 is too old", text)


# ---------------------------------------------------------------------------------------------------- reconcile

class _TF:
    def __init__(self, state=()):
        self.state, self.calls = list(state), []

    def state_list(self):
        return self.state

    def run(self, *args, **kw):
        self.calls.append(args)
        raise AssertionError(f"nothing may be imported or applied: {args}")


AA = "module.stack.module.security_baseline[0].aws_accessanalyzer_analyzer.this[0]"


class ReconcileTests(unittest.TestCase):
    CFG = {"cloud": "aws", "env": "dev", "name": "acme", "owner": "alice", "region": "us-gov-west-1", "vars": {}}

    def _lookups(self, answers):
        def fake(self, *args):
            for prefix, value in answers.items():
                if args[:len(prefix)] == prefix:
                    return value
            return None
        return mock.patch.object(reconcile.CloudLookups, "_awscli", fake)

    def test_iam_policy_ids_use_the_caller_s_partition(self):
        gov = {("sts", "get-caller-identity"): {"Account": "123456789012",
                                                "Arn": "arn:aws-us-gov:sts::123456789012:assumed-role/admin/me"}}
        with self._lookups(gov):
            lk = reconcile.CloudLookups("aws", self.CFG)
            self.assertEqual(lk.aws_iam_policy_arn("acme-dev-x"), "arn:aws-us-gov:iam::123456789012:policy/acme-dev-x")
        std = {("sts", "get-caller-identity"): {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/me"}}
        with self._lookups(std):
            self.assertEqual(reconcile.CloudLookups("aws", self.CFG).aws_iam_policy_arn("p"),
                             "arn:aws:iam::123456789012:policy/p")
        with self._lookups({("sts", "get-caller-identity"): {"Account": "123456789012"}}):
            self.assertEqual(reconcile.CloudLookups("aws", self.CFG).aws_iam_policy_arn("p"),
                             "arn:aws:iam::123456789012:policy/p")
        with self._lookups({}):
            self.assertIsNone(reconcile.CloudLookups("aws", self.CFG).aws_iam_policy_arn("p"))

    def _planned(self, name="acme-dev-analyzer"):
        return {AA: {"type": "aws_accessanalyzer_analyzer", "values": {"analyzer_name": name, "type": "ACCOUNT"}}}

    def test_another_account_analyzer_stops_before_apply(self):
        listed = {("accessanalyzer", "list-analyzers"): {"analyzers": [{"name": "ConsoleAnalyzer-1a2b", "status": "ACTIVE"}]}}
        with self._lookups(listed):
            with self.assertRaises(reconcile.SingletonExists) as cm:
                reconcile.preflight(_TF(), "aws", self.CFG, self._planned())
        msg = str(cm.exception)
        self.assertIn("An account-level IAM Access Analyzer (ConsoleAnalyzer-1a2b) already exists in us-gov-west-1", msg)
        self.assertIn("re-run with --var enable_access_analyzer=false", msg)
        self.assertIn("Nothing was applied.", msg)
        self.assertIn("cloudseed setup aws --env dev --var enable_access_analyzer=false", msg)
        self.assertEqual(cm.exception.disable, {"enable_access_analyzer": False})
        self.assertTrue(cm.exception.auto)
        cfg = dict(self.CFG, vars={"enable_access_analyzer": True})
        with self._lookups(listed):
            with self.assertRaises(reconcile.SingletonExists) as cm:
                reconcile.preflight(_TF(), "aws", cfg, self._planned())
        self.assertFalse(cm.exception.auto)             # asked for explicitly: never switched off behind the user's back
        self.assertNotIn("aws_accessanalyzer_analyzer", reconcile.NEVER_ADOPT)
        self.assertIn("aws_accessanalyzer_analyzer", reconcile.IMPORT_ID)

    def test_no_stop_for_our_own_name_no_cli_or_one_already_in_state(self):
        mine = {("accessanalyzer", "list-analyzers"): {"analyzers": [{"name": "acme-dev-analyzer"}]}}
        with self._lookups(mine):
            self.assertEqual(reconcile.preflight(_TF(), "aws", self.CFG, self._planned()), [])
        with self._lookups({}):                         # no aws CLI / no permission: nothing can be listed
            self.assertEqual(reconcile.preflight(_TF(), "aws", self.CFG, self._planned()), [])
        with self._lookups({("accessanalyzer", "list-analyzers"): {"analyzers": []}}):
            self.assertEqual(reconcile.preflight(_TF(), "aws", self.CFG, self._planned()), [])
        with mock.patch.object(reconcile.CloudLookups, "_awscli", side_effect=AssertionError("no lookup")):
            self.assertEqual(reconcile.preflight(_TF(state=[AA]), "aws", self.CFG, self._planned()), [])

    def test_it_is_named_with_the_other_singletons(self):
        gd = "module.stack.module.security_baseline[0].aws_guardduty_detector.this[0]"
        planned = dict(self._planned(), **{gd: {"type": "aws_guardduty_detector", "values": {}}})
        answers = {("accessanalyzer", "list-analyzers"): {"analyzers": [{"name": "other"}]},
                   ("guardduty", "list-detectors"): {"DetectorIds": ["d1"]}}
        with self._lookups(answers):
            with self.assertRaises(reconcile.SingletonExists) as cm:
                reconcile.preflight(_TF(), "aws", self.CFG, planned)
        self.assertEqual(cm.exception.disable, {"enable_access_analyzer": False, "enable_guardduty": False})
        lines = cm.exception.switch_off({})
        self.assertTrue(any(x.startswith("An account-level IAM Access Analyzer already exists in this region (other)")
                            for x in lines), lines)


# ---------------------------------------------------------------------------------------------------- finops

class EstimateBaselineTests(unittest.TestCase):
    def _names(self, name, **variables):
        e = paths.Env("aws", name)
        e.create_dirs()
        return [n for n, _ in finops.estimate(clouds.get("aws"), e, {"vars": {}, "extra_vars": variables})["lines"]]

    def test_regional_services_follow_the_regional_switch(self):
        regional_only = self._names("w4b1", enable_account_baseline=False, enable_regional_baseline=True,
                                    enable_security_hub=True)
        self.assertIn("GuardDuty (low volume)", regional_only)
        self.assertIn("Security Hub checks (low volume)", regional_only)
        self.assertIn("AWS Config recorder (low volume)", regional_only)
        self.assertFalse(any(n.startswith("CloudTrail") for n in regional_only))
        account_only = self._names("w4b2", enable_account_baseline=True, enable_regional_baseline="false",
                                   enable_security_hub=True)
        self.assertTrue(any(n.startswith("CloudTrail") for n in account_only))
        self.assertFalse(any("GuardDuty" in n or "Security Hub" in n or "Config" in n for n in account_only))

    def test_null_follows_the_account_switch(self):
        for value in (None, "null", ""):
            on = self._names("w4b3", enable_regional_baseline=value) if value is not None else self._names("w4b3")
            self.assertIn("GuardDuty (low volume)", on, value)
            off = self._names("w4b4", enable_account_baseline="off", enable_regional_baseline=value)
            self.assertFalse(any("GuardDuty" in n or n.startswith("CloudTrail") for n in off), (value, off))


# ---------------------------------------------------------------------------------------------------- deps

def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class DepsTests(unittest.TestCase):
    def setUp(self):
        self.bin = Path(tempfile.mkdtemp())
        self.state = self.bin / "go-version"
        self.state.write_text("go1.22.5\n")
        self.calls = self.bin / "calls"
        # a Go that reports what the state file says, only with GOTOOLCHAIN=local (else it would name the toolchain
        # a go.mod asks for), and a brew that records what it is asked and upgrades that Go
        _script(self.bin / "go", f'[ "$GOTOOLCHAIN" = local ] || {{ echo go1.99.0; exit 0; }}\n'
                                 f'if [ "$1" = env ]; then cat "{self.state}"; else echo "go version $(cat "{self.state}") '
                                 'darwin/arm64"; fi\n')
        _script(self.bin / "brew", f'echo "$*" >> "{self.calls}"\n'
                                   f'case "$1" in list) echo "go 1.22.5";; upgrade) echo go1.25.1 > "{self.state}";; esac\n')
        self._path = mock.patch.dict(os.environ, {"PATH": f"{self.bin}{os.pathsep}/usr/bin{os.pathsep}/bin"})
        self._path.start()
        self._bin_dir = mock.patch.object(paths, "BIN_DIR", self.bin / "cloudseed-bin")
        self._bin_dir.start()

    def tearDown(self):
        self._path.stop()
        self._bin_dir.stop()

    def test_go_version_is_the_local_toolchain(self):
        self.assertEqual(deps.version_of("go"), "1.22.5")
        self.assertTrue(deps.too_old("go", deps.version_of("go")))
        self.assertEqual(deps.TOOLS["go"]["min_version"], "1.25")
        self.state.write_text("go1.27.1\n")
        self.assertEqual(deps.version_of("go"), "1.27.1")
        self.assertFalse(deps.too_old("go", "1.27.1"))
        self.assertTrue(deps.too_old("go", "1.24.13"))
        self.assertFalse(deps.too_old("go", "1.25.0"))
        self.assertFalse(deps.too_old("go", "1.25rc2"))

    def test_go_minimum_matches_provider_toolchain(self):
        go_mod = (Path(__file__).resolve().parents[1] / "providers" / "vmdesktop" / "go.mod").read_text()
        required = next(line.split()[1] for line in go_mod.splitlines() if line.startswith("go "))
        self.assertEqual(deps.TOOLS["go"]["min_version"].split(".")[:2], required.split(".")[:2])

    def test_status_rows_carry_their_clouds(self):
        with mock.patch.object(deps, "find", return_value=None):
            rows = {r["tool"]: r for r in deps.status()}
        self.assertEqual(rows["go"]["clouds"], ("vmware",))
        self.assertEqual(rows["kubectl"]["clouds"], ())
        self.assertIn("aws", rows["terraform"]["clouds"])
        json.dumps(rows)                                  # the console and MCP serialize them

    def test_an_old_go_is_reported_and_upgraded_with_brew(self):
        row = next(r for r in deps.status("vmware") if r["tool"] == "go")
        self.assertTrue(row["outdated"])
        self.assertIn("needs >= 1.25", row["version"])
        self.assertIn("go", deps.missing("vmware")[1])
        stack, out = _quiet()
        with stack, mock.patch.object(deps, "_download", side_effect=AssertionError("no download expected")):
            self.assertTrue(deps.install("go"))
        calls = self.calls.read_text().splitlines()
        self.assertIn("upgrade go", calls)
        self.assertNotIn("install go", calls)
        self.assertEqual(deps.version_of("go"), "1.25.1")
        self.assertIn("older than 1.25", out.getvalue())

    def test_a_go_brew_cannot_update_falls_back_to_the_official_release(self):
        _script(self.bin / "brew", f'echo "$*" >> "{self.calls}"\ncase "$1" in list) exit 1;; esac\n')   # not brew's Go
        called = []

        def release(url, timeout=0):
            called.append(url)
            raise deps.DownloadError(f"Download of {url} failed: offline.")
        stack, out = _quiet()
        with stack, mock.patch.object(deps, "_download", side_effect=release):
            self.assertFalse(deps.install("go"))
        self.assertIn("install go", self.calls.read_text())
        self.assertTrue(called and called[0].startswith("https://go.dev/dl/"))
        self.assertIn("older than 1.25", out.getvalue())

    def test_a_current_go_is_left_alone(self):
        self.state.write_text("go1.26.0\n")
        stack, out = _quiet()
        with stack:
            self.assertTrue(deps.install("go"))
        self.assertFalse(self.calls.exists())
        self.assertIn("already installed", out.getvalue())


class AzureNoteTests(unittest.TestCase):
    def _note(self, **env):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("ARM_")}
        clean.update(env)
        with mock.patch.dict(os.environ, clean, clear=True):
            return deps.optional_cli_note("azure", "az")

    def test_the_note_follows_the_provider_s_rules(self):
        self.assertIn("optional here", self._note(ARM_USE_MSI="true"))            # system-assigned: no client id
        self.assertIn("optional here", self._note(ARM_CLIENT_ID="x", ARM_CLIENT_SECRET="y", ARM_TENANT_ID="z"))
        self.assertIn("optional here", self._note(ARM_CLIENT_ID="x", ARM_CLIENT_CERTIFICATE_PATH="/c.pfx"))
        self.assertIn("optional here", self._note(ARM_CLIENT_ID="x", ARM_USE_OIDC="true"))
        for env in ({"ARM_CLIENT_ID": "x", "ARM_USE_MSI": "false"}, {"ARM_CLIENT_ID": "x", "ARM_USE_OIDC": "false"},
                    {"ARM_CLIENT_ID": "x"}, {}):
            note = self._note(**env)
            self.assertNotIn("optional here", note, env)
            self.assertIn("unless", note)
            self.assertIn("ARM_USE_MSI=true", note)
            self.assertIn("ARM_USE_OIDC=true", note)
            self.assertIn("ARM_CLIENT_CERTIFICATE_PATH", note)

    def test_it_names_what_it_found(self):
        self.assertIn("a managed identity (ARM_USE_MSI)", self._note(ARM_USE_MSI="1"))


if __name__ == "__main__":
    unittest.main()
