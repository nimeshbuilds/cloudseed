"""Wave-5 regression tests for the cloud adapters' last cross-file changes: the AWS questions declare what they follow
and what they depend on (Security Hub only with the regional baseline), the cluster settings follow their switch in
every cloud, AWS tag keys use IAM's set with GuardDuty's narrower one only where this environment creates the
detector, a private AKS cluster keeps within Azure Private DNS's 15 tags, a blank saved yes/no or number is its
default without a warning, the vault refuses a bad value before writing it, and a service manager that keeps refusing
the console the same way is warned about once.

Stdlib only; no network, no cloud credentials, no launchd/systemd (stubbed), no listening sockets."""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, creds, ui, webui  # noqa: E402
from cloudseed.clouds import aws as aws_mod  # noqa: E402
from cloudseed.clouds import azure as azure_mod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
GUID = "0123abcd-0000-0000-0000-000000000000"


@contextlib.contextmanager
def _captured():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        yield buf


def _aws_cfg(tags=None, extra=None, **vars_):
    return {"cloud": "aws", "env": "dev", "name": "cs", "owner": "me", "uid": "abc123", "region": "us-east-1",
            "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.7/32"], "ssh_public_key": "",
            "state": {"type": "local", "backend": None}, "vars": dict(vars_), "extra_vars": dict(extra or {}),
            "tags": dict(tags or {}), "platform_prereqs": []}


def _azure_cfg(tags=None, uid="abc123", **vars_):
    v = {"subscription_id": GUID}
    v.update(vars_)
    return {"cloud": "azure", "env": "dev", "name": "cs", "owner": "me", "uid": uid, "region": "eastus",
            "network_cidr": "10.20.0.0/16", "allowed_ssh_cidrs": ["203.0.113.7/32"], "ssh_public_key": "",
            "state": {"type": "local", "backend": None}, "vars": v, "extra_vars": {}, "tags": dict(tags or {}),
            "platform_prereqs": []}


# ---------------------------------------------------------------- AWS questions: follows / depends_on

class AwsQuestionFields(unittest.TestCase):
    def setUp(self):
        self.aws = clouds.get("aws")

    def test_declared_as_constructor_fields(self):
        regional = self.aws.question("enable_regional_baseline")
        self.assertEqual((regional.follows, regional.depends_on), ("enable_account_baseline", ""))
        hub = self.aws.question("enable_security_hub")
        self.assertEqual(hub.depends_on, "enable_regional_baseline")
        self.assertEqual(hub.parent(), "enable_regional_baseline")
        self.assertIs(aws_mod._REGIONAL_BASELINE, regional)
        keys = [q.key for q in self.aws.questions]
        self.assertLess(keys.index("enable_regional_baseline"), keys.index("enable_security_hub"))

    def collect(self, overrides, existing=None, advanced=True):
        asked = []

        def ask_bool(prompt, default):
            asked.append(prompt)
            return default

        def ask(prompt, default=None, **kw):
            asked.append(prompt)
            return default
        with mock.patch.object(ui, "interactive", return_value=True), mock.patch.object(ui, "ask_bool", side_effect=ask_bool), \
                mock.patch.object(ui, "ask", side_effect=ask), mock.patch.dict(os.environ, {"AWS_PROFILE": ""}), _captured():
            out = self.aws.collect_vars(argparse.Namespace(), existing or {}, _aws_cfg(), advanced, overrides=overrides)
        return out, [p for p in asked if p.startswith("Enable Security Hub")]

    def test_security_hub_is_asked_only_with_the_regional_baseline(self):
        out, hub = self.collect({"enable_account_baseline": False, "enable_regional_baseline": False})
        self.assertEqual(hub, [])
        self.assertIs(out["enable_security_hub"], False, "kept at its default, not dropped")
        out, hub = self.collect({"enable_account_baseline": True})
        self.assertEqual(len(hub), 1)

    def test_the_regional_answer_it_follows_counts(self):
        # the regional baseline follows a 'no' account answer when it is not given: Security Hub is not asked either
        _out, hub = self.collect({"enable_account_baseline": False})
        self.assertEqual(hub, [])
        # an environment alone in its region: account half off, regional half on - Security Hub is asked
        _out, hub = self.collect({"enable_account_baseline": False, "enable_regional_baseline": True})
        self.assertEqual(len(hub), 1)

    def test_a_saved_answer_is_kept_while_not_asked(self):
        out, hub = self.collect({"enable_regional_baseline": False, "enable_account_baseline": False},
                                existing={"enable_security_hub": True})
        self.assertEqual(hub, [])
        self.assertIs(out["enable_security_hub"], True)

    def test_unused_while_the_regional_baseline_is_off(self):
        hub = self.aws.question("enable_security_hub")
        self.assertTrue(self.aws.unused(hub, {"vars": {"enable_account_baseline": False}}))
        self.assertTrue(self.aws.unused(hub, {"vars": {"enable_regional_baseline": "no"}}))
        self.assertFalse(self.aws.unused(hub, {"vars": {}}), "both halves default to on")
        self.assertFalse(self.aws.unused(hub, {"vars": {"enable_account_baseline": False, "enable_regional_baseline": True}}))


# ---------------------------------------------------------------- question order (a2-gcp#19)

class QuestionOrder(unittest.TestCase):
    def test_cluster_settings_follow_their_switch_in_every_cloud(self):
        for key in ("aws", "gcp", "azure"):
            with self.subTest(cloud=key):
                keys = [q.key for q in clouds.get(key).questions]
                k = keys.index("enable_kubernetes")
                self.assertEqual(keys[k + 1:k + 4], ["kubernetes_node_size", "kubernetes_node_count",
                                                     "kubernetes_public_endpoint"])
                self.assertEqual(keys[k + 4:k + 6], ["enable_vpn", "vpn_type"])

    def test_the_aws_prompts_come_in_that_order(self):
        asked = []

        def ask_bool(prompt, default):
            asked.append(prompt)
            return True if prompt.startswith("Create a private managed Kubernetes") else default

        def ask(prompt, default=None, **kw):
            asked.append(prompt)
            return default
        aws = clouds.get("aws")
        with mock.patch.object(ui, "interactive", return_value=True), mock.patch.object(ui, "ask_bool", side_effect=ask_bool), \
                mock.patch.object(ui, "ask", side_effect=ask), mock.patch.dict(os.environ, {"AWS_PROFILE": ""}), _captured():
            aws.collect_vars(argparse.Namespace(), {}, _aws_cfg(), True, overrides={})
        order = [next(i for i, p in enumerate(asked) if p.startswith(prefix)) for prefix in
                 ("Create a private managed Kubernetes", "Kubernetes node size", "Kubernetes node count",
                  "Expose the Kubernetes API", "Create a VPN host")]
        self.assertEqual(order, sorted(order))


# ---------------------------------------------------------------- AWS tag rules

class AwsTagRules(unittest.TestCase):
    def setUp(self):
        self.aws = clouds.get("aws")

    def test_keys_and_values_use_iams_set(self):
        for key in ("team", "Cost Center", "owner@team", "Équipe", "app.kubernetes.io/name", "k" * 128):
            self.assertIsNone(self.aws.tag_problem(key, "x"), key)
        for key, shown in (("Cost#Center", "'#'"), ("R&D", "'&'"), ("tab\tkey", "tab"), ("50%", "'%'")):
            problem = self.aws.tag_problem(key, "x")
            self.assertIn("letters, digits, spaces and _ . : / = + - @", problem, key)
            self.assertIn(shown, problem)
        self.assertIn("at most 128", self.aws.tag_problem("k" * 129, "x"))
        self.assertIn("at most 256", self.aws.tag_problem("team", "v" * 257))
        self.assertIsNone(self.aws.tag_problem("team", "v" * 256))
        self.assertIsNone(self.aws.tag_problem("team", ""), "an emptied tag drops a saved one")
        for key in ("aws:createdBy", "AWS:x"):
            self.assertIn("reserved by AWS", self.aws.tag_problem(key, "x"))

    def test_guardduty_keys_only_where_this_environment_creates_the_detector(self):
        tags = {"Cost Center": "42", "owner@team": "a", "ok-key": "b"}
        problems = self.aws.tags_problems(_aws_cfg(tags=tags))        # default: regional baseline and GuardDuty on
        self.assertEqual(len(problems), 2, problems)
        joined = "\n".join(problems)
        self.assertIn("--tag Cost Center=42: this environment creates the GuardDuty detector", joined)
        self.assertIn("not space", joined)
        self.assertIn("e.g. --tag Cost-Center=42; a saved one is dropped with --tag 'Cost Center='", joined)
        self.assertIn("e.g. --tag owner-team=a; a saved one is dropped with --tag owner@team=", joined)
        self.assertIn("--var enable_guardduty=false", joined)
        for cfg in (_aws_cfg(tags=tags, enable_regional_baseline=False),
                    _aws_cfg(tags=tags, enable_account_baseline="no"),               # the regional half follows it
                    _aws_cfg(tags=tags, extra={"enable_guardduty": False}),
                    _aws_cfg(tags=tags, extra={"enable_guardduty": "false"})):
            with self.subTest(vars=cfg["vars"], extra=cfg["extra_vars"]):
                self.assertEqual(self.aws.tags_problems(cfg), [])
        # an environment alone in its region manages the regional half (and GuardDuty) without the account half
        self.assertEqual(len(self.aws.tags_problems(_aws_cfg(tags=tags, enable_account_baseline=False,
                                                              enable_regional_baseline=True))), 2)

    def test_the_guardduty_check_skips_what_is_not_rendered_or_reported_already(self):
        cfg = _aws_cfg(tags={"Cost Center": "", "Cost#Center": "x", "managedby": "y", "Team": "ok"})
        self.assertEqual(self.aws.tags_problems(cfg), [])
        problems = self.aws.check_config(cfg)
        self.assertEqual(len([p for p in problems if "Cost#Center" in p]), 1, problems)     # tag_problem's, once

    def test_no_suggestion_when_nothing_ascii_is_left(self):
        problems = self.aws.tags_problems(_aws_cfg(tags={"東京": "x"}))
        self.assertEqual(len(problems), 1)
        self.assertIn("Rename the tag (a saved one is dropped with --tag '東京=')", problems[0])
        self.assertEqual(aws_mod._guardduty_key("Équipe Nord"), "Equipe-Nord")
        # never a suggestion AWS refuses: the reserved prefix, or longer than a key may be
        self.assertEqual(aws_mod._guardduty_key("@aws:team"), "")
        self.assertEqual(len(aws_mod._guardduty_key("\ufb01" * 100)), 128)          # 'ﬁ' -> 'fi'
        problems = self.aws.tags_problems(_aws_cfg(tags={"@aws:team": "x"}))
        self.assertEqual(len(problems), 1)
        self.assertNotIn("e.g. --tag aws:", problems[0])

    def test_setup_checks_and_saved_tags(self):
        problems = self.aws.check_config(_aws_cfg(tags={"Cost Center": "42"}))
        self.assertTrue(any("GuardDuty" in p for p in problems), problems)
        self.assertEqual(self.aws.check_config(_aws_cfg(tags={"Cost Center": "42"}, enable_regional_baseline=False,
                                                        enable_account_baseline=False)), [])
        with _captured() as out:   # a saved one that IAM accepts is kept: check_config decides with the configuration
            self.assertEqual(cli._saved_tags(self.aws, {"tags": {"Cost Center": "42", "R&D": "x"}}), {"Cost Center": "42"})
        self.assertIn("Dropping the saved tag R&D=x", out.getvalue())
        args = argparse.Namespace(tag=["Cost Center=42"], name=None, cidr=None, region=None, allow_ip=None,
                                  **{k: None for k in clouds.Question.FLAG_KEYS})
        with _captured():
            cli._check_setup_flags(self.aws, args)          # not refused before the configuration is known

    def test_the_stack_merges_environment_first(self):
        for cloud in ("aws", "azure"):
            text = (ROOT / "terraform" / cloud / "main.tf").read_text()
            self.assertIn('merge({ Environment = var.environment }, var.tags, { ManagedBy = "cloudseed" })', text)


# ---------------------------------------------------------------- Azure tag rules

class AzureTagRules(unittest.TestCase):
    def setUp(self):
        self.az = clouds.get("azure")

    def test_name_and_value_rules(self):
        self.assertIsNone(self.az.tag_problem("k" * 128, "v" * 256))
        self.assertIn("at most 128", self.az.tag_problem("k" * 129, "v"))
        self.assertIn("at most 256", self.az.tag_problem("k", "v" * 257))
        for ch in "<>%&\\?/":
            self.assertIn("Azure tag names cannot contain", self.az.tag_problem(f"a{ch}b", "v"), ch)

    def tags(self, n):
        return {f"t{i}": "x" for i in range(n)}

    def test_a_private_cluster_keeps_within_private_dns_15_tags(self):
        self.assertEqual(self.az.tags_problems(_azure_cfg(tags=self.tags(9), enable_kubernetes=True)), [])
        problems = self.az.tags_problems(_azure_cfg(tags=self.tags(10), enable_kubernetes="yes"))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("10 --tag names are too many for a private AKS cluster", problems[0])
        self.assertIn("private DNS zone, which holds at most 15 tags", problems[0])
        self.assertIn("cloudseed sets 6 itself", problems[0])
        self.assertIn("at most 9 of your own; drop 1", problems[0])
        # Project / Environment / Owner in any spelling only change a value: they take no slot of their own
        cfg = _azure_cfg(tags={**self.tags(9), "project": "p", "ENVIRONMENT": "e", "Owner": "o"}, enable_kubernetes=True)
        self.assertEqual(self.az.tags_problems(cfg), [])
        # an environment from before CloudseedEnvId has one more free slot; an emptied tag renders nothing
        self.assertEqual(self.az.tags_problems(_azure_cfg(tags=self.tags(10), uid="", enable_kubernetes=True)), [])
        self.assertEqual(self.az.tags_problems(_azure_cfg(tags={**self.tags(9), "gone": ""}, enable_kubernetes=True)), [])

    def test_no_private_dns_limit_without_a_private_cluster(self):
        for vars_ in ({}, {"enable_kubernetes": False}, {"enable_kubernetes": "no"},
                      {"enable_kubernetes": True, "kubernetes_public_endpoint": True},
                      {"enable_kubernetes": "true", "kubernetes_public_endpoint": "yes"}):
            with self.subTest(vars=vars_):
                self.assertEqual(self.az.tags_problems(_azure_cfg(tags=self.tags(20), **vars_)), [])

    def test_the_stricter_limit_is_reported_alone(self):
        problems = self.az.tags_problems(_azure_cfg(tags=self.tags(44), enable_kubernetes=True))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("private AKS cluster", problems[0])
        self.assertIn("drop 35", problems[0])
        problems = self.az.tags_problems(_azure_cfg(tags=self.tags(44)))
        self.assertEqual(len(problems), 1)
        self.assertIn("at most 43 of your own; drop 1", problems[0])

    def test_check_config_refuses_before_saving(self):
        problems = self.az.check_config(_azure_cfg(tags=self.tags(12), enable_kubernetes=True))
        self.assertTrue(any("private AKS cluster" in p for p in problems), problems)
        self.assertEqual(azure_mod.PRIVATE_DNS_TAGS_MAX, 15)


# ---------------------------------------------------------------- blank saved answers

class BlankSavedAnswers(unittest.TestCase):
    def saved(self, cloud, vars_, region="us-east-1"):
        with _captured() as out:
            got = cli._saved_answers(clouds.get(cloud), {"vars": vars_}, {}, {"unset": []}, {"region": region}, set())
        return got, out.getvalue()

    def test_a_blank_yes_no_or_number_is_the_default_without_a_word(self):
        got, said = self.saved("gcp", {"enable_vpn": "", "kubernetes_node_count": None, "fips_mode": "  ",
                                       "enable_kubernetes": "yes", "zone": "us-east1-b"}, region="us-east1")
        self.assertEqual(said, "")
        self.assertNotIn("enable_vpn", got)
        self.assertNotIn("kubernetes_node_count", got)
        self.assertNotIn("fips_mode", got)
        self.assertIs(got["enable_kubernetes"], True)
        got, said = self.saved("aws", {"az_count": "", "enable_security_hub": None, "single_nat_gateway": "no"})
        self.assertEqual(said, "")
        self.assertEqual(got, {"single_nat_gateway": False})

    def test_anything_else_invalid_is_still_reported(self):
        got, said = self.saved("aws", {"enable_vpn": "maybe", "az_count": "three"})
        self.assertIn("The saved enable_vpn 'maybe' is invalid", said)
        self.assertIn("The saved az_count 'three' is invalid", said)
        self.assertEqual(got, {})

    def test_a_blank_answer_is_not_an_invalid_one(self):
        aws = clouds.get("aws")
        self.assertEqual(aws.invalid_answers({"vars": {"enable_vpn": "  ", "az_count": "", "fips_mode": None}}), {})
        self.assertIn("enable_vpn", aws.invalid_answers({"vars": {"enable_vpn": "maybe"}}))

    def test_a_whitespace_only_text_answer_is_still_reported(self):
        # it is rendered as it is (a zone or login name of '  ' reaches Terraform): only an empty one is "not set"
        gcp = clouds.get("gcp")
        bad = gcp.invalid_answers({"region": "us-east1", "vars": {"zone": "  ", "ssh_username": " ", "enable_vpn": " "}})
        self.assertEqual(sorted(bad), ["ssh_username", "zone"])
        self.assertIn("admin_username", clouds.get("azure").invalid_answers({"vars": {"admin_username": "  "}}))
        self.assertEqual(gcp.invalid_answers({"region": "us-east1", "vars": {"zone": "", "ssh_username": None}}), {})


# ---------------------------------------------------------------- the vault refuses a bad value before writing

class VaultValues(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w5-creds-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_the_cli_refuses_a_bad_project_id_and_stores_nothing(self):
        home = self.tmp / "cs"
        env = dict(os.environ, CLOUDSEED_HOME=str(home), HOME=str(self.tmp / "home"), NO_COLOR="1")
        for k in ("GOOGLE_PROJECT", "CLOUDSDK_CORE_PROJECT"):
            env.pop(k, None)
        r = subprocess.run([sys.executable, str(ROOT / "bin" / "cloudseed"), "creds", "set", "GOOGLE_PROJECT=Bad_X",
                            "AWS_DEFAULT_REGION=us-east-1"], capture_output=True, text=True, env=env, timeout=60,
                           stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("'Bad_X' is not a GCP project ID", r.stdout + r.stderr)
        self.assertIn("Setup would ignore it. Nothing was changed.", r.stdout + r.stderr)     # one full stop
        self.assertFalse((home / "credentials.json").exists())

    def test_the_console_refuses_a_bad_project_id_and_stores_nothing(self):
        store = self.tmp / "credentials.json"
        with mock.patch.object(creds, "STORE", store), mock.patch.object(creds, "GCP_FILE", self.tmp / "gcp.json"), \
                mock.patch.dict(creds.APPLIED, clear=True):
            with self.assertRaises(ValueError) as cm:
                webui._change_creds({"set": {"GOOGLE_PROJECT": "Bad_X", "AWS_DEFAULT_REGION": "us-east-1"}})
            self.assertIn("Nothing was changed", str(cm.exception))
            self.assertFalse(store.exists())
            with self.assertRaises(ValueError):
                webui._change_creds({"set": {"GOOGLE_CREDENTIALS": "{"}})
            self.assertFalse(store.exists())


# ---------------------------------------------------------------- the console's service fallback, warned once

class ServiceFallback(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w5-ui-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "home"
        self.home.mkdir()
        ui_dir = self.tmp / "ui"
        self.why = "Failed to connect to bus: No medium found"
        self.failing = True
        self.cmds: list = []

        def fake_run(cmd, **kw):
            self.cmds.append(list(cmd))
            bad = self.failing and list(cmd[:3]) == ["systemctl", "--user", "daemon-reload"]
            return subprocess.CompletedProcess(cmd, 1 if bad else 0, "", self.why if bad else "")

        class FakeProc:
            pid = 999999

            def poll(self):
                return 0
        self.warn = mock.Mock()
        patches = [mock.patch.object(webui, "UI_DIR", ui_dir), mock.patch.object(webui, "STATE_PATH", ui_dir / "server.json"),
                   mock.patch.object(webui, "LOG_PATH", ui_dir / "server.log"), mock.patch.object(webui, "PID_PATH", ui_dir / "server.pid"),
                   mock.patch.object(Path, "home", return_value=self.home),
                   mock.patch.object(webui.subprocess, "run", side_effect=fake_run),
                   mock.patch.object(webui.subprocess, "Popen", side_effect=lambda argv, **kw: FakeProc()),
                   mock.patch.object(webui, "_wait_started", return_value=True),
                   mock.patch.object(webui.ui, "warn", self.warn)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def start(self, state=None):
        self.warn.reset_mock()
        s = dict(state if state is not None else webui.load_state()) or {"host": "127.0.0.1", "port": 7641, "service": "systemd"}
        kind = webui.start(s)
        return kind, " ".join(str(c.args[0]) for c in self.warn.call_args_list)

    def test_the_same_refusal_is_warned_about_once(self):
        kind, warned = self.start({"host": "127.0.0.1", "port": 7641, "service": "systemd"})
        self.assertEqual(kind, "background")
        self.assertIn("systemd --user is not usable here (Failed to connect to bus", warned)
        # cs ui restart (the whole saved state) and cs ui start (host/port/service only): tried again, not warned again
        kind, warned = self.start()
        self.assertEqual((kind, warned), ("background", ""))
        kind, warned = self.start({"host": "127.0.0.1", "port": 7641, "service": "systemd"})
        self.assertEqual((kind, warned), ("background", ""))
        self.assertEqual(webui.load_state()["service"], "systemd", "still the preference")
        self.assertEqual(sum(1 for c in self.cmds if c[:3] == ["systemctl", "--user", "daemon-reload"]), 3)

    def test_a_new_reason_or_a_working_service_manager_is_news(self):
        self.start({"host": "127.0.0.1", "port": 7642, "service": "systemd"})
        self.why = "Failed to connect to bus: Permission denied"
        _kind, warned = self.start()
        self.assertIn("Permission denied", warned)
        self.failing = False                       # a desktop session: the login item works, and the record goes
        kind, warned = self.start()
        self.assertEqual((kind, warned), ("systemd", ""))
        self.assertNotIn("refused", webui.load_state())
        self.failing = True                        # refused again later: said again
        _kind, warned = self.start()
        self.assertIn("systemd --user is not usable here", warned)


if __name__ == "__main__":
    unittest.main()
