"""Wave-4 docs regression tests: help / explain / manual (docs/guides/manual.md) / skills text that must follow the code the other wave-3
groups changed (AWS baseline halves, GCP project-wide logging kept on destroy and the OS Login key cleanup, the
built-in agent's approvals and previews, Claude Code's deny rules, the CLI's human-only gate, the credential vault's
refused names, MCP and kubeconfig behaviour, undo semantics, platform FIPS tiers / --set / arm64 skips, DR and scan
options, VMware floors and rebuilds, the allow-list and tag rules, the environment shorthand) and the error hint that
names an exact help topic once, never next to a corrected command line."""

from __future__ import annotations

import contextlib
import io
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

# The reference text that README.md carried before it became the landing page lives in the manual on the docs
# site (docs/guides/manual.md); these checks follow it there. tests/test_readme.py checks the landing README.
MANUAL = "docs/guides/manual.md"
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-w4docs-"))

from cloudseed import agents, builtin_agent, cli, creds, deps, explain, help as h, localvm, netutil, paths  # noqa: E402
from cloudseed import platform as pl, undo  # noqa: E402
from cloudseed.clouds import base as cloudbase, gcp as gcpmod, vmware as vmmod  # noqa: E402

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _read(rel: str) -> str:
    return (ROOT / rel).read_text()


def _flat(text: str) -> str:
    return " ".join(text.split())


def _plain(text: str) -> str:
    return ANSI.sub("", text)


def _render(topic, columns=None, cloud=None) -> str:
    buf = io.StringIO()
    env = {"COLUMNS": str(columns)} if columns else {}
    with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(buf):
        if columns is None:
            os.environ.pop("COLUMNS", None)
        h.print_page(topic, cloud)
    return _plain(buf.getvalue())


def _parse_error(argv: list[str]) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(io.StringIO()), \
            mock.patch.object(sys, "argv", ["cloudseed", *argv]):
        try:
            cli.build_parser().parse_args(argv)
        except SystemExit:
            pass
    return _plain(buf.getvalue())


MANUAL_TEXT = _flat(_read(MANUAL))


def _skill(name: str) -> str:
    return _flat(_read(f"skills/{name}/SKILL.md"))


# ---------------------------------------------------------------- error hints: exact topics and corrected commands

class TopicHints(unittest.TestCase):
    """help.error_hint on its own (the corrected command lines cli._unknown_command builds arrive as `near`), and the
    parser end to end with assertions that hold however the CLI hands a help-topic word over (as a corrected
    `cloudseed help <topic>` line, or as the bad word for error_hint to name)."""

    def test_a_corrected_command_line_is_the_answer(self):
        # `cs aws setup`: 'aws' is also a help topic, but the corrected command line is what to type - no page pointer
        text = _plain(h.error_hint(None, "unknown command 'aws'", "aws", near=["cloudseed setup aws"], width=0))
        self.assertIn("did you mean cloudseed setup aws?", text)
        self.assertNotIn("help topic", text)
        # corrected lines survive the far-fetched filter an exact topic puts on the parser's fuzzy command matches
        text = _plain(h.error_hint(None, "x", "quickstart", near=["cloudseed help quickstart", "status"], width=0))
        self.assertIn("did you mean cloudseed help quickstart?", text)
        self.assertEqual(text.count("cloudseed help quickstart"), 1)
        self.assertNotIn("help topic", text)
        err = _parse_error(["aws", "setup"])
        self.assertIn("did you mean cloudseed setup aws?", err)
        self.assertNotIn("help topic", err)
        err = _parse_error(["-y", "aws", "setup", "--env", "dev"])
        self.assertIn("did you mean cloudseed -y setup aws --env dev?", err)

    def test_a_topic_typed_as_a_command_names_its_page_once(self):
        for word in ("quickstart", "fips", "security", "state", "examples"):
            err = _parse_error([word])
            self.assertRegex(err, rf"(help topic|did you mean) cloudseed help {word}\b", word)
            self.assertEqual(err.count(f"cloudseed help {word}"), 1, word)
            self.assertNotRegex(err, r"did you mean (status|state|setup|list)\b", word)   # nothing far-fetched
        err = _parse_error(["variables", "aws"])
        self.assertIn("cloudseed help variables aws", err)
        self.assertNotIn("variables <cloud>", err)          # the cloud typed, not the placeholder page as well

    def test_a_topic_one_letter_off_a_command_gets_both(self):
        err = _parse_error(["envs"])
        self.assertEqual(err.count("cloudseed help envs"), 1)
        self.assertRegex(err, r"did you mean (cloudseed help envs, or the command )?env\?")
        text = _plain(h.error_hint(None, "unknown command 'envs'", "envs", width=0))      # no parser suggestions
        self.assertIn("did you mean env?", text)
        self.assertIn("help topic cloudseed help envs", text)
        self.assertLess(text.index("help topic"), text.index("did you mean"))      # the exact topic first
        text = _plain(h.error_hint(None, "x", "envs", near=["cloudseed help envs", "env"], width=0))
        self.assertIn("did you mean cloudseed help envs, or the command env?", text)
        self.assertNotIn("help topic", text)

    def test_far_fetched_matches_stay_out(self):
        text = _plain(h.error_hint(None, "x", "quickstart", near=["status"], width=0))
        self.assertNotIn("did you mean", text)
        self.assertIn("help topic cloudseed help quickstart", text)
        self.assertEqual(_plain(h.error_hint("setup", "boom", "quickstart", near=["x"], width=0)).count("help topic"), 0)
        self.assertIn("cloudseed help quickstart", _parse_error(["quickstrt"]))        # a typo gets the closest topic


# ---------------------------------------------------------------- AWS baseline halves

class AwsBaselineDocs(unittest.TestCase):
    def test_every_text_gives_the_regional_advice(self):
        tf = _read("terraform/aws/variables.tf")
        for var in ("enable_account_baseline", "enable_regional_baseline", "enable_access_analyzer", "subnet_stride"):
            self.assertIn(f'variable "{var}"', tf)
        texts = {"manual": MANUAL_TEXT, "help security": _flat(h.TOPICS["security"]),
                 "help troubleshooting": _flat(h.TOPICS["troubleshooting"]), "aws skill": _skill("cloudseed-aws"),
                 "explain": _flat(" ".join([explain.FEATURES["security-baseline"]["what"]]
                                           + explain.FEATURES["security-baseline"]["commands"]))}
        for name, text in texts.items():
            self.assertIn("enable_regional_baseline", text, name)
            self.assertIn("enable_access_analyzer=false", text, name)
        skill = texts["aws skill"]
        for part in ("`vpn_instance_id`", "`subnet_stride`", "Account-wide baseline", "Regional baseline",
                     "one account analyzer per region", "`az_count` can change on a deployed environment",
                     "AWS China", "eks:DescribeCluster"):
            self.assertIn(part, skill, part)
        self.assertIn("AWS China and the isolated (ISO) regions are not supported", MANUAL_TEXT)
        self.assertIn("EBS encryption by default - it protects its region, not the account", MANUAL_TEXT)

    def test_the_documented_rules_hold(self):
        from cloudseed.clouds import aws
        self.assertTrue(aws._UNSUPPORTED_REGION.fullmatch("cn-north-1"))
        self.assertTrue(aws._UNSUPPORTED_REGION.fullmatch("us-iso-east-1"))
        self.assertFalse(aws._UNSUPPORTED_REGION.fullmatch("us-gov-west-1"))
        self.assertEqual(aws._REGIONAL_BASELINE.follows, "enable_account_baseline")
        self.assertIs(aws._regional_default({"vars": {"enable_account_baseline": False}}), False)
        self.assertIn('Action = ["eks:DescribeCluster"]', _read("terraform/aws/main.tf"))


# ---------------------------------------------------------------- GCP project-wide logging and OS Login

class GcpDocs(unittest.TestCase):
    def test_project_wide_logging_is_kept_everywhere(self):
        self.assertIn("google_project_iam_audit_config", gcpmod.GCP.PROJECT_WIDE)
        self.assertIn("google_logging_project_bucket_config", gcpmod.GCP.PROJECT_WIDE)
        for name, text in (("help destroy", _flat(h.COMMANDS["destroy"])), ("destroy skill", _skill("cloudseed-destroy")),
                           ("help security", _flat(h.TOPICS["security"])), ("gcp skill", _skill("cloudseed-gcp")),
                           ("manual", MANUAL_TEXT)):
            self.assertNotIn("audit config is removed", text, name)
            self.assertNotIn("removes the allServices audit config", text, name)
            self.assertRegex(text, r"audit (config|logs)[^.]*stay", name)
        self.assertIn("enable_project_baseline=false", MANUAL_TEXT)
        baseline = explain.FEATURES["security-baseline"]
        self.assertIn("cloudseed/clouds/aws.py, azure.py + gcp.py keep_on_destroy", baseline["files"])
        self.assertTrue(hasattr(gcpmod.GCP, "keep_on_destroy"))
        self.assertIn("enable_project_baseline=false", _flat(baseline["what"] + " ".join(baseline["commands"])))

    def test_os_login_key_cleanup(self):
        self.assertTrue(hasattr(gcpmod.GCP, "release_os_login"))
        skill = _skill("cloudseed-gcp")
        for part in ("gcloud compute os-login ssh-keys list", "gcloud compute os-login ssh-keys remove",
                     "only when cloudseed added it", "no other environment logs in with it"):
            self.assertIn(part, skill, part)
        for text in (_flat(h.COMMANDS["destroy"]), _skill("cloudseed-destroy")):
            self.assertIn("no other environment uses it", text)


# ---------------------------------------------------------------- agents

class AgentDocs(unittest.TestCase):
    def test_approvals_follow_the_builtin_agent(self):
        self.assertIn("provision", builtin_agent.APPROVAL_TEXT)
        self.assertIn("node add/remove/scale", builtin_agent.PREVIEW_TEXT)
        for name, text in (("manual", MANUAL_TEXT), ("help agentic", _flat(h.TOPICS["agentic"]))):
            for part in ("provision", "scans (all but", "vpn add-user/provision/revoke/connect/disconnect",
                         "helm template/lint", "json|yaml", "node add/remove/scale", "platform uninstall",
                         "chaos run --target", "preview", "Refused and unapproved calls are shown to you too"):
                self.assertIn(part, text, (name, part))
            self.assertNotIn("destroy, undo, --auto-approve, --purge*, node add/remove,", text, name)
        self.assertTrue(all(len(line) <= 120 for line in h.TOPICS["agentic"].splitlines()))

    def test_grok_gets_its_skills_in_the_prompt(self):
        self.assertTrue(agents.DEFAULT_AGENTS["grok"].get("skills_in_prompt"))
        self.assertIsNone(agents.DEFAULT_AGENTS["grok"].get("skills_dir"))
        for name, text in (("help install", h.COMMANDS["install"]), ("help skill", h.COMMANDS["skill"]),
                           ("manual", _read(MANUAL))):
            self.assertNotIn("~/.grok/skills", text, name)
            self.assertIn("Grok", text, name)
        self.assertIn("installs them for Claude Code", _flat(h.COMMANDS["skill"]))

    def test_readme_names_every_claude_deny_rule(self):
        home = {os.path.abspath(paths.HOME), os.path.realpath(paths.HOME)}
        for rule in agents.claude_deny_rules():
            path = rule[len("Read("):-1]
            if path.startswith("//"):
                path = path[1:]
            for base in home:
                if path.startswith(base + "/"):
                    path = path[len(base) + 1:]
            path = re.sub(r"^(~/|\*\*/)", "", path)
            path = re.sub(r"^envs/\*/", "", path)
            path = re.sub(r"/\*\*$", "", path)
            if path.startswith("/"):        # a custom working directory from another test's index
                continue
            self.assertIn(path.split("/")[0], MANUAL_TEXT, rule)
        for part in ("`vmware.json`", "`helm/`", "`mcp/`", "`vpn/`", "`*.ovpn`", "`managed/`"):
            self.assertIn(part, MANUAL_TEXT, part)

    def test_custom_agent_placeholders(self):
        self.assertIn("--skip-git-repo-check", agents.DEFAULT_AGENTS["codex"]["exec"])
        for text in (MANUAL_TEXT, _flat(h.TOPICS["agentic"])):
            self.assertIn("replaced anywhere inside a word", text)
            self.assertIn("--skip-git-repo-check", text)

    def test_human_only_gate_is_described_for_every_agent_session(self):
        for cmd in cli._HUMAN_ONLY_WHY:
            self.assertIn(f"`{cmd}", MANUAL_TEXT.split("**Human-only commands**")[1][:900], cmd)
        install = _flat(h.COMMANDS["install"])
        self.assertIn("in every agent session", install)
        self.assertIn("exit code 2", install)
        self.assertNotIn("the built-in agent refuses `install` and `deps install`, the skills tell", install)
        self.assertIn("In an agent session cloudseed itself refuses them", _skill("cloudseed"))


class Redaction(unittest.TestCase):
    def test_no_caveat_is_left(self):
        from cloudseed import managed
        import inspect
        self.assertIn("run_redacted", inspect.getsource(managed.run))
        texts = {"manual": MANUAL_TEXT, "help security": _flat(h.TOPICS["security"]),
                 "explain agentic": _flat(" ".join(explain.FEATURES["agentic"]["controls"])),
                 "managed skill": _skill("cloudseed-managed")}
        for name, text in texts.items():
            self.assertNotIn("not redacted yet", text, name)
            self.assertNotIn("passed through as it is", text, name)
        self.assertIn("`cs databricks` and `cs snowflake`", MANUAL_TEXT)


class VaultNames(unittest.TestCase):
    def test_refused_names_match_the_vault(self):
        for name in ("ANSIBLE_CONFIG", "OPENSSL_CONF", "NODE_OPTIONS", "GIT_SSH_COMMAND", "OPENAI_BASE_URL",
                     "FOO_ENDPOINT", "HTTPS_PROXY", "TF_LOG", "CLOUDSEED_HOME", "PYTHONPATH"):
            self.assertFalse(creds.valid_key(name), name)
        self.assertTrue(creds.valid_key("GITLAB_RUNNER_TOKEN"))
        page = _flat(h.COMMANDS["creds"])
        for part in ("ANSIBLE_*", "OPENSSL_*", "NODE_*", "GIT_*", "*_BASE_URL", "*_ENDPOINT*", "HTTP(S)_PROXY",
                     "TF_LOG*", "CLOUDSEED_*"):
            self.assertIn(part, page, part)
            self.assertIn(part.replace("HTTP(S)_PROXY", "proxies"), MANUAL_TEXT.replace("`", ""), part)

    def test_google_credentials_takes_the_json(self):
        with self.assertRaises(ValueError):
            creds.check_value("GOOGLE_CREDENTIALS", "/path/key.json")
        page = _flat(h.COMMANDS["creds"])
        self.assertNotIn("(path or JSON)", page)
        self.assertNotIn("(path or JSON)", h.COMMANDS["creds"])
        self.assertIn("GOOGLE_APPLICATION_CREDENTIALS=/path/key.json", page)
        self.assertIn("never a path", page)


# ---------------------------------------------------------------- MCP, kubeconfig, undo

class McpAndKubeconfig(unittest.TestCase):
    def test_token_rotation_and_connect(self):
        page = h.COMMANDS["mcp"]
        self.assertNotIn("then: cs mcp connect all", page)
        self.assertIn("HTTP-connected clients are updated automatically", page)
        flat = _flat(page)
        for part in ("never set up", "only warns", "needs the HTTP deployment", "helm status -o json|yaml"):
            self.assertIn(part, flat, part)
        self.assertIn("`helm status -o json|yaml`", MANUAL_TEXT)

    def test_service_names_per_home(self):
        from cloudseed import mcp
        import inspect
        src = inspect.getsource(mcp)
        self.assertIn('f"{LAUNCHD_LABEL}.{_home_id()}"', src)
        self.assertIn('f"{SYSTEMD_UNIT}-{_home_id()}"', src)
        state = " ".join(explain.FEATURES["mcp"]["state"])
        self.assertIn("io.cloudseed.mcp.<home id>.plist", state)
        self.assertIn("cloudseed-mcp-<home id>.service", state)
        self.assertIn("io.cloudseed.mcp.<home id>", MANUAL_TEXT)

    def test_kubeconfig_switches_the_context(self):
        for name, text in (("help k8s", _flat(h.COMMANDS["k8s"])), ("help vmware", _flat(h.TOPICS["vmware"])),
                           ("manual", MANUAL_TEXT), ("vmware skill", _skill("cloudseed-vmware")),
                           ("core skill", _skill("cloudseed")), ("explain", explain.FEATURES["kubernetes"]["what"])):
            self.assertRegex(text, r"current (kubectl )?context", name)


class UndoDocs(unittest.TestCase):
    def test_file_undos_keep_later_edits(self):
        import inspect
        self.assertIn("cloudseed-undo-", inspect.getsource(undo))
        self.assertIn('"undo-kept"', inspect.getsource(undo))
        page = _flat(h.COMMANDS["undo"])
        self.assertNotIn("k8s kubeconfig, platform template, mcp/ui token rotate -> the previous file is put back", page)
        for part in ("the contexts it merged are taken out again", "<file>.cloudseed-undo-<time>",
                     "the settings keys that command changed", "(failed part-way)", "cs node remove",
                     "Velero's bucket and identity are kept", "cs node scale"):
            self.assertIn(part, page, part)
        for part in ("<file>.cloudseed-undo-<time>", "~/.cloudseed/undo-kept/", "restore only the keys",
                     "history (inventory and audit trail)"):
            self.assertIn(part, MANUAL_TEXT, part)
        self.assertIn("undo-kept", " ".join(explain.FEATURES["undo"]["state"]))

    def test_the_undo_table_keeps_its_columns(self):
        rows = h.COMMANDS["undo"].split("revert it:\n")[1].split("\nA kubectl")[0].splitlines()
        arrows = {row.index("->") for row in rows if "->" in row}
        self.assertEqual(len(arrows), 1, rows)


# ---------------------------------------------------------------- platform, DR, scans

class PlatformDocs(unittest.TestCase):
    def test_fips_tiers_follow_the_catalog(self):
        self.assertEqual(pl.FIPS_CLASSES, ("compatible", "tls-restricted", "crypto-restricted"))
        crypto = sorted(n for n, v in pl.CATALOG.items() if v.get("fips") == "crypto-restricted")
        for name, text in (("help fips", _flat(h.TOPICS["fips"])), ("manual", MANUAL_TEXT),
                           ("explain fips", explain.FEATURES["fips"]["what"]), ("platform skill", _skill("cloudseed-platform"))):
            self.assertIn("crypto-restricted", text, name)
            self.assertNotIn("three tiers", text, name)
            for item in crypto:
                self.assertIn(item, text, (name, item))

    def test_resilience_group_and_arm64_skips(self):
        groups = h.COMMANDS["platform"].split("GROUPS")[1].split("GATEWAYS AND UIS")[0]
        resilience = groups.split("resilience")[1].split("chaos")[0]
        self.assertNotIn("kube-prometheus-stack", resilience)
        members = [n for n, v in pl.CATALOG.items() if v.get("group") == "resilience" and not v.get("hidden")]
        self.assertFalse(any("prometheus" in (pl.CATALOG[m].get("needs") or []) for m in members))
        amd64 = sorted(n for n, v in pl.CATALOG.items() if v.get("arch") and "arm64" not in v["arch"])
        self.assertTrue(amd64)
        for name, text in (("help platform", _flat(h.COMMANDS["platform"])), ("manual", MANUAL_TEXT),
                           ("platform skill", _skill("cloudseed-platform"))):
            for item in amd64:
                self.assertIn(item, text, (name, item))

    def test_set_values_uninstall_and_exit_codes(self):
        page = _flat(h.COMMANDS["platform"])
        for part in ("`--set key-` forgets", "exits 1 when nothing", "PVC minio/minio", "Polaris database",
                     "cloudnative-pg stays installed while Postgres clusters", "valid for 10 years",
                     "kagent_password", "reachable from this machine directly", "[--version V] [--set k=v]"):
            self.assertIn(part, page, part)
        self.assertEqual(len(h._synopsis_group(h.COMMANDS["platform"].splitlines(), 2)), 1)   # plan: one row
        for part in ("`--set key-`", "exits 1 when nothing", "MinIO's volume"):
            self.assertIn(part, MANUAL_TEXT, part)

    def test_dr_and_scan_options(self):
        dr_page = _flat(h.COMMANDS["dr"])
        for part in ("30d is taken as 720h", "RFC 1123", "need no velero CLI", "--no-volume skips the volume",
                     "never in an agent session", "CLOUDSEED_AUTO_INSTALL=1"):
            self.assertIn(part, dr_page, part)
        self.assertEqual(cli._GO_DURATION.fullmatch("30d"), None)       # the doc's reason: Go has no day unit
        scan = _flat(h.COMMANDS["scan"])
        for part in ("comma-separated or repeated", "exit code 2", "temporary read-only ClusterRole", "FIPS endpoints"):
            self.assertIn(part, scan, part)
        self.assertIn("KUBE_BENCH_RBAC", " ".join(dir(__import__("cloudseed.scan", fromlist=["x"]))))
        self.assertIn("`dr status` and `dr backups` need no velero CLI", _skill("cloudseed-platform"))
        self.assertIn("`cs dr status` and `cs dr backups` need no velero CLI", MANUAL_TEXT)

    def test_chaos_mesh_install_needs_consent(self):
        import inspect
        self.assertIn("args.auto_approve", inspect.getsource(cli._ensure_chaos_mesh))
        self.assertIn("install Chaos Mesh", _flat(h.COMMANDS["chaos"]))


# ---------------------------------------------------------------- VMware

class VmwareDocs(unittest.TestCase):
    def test_versions_floors_and_rebuilds(self):
        self.assertEqual(localvm.MIN_VERSION, {"fusion": (13, 0), "workstation": (17, 0)})
        topic, skill = _flat(h.TOPICS["vmware"]), _skill("cloudseed-vmware")
        self.assertIn("Fusion Pro 13+", topic)
        self.assertIn("Workstation Pro 17+", topic)
        self.assertIn("Fusion Pro 13 / Workstation Pro 17", skill)
        self.assertIn("Fusion Pro 13+", MANUAL_TEXT)
        self.assertIsNone(vmmod._MEMORY_MB(512))
        self.assertIsNotNone(vmmod._MEMORY_MB(508))
        self.assertIsNotNone(vmmod._MEMORY_MB(514))
        self.assertIsNone(vmmod._DISK_GB(10))
        self.assertIsNotNone(vmmod._DISK_GB(9))
        self.assertIsNotNone(vmmod._NODE_DISK_GB(19))
        for text in (topic, skill):
            for part in ("512 MB", "multiple", "10 GB", "20 GB", "2048 MB", "must be replaced", "`cloudseed ssh`"
                         if text is skill else "cloudseed ssh", ".replaced-<time>.vmwarevm", "RFC 1918"):
                self.assertIn(part, text, part)
        self.assertIn("Workload VMs are not", topic)
        self.assertIn("not Ansible-hardened", skill)
        self.assertNotIn("| same Ansible hardening |", _read(MANUAL))

    def test_workloads_turn_on_security_updates(self):
        tf = _read("terraform/vmware/modules/workloads/main.tf")
        self.assertIn("unattended-upgrades", tf)
        self.assertIn("auto_updates: false", _read("ansible/kubernetes.yml"))
        self.assertIn("unattended security updates", MANUAL_TEXT)


# ---------------------------------------------------------------- setup flags and environment selection

class SetupFlagDocs(unittest.TestCase):
    def test_allow_list_rules(self):
        self.assertIsNotNone(netutil.validate_cidr_list("203.0.113.7/24"))
        self.assertIsNone(netutil.validate_cidr_list("203.0.113.0/24"))
        self.assertIsNone(netutil.validate_cidr_list("203.0.113.7/32"))
        self.assertIsNone(netutil.validate_cidr_list("10.0.0.0/8,11.0.0.0/8"))          # adjacent /8s are fine
        self.assertIsNotNone(netutil.validate_cidr_list("10.0.0.0/8,11.0.0.0/8,12.0.0.0/8"))
        for name, text in (("help setup", _flat(h.COMMANDS["setup"])), ("help update-ip", _flat(h.COMMANDS["update-ip"])),
                           ("help security", _flat(h.TOPICS["security"])), ("manual", MANUAL_TEXT),
                           ("core skill", _skill("cloudseed"))):
            self.assertIn("203.0.113.7/24", text, name)
            self.assertIn("/8", text, name)

    def test_tag_rules(self):
        identity = cloudbase.Cloud.IDENTITY_TAGS
        tags = cloudbase.Cloud.tags(mock.Mock(key="aws"), {"name": "a", "env": "e", "owner": "o", "uid": "u",
                                                           "tags": {"owner": "x", "ManagedBy": "me", "team": ""}})
        self.assertEqual(tags["Owner"], "x")            # case-insensitive: owner sets Owner
        self.assertEqual(tags["ManagedBy"], "cloudseed")
        self.assertNotIn("team", tags)                  # KEY= removes
        for name, text in (("help setup", _flat(h.COMMANDS["setup"])), ("help envs", _flat(h.TOPICS["envs"])),
                           ("manual", MANUAL_TEXT), ("core skill", _skill("cloudseed"))):
            for tag in identity:
                self.assertIn(tag, text, (name, tag))
            self.assertRegex(text, r"case-insensitive", name)
            self.assertRegex(text, r"\b(K|KEY)=`? removes", name)

    def test_environment_shorthand(self):
        overview = _flat(h.OVERVIEW)
        self.assertIn("--env aws-prod", overview)
        for cmd in cli._CURRENT_ENV_COMMANDS:
            self.assertRegex(overview.split("<cloud> without --env")[1], r"\b%s\b" % cmd, cmd)
            self.assertIn(f"`{cmd}`", MANUAL_TEXT.split("`<cloud>` without `--env`")[1][:600], cmd)
        self.assertIn("--env aws-prod", _skill("cloudseed"))
        self.assertIn("--env aws-prod", MANUAL_TEXT)

    def test_workdir_purge_and_rename(self):
        for name, text in (("help destroy", _flat(h.COMMANDS["destroy"])), ("destroy skill", _skill("cloudseed-destroy")),
                           ("manual", MANUAL_TEXT)):
            self.assertIn("only when nothing else is left in it", text, name)
        self.assertIn("(a new or empty directory)", MANUAL_TEXT)
        self.assertIn("a new or empty directory", _flat(h.COMMANDS["setup"]))
        import inspect
        self.assertIn("--plan-only, then apply it", inspect.getsource(cli._check_rename))
        for text in (_flat(h.COMMANDS["setup"]), MANUAL_TEXT, _skill("cloudseed")):
            self.assertIn("--plan-only", text)
            self.assertIn("cloudseed apply", text)


# ---------------------------------------------------------------- install, deps, layout, troubleshooting

class InstallAndLayout(unittest.TestCase):
    def test_install_page(self):
        page = _flat(h.COMMANDS["install"])
        for tool in (deps.GKE_AUTH_PLUGIN, "kubescape", "trivy"):
            self.assertIn(tool, page, tool)
        self.assertEqual(deps.PIP_CLI_PYTHON, (3, 10))
        self.assertIn("Python 3.10+", page)
        self.assertIn("Python 3.10+", _flat(h.COMMANDS["deps"]))
        self.assertIn("(Python 3.10+)", MANUAL_TEXT)
        self.assertIn("`cloudseed install all` is the larger set", MANUAL_TEXT)

    def test_readme_layout_matches_the_tree(self):
        layout = _read(MANUAL).split("## Layout")[1].split("## Web console")[0]
        for script in sorted(p.name for p in (ROOT / "scripts").iterdir() if p.is_file() and not p.name.startswith(".")):   # not .DS_Store
            self.assertIn(script, layout, script)
        phony = re.search(r"^\.PHONY:(.*)$", _read("Makefile"), re.M).group(1).split()
        makefile_row = next(line for line in layout.splitlines() if line.startswith("Makefile"))
        for target in phony:
            if target != "help":
                self.assertRegex(makefile_row, r"\b%s\b" % target, target)
        self.assertTrue((ROOT / "terraform/aws/modules/kms").is_dir())
        self.assertTrue((ROOT / "terraform/gcp/modules/names").is_dir())
        self.assertIn("kms on aws, names on gcp", layout)
        self.assertIn("make tftest", layout)

    def test_troubleshooting_rows(self):
        topic = _flat(h.TOPICS["troubleshooting"])
        for part in (".terraform.lock.hcl", "TF_PLUGIN_CACHE_DIR", "a plan with no changes exits 0",
                     "enable_access_analyzer=false", "enable_regional_baseline=true"):
            self.assertIn(part, topic, part)
        self.assertIn("the failed change", _flat(h.COMMANDS["troubleshoot"]))
        self.assertNotIn("in the last failing log", _flat(h.COMMANDS["troubleshoot"]))
        self.assertIn('"... is not ready: ..."', _flat(h.COMMANDS["doctor"]))

    def test_provision_page(self):
        page = _flat(h.COMMANDS["provision"])
        for part in ("private keys", "kubeconfigs", "stops the copy", "--no-firewall removes", "PAM null-password",
                     "keep the NAT"):
            self.assertIn(part, page, part)
        from cloudseed import provision
        import inspect
        self.assertIn("PAM null-password", inspect.getsource(provision.provision))


class AzureDocs(unittest.TestCase):
    def test_skill_follows_the_module(self):
        tf = _read("terraform/azure/modules/kubernetes/main.tf")
        self.assertIn("private_cluster_public_fqdn_enabled = !var.public_endpoint", tf)
        base = _read("terraform/azure/modules/security-baseline/main.tf")
        self.assertIn('VirtualMachines = "P2", StorageAccounts = "DefenderForStorageV2"', base)
        skill = _skill("cloudseed-azure")
        for part in (".hcp.<region>.azmk8s.io", "Plan 2", "`DefenderForStorageV2`", "`ARM_USE_MSI=true`",
                     "`ARM_USE_OIDC=true`", "`AZURE_CONFIG_DIR`", "1-65535", "never falls back to az's subscription",
                     # the wave-4 Azure outputs and tag rules (terraform/azure/outputs.tf, Azure.tag_problem)
                     "`bastion_instance_id`", "`vpn_instance_id`", "`< > % & \\ ? /`", "at most 43 names"):
            self.assertIn(part, skill, part)


class PagesFit(unittest.TestCase):
    def test_changed_pages_fit_the_terminal(self):
        topics = ("setup", "provision", "k8s", "vpn", "destroy", "platform", "kubectl", "finops", "troubleshoot", "doctor",
                  "deps", "mcp", "undo", "creds", "chaos", "dr", "scan", "agentic", "skill", "install", "fips",
                  "security", "envs", "vmware", "troubleshooting", "update-ip", None)
        for cols in (60, 80, 100):
            for topic in topics:
                long = [l for l in _render(topic, cols).splitlines() if len(l) > cols and '"' not in l]
                self.assertEqual(long, [], f"help {topic} @ {cols}")

    def test_explain_pages_render(self):
        with mock.patch.dict(os.environ, {"COLUMNS": "80"}):
            for feature in ("security-baseline", "agentic", "mcp", "fips", "dr", "undo", "vmware", "kubernetes"):
                out = _plain(explain.page(feature))
                long = [line for line in out.splitlines() if len(line) > 80 and str(paths.REPO_ROOT) not in line]
                self.assertEqual(long, [], feature)


if __name__ == "__main__":
    unittest.main()
