"""Wave-2 docs regression tests: help pages, explain, the manual (docs/guides/manual.md) and skills describe what the merged code does (destroy/purge,
update-ip, managed vars, reconcile, undo scopes, MCP safety, FIPS keys, platform catalog, vmware limits, managed data
profiles, chaos/dr/scan exit codes), and wide-term tables render the same way from top to bottom."""

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
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-w2docs-"))

from cloudseed import builtin_agent, cli, clouds, explain, help as h, managed, mcp, platform as pl  # noqa: E402
from cloudseed.clouds import vmware as vmwaremod  # noqa: E402


def _read(rel: str) -> str:
    return (ROOT / rel).read_text()


def _flat(text: str) -> str:
    """Whitespace-normalised text, so a phrase is found even when the page wraps it."""
    return " ".join(text.split())


def _render(topic, cloud=None, columns=None) -> str:
    buf = io.StringIO()
    env = {"COLUMNS": str(columns)} if columns else {}
    with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(buf):
        if columns is None:
            os.environ.pop("COLUMNS", None)
        h.print_page(topic, cloud)
    return buf.getvalue()


class OverviewAndSetup(unittest.TestCase):
    def test_env_shorthand_and_env_vars_are_documented(self):
        overview = _flat(h.page(None))
        for cmd in cli._ENV_SCOPED:           # every command that may leave out <cloud>
            self.assertRegex(overview, r"Env shorthand:[^.]*\b%s\b" % re.escape(cmd), cmd)
        for var in ("CLOUDSEED_NONINTERACTIVE=1", "CLOUDSEED_DEBUG=1", "CLOUDSEED_HOME"):
            self.assertIn(var, overview)
        for cmd in ("status", "output", "ssh", "plan"):
            self.assertIn(f"cloudseed {cmd} [<cloud>]", h.COMMANDS[cmd])

    def test_setup_page_matches_the_input_rules(self):
        setup = _flat(h.COMMANDS["setup"])
        self.assertIn("IPv4 only", setup)
        self.assertIn("wider than a /8", setup)
        self.assertIn("K=null drops a saved override", setup)
        self.assertIn("<region>-b in us-east1 and europe-west1", setup)
        self.assertIn("creates nothing", setup)

    def test_variables_page_lists_exactly_what_setup_refuses(self):
        for key, cloud in clouds.CLOUDS.items():
            declared = cli._variable_types(key)
            refused = set(cli._managed_vars(cloud, declared))
            page = h.variables_page(key)
            self.assertIn("refused in --var", page)
            listed = set(re.findall(r"^  (\w+)\s", page.split("SET BY CLOUDSEED")[1], re.M))
            self.assertEqual(listed, refused, key)
        gcp = h.variables_page("gcp")
        self.assertNotIn("project_id", gcp.split("SET BY CLOUDSEED")[1])   # a setup answer: --var project_id works
        self.assertRegex(gcp, r"project_id\s+default: none: --project-id")
        self.assertIn("--var name=null drops a saved override", h.variables_page("aws"))


class DestroyAndUpdateIp(unittest.TestCase):
    def test_destroy_page_says_what_purge_keeps(self):
        page = _flat(h.COMMANDS["destroy"])
        self.assertNotIn("(config, generated SSH keys)", page)
        for part in ("~/.cloudseed/logs/purged/<cloud>-<env>/", "~/.cloudseed/undo/", "only cloudseed's own files",
                     "exits 3", "Karpenter NodePools", "LoadBalancer", "must be reachable",
                     "no other VMware environment is left and no VM is running", "only this environment's leftover VM files",
                     "S3 account public-access block", "Config service-linked role", "Defender"):
            self.assertIn(part, page, part)

    def test_purge_paths_match_the_code(self):
        # the page names the directories cli._purge_env_dir really uses
        self.assertEqual(cli.undo.BACKUPS.name, "undo")
        src = _read("cloudseed/cli.py")
        self.assertIn('paths.HOME / "logs" / "purged" / env.id', src)

    def test_update_ip_page(self):
        page = _flat(h.COMMANDS["update-ip"])
        self.assertIn("Cloud targets only", page)
        self.assertIn("Only the SSH-source changes are applied", page)
        self.assertIn("recovery commands", page)
        provision = _flat(h.COMMANDS["provision"])
        self.assertIn("enforced by the cloud firewall", provision)
        self.assertNotIn("SSH from your IPs only", provision)
        controls = " ".join(explain.FEATURES["bastion"]["controls"])
        self.assertIn("host nftables default-deny", controls)


class Pages(unittest.TestCase):
    def test_install_on_demand_is_asked(self):
        for page in ("k8s", "vpn", "kubectl"):
            text = _flat(h.COMMANDS[page])
            self.assertNotIn("installed on demand", text, page)
            self.assertIn("exit code 2", text, page)

    def test_k8s_page(self):
        k8s = _flat(h.COMMANDS["k8s"])
        for part in ("bastion role only", "external_secrets_prefixes", "gke-gcloud-auth-plugin", "az_count >= 2",
                     "Google-managed keys", "CIS hardening profile is not enabled", "joins at the version the cluster runs"):
            self.assertIn(part, k8s, part)
        self.assertNotIn("bastion / VPN roles", k8s)
        self.assertNotIn("CIS-hardened defaults", h.TOPICS["vmware"])

    def test_managed_page_and_examples_work(self):
        page = h.COMMANDS["managed"]
        flat = _flat(page)
        for part in ("the saved 'default' one", "cs databricks -- clusters list --profile X", "--config-file",
                     "before or after the subcommand"):
            self.assertIn(part, flat, part)
        self.assertNotIn("goes BEFORE the subcommand", flat)
        for m in re.finditer(r"^  cs (databricks|snowflake) connect (.*?)(?:\s+#.*)?$", page, re.M):
            values, prof = managed.parse_connect_args(m.group(1), m.group(2).split())
            self.assertTrue(values, m.group(0))
        # the profile flag works after the subcommand, and `--` hands the rest to the vendor CLI
        self.assertEqual(cli._pull_profile_arg(["test", "--profile", "prod"]), (["test"], "prod"))
        self.assertEqual(cli._pull_profile_arg(["--", "clusters", "--profile", "X"])[1], None)

    def test_chaos_page(self):
        page = h.COMMANDS["chaos"]
        flat = _flat(page)
        for part in ("45, 45s or 2m", "15s..1h", "2..20", "INCONCLUSIVE", "exit code is 0 only for PASS", "never a PASS"):
            self.assertIn(part, flat, part)
        for value in re.findall(r"--duration (\S+)", page.split("EXAMPLES")[1]):
            cli._chaos_seconds(value)          # every example duration is accepted

    def test_scan_and_dr_pages(self):
        scan = _flat(h.COMMANDS["scan"])
        self.assertIn("Exit code: 1 when a verdict is FAIL", scan)
        self.assertIn("scans/raw/", scan)
        self.assertNotIn("cs scan cis && cs scan kube", h.COMMANDS["scan"])
        self.assertIn("N/A", scan)
        dr = h.COMMANDS["dr"]
        self.assertIn("cloudseed dr status|backup|restore|backups|schedule|test [name] [<cloud> --env NAME]", dr)
        self.assertIn("random file", _flat(dr))
        self.assertIn("PodVolumeBackups", _flat(dr))

    def test_mcp_page_and_readme_list_the_confirmations(self):
        page = _flat(h.COMMANDS["mcp"])
        self.assertIn(f"{len(mcp.TOOLS)} tools", page)
        for part in ("update-ip", "provision", "vpn add-user/revoke/provision", "status/test/list/get/describe",
                     "every kind except architecture, fips and reports", "input schema", "cs undo --global", "MCP_TOOL_TIMEOUT=3600000",
                     "1-hour tool timeout"):
            self.assertIn(part, page, part)
        readme = _flat(_read(MANUAL))
        for part in ("MCP_TOOL_TIMEOUT=3600000", "every kind except `architecture`, `fips` and `reports`", "schema", "update-ip, provision"):
            self.assertIn(part, readme, part)

    def test_undo_and_creds_pages(self):
        undo = _flat(h.COMMANDS["undo"])
        for part in ("Fifteen real undo points", "at most five of one kind", "minor", "never push a real undo point out", "CLOUDSEED_AGENT",
                     "`cs undo --global` is refused", "rewrites config.json only once the re-apply worked"):
            self.assertIn(part, undo, part)
        creds = _flat(h.COMMANDS["creds"])
        for part in ("`set KEY` without a value", "hidden input", "exit code 2", "~ expanded", "CLOUDSEED_*",
                     "last 4 characters"):
            self.assertIn(part, creds, part)
        self.assertIn("cs creds set AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY", h.COMMANDS["creds"])

    def test_skill_install_and_explain_pages(self):
        skill = _flat(h.COMMANDS["skill"])
        self.assertIn("skill show <name>", skill)
        self.assertIn("all bundled skills", skill)
        self.assertIn("aws, gcp, azure, vmware, destroy, platform, finops, managed, architecture", skill)
        self.assertIn("selected agent only when none is selected yet", _flat(h.COMMANDS["install"]))
        exp = _flat(h.COMMANDS["explain"])
        self.assertIn("feature|target|topic|command|group|item <name>", exp)
        self.assertIn("feature > target > platform group / item > command / topic", exp)
        self.assertEqual(explain.NAMESPACES, cli._EXPLAIN_NAMESPACES)
        index = _flat(re.sub(r"\x1b\[[0-9;]*m", "", explain.index()))
        self.assertIn("|".join(cli._EXPLAIN_NAMESPACES) + " <name>", index)
        self.assertIn("variables <cloud> | outputs <cloud>", index)

    def test_fips_texts_name_rsa_keys(self):
        for name, text in (("help fips", h.TOPICS["fips"]), ("manual", _read(MANUAL)),
                           ("explain fips", explain.FEATURES["fips"]["what"])):
            flat = _flat(text)
            self.assertIn("RSA-4096", flat, name)
            self.assertNotIn("ECDSA P-384", flat, name)
            self.assertNotIn("ECDSA SSH keys", flat, name)
            self.assertIn("tls-restricted", flat, name)
        self.assertIn("RSA-4096", _read("skills/cloudseed-vmware/SKILL.md"))
        self.assertIn("RSA-4096", _read("skills/cloudseed/SKILL.md"))

    def test_agentic_topic_and_readme_match_the_builtin_agent(self):
        topic = _flat(h.TOPICS["agentic"])
        readme = _flat(_read(MANUAL))
        for model in builtin_agent.MODELS:
            self.assertIn(model, topic)
            self.assertIn(f"`{model}`", readme)
        for word in ("ssh", "k9s", "install", "mcp", "ui", "creds", "use", "enable", "disable", "model"):
            self.assertIn(word, topic)
        for value, allowed in (("1", True), ("true", True), ("yes", True), ("on", True), ("0", False), ("no", False)):
            with mock.patch.dict(os.environ, {"CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE": value}):
                self.assertEqual(builtin_agent._allow_unattended(), allowed, value)
        self.assertIn("`1`, `true`, `yes` or `on`", readme)
        self.assertIn("1, true, yes or on", topic)
        self.assertNotIn("0600 session file", readme)
        self.assertNotIn("parked in a 0600 session file", _flat(h.TOPICS["security"]))


class Catalog(unittest.TestCase):
    def test_platform_page_lists_every_group_member(self):
        page = h.COMMANDS["platform"]
        groups = page.split("GROUPS")[1].split("GATEWAYS AND UIS")[0]
        for name, spec in pl.CATALOG.items():
            if spec.get("hidden") or name in ("metallb",):
                continue
            self.assertRegex(groups, r"(?<![\w-])%s(?![\w-])" % re.escape(name), name)
        flat = _flat(page)
        for stale in ("llm-d", "(kgateway)", "Harbor -> Trivy"):
            self.assertNotIn(stale, flat)
        for part in ("GITLAB_RUNNER_TOKEN", "ANTHROPIC_API_KEY or OPENAI_API_KEY", "Loki 3", "Open WebUI -> Ollama",
                     "kagent -> kmcp", "asks before installing it", "never removed implicitly", "pinned"):
            self.assertIn(part, flat, part)

    def test_readme_and_skills_follow_the_catalog(self):
        readme = _flat(_read(MANUAL))
        skill = _flat(_read("skills/cloudseed-platform/SKILL.md"))
        for text in (readme, skill):
            self.assertNotIn("llm-d", text)
            self.assertIn("Alloy".lower(), text.lower())
            self.assertIn("GITLAB_RUNNER_TOKEN", text)
        self.assertIn("Prometheus/cert-manager/Ollama/kmcp", skill)
        self.assertNotIn("Trivy disabled", skill)
        self.assertIn("pinned per cloudseed release", readme)


class Readme(unittest.TestCase):
    def test_readme_matches_the_code(self):
        readme = _flat(_read(MANUAL))
        for part in ("Python 3.9+", "--alias NAME | --no-alias] [--force] [--uninstall]", "make uninstall",
                     "`cs undo --global`", "`--id ID`", "`--drop`", "five slots of their own",
                     "~/.cloudseed/logs/<ts>-<cmd>-crash.log", "CLOUDSEED_DEBUG=1", "CLOUDSEED_NONINTERACTIVE=1",
                     "container-linux-<arch>", "kubectl + helm", "`az` must be installed", "SHA256-verified",
                     "never adopted", "CLOUDSEED_ADOPT=1", "enable_aws_config=false", "experimental",
                     "raw tool output", "Debian 12 GCP bastion have no STIG content", "exits 1 when a verdict is FAIL",
                     "random file", "`local` volumes", "INCONCLUSIVE", "no customer KMS key", "AzureLoadBalancer probes",
                     "five Activity Log diagnostic settings", "IAM password policy and the AWS Config service-linked role",
                     "only cloudseed's own files", "no cookie", "X-CS-Token", "Any stack variable except those cloudseed",
                     "`--var name=null` drops a saved override", "node add|list|remove|scale"):
            self.assertIn(part, readme, part)
        for stale in ("never deletes anything", "ECDSA P-384", "installed on demand", "keeps a final copy of both"):
            self.assertNotIn(stale, readme)


class Explain(unittest.TestCase):
    def test_reconcile_describes_the_ownership_rules(self):
        f = explain.FEATURES["reconcile"]
        text = _flat(f["what"] + " " + " ".join(f["controls"]))
        self.assertNotIn("never deletes anything", text)
        self.assertNotIn("known account singletons (GuardDuty detector, EKS OIDC provider) are looked up and imported", text)
        for part in ("never adopted", "CLOUDSEED_ADOPT=1", "approved again", "exactly that planfile", "cs destroy"):
            self.assertIn(part, text, part)

    def test_other_features(self):
        ui = " ".join(explain.FEATURES["ui"]["controls"])
        self.assertNotIn("link/cookie", ui)
        self.assertIn("frame-ancestors 'none'", ui)
        kube = explain.FEATURES["kubernetes"]["what"]
        self.assertIn("platform-managed encryption at rest on GKE/AKS", kube)
        undo = " ".join([explain.FEATURES["undo"]["what"]] + explain.FEATURES["undo"]["state"])
        self.assertNotIn("~/.cloudseed/logs/purged/<env>/ (destroy --purge snapshot)", undo)
        self.assertIn("~/.cloudseed/undo/", undo)
        self.assertIn("crash.log", explain.FEATURES["audit"]["what"])
        self.assertIn("raw", " ".join(explain.FEATURES["scan"]["state"]))
        self.assertIn("never injected is an ERROR", explain.FEATURES["chaos"]["what"])
        self.assertIn("[name] [<cloud> --env NAME]", explain.FEATURES["dr"]["commands"][0])
        self.assertIn("Windows: experimental", explain.FEATURES["vmware"]["what"])
        self.assertIn("unix socket", " ".join(explain.FEATURES["agentic"]["controls"]))

    def test_what_paragraphs_wrap_to_the_width(self):
        with mock.patch.dict(os.environ, {"COLUMNS": "60"}):
            out = re.sub(r"\x1b\[[0-9;]*m", "", explain.page("reconcile"))
        body = out.split("Implemented in")[0]
        self.assertTrue(all(len(line) <= 60 for line in body.splitlines()), body)


class Skills(unittest.TestCase):
    def test_destroy_skill(self):
        s = _flat(_read("skills/cloudseed-destroy/SKILL.md"))
        for part in ("~/.cloudseed/logs/purged/<cloud>-<env>/", "~/.cloudseed/undo/", "only cloudseed's own files",
                     "Karpenter NodePools", "must be reachable", "EBS encryption by default",
                     "Defender plans and the Ubuntu Pro FIPS image terms stay", "exit code 3"):
            self.assertIn(part, s, part)
        self.assertNotIn("reset to defaults", s)

    def test_vmware_skill_limits_match_the_adapter(self):
        s = _flat(_read("skills/cloudseed-vmware/SKILL.md"))
        wl, cp, wk = vmwaremod.WORKLOAD_BASE, vmwaremod.CONTROL_PLANE_BASE, vmwaremod.WORKER_BASE
        # workers stop below MetalLB's LoadBalancer pool (.100-.127 on a /24), which sits just below the DHCP pool
        top, max_cp = vmwaremod.MAX_STATIC_HOST - vmwaremod.LB_POOL_SIZE, vmwaremod.MAX_CONTROL_PLANES
        self.assertIn(f"workloads `.{wl}+` (at most {cp - wl} when Kubernetes is on", s)
        self.assertIn(f"control planes `.{cp}-.{cp + max_cp - 1}` (1-{max_cp})", s)
        self.assertIn(f"workers `.{wk}-.{top}` (at most {top - wk + 1} on a /24", s)
        for part in ("sudo vmrest", "VMREST_USER", "experimental", "grows the disk in place", "rebuilds the VM",
                     "relative to the working directory", "leaves the workers alone", "`.100-.127`"):
            self.assertIn(part, s, part)
        vm_help = _flat(h.TOPICS["vmware"])
        self.assertIn(f"workers .{wk}-.{top} (at most {top - wk + 1} on a /24)", vm_help)
        self.assertIn("experimental", vm_help)

    def test_cloud_skills(self):
        aws = _flat(_read("skills/cloudseed-aws/SKILL.md"))
        self.assertNotIn("adopts an existing detector", aws)
        self.assertNotIn("(using the CMK)", aws)
        for part in ("`aws/ebs` key", "AWS Config", "external_secrets_prefixes", "bastion role only", "az_count >= 2",
                     "raises the max automatically"):
            self.assertIn(part, aws, part)
        gcp = _read("skills/cloudseed-gcp/SKILL.md")
        self.assertIn("container", gcp.split("\n")[9])
        flat = _flat(gcp)
        for part in ("cloudresourcemanager", "iamcredentials", "secretmanager", "<region>-b", "Service Usage",
                     "roles/compute.osAdminLogin", "roles/compute.osLoginExternalUser", "gke-gcloud-auth-plugin",
                     "Google-managed keys"):
            self.assertIn(part, flat, part)
        azure = _flat(_read("skills/cloudseed-azure/SKILL.md"))
        for part in ("(210)", "(220)", "(300)", "systemtmp", "4.65", "control-plane logs", "raises the max"):
            self.assertIn(part, azure, part)
        self.assertNotIn("sets it back to Free", azure)

    def test_driver_and_managed_skills(self):
        main = _flat(_read("skills/cloudseed/SKILL.md"))
        self.assertIn("BEFORE the command", main)
        for f in ("credentials.json", "gcp-credentials.json", "managed.json", "mcp/token", "ui/token", "platform/secrets.json"):
            self.assertIn(f, main, f)
        for part in ("cloudseed undo --global", "--drop", "--forget", "creates nothing"):
            self.assertIn(part, main, part)
        man = _flat(_read("skills/cloudseed-managed/SKILL.md"))
        for part in ("saved `default` one", "cloudseed databricks -- clusters list --profile X", "--config-file",
                     "`--env NAME`"):
            self.assertIn(part, man, part)


class WideTables(unittest.TestCase):
    @staticmethod
    def _rows(out: str) -> list[str]:
        return [line for line in out.splitlines() if line.startswith("  ") and not line.startswith("    ")]

    def test_a_wide_term_table_is_stacked_throughout(self):
        out = re.sub(r"\x1b\[[0-9;]*m", "", _render("troubleshooting", columns=80))
        rows = self._rows(out)[1:]            # the header, then one line per term
        self.assertTrue(rows)
        for line in rows:                     # never "term   description" on one line at this width
            self.assertIsNone(re.search(r"\S {2,}\S", line.strip()), line)
        wide = re.sub(r"\x1b\[[0-9;]*m", "", _render("troubleshooting", columns=160))
        self.assertIn("Second env in the same AWS account      --var enable_account_baseline=false", wide)

    def test_narrow_term_tables_keep_their_rows_inline(self):
        out = re.sub(r"\x1b\[[0-9;]*m", "", _render("chaos", columns=80))
        self.assertRegex(out, r"\n  basic    pod-kill, pod-failure, container-kill")
        self.assertEqual(h._stacked_rows(["  a    b", "  c    d"], None), set())


if __name__ == "__main__":
    unittest.main()
