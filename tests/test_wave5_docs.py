"""Wave-5 (final) docs regression tests: help / explain / manual (docs/guides/manual.md) / skills text that must follow the code the wave-4
groups changed - the VMware address plan (workers below MetalLB's pool, pod/Service range refusal, public ranges and
DNS), the RKE2 CIS profile's namespace labels and exemptions, `doctor <cloud>` exiting 1 when not ready, the human-only
policy every agent session shares (read-only forms), the redaction of databricks/snowflake and what agent sessions
refuse, VPN certificate expiry, MCP --no-auth/--no-service and transport-keeping connects, `cs env` ids, undo limits,
GuardDuty/Access Analyzer left alone automatically, Azure --region checks, GCP OS Login expiry, DR/scan details, the
provisioning re-run command and kubectl on the bastion."""

from __future__ import annotations

import argparse
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
if not os.environ.get("CLOUDSEED_HOME"):      # (no temp directory is made when the suite already sets one)
    os.environ["CLOUDSEED_HOME"] = tempfile.mkdtemp(prefix="cs-w5docs-")

from cloudseed import builtin_agent, cli, deps, dr, explain, help as h, managed, provision, scan, services, undo  # noqa: E402
from cloudseed import platform as pl  # noqa: E402
from cloudseed.clouds import azure as azmod, gcp as gcpmod, vmware as vmmod  # noqa: E402

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _read(rel: str) -> str:
    return (ROOT / rel).read_text()


def _flat(text: str) -> str:
    return " ".join(text.split())


def _skill(name: str) -> str:
    return _flat(_read(f"skills/{name}/SKILL.md"))


MANUAL_TEXT = _flat(_read(MANUAL))


def _render(topic, columns: int) -> str:
    buf = io.StringIO()
    with mock.patch.dict(os.environ, {"COLUMNS": str(columns)}), contextlib.redirect_stdout(buf):
        h.print_page(topic, None)
    return ANSI.sub("", buf.getvalue())


def _capture(fn, *args) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = fn(*args)
    return rc, ANSI.sub("", out.getvalue())


# ---------------------------------------------------------------- VMware address plan

class VmwareAddressPlan(unittest.TestCase):
    def test_worker_range_follows_the_adapter(self):
        wk = vmmod.WORKER_BASE
        top = vmmod.MAX_STATIC_HOST - vmmod.LB_POOL_SIZE          # the last worker address below MetalLB's pool
        pool = f".{top + 1}-.{vmmod.MAX_STATIC_HOST}"
        self.assertEqual((top, top - wk + 1, pool), (99, 60, ".100-.127"))
        texts = {"help vmware": _flat(h.TOPICS["vmware"]), "vmware skill": _skill("cloudseed-vmware"), "manual": MANUAL_TEXT,
                 "explain vmware": _flat(explain.FEATURES["vmware"]["what"])}
        for name, text in texts.items():
            self.assertRegex(text, r"workers `?\.%d-\.%d`?" % (wk, top), name)
            self.assertIn(pool, text, name)
            self.assertNotIn(f".{wk}-.{vmmod.MAX_STATIC_HOST}", text, name)       # the old plan (workers up to .127)
            self.assertNotIn("at most 88", text, name)
        for name in ("help vmware", "vmware skill", "manual"):
            self.assertIn(f"at most {top - wk + 1} on a /24", texts[name], name)
            self.assertIn("warned, not refused" if name != "vmware skill" else "only warned", texts[name], name)

    def test_pod_and_service_ranges_are_documented(self):
        ranges = [r for rows in provision.LOCAL_K8S_RANGES.values() for _, r in rows]
        self.assertEqual(len(ranges), 4)
        for name, text in (("help vmware", _flat(h.TOPICS["vmware"])), ("vmware skill", _skill("cloudseed-vmware")),
                           ("manual", MANUAL_TEXT)):
            for rng in ranges:
                self.assertIn(rng, text, (name, rng))
            self.assertIn("only warns for a cluster that already runs there", text, name)
        # the rule the docs describe: refused for a new environment, warned for a cluster that exists
        self.assertTrue(provision.local_k8s_range_problems("10.42.0.0/24", "rke2"))
        self.assertFalse(provision.local_k8s_range_problems("10.42.0.0/24", "kubeadm"))

    def test_public_range_note_names_the_guest_dns(self):
        for name, text in (("help vmware", _flat(h.TOPICS["vmware"])), ("vmware skill", _skill("cloudseed-vmware")),
                           ("manual", MANUAL_TEXT)):
            for dns in vmmod.GUEST_DNS:
                self.assertIn(dns, text, (name, dns))
        import ipaddress
        msg = vmmod.VMware().public_range_problem(ipaddress.ip_network("1.1.1.0/24"))
        self.assertIn("DNS", msg)

    def test_node_add_refusal_is_documented(self):
        self.assertIn("MetalLB's LoadBalancer pool", _flat(h.COMMANDS["node"]))
        self.assertIn("LoadBalancer pool is refused", MANUAL_TEXT)
        self.assertIn("refuses a node whose address would fall in the pool", _skill("cloudseed-vmware"))


# ---------------------------------------------------------------- RKE2 CIS profile: exemptions and labels

class CisProfileDocs(unittest.TestCase):
    PRIVILEGED = ("velero", "local-path-provisioner", "metallb", "kube-prometheus-stack", "falco", "neuvector", "kured",
                  "chaos-mesh", "kubescape-operator", "trivy-operator")
    BASELINE = ("minio", "loki", "alloy")

    def test_named_levels_match_the_catalog(self):
        def levels(item):
            ps = pl.CATALOG[item].get("pod_security")
            return set(ps.values()) if isinstance(ps, dict) else {ps}
        for item in self.PRIVILEGED:
            self.assertIn("privileged", levels(item), item)
        for item in self.BASELINE:
            self.assertEqual(levels(item), {"baseline"}, item)
        for item in ("istio-cni", "ztunnel"):                 # "istio ambient"
            self.assertIn("privileged", levels(item), item)

    def test_every_text_names_the_labels_and_info(self):
        texts = {"help k8s": _flat(h.COMMANDS["k8s"]), "help platform": _flat(h.COMMANDS["platform"]),
                 "manual": MANUAL_TEXT, "vmware skill": _skill("cloudseed-vmware"), "platform skill": _skill("cloudseed-platform")}
        for name, text in texts.items():
            self.assertIn("platform info <item>", text, name)
            for item in self.PRIVILEGED + self.BASELINE:
                self.assertIn(item, text, (name, item))
        self.assertIn("platform info <item>", _flat(h.TOPICS["vmware"]))

    def test_exempt_namespaces_match_the_rke2_role(self):
        role = _read("ansible/roles/rke2/tasks/main.yml")
        m = re.search(r"rke2_psa_cloudseed_namespaces: \[([^\]]*)\]", role)
        self.assertIsNotNone(m)
        exempt = [n.strip() for n in m.group(1).split(",")]
        self.assertEqual(exempt, ["cloudseed-scan", "velero", "local-path-storage", "minio", "chaos-mesh"])
        for name, text in (("help k8s", _flat(h.COMMANDS["k8s"])), ("help vmware", _flat(h.TOPICS["vmware"])),
                           ("manual", MANUAL_TEXT), ("vmware skill", _skill("cloudseed-vmware"))):
            for ns in exempt:
                self.assertIn(ns, text, (name, ns))

    def test_set_mode_is_only_istios_when_istio_is_asked_for(self):
        self.assertTrue(pl.meta_mode_applies(["kiali"]))
        self.assertFalse(pl.meta_mode_applies(["minio"]))
        for name, text in (("help platform", _flat(h.COMMANDS["platform"])), ("manual", MANUAL_TEXT),
                           ("platform skill", _skill("cloudseed-platform"))):
            self.assertIn("install minio --set mode=distributed", text, name)
            self.assertIn("only when istio is part of the request", text, name)


# ---------------------------------------------------------------- doctor exit code

class DoctorExitCode(unittest.TestCase):
    def run_doctor(self, cloud, rows, live=None, warnings=()):
        from cloudseed import clouds
        with mock.patch.object(deps, "status", return_value=rows), \
                mock.patch.object(deps, "live_credential_check", return_value=live), \
                mock.patch.object(type(clouds.get(cloud or "aws")), "credential_warnings", lambda self, cfg: list(warnings)):
            return _capture(cli.cmd_doctor, argparse.Namespace(cloud=cloud), {})

    @staticmethod
    def row(tool, path="/x", required=True):
        return {"tool": tool, "path": path, "required": required, "desc": "d", "version": "1.0", "outdated": False}

    def test_a_named_cloud_that_is_not_ready_exits_1(self):
        rc, out = self.run_doctor("aws", [self.row("terraform", path=None)], live=(True, "ok"))
        self.assertEqual(rc, 1, out)
        self.assertIn("is not ready: terraform is missing", out)
        rc, out = self.run_doctor("aws", [self.row("terraform")], live=(False, "expired"))
        self.assertEqual(rc, 1, out)
        rc, out = self.run_doctor("aws", [self.row("terraform")], warnings=["No AWS credentials detected."])
        self.assertEqual(rc, 1, out)

    def test_a_ready_cloud_and_the_overview_exit_0(self):
        rc, out = self.run_doctor("aws", [self.row("terraform"), self.row("aws", required=False, path=None)],
                                  live=(True, "ok"))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("not ready", out)
        rc, out = self.run_doctor(None, [self.row("terraform", path=None)], live=(False, "expired"))
        self.assertEqual(rc, 0, out)                     # the overview never fails
        self.assertNotIn("not ready", out)

    def test_documented(self):
        page = _flat(h.COMMANDS["doctor"])
        self.assertIn("exits 1", page)
        self.assertIn("always exits 0", page)
        self.assertNotIn("the exit code stays 0", page)
        self.assertIn("Common tools", page)
        self.assertIn("exits 1 when that cloud is not ready", MANUAL_TEXT)
        self.assertNotIn("test_cli_e2e", _read("cloudseed/cli.py").split("def cmd_doctor", 1)[1].split("\ndef ", 1)[0])


# ---------------------------------------------------------------- agent sessions

class AgentPolicyDocs(unittest.TestCase):
    READ_FORMS = ("creds list", "use list", "install list", "ui status|logs", "mcp status|guide|tools|config|test|logs",
                  "deps status", "skill list|show")

    def test_read_forms_follow_the_cli_gate(self):
        forms = cli._AGENT_READ_FORMS
        self.assertEqual(forms["ui"], ("status", "logs"))
        self.assertEqual(forms["deps"], ("status",))
        self.assertEqual(forms["skill"], ("list", "show"))
        self.assertTrue(set(("status", "guide", "tools", "config", "test", "logs")) <= set(forms["mcp"]))
        # model without an id and `use list` are read-only too
        self.assertIsNone(cli.human_only_reason(argparse.Namespace(cmd="model", model=None, forget=None)))
        self.assertIsNone(cli.human_only_reason(argparse.Namespace(cmd="use", agent="list")))
        self.assertIsNotNone(cli.human_only_reason(argparse.Namespace(cmd="use", agent="codex")))

    def test_every_text_lists_the_read_forms(self):
        texts = {"manual": MANUAL_TEXT, "help agentic": _flat(h.TOPICS["agentic"]), "help security": _flat(h.TOPICS["security"]),
                 "core skill": _skill("cloudseed")}
        for name, text in texts.items():
            for form in self.READ_FORMS:
                self.assertIn(form.replace("`", ""), text.replace("`", ""), (name, form))
        for name in ("manual", "help agentic"):
            self.assertIn("mcp serve", texts[name], name)
        # the built-in agent's own prompt says the same (its words for `creds list` are `creds (list)`)
        for form in self.READ_FORMS[1:]:
            self.assertIn(form, _flat(builtin_agent._HUMAN_ONLY_TEXT), form)
        # the old whole-command lists are gone
        self.assertNotIn("Human-only commands are refused: ssh, k9s, install,", texts["help agentic"])
        self.assertNotIn("human-only ones (ssh, install, creds, mcp, ui, use, enable ...)", texts["help security"])
        self.assertNotIn("`cloudseed use <agent>`, `cloudseed model [id]`", texts["core skill"])

    def test_core_skill_marks_the_read_forms_usable(self):
        skill = _read("skills/cloudseed/SKILL.md")
        agents_row = next(line for line in skill.splitlines() if line.startswith("| Agents |"))
        self.assertIn("`cloudseed model` (shows the models)", agents_row)
        self.assertIn("`cloudseed model <id>`", agents_row)
        ui_row = next(line for line in skill.splitlines() if line.startswith("| Web console |"))
        self.assertIn("`cloudseed ui status\\|logs` (read-only)", ui_row)
        mcp_row = next(line for line in skill.splitlines() if line.startswith("| MCP server |"))
        self.assertIn("`cloudseed mcp status\\|guide\\|tools\\|config\\|test\\|logs` (read-only)", mcp_row)

    def test_terminal_refusals_are_documented(self):
        self.assertIsNotNone(managed.needs_terminal("databricks", ["auth", "login"], piped=False))
        self.assertIsNotNone(managed.needs_terminal("snowflake", ["sql"], piped=False))
        self.assertIsNone(managed.needs_terminal("snowflake", ["sql", "-q", "select 1"], piped=False))
        for name, text in (("manual", MANUAL_TEXT), ("help security", _flat(h.TOPICS["security"])),
                           ("help managed", _flat(h.COMMANDS["managed"])), ("managed skill", _skill("cloudseed-managed")),
                           ("explain agentic", _flat(" ".join(explain.FEATURES["agentic"]["controls"])))):
            self.assertIn("databricks auth login", text, name)
            self.assertIn("snow sql", text, name)
            self.assertNotIn("not redacted yet", text, name)
        for name, text in (("help managed", _flat(h.COMMANDS["managed"])), ("managed skill", _skill("cloudseed-managed"))):
            self.assertIn("exit code 2", text, name)

    def test_streams_and_ttl(self):
        sec = _flat(h.TOPICS["security"])
        for part in ("logs -f", "port-forward", "proxy", "--tail", "kubectl wait --timeout", "30d", "720h"):
            self.assertIn(part, sec, part)
        self.assertIn("30d is taken as 720h", _flat(h.COMMANDS["dr"]))

    def test_agentic_examples_fit_60_columns(self):
        out = _render("agentic", 60)
        wide = [line for line in out.splitlines() if len(line) > 60]
        self.assertEqual(wide, [])


# ---------------------------------------------------------------- VPN, MCP, env

class ServiceDocs(unittest.TestCase):
    def test_vpn_certificates(self):
        defaults = _read("ansible/roles/openvpn/defaults/main.yml")
        days = re.search(r'EASYRSA_CERT_EXPIRE: "(\d+)"', defaults).group(1)
        page = _flat(h.COMMANDS["vpn"])
        self.assertIn(f"{days} days", page)
        self.assertIn(f"within {services.RENEW_DAYS} days", page)
        self.assertIn(services._renew_server_hint("<cloud>", "NAME"), page)
        self.assertIn(services._renew_client_hint("<cloud>", "NAME", "<name>"), page)
        self.assertIn("sudo -n", page)
        self.assertIn("users lists the client certificates with their expiry", page)
        self.assertIn(f"live {days} days", MANUAL_TEXT)
        self.assertEqual(services._sudo()[:1], ["sudo"] if os.geteuid() != 0 else [])

    def test_vpn_on_vmware(self):
        self.assertIn("without Terraform or vmrest", _flat(h.COMMANDS["vpn"]))

    def test_mcp_auth_service_and_connect(self):
        page = _flat(h.COMMANDS["mcp"])
        for part in ("--no-auth", "--no-service", "--rotate-token requires a token again", "keeps its transport",
                     "refuse while MCP is disabled", "new ones: http when deployed", "unless the server was deployed with --no-auth"):
            self.assertIn(part, page, part)
        self.assertNotIn("then: cs mcp connect all", page)
        self.assertNotIn("(http when deployed, else stdio)", page)
        self.assertIn("unless deployed with `--no-auth`", MANUAL_TEXT)
        self.assertIn("keeps its transport", MANUAL_TEXT)
        self.assertIn("unless deployed with --no-auth", " ".join(explain.FEATURES["mcp"]["controls"]))
        # the behaviour behind the words
        src = _read("cloudseed/cli.py")
        self.assertIn('(cur if cur in c["transports"] else None)', src)

    def test_env_page(self):
        page = _flat(h.COMMANDS["env"])
        for part in ("use <id | a name only one environment has>", "takes no id", "only the current one's",
                     "exit code 2"):
            self.assertIn(part, page, part)
        out = _render("env", 60)
        self.assertTrue(all(len(line) <= 60 for line in out.splitlines()), out)
        self.assertIn("cs env use prod", MANUAL_TEXT)


# ---------------------------------------------------------------- undo limits

class UndoDocs(unittest.TestCase):
    WORDS = {5: "five", 15: "fifteen"}

    def test_limits_follow_the_journal(self):
        total, per_kind, light = undo.KEEP_TOTAL, undo.KEEP, undo.KEEP_LIGHT
        self.assertEqual((total, per_kind, light), (15, 5, 5))
        n = lambda v: r"(?:%d|%s)" % (v, self.WORDS[v])   # noqa: E731 - a number in digits or in words
        texts = {"help undo": _flat(h.COMMANDS["undo"]), "overview": _flat(h.OVERVIEW), "manual": MANUAL_TEXT,
                 "explain undo": _flat(explain.FEATURES["undo"]["what"] + " " + " ".join(explain.FEATURES["undo"]["controls"])),
                 "core skill": _skill("cloudseed")}
        for name, text in texts.items():
            self.assertRegex(text.lower(), r"\b%s\b[^.]*\b%s of one kind" % (n(total), n(per_kind)), name)
            self.assertNotRegex(text.lower(), r"five (real )?undo points|five deep|last five state-changing", name)
        for name, text in (("help destroy", _flat(h.COMMANDS["destroy"])), ("help creds", _flat(h.COMMANDS["creds"])),
                           ("destroy skill", _skill("cloudseed-destroy")), ("manual", MANUAL_TEXT)):
            self.assertNotIn("five newer", text, name)

    def test_config_and_velero_undo_details(self):
        page = _flat(h.COMMANDS["undo"])
        for part in ("nodes it deletes are drained first", "only dropped from the state",
                     "Velero's bucket is never removed", "objects and namespaces the change created are deleted first",
                     "velero and minio namespaces and pod volumes are left out"):
            self.assertIn(part, page, part)
        self.assertEqual(undo.VELERO_POINT_EXCLUDED, ("velero", "minio"))
        for part in ("drained and taken out of the cluster", "Velero's bucket is never removed by an undo",
                     "the velero and minio namespaces and pod volumes are left out"):
            self.assertIn(part, MANUAL_TEXT, part)


# ---------------------------------------------------------------- clouds

class CloudDocs(unittest.TestCase):
    def test_guardduty_is_left_alone_while_only_on_by_default(self):
        from cloudseed import reconcile
        self.assertEqual(reconcile.DISABLE_VAR["aws_guardduty_detector"], "enable_guardduty")
        self.assertEqual(reconcile.DISABLE_VAR["aws_accessanalyzer_analyzer"], "enable_access_analyzer")
        texts = {"aws skill": _skill("cloudseed-aws"), "manual": MANUAL_TEXT, "help setup": _flat(h.COMMANDS["setup"]),
                 "help security": _flat(h.TOPICS["security"]), "help troubleshooting": _flat(h.TOPICS["troubleshooting"]),
                 "explain reconcile": _flat(explain.FEATURES["reconcile"]["what"]),
                 "explain baseline": _flat(explain.FEATURES["security-baseline"]["what"])}
        for name, text in texts.items():
            self.assertIn("never adopted" if "setup" not in name else "left alone", text, name)
            self.assertRegex(text, re.compile(r"only (has (it )?)?on by default", re.I), name)
            self.assertIn("explicitly", text, name)
        self.assertNotIn("when a detector (or Security Hub) already exists, setup stops", texts["aws skill"])

    def test_azure_region_checks(self):
        with mock.patch.dict(os.environ, {"ARM_ENVIRONMENT": "usgovernment"}):
            self.assertEqual(azmod.Azure().default_region, "usgovvirginia")
        with mock.patch.dict(os.environ, {"ARM_ENVIRONMENT": "china"}):
            self.assertEqual(azmod.Azure().default_region, "chinanorth3")
        self.assertTrue(azmod.location_problem("usgovvirginia", {}))
        for name, text in (("azure skill", _skill("cloudseed-azure")), ("help setup", _flat(h.COMMANDS["setup"])),
                           ("manual", MANUAL_TEXT)):
            for part in ("ARM_ENVIRONMENT=usgovernment", "ARM_ENVIRONMENT=china", "usgovvirginia", "chinanorth3"):
                self.assertIn(part, text, (name, part))
        skill = _skill("cloudseed-azure")
        self.assertIn("`>= 4.9`", skill)
        self.assertIn("case-insensitive", skill)
        self.assertIn("`bastion_instance_id`", skill)
        self.assertIn("`vpn_instance_id`", skill)

    def test_gcp_os_login_expiry_and_answers(self):
        self.assertEqual(gcpmod.GCP._RENEW_WITHIN, 3600)                 # "within the hour"
        skill = _skill("cloudseed-gcp")
        for part in ("expires within the hour", "registered again without one", "only warned about",
                     "openvpn | tailscale, any case", "at least 1"):
            self.assertIn(part, skill, part)
        self.assertNotIn("removes the audit config (unless", skill)
        q = next(q for q in gcpmod.GCP.questions if q.key == "kubernetes_node_count")
        self.assertEqual(q.minimum, 1)
        self.assertIsNone(gcpmod._check_vpn_type("Tailscale"))

    def test_gcp_fips_custom_image(self):
        self.assertIn("custom bastion_image", _flat(h.TOPICS["fips"]))
        self.assertIn("RHEL-family", _flat(h.TOPICS["fips"]))

    def test_explain_fips_names_the_real_helpers(self):
        files = " ".join(explain.FEATURES["fips"]["files"])
        self.assertIn("_verify_fips (provision.await_fips)", files)
        self.assertTrue(hasattr(cli, "_verify_fips") and hasattr(provision, "await_fips"))


# ---------------------------------------------------------------- setup, provision, dr, scan

class CommandDocs(unittest.TestCase):
    def test_setup_preview_and_changes(self):
        page = _flat(h.COMMANDS["setup"])
        self.assertIn("--preview", page)
        self.assertIn('getattr(args, "preview", False)', _read("cloudseed/cli.py"))
        for part in ("only dropped from the state", "drained and taken out of the cluster first",
                     "China (cn-*)"):
            self.assertIn(part, page, part)
        self.assertIn("[--plan-only | --preview]", MANUAL_TEXT)

    def test_provision_rerun_and_bastion_kubectl(self):
        from types import SimpleNamespace
        cmd = provision.rerun_command(SimpleNamespace(key="aws"), SimpleNamespace(name="dev"), "vpn", harden=False,
                                      firewall=False)
        self.assertEqual(cmd, "cloudseed provision aws --env dev --host vpn --no-harden --no-firewall")
        page = _flat(h.COMMANDS["provision"])
        for part in ("the whole command to re-run", "--no-tools", "--sync-only", "aws eks update-kubeconfig",
                     "AWS_USE_FIPS_ENDPOINT=true", "sha256-verified"):
            self.assertIn(part, page, part)
        tools = _read("ansible/roles/tools/tasks/main.yml")
        self.assertIn("kubectl.sha256", tools)
        self.assertIn("AWS_USE_FIPS_ENDPOINT=true", tools)
        for text in (MANUAL_TEXT, _skill("cloudseed-aws")):
            self.assertIn("aws eks update-kubeconfig --name <cluster> --region <region>", text.replace("`", ""))

    def test_dr_keep(self):
        self.assertIn("30 days", (dr._kept_hint.__doc__ or ""))
        for name, text in (("help dr", _flat(h.COMMANDS["dr"])), ("manual", MANUAL_TEXT),
                           ("platform skill", _skill("cloudseed-platform"))):
            self.assertIn("30", text, name)
            self.assertIn("--keep", text, name)
        self.assertIn("Velero keeps it for its default 30 days", _flat(h.COMMANDS["dr"]))

    def test_scan_details(self):
        self.assertIn("EKS 4.5.2", _read("cloudseed/scan.py"))
        self.assertTrue(callable(scan._default_ns_scope))
        page = _flat(h.COMMANDS["scan"])
        for part in ("EKS 4.5.2", "GKE 4.6.4", "AKS 4.6.3", "kubernetes_cis_profile=true", "--host k8s",
                     "crypto-restricted", "AWS_USE_FIPS_ENDPOINT", "s3-fips", "EC2NodeClass", "-fips"):
            self.assertIn(part, page, part)
        for part in ("EKS 4.5.2", "s3-fips", "kubernetes_cis_profile=true"):
            self.assertIn(part, MANUAL_TEXT, part)
        crypto = [i for i, spec in pl.CATALOG.items() if spec.get("fips") == "crypto-restricted"]
        self.assertEqual(sorted(crypto), sorted(["cert-manager", "sealed-secrets", "velero", "cloudnative-pg"]))

    def test_pages_fit_narrow_terminals(self):
        for topic in ("setup", "provision", "k8s", "vpn", "env", "node", "platform", "doctor", "mcp", "undo", "dr",
                      "scan", "managed", "security", "agentic", "vmware", "fips", "troubleshooting"):
            for cols in (60, 80):
                out = _render(topic, cols)
                wide = [line for line in out.splitlines() if len(line) > cols]
                self.assertEqual(wide, [], (topic, cols))


if __name__ == "__main__":
    unittest.main()
