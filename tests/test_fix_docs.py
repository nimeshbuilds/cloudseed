"""Regression tests for the docs / help / explain fixes: help pages, rendering, suggestions, skills and README."""

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
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-fixdocs-"))

from cloudseed import cli, clouds, explain, help as h, mcp, paths, platform as pl, skills, ui  # noqa: E402

COMMON = {"-h", "--help", "--runtime", "--engine", "-y", "--yes", "-e", "--env"}


def _parse_error(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf), mock.patch.object(sys, "argv", ["cloudseed", *argv]):
        try:
            cli.build_parser().parse_args(argv)
        except SystemExit as e:
            return e.code, buf.getvalue()
    return 0, buf.getvalue()


def _render(topic, cloud=None, columns=None) -> str:
    env = {"COLUMNS": str(columns)} if columns else {}
    buf = io.StringIO()
    with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(buf):
        if columns is None:
            os.environ.pop("COLUMNS", None)
        h.print_page(topic, cloud)
    return buf.getvalue()


def _did_you_mean(text: str) -> list[str]:
    m = re.search(r"did you mean (.*)\?", text)
    return [x.strip() for x in m.group(1).split(",")] if m else []


class SkillFrontmatter(unittest.TestCase):
    def test_every_skill_has_valid_frontmatter(self):
        found = sorted(p.parent.name for p in (ROOT / "skills").glob("*/SKILL.md"))
        self.assertGreaterEqual(len(found), 10)
        for p in (ROOT / "skills").glob("*/SKILL.md"):
            text = p.read_text()
            self.assertTrue(text.startswith("---\n"), p)
            fm = text.split("---", 2)[1]
            keys = {}
            for line in fm.strip().splitlines():
                m = re.match(r"^([A-Za-z0-9_-]+):[ \t]+(.+)$", line)
                self.assertIsNotNone(m, f"{p}: {line!r}")
                key, value = m.group(1), m.group(2).strip()
                keys[key] = value
                quoted = len(value) > 1 and value[0] in "\"'" and value[-1] == value[0]
                if not quoted:   # a plain YAML scalar: ': ' starts a mapping, ' #' a comment, some leaders are syntax
                    self.assertNotIn(": ", value, f"{p} {key}: quote it or drop the ': '")
                    self.assertNotIn(" #", value, p)
                    self.assertNotIn(value[0], "[{&*!|>%@`", p)
            self.assertEqual(keys.get("name"), p.parent.name)
            self.assertTrue(keys.get("description"))

    def test_skills_do_not_carry_stale_claims(self):
        vm = (ROOT / "skills/cloudseed-vmware/SKILL.md").read_text()
        self.assertNotIn("no DHCP) created through vmrest", vm)
        self.assertNotIn("~/.cloudseed/vms", vm)
        self.assertIn("<workdir>/vms", vm)
        for out in ("kubernetes_endpoint", "fips_mode", "kubernetes_control_plane_ips"):
            self.assertIn(out, vm)
        destroy = (ROOT / "skills/cloudseed-destroy/SKILL.md").read_text()
        self.assertNotIn("security_baseline[0]`,", destroy)
        self.assertIn("module.stack.module.workloads", destroy)
        self.assertIn("container", (ROOT / "skills/cloudseed-gcp/SKILL.md").read_text().split("\n")[9])
        managed = (ROOT / "skills/cloudseed-managed/SKILL.md").read_text()
        self.assertNotIn("connect --host", managed)
        self.assertNotIn("dev CA issuer", (ROOT / "skills/cloudseed-platform/SKILL.md").read_text())
        main = (ROOT / "skills/cloudseed/SKILL.md").read_text()
        self.assertNotIn("test [<cloud> --env dev]", main)

    def test_cloud_skills_list_every_variable_and_output(self):
        skip = {"name", "environment", "allowed_ssh_cidrs", "ssh_public_key", "project_id", "region", "location",
                "base_disk", "guest_os_id", "labels", "tags"}
        for cloud in ("aws", "gcp", "azure", "vmware"):
            text = (ROOT / f"skills/cloudseed-{cloud}/SKILL.md").read_text()
            for name, _, _ in h._parse_variables(cloud):
                if name not in skip:
                    self.assertIn(f"`{name}`", text, f"{cloud} skill misses variable {name}")
            for name, _ in h._parse_outputs(cloud):
                self.assertIn(f"`{name}`", text, f"{cloud} skill misses output {name}")


class HelpPages(unittest.TestCase):
    def test_every_command_has_a_page_and_examples(self):
        sub = next(a for a in cli.build_parser()._actions if isinstance(a, argparse._SubParsersAction))
        for name in sub.choices:
            self.assertTrue(h.has_page(name), name)
            self.assertIn("EXAMPLES", h.epilog(name), name)
            self.assertNotIn("No help for", h.page(name, None), name)
        for alias, target in h.ALIASES.items():
            self.assertEqual(h.COMMANDS[alias], h.COMMANDS[target])

    def test_topics_are_not_shadowed_by_commands(self):
        deps = h.page("deps", None)
        self.assertIn("DEPENDENCIES AND RUNTIMES", deps)
        self.assertIn("terraform (>= 1.10)", deps)
        self.assertNotIn("See `cloudseed help deps`", deps)
        agentic = h.page("agentic", None)
        self.assertIn("AGENTIC MODE", agentic)
        self.assertIn("agents.json", agentic)
        self.assertLess(agentic.index("AGENTIC MODE"), agentic.index("\nEXAMPLES\n"))
        self.assertEqual(h.page("destroy", None).count("--purge-state"), h.COMMANDS["destroy"].count("--purge-state"))

    def test_unknown_topic(self):
        self.assertFalse(h.has_page("setpu"))
        text = h.page("setpu", None)
        self.assertIn("No help for 'setpu'", text)
        self.assertIn("setup", text)
        self.assertNotIn("CORE COMMANDS", text)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli.cmd_help(argparse.Namespace(topic="setpu", cloud=None), {})
        self.assertEqual(rc, 2)
        self.assertIn("setup", err.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.cmd_help(argparse.Namespace(topic="helm", cloud=None), {}), 0)
            self.assertEqual(cli.cmd_help(argparse.Namespace(topic="variables", cloud="vmware"), {}), 0)
            self.assertEqual(cli.cmd_help(argparse.Namespace(topic=None, cloud=None), {}), 0)

    def test_skill_topics_are_rendered_not_raw_markdown(self):
        for topic in ("aws", "gcp", "azure", "vmware-skill"):
            text = h.page(topic, None)
            self.assertNotIn("**", text, topic)
            self.assertNotIn("`", text.split("STACK VARIABLES")[0], topic)
            self.assertFalse(re.search(r"^#", text, re.M), topic)
            self.assertIn("STACK VARIABLES FOR", text)
            self.assertIn("STACK OUTPUTS FOR", text)
            self.assertIn("GOTCHAS", text)
            self.assertEqual(text.count("STACK VARIABLES FOR"), 1)   # the skill's own variable list is dropped
        self.assertIn("vmware", h.page("vmware-skill", None).split("\n")[0].lower())

    def test_md_to_text(self):
        md = "# Title\n\nIntro with **bold** and `code`\nthat continues.\n\n## Variables (`--var`)\n\n- a\n\n## Gotchas\n\n- one\n  two\n1. first\n"
        out = h.md_to_text(md, drop=("variables",))
        self.assertTrue(out.startswith("Title\n"))
        self.assertIn("  Intro with bold and code that continues.", out)
        self.assertIn("GOTCHAS", out)
        self.assertNotIn("VARIABLES", out)
        self.assertIn("  - one two", out)
        self.assertIn("  1. first", out)

    def test_variables_page_marks_cloudseed_values(self):
        for cloud in ("aws", "gcp", "azure", "vmware"):
            text = h.variables_page(cloud)
            self.assertNotIn("(required)", text, cloud)
            self.assertIn("SET BY CLOUDSEED", text)
            self.assertIn("ssh_public_key", text)
        vm = h.variables_page("vmware")
        self.assertIn("guest_os", vm)
        self.assertIn("debian-12", vm)
        self.assertRegex(vm, r"vm_dir\s+default: <workdir>/vms")
        set_by = vm.split("SET BY CLOUDSEED")[1]
        self.assertIn("base_disk", set_by)
        self.assertIn("guest_os_id", set_by)
        self.assertRegex(vm, r"ssh_username\s+default: your local username")
        self.assertIn("first free 10.N.0.0/16", h.variables_page("azure"))
        # the network CIDR is kept in the env config too (overlaps, VPN routes): set with --cidr, never --var
        for cloud, var in (("aws", "vpc_cidr"), ("gcp", "network_cidr"), ("azure", "network_cidr"), ("vmware", "private_cidr")):
            self.assertRegex(h.variables_page(cloud).split("SET BY CLOUDSEED")[1], r"\n  %s\s+--cidr" % var)
        self.assertIn("profile", h.variables_page("aws"))
        self.assertIn("subscription_id", h.variables_page("azure"))
        # descriptions fall back to the setup question's prompt
        self.assertRegex(h.variables_page("gcp"), r"kubernetes_node_size[^\n]*\n\s+Kubernetes node size")   # (aws now documents it in variables.tf)

    def test_outputs_page_keeps_names_apart(self):
        for cloud in ("aws", "gcp", "azure", "vmware"):
            for line in h.outputs_page(cloud).splitlines()[2:]:
                m = re.match(r"^  (\S+)(\s*)(.*)$", line)
                if m and m.group(3):
                    self.assertGreaterEqual(len(m.group(2)), 2, line)

    def test_parse_outputs_is_brace_aware(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "x").mkdir()
            (Path(d) / "x" / "outputs.tf").write_text(
                'output "one" { value = { a = 1 } }\n'
                'output "two" {\n  value       = "${var.a}-{x}"\n  description = "after a braced value"\n}\n'
                'output "three" {\n  description = "has \\"quotes\\""\n  value = 1\n}\n')
            with mock.patch.object(paths, "tf_root", lambda: Path(d)):
                self.assertEqual(h._parse_outputs("x"), [("one", ""), ("two", "after a braced value"), ("three", 'has "quotes"')])

    def test_content_matches_the_code(self):
        overview = h.page(None, None)
        for g in pl.GROUPS:
            self.assertIn(g, overview)
            self.assertRegex(h.COMMANDS["platform"], r"\n  %s\s" % re.escape(g))
        self.assertNotIn("node roles (printed)", h.COMMANDS["platform"])
        self.assertNotIn("dev CA", h.COMMANDS["platform"])
        self.assertIn("kubecost-cost-analyzer", h.COMMANDS["platform"])
        for f in explain.FEATURES:
            self.assertRegex(h.COMMANDS["explain"], r"(?<![\w-])%s(?![\w-])" % re.escape(f))
        for tool in mcp.TOOLS:
            short = tool.replace("cloudseed_", "").replace("_", "-")
            self.assertRegex(h.COMMANDS["mcp"], r"(?<![\w-])%s(?![\w-])" % re.escape(short), tool)
        names = [p.name for p in skills.available()]
        for n in names:
            short = n.replace("cloudseed-", "")
            self.assertRegex(h.COMMANDS["skill"], r"(?<![\w])-?%s(?![\w-])" % re.escape(short), n)
        self.assertNotIn("all five", h.COMMANDS["install"])
        for c in ("ui", "mcp"):
            self.assertIn(c, h.COMMANDS["enable"].split("\n")[1])
            self.assertIn(c, h.COMMANDS["disable"].split("\n")[0])
        sec = h.TOPICS["security"]
        self.assertNotIn("deny-all rules are logged (GCP, Azure)", sec)
        self.assertIn("not logged", sec)
        fips = h.TOPICS["fips"]
        self.assertRegex(fips, r"The VPN\s+host is Ubuntu")
        self.assertNotRegex(fips, r"bastion/VPN\s+\(Amazon Linux 2023\)")
        self.assertIn("agentic --agent help", h.COMMANDS["agents"])
        self.assertIn("UTC", h.COMMANDS["dr"])
        self.assertNotIn("security_baseline[0])", h.COMMANDS["destroy"])
        self.assertIn("cs k8s untunnel <cloud> --env NAME", h.COMMANDS["kubectl"])
        self.assertNotIn("connect --host", h.COMMANDS["managed"])

    def test_every_option_is_documented_on_its_page(self):
        parser = cli.build_parser()
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        missing: list[str] = []

        def documented(token: str, page: str) -> bool:
            if re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(token), page):
                return True
            base = token[5:] if token.startswith("--no-") else token[2:]
            return f"--[no-]{base}" in page

        def walk(name, p, page):
            for a in p._actions:
                if isinstance(a, argparse._SubParsersAction):
                    for cname, cp in a.choices.items():
                        if not documented(cname, page):
                            missing.append(f"{name}: subcommand {cname}")
                        walk(name, cp, page)
                    continue
                for o in a.option_strings:
                    if o not in COMMON and not documented(o, page):
                        missing.append(f"{name}: {o}")
                if not a.option_strings and a.choices and a.dest != "cloud":
                    missing.extend(f"{name}: {a.dest}={c}" for c in a.choices if not documented(str(c), page))

        seen = set()
        for name, sp in sub.choices.items():
            if id(sp) in seen:
                continue
            seen.add(id(sp))
            walk(name, sp, h.page(name, None))
        self.assertEqual(missing, [])


class Rendering(unittest.TestCase):
    PAGES = [None, "setup", "platform", "mcp", "scan", "undo", "managed", "troubleshooting", "security", "fips",
             "vmware", "aws", "azure", "vmware-skill", "deps", "k8s", "dr", "chaos", "ui", "install", "destroy"]

    def test_pages_fit_the_terminal(self):
        for cols in (60, 80, 100):
            for topic in self.PAGES:
                out = _render(topic, None, cols)
                long = [l for l in out.splitlines() if len(l) > cols and '"' not in l]
                self.assertEqual(long, [], f"help {topic} @ {cols}")

    def test_words_are_never_cut(self):
        # a wrapped page keeps every word whole: a too-long [group] splits between its alternatives, a too-long
        # identifier only after a '/', '|' or ','  (was: `help explain` at 80 columns printed "[<gro" / "up>|<item>]")
        for cols in (60, 80, 100):
            for topic in self.PAGES[1:] + ["explain", "ui", "vpn", "enable", "agentic"]:
                words = set(h.page(topic, None).split())
                prev = ""
                for tok in ui._strip(_render(topic, None, cols)).split():
                    if tok in ("\\", "━━"):
                        continue
                    self.assertTrue(tok in words or tok.endswith(("/", "|", ",")) or prev.endswith(("/", "|", ",")),
                                    f"help {topic} @ {cols}: {prev!r} {tok!r}")
                    prev = tok
        self.assertIn("[<group>|<item>]", _render("explain", None, 80))
        self.assertEqual(h._split_word("ARM_CLIENT_ID/ARM_TENANT_ID", 20), ["ARM_CLIENT_ID/", "ARM_TENANT_ID"])

    def test_synopsis_block_is_indented(self):
        out = _render("scan", None, 200)
        lines = out.splitlines()
        self.assertTrue(all(l.startswith("  cloudseed scan") for l in lines[:6]), lines[:6])
        self.assertFalse(any(l.startswith("cloudseed ") for l in lines))
        for line in out.splitlines():
            if line.strip():
                self.assertTrue(line.startswith("  "), line)   # nothing prints at column 0

    def test_comment_column_is_kept(self):
        out = _render("mcp", None, 200)
        cols = {l.index("#") for l in out.splitlines() if re.match(r"\s+cs \S.*#", l)}
        self.assertEqual(len(cols), 1, cols)

    def test_long_rows_wrap_with_hanging_indent(self):
        out = _render("setup", None, 70)
        i = next(i for i, l in enumerate(out.splitlines()) if l.lstrip().startswith("--workdir"))
        lines = out.splitlines()
        self.assertTrue(lines[i + 1].startswith(" " * 26), lines[i + 1])
        self.assertIn("cloudseed setup aws --env prod --name acme --region eu-west-1 \\", out)   # copy-pasteable split

    def test_piped_output_is_not_rewrapped(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("COLUMNS", None)
            with mock.patch.object(sys.stdout, "isatty", lambda: False, create=True):
                self.assertIsNone(h.term_width())

    def test_error_hint_aligns_comments(self):
        text = h.error_hint("mcp", "boom")
        rows = [l for l in text.splitlines() if "#" in l and "cs " in l]
        self.assertGreater(len(rows), 1)
        self.assertEqual(len({l.index("#") for l in rows}), 1)

    def test_explain_fits_and_is_complete(self):
        with mock.patch.dict(os.environ, {"COLUMNS": "80"}):
            for text in (explain.page(None), explain.index(), explain.page("undo"), explain.page("fips")):
                long = [l for l in text.splitlines() if len(ui._strip(l)) > 80 and "source checkout" not in l and "/" not in l.strip()[:1]]
                self.assertEqual(long, [])
            idx = explain.index()
        for item in ("aws-load-balancer-controller", "kubecost-cost-analyzer", "resilience"):
            self.assertIn(item, idx)
        for line in idx.splitlines():
            self.assertFalse(line.rstrip().endswith("aws-load-balancer-"), line)


class Suggestions(unittest.TestCase):
    def test_suggest_has_no_duplicates(self):
        for w in ("destory", "dep", "agentc", "databrick"):
            near = h.suggest(w)
            self.assertEqual(len(near), len(set(near)), near)
        self.assertEqual(h.suggest("helm")[0], "helm")
        self.assertEqual(h.suggest("databrick")[0], "databricks")

    def test_parser_suggests_real_choices(self):
        cases = {
            ("destory", "aws"): ["destroy"],
            ("databrick",): ["databricks"],
            ("snowflak",): ["snowflake"],
            ("hlem",): ["helm"],
            ("scan", "cis2"): ["cis"],
            ("vpn", "conect", "aws"): ["connect"],
            ("deps", "instal"): ["install"],
            ("setup", "aws", "--runtime", "locl"): ["local"],
            ("setup", "aws", "--regin", "us-east-1"): ["--region"],
            ("status", "aws", "--evn=dev"): ["--env"],
        }
        for argv, want in cases.items():
            rc, err = _parse_error(list(argv))
            self.assertEqual(rc, 2, argv)
            near = _did_you_mean(err)
            self.assertEqual(near[: len(want)], want, (argv, err))
            self.assertEqual(len(near), len(set(near)), argv)

    def test_unknown_command_never_shows_another_commands_examples(self):
        rc, err = _parse_error(["platfrom", "list"])
        self.assertIn("unknown command 'platfrom'", err)
        self.assertNotIn("Examples for cloudseed list", err)
        self.assertIn("platform", _did_you_mean(err))
        rc, err = _parse_error(["managd"])
        self.assertNotIn("managed", _did_you_mean(err))
        rc, err = _parse_error(["quickstrt"])
        self.assertIn("cloudseed help quickstart", err)

    def test_needs_a_cloud_lists_every_target(self):
        rc, err = _parse_error(["setup"])
        self.assertEqual(rc, 2)
        self.assertIn("aws, gcp, azure or vmware", err)

    def test_unknown_var_suggests_the_variable(self):
        with self.assertRaises(ui.Abort) as cm:
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                cli._check_extra_vars(clouds.get("aws"), {"az_cout": 3})
        self.assertIn("did you mean az_count?", cm.exception.msg)

    def test_explain_suggestions(self):
        self.assertIn("istio", explain.suggest("istoi"))
        self.assertIn("kubernetes", explain.suggest("kubernets"))
        self.assertIn("bastion", explain.suggest("bastoin"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.cmd_explain(cli.build_parser().parse_args(["explain", "istoi"]), {})


class ExplainContent(unittest.TestCase):
    def test_undo_and_reconcile_match_the_code(self):
        undo = explain.FEATURES["undo"]
        text = undo["what"] + " ".join(undo["controls"])
        self.assertNotIn("clears the environment's journal", text)
        self.assertNotIn("not for destroy", text)
        self.assertIn("recreate", text)
        self.assertIn("provision", text)
        rec = " ".join(explain.FEATURES["reconcile"]["controls"])
        self.assertIn("cs destroy", rec)
        self.assertNotIn("logged in the run log and inventory", rec)
        net = explain.FEATURES["network"]["what"]
        self.assertNotIn("explicit logged deny-all on GCP/Azure", net)
        self.assertNotIn("~/.cloudseed/bin/{kubescape,trivy,velero}", " ".join(explain.FEATURES["scan"]["state"]))
        self.assertNotIn("cert-manager TLS ingresses", explain.FEATURES["platform"]["what"])


class Readme(unittest.TestCase):
    def test_readme_is_current(self):
        # the landing README's own claims (the full check of it: tests/test_readme.py)
        readme = (ROOT / "README.md").read_text()
        for m in re.finditer(r"\b(\d+) tools\b", readme):
            self.assertEqual(int(m.group(1)), len(mcp.TOOLS))
        for g in pl.GROUPS:
            self.assertIn(g, readme)
        # the reference that README.md carried before lives in the manual on the docs site
        text = (ROOT / "docs" / "guides" / "manual.md").read_text()
        for m in re.finditer(r"\b(\d+) tools\b", text):
            self.assertEqual(int(m.group(1)), len(mcp.TOOLS))
        for p in skills.available():
            if p.name == "cloudseed":
                pattern = r"`cloudseed` \(the driver\)"
            else:
                short = p.name.replace("cloudseed-", "")
                pattern = r"(?<![\w])(`cloudseed-%s`|`-%s`)" % (re.escape(short), re.escape(short))
            self.assertTrue(re.search(pattern, text), f"the manual does not list the {p.name} skill")
        for g in pl.GROUPS:
            self.assertIn(g, text)
        self.assertNotIn("cloudseed vpn add-user <name>", text)
        self.assertNotIn("ingress-nginx + MetalLB or the AWS LB controller", text)
        for part in ("providers/vmdesktop", "templates/gitlab-ci", "k8s_common", "clouds/{aws,gcp,azure,vmware}", "Makefile"):
            self.assertIn(part, text)


if __name__ == "__main__":
    unittest.main()
