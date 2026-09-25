"""Wave-3 docs regression tests: help rendering (synopsis continuation rows, copy-pasteable wrapped examples, error
hints laid out for the terminal), the generated variables page, and help / explain / manual (docs/guides/manual.md) / skills text that must
follow the code (RKE2 CIS profile and version inputs, redaction of pass-through tools, GCP env vars / labels / GKE
autoscaler floor / destroy leftovers, dependents of a --target destroy, human-only commands in the skill, Azure NSG
rules and permissions, finops levers, MCP confirmations)."""

from __future__ import annotations

import argparse
import contextlib
import inspect
import io
import os
import re
import shlex
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
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-w3docs-"))

from cloudseed import agents, cli, clouds, dr, explain, help as h, managed, paths  # noqa: E402
from cloudseed.clouds import base as cloudbase  # noqa: E402

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
    with contextlib.redirect_stderr(buf), mock.patch.object(sys, "argv", ["cloudseed", *argv]):
        try:
            cli.build_parser().parse_args(argv)
        except SystemExit:
            pass
    return _plain(buf.getvalue())


def _pasted(lines: list[str]) -> tuple[list[list[str]], list[str]]:
    """What a shell runs when these lines are pasted: the commands (argv, comments dropped) and any line that would run
    although it is not a cloudseed command (a comment or an argument that lost its '#' / '\\')."""
    commands, stray = [], []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith(("#", "━━")) or line == "EXAMPLES":
            continue
        parts = [line]
        while parts[-1].endswith("\\") and i < len(lines):
            parts[-1] = parts[-1][:-1]
            parts.append(lines[i].strip())
            i += 1
        argv = shlex.split(" ".join(parts), comments=True)
        if argv and argv[0] in ("cloudseed", "cs"):
            commands.append(argv)
        else:
            stray.append(" ".join(parts))
    return commands, stray


def _examples_block(text: str) -> list[str]:
    return text[text.index("EXAMPLES"):].splitlines()


class SynopsisRows(unittest.TestCase):
    PAGES = ("undo", "dr", "platform", "mcp", "chaos", "setup", "scan", "managed", "ui", "node", "explain")

    def _synopsis(self, out: str) -> list[str]:
        return out.split("\n\n")[0].splitlines()

    def test_continued_descriptions_wrap_as_one_paragraph(self):
        for cols in (60, 80, 100, 120):
            for topic in self.PAGES:
                rows = self._synopsis(_render(topic, cols))
                for n, line in enumerate(rows):
                    self.assertLessEqual(len(line), cols, f"help {topic} @ {cols}: {line!r}")
                    if len(line.strip()) <= 14 and n + 1 < len(rows):
                        # a short line ("newest", "a cloud") may only end a wrapped row: the next line starts a new one
                        self.assertRegex(rows[n + 1], r"^\s*(cloudseed |cs |\()", f"help {topic} @ {cols}: {line!r}")
        undo = " ".join(self._synopsis(_render("undo", 80)))
        self.assertIn("the newest anywhere; a cloud or --env alone only narrows the choice", _flat(undo))
        self.assertNotIn("\n" + " " * 50, "\n".join(self._synopsis(_render("undo", 60))))   # no one-word column

    def test_pipes_and_wide_terminals_keep_the_source_layout(self):
        src = h.COMMANDS["undo"].split("\n\n")[0].splitlines()
        self.assertEqual(self._synopsis(_render("undo")), ["  " + l for l in src])
        self.assertEqual(self._synopsis(_render("undo", 200)), ["  " + l for l in src])
        self.assertEqual(self._synopsis(_render("dr")), ["  " + l for l in h.COMMANDS["dr"].split("\n\n")[0].splitlines()])

    def test_row_parts_are_told_apart(self):
        kinds = h._layout(h.COMMANDS["undo"], 120, True)
        self.assertEqual(kinds[0][0], "synopsis")
        self.assertEqual(kinds[1][0], "syntext")          # the description, not styled like the command
        dr_kinds = [k for k, line in h._layout(h.COMMANDS["dr"], 80, True) if "backup name" in line]
        self.assertEqual(dr_kinds, ["synnote"])           # the rest of a (note) stays dim
        self.assertEqual(h._syn_desc_kind("[--env NAME]"), "synopsis")
        self.assertEqual(h._syn_desc_kind("(EKS/GKE/AKS)"), "synnote")
        self.assertEqual(h._syn_desc_kind("undo the newest action"), "syntext")
        group = h._synopsis_group(h.COMMANDS["platform"].splitlines(), 3)
        self.assertEqual(len(group), 2)                   # platform install + its [--auto-approve] ... line
        self.assertEqual(len(h._synopsis_group(h.COMMANDS["dr"].splitlines(), 2)), 1)   # a (note) is a row of its own


class CopyPasteableExamples(unittest.TestCase):
    def test_wrapped_examples_paste_as_the_same_commands(self):
        pages = [("examples", h.TOPICS["examples"])] + [(k, v) for k, v in h.COMMANDS.items() if "\nEXAMPLES\n" in v]
        for topic, text in pages:
            want, stray = _pasted(_examples_block(text))
            self.assertEqual(stray, [], topic)
            for cols in (60, 80, 100):
                got, stray = _pasted(_examples_block(_render(topic, cols)))
                self.assertEqual(stray, [], f"help {topic} @ {cols}")
                self.assertEqual(got, want, f"help {topic} @ {cols}")

    def test_the_scripted_example_keeps_every_flag(self):
        for cols in (60, 80):
            out = _render("examples", cols)
            cmds, _ = _pasted(_examples_block(out))
            prod = next(c for c in cmds if "--name" in c)
            self.assertEqual(prod[-1], "--auto-approve")
            self.assertIn("single_nat_gateway=false", prod)

    def test_options_stay_with_their_values(self):
        rows = h._wrap_command("cloudseed setup gcp --env dev --project-id my-proj --var enable_os_login=true", 40, 2)
        for row in rows:
            self.assertFalse(re.search(r"(--var|--project-id|--env) \\$", row), rows)
        self.assertEqual(shlex.split(" ".join(r.rstrip("\\") for r in rows)),
                         shlex.split("cloudseed setup gcp --env dev --project-id my-proj --var enable_os_login=true"))

    def test_wrapped_comments_stay_comments(self):
        out = _render("undo", 60).splitlines()
        comments = [l for l in out if l.strip().startswith("#")]
        self.assertGreater(len(comments), 4)
        self.assertTrue(all(l.startswith("      # ") for l in comments), comments)
        caption = [l for l in _render("examples", 40).splitlines() if "per-AZ" in l or l.strip().endswith("AZs")]
        self.assertTrue(caption and all(l.strip().startswith("#") for l in caption), caption)

    def test_an_oversized_token_keeps_the_gutter(self):
        rows = h._wrap_command('cloudseed agentic "' + "x " * 40 + '"', 60, 2)
        self.assertTrue(all(r.startswith("  ") for r in rows), rows)

    def test_a_pair_too_long_for_a_line_parts_and_the_last_word_needs_no_backslash_room(self):
        cmd = "cloudseed update-ip azure --env dev --allow-ip 198.51.100.4,203.0.113.0/24 --auto-approve"
        rows = h._wrap_command(cmd, 40, 2)
        self.assertTrue(all(len(r) <= 40 for r in rows), rows)          # kept together it would overflow a 40-col line
        self.assertTrue(all(r.startswith("      ") for r in rows[1:]), rows)
        self.assertEqual(shlex.split(" ".join(r.rstrip("\\") for r in rows)), shlex.split(cmd))
        self.assertEqual(h._wrap_command("cs dr restore b1 --namespaces shop", 36, 2), ["  cs dr restore b1 --namespaces shop"])


class ErrorHints(unittest.TestCase):
    def test_shared_pages_show_the_commands_own_examples(self):
        for cmd in ("snowflake", "databricks", "helm"):
            ex = h.examples(cmd)
            self.assertTrue(ex, cmd)
            self.assertTrue(all(re.match(r"(cs|cloudseed) %s\b" % cmd, e) for e in ex), (cmd, ex))
        self.assertTrue(h.examples("do"))                 # no `cs do` example: the agentic ones
        self.assertNotIn("cs databricks", h.error_hint("snowflake", "boom", width=0))
        self.assertNotIn("cs snowflake", h.error_hint("databricks", "boom", width=0))

    def test_an_exact_help_topic_is_named_first(self):
        text = _plain(h.error_hint(None, "unknown command 'quickstart'", "quickstart", near=["status"], width=0))
        self.assertIn("help topic cloudseed help quickstart", text)
        self.assertNotIn("did you mean", text)
        text = _plain(h.error_hint(None, "x", "outputs", near=["output"], width=0))
        self.assertIn("cloudseed help outputs <cloud>", text)
        self.assertIn("did you mean output?", text)            # a close variant still shows
        text = _plain(h.error_hint(None, "x", "fips", near=["finops", "list"], width=0))
        self.assertIn("cloudseed help fips", text)
        self.assertNotIn("finops", text)
        for word in ("quickstart", "state", "examples", "fips", "security"):
            # the page is named once - as the help-topic row, or as the CLI's corrected command line when
            # cli._unknown_command already built `cloudseed help <topic>` - and never next to a far-fetched command
            err = _parse_error([word])
            self.assertRegex(err, rf"(help topic|did you mean) cloudseed help {word}\b", word)
            self.assertEqual(err.count(f"cloudseed help {word}"), 1, word)
            self.assertNotRegex(err, r"did you mean (status|state|setup|list)\b", word)
        self.assertIn("cloudseed help quickstart", _parse_error(["quickstrt"]))   # typos keep the fuzzy topic hint
        envs = _parse_error(["envs"])                  # a topic that is also one letter off a command: both
        self.assertEqual(envs.count("cloudseed help envs"), 1)
        self.assertRegex(envs, r"did you mean (cloudseed help envs, or the command )?env\?")

    def test_hints_fit_the_terminal(self):
        problem = ("unknown command 'frobnicate'. Natural-language tasks need agentic mode:  cloudseed enable agentic, "
                   'then  cloudseed agentic "frobnicate the cluster now"')
        for cols in (40, 60, 80):
            for cmd, prob in ((None, problem), ("undo", "unrecognized arguments: --bogus"), ("mcp", "boom"),
                              ("dr", "x" * 10)):
                text = _plain(h.error_hint(cmd, prob, width=cols))
                for line in text.splitlines():
                    self.assertLessEqual(len(line), cols, (cmd, cols, line))
                self.assertTrue(text.startswith("  ✖ "), text)
        text = _plain(h.error_hint(None, problem, width=60))
        self.assertTrue(any('cloudseed agentic "frobnicate the cluster now"' in l for l in text.splitlines()), text)
        self.assertTrue(any("cloudseed enable agentic" in l for l in text.splitlines()), text)
        undo = _plain(h.error_hint("undo", "boom", width=60)).splitlines()
        self.assertTrue(any(l.startswith("      # ") for l in undo), undo)   # comments below their command
        wide = _plain(h.error_hint("undo", problem, width=0)).splitlines()
        self.assertEqual(wide[0], "  ✖ " + problem)                           # pipes: one line per message
        self.assertEqual(_plain(h.error_hint(None, "a /" + "x/" * 40 + " b", width=40)).splitlines()[0][:4], "  ✖ ")

    def test_width_follows_stderr(self):
        with mock.patch.dict(os.environ, {"COLUMNS": ""}), mock.patch.object(sys.stderr, "isatty", lambda: False, create=True):
            self.assertIsNone(h._stderr_width())
        with mock.patch.dict(os.environ, {"COLUMNS": "72"}):
            self.assertEqual(h._stderr_width(), 72)

    def test_dead_helper_is_gone(self):
        self.assertFalse(hasattr(h, "error_hint_styled"))


class VariablesPage(unittest.TestCase):
    def test_defaults_print_like_the_cli(self):
        for cloud in clouds.CLOUDS:
            page = h.variables_page(cloud)
            self.assertIsNone(re.search(r"default: (True|False|None)\b", page), cloud)
        vm = h.variables_page("vmware")
        self.assertRegex(vm, r"kubernetes_cis_profile\s+default: false")
        self.assertRegex(vm, r"guest_os\s+default: ubuntu-24.04\n")          # text keeps no quotes
        self.assertRegex(vm, r"kubernetes_version\s+default: -")
        self.assertEqual(h._shown_default(False), "false")
        self.assertEqual(h._shown_default(None), "-")
        self.assertEqual(h._shown_default(["a"]), '["a"]')

    def test_env_sources_come_from_the_questions(self):
        for key, cloud in clouds.CLOUDS.items():
            page = h.variables_page(key)
            for q in cloud.questions:
                for var in q.env:
                    if q.key in ("project_id", "subscription_id", "profile"):
                        self.assertIn(var, page, (key, q.key, var))
        gcp = next(q for q in clouds.CLOUDS["gcp"].questions if q.key == "project_id")
        setup = _flat(h.COMMANDS["setup"])
        for var in gcp.env:
            self.assertIn(var, setup)
        azure = next(q for q in clouds.CLOUDS["azure"].questions if q.key == "subscription_id")
        for var in azure.env:
            self.assertIn(var, setup)
        self.assertRegex(h.variables_page("aws"), r"profile\s+default: -\s+\(--profile or AWS_PROFILE\)")
        self.assertIn("az account show", h.variables_page("azure"))

    def test_identity_tags_match_the_cloud(self):
        cfg = {"name": "acme", "env": "dev", "owner": "me", "uid": "u-1"}
        for key in ("aws", "azure"):
            tags = set(clouds.CLOUDS[key].tags(dict(cfg)))
            self.assertEqual(tags, set(h._IDENTITY_TAGS.split("/")), key)
        labels = set(clouds.CLOUDS["gcp"].tags(dict(cfg)))
        self.assertEqual(labels, set(h._IDENTITY_TAGS.lower().split("/")))
        self.assertIn("cloudseedenvid", h.variables_page("gcp"))

    def test_question_helpers(self):
        q = cloudbase.Question("vpn_type", "VPN type?", "openvpn", choices=("openvpn", "tailscale"))
        self.assertEqual(h._question_choices(q), ["openvpn", "tailscale"])
        guest = next(q for q in clouds.CLOUDS["vmware"].questions if q.key == "guest_os")
        self.assertTrue(h._question_choices(guest))
        self.assertEqual(h._question_flag(cloudbase.Question("zone", "Zone")), "--zone")
        self.assertIsNone(h._question_flag(q))
        self.assertEqual(h._as_statement("Create a VPN host?"), "Create a VPN host")
        self.assertNotRegex(h.variables_page("gcp"), r"\n      Create a VPN host[^\n]*\?\n")

    def test_every_setup_input_is_in_the_skill(self):
        for key in clouds.CLOUDS:
            declared = {n for n, _, _ in h._parse_variables(key)}
            skill = _read(f"skills/cloudseed-{key}/SKILL.md")
            for q in clouds.CLOUDS[key].questions:
                if q.key not in declared:
                    self.assertTrue(f"`{q.key}`" in skill or q.flag in skill, (key, q.key))


class KubernetesOnVMware(unittest.TestCase):
    def test_cis_profile_and_version_are_documented_as_settable(self):
        k8s = _flat(h.COMMANDS["k8s"])
        for part in ("CIS hardening profile is not enabled", "kubernetes_cis_profile=true", "kubernetes_version",
                     "joins at the version the cluster runs", "Variables (vmware)"):
            self.assertIn(part, k8s, part)
        topic = _flat(h.TOPICS["vmware"])
        self.assertIn("--var kubernetes_cis_profile=true", topic)
        self.assertIn("kubernetes_version", topic)
        self.assertNotIn("CIS-hardened defaults", topic)
        skill = _flat(_read("skills/cloudseed-vmware/SKILL.md"))
        for part in ("`kubernetes_cis_profile` (false; RKE2 only", "`kubernetes_version` (\"\" = automatic",
                     "`kubernetes_workers=0`", "setup inputs (not Terraform variables)", "Setup warns when the directory is shared"):
            self.assertIn(part, skill, part)
        self.assertNotIn("its CIS hardening profile is not enabled)", skill)
        self.assertNotIn("`10.100.0.0/24` is only the fallback", skill)
        vm = clouds.CLOUDS["vmware"]
        for q in vm.questions:                         # the inputs the docs name exist, with the documented default
            if q.key == "kubernetes_cis_profile":
                self.assertIs(q.default, False)
        self.assertIn("kubernetes_cis_profile", {q.key for q in vm.questions})
        self.assertIn("kubernetes_cis_profile", _read(MANUAL))
        self.assertIn("kubernetes_cis_profile", explain.FEATURES["kubernetes"]["what"])

    def test_a_pinned_version_is_described_as_the_roles_use_it(self):
        # RKE2: a pinned rke2_version wins over the running cluster's version for every node installed later;
        # kubeadm: the running cluster's minor wins, the pin only picks a new cluster's minor; neither reinstalls a node
        rke2 = _read("ansible/roles/rke2/tasks/main.yml")
        self.assertIn("rke2_version | default('', true) or (cluster_rke2.stdout", rke2)
        self.assertIn("creates: /usr/local/bin/rke2", rke2)
        self.assertIn("else (kubernetes_version | default('', true)", _read("ansible/roles/kubeadm/tasks/main.yml"))
        for name, text in (("help k8s", _flat(h.COMMANDS["k8s"])), ("help vmware", _flat(h.TOPICS["vmware"]))):
            self.assertIn("installed by every new node", text, name)
            self.assertIn("for a new cluster only", text, name)
            self.assertIn("never upgrades a node that is already installed", text, name)
        skill = _flat(_read("skills/cloudseed-vmware/SKILL.md"))
        self.assertIn("it is not an upgrade path", skill)
        self.assertIn("only a new cluster uses it", skill)
        self.assertIn("the minor a new cluster starts with", _flat(_read(MANUAL)))


class Redaction(unittest.TestCase):
    def test_caveat_matches_what_is_redacted(self):
        texts = {"manual": _flat(_read(MANUAL)), "help security": _flat(h.TOPICS["security"]),
                 "explain agentic": _flat(" ".join(explain.FEATURES["agentic"]["controls"]))}
        self.assertIn("secrets.run_redacted", inspect.getsource(cli.cmd_ktool))
        managed_redacted = "run_redacted" in inspect.getsource(managed.run)
        for name, text in texts.items():
            self.assertNotIn("(kubectl, helm, databricks, snowflake) is not redacted", text, name)
            self.assertNotRegex(text, r"`cs kubectl`, `cs helm`, `cs databricks`, `cs snowflake`\) is not redacted", name)
            self.assertRegex(text, r"kubectl[^.]*helm[^.]*(output )?included|including the output of `cs kubectl`", name)
            self.assertIn("k9s", text, name)
            if managed_redacted:         # managed.run redacts now: the databricks/snowflake caveat must go too
                self.assertNotIn("not redacted yet", text, name)
            else:
                self.assertRegex(text, r"databricks[^.]*snowflake[^.]*not redacted yet", name)


class GcpDocs(unittest.TestCase):
    def test_gke_floor_and_destroy_leftovers(self):
        tf = _read("terraform/gcp/modules/kubernetes/main.tf")
        self.assertIn("min_node_count = max(var.node_min, var.node_count)", tf)
        skill = _flat(_read("skills/cloudseed-gcp/SKILL.md"))
        self.assertNotIn("autoscaling between `kubernetes_node_min/max`", skill)
        self.assertIn("the count is the floor", skill)
        for text in (_flat(_read(MANUAL)), _flat(_read("skills/cloudseed-platform/SKILL.md")), _flat(h.COMMANDS["k8s"])):
            self.assertRegex(text, r"(GKE never (scales )?below|on GKE the autoscaler never goes below) `?kubernetes_node_count")
        # `cs node scale --min` below the count is saved to config.json, but the GKE module's floor wins at the next apply
        self.assertIn('cfg.setdefault("vars", {})["kubernetes_node_count"] = pool["size"]', inspect.getsource(cli._sync_pool_cfg))
        self.assertIn("except on GKE, where an apply raises a --min below the count back to the count", _flat(h.COMMANDS["node"]))
        destroy_skill = _flat(_read("skills/cloudseed-destroy/SKILL.md"))
        destroy_help = _flat(h.COMMANDS["destroy"])
        for text in (destroy_skill, destroy_help):
            for part in ("GCP:", "_Default", "--retention-days=30", "APIs stay on", "os-login ssh-keys remove"):
                self.assertIn(part, text, part)
        self.assertIn("_Default", _flat(h.TOPICS["security"]))


class DestroyDocs(unittest.TestCase):
    def test_a_target_takes_its_dependents(self):
        skill = _flat(_read("skills/cloudseed-destroy/SKILL.md"))
        self.assertNotIn("refused by the cloud", skill)
        for part in ("depends on the target", "`--target module.stack.module.network`", "Kubernetes cluster",
                     "The confirmation count includes those dependents"):
            self.assertIn(part, skill, part)
        self.assertIn("depends on a target", _flat(h.COMMANDS["destroy"]))

    def test_purge_describes_which_workdirs_go_entirely(self):
        for text in (_flat(h.COMMANDS["destroy"]), _flat(_read("skills/cloudseed-destroy/SKILL.md")), _flat(_read(MANUAL))):
            self.assertIn("only cloudseed's own files", text)
            self.assertRegex(text, r"new / empty `?(setup )?--workdir")
        owned = inspect.getsource(cli._workdir_owned)      # the rule the docs describe: default, or empty when taken
        self.assertIn("_is_default_workdir(env)", owned)
        self.assertIn("_workdir_preexisting(env) == []", owned)


class CoreSkill(unittest.TestCase):
    def test_installing_is_human_only(self):
        skill = _read("skills/cloudseed/SKILL.md")
        row = next(l for l in skill.splitlines() if l.startswith("| Install software"))
        self.assertIn("Human-only", row)
        self.assertNotIn("| Install anything |", skill)
        self.assertNotIn("`cloudseed doctor [cloud]`, `cloudseed deps install terraform`", skill)
        for word in ("use", "model", "enable", "skill install", "ui", "mcp", "creds"):
            self.assertRegex(_flat(skill), r"human-only[^|]*%s" % re.escape(word), word)
        from cloudseed import builtin_agent
        for cmd in builtin_agent.HUMAN_ONLY:            # everything the built-in agent refuses is marked in the skill
            if cmd in ("do", "agentic"):
                continue
            self.assertRegex(_flat(skill), r"[Hh]uman-only[^.]*\b%s\b" % re.escape(cmd), cmd)
        install = _flat(h.COMMANDS["install"])
        self.assertNotIn("Equivalent long forms", install)
        self.assertIn("its `all` is terraform aws gcloud az", install)
        self.assertIn("confirm=true", install)
        from cloudseed import deps
        self.assertIn("vmrun", deps.INSTALLERS)            # `deps install vmrun` works: only --from FILE is install's
        self.assertNotIn("agents, vmrun and the provider are `install` targets", install)
        self.assertIn("`vmrun --from FILE` are `install` targets", install)

    def test_secret_files_the_code_writes_are_named(self):
        from cloudseed import localvm, mcp
        skill = _flat(_read("skills/cloudseed/SKILL.md"))
        self.assertEqual(localvm.VMREST_CREDS.name, "vmware.json")
        self.assertIn("`~/.cloudseed/vmware.json`", skill)
        self.assertIn('paths.HOME / "managed"', inspect.getsource(managed))      # generated Snowflake configs
        self.assertIn("`~/.cloudseed/managed/`", skill)
        self.assertEqual(mcp.BACKUPS_DIR.parent, mcp.TOKEN_PATH.parent)          # client-config backups carry the token
        self.assertIn("the rest of `~/.cloudseed/mcp/`", skill)
        for part in ("`~/.cloudseed/helm/`", "`vpn/` (`*.ovpn`", "`platform/` (`platform/secrets.json`"):
            self.assertIn(part, skill)

    def test_secret_files_rule_names_every_denied_path(self):
        skill = _flat(_read("skills/cloudseed/SKILL.md"))
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
            self.assertIn(path, skill, rule)


class AzureDocs(unittest.TestCase):
    def test_vpn_nsg_rules_follow_the_module(self):
        tf = _read("terraform/azure/modules/vpn/main.tf")
        skill = _flat(_read("skills/cloudseed-azure/SKILL.md"))
        rules = re.findall(r'name\s*=\s*"(Allow\w+)"\s*\n\s*priority\s*=\s*(\d+)', tf)
        self.assertEqual(len(rules), 2)
        for name, prio in rules:
            self.assertIn(f"({name}, {prio}", skill)
        readme = _flat(_read(MANUAL))
        self.assertIn("traffic from the VPN host (`enable_vpn`)", readme)
        self.assertIn("the VPN port to the VPN host with `enable_vpn`", readme)

    def test_permissions_and_validations(self):
        skill = _flat(_read("skills/cloudseed-azure/SKILL.md"))
        self.assertIn("Role Based Access Control Administrator cannot create role definitions", skill)
        self.assertIn("Contributor + User Access Administrator", _flat(h.TOPICS["troubleshooting"]))
        for part in ("a GUID", "AZURE_SUBSCRIPTION_ID", "admin, administrator, root", "30-730", "41641",
                     "`tenant_id`, `subscription_id` (both set with or without AKS)"):
            self.assertIn(part, skill, part)
        from cloudseed.clouds import azure
        self.assertTrue({"admin", "administrator", "root"} <= set(azure.RESERVED_ADMIN_NAMES))
        low = azure.Azure.AZURERM_VERSION.split(",")[0].strip()          # ">= 4.65"
        self.assertIn(f"azurerm {low}", _read(MANUAL))
        self.assertNotIn("azurerm ~> 4.", _read(MANUAL))


class AwsDocs(unittest.TestCase):
    def test_subnet_tags_and_tailscale_port(self):
        skill = _flat(_read("skills/cloudseed-aws/SKILL.md"))
        tf = _read("terraform/aws/modules/network/main.tf")
        for tag in ("kubernetes.io/role/elb", "kubernetes.io/role/internal-elb"):
            self.assertIn(tag, tf)
            self.assertIn(f"`{tag}`", skill)
        self.assertIn("41641", skill)


class FinopsDocs(unittest.TestCase):
    def test_spot_is_not_a_cloudseed_lever(self):
        page = _flat(h.COMMANDS["finops"])
        self.assertNotIn("spot/preemptible nodes)", page)
        self.assertIn("outside cloudseed", page)
        skill = _flat(_read("skills/cloudseed-finops/SKILL.md"))
        self.assertNotIn("consider spot/preemptible", skill)
        self.assertIn("not managed by cloudseed", skill)
        self.assertIn("never invent a `--var`", skill)
        self.assertRegex(_read("terraform/aws/modules/kubernetes/main.tf"), r'capacity_type\s*=\s*"ON_DEMAND"')


class OverviewAndPages(unittest.TestCase):
    def _row(self, name: str) -> str:
        m = re.search(r"^  %s\s+(.*(?:\n {21}.*)*)" % re.escape(name), h.OVERVIEW, re.M)
        self.assertIsNotNone(m, name)
        return _flat(m.group(1))

    def test_overview_lists_every_subcommand(self):
        sub = next(a for a in cli.build_parser()._actions if isinstance(a, argparse._SubParsersAction))
        for cmd, label in (("node", "node"), ("platform", "platform"), ("vpn", "vpn <cloud>"), ("env", "env")):
            parser = sub.choices[cmd]
            choices = [c for a in parser._actions if not a.option_strings and a.choices for c in a.choices]
            if isinstance(choices, dict):
                choices = list(choices)
            row = self._row(label)
            for choice in choices:
                if choice in clouds.CLOUDS:
                    continue
                self.assertRegex(row, r"(?<![\w-])%s(?![\w-])" % re.escape(str(choice)), f"{cmd}: {choice}")
        self.assertNotIn("auto-installed", h.OVERVIEW)
        self.assertIn("installed after asking", self._row("kubectl|helm|k9s"))
        self.assertIn("Most commands also accept them after it", _flat(h.OVERVIEW))

    def test_setup_and_troubleshooting_pages(self):
        setup = _flat(h.COMMANDS["setup"])
        self.assertIn("read by the variable's declared type", setup)
        self.assertIn("CLOUDSEED_NONINTERACTIVE=1", setup)
        self.assertIn("--ssh-private-key FILE", setup)
        self.assertIn("CLOUDSEED_NONINTERACTIVE=1", _flat(h.TOPICS["troubleshooting"]))
        self.assertIn('text stays text (kubernetes_version=1.30)', setup)
        self.assertEqual(cli._typed_var("kubernetes_version", "1.30", "string"), "1.30")   # the documented rule
        agentic = h.TOPICS["agentic"]
        self.assertIn("deps install|image|bundle|runtime,", agentic)
        self.assertTrue(all(len(l) <= 120 for l in agentic.splitlines()))

    def test_mcp_dr_managed_and_explain(self):
        mcp_page = _flat(h.COMMANDS["mcp"])
        for part in ("helm get values|all|manifest|hooks", "undo (--drop included)", "an agent's call for one is refused"):
            self.assertIn(part, mcp_page, part)
        self.assertIn("helm get values|all|manifest|hooks", " ".join(explain.FEATURES["mcp"]["controls"]))
        dr_page = _flat(h.COMMANDS["dr"])
        self.assertIn(f"after {dr.DRILL_BACKUP_TTL}", dr_page)
        hint = "-n velero exec svc/velero -c velero -- /velero"
        self.assertIn(hint, dr_page)
        self.assertIn('"-n", "velero", "exec", SERVER, "-c", "velero", "--", "/velero"', inspect.getsource(dr.velero_hint))
        self.assertIn("in front of the subcommand (cs snowflake --env prod test)", _flat(h.COMMANDS["managed"]))
        self.assertIn("agent and MCP sessions stop with the install command", _flat(" ".join(explain.FEATURES["scan"]["state"])))

    def test_pages_still_fit(self):
        for cols in (60, 80, 100):
            for topic in ("k8s", "vmware", "destroy", "dr", "managed", "install", "finops", "security", "mcp", None):
                long = [l for l in _render(topic, cols).splitlines() if len(l) > cols and '"' not in l]
                self.assertEqual(long, [], f"help {topic} @ {cols}")


if __name__ == "__main__":
    unittest.main()
