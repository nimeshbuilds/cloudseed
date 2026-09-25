"""Wave-3 regression tests for the agentic group: the built-in agent's fail-closed kubectl/helm reader and approval
rules (provision / vpn / scans, previews before --auto-approve), refused calls shown to the user, cut-off answers,
Anthropic credential detection and the shared no-credentials text, agent templates (codex outside a git repository,
{model} placement), Grok (skills in the prompt, key-based readiness), Claude Code deny rules, the vault's name
denylist, the headliner on malformed configs, redaction gaps and the wrapped `cs agents` page."""

import contextlib
import io
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import agents, builtin_agent, creds, headliner, paths, secrets, skills, ui, undo  # noqa: E402

R = secrets.REDACTED
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _reason(cmd: str):
    ns, _ = builtin_agent._parse(shlex.split(cmd))
    return builtin_agent._approval_reason(ns)


class _TmpHome(unittest.TestCase):
    """A throw-away HOME (and a clean Anthropic/Grok environment) for each test."""

    def setUp(self):
        self.addCleanup(secrets.set_strict, False)     # agent runs mark the process agent-facing
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w3-agentic-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "GROK_"))}
        env["HOME"] = str(self.tmp)
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        agents._CLAUDE_AUTH_CACHE.clear()


# ------------------------------------------------------------------------------------------------ kubectl / helm

class KubeReaderTests(unittest.TestCase):
    APPROVAL = [
        # an option before the verb that takes a value hides the real verb
        "kubectl --cache-dir get delete ns prod", "kubectl --profile-output get apply -f x.yaml",
        "kubectl --tls-server-name get delete pod x", "helm --repository-cache list uninstall rel",
        "helm --registry-config status get values monitoring", "kubectl --cache-dir describe get secret x -o yaml",
        "kubectl --cache-dir version config view --raw", "kubectl --foo get delete ns prod", "kubectl -A get pods",
        # secrets through --raw (query strings, %-encoding and .. defeat a word match)
        "kubectl get --raw=/api/v1/namespaces/default/secrets", "kubectl get --raw=/api/v1/secrets?limit=1",
        "kubectl get --raw=/api/v1/namespaces/default/%73ecrets", "kubectl get --raw /livez/../api/v1/secrets",
        "kubectl aws --env dev get --raw=/api/v1/secrets", "kubectl get -- secrets", "kubectl get pods,secrets",
        # another server / identity / local files
        "kubectl get pods --server https://x", "kubectl get pods -s https://x", "kubectl get pods -As https://x",
        "kubectl get pods --insecure-skip-tls-verify", "kubectl get pods --kubeconfig /tmp/k", "kubectl get pods --as admin",
        "kubectl get -f https://x/s.yaml", "kubectl get -Rf ./dir", "kubectl describe -k ./dir",
        "kubectl cluster-info dump --output-directory=/tmp/x", "kubectl get pods -o go-template-file=/etc/passwd",
        "kubectl get pods -ogo-template-file=/etc/passwd", "helm list --kube-apiserver https://x",
        # helm: rendering with local files, values in status output, sub-commands
        "helm template x c --output-dir /tmp/y", "helm lint ./c", "helm status x -o json", "helm status x -ojson",
        "helm status x -o=yaml", "helm status x --output json", "helm status x --output=yaml",
        "helm status x --revision 2 -o json", "helm get --all values x", "helm get values x", "helm get",
        "helm repo add a https://b", "kubectl", "helm",
    ]
    NO_APPROVAL = [
        "kubectl aws --env dev get pods", "kubectl --cache-dir=/tmp/c get pods", "kubectl -n shop get pods",
        "kubectl -nshop get pods", "kubectl -v 6 get pods", "helm aws --env dev list -A", "kubectl get pods",
        "kubectl describe secret x", "kubectl logs -f pod", "kubectl logs -p -c app pod", "kubectl get --raw /healthz",
        "kubectl get --raw=/readyz?verbose", "kubectl get ns -o jsonpath={.items[*].metadata.name}", "helm list -A",
        "helm get notes x", "helm status x", "helm status x -o table", "helm history x -o json",
        "helm get metadata x -o json", "helm repo list",
    ]

    def test_fail_closed(self):
        for c in self.APPROVAL:
            with self.subTest(cmd=c):
                self.assertIsNone(builtin_agent.guard(shlex.split(c)))
                self.assertTrue(builtin_agent.is_destructive(shlex.split(c)))
        for c in self.NO_APPROVAL:
            with self.subTest(cmd=c):
                self.assertFalse(builtin_agent.is_destructive(shlex.split(c)))

    def test_reasons_name_the_real_verb(self):
        self.assertIn("kubectl delete", _reason("kubectl --cache-dir get delete ns prod"))
        self.assertIn("cannot read", _reason("kubectl --foo get delete ns prod"))
        self.assertIn("--server", _reason("kubectl get pods --server https://x"))
        self.assertIn("status -o json", _reason("helm status x -o json"))

    def test_public_reader_takes_cloudseed_prefixes(self):
        self.assertIsNone(builtin_agent.kube_approval("kubectl", ["aws", "--env", "dev", "get", "pods"]))
        self.assertIsNone(builtin_agent.kube_approval("kubectl", ["-edev", "get", "pods"]))
        self.assertIsNotNone(builtin_agent.kube_approval("kubectl", ["aws", "--env", "dev", "delete", "ns", "x"]))
        self.assertIsNotNone(builtin_agent.kube_approval("helm", ["--", "uninstall", "x"]))


# ------------------------------------------------------------------------------------------------ approval rules

class ApprovalRuleTests(unittest.TestCase):
    def test_provision_vpn_and_scans_need_approval_like_mcp(self):
        for c in ("provision aws --env dev", "provision aws --host bastion", "vpn add-user aws --env dev bob",
                  "vpn provision aws --env dev", "scan host aws", "scan stig aws", "scan cis aws", "scan kube",
                  "scan images", "scan cloud aws", "scan all", "vpn revoke aws bob", "vpn connect aws"):
            with self.subTest(cmd=c):
                self.assertTrue(builtin_agent.is_destructive(shlex.split(c)))
        for c in ("scan architecture aws", "scan fips aws", "scan reports aws", "vpn users aws", "vpn status aws"):
            with self.subTest(cmd=c):
                self.assertFalse(builtin_agent.is_destructive(shlex.split(c)))
        self.assertIn("certificate", _reason("vpn add-user aws bob"))
        self.assertIn("Ansible", _reason("provision aws"))

    def test_previews_run_unasked_and_the_auto_approve_form_is_approved(self):
        for c in ("destroy aws --env dev", "dr restore b1", "chaos run --target deploy/x", "node add aws",
                  "node remove aws n1", "node scale aws --count 3", "apply aws", "update-ip aws",
                  "platform uninstall keda"):   # (prints the removal list, then stops at its approval)
            with self.subTest(cmd=c):
                self.assertIsNone(_reason(c))
                self.assertIsNotNone(_reason(c + " --auto-approve"))
        self.assertEqual(_reason("destroy aws --env dev --auto-approve"), "destroys infrastructure")
        self.assertIn("Velero", _reason("dr restore b1 --auto-approve"))
        # forms that change things without --auto-approve stay gated
        for c in ("chaos run", "chaos stop", "dr backup", "platform install basek8s", "platform ui", "destroy aws --purge",
                  "destroy aws --purge-state"):
            with self.subTest(cmd=c):
                self.assertIsNotNone(_reason(c))

    def test_undo_follows_the_entry_it_would_revert(self):
        cfg_entry = {"id": "u1", "scope": "aws-dev", "kind": "config", "summary": "update-ip",
                     "data": {"what": "allowed IPs", "prev_cfg": {}}, "at": "2026-01-01T00:00:00"}
        with mock.patch.object(undo, "entries", return_value=[cfg_entry]):
            self.assertIsNone(_reason("undo"))                          # a preview: stops at the approval (exit 3)
            self.assertIsNone(_reason("undo aws --env dev"))
            why = _reason("undo --auto-approve")
            self.assertIn("update-ip", why)
            self.assertIn("restore the previous configuration", why)   # undo.describe(entry) is in the question
            self.assertIsNotNone(_reason("undo --drop"))
            self.assertIsNotNone(_reason("undo aws"))                  # which environment: only the child knows
        for kind in ("info", "settings-restore"):                       # applied without cloudseed's approval step
            entry = dict(cfg_entry, kind=kind, data={"advice": "x", "what": ["agent"], "settings": {}})
            with mock.patch.object(undo, "entries", return_value=[entry]):
                self.assertIsNotNone(_reason("undo"), kind)
        broken = dict(cfg_entry, kind="helm", data=["not", "a", "mapping"])   # a damaged journal entry
        with mock.patch.object(undo, "entries", return_value=[broken]):
            self.assertEqual(_reason("undo --auto-approve"), "undo reverts the last change")
        with mock.patch.object(undo, "entries", return_value=[]):
            self.assertIsNone(_reason("undo --auto-approve"))           # nothing to undo: nothing happens
        with mock.patch.object(undo, "entries", return_value=[dict(cfg_entry, scope=undo.GLOBAL)]):
            self.assertIsNone(_reason("undo --auto-approve"))           # global entries: refused for agents anyway

    def test_parity_with_mcp(self):
        """Whatever needs confirm=true over MCP needs the user's approval in the built-in agent (MCP adds
        --auto-approve itself, so its argv is the approved form)."""
        from cloudseed import mcp
        cases = [
            ("cloudseed_setup", {"cloud": "aws", "env": "dev", "apply": True}), ("cloudseed_apply", {"cloud": "aws", "env": "dev"}),
            ("cloudseed_destroy", {"cloud": "aws", "env": "dev"}), ("cloudseed_update_ip", {"cloud": "aws", "env": "dev"}),
            ("cloudseed_ssh", {"cloud": "aws", "env": "dev", "command": "uptime"}),
            ("cloudseed_provision", {"cloud": "aws", "env": "dev"}), ("cloudseed_provision", {"cloud": "aws", "host": "bastion"}),
            ("cloudseed_node", {"action": "add", "cloud": "aws"}), ("cloudseed_node", {"action": "remove", "cloud": "aws", "name": "n1"}),
            ("cloudseed_node", {"action": "scale", "cloud": "aws", "count": 3}),
            ("cloudseed_platform", {"action": "install", "items": ["basek8s"]}), ("cloudseed_platform", {"action": "ui"}),
            ("cloudseed_kubectl", {"args": "delete ns x"}), ("cloudseed_kubectl", {"args": "get secret x -o yaml"}),
            ("cloudseed_helm", {"args": "uninstall x"}), ("cloudseed_helm", {"args": "get values x"}),
            ("cloudseed_helm", {"args": "template x c"}),
            ("cloudseed_vpn", {"action": "add-user", "cloud": "aws", "name": "bob"}), ("cloudseed_vpn", {"action": "provision", "cloud": "aws"}),
            ("cloudseed_vpn", {"action": "revoke", "cloud": "aws", "name": "bob"}),
            ("cloudseed_managed", {"service": "databricks", "args": "clusters delete x"}),
            ("cloudseed_chaos", {"action": "run"}), ("cloudseed_chaos", {"action": "stop"}),
            ("cloudseed_dr", {"action": "restore", "name": "b1"}), ("cloudseed_dr", {"action": "backup"}),
            ("cloudseed_dr", {"action": "schedule"}), ("cloudseed_dr", {"action": "test"}),
            ("cloudseed_scan", {"kind": "host", "cloud": "aws"}), ("cloudseed_scan", {"kind": "all"}),
            ("cloudseed_scan", {"kind": "cis"}), ("cloudseed_scan", {"kind": "stig"}), ("cloudseed_undo", {"cloud": "aws", "env": "dev"}),
        ]
        entry = {"id": "u1", "scope": "aws-dev", "kind": "config", "summary": "x", "data": {}, "at": "2026-01-01"}
        with mock.patch.object(undo, "entries", return_value=[entry]):
            for tool, a in cases:
                a = dict(a, confirm=True)
                with self.subTest(tool=tool, args=a):
                    t = mcp.TOOLS[tool]
                    argv = t["argv"](a)
                    if mcp._is_destructive(t, a):
                        self.assertTrue(builtin_agent.is_destructive(argv), argv)

    def test_system_prompt_states_the_rules(self):
        sp = builtin_agent.system_prompt("destroy the aws dev env")
        for part in ("provision", "scans (all but architecture, fips and reports)", "vpn add-user", "run the preview first",
                     "without a terminal they are refused", builtin_agent.PREVIEW_TEXT):
            self.assertIn(part, sp)
        self.assertIn('<skill name="cloudseed-destroy">', sp)
        self.assertIn("<skill-index>", sp)


# ------------------------------------------------------------------------------------------------ tool calls

class ToolCallTests(unittest.TestCase):
    def tearDown(self):
        secrets.set_strict(False)
        secrets._REGISTERED.clear()

    def _tool(self, args, rc=0, out="", interactive=False, confirm=False):
        err, outbuf, ran = io.StringIO(), io.StringIO(), []

        def child(cmd, env):
            ran.append(cmd)
            return rc, out
        env = {k: v for k, v in os.environ.items() if k != "CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE"}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(builtin_agent, "_run_child", side_effect=child), \
                mock.patch.object(ui, "interactive", return_value=interactive), \
                mock.patch.object(ui, "confirm", return_value=confirm), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(outbuf):
            result = builtin_agent.run_tool(args, ["cloudseed"], {})
        return result, _ANSI.sub("", err.getvalue()), _ANSI.sub("", outbuf.getvalue()), ran

    def test_refused_calls_are_shown_to_the_user_redacted(self):
        result, err, _o, ran = self._tool("destroy aws --env x --auto-approve")
        self.assertTrue(result.startswith("REFUSED"))
        self.assertIn("cloudseed destroy aws --env x --auto-approve", err)
        self.assertIn("CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE", err)
        self.assertEqual(ran, [])
        result, err, _o, ran = self._tool("creds set AWS_SECRET_ACCESS_KEY=AKIA" + "IOSFODNN7EXAMPLE")
        self.assertTrue(result.startswith("REFUSED"))
        self.assertIn("Refused agent command: cloudseed creds set", err)
        self.assertNotIn("AKIA" + "IOSFODNN7EXAMPLE", err)
        # a vault value is a plain word no pattern recognises: only the variable names are shown
        for call, shown in (("creds set MY_SECRET hunter2hunter2", "cloudseed creds set MY_SECRET " + R),
                            ("creds set FOO=hunter2hunter2 BAR", f"cloudseed creds set FOO={R} BAR"),
                            ("creds set 'p@ss word!'", "cloudseed creds set " + R),
                            ("creds set MY_SECRET 'hunter2 unclosed", "cloudseed creds set MY_SECRET " + R)):
            with self.subTest(call=call):
                result, err, _o, ran = self._tool(call)
                self.assertTrue(result.startswith(("REFUSED", "ERROR")))       # (ERROR: the unclosed quote)
                self.assertEqual(ran, [])
                self.assertIn(shown, err)
                self.assertNotIn("hunter2", err)
                self.assertNotIn("p@ss", err)
        result, err, _o, _r = self._tool("status 'aws")
        self.assertTrue(result.startswith("ERROR"))
        self.assertIn("unparseable", err)
        result, err, _o, ran = self._tool("vpn revoke aws bob", interactive=True, confirm=False)
        self.assertTrue(result.startswith("USER DECLINED"))
        self.assertIn("The agent wants to run:  cloudseed vpn revoke aws bob", err)
        self.assertEqual(ran, [])

    def test_a_preview_tells_the_model_how_to_go_ahead(self):
        result, _e, out, ran = self._tool("destroy aws --env dev", rc=3, out="plan: 3 to destroy\n")
        self.assertEqual(len(ran), 1)                                    # ran unasked: it only previews
        self.assertIn("PREVIEW ONLY", result)
        self.assertIn("--auto-approve", result)
        result, *_ = self._tool("status aws --env dev", rc=3)
        self.assertNotIn("PREVIEW ONLY", result)                        # status has no --auto-approve


class _Block:
    def __init__(self, type_, text=""):
        self.type, self.text = type_, text


class _FakeSDK(types.ModuleType):
    def __init__(self, messages):
        super().__init__("anthropic")
        for n in ("AuthenticationError", "RateLimitError", "APIStatusError", "APIConnectionError"):
            setattr(self, n, type(n, (Exception,), {"status_code": 500}))
        self.CredentialsError = type("CredentialsError", (Exception,), {})
        self.beta_tool = lambda fn: fn
        sdk = self

        class _Messages:
            def tool_runner(self, **kw):
                for m in messages:
                    if isinstance(m, Exception):
                        raise m
                    yield m

        class Anthropic:
            def __init__(self):
                if getattr(sdk, "fail_init", None):
                    raise sdk.fail_init
                self.beta = types.SimpleNamespace(messages=_Messages())

        self.Anthropic = Anthropic


class RunTests(_TmpHome):
    def tearDown(self):
        secrets.set_strict(False)
        secrets._REGISTERED.clear()

    def _run(self, sdk):
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-" + "test-000000000000000000000"
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(sys.modules, {"anthropic": sdk}), mock.patch.object(builtin_agent, "ensure_sdk"), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = builtin_agent.run("prompt", "claude-sonnet-5", "task")
        return rc, out.getvalue(), _ANSI.sub("", err.getvalue())

    def test_a_cut_off_answer_is_not_a_success(self):
        msg = types.SimpleNamespace(content=[_Block("text", "I will now destroy the envir")], stop_reason="max_tokens")
        rc, out, err = self._run(_FakeSDK([msg]))
        self.assertEqual(rc, 1)
        self.assertIn("I will now destroy the envir", out)
        self.assertIn("cut off (max_tokens)", err)
        msg = types.SimpleNamespace(content=[_Block("text", "Destroying now."), _Block("tool_use")],
                                    stop_reason="max_tokens")
        rc, _o, err = self._run(_FakeSDK([msg]))
        self.assertEqual(rc, 1)
        self.assertIn("NOT run", err)
        rc, _o, err = self._run(_FakeSDK([types.SimpleNamespace(content=[], stop_reason="model_context_window_exceeded")]))
        self.assertEqual(rc, 1)
        rc, _o, _e = self._run(_FakeSDK([types.SimpleNamespace(content=[_Block("text", "ok")], stop_reason="end_turn")]))
        self.assertEqual(rc, 0)

    def test_credential_errors_explain_instead_of_crashing(self):
        sdk = _FakeSDK([])
        sdk.fail_init = sdk.CredentialsError("profile 'work' not found")
        rc, _o, err = self._run(sdk)
        self.assertEqual(rc, 1)
        self.assertIn("could not be used", err)
        self.assertIn("ant auth login", err)
        self.assertIn("Options:", err)
        self.assertNotIn("found.", err)          # the options only, never a slice of the wrapped headline
        with mock.patch.dict(os.environ, {"COLUMNS": "50"}):
            rc, _o, err = self._run(sdk)
        self.assertNotIn("found.", err)
        rc, _o, err = self._run(_FakeSDK([TypeError("Could not resolve authentication method")]))
        self.assertEqual(rc, 1)
        self.assertIn("none were found", err)

    def test_no_credentials_aborts_with_the_shared_message(self):
        with mock.patch.dict(sys.modules, {"anthropic": _FakeSDK([])}), mock.patch.object(builtin_agent, "ensure_sdk"), \
                mock.patch.object(builtin_agent, "claude_fallback", return_value=({}, "missing")):
            with self.assertRaises(ui.Abort) as cm:
                builtin_agent.run("p", None, "t")
        self.assertIn("npm install -g @anthropic-ai/claude-code", str(cm.exception))


# ------------------------------------------------------------------------------------------------ credentials

class AnthropicCredentialTests(_TmpHome):
    def cfg(self) -> Path:
        d = self.tmp / ".config" / "anthropic"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def test_a_config_directory_alone_is_not_a_credential(self):
        self.assertFalse(builtin_agent.has_api_credentials())
        (self.cfg() / "config.json").write_text("{}")
        (self.cfg() / ".DS_Store").write_text("x")
        (self.cfg() / "configs").mkdir()
        (self.cfg() / "configs" / "work.json").write_text("{}")     # not the active profile
        self.assertFalse(builtin_agent.has_api_credentials())
        spec = agents.get("builtin")
        self.assertFalse(agents.auth_ok(spec))
        with mock.patch.object(agents, "installed", side_effect=lambda s: "builtin" if s.get("builtin") else None):
            ok, msg = agents.readiness(spec)
        self.assertFalse(ok)
        self.assertIn("no credentials", msg)

    def test_the_sdk_resolution_order(self):
        (self.cfg() / "configs").mkdir()
        (self.cfg() / "configs" / "default.json").write_text("{}")
        self.assertTrue(builtin_agent.has_api_credentials())
        self.assertTrue(agents.auth_ok(agents.get("builtin")))
        (self.cfg() / "configs" / "default.json").unlink()
        (self.cfg() / "active_config").write_text("work\n")         # an explicit choice (a broken one surfaces later)
        self.assertTrue(builtin_agent.has_api_credentials())
        (self.cfg() / "active_config").write_text("  \n")
        self.assertFalse(builtin_agent.has_api_credentials())
        for env in ({"ANTHROPIC_PROFILE": "dev"}, {"ANTHROPIC_CONFIG_DIR": str(self.tmp / "elsewhere")},
                    {"ANTHROPIC_AUTH_TOKEN": "t"},
                    {"ANTHROPIC_FEDERATION_RULE_ID": "r", "ANTHROPIC_ORGANIZATION_ID": "o",
                     "ANTHROPIC_IDENTITY_TOKEN_FILE": "/var/run/token"}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env):
                self.assertTrue(builtin_agent.has_api_credentials())
        with mock.patch.dict(os.environ, {"ANTHROPIC_FEDERATION_RULE_ID": "r", "ANTHROPIC_ORGANIZATION_ID": "o"}):
            self.assertFalse(builtin_agent.has_api_credentials())    # no identity token: not usable

    def test_no_credentials_text_fits_the_terminal_and_the_machine(self):
        for state, want, absent in (("ready", "cloudseed use claude", "npm install"),
                                    ("login", "not logged in", "npm install"),
                                    ("missing", "npm install -g @anthropic-ai/claude-code", "not logged in")):
            for cols in ("60", "120"):
                with self.subTest(state=state, cols=cols), mock.patch.dict(os.environ, {"COLUMNS": cols}):
                    text = builtin_agent.no_creds_msg(state)
                    self.assertIn(want, text)
                    self.assertNotIn(absent, text)
                    self.assertIn("ANTHROPIC_API_KEY", text)
                    self.assertTrue(all(len(line) + 4 <= ui.width() for line in text.splitlines()), text)
                    rest = builtin_agent.no_creds_msg(state, headline=False)   # under another message
                    self.assertTrue(rest.startswith("  Options:"), rest)
                    self.assertNotIn("none were found", rest)


# ------------------------------------------------------------------------------------------------ agent templates

class TemplateTests(unittest.TestCase):
    def tearDown(self):
        secrets.set_strict(False)

    def test_codex_runs_outside_a_git_repository(self):
        tpl = agents.get("codex")["exec"]
        self.assertEqual(tpl[:3], ["codex", "exec", "--skip-git-repo-check"])
        filled = agents._fill(tpl, "P", None)
        self.assertIn("--skip-git-repo-check", filled)
        self.assertNotIn("--model", filled)
        self.assertEqual(filled[-1], "P")
        self.assertEqual(agents._fill(tpl, "P", "o3")[3:5], ["--model", "o3"])

    def test_model_placeholder_anywhere(self):
        f = agents._fill
        self.assertEqual(f(["a", "{model}", "{prompt}"], "T", None), ["a", "T"])
        self.assertEqual(f(["a", "{model}", "{prompt}"], "T", "m1"), ["a", "m1", "T"])
        self.assertEqual(f(["a", "--model={model}", "-p", "{prompt}"], "T", "m1"), ["a", "--model=m1", "-p", "T"])
        self.assertEqual(f(["a", "--model={model}", "-p", "{prompt}"], "T", None), ["a", "-p", "T"])
        self.assertEqual(f(["ollama", "run", "{model}", "{prompt}"], "T", None), ["ollama", "run", "T"])
        self.assertEqual(f(["{model}", "{prompt}"], "T", ""), ["", "T"])              # no IndexError
        self.assertEqual(f(["a", "-m", "{model}", "-p", "{prompt}"], "T", ""), ["a", "-p", "T"])
        self.assertEqual(f(["a", "-p", "{prompt}"], "use {model} and {prompt}", "m"), ["a", "-p", "use {model} and {prompt}"])
        self.assertEqual(f(["claude", "-p", "{prompt}", "--model", "{model}", "--x"], "hi", None), ["claude", "-p", "hi", "--x"])

    def test_custom_agent_with_model_after_the_binary_keeps_the_task(self):
        tmp = Path(tempfile.mkdtemp(prefix="cs-w3-agents-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "agents.json").write_text(json.dumps({"myagent": {"binary": "myagent", "exec": ["myagent", "{model}", "{prompt}"]}}))
        seen = []

        class _P:
            pid, returncode = 1, 0

            def __init__(self, cmd, **kw):
                seen.append(cmd)

            def wait(self, *a):
                return 0

            def poll(self):
                return 0
        with mock.patch.object(agents, "AGENTS_FILE", tmp / "agents.json"), \
                mock.patch.object(agents, "installed", return_value="/usr/local/bin/myagent"), \
                mock.patch.object(agents.subprocess, "Popen", _P), contextlib.redirect_stdout(io.StringIO()):
            rc = agents.run(agents.get("myagent"), "list my envs", None, interactive=False)
        self.assertEqual(rc, 0)
        self.assertEqual(seen[0], ["/usr/local/bin/myagent", "list my envs"])


class ClaudeBillingTests(_TmpHome):
    def test_a_vault_key_is_not_handed_to_a_logged_in_claude_code(self):
        spec = agents.get("claude")
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-" + "vault-000000000000000000"
        seen_env = []

        def status(cmd, **kw):
            seen_env.append(kw.get("env") or {})
            return types.SimpleNamespace(stdout=json.dumps({"loggedIn": True}), returncode=0)
        with mock.patch.dict(creds.APPLIED, {"ANTHROPIC_API_KEY": "sk-ant-" + "vault-000000000000000000"}), \
                mock.patch.object(agents.subprocess, "run", side_effect=status):
            keep, note = agents._agent_keys(spec, "/usr/local/bin/claude")
        self.assertNotIn("ANTHROPIC_API_KEY", keep)
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", keep)
        self.assertIn("own login", note)
        self.assertNotIn("ANTHROPIC_API_KEY", seen_env[0])       # asked without the key in its environment
        agents._CLAUDE_AUTH_CACHE.clear()
        with mock.patch.dict(creds.APPLIED, {"ANTHROPIC_API_KEY": "sk-ant-" + "vault-000000000000000000"}), \
                mock.patch.object(agents.subprocess, "run",
                                  return_value=types.SimpleNamespace(stdout=json.dumps({"loggedIn": False}), returncode=1)):
            keep, note = agents._agent_keys(spec, "/usr/local/bin/claude")
        self.assertIn("ANTHROPIC_API_KEY", keep)                  # its only way in: kept, and said so
        self.assertIn("billed", note)
        keep, note = agents._agent_keys(spec, "/usr/local/bin/claude")   # exported in the shell: the user's choice
        self.assertIn("ANTHROPIC_API_KEY", keep)
        self.assertIsNone(note)
        self.assertEqual(agents._agent_keys(agents.get("codex"), "codex"), (("OPENAI_API_KEY",), None))


class GrokTests(_TmpHome):
    def test_readiness_needs_a_key_not_just_the_settings_file(self):
        spec = agents.get("grok")
        self.assertFalse(agents.auth_ok(spec))
        d = self.tmp / ".grok"
        d.mkdir()
        (d / "user-settings.json").write_text(json.dumps({"baseURL": "https://api.x.ai/v1", "defaultModel": "grok-4-latest"}))
        self.assertFalse(agents.auth_ok(spec))                       # written by Grok's first start, keyless
        (d / "user-settings.json").write_text(json.dumps({"apiKey": "  "}))
        self.assertFalse(agents.auth_ok(spec))
        (d / "user-settings.json").write_text(json.dumps({"apiKey": "xai-abc"}))
        self.assertTrue(agents.auth_ok(spec))
        (d / "user-settings.json").write_text("not json")
        self.assertFalse(agents.auth_ok(spec))
        with mock.patch.dict(os.environ, {"GROK_API_KEY": "xai-abc"}):
            self.assertTrue(agents.auth_ok(spec))

    def test_skills_go_into_the_prompt_not_a_directory_grok_never_reads(self):
        spec = agents.get("grok")
        self.assertIsNone(spec["skills_dir"])
        self.assertTrue(spec["skills_in_prompt"])
        self.assertEqual(skills.state("grok"), "n/a")
        self.assertTrue(skills.installed("grok"))
        for project in (False, True):
            with self.assertRaises(ui.Abort) as cm:
                skills.target_dir("grok", None, project)
            self.assertIn("prompt", str(cm.exception))
        self.assertEqual(skills.target_dir("grok", str(self.tmp / "x"), False), self.tmp / "x")   # --dir still works
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            key, dest = skills.resolve_target("grok", None, False)   # `install skills` with grok selected
        self.assertEqual((key, dest), ("claude", skills.target_dir("claude", None, False)))
        self.assertIn("cannot load skills", out.getvalue())
        seen = []

        class _P:
            pid, returncode = 1, 0

            def __init__(self, cmd, **kw):
                seen.append(cmd)

            def wait(self, *a):
                return 0

            def poll(self):
                return 0
        os.environ["GROK_API_KEY"] = "xai-abc"
        prompt = headliner.plain("destroy my aws dev env", skills_in_prompt=True)
        self.assertIn("Follow the cloudseed skill included above", prompt)
        with mock.patch.object(agents, "installed", return_value="/usr/local/bin/grok"), \
                mock.patch.object(agents.subprocess, "Popen", _P), contextlib.redirect_stdout(io.StringIO()):
            agents.run(spec, prompt, None, interactive=False, task="destroy my aws dev env")
        sent = seen[0][seen[0].index("-p") + 1]
        self.assertTrue(sent.startswith(agents.SKILLS_INTRO))
        self.assertIn('<skill name="cloudseed">', sent)
        self.assertIn('<skill name="cloudseed-destroy">', sent)
        self.assertIn("cloudseed skill show <name>", sent)
        self.assertTrue(sent.rstrip().endswith("Task: destroy my aws dev env"))
        self.assertLess(len(sent), agents.MAX_PROMPT_CHARS)

    def test_bundle_shrinks_to_the_core_skill_when_too_long(self):
        full = skills.prompt_bundle("destroy aws gcp azure platform costs databricks how")
        core = skills.prompt_bundle("destroy aws gcp azure platform costs databricks how", max_chars=len(full) - 1)
        self.assertIn('<skill name="cloudseed">', core)
        self.assertNotIn('<skill name="cloudseed-aws">', core)
        self.assertIn("- cloudseed-aws:", core)


# ------------------------------------------------------------------------------------------------ files and vault

class DenyRuleTests(unittest.TestCase):
    def test_every_cloudseed_secret_file_is_denied(self):
        tmp = Path(tempfile.mkdtemp(prefix="cs-w3-deny-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        index = tmp / "workdirs.json"
        index.write_text(json.dumps({"aws-dev": str(tmp / "wd")}))
        with mock.patch.object(paths, "WORKDIRS_INDEX", index):
            rules = agents.claude_deny_rules()
        home = os.path.abspath(paths.HOME)
        for part in ("managed/**", "vmware.json", "helm/**", "mcp/**", "envs/*/vpn/**", "envs/*/platform/**",
                     "credentials.json", "sessions/**", "ui/token"):
            with self.subTest(part=part):
                self.assertIn(f"Read(/{home}/{part})", rules)
        wd = os.path.abspath(tmp / "wd")
        for part in ("vpn/**", "platform/**", "ssh/**", "k8s/**"):
            self.assertIn(f"Read(/{wd}/{part})", rules)
        self.assertIn("Read(**/*.ovpn)", rules)


class VaultNameTests(unittest.TestCase):
    REFUSED = ["ANSIBLE_SSH_ARGS", "ANSIBLE_SSH_EXECUTABLE", "ANSIBLE_CALLBACK_PLUGINS", "ANSIBLE_LIBRARY",
               "ANSIBLE_VAULT_PASSWORD_FILE", "CLOUDSDK_PYTHON", "OPENSSL_CONF", "OPENSSL_MODULES", "KUBECTL_EXTERNAL_DIFF",
               "KUBE_EDITOR", "GCONV_PATH", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS", "TF_LOG", "TF_LOG_PATH",
               "TF_REATTACH_PROVIDERS", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "HTTPS_PROXY", "http_proxy", "ALL_PROXY",
               "NO_PROXY", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "GIT_PROXY_COMMAND", "GIT_SSH_COMMAND",
               "GIT_TEMPLATE_DIR", "BROWSER", "SHELLOPTS", "PS4", "SSLKEYLOGFILE", "SSL_KEYLOG_FILE", "NETRC",
               "GOTOOLCHAIN", "ARM_METADATA_HOSTNAME", "DOCKER_HOST", "LESSOPEN", "CURL_HOME", "MY_API_ENDPOINT"]
    ALLOWED = ["GITLAB_RUNNER_TOKEN", "GOOGLE_CREDENTIALS", "GOOGLE_PROJECT", "DATABRICKS_HOST", "DATABRICKS_TOKEN",
               "VMREST_USER", "ARM_USE_OIDC", "ARM_CLIENT_CERTIFICATE_PATH", "MY_TOKEN", "UBUNTU_PRO_TOKEN",
               "SNOWFLAKE_PASSWORD", "AWS_PROFILE"]

    def test_denylist(self):
        for k in self.REFUSED:
            with self.subTest(key=k):
                self.assertFalse(creds.valid_key(k))
        for k in self.ALLOWED:
            with self.subTest(key=k):
                self.assertTrue(creds.valid_key(k))

    def test_names_stored_earlier_are_ignored_now(self):
        tmp = Path(tempfile.mkdtemp(prefix="cs-w3-vault-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        store = tmp / "credentials.json"
        store.write_text(json.dumps({"ANSIBLE_SSH_ARGS": "-o ProxyCommand=touch /tmp/x", "MY_TOKEN": "abc"}))
        with mock.patch.object(creds, "STORE", store), mock.patch.object(creds, "GCP_FILE", tmp / "gcp.json"):
            self.assertEqual(creds.env(), {"MY_TOKEN": "abc"})
            rows = {r["key"]: r for r in creds.masked()}
        self.assertTrue(rows["ANSIBLE_SSH_ARGS"].get("ignored"))

    def test_google_credentials_must_be_a_whole_key_file(self):
        with self.assertRaises(ValueError):
            creds.check_value("GOOGLE_CREDENTIALS", "{")
        with self.assertRaises(ValueError):
            creds.check_value("GOOGLE_CREDENTIALS", '{"private_key": "x"}')   # no "type"
        for t in ("service_account", "authorized_user", "external_account"):
            self.assertTrue(creds.check_value("google_credentials", json.dumps({"type": t})))
        self.assertEqual(creds.check_value("GOOGLE_CREDENTIALS", ""), "")      # empty: remove
        self.assertEqual(creds.check_value("AWS_SECRET_ACCESS_KEY", "{"), "{")
        tmp = Path(tempfile.mkdtemp(prefix="cs-w3-vault-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "c.json").write_text(json.dumps({"GOOGLE_CREDENTIALS": "{"}))
        with mock.patch.object(creds, "STORE", tmp / "c.json"), mock.patch.object(creds, "GCP_FILE", tmp / "g.json"):
            rows = {r["key"]: r for r in creds.masked()}
        self.assertIn("not valid JSON", rows["GOOGLE_CREDENTIALS"]["hint"])


# ------------------------------------------------------------------------------------------------ headliner

class HeadlinerTests(unittest.TestCase):
    def test_malformed_environment_fields_do_not_break_the_brief(self):
        env_ok = types.SimpleNamespace(id="aws-dev", dir=Path("/nonexistent/aws-dev"))
        cases = [
            ({"name": "a", "allowed_ssh_cidrs": None, "vars": [], "state": "local"}, "ssh_from= "),
            ({"name": "a", "allowed_ssh_cidrs": [1, 2], "vars": None, "state": None}, "ssh_from=1,2 "),
            ({"name": "a", "allowed_ssh_cidrs": "1.2.3.4/32", "vars": {"profile": "p", "k": 1}}, "ssh_from=1.2.3.4/32 "),
        ]
        for cfg, want in cases:
            env = types.SimpleNamespace(**vars(env_ok), load=lambda cfg=cfg: cfg)
            with self.subTest(cfg=cfg), mock.patch.object(paths.Env, "list_all", return_value=[env]), \
                    mock.patch.object(headliner.deps, "status", return_value=[]), \
                    mock.patch.object(headliner.clouds, "get") as get:
                get.return_value.credential_warnings.return_value = []
                brief = headliner.build("list envs", {})
                self.assertIn("- aws-dev: name=a", brief)
                self.assertIn(want, brief)
                self.assertNotIn("'profile'", brief)
                self.assertTrue(brief.rstrip().endswith("list envs"))
        self.assertIn("{'k': 1}", headliner._env_line("x", cases[2][0], {}))

    def test_plain_prompt_wording(self):
        self.assertIn("Use the `cloudseed` skill", headliner.plain("x"))
        self.assertNotIn("Use the `cloudseed` skill", headliner.plain("x", skills_in_prompt=True))


# ------------------------------------------------------------------------------------------------ redaction

class RedactionTests(unittest.TestCase):
    def setUp(self):
        secrets.set_strict(False)
        self.addCleanup(secrets.set_strict, False)

    def test_gaps_are_closed(self):
        azure = "Abc8Q~" + "a" * 20 + "B" * 14
        cases = {
            "token ya29." + "c.c0ASRK0GYabcdefghijklmnopqrstuvwxyz0123456789.seg_2-x done.": "ya29.c",
            "user ya29." + "a0AfH6SMBxyzabcdefghijklmnop123456. End.": "ya29.a0",
            f"secret {azure} ok": azure,
            "client GOCSPX-" + "abcdefghijklmnopqrstuvwxyz12": "GOCSPX-",
            "curl -u admin:" + "hunter2hunter2 https://x": "hunter2",
            "curl --user=admin:" + "s3cret https://x": "s3cret",
            '{"auths":{"ghcr.io":{"auth":"' + 'dXNlcjpwYXNzd29yZA=="}}}': "dXNlcjpwYXNzd29yZA",
            '    "auth": "' + 'dXNlcjpwYXNzd29yZA==",': "dXNlcjpwYXNzd29yZA",
        }
        for text, secret in cases.items():
            with self.subTest(text=text):
                out = secrets.redact(text)
                self.assertNotIn(secret, out)
                self.assertIn(R, out)
        self.assertEqual(secrets.redact("user ya29." + "a0AfH6SMBxyzabcdefghijklmnop123456. End."), f"user {R}. End.")
        self.assertIn("curl -u admin:", secrets.redact("curl -u admin:" + "hunter2hunter2 https://x"))
        for text in ("docker run -u 1000:1000 img", "auth: enabled", "see https://example.com/path.", "ya29.short",
                     '{"auth": "disabled"}', '{"auth":"serviceaccount"}', '"auth": "YWJjZGVm"'):   # not user:password
            self.assertEqual(secrets.redact(text), text)

    def test_compact_json_secrets(self):
        secret = ('{"apiVersion":"v1","data":{"config.json":"eyJhYmMiOiJkZWYifQ==","database-url":'
                  '"cG9zdGdyZXM6Ly9hZG1pbjpodW50ZXIyQGRi"},"kind":"Secret","metadata":{"name":"x"}}')
        out = secrets.redact(secret)
        self.assertNotIn("cG9zdGdyZXM", out)
        self.assertNotIn("eyJhYmMi", out)
        self.assertEqual(json.loads(out)["data"], {"config.json": R, "database-url": R})
        lst = '{"kind":"SecretList","apiVersion":"v1","items":[{"metadata":{"name":"a"},"data":{"u":"YWRtaW4="},"type":"Opaque"}]}'
        self.assertNotIn("YWRtaW4", secrets.redact(lst))
        annotation = ('    kubectl.kubernetes.io/last-applied-configuration: |\n      {"apiVersion":"v1","data":{"password":'
                      '"aHVudGVyMg=="},"kind":"Secret","metadata":{"annotations":{},"name":"db"}}\n')
        self.assertNotIn("aHVudGVyMg", secrets.redact(annotation))
        escaped = ('"kubectl.kubernetes.io/last-applied-configuration": "{\\"apiVersion\\":\\"v1\\",\\"data\\":'
                   '{\\"password\\":\\"aHVudGVyMg==\\"},\\"kind\\":\\"Secret\\"}\\n"')
        self.assertNotIn("aHVudGVyMg", secrets.redact(escaped))
        red = secrets.StreamRedactor()
        self.assertNotIn("cG9zdGdyZXM", red.feed(secret + "\n"))
        cm = '{"apiVersion":"v1","data":{"index.html":"PGh0bWw+"},"kind":"ConfigMap"}'
        self.assertEqual(secrets.redact(cm), cm)                          # only Secrets
        data_map = '{"db-url":"aHVudGVyMg==","user":"YWRtaW4x"}'         # -o jsonpath={.data}
        self.assertEqual(secrets.redact(data_map), data_map)              # the user's own terminal
        secrets.set_strict(True)
        self.assertNotIn("aHVudGVyMg", secrets.redact(data_map))          # what an agent reads

    def test_authorization_headers_for_files_on_disk(self):
        h = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"
        self.assertEqual(secrets.redact(h), h)                            # the terminal/console default is unchanged
        self.assertEqual(secrets.redact(h, auth=True), f"Authorization: Bearer {R}")
        self.assertIn(R, secrets.redact("curl -HAuthorization: Basic dXNlcjpwYXNzd29yZA== x", auth=True))
        self.assertEqual(secrets.mask_argv(["curl", "-H", h], auth=True)[2], f"Authorization: Bearer {R}")
        self.assertIn(R, secrets.StreamRedactor(auth=True).feed("> " + h + "\n"))
        self.assertNotIn(R, secrets.StreamRedactor().feed("> " + h + "\n"))


# ------------------------------------------------------------------------------------------------ skills installs

class ForeignSkillTests(_TmpHome):
    def test_automatic_installs_leave_someone_elses_directory_alone(self):
        dest = skills.target_dir("claude", None, False)
        mine = dest / "cloudseed-aws"
        mine.mkdir(parents=True)
        (mine / "SKILL.md").write_text("---\nname: my-own-aws\n---\nmine\n")
        with self.assertRaises(ui.Abort):
            skills.install(None, dest)                                    # explicit installs stay all-or-nothing
        self.assertFalse((dest / "cloudseed").exists())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            done = skills.install(None, dest, skip_foreign=True)
        self.assertIn("Left", err.getvalue())
        self.assertNotIn(mine, done)
        self.assertEqual((mine / "SKILL.md").read_text(), "---\nname: my-own-aws\n---\nmine\n")
        self.assertTrue((dest / "cloudseed" / "SKILL.md").exists())
        self.assertEqual(skills.state("claude"), "partial")
        self.assertTrue(skills.installed("claude"))                       # no reinstall on every run
        self.assertEqual(skills.foreign("claude"), ["cloudseed-aws"])


# ------------------------------------------------------------------------------------------------ cs agents page

class AgentsPageTests(unittest.TestCase):
    def test_page_wraps_and_names_the_real_agents_file(self):
        tmp = Path(tempfile.mkdtemp(prefix="cs-w3-page-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        for cols in ("60", "80", "44"):
            with self.subTest(cols=cols), mock.patch.dict(os.environ, {"COLUMNS": cols}), \
                    mock.patch.object(agents, "AGENTS_FILE", tmp / "agents.json"):
                page = _ANSI.sub("", agents.agents_page({"agent": "builtin"}))
                width = ui.width()
                long = [line for line in page.splitlines() if len(line) > width]
                self.assertEqual(long, [], page)
                self.assertIn("status", page)
                self.assertIn("claude", page)
                flat = re.sub(r"\s+", "", page)
                self.assertIn(re.sub(r"\s+", "", str(tmp / "agents.json")), flat)
                self.assertIn("cloudseed help agentic", page)
        self.assertEqual(agents._home_path(Path.home() / ".cloudseed" / "agents.json"), "~/.cloudseed/agents.json")
        self.assertEqual(agents._home_path("/opt/cs/agents.json"), "/opt/cs/agents.json")


if __name__ == "__main__":
    unittest.main()
