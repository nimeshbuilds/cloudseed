"""Explicit bastion/host Kubernetes context: no Terraform state or implicit retargeting."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cs-local-context-"))
from cloudseed import builtin_agent, cli, mcp, ui

CONTEXT = {"current-context": "bastion-authorized", "clusters": [{"name": "cluster", "cluster": {"server": "https://private.example:443"}}]}


class LocalContextTests(unittest.TestCase):
    def parse(self, words):
        with contextlib.redirect_stderr(io.StringIO()):
            return cli.build_parser().parse_args(words)

    def test_mode_is_explicit_and_rejects_environment_selectors(self):
        for tool in ("kubectl", "helm", "k9s"):
            args = self.parse([tool, "--local-context", "--", "--context", "chosen", "get", "pods"])
            self.assertTrue(args.local_context)
            self.assertTrue(args.tool_verbatim)
            self.assertEqual(args.tool_args, ["--context", "chosen", "get", "pods"])
            self.assertFalse(self.parse([tool, "--", "--local-context"]).local_context)
            for selectors in (["aws"], ["--env", "dev"], ["gcp", "--env=dev"]):
                with self.assertRaises(SystemExit):
                    self.parse([tool, "--local-context", *selectors, "get", "pods"])

    def test_host_clients_use_native_configuration_without_environment_or_undo(self):
        for tool, words in (("kubectl", ["get", "pods", "-A"]), ("helm", ["list", "-A"]), ("k9s", [])):
            args = self.parse([tool, "--local-context", *words])
            with mock.patch.object(cli, "_resolve_cluster_env", side_effect=AssertionError("must not select env")), \
                 mock.patch.object(cli, "_pre_change_undo", side_effect=AssertionError("no managed undo")), \
                 mock.patch.object(cli.services, "ensure_tool", side_effect=lambda name, *a, **kw: "/tools/" + name), \
                 mock.patch.object(cli.deps, "path_env", return_value={"PATH": "/tools", "KUBECONFIG": "/private/user-config"}), \
                 mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
                 mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(CONTEXT), "")), \
                 mock.patch.object(cli.subprocess, "call", return_value=7) as call, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.cmd_ktool(args, {"current_env": "aws-unrelated"}), 7)
                self.assertEqual(call.call_args.args[0], ["/tools/" + tool, *words])
                self.assertEqual(call.call_args.kwargs["env"]["KUBECONFIG"], "/private/user-config")

    def test_selected_kubeconfig_and_context_are_validated(self):
        for tool, flag in (("kubectl", "--context"), ("helm", "--kube-context"), ("k9s", "--context")):
            args = self.parse([tool, "--local-context", "--kubeconfig=/safe/config", flag, "chosen", "get", "pods"])
            with mock.patch.object(cli.services, "ensure_tool", return_value="kubectl"), \
                 mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
                 mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(CONTEXT), "")) as run, \
                 mock.patch.object(cli.subprocess, "call", return_value=0), contextlib.redirect_stderr(io.StringIO()):
                cli.cmd_ktool(args, {})
                self.assertEqual(run.call_args.args[0][-4:], ["--kubeconfig", "/safe/config", "--context", "chosen"])
                self.assertNotIn("--raw", run.call_args.args[0])

    def test_missing_malformed_or_failed_context_stops_before_cluster_command(self):
        for output, rc in (("{}", 0), ("[]", 0), ("bad-json", 0), (json.dumps(CONTEXT), 1),
                           (json.dumps({"current-context": "named", "clusters": [{"cluster": []}]}), 0)):
            args = self.parse(["kubectl", "--local-context", "delete", "pod", "example"])
            with mock.patch.object(cli.services, "ensure_tool", return_value="kubectl"), \
                 mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
                 mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], rc, output, "secret-error-data")), \
                 mock.patch.object(cli.subprocess, "call") as call:
                with self.assertRaises(ui.Abort) as ex:
                    cli.cmd_ktool(args, {})
                self.assertIn("No usable Kubernetes context", ex.exception.msg)
                self.assertNotIn("secret-error-data", ex.exception.msg)
                call.assert_not_called()

    def test_helm_environment_context_is_used_and_explicit_context_takes_precedence(self):
        for override, expected in (([], "from-environment"), (["--kube-context", "explicit"], "explicit")):
            with mock.patch.object(cli.services, "ensure_tool", return_value="kubectl"), \
                 mock.patch.object(cli.deps, "path_env", return_value={"HELM_KUBECONTEXT": "from-environment"}), \
                 mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
                 mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(CONTEXT), "")) as run, \
                 mock.patch.object(cli.subprocess, "call", return_value=0), contextlib.redirect_stderr(io.StringIO()):
                cli.cmd_ktool(self.parse(["helm", "--local-context", *override, "list"]), {})
                self.assertEqual(run.call_args.args[0][-2:], ["--context", expected])

    def test_insecure_effective_endpoints_and_tls_overrides_are_refused(self):
        cases = [("kubectl", ["--server=http://private.example"], {}, CONTEXT),
                 ("kubectl", ["-s", "http://private.example"], {}, CONTEXT),
                 ("kubectl", ["-shttp://private.example"], {}, CONTEXT),
                 ("kubectl", ["-s=http://private.example"], {}, CONTEXT),
                 ("kubectl", ["-Ashttp://private.example"], {}, CONTEXT),
                 ("kubectl", ["-As=http://private.example"], {}, CONTEXT),
                 ("kubectl", ["-As", "http://private.example"], {}, CONTEXT),
                 ("kubectl", ["--server=https://private.example", "-Ashttp://private.example"], {}, CONTEXT),
                 ("kubectl", ["--server=https://private.example", "-shttp://private.example"], {}, CONTEXT),
                 ("kubectl", ["-shttps://private.example", "--server=http://private.example"], {}, CONTEXT),
                 ("kubectl", ["--insecure-skip-tls-verify=true"], {}, CONTEXT),
                 ("kubectl", ["--insecure_skip_tls_verify=true"], {}, CONTEXT),
                 ("helm", [], {"HELM_KUBEAPISERVER": "http://private.example"}, CONTEXT),
                 ("helm", [], {"HELM_KUBEINSECURE_SKIP_TLS_VERIFY": "true"}, CONTEXT),
                 ("k9s", [], {}, {**CONTEXT, "clusters": [{"cluster": {"server": "https://private.example", "insecure-skip-tls-verify": True}}]}),
                 ("kubectl", ["--insecure-skip-tls-verify=false"], {}, {**CONTEXT, "clusters": [{"cluster": {"server": "https://private.example", "insecure-skip-tls-verify": True}}]}),
                 ("helm", [], {"HELM_KUBEINSECURE_SKIP_TLS_VERIFY": "false"}, {**CONTEXT, "clusters": [{"cluster": {"server": "https://private.example", "insecure-skip-tls-verify": True}}]})]
        for tool, flags, env, context in cases:
            with mock.patch.object(cli.services, "ensure_tool", return_value=tool), \
                 mock.patch.object(cli.deps, "path_env", return_value=env), \
                 mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
                 mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(context), "")), \
                 mock.patch.object(cli.subprocess, "call") as call:
                with self.assertRaises(ui.Abort) as ex:
                    cli.cmd_ktool(self.parse([tool, "--local-context", *flags, "get", "pods"]), {})
                self.assertIn("TLS certificate verification", ex.exception.msg)
                call.assert_not_called()

    def test_cluster_override_requires_a_complete_context(self):
        for tool in ("kubectl", "k9s"):
            with mock.patch.object(cli.services, "ensure_tool", return_value=tool), \
                 mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
                 mock.patch.object(cli.subprocess, "run") as run, \
                 mock.patch.object(cli.subprocess, "call") as call:
                with self.assertRaises(ui.Abort) as ex:
                    cli.cmd_ktool(self.parse([tool, "--local-context", "--cluster", "other", "get", "pods"]), {})
                self.assertIn("complete context", ex.exception.msg)
                run.assert_not_called()
                call.assert_not_called()

    def test_secure_endpoint_alias_precedence_and_explicit_tls_verification(self):
        for flags in (["-shttp://unused.example", "--server=https://private.example"],
                      ["-Ashttp://unused.example", "--server=https://private.example"],
                      ["--server=http://unused.example", "-Ashttps://private.example"],
                      ["--server=http://unused.example", "-s=https://private.example"],
                      ["--insecure-skip-tls-verify=false"]):
            context = CONTEXT
            with mock.patch.object(cli.services, "ensure_tool", return_value="kubectl"), \
                 mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
                 mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(context), "")), \
                 mock.patch.object(cli.subprocess, "call", return_value=0) as call, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.cmd_ktool(self.parse(["kubectl", "--local-context", *flags, "get", "pods"]), {}), 0)
                call.assert_called_once()

    def test_agent_output_and_streaming_restrictions_are_preserved(self):
        with mock.patch.object(cli.secrets, "redact_enabled", return_value=True), mock.patch.object(cli, "_local_ktool") as run:
            for words in (["kubectl", "--local-context", "logs", "pod", "-f"], ["k9s", "--local-context"]):
                with self.assertRaises(ui.Abort):
                    cli.cmd_ktool(self.parse(words), {})
            run.assert_not_called()
        with mock.patch.object(cli.services, "ensure_tool", return_value="kubectl"), \
             mock.patch.object(cli.secrets, "redact_enabled", return_value=True), \
             mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(CONTEXT), "")), \
             mock.patch.object(cli.secrets, "run_redacted", return_value=0) as redacted, \
             mock.patch.object(cli.subprocess, "call", side_effect=AssertionError("unredacted output")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_ktool(self.parse(["kubectl", "--local-context", "get", "pods"]), {}), 0)
            redacted.assert_called_once()

    def test_mcp_and_builtin_agent_require_confirmation_even_for_host_context_reads(self):
        for tool, words in (("kubectl", "get pods"), ("helm", "list -A")):
            name = "cloudseed_" + tool
            args = {"args": words, "local_context": True}
            with mock.patch.object(mcp, "_run", return_value={"ran": True}) as run:
                blocked = mcp.call_tool(name, args, {})
                self.assertTrue(blocked["isError"])
                self.assertIn("local_context", blocked["content"][0]["text"])
                run.assert_not_called()
                self.assertEqual(mcp.call_tool(name, dict(args, confirm=True), {}), {"ran": True})
                self.assertEqual(run.call_args.args[1], [tool, "--local-context", "--", *words.split()])
            ns = self.parse([tool, "--local-context", *words.split()])
            self.assertIn("--local-context", builtin_agent._approval_reason(ns))
            for extra in ({"cloud": "aws"}, {"env": "prod"}, {"args": "gcp --env prod " + words}):
                with self.assertRaises(ValueError):
                    mcp.TOOLS[name]["argv"]({**args, **extra})

    def test_normal_managed_environment_path_is_unchanged(self):
        args = self.parse(["kubectl", "get", "pods"])
        with mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
             mock.patch.object(cli, "_local_ktool", side_effect=AssertionError("implicit host context")), \
             mock.patch.object(cli, "_resolve_cluster_env", side_effect=ui.Abort("managed selection")):
            with self.assertRaisesRegex(ui.Abort, "managed selection"):
                cli.cmd_ktool(args, {})


if __name__ == "__main__":
    unittest.main()
