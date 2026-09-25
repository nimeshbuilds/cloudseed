"""Wave-4 regression tests for cloudseed/mcp.py: kubectl/helm calls gated by the built-in agent's fail-closed reader
(builtin_agent.kube_approval) and cluster selectors written into args, the stream refusal in the texts, setup/provision
switches and tag keys, the managed tool's environment, purge/scan/ttl/env descriptions, JSON tools with stderr kept
apart, serve_http (ports out of range, service runs, the foreground URL), the login service definition (ProcessType
Interactive, the service marker) and the guide's disabled note. Stdlib only, no network, temp dirs; launchctl/systemctl
are always mocked (nothing reaches the real per-user launchd domain)."""
import contextlib
import io
import json
import os
import plistlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, mcp, webui  # noqa: E402
from cloudseed.cli import build_parser, normalize_argv  # noqa: E402


def _text(result: dict) -> str:
    return result["content"][0]["text"]


def _call(name: str, args: dict) -> dict:
    """call_tool without running anything: the tool result, or {'argv': [...]} when it would have run."""
    ran = {}

    def fake_run(_name, argv, _env, call=None, progress=None):
        ran["argv"] = argv
        return mcp._result("ran", False)
    with mock.patch.object(mcp, "_run", side_effect=fake_run):
        res = mcp.call_tool(name, args, {})
    return ran if ran else res


def _parse(argv):
    with contextlib.redirect_stderr(io.StringIO()):
        return build_parser().parse_args(normalize_argv(list(argv)))


# ------------------------------------------------------------------------------------------------ kubectl / helm reader
class KubeGateTests(unittest.TestCase):                                 # a2-mcp#0 (agentic needs_other): one shared reader
    # the case lists of test_wave3_agentic.KubeReaderTests, as MCP calls ("kubectl <args>" / "helm <args>")
    APPROVAL = [
        "kubectl --cache-dir get delete ns prod", "kubectl --profile-output get apply -f x.yaml",
        "kubectl --tls-server-name get delete pod x", "helm --repository-cache list uninstall rel",
        "helm --registry-config status get values monitoring", "kubectl --cache-dir describe get secret x -o yaml",
        "kubectl --cache-dir version config view --raw", "kubectl --foo get delete ns prod", "kubectl -A get pods",
        "kubectl get --raw=/api/v1/namespaces/default/secrets", "kubectl get --raw=/api/v1/secrets?limit=1",
        "kubectl get --raw=/api/v1/namespaces/default/%73ecrets", "kubectl get --raw /livez/../api/v1/secrets",
        "kubectl aws --env dev get --raw=/api/v1/secrets", "kubectl get -- secrets", "kubectl get pods,secrets",
        "kubectl get pods --server https://x", "kubectl get pods -s https://x", "kubectl get pods -As https://x",
        "kubectl get pods --insecure-skip-tls-verify", "kubectl get pods --kubeconfig /tmp/k", "kubectl get pods --as admin",
        "kubectl get -f https://x/s.yaml", "kubectl get -Rf ./dir", "kubectl describe -k ./dir",
        "kubectl cluster-info dump --output-directory=/tmp/x", "kubectl get pods -o go-template-file=/etc/passwd",
        "kubectl get pods -ogo-template-file=/etc/passwd", "helm list --kube-apiserver https://x",
        "helm template x c --output-dir /tmp/y", "helm lint ./c", "helm status x -o json", "helm status x -ojson",
        "helm status x -o=yaml", "helm status x --output json", "helm status x --output=yaml",
        "helm status x --revision 2 -o json", "helm get --all values x", "helm get values x", "helm get",
        "helm repo add a https://b", "kubectl --context other get pods", "helm --kube-context other list",
    ]
    NO_APPROVAL = [
        "kubectl aws --env dev get pods", "kubectl --cache-dir=/tmp/c get pods", "kubectl -n shop get pods",
        "kubectl -nshop get pods", "kubectl -v 6 get pods", "helm aws --env dev list -A", "kubectl get pods",
        "kubectl describe secret x", "kubectl logs -p -c app pod", "kubectl get --raw /healthz",
        "kubectl get --raw=/readyz?verbose", "kubectl get ns -o jsonpath={.items[*].metadata.name}", "helm list -A",
        "helm get notes x", "helm status x", "helm status x -o table", "helm history x -o json",
        "helm get metadata x -o json", "helm repo list",
    ]

    @staticmethod
    def split(cmd: str):
        tool, _, args = cmd.partition(" ")
        return f"cloudseed_{tool}", {"args": args}

    def test_the_shared_reader_decides(self):
        for cmd in self.APPROVAL:
            with self.subTest(cmd=cmd):
                name, a = self.split(cmd)
                if not a["args"]:
                    continue
                self.assertTrue(mcp._is_destructive(mcp.TOOLS[name], a))
                r = _call(name, a)
                self.assertTrue(r.get("isError"))
                self.assertIn("confirm=true", _text(r))
                self.assertIn("argv", _call(name, dict(a, confirm=True)))
        for cmd in self.NO_APPROVAL:
            with self.subTest(cmd=cmd):
                name, a = self.split(cmd)
                self.assertFalse(mcp._is_destructive(mcp.TOOLS[name], a))
                self.assertIn("argv", _call(name, a))

    def test_the_console_gate_follows(self):
        with self.assertRaises(webui.NeedsConfirm):
            webui.build_argv("cloudseed_kubectl", {"args": "get pods --server https://evil.example"})
        with self.assertRaises(webui.NeedsConfirm):
            webui.build_argv("cloudseed_helm", {"args": "template x ./chart"})
        self.assertEqual(webui.build_argv("cloudseed_kubectl", {"args": "get pods -A"}), ["kubectl", "--", "get", "pods", "-A"])

    def test_the_refusal_names_the_real_reason(self):
        self.assertIn("--server", _text(_call("cloudseed_kubectl", {"args": "get pods --server https://x"})))
        self.assertIn("get --raw", _text(_call("cloudseed_kubectl", {"args": "get --raw /api/v1/secrets"})))
        self.assertIn("kubectl delete", _text(_call("cloudseed_kubectl", {"args": "--cache-dir get delete ns prod"})))
        self.assertIn("helm template", _text(_call("cloudseed_helm", {"args": "template x ./c"})))
        # a tool without its own reason still gets its rule
        self.assertIn("apply=true", _text(_call("cloudseed_setup", {"cloud": "aws", "apply": True})))

    def test_the_old_copies_are_gone(self):
        for name in ("_positionals", "_KUBECTL_VALUE_FLAGS", "_KUBECTL_READ", "_SECRET_WORD", "_HELM_VALUE_FLAGS", "_HELM_READ", "_helm_outputs"):
            self.assertFalse(hasattr(mcp, name), name)

    def test_texts_name_the_gates(self):
        k, h = mcp.TOOLS["cloudseed_kubectl"]["confirm_when"], mcp.TOOLS["cloudseed_helm"]["confirm_when"]
        for part in ("get of Secrets", "get --raw", "another server, identity or local file", "--context", "-o *-file"):
            self.assertIn(part, k)
        for part in ("status -o json/yaml", "get values/all/manifest/hooks", "template/lint", "another server, identity or local file"):
            self.assertIn(part, h)
        guide = json.dumps(mcp.guide_lines(None), ensure_ascii=False)
        for part in ("helm status -o json/yaml", "helm template/lint", "kubectl get --raw", "another server, identity or local file"):
            self.assertIn(part, guide)
        self.assertIn("template/lint", mcp.__doc__)
        self.assertIn("kube_approval", mcp.__doc__)


class KubeSelectorInArgsTests(unittest.TestCase):                       # a2-mcp#1 hardening
    def test_selectors_in_args_are_moved_in_front_of_the_separator(self):
        cases = (({"args": "aws --env dev get pods"}, ["kubectl", "aws", "--env", "dev", "--", "get", "pods"]),
                 ({"args": "-- gcp -eprod get pods -A"}, ["kubectl", "gcp", "--env", "prod", "--", "get", "pods", "-A"]),
                 ({"args": "--env=lab get pods", "cloud": "vmware"}, ["kubectl", "vmware", "--env", "lab", "--", "get", "pods"]),
                 ({"args": "aws get pods", "cloud": "aws"}, ["kubectl", "aws", "--", "get", "pods"]),
                 # any order, and a selector after the first `--` (as `cs kubectl --env dev aws ...` / `aws -- --env prod` read)
                 ({"args": "--env dev aws get pods"}, ["kubectl", "aws", "--env", "dev", "--", "get", "pods"]),
                 ({"args": "aws -- --env prod get pods"}, ["kubectl", "aws", "--env", "prod", "--", "get", "pods"]),
                 ({"args": "exec pod -- env -e x"}, ["kubectl", "--", "exec", "pod", "--", "env", "-e", "x"]))
        for a, want in cases:
            with self.subTest(a=a):
                self.assertEqual(mcp.TOOLS["cloudseed_kubectl"]["argv"](a), want)
                ns = _parse(want)
                self.assertEqual(ns.tool_args, want[want.index("--") + 1:])

    def test_a_contradiction_or_a_repeat_is_refused(self):
        for a in ({"args": "aws get pods", "cloud": "gcp"}, {"args": "--env lab get pods", "env": "prod"},
                  {"args": "aws --env dev gcp get pods"}, {"args": "--env dev --env prod get pods"}, {"args": "-e=x get pods"}):
            with self.subTest(a=a):
                r = _call("cloudseed_kubectl", dict(a, confirm=True))
                self.assertTrue(r.get("isError"))
                self.assertIn("invalid arguments", _text(r))
                self.assertTrue(mcp._is_destructive(mcp.TOOLS["cloudseed_kubectl"], a))    # fail closed
        with self.assertRaises(ValueError):
            webui.build_argv("cloudseed_helm", {"args": "aws list -A", "cloud": "gcp"})

    def test_extra_separators_cannot_hide_a_selector(self):
        # cmd_ktool drops one more `--` after cloudseed's own and then reads a cloud key / --env again: with three `--`
        # in args, 'aws --env prod' used to reach it and win over the fields (a confirmed delete ran on aws-prod)
        for a in ({"cloud": "vmware", "env": "lab", "args": "-- -- -- aws --env prod delete ns shop", "confirm": True},
                  {"cloud": "vmware", "args": "-- -- -- aws get pods"}, {"args": "-- -- -- --env prod get pods"},
                  {"cloud": "vmware", "args": "-- -- aws get pods"}):
            with self.subTest(a=a):
                r = _call("cloudseed_kubectl", a)
                self.assertTrue(r.get("isError"))
                self.assertIn("invalid arguments", _text(r))
        # whatever reaches the CLI: it picks the cluster of the fields, and the gate read the words the tool gets
        from cloudseed import builtin_agent
        for args in ("-- -- get pods", "-- -- -- -- get pods", "-- -- -- -- -- --env x get pods", "-- delete ns x"):
            with self.subTest(args=args):
                a = {"cloud": "vmware", "env": "lab", "args": args}
                ns = _parse(mcp.TOOLS["cloudseed_kubectl"]["argv"](a))
                self.assertEqual((ns.cloud, ns.env), ("vmware", "lab"))
                rest = cli._strip_leading_sep(ns.tool_args)
                self.assertFalse(rest[:1] and rest[0] in cli.CLOUD_KEYS)
                self.assertEqual(cli._pull_env_arg(ns, list(rest)), rest)
                self.assertEqual(builtin_agent._tool_rest(mcp._kube_words(a)[2]), cli._strip_leading_sep(rest))


class StreamRefusalTextTests(unittest.TestCase):                        # a2-mcp#8, cli-cluster
    def test_the_description_and_the_guide_warn(self):
        d = mcp.TOOLS["cloudseed_kubectl"]["description"]
        for part in ("Over MCP", "port-forward", "proxy", "attach", "logs -f", "get -w", "--tail", "--since", "--timeout", "exec"):
            self.assertIn(part, d)     # (the console's own jobs are not agent sessions: they may follow a log)
        guide = json.dumps(mcp.guide_lines(None), ensure_ascii=False)
        self.assertIn("port-forward, proxy and attach", guide)
        self.assertIn("logs --tail/--since", guide)

    def test_the_cli_refuses_them_in_an_agent_session(self):     # what the text promises is what cmd_ktool does
        for rest in (["logs", "-f", "pod/x"], ["get", "pods", "-w"], ["port-forward", "svc/x", "80"], ["proxy"], ["attach", "p"]):
            self.assertIsNotNone(cli._never_ends("kubectl", rest), rest)
        self.assertIsNotNone(cli._needs_terminal("kubectl", ["exec", "-it", "p", "--", "sh"]))
        self.assertIsNone(cli._never_ends("kubectl", ["logs", "--tail=200", "pod/x"]))


# ------------------------------------------------------------------------------------------------ setup / provision
class SetupProvisionTests(unittest.TestCase):                           # a2-ansible#4, a2-webui-functional#8
    def test_setup_switches_reach_the_cli(self):
        a = {"cloud": "aws", "env": "dev", "apply": True, "confirm": True, "no_provision": True, "no_harden": True,
             "no_firewall": True, "no_tools": True}
        ns = _parse(_call("cloudseed_setup", a)["argv"])
        self.assertTrue(ns.no_provision and ns.no_harden and ns.no_firewall and ns.no_tools and ns.auto_approve)
        ns = _parse(_call("cloudseed_setup", {"cloud": "aws", "no_harden": False})["argv"])
        self.assertFalse(ns.no_harden)
        props = mcp.TOOLS["cloudseed_setup"]["schema"]["properties"]
        for k in ("no_provision", "no_harden", "no_firewall", "no_tools"):
            self.assertEqual(props[k]["type"], "boolean", k)
        self.assertTrue(_call("cloudseed_setup", {"cloud": "aws", "no_harden": "yes"})["isError"])

    def test_provision_switches_reach_the_cli(self):
        a = {"cloud": "gcp", "env": "dev", "host": "bastion", "no_harden": True, "no_firewall": True, "no_tools": True,
             "sync_only": True, "confirm": True}
        ns = _parse(_call("cloudseed_provision", a)["argv"])
        self.assertEqual(ns.host, "bastion")
        self.assertTrue(ns.no_harden and ns.no_firewall and ns.no_tools and ns.sync_only)

    def test_tag_keys_are_checked(self):
        argv = _call("cloudseed_setup", {"cloud": "aws", "tags": {"team": "a=b", "cost-center": "42"}})["argv"]
        self.assertEqual(_parse(argv).tag, ["team=a=b", "cost-center=42"])
        self.assertEqual(cli._parse_kv(_parse(argv).tag), {"team": "a=b", "cost-center": "42"})
        for tags, why in (({"cost=center": "x"}, "cannot contain '='"), ({"": "x"}, "cannot be empty"), ({"  ": "x"}, "cannot be empty"),
                          ({" team": "x"}, "starts or ends with a space")):
            with self.subTest(tags=tags):
                r = _call("cloudseed_setup", {"cloud": "aws", "tags": tags})
                self.assertTrue(r["isError"])
                self.assertIn(why, _text(r))
        with self.assertRaises(ValueError):     # the console path (no schema check on values)
            mcp.TOOLS["cloudseed_setup"]["argv"]({"cloud": "aws", "tags": {"a": 1}})
        with self.assertRaises(ValueError):
            webui.build_argv("cloudseed_setup", {"cloud": "aws", "tags": {"x=y": "z"}})


# ------------------------------------------------------------------------------------------------ managed
class ManagedEnvTests(unittest.TestCase):                               # a2-webui-functional#1
    def test_env_and_cloud_pick_the_profile_environment(self):
        argv = _call("cloudseed_managed", {"service": "databricks", "args": "clusters list", "cloud": "aws", "env": "dev"})["argv"]
        self.assertEqual(argv, ["databricks", "--env", "aws-dev", "clusters", "list"])
        self.assertEqual(_call("cloudseed_managed", {"service": "databricks", "cloud": "aws", "env": "aws-dev"})["argv"],
                         ["databricks", "--env", "aws-dev", "status"])
        long_id = "azure-" + "a" * 23                      # an id is longer than the 24 characters of a name
        self.assertEqual(_call("cloudseed_managed", {"service": "databricks", "env": long_id})["argv"][:3], ["databricks", "--env", long_id])
        self.assertTrue(_call("cloudseed_managed", {"service": "databricks", "env": "-x"})["isError"])
        argv = _call("cloudseed_managed", {"service": "snowflake", "env": "aws-dev", "profile": "p1"})["argv"]
        self.assertEqual(argv, ["snowflake", "--profile", "p1", "--env", "aws-dev", "status"])
        ns = _parse(argv)
        cli._pull_env_from_remainder(ns, "svc_args")
        self.assertEqual((ns.env, ns.profile, ns.svc_args), ("aws-dev", "p1", ["status"]))

    def test_cmd_managed_uses_that_environments_profile(self):
        seen = {}
        from cloudseed import paths
        argv = _call("cloudseed_managed", {"service": "databricks", "args": "clusters list", "cloud": "gcp", "env": "dev"})["argv"]
        ns = _parse(argv)
        envs = [paths.Env("aws", "dev"), paths.Env("gcp", "dev")]

        def profile(service, explicit, current):
            seen["current"] = current
            return "p", None
        with mock.patch.object(paths.Env, "list_all", return_value=envs), mock.patch.object(cli, "_managed_profile", side_effect=profile), \
                mock.patch.object(cli.managed, "run", return_value=0) as run:
            cli.cmd_managed(ns, {"current_env": "aws-dev"})
        self.assertEqual(seen["current"], "gcp-dev")
        self.assertEqual(run.call_args[0][2], ["clusters", "list"])

    def test_conflicts_are_refused(self):
        for a in ({"service": "databricks", "args": "--env x clusters list", "env": "dev"}, {"service": "databricks", "cloud": "aws"}):
            with self.subTest(a=a):
                r = _call("cloudseed_managed", a)
                self.assertTrue(r["isError"])
                self.assertIn("invalid arguments", _text(r))

    def test_the_console_fills_it(self):
        props = mcp.TOOLS["cloudseed_managed"]["schema"]["properties"]
        self.assertIn("env", props)
        self.assertIn("cloud", props)
        self.assertEqual(webui.build_argv("cloudseed_managed", {"service": "databricks", "cloud": "aws", "env": "dev"}),
                         ["databricks", "--env", "aws-dev", "status"])


# ------------------------------------------------------------------------------------------------ descriptions
class DescriptionTests(unittest.TestCase):
    def test_purge_is_undoable(self):                                   # a2-webui-functional#5
        p = mcp.TOOLS["cloudseed_destroy"]["schema"]["properties"]
        self.assertNotIn("irreversible", p["purge"]["description"])
        self.assertIn("cloudseed_undo", p["purge"]["description"])
        self.assertIn("VPN keys are not", p["purge"]["description"])
        self.assertIn("irreversible", p["purge_state"]["description"])

    def test_scan_hosts(self):                                          # a2-resilience#14
        d = mcp.TOOLS["cloudseed_scan"]["schema"]["properties"]["hosts"]["description"]
        self.assertIn("comma-separated: bastion,vpn,k8s", d)
        for hosts in (" bastion , k8s", "bastion k8s", "bastion,,k8s,"):      # as scan.parse_hosts splits them
            with self.subTest(hosts=hosts):
                argv = _call("cloudseed_scan", {"kind": "host", "hosts": hosts, "confirm": True})["argv"]
                self.assertEqual(argv, ["scan", "host", "--host", "bastion,k8s", "-y"])
                self.assertEqual(cli.scan.parse_hosts(_parse(argv).host), ["bastion", "k8s"])
        r = _call("cloudseed_scan", {"kind": "host", "hosts": "bastion,db", "confirm": True})
        self.assertTrue(r["isError"])
        self.assertIn("bastion, vpn, k8s", _text(r))

    def test_ttl_takes_days(self):                                      # cli-cluster: dr --ttl Nd rewrite
        self.assertIn("30d", mcp.TOOLS["cloudseed_dr"]["schema"]["properties"]["ttl"]["description"])
        for ok in ("30d", "720h", "72h30m", "90m", "720h0m0s"):
            self.assertIn("argv", _call("cloudseed_dr", {"action": "schedule", "name": "n", "ttl": ok, "confirm": True}), ok)
        ns = _parse(_call("cloudseed_dr", {"action": "schedule", "name": "n", "ttl": "30d", "confirm": True})["argv"])
        with mock.patch.object(cli.ui, "info"):
            cli._check_dr_args(ns)                     # what `cs dr schedule` does with it
        self.assertEqual(ns.ttl, "720h")
        r = _call("cloudseed_dr", {"action": "schedule", "name": "n", "ttl": "1w", "confirm": True})
        self.assertTrue(r["isError"])
        self.assertIn("30d", _text(r))                  # the hint names the day form

    def test_env_rule_is_described(self):                               # a2-cli-ux#1 / a2-cli-lifecycle#7
        d = mcp.S_ENV["description"]
        for part in ("the cloud's only environment", "the current one", "for read-only tools", "else dev", "never guess"):
            self.assertIn(part, d)
        self.assertLess(len(d), 200)        # shown under every environment field of the console


# ------------------------------------------------------------------------------------------------ JSON tools
_FAKE = r'''
import json, sys
mode = sys.argv[-1]
sys.stderr.write("  (output: aws-dev, the current environment)\n")
if mode == "fail":
    sys.stderr.write("Environment aws-x does not exist.\n")
    sys.exit(1)
if mode == "list":
    print(json.dumps([1, 2]))
else:
    print(json.dumps({"bastion_public_ip": "203.0.113.7", "vpc_id": "vpc-1"}))
'''


class JsonToolTests(unittest.TestCase):                                 # a2-cli-lifecycle#5
    def spawn(self, name, argv):
        with mock.patch.object(mcp, "_launcher", return_value=[sys.executable, "-c", _FAKE]):
            return mcp._spawn(name, argv, dict(os.environ))

    def test_the_result_is_the_clean_json(self):
        r = self.spawn("cloudseed_output", ["output", "aws", "--json"])
        self.assertFalse(r["isError"])
        self.assertEqual(json.loads(r["content"][0]["text"]), {"bastion_public_ip": "203.0.113.7", "vpc_id": "vpc-1"})
        self.assertEqual(r["structuredContent"]["vpc_id"], "vpc-1")
        tail = r["content"][1]["text"]
        self.assertIn("$ cloudseed output aws --json", tail)
        self.assertIn("exit code: 0", tail)
        self.assertIn("the current environment", tail)       # the notes are kept, apart from the JSON

    def test_a_list_has_no_structured_content(self):
        r = self.spawn("cloudseed_inventory", ["inventory", "aws", "--json", "list"])
        self.assertEqual(json.loads(r["content"][0]["text"]), [1, 2])
        self.assertNotIn("structuredContent", r)

    def test_a_failure_shows_the_error(self):
        r = self.spawn("cloudseed_output", ["output", "aws", "--json", "fail"])
        self.assertTrue(r["isError"])
        self.assertIn("exit code: 1", _text(r))
        self.assertIn("does not exist", _text(r))

    def test_other_tools_keep_one_stream(self):
        r = self.spawn("cloudseed_inventory", ["inventory", "aws"])       # the table form (no --json)
        self.assertEqual(len(r["content"]), 1)
        self.assertIn("the current environment", _text(r))
        self.assertIn("203.0.113.7", _text(r))
        self.assertTrue(mcp._json_stdout("cloudseed_output", ["output", "aws", "--json"]))
        self.assertFalse(mcp._json_stdout("cloudseed_status", ["status", "aws", "--json"]))

    def test_secrets_are_redacted_in_both(self):
        fake = 'import sys; print(\'{"k": "AKIA' + 'ABCDEFGHIJKLMNOP"}\'); sys.stderr.write("token ghp_' + 'abcdefghijklmnopqrstuvwxyz0123456789\\n")'
        with mock.patch.object(mcp, "_launcher", return_value=[sys.executable, "-c", fake]):
            r = mcp._spawn("cloudseed_output", ["output", "aws", "--json"], dict(os.environ))
        whole = json.dumps(r)
        self.assertNotIn("AKIA" + "ABCDEFGHIJKLMNOP", whole)
        self.assertNotIn("ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789", whole)


# ------------------------------------------------------------------------------------------------ serve_http
class ServeHttpTests(unittest.TestCase):                                # a2-mcp#10, webui-backend#14
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4mcp-"))
        mdir = self.tmp / "mcp"
        mdir.mkdir()
        self.patches = [mock.patch.object(mcp, "MCP_DIR", mdir), mock.patch.object(mcp, "PID_PATH", mdir / "server.pid"),
                        mock.patch.object(mcp, "LOG_PATH", mdir / "server.log"), mock.patch.object(mcp, "TOKEN_PATH", mdir / "token"),
                        mock.patch.dict(os.environ, {"CLOUDSEED_MCP_FORCE": "1"})]
        for p in self.patches:
            p.start()
        os.environ.pop(mcp.MANAGED_ENV, None)
        os.environ.pop("XPC_SERVICE_NAME", None)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def serve(self, *a, **kw):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = mcp.serve_http(*a, **kw)
        return rc, err.getvalue()

    def test_a_port_out_of_range_is_a_message_not_a_crash(self):
        rc, err = self.serve("127.0.0.1", 99999, auth=False)
        self.assertEqual(rc, 1)
        self.assertIn("Cannot listen on 127.0.0.1:99999", err)
        self.assertIn("1-65535", err)

    def test_free_port_skips_impossible_ports(self):
        self.assertLessEqual(mcp.free_port(65534), 65535)
        with self.assertRaises(mcp.ui.Abort):
            mcp.free_port(70000)

    def test_a_foreground_run_says_where_it_is(self):
        class _Fake:
            def __init__(self, *a):
                pass

            def serve_forever(self):
                pass

            def server_close(self):
                pass
        with mock.patch.object(mcp, "server_class", return_value=_Fake), mock.patch.object(mcp, "LiveEnv") as live:
            rc, err = self.serve("127.0.0.1", 7671, auth=False)
            self.assertEqual(rc, 0)
            self.assertIn("cloudseed MCP server on http://127.0.0.1:7671/mcp", err)
            self.assertIn("Ctrl-C stops it", err)
            live.return_value.close.assert_called()
            with mock.patch.dict(os.environ, {mcp.MANAGED_ENV: "1"}):
                rc, err = self.serve("127.0.0.1", 7671, auth=False)
            self.assertEqual((rc, err), (0, ""))
            self.assertIn("listening on http://127.0.0.1:7671/mcp", mcp.LOG_PATH.read_text())

    def test_a_service_that_can_never_start_does_not_crash_loop(self):
        with mock.patch.object(mcp, "enabled", return_value=False):
            rc, err = self.serve("127.0.0.1", 7672)
            self.assertEqual(rc, 2)
            self.assertIn("disabled", err)
            with mock.patch.dict(os.environ, {mcp.MANAGED_ENV: "1"}):
                rc, err = self.serve("127.0.0.1", 7672)
            self.assertEqual((rc, err), (0, ""))            # launchd KeepAlive / systemd Restart=on-failure: no restart
            self.assertIn("disabled", mcp.LOG_PATH.read_text())
        with mock.patch.dict(os.environ, {mcp.MANAGED_ENV: "1"}):
            rc, _ = self.serve("0.0.0.0", 7672)
        self.assertEqual(rc, 0)
        self.assertIn("Refusing to listen", mcp.LOG_PATH.read_text())

    def test_tool_children_do_not_inherit_the_marker(self):
        with mock.patch.dict(os.environ, {mcp.MANAGED_ENV: "1"}), mock.patch.object(mcp.secrets, "open_session", return_value=("s", dict(os.environ))):
            _sid, env = mcp._child_env()
        self.assertNotIn(mcp.MANAGED_ENV, env)


# ------------------------------------------------------------------------------------------------ the login service
class ServiceDefinitionTests(unittest.TestCase):                        # a2-webui-backend#3
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4mcp-svc-"))
        mdir = self.tmp / "mcp"
        mdir.mkdir()
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.patches = [mock.patch.object(mcp, "MCP_DIR", mdir), mock.patch.object(mcp, "PID_PATH", mdir / "server.pid"),
                        mock.patch.object(mcp, "LOG_PATH", mdir / "server.log"), mock.patch.object(mcp, "STATE_PATH", mdir / "server.json"),
                        mock.patch.object(mcp.Path, "home", return_value=self.home),
                        mock.patch.object(mcp.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")),
                        mock.patch.object(mcp, "health", return_value={"ok": True}),
                        mock.patch.object(mcp, "_drop_other_services", return_value=[])]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_launchd_job_is_interactive_and_marked(self):
        state = {"transport": "http", "host": "127.0.0.1", "port": 7673, "auth": "token", "service": "launchd"}
        self.assertEqual(mcp.start(state), "launchd")
        with open(mcp._launchd_plist(), "rb") as fh:
            data = plistlib.load(fh)
        self.assertEqual(data["ProcessType"], "Interactive")
        self.assertNotIn(data["ProcessType"], ("Background", "Adaptive"))
        self.assertEqual(data["EnvironmentVariables"][mcp.MANAGED_ENV], "1")
        self.assertIsNone(mcp.outdated_service(state))
        data["ProcessType"] = "Background"                  # what an older version wrote
        with open(mcp._launchd_plist(), "wb") as fh:
            plistlib.dump(data, fh)
        self.assertIn("ProcessType Background", mcp.outdated_service(state))

    def test_systemd_unit_is_marked(self):
        state = {"transport": "http", "host": "127.0.0.1", "port": 7674, "auth": "token", "service": "systemd"}
        self.assertEqual(mcp.start(state), "systemd")
        text = mcp._systemd_unit().read_text()
        self.assertIn(f'Environment="{mcp.MANAGED_ENV}=1"', text)
        self.assertIsNone(mcp.outdated_service(state))
        mcp._systemd_unit().write_text(text.replace(f'Environment="{mcp.MANAGED_ENV}=1"\n', ""))
        self.assertIn("older version", mcp.outdated_service(state))
        self.assertIsNone(mcp.outdated_service({"transport": "stdio"}))


# ------------------------------------------------------------------------------------------------ guide
class GuideTests(unittest.TestCase):                                    # a2-mcp#6
    def test_disabled_note_in_the_live_guide_only(self):
        with mock.patch.object(mcp, "enabled", return_value=False):
            rows = dict(dict(mcp.guide_lines(None))["1. Your cloudseed MCP server"])
            self.assertIn("cs enable mcp", rows["Disabled"])
            self.assertIn("MCP is disabled", rows["Disabled"])
            saved = dict(dict(mcp.guide_lines(None, live=False))["1. Your cloudseed MCP server"])
            self.assertNotIn("Disabled", saved)
        with mock.patch.object(mcp, "enabled", return_value=True):
            self.assertNotIn("Disabled", dict(dict(mcp.guide_lines(None))["1. Your cloudseed MCP server"]))

    def test_auth_off_says_so_and_names_no_token(self):                 # a2-mcp#13 (the mcp.py part)
        state = {"transport": "http", "host": "127.0.0.1", "port": 7675, "auth": "none", "service": "background"}
        with mock.patch.object(mcp, "load_token", return_value="tok-abc123"):
            rows = dict(dict(mcp.guide_lines(state))["1. Your cloudseed MCP server"])
            self.assertNotIn("Token file", rows)
            self.assertNotIn("Auth header", rows)
            self.assertIn("--no-auth", rows["Auth"])
            self.assertIn("confirm=true ones included", rows["Auth"])
            # the way back that works whether or not a setup re-run keeps --no-auth
            self.assertIn("cs setup mcp --rotate-token", rows["Auth"])
            self.assertNotIn("tok-abc123", json.dumps(mcp.guide_lines(state)))
            safety = " ".join(dict(mcp.guide_lines(state))["5. Safety model (what the agent can and cannot do)"])
            self.assertIn("does NOT ask for a bearer token", safety)
            self.assertNotIn("needs the bearer token", safety)
            rows = dict(dict(mcp.guide_lines(dict(state, auth="token")))["1. Your cloudseed MCP server"])
            self.assertEqual(rows["Auth header"], "Authorization: Bearer tok-abc123")
            self.assertIn("Token file", rows)
            safety = " ".join(dict(mcp.guide_lines(dict(state, auth="token")))["5. Safety model (what the agent can and cannot do)"])
            self.assertIn("needs the bearer token", safety)
            ns = _parse(["setup", "mcp", "--rotate-token"])        # the advice parses
            self.assertTrue(ns.rotate_token)
        with mock.patch.object(mcp, "load_token", return_value=None):      # token deployment, file gone: not "no auth"
            rows = dict(dict(mcp.guide_lines(dict(state, auth="token")))["1. Your cloudseed MCP server"])
            self.assertNotIn("none", rows["Auth header"])
            # the running server keeps the token it started with: only a rotation (which restarts it) makes a new file valid
            self.assertIn("cs mcp token --rotate", rows["Auth header"])

    def test_print_guide_shows_it_and_the_saved_file_does_not(self):
        tmp = Path(tempfile.mkdtemp(prefix="cs-w4mcp-guide-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        out = io.StringIO()
        with mock.patch.object(mcp, "enabled", return_value=False), mock.patch.object(mcp, "GUIDE_PATH", tmp / "CONNECT.md"), \
                contextlib.redirect_stdout(out):
            mcp.print_guide(None)
        self.assertIn("MCP is disabled", out.getvalue())
        self.assertNotIn("MCP is disabled", (tmp / "CONNECT.md").read_text())


if __name__ == "__main__":
    unittest.main()
