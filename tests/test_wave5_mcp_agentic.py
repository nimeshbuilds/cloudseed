"""Wave-5 (final) regression tests for the MCP server and the built-in agent, plus the CLI pieces they lean on: the
kubectl/helm approval reads exactly the words `cs kubectl|helm` hands the tool (an explicit `--` makes them verbatim),
the CLI's human-only gate never repeats a vault value, the MCP guide for --no-auth / --no-service deployments,
`cs list` with a malformed saved state or outputs cache, and a destroy preview with an empty state that stays
read-only. Stdlib only, no network, no cloud; temp dirs; the tool, cluster and cloud calls are mocked."""
import argparse
import contextlib
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import builtin_agent, cli, clouds, mcp, paths, ui  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CS = [sys.executable, str(ROOT / "bin" / "cloudseed")]


def _parse(argv):
    with contextlib.redirect_stderr(io.StringIO()):
        return cli.build_parser().parse_args(cli.normalize_argv(list(argv)))


class _Cluster:
    def __init__(self, *_a):
        pass

    def procenv(self) -> dict:
        return {"HELM_REGISTRY_CONFIG": "/nonexistent/cloudseed-test/registry.json"}


def _tool_gets(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    """(the parsed namespace, the words `cs <argv>` hands kubectl/helm): cmd_ktool itself, with the cluster, the
    kubeconfig, the tool binary and the process call mocked."""
    ns = _parse(argv)
    got: dict = {}

    def call(cmd, env=None):
        got["argv"] = list(cmd[1:])
        return 0
    env = mock.Mock(id="vmware-lab")
    with mock.patch.object(cli, "_resolve_cluster_env", return_value=(mock.Mock(), env, {}, {})), \
            mock.patch.object(cli.services, "ensure_kubeconfig", return_value="/nonexistent/kubeconfig"), \
            mock.patch.object(cli.services, "ensure_tool", return_value="/nonexistent/tool"), \
            mock.patch.object(cli.platformmod, "Cluster", _Cluster), \
            mock.patch.object(cli, "_pre_change_undo", return_value=None), \
            mock.patch.object(cli, "_migrate_helm_registry_login"), \
            mock.patch.object(cli.secrets, "redact_enabled", return_value=False), \
            mock.patch.object(cli.subprocess, "call", side_effect=call), \
            contextlib.redirect_stderr(io.StringIO()):
        rc = cli.cmd_ktool(ns, {})
    assert rc == 0, rc
    return ns, got["argv"]


# ------------------------------------------------------------------------------------------------ one kubectl/helm reader
class ToolVerbatimTests(unittest.TestCase):                   # cli-cluster needs_other: _tool_rest mirrors tool_verbatim
    CASES = [
        # (cs argv, what the tool gets)
        (["kubectl", "--", "vmware", "get", "pods"], ["vmware", "get", "pods"]),
        (["kubectl", "vmware", "--env", "prod", "--", "--env", "lab", "get", "pods"], ["--env", "lab", "get", "pods"]),
        (["kubectl", "vmware", "--env", "prod", "--", "vmware", "delete", "ns", "x"], ["vmware", "delete", "ns", "x"]),
        (["kubectl", "aws", "--env", "dev", "get", "pods"], ["get", "pods"]),
        (["kubectl", "--env=dev", "aws", "get", "pods"], ["get", "pods"]),
        (["kubectl", "-edev", "get", "pods"], ["get", "pods"]),
        (["kubectl", "--", "--", "get", "pods"], ["get", "pods"]),
        (["kubectl", "get", "pods", "-y"], ["get", "pods"]),
        (["kubectl", "aws", "gcp", "get", "pods"], ["get", "pods"]),
        (["kubectl", "exec", "p", "--", "sh", "-y"], ["exec", "p", "--", "sh", "-y"]),
        (["helm", "--", "aws", "list"], ["aws", "list"]),
        (["helm", "aws", "--env", "dev", "--", "-e", "x", "uninstall", "r"], ["-e", "x", "uninstall", "r"]),
    ]

    def test_the_reader_gets_exactly_what_the_tool_gets(self):
        for argv, want in self.CASES:
            with self.subTest(argv=argv):
                ns, gets = _tool_gets(argv)
                self.assertEqual(gets, want)
                self.assertEqual(builtin_agent._tool_rest(ns.tool_args, ns.tool_verbatim), gets)   # the parsed words
                self.assertEqual(builtin_agent._tool_rest(argv[1:]), gets)                        # the typed words

    def test_explicit_separator_keeps_the_cluster_of_the_selectors(self):
        ns, gets = _tool_gets(["kubectl", "vmware", "--env", "prod", "--", "--env", "lab", "get", "pods"])
        self.assertEqual((ns.cloud, ns.env), ("vmware", "prod"))       # (was: lab, from the tool's own words)
        self.assertTrue(ns.tool_verbatim)

    def test_the_agent_approves_what_really_runs(self):
        def reason(cmd: str):
            ns, _final = builtin_agent._parse(shlex.split(cmd))
            return builtin_agent._approval_reason(ns)
        # a cloud key after the explicit `--` is kubectl's first word: `kubectl vmware get pods` is not a known read
        self.assertIn("kubectl vmware", reason("kubectl -- vmware get pods") or "")
        self.assertIn("kubectl vmware", reason("kubectl vmware --env prod -- vmware delete ns x") or "")
        self.assertIn("helm aws", reason("helm -- aws list") or "")
        self.assertIsNone(reason("kubectl vmware --env prod -- get pods"))
        self.assertIsNone(reason("kubectl aws --env dev get pods"))
        self.assertIsNone(reason("kubectl -edev get pods"))
        self.assertIsNotNone(reason("kubectl aws --env dev -- delete ns x"))
        self.assertIsNotNone(reason("kubectl get secrets"))

    def test_the_public_reader_keeps_its_prefix_form(self):
        self.assertIsNone(builtin_agent.kube_approval("kubectl", ["aws", "--env", "dev", "get", "pods"]))
        self.assertIsNone(builtin_agent.kube_approval("kubectl", ["-edev", "get", "pods"]))
        self.assertIsNotNone(builtin_agent.kube_approval("kubectl", ["--", "vmware", "get", "pods"]))
        self.assertIsNotNone(builtin_agent.kube_approval("helm", ["--", "uninstall", "x"]))
        # a malformed global option: the CLI refuses the call, and the reader fails closed
        self.assertIsNotNone(builtin_agent.kube_approval("kubectl", ["--runtime", "bogus", "get", "pods"]))
        self.assertIsNone(builtin_agent.kube_approval("kubectl", ["--", "get", "pods"], verbatim=True))
        self.assertIsNotNone(builtin_agent.kube_approval("kubectl", ["vmware", "get", "pods"], verbatim=True))

    def test_mcp_gates_the_words_the_tool_gets(self):
        for args in ("get pods", "aws --env dev get pods", "-- get pods", "-- -- get pods", "-- -- -- -- get pods",
                     "-- -- -- -- -- get pods", "-- -- -- -- -- --env x get pods", "-- delete ns x", "logs --tail=5 p"):
            a = {"cloud": "aws", "env": "dev", "args": args}
            with self.subTest(args=args):
                _ns, gets = _tool_gets(mcp.TOOLS["cloudseed_kubectl"]["argv"](a))
                self.assertEqual(builtin_agent._tool_rest(mcp._kube_words(a)[2], verbatim=True), gets)
        # kubectl gets `-- get pods` here: that is no read cloudseed recognises, so it needs confirm=true
        self.assertIsNotNone(mcp._kube_reason("kubectl", {"cloud": "aws", "env": "dev", "args": "-- -- -- -- -- get pods"}))
        self.assertIsNone(mcp._kube_reason("kubectl", {"cloud": "aws", "env": "dev", "args": "-- -- get pods"}))


# ------------------------------------------------------------------------------------------------ human-only gate
class HumanCommandTests(unittest.TestCase):                  # agentic reviewer: cli._human_command repeated bare values
    def test_a_bare_vault_value_is_never_repeated(self):
        self.assertEqual(cli._human_command(["creds", "set", "OPENAI_API_KEY", "plainsecretword"]),
                         "cloudseed creds set OPENAI_API_KEY")
        self.assertEqual(cli._human_command(["creds", "set", "KEY", "v1", "OTHER", "v2", "-y"]), "cloudseed creds set KEY OTHER")
        self.assertEqual(cli._human_command(["-y", "--runtime", "local", "creds", "set", "github_token=abc123"]),
                         "cloudseed --runtime local creds set GITHUB_TOKEN")
        self.assertEqual(cli._human_command(["creds", "unset", "aws_profile", "--forget"]),
                         "cloudseed creds unset AWS_PROFILE --forget")
        # the earlier cases still hold
        self.assertEqual(cli._human_command(["-y", "creds", "set", "ANTHROPIC_BASE_URL=https://evil.example", "FOO=bar"]),
                         "cloudseed creds set ANTHROPIC_BASE_URL FOO")
        self.assertEqual(cli._human_command(["ui", "token", "--rotate", "-y"]), "cloudseed ui token --rotate")

    def test_the_cli_gate_and_the_built_in_agent_agree(self):
        for words in (["creds", "set", "KEY", "value"], ["creds", "set", "a=b", "c", "d"], ["creds", "clear", "--forget"],
                      ["creds", "set", "KEY", "Some Value With Spaces"], ["creds", "--forget", "unset", "X"]):
            with self.subTest(words=words):
                self.assertEqual(cli._human_command(words), builtin_agent._human_command(words))

    def test_global_options_among_the_vault_words_keep_their_value(self):
        # --runtime / --engine take one of their fixed choices, also after the command and abbreviated as argparse
        # allows: that word is the option's, never a variable name or a vault value (review: `creds set FOO --runtime
        # local` lost `local`, and `creds --runtime local set FOO secret` came out as `--runtime LOCAL set SECRET`)
        cases = [
            (["creds", "set", "FOO", "--runtime", "local"], "cloudseed creds set FOO --runtime local"),
            (["creds", "--runtime", "local", "set", "FOO", "barsecret"], "cloudseed creds --runtime local set FOO"),
            (["creds", "set", "--runtime=local", "FOO", "barsecret"], "cloudseed creds set --runtime=local FOO"),
            (["creds", "set", "FOO", "barsecret", "--engine", "podman"], "cloudseed creds set FOO --engine podman"),
            (["creds", "set", "FOO", "--run", "local", "barsecret"], "cloudseed creds set FOO --run local"),
            (["creds", "set", "FOO", "--runtime", "notachoice"], "cloudseed creds set FOO --runtime"),
        ]
        for words, want in cases:
            with self.subTest(words=words):
                self.assertEqual(cli._human_command(words), want)
                self.assertEqual(builtin_agent._human_command(words), want)
                shown = builtin_agent._shown_args(shlex.join(words))
                self.assertNotIn("barsecret", shown.lower())
                self.assertNotIn("notachoice", shown)
        # an abbreviated global option before the command: the parsed command line says where `creds` is
        argv = ["--run", "local", "creds", "set", "FOO", "barsecret"]
        self.assertEqual(cli._human_command(argv, _parse(argv)), "cloudseed --run local creds set FOO")

    def test_the_real_cli_refuses_without_the_value(self):
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, CLOUDSEED_HOME=str(Path(home) / "cs"), HOME=home, CLOUDSEED_AGENT="claude")
            env.pop("CLOUDSEED_REDACT", None)
            for argv, want in ((["creds", "set", "OPENAI_API_KEY", "plainsecretword"], "cloudseed creds set OPENAI_API_KEY"),
                               (["creds", "--runtime", "local", "set", "FOO", "plainsecretword"],
                                "cloudseed creds --runtime local set FOO"),
                               (["--run", "local", "creds", "set", "FOO", "plainsecretword"],
                                "cloudseed --run local creds set FOO")):
                with self.subTest(argv=argv):
                    r = subprocess.run(CS + argv, env=env, capture_output=True, text=True, timeout=120)
                    out = r.stdout + r.stderr
                    self.assertEqual(r.returncode, 2, out)
                    self.assertIn(want + "`", out)
                    self.assertNotIn("plainsecretword", out.lower())
            self.assertFalse((Path(home) / "cs" / "creds.json").exists())


# ------------------------------------------------------------------------------------------------ MCP guide
class GuideTests(unittest.TestCase):                                      # a2-mcp#13
    BASE = {"transport": "http", "host": "127.0.0.1", "port": 7661}

    @staticmethod
    def _text(state: dict) -> str:
        return json.dumps(mcp.guide_lines(state, {}, live=False), ensure_ascii=False)

    def test_no_auth_has_no_token_row_and_says_auth_is_off(self):
        text = self._text(dict(self.BASE, auth="none", service="launchd"))
        self.assertNotIn("Token file", text)
        self.assertNotIn("Authorization: Bearer", text)
        self.assertNotIn("needs the bearer token", text)
        self.assertIn("off (deployed with --no-auth)", text)
        self.assertIn("cs setup mcp --rotate-token", text)
        self.assertIn("cs setup mcp --auth", text)                 # the way back without a new token (w5/web-ui)

    def test_a_token_deployment_keeps_its_rows(self):
        for auth in ("token", None):          # (setup saves 'token'; a missing value means a token, as in cli)
            with self.subTest(auth=auth):
                state = dict(self.BASE, service="launchd")
                if auth is not None:
                    state["auth"] = auth
                text = self._text(state)
                self.assertIn("Token file", text)
                self.assertIn("needs the bearer token", text)
        self.assertIn("Token file", self._text(dict(self.BASE, auth=None, service="launchd")))

    def test_the_kept_no_service_choice_is_named(self):
        chosen = self._text(dict(self.BASE, auth="token", service="background", no_service=True))
        self.assertIn("chosen with --no-service", chosen)
        self.assertIn("offers the login service again", chosen)
        self.assertIn("cs setup mcp --service", chosen)            # the way back without a terminal (w5/web-ui)
        legacy = self._text(dict(self.BASE, auth="token", service="background"))   # written before no_service existed
        self.assertIn("chosen with --no-service", legacy)
        fallback = self._text(dict(self.BASE, auth="token", service="background", no_service=False))
        self.assertIn("could not be installed", fallback)
        self.assertNotIn("--no-service", fallback)
        self.assertNotIn("--no-service", self._text(dict(self.BASE, auth="token", service="launchd", no_service=False)))

    def test_the_saved_guide_follows(self):
        with mock.patch.object(mcp, "GUIDE_PATH", Path(tempfile.mkdtemp(prefix="cloudseed-test-")) / "CONNECT.md"):
            path = mcp.save_guide(dict(self.BASE, auth="none", service="background", no_service=True))
            text = path.read_text()
        self.assertNotIn("Token file", text)
        self.assertIn("chosen with --no-service", text)


# ------------------------------------------------------------------------------------------------ cs list
class ListTests(unittest.TestCase):                                         # agentic (e)
    def test_a_malformed_state_or_outputs_cache_is_listed(self):
        with tempfile.TemporaryDirectory() as home:
            env_dir = Path(home) / "cs" / "envs" / "aws-w5"
            env_dir.mkdir(parents=True)
            (env_dir / "config.json").write_text(json.dumps({"cloud": "aws", "env": "w5", "name": "seed", "region": "us-east-1",
                                                             "state": "local", "updated_at": None}))
            (env_dir / "outputs.json").write_text('["not", "an", "object"]')
            env = dict(os.environ, CLOUDSEED_HOME=str(Path(home) / "cs"), HOME=home)
            for k in ("CLOUDSEED_AGENT", "CLOUDSEED_REDACT"):
                env.pop(k, None)
            r = subprocess.run(CS + ["list"], env=env, capture_output=True, text=True, timeout=120)
            out = r.stdout + r.stderr
            self.assertEqual(r.returncode, 0, out)
            self.assertIn("aws-w5", out)
            self.assertNotIn("Unexpected error", out)
            self.assertNotIn("None", out)

    def test_cached_outputs_are_always_a_dict(self):
        with tempfile.TemporaryDirectory() as d:
            env = paths.Env("aws", "w5", workdir=d)
            for text, want in (('["x"]', {}), ('"x"', {}), ("{broken", {}), ('{"a": 1}', {"a": 1})):
                (Path(d) / "outputs.json").write_text(text)
                self.assertEqual(cli._cached_outputs(env), want, text)


# ------------------------------------------------------------------------------------------------ destroy preview
class EmptyDestroyPreviewTests(unittest.TestCase):                          # agentic (f)
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _env(self, cloud: str) -> paths.Env:
        env = paths.Env(cloud, "w5", workdir=self.dir)
        (self.dir / "ssh").mkdir()
        (self.dir / "k8s").mkdir()
        (self.dir / "k8s" / "kubeconfig").write_text("x")
        env.known_hosts_path().write_text("198.51.100.9 ssh-ed25519 AAAA\n")
        (self.dir / "outputs.json").write_text('{"bastion_public_ip": "198.51.100.9"}')
        return env

    def _run(self, cloud_key: str, cfg: dict, auto: bool = False):
        cloud = clouds.get(cloud_key)
        env = self._env(cloud_key)
        args = argparse.Namespace(auto_approve=auto, purge=False, purge_state=False)
        t = mock.Mock()
        with mock.patch.object(ui, "interactive", return_value=False), \
                mock.patch.object(ui, "confirm", return_value=False), \
                mock.patch.object(cli, "_release_os_login") as release, \
                mock.patch.object(cli, "_forget_cluster_access") as forget, \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                rc = cli._destroy_everything(cloud, env, cfg, t, [], args, {})
            except ui.Abort as e:
                rc = e
        return rc, env, release, forget, out.getvalue() + err.getvalue()

    def test_nothing_pending_is_read_only(self):
        rc, env, release, forget, out = self._run("aws", {"cloud": "aws", "env": "w5"})
        self.assertEqual(rc, 0, out)
        self.assertIn("Nothing to destroy in aws-w5", out)
        self.assertIn("cached outputs, SSH host keys and cluster access files stay", out)
        self.assertTrue((self.dir / "outputs.json").exists())
        self.assertTrue(env.known_hosts_path().exists())
        self.assertTrue((self.dir / "k8s" / "kubeconfig").exists())
        release.assert_not_called()
        forget.assert_not_called()

    def test_an_os_login_key_is_pending(self):
        cfg = {"cloud": "gcp", "env": "w5", "os_login": {"added": True, "account": "dev@example.com", "key": "ssh-ed25519 AAAA"}}
        rc, _env, release, forget, out = self._run("gcp", cfg)
        self.assertIsInstance(rc, ui.Abort)
        self.assertEqual(rc.code, 3)
        self.assertIn("OS Login SSH key cloudseed registered for dev@example.com", rc.msg)
        release.assert_not_called()
        forget.assert_not_called()
        self.assertTrue((self.dir / "outputs.json").exists())
        # a key someone else registered (added=False) is never cloudseed's to remove, nor is a record without a key
        # (GCP.release_os_login then removes nothing): nothing pending
        none = argparse.Namespace(purge=False, purge_state=False)
        for login in ({"added": False, "account": "dev@example.com", "key": "ssh-ed25519 AAAA"},
                      {"added": True, "account": "dev@example.com"}, {"added": True, "account": "dev@example.com", "key": "x"}):
            with self.subTest(login=login):
                self.assertEqual(cli._pending_cleanup(clouds.get("gcp"), _env, dict(cfg, os_login=login), none, [], {}), [])

    def test_auto_approve_still_cleans_up(self):
        rc, env, release, forget, out = self._run("aws", {"cloud": "aws", "env": "w5"}, auto=True)
        self.assertEqual(rc, 0, out)
        self.assertFalse((self.dir / "outputs.json").exists())
        self.assertFalse(env.known_hosts_path().exists())
        release.assert_called_once()
        forget.assert_called_once()


if __name__ == "__main__":
    unittest.main()
