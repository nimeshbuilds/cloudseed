"""Integration of fix/cli-life with the groups merged before it.

cli-life rewrote destroy (targeted/full split, strict state read), ssh argument handling (env only in the leading
tokens, ssh's value options), troubleshoot's vmware advice and the "enabled but not created yet" messages. The groups
merged before it had changed the same places: platform-logic closes the API tunnel on destroy, cli-parser takes
cloudseed's options out of `cs ssh` at parse time and made ui.Abort quiet, ops fills <cloud>/<env> into log hints and
webui-backend/platform-logic moved the kubeconfig fetch into services._fetch_kubeconfig.
"""
from __future__ import annotations

import contextlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_fix_cli_life import FakeTF, LifeBase, _names  # noqa: E402

from cloudseed import cli, clouds, localvm, services, troubleshoot  # noqa: E402


def parse_ssh(*argv):
    a = cli.build_parser().parse_args(["ssh", "aws", *argv])
    if "--" in argv:
        a = cli._parse_ssh_argv(["ssh", "aws", *argv])
    cli._pull_env_from_remainder(a, "ssh_args")
    opts, remote = cli._split_ssh_args(a.ssh_args or [])
    return a, opts, remote


class SshArgvTests(unittest.TestCase):
    """cli-parser's parse-time _ssh_post must not take back what cli-life leaves to ssh and the remote command."""

    def test_ssh_escape_option_after_ssh_options_is_ssh_s(self):
        a, opts, remote = parse_ssh("--env", "E", "-N", "-T", "-e", "none")
        self.assertEqual((a.env, opts, remote), ("E", ["-N", "-T", "-e", "none"], []))

    def test_remote_command_options_reach_the_host(self):
        a, opts, remote = parse_ssh("--env", "E", "grep", "-e", "foo", "/etc/hosts")
        self.assertEqual((a.env, remote), ("E", ["grep", "-e", "foo", "/etc/hosts"]))
        a, opts, remote = parse_ssh("--env", "E", "sudo", "apt-get", "install", "-y", "nginx")
        self.assertEqual((a.env, a.yes, remote), ("E", False, ["sudo", "apt-get", "install", "-y", "nginx"]))
        a, opts, remote = parse_ssh("--runtime", "local", "--env", "E", "docker", "run", "--env", "X=1", "img")
        self.assertEqual((a.env, a.runtime, remote), ("E", "local", ["docker", "run", "--env", "X=1", "img"]))

    def test_ssh_option_values_are_never_taken_as_cloudseed_options(self):
        a, opts, remote = parse_ssh("--env", "E", "-o", "BatchMode=yes", "ls", "-y")
        self.assertEqual((a.env, a.yes, opts, remote), ("E", False, ["-o", "BatchMode=yes"], ["ls", "-y"]))

    def test_cloudseed_options_among_ssh_options_still_work(self):
        a, opts, remote = parse_ssh("-L", "8080:h:80", "--env", "E")          # cli-parser: unambiguous long option
        self.assertEqual((a.env, opts), ("E", ["-L", "8080:h:80"]))
        a, opts, remote = parse_ssh("-y")
        self.assertEqual((a.yes, opts, remote), (True, [], []))
        a, opts, remote = parse_ssh("-eE", "uptime")                           # cli-life: attached -eNAME
        self.assertEqual((a.env, remote), ("E", ["uptime"]))
        a, opts, remote = parse_ssh("--env=E", "-L", "8080:h:80", "--", "uptime", "-y")
        self.assertEqual((a.env, a.yes, opts, remote), ("E", False, ["-L", "8080:h:80"], ["uptime", "-y"]))


class SshCommandTests(LifeBase):
    def test_escape_option_reaches_ssh_for_the_chosen_env(self):
        (self.env.dir / "outputs.json").write_text('{"bastion_public_ip": "203.0.113.9"}')
        captured = {}
        with mock.patch.object(cli.subprocess, "call", lambda cmd, **kw: captured.setdefault("cmd", cmd) and 0), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            rc = cli.main(["ssh", "aws", "--env", self.env_name, "-N", "-e", "none"])
        self.assertEqual(rc, 0, self.out.getvalue())
        cmd = captured["cmd"]
        dest = next(i for i, a in enumerate(cmd) if a.endswith("@203.0.113.9"))
        self.assertEqual(cmd[dest - 3:dest], ["-N", "-e", "none"])


class DestroyTunnelTests(LifeBase):
    """platform-logic's tunnel close lives on in cli-life's _destroy_targets / _destroy_everything."""

    def test_targeted_destroy_of_the_cluster_closes_the_tunnel(self):
        FakeTF.reset(state=["module.stack.module.eks[0].aws_eks_cluster.this", "module.stack.module.bastion.aws_instance.bastion"],
                     changes=[{"address": "module.stack.module.eks[0].aws_eks_cluster.this", "type": "aws_eks_cluster",
                               "mode": "managed", "change": {"actions": ["delete"]}}])
        with mock.patch.object(services, "close_tunnel") as close:
            rc = self.destroy("--target", "module.stack.module.eks", "-y", "--auto-approve")
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertEqual([(c.args[0].id, c.kwargs) for c in close.call_args_list], [(self.env.id, {"quiet": True})])

    def test_targeted_destroy_of_the_bastion_keeps_the_tunnel(self):
        FakeTF.reset(state=["module.stack.module.bastion.aws_instance.bastion"],
                     changes=[{"address": "module.stack.module.bastion.aws_instance.bastion", "type": "aws_instance",
                               "mode": "managed", "change": {"actions": ["delete"]}}])
        with mock.patch.object(services, "close_tunnel") as close:
            rc = self.destroy("--target", "module.stack.module.bastion", "-y", "--auto-approve")
        self.assertEqual(rc, 0, self.out.getvalue())
        close.assert_not_called()

    def test_full_destroy_closes_the_tunnel(self):
        FakeTF.reset(state=["module.stack.aws_vpc.this"])
        (self.env.dir / "k8s").mkdir(exist_ok=True)
        (self.env.dir / "k8s" / "tunnel.pid").write_text(json.dumps({"pid": 999999, "port": 16443, "host": "h", "rport": 443}))
        rc = self.destroy("-y", "--auto-approve")
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertEqual(len(_names(FakeTF.calls, "apply")), 1)
        self.assertFalse((self.env.dir / "k8s" / "tunnel.pid").exists())


class TroubleshootHintTests(LifeBase):
    def _run(self, cloud_key):
        from cloudseed import paths
        env = paths.Env(cloud_key, self.env_name)
        env.create_dirs()
        env.save(dict(self.cfg, cloud=cloud_key))
        log = env.dir / "logs" / "20260101-000000-provision.log"
        log.write_text("bastion did not accept SSH within 420s\n")
        (env.dir / "logs" / "audit.jsonl").write_text(json.dumps(
            {"at": "2026-01-01T00:00:00", "command": "provision", "argv": ["provision", cloud_key], "exit_code": 1,
             "log": str(log)}) + "\n")
        with mock.patch.object(troubleshoot.deps, "missing", return_value=([], [])), \
                mock.patch.object(troubleshoot.deps, "live_credential_check", return_value=None), \
                mock.patch.object(troubleshoot.netutil, "detect_public_ip", return_value=None), \
                mock.patch.object(localvm, "detect_host", lambda: None), \
                contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.out):
            troubleshoot.run(clouds.get(cloud_key), env, env.load())
        return self.out.getvalue()

    def test_cloud_hint_names_the_env(self):
        out = self._run("aws")
        self.assertIn(f"cloudseed update-ip aws --env {self.env_name}", out)   # ops fills <cloud>/<env>
        self.assertNotIn("<cloud>", out)

    def test_vmware_hint_is_about_the_vm_not_the_ip(self):
        out = self._run("vmware")
        self.assertIn("powered off or still booting", out)                    # cli-life's local-cloud rewrite
        self.assertNotIn("update-ip", out)


class KubeconfigMessageTests(LifeBase):
    def test_enabled_but_not_created_with_the_cached_fetch(self):
        cfg = dict(self.cfg, vars={"enable_kubernetes": True})
        with self.assertRaises(SystemExit) as cm:
            services.ensure_kubeconfig(clouds.get("aws"), self.env, cfg, {})
        self.assertIn("enabled for", str(cm.exception))
        self.assertIn("not created yet", str(cm.exception))
        with self.assertRaises(SystemExit) as cm:
            services.ensure_kubeconfig(clouds.get("aws"), self.env, self.cfg, {})
        self.assertIn("--var enable_kubernetes=true", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
