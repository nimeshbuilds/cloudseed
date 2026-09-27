"""Private API access must prepare kubectl before reporting a usable tunnel. No network or cloud calls."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cloudseed import services, ui


class PrivateTunnelTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="cloudseed-k8s-access-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.env = SimpleNamespace(dir=self.root, id="aws-fixture", name="fixture",
                                   private_key_path=lambda cfg: self.root / "key", ssh_options=lambda: [])
        self.cloud = SimpleNamespace(key="aws", ssh_user=lambda cfg: "ec2-user")
        self.cfg = {"env": "fixture", "region": "us-east-1", "vars": {}}
        self.outputs = {"kubernetes_cluster_name": "fixture", "kubernetes_endpoint": "https://api.example.invalid",
                        "bastion_public_ip": "192.0.2.1"}
        self.events = []
        self.installed = False

    def install(self, tool, why):
        self.assertEqual(tool, "kubectl")
        self.events.append("prepare kubectl")
        self.installed = True
        return "/fixture/kubectl"

    def fetch(self, cloud, cfg, outputs, kc):
        kc.write_text(json.dumps({"server": outputs["kubernetes_endpoint"]}))

    def run_tool(self, args, **kwargs):
        self.events.append(args[0])
        if args[0] == "pgrep":
            return subprocess.CompletedProcess(args, 0, "123\n", "")
        if args[:3] == ["/fixture/kubectl", "config", "view"]:
            return subprocess.CompletedProcess(args, 0, "fixture", "")
        if args[:3] == ["/fixture/kubectl", "config", "set-cluster"]:
            server = next(a.split("=", 1)[1] for a in args if a.startswith("--server="))
            Path(kwargs["env"]["KUBECONFIG"]).write_text(json.dumps({"server": server}))
        return subprocess.CompletedProcess(args, 0, "", "")

    @contextlib.contextmanager
    def offline(self):
        with mock.patch.object(services, "_fetch_kubeconfig", side_effect=self.fetch), \
                mock.patch.object(services, "tunnel_info", return_value=None), \
                mock.patch.object(services, "_tcp_open", return_value=False), \
                mock.patch.object(services, "_free_port", return_value=17443), \
                mock.patch.object(services, "close_tunnel"), \
                mock.patch.object(services, "ensure_tool", side_effect=self.install), \
                mock.patch.object(services.deps, "find", side_effect=lambda name: "/fixture/kubectl" if self.installed else None), \
                mock.patch.object(services.subprocess, "run", side_effect=self.run_tool), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            yield

    def test_first_run_installs_kubectl_before_ssh_and_rewrites_kubeconfig(self):
        with self.offline():
            kc = services.ensure_kubeconfig(self.cloud, self.env, self.cfg, self.outputs)
        self.assertLess(self.events.index("prepare kubectl"), self.events.index("ssh"))
        self.assertEqual(json.loads(kc.read_text())["server"], "https://127.0.0.1:17443")
        self.assertTrue(services._read_stamp(self.env)["tunnel"])

    def test_refused_tool_preparation_does_not_open_ssh(self):
        with self.offline(), mock.patch.object(services, "ensure_tool", side_effect=ui.Abort("kubectl required", code=2)):
            with self.assertRaises(ui.Abort):
                services.ensure_kubeconfig(self.cloud, self.env, self.cfg, self.outputs)
        self.assertNotIn("ssh", self.events)
        self.assertFalse(services._read_stamp(self.env)["tunnel"])

    def test_rewrite_failure_does_not_record_ready_tunnel(self):
        with self.offline(), mock.patch.object(services, "_point_kubeconfig", return_value=False):
            with self.assertRaisesRegex(ui.Abort, "kubeconfig could not be updated"):
                services.ensure_kubeconfig(self.cloud, self.env, self.cfg, self.outputs)
        self.assertFalse(services._read_stamp(self.env)["tunnel"])

    def test_reused_tunnel_prepares_kubectl_and_rejects_failed_rewrite(self):
        live = {"host": "api.example.invalid", "port": 17443, "rport": 443}
        with self.offline(), mock.patch.object(services, "tunnel_info", return_value=live), \
                mock.patch.object(services, "_tcp_open", return_value=True), \
                mock.patch.object(services, "_point_kubeconfig", return_value=False):
            with self.assertRaisesRegex(ui.Abort, "Could not point"):
                services.ensure_kubeconfig(self.cloud, self.env, self.cfg, self.outputs)
        self.assertIn("prepare kubectl", self.events)
        self.assertNotIn("ssh", self.events)

    def test_direct_api_does_not_require_tunnel_tools(self):
        with self.offline(), mock.patch.object(services, "_tcp_open", return_value=True):
            kc = services.ensure_kubeconfig(self.cloud, self.env, self.cfg, self.outputs)
        self.assertEqual(json.loads(kc.read_text())["server"], "https://api.example.invalid")
        self.assertFalse(self.events)


if __name__ == "__main__":
    unittest.main()
