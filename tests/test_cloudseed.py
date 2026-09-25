import json
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import agents, clouds, netutil, secrets  # noqa: E402
from cloudseed.cli import build_parser  # noqa: E402


def render_post_manifest(ctx, name: str) -> str:
    """A POST_MANIFESTS entry exactly as `platform install` renders it: drive platform._apply_manifest with kubectl
    stubbed out and read the file it hands to `kubectl apply -f` (so the test cannot drift from the real code)."""
    from unittest import mock
    from cloudseed import platform as pl
    applied = []

    def fake_run(cmd, ctx_, check=True):
        if "apply" in cmd and "-f" in cmd:
            applied.append(cmd[cmd.index("-f") + 1])
        return 0
    with mock.patch.object(pl, "_run", fake_run), mock.patch.object(pl, "_warn_pool_move"):
        # Cluster inspection is separate from rendering; never query a real kubectl here.
        pl._apply_manifest(ctx, "kubectl", name, "ns", wait_ns=False)
    return Path(applied[-1]).read_text()


def structure_problems(text: str) -> list:
    """Stdlib well-formedness checks for rendered Kubernetes YAML: every document has apiVersion/kind, no {placeholder}
    is left, and flow collections ({...} / [...]) balance outside quotes, comments and block scalars."""
    import re
    problems = []
    for i, doc in enumerate(re.split(r"(?m)^---\s*$", text)):
        if not doc.strip():
            continue
        if not re.search(r"(?m)^apiVersion:", doc) or not re.search(r"(?m)^kind:", doc):
            problems.append(f"document {i}: missing apiVersion/kind")
        left = re.findall(r"\{[a-z_]+\}", doc)
        if left:
            problems.append(f"document {i}: unresolved placeholders {left}")
        block_indent = None
        for n, line in enumerate(doc.splitlines(), 1):
            indent = len(line) - len(line.lstrip())
            if block_indent is not None:
                if not line.strip() or indent > block_indent:
                    continue
                block_indent = None
            depth = {"{": 0, "[": 0}
            quote = None
            for ch in line:
                if quote:
                    quote = None if ch == quote else quote
                elif ch in "\"'":
                    quote = ch
                elif ch == "#":
                    break
                elif ch in "{[":
                    depth[ch] += 1
                elif ch in "}]":
                    depth["{" if ch == "}" else "["] -= 1
            if any(depth.values()):
                problems.append(f"document {i} line {n}: unbalanced flow collection: {line.strip()}")
            if re.search(r":\s*[|>][-+0-9]*\s*$", line):
                block_indent = indent
    return problems


class RedactTests(unittest.TestCase):
    def test_patterns(self):
        key_id, secret = "AKIA" + "IOSFODNN7EXAMPLE", "wJalr" + "XUtnFEMI/K7MDENG" + "/bPxRfiCYEXAMPLEKEY"   # AWS docs' pair
        text = (f"{key_id} aws_secret_access_key={secret} "
                "-----BEGIN " "RSA PRIVATE KEY-----\nxx\n-----END RSA PRIVATE KEY----- sk-ant-" "abcdefghijklmnopqrstuvwxyz "
                "password: hunter2secret plain text stays")
        out = secrets.redact(text)
        self.assertNotIn(key_id, out)
        self.assertNotIn("wJalrXUtnFEMI", out)
        self.assertNotIn("BEGIN RSA", out)
        self.assertNotIn("sk-ant-", out)
        self.assertNotIn("hunter2secret", out)
        self.assertIn("plain text stays", out)

    def test_secret_env_detection(self):
        self.assertTrue(secrets.is_secret_env("AWS_SECRET_ACCESS_KEY"))
        self.assertTrue(secrets.is_secret_env("MY_API_KEY"))
        self.assertFalse(secrets.is_secret_env("AWS_REGION"))
        self.assertFalse(secrets.is_secret_env("PATH"))


class NetTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(netutil.normalize_cidr("203.0.113.7"), "203.0.113.7/32")
        self.assertEqual(netutil.normalize_cidr("10.0.0.5/24"), "10.0.0.0/24")

    def test_reject_open_world(self):
        self.assertIsNotNone(netutil.validate_cidr_list("0.0.0.0/0"))
        self.assertIsNone(netutil.validate_cidr_list("1.2.3.4, 10.0.0.0/8"))

    def test_pick_cidr_skips_used(self):
        self.assertEqual(netutil.pick_network_cidr([]), "10.0.0.0/16")
        self.assertEqual(netutil.pick_network_cidr(["10.0.0.0/16", "10.1.0.0/16"]), "10.2.0.0/16")
        # 172.16.0.0/16 is skipped: it holds GKE's default control-plane range 172.16.0.0/28
        self.assertEqual(netutil.pick_network_cidr(["10.0.0.0/8"]), "172.17.0.0/16")


class RenderTests(unittest.TestCase):
    def cfg(self, cloud, **vars_):
        return {"cloud": cloud, "env": "dev", "name": "acme", "owner": "me", "region": "r1",
                "network_cidr": "10.0.0.0/16", "allowed_ssh_cidrs": ["1.2.3.4/32"],
                "ssh_public_key": "ssh-ed25519 AAAA test ${not.interpolated}", "state": {"type": "local", "backend": None},
                "vars": vars_, "extra_vars": {"az_count": 3}, "tags": {"Team": "x"}}

    def test_aws_root(self):
        root = clouds.get("aws").render_stack(self.cfg("aws", profile="p1"), Path("/tf"))
        mod = root["module"]["stack"]
        self.assertEqual(mod["source"], "/tf/aws")
        self.assertEqual(mod["az_count"], 3)                       # extra var overrides
        self.assertEqual(mod["tags"]["Project"], "acme")
        self.assertEqual(mod["tags"]["Team"], "x")
        self.assertIn("$${not.interpolated}", mod["ssh_public_key"])  # escaped
        self.assertEqual(root["provider"]["aws"]["profile"], "p1")
        self.assertNotIn("backend", root["terraform"])
        self.assertTrue(root["output"]["bastion_public_ip"]["value"].startswith("${module.stack."))

    def test_backend_blocks(self):
        aws, gcp, az = clouds.get("aws"), clouds.get("gcp"), clouds.get("azure")
        c = self.cfg("aws", profile="")
        self.assertEqual(aws.backend_from_outputs(c, {"bucket": "b", "region": "r1"})["s3"]["use_lockfile"], True)
        c = self.cfg("gcp", project_id="p")
        self.assertEqual(gcp.backend_from_outputs(c, {"bucket": "b"})["gcs"]["prefix"], "gcp-dev")
        c = self.cfg("azure", subscription_id="s")
        self.assertEqual(az.backend_from_outputs(c, {"resource_group_name": "rg", "storage_account_name": "sa",
                                                     "container_name": "c"})["azurerm"]["key"], "azure-dev.tfstate")

    def test_gcp_labels_are_valid(self):
        root = clouds.get("gcp").render_stack(self.cfg("gcp", project_id="p", zone="r1-a"), Path("/tf"))
        for k, v in root["module"]["stack"]["labels"].items():
            self.assertRegex(k, r"^[a-z0-9_-]+$")
            self.assertRegex(v, r"^[a-z0-9_-]*$")


class AgentTests(unittest.TestCase):
    def test_fill_drops_model_flag_when_unset(self):
        tpl = ["claude", "-p", "{prompt}", "--model", "{model}", "--x"]
        self.assertEqual(agents._fill(tpl, "hi", None), ["claude", "-p", "hi", "--x"])
        self.assertEqual(agents._fill(tpl, "hi", "m1"), ["claude", "-p", "hi", "--model", "m1", "--x"])


class ParserTests(unittest.TestCase):
    def test_setup_flags(self):
        a = build_parser().parse_args(["setup", "aws", "--env", "dev", "--allow-ip", "1.2.3.4", "--var", "az_count=3",
                                       "--runtime", "container", "-y"])
        self.assertEqual(a.cloud, "aws")
        self.assertEqual(a.runtime, "container")
        self.assertTrue(a.yes)

    def test_top_level_runtime_not_overridden(self):
        a = build_parser().parse_args(["--runtime", "local", "plan", "gcp"])
        self.assertEqual(a.runtime, "local")

    def test_agentic_remainder(self):
        for cmd in ("agentic", "do"):
            a = build_parser().parse_args([cmd, "--model", "m", "make", "an", "env"])
            self.assertEqual(a.task, ["make", "an", "env"])
            self.assertEqual(a.model, "m")

    def test_no_free_text_routing(self):
        import contextlib, io
        from cloudseed.cli import main
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = main(["set", "up", "aws"])
        self.assertEqual(rc, 2)
        self.assertIn("unknown command 'set'", buf.getvalue())
        self.assertIn("cloudseed agentic", buf.getvalue())


if __name__ == "__main__":
    unittest.main()


class BuiltinAgentTests(unittest.TestCase):
    def test_guard_blocks_meta_commands(self):
        from cloudseed import builtin_agent as b
        self.assertIsNone(b.guard(["status", "aws", "--env", "dev"]))
        self.assertIsNotNone(b.guard(["do", "something"]))
        self.assertIsNotNone(b.guard(["setup", "aws", "--runtime", "container"]))
        self.assertIsNotNone(b.guard(["setup", "aws", "--ssh-private-key", "/x"]))
        self.assertTrue(b.is_destructive(["destroy", "aws", "--auto-approve"]))   # (without it: a preview, exit 3)
        self.assertTrue(b.is_destructive(["apply", "aws", "--auto-approve"]))
        self.assertFalse(b.is_destructive(["plan", "aws"]))

    def test_system_prompt_picks_skills(self):
        from cloudseed import builtin_agent as b
        sp = b.system_prompt("destroy the aws dev env")
        self.assertIn('name="cloudseed-aws"', sp)
        self.assertIn('name="cloudseed-destroy"', sp)
        self.assertNotIn('name="cloudseed-gcp"', sp)

    def test_readiness_and_page(self):
        spec = agents.get("grok")
        ok, msg = agents.readiness(spec)
        if not agents.installed(spec):
            self.assertFalse(ok)
            self.assertIn("npm install", msg)
        page = agents.agents_page({})
        for key in ("builtin", "claude", "codex", "gemini", "grok"):
            self.assertIn(key, page)
        self.assertTrue(build_parser().parse_args(["agents"]).cmd == "agents")

    def test_session_keeps_agent_key(self):
        os.environ["GEMINI_API_KEY"] = "test-key-123456"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "s3cr3t-abcdefgh"
        try:
            sid, env = secrets.open_session(keep=("GEMINI_API_KEY",))
            secrets.close_session(sid)
            self.assertIn("GEMINI_API_KEY", env)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        finally:
            del os.environ["GEMINI_API_KEY"], os.environ["AWS_SECRET_ACCESS_KEY"]

    def test_builtin_registered(self):
        spec = agents.get("builtin")
        self.assertTrue(spec["builtin"])
        self.assertEqual(agents.installed(spec), "builtin")


class ExplainTests(unittest.TestCase):
    def test_explain_everything(self):
        import contextlib, io
        from cloudseed import cli
        for words in (["kubernetes"], ["vmware"], ["platform"], ["platform", "security"], ["istio"], ["destroy"], ["quickstart"], []):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.cmd_explain(cli.build_parser().parse_args(["explain", *words]), {})
            self.assertEqual(rc, 0, words)
            self.assertGreater(len(buf.getvalue()), 100, words)
        with self.assertRaises(SystemExit):
            cli.cmd_explain(cli.build_parser().parse_args(["explain", "nonsense-xyz"]), {})

    def test_env_recovered_from_remainder(self):
        from cloudseed.cli import build_parser, _pull_env_from_remainder
        a = build_parser().parse_args(["ssh", "vmware", "--env", "cstest", "--", "uname", "-a"])
        _pull_env_from_remainder(a, "ssh_args")
        self.assertEqual((a.env, a.ssh_args), ("cstest", ["--", "uname", "-a"]))


class SshArgsTests(unittest.TestCase):
    def test_ssh_arg_order(self):
        import contextlib, io
        from cloudseed import cli, paths
        env = paths.Env("aws", "sshtest"); env.create_dirs()
        env.save({"cloud": "aws", "env": "sshtest", "vars": {}})
        (env.dir / "outputs.json").write_text('{"bastion_public_ip": "203.0.113.5"}')
        captured = {}
        cli.subprocess.call = lambda cmd, **kw: captured.setdefault("cmd", cmd) or 0
        args = cli.build_parser().parse_args(["ssh", "aws", "--env", "sshtest", "--", "-L", "8080:10.0.0.1:80", "uname", "-a"])
        with contextlib.redirect_stdout(io.StringIO()):
            cli.cmd_ssh(args, {})
        cmd = captured["cmd"]
        dest = next(i for i, a in enumerate(cmd) if "@" in a)
        self.assertEqual(cmd[dest - 2:dest], ["-L", "8080:10.0.0.1:80"])
        self.assertEqual(cmd[dest + 1:], ["uname", "-a"])


class HelpTests(unittest.TestCase):
    def test_pages(self):
        from cloudseed import help as h
        self.assertIn("CORE COMMANDS", h.page(None, None))
        for cmd in ("setup", "destroy", "agentic", "deps", "skill"):
            self.assertIn("cloudseed " + cmd, h.page(cmd, None))
        for topic in ("security", "agentic", "state", "deps", "troubleshooting", "examples", "quickstart", "envs"):
            self.assertTrue(len(h.page(topic, None)) > 200, topic)
        self.assertIn("Usage: cloudseed help variables", h.page("variables", None))
        for cloud in ("aws", "gcp", "azure"):
            self.assertIn("allowed_ssh_cidrs", h.page("variables", cloud))
            self.assertIn("bastion_public_ip", h.page("outputs", cloud))
        self.assertIn("EXAMPLES", h.epilog("setup"))
        self.assertTrue(build_parser().parse_args(["help", "variables", "aws"]).cloud == "aws")


class ErrorHintTests(unittest.TestCase):
    def test_suggest_and_hint(self):
        from cloudseed import help as h
        self.assertIn("status", h.suggest("stauts"))
        text = h.error_hint("setup", "needs a cloud", None)
        self.assertIn("cloudseed setup aws", text)
        self.assertIn("cloudseed help setup", text)
        self.assertIn("Common commands", h.error_hint(None, "unknown", "sttus"))

    def test_terraform_explain(self):
        from cloudseed import tf
        self.assertIn("aws sso login", tf.explain("Error: ... api error InvalidClientTokenId: bad", "plan"))
        self.assertIn("gcloud auth application-default login", tf.explain("could not find default credentials", "plan"))
        self.assertIn("az login", tf.explain("Error: building account: obtaining Authorization Token", "plan"))
        self.assertIn("enable_guardduty=false", tf.explain("BadRequestException: The request is rejected because a detector already exists", "apply"))
        self.assertIn("see the output above", tf.explain("something odd", "apply"))

    def test_parser_error_shows_examples(self):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf), self.assertRaises(SystemExit) as cm:
            build_parser().parse_args(["setup"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("needs a cloud", buf.getvalue())
        self.assertIn("cloudseed setup gcp -y", buf.getvalue())

    def test_noninteractive_required_names_flag(self):
        from cloudseed import ui
        old = ui.NON_INTERACTIVE
        ui.NON_INTERACTIVE = True
        try:
            with self.assertRaises(ui.Abort) as cm:
                ui.ask("GCP project ID", "", required=True, flag="--project-id")
            self.assertIn("--project-id", cm.exception.msg)
        finally:
            ui.NON_INTERACTIVE = old


class ServicesTests(unittest.TestCase):
    def test_kubeconfig_commands(self):
        from cloudseed import services
        cfg = {"env": "dev", "region": "us-east-1", "vars": {"profile": "p", "project_id": "proj", "zone": "us-central1-a",
                                                            "subscription_id": "sub"}}
        out = {"kubernetes_cluster_name": "acme-dev-eks", "resource_group_name": "rg", "kubernetes_location": "us-central1-a"}
        self.assertEqual(services.kubeconfig_command("aws", cfg, out)[:4], ["aws", "eks", "update-kubeconfig", "--name"])
        self.assertIn("--internal-ip", services.kubeconfig_command("gcp", cfg, out))
        self.assertIn("--resource-group", services.kubeconfig_command("azure", cfg, out))
        with self.assertRaises(SystemExit):
            services.kubeconfig_command("aws", cfg, {})

    def test_parser_k8s_vpn_order(self):
        a = build_parser().parse_args(["vpn", "add-user", "aws", "--env", "dev", "alice"])
        self.assertEqual((a.vpn_cmd, a.cloud, a.name, a.env), ("add-user", "aws", "alice", "dev"))
        a = build_parser().parse_args(["k8s", "kubeconfig", "gcp"])
        self.assertEqual((a.k8s_cmd, a.cloud), ("kubeconfig", "gcp"))

    def test_stack_vars_include_services(self):
        cfg = {"cloud": "aws", "env": "dev", "name": "acme", "owner": "me", "region": "r", "network_cidr": "10.0.0.0/16",
               "allowed_ssh_cidrs": ["1.2.3.4/32"], "ssh_public_key": "ssh-ed25519 AAAA x",
               "state": {"type": "local", "backend": None}, "vars": {"enable_vpn": True, "vpn_type": "tailscale"},
               "extra_vars": {}, "tags": {}}
        for key in ("aws", "gcp", "azure"):
            cfg["vars"].update({"project_id": "p", "zone": "z-a", "subscription_id": "s"})
            v = clouds.get(key).stack_vars(cfg)
            self.assertIn("enable_kubernetes", v)
            self.assertEqual(v["vpn_type"], "tailscale")
            self.assertIn("vpn_public_ip", clouds.get(key).outputs)

    def test_provision_excludes(self):
        from cloudseed import provision
        self.assertFalse(provision._include(Path(".git/config")))
        self.assertFalse(provision._include(Path("envs/x/terraform.tfstate")))
        self.assertTrue(provision._include(Path("ansible/bastion.yml")))


class VMwareTests(unittest.TestCase):
    def test_find_installer(self):
        from cloudseed import localvm
        d = Path(tempfile.mkdtemp())
        f = d / "VMware-Fusion-13.6.4-12345.dmg"
        f.write_bytes(b"x")
        self.assertEqual(localvm.find_installer(str(f)), f)
        self.assertIsNone(localvm.find_installer(str(d / "missing.dmg")))
        localvm._search_dirs = lambda: [d]
        if localvm.platform.system().lower() == "darwin":
            self.assertEqual(localvm.find_installer(), f)

    def test_image_catalogue_and_guest_ids(self):
        from cloudseed import localvm
        for os_key, spec in localvm.IMAGES.items():
            for arch in ("amd64", "arm64"):
                self.assertIn("file", spec[arch])
                self.assertTrue(spec[arch]["base"].startswith("https://"))
                self.assertTrue(localvm.guest_os_id(os_key, arch))
        self.assertEqual(localvm.guest_os_id("ubuntu-24.04", "arm64"), "arm-ubuntu-64")
        self.assertFalse(localvm.IMAGES["ubuntu-24.04"]["amd64"]["convert"])
        self.assertTrue(localvm.IMAGES["ubuntu-24.04"]["arm64"]["convert"])

    def test_vmrest_password_policy(self):
        from cloudseed import localvm
        for _ in range(20):
            pw = localvm._generate_vmrest_password()
            self.assertTrue(8 <= len(pw) <= 12)
            self.assertTrue(any(c.isupper() for c in pw) and any(c.islower() for c in pw) and any(c.isdigit() for c in pw))
            self.assertTrue(any(c in "!#$%&*+-=?@^_" for c in pw))

    def test_detect_host_is_graceful(self):
        from cloudseed import localvm
        h = localvm.detect_host()
        self.assertTrue(h is None or "found" in h)

    def test_render_vmware_stack(self):
        cfg = {"cloud": "vmware", "env": "lab", "name": "acme", "owner": "me", "region": "local",
               "network_cidr": "10.100.0.0/24", "allowed_ssh_cidrs": ["127.0.0.1/32"], "ssh_public_key": "ssh-ed25519 AAAA x",
               "state": {"type": "local", "backend": None},
               "vars": {"guest_os": "debian-12", "guest_os_id": "arm-debian12-64", "base_disk": "/tmp/x.vmdk", "workload_count": 2},
               "extra_vars": {}, "tags": {}}
        root = clouds.get("vmware").render_stack(cfg, Path("/tf"))
        mod = root["module"]["stack"]
        self.assertEqual(mod["source"], "/tf/vmware")
        self.assertEqual(mod["workload_count"], 2)
        self.assertEqual(mod["guest_os_id"], "arm-debian12-64")
        self.assertIn("vmdesktop", root["terraform"]["required_providers"])
        self.assertNotIn("backend", root["terraform"])

    def test_vmware_kubernetes_vars(self):
        cfg = {"cloud": "vmware", "env": "lab", "name": "acme", "owner": "me", "region": "local",
               "network_cidr": "10.100.0.0/24", "allowed_ssh_cidrs": ["127.0.0.1/32"], "ssh_public_key": "ssh-ed25519 AAAA x",
               "state": {"type": "local", "backend": None}, "workdir": "/tmp/w",
               "vars": {"enable_kubernetes": True, "kubernetes_distro": "kubeadm", "kubernetes_workers": 3, "base_disk": "/x", "guest_os_id": "ubuntu-64"},
               "extra_vars": {}, "tags": {}}
        v = clouds.get("vmware").stack_vars(cfg)
        self.assertTrue(v["enable_kubernetes"])
        self.assertEqual((v["kubernetes_distro"], v["kubernetes_workers"]), ("kubeadm", 3))
        from cloudseed import services
        self.assertEqual(services.kubeconfig_command("vmware", cfg, {})[0], "export")

    def test_parser_accepts_vmware(self):
        a = build_parser().parse_args(["setup", "vmware", "--env", "lab", "-y"])
        self.assertEqual(a.cloud, "vmware")
        self.assertTrue(clouds.get("vmware").local)


class WorkdirTests(unittest.TestCase):
    def test_custom_workdir_is_remembered(self):
        from cloudseed import paths
        custom = Path(tempfile.mkdtemp(prefix="cs-work-")) / "lab"
        env = paths.Env("vmware", "wdtest")
        env.set_workdir(custom)
        self.assertEqual(env.dir, custom.resolve())
        self.assertTrue(env.stack_dir.exists() and env.ssh_dir.exists())
        env.save({"cloud": "vmware", "env": "wdtest"})
        again = paths.Env("vmware", "wdtest")
        self.assertEqual(again.dir, custom.resolve())
        self.assertIn("vmware-wdtest", [e.id for e in paths.Env.list_all()])
        self.assertEqual(env.load()["workdir"], str(custom.resolve()))
        env.set_workdir(None)
        self.assertEqual(paths.Env("vmware", "wdtest").dir, paths.ENVS_DIR / "vmware-wdtest")

    def test_parser_workdir(self):
        a = build_parser().parse_args(["setup", "vmware", "--workdir", "/tmp/x", "-y"])
        self.assertEqual(a.workdir, "/tmp/x")


class AuditTests(unittest.TestCase):
    def test_audit_and_inventory_written(self):
        from cloudseed import audit, paths
        env = paths.Env("aws", "audittest")
        env.create_dirs()
        audit.begin(["status", "aws", "--env", "audittest"])
        audit.attach(env)
        from cloudseed import ui
        ui.info("hello AKIA" + "IOSFODNN7EXAMPLE")
        audit.end(3)
        rec = audit.read_audit(env)[-1]
        self.assertEqual(rec["exit_code"], 3)
        self.assertEqual(rec["env"], "aws-audittest")
        text = Path(rec["log"]).read_text()
        self.assertIn("hello", text)
        self.assertNotIn("AKIA" + "IOSFODNN7EXAMPLE", text)
        audit.note(env, "provision-bastion", {"host": "1.2.3.4"})
        inv = audit.load(env)
        self.assertEqual(inv["history"][-1]["action"], "provision-bastion")
        self.assertEqual(inv["current"]["notes"]["provision-bastion"]["host"], "1.2.3.4")

    def test_troubleshoot_scans_hints(self):
        from cloudseed import troubleshoot
        log = Path(tempfile.mkdtemp()) / "x.log"
        log.write_text("ssh: connect to host 1.2.3.4 port 22: Connection timed out\nError: InvalidClientTokenId\n")
        hits = troubleshoot._scan_log(log)
        self.assertTrue(any("not reachable" in h.what for h in hits))
        self.assertTrue(any("AWS credentials" in h.what for h in hits))


class PlatformTests(unittest.TestCase):
    def _ctx(self, target, distro):
        from cloudseed import platform as pl, paths
        env = paths.Env(target, "pt")
        env.create_dirs()
        cfg = {"env": "pt", "region": "r", "network_cidr": "10.100.0.0/24"}
        outputs = {"kubernetes_distro": distro} if target == "vmware" else {"kubernetes_cluster_name": "c"}
        return pl.Cluster(clouds.get(target), env, cfg, outputs, env.dir / "k8s" / "kubeconfig")

    def test_catalog_integrity(self):
        from cloudseed import platform as pl
        for name, spec in pl.CATALOG.items():
            self.assertIn(spec["group"], pl.GROUPS, name)
            self.assertIn(spec["method"], ("helm", "oci", "kustomize", "manifest", "git", "meta", "post-only"), name)
            for dep in spec.get("needs", []):
                self.assertIn(dep, pl.CATALOG, f"{name} needs unknown {dep}")

    def test_resolve_orders_dependencies_and_filters_targets(self):
        from cloudseed import platform as pl
        vm = self._ctx("vmware", "rke2")
        items = pl.resolve(["ingress-nginx", "opentelemetry-operator"], vm)
        self.assertLess(items.index("metallb"), items.index("ingress-nginx"))
        self.assertLess(items.index("cert-manager"), items.index("opentelemetry-operator"))
        aws = self._ctx("aws", "eks")
        self.assertNotIn("metallb", pl.resolve(["basek8s"], aws))
        base = pl.resolve(["basek8s"], aws)
        self.assertIn("gateway-api", base)
        self.assertIn("envoy-gateway", base)
        self.assertNotIn("ingress-nginx", base)
        self.assertLess(base.index("gateway-api"), base.index("cert-manager"))
        self.assertLess(base.index("cert-manager-issuer"), base.index("envoy-gateway"))
        self.assertIn("aws-load-balancer-scheme", aws.placeholders()["lb_annotations"])
        self.assertIn("cloudseed.io/lb", vm.placeholders()["lb_annotations"])
        self.assertIn("HTTPRoute", pl.HTTPROUTE_TEMPLATE.format(name="x", ns="n", host="h", svc="s", port=80))
        self.assertIn("aws-load-balancer-controller", pl.CATALOG)
        self.assertNotIn("cluster-autoscaler", pl.resolve(["scaling"], vm))
        self.assertIn("keda", pl.resolve(["scaling"], vm))

    def test_values_and_placeholders(self):
        from cloudseed import platform as pl
        vm = self._ctx("vmware", "kubeadm")
        args = pl._values_args(pl.CATALOG["metrics-server"], vm)
        self.assertIn("args[0]=--kubelet-insecure-tls", args)
        ph = vm.placeholders()
        self.assertTrue(ph["grafana_password"])
        self.assertEqual(ph["grafana_password"], vm.placeholders()["grafana_password"])  # stable per env
        self.assertIn("-", ph["lb_range"])

    def test_meta_and_skip(self):
        from cloudseed import platform as pl
        vm = self._ctx("vmware", "rke2")
        items = pl.resolve(["istio"], vm)
        self.assertEqual(items[:4], ["istio-base", "istiod", "istio-cni", "ztunnel"])
        vm.options["mode"] = "sidecar"
        self.assertNotIn("ztunnel", pl.resolve(["istio"], vm))
        self.assertIn("argocd", pl.resolve(["devsecops"], vm))
        self.assertTrue(pl._already_installed(pl.CATALOG["argocd"], "argocd", {"argocd/argocd": {"status": "deployed"}}))
        self.assertFalse(pl._already_installed(pl.CATALOG["argocd"], "argocd", {}))

    def test_post_manifests_render(self):
        """Every manifest, rendered exactly as `platform install` renders it, is well-formed YAML with every
        placeholder resolved, on every target. Stdlib checks always run; a full YAML parse runs when PyYAML exists."""
        from cloudseed import platform as pl
        try:
            import yaml
        except ImportError:
            yaml = None
        for target, distro in (("vmware", "rke2"), ("aws", "eks"), ("gcp", "gke"), ("azure", "aks")):
            ctx = self._ctx(target, distro)
            for name in pl.POST_MANIFESTS:
                text = render_post_manifest(ctx, name)
                self.assertEqual(structure_problems(text), [], f"{name} on {target}:\n{text}")
                if yaml is not None:
                    docs = list(yaml.safe_load_all(text))
                    self.assertTrue(all(isinstance(d, dict) and "kind" in d for d in docs), f"{name} on {target}")
        self.assertIn("selfSigned: {}", render_post_manifest(self._ctx("aws", "eks"), "selfsigned-issuer"))

    def test_plan_dedup_conflicts(self):
        from cloudseed import platform as pl
        vm = self._ctx("vmware", "rke2")
        # duplicates across groups resolve once
        items = pl.resolve(["basek8s", "devsecops", "finops", "security"], vm)
        self.assertEqual(len(items), len(set(items)))
        self.assertEqual(items.count("argocd"), 1)
        self.assertEqual(items.count("cert-manager"), 1)
        # conflict: kubecost after opencost is skipped; sibling values wired
        entries = pl.plan(["opencost", "kubecost-cost-analyzer", "kube-prometheus-stack"], vm, releases={})
        by = {e["item"]: e for e in entries}
        self.assertEqual(by["kubecost-cost-analyzer"]["action"], "skip-conflict")
        self.assertEqual(by["opencost"]["action"], "install")
        forced = {e["item"]: e for e in pl.plan(["kubecost-cost-analyzer", "kube-prometheus-stack"], vm, releases={}, force=True)}
        self.assertEqual(forced["kubecost-cost-analyzer"]["action"], "install")
        self.assertEqual(forced["kubecost-cost-analyzer"]["sets"]["prometheus.enabled"], "false")
        rke2 = self._ctx("vmware", "rke2")
        prov = {x["item"]: x for x in pl.plan(["metrics-server", "ingress-nginx", "keda"], rke2, releases={})}
        self.assertEqual(prov["metrics-server"]["action"], "skip-provided")
        self.assertEqual(prov["ingress-nginx"]["action"], "install")   # RKE2's bundled ingress is disabled by the rke2 role
        self.assertEqual(prov["keda"]["action"], "install")
        # already installed -> skip; overlap -> warning reason
        rel = {"monitoring/monitoring": {"status": "deployed", "chart": "kube-prometheus-stack-1"}}
        e = {x["item"]: x for x in pl.plan(["kube-prometheus-stack", "kiali"], vm, releases=rel)}
        self.assertEqual(e["kube-prometheus-stack"]["action"], "skip-installed")
        self.assertIn("external_services.prometheus.url", e["kiali"]["sets"])
        ov = {x["item"]: x for x in pl.plan(["falco", "neuvector"], vm, releases={})}
        self.assertTrue(any("overlaps" in r for r in ov["neuvector"]["reasons"]))
        # rules reference real items; no two items share namespace/release
        for item, rule in pl.RULES.items():
            self.assertIn(item, pl.CATALOG, item)
            for other in rule.get("conflicts", []) + list(rule.get("when_installed", {})):
                self.assertIn(other, pl.CATALOG, f"{item} -> {other}")
        keys = [f"{v.get('ns', 'default')}/{v.get('release', k)}" for k, v in pl.CATALOG.items() if v["method"] in ("helm", "oci", "git")]
        self.assertEqual(len(keys), len(set(keys)), "namespace/release collision in catalog")

    def test_group_info(self):
        from cloudseed import platform as pl
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pl.group_info("security", None)
            pl.info("istio", None)
            pl.status(None, charts=True)
        out = buf.getvalue()
        for w in ("ztunnel", "falco", "kyverno-policies", "(dependency)", "[extra]", "bundle of", "https://istio-release"):
            self.assertIn(w, out)

    def test_parsers(self):
        a = build_parser().parse_args(["node", "add", "--count", "2", "--role", "worker", "vmware", "--env", "dev"])
        self.assertEqual((a.node_cmd, a.count, a.role, a.cloud, a.env), ("add", 2, "worker", "vmware", "dev"))
        a = build_parser().parse_args(["platform", "install", "basek8s", "trino", "--no-wait"])
        self.assertEqual(a.items, ["basek8s", "trino"])
        a = build_parser().parse_args(["kubectl", "get", "pods", "-A"])
        self.assertEqual(a.tool_args, ["get", "pods", "-A"])
        a = build_parser().parse_args(["env", "use", "vmware-dev"])
        self.assertEqual((a.env_cmd, a.id), ("use", "vmware-dev"))


class SkillCoverageTests(unittest.TestCase):
    def test_every_command_has_a_skill(self):
        from cloudseed.cli import HANDLERS
        from cloudseed import paths
        text = "\n".join(p.read_text() for p in (paths.REPO_ROOT / "skills").rglob("SKILL.md"))
        missing = [c for c in HANDLERS if f"cloudseed {c}" not in text and f"cs {c}" not in text and c not in ("do", "help")]
        self.assertEqual(missing, [], f"commands without skill coverage: {missing}")


class FinopsTests(unittest.TestCase):
    def test_estimate(self):
        from cloudseed import finops, paths
        env = paths.Env("aws", "fin")
        env.create_dirs()
        cfg = {"vars": {"bastion_instance_type": "t3.micro", "enable_kubernetes": True, "kubernetes_node_count": 3,
                        "kubernetes_node_size": "t3.medium", "single_nat_gateway": True}}
        est = finops.estimate(clouds.get("aws"), env, cfg)
        self.assertGreater(est["total"], 100)
        self.assertTrue(any("EKS control plane" in n for n, _ in est["lines"]))
        vm = finops.estimate(clouds.get("vmware"), paths.Env("vmware", "fin"), {"vars": {"workload_count": 2}})
        self.assertEqual(vm["total"], 0.0)

    def test_ui_registry_and_group(self):
        from cloudseed import platform as pl
        for item in pl.UIS:
            self.assertIn(item, pl.CATALOG, item)
        self.assertIn("opencost", pl.CATALOG)
        self.assertEqual(pl.CATALOG["cert-manager-issuer"]["group"], "basek8s")
        self.assertIn("spark-history-server", pl.CATALOG)
        a = build_parser().parse_args(["finops", "k8s", "--by", "controller"])
        self.assertEqual((a.finops_cmd, a.by), ("k8s", "controller"))


class ReconcileTests(unittest.TestCase):
    def test_conflict_parsing_and_import_ids(self):
        from cloudseed import reconcile as rc
        out = """Error: creating IAM Role (acme-dev-bastion): EntityAlreadyExists: Role with name acme-dev-bastion already exists.

  with module.stack.module.bastion.aws_iam_role.bastion,
  on main.tf line 1

Error: something unrelated failed

  with module.stack.module.network.aws_vpc.this,

Error: creating GuardDuty Detector: BadRequestException: The request is rejected because a detector already exists for the current account.

  with module.stack.module.security_baseline[0].aws_guardduty_detector.this[0],
"""
        addrs = rc.conflicts(out)
        self.assertEqual(addrs, ["module.stack.module.bastion.aws_iam_role.bastion",
                                 "module.stack.module.security_baseline[0].aws_guardduty_detector.this[0]"])
        lk = rc.CloudLookups("azure", {"vars": {"subscription_id": "sub1"}})
        self.assertEqual(rc.IMPORT_ID["aws_iam_role"]({"name": "r"}, lk), "r")
        self.assertEqual(rc.IMPORT_ID["azurerm_resource_group"]({"name": "rg"}, lk), "/subscriptions/sub1/resourceGroups/rg")
        self.assertIn("serviceAccounts/x@p.iam", rc.IMPORT_ID["google_service_account"]({"project": "p", "account_id": "x"}, lk))

    def test_platform_wires_cloud_identities(self):
        from cloudseed import platform as pl, paths
        env = paths.Env("aws", "irsa")
        env.create_dirs()
        outputs = {"kubernetes_cluster_name": "c", "vpc_id": "vpc-1",
                   "kubernetes_irsa_role_arns": {"lb-controller": "arn:lb", "autoscaler": "arn:as", "external-secrets": "arn:es"}}
        ctx = pl.Cluster(clouds.get("aws"), env, {"env": "irsa", "region": "us-east-1", "network_cidr": "10.0.0.0/16"}, outputs, env.dir / "kc")
        args = " ".join(pl._values_args(pl.CATALOG["aws-load-balancer-controller"], ctx))
        self.assertIn("role-arn=arn:lb", args)
        args = " ".join(pl._values_args(pl.CATALOG["external-secrets"], ctx))
        self.assertIn("role-arn=arn:es", args)
        gcp_env = paths.Env("gcp", "wi"); gcp_env.create_dirs()
        gctx = pl.Cluster(clouds.get("gcp"), gcp_env, {"env": "wi", "region": "r", "network_cidr": "10.0.0.0/16", "vars": {"project_id": "p"}},
                          {"kubernetes_cluster_name": "c", "kubernetes_external_secrets_gsa": "es@p.iam.gserviceaccount.com"}, gcp_env.dir / "kc")
        self.assertIn("gcp-service-account=es@p.iam", " ".join(pl._values_args(pl.CATALOG["external-secrets"], gctx)))


class McpTests(unittest.TestCase):
    def test_tools_and_guards(self):
        from cloudseed import mcp
        tools = {t["name"]: t for t in mcp.tool_list()}
        for name in ("cloudseed_setup", "cloudseed_status", "cloudseed_destroy", "cloudseed_platform", "cloudseed_finops", "cloudseed_explain", "cloudseed_kubectl"):
            self.assertIn(name, tools)
        self.assertTrue(tools["cloudseed_destroy"]["annotations"]["destructiveHint"])
        self.assertFalse(tools["cloudseed_status"]["annotations"]["destructiveHint"])
        r = mcp.call_tool("cloudseed_destroy", {"cloud": "aws"}, dict(os.environ))
        self.assertTrue(r["isError"]); self.assertIn("confirm=true", r["content"][0]["text"])
        self.assertEqual(mcp.TOOLS["cloudseed_setup"]["argv"]({"cloud": "aws", "env": "d", "vars": {"enable_vpn": True}}),
                         ["setup", "aws", "--env", "d", "-y", "--var", "enable_vpn=true", "--preview"])
        self.assertTrue(mcp.TOOLS["cloudseed_kubectl"]["destructive_when"]({"args": "delete pod x"}))
        self.assertFalse(mcp.TOOLS["cloudseed_kubectl"]["destructive_when"]({"args": "get pods -A"}))

    def test_stdio_roundtrip(self):
        import json, subprocess, sys
        from cloudseed import paths
        env = dict(os.environ, CLOUDSEED_MCP_FORCE="1", NO_COLOR="1")
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "cloudseed_explain", "arguments": {"what": "audit"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "nope"}]
        proc = subprocess.run([sys.executable, str(paths.REPO_ROOT / "bin" / "cloudseed"), "mcp", "serve"], input="\n".join(json.dumps(m) for m in msgs) + "\n",
                              capture_output=True, text=True, env=env, timeout=120)
        # one answer per request, matched by id: requests are served concurrently, so a slow tool call may answer
        # after a later request (JSON-RPC pairs answers with requests by id, not by order)
        out = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
        self.assertEqual(sorted(o["id"] for o in out), [1, 2, 3, 4], proc.stdout + proc.stderr)
        by_id = {o["id"]: o for o in out}
        self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], "cloudseed")
        self.assertGreater(len(by_id[2]["result"]["tools"]), 15)
        self.assertIn("audit.jsonl", by_id[3]["result"]["content"][0]["text"])
        self.assertIn("error", by_id[4])



class PlatformClusterTests(unittest.TestCase):
    def test_env_is_env_object_and_procenv_is_dict(self):
        import inspect
        from cloudseed import paths, platform as platformmod
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            env = paths.Env("vmware", "unit", tmp / "envs" / "vmware-unit")
            cfg = {"env": "unit", "region": "", "network_cidr": "10.100.0.0/24"}
            ctx = platformmod.Cluster(clouds.get("vmware"), env, cfg, {"kubernetes_distro": "rke2"}, tmp / "kubeconfig")
            self.assertIs(ctx.env, env)
            e = ctx.procenv()
            self.assertIsInstance(e, dict)
            self.assertEqual(e["KUBECONFIG"], str(tmp / "kubeconfig"))
            self.assertTrue(e["DOCKER_CONFIG"].endswith("/helm/docker"))   # never the user's ~/.docker (credential helpers)
            self.assertTrue(e["HELM_REGISTRY_CONFIG"].endswith("registry.json"))
        # every helper that shells out must use procenv(); the Env object is not callable
        src = inspect.getsource(platformmod)
        self.assertNotIn("ctx.env()", src)
        self.assertNotIn("self.env()", src)

    def test_platform_accepts_cloud_key_among_items(self):
        args = build_parser().parse_args(["platform", "plan", "keda", "vmware", "--env", "k8stest"])
        self.assertEqual(args.items, ["keda", "vmware"])
        self.assertIsNone(args.cloud)
        from cloudseed import cli
        keys = [i for i in args.items if i in cli.CLOUD_KEYS]
        self.assertEqual(keys, ["vmware"])


class LocalHostGateTests(unittest.TestCase):
    def test_vm_changing_commands_need_the_hypervisor_and_read_only_ones_do_not(self):
        from cloudseed import cli
        need = [["node", "add", "vmware", "--env", "x"], ["node", "remove", "vmware", "wk1", "--env", "x"],
                ["apply", "vmware"], ["plan", "vmware"], ["provision", "vmware"]]
        no_need = [["node", "list", "vmware"], ["status", "vmware"], ["platform", "status", "vmware"],
                   ["k8s", "info", "vmware"], ["ssh", "vmware"], ["inventory", "vmware"]]
        for argv in need:
            self.assertTrue(cli._touches_vms(build_parser().parse_args(argv)), argv)
        for argv in no_need:
            self.assertFalse(cli._touches_vms(build_parser().parse_args(argv)), argv)


class KnownHostsTests(unittest.TestCase):
    def test_every_ssh_uses_the_environment_known_hosts(self):
        from cloudseed import paths, provision, services, cli
        with tempfile.TemporaryDirectory() as td:
            env = paths.Env("vmware", "kh", Path(td) / "vmware-kh")
            kh = str(env.known_hosts_path())
            h = provision.Host("10.0.0.5", "u", Path(td) / "key", "cp1", env=env)
            self.assertIn(f'UserKnownHostsFile="{kh}"', h.ssh("true"))   # quoted: ssh splits the value at spaces
            self.assertIn("StrictHostKeyChecking=accept-new", h.ssh("true"))
            self.assertIn(f'UserKnownHostsFile="{kh}"', env.ssh_options())
            env.known_hosts_path().write_text("10.0.0.5 ssh-ed25519 AAAA\n")
            env.forget_host_keys()
            self.assertFalse(env.known_hosts_path().exists())
        # no SSH call site may fall back to the user's ~/.ssh/known_hosts
        import inspect
        for mod in (cli, provision, services):
            for line in inspect.getsource(mod).splitlines():
                if '["ssh", "-i"' in line:
                    self.assertTrue("ssh_options()" in line or "self.ssh_opts" in line, f"{mod.__name__}: {line.strip()}")


class ExtraVarsTests(unittest.TestCase):
    def test_unknown_var_is_refused_with_a_reason(self):
        from cloudseed import cli, ui
        with self.assertRaises(ui.Abort) as cm:
            cli._check_extra_vars(clouds.get("vmware"), {"enable_vpn": True})
        self.assertIn("reachable from this machine directly", cm.exception.msg)
        with self.assertRaises(ui.Abort) as cm:
            cli._check_extra_vars(clouds.get("aws"), {"single_nat_gatewy": False})
        self.assertIn("not a variable of the aws stack", cm.exception.msg)
        self.assertIn("help variables aws", cm.exception.msg)
        cli._check_extra_vars(clouds.get("aws"), {"single_nat_gateway": False, "enable_vpn": True})   # declared: fine
        cli._check_extra_vars(clouds.get("vmware"), {"kubernetes_workers": 1, "workload_count": 1})


class ClusterTokenTests(unittest.TestCase):
    def test_token_matches_kubeadm_bootstrap_format(self):
        from cloudseed import provision
        for _ in range(20):
            self.assertRegex(provision.new_cluster_token("kubeadm"), r"^[a-z0-9]{6}\.[a-z0-9]{16}$")
            self.assertRegex(provision.new_cluster_token("rke2"), r"^[0-9a-f]{48}$")   # no '.': RKE2 would read it as K10 format
            self.assertRegex(provision.new_cluster_token(), r"^[0-9a-f]{48}$")


class GatewayApiPinTests(unittest.TestCase):
    def test_gateway_api_pin_matches_the_channel_envoy_gateway_bundles(self):
        from cloudseed import platform as platformmod
        ga = platformmod.CATALOG["gateway-api"]
        self.assertEqual(ga["gateway_api"], {"channel": "experimental", "version": "v1.6.1"})
        self.assertIn("/v1.6.1/experimental-install.yaml", ga["url"])
        self.assertIn("gateway-api", platformmod.CATALOG["envoy-gateway"]["needs"])


class ProbeTests(unittest.TestCase):
    def test_release_less_items_are_recognised_through_probes(self):
        from cloudseed import platform as platformmod
        for item in ("gateway-api", "cert-manager-issuer", "kube-green"):
            spec = platformmod.CATALOG[item]
            self.assertIn("probe", spec, item)
            self.assertTrue(platformmod._already_installed(spec, item, {"probe:" + item: {"status": "present"}}))
            self.assertFalse(platformmod._already_installed(spec, item, {}))


class McpDeployTests(unittest.TestCase):
    """HTTP transport, client wiring and the guide - all in temp dirs, nothing on this machine is touched."""

    def test_http_transport_roundtrip(self):
        import http.client, io, threading, socket
        from contextlib import redirect_stderr
        from unittest import mock
        from cloudseed import mcp
        force = mock.patch.dict(os.environ, {"CLOUDSEED_MCP_FORCE": "1"})   # this test only: later ones see MCP as it is
        force.start()
        self.addCleanup(force.stop)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
        mcp.MCP_DIR.mkdir(parents=True, exist_ok=True)
        tok = mcp.ensure_token(rotate=True)
        with redirect_stderr(io.StringIO()):   # (a thread is no service: it says where it listens, before it answers)
            t = threading.Thread(target=mcp.serve_http, args=("127.0.0.1", port, True), daemon=True); t.start()
            for _ in range(40):
                if mcp.health({"host": "127.0.0.1", "port": port, "auth": "token"}):
                    break
                time.sleep(0.1)

        def post(path, body, headers=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            c.request("POST", path, body=json.dumps(body), headers={"Content-Type": "application/json", **(headers or {})})
            r = c.getresponse(); data = r.read().decode(); c.close(); return r.status, dict(r.getheaders()), data

        auth = {"Authorization": f"Bearer {tok}"}
        self.assertEqual(post("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"})[0], 401)
        self.assertEqual(post("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {**auth, "Origin": "http://evil.test"})[0], 403)
        st, hdr, body = post("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}, auth)
        self.assertEqual(st, 200); self.assertIn("Mcp-Session-Id", hdr)
        self.assertEqual(json.loads(body)["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(post("/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, auth)[0], 202)
        st, _, body = post("/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, auth)
        self.assertGreater(len(json.loads(body)["result"]["tools"]), 20)
        st, _, body = post("/mcp", {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "cloudseed://skills/cloudseed"}}, auth)
        self.assertIn("cloudseed", json.loads(body)["result"]["contents"][0]["text"])
        st, _, body = post("/mcp", {"jsonrpc": "2.0", "id": 4, "method": "prompts/get", "params": {"name": "teardown", "arguments": {"cloud": "aws", "env": "x"}}}, auth)
        self.assertIn("confirm=true", json.loads(body)["result"]["messages"][0]["content"]["text"])
        st, hdr, body = post("/mcp", {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "cloudseed_destroy", "arguments": {"cloud": "aws"}}},
                             {**auth, "Accept": "application/json, text/event-stream"})
        self.assertTrue(hdr.get("Content-Type", "").startswith("text/event-stream")); self.assertIn("confirm=true", body)
        # legacy SSE: endpoint event, then the response to a POST arrives on the stream
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30); c.request("GET", "/sse", headers=auth); r = c.getresponse()
        first = r.readline().decode() + r.readline().decode()
        sid = first.split("sessionId=")[1].strip()
        self.assertEqual(post(f"/messages?sessionId={sid}", {"jsonrpc": "2.0", "id": 9, "method": "ping"}, auth)[0], 202)
        got = ""
        for _ in range(20):
            got += r.readline().decode()
            if '"id": 9' in got:
                break
        self.assertIn('"id": 9', got)
        c.close()

    def test_client_wiring_and_guide(self):
        from unittest import mock
        from cloudseed import mcp
        home = tempfile.mkdtemp(prefix="cs-mcp-clients-")
        # a throw-away HOME and XDG_CONFIG_HOME (as test_fix_mcp's _Home): on Linux the Claude Desktop and VS Code
        # configs this test writes follow $XDG_CONFIG_HOME, which CI runners (and many desktops) point at the real
        # ~/.config; the environment is restored afterwards
        isolate = mock.patch.dict(os.environ, {"HOME": home, "XDG_CONFIG_HOME": str(Path(home) / ".config")})
        isolate.start()
        try:
            (Path(home) / ".codex").mkdir(); (Path(home) / ".codex" / "config.toml").write_text('model = "x"\n\n[mcp_servers.other]\ncommand = "y"\n')
            (Path(home) / ".cursor").mkdir(); (Path(home) / ".cursor" / "mcp.json").write_text('{"mcpServers": {"keep": {"command": "z"}}}')
            state = {"transport": "http", "host": "127.0.0.1", "port": 7555, "auth": "token", "service": "background"}
            mcp.ensure_token()
            self.assertIn("(http)", mcp.connect("codex", "http", state))
            self.assertEqual(mcp.connected("codex"), "http")
            toml = (Path(home) / ".codex" / "config.toml").read_text()
            self.assertIn("[mcp_servers.other]", toml); self.assertIn('url = "http://127.0.0.1:7555/mcp"', toml); self.assertIn("http_headers", toml)
            mcp.connect("codex", "stdio", state)
            self.assertEqual(mcp.connected("codex"), "stdio")
            self.assertEqual((Path(home) / ".codex" / "config.toml").read_text().count("[mcp_servers.cloudseed]"), 1)
            mcp.connect("cursor", "http", state)
            data = json.loads((Path(home) / ".cursor" / "mcp.json").read_text())
            self.assertIn("keep", data["mcpServers"]); self.assertIn("Authorization", data["mcpServers"]["cloudseed"]["headers"])
            mcp.connect("claude-desktop", "http", state)   # stdio-only client: http request degrades to stdio
            self.assertEqual(mcp.connected("claude-desktop"), "stdio")
            entry = json.loads(mcp.CLIENTS["claude-desktop"]["path"]().read_text())["mcpServers"]["cloudseed"]
            self.assertIn("PATH", entry["env"]); self.assertEqual(entry["args"][-2:], ["mcp", "serve"])
            mcp.connect("vscode", "http", state)
            self.assertEqual(json.loads(mcp.CLIENTS["vscode"]["path"]().read_text())["servers"]["cloudseed"]["type"], "http")
            self.assertIsNotNone(mcp.disconnect("cursor")); self.assertIsNone(mcp.connected("cursor")); self.assertIsNone(mcp.disconnect("cursor"))
            self.assertIsNotNone(mcp.disconnect("codex")); self.assertIn("[mcp_servers.other]", (Path(home) / ".codex" / "config.toml").read_text())
            guide = mcp.save_guide(state, {"codex": "http"})
            text = guide.read_text()
            for needle in ("http://127.0.0.1:7555/mcp", "confirm=true", "claude mcp add", "[mcp_servers.cloudseed]", "cs destroy mcp"):
                self.assertIn(needle, text)
            self.assertEqual(oct(guide.stat().st_mode & 0o777), "0o600")
            snippets = mcp.client_configs(state)
            self.assertTrue(any("Claude Desktop" in k for k in snippets))
        finally:
            isolate.stop()

    def test_toml_strip_and_argv(self):
        from cloudseed import mcp
        doc = '[a]\nx = 1\n[mcp_servers.cloudseed]\nurl = "u"\n[mcp_servers.cloudseed.env]\nPATH = "p"\n[mcp_servers.cloudseedy]\nz = 1\n[b]\ny = 2\n'
        out = mcp._toml_strip(doc)
        self.assertIn("[a]", out); self.assertIn("[b]", out); self.assertIn("cloudseedy", out); self.assertNotIn('url = "u"', out); self.assertNotIn('PATH = "p"', out)
        self.assertEqual(mcp.TOOLS["cloudseed_ssh"]["argv"]({"cloud": "aws", "env": "d", "command": "sudo nft list ruleset"}),
                         ["ssh", "aws", "--env", "d", "--", "-o", "BatchMode=yes", "sudo nft list ruleset"])
        self.assertTrue(mcp._is_destructive(mcp.TOOLS["cloudseed_ssh"], {"cloud": "aws", "command": "uptime"}))
        self.assertEqual(mcp.TOOLS["cloudseed_setup"]["argv"]({"cloud": "gcp", "dry_run": True, "tags": {"team": "x"}})[-3:], ["--tag", "team=x", "--dry-run"])
        self.assertIsNone(mcp.read_resource("cloudseed://skills/nope"))
        self.assertEqual({p["name"] for p in mcp.prompt_list()}, set(mcp.PROMPTS))



class ResilienceComplianceTests(unittest.TestCase):
    """chaos / dr / scan / prerequisites / FIPS - offline (rendering, planning, parsing, parsers)."""

    def _ctx(self, cloud_key="aws", outputs=None, fips=False):
        from cloudseed import paths, platform as pl
        env = paths.Env(cloud_key, "rc"); env.create_dirs()
        cfg = {"env": "rc", "region": "us-west-2", "network_cidr": "10.0.0.0/16", "vars": {"fips_mode": fips, "project_id": "p", "subscription_id": "s"}, "platform_prereqs": []}
        return pl.Cluster(clouds.get(cloud_key), env, cfg, outputs or {"kubernetes_cluster_name": "c"}, env.dir / "kc")

    def test_catalog_new_items_and_groups(self):
        from cloudseed import platform as pl
        for n in ("velero", "kured", "descheduler", "chaos-mesh", "litmus", "kubescape-operator", "external-dns"):
            self.assertIn(n, pl.CATALOG)
        self.assertEqual(pl.CATALOG["velero"]["group"], "resilience"); self.assertEqual(pl.CATALOG["chaos-mesh"]["group"], "chaos")
        self.assertIn("resilience", pl.GROUPS); self.assertIn("chaos", pl.GROUPS)
        self.assertEqual(pl.CATALOG["cluster-autoscaler"]["only"], ["aws", "gcp", "azure"])
        self.assertIn("gke", pl.PROVIDED_BY_DISTRO["cluster-autoscaler"])
        self.assertIn("chaos-mesh", pl.UIS)

    def test_resolve_needs_by_target_and_prereqs(self):
        from cloudseed import platform as pl
        ctx = self._ctx("vmware", {"kubernetes_distro": "rke2"})
        order = pl.resolve(["velero"], ctx)
        self.assertLess(order.index("minio"), order.index("velero"))
        self.assertEqual(pl.missing_prereqs(["velero"], ctx, releases={}), [])
        ctx = self._ctx("aws")
        self.assertNotIn("minio", pl.resolve(["velero"], ctx))
        self.assertEqual(pl.missing_prereqs(["velero", "karpenter"], ctx, releases={}), ["velero", "karpenter"])
        ctx.outputs["kubernetes_velero_bucket"] = "b"; ctx.cfg["platform_prereqs"] = ["velero"]
        self.assertEqual(pl.missing_prereqs(["velero"], ctx, releases={}), [])
        entries = {e["item"]: e for e in pl.plan(["karpenter"], ctx, releases={})}
        self.assertEqual(entries["karpenter"]["cloud_prereqs"], ["karpenter"])
        with self.assertRaises(SystemExit):
            pl.install(["karpenter"], ctx)

    def test_values_wire_cloud_outputs(self):
        from cloudseed import platform as pl
        ctx = self._ctx("aws", {"kubernetes_cluster_name": "c", "kubernetes_irsa_role_arns": {"velero": "arn:velero", "external-dns": "arn:dns", "karpenter": "arn:karp"},
                                "kubernetes_velero_bucket": "bkt", "kubernetes_karpenter_queue": "q"})
        args = " ".join(pl._values_args(pl.CATALOG["velero"], ctx))
        self.assertIn("role-arn=arn:velero", args); self.assertIn("bucket=bkt", args); self.assertIn("velero-plugin-for-aws", args)
        self.assertIn("interruptionQueue=q", " ".join(pl._values_args(pl.CATALOG["karpenter"], ctx)))
        self.assertIn("role-arn=arn:dns", " ".join(pl._values_args(pl.CATALOG["external-dns"], ctx)))
        vm = self._ctx("vmware", {"kubernetes_distro": "rke2"})
        args = " ".join(pl._values_args(pl.CATALOG["chaos-mesh"], vm))
        self.assertIn("/run/k3s/containerd/containerd.sock", args)
        self.assertIn("s3Url=http://minio.minio.svc:9000", " ".join(pl._values_args(pl.CATALOG["velero"], vm)))
        az = self._ctx("azure", {"kubernetes_cluster_name": "c", "kubernetes_velero_client_id": "cid", "kubernetes_velero_storage_account": "sa", "kubernetes_velero_container": "velero",
                                 "resource_group_name": "rg", "kubernetes_node_resource_group": "mc_rg", "tenant_id": "t", "subscription_id": "s"})
        args = " ".join(pl._values_args(pl.CATALOG["velero"], az))
        self.assertIn("storageAccount=sa", args); self.assertIn("client-id=cid", args)
        self.assertIn("AZURE_RESOURCE_GROUP=mc_rg", render_post_manifest(az, "velero-azure-credentials"))
        dns = render_post_manifest(az, "external-dns-azure-config")
        azure_json = json.loads(next(ln for ln in dns.splitlines() if "tenantId" in ln))
        self.assertEqual((azure_json["tenantId"], azure_json["subscriptionId"], azure_json["resourceGroup"]), ("t", "s", "rg"))

    def test_fips_gating_and_values(self):
        from cloudseed import platform as pl
        ctx = self._ctx("aws", fips=True)
        self.assertTrue(ctx.fips)
        actions = {e["item"]: e["action"] for e in pl.plan(["gitlab", "cert-manager", "velero"], ctx, releases={})}
        self.assertEqual(actions["gitlab"], "skip-fips"); self.assertEqual(actions["cert-manager"], "install")
        self.assertEqual({e["item"]: e["action"] for e in pl.plan(["gitlab"], ctx, releases={}, force=True)}["gitlab"], "install")
        self.assertIn("ssl-protocols=TLSv1.2 TLSv1.3", " ".join(pl._values_args(pl.CATALOG["ingress-nginx"], ctx)))
        self.assertNotIn("ssl-protocols", " ".join(pl._values_args(pl.CATALOG["ingress-nginx"], self._ctx("aws"))))

    def test_chaos_manifests_and_report(self):
        import json as _json
        from cloudseed import chaos
        self.assertEqual(set(chaos.SUITES["full"]), set(chaos.EXPERIMENTS))
        t = chaos.Target("ns", "app", "app", "app", 8080, True)
        for name, e in chaos.EXPERIMENTS.items():
            m = chaos._experiment_manifest(name, e, t, "30s", "run1")
            self.assertEqual(m["kind"], e["kind"]); self.assertEqual(m["metadata"]["labels"][chaos.LABEL], "run1")
            _json.dumps(m)
        self.assertEqual(chaos._experiment_manifest("pod-kill", chaos.EXPERIMENTS["pod-kill"], t, "30s", "r")["spec"]["selector"]["labelSelectors"], {"app": "app"})
        manifest = chaos.CANARY_MANIFEST % {"ns": "x", "name": "canary", "replicas": 3, "probe": "p", "label": chaos.LABEL}
        self.assertIn("replicas: 3", manifest)
        ctx = self._ctx("vmware")
        report = {"run": "r1", "env": ctx.env.id, "target": "x/canary", "canary": True, "duration_s": 5, "distro": "rke2", "cloud": "vmware",
                  "results": [{"experiment": "pod-kill", "verdict": "PASS", "availability": 0.9, "min_availability": 0.5, "recovered": True, "recovery_s": 3, "recovery_bound_s": 90, "reason": ""}],
                  "summary": {"PASS": 1, "FAIL": 0, "SKIP": 0, "ERROR": 0}}
        path = chaos.save_report(ctx, report)
        self.assertTrue(path.exists()); self.assertIn("| pod-kill | PASS |", path.with_suffix(".md").read_text())
        self.assertEqual(chaos.last_report(ctx.env), path)

    def test_dr_report_and_manifest(self):
        from cloudseed import dr
        ctx = self._ctx("vmware")
        m = dr.DRILL_MANIFEST % {"ns": dr.DRILL_NS, "token": "tok", "created": "now"}
        self.assertIn("token: \"tok\"", m)
        report = {"run": "r", "env": ctx.env.id, "cloud": "vmware", "distro": "rke2", "velero": "v1.18.2", "volume_tested": False,
                  "steps": [{"step": "1. create sample workload", "ok": True, "seconds": 1.0, "detail": "x"}], "verdict": "PASS", "total_s": 1.0, "rto_s": 0.0}
        p = dr.save_report(ctx, report)
        self.assertIn("**PASS**", p.with_suffix(".md").read_text())

    def test_scan_parsers_and_benchmarks(self):
        from cloudseed import scan, paths
        xml = """<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult id="t">
        <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" severity="medium"><result>fail</result></rule-result>
        <rule-result idref="xccdf_org.ssgproject.content_rule_x" severity="low"><result>pass</result></rule-result>
        <rule-result idref="xccdf_org.ssgproject.content_rule_y"><result>notapplicable</result></rule-result>
        <score system="urn:xccdf:scoring:default" maximum="100">66.6</score></TestResult></Benchmark>"""
        p = Path(tempfile.mkdtemp()) / "results.xml"; p.write_text(xml)
        r = scan._parse_xccdf(p)
        self.assertEqual((r["pass"], r["fail"], r["notapplicable"], r["score"]), (1, 1, 1, 66.6))
        self.assertEqual(r["failed_rules"][0]["title"], "sshd disable root login")
        for d in ("eks", "gke", "aks", "rke2"):
            self.assertTrue(scan.BENCHMARKS[d])
        self.assertIn("eks", scan.STIG_BENCHMARKS)
        env = paths.Env("aws", "rc"); env.create_dirs()
        path = scan.save_report(env, "cis", {"summary": {"pass": 1, "fail": 0}, "findings": []})
        self.assertTrue(path.exists()); self.assertEqual(scan.reports(env)[-1], path)
        job = scan.KUBE_BENCH_JOB % {"ns": "n", "role": "node", "placement": "", "command": '["kube-bench"]'}
        self.assertIn("hostPID: true", job)

    def test_fips_setup_rules(self):
        from cloudseed import cli, netutil
        from unittest import mock
        ok = {"vars": {"fips_mode": True, "enable_vpn": True, "vpn_type": "openvpn"}}
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": "t"}):   # the AWS VPN host is Ubuntu: FIPS needs Pro
            cli._check_fips(clouds.get("aws"), ok)
        with mock.patch.dict(os.environ, {"UBUNTU_PRO_TOKEN": ""}), self.assertRaises(SystemExit):
            cli._check_fips(clouds.get("aws"), ok)
        bad = {"vars": {"fips_mode": True, "enable_vpn": True, "vpn_type": "tailscale"}}
        with self.assertRaises(SystemExit):
            cli._check_fips(clouds.get("aws"), bad)
        with self.assertRaises(SystemExit):
            cli._check_fips(clouds.get("vmware"), {"vars": {"fips_mode": True, "enable_kubernetes": True, "kubernetes_distro": "kubeadm"}})
        cli._check_fips(clouds.get("aws"), {"vars": {"fips_mode": False, "vpn_type": "tailscale", "enable_vpn": True}})
        d = Path(tempfile.mkdtemp())
        priv, pub = netutil.ensure_ssh_key(d, "t", fips=True)
        # RSA-4096: ed25519 is not FIPS-approved and EC2 key pairs / Azure VMs refuse ECDSA
        self.assertEqual(netutil.ssh_key_info(pub.read_text()), ("ssh-rsa", 4096))
        self.assertEqual(priv.name, "id_rsa")
        p = build_parser()
        a = p.parse_args(["chaos", "run", "network", "--target", "shop/api:8080", "--duration", "30"])
        self.assertEqual((a.chaos_cmd, a.items, a.target), ("run", ["network"], "shop/api:8080"))
        a = p.parse_args(["dr", "schedule", "nightly", "--cron", "0 2 * * *"]); self.assertEqual(a.name, "nightly")
        a = p.parse_args(["scan", "host", "aws", "--env", "prod", "--profile", "stig"]); self.assertEqual((a.cloud, a.profile), ("aws", "stig"))

    def test_render_fips_and_prereqs(self):
        from cloudseed import paths
        cfg = {"name": "n", "env": "rc", "region": "us-west-2", "network_cidr": "10.0.0.0/16", "allowed_ssh_cidrs": ["1.2.3.4/32"], "ssh_public_key": "ecdsa-sha2-nistp384 AAAA",
               "owner": "o", "tags": {}, "vars": {"fips_mode": True, "enable_kubernetes": True}, "extra_vars": {}, "platform_prereqs": ["velero"], "state": {"type": "local"}}
        root = clouds.get("aws").render_stack(cfg, paths.tf_root())
        self.assertTrue(root["provider"]["aws"]["use_fips_endpoint"])
        self.assertEqual(root["module"]["stack"]["platform_prereqs"], ["velero"]); self.assertTrue(root["module"]["stack"]["fips_mode"])
        self.assertIn("kubernetes_velero_bucket", root["output"])
        cfg["vars"]["subscription_id"] = "s"
        self.assertTrue(clouds.get("azure").render_stack(cfg, paths.tf_root())["module"]["stack"]["fips_mode"])

    def test_mcp_new_tools(self):
        from cloudseed import mcp
        self.assertEqual(mcp.TOOLS["cloudseed_scan"]["argv"]({"kind": "host", "cloud": "aws", "env": "p", "profile": "stig"}), ["scan", "host", "aws", "--env", "p", "--profile", "stig", "-y"])
        self.assertTrue(mcp._is_destructive(mcp.TOOLS["cloudseed_chaos"], {"action": "run"}))
        self.assertFalse(mcp._is_destructive(mcp.TOOLS["cloudseed_dr"], {"action": "status"}))
        self.assertEqual(mcp.TOOLS["cloudseed_dr"]["argv"]({"action": "test", "cloud": "vmware", "env": "k8s", "confirm": True})[:4], ["dr", "test", "--cloud", "vmware"])


class UndoCredsWebUITests(unittest.TestCase):
    def test_undo_journal(self):
        from cloudseed import undo
        undo.clear("t-scope")
        for i in range(7):
            undo.record("t-scope", f"action {i}", "info", {"advice": "nothing"})
        self.assertEqual(len(undo.entries("t-scope")), 5)
        self.assertEqual(undo.latest("t-scope")["summary"], "action 6")
        e = undo.latest("t-scope"); undo.pop(e)
        self.assertEqual(undo.latest("t-scope")["summary"], "action 5")
        self.assertIn("nothing", undo.describe(undo.latest("t-scope")))
        os.environ["CLOUDSEED_UNDOING"] = "1"
        self.assertEqual(undo.record("t-scope", "nested", "info"), {})
        os.environ.pop("CLOUDSEED_UNDOING")
        undo.clear("t-scope"); self.assertIsNone(undo.latest("t-scope"))
        self.assertEqual(undo.kubectl_namespaces(["get", "pods", "-n", "shop"]), ["shop"])
        self.assertIsNone(undo.kubectl_namespaces(["get", "pods", "-A"]))

    def test_undo_perform_kinds(self):
        from cloudseed import undo, creds, paths
        creds.set_("T_KEY", "v1")
        undo.perform({"kind": "creds-unset", "data": {"keys": ["T_KEY"]}, "scope": "global", "summary": "x"}, {}, True)
        self.assertNotIn("T_KEY", creds.load())
        undo.perform({"kind": "creds-restore", "data": {"values": {"T_KEY": "v1"}}, "scope": "global", "summary": "x"}, {}, True)
        self.assertEqual(creds.load()["T_KEY"], "v1"); creds.unset("T_KEY")
        s = paths.load_settings(); s["probe"] = 1; paths.save_settings(s)
        undo.perform({"kind": "settings-restore", "data": {"settings": {k: v for k, v in s.items() if k != "probe"}, "what": ["probe"]}, "scope": "global", "summary": "x"}, {}, True)
        self.assertNotIn("probe", paths.load_settings())
        d = Path(tempfile.mkdtemp()); f = d / "a.txt"; f.write_text("old"); b = undo.backup_file(f); f.write_text("new"); g = d / "new.txt"; g.write_text("x")
        undo.perform({"kind": "restore-files", "data": {"files": {str(f): b, str(g): None}}, "scope": "global", "summary": "x"}, {}, True)
        self.assertEqual(f.read_text(), "old"); self.assertFalse(g.exists())
        h = d / "h.txt"; h.write_text("x")
        undo.perform({"kind": "delete-paths", "data": {"paths": [str(h)]}, "scope": "global", "summary": "x"}, {}, True)
        self.assertFalse(h.exists())

    def test_creds_vault(self):
        from cloudseed import creds
        creds.set_("MY_TOKEN", "abcdefghijklmnop"); creds.set_("AWS_PROFILE", "p")
        rows = {r["key"]: r for r in creds.masked()}
        self.assertTrue(rows["MY_TOKEN"]["set"]); self.assertNotIn("abcdefghijklmnop", rows["MY_TOKEN"]["hint"]); self.assertEqual(rows["AWS_PROFILE"]["hint"], "p")
        self.assertEqual(creds.env()["MY_TOKEN"], "abcdefghijklmnop")
        with self.assertRaises(ValueError):
            creds.set_("bad key!", "x")
        creds.clear(); self.assertEqual(creds.load(), {})

    def test_webui_registry_and_argv(self):
        from cloudseed import webui
        names = {a["name"] for a in webui.actions_catalog()}
        for n in ("cloudseed_setup", "cloudseed_platform", "cloudseed_agentic", "cloudseed_mcp", "cloudseed_undo", "cloudseed_enable"):
            self.assertIn(n, names)
        self.assertEqual(webui.build_argv("cloudseed_list", {}), ["list"])
        with self.assertRaises(PermissionError):
            webui.build_argv("cloudseed_destroy", {"cloud": "aws"})
        self.assertEqual(webui.build_argv("cloudseed_agentic", {"task": "list envs", "confirm": True}), ["agentic", "--force", "list envs"])
        self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": "setup", "confirm": True}), ["mcp", "setup", "--client", "none", "-y"])
        cl = webui.clouds_catalog(); self.assertIn("fips_mode", [q["key"] for q in cl["aws"]["questions"]])
        pc = webui.platform_catalog(); self.assertTrue(any(i["name"] == "velero" for i in pc["items"])); self.assertIn("basic", pc["chaos"]["suites"])
        self.assertIsNone(webui.read_env_file("/etc/passwd"))
        p = build_parser(); a = p.parse_args(["undo", "aws", "--env", "dev", "--list"]); self.assertTrue(a.list)
        a = p.parse_args(["ui", "start", "--no-open", "--port", "7500"]); self.assertEqual((a.ui_cmd, a.port), ("start", 7500))
        a = p.parse_args(["creds", "set", "A=b"]); self.assertEqual(a.items, ["A=b"])
