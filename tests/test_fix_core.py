"""Regression tests for the core fixes: CIDR guards, SSH keys (FIPS/cloud rules), --var validation, managed variables,
template escaping, config.json robustness, Terraform interrupts/diagnosis/CLI config, reviewed-plan applies, stream
redaction, and Python 3.9 compatibility. Stdlib only; no network, no cloud; subprocess is faked where needed."""
import base64
import contextlib
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, netutil, paths, secrets, tf, ui  # noqa: E402
from cloudseed.clouds import base  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HAVE_KEYGEN = shutil.which("ssh-keygen") is not None


def _rsa_pub(bits: int) -> str:
    """A syntactically valid ssh-rsa public key line with a modulus of `bits` bits (no key generation needed)."""
    def s(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b
    n = (1 << (bits - 1)) | 1
    blob = s(b"ssh-rsa") + s(b"\x01\x00\x01") + s(b"\x00" + n.to_bytes((bits + 7) // 8, "big"))
    return "ssh-rsa " + base64.b64encode(blob).decode() + " test"


def _ecdsa_pub(curve: str = "nistp384") -> str:
    def s(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b
    blob = s(f"ecdsa-sha2-{curve}".encode()) + s(curve.encode()) + s(b"\x04" + b"\x01" * 96)
    return f"ecdsa-sha2-{curve} " + base64.b64encode(blob).decode() + " test"


def _ed25519_pub() -> str:
    def s(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b
    return "ssh-ed25519 " + base64.b64encode(s(b"ssh-ed25519") + s(b"\x02" * 32)).decode() + " test"


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
        yield out, err


@contextlib.contextmanager
def non_interactive(flag: bool = True):
    old = ui.NON_INTERACTIVE
    ui.NON_INTERACTIVE = flag
    try:
        yield
    finally:
        ui.NON_INTERACTIVE = old


class CidrGuardTests(unittest.TestCase):
    def test_refuses_the_internet_in_disguise(self):
        for raw in ("0.0.0.0/0", "1.2.3.4/0", "0.0.0.0/1,128.0.0.0/1", "0.0.0.0/1", "10.0.0.0/7",
                    "64.0.0.0/2,0.0.0.0/2,128.0.0.0/2,192.0.0.0/2", "10.0.0.0/8,11.0.0.0/8,12.0.0.0/8"):
            self.assertIsNotNone(netutil.validate_cidr_list(raw), raw)
        self.assertIn("together cover it", netutil.validate_cidr_list("0.0.0.0/1, 128.0.0.0/1"))

    def test_refuses_ipv6_and_host_bit_typos(self):
        for raw in ("2001:db8::1", "::/0", "::/1,8000::/1"):
            self.assertIn("IPv6", netutil.validate_cidr_list(raw), raw)
        self.assertIn("host bits", netutil.validate_cidr_list("203.0.113.7/3"))
        self.assertIn("not a valid", netutil.validate_cidr_list("300.1.1.1"))
        self.assertIsNotNone(netutil.validate_cidr_list(""))

    def test_accepts_normal_ranges(self):
        for raw in ("203.0.113.7", "198.51.100.0/24", "10.0.0.0/8", "1.2.3.4, 10.0.0.0/8", ["1.2.3.4", "5.6.7.8/32"]):
            self.assertIsNone(netutil.validate_cidr_list(raw), raw)

    def test_normalized_list_is_canonical(self):
        self.assertEqual(netutil.normalize_cidr_list(["203.0.113.7", "203.0.113.7/32", "203.0.113.0/24"]), ["203.0.113.0/24"])
        self.assertEqual(netutil.normalize_cidr_list("5.6.7.8,1.2.3.4"), ["1.2.3.4/32", "5.6.7.8/32"])

    def test_update_ip_compares_canonical_lists(self):
        env = paths.Env("aws", "sameips")
        env.save(_cfg("aws", env="sameips", vars={}, allowed_ssh_cidrs=["1.2.3.4/32", "5.6.7.8/32"]))
        try:
            with quiet() as (out, err), mock.patch.object(cli, "Terraform", side_effect=AssertionError("no terraform run")):
                rc = cli.cmd_update_ip(SimpleNamespace(cloud="aws", env="sameips", allow_ip=["5.6.7.8, 1.2.3.4/32"],
                                                       auto_approve=True, cmd="update-ip"), {})
        finally:
            shutil.rmtree(env.dir, ignore_errors=True)
        self.assertEqual(rc, 0)
        self.assertIn("nothing to do", out.getvalue() + err.getvalue())

    def test_network_cidr(self):
        self.assertIsNone(netutil.validate_cidr("10.0.0.0/16"))
        self.assertIn("host bits", netutil.validate_cidr("10.0.0.1/16"))
        self.assertIn("IPv6", netutil.validate_cidr("fd00::/48"))
        self.assertIn("not a valid", netutil.validate_cidr("notacidr"))

    def test_pick_network_cidr_never_returns_a_used_range(self):
        self.assertEqual(netutil.pick_network_cidr(["10.0.0.0/8", "172.17.0.0/16"]), "172.18.0.0/16")
        every = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        with quiet(), self.assertRaises(SystemExit):
            netutil.pick_network_cidr(every)


class LoginNameTests(unittest.TestCase):
    def test_root_and_invalid_names_fall_back(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_USER": "", "SUDO_USER": ""}), \
                mock.patch.object(netutil.getpass, "getuser", return_value="root"):
            self.assertEqual(netutil.local_username(), "cloudseed")
        with mock.patch.dict(os.environ, {"CLOUDSEED_USER": "", "SUDO_USER": "alice"}), \
                mock.patch.object(netutil.getpass, "getuser", return_value="root"):
            self.assertEqual(netutil.local_username(), "alice")      # sudo: the invoking user
        with mock.patch.dict(os.environ, {"CLOUDSEED_USER": "", "SUDO_USER": ""}), \
                mock.patch.object(netutil.getpass, "getuser", return_value="1st.user"):
            self.assertEqual(netutil.local_username(), "cloudseed")  # must not start with a digit

    def test_container_passes_the_host_user(self):
        with mock.patch.dict(os.environ, {"CLOUDSEED_USER": "Bob.Smith"}), \
                mock.patch.object(netutil.getpass, "getuser", return_value="root"):
            self.assertEqual(netutil.local_username(), "bobsmith")

    def test_validator(self):
        for ok in ("azureuser", "AzureAdmin", "john.doe", "_svc"):   # names existing environments may already use
            self.assertIsNone(netutil.validate_login_username(ok), ok)
        for bad in ("root", "daemon", "nobody", "systemd-network", "Bad Name", "-x", "1user", "a:b", "x" * 33, ""):
            self.assertIsNotNone(netutil.validate_login_username(bad), bad)
        gcp = clouds.get("gcp")
        q = gcp.question("ssh_username")
        self.assertIn("PermitRootLogin", gcp.answer_problem(q, "root", {"region": "us-central1"}))

    def test_container_reexec_forwards_the_user(self):
        from cloudseed import container
        captured = {}
        with mock.patch.dict(os.environ, {}, clear=False), \
                mock.patch.object(container, "image_exists", return_value=True), \
                mock.patch.object(container, "ensure_daemon"), \
                mock.patch.object(container.os, "execvp", side_effect=lambda eng, cmd: captured.setdefault("cmd", cmd)), \
                mock.patch.object(netutil, "local_username", return_value="hostuser"), quiet():
            os.environ.pop("CLOUDSEED_USER", None)
            container.reexec("docker", ["status", "gcp"])
        joined = " ".join(captured["cmd"])
        self.assertIn("CLOUDSEED_USER=hostuser", joined)


class SshKeyTests(unittest.TestCase):
    def test_key_info_parses_real_wire_format(self):
        self.assertEqual(netutil.ssh_key_info(_rsa_pub(3072)), ("ssh-rsa", 3072))
        self.assertEqual(netutil.ssh_key_info(_ecdsa_pub()), ("ecdsa-sha2-nistp384", 384))
        self.assertEqual(netutil.ssh_key_info(_ed25519_pub()), ("ssh-ed25519", 256))
        self.assertEqual(netutil.ssh_key_info("ssh-rsa AAAA test"), ("", 0))              # truncated blob
        self.assertEqual(netutil.ssh_key_info("ssh-ed25519 " + _rsa_pub(2048).split()[1]), ("", 0))   # type mismatch

    def test_cloud_and_fips_rules(self):
        p = netutil.ssh_key_problem
        self.assertIsNone(p(_ed25519_pub(), cloud="aws"))
        self.assertIn("FIPS", p(_ed25519_pub(), fips=True, cloud="gcp"))
        self.assertIn("EC2", p(_ecdsa_pub(), cloud="aws"))                # EC2 ImportKeyPair: RSA / ED25519 only
        self.assertIn("Azure", p(_ecdsa_pub(), fips=True, cloud="azure"))  # Azure VMs: RSA / ED25519 only
        self.assertIsNone(p(_ecdsa_pub(), fips=True, cloud="gcp"))
        self.assertIn("FIPS", p(_rsa_pub(2048), fips=True, cloud="gcp"))
        self.assertIn("EC2", p(_rsa_pub(3072), fips=True, cloud="aws"))   # EC2 only imports 1024/2048/4096
        self.assertIsNone(p(_rsa_pub(4096), fips=True, cloud="aws"))
        self.assertIsNone(p(_rsa_pub(4096), fips=True, cloud="azure"))
        self.assertIn("Azure", p(_rsa_pub(1024), cloud="azure"))
        self.assertIn("weak", p(_rsa_pub(768), cloud="gcp"))

    @unittest.skipUnless(HAVE_KEYGEN, "ssh-keygen not installed")
    def test_fips_never_reuses_a_leftover_ed25519_pair(self):
        d = Path(tempfile.mkdtemp())
        with quiet():
            priv0, pub0 = netutil.ensure_ssh_key(d, "t")               # a setup that aborted before FIPS was chosen
            self.assertEqual(netutil.ensure_ssh_key(d, "t"), (priv0, pub0))
            priv, pub = netutil.ensure_ssh_key(d, "t", fips=True, cloud="azure")
        self.assertEqual(netutil.ssh_key_info(pub.read_text())[0], "ssh-rsa")
        self.assertEqual(priv.name, "id_rsa")
        self.assertTrue(priv0.exists() and pub0.exists())             # never deleted
        self.assertEqual(stat.S_IMODE(priv.stat().st_mode), 0o600)

    @unittest.skipUnless(HAVE_KEYGEN, "ssh-keygen not installed")
    def test_unusable_pair_under_the_target_name_is_moved_aside(self):
        d = Path(tempfile.mkdtemp())
        (d / "id_rsa").write_text("junk")
        (d / "id_rsa.pub").write_text(_rsa_pub(2048))                  # too short for FIPS
        with quiet():
            priv, pub = netutil.ensure_ssh_key(d, "t", fips=True, cloud="gcp")
        self.assertEqual(netutil.ssh_key_info(pub.read_text()), ("ssh-rsa", 4096))
        self.assertTrue(list(d.glob("id_rsa.replaced-*")))

    def test_missing_ssh_keygen_is_a_clean_error(self):
        d = Path(tempfile.mkdtemp())
        with mock.patch.object(netutil.subprocess, "run", side_effect=FileNotFoundError), quiet(), \
                self.assertRaises(SystemExit):
            netutil.ensure_ssh_key(d, "t")

    def test_read_public_key_errors_are_clean(self):
        d = Path(tempfile.mkdtemp())
        (d / "bin").write_bytes(b"\xff\xfe\x00binary")
        (d / "priv").write_text("-----BEGIN " + "OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n")
        (d / "notakey.pub").write_text("hello world\n")
        for path, words in ((d / "missing.pub", "not found"), (d, "directory"), (d / "bin", "Cannot read"),
                            (d / "priv", "private key"), (d / "notakey.pub", "does not look like")):
            with quiet() as (_, err), self.assertRaises(ui.Abort) as cm:
                netutil.read_public_key(path)
            self.assertIn(words, cm.exception.msg, path)
        (d / "multi.pub").write_text("# my key\n\n" + _ed25519_pub() + "\n" + _rsa_pub(2048) + "\n")
        self.assertEqual(netutil.read_public_key(d / "multi.pub"), _ed25519_pub())

    def test_private_key_is_derived_or_explained(self):
        d = Path(tempfile.mkdtemp())
        (d / "k.pub").write_text(_ed25519_pub())
        (d / "k").write_text("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n")
        self.assertEqual(netutil.private_key_for(d / "k.pub"), (str(d / "k"), None))
        (d / "agent.pub").write_text(_ed25519_pub())
        path, warning = netutil.private_key_for(d / "agent.pub")
        self.assertEqual(path, str(d / "agent.pub"))
        self.assertIn("ssh-agent", warning)
        (d / "mykey.txt").write_text(_ed25519_pub())
        path, warning = netutil.private_key_for(d / "mykey.txt")
        self.assertEqual(path, str(d / "mykey.txt"))
        self.assertIn("--ssh-private-key", warning)
        path, warning = netutil.private_key_for(d / "k.pub", str(d / "nope"))
        self.assertIn("does not exist", warning)

    def test_env_private_key_matches_the_environment_key(self):
        env = paths.Env("gcp", "keysel", workdir=tempfile.mkdtemp())
        env.create_dirs()
        (env.ssh_dir / "id_ed25519").write_text("x")
        (env.ssh_dir / "id_ed25519.pub").write_text(_ed25519_pub())
        (env.ssh_dir / "id_rsa").write_text("x")
        (env.ssh_dir / "id_rsa.pub").write_text(_rsa_pub(4096))
        self.assertEqual(env.private_key_path({"ssh_public_key": _rsa_pub(4096)}).name, "id_rsa")
        self.assertEqual(env.private_key_path({"ssh_public_key": _ed25519_pub()}).name, "id_ed25519")
        self.assertEqual(env.private_key_path({"ssh_public_key": "x", "ssh_private_key_path": "~/k"}), Path("~/k").expanduser())
        empty = paths.Env("gcp", "keysel2", workdir=tempfile.mkdtemp())
        self.assertEqual(empty.private_key_path({}).name, "id_ed25519")


class ConfigFileTests(unittest.TestCase):
    def test_atomic_write(self):
        d = Path(tempfile.mkdtemp())
        target = d / "config.json"
        paths.atomic_write(target, "one\n")
        self.assertEqual(target.read_text(), "one\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        with mock.patch.object(paths.os, "replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
            paths.atomic_write(target, "two\n")
        self.assertEqual(target.read_text(), "one\n")                   # the old file survives a failed write
        self.assertEqual([p.name for p in d.iterdir()], ["config.json"])  # no temp file left behind

    def test_corrupt_config_is_named_and_tolerated(self):
        env = paths.Env("aws", "corrupt", workdir=tempfile.mkdtemp())
        env.save({"name": "x"})
        self.assertEqual(env.try_load(), (env.load(), None))
        env.config_path.write_text("{\n")
        with self.assertRaises(paths.ConfigError) as cm:
            env.load()
        self.assertIsInstance(cm.exception, ValueError)                 # old `except ValueError` handlers still work
        self.assertIn(str(env.config_path), str(cm.exception))
        self.assertIn("line 2", str(cm.exception))
        cfg, problem = env.try_load()
        self.assertEqual(cfg, {})
        self.assertIn("not valid JSON", problem)
        env.config_path.write_text("[1, 2]")
        self.assertIn("not an object", env.try_load()[1])

    def test_cli_reports_a_corrupt_config_plainly(self):
        env = paths.Env("aws", "brokencfg")
        env.save({"name": "x", "cloud": "aws", "env": "brokencfg"})
        env.config_path.write_text("{\n")
        try:
            with quiet() as (out, err), non_interactive():
                rc = cli.main(["status", "aws", "--env", "brokencfg", "--runtime", "local"])
            self.assertEqual(rc, 1)
            self.assertIn("is not valid JSON", err.getvalue())
            self.assertNotIn("Unexpected error", err.getvalue())
            with quiet() as (out, err):
                self.assertEqual(cli.cmd_list(SimpleNamespace(), {}), 0)
            self.assertIn("aws-brokencfg", out.getvalue())
            self.assertIn("unreadable", out.getvalue() + err.getvalue())
        finally:
            shutil.rmtree(env.dir, ignore_errors=True)


class ValueCoercionTests(unittest.TestCase):
    def test_as_bool_and_as_int(self):
        for v, want in ((True, True), ("no", False), ("False", False), ("on", True), (1, True), (0, False), ("Y", True)):
            self.assertEqual(base.as_bool(v), want, v)
        for bad in ("maybe", 2, None, 1.5):
            with self.assertRaises(ValueError):
                base.as_bool(bad)
        self.assertEqual(base.as_int("3"), 3)
        self.assertEqual(base.as_int(2.0), 2)
        for bad in ("abc", True, 2.5, -1, None):
            with self.assertRaises(ValueError):
                base.as_int(bad)


def _args(**kw):
    ns = SimpleNamespace(project_id=None, zone=None, ssh_username=None, subscription_id=None, admin_username=None,
                         profile=None)
    ns.__dict__.update(kw)
    return ns


# a GUID-shaped fake: Azure checks the subscription ID (with a terminal, as soon as the flag is read)
AZ_SUB = "0000aaaa-0000-0000-0000-000000000000"


class CollectVarsTests(unittest.TestCase):
    def collect(self, cloud_key, existing=None, overrides=None, cfg=None, advanced=False, **flags):
        cloud = clouds.get(cloud_key)
        cfg = cfg or {"region": {"gcp": "us-central1", "aws": "us-east-1", "azure": "eastus"}.get(cloud_key, "local"),
                      "workdir": tempfile.mkdtemp()}
        with non_interactive(), quiet():
            return cloud.collect_vars(_args(**flags), existing or {}, cfg, advanced, overrides)

    def test_invalid_var_answers_are_refused_before_anything_is_saved(self):
        for key, value in (("guest_os", "centos-9"), ("workload_count", "abc"), ("kubernetes_distro", "k3s"),
                           ("fips_mode", "maybe")):
            with self.assertRaises(SystemExit, msg=key):
                self.collect("vmware", overrides={key: value})
        with self.assertRaises(SystemExit):
            self.collect("azure", overrides={"vpn_type": "wireguard", "enable_vpn": True}, subscription_id=AZ_SUB)

    def test_var_answers_are_typed_and_win_over_a_bad_saved_value(self):
        out = self.collect("vmware", existing={"guest_os": "centos-9", "workload_count": "abc"},
                           overrides={"guest_os": "debian-12", "workload_count": "2", "fips_mode": "no",
                                      "enable_kubernetes": "true"})
        self.assertEqual((out["guest_os"], out["workload_count"], out["fips_mode"], out["enable_kubernetes"]),
                         ("debian-12", 2, False, True))
        out = self.collect("azure", existing={"vpn_type": "wireguard", "enable_vpn": True},
                           overrides={"vpn_type": "openvpn"}, subscription_id=AZ_SUB)
        self.assertEqual(out["vpn_type"], "openvpn")

    def test_bad_saved_answer_in_yes_mode_names_value_and_fix(self):
        cloud = clouds.get("vmware")
        with non_interactive(), quiet(), self.assertRaises(ui.Abort) as cm:
            cloud.collect_vars(_args(), {"guest_os": "centos-9"}, {"region": "local", "workdir": "/tmp"}, False, {})
        self.assertIn("centos-9", cm.exception.msg)
        self.assertIn("--var guest_os=VALUE", cm.exception.msg)

    def test_bad_saved_answer_for_an_unasked_question_is_healed(self):
        out = self.collect("azure", existing={"vpn_type": "wireguard", "enable_vpn": False,
                                              "kubernetes_node_count": "three"}, subscription_id=AZ_SUB)
        self.assertEqual((out["vpn_type"], out["kubernetes_node_count"]), ("openvpn", 2))
        self.assertEqual(self.collect("aws", existing={"single_nat_gateway": "no"})["single_nat_gateway"], False)

    def test_var_answers_are_not_prompted_again(self):
        cloud = clouds.get("vmware")
        with non_interactive(False), mock.patch.object(ui, "interactive", return_value=True), \
                mock.patch.object(ui, "ask", side_effect=lambda q, d=None, **k: d), \
                mock.patch.object(ui, "ask_bool", side_effect=lambda q, d: d) as ask_bool, quiet():
            out = cloud.collect_vars(_args(), {}, {"region": "local", "workdir": "/tmp"}, False,
                                     {"fips_mode": True, "enable_kubernetes": "yes"})
        prompted = [c.args[0] for c in ask_bool.call_args_list]
        self.assertFalse(any("FIPS" in p or "Kubernetes cluster" in p for p in prompted), prompted)
        self.assertTrue(out["fips_mode"] and out["enable_kubernetes"])

    def test_flag_value_is_used_without_computing_the_default(self):
        slow = mock.Mock(return_value="from-az")

        class Probe(base.Cloud):
            key = "probe"
            questions = [base.Question("subscription_id", "Subscription", slow, required=True)]
        with non_interactive(), quiet():
            out = Probe().collect_vars(_args(subscription_id="given"), {}, {"region": "r"}, False)
        self.assertEqual(out["subscription_id"], "given")
        slow.assert_not_called()

    def test_azure_subscription_lookup_is_cached(self):
        from cloudseed.clouds import azure
        azure._SUBSCRIPTION_CACHE.clear()
        sub = "0000aaaa-0000-0000-0000-000000000001"
        fake = SimpleNamespace(stdout=json.dumps({"id": sub}))
        # the variables win over `az account show`: the runner's own must not answer for it
        with mock.patch.dict(os.environ), mock.patch.object(azure.deps, "find", return_value="/usr/bin/az"), \
                mock.patch.object(azure.subprocess, "run", return_value=fake) as run:
            for name in ("ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID"):
                os.environ.pop(name, None)
            self.assertEqual(azure._default_subscription({}), sub)
            self.assertEqual(azure._default_subscription({}), sub)
        self.assertEqual(run.call_count, 1)

    def test_gcp_zone_follows_the_region(self):
        out = self.collect("gcp", existing={"project_id": "my-proj-123", "zone": "us-central1-c"},
                           cfg={"region": "europe-west4", "workdir": "/tmp"})
        self.assertEqual(out["zone"], "europe-west4-a")
        out = self.collect("gcp", existing={"project_id": "my-proj-123", "zone": "europe-west4-b"},
                           cfg={"region": "europe-west4", "workdir": "/tmp"})
        self.assertEqual(out["zone"], "europe-west4-b")                   # a valid custom zone is kept
        with mock.patch.dict(os.environ, {"CLOUDSDK_COMPUTE_ZONE": "us-central1-f"}):
            out = self.collect("gcp", existing={"project_id": "my-proj-123"}, cfg={"region": "europe-west4", "workdir": "/tmp"})
        self.assertEqual(out["zone"], "europe-west4-a")                   # env zone of another region ignored
        for zone in ("us-central1", "europe-west4-a"):
            with self.assertRaises(SystemExit, msg=zone):
                self.collect("gcp", existing={"project_id": "my-proj-123"}, zone=zone)
        self.assertEqual(self.collect("gcp", overrides={"project_id": "my-proj-456"})["project_id"], "my-proj-456")

    def test_empty_answers(self):
        self.assertEqual(self.collect("gcp", overrides={"project_id": "my-proj-123", "zone": ""})["zone"], "us-central1-a")
        with self.assertRaises(SystemExit):
            self.collect("gcp", overrides={"project_id": " "})
        self.assertEqual(self.collect("aws", existing={"profile": "old"}, overrides={"profile": ""})["profile"], "")


def _cfg(cloud, **over):
    cfg = {"cloud": cloud, "env": "dev", "name": "acme", "owner": "me", "region": {"gcp": "us-central1", "azure": "eastus"}.get(cloud, "us-east-1"),
           "network_cidr": "10.0.0.0/16", "allowed_ssh_cidrs": ["1.2.3.4/32"], "ssh_public_key": _ed25519_pub(),
           "state": {"type": "local", "backend": None}, "workdir": "/tmp/x",
           "vars": {"project_id": "my-proj-123", "zone": "us-central1-a", "subscription_id": "s"}, "extra_vars": {}, "tags": {}}
    cfg.update(over)
    return cfg


class RenderSafetyTests(unittest.TestCase):
    def test_template_sequences_in_keys_and_provider_blocks_are_literal(self):
        tags = {"${file(\"/etc/passwd\")}": "${upper(\"x\")}", "%{if true}k%{endif}": "v"}
        aws = clouds.get("aws").render_stack(_cfg("aws", tags=tags), Path("/tf"))
        default_tags = aws["provider"]["aws"]["default_tags"]["tags"]
        self.assertIn("$${file(\"/etc/passwd\")}", default_tags)
        self.assertEqual(default_tags["$${file(\"/etc/passwd\")}"], "$${upper(\"x\")}")
        self.assertIn("%%{if true}k%%{endif}", aws["module"]["stack"]["tags"])
        gcp = clouds.get("gcp").render_stack(_cfg("gcp", vars={"project_id": "${p}", "zone": "us-central1-a"}), Path("/tf"))
        self.assertEqual(gcp["provider"]["google"]["project"], "$${p}")
        boot = clouds.get("azure").render_bootstrap(_cfg("azure", tags={"${k}": "v"}), Path("/tf"))
        self.assertIn("$${k}", boot["module"]["state"]["tags"])
        self.assertEqual(aws["output"]["vpc_id"]["value"], "${module.stack.vpc_id}")   # real references untouched

    def test_managed_variables(self):
        want = {"aws": {"vpc_cidr", "allowed_ssh_cidrs", "name", "environment", "ssh_public_key", "tags", "platform_prereqs"},
                "gcp": {"region", "network_cidr", "labels", "allowed_ssh_cidrs"},
                "azure": {"location", "network_cidr", "tags"},
                "vmware": {"private_cidr", "base_disk", "guest_os_id", "ssh_public_key"}}
        for key, expected in want.items():
            managed = clouds.get(key).managed_vars(_cfg(key))
            self.assertTrue(expected <= set(managed), (key, expected - set(managed)))
            self.assertFalse({q.key for q in clouds.get(key).questions} & set(managed), key)
        self.assertIn("--allow-ip", clouds.get("aws").managed_vars()["allowed_ssh_cidrs"])

    def test_saved_overrides_of_guarded_values_are_ignored(self):
        cfg = _cfg("aws", extra_vars={"allowed_ssh_cidrs": ["0.0.0.0/1", "128.0.0.0/1"], "tags": {"x": "y"},
                                      "az_count": 3, "vpc_cidr": "10.50.0.0/16"})
        mod = clouds.get("aws").render_stack(cfg, Path("/tf"))["module"]["stack"]
        self.assertEqual(mod["allowed_ssh_cidrs"], ["1.2.3.4/32"])        # update-ip / the 0.0.0.0/0 guard win
        self.assertEqual(mod["tags"]["ManagedBy"], "cloudseed")
        self.assertEqual((mod["az_count"], mod["vpc_cidr"]), (3, "10.50.0.0/16"))   # others keep working (no replacement)

    def test_setup_refuses_new_managed_overrides_and_migrates_saved_cidr(self):
        # setup's --var handling is cli._parse_setup_vars (new --var items) + cli._saved_extra_vars (saved overrides)
        cloud = clouds.get("azure")
        for bad, flag in (('allowed_ssh_cidrs=["0.0.0.0/1"]', "--allow-ip"), ("location=westeurope", "--region")):
            with quiet(), self.assertRaises(ui.Abort) as cm:
                cli._parse_setup_vars(cloud, [bad])
            self.assertIn(flag, cm.exception.msg)
        with quiet():
            extra, legacy = cli._saved_extra_vars(cloud, {"extra_vars": {"network_cidr": "10.77.0.0/16", "allowed_ssh_cidrs": ["0.0.0.0/1"],
                                                                         "enable_flow_logs": True, "vpn_type": "tailscale"}})
        self.assertEqual((legacy["cidr"], legacy["answers"]), ("10.77.0.0/16", {"vpn_type": "tailscale"}))   # CIDR migrated
        self.assertIsNotNone(cli._allow_list_problem(legacy["allow"]))    # the too-wide saved allow-list is dropped by setup
        self.assertEqual(extra, {"enable_flow_logs": True})
        self.assertEqual(cli._parse_setup_vars(cloud, ["log_retention_days=90"])["extra"], {"log_retention_days": 90})

    def test_check_config(self):
        aws = clouds.get("aws")
        self.assertEqual(aws.check_config(_cfg("aws")), [])
        self.assertTrue(any("tags may not" in p for p in aws.check_config(_cfg("aws", tags={"${x}": "v"}))))
        for cidr, extra, word in (("10.0.0.0/8", {}, "/16"), ("10.0.0.0/25", {}, "/24"), ("10.0.0.0/26", {"subnet_newbits": 4}, "/24"),
                                  ("10.0.0.0/16", {"subnet_newbits": 2}, "subnets")):
            problems = aws.check_config(_cfg("aws", network_cidr=cidr, extra_vars=extra))
            self.assertTrue(any(word in p for p in problems), (cidr, problems))
        self.assertEqual(aws.check_config(_cfg("aws", network_cidr="10.0.0.0/24")), [])
        gcp = clouds.get("gcp")
        self.assertEqual(gcp.check_config(_cfg("gcp")), [])      # GCP project IDs are 6-30 characters (gcp#21)
        self.assertTrue(gcp.check_config(_cfg("gcp", vars={"project_id": "my-proj-123", "zone": "europe-west1-b"})))
        self.assertTrue(gcp.check_config(_cfg("gcp", vars={"project_id": "my-proj-123", "zone": "us-central1-a", "ssh_username": "root"})))


class FipsSetupTests(unittest.TestCase):
    def env(self, name):
        e = paths.Env("aws", name, workdir=tempfile.mkdtemp())
        e.create_dirs()
        return e

    def test_backstop_refuses_unusable_keys_and_regions(self):
        ok = {"region": "us-east-1", "ssh_public_key": _rsa_pub(4096), "vars": {"fips_mode": True}}
        with quiet():
            cli._check_fips(clouds.get("aws"), ok)
        for over in ({"ssh_public_key": _ed25519_pub()}, {"ssh_public_key": _ecdsa_pub()}, {"region": "eu-west-1"}):
            with quiet(), self.assertRaises(SystemExit, msg=over):
                cli._check_fips(clouds.get("aws"), {**ok, **over})

    @unittest.skipUnless(HAVE_KEYGEN, "ssh-keygen not installed")
    def test_key_is_chosen_after_the_fips_answer(self):
        env = self.env("fipskey")
        cfg = {"vars": {"fips_mode": True}}                  # e.g. answered 'yes' at the interactive prompt
        with quiet():
            self.assertTrue(cli._choose_ssh_key(clouds.get("aws"), env, cfg, {}, None, None))
            cli._generate_ssh_key(clouds.get("aws"), env, cfg)
        self.assertEqual(netutil.ssh_key_info(cfg["ssh_public_key"]), ("ssh-rsa", 4096))
        self.assertIsNone(cfg["ssh_private_key_path"])
        self.assertEqual(env.private_key_path(cfg).name, "id_rsa")

    def test_turning_fips_on_for_a_deployed_ed25519_env_is_refused(self):
        env = self.env("fipson")
        (env.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "1.2.3.4"}))
        existing = {"ssh_public_key": _ed25519_pub(), "ssh_private_key_path": None, "vars": {"fips_mode": False}}
        with quiet(), self.assertRaises(ui.Abort) as cm:
            cli._choose_ssh_key(clouds.get("aws"), env, {"vars": {"fips_mode": True}}, existing, None, None)
        self.assertIn("cannot be turned on", cm.exception.msg)

    def test_a_deployed_key_is_kept_when_only_a_cloud_rule_objects(self):
        """An RSA-3072 key on AWS is outside EC2's documented import sizes; if the environment is already deployed EC2
        accepted it, so re-running setup must keep it instead of locking the user out."""
        existing = {"ssh_public_key": _rsa_pub(3072), "ssh_private_key_path": "/keys/id_rsa", "vars": {}}
        deployed = self.env("deployedkey")
        (deployed.dir / "outputs.json").write_text(json.dumps({"bastion_public_ip": "1.2.3.4"}))
        with quiet():
            self.assertFalse(cli._choose_ssh_key(clouds.get("aws"), deployed, {"vars": {"fips_mode": False}}, existing,
                                                 None, None))
        with quiet(), self.assertRaises(ui.Abort):     # not deployed yet: EC2 would refuse it at apply
            cli._choose_ssh_key(clouds.get("aws"), self.env("newkey"), {"vars": {"fips_mode": False}}, existing, None, None)
        existing = {"ssh_public_key": _ed25519_pub(), "ssh_private_key_path": "/keys/id_ed25519", "vars": {}}
        with quiet(), self.assertRaises(ui.Abort):     # a FIPS problem is never waved through
            cli._choose_ssh_key(clouds.get("aws"), deployed, {"vars": {"fips_mode": True}}, existing, None, None)

    def test_saved_string_answers_are_typed_on_load(self):
        cloud, env = clouds.get("aws"), paths.Env("aws", "strbool")
        cfg = _cfg("aws", env="strbool", vars={"fips_mode": "no", "enable_vpn": "yes", "az_count": "3"})
        with quiet():
            cli._check_saved_answers(SimpleNamespace(cmd="apply"), cloud, env, cfg)
        self.assertEqual((cfg["vars"]["fips_mode"], cfg["vars"]["enable_vpn"], cfg["vars"]["az_count"]), (False, True, 3))
        self.assertIs(cloud.render_stack(cfg, Path("/tf"))["module"]["stack"]["fips_mode"], False)   # bool("no") was True

    def test_user_key_rules(self):
        env = self.env("userkey")
        pub = env.dir / "k.pub"
        pub.write_text(_ecdsa_pub())
        with quiet(), self.assertRaises(ui.Abort) as cm:
            cli._choose_ssh_key(clouds.get("azure"), env, {"vars": {}}, {}, (_ecdsa_pub(), pub), None)
        self.assertIn("Azure", cm.exception.msg)
        cfg = {"vars": {}}
        with quiet():
            cli._choose_ssh_key(clouds.get("gcp"), env, cfg, {}, (_ecdsa_pub(), pub), None)
        self.assertEqual(cfg["ssh_private_key_path"], str(pub))           # no private key file next to it


class SetupCliTests(unittest.TestCase):
    """Whole `cloudseed setup` runs that must stop before anything is saved or Terraform runs."""

    def run_cli(self, *argv):
        with quiet() as (out, err):
            rc = cli.main(list(argv))
        ui.NON_INTERACTIVE = False
        return rc, out.getvalue() + err.getvalue()

    def setUp(self):
        for cloud in ("vmware", "aws", "gcp"):
            shutil.rmtree(paths.Env(cloud, "badvals").dir, ignore_errors=True)

    def test_bad_var_values_are_refused_and_nothing_is_saved(self):
        for argv, words in ((["setup", "vmware", "-y", "--env", "badvals", "--var", "guest_os=centos-9"], "guest_os"),
                            (["setup", "vmware", "-y", "--env", "badvals", "--var", "workload_count=abc"], "whole number"),
                            (["setup", "aws", "-y", "--env", "badvals", "--allow-ip", "1.2.3.4", "--var", "enable_vpn=maybe"], "true or false"),
                            (["setup", "aws", "-y", "--env", "badvals", "--allow-ip", "1.2.3.4", "--var", "vpc_cidr=10.9.0.0/16"], "--cidr"),
                            (["setup", "aws", "-y", "--env", "badvals", "--allow-ip", "0.0.0.0/1,128.0.0.0/1"], "0.0.0.0/0"),
                            (["setup", "aws", "-y", "--env", "badvals", "--allow-ip", "1.2.3.4", "--cidr", "10.0.0.0/25"], "/24"),
                            (["setup", "gcp", "-y", "--env", "badvals", "--project-id", "p1-e2e-test", "--allow-ip", "1.2.3.4", "--zone", "us-central1"], "zone")):
            rc, out = self.run_cli(*argv, "--dry-run", "--runtime", "local")
            self.assertEqual(rc, 1, (argv, out[-800:]))
            self.assertIn(words, out, argv)
            for cloud in ("vmware", "aws", "gcp"):
                self.assertFalse(paths.Env(cloud, "badvals").exists(), argv)
                self.assertFalse(list(paths.Env(cloud, "badvals").ssh_dir.glob("id_*")), argv)   # no orphan key

    def test_status_and_destroy_survive_an_invalid_saved_answer(self):
        cloud, env = clouds.get("vmware"), paths.Env("vmware", "wedged")
        env.create_dirs()
        env.save({"cloud": "vmware", "env": "wedged", "name": "cloudseed", "region": "local", "network_cidr": "10.100.0.0/24",
                  "allowed_ssh_cidrs": ["127.0.0.1/32"], "ssh_public_key": _ed25519_pub(), "state": {"type": "local"},
                  "vars": {"guest_os": "centos-9", "workload_count": "abc"}, "extra_vars": {}, "tags": {}})
        cfg = env.load()
        with quiet() as (out, err):
            cli._check_saved_answers(SimpleNamespace(cmd="status"), cloud, env, cfg)
        self.assertEqual((cfg["vars"]["guest_os"], cfg["vars"]["workload_count"]), ("ubuntu-24.04", 0))
        self.assertIn("--var guest_os=VALUE", err.getvalue() + out.getvalue())
        cloud.render_stack(cfg, paths.tf_root())                       # renders (destroy can plan) instead of crashing
        with quiet(), self.assertRaises(ui.Abort):
            cli._check_saved_answers(SimpleNamespace(cmd="apply"), cloud, env, env.load())
        shutil.rmtree(env.dir, ignore_errors=True)


class HintTests(unittest.TestCase):
    def test_diagnosis_is_specific(self):
        e = tf.explain
        cases = [
            ('Error: unable to build authorizer for Resource Manager API: could not configure AzureCli Authorizer: could not '
             'parse Azure CLI version: launching Azure CLI: exec: "az": executable file not found in $PATH', "cloudseed install az"),
            ("Error: building account: obtaining Authorization Token", "az login"),
            ("Error: unable to build authorizer for Resource Manager API: could not configure AzureCli Authorizer: token expired", "az login"),
            ("Error: failed to get shared config profile, prod", "--profile"),
            ("Error: No valid credential sources found", "aws sso login"),
            ("Error: Conflicting configuration arguments", "--var overrides"),
            ("unexpected status 409 (409 Conflict) with error: MissingSubscriptionRegistration: The subscription is not "
             "registered to use namespace 'Microsoft.OperationalInsights'", "az provider register"),
            ("googleapi: Error 403: Compute Engine API has not been used in project 1 before or it is disabled. "
             "SERVICE_DISABLED PERMISSION_DENIED", "gcloud services enable"),
            ("api error RequestLimitExceeded: Request limit exceeded.", "wait a minute"),
            ("api error VcpuLimitExceeded: You have requested more vCPU capacity", "quota"),
            ("Error: creating IAM Role (x): EntityAlreadyExists: Role with name x already exists.", "already exists"),
            ("BadRequestException: The request is rejected because a detector already exists", "enable_guardduty=false"),
            ("Error: Saved plan is stale", "plans again"),
            ("\x1b[31mError: \x1b[0m\x1b[1mfailed to get shared config profile, prod\x1b[0m", "--profile"),
        ]
        for text, want in cases:
            self.assertIn(want, e(text, "plan"), text)
        self.assertNotIn("already exists", e("Error: Conflicting configuration arguments", "plan"))

    def test_init_failure_is_diagnosed_and_logged(self):
        t = tf.Terraform.__new__(tf.Terraform)
        t.workdir, t.binary = Path(tempfile.mkdtemp()), "terraform"
        failed = subprocess.CompletedProcess([], 1, "", "Error: No valid credential sources found\n")
        with mock.patch.object(tf.Terraform, "run", return_value=failed), \
                mock.patch.object(tf.audit, "write") as write, quiet(), self.assertRaises(tf.TerraformError) as cm:
            t.init()
        self.assertIn("aws sso login", str(cm.exception))
        self.assertIn("No valid credential sources", "".join(c.args[0] for c in write.call_args_list))


class CliConfigTests(unittest.TestCase):
    OURS = ('provider_installation {\n  filesystem_mirror {\n    path    = "/cs/providers"\n    include = ["registry.local/*/*"]\n'
            '  }\n  direct {\n    exclude = ["registry.local/*/*"]\n  }\n}\n')

    def test_merge(self):
        merged = tf.merge_cli_config('plugin_cache_dir = "/c"\n', self.OURS)
        self.assertTrue(merged.startswith('plugin_cache_dir = "/c"') and "registry.local" in merged)
        user = ('provider_installation {\n  network_mirror {\n    url = "https://m/"\n  }\n  direct {}\n}\n'
                'credentials "app.terraform.io" { token = "x" }\n')
        merged = tf.merge_cli_config(user, self.OURS)
        self.assertEqual(merged.count("provider_installation"), 1)
        self.assertIn('path    = "/cs/providers"', merged)
        self.assertEqual(merged.count('exclude = ["registry.local/*/*"]'), 2)
        self.assertIn('credentials "app.terraform.io"', merged)
        merged = tf.merge_cli_config('provider_installation {\n  direct {\n    exclude = ["a/*/*"]\n  }\n}\n', self.OURS)
        self.assertIn('exclude = ["registry.local/*/*", "a/*/*"]', merged)
        self.assertIsNone(tf.merge_cli_config("provider_installation {}\nprovider_installation {}\n", self.OURS))
        self.assertIsNone(tf.merge_cli_config('{"provider_installation": {}}', self.OURS))

    def test_only_local_provider_roots_get_cloudseeds_cli_config(self):
        home = Path(tempfile.mkdtemp())
        (home / "terraform.rc").write_text(self.OURS)
        vm, cloud = Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())
        (vm / "main.tf.json").write_text(json.dumps({"terraform": {"required_providers": {"vmdesktop": {"source": tf.LOCAL_PROVIDER}}}}))
        (cloud / "main.tf.json").write_text(json.dumps({"terraform": {"required_providers": {"aws": {"source": "hashicorp/aws"}}}}))
        user_rc = home / "user.rc"
        user_rc.write_text('plugin_cache_dir = "/c"\n')
        with mock.patch.object(tf.paths, "HOME", home), mock.patch.dict(os.environ, {"TF_CLI_CONFIG_FILE": str(user_rc)}):
            t_vm, t_cloud = tf.Terraform.__new__(tf.Terraform), tf.Terraform.__new__(tf.Terraform)
            t_vm.workdir, t_cloud.workdir = vm, cloud
            self.assertEqual(t_cloud._env()["TF_CLI_CONFIG_FILE"], str(user_rc))       # the user's config stays
            rc = Path(t_vm._env()["TF_CLI_CONFIG_FILE"])
            self.assertEqual(rc, home / "terraform-merged.rc")
            self.assertIn('plugin_cache_dir = "/c"', rc.read_text())
            self.assertIn("registry.local", rc.read_text())
        with mock.patch.object(tf.paths, "HOME", home), mock.patch.dict(os.environ, {"HOME": str(home)}):
            os.environ.pop("TF_CLI_CONFIG_FILE", None)
            self.assertNotIn("TF_CLI_CONFIG_FILE", t_cloud._env())
            self.assertEqual(t_vm._env()["TF_CLI_CONFIG_FILE"], str(home / "terraform.rc"))


def _interactive_sigint(test: unittest.TestCase) -> None:
    """Give the test the Ctrl-C of an interactive terminal. A runner started in the background by a non-interactive
    shell (`python -m unittest ... &`) ignores SIGINT, and every process it starts inherits that, so no interrupt or
    cancel could reach anything - whatever the code under test does."""
    old = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    test.addCleanup(signal.signal, signal.SIGINT, old if old is not None else signal.SIG_DFL)


FAKE_TF = """#!/bin/sh
case "$2" in
  apply)
    trap 'echo "Interrupt received."; sleep 1; echo "Gracefully shut down."; exit 1' INT
    echo "Creating..."
    i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done
    echo "never interrupted"; exit 0 ;;
  keys)
    echo "Outputs:"
    printf -- '-----BEGIN ''OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\\nAAAAC3NzaC1lZDI1NTE5AAAAIB\\n-----END OPENSSH PRIVATE KEY-----\\n'
    echo "done"; exit 0 ;;
esac
exit 0
"""


class TerraformRunTests(unittest.TestCase):
    def fake(self):
        d = Path(tempfile.mkdtemp())
        exe = d / "terraform"
        exe.write_text(FAKE_TF)
        exe.chmod(0o755)
        t = tf.Terraform.__new__(tf.Terraform)
        t.workdir, t.binary = d, str(exe)
        return t

    @unittest.skipIf(sys.platform == "win32", "POSIX signals")
    def test_interrupt_waits_for_terraform_to_stop(self):
        _interactive_sigint(self)
        t = self.fake()
        seen = []
        real_print = print

        def ctrl_c_once_applying():
            # the fake terraform prints "Creating..." once its INT trap is set: press Ctrl-C then, however slow the machine
            end = time.time() + 15
            while time.time() < end and not any("Creating..." in line for line in seen):
                time.sleep(0.05)
            os.kill(os.getpid(), signal.SIGINT)
        timer = threading.Thread(target=ctrl_c_once_applying, daemon=True)

        def capture(*a, **k):
            seen.append(" ".join(str(x) for x in a))
        with mock.patch("builtins.print", capture), quiet():
            timer.start()
            started = time.time()
            with self.assertRaises(KeyboardInterrupt):
                t.run("apply", "-input=false")
        real_print  # noqa: B018
        out = "".join(seen)
        self.assertIn("Interrupt received.", out)        # terraform got exactly one SIGINT ...
        self.assertIn("Gracefully shut down.", out)      # ... and its shutdown output was still read (no SIGPIPE)
        self.assertNotIn("never interrupted", out)
        self.assertLess(time.time() - started, 20)

    def test_multiline_private_keys_never_reach_the_log_or_an_agent(self):
        t = self.fake()
        seen = []
        with mock.patch.dict(os.environ, {"CLOUDSEED_REDACT": "1"}), \
                mock.patch.object(tf.audit, "write", side_effect=lambda s: seen.append(s)), \
                mock.patch("builtins.print", lambda *a, **k: seen.append(" ".join(map(str, a)))):
            proc = t.run("keys")
        text = "".join(seen)
        self.assertNotIn("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU", text)
        self.assertIn("[REDACTED]", text)
        self.assertIn("done", text)
        self.assertIn("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU", proc.stdout)   # callers still get the raw text to parse


class ApplyReviewedPlanTests(unittest.TestCase):
    def tf(self, applies, deletes=()):
        t = tf.Terraform.__new__(tf.Terraform)
        t.workdir, t.binary = Path(tempfile.mkdtemp()), "terraform"
        (t.workdir / "tfplan").write_text("approved")
        calls = []
        results = list(applies)

        def run(*args, capture=False, check=True):
            calls.append(args)
            if args[0] == "apply":
                return subprocess.CompletedProcess(args, results.pop(0), "Error: x already exists\n  with aws_iam_role.r," if results else "", "")
            return subprocess.CompletedProcess(args, 0, "{}", "")
        t.run = run
        t.plan = mock.Mock()
        deleting = [set(), set(deletes)]
        t._deleting = mock.Mock(side_effect=lambda f: deleting.pop(0) if deleting else set())
        return t, calls

    def test_the_approved_plan_is_applied_without_replanning(self):
        t, calls = self.tf([0])
        with mock.patch("cloudseed.reconcile.planned_values", return_value={}), quiet():
            t.apply_reconciled("aws", {})
        t.plan.assert_not_called()
        self.assertEqual([c for c in calls if c[0] == "apply"], [("apply", "-input=false", "tfplan")])

    def test_after_adoption_the_new_plan_needs_approval(self):
        t, calls = self.tf([1, 0])
        approve = mock.Mock()
        with mock.patch("cloudseed.reconcile.planned_values", return_value={}), \
                mock.patch("cloudseed.reconcile.recover", return_value=["aws_iam_role.r"]), quiet():
            t.apply_reconciled("aws", {}, approve=approve)
        t.plan.assert_called_once()
        approve.assert_called_once()
        self.assertIn("aws_iam_role.r", approve.call_args[0][0])

    def test_after_adoption_new_deletes_are_refused(self):
        t, calls = self.tf([1, 0], deletes={"aws_eks_cluster.this"})
        approve = mock.Mock()
        with mock.patch("cloudseed.reconcile.planned_values", return_value={}), \
                mock.patch("cloudseed.reconcile.recover", return_value=["aws_eks_cluster.this"]), quiet(), \
                self.assertRaises(tf.TerraformError) as cm:
            t.apply_reconciled("aws", {}, approve=approve)
        self.assertIn("aws_eks_cluster.this", str(cm.exception))
        approve.assert_not_called()
        self.assertEqual(len([c for c in calls if c[0] == "apply"]), 1)

    def test_known_singletons_are_adopted_before_the_plan_is_shown(self):
        t = tf.Terraform.__new__(tf.Terraform)
        t.workdir, t.binary = Path(tempfile.mkdtemp()), "terraform"
        for adopted, plans in (([], 1), (["module.stack.aws_guardduty_detector.this[0]"], 2)):
            t.plan = mock.Mock()
            with mock.patch("cloudseed.reconcile.planned_values", return_value={}), \
                    mock.patch("cloudseed.reconcile.preflight", return_value=adopted) as preflight, quiet():
                t.plan_for_apply("aws", {})
            preflight.assert_called_once()
            self.assertEqual(t.plan.call_count, plans, adopted)   # re-planned only when something was adopted

    def test_apply_commands_review_the_preflighted_plan(self):
        """cmd_apply (like setup, node add, platform prereqs and undo) shows the plan made by plan_for_apply, so the
        GuardDuty/OIDC singletons are adopted before approval and apply_reconciled applies exactly that plan."""
        env = paths.Env("aws", "reviewed")
        env.save(_cfg("aws", env="reviewed", vars={}))
        calls = []

        class FakeTerraform:
            def __init__(self, workdir):
                self.workdir = workdir

            def init(self, **kw):
                calls.append("init")

            def state_list(self):
                return []

            def run(self, *args, **kw):   # cli-life: cmd_apply reads the state strictly (`terraform state list`)
                return subprocess.CompletedProcess(args, 0, "", "")

            def plan(self, *a, **k):
                calls.append("plan")

            def plan_for_apply(self, cloud_key, cfg, *a, **k):
                calls.append("plan_for_apply")

            def apply_reconciled(self, cloud_key, cfg, **k):
                calls.append("apply_reconciled")
        try:
            with mock.patch.object(cli, "Terraform", FakeTerraform), mock.patch.object(cli, "_finish"), \
                    mock.patch.object(cli.undo, "record"), quiet():
                cli.cmd_apply(SimpleNamespace(cloud="aws", env="reviewed", auto_approve=True, cmd="apply"), {})
        finally:
            shutil.rmtree(env.dir, ignore_errors=True)
        self.assertEqual(calls, ["init", "plan_for_apply", "apply_reconciled"])


class StreamRedactorTests(unittest.TestCase):
    PEM = ("-----BEGIN " "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n"
           "AAAAAAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBx\n-----END OPENSSH PRIVATE KEY-----\n")

    def feed(self, text):
        r = secrets.StreamRedactor()
        return "".join(r.feed(line) for line in text.splitlines(True))

    def test_multiline_keys(self):
        self.assertEqual("\n".join(secrets.redact(x) for x in self.PEM.splitlines()), self.PEM.rstrip("\n"))   # the old gap
        out = self.feed("before\n" + self.PEM + "after token=" + "abcdef123456\n")
        self.assertEqual(out, "before\n[REDACTED]\nafter token=[REDACTED]\n")
        out = self.feed("key: " + self.PEM.replace("-----END", "x\n-----END"))
        self.assertEqual(out, "key: [REDACTED]\n")
        pgp = "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----\nok\n"
        self.assertEqual(self.feed(pgp), "[REDACTED]\nok\n")
        ovpn = "-----BEGIN OpenVPN Static key V1-----\n0123abcd\n-----END OpenVPN Static key V1-----\n"
        self.assertEqual(self.feed(ovpn), "[REDACTED]\n")

    def test_one_line_and_runaway_blocks(self):
        one = '{"key": "-----BEGIN ' + 'RSA PRIVATE KEY-----\\nabc\\n-----END RSA PRIVATE KEY-----"}\n'
        self.assertNotIn("abc", self.feed(one))
        r = secrets.StreamRedactor()
        r.feed("-----BEGIN " + "RSA PRIVATE KEY-----\n")
        outs = [r.feed("line\n") for _ in range(r.MAX_KEY_LINES)]
        self.assertTrue(outs[-1].startswith("[REDACTED]"))
        self.assertEqual(r.feed("visible again\n"), "visible again\n")


class PythonCompatTests(unittest.TestCase):
    def test_every_module_compiles_on_an_older_python(self):
        """cloudseed promises Python 3.9 (stock macOS python3). Newer syntax such as PEP 701 f-strings only fails on a
        real old interpreter (ast.parse(feature_version=...) accepts it), so compile with one when available."""
        candidates = [shutil.which(n) for n in ("python3.9", "python3.10", "python3.11")] + ["/usr/bin/python3"]
        old = None
        for exe in filter(None, candidates):
            try:
                ver = subprocess.run([exe, "-c", "import sys; print(sys.version_info[:2] < (3, 12))"], capture_output=True,
                                     text=True, timeout=30).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                continue
            if ver == "True":
                old = exe
                break
        if not old:
            self.skipTest("no Python older than 3.12 on this machine")
        files = sorted(str(p) for p in (ROOT / "cloudseed").rglob("*.py")
                       if not p.name.startswith(".")) + [str(ROOT / "bin" / "cloudseed")]   # not ._*.py debris
        code = ("import sys\nbad = []\nfor p in sys.argv[1:]:\n    try:\n        compile(open(p, encoding='utf-8').read(), p, 'exec')\n"
                "    except SyntaxError as e:\n        bad.append(f'{p}:{e.lineno}: {e.msg}')\nprint('\\n'.join(bad))\n"
                "sys.exit(1 if bad else 0)\n")
        p = subprocess.run([old, "-c", code, *files], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


class TerraformModuleTests(unittest.TestCase):
    """Plan-level tests of the Terraform stacks (terraform/<cloud>/tests/*.tftest.hcl, mock providers). Opt-in:
    they need the provider schemas (network or a plugin cache) and take minutes: CLOUDSEED_TF_TESTS=1."""

    def test_terraform_test_suites(self):
        suites = sorted({p.parent.parent for p in (ROOT / "terraform").glob("*/tests/*.tftest.hcl")})
        if os.environ.get("CLOUDSEED_TF_TESTS") != "1":
            self.skipTest(f"set CLOUDSEED_TF_TESTS=1 to run {len(suites)} terraform test suite(s)")
        terraform = shutil.which("terraform")
        if not terraform:
            self.skipTest("terraform not installed")
        work = Path(tempfile.mkdtemp()) / "terraform"
        shutil.copytree(ROOT / "terraform", work, ignore=shutil.ignore_patterns(".terraform", ".terraform.lock.hcl"))
        for suite in suites:
            d = work / suite.name
            for args in (["init", "-backend=false", "-input=false", "-no-color"], ["test", "-no-color"]):
                p = subprocess.run([terraform, f"-chdir={d}", *args], capture_output=True, text=True, timeout=1800)
                self.assertEqual(p.returncode, 0, f"{suite.name}: terraform {args[0]}\n{(p.stdout + p.stderr)[-3000:]}")


if __name__ == "__main__":
    unittest.main()
