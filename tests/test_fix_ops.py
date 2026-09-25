"""Regression tests for the ops fixes: undo journal, audit trail, container runtime, deps, finops, reconcile,
troubleshoot, and the build/install scripts. Stdlib only, no network, no cloud."""

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import audit, clouds, container, deps, finops, paths, reconcile, secrets, troubleshoot, ui, undo  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _scope(name: str) -> str:
    undo.clear(name)
    return name


# ---------------------------------------------------------------------------------------------------- undo journal

class UndoJournalTests(unittest.TestCase):
    def test_parallel_processes_never_lose_entries(self):
        home = tempfile.mkdtemp(prefix="cs-undo-par-")
        code = textwrap.dedent("""
            import sys
            sys.path.insert(0, sys.argv[1])
            from cloudseed import undo
            for i in range(15):
                undo.record(sys.argv[2], f"a{i}", "info", {"i": i}, minor=False)
                undo.record("shared", f"{sys.argv[2]}-{i}", "argv", {"argv": ["x", sys.argv[2], str(i)]})
        """)
        env = dict(os.environ, CLOUDSEED_HOME=home)
        seed = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, sys.argv[1]); from cloudseed import undo; "
                               "[undo.record('seed', f's{i}', 'argv', {'argv': [str(i)]}) for i in range(3)]", str(REPO)], env=env)
        self.assertEqual(seed.returncode, 0)
        procs = [subprocess.Popen([sys.executable, "-c", code, str(REPO), f"p{n}"], env=env) for n in range(4)]
        self.assertEqual([p.wait() for p in procs], [0, 0, 0, 0])
        data = json.loads((Path(home) / "undo.json").read_text())
        self.assertEqual(len(data["seed"]), 3)                   # untouched by the parallel writers
        for n in range(4):
            self.assertEqual(len(data[f"p{n}"]), undo.KEEP_LIGHT)
        self.assertEqual(len(data["shared"]), undo.KEEP)
        self.assertEqual(oct(os.stat(Path(home) / "undo.json").st_mode & 0o777), "0o600")
        self.assertEqual(sorted(p.name for p in Path(home).iterdir() if p.name.startswith(".undo.")), [])  # no temp files left

    def test_corrupt_journal_is_kept_aside(self):
        undo.clear("c-scope")
        text = undo.JOURNAL.read_text() if undo.JOURNAL.exists() else "{}"
        try:
            undo.JOURNAL.write_text("{not json")
            undo.record("c-scope", "x", "argv", {"argv": ["a"]})
            kept = list(undo.JOURNAL.parent.glob("undo.json.corrupt-*"))
            self.assertTrue(kept)
            self.assertEqual(kept[0].read_text(), "{not json")
            for k in kept:
                k.unlink()
        finally:
            undo.JOURNAL.write_text(text)

    def test_minor_entries_never_evict_real_changes(self):
        s = _scope("m-scope")
        for i in range(5):
            undo.record(s, f"real {i}", "argv", {"argv": ["disable", str(i)]})
        for i in range(8):
            undo.record(s, f"report {i}", "delete-paths", {"paths": [f"/tmp/r{i}"]})
            undo.record(s, f"scan {i}", "argv-seq", {"argvs": [["x", str(i)]]}, minor=True)
        es = undo.entries(s)
        self.assertEqual([e["summary"] for e in es if not undo.is_minor(e)], [f"real {i}" for i in range(5)])
        self.assertEqual(len([e for e in es if undo.is_minor(e)]), undo.KEEP_LIGHT)
        undo.clear(s)

    def test_identical_entries_are_kept_unless_coalesced(self):
        s = _scope("co-scope")
        for i in range(3):
            undo.record(s, f"same {i}", "info", {"advice": "x"})
        self.assertEqual(len(undo.entries(s)), 3)
        undo.clear(s)
        for i in range(4):
            undo.record(s, f"env use e{i}", "settings-restore", {"settings": {"current_env": f"e{i}"}, "what": ["current_env"]},
                        coalesce="current_env")
        es = undo.entries(s)
        self.assertEqual(len(es), 1)
        self.assertEqual(es[0]["summary"], "env use e3")                          # newest summary
        self.assertEqual(es[0]["data"]["settings"]["current_env"], "e0")          # oldest data: undo goes back before the run
        undo.clear(s)

    def test_scopes_entries_collection_and_drop(self):
        a, b = _scope("sc-a"), _scope("sc-b")
        undo.record(a, "a1", "argv", {"argv": ["a"]})
        e = undo.record(b, "b1", "restore-files", {"files": {"/x": undo.backup_file(__file__)}})
        self.assertIn(a, undo.scopes())
        self.assertEqual({x["scope"] for x in undo.entries([a, b])}, {a, b})
        backup = Path(e["data"]["files"]["/x"])
        self.assertTrue(backup.exists())
        undo.drop(e)
        self.assertFalse(backup.exists())
        self.assertIsNone(undo.latest(b))
        undo.clear(a)

    def test_backup_names_are_unique(self):
        d = Path(tempfile.mkdtemp())
        (d / "a").mkdir()
        (d / "b").mkdir()
        (d / "a" / "values.yaml").write_text("A-original")
        (d / "b" / "values.yaml").write_text("B-original")
        (d / "c1").mkdir()
        (d / "c2").mkdir()
        (d / "c1" / "cfg").mkdir()
        (d / "c2" / "cfg").mkdir()
        ba, bb = undo.backup_file(d / "a" / "values.yaml"), undo.backup_file(d / "b" / "values.yaml")
        self.assertNotEqual(ba, bb)
        self.assertEqual(Path(ba).read_text(), "A-original")
        self.assertEqual(Path(bb).read_text(), "B-original")
        self.assertNotEqual(undo.backup_file(d / "c1" / "cfg"), undo.backup_file(d / "c2" / "cfg"))   # no FileExistsError

    def test_restore_files_refuses_when_backup_is_missing(self):
        d = Path(tempfile.mkdtemp())
        f = d / "token"
        f.write_text("current")
        entry = {"kind": "restore-files", "data": {"files": {str(f): str(undo.BACKUPS / "gone-token")}}, "scope": "global", "summary": "x"}
        with self.assertRaises(ui.Abort):
            undo.perform(entry, {}, True)
        self.assertEqual(f.read_text(), "current")

    def test_settings_restore_current_env_only_touches_that_key(self):
        s = paths.load_settings()
        s.update(current_env="aws-new", runtime="container")
        paths.save_settings(s)
        undo.perform({"kind": "settings-restore", "data": {"settings": {"current_env": "aws-old", "runtime": "local"},
                      "what": ["current_env"]}, "scope": "global", "summary": "env use"}, {}, True)
        now = paths.load_settings()
        self.assertEqual(now["current_env"], "aws-old")
        self.assertEqual(now["runtime"], "container")          # changed since, not part of the entry
        now.pop("runtime")
        now.pop("current_env")
        paths.save_settings(now)

    def test_creds_restore_puts_back_and_removes(self):
        from cloudseed import creds
        creds.set_("OPS_T_OLD", "old-value")
        creds.set_("OPS_T_NEW", "new-value")
        undo.perform({"kind": "creds-restore", "data": {"values": {"OPS_T_OLD": "older"}, "unset": ["OPS_T_NEW"]},
                      "scope": "global", "summary": "creds set"}, {}, True)
        data = creds.load()
        self.assertEqual(data["OPS_T_OLD"], "older")
        self.assertNotIn("OPS_T_NEW", data)
        self.assertIn("remove stored credential(s): OPS_T_NEW",
                      undo.describe({"kind": "creds-restore", "scope": "global", "data": {"values": {"A": "1"}, "unset": ["OPS_T_NEW"]}}))
        creds.unset("OPS_T_OLD")

    def test_argv_entry_with_approval_gets_auto_approve_after_interactive_yes(self):
        from cloudseed import cli
        calls = []
        entry = {"kind": "argv", "data": {"argv": ["apply", "aws", "--env", "dev", "-y"], "approve": True}, "scope": "global",
                 "summary": "destroy targets"}
        with mock.patch.object(cli, "_approve", lambda q, auto: None), mock.patch.object(undo, "_run_cli", calls.append):
            undo.perform(entry, {}, False)                       # interactive yes (no --auto-approve)
        self.assertEqual(calls, [["apply", "aws", "--env", "dev", "-y", "--auto-approve"]])

    def test_run_cli_restores_interactive_flag_and_audit_state(self):
        audit.begin(["undo", "--list"])
        before = dict(audit._state)
        ui.NON_INTERACTIVE = False
        undo._run_cli(["-y", "disable", "headliner"])
        self.assertFalse(ui.NON_INTERACTIVE)
        self.assertEqual(audit._state["argv"], before["argv"])
        self.assertEqual(audit._state["cmd"], "undo")
        last = json.loads((paths.HOME / "logs" / "audit.jsonl").read_text().splitlines()[-1])
        self.assertEqual(last["command"], "disable")
        self.assertEqual(last["parent"], "undo")

    def test_config_undo_does_not_touch_config_when_the_plan_fails(self):
        from cloudseed import cli
        from cloudseed.tf import TerraformError
        env = paths.Env("aws", "undocfg")
        env.create_dirs()
        cur = {"cloud": "aws", "env": "undocfg", "name": "cs", "allowed_ssh_cidrs": ["203.0.113.7/32"], "state": {"type": "local"}}
        env.save(dict(cur))
        rendered = []

        class FakeTf:
            def __init__(self, workdir):
                pass

            def init(self, migrate=False):
                pass

            def plan(self, out):
                raise TerraformError("terraform plan failed: AWS credentials are missing")

            def plan_for_apply(self, cloud_key, cfg, out="tfplan", targets=(), render=None):   # core: undo reviews this plan
                self.plan(out)

        entry = {"kind": "config", "scope": env.id, "summary": "update-ip",
                 "data": {"prev_cfg": {**cur, "allowed_ssh_cidrs": ["198.51.100.1/32"]}}}
        with mock.patch.object(cli, "_render", lambda c, e, cfg: rendered.append(cfg["allowed_ssh_cidrs"]) or False), \
                mock.patch("cloudseed.tf.Terraform", FakeTf):
            with self.assertRaises(TerraformError):
                undo.perform(entry, {}, True)
        self.assertEqual(env.load()["allowed_ssh_cidrs"], ["203.0.113.7/32"])       # config.json untouched
        self.assertEqual(rendered[-1], ["203.0.113.7/32"])                          # rendered root put back
        self.assertEqual(entry["data"]["prev_cfg"]["allowed_ssh_cidrs"], ["198.51.100.1/32"])   # entry not mutated


class KubeArgTests(unittest.TestCase):
    """undo.kubectl_namespaces reads a command line exactly like `cs kubectl` does for its Velero undo point."""

    def test_namespaces(self):
        ns = undo.kubectl_namespaces
        self.assertEqual(ns(["delete", "ns", "shop"]), ["shop"])
        self.assertEqual(ns(["delete", "namespace", "a", "b"]), ["a", "b"])
        self.assertEqual(ns(["delete", "ns/shop"]), ["shop"])
        self.assertEqual(ns(["-n", "shop", "delete", "pod", "x"]), ["shop"])
        self.assertEqual(ns(["delete", "pod", "x", "-nshop"]), ["shop"])
        self.assertEqual(ns(["delete", "pod", "x", "--namespace=shop"]), ["shop"])
        self.assertIsNone(ns(["delete", "crd", "foos.example.com"]))
        self.assertIsNone(ns(["apply", "-f", "all.yaml"]))
        self.assertEqual(ns(["apply", "-f", "x.yaml", "-n", "shop"]), ["shop"])
        self.assertIsNone(ns(["delete", "pods", "--all", "-A"]))
        self.assertEqual(ns(["scale", "deploy/web", "--replicas", "3"]), ["default"])
        # label/annotate arguments are not namespaces (velero would reject `--include-namespaces team=a`)
        self.assertEqual(ns(["label", "ns", "shop", "team=a"]), ["shop"])
        self.assertEqual(ns(["annotate", "ns", "shop", "note-"]), ["shop"])
        self.assertEqual(ns(["label", "ns/shop", "team=a"]), ["shop"])
        # mixed targets: the namespace itself and the namespaced object; a cluster-scoped one means the whole cluster
        self.assertEqual(ns(["delete", "ns/a", "deploy/b"]), ["a", "default"])
        self.assertIsNone(ns(["delete", "ns/a", "clusterrole/b"]))


# ---------------------------------------------------------------------------------------------------- audit trail

class AuditFixTests(unittest.TestCase):
    def test_creds_values_are_masked_whatever_the_key(self):
        argv = ["-y", "creds", "set", "MY_DB_PASS=hunter2hunter2", "TS_AUTHKEY=tskey-" + "auth-kABCDEF123", "SHORT=abc",
                "GOOGLE_PROJECT=myproj", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI"]
        out = " ".join(audit.safe_argv(argv))
        for secret in ("hunter2hunter2", "tskey-auth", "abc", "wJalrXUtnFEMI"):
            self.assertNotIn("=" + secret, out)
        self.assertIn("GOOGLE_PROJECT=myproj", out)                  # plain-text vault settings stay readable
        self.assertTrue(secrets.is_secret_env("TS_AUTHKEY"))          # parked by the agent session broker too

    def test_command_skips_global_option_values(self):
        self.assertEqual(audit.command_of(["--runtime", "container", "status", "aws"]), "status")
        self.assertEqual(audit.command_of(["--runtime", "local", "--runtime", "container", "status", "aws"]), "status")
        self.assertEqual(audit.command_of(["--engine", "docker", "-y", "setup", "aws"]), "setup")
        self.assertEqual(audit.command_of(["setup", "mcp"]), "mcp")
        self.assertEqual(audit.command_of(["-y"]), "cloudseed")

    def test_log_file_named_after_command_and_private(self):
        env = paths.Env("aws", "auditfix")
        env.create_dirs()
        audit.begin(["--runtime", "local", "status", "aws", "--env", "auditfix"])
        audit.attach(env)
        audit.write("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n")
        audit.write("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n")
        audit.write("-----END OPENSSH PRIVATE KEY-----\n")
        audit.write("after the key\n")
        audit.tag(undo={"id": "x1"})
        audit.end(0)
        rec = audit.read_audit(env)[-1]
        self.assertEqual(rec["command"], "status")
        self.assertTrue(rec["log"].endswith("-status.log"))
        self.assertEqual(rec["undo"], {"id": "x1"})
        text = Path(rec["log"]).read_text()
        self.assertNotIn("b3BlbnNzaC1rZXkt", text)
        self.assertIn("after the key", text)
        self.assertEqual(oct(os.stat(rec["log"]).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(env.dir / "logs" / "audit.jsonl").st_mode & 0o777), "0o600")

    def test_key_body_is_dropped_when_a_key_name_precedes_the_marker(self):
        # redact()'s key=value rule used to eat "-----BEGIN" first, so the body lines were no longer recognised
        f = io.StringIO()
        audit.begin(["x"])
        audit._state["log"] = f
        try:
            for line in ("private_key: -----BEGIN " + "RSA PRIVATE KEY-----", "MIIEpAIBAAKCAQEAsecretbody", "-----END RSA PRIVATE KEY-----", "ok"):
                audit.write(line)
        finally:
            audit._state["log"] = None
        self.assertNotIn("MIIEpAIBAAKCAQEAsecretbody", f.getvalue())
        self.assertIn("ok", f.getvalue())

    def test_stray_begin_marker_does_not_swallow_the_log(self):
        f = audit._KeyFilter()
        out = f.feed("-----BEGIN " + "RSA PRIVATE KEY-----\n") + "".join(f.feed("line\n") for _ in range(audit._KeyFilter.MAX_LINES + 5))
        self.assertIn("no END marker", out)
        self.assertIn("line", out)

    def test_inventory_identifier_fields_still_hide_token_formats(self):
        tok = "ghp_" + "A1b2C3d4" * 5
        out = audit.secrets_free({"id": f"cs/{tok}", "endpoint": "redis://:hunter2hunter2@cache:6379"})
        self.assertNotIn(tok, out["id"])
        self.assertNotIn("hunter2hunter2", out["endpoint"])

    def test_inventory_keeps_ids_and_hides_sensitive_outputs(self):
        inv = {"current": {"resources": [{"id": "cs-dev-eks-external-secrets:external-secrets",
                                          "arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"}]}}
        out = audit.secrets_free(inv)["current"]["resources"][0]
        self.assertEqual(out["id"], "cs-dev-eks-external-secrets:external-secrets")
        self.assertIn("secret:prod/db-AbCdEf", out["arn"])

        class T:
            def run(self, *a, **k):
                return subprocess.CompletedProcess([], 0, json.dumps({"values": {"outputs": {
                    "db_password": {"value": "hunter2hunter2", "sensitive": True}, "ip": {"value": "1.2.3.4"}}}}), "")
        env = paths.Env("aws", "auditsens")
        env.create_dirs()
        inv = audit.refresh(env, T(), "apply")
        self.assertEqual(inv["current"]["outputs"]["db_password"], secrets.REDACTED)
        self.assertNotIn("hunter2hunter2", (env.dir / "inventory.json").read_text())

    def test_read_audit_nonpositive(self):
        self.assertEqual(audit.read_audit(paths.Env("aws", "auditfix"), 0), [])
        self.assertEqual(audit.read_audit(paths.Env("aws", "auditfix"), -3), [])


# ---------------------------------------------------------------------------------------------------- container

class ContainerTests(unittest.TestCase):
    def test_run_command_has_no_secret_values_and_maps_paths(self):
        key = Path(tempfile.mkdtemp()) / "sa.json"
        key.write_text("{}")
        environ = {"AWS_SECRET_ACCESS_KEY": "SECRETVALUE", "ARM_CLIENT_SECRET": "AZSECRET", "GOOGLE_APPLICATION_CREDENTIALS": str(key),
                   "TF_PLUGIN_CACHE_DIR": "/does/not/exist", "CLOUDSEED_HOME": "/elsewhere", "PATH": "/usr/bin"}
        cmd = container.build_run_command("docker", ["--runtime", "container", "status", "aws", "--engine=docker"], environ, tty=False)
        joined = " ".join(cmd)
        self.assertNotIn("SECRETVALUE", joined)
        self.assertNotIn("AZSECRET", joined)
        self.assertIn("AWS_SECRET_ACCESS_KEY", cmd)
        self.assertIn(f"{key.resolve()}:/run/cloudseed/google_application_credentials.json:ro", cmd)
        self.assertIn("GOOGLE_APPLICATION_CREDENTIALS=/run/cloudseed/google_application_credentials.json", cmd)
        self.assertNotIn("TF_PLUGIN_CACHE_DIR", joined)                   # host-only path that does not exist: dropped
        self.assertIn(f"{paths.HOME}:{paths.HOME}", cmd)                 # same absolute path inside
        self.assertIn(f"CLOUDSEED_HOME={paths.HOME}", cmd)
        self.assertIn(f"{container.tools_home() / 'bin'}:{paths.HOME / 'bin'}", cmd)   # container tools never land in the host bin
        self.assertEqual(cmd[-4:], ["--runtime", "local", "status", "aws"])
        self.assertTrue(any(c.startswith("USER=") for c in cmd))
        self.assertTrue(any(c.startswith("CLOUDSEED_HOST_NAME=") for c in cmd))

    def test_host_path_maps_legacy_container_records(self):
        self.assertEqual(container.host_path("/root/.cloudseed/envs/aws-dev/logs/x.log"), paths.HOME / "envs/aws-dev/logs/x.log")
        self.assertEqual(container.host_path("/tmp/other"), Path("/tmp/other"))

    def test_daemon_down_and_hanging(self):
        container._DAEMON_OK.discard("docker")
        with mock.patch.object(container.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(container.subprocess, "run", return_value=subprocess.CompletedProcess(
                    [], 1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock")):
            with self.assertRaises(ui.Abort):
                container.image_exists("docker")
        with mock.patch.object(container.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(container.subprocess, "run", side_effect=subprocess.TimeoutExpired("docker", 30)):
            with self.assertRaises(ui.Abort):
                container.ensure_daemon("docker")
        self.assertNotIn("docker", container._DAEMON_OK)


# ---------------------------------------------------------------------------------------------------- deps

class DepsFixTests(unittest.TestCase):
    def test_vmware_needs_terraform_and_ssh_keygen(self):
        self.assertIn("vmware", deps.TOOLS["terraform"]["clouds"])
        self.assertIn("vmware", deps.TOOLS["ssh-keygen"]["clouds"])

    def test_too_old(self):
        self.assertTrue(deps.too_old("terraform", "1.5.7"))
        self.assertFalse(deps.too_old("terraform", "1.10.0"))
        self.assertFalse(deps.too_old("terraform", "1.16.4-beta1"))
        self.assertFalse(deps.too_old("terraform", "installed"))
        self.assertFalse(deps.too_old("kubectl", "0.1"))

    def test_outdated_terraform_counts_as_missing_and_is_upgraded(self):
        with mock.patch.object(deps, "find", lambda t: f"/x/{t}"), mock.patch.object(deps, "version_of", lambda t: "1.5.7" if t == "terraform" else "ok"):
            req, _ = deps.missing("aws")
            self.assertIn("terraform", req)
            called = []
            with mock.patch.object(deps, "install_terraform_release", lambda *a, **k: called.append(1)), \
                    mock.patch.object(deps, "too_old", side_effect=[True, False]):
                self.assertTrue(deps.install("terraform"))
            self.assertEqual(called, [1])

    def test_find_skips_binaries_for_another_platform(self):
        d = Path(tempfile.mkdtemp())
        foreign = d / "kubectl"
        magic = b"\x7fELF" if sys.platform == "darwin" else b"\xcf\xfa\xed\xfe"
        foreign.write_bytes(magic + b"\x02\x01\x01" + b"\0" * 64)
        foreign.chmod(0o755)
        script = d / "helm"
        script.write_text("#!/bin/sh\necho ok\n")
        script.chmod(0o755)
        with mock.patch.object(deps, "path_env", lambda: {"PATH": str(d)}):
            self.assertIsNone(deps.find("kubectl"))
            self.assertEqual(deps.find("helm"), str(script))

    def test_optional_nag_only_for_the_cloud_cli(self):
        asked = []
        with mock.patch.object(deps, "missing", lambda c: ([], ["k9s", "openvpn", "tailscale"])), \
                mock.patch.object(ui, "interactive", lambda: True), mock.patch.object(ui, "confirm", lambda *a, **k: asked.append(a) or False):
            self.assertEqual(deps.ensure_runtime("aws", "auto", {}), "local")
        self.assertEqual(asked, [])
        with mock.patch.object(deps, "missing", lambda c: ([], ["aws", "k9s"])), \
                mock.patch.object(ui, "interactive", lambda: True), mock.patch.object(ui, "confirm", lambda *a, **k: asked.append(a) or False), \
                mock.patch.object(paths, "save_settings", lambda s: None):
            deps.ensure_runtime("aws", "auto", {}, nag_optional=False)
            self.assertEqual(asked, [])
            deps.ensure_runtime("aws", "auto", {})
            self.assertTrue(asked)

    def test_vmware_setup_requires_terraform_up_front(self):
        with mock.patch.object(deps, "missing", lambda c: (["terraform"], [])), mock.patch.object(deps, "find", lambda t: "/vmrun" if t == "vmrun" else None), \
                mock.patch.object(ui, "interactive", lambda: False):
            with self.assertRaises(ui.Abort) as cm:
                deps.ensure_runtime("vmware", "container", {}, needs_host=True)
            self.assertEqual(cm.exception.code, 2)
            self.assertEqual(deps.ensure_runtime("vmware", "auto", {}, needs_host=False), "local")   # read-only commands still run

    def test_venv_entry_point_from_the_container_is_not_usable(self):
        d = Path(tempfile.mkdtemp())
        script = d / "ansible-playbook"
        script.write_text("#!/root/.cloudseed/venv-ansible/bin/python\nprint(1)\n")
        self.assertFalse(deps._shebang_ok(script))
        script.write_text(f"#!{sys.executable}\nprint(1)\n")
        self.assertTrue(deps._shebang_ok(script))

    def test_checksums_and_safe_extract(self):
        with self.assertRaises(ui.Abort):
            deps._verify_sha256(b"data", "0" * 64, "x")
        with self.assertRaises(ui.Abort):
            deps._verify_sha256(b"data", None, "x")
        import hashlib
        deps._verify_sha256(b"data", hashlib.sha256(b"data").hexdigest(), "x")
        self.assertEqual(deps._sum_for("abc  a.zip\ndef *b.zip\n", "b.zip"), "def")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo("../evil")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
        buf.seek(0)
        dest = Path(tempfile.mkdtemp()) / "d"
        dest.mkdir()
        with tarfile.open(fileobj=buf, mode="r:gz") as tf:
            with self.assertRaises((Exception, ui.Abort)):   # tarfile's filter error (3.12+) or the 3.9-3.11 fallback's Abort
                deps._safe_extract(tf, dest)
        self.assertFalse((dest.parent / "evil").exists())

    def test_databricks_uses_the_verified_release_zip(self):
        import hashlib
        import zipfile
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as zf:
            zf.writestr("databricks", "#!/bin/sh\necho databricks\n")
        blob = zbuf.getvalue()
        os_name, arch = deps._os_arch()
        name = f"databricks_cli_9.9.9_{os_name}_{arch}.zip"
        files = {name: blob, "databricks_cli_9.9.9_SHA256SUMS": f"{hashlib.sha256(blob).hexdigest()}  {name}\n".encode()}
        with mock.patch.object(deps, "_brew_install", lambda p: False), mock.patch.object(deps, "_latest_github_tag", lambda r, f: "v9.9.9"), \
                mock.patch.object(deps, "_download", lambda url, timeout=0: files[url.rsplit("/", 1)[1]]):
            self.assertTrue(deps.install_databricks())
        self.assertTrue((paths.BIN_DIR / "databricks").exists())
        (paths.BIN_DIR / "databricks").unlink()


# ---------------------------------------------------------------------------------------------------- finops

class FinopsFixTests(unittest.TestCase):
    def _est(self, cloud, env, cfg):
        e = paths.Env(cloud, env)
        e.create_dirs()
        return finops.estimate(clouds.get(cloud), e, cfg)

    def test_extra_vars_and_defaults(self):
        est = self._est("aws", "fx1", {"vars": {"enable_vpn": True, "vpn_instance_type": None}, "extra_vars": {"vpn_instance_type": "t3.small"}})
        names = [n for n, _ in est["lines"]]
        self.assertIn("vpn host t3.small x1", names)
        self.assertIn("public IPv4 x3", names)                  # bastion + NAT + VPN
        self.assertIn("KMS key x1", names)

    def test_unknown_size_makes_the_total_a_lower_bound(self):
        est = self._est("aws", "fx2", {"vars": {"enable_kubernetes": True, "kubernetes_node_size": "x9.mega", "kubernetes_node_count": 3}})
        self.assertTrue(est["lower_bound"])
        self.assertEqual(est["unpriced"], ["x9.mega"])
        self.assertTrue(any("lower bound" in n for n in est["notes"]))

    def test_gcp_nat_is_per_vm(self):
        est = dict(self._est("gcp", "fx3", {"vars": {}})["lines"])
        self.assertAlmostEqual(est["Cloud NAT (0 VMs)"], 0.0)
        self.assertIn("static external IP x1", est)
        est = dict(self._est("gcp", "fx4", {"vars": {"enable_kubernetes": True, "kubernetes_node_count": 2}, "extra_vars": {"enable_vpn": True, "vpn_machine_type": "e2-standard-2"}})["lines"])
        self.assertAlmostEqual(est["Cloud NAT (2 VMs)"], 0.0014 * 730 * 2, places=2)
        self.assertIn("vpn host e2-standard-2 x1", est)
        self.assertIn("static external IP x2", est)

    def test_vmware_counts_stack_defaults(self):
        est = self._est("vmware", "fx5", {"vars": {"enable_kubernetes": True}})
        self.assertIn("local VMs x4 (no cloud cost)", [n for n, _ in est["lines"]])

    def test_reports_are_unique_and_utc(self):
        env = paths.Env("aws", "fx6")
        env.create_dirs()
        a = finops.save_report(env, {"x": 1})
        b = finops.save_report(env, {"x": 2})
        self.assertNotEqual(a, b)
        self.assertTrue(a.exists() and b.exists())
        self.assertEqual(json.loads((env.dir / "finops" / "latest.json").read_text()), {"x": 2})
        import time
        self.assertIn(time.strftime("%Y%m%d", time.gmtime()), a.name)


# ---------------------------------------------------------------------------------------------------- reconcile

COLORED = ('\x1b[31m╷\x1b[0m\x1b[0m\n\x1b[31m│\x1b[0m \x1b[0m\x1b[1m\x1b[31mError: \x1b[0m\x1b[0m\x1b[1mcreating IAM Role\x1b[0m\n'
           '\x1b[31m│\x1b[0m \x1b[0m\n\x1b[31m│\x1b[0m \x1b[0m\x1b[0m  with module.stack.aws_iam_role.bastion,\n'
           '\x1b[31m│\x1b[0m \x1b[0m  on main.tf line 2:\n\x1b[31m│\x1b[0m \x1b[0mEntityAlreadyExists: Role with name acme-dev-bastion already exists.\n'
           '\x1b[31m╵\x1b[0m\x1b[0m\n\x1b[31m╷\x1b[0m\x1b[0m\n\x1b[31m│\x1b[0m \x1b[0m\x1b[1m\x1b[31mError: \x1b[0m\x1b[0m\x1b[1mcreating bucket\x1b[0m\n'
           '\x1b[31m│\x1b[0m \x1b[0m\x1b[0m  with module.stack.aws_s3_bucket.trail,\n\x1b[31m│\x1b[0m \x1b[0mBucketAlreadyOwnedByYou\n\x1b[31m╵\x1b[0m\x1b[0m\n')


class FakeTf:
    def __init__(self, state=()):
        self.state, self.calls = list(state), []

    def state_list(self):
        return self.state

    def run(self, *args, **kw):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")


class ReconcileFixTests(unittest.TestCase):
    CFG = {"cloud": "aws", "env": "dev", "name": "acme", "owner": "alice", "region": "us-east-1", "vars": {}}

    def test_coloured_output_is_parsed(self):
        self.assertEqual(reconcile.conflicts(COLORED), ["module.stack.aws_iam_role.bastion", "module.stack.aws_s3_bucket.trail"])

    def test_generic_conflict_is_not_already_exists(self):
        self.assertEqual(reconcile.conflicts("Error: Apply failed with 1 conflict: conflict with \"helm\"\n\n  with module.x.aws_iam_role.y,\n"), [])

    def test_recover_only_adopts_what_this_env_owns(self):
        planned = {"module.stack.aws_iam_role.bastion": {"type": "aws_iam_role", "values": {"name": "acme-dev-bastion"}},
                   "module.stack.aws_s3_bucket.trail": {"type": "aws_s3_bucket", "values": {"bucket": "acme-dev-trail"}}}
        tags = {"acme-dev-bastion": {"CloudseedEnv": "aws-dev", "Owner": "alice"},
                "acme-dev-trail": {"CloudseedEnv": "aws-dev", "Owner": "bob"}}
        tf = FakeTf()
        with mock.patch.object(reconcile.CloudLookups, "tags", lambda self, t, v, ident: tags.get(ident)):
            imported = reconcile.recover(tf, "aws", self.CFG, COLORED, planned)
        self.assertEqual(imported, ["module.stack.aws_iam_role.bastion"])      # bob's bucket is left alone
        self.assertEqual([c[0] for c in tf.calls], ["import"])

    def test_unknown_owner_needs_consent(self):
        planned = {"module.stack.aws_iam_role.bastion": {"type": "aws_iam_role", "values": {"name": "acme-dev-bastion"}}}
        with mock.patch.object(reconcile.CloudLookups, "tags", lambda *a: None), mock.patch.object(ui, "interactive", lambda: False):
            with mock.patch.dict(os.environ, {"CLOUDSEED_ADOPT": ""}):
                self.assertEqual(reconcile.recover(FakeTf(), "aws", self.CFG, COLORED, planned), [])
            with mock.patch.dict(os.environ, {"CLOUDSEED_ADOPT": "1"}):
                self.assertEqual(reconcile.recover(FakeTf(), "aws", self.CFG, COLORED, planned), ["module.stack.aws_iam_role.bastion"])

    def test_uid_tag_is_authoritative(self):
        exp = reconcile.expected_tags("aws", {**self.CFG, "uid": "u1"})
        self.assertEqual(reconcile.ownership({"CloudseedEnvId": "u2", "CloudseedEnv": "aws-dev", "Owner": "alice"}, exp)[0], "other")
        self.assertEqual(reconcile.ownership({"CloudseedEnvId": "u1"}, exp)[0], "mine")
        self.assertEqual(reconcile.ownership({}, exp)[0], "other")
        self.assertEqual(reconcile.ownership(None, exp)[0], "unknown")

    def test_guardduty_is_never_adopted(self):
        planned = {"module.stack.module.security_baseline[0].aws_guardduty_detector.this[0]": {"type": "aws_guardduty_detector", "values": {}}}
        tf = FakeTf()
        from cloudseed.tf import TerraformError
        with mock.patch.object(reconcile.CloudLookups, "aws_guardduty_detector", lambda self: "b2c3d4"):
            with self.assertRaises(TerraformError) as cm:
                reconcile.preflight(tf, "aws", self.CFG, planned)
            self.assertIn("enable_guardduty=false", str(cm.exception))
            self.assertEqual(tf.calls, [])
            out = ("Error: creating GuardDuty Detector: BadRequestException: The request is rejected because a detector already exists\n\n"
                   "  with module.stack.module.security_baseline[0].aws_guardduty_detector.this[0],\n")
            self.assertEqual(reconcile.recover(tf, "aws", self.CFG, out, planned), [])
            self.assertEqual(tf.calls, [])
            # a detector this environment already manages is fine
            self.assertEqual(reconcile.preflight(FakeTf(state=list(planned)), "aws", self.CFG, planned), [])


# ---------------------------------------------------------------------------------------------------- troubleshoot

def _rec(argv, rc, log=None):
    return {"argv": argv, "command": argv[0], "exit_code": rc, "log": log, "at": "2026-01-01T00:00:00Z"}


class TroubleshootFixTests(unittest.TestCase):
    def test_read_only_runs_do_not_settle_a_failure(self):
        fail = _rec(["setup", "aws", "--env", "dev", "--auto-approve"], 1)
        for ok in (["finops", "estimate", "aws", "--env", "dev"], ["vpn", "status", "aws", "--env", "dev"], ["plan", "aws", "--env", "dev"],
                   ["setup", "aws", "--env", "dev", "--dry-run"], ["kubectl", "get", "pods"], ["platform", "install", "keda"]):
            self.assertFalse(troubleshoot._supersedes(_rec(ok, 0), fail), ok)
        self.assertTrue(troubleshoot._supersedes(_rec(["-y", "setup", "aws", "--env", "dev"], 0), fail))
        self.assertTrue(troubleshoot._supersedes(_rec(["apply", "aws", "--env", "dev"], 0), fail))
        pfail = _rec(["platform", "install", "velero", "--cloud", "aws", "--env", "dev"], 1)
        self.assertFalse(troubleshoot._supersedes(_rec(["platform", "install", "gitlab", "--cloud", "aws", "--env", "dev"], 0), pfail))
        self.assertTrue(troubleshoot._supersedes(_rec(["platform", "install", "velero", "keda", "--cloud", "aws", "--env", "dev"], 0), pfail))
        self.assertTrue(troubleshoot._supersedes(_rec(["--runtime", "local", "destroy", "aws", "--env", "dev"], 0), pfail))

    def _scan(self, text):
        log = Path(tempfile.mkdtemp()) / "x.log"
        log.write_text(text)
        return [f.what for f in troubleshoot._scan_log(log, "vmware", "lab")]

    def test_signatures(self):
        hits = self._scan("$ helm upgrade --install x chart --force-conflicts --wait\nError: INSTALLATION FAILED: context deadline exceeded\n")
        self.assertFalse(any("same name already exists" in h for h in hits), hits)
        self.assertTrue(any("cloudseed-lab-cp1" in h for h in self._scan("fatal: [cloudseed-lab-cp1]: FAILED! => {}\n")))
        self.assertTrue(any("provider" in h for h in self._scan(
            "Error: Failed to query available provider packages\n\nCould not retrieve the list of available versions for provider\n"
            "registry.local/cloudseed/vmdesktop: provider registry.local/cloudseed/vmdesktop was not found\n")))
        self.assertFalse(any("crashed" in h for h in self._scan("fatal: [localhost]: FAILED! => ModuleNotFoundError: No module named 'apt_pkg'\n")))
        self.assertTrue(any("crashed" in h for h in self._scan("  ✖ Unexpected error: KeyError: 'vars'\n")))
        self.assertTrue(any("credential helper" in h for h in self._scan('error: exec: "docker-credential-ecr-login": executable file not found\n')))
        self.assertEqual(len([h for h in self._scan("Error: Error acquiring the state lock\n\nLock Info:\n") if "lock" in h]), 1)
        coloured = self._scan("\x1b[31m│\x1b[0m \x1b[1m\x1b[31mError: \x1b[0mInvalidClientTokenId: token invalid\n")
        self.assertTrue(any("AWS credentials" in h for h in coloured))

    def test_last_must_be_positive(self):
        env = paths.Env("aws", "tsfix")
        env.create_dirs()
        for bad in (0, -2):
            with self.assertRaises(ui.Abort) as cm, mock.patch("sys.stderr", io.StringIO()):
                troubleshoot.run(clouds.get("aws"), env, {"vars": {}}, last=bad)
            self.assertEqual(cm.exception.code, 2)

    def test_run_reports_the_failure_after_read_only_runs(self):
        env = paths.Env("aws", "tsfix")
        env.create_dirs()
        log = env.dir / "logs" / "20260101-000000-setup.log"
        log.write_text("Error: creating EC2 Instance: VcpuLimitExceeded: You have requested more vCPU capacity\n")
        runs = [_rec(["setup", "aws", "--env", "tsfix"], 1, str(log)), _rec(["finops", "estimate", "aws", "--env", "tsfix"], 0)]
        (env.dir / "logs" / "audit.jsonl").write_text("".join(json.dumps(r) + "\n" for r in runs))
        buf = io.StringIO()
        with mock.patch.object(deps, "missing", lambda c: ([], [])), mock.patch.object(deps, "live_credential_check", lambda c: None), \
                mock.patch("sys.stdout", buf):
            troubleshoot.run(clouds.get("aws"), env, {"vars": {}}, last=10)
        self.assertIn("quota", buf.getvalue())


# ---------------------------------------------------------------------------------------------------- scripts & images

class ScriptTests(unittest.TestCase):
    def test_bundle_carries_every_data_dir_and_stages_clean_copies(self):
        text = (REPO / "scripts" / "build-bundle.sh").read_text()
        import re
        dests = set(re.findall(r'--add-data "[^"]*:([^"]+)"', text))
        self.assertTrue({"terraform", "skills", "ansible", "providers", "templates", "assets", "cloudseed/web", "tfbin"} <= dests, dests)
        self.assertNotIn('--add-data "$ROOT/terraform:terraform"', text)
        self.assertIn('".terraform"', text)
        self.assertEqual(subprocess.run(["bash", "-n", str(REPO / "scripts" / "build-bundle.sh")]).returncode, 0)

    def _install(self, target, *args):
        return subprocess.run(["bash", str(REPO / "scripts" / "install.sh"), str(target), *args], capture_output=True, text=True,
                              env=dict(os.environ, PATH=f"{target}:{os.environ.get('PATH', '')}"))

    def test_install_never_replaces_another_cs(self):
        target = Path(tempfile.mkdtemp())
        other = target / "cs"
        other.write_text("#!/bin/sh\necho I am coursier\n")
        other.chmod(0o755)
        r = self._install(target)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(other.read_text(), "#!/bin/sh\necho I am coursier\n")
        self.assertTrue((target / "cloudseed").is_symlink())
        self.assertIn("not replacing", r.stdout)
        r = self._install(target, "--alias", "cls")
        self.assertTrue((target / "cls").is_symlink())
        r = self._install(target, "--force")
        self.assertTrue((target / "cs").is_symlink())
        self.assertTrue(list(target.glob("cs.bak.*")))
        r = self._install(target, "--uninstall")
        self.assertFalse((target / "cloudseed").exists() or (target / "cs").is_symlink())
        self.assertTrue(list(target.glob("cs.bak.*")))            # the moved-aside file is the user's: kept

    def test_install_refuses_to_replace_an_unrelated_cloudseed(self):
        target = Path(tempfile.mkdtemp())
        (target / "cloudseed").write_text("other")
        r = self._install(target)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual((target / "cloudseed").read_text(), "other")

    @unittest.skipUnless(shutil.which("make"), "make not installed")
    def test_make_validate_uses_cloudseed_home(self):
        home = tempfile.mkdtemp()
        r = subprocess.run(["make", "-n", "validate"], cwd=REPO, capture_output=True, text=True, env=dict(os.environ, CLOUDSEED_HOME=home))
        self.assertIn(f'TF_CLI_CONFIG_FILE="{home}/terraform.rc"', r.stdout)

    @unittest.skipUnless(shutil.which("make"), "make not installed")
    def test_make_clean_keeps_tracked_lock_files(self):
        r = subprocess.run(["make", "-n", "clean"], cwd=REPO, capture_output=True, text=True)
        self.assertIn("terraform/*/.terraform", r.stdout)
        self.assertNotIn("lock.hcl", r.stdout)

    def test_dockerfile_and_dockerignore(self):
        df = (REPO / "Dockerfile").read_text()
        self.assertRegex(df, r"FROM python:[\w.-]+@sha256:[0-9a-f]{64}")
        for needle in ("/usr/local/bin/kubectl", "/usr/local/bin/helm", "sha256sum -c", "pipefail", "VALIDSIG"):
            self.assertIn(needle, df)
        code = "\n".join(line for line in df.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("| bash", code)
        ignore = (REPO / ".dockerignore").read_text().split()
        for entry in (".env", "**/.DS_Store", ".venv/", "*.spec", "**/.terraform/"):
            self.assertIn(entry, ignore)


if __name__ == "__main__":
    unittest.main()
