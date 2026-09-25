"""Wave-4 regression tests for the web console backend (cloudseed/webui.py): the changes other groups needed in it.

Stdlib only, no network, no cloud, no launchd/systemd (launchctl/systemctl and background processes are stubbed), no
listening sockets."""
import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import agents, audit, clouds, creds, deps, mcp, paths, undo, webui  # noqa: E402
from cloudseed.clouds.base import Question  # noqa: E402

GUID = "0000aaaa-0000-0000-0000-000000000000"


class Isolated(unittest.TestCase):
    """Every file the console touches lives in a fresh temp dir for each test."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w4-webui-"))
        ui_dir = self.tmp / "ui"
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.patches = [
            mock.patch.object(webui, "UI_DIR", ui_dir), mock.patch.object(webui, "JOBS_DIR", ui_dir / "jobs"),
            mock.patch.object(webui, "TOKEN_PATH", ui_dir / "token"), mock.patch.object(webui, "STATE_PATH", ui_dir / "server.json"),
            mock.patch.object(webui, "LOG_PATH", ui_dir / "server.log"), mock.patch.object(webui, "PID_PATH", ui_dir / "server.pid"),
            mock.patch.object(paths, "ENVS_DIR", self.tmp / "envs"), mock.patch.object(paths, "WORKDIRS_INDEX", self.tmp / "workdirs.json"),
            mock.patch.object(paths, "SETTINGS_PATH", self.tmp / "settings.json"), mock.patch.object(undo, "JOURNAL", self.tmp / "undo.json"),
            mock.patch.object(undo, "LOCK", self.tmp / "undo.lock"), mock.patch.object(undo, "BACKUPS", self.tmp / "undo"),
            mock.patch.object(creds, "GCP_FILE", self.tmp / "gcp-credentials.json"),
            mock.patch.object(paths, "HOME", self.tmp / "cs"), mock.patch.object(paths, "BIN_DIR", self.tmp / "cs" / "bin"),
            mock.patch.object(creds, "STORE", self.tmp / "credentials.json"), mock.patch.object(agents, "AGENTS_FILE", self.tmp / "agents.json"),
            mock.patch.dict(webui.JOBS, clear=True), mock.patch.dict(creds.APPLIED, clear=True), mock.patch.dict(os.environ),
            mock.patch.dict(webui._DEFAULTS, clear=True),
        ]
        for p in self.patches:
            p.start()
        for k in (webui.MANAGED_ENV, "CLOUDSEED_UI_FORCE", "XPC_SERVICE_NAME", "ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID",
                  "ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_USE_MSI", "ARM_USE_CLI", "ARM_USE_OIDC", "ARM_USE_AKS_WORKLOAD_IDENTITY",
                  "GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT", "CLOUDSDK_COMPUTE_ZONE"):
            os.environ.pop(k, None)
        (self.tmp / "envs").mkdir()
        (self.tmp / "cs" / "bin").mkdir(parents=True)
        webui._State.token, webui._State.token_sig = None, None

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_env(self, cloud="aws", name="dev", outputs=None) -> Path:
        d = self.tmp / "envs" / f"{cloud}-{name}"
        d.mkdir(parents=True)
        (d / "config.json").write_text(json.dumps({"cloud": cloud, "env": name, "name": "cs", "region": "r1", "vars": {}, "state": {"type": "local"}}))
        if outputs is not None:
            (d / "outputs.json").write_text(json.dumps(outputs))
        return d

    def env(self, env_id):
        return {e.id: e for e in paths.Env.list_all()}[env_id]

    def catalog(self, vault=None):
        from cloudseed import ui
        with mock.patch.object(creds, "load", return_value=dict(vault or {})), mock.patch.object(deps, "find", return_value=None), \
                mock.patch.object(ui, "warn"):     # Azure's own "ARM_SUBSCRIPTION_ID is not a GUID" warning (the console log)
            cat = webui.clouds_catalog()
        return cat, {c: {q["key"]: q for q in cat[c]["questions"]} for c in cat}


# ---------------------------------------------------------------- forms (a2-mcp#15, a2-cli-ux#19, agentic, web)

class FormTests(Isolated):
    def test_mcp_connect_and_disconnect_need_the_clients(self):
        for act in ("connect", "disconnect"):
            for args in ({"action": act}, {"action": act, "clients": []}):
                with self.assertRaises(ValueError) as cm:             # never `mcp disconnect -y` = every known client
                    webui.build_argv("cloudseed_mcp", args)
                self.assertIn("clients", str(cm.exception))
            self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": act, "clients": ["claude-code"]}), ["mcp", act, "claude-code", "-y"])
            self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": act, "clients": ["all"]}), ["mcp", act, "all", "-y"])
        self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": "setup", "confirm": True}), ["mcp", "setup", "--client", "none", "-y"])
        self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": "setup", "clients": ["codex"], "port": 7581, "confirm": True}),
                         ["mcp", "setup", "codex", "--port", "7581", "-y"])
        self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": "uninstall", "confirm": True}), ["mcp", "uninstall", "--auto-approve", "-y"])
        self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": "status"}), ["mcp", "status", "-y"])

    def test_grok_is_not_offered_for_skill_installs(self):
        self.assertNotIn("grok", webui.UI_ACTIONS["cloudseed_skill"]["schema"]["properties"]["agent"]["enum"])
        self.assertNotIn("grok", webui.registry()["cloudseed_skill"]["schema"]["properties"]["agent"]["enum"])
        with self.assertRaises(ValueError):
            webui.build_argv("cloudseed_skill", {"action": "install", "agent": "grok"})
        self.assertIn("grok", webui.registry()["cloudseed_use"]["schema"]["properties"]["agent"]["enum"])   # still an agent

    def test_field_hints_for_every_client_without_changing_the_registry(self):
        cat = {a["name"]: a for a in webui.actions_catalog()}
        self.assertIs(cat["cloudseed_platform"]["schema"]["properties"]["set"].get("x-lines"), True)
        self.assertEqual(cat["cloudseed_platform"]["schema"]["properties"]["set"]["title"], "Set")
        self.assertIs(cat["cloudseed_agentic"]["schema"]["properties"]["task"].get("multiline"), True)
        self.assertNotIn("x-lines", mcp.TOOLS["cloudseed_platform"]["schema"]["properties"]["set"])        # the shared definition
        self.assertNotIn("title", mcp.TOOLS["cloudseed_platform"]["schema"]["properties"]["set"])
        argv = webui.build_argv("cloudseed_platform", {"action": "install", "items": ["minio"], "set": ["a=b", "hosts={x,y}"], "confirm": True})
        i = argv.index("--set")
        self.assertEqual(argv[i:i + 4], ["--set", "a=b", "--set", "hosts={x,y}"])    # a list value stays one value

    def test_cloud_scan_of_a_local_environment_installs_nothing(self):
        self.assertFalse(webui._scan_mutating({"kind": "cloud", "cloud": "vmware"}))
        self.assertTrue(webui._scan_mutating({"kind": "cloud", "cloud": "aws"}))       # prowler is not installed here
        self.assertTrue(webui._scan_mutating({"kind": "cloud"}))                        # the current env may be a cloud one
        venv = paths.HOME / "venv-prowler" / "bin"
        venv.mkdir(parents=True)
        (venv / "prowler").write_text("")
        self.assertFalse(webui._scan_mutating({"kind": "cloud", "cloud": "aws"}))

    def test_one_definition_of_the_mutating_commands(self):
        self.assertIs(webui._MUTATING, audit.MUTATING)
        self.assertIs(webui._SUB_MUTATING, audit.SUB_MUTATING)
        self.make_env("aws", "dev")
        self.assertEqual(webui.env_key(["node", "scale", "aws", "--env", "dev"]), "aws-dev")
        self.assertIsNone(webui.env_key(["platform", "status", "aws"]))


# ---------------------------------------------------------------- jobs (web: interrupted; ops: auth scrubbed from logs)

class JobTests(Isolated):
    def job(self, jid="20260101-000000-abcd"):
        webui._jobs_dir()
        return webui.Job(jid, ["apply", "aws", "--env", "dev"], "apply")

    def test_interrupted_is_reported_and_survives_a_restart(self):
        job = self.job()
        self.assertIs(job.to_dict(tail=0)["interrupted"], False)
        job.cancels, job.killed, job.pid = 3, True, 999999
        job.log_path.write_text("working\n")
        job.save_meta()
        self.assertIs(json.loads(job.meta_path.read_text())["interrupted"], True)
        with mock.patch.dict(webui.JOBS, clear=True), mock.patch.object(webui, "_scrub_finished"):
            webui._restore_jobs()                                        # a console restarted after the third interrupt killed it
            back = webui.JOBS[job.id].to_dict(tail=0)
        self.assertEqual((back["rc"], back["lost"], back["interrupted"], back["interrupts"]), (137, False, True, 3))

    def test_rewritten_logs_keep_no_authorization_headers(self):
        job = self.job("20260101-000001-abcd")
        header = "curl -H 'Authorization: Bearer " + "abcdefghijklmnopqrstu12345' https://api.example.test"
        job.log_path.write_text(header + "\nplain line\n")
        self.assertTrue(webui._scrub_log(job))
        text = job.log_path.read_text()
        self.assertNotIn("abcdefghijklmnopqrstu12345", text)
        self.assertIn("plain line", text)
        self.assertIn("Authorization: Bearer", text)
        self.assertTrue(job.scrubbed)


# ---------------------------------------------------------------- toolchain rows (web: az needed without ARM_* credentials)

class ToolRowTests(Isolated):
    ROWS = [{"tool": "terraform", "path": "/bin/terraform", "required": True, "desc": "t"},
            {"tool": "az", "path": None, "required": False, "desc": "Azure CLI"},
            {"tool": "kubectl", "path": None, "required": False, "desc": "k"}]

    def rows(self, cloud="azure", environ=None):
        with mock.patch.object(deps, "status", return_value=[dict(r) for r in self.ROWS]):
            return {r["tool"]: r for r in webui._tool_rows(cloud, dict(environ or {}))}

    def test_az_is_needed_unless_arm_variables_sign_in(self):
        rows = self.rows()
        self.assertTrue(rows["az"]["needed"])
        self.assertIn("ARM_", rows["az"]["need_note"])
        self.assertFalse(rows["az"]["ok"])
        self.assertTrue(rows["terraform"]["needed"])                                   # required
        self.assertFalse(rows["kubectl"]["needed"])
        self.assertNotIn("need_note", rows["kubectl"])
        for env in ({"ARM_CLIENT_ID": "c", "ARM_CLIENT_SECRET": "s"}, {"ARM_USE_MSI": "true"}, {"ARM_USE_CLI": "false"}):
            self.assertFalse(self.rows(environ=env)["az"]["needed"], env)
        self.assertTrue(self.rows(environ={"ARM_USE_MSI": "false"})["az"]["needed"])   # read as Terraform reads it
        self.assertFalse(self.rows("aws")["az"]["needed"])                             # only Azure signs in through its CLI

    def test_the_vault_counts_like_in_a_job(self):
        creds.save({"ARM_CLIENT_ID": "c", "ARM_CLIENT_SECRET": "s"})
        env = webui._job_environ()
        self.assertEqual((env.get("ARM_CLIENT_ID"), env.get("ARM_CLIENT_SECRET")), ("c", "s"))
        os.environ["ARM_CLIENT_ID"] = "from-shell"
        self.assertEqual(webui._job_environ()["ARM_CLIENT_ID"], "from-shell")          # the shell wins, as in a job
        with mock.patch.object(deps, "status", return_value=[dict(r) for r in self.ROWS]):
            self.assertFalse({r["tool"]: r for r in webui.state()["tools"]["azure"]}["az"]["needed"])


# ---------------------------------------------------------------- DR verdicts and reports (a2-resilience#7)

class DrTests(Isolated):
    def write(self, name, data):
        d = self.tmp / "envs" / "aws-dev" / "dr"
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(json.dumps(data))

    STEPS = [{"step": "1. create sample workload", "ok": True, "seconds": 10}, {"step": "2. backup", "ok": True, "seconds": 20.5},
             {"step": "3. delete it (disaster)", "ok": True, "seconds": 7}, {"step": "4. restore from backup", "ok": True, "seconds": 30},
             {"step": "5. verify", "ok": False, "seconds": 4.5}]

    def test_a_failed_drill_has_no_rto(self):
        self.make_env("aws", "dev")
        self.write("drill-20260101-000000.json", {"run": "r1", "verdict": "FAIL", "rto_s": None, "total_s": 72, "steps": self.STEPS})
        v = webui.verdicts(self.env("aws-dev"))["dr"]
        self.assertEqual((v["verdict"], v["detail"]), ("FAIL", "RTO not measured (failed at 5. verify)"))
        row = webui.reports("aws-dev")["dr"][0]
        self.assertNotIn("rto_s", row)
        self.assertEqual(row["summary"], {"RTO": "not measured", "total": "72s", "steps": "4/5 ok"})   # never 34.5s from the steps

    def test_an_old_failed_report_with_a_number_is_not_believed(self):
        self.make_env("aws", "dev")
        self.write("drill-20260101-000000.json", {"run": "r1", "verdict": "FAIL", "rto_s": 34.5, "steps": self.STEPS})
        self.assertNotIn("34.5", webui.verdicts(self.env("aws-dev"))["dr"]["detail"])
        row = webui.reports("aws-dev")["dr"][0]
        self.assertNotIn("rto_s", row)
        self.assertEqual(row["summary"]["RTO"], "not measured")

    def test_an_interrupted_drill(self):
        self.make_env("aws", "dev")
        steps = self.STEPS[:2] + [{"step": "interrupted", "ok": False, "seconds": 0, "detail": "Ctrl-C"}]
        self.write("drill-20260101-000000.json", {"run": "r1", "verdict": "INTERRUPTED", "rto_s": None, "total_s": 30.5, "steps": steps})
        self.assertEqual(webui.verdicts(self.env("aws-dev"))["dr"]["detail"], "RTO not measured (interrupted)")
        self.assertEqual(webui.reports("aws-dev")["dr"][0]["summary"], {"RTO": "not measured", "total": "30.5s", "steps": "2/3 ok"})

    def test_a_passed_drill_keeps_its_rto(self):
        self.make_env("aws", "dev")
        steps = [dict(s, ok=True) for s in self.STEPS]
        self.write("drill-20260101-000000.json", {"run": "r1", "verdict": "PASS", "rto_s": 34.5, "total_s": 72, "steps": steps})
        self.assertEqual(webui.verdicts(self.env("aws-dev"))["dr"]["detail"], "RTO 34.5s")
        row = webui.reports("aws-dev")["dr"][0]
        self.assertEqual((row["rto_s"], row["total_s"]), (34.5, 72))
        self.assertEqual(row["summary"], {"RTO": "34.5s", "total": "72s", "steps": "5/5 ok"})


# ---------------------------------------------------------------- platform catalog (a2-platform-catalog#16, #2)

class PlatformCatalogTests(Isolated):
    def test_needs_by_target_and_arch_are_exported(self):
        from cloudseed import platform as pl
        items = {i["name"]: i for i in webui.platform_catalog()["items"]}
        for name, spec in pl.CATALOG.items():
            if spec.get("hidden"):
                continue
            self.assertEqual(items[name]["needs_by_target"], {k: list(v) for k, v in (spec.get("needs_by_target") or {}).items()}, name)
            self.assertEqual(items[name]["arch"], list(spec.get("arch") or []), name)
        self.assertTrue(any(i["arch"] for i in items.values()))
        self.assertIn("vmware", items["velero"]["needs_by_target"])
        json.dumps(items)


# ---------------------------------------------------------------- the setup wizard's questions (core, vmware, azure, aws, gcp#16)

class WizardCatalogTests(Isolated):
    def test_an_invalid_subscription_variable_is_not_offered_as_the_answer(self):
        os.environ["ARM_SUBSCRIPTION_ID"] = "not-a-guid-my-secret"
        cat, q = self.catalog()
        sub = q["azure"]["subscription_id"]
        self.assertEqual(sub["from_env"], [])                               # the CLI ignores it: no "blank = $ARM_SUBSCRIPTION_ID"
        self.assertEqual(sub["invalid_env"], ["ARM_SUBSCRIPTION_ID"])
        self.assertEqual(sub["ignored_env"][0]["name"], "ARM_SUBSCRIPTION_ID")
        self.assertIn("$ARM_SUBSCRIPTION_ID is not an Azure subscription ID", sub["ignored_env"][0]["problem"])
        self.assertNotIn("not-a-guid-my-secret", json.dumps(cat))            # names only, never values
        _cat, q = self.catalog({"AZURE_SUBSCRIPTION_ID": GUID})                # the next variable holds one: the CLI uses it
        self.assertEqual(q["azure"]["subscription_id"]["from_env"], ["AZURE_SUBSCRIPTION_ID"])
        self.assertEqual(q["azure"]["subscription_id"]["invalid_env"], ["ARM_SUBSCRIPTION_ID"])
        os.environ["ARM_SUBSCRIPTION_ID"] = GUID
        _cat, q = self.catalog()
        self.assertEqual(q["azure"]["subscription_id"]["from_env"], ["ARM_SUBSCRIPTION_ID"])
        self.assertNotIn("ignored_env", q["azure"]["subscription_id"])

    def test_an_invalid_project_variable_says_why(self):
        _cat, q = self.catalog({"GOOGLE_PROJECT": "Bad_Project!"})
        row = q["gcp"]["project_id"]
        self.assertEqual(row["from_env"], [])
        self.assertIn("$GOOGLE_PROJECT", row["ignored_env"][0]["problem"])
        self.assertNotIn("Bad_Project", json.dumps(row))

    def test_patterns_and_reserved_names_for_the_page(self):
        _cat, q = self.catalog()
        from cloudseed.clouds import azure
        sub = q["azure"]["subscription_id"]
        self.assertEqual(sub["pattern"], azure.Azure.answer_patterns["subscription_id"][0])
        self.assertIn("GUID", sub["pattern_hint"])
        self.assertIn("admin", q["azure"]["admin_username"]["reserved"])
        self.assertEqual(sorted(q["azure"]["admin_username"]["reserved"]), sorted(azure.RESERVED_ADMIN_NAMES))
        self.assertNotIn("pattern", q["aws"]["profile"])
        self.assertEqual(q["aws"]["enable_regional_baseline"]["follows"], "enable_account_baseline")
        self.assertNotIn("follows", q["aws"]["enable_account_baseline"])

    def test_number_fields_carry_the_range_setup_accepts(self):
        _cat, q = self.catalog()
        vm = q["vmware"]
        self.assertEqual((vm["bastion_memory_mb"]["minimum"], vm["bastion_disk_gb"]["minimum"], vm["kubernetes_disk_gb"]["minimum"],
                          vm["workload_cpus"]["minimum"]), (512, 10, 20, 1))
        self.assertEqual(vm["workload_count"].get("minimum", 0), 0)        # 0 workload VMs is a valid answer (declared: 0)
        self.assertEqual(vm["kubernetes_workers"].get("minimum", 0), 0)
        self.assertEqual((vm["kubernetes_control_planes"]["minimum"], vm["kubernetes_control_planes"]["maximum"]), (1, 20))
        self.assertEqual(q["aws"]["az_count"]["maximum"], 5)
        self.assertEqual(q["aws"]["az_count"]["minimum"], 1)
        self.assertNotIn("minimum", q["aws"]["profile"])                    # not a number
        c = clouds.get("vmware")
        for key, row in vm.items():                                           # the bound never refuses what setup accepts
            if "minimum" in row:
                qq = c.question(key)
                self.assertIsNone(qq.problem(row["minimum"]), key)
                self.assertIsNotNone(qq.problem(row["minimum"] - 1), key)

    def test_declared_bounds_win(self):
        q = Question("n", "How many", 3, kind="int", minimum=2, maximum=7)
        with mock.patch.object(clouds.get("aws"), "questions", [q]):
            _cat, rows = self.catalog()
        self.assertEqual((rows["aws"]["n"]["minimum"], rows["aws"]["n"]["maximum"]), (2, 7))
        self.assertIsNone(webui._int_minimum(Question("m", "free", 0, kind="int")))
        self.assertEqual(webui._int_minimum(Question("z", "zero is fine", 0, kind="int", minimum=0)), 0)

    def test_a_validator_stricter_than_the_declared_minimum_wins(self):
        # an adapter declaring minimum=1 on a question whose validator wants 512: the page must not offer 1..511
        mem = Question("mem", "Memory (MB)", 2048, kind="int", minimum=1,
                       validate=lambda v: None if int(v) >= 512 and int(v) % 4 == 0 else "at least 512, a multiple of 4")
        self.assertEqual(webui._int_minimum(mem), 512)
        broken = Question("b", "Breaks", 1, kind="int", minimum=3, validate=lambda v: 1 / 0)
        self.assertEqual(webui._int_minimum(broken), 3)                     # a validator that raises: the declared bound

    def test_problem_messages_never_carry_the_value(self):
        self.assertEqual(webui._without_value("'abc12345' is not valid", "X", "abc12345"), "$X is not valid")
        self.assertEqual(webui._without_value("got abc12345 here", "X", "abc12345"), "got $X here")
        self.assertEqual(webui._without_value("must be >= 1, got 0", "X", "0"), "must be >= 1, got 0")   # too short to matter
        # a value that is part of the variable's name is not replaced inside the name that stands for it
        self.assertEqual(webui._without_value("'SUBSCRIPTION' is not a GUID", "ARM_SUBSCRIPTION_ID", "SUBSCRIPTION"),
                         "$ARM_SUBSCRIPTION_ID is not a GUID")


# ---------------------------------------------------------------- credentials (a2-agentic#1)

class CredsTests(Isolated):
    def test_a_google_key_must_be_a_whole_key_file(self):
        for bad in ("{", '{"project_id": "p"}', "/path/to/key.json", '["type"]'):
            with self.assertRaises(ValueError) as cm:
                webui.change_creds({"set": {"GOOGLE_CREDENTIALS": bad, "AWS_PROFILE": "prod"}})
            self.assertIn("Nothing was changed", str(cm.exception))
            self.assertEqual(creds.load(), {})                              # all or nothing: AWS_PROFILE is not stored either
        key = json.dumps({"type": "service_account", "project_id": "p"})
        out = webui.change_creds({"set": {"GOOGLE_CREDENTIALS": key}})
        self.assertEqual(out["changed"], ["GOOGLE_CREDENTIALS"])
        self.assertEqual(json.loads(creds.load()["GOOGLE_CREDENTIALS"])["type"], "service_account")


# ---------------------------------------------------------------- MCP guide (web: one Copy per client and transport)

class McpGuideTests(Isolated):
    def test_variants_come_with_the_joined_configs(self):
        g = webui.mcp_guide()
        self.assertTrue(g["sections"])
        self.assertTrue(g["variants"])
        names = {b["display"] for b in g["variants"]}
        self.assertEqual(names, {c["display"] for c in mcp.CLIENTS.values()})
        for b in g["variants"]:
            self.assertTrue(all(isinstance(v, list) and len(v) == 2 for v in b["variants"]), b)
        self.assertTrue(g["configs"])
        json.dumps(g)


# ---------------------------------------------------------------- serve and start (a2-webui-backend#11, #12, a2-mcp#10)

class ServeTests(Isolated):
    def serve(self, *a):
        with mock.patch("sys.stderr") as err:
            rc = webui.serve(*a)
        return rc, "".join(str(c.args[0]) for c in err.write.call_args_list)

    def test_ports_that_are_no_tcp_port_are_refused_readably(self):
        paths.save_settings({"ui": True})
        for port in (70000, 0, -5):
            rc, said = self.serve("127.0.0.1", port)
            self.assertEqual(rc, 2, port)
            self.assertIn(f"Invalid port {port}", said)
            self.assertIn("1-65535", said)
        webui.save_state({"host": "127.0.0.1", "port": 99999})                # a hand-edited server.json
        rc, said = self.serve()
        self.assertEqual(rc, 2)
        self.assertIn("Invalid port 99999", said)

    def test_a_bind_error_is_a_message_not_a_crash(self):
        paths.save_settings({"ui": True})
        for exc in (OverflowError("bind(): port must be 0-65535."), OSError(48, "Address already in use")):
            with mock.patch.object(webui, "_Server", side_effect=exc):
                rc, said = self.serve("127.0.0.1", 7589)
            self.assertEqual(rc, 1)
            self.assertIn("Cannot listen on 127.0.0.1:7589", said)


class StartTests(Isolated):
    failing: tuple = ()      # command prefixes the fake launchctl / systemctl refuses

    def stub(self):
        self.cmds = []

        def fake_run(cmd, **kw):
            self.cmds.append(list(cmd))
            bad = any(list(cmd[:len(f)]) == list(f) for f in self.failing)
            return subprocess.CompletedProcess(cmd, 1 if bad else 0, "", "Failed to connect to bus" if bad else "")

        class FakeProc:
            pid = 999999

            def poll(self):
                return 0
        self.spawned = []

        def fake_popen(argv, **kw):
            self.spawned.append(argv)
            return FakeProc()
        return [mock.patch.object(Path, "home", return_value=self.home), mock.patch.object(webui.subprocess, "run", side_effect=fake_run),
                mock.patch.object(webui.subprocess, "Popen", side_effect=fake_popen), mock.patch.object(webui, "health", return_value=False),
                mock.patch.object(webui, "_wait_started", return_value=False),     # nothing really starts here
                mock.patch.object(webui.os, "getuid", return_value=501, create=True), mock.patch.object(webui.ui, "warn")]

    def run_start(self, s):
        ps = self.stub()
        for p in ps:
            p.start()
        try:
            kind = webui.start(s)
            warned = " ".join(str(c.args[0]) for c in webui.ui.warn.call_args_list)
        finally:
            for p in reversed(ps):
                p.stop()
        return kind, warned

    def test_an_unwritable_launch_agents_folder_starts_a_background_console(self):
        (self.home / "Library").mkdir()
        (self.home / "Library" / "LaunchAgents").write_text("not a folder")
        kind, warned = self.run_start({"host": "127.0.0.1", "port": 7590, "service": "launchd"})
        self.assertEqual(kind, "background")
        self.assertIn("cannot write", warned)
        self.assertIn("background process", warned)
        self.assertEqual(len(self.spawned), 1)
        self.assertFalse(any(c[:2] == ["launchctl", "bootstrap"] for c in self.cmds))
        st = webui.load_state()
        self.assertEqual((st["service"], st["started_as"]), ("launchd", "background"))   # the next start tries the login item again

    def test_an_unwritable_systemd_folder_starts_a_background_console(self):
        (self.home / ".config").mkdir()
        (self.home / ".config" / "systemd").write_text("not a folder")
        kind, warned = self.run_start({"host": "127.0.0.1", "port": 7591, "service": "systemd"})
        self.assertEqual(kind, "background")
        self.assertIn("cannot write", warned)
        self.assertFalse(any(c[:3] == ["systemctl", "--user", "enable"] for c in self.cmds))
        self.assertEqual(webui.load_state()["service"], "systemd")

    def test_a_written_login_item_is_complete_and_leaves_no_temp_file(self):
        kind, _warned = self.run_start({"host": "127.0.0.1", "port": 7592, "service": "launchd"})
        self.assertEqual(kind, "launchd")
        folder = self.home / "Library" / "LaunchAgents"
        with open(folder / f"{webui.LAUNCHD_LABEL}.plist", "rb") as fh:
            self.assertEqual(plistlib.load(fh)["Label"], webui.LAUNCHD_LABEL)
        self.assertEqual([p.name for p in folder.iterdir()], [f"{webui.LAUNCHD_LABEL}.plist"])
        self.assertEqual(webui.load_state()["started_as"], "launchd")
        with mock.patch.object(Path, "home", return_value=self.home):
            self.assertEqual(webui.login_item(), "launchd")

    @unittest.skipIf(webui.LAUNCHD_LABEL == webui.LEGACY_LAUNCHD_LABEL, "the default home has no older shared-name item")
    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes into a read-only folder")
    def test_a_read_only_folder_holding_this_homes_old_item_starts_a_background_console(self):
        # the shared-name plist an older version installed for this home cannot be deleted: a warning, not a crash
        folder = self.home / "Library" / "LaunchAgents"
        folder.mkdir(parents=True)
        old = folder / f"{webui.LEGACY_LAUNCHD_LABEL}.plist"
        with open(old, "wb") as fh:
            plistlib.dump({"Label": webui.LEGACY_LAUNCHD_LABEL, "ProgramArguments": ["cloudseed", "ui", "serve"],
                           "EnvironmentVariables": {"CLOUDSEED_HOME": str(paths.HOME)}}, fh)
        folder.chmod(0o555)
        try:
            kind, warned = self.run_start({"host": "127.0.0.1", "port": 7594, "service": "launchd"})
        finally:
            folder.chmod(0o755)
        self.assertEqual(kind, "background")
        self.assertIn("cannot remove the old login item", warned)
        self.assertIn("cannot write", warned)
        self.assertTrue(old.exists())
        self.assertIn(["launchctl", "bootout", f"gui/501/{webui.LEGACY_LAUNCHD_LABEL}"], self.cmds)
        self.assertFalse(any(c[:2] == ["launchctl", "bootstrap"] for c in self.cmds))
        self.assertEqual(len(self.spawned), 1)
        self.assertEqual([p.name for p in folder.iterdir()], [old.name])            # no temp file either

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root writes into a read-only folder")
    def test_a_plist_that_cannot_be_rewritten_is_said_to_start_at_login(self):
        # launchd loads the plist already there at the next login: the warning must not claim nothing starts then
        folder = self.home / "Library" / "LaunchAgents"
        folder.mkdir(parents=True)
        mine = folder / f"{webui.LAUNCHD_LABEL}.plist"
        with open(mine, "wb") as fh:
            plistlib.dump({"Label": webui.LAUNCHD_LABEL, "ProgramArguments": ["cloudseed", "ui", "serve", "--port", "7000"],
                           "EnvironmentVariables": {"CLOUDSEED_HOME": str(paths.HOME)}}, fh)
        folder.chmod(0o555)
        try:
            kind, warned = self.run_start({"host": "127.0.0.1", "port": 7596, "service": "launchd"})
        finally:
            folder.chmod(0o755)
        self.assertEqual(kind, "background")
        self.assertIn("keeps its old settings and still starts the console at login", warned)
        self.assertNotIn("does not start again at login", warned)
        self.assertIn(["launchctl", "bootout", f"gui/501/{webui.LAUNCHD_LABEL}"], self.cmds)   # not a second console now

    def test_a_unit_systemd_never_loaded_is_not_left_behind(self):
        # WSL / a container / an SSH session without a user bus: nothing was enabled, so no file may claim a login item
        self.failing = (["systemctl", "--user", "daemon-reload"],)
        kind, warned = self.run_start({"host": "127.0.0.1", "port": 7597, "service": "systemd"})
        self.assertEqual(kind, "background")
        self.assertIn("systemd --user is not usable here", warned)
        unit = self.home / ".config" / "systemd" / "user" / f"{webui.SYSTEMD_UNIT}.service"
        self.assertFalse(unit.exists())
        with mock.patch.object(Path, "home", return_value=self.home):
            self.assertIsNone(webui.login_item())
        self.assertEqual(len(self.spawned), 1)
        self.assertEqual(webui.load_state()["service"], "systemd")          # still the preference: tried again next time

    def test_a_unit_that_was_there_before_is_kept_when_systemd_is_unreachable(self):
        unit = self.home / ".config" / "systemd" / "user" / f"{webui.SYSTEMD_UNIT}.service"
        unit.parent.mkdir(parents=True)
        unit.write_text(f"[Service]\nEnvironment=\"CLOUDSEED_HOME={paths.HOME}\"\n")   # enabled from a desktop session
        self.failing = (["systemctl", "--user", "daemon-reload"],)
        kind, _warned = self.run_start({"host": "127.0.0.1", "port": 7598, "service": "systemd"})
        self.assertEqual(kind, "background")
        self.assertTrue(unit.exists())

    def test_a_file_where_the_folder_should_be_is_named_so(self):
        (self.home / "Library").mkdir()
        (self.home / "Library" / "LaunchAgents").write_text("not a folder")
        _kind, warned = self.run_start({"host": "127.0.0.1", "port": 7595, "service": "launchd"})
        self.assertIn("a file is in the way where a folder should be", warned)
        self.assertNotIn("File exists", warned)

    def test_an_explicit_background_preference_is_kept(self):
        kind, _warned = self.run_start({"host": "127.0.0.1", "port": 7593, "service": "background"})
        self.assertEqual(kind, "background")
        self.assertEqual(webui.load_state()["service"], "background")


# ---------------------------------------------------------------- per-home service names (a2-mcp#18, a2-webui-backend#8)

class HomeTests(Isolated):
    def plist(self, label, env):
        p = self.home / "Library" / "LaunchAgents" / f"{label}.plist"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as fh:
            plistlib.dump({"Label": label, "ProgramArguments": ["cloudseed", "ui", "serve"], "EnvironmentVariables": env}, fh)
        return p

    def test_the_default_home_is_the_os_users_not_this_processes_home(self):
        with mock.patch.object(Path, "home", return_value=self.home), mock.patch.object(paths, "HOME", self.home / ".cloudseed"):
            self.assertFalse(webui._default_home())          # a sandbox HOME shares the per-user launchd domain: its own label
        with mock.patch.object(paths, "HOME", mcp._default_home()):
            self.assertTrue(webui._default_home())

    def test_a_definitions_home_is_decided_like_the_mcp_servers(self):
        with mock.patch.object(Path, "home", return_value=self.home):
            mine = self.plist("a", {"CLOUDSEED_HOME": str(paths.HOME)})
            by_home = self.plist("b", {"HOME": str(self.tmp / "other")})
            with mock.patch.object(paths, "HOME", self.tmp / "other" / ".cloudseed"):
                (self.tmp / "other" / ".cloudseed").mkdir(parents=True)
                self.assertIs(webui._home_of(by_home), True)           # no CLOUDSEED_HOME: <its HOME>/.cloudseed
            self.assertIs(webui._home_of(mine), True)
            self.assertIs(webui._home_of(by_home), False)
            unit = self.home / "x.service"
            unit.write_text(f"[Service]\nEnvironment=CLOUDSEED_HOME={paths.HOME}\nEnvironment=\"PATH=/usr/bin\"\n")
            self.assertIs(webui._home_of(unit), True)                    # unquoted Environment= lines too
            broken = self.home / "Library" / "LaunchAgents" / "c.plist"
            broken.write_text("not a plist")
            self.assertIsNone(webui._home_of(broken))

    def test_login_item_reads_this_homes_files_only(self):
        with mock.patch.object(Path, "home", return_value=self.home):
            self.assertIsNone(webui.login_item())
            other = self.plist(webui.LEGACY_LAUNCHD_LABEL, {"CLOUDSEED_HOME": str(self.tmp / "another-home")})
            self.assertIsNone(webui.login_item())                          # another home's console on the shared name
            other.unlink()
            self.plist(webui.LEGACY_LAUNCHD_LABEL, {"CLOUDSEED_HOME": str(paths.HOME)})
            self.assertEqual(webui.login_item(), "launchd")               # this home's, written by an older version
            (self.home / "Library" / "LaunchAgents" / f"{webui.LEGACY_LAUNCHD_LABEL}.plist").unlink()
            unit = self.home / ".config" / "systemd" / "user" / f"{webui.SYSTEMD_UNIT}.service"
            unit.parent.mkdir(parents=True)
            unit.write_text("[Service]\n")
            self.assertEqual(webui.login_item(), "systemd")


if __name__ == "__main__":
    unittest.main()
