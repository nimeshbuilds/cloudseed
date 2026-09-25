"""Regression tests for the web console backend (cloudseed/webui.py): jobs, auth, validation, credentials, reports.

Stdlib only, no network, no cloud. In-process servers and the `ui serve` subprocess bind ephemeral 127.0.0.1 ports."""
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import creds, mcp, paths, ui, undo, webui  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    """A free ephemeral port chosen by the OS (bind to port 0): suites running at the same time never collide."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(cond, timeout=15.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


class Isolated(unittest.TestCase):
    """Every file the console touches lives in a fresh temp dir for each test."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-webui-"))
        ui_dir = self.tmp / "ui"
        self.patches = [
            mock.patch.object(webui, "UI_DIR", ui_dir), mock.patch.object(webui, "JOBS_DIR", ui_dir / "jobs"),
            mock.patch.object(webui, "TOKEN_PATH", ui_dir / "token"), mock.patch.object(webui, "STATE_PATH", ui_dir / "server.json"),
            mock.patch.object(webui, "LOG_PATH", ui_dir / "server.log"), mock.patch.object(webui, "PID_PATH", ui_dir / "server.pid"),
            mock.patch.object(paths, "ENVS_DIR", self.tmp / "envs"), mock.patch.object(paths, "WORKDIRS_INDEX", self.tmp / "workdirs.json"),
            mock.patch.object(paths, "SETTINGS_PATH", self.tmp / "settings.json"), mock.patch.object(undo, "JOURNAL", self.tmp / "undo.json"),
            mock.patch.object(creds, "STORE", self.tmp / "credentials.json"),
            mock.patch.dict(webui.JOBS, clear=True), mock.patch.dict(creds.APPLIED, clear=True), mock.patch.dict(os.environ),
        ]
        for p in self.patches:
            p.start()
        (self.tmp / "envs").mkdir()
        webui._State.token, webui._State.token_sig = None, None

    def tearDown(self):
        for j in list(webui.JOBS.values()):
            if j.running and j.pid:
                try:
                    os.killpg(j.pid, signal.SIGKILL)
                except OSError:
                    pass
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_env(self, cloud="aws", name="dev", outputs=None, cfg=None) -> Path:
        d = self.tmp / "envs" / f"{cloud}-{name}"
        d.mkdir(parents=True)
        (d / "config.json").write_text(json.dumps(cfg or {"cloud": cloud, "env": name, "name": "cs", "region": "r1", "vars": {}, "state": {"type": "local"}}))
        if outputs is not None:
            (d / "outputs.json").write_text(json.dumps(outputs))
        return d

    def script(self, body: str) -> list:
        p = self.tmp / f"child{len(list(self.tmp.glob('child*')))}.py"
        p.write_text(body)
        return [sys.executable, str(p)]


# ---------------------------------------------------------------- jobs

class JobOutputTests(unittest.TestCase):
    def test_tail_zero_means_no_lines(self):          # webui-functional#19, webui-backend#12
        j = webui.Job("x", ["list"], "x")
        for i in range(50):
            j.push(f"line {i}")
        self.assertEqual(j.to_dict(tail=0)["lines"], [])
        self.assertEqual(j.to_dict(tail=0)["line_count"], 50)
        self.assertEqual(len(j.to_dict()["lines"]), 50)
        self.assertEqual(j.to_dict(tail=3)["lines"], ["line 47", "line 48", "line 49"])

    def test_cap_keeps_head_and_the_end(self):         # webui-backend#13
        j = webui.Job("x", ["setup"], "x")
        for i in range(webui.MAX_LINES + 10):
            j.push(f"line {i}")
        j.push("Error: the real failure at the end")
        lines = j.to_dict()["lines"]
        self.assertEqual(lines[0], "line 0")
        self.assertEqual(lines[-1], "Error: the real failure at the end")
        self.assertTrue(any("lines omitted" in line for line in lines))
        self.assertLessEqual(len(lines), webui.MAX_LINES + 1)
        json.dumps(j.to_dict(tail=0))                    # the SSE 'done' payload stays serialisable

    def test_split_lines_and_decoding(self):           # webui-backend#6
        lines, rest = webui._split_lines(b"caf\xe9\r\nnext\rover\npart")
        self.assertEqual([webui._clean(x) for x in lines], ["caf�", "next", "over"])
        self.assertEqual(rest, b"part")
        lines, rest = webui._split_lines(b"a\r")          # \r at a chunk end may be half of \r\n
        self.assertEqual((lines, rest), ([], b"a\r"))


def _interactive_sigint(test: unittest.TestCase) -> None:
    """Give the test the Ctrl-C of an interactive terminal. A runner started in the background by a non-interactive
    shell (`python -m unittest ... &`) ignores SIGINT, and every process it starts inherits that, so no interrupt or
    cancel could reach anything - whatever the code under test does."""
    old = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    test.addCleanup(signal.signal, signal.SIGINT, old if old is not None else signal.SIG_DFL)


class JobRunTests(Isolated):
    def test_non_utf8_output_does_not_kill_the_job(self):      # webui-backend#6
        argv = self.script("import sys,time\nsys.stdout.buffer.write(b'caf\\xe9\\n'); sys.stdout.flush()\ntime.sleep(0.3)\nprint('after the byte')\nsys.exit(3)\n")
        with mock.patch.object(mcp, "_launcher", return_value=argv):
            job = webui.start_job([], "latin1")
        self.assertTrue(wait_for(lambda: not job.running))
        d = job.to_dict()
        self.assertEqual(d["rc"], 3)
        self.assertEqual(d["lines"], ["caf�", "after the byte"])
        self.assertTrue(job.log_path.exists())
        self.assertEqual(os.stat(job.log_path).st_mode & 0o077, 0)

    def test_job_runs_in_its_own_process_group_and_cancel_reaches_grandchildren(self):   # webui-backend#4
        _interactive_sigint(self)       # a cancel is a SIGINT to the job's process group
        marker = self.tmp / "grandchild.txt"
        grandchild = self.script("import signal,sys,time\n"
                                 f"def stop(*_):\n    open({str(marker)!r}, 'w').write('interrupted')\n    sys.exit(0)\n"
                                 "signal.signal(signal.SIGINT, stop)\nprint('ready', flush=True)\ntime.sleep(30)\n")
        argv = self.script("import subprocess,sys\n"
                           f"g = subprocess.Popen({grandchild!r})\n"
                           "try:\n    print('waiting', flush=True); g.wait()\n"
                           "except KeyboardInterrupt:\n    g.wait(); print('parent interrupted', flush=True); sys.exit(130)\n")
        with mock.patch.object(mcp, "_launcher", return_value=argv):
            job = webui.start_job([], "group")
        # both are set up: the grandchild's handler, and the parent inside its try
        self.assertTrue(wait_for(lambda: {"ready", "waiting"} <= set(job.to_dict()["lines"]), timeout=30))
        self.assertEqual(os.getpgid(job.pid), job.pid)                 # its own group, not the server's
        self.assertNotEqual(os.getpgid(job.pid), os.getpgid(0))
        r = webui.cancel_job(job)
        self.assertTrue(r["cancelled"])
        self.assertEqual(r["signal"], "SIGINT")
        self.assertTrue(wait_for(lambda: not job.running))
        self.assertEqual(marker.read_text(), "interrupted")              # the grandchild got the Ctrl-C too
        self.assertEqual(job.rc, 130)
        self.assertFalse(webui.cancel_job(job)["cancelled"])

    def test_third_interrupt_kills(self):                                 # webui-backend#4
        argv = self.script("import signal,time\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\nprint('up', flush=True)\ntime.sleep(30)\n")
        with mock.patch.object(mcp, "_launcher", return_value=argv):
            job = webui.start_job([], "stubborn")
        self.assertTrue(wait_for(lambda: job.to_dict()["line_count"] >= 1))
        self.assertEqual(webui.cancel_job(job)["signal"], "SIGINT")
        self.assertEqual(webui.cancel_job(job)["signal"], "SIGINT")
        self.assertEqual(webui.cancel_job(job)["signal"], "SIGKILL")
        self.assertTrue(wait_for(lambda: not job.running))
        self.assertEqual(job.rc, 137)

    def test_running_jobs_are_never_evicted(self):                        # webui-backend#23
        slow = self.script("import time\ntime.sleep(20)\n")
        quick = self.script("print('q')\n")
        with mock.patch.object(webui, "MAX_JOBS", 2):
            with mock.patch.object(mcp, "_launcher", return_value=slow):
                long_job = webui.start_job([], "long")
            quick_jobs = []
            for _ in range(3):
                with mock.patch.object(mcp, "_launcher", return_value=quick):
                    q = webui.start_job([], "quick")
                quick_jobs.append(q)
                self.assertTrue(wait_for(lambda: not q.running))
        self.assertIn(long_job.id, webui.JOBS)
        self.assertIn(long_job.id, [j.id for j in webui.recent_jobs(1)])  # listed even beyond the window
        self.assertLessEqual(len(webui.JOBS), 3)
        webui.cancel_job(long_job)

    def test_job_survives_and_is_restored(self):                          # webui-backend#3
        argv = self.script("import time\nprint('start', flush=True)\ntime.sleep(1.5)\nprint('end', flush=True)\n")
        with mock.patch.object(mcp, "_launcher", return_value=argv):
            job = webui.start_job(["setup", "aws", "--env", "dev"], "setup", "aws-dev")
        self.assertTrue(wait_for(lambda: job.to_dict()["line_count"] >= 1))
        webui.JOBS.clear()                     # "the console restarted": only the files are left
        webui._restore_jobs()
        restored = webui.JOBS[job.id]
        self.assertTrue(restored.running)
        self.assertEqual(restored.key, "aws-dev")
        self.assertTrue(wait_for(lambda: not restored.running))
        self.assertEqual(restored.rc, 0)
        self.assertEqual(restored.to_dict()["lines"], ["start", "end"])
        webui.JOBS.clear()                     # and a finished job comes back with its output, loaded lazily
        webui._restore_jobs()
        again = webui.JOBS[job.id]
        self.assertEqual((again.rc, again.running), (0, False))
        self.assertEqual(again.to_dict(tail=0)["lines"], [])
        self.assertEqual(again.to_dict()["lines"], ["start", "end"])

    def test_a_job_that_cannot_start_does_not_hold_its_env(self):          # webui-backend#14 (review)
        with mock.patch.object(webui, "child_env", side_effect=KeyError("AWS_PROFILE")):
            job = webui.start_job(["setup", "aws", "--env", "dev"], "a", "aws-dev")
        self.assertFalse(job.running)
        self.assertEqual(job.rc, 1)
        self.assertIn("failed to run", job.to_dict()["lines"][-1])
        self.assertIsNone(webui._conflicting("aws-dev"))

    def test_restored_job_reports_its_line_count_before_loading(self):    # webui-backend#23 (review)
        argv = self.script("print('a'); print('b'); print('c')\n")
        with mock.patch.object(mcp, "_launcher", return_value=argv):
            job = webui.start_job([], "three")
        self.assertTrue(wait_for(lambda: not job.running))
        webui.JOBS.clear()
        webui._restore_jobs()
        again = webui.JOBS[job.id]
        self.assertEqual(again.to_dict(tail=0)["line_count"], 3)
        self.assertEqual(again.to_dict()["lines"], ["a", "b", "c"])

    def test_per_environment_lock(self):                                  # webui-backend#14
        self.make_env("aws", "dev")
        self.make_env("gcp", "lab")
        self.assertEqual(webui.env_key(["setup", "aws", "--env", "dev", "-y"]), "aws-dev")
        self.assertEqual(webui.env_key(["setup", "aws", "-y"]), "aws-dev")          # the only aws env
        self.assertEqual(webui.env_key(["platform", "install", "x", "--cloud", "gcp", "--env", "lab"]), "gcp-lab")
        self.assertEqual(webui.env_key(["node", "add", "aws", "--env=dev"]), "aws-dev")
        self.assertIsNone(webui.env_key(["status", "aws", "--env", "dev"]))
        self.assertIsNone(webui.env_key(["platform", "status"]))
        self.assertIsNone(webui.env_key(["undo", "aws", "--env", "dev", "--list"]))
        self.assertEqual(webui.env_key(["undo", "-y"]), "*")
        slow = self.script("import time\ntime.sleep(20)\n")
        with mock.patch.object(mcp, "_launcher", return_value=slow):
            first = webui.start_job(["setup", "aws", "--env", "dev"], "a", "aws-dev")
            with self.assertRaises(webui.Conflict) as cm:
                webui.start_job(["apply", "aws", "--env", "dev"], "b", "aws-dev")
            self.assertEqual(cm.exception.job, first.id)
            other = webui.start_job(["setup", "gcp", "--env", "lab"], "c", "gcp-lab")   # another env is fine
            with self.assertRaises(webui.Conflict):
                webui.start_job(["undo"], "d", "*")
        for j in (first, other):
            webui.cancel_job(j)


# ---------------------------------------------------------------- action validation and the tick

class ArgvTests(unittest.TestCase):
    def test_schema_validation(self):                                     # webui-backend#11
        with self.assertRaisesRegex(ValueError, "missing required field.*cloud"):
            webui.build_argv("cloudseed_setup", {})
        with self.assertRaisesRegex(ValueError, "command"):
            webui.build_argv("cloudseed_ssh", {"cloud": "aws", "confirm": True})
        with self.assertRaisesRegex(ValueError, "clients: expected a list"):
            webui.build_argv("cloudseed_mcp", {"action": "status", "clients": "all"})
        with self.assertRaisesRegex(ValueError, "port"):
            webui.build_argv("cloudseed_mcp", {"action": "status", "port": "abc"})
        with self.assertRaisesRegex(ValueError, "kind"):
            webui.build_argv("cloudseed_scan", {"kind": "bogus"})
        with self.assertRaisesRegex(ValueError, "invalid arguments"):
            webui.build_argv("cloudseed_kubectl", {"args": 'get "pods'})
        with self.assertRaisesRegex(ValueError, "args must be"):
            webui.build_argv("cloudseed_list", [1, 2])
        self.assertEqual(webui.build_argv("cloudseed_mcp", {"action": "status", "port": "7433"}), ["mcp", "status", "--port", "7433", "-y"])
        self.assertEqual(webui.build_argv("cloudseed_status", {"cloud": "aws", "env": "", "unknown": 1}), ["status", "aws"])

    def test_confirm_must_be_a_real_true(self):                           # webui-backend#1
        with self.assertRaises(ValueError):
            webui.build_argv("cloudseed_destroy", {"cloud": "aws", "confirm": "false"})
        with self.assertRaises(PermissionError):
            webui.build_argv("cloudseed_destroy", {"cloud": "aws", "confirm": False})
        self.assertEqual(webui.build_argv("cloudseed_destroy", {"cloud": "aws", "confirm": True})[:2], ["destroy", "aws"])

    def test_managed_cannot_pick_the_command_and_needs_the_tick(self):    # webui-backend#1
        with self.assertRaisesRegex(ValueError, "service"):
            webui.build_argv("cloudseed_managed", {"service": "destroy", "args": "aws --env x -y --auto-approve"})
        with self.assertRaises(webui.NeedsConfirm) as cm:
            webui.build_argv("cloudseed_managed", {"service": "databricks", "args": "clusters delete x"})
        self.assertEqual(cm.exception.argv, ["databricks", "clusters", "delete", "x"])
        with self.assertRaises(webui.NeedsConfirm):
            webui.build_argv("cloudseed_managed", {"service": "snowflake", "args": "--debug sql -q 'drop database x'"})
        self.assertEqual(webui.build_argv("cloudseed_managed", {"service": "snowflake"}), ["snowflake", "status"])
        self.assertEqual(webui.build_argv("cloudseed_managed", {"service": "databricks", "args": "test"}), ["databricks", "test"])

    def test_managed_options_cannot_hide_the_command(self):                # webui-backend#1 (review)
        for args in ("--profile status clusters delete x", "--profile=status clusters delete x", "--env dev -- clusters delete x", "connect host=x"):
            with self.assertRaises(webui.NeedsConfirm, msg=args):
                webui.build_argv("cloudseed_managed", {"service": "databricks", "args": args})
        for args in ("--profile p status", "status --profile p", "-- test", "help clusters"):
            webui.build_argv("cloudseed_managed", {"service": "databricks", "args": args})

    def test_first_run_scanner_installs_need_the_tick(self):              # webui-backend#20 (review)
        with mock.patch.object(webui.deps, "find", return_value=None), mock.patch.object(webui.paths, "HOME", Path(tempfile.mkdtemp())):
            for kind in ("kube", "images", "cloud"):
                self.assertTrue(webui._scan_mutating({"kind": kind}), kind)
                with self.assertRaises(webui.NeedsConfirm, msg=kind):
                    webui.build_argv("cloudseed_scan", {"kind": kind})
        with mock.patch.object(webui.deps, "find", return_value="/usr/local/bin/x"):
            for kind in ("kube", "images", "cis"):   # scanner already here: the console's own install gate is satisfied ...
                self.assertFalse(webui._scan_mutating({"kind": kind}), kind)
                # ... and the shared MCP rule (fix/mcp) still asks for the tick: these scans run jobs on the cluster
                self.assertEqual(webui.build_argv("cloudseed_scan", {"kind": kind, "confirm": True})[:2], ["scan", kind])
            for kind in ("fips", "reports"):                                    # read-only: no tick
                self.assertEqual(webui.build_argv("cloudseed_scan", {"kind": kind})[:2], ["scan", kind])

    def test_infrastructure_changes_need_the_tick(self):                  # webui-backend#20
        for name, args in (("cloudseed_update_ip", {"cloud": "aws"}), ("cloudseed_provision", {"cloud": "aws"}),
                           ("cloudseed_vpn", {"action": "provision", "cloud": "aws"}), ("cloudseed_vpn", {"action": "add-user", "cloud": "aws", "name": "a"}),
                           ("cloudseed_scan", {"kind": "host"}), ("cloudseed_scan", {"kind": "all"})):
            with self.assertRaises(webui.NeedsConfirm, msg=name):
                webui.build_argv(name, args)
            webui.build_argv(name, dict(args, confirm=True))
        webui.build_argv("cloudseed_scan", {"kind": "reports"})
        webui.build_argv("cloudseed_vpn", {"action": "status", "cloud": "aws"})
        cat = {a["name"]: a for a in webui.actions_catalog()}
        self.assertTrue(cat["cloudseed_update_ip"]["always_destructive"])
        self.assertTrue(cat["cloudseed_managed"]["destructive"])
        self.assertTrue(cat["cloudseed_scan"]["destructive"])

    def test_agentic_task_is_never_an_option(self):                        # webui-backend#20
        from cloudseed.cli import build_parser
        argv = webui.build_argv("cloudseed_agentic", {"task": "--list", "confirm": True})
        args = build_parser().parse_args(argv)
        self.assertEqual(" ".join(args.task).strip(), "--list")
        argv = webui.build_argv("cloudseed_agentic", {"task": "-i need a cluster", "confirm": True})
        args = build_parser().parse_args(argv)
        self.assertFalse(args.interactive)
        self.assertEqual(" ".join(args.task).strip(), "-i need a cluster")

    def test_raw_argv_is_gated_and_y_never_lands_after_dashdash(self):     # webui-backend#1
        with self.assertRaises(webui.NeedsConfirm):
            webui.raw_argv({"argv": ["destroy", "aws", "--env", "x", "--auto-approve"]})
        self.assertEqual(webui.raw_argv({"argv": ["list"]}), ["-y", "list"])
        argv = webui.raw_argv({"argv": ["ssh", "aws", "--env", "t", "--", "uptime"], "confirm": True})
        self.assertEqual(argv[-2:], ["--", "uptime"])
        self.assertNotIn("-y", argv[argv.index("--"):])
        self.assertEqual(webui.raw_argv({"argv": ["status", "aws", "-y"]}), ["status", "aws", "-y"])
        with self.assertRaises(ValueError):
            webui.raw_argv({"argv": ["ssh", "aws"], "confirm": True})
        with self.assertRaises(ValueError):
            webui.raw_argv({"argv": "list"})


# ---------------------------------------------------------------- credentials, undo, current environment

class CredsTests(Isolated):
    def test_vault_edits_reach_the_next_job_and_status(self):             # webui-functional#8, webui-backend#5
        for k in ("AWS_DEFAULT_REGION", "TS_AUTHKEY"):
            os.environ.pop(k, None)
        creds.set_("AWS_DEFAULT_REGION", "eu-west-9")
        creds.set_("TS_AUTHKEY", "tskey-" + "OLD-0123456789")
        creds.apply()                                   # what cli._dispatch does before `ui serve`
        self.assertEqual(os.environ["AWS_DEFAULT_REGION"], "eu-west-9")
        out = webui.change_creds({"unset": ["aws_default_region"], "set": {"TS_AUTHKEY": "tskey-" + "NEW-9876543210"}})
        rows = {r["key"]: r for r in out["creds"]}
        self.assertFalse(rows["AWS_DEFAULT_REGION"]["from_env"])     # not "from shell": the shell never had it
        self.assertTrue(rows["TS_AUTHKEY"]["set"])
        env = webui.child_env()
        self.assertNotIn("AWS_DEFAULT_REGION", env)                    # jobs read the vault themselves, fresh
        self.assertNotIn("TS_AUTHKEY", env)
        self.assertNotIn("AWS_DEFAULT_REGION", os.environ)             # the server's own env follows the vault
        self.assertEqual(os.environ["TS_AUTHKEY"], "tskey-" + "NEW-9876543210")
        self.assertNotIn("AWS_DEFAULT_REGION", mcp._service_env())    # never baked into a plist / unit

    def test_shell_variables_still_win(self):
        os.environ["AWS_PROFILE"] = "from-shell"
        creds.set_("AWS_PROFILE", "from-vault")
        creds.apply()
        creds.refresh()
        self.assertEqual(os.environ["AWS_PROFILE"], "from-shell")
        self.assertEqual(webui.child_env()["AWS_PROFILE"], "from-shell")
        self.assertEqual(mcp._service_env()["AWS_PROFILE"], "from-shell")

    def test_undo_puts_back_the_previous_value(self):                    # webui-backend#17
        webui.change_creds({"set": {"AWS_DEFAULT_REGION": "eu-west-1"}})
        webui.change_creds({"set": {"aws_default_region": "ap-south-1", "NEW_KEY": "x"}})
        e = undo.latest(undo.GLOBAL)
        self.assertEqual(e["kind"], "creds-restore")
        self.assertEqual(e["data"]["values"], {"AWS_DEFAULT_REGION": "eu-west-1"})
        self.assertEqual(e["data"]["unset"], ["NEW_KEY"])
        undo.perform(e, {}, True)
        self.assertEqual(creds.load()["AWS_DEFAULT_REGION"], "eu-west-1")
        n = len(undo.entries(undo.GLOBAL))
        webui.change_creds({"set": {"AWS_DEFAULT_REGION": "eu-west-1"}})     # no change: no entry
        self.assertEqual(len(undo.entries(undo.GLOBAL)), n)

    def test_invalid_requests_leave_no_trace(self):                        # webui-backend#17
        for body in ({"set": ["A"]}, {"set": {"bad key!": "v"}}, {"set": {"1ABC": "v"}}, {"set": {"OK": "v", "no good": "x"}}, {"unset": "A"}):
            with self.assertRaises(ValueError):
                webui.change_creds(body)
        self.assertEqual(undo.entries(), [])
        self.assertEqual(creds.load(), {})

    def test_env_use(self):                                                 # webui-backend#17
        self.make_env("aws", "dev")
        self.make_env("gcp", "lab")
        with self.assertRaisesRegex(ValueError, "Unknown environment"):
            webui.use_env("nope-nope")
        self.assertNotIn("current_env", paths.load_settings())
        for env_id in ("aws-dev", "aws-dev", "gcp-lab", "aws-dev", ""):
            webui.use_env(env_id)
        self.assertNotIn("current_env", paths.load_settings())
        self.assertEqual(len([e for e in undo.entries() if e["summary"].startswith("env use")]), 1)   # one slot for the run
        self.assertFalse(webui.use_env(None)["changed"])


# ---------------------------------------------------------------- reports, verdicts, files, platform status

class ReportTests(Isolated):
    def test_reports_skip_raw_dumps_sort_by_time_and_cap(self):          # webui-functional#17, webui-backend#19
        d = self.make_env("aws", "dev")
        scans = d / "scans"
        scans.mkdir()
        (scans / "kubescape-20260101-000000.json").write_text(json.dumps({"results": [{"r": i} for i in range(3000)]}))
        (scans / "trivy-20260101-000000.json").write_text("{}")
        (scans / "kube-20260101-000000.json").write_text(json.dumps({"kind": "kube", "summary": {"controls failed": 2}, "findings": [{"severity": "LOW"}]}))
        (scans / "cis-20260102-000000.json").write_text(json.dumps({"kind": "cis", "summary": {"pass": 3, "fail": 1}, "results": [{"x": i} for i in range(500)]}))
        (scans / "fips-20250101-000000.json").write_text(json.dumps({"kind": "fips", "summary": {"fail": 0}}))
        r = webui.reports("aws-dev")
        self.assertEqual([s["name"] for s in r["scans"]], ["cis-20260102-000000", "kube-20260101-000000", "fips-20250101-000000"])
        self.assertEqual({s["name"]: s["verdict"] for s in r["scans"]}, {"cis-20260102-000000": "FAIL", "kube-20260101-000000": "PASS", "fips-20250101-000000": "PASS"})
        self.assertEqual(len(r["scans"][0]["results"]), 200)

    def test_verdicts_match_the_cli(self):                                  # webui-backend#19
        d = self.make_env("aws", "dev")
        (d / "chaos").mkdir()
        (d / "scans").mkdir()
        (d / "chaos" / "report-20260101-000000.json").write_text(json.dumps({"run": "1", "results": [], "summary": {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}}))
        (d / "scans" / "kube-20260101-000000.json").write_text(json.dumps({"summary": {"controls failed": 2}, "findings": [{"severity": "LOW"}]}))
        v = webui.verdicts(paths.Env("aws", "dev"))
        self.assertNotEqual(v["chaos"]["verdict"], "PASS")
        self.assertEqual(v["chaos"]["detail"], "no experiments ran")
        self.assertEqual(v["kube"]["verdict"], "PASS")
        (d / "chaos" / "report-20260102-000000.json").write_text(json.dumps({"run": "2", "results": [{}, {}], "summary": {"PASS": 1, "SKIP": 1}}))
        self.assertEqual(webui.verdicts(paths.Env("aws", "dev"))["chaos"]["verdict"], "INCONCLUSIVE")
        (d / "chaos" / "report-20260103-000000.json").write_text(json.dumps({"run": "3", "results": [{}], "summary": {"PASS": 1}, "verdict": "PASS"}))
        self.assertEqual(webui.verdicts(paths.Env("aws", "dev"))["chaos"]["verdict"], "PASS")
        (d / "scans" / "kube-20260102-000000.json").write_text(json.dumps({"summary": {}, "findings": [{"severity": "HIGH"}]}))
        self.assertEqual(webui.verdicts(paths.Env("aws", "dev"))["kube"]["verdict"], "FAIL")

    def test_a_damaged_report_does_not_break_the_console(self):            # webui-backend#19 (review)
        d = self.make_env("aws", "dev")
        (d / "scans").mkdir()
        (d / "chaos").mkdir()
        (d / "scans" / "kube-20260101-000000.json").write_text(json.dumps({"findings": 5, "checks": {"a": 1}, "results": "x"}))
        (d / "scans" / "images-20260101-000000.json").write_text(json.dumps({"findings": {"a": 1}, "summary": [1]}))
        (d / "chaos" / "report-20260101-000000.json").write_text(json.dumps({"results": "x", "summary": "y"}))
        r = webui.reports("aws-dev")
        self.assertEqual({s["name"] for s in r["scans"]}, {"kube-20260101-000000", "images-20260101-000000"})
        self.assertTrue(all(s["findings"] == [] and s["checks"] == [] and s["results"] == [] for s in r["scans"]))
        v = webui.verdicts(paths.Env("aws", "dev"))
        self.assertEqual(v["kube"]["verdict"], "PASS")
        self.assertEqual(v["chaos"]["verdict"], "INCONCLUSIVE")

    def test_read_env_file_allowlist(self):                                 # webui-backend#9
        d = self.make_env("aws", "dev")
        for rel, text in (("platform/secrets.json", '{"grafana_password": "Px3h"}'), ("k8s/vars.json", '{"k8s_token": "abc"}'), ("k8s/kubeconfig", "x"),
                          ("stack/main.tf.json", "{}"), ("logs/1-setup.log", "log line"), ("scans/cis-1.md", "# report"), ("chaos/report-1.json", "{}")):
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(text)
        for rel in ("platform/secrets.json", "k8s/vars.json", "k8s/kubeconfig", "stack/main.tf.json", "config.json", "../envs/aws-dev/config.json"):
            self.assertIsNone(webui.read_env_file(str(d / rel)), rel)
        self.assertEqual(webui.read_env_file(str(d / "logs" / "1-setup.log")), "log line")
        self.assertEqual(webui.read_env_file(str(d / "scans" / "cis-1.md")), "# report")
        self.assertIsNotNone(webui.read_env_file(str(d / "chaos" / "report-1.json")))
        self.assertIsNone(webui.read_env_file("/etc/passwd"))
        self.assertIsNone(webui.read_env_file("\x00"))

    def test_platform_status_never_drops_and_never_installs(self):         # webui-backend#10
        self.make_env("gcp", "lab", outputs={"kubernetes_cluster_name": "c1"},
                      cfg={"cloud": "gcp", "env": "lab", "region": "r1", "vars": {"project_id": "p", "zone": "z"}, "state": {"type": "local"}})
        self.make_env("vmware", "lab", outputs={"kubernetes_control_plane_ips": ["10.0.0.5"]},
                      cfg={"cloud": "vmware", "env": "lab", "region": "local", "vars": {}, "state": {"type": "local"}})
        real_find = webui.deps.find
        with mock.patch.object(webui.deps, "find", side_effect=lambda t: "/bin/helm" if t == "helm" else None if t == "gcloud" else real_find(t)), \
             mock.patch.object(webui.deps, "install", side_effect=AssertionError("a status page must not install tools")):
            r = webui.platform_status("gcp-lab")
            self.assertIn("gcloud is not installed", r["error"])
            r = webui.platform_status("vmware-lab")
            self.assertIn("no kubeconfig yet", r["error"].lower())
        with mock.patch.object(webui, "_status_kubeconfig", side_effect=ui.Abort("could not fetch it")), \
             mock.patch.object(webui.deps, "find", return_value="/bin/helm"):
            self.assertEqual(webui.platform_status("gcp-lab"), {"error": "could not fetch it"})

    def test_help_with_quotes(self):                                         # webui-backend#11
        self.assertNotIn("No closing quotation", webui.help_page('"'))
        self.assertIsInstance(webui.help_page("what's new"), str)


# ---------------------------------------------------------------- the HTTP server

class HttpTests(Isolated):
    def setUp(self):
        super().setUp()
        self.port = free_port()
        self.token = webui.ensure_token()
        webui._State.host, webui._State.port = "127.0.0.1", self.port
        self.httpd = webui._Server(("127.0.0.1", self.port), webui._Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def req(self, method, path, body=None, headers=None, raw_body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"X-CS-Token": self.token}
        h.update(headers or {})
        data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        out = (r.status, dict(r.getheaders()), r.read())
        c.close()
        return out

    def test_static_traversal(self):                                         # webui-functional#28, webui-backend#22
        self.assertEqual(self.req("GET", "/static/../webui.py")[0], 404)
        self.assertEqual(self.req("GET", "/static//etc/passwd")[0], 404)
        self.assertEqual(self.req("GET", "/static/app.js")[0], 200)
        self.assertEqual(self.req("GET", "/static/boot.js")[0], 200)

    def test_no_cookie_no_framing_no_cache(self):                            # webui-backend#8, #21
        code, h, body = self.req("GET", f"/?token={self.token}", headers={"X-CS-Token": ""})
        self.assertEqual(code, 200)
        self.assertNotIn("Set-Cookie", h)
        self.assertNotIn("Location", h)
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertIn(self.token.encode(), body)
        self.assertIn(b"/static/boot.js", body)
        code, _, body = self.req("GET", "/", headers={"X-CS-Token": "", "Cookie": f"cs_token={self.token}"})
        self.assertEqual(code, 200)                                        # the lock screen, not the console
        self.assertNotIn(self.token.encode(), body)
        self.assertIn(b"locked", body)
        self.assertIn(b"/static/boot.js", body)
        self.assertEqual(self.req("GET", "/?token=wrong", headers={"X-CS-Token": ""})[0], 401)
        self.assertEqual(self.req("GET", "/api/state", headers={"X-CS-Token": "", "Cookie": f"cs_token={self.token}"})[0], 401)

    def test_host_and_origin_checks(self):                                   # webui-backend#8, #22
        self.assertEqual(self.req("GET", "/health", headers={"Host": "evil.example:%d" % self.port})[0], 403)
        self.assertEqual(self.req("GET", "/health", headers={"Host": "localhost:%d" % self.port})[0], 200)
        self.assertEqual(self.req("GET", "/api/jobs", headers={"Origin": "http://127.0.0.1:7621"})[0], 403)
        self.assertEqual(self.req("GET", "/api/jobs", headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)

    def test_token_rotation_without_restart(self):                            # webui-backend#3
        self.assertEqual(self.req("GET", "/api/jobs")[0], 200)
        time.sleep(0.01)
        new = webui.ensure_token(rotate=True)
        self.assertEqual(self.req("GET", "/api/jobs")[0], 401)
        self.assertEqual(self.req("GET", "/api/jobs", headers={"X-CS-Token": new})[0], 200)

    def test_bad_requests_get_json_errors(self):                              # webui-backend#11, #10
        code, _, body = self.req("GET", "/api/help?topic=%22")
        self.assertEqual(code, 200)
        self.assertEqual(self.req("GET", "/api/file?path=%00")[0], 404)
        self.assertEqual(self.req("POST", "/api/run", raw_body=b"{}", headers={"Content-Length": "abc"})[0], 400)
        for raw in (b"[1,2]", b'"x"', b"{nope"):
            code, _, body = self.req("POST", "/api/run", raw_body=raw)
            self.assertEqual(code, 400, raw)
            self.assertIn(b"error", body)
        code, _, body = self.req("POST", "/api/run", {"action": "cloudseed_setup", "args": {}})
        self.assertEqual(code, 400)
        self.assertIn(b"cloud", body)
        code, _, body = self.req("POST", "/api/run", {"action": "cloudseed_destroy", "args": {"cloud": "aws"}})
        self.assertEqual(code, 409)
        self.assertTrue(json.loads(body)["needs_confirm"])
        with mock.patch.object(webui, "platform_status", side_effect=ui.Abort("boom")):
            code, _, body = self.req("GET", "/api/platform/status?env=x")
        self.assertEqual(code, 500)
        self.assertEqual(json.loads(body)["error"], "boom")

    def test_sse_ids_and_resume(self):                                         # webui-backend#23
        job = webui.Job("20260101-000000-abcd", ["list"], "list")
        for i in range(5):
            job.push(f"line {i}")
        job.finish(0)
        webui.JOBS[job.id] = job
        _, _, body = self.req("GET", f"/api/jobs/{job.id}/stream?token={self.token}", headers={"X-CS-Token": ""})
        text = body.decode()
        self.assertIn("id: 1\ndata: \"line 0\"", text)
        self.assertIn("event: done", text)
        done = json.loads(text.split("event: done\ndata: ", 1)[1].split("\n", 1)[0])
        self.assertEqual(done["lines"], [])
        _, _, body = self.req("GET", f"/api/jobs/{job.id}/stream?token={self.token}", headers={"X-CS-Token": "", "Last-Event-ID": "3"})
        self.assertNotIn('"line 2"', body.decode())
        self.assertIn('"line 3"', body.decode())
        code, _, body = self.req("GET", "/api/state")
        self.assertEqual(code, 200)
        self.assertTrue(all(j["lines"] == [] for j in json.loads(body)["jobs"]))


# ---------------------------------------------------------------- service management

class ServiceTests(Isolated):
    def test_stale_pid_file_is_not_trusted(self):                            # webui-backend#18
        victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(victim.wait)
        self.addCleanup(victim.kill)
        webui.UI_DIR.mkdir(parents=True, exist_ok=True)
        webui.PID_PATH.write_text(str(victim.pid))
        self.assertIsNone(webui.running_pid())
        self.assertFalse(webui.PID_PATH.exists())
        webui.PID_PATH.write_text(str(victim.pid))
        with mock.patch.object(webui, "health", return_value=False), mock.patch.object(Path, "home", return_value=self.tmp / "home"):
            self.assertFalse(webui.stop())
        self.assertIsNone(victim.poll())                                     # still alive

    def test_service_definitions_let_jobs_outlive_the_console(self):         # webui-backend#2, #3
        seen = {}

        def fake_run(cmd, **kw):
            seen.setdefault("cmds", []).append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        home = self.tmp / "home"
        with mock.patch.object(Path, "home", return_value=home), mock.patch.object(webui.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(webui, "health", return_value=True), mock.patch.object(webui.os, "getuid", return_value=501, create=True):
            webui.start({"host": "127.0.0.1", "port": 7699, "service": "launchd"})
            import plistlib
            with open(home / "Library" / "LaunchAgents" / f"{webui.LAUNCHD_LABEL}.plist", "rb") as fh:
                pl = plistlib.load(fh)
            self.assertTrue(pl["AbandonProcessGroup"])
            self.assertEqual(pl["EnvironmentVariables"][webui.MANAGED_ENV], "1")
            webui.start({"host": "127.0.0.1", "port": 7699, "service": "systemd"})
            unit = (home / ".config" / "systemd" / "user" / f"{webui.SYSTEMD_UNIT}.service").read_text()
            self.assertIn("KillMode=process", unit)
        self.assertEqual(webui.url(s={"host": "127.0.0.1", "port": 7699}), "http://127.0.0.1:7699/")


class LocalServerStartupTests(unittest.TestCase):
    def test_binding_does_not_wait_for_reverse_dns(self):
        with mock.patch.object(socket, "getfqdn", side_effect=AssertionError("reverse DNS must not run")):
            server = webui._Server(("127.0.0.1", 0), webui._Handler)
        self.addCleanup(server.server_close)
        self.assertEqual(server.server_name, "127.0.0.1")
        self.assertGreater(server.server_port, 0)


class ForegroundServeTests(unittest.TestCase):                                # webui-backend#16, #3 (end to end)
    def test_foreground_serve_records_its_address_and_jobs_survive_a_restart(self):
        home = Path(tempfile.mkdtemp(prefix="cs-webui-fg-"))
        self.addCleanup(shutil.rmtree, home, True)
        cs = home / "cs"
        (cs / "bin").mkdir(parents=True)
        (cs / "settings.json").write_text('{"ui": true}')
        env_dir = cs / "envs" / "aws-dev"
        env_dir.mkdir(parents=True)
        (env_dir / "config.json").write_text(json.dumps({"cloud": "aws", "env": "dev", "name": "cs", "region": "r1", "vars": {}, "state": {"type": "local"}}))
        (env_dir / "outputs.json").write_text('{"bastion_public_ip": "192.0.2.1"}')
        fake_ssh = cs / "bin" / "ssh"
        fake_ssh.write_text("#!/bin/sh\necho start\nsleep 2\necho end\n")
        fake_ssh.chmod(0o755)
        port = free_port()
        env = dict(os.environ, CLOUDSEED_HOME=str(cs), HOME=str(home), NO_COLOR="1")
        env.pop(webui.MANAGED_ENV, None)
        cli = [sys.executable, str(ROOT / "bin" / "cloudseed")]

        def serve():
            p = subprocess.Popen(cli + ["ui", "serve", "--port", str(port)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.addCleanup(lambda: (p.poll() is None and p.kill(), p.wait()))
            self.assertTrue(wait_for(lambda: self._health(port)), "console did not start")
            return p

        def api(method, path, body=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request(method, path, body=json.dumps(body) if body is not None else None, headers={"X-CS-Token": (cs / "ui" / "token").read_text().strip()})
            try:
                r = c.getresponse()
                return r.status, json.loads(r.read() or b"null")
            finally:
                c.close()

        p = serve()
        st = json.loads((cs / "ui" / "server.json").read_text())
        self.assertEqual((st["port"], st["foreground_pid"]), (port, p.pid))
        out = subprocess.run(cli + ["ui", "token"], env=env, capture_output=True, text=True, timeout=60).stdout
        self.assertIn(f"http://127.0.0.1:{port}/?token=", out)
        code, r = api("POST", "/api/run", {"action": "cloudseed_ssh", "args": {"cloud": "aws", "env": "dev", "command": "uptime", "confirm": True}})
        self.assertEqual(code, 200, r)
        jid = r["job"]
        self.assertTrue(wait_for(lambda: "start" in api("GET", f"/api/jobs/{jid}")[1]["lines"]))
        p.send_signal(signal.SIGTERM)                                         # restart the console mid-job
        p.wait(timeout=10)
        self.assertFalse((cs / "ui" / "server.json").exists())                # the foreground address is withdrawn
        p = serve()
        code, j = api("GET", f"/api/jobs/{jid}")
        self.assertEqual(code, 200)
        self.assertTrue(wait_for(lambda: not api("GET", f"/api/jobs/{jid}")[1]["running"], timeout=20))
        j = api("GET", f"/api/jobs/{jid}")[1]
        self.assertEqual(j["rc"], 0)
        self.assertIn("end", j["lines"])
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=10)

    @staticmethod
    def _health(port) -> bool:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            c.request("GET", "/health")
            return c.getresponse().status == 200
        except OSError:
            return False
        finally:
            c.close()


# ---------------------------------------------------------------- integration with fix/mcp, fix/agentic, fix/ops

class IntegrationTests(Isolated):
    def test_console_actions_use_the_shared_schema_rules(self):           # mcp#2: option-like values never reach argv
        with self.assertRaisesRegex(ValueError, "not allowed here"):
            webui.build_argv("cloudseed_status", {"cloud": "aws", "env": "--help"})
        with self.assertRaisesRegex(ValueError, "not allowed here"):
            webui.build_argv("cloudseed_install", {"what": ["--force"], "confirm": True})
        self.assertEqual(webui.build_argv("cloudseed_status", {"cloud": "aws", "env": "dev"}), ["status", "aws", "--env", "dev"])

    def test_managed_gate_reads_options_like_the_cli(self):              # webui-backend#1 handoff to mcp
        m = mcp.TOOLS["cloudseed_managed"]["destructive_when"]
        for a in ("--profile status clusters delete x", "--profile=status clusters delete x", "--env dev -- clusters delete x",
                  "-- --env x clusters delete", "--debug clusters delete x"):
            self.assertTrue(m({"args": a}), a)
        for a in ("--profile p status", "-e dev clusters list", "-- test", "help clusters"):
            self.assertFalse(m({"args": a}), a)

    def test_creds_refuses_unsafe_names_before_writing(self):             # agentic#2, agentic#24
        for body in ({"set": {"OK_KEY": "v", "PATH": "/tmp/x"}}, {"set": {"LD_PRELOAD": "x"}}):
            with self.assertRaisesRegex(ValueError, "cannot be stored"):
                webui.change_creds(body)
        self.assertEqual(creds.load(), {})
        self.assertEqual(undo.entries(), [])
        creds.save({"PYTHONPATH": "/tmp/elsewhere"})                      # written by an older version or by hand
        self.assertEqual(webui.change_creds({"unset": ["PYTHONPATH"]})["changed"], ["PYTHONPATH"])
        self.assertEqual(creds.load(), {})

    def test_path_values_are_compared_as_stored(self):                    # webui-backend#17 no-op + creds path normalising
        webui.change_creds({"set": {"GOOGLE_APPLICATION_CREDENTIALS": "~/k.json"}})
        self.assertTrue(Path(creds.load()["GOOGLE_APPLICATION_CREDENTIALS"]).is_absolute())
        n = len(undo.entries(undo.GLOBAL))
        self.assertEqual(webui.change_creds({"set": {"GOOGLE_APPLICATION_CREDENTIALS": "~/k.json"}})["changed"], [])
        self.assertEqual(len(undo.entries(undo.GLOBAL)), n)

    def test_job_output_redacts_multi_line_private_keys(self):            # ops#35, agentic#10
        pem = ("before\n-----BEGIN " "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAverySECRETbody\nmoreSECRETbody==\n"
               "-----END RSA PRIVATE KEY-----\nafter\n\n")
        webui.JOBS_DIR.mkdir(parents=True)
        restored = webui.Job("pem", ["setup"], "pem")                     # a finished job read back from its log
        restored.log_path.write_text(pem)
        restored.rc, restored._loaded = 0, False
        argv = self.script(f"import sys\nsys.stdout.write({pem!r})\n")
        with mock.patch.object(mcp, "_launcher", return_value=argv):
            live = webui.start_job([], "pem-live")                        # a live job streamed from its runner
        self.assertTrue(wait_for(lambda: not live.running))
        for job in (restored, live):
            lines = job.to_dict()["lines"]
            self.assertFalse(any("SECRET" in x for x in lines), lines)
            self.assertEqual([lines[0], lines[1], lines[-2], lines[-1]], ["before", "[REDACTED]", "after", ""], lines)

    def test_ui_switches_need_a_true_value(self):                         # agentic#21
        os.environ["CLOUDSEED_UI_FORCE"] = "0"
        with mock.patch("sys.stderr"):
            self.assertEqual(webui.serve("127.0.0.1", free_port()), 2)    # the UI is disabled here; "0" does not force it


if __name__ == "__main__":
    unittest.main()
