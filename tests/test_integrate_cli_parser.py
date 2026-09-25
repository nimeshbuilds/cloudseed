"""Integration of fix/cli-parser with the groups merged before it.

cli-parser made ui.Abort quiet when it is raised (the dispatcher prints it once; str(e) is the message) and added a
crash log. mcp and resilience had catch sites written for the old self-printing Abort; ops rewrote audit.py's command
naming, argv masking and 0600 log handles; agentic redacts everything an agent-session process prints.
"""

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import chaos, cli, mcp, paths, ui  # noqa: E402
from cloudseed import platform as pl  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_fix_resilience import FakeChaosCluster, FakeClock, make_ctx  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(cli.deps, "ensure_runtime", return_value="local"):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


def _crash_logs() -> set:
    logs = paths.HOME / "logs"
    return set(logs.glob("*-crash.log")) if logs.exists() else set()


class AbortCatchSiteTests(unittest.TestCase):
    """Code that catches an Abort to carry on must now show its message itself."""

    def tearDown(self):
        ui.NON_INTERACTIVE = False

    def test_mcp_connect_names_the_reason_a_client_was_not_connected(self):
        client = next(iter(mcp.CLIENTS))
        with mock.patch.object(mcp, "connect", side_effect=ui.Abort("its config file is not valid JSON")):
            rc, out, err = run_main("mcp", "connect", client)
        self.assertEqual(rc, 1)
        self.assertIn(f"{mcp.CLIENTS[client]['display']}: not connected: its config file is not valid JSON", err)
        self.assertNotIn("see above", err)
        self.assertEqual(err.count("its config file is not valid JSON"), 1)

    def test_chaos_run_reports_an_abort_that_stopped_it(self):
        def exp(ctx, name, t, d, run_id):
            raise ui.Abort("Could not download the velero CLI")
        ctx = make_ctx()
        t = chaos.Target(chaos.CANARY_NS, "canary", "canary", "canary", 8080, True)
        err = io.StringIO()
        with mock.patch.object(chaos, "_kubectl", FakeChaosCluster()), mock.patch.object(chaos, "time", FakeClock()), \
                mock.patch.object(chaos, "ensure_chaos_mesh"), mock.patch.object(pl, "ensure_tools"), \
                mock.patch.object(chaos, "dns_chaos_available", return_value=True), \
                mock.patch.object(chaos, "resolve_target", return_value=t), \
                mock.patch.object(chaos, "run_experiment", side_effect=exp), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = chaos.run(ctx, ["pod-kill"], None, None, 10, 2, False)
        self.assertEqual(rc, 1)
        self.assertIn("chaos run stopped: Could not download the velero CLI", err.getvalue())
        rep = json.loads(chaos.last_report(ctx.env).read_text())
        self.assertEqual(rep["results"][0]["reason"], "Could not download the velero CLI")


class CrashLogTests(unittest.TestCase):
    """cli-parser's crash log uses ops' audit naming (parsed command), argv masking and key filtering."""

    def _crash(self, argv, exc):
        def crash(args, settings):
            raise exc
        before = _crash_logs()
        cmd = next(a for a in argv if a in cli.HANDLERS)
        with mock.patch.dict(cli.HANDLERS, {cmd: crash}):
            rc, out, err = run_main(*argv)
        self.assertEqual(rc, 1)
        new = _crash_logs() - before
        self.assertEqual(len(new), 1, err)
        return new.pop(), err

    def test_crash_log_is_named_after_the_parsed_command(self):
        log, err = self._crash(["--runtime", "local", "-y", "list"], RuntimeError("boom"))
        try:
            self.assertTrue(log.name.endswith("-list-crash.log"), log.name)
            self.assertIn(str(log), err)
            last = json.loads((paths.HOME / "logs" / "audit.jsonl").read_text().splitlines()[-1])
            self.assertEqual((last["command"], last["log"]), ("list", str(log)))
        finally:
            log.unlink()

    def test_crash_log_masks_argv_and_private_keys(self):
        key = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretbody\n-----END RSA PRIVATE KEY-----"
        log, err = self._crash(["creds", "set", "FOO=hunter2plainvalue"], RuntimeError(f"bad key\n{key}"))
        try:
            text = log.read_text()
            self.assertIn("Traceback", text)
            self.assertNotIn("hunter2plainvalue", text)      # every creds set value is masked (ops' safe_argv)
            self.assertNotIn("MIIEowIBAAKCAQEAsecretbody", text)
            self.assertNotIn("MIIEowIBAAKCAQEAsecretbody", err)
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        finally:
            log.unlink()


class AgentSessionUsageErrorTests(unittest.TestCase):
    def test_usage_errors_are_redacted_in_agent_sessions(self):
        home = Path(tempfile.mkdtemp(prefix="cs-redact-usage-"))
        secret = "Zq8" * 12
        env = dict(os.environ, CLOUDSEED_HOME=str(home), HOME=str(home), CLOUDSEED_REDACT="1", NO_COLOR="1",
                   MY_SERVICE_PASSWORD=secret)
        env.pop("CLOUDSEED_SESSION", None)
        try:
            r = subprocess.run([sys.executable, str(REPO / "bin" / "cloudseed"), "node", "add", secret],
                               env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertNotIn(secret, r.stdout + r.stderr)
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
