"""Wave-2 regression tests for the web console backend (cloudseed/webui.py): handoffs from the other groups.

Stdlib only, no network, no cloud, no launchd/systemd. In-process servers bind ephemeral 127.0.0.1 ports."""
import http.client
import json
import os
import shutil
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

from cloudseed import creds, mcp, paths, undo, webui  # noqa: E402
from cloudseed import platform as pl  # noqa: E402
from cloudseed.clouds import azure as azmod  # noqa: E402
from cloudseed.clouds import gcp as gcpmod  # noqa: E402


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
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-w2-webui-"))
        ui_dir = self.tmp / "ui"
        self.patches = [
            mock.patch.object(webui, "UI_DIR", ui_dir), mock.patch.object(webui, "JOBS_DIR", ui_dir / "jobs"),
            mock.patch.object(webui, "TOKEN_PATH", ui_dir / "token"), mock.patch.object(webui, "STATE_PATH", ui_dir / "server.json"),
            mock.patch.object(webui, "LOG_PATH", ui_dir / "server.log"), mock.patch.object(webui, "PID_PATH", ui_dir / "server.pid"),
            mock.patch.object(paths, "ENVS_DIR", self.tmp / "envs"), mock.patch.object(paths, "WORKDIRS_INDEX", self.tmp / "workdirs.json"),
            mock.patch.object(paths, "SETTINGS_PATH", self.tmp / "settings.json"), mock.patch.object(undo, "JOURNAL", self.tmp / "undo.json"),
            mock.patch.object(creds, "STORE", self.tmp / "credentials.json"),
            mock.patch.dict(webui.JOBS, clear=True), mock.patch.dict(creds.APPLIED, clear=True), mock.patch.dict(os.environ),
            mock.patch.dict(webui._DEFAULTS, clear=True),
        ]
        for p in self.patches:
            p.start()
        for k in (webui.MANAGED_ENV, "CLOUDSEED_UI_FORCE", "CLOUDSEED_UI_ALLOW_REMOTE"):
            os.environ.pop(k, None)
        (self.tmp / "envs").mkdir()
        webui._State.token, webui._State.token_sig = None, None

    def tearDown(self):
        for j in list(webui.JOBS.values()):
            if j.running and j.pid:
                try:
                    os.killpg(j.pid, 9)
                except OSError:
                    pass
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_env(self, cloud="aws", name="dev", outputs=None, cfg=None, raw_cfg=None) -> Path:
        d = self.tmp / "envs" / f"{cloud}-{name}"
        d.mkdir(parents=True)
        (d / "config.json").write_text(raw_cfg if raw_cfg is not None else
                                       json.dumps(cfg or {"cloud": cloud, "env": name, "name": "cs", "region": "r1", "vars": {}, "state": {"type": "local"}}))
        if outputs is not None:
            (d / "outputs.json").write_text(json.dumps(outputs))
        return d

    def quiet_mcp(self, connected=None, stale=None):
        """No client probing (claude mcp get, config files) while state() is built."""
        conn = connected or {}
        return [mock.patch.object(mcp, "connected", side_effect=lambda k: conn.get(k)),
                mock.patch.object(mcp, "client_present", return_value=False),
                mock.patch.object(mcp, "stale", side_effect=stale or (lambda k, s=None: False))]

    def state(self, connected=None, stale=None):
        ps = self.quiet_mcp(connected, stale)
        for p in ps:
            p.start()
        try:
            return webui.state()
        finally:
            for p in reversed(ps):
                p.stop()


# ---------------------------------------------------------------- wizard catalog (azure#25, webui-visual#28, cli-lifecycle#11)

class CatalogTests(Isolated):
    def q(self, cat, cloud, key):
        return {x["key"]: x for x in cat[cloud]["questions"]}[key]

    def test_env_variables_win_and_no_cloud_cli_runs(self):                   # azure#25
        os.environ["ARM_SUBSCRIPTION_ID"] = "11111111-2222-3333-4444-555555555555"
        with mock.patch.object(azmod.subprocess, "run", side_effect=AssertionError("az must not run for a page view")), \
                mock.patch.object(azmod.deps, "find", return_value="/bin/az"):
            cat = webui.clouds_catalog()
        sub = self.q(cat, "azure", "subscription_id")
        self.assertEqual(sub["from_env"], ["ARM_SUBSCRIPTION_ID"])
        self.assertEqual(sub["default"], "")                                   # blank = the CLI takes $ARM_SUBSCRIPTION_ID
        self.assertNotIn("11111111-2222", json.dumps(cat))                     # names only, never values

    def test_env_zone_wins_over_the_region_derived_default(self):             # azure#25 / cli-lifecycle#11
        os.environ["CLOUDSDK_COMPUTE_ZONE"] = "europe-west1-c"
        zone = self.q(webui.clouds_catalog(), "gcp", "zone")
        self.assertEqual((zone["default"], zone["from_env"]), ("", ["CLOUDSDK_COMPUTE_ZONE"]))
        self.assertNotIn("region_defaults", zone)
        os.environ["CLOUDSDK_COMPUTE_ZONE"] = "not a zone"                     # the CLI ignores an invalid value too
        zone = self.q(webui.clouds_catalog(), "gcp", "zone")
        self.assertEqual((zone["default"], zone["from_env"]), ("us-central1-a", []))
        self.assertEqual(zone["region_defaults"], {r: gcpmod.default_zone(r) for r in ("europe-west1", "us-east1")})

    def test_vault_values_count_like_shell_ones(self):
        for n in ("GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT"):
            os.environ.pop(n, None)
        creds.save({"GOOGLE_PROJECT": "vault-project-1"})
        pid = self.q(webui.clouds_catalog(), "gcp", "project_id")
        self.assertEqual(pid["from_env"], ["GOOGLE_PROJECT"])
        self.assertNotIn("vault-project-1", json.dumps(pid))

    def test_computed_defaults_never_make_a_poll_wait(self):                 # azure#25: az runs once, then in the background
        calls = []
        release = threading.Event()

        def slow(cfg):
            calls.append(cfg["region"])
            if len(calls) > 1:
                release.wait(5)                                                # a slow refresh (az account show)
            return f"value-{len(calls)}"
        q = mock.Mock(key="probe", default=slow)
        q.stock_default.side_effect = slow
        cfg = {"region": "r", "workdir": ""}
        self.assertEqual(webui.computed_default("x", q, cfg), "value-1")
        self.assertEqual(webui.computed_default("x", q, cfg), "value-1")        # cached: not computed again
        self.assertEqual(len(calls), 1)
        webui._DEFAULTS[("x", "probe")][1] -= webui.DEFAULT_TTL + 1            # it is old now
        t0 = time.monotonic()
        self.assertEqual(webui.computed_default("x", q, cfg), "value-1")        # the old value, at once
        self.assertEqual(webui.computed_default("x", q, cfg), "value-1")        # one refresh at a time
        self.assertLess(time.monotonic() - t0, 1.0)
        release.set()
        self.assertTrue(wait_for(lambda: webui._DEFAULTS[("x", "probe")][0] == "value-2"))
        self.assertEqual(webui.computed_default("x", q, cfg), "value-2")
        self.assertEqual(len(calls), 2)

    def test_a_broken_default_is_not_suggested(self):
        q = mock.Mock(key="boom")
        q.stock_default.side_effect = KeyError("region")
        self.assertEqual(webui.computed_default("x", q, {"region": "r"}), "")

    def test_choices_are_offered_when_a_question_has_them(self):             # webui-visual#28
        from cloudseed import clouds
        vpn = next(q for q in clouds.get("aws").questions if q.key == "vpn_type")
        if not getattr(vpn, "choices", None):                                 # no choices: a free text field, as before
            self.assertNotIn("choices", self.q(webui.clouds_catalog(), "aws", "vpn_type"))
        with mock.patch.object(vpn, "choices", ("openvpn", "tailscale"), create=True):
            self.assertEqual(self.q(webui.clouds_catalog(), "aws", "vpn_type")["choices"], ["openvpn", "tailscale"])


# ---------------------------------------------------------------- /api/state (azure#25, mcp#19)

class StateTests(Isolated):
    def test_an_unreadable_environment_is_shown_not_hidden(self):             # azure#25
        self.make_env("aws", "dev")
        self.make_env("gcp", "bad", raw_cfg="{not json")
        self.make_env("azure", "list", raw_cfg="[1, 2]")
        rows = {r["id"]: r for r in self.state()["envs"]}
        self.assertEqual(set(rows), {"aws-dev", "gcp-bad", "azure-list"})
        self.assertNotIn("error", rows["aws-dev"])
        self.assertIn("unreadable", rows["gcp-bad"]["error"])
        self.assertIn("not valid JSON", rows["gcp-bad"]["error"])
        self.assertIn("not an object", rows["azure-list"]["error"])
        self.assertEqual((rows["gcp-bad"]["vars"], rows["gcp-bad"]["tags"], rows["gcp-bad"]["allowed_ssh_cidrs"]), ({}, {}, []))

    def test_damaged_side_files_do_not_break_the_state(self):
        d = self.make_env("aws", "dev", cfg={"cloud": "aws", "env": "dev", "region": "r1", "vars": ["x"], "tags": "t", "state": "local",
                                             "allowed_ssh_cidrs": "1.2.3.4/32", "provisioned": 3})
        (d / "outputs.json").write_text("[1]")
        (d / "inventory.json").write_text('{"current": []}')
        row = self.state()["envs"][0]
        self.assertEqual((row["vars"], row["tags"], row["outputs"], row["resources"], row["provisioned"]), ({}, {}, {}, 0, []))

    def test_mcp_clients_carry_stale(self):                                    # mcp#19
        keys = list(mcp.CLIENTS)
        seen = []

        def stale(k, s=None):
            seen.append(k)
            return k == keys[0]
        st = self.state(connected={keys[0]: "http", keys[1]: "stdio"}, stale=stale)
        rows = st["mcp"]["clients"]
        self.assertTrue(rows[keys[0]]["stale"])
        self.assertFalse(rows[keys[1]]["stale"])
        self.assertEqual(seen, [keys[0]])                                        # only HTTP entries can be out of date
        self.assertTrue(all("stale" in r for r in rows.values()))

    def test_a_client_config_that_cannot_be_read_is_not_an_error(self):
        keys = list(mcp.CLIENTS)
        st = self.state(connected={keys[0]: "http"}, stale=lambda k, s=None: (_ for _ in ()).throw(ValueError("bad toml")))
        self.assertFalse(st["mcp"]["clients"][keys[0]]["stale"])


# ---------------------------------------------------------------- platform status (platform-logic#3)

class PlatformStatusTests(Isolated):
    @staticmethod
    def rel(status="deployed", revision="1", chart="c-1.0"):
        return {"status": status, "revision": revision, "chart": chart}

    def test_failed_and_pending_releases_are_reported(self):
        ctx = mock.Mock(distro="eks", target="aws")
        rel = {"trino/trino": self.rel("failed", "2"), "cert-manager/cert-manager": self.rel("pending-install"),
               "istio-system/istiod": self.rel("pending-upgrade", "3"), "probe:istio": {"status": "present"}}
        st = {n: webui._item_state(pl, ctx, n, pl.CATALOG[n], rel) for n in ("trino", "cert-manager", "istio", "istiod", "metrics-server")}
        self.assertEqual(st["trino"], {"state": "failed", "chart": "c-1.0", "status": "failed", "fix": "cs platform install trino"})
        self.assertEqual(st["cert-manager"]["state"], "pending")
        self.assertEqual(st["cert-manager"]["fix"], "cs helm uninstall cert-manager -n cert-manager, then cs platform install cert-manager")
        # the istio bundle follows its istiod release (as `cs platform status` does), not the probe
        self.assertEqual(st["istio"]["state"], "pending")
        self.assertIn("cs helm rollback istiod -n istio-system", st["istio"]["fix"])
        self.assertEqual(st["istiod"]["state"], "pending")
        self.assertIsNone(st["metrics-server"])
        self.assertEqual(webui._item_state(pl, mock.Mock(distro="gke"), "metrics-server", pl.CATALOG["metrics-server"], {}), {"state": "built-in"})
        ok = webui._item_state(pl, ctx, "trino", pl.CATALOG["trino"], {"trino/trino": self.rel()})
        self.assertEqual(ok, {"state": "installed", "chart": "c-1.0", "status": "deployed"})

    def test_platform_status_end_to_end(self):
        self.make_env("aws", "k8s", outputs={"kubernetes_cluster_name": "c1"})
        kc = self.tmp / "kubeconfig"
        kc.write_text("apiVersion: v1\n")
        fake = mock.Mock(distro="eks", target="aws")
        with mock.patch.object(webui, "_status_kubeconfig", return_value=kc), mock.patch.object(pl, "Cluster", return_value=fake), \
                mock.patch.object(webui.deps, "find", side_effect=lambda t: "/bin/helm" if t == "helm" else None), \
                mock.patch.object(pl, "installed_releases", return_value={"trino/trino": self.rel("failed"), "cert-manager/cert-manager": self.rel()}):
            r = webui.platform_status("aws-k8s")
        self.assertEqual(r["items"]["trino"]["state"], "failed")
        self.assertEqual(r["items"]["cert-manager"]["state"], "installed")
        self.assertNotIn("argo-cd", r["items"])
        with mock.patch.object(webui, "_status_kubeconfig", return_value=kc), mock.patch.object(pl, "Cluster", return_value=fake), \
                mock.patch.object(webui.deps, "find", side_effect=lambda t: "/bin/helm" if t == "helm" else None), \
                mock.patch.object(pl, "installed_releases", side_effect=pl.ClusterUnreachable("cluster aws-k8s is not reachable (x)")):
            self.assertEqual(webui.platform_status("aws-k8s"), {"error": "cluster aws-k8s is not reachable (x)"})


# ---------------------------------------------------------------- reports (webui-visual#35, resilience#15, remaining host nuance)

class ReportTests(Isolated):
    def test_dr_rows_carry_the_drill_measurements(self):                     # webui-visual#35
        d = self.make_env("aws", "dev")
        (d / "dr").mkdir()
        (d / "dr" / "drill-20260101-000000.json").write_text(json.dumps({"run": "20260101-000000", "verdict": "PASS", "rto_s": 41.5, "total_s": 90,
                                                                          "steps": [{"step": "4. restore", "ok": True, "seconds": 30}]}))
        (d / "dr" / "drill-20250101-000000.json").write_text(json.dumps({"run": "20250101-000000", "verdict": "FAIL", "rto_s": "x", "steps": []}))
        rows = webui.reports("aws-dev")["dr"]
        self.assertEqual([r["run"] for r in rows], ["20260101-000000", "20250101-000000"])
        self.assertEqual((rows[0]["rto_s"], rows[0]["total_s"], rows[0]["verdict"]), (41.5, 90, "PASS"))
        self.assertNotIn("rto_s", rows[1])                                      # not a number: the console derives it

    def test_host_scan_fallback_matches_the_cli(self):                       # remaining: legacy host reports
        f = {"status": "FAIL", "severity": "HIGH"}
        broken = {"a": {"error": "no results (see the log above)"}}
        self.assertEqual(webui.scan_verdict("host-cis", {"hosts": broken, "ansible_rc": 0, "findings": []}), "PASS")
        self.assertEqual(webui.scan_verdict("host-cis", {"hosts": broken, "ansible_rc": 2, "findings": []}), "FAIL")
        self.assertEqual(webui.scan_verdict("host-cis", {"hosts": {"a": {"score": 90}}, "ansible_rc": 0, "findings": [f]}), "FAIL")
        self.assertEqual(webui.scan_verdict("host-cis", {"hosts": broken, "findings": []}), "FAIL")             # no rc recorded: not clean
        skipped = {"a": {"error": "n/a - no STIG", "skipped": "no STIG"}, "b": {"error": "n/a - x", "skipped": "x"}}
        self.assertEqual(webui.scan_verdict("stig-host", {"hosts": skipped, "ansible_rc": 0, "findings": []}), "N/A")
        mixed = dict(skipped, c={"score": 100})
        self.assertEqual(webui.scan_verdict("stig-host", {"hosts": mixed, "findings": []}), "PASS")             # skipped is not broken
        self.assertEqual(webui.scan_verdict("host-cis", {"hosts": broken, "ansible_rc": 0, "verdict": "FAIL"}), "FAIL")   # stored wins


# ---------------------------------------------------------------- /api/creds and /api/env/use (agentic#6, webui-functional#14, e2e#22)

class CredsTests(Isolated):
    def test_empty_values_are_refused_like_the_cli(self):                    # agentic#6
        creds.save({"TS_AUTHKEY": "tskey-" + "keep-0123456789"})
        for v in ("", "   "):
            with self.assertRaisesRegex(ValueError, "empty"):
                webui.change_creds({"set": {"OK_KEY": "v", "ts_authkey": v}})
        self.assertEqual(creds.load(), {"TS_AUTHKEY": "tskey-" + "keep-0123456789"})
        self.assertEqual(undo.entries(), [])

    def test_one_creds_restore_entry_for_new_keys_too(self):                 # agentic#6
        webui.change_creds({"set": {" new_key ": "v1", "OTHER_KEY": "v2"}})
        e = undo.latest(undo.GLOBAL)
        self.assertEqual(e["kind"], "creds-restore")
        self.assertEqual(e["data"], {"values": {}, "unset": ["NEW_KEY", "OTHER_KEY"]})
        self.assertEqual(len(undo.entries(undo.GLOBAL)), 1)
        with mock.patch("sys.stdout"):
            undo.perform(e, {}, True)
        self.assertEqual(creds.load(), {})

    def test_a_failed_write_changes_nothing(self):
        creds.save({"A_KEY": "old"})
        real = creds.set_
        calls = []

        def flaky(k, v):
            calls.append(k)
            if len(calls) == 2:
                raise OSError("disk full")
            return real(k, v)
        with mock.patch.object(creds, "set_", side_effect=flaky), self.assertRaises(OSError):
            webui.change_creds({"set": {"A_KEY": "new", "B_KEY": "b"}})
        self.assertEqual(creds.load(), {"A_KEY": "old"})
        self.assertEqual(undo.entries(), [])

    def test_env_switches_share_one_coalesced_slot(self):                     # e2e#22 / webui-functional#13
        for n in ("dev", "lab"):
            self.make_env("aws", n)
        webui.use_env("aws-dev")
        webui.use_env("aws-lab")
        es = [e for e in undo.entries(undo.GLOBAL) if e["summary"].startswith("env use")]
        self.assertEqual(len(es), 1)
        self.assertEqual(es[0]["coalesce"], "current_env")
        self.assertEqual(es[0]["summary"], "env use aws-lab")
        with mock.patch("sys.stdout"):
            undo.perform(es[0], {}, True)
        self.assertNotIn("current_env", paths.load_settings())               # back to before the whole run


# ---------------------------------------------------------------- HTTP (webui-backend#24, ops#9)

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

    def req(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers={"X-CS-Token": self.token})
        r = c.getresponse()
        out = (r.status, dict(r.getheaders()), r.read())
        c.close()
        return out

    def test_api_open_is_gone(self):                                          # webui-backend#24
        with mock.patch.object(webui.webbrowser, "open", side_effect=AssertionError("must not open anything")):
            code, _, body = self.req("POST", "/api/open", {"url": "file:///etc/passwd"})
        self.assertEqual(code, 404)
        self.assertEqual(json.loads(body)["error"], "unknown api")

    def test_missing_web_files_give_a_clear_error(self):                     # ops#9
        empty = self.tmp / "noweb"
        empty.mkdir()
        with mock.patch.object(webui, "WEB_ROOT", empty):
            code, h, body = self.req("GET", "/")
        self.assertEqual(code, 500)
        self.assertTrue(h["Content-Type"].startswith("text/plain"))
        self.assertIn(b"files are missing", body)
        self.assertIn("web console files missing", webui.LOG_PATH.read_text())
        code, h, body = self.req("GET", f"/?token={self.token}")               # the real page still works
        self.assertEqual(code, 200)
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertNotIn("Location", h)

    def test_server_errors_are_one_log_line(self):                           # mcp#2: quiet handle_error
        try:
            raise RuntimeError("handler blew up")
        except RuntimeError:
            with mock.patch("sys.stderr") as err:
                self.httpd.handle_error(None, ("127.0.0.1", 5))
        err.write.assert_not_called()
        self.assertIn("RuntimeError: handler blew up", webui.LOG_PATH.read_text())
        try:
            raise ConnectionResetError()
        except ConnectionResetError:
            self.httpd.handle_error(None, ("127.0.0.1", 5))
        self.assertNotIn("ConnectionReset", webui.LOG_PATH.read_text())
        self.assertGreaterEqual(webui._Server.request_queue_size, 128)


# ---------------------------------------------------------------- serve / start (webui-backend#15, ops#9, mcp#2)

class ServeTests(Isolated):
    def test_permanent_refusals_do_not_restart_a_service(self):              # webui-backend#15
        with mock.patch("sys.stderr"):
            self.assertEqual(webui.serve("127.0.0.1", free_port()), 2)         # foreground: an error
        os.environ[webui.MANAGED_ENV] = "1"
        self.assertEqual(webui.serve("127.0.0.1", free_port()), 0)             # service: a clean exit, not restarted
        self.assertIn("cloudseed UI is disabled", webui.LOG_PATH.read_text())  # where `cs ui start` finds the reason
        paths.save_settings({"ui": True})
        self.assertEqual(webui.serve("192.0.2.1", free_port()), 0)
        self.assertIn("Refusing to listen on 192.0.2.1", webui.LOG_PATH.read_text())

    def test_missing_web_files_refuse_to_start(self):                        # ops#9
        paths.save_settings({"ui": True})
        empty = self.tmp / "noweb"
        empty.mkdir()
        (empty / "index.html").write_text("<html></html>")
        with mock.patch.object(webui, "WEB_ROOT", empty), mock.patch("sys.stderr") as err:
            self.assertEqual(webui.serve("127.0.0.1", free_port()), 1)
        said = "".join(c.args[0] for c in err.write.call_args_list)
        self.assertIn("locked.html", said)
        self.assertIn("app.js", said)
        self.assertFalse(webui.PID_PATH.exists())

    def test_bracketed_ipv6_host_is_the_address(self):                       # mcp#2 / webui-backend#24
        paths.save_settings({"ui": True})
        with mock.patch.object(webui, "_Server6", side_effect=OSError("no v6 here")) as srv6, mock.patch("sys.stderr") as err:
            self.assertEqual(webui.serve("[::1]", 7631), 1)
        self.assertEqual(srv6.call_args[0][0], ("::1", 7631))
        self.assertIn("Cannot listen on [::1]:7631", "".join(c.args[0] for c in err.write.call_args_list))
        self.assertEqual(webui.url(s={"host": "::1", "port": 7631}), "http://[::1]:7631/")

    def test_service_definitions_throttle_restarts(self):                    # webui-backend#15
        home = self.tmp / "home"
        with mock.patch.object(Path, "home", return_value=home), \
                mock.patch.object(webui.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                mock.patch.object(webui, "health", return_value=True), mock.patch.object(webui.os, "getuid", return_value=501, create=True):
            webui.start({"host": "127.0.0.1", "port": 7632, "service": "launchd"})
            import plistlib
            with open(home / "Library" / "LaunchAgents" / f"{webui.LAUNCHD_LABEL}.plist", "rb") as fh:
                plist = plistlib.load(fh)
            self.assertEqual(plist["ThrottleInterval"], webui.RESTART_THROTTLE)
            self.assertEqual(plist["KeepAlive"], {"SuccessfulExit": False})
            webui.start({"host": "127.0.0.1", "port": 7632, "service": "systemd"})
            unit = (home / ".config" / "systemd" / "user" / f"{webui.SYSTEMD_UNIT}.service").read_text()
        for line in ("StartLimitIntervalSec=300", "StartLimitBurst=5", "RestartPreventExitStatus=2", "Restart=on-failure", "KillMode=process"):
            self.assertIn(line, unit)
        self.assertLess(unit.index("StartLimitBurst"), unit.index("[Service]"))    # a [Unit] setting

    def test_start_stops_waiting_when_the_console_exits(self):               # webui-backend#15
        proc = mock.Mock()
        proc.poll.return_value = 0
        with mock.patch.object(webui, "health", return_value=False) as h:
            t0 = time.monotonic()
            self.assertFalse(webui._wait_started({"host": "127.0.0.1", "port": 7633}, "background", proc))
        self.assertLess(time.monotonic() - t0, 2)
        self.assertEqual(h.call_args[1], {"timeout": 0.5})
        with mock.patch.object(webui, "health", side_effect=[False, False, True]):
            self.assertTrue(webui._wait_started({"host": "127.0.0.1", "port": 7633}, "background", mock.Mock(**{"poll.return_value": None})))
        with mock.patch.object(webui, "health", return_value=False), mock.patch.object(webui, "_service_exited", return_value=True):
            t0 = time.monotonic()
            self.assertFalse(webui._wait_started({"host": "127.0.0.1", "port": 7633}, "launchd"))
        self.assertLess(time.monotonic() - t0, 3)
        with mock.patch.object(webui, "health", return_value=False), mock.patch.object(webui, "_service_exited", return_value=False):
            t0 = time.monotonic()
            self.assertFalse(webui._wait_started({"host": "127.0.0.1", "port": 7633}, "systemd", timeout=1.0))
        self.assertLess(time.monotonic() - t0, 3)                                # a deadline, not 40 x 2 s

    def test_service_exit_detection(self):
        def run_with(out, rc=0):
            return mock.patch.object(webui.subprocess, "run", return_value=subprocess.CompletedProcess([], rc, out, ""))
        with mock.patch.object(webui.os, "getuid", return_value=501, create=True):
            for out, want in (("\tstate = running\n\truns = 1\n\tlast exit code = (never exited)\n", False),
                              ("\tstate = not running\n\truns = 0\n\tlast exit code = (never exited)\n", False),   # not spawned yet
                              ("\tstate = not running\n\truns = 1\n\tlast exit code = 0\n\t\tstate = active\n", True),
                              ("\tstate = not running\n\tlast exit code = 1\n", True),
                              ("\tstate = spawn scheduled\n\tlast exit reason = OS_REASON_SIGNAL\n", True)):
                with run_with(out):
                    self.assertEqual(webui._service_exited("launchd"), want, out)
            with run_with("", 113):
                self.assertFalse(webui._service_exited("launchd"))
        for out, want in (("ActiveState=active\nSubState=running\n", False), ("ActiveState=inactive\nSubState=dead\n", True),
                          ("ActiveState=activating\nSubState=auto-restart\n", True), ("ActiveState=failed\nSubState=failed\n", True)):
            with run_with(out):
                self.assertEqual(webui._service_exited("systemd"), want, out)
        with mock.patch.object(webui.subprocess, "run", side_effect=FileNotFoundError("launchctl")):
            self.assertFalse(webui._service_exited("launchd"))


# ---------------------------------------------------------------- job logs on disk (remaining: defense in depth)

class JobLogScrubTests(Isolated):
    PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUSECRETBODY\n-----END OPENSSH PRIVATE KEY-----\n"

    def printer(self, text: bytes) -> list:
        p = self.tmp / "child.py"
        p.write_text(f"import sys\nsys.stdout.buffer.write({text!r})\nsys.stdout.flush()\n")
        return [sys.executable, str(p)]

    def test_finished_job_log_keeps_only_redacted_output(self):
        out = b"before AKIA" + b"IOSFODNN7EXAMPLE\n" + self.PEM.encode() + b"caf\xe9 after\n"
        with mock.patch.object(mcp, "_launcher", return_value=self.printer(out)):
            job = webui.start_job(["list"], "scrub")
        self.assertTrue(wait_for(lambda: not job.running))
        self.assertTrue(wait_for(lambda: json.loads(job.meta_path.read_text()).get("scrubbed") is True))
        disk = job.log_path.read_bytes()
        self.assertNotIn(b"AKIA" + b"IOSFODNN7EXAMPLE", disk)
        self.assertNotIn(b"SECRETBODY", disk)
        self.assertIn(b"caf\xe9 after", disk)                                   # other bytes are kept as they were
        self.assertEqual(os.stat(job.log_path).st_mode & 0o077, 0)
        self.assertEqual(job.to_dict()["lines"][0], "before [REDACTED]")
        self.assertFalse(list(webui.JOBS_DIR.glob("*.scrub")))

    def test_restored_unscrubbed_jobs_are_scrubbed(self):                     # older consoles / finished while away
        webui._jobs_dir()
        job = webui.Job("20260101-000000-abcd", ["list"], "old")
        job.log_path.write_text("token AKIA" + "IOSFODNN7EXAMPLE\n")
        job.rc, job.finished = 0, time.time()
        job.save_meta()
        webui.JOBS.clear()
        webui._restore_jobs()
        again = webui.JOBS[job.id]
        self.assertTrue(wait_for(lambda: again.scrubbed))
        self.assertNotIn("AKIA" + "IOSFODNN7EXAMPLE", again.log_path.read_text())
        self.assertTrue(wait_for(lambda: json.loads(again.meta_path.read_text()).get("scrubbed") is True))
        self.assertEqual(again.to_dict()["lines"], ["token [REDACTED]"])

    def test_a_scrub_that_fails_keeps_the_original(self):
        webui._jobs_dir()
        job = webui.Job("j1", ["list"], "x")
        self.assertFalse(webui._scrub_log(job))                                  # no log at all
        job.log_path.write_text("keep me\n")
        with mock.patch.object(webui.os, "replace", side_effect=OSError("read-only")):
            self.assertFalse(webui._scrub_log(job))
        self.assertEqual(job.log_path.read_text(), "keep me\n")
        self.assertFalse(job.scrubbed)
        self.assertFalse(list(webui.JOBS_DIR.glob("*.scrub")))


if __name__ == "__main__":
    unittest.main()
