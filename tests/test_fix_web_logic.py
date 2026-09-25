"""Regression tests for the web console logic fixes (web-logic group).

Python side: the /api/run confirmation contract, the state the wizard and the undo dialog rely on, the action
effect labels, platform-status error reporting, help lookups, host-scan totals.
JavaScript side (only when `node` is installed): pure helpers of cloudseed/web/app.js - shell quoting of the
command preview, output colouring, the wizard's CIDR checks - plus source-level guards for the one-click
confirmation and palette behaviour.
"""
from __future__ import annotations

import email.message
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import paths, scan, undo, webui  # noqa: E402

APP_JS = Path(webui.WEB_ROOT) / "app.js"


def _fake_env(cloud: str, name: str, cfg: dict, outputs: dict | None = None) -> paths.Env:
    env = paths.Env(cloud, name)
    env.create_dirs()
    base = {"cloud": cloud, "env": name, "name": "acme", "region": "europe-west1", "network_cidr": "10.42.0.0/16",
            "allowed_ssh_cidrs": ["198.51.100.7/32"], "tags": {"team": "platform"}, "state": {"type": "local", "backend": None}, "vars": {}}
    base.update(cfg)
    env.save(base)
    if outputs is not None:
        (env.dir / "outputs.json").write_text(json.dumps(outputs))
    return env


def _post(path: str, body: dict, token: str = "tok") -> tuple[int, dict]:
    """Drive webui._Handler.do_POST without sockets."""
    raw = json.dumps(body).encode()
    h = webui._Handler.__new__(webui._Handler)
    h.rfile, h.wfile = io.BytesIO(raw), io.BytesIO()
    msg = email.message.Message()
    msg["X-CS-Token"] = token
    msg["Content-Length"] = str(len(raw))
    msg["Content-Type"] = "application/json"
    h.headers = msg
    h.path, h.command, h.request_version, h.requestline = path, "POST", "HTTP/1.1", f"POST {path} HTTP/1.1"
    h.client_address, h.close_connection = ("127.0.0.1", 0), False
    webui._State.token = token
    h.do_POST()
    head, _, payload = h.wfile.getvalue().partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    return status, json.loads(payload or b"{}")


class RunConfirmContractTests(unittest.TestCase):
    """webui-functional#5: destructive one-click buttons no longer send confirm=true themselves; the server answers
    a missing tick with the command it would run, and the console asks for the tick."""

    def test_build_argv_needs_confirm_carries_the_command(self):
        with self.assertRaises(webui.NeedsConfirm) as cm:
            webui.build_argv("cloudseed_platform", {"action": "uninstall", "items": ["security"], "cloud": "aws", "env": "dev"})
        self.assertIsInstance(cm.exception, PermissionError)          # older callers still see a PermissionError
        self.assertEqual(cm.exception.argv[:3], ["platform", "uninstall", "security"])
        self.assertIn("--auto-approve", cm.exception.argv)
        # read-only uses of the same tool need no tick
        self.assertEqual(webui.build_argv("cloudseed_platform", {"action": "status", "cloud": "aws", "env": "dev"})[:2], ["platform", "status"])
        # with the tick it builds normally
        self.assertIn("--auto-approve", webui.build_argv("cloudseed_platform", {"action": "install", "items": ["istio"], "confirm": True}))

    def test_api_run_answers_needs_confirm_without_starting_a_job(self):
        with mock.patch.object(webui, "start_job") as start:
            status, data = _post("/api/run", {"action": "cloudseed_chaos", "args": {"action": "run", "items": ["basic"], "cloud": "vmware", "env": "demo"}})
        start.assert_not_called()
        self.assertEqual(status, 409)       # webui-backend#1 answers a missing tick with 409 {needs_confirm, argv}; app.js handles it
        self.assertTrue(data["needs_confirm"])
        self.assertNotIn("job", data)
        self.assertEqual(data["argv"][:3], ["chaos", "run", "basic"])
        self.assertIn("confirm", data["error"])

    def test_api_run_with_confirm_starts_the_job(self):
        job = mock.Mock(id="j1")
        with mock.patch.object(webui, "start_job", return_value=job) as start:
            status, data = _post("/api/run", {"action": "cloudseed_dr", "args": {"action": "test", "cloud": "vmware", "env": "demo", "confirm": True}, "label": "DR drill"})
        self.assertEqual((status, data["job"]), (200, "j1"))
        self.assertEqual(start.call_args[0][0][:2], ["dr", "test"])


class ConsoleStateTests(unittest.TestCase):
    def setUp(self):
        self.env = _fake_env("gcp", "wlprod", {"vars": {"project_id": "acme-1", "zone": "europe-west1-b"}})
        self.recorded: list[dict] = []

    def tearDown(self):
        shutil.rmtree(self.env.dir, ignore_errors=True)
        for e in self.recorded:          # only what this test added: other tests share the journal
            undo.pop(e)

    def test_state_carries_what_change_settings_needs(self):
        # webui-functional#1: the wizard seeds 'Change settings' from the saved allow-list and tags
        row = next(e for e in webui.state()["envs"] if e["id"] == "gcp-wlprod")
        self.assertEqual(row["allowed_ssh_cidrs"], ["198.51.100.7/32"])
        self.assertEqual(row["tags"], {"team": "platform"})
        self.assertEqual((row["name"], row["region"], row["cidr"]), ("acme", "europe-west1", "10.42.0.0/16"))

    def test_undo_rows_carry_entry_ids(self):
        # webui-functional#0 / ops#0: the undo dialog can name exactly the row that was clicked
        g = undo.record(undo.GLOBAL, "creds set WL_PROBE", "creds-unset", {"keys": ["WL_PROBE"]})
        e = undo.record("gcp-wlprod", "probe", "info", {"advice": "nothing"})
        self.recorded += [g, e]
        rows = webui.state()["undo"]
        by_id = {r["id"]: r for r in rows}
        self.assertEqual(by_id[g["id"]]["scope"], "global")
        self.assertEqual(by_id[e["id"]]["scope"], "gcp-wlprod")
        self.assertEqual(rows[0]["id"], e["id"])        # newest first: the global row is not the newest overall here

    def test_platform_status_reports_abort_instead_of_dropping_the_request(self):
        # webui-functional#9: ui.Abort is a SystemExit; the status call must answer {error} with its message
        env = _fake_env("vmware", "wlk8s", {"region": "local"}, {"kubernetes_control_plane_ips": ["10.100.0.10"]})
        try:
            with mock.patch("sys.stderr", new=io.StringIO()):
                res = webui.platform_status("vmware-wlk8s")
            self.assertIn("error", res)
            self.assertIn("No kubeconfig yet", res["error"])   # the node VMs exist (control-plane IPs), no kubeconfig
            self.assertNotEqual(res["error"].strip(), "1")
        finally:
            shutil.rmtree(env.dir, ignore_errors=True)


class ReviewFollowUpTests(unittest.TestCase):
    """Review of the web-logic fixes: the wizard's required-answer check, platform status on an unusable cluster,
    scan report ordering."""

    def test_clouds_catalog_names_env_sources_without_values(self):
        # a blank GCP project / Azure subscription is filled by the CLI from the shell or the vault (GOOGLE_PROJECT,
        # ARM_SUBSCRIPTION_ID): the wizard must not refuse it as "required"
        from cloudseed import creds
        # a GUID-shaped fake (a valid answer however the catalog checks it); the runner's own variables do not count
        sub = "0000aaaa-0000-0000-0000-000000000000"
        with mock.patch.dict(os.environ, {"GOOGLE_CLOUD_PROJECT": "from-shell-1"}), \
                mock.patch.object(creds, "load", return_value={"ARM_SUBSCRIPTION_ID": sub}):
            for n in ("GOOGLE_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT", "ARM_SUBSCRIPTION_ID",
                      "AZURE_SUBSCRIPTION_ID"):
                os.environ.pop(n, None)
            cat = webui.clouds_catalog()
        q = {c: {x["key"]: x for x in cat[c]["questions"]} for c in cat}
        self.assertEqual(q["gcp"]["project_id"]["from_env"], ["GOOGLE_CLOUD_PROJECT"])
        self.assertEqual(q["azure"]["subscription_id"]["from_env"], ["ARM_SUBSCRIPTION_ID"])
        self.assertNotIn("from-shell-1", json.dumps(cat))            # names only, never values
        self.assertNotIn(sub, json.dumps(cat))
        with mock.patch.dict(os.environ, {}, clear=False), mock.patch.object(creds, "load", return_value={}):
            for n in ("GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT"):
                os.environ.pop(n, None)
            self.assertEqual({x["key"]: x for x in webui.clouds_catalog()["gcp"]["questions"]}["project_id"]["from_env"], [])

    def _k8s_env(self, name):
        env = _fake_env("vmware", name, {"region": "local"}, {"kubernetes_control_plane_ips": ["10.100.0.10"]})
        (env.dir / "k8s").mkdir(exist_ok=True)
        (env.dir / "k8s" / "kubeconfig").write_text("apiVersion: v1\nkind: Config\n")
        self.addCleanup(shutil.rmtree, env.dir, True)
        return env

    def test_platform_status_reports_an_unreachable_cluster(self):
        # webui-functional#9: a kubeconfig whose cluster does not answer used to read as "0 of N installed"
        env = self._k8s_env("wlunreach")
        refused = subprocess.CompletedProcess([], 1, "", "The connection to the server 10.100.0.10:6443 was refused\n")
        with mock.patch.object(webui.deps, "find", side_effect=lambda t: "/bin/" + t), \
                mock.patch.object(webui.subprocess, "run", return_value=refused) as run:
            res = webui.platform_status(env.id)
        self.assertIn("did not answer", res.get("error", ""))
        self.assertNotIn("items", res)
        self.assertEqual(run.call_args[0][0][:2], ["/bin/kubectl", "version"])

    def test_platform_status_never_installs_from_a_get(self):
        env = self._k8s_env("wlnohelm")
        from cloudseed import deps
        with mock.patch.object(webui.deps, "find", return_value=None), mock.patch.object(deps, "install") as install:
            res = webui.platform_status(env.id)
        self.assertIn("helm is not installed", res["error"])
        install.assert_not_called()
        gcp = _fake_env("gcp", "wlnogcloud", {"vars": {"project_id": "p", "zone": "europe-west1-b"}}, {"kubernetes_cluster_name": "c1"})
        self.addCleanup(shutil.rmtree, gcp.dir, True)
        with mock.patch.object(webui.deps, "find", return_value=None), mock.patch.object(deps, "install") as install:
            res = webui.platform_status(gcp.id)
        self.assertIn("gcloud is not installed", res["error"])
        install.assert_not_called()

    def test_scan_reports_newest_last_whatever_the_kind(self):
        # resilience#19: `cs scan reports --last 2` listed kube-/kubescape- (alphabetical), not the two newest
        d = Path(tempfile.mkdtemp()); (d / "scans").mkdir()
        self.addCleanup(shutil.rmtree, d, True)
        for n in ("kube-20260101-000000", "kubescape-20260101-000001", "fips-20260105-000000", "host-cis-20260103-120000"):
            (d / "scans" / f"{n}.json").write_text("{}")
            (d / "scans" / f"{n}.md").write_text("# report")   # a saved report has its .md twin (raw tool output has none)
        env = mock.Mock(id="aws-wlorder", dir=d)
        self.assertEqual([p.stem for p in scan.reports(env)][-2:], ["host-cis-20260103-120000", "fips-20260105-000000"])


class ActionEffectTests(unittest.TestCase):
    def test_effect_labels(self):
        # webui-functional#20: state-changing actions are not labelled read-only
        eff = {a["name"]: a["effect"] for a in webui.actions_catalog()}
        for n in ("cloudseed_update_ip", "cloudseed_provision", "cloudseed_setup", "cloudseed_destroy", "cloudseed_use", "cloudseed_enable", "cloudseed_disable"):
            self.assertEqual(eff[n], "changes", n)
        for n in ("cloudseed_platform", "cloudseed_env", "cloudseed_kubectl", "cloudseed_scan", "cloudseed_finops", "cloudseed_undo", "cloudseed_k8s"):
            self.assertEqual(eff[n], "depends", n)
        for n in ("cloudseed_status", "cloudseed_list", "cloudseed_output", "cloudseed_help", "cloudseed_plan"):
            self.assertEqual(eff[n], "read-only", n)
        # the confirm tick stays tied to destructive / destructive_when
        cat = {a["name"]: a for a in webui.actions_catalog()}
        self.assertTrue(cat["cloudseed_destroy"]["always_destructive"])
        self.assertFalse(cat["cloudseed_status"]["destructive"])


class HelpLookupTests(unittest.TestCase):
    def test_unbalanced_quote_still_answers(self):
        # webui-functional#24: shlex.split used to raise outside the try and drop the connection
        for topic in ('"unbalanced', "what's new"):
            text = webui.help_page(topic)
            self.assertIsInstance(text, str)
            self.assertTrue(text)


class HostScanTotalsTests(unittest.TestCase):
    """resilience#19: OpenSCAP host reports carry numeric pass/fail totals (and count hosts without results)."""

    def test_host_summary_totals(self):
        d = Path(tempfile.mkdtemp())
        env = mock.Mock(id="aws-wlscan", dir=d)
        env.private_key_path.return_value = d / "key"
        env.known_hosts_path.return_value = d / "known_hosts"
        cloud = mock.Mock(); cloud.ssh_user.return_value = "ops"

        class FakeProc:
            def __init__(self, cmd, **kw):
                extra = json.loads(cmd[cmd.index("-e") + 1])     # the -e vars are one JSON object (fix/ansible)
                dest = Path(extra["scan_dest"])
                (dest / "bastion").mkdir(parents=True, exist_ok=True)
                (dest / "bastion" / "results.xml").write_text("<x/>")      # the vpn host produces no results
                self.stdout = iter(())

            def wait(self):
                return 2

        parsed = {"pass": 180, "fail": 95, "notapplicable": 3, "notchecked": 0, "error": 0, "informational": 0, "notselected": 0, "unknown": 0,
                  "score": 61.2, "failed_rules": [{"id": "r1", "severity": "high", "title": "t"}]}
        with mock.patch.object(scan, "_hosts", return_value=[("bastion", "1.2.3.4"), ("vpn", "5.6.7.8")]), \
                mock.patch.object(scan.prov, "Host"), mock.patch.object(scan, "_ssg_version", return_value="0.1.82"), \
                mock.patch.object(scan.deps, "ensure_local_ansible", return_value=Path("/usr/bin/true")), \
                mock.patch.object(scan.subprocess, "Popen", FakeProc), mock.patch.object(scan, "_parse_xccdf", return_value=parsed), \
                mock.patch.object(scan, "audit"), mock.patch.object(scan, "_panel"), mock.patch.object(scan.ui, "header"):
            path = scan.host(cloud, env, {"name": "acme", "env": "dev"}, {}, ["bastion", "vpn"], "cis")
        summary = json.loads(Path(path).read_text())["summary"]
        self.assertEqual((summary["pass"], summary["fail"], summary["errors"]), (180, 95, 1))
        self.assertEqual(list(summary)[:4], ["profile", "ssg", "pass", "fail"])   # the console table shows the first four
        shutil.rmtree(d, ignore_errors=True)

    def test_hosts_without_profile_content_are_not_errors(self):
        # fix/ansible: a host whose OS has no content for the profile writes meta.json {"skipped": reason}; it is n/a,
        # neither an error nor a pass, and a report where every host is n/a persists the N/A verdict
        d = Path(tempfile.mkdtemp())
        env = mock.Mock(id="aws-wlna", dir=d)
        env.private_key_path.return_value = d / "key"
        env.known_hosts_path.return_value = d / "known_hosts"
        cloud = mock.Mock(); cloud.ssh_user.return_value = "ops"
        layout = {}

        class FakeProc:
            def __init__(self, cmd, **kw):
                dest = Path(json.loads(cmd[cmd.index("-e") + 1])["scan_dest"])
                for host, what in layout.items():
                    shutil.rmtree(dest / host, ignore_errors=True)      # two runs in one second share the run directory
                    (dest / host).mkdir(parents=True)
                    if what == "n/a":
                        (dest / host / "meta.json").write_text(json.dumps({"skipped": "no DISA STIG profile"}))
                self.stdout = iter(())

            def wait(self):
                return 0

        def run(hosts):
            layout.clear(); layout.update(hosts)
            with mock.patch.object(scan, "_hosts", return_value=[(h, "1.2.3.4") for h in hosts]), \
                    mock.patch.object(scan.prov, "Host"), mock.patch.object(scan, "_ssg_version", return_value="0.1.82"), \
                    mock.patch.object(scan.deps, "ensure_local_ansible", return_value=Path("/usr/bin/true")), \
                    mock.patch.object(scan.subprocess, "Popen", FakeProc), mock.patch.object(scan, "audit"), \
                    mock.patch.object(scan, "_panel"), mock.patch.object(scan.ui, "header"):
                return json.loads(Path(scan.host(cloud, env, {"name": "acme", "env": "dev"}, {}, list(hosts), "stig")).read_text())

        report = run({"bastion": "n/a", "vpn": "n/a"})
        self.assertEqual(report["verdict"], "N/A")
        self.assertNotIn("errors", report["summary"])
        report = run({"bastion": "n/a", "vpn": "nothing"})              # the vpn host produced no results at all
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertNotEqual(report["verdict"], "N/A")
        shutil.rmtree(d, ignore_errors=True)

    def test_show_reports_last_zero(self):
        d = Path(tempfile.mkdtemp()); (d / "scans").mkdir()
        (d / "scans" / "fips-20260101-000000.json").write_text(json.dumps({"summary": {"pass": 1}}))
        env = mock.Mock(id="aws-wl", dir=d)
        with mock.patch.object(scan.ui, "panel") as panel:
            scan.show_reports(env, 0)
        rows = panel.call_args[0][1]
        self.assertFalse(any(isinstance(r, tuple) and r[0].startswith("fips-") for r in rows))
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ app.js
def _js_block(src: str, start: str) -> str:
    """Source of one `const name = (...) => {...};` definition, found by brace matching."""
    i = src.index(start)
    j = src.index("{", i)
    depth = 0
    for k in range(j, len(src)):
        c = src[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = src.index(";", k)
                return src[i:end + 1]
    raise AssertionError(f"unbalanced block after {start}")


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class AppJsHelperTests(unittest.TestCase):
    src = APP_JS.read_text()

    def node(self, code: str):
        out = subprocess.run(["node", "-e", code], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_shell_quoting_round_trips_through_sh(self):
        # webui-functional#21: the copied command must reach the CLI with exactly the argv the console runs
        shq = _js_block(self.src, "const shq = ")
        cases = ["plain", "my stack", "cost=a&b", 'labels_extra={"a":1}', "it's", "$(id -un)", "", "=x", "cidrs=[\"10.0.0.0/8\"]", "a;b|c"]
        quoted = self.node(shq + f"\nconsole.log(JSON.stringify({json.dumps(cases)}.map(shq)));")
        self.assertEqual(quoted[0], "plain")
        for original, q in zip(cases, quoted):
            got = subprocess.run(["/bin/sh", "-c", "printf '%s' " + q], capture_output=True, text=True).stdout
            self.assertEqual(got, original, q)

    def test_output_colouring(self):
        # webui-functional#27: glyph first, then whole words; 'not installed' is never green, '0 errors' never red
        block = _js_block(self.src, "const colorize = ")
        lines = ["▲ kubectl is not installed", "✖ terraform is not installed", "  │ ✔ PASS pod-kill", "○ metrics-server   not installed",
                 "N passed   0 failed   0 skipped, 0 errors", "│ Error: invalid provider", "Apply complete! Resources: 3 added", "3 failed", "✔ installed",
                 "PASS - backup and restore are trustworthy", "[exit code 2]", "already running"]
        got = self.node("const el = (t, a) => a.class;\n" + block + f"\nconsole.log(JSON.stringify({json.dumps(lines)}.map(colorize)));")
        self.assertEqual(dict(zip(lines, got)), {
            "▲ kubectl is not installed": "warn", "✖ terraform is not installed": "bad", "  │ ✔ PASS pod-kill": "ok",
            "○ metrics-server   not installed": "dim", "N passed   0 failed   0 skipped, 0 errors": "", "│ Error: invalid provider": "bad",
            "Apply complete! Resources: 3 added": "ok", "3 failed": "bad", "✔ installed": "ok", "PASS - backup and restore are trustworthy": "ok",
            "[exit code 2]": "bad", "already running": ""})

    def test_wizard_network_checks(self):
        # webui-functional#23: bad input is caught in the wizard, like the CLI would
        code = "\n".join([_js_block(self.src, "const ipv4 = "), _js_block(self.src, "const cidrProblem = "), _js_block(self.src, "const allowProblem = ")])
        res = self.node(code + "\nconsole.log(JSON.stringify([cidrProblem('10.42.0.0/16'), cidrProblem('10.42.0.1/16'), cidrProblem('10.0.0.0/33'), cidrProblem('foo'),"
                               " allowProblem('1.2.3.4, 10.0.0.0/8'), allowProblem('0.0.0.0/0'), allowProblem('300.1.1.1'), allowProblem('2001:db8::/32')]));")
        self.assertIsNone(res[0])
        self.assertIn("10.42.0.0/16", res[1])        # suggests the network address
        self.assertIsNotNone(res[2]); self.assertIsNotNone(res[3])
        self.assertIsNone(res[4]); self.assertIn("0.0.0.0/0", res[5]); self.assertIsNotNone(res[6]); self.assertIsNone(res[7])

    def test_one_click_buttons_do_not_confirm_by_themselves(self):
        # webui-functional#5 / #6: quick() adds no confirm, the palette never installs directly
        quick = re.search(r"const quick = .*", self.src).group(0)
        self.assertNotIn("confirm", quick)
        start = self.src.index("function paletteItems()")
        palette = self.src[start:self.src.index("\n  }\n", start)]
        self.assertNotIn("quick(", palette)
        self.assertIn("openAction('cloudseed_platform', { action: 'install', items: [i.name] })", palette)
        # the wizard: a required answer the CLI takes from the environment/vault is not refused; the Options step's
        # input handlers are dropped when another step is drawn (they used to wipe the Basics errors)
        self.assertIn("!(q.from_env || []).length", self.src)
        self.assertIn("body.innerHTML = ''; body.oninput = null; body.onchange = null;", self.src)
        # no hard-coded confirm for the MCP / deps buttons either
        self.assertNotIn("{ action: 'uninstall', confirm: true }", self.src)
        self.assertNotIn("action: 'install', tools: missing.map((r) => r.tool), confirm: true", self.src)


if __name__ == "__main__":
    unittest.main()
