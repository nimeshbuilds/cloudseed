"""`cs explain` everywhere, backend: explain.lookup() / names() (one structured source), `cs explain --json`, the web
console's GET /api/explain and /api/explain/names, and the MCP server's cloudseed_explain format=json and
cloudseed://explain/{query} resource.

Stdlib only, no network, no cloud. The in-process console binds an ephemeral 127.0.0.1 port."""
import contextlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import cli, clouds, explain, mcp, paths, platform as pl, secrets, ui, webui  # noqa: E402
from cloudseed import help as helpmod  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
KEYS = {"query", "found", "kind", "name", "title", "summary", "sections", "text", "commands", "also", "did_you_mean", "cli", "error"}
# secret-shaped words whose redaction patterns are case-sensitive (assembled at runtime: no scanner-shaped literal in
# the source); lower-cased before redaction they would be echoed back unmasked
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
UPPER_SECRETS = (AWS_KEY, "AIza" + "Sy" + "Ab1" * 11, "GOCSPX-" + "AbCdEfGhIjKlMnOpQrStUvWx")


def _norm(text: str) -> str:
    """Content only: no ANSI, no box drawing, no layout (wrapping, indentation, the ━━ header marks)."""
    return re.sub(r"[━│╭╮╰╯─·\\\s]", "", ui._strip(text))


def _cli(*words: str):
    """(rc, stdout) of `cs explain <words>` in-process; an Abort gives rc 1."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        try:
            rc = cli.cmd_explain(cli.build_parser().parse_args(["explain", *words]), {})
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
    return rc, buf.getvalue()


def _old_feature_page(feature: str, w: int) -> str:
    """explain.page(<feature>) before lookup() existed: the terminal page must not change."""
    f = explain.FEATURES[feature]
    what = "\n".join(explain._wrap(f["what"], max(40, w), "  ", "  "))
    out = [f"  {ui.style('━━', 'brand')} {ui.style(feature, 'bold', 'text')}", "", what, ""]
    for key, title in (("files", "Implemented in"), ("controls", "Security controls"), ("state", "State and logs"), ("commands", "Commands")):
        if f.get(key):
            out.append(f"  {ui.style(title, 'muted')}")
            for x in f[key]:
                rows = explain._wrap(x, max(24, w - 6), "", "")
                out.append(f"    {ui.style('·', 'brand')} {rows[0]}")
                out += ["      " + r for r in rows[1:]]
            out.append("")
    src = f"  source checkout: {paths.REPO_ROOT}"
    out += [ui.dim(src)] if len(src) <= w else [ui.dim("  source checkout:"), ui.dim(f"  {paths.REPO_ROOT}")]
    return "\n".join(out)


class Quiet(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("COLUMNS", None)     # pages laid out like `cs explain ... | cat`


# ---------------------------------------------------------------- lookup() and names()

class LookupTests(Quiet):
    def test_every_name_resolves_with_content(self):
        names = explain.names()
        self.assertGreater(len(names), 250)
        queries = [n["query"] for n in names]
        self.assertEqual(len(queries), len(set(queries)), "names() lists every thing once")
        for n in names:
            self.assertEqual(set(n), {"kind", "name", "summary", "query"}, n)
            self.assertTrue(n["summary"] and len(n["summary"]) <= 160, n)
            r = explain.lookup(n["query"])
            self.assertEqual(set(r) - {"cloud"}, KEYS, n)
            self.assertTrue(r["found"], (n, r["error"]))
            self.assertEqual(r["kind"], n["kind"], n)
            self.assertTrue(r["title"] and r["summary"] and r["text"].strip(), n)
            self.assertTrue(r["sections"], n)
            for sec in r["sections"]:
                self.assertEqual(set(sec), {"heading", "format", "lines"}, n)
                self.assertIn(sec["format"], ("list", "text"))
                self.assertTrue(sec["heading"] and sec["lines"], (n, sec))
                self.assertTrue(all(isinstance(x, str) for x in sec["lines"]))
            self.assertLessEqual(len(r["summary"]), 160, n)
            self.assertEqual(r["did_you_mean"], [])
            self.assertEqual(r["cli"], "cs explain " + n["query"])
            dumped = json.dumps(r)
            self.assertNotIn("\x1b", dumped, n)
            self.assertNotIn("━", r["text"], n)
            for a in r["also"]:
                self.assertEqual(set(a), {"kind", "name", "query", "cli"})
                self.assertTrue(explain.lookup(a["query"])["found"], a)

    def test_text_is_the_cli_page(self):
        """lookup()["text"] has the content `cs explain <query>` prints (the same resolution, the same renderers)."""
        for n in explain.names():
            rc, out = _cli(*n["query"].split())
            self.assertEqual(rc, 0, n)
            text = explain.lookup(n["query"])["text"]
            if n["kind"] == "group":
                # the terminal cuts the panel title to its width; every other line is the same
                body = [_norm(x) for x in out.splitlines() if x.strip() and "group ·" not in x]
                self.assertTrue(all(b in _norm(text) for b in body), n)
            else:
                self.assertEqual(_norm(out), _norm(text), n)

    def test_cli_and_lookup_resolve_the_same_way(self):
        queries = ["", "vpn", "vmware", "aws", "security", "platform", "platform security", "platform istio velero", "istio",
                   "destroy", "deps", "help", "setup aws", "topic security", "topic deps", "command vpn", "group chaos", "item velero",
                   "target vmware", "feature platform", "variables gcp", "outputs azure", "variable aws az_count", "aws az_count",
                   "vmware guest_os", "gcp project_id", "aws nope", "kubernets", "topic", "topic nope", "platform nope",
                   "variables", "variables xx", "variable", "variable aws", "variable aws nope", "variable xx az_count", "VPN", "Target VMware"]
        for q in queries:
            rc, _ = _cli(*q.split())
            self.assertEqual(rc == 0, explain.lookup(q)["found"], q)

    def test_bare_words_and_namespaces(self):
        cases = {"vpn": ("feature", "vpn"), "command vpn": ("command", "vpn"), "vmware": ("feature", "vmware"),
                 "target vmware": ("target", "vmware"), "topic vmware": ("topic", "vmware"), "aws": ("target", "aws"),
                 "security": ("group", "security"), "topic security": ("topic", "security"), "item velero": ("item", "velero"),
                 "velero": ("item", "velero"), "platform security": ("group", "security"), "platform": ("feature", "platform"),
                 "destroy": ("command", "destroy"), "envs": ("topic", "envs"), "feature dr": ("feature", "dr"),
                 "variables aws": ("topic", "variables aws"), "outputs gcp": ("topic", "outputs gcp"),
                 "variable aws single_nat_gateway": ("variable", "aws single_nat_gateway"),
                 "aws single_nat_gateway": ("variable", "aws single_nat_gateway"), "vmware guest_os": ("variable", "vmware guest_os"),
                 "  Target   VMWARE ": ("target", "vmware")}
        for q, (kind, name) in cases.items():
            r = explain.lookup(q)
            self.assertTrue(r["found"], (q, r["error"]))
            self.assertEqual((r["kind"], r["name"]), (kind, name), q)
        self.assertEqual(explain.lookup(["target", "vmware"])["kind"], "target")          # the CLI's argv as it is
        vm = explain.lookup("vmware")
        self.assertIn("STACK VARIABLES FOR VMWARE", vm["text"])                           # feature + target, like the CLI
        self.assertEqual([a["query"] for a in vm["also"]], ["topic vmware"])
        self.assertIn("topic security", [a["query"] for a in explain.lookup("security")["also"]])
        self.assertIn("command platform", [a["query"] for a in explain.lookup("platform")["also"]])
        # a word that is a command and a topic shows one page: no link to itself
        self.assertEqual(explain.lookup("topic deps")["also"], [])
        var = explain.lookup("aws single_nat_gateway")
        self.assertEqual(var["cloud"], "aws")
        self.assertEqual(var["cli"], "cs explain aws single_nat_gateway")
        self.assertIn("Default: true", var["summary"])
        self.assertIn("cs setup aws --var single_nat_gateway=<value>", var["commands"])
        self.assertIn("cs setup gcp --project-id <value>", explain.lookup("gcp project_id")["commands"])
        self.assertIn("Set by cloudseed", explain.lookup("variable aws allowed_ssh_cidrs")["summary"])

    def test_typos_get_did_you_mean(self):
        cases = {"kubernets": "kubernetes", "istoi": "istio", "bastoin": "bastion", "group secrity": "group security",
                 "target vmwre": "target vmware", "variable aws single_nat_gatway": "variable aws single_nat_gateway",
                 "variables awz": "variables aws", "platform veleor": "platform velero"}
        for q, want in cases.items():
            r = explain.lookup(q)
            self.assertFalse(r["found"], q)
            self.assertEqual((r["kind"], r["name"], r["title"], r["text"], r["sections"], r["commands"]), ("", "", "", "", [], []), q)
            self.assertIn(want, r["did_you_mean"], q)
            self.assertTrue(r["error"], q)
            for near in r["did_you_mean"]:
                self.assertTrue(explain.lookup(near)["found"], (q, near))
        self.assertIn("Did you mean: kubernetes", explain.lookup("kubernets")["error"])

    def test_index(self):
        r = explain.lookup("")
        self.assertTrue(r["found"])
        self.assertEqual((r["kind"], r["name"], r["cli"]), ("index", "", "cs explain"))
        headings = [s["heading"] for s in r["sections"]]
        for h in ("Features", "Targets", "Commands", "Topics", "Platform groups", "Platform items", "AWS variables", "VMware variables"):
            self.assertIn(h, headings)
        listed = [line.split(" — ", 1)[0] for s in r["sections"] for line in s["lines"]]
        self.assertEqual(sorted(listed), sorted(n["name"] for n in explain.names()))
        self.assertIn("Everything you can explain", r["text"])
        self.assertEqual(explain.lookup(None)["kind"], "index")

    def test_never_raises(self):
        for q in (None, "", "   ", "\x00\n\t", "'\"", "--json", "../../etc/passwd", "a" * 5000, 123, ["a", None], ("topic",), "variable aws"):
            r = explain.lookup(q)
            self.assertEqual(set(r), KEYS, q)
            json.dumps(r)
        long = explain.lookup("x" * (explain.MAX_QUERY + 1))
        self.assertFalse(long["found"])
        self.assertIn("too long", long["error"])
        with mock.patch.object(explain, "_step_data", side_effect=RuntimeError("boom")):
            r = explain.lookup("vpn")
        self.assertFalse(r["found"])
        self.assertIn("boom", r["error"])

    def test_secrets_are_masked_before_the_query_is_lower_cased(self):
        for key in UPPER_SECRETS:
            for q in (key, f"variable aws {key}", ["platform", key], f"topic {key}", f"Variable AWS {key}"):
                with self.subTest(key=key[:6], q=q):
                    r = explain.lookup(q)
                    self.assertFalse(r["found"])
                    self.assertNotIn(key.lower(), json.dumps(r).lower())
                    self.assertIn(secrets.REDACTED, r["query"])
                    self.assertIn(secrets.REDACTED, r["cli"])
                    self.assertIn(secrets.REDACTED, r["error"])
            res = explain.resolve([key])                   # what the CLI prints (and an MCP text call's child)
            self.assertNotIn(key.lower(), json.dumps(res).lower())
            self.assertEqual(res["query"], secrets.REDACTED)
            self.assertNotIn(key.lower(), json.dumps(explain.lookup("x " * explain.MAX_QUERY + key)).lower())   # too long
            with mock.patch.object(explain, "_step_data", side_effect=RuntimeError("boom")):
                r = explain.lookup(f"vpn {key}")                                                       # the fallback
            self.assertIn("boom", r["error"])
            self.assertNotIn(key.lower(), json.dumps(r).lower())
        self.assertEqual(explain.lookup("VPN")["name"], "vpn")      # ordinary words are still only lower-cased
        self.assertEqual(explain.lookup("password")["query"], "password")

    def test_lookup_prints_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            for q in ("istio", "group security", "platform", "security", "vpn", "aws az_count", ""):
                explain.lookup(q)
        self.assertEqual(out.getvalue(), "")

    def test_feature_pages_are_unchanged(self):
        for w in (60, 100, 140):
            for f in explain.FEATURES:
                self.assertEqual(explain.page(f, width=w), _old_feature_page(f, w), (f, w))
        data = explain.lookup("feature undo")
        self.assertEqual([s["heading"] for s in data["sections"]][:2], ["How it works", "Implemented in"])
        self.assertEqual(data["sections"][1]["lines"], explain.FEATURES["undo"]["files"])
        self.assertEqual(data["commands"], explain.FEATURES["undo"]["commands"])

    def test_every_wizard_question_has_a_page(self):
        for cloud in helpmod.CLOUDS:
            for q in clouds.get(cloud).questions:
                r = explain.lookup(f"variable {cloud} {q.key}")
                self.assertTrue(r["found"], (cloud, q.key))
                self.assertIn(q.key, r["title"])
            for key in webui.clouds_catalog()[cloud]["questions"]:
                self.assertTrue(explain.lookup(f"{cloud} {key['key']}")["found"], (cloud, key["key"]))

    def test_variable_rows_match_the_variables_page(self):
        for cloud in helpmod.CLOUDS:
            page_lines = helpmod.variables_page(cloud).splitlines()
            rows = explain.variable_rows(cloud)
            self.assertTrue(rows)
            for name, row in rows.items():
                mine = [x for x in page_lines if re.match(r"^  %s\s" % re.escape(name), x)]
                self.assertEqual(len(mine), 1, (cloud, name))
                if row["source"] == "cloudseed":
                    self.assertIn(row["how"], mine[0], (cloud, name))
                else:
                    self.assertIn(f"default: {row['default']}", mine[0], (cloud, name))

    def test_group_sections_name_what_the_cli_lists(self):
        for g in pl.GROUPS:
            _, out = _cli("group", g)
            listed = set(re.findall(r"○ (\S+)", ui._strip(out)))
            shown = {line.split(" — ", 1)[0] for s in explain.lookup(f"group {g}")["sections"] for line in s["lines"]}
            self.assertEqual(listed, shown, g)


class CollectorTests(unittest.TestCase):
    def test_collecting_is_per_thread(self):
        started, release = threading.Event(), threading.Event()
        seen = {}

        def other():
            with ui.collecting() as items:
                started.set()
                release.wait(5)
                ui.panel("from the thread", [("k", "v")])
            seen["items"] = items

        t = threading.Thread(target=other)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            t.start()
            started.wait(5)
            ui.panel("from main", [("a", "b")])      # printed although another thread is collecting
            release.set()
            t.join(5)
        self.assertIn("from main", buf.getvalue())
        self.assertNotIn("from the thread", buf.getvalue())
        self.assertEqual(seen["items"], [("panel", "from the thread", [("k", "v")])])
        self.assertFalse(ui.collect("panel", "x", []))    # outside a block: nothing is kept

    def test_platform_hints_are_collected(self):
        with ui.collecting() as items, contextlib.redirect_stdout(io.StringIO()) as out:
            pl.info("velero", None)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual([i[0] for i in items], ["panel", "hints"])


# ---------------------------------------------------------------- CLI

class CliTests(Quiet):
    def json_run(self, *words):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.cmd_explain(cli.build_parser().parse_args(["explain", *words, "--json"]), {})
        return rc, json.loads(buf.getvalue())

    def test_json_exit_codes_and_shape(self):
        rc, data = self.json_run("vpn")
        self.assertEqual(rc, 0)
        self.assertEqual(data, explain.lookup("vpn"))
        rc, data = self.json_run("kubernets")
        self.assertEqual(rc, 1)
        self.assertFalse(data["found"])
        self.assertIn("kubernetes", data["did_you_mean"])
        rc, data = self.json_run()
        self.assertEqual((rc, data["kind"]), (0, "index"))
        rc, data = self.json_run("platform", "security")
        self.assertEqual((rc, data["kind"]), (0, "group"))
        rc, data = self.json_run("topic", "nope")
        self.assertEqual(rc, 1)
        self.assertIn("No topic 'nope'", data["error"])
        self.assertTrue(cli.build_parser().parse_args(["explain", "--json", "aws"]).json)

    def test_text_form(self):
        rc, out = _cli("aws", "single_nat_gateway")
        self.assertEqual(rc, 0)
        self.assertIn("single_nat_gateway", out)
        self.assertIn("default", out)
        self.assertIn("also: cs explain variables aws", ui._strip(out))
        rc, _ = _cli("variable", "aws", "single_nat_gatway")
        self.assertEqual(rc, 1)
        with self.assertRaises(ui.Abort) as cm, contextlib.redirect_stdout(io.StringIO()):
            cli.cmd_explain(cli.build_parser().parse_args(["explain", "variable", "aws", "single_nat_gatway"]), {})
        self.assertIn("did you mean single_nat_gateway?", cm.exception.msg)

    def test_real_exit_codes(self):
        env = dict(os.environ, NO_COLOR="1")
        ok = subprocess.run([sys.executable, str(REPO / "bin" / "cloudseed"), "explain", "vpn", "--json"], capture_output=True, text=True,
                            env=env, timeout=60)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertTrue(json.loads(ok.stdout)["found"])
        bad = subprocess.run([sys.executable, str(REPO / "bin" / "cloudseed"), "explain", "kubernets", "--json"], capture_output=True,
                             text=True, env=env, timeout=60)
        self.assertEqual(bad.returncode, 1, bad.stderr)
        self.assertIn("kubernetes", json.loads(bad.stdout)["did_you_mean"])

    def test_help_documents_the_formats(self):
        page = helpmod.page("explain")
        for s in ("--json", "/api/explain", "cloudseed://explain/", "format=json", "variable <cloud> <name>"):
            self.assertIn(s, page)
        self.assertIn("variable <cloud> <name>", ui._strip(explain.index()))


# ---------------------------------------------------------------- web console

def _free_port() -> int:
    """A free ephemeral port chosen by the OS (bind to port 0): suites running at the same time never collide."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cs-explain-web-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        ui_dir = self.tmp / "ui"
        for p in (mock.patch.object(webui, "UI_DIR", ui_dir), mock.patch.object(webui, "JOBS_DIR", ui_dir / "jobs"),
                  mock.patch.object(webui, "TOKEN_PATH", ui_dir / "token"), mock.patch.object(webui, "STATE_PATH", ui_dir / "server.json"),
                  mock.patch.object(webui, "LOG_PATH", ui_dir / "server.log"), mock.patch.object(webui, "PID_PATH", ui_dir / "server.pid"),
                  mock.patch.object(paths, "HOME", self.tmp / "cs"), mock.patch.dict(webui.JOBS, clear=True)):
            p.start()
            self.addCleanup(p.stop)
        webui._State.token, webui._State.token_sig = None, None
        self.token = webui.ensure_token()
        self.port = _free_port()
        old = (webui._State.host, webui._State.port)
        webui._State.host, webui._State.port = "127.0.0.1", self.port
        self.addCleanup(setattr, webui._State, "host", old[0])
        self.addCleanup(setattr, webui._State, "port", old[1])
        self.httpd = webui._Server(("127.0.0.1", self.port), webui._Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def get(self, path, headers=None, token=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"X-CS-Token": self.token} if token else {}
        h.update(headers or {})
        c.request("GET", path, headers=h)
        r = c.getresponse()
        out = (r.status, dict(r.getheaders()), r.read())
        c.close()
        return out

    def test_lookup_endpoint(self):
        code, h, body = self.get("/api/explain?q=vpn")
        self.assertEqual(code, 200, body)
        self.assertEqual(h["Content-Type"], "application/json")
        self.assertIn("Content-Security-Policy", h)
        data = json.loads(body)
        self.assertEqual(set(data), KEYS)
        self.assertEqual((data["found"], data["kind"], data["name"]), (True, "feature", "vpn"))
        self.assertEqual(data, explain.lookup("vpn"))
        code, _, body = self.get("/api/explain?q=variable+aws+az_count")
        self.assertEqual((code, json.loads(body)["kind"]), (200, "variable"))
        code, _, body = self.get("/api/explain?q=group%20security")
        self.assertEqual(json.loads(body)["kind"], "group")
        code, _, body = self.get("/api/explain")
        self.assertEqual((code, json.loads(body)["kind"]), (200, "index"))
        code, _, body = self.get("/api/explain?q=kubernets")
        data = json.loads(body)
        self.assertEqual((code, data["found"]), (200, False))
        self.assertIn("kubernetes", data["did_you_mean"])

    def test_names_endpoint(self):
        code, _, body = self.get("/api/explain/names")
        self.assertEqual(code, 200)
        names = json.loads(body)["names"]
        self.assertEqual(names, explain.names())
        self.assertTrue(all(set(n) == {"kind", "name", "summary", "query"} for n in names))
        self.assertEqual(self.get("/api/explain/names/")[0], 200)

    def test_same_rules_as_every_api_read(self):
        self.assertEqual(self.get("/api/explain?q=vpn", token=False)[0], 401)
        self.assertEqual(self.get("/api/explain/names", token=False)[0], 401)
        self.assertEqual(self.get("/api/explain?q=vpn", headers={"X-CS-Token": "wrong"})[0], 401)
        self.assertEqual(self.get(f"/api/explain?q=vpn&token={self.token}", token=False)[0], 200)     # GET may carry it
        self.assertEqual(self.get("/api/explain?q=vpn", headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.get("/api/explain?q=vpn", headers={"Host": f"evil.example:{self.port}"})[0], 403)
        self.assertEqual(self.get("/api/explain?q=vpn", headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)

    def test_query_is_bounded_and_nothing_is_recorded(self):
        code, _, body = self.get("/api/explain?q=" + "a" * (explain.MAX_QUERY + 1))
        self.assertEqual(code, 400)
        self.assertIn("too long", json.loads(body)["error"])
        self.assertEqual(self.get("/api/explain?q=" + "a" * explain.MAX_QUERY)[0], 200)
        code, _, body = self.get("/api/explain?q=" + AWS_KEY)
        self.assertEqual(code, 200)
        self.assertNotIn(AWS_KEY.lower(), body.decode().lower())         # the caller's words come back redacted,
        self.assertEqual(json.loads(body)["query"], secrets.REDACTED)     # upper-case key and all
        self.assertEqual(webui.JOBS, {})                                 # documentation: no job
        self.assertFalse((self.tmp / "cs" / "logs" / "audit.jsonl").exists())   # and no audit entry


# ---------------------------------------------------------------- MCP

class McpTests(Quiet):
    def call(self, args):
        with mock.patch.object(mcp, "_spawn", side_effect=AssertionError("format=json runs in-process")):
            return mcp.call_tool("cloudseed_explain", args, dict(os.environ))

    def test_format_json(self):
        r = self.call({"what": "vpn", "format": "json"})
        self.assertFalse(r["isError"])
        data = json.loads(r["content"][0]["text"])
        self.assertEqual(data, explain.lookup("vpn"))
        r = self.call({"what": "'platform security'", "format": "json"})
        self.assertEqual(json.loads(r["content"][0]["text"])["kind"], "group")
        r = self.call({"format": "json"})
        self.assertEqual(json.loads(r["content"][0]["text"])["kind"], "index")
        r = self.call({"what": "kubernets", "format": "json"})
        self.assertTrue(r["isError"])
        self.assertIn("kubernetes", json.loads(r["content"][0]["text"])["did_you_mean"])
        for key in UPPER_SECRETS:
            r = self.call({"what": key, "format": "json"})
            self.assertNotIn(key.lower(), r["content"][0]["text"].lower())
            self.assertEqual(json.loads(r["content"][0]["text"])["query"], secrets.REDACTED)
            out = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": f"cloudseed://explain/{key}"}},
                             mcp.Session(dict(os.environ)))
            self.assertNotIn(key.lower(), out["result"]["contents"][0]["text"].lower())
        r = self.call({"what": "vpn", "format": "xml"})
        self.assertTrue(r["isError"])
        self.assertIn("invalid arguments", r["content"][0]["text"])

    def test_text_stays_the_cli(self):
        argv = mcp.TOOLS["cloudseed_explain"]["argv"]
        self.assertEqual(argv({"what": "vpn"}), ["explain", "vpn"])
        self.assertEqual(argv({"what": "vpn", "format": "text"}), ["explain", "vpn"])
        self.assertEqual(argv({"what": "vpn", "format": "json"}), ["explain", "vpn", "--json"])   # the console's form runs this
        with mock.patch.object(mcp, "_spawn", return_value=mcp._result("page", False)) as spawn:
            mcp.call_tool("cloudseed_explain", {"what": "vpn"}, dict(os.environ))
        self.assertEqual(spawn.call_args[0][1], ["explain", "vpn"])
        tool = {t["name"]: t for t in mcp.tool_list()}["cloudseed_explain"]
        self.assertEqual(tool["inputSchema"]["properties"]["format"]["enum"], ["text", "json"])
        for word in ("feature", "target", "command", "topic", "group", "item", "variable", "format=json", "cloudseed://explain/"):
            self.assertIn(word, tool["description"])

    def test_resource_template(self):
        session = mcp.Session(dict(os.environ))
        res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "resources/templates/list"}, session)["result"]
        self.assertEqual([t["uriTemplate"] for t in res["resourceTemplates"]], ["cloudseed://explain/{query}"])
        self.assertEqual(res["resourceTemplates"][0]["mimeType"], "application/json")
        cases = {"cloudseed://explain/vpn": ("feature", "vpn"), "cloudseed://explain/target%20vmware": ("target", "vmware"),
                 "cloudseed://explain/group/security": ("group", "security"),
                 "cloudseed://explain/variable/aws/az_count": ("variable", "aws az_count"),
                 "cloudseed://explain": ("index", ""), "cloudseed://explain/": ("index", "")}
        for uri, (kind, name) in cases.items():
            out = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": uri}}, session)["result"]
            self.assertEqual(out["contents"][0]["uri"], uri)
            self.assertEqual(out["contents"][0]["mimeType"], "application/json")
            data = json.loads(out["contents"][0]["text"])
            self.assertEqual((data["found"], data["kind"], data["name"]), (True, kind, name), uri)
        out = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "cloudseed://explain/kubernets"}}, session)
        data = json.loads(out["result"]["contents"][0]["text"])
        self.assertFalse(data["found"])
        self.assertIn("kubernetes", data["did_you_mean"])
        out = mcp.handle({"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "cloudseed://explainer"}}, session)
        self.assertIn("error", out)
        self.assertIn("cloudseed://explain/", mcp.INSTRUCTIONS)


if __name__ == "__main__":
    unittest.main()
