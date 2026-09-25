"""cloudseed web UI: a local, branded console where every cloudseed action is a form and a button.

`cs enable ui` starts it (127.0.0.1 only, token-protected, launchd/systemd user service so it survives logins) and
opens the browser; `cs ui` opens it again; `cs disable ui` stops and removes it.

Everything the UI does is a cloudseed command run as a child process (same code path as the CLI and the MCP server):
the action registry is cloudseed/mcp.py TOOLS plus a few UI-only forms (setup wizard, agents, MCP, credentials).
Output is streamed live (SSE) and redacted; credentials entered in the UI go to the local vault (creds.py) and are
injected into child processes only. No CDN, no telemetry, no dependencies beyond the standard library.

Jobs outlive the console: each one runs in its own process group (so Interrupt reaches Terraform like a terminal
Ctrl-C does) with its output in ~/.cloudseed/ui/jobs/<id>.log (0600; rewritten redacted once the job has ended), and a
restarted console (token rotation, `cs ui restart`, an upgrade) picks running and finished jobs up again instead of
killing them.
"""

from __future__ import annotations

import collections
import json
import os
import plistlib
import queue
import re
import shlex
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__, agents, audit, creds, deps, mcp, paths, secrets, skills, ui, undo

DEFAULT_PORT = 7434
UI_DIR = paths.HOME / "ui"
STATE_PATH = UI_DIR / "server.json"
TOKEN_PATH = UI_DIR / "token"
LOG_PATH = UI_DIR / "server.log"
PID_PATH = UI_DIR / "server.pid"
JOBS_DIR = UI_DIR / "jobs"
WEB_ROOT = paths.REPO_ROOT / "cloudseed" / "web"
ASSETS = paths.REPO_ROOT / "assets"
LEGACY_LAUNCHD_LABEL = "io.cloudseed.ui"   # the default home's service names (every home's, before they were per home)
LEGACY_SYSTEMD_UNIT = "cloudseed-ui"


def _default_home() -> bool:
    """True for the OS user's own cloudseed home, <passwd home>/.cloudseed, as the MCP server decides it
    (mcp._default_home). Not $HOME: a sandbox or test HOME still shares the one per-user launchd / systemd domain, so
    its home must not take the shared names either."""
    return mcp._home_path() == mcp._default_home()


# The service is per CLOUDSEED_HOME: another home's `cs enable ui` / `disable ui` must never stop or remove this one.
LAUNCHD_LABEL = LEGACY_LAUNCHD_LABEL if _default_home() else f"{LEGACY_LAUNCHD_LABEL}.{mcp._home_id()}"
SYSTEMD_UNIT = LEGACY_SYSTEMD_UNIT if _default_home() else f"{LEGACY_SYSTEMD_UNIT}-{mcp._home_id()}"
MAX_JOBS = 200
MAX_LINES = 20000          # lines of a job kept in memory: the first HEAD_LINES plus the most recent rest
HEAD_LINES = 2000
MAX_LINE_CHARS = 8000
MAX_BODY = 1 << 20         # request bodies (JSON) larger than this are refused
MANAGED_ENV = "CLOUDSEED_UI_MANAGED"   # set by the launchd/systemd/background service: `ui serve` is not a foreground run
LOOPBACK = ("127.0.0.1", "localhost", "::1")
BOOT_TAG = b'<script src="/static/boot.js"></script>'

# UI-only actions (forms the MCP registry does not carry because they are meta / interactive on the CLI). The agent
# fields list the built-in agents here; registry() replaces them on every request with the agents agents.json defines
# now (a custom agent added while the console runs can be chosen at once). `title` is the field's label in the console.
_AGENTS = ["builtin", "claude", "codex", "gemini", "grok"]
S_AGENT = {"type": "string", "title": "Agent", "enum": [""] + _AGENTS,
           "description": "blank = the selected agent; builtin needs no install; custom agents come from agents.json"}
S_MODEL = {**mcp.S_WORD, "title": "Model", "description": "model id; blank = the agent's default (Models lists them)"}
_SKILL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


def _skill_names(a: dict) -> list[str]:
    """The skill names of the skills form ('aws destroy' or 'aws, destroy'), checked before anything runs: a typo or a
    value that looks like an option (--dir=/x) is a clear message instead of a failed job or a hijacked option."""
    names = str(a.get("name") or "").replace(",", " ").split()
    for n in names:
        if not _SKILL_NAME.fullmatch(n) or not (n.lower() == "all" or skills.is_skill_name(n)):
            raise ValueError(f"name: unknown skill {n[:60]!r}. Available: {', '.join(skills.short_names())} (or all)")
    return names


def _skill_argv(a: dict) -> list[str]:
    """list takes nothing; show exactly one name; install any names (blank = all), an agent and a folder. There is no
    'project' install from the console: its jobs run in the home folder, so ./.<agent>/skills would be the agent's own
    folder anyway (install into any folder with `dir`)."""
    act = a["action"]
    if act == "show":
        names = _skill_names(a)
        if len(names) != 1 or names[0].lower() == "all":
            raise ValueError("show prints one skill: give its name, e.g. aws (list describes them all)")
        return ["skill", "show", names[0]]
    if act == "install":
        return (["skill", "install"] + _skill_names(a) + (["--agent", a["agent"]] if a.get("agent") else [])
                + (["--dir", a["dir"]] if a.get("dir") else []))
    return ["skill", act]


# setup's bearer token and service kind. Blank keeps what is deployed (a setup re-run keeps --no-auth / --no-service);
# the console cannot answer the terminal questions that offer them back, so both directions are explicit choices.
_MCP_AUTH_FLAGS = {"token": "--auth", "none": "--no-auth"}
_MCP_SERVICE_FLAGS = {"service": "--service", "background": "--no-service"}


def _mcp_argv(a: dict) -> list[str]:
    """`cs mcp ...` of the MCP form. connect / disconnect need the clients named (or all): the CLI refuses a bare
    `mcp disconnect`, and an empty list must never turn into every known client. auth / service are setup's."""
    act, clients = a["action"], list(a.get("clients") or [])
    if act in ("connect", "disconnect") and not clients:
        raise ValueError(f"clients: choose the client(s) to {act} (or all)")
    auth, service = str(a.get("auth") or ""), str(a.get("service") or "")
    if (auth or service) and act != "setup":
        raise ValueError(f"auth / service choose how setup deploys the HTTP server; {act} takes neither")
    return (["mcp", act] + clients + (["--transport", a["transport"]] if a.get("transport") else []) + (["--port", str(a["port"])] if a.get("port") else [])
            + ([_MCP_AUTH_FLAGS[auth]] if auth else []) + ([_MCP_SERVICE_FLAGS[service]] if service else [])
            + (["--auto-approve"] if act == "uninstall" else []) + (["--client", "none"] if act == "setup" and not clients else []) + ["-y"])


UI_ACTIONS: dict[str, dict] = {
    "cloudseed_agentic": {"description": "Run a natural-language task through the selected agent (built-in, Claude Code, Codex, Gemini, Grok or a custom one).",
                          "schema": mcp._p(task={"type": "string", "title": "Task", "description": "the task in plain English", "multiline": True}, agent=S_AGENT, model=S_MODEL,
                                           no_headliner={"type": "boolean", "title": "Skip the research brief", "description": "send the task without the headliner brief"}),
                          "required": ["task"], "destructive": True,
                          # a task starting with '-' would be parsed as an option: a leading space keeps it a positional (cmd_do strips it)
                          "argv": lambda a: ["agentic"] + (["--agent", a["agent"]] if a.get("agent") else []) + (["--model", a["model"]] if a.get("model") else [])
                                   + (["--no-headliner"] if a.get("no_headliner") is True else []) + ["--force", (" " + a["task"]) if a["task"].startswith("-") else a["task"]]},
    "cloudseed_enable": {"description": "Enable a feature: agentic (agent-driven tasks), headliner (a research brief for agent prompts) or mcp (the MCP server).",
                         "schema": mcp._p(feature={"type": "string", "title": "Feature", "enum": ["agentic", "headliner", "mcp"]}, agent=S_AGENT),
                         "required": ["feature"], "argv": lambda a: ["enable", a["feature"]] + (["--agent", a["agent"]] if a.get("agent") else [])},
    "cloudseed_disable": {"description": "Disable a feature: agentic, headliner or mcp.", "schema": mcp._p(feature={"type": "string", "title": "Feature", "enum": ["agentic", "headliner", "mcp"]}),
                          "required": ["feature"], "argv": lambda a: ["disable", a["feature"]]},
    "cloudseed_use": {"description": "Select the agent (and optionally its model); installs its cloudseed skills. A missing agent CLI is installed with Install (cloudseed_install).",
                      "schema": mcp._p(agent={**S_AGENT, "enum": list(_AGENTS), "description": "builtin needs no install; custom agents come from agents.json"}, model=S_MODEL),
                      "required": ["agent"], "argv": lambda a: ["use", a["agent"]] + (["--model", a["model"]] if a.get("model") else [])},
    "cloudseed_model": {"description": "Show the models of the selected agent, or pick one.", "schema": mcp._p(model={**S_MODEL, "description": "the model to select (blank = list them)"}, agent=S_AGENT),
                        "argv": lambda a: ["model"] + ([a["model"]] if a.get("model") else []) + (["--agent", a["agent"]] if a.get("agent") else [])},
    "cloudseed_agents": {"description": "What each agent is, whether it is installed and logged in.", "schema": mcp._p(), "argv": lambda a: ["agents"]},
    "cloudseed_mcp": {"description": "MCP server: deploy (setup), status, guide, connect/disconnect clients, test, start/stop/restart, token, uninstall.",
                      "schema": mcp._p(action={"type": "string", "title": "Action", "enum": ["setup", "status", "guide", "connect", "disconnect", "tools", "config", "test", "start", "stop", "restart", "logs", "token", "uninstall"]},
                                       clients={"type": "array", "title": "Clients", "items": {"type": "string", "enum": ["all"] + list(mcp.CLIENTS)},
                                                "description": "connect / disconnect (required): the clients, or all · setup: the clients to wire up (blank = none)"}, transport={"type": "string", "title": "Transport", "enum": ["", "http", "stdio"]},
                                       port={"type": "integer", "title": "Port", "minimum": 1, "maximum": 65535, "description": "setup: the HTTP server's TCP port"},
                                       auth={"type": "string", "title": "Bearer token", "enum": [""] + list(_MCP_AUTH_FLAGS),
                                             "description": "setup: token = clients must send the bearer token (again, after none) · none = no token: any local process can call every tool · blank = keep the deployed choice"},
                                       service={"type": "string", "title": "Runs as", "enum": [""] + list(_MCP_SERVICE_FLAGS),
                                                "description": "setup: service = a launchd/systemd login service (starts at login) · background = a detached background process · blank = keep the deployed choice"}), "required": ["action"],
                      "destructive_when": lambda a: a.get("action") in ("uninstall", "setup", "token"), "argv": _mcp_argv},
    # grok is not offered: it cannot load skills from a folder (they go into each task's prompt instead)
    "cloudseed_skill": {"description": "The bundled agent skills: list them, show one, or install them for an agent (all, or the ones named).",
                        "schema": mcp._p(action={"type": "string", "title": "Action", "enum": ["list", "install", "show"]},
                                         agent={**S_AGENT, "enum": ["", "claude", "codex", "gemini"], "description": "install: the agent whose skills folder gets them (blank = the selected agent, else Claude Code)"},
                                         name={"type": "string", "title": "Skill name(s)", "description": "install: names such as aws destroy (blank = all) · show: one name"},
                                         dir={**mcp.S_WORD, "title": "Folder", "description": "install: install into this folder instead of the agent's skills folder"}),
                        "required": ["action"], "argv": _skill_argv},
    "cloudseed_deps": {"description": "Dependencies: status, install tools, build the container image, set the runtime.",
                       "schema": mcp._p(action={"type": "string", "title": "Action", "enum": ["status", "install", "image", "runtime"]}, tools={"type": "array", "title": "Tools", "items": {"type": "string"}},
                                        mode={"type": "string", "title": "Runtime", "enum": ["", "auto", "local", "container"]}),
                       "required": ["action"], "destructive_when": lambda a: a.get("action") in ("install", "image"),
                       "argv": lambda a: ["deps", a["action"]] + (list(a.get("tools") or ["terraform"]) if a["action"] == "install" else []) + ([a.get("mode") or "auto"] if a["action"] == "runtime" else [])},
    "cloudseed_vpn_connect": {"description": "Connect / disconnect this machine's OpenVPN client (Tailscale: tailscale up). OpenVPN runs as root and the console cannot answer a sudo "
                                             "password prompt: this needs passwordless sudo for openvpn (and kill, to disconnect), or an askpass "
                                             "helper (SUDO_ASKPASS) that asks for the password; otherwise run `cs vpn connect <cloud> --env <name>` "
                                             "in a terminal.",
                              "schema": mcp._p(action={"type": "string", "title": "Action", "enum": ["connect", "disconnect"]}, cloud=mcp.S_CLOUD, env=mcp.S_ENV,
                                               user={**mcp.S_WORD, "title": "VPN user", "description": "connect: the client profile to use (created when missing)"}),
                              "required": ["action", "cloud"], "destructive": True, "preflight": lambda a: _vpn_preflight(a),
                              "argv": lambda a: ["vpn", a["action"], a["cloud"]] + (["--env", a["env"]] if a.get("env") else []) + (["--user", a["user"]] if a.get("user") else [])},
}


def _managed_mutating(a: dict) -> bool:
    """Databricks / Snowflake passthrough: only status / test / help run without the tick (fails closed). Mirrors
    cmd_managed: `--profile X` / `--env X` are cloudseed's own options, everything else from the first remaining word
    on goes to the vendor CLI (so `--profile status clusters delete x` is a delete, not a status)."""
    try:
        words = shlex.split(a.get("args") or "")
    except ValueError:
        return True
    rest, i = [], 0
    while i < len(words):
        w = words[i]
        if w in ("--profile", "--env", "-e"):
            i += 2
            continue
        if not w.startswith(("--profile=", "--env=")) and w != "--":
            rest.append(w)
        i += 1
    return bool(rest) and rest[0] not in ("status", "test", "help")


def _scan_mutating(a: dict) -> bool:
    """host / stig / all install OpenSCAP on the hosts (become); kube / images / cloud install their scanner on this
    machine the first time (brew, a vendor install script, a pip venv), like `cloudseed install` which needs the tick."""
    kind = a.get("kind")
    if kind in ("host", "stig", "all"):
        return True
    if kind == "kube":
        return not deps.find("kubescape")
    if kind == "images":
        return not deps.find("trivy")
    if kind == "cloud":   # a local (VMware) environment has no cloud account: the scan stops before installing prowler
        return not _local_cloud(a.get("cloud")) and not (paths.HOME / "venv-prowler" / "bin" / "prowler").exists()
    return False


def _local_cloud(cloud) -> bool:
    """True for a local target (VMware); False for a cloud, for no cloud given (the current environment's may be
    either) and for a name that is not a target."""
    if not cloud or cloud not in mcp.CLOUDS:
        return False
    from . import clouds
    try:
        return bool(clouds.get(cloud).local)
    except Exception:  # noqa: BLE001 - unknown: gate as for a cloud (fails closed)
        return False


# Extra safety for registry tools in the console, on top of their own destructive / destructive_when (either one asks
# for the tick): these change infrastructure or run things on hosts, so they never run from one stray click.
UI_GATES: dict[str, object] = {
    "cloudseed_update_ip": True,                                                            # terraform apply of the SSH allow-list
    "cloudseed_provision": True,                                                            # Ansible with root on the hosts
    "cloudseed_managed": _managed_mutating,                                                 # any databricks/snowflake command
    "cloudseed_vpn": lambda a: a.get("action") in ("revoke", "provision", "add-user"),
    "cloudseed_scan": _scan_mutating,                                                       # OpenSCAP on hosts; first-run scanner installs
}


_AGENT_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


def _with_enum(t: dict, field: str, values: list[str]) -> dict:
    """A copy of an action whose `field` offers `values` (the shared definition is never changed)."""
    props = dict(t["schema"]["properties"])
    props[field] = dict(props[field], enum=values)
    return dict(t, schema=dict(t["schema"], properties=props))


def registry() -> dict[str, dict]:
    """Every action the console offers: the MCP tools plus the UI-only forms, whose agent choices are the agents known
    right now (built-in ones plus agents.json; a name that would read as an option is left out)."""
    out = dict(mcp.TOOLS)
    out.update(UI_ACTIONS)
    try:
        reg = {k: v for k, v in agents.registry().items() if isinstance(k, str) and _AGENT_KEY.fullmatch(k) and isinstance(v, dict)}
    except Exception:  # noqa: BLE001 - an unreadable agents.json leaves the built-in choices
        return out
    keys = list(reg)
    out["cloudseed_use"] = _with_enum(out["cloudseed_use"], "agent", keys)
    for name in ("cloudseed_agentic", "cloudseed_enable", "cloudseed_model"):
        out[name] = _with_enum(out[name], "agent", [""] + keys)
    # skills go into an agent's skills folder: agents without one (and the built-in agent, which reads them from the
    # repo) are not offered; the CLI maps builtin to Claude Code
    out["cloudseed_skill"] = _with_enum(out["cloudseed_skill"], "agent", [""] + [k for k, v in reg.items() if v.get("skills_dir") and not v.get("builtin")])
    return out


def _find_env(cloud, name) -> paths.Env | None:
    """The environment a <cloud> [--env name] form names, resolved like the CLI (default: the only one of the cloud,
    else dev); None when there is no such environment."""
    envs = [e for e in paths.Env.list_all() if e.cloud == cloud]
    if not name:
        name = envs[0].name if len(envs) == 1 else "dev"
    return next((e for e in envs if e.name == name), None)


def _sudo_ok(cmd: str, run: list[str] | None = None) -> bool:
    """Whether sudo runs `cmd` without a password for a process without a terminal (what a console job is): a
    passwordless rule for everything, or one for this command. `run` is a harmless run of the command itself
    (kill -0 <pid>), the exact test; without it, whether sudo lists the command - which says it is allowed, not that
    it needs no password (a NOPASSWD rule for anything else is enough to list), so a job may still be refused.
    True when it cannot be told (the job then reports)."""
    sudo = shutil.which("sudo")
    if not sudo:
        return True
    kw: dict = {"capture_output": True, "text": True, "timeout": 10, "stdin": subprocess.DEVNULL, "start_new_session": True}
    for probe in ([sudo, "-n", "true"], [sudo, "-n", *run] if run else [sudo, "-n", "-l", cmd]):
        try:
            if subprocess.run(probe, **kw).returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            return True
    return False


def _vpn_preflight(a: dict) -> None:
    """The OpenVPN client runs as root through sudo, and a console job has no terminal to type the password into: sudo
    would fail (and an older disconnect then reported success while openvpn kept running). Refuse up front, with the
    terminal command, unless sudo works without a password (or there is nothing to do: already connected / not
    connected, a Tailscale VPN, openvpn not installed yet, running as root) or an askpass helper (SUDO_ASKPASS or
    sudo.conf) is set up: the job's `sudo -A` then asks for the password through it."""
    from . import services
    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        return
    env = _find_env(a.get("cloud"), a.get("env"))
    if env is None:
        return                          # the command says which environments exist
    cfg, _problem = env.try_load()
    outputs = _json_obj(env.dir / "outputs.json")
    try:
        vpn_type = services._vpn_type({"vars": _dict(cfg.get("vars"))}, outputs)
    except Exception:  # noqa: BLE001
        vpn_type = "openvpn"
    if vpn_type != "openvpn" or not outputs.get("vpn_public_ip"):
        return                          # Tailscale needs no sudo; no VPN host yet: the command explains
    running = services._running(env) if (env.dir / "vpn" / "openvpn.pid").exists() else None
    if a.get("action") == "connect":
        need, run = (None if running else deps.find("openvpn")), None
    else:   # disconnect runs `sudo kill -TERM <pid>`: signal 0 as root tests exactly that, and changes nothing
        need, run = ("kill", ["kill", "-0", str(running)]) if running else (None, None)
    if not need or services._askpass() or _sudo_ok(need, run):
        return
    if run and not services._running(env):
        return                          # it ended meanwhile: nothing to do
    what = "openvpn" if a.get("action") == "connect" else "kill"
    user = f" --user {a['user']}" if a.get("action") == "connect" and a.get("user") else ""
    raise ValueError(f"vpn {a.get('action')} needs your sudo password, and the console cannot ask for it (its jobs have no terminal). "
                     f"Run it in a terminal: cs vpn {a.get('action')} {env.cloud} --env {env.name}{user}   (or allow passwordless "
                     f"sudo for {what}, or set up an askpass helper: SUDO_ASKPASS)")


def is_destructive(name: str, t: dict, args: dict) -> bool:
    if mcp._is_destructive(t, args):
        return True
    gate = UI_GATES.get(name)
    return gate is True or bool(callable(gate) and gate(args))


# What running an action does, for the console's label (the confirm tick stays tied to destructive/destructive_when):
# 'changes' = always writes something (config, hosts, settings, installs); 'depends' = read-only for some actions or
# arguments only; everything else is read-only. A tool may also carry mutates / mutates_when itself.
EFFECT = {"cloudseed_setup": "changes", "cloudseed_update_ip": "changes", "cloudseed_provision": "changes", "cloudseed_enable": "changes",
          "cloudseed_disable": "changes", "cloudseed_use": "changes", "cloudseed_env": "depends", "cloudseed_k8s": "depends",
          "cloudseed_scan": "depends", "cloudseed_finops": "depends", "cloudseed_managed": "depends", "cloudseed_model": "depends",
          "cloudseed_skill": "depends"}


def action_effect(name: str, t: dict) -> str:
    if t.get("destructive") or t.get("mutates"):
        return "changes"
    if name in EFFECT:
        return EFFECT[name]
    return "depends" if (t.get("destructive_when") or t.get("mutates_when")) else "read-only"


_TITLE_WORDS = {"env": "environment", "id": "ID", "ip": "IP", "cidr": "CIDR", "ssh": "SSH", "vpn": "VPN", "dr": "DR", "k8s": "Kubernetes",
                "mcp": "MCP", "url": "URL", "fips": "FIPS", "tf": "Terraform", "ui": "UI", "os": "OS", "vars": "variables",
                "workdir": "working directory", "args": "arguments", "dir": "folder"}


def _title(key: str) -> str:
    """A field's label for the console: allow_ip -> "Allow IP", env -> "Environment" (the argument name stays the key)."""
    text = " ".join(_TITLE_WORDS.get(w, w) for w in key.split("_") if w)
    return text[:1].upper() + text[1:]


# How a registry field is best entered, for any client of /api/actions (the definitions in mcp.py stay as they are):
# helm --set values one per line (a list like hosts={a,b} is one value, so no comma splitting).
FIELD_HINTS = {"cloudseed_platform": {"set": {"x-lines": True}}}


def _titled(schema: dict, hints: dict | None = None) -> dict:
    """A copy of an action's schema whose fields carry a `title` and the action's FIELD_HINTS (the shared definitions
    are never changed)."""
    props = schema.get("properties") or {}
    out = {}
    for k, v in props.items():
        if isinstance(v, dict):
            v = dict(v, **(hints or {}).get(k, {}))
            if not v.get("title"):
                v["title"] = _title(k)
        out[k] = v
    return dict(schema, properties=out)


def actions_catalog() -> list[dict]:
    """Every action with its schema, grouped for the UI; every field has a human `title` for its label."""
    groups = {"Discover": ["cloudseed_list", "cloudseed_doctor", "cloudseed_status", "cloudseed_output", "cloudseed_inventory", "cloudseed_env", "cloudseed_troubleshoot"],
              "Build & change": ["cloudseed_setup", "cloudseed_plan", "cloudseed_apply", "cloudseed_update_ip", "cloudseed_provision", "cloudseed_undo", "cloudseed_destroy"],
              "Kubernetes & platform": ["cloudseed_k8s", "cloudseed_node", "cloudseed_platform", "cloudseed_kubectl", "cloudseed_helm"],
              "Access & services": ["cloudseed_ssh", "cloudseed_vpn", "cloudseed_vpn_connect", "cloudseed_managed"],
              "Resilience & compliance": ["cloudseed_dr", "cloudseed_chaos", "cloudseed_scan"],
              "Cost": ["cloudseed_finops"],
              "Agents & MCP": ["cloudseed_agentic", "cloudseed_enable", "cloudseed_disable", "cloudseed_use", "cloudseed_model", "cloudseed_agents", "cloudseed_mcp", "cloudseed_skill"],
              "Tools & help": ["cloudseed_deps", "cloudseed_install", "cloudseed_help", "cloudseed_explain"]}
    reg = registry()
    out = []
    for group, names in groups.items():
        for n in names:
            t = reg.get(n)
            if not t:
                continue
            schema = _titled(t["schema"], FIELD_HINTS.get(n))
            if t.get("required"):
                schema["required"] = t["required"]
            always = bool(t.get("destructive")) or UI_GATES.get(n) is True
            out.append({"name": n, "group": group, "description": t["description"], "schema": schema,
                        "destructive": always or bool(t.get("destructive_when")) or n in UI_GATES, "always_destructive": always,
                        "effect": action_effect(n, t)})
    return out


class NeedsConfirm(PermissionError):
    """A state-changing action was sent without the explicit tick; carries the command it would run (HTTP 409)."""

    def __init__(self, msg: str, argv: list[str] | None = None):
        super().__init__(msg)
        self.argv = list(argv or [])


class Conflict(Exception):
    """Another job is already working on the same environment (HTTP 409)."""

    def __init__(self, msg: str, job: str):
        super().__init__(msg)
        self.job = job


def _check(path: str, spec: dict, v):
    """Validate / normalise one argument against its (subset of) JSON schema. Raises ValueError naming the field."""
    typ = spec.get("type")
    if typ == "string":
        if isinstance(v, bool) or not isinstance(v, (str, int, float)):
            raise ValueError(f"{path}: expected text")
        v = str(v)
        if "\x00" in v:
            raise ValueError(f"{path}: contains a NUL character")
    elif typ == "integer":
        if isinstance(v, str) and re.fullmatch(r"\s*-?\d+\s*", v):
            v = int(v)
        elif isinstance(v, float) and v.is_integer():
            v = int(v)
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{path}: expected a whole number")
    elif typ == "boolean":
        if not isinstance(v, bool):
            raise ValueError(f"{path}: expected true or false")
    elif typ == "array":
        if not isinstance(v, list):
            raise ValueError(f"{path}: expected a list")
        items = spec.get("items") or {}
        v = [_check(f"{path}[{i}]", items, x) for i, x in enumerate(v)] if items else list(v)
    elif typ == "object":
        if not isinstance(v, dict):
            raise ValueError(f"{path}: expected an object like {{\"key\": \"value\"}}")
        extra = spec.get("additionalProperties")
        if isinstance(extra, dict) and extra.get("type"):
            v = {str(k): _check(f"{path}.{k}", extra, x) for k, x in v.items()}
    if spec.get("enum") is not None and v not in spec["enum"]:
        raise ValueError(f"{path}: must be one of: {', '.join(repr(x) for x in spec['enum'] if x != '') or '(empty)'}")
    return v


def validate_args(name: str, t: dict, args) -> dict:
    """Check the arguments of an action against its schema: required fields, types, enums. Blank optional fields are
    dropped; unknown keys are ignored (argv builders only read declared fields); `confirm` must be a real boolean."""
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ValueError("args must be a JSON object")
    props = (t.get("schema") or {}).get("properties") or {}
    out: dict = {}
    for k, v in args.items():
        if k == "confirm":
            if not isinstance(v, bool):
                raise ValueError("confirm: expected true or false")
            out[k] = v
            continue
        spec = props.get(k)
        if spec is None or v is None:
            continue
        if v == "" and "" not in (spec.get("enum") or []):
            continue
        v = _check(k, spec, v)
        err = mcp._check(spec, v, k)   # the shared rules too: patterns (no value that looks like an option), minimums
        if err:
            raise ValueError(err)
        out[k] = v
    missing = [k for k in t.get("required") or [] if out.get(k) in (None, "", []) or (isinstance(out.get(k), str) and not out[k].strip())]
    if missing:
        raise ValueError(f"{name.replace('cloudseed_', '')}: missing required field(s): {', '.join(missing)}")
    return out


def build_argv(name: str, args: dict) -> list[str]:
    t = registry().get(name)
    if not t:
        raise ValueError(f"unknown action {name}")
    a = validate_args(name, t, args)
    try:
        destructive = is_destructive(name, t, a)
        argv = [str(x) for x in t["argv"](a)]
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as e:
        raise ValueError(f"invalid arguments for {name.replace('cloudseed_', '')}: {e}") from None
    if destructive and a.get("confirm") is not True:   # the preview shows secret values masked, as the CLI echoes them
        raise NeedsConfirm(f"{name} changes infrastructure or runs a task; tick 'I understand' to confirm.", audit.safe_argv(argv))
    if t.get("preflight"):
        try:
            t["preflight"](a)                               # ValueError: why it cannot work from the console
        except ValueError:
            raise
        except Exception:  # noqa: BLE001 - a check that cannot be made lets the command run and report
            pass
    return argv


READ_ONLY_COMMANDS = ("help", "explain", "list", "agents", "status", "output", "inventory", "doctor", "troubleshoot")
_GLOBAL_VALUED = ("--runtime", "--engine")   # top-level options that take a value (cli._GLOBAL_VALUED)


def _skip_globals(argv: list[str]) -> int:
    """Index of the first word after the leading global options (-y/--yes, --runtime X, --engine=X): the command."""
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-y", "--yes"):
            i += 1
        elif tok.partition("=")[0] in _GLOBAL_VALUED:
            i += 1 if "=" in tok else 2
        else:
            break
    return i


def raw_argv(body: dict) -> list[str]:
    """A raw `{"argv": [...]}` request (scripts; the console itself always sends an action). Anything but a read-only
    command needs `"confirm": true` like the actions do, and the non-interactive -y goes first, never after `--`."""
    argv = body.get("argv")
    if not isinstance(argv, list) or not argv or any(isinstance(a, (bool, dict, list)) or a is None for a in argv):
        raise ValueError("argv must be a non-empty list of strings")
    argv = [str(a) for a in argv]
    if any("\x00" in a for a in argv):
        raise ValueError("argv contains a NUL character")
    g = _skip_globals(argv)
    rest = argv[g:]
    if len(rest) >= 2 and rest[1] == "mcp" and rest[0] in ("setup", "status", "destroy"):   # the CLI's alias, spelled out
        argv = argv[:g] + ["mcp", {"setup": "setup", "status": "status", "destroy": "uninstall"}[rest[0]]] + rest[2:]
    head = argv[:argv.index("--")] if "--" in argv else argv
    cmd = next((a for a in head[g:] if not a.startswith("-")), "")   # `--runtime local setup ...` is a setup
    if cmd in ("ssh", "k9s") and "--" not in argv:
        raise ValueError("interactive commands need a remote command (use the SSH action)")
    if cmd not in READ_ONLY_COMMANDS and body.get("confirm") is not True:
        raise NeedsConfirm(f"`cloudseed {cmd}` can change things; send \"confirm\": true to run it.", audit.safe_argv(argv))
    if "-y" not in head and "--yes" not in head:
        argv = ["-y"] + argv
    return argv


# ---------------------------------------------------------------- jobs

_NL = re.compile(rb"\r\n|\r|\n")
_RUNNER = ('trap ":" INT TERM HUP; rcf=$1; shift; "$@"; rc=$?; '
           '(umask 077; printf "%s\\n" "$rc" > "$rcf.tmp") && mv -f "$rcf.tmp" "$rcf"; exit $rc')
_USE_RUNNER = os.name != "nt" and os.path.exists("/bin/sh")


def _split_lines(buf: bytes) -> tuple[list[bytes], bytes]:
    """Complete lines of a byte buffer (\\n, \\r\\n or a lone \\r end a line) and the incomplete rest."""
    hold = b""
    if buf.endswith(b"\r"):          # maybe the first half of \r\n: decide when the next chunk arrives
        buf, hold = buf[:-1], b"\r"
    parts = _NL.split(buf)
    rest = parts.pop() + hold
    if len(rest) > 65536:            # binary output without newlines: do not buffer forever
        parts.append(rest)
        rest = b""
    return parts, rest


def _clean(raw: bytes, red: secrets.StreamRedactor | None = None) -> str | None:
    """One output line, decoded leniently, capped and redacted. With a per-stream `red`, a private key spanning several
    lines is swallowed whole: its body lines give None (not pushed at all)."""
    line = raw.decode("utf-8", errors="replace")   # one Latin-1 byte must never kill the job's output stream
    if len(line) > MAX_LINE_CHARS:
        line = line[:MAX_LINE_CHARS] + f" … [{len(line) - MAX_LINE_CHARS} more characters]"
    if red is None:
        return secrets.redact(line)
    out = red.feed(line)
    return None if line and not out else out


def _push_raw(job: "Job", raw: bytes, red: secrets.StreamRedactor) -> None:
    line = _clean(raw, red)
    if line is not None:
        job.push(line)


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, path)


def _proc_cmdline(pid: int) -> str | None:
    """The command line of a process (None when unknown: no `ps` here)."""
    ps = shutil.which("ps")
    if not ps:
        return None
    try:   # -ww: never cut to a terminal/COLUMNS width (the markers we look for sit far to the right)
        r = subprocess.run([ps, "-ww", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else ""


def _alive(pid: int | None, marker: str | None = None) -> bool:
    """True when `pid` is running (and, with `marker`, its command line contains it: a reused pid is not ours)."""
    if not pid or pid <= 0:
        return False
    if os.name == "nt":             # os.kill(pid, 0) would send CTRL_C_EVENT there; identity cannot be checked either
        return marker is None
    try:
        os.kill(pid, 0)
    except OSError:                 # gone, or another user's process (a reused pid): not ours either way
        return False
    if marker:
        cmd = _proc_cmdline(pid)
        if cmd is not None and marker not in cmd:
            return False
    return True


class Job:
    def __init__(self, jid: str, argv: list[str], label: str, key: str | None = None, started: float | None = None):
        # the command as it may be shown and kept (ui/jobs/<id>.json, /api/state): secret values masked like the CLI's
        # own audit trail does (audit.safe_argv); the job itself runs the real argv, which is never stored
        self.id, self.argv, self.label, self.key = jid, audit.safe_argv([str(a) for a in argv]), secrets.redact(label), key
        self.head: list[tuple[int, str]] = []
        self.tail: collections.deque = collections.deque(maxlen=MAX_LINES - HEAD_LINES)
        self.seq = 0                   # number of lines pushed so far (SSE event ids)
        self.rc: int | None = None
        self.started = started or time.time()
        self.finished: float | None = None
        self.proc: subprocess.Popen | None = None   # the runner, when this server started it
        self.pid: int | None = None                 # the runner's pid = the job's process group
        self.cancels = 0               # interrupts sent so far (kept in the meta file: a restarted console counts on)
        self.killed = False            # the third interrupt's SIGKILL was delivered by a console (not "lost")
        self.lost = False
        self.meta_lock = threading.Lock()   # the follow thread and a request (interrupt) both write the meta file
        self.subscribers: list[queue.Queue] = []
        self.lock = threading.Lock()
        self._loaded = True            # False for a finished job restored from disk until its log is read
        self._load_lock = threading.Lock()
        self.saved_lines = 0           # line count recorded on disk (reported until the log has been read again)
        self.log_lock = threading.Lock()   # console notes appended to the log vs. the rewrite that scrubs it
        self.scrubbed = False          # the log on disk holds only redacted output (rewritten once the job ended)

    # ---- files
    @property
    def log_path(self) -> Path:
        return JOBS_DIR / f"{self.id}.log"

    @property
    def meta_path(self) -> Path:
        return JOBS_DIR / f"{self.id}.json"

    @property
    def rc_path(self) -> Path:
        return JOBS_DIR / f"{self.id}.rc"

    @property
    def running(self) -> bool:
        with self.lock:
            return self.rc is None

    def save_meta(self) -> None:
        with self.meta_lock:
            try:
                _write_json(self.meta_path, {"id": self.id, "argv": self.argv, "label": self.label, "key": self.key, "started": self.started,
                                             "pid": self.pid, "rc": self.rc, "finished": self.finished, "lost": self.lost, "scrubbed": self.scrubbed,
                                             "cancels": self.cancels, "killed": self.killed, "interrupted": self.cancels > 0,
                                             "lines": self.seq if self._loaded else max(self.seq, self.saved_lines)})
            except OSError:
                pass

    # ---- output
    def push(self, line: str) -> None:
        with self.lock:
            self.seq += 1
            item = (self.seq, line)
            if len(self.head) < HEAD_LINES:
                self.head.append(item)
            else:
                self.tail.append(item)
            subs = list(self.subscribers)
        for q in subs:
            q.put(item)

    def finish(self, rc: int, lost: bool = False) -> None:
        with self.lock:
            if self.rc is not None:
                return
            self.lost = lost
            self.finished = self.finished or time.time()
            self.rc = rc
            subs = list(self.subscribers)
            # Publish completion only after its durable record is written. Status readers (and pruning) must not
            # observe a finished job while a restart would still restore rc=null, especially after an adopted kill.
            self.save_meta()
        for q in subs:
            q.put(None)

    def _snapshot(self) -> list[tuple[int, str]]:
        """(event id, line) pairs kept in memory; a marker line stands in for what was dropped from the middle."""
        out = list(self.head)
        if self.tail:
            first = self.tail[0][0]
            gap = first - (self.head[-1][0] if self.head else 0) - 1
            if gap > 0:
                out.append((first - 1, f"[ui] … {gap} lines omitted here (the console keeps the first {HEAD_LINES} and the last "
                                       f"{self.tail.maxlen} lines); the full output is in {self.log_path} …"))
            out.extend(self.tail)
        return out

    def ensure_loaded(self) -> None:
        """A finished job restored from disk reads its log only when someone looks at it."""
        if self._loaded:
            return
        with self._load_lock:
            if self._loaded:
                return
            red = secrets.StreamRedactor()   # one per stream: multi-line private keys are redacted whole
            try:
                with open(self.log_path, "rb") as fh:
                    buf = b""
                    while True:
                        chunk = fh.read(1 << 16)
                        if not chunk:
                            break
                        lines, buf = _split_lines(buf + chunk)
                        for raw in lines:
                            _push_raw(self, raw, red)
                    buf = buf.rstrip(b"\r")
                    if buf:
                        _push_raw(self, buf, red)
            except OSError:
                self.push(f"[ui] the output of this job is no longer available ({self.log_path})")
            self._loaded = True

    def to_dict(self, tail: int | None = None) -> dict:
        """tail=None: every line kept; tail=0: no lines (job lists, SSE 'done'); tail=N: the last N lines."""
        if tail is None or tail > 0:
            self.ensure_loaded()
        with self.lock:
            snap = self._snapshot() if tail is None or tail > 0 else []
            count, rc, finished = (self.seq if self._loaded else max(self.seq, self.saved_lines)), self.rc, self.finished
        if tail is not None and tail > 0:
            snap = snap[-tail:]
        # interrupted: someone pressed Interrupt (in any tab, before a console restart too: the count is in the meta
        # file), so an exit code 130 / 137 / 1 afterwards is the interrupt taking effect, not a failure
        return {"id": self.id, "label": self.label, "argv": self.argv, "rc": rc, "running": rc is None, "lost": self.lost, "env": self.key,
                "interrupted": self.cancels > 0, "interrupts": self.cancels,
                "started": datetime.fromtimestamp(self.started, timezone.utc).isoformat(timespec="seconds"),
                "seconds": round((finished or time.time()) - self.started, 1), "line_count": count, "lines": [line for _, line in snap]}


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


def child_env() -> dict:
    """Environment of a job: the real shell environment (never the vault values this server was started with: the
    child reads the vault itself, so a credential changed or cleared in the console reaches the very next job)."""
    with creds._LOCK:   # a concurrent creds.refresh() must not change os.environ while it is being copied
        e = creds.shell_env(deps.path_env())
    for k in (MANAGED_ENV, "CLOUDSEED_UI_FORCE"):
        e.pop(k, None)
    if e.get("XPC_SERVICE_NAME") in (LAUNCHD_LABEL, LEGACY_LAUNCHD_LABEL):   # launchd's name for the console, not for its jobs
        e.pop("XPC_SERVICE_NAME", None)
    e.update({"NO_COLOR": "1", "CLOUDSEED_UI": "1", "PYTHONUNBUFFERED": "1", "TERM": "dumb"})
    if paths.IS_BUNDLE:
        # Jobs survive console restarts, so their bundled Terraform, skills and
        # playbooks must not share the console's temporary extraction directory.
        e["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return e


# commands (and subcommands) that write an environment's working directory, state or cluster: one at a time per env.
# One definition for the console, the audit trail and troubleshoot (audit.MUTATING / SUB_MUTATING).
_MUTATING = audit.MUTATING
_SUB_MUTATING = audit.SUB_MUTATING
# global undo entries that change no environment and no tool a running job uses: settings, the vault, advice only
_UNDO_HARMLESS = ("settings-restore", "creds-restore", "info")


def _undo_entry_key(entry_id: str, depth: int = 0) -> str | None:
    """What undoing one journal entry (by id) touches: its environment, None for a global entry that changes no
    environment (settings, credentials, the console or MCP server), '*' when it may pull a tool out from under a
    running job (the undo of an install deletes terraform/kubectl/helm from ~/.cloudseed/bin) or is unknown."""
    try:
        entry = next((e for e in undo.entries() if e.get("id") == entry_id), None)
    except Exception:  # noqa: BLE001 - an unreadable journal: the undo itself will say so
        return "*"
    if not entry:
        return "*"
    scope = entry.get("scope")
    if scope != undo.GLOBAL:
        return scope if isinstance(scope, str) and scope else "*"
    kind, data = entry.get("kind"), _dict(entry.get("data"))
    if kind in _UNDO_HARMLESS:
        return None
    if kind == "restore-files":
        try:
            bin_dir = paths.BIN_DIR.resolve()
            files = [Path(str(f)).expanduser().resolve() for f in _dict(data.get("files"))]
        except (OSError, RuntimeError, ValueError):
            return "*"
        if any(f == bin_dir or bin_dir in f.parents for f in files):
            return "*"
        inverse = [x for x in (data.get("then") or []) if isinstance(x, list)]
    elif kind == "argv":
        inverse = [data.get("argv")]
    elif kind == "argv-seq":
        inverse = list(data.get("argvs") or [])
    else:
        return "*"
    keys = set()
    for argv in inverse:
        if not isinstance(argv, list) or not argv:
            continue
        argv = [str(x) for x in argv]
        keys.add("*" if depth or argv[_skip_globals(argv):][:1] == ["undo"] else env_key(argv, depth + 1))
    if "*" in keys:
        return "*"
    ids = [k for k in keys if k]
    return ids[0] if len(ids) == 1 else ("*" if ids else None)


def env_key(argv: list[str], _depth: int = 0) -> str | None:
    """The environment a job changes ('aws-dev'), '*' when a cluster command's target cannot be told, None if read-only."""
    head = argv[:argv.index("--")] if "--" in argv else list(argv)
    head = head[_skip_globals(head):]      # `--runtime local setup aws`: the command is setup, not "local"
    words = [a for a in head if not a.startswith("-")]
    if not words:
        return None
    cmd = words[0]
    if cmd in _SUB_MUTATING:
        if len(words) < 2 or words[1] not in _SUB_MUTATING[cmd]:
            return None
    elif cmd not in _MUTATING or (cmd == "undo" and "--list" in head):
        return None

    def opt(*names: str) -> str | None:
        for i, a in enumerate(head):
            for n in names:
                if a == n and i + 1 < len(head):
                    return head[i + 1]
                if a.startswith(n + "="):
                    return a.split("=", 1)[1]
        return None

    cloud = opt("--cloud") or next((w for w in words[1:] if w in mcp.CLOUDS), None)
    name = opt("--env", "-e")
    envs = paths.Env.list_all()
    if cloud:
        if not name:
            cands = [e for e in envs if e.cloud == cloud]
            name = cands[0].name if len(cands) == 1 else "dev"
        return f"{cloud}-{name}"
    if cmd == "undo":
        uid = opt("--id")
        return _undo_entry_key(uid, _depth) if uid else "*"   # a bare `undo` may pick any environment's entry
    cur = paths.load_settings().get("current_env")
    if name:
        match = [e.id for e in envs if e.name == name]
        if len(match) == 1:
            return match[0]
        if len(match) > 1:                 # aws-draws and vmware-draws: the CLI prefers the current one, else it is unclear
            return cur if cur in match else "*"
    if cur:
        return cur
    return envs[0].id if len(envs) == 1 else "*"


def _conflicting(key: str | None) -> Job | None:
    if not key:
        return None
    for j in JOBS.values():
        if j.running and j.key and (j.key == key or "*" in (j.key, key)):
            return j
    return None


def _prune_locked() -> None:
    """Keep at most MAX_JOBS jobs; only finished ones are dropped (a running job always stays reachable)."""
    excess = len(JOBS) - MAX_JOBS
    if excess <= 0:
        return
    for jid in [k for k, j in JOBS.items() if not j.running][:excess]:
        JOBS.pop(jid, None)
        for suffix in (".json", ".log", ".rc", ".rc.tmp", ".json.tmp", ".log.scrub"):
            try:
                (JOBS_DIR / f"{jid}{suffix}").unlink()
            except OSError:
                pass


def _jobs_dir() -> None:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    for d in (UI_DIR, JOBS_DIR):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass


def start_job(argv: list[str], label: str, key: str | None = None) -> Job:
    """Run `cloudseed <argv>` detached from this server: its own process group, output to a 0600 log file, exit code
    written by a tiny /bin/sh runner. The server only follows the log, so it can restart without touching the job."""
    _jobs_dir()
    jid = f"{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{secrets_token(4)}"
    job = Job(jid, argv, label, key)
    with JOBS_LOCK:
        other = _conflicting(key)
        if other:
            raise Conflict(f"a job is already running on {other.key}: {other.label} (started {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(other.started))}). "
                           "Wait for it to finish or interrupt it first.", other.id)
        JOBS[jid] = job
        _prune_locked()
    _log(f"job {jid} $ cloudseed {' '.join(job.argv)}")
    cmd = mcp._launcher() + argv
    if _USE_RUNNER:
        cmd = ["/bin/sh", "-c", _RUNNER, "cloudseed-job", str(job.rc_path)] + cmd
    try:
        fd = os.open(job.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            kw: dict = {"start_new_session": True} if os.name != "nt" else {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
            job.proc = subprocess.Popen(cmd, env=child_env(), stdout=fd, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=str(Path.home()), **kw)
        finally:
            os.close(fd)
    except Exception as e:  # noqa: BLE001 - a job that never started must not stay 'running' (and hold its env lock)
        job.push(f"[ui] failed to run: {type(e).__name__}: {e}")
        job.finish(1)
        _log(f"job {jid} could not start: {e}")
        return job
    job.pid = job.proc.pid
    job.save_meta()
    threading.Thread(target=_follow, args=(job,), daemon=True, name=f"job-{jid}").start()
    return job


def _note(job: Job, msg: str) -> None:
    """A console message in a running job's output. It goes through the log file (the single source of the output), so
    a console restarted later shows it too, in the same place."""
    line = f"[ui] {msg}"
    if job.running:
        try:
            with job.log_lock, open(job.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return
        except OSError:
            pass
    job.push(line)


def _job_rc(job: Job) -> int | None:
    try:
        return int(job.rc_path.read_text().strip())
    except (OSError, ValueError):
        return None


def _scrub_log(job: Job) -> bool:
    """Rewrite a finished job's log with only what the console shows: redacted (multi-line private keys whole), like
    the CLI's own logs/<stamp>-<command>.log, and without Authorization header values or bearer tokens (audit.scrub_auth,
    as every file cloudseed persists). While a job runs its command writes the file directly (so the job outlives the
    console); afterwards no secret stays on disk in it. Best effort: on any error the original is kept."""
    src = job.log_path
    tmp = src.with_name(src.name + ".scrub")
    red = secrets.StreamRedactor()

    def put(fout, raw: bytes) -> None:
        text = raw.decode("utf-8", errors="surrogateescape")   # bytes that are not UTF-8 are written back unchanged
        out = red.feed(text)
        if text and not out:
            return                                               # the body of a private key: swallowed
        # the live view may show the user's own Authorization headers (curl -H ... through cs ssh); a file never keeps them
        out = audit.scrub_auth(out)
        fout.write(out.encode("utf-8", errors="surrogateescape") + b"\n")

    try:
        with job.log_lock, open(src, "rb") as fin:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fout:
                buf = b""
                while True:
                    chunk = fin.read(1 << 16)
                    if not chunk:
                        break
                    lines, buf = _split_lines(buf + chunk)
                    for raw in lines:
                        put(fout, raw)
                buf = buf.rstrip(b"\r")
                if buf:
                    put(fout, buf)
            os.replace(tmp, src)
    except (OSError, UnicodeError):
        try:
            tmp.unlink()
        except OSError:
            pass
        return False
    job.scrubbed = True
    return True


def _follow(job: Job, offset: int = 0) -> None:
    """Stream a job's log file into the job (redacted, decoded leniently) until its runner has exited."""
    proc, buf = job.proc, b""
    marker = str(job.rc_path)
    red = secrets.StreamRedactor()   # one per stream: multi-line private keys are redacted whole
    try:
        fh = open(job.log_path, "rb")
    except OSError as e:
        job.push(f"[ui] cannot read the job output: {e}")
        fh = None
    try:
        if fh is not None and offset:
            fh.seek(offset)
        checked = 0.0
        while True:
            chunk = fh.read(1 << 16) if fh is not None else b""
            if chunk:
                lines, buf = _split_lines(buf + chunk)
                for raw in lines:
                    _push_raw(job, raw, red)
                continue
            if proc is not None:
                done = proc.poll() is not None
            else:   # a job adopted from an earlier console: confirm its identity now and then (ps), else just the pid
                deep = time.time() - checked > 5
                checked = time.time() if deep else checked
                done = not _alive(job.pid, marker if deep else None)
            if done:
                tail = fh.read() if fh is not None else b""
                if tail:
                    lines, buf = _split_lines(buf + tail)
                    for raw in lines:
                        _push_raw(job, raw, red)
                break
            time.sleep(0.1)
    except Exception as e:  # noqa: BLE001 - a reader problem must not leave the job 'running' forever
        job.push(f"[ui] lost track of the job output: {type(e).__name__}: {e}")
    finally:
        if fh is not None:
            fh.close()
    buf = buf.rstrip(b"\r")   # a \r held back as a possible half of \r\n ends the last line, it is not a line itself
    if buf:
        _push_raw(job, buf, red)
    rc = _job_rc(job)
    lost = False
    if proc is not None:
        prc = proc.wait()
        if rc is None:
            rc = prc if prc >= 0 else 128 - prc      # killed by a signal: shell-style 128+N
    elif rc is None and job.killed:       # adopted after a restart, and killed by this console's third interrupt
        rc = 128 + int(getattr(signal, "SIGKILL", 9))
    elif rc is None:
        rc, lost = -1, True
        job.push("[ui] the job ended while the console was not running and its exit code was not recorded")
    job.finish(rc, lost=lost)
    _log(f"job {job.id} rc={rc} {round((job.finished or time.time()) - job.started, 1)}s")
    if _scrub_log(job):   # the output is all in memory now: the file keeps only its redacted form
        job.save_meta()


def cancel_job(job: Job) -> dict:
    """Interrupt a job the way Ctrl-C in a terminal does: SIGINT to its whole process group, so Terraform/Ansible stop
    cleanly (state saved, lock released). A second interrupt is Terraform's 'stop now'; a third kills the job."""
    if not job.running or not job.pid:
        return {"cancelled": False, "message": "the job is not running"}
    if job.proc is None and not _alive(job.pid, str(job.rc_path)):
        return {"cancelled": False, "message": "the job has already ended"}
    job.cancels += 1
    n = job.cancels
    sig = signal.SIGINT if n <= 2 else getattr(signal, "SIGKILL", signal.SIGTERM)
    try:
        if os.name == "nt":
            if job.proc is None:
                return {"cancelled": False, "message": "cannot signal a job started by an earlier console on Windows"}
            if n <= 2 and hasattr(signal, "CTRL_BREAK_EVENT"):
                job.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                job.proc.kill()
        else:
            if os.getpgid(job.pid) != job.pid or job.pid == os.getpgid(0):
                return {"cancelled": False, "message": "the job's process group is not its own; refusing to signal it"}
            os.killpg(job.pid, sig)
    except ProcessLookupError:
        return {"cancelled": False, "message": "the job has already ended"}
    except OSError as e:
        return {"cancelled": False, "message": f"could not signal the job: {e}"}
    if n >= 3:
        job.killed = True   # its runner is gone too, so no exit code gets written: the 137 is ours to record
    job.save_meta()         # a console restarted now counts on from here, and knows about the kill
    msg = ("Interrupt sent (like Ctrl-C): waiting for the command to stop cleanly; Terraform saves its state and releases the lock. "
           "Interrupt again to stop it immediately." if n == 1 else
           "Second interrupt sent: Terraform stops immediately (a remote state lock may need `terraform force-unlock`). "
           "Interrupt once more to kill the job." if n == 2 else "Job killed.")
    _note(job, msg)
    _log(f"job {job.id} interrupt #{n} ({getattr(sig, 'name', sig)})")
    return {"cancelled": True, "signal": getattr(sig, "name", str(sig)), "interrupts": n, "message": msg}


def recent_jobs(limit: int) -> list[Job]:
    """Every running job plus the most recent finished ones, oldest first."""
    with JOBS_LOCK:
        jobs = sorted(JOBS.values(), key=lambda j: j.started)
    running = [j for j in jobs if j.running]
    done = [j for j in jobs if not j.running]
    room = max(0, limit - len(running))
    keep = set(map(id, running)) | set(map(id, done[len(done) - room:] if room else []))
    return [j for j in jobs if id(j) in keep]


def _restore_jobs() -> None:
    """Jobs from an earlier run of the console: finished ones come back with their output, running ones are followed."""
    if not JOBS_DIR.is_dir():
        return
    metas = []
    for p in JOBS_DIR.glob("*.json"):
        try:
            m = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(m, dict) and m.get("id") == p.stem and isinstance(m.get("argv"), list):
            metas.append(m)
    for m in sorted(metas, key=lambda m: m.get("started") if isinstance(m.get("started"), (int, float)) else 0):
        if m["id"] in JOBS:
            continue
        try:
            raw, label = [str(a) for a in m["argv"]], str(m.get("label") or " ".join(map(str, m["argv"][:3])))
            job = Job(m["id"], raw, label, m.get("key") if isinstance(m.get("key"), str) else None, float(m.get("started") or time.time()))
            # an older version's label repeats the command's first words: the words masked in the command are masked there too
            masks = {w: m for w, m in zip(raw, job.argv) if w != m} if len(raw) == len(job.argv) else {}
            if masks:
                job.label = " ".join(masks.get(t, t) for t in job.label.split(" "))
            stale = job.argv != raw or job.label != label   # written by an older version with secret values in it
            job.pid = m["pid"] if isinstance(m.get("pid"), int) else None
            job.saved_lines = m["lines"] if isinstance(m.get("lines"), int) else 0
            job.scrubbed = m.get("scrubbed") is True
            job.cancels = m["cancels"] if isinstance(m.get("cancels"), int) and not isinstance(m.get("cancels"), bool) and m["cancels"] > 0 else 0
            job.killed = m.get("killed") is True
            rc = int(m["rc"]) if m.get("rc") is not None else None
            finished = float(m["finished"]) if m.get("finished") is not None else None
        except (TypeError, ValueError):
            continue   # a damaged record: leave it out
        if rc is not None:
            job.rc, job.lost, job._loaded = rc, bool(m.get("lost")), False
            job.finished = finished or job.started
            if stale:                      # scrub the record on disk now (a dead job's is re-saved below)
                job.save_meta()
        elif _alive(job.pid, str(job.rc_path)):
            if stale:
                job.save_meta()
            threading.Thread(target=_follow, args=(job,), daemon=True, name=f"job-{job.id}").start()
        else:
            job._loaded = False
            rc = _job_rc(job)
            try:
                job.finished = job.log_path.stat().st_mtime
            except OSError:
                job.finished = time.time()
            if rc is None and job.killed:   # killed by a console that stopped before it could record the 137
                job.rc = 128 + int(getattr(signal, "SIGKILL", 9))
            elif rc is None:
                job.rc, job.lost = -1, True
            else:
                job.rc = rc
            job.save_meta()
        with JOBS_LOCK:
            JOBS[job.id] = job
    with JOBS_LOCK:
        _prune_locked()
        unscrubbed = [j for j in JOBS.values() if not j.running and not j.scrubbed]
    if unscrubbed:   # finished while no console ran, or by an older version: scrub their logs without delaying the start
        threading.Thread(target=_scrub_finished, args=(unscrubbed,), daemon=True, name="job-log-scrub").start()


def _scrub_finished(jobs: list[Job]) -> None:
    for job in jobs:
        with JOBS_LOCK:
            if JOBS.get(job.id) is not job:
                continue            # pruned meanwhile
        if _scrub_log(job):
            with JOBS_LOCK:
                pruned = JOBS.get(job.id) is not job
            if pruned:              # pruned while being rewritten: do not leave the rewritten file behind
                job.log_path.unlink(missing_ok=True)
            else:
                job.save_meta()


# ---------------------------------------------------------------- data for the UI

def _json_obj(path: Path) -> dict:
    """A JSON object from a file; {} when it is missing, unreadable or not an object (a hand edit gone wrong)."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _dict(v) -> dict:
    return v if isinstance(v, dict) else {}


def _env_row(e) -> dict:
    """One environment for the console. An unreadable config.json does not hide the environment: its row carries
    `error` (what is wrong and the way out), like `cs list` shows it."""
    cfg, problem = e.try_load()
    outputs = _json_obj(e.dir / "outputs.json")
    cur = _dict(_json_obj(e.dir / "inventory.json").get("current"))
    cfg_vars = _dict(cfg.get("vars"))
    row = {"id": e.id, "cloud": e.cloud, "env": e.name, "name": cfg.get("name"), "verdicts": verdicts(e), "region": cfg.get("region"), "state": _dict(cfg.get("state")).get("type"),
           "cidr": cfg.get("network_cidr"), "workdir": str(e.dir), "updated": cfg.get("updated_at"), "fips": bool(cfg_vars.get("fips_mode")),
           "kubernetes": bool(outputs.get("kubernetes_cluster_name") or outputs.get("kubernetes_control_plane_ips")),
           "vpn": bool(outputs.get("vpn_public_ip")), "bastion_ip": outputs.get("bastion_public_ip"), "resources": cur.get("count", 0),
           "vars": {k: v for k, v in cfg_vars.items() if k not in ("base_disk", "guest_os_id")}, "outputs": outputs,
           "provisioned": list(_dict(cfg.get("provisioned")).keys()), "allowed_ssh_cidrs": list(cfg.get("allowed_ssh_cidrs") or []) if isinstance(cfg.get("allowed_ssh_cidrs"), list) else [],
           "tags": dict(_dict(cfg.get("tags")))}
    if problem:
        row["error"] = problem
    return row


def _mcp_clients(mstate: dict) -> dict:
    """MCP client rows; `stale` = wired over HTTP to a server that is not there any more (other port, old token), the
    'out of date' of `cs mcp status` (fix: Reconnect)."""
    out = {}
    for k, c in mcp.CLIENTS.items():
        conn = mcp.connected(k)
        stale = False
        if conn == "http":
            try:
                stale = bool(mcp.stale(k, mstate))
            except Exception:  # noqa: BLE001 - an unreadable client config must not break the whole state
                stale = False
        out[k] = {"display": c["display"], "present": mcp.client_present(k), "connected": conn, "stale": stale}
    return out


def _job_environ() -> dict:
    """The variables a job sees: the vault fills in what the shell does not export (creds.apply in the child)."""
    vault = {k: v for k, v in creds.load().items() if isinstance(k, str) and isinstance(v, str)}
    return {**vault, **creds.shell_env()}


def _tool_need(cloud_key: str, tool: str, environ: dict) -> str | None:
    """Why an optional tool is needed after all here (None: it is not). The azurerm provider signs in by running the
    az CLI unless ARM_* variables authenticate it (a service principal, a managed or workload identity, OIDC), so
    without them every Azure plan fails on a missing az - the check setup and `cs doctor` make (azure.arm_credentials)."""
    if cloud_key != "azure" or tool != "az":
        return None
    from .clouds import azure
    try:
        if azure.arm_credentials(environ):
            return None
    except Exception:  # noqa: BLE001 - cannot tell: do not claim it is needed
        return None
    if str(environ.get("ARM_USE_CLI") or "").strip().lower() in ("0", "f", "false"):
        return None      # Terraform is told not to use the az CLI: installing it would not help (setup says what is missing)
    return "needed to sign in (az login) unless ARM_* service-principal / managed-identity variables are set"


def _tool_rows(cloud_key: str, environ: dict) -> list[dict]:
    rows = []
    for r in deps.status(cloud_key):
        ok = bool(r["path"]) and not r.get("outdated")
        row = {"tool": r["tool"], "ok": ok, "outdated": bool(r.get("outdated")), "required": r["required"], "version": r.get("version", ""), "desc": r.get("desc", "")}
        # needed: required, or optional in general but not in this setup (az without ARM_* credentials); the console
        # then shows it as missing, with Install, instead of "tools ok"
        need = None if r["required"] else _tool_need(cloud_key, r["tool"], environ)
        row["needed"] = bool(r["required"] or need)
        if need:
            row["need_note"] = need
        rows.append(row)
    return rows


def state() -> dict:
    settings = paths.load_settings()
    envs = [_env_row(e) for e in paths.Env.list_all()]
    mstate = mcp.load_state()
    environ = _job_environ()
    tools = {cloud_key: _tool_rows(cloud_key, environ) for cloud_key in ("aws", "gcp", "azure", "vmware")}
    return {"version": __version__, "home": str(paths.HOME), "settings": {k: v for k, v in settings.items() if k not in ("models", "custom_models")} | {"models": settings.get("models", {})},
            "envs": envs, "current_env": settings.get("current_env"),
            "mcp": {"enabled": bool(settings.get("mcp")), "transport": mstate.get("transport"), "url": mcp.url(mstate) if mstate.get("transport") == "http" else None,
                    "running": bool(mcp.health(mstate)) if mstate.get("transport") == "http" else None, "clients": _mcp_clients(mstate)},
            "tools": tools, "clouds": clouds_catalog(), "platform": platform_catalog(), "jobs": [j.to_dict(tail=0) for j in recent_jobs(30)],
            "creds": _creds_rows(), "creds_groups": {**{"custom": "Custom variables"}, **creds.GROUPS}, "ui": {"url": f"http://{_hp(_State.host)}:{_State.port}/", "log": str(LOG_PATH), "jobs_dir": str(JOBS_DIR)},
            "undo": [{"id": e.get("id"), "scope": e["scope"], "at": e["at"], "summary": e["summary"], "inverse": undo.describe(e)} for e in reversed(undo.entries())]}


# Computed wizard defaults (Azure: `az account show`, seconds; the local user name; ...) are worked out once and then
# served from memory, refreshed in the background when older than DEFAULT_TTL: a state poll never waits for a cloud CLI.
DEFAULT_TTL = 120.0
_DEFAULTS: dict = {}                 # (cloud, question) -> [value, computed at (monotonic), refresh running]
_DEFAULTS_LOCK = threading.Lock()


def _eval_default(q, cfg: dict):
    try:
        return q.stock_default(cfg)
    except Exception:  # noqa: BLE001 - a default that cannot be worked out is simply not suggested
        return ""


def _refresh_default(key: tuple, q, cfg: dict):
    val = _eval_default(q, cfg)
    with _DEFAULTS_LOCK:
        _DEFAULTS[key] = [val, time.monotonic(), False]
    return val


def computed_default(cloud_key: str, q, cfg: dict):
    """A question's computed default without making the caller wait once it is known (stale-while-revalidate)."""
    key = (cloud_key, q.key)
    with _DEFAULTS_LOCK:
        hit = _DEFAULTS.get(key)
        old = hit is not None and not hit[2] and time.monotonic() - hit[1] >= DEFAULT_TTL
        if old:
            hit[2] = True
    if hit is None:
        return _refresh_default(key, q, cfg)
    if old:
        threading.Thread(target=_refresh_default, args=(key, q, cfg), daemon=True, name=f"ui-default-{q.key}").start()
    return hit[0]


def _env_value(vault: dict, name: str) -> str | None:
    """A variable's value as a cloudseed process sees it (the shell, else the vault); None when unset or blank."""
    v = os.environ.get(name) or vault.get(name)
    if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v).strip():
        return str(v)
    return None


def _env_problem(c, q, value: str, cfg: dict) -> str | None:
    """Why the CLI would not take `value` from the environment for a blank answer (Cloud._default judges it with the
    cloud's answer_problem: an Azure subscription must be a GUID, a GCP project ID well-formed). A region-bound value
    (a GCP zone) is valid when it fits its own region; env_region then says where it applies."""
    try:
        problem = c.answer_problem(q, value, cfg)
    except Exception:  # noqa: BLE001 - a check that cannot run: the format check alone
        try:
            problem = q.problem(value)
        except Exception:  # noqa: BLE001 - nothing can be told: the CLI decides (as before this check)
            problem = None
    if problem and "-" in value.strip():
        try:
            if c.answer_problem(q, value, {"region": value.strip().rsplit("-", 1)[0], "workdir": ""}) is None:
                return None
        except Exception:  # noqa: BLE001
            pass
    return problem


def _without_value(problem: str, name: str, value: str) -> str:
    """A problem message fit for the page: the variable's value is never sent (it may be anything, e.g. a pasted
    secret), so where the message quotes it, it names the variable instead."""
    v, mark = value.strip(), "\x00"      # the name goes in last: a value found inside it must not be replaced there
    for quoted in (repr(value), repr(v), f"'{v}'", f'"{v}"'):
        problem = problem.replace(quoted, mark)
    if len(v) >= 4:
        problem = problem.replace(v, mark)
    return secrets.redact(problem).replace(mark, f"${name}")


def _env_answer(c, q, vault: dict, cfg: dict) -> tuple[list[str], list[dict]]:
    """(the variables, names only, a blank answer is taken from - the CLI takes the first one; the variables that are
    set but that the CLI ignores, [{name, problem}]), as Cloud._default decides it. The vault is part of the
    environment of every cloudseed process."""
    names, ignored = [], []
    for n in q.env:
        v = _env_value(vault, n)
        if v is None:
            continue
        problem = _env_problem(c, q, v, cfg)
        if problem is None:
            names.append(n)
        else:
            ignored.append({"name": n, "problem": _without_value(problem, n, v)})
    return names, ignored


def _env_region(c, q, vault: dict, name: str) -> str | None:
    """The region an answer taken from the environment is bound to (GCP zone europe-west1-c: europe-west1), None when it
    fits every region (a project or subscription id). The CLI uses such a value only when the chosen region matches
    (Cloud._default), so the wizard needs it to tell. Only the region is sent, never the value."""
    v = (_env_value(vault, name) or "").strip()
    if "-" not in v:
        return None
    region = v.rsplit("-", 1)[0]
    try:
        fits = c.answer_problem(q, v, {"region": region, "workdir": ""}) is None
        bound = c.answer_problem(q, v, {"region": "cs-no-such-region", "workdir": ""}) is not None
    except Exception:  # noqa: BLE001 - a check that cannot run: treat the value as region-independent (as before)
        return None
    return region if fits and bound else None


def _region_defaults(c, q, default) -> dict:
    """The regions where a region-derived default does not follow the <default region> prefix (GCP europe-west1 and
    us-east1 start at zone -b; setup refuses their nonexistent -a zone)."""
    if not (callable(q.default) and isinstance(default, str) and c.default_region and default.startswith(c.default_region) and not c.local):
        return {}
    irregular = {}
    for r in getattr(c, "irregular_regions", ()):
        val = _eval_default(q, {"region": r, "workdir": ""})
        if val and val != r + default[len(c.default_region):]:
            irregular[r] = val
    return irregular


_PROBE_MAX = 4096    # int answers probed for their smallest accepted value (_int_minimum)


def _int_minimum(q) -> int | None:
    """The smallest whole number an int question accepts, for the wizard's number field, found by asking the question
    itself from Question.minimum (or 0) up: its validator may refuse more than the declared bound (VM memory 512, a
    disk 10 or 20, a node count 1). Every smaller number is refused by setup, so the bound never blocks an answer setup
    takes. Without a declared minimum: None when 0 is accepted or nothing up to _PROBE_MAX is (the page keeps its own
    rule)."""
    declared = q.minimum if isinstance(q.minimum, int) and not isinstance(q.minimum, bool) else None
    start = 0 if declared is None else declared
    try:
        if q.kind != "int" or q.problem(start) is None:
            return declared
        return next((n for n in range(start + 1, start + _PROBE_MAX + 1) if q.problem(n) is None), declared)
    except Exception:  # noqa: BLE001 - a validator that breaks on a number: the declared bound, else none (never no wizard)
        return declared


def _question_row(key: str, c, q, cfg: dict, vault: dict) -> dict:
    """One setup question for the web wizard: what the CLI would ask, and everything the page needs to check an answer
    the way setup does, without running Python validators or a cloud CLI."""
    # from_env: the variables (names only, never values) the CLI takes a blank answer from - shell or vault. They win
    # over the built-in default (Cloud._default), so the wizard then shows a blank answer (hint: "blank = $NAME")
    # instead of a default the CLI would not use - and no cloud CLI runs to compute it. ignored_env / invalid_env: the
    # ones that are set but that the CLI ignores (an ARM_SUBSCRIPTION_ID that is no GUID), with the reason.
    from_env, ignored = _env_answer(c, q, vault, cfg)
    env_region = _env_region(c, q, vault, from_env[0]) if from_env else None
    if from_env:
        default = ""
    elif callable(q.default):
        default = computed_default(key, q, cfg)
    else:
        default = q.default
    if callable(default) or default is None:
        default = ""
    row = {"key": q.key, "prompt": q.prompt, "default": default, "kind": q.kind, "required": q.required, "advanced": q.advanced, "from_env": from_env}
    if ignored:
        row["ignored_env"] = ignored
        row["invalid_env"] = [x["name"] for x in ignored]
    choices = getattr(q, "choices", None)    # a fixed set of answers (vpn_type, kubernetes_distro, guest_os): a select
    if choices:
        row["choices"] = [str(x) for x in choices]
    if q.kind == "int":                      # the range setup accepts (VM sizes, node and zone counts)
        lo = _int_minimum(q)
        if lo is not None:
            row["minimum"] = lo
        if isinstance(q.maximum, int) and not isinstance(q.maximum, bool):
            row["maximum"] = q.maximum
    pattern = (getattr(c, "answer_patterns", None) or {}).get(q.key)
    if pattern:                              # a JavaScript-compatible regex and what it means (the Azure subscription GUID)
        row["pattern"], row["pattern_hint"] = pattern[0], pattern[1]
    reserved = (getattr(c, "answer_reserved", None) or {}).get(q.key)
    if reserved:                             # answers the cloud refuses, compared case-insensitively (Azure admin names)
        row["reserved"] = [str(x) for x in reserved]
    follows = getattr(q, "follows", "")
    if follows:                              # its default is the answer to that question (AWS regional baseline)
        row["follows"] = str(follows)
    # the yes/no question this setting belongs to (vpn_type: enable_vpn, Security Hub: the regional baseline): while
    # that answer is no, setup does not ask it and it has no effect (Cloud.unused), so the wizard hides it
    parent = q.parent() if callable(getattr(q, "parent", None)) else ""
    if parent and c.question(parent) is not None:
        row["depends_on"] = str(parent)
    irregular = _region_defaults(c, q, default)
    if irregular:
        row["region_defaults"] = irregular
    if env_region:
        # the environment's answer applies only while the chosen region is env_region; elsewhere the CLI uses the
        # built-in default, sent as `stock` (a region-bound default is computed locally: no cloud CLI runs)
        row["env_region"] = env_region
        stock = computed_default(key, q, cfg) if callable(q.default) else q.default
        if isinstance(stock, (str, int, float)) and not isinstance(stock, bool) and stock != "":
            row["stock"] = {"default": stock}
            stock_irregular = _region_defaults(c, q, stock)
            if stock_irregular:
                row["stock"]["region_defaults"] = stock_irregular
    return row


def clouds_catalog() -> dict:
    from . import clouds
    out = {}
    vault = creds.load()
    for key in ("aws", "gcp", "azure", "vmware"):
        c = clouds.get(key)
        cfg = {"region": c.default_region, "workdir": ""}
        qs = [_question_row(key, c, q, cfg, vault) for q in c.questions]
        out[key] = {"display": c.display, "local": c.local, "region_prompt": c.region_prompt, "default_region": c.default_region, "login_hint": c.login_hint, "questions": qs}
    return out


def platform_catalog() -> dict:
    from . import chaos, platform as pl
    items = []
    for name, spec in pl.CATALOG.items():
        if spec.get("hidden"):
            continue
        # needs_by_target: what an item needs only on some targets (velero on VMware: local-path-provisioner, minio);
        # arch: the CPU architectures its images exist for (empty = all)
        items.append({"name": name, "group": spec["group"], "desc": spec["desc"], "tier": spec.get("tier", "core"), "only": spec.get("only", []),
                      "needs": spec.get("needs", []), "needs_by_target": {str(t): list(v) for t, v in (spec.get("needs_by_target") or {}).items()},
                      "arch": list(spec.get("arch") or []), "notes": spec.get("notes", ""), "fips": spec.get("fips", ""),
                      "cloud_prereqs": spec.get("cloud_prereqs", []), "ui": name in pl.UIS, "source": pl.source_of(spec)})
    return {"groups": pl.GROUPS, "items": items, "chaos": {"suites": chaos.SUITES, "experiments": {k: v["desc"] for k, v in chaos.EXPERIMENTS.items()}}}


class _Unavailable(Exception):
    """The cluster cannot be asked right now (reason shown in the Platform view)."""


def _err_text(ex: BaseException) -> str:
    """A readable message for any exception, ui.Abort included (its message, never just an exit code)."""
    if isinstance(ex, KeyError) and ex.args:   # never the bare repr "'resource_group_name'"
        return f"missing {ex.args[0]!r} in the environment's saved configuration or outputs"
    msg = getattr(ex, "msg", "") or str(ex) or type(ex).__name__
    return secrets.redact(str(msg)).strip()[:400]


def _status_kubeconfig(cloud, e, cfg: dict, outputs: dict) -> Path:
    """The environment's kubeconfig for a read-only status probe: no tool installs, no SSH tunnels from a page view.
    The fetch writes only the environment's own file (az and aws are told so: az would otherwise merge into, and switch,
    ~/.kube/config) with the same cloud CLI environment as the CLI's fetch (AWS FIPS endpoints)."""
    from . import services
    kc = services.kubeconfig_path(e)
    if not kc.exists():
        if cloud.key == "vmware":
            raise _Unavailable(f"No kubeconfig yet for {e.id}: cloudseed provision vmware --env {e.name} --host k8s")
        try:
            cmd = services.kubeconfig_command(cloud.key, cfg, outputs, kubeconfig=kc)
        except KeyError as ex:
            key = ex.args[0] if ex.args else "?"
            if key in outputs or not (str(key).endswith("_name") or str(key).startswith("kubernetes_")):
                raise _Unavailable(f"the configuration of {e.id} has no {key}: cloudseed setup {e.cloud} --env {e.name} sets it") from None
            raise _Unavailable(f"the saved outputs of {e.id} have no {key} yet: refresh them with cloudseed output {e.cloud} --env {e.name} "
                               f"(or cloudseed apply {e.cloud} --env {e.name})") from None
        binary = deps.find(cmd[0])
        if not binary:
            raise _Unavailable(f"{cmd[0]} is not installed, so the kubeconfig cannot be fetched: cloudseed install {cmd[0]}")
        made = not kc.parent.exists()
        kc.parent.mkdir(parents=True, exist_ok=True)
        try:
            try:
                proc = subprocess.run([binary] + cmd[1:], env=dict(services.cloud_cli_env(cloud.key, cfg, outputs), KUBECONFIG=str(kc)),
                                      capture_output=True, text=True, errors="replace", timeout=90, stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                raise _Unavailable(f"`{cmd[0]}` did not answer within 90 s while fetching the kubeconfig") from None
            except OSError as ex:
                raise _Unavailable(f"could not run {cmd[0]}: {ex.strerror or ex}") from None
            if proc.returncode != 0 or not kc.exists():
                raise _Unavailable("could not fetch the kubeconfig: " + secrets.redact((proc.stderr or proc.stdout).strip()[-300:]))
        except _Unavailable:
            if made:                           # a failed probe leaves no empty k8s/ behind
                try:
                    kc.parent.rmdir()
                except OSError:
                    pass
            raise
        try:
            os.chmod(kc, 0o600)
        except OSError:
            pass
        if services._aws_fips(cloud.key, cfg, outputs):   # kubectl/helm tokens are signed against the FIPS STS endpoint too
            try:
                services.pin_fips_token_endpoint(kc, outputs.get("kubernetes_cluster_name") or "")
            except (OSError, subprocess.SubprocessError):
                pass
    m = re.search(r"^\s*server:\s*['\"]?(\S+?)['\"]?\s*$", kc.read_text(errors="replace"), re.M)
    if m:
        u = urlsplit(m.group(1) if "://" in m.group(1) else "https://" + m.group(1))
        host, port = u.hostname, u.port or 443
        if host:
            try:
                with socket.create_connection((host, port), timeout=4):
                    pass
            except OSError:
                hint = ("the SSH tunnel through the bastion is not open (any platform action opens it)" if host in LOOPBACK
                        else "a private endpoint: connect the VPN, or run a platform action to open the SSH tunnel")
                raise _Unavailable(f"the cluster API {host}:{port} is not reachable from here ({hint})") from None
    return kc


def _item_state(pl, ctx, name: str, spec: dict, rel: dict) -> dict | None:
    """One catalog item on the cluster, as `cs platform status` reports it: built-in, installed, failed (repair: install
    again) or pending (an interrupted install/upgrade: roll back or uninstall first); None = not there."""
    if ctx.distro in pl.PROVIDED_BY_DISTRO.get(name, []):
        return {"state": "built-in"}
    st = pl._state_of(name, spec, rel)
    if not st:
        return None
    # the release that carries the state (the istio bundle is tracked by its istiod release)
    carrier, cspec = ("istiod", pl.CATALOG["istiod"]) if spec.get("method") == "meta" and name == "istio" else (name, spec)
    r = rel.get(pl._release_key(cspec, carrier)) or rel.get("probe:" + name) or {}
    row = {"chart": r.get("chart", ""), "status": r.get("status", "")}
    if st in ("deployed", "present"):
        row["state"] = "installed"
    elif st == "failed":
        row.update(state="failed", fix=f"cs platform install {name}")
    else:
        row.update(state="pending", fix=f"{pl._pending_fix(cspec, carrier, rel)}, then cs platform install {name}")
    return row


def platform_status(env_id: str) -> dict:
    """Releases on the environment's cluster (helm list + probes), keyed by catalog item name: installed, failed and
    pending ones (never hidden: a failed release is not 'not installed'), plus what the distribution builds in."""
    from . import clouds, platform as pl
    envs = {e.id: e for e in paths.Env.list_all()}
    e = envs.get(env_id)
    if not e:
        return {"error": "no such environment"}
    try:
        cfg = e.load()
    except paths.ConfigError as ex:   # its message names the environment, the file and the way out
        return {"error": str(ex)}
    except (OSError, ValueError) as ex:
        return {"error": f"cannot read {e.id}/config.json: {getattr(ex, 'strerror', None) or ex}"}
    try:
        outputs = json.loads((e.dir / "outputs.json").read_text())
    except (OSError, ValueError):
        outputs = {}
    if not (outputs.get("kubernetes_cluster_name") or outputs.get("kubernetes_control_plane_ips")):
        return {"error": "no cluster"}
    creds.refresh()   # cloud auth plugins (aws eks get-token, gke-gcloud-auth-plugin) run in this process's environment
    try:
        cloud = clouds.get(e.cloud)
        # a status GET never installs anything or opens tunnels: the kubeconfig first (no cloud CLI = it cannot be
        # fetched), then helm (nothing can be listed without it), then one quick API probe
        ctx = pl.Cluster(cloud, e, cfg, outputs, _status_kubeconfig(cloud, e, cfg, outputs))
        if not deps.find("helm"):
            raise _Unavailable("helm is not installed: cloudseed install helm")
        kubectl = deps.find("kubectl")
        if kubectl:   # an unreachable cluster lists nothing: say so instead of reporting "0 installed"
            probe = subprocess.run([kubectl, "version", "--request-timeout=8s", "-o", "json"], env=ctx.procenv(), capture_output=True,
                                   text=True, errors="replace", timeout=30, stdin=subprocess.DEVNULL)
            if probe.returncode != 0:
                why = ((probe.stderr or "").strip().splitlines() or ["no answer"])[-1]
                raise _Unavailable("the cluster did not answer: " + why)
        rel = pl.installed_releases(ctx)
        out = {}
        for name, spec in pl.CATALOG.items():
            row = _item_state(pl, ctx, name, spec, rel)
            if row:
                out[name] = row
    except (Exception, ui.Abort) as ex:  # noqa: BLE001 - ui.Abort is a SystemExit: never let it drop the connection
        return {"error": _err_text(ex)}
    return {"items": out, "distro": ctx.distro, "target": ctx.target}


# ---------------------------------------------------------------- reports and verdicts

REPORT_PREFIXES = ("cis-", "stig-", "kube-", "images-", "host-", "cloud-", "fips-")   # what scan.save_report writes
RAW_PREFIXES = ("kubescape-", "trivy-")                                                # tool dumps next to them: never reports
MAX_REPORT_BYTES = 32 << 20


def _run_key(p: Path) -> tuple[str, str]:
    """Reports end with their run stamp YYYYMMDD-HHMMSS: order by it, not by the kind in front."""
    return (p.stem[-15:], p.stem)


def _report_files(d: Path, pattern: str, scans: bool = False) -> list[Path]:
    """Report files of one kind, newest first; for scans only real reports (raw tool output is skipped unread)."""
    if not d.is_dir():
        return []
    out = []
    for p in d.glob(pattern):
        if not p.is_file():
            continue
        if scans and (not p.name.startswith(REPORT_PREFIXES) or p.name.startswith(RAW_PREFIXES)):
            continue
        out.append(p)
    return sorted(out, key=_run_key, reverse=True)


def _load_report(p: Path) -> dict | None:
    try:
        if p.stat().st_size > MAX_REPORT_BYTES:
            return None
        data = json.loads(p.read_text(errors="replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _stored_verdict(data: dict) -> str | None:
    """The verdict a report recorded itself ("PASS", "FAIL - 2 failed", ...), normalised to its first word."""
    v = data.get("verdict")
    if not v and isinstance(data.get("summary"), dict):
        v = data["summary"].get("verdict")
    if isinstance(v, str) and v.strip():
        return v.strip().split()[0].upper()
    return None


def _items(data: dict, key: str, cap: int | None = None) -> list:
    """A list field of a report (anything else, e.g. from a damaged or foreign file, counts as empty)."""
    v = data.get(key)
    return (v[:cap] if cap is not None else v) if isinstance(v, list) else []


def _num(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def chaos_verdict(data: dict) -> tuple[str, str]:
    """PASS only when experiments ran and every one passed; an empty or all-skipped run proves nothing."""
    sm = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    results = data.get("results") if isinstance(data.get("results"), list) else []
    total = len(results) or sum(_num(v) for v in sm.values())
    passed, failed, errors, skipped = (_num(sm.get(k)) for k in ("PASS", "FAIL", "ERROR", "SKIP"))
    stored = _stored_verdict(data)
    if stored:
        verdict = stored
    elif failed or errors:
        verdict = "FAIL"
    elif total and passed == total:
        verdict = "PASS"
    else:
        verdict = "INCONCLUSIVE"
    if not total:
        detail = "no experiments ran"
    else:
        detail = f"{passed}/{total} passed" + (f", {skipped} skipped" if skipped else "") + (f", {failed} failed" if failed else "") + (f", {errors} errors" if errors else "")
    return verdict, detail


def scan_verdict(kind: str, data: dict) -> str:
    """The same verdict the CLI prints for the scan (stored in the report when the scan saved one)."""
    stored = _stored_verdict(data)
    if stored:
        return stored
    sm = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    findings = [f for f in _items(data, "findings") if isinstance(f, dict)]
    high = any(str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH") for f in findings)
    if kind == "kube" or kind == "cloud":
        return "FAIL" if high else "PASS"
    if kind == "images":
        return "FAIL" if _num(sm.get("critical")) or any(str(f.get("severity", "")).upper() == "CRITICAL" for f in findings) else "PASS"
    if kind.startswith("host") or kind == "stig-host":
        hosts = [h for h in (data.get("hosts") if isinstance(data.get("hosts"), dict) else {}).values() if isinstance(h, dict)]
        if hosts and all(h.get("skipped") for h in hosts):
            return "N/A"            # no scanned host has content for this profile (e.g. no DISA STIG for the OS)
        if "ansible_rc" in data:    # what the CLI printed: PASS when Ansible succeeded and no rule failed
            return "FAIL" if findings or _num(data.get("ansible_rc")) else "PASS"
        # an old report without the Ansible exit code: a host without results is not a clean one
        broken = any("error" in h and not h.get("skipped") for h in hosts)
        return "FAIL" if findings or broken else "PASS"
    return "FAIL" if _num(sm.get("fail")) or _num(sm.get("controls failed")) else "PASS"   # cis, stig-k8s, fips


def _scan_kind(p: Path) -> str:
    return p.stem[:-16] if len(p.stem) > 16 else p.stem


def _detail(sm: dict) -> str:
    nums = [f"{k} {v}" for k, v in list(sm.items()) if isinstance(v, (int, float)) and not isinstance(v, bool)][:3]
    return ", ".join(nums) or (str(next(iter(sm.values()), ""))[:60] if sm else "")


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _secs(v: float) -> str:
    v = round(float(v), 1)
    return str(int(v)) if v.is_integer() else str(v)


def drill_rto(data: dict) -> str:
    """A PASS drill's RTO (restore + verify) as the Reports view shows it: the recorded rto_s, else (a report from an
    older version) the sum of its steps 4. and 5., else '?'. Only a drill that recovered its workload measured one (see
    drill_detail): never call this for a failed or interrupted drill."""
    if _is_num(data.get("rto_s")):
        return _secs(data["rto_s"])
    steps = [s for s in _items(data, "steps") if isinstance(s, dict)]
    if not steps:
        return "?"
    return _secs(sum(s["seconds"] for s in steps if str(s.get("step") or "").startswith(("4.", "5.")) and _is_num(s.get("seconds"))))


def _drill_passed(data: dict) -> bool:
    return _stored_verdict(data) == "PASS"


def _failed_step(data: dict) -> str | None:
    """The first step of a drill that did not succeed ('4. restore from backup'; 'interrupted' for Ctrl-C)."""
    for st in _items(data, "steps"):
        if isinstance(st, dict) and st.get("ok") is False:
            return str(st.get("step") or "?")[:80]
    return None


def drill_detail(data: dict) -> str:
    """The dashboard's line for a drill, as `cs dr` words it (dr.rto_text): 'RTO 34.5s' for a PASS; otherwise no RTO
    was measured (a failed restore's seconds are not a recovery time), and the step that failed says why."""
    if _drill_passed(data):
        return f"RTO {drill_rto(data)}s"
    step = _failed_step(data)
    if step == "interrupted" or _stored_verdict(data) == "INTERRUPTED":
        return "RTO not measured (interrupted)"
    return "RTO not measured" + (f" (failed at {step})" if step else "")


def drill_summary(data: dict) -> dict:
    """What the Reports view shows above a drill's steps (drill reports carry no summary block): the RTO of a PASS
    only, the total time and how many steps succeeded."""
    steps = [st for st in _items(data, "steps") if isinstance(st, dict)]
    if not steps and not _is_num(data.get("rto_s")) and not _is_num(data.get("total_s")):
        return {}
    real = [st for st in steps if st.get("step") != "interrupted"]
    total = data["total_s"] if _is_num(data.get("total_s")) else sum(st["seconds"] for st in real if _is_num(st.get("seconds")))
    out = {"RTO": f"{drill_rto(data)}s" if _drill_passed(data) else "not measured", "total": f"{_secs(total)}s"}
    if steps:
        out["steps"] = f"{sum(1 for st in steps if st.get('ok'))}/{len(steps)} ok"
    return out


def verdicts(env) -> dict:
    """Last chaos / DR / scan verdicts of an environment for the dashboard (same rules as the CLI)."""
    out: dict = {}
    for key, sub, pat in (("chaos", "chaos", "report-*.json"), ("dr", "dr", "drill-*.json"), ("fips", "scans", "fips-*.json"),
                          ("cis", "scans", "cis-*.json"), ("kube", "scans", "kube-*.json")):
        for p in _report_files(env.dir / sub, pat, scans=sub == "scans")[:3]:
            data = _load_report(p)
            if data is None:
                continue
            sm = data.get("summary") if isinstance(data.get("summary"), dict) else {}
            if key == "chaos":
                v, detail = chaos_verdict(data)
                out[key] = {"verdict": v, "detail": detail, "at": data.get("run")}
            elif key == "dr":
                out[key] = {"verdict": _stored_verdict(data) or "?", "detail": drill_detail(data), "at": data.get("run")}
            else:
                out[key] = {"verdict": scan_verdict(key, data), "detail": _detail(sm), "at": data.get("run")}
            break
    return out


def reports(env_id: str) -> dict:
    out: dict = {"chaos": [], "dr": [], "scans": [], "logs": []}
    envs = {e.id: e for e in paths.Env.list_all()}
    e = envs.get(env_id)
    if not e:
        return out
    for kind, sub, pat in (("chaos", "chaos", "report-*.json"), ("dr", "dr", "drill-*.json"), ("scans", "scans", "*-*.json")):
        for p in _report_files(e.dir / sub, pat, scans=kind == "scans"):
            if len(out[kind]) >= 40:
                break
            data = _load_report(p)
            if data is None:
                continue
            sm = data.get("summary") if isinstance(data.get("summary"), dict) else {}
            if kind == "chaos":
                verdict = chaos_verdict(data)[0]
            elif kind == "dr":
                verdict = _stored_verdict(data)
            else:
                verdict = scan_verdict(_scan_kind(p), data)
            row = {"path": str(p), "name": p.stem, "kind": _scan_kind(p) if kind == "scans" else kind, "summary": sm, "verdict": verdict,
                   "run": data.get("run") if isinstance(data.get("run"), str) else None,
                   "results": _items(data, "results", 200) or _items(data, "steps", 200), "findings": _items(data, "findings", 100),
                   "checks": _items(data, "checks", 200)}
            if kind == "dr":
                # the drill's own measurements; an RTO only for a PASS (a failed or interrupted drill recovered nothing,
                # whatever its steps took), and the summary the Reports view shows, so it never derives one from the steps
                for k in ("rto_s", "total_s"):
                    if _is_num(data.get(k)) and (k != "rto_s" or verdict == "PASS"):
                        row[k] = data[k]
                if not sm:
                    row["summary"] = drill_summary(data)
            out[kind].append(row)
    d = e.dir / "logs"
    out["logs"] = [str(p) for p in sorted(d.glob("*.log"), reverse=True)[:30]] if d.is_dir() else []
    return out


READABLE = {"logs": (".log", ".jsonl", ".txt"), "chaos": (".json", ".md", ".html"), "dr": (".json", ".md", ".html"),
            "scans": (".json", ".md", ".html", ".txt", ".log")}


def read_env_file(path: str) -> str | None:
    """Only logs and reports under an environment's working directory (logs/, chaos/, dr/, scans/); never the
    configuration, state, keys, kubeconfigs or generated platform secrets."""
    if not path or "\x00" in path:
        return None
    try:
        p = Path(path).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    for e in paths.Env.list_all():
        try:
            root = e.dir.resolve()
        except OSError:
            continue
        if root not in p.parents:
            continue
        rel = p.relative_to(root).parts
        if len(rel) < 2 or rel[0] not in READABLE or p.suffix not in READABLE[rel[0]] or "ssh" in rel or "tfstate" in p.name or not p.is_file():
            return None
        try:
            return secrets.redact(p.read_text(errors="replace")[-400000:])
        except OSError:
            return None
    return None


def mcp_guide() -> dict:
    """GET /api/mcp/guide: the guide's sections, and per client one snippet per transport (`variants`: the page offers a
    Copy for each; `configs` joins a client's variants into one text, for older pages)."""
    st = mcp.load_state()
    http = st if st.get("transport") == "http" else None
    return {"sections": [{"title": t, "rows": [list(r) if isinstance(r, tuple) else r for r in rows]} for t, rows in mcp.guide_lines(http)],
            "variants": [{"key": b.get("key", ""), "display": b["display"], "path": b["path"], "variants": [list(v) for v in b["variants"]]}
                         for b in mcp.client_config_variants(http)],
            "configs": mcp.client_configs(http)}


def help_page(topic: str) -> str:
    from . import help as helpmod
    try:
        words = shlex.split(topic or "")
    except ValueError:   # an apostrophe ("what's new") is not a syntax error for a help search
        words = (topic or "").replace('"', " ").replace("'", " ").split()
    try:
        return helpmod.page(words[0] if words else None, words[1] if len(words) > 1 else None)
    except (Exception, ui.Abort) as e:  # noqa: BLE001
        return f"no help for {topic!r}: {_err_text(e)}"


def explain_page(q: str) -> tuple[int, dict]:
    """GET /api/explain?q=<query>: the structured `cs explain` page (explain.lookup), for the console's "?" buttons and
    Explain panel. Documentation only: answered in-process, no job, no audit entry. Nothing found is still a 200 answer
    (found: false, did_you_mean, error); a q over explain.MAX_QUERY characters is refused (400). The caller's own words
    (query, cli, error) are redacted like everything else the console shows."""
    from . import explain
    if len(q) > explain.MAX_QUERY:
        return 400, {"error": f"q is too long (at most {explain.MAX_QUERY} characters)"}
    res = explain.lookup(q)
    for k in ("query", "cli", "error"):
        res[k] = secrets.redact(res[k])
    return 200, res


def explain_names() -> dict:
    """GET /api/explain/names: every explainable thing once, {names: [{kind, name, summary, query}]} (search, ⌘K, tooltips)."""
    from . import explain
    return {"names": explain.names()}


# ---------------------------------------------------------------- http

def secrets_token(n: int = 24) -> str:
    import secrets as _s
    return _s.token_urlsafe(n)


def load_token() -> str | None:
    try:
        return TOKEN_PATH.read_text().strip() or None
    except OSError:
        return None


def ensure_token(rotate: bool = False) -> str:
    tok = None if rotate else load_token()
    if tok:
        return tok
    UI_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(UI_DIR, 0o700)
    except OSError:
        pass
    tok = secrets_token(24)
    tmp = TOKEN_PATH.with_name(TOKEN_PATH.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(tok + "\n")
    os.replace(tmp, TOKEN_PATH)     # a running console never sees a half-written token
    return tok


def load_state() -> dict:
    try:
        s = json.loads(STATE_PATH.read_text())
        return s if isinstance(s, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(s: dict) -> None:
    UI_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(s, indent=2) + "\n")


def _hp(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def url(with_token: bool = False, s: dict | None = None) -> str:
    """The console's address (from `s`, default the saved state), optionally with the token that opens it."""
    s = load_state() if s is None else s
    base = f"http://{_hp(str(s.get('host') or '127.0.0.1'))}:{s.get('port') or DEFAULT_PORT}/"
    tok = load_token() if with_token else None
    return base + (f"?token={tok}" if tok else "")


def _log(msg: str) -> None:
    try:
        UI_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {secrets.redact(msg)}\n")
    except OSError:
        pass


class _State:
    token: str | None = None
    token_sig: tuple | None = None
    host = "127.0.0.1"
    port = DEFAULT_PORT
    lock = threading.Lock()


def current_token() -> str | None:
    """The token as it is on disk now (re-read when the file changes), so `cs ui token --rotate` takes effect without
    restarting the console; the previous token stops working at once."""
    try:
        st = TOKEN_PATH.stat()
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        return _State.token
    with _State.lock:
        if sig != _State.token_sig:
            tok = load_token()
            if tok:
                _State.token, _State.token_sig = tok, sig
        return _State.token


MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
        ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json", ".woff2": "font/woff2"}
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class _HTTPError(Exception):
    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code = code


WEB_FILES = ("index.html", "locked.html", "boot.js", "app.js", "style.css")   # what the console cannot work without


def missing_web_files() -> list[str]:
    return [n for n in WEB_FILES if not (WEB_ROOT / n).is_file()]


def _page(name: str, token: str | None = None) -> bytes:
    """index.html / locked.html with the token filled in and the bootstrap script that keeps it out of the address bar."""
    body = (WEB_ROOT / name).read_bytes()
    if token:
        body = body.replace(b"__CS_TOKEN__", token.encode())
    if BOOT_TAG not in body:
        body = body.replace(b"</head>", BOOT_TAG + b"</head>", 1)
    return body


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"cloudseed-ui/{__version__}"
    timeout = 120          # a client that stalls mid-request (short body, idle keep-alive) cannot pin a thread forever

    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        self._sent = True
        super().end_headers()

    # ---- helpers
    def _send(self, code: int, body: bytes = b"", ctype: str = "application/json", extra: dict | None = None) -> None:
        headers = {"Content-Type": ctype, "Content-Length": str(len(body)), "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                   "Content-Security-Policy": CSP, "X-Frame-Options": "DENY", "Cross-Origin-Resource-Policy": "same-origin", "Cache-Control": "no-store"}
        headers.update(extra or {})
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code: int, obj, extra: dict | None = None) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), extra=extra)

    def send_error(self, code, message=None, explain=None):
        """Errors the HTTP layer raises itself (a malformed request line, headers too long, an unknown method): JSON with
        the same security headers as every other answer, not Python's bare HTML page."""
        self.close_connection = True
        short = self.responses.get(code, ("error",))[0] if hasattr(self, "responses") else "error"
        head = getattr(self, "command", None) == "HEAD" or code < 200 or code in (204, 304)
        try:
            self._send(code, b"" if head else json.dumps({"error": str(message or short)}).encode(), extra={"Connection": "close"})
        except OSError:
            pass

    def _not_allowed(self):
        self._sent = False
        # the request's body (a PUT/PATCH usually has one) is never read: on a kept-alive connection it would be parsed
        # as the next request (a spurious 400, and a pipelined request after it lost), so this answer ends the connection
        self.close_connection = True
        if not self._host_ok():
            return
        extra = {"Allow": "GET, POST", "Connection": "close"}
        if self.command == "HEAD":         # headers only
            self._send(405, b"", extra=extra)
        else:
            self._json(405, {"error": f"method {self.command} not allowed (GET, POST)"}, extra=extra)

    do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_allowed

    def _host_ok(self) -> bool:
        """Only requests addressed to this server by a loopback name (defeats DNS rebinding). The console is local-only;
        from another machine use an SSH tunnel to the same port (ssh -L 7434:127.0.0.1:7434 <host>)."""
        host = (self.headers.get("Host") or "").strip().lower()
        if not host:
            return True
        names = {n.lower() for n in LOOPBACK + (_State.host,)}
        allowed = {f"{_hp(n)}:{_State.port}" for n in names} | ({_hp(n) for n in names} if _State.port == 80 else set())
        if host in allowed:
            return True
        self.close_connection = True
        self._json(403, {"error": "unexpected Host header", "hint": f"open http://127.0.0.1:{_State.port}/"})
        return False

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        try:
            u = urlsplit(origin)
            port = u.port or (443 if u.scheme == "https" else 80)
        except ValueError:
            return False
        return (u.hostname or "") in LOOPBACK + (_State.host,) and port == _State.port

    def _authed(self, api: bool) -> bool:
        if not self._origin_ok():
            self.close_connection = True
            self._json(403, {"error": "origin not allowed"})
            return False
        presented = self.headers.get("X-CS-Token")
        if not presented and self.command == "GET":   # EventSource streams cannot send headers
            presented = (parse_qs(urlsplit(self.path).query).get("token") or [None])[0]
        tok = current_token()
        if tok and presented and mcp.secrets_eq(presented, tok):
            return True
        self.close_connection = True
        self._json(401, {"error": "not authorized", "hint": "open the URL printed by `cs ui token` (it carries the token)"})
        return False

    def _read_json(self):
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise _HTTPError(411, "send the request body with a Content-Length (chunked bodies are not supported)")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            raise _HTTPError(400, "invalid Content-Length") from None
        if n < 0:
            self.close_connection = True
            raise _HTTPError(400, "invalid Content-Length")
        if n > MAX_BODY:
            self.close_connection = True
            raise _HTTPError(413, f"request body too large (max {MAX_BODY} bytes)")
        raw = self.rfile.read(n) if n else b""
        if not raw.strip():
            return {}
        try:
            body = json.loads(raw)
        except ValueError:
            raise _HTTPError(400, "the request body is not valid JSON") from None
        if body is None:
            return {}
        if not isinstance(body, dict):
            raise _HTTPError(400, "the request body must be a JSON object")
        return body

    def _error(self, e: BaseException, where: str) -> None:
        """Answer with JSON for any failure (unless a streamed response has already started)."""
        if isinstance(e, (BrokenPipeError, ConnectionResetError)):
            return
        if isinstance(e, NeedsConfirm):
            code, obj = 409, {"error": str(e), "needs_confirm": True, "argv": e.argv}
        elif isinstance(e, Conflict):
            code, obj = 409, {"error": str(e), "conflict": True, "job": e.job}
        elif isinstance(e, _HTTPError):
            code, obj = e.code, {"error": str(e)}
        elif isinstance(e, (ValueError, PermissionError)):
            code, obj = 400, {"error": str(e)}
        else:
            _log(f"api error {where}: {type(e).__name__}: {_err_text(e)}")
            code, obj = 500, {"error": f"{type(e).__name__}: {_err_text(e)}" if not isinstance(e, ui.Abort) else _err_text(e)}
        if getattr(self, "_sent", False):
            self.close_connection = True
            return
        try:
            self._json(code, obj)
        except OSError:
            pass

    # ---- routes
    def do_GET(self):
        self._sent = False
        if not self._host_ok():
            return
        try:
            self._get()
        except (Exception, ui.Abort) as e:  # noqa: BLE001 - never drop a request without an answer
            self._error(e, urlsplit(self.path).path)

    def _get(self):
        u = urlsplit(self.path)
        p = u.path.rstrip("/") or "/"
        qs = parse_qs(u.query)
        if p == "/health":   # `home` (a hash, never the path): another CLOUDSEED_HOME's console is not taken for this one
            self._json(200, {"ok": True, "server": "cloudseed-ui", "version": __version__, "home": mcp._home_id(), "pid": os.getpid()})
            return
        if p == "/":
            tok = (qs.get("token") or [None])[0]
            cur = current_token()
            ok = bool(tok and cur and mcp.secrets_eq(tok, cur))
            try:
                page = _page("index.html", tok) if ok else _page("locked.html")
            except OSError:   # an installation without the web files (a bad package build) says so instead of a traceback
                _log(f"web console files missing: {', '.join(missing_web_files()) or WEB_ROOT}")
                self._send(500, (f"The cloudseed web console's files are missing from this installation ({WEB_ROOT}).\n"
                                 "Reinstall cloudseed; `cs ui serve` names the missing files.\n").encode(), "text/plain; charset=utf-8")
                return
            # the lock screen: 401 when a token was presented and refused; a plain visit is not an error (its boot
            # script re-opens the console with the token this tab already holds, e.g. on reload)
            self._send(401 if tok and not ok else 200, page, "text/html; charset=utf-8")
            return
        if p.startswith("/static/") or p.startswith("/assets/"):
            root = (WEB_ROOT if p.startswith("/static/") else ASSETS).resolve()
            f = (root / p.split("/", 2)[2]).resolve()
            if root not in f.parents or not f.is_file():
                self._json(404, {"error": "not found"})
                return
            self._send(200, f.read_bytes(), MIME.get(f.suffix, "application/octet-stream"), {"Cache-Control": "no-cache"})
            return
        if not p.startswith("/api/"):
            self._json(404, {"error": "not found"})
            return
        if not self._authed(api=True):
            return
        if p == "/api/state":
            self._json(200, state())
        elif p == "/api/actions":
            self._json(200, actions_catalog())
        elif p == "/api/reports":
            self._json(200, reports((qs.get("env") or [""])[0]))
        elif p == "/api/platform/status":
            self._json(200, platform_status((qs.get("env") or [""])[0]))
        elif p == "/api/file":
            text = read_env_file((qs.get("path") or [""])[0])
            self._json(200 if text is not None else 404, {"text": text} if text is not None else {"error": "not readable (only logs and reports of an environment)"})
        elif p == "/api/help":
            self._json(200, {"text": help_page((qs.get("topic") or [""])[0])})
        elif p == "/api/explain":
            self._json(*explain_page((qs.get("q") or [""])[0]))
        elif p == "/api/explain/names":
            self._json(200, explain_names())
        elif p == "/api/jobs":
            self._json(200, [j.to_dict(tail=0) for j in recent_jobs(50)])
        elif p.startswith("/api/jobs/") and p.endswith("/stream"):
            self._stream(p.split("/")[3])
        elif p.startswith("/api/jobs/"):
            job = JOBS.get(p.split("/")[3])
            self._json(200 if job else 404, job.to_dict() if job else {"error": "no such job"})
        elif p == "/api/mcp/guide":
            self._json(200, mcp_guide())
        else:
            self._json(404, {"error": "unknown api"})

    def do_POST(self):
        self._sent = False
        if not self._host_ok():
            return
        if not self._authed(api=True):
            return
        p = urlsplit(self.path).path.rstrip("/")
        try:
            body = self._read_json()
            if p == "/api/run":
                if body.get("argv") is not None:
                    argv = raw_argv(body)
                    label = str(body.get("label") or " ".join(a for a in audit.safe_argv(argv)[:4] if a != "-y"))
                else:
                    action = body.get("action")
                    if not isinstance(action, str) or not action:
                        raise ValueError("send an action (e.g. cloudseed_status) and its args")
                    args = body.get("args")
                    if args is not None and not isinstance(args, dict):
                        raise ValueError("args must be a JSON object")
                    argv = build_argv(action, args or {})
                    label = str(body.get("label") or action.replace("cloudseed_", ""))
                job = start_job(argv, label[:120], env_key(argv))
                self._json(200, {"job": job.id, "argv": job.argv, "env": job.key})   # the masked command, as the job lists show it
            elif p.startswith("/api/jobs/") and p.endswith("/cancel"):
                job = JOBS.get(p.split("/")[3])
                self._json(200 if job else 404, cancel_job(job) if job else {"cancelled": False, "error": "no such job"})
            elif p == "/api/creds":
                self._json(200, change_creds(body))
            elif p == "/api/env/use":
                self._json(200, use_env(body.get("id")))
            else:   # no /api/open: a page must never make this machine open an arbitrary URL, file or app scheme
                self._json(404, {"error": "unknown api"})
        except (Exception, ui.Abort) as e:  # noqa: BLE001 - a ui.Abort must not drop the connection either
            self._error(e, p)

    def _stream(self, jid: str) -> None:
        job = JOBS.get(jid)
        if not job:
            self._json(404, {"error": "no such job"})
            return
        job.ensure_loaded()
        try:   # EventSource resends the id of the last event it saw when it reconnects: continue after it
            last = int(self.headers.get("Last-Event-ID") or -1)
        except ValueError:
            last = -1
        q: queue.Queue = queue.Queue()
        with job.lock:
            backlog = job._snapshot()
            done = job.rc is not None
            if not done:
                job.subscribers.append(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(b"retry: 3000\n\n")
            for seq, line in backlog:
                if seq > last:
                    self.wfile.write(f"id: {seq}\ndata: {json.dumps(line)}\n\n".encode())
            self.wfile.flush()
            if done:
                self.wfile.write(f"event: done\ndata: {json.dumps(job.to_dict(tail=0), default=str)}\n\n".encode())
                self.wfile.flush()
                return
            while True:
                try:
                    item = q.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    continue
                if item is None:
                    self.wfile.write(f"event: done\ndata: {json.dumps(job.to_dict(tail=0), default=str)}\n\n".encode())
                    self.wfile.flush()
                    break
                seq, line = item
                if seq > last:
                    self.wfile.write(f"id: {seq}\ndata: {json.dumps(line)}\n\n".encode())
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with job.lock:
                if q in job.subscribers:
                    job.subscribers.remove(q)


# ---------------------------------------------------------------- credentials and the current environment

_KEY_RE = re.compile(r"[A-Z_][A-Z0-9_]*")


def _cred_key(k) -> str:
    key = str(k).strip().upper()
    if not _KEY_RE.fullmatch(key):
        raise ValueError(f"not a variable name: {str(k)[:60]!r} (letters, digits and _, not starting with a digit)")
    return key


def _audit(argv: list[str], rc: int = 0, **tags) -> None:
    """One line in the audit trail (~/.cloudseed/logs/audit.jsonl) for a change the console makes itself instead of
    through a job (the vault, the current environment): the same record the CLI writes for `cs creds ...` / `cs env
    ...`, secret values masked (audit.safe_argv), marked via=ui. Jobs are CLI runs and write their own. audit.record
    is thread-safe and best effort: the audit trail never fails a request."""
    audit.record(argv, rc, via="ui", **tags)


def _creds_rows() -> list[dict]:
    """The vault for the Credentials view (masked): a stored path that does not point at a file says so."""
    rows = creds.masked()
    for r in rows:
        if r.get("kind") == "path" and r.get("set"):
            warn = creds.path_warning(r["key"], str(r.get("hint") or ""))
            if warn:
                r["warning"] = warn
    return rows


def change_creds(body: dict) -> dict:
    """POST /api/creds {set: {KEY: value}, unset: [KEY], clear: true}. Everything is validated before anything is
    written; the undo entry is recorded after the write and puts back exactly what was there before. Every request
    lands in the audit trail like `cs creds set/unset/clear` (names only for secrets), failures included."""
    try:
        return _change_creds(body)
    except (Exception, ui.Abort) as e:  # noqa: BLE001 - recorded, then answered as before
        what = body.get("set") if isinstance(body, dict) else None
        argv = (["creds", "set"] + [f"{k}=" for k in what] if isinstance(what, dict) and what else ["creds", "clear"] if isinstance(body, dict) and body.get("clear") is True
                else ["creds", "unset"] + [str(k) for k in (body.get("unset") or [])] if isinstance(body, dict) and isinstance(body.get("unset"), list) else ["creds"])
        _audit([str(a)[:80] for a in argv], rc=1, error=_err_text(e))
        raise


def _change_creds(body: dict) -> dict:
    set_ = body.get("set")
    unset = body.get("unset")
    if set_ is not None and not isinstance(set_, dict):
        raise ValueError("set must be an object {\"KEY\": \"value\"}")
    if unset is not None and not isinstance(unset, list):
        raise ValueError("unset must be a list of keys")
    pairs: dict[str, str] = {}
    for k, v in (set_ or {}).items():
        key = creds.check_key(_cred_key(k))   # the vault's own rules (refused names) before anything is written
        if isinstance(v, bool) or not isinstance(v, (str, int, float)):
            raise ValueError(f"{key}: the value must be text")
        v = str(v).strip() if key not in creds.KNOWN or creds.KNOWN[key][2] != "json" else str(v)
        if not v.strip():   # like `cs creds set KEY=`: an empty value is a mistake, removing is its own request (unset)
            raise ValueError(f"{key}: the value is empty. To delete a stored credential, remove it (unset). Nothing was changed.")
        try:                # what the value must be, as `cs creds set` checks it (GOOGLE_CREDENTIALS: a whole JSON key file)
            creds.check_value(key, v)
        except ValueError as e:
            msg = str(e).rstrip()
            raise ValueError(msg + (" " if msg.endswith(".") else ". ") + "Nothing was changed.") from None
        pairs[key] = creds._norm_value(key, v)   # what set_() would store, so a no-op is recognised as one
    stored = creds.load()
    # a name the vault now refuses (written by an older version or by hand) can still be removed
    keys_unset = [k if isinstance(k, str) and k in stored else _cred_key(k) for k in unset or []]
    changed = {k: v for k, v in pairs.items() if stored.get(k) != v}
    try:
        for k, v in changed.items():
            creds.set_(k, v)
    except (OSError, ValueError):
        creds.save(stored)                   # all or nothing, like `cs creds set`
        raise
    if pairs:
        _audit(["creds", "set"] + [f"{k}={v}" for k, v in pairs.items()], changed=sorted(changed))
    if changed:   # one entry, as `cs creds set` records it: undo puts back overwritten values and removes new keys
        undo.record(undo.GLOBAL, "creds set " + " ".join(changed), "creds-restore",
                    {"values": {k: stored[k] for k in changed if k in stored}, "unset": [k for k in changed if k not in stored]})
    removed: dict[str, str] = {}
    if keys_unset:
        now = creds.load()
        removed = {k: now[k] for k in dict.fromkeys(keys_unset) if k in now}
        for k in removed:
            creds.unset(k)
        _audit(["creds", "unset"] + list(dict.fromkeys(keys_unset)), removed=sorted(removed))
        if removed:
            undo.record(undo.GLOBAL, "creds unset " + " ".join(removed), "creds-restore", {"values": removed})
    cleared = False
    if body.get("clear") is True:
        now = creds.load()
        if now:
            undo.record(undo.GLOBAL, "creds clear", "creds-restore", {"values": now})
            cleared = True
        creds.clear()
        _audit(["creds", "clear"], cleared=cleared)
    creds.refresh()
    # a key-file path that points nowhere is stored (the file may come later), but the console says so, like the CLI
    warnings = [w for w in (creds.path_warning(k, v) for k, v in pairs.items()) if w]
    return {"creds": _creds_rows(), "changed": sorted(set(changed) | set(removed)), "cleared": cleared, "warnings": warnings}


def use_env(env_id) -> dict:
    """POST /api/env/use {id}: select the current environment (unknown ids are refused; no-ops record nothing in the
    undo journal). Every request lands in the audit trail like `cs env use` / `cs env clear`."""
    argv = ["env", "use", str(env_id)[:80]] if env_id else ["env", "clear"]
    try:
        out = _use_env(env_id)
    except (Exception, ui.Abort) as e:  # noqa: BLE001
        _audit(argv, rc=1, error=_err_text(e))
        raise
    _audit(argv, changed=out["changed"])
    return out


def _use_env(env_id) -> dict:
    if env_id is not None and not isinstance(env_id, str):
        raise ValueError("id must be an environment id such as aws-dev")
    new = env_id or None
    known = [e.id for e in paths.Env.list_all()]
    if new and new not in known:
        raise ValueError(f"Unknown environment '{new}'. Known: {', '.join(known) or 'none'}")
    s = paths.load_settings()
    if s.get("current_env") == new:
        return {"current_env": new, "changed": False}
    # a run of switches takes one undo slot (like `cs env use`): undo goes back to the env selected before the run
    undo.record(undo.GLOBAL, f"env use {new or '(clear)'}", "settings-restore", undo.snapshot_settings(["current_env"]), coalesce="current_env")
    if new:
        s["current_env"] = new
    else:
        s.pop("current_env", None)
    paths.save_settings(s)
    return {"current_env": new, "changed": True}


# ---------------------------------------------------------------- server

class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128   # listen backlog: the socketserver default (5) resets connections when a page loads in parallel

    def server_bind(self):
        # HTTPServer performs reverse DNS here; a local console must start even
        # when the host resolver is slow or unavailable. No handler needs a PTR name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address):
        """One line in the console log instead of a traceback on stderr (= the service log) per broken connection."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError)):
            return
        _log(f"request from {client_address[0] if client_address else '?'} failed: {type(exc).__name__}: {exc}")


class _Server6(_Server):
    address_family = socket.AF_INET6


def _stderr_is_log() -> bool:
    try:
        a, b = os.fstat(sys.stderr.fileno()), os.stat(LOG_PATH)
    except (OSError, ValueError, AttributeError):
        return False
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _say(msg: str, managed: bool) -> None:
    """A start-up problem: on stderr (a terminal; the console log for launchd and background services), and in the
    console log for a service whose stderr goes elsewhere (systemd's journal): `cs ui start` / `restart` read it there."""
    if managed and not _stderr_is_log():
        _log(msg)
    else:
        sys.stderr.write(msg + "\n")


def _refuse(msg: str, rc: int, managed: bool) -> int:
    """A start that can never succeed as configured (disabled, a non-local address, files missing). A service run
    exits 0 so launchd (KeepAlive: SuccessfulExit false) and systemd (Restart=on-failure) do not restart it forever."""
    _say(msg, managed)
    return 0 if managed else rc


def serve(host: str | None = None, port: int | None = None) -> int:
    """Run the console in this process (what the launchd/systemd service runs, or `cs ui serve` in a terminal).
    Host and port default to the saved configuration so a foreground run matches `cs ui token`/`status`."""
    saved = load_state()
    host = mcp._bare_host(host or str(saved.get("host") or "127.0.0.1"))   # "[::1]" is ::1
    try:   # an explicit --port 0 is a mistake to report, not "the saved port"
        port = int(port if port is not None else (saved.get("port") or DEFAULT_PORT))
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    # a service run: our launchd/systemd/background definitions set MANAGED_ENV; a login item written by an older
    # version does not, but launchd names the job in XPC_SERVICE_NAME (a terminal has "0" or an app's name there)
    by_launchd = os.environ.get("XPC_SERVICE_NAME") in (LAUNCHD_LABEL, LEGACY_LAUNCHD_LABEL)
    managed = os.environ.get(MANAGED_ENV) == "1" or by_launchd
    if not paths.load_settings().get("ui") and not secrets.env_flag("CLOUDSEED_UI_FORCE"):
        if by_launchd:
            _drop_disabled_login_item(os.environ.get("XPC_SERVICE_NAME") or LAUNCHD_LABEL)
        return _refuse("cloudseed UI is disabled. Run: cs enable ui", 2, managed)
    if host not in LOOPBACK:
        return _refuse(f"Refusing to listen on {host}: the console is local-only (127.0.0.1, localhost or ::1). From another machine, "
                       f"use an SSH tunnel to the same port: ssh -L {port}:127.0.0.1:{port} <this host>", 2, managed)
    if not 1 <= port <= 65535:   # a hand-edited server.json, or --port 70000: no TCP port at all (bind would overflow)
        return _refuse(f"Invalid port {port}: a TCP port is 1-65535. Choose one with: cs ui serve --port <port>   "
                       "(the service: cs ui start --port <port>)", 2, managed)
    missing = missing_web_files()
    if missing:
        return _refuse(f"Error: the web console's files are missing from this installation ({WEB_ROOT}: {', '.join(missing)}); "
                       "reinstall cloudseed.", 1, managed)
    creds.refresh()
    _State.token = ensure_token()
    _State.token_sig = None
    _State.host, _State.port = host, port
    try:
        httpd = (_Server6 if ":" in host else _Server)((host, port), _Handler)
    except (OSError, OverflowError) as e:
        why = getattr(e, "strerror", None) or str(e) or type(e).__name__
        _say(f"Cannot listen on {_hp(host)}:{port}: {why}", managed)   # maybe transient (a port taken at login): retried
        return 1
    UI_DIR.mkdir(parents=True, exist_ok=True)
    PID_PATH.write_text(str(os.getpid()))
    prev = None
    if not managed:   # a foreground `cs ui serve`: status / token / open must find this server while it runs
        prev = {k: v for k, v in load_state().items() if k != "foreground_pid"}
        save_state({**prev, "host": host, "port": port, "foreground_pid": os.getpid()})
    _restore_jobs()
    _log(f"ui listening on http://{_hp(host)}:{port}/ pid={os.getpid()}" + ("" if managed else " (foreground)"))
    if not managed:   # a terminal run says where it is (the page needs the link with the token: never printed here)
        sys.stderr.write(f"cloudseed console on http://{_hp(host)}:{port}/ - open it with: cs ui open   "
                         "(the link with its token: cs ui token); Ctrl-C stops it\n")
        sys.stderr.flush()

    def _stop(*_):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for s in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(s, _stop)
        except (ValueError, OSError):
            pass
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
        try:
            if PID_PATH.exists() and PID_PATH.read_text().strip() == str(os.getpid()):
                PID_PATH.unlink()
        except OSError:
            pass
        if prev is not None and load_state().get("foreground_pid") == os.getpid():
            if prev:
                save_state(prev)
            else:
                try:
                    STATE_PATH.unlink()
                except OSError:
                    pass
        running = [j for j in JOBS.values() if j.running]
        note = f"{len(running)} job(s) keep running and reappear when the console starts again" if running else ""
        _log("ui stopped" + (f"; {note}" if note else ""))
        if note and not managed:   # Ctrl-C on a foreground console does not reach its jobs (own sessions): say so
            sys.stderr.write(f"cloudseed console stopped; {note} (output: {JOBS_DIR}).\n")
    return 0


# ---------------------------------------------------------------- service management (same shape as the MCP server)

def health(s: dict | None = None, timeout: float = 2.0) -> bool:
    """True when THIS home's console answers at the saved (or given) address. Never through an HTTP(S) proxy (the
    console is on this machine: a proxy would make it look down), and another CLOUDSEED_HOME's console on the same
    port is not ours (a console of an older version reports no home and is accepted)."""
    s = s or load_state()
    if not s:
        return False
    try:
        req = urllib.request.Request(f"http://{_hp(str(s.get('host', '127.0.0.1')))}:{s.get('port', DEFAULT_PORT)}/health", method="GET")
        with mcp._open(req, timeout) as r:
            data = json.loads(r.read().decode())
    except Exception:  # noqa: BLE001
        return False
    return isinstance(data, dict) and data.get("server") == "cloudseed-ui" and data.get("home") in (None, mcp._home_id())


def _serve_argv(s: dict) -> list[str]:
    return mcp._launcher() + ["ui", "serve", "--host", s["host"], "--port", str(s["port"])]


def _managed_env() -> dict:
    return {**mcp._service_env(), MANAGED_ENV: "1"}


START_TIMEOUT = 10.0     # seconds start() waits for the console to answer
RESTART_THROTTLE = 30    # launchd: at most one restart of a crashing console per this many seconds


def _service_exited(kind: str) -> bool:
    """True when launchd / systemd reports that the console process has already ended (it will not answer: stop waiting)."""
    try:
        if kind == "launchd":
            r = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{LAUNCHD_LABEL}"], capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                return False
            st = re.search(r"^\s*state = (.+)$", r.stdout, re.M)      # the first one is the service's own state
            if not st or st.group(1).strip() == "running":
                return False
            runs = re.search(r"^\s*runs = (\d+)", r.stdout, re.M)
            return bool((runs and int(runs.group(1)) > 0) or re.search(r"^\s*last exit (code = -?\d|reason = )", r.stdout, re.M))
        if kind == "systemd":
            r = subprocess.run(["systemctl", "--user", "show", "-p", "ActiveState", "-p", "SubState", f"{SYSTEMD_UNIT}.service"],
                               capture_output=True, text=True, timeout=5)
            props = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
            return props.get("ActiveState") in ("failed", "inactive") or props.get("SubState") == "auto-restart"
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return False


def _wait_started(s: dict, kind: str, proc: subprocess.Popen | None = None, timeout: float = START_TIMEOUT) -> bool:
    """Wait (at most `timeout` s) until the console answers; give up early when its process has already exited."""
    end = time.monotonic() + timeout
    check_at = time.monotonic() + 0.5          # give launchd/systemd a moment to spawn it before asking
    while True:
        if health(s, timeout=0.5):
            return True
        now = time.monotonic()
        if proc is not None and proc.poll() is not None:   # a background console that already exited (it logged why)
            return False
        if kind in ("launchd", "systemd") and now >= check_at:
            if _service_exited(kind):
                return False
            check_at = now + 1.0
        if now >= end:
            return False
        time.sleep(0.2)


def _plist_path(label: str | None = None) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label or LAUNCHD_LABEL}.plist"


def _unit_path(unit: str | None = None) -> Path:
    return Path.home() / ".config" / "systemd" / "user" / f"{unit or SYSTEMD_UNIT}.service"


_UNIT_ENV = re.compile(r'^Environment="?([A-Za-z_][A-Za-z0-9_]*)=([^"\n]*)"?\s*$', re.M)


def _service_definition(path: Path) -> dict | None:
    """{'home': the CLOUDSEED_HOME it runs, 'env': its environment variables, 'process_type': ...} of a login item file,
    None when it cannot be read. The home is decided as for the MCP server's (mcp._home_of): its CLOUDSEED_HOME, else
    <its HOME>/.cloudseed, else the OS user's default home - never this process's $HOME, which a sandbox may change."""
    try:
        if path.suffix == ".plist":
            with open(path, "rb") as fh:
                data = plistlib.load(fh)
            env = data.get("EnvironmentVariables") if isinstance(data, dict) else None
            env = {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}
            ptype = data.get("ProcessType") if isinstance(data, dict) else None
        else:
            env = dict(m.groups() for m in _UNIT_ENV.finditer(path.read_text(errors="replace")))
            ptype = None
        home = mcp._home_of(env)
    except Exception:  # noqa: BLE001 - unreadable or not a plist: not ours to judge
        return None
    return {"home": home, "env": env, "process_type": ptype}


def _home_of(path: Path) -> bool | None:
    """True / False: the login item runs this CLOUDSEED_HOME / another one; None: it cannot be read."""
    d = _service_definition(path)
    if not d:
        return None
    try:
        return Path(d["home"]).expanduser().resolve() == mcp._home_path()
    except (OSError, RuntimeError):
        return None


def _runs_this_home(path: Path) -> bool:
    return _home_of(path) is True


def _targets(own_name: str, legacy_name: str, path_of) -> list[tuple[str, Path]]:
    """(name, file) of this home's console service: its own name (unless that file runs another home, which only the
    shared default name can), plus the shared name an older version installed for this home."""
    out = []
    own = path_of(own_name)
    if own_name != legacy_name or not own.exists() or _home_of(own) is not False:
        out.append((own_name, own))
    legacy = path_of(legacy_name)
    if own_name != legacy_name and legacy.exists() and _runs_this_home(legacy):
        out.append((legacy_name, legacy))
    return out


def _launchd_targets() -> list[tuple[str, Path]]:
    return _targets(LAUNCHD_LABEL, LEGACY_LAUNCHD_LABEL, _plist_path)


def _systemd_targets() -> list[tuple[str, Path]]:
    return _targets(SYSTEMD_UNIT, LEGACY_SYSTEMD_UNIT, _unit_path)


def _drop_disabled_login_item(label: str) -> None:
    """A login item that started the console although it is disabled (left by an older version, or by an undo the
    service itself interrupted) can only refuse at every login: remove its file (launchd keeps the loaded job until
    logout; it exits 0 now and is not restarted). Only this home's."""
    plist = _plist_path(label)
    if plist.exists() and _runs_this_home(plist):
        try:
            plist.unlink()
            _log(f"removed the login item {plist}: the console is disabled (cs enable ui adds it again)")
        except OSError:
            pass


def login_item() -> str | None:
    """'launchd' / 'systemd' when this home's console is installed as a login item (its plist / unit file exists, under
    its own name or the shared name an older version gave it), else None. Read from the files on disk, never from
    server.json, whose 'service' is only the preference for the next start."""
    for kind, targets in (("launchd", _launchd_targets()), ("systemd", _systemd_targets())):
        if any(p.exists() for _n, p in targets):
            return kind
    return None


def leftover_service(settings: dict | None = None) -> str | None:
    """What is wrong with this home's console login item, for `cs ui status` / `cs doctor` (None: nothing): installed
    while the console is disabled (at every login it can only refuse), or written by an older version (no service
    marker: it may restart forever; background priority: every job runs throttled)."""
    settings = paths.load_settings() if settings is None else settings
    for _name, path in _launchd_targets() + _systemd_targets():
        if not path.exists():
            continue
        if not settings.get("ui"):
            return f"a login item is still installed although the console is disabled: {path}  (remove it: cs disable ui)"
        d = _service_definition(path) or {}
        outdated = (d.get("env") or {}).get(MANAGED_ENV) != "1" or (path.suffix == ".plist" and d.get("process_type") != "Interactive")
        if outdated or path.stem != (LAUNCHD_LABEL if path.suffix == ".plist" else SYSTEMD_UNIT):
            return f"the login item was written by an older version: {path}  (rewrite it: cs ui restart)"
    return None


def _run_quietly(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass


def _os_reason(e: OSError) -> str:
    """An OSError in words: 'File exists' for a folder that is a file says the wrong thing."""
    if isinstance(e, (FileExistsError, NotADirectoryError)):
        return "a file is in the way where a folder should be"
    return e.strerror or str(e) or type(e).__name__


def _drop_old_definition(path: Path) -> None:
    """Delete the login item file an older version installed for this home under the shared name (it was booted out
    first). One that cannot be deleted (a read-only folder) is reported, never a reason not to start."""
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        ui.warn(f"cannot remove the old login item {path} ({_os_reason(e)}): it starts this console under its old name at "
                "login until it is removed.")


def _write_definition(path: Path, write) -> bool:
    """Write a login item file (plist / unit) through write(binary file); False, with a warning, when it cannot be
    written (a read-only or foreign-owned ~/Library/LaunchAgents, a full disk): the console then starts as a background
    process that does not come back at login, instead of failing. Nothing half-written is left behind."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "wb") as fh:
            write(fh)
        os.replace(tmp, path)
        return True
    except OSError as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        why = _os_reason(e)
        where = str(e.filename) if e.filename and str(e.filename) not in (str(path), str(tmp)) else ""   # the folder
        # a plist already there (an earlier start's) is booted out now, but launchd loads it again at the next login;
        # a unit is disabled by the caller, so it does not start then
        stale = path.suffix == ".plist" and path.exists()
        ui.warn(f"cannot write {path} ({where + ': ' if where else ''}{why}); starting a background process instead ("
                + ("the file already there keeps its old settings and still starts the console at login" if stale else
                   "it does not start again at login") + " until the file can be written: cs ui restart).")
        return False


def start(s: dict) -> str:
    """Start this home's console as `s` says (host, port; service: launchd / systemd / background, default the
    platform's) and return how it runs. A login item that cannot be installed falls back to a background process; the
    saved `service` stays the preference, so the next start (cs ui restart) tries the login item again. A service
    manager that refuses for the same reason as at the last start (systemd --user is never usable under WSL, in a
    container or over SSH) is not warned about again: the console still starts, in the background, as it did then."""
    UI_DIR.mkdir(parents=True, exist_ok=True)
    kind = s.get("service") if s.get("service") in ("launchd", "systemd", "background") else mcp._service_kind()
    wanted = kind
    last_refusal = s.pop("refused", load_state().get("refused"))    # what the last start fell back from, and why

    def refused(key: str, message: str) -> None:
        s["refused"] = key           # kept for the next start: the same refusal again is no news
        if key != last_refusal:
            ui.warn(message)
    argv = _serve_argv(s)
    proc = None
    if kind == "launchd":
        uid = os.getuid()
        for label, old in _launchd_targets():   # this home's login item from an older version (the shared label): replaced
            if label != LAUNCHD_LABEL:
                subprocess.run(["launchctl", "bootout", f"gui/{uid}/{label}"], capture_output=True)
                _drop_old_definition(old)
        plist = _plist_path()
        if plist.exists() and _home_of(plist) is False:
            ui.warn(f"{plist} ran another cloudseed home's console (an older version shared this login item); that console now "
                    "needs `cs ui start` from its own home.")
        # jobs run in their own sessions; AbandonProcessGroup keeps anything else alive too. A refusal that cannot
        # change by retrying exits 0 (serve), which KeepAlive does not restart; a crash is retried at most every 30 s.
        # Interactive: the console runs what the user asks for, now - "Background" would throttle it and every job
        # (terraform, ansible, helm) to background CPU / disk / network priority.
        if _write_definition(plist, lambda fh: plistlib.dump(
                {"Label": LAUNCHD_LABEL, "ProgramArguments": argv, "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                 "ThrottleInterval": RESTART_THROTTLE, "StandardOutPath": str(LOG_PATH), "StandardErrorPath": str(LOG_PATH),
                 "EnvironmentVariables": _managed_env(), "WorkingDirectory": str(Path.home()), "ProcessType": "Interactive",
                 "AbandonProcessGroup": True}, fh)):
            subprocess.run(["launchctl", "bootout", f"gui/{uid}/{LAUNCHD_LABEL}"], capture_output=True)
            r = subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(plist)], capture_output=True, text=True)
            if r.returncode != 0:
                r = subprocess.run(["launchctl", "load", "-w", str(plist)], capture_output=True, text=True)
            if r.returncode != 0:
                why = r.stderr.strip() or r.stdout.strip() or f"exit code {r.returncode}"
                refused(f"launchd: {why}", f"launchd refused the service ({why}); starting a background process instead.")
                kind = "background"
        else:   # an old definition under this name must not start a second console on the same port
            _run_quietly(["launchctl", "bootout", f"gui/{uid}/{LAUNCHD_LABEL}"])
            kind = "background"
    if kind == "systemd":
        for name, old in _systemd_targets():     # the shared unit an older version installed for this home: replaced
            if name != SYSTEMD_UNIT:
                subprocess.run(["systemctl", "--user", "disable", "--now", f"{name}.service"], capture_output=True)
                _drop_old_definition(old)
        unit = _unit_path()
        envs = "\n".join(f'Environment="{k}={v}"' for k, v in _managed_env().items())
        # KillMode=process: stopping the console must not kill the jobs it started (they are followed again on start).
        # Restarts: only on a failure (a refusal exits 0; exit 2 is a usage error), and at most 5 per 5 minutes.
        text = (f"[Unit]\nDescription=cloudseed web UI (local)\nAfter=network.target\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\n"
                f"[Service]\nType=simple\nExecStart={' '.join(shlex.quote(a) for a in argv)}\nRestart=on-failure\nRestartSec=3\n"
                f"RestartPreventExitStatus=2\nKillMode=process\n{envs}\n\n[Install]\nWantedBy=default.target\n")
        existed = unit.exists()
        if _write_definition(unit, lambda fh: fh.write(text.encode())):
            r = subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True)
            if r.returncode == 0:
                r = subprocess.run(["systemctl", "--user", "enable", "--now", f"{SYSTEMD_UNIT}.service"], capture_output=True, text=True)
            elif not existed:
                # systemd --user is not usable here (WSL or a container without it, an SSH session without a user bus):
                # the unit was never enabled, so it would only make status / doctor claim a login item. One that was
                # there before (enabled from a desktop session) is kept.
                try:
                    unit.unlink()
                except OSError:
                    pass
            if r.returncode != 0:
                why = r.stderr.strip() or r.stdout.strip() or f"exit code {r.returncode}"
                refused(f"systemd: {why}", f"systemd --user is not usable here ({why}); starting a background process "
                        "instead.")
                kind = "background"
        else:
            _run_quietly(["systemctl", "--user", "disable", "--now", f"{SYSTEMD_UNIT}.service"])
            kind = "background"
    if kind == "background":
        with open(LOG_PATH, "a") as log:   # serve() writes its own pid file once it listens: a child that fails leaves none behind
            proc = subprocess.Popen(argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True, env=dict(creds.shell_env(), **_managed_env()))
    s["service"] = wanted            # the preference (a fallback is not remembered as one)
    s["started_as"] = kind
    s["started_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    s.pop("foreground_pid", None)
    save_state(s)
    _wait_started(s, kind, proc)
    return kind


def _our_pid() -> int | None:
    """The pid in the pid file, only if that process is still a cloudseed console (`ui serve`); a stale file (crash,
    SIGKILL, reboot: the pid may now belong to anything) is removed instead of trusted."""
    try:
        pid = int(PID_PATH.read_text().strip())
    except (OSError, ValueError):
        return None
    ok = pid > 1 and pid not in (os.getpid(), os.getppid()) and _alive(pid)
    if ok:
        cmd = _proc_cmdline(pid)
        ok = cmd is None or " ui serve" in f" {cmd}"
    if not ok:
        try:
            if PID_PATH.read_text().strip() == str(pid):
                PID_PATH.unlink()
        except OSError:
            pass
        return None
    return pid


def stop() -> bool:
    """Stop this home's console (its launchd/systemd service stays installed: it starts again at login). Another
    CLOUDSEED_HOME's console is never touched, even one on the old shared service name."""
    stopped = False
    if shutil.which("launchctl"):
        for label, plist in _launchd_targets():
            if not plist.exists():
                continue
            r = subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{label}"], capture_output=True)
            stopped = stopped or r.returncode == 0
            for _ in range(20):
                if subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{label}"], capture_output=True).returncode != 0:
                    break
                time.sleep(0.25)
    if shutil.which("systemctl"):
        for name, unit in _systemd_targets():
            if unit.exists():
                r = subprocess.run(["systemctl", "--user", "disable", "--now", f"{name}.service"], capture_output=True)
                stopped = stopped or r.returncode == 0
    pid = _our_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            stopped = True
        except OSError:
            pass
    for _ in range(20):
        if not health(timeout=0.5):
            break
        time.sleep(0.25)
    _our_pid()   # drops the pid file if it now names a process that is gone
    return stopped


def remove_service() -> None:
    """Stop this home's console and remove its login item (launchd plist / systemd unit), old shared names included."""
    targets = [p for _n, p in _launchd_targets() + _systemd_targets()]
    stop()
    for p in targets + [PID_PATH]:
        try:
            p.unlink()
        except OSError:
            pass


def running_pid() -> int | None:
    return _our_pid()


def free_port(preferred: int) -> int:
    for port in [preferred] + list(range(preferred + 1, preferred + 50)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise ui.Abort(f"No free TCP port near {preferred}; pass --port.")


def open_browser() -> bool:
    try:
        return webbrowser.open(url(with_token=True))
    except Exception:  # noqa: BLE001
        return False
