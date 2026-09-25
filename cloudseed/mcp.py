"""cloudseed MCP server: every cloudseed feature as a Model Context Protocol tool, resource and prompt.

Transports
  * stdio (default)  - the client launches `cloudseed mcp serve`; no network port, the client process is the only peer.
  * http             - `cloudseed setup mcp` deploys a local Streamable-HTTP server (127.0.0.1:<port>/mcp, bearer token,
                       legacy SSE at /sse for older clients) as a launchd / systemd user service, so several clients
                       (Claude Code, Codex, Cursor, Gemini CLI, VS Code, ...) share one running server.

Security model (same as the built-in agent)
  * tools run `cloudseed ...` as a child under the credential session broker: the client process never sees secrets,
    every result is redacted before it is returned.
  * every call is checked against the tool's inputSchema (types, enums, required and unknown arguments) before anything runs.
  * anything that changes infrastructure, a host or a service (setup apply, apply, destroy, update-ip, provision, node,
    platform, mutating kubectl/helm, vpn add-user/revoke/provision, databricks/snowflake commands, scans that run jobs,
    dr, chaos, install, undo, remote ssh commands) requires `confirm: true`; so does reading Kubernetes Secrets or helm
    release values/manifests (helm get values/all/manifest/hooks, helm status -o json|yaml, helm template/lint: they
    carry passwords that redaction cannot always recognise), kubectl get --raw (other than health endpoints) and any
    kubectl/helm option that points the tool at another server, identity or local file. kubectl/helm calls are read by
    the built-in agent's fail-closed reader (builtin_agent.kube_approval): what it cannot read needs confirm.
    A scanner missing on this machine is never installed by a tool call.
  * the credential session is rebuilt for every call from the vault as it is now: a key set, rotated or removed in the
    web console or with `cs creds` reaches the next call of a long-running server.
  * meta commands (agentic, enable/disable, use, mcp) are not exposed, and cloudseed_undo cannot revert global actions
    (MCP/UI/credential/agent settings): only the user can, from a terminal or the web console.
  * http: loopback only, bearer token (0600 file), Origin and Content-Type validated (no DNS rebinding, no cross-site
    form posts), 401 without the token.
  * a client can cancel a running call (notifications/cancelled): the command's process group gets SIGINT, so Terraform
    stops gracefully; long calls report progress when the client asks for it.

Wire it up:  cs setup mcp     ->  deploys the server, connects the clients you pick, prints the full guide.
Run it:      cs mcp serve     (stdio, launched by clients)   ·   cs mcp serve --http  (what the service runs)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import plistlib
import queue
import re
import shlex
import shutil
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__, paths, secrets, skills, ui
from . import platform as catalog   # the platform catalog (the stdlib `platform` above is the OS module)

PROTOCOL = "2025-06-18"
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
STRUCTURED_SINCE = "2025-06-18"     # the first protocol version with a tool result's structuredContent
MAX_OUTPUT = 16000
MAX_JSON_OUTPUT = 4 * MAX_OUTPUT   # a JSON result is returned whole up to this size (cut in half it would not parse)
CLOUDS = ["aws", "gcp", "azure", "vmware"]
SERVER_NAME = "cloudseed"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7433
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
MCP_DIR = paths.HOME / "mcp"
STATE_PATH = MCP_DIR / "server.json"
TOKEN_PATH = MCP_DIR / "token"
LOG_PATH = MCP_DIR / "server.log"
PID_PATH = MCP_DIR / "server.pid"
GUIDE_PATH = MCP_DIR / "CONNECT.md"
BACKUPS_DIR = MCP_DIR / "backups"
LAUNCHD_LABEL = "io.cloudseed.mcp"
SYSTEMD_UNIT = "cloudseed-mcp"
MANAGED_ENV = "CLOUDSEED_MCP_MANAGED"   # set by the launchd/systemd/background service: `mcp serve --http` is not a foreground run

TOOL_TIMEOUT = 3600            # seconds one tool call may run
PROGRESS_EVERY = 10.0          # seconds between progress notifications (when the client sent a progressToken)
INTERRUPT_GRACE = 120          # seconds Terraform gets to stop gracefully after SIGINT before SIGTERM / SIGKILL
CLIENT_TIMEOUT_SEC = 3600      # per-call timeout written into client configs that support one (Codex, Gemini)
MAX_BODY = 16 * 1024 * 1024    # largest HTTP request body accepted
MAX_SESSIONS = 256             # HTTP sessions kept (least recently used are evicted)
SESSION_TTL = 24 * 3600        # idle HTTP sessions older than this are dropped
KEEP_BACKUPS = 5               # client-config backups kept per client (plus the first one, which is never pruned)
ORDER_WAIT = 2.0               # seconds a finished stdio response waits for an earlier request still running (see _Ordered)


# =============================================================================================== schemas & validation
def _p(**props) -> dict:
    return {"type": "object", "properties": props, "additionalProperties": False}


S_CLOUD = {"type": "string", "enum": CLOUDS, "description": "target: aws | gcp | azure | vmware"}
ENV_NAME = r"^[a-z][a-z0-9-]{1,23}$"       # the CLI's rule for environment names (cli.NAME_RE): a bad name fails here, not in a child
ENV_ID = rf"^({'|'.join(CLOUDS)})-[a-z][a-z0-9-]{{1,23}}$"
ENV_REF = rf"^([a-z][a-z0-9-]{{1,23}}|({'|'.join(CLOUDS)})-[a-z][a-z0-9-]{{1,23}})$"    # a name (dev) or an id (aws-dev)
# a Go duration as Velero takes it (720h, 72h30m, 720h0m0s), or whole days (30d), which `cs dr` rewrites to hours (720h)
DURATION = r"^(\d+d|(?=\d)(\d+h)?(\d+m)?(\d+s)?)$"
# scan --host: bastion / vpn / k8s, separated by commas or spaces as scan.parse_hosts splits them
SCAN_HOSTS = r"^[\s,]*(bastion|vpn|k8s)([\s,]+(bastion|vpn|k8s))*[\s,]*$"
S_ENV = {"type": "string", "minLength": 1, "pattern": ENV_NAME,
         "description": "environment name, e.g. dev (lowercase letters, digits, hyphens). Blank: the cloud's only environment, "
                        "else the current one for read-only tools, else dev; tools that change things never guess"}
# what a pattern means, for the 'invalid arguments' answer (an agent corrects itself from it)
_PATTERN_HINTS = {ENV_NAME: "use 2-24 lowercase letters, digits or hyphens, starting with a letter",
                  ENV_ID: "an environment id such as aws-dev (cloudseed_list shows them)",
                  ENV_REF: "an environment name such as dev, or an id such as aws-dev (cloudseed_list shows them)",
                  DURATION: "a duration such as 720h, 72h30m, 90m or 30d (days become hours: 30d = 720h)",
                  SCAN_HOSTS: "host names bastion, vpn, k8s, comma-separated, e.g. bastion,k8s"}
S_VARS = {"type": "object", "additionalProperties": True,
          "description": "stack variables to override, e.g. {\"enable_kubernetes\": true}; null resets a saved override to its default. "
                         "Variables cloudseed sets itself (name, region, network CIDRs, allowed_ssh_cidrs, tags/labels, "
                         "ssh_public_key ...) are refused: use the dedicated fields (name, region, cidr, allow_ip, tags)"}
S_CONFIRM = {"type": "boolean", "description": "must be true to run a destructive action (ask the user first)"}
S_WORD = {"type": "string", "minLength": 1, "pattern": r"^[^-\s]"}          # a value passed as a positional argument: must not look like an option
S_WORDS = {"type": "array", "items": S_WORD}


def _count(desc: str, minimum: int = 1, maximum: int | None = None) -> dict:
    """An integer argument with the same bounds the CLI's parser enforces (so a bad value is refused before anything runs)."""
    return {"type": "integer", "minimum": minimum, **({"maximum": maximum} if maximum is not None else {}), "description": desc}


class InvalidParams(ValueError):
    """A request whose parameters are invalid at the protocol level (JSON-RPC -32602)."""


def _tname(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def _check(schema: dict, v, path: str) -> str | None:
    """Validate one value against the JSON-Schema subset the tool schemas use. Returns an error or None."""
    typ = schema.get("type")
    if typ == "string" and not isinstance(v, str):
        return f"{path}: expected string, got {_tname(v)}"
    if typ == "boolean" and not isinstance(v, bool):
        return f"{path}: expected boolean (true/false), got {_tname(v)}"
    if typ == "integer" and (isinstance(v, bool) or not isinstance(v, int)):
        return f"{path}: expected integer, got {_tname(v)}"
    if typ == "number" and (isinstance(v, bool) or not isinstance(v, (int, float))):
        return f"{path}: expected number, got {_tname(v)}"
    if typ == "array":
        if not isinstance(v, list):
            return f"{path}: expected array" + (f" of {schema['items'].get('type', 'values')}s" if isinstance(schema.get("items"), dict) else "") + f", got {_tname(v)}"
        if len(v) < schema.get("minItems", 0):
            return f"{path}: needs at least {schema['minItems']} item(s)"
        items = schema.get("items")
        if isinstance(items, dict):
            for i, x in enumerate(v):
                e = _check(items, x, f"{path}[{i}]")
                if e:
                    return e
    if typ == "object":
        if not isinstance(v, dict):
            return f"{path}: expected object, got {_tname(v)}"
        props, extra = schema.get("properties") or {}, schema.get("additionalProperties", True)
        for k, x in v.items():
            if k in props:
                e = _check(props[k], x, f"{path}.{k}")
            elif isinstance(extra, dict):
                e = _check(extra, x, f"{path}.{k}")
            elif extra is False:
                e = f"{path}: unknown key {k!r}"
            else:
                e = None
            if e:
                return e
    if "enum" in schema and v not in schema["enum"]:
        return f"{path}: must be one of {', '.join(repr(x) for x in schema['enum'])}, got {v!r}"
    if isinstance(v, str):
        if len(v) < schema.get("minLength", 0):
            return f"{path}: must not be empty" if not v else f"{path}: must be at least {schema['minLength']} characters long"
        if schema.get("pattern") and not re.search(schema["pattern"], v):
            return f"{path}: {v!r} is not allowed here ({_pattern_why(schema['pattern'], v)})"
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if "minimum" in schema and v < schema["minimum"]:
            return f"{path}: must be >= {schema['minimum']}, got {v}"
        if "maximum" in schema and v > schema["maximum"]:
            return f"{path}: must be <= {schema['maximum']}, got {v}"
    return None


def _pattern_why(pattern: str, v: str) -> str:
    """Why a string failed its pattern, in words (the rule the value broke, not the regex, where it is known)."""
    if pattern in _PATTERN_HINTS:
        return _PATTERN_HINTS[pattern]
    if v.lstrip().startswith("-"):
        return "it must not start with '-'"
    if v[:1].isspace():
        return "it must not start with a space"
    return f"pattern {pattern}"


def validate_args(t: dict, args, strict: bool = True) -> tuple[dict, str | None]:
    """Check a call's arguments against the tool schema. Returns (normalised args, error or None).
    `confirm` is always accepted (it must be a boolean); JSON null (and "" for an optional field) counts as absent;
    integral floats (2.0) become ints.
    strict=False ignores unknown keys instead of rejecting them (the web console sends a few shared form fields)."""
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return {}, f"arguments must be an object, got {_tname(args)}"
    schema = t["schema"]
    props = schema.get("properties") or {}
    required = set(t.get("required") or [])
    out: dict = {}
    for k, v in args.items():
        if v is None or (v == "" and k not in required):
            continue
        spec = props.get(k) or (S_CONFIRM if k == "confirm" else None)
        if spec is None:
            if strict and schema.get("additionalProperties") is False:
                return {}, f"unknown argument {k!r} (allowed: {', '.join(sorted(props)) or 'none'})"
            continue
        if spec.get("type") == "integer" and isinstance(v, float) and v.is_integer():
            v = int(v)
        e = _check(spec, v, k)
        if e:
            return {}, e
        out[k] = v
    for k in t.get("required") or []:
        v = out.get(k)
        if v is None or (isinstance(v, str) and not v.strip()) or (isinstance(v, (list, dict)) and not v):
            return {}, f"missing required argument {k!r}"
    return out, None


def schema_hint(t: dict) -> str:
    """One line describing the expected arguments (returned with 'invalid arguments' so an agent can correct itself)."""
    req = set(t.get("required") or [])
    parts = []
    for k, s in (t["schema"].get("properties") or {}).items():
        typ = s.get("type", "any")
        if "enum" in s:
            typ = "|".join(str(x) for x in s["enum"] if x != "")
        elif typ == "array":
            typ = f"array of {(s.get('items') or {}).get('type', 'values')}s"
        parts.append(f"{k} ({typ}{', required' if k in req else ''})")
    return ", ".join(parts) or "no arguments"


# =============================================================================================== argv helpers
def _on(a: dict, k: str) -> bool:
    """Boolean flags count only when they are really true (never "false", 1 or "no")."""
    return a.get(k) is True


def _cloud(a: dict) -> str:
    c = a.get("cloud")
    if c not in CLOUDS:
        raise ValueError(f"cloud must be one of {', '.join(CLOUDS)}")
    return c


def _opt_cloud(a: dict) -> list[str]:
    return [_cloud(a)] if a.get("cloud") else []


def _env_args(a: dict) -> list[str]:
    return [_cloud(a)] + (["--env", a["env"]] if a.get("env") else [])


def _opt(a: dict, key: str, flag: str) -> list[str]:
    v = a.get(key)
    return [flag, str(v)] if v not in (None, "", False) else []


def _yes(a: dict, read_only: tuple) -> list[str]:
    """-y always (never a prompt). --auto-approve only for the actions that need confirm=true: it is also the consent
    to install a missing kubectl/helm/cloud CLI (services.ensure_tool) or Velero and its cloud prerequisites, which a
    read-only list/status must never do on its own."""
    return ["-y"] if a.get("action") in read_only else ["-y", "--auto-approve"]


def _var_args(a: dict) -> list[str]:
    out = []
    for k, v in (a.get("vars") or {}).items():
        out += ["--var", f"{k}={json.dumps(v) if not isinstance(v, str) else v}"]
    return out


def _split(a: dict, key: str = "args") -> list[str] | None:
    """shlex-split a string argument; None when it is not a string or cannot be parsed."""
    v = a.get(key)
    if v is None:
        return []
    if not isinstance(v, str):
        return None
    try:
        return shlex.split(v)
    except ValueError:
        return None


def _words(a: dict, key: str = "args") -> list[str]:
    w = _split(a, key)
    if w is None:
        raise ValueError(f"{key}: cannot parse {a.get(key)!r} (unbalanced quotes?)")
    return w


def _first_word(a: dict, key: str = "args") -> str:
    return ((_split(a, key) or [])[:1] or [""])[0]


def _env_opt(words: list[str]) -> tuple[str | None, int]:
    """A leading `--env NAME` / `-e NAME` / `--env=NAME` / `-eNAME` as `cs kubectl|helm` reads it (cli._pull_env_arg):
    (the name, how many words it takes), else (None, 0)."""
    if words[:1] in (["--env"], ["-e"]) and len(words) > 1:
        return words[1], 2
    if words and words[0].startswith("--env="):
        return words[0].split("=", 1)[1], 1
    if words and words[0].startswith("-e") and not words[0].startswith("--") and len(words[0]) > 2:
        return words[0][2:], 1
    return None, 0


def _sep(words: list[str]) -> list[str]:
    """Drop one leading `--`, as `cs kubectl|helm` does each time it reads the words (cli._strip_leading_sep)."""
    return words[1:] if words[:1] == ["--"] else list(words)


def _kube_words(a: dict) -> tuple[str | None, str | None, list[str]]:
    """(cloud, env, the tool's own words) of a cloudseed_kubectl/helm call. `cs kubectl|helm` reads a cloud key and
    `--env NAME` in front of the tool's arguments as its own cluster selectors, in any order, then one `--`
    (cli._kube_passthrough); after that explicit `--` the words are the tool's (cli tool_verbatim: cmd_ktool only drops
    one more leading `--`). An agent's 'aws --env dev get pods' is taken apart here and passed as cloudseed's, in front
    of the `--` cloudseed adds; so is one more cloud key / --env NAME after one or two leading `--`. A selector read
    twice, one still in front of the words the tool gets, or one that contradicts the cloud/env field is refused: the
    cluster is never picked silently. Raises ValueError."""
    got: dict[str, str | None] = {"cloud": None, "env": None}
    twice = ValueError("args name the cluster more than once (a cloud key or --env where one was already read): pass it "
                       "once, in the cloud and env fields")

    def take(key: str, value: str) -> None:
        if got[key] is not None:
            raise twice
        got[key] = value

    rest = list(_words(a))
    while rest:                                     # _kube_passthrough: a cloud key and --env NAME, in any order
        if rest[0] in CLOUDS and got["cloud"] is None:
            take("cloud", rest.pop(0))
            continue
        value, n = _env_opt(rest)
        if n and got["env"] is None:
            take("env", value)
            rest = rest[n:]
            continue
        break
    rest = _sep(_sep(rest))                         # its `--`, then cmd_ktool's
    if rest and rest[0] in CLOUDS:
        take("cloud", rest.pop(0))
    value, n = _env_opt(rest)
    if n:
        take("env", value)
        rest = rest[n:]
    rest = _sep(rest)
    # cloudseed sends [tool, cloud, --env NAME, "--"] + rest: a selector still in front of rest reaches the tool as its
    # first word, which an agent never means - refused, like a repeat
    again = _sep(rest)
    if again and (again[0] in CLOUDS or _env_opt(again)[1]):
        raise twice
    cloud, env = got["cloud"], got["env"]
    if env is not None and not re.match(ENV_NAME, env):
        raise ValueError(f"args: --env {env!r} is not an environment name ({_PATTERN_HINTS[ENV_NAME]})")
    for key, picked in (("cloud", cloud), ("env", env)):
        if picked is not None and a.get(key) and a[key] != picked:
            raise ValueError(f"args select {key} {picked!r} but the {key} field says {a[key]!r}: pass the cluster once, in "
                             f"the cloud and env fields")
    return cloud or a.get("cloud"), env or a.get("env"), rest


def _kube_reason(tool: str, a: dict) -> str | None:
    """Why this kubectl/helm call needs confirm=true, or None for a plain read. The built-in agent's fail-closed reader
    (builtin_agent.kube_approval) decides, so an agent session and an MCP client get the same answer: a write, a Secret
    read (get secret, --raw other than health endpoints, helm get values/all/manifest/hooks, helm status -o json|yaml,
    helm template/lint), an option that points the tool at another server, identity or local file (--server,
    --kubeconfig, --context, --token, --as, get -f URL, -o *-file ...) or an option before the verb it cannot read."""
    try:
        _cloud_, _env_, rest = _kube_words(a)
    except ValueError as e:
        return str(e)
    from . import builtin_agent     # lazily: the reader imports cli, which imports this module
    return builtin_agent.kube_approval(tool, rest, verbatim=True)   # rest follows cloudseed's own `--` (_kube_argv)


def _kubectl_mutating(a: dict) -> bool:
    return _kube_reason("kubectl", a) is not None


def _helm_mutating(a: dict) -> bool:
    return _kube_reason("helm", a) is not None


_MANAGED_READ_PAIRS = {("current-user", "me"), ("auth", "describe"), ("auth", "profiles"), ("connection", "list"), ("connection", "test"),
                       ("fs", "ls"), ("fs", "cat")}
_MANAGED_NEVER_READ = {"sql", "secrets", "api", "auth", "connect", "tokens", "token-management"}
_MANAGED_READ_VERB = re.compile(r"^(list|get|describe|ls|show)(-[a-z0-9-]+)?$")


def _managed_words(words: list[str]) -> list[str]:
    """What the vendor CLI will see, parsed like cmd_managed: a leading `--profile X` / `--profile=X` is cloudseed's own
    option, `--env X` / `-e X` are pulled out up to a `--`, and `--` itself is dropped. So an option value can never
    pose as the command (`--profile status clusters delete x` is a delete)."""
    out: list[str] = []
    i, sep = 0, False
    while i < len(words):
        w = words[i]
        if not out and not sep and w == "--profile":
            i += 2
            continue
        if not out and not sep and w.startswith("--profile="):
            i += 1
            continue
        if not sep and w in ("--env", "-e") and i + 1 < len(words):
            i += 2
            continue
        if w == "--":
            sep = True
            i += 1
            continue
        out.append(w)
        i += 1
    return out


def _managed_mutating(a: dict) -> bool:
    """databricks/snowflake passthrough: only status, test, help, --help/--version and plain list/get/describe commands
    run without confirm; everything else (sql, connect, create, delete, ...) needs it. Unknown shapes fail closed."""
    words = _split(a)
    if words is None:
        return True
    words = _managed_words(words)
    if not words or words[0] in ("status", "test", "help"):
        return False
    if len(words) == 1 and words[0] in ("--help", "-h", "help", "--version", "version"):
        return False
    if words[0].startswith("-") or len(words) < 2:
        return True
    if (words[0], words[1]) in _MANAGED_READ_PAIRS:
        return False
    if words[0] in _MANAGED_NEVER_READ:
        return True
    return not _MANAGED_READ_VERB.match(words[1])


def _managed_argv(a: dict) -> list[str]:
    """cs databricks|snowflake [--profile P] [--env <env or cloud-env>] <args>: env picks the environment whose profile is
    used (the console sends the environment chosen on its page; the CLI's current environment is never switched)."""
    svc = a.get("service")
    if svc not in ("databricks", "snowflake"):
        raise ValueError("service must be databricks or snowflake")
    words = _words(a)
    env = []
    if a.get("env"):
        if _env_opt(words)[1]:
            raise ValueError("the environment is given twice (env and a leading --env in args): use the env field only")
        ref, cloud = a["env"], a.get("cloud")
        if cloud and not ref.startswith(_cloud(a) + "-"):     # (an id of that cloud, or such a name, is matched as it is)
            ref = f"{cloud}-{ref}"
        env = ["--env", ref]
    elif a.get("cloud"):
        raise ValueError("cloud needs env too (together they name the environment whose profile is used, e.g. cloud=aws env=dev)")
    return [svc] + _opt(a, "profile", "--profile") + env + (words or ["status"])


def _skill_argv(a: dict) -> list[str]:
    name = a.get("name")
    if not name:
        return ["skill", "list"]
    p = skills._lookup(name)      # short names too, like `cs skill show aws` (never skills.resolve: its Abort is a SystemExit)
    if p is None:
        raise ValueError(f"unknown skill {name!r}; available: {', '.join(skills.short_names())} (short or full names, e.g. aws or cloudseed-aws)")
    return ["skill", "show", p.name]


def _kube_argv(tool: str):
    """cloudseed_kubectl / cloudseed_helm: cloud and env are passed on their own, like `cs kubectl [cloud] [--env NAME]`
    (one without the other must never be dropped: the command would run on another cluster). The user's words follow
    an explicit `--` (the documented `cs kubectl [cloud] [--env NAME] [--] <args>` form): they belong to the tool, and a
    -y or --runtime among them is never taken as cloudseed's own option. Selectors written into args are moved in front
    of the `--` (see _kube_words)."""
    def argv(a: dict) -> list[str]:
        cloud, env, rest = _kube_words(a)
        if cloud is not None and cloud not in CLOUDS:
            raise ValueError(f"cloud must be one of {', '.join(CLOUDS)}")
        return [tool] + ([cloud] if cloud else []) + (["--env", env] if env else []) + ["--"] + rest
    return argv


def _env_argv(a: dict) -> list[str]:
    """cloudseed_env: an id alone means `use` (what an agent means by it); an id with show/clear is refused, not ignored."""
    act = a.get("action") or ("use" if a.get("id") else "show")
    if a.get("id") and act != "use":
        raise ValueError(f"id goes with action=use only (action={act} takes none)")
    return ["env", act] + ([a["id"]] if a.get("id") else [])


def _help_argv(a: dict) -> list[str]:
    words = _words(a, "topic")
    return ["help"] + words + ([] if not a.get("cloud") or a["cloud"] in words else [_cloud(a)])


_DR_READ_ONLY = ("status", "backups", "describe", "logs")


def _dr_argv(a: dict) -> list[str]:
    volume = {"on": ["--volume"], "off": ["--no-volume"]}.get(a.get("volume") or "", [])
    words = [a["name"]] if a.get("name") else []
    if a.get("action") in ("describe", "logs"):   # `dr describe|logs backup|restore <name>`
        if a.get("kind") not in ("backup", "restore") or not a.get("name"):
            raise ValueError(f"action={a.get('action')} needs kind (backup or restore) and name (the Velero object's name, "
                             "see action=backups)")
        words = [a["kind"], a["name"]]
    return (["dr", a["action"]] + words + _opt(a, "cloud", "--cloud") + _opt(a, "env", "--env")
            + _opt(a, "namespaces", "--namespaces") + _opt(a, "cron", "--cron") + _opt(a, "ttl", "--ttl")
            + (["--no-wait"] if _on(a, "no_wait") else []) + (["--keep"] if _on(a, "keep") else []) + volume
            + (["--details"] if _on(a, "details") and a.get("action") == "describe" else []) + _yes(a, _DR_READ_ONLY))


def _ssh_argv(a: dict) -> list[str]:
    command = a.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    if command.lstrip().startswith("-"):
        raise ValueError("command must not start with '-' (it would be read as an ssh option, not a remote command)")
    # ONE argument: ssh hands it to the remote shell unchanged, so the command's own quoting survives
    return ["ssh"] + _env_args(a) + ["--", "-o", "BatchMode=yes", command]


def _undo_argv(a: dict) -> list[str]:
    argv = ["undo"] + _opt_cloud(a) + (["--env", a["env"]] if a.get("env") else []) + (["--id", a["id"]] if a.get("id") else [])
    if _on(a, "list"):
        return argv + ["--list"]
    if not (a.get("cloud") or a.get("id")):
        raise ValueError("say what to " + ("drop" if _on(a, "drop") else "undo") + ": cloud (+ env) for the newest action of an environment, "
                         "or the id of an entry from list=true")
    return argv + (["--drop"] if _on(a, "drop") else []) + ["-y", "--auto-approve"]


_SETUP_OPTS = ("name", "region", "state", "cidr", "allow_ip", "workdir", "project_id", "subscription_id", "profile")
# provisioning switches: (argument, flag, description) - the CLI's own options of setup / provision
_NO_HARDEN = ("no_harden", "--no-harden", "provision without OS hardening; sshd settings, fail2ban, kernel/core-dump/sudo settings "
                                           "and audit rules from an earlier run are removed (PAM and umask edits stay; automatic "
                                           "updates are left as they are); the host firewall and IP forwarding stay (no_firewall)")
_NO_FIREWALL = ("no_firewall", "--no-firewall", "provision without the nftables host firewall (an earlier run's is removed; VPN/NAT "
                                               "hosts keep their NAT rule)")
_NO_TOOLS = ("no_tools", "--no-tools", "provision without installing terraform / the cloud CLI on the bastion")
_SETUP_SWITCHES = (("no_provision", "--no-provision", "apply only: do not copy the repo to the bastion and harden it with Ansible"),
                   _NO_HARDEN, _NO_FIREWALL, _NO_TOOLS)
_PROVISION_SWITCHES = (_NO_HARDEN, _NO_FIREWALL, _NO_TOOLS, ("sync_only", "--sync-only", "only copy the repository to the host(s); do not run Ansible"))


def _switch_props(switches) -> dict:
    return {k: {"type": "boolean", "description": d} for k, _f, d in switches}


def _switches(a: dict, switches) -> list[str]:
    return [f for k, f, _d in switches if _on(a, k)]


def _tag_args(a: dict) -> list[str]:
    """--tag KEY=VALUE for every tag. setup splits each at its first '=' and strips the key, so a key that is empty,
    holds '=' ('cost=center' would become tag 'cost') or starts/ends with a space is refused instead of changed."""
    out: list[str] = []
    for k, v in (a.get("tags") or {}).items():
        if not isinstance(k, str) or not k.strip():
            raise ValueError("tags: a tag key cannot be empty")
        if "=" in k:
            raise ValueError(f"tags: key {k!r} cannot contain '=' (tags are passed as KEY=VALUE)")
        if k != k.strip():
            raise ValueError(f"tags: key {k!r} starts or ends with a space")
        if not isinstance(v, str):
            raise ValueError(f"tags.{k}: the value must be a string")
        out += ["--tag", f"{k}={v}"]
    return out


def _setup_argv(a: dict) -> list[str]:
    # without apply: a plan that keeps nothing (--preview), unless save=true keeps the planned settings (--plan-only)
    return (["setup"] + _env_args(a) + ["-y"] + sum([[f"--{k.replace('_', '-')}", str(a[k])] for k in _SETUP_OPTS if a.get(k)], [])
            + _tag_args(a) + _var_args(a) + _switches(a, _SETUP_SWITCHES)
            + (["--dry-run"] if _on(a, "dry_run") else ["--auto-approve"] if _on(a, "apply") else ["--plan-only"] if _on(a, "save") else ["--preview"]))

# Per-tool keys: description, schema, required, argv(args) -> cloudseed argv.
#   destructive        always needs confirm=true
#   destructive_when   fn(args) -> bool: needs confirm=true for these calls (fail closed: an error counts as destructive)
#   confirm_when       what needs confirm, for the description
#   writes             changes local files/settings (so it is not advertised as read-only) without needing confirm
TOOLS: dict[str, dict] = {
    "cloudseed_list": {"description": "List all environments (cloud, region, state, bastion IP, working dir).", "schema": _p(), "argv": lambda a: ["list"]},
    "cloudseed_doctor": {"description": "Check tools, versions and cloud credentials. With a cloud it exits 1 when that cloud "
                                        "is not ready (a required tool missing or too old, no or invalid credentials; the "
                                        "last line says what); without one it always exits 0.", "schema": _p(cloud=S_CLOUD),
                         "argv": lambda a: ["doctor"] + _opt_cloud(a)},
    "cloudseed_setup": {"description": "Create or update an environment (network, bastion, baseline; optional Kubernetes/VPN). Shows the plan; apply=true applies it; dry_run=true only renders and validates. "
                                       "A plan creates nothing in the cloud: a new remote-state bucket/container is only planned then (with a throw-away local state) and created first on apply. "
                                       "Without apply nothing is kept either (like `cs setup --preview`): an existing environment keeps its saved configuration and a new one is "
                                       "not created, so the same call with apply=true applies what was shown. save=true instead keeps the planned settings for a later "
                                       "cloudseed_apply (like `cs setup --plan-only`; no undo point is recorded for them). Renaming a deployed environment (name) needs that: "
                                       "setup never applies a rename unattended, so plan it with save=true, show the plan, then call cloudseed_apply. "
                                       "To price an environment before creating it, call this with dry_run=true first (offline, no cloud credentials, "
                                       "saves its settings, creates nothing), then cloudseed_finops action=estimate; a plan without apply keeps nothing to estimate.",
                        "schema": _p(cloud=S_CLOUD, env=S_ENV, name={"type": "string"}, region={"type": "string"}, state={"type": "string", "enum": ["remote", "local"]},
                                     cidr={"type": "string"}, allow_ip={"type": "string"}, vars=S_VARS,
                                     apply={"type": "boolean", "description": "apply the plan (otherwise plan only: nothing is kept)"},
                                     save={"type": "boolean", "description": "without apply: keep the planned settings for a later cloudseed_apply (needed to rename a deployed environment)"},
                                     dry_run={"type": "boolean", "description": "render + terraform validate only; touches nothing"},
                                     tags={"type": "object", "additionalProperties": {"type": "string"},
                                           "description": "extra tags/labels on every resource, {key: value}; a key cannot be empty, contain '=' or start/end with a space"},
                                     workdir={"type": "string"}, project_id={"type": "string"}, subscription_id={"type": "string"}, profile={"type": "string"},
                                     **_switch_props(_SETUP_SWITCHES), confirm=S_CONFIRM),
                        "required": ["cloud"], "writes": True, "confirm_when": "only apply=true needs confirm=true (a plan or dry_run does not)",
                        "destructive_when": lambda a: _on(a, "apply") and not _on(a, "dry_run"),
                        "argv": _setup_argv},
    "cloudseed_plan": {"description": "Show what apply would change.", "schema": _p(cloud=S_CLOUD, env=S_ENV), "required": ["cloud"], "argv": lambda a: ["plan"] + _env_args(a)},
    "cloudseed_apply": {"description": "Apply the saved configuration (creates/changes cloud resources), including settings saved by an earlier cloudseed_setup "
                                       "call with save=true; call cloudseed_plan first to see what it would change.", "schema": _p(cloud=S_CLOUD, env=S_ENV, confirm=S_CONFIRM),
                        "required": ["cloud"], "destructive": True, "argv": lambda a: ["apply"] + _env_args(a) + ["-y", "--auto-approve"]},
    "cloudseed_destroy": {"description": "Destroy everything in an environment, or only the given Terraform targets (cloudseed_inventory lists the addresses). "
                                         "Targets that match nothing in the state are skipped with a warning; when none matches, nothing is changed and the call fails (exit code 1). "
                                         "purge_state / purge apply to a full destroy only.",
                          "schema": _p(cloud=S_CLOUD, env=S_ENV,
                                       targets={"type": "array", "items": {"type": "string", "minLength": 1, "pattern": r"^[^-\s]"},
                                                "description": "Terraform addresses to destroy only, e.g. module.stack.module.bastion (empty = everything)"},
                                       purge_state={"type": "boolean", "description": "also delete the remote state bucket/container (irreversible)"},
                                       purge={"type": "boolean", "description": "also delete the local env directory; config.json and the SSH keys are kept in the "
                                                                                "undo journal so cloudseed_undo can re-create the environment, VPN keys are not"},
                                       confirm=S_CONFIRM),
                          "required": ["cloud"], "destructive": True,
                          "argv": lambda a: ["destroy"] + _env_args(a) + ["-y", "--auto-approve"] + sum([["--target", t] for t in a.get("targets") or []], [])
                                   + (["--purge-state"] if _on(a, "purge_state") else []) + (["--purge"] if _on(a, "purge") else [])},
    "cloudseed_status": {"description": "Configuration, state summary, outputs and next steps of an environment.", "schema": _p(cloud=S_CLOUD, env=S_ENV), "required": ["cloud"],
                         "argv": lambda a: ["status"] + _env_args(a)},
    "cloudseed_output": {"description": "Stack outputs as JSON (bastion IP, subnet IDs, cluster endpoint...), returned on their own: notes "
                                        "and warnings follow separately.",
                         "schema": _p(cloud=S_CLOUD, env=S_ENV), "required": ["cloud"], "json_stdout": True,
                         "argv": lambda a: ["output"] + _env_args(a) + ["--json"]},
    "cloudseed_update_ip": {"description": "Re-detect the public IP (or use allow_ip) and apply the new bastion SSH allow-list. Cloud targets (aws, gcp, azure) only: "
                                           "not applicable to vmware (its VMs sit on a private VMware network this machine reaches directly; a vmware call changes nothing).",
                            "schema": _p(cloud=S_CLOUD, env=S_ENV, allow_ip={"type": "string", "description": "comma-separated IPs/CIDRs allowed to SSH to the bastion"}, confirm=S_CONFIRM),
                            "required": ["cloud"], "destructive": True,
                            "argv": lambda a: ["update-ip"] + _env_args(a) + ["-y", "--auto-approve"] + _opt(a, "allow_ip", "--allow-ip")},
    "cloudseed_ssh": {"description": "Run a shell command on the bastion over SSH (non-interactive) and return its output.",
                      "schema": _p(cloud=S_CLOUD, env=S_ENV, command={"type": "string", "minLength": 1, "pattern": r"^\s*[^-\s]", "description": "remote shell command, e.g. 'uptime' or \"sudo sh -c 'nft list ruleset; ss -tlnp'\""}, confirm=S_CONFIRM),
                      "required": ["cloud", "command"], "destructive": True, "argv": _ssh_argv},
    "cloudseed_provision": {"description": "Copy the repo to the bastion/VPN/k8s nodes and run the Ansible hardening/tooling (as root on the hosts).",
                            "schema": _p(cloud=S_CLOUD, env=S_ENV, host={"type": "string", "enum": ["bastion", "vpn", "k8s"], "description": "provision only this part (default: all)"},
                                         **_switch_props(_PROVISION_SWITCHES), confirm=S_CONFIRM), "required": ["cloud"],
                            "destructive": True, "argv": lambda a: ["provision"] + _env_args(a) + ["-y"] + _opt(a, "host", "--host") + _switches(a, _PROVISION_SWITCHES)},
    "cloudseed_inventory": {"description": "What exists in the environment (from state) and its change history.",
                            "schema": _p(cloud=S_CLOUD, env=S_ENV, json={"type": "boolean", "description": "JSON instead of the table, returned on its own (notes follow separately)"}),
                            "required": ["cloud"], "json_stdout": True, "argv": lambda a: ["inventory"] + _env_args(a) + (["--json"] if _on(a, "json") else [])},
    "cloudseed_troubleshoot": {"description": "Deterministic diagnosis: audit log, last failure, inventory, reachability, tools.", "schema": _p(cloud=S_CLOUD, env=S_ENV, log={"type": "boolean"}),
                               "required": ["cloud"], "argv": lambda a: ["troubleshoot"] + _env_args(a) + (["--log"] if _on(a, "log") else [])},
    "cloudseed_explain": {"description": "Explain how anything in cloudseed works: a feature (vpn, kubernetes, dr), a target (aws, gcp, azure, "
                                         "vmware), a command (destroy), a topic (envs), a platform group or item (security, istio) or a setup "
                                         "variable. A bare word is looked up as feature > target > platform group/item > command/topic; the "
                                         "namespaced forms pick one meaning: 'feature vpn', 'target vmware', 'command vpn', 'topic security', "
                                         "'group security', 'item velero', 'platform <group|item>', 'variables aws', 'variable aws "
                                         "single_nat_gateway' (or 'aws single_nat_gateway'). format=json returns the page as data (kind, title, "
                                         "summary, sections, commands, also, did_you_mean); the same data is the resource cloudseed://explain/{query}.",
                          "schema": _p(what={"type": "string", "description": "e.g. kubernetes, vmware, 'platform security', istio, destroy, "
                                                                              "'variable aws az_count'; empty = index"},
                                       format={"type": "string", "enum": ["text", "json"],
                                               "description": "text (default): the page as `cs explain` prints it; json: structured (explain.lookup)"}),
                          "argv": lambda a: ["explain"] + _words(a, "what") + (["--json"] if a.get("format") == "json" else [])},
    "cloudseed_help": {"description": "cloudseed help pages: command, topic, 'variables <cloud>', 'outputs <cloud>' (or topic=variables with cloud=aws).",
                       "schema": _p(topic={"type": "string"}, cloud=S_CLOUD), "argv": _help_argv},
    "cloudseed_k8s": {"description": "Kubernetes info for the environment's cluster; tunnel/untunnel open/close an SSH tunnel to a private API. "
                                     "kubeconfig merges the cluster into the user's own kubeconfig ($KUBECONFIG's first file, else ~/.kube/config) AND makes it "
                                     "the current kubectl context, so kubectl in every terminal of the user targets it from then on (the other contexts are kept; "
                                     "cloudseed_undo reverts it). cloudseed_kubectl/cloudseed_helm never need it (they use a per-environment kubeconfig): "
                                     "tell the user before calling it.",
                      "schema": _p(cloud=S_CLOUD, env=S_ENV, action={"type": "string", "enum": ["info", "kubeconfig", "tunnel", "untunnel"]}),
                      "required": ["cloud"], "writes": True, "argv": lambda a: ["k8s", a.get("action") or "info"] + _env_args(a)},
    "cloudseed_node": {"description": "Scale the cluster: list nodes, add N nodes, remove a node, or (EKS/GKE/AKS) set the managed pool "
                                      "size and autoscaler limits with scale.",
                       "schema": _p(action={"type": "string", "enum": ["list", "add", "remove", "scale"]}, cloud=S_CLOUD, env=S_ENV,
                                    count=_count("add: nodes to add · scale: the pool size"),
                                    min={"type": "integer", "minimum": 0, "description": "scale: autoscaler minimum (default: the new count)"},
                                    max=_count("scale: autoscaler maximum (default: unchanged, or the count when larger)"),
                                    role={"type": "string", "enum": ["worker", "control-plane"]}, name=S_WORD, confirm=S_CONFIRM),
                       "required": ["action"], "confirm_when": "add, remove and scale need confirm=true (list does not)", "destructive_when": lambda a: a.get("action") != "list",
                       "argv": lambda a: ["node", a["action"]] + _opt_cloud(a) + ([a["name"]] if a.get("name") else []) + _opt(a, "env", "--env")
                                + _opt(a, "count", "--count") + (["--min", str(a["min"])] if a.get("min") is not None else [])
                                + _opt(a, "max", "--max") + _opt(a, "role", "--role") + _yes(a, ("list",))},
    "cloudseed_platform": {"description": f"Platform catalog: list/status/plan/info/install/uninstall groups ({' '.join(catalog.GROUPS)}) or items (cloud prerequisites such as buckets/identities are applied first); ui exposes installed UIs.",
                           "schema": _p(action={"type": "string", "enum": ["list", "status", "plan", "info", "install", "uninstall", "ui"]}, items=S_WORDS,
                                        cloud=S_CLOUD, env=S_ENV, no_wait={"type": "boolean"}, upgrade={"type": "boolean"}, force={"type": "boolean"},
                                        set={"type": "array", "items": {"type": "string", "minLength": 1}, "description": "helm --set overrides, key=value"}, confirm=S_CONFIRM),
                           "required": ["action"], "confirm_when": "install, uninstall and ui need confirm=true (list, status, plan and info do not)",
                           "destructive_when": lambda a: a.get("action") not in ("list", "status", "plan", "info"),
                           "argv": lambda a: ["platform", a["action"]] + list(a.get("items") or []) + _opt(a, "cloud", "--cloud") + _opt(a, "env", "--env")
                                    + (["--no-wait"] if _on(a, "no_wait") else []) + (["--upgrade"] if _on(a, "upgrade") else []) + (["--force"] if _on(a, "force") else [])
                                    + sum([["--set", s_] for s_ in a.get("set") or []], []) + _yes(a, ("list", "status", "plan", "info"))},
    "cloudseed_kubectl": {"description": "Run kubectl against the cluster of the environment picked by cloud and/or env (either one alone works; "
                                         "neither = the current environment, cs env use, or the only cluster). Over MCP it runs without a "
                                         "terminal and returns its whole output at the end, so commands that never end are refused: "
                                         "follow/watch (logs -f, get -w), port-forward, proxy and attach; use logs --tail=200 or --since=10m, "
                                         "get without -w, or kubectl wait --for=condition=... --timeout=120s. Interactive ones (edit, "
                                         "exec/run/debug -i/-t) are refused too: those belong in the user's own terminal.",
                          "schema": _p(args={"type": "string", "minLength": 1, "description": "kubectl arguments, e.g. 'get pods -A' (the cluster goes in cloud/env)"},
                                       cloud=S_CLOUD, env=S_ENV, confirm=S_CONFIRM),
                          "required": ["args"], "confirm_when": "reads run directly (get, describe, logs, top, explain, version, api-resources, api-versions, "
                                                                "cluster-info, events); everything else needs confirm=true, a get of Secrets included, and so do "
                                                                "get --raw (except the health, version and metrics endpoints), get/describe -f/-k, -o *-file, "
                                                                "cluster-info dump --output-directory, any option that points kubectl at another server, identity "
                                                                "or local file (--server, --kubeconfig, --context, --token, --as, --insecure-skip-tls-verify ...) "
                                                                "and an option before the verb that cloudseed cannot read",
                          "destructive_when": _kubectl_mutating, "why": lambda a: _kube_reason("kubectl", a), "argv": _kube_argv("kubectl")},
    "cloudseed_helm": {"description": "Run helm against the cluster of the environment picked by cloud and/or env (either one alone works; "
                                      "neither = the current environment, cs env use, or the only cluster).",
                       "schema": _p(args={"type": "string", "minLength": 1, "description": "helm arguments, e.g. 'list -A' (the cluster goes in cloud/env)"},
                                    cloud=S_CLOUD, env=S_ENV, confirm=S_CONFIRM),
                       "required": ["args"], "confirm_when": "reads run directly (list, status with table output, history, show, search, version, env, "
                                                             "repo/dependency/plugin list, get notes/metadata); everything else needs confirm=true, including the "
                                                             "reads that carry release secrets: status -o json/yaml and get values/all/manifest/hooks, template/lint "
                                                             "(they render charts with values and files from this machine), and any option that points helm at "
                                                             "another server, identity or local file (--kube-apiserver, --kube-context, --kubeconfig, --kube-token ...)",
                       "destructive_when": _helm_mutating, "why": lambda a: _kube_reason("helm", a), "argv": _kube_argv("helm")},
    "cloudseed_vpn": {"description": "VPN: status, users, add-user, revoke, provision.",
                      "schema": _p(action={"type": "string", "enum": ["status", "users", "add-user", "revoke", "provision"]}, cloud=S_CLOUD, env=S_ENV,
                                   name={"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", "description": "VPN client name (letters, digits, . _ -)"}, confirm=S_CONFIRM),
                      "required": ["action", "cloud"], "confirm_when": "add-user, revoke and provision need confirm=true (status and users do not)",
                      "destructive_when": lambda a: a.get("action") not in ("status", "users"),
                      "argv": lambda a: ["vpn", a["action"], _cloud(a)] + ([a["name"]] if a.get("name") else []) + _opt(a, "env", "--env")},
    "cloudseed_finops": {"description": "Costs: estimate (offline), cloud bill, Kubernetes allocation (OpenCost), or a saved report. "
                                        "estimate prices a saved environment from its settings and inventory: for one that does not exist yet, "
                                        "call cloudseed_setup with dry_run=true first (offline, no credentials, creates nothing), then estimate.",
                         "schema": _p(action={"type": "string", "enum": ["estimate", "cloud", "k8s", "report"]}, cloud=S_CLOUD, env=S_ENV, days=_count("days of billing history (1-365)", maximum=365),
                                      window={"type": "string"}, by={"type": "string"}, save={"type": "boolean", "description": "also save the result as a report under <workdir>/finops/ (report always saves)"}),
                         "required": ["action"], "writes": True,
                         "argv": lambda a: ["finops", a["action"]] + _opt_cloud(a) + _opt(a, "env", "--env") + _opt(a, "days", "--days") + _opt(a, "window", "--window")
                                  + _opt(a, "by", "--by") + (["--save"] if _on(a, "save") else [])},
    "cloudseed_env": {"description": "Show or set the current environment for cluster commands (an id alone means use).",
                      "schema": _p(action={"type": "string", "enum": ["show", "use", "clear"]},
                                   id={"type": "string", "pattern": ENV_ID, "description": "environment id for use, e.g. aws-dev"}),
                      "writes": True, "argv": _env_argv},
    "cloudseed_managed": {"description": "Databricks / Snowflake: status, test, or pass a CLI command (profile per environment: env, or cloud + env, "
                                         "picks the environment whose profile is used; neither = the current environment's, else 'default').",
                          "schema": _p(service={"type": "string", "enum": ["databricks", "snowflake"]}, args={"type": "string", "description": "CLI arguments, e.g. 'clusters list' (default: status)"},
                                       profile={"type": "string", "description": "profile name (overrides the environment's)"},
                                       cloud={**S_CLOUD, "description": "with env: the environment's cloud (aws | gcp | azure | vmware), for a name several clouds use"},
                                       env={**S_ENV, "pattern": ENV_REF, "description": "the environment whose profile is used: a name (dev) or an id (aws-dev)"},
                                       confirm=S_CONFIRM),
                          "required": ["service"], "confirm_when": "status, test and plain list/get/describe commands run directly; anything else (sql, connect, create, delete, ...) needs confirm=true",
                          "destructive_when": _managed_mutating, "argv": _managed_argv},
    "cloudseed_chaos": {"description": "Chaos engineering: list experiments, run a suite/experiments (installs Chaos Mesh, prints PASS/FAIL), status, stop, last report.",
                        "schema": _p(action={"type": "string", "enum": ["run", "list", "status", "stop", "report"]}, items={**S_WORDS, "description": "suites (basic network stress full) or experiment names"},
                                     cloud=S_CLOUD, env=S_ENV, target={"type": "string", "description": "ns/deployment[:port] to test a real workload"}, duration=_count("seconds per experiment (15-3600, default 45)", minimum=15, maximum=3600),
                                     replicas=_count("run: canary replicas (2-20, default 3; not used with target)", minimum=2, maximum=20),
                                     keep={"type": "boolean", "description": "run: keep the canary namespace afterwards (chaos stop removes it)"}, confirm=S_CONFIRM),
                        "required": ["action"], "confirm_when": "run and stop need confirm=true (list, status and report do not)", "destructive_when": lambda a: a.get("action") not in ("list", "status", "report"),
                        "argv": lambda a: ["chaos", a["action"]] + list(a.get("items") or []) + _opt(a, "cloud", "--cloud") + _opt(a, "env", "--env")
                                 + _opt(a, "target", "--target") + _opt(a, "duration", "--duration") + _opt(a, "replicas", "--replicas")
                                 + (["--keep"] if _on(a, "keep") else []) + _yes(a, ("list", "status", "report"))},
    "cloudseed_dr": {"description": "Disaster recovery (Velero): status, backups, backup, restore, schedule, the automated drill `test` (create/backup/delete/restore/verify), "
                                    "or velero's own view of one backup/restore: describe (details=true lists every object and volume) and logs.",
                     "schema": _p(action={"type": "string", "enum": ["status", "backups", "backup", "restore", "schedule", "test", "describe", "logs"]}, name=S_WORD, cloud=S_CLOUD, env=S_ENV,
                                  kind={"type": "string", "enum": ["backup", "restore"], "description": "describe/logs: what `name` is"},
                                  details={"type": "boolean", "description": "describe: also list every object and volume (velero describe --details)"},
                                  namespaces={"type": "string"}, cron={"type": "string"},
                                  ttl={"type": "string", "pattern": DURATION, "description": "schedule: how long Velero keeps each backup, e.g. 720h, 72h30m or 30d "
                                                                                           "(days are rewritten to hours: 30d = 720h; default 720h)"},
                                  no_wait={"type": "boolean", "description": "backup/restore: return immediately instead of waiting for Velero"},
                                  keep={"type": "boolean", "description": "test: keep the drill namespace and backup for inspection"},
                                  volume={"type": "string", "enum": ["", "on", "off"], "description": "test: force the volume backup on or off (blank = when a default StorageClass exists)"},
                                  confirm=S_CONFIRM),
                     "required": ["action"], "confirm_when": "backup, restore, schedule and test need confirm=true (status, backups, describe and logs do not)",
                     "destructive_when": lambda a: a.get("action") not in _DR_READ_ONLY,
                     "argv": _dr_argv},
    "cloudseed_scan": {"description": "Scans with saved reports: architecture (AWS/Azure/GCP Well-Architected screening, common guidance for VMware; local configuration and saved evidence only, no live cloud checks), cis (kube-bench), kube (kubescape NSA/MITRE), images (trivy), host (OpenSCAP CIS), stig (DISA STIG), cloud (prowler CIS), fips (FIPS 140 verification), all (security scans only), reports. Architecture returns PASS, FAIL, or INCOMPLETE when required evidence is missing or stale.",
                       "schema": _p(kind={"type": "string", "enum": ["architecture", "cis", "kube", "images", "host", "stig", "cloud", "fips", "all", "reports"]}, cloud=S_CLOUD, env=S_ENV,
                                    profile={"type": "string", "enum": ["production", "lab", "cis", "stig"], "description": "architecture: production (default) or lab; host/all: cis (default) or stig"},
                                    max_age_days=_count("architecture: maximum age of saved evidence in days (default 30)", minimum=1, maximum=3650),
                                    json={"type": "boolean", "description": "architecture: return the full assessment as JSON"},
                                    framework={"type": "string"}, hosts={"type": "string", "pattern": SCAN_HOSTS, "description": "host/stig/all: comma-separated: bastion,vpn,k8s (default: every reachable host)"}, confirm=S_CONFIRM),
                       "required": ["kind"], "confirm_when": "every kind except architecture, fips and reports runs cluster jobs or Ansible on hosts and needs confirm=true; a scanner "
                                                             "missing on this machine is never installed by an MCP call (it stops with the install command for the user)",
                       "destructive_when": lambda a: a.get("kind") not in ("architecture", "fips", "reports"), "json_stdout": True,
                       "argv": lambda a: ["scan", a["kind"]] + _opt_cloud(a) + _opt(a, "env", "--env") + _opt(a, "profile", "--profile") + _opt(a, "framework", "--framework")
                                + _opt(a, "max_age_days", "--max-age-days") + (["--json"] if _on(a, "json") else [])
                                + (["--host", ",".join(h for h in re.split(r"[\s,]+", a["hosts"]) if h)] if a.get("hosts") else []) + ["-y"]},
    "cloudseed_undo": {"description": "Undo the newest state-changing action of an environment (fifteen kept per environment, at most five of one kind): restores the previous configuration and re-applies, uninstalls what was installed, revokes, deletes backups... "
                                      "list=true shows the history with entry ids; pass cloud (+ env), or the id of the newest entry of an environment. drop=true discards that entry "
                                      "without undoing it (for a step that can never succeed). Global actions (MCP/UI/credential/agent settings) can only be undone by the user "
                                      "(cs undo --global in a terminal, or the web console's Undo): an agent's call is refused.",
                       "schema": _p(cloud=S_CLOUD, env=S_ENV, id={"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$", "description": "entry id from list=true (must be the newest of its environment)"},
                                    list={"type": "boolean", "description": "show the history (with entry ids) instead of undoing"},
                                    drop={"type": "boolean", "description": "discard the entry from the history without undoing it (nothing is changed)"}, confirm=S_CONFIRM),
                       "confirm_when": "everything except list=true needs confirm=true", "destructive_when": lambda a: not _on(a, "list"), "argv": _undo_argv},
    "cloudseed_install": {"description": "Install a tool or group cloudseed needs: terraform aws gcloud az kubectl helm k9s openvpn tailscale go qemu-img vmware-provider | cloud vmware vpn.",
                          "schema": _p(what={**S_WORDS, "minItems": 1}, confirm=S_CONFIRM), "required": ["what"], "destructive": True,
                          "argv": lambda a: ["install", "-y"] + list(a["what"])},
    "cloudseed_skill": {"description": "Read one of the bundled agent skills (cloudseed, cloudseed-aws/gcp/azure/vmware, cloudseed-destroy, cloudseed-platform, ...): the operating manual for driving cloudseed.",
                        "schema": _p(name={"type": "string", "description": "skill name, short or full (aws = cloudseed-aws, platform, destroy ...); empty = list them"}),
                        "argv": _skill_argv},
}


def _is_destructive(t: dict, args: dict) -> bool:
    if t.get("destructive"):
        return True
    fn = t.get("destructive_when")
    if not fn:
        return False
    try:
        return bool(fn(args or {}))
    except Exception:  # noqa: BLE001 - an argument we cannot classify is treated as destructive (fail closed)
        return True


def _confirm_why(t: dict, args: dict) -> str:
    """Why this call needs confirm: its own reason where the tool can name it (kubectl/helm: 'kubectl --server points
    kubectl at another server ...'), else the tool's rule."""
    reason = None
    if t.get("why"):
        try:
            reason = t["why"](args or {})
        except Exception:  # noqa: BLE001 - the rule is still an answer
            reason = None
    if reason:
        return f": {reason}"
    return f" ({t['confirm_when']})" if t.get("confirm_when") else ""


def needs_confirm(t: dict, args: dict) -> bool:
    """True when this call must carry confirm=true (and does not). Shared with the web console."""
    return _is_destructive(t, args) and (args or {}).get("confirm") is not True


def tool_list() -> list[dict]:
    out = []
    for name, t in TOOLS.items():
        schema = dict(t["schema"])
        props = dict(schema.get("properties") or {})
        mutating = bool(t.get("destructive") or t.get("destructive_when"))
        if mutating and "confirm" not in props:
            props["confirm"] = S_CONFIRM     # a destructive tool must always be able to carry confirm (schemas are additionalProperties:false)
        schema["properties"] = props
        if t.get("required"):
            schema["required"] = list(t["required"])
        desc = t["description"]
        if t.get("destructive"):
            desc += " Needs confirm=true (ask the user first)."
        elif mutating:
            when = t.get("confirm_when") or "some uses need confirm=true (ask the user first)"
            desc += f" {when[:1].upper()}{when[1:]}."
        out.append({"name": name, "description": desc, "inputSchema": schema,
                    "annotations": {"title": name.replace("cloudseed_", "cloudseed ").replace("_", "-"), "destructiveHint": mutating,
                                    "readOnlyHint": not (mutating or t.get("writes")), "openWorldHint": True}})
    return out


# =============================================================================================== running a tool
def _launcher() -> list[str]:
    if paths.IS_BUNDLE:
        return [sys.executable]
    return [sys.executable, str(paths.REPO_ROOT / "bin" / "cloudseed")]


def _result(text: str, is_error: bool) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


_NO_JSON = object()


class _Call:
    """One in-flight tools/call: its child process and whether the client cancelled it."""

    def __init__(self, rid=None):
        self.rid = rid
        self.proc: subprocess.Popen | None = None
        self.cancelled = False
        self._lock = threading.Lock()

    def attach(self, proc: subprocess.Popen) -> bool:
        """Remember the child; False when the call was cancelled before it started (the caller interrupts it)."""
        with self._lock:
            self.proc = proc
            return not self.cancelled

    def cancel(self) -> None:
        with self._lock:
            if self.cancelled:
                return
            self.cancelled = True
            proc = self.proc
        if proc is not None and proc.poll() is None:
            threading.Thread(target=_interrupt, args=(proc,), daemon=True).start()


def _new_group() -> dict:
    # its own process group: a cancel/timeout can signal cloudseed AND the terraform/ansible/kubectl it runs, and a
    # client that kills the server does not signal a half-finished apply (its output goes to a file: see _output_file)
    return {"start_new_session": True} if os.name == "posix" else {}


def _signal_group(proc: subprocess.Popen, sig) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, sig)
        else:
            proc.send_signal(sig)
    except OSError:
        pass


def _interrupt(proc: subprocess.Popen, grace: float | None = None) -> None:
    """Stop a tool's process group like Ctrl-C would (Terraform shuts down gracefully and releases its lock),
    escalating to SIGTERM and SIGKILL when it does not exit in time."""
    grace = INTERRUPT_GRACE if grace is None else grace
    for sig, wait in ((signal.SIGINT, grace), (signal.SIGTERM, 10), (getattr(signal, "SIGKILL", signal.SIGTERM), 5)):
        if proc.poll() is not None:
            return
        _signal_group(proc, sig)
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _shell_join(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


def _output_file() -> tuple[int, io.FileIO]:
    """(write fd for the child's stdout+stderr, our read handle). The file is unlinked at once, so nothing lingers on
    disk. Unlike a pipe it never breaks: a child whose server exits mid-call (client closed, `cs mcp restart`) keeps
    writing to it and finishes, instead of dying of EPIPE/SIGPIPE halfway through a Terraform apply."""
    fd, path = tempfile.mkstemp(prefix="cloudseed-mcp-", suffix=".out")
    try:
        wfd = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            rfh = open(path, "rb", buffering=0)
        except OSError:
            os.close(wfd)
            raise
    finally:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
    return wfd, rfh


def _run(name: str, argv: list[str], env, call: _Call | None = None, progress=None) -> dict:
    """Run `cloudseed <argv>` as a child; returns the MCP tool result (redacted, truncated).
    env: the child's environment, or a LiveEnv that builds a fresh credential session for this one call."""
    if not isinstance(env, LiveEnv):
        return _spawn(name, argv, env, call, progress)
    if call is not None and call.cancelled:
        return _result(f"$ cloudseed {_shell_join(argv)}\ncancelled before it started", True)
    try:
        rec = env.acquire()
    except Exception as e:  # noqa: BLE001 - reported as the call's result, never a dead server
        _log(f"tool {name}: cannot open the credential session: {type(e).__name__}: {e}")
        return _result(f"$ cloudseed {_shell_join(argv)}\ncould not open the credential session: {secrets.redact(str(e))}", True)
    try:
        return _spawn(name, argv, rec["env"], call, progress)
    finally:
        env.release(rec)


def _json_stdout(name: str, argv: list[str]) -> bool:
    """True when this call's stdout is the command's JSON (cloudseed_output, cloudseed_inventory json=true): the CLI keeps
    its notes and warnings on stderr then, and the two are captured apart so the result is JSON a client can parse."""
    return bool((TOOLS.get(name) or {}).get("json_stdout")) and "--json" in argv


def _clip(text: str, limit: int = MAX_OUTPUT) -> str:
    return text if len(text) <= limit else text[: limit // 2] + "\n...[truncated]...\n" + text[-limit // 2:]


def _spawn(name: str, argv: list[str], env: dict, call: _Call | None = None, progress=None) -> dict:
    shown = f"$ cloudseed {_shell_join(argv)}"
    if call is not None and call.cancelled:
        return _result(f"{shown}\ncancelled before it started", True)
    started = time.time()
    split = _json_stdout(name, argv)
    files: list[tuple[int, io.FileIO]] = []    # (write fd, read handle): stdout+stderr, or stdout then stderr
    try:
        for _ in range(2 if split else 1):
            files.append(_output_file())
    except OSError as e:
        for wfd, rfh in files:
            os.close(wfd)
            rfh.close()
        return _result(f"{shown}\ncould not start cloudseed: {e}", True)
    chunks: list[list[bytes]] = [[] for _ in files]
    last = ""

    def _drain() -> None:
        nonlocal last
        for i, (_w, rfh) in enumerate(files):
            try:
                data = rfh.read()
            except OSError:
                continue
            if data:
                chunks[i].append(data)
                lines = [ln.strip() for ln in data.decode("utf-8", "replace").splitlines() if ln.strip()]
                if lines:
                    last = lines[-1]

    try:
        try:
            proc = subprocess.Popen(_launcher() + argv, env=env, stdin=subprocess.DEVNULL, stdout=files[0][0],
                                    stderr=files[1][0] if split else subprocess.STDOUT, **_new_group())
        except OSError as e:
            return _result(f"{shown}\ncould not start cloudseed: {e}", True)
        finally:
            for wfd, _r in files:
                os.close(wfd)
        if call is not None and not call.attach(proc):
            threading.Thread(target=_interrupt, args=(proc,), daemon=True).start()
        deadline, timed_out, tick = started + TOOL_TIMEOUT, False, 0
        while True:
            try:
                proc.wait(timeout=PROGRESS_EVERY)
                break
            except subprocess.TimeoutExpired:
                _drain()
                if not timed_out and time.time() >= deadline:
                    timed_out = True
                    threading.Thread(target=_interrupt, args=(proc,), daemon=True).start()
                if progress is not None and not (call is not None and call.cancelled):
                    tick += 1
                    try:
                        progress(tick, secrets.redact(last)[:200] or f"running for {int(time.time() - started)}s")
                    except Exception:  # noqa: BLE001 - a client that went away must not break the call
                        pass
        _drain()    # never blocks: a background process the command started (ssh tunnel) cannot hold the call open
    finally:
        for _w, rfh in files:
            rfh.close()
    texts = [secrets.redact(b"".join(c).decode("utf-8", "replace")) for c in chunks]
    cancelled = call is not None and call.cancelled
    note = " (cancelled by the client; interrupted)" if cancelled else f" (timed out after {TOOL_TIMEOUT}s; interrupted)" if timed_out else ""
    _log(f"tool {name} rc={proc.returncode}{note} {round(time.time() - started, 1)}s  {shown}")
    failed = proc.returncode != 0 or timed_out or cancelled
    if split:
        out, err = texts[0].strip(), texts[1].strip()
        parsed = _NO_JSON
        assessment = name == "cloudseed_scan" and argv[:2] == ["scan", "architecture"] and proc.returncode in (1, 3)
        if (not failed or assessment) and not timed_out and not cancelled and len(out) <= MAX_JSON_OUTPUT:
            try:
                parsed = json.loads(out)
            except ValueError:
                parsed = _NO_JSON
        if parsed is not _NO_JSON:
            # the JSON on its own (a client parses it as it is), then the command line and the notes it printed
            res = {"content": [{"type": "text", "text": out},
                               {"type": "text", "text": f"{shown}\nexit code: {proc.returncode}" + (f"\nnotes (stderr):\n{_clip(err)}" if err else "")}],
                   "isError": failed}
            if isinstance(parsed, dict):
                res["structuredContent"] = parsed
            return res
        body = _clip("\n".join(t for t in (err, out) if t))
    else:
        body = _clip(texts[0])
    return _result(f"{shown}\nexit code: {proc.returncode}{note}\n{body}", failed)


def call_tool(name: str, args: dict, env, call: _Call | None = None, progress=None) -> dict:
    """Validate, gate (confirm) and run one tool. Unknown tool names raise InvalidParams (JSON-RPC -32602).
    env: the child's environment (a dict), or the server's LiveEnv (a fresh credential session per call)."""
    t = TOOLS.get(name)
    if not t:
        raise InvalidParams(f"unknown tool: {name!r} (tools/list shows the {len(TOOLS)} tools)")
    args, problem = validate_args(t, args)
    if problem:
        return _result(f"invalid arguments: {problem}\nexpected: {schema_hint(t)}", True)
    try:
        argv = t["argv"](args)      # pure: builds the command line only (and rejects what cannot be parsed)
    except (KeyError, ValueError, TypeError, AttributeError) as e:
        return _result(f"invalid arguments: {e}\nexpected: {schema_hint(t)}", True)
    if name == "cloudseed_explain" and args.get("format") == "json":
        return _explain_json(_words(args, "what"))   # static documentation: answered in-process, no child, no credentials
    if needs_confirm(t, args):
        return _result(f"{name} would change infrastructure, a host or a service, run a command on a host, or show secrets"
                       f"{_confirm_why(t, args)}. Ask the user, then call again with confirm=true.", True)
    return _run(name, argv, env, call, progress)


def _explain_lookup(query) -> dict:
    """explain.lookup() with the caller's own words (query, cli, error) redacted like any output."""
    from . import explain
    res = explain.lookup(query)
    for k in ("query", "cli", "error"):
        res[k] = secrets.redact(res[k])
    return res


def _explain_json(words: list[str]) -> dict:
    """cloudseed_explain format=json: the structured page; isError when nothing matches (did_you_mean says what does),
    like the exit code of `cs explain`."""
    res = _explain_lookup(words)
    return _result(json.dumps(res, indent=2, ensure_ascii=False), not res["found"])


# =============================================================================================== resources & prompts
EXPLAIN_TEMPLATE = "cloudseed://explain/{query}"


def resource_templates() -> list[dict]:
    return [{"uriTemplate": EXPLAIN_TEMPLATE, "name": "explain", "title": "cloudseed explain",
             "description": "How anything in cloudseed works, as JSON (explain.lookup: kind, title, summary, sections, commands, also, "
                            "did_you_mean). {query} is what `cs explain` takes, URL-encoded or with / between words: vpn, target%20vmware, "
                            "group/security, variable/aws/single_nat_gateway; cloudseed://explain alone is the index.",
             "mimeType": "application/json"}]


def _skills_dir() -> Path:
    return paths.REPO_ROOT / "skills"


def resource_list() -> list[dict]:
    out = [{"uri": "cloudseed://environments", "name": "environments", "title": "cloudseed environments",
            "description": "Every environment with its configuration (no secrets) and cached outputs.", "mimeType": "application/json"}]
    for p in sorted(_skills_dir().glob("*/SKILL.md")):
        out.append({"uri": f"cloudseed://skills/{p.parent.name}", "name": p.parent.name, "title": f"skill: {p.parent.name}",
                    "description": "Operating manual (Agent Skills format) for this part of cloudseed.", "mimeType": "text/markdown"})
    return out


def _environments() -> list[dict]:
    envs = []
    for e in paths.Env.list_all():
        item: dict = {"id": e.id, "cloud": e.cloud, "env": e.name, "workdir": str(e.dir)}
        try:
            cfg = e.load()
            if not isinstance(cfg, dict):
                raise ValueError("not a JSON object")
        except (OSError, ValueError, ui.Abort) as err:   # one broken env must not hide the others
            item["error"] = f"unreadable config.json ({type(err).__name__}); fix or remove {e.config_path}"
            envs.append(item)
            continue
        try:
            outputs = json.loads((e.dir / "outputs.json").read_text())
        except (OSError, ValueError):
            outputs = {}
        item.update({"config": {k: v for k, v in cfg.items() if k not in ("ssh_public_key", "ssh_private_key_path")}, "outputs": outputs})
        envs.append(item)
    return envs


def read_resource(uri: str) -> dict | None:
    m = re.fullmatch(r"cloudseed://explain(?:/(.*))?", uri, re.S)
    if m:
        from urllib.parse import unquote
        query = unquote(m.group(1) or "").replace("/", " ")
        text = json.dumps(_explain_lookup(query), indent=2, ensure_ascii=False)
        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]}
    if uri == "cloudseed://environments":
        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": secrets.redact(json.dumps(_environments(), indent=2))}]}
    m = re.fullmatch(r"cloudseed://skills/([A-Za-z0-9-]+)", uri)
    p = skills._lookup(m.group(1)) if m else None     # short names too: cloudseed://skills/aws is cloudseed-aws
    if p is not None and (p / "SKILL.md").exists():
        return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": (p / "SKILL.md").read_text()}]}
    return None


PROMPTS: dict[str, dict] = {
    "create-environment": {
        "description": "Plan and create a secure landing zone on a cloud, showing the plan before applying.",
        "arguments": [{"name": "cloud", "description": "aws | gcp | azure | vmware", "required": True},
                      {"name": "env", "description": "environment name (e.g. dev, staging)", "required": False},
                      {"name": "region", "description": "region / location", "required": False},
                      {"name": "extras", "description": "e.g. 'with a private Kubernetes cluster and an OpenVPN host'", "required": False}],
        "text": lambda a: (f"Create a cloudseed environment on {a['cloud']}"
                           + (f" named {a['env']}" if a.get("env") else "") + (f" in {a['region']}" if a.get("region") else "")
                           + (f" {a['extras']}" if a.get("extras") else "") + ".\n"
                           "Steps: 1) cloudseed_doctor for that cloud and stop if credentials are missing (tell me the login command). "
                           "2) cloudseed_setup without apply to show me the plan and summarize it in plain words (resources, monthly cost via cloudseed_finops estimate). "
                           "3) Only after I say yes, call cloudseed_setup again with apply=true and confirm=true. "
                           "4) Report the outputs that matter: bastion IP, SSH command, subnet IDs, and the next commands."),
    },
    "review-environment": {
        "description": "Health, cost and security review of an existing environment.",
        "arguments": [{"name": "cloud", "required": True, "description": "aws | gcp | azure | vmware"}, {"name": "env", "required": False, "description": "environment name"}],
        "text": lambda a: (f"Review the cloudseed environment {a['cloud']}" + (f"/{a['env']}" if a.get("env") else "") + ": "
                           "run cloudseed_status, cloudseed_inventory, cloudseed_troubleshoot and cloudseed_finops (estimate, then cloud bill if credentials allow). "
                           "Summarize: what exists, anything unhealthy or drifted, cost drivers, and concrete savings or hardening steps. Do not change anything."),
    },
    "troubleshoot": {
        "description": "Diagnose the last failure in an environment and propose the fix.",
        "arguments": [{"name": "cloud", "required": True, "description": "aws | gcp | azure | vmware"}, {"name": "env", "required": False, "description": "environment name"}],
        "text": lambda a: (f"Something failed in cloudseed environment {a['cloud']}" + (f"/{a['env']}" if a.get("env") else "") + ". "
                           "Call cloudseed_troubleshoot with log=true, read the diagnosis and the failure log, explain the root cause in plain words, "
                           "and propose the exact cloudseed tool call that fixes it. Ask before running anything destructive."),
    },
    "teardown": {
        "description": "Safely destroy an environment (restates what is deleted, asks for confirmation).",
        "arguments": [{"name": "cloud", "required": True, "description": "aws | gcp | azure | vmware"}, {"name": "env", "required": True, "description": "environment name"}],
        "text": lambda a: (f"I want to tear down cloudseed environment {a['cloud']}/{a['env']}. "
                           "First run cloudseed_inventory and list exactly what will be destroyed (including audit-log buckets). "
                           "Ask whether I also want the remote state storage and the local working directory removed. "
                           "Only after an explicit yes, call cloudseed_destroy with confirm=true (and purge/purge_state as I answered)."),
    },
}


class PromptArgError(InvalidParams):
    """Missing or malformed prompt arguments (JSON-RPC -32602)."""


def prompt_list() -> list[dict]:
    return [{"name": k, "title": k.replace("-", " "), "description": v["description"], "arguments": v["arguments"]} for k, v in PROMPTS.items()]


def get_prompt(name: str, args) -> dict | None:
    """None for an unknown prompt; PromptArgError when required arguments are missing or not strings."""
    p = PROMPTS.get(name)
    if not p:
        return None
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise PromptArgError("prompt arguments must be an object of string values")
    bad = sorted(k for k, v in args.items() if v is not None and not isinstance(v, str))
    if bad:
        raise PromptArgError("prompt arguments must be strings: " + ", ".join(bad))
    a = {k: v.strip() for k, v in args.items() if isinstance(v, str) and v.strip()}
    missing = [x["name"] for x in p["arguments"] if x.get("required") and x["name"] not in a]
    if missing:
        raise PromptArgError("missing required argument(s): " + ", ".join(missing))
    if "cloud" in a and a["cloud"] not in CLOUDS:
        raise PromptArgError(f"cloud must be one of: {', '.join(CLOUDS)}")
    return {"description": p["description"], "messages": [{"role": "user", "content": {"type": "text", "text": p["text"](a)}}]}


# =============================================================================================== JSON-RPC core
INSTRUCTIONS = ("cloudseed builds and operates secure cloud landing zones (AWS, GCP, Azure, local VMware) with Terraform. "
                "Start with cloudseed_list and cloudseed_doctor; read the resource cloudseed://skills/cloudseed for the operating manual. "
                "Use cloudseed_setup without apply to show a plan first; tools that change anything need confirm=true, which you may only send "
                "after the user agreed. Output is already redacted; never ask the user for credentials or try to read credential/state files. "
                "How something works (a feature, target, command, platform item, setup variable): read cloudseed://explain/<query> or call "
                "cloudseed_explain with format=json before guessing.")


class Session:
    """One MCP peer (stdio pipe or one HTTP client): protocol version negotiated at initialize, and its in-flight calls.
    child_env: what call_tool gets as env (the server passes its LiveEnv)."""

    def __init__(self, child_env):
        self.child_env = child_env
        self.protocol = PROTOCOL
        self.last_used = time.time()
        self._lock = threading.Lock()
        self._calls: dict = {}

    def begin(self, rid) -> _Call:
        c = _Call(rid)
        with self._lock:
            self._calls[rid] = c
        return c

    def end(self, rid, call: _Call) -> None:
        with self._lock:
            if self._calls.get(rid) is call:
                del self._calls[rid]

    def cancel(self, rid) -> bool:
        try:
            with self._lock:
                c = self._calls.get(rid)
        except TypeError:   # unhashable id
            return False
        if c is None:
            return False
        c.cancel()
        return True

    def busy(self) -> bool:
        with self._lock:
            return bool(self._calls)


def _valid_id(rid) -> bool:
    return rid is None or (isinstance(rid, (str, int, float)) and not isinstance(rid, bool))


def handle(req, session: Session, notify=None) -> dict | None:
    """Handle one JSON-RPC message. Returns the response, or None for notifications, client responses and cancelled calls.
    notify(message) sends a server->client notification (progress) on the same channel when the transport can."""
    if not isinstance(req, dict):
        return _err(None, -32600, "invalid request: expected a JSON-RPC object")
    rid, method = req.get("id"), req.get("method")
    if not _valid_id(rid):
        return _err(None, -32600, "invalid request: id must be a string or a number")
    if method is None:
        if "result" in req or "error" in req:   # a response from the client (to a server request) - nothing to do
            return None
        return _err(rid, -32600, "invalid request: missing method") if rid is not None else None
    if not isinstance(method, str):
        return _err(rid, -32600, "invalid request: method must be a string") if rid is not None else None
    params = req.get("params")
    params = {} if params is None else params
    if not isinstance(params, dict):
        return _err(rid, -32602, "invalid params: expected an object") if rid is not None else None
    session.last_used = time.time()
    if rid is None:     # notification
        if method == "notifications/initialized":
            _log(f"client initialized (protocol {session.protocol})")
        elif method == "notifications/cancelled":
            target = params.get("requestId")
            if session.cancel(target):
                _log(f"client cancelled request {target!r}: interrupting it")
        return None
    try:
        if method == "initialize":
            wanted = str(params.get("protocolVersion") or PROTOCOL)
            session.protocol = wanted if wanted in SUPPORTED_PROTOCOLS else PROTOCOL
            client = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
            if client.get("name") != "cloudseed-status":   # health probes (cs mcp status, the console) are not worth a line each
                _log(f"initialize from {client.get('name', '?')} {client.get('version', '')} (protocol {session.protocol})")
            return _ok(rid, {"protocolVersion": session.protocol,
                             "capabilities": {"tools": {"listChanged": False}, "resources": {"subscribe": False, "listChanged": False}, "prompts": {"listChanged": False}},
                             "serverInfo": {"name": SERVER_NAME, "title": "cloudseed", "version": __version__},
                             "instructions": INSTRUCTIONS})
        if method == "ping":
            return _ok(rid, {})
        if method == "tools/list":
            return _ok(rid, {"tools": tool_list()})
        if method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                return _err(rid, -32602, "invalid params: tools/call needs the tool name")
            meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
            call = session.begin(rid)
            try:
                res = call_tool(name, params.get("arguments"), session.child_env, call=call, progress=_progress_sender(notify, meta.get("progressToken")))
            finally:
                session.end(rid, call)
            if call.cancelled:
                return None     # the client cancelled it: no response (MCP cancellation)
            if isinstance(res, dict) and "structuredContent" in res and session.protocol < STRUCTURED_SINCE:
                # a peer that negotiated an older protocol gets the result as that version defines it: the JSON is the
                # first text block either way (the protocol versions are dates, so they compare as strings)
                res = {k: v for k, v in res.items() if k != "structuredContent"}
            return _ok(rid, res)
        if method == "resources/list":
            return _ok(rid, {"resources": resource_list()})
        if method == "resources/templates/list":
            return _ok(rid, {"resourceTemplates": resource_templates()})
        if method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str) or not uri:
                raise InvalidParams("invalid params: resources/read needs a uri (a string, e.g. cloudseed://environments)")
            res = read_resource(uri)
            return _ok(rid, res) if res else _err(rid, -32002, f"resource not found: {uri} (resources/list shows them)")
        if method == "prompts/list":
            return _ok(rid, {"prompts": prompt_list()})
        if method == "prompts/get":
            if not isinstance(params.get("name"), str) or not params.get("name"):
                raise InvalidParams("invalid params: prompts/get needs the prompt name (a string)")
            res = get_prompt(params["name"], params.get("arguments"))
            return _ok(rid, res) if res else _err(rid, -32602, f"unknown prompt: {params.get('name')}")
        if method in ("completion/complete", "logging/setLevel"):
            return _ok(rid, {"completion": {"values": []}} if method == "completion/complete" else {})
        return _err(rid, -32601, f"method not found: {method}")
    except InvalidParams as e:
        return _err(rid, -32602, str(e))
    except ui.Abort as e:   # a cloudseed helper refused: report it, never exit the server
        return _err(rid, -32603, secrets.redact(e.msg or "aborted"))
    except Exception as e:  # noqa: BLE001 - never kill the server on a bad request
        _log(f"error handling {method}: {type(e).__name__}: {e}")
        return _err(rid, -32603, secrets.redact(f"{type(e).__name__}: {e}"))


def _progress_sender(notify, token):
    """progress(n, message) -> notifications/progress for the request's progressToken; None when the client sent none."""
    if notify is None or token is None or isinstance(token, bool) or not isinstance(token, (str, int)):
        return None

    def progress(n: int, message: str) -> None:
        notify({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": token, "progress": n, "message": message}})
    return progress


def dispatch(payload, session: Session, notify=None):
    """One message or a JSON-RPC batch. Returns the response (a list for batches) or None when nothing is owed."""
    if isinstance(payload, list):
        if not payload:
            return _err(None, -32600, "invalid request: empty batch")
        out = []
        for m in payload:
            if isinstance(m, dict) and m.get("method") == "initialize":
                if m.get("id") is not None:
                    out.append(_err(m.get("id"), -32600, "invalid request: initialize must not be part of a batch"))
                continue
            r = handle(m, session, notify)
            if r is not None:
                out.append(r)
        return out or None
    return handle(payload, session, notify)


def _safe_dispatch(payload, session: Session, notify=None):
    try:
        return dispatch(payload, session, notify)
    except (Exception, ui.Abort) as e:  # noqa: BLE001 - last resort: a transport must always answer
        _log(f"error dispatching: {type(e).__name__}: {e}")
        return _err(None, -32603, secrets.redact(f"{type(e).__name__}: {e}"))


def _ok(rid, result) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(rid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


_log_lock = threading.Lock()
LOG_MAX = 1_000_000   # bytes; the log is rotated to server.log.1 beyond this


def _log(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {secrets.redact(msg)}\n"
    with _log_lock:
        try:
            MCP_DIR.mkdir(parents=True, exist_ok=True)
            try:
                if LOG_PATH.stat().st_size > LOG_MAX:
                    os.replace(LOG_PATH, LOG_PATH.with_name(LOG_PATH.name + ".1"))
            except OSError:
                pass
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass
        if os.environ.get("CLOUDSEED_MCP_STDERR"):
            sys.stderr.write(line)


def enabled() -> bool:
    return bool(paths.load_settings().get("mcp")) or secrets.env_flag("CLOUDSEED_MCP_FORCE")


def _child_env() -> tuple[str, dict]:
    sid, child_env = secrets.open_session()
    child_env["CLOUDSEED_AGENT"] = "mcp"
    child_env["NO_COLOR"] = "1"
    # a server started from a console job (cs mcp start / setup mcp there, --no-service) inherits the job's
    # CLOUDSEED_UI=1; its tool calls are an MCP client's, and the audit trail must say so (audit.origin: via=mcp)
    child_env.pop("CLOUDSEED_UI", None)
    child_env.pop("CLOUDSEED_MCP_FORCE", None)
    child_env.pop(MANAGED_ENV, None)
    from . import deps
    child_env["PATH"] = deps.path_env()["PATH"]
    return sid, child_env


class LiveEnv:
    """The environment of a running server's tool children, checked against the credential vault before EVERY call.
    The server lives for hours (a launchd/systemd service, or a stdio server as long as its client): a session parked
    once at startup would keep handing out credentials the user has since rotated or removed in the web console or with
    `cs creds`. So each call re-reads the vault first (creds.refresh: values the vault injected are updated or dropped,
    variables the shell exported still win); when that changed anything, a new session parks what is current, and the
    old one is closed as soon as the calls still using it have finished."""

    def __init__(self):
        self._lock = threading.Lock()
        self._cur: dict | None = None       # {"sid", "env", "key", "users"}
        self._open: dict = {}                # sid -> rec: every session this server still holds
        self.release(self.acquire())         # parked at startup, as before (it also arms the SIGTERM/SIGHUP clean-up)

    @staticmethod
    def _key() -> str:
        return hashlib.sha256(json.dumps(sorted(os.environ.items())).encode()).hexdigest()

    def acquire(self) -> dict:
        """The session for one call (release it when the call ends). Raises when no session can be opened."""
        from . import creds
        with creds._LOCK:   # os.environ must not change (another call's refresh) while it is compared, parked and copied
            try:
                creds.refresh()
            except Exception as e:  # noqa: BLE001 - an unreadable vault must not stop the call: the child reports it itself
                _log(f"credential vault not re-read: {type(e).__name__}: {e}")
            key = self._key()
            with self._lock:
                cur = self._cur
                if cur is not None and cur["key"] == key:
                    cur["users"] += 1
                    return cur
            sid, env = _child_env()
            rec = {"sid": sid, "env": env, "key": key, "users": 1}
            with self._lock:
                old, self._cur = self._cur, rec
                self._open[sid] = rec
                retire = old is not None and old["users"] <= 0
                if retire:
                    self._open.pop(old["sid"], None)
            if retire:
                secrets.close_session(old["sid"])
            if old is not None:
                _log("credentials changed: tool calls use a new credential session from now on")
            return rec

    def release(self, rec: dict) -> None:
        with self._lock:
            rec["users"] -= 1
            done = rec is not self._cur and rec["users"] <= 0
            if done:
                self._open.pop(rec["sid"], None)
        if done:    # superseded while this call ran: nothing uses it any more
            secrets.close_session(rec["sid"])

    def close(self) -> None:
        """Server exit: end every session (calls still running fetched their credentials when they started)."""
        with self._lock:
            recs, self._open, self._cur = list(self._open.values()), {}, None
        for rec in recs:
            secrets.close_session(rec["sid"])


def _exit_on_signals(signals_=("SIGTERM", "SIGHUP")) -> None:
    """Turn SIGTERM/SIGHUP into SystemExit so `finally` blocks run (the parked-credentials file is deleted).
    Running tool children live in their own process group and finish on their own."""
    def _bye(signum, _frame):
        raise SystemExit(128 + signum)
    for name in signals_:
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _bye)
        except (ValueError, OSError):   # not the main thread / not supported here
            pass


# =============================================================================================== stdio transport
class _Ordered:
    """stdio responses in request order, as long as that costs next to nothing: a finished response waits for an
    earlier request that is still running only during that request's first ORDER_WAIT seconds, then it goes out on
    its own. So a script piped into `cloudseed mcp serve` reads its answers in order, while tools/list, resources/*,
    prompts/* or a quick tool call are never held up behind a 30-minute apply (clients match responses by id; neither
    JSON-RPC nor MCP requires order). Pings and notifications (progress) bypass the queue."""

    def __init__(self, write, wait: float | None = None):
        self._write = write
        self._wait = ORDER_WAIT if wait is None else wait
        self._lock = threading.Lock()
        self._next = 0
        self._running: dict = {}     # seq -> when a request that is still being handled started (monotonic)
        self._held: dict = {}        # seq -> a finished response waiting for an earlier, young request
        self._timer: threading.Timer | None = None

    def reserve(self) -> int:
        with self._lock:
            n = self._next
            self._next += 1
            self._running[n] = time.monotonic()
            return n

    def complete(self, seq: int, msg) -> None:
        with self._lock:
            self._running.pop(seq, None)
            self._held[seq] = msg
            self._flush()

    def _flush(self) -> None:
        """Write every held response no young earlier request is in front of (the lock is held)."""
        now = time.monotonic()
        for seq in sorted(self._held):
            young = [t0 + self._wait for s, t0 in self._running.items() if s < seq and t0 + self._wait > now]
            if young:    # every later held response has this one's earlier requests in front of it too
                if self._timer is not None:
                    self._timer.cancel()
                self._timer = threading.Timer(max(max(young) - now, 0.01), self._tick)
                self._timer.daemon = True
                self._timer.start()
                return
            m = self._held.pop(seq)
            if m is not None:
                self._write(m)

    def _tick(self) -> None:
        with self._lock:
            self._flush()


def _is_tool_call(payload) -> bool:
    if isinstance(payload, list):
        return any(_is_tool_call(m) for m in payload)
    return isinstance(payload, dict) and payload.get("method") == "tools/call" and payload.get("id") is not None


def serve() -> int:
    """stdio JSON-RPC loop (newline-delimited messages). Tool calls run on worker threads so pings, cancellations and
    other requests are read and answered while a long call runs (_Ordered: order is kept only while it costs next to
    nothing)."""
    if not enabled():
        sys.stderr.write("cloudseed MCP is disabled. Run: cs setup mcp   (or: cs enable mcp)\n")
        return 2
    live = LiveEnv()
    session = Session(live)
    inp, outp = sys.stdin.buffer, sys.stdout.buffer
    wlock = threading.Lock()

    def write(msg) -> None:
        data = (json.dumps(msg) + "\n").encode()
        with wlock:
            try:
                outp.write(data)
                outp.flush()
            except (OSError, ValueError):   # the client went away
                pass

    ordered = _Ordered(write)
    workers: list[threading.Thread] = []

    def work(seq: int, payload) -> None:
        resp = None
        try:
            resp = _safe_dispatch(payload, session, write)
        finally:    # always release the slot, or every later response would wait forever
            ordered.complete(seq, resp)

    try:
        # inside the try: from the moment these handlers replace the ones that parked the session (secrets), a
        # SIGTERM raises SystemExit here, and only the `finally` below still ends the session (its file fallback
        # holds the credentials in plain text); the log line used to sit between the two, a window a quick SIGTERM hit
        _exit_on_signals()
        _log("stdio server started")
        for raw in inp:
            raw = raw.strip()
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except ValueError:   # also UnicodeDecodeError
                write(_err(None, -32700, "parse error: not valid JSON"))
                continue
            if isinstance(payload, dict) and payload.get("id") is None:     # notification (cancel, initialized): now
                resp = _safe_dispatch(payload, session, write)
                if resp is not None:
                    write(resp)
                continue
            if isinstance(payload, dict) and payload.get("method") == "ping":   # liveness: answer at once
                write(_safe_dispatch(payload, session, write))
                continue
            seq = ordered.reserve()
            if _is_tool_call(payload):
                th = threading.Thread(target=work, args=(seq, payload), daemon=True)
                th.start()
                workers = [w for w in workers if w.is_alive()] + [th]
            else:
                work(seq, payload)
        for w in workers:   # stdin closed: let in-flight calls finish and answer
            w.join()
    finally:
        live.close()
        _log("stdio server stopped")
    return 0


# =============================================================================================== http transport
class _HTTPServer(ThreadingHTTPServer):
    request_queue_size = 128   # listen backlog: the socketserver default (5) resets connections under parallel tool calls
    daemon_threads = True

    def server_bind(self):
        # HTTPServer resolves a reverse-DNS name here; an offline resolver can stall a loopback service startup.
        # Our API never needs that name, and the literal also works for IPv6's four-part socket address.
        socketserver.TCPServer.server_bind(self)
        self.server_name = self.server_address[0]
        self.server_port = self.server_address[1]

    def handle_error(self, request, client_address):
        """One line in our log instead of a traceback on stderr (= the service log) per misbehaving connection."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError)):
            return
        _log(f"http request from {client_address[0]} failed: {type(exc).__name__}: {exc}")


class _HTTPServer6(_HTTPServer):
    address_family = socket.AF_INET6


def server_class(host: str) -> type:
    """The threading HTTP server class for a bind address (IPv6 literals such as ::1 need AF_INET6)."""
    return _HTTPServer6 if ":" in _bare_host(host) else _HTTPServer


class _State:
    child_env = None     # LiveEnv of the running server
    token: str | None = None
    sse_sessions: dict = {}
    sessions: OrderedDict = OrderedDict()
    anon: Session | None = None
    lock = threading.Lock()


def _session_get(sid: str) -> Session | None:
    with _State.lock:
        s = _State.sessions.get(sid)
        if s is not None:
            _State.sessions.move_to_end(sid)
        return s


def _session_add(sid: str, session: Session) -> None:
    """Keep a bounded set of sessions: expired or least recently used idle ones are dropped (nothing leaks per health check)."""
    with _State.lock:
        _State.sessions[sid] = session
        _State.sessions.move_to_end(sid)
        now = time.time()
        for old in list(_State.sessions):
            if len(_State.sessions) <= MAX_SESSIONS and now - _State.sessions[old].last_used < SESSION_TTL:
                break
            if old == sid or old in _State.sse_sessions or _State.sessions[old].busy():
                continue
            del _State.sessions[old]


def _session_drop(sid: str) -> bool:
    with _State.lock:
        return _State.sessions.pop(sid, None) is not None


def _bare_host(host: str) -> str:
    host = (host or "").strip()
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


def _url_host(host: str) -> str:
    h = _bare_host(host)
    return f"[{h}]" if ":" in h else h


def _is_local_origin(origin: str, host: str, port: int) -> bool:
    if not origin:
        return True
    try:
        u = urlsplit(origin)
    except ValueError:
        return False
    return u.hostname in ("localhost", "127.0.0.1", "::1", _bare_host(host)) or (u.hostname or "").endswith(".localhost")


def _home_id() -> str:
    """Identifies this CLOUDSEED_HOME in /health (without exposing the path), so stop() never signals another home's server."""
    return hashlib.sha256(str(paths.HOME.expanduser().resolve()).encode()).hexdigest()[:12]


class _BadRequest(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"cloudseed-mcp/{__version__}"

    def log_message(self, fmt, *args):  # quiet; we keep our own log
        pass

    # ---- helpers
    def _send(self, code: int, body: bytes = b"", ctype: str = "application/json", extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code: int, obj, extra: dict | None = None) -> None:
        self._send(code, json.dumps(obj).encode(), extra=extra)

    def _refuse(self, code: int, obj, extra: dict | None = None) -> None:
        """Error before the body was read: close the connection so unread body bytes are never parsed as a request."""
        self.close_connection = True
        self._json(code, obj, extra)

    def _authorized(self) -> bool:
        if not _is_local_origin(self.headers.get("Origin", ""), *self.server.server_address[:2]):
            self._refuse(403, {"error": "origin not allowed"})
            return False
        if _State.token:
            scheme, _, cred = (self.headers.get("Authorization") or "").strip().partition(" ")
            if not (scheme.lower() == "bearer" and secrets_eq(cred.strip(), _State.token)):
                self._refuse(401, {"error": "missing or invalid bearer token", "hint": "cs mcp token"}, extra={"WWW-Authenticate": 'Bearer realm="cloudseed"'})
                return False
        return True

    def _session(self) -> Session:
        sid = self.headers.get("Mcp-Session-Id") or self.headers.get("X-Session-Id") or ""
        if not sid:
            return _State.anon or Session(_State.child_env)
        s = _session_get(sid)
        if s is None:   # a session from before a restart (or evicted): keep serving it, under the same id
            s = Session(_State.child_env)
            _session_add(sid, s)
        return s

    def _read_body(self) -> bytes:
        """The request body (Content-Length or chunked). Raises _BadRequest for malformed framing or oversize bodies."""
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            body = bytearray()
            while True:
                line = self.rfile.readline(1024)
                try:
                    size = int(line.split(b";", 1)[0].strip(), 16)
                except ValueError:
                    raise _BadRequest(400, "malformed chunked body") from None
                if size < 0:
                    raise _BadRequest(400, "malformed chunked body")
                if size == 0:
                    while self.rfile.readline(8192).strip():   # trailers up to the blank line
                        pass
                    return bytes(body)
                if len(body) + size > MAX_BODY:
                    raise _BadRequest(413, "request body too large")
                body += self.rfile.read(size)
                if self.rfile.read(2) != b"\r\n":
                    raise _BadRequest(400, "malformed chunked body")
        raw = self.headers.get("Content-Length")
        if raw is None:
            return b""
        try:
            n = int(raw.strip())
        except ValueError:
            raise _BadRequest(400, "invalid Content-Length") from None
        if n < 0:
            raise _BadRequest(400, "invalid Content-Length")
        if n > MAX_BODY:
            raise _BadRequest(413, "request body too large")
        return self.rfile.read(n) if n else b""

    def _path(self) -> str:
        return urlsplit(self.path).path.rstrip("/") or "/"

    # ---- routes
    def do_GET(self):
        p = self._path()
        if p == "/health":
            self._json(200, {"ok": True, "server": SERVER_NAME, "version": __version__, "protocol": PROTOCOL, "pid": os.getpid(), "home": _home_id()})
            return
        if not self._authorized():
            return
        if p == "/sse":
            self._sse_stream()
            return
        if p == "/mcp":
            self._json(405, {"error": "this server does not open server-initiated streams; POST JSON-RPC to /mcp"}, extra={"Allow": "POST, DELETE"})
            return
        self._json(404, {"error": "not found", "endpoints": ["/mcp", "/sse", "/health"]})

    def do_DELETE(self):
        if not self._authorized():
            return
        sid = self.headers.get("Mcp-Session-Id", "")
        if sid and _session_drop(sid):
            self._send(200)
        else:
            self._json(404, {"error": "unknown session"})

    def do_OPTIONS(self):
        self._send(204, extra={"Allow": "GET, POST, DELETE, OPTIONS"})

    def do_POST(self):
        if not self._authorized():
            return
        # JSON only: a browser page can send text/plain or form posts cross-site without a CORS preflight (CSRF), never JSON
        if (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower() != "application/json":
            self._refuse(415, {"error": "Content-Type must be application/json"})
            return
        try:
            body = self._read_body()
        except _BadRequest as e:
            self._refuse(e.code, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700 if e.code == 400 else -32600, "message": str(e)}})
            return
        try:
            if not body.strip():
                raise ValueError("empty body")
            payload = json.loads(body.decode("utf-8"))
        except ValueError as e:
            self._json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"parse error: {e}"}})
            return
        if not isinstance(payload, (dict, list)):
            self._json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request: expected a JSON-RPC object or batch"}})
            return
        p = self._path()
        if p == "/messages":
            sid = (parse_qs(urlsplit(self.path).query).get("sessionId") or [""])[0]
            q = _State.sse_sessions.get(sid)
            if q is None:
                self._json(404, {"error": "unknown SSE session; open GET /sse first"})
                return
            session = _session_get(sid) or Session(_State.child_env)
            self._send(202)
            threading.Thread(target=lambda: _push(q, _safe_dispatch(payload, session, q.put)), daemon=True).start()
            return
        if p != "/mcp":
            self._json(404, {"error": "not found", "endpoints": ["/mcp", "/sse", "/health"]})
            return
        extra = {}
        if isinstance(payload, dict) and payload.get("method") == "initialize":
            sid = secrets_token()
            session = Session(_State.child_env)
            _session_add(sid, session)
            extra["Mcp-Session-Id"] = sid
        else:
            session = self._session()
        wants_stream = (isinstance(payload, dict) and payload.get("method") == "tools/call" and payload.get("id") is not None
                        and "text/event-stream" in (self.headers.get("Accept") or ""))
        if not wants_stream:
            resp = _safe_dispatch(payload, session)
            if resp is None:
                self._send(202, extra=extra)
            else:
                self._json(200, resp, extra=extra)
            return
        # long tool calls: answer over an SSE stream with keep-alive comments (and progress notifications when asked for)
        # so proxies/clients never time out. A dropped connection does NOT cancel the call; notifications/cancelled does.
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        events: queue.Queue = queue.Queue()
        threading.Thread(target=lambda: events.put(("result", _safe_dispatch(payload, session, lambda m: events.put(("note", m))))), daemon=True).start()
        try:
            while True:
                try:
                    kind, msg = events.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    continue
                if msg is not None:
                    self.wfile.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode())
                    self.wfile.flush()
                if kind == "result":
                    break
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _sse_stream(self):
        """Legacy HTTP+SSE transport (2024-11-05): GET /sse opens the stream, POST /messages?sessionId=... sends requests."""
        sid = secrets_token()
        q: queue.Queue = queue.Queue()
        _State.sse_sessions[sid] = q
        _session_add(sid, Session(_State.child_env))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(f"event: endpoint\ndata: /messages?sessionId={sid}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=15)
                    self.wfile.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            _State.sse_sessions.pop(sid, None)
            _session_drop(sid)


def _push(q: queue.Queue, resp) -> None:
    if resp is not None:
        q.put(resp)


def secrets_token() -> str:
    import secrets as _s
    return _s.token_urlsafe(24)


def secrets_eq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


def host_problem(host: str) -> str | None:
    """Why the server cannot/must not listen on host (None when it is fine): loopback only unless CLOUDSEED_MCP_ALLOW_REMOTE."""
    h = _bare_host(host)
    if not h:
        return "no host given"
    if h not in LOOPBACK_HOSTS and not secrets.env_flag("CLOUDSEED_MCP_ALLOW_REMOTE"):   # "0"/"false" keep it local-only
        return f"Refusing to listen on {h}: the MCP server is local-only (127.0.0.1, localhost or ::1; set CLOUDSEED_MCP_ALLOW_REMOTE=1 to override)."
    try:
        socket.getaddrinfo(h, None, socket.AF_INET6 if ":" in h else socket.AF_INET)
    except (OSError, UnicodeError) as e:
        return f"Cannot use host {h}: {e}"
    return None


def _managed() -> bool:
    """True when this `mcp serve --http` runs as the login service (launchd/systemd) or the detached background process
    that start() launched, not in someone's terminal. A launchd job written by an older version has no MANAGED_ENV, but
    launchd names the job in XPC_SERVICE_NAME (a terminal has "0" or an app's name there)."""
    return os.environ.get(MANAGED_ENV) == "1" or os.environ.get("XPC_SERVICE_NAME") in (LAUNCHD_LABEL, _service_label())


def _say(msg: str, managed: bool) -> None:
    """A start-up problem: on stderr for a terminal run; in server.log for a service (where `cs mcp status/logs` and
    start() read it; launchd's stderr is that log already, systemd's is the journal)."""
    if managed:
        _log(msg)
    else:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()


def serve_http(host: str, port: int, auth: bool = True) -> int:
    """The HTTP transport (what the service runs, or `cs mcp serve --http` in a terminal). A service run that can never
    start as configured (MCP disabled, a non-local address) exits 0, so launchd (KeepAlive: SuccessfulExit false) and
    systemd (Restart=on-failure) do not restart it forever; a port that is busy right now exits 1 and is retried."""
    managed = _managed()
    if not enabled():
        _say("cloudseed MCP is disabled. Run: cs setup mcp   (or: cs enable mcp)", managed)
        return 0 if managed else 2
    problem = host_problem(host)
    if problem:
        _say(problem, managed)
        return 0 if managed else 2
    host = _bare_host(host)
    try:
        httpd = server_class(host)((host, port), _Handler)
    except (OSError, OverflowError) as e:    # OverflowError: a port outside 0-65535
        why = str(e) if isinstance(e, OSError) else "the port must be 1-65535"
        _say(f"Cannot listen on {_url_host(host)}:{port}: {why}", managed)
        return 1
    live = _State.child_env = LiveEnv()
    _State.anon = Session(live)
    _State.token = load_token() if auth else None
    if auth and not _State.token:
        _State.token = ensure_token()
    try:
        PID_PATH.parent.mkdir(parents=True, exist_ok=True)
        PID_PATH.write_text(str(os.getpid()))
    except OSError:
        pass
    where = f"http://{_url_host(host)}:{port}/mcp"
    _log(f"http server listening on {where} (auth={'token' if _State.token else 'none'}) pid={os.getpid()}" + ("" if managed else " (foreground)"))
    if not managed:     # a terminal run says where it is (the token itself is never printed here)
        sys.stderr.write(f"cloudseed MCP server on {where}   " + ("(bearer token: cs mcp token)" if _State.token else "(no auth)")
                         + "; Ctrl-C stops it\n")
        sys.stderr.flush()

    def _stop(*_):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for s in (signal.SIGTERM, signal.SIGINT, getattr(signal, "SIGHUP", None)):
        if s is None:
            continue
        try:
            signal.signal(s, _stop)
        except (ValueError, OSError):
            pass
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
        live.close()
        try:
            if PID_PATH.exists() and PID_PATH.read_text().strip() == str(os.getpid()):
                PID_PATH.unlink()
        except OSError:
            pass
        _log("http server stopped")
    return 0


# =============================================================================================== deployment state
def load_state() -> dict:
    try:
        data = json.loads(STATE_PATH.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    MCP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(MCP_DIR, 0o700)
    except OSError:
        pass
    STATE_PATH.write_text(json.dumps(state, indent=2) + "\n")


def load_token() -> str | None:
    try:
        return TOKEN_PATH.read_text().strip() or None
    except OSError:
        return None


def ensure_token(rotate: bool = False) -> str:
    tok = None if rotate else load_token()
    if tok:
        return tok
    MCP_DIR.mkdir(parents=True, exist_ok=True)
    tok = secrets_token() + secrets_token()
    fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(tok + "\n")
    return tok


def url(state: dict | None = None) -> str:
    s = state or load_state()
    return f"http://{_url_host(str(s.get('host') or DEFAULT_HOST))}:{s.get('port', DEFAULT_PORT)}/mcp"


def sse_url(state: dict | None = None) -> str:
    return url(state)[: -len("/mcp")] + "/sse"


def free_port(preferred: int, host: str = DEFAULT_HOST) -> int:
    h = _bare_host(host) or DEFAULT_HOST
    family = socket.AF_INET6 if ":" in h else socket.AF_INET
    for port in [preferred] + list(range(preferred + 1, preferred + 50)):
        if not 0 < port <= 65535:
            continue
        with socket.socket(family, socket.SOCK_STREAM) as s:
            try:
                s.bind((h, port))
                return port
            except (OSError, OverflowError):
                continue
    raise ui.Abort(f"No free TCP port near {preferred}; pass --port.")


def _open(req: urllib.request.Request, timeout: float):
    # never through an HTTP(S)_PROXY: the server is on this machine
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout)


def health(state: dict | None = None, timeout: float = 2.0) -> dict | None:
    """POST initialize to the running server (then end that session); None when it is not reachable / not ours."""
    s = state or load_state()
    if not s:
        return None
    body = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "cloudseed-status", "version": __version__}}}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    tok = load_token()
    if s.get("auth", "token") == "token" and tok:
        headers["Authorization"] = f"Bearer {tok}"
    try:
        with _open(urllib.request.Request(url(s), data=body, method="POST", headers=headers), timeout) as r:
            data = json.loads(r.read().decode())
            sid = r.headers.get("Mcp-Session-Id")
    except Exception:  # noqa: BLE001
        return None
    if sid:
        try:
            _open(urllib.request.Request(url(s), method="DELETE", headers={**headers, "Mcp-Session-Id": sid}), timeout).close()
        except Exception:  # noqa: BLE001 - best effort
            pass
    res = data.get("result") if isinstance(data, dict) else None
    return res if isinstance(res, dict) else None


def alive(state: dict | None = None, timeout: float = 1.0) -> dict | None:
    """GET /health (no token needed): the server's info when a cloudseed MCP server of THIS home answers, else None."""
    s = state or load_state()
    if not s:
        return None
    try:
        with _open(urllib.request.Request(url(s)[: -len("/mcp")] + "/health", method="GET"), timeout) as r:
            data = json.loads(r.read().decode())
    except Exception:  # noqa: BLE001
        return None
    if isinstance(data, dict) and data.get("server") == SERVER_NAME and data.get("home") in (None, _home_id()):
        return data
    return None


def _service_kind() -> str:
    if platform.system() == "Darwin" and shutil.which("launchctl"):
        return "launchd"
    if platform.system() == "Linux" and shutil.which("systemctl"):
        return "systemd"
    return "background"


def _serve_argv(state: dict) -> list[str]:
    return _launcher() + ["mcp", "serve", "--http", "--host", _bare_host(state["host"]), "--port", str(state["port"])] + (["--no-auth"] if state.get("auth") == "none" else [])


def _service_env() -> dict:
    from . import creds, deps
    env = {"PATH": deps.path_env()["PATH"], "HOME": str(Path.home()), "NO_COLOR": "1", "LANG": os.environ.get("LANG", "en_US.UTF-8")}
    if paths.IS_BUNDLE:
        # A detached server outlives this CLI. Give it its own extraction directory;
        # PyInstaller otherwise reuses ours and loses every asset when we exit.
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    shell = creds.shell_env()   # never bake credential-vault values into the service: it reads the vault itself, fresh
    for k in ("CLOUDSEED_HOME", "AWS_PROFILE", "AWS_DEFAULT_REGION", "AWS_REGION", "CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_PROJECT", "ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID", "KUBECONFIG"):
        if shell.get(k):
            env[k] = shell[k]
    return env


def _resolved(p: Path) -> Path:
    try:
        return Path(p).expanduser().resolve()
    except (OSError, RuntimeError):
        return Path(p).expanduser()


def _home_path() -> Path:
    return _resolved(paths.HOME)


def _default_home() -> Path:
    """The cloudseed home of this OS user when nothing is overridden: <passwd home>/.cloudseed (not $HOME, which a
    test or sandbox may point elsewhere while launchd/systemd still see the one real per-user domain)."""
    try:
        import pwd
        base = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError, AttributeError):
        base = Path(os.path.expanduser("~"))
    return _resolved(base / ".cloudseed")


def _service_label() -> str:
    """The launchd label of THIS home's server. Labels (and systemd unit names) are global per OS user, so a second
    CLOUDSEED_HOME gets its own (io.cloudseed.mcp.<home id>) instead of replacing the first home's login service; the
    default home keeps the plain name every earlier version used."""
    return LAUNCHD_LABEL if _home_path() == _default_home() else f"{LAUNCHD_LABEL}.{_home_id()}"


def _systemd_name() -> str:
    return SYSTEMD_UNIT if _home_path() == _default_home() else f"{SYSTEMD_UNIT}-{_home_id()}"


def _launchd_plist(label: str | None = None) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label or _service_label()}.plist"


def _systemd_unit(name: str | None = None) -> Path:
    return Path.home() / ".config" / "systemd" / "user" / f"{name or _systemd_name()}.service"


def _home_of(env: dict) -> Path:
    """The CLOUDSEED_HOME a service definition's server runs with: its CLOUDSEED_HOME, else <its HOME>/.cloudseed."""
    if env.get("CLOUDSEED_HOME"):
        return _resolved(Path(str(env["CLOUDSEED_HOME"])))
    return _resolved(Path(str(env["HOME"])) / ".cloudseed") if env.get("HOME") else _default_home()


def _plist_home(plist: Path) -> Path | None:
    try:
        with open(plist, "rb") as fh:
            data = plistlib.load(fh)
        env = data.get("EnvironmentVariables") if isinstance(data, dict) else None
        return _home_of(env if isinstance(env, dict) else {})
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None


def _unit_home(unit: Path) -> Path | None:
    try:
        text = unit.read_text(errors="replace")
    except OSError:
        return None
    env = dict(m.groups() for m in re.finditer(r'^Environment="?([A-Za-z_][A-Za-z0-9_]*)=([^"\n]*)"?\s*$', text, re.M))
    return _home_of(env)


def _service_defs(kind: str) -> list[tuple[str, Path]]:
    """This home's launchd jobs / systemd units as (label or unit name, definition file): its own name, and the shared
    name older versions gave every home when that definition runs this home's server. A definition under the shared
    name that runs ANOTHER home's server is never listed, so nothing here stops or deletes it."""
    mine = _home_path()
    if kind == "launchd":
        cur, legacy, path_of, home_of = _service_label(), LAUNCHD_LABEL, _launchd_plist, _plist_home
    else:
        cur, legacy, path_of, home_of = _systemd_name(), SYSTEMD_UNIT, _systemd_unit, _unit_home
    out: list[tuple[str, Path]] = []
    own = path_of(cur)
    if not (own.exists() and home_of(own) not in (None, mine)):
        out.append((cur, own))
    if legacy != cur:
        old = path_of(legacy)
        if old.exists() and home_of(old) == mine:
            out.append((legacy, old))
    return out


def _launchd_bootout(label: str) -> bool:
    """Unload a launchd job and wait until launchd has really dropped it (bootout is asynchronous)."""
    target = f"gui/{os.getuid()}/{label}"
    try:
        r = subprocess.run(["launchctl", "bootout", target], capture_output=True)
        for _ in range(20):
            if subprocess.run(["launchctl", "print", target], capture_output=True).returncode != 0:
                break
            time.sleep(0.25)
    except OSError:
        return False
    return r.returncode == 0


def _systemd_off(name: str) -> bool:
    try:
        r = subprocess.run(["systemctl", "--user", "disable", "--now", f"{name}.service"], capture_output=True)
        if r.returncode != 0:   # e.g. the unit file is already gone: stopping the loaded unit still works
            r = subprocess.run(["systemctl", "--user", "stop", f"{name}.service"], capture_output=True)
    except OSError:
        return False
    return r.returncode == 0


def _drop_other_services(kind: str) -> list[str]:
    """Remove this home's service definitions that do not match how the server runs now: after a switch to a
    background process (or launchd/systemd refusing the service), or the shared name of an older version. Otherwise
    a second server starts at every login and fails on the busy port, restarting forever. Returns what was removed."""
    removed: list[str] = []
    for label, plist in _service_defs("launchd"):
        if (kind == "launchd" and label == _service_label()) or not plist.exists():
            continue
        _launchd_bootout(label)
        try:
            plist.unlink()
            removed.append(str(plist))
        except OSError:
            pass
    reload = False
    for name, unit in _service_defs("systemd"):
        if (kind == "systemd" and name == _systemd_name()) or not unit.exists():
            continue
        _systemd_off(name)
        try:
            unit.unlink()
            removed.append(str(unit))
            reload = True
        except OSError:
            pass
    if reload and shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    return removed


def leftover_services(state: dict | None = None) -> list[str]:
    """Service definitions of this home that do not match the deployment (for `cs mcp status`): a launchd plist or
    systemd unit while the server runs as another kind, or any of them without an HTTP deployment. `cs mcp restart`
    (http) or `cs setup mcp` removes them."""
    s = load_state() if state is None else state
    kind = s.get("service") if s.get("transport") == "http" else None
    out = []
    for k, cur in (("launchd", _service_label()), ("systemd", _systemd_name())):
        for name, p in _service_defs(k):
            if p.exists() and not (kind == k and name == cur):
                out.append(str(p))
    return out


def outdated_service(state: dict | None = None) -> str | None:
    """Why the login service definition of this home's HTTP server should be rewritten, or None (for `cs mcp status`;
    `cs mcp restart` rewrites it): a launchd job an older version wrote as ProcessType Background, which macOS runs with
    throttled CPU and I/O (every tool call's Terraform/kubectl is its child), or a definition without the service marker
    (a service that can never start then restarts forever instead of stopping)."""
    s = load_state() if state is None else state
    if s.get("transport") != "http" or s.get("service") not in ("launchd", "systemd"):
        return None
    if s["service"] == "launchd":
        plist = _launchd_plist()
        try:
            with open(plist, "rb") as fh:
                data = plistlib.load(fh)
        except (OSError, ValueError, plistlib.InvalidFileException):
            return None
        if not isinstance(data, dict):
            return None
        ptype = data.get("ProcessType")
        if ptype != "Interactive":
            return f"{plist} runs the server as ProcessType {ptype or 'Standard'} (macOS throttles it; tool calls run slower)"
        env = data.get("EnvironmentVariables")
        if not (isinstance(env, dict) and env.get(MANAGED_ENV) == "1"):
            return f"{plist} was written by an older version"
        return None
    unit = _systemd_unit()
    try:
        text = unit.read_text(errors="replace")
    except OSError:
        return None
    return None if f'Environment="{MANAGED_ENV}=1"' in text else f"{unit} was written by an older version"


def _read_pid() -> int | None:
    try:
        pid = int(PID_PATH.read_text().strip())
        return pid if pid > 0 else None
    except (OSError, ValueError):
        return None


def _drop_pid_file(pid: int | None = None) -> None:
    """Remove server.pid (only when it still names `pid`, if given)."""
    try:
        if pid is None or _read_pid() == pid:
            PID_PATH.unlink()
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _cmdline(pid: int) -> str | None:
    try:
        # The launcher's path can fill the terminal width before `mcp serve --http`. A truncated command makes a
        # live server look like an unrelated PID, so stop/restart would leave it listening with its old token.
        r = subprocess.run(["ps", "-ww", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, errors="replace", timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return None


def _is_our_server(pid: int) -> bool:
    """True only for a live `cloudseed mcp serve --http` process: a stale server.pid (crash, reboot, reused pid)
    must never make stop() signal an unrelated process."""
    if pid <= 1 or pid == os.getpid():
        return False
    try:
        os.kill(pid, 0)
    except OSError:     # gone, or not ours to signal
        return False
    cmd = _cmdline(pid)
    if not cmd:
        return False
    words = cmd.split()
    return " mcp serve" in f" {cmd}" and "--http" in words


def _warn_taking_over(path: Path, home_of) -> None:
    """Only the default home still uses the shared service name; say so when an older version left another home's
    server under it (that home gets its own name again with a restart there)."""
    other = home_of(path) if path.exists() else None
    if other is not None and other != _home_path():
        ui.warn(f"{path} ran the MCP server of {other} (older cloudseed versions gave every home the same login service); it now runs "
                f"this home's. Give that home its own service again: CLOUDSEED_HOME={other} cloudseed mcp restart")


def start(state: dict) -> str:
    """Start the http server as a user service (launchd/systemd) or a detached background process. Returns the kind.
    Service definitions of this home that do not match that kind are removed, so no second server starts at login."""
    MCP_DIR.mkdir(parents=True, exist_ok=True)
    kind = wanted = state.get("service") or _service_kind()
    argv = _serve_argv(state)
    env = {**_service_env(), MANAGED_ENV: "1"}     # the server knows it is a service run (see serve_http)
    proc = None
    _drop_other_services(kind)     # a leftover of another kind (or an older shared name) must not hold the port or come back at login
    if kind == "launchd":
        label, plist = _service_label(), _launchd_plist()
        _warn_taking_over(plist, _plist_home)
        plist.parent.mkdir(parents=True, exist_ok=True)
        with open(plist, "wb") as fh:
            plistlib.dump({"Label": label, "ProgramArguments": argv, "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                           "StandardOutPath": str(LOG_PATH), "StandardErrorPath": str(LOG_PATH), "EnvironmentVariables": env,
                           # Interactive: a Background job gets throttled CPU and I/O, and every tool call runs Terraform/kubectl
                           # as its child for someone waiting on the answer
                           "WorkingDirectory": str(Path.home()), "ProcessType": "Interactive"}, fh)
        uid = os.getuid()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}/{label}"], capture_output=True)
        r = subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(plist)], capture_output=True, text=True, errors="replace")
        if r.returncode != 0:
            r = subprocess.run(["launchctl", "load", "-w", str(plist)], capture_output=True, text=True, errors="replace")
        if r.returncode != 0:
            ui.warn(f"launchd refused the service ({r.stderr.strip() or r.stdout.strip()}); starting a background process instead.")
            kind = "background"
    if kind == "systemd":
        name, unit = _systemd_name(), _systemd_unit()
        _warn_taking_over(unit, _unit_home)
        unit.parent.mkdir(parents=True, exist_ok=True)
        envs = "\n".join(f'Environment="{k}={v}"' for k, v in env.items())
        unit.write_text(f"[Unit]\nDescription=cloudseed MCP server (local, {url(state)})\nAfter=network.target\n\n[Service]\nType=simple\n"
                        f"ExecStart={' '.join(shlex.quote(a) for a in argv)}\nRestart=on-failure\nRestartSec=3\n{envs}\n\n[Install]\nWantedBy=default.target\n")
        r = subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True, errors="replace")
        if r.returncode == 0:
            r = subprocess.run(["systemctl", "--user", "enable", "--now", f"{name}.service"], capture_output=True, text=True, errors="replace")
        if r.returncode != 0:
            ui.warn(f"systemd --user is not usable here ({r.stderr.strip()}); starting a background process instead.")
            kind = "background"
    if kind != wanted:
        _drop_other_services(kind)   # the definition written above was refused: it must not start (and fail) at the next login
    if kind == "background":
        # server.pid is NOT written here: serve_http writes its own pid once it listens. Writing the child's pid first
        # would replace the record of a server that still runs whenever this one cannot bind (busy port).
        with open(LOG_PATH, "a") as log:
            proc = subprocess.Popen(argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True, env=dict(os.environ, **env))
    state["service"] = kind
    state["started_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save_state(state)
    for _ in range(40):
        if health(state):
            return kind
        if proc is not None and proc.poll() is not None:   # the server exited (port busy, refused host...): fail fast
            return kind
        time.sleep(0.25)
    if proc is not None and proc.poll() is None:
        # still not answering after 10 s but alive: keep it findable, so the caller's stop()/remove_service() ends it
        # instead of leaving an orphan (unless server.pid already names a live server of ours - never overwrite that)
        cur = _read_pid()
        if cur is None or not _is_our_server(cur):
            try:
                PID_PATH.write_text(str(proc.pid))
            except OSError:
                pass
    return kind


def stop(state: dict | None = None) -> bool:
    s = state or load_state()
    kind = s.get("service")
    stopped = False
    for label, plist in _service_defs("launchd"):     # never another home's job (see _service_defs)
        if (kind == "launchd" and label == _service_label()) or plist.exists():
            stopped = _launchd_bootout(label) or stopped
    for name, unit in _service_defs("systemd"):
        if (kind == "systemd" and name == _systemd_name()) or unit.exists():
            stopped = _systemd_off(name) or stopped
    pid = _read_pid()
    if pid is None and s.get("transport") == "http":
        info = alive(s)    # the pid file was lost, but a server of this home answers: it reports its pid
        pid = info.get("pid") if info and isinstance(info.get("pid"), int) else None
    if pid is not None:
        if _is_our_server(pid):
            try:
                os.kill(pid, signal.SIGTERM)
                stopped = True
            except OSError:
                pass
        else:
            _drop_pid_file(pid)   # stale: never signal whatever process reuses that pid now
    for _ in range(20):
        if not (s.get("transport") == "http" and alive(s, timeout=0.5)) and not (pid and _is_our_server(pid)):
            break
        time.sleep(0.25)
    if pid is not None and not _is_our_server(pid):
        _drop_pid_file(pid)
    return stopped


def remove_service(state: dict | None = None) -> None:
    """Stop the server and delete its service definition. The definition goes FIRST: if stopping kills the process
    that runs this (an uninstall started from inside the service), nothing is left to start again at login."""
    s = state if state is not None else load_state()
    launchd, systemd = _service_defs("launchd"), _service_defs("systemd")
    kind = "launchd" if any(p.exists() for _, p in launchd) else "systemd" if any(p.exists() for _, p in systemd) else s.get("service")
    for name, unit in systemd:
        if unit.exists() and shutil.which("systemctl"):
            subprocess.run(["systemctl", "--user", "disable", f"{name}.service"], capture_output=True)
    for _, p in launchd + systemd:
        try:
            p.unlink()
        except OSError:
            pass
    # an older version's shared name (its definition is gone now, so stop() no longer sees it): unload it here
    for label, _ in launchd:
        if label != _service_label():
            _launchd_bootout(label)
    for name, _ in systemd:
        if name != _systemd_name():
            _systemd_off(name)
    stop({**s, "service": kind})
    _drop_pid_file()
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)


def running_pid() -> int | None:
    pid = _read_pid()
    return pid if pid is not None and _is_our_server(pid) else None


# =============================================================================================== clients
def _cfg_home() -> Path:
    return Path.home()


def _app_support(name: str) -> Path:
    sysname = platform.system()
    if sysname == "Darwin":
        return _cfg_home() / "Library" / "Application Support" / name
    if sysname == "Windows":
        return Path(os.environ.get("APPDATA") or str(_cfg_home() / "AppData" / "Roaming")) / name
    # Linux & co: $XDG_CONFIG_HOME (Claude Desktop builds, VS Code), ~/.config when it is unset, empty or relative (the
    # XDG spec ignores those; a relative one would put the client config under whatever directory cloudseed runs in)
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    return (Path(xdg) if os.path.isabs(xdg) else _cfg_home() / ".config") / name


CLIENTS: dict[str, dict] = {
    "claude-code": {"display": "Claude Code", "kind": "claude-cli", "binary": "claude", "transports": ("http", "stdio"),
                    "docs": "https://docs.claude.com/en/docs/claude-code/mcp"},
    "claude-desktop": {"display": "Claude Desktop", "kind": "json", "key": "mcpServers", "transports": ("stdio",),
                       "path": lambda: _app_support("Claude") / "claude_desktop_config.json",
                       "present": lambda: _app_support("Claude").exists() or Path("/Applications/Claude.app").exists(),
                       "docs": "https://modelcontextprotocol.io/quickstart/user"},
    "codex": {"display": "OpenAI Codex CLI", "kind": "toml", "binary": "codex", "transports": ("http", "stdio"),
              "path": lambda: _cfg_home() / ".codex" / "config.toml", "present": lambda: (_cfg_home() / ".codex").exists(),
              "docs": "https://developers.openai.com/codex/mcp"},
    "cursor": {"display": "Cursor", "kind": "json", "key": "mcpServers", "transports": ("http", "stdio"), "url_key": "url",
               "path": lambda: _cfg_home() / ".cursor" / "mcp.json", "present": lambda: (_cfg_home() / ".cursor").exists() or Path("/Applications/Cursor.app").exists(),
               "docs": "https://docs.cursor.com/context/model-context-protocol"},
    "windsurf": {"display": "Windsurf", "kind": "json", "key": "mcpServers", "transports": ("http", "stdio"), "url_key": "serverUrl",
                 "path": lambda: _cfg_home() / ".codeium" / "windsurf" / "mcp_config.json", "present": lambda: (_cfg_home() / ".codeium" / "windsurf").exists(),
                 "docs": "https://docs.windsurf.com/windsurf/cascade/mcp"},
    "gemini": {"display": "Gemini CLI", "kind": "json", "key": "mcpServers", "binary": "gemini", "transports": ("http", "stdio"), "url_key": "httpUrl",
               "timeout_ms": True, "path": lambda: _cfg_home() / ".gemini" / "settings.json", "docs": "https://geminicli.com/docs/tools/mcp-server/"},
    "vscode": {"display": "VS Code (Copilot agent mode)", "kind": "json", "key": "servers", "binary": "code", "transports": ("http", "stdio"), "url_key": "url", "typed": True,
               "path": lambda: _app_support("Code") / "User" / "mcp.json", "present": lambda: (_app_support("Code") / "User").exists(),
               "docs": "https://code.visualstudio.com/docs/copilot/chat/mcp-servers"},
}


def client_present(key: str) -> bool:
    c = CLIENTS[key]
    if c.get("binary") and shutil.which(c["binary"]):
        return True
    return bool(c.get("present") and c["present"]())


def _stdio_spec() -> tuple[str, list[str]]:
    argv = _launcher() + ["mcp", "serve"]
    return argv[0], argv[1:]


def _stdio_env() -> dict:
    """Environment pinned into every stdio registration: GUI apps (and Codex, which forwards only an allow-list of
    variables) start the server without the shell's PATH / CLOUDSEED_HOME."""
    from . import deps
    env = {"PATH": deps.path_env()["PATH"]}
    if os.environ.get("CLOUDSEED_HOME"):
        env["CLOUDSEED_HOME"] = str(paths.HOME.expanduser().resolve())
    return env


def stdio_entry(client: str) -> dict:
    """Server entry for a stdio launch; PATH (and CLOUDSEED_HOME) are pinned because GUI apps start with a minimal environment."""
    cmd, args = _stdio_spec()
    entry: dict = {"command": cmd, "args": args, "env": _stdio_env()}
    if CLIENTS[client].get("timeout_ms"):
        entry["timeout"] = CLIENT_TIMEOUT_SEC * 1000     # Gemini's default is 10 min; setup/apply can take longer
    if CLIENTS[client].get("typed"):
        entry = {"type": "stdio", **entry}
    return entry


def http_entry(client: str, state: dict) -> dict:
    c = CLIENTS[client]
    entry: dict = {c.get("url_key", "url"): url(state)}
    if state.get("auth", "token") == "token":
        entry["headers"] = {"Authorization": f"Bearer {load_token() or ensure_token()}"}
    if c.get("timeout_ms"):
        entry["timeout"] = CLIENT_TIMEOUT_SEC * 1000
    if c.get("typed"):
        entry = {"type": "http", **entry}
    return entry


class ClientConfigError(Exception):
    """A client config file cloudseed must not (or cannot) rewrite."""


def _loads_jsonc(text: str):
    """json.loads for JSONC (VS Code / Gemini settings): // and /* */ comments and trailing commas are allowed.
    String-aware, so '//' inside values such as "https://..." is left alone."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ValueError("unterminated /* comment")
            out.append(" ")
            i = j + 2
            continue
        out.append(ch)
        i += 1
    cleaned = "".join(out)
    # drop commas that are followed (after whitespace) by } or ] - again only outside strings
    res: list[str] = []
    in_str = False
    i, n = 0, len(cleaned)
    while i < n:
        ch = cleaned[i]
        if in_str:
            res.append(ch)
            if ch == "\\" and i + 1 < n:
                res.append(cleaned[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            res.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and cleaned[j] in " \t\r\n":
                j += 1
            if j >= n or cleaned[j] not in "}]":
                res.append(ch)
        else:
            res.append(ch)
        i += 1
    return json.loads("".join(res))


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return ""
    except (OSError, UnicodeDecodeError) as e:
        raise ClientConfigError(f"cannot read {path} ({e}); left it untouched. Add the entry by hand: cs mcp config") from None


def _read_client_json(path: Path) -> tuple[dict, bool]:
    """(data, had_comments_or_trailing_commas). A missing or empty file is {}. Anything that does not parse, or is not
    a JSON object, raises ClientConfigError - it is NEVER treated as empty (that would wipe the user's other servers)."""
    text = _read_text(path)
    if not text.strip():
        return {}, False
    try:
        data, jsonc = json.loads(text), False
    except ValueError:
        try:
            data, jsonc = _loads_jsonc(text), True
        except ValueError as e:
            raise ClientConfigError(f"cannot parse {path} ({e}); left it untouched. Fix it, or add the entry by hand: cs mcp config") from None
    if not isinstance(data, dict):
        raise ClientConfigError(f"{path}: unexpected layout (the top level is not an object); left it untouched. Add the entry by hand: cs mcp config")
    return data, jsonc


def _backup(path: Path, client: str, keep: bool = False) -> str | None:
    """Copy a client config aside (0600, under ~/.cloudseed/mcp/backups) before rewriting it. The newest KEEP_BACKUPS
    per client are kept, plus - never pruned - the first copy ever made (the file as it was before cloudseed touched
    it; after an upgrade, the oldest copy an older version left) and every copy made with keep=True (a commented JSONC
    original the rewrite cannot reproduce)."""
    try:
        if not path.exists() or path.stat().st_size == 0:
            return None
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        for d in (MCP_DIR, BACKUPS_DIR):
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
        protected = f"{client}-original-"
        earlier = list(BACKUPS_DIR.glob(f"{client}-*"))
        if not any(p.name.startswith(protected) for p in earlier):
            if earlier:     # copies of an older version (it had no protected original): its oldest is the closest to the original
                first = min(earlier, key=lambda p: (p.stat().st_mtime, p.name))
                try:
                    first.rename(BACKUPS_DIR / (protected + first.name[len(client) + 1:]))
                except OSError:
                    pass
            else:
                keep = True
        prefix = protected if keep else f"{client}-"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        dest = BACKUPS_DIR / f"{prefix}{stamp}-{path.name}"
        n = 1
        while dest.exists():
            dest = BACKUPS_DIR / f"{prefix}{stamp}-{n}-{path.name}"
            n += 1
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(path.read_bytes())
        olds = sorted((p for p in BACKUPS_DIR.glob(f"{client}-*") if not p.name.startswith(protected)), key=lambda p: (p.stat().st_mtime, p.name))
        for old in olds[:-KEEP_BACKUPS]:
            try:
                old.unlink()
            except OSError:
                pass
        return str(dest)
    except OSError as e:
        raise ClientConfigError(f"cannot back up {path} before changing it ({e}); left it untouched") from None


def _tighten(path: Path) -> None:
    """Client configs hold the bearer token: no access for group/others."""
    try:
        target = path.resolve()
        mode = stat.S_IMODE(target.stat().st_mode)
        if mode & 0o077:
            os.chmod(target, mode & ~0o077)
    except OSError:
        pass


def _write_private(path: Path, text: str) -> None:
    """Write a client config atomically with owner-only permissions (it can hold the bearer token).
    A symlinked config (dotfiles repo) is written through the link, never replaced by a plain file."""
    target = path.resolve() if path.is_symlink() else path
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = (stat.S_IMODE(target.stat().st_mode) & ~0o077) | 0o600
    except OSError:
        mode = 0o600
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write_json_file(path: Path, data: dict) -> None:
    _write_private(path, json.dumps(data, indent=2) + "\n")


def _toml_section(state: dict | None, transport: str) -> str:
    if transport == "http" and state:
        lines = [f"[mcp_servers.{SERVER_NAME}]", f"url = {json.dumps(url(state))}"]
        if state.get("auth", "token") == "token":
            lines.append(f'http_headers = {{ Authorization = "Bearer {load_token() or ensure_token()}" }}')
        lines.append(f"tool_timeout_sec = {CLIENT_TIMEOUT_SEC}")    # Codex's default is 60 s; setup/apply take longer
        return "\n".join(lines) + "\n"
    cmd, args = _stdio_spec()
    lines = [f"[mcp_servers.{SERVER_NAME}]", f"command = {json.dumps(cmd)}", f"args = {json.dumps(args)}", f"tool_timeout_sec = {CLIENT_TIMEOUT_SEC}",
             f"[mcp_servers.{SERVER_NAME}.env]"] + [f"{k} = {json.dumps(v)}" for k, v in _stdio_env().items()]
    return "\n".join(lines) + "\n"


# our tables in any ordinary spelling: [mcp_servers.cloudseed], [ mcp_servers."cloudseed" ], ["mcp_servers".cloudseed],
# [mcp_servers.'cloudseed'.env], a trailing comment; never [mcp_servers.cloudseedy] or an array of tables [[...]]
_TOML_NAME = rf"""(?:{SERVER_NAME}|"{SERVER_NAME}"|'{SERVER_NAME}')"""
_TOML_SERVERS = r"""(?:mcp_servers|"mcp_servers"|'mcp_servers')"""
_TOML_OUR_TABLE = re.compile(rf"^[ \t]*\[[ \t]*{_TOML_SERVERS}[ \t]*\.[ \t]*{_TOML_NAME}[ \t]*(?:\.[^\]\n]*)?\][ \t]*(?:#[^\n]*)?$", re.M)
_TOML_OUR_BODY = re.compile(rf"^[ \t]*\[[ \t]*{_TOML_SERVERS}[ \t]*\.[ \t]*{_TOML_NAME}[ \t]*\][ \t]*(?:#[^\n]*)?$(.*?)(?=^[ \t]*\[|\Z)", re.M | re.S)


def _tomllib():
    """The stdlib TOML parser (Python 3.11+), else None: older Pythons fall back to a conservative line scan."""
    try:
        import tomllib
        return tomllib
    except ImportError:
        return None


def _toml_strip(text: str) -> str:
    """Remove every [mcp_servers.cloudseed*] table from a TOML document (text based; the file keeps everything else)."""
    out, skipping = [], False
    for line in text.splitlines():
        if re.match(r"^\s*\[", line):
            skipping = bool(_TOML_OUR_TABLE.match(line))
        if not skipping:
            out.append(line)
    return "\n".join(out).rstrip() + "\n" if out else ""


def _toml_scan(text: str) -> list[tuple[str, str]]:
    """Line-based look at a TOML document for what _toml_strip cannot rewrite: [(kind, line)] with kind 'inline'
    (mcp_servers.cloudseed as an inline table or dotted keys), 'root-inline' (mcp_servers itself an inline table or a
    value, which a [mcp_servers.cloudseed] table cannot be added to) or 'header' (a table header naming it in another
    form, e.g. [[mcp_servers.cloudseed]]). Dotted keys count at the root only (under [foo] they mean foo.mcp_servers)."""
    found: list[tuple[str, str]] = []
    table = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            table = re.sub(r"""[\s"']""", "", line.split("#", 1)[0])
            if re.match(rf"^\[+mcp_servers\.{SERVER_NAME}[.\]]", table) and not _TOML_OUR_TABLE.match(raw):
                found.append(("header", raw))
            continue
        if not table:
            if re.match(rf"""^["']?mcp_servers["']?[ \t]*\.[ \t]*{_TOML_NAME}[ \t]*[.=]""", line):
                found.append(("inline", raw))
            elif re.match(r"""^["']?mcp_servers["']?[ \t]*=""", line):
                found.append(("root-inline", raw))
        elif table == "[mcp_servers]" and re.match(rf"^{_TOML_NAME}[ \t]*[.=]", line):
            found.append(("inline", raw))
    return found


_TOML_INLINE_WHY = (f"defines mcp_servers.{SERVER_NAME} as an inline table or with dotted keys, which cloudseed does not rewrite; left it "
                    f"untouched. Remove that entry by hand (or turn it into a [mcp_servers.{SERVER_NAME}] table)")


def _toml_defined_elsewhere(text: str) -> bool:
    """True when mcp_servers.cloudseed is still defined once our [mcp_servers.cloudseed*] tables are stripped."""
    tl = _tomllib()
    if tl is not None:
        try:
            ms = tl.loads(text).get("mcp_servers")
            return isinstance(ms, dict) and SERVER_NAME in ms
        except ValueError:      # tomllib.TOMLDecodeError: fall back to the scan
            pass
    return any(k in ("inline", "header") for k, _ in _toml_scan(text))


def _toml_prepare(path: Path, old: str, section: str) -> str:
    """The new config.toml: the old one without our tables plus `section`. Raises ClientConfigError, with the file left
    untouched, when that cannot be done safely (a file that does not parse, an entry in a form the text rewrite cannot
    remove, an mcp_servers a table cannot be added to): a duplicate key would stop Codex from starting at all."""
    tl = _tomllib()
    if tl is not None and old.strip():
        try:
            tl.loads(old)
        except ValueError as e:
            raise ClientConfigError(f"cannot parse {path} ({e}); left it untouched. Fix it, or add the entry by hand: cs mcp config") from None
    kept = _toml_strip(old)
    if tl is not None:
        if _toml_defined_elsewhere(kept):
            raise ClientConfigError(f"{path} {_TOML_INLINE_WHY}, then connect again (the entry to add: cs mcp config)")
    else:
        kinds = {k for k, _ in _toml_scan(kept)}
        if kinds & {"inline", "header"}:
            raise ClientConfigError(f"{path} {_TOML_INLINE_WHY}, then connect again (the entry to add: cs mcp config)")
        if "root-inline" in kinds:
            raise ClientConfigError(f"{path} writes mcp_servers as an inline table (mcp_servers = {{...}}), which a [mcp_servers.{SERVER_NAME}] "
                                    "table cannot be added to; left it untouched. Turn it into [mcp_servers.<name>] tables, or add the entry by hand: cs mcp config")
    new = (kept + "\n" if kept.strip() else "") + section
    if tl is not None:
        try:
            doc = tl.loads(new)
            ok = isinstance(doc.get("mcp_servers"), dict) and isinstance(doc["mcp_servers"].get(SERVER_NAME), dict)
        except ValueError as e:
            raise ClientConfigError(f"adding [mcp_servers.{SERVER_NAME}] would make {path} invalid ({e}; e.g. mcp_servers is written as an inline "
                                    "table: mcp_servers = {...}); left it untouched. Add the entry by hand: cs mcp config") from None
        if not ok:
            raise ClientConfigError(f"{path}: unexpected layout (mcp_servers is not a table); left it untouched. Add the entry by hand: cs mcp config")
    return new


def _toml_entry(text: str) -> dict | None:
    """The cloudseed entry of a Codex config.toml as {'url', 'auth'} (None when there is none), whatever its form.
    Raises ClientConfigError when the file does not parse (Python 3.11+)."""
    tl = _tomllib()
    if tl is not None:
        try:
            doc = tl.loads(text)
        except ValueError as e:
            raise ClientConfigError(f"does not parse ({e})") from None
        ms = doc.get("mcp_servers")
        e = ms.get(SERVER_NAME) if isinstance(ms, dict) else None
        if not isinstance(e, dict):
            return None
        hdr = e.get("http_headers") if isinstance(e.get("http_headers"), dict) else {}
        return {"url": e.get("url") if isinstance(e.get("url"), str) else None, "auth": hdr.get("Authorization")}
    m = _TOML_OUR_BODY.search(text)
    if m:
        body = m.group(1)
    else:
        body = "\n".join(line for kind, line in _toml_scan(text) if kind == "inline")
        if not body:
            return None
    got_url = re.search(r'(?<![\w-])url[ \t]*=[ \t]*"([^"]*)"', body)
    got_auth = re.search(r'Authorization[ \t]*=[ \t]*"([^"]*)"', body)
    return {"url": got_url.group(1) if got_url else None, "auth": got_auth.group(1) if got_auth else None}


def _claude_stdio_argv() -> list[str]:
    cmd, args = _stdio_spec()
    argv = ["claude", "mcp", "add", "-s", "user", SERVER_NAME]
    for k, v in _stdio_env().items():   # -e is variadic in the claude CLI: it must come AFTER the server name
        argv += ["-e", f"{k}={v}"]
    return argv + ["--", cmd, *args]


def connect(client: str, transport: str, state: dict | None) -> str:
    """Register the cloudseed server with a client. Returns a one-line description of what was written.
    Config files are backed up first, written 0600 and atomically; a file that does not parse is never touched."""
    c = CLIENTS[client]
    if transport not in c["transports"]:
        transport = c["transports"][0]
    if transport == "http" and not state:
        transport = "stdio"
    if c["kind"] == "claude-cli":
        if not shutil.which("claude"):
            raise ui.Abort("Claude Code ('claude') is not on PATH: npm install -g @anthropic-ai/claude-code")
        if transport == "http":
            argv = ["claude", "mcp", "add", "-s", "user", "--transport", "http", SERVER_NAME, url(state)]
            if state.get("auth", "token") == "token":
                argv += ["--header", f"Authorization: Bearer {load_token() or ensure_token()}"]
        else:
            argv = _claude_stdio_argv()
        subprocess.run(["claude", "mcp", "remove", "-s", "user", SERVER_NAME], capture_output=True)
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace")
        if r.returncode != 0:
            raise ui.Abort(f"claude mcp add failed: {secrets.redact((r.stderr or r.stdout).strip())}")
        return f"registered with `claude mcp add -s user` ({transport})"
    path = c["path"]()
    try:
        if c["kind"] == "toml":
            old = _read_text(path)
            new = _toml_prepare(path, old, _toml_section(state, transport))
            if new == old:
                _tighten(path)
                return f"[mcp_servers.{SERVER_NAME}] in {path} is already up to date ({transport})"
            bak = _backup(path, client)
            _write_private(path, new)
            return f"wrote [mcp_servers.{SERVER_NAME}] to {path} ({transport})" + (f"; previous version: {bak}" if bak else "")
        data, jsonc = _read_client_json(path)
        servers = data.get(c["key"])
        if servers is None:
            servers = data[c["key"]] = {}
        elif not isinstance(servers, dict):
            raise ClientConfigError(f"{path}: '{c['key']}' is not an object; left it untouched. Add the entry by hand: cs mcp config")
        entry = http_entry(client, state) if transport == "http" else stdio_entry(client)
        if servers.get(SERVER_NAME) == entry:
            _tighten(path)
            return f"{c['key']}.{SERVER_NAME} in {path} is already up to date ({transport})"
        servers[SERVER_NAME] = entry
        bak = _backup(path, client, keep=jsonc)
        _write_json_file(path, data)
    except ClientConfigError as e:
        raise ui.Abort(str(e)) from None
    if jsonc:
        ui.warn(f"{path} had comments or trailing commas; the rewritten file has none (the original is kept at {bak}; it is never pruned).")
    return f"wrote {c['key']}.{SERVER_NAME} to {path} ({transport})" + (f"; previous version: {bak}" if bak else "")


def disconnect(client: str) -> str | None:
    c = CLIENTS[client]
    if c["kind"] == "claude-cli":
        if not shutil.which("claude"):
            return None
        r = subprocess.run(["claude", "mcp", "remove", "-s", "user", SERVER_NAME], capture_output=True, text=True, errors="replace")
        return "removed (user scope, `claude mcp remove`)" if r.returncode == 0 else None
    path = c["path"]()
    if not path.exists():
        return None
    try:
        if c["kind"] == "toml":
            text = _read_text(path)
            tl = _tomllib()
            if tl is not None:
                try:
                    tl.loads(text)
                except ValueError as e:
                    raise ClientConfigError(f"cannot parse {path} ({e}); left it untouched") from None
            kept = _toml_strip(text) if _TOML_OUR_TABLE.search(text) else text
            if tl is not None and kept != text:
                try:    # the text rewrite must leave a file Codex still loads (e.g. a header-like line inside a """string""")
                    tl.loads(kept)
                except ValueError as e:
                    raise ClientConfigError(f"removing [mcp_servers.{SERVER_NAME}] would leave {path} invalid ({e}); left it untouched. "
                                            "Remove that entry by hand") from None
            if _toml_defined_elsewhere(kept):   # never report "removed" while the entry is still there
                raise ClientConfigError(f"{path} {_TOML_INLINE_WHY}")
            if kept == text:
                return None
            bak = _backup(path, client)
            _write_private(path, kept)
            return f"removed [mcp_servers.{SERVER_NAME}] from {path}" + (f" (previous version: {bak})" if bak else "")
        data, jsonc = _read_client_json(path)
        servers = data.get(c["key"])
        if not isinstance(servers, dict) or SERVER_NAME not in servers:
            return None
        del servers[SERVER_NAME]
        bak = _backup(path, client, keep=jsonc)
        _write_json_file(path, data)
    except ClientConfigError as e:
        ui.warn(f"{c['display']}: {e}")
        return None
    if jsonc:
        ui.warn(f"{path} had comments or trailing commas; the rewritten file has none (the original is kept at {bak}; it is never pruned).")
    return f"removed {c['key']}.{SERVER_NAME} from {path}" + (f" (previous version: {bak})" if bak else "")


def connected(client: str) -> str | None:
    """'http' / 'stdio' when the client config already has the cloudseed server, else None (also for unreadable files)."""
    c = CLIENTS[client]
    if c["kind"] == "claude-cli":
        if not shutil.which("claude"):
            return None
        try:
            r = subprocess.run(["claude", "mcp", "get", SERVER_NAME], capture_output=True, text=True, errors="replace", timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0 or SERVER_NAME not in (r.stdout + r.stderr):
            return None
        return "http" if "http" in r.stdout.lower() and "/mcp" in r.stdout else "stdio"
    path = c["path"]()
    if not path.exists():
        return None
    try:
        if c["kind"] == "toml":
            entry = _toml_entry(_read_text(path))     # any form: a table, an inline table, dotted keys
            return None if entry is None else "http" if entry["url"] else "stdio"
        servers = _read_client_json(path)[0].get(c["key"])
    except ClientConfigError:
        return None
    entry = servers.get(SERVER_NAME) if isinstance(servers, dict) else None
    if not isinstance(entry, dict) or not entry:
        return None
    return "http" if any(k in entry for k in ("url", "serverUrl", "httpUrl")) else "stdio"


def stale(client: str, state: dict | None = None) -> bool:
    """True when the client is wired over HTTP but its entry does not match the deployed server any more (other
    URL/port, old or missing token, or no HTTP server deployed at all). stdio entries never go stale."""
    if connected(client) != "http":
        return False
    s = load_state() if state is None else state
    if not s or s.get("transport") != "http":
        return True
    want_url = url(s)
    tok = load_token() if s.get("auth", "token") == "token" else None
    want_auth = f"Bearer {tok}" if tok else None
    c = CLIENTS[client]
    if c["kind"] == "claude-cli":   # `claude mcp get` shows the URL; the header value is not reliably printed
        try:
            r = subprocess.run(["claude", "mcp", "get", SERVER_NAME], capture_output=True, text=True, errors="replace", timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return want_url not in (r.stdout + r.stderr)
    path = c["path"]()
    try:
        if c["kind"] == "toml":
            entry = _toml_entry(_read_text(path)) or {}
            return entry.get("url") != want_url or entry.get("auth") != want_auth
        servers = _read_client_json(path)[0].get(c["key"])
    except ClientConfigError:
        return False      # unreadable config: connected() already reports it as not wired; never rewrite it blindly
    entry = servers.get(SERVER_NAME) if isinstance(servers, dict) else None
    entry = entry if isinstance(entry, dict) else {}
    got_url = next((entry[k] for k in (c.get("url_key", "url"), "url", "serverUrl", "httpUrl") if entry.get(k)), None)
    headers = entry.get("headers") if isinstance(entry.get("headers"), dict) else {}
    return got_url != want_url or headers.get("Authorization") != want_auth


def refresh_clients(state: dict | None, skip=(), force: bool = False) -> dict[str, str]:
    """Re-write the cloudseed entry of every client wired over HTTP whose entry is stale (or all of them with force),
    so a new port / rotated token / removed server does not leave clients pointing at nothing. Without an HTTP
    deployment the entries are switched to stdio. Returns {client: what was written, or 'failed: ...'}."""
    s = state if state and state.get("transport") == "http" else None
    done: dict[str, str] = {}
    for k in CLIENTS:
        if k in skip or connected(k) != "http" or not (force or stale(k, state or {})):
            continue
        try:
            done[k] = connect(k, "http" if s else "stdio", s)
        except ui.Abort as e:
            done[k] = "failed: " + (getattr(e, "msg", "") or "error")
    return done


def client_config_variants(state: dict | None = None) -> list[dict]:
    """Copy-paste snippets per client: [{key, display, path, variants: [(label, snippet)]}]. HTTP and stdio are
    alternatives - a client gets exactly one of them."""
    s = state or load_state() or None
    if s and s.get("transport") != "http":
        s = None
    out: list[dict] = []
    for key, c in CLIENTS.items():
        variants: list[tuple[str, str]] = []
        if s and "http" in c["transports"]:
            if c["kind"] == "claude-cli":
                tok = f' --header "Authorization: Bearer {load_token()}"' if s.get("auth", "token") == "token" else ""
                snippet = f"claude mcp add -s user --transport http {SERVER_NAME} {url(s)}{tok}"
            elif c["kind"] == "toml":
                snippet = _toml_section(s, "http").rstrip()
            else:
                snippet = json.dumps({c["key"]: {SERVER_NAME: http_entry(key, s)}}, indent=2)
            variants.append((f"HTTP (the shared server at {url(s)})", snippet))
        if "stdio" in c["transports"]:
            if c["kind"] == "claude-cli":
                snippet = _shell_join(_claude_stdio_argv())
            elif c["kind"] == "toml":
                snippet = _toml_section(None, "stdio").rstrip()
            else:
                snippet = json.dumps({c["key"]: {SERVER_NAME: stdio_entry(key)}}, indent=2)
            variants.append(("stdio (the client launches `cloudseed mcp serve`)", snippet))
        out.append({"key": key, "display": c["display"], "path": str(c["path"]()) if c.get("path") else "", "variants": variants})
    return out


def client_configs(state: dict | None = None) -> dict[str, str]:
    """Copy-paste snippets per client (both transports where they apply), keyed by 'display  (path)'."""
    return {b["display"] + (f"  ({b['path']})" if b["path"] else ""): "\n\n".join(v for _, v in b["variants"])
            for b in client_config_variants(state)}


# =============================================================================================== guide
TOOL_GROUPS = [
    ("Discover", "cloudseed_list · cloudseed_doctor · cloudseed_status · cloudseed_output · cloudseed_inventory · cloudseed_env"),
    ("Build & change", "cloudseed_setup (plan / apply / dry_run) · cloudseed_plan · cloudseed_apply · cloudseed_update_ip · cloudseed_provision · cloudseed_install"),
    ("Kubernetes & platform", f"cloudseed_k8s · cloudseed_node · cloudseed_platform ({' '.join(catalog.GROUPS)}) · cloudseed_kubectl · cloudseed_helm"),
    ("Access & services", "cloudseed_ssh · cloudseed_vpn · cloudseed_managed (databricks / snowflake)"),
    ("Cost & diagnosis", "cloudseed_finops (estimate / cloud bill / OpenCost) · cloudseed_troubleshoot · cloudseed_explain · cloudseed_help · cloudseed_skill"),
    ("Resilience & compliance", "cloudseed_dr (backup / restore / drill) · cloudseed_chaos (experiments with verdicts) · cloudseed_scan (Well-Architected / CIS / STIG / vulnerabilities / cloud / FIPS)"),
    ("Undo & tear down", "cloudseed_undo (revert the last action, 5 deep) · cloudseed_destroy (targets / purge_state / purge)"),
]

EXAMPLE_PROMPTS = [
    "List my cloudseed environments and tell me which ones have a bastion running.",
    "Check whether my AWS credentials work and what tools are missing.",
    "Plan a dev environment on AWS in us-west-2 with a private EKS cluster; show me the plan and the monthly estimate before applying.",
    "Apply the plan for aws/dev.  (the agent will call cloudseed_setup with apply=true, confirm=true)",
    "My public IP changed - fix bastion access for gcp/staging.",
    "Install the basek8s platform group on the current cluster and show me the UIs afterwards.",
    "What does aws/dev cost per month, and where can I save?",
    "The last apply on azure/dev failed - diagnose it and propose the fix.",
    "Run the basic chaos suite on the current cluster and explain any failed experiment.",
    "Prove our backups work: run a DR drill and tell me the restore time.",
    "Run the CIS and STIG scans on aws/prod and list the failed controls with remediation.",
    "Is vmware/lab really FIPS-compliant? Verify it.",
    "Tear down vmware/lab completely, including the working directory.",
]


def guide_lines(state: dict | None, wired: dict[str, str] | None = None, live: bool = True) -> list[tuple[str, list]]:
    """The full 'how to use cloudseed from an MCP client' guide as (panel title, rows). live: the guide is shown now (a
    terminal, the web console), so it also says when MCP is switched off; the saved CONNECT.md (live=False) does not,
    since it outlives the setting."""
    s = state or None
    wired = wired or {}
    no_auth = bool(s) and (s.get("auth") or "token") != "token"     # (cli setup: a missing auth means a token)
    tok = load_token() if s and not no_auth else None
    cmd, args = _stdio_spec()
    sections: list[tuple[str, list]] = []
    server_rows: list = []
    if live and not enabled():
        server_rows.append(("Disabled", "MCP is disabled: these entries fail until you run cs enable mcp   (or: cs setup mcp)"))
    if s:
        if no_auth:    # --no-auth: no header and no token file to point at
            auth_rows = [("Auth", "off (deployed with --no-auth): any local process or user that can reach this port can call "
                                  "every tool, confirm=true ones included. To require a bearer token again: cs setup mcp --auth (or "
                                  "cs setup mcp --rotate-token, which always writes a new token)")]
        else:
            # (a missing file: the running server still holds the token it started with; --rotate writes a new one,
            # restarts the server and reconnects the HTTP clients)
            auth_rows = [("Auth header", f"Authorization: Bearer {tok}" if tok else "Authorization: Bearer <token>   (the token file "
                                                                                     "is missing: cs mcp token --rotate writes a new one)"),
                         ("Token file", f"{TOKEN_PATH}   (0600; rotate: cs mcp token --rotate - it restarts the server and updates every "
                                        "HTTP-connected client itself)")]
        # --no-service (recorded as no_service; an older deployment only says service=background) is kept by setup
        # re-runs like --no-auth; a background process without it is the fallback for a refused launchd/systemd
        no_service = s.get("no_service") if "no_service" in s else s.get("service") == "background"
        background = ("detached background process, chosen with --no-service (restart after reboot: cs mcp start; setup "
                      "re-runs keep it - cs setup mcp --service, or `cs setup mcp` at a terminal, offers the login service again)" if no_service else
                      "detached background process: the login service could not be installed (restart after reboot: "
                      "cs mcp start; `cs setup mcp` tries the service again)")
        server_rows += [("Streamable HTTP", url(s)), ("Legacy SSE", sse_url(s) + "   (older clients)"), ("Health", url(s)[: -len('/mcp')] + "/health"),
                        *auth_rows,
                        ("Runs as", {"launchd": f"launchd user agent {_service_label()} (starts at login)", "systemd": f"systemd --user unit {_systemd_name()} (starts at login)",
                                     "background": background}.get(s.get("service") or "", s.get("service") or "?")),
                        ("Log", str(LOG_PATH)),
                        ("Manage", "cs mcp status · cs mcp restart · cs mcp stop · cs mcp start · cs mcp logs")]
    server_rows += [("stdio (per client)", f"{cmd} {' '.join(args)}   - the client launches it; no port, no token"),
                    ("Tools / self-test", "cs mcp tools · cs mcp test" + (" · cs mcp test --http" if s else ""))]
    sections.append(("1. Your cloudseed MCP server", server_rows))

    rows: list = []
    for key, c in CLIENTS.items():
        present = client_present(key)
        state_txt = wired.get(key) or connected(key)
        if state_txt and key not in wired and stale(key, s or {}):
            rows.append((c["display"], f"▲ connected ({state_txt}) but out of date - reconnect:   cs mcp connect {key}"))
        elif state_txt:
            rows.append((c["display"], f"✔ connected ({state_txt})"))
        else:
            mark = "○ installed, not connected" if present else "· not detected"
            rows.append((c["display"], f"{mark}   cs mcp connect {key}" + ("   (or --transport stdio)" if s and "http" in c["transports"] else "")))
    rows.append(("Anything else", "cs mcp config   prints copy-paste snippets for every client and transport"))
    rows.append(("Backups", f"every config cloudseed rewrites is copied to {BACKUPS_DIR} first (the last {KEEP_BACKUPS} per client, plus the "
                            "first copy and any original with comments, which are never pruned)"))
    sections.append(("2. Connect a client  (cs mcp connect <client> | all)", rows))

    how: list = [
        ("Claude Code", "restart it or type /mcp -> cloudseed should be 'connected'; tools appear as mcp__cloudseed__<tool>, prompts as /mcp__cloudseed__<prompt>."),
        ("Claude Desktop", "quit and reopen the app; the tools menu lists the cloudseed tools; a wrong path shows in Settings > Developer > Logs."),
        ("Codex CLI", "`codex mcp list` shows cloudseed; in a session type: 'use the cloudseed tools to list my environments'."),
        ("Cursor / Windsurf", "Settings > MCP (Cursor) or Cascade > MCP (Windsurf): enable 'cloudseed'."),
        ("VS Code", "the mcp.json 'Start' code lens, or MCP: List Servers: start 'cloudseed'."),
        ("Gemini CLI", "`/mcp` inside gemini lists the servers and their tools."),
        ("Any client", "first ask it to read the resource cloudseed://skills/cloudseed - the operating manual - then talk normally."),
        ("How it works", "ask how anything works ('how does the VPN work?', 'what does single_nat_gateway change on AWS?'): the agent "
                         "reads cloudseed://explain/<query> or calls cloudseed_explain with format=json - the page `cs explain` prints."),
        ("Long calls", "setup/apply/destroy/platform install can run for many minutes. Codex and Gemini entries get a 1-hour tool timeout; "
                       "for Claude Code start it with MCP_TOOL_TIMEOUT=3600000 if long calls time out. Cancelling a call in the client "
                       "interrupts the command (Terraform stops gracefully and releases its lock)."),
    ]
    sections.append(("3. Verify the connection", how))

    sections.append(("4. What you can ask", list(TOOL_GROUPS) + [""] + [f"“{p}”" for p in EXAMPLE_PROMPTS]))

    sections.append(("5. Safety model (what the agent can and cannot do)", [
        "Read-only tools (list, status, output, plan, inventory, troubleshoot, finops, explain, help, kubectl get/describe/logs, helm "
        "list/status, scan architecture, scan fips ...) run immediately. Reading Secrets (kubectl get secret, kubectl get --raw other than the health "
        "endpoints) or release values (helm get values/all/manifest/hooks, helm status -o json/yaml, helm template/lint) is not: those "
        "can print passwords, so they need confirm=true like a change. So does a kubectl/helm option that points the tool at another "
        "server, identity or local file (--server, --kubeconfig, --context, --token, --as, get -f <url>, -o *-file ...).",
        "kubectl runs without a terminal and returns its whole output at the end, so calls that never end are refused: follow/watch "
        "(logs -f, get -w), port-forward, proxy and attach (use logs --tail/--since, or kubectl wait --timeout), and so are interactive "
        "ones (edit, exec -it). Run those in your own terminal: cs kubectl ...",
        "cloudseed_k8s kubeconfig needs no confirm (it only writes local files) but it switches your current kubectl context to the "
        "cluster; cloudseed_undo switches it back.",
        "Anything that changes infrastructure, a host or a service (setup apply, apply, destroy, update-ip, provision, node add/remove/scale, "
        "platform install/uninstall/ui, vpn add-user/revoke/provision, ssh commands, mutating kubectl/helm, databricks/snowflake commands "
        "other than status/test/list/get/describe, scans that run jobs, dr, chaos, install, undo) is marked destructiveHint "
        "and refuses to run unless the call carries confirm=true - the agent must ask you first.",
        "Every argument is checked against the tool's schema first (a string 'false' is not a yes). Global actions (MCP/UI/credentials/"
        "agent settings) can only be undone by you: cs undo --global, or the web console.",
        "Every call runs `cloudseed ...` as a child under the credential broker: the client process never sees AWS/GCP/Azure secrets, and all "
        "output is redacted (keys, tokens, private keys, password= pairs). Terraform state and credential files are never exposed as resources.",
        ("The HTTP server listens on 127.0.0.1 only and validates the Origin and Content-Type headers. This one was deployed with "
         "--no-auth, so it does NOT ask for a bearer token: any local process can call every tool (cs setup mcp --rotate-token "
         "requires one again)." if no_auth else
         "The HTTP server listens on 127.0.0.1 only, validates the Origin and Content-Type headers and needs the bearer token. The token is "
         "also stored in each connected client's config (written 0600; Claude Code gets it once on the `claude mcp add` command line).")
        + " Never expose the server publicly; use stdio instead.",
        "Credentials for the background service come from files (~/.aws, ADC, az login). Shell-only env vars (AWS_ACCESS_KEY_ID exported in a "
        "terminal) are not visible to a launchd/systemd service: either use `aws configure` / profiles, or connect that client over stdio.",
    ]))
    sections.append(("6. Turn it off", [("cs mcp disconnect all", "remove the server from every client config"),
                                        ("cs mcp stop | cs disable mcp", "stop the server / refuse to serve until enabled again"),
                                        ("cs destroy mcp", "stop + remove the service, the token and every client entry"),
                                        f"This guide is saved at {GUIDE_PATH}   (cs mcp guide prints it again)"]))
    return sections


def print_guide(state: dict | None, wired: dict[str, str] | None = None) -> None:
    for title, rows in guide_lines(state, wired):
        ui.panel(title, rows, accent="leaf" if title.startswith("1.") else "brand")
    save_guide(state, wired)


def save_guide(state: dict | None, wired: dict[str, str] | None = None) -> Path:
    lines = ["# Using cloudseed from an MCP client", "", f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `cloudseed setup mcp`. Re-print with `cs mcp guide`.", ""]
    for title, rows in guide_lines(state, wired, live=False):
        lines += [f"## {title}", ""]
        for r in rows:
            if isinstance(r, tuple):
                lines.append(f"- **{r[0]}**: {r[1]}")
            elif r:
                lines.append(f"- {r}")
            else:
                lines.append("")
        lines.append("")
    lines += ["## Copy-paste configuration for every client", "", "Use ONE variant per client.", ""]
    for b in client_config_variants(state):
        lines += [f"### {b['display']}", ""] + ([f"Paste into `{b['path']}`", ""] if b["path"] else [])
        for label, snippet in b["variants"]:
            lang = "sh" if snippet.startswith("claude ") else ("toml" if snippet.startswith("[") else "json")
            lines += [f"#### {label}", "", f"```{lang}", snippet, "```", ""]
    _write_private(GUIDE_PATH, "\n".join(lines))   # contains the bearer token: 0600 from the first byte
    return GUIDE_PATH
