"""Always-on audit trail and inventory, kept in every environment's working directory.

  <workdir>/logs/audit.jsonl      one JSON line per cloudseed invocation (who, what, when, exit code, duration, and
                                  via: cli, ui for the web console, or the agent - mcp, builtin, claude, ...)
  <workdir>/logs/<ts>-<cmd>.log   full (redacted) output of that invocation: cloudseed messages, terraform, ansible
                                  (one file per run: a second run of the same command in the same second gets
                                  <ts>-<cmd>-<random>.log)
  <workdir>/inventory.json        what exists right now (from terraform state) + a history of every change
  ~/.cloudseed/logs/audit.jsonl   global copy of the audit lines (for runs that never reached an environment)
  ~/.cloudseed/logs/<ts>-<cmd>-crash.log
                                  redacted traceback of an unexpected error when no environment log is attached (0600)

Nothing here is optional: every command writes its trail regardless of flags. Everything written here is redacted,
Authorization headers and bearer tokens included (the terminal and the console may show those to their owner; files
on disk never keep them).
"""

from __future__ import annotations

import contextlib
import getpass
import json
import os
import re
import secrets as _random
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import paths, secrets, ui

_state: dict = {"argv": [], "started": 0.0, "env": None, "log": None, "cmd": ""}
_PARENTS: list[str] = []   # set while an in-process nested command runs (cs undo -> cloudseed destroy ...)

# top-level options that take a separate value: their value is not the command (`cs --runtime container status ...`)
GLOBAL_VALUE_OPTS = ("--runtime", "--engine")

# Commands (and group subcommands) that change an environment - its working directory, state, hosts or cluster: the
# console's one-job-per-environment rule (webui._MUTATING/_SUB_MUTATING) is the same set. troubleshoot diagnoses their
# failures before those of read-only runs.
MUTATING = frozenset(("setup", "apply", "destroy", "update-ip", "provision", "plan", "undo"))
SUB_MUTATING = {"node": ("add", "remove", "scale"), "platform": ("install", "uninstall", "ui"),
                "dr": ("backup", "restore", "schedule", "test"), "chaos": ("run", "stop"),
                "vpn": ("add-user", "revoke", "provision"), "k8s": ("kubeconfig", "tunnel", "untunnel"),
                "scan": ("cis", "kube", "images", "host", "stig", "cloud", "fips", "all")}

# Authorization headers and bearer tokens. secrets.redact() hides them only in agent-facing contexts (the terminal and
# the console legitimately show users their own MCP client configuration), but nothing persisted here may keep them:
# `cs ssh -- curl -H 'Authorization: Bearer ...'`, `helm --set ...headers.Authorization=Basic ...`, curl's glued
# `-HAuthorization: ...` form and whatever such a command prints.
_AUTH_PATTERNS = [
    re.compile(r"(?i)((?:\b|(?<=-H))(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?\s*"
               r"(?:bearer|basic|token|digest|bot|negotiate|apikey)\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/-]{16,}=*"),
    # a value with no scheme (`-H "Authorization: <api key>"`): anything token-like, 16+ characters with a digit
    re.compile(r"(?i)((?:\b|(?<=-H))(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?\s*)"
               r"(?!(?:bearer|basic|token|digest|bot|negotiate|apikey|aws4-hmac-sha256)\s)"
               r"(?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{16,}"),
]


def scrub_auth(text):
    """`text` without Authorization header values or bearer tokens (whatever the redaction mode), for files on disk."""
    if not text or not isinstance(text, str):
        return text
    for pat in _AUTH_PATTERNS + list(getattr(secrets, "_AGENT_PREFIX_PATTERNS", None) or []):
        text = pat.sub(lambda m: m.group(1) + secrets.REDACTED, text)
    return text


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _words(argv: list[str]) -> list[str]:
    """Positional words of a command line, skipping the values of the global options that take one."""
    out: list[str] = []
    it = iter(argv)
    for a in it:
        if a in GLOBAL_VALUE_OPTS:
            next(it, None)
            continue
        if not a.startswith("-"):
            out.append(a)
    return out


def command_of(argv: list[str]) -> str:
    """The cloudseed command an argv runs (what `command` in the audit record and the log file name show)."""
    words = _words(argv)
    if not words:
        return "cloudseed"
    # `cs setup mcp` / `status mcp` / `destroy mcp` are handled by the mcp command (cli._dispatch rewrites them)
    if len(words) > 1 and words[1] == "mcp" and words[0] in ("setup", "status", "destroy"):
        return "mcp"
    return words[0]


# passthrough commands whose tool has secret flags of its own (managed.mask_argv): snow's and helm's -p is a password,
# databricks' -p a profile name and kubectl's --previous/--patch, which stay readable
TOOL_COMMANDS = ("databricks", "snowflake", "helm", "kubectl", "k9s")


def safe_argv(argv: list[str]) -> list[str]:
    """argv as it may be persisted: every value of `creds set KEY=VALUE` is masked whatever the key is called
    (only the vault's plain-text settings such as AWS_PROFILE stay readable); the values of secret flags passed through
    to other CLIs (--string-value X, --password X, --from-literal=k=X, and the passthrough tool's own: `cs helm ...
    registry login -p X`) are masked, everything else goes through redact() with Authorization headers and bearer
    tokens hidden whatever the redaction mode (secrets.mask_argv(auth=True))."""
    words = _words([str(a) for a in argv])
    creds_set = words[:2] == ["creds", "set"]
    known: dict = {}
    if creds_set:
        try:
            from .creds import KNOWN as known
        except Exception:  # noqa: BLE001 - the audit trail must never break a command
            known = {}
    out = []
    for a in argv:
        a = str(a)
        if creds_set and not a.startswith("-") and "=" in a:
            k, _, _v = a.partition("=")
            if known.get(k.strip().upper(), ("", "", "secret"))[2] not in ("text", "path"):
                a = f"{k}={secrets.REDACTED}"
        out.append(a)
    masked = None
    tool = words[0] if words[:1] and words[0] in TOOL_COMMANDS else None
    if tool:
        try:
            from .managed import mask_argv   # also the tool's own secret flags (snow/helm -p <password>)
            # headers first: the key=value rule would otherwise take `X-Auth-Token: Bearer` and leave the token
            masked = mask_argv([scrub_auth(a) for a in out], tool, auth=True)
        except Exception:  # noqa: BLE001 - the audit trail must never break a command
            masked = None
    if masked is None:
        masked = secrets.mask_argv(out, auth=True)
    return [scrub_auth(a) for a in masked]    # persisted: Authorization headers go whatever the redaction mode


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no passwd entry (container uid mapping)
        return os.environ.get("USER", "?")


def _host() -> str:
    # the container runtime passes the host's name: the audit trail records the machine the user is on
    return os.environ.get("CLOUDSEED_HOST_NAME") or socket.gethostname()


def _open_private(path: Path):
    """Append-mode text handle for a log file, created 0600 (logs can quote command lines and outputs)."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)          # files created 0644 by older versions are tightened too
    except (OSError, AttributeError):
        pass
    return os.fdopen(fd, "a", encoding="utf-8")


def _create_private(folder: Path, stem: str, tail: str = ".log"):
    """(path, handle) of a NEW 0600 file <stem><tail> in folder - never one another run is writing: when two runs of
    the same command start in the same second, the later one gets <stem>-<random><tail> (exclusive create; the pid is
    not enough, container runs reuse pids)."""
    name = stem + tail
    for _ in range(64):
        path = folder / name
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        except FileExistsError:
            name = f"{stem}-{_random.token_hex(3)}{tail}"
            continue
        return path, os.fdopen(fd, "a", encoding="utf-8")
    raise FileExistsError(f"no free log file name for {folder / (stem + tail)}")


def begin(argv: list[str]) -> None:
    if not _PARENTS and _state.get("log"):
        # a previous in-process invocation that never reached end(); a nested one keeps the parent's handle (restored)
        try:
            _state["log"].close()
        except (OSError, ValueError):
            pass
    _state.update(argv=list(argv), started=time.time(), env=None, log=None, logpath=None, purged=False,
                  tags={}, parent=_PARENTS[-1] if _PARENTS else None, keys=_KeyFilter(), cmd=command_of(argv))
    ui.set_sink(write)


def set_command(cmd: str) -> None:
    """Called once argparse knows the real command (more exact than the argv scan in begin())."""
    if cmd:
        _state["cmd"] = cmd


def tag(**fields) -> None:
    """Extra fields for this invocation's audit record (e.g. which undo entry was undone)."""
    _state.setdefault("tags", {}).update(fields)


@contextlib.contextmanager
def nested(parent: str):
    """Run another cloudseed command in-process (cs undo -> cli.main([...])) with its own audit record, tagged
    parent=<parent>, and give the outer command its own state (argv, start time, log) back afterwards."""
    saved = dict(_state)
    _PARENTS.append(parent)
    try:
        yield
    finally:
        _PARENTS.pop()
        inner = _state.get("log")
        if inner is not None and inner is not saved.get("log"):
            try:
                inner.close()
            except (OSError, ValueError):
                pass
        _state.clear()
        _state.update(saved)
        ui.set_sink(write)


def _safe_cmd() -> str:
    """The command, as it may appear in a file name."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", _state.get("cmd") or "cloudseed")[:40]


def attach(env: paths.Env) -> None:
    """Switch the output log into the environment's working directory (called as soon as the env is known)."""
    if _state["env"] is not None and _state["env"].id == env.id:
        return
    logs = env.dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(logs, 0o700)
    except OSError:
        pass
    path, fh = _create_private(logs, f"{_ts()}-{_safe_cmd()}")
    fh.write(f"# cloudseed {' '.join(safe_argv(_state['argv']))}\n# {_now()} user={_user()} host={_host()} cwd={os.getcwd()}\n")
    if _state["log"]:
        try:
            _state["log"].close()
        except (OSError, ValueError):
            pass
    _state.update(env=env, log=fh, logpath=path)
    if not (env.dir / "inventory.json").exists():
        save(env, load(env))


class _KeyFilter(secrets.StreamRedactor):
    """The log's redactor: secrets.StreamRedactor (private keys printed over several lines - helm values, ssh output -
    are swallowed whole, which line-by-line redaction cannot do), fed line by line: one write() may carry several
    lines (a traceback, a multi-line message). One instance per command, created in begin()."""

    MAX_LINES = secrets.StreamRedactor.MAX_KEY_LINES   # a stray BEGIN (quoted in an error) must not swallow the log

    def __init__(self):
        # auth=True: a log is a file on disk, so Authorization headers and bearer tokens go before the key=value rule
        # runs (`X-Auth-Token: Bearer <token>` would otherwise lose only the word "Bearer")
        super(_KeyFilter, self).__init__(auth=True)

    def feed(self, text: str) -> str:
        # scrub_auth: a log is a file on disk, where Authorization headers never go (whatever the redaction mode)
        return "".join(scrub_auth(super(_KeyFilter, self).feed(line)) for line in text.splitlines(keepends=True))


def write(line: str) -> None:
    fh = _state.get("log")
    if fh:
        try:
            text = line if line.endswith("\n") else line + "\n"
            keys = _state.get("keys")
            if keys is None:
                keys = _state["keys"] = _KeyFilter()
            text = keys.feed(text)       # redact() included, after the look for a BEGIN marker
            if text:
                fh.write(text)
                fh.flush()
        except (OSError, ValueError):
            pass


def origin() -> str:
    """Who ran this invocation, for the audit record's `via`: "ui" for the web console (its jobs run with
    CLOUDSEED_UI=1, even when an agent started them from the console), else the agent that did (CLOUDSEED_AGENT: "mcp",
    "builtin", "claude", ...), else "cli" (a person at a terminal, a script, CI)."""
    if os.environ.get("CLOUDSEED_UI") == "1":
        return "ui"
    agent = re.sub(r"[^A-Za-z0-9_.:-]", "_", (os.environ.get("CLOUDSEED_AGENT") or "").strip())[:40]
    return agent or "cli"


_APPEND_LOCK = threading.Lock()     # one writer at a time within a process (the console answers from many threads)


def _append(line: str, env: paths.Env | None = None) -> None:
    """Append one audit line to the global trail and, when given, to the environment's own (best effort)."""
    targets = [paths.HOME / "logs" / "audit.jsonl"]
    if env is not None:
        targets.append(env.dir / "logs" / "audit.jsonl")
    with _APPEND_LOCK:
        for t in targets:
            try:
                t.parent.mkdir(parents=True, exist_ok=True)
                with _open_private(t) as fh:
                    fh.write(line)
            except OSError:
                pass


def record(argv: list[str], rc: int = 0, via: str | None = None, env: paths.Env | None = None, **tags) -> dict:
    """Write one audit record for a change made outside a cloudseed command run - the web console's own changes to
    the vault or the current environment - exactly as the CLI records `cs creds ...` / `cs env ...` (secret values
    masked by safe_argv, tags redacted by secrets_free). `via` defaults to origin(); `env` also writes the line into
    that environment's trail when its working directory exists (a record never creates one; an environment id string
    is recorded as such, in the global trail only). Thread-safe and best effort: the audit trail never fails the
    change. Returns the record."""
    rec: dict = {}
    try:
        argv = [str(a) for a in argv or []]
        own = env if isinstance(env, paths.Env) else None
        env_id = getattr(env, "id", None) or (str(env) if env else None)
        rec = {"at": _now(), "user": _user(), "host": _host(), "command": command_of(argv), "argv": safe_argv(argv),
               "exit_code": rc, "duration_s": 0.0, "env": env_id, "log": None,
               "cloudseed": paths.REPO_ROOT.name, "python": sys.version.split()[0], "via": via or origin()}
        for k, v in tags.items():
            rec.setdefault(k, secrets_free(v))
        _append(json.dumps(rec, default=str) + "\n", own if own is not None and own.dir.is_dir() else None)
    except Exception:  # noqa: BLE001 - never fail the change being recorded
        pass
    return rec


def end(rc: int) -> None:
    rec = {
        "at": _now(), "user": _user(), "host": _host(),
        "command": _state["cmd"], "argv": safe_argv(_state["argv"]),
        "exit_code": rc, "duration_s": round(time.time() - _state["started"], 1),
        "env": _state["env"].id if _state["env"] else None,
        "log": str(_state.get("logpath")) if _state.get("log") else None,
        "cloudseed": paths.REPO_ROOT.name, "python": sys.version.split()[0],
        # console job, MCP call, agent run or a person at a terminal: told apart in the trail
        "via": origin(),
    }
    if _state.get("parent"):
        rec["parent"] = _state["parent"]
    for k, v in (_state.get("tags") or {}).items():
        rec.setdefault(k, secrets_free(v))
    _append(json.dumps(rec, default=str) + "\n",
            _state["env"] if _state["env"] and not _state.get("purged") else None)
    if _state.get("log"):
        try:
            _state["log"].write(f"# exit {rc} after {rec['duration_s']}s\n")
            _state["log"].close()
        except (OSError, ValueError):
            pass
        _state["log"] = None


def mark_purged() -> None:
    """The environment directory is gone: keep the final audit line in the global log only."""
    _state["purged"] = True
    if _state.get("log"):
        try:
            _state["log"].close()
        except OSError:
            pass
        _state["log"] = None


def attached() -> tuple:
    """(env, log path) of the environment log this command is writing, or (None, None) when there is none."""
    if _state.get("log") and _state.get("env") is not None:
        return _state["env"], _state.get("logpath")
    return None, None


def record_crash(text: str) -> Path | None:
    """Keep an unexpected error's traceback (redacted): in the environment log when one is attached, otherwise in
    ~/.cloudseed/logs/<ts>-<cmd>-crash.log (0600), which the global audit line then points at. Returns the file, or
    None when nothing could be written."""
    if _state.get("log"):
        write(text)
        return _state.get("logpath")
    try:
        logs = paths.HOME / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        path, fh = _create_private(logs, f"{_ts()}-{_safe_cmd()}", "-crash.log")
        fh.write(f"# cloudseed {' '.join(safe_argv(_state['argv']))}\n# {_now()} user={_user()} host={_host()} cwd={os.getcwd()}\n")
        fh.flush()
    except OSError:
        return None
    _state.update(log=fh, logpath=path)
    write(text)   # the same key filter + redaction as every other log line
    return path


def read_audit(env: paths.Env, last: int = 20) -> list[dict]:
    if last <= 0:
        return []
    p = env.dir / "logs" / "audit.jsonl"
    try:
        lines = p.read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-last:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


# ---------------- inventory ----------------

INTERESTING = ("id", "name", "arn", "public_ip", "private_ip", "ip", "address", "endpoint", "vmx_path", "bucket",
               "cidr_block", "ip_cidr_range", "address_prefixes", "self_link", "fqdn", "private_fqdn")
# attributes whose name collides with a field of the inventory row itself (Terraform's address/name): stored under
# another key, so `address` is always the Terraform address (google_compute_address.address is an IP) and `name` the
# Terraform resource name (the object's own name - a VM, a bucket, a role - is `cloud_name`)
RENAMED = {"address": "ip_address", "name": "cloud_name"}
# every key an inventory row can hold as a cloud value (for secrets_free: identifiers keep their shape)
_VALUE_KEYS = frozenset(INTERESTING) | frozenset(RENAMED.values())


def _walk(module: dict, out: list) -> None:
    for r in module.get("resources", []):
        vals = r.get("values") or {}
        row = {RENAMED.get(k, k): vals[k] for k in INTERESTING if k in vals and isinstance(vals[k], (str, int, list))}
        # Terraform's own fields last: they are authoritative
        row.update(address=r.get("address"), type=r.get("type"), name=r.get("name"), mode=r.get("mode"))
        out.append(row)
    for child in module.get("child_modules", []):
        _walk(child, out)


def refresh(env: paths.Env, tf, action: str, extra: dict | None = None) -> dict:
    """Rebuild <workdir>/inventory.json from terraform state; append a history entry."""
    resources: list = []
    outputs: dict = {}
    proc = tf.run("show", "-json", capture=True, check=False)
    if proc.returncode != 0:
        # the state could not be read (a provider terraform cannot load, a backend it cannot reach): what exists is
        # unknown, so the inventory keeps what it knew and the history says so - never "0 resources (nothing deployed)"
        text = secrets.redact(((proc.stderr or "") + "\n" + (proc.stdout or "")).strip())
        lines = [ln.strip(" \t│╷╵") for ln in text.splitlines() if ln.strip(" \t│╷╵")]
        why = next((ln for ln in lines if ln.startswith("Error:")), lines[0] if lines else f"exit {proc.returncode}")
        inv = load(env)
        inv.setdefault("history", []).append({"at": _now(), "action": action, "state_unreadable": why[:200], **(extra or {})})
        inv["history"] = inv["history"][-200:]
        save(env, inv)
        return inv
    if proc.stdout.strip():
        try:
            data = json.loads(proc.stdout)
            _walk((data.get("values") or {}).get("root_module") or {}, resources)
            # outputs marked sensitive never land in inventory.json (read by the console, MCP and agents)
            outputs = {k: (secrets.REDACTED if v.get("sensitive") else v.get("value"))
                       for k, v in ((data.get("values") or {}).get("outputs") or {}).items()}
        except ValueError:
            pass
    resources = [r for r in resources if r.get("mode") == "managed"]
    inv = load(env)
    by_type: dict[str, int] = {}
    for r in resources:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
    entry = {"at": _now(), "action": action, "resources": len(resources), "by_type": by_type, **(extra or {})}
    inv.setdefault("history", []).append(entry)
    inv["history"] = inv["history"][-200:]
    inv["current"] = {"updated_at": _now(), "resources": resources, "outputs": outputs, "count": len(resources)}
    save(env, inv)
    return inv


def note(env: paths.Env, event: str, data: dict | None = None) -> None:
    """Record a non-terraform change (provisioning, VPN users, images) in the inventory history."""
    inv = load(env)
    inv.setdefault("history", []).append({"at": _now(), "action": event, **(data or {})})
    inv.setdefault("current", {}).setdefault("notes", {})[event] = {"at": _now(), **(data or {})}
    save(env, inv)


def load(env: paths.Env) -> dict:
    try:
        return json.loads((env.dir / "inventory.json").read_text())
    except (OSError, ValueError):
        return {"env": env.id, "created_at": _now(), "history": [], "current": {}}


def save(env: paths.Env, inv: dict) -> None:
    inv["env"] = env.id
    env.dir.mkdir(parents=True, exist_ok=True)
    target = env.dir / "inventory.json"
    # written aside and renamed: a reader (console, MCP, a parallel command) never sees a half-written file
    fd, tmp = tempfile.mkstemp(dir=str(env.dir), prefix=".inventory.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(secrets_free(inv), indent=2) + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _token_redact(text: str) -> str:
    """Only the token-shaped patterns (keys, JWTs, API tokens): identifiers such as ARNs and resource ids contain
    words like 'secret' or 'token' followed by ':' and would be mangled by the key=value rule. redact(kv=False)
    still scrubs token formats, URL passwords, signed-URL params and literal vault secrets (and, on disk, bearer
    tokens and Authorization headers)."""
    return secrets.redact(text, kv=False, auth=True)


def secrets_free(obj, _key: str | None = None):
    """`obj` (a string, or lists/dicts of them) as it may be written to disk: redacted, Authorization headers and
    bearer tokens included whatever the redaction mode; inventory values (ids, ARNs, addresses) keep their shape."""
    if isinstance(obj, str):
        return scrub_auth(_token_redact(obj) if _key in _VALUE_KEYS else secrets.redact(obj, auth=True))
    if isinstance(obj, list):
        return [secrets_free(x, _key) for x in obj]
    if isinstance(obj, dict):
        return {k: secrets_free(v, k) for k, v in obj.items()}
    return obj
