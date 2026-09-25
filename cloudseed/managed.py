"""Managed data platforms reachable from the CLI: Databricks and Snowflake.

cloudseed installs the official CLIs, stores connection profiles (0600, redacted in logs, stripped from agent
environments) and runs `cs databricks ...` / `cs snowflake ...` with the profile of the current environment.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path

from . import deps, paths, secrets, ui

PROFILES = paths.HOME / "managed.json"

SERVICES = {
    "databricks": {
        "tool": "databricks", "display": "Databricks",
        # (key, prompt, secret)
        "fields": [("host", "Workspace URL (https://<workspace>.cloud.databricks.com)", False),
                   ("token", "Personal access token (or leave empty to use OAuth: `databricks auth login`)", True)],
        "required": ("host",),
        "env": {"host": "DATABRICKS_HOST", "token": "DATABRICKS_TOKEN"},
        "check": ["current-user", "me"],
        "docs": "https://docs.databricks.com/dev-tools/cli/",
    },
    "snowflake": {
        "tool": "snow", "display": "Snowflake",
        "fields": [("account", "Account identifier (orgname-accountname)", False), ("user", "User", False),
                   ("password", "Password (empty = key-pair/SSO via `snow connection add`)", True),
                   ("role", "Default role", False), ("warehouse", "Default warehouse", False), ("database", "Default database", False)],
        "required": ("account", "user"),
        "env": {"account": "SNOWFLAKE_ACCOUNT", "user": "SNOWFLAKE_USER", "password": "SNOWFLAKE_PASSWORD", "role": "SNOWFLAKE_ROLE",
                "warehouse": "SNOWFLAKE_WAREHOUSE", "database": "SNOWFLAKE_DATABASE"},
        # the profile reaches `snow` as a generated config file whose default connection is the profile (see run())
        "check": ["connection", "test"],
        "docs": "https://docs.snowflake.com/en/developer-guide/snowflake-cli/",
    },
}

# argv values that are secrets whatever their shape (masked in the echoed command line), on top of the flags
# secrets.mask_argv already knows (--string-value, --password, --token, ...)
_SECRET_FLAGS = {"--private-key-passphrase", "--pat"}
# short flags that are a secret for one tool only: snow's -p is --password (`snow connection add`), helm's is
# `registry login --password`; for databricks -p is --profile, for kubectl --previous (`logs -p`) or --patch
_SHORT_SECRET_FLAGS = {"snowflake": {"-p"}, "snow": {"-p"}, "helm": {"-p"}}
_NO_SHORT_SECRETS = {"databricks", "kubectl", "k9s"}
# the Databricks CLI's own profile flag (a persistent flag of every command): its ~/.databrickscfg profile
_DATABRICKS_PROFILE_FLAGS = ("-p", "--profile")


def _load() -> dict:
    try:
        return json.loads(PROFILES.read_text())
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    paths.ensure_home()
    fd = os.open(PROFILES, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)


def profile(service: str, name: str) -> dict:
    return _load().get(service, {}).get(name, {})


def parse_connect_args(service: str, args: list[str]) -> tuple[dict, str | None]:
    """`connect` arguments: key=value, --key value and --key=value (the documented form), plus --profile NAME.
    Returns (values, profile or None). Unknown keys are refused instead of silently dropped."""
    known = [k for k, _, _ in SERVICES[service]["fields"]]
    values: dict = {}
    prof = None
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            key, eq, val = a[2:].partition("=")
            if not eq:
                if i + 1 >= len(args) or args[i + 1].startswith("--"):
                    raise ui.Abort(f"--{key} needs a value, e.g. --{key} VALUE")
                val = args[i + 1]
                i += 1
        elif "=" in a:
            key, _, val = a.partition("=")
        else:
            raise ui.Abort(f"Expected --key value or key=value, got '{a}' (keys: {', '.join(known)})")
        key = key.strip().replace("-", "_")
        if key == "profile":
            prof = val
        elif key in known:
            values[key] = val
        else:
            raise ui.Abort(f"Unknown {SERVICES[service]['display']} setting '{key}' (known: {', '.join(known)}, profile)")
        i += 1
    return values, prof


def connect(service: str, name: str, values: dict | None = None) -> None:
    """Save (or update) a profile. Required settings (Databricks host; Snowflake account and user) must be given or
    answered - with -y a missing one stops with the flag to pass instead of saving an unusable profile."""
    spec = SERVICES[service]
    data = _load()
    current = data.setdefault(service, {}).get(name, {})
    out = dict(current)
    required = spec.get("required", ())
    for key, prompt, secret in spec["fields"]:
        if values and key in values:
            out[key] = values[key]
        elif secret:
            if ui.interactive():
                import getpass
                v = getpass.getpass(f"  ? {prompt} [{'set' if current.get(key) else 'empty'}]: ")
                if v:
                    out[key] = v
        else:
            have = current.get(key) or ""
            out[key] = ui.ask(prompt, have if have or key not in required else None, required=key in required, flag=f"--{key}")
        if key in required and not str(out.get(key) or "").strip():
            raise ui.Abort(f"{spec['display']} needs {key}: cs {service} connect --{key} VALUE")
    out = {k: v for k, v in out.items() if str(v).strip()}      # empty optional settings are left out, not stored as ""
    data[service][name] = out
    _save(data)
    ui.ok(f"{spec['display']} profile '{name}' saved to {PROFILES} (0600)")


def env_for(service: str, name: str) -> dict:
    spec = SERVICES[service]
    e = deps.path_env()
    for key, var in spec["env"].items():
        val = profile(service, name).get(key)
        if val:
            e[var] = val
    return e


def _toml_str(v: str) -> str:
    """A TOML basic string. JSON's escaping fits TOML except for astral characters, which ensure_ascii would write as
    surrogate pairs (not valid TOML escapes); DEL is the one control character JSON leaves raw."""
    return json.dumps(str(v), ensure_ascii=False).replace("\x7f", "\\u007F")


def snowflake_config(name: str) -> Path | None:
    """A 0600 snow config file whose default connection is this cloudseed profile. `snow` reads SNOWFLAKE_* variables only
    with --temporary-connection (which several subcommands reject), so the profile is handed over as a config file."""
    prof = profile("snowflake", name)
    if not prof.get("account"):
        return None
    conn = "cloudseed-" + re.sub(r"[^A-Za-z0-9_-]", "-", name)
    d = paths.HOME / "managed"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    lines = [f"default_connection_name = {_toml_str(conn)}", "", f"[connections.{_toml_str(conn)}]"]
    for key, _, _ in SERVICES["snowflake"]["fields"]:
        if prof.get(key):
            lines.append(f"{key} = {_toml_str(prof[key])}")
    path = d / f"snowflake-{re.sub(r'[^A-Za-z0-9_-]', '-', name)}.toml"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    return path


def _secret_flags(tool: str | None) -> set:
    """The flags whose value is masked for `tool` (the service or CLI name). An unknown tool masks every short
    secret flag any of them has: over-masking an echo is harmless, a password in the audit trail is not."""
    if tool in _SHORT_SECRET_FLAGS:
        return _SECRET_FLAGS | _SHORT_SECRET_FLAGS[tool]
    if tool in _NO_SHORT_SECRETS:
        return set(_SECRET_FLAGS)
    return _SECRET_FLAGS.union(*_SHORT_SECRET_FLAGS.values())


def mask_argv(args: list[str], tool: str | None = None, auth: bool | None = None) -> list[str]:
    """argv for display/logging: secrets.mask_argv (secret flags, --from-literal, everything else through
    secrets.redact) plus the managed CLIs' own secret flags. `tool` names the CLI the arguments belong to (databricks,
    snowflake/snow, kubectl, helm, k9s): -p is a password for snow and helm, but databricks' --profile and kubectl's
    --previous/--patch. auth=True also hides Authorization headers and bearer tokens whatever the redaction mode (the
    echoed `$ databricks ...` / `$ helm ...` line, which reaches the command log too)."""
    flags = _secret_flags(tool)
    args = [str(a) for a in args]
    out = secrets.mask_argv(args, auth=auth)   # one entry per argument
    for i, a in enumerate(args):
        flag, eq, _ = a.partition("=")
        if a in flags and i + 1 < len(args):
            out[i + 1] = secrets.REDACTED
        elif eq and flag in flags:
            out[i] = f"{flag}={secrets.REDACTED}"
    return out


def _databricks_own_profile(args: list[str]) -> bool:
    """The command names a ~/.databrickscfg profile itself (-p NAME / --profile NAME / --profile=NAME)."""
    return any(a in _DATABRICKS_PROFILE_FLAGS or a.split("=", 1)[0] in _DATABRICKS_PROFILE_FLAGS for a in args)


# options of the vendor CLIs that take a value, so the value is not read as a command word
_VALUE_FLAGS = {
    "databricks": {"-p", "--profile", "-o", "--output", "-t", "--target", "--log-level", "--log-file", "--log-format"},
    "snowflake": {"-c", "--connection", "--config-file", "--format", "-D", "--variable", "--role", "--warehouse",
                  "--database", "--schema", "--account", "--user", "--host", "--port", "--region", "--authenticator",
                  "--private-key-file", "--private-key-path", "--token-file-path", "--mfa-passcode"},
}


def _words(service: str, args: list[str]) -> list[str]:
    """The command words of a vendor command line (options and their values left out): ['auth', 'login']."""
    takes_value = _VALUE_FLAGS.get(service, set())
    out, skip, plain = [], False, False
    for a in args:
        if skip:
            skip = False
            continue
        if a == "--" and not plain:
            plain = True                # everything after it is an argument, never an option
            continue
        if a.startswith("-") and not plain:
            skip = a in takes_value     # --flag VALUE (a --flag=VALUE carries its own)
            continue
        out.append(a)
    return out


def _stdin_inheritable() -> bool:
    """A redacted run may hand its stdin on to the vendor CLI: anything but a terminal (a prompt there would be hidden
    behind the line-by-line redaction)."""
    try:
        return not sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _stdin_piped() -> bool:
    """Input is really there on stdin: a pipe, a file or a socket (`echo TOKEN | cs databricks configure ...`). Neither
    a terminal is (a redacted run never lends it to the vendor CLI) nor /dev/null, which is what agent, MCP and console
    sessions give the commands they run: a prompt there would only read end-of-file."""
    try:
        if sys.stdin is None or sys.stdin.isatty():
            return False
        mode = os.fstat(sys.stdin.fileno()).st_mode
    except (AttributeError, ValueError, TypeError, OSError):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISREG(mode) or stat.S_ISSOCK(mode)


def needs_terminal(service: str, args: list[str], piped: bool | None = None) -> str | None:
    """Why this vendor command needs a person at a terminal (a browser sign-in, prompts, an interactive shell), or None.
    An agent session runs the command with its output redacted line by line and no terminal: such a command would
    wait for an answer nobody can give (`databricks auth login` waits for the browser sign-in until it is cancelled).
    Asking for a command's --help never needs one (-h too for databricks; for `snow connection add` it is --host)."""
    plain = args[:args.index("--")] if "--" in args else args
    if "--help" in plain or (service == "databricks" and "-h" in plain):
        return None
    words = _words(service, args)
    piped = _stdin_piped() if piped is None else piped
    has = set(plain) | {a.split("=", 1)[0] for a in plain}
    if service == "databricks":
        if words[:2] == ["auth", "login"]:
            return "databricks auth login signs in through a browser and waits for it"
        if words[:1] == ["configure"] and not piped:
            return "databricks configure asks for the workspace and token"
    if service == "snowflake":
        if words[:2] == ["connection", "add"] and "--no-interactive" not in has and not piped:
            return "snow connection add asks for every setting it is not given (pass --no-interactive)"
        if words[:1] == ["sql"] and not piped and not has & {"-q", "--query", "-f", "--filename", "-i", "--stdin"}:
            return "snow sql without -q/-f starts an interactive SQL shell"
    return None


def terminal_command(service: str, name: str, args: list[str]) -> str:
    """The `cs` command line that repeats this run in a terminal: the cloudseed profile in use is named (unless it is
    the 'default' one), and a `--` goes in front of vendor arguments cloudseed would otherwise read as its own (a
    --profile before any `--`, a leading option such as -e/--env, a trailing -y). Secret values stay masked."""
    plain = args[:args.index("--")] if "--" in args else args
    sep = bool(args) and (args[0].startswith("-") or args[-1] in ("-y", "--yes")
                          or any(a == "--profile" or a.startswith("--profile=") for a in plain))
    words = ["cs", service] + (["--profile", name] if name and name != "default" else []) + (["--"] if sep else [])
    return " ".join(shlex.quote(a) for a in words + mask_argv(args, service))


def ensure_tool(service: str) -> str:
    """The vendor CLI. A missing one is never installed from an agent or MCP session (their read-only calls such as
    `test` need no confirmation), and never on the strength of an --auto-approve in the passthrough arguments, which
    belongs to the vendor command (`databricks bundle deploy --auto-approve`): on a terminal it is offered, otherwise
    the command stops with `cloudseed install <tool>`."""
    spec = SERVICES[service]
    tool, why = spec["tool"], f"for cs {service} ({spec['docs']})"
    found = deps.find(tool)
    if found:
        return found
    if os.environ.get("CLOUDSEED_AGENT"):
        raise ui.Abort(f"{tool} is needed {why} but is not installed, and cloudseed does not install software from an agent "
                       f"or MCP session. Install it yourself first: cloudseed install {tool}", code=2)
    from . import services
    return services.ensure_tool(tool, why, argv_consent=False)


def run(service: str, name: str, args: list[str]) -> int:
    redacted = secrets.redact_enabled()
    if redacted:
        # before anything is installed or echoed: a command that needs a terminal cannot run in an agent session
        why = needs_terminal(service, args)
        if why:
            raise ui.Abort(f"{why}, which is not available inside an agent session (its output is redacted and it gets no "
                           f"terminal). Run it in your own terminal instead: {terminal_command(service, name, args)}", code=2)
    binary = ensure_tool(service)
    prof = profile(service, name)
    # the profile's token/password are literal secrets for this process: the vendor CLI can print them back
    # (`databricks auth env`), and a redacted run must hide them whatever their shape
    secrets.register(*(prof.get(key) for key, _, secret in SERVICES[service]["fields"] if secret))
    existing = ", ".join(_load().get(service, {})) or "none"
    hint = f" (saved profiles: {existing}; pick one with --profile NAME)" if existing != "none" else ""
    cmd = [binary, *args]
    env = env_for(service, name)
    label = name
    if service == "snowflake":
        own = {"-c", "--connection", "-x", "--temporary-connection", "--config-file"}
        uses_own = any(a in own or a.split("=", 1)[0] in own for a in args)
        if any(a.split("=", 1)[0] in ("-c", "--connection", "--config-file") for a in args):
            # the user's own snow connection: snow fills every key it lacks from SNOWFLAKE_* variables, so the
            # cloudseed profile (password, role, warehouse ...) must not leak into it
            env = {k: v for k, v in env.items() if k not in SERVICES["snowflake"]["env"].values()}
            label = ""                  # no cloudseed profile in play: the echo names none
        if not prof and not uses_own:
            ui.warn(f"No Snowflake profile '{name}'{hint}: cs snowflake connect   (or use `snow connection add` and pass -c <name>)")
        if not uses_own:
            conf = snowflake_config(name)
            if conf:
                cmd = [binary, "--config-file", str(conf), *args]
    if service == "databricks":
        if _databricks_own_profile(args):
            # the user's own ~/.databrickscfg profile: the Databricks CLI lets DATABRICKS_HOST/TOKEN variables override
            # what the profile says, so the cloudseed profile (or a vault token) must not reach it
            env = {k: v for k, v in env.items() if k not in SERVICES["databricks"]["env"].values()}
            label = ""
        elif not prof.get("host") and not os.environ.get("DATABRICKS_HOST"):
            ui.warn(f"No Databricks profile '{name}'{hint}: cs databricks connect   (or `databricks auth login --host <url>`)")
    shown = " ".join(shlex.quote(a) for a in mask_argv(args, service, auth=True))
    print(ui.dim(f"  [{service}{':' + label if label else ''}] $ {SERVICES[service]['tool']} {shown}"))
    if redacted:
        # an agent session: the vendor CLI's output (tokens, secrets, query results with credentials) is redacted line
        # by line like every other passthrough; piped input stays available, a terminal never is (no hidden prompts)
        return secrets.run_redacted(cmd, env=env, stdin=None if _stdin_inheritable() else subprocess.DEVNULL)
    return subprocess.call(cmd, env=env)


def test(service: str, name: str) -> int:
    return run(service, name, SERVICES[service]["check"])


def status() -> None:
    data = _load()
    rows = []
    for svc, spec in SERVICES.items():
        installed = deps.find(spec["tool"])
        profs = ", ".join(data.get(svc, {}).keys()) or ui.dim("no profiles")
        mark = ui.style("✔", "leaf", "bold") if installed else ui.style("○", "muted")
        rows.append(f"{mark} {ui.style(svc.ljust(12), 'text')} {ui.dim(spec['display'] + ' CLI: ' + ('installed' if installed else 'cs install ' + spec['tool']))}   profiles: {profs}")
    ui.panel("Managed data platforms", rows)
    print(ui.dim("  cs databricks connect --host URL · cs databricks <args>   ·   cs snowflake connect --account ORG-ACCT --user NAME · cs snowflake <args>   ·   cs help managed"))
