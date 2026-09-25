"""Built-in agent: drives cloudseed through the Claude API without any external agent CLI.

- Uses the official `anthropic` SDK (installed on demand into ~/.cloudseed/venv-agent, so the core CLI
  stays dependency-free).
- Exactly one tool: run a `cloudseed ...` command. Nothing else (no shell, no file access). Every command is
  parsed with cloudseed's own parser (exact option names, no abbreviations) and checked on what it will really
  do: human-only commands (agent/host/credential configuration, shells, installers) are refused by the same policy
  as every agent session's (cli.human_only_reason: read-only forms such as `creds list` stay available), and anything
  that changes or deletes infrastructure, the hosts or this machine needs the user's approval (APPROVAL_TEXT:
  --auto-approve, --purge, provision, scans, vpn add-user/provision/revoke/connect/disconnect, platform/chaos/dr
  changes, mutating kubectl/helm, reading cluster secrets...). Commands that stop at cloudseed's own approval step
  without --auto-approve (PREVIEW_TEXT: destroy, undo, node add/remove/scale, platform uninstall, dr restore, chaos run
  --target) run unasked as a preview, so the user approves once, with the plan on screen. Refused calls are shown to
  the user too.
- Child commands run with the user's credentials but every line they print is redacted, shown to the user as it
  arrives, and redacted again before it goes back to the model (first and last 6000 characters of long output).
  SIGTERM/SIGHUP or Ctrl-C stop the running command together with the agent.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import importlib
import io
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from . import paths, secrets, skills, ui

VENV = paths.HOME / "venv-agent"
MAX_OUTPUT = 12000
DRAIN_SECONDS = 10   # how long to wait for the rest of a finished command's output (a process it left behind may hold the pipe)
MODELS = ["claude-opus-5", "claude-opus-5-5", "claude-fable-5-1", "claude-sonnet-5"]
DEFAULT_MODEL = "claude-opus-5"
# model families that predate adaptive thinking (they reject {"type": "adaptive"}); newer ones get it
_NO_ADAPTIVE_THINKING = ("claude-haiku-4-5", "claude-sonnet-4-5", "claude-opus-4-5", "claude-opus-4-1", "claude-opus-4-2025",
                         "claude-sonnet-4-2025", "claude-opus-4-0", "claude-sonnet-4-0", "claude-3")


def _py_version() -> str:
    return "%d.%d" % sys.version_info[:2]


def _venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _venv_site_packages() -> Path:
    """The venv's site-packages for THIS interpreter's version (the only one this process can import from)."""
    if os.name == "nt":
        return VENV / "Lib" / "site-packages"
    return VENV / "lib" / f"python{_py_version()}" / "site-packages"


def _venv_version() -> str | None:
    """major.minor of the Python that created venv-agent (from pyvenv.cfg)."""
    try:
        text = (VENV / "pyvenv.cfg").read_text()
    except (OSError, ValueError):
        return None
    for line in text.splitlines():
        key, _, val = line.partition("=")
        if key.strip().lower() in ("version", "version_info"):
            return ".".join(val.strip().split(".")[:2]) or None
    return None


def _venv_matches() -> bool:
    """venv-agent was built by a Python of this version and its interpreter runs on this machine. A venv made by the
    container runtime (Linux), by another Python version, or by an interpreter that has since been removed must not be
    put on sys.path: its compiled packages (pydantic-core) cannot load here."""
    if _venv_version() != _py_version() or not _venv_site_packages().is_dir():
        return False
    if os.name == "nt":
        return _venv_python().exists()
    from . import deps
    return deps.venv_usable(VENV)


def _import_sdk() -> bool:
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def _use_venv() -> None:
    sp = str(_venv_site_packages())
    if sp not in sys.path:
        sys.path.insert(0, sp)
    importlib.invalidate_caches()


def _forget_venv_modules() -> None:
    """Drop modules a failed import left behind from venv-agent, so the rebuilt venv's copies are loaded instead."""
    root = os.path.realpath(VENV) + os.sep
    for name, mod in list(sys.modules.items()):
        f = getattr(mod, "__file__", None)
        if f and os.path.realpath(f).startswith(root):
            sys.modules.pop(name, None)


def ensure_sdk(auto: bool = True) -> None:
    """Import `anthropic`, installing it into a private venv (~/.cloudseed/venv-agent) on first use. A venv this
    interpreter cannot use (built by another Python version or platform, or broken) is rebuilt."""
    if _import_sdk():
        return
    exists = VENV.exists() or VENV.is_symlink()
    if exists and _venv_matches():
        _use_venv()
        if _import_sdk():
            return
    if not auto:
        raise ui.Abort("The `anthropic` package is required for the built-in agent (pip install anthropic).")
    if paths.IS_BUNDLE:
        raise ui.Abort("The single-binary build cannot install the Anthropic SDK; use an external agent "
                       "(cloudseed use claude) or run cloudseed from a source checkout.")
    if exists:
        built = _venv_version()
        why = (f"it was built by Python {built}, this is {_py_version()}" if built and built != _py_version() else
               "it was built by another interpreter or platform, or is incomplete")
        ui.info(f"Rebuilding {VENV} for this Python ({why})")
    else:
        ui.info(f"Installing the Anthropic SDK into {VENV} (first time only)")
    try:
        if VENV.is_symlink() or (exists and not VENV.is_dir()):
            VENV.unlink()
        elif exists:
            shutil.rmtree(VENV)
        rc = subprocess.run([sys.executable, "-m", "venv", str(VENV)]).returncode
        if rc == 0:
            rc = subprocess.run([str(_venv_python()), "-m", "pip", "install", "--quiet", "--upgrade", "pip",
                                 "anthropic"]).returncode
    except OSError as e:
        raise ui.Abort(f"Could not create {VENV}: {e}") from None
    if rc != 0:
        raise ui.Abort(f"Could not install the anthropic package into {VENV}.")
    _forget_venv_modules()
    _use_venv()
    try:
        import anthropic  # noqa: F401
    except ImportError as e:
        raise ui.Abort(f"The Anthropic SDK was installed into {VENV} but cannot be imported here: {e}") from None


def anthropic_config_dir() -> Path:
    """Where the Anthropic SDK and `ant auth login` keep profiles: $ANTHROPIC_CONFIG_DIR, else %APPDATA%\\Anthropic on
    Windows, else ~/.config/anthropic (macOS included)."""
    env = os.environ.get("ANTHROPIC_CONFIG_DIR")
    if env:
        return Path(env)
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        return (Path(appdata) if appdata else Path.home() / "AppData" / "Roaming") / "Anthropic"
    return Path.home() / ".config" / "anthropic"


def _active_config_pointer() -> str:
    try:
        return (anthropic_config_dir() / "active_config").read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return ""


def has_api_credentials() -> bool:
    """Would the Anthropic SDK find credentials? The SDK's own resolution order, without importing it (this runs before
    the SDK is installed): an API key or auth token; an explicitly selected profile (ANTHROPIC_PROFILE,
    ANTHROPIC_CONFIG_DIR or a non-empty active_config pointer); workload-identity variables; or the active profile's
    configs/<profile>.json. A config directory that merely exists (an empty config.json, a Finder .DS_Store) is not a
    credential."""
    env = os.environ
    if env.get("ANTHROPIC_API_KEY") or env.get("ANTHROPIC_AUTH_TOKEN"):
        return True
    pointer = _active_config_pointer()
    if env.get("ANTHROPIC_PROFILE") or env.get("ANTHROPIC_CONFIG_DIR") or pointer:
        return True
    if env.get("ANTHROPIC_FEDERATION_RULE_ID") and env.get("ANTHROPIC_ORGANIZATION_ID") and \
            ("ANTHROPIC_IDENTITY_TOKEN" in env or env.get("ANTHROPIC_IDENTITY_TOKEN_FILE")):
        return True
    profile = pointer or "default"
    if not profile or profile.startswith(".") or any(s in profile for s in ("/", "\\", "\x00")):
        return False
    try:
        return (anthropic_config_dir() / "configs" / f"{profile}.json").is_file()
    except OSError:
        return False


def claude_fallback() -> tuple[dict, str]:
    """Claude Code as the built-in agent's fallback when no API key exists: (its spec, state), state 'ready' when it is
    installed and logged in, 'login' when it is installed but not logged in, 'missing' when it is not installed.
    Only a 'ready' Claude Code is ever used: routing a task to a CLI that is not logged in just fails later."""
    from . import agents
    claude = agents.get("claude")
    if not agents.installed(claude):
        return claude, "missing"
    return claude, ("ready" if agents.auth_ok(claude) else "login")


def _msg_rows(rows: list[tuple[str, str]], avail: int) -> list[str]:
    """`command   (note)` rows, the notes wrapped in their own column; below ~60 columns (or for a command too long
    for the column) the note goes on the lines under its command."""
    from . import help as helpmod
    col = min(35, max(len(c) for c, _ in rows) + 2)
    out: list[str] = []
    for cmd, note in rows:
        note = f"({note})"
        if avail - 4 - col >= 24 and len(cmd) + 2 <= col:
            out += helpmod._wrap(note, avail, "    " + cmd.ljust(col), " " * (4 + col))
        else:
            out += helpmod._wrap(cmd, avail, "    ", "      ")
            out += helpmod._wrap(note, avail, "      ", "      ")
    return out


def no_creds_msg(claude_state: str | None = None, headline: bool = True) -> str:
    """The built-in agent's 'no API credentials' text, wrapped to the terminal (it is shown after the 4-column `▲ ` /
    `✖ ` prefix), without advice that cannot work on this machine (`cloudseed use claude` only helps once Claude Code
    is installed and logged in). headline=False: only the options and the note (under another message)."""
    from . import help as helpmod
    if claude_state is None:
        claude_state = claude_fallback()[1]
    if claude_state == "ready":
        claude = ("cloudseed use claude", "use your logged-in Claude Code CLI instead - no API key needed")
    elif claude_state == "login":
        claude = ("claude", "Claude Code is installed but not logged in: run it once and log in; agent tasks then run "
                            "through it - no API key needed")
    else:
        claude = ("npm install -g @anthropic-ai/claude-code, log in with `claude`, then: cloudseed use claude",
                  "Claude Code with your claude.ai subscription - no API key needed")
    avail = max(36, ui.width() - 4)
    rows = [("export ANTHROPIC_API_KEY=...", "console.anthropic.com; or: cloudseed creds set ANTHROPIC_API_KEY"),
            ("ant auth login", "Anthropic CLI profile"), claude]
    lines = helpmod._wrap("The built-in agent needs Anthropic API credentials, and none were found.", avail, "", "") \
        if headline else []
    lines += ["  Options:"] + _msg_rows(rows, avail)
    lines += helpmod._wrap("Note: a Claude Code / claude.ai subscription login cannot be used by the API SDK; Claude Code "
                           "is the way to use it.", avail, "  ", "        ")
    return "\n".join(lines)


# Commands that are human-only, entirely or in every form that changes something (the agent/host/credential setup,
# shells, installers). Which call is refused is decided per call by cli.human_only_reason - the one policy every agent
# session shares with the CLI's own gate - so read-only forms (creds list, model, use list, ui status, mcp guide, deps
# status, skill list ...) work here as they do for any agent; ssh and k9s are refused on top (they need a terminal,
# which the built-in agent's commands never have).
HUMAN_ONLY = ("agentic", "do", "enable", "disable", "use", "model", "ssh", "k9s", "install", "mcp", "ui", "creds")
_NEEDS_TERMINAL = {"ssh": "an interactive SSH session needs the user's terminal",
                   "k9s": "a full-screen terminal UI needs the user's terminal"}
_ALWAYS_REFUSED = ("agentic", "do", "enable", "disable", "ssh", "k9s")   # no form of these is for an agent
# (keep in step with cli.human_only_reason / cli._AGENT_READ_FORMS and the extra refusals in _parse)
_HUMAN_ONLY_TEXT = ("cloudseed ssh, k9s, agentic, enable, disable, install <anything>, deps install|image|bundle|runtime, "
                    "skill install, creds set|unset|clear, use <agent>, model <id>|--forget, ui (open/start/stop/restart/"
                    "serve/token), mcp setup|connect|disconnect|start|stop|restart|serve|token|uninstall (setup/destroy "
                    "mcp). Their read-only forms work: creds (list), model, use list, install list, ui status|logs, mcp "
                    "status|guide|tools|config|test|logs, deps status, skill list|show")
# Commands whose trailing arguments belong to another program (never strip or add flags there).
_PASSTHROUGH = ("kubectl", "helm", "k9s", "databricks", "snowflake", "ssh", "agentic", "do")
_SKILL_WORDS = skills.TASK_WORDS   # (kept under the old name)

# What needs the user's approval, in words the model is given (keep in step with _approval_reason).
APPROVAL_TEXT = ("any --auto-approve, --purge/--purge-state, provision, scans (all but architecture, fips and reports), vpn "
                 "add-user/provision/revoke/connect/disconnect, platform install/ui, chaos run/stop, dr "
                 "backup/schedule/test, mutating kubectl/helm (and options that point them at another server, identity or "
                 "local file), helm template/lint, reading cluster secrets, and databricks/snowflake commands other than "
                 "status/test")
PREVIEW_TEXT = "destroy, undo, node add/remove/scale, platform uninstall, dr restore and chaos run --target"


def system_prompt(task: str) -> str:
    """The cloudseed skills become the (cacheable) system prompt: the core skill, the ones the task needs, and an
    index of the others (the agent can read any of them with `skill show <name>`)."""
    parts = [
        "You are cloudseed's built-in infrastructure agent. You can ONLY act through the run_cloudseed tool, "
        "which runs `cloudseed <args>` on the user's machine. You cannot run other programs or read files. "
        "Follow the skills below exactly. Be concise; report outcomes, not process. "
        "Never ask for, guess, or echo credentials; the environment is authenticated already or `cloudseed doctor` "
        "will say what the user must run themselves. "
        f"These commands are human-only and will be refused: {_HUMAN_ONLY_TEXT}. When a skill calls for one, "
        "give the user the exact command to run instead. Commands run non-interactively (no -y needed). "
        f"These need the user's approval and are shown to them first (without a terminal they are refused): "
        f"{APPROVAL_TEXT}. {PREVIEW_TEXT} only preview without --auto-approve (exit code 3, nothing changes): run "
        "the preview first, then the same command with --auto-approve - the user is asked once, with the preview on "
        "screen.",
        "",
        skills.prompt_bundle(task, tool="run_cloudseed(\"skill show <name>\")"),
    ]
    return "\n".join(parts)


class _Refused(Exception):
    pass


_PARSER: dict = {}


def _parser() -> argparse.ArgumentParser:
    """cloudseed's own parser with option abbreviations disabled everywhere (`--auto` is not `--auto-approve`)."""
    if "p" not in _PARSER:
        from . import cli
        p = cli.build_parser()
        stack, seen = [p], set()
        while stack:
            q = stack.pop()
            if id(q) in seen:
                continue
            seen.add(id(q))
            q.allow_abbrev = False
            for action in q._actions:
                if isinstance(action, argparse._SubParsersAction):
                    stack.extend(action.choices.values())
        _PARSER["p"] = p
    return _PARSER["p"]


def _commands() -> set:
    for action in _parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _parse(args: list[str]) -> tuple[argparse.Namespace | None, list[str]]:
    """Validate a tool call. Returns (namespace or None for --help/--version, argv to execute); raises _Refused."""
    argv = list(args)
    if argv and argv[0] in ("cloudseed", "cs"):   # models often repeat the program name
        argv.pop(0)
    while argv and argv[0] in ("-y", "--yes"):
        argv.pop(0)
    if not argv:
        raise _Refused("empty command")
    if argv[0] in ("-h", "--help", "--version"):
        return None, ["-y"] + argv[:1]
    if argv[0].startswith("-"):
        raise _Refused("global options (--runtime, --engine, ...) are not available to the agent; start with the command")
    from . import cli
    cmd = argv[0]
    if cmd in _ALWAYS_REFUSED:
        why = _NEEDS_TERMINAL.get(cmd) or cli.human_only_reason(argparse.Namespace(cmd=cmd)) or "human-only"
        shown = _human_command(argv)
        shown = shown if len(shown) <= 160 else shown[:159] + "…"
        raise _Refused(f"`{shown}` is human-only ({why}) and not available to the agent; give the user the command "
                       "to run in a terminal.")
    if cmd not in _commands():
        raise _Refused(f"unknown command '{cmd}'. Commands: "
                       f"{', '.join(sorted(c for c in _commands() if c not in _ALWAYS_REFUSED))}")
    if cmd not in _PASSTHROUGH:
        argv = [argv[0]] + [a for a in argv[1:] if a not in ("-y", "--yes")]
    # the global position: accepted by every command, never inside a passthrough. `setup|status|destroy mcp` become
    # the mcp command exactly as the CLI rewrites them (the child runs the same rewrite)
    final = cli.normalize_argv(["-y"] + argv)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            ns = _parser().parse_args(final)
    except SystemExit as e:
        text = _ANSI.sub("", buf.getvalue()).strip()
        if e.code in (0, None):
            return None, final   # --help / --version: harmless, let the child print it
        errs = [ln.strip().lstrip("✖").strip() for ln in text.splitlines() if "✖" in ln or ln.strip().startswith("error:")]
        raise _Refused("invalid arguments: " + secrets.redact("; ".join(errs) or text[-800:]) +
                       " (spell options out in full; for kubectl/helm put the verb first, e.g. kubectl get pods -n NS)")
    why = _NEEDS_TERMINAL.get(ns.cmd) or cli.human_only_reason(ns)
    if why:
        raise _Refused(f"`{_human_command(final)}` is human-only ({why}) and not available to the agent; give the "
                       "user the command to run in a terminal.")
    if ns.cmd == "mcp" and getattr(ns, "mcp_cmd", None) == "serve":   # (an MCP client starts it, never this agent)
        raise _Refused("`cloudseed mcp serve` is the MCP server itself: it runs until it is stopped and the built-in "
                       "agent cannot talk to it. Use `cloudseed mcp status` or `cloudseed mcp test` to check it.")
    if getattr(ns, "runtime", None) or getattr(ns, "engine", None):
        raise _Refused("runtime selection is not available to the agent.")
    if getattr(ns, "ssh_public_key", None) or getattr(ns, "ssh_private_key", None):
        raise _Refused("SSH key paths are managed by cloudseed; do not pass key paths.")
    return ns, final


# ---------------------------------------------------------------- kubectl / helm: what a call really does
# One fail-closed reader for the agent's kubectl/helm calls (MCP can use kube_approval too). Before the verb only the
# tools' global options can appear; one that is not known here makes the verb unknowable (`--cache-dir get delete`
# runs a delete: `get` is the option's value), so such a call needs approval.
_KUBECTL_GLOBAL_VALUE = frozenset((
    "-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server", "--token", "--as",
    "--as-group", "--as-uid", "--request-timeout", "--certificate-authority", "--client-certificate", "--client-key",
    "--tls-server-name", "--cache-dir", "-v", "--v", "--vmodule", "--profile", "--profile-output", "--username",
    "--password", "--log-flush-frequency", "--kuberc"))
_KUBECTL_GLOBAL_BOOL = frozenset(("--insecure-skip-tls-verify", "--match-server-version", "--warnings-as-errors",
                                  "--disable-compression", "-h", "--help"))
_HELM_GLOBAL_VALUE = frozenset((
    "-n", "--namespace", "--kube-context", "--kubeconfig", "--kube-apiserver", "--kube-token", "--kube-as-user",
    "--kube-as-group", "--kube-ca-file", "--kube-tls-server-name", "--registry-config", "--repository-config",
    "--repository-cache", "--content-cache", "--burst-limit", "--qps", "--color", "--colour"))
_HELM_GLOBAL_BOOL = frozenset(("--debug", "--kube-insecure-skip-tls-verify", "-h", "--help"))
# Options (anywhere) that point the tool at another API server or identity - `--server https://x
# --insecure-skip-tls-verify` sends the cluster's bearer token there - or make it read/write files on this machine.
_KUBECTL_OVERRIDES = frozenset((
    "-s", "--server", "--kubeconfig", "--context", "--cluster", "--user", "--token", "--username", "--password",
    "--insecure-skip-tls-verify", "--certificate-authority", "--client-certificate", "--client-key", "--tls-server-name",
    "--as", "--as-group", "--as-uid", "--profile", "--profile-output", "--kuberc"))
_HELM_OVERRIDES = frozenset((
    "--kubeconfig", "--kube-context", "--kube-apiserver", "--kube-token", "--kube-as-user", "--kube-as-group",
    "--kube-ca-file", "--kube-tls-server-name", "--kube-insecure-skip-tls-verify", "--registry-config",
    "--repository-config", "--repository-cache", "--content-cache", "--ca-file", "--cert-file", "--key-file", "--keyring",
    "--values", "--set-file", "--post-renderer"))
# long options whose value is the next word (for reading values; any other long option counts as a switch)
_KUBECTL_LONG_VALUE = _KUBECTL_GLOBAL_VALUE | {"--output", "--raw", "--filename", "--kustomize", "--output-directory",
                                               "--template", "--selector", "--field-selector", "--container"}
_HELM_LONG_VALUE = _HELM_GLOBAL_VALUE | {"--output", "--revision", "--max", "--selector", "--values", "--version"}
# one-letter options that take a value (the rest of a bundle is its value: -nshop, -n=shop, -ojson)
_KUBECTL_SHORT_VALUE = "nolLsvc"
_HELM_SHORT_VALUE = "nolmf"

_KUBECTL_READ = {"get", "describe", "logs", "top", "explain", "version", "api-resources", "api-versions",
                 "cluster-info", "events"}
# `template` and `lint` are not reads: they render charts with values/files from this machine (as MCP counts them)
_HELM_READ = {"list", "ls", "status", "history", "hist", "show", "inspect", "search", "version", "repo", "get", "env",
              "dependency", "dep", "plugin"}
_HELM_SUBVERB = {"get", "repo", "dependency", "dep", "plugin"}   # the second word decides what they do
_HELM_SECRET_GET = {"values", "all", "manifest", "hooks"}   # rendered values/manifests carry Secrets and passwords
_SECRET_WORD = re.compile(r"(?:^|[,/])secrets?(?:$|[,/.?])", re.I)
# `kubectl get --raw` paths that are health/version/metrics endpoints (anything else can be a Secret: query strings
# and %-encoding defeat a word match, so only these exact shapes pass)
_SAFE_RAW = re.compile(r"/(?:(?:healthz|livez|readyz)(?:/[A-Za-z0-9_-]+)?|version|metrics)/?(?:\?[A-Za-z0-9_=&-]*)?")


class _StrictParser:
    """What cli._kube_passthrough reports a malformed global option (`--runtime bogus`) to: raised, never printed."""
    @staticmethod
    def error(message: str) -> None:
        raise ValueError(message)


def _tool_rest(words: list[str], verbatim: bool | None = None) -> list[str]:
    """The tool's own arguments exactly as `cs kubectl|helm` hands them to the tool (cmd_ktool). `verbatim` is the
    parsed tool_verbatim when `words` are the parsed tool_args; None means `words` are everything after
    `cloudseed kubectl|helm`, read first as cli._kube_passthrough reads them (a cloud key, `--env NAME` and global
    options in front, then an explicit `--`). After that explicit `--` the words are the tool's own: only one more
    leading `--` is dropped, and a cloud key or --env there reaches the tool. Without it, cmd_ktool still takes a
    leading `--`, a cloud key and `--env NAME` / `-e NAME` / `--env=NAME` / `-eNAME` as cloudseed's."""
    from . import cli
    words = list(words or [])
    if verbatim is None:
        ns = argparse.Namespace(cloud=None, env=None, yes=False, runtime=None, engine=None)
        try:
            cli._kube_passthrough(words, ns, _StrictParser)
        except ValueError:            # the CLI refuses the call; read the words as they are (fails closed)
            return words
        words, verbatim = list(ns.tool_args), bool(ns.tool_verbatim)
    rest = cli._strip_leading_sep(words)
    if verbatim:
        return rest
    if rest and rest[0] in cli.CLOUD_KEYS:
        rest = rest[1:]
    return cli._strip_leading_sep(cli._pull_env_arg(argparse.Namespace(env=None), rest))


def _short_letters(tok: str, value_letters: str) -> tuple[list[str], str | None]:
    """The option letters of a one-dash bundle (`-it`, `-As`, `-nshop`) and the glued value of the first letter that
    takes one ('' when its value is the next word, None when no letter takes a value)."""
    letters: list[str] = []
    for i, ch in enumerate(tok[1:], 1):
        if not ch.isalpha():
            break
        letters.append(ch)
        if ch in value_letters:
            rest = tok[i + 1:]
            return letters, rest[1:] if rest.startswith("=") else rest
    return letters, None


def _read_call(tool: str, words: list[str]) -> dict:
    """{"pos": positional words, "opts": [(name, value or None)], "words": the words up to `--`, "tail": the words after
    it, "unreadable": an option cloudseed cannot read where it decides what runs - before the verb, or (helm) before
    the sub-command of get/repo/dependency/plugin - else None}."""
    kube = tool == "kubectl"
    gvalue, gbool = (_KUBECTL_GLOBAL_VALUE, _KUBECTL_GLOBAL_BOOL) if kube else (_HELM_GLOBAL_VALUE, _HELM_GLOBAL_BOOL)
    long_value = _KUBECTL_LONG_VALUE if kube else _HELM_LONG_VALUE
    short_value = _KUBECTL_SHORT_VALUE if kube else _HELM_SHORT_VALUE
    pos: list[str] = []
    opts: list[tuple[str, str | None]] = []
    unreadable = None
    i = 0
    while i < len(words):
        w = words[i]
        if w == "--":
            break
        # where an option decides what runs: before the verb, or before a helm verb's sub-command
        deciding = not pos or (not kube and len(pos) == 1 and pos[0] in _HELM_SUBVERB)
        if w.startswith("--") and len(w) > 2:
            name, eq, val = w.partition("=")
            if eq:
                opts.append((name, val))
            elif name in (gvalue if not pos else long_value):
                opts.append((name, words[i + 1] if i + 1 < len(words) else ""))
                i += 1
            else:
                opts.append((name, None))
            if deciding and unreadable is None and name not in gvalue and name not in gbool \
                    and (not pos or (not eq and name not in long_value)):
                unreadable = w
            i += 1
            continue
        if w.startswith("-") and len(w) > 1 and not w[1:].replace(".", "", 1).isdigit():
            letters, glued = _short_letters(w, short_value)
            known = ("-" + "".join(letters) in gbool) or (len(letters) == 1 and "-" + letters[0] in gvalue)
            if deciding and unreadable is None and not known:
                unreadable = w
            for ch in (letters[:-1] if glued is not None else letters):
                opts.append(("-" + ch, None))
            if glued is not None:
                if glued == "":
                    glued = words[i + 1] if i + 1 < len(words) else ""
                    i += 1
                opts.append(("-" + letters[-1], glued))
            i += 1
            continue
        pos.append(w)
        i += 1
    return {"pos": pos, "opts": opts, "unreadable": unreadable, "words": words[:i], "tail": words[i + 1:]}


def kube_approval(tool: str, words: list[str], verbatim: bool | None = None) -> str | None:
    """Why this kubectl/helm call needs the user's approval, or None when it only reads (without secrets). `words` are
    the arguments after `cloudseed kubectl|helm` (a leading cloud key / --env NAME are cloudseed's own), or with
    `verbatim` given, the parsed tool_args and tool_verbatim (see _tool_rest): the words read are always the ones the
    tool gets. Fails closed: anything that cannot be read with certainty needs approval."""
    rest = _tool_rest(words, verbatim)
    call = _read_call(tool, rest)
    pos, opts = call["pos"], call["opts"]
    names = {n for n, _ in opts}
    verb = pos[0] if pos else ""

    def values(*wanted: str) -> list[str]:
        return [v or "" for n, v in opts if n in wanted]

    if call["unreadable"] is not None:
        return (f"{tool} {call['unreadable']}: an option before the command that cloudseed cannot read (the real "
                f"command could hide behind it)")
    if tool == "kubectl":
        if verb not in _KUBECTL_READ:
            return f"kubectl {verb or '(no verb)'} can change the cluster"
        override = sorted(names & _KUBECTL_OVERRIDES)
        if override:
            return f"kubectl {override[0]} points kubectl at another server, identity or local file"
        if any(v.endswith("-file") or "-file=" in v for v in values("-o", "--output")):
            return "kubectl -o ...-file reads a template file from this machine"
        if verb in ("get", "describe") and names & {"-f", "--filename", "-k", "--kustomize"}:
            return f"kubectl {verb} -f/-k reads manifests from files or URLs (which can name a Secret)"
        if verb == "cluster-info" and "--output-directory" in names:
            return "kubectl cluster-info dump --output-directory writes files on this machine"
        if verb == "get":
            raw = values("--raw")
            if raw and not all(_SAFE_RAW.fullmatch(v) for v in raw):
                return "kubectl get --raw reads any API path (cluster Secrets included)"
            scan = list(call["words"]) + list(call["tail"]) + [v for _n, v in opts if v]
            if any(_SECRET_WORD.search(w) for w in scan):
                return "reading Kubernetes secrets"
        return None
    if verb in ("template", "lint"):
        return f"helm {verb} renders charts with values and files from this machine"
    if verb not in _HELM_READ:
        return f"helm {verb or '(no verb)'} can change the cluster"
    override = sorted(names & _HELM_OVERRIDES)
    if override:
        return f"helm {override[0]} points helm at another server, identity or local file"
    sub = pos[1] if len(pos) > 1 else ""
    if verb == "get" and (not sub or sub in _HELM_SECRET_GET):
        return "helm get values/all/manifest/hooks can reveal passwords"
    if verb in ("repo", "dependency", "dep", "plugin") and sub not in ("list", "ls"):
        return f"helm {verb} {sub or '(no sub-command)'} changes helm configuration"
    if verb == "status" and any(v != "table" for v in values("-o", "--output")):
        return "helm status -o json/yaml includes the release's values, rendered manifests and live Secrets"
    return None


def _undo_entry(ns: argparse.Namespace):
    """The entry `cloudseed undo` would act on in this agent session: the entry, False when nothing would happen (no
    entry, or one an agent may not undo), None when it cannot be known up front."""
    from . import undo
    if getattr(ns, "global_scope", False):
        return False            # refused for agents (cmd_undo)
    try:
        entries = undo.entries()
    except Exception:  # noqa: BLE001 - an unreadable journal: the child reports it
        return None
    eid = getattr(ns, "id", None)
    cloud, env = getattr(ns, "cloud", None), getattr(ns, "env", None)
    if eid:
        entry = next((e for e in entries if e.get("id") == eid), None)
    elif cloud and env:
        pool = [e for e in entries if e.get("scope") == f"{cloud}-{env}"]
        entry = pool[-1] if pool else None
    elif not cloud and not env:
        pool = [e for e in entries if e.get("scope") != undo.GLOBAL]
        entry = pool[-1] if pool else None
    else:
        return None             # one of <cloud> / --env: the child picks among the matching environments
    if entry is None or entry.get("scope") == undo.GLOBAL:
        return False
    return entry


def _undo_reason(ns: argparse.Namespace, auto: bool) -> str | None:
    from . import undo
    if getattr(ns, "list", False):
        return None
    if getattr(ns, "drop", False):
        return "undo --drop removes an entry from the undo history (nothing can be undone with it afterwards)"
    entry = _undo_entry(ns)
    if entry is False:
        return None             # nothing to undo: the child says so and changes nothing
    try:   # (the reason is shown to the user and, when refused, returned to the model: redacted)
        what = secrets.redact(f"undo '{entry['summary']}': {undo.describe(entry)}") if entry else \
            "undo reverts the last change"
    except Exception:  # noqa: BLE001 - a hand-edited or damaged journal entry: the child reports it
        what = "undo reverts the last change"
    # without --auto-approve undo stops at its approval (exit 3) - except for entries it applies without one
    if auto or entry is None or entry.get("kind") in ("info", "settings-restore"):
        return what
    return None


# Commands that, without --auto-approve, only preview (the child stops at cloudseed's approval with exit 3 before
# changing anything): their --auto-approve form is what the user approves.
def _preview_only(ns: argparse.Namespace) -> bool:
    cmd = ns.cmd
    if cmd == "destroy":
        return not (getattr(ns, "purge", False) or getattr(ns, "purge_state", False))
    if cmd == "dr":
        return getattr(ns, "dr_cmd", None) == "restore"
    if cmd == "chaos":
        return getattr(ns, "chaos_cmd", None) == "run" and bool(getattr(ns, "target", None))
    if cmd == "node":
        return getattr(ns, "node_cmd", None) in ("add", "remove", "scale")
    if cmd == "platform":   # uninstall prints the removal list, then stops at its approval; install and ui can change
        return getattr(ns, "platform_cmd", None) == "uninstall"   # things without one (no cloud prerequisite, no UI deps)
    return False


_SUB_GATES = {"vpn": ("vpn_cmd", {"revoke", "add-user", "provision"}), "node": ("node_cmd", {"add", "remove", "scale"}),
              "platform": ("platform_cmd", {"install", "uninstall", "ui"}), "chaos": ("chaos_cmd", {"run", "stop"}),
              "dr": ("dr_cmd", {"backup", "restore", "schedule", "test"})}
_SUB_WHY = {"vpn add-user": "issues a VPN client certificate: network access to the environment",
            "vpn provision": "installs and configures the VPN server with root Ansible on the VPN host",
            "vpn revoke": "revokes a VPN client certificate",
            "dr restore": "restores a backup into the cluster; with --auto-approve it may also install Velero and "
                          "create its bucket and identity",
            "chaos run": "injects faults into the cluster"}


def _approval_reason(ns: argparse.Namespace | None) -> str | None:
    """Why this command needs the user's approval, or None when it only reads, plans or previews."""
    if ns is None:
        return None
    cmd = ns.cmd
    auto = bool(getattr(ns, "auto_approve", False))
    if getattr(ns, "purge", False) or getattr(ns, "purge_state", False):
        return "destroys infrastructure; --purge/--purge-state also delete local/remote state"
    if cmd == "destroy":
        return "destroys infrastructure" if auto else None   # without --auto-approve: a preview (exit 3)
    if cmd == "undo":
        return _undo_reason(ns, auto)
    if cmd == "vpn" and getattr(ns, "vpn_cmd", None) in ("connect", "disconnect"):
        return f"vpn {ns.vpn_cmd} changes this machine's network; it may also install the OpenVPN client"
    if cmd == "ops":
        from . import operations
        if ns.ops_cmd == "list":
            return None
        params = operations.parameters(ns)
        if operations.OPERATIONS[ns.ops_cmd].changing(params):
            return operations.OPERATIONS[ns.ops_cmd].description
        return None
    if cmd == "provision":
        return "provision runs Ansible as root on the environment's hosts"
    if cmd == "scan" and getattr(ns, "scan_cmd", None) not in ("architecture", "fips", "reports"):
        return f"scan {getattr(ns, 'scan_cmd', None) or 'all'} runs cluster jobs or Ansible as root on the hosts"
    if cmd in _SUB_GATES:
        attr, verbs = _SUB_GATES[cmd]
        sub = getattr(ns, attr, None)
        if sub in verbs and (auto or not _preview_only(ns)):
            return f"{cmd} {sub} " + _SUB_WHY.get(f"{cmd} {sub}", "changes the environment")
    if auto:
        return "--auto-approve applies changes"
    if cmd in ("kubectl", "helm"):
        return kube_approval(cmd, list(getattr(ns, "tool_args", None) or []), bool(getattr(ns, "tool_verbatim", False)))
    if cmd in ("databricks", "snowflake"):
        # stricter than MCP on purpose: only status/test run unasked (a vendor CLI's own verbs are not checked here)
        words = [w for w in (getattr(ns, "svc_args", None) or []) if not w.startswith("-")]
        if words and words[0] not in ("status", "test"):
            return f"{cmd} {words[0]} runs a {cmd} CLI command"
    return None


def guard(args: list[str]) -> str | None:
    """Return a refusal message for disallowed invocations, else None."""
    try:
        _parse(args)
    except _Refused as e:
        return str(e)
    return None


def is_destructive(args: list[str]) -> bool:
    """Does this command need the user's approval? (Unparseable commands count as destructive.)"""
    try:
        ns, _ = _parse(args)
    except _Refused:
        return True
    return _approval_reason(ns) is not None


def _allow_unattended() -> bool:
    return secrets.env_flag("CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE")


class _Capture:
    """What the model gets back from a command: all of its output when short, else the first and the last
    `limit // 2` characters. Memory stays bounded however much a command prints."""

    def __init__(self, limit: int):
        self.half = max(1, limit // 2)
        self.limit = limit
        self.head = ""
        self.tail: collections.deque = collections.deque()
        self.tail_len = 0
        self.dropped = False

    def add(self, text: str) -> None:
        room = self.half - len(self.head)
        if room > 0:
            self.head += text[:room]
            text = text[room:]
        if not text:
            return
        self.tail.append(text)
        self.tail_len += len(text)
        while self.tail and self.tail_len - len(self.tail[0]) >= self.half:
            self.tail_len -= len(self.tail.popleft())
            self.dropped = True

    def text(self) -> str:
        tail = "".join(self.tail)
        if self.dropped or len(self.head) + len(tail) > self.limit:
            return self.head + "\n...[truncated]...\n" + tail[-self.half:]
        return self.head + tail


def _echo(line: str) -> None:
    """Show a line of the command's output to the user while it runs (the model gets it when the command ends)."""
    try:
        sys.stdout.write(ui.dim("    " + line.rstrip("\n")) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


def _stop_child(proc: subprocess.Popen, interrupted: bool) -> None:
    """Stop the running command when the agent itself is stopped. After Ctrl-C (which the command received too) it
    gets time to stop on its own - Terraform finishes the calls in flight and releases its state lock; a second
    Ctrl-C, or SIGTERM/SIGHUP, stops it now (cloudseed passes SIGTERM on to Terraform as an interrupt)."""
    if proc.poll() is not None:
        return
    try:
        if interrupted:
            ui.warn("Waiting for the running cloudseed command to stop (Ctrl-C again to stop it now).")
            try:
                proc.wait(120)
                return
            except subprocess.TimeoutExpired:
                pass
        proc.terminate()
        try:
            proc.wait(30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)
    except (OSError, subprocess.TimeoutExpired):
        pass
    except BaseException:   # a second Ctrl-C or signal while waiting: stop it now (the caller re-raises the first)
        try:
            proc.kill()
        except OSError:
            pass


def _run_child(cmd: list[str], env: dict) -> tuple[int, str]:
    """Run one cloudseed command: its output (stdout and stderr, in order) is redacted line by line, shown to the
    user as it arrives, and returned for the model (bounded, see _Capture). stdin is closed: nothing can prompt."""
    proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors="replace", bufsize=1)
    cap = _Capture(MAX_OUTPUT)
    red = secrets.StreamRedactor()
    quiet = threading.Event()   # set when the command is over but something it started still holds the pipe

    def pump() -> None:
        try:
            for line in proc.stdout:
                if quiet.is_set():
                    continue      # keep draining so a left-behind process never blocks on a full pipe
                shown = red.feed(line)
                if shown:
                    cap.add(shown)
                    _echo(shown)
        except (OSError, ValueError):
            pass
        finally:
            with contextlib.suppress(OSError):
                proc.stdout.close()

    reader = threading.Thread(target=pump, name="cloudseed-agent-output", daemon=True)
    reader.start()
    try:
        rc = proc.wait()
    except BaseException as e:   # Ctrl-C, or SIGTERM/SIGHUP raised as SystemExit (secrets.exit_on_signals)
        _stop_child(proc, isinstance(e, KeyboardInterrupt))
        raise
    reader.join(DRAIN_SECONDS)
    quiet.set()
    return rc, cap.text()


_VAR_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_CREDS_WORDS = ("list", "set", "unset", "clear")
_CREDS_OPTIONS = ("--engine", "--forget", "--help", "--runtime", "--yes")   # what `cs creds` accepts after the command


def _creds_option_choices(name: str) -> tuple[str, ...] | None:
    """The choices of the global option (--runtime / --engine) `name` stands for - argparse also takes an unambiguous
    prefix (`--run local`) - or None for any other word."""
    from . import cli
    hits = [o for o in _CREDS_OPTIONS if o.startswith(name)] if name.startswith("--") and len(name) > 2 else []
    return cli._GLOBAL_VALUED.get(name if name in hits else hits[0] if len(hits) == 1 else "")


def _creds_args(words: list[str]) -> list[tuple[str, str]]:
    """The words after `creds`, each with what it is, so that no value in them is ever repeated: "word" (the action or
    an option; the value of --runtime / --engine too, one of their fixed choices), "name" (a variable name), "name=" /
    "opt=" (a KEY=VALUE or --opt=VALUE: the value cut off) and "value" (a bare value, cut: the word is empty). After
    `set`, a bare word that follows a bare name is that name's value (`creds set KEY value`; the CLI would take both for
    names and ask for each) - whatever it looks like."""
    out: list[tuple[str, str]] = []
    action, after_name, choices = None, False, None
    for w in words:
        name, eq, _value = w.partition("=")
        if choices is not None:     # the word after --runtime / --engine: its value (anything else is refused by the CLI)
            out.append((w, "word") if w in choices else ("", "value"))
            choices = None
            continue
        if w.startswith("-"):
            valued = _creds_option_choices(name)
            if valued and eq:
                out.append((w, "word") if _value in valued else (name, "opt="))
            elif valued:
                out.append((w, "word"))
                choices = valued
            else:
                out.append((name, "opt=") if eq else (w, "word"))
            continue
        if action is None and w in _CREDS_WORDS:
            action = w
            out.append((w, "word"))
            continue
        key = name if eq else w
        if _VAR_NAME.fullmatch(key.upper()) and not (action == "set" and not eq and after_name):
            out.append((key, "name=" if eq else "name"))
            after_name = not eq
            continue
        out.append(("", "value"))
        after_name = False
    return out


def _human_command(final: list[str]) -> str:
    """A refused command as the user is to run it: without -y, and for the vault only its action, options and variable
    names (upper case, as the vault stores them) - a value the model put there is never repeated (`creds set KEY`
    prompts for it, hidden)."""
    words = [w for w in final if w not in ("-y", "--yes")]
    if words[:1] == ["creds"]:
        words = ["creds"] + [w.upper() if what.startswith("name") else w
                             for w, what in _creds_args(words[1:]) if what in ("word", "name", "name=")]
    return "cloudseed " + " ".join(shlex.quote(w) for w in words)


def _shown_args(args: str) -> str:
    """A tool call's arguments as the user may see them: redacted (the model writes them) and bounded. For the
    vault (`creds set KEY VALUE`) only variable names are shown: a stored value is a plain word no pattern recognises."""
    text = secrets.redact(str(args))
    try:
        words = shlex.split(text)
    except ValueError:            # (an unclosed quote: shown as typed, still without the vault's values)
        words = text.split()
    if "creds" in words[:3]:
        i = words.index("creds") + 1
        shown = [secrets.REDACTED if what == "value" else shlex.quote(w) + ("=" + secrets.REDACTED if what.endswith("=")
                                                                           else "")
                 for w, what in _creds_args(words[i:])]
        text = " ".join([shlex.quote(w) for w in words[:i]] + shown)
    text = text.replace("\n", " ")
    return text if len(text) <= 200 else text[:199] + "…"


_PREVIEW_HINT = ("PREVIEW ONLY: nothing was changed. To go ahead, run the same command again with --auto-approve; "
                 "that asks the user for approval.")


def run_tool(args: str, launcher_cmd: list[str], child_env: dict) -> str:
    """One run_cloudseed tool call: parse and check it, ask the user when it needs approval, run it, and return what
    the model gets back. Every call that is not run is shown to the user too (with the reason), never only to the model."""
    try:
        argv = shlex.split(args)
    except ValueError as e:
        ui.warn(f"Agent command not run (unparseable): cloudseed {_shown_args(args)}")
        return f"ERROR: could not parse arguments: {e}"
    try:
        ns, final = _parse(argv)
    except _Refused as e:
        ui.warn(f"Refused agent command: cloudseed {_shown_args(args)}  - {secrets.redact(str(e))}")
        return f"REFUSED: {e}"
    reason = _approval_reason(ns)
    shown = secrets.redact(" ".join(shlex.quote(a) for a in final[1:]))
    if reason:
        if ui.interactive():
            print()
            ui.warn(f"The agent wants to run:  cloudseed {shown}   ({reason})")
            if not ui.confirm("Allow it?", default=False):   # (the answer is echoed by the prompt itself)
                return "USER DECLINED: the user did not approve this command. Ask what they want instead."
        elif not _allow_unattended():
            ui.warn(f"Refused (needs your approval, and there is no terminal to ask on): cloudseed {shown}  ({reason}). "
                    "Run it yourself, or set CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE=1 to let the agent run such commands "
                    "unattended.")
            return (f"REFUSED: this needs a human ({reason}). Re-run with a terminal attached, or set "
                    "CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE=1 to allow such commands non-interactively.")
    print(ui.dim(f"  ⚙ cloudseed {shown}"), flush=True)
    rc, out = _run_child(launcher_cmd + final, child_env)
    result = f"exit code: {rc}\n{secrets.redact(out)}"
    if rc == 3 and ns is not None and not getattr(ns, "auto_approve", False) and hasattr(ns, "auto_approve"):
        result += "\n" + _PREVIEW_HINT   # stopped at cloudseed's own approval step: a preview
    return result


def _stop_warning(final) -> str | None:
    """Why the model's last answer is incomplete (it hit the output limit or the context window), or None."""
    reason = getattr(final, "stop_reason", None) if final is not None else None
    if reason not in ("max_tokens", "model_context_window_exceeded"):
        return None
    cut_call = any(getattr(b, "type", "") == "tool_use" for b in (getattr(final, "content", None) or []))
    return (f"The model's answer was cut off ({reason})" + ("; its last command was NOT run" if cut_call else "") +
            ". Re-run the task, or split it into smaller steps.")


def run(prompt: str, model: str | None, task: str) -> int:
    ensure_sdk()
    import anthropic
    from anthropic import beta_tool

    if not has_api_credentials():
        raise ui.Abort(no_creds_msg())
    model = model or DEFAULT_MODEL
    # Child commands are started by this process (not by the model), so they get the real environment; everything
    # they print is redacted (CLOUDSEED_REDACT) and redacted again below before the model sees it.
    secrets.set_strict(True)
    secrets.register_env_secrets()
    child_env = {k: v for k, v in os.environ.items() if k not in ("CLOUDSEED_AGENT_ALLOW_DESTRUCTIVE",)}
    # PYTHONUNBUFFERED: the child writes to a pipe, and its output is shown while it runs
    child_env.update({"CLOUDSEED_AGENT": "builtin", "CLOUDSEED_REDACT": "1", "NO_COLOR": "1", "PYTHONUNBUFFERED": "1"})
    launcher = str(paths.REPO_ROOT / "bin" / "cloudseed") if not paths.IS_BUNDLE else sys.executable
    launcher_cmd = [launcher] if paths.IS_BUNDLE else [sys.executable, launcher]

    @beta_tool
    def run_cloudseed(args: str) -> str:
        """Run one cloudseed CLI command on the user's machine and return its (redacted) output.

        Args:
            args: Everything after `cloudseed`, e.g. "status aws --env dev" or
                  "setup aws --env dev --region us-west-2". Commands run non-interactively (no -y needed).
                  Spell options out in full. Commands that take --auto-approve only preview without it (exit
                  code 3, nothing changed); with it, and for the other changes that need approval, the user is
                  asked first (without a terminal they are refused).
        """
        return run_tool(args, launcher_cmd, child_env)

    kwargs: dict = {}
    if not model.startswith(_NO_ADAPTIVE_THINKING):
        kwargs["thinking"] = {"type": "adaptive"}
    if model.startswith(("claude-opus-5", "claude-fable-5-1")):
        # Server-side refusal fallback: a policy decline re-runs on a fallback model inside the same call.
        kwargs["betas"] = ["server-side-fallback-2026-07-01"]
        kwargs["extra_body"] = {"fallbacks": "default"}
    # a profile that is selected but broken (bad file, bad pointer) raises this, at construction or at request time
    cred_errors = tuple(e for e in (getattr(anthropic, "CredentialsError", None),) if isinstance(e, type))

    try:
        client = anthropic.Anthropic()
        with secrets.exit_on_signals():   # SIGTERM/SIGHUP stop the running command too, not just this process
            runner = client.beta.messages.tool_runner(
                model=model,
                max_tokens=16000,
                system=[{"type": "text", "text": system_prompt(task), "cache_control": {"type": "ephemeral"}}],
                tools=[run_cloudseed],
                messages=[{"role": "user", "content": prompt}],
                **kwargs,
            )
            final = None
            for message in runner:
                final = message
                for block in message.content:
                    if block.type == "text" and block.text.strip():
                        print(block.text.strip())
                        print()
        if final is not None and final.stop_reason == "refusal":
            ui.warn("The model declined this request (safety refusal).")
            return 2
        cut = _stop_warning(final)
        if cut:
            ui.warn(cut)
            return 1
        return 0
    except anthropic.AuthenticationError:
        ui.err("Anthropic rejected the API credentials (401). Check or replace ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN "
               "(cloudseed creds set ANTHROPIC_API_KEY) or your `ant auth login` profile - or use your logged-in Claude Code "
               "instead: cloudseed use claude")
        return 1
    except cred_errors as e:
        ui.err(f"The Anthropic credentials could not be used: {secrets.redact(str(e))}\n"
               f"Profiles live in {anthropic_config_dir()} (ANTHROPIC_PROFILE / active_config choose one). Fix it with "
               "`ant auth login`, or set ANTHROPIC_API_KEY.\n" + no_creds_msg(headline=False))
        return 1
    except TypeError as e:  # SDK raises TypeError when it cannot find any credential source
        if "authentication" in str(e).lower():
            ui.err(no_creds_msg())
            return 1
        raise
    except anthropic.RateLimitError:
        ui.err("Anthropic rate limit hit; try again shortly.")
        return 1
    except anthropic.APIStatusError as e:
        ui.err(f"Anthropic API error {e.status_code}: {secrets.redact(str(e))}")
        return 1
    except anthropic.APIConnectionError as e:
        ui.err(f"Could not reach the Anthropic API: {e}")
        return 1
