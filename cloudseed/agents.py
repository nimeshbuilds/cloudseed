"""Agent CLI adapters (Claude Code, Codex, Gemini CLI, Grok) and model registry.

Templates can be overridden/extended in ~/.cloudseed/agents.json (same shape as DEFAULT_AGENTS; a field given there
replaces the default one, so an "exec" override keeps its own flags). Command templates: the first word is the program;
`{prompt}` and `{model}` are replaced anywhere inside a word. Without a model, a bare `{model}` word is dropped together
with the option right before it (`--model {model}`), and a word that contains `{model}` (`--model={model}`) is dropped.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import paths, secrets, ui

DEFAULT_AGENTS: dict[str, dict] = {
    "builtin": {
        "display": "Built-in agent",
        "what": "cloudseed's own agent loop, calling the Claude API directly with the official Anthropic SDK. "
                "No external CLI. Its only tool is running cloudseed commands; destructive ones ask you first.",
        "binary": None,
        "builtin": True,
        "install_hint": "nothing to install (the SDK is fetched automatically)",
        "auth": "ANTHROPIC_API_KEY (console.anthropic.com) or `ant auth login`. Without either, cloudseed falls back "
                "to your logged-in Claude Code CLI.",
        "auth_env": ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
        "auth_files": [],
        "auth_check": "anthropic",   # the SDK's own resolution (builtin_agent.has_api_credentials), not a directory
        "skills_dir": None,
        "models": ["claude-opus-5", "claude-opus-5-5", "claude-fable-5-1", "claude-sonnet-5"],
        "default_model": "claude-opus-5",
    },
    "claude": {
        "display": "Claude Code",
        "what": "Anthropic's coding agent CLI. Works with your claude.ai subscription login (no API key).",
        "binary": "claude",
        "install_hint": "npm install -g @anthropic-ai/claude-code",
        "auth": "run `claude` once and log in (subscription), or set ANTHROPIC_API_KEY",
        # login is detected with `claude auth status` (see _claude_logged_in); the files are only a fallback for
        # old CLIs. ~/.claude itself proves nothing: cloudseed's own skill install creates ~/.claude/skills.
        "auth_env": ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"],
        "auth_files": ["~/.claude/.credentials.json"],
        "auth_check": "claude",
        "skills_dir": "~/.claude/skills",
        "models": ["claude-fable-5-1", "claude-opus-5", "claude-opus-5-5", "claude-sonnet-5", "claude-haiku-4-5",
                   "claude-haiku-4-5-20251001"],
        "default_model": "claude-sonnet-5",
        # Non-interactive run. Only `cloudseed ...` shell commands are pre-approved; credential paths are denied
        # (run() appends the cloudseed secret files, resolved against CLOUDSEED_HOME, to --disallowedTools).
        "exec": ["claude", "-p", "{prompt}", "--model", "{model}",
                 "--allowedTools", "Bash(cloudseed:*),Bash(cloudseed *),Bash(cs:*),Bash(cs *)",
                 "--disallowedTools",
                 "Read(~/.aws/**),Read(~/.config/gcloud/**),Read(~/.azure/**),Read(~/.cloudseed/sessions/**),"
                 "Read(**/*.tfstate*),Bash(env:*),Bash(printenv:*),Bash(cat:*)"],
        "interactive": ["claude", "--model", "{model}", "{prompt}"],
    },
    "codex": {
        "display": "OpenAI Codex CLI",
        "what": "OpenAI's coding agent CLI (ChatGPT login or OPENAI_API_KEY).",
        "binary": "codex",
        "install_hint": "npm install -g @openai/codex",
        "auth": "run `codex login` (ChatGPT account) or set OPENAI_API_KEY",
        "auth_env": ["OPENAI_API_KEY"],
        "auth_files": ["~/.codex/auth.json"],
        "skills_dir": "~/.codex/skills",
        "models": ["gpt-5-codex", "gpt-5", "o3"],
        "default_model": "gpt-5-codex",
        # cloudseed needs network access for Terraform, so the default sandbox is widened. Adjust in agents.json.
        # --skip-git-repo-check: cloudseed needs no repository, and tasks run from anywhere (the web console: $HOME)
        "exec": ["codex", "exec", "--skip-git-repo-check", "--model", "{model}", "--sandbox", "danger-full-access",
                 "{prompt}"],
        "interactive": ["codex", "--model", "{model}", "{prompt}"],
    },
    "gemini": {
        "display": "Gemini CLI",
        "what": "Google's coding agent CLI (Google account login or GEMINI_API_KEY).",
        "binary": "gemini",
        "install_hint": "npm install -g @google/gemini-cli",
        "auth": "run `gemini` once and log in with Google, or set GEMINI_API_KEY (aistudio.google.com)",
        "auth_env": ["GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_GENAI_USE_GCA"],
        "auth_files": ["~/.gemini/oauth_creds.json", "~/.gemini/google_accounts.json"],
        "skills_dir": "~/.gemini/skills",
        "models": ["gemini-2.5-pro", "gemini-2.5-flash"],
        "default_model": "gemini-2.5-pro",
        # only the cloudseed shell command is pre-approved
        "exec": ["gemini", "-m", "{model}", "--allowed-tools", "run_shell_command(cloudseed),run_shell_command(cs)",
                 "-p", "{prompt}"],
        "interactive": ["gemini", "-m", "{model}", "-i", "{prompt}"],
    },
    "grok": {
        "display": "Grok CLI",
        "what": "Community CLI for xAI's Grok models (needs an xAI API key).",
        "binary": "grok",
        "install_hint": "npm install -g @vibe-kit/grok-cli",
        "auth": "set GROK_API_KEY (console.x.ai), or save the key once with `grok -k <key>`",
        "auth_env": ["GROK_API_KEY"],
        "auth_files": ["~/.grok/user-settings.json"],
        "auth_check": "grok",        # an apiKey inside user-settings.json (Grok writes the file without one on first start)
        "skills_dir": None,          # Grok CLI has no skills support: the skills go into each task's prompt instead
        "skills_in_prompt": True,
        "models": ["grok-4-latest", "grok-code-fast-1", "grok-3-latest", "grok-3-fast"],
        "default_model": "grok-4-latest",
        "exec": ["grok", "--model", "{model}", "--max-tool-rounds", "40", "-p", "{prompt}"],
        "interactive": ["grok", "--model", "{model}", "{prompt}"],
    },
}

AGENTS_FILE = paths.HOME / "agents.json"
_LIST_FIELDS = ("auth_env", "auth_files", "models", "exec", "interactive")
_WARNED: set = set()


def _warn_once(msg: str) -> None:
    if msg not in _WARNED:
        _WARNED.add(msg)
        ui.warn(msg)


def _clean_spec(key: str, spec: dict) -> dict:
    """Drop fields of the wrong type (with a warning) so one bad entry cannot crash every agent command."""
    out = {}
    for field, val in spec.items():
        if field in _LIST_FIELDS and not (isinstance(val, list) and all(isinstance(x, str) for x in val)):
            _warn_once(f"{AGENTS_FILE}: agent '{key}' field '{field}' must be a list of strings; ignoring it.")
            continue
        if field in ("display", "what", "install_hint", "auth", "binary", "skills_dir", "default_model") \
                and val is not None and not isinstance(val, str):
            _warn_once(f"{AGENTS_FILE}: agent '{key}' field '{field}' must be a string; ignoring it.")
            continue
        out[field] = val
    return out


def _custom_defaults(key: str, spec: dict) -> dict:
    binary = spec.get("binary") or ((spec.get("exec") or [None])[0])
    return {
        "display": key, "what": "Custom agent from agents.json.", "binary": binary,
        "install_hint": f"install `{binary}` yourself (custom agent)" if binary else "custom agent: set \"binary\" in agents.json",
        "auth": "see the agent's own docs", "auth_env": [], "auth_files": [], "models": [], "default_model": None,
        "skills_dir": None,
    }


def registry() -> dict[str, dict]:
    reg = json.loads(json.dumps(DEFAULT_AGENTS))
    try:
        text = AGENTS_FILE.read_text()
    except OSError:
        return reg
    try:
        custom = json.loads(text)
    except ValueError as e:
        _warn_once(f"Ignoring {AGENTS_FILE}: not valid JSON ({e}).")
        return reg
    if not isinstance(custom, dict):
        _warn_once(f"Ignoring {AGENTS_FILE}: expected an object of agent name -> settings.")
        return reg
    for key, spec in custom.items():
        if not isinstance(spec, dict):
            _warn_once(f"{AGENTS_FILE}: agent '{key}' must be an object; ignoring it.")
            continue
        spec = _clean_spec(key, spec)
        if key in reg:
            reg[key].update(spec)
        else:
            reg[key] = dict(_custom_defaults(key, spec), **spec)
    return reg


def get(key: str) -> dict:
    reg = registry()
    if key not in reg:
        raise ui.Abort(f"Unknown agent '{key}'. Known: {', '.join(reg)} (add more in {AGENTS_FILE}).")
    spec = dict(reg[key])
    spec["key"] = key
    return spec


def installed(spec: dict) -> str | None:
    if spec.get("builtin"):
        return "builtin"
    return shutil.which(spec["binary"]) if spec.get("binary") else None


def models(spec: dict, settings: dict) -> list[str]:
    extra = (settings.get("custom_models") or {}).get(spec["key"], [])
    return list(dict.fromkeys(list(spec.get("models", [])) + list(extra)))


def selected_model(spec: dict, settings: dict) -> str | None:
    return (settings.get("models") or {}).get(spec["key"]) or spec.get("default_model")


_CLAUDE_AUTH_CACHE: dict = {}


def _claude_login_files() -> bool:
    """Fallback for Claude Code builds without `claude auth status`: a real login leaves an account in
    ~/.claude.json (oauthAccount / primaryApiKey) or a credentials file (Linux); a bare ~/.claude.json does not."""
    try:
        data = json.loads((Path.home() / ".claude.json").read_text())
        if isinstance(data, dict) and (data.get("oauthAccount") or data.get("primaryApiKey")):
            return True
    except (OSError, ValueError):
        pass
    return (Path.home() / ".claude" / ".credentials.json").is_file()


_ANTHROPIC_KEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")


def _claude_logged_in(binary: str | None, own: bool = False) -> bool:
    """Ask Claude Code itself (`claude auth status --json`, ~0.1 s, cached for a minute). own=True: logged in by itself
    (subscription or its own stored key), not merely through an Anthropic key in the environment."""
    cache_key = (binary, str(Path.home()), own)
    hit = _CLAUDE_AUTH_CACHE.get(cache_key)
    if hit and time.time() - hit[1] < 60:
        return hit[0]
    result = None
    if binary:
        env = {k: v for k, v in os.environ.items() if not (own and k in _ANTHROPIC_KEYS)}
        try:
            proc = subprocess.run([binary, "auth", "status", "--json"], capture_output=True, text=True, timeout=10,
                                  stdin=subprocess.DEVNULL, env=env)
            try:
                data = json.loads(proc.stdout or "")
            except ValueError:
                data = None
            if isinstance(data, dict) and "loggedIn" in data:
                result = bool(data["loggedIn"])
        except (OSError, subprocess.SubprocessError):
            result = None
    if result is None:
        result = _claude_login_files()
    _CLAUDE_AUTH_CACHE[cache_key] = (result, time.time())
    return result


def _grok_key() -> bool:
    """Grok CLI stores a key given with `grok -k` as "apiKey" in ~/.grok/user-settings.json; it also writes that file,
    without a key, the first time it starts - so the file alone proves nothing."""
    try:
        data = json.loads((Path.home() / ".grok" / "user-settings.json").read_text())
    except (OSError, ValueError):
        return False
    key = data.get("apiKey") if isinstance(data, dict) else None
    return isinstance(key, str) and bool(key.strip())


def auth_ok(spec: dict) -> bool:
    """Best-effort: is the agent authenticated (env var set, logged in, or login file present)?
    An agent that lists nothing to check (custom agents) counts as ready."""
    auth_env, auth_files = spec.get("auth_env") or [], spec.get("auth_files") or []
    if any(os.environ.get(v) for v in auth_env):
        return True
    check = spec.get("auth_check")
    if check == "claude":
        return _claude_logged_in(installed(spec))
    if check == "anthropic":
        from . import builtin_agent
        return builtin_agent.has_api_credentials()
    if check == "grok":
        return _grok_key()
    for f in auth_files:
        p = Path(f).expanduser()
        try:
            if p.exists() and (p.is_file() or any(p.iterdir())):
                return True
        except OSError:
            continue
    return not auth_env and not auth_files


def readiness(spec: dict) -> tuple[bool, str]:
    """(ready, human message) covering install + auth."""
    if not installed(spec):
        return False, f"not installed  ->  {spec.get('install_hint') or 'see agents.json'}"
    if spec.get("builtin"):
        if auth_ok(spec):
            return True, "ready (API credentials found)"
        claude = get("claude")
        if installed(claude) and auth_ok(claude):
            return True, "no API key; will use your logged-in Claude Code instead"
        return False, f"no credentials  ->  {spec.get('auth', '')}"
    if not spec.get("exec"):
        return False, f"no \"exec\" command template in {AGENTS_FILE}"
    if not auth_ok(spec):
        return False, f"installed, not logged in  ->  {spec.get('auth', '')}"
    return True, "ready"


def describe(spec: dict, settings: dict) -> None:
    model = selected_model(spec, settings)
    avail = models(spec, settings)
    ok, msg = readiness(spec)
    ui.kv("Agent", f"{spec.get('display', spec['key'])} ({spec['key']})")
    ui.kv("Status", (ui.style("✔ ", "leaf", "bold") if ok else ui.style("▲ ", "seed", "bold")) + msg)
    ui.kv("Model", model or "(agent default)")
    ui.kv("Available models", ", ".join(m + (" *" if m == model else "") for m in avail) or "-")


def _home_path(p: Path | str) -> str:
    """A path as the user reads it: ~/... only when it really is under the home directory."""
    p, h = str(p), str(Path.home())
    return "~" + p[len(h):] if p.startswith(h + os.sep) else p


def _page_rows(label: str, value: str, w: int, lead: int) -> list[str]:
    """`label  value` with the value wrapped under its own column (paths split at separators, never mid-name)."""
    from . import help as helpmod
    first = " " * lead + label.ljust(7) + " "
    out = helpmod._wrap(value or "-", w, first, " " * len(first))
    if out and out[0].startswith(first):
        out[0] = " " * lead + ui.style(label.ljust(7), "muted") + " " + out[0][len(first):]
    else:                                  # a word too long for the column: the value starts on the next line
        out.insert(0, " " * lead + ui.style(label, "muted"))
    return out


def agents_page(settings: dict) -> str:
    """Overview of every agent: what it is, install/auth status, how to fix (wrapped to the terminal width)."""
    from . import help as helpmod
    w = ui.width()
    lead = 13 if w >= 60 else 4
    usage = 'cloudseed use <agent> · cloudseed agentic --agent <agent> "..."'
    if len("AGENTS  (" + usage + ")") <= w:
        lines = [ui.bold("AGENTS  (" + usage + ")"), ""]
    else:
        lines = [ui.bold("AGENTS")] + [ui.dim(x) for x in helpmod._wrap(usage, w, "  ", "    ")] + [""]
    selected = settings.get("agent")
    for key, spec in registry().items():
        spec = dict(spec, key=key)
        ok, msg = readiness(spec)
        mark = ui.style("✔", "leaf", "bold") if ok else ui.style("○", "seed")
        sel = ui.style("  ◀ selected", "brand") if key == selected else ""
        lines.append(f"  {mark} {ui.style(key.ljust(8), 'text', 'bold')} {spec.get('display', key)}{sel}")
        if spec.get("what"):
            lines += [ui.dim(x) for x in helpmod._wrap(spec["what"], w, " " * lead, " " * lead)]
        lines += _page_rows("status", msg, w, lead)
        lines += _page_rows("install", spec.get("install_hint", ""), w, lead)
        lines += _page_rows("auth", spec.get("auth", ""), w, lead)
        lines += _page_rows("models", ", ".join(spec.get("models") or []), w, lead)
        lines.append("")
    footer = f"Custom agents / template overrides: {_home_path(AGENTS_FILE)}"
    if len(footer + "   ·   cloudseed help agentic") <= w:
        lines.append(ui.dim(footer + "   ·   cloudseed help agentic"))
    else:
        lines += [ui.dim(x) for x in helpmod._wrap(footer, w, "", "  ")] + [ui.dim("More: cloudseed help agentic")]
    return "\n".join(lines)


_PLACEHOLDER = re.compile(r"\{(model|prompt)\}")


def _fill(template: list[str], prompt: str, model: str | None) -> list[str]:
    """Fill an agent command template. The first word is the program (run() puts the resolved binary there): it is
    never dropped. `{prompt}` and `{model}` are replaced anywhere inside a word, in one pass (a prompt that says
    "{model}" stays as it is). Without a model (None or ""), a bare `{model}` word is dropped together with the
    option right before it (`--model {model}`, `-m {model}`; a positional such as `run` stays), and a word that
    contains `{model}` among other text (`--model={model}`) is dropped."""
    if not template:
        return []

    def sub(tok: str) -> str:
        return _PLACEHOLDER.sub(lambda m: (model or "") if m.group(1) == "model" else prompt, tok)

    out = [sub(template[0])]
    prev_option = False   # out[-1] is an option copied verbatim from the template word right before this one
    for tok in template[1:]:
        if not model and "{model}" in tok:
            if tok == "{model}" and prev_option and len(out) > 1:
                out.pop()
            prev_option = False
            continue
        filled = sub(tok)
        out.append(filled)
        prev_option = filled == tok and tok.startswith("-")
    return out


def claude_deny_rules() -> list[str]:
    """Claude Code permission rules denying cloudseed's secret files, resolved against the real CLOUDSEED_HOME and
    custom working directories (`//` = absolute path in Claude Code rules)."""
    def rules_for(base: Path, *parts: str) -> list[str]:
        # absolute (a relative CLOUDSEED_HOME would otherwise become project-relative), plus the symlink-free
        # spelling when it differs (/tmp vs /private/tmp): the agent may reach the file by either path
        spellings = dict.fromkeys([os.path.abspath(base), os.path.realpath(base)])
        return ["Read(/" + str(Path(b, *parts)).replace("\\", "/") + ")" for b in spellings]

    home = paths.HOME
    # credentials.json: the vault; managed/: Snowflake connection files with the password; vmware.json: the vmrest
    # login; helm/: registry logins and cloudseed's copy of the Docker auths; mcp/: the MCP token and the backups of MCP
    # client configs (which carry it); envs/*/vpn: client profiles with private keys; envs/*/platform: manifests with
    # generated passwords and secrets.json
    rules = [r for parts in (("sessions", "**"), ("credentials.json",), ("gcp-credentials.json",), ("undo.json",),
                             ("undo", "**"), ("managed.json",), ("managed", "**"), ("vmware.json",), ("helm", "**"),
                             ("mcp", "**"), ("ui", "token"), ("envs", "*", "ssh", "**"), ("envs", "*", "k8s", "**"),
                             ("envs", "*", "vpn", "**"), ("envs", "*", "platform", "**"))
             for r in rules_for(home, *parts)]
    rules += ["Read(**/platform/secrets.json)", "Read(**/*.ovpn)", "Read(~/.ssh/**)", "Read(~/.kube/**)",
              "Read(~/.docker/config.json)"]
    try:
        index = json.loads(paths.WORKDIRS_INDEX.read_text())
    except (OSError, ValueError):
        index = {}
    if isinstance(index, dict):
        for wd in index.values():
            if isinstance(wd, str) and wd:
                w = Path(wd).expanduser()
                rules += (rules_for(w, "ssh", "**") + rules_for(w, "k8s", "**") + rules_for(w, "vpn", "**") +
                          rules_for(w, "platform", "**"))
    return list(dict.fromkeys(rules))


def _with_claude_denies(cmd: list[str]) -> list[str]:
    rules = ",".join(claude_deny_rules())
    for i, tok in enumerate(cmd):
        if tok in ("--disallowedTools", "--disallowed-tools") and i + 1 < len(cmd):
            cmd[i + 1] = f"{cmd[i + 1]},{rules}" if cmd[i + 1] else rules
            return cmd
        if tok.startswith(("--disallowedTools=", "--disallowed-tools=")):
            cmd[i] = f"{tok},{rules}"
            return cmd
    # `--flag=value` form: the option is variadic, so a separate value would swallow the prompt that follows
    return [cmd[0], f"--disallowedTools={rules}"] + cmd[1:]


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except OSError:
        return False


def _stop(proc: subprocess.Popen, group: bool, grace: float = 10.0) -> None:
    """Stop the agent (and, in exec mode, everything it started): SIGTERM, then SIGKILL after a grace period."""
    import signal
    try:
        os.killpg(proc.pid, signal.SIGTERM) if group else proc.terminate()
    except OSError:
        return
    deadline = time.time() + grace
    while time.time() < deadline:
        if proc.poll() is not None and not (group and _group_alive(proc.pid)):
            return
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, getattr(signal, "SIGKILL", signal.SIGTERM)) if group else proc.kill()
        proc.wait(2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _wait(proc: subprocess.Popen, group: bool = False) -> int:
    try:
        return proc.wait()
    except BaseException:   # Ctrl-C, SIGTERM/SIGHUP (raised as SystemExit by the session broker): stop the agent too
        _stop(proc, group)
        raise


def _agent_keys(spec: dict, binary: str) -> tuple[tuple, str | None]:
    """The credential variables the agent itself gets (everything else secret is parked with the session broker), and
    a note on how Claude Code is billed. An Anthropic key that only the vault supplied (`cs creds`, stored for the
    built-in agent or kagent) is not handed to Claude Code when Claude Code has its own login: it would otherwise
    bill every task to that API key instead of the user's subscription. A key exported in the shell is kept (the
    user's choice) - and when Claude Code also has a login of its own, the note says the key is what it uses."""
    keep = list(spec.get("auth_env") or [])
    if spec.get("auth_check") != "claude":
        return tuple(keep), None
    from . import creds
    present = [k for k in _ANTHROPIC_KEYS if os.environ.get(k)]
    if not present:
        return tuple(keep), None
    vault = [k for k in present if creds.APPLIED.get(k) == os.environ.get(k)]
    shell = [k for k in present if k not in vault]
    own = _claude_logged_in(binary, own=True)
    kept = tuple(k for k in keep if not (own and k in vault))
    if shell:
        names = " and ".join(shell)
        return kept, (f"Claude Code gets the {names} exported in your shell, which it uses instead of its own login "
                      f"(usage is billed to that key; unset it to use the login)." if own else None)
    if own:
        return kept, "Claude Code runs on its own login; the Anthropic key stored in the vault is not passed to it."
    return kept, "Claude Code runs on the Anthropic key stored in the vault (usage is billed to that key)."


# An agent CLI gets the prompt as one argument; Linux caps a single argument at 128 KiB.
MAX_PROMPT_CHARS = 100_000
SKILLS_INTRO = ("The cloudseed skills follow: your instructions for the `cloudseed` CLI. This agent cannot load skills "
                "by itself, so they are included here; \"the `cloudseed` skill\" is the one named cloudseed.")


def skills_prompt(task: str, prompt: str) -> str:
    """The prompt for an agent that cannot load skills from a directory (Grok): the skills the task needs (core skill
    first, an index of the others) ahead of it, trimmed to the core skill when the whole would be too long."""
    from . import skills
    room = max(12_000, MAX_PROMPT_CHARS - len(prompt) - len(SKILLS_INTRO) - 16)
    bundle = skills.prompt_bundle(task, tool="`cloudseed skill show <name>`", max_chars=room)
    return f"{SKILLS_INTRO}\n\n{bundle}\n{prompt}"


def run(spec: dict, prompt: str, model: str | None, interactive: bool, task: str = "") -> int:
    if spec.get("builtin"):
        if interactive:
            ui.warn("--interactive only applies to external agents; the built-in agent runs the task one-shot.")
        from . import builtin_agent
        return builtin_agent.run(prompt, model, task or prompt)
    binary = installed(spec)
    if not binary:
        raise ui.Abort(f"{spec.get('display', spec['key'])} is not installed. Install it with: {spec.get('install_hint', '')}")
    ok, msg = readiness(spec)
    if not ok:
        raise ui.Abort(f"{spec.get('display', spec['key'])} is {msg}")
    template = spec.get("interactive") if interactive else spec.get("exec")
    if not template:
        raise ui.Abort(f"Agent '{spec['key']}' has no \"{'interactive' if interactive else 'exec'}\" template in {AGENTS_FILE}.")
    if spec.get("skills_in_prompt"):
        from . import headliner
        if task and prompt == headliner.plain(task):   # the brief-less prompt, worded for an agent that loads skills
            prompt = headliner.plain(task, skills_in_prompt=True)
    prompt = secrets.redact(prompt)
    if spec.get("skills_in_prompt"):
        prompt = skills_prompt(task or prompt, prompt)
    cmd = _fill(template, prompt, model)
    cmd[0] = binary      # (the first word of a template is the program; _fill never drops it)
    if Path(binary).name == "claude" or spec.get("auth_check") == "claude":
        cmd = _with_claude_denies(cmd)
    keep, auth_note = _agent_keys(spec, binary)
    if auth_note:
        print(ui.dim(f"  {auth_note}"))
    sid, env = secrets.open_session(keep=keep)
    env["CLOUDSEED_AGENT"] = spec["key"]
    if not paths.IS_BUNDLE:
        env["PATH"] = os.pathsep.join([str(paths.REPO_ROOT / "bin"), env.get("PATH", "")])
    extra = ", skills in the prompt" if spec.get("skills_in_prompt") else ""
    print(ui.dim(f"$ {spec.get('binary') or cmd[0]} ... ({'interactive' if interactive else 'exec'} mode, "
                 f"model={model or 'default'}{extra})"))
    try:
        # exec mode: no stdin (Claude Code otherwise waits for piped input); interactive mode keeps the terminal
        # exec mode runs in its own process group so everything the agent started can be stopped with it;
        # interactive mode stays in the terminal's foreground group (it needs the keyboard)
        group = not interactive and os.name == "posix"
        return _wait(subprocess.Popen(cmd, env=env, stdin=None if interactive else subprocess.DEVNULL,
                                      start_new_session=group), group)
    finally:
        secrets.close_session(sid)
