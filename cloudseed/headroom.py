"""Managed Headroom lossless proxy, isolated to one agent invocation.

This is the real headroom-ai proxy, not the deterministic context brief. We
never run `headroom wrap`, change an agent's global configuration, or give the
proxy cloud/model credentials. Authorization arrives on the client's request.
Headroom exempts loopback from token authentication: this is a same-user local
process boundary, not a defence against other processes on the machine.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import deps, paths, ui

VERSION = "0.39.1"
PACKAGE = "headroom-ai[proxy]==" + VERSION
SUPPORTED = ("builtin", "claude", "codex")
VENV = paths.HOME / "venv-headroom"
START_TIMEOUT = 60.0


def _python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _fingerprint() -> tuple:
    files = [_python(), VENV / "pyvenv.cfg"]
    files += sorted(VENV.glob("lib/python*/site-packages/headroom_ai-*.dist-info/METADATA"))
    files += sorted(VENV.glob("Lib/site-packages/headroom_ai-*.dist-info/METADATA"))
    return tuple((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in files if p.exists())


@functools.lru_cache(maxsize=4)
def _installed_version(fingerprint: tuple) -> tuple:
    if not _python().is_file():
        return None, "Headroom is not installed; run cloudseed enable headroom."
    try:
        check = subprocess.run(
            [str(_python()), "-I", "-c", "import importlib.metadata as m; import fastapi, uvicorn; "
             "import headroom._core; print(m.version('headroom-ai'))"],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "The managed Headroom interpreter could not run; reinstall Headroom."
    if check.returncode:
        return None, "The managed Headroom dependency check failed; reinstall Headroom."
    version = check.stdout.strip()
    if version != VERSION:
        return version, f"Headroom {VERSION} is required; reinstall the managed dependency."
    return version, "Installed; the proxy starts only during supported agent sessions."


def status() -> dict:
    """Cached, credential-free dependency status; does not start a proxy."""
    try:
        version, reason = _installed_version(_fingerprint())
    except OSError:
        version, reason = None, "The managed Headroom installation is unreadable."
    return {"installed": version == VERSION, "version": version, "required_version": VERSION,
            "ready": version == VERSION, "reason": reason, "mode": "lossless",
            "supported_agents": list(SUPPORTED)}


def install() -> bool:
    """Explicit, pinned installation into Cloudseed's own virtual environment."""
    deps.refuse_install_in_agent_session("headroom")
    if VENV.is_symlink():
        raise ui.Abort("The managed Headroom directory is a symlink; refusing to modify it.")
    if status()["ready"]:
        return True
    paths.ensure_home()
    lock = paths.HOME / ".headroom-install-lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise ui.Abort("Another Headroom installation is in progress. If it was interrupted, remove "
                       f"{lock} and retry.", code=2) from None
    try:
        interpreter = deps.venv_python((3, 10), "Headroom")
        if not deps.venv_usable(VENV):
            # This directory is reserved for the managed dependency, never user code.
            if VENV.is_symlink():
                raise ui.Abort("The managed Headroom directory is a symlink; refusing to replace it.")
            if VENV.exists():
                shutil.rmtree(VENV)
            subprocess.run([interpreter, "-m", "venv", str(VENV)], check=True)
        os.chmod(VENV, 0o700)
        subprocess.run([str(_python()), "-m", "pip", "install", "--disable-pip-version-check", PACKAGE], check=True)
        _installed_version.cache_clear()
        if not status()["ready"]:
            raise ui.Abort(status()["reason"])
        return True
    except (OSError, subprocess.CalledProcessError):
        raise ui.Abort("Headroom installation failed. Check Python 3.10+ and package download access, then retry.") from None
    finally:
        lock.rmdir()


@dataclasses.dataclass
class Route:
    env: dict
    active: bool = False
    reason: str = "Headroom is disabled."
    base_url: str = ""
    command_args: list = dataclasses.field(default_factory=list)


def _target_url(value: str) -> str:
    """Keep the original destination; refuse URL credentials/query ambiguity."""
    try:
        parsed = urllib.parse.urlsplit(value)
        parsed.port  # Validate a malformed/out-of-range port without rebuilding the original authority.
    except ValueError:
        raise ui.Abort("Headroom cannot route the configured provider URL: invalid URL.") from None
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or "\n" in value or "\r" in value):
        raise ui.Abort("Headroom requires a provider base URL without embedded credentials, query, or fragment.")
    # The provider handlers append /v1; avoid changing the meaning of arbitrary
    # custom API prefixes without a separately verified routing contract.
    if parsed.path.rstrip("/") not in ("", "/v1"):
        raise ui.Abort("Headroom does not yet support this provider URL path. Use --no-headroom to preserve it.")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1", "localhost"):
        raise ui.Abort("Headroom requires HTTPS for remote provider endpoints.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _proxy_env(directory: Path, source: dict) -> dict:
    # Never inherit model/cloud credentials, Python import hooks, provider
    # targets, telemetry exporters, or user Headroom settings. TLS/proxy network
    # settings retain the user's approved network path, without model auth.
    allow = ("PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
             "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
             "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy")
    env = {k: source[k] for k in allow if k in source}
    env.update({
        # Scope the child's home as well as documented config roots: optional
        # provider integrations must not discover the operator's credentials.
        # This does not modify Cloudseed's or the agent client's environment.
        "HOME": str(directory), "USERPROFILE": str(directory),
        "HEADROOM_WORKSPACE_DIR": str(directory / "state"),
        "HEADROOM_CONFIG_DIR": str(directory / "config"),
        "HEADROOM_SETTINGS_PATH": str(directory / "settings.json"),
        "CLAUDE_CONFIG_DIR": str(directory / "claude"),
        "ANTHROPIC_CONFIG_DIR": str(directory / "anthropic"),
        "HEADROOM_STATELESS": "true", "HEADROOM_BEACON": "off", "DO_NOT_TRACK": "1",
        "HEADROOM_TELEMETRY": "off", "HEADROOM_UPDATE_CHECK": "off", "HEADROOM_OFFLINE": "1",
        "HEADROOM_SKIP_UPSTREAM_CHECK": "1", "HEADROOM_LOSSLESS_ONLY": "1",
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HOME": str(directory / "hf"),
        "XDG_CACHE_HOME": str(directory / "cache"), "XDG_CONFIG_HOME": str(directory / "config"),
        "PYTHONUNBUFFERED": "1", "NO_COLOR": "1",
    })
    return env


def _read_health(base: str) -> dict:
    # Bypass user HTTP proxies for our owned loopback process.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base + "/health", timeout=1) as response:
        raw = response.read(131073)
    if len(raw) > 131072:
        raise ValueError("oversized health response")
    return json.loads(raw)


def _wait_ready(process, base: str) -> None:
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ui.Abort("Headroom exited before becoming ready. Reinstall Headroom or use --no-headroom.")
        try:
            health = _read_health(base)
            if (health.get("service") == "headroom-proxy" and health.get("version") == VERSION
                    and health.get("ready") is True and health.get("config", {}).get("pid") == process.pid
                    and health.get("config", {}).get("optimize") is True
                    and health.get("rust_core") == "loaded"):
                return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise ui.Abort("Headroom did not become ready within 60 seconds. Use --no-headroom to run without compression.")


def _stop(process) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)
    except ProcessLookupError:
        pass


@contextlib.contextmanager
def session(agent: str, env: dict, enabled: bool = True, *, upstream_url: str | None = None):
    """Own exactly one proxy, with cleanup on errors, cancellation and normal exit.

    Codex callers must additionally verify that the selected provider is the
    standard OpenAI provider. Subscription/custom-provider routing is not yet
    validated here; an explicit API key is required for this initial adapter.
    """
    route = Route(dict(env))
    if not enabled:
        yield route
        return
    if agent not in SUPPORTED:
        route.reason = f"Headroom routing is not supported for {agent}; the agent uses its original connection."
        yield route
        return
    if agent == "codex" and (not str(env.get("CODEX_API_KEY", "")).strip()
                            or any(env.get(k) for k in ("OPENAI_FEDERATION_RULE_ID", "OPENAI_IDENTITY_TOKEN_FILE", "CODEX_ACCESS_TOKEN"))):
        route.reason = "Headroom's Codex adapter requires explicit CODEX_API_KEY without federated/access-token authentication."
        yield route
        return
    if agent == "claude" and any(env.get(k, "").lower() in ("1", "true") for k in
                                 ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")):
        route.reason = "Headroom's Claude adapter supports direct Anthropic API routing; this cloud-provider mode is unsupported."
        yield route
        return
    ready = status()
    if not ready["ready"]:
        raise ui.Abort(ready["reason"], code=2)
    anthropic = agent in ("builtin", "claude")
    original = upstream_url or env.get("ANTHROPIC_BASE_URL" if anthropic else "OPENAI_BASE_URL")
    target = _target_url(original or ("https://api.anthropic.com" if anthropic else "https://api.openai.com"))
    paths.ensure_home()
    with tempfile.TemporaryDirectory(prefix="headroom-session-", dir=str(paths.HOME)) as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        route.base_url = f"http://127.0.0.1:{port}"
        cmd = [str(_python()), "-I", "-m", "headroom.cli", "proxy", "--host", "127.0.0.1", "--port", str(port),
               "--workers", "1", "--mode", "cache", "--stateless", "--no-telemetry", "--no-subscription-tracking",
               "--no-learn", "--lossless", "--disable-kompress", "--disable-kompress-fallback", "--no-rate-limit",
               "--protect-tool-results", "run_cloudseed,Bash,bash,exec_command,shell,shell_command",
               "--no-cache", "--anthropic-api-url" if anthropic else "--openai-api-url", target]
        process = None
        try:
            # No raw provider/model payloads or credentials ever enter a durable log.
            proxy_env = _proxy_env(directory, env)
            if agent == "codex" and env.get("CODEX_CA_CERTIFICATE"):
                # Codex's dedicated CA bundle takes precedence over SSL_CERT_FILE.
                # HTTPX in the proxy understands the latter, so preserve trust
                # through the transport change without disabling verification.
                proxy_env["SSL_CERT_FILE"] = env["CODEX_CA_CERTIFICATE"]
            process = subprocess.Popen(cmd, cwd=str(directory), env=proxy_env,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=os.name == "posix")
            _wait_ready(process, route.base_url)
            route.active = True
            route.reason = "Headroom lossless proxy is active for this session; savings depend on eligible content."
            route.env["ANTHROPIC_BASE_URL" if anthropic else "OPENAI_BASE_URL"] = route.base_url + ("" if anthropic else "/v1")
            # Only the agent-to-Headroom hop bypasses HTTP(S) proxies. The
            # owned proxy retains the original upstream proxy configuration.
            exclusions = [part.strip() for key in ("NO_PROXY", "no_proxy")
                          for part in env.get(key, "").split(",") if part.strip()]
            exclusions += ["127.0.0.1", "localhost", "::1"]
            local_bypass = ",".join(dict.fromkeys(exclusions))
            route.env["NO_PROXY"] = route.env["no_proxy"] = local_bypass
            if agent == "codex":
                route.command_args = ["--config", "openai_base_url=" + json.dumps(route.base_url + "/v1")]
            yield route
        except OSError:
            raise ui.Abort("Could not start the managed Headroom proxy. Reinstall Headroom or use --no-headroom.") from None
        finally:
            _stop(process)
