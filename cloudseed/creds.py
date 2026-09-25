"""Local credential vault: cloud / agent / service secrets the user enters once (CLI or web UI) and every cloudseed
command inherits. Stored in ~/.cloudseed/credentials.json (0600), injected into the process environment at start
(never overriding variables already exported), never printed (only masked hints), never sent anywhere."""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

from . import paths

STORE = paths.HOME / "credentials.json"
GCP_FILE = paths.HOME / "gcp-credentials.json"   # a pasted GOOGLE_CREDENTIALS key, materialised for the SDKs

# key -> (group, label, kind) ; kind: secret | text | path | json
KNOWN: dict[str, tuple[str, str, str]] = {
    "AWS_PROFILE": ("aws", "AWS CLI profile (from ~/.aws/config)", "text"),
    "AWS_ACCESS_KEY_ID": ("aws", "AWS access key id", "text"),
    "AWS_SECRET_ACCESS_KEY": ("aws", "AWS secret access key", "secret"),
    "AWS_SESSION_TOKEN": ("aws", "AWS session token (temporary credentials)", "secret"),
    "AWS_DEFAULT_REGION": ("aws", "AWS default region", "text"),
    "GOOGLE_APPLICATION_CREDENTIALS": ("gcp", "Path to a service-account key file (or paste the JSON below)", "path"),
    "GOOGLE_CREDENTIALS": ("gcp", "Service-account key JSON", "json"),
    "GOOGLE_PROJECT": ("gcp", "Default GCP project", "text"),
    "ARM_SUBSCRIPTION_ID": ("azure", "Azure subscription id", "text"),
    "ARM_TENANT_ID": ("azure", "Azure tenant id", "text"),
    "ARM_CLIENT_ID": ("azure", "Service principal client id", "text"),
    "ARM_CLIENT_SECRET": ("azure", "Service principal secret", "secret"),
    "ANTHROPIC_API_KEY": ("agents", "Anthropic API key (built-in agent, kagent; Claude Code only when it has no login of "
                                    "its own)", "secret"),
    "OPENAI_API_KEY": ("agents", "OpenAI API key (Codex, litellm, kagent)", "secret"),
    "GEMINI_API_KEY": ("agents", "Gemini API key", "secret"),
    "GROK_API_KEY": ("agents", "xAI Grok API key", "secret"),
    "UBUNTU_PRO_TOKEN": ("services", "Ubuntu Pro token (FIPS mode on VMware / plain Ubuntu hosts)", "secret"),
    "TS_AUTHKEY": ("services", "Tailscale auth key (vpn_type=tailscale)", "secret"),
    "GITLAB_RUNNER_TOKEN": ("services", "GitLab runner registration token", "secret"),
    "DATABRICKS_TOKEN": ("services", "Databricks personal access token", "secret"),
    "SNOWFLAKE_PASSWORD": ("services", "Snowflake password", "secret"),
}
GROUPS = {"aws": "Amazon Web Services", "gcp": "Google Cloud", "azure": "Microsoft Azure", "agents": "AI agents",
          "services": "Services and add-ons", "custom": "Custom variables"}   # custom: any other (allowed) name
# Variables that hold a GCP project id (setup takes its default project from them): a value that cannot be one is
# refused (check_value) instead of being stored for setup to ignore later.
GCP_PROJECT_KEYS = ("GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT")

# Custom names that would change how programs start, which code they load, which config/CA/credentials file they
# read, where they send requests (proxies, API endpoints: a stored key would go to that host) or whether they check
# TLS, what they log, or cloudseed's own safety switches. Values in the vault are injected into every cloudseed process
# (Terraform, Ansible, kubectl, helm, the agents' SDKs), so these are refused (set them in your shell if you really need
# them). Names stored before a name was refused are ignored from then on (env() re-checks every name).
_DENY_EXACT = {
    "PATH", "HOME", "SHELL", "ENV", "BASH_ENV", "IFS", "PROMPT_COMMAND", "TMPDIR", "USER", "LOGNAME", "ZDOTDIR",
    "SHELLOPTS", "BASHOPTS", "PS4", "BROWSER", "MANPAGER", "NETRC", "WGETRC",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
    "SSH_ASKPASS", "SUDO_ASKPASS", "KUBECONFIG", "CLOUDSDK_PYTHON", "CLOUDSDK_PYTHON_ARGS",
    "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE",
    "TF_DATA_DIR", "TF_PLUGIN_CACHE_DIR", "TF_LOG", "TF_LOG_PATH", "TF_LOG_CORE", "TF_LOG_PROVIDER",
    "TF_REATTACH_PROVIDERS", "EDITOR", "VISUAL", "PAGER",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "ARM_METADATA_HOSTNAME",
    "AWS_SHARED_CREDENTIALS_FILE", "SSH_AUTH_SOCK", "GNUPGHOME", "GOFLAGS", "GOPROXY", "GOSUMDB", "GONOSUMDB",
    "GOTOOLCHAIN", "GOPRIVATE", "GONOPROXY",
    # gcloud / Azure CLI / Terraform's OIDC exchange: a CA file, TLS verification off, or where a request token is sent
    "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", "AZURE_CLI_DISABLE_CONNECTION_VERIFICATION", "ARM_OIDC_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    # Google's auth libraries run the command an external_account key names only with this switch on (a key file from
    # the vault could then run anything); the AWS SDKs take their credentials from the container URI (and send it their
    # token), Google's from the metadata server (like ARM_METADATA_HOSTNAME above); Azure Identity sends the client
    # secret to the authority host
    "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AZURE_AUTHORITY_HOST",
    "GCE_METADATA_HOST", "GCE_METADATA_IP", "GCE_METADATA_ROOT",
}
# Names a suffix below would refuse: switches between the provider's own endpoints (no host of your choice), and
# cloudseed's own VMWARE_HOME (where vmrun is found; the console and its jobs only see it when the vault has it)
_ALLOW_EXACT = {"AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT", "VMWARE_HOME"}
# (not "GO": GOOGLE_CREDENTIALS / GOOGLE_PROJECT are ordinary entries; "GIT_" leaves GITLAB_RUNNER_TOKEN alone)
_DENY_PREFIX = ("PYTHON", "DYLD_", "LD_", "PERL5", "PERL_", "RUBY", "GIT_", "TF_CLI_", "CLOUDSEED_",
                "NPM_CONFIG_", "BASH_FUNC_", "HELM_", "PIP_", "XDG_", "ANSIBLE_", "OPENSSL_", "SSL", "KUBECTL_",
                "KUBE_", "GCONV", "NODE_", "DOCKER_", "CURL_", "LESS", "AWS_ENDPOINT_URL", "GRPC_", "HTTPLIB2_",
                "CLOUDSDK_PROXY_", "CLOUDSDK_API_ENDPOINT_OVERRIDES_", "CLOUDSDK_AUTH_")
# _PROXY: every proxy variable (SOCKS_PROXY ...); _API_BASE: litellm / older OpenAI SDKs' endpoint (OPENAI_API_BASE);
# _UNIVERSE_DOMAIN: Google's client libraries send every request (and token) to that domain; _HOME: where a program
# loads its config and code from (CODEX_HOME holds the model provider's base_url, JAVA_HOME picks the java that runs)
_DENY_SUFFIX = ("_CONFIG_FILE", "_CONFIG_DIR", "_CONFIG", "_BASE_URL", "_ENDPOINT", "_ENDPOINT_URL", "_PROXY",
                "_API_BASE", "_UNIVERSE_DOMAIN", "_HOME")


def check_key(key: str) -> str:
    """Normalise a variable name (upper case) and return it; raise ValueError saying why a name is refused."""
    k = str(key).strip().upper()
    if k in KNOWN or k in _ALLOW_EXACT:
        return k
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", k, re.ASCII):
        raise ValueError(f"not a variable name: {key!r} (use letters, digits and _, e.g. MY_TOKEN)")
    if k in _DENY_EXACT or k.startswith(_DENY_PREFIX) or k.endswith(_DENY_SUFFIX):
        raise ValueError(f"{k} changes how programs run, which files or servers they trust, or where they send "
                         "requests; it cannot be stored in the vault (export it in your shell if you really need it)")
    return k


def check_value(key: str, value: str) -> str:
    """Raise ValueError when a value cannot be what the key needs; returns the value. A JSON-kind key
    (GOOGLE_CREDENTIALS) must hold a whole key file: a JSON object with a "type" (service_account, authorized_user,
    external_account...). A pasted file cut short (a hidden prompt reads one line: `{`) is refused here. A GCP project
    variable (GCP_PROJECT_KEYS) must hold a project id: setup ignores anything else. Callers check before anything is
    written; set_() does not, so an undo can always put back what was there."""
    k = check_key(key)
    if not str(value).strip():
        return value                     # (empty: a removal)
    if kind(k) == "json" and not _json_ok(value):
        raise ValueError(f"{k} must be the whole key file (JSON with a \"type\"); what was given is not. Paste the "
                         "file's contents again, or store its path instead: GOOGLE_APPLICATION_CREDENTIALS=/path/key.json")
    problem = value_problem(k, value)
    if problem:
        raise ValueError(problem)
    return value


def value_problem(key: str, value: str) -> str | None:
    """Why a stored (or to-be-stored) plain value cannot be used for `key`, or None: a GCP project variable that holds
    no project id."""
    if key in GCP_PROJECT_KEYS and str(value).strip():
        from .clouds import gcp   # (the one rule setup applies)
        problem = gcp._check_project_id(str(value))
        if problem:
            return f"{key}: {problem} Setup would ignore it."
    return None


def _json_ok(value) -> bool:
    try:
        data = json.loads(value)
    except (TypeError, ValueError):
        return False
    return isinstance(data, dict) and isinstance(data.get("type"), str)


def valid_key(key: str) -> bool:
    try:
        check_key(key)
        return True
    except ValueError:
        return False


def kind(key: str) -> str:
    return KNOWN.get(key, ("", "", "secret"))[2]


def _norm_value(key: str, value: str) -> str:
    """Path-kind values are stored absolute: zsh does not expand `~` after `=`, and terraform runs in another
    directory, so `~/k.json` or `k.json` would point nowhere."""
    if kind(key) == "path" and value.strip():
        return os.path.abspath(os.path.expanduser(value.strip()))
    return value


def load() -> dict:
    try:
        data = json.loads(STORE.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_private(path: Path, text: str) -> None:
    """Replace a 0600 file atomically: an interrupted write (Ctrl-C, full disk, crash) keeps the previous contents,
    and a concurrent reader (another cloudseed process, Terraform reading the GCP key) never sees a half-written
    file. A symlinked file is written through the link, so a vault kept elsewhere stays where it is."""
    paths.atomic_write(Path(os.path.realpath(path)), text, 0o600)


def save(data: dict) -> None:
    paths.ensure_home()
    _write_private(STORE, json.dumps(data, indent=2) + "\n")


def _drop_gcp_file() -> None:
    try:
        GCP_FILE.unlink()
    except OSError:
        pass


def set_(key: str, value: str) -> str:
    """Store (or, with an empty value, remove) one variable. Returns the stored value. Raises ValueError on a
    refused name."""
    key = check_key(key)
    value = _norm_value(key, str(value))
    data = load()
    if value == "":
        data.pop(key, None)
    else:
        data[key] = value
    save(data)
    if key == "GOOGLE_CREDENTIALS" and not value:
        _drop_gcp_file()
    return value


def unset(key: str) -> bool:
    data = load()
    norm = str(key).strip().upper()
    if norm == "GOOGLE_CREDENTIALS":
        _drop_gcp_file()   # also a copy left behind when the key was removed some other way
    for k in (key, norm):
        if k in data:
            del data[k]
            save(data)
            return True
    return False


def clear() -> None:
    try:
        STORE.unlink()
    except OSError:
        pass
    _drop_gcp_file()


def env() -> dict:
    """Variables to inject into cloudseed processes (a JSON key pasted for GCP is materialised to a 0600 file).
    Names the vault refuses (e.g. written by an older version or by hand) are never injected."""
    data = load()
    out = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, str) and valid_key(k):
            out[k] = _norm_value(k, v)
    if out.get("GOOGLE_CREDENTIALS") and not out.get("GOOGLE_APPLICATION_CREDENTIALS"):
        try:
            try:
                current = GCP_FILE.read_text()
            except (OSError, ValueError):
                current = None
            # every cloudseed start comes through here: rewrite only on change, and atomically, so a Terraform run in
            # another cloudseed process never reads a truncated key file
            if current != out["GOOGLE_CREDENTIALS"]:
                _write_private(GCP_FILE, out["GOOGLE_CREDENTIALS"])
            else:
                os.chmod(GCP_FILE, 0o600)
            out["GOOGLE_APPLICATION_CREDENTIALS"] = str(GCP_FILE)
        except OSError:
            pass
    elif GCP_FILE.exists() and str(GCP_FILE) not in (out.get("GOOGLE_APPLICATION_CREDENTIALS"),
                                                     os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")):
        _drop_gcp_file()   # the pasted key was removed or replaced by a key-file path: no stale copy on disk
    return out


# Values apply()/refresh() put into os.environ, so a long-running process (web console, MCP server) can tell them apart
# from what the user's shell really exported: shell variables win, vault edits must reach the next job, and vault
# values must never be baked into a launchd plist / systemd unit as if they were shell variables.
APPLIED: dict[str, str] = {}
_LOCK = threading.RLock()


def apply() -> None:
    """Called at CLI start: saved credentials fill in what the shell did not export."""
    with _LOCK:
        for k, v in env().items():
            if k not in os.environ:
                os.environ[k] = v
                APPLIED[k] = v


def refresh() -> None:
    """Long-running processes: bring os.environ in line with the vault as it is now. Values an earlier apply() injected
    are updated or dropped (a cleared / rotated credential stops being used); shell variables are never touched."""
    with _LOCK:
        now = env()
        for k, v in list(APPLIED.items()):
            if os.environ.get(k) != v:        # changed by someone else since: no longer ours to manage
                APPLIED.pop(k, None)
            elif k not in now:
                os.environ.pop(k, None)
                APPLIED.pop(k, None)
            elif now[k] != v:
                os.environ[k] = APPLIED[k] = now[k]
        for k, v in now.items():
            if k not in os.environ:
                os.environ[k] = APPLIED[k] = v


def shell_env(base: dict | None = None) -> dict:
    """A copy of `base` (default: os.environ) without the values the vault injected: the real shell environment."""
    with _LOCK:
        out = dict(os.environ if base is None else base)
        for k, v in APPLIED.items():
            if out.get(k) == v:
                out.pop(k, None)
        return out


def _mask(value: str) -> str:
    """Fixed-length mask: never reveals the length, and only the last 4 characters of long (16+) secrets."""
    v = str(value)
    return "••••••••" + (v[-4:] if len(v) >= 16 else "")


def _json_hint(value) -> str:
    """What a stored JSON key is, without anything secret: its type (and project), or why it cannot be used. (No
    'stored ...' prefix: the list and the console already say it is stored.)"""
    try:
        data = json.loads(value)
    except (TypeError, ValueError):
        return "not valid JSON: paste the key file again"
    if not (isinstance(data, dict) and isinstance(data.get("type"), str)):
        return "not a Google key file (JSON without a \"type\"): paste the key file again"
    # (only plain words: a hand-edited file must not put control characters or a long text into the list)
    ktype = data["type"] if re.fullmatch(r"[A-Za-z0-9_-]{1,40}", data["type"]) else "unknown type"
    project = data.get("project_id") or data.get("quota_project_id")
    shown = isinstance(project, str) and re.fullmatch(r"[a-z0-9][a-z0-9.:-]{0,62}", project)
    return f"JSON key ({ktype}" + (f", project {project})" if shown else ")")


def _problem_note(key: str, value) -> str:
    return "  (not a GCP project ID: setup ignores it)" if value_problem(key, str(value)) else ""


def masked() -> list[dict]:
    """What the vault holds, for display: never the values of secrets."""
    data = load()
    shell = shell_env()
    rows = []
    for key, (group, label, knd) in KNOWN.items():
        val = data.get(key)
        if val is None:
            hint = ""
        elif knd in ("text", "path"):
            hint = str(val) + _problem_note(key, val)
        elif knd == "json":
            hint = _json_hint(val)
        else:
            hint = _mask(val)
        rows.append({"key": key, "group": group, "label": label, "kind": knd, "set": val is not None,
                     "hint": hint, "from_env": key in shell and val is None})
    for key, val in data.items():
        if key not in KNOWN:
            ok = valid_key(key)
            rows.append({"key": key, "group": "custom", "label": key, "kind": "secret", "set": True,
                         "hint": _mask(val) + _problem_note(key, val) if ok else
                         "ignored: unsafe variable name (cs creds unset " + str(key) + ")",
                         "from_env": False, **({} if ok else {"ignored": True})})
    return rows


def path_warning(key: str, value: str) -> str | None:
    """A hint when a stored value cannot be used as it is: a path-kind value that does not point at a file (the file
    may be created later), or a GCP project variable that holds no project id (`cs creds set` shows it after storing)."""
    if kind(key) == "path" and value and not Path(value).is_file():
        return f"{key} points to {value}, which does not exist (yet)."
    problem = value_problem(key, value)
    if problem:
        return f"{problem} Store the project ID (cs creds set {key}=my-proj-123) or remove it (cs creds unset {key})."
    return None
