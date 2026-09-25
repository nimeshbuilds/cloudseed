"""Credential hygiene for the agentic layer.

Two guarantees:
  * redact(): scrubs anything that looks like a secret from text before it reaches an agent/LLM, a log or the web
    console (token formats, private keys, URL passwords, key=value / "key": "value" pairs, secrets named on another
    line of YAML/JSON output such as Kubernetes Secret data and env name/value pairs, and the literal values held in
    the credential vault). StreamRedactor / RedactingWriter do the same for line-by-line output, including
    multi-line private keys.
  * session broker: `cloudseed agentic` strips credential env vars from the agent's environment. Child `cloudseed`
    processes get them back from a per-session broker owned by the `cloudseed agentic` process: a private unix socket
    (nothing on disk, gone when the session ends) or, where unix sockets are unavailable, a 0600 session file that
    is deleted when the session ends (also on SIGTERM/SIGHUP) and swept when its owner died.
    Limit: an agent with a shell runs as the same user and can reach whatever that user can; the broker keeps
    secrets out of the agent's environment and off disk, it is not a sandbox.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
import json
import os
import re
import secrets as _secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import paths

REDACTED = "[REDACTED]"

# ------------------------------------------------------------------------------------------------ env classification

# Env vars that hold credentials (never handed to an agent process).
SECRET_ENV_EXACT = {
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
    "GOOGLE_CREDENTIALS", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "ARM_CLIENT_SECRET", "ARM_CLIENT_CERTIFICATE_PASSWORD", "ARM_ACCESS_KEY", "ARM_SAS_TOKEN", "AZURE_CLIENT_SECRET",
    "TF_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "TS_AUTHKEY", "TAILSCALE_AUTHKEY", "UBUNTU_PRO_TOKEN",
}
SECRET_ENV_PATTERNS = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|PASSCODE|PRIVATE_KEY|API_KEY|APIKEY|CREDENTIALS)"
    r"|_(PASS|PWD)$"
    r"|(^|_)(AUTHKEY|AUTH_KEY|WEBHOOK|WEBHOOK_URL|DSN|CONNECTION_STRING|SAS|SAS_URL|ACCESS_KEY|ACCOUNT_KEY|CERT_KEY|"
    r"CERTIFICATE_KEY)(_|$)"
    r"|(^|_)(DATABASE|DB|MONGO|MONGODB|REDIS|POSTGRES|POSTGRESQL|MYSQL|AMQP)_UR[LI]$", re.I)


def is_secret_env(name: str) -> bool:
    return name in SECRET_ENV_EXACT or bool(SECRET_ENV_PATTERNS.search(name))


def _vault_secret_keys() -> set:
    """Names the credential vault classifies as secrets: every non-text KNOWN key (stored or not) and every custom
    key stored in the vault. They are parked even when their name does not look secret (TS_AUTHKEY, MY_DB_PASS...)."""
    from . import creds
    keys = {k for k, (_g, _l, kind) in creds.KNOWN.items() if kind != "text"}
    try:
        keys |= {k for k in creds.load() if creds.KNOWN.get(k, ("", "", "secret"))[2] != "text"}
    except Exception:  # noqa: BLE001 - a broken vault must never stop the broker
        pass
    return keys


# ------------------------------------------------------------------------------------------------ redaction

_TOKEN_PATTERNS = [
    # (bounded: a real key block is a few KB; an unbounded lazy scan is quadratic on many BEGIN markers)
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V\d)-----.{0,16384}?"
               r"-----END (?:[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V\d)-----", re.S),
    re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),                    # AWS access key id
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),        # JWT
    re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])"),                              # Google API key
    re.compile(r"(?<![\w-])sk-ant-[A-Za-z0-9_-]{20,}"),                                   # Anthropic
    re.compile(r"(?<![\w-])sk-[A-Za-z0-9_-]{20,}"),                                       # OpenAI-style
    re.compile(r"(?<![\w-])xai-[A-Za-z0-9_-]{20,}"),                                      # xAI
    re.compile(r"(?<![\w-])gh[pousr]_[A-Za-z0-9]{20,}"),                                  # GitHub
    re.compile(r"(?<![\w-])github_pat_[A-Za-z0-9_]{22,}"),                                # GitHub fine-grained PAT
    re.compile(r"(?<![\w-])gl(?:pat|rt|dt|ptt|cbt|soat)-[A-Za-z0-9_-]{20,}"),             # GitLab
    re.compile(r"(?<![\w-])xox[baprs]-[A-Za-z0-9-]{10,}"),                                # Slack token
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),                    # Slack webhook
    # Google OAuth access token: user tokens (ya29.a0...) and service-account / metadata tokens (ya29.c.c0...), whose
    # body has dots; a sentence's final period is not part of it
    re.compile(r"(?<![\w-])ya29\.(?=[A-Za-z0-9_.-]{20})[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*"),
    re.compile(r"(?<![\w-])GOCSPX-[A-Za-z0-9_-]{20,}"),                                  # Google OAuth client secret
    re.compile(r"(?<![\w~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![\w~.-])"),   # Azure AD client secret
    re.compile(r"(?<![\w-])dapi[0-9a-f]{32}(?:-\d)?(?![\w-])"),                           # Databricks PAT
    re.compile(r"(?<![\w-])hv[sbr]\.[A-Za-z0-9_-]{24,}"),                                 # HashiCorp Vault
    re.compile(r"(?<![\w-])npm_[A-Za-z0-9]{36}(?![\w-])"),                                # npm
    re.compile(r"(?<![\w-])[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),                        # Stripe
    re.compile(r"(?<![\w-])tskey-[A-Za-z0-9-]{16,}"),                                     # Tailscale auth key
    re.compile(r"(?<![\w.-])[a-z0-9]{6}\.[a-z0-9]{16}(?![\w.-])"),                        # kubeadm bootstrap token
]

# Patterns that keep a readable prefix and replace only the secret part (group 1 is kept).
_PREFIX_PATTERNS = [
    # URL userinfo: scheme://user:PASSWORD@host or redis://:PASSWORD@host (the password may not contain /, so
    # registry:5000/x@sha256 is safe)
    re.compile(r"((?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://[^/\s:@\"'<>]{0,256}:)[^@\s/\"'<>]{1,512}(?=@)"),
    # signed URLs / connection strings: sig=, X-Amz-Signature=, AccountKey=, SharedAccessKey=
    re.compile(r"(?i)((?<![A-Za-z0-9_])(?:sig|signature|x-amz-signature|x-amz-security-token|x-amz-credential|"
               r"x-goog-signature|x-goog-credential|accountkey|sharedaccesskey|sharedaccesssignature)=)[^&;\s\"'<>]+"),
    # kubeconfig / Kubernetes Secret data keys whose values are key material
    re.compile(r"(?im)((?:^|[\s{,])[\"']?(?:client-key-data|token-data|tls\.key|ca\.key|ssh-privatekey|"
               r"\.dockerconfigjson|\.dockercfg|\.git-credentials)[\"']?[ \t]*:[ \t]*[\"']?)[A-Za-z0-9+/=_-]{8,}"),
    # kubeadm's control-plane certificate key: `kubeadm init phase upload-certs` prints "Using certificate key:" and
    # the key on the next line (a literal \n inside Ansible's JSON result)
    re.compile(r"(?i)(certificate key:(?:[ \t]|\r?\n|\\r|\\n){0,8})[0-9a-f]{64}(?![0-9a-f])"),
    # curl -u user:password / --user=user:password (the user stays readable; -u 1000:1000 is a uid:gid, not a secret)
    re.compile(r"((?:^|\s)(?:-u|--user)(?:[ \t]+|=)[\"']?[^\s:@\"']{1,128}:)(?!\d+(?:[\s\"']|$))[^\s\"']+"),
]

# Docker / registry config: "auth": "<base64 of user:password>". A bare `auth:` word is not enough, and a value that
# does not decode to user:password ("auth": "disabled") is left alone.
_DOCKER_AUTH = re.compile(r"(?i)((?:^|[\s{,])[\"']auth[\"'][ \t]*:[ \t]*[\"'])([A-Za-z0-9+/]{8,}={0,2})")


def _docker_auth_sub(m: re.Match) -> str:
    value = m.group(2)
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4))
    except ValueError:            # (binascii.Error): not base64 at all
        return m.group(0)
    return m.group(1) + REDACTED if b":" in raw else m.group(0)


# Authorization headers and bare bearer tokens. In agent-facing contexts (see strict()) and in everything written to
# disk (audit.jsonl, command logs: redact(..., auth=True)); the web console and the terminal legitimately show the
# user their own MCP client configuration.
_AGENT_PREFIX_PATTERNS = [
    re.compile(r"(?i)((?:\b|(?<=-H))authorization[\"']?\s*[:=]\s*[\"']?\s*(?:bearer|basic|token|digest|bot)\s+)"
               r"[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/-]{16,}=*"),
]

# CLI flags whose value is a secret: --password X, --token=X, "--token", "X" (Ansible's JSON argv)
_FLAG = re.compile(
    r"(?i)(--[a-z0-9-]{0,40}(?:password|passwd|passphrase|passcode|token|secret|api-key|apikey|auth-key|authkey|"
    r"certificate-key)"
    r"[a-z0-9-]{0,40})((?:=|[ \t]+|[\"'],[ \t]*[\"']))(?!-)([^\s\"',;]+)")
_FLAG_SAFE_SUFFIX = ("-hash", "-file", "-path", "-ttl", "-stdin", "-length", "-name", "-id", "-type", "-dir", "-env")

# key = value / key: value / "key": "value" pairs where the key smells like a secret
_KW = (r"(?:secret|password|passwd|passphrase|passcode|(?<=[_.-])pwd|token|api[_-]?key|apikey|private[_-]?key|"
       r"client[_-]?secret|access[_-]?key|account[_-]?key|auth[_-]?key|cert(?:ificate)?[_-]?key|(?<![a-z])sas(?![a-z]))")
# (an auth scheme before the value - `X-Auth-Token: Bearer <token>` - is kept, and the credential after it is the
# value: the scheme word alone must not be what gets masked)
_KV = re.compile(
    r"(?i)\b([A-Z0-9_.-]{0,64}?" + _KW + r"[A-Z0-9_.-]{0,64})"
    r"([\"']?[ \t]*[=:][ \t]*(?:(?:bearer|basic|token|digest|bot|negotiate|apikey)[ \t]+(?=[^\s\"',;}\]]{4}))?)"
    r"(\"(?:[^\"\\\n]|\\.){0,4096}\"|'[^'\n]{0,4096}'|[^\s\"',;}\]]{4,})")
# keys that contain a keyword but name something that is not a secret
_KV_SAFE_KEY = re.compile(
    r"(?i)(?:arn|name|gsa|client[_-]?id|policy|ttl|length|age|path|file|dir|store|version|count|enabled|type|"
    r"ref|hash|expiry|expires|expiration|expires[_-]?at|mode|format|size|min|max|endpoint|this|rotation|usage|"
    r"source|provider|kind)$")
_ARN_BEFORE = re.compile(r"\barn:[a-z0-9-]+:$")
# a plural last segment names a product/collection (external-secrets, max_tokens), not a value
_KV_PLURAL_LAST = re.compile(r"(?i)(?:^|[_.-])(?:secrets|tokens)$")
_KV_SAFE_VALUE = re.compile(
    r"(?:(?:Creating|Creation|Destroying|Destruction|Modifying|Modifications|Refreshing|Reading|Read|Importing|"
    r"Provisioning|Still|Preparing|Waiting)\b"
    r"|(?i:(?:true|false|null|none|nil|yes|no|on|off|enabled|disabled|required|optional|redacted|sensitive|unknown)"
    r"[,.;]?$)"
    r"|\(sensitive|<sensitive|\(known|arn:|\$\{|\{\{|\*{3}|•)")


def _kv_sub(m: re.Match) -> str:
    key, sep, value = m.group(1), m.group(2), m.group(3)
    quote = value[0] if value[:1] in ("\"", "'") else ""
    inner = value[1:-1] if quote else value
    if not inner or "[REDACTED" in inner or _KV_SAFE_VALUE.match(inner):
        return m.group(0)
    k = key.rstrip(".-_")
    if _KV_SAFE_KEY.search(k) or _KV_PLURAL_LAST.search(k):
        return m.group(0)
    if _ARN_BEFORE.search(m.string, max(0, m.start() - 40), m.start()):   # arn:aws:secretsmanager:<region>:...
        return m.group(0)
    return f"{key}{sep}{quote}{REDACTED}{quote}"


# Structured output (YAML / pretty-printed JSON, e.g. `kubectl get ... -o yaml`, `helm get values`) where the secret is
# not on the line that names it:
#   rootPassword:            a secret-named key holding a mapping: its `value` child is the secret
#     value: S3cr3t
#   - name: DB_PASSWORD      an env-style name/value pair: the sibling `value` of a secret-looking name
#     value: hunter2
#   data:                    a Kubernetes Secret's data block: its base64 values (stringData: every value)
#     api-endpoint: aHR0cHM6Ly9leGFtcGxl
_NEST_KEYLINE = re.compile(r"^([ \t]*)(-[ \t]+)?([\"']?)([^\s\"':{}\[\],]{1,200})\3[ \t]*:(?:[ \t]+(.*))?$")
_NEST_QUOTED = re.compile(r"\"(?:[^\"\\]|\\.){0,4096}\"|'[^']{0,4096}'")
_NEST_COMMENT = re.compile(r"[ \t]+#")
_NEST_OPEN = re.compile(r"^(?:\{)?[ \t]*(?:#.*)?$")
_BASE64ISH = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")
_SECRET_KEY = re.compile(r"(?i)[A-Za-z0-9_.-]{0,64}?" + _KW + r"[A-Za-z0-9_.-]{0,64}")


def _secretish_key(key: str) -> bool:
    k = key.rstrip(".-_")
    return bool(_SECRET_KEY.fullmatch(key)) and not (_KV_SAFE_KEY.search(k) or _KV_PLURAL_LAST.search(k))


def _base64ish(v: str) -> bool:
    """Looks like base64 data (a Secret's data value), not a plain word such as `info` or `database`."""
    return len(v) >= 8 and len(v) % 4 == 0 and bool(_BASE64ISH.fullmatch(v)) and \
        bool(re.search(r"[0-9+/=]", v) or (re.search(r"[a-z]", v) and re.search(r"[A-Z]", v)))


def _redact_scalar(body: str, start: int, test=None) -> tuple:
    """(line, block) with the scalar value at body[start:] replaced (quotes kept), unless it is empty, already redacted,
    a safe literal (true/null/...) or fails `test`. block is True when the value is a YAML block scalar (| or >):
    its content follows on the more indented lines."""
    rest = body[start:]
    if rest[:1] in ("|", ">"):     # (a Secret's data values are single-line base64; a ConfigMap's files are not)
        return body, test is None
    if not rest or rest[:1] in ("{", "[", "&", "*", "!"):
        return body, False
    m = _NEST_QUOTED.match(rest)
    if m:
        value, quote = m.group(0), rest[0]
        inner = value[1:-1]
    else:
        c = _NEST_COMMENT.search(rest)
        value = (rest[:c.start()] if c else rest).rstrip()
        quote, inner = "", value
    if not inner or "[REDACTED" in inner or _KV_SAFE_VALUE.match(inner) or (test and not test(inner)):
        return body, False
    return body[:start] + quote + REDACTED + quote + rest[len(value):], False


class _Structured:
    """Line-by-line state for secrets named on another line than their value (one instance per text or stream):
      rootPassword:            a secret-named key holding a mapping: its `value` child is the secret
        value: S3cr3t          (`helm get values` of charts that take {value: ...})
      - name: DB_PASSWORD      an env-style name/value pair: the sibling `value` of a secret-looking name
        value: hunter2         (`kubectl get pod -o yaml`, pretty-printed JSON alike)
      data:                    a Kubernetes Secret's data block: its base64 values; stringData: every value
        api-endpoint: aHR0cHM6Ly9leGFtcGxl
    YAML block scalars (`value: |`) are hidden line by line."""

    def __init__(self):
        self.block = None      # (key column, kind) of an open secret-named mapping / data block
        self.item = None       # key column of an env item whose name looks secret
        self.scalar = None     # indent of the key whose block-scalar value is being hidden

    def line(self, line: str) -> str:
        body = line.rstrip("\r\n")
        if not body.strip():
            return line
        nl = line[len(body):]
        indent = len(body) - len(body.lstrip(" \t"))
        if self.scalar is not None:
            if indent > self.scalar:
                return body[:indent] + REDACTED + nl
            self.scalar = None
        if self.block and indent <= self.block[0]:
            self.block = None
        m = _NEST_KEYLINE.match(body)
        col = indent + len(m.group(2) or "") if m else indent
        if self.item is not None and (indent < self.item or (m and m.group(2) and col <= self.item)):
            self.item = None
        if not m:
            return line
        key, rest = m.group(4), m.group(5) or ""
        start = m.start(5) if m.group(5) is not None else len(body)
        low = key.lower()
        target = None
        if self.block:
            kind = self.block[1]
            if kind == "stringdata" or (kind == "secret" and low == "value"):
                target = (None,)
            elif kind == "data":
                target = (_base64ish,)
        elif self.item is not None and col == self.item and not m.group(2) and low == "value":
            self.item = None
            target = (None,)
        if target:
            out, block = _redact_scalar(body, start, target[0])
            if block:
                self.scalar = col
            return out + nl
        if low == "name":
            q = _NEST_QUOTED.match(rest)
            name = q.group(0)[1:-1] if q else rest.split("#")[0].strip()
            self.item = col if name and (is_secret_env(name) or _secretish_key(name)) else None
        if self.block is None and _NEST_OPEN.match(rest):   # the key opens a mapping (YAML `key:` / JSON `"key": {`)
            if low == "data":
                self.block = (col, "data")
            elif low == "stringdata":
                self.block = (col, "stringdata")
            elif _secretish_key(key):
                self.block = (col, "secret")
        return line


def _structured(text: str) -> str:
    st = _Structured()
    return "".join(st.line(ln) for ln in text.splitlines(True))


# Kubernetes Secrets as compact one-line JSON (`kubectl get --raw`, `-o json` through some tools, the
# last-applied-configuration annotation, `-o jsonpath={.data}`): the line-by-line YAML/JSON rules above never see
# them, so such lines are parsed and the Secret's data values replaced.
_JSON_DATA_HINT = re.compile(r'\\?"(?:data|stringData)\\?"\s*:\s*\{')
_ESCAPED_SECRET = re.compile(r'\\"kind\\"\s*:\s*\\"Secret(?:List)?\\"')
_ESCAPED_DATA = re.compile(r'(\\"(?:data|stringData)\\"\s*:\s*\{)([^{}]*)(\})')
_ESCAPED_PAIR = re.compile(r'(\\"[^"\\]{0,256}\\"\s*:\s*\\")((?:[^"\\]|\\\\)*?)(\\")')
_PLAIN_SECRET = re.compile(r'"kind"\s*:\s*"Secret(?:List)?"')
_PLAIN_DATA = re.compile(r'("(?:data|stringData)"\s*:\s*\{)([^{}]*)(\})')
_PLAIN_PAIR = re.compile(r'("(?:[^"\\]|\\.){0,256}"\s*:\s*")((?:[^"\\]|\\.)*)(")')
_LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"


def _hide_secret_data(obj, secret: bool = False) -> bool:
    """Replace the data/stringData values of every Secret in a parsed JSON value (lists, SecretList items and the
    last-applied-configuration annotation included). True when something was replaced."""
    changed = False
    if isinstance(obj, list):
        for item in obj:
            changed |= _hide_secret_data(item, secret)
        return changed
    if not isinstance(obj, dict):
        return False
    kind = obj.get("kind")
    if secret or kind == "Secret":
        for key in ("data", "stringData"):
            block = obj.get(key)
            if isinstance(block, dict) and any(v != REDACTED for v in block.values()):
                obj[key] = {k: REDACTED for k in block}
                changed = True
    meta = obj.get("metadata")
    ann = meta.get("annotations") if isinstance(meta, dict) else None
    if isinstance(ann, dict) and isinstance(ann.get(_LAST_APPLIED), str):
        try:
            inner = json.loads(ann[_LAST_APPLIED])
        except ValueError:
            inner = None
        if inner is not None and _hide_secret_data(inner):
            ann[_LAST_APPLIED] = json.dumps(inner, separators=(",", ":"), ensure_ascii=False) + "\n"
            changed = True
    for key, val in obj.items():
        if key in ("data", "stringData", "metadata"):
            continue
        changed |= _hide_secret_data(val, secret=(key == "items" and kind == "SecretList"))
    return changed


def _secret_json_line(line: str) -> str:
    body = line.strip()
    if not body or len(body) > 4 * 1024 * 1024:
        return line
    lead = line[:len(line) - len(line.lstrip())]
    trail = line[len(line.rstrip()):]
    if body[0] in "{[" and body[-1] in "}]":
        try:
            obj = json.loads(body)
        except ValueError:
            obj = None
        if obj is not None:
            if _hide_secret_data(obj):
                return lead + json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + trail
            # `-o jsonpath={.data}` of a Secret: one mapping of base64 values (only where an agent reads the output:
            # in the user's own terminal a mapping of hashes or ids must stay readable)
            if strict() and isinstance(obj, dict) and obj and \
                    all(isinstance(v, str) and _base64ish(v) for v in obj.values()):
                return lead + json.dumps({k: REDACTED for k in obj}, separators=(",", ":"), ensure_ascii=False) + trail
            return line
    # not parseable (cut short, or JSON escaped inside a string such as a -o json annotation): by pattern
    if _ESCAPED_SECRET.search(line):
        line = _ESCAPED_DATA.sub(lambda m: m.group(1) + _ESCAPED_PAIR.sub(
            lambda p: p.group(1) + REDACTED + p.group(3), m.group(2)) + m.group(3), line)
    if _PLAIN_SECRET.search(line):
        line = _PLAIN_DATA.sub(lambda m: m.group(1) + _PLAIN_PAIR.sub(
            lambda p: p.group(1) + REDACTED + p.group(3), m.group(2)) + m.group(3), line)
    return line


def _secret_json(text: str) -> str:
    """Secret data in compact JSON lines (see _secret_json_line); other text is returned unchanged."""
    if not (_JSON_DATA_HINT.search(text) or ('{"' in text and "}" in text)):
        return text
    return "".join(_secret_json_line(ln) if ("{" in ln and "}" in ln) else ln for ln in text.splitlines(True))


def _flag_sub(m: re.Match) -> str:
    flag = m.group(1).lower()
    if flag.endswith(_FLAG_SAFE_SUFFIX) or "[REDACTED" in m.group(3) or _KV_SAFE_VALUE.match(m.group(3)):
        return m.group(0)
    return f"{m.group(1)}{m.group(2)}{REDACTED}"


# Literal secret values (the vault's secret entries, the MCP / console bearer tokens, parked session values and
# values registered at run time, e.g. generated platform passwords) are replaced wherever they appear.
_MIN_LITERAL = 8
_REGISTERED: set = set()
_LIT_CACHE: dict = {"stamp": None, "values": ()}
_LIT_LOCK = threading.Lock()


def register(*values) -> None:
    """Treat these exact values as secrets from now on (in this process)."""
    for v in values:
        if isinstance(v, str) and len(v.strip()) >= _MIN_LITERAL and REDACTED not in v:
            _REGISTERED.add(v.strip())


_STRICT = {"on": False}


def set_strict(on: bool = True) -> None:
    """Mark this process as agent-facing: its redaction also hides the MCP / console bearer tokens and
    Authorization headers (which the web console and terminal otherwise show the user on purpose)."""
    _STRICT["on"] = bool(on)


def strict() -> bool:
    return _STRICT["on"] or redact_enabled()


def _literal_sources(agent: bool) -> list:
    vault = [paths.HOME / "credentials.json"]
    return vault + ([paths.HOME / "mcp" / "token", paths.HOME / "ui" / "token"] if agent else [])


def _literals() -> tuple:
    agent = strict()
    stamp = [agent, len(_REGISTERED)]
    for p in _literal_sources(agent):
        try:
            st = p.stat()
            stamp.append((st.st_mtime_ns, st.st_size))
        except OSError:
            stamp.append(None)
    stamp = tuple(stamp)
    if _LIT_CACHE["stamp"] == stamp:
        return _LIT_CACHE["values"]
    with _LIT_LOCK:
        vals = set(_REGISTERED)
        try:
            from . import creds
            for k, v in creds.load().items():
                if isinstance(v, str) and creds.KNOWN.get(k, ("", "", "secret"))[2] in ("secret", "json"):
                    vals.add(v.strip())
        except Exception:  # noqa: BLE001
            pass
        for p in _literal_sources(agent)[1:]:
            try:
                vals.add(p.read_text().strip())
            except OSError:
                pass
        values = tuple(sorted((v for v in vals if len(v) >= _MIN_LITERAL), key=len, reverse=True))
        _LIT_CACHE.update(stamp=stamp, values=values)
    return values


def redact(text: str, kv: bool = True, auth: bool | None = None) -> str:
    """Scrub secrets from text. kv=False skips the key-name heuristics (for structured values such as resource ids
    that are known not to be secrets); token formats and literal secrets are always scrubbed. auth: also hide
    Authorization headers and bearer tokens (default: in agent-facing processes, see strict(); pass True for anything
    written to disk)."""
    if not text or not isinstance(text, str):
        return text
    for lit in _literals():
        if lit in text:
            text = text.replace(lit, REDACTED)
    for pat in _TOKEN_PATTERNS:
        text = pat.sub(REDACTED, text)
    if kv:
        text = _secret_json(text)
    use_auth = strict() if auth is None else auth
    for pat in _PREFIX_PATTERNS + (_AGENT_PREFIX_PATTERNS if use_auth else []):
        text = pat.sub(lambda m: m.group(1) + REDACTED, text)
    text = _DOCKER_AUTH.sub(_docker_auth_sub, text)
    if kv:
        text = _FLAG.sub(_flag_sub, text)
        text = _KV.sub(_kv_sub, text)
        if "\n" in text.rstrip("\r\n"):   # several lines: secrets named on another line (see _Structured)
            text = _structured(text)
    return text


_SECRET_FLAGS = {"--string-value", "--bytes-value", "--password", "--token", "--secret", "--client-secret",
                 "--docker-password", "--api-key", "--auth-key", "--authkey", "--passphrase", "--sas-token"}


def mask_argv(argv: list, auth: bool | None = None) -> list:
    """An argv list safe to print or log: values of secret flags, --from-literal values and secrets are masked
    (auth=True: Authorization headers too, as for audit files; see redact)."""
    out: list = []
    mask_next = False
    for a in argv:
        a = str(a)
        if mask_next:
            out.append(REDACTED)
            mask_next = False
            continue
        low = a.lower()
        if low in _SECRET_FLAGS:
            mask_next = True
            out.append(a)
            continue
        flag, eq, _val = a.partition("=")
        if eq and flag.lower() in _SECRET_FLAGS:
            out.append(f"{flag}={REDACTED}")
            continue
        if eq and flag.lower() == "--from-literal":
            k, eq2, _v = _val.partition("=")
            out.append(f"{flag}={k}={REDACTED}" if eq2 else a)
            continue
        out.append(redact(a, auth=auth))
    return out


_PEM_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V\d)-----")
_PEM_END = re.compile(r"-----END (?:[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?|OpenVPN Static key V\d)-----")
_CERT_KEY_INTRO = re.compile(r"(?i)certificate key:\s*$")
_CERT_KEY_LINE = re.compile(r"(\s*)[0-9a-f]{64}(?![0-9a-f])")


class StreamRedactor:
    """Redact a stream line by line, including private keys that span several lines.

    Use one instance per stream: feed() each line (with or without its newline) and print what it returns
    ("" for swallowed key lines). A BEGIN with no END within MAX_KEY_LINES stops swallowing, so a stray marker
    cannot hide the rest of a log."""

    MAX_KEY_LINES = 200

    def __init__(self, kv: bool = True, auth: bool | None = None):
        self.kv = kv
        self.auth = auth      # see redact(): None = only in agent-facing processes, True = always (files on disk)
        self.in_key = False
        self._n = 0
        self._cert_next = False
        self._structured = _Structured()

    def feed(self, line: str) -> str:
        out = self._feed(line)
        # secrets named on an earlier line (nested YAML / JSON, env name/value pairs, Secret data blocks)
        return self._structured.line(out) if out and self.kv else out

    def _feed(self, line: str) -> str:
        if not line:
            return line
        nl = "\n" if line.endswith("\n") else ""
        # kubeadm prints "Using certificate key:" and the key itself on the line after it
        cert_next, self._cert_next = self._cert_next, bool(_CERT_KEY_INTRO.search(line))
        if cert_next and not self.in_key:
            m = _CERT_KEY_LINE.match(line)
            if m:
                return m.group(1) + REDACTED + redact(line[m.end():], self.kv, self.auth)
        if self.in_key:
            m = _PEM_END.search(line)
            if not m:
                self._n += 1
                if self._n >= self.MAX_KEY_LINES:
                    self.in_key = False
                    return REDACTED + " (no END marker)" + nl
                return ""
            self.in_key = False
            rest = line[m.end():]
            return redact(rest, self.kv, self.auth) if rest.strip() else ""
        # look for the BEGIN marker before redact(): its key=value rule would eat the marker of
        # `private_key: -----BEGIN ...` and the key body on the following lines would pass through
        m = _PEM_BEGIN.search(line)
        if m and not _PEM_END.search(line, m.end()):
            self.in_key = True
            self._n = 0
            return redact(line[:m.start()], self.kv, self.auth) + REDACTED + nl
        return redact(line, self.kv, self.auth)


class RedactingWriter:
    """File-like wrapper that redacts complete lines before they reach the wrapped text stream."""

    def __init__(self, stream):
        self._stream = stream
        self._buf = ""
        self._red = StreamRedactor()

    def write(self, s) -> int:
        s = s if isinstance(s, str) else str(s)
        self._buf += s
        if "\n" in self._buf:
            *lines, self._buf = self._buf.split("\n")
            out = "".join(self._red.feed(line + "\n") for line in lines)
            if out:
                self._stream.write(out)
        return len(s)

    def writelines(self, lines) -> None:
        for line in lines:
            self.write(line)

    def flush(self) -> None:
        if self._buf:
            out, self._buf = self._red.feed(self._buf), ""
            if out:
                self._stream.write(out)
        try:
            self._stream.flush()
        except (OSError, ValueError):
            pass

    def __getattr__(self, name):
        return getattr(self._stream, name)


def register_env_secrets() -> None:
    """Treat the values of this process's credential env vars (and vault-classified ones) as literal secrets."""
    extra = _vault_secret_keys()
    _register_parked({k: v for k, v in os.environ.items() if is_secret_env(k) or k in extra})


def wrap_std_streams() -> None:
    """Redact everything this process prints (used inside agent sessions)."""
    register_env_secrets()
    for name in ("stdout", "stderr"):
        cur = getattr(sys, name)
        if cur is not None and not isinstance(cur, RedactingWriter):
            setattr(sys, name, RedactingWriter(cur))


def run_redacted(cmd: list, **kw) -> int:
    """Run a command and print its (merged) output redacted - for passthrough commands inside agent sessions."""
    red = StreamRedactor()
    kw.setdefault("stdin", subprocess.DEVNULL)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", **kw)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            out = red.feed(line)
            if out:
                sys.stdout.write(out)
                sys.stdout.flush()
        return proc.wait()
    except BaseException:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise


def redact_enabled() -> bool:
    return os.environ.get("CLOUDSEED_REDACT") == "1"


def env_flag(name: str) -> bool:
    """A boolean switch from the environment: only 1/true/yes/on enable it (0/false/no/empty do not)."""
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


# ------------------------------------------------------------------------------------------------ session broker

SESSIONS_DIR = paths.HOME / "sessions"
_SOCK_PREFIX = "sock:"
_TMP_PREFIX = "cloudseed-sess-"
_OPEN: dict = {}            # sid -> {"kind": "sock"|"file", ...}
_OPEN_LOCK = threading.RLock()   # re-entrant: the SIGTERM handler may run while the main thread holds it
_PREV_HANDLERS: dict = {}
_SIGNAL_HOLDS = {"n": 0}   # active exit_on_signals() blocks: the handlers stay until the last one ends
_LEGACY_MAX_AGE = 7 * 24 * 3600


def _register_parked(parked: dict) -> None:
    """Parked values become literal secrets, except plain file paths (GOOGLE_APPLICATION_CREDENTIALS and the like)."""
    for v in parked.values():
        if v.startswith(("/", "~")) and os.path.exists(os.path.expanduser(v)):
            continue
        register(v)


def _pid_alive(pid) -> bool:
    if os.name == "nt":   # os.kill(pid, 0) would terminate the process on Windows
        return True
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except (PermissionError, OSError, ValueError, TypeError):
        return True
    return True


def _sweep_stale() -> None:
    """Delete session files / broker dirs whose owner process is gone (a SIGKILL skips every cleanup)."""
    try:
        files = list(SESSIONS_DIR.glob("*.json"))
    except OSError:
        files = []
    now = time.time()
    for f in files:
        try:
            data = json.loads(f.read_text())
            owner = data.get("pid") if isinstance(data, dict) and isinstance(data.get("env"), dict) else None
            if owner is not None:
                if not _pid_alive(owner):
                    f.unlink()
            elif now - f.stat().st_mtime > _LEGACY_MAX_AGE:   # flat file written by an older cloudseed
                f.unlink()
        except (OSError, ValueError):
            continue
    for base in {tempfile.gettempdir(), "/tmp"}:
        try:
            for d in Path(base).glob(_TMP_PREFIX + "*"):
                m = re.match(re.escape(_TMP_PREFIX) + r"(\d+)-", d.name)
                if m and d.is_dir() and not _pid_alive(int(m.group(1))):
                    shutil.rmtree(d, ignore_errors=True)
        except OSError:
            continue


def _broker_dir() -> Path | None:
    for base in (tempfile.gettempdir(), "/tmp"):
        if len(os.path.join(base, _TMP_PREFIX + "0000000-xxxxxxxx", "s")) > 100:   # AF_UNIX path limit
            continue
        try:
            return Path(tempfile.mkdtemp(prefix=f"{_TMP_PREFIX}{os.getpid()}-", dir=base))
        except OSError:
            continue
    return None


def _serve_broker(srv: socket.socket, token: bytes, payload: bytes, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        try:
            conn.settimeout(5)
            data = b""
            while b"\n" not in data and len(data) < 512:
                chunk = conn.recv(512)
                if not chunk:
                    break
                data += chunk
            if hmac.compare_digest(data.strip(), token):
                conn.sendall(payload)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _start_broker(parked: dict) -> dict | None:
    if not hasattr(socket, "AF_UNIX"):
        return None
    d = _broker_dir()
    if d is None:
        return None
    path = d / "s"
    try:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(path))
        os.chmod(path, 0o600)
        srv.listen(16)
        srv.settimeout(0.5)
    except OSError:
        shutil.rmtree(d, ignore_errors=True)
        return None
    token = _secrets.token_hex(32)
    stop = threading.Event()
    t = threading.Thread(target=_serve_broker, args=(srv, token.encode(), json.dumps(parked).encode(), stop),
                         name="cloudseed-session-broker", daemon=True)
    t.start()
    return {"kind": "sock", "sock": srv, "dir": d, "stop": stop, "thread": t,
            "handle": f"{_SOCK_PREFIX}{path}#{token}"}


def _write_session_file(sid: str, parked: dict) -> dict:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SESSIONS_DIR, 0o700)
    path = SESSIONS_DIR / f"{sid}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"pid": os.getpid(), "created": time.time(), "env": parked}, fh)
    return {"kind": "file", "path": path, "handle": sid}


def _on_signal(signum, _frame):
    close_all_sessions()
    raise SystemExit(128 + signum)


def _install_signal_handlers() -> None:
    """SIGTERM/SIGHUP (terminal closed, `kill`) would skip the `finally` that ends a session: end it and exit
    through SystemExit so cleanup code and child termination still run. Handlers someone else installed, and
    SIG_IGN (nohup), are left alone."""
    if threading.current_thread() is not threading.main_thread():
        return
    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None or sig in _PREV_HANDLERS:
            continue
        try:
            if signal.getsignal(sig) is signal.SIG_DFL:
                signal.signal(sig, _on_signal)
                _PREV_HANDLERS[sig] = signal.SIG_DFL
        except (ValueError, OSError):
            continue


def _restore_signal_handlers() -> None:
    if threading.current_thread() is not threading.main_thread():
        return
    with _OPEN_LOCK:
        if _OPEN or _SIGNAL_HOLDS["n"]:   # still needed by an open session or an exit_on_signals() block
            return
    for sig, prev in list(_PREV_HANDLERS.items()):
        try:
            if signal.getsignal(sig) is _on_signal:
                signal.signal(sig, prev)
        except (ValueError, OSError):
            pass
        _PREV_HANDLERS.pop(sig, None)


@contextlib.contextmanager
def exit_on_signals():
    """For the duration of the block, SIGTERM/SIGHUP (terminal closed, `kill`) end the process through SystemExit,
    after closing any open session, instead of killing it outright, so `finally` blocks and child-process cleanup
    still run (the built-in agent stops the command it is running). Handlers someone else installed are kept."""
    with _OPEN_LOCK:
        _SIGNAL_HOLDS["n"] += 1
    _install_signal_handlers()
    try:
        yield
    finally:
        with _OPEN_LOCK:
            _SIGNAL_HOLDS["n"] -= 1
        _restore_signal_handlers()


def open_session(keep: tuple = ()) -> tuple:
    """Park credential env vars with a broker. Returns (session_id, env_for_agent).
    `keep` names env vars the agent itself needs (its own API key); everything else secret is parked."""
    _sweep_stale()
    extra = _vault_secret_keys()

    def secret(k: str) -> bool:
        return is_secret_env(k) or k in extra

    parked = {k: v for k, v in os.environ.items() if secret(k)}
    _register_parked(parked)
    set_strict(True)
    env = {k: v for k, v in os.environ.items() if not secret(k) or k in keep}
    sid = _secrets.token_hex(8)
    # SIGTERM/SIGHUP handlers first, and the session known under its file's name before anything is written: a signal
    # at any point from here on ends the session through close_all_sessions, so the plaintext session file (the
    # fallback when no broker socket can be made) is never left behind until the next _sweep_stale
    _install_signal_handlers()
    with _OPEN_LOCK:
        _OPEN[sid] = {"kind": "file", "path": SESSIONS_DIR / f"{sid}.json", "handle": sid}
    try:
        rec = _start_broker(parked) or _write_session_file(sid, parked)
        with _OPEN_LOCK:
            _OPEN[sid] = rec
    except BaseException:
        close_session(sid)
        raise
    env["CLOUDSEED_SESSION"] = rec["handle"]
    env["CLOUDSEED_REDACT"] = "1"
    return sid, env


def close_session(sid: str) -> None:
    """End a session: its broker stops / its file goes. The record is dropped only after the cleanup, so a signal that
    arrives in between still finds it (every step can safely run twice)."""
    with _OPEN_LOCK:
        rec = _OPEN.get(sid)
    if rec is None:   # unknown here (e.g. a file from another process): best-effort removal of the file form
        if re.fullmatch(r"[0-9a-f]{16}", sid or ""):
            try:
                (SESSIONS_DIR / f"{sid}.json").unlink()
            except OSError:
                pass
    elif rec["kind"] == "sock":
        rec["stop"].set()
        try:
            rec["sock"].close()
        except OSError:
            pass
        shutil.rmtree(rec["dir"], ignore_errors=True)
    else:
        try:
            rec["path"].unlink()
        except OSError:
            pass
    with _OPEN_LOCK:
        _OPEN.pop(sid, None)
        empty = not _OPEN
    if empty:
        _restore_signal_handlers()


def close_all_sessions() -> None:
    for sid in list(_OPEN):
        close_session(sid)


def _fetch_from_broker(handle: str) -> dict | None:
    """The parked variables from the session's broker, or None when it cannot be reached."""
    path, _, token = handle[len(_SOCK_PREFIX):].rpartition("#")
    p = Path(path)
    if not path or not token or not p.is_absolute() or not p.parent.name.startswith(_TMP_PREFIX):
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.settimeout(10)
            c.connect(path)
            c.sendall(token.encode() + b"\n")
            chunks = []
            while True:
                chunk = c.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(x) for x in chunks) > 4 * 1024 * 1024:
                    return None
        data = json.loads(b"".join(chunks).decode())
    except (OSError, ValueError, AttributeError):
        return None
    return data if isinstance(data, dict) else None


def restore_session_env() -> None:
    """Called at CLI start: when running under an agent session, reload the parked credentials
    so Terraform/cloud SDKs work, without them ever having been in the agent's environment."""
    handle = os.environ.get("CLOUDSEED_SESSION") or ""
    parked: dict = {}
    if handle.startswith(_SOCK_PREFIX):
        parked = _fetch_from_broker(handle)
        if parked is None and not paths.IN_CONTAINER:   # (inside the container the credentials arrive as -e variables)
            sys.stderr.write("  ▲ The agent session that started this command has ended; its credentials are not "
                             "available (run the command yourself, or start a new `cloudseed agentic` session).\n")
    elif re.fullmatch(r"[0-9a-f]{16}", handle):
        try:
            data = json.loads((SESSIONS_DIR / f"{handle}.json").read_text())
        except (OSError, ValueError):
            return
        if isinstance(data, dict):
            parked = data["env"] if isinstance(data.get("env"), dict) else data
    else:
        return
    parked = {k: v for k, v in (parked or {}).items() if isinstance(k, str) and isinstance(v, str)}
    for k, v in parked.items():
        os.environ.setdefault(k, v)
    _register_parked(parked)
