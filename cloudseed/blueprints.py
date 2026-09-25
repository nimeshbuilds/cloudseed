"""Portable, credential-free environment specifications and reviewed deployment profiles.

Saving changes only local configuration. Terraform plan/apply, chart installation, backup
schedules and policy enforcement remain explicit operations.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import math
import re
from datetime import datetime

from . import paths, ui
from .clouds.base import MANAGED_VAR_FLAGS

SCHEMA_VERSION = 1
PROFILES = ("lab", "team", "production")
CONFIG_KEYS = frozenset(("name", "region", "network_cidr", "allowed_ssh_cidrs", "tags", "vars", "extra_vars"))
OPERATIONS_KEYS = frozenset(("profile", "budget_max_monthly", "require_complete_cost", "block_destroy",
                            "expires_at", "cleanup_opt_in", "backup", "platform"))
# These names are legitimate stack inputs but bind a particular machine, key or login session.
EXCLUDED = frozenset(("ssh_public_key", "ssh_private_key_path", "base_disk", "vm_dir", "guest_os_id", "os_login_member", "profile"))
_SECRET = re.compile(r"(?:password|secret|token|credential|private_key|auth_key|access_key)", re.I)
_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def _finite_number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except (OverflowError, ValueError):
        return False


def _error(message):
    raise ui.Abort(message, code=2)


def _bounded(value):
    try:
        encoded = json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        _error("Specification must be finite JSON-compatible data (no aliases, dates or special objects).")
    if len(encoded.encode()) > 512 * 1024:
        _error("Specification exceeds 512 KiB.")
    def visit(item, depth=0):
        if depth > 12:
            _error("Specification exceeds 12 nesting levels.")
        if isinstance(item, dict):
            if any(not isinstance(k, str) for k in item):
                _error("Specification mapping keys must be strings.")
            for v in item.values():
                visit(v, depth + 1)
        elif isinstance(item, list):
            for v in item:
                visit(v, depth + 1)
        elif isinstance(item, str) and ("PRIVATE KEY-----" in item or "\x00" in item):
            _error("Specifications cannot contain private keys or NUL characters.")
    visit(value)


def _variable_types(cloud):
    text = (paths.tf_root() / cloud.key / "variables.tf").read_text()
    out = {}
    for match in re.finditer(r'variable\s+"([^"]+)"\s*\{(.*?)\n\}', text, re.S):
        typ = re.search(r'^\s*type\s*=\s*(.+)$', match.group(2), re.M)
        if typ:
            out[match.group(1)] = typ.group(1).strip()
    return out


def _safe_key(key):
    return key not in EXCLUDED and not _SECRET.search(key)


def export_spec(cloud, env, cfg):
    config = {key: copy.deepcopy(cfg[key]) for key in CONFIG_KEYS if key in cfg and key not in ("vars", "extra_vars")}
    config["vars"] = {k: copy.deepcopy(v) for k, v in (cfg.get("vars") or {}).items()
                      if k in {q.key for q in cloud.questions} and _safe_key(k)}
    config["extra_vars"] = {k: copy.deepcopy(v) for k, v in (cfg.get("extra_vars") or {}).items()
                            if k in _variable_types(cloud) and k not in cloud.managed_vars(cfg) and _safe_key(k)}
    if "tags" in config:
        config["tags"] = {k: v for k, v in config["tags"].items() if _safe_key(k)}
    result = {"schema_version": 1, "cloud": cloud.key, "environment": env.name, "configuration": config}
    if cfg.get("operations"):
        result["operations"] = {k: copy.deepcopy(v) for k, v in cfg["operations"].items() if k in OPERATIONS_KEYS}
    validate_operations(result.get("operations", {}))
    # A malformed manually edited config must not leak key material through export.
    _bounded(result)
    return result


def validate_operations(operations):
    if not isinstance(operations, dict) or set(operations) - OPERATIONS_KEYS:
        _error("operations contains unsupported fields.")
    for key in ("require_complete_cost", "block_destroy", "cleanup_opt_in"):
        if key in operations and type(operations[key]) is not bool:
            _error(f"operations.{key} must be boolean.")
    if "profile" in operations and operations["profile"] not in PROFILES:
        _error("operations.profile must be lab, team or production.")
    if "budget_max_monthly" in operations:
        amount = operations["budget_max_monthly"]
        if not _finite_number(amount) or amount <= 0:
            _error("operations.budget_max_monthly must be a positive finite USD amount.")
    if "expires_at" in operations:
        try:
            stamp = datetime.fromisoformat(operations["expires_at"].replace("Z", "+00:00"))
            if stamp.utcoffset() is None:
                raise ValueError()
        except (AttributeError, TypeError, ValueError):
            _error("operations.expires_at must be an ISO timestamp with a timezone.")
    if operations.get("cleanup_opt_in") and not operations.get("expires_at"):
        _error("cleanup_opt_in requires an explicit expires_at timestamp; it never schedules deletion.")
    if "platform" in operations:
        from .platform import CATALOG
        items = operations["platform"]
        if not isinstance(items, list) or any(not isinstance(x, str) or x not in CATALOG for x in items) or len(set(items)) != len(items):
            _error("operations.platform must list distinct known platform item names.")
    if "backup" in operations:
        from .dr import ttl_duration, CRON_RE
        backup = operations["backup"]
        if not isinstance(backup, dict) or set(backup) - {"schedule", "ttl", "namespaces"}:
            _error("operations.backup accepts schedule, ttl and namespaces only.")
        if "ttl" in backup:
            ttl_duration(backup["ttl"])
        if "schedule" in backup:
            if not isinstance(backup["schedule"], str) or not CRON_RE.fullmatch(backup["schedule"].strip()):
                _error("backup.schedule must be a five-field cron expression or supported descriptor.")
        namespaces = backup.get("namespaces", [])
        if not isinstance(namespaces, list) or any(not isinstance(n, str) or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", n) for n in namespaces):
            _error("backup.namespaces must list Kubernetes namespace names.")


def validate_spec(spec, cloud, env):
    _bounded(spec)
    if not isinstance(spec, dict) or set(spec) - {"schema_version", "cloud", "environment", "configuration", "operations"}:
        _error("Specification contains unsupported top-level fields.")
    if type(spec.get("schema_version")) is not int or spec["schema_version"] != 1:
        _error("Unsupported specification schema_version; expected 1.")
    if spec.get("cloud") != cloud.key or spec.get("environment") != env.name:
        _error("Specification cloud/environment must match the selected environment; edit those fields explicitly before importing a copy.")
    config = spec.get("configuration")
    if not isinstance(config, dict) or set(config) - CONFIG_KEYS:
        _error("configuration contains unsupported fields (credentials, state and local paths are not portable).")
    for name in ("name", "region", "network_cidr"):
        if not isinstance(config.get(name), str) or not config[name].strip():
            _error(f"configuration.{name} is required.")
    if not _NAME.fullmatch(config["name"]):
        _error("configuration.name must be 1-63 letters, digits, underscores or hyphens.")
    try:
        ipaddress.ip_network(config["network_cidr"], strict=True)
        allowed = config.get("allowed_ssh_cidrs", [])
        if not isinstance(allowed, list):
            raise ValueError()
        for cidr in allowed:
            if not isinstance(cidr, str) or "/" not in cidr:
                raise ValueError()
            ipaddress.ip_network(cidr, strict=True)
    except ValueError:
        _error("Network and allowed SSH ranges must be explicit, valid CIDRs.")
    tags = config.get("tags", {})
    if not isinstance(tags, dict) or any(not isinstance(v, str) or not _safe_key(k) for k, v in tags.items()):
        _error("Tags must be string values and must not contain credential fields.")
    variables = config.get("vars", {})
    extras = config.get("extra_vars", {})
    if not isinstance(variables, dict) or not isinstance(extras, dict):
        _error("vars and extra_vars must be objects.")
    questions = {q.key: q for q in cloud.questions}
    for key, value in variables.items():
        if key not in questions or not _safe_key(key):
            _error(f"Unsupported portable configuration variable: {key}.")
        try:
            questions[key].coerce(value)
        except (TypeError, ValueError):
            _error(f"Invalid type for configuration variable: {key}.")
    types = _variable_types(cloud)
    for key, value in extras.items():
        if key not in types or key in cloud.managed_vars(config) or not _safe_key(key):
            _error(f"Unsupported portable Terraform override: {key}.")
        typ = types[key]
        ok = value is None or (typ == "bool" and type(value) is bool) or (typ == "number" and type(value) in (int, float)) or (typ == "string" and isinstance(value, str)) or (typ == "list(string)" and isinstance(value, list) and all(isinstance(x, str) for x in value))
        if not ok:
            _error(f"Terraform override {key} must have type {typ}.")
    candidate = {**copy.deepcopy(config), "cloud": cloud.key, "env": env.name}
    for problem in cloud.check_config(candidate):
        _error("Specification configuration is invalid: " + problem)
    _topology(cloud, candidate)
    validate_operations(spec.get("operations", {}))
    return copy.deepcopy(spec)


def _topology(cloud, cfg):
    from .finops import effective_vars
    v = effective_vars(cloud.key, cfg)
    if cloud.key == "gcp":
        zones = v.get("kubernetes_node_locations", [])
        if not isinstance(zones, list) or any(not isinstance(z, str) or not re.fullmatch(re.escape(cfg["region"]) + r"-[a-z]", z) for z in zones) or len(set(zones)) != len(zones):
            _error("GKE node locations must be distinct zones in the selected region.")
        if v.get("kubernetes_regional") and not zones:
            _error("Regional GKE requires explicit kubernetes_node_locations; node counts are per zone.")
    if cloud.key == "azure":
        if v.get("kubernetes_sku_tier", "Free") not in ("Free", "Standard"):
            _error("AKS tier must be Free or Standard.")
        zones = v.get("kubernetes_zones", [])
        if not isinstance(zones, list) or any(z not in ("1", "2", "3") for z in zones) or len(set(zones)) != len(zones):
            _error("AKS zones must be distinct strings 1, 2 or 3.")


def _changes(before, after, prefix=""):
    changes = []
    for key in sorted(set(before) | set(after)):
        path = f"{prefix}.{key}" if prefix else key
        a, b = before.get(key), after.get(key)
        if isinstance(a, dict) and isinstance(b, dict):
            changes += _changes(a, b, path)
        elif a != b:
            changes.append({"path": path, "before": a, "after": b})
    return changes


def _profile(cloud, env, cfg, name):
    if name not in PROFILES:
        _error("Profile must be lab, team or production.")
    result = export_spec(cloud, env, cfg)
    config = result["configuration"]
    variables = config.setdefault("vars", {})
    extra = config.setdefault("extra_vars", {})
    production = name == "production"
    # Set prompted variables where the cloud adapter actually consumes them, raw overrides otherwise.
    def setvar(key, value):
        if cloud.question(key):
            variables[key] = value
            extra.pop(key, None)
        else:
            extra[key] = value
    setvar("enable_kubernetes", True)
    if cloud.key != "vmware":
        setvar("kubernetes_public_endpoint", False)
        setvar("kubernetes_node_count", 3 if production else 2 if name == "team" else 1)
        extra.update(kubernetes_node_min=3 if production else 1, kubernetes_node_max=6 if production else 3)
    if cloud.key == "aws":
        setvar("az_count", 3 if production else 2)
        setvar("single_nat_gateway", not production)
        extra.update(enable_flow_logs=True, log_retention_days=365 if production else 30)
    elif cloud.key == "gcp":
        region = config["region"]
        first = "b" if region in ("us-east1", "europe-west1") else "a"
        zones = [region + "-" + chr(ord(first) + i) for i in range(3)] if production else []
        extra.update(kubernetes_regional=production, kubernetes_node_locations=zones,
                     kubernetes_node_min=1, log_retention_days=365 if production else 30)
        if production:
            extra["enable_data_access_audit_logs"] = True
        setvar("kubernetes_node_count", 1 if production else 2 if name == "team" else 1)
        extra["kubernetes_node_max"] = 3 if production else 3
    elif cloud.key == "azure":
        extra.update(kubernetes_sku_tier="Standard" if name != "lab" else "Free",
                     kubernetes_zones=["1", "2", "3"] if production else [], log_retention_days=365 if production else 30)
    else:
        setvar("kubernetes_control_planes", 3 if production else 1)
        setvar("kubernetes_workers", 3 if production else 2 if name == "team" else 1)
    operations = result.setdefault("operations", {})
    operations.update(profile=name, block_destroy=production, require_complete_cost=True,
                      backup={"schedule": "0 2 * * *", "ttl": "2160h" if production else "720h" if name == "team" else "168h", "namespaces": []})
    validate_spec(result, cloud, env)
    return result


def execute(action, cloud, env, cfg, params):
    if action not in ("profile", "spec-export", "spec-validate", "spec-diff", "spec-import"):
        _error("Unknown blueprint operation.")
    if "approve" in params and type(params["approve"]) is not bool:
        _error("approve must be boolean.")
    if action == "spec-validate" and env is None:
        from types import SimpleNamespace
        from . import clouds
        incoming = params.get("spec")
        if not isinstance(incoming, dict) or incoming.get("cloud") not in clouds.CLOUDS or not re.fullmatch(r"[a-z][a-z0-9-]{1,23}", str(incoming.get("environment", ""))):
            _error("Specification requires a supported cloud and a valid environment name.")
        cloud = cloud or clouds.get(incoming["cloud"])
        env = SimpleNamespace(name=incoming["environment"], id=incoming["cloud"] + "-" + incoming["environment"])
    before = export_spec(cloud, env, cfg)
    spec = before if action == "spec-export" else (_profile(cloud, env, cfg, params.get("profile", "team")) if action == "profile" else validate_spec(params.get("spec"), cloud, env))
    report = {"schema_version": 1, "action": action, "env": env.id, "verdict": "PASS", "saved": False,
              "spec": spec, "changes": _changes(before, spec), "notes": [
                  "Specifications exclude credentials, SSH keys, runtime paths, resource state and environment ownership IDs.",
                  "Profile/import saves desired configuration only. Review Terraform plan before apply; topology changes can replace clusters or rotate nodes.",
                  "Backup schedule and platform lists are desired intent; run the DR and platform actions explicitly to install them."]}
    if action == "profile":
        from .guardrails import cost_preview
        candidate = {**copy.deepcopy(cfg), **spec["configuration"], "operations": spec.get("operations", {})}
        report["cost"] = cost_preview(cloud, env, candidate)
        if cloud.key == "gcp":
            report["notes"].append("GKE node count/min/max are per zone. Production requests three zones with one initial node each; validate zone and quota availability before apply.")
        if cloud.key == "azure":
            report["notes"].append("Confirm AKS zone/VM-size availability and quota in your region. Standard tier is paid; its fee is not priced by the local estimator.")
        if cloud.key == "vmware":
            report["notes"].append("Multiple VMware control planes on one physical host do not provide host-level high availability.")
    if action in ("profile", "spec-import") and params.get("approve"):
        with env.lock("save " + action):
            current = env.load() if env.exists() else copy.deepcopy(cfg)
            if export_spec(cloud, env, current) != before:
                _error("Environment configuration changed during review; preview again before saving.")
            candidate = copy.deepcopy(current)
            for key in CONFIG_KEYS:
                if key in spec["configuration"]:
                    candidate[key] = copy.deepcopy(spec["configuration"][key])
                else:
                    candidate.pop(key, None)
            # Preserve machine-specific/auth-only question values omitted from portable specs.
            for bucket in ("vars", "extra_vars"):
                for key, value in (current.get(bucket) or {}).items():
                    if not _safe_key(key):
                        candidate.setdefault(bucket, {})[key] = value
            candidate.update(cloud=cloud.key, env=env.name, operations=copy.deepcopy(spec.get("operations", {})))
            env.save(candidate)
            report["saved"] = True
    return report


def load_spec(path):
    """Read JSON or the portable YAML subset, without third-party/object constructors.

    YAML supports indented mappings, scalar lists, JSON flow lists/objects and quoted
    strings. Tags, aliases, anchors, merge keys, block strings and multiple documents
    are deliberately rejected. Exported JSON is also valid cloudseed.yaml content.
    """
    import os
    import stat
    from pathlib import Path
    fd = None
    try:
        fd = os.open(Path(path).expanduser(), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            _error("Specification input must be a regular file.")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(512 * 1024 + 1)
    except (OSError, TypeError, ValueError):
        _error("Cannot read specification input file.")
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > 512 * 1024:
        _error("Specification exceeds 512 KiB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        _error("Specification must be UTF-8 text.")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _error("Duplicate specification mapping key.")
            result[key] = value
        return result
    def json_value(value):
        return json.loads(value, object_pairs_hook=unique, parse_constant=lambda _: _error("Non-finite specification number."))
    if text.lstrip().startswith(("{", "[")):
        try:
            result = json_value(text)
        except (ValueError, RecursionError):
            _error("Invalid JSON specification.")
    else:
        def uncomment(line):
            quote = None
            escaped = False
            for index, char in enumerate(line):
                if escaped:
                    escaped = False
                elif char == "\\" and quote == '"':
                    escaped = True
                elif quote:
                    if char == quote:
                        quote = None
                elif char in ("'", '"'):
                    quote = char
                elif char == "#" and (index == 0 or line[index - 1].isspace()):
                    return line[:index].rstrip()
            return line.rstrip()
        lines = []
        for line in text.splitlines():
            if "\t" in line:
                _error("YAML indentation must use spaces, not tabs.")
            line = uncomment(line)
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            content = line.strip()
            if content in ("---", "...") or content.startswith(("%", "!", "&", "*")):
                _error("YAML documents, directives, tags, anchors and aliases are unsupported.")
            lines.append((indent, content))
        def scalar(value):
            if not value:
                return None
            if value.startswith(("!", "&", "*", "|", ">")):
                _error("YAML tags, anchors, aliases and block strings are unsupported.")
            if value[0] in '[{"':
                try:
                    return json_value(value)
                except (ValueError, RecursionError):
                    _error("YAML flow values must use JSON syntax with quoted keys/strings.")
            if value.startswith("'"):
                if not value.endswith("'") or len(value) < 2:
                    _error("Unterminated YAML string.")
                return value[1:-1].replace("''", "'")
            if value in ("true", "false", "null", "~"):
                return {"true": True, "false": False, "null": None, "~": None}[value]
            if re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", value):
                return json_value(value)
            if value.lower() in (".nan", ".inf", "-.inf", "+.inf"):
                _error("Non-finite specification number.")
            return value
        def block(index, indent, depth=0):
            if depth > 12:
                _error("Specification exceeds 12 nesting levels.")
            is_list = lines[index][1].startswith("- ") or lines[index][1] == "-"
            result = [] if is_list else {}
            while index < len(lines) and lines[index][0] == indent:
                content = lines[index][1]
                if is_list:
                    if not content.startswith("- "):
                        _error("YAML lists must contain scalar values on each line.")
                    result.append(scalar(content[2:].strip()))
                    index += 1
                else:
                    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.-]*):(?:\s+(.*))?", content)
                    if not match or match[1] == "<<":
                        _error("YAML mappings require simple field names; merge keys are unsupported.")
                    key, value = match[1], match[2]
                    if key in result:
                        _error("Duplicate specification mapping key.")
                    index += 1
                    if value is None and index < len(lines) and lines[index][0] > indent:
                        result[key], index = block(index, lines[index][0], depth + 1)
                    else:
                        result[key] = scalar(value or "")
                if index < len(lines) and lines[index][0] > indent:
                    _error("Unexpected YAML indentation.")
            return result, index
        if not lines or lines[0][0] != 0:
            _error("YAML specification must start with a root mapping.")
        result, consumed = block(0, 0)
        if consumed != len(lines):
            _error("Inconsistent YAML indentation.")
    if not isinstance(result, dict):
        _error("Specification root must be an object.")
    _bounded(result)
    return result
