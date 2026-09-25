"""One contract for operational workflows in the CLI, MCP, console and agents.

Execution stays in the domain modules. This registry owns input validation, effect
classification and transport argument construction; transports never infer safety
from a command's spelling or from a client-provided result.
"""
from __future__ import annotations

import importlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path

CLOUDS = ["aws", "gcp", "azure", "vmware"]


def text(description="", **kw):
    return dict(type="string", description=description, **kw)


def flag(description="", **kw):
    return dict(type="boolean", description=description, **kw)


def count(description="", minimum=1, maximum=3600):
    return dict(type="integer", description=description, minimum=minimum, maximum=maximum)


OBJECT = {"type": "object", "additionalProperties": True}
TIMEOUT = count("Timeout in seconds", maximum=7200)


@dataclass(frozen=True)
class Operation:
    name: str
    module: str
    description: str
    parameters: dict = field(default_factory=dict)
    effect: str = "read"
    requires_env: bool = True

    def changing(self, params):
        return self.effect == "change" or (self.effect == "live" and bool(params.get("live"))) or (self.effect == "active" and bool(params.get("active"))) or (
            self.effect == "save" and bool(params.get("approve")))


OPERATIONS = {
    op.name: op for op in (
        Operation("credentials-backend", "credential_store", "Inspect or migrate credential storage to the native OS keychain.",
                  {"backend": text(enum=["file", "os-keychain"])}, "save", requires_env=False),
        Operation("acceptance", "acceptance", "Preview or execute an isolated real-cloud lifecycle with identity, spend-estimate and cleanup guards.",
                  {"live": flag(), "allow_cloud_changes": flag(), "identity": text(), "region": text(),
                   "max_budget_usd": {"type": "number", "minimum": 0}, "estimated_hourly_usd": {"type": "number", "minimum": 0},
                   "max_duration_minutes": count(minimum=30, maximum=360), "allow_ip": text()}, "live", requires_env=False),
        Operation("release-verify", "releases", "Verify downloaded artifact integrity and signed release-workflow provenance without executing it.",
                  {"artifact": text(), "sha256": text(), "verify_attestation": flag()}, requires_env=False),
        Operation("expiry-plan", "guardrails", "Preview cleanup of an explicitly opted-in expired environment."),
        Operation("expiry-cleanup", "guardrails", "Destroy only the reviewed, expired, opted-in environment; retain local recovery state.", {}, "change"),
        Operation("health", "health", "Environment health with explicit evidence and freshness; live queries are opt-in.",
                  {"live": flag("Query deployed resources"), "timeout": count(minimum=5, maximum=300), "max_age_days": count("Evidence age", maximum=365)}),
        Operation("network", "health", "Diagnose private cluster DNS, API, registry and outbound connectivity.",
                  {"live": flag("Query the cluster"), "active": flag("Create and clean up a temporary diagnostic workload"),
                   "timeout": count(minimum=5, maximum=300), "endpoints": {"type": "array", "items": text()}}, "active"),
        Operation("profile", "blueprints", "Preview or save a lab, team or production deployment profile; never applies infrastructure.",
                  {"profile": text(enum=["lab", "team", "production"])}, "save"),
        Operation("spec-export", "blueprints", "Export a portable environment specification without credentials or local state.",
                  {"output": text("Optional destination file for the portable specification (JSON, also valid YAML)")}),
        Operation("spec-validate", "blueprints", "Validate a versioned portable specification without cloud calls.",
                  {"spec": OBJECT}, requires_env=False),
        Operation("spec-diff", "blueprints", "Compare a portable specification with the saved environment.", {"spec": OBJECT}),
        Operation("spec-import", "blueprints", "Preview or save a validated portable specification; never applies infrastructure.",
                  {"spec": OBJECT}, "save"),
        Operation("policy-check", "guardrails", "Evaluate cost coverage, budget, expiry and destructive-change policy before apply.",
                  {"plan": OBJECT, "estimate": OBJECT, "budget_max_monthly": {"type": "number", "minimum": 0},
                   "allow_destroy": flag(), "require_complete_cost": flag(default=True), "block_destroy": flag(), "expires_at": text(), "cleanup_opt_in": flag()}),
        Operation("drift", "lifecycle", "Compare deployed infrastructure, Terraform state and intended configuration without applying.",
                  {"timeout_s": TIMEOUT}),
        Operation("upgrade-plan", "lifecycle", "Record a pinned upgrade plan with readiness, compatibility and backup checks.",
                  {"target_version": text(), "backup": text(), "timeout_s": TIMEOUT, "kubeadm_package_version": text(),
                   "compatibility_reviewed": flag("Explicitly attest that charts, CRDs and plugins were reviewed")}),
        Operation("upgrade-apply", "lifecycle", "Execute an approved, fresh upgrade plan with health gates and recovery evidence.",
                  {"plan": text("Path of the reviewed upgrade plan"), "timeout_s": TIMEOUT}, "change"),
        Operation("recovery-plan", "recovery", "Plan an application restore into a separate namespace; original workload is preserved.",
                  {"namespace": text(), "selector": text(), "timeout_s": TIMEOUT, "rto_seconds": count(maximum=86400),
                   "rpo_seconds": count(maximum=2592000), "verify_data": flag(default=False), "with_volumes": flag(default=False), "keep": flag(),
                   "isolation_reviewed": flag(), "consistency_hook": text(enum=["none", "filesystem-sync", "postgres-checkpoint"]),
                   "pod": text(), "container": text(), "data_file": text()}),
        Operation("recovery-test", "recovery", "Back up and restore a selected application to an isolated namespace and verify recovery.",
                  {"namespace": text(), "selector": text(), "timeout_s": TIMEOUT, "rto_seconds": count(maximum=86400),
                   "rpo_seconds": count(maximum=2592000), "verify_data": flag(default=False), "with_volumes": flag(default=False), "keep": flag(),
                   "isolation_reviewed": flag(), "consistency_hook": text(enum=["none", "filesystem-sync", "postgres-checkpoint"]),
                   "pod": text(), "container": text(), "data_file": text()}, "change"),
    )
}


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _validate(value, schema, path):
    kind = schema.get("type")
    good = {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str),
            "boolean": isinstance(value, bool), "integer": type(value) is int,
            "number": _finite(value)}.get(kind, False)
    if not good:
        raise ValueError(f"{path}: expected {kind}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: choose from {', '.join(schema['enum'])}")
    for bound, compare in (("minimum", lambda a, b: a < b), ("maximum", lambda a, b: a > b)):
        if bound in schema and compare(value, schema[bound]):
            raise ValueError(f"{path}: outside permitted range")
    if kind == "array":
        if len(value) > 100:
            raise ValueError(f"{path}: at most 100 entries")
        for i, item in enumerate(value):
            _validate(item, schema["items"], f"{path}[{i}]")


def validate(name, params):
    op = OPERATIONS[name]
    if not isinstance(params, dict):
        raise ValueError("operation parameters must be an object")
    schema = dict(op.parameters, approve=flag())
    unknown = set(params) - set(schema)
    if unknown:
        raise ValueError("Unsupported parameters: " + ", ".join(sorted(unknown)))
    for key, value in params.items():
        _validate(value, schema[key], key)
    if len(json.dumps(params, allow_nan=False).encode()) > 1024 * 1024:
        raise ValueError("Operation input exceeds 1 MiB")
    return op


def execute(name, cloud, env, cfg, params):
    op = validate(name, params)
    if op.changing(params) and not params.get("approve"):
        raise ValueError(f"{name} requires explicit approval (--approve / confirm=true)")
    module = importlib.import_module("." + op.module, __package__)
    from contextlib import nullcontext
    lock = env.lock(f"ops {name}") if env is not None and (op.changing(params) or name in ("drift", "upgrade-plan")) else nullcontext()
    with lock:
        if env is not None and (op.changing(params) or name in ("drift", "upgrade-plan")) and env.exists() and env.load() != cfg:
            raise ValueError("Environment configuration changed while waiting for the lock; review and retry the operation.")
        result = module.execute(name, cloud, env, cfg, dict(params))
    if not isinstance(result, dict):
        raise TypeError(f"{name} did not return a structured report")
    result.setdefault("schema_version", 1)
    result.setdefault("operation", name)
    if name in ("health", "network") and env is not None:
        from . import scan
        result["report"] = str(scan.save_report(env, name, result))
    if name == "spec-export" and params.get("output"):
        from . import paths
        destination = Path(params["output"]).expanduser().absolute()
        if destination.exists():
            if not destination.is_file() or destination.is_symlink() or destination.stat().st_size > 1024 * 1024:
                raise ValueError("Existing export destination must be a regular file no larger than 1 MiB")
            from uuid import uuid4
            backup = destination.with_name(destination.name + "." + uuid4().hex[:12] + ".bak")
            paths.atomic_write(backup, destination.read_text())
            result["previous_output"] = str(backup)
        paths.atomic_write(destination, json.dumps(result["spec"], indent=2, allow_nan=False) + "\n")
        result["output"] = str(destination)
    if env is not None and not result.get("report"):
        from . import paths, scan
        from datetime import datetime, timezone
        from uuid import uuid4
        result.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
        result.setdefault("kind", name)
        result.setdefault("run", scan.run_stamp() + "-" + uuid4().hex[:8])
        report_path = env.dir / "operations" / (name + "-" + result["run"] + ".json")
        if report_path.parent.is_symlink():
            raise ValueError("The operations report directory must not be a symlink")
        result["report"] = str(report_path)
        paths.atomic_write(report_path, json.dumps(result, indent=2, allow_nan=False) + "\n")
    return result


def exit_code(result):
    verdict = str(result.get("verdict", result.get("status", "INCOMPLETE"))).upper()
    if verdict in ("FAIL", "FAILED", "BLOCKED", "ERROR"):
        return 1
    return 0 if verdict in ("PASS", "PLAN") else 3


def argv(name, args):
    params = {k: v for k, v in args.items() if k not in ("cloud", "env", "json", "confirm")}
    if args.get("confirm"):
        params["approve"] = True
    validate(name, params)
    words = ["ops", name]
    if args.get("cloud"):
        words.append(args["cloud"])
    if args.get("env"):
        words += ["--env", args["env"]]
    words += ["--params", json.dumps(params, separators=(",", ":"))]
    if args.get("json", True):
        words.append("--json")
    return words


def mcp_tools():
    tools = {}
    for name, op in OPERATIONS.items():
        props = {"cloud": text(enum=CLOUDS), "env": text(pattern=r"^[a-z][a-z0-9-]{1,23}$"),
                 **op.parameters, "json": flag("Return structured JSON (default true)", default=True)}
        if op.effect != "read":
            props["confirm"] = flag("Approve the described change")
        def changing(args, selected=op):
            return selected.changing(dict(args, approve=bool(args.get("confirm"))))
        tools["cloudseed_ops_" + name.replace("-", "_")] = {
            "description": op.description, "schema": {"type": "object", "properties": props, "additionalProperties": False},
            "argv": lambda a, selected=name: argv(selected, a), "writes": True,
            "json_stdout": True, "operation": name,
        }
        if op.effect != "read":
            tools["cloudseed_ops_" + name.replace("-", "_")].update(
                destructive_when=changing, confirm_when="changes need confirm=true; previews do not")
    return tools


def parser(sub):
    p = sub.add_parser("ops", help="health, network, profiles, specifications, policy, drift, upgrades and recovery")
    p.add_argument("ops_cmd", choices=["list"] + list(OPERATIONS))
    p.add_argument("cloud", nargs="?", choices=CLOUDS)
    p.add_argument("--env", "-e")
    p.add_argument("--params", default="{}", help="JSON object of operation parameters (see cs ops list --json)")
    p.add_argument("--input", type=Path, help="JSON/YAML portable specification; for spec operations")
    p.add_argument("--output", help="Destination file for spec-export")
    p.add_argument("--approve", action="store_true", help="approve this operation's described effects")
    p.add_argument("--json", action="store_true")
    # Friendly flags for common workflows. Complex specs remain structured objects.
    p.add_argument("--profile", choices=["lab", "team", "production"])
    p.add_argument("--live", action="store_true", default=None)
    p.add_argument("--active", action="store_true", default=None)
    p.add_argument("--namespace")
    p.add_argument("--target-version")
    p.add_argument("--plan")
    p.add_argument("--backup")
    return p


def parameters(args):
    try:
        params = json.loads(args.params)
    except (ValueError, TypeError) as exc:
        raise ValueError("--params must be a JSON object") from exc
    if not isinstance(params, dict):
        raise ValueError("--params must be a JSON object")
    for key in ("profile", "live", "active", "namespace", "target_version", "plan", "backup", "output"):
        value = getattr(args, key, None)
        if value is not None:
            if key in params and params[key] != value:
                raise ValueError(f"{key} supplied twice with different values")
            params[key] = value
    if args.input:
        from . import blueprints
        params["spec"] = blueprints.load_spec(args.input)
    if args.approve:
        params["approve"] = True
    validate(args.ops_cmd, params)
    return params


def contract():
    return [{"name": op.name, "description": op.description, "effect": op.effect,
             "requires_env": op.requires_env, "parameters": op.parameters,
             "mcp_tool": "cloudseed_ops_" + op.name.replace("-", "_")} for op in OPERATIONS.values()]
