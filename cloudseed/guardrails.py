"""Offline cost and Terraform policy previews; explicit fail-closed application gates.

No budget is a billing cap. Expiry is an operator-reviewed cleanup plan, never a timer.
"""
from __future__ import annotations

import math
import contextlib
import contextvars
import copy
from datetime import datetime, timezone

from . import finops, paths, ui
from .blueprints import validate_operations, _finite_number


_DESTROY_ALLOWANCES = contextvars.ContextVar("cloudseed_explicit_destroy_allowances", default=frozenset())


@contextlib.contextmanager
def allow_destroy_for(env_id):
    """Internal scope used after explicit destroy approval; never a public policy option."""
    token = _DESTROY_ALLOWANCES.set(_DESTROY_ALLOWANCES.get() | {env_id})
    try:
        yield
    finally:
        _DESTROY_ALLOWANCES.reset(token)


def cost_preview(cloud, env, cfg):
    try:
        estimate = finops.estimate(cloud, env, cfg, use_inventory=False)
    except (OverflowError, ValueError, TypeError):
        raise ui.Abort("Cost estimation requires finite, valid configuration values.", code=2) from None
    return {"currency": "USD", "period": "month", "known_monthly": estimate["total"],
            "coverage_complete": False, "source": "offline reference-region list prices",
            "components": [{"name": name, "monthly": amount} for name, amount in estimate["lines"]],
            "unpriced": list(estimate["unpriced"]) + ["Traffic/NAT processing", "Actual log and backup volume", "Regional and contractual pricing", "Application usage and autoscaling above initial capacity"],
            "notes": estimate["notes"] + ["This is an approximate partial estimate, not a bill, quote or spend cap."]}


def _plan_changes(plan):
    if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes"), list):
        raise ui.Abort("plan must be Terraform show -json data with resource_changes.", code=2)
    changes = []
    for resource in plan["resource_changes"]:
        if not isinstance(resource, dict) or not isinstance(resource.get("change"), dict):
            raise ui.Abort("Malformed Terraform resource change.", code=2)
        actions = resource["change"].get("actions")
        if not isinstance(actions, list) or not actions or any(a not in ("no-op", "read", "create", "update", "delete", "forget") for a in actions):
            raise ui.Abort("Unsupported or malformed Terraform plan actions.", code=2)
        address = resource.get("address")
        if not isinstance(address, str) or not address or len(address) > 1024:
            raise ui.Abort("Malformed Terraform resource address.", code=2)
        changes.append({"address": address, "actions": actions, "destructive": "delete" in actions or "forget" in actions})
    return changes


def execute(action, cloud, env, cfg, params):
    if action in ("expiry-plan", "expiry-cleanup"):
        return _expiry(action, cloud, env, cfg, params)
    if action != "policy-check":
        raise ui.Abort("Unknown guardrail operation.", code=2)
    policy = dict(cfg.get("operations") or {})
    for key in ("budget_max_monthly", "require_complete_cost", "block_destroy", "expires_at", "cleanup_opt_in"):
        if key in params:
            policy[key] = params[key]
    validate_operations(policy)
    if "allow_destroy" in params and type(params["allow_destroy"]) is not bool:
        raise ui.Abort("allow_destroy must be boolean.", code=2)
    estimate = params.get("estimate")
    if estimate is None:
        estimate = cost_preview(cloud, env, cfg)
    elif not isinstance(estimate, dict) or set(estimate) - {"currency", "period", "known_monthly", "coverage_complete", "unpriced", "source", "notes", "components"}:
        raise ui.Abort("Estimate must use currency, period, known_monthly, coverage_complete and optional coverage details.", code=2)
    amount = estimate.get("known_monthly")
    if not _finite_number(amount) or amount < 0 or estimate.get("currency") != "USD" or estimate.get("period") != "month" or type(estimate.get("coverage_complete")) is not bool:
        raise ui.Abort("Estimate requires finite nonnegative known_monthly, currency USD, period month and boolean coverage_complete.", code=2)
    if estimate["coverage_complete"] and estimate.get("unpriced"):
        raise ui.Abort("An estimate with unpriced components cannot claim complete coverage.", code=2)
    checks = []
    def check(id_, status, detail):
        checks.append({"id": id_, "status": status, "detail": detail})
    budget = policy.get("budget_max_monthly")
    if budget is not None:
        if amount > budget:
            check("cost.budget", "BLOCKED", f"Known monthly estimate ${amount:.2f} exceeds the ${budget:.2f} budget.")
        elif not estimate["coverage_complete"]:
            check("cost.budget", "BLOCKED" if policy.get("require_complete_cost", True) else "UNKNOWN",
                  "Known costs fit the budget but coverage is incomplete; total spend cannot be established.")
        else:
            check("cost.budget", "PASS", "The supplied monthly estimate fits the configured budget; actual spend may vary.")
    else:
        check("cost.budget", "UNKNOWN", "No monthly budget is configured; this preview does not limit spend.")
    changes = _plan_changes(params["plan"]) if "plan" in params else None
    destructive = [change for change in changes or [] if change["destructive"]]
    if changes is None:
        check("plan.destructive", "BLOCKED" if policy.get("block_destroy") else "UNKNOWN", "No Terraform JSON plan supplied; resource deletions and replacements cannot be evaluated.")
    elif destructive:
        blocked = policy.get("block_destroy", True) and not params.get("allow_destroy", False)
        check("plan.destructive", "BLOCKED" if blocked else "UNKNOWN", f"Plan contains {len(destructive)} deletions, replacements or forget operations; explicit review is required.")
    else:
        check("plan.destructive", "PASS", "No delete, replacement or forget actions in the supplied Terraform plan.")
    # The same declaration validator applies for previews and apply gates.
    from .architecture import assess
    architecture = assess(cloud, env, cfg, profile="production" if policy.get("profile") == "production" else "lab")
    security = [f for f in architecture["findings"] if f["pillar"] == "security" and f["status"] == "FAIL"
                and any(isinstance(e, dict) and e.get("type") == "declared_configuration" for e in f.get("evidence", []))]
    check("security.declarations", "BLOCKED" if security else "UNKNOWN", "Declared security failures: " + ", ".join(f["id"] for f in security) if security else "No definite declaration failures; live workload policy effects are not established.")
    cleanup = {"opted_in": bool(policy.get("cleanup_opt_in")), "due": False, "scheduled": False,
               "instruction": "Review a Terraform destroy plan and explicitly run the existing destroy action; no deletion is scheduled."}
    if policy.get("expires_at"):
        stamp = datetime.fromisoformat(policy["expires_at"].replace("Z", "+00:00"))
        cleanup.update(expires_at=policy["expires_at"], due=stamp <= datetime.now(timezone.utc))
        check("lifecycle.expiry", "UNKNOWN" if cleanup["due"] else "PASS", "Expiry is due; review cleanup explicitly." if cleanup["due"] else "Expiry is in the future; no automatic cleanup is configured.")
    blocked = any(c["status"] == "BLOCKED" for c in checks)
    return {"schema_version": 1, "action": action, "env": env.id,
            "verdict": "BLOCKED" if blocked else "INCOMPLETE" if any(c["status"] == "UNKNOWN" for c in checks) else "PASS",
            "allowed": not blocked, "checks": checks, "cost": estimate, "destructive_changes": destructive,
            "cleanup": cleanup, "notes": ["Policy previews inspect supplied plans and declared configuration; they do not simulate admission of existing workloads.",
                                           "Only explicitly configured apply gates enforce these decisions. Budget estimates do not cap cloud billing."]}


def enforce(cloud, env, cfg, *, plan=None, estimate=None):
    """Apply integration: call with the exact saved plan's JSON before Terraform apply.

    No operations policy means existing behavior is preserved. Never silently use a
    caller-supplied allow_destroy override in an unattended deployment.
    """
    if not cfg.get("operations"):
        return None
    params = {}
    if plan is not None:
        params["plan"] = plan
    if estimate is not None:
        params["estimate"] = estimate
    explicit = env.id in _DESTROY_ALLOWANCES.get()
    changes = _plan_changes(plan) if explicit and plan is not None else None
    teardown = explicit and changes is not None and all(set(c["actions"]) <= {"no-op", "read", "delete", "forget"} for c in changes)
    checked_cfg = copy.deepcopy(cfg)
    if teardown:
        params["allow_destroy"] = True
        checked_cfg["operations"].pop("budget_max_monthly", None)
    report = execute("policy-check", cloud, env, checked_cfg, params)
    if teardown:
        # A verified deletion-only plan reduces exposure. Existing unsafe declarations
        # must not trap those resources by preventing their explicitly approved removal.
        for check in report["checks"]:
            if check["id"] == "security.declarations":
                check.update(status="NOT_APPLICABLE", detail="Explicitly approved deletion-only plan; no infrastructure is created or updated.")
        report["allowed"] = not any(c["status"] == "BLOCKED" for c in report["checks"])
        report["verdict"] = "INCOMPLETE" if report["allowed"] else "BLOCKED"
        report["lifecycle"] = "destroy"
    if not report["allowed"]:
        details = "; ".join(c["detail"] for c in report["checks"] if c["status"] == "BLOCKED")
        raise ui.Abort("Deployment guardrails blocked this plan: " + details, code=2)
    return report



def _expiry(action, cloud, env, cfg, params):
    from . import audit
    policy = cfg.get("operations") or {}
    validate_operations(policy)
    due = bool(policy.get("expires_at")) and datetime.fromisoformat(policy["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc)
    eligible = bool(due and policy.get("cleanup_opt_in"))
    command = ["destroy", cloud.key, "--env", env.name, "--auto-approve"]
    report = {"schema_version": 1, "action": action, "env": env.id, "verdict": "PASS" if eligible else "BLOCKED",
              "eligible": eligible, "due": due, "cleanup_opt_in": bool(policy.get("cleanup_opt_in")),
              "expires_at": policy.get("expires_at"), "executed": False, "purge": False, "purge_state": False,
              "command": ["cs", *command], "notes": ["Cleanup runs only for this explicitly selected environment. Configuration and state storage are retained.",
                                                     "The existing destroy operation creates and applies its destroy plan; shared cloud settings are retained by its existing protections."]}
    if action == "expiry-plan" or not params.get("approve"):
        report["notes"].append("Execution requires --approve, a saved elapsed expires_at and saved cleanup_opt_in=true; no scheduler is created.")
        return report
    if type(params.get("approve")) is not bool:
        raise ui.Abort("approve must be boolean.", code=2)
    if not eligible:
        raise ui.Abort("Expiry cleanup requires a saved elapsed expires_at and saved cleanup_opt_in=true.", code=2)
    with env.lock("expiry cleanup"):
        current = env.load()
        if current != cfg:
            raise ui.Abort("Environment changed since the expiry review; review it again before cleanup.", code=2)
        from . import cli
        args = cli.build_parser().parse_args(command)
        # cmd_destroy owns the cloud-aware drain/plan/shared-resource retention logic.
        with allow_destroy_for(env.id):
            result = cli.cmd_destroy(args, paths.load_settings())
        report.update(executed=True, exit_code=result, verdict="PASS" if result == 0 else "FAIL")
        report["notes"].append("Destroy completion is recorded; retained shared resources are documented by the destroy operation.")
        audit.note(env, "expiry-cleanup", {"exit_code": result, "expires_at": policy["expires_at"], "purge": False, "purge_state": False})
    return report
