"""Opt-in real-cloud lifecycle acceptance with durable ownership and cleanup evidence.

Preview is entirely local. A live run is intentionally separate from the selected environment: an isolated
Cloudseed home, unique resource name, local Terraform state and a cleanup manifest are retained for recovery.
An estimated cost gate and wall-clock deadline are not a cloud-provider spending cap.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import secrets
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from . import architecture, deps, health, paths, ui

CLOUDS = ("aws", "gcp", "azure")
LIMITATIONS = [
    "Preview does not contact any provider and is not real cloud acceptance.",
    "Budget enforcement is a caller-supplied estimate plus a time deadline, not a provider billing hard cap. Cleanup and retained resources can incur additional charges.",
    "This lifecycle covers a small Kubernetes environment, Velero chart, a tag change, and a volume restore drill. It does not certify every catalog chart or cloud region.",
    "Terraform empty-state verification does not establish that every provider-side resource or billing charge is gone. Review the provider inventory and billing after cleanup.",
    "GCP APIs must already be enabled. AWS KMS deletion schedules and provider logs may outlive the test; the cleanup manifest and state are deliberately retained.",
]


def _numeric(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value > 0
    except OverflowError:
        return False


def _guard(cloud, params):
    problems = []
    identity, region = params.get("identity", ""), params.get("region", "")
    pattern = {"aws": r"\d{12}", "gcp": r"[a-z][a-z0-9-]{4,28}[a-z0-9]", "azure": r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"}[cloud]
    if not isinstance(identity, str) or not re.fullmatch(pattern, identity):
        problems.append("Supply an explicit sandbox account, project or subscription identifier for the selected cloud.")
    if not isinstance(region, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,39}", region):
        problems.append("Supply an explicit region.")
    budget, hourly = params.get("max_budget_usd"), params.get("estimated_hourly_usd")
    if not _numeric(budget) or not _numeric(hourly):
        problems.append("Supply positive finite max_budget_usd and estimated_hourly_usd values.")
    duration = params.get("max_duration_minutes", 120)
    if type(duration) is not int or not 30 <= duration <= 360:
        problems.append("max_duration_minutes must be an integer from 30 to 360.")
    elif _numeric(budget) and _numeric(hourly) and hourly * duration / 60 * 1.5 > budget:
        problems.append("Estimated run cost plus a 50% cleanup reserve exceeds max_budget_usd.")
    try:
        source = params.get("allow_ip", "")
        if not isinstance(source, str) or not source.endswith("/32"):
            raise ValueError()
        address = ipaddress.ip_network(source, strict=True)
        if address.version != 4 or address.prefixlen != 32 or not address.network_address.is_global:
            raise ValueError()
    except (ValueError, TypeError):
        problems.append("Supply allow_ip as your explicit public IPv4 /32 for bastion access.")
    return problems


def _launcher():
    return [sys.executable] if paths.IS_BUNDLE else [sys.executable, str(paths.REPO_ROOT / "bin" / "cloudseed")]


def _plan(cloud, name, params):
    identity, region, allow_ip = (params.get(k) or f"<{k}>" for k in ("identity", "region", "allow_ip"))
    selection = [cloud, "--env", name]
    setup = ["setup", *selection, "--name", "accept", "--region", region, "--state", "local", "--allow-ip", allow_ip,
             "--var", "enable_kubernetes=true", "--var", "kubernetes_node_count=2", "--var", "enable_vpn=false",
             "--tag", "acceptance=" + name, "--auto-approve"]
    # These checks must never change shared account/project security policy or adopt an existing baseline.
    if cloud == "aws":
        setup += ["--var", "enable_account_baseline=false", "--var", "enable_regional_baseline=false"]
    elif cloud == "gcp":
        setup += ["--project-id", identity, "--var", "enable_project_baseline=false", "--var", "enable_apis=false", "--var", "enable_os_login=false"]
    else:
        setup += ["--subscription-id", identity, "--var", "enable_defender=false"]
    return [
        {"id": "create", "title": "Create a unique isolated sandbox environment", "argv": setup},
        {"id": "readiness", "title": "Verify every cluster node is Ready", "argv": ["kubectl", *selection, "wait", "--for=condition=Ready", "node", "--all", "--timeout=300s"]},
        {"id": "chart", "title": "Install and wait for the pinned Velero chart and cloud backup prerequisites", "argv": ["platform", "install", "velero", *selection, "--auto-approve"]},
        {"id": "change", "title": "Apply a reversible environment tag change", "argv": ["setup", *selection, "--tag", "acceptancephase=changed", "--auto-approve", "--no-provision"]},
        {"id": "restore", "title": "Back up, delete and restore the sample workload including its volume", "argv": ["dr", "test", *selection, "--volume", "--auto-approve"]},
        {"id": "destroy", "title": "Destroy only this acceptance environment; preserve local state for verification", "argv": ["destroy", *selection, "--auto-approve"]},
    ]


def _identity(cloud, params, procenv):
    identity, region = params["identity"], params["region"]
    args = {"aws": ["aws", "sts", "get-caller-identity", "--region", region, "--output", "json"],
            "gcp": ["gcloud", "projects", "describe", identity, "--format=json"],
            "azure": ["az", "account", "show", "--subscription", identity, "--output", "json"]}[cloud]
    args[0] = deps.find(args[0]) or args[0]
    try:
        value = health._json(health._run(args, env=procenv, timeout=30))
    except OSError:
        value = None
    key = {"aws": "Account", "gcp": "projectId", "azure": "id"}[cloud]
    return isinstance(value, dict) and str(value.get(key, "")).lower() == identity.lower()


def _manifest_write(path, manifest):
    paths.atomic_write(path, json.dumps(manifest, indent=2, allow_nan=False) + "\n")


def _state_empty(env):
    state, reason = architecture._read_json(env, "stack/terraform.tfstate")
    if state is None or not isinstance(state.get("resources"), list):
        return False
    return all(isinstance(r, dict) and r.get("mode") == "data" for r in state["resources"])


def execute(action, cloud, env, cfg, params=None):
    """Preview or execute acceptance; see _guard for explicit account, region, cost, time and access requirements."""
    target = cloud if isinstance(cloud, str) else getattr(cloud, "key", None)
    if action != "acceptance" or target not in CLOUDS:
        raise ui.Abort("Real cloud acceptance supports aws, gcp and azure.", code=2)
    if env is None:
        env = SimpleNamespace(dir=paths.HOME / "acceptance-runs", id="acceptance-harness")
    params = {} if params is None else params
    if not isinstance(params, dict) or not isinstance(cfg, dict):
        raise ui.Abort("Acceptance requires configuration and options objects.", code=2)
    live, allowed = params.get("live", False), params.get("allow_cloud_changes", False)
    if type(live) is not bool or type(allowed) is not bool:
        raise ui.Abort("live and allow_cloud_changes must be booleans.", code=2)
    problems = _guard(target, params)
    if live and not allowed:
        problems.append("Live acceptance requires allow_cloud_changes=true in addition to live=true.")
    if live and problems:
        raise ui.Abort("Live acceptance refused: " + " ".join(problems), code=2)
    name = "accept-" + secrets.token_hex(6)
    now = datetime.now(timezone.utc)
    steps = _plan(target, name, params)
    findings = [health._finding("acceptance.prerequisites", "UNKNOWN" if problems else "PASS", "Sandbox and budget guards",
                               " ".join(problems) if problems else "Explicit sandbox, region, estimated cost, time and SSH limits are valid.",
                               "Supply the missing guards and review the lifecycle before authorizing execution.")]
    report = {"schema_version": 1, "kind": "acceptance", "cloud": target, "target": target, "env": env.id,
              "generated_at": now.isoformat().replace("+00:00", "Z"), "run": now.strftime("%Y%m%d-%H%M%S"),
              "live": live, "verdict": "INCOMPLETE", "acceptance_env": f"{target}-{name}", "plan": steps,
              "findings": findings, "coverage_limits": LIMITATIONS, "summary": {"preview": not live, "steps": len(steps)}}
    if not live:
        findings.append(health._finding("acceptance.lifecycle", "UNKNOWN", "Real cloud lifecycle", "Preview only; no resources were created and no provider was contacted.",
                                       "Provide a sandbox identity, region, budget and live execution authorization when available."))
        return report
    needed = ["terraform", "kubectl", "helm", "velero", "ssh", "ansible-playbook", {"aws": "aws", "gcp": "gcloud", "azure": "az"}[target]]
    if target == "gcp":
        needed.append("gke-gcloud-auth-plugin")
    missing = [tool for tool in needed if not deps.find(tool)]
    if missing:
        raise ui.Abort("Acceptance never installs tools. Install explicitly first: " + ", ".join(missing), code=2)
    procenv = deps.path_env()
    procenv.update(CLOUDSEED_AGENT="acceptance", CLOUDSEED_NONINTERACTIVE="1", CLOUDSEED_AUTO_INSTALL="0")
    # Provider identity and every child use the same selected credentials and explicit provider target.
    if target == "aws":
        profile = cfg.get("vars", {}).get("profile") if isinstance(cfg.get("vars"), dict) else None
        if profile:
            procenv["AWS_PROFILE"] = str(profile)
        procenv.update(AWS_REGION=params["region"], AWS_DEFAULT_REGION=params["region"])
    elif target == "gcp":
        procenv.update(GOOGLE_PROJECT=params["identity"], GOOGLE_CLOUD_PROJECT=params["identity"], CLOUDSDK_CORE_PROJECT=params["identity"])
    else:
        procenv.update(ARM_SUBSCRIPTION_ID=params["identity"], AZURE_SUBSCRIPTION_ID=params["identity"])
    if not _identity(target, params, procenv):
        raise ui.Abort("Acceptance refused: the selected provider identity could not be verified. No environment was created.", code=2)
    # tempfile's unpredictable directory plus a newly minted resource name prevents reusing or destroying user envs.
    base = Path(env.dir) / "acceptance"
    if base.is_symlink():
        raise ui.Abort("Refusing a symlinked acceptance run directory.", code=2)
    base.mkdir(parents=True, exist_ok=True)
    home = Path(tempfile.mkdtemp(prefix=name + "-", dir=str(base)))
    manifest_path = home / "cleanup.json"
    procenv["CLOUDSEED_HOME"] = str(home)
    child_env = SimpleNamespace(dir=home / "envs" / f"{target}-{name}", id=f"{target}-{name}", name=name)
    manifest = {"schema_version": 1, "owner": name, "cloud": target, "identity": params["identity"], "region": params["region"],
                "home": str(home), "env": child_env.id, "max_budget_usd": params["max_budget_usd"],
                "estimated_hourly_usd": params["estimated_hourly_usd"], "max_duration_minutes": params.get("max_duration_minutes", 120),
                "created_at": report["generated_at"], "cleanup": "pending", "cleanup_argv": steps[-1]["argv"], "steps": []}
    _manifest_write(manifest_path, manifest)
    report["manifest"] = str(manifest_path)
    report["cleanup_home"] = str(home)
    started = time.monotonic()
    deadline = started + params.get("max_duration_minutes", 120) * 60
    failed = False
    interrupted = False

    def run(step, seconds):
        before = time.monotonic()
        proc = health._run([*_launcher(), "--runtime", "local", "-y", *step["argv"]], env=procenv, timeout=seconds, graceful=True)
        result = {"id": step["id"], "exit_code": proc.returncode, "seconds": round(time.monotonic() - before, 2), "ok": proc.returncode == 0}
        manifest["steps"].append(result)
        _manifest_write(manifest_path, manifest)
        findings.append(health._finding("acceptance." + step["id"], "PASS" if result["ok"] else "FAIL", step["title"],
                                       f"Command exited {proc.returncode}; elapsed {result['seconds']} seconds. Output is not copied into the report.",
                                       "Inspect this isolated environment's audit and command logs.", live=True, **result))
        return result["ok"]

    with health._cleanup_on_term():
        try:
            for step in steps[:-1]:
                left = int(deadline - time.monotonic())
                if left <= 0:
                    failed = True
                    findings.append(health._finding("acceptance.deadline", "FAIL", "Execution deadline", "Time budget exhausted; proceeding to cleanup.", "Review the estimate and the failed step before rerunning.", live=True))
                    break
                if not run(step, left):
                    failed = True
                    break
        except (KeyboardInterrupt, OSError):
            failed, interrupted = True, True
            findings.append(health._finding("acceptance.interrupted", "FAIL", "Interrupted lifecycle", "The lifecycle was interrupted; cleanup was attempted.", "Review the cleanup manifest and any remaining resources.", live=True))
        finally:
            # Never a purge: a failed destroy must retain every recovery credential and Terraform record.
            try:
                child_cfg, _ = architecture._read_json(child_env, "config.json")
                owns = isinstance(child_cfg, dict) and child_cfg.get("cloud") == target and child_cfg.get("env") == name and child_cfg.get("name") == "accept"
                if owns:
                    cleaned = run(steps[-1], 1800)
                    empty = cleaned and _state_empty(child_env)
                    manifest["cleanup"] = "state_empty" if empty else "failed"
                else:
                    manifest["cleanup"] = "unknown"
                    empty = False
                findings.append(health._finding("acceptance.cleanup", "PASS" if empty else "UNKNOWN", "Terraform cleanup verification",
                                               "Destroy completed and the isolated Terraform state contains no managed resources." if empty else "No verified empty owned Terraform state; manual cleanup review is required.",
                                               "Use cleanup.json's CLOUDSEED_HOME and exact environment; never destroy a different environment.", live=empty))
            except (OSError, KeyboardInterrupt):
                manifest["cleanup"] = "failed"
                empty = False
            manifest["finished_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            _manifest_write(manifest_path, manifest)
    findings.append(health._finding("acceptance.provider_inventory", "UNKNOWN", "Provider residual resource review",
                                   "The harness does not enumerate all provider resources or final billing; review tagged resources and scheduled deletions.",
                                   "Use the recorded identity, region and acceptance name to check provider inventory and billing."))
    report["verdict"] = "FAIL" if failed or manifest["cleanup"] == "failed" else "INCOMPLETE"
    report["summary"] = {"preview": False, "completed_steps": sum(s["ok"] for s in manifest["steps"]), "cleanup": manifest["cleanup"], "interrupted": interrupted}
    return report
