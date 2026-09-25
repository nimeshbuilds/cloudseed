"""Local Well-Architected screening: declared configuration and saved evidence, never a live certification.

This module deliberately performs no provider, Terraform, Kubernetes or installation calls. A passed configuration
check describes the intended deployment only. Missing evidence and organisational questions stay UNKNOWN.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import paths, scan, ui

SCHEMA_VERSION = 1
PROFILES = ("production", "lab")
PILLARS = ("operational_excellence", "security", "reliability", "performance_efficiency", "cost_optimization", "sustainability")
REFERENCES = {
    "aws": "https://docs.aws.amazon.com/wellarchitected/latest/framework/the-pillars-of-the-framework.html",
    "azure": "https://learn.microsoft.com/en-us/azure/well-architected/pillars",
    "gcp": "https://docs.cloud.google.com/architecture/framework",
    "vmware": "https://docs.aws.amazon.com/wellarchitected/latest/framework/the-pillars-of-the-framework.html",
}
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 512
_STAMP = re.compile(r"^\d{8}-\d{6}$")
_DR_STEPS = ("1. create sample workload", "2. backup", "3. delete it (disaster)", "4. restore from backup", "5. verify")
# These are raw Terraform overrides, not prompted settings passed by stack_vars. Misplaced legacy values in `vars`
# do not reach Terraform and must not hide the actual default (module_vars only overlays extra_vars).
_EXTRA_ONLY = frozenset(("enable_flow_logs", "enable_cloudtrail", "enable_project_baseline"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        if _STAMP.fullmatch(value):
            return datetime.strptime(value, scan.RUN_FORMAT).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc) if dt.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _fresh(value, now: datetime, days: int) -> bool:
    dt = _utc(value)
    return dt is not None and now - timedelta(days=days) <= dt <= now


def _object(value) -> dict:
    return value if isinstance(value, dict) else {}


def _value(cfg: dict, key: str, default=None):
    """Render precedence without invoking cloud adapters (some adapter helpers inspect external state)."""
    extra = _object(cfg.get("extra_vars"))
    if key in extra:
        return extra[key]  # an explicit invalid/null override must not become a passing default
    if key in _EXTRA_ONLY:
        return default
    value = _object(cfg.get("vars")).get(key)
    return default if value is None or isinstance(value, str) and not value.strip() else value


def _bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in ("true", "yes", "y", "1", "on"):
            return True
        if value.strip().lower() in ("false", "no", "n", "0", "off"):
            return False
    if type(value) is int and value in (0, 1):
        return bool(value)
    return None


def _flag(cfg: dict, key: str, default: bool | None) -> bool | None:
    """Prompt answers use Cloud.var_bool coercion; raw overrides reach Terraform without that coercion."""
    value = _value(cfg, key, default)
    if key in _object(cfg.get("extra_vars")):
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value in ("true", "false"):
            return value == "true"
        return None
    return _bool(value)


def _number(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return float(value) if math.isfinite(value) else None
    except OverflowError:
        return None


def _integer(value) -> int | None:
    if isinstance(value, str) and re.fullmatch(r"\d{1,6}", value.strip()):
        return int(value)
    n = _number(value)
    return int(n) if n is not None and n == int(n) else None


def _read_json(env, relative: str) -> tuple[dict | None, str]:
    """Bounded regular-file read beneath an open workdir, with no symlink traversal (including parent directories).

    Open directory descriptors keep a concurrently replaced parent from redirecting the read outside the workdir.
    Platforms lacking these primitives report evidence unavailable instead of following a less safe path.
    """
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in (".", "..") for p in parts):
        return None, "unsafe evidence path"
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        return None, "safe evidence reads are unavailable on this platform"
    opened = []
    try:
        fd = os.open(str(Path(env.dir).resolve()), os.O_RDONLY | os.O_DIRECTORY)
        opened.append(fd)
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            opened.append(fd)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        opened.append(fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_EVIDENCE_BYTES:
            return None, "evidence is not a bounded regular file"
        data = bytearray()
        while len(data) <= MAX_EVIDENCE_BYTES:
            chunk = os.read(fd, min(65536, MAX_EVIDENCE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_EVIDENCE_BYTES:
            return None, "evidence exceeds the size limit"
        obj = json.loads(data.decode("utf-8"))
        return (obj, "") if isinstance(obj, dict) else (None, "evidence is not a JSON object")
    except (OSError, ValueError, UnicodeError, RuntimeError, RecursionError):
        return None, "evidence is missing, unsafe or unreadable"
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _latest(env, folder: str, prefix: str, now: datetime, days: int) -> tuple[dict | None, dict]:
    """Use the newest report only: an older success cannot conceal a newer failed or corrupt run."""
    directory = Path(env.dir) / folder
    evidence = {"type": "saved_report", "source": folder, "live_verified": False}
    names = []
    try:
        if directory.is_symlink():
            raise OSError("symlink")
        with os.scandir(directory) as entries:
            for i, entry in enumerate(entries):
                if i >= MAX_DIRECTORY_ENTRIES:
                    evidence["reason"] = "evidence directory exceeds the entry limit"
                    return None, evidence
                if entry.name.startswith(prefix + "-") and entry.name.endswith(".json"):
                    stamp = entry.name[len(prefix) + 1:-5]
                    if _STAMP.fullmatch(stamp):
                        names.append(entry.name)
        if not names:
            raise OSError("missing")
    except OSError:
        evidence["reason"] = "no safe saved report is available"
        return None, evidence
    name = max(names)
    evidence["source"] = f"{folder}/{name}"
    data, problem = _read_json(env, evidence["source"])
    if data is None:
        evidence["reason"] = problem
    elif data.get("run") != name[len(prefix) + 1:-5] or not _fresh(data.get("run"), now, days):
        evidence["reason"] = "latest report is stale, future-dated or has an invalid run timestamp"
        data = None
    return data, evidence


def assess(cloud, env, cfg: dict, profile: str = "production", max_age_days: int = 30) -> dict:
    """Return JSON-safe findings, without changing config or touching external infrastructure."""
    target = cloud if isinstance(cloud, str) else cloud.key
    if target not in REFERENCES:
        raise ui.Abort("Architecture scanning supports aws, azure, gcp and vmware.", code=2)
    if profile not in PROFILES:
        raise ui.Abort("Architecture profile must be production or lab.", code=2)
    if type(max_age_days) is not int or not 1 <= max_age_days <= 3650:
        raise ui.Abort("Architecture evidence age must be an integer from 1 to 3650 days.", code=2)
    if not isinstance(cfg, dict):
        raise ui.Abort("Architecture scanning requires an environment configuration object.", code=2)
    if any(key in cfg and cfg[key] is not None and not isinstance(cfg[key], dict) for key in ("vars", "extra_vars")):
        raise ui.Abort("Architecture scanning requires vars and extra_vars to be configuration objects.", code=2)
    now = _now()
    findings = []
    production = profile == "production"
    k8s = _flag(cfg, "enable_kubernetes", False)

    def add(id_, pillar, status, title, detail, remediation, evidence=None, severity="MEDIUM"):
        references = [{"url": REFERENCES[target], "pillar": pillar,
                       "scope": "common guidance only" if target == "vmware" else
                       "supplementary sustainability guidance; not an Azure WAF pillar" if target == "azure" and pillar == "sustainability" else
                       "provider framework pillar"}]
        if target == "azure" and pillar == "sustainability":
            references[0]["url"] = "https://learn.microsoft.com/en-us/azure/well-architected/sustainability/"
        findings.append({"id": id_, "pillar": pillar, "status": status, "severity": severity,
                         "title": title, "detail": detail, "remediation": remediation,
                         "evidence": evidence or [{"type": "manual_review", "live_verified": False}], "references": references})

    def declared(*keys, source="config.json"):
        return [{"type": "declared_configuration", "source": source, "fields": list(keys), "live_verified": False}]

    def toggle(id_, pillar, key, default, title, remediation, parent=True):
        value = _flag(cfg, key, default)
        status = "UNKNOWN" if parent is not True or value is None else "PASS" if value else "FAIL"
        detail = "Declared setting is enabled; deployment and effective coverage have not been checked." if status == "PASS" else \
                 "Declared setting is disabled." if status == "FAIL" else "The setting or its baseline owner cannot be established from this configuration."
        add(id_, pillar, status, title, detail, remediation, declared(key))

    # These controls examine declarations, not the currently deployed API endpoint or firewall rules.
    if target == "vmware":
        add("security.ssh_access", "security", "UNKNOWN", "Host and SSH access boundaries",
            "The local host firewall, VMware networks and SSH access were not inspected.",
            "Review host firewall rules, private network access and SSH identities.")
    else:
        cidrs = cfg.get("allowed_ssh_cidrs")  # enforced by module_vars; an extra_vars value is deliberately ignored
        networks = []
        try:
            if not isinstance(cidrs, list) or not cidrs or len(cidrs) > 256:
                raise ValueError("missing or invalid")
            # ip_network accepts bare addresses and dotted netmasks, whereas the Terraform variables require
            # explicit numeric CIDR prefixes. Never turn an invalid Terraform input into a passing declaration.
            networks = [ipaddress.ip_network(c, strict=False) for c in cidrs
                        if isinstance(c, str) and re.fullmatch(r"[^/\s]+/[0-9]{1,3}", c)]
            if len(networks) != len(cidrs):
                raise ValueError("invalid")
            restricted = all(n.version == 4 and n.prefixlen >= 8 for n in networks)
            status = "PASS" if restricted else "FAIL"
        except ValueError:
            status = "UNKNOWN"
        add("security.ssh_access", "security", status, "Declared SSH source restrictions",
            "Declared IPv4 SSH sources are restricted (no wider than /8); live firewall rules were not checked." if status == "PASS" else
            "Declared SSH sources include unrestricted, excessively broad or unsupported networks." if status == "FAIL" else
            "The declared SSH source list is missing or invalid.",
            "Use --allow-ip for the narrowest required trusted IPv4 ranges, then verify the deployed firewall.",
            declared("allowed_ssh_cidrs"), "HIGH")
    public = _flag(cfg, "kubernetes_public_endpoint", False)
    status = "NOT_APPLICABLE" if k8s is False else "UNKNOWN" if k8s is None or target == "vmware" or public is None else \
             "PASS" if public is False else "FAIL" if production else "UNKNOWN"
    add("security.kubernetes_api", "security", status, "Private Kubernetes API",
        "Kubernetes is not enabled in the declared configuration." if k8s is False else
        "A private API is declared; actual reachability and identity policy were not tested." if status == "PASS" else
        "A public API is declared; production screening requires private access or a separately reviewed exception." if public else
        "The API access boundary requires verification.",
        "Prefer kubernetes_public_endpoint=false; review required access paths, authorized source ranges and identities.",
        declared("enable_kubernetes", "kubernetes_public_endpoint"), "HIGH")

    if target == "aws":
        az = _integer(_value(cfg, "az_count", 2))
        single = _flag(cfg, "single_nat_gateway", True)
        status = "NOT_APPLICABLE" if not production else "UNKNOWN" if az is None or single is None else \
                 "PASS" if 2 <= az <= 5 and single is False else "FAIL"
        add("reliability.aws_egress", "reliability", status, "Independent egress across availability zones",
            "Lab profile does not require multi-zone egress." if not production else
            "Declared multi-zone subnets have one NAT gateway per zone; live routing and recovery were not tested." if status == "PASS" else
            "Production screening requires at least two zones and per-zone NAT gateways; the default shares one NAT." if status == "FAIL" else
            "The declared zone count or NAT setting is invalid.",
            "Review availability and cost requirements before setting az_count>=2 and single_nat_gateway=false.",
            declared("az_count", "single_nat_gateway"), "HIGH")
        account = _flag(cfg, "enable_account_baseline", True)
        # The prompted regional default follows the prompted account answer, before extra_vars are merged.
        saved_account = _bool(_object(cfg.get("vars")).get("enable_account_baseline", True))
        regional = _flag(cfg, "enable_regional_baseline", saved_account)
        toggle("security.audit_logging", "security", "enable_cloudtrail", True, "Declared CloudTrail logging",
               "Confirm one account owner manages CloudTrail and verify coverage, delivery and retention.", account)
        toggle("operations.network_logs", "operational_excellence", "enable_flow_logs", True, "Declared VPC flow logs",
               "Enable VPC flow logs and verify log delivery, retention and useful alerting.")
        baseline_detail = "Account/regional baseline ownership and effective controls require cross-environment review."
        baseline_keys = ("enable_account_baseline", "enable_regional_baseline")
        if account is False or regional is False:
            baseline_detail += " At least one baseline is delegated; this does not prove its controls are absent."
    elif target == "gcp":
        status = "NOT_APPLICABLE" if not production or k8s is False else "UNKNOWN" if k8s is None else "FAIL"
        add("reliability.gke_location", "reliability", status, "GKE control-plane failure domains",
            "Current Terraform passes the environment zone as GKE location; the cluster is zonal." if status == "FAIL" else
            "Kubernetes enablement cannot be established from the saved configuration." if status == "UNKNOWN" else
            "Regional GKE topology is not required when Kubernetes is disabled or the lab profile is selected.",
            "For zone failure tolerance, add supported regional GKE configuration and plan migration; node count alone does not change control-plane topology.",
            declared("zone", source="terraform/gcp/main.tf"), "HIGH")
        baseline = _flag(cfg, "enable_project_baseline", True)
        toggle("security.audit_logging", "security", "enable_data_access_audit_logs", False, "Declared Data Access audit logging",
               "Review data sensitivity and logging costs, enable required Data Access logs, and verify delivery and retention.", baseline)
        baseline_detail = "Project-wide logging ownership and effective controls require cross-environment review."
        baseline_keys = ("enable_project_baseline",)
    elif target == "azure":
        status = "NOT_APPLICABLE" if not production or k8s is False else "UNKNOWN" if k8s is None else "FAIL"
        add("reliability.aks_availability", "reliability", status, "AKS tier and node failure domains",
            "Current Terraform declares the Free tier and no node-pool availability zones." if status == "FAIL" else
            "Kubernetes enablement cannot be established from the saved configuration." if status == "UNKNOWN" else
            "Higher AKS availability is not required when Kubernetes is disabled or the lab profile is selected.",
            "Add supported AKS tier and zone controls, choose them against availability requirements, and assess migration costs before changing a deployed cluster.",
            declared("sku_tier", "default_node_pool.zones", source="terraform/azure/modules/kubernetes/main.tf"), "HIGH")
        toggle("security.audit_logging", "security", "enable_activity_log", True, "Declared Activity Log export",
               "Confirm subscription-wide ownership and verify Activity Log delivery, retention and alerts.")
        baseline_detail = "Subscription-wide Activity Log and Defender ownership require cross-environment review."
        baseline_keys = ("enable_activity_log", "enable_defender")
    else:
        add("reliability.vmware_host", "reliability", "FAIL" if production else "NOT_APPLICABLE", "Independent physical failure domains",
            "The local VMware target places its VMs on one workstation; multiple guest control planes do not provide host-level redundancy.",
            "Use this target for lab workloads or design and validate independent hosts and recovery outside this workstation.",
            declared(source="terraform/vmware"), "HIGH")
        baseline_detail = "Host security, patching, backup ownership and physical access require local review."
        baseline_keys = ()
    add("security.baseline_ownership", "security", "UNKNOWN", "Security baseline ownership", baseline_detail,
        "Identify the accountable owner and verify effective controls across all environments sharing the account, project, subscription or host.",
        declared(*baseline_keys))

    # A saved security scan's PASS only means no critical/high findings. Never promote it to complete coverage.
    if target == "vmware":
        add("security.saved_cloud_scan", "security", "NOT_APPLICABLE", "Saved cloud security evidence",
            "The VMware target has no cloud account benchmark.", "Run host and Kubernetes scans where applicable.")
    else:
        report, evidence = _latest(env, "scans", "cloud", now, max_age_days)
        summary = _object(report.get("summary")) if report else {}
        passed = _integer(summary.get("pass"))
        failed = _integer(summary.get("fail"))
        valid = report is not None and report.get("kind") == "cloud" and summary.get("provider") == target and \
                passed is not None and passed >= 0 and failed is not None and failed >= 0
        status = "FAIL" if valid and failed > 0 else "UNKNOWN"
        detail = "The latest fresh cloud benchmark records failed checks (including medium/low findings)." if status == "FAIL" else \
                 "The latest report cannot establish complete security coverage: existing cloud reports do not attest to skipped, unreachable or missing checks."
        if valid:
            evidence.update({"checks_passed": passed, "checks_failed": failed})
        add("security.saved_cloud_scan", "security", status, "Saved cloud security evidence", detail,
            "Run cs scan cloud, resolve findings and separately verify permissions, scope and checks that could not run.", [evidence], "HIGH")

    if k8s is False:
        add("reliability.restore_drill", "reliability", "NOT_APPLICABLE", "Saved Kubernetes recovery drill",
            "Kubernetes is not enabled; host, service and application recovery remain separate review items.",
            "Define and test recovery for every stateful workload.", declared("enable_kubernetes"))
    else:
        report, evidence = _latest(env, "dr", "drill", now, max_age_days)
        status, detail = "UNKNOWN", "No fresh, complete recovery drill proves restored sample workload data and volume contents."
        if report and report.get("env") == env.id and report.get("cloud") == target:
            steps = report.get("steps")
            rto = _number(report.get("rto_s"))
            verified = isinstance(steps, list) and len(steps) == len(_DR_STEPS) and all(
                isinstance(s, dict) and s.get("step") == name and s.get("ok") is True
                and _number(s.get("seconds")) is not None and s["seconds"] >= 0 for s, name in zip(steps, _DR_STEPS))
            if report.get("verdict") == "FAIL":
                status, detail = "FAIL", "The latest fresh recovery drill failed; an older success does not replace it."
            elif report.get("verdict") == "PASS" and verified and rto is not None and rto > 0 \
                    and math.isclose(rto, sum(s["seconds"] for s in steps[-2:]), abs_tol=0.11) \
                    and report.get("volume_tested") is True and report.get("volume_verified") is True:
                status, detail = "PASS", "A fresh saved drill recovered its sample workload and PVC contents; this does not prove application RTO/RPO objectives."
                evidence.update({"measured_sample_rto_seconds": rto, "volume_verified": True})
        add("reliability.restore_drill", "reliability", status, "Saved Kubernetes recovery drill", detail,
            "Run cs dr test with volume verification and validate application recovery and backup freshness against agreed RTO/RPO targets.", [evidence], "HIGH")

    # Installation notes do not store Helm overrides. A note proves an action, not the live release values.
    inventory, _problem = _read_json(env, "inventory.json")
    notes = _object(_object(inventory.get("current")).get("notes")) if inventory and inventory.get("env") == env.id else {}
    for item, title, risk in (("vault", "Vault production configuration", "The catalog defaults to development mode."),
                              ("kyverno-policies", "Enforced admission policies", "The catalog defaults to Audit mode, which does not block violations.")):
        install, uninstall = _object(notes.get("platform-install-" + item)), _object(notes.get("platform-uninstall-" + item))
        installed_at, removed_at = _utc(install.get("at")), _utc(uninstall.get("at"))
        recent = installed_at is not None and _fresh(install.get("at"), now, max_age_days) and \
                 (not uninstall or removed_at is not None and removed_at <= installed_at)
        detail = risk + " A recent installation is recorded, but live values and custom overrides are unavailable." if recent else \
                 "A current installation and its effective values cannot be established from local evidence."
        add("security.platform_" + item.replace("-", "_"), "security", "NOT_APPLICABLE" if k8s is False or not production else "UNKNOWN", title,
            "This production Kubernetes control is outside the selected configuration/profile." if k8s is False or not production else detail,
            "Inspect installed release values; use durable production Vault storage/unsealing and reviewed admission enforcement where required.",
            [{"type": "saved_installation_note", "source": "inventory.json", "recent_install_recorded": recent, "live_verified": False}])

    for id_, pillar, title, detail, remediation in (
        ("operations.ownership_alerting", "operational_excellence", "Workload ownership and actionable alerts",
         "Local configuration cannot establish on-call ownership, service objectives, alert routing or incident runbooks.",
         "Record owners and SLOs; exercise alerts, escalation and incident runbooks."),
        ("operations.drift_upgrade", "operational_excellence", "Drift and upgrade procedures",
         "No live drift, patch support or safe upgrade/rollback exercise was performed.",
         "Review Terraform plans, component support windows and tested upgrade/rollback procedures."),
        ("reliability.workload_objectives", "reliability", "Application recovery objectives",
         "A sample drill or topology alone cannot establish workload RTO/RPO, backup freshness or regional disaster recovery.",
         "Agree RTO/RPO and availability objectives, then exercise real application recovery and dependencies."),
        ("performance.capacity", "performance_efficiency", "Measured performance and capacity",
         "Configured node sizes and autoscaling do not prove workload latency, throughput or capacity headroom.",
         "Measure representative load against targets and test scaling, resource limits and bottlenecks."),
        ("cost.allocation_budget", "cost_optimization", "Environment cost allocation and budgets",
         "Estimates omit usage-dependent charges; account/subscription billing is not proof of this environment's cost or budget controls.",
         "Verify environment-specific allocation, budgets and anomaly alerts using provider billing and workload usage."),
        ("sustainability.utilization", "sustainability", "Measured utilization and idle resources",
         "No utilization, idle-resource, scheduling or sustainability measurement was collected.",
         "Measure utilization and remove idle capacity; evaluate scheduling and scaling against workload requirements."),
    ):
        add(id_, pillar, "UNKNOWN", title, detail, remediation)

    counts = {status: sum(f["status"] == status for f in findings) for status in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")}
    verdict = "FAIL" if counts["FAIL"] else "INCOMPLETE" if counts["UNKNOWN"] else "PASS"
    limits = ["Local declared configuration and bounded saved evidence only; no live provider, host or cluster inspection.",
              "PASS applies to individual screened controls, not complete framework compliance or certification.",
              "Manual organisational and workload requirements remain UNKNOWN; missing evidence is never a pass.",
              "Saved reports are local historical evidence, not independently authenticated or current-state attestations."]
    if target == "azure":
        limits.append("Azure has five Well-Architected pillars; sustainability is supplementary architecture guidance.")
    if target == "vmware":
        limits.append("VMware screening uses common architectural guidance; it is not an official cloud-provider assessment.")
    return {"schema_version": SCHEMA_VERSION, "kind": "architecture", "target": target, "cloud": target, "env": env.id,
            "profile": profile, "generated_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "run": now.strftime(scan.RUN_FORMAT), "max_age_days": max_age_days, "verdict": verdict,
            "summary": {"verdict": verdict, "profile": profile, "passed": counts["PASS"], "failed": counts["FAIL"],
                        "unknown": counts["UNKNOWN"], "not applicable": counts["NOT_APPLICABLE"], "scope": "local configuration and saved evidence"},
            "coverage_limits": limits, "findings": findings,
            "hint": "Address failed controls, then collect evidence and review UNKNOWN items. Configuration passes do not verify the live deployment."}


def run(cloud, env, cfg: dict, profile: str = "production", max_age_days: int = 30, json_output: bool = False) -> Path:
    """Save an ordinary scan report (including collect/undo bookkeeping) and print a bounded summary or full JSON."""
    report = assess(cloud, env, cfg, profile, max_age_days)
    path = scan.save_report(env, "architecture", report)
    # The common report writer registers both artifacts for collection/undo. Architecture's Markdown needs full
    # remediation and provenance, rather than the compact/truncated finding table intended for tool scan output.
    md = [f"# Well-Architected screening · {env.id}", "", f"**{report['verdict']}** · {profile} · {report['generated_at']}", "",
          "## Coverage", "", *(f"- {limit}" for limit in report["coverage_limits"]), "", "## Findings", ""]
    for finding in report["findings"]:
        md += [f"### {finding['id']} · {finding['title']}", "",
               f"**{finding['status']}** · {finding['severity']} · {finding['pillar']}", "", finding["detail"], "",
               f"**Remediation:** {finding['remediation']}", "", "**Evidence:**", ""]
        md += ["- " + scan.md_cell(json.dumps(evidence, sort_keys=True)) for evidence in finding["evidence"]]
        md += ["", "**References:**", ""]
        md += [f"- [{reference['scope']}: {reference['pillar']}]({reference['url']})" for reference in finding["references"]]
        md.append("")
    paths.atomic_write(path.with_suffix(".md"), "\n".join(md))
    if json_output:
        print(json.dumps(report, indent=2, allow_nan=False))
    else:
        # Generic tool-scan panels treat severity HIGH as a finding regardless of status. Here severity describes
        # the control's importance, so a passed or inapplicable HIGH control must never appear as a failure.
        attention = [{**finding, "title": f"{finding['status']} · {finding['title']}"}
                     for finding in report["findings"] if finding["status"] in ("FAIL", "UNKNOWN")]
        summary = {key: value for key, value in report["summary"].items() if key != "verdict"}
        scan._panel(f"Well-Architected screening · {env.id}", summary, attention, path,
                    verdict=report["verdict"], note=report["coverage_limits"][0], hint=report["hint"])
    return path
