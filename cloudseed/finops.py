"""FinOps: what the environment costs - cloud bills (provider APIs), cloudseed's own estimate from the inventory,
and Kubernetes allocation from OpenCost. Reports are saved in <workdir>/finops/ for the agentic skill to analyze."""

from __future__ import annotations

import json
import os
import re
import secrets as _secrets
import subprocess
import tempfile
import time
from datetime import date, timedelta
from pathlib import Path

from . import audit, deps, paths

# Rough on-demand list prices (USD/hour, us-east-1 / us-central1 / eastus) used only for the *estimate*; actuals come
# from the provider APIs.
HOURLY = {
    # AWS
    "t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664,
    "t3.2xlarge": 0.3328, "t3a.micro": 0.0094, "t3a.small": 0.0188, "t3a.medium": 0.0376, "t3a.large": 0.0752,
    "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336, "t4g.large": 0.0672, "t4g.xlarge": 0.1344,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384, "m6i.large": 0.096, "m6i.xlarge": 0.192, "m6i.2xlarge": 0.384,
    "m7i.large": 0.1008, "m7i.xlarge": 0.2016, "m6g.large": 0.077, "m7g.large": 0.0816, "c5.large": 0.085, "c5.xlarge": 0.17,
    "c6i.large": 0.085, "c6i.xlarge": 0.17, "r6i.large": 0.126,
    # GCP
    "e2-micro": 0.0084, "e2-small": 0.0168, "e2-medium": 0.0335, "e2-standard-2": 0.067, "e2-standard-4": 0.134,
    "e2-standard-8": 0.268, "e2-standard-16": 0.536, "e2-highmem-2": 0.0904, "n2-standard-2": 0.097, "n2-standard-4": 0.194,
    "n2-standard-8": 0.388, "n2d-standard-2": 0.0845,
    # Azure
    "Standard_B1s": 0.0104, "Standard_B1ms": 0.0207, "Standard_B2s": 0.0416, "Standard_B2ms": 0.0832, "Standard_B4ms": 0.166,
    "Standard_D2s_v5": 0.096, "Standard_D4s_v5": 0.192, "Standard_D8s_v5": 0.384, "Standard_D2as_v5": 0.086,
    "Standard_D4as_v5": 0.172, "Standard_E2s_v5": 0.126,
}
FIXED = {  # USD/hour
    "aws_nat_gateway": 0.045, "aws_eks_cluster": 0.10, "aws_eip": 0.005, "aws_cloudtrail": 0.0, "aws_guardduty_detector": 0.006,
    "google_container_cluster": 0.10, "google_compute_address": 0.005,
    "azurerm_nat_gateway": 0.045, "azurerm_kubernetes_cluster": 0.0, "azurerm_public_ip": 0.005, "azurerm_log_analytics_workspace": 0.0,
}
MONTHLY = {                              # USD/month
    "aws_kms_key": 1.0,
    # usage-billed security services at a small environment's volume (like GuardDuty/CloudTrail below): per security
    # check (Security Hub) and per recorded configuration item + rule evaluation (AWS Config)
    "aws_security_hub": 5.0, "aws_config": 5.0,
    # Microsoft Defender for Cloud list prices: Servers Plan 2 (the default plan) per VM, Storage per account
    "azure_defender_servers": 14.6, "azure_defender_storage": 10.0,
}
GCP_NAT_PER_VM = 0.0014                  # Cloud NAT uptime per VM using the gateway (USD/hour) ...
GCP_NAT_CAP = 0.044                      # ... capped at this rate from 32 VMs up
STORAGE_GB_MONTH = {"aws": 0.08, "gcp": 0.10, "azure": 0.075}
NODE_DISK_GB = {"aws": 50, "gcp": 50, "azure": 64}          # per managed Kubernetes node (the stacks' disk sizes)
VPN_DISK_GB = {"aws": 10, "gcp": 10, "azure": 30}
PRICE_REGION = {"aws": "us-east-1", "gcp": "us-central1", "azure": "eastus"}


def _tf_literal(raw: str):
    raw = raw.strip()
    if raw in ("true", "false"):
        return raw == "true"
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1]
    try:
        return int(raw)
    except ValueError:
        try:
            return float(raw)
        except ValueError:
            return None          # lists, maps, null, expressions: not needed for the estimate


def stack_defaults(cloud_key: str) -> dict:
    """Simple defaults from terraform/<cloud>/variables.tf, so the estimate follows the stack, not a copy of it."""
    try:
        text = (paths.tf_root() / cloud_key / "variables.tf").read_text()
    except OSError:
        return {}
    out = {}
    for m in re.finditer(r'variable\s+"([^"]+)"\s*\{(.*?)\n\}', text, re.S):
        d = re.search(r"^\s*default\s*=\s*(.+?)\s*$", m.group(2), re.M)
        if d:
            val = _tf_literal(d.group(1))
            if val is not None:
                out[m.group(1)] = val
    return out


def effective_vars(cloud_key: str, cfg: dict) -> dict:
    """What the stack is rendered with: stack defaults < prompted vars < --var extra vars (as clouds/base.py merges)."""
    given = {k: v for k, v in (cfg.get("vars") or {}).items() if v is not None and v != ""}
    extra = {k: v for k, v in (cfg.get("extra_vars") or {}).items() if v is not None}
    return {**stack_defaults(cloud_key), **given, **extra}


def _int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _on(v) -> bool:
    """A yes/no variable as the stacks read it (booleans, and the strings clouds/base.as_bool accepts for true)."""
    return v is True or str(v).strip().lower() in ("true", "1", "yes", "y", "on")


def _unset(v) -> bool:
    """A variable left at the stack's null (not given, or given as null / an empty value)."""
    return v is None or str(v).strip().lower() in ("", "null")


def estimate(cloud, env, cfg: dict, *, use_inventory: bool = True) -> dict:
    """Monthly estimate from the inventory + config (list prices, no discounts, no traffic). Deterministic and offline."""
    inv = audit.load(env) if use_inventory else {}
    resources = (inv.get("current") or {}).get("resources", [])
    v = effective_vars(cloud.key, cfg)
    lines: list[tuple[str, float]] = []
    unpriced: list[str] = []
    notes: list[str] = []
    hours = 730.0

    def count(rtype: str, fallback: int) -> int:
        n = sum(1 for r in resources if r.get("type") == rtype)
        return n or fallback

    def inst(kind: str, size: str, n: int = 1):
        rate = HOURLY.get(str(size))
        if rate is None:
            unpriced.append(str(size))
            lines.append((f"{kind} {size} x{n} (no list price)", 0.0))
        else:
            lines.append((f"{kind} {size} x{n}", rate * hours * n))

    k8s = _on(v.get("enable_kubernetes"))
    vpn = _on(v.get("enable_vpn"))
    nodes = _int(v.get("kubernetes_node_count"), 2) if k8s else 0
    if cloud.key == "gcp" and k8s:
        zones = v.get("kubernetes_node_locations") or []
        nodes *= max(len(zones), 1)
    if cloud.key == "aws":
        inst("bastion", v.get("bastion_instance_type", "t3.micro"))
        nats = count("aws_nat_gateway", 1 if _on(v.get("single_nat_gateway", True)) else _int(v.get("az_count"), 2))
        lines.append((f"NAT gateway x{nats}", FIXED["aws_nat_gateway"] * hours * nats))
        if k8s:
            lines.append(("EKS control plane", FIXED["aws_eks_cluster"] * hours))
            inst("EKS node", v.get("kubernetes_node_size", "t3.medium"), nodes)
        if vpn:
            inst("vpn host", v.get("vpn_instance_type", "t3.micro"))
        ips = count("aws_eip", 1 + nats + (1 if vpn else 0))
        lines.append((f"public IPv4 x{ips}", FIXED["aws_eip"] * hours * ips))
        keys = count("aws_kms_key", 1)
        lines.append((f"KMS key x{keys}", MONTHLY["aws_kms_key"] * keys))
        # the stack's two halves of the baseline (terraform/aws/main.tf): CloudTrail is account-wide
        # (enable_account_baseline); GuardDuty, Security Hub and AWS Config are this region's (enable_regional_baseline,
        # null = follows the account switch)
        account = _on(v.get("enable_account_baseline", True))
        regional = account if _unset(v.get("enable_regional_baseline")) else _on(v.get("enable_regional_baseline"))
        if account and _on(v.get("enable_cloudtrail", True)):
            lines.append(("CloudTrail + logs (low vol.)", 3.0))
        if regional:
            if _on(v.get("enable_guardduty", True)):
                lines.append(("GuardDuty (low volume)", 5.0))
            hub = _on(v.get("enable_security_hub"))
            # AWS Config follows the stack's rule (terraform/aws/main.tf): null = on together with Security Hub
            recorder = hub if _unset(v.get("enable_aws_config")) else _on(v.get("enable_aws_config"))
            if hub:
                lines.append(("Security Hub checks (low volume)", MONTHLY["aws_security_hub"]))
            if recorder:
                lines.append(("AWS Config recorder (low volume)", MONTHLY["aws_config"]))
            if hub and recorder:
                notes.append("Security Hub is billed per security check and AWS Config per recorded configuration item "
                             "and rule evaluation: both grow with the number of resources and their churn (autoscaling "
                             "nodes); the lines above assume a small environment.")
            elif hub or recorder:
                notes.append(("Security Hub is billed per security check" if hub else
                              "AWS Config is billed per recorded configuration item and rule evaluation") +
                             ": it grows with the number of resources and their churn (autoscaling nodes); the line "
                             "above assumes a small environment.")
        logs = []
        if _on(v.get("enable_flow_logs", True)):
            logs.append(f"VPC flow logs ({_int(v.get('flow_log_retention_days'), 30)}-day retention)")
        if k8s:
            logs.append(f"EKS control-plane logs (5 types, {_int(v.get('log_retention_days'), 365)}-day retention)")
        if logs:
            notes.append(" and ".join(logs) + " are billed per GB ingested and stored in CloudWatch: not included.")
        disk = _int(v.get("bastion_root_volume_size"), 10)
    elif cloud.key == "gcp":
        inst("bastion", v.get("bastion_machine_type", "e2-micro"))
        # Cloud NAT is billed per VM that uses it (only the private GKE nodes: bastion and VPN have their own IPs)
        rate = GCP_NAT_CAP if nodes >= 32 else GCP_NAT_PER_VM * nodes
        lines.append((f"Cloud NAT ({nodes} VM{'' if nodes == 1 else 's'})", rate * hours))
        if nodes:
            lines.append(("Cloud NAT IP x1", FIXED["google_compute_address"] * hours))
        if k8s:
            regional = _on(v.get("kubernetes_regional"))
            lines.append((f"GKE cluster fee ({'regional' if regional else 'zonal'})", FIXED["google_container_cluster"] * hours))
            if not regional:
                notes.append("The GKE free tier credits one zonal cluster per billing account ($74.40/month).")
            if len(v.get("kubernetes_node_locations") or []) > 1:
                notes.append("GKE count/min/max are per zone; this estimate multiplies initial nodes by the explicit node zone count.")
            inst("GKE node", v.get("kubernetes_node_size", "e2-standard-2"), nodes)
        if vpn:
            inst("vpn host", v.get("vpn_machine_type", "e2-micro"))
        ips = 1 + (1 if vpn else 0)
        lines.append((f"static external IP x{ips}", FIXED["google_compute_address"] * hours * ips))
        if _on(v.get("fips_mode")):
            notes.append("FIPS mode: the Ubuntu Pro FIPS images (bastion unless bastion_image is set, VPN host) carry a "
                         "premium image charge per vCPU-hour on top of the VM price: not included.")
        disk = _int(v.get("bastion_disk_size"), 10)
    elif cloud.key == "azure":
        inst("bastion", v.get("bastion_vm_size", "Standard_B1s"))
        lines.append(("NAT gateway", FIXED["azurerm_nat_gateway"] * hours))
        if k8s:
            inst("AKS node", v.get("kubernetes_node_size", "Standard_B2s"), nodes)
            if v.get("kubernetes_sku_tier", "Free") != "Free":
                unpriced.append("AKS " + str(v["kubernetes_sku_tier"]) + " control-plane tier")
        if vpn:
            inst("vpn host", v.get("vpn_vm_size", "Standard_B1s"))
        ips = count("azurerm_public_ip", 2 + (1 if vpn else 0))     # bastion + NAT (+ VPN)
        lines.append((f"public IPv4 x{ips}", FIXED["azurerm_public_ip"] * hours * ips))
        lines.append(("Log Analytics (low volume)", 5.0))
        if k8s:
            notes.append("AKS Container Insights and the control-plane (kube-audit-admin) diagnostic logs are billed per "
                         "GB ingested into Log Analytics (a small cluster can ingest several GB a day): not included.")
        if _on(v.get("enable_defender")):
            servers = 1 + (1 if vpn else 0)                           # bastion (+ VPN host)
            lines.append((f"Defender for Servers P2 x{servers}", MONTHLY["azure_defender_servers"] * servers))
            accounts = sum(1 for r in resources if r.get("type") == "azurerm_storage_account") + \
                (1 if ((cfg.get("state") or {}).get("type") or "remote") == "remote" else 0)   # + the tfstate account
            if accounts:
                lines.append((f"Defender for Storage x{accounts} account{'' if accounts == 1 else 's'}",
                              MONTHLY["azure_defender_storage"] * accounts))
            notes.append("Microsoft Defender for Cloud is subscription-wide: every VM, scale set instance (AKS nodes "
                         "included, depending on the plan) and storage account in the subscription is billed, not only "
                         "this environment's; enable it in one environment per subscription.")
        if _on(v.get("fips_mode")):
            notes.append("FIPS mode: the Ubuntu Pro FIPS marketplace images (bastion, VPN host) carry a Canonical software "
                         "charge per VM-hour on top of the VM price: not included.")
        disk = 30                                                    # Ubuntu image OS disk
    else:  # vmware: electricity/host only
        vms = 1 + _int(v.get("workload_count")) + ((_int(v.get("kubernetes_control_planes"), 1) + _int(v.get("kubernetes_workers"), 2)) if k8s else 0)
        lines.append((f"local VMs x{vms} (no cloud cost)", 0.0))
        disk = 0
    if cloud.key in STORAGE_GB_MONTH:
        disks = disk + (VPN_DISK_GB[cloud.key] if vpn else 0) + nodes * NODE_DISK_GB[cloud.key]
        lines.append((f"block storage ~{disks} GB", disks * STORAGE_GB_MONTH[cloud.key]))
    total = round(sum(x for _, x in lines), 2)
    region = cfg.get("region") or ""
    if unpriced:
        notes.append(f"No list price for {', '.join(sorted(set(unpriced)))}: the total is a lower bound.")
    if cloud.key in PRICE_REGION:
        notes.append(f"Prices are {PRICE_REGION[cloud.key]} on-demand list prices" +
                     (f"; {region} may differ." if region and region != PRICE_REGION[cloud.key] else ".") +
                     " Data transfer and NAT processing are not included.")
    return {"env": env.id, "currency": "USD", "period": "month, 730h at on-demand list prices", "lines": lines, "total": total,
            "lower_bound": bool(unpriced), "unpriced": sorted(set(unpriced)), "region": region,
            "price_region": PRICE_REGION.get(cloud.key), "notes": notes, "resources_in_state": len(resources)}


def cloud_actuals(cloud, cfg: dict, days: int = 30) -> dict:
    """Actual spend from the provider (needs the cloud CLI and billing permissions)."""
    days = max(1, int(30 if days is None else days))
    end = date.today()
    start = end - timedelta(days=days)
    out = {"provider": cloud.key, "from": str(start), "to": str(end), "by_service": {}, "total": None, "error": None}
    env = deps.path_env()
    try:
        if cloud.key == "aws":
            aws = deps.find("aws")
            if not aws:
                raise RuntimeError("aws CLI missing (cs install aws)")
            cmd = [aws, "ce", "get-cost-and-usage", "--time-period", f"Start={start},End={end}", "--granularity", "MONTHLY",
                   "--metrics", "UnblendedCost", "--group-by", "Type=DIMENSION,Key=SERVICE", "--output", "json"]
            if cfg.get("vars", {}).get("profile"):
                cmd += ["--profile", cfg["vars"]["profile"]]
            data = json.loads(subprocess.run(cmd, env=env, capture_output=True, text=True, check=True).stdout)
            for period in data.get("ResultsByTime", []):
                for g in period.get("Groups", []):
                    amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
                    out["by_service"][g["Keys"][0]] = round(out["by_service"].get(g["Keys"][0], 0) + amt, 2)
            out["total"] = round(sum(out["by_service"].values()), 2)
        elif cloud.key == "azure":
            az = deps.find("az")
            if not az:
                raise RuntimeError("az CLI missing (cs install az)")
            sub = cfg["vars"]["subscription_id"]
            body = json.dumps({"type": "ActualCost", "timeframe": "Custom", "timePeriod": {"from": f"{start}T00:00:00Z", "to": f"{end}T00:00:00Z"},
                               "dataset": {"granularity": "None", "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
                                           "grouping": [{"type": "Dimension", "name": "ServiceName"}]}})
            cmd = [az, "rest", "--method", "post", "--url",
                   f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.CostManagement/query?api-version=2023-11-01",
                   "--body", body, "-o", "json"]
            data = json.loads(subprocess.run(cmd, env=env, capture_output=True, text=True, check=True).stdout)
            cols = [c["name"] for c in data["properties"]["columns"]]
            for row in data["properties"]["rows"]:
                rec = dict(zip(cols, row))
                out["by_service"][rec.get("ServiceName", "?")] = round(float(rec.get("Cost", 0)), 2)
            out["total"] = round(sum(out["by_service"].values()), 2)
        elif cloud.key == "gcp":
            out["error"] = ("GCP has no cost query API without a BigQuery billing export. Enable the export "
                            "(Billing > Billing export) and query it, or open https://console.cloud.google.com/billing")
        else:
            out["error"] = "local VMs have no cloud bill"
    except subprocess.CalledProcessError as e:
        out["error"] = (e.stderr or e.stdout or "").strip()[-400:]
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


_FORWARDING = re.compile(r"Forwarding from 127\.0\.0\.1:(\d+) -> \d+")
OPENCOST_HINT = "--by namespace|controller|pod|node|label:<key>, --window e.g. 24h, 7d, 30d, today, lastweek"


def _tail(lines, n: int = 400) -> str:
    return " ".join(x.strip() for x in lines if x.strip())[-n:]


def _port_forward(kubectl: str, env: dict, deadline: float):
    """(process, local port, error). kubectl picks a free local port itself (`:9003`) and reports it on its first
    line; only that answer is trusted, so a port some other forward (another environment's `finops k8s`, an orphan)
    already holds can never be mistaken for this cluster's OpenCost."""
    import queue
    import threading
    pf = subprocess.Popen([kubectl, "-n", "opencost", "port-forward", "--address", "127.0.0.1", "svc/opencost", ":9003"],
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
                          stdin=subprocess.DEVNULL)
    lines: "queue.Queue" = queue.Queue()
    err: list = []

    def pump(stream, sink, eof: bool) -> None:   # drains for the forward's whole life (a full pipe blocks kubectl)
        try:
            for line in stream:
                sink(line)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass
        if eof:
            lines.put(None)

    pf.pumps = [threading.Thread(target=pump, args=(stream, sink, eof), daemon=True)
                for stream, sink, eof in ((pf.stdout, lines.put, True), (pf.stderr, err.append, False))]
    for t in pf.pumps:
        t.start()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return pf, None, "kubectl port-forward to svc/opencost did not start within 20s" + \
                (f": {_tail(err)}" if err else "")
        try:
            line = lines.get(timeout=min(0.25, left))
        except queue.Empty:
            continue
        if line is None:                       # kubectl exited (the service has no ready pod, RBAC, ...)
            try:
                pf.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            for t in pf.pumps:                 # everything kubectl said on stderr
                t.join(timeout=2)
            return pf, None, "kubectl port-forward to svc/opencost failed" + (f": {_tail(err)}" if err else "")
        m = _FORWARDING.search(line)
        if m:
            return pf, int(m.group(1)), None


def _stop(pf) -> None:
    """End the port-forward and let its output pumps finish (they close the pipes at EOF)."""
    if pf is None:
        return
    if pf.poll() is None:
        pf.terminate()
        try:
            pf.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pf.kill()
            try:
                pf.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    for t in getattr(pf, "pumps", ()):
        t.join(timeout=2)


def opencost(ctx, window: str = "7d", aggregate: str = "namespace") -> dict:
    """Allocation from OpenCost through a temporary port-forward (a free local port kubectl chooses)."""
    import http.client
    import urllib.error
    import urllib.parse
    import urllib.request
    kubectl = deps.find("kubectl")
    if not kubectl:
        return {"error": "kubectl missing (cloudseed install kubectl)"}
    env = ctx.procenv()
    try:
        svc = subprocess.run([kubectl, "-n", "opencost", "get", "svc", "opencost"], env=env, capture_output=True,
                             text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "kubectl did not answer within 60s (is the cluster reachable?)"}
    except OSError as e:
        return {"error": f"kubectl could not be run: {e}"}
    if svc.returncode != 0:
        why = (svc.stderr or svc.stdout or "").strip()
        # the service (or its namespace) is missing - not "executable aws not found" from a kubeconfig's exec plugin
        if not why or re.search(r"\(NotFound\)|\"opencost\" not found", why):
            return {"error": "OpenCost is not installed: cs platform install finops"}
        return {"error": f"kubectl could not read the opencost service: {why.splitlines()[-1][:300]}"}
    query = urllib.parse.urlencode({"window": window, "aggregate": aggregate, "accumulate": "true"})
    start = time.monotonic()
    pf, port, error = _port_forward(kubectl, env, start + 20)
    try:
        if error:
            return {"error": error}
        url = f"http://127.0.0.1:{port}/allocation/compute?{query}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # the forward is local: never a proxy
        deadline = start + 40
        data, last = None, ""
        while data is None:
            try:
                with opener.open(url, timeout=10) as r:
                    data = json.loads(r.read() or b"{}")
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read().decode("utf-8", "replace")
                except (OSError, http.client.HTTPException):
                    pass
                try:
                    body = json.loads(body).get("message") or body
                except (ValueError, AttributeError):
                    pass
                if 400 <= e.code < 500:
                    return {"error": f"OpenCost rejected the query (HTTP {e.code}): {' '.join(str(body).split())[:300]}"
                                     f"   ({OPENCOST_HINT})"}
                last = f"HTTP {e.code}"
            except ValueError as e:              # not JSON (something else answered?)
                return {"error": f"OpenCost returned an unexpected answer: {e}"}
            except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
                last = str(getattr(e, "reason", None) or e)
            if data is None:
                if pf.poll() is not None:
                    return {"error": "kubectl port-forward to svc/opencost stopped" + (f": {last}" if last else "")}
                if time.monotonic() >= deadline:
                    return {"error": "OpenCost API not reachable" + (f" ({last})" if last else "") +
                                     ": check the opencost pod (cs kubectl -n opencost get pods)"}
                time.sleep(0.5)
        if isinstance(data, dict) and data.get("code") not in (None, 200):
            return {"error": f"OpenCost rejected the query: {data.get('message') or data.get('code')}   ({OPENCOST_HINT})"}
        rows = {}
        for item in (data.get("data") or []) if isinstance(data, dict) else []:
            for name, a in (item or {}).items():
                rows[name] = {"cpu": round(a.get("cpuCost", 0), 2), "ram": round(a.get("ramCost", 0), 2), "pv": round(a.get("pvCost", 0), 2),
                              "total": round(a.get("totalCost", 0), 2), "efficiency": round(a.get("totalEfficiency", 0) * 100)}
        return {"window": window, "aggregate": aggregate, "rows": rows, "total": round(sum(r["total"] for r in rows.values()), 2)}
    finally:
        _stop(pf)


def _write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_report(env, report: dict) -> Path:
    """<workdir>/finops/report-<UTC time>-<random>.json (unique even for parallel runs) + latest.json."""
    d = env.dir / "finops"
    d.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report, indent=2, default=str) + "\n"
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    while True:
        path = d / f"report-{stamp}-{_secrets.token_hex(3)}.json"
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            break
        except FileExistsError:
            continue
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    _write_atomic(d / "latest.json", text)
    audit.note(env, "finops-report", {"path": str(path), "estimate_total": report.get("estimate", {}).get("total")})
    return path
