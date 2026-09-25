"""Chaos engineering: automated, end-to-end chaos experiments against the current cluster with a printed verdict.

`cs chaos run` installs Chaos Mesh when needed, deploys a canary workload (or targets one of yours), then runs a suite
of experiments one after the other. Every experiment has a steady-state hypothesis (the workload keeps answering /
recovers within a bound), availability is sampled while the fault is injected, recovery is timed after it is lifted,
and a PASS / FAIL table plus a JSON + Markdown report are produced. A fault that Chaos Mesh never injected is an ERROR,
never a PASS. Nothing is left behind: experiments are deleted, the canary namespace is removed (keep it with --keep).

Suites: basic (pod-kill, pod-failure, container-kill) · network (delay, loss, partition, dns) · stress (cpu, memory,
time-skew) · full (all of them).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from . import audit, deps, paths, ui

CANARY_NS = "cloudseed-chaos"
CANARY_NAME = "canary"
PROBE_NAME = "cloudseed-probe"
LABEL = "cloudseed.io/chaos"
CANARY_IMAGE = "registry.k8s.io/e2e-test-images/agnhost:2.53"
PROBE_IMAGE = "busybox:1.36"

# The probe pod: a shell that fetches the target Service. Hardened, but its root filesystem stays writable because
# DNSChaos rewrites /etc/resolv.conf inside it.
PROBE_MANIFEST = """apiVersion: v1
kind: Pod
metadata: {name: %(probe)s, namespace: %(ns)s, labels: {app: %(probe)s}}
spec:
  restartPolicy: Always
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, runAsUser: 65534, runAsGroup: 65534, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: probe
      image: busybox:1.36
      command: ["sh", "-c", "sleep 1000000"]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      resources: {requests: {cpu: 10m, memory: 16Mi}}
"""

# The canary answers HTTP with agnhost serve-hostname: a single "/" handler (no /shell, /upload or /exit endpoints
# like netexec has), running as a non-root user on a read-only root filesystem.
CANARY_MANIFEST = """apiVersion: v1
kind: Namespace
metadata: {name: %(ns)s, labels: {%(label)s: canary}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: %(name)s, namespace: %(ns)s, labels: {app: %(name)s}}
spec:
  replicas: %(replicas)d
  selector: {matchLabels: {app: %(name)s}}
  template:
    metadata: {labels: {app: %(name)s}}
    spec:
      terminationGracePeriodSeconds: 5
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, seccompProfile: {type: RuntimeDefault}}
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector: {matchLabels: {app: %(name)s}}
                topologyKey: kubernetes.io/hostname
      containers:
        - name: web
          image: registry.k8s.io/e2e-test-images/agnhost:2.53
          args: ["serve-hostname", "--port=8080"]
          ports: [{containerPort: 8080, name: http}]
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
          readinessProbe: {httpGet: {path: /healthz, port: 8080}, periodSeconds: 2, failureThreshold: 2}
          livenessProbe: {httpGet: {path: /healthz, port: 8080}, periodSeconds: 5, failureThreshold: 3}
          resources: {requests: {cpu: 50m, memory: 64Mi}, limits: {cpu: "1", memory: 256Mi}}
---
apiVersion: v1
kind: Service
metadata: {name: %(name)s, namespace: %(ns)s}
spec:
  selector: {app: %(name)s}
  ports: [{port: 8080, targetPort: 8080, name: http}]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: %(name)s, namespace: %(ns)s}
spec:
  minAvailable: 1
  selector: {matchLabels: {app: %(name)s}}
---
""" + PROBE_MANIFEST

CHAOS_KINDS = ("podchaos", "networkchaos", "dnschaos", "stresschaos", "timechaos", "iochaos", "httpchaos")
ONESHOT_WINDOW_S = 15   # a one-shot fault (pod-kill, container-kill) is injected once; availability is watched this long


# experiment name -> (suite, Chaos Mesh kind, spec builder, hypothesis)
# hypothesis: min availability while injected (fraction of probes answered), max recovery seconds after the fault is lifted.
# Spec builders get the Target (its full pod selector, Service and main container) and the duration.
def _sel(ns: str, app: str) -> dict:
    return {"namespaces": [ns], "labelSelectors": {"app": app}}


def _dns_patterns(t: "Target") -> list[str]:
    """Chaos Mesh DNS patterns may only carry a wildcard as their LAST character (the DNS server rejects anything else)."""
    return [f"{t.svc}.{t.ns}.svc*", f"{t.svc}*"]


EXPERIMENTS: dict[str, dict] = {
    "pod-kill": {"suite": "basic", "kind": "PodChaos", "desc": "kill one pod; the Deployment must replace it",
                 "spec": lambda t, d: {"action": "pod-kill", "mode": "one", "selector": t.selector()}, "oneshot": True,
                 "min_avail": 0.5, "recover_s": 90},
    "pod-failure": {"suite": "basic", "kind": "PodChaos", "desc": "make one pod fail for the duration; the others must serve",
                    "spec": lambda t, d: {"action": "pod-failure", "mode": "one", "duration": d, "selector": t.selector()},
                    "min_avail": 0.7, "recover_s": 90},
    "container-kill": {"suite": "basic", "kind": "PodChaos", "desc": "kill the main container in one pod; kubelet must restart it",
                       "spec": lambda t, d: {"action": "container-kill", "mode": "one", "containerNames": [t.container], "selector": t.selector()},
                       "oneshot": True, "min_avail": 0.5, "recover_s": 90},
    "network-delay": {"suite": "network", "kind": "NetworkChaos", "desc": "add 300ms +-100ms latency to all pods; requests must still complete",
                      "spec": lambda t, d: {"action": "delay", "mode": "all", "duration": d, "selector": t.selector(),
                                            "delay": {"latency": "300ms", "jitter": "100ms", "correlation": "50"}},
                      "min_avail": 0.8, "recover_s": 60},
    "network-loss": {"suite": "network", "kind": "NetworkChaos", "desc": "drop 30% of packets to all pods; TCP must retry through it",
                     "spec": lambda t, d: {"action": "loss", "mode": "all", "duration": d, "selector": t.selector(), "loss": {"loss": "30", "correlation": "25"}},
                     "min_avail": 0.6, "recover_s": 60},
    "network-partition": {"suite": "network", "kind": "NetworkChaos", "desc": "partition the probe from the workload; expected outage, must recover",
                          "spec": lambda t, d: {"action": "partition", "mode": "all", "duration": d, "selector": t.selector(),
                                                "direction": "both", "target": {"mode": "all", "selector": _sel(t.ns, PROBE_NAME)}},
                          "min_avail": 0.0, "recover_s": 60, "expect_outage": True},
    "dns-error": {"suite": "network", "kind": "DNSChaos", "desc": "make DNS fail for the probe; service must be back once lifted",
                  "spec": lambda t, d: {"action": "error", "mode": "all", "duration": d, "selector": _sel(t.ns, PROBE_NAME), "patterns": _dns_patterns(t)},
                  "min_avail": 0.0, "recover_s": 60, "expect_outage": True, "needs": "dns"},
    "cpu-stress": {"suite": "stress", "kind": "StressChaos", "desc": "burn CPU inside every pod; they must keep serving",
                   "spec": lambda t, d: {"mode": "all", "duration": d, "selector": t.selector(), "stressors": {"cpu": {"workers": 2, "load": 90}}},
                   "min_avail": 0.8, "recover_s": 60},
    "memory-stress": {"suite": "stress", "kind": "StressChaos", "desc": "allocate memory inside every pod (under the limit); they must keep serving",
                      "spec": lambda t, d: {"mode": "all", "duration": d, "selector": t.selector(), "stressors": {"memory": {"workers": 1, "size": "128MB"}}},
                      "min_avail": 0.8, "recover_s": 90},
    "time-skew": {"suite": "stress", "kind": "TimeChaos", "desc": "shift the clock 10 minutes in every pod; they must keep serving",
                  "spec": lambda t, d: {"mode": "all", "duration": d, "selector": t.selector(), "timeOffset": "-10m"},
                  "min_avail": 0.8, "recover_s": 60},
}
SUITES = {"basic": [k for k, v in EXPERIMENTS.items() if v["suite"] == "basic"],
          "network": [k for k, v in EXPERIMENTS.items() if v["suite"] == "network"],
          "stress": [k for k, v in EXPERIMENTS.items() if v["suite"] == "stress"],
          "full": list(EXPERIMENTS)}


def resolve_names(names: list[str] | None, suite: str | None = None) -> list[str]:
    """Experiment / suite names -> ordered, de-duplicated experiment list. Needs no cluster, so typos fail before anything is installed."""
    wanted: list[str] = []
    for n in names or []:
        if n in SUITES:
            wanted += SUITES[n]
        elif n in EXPERIMENTS:
            wanted.append(n)
        else:
            raise ui.Abort(f"Unknown experiment or suite '{n}'. Experiments: {', '.join(EXPERIMENTS)}; suites: {', '.join(SUITES)}")
    if not wanted:
        if suite and suite not in SUITES:
            raise ui.Abort(f"Unknown suite '{suite}'. Suites: {', '.join(SUITES)}")
        wanted = list(SUITES[suite or "basic"])
    return list(dict.fromkeys(wanted))


def _tail(text, n: int = 200, lines: int = 1) -> str:
    from .scan import tail_text
    return tail_text(text, n, lines)


def _memo(ctx, key: str, value):
    """Remember `value` on the cluster context for the caller (a context that takes no attributes just skips it)."""
    try:
        setattr(ctx, key, value)
    except AttributeError:
        pass
    return value


def _kubectl_path() -> str:
    """kubectl, installed only with consent like every other cluster command (asked on a terminal; with -y only after
    --auto-approve, else exit 2 with `cloudseed install kubectl`) - never a TypeError from running [None, ...]."""
    found = deps.find("kubectl")
    if found:
        return found
    from . import services
    return services.ensure_tool("kubectl", "to talk to the cluster", default=True)


def _kubectl(ctx, *args: str, input: str | None = None, check: bool = False, timeout: int = 120) -> subprocess.CompletedProcess:
    """kubectl against the cluster. A hung call (slow API server, dead tunnel) becomes rc 124 instead of an exception."""
    kubectl = _kubectl_path()
    try:
        proc = subprocess.run([kubectl, *args], env=ctx.procenv(), capture_output=True, text=True, input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess([kubectl, *args], 124, "", f"kubectl {' '.join(args[:3])} timed out after {timeout}s")
    if check and proc.returncode != 0:
        raise ui.Abort(f"kubectl {' '.join(args[:3])} failed: {_tail(proc.stderr or proc.stdout, 600, lines=4)}")
    return proc


def chaos_mesh_ready(ctx) -> bool:
    return _kubectl(ctx, "get", "crd", "podchaos.chaos-mesh.org").returncode == 0 and \
        _kubectl(ctx, "-n", "chaos-mesh", "get", "deploy", "chaos-controller-manager").returncode == 0


def ensure_chaos_mesh(ctx) -> None:
    from . import platform as platformmod
    if chaos_mesh_ready(ctx):
        return
    ui.info("Chaos Mesh is not installed yet; installing it (cs platform install chaos-mesh)")
    # summary=False: the platform's own "Done" panel (status / web UIs / k9s) does not belong in the middle of a chaos run
    platformmod.install(["chaos-mesh"], ctx, wait=True, summary=False)
    _kubectl(ctx, "-n", "chaos-mesh", "wait", "--for=condition=Available", "deployment", "--all", "--timeout=300s", timeout=330)


def dns_chaos_available(ctx) -> bool:
    return _kubectl(ctx, "-n", "chaos-mesh", "get", "deploy", "chaos-dns-server").returncode == 0


def _diagnostics(ctx, ns: str, limit: int = 6) -> str:
    """Pods and the latest events of a namespace, for failure messages."""
    pods = _kubectl(ctx, "-n", ns, "get", "pods", "-o", "wide", timeout=30).stdout.strip().splitlines()
    events = _kubectl(ctx, "-n", ns, "get", "events", "--sort-by=.lastTimestamp", timeout=30).stdout.strip().splitlines()
    out = []
    if len(pods) > 1:
        out += ["    pods:"] + ["      " + p for p in pods[:limit + 1]]
    if len(events) > 1:
        out += ["    recent events:"] + ["      " + e[:200] for e in events[-limit:]]
    return "\n".join(out)


# ---------------------------------------------------------------- target / probe

class Target:
    """What the experiments hit: a Deployment (selected by its FULL pod selector), the Service probed and its port."""

    def __init__(self, ns: str, deploy: str, app_label: str, svc: str, port: int, canary: bool,
                 labels: dict | None = None, exprs: list | None = None, container: str | None = None):
        self.ns, self.deploy, self.app, self.svc, self.port, self.canary = ns, deploy, app_label, svc, port, canary
        self.labels = dict(labels) if labels else ({"app": app_label} if not exprs else {})
        self.exprs = [dict(x) for x in exprs or []]
        self.container = container or "web"

    @property
    def url(self) -> str:
        return f"http://{self.svc}.{self.ns}.svc:{self.port}/"

    def selector(self) -> dict:
        """Chaos Mesh selector for the workload's pods: every matchLabel (ANDed) plus the matchExpressions."""
        sel: dict = {"namespaces": [self.ns]}
        if self.labels:
            sel["labelSelectors"] = dict(self.labels)
        if self.exprs:
            sel["expressionSelectors"] = [dict(x) for x in self.exprs]
        return sel

    def selector_text(self) -> str:
        """The same selector in kubectl -l syntax."""
        parts = [f"{k}={v}" for k, v in self.labels.items()]
        for x in self.exprs:
            op, key, vals = str(x.get("operator", "")), x.get("key", ""), ",".join(str(v) for v in x.get("values") or [])
            parts.append({"In": f"{key} in ({vals})", "NotIn": f"{key} notin ({vals})", "Exists": key, "DoesNotExist": f"!{key}"}.get(op, f"{key} {op} ({vals})"))
        return ",".join(parts)


def deploy_canary(ctx, replicas: int) -> Target:
    manifest = CANARY_MANIFEST % {"ns": CANARY_NS, "name": CANARY_NAME, "replicas": replicas, "probe": PROBE_NAME, "label": LABEL}
    path = ctx.workdir / "chaos-canary.yaml"
    path.write_text(manifest)
    _kubectl(ctx, "apply", "-f", str(path), check=True)
    problem = ""
    with ui.Spinner(f"Waiting for the canary workload ({replicas} replicas) in {CANARY_NS}") as sp:
        r = _kubectl(ctx, "-n", CANARY_NS, "rollout", "status", f"deploy/{CANARY_NAME}", "--timeout=300s", timeout=330)
        if r.returncode != 0:
            problem = f"the canary Deployment did not become ready ({_tail(r.stderr or r.stdout, 200)})"
        else:
            w = _kubectl(ctx, "-n", CANARY_NS, "wait", "--for=condition=Ready", f"pod/{PROBE_NAME}", "--timeout=180s", timeout=200)
            if w.returncode != 0:
                problem = f"the probe pod did not become ready ({_tail(w.stderr or w.stdout, 200)})"
        if not problem:
            sp.done_text = "canary workload and probe are ready"
    if problem:
        diag = _diagnostics(ctx, CANARY_NS)
        _kubectl(ctx, "delete", "ns", CANARY_NS, "--ignore-not-found", "--wait=false")
        raise ui.Abort(f"Chaos run stopped before any experiment: {problem}.\n" + (diag + "\n" if diag else "")
                       + f"    Typical causes: the images {CANARY_IMAGE} / {PROBE_IMAGE} cannot be pulled (air-gapped or proxied cluster), "
                       "or no node has room for the pods. The canary namespace was removed.")
    return Target(CANARY_NS, CANARY_NAME, CANARY_NAME, CANARY_NAME, 8080, True)


_NS_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")              # a namespace: RFC 1123 label (no dots)
_DEPLOY_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")         # a Deployment: RFC 1123 subdomain
_PORT_NAME_RE = re.compile(r"^(?=.*[a-z])[a-z0-9]([-a-z0-9]{0,13}[a-z0-9])?$")   # a named port: IANA_SVC_NAME


def parse_target(spec: str) -> tuple[str, str, str]:
    """ns/deployment[:port|port-name] (or just deployment, in namespace default) -> (ns, deployment, port); checked
    before anything touches the cluster."""
    s = (spec or "").strip()
    usage = "Use <namespace>/<deployment>[:port|port-name], e.g. shop/api:8080, or omit --target for the cloudseed canary."
    if "/" in s:
        ns, _, rest = s.partition("/")
    else:
        ns, rest = "default", s
    name, colon, port = rest.partition(":")
    if "/" in s and not name:
        raise ui.Abort(f"Bad --target '{spec}': give the deployment too, e.g. {ns or '<namespace>'}/<deployment>. {usage}")
    if not ns:
        raise ui.Abort(f"Bad --target '{spec}': the namespace before '/' is empty. {usage}")
    if not _NS_RE.match(ns):
        raise ui.Abort(f"Bad --target '{spec}': '{ns}' is not a namespace name (lowercase letters, digits and '-', at most 63). {usage}")
    if not _DEPLOY_RE.match(name):
        raise ui.Abort(f"Bad --target '{spec}': '{name}' is not a Deployment name. {usage}")
    if colon:
        if port.isdigit():
            if not 1 <= int(port) <= 65535:
                raise ui.Abort(f"Bad --target '{spec}': port {port} is outside 1..65535. {usage}")
            port = str(int(port))   # 08080 is port 8080
        elif not _PORT_NAME_RE.match(port):
            raise ui.Abort(f"Bad --target '{spec}': " + (f"'{port}' is not a port number or port name" if port else "nothing after ':'")
                           + f". {usage}")
    return ns, name, port


def _service_port(ns: str, name: str, svc: dict, port: str) -> int:
    ports = (svc.get("spec") or {}).get("ports") or []
    if not ports:
        raise ui.Abort(f"Service {ns}/{name} exposes no ports to probe.")
    listing = ", ".join(f"{p.get('name') or '-'}={p.get('port')}" for p in ports)
    if not port:
        return int(ports[0]["port"])
    if port.isdigit():
        if not any(str(p.get("port")) == port for p in ports):
            ui.warn(f"Service {ns}/{name} does not list port {port} (ports: {listing}); probing it anyway.")
        return int(port)
    match = next((p for p in ports if p.get("name") == port), None)
    if not match:
        raise ui.Abort(f"Service {ns}/{name} has no port named '{port}' (ports: {listing}). Use --target {ns}/{name}:<port|port-name>.")
    return int(match["port"])


def _foreign_pods(ctx, t: Target) -> list[str]:
    """Pods matched by the target's selector that do not belong to the target Deployment (the blast radius beyond it)."""
    proc = _kubectl(ctx, "-n", t.ns, "get", "pods", "-l", t.selector_text(), "-o", "json", timeout=60)
    try:
        items = json.loads(proc.stdout or "{}").get("items") or []
    except ValueError:
        return []
    out = []
    for p in items:
        md = p.get("metadata") or {}
        rs = f"{t.deploy}-{(md.get('labels') or {}).get('pod-template-hash', '')}"
        owners = [o.get("name", "") for o in md.get("ownerReferences") or [] if o.get("kind") == "ReplicaSet"]
        if rs not in owners:
            out.append(md.get("name", "?"))
    return out


def resolve_target(ctx, spec: str | None, replicas: int) -> Target:
    """--target ns/deployment[:port|port-name]: one of the user's Deployments (its full pod selector) + a Service of the same name."""
    if not spec:
        return deploy_canary(ctx, replicas)
    ns, name, port = parse_target(spec)
    proc = _kubectl(ctx, "-n", ns, "get", "deploy", name, "-o", "json")
    if proc.returncode != 0:
        raise ui.Abort(f"Deployment {ns}/{name} not found. Use --target <namespace>/<deployment>[:port], or omit it for the canary.")
    d = json.loads(proc.stdout)
    sel = (d.get("spec") or {}).get("selector") or {}
    labels = dict(sel.get("matchLabels") or {})
    exprs = [dict(x) for x in sel.get("matchExpressions") or []]
    if not labels and not exprs:
        raise ui.Abort(f"Deployment {ns}/{name} has no pod selector; chaos experiments select pods by label.")
    containers = (((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []
    container = containers[0].get("name") if containers else None
    svc = _kubectl(ctx, "-n", ns, "get", "svc", name, "-o", "json")
    if svc.returncode != 0:
        raise ui.Abort(f"No Service named {name} in {ns} to probe; give one with the same name as the Deployment.")
    port_n = _service_port(ns, name, json.loads(svc.stdout), port)
    app_val = labels.get("app") or next(iter(labels.values()), name)
    t = Target(ns, name, app_val, name, port_n, False, labels=labels, exprs=exprs, container=container)
    ui.info(f"Experiments select pods in {ns} with: {t.selector_text()}" + (f"  (container-kill hits container '{t.container}')" if container else ""))
    others = _foreign_pods(ctx, t)
    if others:
        ui.warn(f"The selector also matches {len(others)} pod(s) not owned by {ns}/{name} (e.g. {', '.join(others[:5])}); faults will hit them too.")
    # the probe pod lives next to the target
    _kubectl(ctx, "apply", "-f", "-", input=PROBE_MANIFEST % {"ns": ns, "probe": PROBE_NAME}, check=True)
    w = _kubectl(ctx, "-n", ns, "wait", "--for=condition=Ready", f"pod/{PROBE_NAME}", "--timeout=180s", timeout=200)
    if w.returncode != 0:
        diag = _diagnostics(ctx, ns)
        _kubectl(ctx, "-n", ns, "delete", "pod", PROBE_NAME, "--ignore-not-found", "--wait=false")
        raise ui.Abort(f"The probe pod in {ns} did not become ready ({_tail(w.stderr or w.stdout, 200)}).\n" + (diag + "\n" if diag else "")
                       + f"    It needs the image {PROBE_IMAGE} and must be admitted in {ns} (it runs as non-root). Nothing was injected.")
    return t


def probe(ctx, t: Target) -> bool:
    """One HTTP request from the probe pod to the Service (2s timeout). A hung exec counts as a failed probe."""
    proc = _kubectl(ctx, "-n", t.ns, "exec", PROBE_NAME, "--", "sh", "-c", f"wget -q -O- -T 2 {t.url} >/dev/null 2>&1 && echo ok || echo fail", timeout=20)
    return proc.stdout.strip() == "ok"


def available_replicas(ctx, t: Target) -> tuple[int, int]:
    proc = _kubectl(ctx, "-n", t.ns, "get", "deploy", t.deploy, "-o", "jsonpath={.status.availableReplicas},{.spec.replicas}")
    a, _, want = proc.stdout.strip().partition(",")
    try:
        return int(a or 0), int(want or 0)
    except ValueError:
        return 0, 0


def steady(ctx, t: Target) -> bool:
    a, want = available_replicas(ctx, t)
    return a >= want and want > 0 and probe(ctx, t)


# ---------------------------------------------------------------- experiments

def _experiment_manifest(name: str, e: dict, t: Target, duration: str, run_id: str) -> dict:
    return {"apiVersion": "chaos-mesh.org/v1alpha1", "kind": e["kind"],
            "metadata": {"name": f"cs-{name}", "namespace": t.ns, "labels": {LABEL: run_id}}, "spec": e["spec"](t, duration)}


def _cleanup_experiments(ctx, t: Target) -> None:
    for kind in CHAOS_KINDS:
        _kubectl(ctx, "-n", t.ns, "delete", kind, "-l", LABEL, "--ignore-not-found", "--wait=false")


def _injection_state(ctx, ns: str, kind: str, name: str) -> tuple[bool | None, str]:
    """Did Chaos Mesh inject the fault? True (records show it), False (nothing selected), None (not yet / unknown)."""
    proc = _kubectl(ctx, "-n", ns, "get", kind, name, "-o", "json", timeout=30)
    if proc.returncode != 0:
        return None, _tail(proc.stderr, 200) or "status unavailable"
    try:
        st = (json.loads(proc.stdout or "{}").get("status") or {})
    except ValueError:
        return None, "unreadable status"
    conds = {c.get("type"): c for c in st.get("conditions") or [] if isinstance(c, dict)}
    records = [r for r in (st.get("experiment") or {}).get("containerRecords") or [] if isinstance(r, dict)]

    def _count(r: dict) -> int:
        try:
            return int(r.get("injectedCount") or 0)
        except (TypeError, ValueError):
            return 0

    injected = [r for r in records if str(r.get("phase")) == "Injected" or _count(r) > 0]
    if injected or str((conds.get("AllInjected") or {}).get("status")) == "True":
        return True, f"injected into {len(injected) or len(records)} target(s)"
    detail = ", ".join(f"{k}={v.get('status')}" + (f" ({v.get('reason')})" if v.get("reason") else "") for k, v in conds.items())
    if records:
        detail += ("; " if detail else "") + "records: " + ", ".join(f"{r.get('id', '?')}={r.get('phase', '?')}" for r in records[:3])
    if str((conds.get("Selected") or {}).get("status")) == "False":
        return False, "nothing was selected: " + (detail or "no matching pods")
    return None, detail or "no status yet"


def _events(ctx, ns: str, name: str, limit: int = 3) -> str:
    proc = _kubectl(ctx, "-n", ns, "get", "events", "--field-selector", f"involvedObject.name={name}", "-o", "json", timeout=30)
    try:
        items = json.loads(proc.stdout or "{}").get("items") or []
    except ValueError:
        return ""
    items.sort(key=lambda ev: str(ev.get("lastTimestamp") or ev.get("eventTime") or ""))
    return " | ".join(f"{ev.get('reason', '')}: {str(ev.get('message', '')).strip()[:160]}" for ev in items[-limit:])


def run_experiment(ctx, name: str, t: Target, duration_s: int, run_id: str, interval: float = 3.0) -> dict:
    e = EXPERIMENTS[name]
    result = {"experiment": name, "kind": e["kind"], "desc": e["desc"], "started": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    print(f"\n  {ui.style('◆', 'brand')} {ui.style(name, 'bold', 'text')}  {ui.dim(e['desc'])}")
    if not steady(ctx, t):
        ui.warn("workload not steady before injection; waiting up to 120s")
        if not wait_recovery(ctx, t, 120)[0]:
            result.update(verdict="SKIP", reason="workload not steady before the experiment")
            ui.warn("skipped: not steady")
            return result
    manifest = _experiment_manifest(name, e, t, f"{duration_s}s", run_id)
    kind, cname = e["kind"].lower(), manifest["metadata"]["name"]
    proc = _kubectl(ctx, "apply", "-f", "-", input=json.dumps(manifest))
    if proc.returncode != 0:
        result.update(verdict="ERROR", reason=_tail(proc.stderr or proc.stdout, 300, lines=2))
        ui.err(f"could not create {e['kind']}: {result['reason']}")
        return result
    window = ONESHOT_WINDOW_S if e.get("oneshot") else duration_s
    ok = total = 0
    injected, inj_detail, checked = False, "", 0.0
    t0 = time.time()
    with ui.Spinner(f"injecting for {window}s") as sp:
        while time.time() - t0 < window:
            if not injected and time.time() - checked >= 2:
                state, inj_detail = _injection_state(ctx, t.ns, kind, cname)
                injected, checked = state is True, time.time()
            total += 1
            if probe(ctx, t):
                ok += 1
            sp.update(f"injecting for {window}s · availability {ok}/{total}" + ("" if injected else " · waiting for Chaos Mesh to inject"))
            time.sleep(interval)
        if not injected:  # injectedCount survives the end of the duration, so one last look is conclusive
            state, inj_detail = _injection_state(ctx, t.ns, kind, cname)
            injected = state is True
        if injected:
            sp.done_text = f"fault window over · availability {ok}/{total} ({round(100 * ok / max(total, 1))}%)"
    removed = _kubectl(ctx, "-n", t.ns, "delete", kind, cname, "--ignore-not-found", "--wait=true", "--timeout=170s", timeout=180)
    if removed.returncode != 0:
        result.update(verdict="ERROR", stuck=True, availability=round(ok / max(total, 1), 3), probes=total,
                      reason=f"fault not removed within 170s ({_tail(removed.stderr, 120)}); Chaos Mesh cannot recover it "
                             "(check the chaos-daemon pods: kubectl -n chaos-mesh get pods), then run: cs chaos stop")
        ui.err(f"{name}: {result['reason']}")
        return result
    recovered, secs = wait_recovery(ctx, t, e["recover_s"])
    avail = ok / max(total, 1)
    result.update(availability=round(avail, 3), probes=total, min_availability=e["min_avail"], recovered=recovered, recovery_s=secs,
                  recovery_bound_s=e["recover_s"], injected=injected)
    if not injected:
        events = _events(ctx, t.ns, cname)
        result.update(verdict="ERROR", reason=f"fault not injected: {inj_detail}" + (f"; events: {events}" if events else ""))
    elif not recovered:
        result.update(verdict="FAIL", reason=f"did not return to steady state within {e['recover_s']}s")
    elif avail < e["min_avail"]:
        result.update(verdict="FAIL", reason=f"availability {round(100 * avail)}% below the {round(100 * e['min_avail'])}% hypothesis")
    elif e.get("expect_outage") and total and ok == total:
        result.update(verdict="FAIL", reason="expected outage not observed: every probe succeeded while the fault was injected (the fault had no effect)")
    else:
        result.update(verdict="PASS", reason="")
    if result["verdict"] == "ERROR":
        ui.err(f"{name}: ERROR  {result['reason']}")
    else:
        (ui.ok if result["verdict"] == "PASS" else ui.err)(f"{name}: {result['verdict']}  availability {round(100 * avail)}%  recovered in {secs}s"
                                                          + (f"  ({result['reason']})" if result["reason"] else ""))
    return result


def wait_recovery(ctx, t: Target, bound: int) -> tuple[bool, int]:
    t0 = time.time()
    while time.time() - t0 < bound:
        if steady(ctx, t):
            return True, int(time.time() - t0)
        time.sleep(2)
    return steady(ctx, t), int(time.time() - t0)


# ---------------------------------------------------------------- orchestration

def windows_text(names: list[str], duration_s: int, detail: bool = True) -> str:
    """'3 experiment(s), 45s each (one-shot 15s: pod-kill, container-kill)': a one-shot fault is injected once and
    watched for ONESHOT_WINDOW_S, not held for the duration. detail=False leaves the names out ('... (one-shot: 15s)'),
    so the run's header line is not cut off before it says it."""
    oneshot = [n for n in names if EXPERIMENTS.get(n, {}).get("oneshot")]
    if oneshot and len(oneshot) == len(names):
        return f"{len(names)} one-shot experiment(s), {ONESHOT_WINDOW_S}s each"
    text = f"{len(names)} experiment(s), {duration_s}s each"
    if not oneshot or int(duration_s) == ONESHOT_WINDOW_S:   # every window is the same length: nothing to tell apart
        return text
    return text + (f" (one-shot {ONESHOT_WINDOW_S}s: {', '.join(oneshot)})" if detail else f" (one-shot: {ONESHOT_WINDOW_S}s)")


def overall_verdict(report: dict) -> str:
    """PASS only when every experiment ran and passed; FAIL when any failed or errored; otherwise INCONCLUSIVE."""
    if report.get("verdict"):
        return str(report["verdict"])
    s = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    results = report.get("results") if isinstance(report.get("results"), list) else []
    if s.get("FAIL") or s.get("ERROR"):
        return "FAIL"
    return "PASS" if results and s.get("PASS", 0) == len(results) else "INCONCLUSIVE"


def _not_run(names: list[str], reason: str) -> list[dict]:
    return [{"experiment": n, "kind": EXPERIMENTS[n]["kind"], "desc": EXPERIMENTS[n]["desc"], "verdict": "SKIP", "reason": reason} for n in names]


def run(ctx, names: list[str] | None, suite: str | None, target: str | None, duration_s: int, replicas: int, keep: bool) -> int:
    """The whole thing: install → target → experiments → report. Returns 0 only when every experiment ran and passed.
    Only kubectl is needed (asked for on the first cluster call); helm only when Chaos Mesh still has to be installed,
    which platform.install checks itself."""
    _memo(ctx, "chaos_report", None)   # set again once this run's report is saved: never a previous run's on a reused context
    wanted = resolve_names(names, suite)
    if target:
        parse_target(target)
    # the CLI checks these too (--duration 15s..1h, --replicas 2..20); a direct caller must not get a run that measures nothing
    if not 0 < int(duration_s) <= 3600:
        raise ui.Abort(f"Experiment duration {duration_s}s is outside 1s..1h (the CLI takes 15s..1h: --duration 45s).")
    if not target and not 2 <= int(replicas) <= 20:
        raise ui.Abort(f"The canary needs 2..20 replicas (got {replicas}; with one replica pod-kill is an outage by design).")
    ensure_chaos_mesh(ctx)
    if any(EXPERIMENTS[w].get("needs") == "dns" for w in wanted) and not dns_chaos_available(ctx):
        ui.warn("dns-error needs the Chaos Mesh DNS server (chaos-dns-server); skipping it. Enable: cs platform install chaos-mesh --upgrade --set dnsServer.create=true")
        wanted = [w for w in wanted if EXPERIMENTS[w].get("needs") != "dns"]
    if not wanted:
        raise ui.Abort("Nothing left to run (dns-error needs chaos-dns-server). Pick other experiments: cs chaos list")
    run_id = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    ui.header(f"Chaos run {run_id} on {ctx.env.id}  ·  {windows_text(wanted, duration_s, detail=False)}")
    try:
        t = resolve_target(ctx, target, replicas)
    except KeyboardInterrupt:  # nothing was injected yet; don't leave the canary / probe behind
        if target:
            _kubectl(ctx, "-n", parse_target(target)[0], "delete", "pod", PROBE_NAME, "--ignore-not-found", "--wait=false")
        elif not keep:
            _kubectl(ctx, "delete", "ns", CANARY_NS, "--ignore-not-found", "--wait=false")
        raise
    ui.kv("Target", f"{t.ns}/{t.deploy}  (service {t.svc}:{t.port}, {'cloudseed canary' if t.canary else 'your workload'})")
    if not t.canary:
        ui.warn("Experiments run against YOUR workload: pods will be killed, delayed and stressed for the duration of each experiment.")
    results: list[dict] = []
    interrupted = False
    current = None
    try:
        baseline = steady(ctx, t)
        if not baseline:
            ui.warn(f"{t.ns}/{t.deploy} is not steady yet (available replicas / probe); waiting up to 120s before the first experiment")
            baseline = wait_recovery(ctx, t, 120)[0]
        if not baseline:
            ui.err(f"{t.ns}/{t.deploy} never became steady, so there is nothing to measure against; no fault was injected.")
            results += _not_run(wanted, "target not steady before the run (available replicas / probe failing)")
        else:
            for i, name in enumerate(wanted):
                current = name
                r = run_experiment(ctx, name, t, duration_s, run_id)
                results.append(r)
                current = None
                if r.get("verdict") == "SKIP" or r.get("stuck"):
                    why = "workload did not return to steady state" if r.get("verdict") == "SKIP" else f"{name}'s fault could not be removed"
                    results += _not_run(wanted[i + 1:], f"not run: {why}")
                    break
    except KeyboardInterrupt:
        interrupted = True
        ui.warn("interrupted; cleaning up experiments")
        done = {r["experiment"] for r in results}
        results += _not_run([n for n in wanted if n not in done], "not run: interrupted")
    except (Exception, ui.Abort) as ex:  # noqa: BLE001 - keep the results so far and still clean up + report
        msg = getattr(ex, "msg", "") or f"{type(ex).__name__}: {ex}"
        ui.err(f"chaos run stopped: {ui.clip(msg, 600)}")   # an Abort does not print itself: it is caught here, so say it
        done = {r["experiment"] for r in results}
        if current:
            results.append({"experiment": current, "kind": EXPERIMENTS[current]["kind"], "desc": EXPERIMENTS[current]["desc"], "verdict": "ERROR", "reason": ui.clip(msg, 300)})
            done.add(current)
        results += _not_run([n for n in wanted if n not in done], "not run: the run stopped on an error")
    finally:
        _cleanup_experiments(ctx, t)
        if t.canary and not keep:
            _kubectl(ctx, "delete", "ns", CANARY_NS, "--ignore-not-found", "--wait=false")
        elif not t.canary:
            _kubectl(ctx, "-n", t.ns, "delete", "pod", PROBE_NAME, "--ignore-not-found", "--wait=false")
    summary = {v: sum(1 for r in results if r.get("verdict") == v) for v in ("PASS", "FAIL", "SKIP", "ERROR")}
    report = {"run": run_id, "env": ctx.env.id, "target": f"{t.ns}/{t.deploy}", "canary": t.canary, "duration_s": duration_s,
              "distro": ctx.distro, "cloud": ctx.target, "results": results, "summary": summary}
    if t.labels or t.exprs:
        report["selector"] = t.selector_text()
    report["verdict"] = overall_verdict(dict(report, verdict=None))
    path = save_report(ctx, report)
    # the caller (cs chaos run) records exactly this run's report for undo - never a parallel run's that appeared meanwhile
    _memo(ctx, "chaos_report", path)
    print_report(report, path)
    audit.note(ctx.env, "chaos-run", {"run": report["run"], "verdict": report["verdict"], "summary": summary, "report": str(path)})
    if interrupted:
        return 130
    return 0 if report["verdict"] == "PASS" else 1


_VERDICT_STYLE = {"PASS": ("leaf", "PASS - every experiment held its steady-state hypothesis"),
                  "FAIL": ("rose", "FAIL - see the failing experiments"),
                  "INCONCLUSIVE": ("seed", "INCONCLUSIVE - not every experiment ran; nothing was proven")}


def _pct(value) -> int | None:
    """A 0..1 fraction as a whole percentage (None when it is not a number: an old or hand-edited report)."""
    try:
        return None if isinstance(value, bool) else round(100 * float(value))
    except (TypeError, ValueError, OverflowError):
        return None


def print_report(report: dict, path: Path | None = None) -> None:
    """The results panel; a report with missing or odd fields (an old or hand-edited one) still prints."""
    report = report if isinstance(report, dict) else {}
    rows = []
    results = [r for r in report.get("results") or [] if isinstance(r, dict)] if isinstance(report.get("results"), list) else []
    for r in results:
        v = str(r.get("verdict", "?"))
        mark = {"PASS": ui.style("✔ PASS", "leaf", "bold"), "FAIL": ui.style("✖ FAIL", "rose", "bold"), "SKIP": ui.style("○ SKIP", "muted"), "ERROR": ui.style("! ERR ", "rose")}.get(v, v)
        reason = str(r.get("reason") or "")
        avail, floor = _pct(r.get("availability")), _pct(r.get("min_availability"))
        if avail is not None and floor is not None and v in ("PASS", "FAIL"):
            detail = (f"availability {str(avail).rjust(3)}%  (min {floor}%)   "
                      f"recovered in {str(r.get('recovery_s', '?')).rjust(3)}s  (max {r.get('recovery_bound_s', '?')}s)")
        else:
            detail = reason
        rows.append(f"{mark}  {ui.style(str(r.get('experiment', '?')).ljust(20), 'text')} {detail}"
                    + (f"   {ui.dim(reason)}" if reason and detail != reason else ""))
    if not results:
        rows.append(ui.dim("no experiment ran"))
    s = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    verdict = overall_verdict(report)
    accent, line = _VERDICT_STYLE.get(verdict, ("rose", verdict))
    rows += ["", ui.style(line, accent, "bold"),
             f"{ui.style(str(s.get('PASS', 0)) + ' passed', 'leaf', 'bold')}   {ui.style(str(s.get('FAIL', 0)) + ' failed', 'rose' if s.get('FAIL') else 'muted')}   "
             f"{ui.dim(str(s.get('SKIP', 0)) + ' skipped, ' + _errors(s.get('ERROR', 0)))}"]
    if report.get("selector") and not report.get("canary"):
        rows.append(ui.dim(f"pod selector: {report['selector']}"))
    if path:
        rows.append(ui.dim(f"report: {path}  ·  {path.with_suffix('.md')}"))
    run = report.get("run") or (path.stem.replace("report-", "", 1) if path else "?")
    ui.panel(f"Chaos results · {report.get('env') or '?'} · {report.get('target') or '?'} · run {run}", rows, accent=accent)


def _errors(n) -> str:
    return f"{n} error" + ("" if n == 1 else "s")


def save_report(ctx, report: dict) -> Path:
    from .scan import claim_run_path, md_cell
    d = ctx.env.dir / "chaos"
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    path, report["run"] = claim_run_path(d, "report-", ".json", str(report.get("run") or time.strftime("%Y%m%d-%H%M%S", time.gmtime())))   # a parallel run never overwrites it
    # written to a temp file next to it and renamed onto the claimed name: an interrupted save never leaves a half-written report
    paths.atomic_write(path, json.dumps(report, indent=2, default=str) + "\n")
    results = [r for r in report.get("results") or [] if isinstance(r, dict)]
    md = [f"# Chaos run {report['run']} · {report.get('env', '?')}", "",
          f"Target: `{report.get('target', '?')}` ({'cloudseed canary' if report.get('canary') else 'user workload'}) · "
          f"{report.get('cloud', '?')}/{report.get('distro', '?')} · {windows_text([str(r.get('experiment', '')) for r in results], report.get('duration_s', 0))}", "",
          "| experiment | verdict | availability | hypothesis | recovery | bound | note |", "|---|---|---|---|---|---|---|"]
    for r in results:
        avail, floor = _pct(r.get("availability")), _pct(r.get("min_availability"))
        md.append(f"| {md_cell(r.get('experiment', '?'))} | {md_cell(r.get('verdict'))} | {'-' if avail is None else str(avail) + '%'} | "
                  f"{'-' if floor is None else '>= ' + str(floor) + '%'} | "
                  f"{str(r['recovery_s']) + 's' if 'recovery_s' in r else '-'} | {str(r['recovery_bound_s']) + 's' if 'recovery_bound_s' in r else '-'} | "
                  f"{md_cell(r.get('reason', ''))} |")
    s = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    md += ["", f"**{overall_verdict(report)}** · {s.get('PASS', 0)} passed · {s.get('FAIL', 0)} failed · {s.get('SKIP', 0)} skipped · "
               f"{_errors(s.get('ERROR', 0))}", ""]
    paths.atomic_write(path.with_suffix(".md"), "\n".join(md))
    return path


def last_report(env) -> Path | None:
    d = env.dir / "chaos"
    reports = sorted(d.glob("report-*.json")) if d.exists() else []
    return reports[-1] if reports else None


def load_last_report(env, quiet: bool = False) -> tuple[dict, Path] | None:
    """(report, path) of the newest readable chaos report; damaged or empty ones (an interrupted save) are skipped with a
    warning (none when quiet). Needs no cluster: `cs chaos report` only reads files."""
    d = env.dir / "chaos"
    for p in (sorted(d.glob("report-*.json"), reverse=True) if d.exists() else []):
        try:
            rep = json.loads(p.read_text())
        except (OSError, ValueError):
            rep = None
        if isinstance(rep, dict) and isinstance(rep.get("results"), list):
            return rep, p
        if not quiet:
            ui.warn(f"Skipping unreadable chaos report {p.name}")
    return None


def _last_report_row(env) -> str:
    found = load_last_report(env, quiet=True)
    if not found:
        last = last_report(env)
        return ui.dim(f"{last.name} is unreadable  (cs chaos run)" if last else "none yet  (cs chaos run)")
    rep, _ = found
    v = overall_verdict(rep)
    s = rep.get("summary") if isinstance(rep.get("summary"), dict) else {}
    return (ui.style(v, _VERDICT_STYLE.get(v, ("rose", ""))[0], "bold") + f" · {s.get('PASS', 0)}/{len(rep['results'])} passed · run {rep.get('run', '?')}"
            + ui.dim("  (cs chaos report)"))


def status(ctx) -> None:
    rows: list = [("Chaos Mesh", ui.style("installed", "leaf") if chaos_mesh_ready(ctx) else ui.dim("not installed  (cs platform install chaos-mesh, or cs chaos run installs it)")),
                  ("DNS chaos", "available" if dns_chaos_available(ctx) else ui.dim("no chaos-dns-server"))]
    for kind in CHAOS_KINDS[:5]:
        proc = _kubectl(ctx, "get", kind, "-A", "-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name} {end}")
        if proc.stdout.strip():
            rows.append((kind, proc.stdout.strip()))
    canary = _kubectl(ctx, "get", "ns", CANARY_NS).returncode == 0
    rows.append(("Canary namespace", CANARY_NS + (" (present)" if canary else " (absent)")))
    rows.append(("Last report", _last_report_row(ctx.env)))
    ui.panel(f"Chaos · {ctx.env.id}", rows)
    print(ui.dim("  cs chaos run [basic|network|stress|full|<experiment>...]   ·   cs chaos list"))
    print(ui.dim("  cs chaos stop   ·   cs chaos report"))


def list_experiments() -> None:
    rows = []
    for suite, members in SUITES.items():
        if suite == "full":
            continue
        rows.append(ui.style(f"{suite}", "bold", "text") + ui.dim(f"   cs chaos run {suite}"))
        for m in members:
            e = EXPERIMENTS[m]
            slo = f">= {round(100 * e['min_avail'])}% avail, recover <= {e['recover_s']}s" + ("  (outage expected)" if e.get("expect_outage") else "")
            rows.append(f"  {ui.style(m.ljust(20), 'text')} {e['desc']}")
            rows.append(" " * 23 + ui.dim(slo))
    rows.append(ui.style("full", "bold", "text") + ui.dim("   every experiment above"))
    ui.panel("Chaos experiments (Chaos Mesh)", rows)


def stop(ctx) -> None:
    kinds = CHAOS_KINDS
    namespaces = {CANARY_NS} | {line.split("/")[0] for kind in kinds
                                for line in _kubectl(ctx, "get", kind, "-A", "-l", LABEL, "-o", "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name} {end}").stdout.split()}
    for ns in namespaces:
        for kind in kinds:
            _kubectl(ctx, "-n", ns, "delete", kind, "-l", LABEL, "--ignore-not-found", "--wait=false")
        if ns != CANARY_NS:
            _kubectl(ctx, "-n", ns, "delete", "pod", PROBE_NAME, "--ignore-not-found", "--wait=false")
    _kubectl(ctx, "delete", "ns", CANARY_NS, "--ignore-not-found", "--wait=false")
    ui.ok("All cloudseed chaos experiments deleted; canary namespace removed.")
