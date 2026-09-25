from __future__ import annotations

import functools
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .. import localvm, netutil, paths, ui
from .base import Cloud, Question, as_bool, as_int, escape_literals

# Static address plan on the private network (fixed offsets, see terraform/vmware): bastion .2, workloads .10+,
# control planes .20-.39, workers .40+. Every static address stays at or below .127: VMware's host-only DHCP pool
# (vmnet1) starts at .128. With Kubernetes on a /24 (or larger) network, the LB_POOL_SIZE addresses just below the DHCP
# pool (.100-.127) are MetalLB's LoadBalancer pool (platform._lb_range), so workers stop at .99: a pool applied earlier
# never hands out an address that a worker added later takes.
WORKLOAD_BASE, CONTROL_PLANE_BASE, WORKER_BASE = 10, 20, 40
MAX_CONTROL_PLANES = 20
MAX_STATIC_HOST = 127
LB_POOL_SIZE = 28
# The VMs' DNS resolvers (the network config of terraform/vmware/modules/workloads and kubernetes)
GUEST_DNS = ("1.1.1.1", "8.8.8.8")

# kubernetes_version: an RKE2 release (INSTALL_RKE2_VERSION, e.g. v1.36.4+rke2r1) or a kubeadm version whose minor picks
# the pkgs.k8s.io repository (1.35, v1.35 or v1.35.2). The value reaches a shell command line in the rke2 role, so
# nothing but these shapes is accepted.
_RKE2_VERSION_RE = re.compile(r"v\d+\.\d+\.\d+\+rke2r\d+")
_KUBEADM_VERSION_RE = re.compile(r"v?\d+\.\d+(\.\d+)?")


def _size_rule(minimum: int, unit: str, multiple: int = 1, why: str = ""):
    """Validator for a VM size answer: a whole number >= minimum (and a multiple of `multiple`). The floors are what
    actually fails - VMware refuses 0 vCPUs or a memory size that is not a multiple of 4 MB only at power-on, after the
    network and other VMs were created, and a disk below the base image's size is silently not grown."""
    def check(value) -> str | None:
        try:
            n = int(str(value).strip())
        except ValueError:
            return "a whole number"
        if n < minimum:
            return f"must be at least {minimum}{unit}{why}"
        if n % multiple:
            return f"must be a multiple of {multiple} (VMware's rule for VM memory), e.g. {n - n % multiple or multiple}"
        return None
    check.minimum = minimum   # the Question's minimum (see _size)
    return check


_CPUS = _size_rule(1, " vCPU")
_MEMORY_MB = _size_rule(512, " (MB)", 4)
_DISK_GB = _size_rule(10, " (GB)", why=": the base image alone takes up to 3.5 GB")
_NODE_DISK_GB = _size_rule(20, " (GB)", why=": Kubernetes keeps its container images and etcd there")
# role -> (default vCPUs, default memory MB) of each kind of VM (<role>_cpus / <role>_memory_mb), for the host limits
_SIZES = {"bastion": (2, 2048), "workload": (2, 2048), "kubernetes": (2, 4096)}

# The first-boot cloud-config line of the previous bastion/workload template (it masked the apt timers on every boot,
# undoing the automatic updates the hardening enables). VMs created from it keep their recorded user-data (any change
# to it rebuilds a VM); see VMware.legacy_user_data.
_LEGACY_APT_MASK = "- [systemctl, mask, apt-daily.service, apt-daily-upgrade.service]"
_PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_STRAYS_REPORTED: set = set()   # (env id, bundle names) already reported by this process
_WARNED: set = set()            # (env id, message) of the address-plan warnings already shown by this process


@functools.lru_cache(maxsize=1)
def _host_memory_mb() -> int | None:
    """This computer's physical memory in MB, or None when it cannot be told."""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=10).stdout
            return int(out.strip()) // (1024 * 1024)
        if sys.platform.startswith("linux"):
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def _is_rfc1918(net) -> bool:
    return net.version == 4 and any(net.subnet_of(p) for p in _PRIVATE_V4)


def _as_int(value, default: int) -> int | None:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _as_bool(value) -> bool:
    """Lenient: a value that is not a boolean counts as off here (Cloud.invalid_answers reports it)."""
    try:
        return as_bool(value)
    except ValueError:
        return False


def kubernetes_version_problem(value, distro: str = "") -> str | None:
    """Problem with a kubernetes_version for this distribution ('' = either), or None. Empty means automatic."""
    v = str(value or "").strip()
    if not v:
        return None
    rke2 = "an RKE2 release such as v1.36.4+rke2r1 (github.com/rancher/rke2/releases)"
    kubeadm = "a Kubernetes version such as 1.35 (kubeadm installs that minor's latest patch)"
    if distro == "rke2":
        return None if _RKE2_VERSION_RE.fullmatch(v) else f"with kubernetes_distro=rke2 use {rke2}, or leave it empty"
    if distro == "kubeadm":
        return None if _KUBEADM_VERSION_RE.fullmatch(v) else f"with kubernetes_distro=kubeadm use {kubeadm}, or leave it empty"
    if _RKE2_VERSION_RE.fullmatch(v) or _KUBEADM_VERSION_RE.fullmatch(v):
        return None
    return f"use {rke2} or {kubeadm}; empty = automatic"


def _control_planes_problem(value) -> str | None:
    try:
        n = int(str(value).strip())
    except ValueError:
        return "a whole number"
    return None if 1 <= n <= MAX_CONTROL_PLANES else f"must be 1-{MAX_CONTROL_PLANES}"


class _Bounded(Question):
    """An int Question whose bounds (minimum/maximum: the CLI checks them, and the web console's number field gets them
    from the catalog) are reported by its own validator, which names the unit and the reason ("must be at least 512
    (MB)", "must be a multiple of 4 ...") rather than the generic "must be >= 512"."""

    def coerce(self, value):
        try:
            return super().coerce(value)
        except ValueError:
            try:
                number = as_int(value, minimum=-sys.maxsize)
            except ValueError:
                raise   # not a whole number at all: as_int's own message
            # the parsed number, as Question.coerce passes it: a JSON 100.0 (web console, MCP) is 100, not "100.0"
            problem = self.validate(str(number)) if self.validate else None
            if problem:
                raise ValueError(problem) from None
            raise


def _size(key: str, prompt: str, default: int, rule, **kw) -> _Bounded:
    """A VM size question: its rule's floor is also its minimum."""
    return _Bounded(key, prompt, default, kind="int", validate=rule, minimum=rule.minimum, **kw)


def _state_resources(state_file: Path) -> list[dict]:
    """The managed resources recorded in a local Terraform state file."""
    try:
        data = json.loads(state_file.read_text())
    except (OSError, ValueError):
        return []
    return [r for r in data.get("resources") or [] if isinstance(r, dict) and r.get("mode") == "managed" and r.get("instances")]


def _state_vms(state_file: Path, live: bool = False) -> list[dict]:
    """The vmdesktop_vm instances recorded in a local Terraform state file (attributes only). live: without tainted
    ones (half-created by a failed apply; the next apply replaces them)."""
    out = []
    for r in _state_resources(state_file):
        if r.get("type") == "vmdesktop_vm":
            out += [i.get("attributes") or {} for i in r.get("instances") or []
                    if isinstance(i, dict) and not (live and i.get("status") == "tainted")]
    return out


def _recorded_path(cfg: dict, path) -> str:
    """A path the provider recorded in the state (vmx_path), resolved: older versions kept a relative vm_dir as given,
    and the provider then recorded paths relative to Terraform's working directory, <workdir>/stack."""
    return localvm.recorded_vmx_path(path, cfg.get("workdir"))


def _default_vm_dir(cfg: dict) -> str:
    """<workdir>/vms: every environment keeps its VMs in a directory of its own. Without a working directory yet (the
    web console's form) it is the relative "vms" the prompt describes."""
    return str(Path(cfg.get("workdir", localvm.VMS_DIR)) / "vms")


class VMware(Cloud):
    key = "vmware"
    display = "VMware Fusion / Workstation (local)"
    local = True
    region_prompt = "Location"
    default_region = "local"
    cli_tool = ""
    login_hint = "no cloud login needed"

    questions = [
        Question("guest_os", f"Guest OS for the VMs ({', '.join(localvm.IMAGES)})", localvm.DEFAULT_OS,
                 choices=tuple(localvm.IMAGES)),
        Question("workload_count", "Private workload VMs behind the bastion", 0, kind="int", minimum=0),
        Question("ssh_username", "Login username on the VMs", lambda cfg: netutil.local_username(),
                 validate=netutil.validate_login_username),
        Question("fips_mode", "FIPS 140 mode for every VM (Ubuntu Pro FIPS via UBUNTU_PRO_TOKEN, FIPS-only SSH, RKE2)?", False, kind="bool"),
        Question("enable_kubernetes", "Create a Kubernetes cluster on private VMs (RKE2 or kubeadm)?", False, kind="bool"),
        Question("kubernetes_distro", "Kubernetes distribution: rke2 (recommended) or kubeadm", "rke2", choices=("rke2", "kubeadm")),
        Question("kubernetes_version", "Kubernetes version: an RKE2 release (e.g. v1.36.4+rke2r1) or a kubeadm minor (e.g. "
                 "1.35); empty = automatic (RKE2's stable channel / kubeadm's supported default; nodes added later match "
                 "the cluster)", "", advanced=True, validate=kubernetes_version_problem),
        Question("kubernetes_cis_profile", "RKE2 CIS hardening profile (enforces the restricted Pod Security Standard "
                 "outside the system namespaces; cloudseed exempts its own - cloudseed-scan, velero, local-path-storage, "
                 "minio, chaos-mesh - and `cs platform install` labels the namespaces of other items that need host "
                 "access; your own such workloads need a privileged namespace label)?", False, kind="bool", advanced=True),
        _Bounded("kubernetes_control_planes", f"Control-plane nodes (1-{MAX_CONTROL_PLANES})", 1, kind="int", advanced=True,
                 validate=_control_planes_problem, minimum=1, maximum=MAX_CONTROL_PLANES),
        Question("kubernetes_workers", "Worker nodes", 2, kind="int", advanced=True, minimum=0),
        _size("kubernetes_cpus", "vCPUs per Kubernetes node", 2, _CPUS, advanced=True),
        _size("kubernetes_memory_mb", "Memory per Kubernetes node (MB)", 4096, _MEMORY_MB, advanced=True),
        _size("kubernetes_disk_gb", "Disk per Kubernetes node (GB)", 40, _NODE_DISK_GB, advanced=True),
        _size("bastion_cpus", "Bastion vCPUs", 2, _CPUS, advanced=True),
        _size("bastion_memory_mb", "Bastion memory (MB)", 2048, _MEMORY_MB, advanced=True),
        _size("bastion_disk_gb", "Bastion disk (GB)", 20, _DISK_GB, advanced=True),
        _size("workload_cpus", "Workload vCPUs", 2, _CPUS, advanced=True),
        _size("workload_memory_mb", "Workload memory (MB)", 2048, _MEMORY_MB, advanced=True),
        _size("workload_disk_gb", "Workload disk (GB)", 20, _DISK_GB, advanced=True),
        Question("vm_dir", "Directory for the VM files (absolute, ~/..., or relative to the working directory)",
                 lambda cfg: _default_vm_dir(cfg), advanced=True),
    ]

    outputs = ["host_product", "host_version", "guest_arch", "private_vmnet", "private_vmnet_adopted", "private_cidr", "bastion_public_ip",
               "bastion_private_ip", "workload_private_ips", "workload_names", "ssh_user",
               "kubernetes_distro", "kubernetes_control_plane_ips", "kubernetes_worker_ips", "kubernetes_endpoint", "fips_mode"]
    bootstrap_outputs: list[str] = []

    def ssh_user(self, cfg):
        return cfg["vars"].get("ssh_username") or netutil.local_username()

    def required_providers(self):
        return {"vmdesktop": {"source": "registry.local/cloudseed/vmdesktop", "version": "~> 0.1"},
                "random": {"source": "hashicorp/random", "version": "~> 3.6"}}

    def provider_block(self, cfg):
        return {"vmdesktop": {}}

    # ---- validation (setup refuses these before anything is saved or created) ----
    def value_problem(self, q, value, cfg):
        problem = super().value_problem(q, value, cfg)   # login names: netutil.validate_login_username
        v = cfg.get("vars") or {}
        distro = str(v.get("kubernetes_distro") or "rke2")
        if problem is None and q.key == "kubernetes_version":
            problem = kubernetes_version_problem(value, distro)
        if problem is None and q.key == "kubernetes_cis_profile" and distro == "kubeadm" and _as_bool(value):
            problem = "the CIS profile is RKE2's (kubernetes_distro=rke2); kubeadm clusters have none"
        if problem is None and q.key in ("kubernetes_cpus", "kubernetes_memory_mb") and _as_bool(v.get("enable_kubernetes")):
            n = _as_int(value, 0)
            if q.key == "kubernetes_cpus" and distro == "kubeadm" and n is not None and n < 2:
                problem = "kubeadm needs at least 2 vCPUs per node (its preflight check refuses fewer)"
            elif q.key == "kubernetes_memory_mb" and n is not None and n < 2048:
                problem = (f"{'RKE2' if distro == 'rke2' else 'kubeadm'} needs at least 2048 MB per node" +
                           (" (kubeadm's preflight check refuses less than ~1700 MB)" if distro == "kubeadm" else
                            "; 4096 is recommended"))
        return problem

    def network_problems(self, cfg: dict) -> list[str]:
        return super().network_problems(cfg) + self.address_problems(cfg) + self.host_problems(cfg)

    def host_problems(self, cfg: dict) -> list[str]:
        """VM sizes this computer cannot give: VMware refuses a VM with more vCPUs than the host has logical CPUs, or
        more memory than it has. Checked at setup (not saved as a rule of the answer): a configuration moved to a
        smaller computer is reported with the fix, not locked out."""
        v = cfg.get("vars") or {}
        cpus, memory = os.cpu_count() or 0, _host_memory_mb()
        used = {"bastion": True, "workload": (_as_int(v.get("workload_count"), 0) or 0) > 0,
                "kubernetes": _as_bool(v.get("enable_kubernetes", False))}
        problems = []
        for role, (cpu_default, mem_default) in _SIZES.items():
            if not used[role]:
                continue
            c, m = _as_int(v.get(f"{role}_cpus"), cpu_default), _as_int(v.get(f"{role}_memory_mb"), mem_default)
            if cpus and c is not None and c > cpus:
                problems.append(f"{role}_cpus={c}: this computer has {cpus} logical CPUs, and VMware cannot give a VM more; "
                                f"fix: --var {role}_cpus={min(cpu_default, cpus)}")
            if memory and m is not None and m > memory:
                problems.append(f"{role}_memory_mb={m}: more than this computer's {memory} MB of memory; "
                                f"fix: --var {role}_memory_mb={min(mem_default, memory // 2 // 4 * 4)}")
        return problems

    def address_problems(self, cfg: dict) -> list[str]:
        """The VM counts must fit the fixed address plan of the private network, or VMs would share an IP (workload
        vm11 = control plane cp1 = the Kubernetes API) or land in VMware's DHCP pool or MetalLB's LoadBalancer pool; the
        network must be a private range, and with Kubernetes on it must not overlap the cluster's pod/Service ranges."""
        v = cfg.get("vars") or {}
        raw = str(cfg.get("network_cidr") or "10.100.0.0/24")
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return [f"network CIDR {raw!r} is not a valid network (e.g. 10.123.0.0/24)"]
        if net.version != 4:
            return [f"network CIDR {raw}: the VMs' private network must be IPv4 (e.g. 10.123.0.0/24)"]
        if net.prefixlen > 29:
            return [f"network CIDR {raw} is too small; use a /29 or larger (/24 recommended)"]
        problems = []
        if cfg.get("cidr_explicit") and not _is_rfc1918(net):
            # (never second-guesses a network VMware assigned itself; one an existing environment already runs on is
            # only warned about, so it stays manageable and destroyable)
            if self.is_new(cfg):
                problems.append(self.public_range_problem(net))
            else:
                self._warn_public_range(cfg, net)
        max_host = min(MAX_STATIC_HOST, net.num_addresses - 2)
        k8s = _as_bool(v.get("enable_kubernetes", False))
        wc = _as_int(v.get("workload_count"), 0)
        limit = CONTROL_PLANE_BASE - WORKLOAD_BASE if k8s else max(max_host - WORKLOAD_BASE + 1, 0)
        if wc is not None and wc > limit:
            if k8s:
                why = (f"with Kubernetes on, workloads use .{WORKLOAD_BASE}-.{CONTROL_PLANE_BASE - 1} and its control "
                       f"planes start at .{CONTROL_PLANE_BASE}")
            elif limit:
                why = f"static addresses .{WORKLOAD_BASE}-.{max_host}"
            else:
                why = f"workloads use .{WORKLOAD_BASE} and up, and its last usable address is .{max_host}"
            problems.append(f"workload_count={wc}: at most {limit} on {net} ({why}); fix: --var workload_count={limit}"
                            + ("" if limit or k8s else ", or a /28 or larger --cidr"))
        if k8s:
            problems += self._cluster_range_problems(cfg, net, str(v.get("kubernetes_distro") or "rke2"))
            cps = _as_int(v.get("kubernetes_control_planes"), 1)
            wks = _as_int(v.get("kubernetes_workers"), 2)
            cp_limit = min(MAX_CONTROL_PLANES, max(max_host - CONTROL_PLANE_BASE + 1, 0))
            if cp_limit == 0:
                problems.append(f"Kubernetes needs a larger network than {net}: its control planes use .{CONTROL_PLANE_BASE}-"
                                f".{CONTROL_PLANE_BASE + MAX_CONTROL_PLANES - 1} (a /26 or larger, /24 recommended)")
                return problems
            if cps is not None and not 1 <= cps <= cp_limit:
                problems.append(f"kubernetes_control_planes={cps}: must be 1-{cp_limit} on {net} (static addresses .{CONTROL_PLANE_BASE}-"
                                f".{CONTROL_PLANE_BASE + cp_limit - 1}); fix: --var kubernetes_control_planes={min(3, cp_limit)}")
            if wks is not None:
                problems += self._worker_problems(cfg, net, max_host, wks)
        return problems

    def public_range_problem(self, net) -> str:
        """Why a (new) private network may not be `net`, a range outside RFC 1918."""
        dns = [d for d in GUEST_DNS if ipaddress.ip_address(d) in net]
        return (f"network CIDR {net} is not a private (RFC 1918) range: a host-only network on it gives this computer a "
                f"direct route to it, hiding the real hosts there (e.g. {dns[0] if dns else net.network_address + 1})"
                + (f", and the VMs could no longer reach their DNS server{'s' if len(dns) > 1 else ''} {', '.join(dns)}"
                   if dns else "")
                + "; use a range in 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16, e.g. --cidr 10.123.0.0/24")

    def _warn_public_range(self, cfg: dict, net) -> None:
        dns = [d for d in GUEST_DNS if ipaddress.ip_address(d) in net]
        self._warn_once(cfg, f"{self._env_id(cfg)} runs on {net}, which is not a private (RFC 1918) range: this computer "
                             "cannot reach the real hosts of that range while the network exists"
                             + (f", and the VMs cannot reach their DNS server{'s' if len(dns) > 1 else ''} {', '.join(dns)}"
                                if dns else "")
                             + ". Destroy it and set it up again with a private --cidr (e.g. 10.123.0.0/24) to fix it.")

    def _worker_problems(self, cfg: dict, net, max_host: int, wks: int) -> list[str]:
        """Workers take .40 and up, below VMware's DHCP pool (.128 on a /24) and, on a /24 or larger network, below
        MetalLB's LoadBalancer pool (.100-.127). Workers an existing cluster already has in that pool's range (created
        before it was kept free) are only warned about: refusing would lock the environment out of setup."""
        dhcp_limit = max(max_host - WORKER_BASE + 1, 0)
        lb = max_host == MAX_STATIC_HOST                            # a /24 or larger: MetalLB keeps .100-.127
        top = MAX_STATIC_HOST - LB_POOL_SIZE if lb else max_host    # the last address a worker may take (.99 on a /24)
        limit = max(top - WORKER_BASE + 1, 0)
        if wks <= limit:
            return []
        have = self._live_nodes(cfg, "wk") if lb else 0
        pool = f".{top + 1}-.{MAX_STATIC_HOST}"
        if wks <= have and wks <= dhcp_limit:
            names = f"wk{limit + 1}" + (f"-wk{wks}" if wks > limit + 1 else "")
            prefix = f"{cfg.get('name') or 'cloudseed'}-{cfg.get('env')}"
            self._warn_once(cfg, f"{self._env_id(cfg)}: worker(s) {names} use addresses in {pool} of {net}, which are kept "
                                 "for MetalLB's LoadBalancer pool (cloudseed platform install metallb), so a LoadBalancer "
                                 f"service could get a worker's address. Keep at most {limit} workers before you use "
                                 f"LoadBalancer services: remove the ones above wk{limit}, highest first (cloudseed node "
                                 f"remove {prefix}-wk{wks} vmware --env {cfg.get('env')}, ...).")
            return []
        allowed = min(max(limit, have), dhcp_limit)
        if lb and allowed > limit:   # an existing cluster with workers in the pool's range: it keeps them, never more
            where = (f"workers use .{WORKER_BASE}-.{top} and {pool} are kept for LoadBalancer addresses (MetalLB); this "
                     f"cluster already has {have} workers, so it keeps them but cannot grow")
        elif lb:
            where = (f"workers use .{WORKER_BASE}-.{top}; {pool} are kept for LoadBalancer addresses (MetalLB) and "
                     f"VMware's DHCP pool starts at .{MAX_STATIC_HOST + 1}")
        elif limit:
            where = f"static addresses .{WORKER_BASE}-.{max_host}, below VMware's DHCP pool"
        else:
            where = f"workers use .{WORKER_BASE} and up, which {net} does not have"
        return [f"kubernetes_workers={wks}: at most {allowed} on {net} ({where}); fix: --var kubernetes_workers={allowed}"]

    def _cluster_range_problems(self, cfg: dict, net, distro: str) -> list[str]:
        """The private network must not overlap the pod or Service range of the cluster (RKE2 10.42/16 + 10.43/16,
        kubeadm 10.244/16 + 10.96/16): Service IPs would land on real hosts and pod routes shadow the nodes. Refused for
        a new environment or when Kubernetes is being turned on (no control-plane VM yet); a cluster that already runs
        there is only warned about. provision.provision_local_kubernetes also refuses to install a cluster there that
        was never installed."""
        from .. import provision   # (imported here: provision pulls in the provisioning modules)
        clash = provision.local_k8s_range_problems(str(net), distro)
        if not clash:
            return []
        if not self.is_new(cfg) and self._cluster_exists(cfg):
            self._warn_once(cfg, f"{self._env_id(cfg)}: {'; '.join(clash)}. Services or pods may collide with hosts on the "
                                 "network; the cluster is left as it is (an environment on another network, e.g. --cidr "
                                 "10.123.0.0/24, avoids it).")
            return []
        other = "kubeadm" if distro == "rke2" else "rke2"
        alt = "" if provision.local_k8s_range_problems(str(net), other) else f", or --var kubernetes_distro={other}"
        text = " ".join(clash)
        why = " and ".join(w for k, w in (("the pod range", "pod routes would shadow the nodes"),
                                          ("the Service range", "Service IPs would land on hosts of the network"))
                           if k in text)
        return [f"{'; '.join(clash)}: {why}; use another network (e.g. --cidr 10.123.0.0/24){alt}"]

    def _cluster_exists(self, cfg: dict) -> bool:
        """A Kubernetes cluster of this environment exists: its control-plane VMs are in the state (a tainted one too: a
        replacement that failed is re-created into the same cluster). A provisioned.kubernetes record alone does not
        count: older versions kept it after Kubernetes was turned off and its VMs destroyed (now the apply or destroy
        that removes them drops it: provision.forget_removed_cluster), and turning it on again creates a new cluster -
        which the network must be able to carry."""
        return self._live_nodes(cfg, "cp", live=False) > 0

    def _live_nodes(self, cfg: dict, role: str, live: bool = True) -> int:
        """The highest number N of this environment's live <prefix>-<role>N VMs in its Terraform state (0: none).
        live=False: tainted ones (half-created by a failed apply) count too."""
        if not cfg.get("workdir"):
            return 0
        top = 0
        for a in _state_vms(Path(cfg["workdir"]) / "stack" / "terraform.tfstate", live=live):
            m = re.search(rf"-{role}(\d+)$", str(a.get("name") or ""))
            if m:
                top = max(top, int(m.group(1)))
        return top

    def _warn_once(self, cfg: dict, msg: str) -> None:
        """ui.warn, once per process: the address plan is checked more than once per command (setup, prepare)."""
        key = (self._env_id(cfg), msg)
        if key not in _WARNED:
            _WARNED.add(key)
            ui.warn(msg)

    # ---- the VM directory ----
    def _vm_dir_in_state(self, cfg: dict, raw: str) -> bool:
        """Do this environment's VMs already use exactly this vm_dir string? The VM's `path` forces a rebuild when it
        changes at all, so such a value is kept as it is - an old relative / ~ value (older versions passed it straight
        to Terraform, whose provider put the VMs under <workdir>/stack/<vm_dir>), and equally an absolute one that
        normalizing would merely re-spell (a trailing '/', '//', '..')."""
        if not raw or not cfg.get("workdir"):
            return False
        return any(a.get("path") == raw for a in _state_vms(Path(cfg["workdir"]) / "stack" / "terraform.tfstate"))

    def vm_dir_value(self, cfg: dict) -> str:
        """vm_dir as Terraform gets it: absolute ('~' expanded, a relative path taken from the environment's working
        directory), except for an environment whose VMs already live under that exact value."""
        raw = str((cfg.get("vars") or {}).get("vm_dir") or "").strip()
        if not raw:
            return _default_vm_dir(cfg)
        if self._vm_dir_in_state(cfg, raw):
            return raw
        p = Path(os.path.expanduser(raw))
        if not p.is_absolute():
            p = Path(cfg.get("workdir") or os.getcwd()) / p
        return str(Path(os.path.normpath(str(p))))

    def vm_dir_path(self, cfg: dict) -> Path:
        """Where this environment's VM bundles actually are on disk (for the leftover sweep and troubleshooting)."""
        value = self.vm_dir_value(cfg)
        if not os.path.isabs(value) and cfg.get("workdir"):
            return Path(cfg["workdir"]) / "stack" / value
        return Path(value)

    def _prefix(self, cfg: dict) -> str:
        """<name>-<env>: every VM bundle of the environment is <prefix>-bastion|vmN|cpN|wkN.vmwarevm."""
        return f"{cfg.get('name')}-{cfg.get('env')}"

    def vm_dir_report(self, cfg: dict) -> dict:
        """Who else keeps VMs in this environment's vm_dir: {"dir": resolved path, "shared": [(env id, prefix)] of the
        other VMware environments configured with the same directory, "foreign": [bundle names] of VMs there that are
        neither this environment's nor one of those, "stray": [bundle names] named like this environment's VMs but not
        in its Terraform state (an earlier environment of the same name, or lost state) - apply moves such a bundle aside
        instead of creating that VM over it, and refuses while it runs}. Destroy only ever removes this environment's own
        bundles; this is what setup tells the user about before VMs land next to someone else's."""
        here = os.path.realpath(str(self.vm_dir_path(cfg)))
        me, workdir = self._env_id(cfg), os.path.realpath(str(cfg.get("workdir") or ""))
        shared: list[tuple[str, str]] = []
        for e in paths.Env.list_all():
            if e.cloud != self.key or e.id == me or os.path.realpath(str(e.dir)) == workdir:
                continue
            other, problem = e.try_load()
            if problem or not other:
                continue
            other = {**other, "workdir": other.get("workdir") or str(e.dir), "env": other.get("env") or e.name}
            try:
                there = os.path.realpath(str(self.vm_dir_path(other)))
            except (TypeError, ValueError, OSError):
                continue
            if there == here:
                shared.append((e.id, self._prefix(other)))
        state = Path(str(cfg["workdir"])) / "stack" / "terraform.tfstate" if cfg.get("workdir") else None
        known = {_recorded_path(cfg, a["vmx_path"]) for a in (_state_vms(state) if state else []) if a.get("vmx_path")}
        foreign: list[str] = []
        stray: list[str] = []
        try:
            bundles = sorted(Path(here).glob("*.vmwarevm")) if os.path.isdir(here) else []
        except OSError:
            bundles = []
        mine = self._prefix(cfg)
        for b in bundles:
            try:
                if any(os.path.realpath(str(x)) in known for x in b.glob("*.vmx")):
                    continue
                if localvm.env_vm_bundle(b.name, mine):
                    # another environment with the same names in this directory owns it (reported as a clash); the
                    # debris of this environment's own failed create carries the provider's marker and is replaced
                    if not any(prefix == mine for _, prefix in shared) and not (b / localvm.INCOMPLETE_MARKER).exists():
                        stray.append(b.name)
                    continue
            except OSError:
                continue
            if any(localvm.env_vm_bundle(b.name, prefix) for _, prefix in shared):
                continue
            foreign.append(b.name)
        return {"dir": here, "shared": shared, "foreign": foreign, "stray": stray}

    def _report_strays(self, cfg: dict, report: dict, host: dict | None = None) -> None:
        """Warn (once per run) about bundles named like this environment's VMs that its state does not know. With the
        host at hand, one that is running stops the run before anything is created: applying would fail on it."""
        names = report.get("stray") or []
        if not names:
            return
        me, where = self._env_id(cfg), report["dir"]
        if host:
            running = {os.path.realpath(p) for p in localvm.vmrun_list(host)}
            busy = [n for n in names if any(os.path.realpath(str(x)) in running for x in (Path(where) / n).glob("*.vmx"))]
            if busy:
                raise ui.Abort(f"{', '.join(busy)} in {where} {'is' if len(busy) == 1 else 'are'} running, named like "
                               f"{me}'s VMs but not in its Terraform state (an earlier environment of the same name, or "
                               "lost state). cloudseed will not create a VM over a running one: stop it (and move it out of "
                               f"{where} if you want to keep it), then retry.")
        key = (me, tuple(names))
        if key in _STRAYS_REPORTED:
            return
        _STRAYS_REPORTED.add(key)
        shown = ", ".join(names[:5]) + (" ..." if len(names) > 5 else "")
        ui.warn(f"vm_dir {where} already holds {shown}: named like {me}'s VMs but not in its Terraform state (an earlier "
                "environment of the same name, a create that failed under an older cloudseed, or lost state). Applying never "
                "deletes them: a VM this environment creates under such a name moves the old bundle aside first "
                "(<name>.replaced-<time>.vmwarevm). Delete or move them if you do not need them; `cloudseed destroy` deletes "
                "every VM named like this environment's.")

    def _refuse_missing_vm_dir(self, cfg: dict) -> None:
        """This environment's VMs are recorded in a vm_dir that is not there - its external or network volume is not
        mounted, most likely. Stop before anything is created: apply would otherwise create an empty vm_dir, the provider
        would find no VMs in it, drop them from the state and create new ones (the provider's own check only covers a
        directory whose parent is missing too)."""
        where = self.vm_dir_path(cfg)
        if not cfg.get("workdir") or os.path.isdir(where):
            return
        here = os.path.realpath(str(where))
        vms = [a for a in _state_vms(Path(cfg["workdir"]) / "stack" / "terraform.tfstate", live=True)
               if a.get("vmx_path") and os.path.dirname(os.path.dirname(_recorded_path(cfg, a["vmx_path"]))) == here]
        if vms:
            raise ui.Abort(f"vm_dir {where} does not exist, but {self._env_id(cfg)}'s Terraform state records {len(vms)} VM(s) "
                           "there: is the disk holding it unmounted (an external or network volume)? Mount it and retry; "
                           f"nothing was changed. If those VMs are really gone, create the directory (mkdir -p '{where}') "
                           "and retry: they then leave the state and are created again.")

    def check_vars(self, cfg: dict) -> None:
        """setup: refuse a vm_dir where this environment's VMs would take another environment's bundle names, and warn
        when the directory is shared or already holds VMs that are not this environment's."""
        parent = getattr(super(), "check_vars", None)
        if parent:
            parent(cfg)
        report = self.vm_dir_report(cfg)
        where, me = report["dir"], self._env_id(cfg)
        clash = [i for i, prefix in report["shared"] if prefix == self._prefix(cfg)]
        if clash:
            msg = (f"{me} and {', '.join(clash)} both name their VMs {self._prefix(cfg)}-* in {where}, so they would "
                   "take over each other's VM files")
            if self.is_new(cfg):
                raise ui.Abort(f"{msg}. Give this environment its own directory (--var vm_dir=<dir>, default <workdir>/vms) "
                               "or another --name.")
            ui.warn(f"{msg}. Destroy one of them to fix it.")
        others = [i for i, _ in report["shared"] if i not in clash]
        if others:
            ui.warn(f"vm_dir {where} is also used by {', '.join(others)}. The VMs stay apart by name (<name>-<env>-...) and "
                    f"destroy only removes {me}'s own, but a directory per environment (the default <workdir>/vms) keeps them "
                    "fully separate.")
        if report["foreign"]:
            names = report["foreign"]
            ui.warn(f"vm_dir {where} already holds {len(names)} VM(s) that are not {me}'s: {', '.join(names[:5])}"
                    + (" ..." if len(names) > 5 else "") + f". cloudseed never touches them (destroy removes only "
                    f"{self._prefix(cfg)}-* VMs), but a directory of its own (the default <workdir>/vms) is safer.")
        self._report_strays(cfg, report)

    def nat_source_cidrs(self, cfg: dict) -> list[str]:
        """The part of the private network the bastion should route and trust: the static zone of the address plan
        (.1-.127), not VMware's DHCP pool above it, where the host-only vmnet shared with other VMs and tools hands out
        addresses. Networks of /25 or smaller are static only, so the whole network."""
        try:
            net = ipaddress.ip_network(str(cfg.get("network_cidr")), strict=False)
        except ValueError:
            return [str(cfg.get("network_cidr"))]
        if net.version != 4 or net.prefixlen >= 25:
            return [str(net)]
        return [str(ipaddress.ip_network(f"{net.network_address}/25"))]

    # ---- terraform ----
    def stack_vars(self, cfg):
        v = cfg["vars"]
        # typed reads of the saved answers: a bad saved value (an older version's "no", "abc") is reported with its fix
        # instead of silently switching a feature on (bool("no") is True) or crashing with a traceback
        n, on = functools.partial(self.var_int, cfg), functools.partial(self.var_bool, cfg)
        return {
            "name": cfg["name"],
            "environment": cfg["env"],
            "private_cidr": cfg["network_cidr"],
            "base_disk": v.get("base_disk", ""),
            "guest_os_id": v.get("guest_os_id", "ubuntu-64"),
            "vm_dir": self.vm_dir_value(cfg),
            "ssh_public_key": cfg["ssh_public_key"],
            "ssh_username": self.ssh_user(cfg),
            "bastion_cpus": n("bastion_cpus", 2),
            "bastion_memory_mb": n("bastion_memory_mb", 2048),
            "bastion_disk_gb": n("bastion_disk_gb", 20),
            "workload_count": n("workload_count", 0),
            "workload_cpus": n("workload_cpus", 2),
            "workload_memory_mb": n("workload_memory_mb", 2048),
            "workload_disk_gb": n("workload_disk_gb", 20),
            "fips_mode": on("fips_mode", False),
            "enable_kubernetes": on("enable_kubernetes", False),
            "kubernetes_distro": v.get("kubernetes_distro", "rke2"),
            "kubernetes_control_planes": n("kubernetes_control_planes", 1),
            "kubernetes_workers": n("kubernetes_workers", 2),
            "kubernetes_cpus": n("kubernetes_cpus", 2),
            "kubernetes_memory_mb": n("kubernetes_memory_mb", 4096),
            "kubernetes_disk_gb": n("kubernetes_disk_gb", 40),
            "tags": self.tags(cfg),
        }

    def render_stack(self, cfg, tf_root):
        """The stack root, plus legacy_user_data: an internal input derived from the Terraform state (declared in the
        module's main.tf, not variables.tf - it is no setting, so neither --var nor the variable listings offer it)."""
        root = super().render_stack(cfg, tf_root)
        root["module"]["stack"]["legacy_user_data"] = escape_literals(self.legacy_user_data(cfg))
        return root

    def legacy_user_data(self, cfg: dict) -> dict[str, str]:
        """{VM name: its recorded cloud-init user-data} of this environment's bastion and workload VMs created from the
        previous first-boot template, which masked the apt timers on every boot (so the automatic security updates the
        hardening enables stopped at the first reboot). Any change to a VM's cloud-init rebuilds it, so the stack keeps
        rendering that template for such a VM as long as its other inputs are unchanged - it is never rebuilt just by
        upgrading cloudseed - and new VMs get the current one."""
        if not cfg.get("workdir"):
            return {}
        out = {}
        for a in _state_vms(Path(cfg["workdir"]) / "stack" / "terraform.tfstate", live=True):
            name, ud = str(a.get("name") or ""), str((a.get("cloud_init") or {}).get("user_data") or "")
            if re.search(r"-(bastion|vm\d+)$", name) and _LEGACY_APT_MASK in ud and "cloud-init-per" not in ud:
                out[name] = ud
        return out

    def bootstrap_vars(self, cfg):
        raise ui.Abort("Local environments keep Terraform state locally; remote state is not available for vmware.")

    def backend_from_outputs(self, cfg, outputs):
        raise ui.Abort("Local environments keep Terraform state locally.")

    def credential_warnings(self, cfg):
        h = localvm.detect_host()
        if not h or not h["found"]:
            return [localvm.vmware_home_problem(h) or
                    f"VMware Desktop not found (vmrun). Install: {(h or {}).get('install', 'Fusion Pro / Workstation Pro')}"]
        too_old = localvm.version_problem(h)
        return [too_old] if too_old else []

    # ---- other environments on the same network ----
    def _env_id(self, cfg: dict) -> str:
        return f"{self.key}-{cfg.get('env')}"

    def is_new(self, cfg: dict) -> bool:
        """No VM of this environment exists (none in its Terraform state; a tainted one - half-created by a failed apply -
        is replaced anyway). Only its network and MAC numbers may be left from a first apply that failed, and such an
        environment is held to every rule a new one is: a retry would otherwise create VMs on the fixed addresses of an
        environment that took the network meanwhile. Environments with VMs are only warned, so they stay manageable;
        destroy never reaches these checks (it runs prepare(dry_run=True), then its own teardown preparation)."""
        return not (cfg.get("workdir") and _state_vms(Path(cfg["workdir"]) / "stack" / "terraform.tfstate", live=True))

    def network_neighbours(self, cfg: dict) -> list[tuple[str, str]]:
        """Other VMware environments with VMs whose private network overlaps this one's: [(env id, cidr)]."""
        try:
            mine = ipaddress.ip_network(str(cfg.get("network_cidr")), strict=False)
        except ValueError:
            return []
        me, here = self._env_id(cfg), os.path.realpath(str(cfg.get("workdir") or ""))
        out = []
        for e in paths.Env.list_all():
            if e.cloud != self.key or e.id == me or os.path.realpath(str(e.dir)) == here:
                continue
            if not _state_vms(e.stack_dir / "terraform.tfstate"):
                continue   # never created, or destroyed without --purge: its saved config does not block anyone
            try:
                other = ipaddress.ip_network(str(e.load().get("network_cidr")), strict=False)
            except (ValueError, OSError):
                continue
            if mine.overlaps(other):
                out.append((e.id, str(other)))
        return out

    def _check_network(self, cfg: dict, creds: dict, net: dict | None) -> None:
        """Refuse a network that cannot work before anything is downloaded or created."""
        cidr = cfg["network_cidr"]
        neighbours = self.network_neighbours(cfg)
        if neighbours:
            names = ", ".join(f"{i} ({c})" for i, c in neighbours)
            first = neighbours[0][0].split("-", 1)[1]
            if not self.is_new(cfg):   # it has VMs (created before this check existed): keep its lifecycle working
                ui.warn(f"{self._env_id(cfg)} shares its private network {cidr} with {names}: both use the same fixed addresses "
                        "(bastion .2, nodes .20+), so their VMs take each other's IPs. Destroy one of them to fix it.")
            else:
                shared = net and not cfg.get("cidr_explicit")
                leftovers = _state_resources(Path(cfg["workdir"]) / "stack" / "terraform.tfstate") if cfg.get("workdir") else []
                raise ui.Abort(
                    f"{self._env_id(cfg)} would use the private network {cidr}, which {names} already uses"
                    + (f" (VMware's built-in host-only {net['name']}: every VMware environment without --cidr gets it)" if shared else "")
                    + ". Both would get the same fixed addresses (bastion .2, workloads .10+, nodes .20+), so their VMs would take "
                    f"each other's IPs.\n  Either destroy the other one first:  cloudseed destroy vmware --env {first}\n"
                    + (f"  or remove what a failed apply left of this one:  cloudseed destroy vmware --env {cfg.get('env')}\n"
                       if leftovers else "")
                    + "  or give this one its own network: run `sudo vmrest` (VMware only lets root create networks), export "
                    "VMREST_USER/VMREST_PASSWORD for it, and pass a free range, e.g. "
                    f"cloudseed setup vmware --env {cfg.get('env')} --cidr 10.123.0.0/24")
        if not cfg.get("cidr_explicit"):
            return
        try:
            want = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            raise ui.Abort(f"--cidr {cidr!r} is not a valid network (e.g. 10.123.0.0/24).") from None
        if not _is_rfc1918(want) and not self.is_new(cfg):   # (a new environment is refused by address_problems)
            self._warn_public_range(cfg, want)
        for n in localvm.list_vmnets(creds) or []:
            have = localvm.vmnet_cidr(n)
            if not have or not want.overlaps(ipaddress.ip_network(have)):
                continue
            if have == str(want) and n.get("type") == "hostOnly":
                continue   # exactly an existing host-only network: adopted
            kind = {"nat": "VMware's NAT network", "hostOnly": "a host-only network"}.get(str(n.get("type")), f"a {n.get('type')} network")
            msg = (f"--cidr {want} overlaps {n.get('name')} ({kind}, {have}). Adopting it would put the private VMs on that "
                   "network instead of behind the bastion" + (" - with direct internet access and a clash with its gateway "
                                                              "address" if n.get("type") == "nat" else ""))
            if not self.is_new(cfg):   # an older version already built it that way: keep it manageable (and destroyable)
                ui.warn(f"{self._env_id(cfg)}: {msg}. Destroy it and set it up again with another --cidr to fix it.")
                return
            raise ui.Abort(f"{msg}. Choose a range that overlaps no VMware network, or leave --cidr out.")

    # ---- Terraform state written by older versions ----
    def migrate_state(self, cfg: dict) -> bool:
        """Kubernetes node VMs used to be count-indexed (node[0], node[1], ...), so adding a control plane shifted every
        worker onto another index - and Terraform rebuilt them all. They are keyed by name now (node["cp1"],
        node["wk1"], ...). Re-key an existing state in place (keys taken from each VM's recorded name, so it is right
        for any number of control planes) so the switch changes no VM. True when the state was rewritten."""
        if not cfg.get("workdir"):
            return False
        stack = Path(cfg["workdir"]) / "stack"
        state_file = stack / "terraform.tfstate"
        if not state_file.exists() or (stack / ".terraform.tfstate.lock.info").exists():
            return False   # nothing to do, or Terraform is running right now
        try:
            text = state_file.read_text()
            data = json.loads(text)
        except (OSError, ValueError):
            return False
        node = mac = None
        for r in data.get("resources") or []:
            if r.get("mode") != "managed" or not str(r.get("module", "")).endswith("module.kubernetes[0]"):
                continue
            if (r.get("type"), r.get("name")) == ("vmdesktop_vm", "node"):
                node = r
            elif (r.get("type"), r.get("name")) == ("random_integer", "mac"):
                mac = r
        if not node or not any(isinstance(i.get("index_key"), int) for i in node.get("instances") or []):
            return False
        keymap: dict[int, str] = {}
        for inst in node["instances"]:
            m = re.search(r"-((?:cp|wk)\d+)$", str((inst.get("attributes") or {}).get("name", "")))
            if not isinstance(inst.get("index_key"), int) or not m:
                ui.warn("The Kubernetes node VMs in the Terraform state are not in the expected shape; leaving the state alone "
                        "(the next plan may want to rebuild them - review it before approving).")
                return False
            keymap[inst["index_key"]] = m.group(1)
        if len(set(keymap.values())) != len(keymap):
            return False
        for inst in node["instances"]:
            inst["index_key"] = keymap[inst["index_key"]]
        if mac:
            kept = []
            for inst in mac.get("instances") or []:
                ik = inst.get("index_key")
                if isinstance(ik, int) and ik // 3 in keymap:
                    inst["index_key"] = f"{keymap[ik // 3]}-{ik % 3}"
                    kept.append(inst)
                elif isinstance(ik, str):
                    kept.append(inst)
                # a MAC number of a node that is not in the state is dropped: it is recreated with that node
            mac["instances"] = kept
        for r in (node, mac):
            if r is not None and "each" in r:
                r["each"] = "map"
        data["serial"] = int(data.get("serial") or 0) + 1
        (stack / "terraform.tfstate.backup").write_text(text)
        tmp = state_file.with_name(f"terraform.tfstate.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, state_file)
        ui.info("Terraform state: the Kubernetes node VMs are now keyed by name (" + ", ".join(sorted(keymap.values())) +
                "); no VM changes.")
        return True

    def _refuse_bad_layout(self, cfg: dict) -> None:
        problems = self.address_problems(cfg)
        if problems:
            raise ui.Abort(f"This {self.key} configuration cannot work:\n  - " + "\n  - ".join(problems))

    # ---- local-only hook: called by the CLI before Terraform runs ----
    def prepare(self, cfg: dict, dry_run: bool = False) -> None:
        # a stale build is good enough to inspect or tear down, never to create or change VMs
        localvm.ensure_provider(stale_ok=dry_run)
        self.migrate_state(cfg)
        if cfg.get("vars", {}).get("vm_dir"):
            value = self.vm_dir_value(cfg)
            if not os.path.isabs(value):
                ui.warn(f"vm_dir {value!r} is relative (an older cloudseed kept it as typed), so this environment's VMs live in "
                        f"{self.vm_dir_path(cfg)}. They stay there; to move them, destroy the environment and set it up again "
                        "with an absolute --var vm_dir.")
            cfg["vars"]["vm_dir"] = value
        if dry_run:
            cfg["vars"].setdefault("base_disk", "/dev/null")
            if "guest_os_id" not in cfg["vars"]:   # (setdefault would evaluate guest_os_id eagerly)
                os_key = cfg["vars"].get("guest_os", localvm.DEFAULT_OS)
                if os_key not in localvm.IMAGES:   # a bad saved value must not block status/destroy; setup reports it
                    os_key = localvm.DEFAULT_OS
                cfg["vars"]["guest_os_id"] = localvm.guest_os_id(os_key, (localvm.detect_host() or {}).get("guest_arch", "amd64"))
            return
        new = self.is_new(cfg)
        if new:   # a new environment: refuse a layout that cannot work before creating anything
            self._refuse_bad_layout(cfg)
        else:     # before vmrest, downloads and the `mkdir` of vm_dir below
            self._refuse_missing_vm_dir(cfg)
        planned_cidr = cfg.get("network_cidr")
        host = localvm.require_host()
        ui.info(f"VMware {host['product']} {host['version']} on {host['os']}/{host['arch']} -> {host['guest_arch']} guests")
        too_old = localvm.version_problem(host)
        if too_old and new:
            raise ui.Abort(too_old)
        if too_old:   # its VMs exist: keep inspect/apply of what is there possible
            ui.warn(too_old)
        creds = localvm.ensure_vmrest(host)          # automatic: generates + configures credentials if needed
        os.environ.update(localvm.provider_env(creds))
        # Creating custom vmnets needs root on Fusion; use the built-in host-only network unless a CIDR was given explicitly.
        net = localvm.hostonly_vmnet(creds)
        if net and not cfg.get("cidr_explicit"):
            if cfg.get("network_cidr") != net["cidr"]:
                ui.info(f"Private network: using VMware's built-in host-only {net['name']} ({net['cidr']}); "
                        f"pass --cidr to insist on a dedicated vmnet (needs `sudo vmrest`, with VMREST_USER/VMREST_PASSWORD "
                        "exported for it).")
            cfg["network_cidr"] = net["cidr"]
        elif net and cfg.get("cidr_explicit") and cfg.get("network_cidr") != net["cidr"]:
            ui.warn(f"A dedicated vmnet for {cfg['network_cidr']} requires vmrest to run as root (`sudo vmrest`, then export "
                    f"VMREST_USER/VMREST_PASSWORD for it); if creation fails, re-run without --cidr to use {net['name']} ({net['cidr']}).")
        self._check_network(cfg, creds, net)
        if new and cfg.get("network_cidr") != planned_cidr:   # now on VMware's host-only network: check its size too
            self._refuse_bad_layout(cfg)
        # state lost, or an environment set up again under the same name over an old vm_dir: say so before the plan
        # (and before the base image download)
        self._report_strays(cfg, self.vm_dir_report(cfg), host)
        os_key = cfg["vars"].get("guest_os", localvm.DEFAULT_OS)
        if os_key not in localvm.IMAGES:
            raise ui.Abort(f"guest_os {os_key!r} is not available (choose one of: {', '.join(localvm.IMAGES)}); fix it with: "
                           f"cloudseed setup vmware --env {cfg.get('env', '<env>')} --var guest_os={localvm.DEFAULT_OS}")
        cfg["vars"]["guest_os_id"] = localvm.guest_os_id(os_key, host["guest_arch"])
        cfg["vars"]["base_disk"] = str(localvm.ensure_image(os_key, host["guest_arch"]))
        cfg["vars"]["vm_dir"] = self.vm_dir_value(cfg)
        os.makedirs(self.vm_dir_path(cfg), exist_ok=True)
