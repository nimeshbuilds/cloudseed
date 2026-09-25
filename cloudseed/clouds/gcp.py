from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
import unicodedata
from pathlib import Path

from .. import audit, creds, deps, netutil, paths, ui
from .base import Cloud, Question, as_bool, as_int

# GCP label keys and values: lower-case letters (international ones too), digits, '_' and '-' - Google's own pattern
# is [\p{Ll}\p{Lo}\p{N}_-]. A key must also start with a letter. At most 63 characters.
_LABEL_CATEGORIES = ("Ll", "Lo", "Nd", "Nl", "No")
_LABEL_MAX = 63


def _label_text(value) -> str:
    """What the user meant, before sanitising: NFC (so a decomposed accent is one character) and lower case."""
    return unicodedata.normalize("NFC", str(value)).lower()


def _label(value) -> str:
    v = "".join(ch if ch in "_-" or unicodedata.category(ch) in _LABEL_CATEGORIES else "-" for ch in _label_text(value))
    v = v[:_LABEL_MAX]
    while len(v.encode("utf-8")) > _LABEL_MAX:     # services that count bytes: an international label may need less
        v = v[:-1]
    return v


def _label_key(key) -> str:
    """GCP label keys must start with a lowercase letter, an international one too (values need not)."""
    k = _label(key)
    return k if k[:1] and unicodedata.category(k[0]) in ("Ll", "Lo") else _label("t-" + k)


def _ascii_label(value) -> str:
    """A label value as earlier versions rendered it: lower case, every character but a-z, 0-9, '_' and '-' a dash
    (international letters included). Kept for the owner label of environments those versions made (see GCP.tags)."""
    return re.sub(r"[^a-z0-9_-]", "-", str(value).lower())[:_LABEL_MAX]


def _node_label(text: str) -> str:
    """A GCP label as a Kubernetes node label (the GKE node pool's node_config.labels): ASCII letters, digits, '_',
    '.' and '-', starting and ending with a letter or digit. Mirrors local.node_labels in modules/kubernetes."""
    return re.sub(r"[^a-z0-9_.-]+", "-", text).strip("-_.")


# Cloud Storage refuses bucket names that start with "goog" or contain "google" (or a close misspelling); the state
# and Velero buckets are then named from a hash instead (terraform/gcp-bootstrap, terraform/gcp/modules/names).
_GOOGLE_LIKE = re.compile(r"g[o0]{2,}g[l1]e")


def google_like(prefix: str) -> bool:
    p = str(prefix).lower()
    return p.startswith("goog") or bool(_GOOGLE_LIKE.search(p))


# Regions whose zones start at -b: europe-west1 and us-east1 only have zones b, c and d.
_FIRST_ZONE = {"europe-west1": "b", "us-east1": "b"}
# ...so their "-a" zones do not exist (older versions defaulted to them; a saved one is replaced, a typed one refused)
_MISSING_ZONES = frozenset(f"{r}-a" for r in _FIRST_ZONE)


def default_zone(region: str) -> str:
    """First zone of a region (the bastion, VPN host and zonal GKE cluster go there)."""
    return f"{region}-{_FIRST_ZONE.get(region, 'a')}"


def zone_in_region(zone: str, region: str) -> bool:
    return bool(re.fullmatch(re.escape(str(region)) + r"-[a-z]", str(zone or "")))


def _default_ssh_username() -> str:
    name = netutil.local_username()           # already [a-z0-9_-], at most 32 characters
    if not re.match(r"[a-z_]", name):         # Linux user names cannot start with a digit or '-'
        name = ("u" + name)[:32]
    return "cloudseed" if name == "root" else name


_PROJECT_RE = re.compile(r"^(?:[a-z][a-z0-9.-]*[a-z0-9]:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
_ZONE_RE = re.compile(r"^[a-z]+-[a-z]+[0-9]+-[a-z]$")
# e2-micro, n2-standard-4, e2-custom-2-4096, custom-2-4096, n2-custom-4-8192-ext, a2-highgpu-1g: always lower case
_MACHINE_TYPE_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)+$")


def _check_project_id(value: str) -> str | None:
    if _PROJECT_RE.match(str(value).strip()):
        return None
    return (f"'{value}' is not a GCP project ID: 6-30 lowercase letters, digits or hyphens, starting with a letter "
            "and not ending with a hyphen (e.g. my-proj-123).")


def _check_ssh_username(value: str) -> str | None:
    if value == "root":
        return "root cannot log in over SSH (the bastion sets PermitRootLogin no); choose another user name."
    if _USER_RE.match(str(value)):
        return None
    return (f"'{value}' is not a valid Linux user name: at most 32 lowercase letters, digits, '_', '.' or '-', "
            "starting with a letter or '_'.")


def _check_zone(value: str) -> str | None:
    zone = str(value).strip()
    if zone in _MISSING_ZONES:
        region = zone[:-2]
        return f"zone {zone} does not exist ({region} only has zones b, c and d); use {default_zone(region)}."
    if _ZONE_RE.match(zone):
        return None
    return f"'{value}' is not a GCP zone (a zone looks like us-central1-a)."


def _check_machine_type(value: str) -> str | None:
    text = str(value).strip()
    if _MACHINE_TYPE_RE.match(text):
        return None
    # a self-link (zones/<zone>/machineTypes/<name>, or the full URL): the name is what cloudseed takes (the zone is
    # the environment's, and GKE node pools and the cost estimate only know names)
    name = text.rsplit("/", 1)[-1] if "/machineTypes/" in text else ""
    if name and _MACHINE_TYPE_RE.match(name.lower()):
        hint = f" (give the machine type's name, not its URL: {name.lower()})"
    elif _MACHINE_TYPE_RE.match(text.lower()):
        hint = f" (machine types are lower case: {text.lower()})"
    else:
        hint = ""
    return (f"'{value}' is not a Compute Engine machine type{hint}; e.g. e2-micro, e2-standard-2, n2-standard-4 or "
            "e2-custom-2-4096.")


def _check_vpn_type(value: str) -> str | None:
    if str(value).strip().lower() in ("openvpn", "tailscale"):
        return None                     # Question.choices turns Tailscale into tailscale
    return f"'{value}' is not a VPN type: use openvpn or tailscale."


def _whole(value) -> int:
    """A --var number that must be whole: a Terraform number (20 and 20.0 alike) or a saved digit string, negative
    ones included (the caller checks the range and says why)."""
    return as_int(value, minimum=-(2 ** 63))


def _below(value, minimum) -> bool:
    """Is `value` a whole number below `minimum` (a range error, not a format error)?"""
    try:
        return minimum is not None and _whole(value) < minimum
    except ValueError:
        return False


def _truthy(value) -> bool:
    """Lenient boolean for reading a setting that has been checked elsewhere (as_bool strictly; None, '' and anything
    unreadable are False here)."""
    try:
        return as_bool(value)
    except ValueError:
        return False


def _key_id(line) -> str:
    """'<type> <base64>' of an OpenSSH public key line, without its comment ('' when it is not one)."""
    parts = str(line or "").split()
    return f"{parts[0]} {parts[1]}" if len(parts) >= 2 else ""


# /28 ranges tried, in order, for the GKE control plane (the first one is the Terraform default)
_MASTER_CANDIDATES = ("172.16.0.0/28", "172.31.255.240/28", "192.168.255.240/28", "10.255.255.240/28")
_DEDICATED_FLAGS = ("project_id", "zone", "ssh_username")
# Ranges GCP refuses in any subnet (docs: VPC > Subnets > Prohibited IPv4 subnet ranges). Checked by overlap: the
# ipaddress is_* flags only fire when the whole network sits inside a range (0.0.0.0/8 and 169.254.0.0/15 slip through).
_GCP_PROHIBITED = (
    ("0.0.0.0/8", "'this' network"), ("127.0.0.0/8", "loopback"), ("169.254.0.0/16", "link-local"),
    ("224.0.0.0/4", "multicast"), ("255.255.255.255/32", "broadcast"),
    ("199.36.153.4/30", "restricted.googleapis.com"), ("199.36.153.8/30", "private.googleapis.com"),
)
_CLASS_E = ipaddress.ip_network("240.0.0.0/4")


class GCP(Cloud):
    key = "gcp"
    display = "Google Cloud"
    region_prompt = "GCP region"
    default_region = "us-central1"
    region_env = ("GOOGLE_REGION", "CLOUDSDK_COMPUTE_REGION")
    cli_tool = "gcloud"
    login_hint = "gcloud auth application-default login   (or: export GOOGLE_APPLICATION_CREDENTIALS=/path/key.json)"
    # regions whose region-derived defaults do not follow <region>-a (the web console asks for these explicitly)
    irregular_regions = tuple(_FIRST_ZONE)

    questions = [
        Question("project_id", "GCP project ID", "", required=True, validate=_check_project_id,
                 env=("GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT")),
        Question("zone", "Zone for the bastion, VPN host and GKE cluster", lambda cfg: default_zone(cfg["region"]),
                 env=("CLOUDSDK_COMPUTE_ZONE",), validate=_check_zone),
        Question("ssh_username", "Login username on the bastion", lambda cfg: _default_ssh_username(),
                 validate=_check_ssh_username),
        Question("enable_os_login", "Use OS Login (IAM-managed SSH) instead of metadata keys? Needs gcloud: cloudseed "
                 "registers the key with your Google account and grants it OS Admin Login on the bastion and VPN host",
                 False, kind="bool", advanced=True),
        Question("bastion_machine_type", "Bastion machine type", "e2-micro", advanced=True, validate=_check_machine_type),
        Question("enable_data_access_audit_logs", "Enable Data Access audit logs for all services (extra cost)",
                 False, kind="bool", advanced=True),
        Question("fips_mode", "FIPS 140 mode (Ubuntu Pro FIPS bastion/VPN, GKE on COS, FIPS-only SSH/TLS)?", False, kind="bool"),
        Question("enable_kubernetes", "Create a private managed Kubernetes cluster (GKE) in the private subnets?", False, kind="bool"),
        # the cluster's own settings follow enable_kubernetes (they are only asked when it is on)
        Question("kubernetes_node_size", "Kubernetes node size", "e2-standard-2", advanced=True, validate=_check_machine_type),
        Question("kubernetes_node_count", "Kubernetes node count", 2, kind="int", advanced=True, minimum=1),
        Question("kubernetes_public_endpoint", "Expose the Kubernetes API publicly (restricted to your IP)?", False, kind="bool", advanced=True),
        Question("enable_vpn", "Create a VPN host (OpenVPN or Tailscale) for private-network access?", False, kind="bool"),
        Question("vpn_type", "VPN type: openvpn (self-contained, client certs) or tailscale (subnet router, needs TS_AUTHKEY)",
                 "openvpn", choices=("openvpn", "tailscale"), validate=_check_vpn_type),
    ]

    outputs = [
        "kubernetes_master_cidr",   # routed through the VPN (provision.vpn_network_vars)
        "project_id", "region", "network_name", "network_self_link", "public_subnet_id", "private_subnet_id",
        "nat_name", "bastion_public_ip", "bastion_name", "bastion_instance_id", "bastion_service_account",
        "workload_network_tag", "ssh_user",
        "kubernetes_cluster_name", "kubernetes_endpoint", "vpn_public_ip", "vpn_instance_id", "vpn_type", "vpn_port",
        "kubernetes_location", "kubernetes_node_pool", "kubernetes_external_secrets_gsa", "kubernetes_external_dns_gsa",
        "kubernetes_velero_gsa", "kubernetes_velero_bucket", "fips_mode",
        "kubernetes_master_version",   # the bastion's kubectl follows it (provision.cluster_version)
    ]
    bootstrap_outputs = ["bucket"]

    # ---- prompts ----
    def collect_vars(self, args, existing: dict, cfg: dict, advanced: bool, *more, **kwargs) -> dict:
        # *more/**kwargs: whatever else the base signature takes (e.g. --var overrides) passes through unchanged
        overrides = kwargs.get("overrides", more[0] if more else None)
        overrides = overrides if isinstance(overrides, dict) else {}
        zone_given = bool(str(getattr(args, "zone", None) or "").strip() or str(overrides.get("zone") or "").strip())
        healed = self._heal_saved(existing or {}, cfg, zone_given=zone_given)
        return super().collect_vars(args, healed, cfg, advanced, *more, **kwargs)

    def _heal_saved(self, existing: dict, cfg: dict, zone_given: bool = False) -> dict:
        """Saved answers are only defaults: fix the zone an earlier version (or a changed --region) left unusable. With
        a zone from --zone / --var zone the saved zone is not used at all, so nothing is said about it. (Saved booleans
        and numbers are typed by cli._saved_answers, and Cloud._usable replaces an invalid one.)"""
        existing = dict(existing)
        if zone_given:
            return existing
        region = cfg.get("region") or self.default_region
        zone = existing.get("zone")
        if zone and zone in _MISSING_ZONES and zone_in_region(zone, region):
            # saved by an older version's default: setup failed at apply, so re-running it must pick a real zone
            ui.info(f"Zone {zone} does not exist; the zone becomes {default_zone(region)} (pass --zone to choose another).")
            existing["zone"] = default_zone(region)
        elif zone and not zone_in_region(zone, region):
            ui.info(f"Zone {zone} is not in region {region}; the zone becomes {default_zone(region)} (pass --zone to choose another).")
            existing["zone"] = default_zone(region)
        elif not zone:
            env_zone = os.environ.get("CLOUDSDK_COMPUTE_ZONE", "")
            if env_zone and (env_zone in _MISSING_ZONES or not zone_in_region(env_zone, region)):
                ui.info(f"Ignoring CLOUDSDK_COMPUTE_ZONE={env_zone}: it is not a zone of region {region}.")
                existing["zone"] = default_zone(region)
        return existing

    def check_vars(self, cfg: dict) -> None:
        """Normalize and validate the final answers (flags, --var and saved values alike) before anything is saved,
        so a dry run catches what GCP would only reject at apply time."""
        v = cfg["vars"]
        problems: list[str] = []
        # a number out of range for a feature that is off is reset to the default, not a blocker (a saved node count of
        # 0 while Kubernetes is off); a value that is no number at all is refused whatever it is for
        off = {} if _truthy(v.get("enable_kubernetes")) else \
            {q.key: "Kubernetes" for q in self.questions if q.key.startswith("kubernetes_")}
        for q in self.questions:
            if q.key not in v:
                continue
            flag = q.flag if q.key in _DEDICATED_FLAGS else f"--var {q.key}"
            value = v[q.key]
            if q.kind != "str" and (value is None or (isinstance(value, str) and not value.strip())):
                v[q.key] = q.coerce(q.stock_default(cfg))   # null or blank means the default (as Cloud.var_bool reads it)
                continue
            try:
                if q.kind == "str":
                    value = "" if value is None else str(value).strip()
                    problem = q.validate(value) if q.validate and value else None   # the question's own words first
                    if problem:
                        raise ValueError(problem)
                v[q.key] = q.coerce(value)   # strict bool / whole number in the question's range; a choice's spelling
            except ValueError as e:
                below = q.kind == "int" and _below(value, q.minimum)
                why = f"{self._BELOW_MINIMUM[q.key]}, got {value!r}" if below and q.key in self._BELOW_MINIMUM else str(e)
                if below and q.key in off:
                    default = q.stock_default(cfg)
                    ui.warn(f"{q.key}={value!r} is invalid ({why}); {off[q.key]} is off, so it is reset to the default "
                            f"{default!r}.")
                    v[q.key] = default
                else:
                    problems.append(f"{flag}: {why}")
        region = cfg.get("region", "")
        zone = v.get("zone", "")
        if zone and _ZONE_RE.match(zone) and not zone_in_region(zone, region):
            problems.append(f"--zone: {zone} is not in region {region}; use a zone of {region}, e.g. --zone {default_zone(region)}.")
        problems += self._network_problems(cfg)
        problems += self._extra_problems(cfg)
        # warnings only: saved tags cannot be removed, and the rest never blocks a re-run of an existing environment
        for w in self._label_warnings(cfg) + self._network_warnings(cfg) + self._baseline_warnings(cfg):
            ui.warn(w)
        for note in self._bucket_notes(cfg):
            ui.info(note)
        if problems:
            raise ui.Abort("Invalid Google Cloud settings:\n  - " + "\n  - ".join(problems))

    # what a whole number below a question's minimum means, in the words of the setting
    _BELOW_MINIMUM = {"kubernetes_node_count": "a node pool needs at least 1 node"}

    def _network_problems(self, cfg: dict) -> list[str]:
        problems: list[str] = []
        extra = cfg.get("extra_vars") or {}
        v6 = [c for c in cfg.get("allowed_ssh_cidrs") or [] if ":" in str(c)]
        if v6:
            problems.append(f"--allow-ip {', '.join(v6)}: IPv6 source ranges are not supported (the bastion and the "
                            "network have no IPv6 address); allow your IPv4 address instead.")
        try:
            newbits = _whole(extra.get("subnet_newbits", 4))
            if newbits < 1:
                raise ValueError(f"must be at least 1 (two subnets are carved from the network), got {newbits}")
        except ValueError as e:
            problems.append(f"--var subnet_newbits: {e}")
            newbits = 4
        net = self._network(cfg)
        if net is None:
            problems.append(f"--cidr: '{cfg.get('network_cidr')}' is not a network CIDR (e.g. 10.10.0.0/16).")
            return problems
        if net.version != 4:
            problems.append(f"--cidr: {net} is IPv6; GCP subnets need an IPv4 range.")
            return problems
        bad = [f"{p} ({why})" for p, why in _GCP_PROHIBITED if net.overlaps(ipaddress.ip_network(p))]
        if bad:
            what = "a reserved range" if len(bad) == 1 else "reserved ranges"
            problems.append(f"--cidr: {net} overlaps {', '.join(bad)}, {what} GCP does not allow in subnets; use a "
                            "private range such as 10.10.0.0/16.")
        if net.prefixlen + newbits > 29:
            problems.append(f"--cidr: {net} is too small: the public and private subnets are /{net.prefixlen + newbits} "
                            f"(subnet_newbits={newbits}) and GCP's smallest subnet is /29; use /{29 - newbits} or larger.")
        if _truthy(cfg["vars"].get("enable_kubernetes")) and extra.get("kubernetes_master_cidr"):
            raw = str(extra["kubernetes_master_cidr"]).strip()
            try:
                master = ipaddress.ip_network(raw, strict=True)
            except ValueError:
                master = None
            if master is None or master.version != 4 or master.prefixlen != 28:
                problems.append(f"--var kubernetes_master_cidr: '{raw}' is not an IPv4 /28 (e.g. 172.16.0.0/28).")
            elif master.overlaps(net):
                problems.append(f"--var kubernetes_master_cidr: {master} overlaps the network {net}; GKE needs a "
                                f"control-plane range outside it (e.g. {self._master_cidr(net)}).")
        return problems

    @staticmethod
    def _network(cfg: dict):
        try:
            return ipaddress.ip_network(str(cfg.get("network_cidr", "")).strip(), strict=True)
        except ValueError:
            return None

    def _network_warnings(self, cfg: dict) -> list[str]:
        net = self._network(cfg)
        if net is None or net.version != 4 or not net.overlaps(_CLASS_E):
            return []
        return [f"--cidr {net} is in 240.0.0.0/4 (Class E). GCP accepts it and the Linux bastion, VPN host and GKE nodes "
                "route it, but Windows, some VPN clients and many on-premises routers do not: VPN clients may not reach "
                "this network. A private range such as 10.10.0.0/16 avoids that."]

    # stack variables set with --var that GCP would only refuse at apply time (terraform/gcp/variables.tf has the same
    # rules as validation blocks, for saved configurations and `cloudseed apply`)
    _WHOLE_RANGES = {
        "log_retention_days": (1, 3650, "the _Default log bucket keeps logs for 1 to 3650 days"),
        "bastion_disk_size": (10, 65536, "the bastion's boot disk needs 10 to 65536 GB (the image alone needs 10)"),
        "vpn_port": (1, 65535, "a UDP port is 1 to 65535"),
        "kubernetes_node_min": (0, None, "a node count cannot be negative"),
        "kubernetes_node_max": (1, None, "the node pool must be allowed at least 1 node"),
    }

    def _extra_problems(self, cfg: dict) -> list[str]:
        extra = cfg.get("extra_vars") or {}
        problems: list[str] = []
        for key, (lo, hi, why) in self._WHOLE_RANGES.items():
            if extra.get(key) is None:
                continue
            try:
                n = _whole(extra[key])
            except ValueError as e:
                problems.append(f"--var {key}: {e}")
                continue
            if n < lo or (hi is not None and n > hi):
                problems.append(f"--var {key}: {why}, got {n}.")
        if "bastion_image" in extra and not str(extra["bastion_image"] or "").strip():
            problems.append("--var bastion_image: cannot be empty (e.g. debian-cloud/debian-12); forget the override "
                            "with --var bastion_image=null.")
        if extra.get("vpn_machine_type") is not None:
            problem = _check_machine_type(extra["vpn_machine_type"])
            if problem:
                problems.append(f"--var vpn_machine_type: {problem}")
        if "enable_project_baseline" in extra:
            try:
                as_bool(extra["enable_project_baseline"])
            except ValueError as e:
                problems.append(f"--var enable_project_baseline: {e}")
        return problems

    def _label_warnings(self, cfg: dict) -> list[str]:
        """One line per --tag that is not applied exactly as typed (as a GCP label, or as a GKE node label), and one
        per pair of tags that become the same label once sanitised (tags that differ only in case are folded into one
        by Cloud.tags, or refused by Cloud.tags_problems, before this)."""
        warnings: list[str] = []
        seen: dict[str, str] = {}
        kubernetes = _truthy((cfg.get("vars") or {}).get("enable_kubernetes"))
        # the user's spelling of each --tag (Cloud.tags writes --tag owner=x as Owner)
        user_tags = {str(k).strip().lower(): str(k) for k, v in (cfg.get("tags") or {}).items() if v not in (None, "")}
        for k, value in super().tags(cfg).items():
            key = _label_key(k)
            if key in seen:
                warnings.append(f"--tag {k}: becomes the label '{key}', the same as the tag '{seen[key]}'; the value of '{k}' wins.")
            seen.setdefault(key, k)
            typed = user_tags.get(str(k).strip().lower())
            if typed is None:
                continue   # the built-in labels are valid by construction
            k = typed
            parts = []
            if key != _label_text(k):
                parts.append(f"the key becomes '{key}' (GCP label keys: lowercase letters, digits, '_' and '-', starting "
                             "with a letter, at most 63 characters)")
            label = self._label_value(cfg, key, value)
            if label != _label(value):
                parts.append(f"the value becomes '{label}' (this environment comes from an earlier cloudseed, which wrote "
                             "international letters in the owner label as dashes; its resources are recognised by that "
                             "value, so it is kept)")
            elif label != _label_text(value):
                parts.append(f"the value becomes '{label}' (GCP label values: lowercase letters, digits, '_' and '-', at "
                             "most 63 characters)")
            if kubernetes:
                node_key, node_value = _node_label(key), _node_label(label)
                if not node_key:
                    parts.append("it is left off the GKE nodes (Kubernetes label keys are ASCII)")
                elif (node_key, node_value) != (key, label):
                    parts.append(f"on the GKE nodes it is {node_key}={node_value} (Kubernetes labels are ASCII and start "
                                 "and end with a letter or digit)")
            if parts:
                warnings.append(f"--tag {k}: " + "; ".join(parts) + ".")
        return warnings

    def _bucket_notes(self, cfg: dict) -> list[str]:
        prefix = f"{cfg.get('name', '')}-{cfg.get('env', '')}"
        if not google_like(prefix):
            return []
        return [f"Cloud Storage refuses bucket names that start with 'goog' or contain 'google', so this environment's "
                f"buckets (remote state, Velero backups) are named from a hash (cs-...) instead of '{prefix}-...'."]

    # ---- the project-wide logging settings (modules/security-baseline) ----
    @staticmethod
    def project_baseline(cfg: dict) -> bool:
        """Does this environment manage its project's logging settings (enable_project_baseline, default true)?"""
        value = (cfg.get("extra_vars") or {}).get("enable_project_baseline", True)
        try:
            return as_bool(True if value is None else value)
        except ValueError:
            return True

    def _baseline_warnings(self, cfg: dict) -> list[str]:
        v = cfg.get("vars") or {}
        if not self.project_baseline(cfg):
            out = []
            if v.get("enable_data_access_audit_logs") is True:
                out.append("enable_data_access_audit_logs=true has no effect with enable_project_baseline=false: this "
                           "environment leaves the project's audit and log-retention settings alone.")
            env = paths.Env(self.key, str(cfg.get("env") or ""))
            held = (audit.load(env).get("current") or {}).get("resources") or []
            if any(isinstance(r, dict) and r.get("type") == "google_project_iam_audit_config" for r in held):
                # count -> 0 is a delete (a removed block cannot cover a resource still in the configuration)
                out.append(f"{env.id} manages the Data Access audit config (allServices) of project "
                           f"{v.get('project_id') or '?'}: with enable_project_baseline=false the next apply deletes it, "
                           "which turns Data Access logs off for the whole project. To leave it on, first drop it from "
                           f"the state (nothing is deleted): cloudseed destroy {self.key} --env {env.name} --target "
                           "module.stack.module.security_baseline")
            return out
        project = str(v.get("project_id") or "")
        if not project:
            return []
        others = self._baseline_owners(project, exclude=f"{self.key}-{cfg.get('env')}")
        if not others:
            return []
        return [f"{', '.join(others)} already manage{'s' if len(others) == 1 else ''} the project-wide logging settings "
                f"of {project} (the _Default log bucket's retention and, with enable_data_access_audit_logs, the Data "
                "Access audit config). Environments that share a project overwrite each other's values there; let one "
                "of them manage them and pass --var enable_project_baseline=false to the others."]

    def _baseline_owners(self, project: str, exclude: str) -> list[str]:
        owners = []
        for env in paths.Env.list_all():
            if env.cloud != self.key or env.id == exclude:
                continue
            other, problem = env.try_load()
            if problem or str((other.get("vars") or {}).get("project_id") or "") != project:
                continue
            if self.project_baseline(other) and self._holds_resources(env):
                owners.append(env.id)
        return owners

    @staticmethod
    def _holds_resources(env) -> bool:
        """Best effort, from local files (like cli._env_has_resources): has the environment been applied and not
        destroyed since? A dry run or a plan manages nothing yet."""
        for h in reversed(audit.load(env).get("history") or []):
            if isinstance(h.get("resources"), int):
                return h["resources"] > 0
        try:
            state = json.loads((env.stack_dir / "terraform.tfstate").read_text() or "{}")
            if isinstance(state, dict) and state.get("resources"):
                return True
        except (OSError, ValueError):
            pass
        return (env.dir / "outputs.json").exists()

    # Project-wide settings the security baseline writes over whatever the project already had (the provider's audit
    # config replaces every allServices entry; the _Default bucket cannot be deleted, only re-configured). A destroy
    # forgets them instead of deleting them: deleting the audit config switches Data Access logs off for the whole
    # project, which other workloads (or a security team) may rely on.
    PROJECT_WIDE = {
        "google_project_iam_audit_config":
            "Data Access audit logs (allServices) stay on for project {project}: a project-wide setting other workloads "
            "may rely on. To turn them off, remove the allServices entry from auditConfigs: gcloud projects "
            "get-iam-policy {project} --format=json > policy.json, edit it, then gcloud projects set-iam-policy "
            "{project} policy.json",
        "google_logging_project_bucket_config":
            "The _Default log bucket of project {project} keeps the retention this environment set ({days} days); "
            "Google does not restore an earlier value. Change it with: gcloud logging buckets update _Default "
            "--location=global --retention-days=N --project {project}",
    }
    _ADDRESS = re.compile(r"^((?:module\.[\w-]+(?:\[[^\]]*\])?\.)*)([\w-]+)\.[\w-]+(?:\[[^\]]*\])?$")

    def keep_on_destroy(self, cfg: dict, resources: list[str]) -> list[tuple[str, str]]:
        """(state address, notice) of the project-wide logging settings in `resources` (terraform state list): a full
        destroy (or one targeting the security baseline) drops them from the state instead of deleting them."""
        project = (cfg.get("vars") or {}).get("project_id") or "?"
        days = (cfg.get("extra_vars") or {}).get("log_retention_days") or 90
        keep = []
        for address in resources:
            m = self._ADDRESS.match(address)
            if m and "module.security_baseline." in "." + m.group(1) and m.group(2) in self.PROJECT_WIDE:
                keep.append((address, self.PROJECT_WIDE[m.group(2)].format(project=project, days=days)))
        return keep

    @staticmethod
    def _master_cidr(net) -> str:
        for cand in _MASTER_CANDIDATES:
            if not ipaddress.ip_network(cand).overlaps(net):
                return cand
        return _MASTER_CANDIDATES[0]

    # ---- naming / access ----
    def tags(self, cfg):
        return {key: self._label_value(cfg, key, v) for key, v in
                ((_label_key(k), v) for k, v in super().tags(cfg).items())}

    @staticmethod
    def _label_value(cfg: dict, key: str, value) -> str:
        """The GCP label value of one tag. An environment made before CloudseedEnvId existed (no uid) is recognised by
        its CloudseedEnv and owner labels (reconcile.ownership), and those versions wrote international letters as
        dashes: its owner label keeps that form, so an --tag Owner=José environment still adopts its own objects."""
        if key == "owner" and not cfg.get("uid"):
            return _ascii_label(value)
        return _label(value)

    def ssh_user(self, cfg):
        v = cfg.get("vars") or {}
        os_login = cfg.get("os_login") or {}
        if _truthy(v.get("enable_os_login")) and os_login.get("user"):
            return os_login["user"]                        # OS Login POSIX name (user_example_com)
        return v.get("ssh_username") or _default_ssh_username()

    def value_problem(self, q, value, cfg):
        # the subnet is created in the region and the bastion/VPN/GKE in the zone: they must match
        if q.key == "zone" and value not in (None, ""):
            region = cfg.get("region") or ""
            if not re.fullmatch(re.escape(region) + r"-[a-z]", str(value)):
                return (f"'{value}' is not a zone of region {region} (zones look like {region}-a, {region}-b, "
                        f"{region}-c); pass --zone {region}-<letter>, or leave it out for the default")
        return super().value_problem(q, value, cfg)

    def required_providers(self):
        return {"google": {"source": "hashicorp/google", "version": ">= 6.0, < 8.0"},
                "random": {"source": "hashicorp/random", "version": "~> 3.6"}}

    def provider_block(self, cfg):
        return {"google": {"project": cfg["vars"]["project_id"], "region": cfg["region"],
                           "zone": cfg["vars"].get("zone") or default_zone(cfg["region"]), "default_labels": self.tags(cfg)}}

    def stack_vars(self, cfg):
        v = cfg["vars"]
        # saved answers, typed: a missing, null or blank one is the default, anything else is parsed strictly and aborts
        # with the fix (Cloud.var_bool / var_int). The node count's floor of 1 is enforced by setup (check_vars), not
        # here: a render must never lock status or destroy out of an environment.
        flag = lambda key: self.var_bool(cfg, key, False)   # noqa: E731
        text = lambda key, default: str(v.get(key) or "").strip() or default   # noqa: E731
        os_login = flag("enable_os_login")
        out = {
            "project_id": v["project_id"],
            "region": cfg["region"],
            "zone": v.get("zone") or default_zone(cfg["region"]),
            "name": cfg["name"],
            "environment": cfg["env"],
            "network_cidr": cfg["network_cidr"],
            "allowed_ssh_cidrs": cfg["allowed_ssh_cidrs"],
            "ssh_public_key": cfg["ssh_public_key"],
            "ssh_username": self.ssh_user(cfg),
            "enable_os_login": os_login,
            "os_login_member": (cfg.get("os_login") or {}).get("member", "") if os_login else "",
            "bastion_machine_type": text("bastion_machine_type", "e2-micro"),
            "enable_data_access_audit_logs": flag("enable_data_access_audit_logs"),
            "fips_mode": flag("fips_mode"),
            "platform_prereqs": list(cfg.get("platform_prereqs") or []),
            "enable_kubernetes": flag("enable_kubernetes"),
            "kubernetes_node_size": text("kubernetes_node_size", "e2-standard-2"),
            "kubernetes_node_count": self.var_int(cfg, "kubernetes_node_count", 2),
            "kubernetes_public_endpoint": flag("kubernetes_public_endpoint"),
            "enable_vpn": flag("enable_vpn"),
            "vpn_type": text("vpn_type", "openvpn").lower(),
            "labels": self.tags(cfg),
        }
        # GKE's control plane /28 must not overlap the network; the default does for 172.16.0.0/12-style networks
        try:
            master = self._master_cidr(ipaddress.ip_network(str(cfg["network_cidr"]), strict=False))
        except ValueError:
            master = _MASTER_CANDIDATES[0]
        if master != _MASTER_CANDIDATES[0]:
            out["kubernetes_master_cidr"] = master
        return out

    def bootstrap_vars(self, cfg):
        return {"project_id": cfg["vars"]["project_id"], "location": cfg["region"],
                "prefix": f"{cfg['name']}-{cfg['env']}", "labels": self.tags(cfg)}

    def backend_from_outputs(self, cfg, outputs):
        return {"gcs": {"bucket": outputs["bucket"], "prefix": f"{self.key}-{cfg['env']}"}}

    def credential_warnings(self, cfg):
        """Where the google provider and Terraform's GCS state backend find credentials, from local facts only (this
        runs for every cloud in the agent brief): key JSON or file, token, ADC file, or a Google runtime's metadata
        server. A key that is there but unusable (a paste cut short at '{', a file that is not a key) is named with
        the fix, because Google's loaders fail on it instead of falling back to other credentials."""
        warnings: list[str] = []
        blob = os.environ.get("GOOGLE_CREDENTIALS", "").strip()
        if blob:
            # read first by the google provider and by the GCS state backend: the key's JSON, or the path of a key file
            why = _credentials_problem(blob)
            if why:
                warnings.append(self._bad_key_warning("GOOGLE_CREDENTIALS", why))
        key_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if key_file and not (blob and _same_file(key_file, creds.GCP_FILE)):   # the vault's copy of that key: done
            # Google's credential loader opens this path exactly as given (no '~' expansion; a relative path resolves
            # in the stack directory Terraform runs in) and does not fall back to other credentials when it fails.
            # The fix depends on where the path comes from: a value stored with `cloudseed creds set` never replaces
            # one the shell exports (creds.apply), so a shell export is fixed in the shell.
            path = Path(key_file).expanduser().resolve()
            if _from_vault("GOOGLE_APPLICATION_CREDENTIALS"):
                set_path = "cloudseed creds set GOOGLE_APPLICATION_CREDENTIALS="
                other = ("or remove it (cloudseed creds unset GOOGLE_APPLICATION_CREDENTIALS) and paste the key "
                         "(cloudseed creds set GOOGLE_CREDENTIALS) or log in: gcloud auth application-default login")
            else:
                set_path = "export GOOGLE_APPLICATION_CREDENTIALS="
                other = ("or unset it in your shell and store the key (cloudseed creds set GOOGLE_CREDENTIALS) or log "
                         "in: gcloud auth application-default login")
            if not path.is_file():
                warnings.append(f"GOOGLE_APPLICATION_CREDENTIALS points to {key_file}, which does not exist. Fix the "
                                f"path ({set_path}/path/key.json) {other}")
            elif not Path(key_file).is_absolute():
                warnings.append(f"GOOGLE_APPLICATION_CREDENTIALS={key_file} is not an absolute path, so Terraform "
                                f"(which runs in the environment's stack directory) cannot open it. Use: {set_path}{path}")
            else:
                why = _key_file_problem(path)
                if why and _same_file(path, creds.GCP_FILE):
                    warnings.append(self._bad_key_warning("GOOGLE_CREDENTIALS", why, vault=True))
                elif why:
                    warnings.append(f"GOOGLE_APPLICATION_CREDENTIALS points to {key_file}, which is not a Google key "
                                    f"file ({why}). Point it at the JSON key file ({set_path}/path/key.json) {other}")
        if blob or key_file:
            return warnings
        # read by the provider and the GCS state backend alike
        if os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN", "").strip():
            return []
        if (Path.home() / ".config" / "gcloud" / "application_default_credentials.json").exists():
            return []
        if _google_runtime():
            return []     # GCE VM, Cloud Shell, GKE, Cloud Run/Build: the attached service account (metadata server)
        for name in ("GOOGLE_CLOUD_KEYFILE_JSON", "GCLOUD_KEYFILE_JSON"):
            if os.environ.get(name, "").strip():
                # (the vault's GOOGLE_CREDENTIALS takes the key's JSON only: a path is stored as the key file's path)
                return [f"{name} is read by the google provider but not by Terraform's GCS state backend, so remote "
                        f"state fails once the state bucket exists. Use GOOGLE_CREDENTIALS instead (export it with the "
                        f"same key file path or JSON), or store the key: cloudseed creds set "
                        f"GOOGLE_APPLICATION_CREDENTIALS=/path/key.json (or paste its JSON: cloudseed creds set "
                        f"GOOGLE_CREDENTIALS)"]
        return ["No Google credentials detected (no application-default login, GOOGLE_APPLICATION_CREDENTIALS, "
                f"GOOGLE_CREDENTIALS or GOOGLE_OAUTH_ACCESS_TOKEN). Log in first: {self.login_hint}"]

    @staticmethod
    def _bad_key_warning(name: str, why: str, vault: bool | None = None) -> str:
        if vault is None:
            vault = _from_vault(name)
        if vault:
            # a stored GOOGLE_CREDENTIALS is read before any key file path, so storing a path alone does not help
            return (f"The Google key stored in the vault ({name}) is not a whole key file ({why}), so Terraform cannot "
                    f"sign in with it. Paste the key file's contents again: cloudseed creds set {name} (or store the "
                    f"file's path instead: cloudseed creds unset {name}, then cloudseed creds set "
                    "GOOGLE_APPLICATION_CREDENTIALS=/path/key.json)")
        return (f"{name} (exported in your shell) is not a Google key ({why}); the google provider and the GCS state "
                "backend read it before any other credentials. Export the key file's JSON or its absolute path, or "
                f"unset it and store the key with: cloudseed creds set {name}")

    # ---- before Terraform: OS Login, and the project's own logging settings ----
    def prepare(self, cfg: dict, dry_run: bool = False) -> None:
        """With enable_os_login the bastion and VPN host ignore metadata keys: register the environment's key with the
        caller's Google account and record its POSIX user name (the SSH login) and IAM member (granted access by
        Terraform). A real run also warns when applying would lower the project's log retention."""
        if _truthy((cfg.get("vars") or {}).get("enable_os_login")):
            self._prepare_os_login(cfg, dry_run)
        else:
            cfg.pop("os_login", None)
        if not dry_run:
            self._check_project_logging(cfg)

    def _prepare_os_login(self, cfg: dict, dry_run: bool) -> None:
        gcloud = deps.find("gcloud")
        if not gcloud:
            msg = ("enable_os_login=true needs the gcloud CLI (to register the SSH key with your Google account): "
                   "cloudseed install gcloud, then gcloud auth login. Or turn it off: --var enable_os_login=false")
            if dry_run:
                ui.warn(msg)
                return
            raise ui.Abort(msg)
        if dry_run:
            ui.info("OS Login: at apply time cloudseed registers this environment's SSH key with your gcloud account "
                    "and grants that account OS Admin Login on the bastion and VPN host.")
            return
        project = cfg["vars"]["project_id"]
        account = self._gcloud(gcloud, ["config", "get-value", "account"], "read the active gcloud account").strip()
        if not account or account == "(unset)":
            raise ui.Abort("enable_os_login=true: gcloud has no active account. Run: gcloud auth login")
        key = _key_id(cfg.get("ssh_public_key"))
        describe = ["compute", "os-login", "describe-profile", "--project", project, "--format", "json"]
        raw = self._gcloud(gcloud, describe, f"read the OS Login profile of {account}")
        fingerprint = self._profile_keys(raw).get(key, "")
        present = bool(fingerprint)
        expires = self._profile_key_expiry(raw).get(key) if present else None
        if expires is not None and expires <= time.time() + self._RENEW_WITHIN:
            # expired (or about to, before setup and provisioning are done): as good as absent. Register it again the
            # way cloudseed registers a key - without an expiry - so cloudseed owns it from now on and removes it when
            # the environment no longer uses it (a later add would not reset the expiry of a key that is still there)
            ui.info(f"OS Login: the environment's key registered for {account} "
                    f"{'expired' if expires <= time.time() else 'expires'} {_when(expires)}; registering it again.")
            self._remove_os_login_key(gcloud, key, account, f"remove the expired OS Login key of {account}")
            present = False
        elif expires is not None:
            ui.warn(f"OS Login: the environment's key registered for {account} expires {_when(expires)} (it was "
                    "registered with an expiry, outside cloudseed); SSH to the bastion and VPN host stops working then. "
                    f"Re-running `cloudseed setup {self.key} --env {cfg.get('env')}` after that registers it again "
                    "without one.")
        if not present:
            with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as fh:
                fh.write(cfg["ssh_public_key"].strip() + "\n")
                key_file = fh.name
            try:
                self._gcloud(gcloud, ["compute", "os-login", "ssh-keys", "add", "--key-file", key_file, "--project", project],
                             f"register the SSH key with OS Login for {account}")
            finally:
                os.unlink(key_file)
            raw = self._gcloud(gcloud, describe, f"read the OS Login profile of {account}")
            fingerprint = self._profile_keys(raw).get(key, "")
        user = self._posix_user(raw, project)
        if not user:
            raise ui.Abort(f"OS Login: the profile of {account} has no POSIX account yet. Run "
                           f"`gcloud compute os-login describe-profile --project {project}` and re-run setup.")
        member = ("serviceAccount:" if account.endswith(".gserviceaccount.com") else "user:") + account
        # "added": cloudseed registered this key (it was not in the profile before, or an environment that registered
        # it still records it), so cloudseed may remove it again (release_os_login). A key that was already there -
        # e.g. the user's own ~/.ssh key passed with --ssh-public-key - is never removed.
        prev = cfg.get("os_login") or {}
        added = (not present) or (bool(prev.get("added")) and prev.get("account") == account and _key_id(prev.get("key")) == key) \
            or bool(self._os_login_users(account, key, exclude=f"{self.key}-{cfg.get('env')}", added_only=True))
        record = {"account": account, "user": user, "member": member, "key": key, "added": added}
        if fingerprint:
            record["fingerprint"] = fingerprint
        cfg["os_login"] = record
        ui.ok(f"OS Login: key {'registered' if not present else 'already registered'} for {account}; login user {user}")

    def release_os_login(self, old_cfg: dict, new_cfg: dict | None = None) -> bool:
        """Best effort: remove from the Google account the OS Login key `old_cfg` recorded, once nothing uses it any
        more. `new_cfg`: the configuration now in effect for the same environment (None after a full destroy).
        Call it after a successful setup that rotated the key or turned OS Login off (old = the previous config),
        after a setup that stopped before applying (old = this run's config, new = the restored one), and after a full
        destroy (old = the config; the record is then dropped from it on success, so a later apply registers again -
        the caller saves it). Only a key cloudseed added is removed, never while another gcp environment records the
        same key for the same account. Never raises: a failure is a warning with the manual command. True = removed."""
        rec = old_cfg.get("os_login") or {}
        key, account = _key_id(rec.get("key")), str(rec.get("account") or "")
        if not (rec.get("added") and key and account):
            return False
        if new_cfg is not None:
            now = new_cfg.get("os_login") or {}
            if _truthy((new_cfg.get("vars") or {}).get("enable_os_login")) and now.get("account") == account \
                    and _key_id(now.get("key")) == key:
                return False                   # this environment still logs in with it
        env_id = f"{self.key}-{old_cfg.get('env')}"
        others = self._os_login_users(account, key, exclude=env_id)
        if others:
            ui.info(f"OS Login: the key of {env_id} stays registered for {account}; {', '.join(others)} still use it.")
            return False
        manual = (f"gcloud compute os-login ssh-keys remove --key {rec.get('fingerprint') or '<fingerprint>'} "
                  f"--account {account}   (list them: gcloud compute os-login ssh-keys list --account {account})")
        gcloud = deps.find("gcloud")
        if not gcloud:
            ui.warn(f"OS Login: the SSH key of {env_id} is still registered for {account} (gcloud is not installed). "
                    f"Remove it with: {manual}")
            return False
        try:
            self._remove_os_login_key(gcloud, key, account, f"remove the SSH key of {env_id} from {account}")
        except ui.Abort as e:
            ui.warn(f"{e.msg}. It stays registered; remove it with: {manual}")
            return False
        ui.ok(f"OS Login: removed the SSH key of {env_id} from {account}")
        if new_cfg is None:
            old_cfg.pop("os_login", None)
        return True

    def _remove_os_login_key(self, gcloud: str, key: str, account: str, what: str) -> None:
        """gcloud compute os-login ssh-keys remove for one key ('<type> <base64>'); ui.Abort when gcloud fails."""
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as fh:
            fh.write(key + "\n")
            key_file = fh.name
        try:
            self._gcloud(gcloud, ["compute", "os-login", "ssh-keys", "remove", "--key-file", key_file, "--account", account],
                         what)
        finally:
            os.unlink(key_file)

    def _os_login_users(self, account: str, key: str, exclude: str, added_only: bool = False) -> list[str]:
        """Other gcp environments that log in through OS Login as `account` with the same key."""
        users = []
        for env in paths.Env.list_all():
            if env.cloud != self.key or env.id == exclude:
                continue
            other, problem = env.try_load()
            rec = (other.get("os_login") or {}) if not problem else {}
            if rec.get("account") == account and _key_id(rec.get("key") or other.get("ssh_public_key")) == key \
                    and _truthy((other.get("vars") or {}).get("enable_os_login")) and (rec.get("added") or not added_only):
                users.append(env.id)
        return users

    @staticmethod
    def _profile_keys(raw: str) -> dict:
        """{'<type> <base64>': fingerprint} of the SSH keys in an OS Login profile (describe-profile --format json)."""
        try:
            keys = (json.loads(raw or "{}") or {}).get("sshPublicKeys") or {}
        except (ValueError, AttributeError):
            return {}
        out = {}
        for fp, entry in (keys.items() if isinstance(keys, dict) else []):
            if isinstance(entry, dict) and _key_id(entry.get("key")):
                out[_key_id(entry["key"])] = str(entry.get("fingerprint") or fp)
        return out

    # a key that expires this soon is renewed like an expired one: setup and provisioning must not outlive it
    _RENEW_WITHIN = 3600

    @staticmethod
    def _profile_key_expiry(raw: str) -> dict:
        """{'<type> <base64>': expiry (seconds since the epoch)} of the OS Login profile's keys that expire
        (sshPublicKeys.*.expirationTimeUsec; a key without one never expires)."""
        try:
            keys = (json.loads(raw or "{}") or {}).get("sshPublicKeys") or {}
        except (ValueError, AttributeError):
            return {}
        out = {}
        for entry in (keys.values() if isinstance(keys, dict) else []):
            if not (isinstance(entry, dict) and _key_id(entry.get("key"))):
                continue
            try:
                usec = int(str(entry.get("expirationTimeUsec") or 0).strip())
            except ValueError:
                continue
            if usec > 0:
                out[_key_id(entry["key"])] = usec / 1_000_000
        return out

    def _check_project_logging(self, cfg: dict) -> None:
        """Best effort, warnings only (gcloud installed and logged in): the security baseline sets the project's _Default
        log retention and replaces its allServices audit config. Say so when that lowers a longer retention (Cloud Logging
        then deletes the older logs) or replaces an audit config someone else set."""
        v = cfg.get("vars") or {}
        project = v.get("project_id")
        if not project or not self.project_baseline(cfg):
            return
        gcloud = deps.find("gcloud")
        if not gcloud:
            return
        try:
            want = _whole((cfg.get("extra_vars") or {}).get("log_retention_days") or 90)
        except ValueError:
            return
        out = self._gcloud_try(gcloud, ["logging", "buckets", "describe", "_Default", "--location=global",
                                        f"--project={project}", "--format=value(retentionDays)"])
        if out and out.strip().isdigit() and int(out.strip()) > want:
            have = int(out.strip())
            ui.warn(f"Project {project} keeps its logs (the _Default log bucket) for {have} days; this environment sets "
                    f"{want}, and Cloud Logging then deletes the older logs. To keep them: --var log_retention_days={have}, "
                    "or leave the project's logging settings alone: --var enable_project_baseline=false")
        if not _truthy(v.get("enable_data_access_audit_logs")):
            return
        out = self._gcloud_try(gcloud, ["projects", "get-iam-policy", project, "--format=json"])
        try:
            configs = (json.loads(out or "{}") or {}).get("auditConfigs") or []
        except (ValueError, AttributeError):
            return
        mine = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
        for c in configs:
            if not isinstance(c, dict) or c.get("service") != "allServices":
                continue
            logs = [x for x in c.get("auditLogConfigs") or [] if isinstance(x, dict)]
            exempt = sorted({m for x in logs for m in x.get("exemptedMembers") or []})
            if exempt or {x.get("logType") for x in logs} != mine:
                detail = f" (exempted: {', '.join(exempt)})" if exempt else ""
                ui.warn(f"Project {project} already has a Data Access audit config for allServices{detail}; applying "
                        "replaces it with cloudseed's (ADMIN_READ, DATA_READ, DATA_WRITE, no exemptions). To leave it "
                        "as it is: --var enable_project_baseline=false")

    @staticmethod
    def _gcloud_try(gcloud: str, argv: list[str], timeout: int = 30) -> str | None:
        try:
            p = subprocess.run([gcloud, *argv, "--quiet"], capture_output=True, text=True, timeout=timeout,
                               env=deps.path_env(), stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return p.stdout if p.returncode == 0 else None

    @staticmethod
    def _gcloud(gcloud: str, argv: list[str], what: str) -> str:
        try:
            p = subprocess.run([gcloud, *argv, "--quiet"], capture_output=True, text=True, timeout=120, env=deps.path_env())
        except (OSError, subprocess.TimeoutExpired) as e:
            raise ui.Abort(f"OS Login: could not {what}: {e}")
        if p.returncode != 0:
            detail = (p.stderr or p.stdout).strip().splitlines()
            raise ui.Abort(f"OS Login: could not {what}: {detail[-1] if detail else 'gcloud exited ' + str(p.returncode)}")
        return p.stdout

    @staticmethod
    def _posix_user(raw: str, project: str) -> str:
        try:
            accounts = (json.loads(raw or "{}") or {}).get("posixAccounts") or []
        except ValueError:
            return ""
        accounts = [a for a in accounts if isinstance(a, dict) and a.get("username")]
        for pick in (lambda a: a.get("accountId") == project, lambda a: a.get("primary"), lambda a: True):
            for a in accounts:
                if pick(a):
                    return a["username"]
        return ""


def _when(epoch: float) -> str:
    """'on 2026-09-24 at 14:05 UTC' (or 'at an unreadable time' for a value out of range)."""
    try:
        return time.strftime("on %Y-%m-%d at %H:%M UTC", time.gmtime(epoch))
    except (OverflowError, OSError, ValueError):
        return "at an unreadable time"


_KEY_FILE_MAX = 1 << 20      # a Google key file is a few KB; anything this large is something else


def _key_json_problem(text: str) -> str | None:
    """Why `text` is not a Google credentials JSON (a service account key, an authorized_user or external_account
    file, ...), or None. What Google's loaders certainly refuse (and `cloudseed creds set GOOGLE_CREDENTIALS` too):
    text that is not a JSON object, and an object with fields but no "type"."""
    body = text.strip()
    if not body:
        return "it is empty"
    try:
        data = json.loads(body)
    except ValueError as e:
        if body.startswith("{") and not body.endswith("}"):
            return "the JSON is cut short: only the start of the key was pasted or saved"
        where = f" at line {e.lineno}, column {e.colno}" if isinstance(e, json.JSONDecodeError) else ""
        return f"it is not valid JSON{where}"
    if not isinstance(data, dict):
        return "it is not a JSON object"
    # an empty object {} is let through: nothing was cut short or mixed up, and Terraform's own error for it ("JSON
    # credentials are not valid: unknown credential type") already says what is wrong
    if data and not (isinstance(data.get("type"), str) and data["type"].strip()):
        return 'it has no "type" (service_account, authorized_user, external_account ...)'
    return None


def _key_file_problem(path: Path) -> str | None:
    """_key_json_problem for a file, which may also be unreadable, binary (a .p12 key) or far too large."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_KEY_FILE_MAX + 1)
    except OSError as e:
        return f"it cannot be read: {e.strerror or e}"
    if len(raw) > _KEY_FILE_MAX:
        return "it is far too large for a key file"
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "it is not a JSON text file (a .p12 key? create a JSON key instead)"
    return _key_json_problem(text)


def _credentials_problem(value: str) -> str | None:
    """GOOGLE_CREDENTIALS holds a key's JSON or the path of a key file (the provider and the GCS backend take both,
    '~' expanded; a relative path resolves in the stack directory Terraform runs in)."""
    if value.lstrip().startswith("{"):
        return _key_json_problem(value)
    path = Path(value).expanduser()
    if not path.is_absolute():
        return "it is neither the key's JSON nor an absolute path to a key file"
    if not path.is_file():
        return f"the key file {value} does not exist"
    return _key_file_problem(path)


def _from_vault(name: str) -> bool:
    """Did the vault put `name` into the environment (creds.apply / refresh) rather than the user's shell? A value
    stored with `cloudseed creds set` never replaces one the shell exports, so the fix differs."""
    value = creds.APPLIED.get(name)
    return bool(value) and value == os.environ.get(name)


def _same_file(a, b) -> bool:
    try:
        return Path(a).expanduser().resolve() == Path(b).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def _google_runtime() -> bool:
    """Running where Google's metadata server hands out the attached service account's token (GCE VM, Cloud Shell,
    GKE, Cloud Run / Functions / Build): the provider and the GCS backend authenticate there without any file.
    Local facts only (no network probe): the metadata host override, the runtimes' own variables, the VM's DMI."""
    if any(os.environ.get(n) for n in ("GCE_METADATA_HOST", "GCE_METADATA_IP", "K_SERVICE", "CLOUD_RUN_JOB",
                                       "FUNCTION_TARGET")) or os.environ.get("CLOUD_SHELL") == "true":
        return True
    try:
        return "Google" in Path("/sys/class/dmi/id/product_name").read_text(errors="replace")
    except OSError:
        return False
