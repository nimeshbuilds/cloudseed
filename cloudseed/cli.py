"""cloudseed command line."""

from __future__ import annotations

import argparse
import contextlib
import copy
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import __version__, agents, audit, chaos, clouds, container, creds, deps, dr, explain, finops, headliner, help as helpmod, managed, mcp, netutil, paths, platform as platformmod, provision as prov, scan, secrets, services, skills, troubleshoot, ui, undo, webui
from .clouds.base import as_bool
from .tf import Terraform, TerraformError

CLOUD_KEYS = ("aws", "gcp", "azure", "vmware")
TF_COMMANDS = {"setup", "plan", "apply", "destroy", "status", "output", "update-ip", "provision", "k8s", "vpn", "troubleshoot",
               "inventory", "node", "platform", "kubectl", "helm", "k9s", "finops", "chaos", "dr", "scan", "undo"}
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,23}$")


# ---------------------------------------------------------------- helpers

def _validate_name(value: str) -> str | None:
    if not NAME_RE.match(str(value or "")):
        return "Use 2-24 lowercase letters, digits or hyphens, starting with a letter."
    return None


def _parse_kv(items: list[str] | None) -> dict:
    out: dict = {}
    for item in items or []:
        if "=" not in item:
            raise ui.Abort(f"Expected key=value, got '{item}'")
        k, _, v = item.partition("=")
        out[k.strip()] = v
    return out


def _env_default(names: tuple[str, ...]) -> str:
    for n in names:
        if os.environ.get(n):
            return os.environ[n]
    return ""


def _fmt(value):
    """A setting shown the way it is written on the command line: true/false/null, JSON for lists and maps."""
    if value is None or isinstance(value, (bool, list, dict)):
        return json.dumps(value)
    return value


# ---------------------------------------------------------------- typed --var values

def _parse_bool(value) -> bool:
    """Strict boolean for user input. bool("False") and bool("no") are True in Python and would silently switch
    features on, so only true/false, yes/no, y/n, on/off and 1/0 (any case) are accepted (clouds.base.as_bool)."""
    return as_bool(value)


def _lenient_bool(value, default: bool = True) -> bool:
    try:
        return _parse_bool(value)
    except ValueError:
        return default


def _coerce_answer(q, value):
    """A prompted setting's value as its kind (bool / int / str), checked by the question's validator
    (clouds.Question.coerce), also accepting a JSON-quoted string. ValueError(explanation) when it is not valid."""
    if q.kind in ("bool", "int"):
        return q.coerce(value)
    text = "" if value is None else str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':      # --var 'key="value"' (a JSON string)
        try:
            decoded = json.loads(text)
        except ValueError:
            decoded = None
        if isinstance(decoded, str):
            text = decoded.strip()
    return q.coerce(text)


def _variable_types(cloud_key: str) -> dict:
    """Declared Terraform type of every variable of a target's stack: 'string', 'number', 'bool', 'list(string)' ..."""
    try:
        text = (paths.tf_root() / cloud_key / "variables.tf").read_text()
    except OSError:
        return {}
    out = {}
    for m in re.finditer(r'variable\s+"([^"]+)"\s*\{(.*?)\n\}', text, re.S):
        t = re.search(r"^\s*type\s*=\s*(.+?)\s*$", m.group(2), re.M)
        out[m.group(1)] = re.sub(r"\s+", "", t.group(1)) if t else "any"
    return out


def _typed_var(key: str, raw: str, ty: str | None):
    """A --var value for a stack variable, read by its declared Terraform type. JSON is decoded for numbers, bools
    and collections only: a string variable keeps the text as typed (kubernetes_version=1.30 must stay "1.30", not
    become the number 1.3)."""
    text = raw.strip()
    base = (ty or "").split("(")[0]
    if base == "string":
        if len(text) >= 2 and text[0] == text[-1] == '"':
            try:
                decoded = json.loads(text)
                if isinstance(decoded, str):
                    return decoded
            except ValueError:
                pass
        return raw
    if base == "bool":
        try:
            return _parse_bool(text)
        except ValueError as e:
            raise ui.Abort(f"--var {key}: {e}")
    if base == "number":
        try:
            value = json.loads(text)
        except ValueError:
            value = None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ui.Abort(f"--var {key}: expected a number, got {raw!r}")
        return value
    example = '{"key":"value"}' if base in ("map", "object") else '["a","b"]'
    bad = ui.Abort(f"--var {key}: expected a JSON {ty} value (e.g. {key}='{example}'), got {raw!r}")
    inner = (ty or "")[len(base) + 1:-1] if (ty or "").startswith(base + "(") else ""
    try:
        value = json.loads(text)
    except ValueError:
        if base in ("list", "set") and inner == "string":
            return [p.strip() for p in text.split(",") if p.strip()]
        if base in ("", "any"):          # not a declared variable (refused just after) or an untyped one
            return raw
        raise bad from None
    # the decoded value must have the declared shape: a wrong one would be saved and fail every later plan
    if base in ("list", "set"):
        if not isinstance(value, list):
            if inner == "string" and value is not None and not isinstance(value, dict):   # "acme/" or 5: as unquoted
                text = value if isinstance(value, str) else json.dumps(value)
                return [p.strip() for p in text.split(",") if p.strip()]
            raise bad
        if any(not _primitive_fits(x, inner) for x in value):
            raise bad
        # Terraform turns numbers and bools into strings for a list(string) itself; save them the way it uses them
        return [x if isinstance(x, str) else json.dumps(x) for x in value] if inner == "string" else value
    if base in ("map", "object"):
        if not isinstance(value, dict) or (base == "map" and any(not _primitive_fits(x, inner) for x in value.values())):
            raise bad
    return value


def _primitive_fits(value, ty: str) -> bool:
    """Does one element of a list/set/map --var fit its declared element type? string also takes numbers and bools
    (Terraform converts them); nested collections, null and anything more complex are only checked for primitives."""
    if ty == "string":
        return isinstance(value, (str, int, float))          # bool is an int
    if ty == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if ty == "bool":
        return isinstance(value, bool)
    return True


# Stack variables cloudseed sets itself, and what sets each one. A --var for them would make the deployment silently
# diverge from what cloudseed shows, saves and hands to Ansible (NAT rules, VPN routes, host firewall) and turn
# `update-ip` into a no-op, so setup refuses it and names the flag. (Overrides saved by older versions are migrated.)
MANAGED_VARS = {
    "name": "--name",
    "environment": "--env",
    "region": "--region",
    "location": "--region",
    "ssh_public_key": "--ssh-public-key",
    "tags": "--tag KEY=VALUE",
    "labels": "--tag KEY=VALUE",
    "platform_prereqs": "`cloudseed platform install <item>` (it applies the item's cloud prerequisites)",
    "base_disk": "--var guest_os=... (cloudseed resolves the base image)",
    "guest_os_id": "--var guest_os=... (cloudseed resolves the VMware guest OS id)",
    "vpc_cidr": "--cidr",
    "network_cidr": "--cidr",
    "private_cidr": "--cidr",
    "allowed_ssh_cidrs": "--allow-ip (or `cloudseed update-ip`)",
    "os_login_member": "--var enable_os_login=true (setup then registers your gcloud account as the OS Login member)",
}
CIDR_VARS = {"aws": "vpc_cidr", "gcp": "network_cidr", "azure": "network_cidr", "vmware": "private_cidr"}
ALLOW_VAR = "allowed_ssh_cidrs"


def _managed_vars(cloud: clouds.Cloud, declared) -> dict:
    """Declared stack variables cloudseed sets itself -> what sets them: the explanations above, plus any other
    variable the adapter's stack_vars computes (clouds.Cloud.managed_vars)."""
    qkeys = {q.key for q in cloud.questions}
    derived = {k: how for k, how in cloud.managed_vars().items() if k in declared}
    return {**derived, **{k: how for k, how in MANAGED_VARS.items() if k in declared and k not in qkeys}}


def _parse_setup_vars(cloud: clouds.Cloud, items: list[str] | None) -> dict:
    """Split and type a setup run's --var items, before anything is asked or written:
      answers  {question: value}   prompted settings, checked like a typed answer and not prompted for again
      extra    {variable: value}   other stack variables, typed by their Terraform declaration
      unset    [key]               KEY=null: forget a saved override or answer (back to the default)"""
    qmap = {q.key: q for q in cloud.questions}
    types = _variable_types(cloud.key)
    managed = _managed_vars(cloud, types)
    out: dict = {"answers": {}, "extra": {}, "unset": []}
    for key, raw in _parse_kv(items).items():
        if not key:
            raise ui.Abort(f"--var needs a variable name before '=', got '={raw}'")
        if raw.strip() == "null":
            out["unset"].append(key)
        elif key in qmap:
            try:
                out["answers"][key] = _coerce_answer(qmap[key], raw)
            except ValueError as e:
                raise ui.Abort(f"--var {key}={raw}: {e}")
        elif key in managed:
            how = managed[key]
            # clouds.base names no flag for a variable its stack_vars computes: say so instead of pointing nowhere
            tail = f"use {how} instead" if how != "the matching setup flag" else \
                f"it cannot be overridden (see: cloudseed help variables {cloud.key})"
            raise ui.Abort(f"--var {key}: this variable is set by cloudseed itself (the summary, update-ip, "
                           f"provisioning and the state storage use cloudseed's value); {tail}.")
        else:
            out["extra"][key] = _typed_var(key, raw, types.get(key))
    _check_extra_vars(cloud, out["extra"])       # a typo is refused now, not after every prompt was answered
    return out


def _saved_extra_vars(cloud: clouds.Cloud, existing: dict, replaced=()) -> tuple[dict, dict]:
    """The saved --var overrides, minus those older versions accepted for settings cloudseed manages. The network CIDR
    and the SSH allow-list come back separately (setup moves them into the configuration, keeping what is deployed);
    tag overrides are dropped (they replaced cloudseed's ManagedBy/CloudseedEnv tags); a saved override of a prompted
    setting becomes that setting's saved answer. `replaced`: keys this run sets again or unsets (no warnings for them)."""
    extra = {k: v for k, v in (existing.get("extra_vars") or {}).items() if k not in replaced}
    legacy: dict = {"answers": {}}
    qkeys = {q.key for q in cloud.questions}
    types = _variable_types(cloud.key)
    managed = _managed_vars(cloud, types)
    for key in list(extra):
        base, value = types.get(key, "").split("(")[0], extra[key]
        if base == "bool" and isinstance(value, str):          # older versions saved "False" / "no" as text
            try:
                extra[key] = _parse_bool(value)
            except ValueError:
                pass
        elif base == "string" and isinstance(value, (int, float)) and not isinstance(value, bool):
            ui.warn(f"The saved --var {key} is the number {value} (older versions read text such as 1.30 as a number); "
                    f"if you meant something else, set it again: --var {key}=<value>.")
            extra[key] = str(value)
        if key == CIDR_VARS.get(cloud.key):
            legacy["cidr"] = extra.pop(key)
        elif key == ALLOW_VAR and key in types:
            legacy["allow"] = extra.pop(key)
        elif key in qkeys:
            legacy["answers"][key] = extra.pop(key)
        elif key in ("tags", "labels"):
            extra.pop(key)
            ui.warn(f"Dropping the saved --var {key} override: it replaced cloudseed's ManagedBy/CloudseedEnv tags. "
                    "Add your own tags with --tag KEY=VALUE.")
        elif key in managed:
            ui.warn(f"The saved --var {key} override ({json.dumps(extra[key])}) still replaces cloudseed's own {key} "
                    f"(new overrides are refused: use {managed[key]}). Drop it with --var {key}=null.")
    return extra, legacy


# ---------------------------------------------------------------- network and SSH allow-list

def _split_cidrs(value) -> list[str]:
    items = value if isinstance(value, (list, tuple)) else [value]
    return [p.strip() for item in items for p in str(item).split(",") if p.strip()]


def _allow_list_problem(value) -> str | None:
    """Problem with an SSH allow-list for a cloud bastion (comma-separated text or a list), or None: IPv4 only, no
    host bits (203.0.113.7/24 is refused at every prefix), no range wider than a /8, and at most two /8s' worth of
    addresses in total (0.0.0.0/1 + 128.0.0.0/1 is refused; two /8s, adjacent or not, are fine). See
    netutil.validate_cidr_list."""
    return netutil.validate_cidr_list(_split_cidrs(value))


def _canonical_cidrs(value) -> list[str]:
    """Normalized allow-list: duplicates and overlapping or adjacent ranges merged (the host firewall's nftables
    interval set refuses overlapping elements), sorted, IPv4 first (as update-ip saves it)."""
    return netutil.normalize_cidr_list(_split_cidrs(value))


def _ip_allowed(ip: str, cidrs) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(str(c), strict=False) for c in cidrs)
    except ValueError:
        return False


def _cidr_problem(value) -> str | None:
    """Problem with a network (VPC / VNet / vmnet) CIDR as typed, or None."""
    problem = netutil.validate_cidr(str(value))
    if problem:
        return problem
    net = ipaddress.ip_network(str(value).strip())
    if net.version != 4:
        return f"'{value}' is IPv6; cloudseed networks are IPv4 (e.g. 10.0.0.0/16)."
    if net.prefixlen < 8:
        return f"'{value}' is far too large for one network; use a private range such as 10.0.0.0/16."
    for block, what in _UNUSABLE_NETS:
        if net.overlaps(ipaddress.ip_network(block)):
            return (f"'{value}' overlaps {block} ({what}), which no cloud or VM network can use; use a private range "
                    "such as 10.0.0.0/16.")
    return None


# Address blocks no VPC, VNet or vmnet can be carved from (RFC 6890 special-purpose ranges). Public ranges stay allowed
# here: cloud VPCs may use non-RFC1918 space (100.64.0.0/10 ...); the vmware target's own rule is stricter.
_UNUSABLE_NETS = (("0.0.0.0/8", "'this network'"), ("127.0.0.0/8", "loopback"), ("169.254.0.0/16", "link-local"),
                  ("224.0.0.0/4", "multicast"), ("240.0.0.0/4", "reserved"))


MIN_SUBNET_PREFIX = {"aws": 28, "gcp": 29, "azure": 29}     # smallest subnet each cloud accepts
DEFAULT_NEWBITS = {"aws": 4, "gcp": 4, "azure": 8}          # terraform/<cloud>/variables.tf subnet_newbits
AKS_RANGES = ("10.244.0.0/16", "10.250.0.0/16")             # AKS pod / service CIDRs (terraform/azure/modules/kubernetes)
GKE_MASTER_CIDR = "172.16.0.0/28"                           # terraform/gcp/variables.tf kubernetes_master_cidr


def _own_network_rules(cloud: clouds.Cloud) -> bool:
    """Does the adapter check the network itself (VMware's address plan, AWS's pinned subnet layout)? Its rule is then
    the only one: it mirrors the Terraform module exactly, where the generic sizing below would only approximate it."""
    return type(cloud).network_problems is not clouds.Cloud.network_problems


def _network_problems(cloud: clouds.Cloud, cfg: dict) -> list[str]:
    """What keeps the network CIDR from working with this configuration. Checked before anything is saved or created:
    Terraform only evaluates cidrsubnet()/cidrhost() at plan time, so a dry run cannot catch these. An adapter with its
    own rules (VMware's fixed address plan: bastion .2, workloads .10+, nodes .20+/.40+, nothing in VMware's DHCP pool;
    AWS's VPC size and subnet layout) answers alone, kept in one place with the Terraform module it mirrors."""
    if cloud.local or _own_network_rules(cloud):
        return list(cloud.network_problems(cfg))
    try:
        net = ipaddress.ip_network(str(cfg["network_cidr"]))
    except ValueError:
        return [f"'{cfg['network_cidr']}' is not a valid network CIDR; pass --cidr."]
    extra = cfg.get("extra_vars") or {}
    problems: list[str] = []
    try:
        newbits = int(extra.get("subnet_newbits", DEFAULT_NEWBITS.get(cloud.key, 4)))
    except (TypeError, ValueError):
        return [f"subnet_newbits={extra.get('subnet_newbits')!r} is not a number."]
    needed, why = 2, "a public and a private subnet"
    if 2 ** newbits < needed:
        problems.append(f"subnet_newbits={newbits} leaves room for {2 ** newbits} subnets, but {needed} are needed ({why}).")
    limit = MIN_SUBNET_PREFIX.get(cloud.key)
    if limit and net.prefixlen + newbits > limit:
        problems.append(f"{net} is too small: its subnets would be /{net.prefixlen + newbits} (subnet_newbits={newbits}), "
                        f"but {cloud.display} subnets must be /{limit} or larger. Use a /{max(limit - newbits, 8)} or larger "
                        "network (--cidr), or a smaller --var subnet_newbits.")
    if _flag_setting(cfg, "enable_kubernetes", False):   # strictly: a saved "false" is not a cluster
        # GKE's control-plane /28 only when set with --var: otherwise the GCP adapter renders one outside the network
        # (GCP.stack_vars moves off the default GKE_MASTER_CIDR when it overlaps)
        reserved = AKS_RANGES if cloud.key == "azure" else \
            ((str(extra["kubernetes_master_cidr"]),) if cloud.key == "gcp" and extra.get("kubernetes_master_cidr") else ())
        for r in reserved:
            try:
                if net.overlaps(ipaddress.ip_network(r, strict=False)):
                    problems.append(f"{net} overlaps {r}, which the {cloud.display} Kubernetes cluster reserves; "
                                    "choose another --cidr.")
            except ValueError:
                pass
    return problems


# Every AWS region with FIPS 140 endpoints for all services the stack uses (EC2, S3, KMS, CloudTrail, EKS ...).
AWS_FIPS_REGIONS = ("us-east-1", "us-east-2", "us-west-1", "us-west-2", "us-gov-east-1", "us-gov-west-1")
REGION_RE = {"aws": r"(?:[a-z]{2}(?:-gov|-iso[a-z]*)?|eusc-[a-z]{2})-[a-z]+-\d+", "gcp": r"[a-z]+-[a-z]+\d+",
             "azure": r"[a-z][a-z0-9]+"}
# AWS partitions (region prefix) whose ARNs and service principals terraform/aws does not build yet
AWS_UNSUPPORTED_PARTITIONS = {"eusc-": "the AWS European Sovereign Cloud (partition aws-eusc)"}
REGION_EXAMPLE = {"aws": "us-east-1", "gcp": "us-central1", "azure": "eastus"}


def _normalize_region(cloud: clouds.Cloud, value) -> str:
    text = str(value or "").strip()
    if cloud.key == "azure":        # azurerm also accepts display names: "East US" is eastus
        text = re.sub(r"\s+", "", text).lower()
    return text


def _region_problem(cloud: clouds.Cloud, value) -> str | None:
    rx = REGION_RE.get(cloud.key)
    region = _normalize_region(cloud, value)
    if rx and not re.fullmatch(rx, region):
        what = f"{cloud.display} {cloud.region_prompt.split()[-1].lower()}"
        article = "an" if what[:1].lower() in "aeiou" else "a"
        return f"'{value}' is not {article} {what} name (e.g. {REGION_EXAMPLE[cloud.key]})."
    if cloud.key == "aws":
        for prefix, where in AWS_UNSUPPORTED_PARTITIONS.items():
            if region.startswith(prefix):
                return (f"'{value}' is in {where}, which cloudseed's AWS stack does not support yet; pick a region of "
                        f"the commercial or GovCloud partition (e.g. {REGION_EXAMPLE['aws']}).")
    # the adapter's own list of real regions/locations, when it has one (e.g. Azure locations): the format alone lets
    # `--region mars` through to the first apply
    check = getattr(cloud, "region_problem", None)
    return check(region) if callable(check) else None


def _setup_region_problem(cloud: clouds.Cloud, value) -> str | None:
    """_region_problem, plus the regions setup cannot deploy to although they are real: AWS China and the isolated
    partitions (the adapter's rule, AWS.check_vars), refused at the region prompt and for --region instead of only after
    every other question was answered."""
    problem = _region_problem(cloud, value)
    if problem or cloud.key != "aws":
        return problem
    from .clouds import aws as awsmod
    region = _normalize_region(cloud, value)
    if awsmod._UNSUPPORTED_REGION.fullmatch(region):
        return (f"Region {region} is not supported: cloudseed's AWS stack is built for the commercial regions and "
                "GovCloud (us-gov-east-1, us-gov-west-1); AWS China and the isolated regions differ in service "
                f"principals, endpoints and images. Pick another region (e.g. {REGION_EXAMPLE['aws']}).")
    return None


def _config_problems(cloud: clouds.Cloud, cfg: dict) -> list[str]:
    """Everything that would only fail at plan or apply time: the adapter's checks (answers incl. GCP zone vs region
    and login names, tags, its network rules), network sizing for targets whose adapter reports nothing, AWS name
    lengths."""
    problems = cloud.check_config(cfg)          # includes the adapter's network_problems
    if not cloud.local and not _own_network_rules(cloud):
        problems += _network_problems(cloud, cfg)
    if cloud.key == "aws" and not any("too long a name prefix" in p for p in problems):
        prefix = f"{cfg['name']}-{cfg['env']}"
        if _flag_setting(cfg, "enable_kubernetes", False):
            limit, why = 33, "EKS add-on resources such as the '<prefix>-eks-karpenter-scheduled-change' rule (64 characters)"
        elif _aws_log_bucket(cfg):
            limit, why = 39, "the baseline's log bucket '<prefix>-cloudtrail-<account id>' (63 characters)"
        else:
            limit, why = 46, "the state bucket '<prefix>-tfstate-<random>' (63 characters)"
        if len(prefix) > limit:
            problems.append(f"'{prefix}' ({len(prefix)} characters) is too long a name prefix on AWS: at most {limit} "
                            f"with these settings, because of {why}. Shorten --name or --env.")
    return list(dict.fromkeys(problems))


def _flag_setting(cfg: dict, key: str, default: bool) -> bool:
    """A boolean setting read strictly (bool("no") is True in Python): a --var override from extra_vars (it wins when
    the stack is rendered: Cloud.module_vars), else a prompted answer from vars; missing, blank or unreadable means the
    default (an invalid value is reported by the answer and Terraform variable checks, not here)."""
    for src in ("extra_vars", "vars"):
        value = (cfg.get(src) or {}).get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        try:
            return _parse_bool(value)
        except ValueError:
            return default
    return default


def _aws_log_bucket(cfg: dict) -> bool:
    """Does this AWS configuration create the baseline's log bucket '<prefix>-cloudtrail-<account id>'? It receives
    CloudTrail (account-wide half, enable_cloudtrail) and AWS Config snapshots (regional half, enable_aws_config, which
    defaults to enable_security_hub): terraform/aws/main.tf's local.regional_baseline / local.enable_aws_config."""
    account = _flag_setting(cfg, "enable_account_baseline", True)
    regional = _flag_setting(cfg, "enable_regional_baseline", account)
    config = _flag_setting(cfg, "enable_aws_config", _flag_setting(cfg, "enable_security_hub", False))
    return (account and _flag_setting(cfg, "enable_cloudtrail", True)) or (regional and config)


def _other_env_networks(env: paths.Env, quiet: bool = False) -> list[tuple[str, str, str]]:
    """(id, cloud, network CIDR) of every other environment (for the default choice and overlap warnings); one
    unreadable config.json must not break creating a new environment (said once: quiet=True for a second look)."""
    used = []
    for e in paths.Env.list_all():
        if e.id == env.id:
            continue
        other_cfg, problem = e.try_load()
        if problem:
            if not quiet:
                ui.warn(f"{e.config_path} is unreadable, so {e.id}'s network is not checked for overlaps.")
            continue
        cidr = other_cfg.get("network_cidr")
        if cidr:
            used.append((e.id, e.cloud, str(cidr)))
    return used


def _other_env_cidrs(env: paths.Env) -> list[str]:
    """Network CIDRs of every other environment."""
    return [cidr for _, _, cidr in _other_env_networks(env)]


# ---------------------------------------------------------------- Terraform roots

def _initialized_backend(directory: Path) -> dict | None:
    """The backend `terraform init` last configured in `directory`, as {type: config}; None for the implicit local
    backend (or a directory that was never initialised)."""
    try:
        data = json.loads((directory / ".terraform" / "terraform.tfstate").read_text())
    except (OSError, ValueError):
        return None
    backend = data.get("backend") if isinstance(data, dict) else None
    if not isinstance(backend, dict) or not backend.get("type"):
        return None
    return {backend["type"]: backend.get("config") or {}}


def _local_state_has_resources(directory: Path) -> bool:
    try:
        data = json.loads((directory / "terraform.tfstate").read_text() or "{}")
    except (OSError, ValueError):
        return False
    return bool(isinstance(data, dict) and data.get("resources"))


def _write_root(directory: Path, root: dict) -> bool:
    """Write main.tf.json. Returns True when `terraform init` must migrate state (-migrate-state -force-copy): the
    rendered backend differs from the one Terraform is initialised with. Deciding from what Terraform has, not from
    the previous render, also repairs a switch whose migrating init failed once (the new backend is rendered then,
    but the state still sits in the old place)."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "main.tf.json").write_text(json.dumps(root, indent=2) + "\n")
    wanted = (root.get("terraform") or {}).get("backend") or None
    current = _initialized_backend(directory)
    if current is None:                 # local state (or none yet): migrate only when there is state to move
        return wanted is not None and _local_state_has_resources(directory)
    if wanted is None:                  # remote -> local
        return True
    ctype, cconf = next(iter(current.items()))
    wtype, wconf = next(iter(wanted.items()))
    # Terraform records every backend attribute, unset ones as null: a key dropped from the render is a change too
    return ctype != wtype or {k: v for k, v in cconf.items() if v is not None} != \
        {k: v for k, v in (wconf or {}).items() if v is not None}


def _touches_vms(args) -> bool:
    """Commands that create/change VMs need the hypervisor, vmrest credentials and the base image; everything else
    (status, output, ssh, kubectl, platform ...) only needs the provider mirror and must work with Fusion closed."""
    cmd = getattr(args, "cmd", "")
    return cmd in ("setup", "apply", "plan", "provision") or \
        (cmd == "node" and getattr(args, "node_cmd", "") in ("add", "remove"))


def _check_owner(env: paths.Env, cfg: dict) -> None:
    """config.json must belong to this environment: two environments registered for one working directory would act
    on each other's configuration and Terraform state."""
    cloud_key, name = cfg.get("cloud"), cfg.get("env")
    if cloud_key and name and (cloud_key, name) != (env.cloud, env.name):
        raise ui.Abort(f"{env.config_path} is the configuration of {cloud_key}-{name}, not {env.id}: both are registered "
                       f"for the working directory {env.dir}. Point {env.id} to its own directory (edit "
                       f"{paths.WORKDIRS_INDEX}) before using it.")


# commands that may act on the current environment (`cs env use`) when only <cloud> is given: the ones that default to
# it without a cloud too (_ENV_SCOPED), and the reports. setup, destroy, apply, update-ip and provision never do: a
# destructive command must not quietly retarget at whatever environment was selected last.
_CURRENT_ENV_COMMANDS = ("status", "inventory", "output", "troubleshoot", "plan", "ssh", "k8s", "vpn", "finops", "scan")


def _command_words(args) -> str:
    """The command as it is typed before <cloud>, subcommand included (`vpn status`, `k8s info`): what the examples in
    a message about the environment must repeat to be runnable."""
    cmd = getattr(args, "cmd", "") or "status"
    sub = getattr(args, f"{cmd.replace('-', '_')}_cmd", None)
    return f"{cmd} {sub}" if isinstance(sub, str) and sub else cmd


def _pick_env_name(args, cloud: clouds.Cloud) -> str:
    """<cloud> without --env: the only environment of that cloud; else the current one (for the commands above); else
    ask at a terminal (current, then dev preselected); else dev, the documented default, when it exists. Several
    environments without a dev (or a current one that is not dev, for a changing command) are refused with the list:
    never a guess, and never 'aws-dev does not exist, create it'."""
    candidates = [e for e in paths.Env.list_all() if e.cloud == cloud.key]
    if len(candidates) == 1:
        return candidates[0].name
    if not candidates:
        return "dev"                            # reported as missing, with how to create one, by the caller
    cmd = getattr(args, "cmd", "") or "status"
    try:
        current = paths.load_settings().get("current_env")
    except Exception:  # noqa: BLE001 - unreadable settings: no current environment
        current = None
    cur = next((e for e in candidates if e.id == current), None)
    dev = next((e for e in candidates if e.name == "dev"), None)
    ids = ", ".join(e.id for e in candidates)
    typed = _command_words(args)
    if cur is not None and cmd in _CURRENT_ENV_COMMANDS:
        ui.eprint(ui.dim(f"  ({cmd}: {cur.id}, the current environment)"))   # stderr: `output --json` stays clean
        return cur.name
    if ui.interactive():
        return ui.choose("Which environment?", [(e.name, e.id) for e in candidates], default=(cur or dev or candidates[0]).name)
    if cur is not None and cur is not dev:
        if dev is not None:
            why = (f"`cloudseed {typed} {cloud.key}` without --env means {dev.id} (the default), but the current environment "
                   f"is {cur.id}")
        else:
            why = f"none is named dev; the current environment is {cur.id}, but {cmd} never picks it on its own"
        raise ui.Abort(f"Several {cloud.key} environments exist ({ids}): {why}. Say which: cloudseed {typed} {cloud.key} "
                       f"--env {cur.name}" + (f"   (or --env {dev.name})" if dev else ""), code=2)
    if dev is None:
        raise ui.Abort(f"Several {cloud.key} environments exist ({ids}) and none is named dev: pass --env NAME, e.g. "
                       f"cloudseed {typed} {cloud.key} --env {candidates[0].name}   (or pick one with: cloudseed env use <id>)",
                       code=2)
    others = ", ".join(e.id for e in candidates if e is not dev)
    note = f"{cmd}: {dev.id}, the default; the other {cloud.key} environments ({others}) need --env NAME"
    if cmd in _CURRENT_ENV_COMMANDS:
        ui.eprint(ui.dim(f"  ({note})"))
    else:
        ui.warn(note[0].upper() + note[1:] + ".")
    return dev.name


def _missing_env(args, cloud: clouds.Cloud, env_name: str) -> ui.Abort:
    """The environment named on the command line does not exist: say which ones do (a typo, an id given as the name)
    instead of inviting a `setup` that would create a stray, billable environment."""
    import difflib
    cmd = getattr(args, "cmd", "") or "status"
    envs = paths.Env.list_all()
    known = [e for e in envs if e.cloud == cloud.key]
    # an id given as --env (aws-prd for aws-prod): named and matched as the id it is, not as aws-aws-prd
    as_id = env_name[len(cloud.key) + 1:] if env_name.startswith(cloud.key + "-") else None
    what = env_name if as_id else f"{cloud.key}-{env_name}"
    msg = f"Environment {what} does not exist" + (" (nothing to destroy)" if cmd == "destroy" else "") + "."
    if known:
        names = [e.name for e in known]
        near = (difflib.get_close_matches(as_id, names, n=1, cutoff=0.6) if as_id else []) or \
            difflib.get_close_matches(env_name, names, n=1, cutoff=0.6)
        if near:
            msg += f" Did you mean --env {near[0]}?"
        msg += f" Known {cloud.key} environments: {', '.join(e.id for e in known)}."
    elif cmd != "destroy":
        msg += f" There is no {cloud.key} environment yet; create one with: cloudseed setup {cloud.key} --env {as_id or env_name}"
    elsewhere = [e for e in envs if e.name == env_name and e.cloud != cloud.key]
    if elsewhere:
        msg += f"  ({elsewhere[0].id} exists: cloudseed {_command_words(args)} {elsewhere[0].cloud} --env {env_name})"
    return ui.Abort(msg)


# settings every command renders from; hand-edited or very old config.json files can lack one
_REQUIRED_SETTINGS = {"name": "--name", "region": "--region", "network_cidr": "--cidr", "ssh_public_key": "--ssh-public-key",
                      "allowed_ssh_cidrs": "--allow-ip", "vars": "--var KEY=VALUE"}


def _check_required_settings(args, cloud: clouds.Cloud, env: paths.Env, cfg: dict) -> list[str]:
    """A config.json without a setting every command needs would crash deep inside the render ('KeyError'). Inspecting
    and tearing down keep working with the deployed value where cloudseed can recover it (else a placeholder that
    Terraform only needs to evaluate the configuration: a destroy acts on the state); anything that could change
    resources stops with the repair. The region and the name are never guessed: a wrong region points the provider at
    other resources. Returns the keys filled in for this command only (they must never be saved or used)."""
    if cloud.local and not cfg.get("region"):
        cfg["region"] = cloud.default_region    # a local target has no region: "local" is all it ever saves
    if getattr(args, "cmd", "") in ("ssh", "inventory", "troubleshoot", "scan"):
        # they never render the stack (they read the cached outputs and the key file); only their vars lookups need a dict
        if not isinstance(cfg.get("vars"), dict):
            cfg["vars"] = {}
            return ["vars"]
        return []
    missing = [k for k in ("name", "region", "network_cidr", "ssh_public_key") if not cfg.get(k)]
    if not isinstance(cfg.get("vars"), dict):
        missing.append("vars")
    if not cloud.local and not isinstance(cfg.get("allowed_ssh_cidrs"), list):
        missing.append("allowed_ssh_cidrs")
    if not missing:
        return []
    fix = (f"put the deployed value(s) back into {env.config_path}, or re-run: cloudseed setup {cloud.key} --env {env.name} "
           + " ".join(f"{_REQUIRED_SETTINGS[k]} <deployed value>" for k in missing if k != "vars"))
    if not _read_only_for_answers(args) or {"name", "region"} & set(missing):
        raise paths.ConfigError(f"{env.config_path} has no {', '.join(missing)}; cloudseed cannot render {env.id} without "
                                f"{'it' if len(missing) == 1 else 'them'}. Fix: {fix}   (use the values that are deployed: a "
                                "different network CIDR replaces the network and every host)")
    outputs = _cached_outputs(env)
    for key in missing:
        if key == "network_cidr":
            found = next((str(outputs[o]) for o in ("vpc_cidr", "private_cidr") if outputs.get(o)), None)
            cfg[key], how = found or "10.0.0.0/16", (f"the deployed {found}" if found else "a placeholder")
        elif key == "allowed_ssh_cidrs":
            cfg[key], how = ["127.0.0.1/32"], "a placeholder"
        elif key == "ssh_public_key":
            cfg[key], how = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholderPlaceholder0 missing", \
                "a placeholder"
        else:
            cfg[key], how = {}, "the defaults"
        ui.warn(f"{env.config_path} has no {key}; using {how} for this command only (nothing is saved). Fix: {fix}")
    return missing


# The per-environment lock (paths.Env.lock) of a command that changes an environment - setup, plan, apply, destroy,
# update-ip, provision (also `vpn provision`) and undo - held until the command returns: _dispatch opens a scope around
# the handler, _hold_env_lock enters the lock into it as soon as the command knows its environment. A second run on the
# same environment (another terminal, the console, an MCP client or agent) then stops with EnvBusy, naming the run that
# holds it, instead of racing it on config.json and the Terraform working directory. Cloudseed processes the command
# starts inherit it; a nested in-process command (an undo running `destroy`) re-enters it. node, platform, chaos and dr
# take the same lock around their own changes.
_LOCK_SCOPES: list = []
_ENV_LOCKING = ("plan", "apply", "destroy", "update-ip", "provision")


@contextlib.contextmanager
def _env_lock_scope():
    scope = contextlib.ExitStack()
    _LOCK_SCOPES.append(scope)
    try:
        with scope:
            yield
    finally:
        _LOCK_SCOPES.remove(scope)


def _hold_env_lock(env: paths.Env, action: str) -> None:
    """Take env's lock for the rest of the running command (nothing outside a dispatched command: direct calls)."""
    if _LOCK_SCOPES:
        _LOCK_SCOPES[-1].enter_context(env.lock(action))


def _locks_env(args) -> bool:
    cmd = getattr(args, "cmd", "")
    return cmd in _ENV_LOCKING or (cmd == "vpn" and getattr(args, "vpn_cmd", "") == "provision")


def _load_env(args, hypervisor: bool = True) -> tuple[clouds.Cloud, paths.Env, dict]:
    """The command's environment, loaded and checked. A local target also makes its provider available;
    hypervisor=False keeps that a dry-run prepare even for a command that changes VMs (vmrest, the base image and
    the network are left alone until the command knows it needs them: provision and node do that themselves)."""
    cloud = clouds.get(args.cloud)
    env_name = args.env or _pick_env_name(args, cloud)
    env = paths.Env(cloud.key, env_name)
    if not env.exists() and args.env and env_name.startswith(cloud.key + "-"):
        # the id as `cs list` shows it (aws-prod): only as a fallback, a real environment named 'aws-prod' comes first
        alt = paths.Env(cloud.key, env_name[len(cloud.key) + 1:])
        if alt.exists():
            ui.eprint(ui.dim(f"  (--env {env_name} is an environment id; using {alt.id})"))
            env, env_name = alt, alt.name
            args.env = alt.name
    if not env.exists():
        raise _missing_env(args, cloud, env_name)
    if _locks_env(args):   # before config.json is read: a run that changes it holds the environment from here on
        _hold_env_lock(env, f"{_command_words(args)} {cloud.key} --env {env.name}")
    cfg = env.load()
    _check_owner(env, cfg)
    filled = _check_required_settings(args, cloud, env, cfg)
    audit.attach(env)
    # invalid saved answers stop a changing command before anything is prepared (vmrest started, an image downloaded,
    # an OS Login key registered); read-only commands carry on with the stock default
    stand_ins = _check_saved_answers(args, cloud, env, cfg)
    if cloud.local:
        # local adapters: make the provider available; touch the hypervisor only for commands that change VMs. Only
        # what those resolve for real (vmnet CIDR, base image, guest OS id) is saved: read-only commands neither
        # rewrite config.json (its updated_at is "last change") nor persist their placeholders. `inventory` only reads
        # inventory.json, and `vpn` has nothing to do on a local target: they need no provider at all.
        if getattr(args, "cmd", "") not in ("inventory", "vpn"):
            touches = hypervisor and _touches_vms(args)
            before = copy.deepcopy(cfg)
            cloud.prepare(cfg, dry_run=not touches)
            if touches and cfg != before:
                env.save(cfg)
    elif _os_login_pending(cloud, cfg) and not _inspect_only(args) and "ssh_public_key" not in filled:
        # OS Login was switched on by a run that never reached prepare() (setup --dry-run / --plan-only, an older
        # version): register the key and record the login now, or the render grants no one OS Admin Login and SSH
        # would use a user name the bastion does not have (never a placeholder key: that one is not the user's)
        cloud.prepare(cfg)
        # saved as the configuration was: the stand-ins and placeholders above are for this command only
        saved = {k: v for k, v in cfg.items() if k not in filled}
        if stand_ins and isinstance(saved.get("vars"), dict):
            saved["vars"] = {**saved["vars"], **stand_ins}
        env.save(saved)
    return cloud, env, cfg


# commands that only inspect or tear down: they never need a cloud-side registration made first
_INSPECT_COMMANDS = ("status", "output", "destroy", "troubleshoot", "inventory", "list", "undo", "finops")


def _inspect_only(args) -> bool:
    cmd = getattr(args, "cmd", "")
    return cmd in _INSPECT_COMMANDS or (cmd == "vpn" and getattr(args, "vpn_cmd", "") in ("status", "disconnect")) or \
        (cmd == "k8s" and getattr(args, "k8s_cmd", "") in ("info", "untunnel"))


def _os_login_pending(cloud: clouds.Cloud, cfg: dict) -> bool:
    """GCP with enable_os_login but no OS Login user recorded yet (GCP.prepare registers the key and records it)."""
    return cloud.key == "gcp" and _lenient_bool((cfg.get("vars") or {}).get("enable_os_login"), False) and \
        not (cfg.get("os_login") or {}).get("user")


def _read_only_for_answers(args) -> bool:
    """Commands that keep working when a saved answer is invalid (with the stock default for the run): everything
    _inspect_only lists, plus the read-only or local-only ones that still need a cloud-side registration first (ssh,
    vpn users) and stopping this machine's VPN client. Anything that changes remote or host state refuses instead."""
    cmd = getattr(args, "cmd", "")
    return _inspect_only(args) or cmd == "ssh" or \
        (cmd == "vpn" and getattr(args, "vpn_cmd", "") in ("users", "disconnect"))


def _check_saved_answers(args, cloud: clouds.Cloud, env: paths.Env, cfg: dict) -> dict:
    """A config saved by an older version can hold an invalid answer (e.g. workload_count='abc'). Inspecting and tearing
    down (status, output, inventory, troubleshoot, destroy, ssh, finops, vpn status/users/disconnect, k8s info/untunnel)
    keep working with the built-in default for this run, so a broken setting never locks the user out; anything that
    could apply or provision refuses with the fix. Returns {key: saved value} of the answers replaced for this run.
    An invalid answer of a setting that is not in use (a sub-setting of a feature that is off, Cloud.unused: e.g. a
    kubernetes_node_count of 0 saved by an older version while Kubernetes is off) never blocks a command: it has no
    effect, so its built-in default stands in for the run (with the fix) whatever the command."""
    answers = cfg.get("vars") or {}
    for q in cloud.questions:   # older versions saved `--var fips_mode=no` as the string "no", which is truthy in Python
        if q.kind in ("bool", "int") and isinstance(answers.get(q.key), str):
            try:
                answers[q.key] = q.coerce(answers[q.key])
            except ValueError:
                pass            # reported just below
    bad = cloud.invalid_answers(cfg)
    # (not when the parent answer is itself invalid: whether the feature is on is then unknown, so both are reported
    # together and one setup run fixes them)
    for key in [k for k in bad if cloud.question(k).parent() not in bad and cloud.unused(cloud.question(k), cfg)]:
        q, problem = cloud.question(key), bad.pop(key)
        stock = q.stock_default(cfg)
        ui.warn(f"The saved {key} {cfg['vars'][key]!r} of {env.id} is invalid ({problem}); it is not in use "
                f"({q.parent()} is off), so {stock!r} stands in. Fix: cloudseed setup {cloud.key} --env {env.name} "
                f"{q.fix_flag}")
        cfg["vars"][key] = stock
    if not bad:
        return {}
    fix = f"cloudseed setup {cloud.key} --env {env.name} " + " ".join(cloud.question(k).fix_flag for k in bad)
    if not _read_only_for_answers(args):
        raise ui.Abort(f"{env.id} has invalid saved settings: " +
                       "; ".join(f"{k}={cfg['vars'][k]!r} ({p})" for k, p in bad.items()) + f". Fix: {fix}")
    replaced = {}
    for key, problem in bad.items():
        stock = cloud.question(key).stock_default(cfg)
        ui.warn(f"The saved {key} {cfg['vars'][key]!r} of {env.id} is invalid ({problem}); using {stock!r} for this "
                f"command. Fix: {fix}")
        replaced[key] = cfg["vars"][key]
        cfg["vars"][key] = stock
    return replaced


LOCAL_NOT_APPLICABLE = {
    "enable_vpn": services.VPN_LOCAL_REASON,      # one wording for setup, provision and every `cs vpn` command
    "vpn_type": "no VPN host exists on the vmware target",
    "single_nat_gateway": "the bastion is the NAT on the vmware target",
    "region": "the VMs run on this machine, so the vmware target has no region",
    "location": "the VMs run on this machine, so the vmware target has no location",
}
# Undeclared --var names that are really a setup flag's job (they are not stack variables of that target)
_FLAG_FOR_VAR = {"vpc_cidr": ("the network CIDR", "--cidr"), "network_cidr": ("the network CIDR", "--cidr"),
                 "private_cidr": ("the network CIDR", "--cidr"), "cidr": ("the network CIDR", "--cidr"),
                 "tags": ("tags", "--tag KEY=VALUE"), "labels": ("labels", "--tag KEY=VALUE")}


def _check_extra_vars(cloud: clouds.Cloud, extra: dict) -> None:
    """Every --var must be a variable of the target's Terraform stack; a typo or a cloud-only setting on vmware would
    otherwise only surface as a Terraform 'unsupported argument' error at plan time."""
    declared = {name for name, _, _ in helpmod._parse_variables(cloud.key)}
    unknown = [k for k in extra if k not in declared]
    if not unknown:
        return
    lines = []
    for k in unknown:
        why = LOCAL_NOT_APPLICABLE.get(k) if cloud.local else None
        flag = _FLAG_FOR_VAR.get(k) or (("the " + cloud.key + " " + k, "--region") if k in ("region", "location")
                                         and not cloud.local else None)
        near = helpmod.suggest(k, sorted(declared), n=1, cutoff=0.6)
        if why:
            lines.append(f"{k}: {why}")
        elif flag:
            lines.append(f"{k}: not a variable of the {cloud.key} stack; {flag[0]} is set with {flag[1]}")
        else:
            lines.append(f"{k}: not a variable of the {cloud.key} stack" + (f" (did you mean {near[0]}?)" if near else ""))
    raise ui.Abort("Unknown --var for " + cloud.key + ":\n  " + "\n  ".join(lines) +
                   f"\nValid variables: cloudseed help variables {cloud.key}   (drop a saved one with --var KEY=null)")


def _render(cloud: clouds.Cloud, env: paths.Env, cfg: dict) -> bool:
    return _write_root(env.stack_dir, cloud.render_stack(cfg, paths.tf_root()))


def _cache_outputs(env: paths.Env, t: Terraform) -> dict:
    """Read the outputs and cache them in outputs.json. A bastion / VPN host that Terraform rebuilt behind the same
    Elastic/static IP (its instance id changed) has new SSH host keys: its remembered key is dropped first, so the next
    ssh, Host.wait or provisioning run does not stop at 'REMOTE HOST IDENTIFICATION HAS CHANGED'. When terraform could
    not read them (t.outputs_error, already shown) the cache is left as it was and {} is returned; env.outputs_error
    keeps the reason for the messages that follow (_finish, _no_bastion_ip), so they never blame the VMs."""
    before = _cached_outputs(env)
    outputs = t.outputs()
    env.outputs_error = getattr(t, "outputs_error", None)
    if env.outputs_error:
        return {}
    try:
        prov.forget_replaced_hosts(env, before, outputs)
    except OSError:
        pass                    # best effort: an unreadable known_hosts file must not fail the apply that just worked
    (env.dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n")
    return outputs


def _cached_outputs(env: paths.Env) -> dict:
    try:
        out = json.loads((env.dir / "outputs.json").read_text())
    except (OSError, ValueError):
        return {}
    return out if isinstance(out, dict) else {}    # a truncated or hand-edited file is no outputs, never a crash


def _vmnet_resolved(cfg: dict, existing: dict | None = None) -> bool:
    """Is a local environment's network CIDR final: chosen with --cidr, or resolved against VMware's networks by a real
    prepare() (which also resolves the base image; a dry run leaves base_disk at /dev/null)?"""
    if cfg.get("cidr_explicit"):
        return True
    for c in (cfg, existing or {}):
        disk = str((c.get("vars") or {}).get("base_disk") or "")
        if disk and disk != "/dev/null" and c.get("network_cidr") == cfg.get("network_cidr"):
            return True
    return False


def _feature_off(cfg: dict, key: str) -> bool:
    """A VPN / Kubernetes setting (or output) of a feature that is switched off in this configuration; on AWS also
    Security Hub while this environment does not manage the regional baseline it belongs to, and the log bucket's
    output when no part of the baseline writes to it."""
    v = cfg.get("vars") or {}
    cloud = clouds.CLOUDS.get(str(cfg.get("cloud") or ""))
    q = cloud.question(key) if cloud is not None else None
    if q is not None and cloud.unused(q, cfg):
        return True     # a setting of a feature that is off: vpn_type, kubernetes_*, a declared depends_on (Cloud.unused)
    if q is None and key.startswith("vpn_"):             # outputs of the VPN host / the cluster
        return not _lenient_bool(v.get("enable_vpn", False), False)
    if q is None and key.startswith("kubernetes_"):
        return not _lenient_bool(v.get("enable_kubernetes", False), False)
    if cfg.get("cloud") == "aws" and key == "enable_security_hub":
        return not _flag_setting(cfg, "enable_regional_baseline", _flag_setting(cfg, "enable_account_baseline", True))
    if cfg.get("cloud") == "aws" and key == "cloudtrail_bucket":
        return not _aws_log_bucket(cfg)
    return False


def _print_summary(cloud: clouds.Cloud, env: paths.Env, cfg: dict, network_resolved: bool = True) -> None:
    state = cfg.get("state", {})
    state_txt = state.get("type", "?")
    if state.get("backend"):
        state_txt += "  " + ui.dim(json.dumps(state["backend"]))
    elif state.get("type") == "local":
        state_txt += "  " + ui.dim(str(env.stack_dir / "terraform.tfstate"))
    elif state.get("type") == "remote":
        state_txt += "  " + ui.dim("(storage created on the first apply)")
    missing = ui.dim("(missing)")
    network = cfg.get("network_cidr") or missing
    if cloud.local and not cfg.get("cidr_explicit") and not network_resolved:
        # the saved value is only a placeholder until prepare() adopts VMware's host-only vmnet
        network = ui.dim("VMware host-only vmnet (resolved at apply)")
    # a local target's VMs sit on a host-only network only this machine reaches: no source allow-list applies
    allowed = "this machine only (host-only/NAT)" if cloud.local else (", ".join(cfg.get("allowed_ssh_cidrs") or []) or missing)
    rows: list = [
        ("Cloud", cloud.display),
        ("Infra name", cfg.get("name") or missing),
        ("Region", cfg.get("region") or missing),
        ("Network CIDR", network),
        ("SSH allowed from", allowed),
        ("Working dir", cfg.get("workdir") or str(env.dir)),
        ("State", state_txt),
    ]
    for k, v in (cfg.get("vars") or {}).items():
        if k in ("base_disk", "guest_os_id") or _feature_off(cfg, k):
            continue    # resolved internals, and the sub-settings of a feature that is off (vpn_type, kubernetes_*)
        rows.append((k, ui.dim("(not set)") if v in ("", None) else _fmt(v)))
    if cfg.get("extra_vars"):
        rows.append(("extra vars", json.dumps(cfg["extra_vars"])))
    if cloud.local:     # terraform/vmware takes `tags` only for a uniform interface: VMs have none
        rows.append(("Tags", ui.dim("not applied (VMware VMs have no tags)")))
    else:
        rows.append(("Tags", ", ".join(f"{k}={v}" for k, v in cloud.tags(cfg).items())))
    ui.panel(f"Environment {env.id}", rows)


def _print_outputs(outputs: dict, cfg: dict | None = None) -> None:
    """The outputs as a panel. With the configuration, empty outputs of a feature that is off (vpn_*, kubernetes_*:
    Terraform returns null for them) are left out."""
    if not outputs:
        ui.info("No outputs yet.")
        return
    rows = [(k, "-" if v is None else _fmt(v)) for k, v in outputs.items()
            if not (cfg is not None and v in (None, "", [], {}) and _feature_off(cfg, k))]
    ui.panel("Outputs", rows, accent="leaf")


def _ssh_command(cloud: clouds.Cloud, env: paths.Env, cfg: dict, outputs: dict) -> list[str] | None:
    ip = outputs.get("bastion_public_ip")
    if not ip:
        return None
    key = env.private_key_path(cfg)
    return ["ssh", "-i", str(key), *env.ssh_options(), f"{cloud.ssh_user(cfg)}@{ip}"]


def _outputs_unreadable(cloud: clouds.Cloud, env: paths.Env) -> str:
    """The outputs of env's stack could not be read (env.outputs_error): what that means and how to go on."""
    again = (f"cloudseed provision {cloud.key} --env {env.name}   (re-reads the outputs, then provisions the bastion)"
             if cloud.local else f"cloudseed status {cloud.key} --env {env.name}   (re-reads the outputs), then "
             f"cloudseed provision {cloud.key} --env {env.name}")
    return (f"Terraform could not read the outputs of {env.id}, so its bastion address is unknown. This is not a problem "
            f"of the {'VMs' if cloud.local else 'bastion'}: terraform itself failed.\n  {env.outputs_error}\n"
            f"  When that is fixed, run: {again}")


def _no_bastion_ip(cloud: clouds.Cloud, env: paths.Env, refreshed: bool = False) -> str:
    """Why there is no bastion address, and what to do. refreshed=True: the outputs were just read from the Terraform
    state (provisioning), so pointing at `status` to read them would lead nowhere."""
    if getattr(env, "outputs_error", None):
        return _outputs_unreadable(cloud, env)      # terraform failed to read them: never "the VM reported no address"
    if not _env_has_resources(env):
        return (f"{env.id} has not been applied yet, so there is no bastion: cloudseed apply {cloud.key} --env {env.name}"
                f"   (or: cloudseed setup {cloud.key} --env {env.name})")
    if cloud.local:
        return (f"No bastion IP: the bastion VM of {env.id} reported no address (VMware could not read one from the guest: it is still "
                "booting, open-vm-tools is not running, or the VM has no network). Check the VM in VMware "
                f"(Fusion/Workstation), then run: cloudseed provision {cloud.key} --env {env.name}   (it re-reads the "
                f"address and provisions the bastion; details: cloudseed troubleshoot {cloud.key} --env {env.name})")
    if refreshed:
        return (f"{env.id}'s Terraform state has no bastion address: the bastion is not deployed (e.g. a targeted "
                f"destroy removed it). Re-create it with: cloudseed apply {cloud.key} --env {env.name}")
    return (f"No bastion IP is known for {env.id}. Read it from the state with: cloudseed status {cloud.key} --env "
            f"{env.name}   (or apply first: cloudseed apply {cloud.key} --env {env.name})")


def _finish(cloud: clouds.Cloud, env: paths.Env, cfg: dict, t: Terraform, explain_missing_ip: bool = True) -> None:
    """Outputs and next steps after an apply. explain_missing_ip=False: provisioning follows and reports a missing
    bastion address itself."""
    outputs = _cache_outputs(env, t)
    audit.refresh(env, t, "apply")
    unreadable = bool(getattr(env, "outputs_error", None))
    # Kubernetes turned off: the record of the cluster that went must not outlive it. Only on outputs that were read:
    # an applied local stack always has some (the bastion's), so none at all means `terraform output` failed
    if cloud.local and outputs:
        _forget_removed_cluster(env, cfg, outputs)
    if not unreadable:              # (the warning above named terraform's error: no "No outputs yet." after an apply)
        _print_outputs(outputs, cfg)
    cmd = _ssh_command(cloud, env, cfg, outputs)
    lines = []
    if cmd:
        lines += [f"{ui.style('ssh     ', 'muted')} cs ssh {cloud.key} --env {env.name}",
                  f"{ui.style('        ', 'muted')} {ui.dim(shlex.join(cmd))}"]
    lines += [f"{ui.style('status  ', 'muted')} cs status {cloud.key} --env {env.name}",
              f"{ui.style('change  ', 'muted')} cs setup {cloud.key} --env {env.name} --var key=value",
              f"{ui.style('destroy ', 'muted')} cs destroy {cloud.key} --env {env.name}"]
    if cmd:
        ui.panel(f"{env.id} is ready", lines, accent="leaf")
    else:   # applied, but not usable yet: no green "ready" for a bastion nobody can reach
        if explain_missing_ip:
            ui.warn(_no_bastion_ip(cloud, env))
        ui.panel(f"{env.id} is applied ({'its outputs could not be read' if unreadable else 'no bastion address yet'})",
                 lines)


def _approve(question: str, auto: bool, cancelled: str = "Cancelled. Nothing was changed.",
             nothing_applied: str = "Nothing applied. Re-run with --auto-approve to apply without a prompt.") -> None:
    if auto:
        return
    if not ui.interactive():
        raise ui.Abort(nothing_applied, code=3)
    if not ui.confirm(question, default=False):
        raise ui.Abort(cancelled, code=0)


# ---------------------------------------------------------------- environment history

def _env_has_resources(env: paths.Env) -> bool:
    """Best effort, from local files only: does the environment's stack hold cloud resources now? Every Terraform
    run records the resource count it left behind in inventory.json; local state is read directly."""
    state = env.stack_dir / "terraform.tfstate"
    if state.exists():
        try:
            data = json.loads(state.read_text() or "{}")
        except (OSError, ValueError):
            return True                         # unreadable state: assume the worst
        if isinstance(data, dict) and data.get("resources"):
            return True
    for h in reversed(audit.load(env).get("history") or []):
        if isinstance(h.get("resources"), int):
            return h["resources"] > 0
    return bool(_cached_outputs(env))


def _first_apply_pending(env: paths.Env) -> bool:
    """True when the stack's resources so far come only from failed applies since the environment was created (or
    fully destroyed): the next successful setup is still its creation, and undoing it must remove everything."""
    failed = False
    for h in reversed(audit.load(env).get("history") or []):
        action = h.get("action")
        if action in ("apply", "undo", "node-add", "node-remove", "platform-prereqs", "destroy-targets"):
            return False
        if action == "destroy":
            break
        if action == "apply-failed":
            failed = True
    return failed


# ---------------------------------------------------------------- remote state

def _bootstrap_state(cloud: clouds.Cloud, env: paths.Env, cfg: dict, auto: bool, preview: bool = False,
                     **approve_text) -> dict | None:
    """Create the remote state storage (plan, approve, apply) and return the backend block. preview=True only plans
    it (nothing is created; returns None), for --plan-only and runs that cannot be confirmed."""
    ui.header("Remote state storage")
    if preview:
        ui.info("The state storage does not exist yet; it is created first when you apply. Its plan:")
    else:
        ui.info("cloudseed will create a hardened, versioned, encrypted bucket for Terraform state.")
    _write_root(env.bootstrap_dir, cloud.render_bootstrap(cfg, paths.tf_root()))
    t = Terraform(env.bootstrap_dir)
    t.init()
    t.plan("tfplan")
    if preview:
        (env.bootstrap_dir / "tfplan").unlink(missing_ok=True)
        return None
    _approve("Create the remote state storage?", auto, **approve_text)
    t.apply("tfplan")
    (env.bootstrap_dir / "tfplan").unlink(missing_ok=True)
    outputs = t.outputs()
    backend = cloud.backend_from_outputs(cfg, outputs)
    ui.ok(f"Remote state ready: {json.dumps(backend)}")
    return backend


def _pending_backend(cloud: clouds.Cloud, cfg: dict) -> bool:
    """Remote state was chosen but its storage was never created (setup ran with --dry-run or --plan-only, or the
    bucket was declined)."""
    state = cfg.get("state") or {}
    return not cloud.local and state.get("type") == "remote" and not state.get("backend")


def _ensure_backend(cloud: clouds.Cloud, env: paths.Env, cfg: dict, auto: bool) -> None:
    """Create a pending remote state storage before anything is applied, so resources are never tracked in a stray
    local state file of an environment whose configuration says 'remote'."""
    if _pending_backend(cloud, cfg):
        cfg["state"]["backend"] = _bootstrap_state(cloud, env, cfg, auto)
        env.save(cfg)


# ---------------------------------------------------------------- setup helpers

def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _workdir_conflict(target: Path, env_id: str) -> str | None:
    """Why `target` cannot be env_id's working directory, or None: paths.workdir_problem - the rule Env.set_workdir
    enforces when the configuration is saved (not the home directory, cloudseed's home or checkout, not a file, not a
    directory holding another environment's configuration or files that are not cloudseed's) - checked before any prompt
    or directory is created, plus no overlap with another environment's directory: two environments sharing one load and
    overwrite each other's config.json and share one Terraform state (a destroy of one hits the other)."""
    home = Path.home().resolve()
    cs_home, envs = paths.HOME.resolve(), paths.ENVS_DIR.resolve()
    if target == Path(target.anchor) or _is_within(home, target) or _is_within(cs_home, target) or target == envs:
        # before the overlap test below, which would otherwise name some environment inside it
        return (f"{target} cannot be an environment's working directory (it holds other data, and `destroy --purge` "
                f"deletes the working directory); use a dedicated directory such as {target / env_id}.")
    others: dict = {}
    for e in paths.Env.list_all():
        if e.id != env_id:
            others[e.id] = e.dir
    for eid, p in paths._load_index().items():
        # a claim whose directory was deleted or moved aside no longer holds an environment (`list` does not show it):
        # the same rule as paths.workdir_problem and the claim release in Env.set_workdir, which drops it on save
        if eid != env_id and eid not in others:
            try:
                if paths.abandoned_workdir(Path(p).expanduser()):
                    continue
            except (OSError, TypeError, ValueError):
                continue
            others[eid] = Path(p)
    for eid, d in others.items():
        d = Path(d).expanduser().resolve()
        if d == target:
            return f"{target} is already the working directory of {eid}; choose another --workdir for {env_id}."
        if _is_within(target, d) or _is_within(d, target):
            return f"{target} overlaps the working directory of {eid} ({d}); choose a separate directory for {env_id}."
    return paths.workdir_problem(target, env_id)


def _setup_env(cloud: clouds.Cloud, env_name: str, args) -> tuple[paths.Env, Path | None]:
    """The environment, and the new working directory when setup places it somewhere else. That choice is written to
    workdirs.json only when the configuration is saved, so a refused setup leaves no index entry behind."""
    env = paths.Env(cloud.key, env_name)
    current = env.dir.resolve()

    def check(path) -> str | None:
        target = Path(str(path)).expanduser().resolve()
        return None if target == current else _workdir_conflict(target, env.id)

    target = None
    if args.workdir:
        target = Path(args.workdir).expanduser().resolve()
    elif not env.exists() and ui.interactive() and cloud.local:
        chosen = ui.ask("Working directory (config, state, SSH key and VM files)", str(env.dir), validate=check)
        target = Path(chosen).expanduser().resolve()
    if target is None or target == current:
        return env, None
    if env.exists():
        raise ui.Abort(f"{env.id} already lives in {env.dir} (its config, SSH key and Terraform state are there); "
                       f"--workdir {target} would start a second, empty {env.id} and lose track of it. Re-run without "
                       f"--workdir to change {env.id}; to move it, destroy it and set it up again with --workdir.")
    problem = _workdir_conflict(target, env.id)
    if problem:
        raise ui.Abort(problem)
    return paths.Env(cloud.key, env_name, workdir=target), target


# cloudseed's own files in a working directory (to take back a first setup that failed before it was saved)
_ENV_ARTIFACTS = ("config.json", "inventory.json", "outputs.json", "stack", "bootstrap", "ssh", "logs", "vms", "k8s",
                  "dry-run")


def _artifact_listing(env: paths.Env) -> dict:
    out: dict = {}
    for name in _ENV_ARTIFACTS:
        p = env.dir / name
        if p.is_dir():
            out[name] = {c.name for c in p.iterdir()}
        elif p.exists():
            out[name] = None
    return out


def _remove(p: Path) -> None:
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p, ignore_errors=True)
    elif p.exists() or p.is_symlink():
        p.unlink()


def _discard_failed_setup(env: paths.Env, dir_existed: bool, before: dict) -> None:
    """A first setup that stopped before its configuration was saved leaves nothing behind: no working directory that
    `cs list` never shows, and no generated SSH key a retry would silently reuse. A directory that existed already
    (e.g. --workdir) only loses what this run added."""
    audit.mark_purged()             # the run's audit line goes to the global log only
    try:
        if not dir_existed:
            shutil.rmtree(env.dir, ignore_errors=True)
            return
        for name in _ENV_ARTIFACTS:
            p = env.dir / name
            if name not in before:
                _remove(p)
            elif before[name] is not None and p.is_dir():
                for child in p.iterdir():
                    if child.name not in before[name]:
                        _remove(child)
    except OSError:
        pass


def _setup_network(args, cloud: clouds.Cloud, env: paths.Env, existing: dict, given: dict, legacy: dict,
                   deployed: bool) -> tuple[str, bool]:
    """The network CIDR and whether it was given explicitly (--cidr, or a --var override of the CIDR variable saved by
    an older version). Every value is validated, whichever path it came from."""
    cidr_var = CIDR_VARS.get(cloud.key, "cidr")
    explicit = None
    if args.cidr is not None:
        problem = _cidr_problem(args.cidr)
        if problem:
            raise ui.Abort(f"--cidr: {problem}")
        explicit = str(ipaddress.ip_network(args.cidr.strip()))
    if explicit is None and "cidr" in legacy and cidr_var not in given["unset"]:
        problem = _cidr_problem(legacy["cidr"])
        if problem:
            ui.warn(f"Dropping the saved --var {cidr_var} override ({problem}).")
        else:
            explicit = str(ipaddress.ip_network(str(legacy["cidr"]).strip()))
            ui.warn(f"Moved the saved --var {cidr_var}={explicit} override into the environment's network CIDR "
                    "(it is what Terraform deployed); change it with --cidr.")
    used = _other_env_cidrs(env)
    if explicit is not None:
        cidr = explicit
    elif cloud.local:
        # a placeholder: prepare() replaces it with VMware's host-only vmnet when there is one (and refuses a second
        # environment on it); without one it becomes this environment's own vmnet, so it must not be another's range
        cidr = str(existing.get("network_cidr") or _local_default_cidr(used))
        problem = _cidr_problem(cidr)
        if problem:
            raise ui.Abort(f"The saved network CIDR of {env.id} is invalid: {problem} Pass a valid one with --cidr.")
    else:
        saved = existing.get("network_cidr")
        if deployed and not saved:
            # a hand-edited config.json lost it: a fresh default would replace the deployed network and every host
            saved = next((str(v) for v in (_cached_outputs(env).get(o) for o in ("vpc_cidr", "private_cidr")) if v), None)
            if not saved:
                raise ui.Abort(f"{env.id} is deployed, but {env.config_path} has no network_cidr and cloudseed cannot "
                               "tell which one is deployed: pass it with --cidr <the deployed CIDR> (a different one "
                               "replaces the network and every host).")
            ui.warn(f"{env.config_path} has no network_cidr; keeping the deployed {saved} (from its outputs).")
        default = saved or netutil.pick_network_cidr(used)
        cidr = ui.ask("Network CIDR (subnets are carved from it automatically)", str(default),
                      validate=_cidr_problem, flag="--cidr")
        cidr = str(ipaddress.ip_network(cidr.strip()))
    if explicit is not None:
        _warn_network_overlaps(cloud, cidr, _other_env_networks(env, quiet=True))
    if deployed and existing.get("network_cidr") and existing["network_cidr"] != cidr \
            and not (cloud.local and not existing.get("cidr_explicit") and explicit is None):
        ui.warn(f"The network of {env.id} changes from {existing['network_cidr']} to {cidr}: that replaces the network "
                "and every host in it (review the plan).")
    return cidr, explicit is not None


def _warn_network_overlaps(cloud: clouds.Cloud, cidr: str, networks) -> None:
    """Warnings for an explicit --cidr: what an overlap with each other environment really breaks (a local VMware
    network has no VPN or peering; a cloud environment's VPN routes on this machine shadow a local network), and a
    public range on a cloud network (vmware refuses those: VMware.network_problems)."""
    net = ipaddress.ip_network(cidr)
    groups: dict[str, list[str]] = {}
    for eid, other_cloud, other in networks:
        try:
            if not net.overlaps(ipaddress.ip_network(other, strict=False)):
                continue
        except (ValueError, TypeError):
            continue
        other_local = bool(getattr(clouds.CLOUDS.get(other_cloud), "local", False))
        kind = ("local" if cloud.local else "cloud") + "-" + ("local" if other_local else "cloud")
        groups.setdefault(kind, []).append(f"{eid} ({other})")
    for kind, envs in groups.items():
        names = ", ".join(envs)
        if kind == "local-local":
            ui.warn(f"{cidr} overlaps the network of {names}: both environments would give their VMs the same fixed "
                    "addresses on this machine, so setup refuses it once the other one has VMs. Choose another --cidr.")
        elif kind == "local-cloud":
            ui.warn(f"{cidr} overlaps the network of {names}: while that environment's VPN is connected on this "
                    "machine, its routes shadow this local network.")
        elif kind == "cloud-local":
            ui.warn(f"{cidr} overlaps the local VMware network of {names}: while this environment's VPN is connected, "
                    "its routes shadow that network on this machine.")
        else:
            ui.warn(f"{cidr} overlaps the network of {names}; VPN routes and peering between them will conflict.")
    if not cloud.local and net.is_global:
        ui.warn(f"{cidr} is a public address range: hosts in this network can no longer reach those addresses on the "
                "internet (traffic to them stays inside the network). Prefer a private range such as 10.0.0.0/16.")


def _local_default_cidr(used) -> str:
    """First 10.N.0.0/24 (N from 100) that overlaps no other environment's network."""
    nets = []
    for u in used:
        try:
            nets.append(ipaddress.ip_network(str(u), strict=False))
        except ValueError:
            pass
    for n in list(range(100, 256)) + list(range(0, 100)):
        cand = ipaddress.ip_network(f"10.{n}.0.0/24")
        if not any(u.version == 4 and cand.overlaps(u) for u in nets):
            return str(cand)
    return "10.100.0.0/24"      # everything in 10/8 is taken: prepare() and the overlap checks decide


def _setup_allow_list(args, cloud: clouds.Cloud, env: paths.Env, existing: dict, given: dict, legacy: dict) -> list[str]:
    """Who may SSH to the bastion. An existing environment keeps its saved list unless --allow-ip (or `update-ip`)
    changes it: re-running setup to change another setting must not replace an office or VPN range with whatever
    network this machine happens to be on."""
    flag = [x.strip() for item in (args.allow_ip or []) for x in item.split(",") if x.strip()] or None
    if flag is not None:
        problem = _allow_list_problem(flag)
        if problem:
            raise ui.Abort(f"--allow-ip: {problem}")
        return _canonical_cidrs(flag)
    prev = list(existing.get("allowed_ssh_cidrs") or [])
    if "allow" in legacy and ALLOW_VAR not in given["unset"]:
        # an older version saved the override as typed, host bits included (203.0.113.7/24), and Terraform deployed its
        # network form: that is what is migrated. Host bits are refused at every prefix now, so the canonical form is
        # checked; a value that cannot even be normalized gets the check of the raw text (and its explanation).
        try:
            canonical = _canonical_cidrs(legacy["allow"])
            problem = _allow_list_problem(canonical) if canonical else _allow_list_problem(legacy["allow"])
        except ValueError:
            canonical, problem = [], _allow_list_problem(legacy["allow"]) or "not a list of IPv4 ranges"
        if problem:
            ui.warn(f"Dropping the saved --var {ALLOW_VAR} override ({problem}).")
        else:
            prev = canonical
            ui.warn(f"Moved the saved --var {ALLOW_VAR} override into the SSH allow-list ({', '.join(prev)}; it is what "
                    "Terraform deployed). Change it with --allow-ip or cloudseed update-ip.")
    if prev:
        problem = _allow_list_problem(prev)
        if problem:
            if not ui.interactive():
                raise ui.Abort(f"The saved SSH allow-list of {env.id} is invalid ({problem}); pass --allow-ip <your-ip>.")
            ui.warn(f"The saved SSH allow-list of {env.id} is invalid ({problem}).")
            prev = []
    detected = netutil.detect_public_ip()
    if prev:
        default = prev
        if detected and not _ip_allowed(detected, prev):
            merged = ",".join(prev + [f"{detected}/32"])
            ui.warn(f"Your public IP {detected} is not in the SSH allow-list of {env.id} ({', '.join(prev)}); "
                    f"the saved list is kept. To add it: cloudseed update-ip {cloud.key} --env {env.name} --allow-ip {merged}")
            if ui.interactive():
                default = prev + [f"{detected}/32"]
    else:
        if detected:
            ui.info(f"Your public IP appears to be {detected}")
        elif not ui.interactive():      # no prompt to "enter it manually" at: say only what to pass
            raise ui.Abort("Could not detect your public IP and none was given: pass --allow-ip <your-ip>.")
        else:
            ui.warn("Could not auto-detect your public IP; enter it manually.")
        default = [f"{detected}/32"] if detected else []
    cidrs = ui.ask_list("Allow SSH to the bastion from", default, validate=_allow_list_problem)
    result = _canonical_cidrs(cidrs)
    if prev and set(result) == set(prev):
        return list(dict.fromkeys(prev))    # unchanged: keep the saved order (no spurious "changed" in undo)
    return result


def _saved_answers(cloud: clouds.Cloud, existing: dict, legacy: dict, given: dict, cfg: dict,
                   flagged: set) -> dict:
    """The saved answers used as defaults: typed by kind where they can be (older versions saved --var strings such
    as "False", which Python reads as True), without the ones reset with KEY=null, and without a GCP zone that belongs
    to a previous region. A null or blank yes/no or number means "not set": its default, without a word (as
    Cloud.var_bool / var_int read it)."""
    saved = {**legacy.get("answers", {}), **(existing.get("vars") or {})}
    for q in cloud.questions:
        if q.key in saved and q.kind in ("bool", "int") and q.key not in flagged:
            value = saved[q.key]
            if value is None or (isinstance(value, str) and not value.strip()):
                saved.pop(q.key)
                continue
            try:
                saved[q.key] = _coerce_answer(q, saved[q.key])
            except ValueError as e:     # a prompt default of bool("maybe") would be True: use the built-in default
                ui.warn(f"The saved {q.key} {saved[q.key]!r} is invalid ({e}); using the default instead.")
                saved.pop(q.key)
    for key in given["unset"]:
        saved.pop(key, None)
    zone = saved.get("zone")
    if cloud.key == "gcp" and zone and "zone" not in flagged and \
            not re.fullmatch(re.escape(str(cfg["region"])) + r"-[a-z]", str(zone)):
        ui.info(f"The saved zone {zone} is not in region {cfg['region']}; using that region's default zone.")
        saved.pop("zone")
    return saved


def _flag_answers(cloud: clouds.Cloud, args, given: dict) -> dict:
    """Answers given with a dedicated flag (--project-id, --zone ...) or --var, checked like typed answers. A flag and
    a --var for the same setting must agree."""
    answers = dict(given["answers"])
    for q in cloud.questions:
        raw = getattr(args, q.key, None)
        if raw is None:
            continue
        try:
            value = _coerce_answer(q, raw)
        except ValueError as e:
            raise ui.Abort(f"{q.flag} {raw}: {e}")
        if q.key in answers and answers[q.key] != value:
            raise ui.Abort(f"{q.flag} and --var {q.key} disagree ({value} vs {answers[q.key]}); pass only one of them.")
        answers[q.key] = value
        setattr(args, q.key, value)
    return answers


def _check_answers(cloud: clouds.Cloud, env: paths.Env, cfg: dict) -> None:
    """Type and validate every answer, whatever path it came from (prompt, flag, --var, saved config). An invalid
    saved value of a feature that is off is reset; any other is refused with the command that fixes it."""
    v = cfg["vars"]
    for q in cloud.questions:
        if q.key not in v:
            continue
        try:
            v[q.key] = _coerce_answer(q, v[q.key])
        except ValueError as e:
            # not in use: Cloud.unused (a missing parent answer counts as its default), or AWS Security Hub without
            # the regional baseline it belongs to
            if cloud.unused(q, cfg) or _feature_off(cfg, q.key):
                default = q.default(cfg) if callable(q.default) else q.default
                ui.warn(f"The saved {q.key} {v[q.key]!r} is invalid ({e}); it is not in use, so it is reset to {default!r}.")
                v[q.key] = default
                continue
            raise ui.Abort(f"The saved setting {q.key}={v[q.key]!r} of {env.id} is invalid: {e}. "
                           f"Fix it with: cloudseed setup {cloud.key} --env {env.name} {q.fix_flag}")


# ---------------------------------------------------------------- SSH key

_KEY_FILES = netutil.KEY_FILES      # names of key pairs cloudseed generates


def _key_algo(pub) -> str:
    parts = str(pub or "").split()
    return parts[0] if parts else ""


def _key_problem(pub: str, fips: bool, cloud_key: str = "") -> str | None:
    """Why `pub` cannot be the environment's key: FIPS mode (ed25519 is not approved) and, with cloud_key, the cloud's
    own key-type rules (EC2 / Azure refuse ECDSA, RSA sizes). See netutil.ssh_key_problem."""
    return netutil.ssh_key_problem(pub, fips=fips, cloud=cloud_key)


def _set_aside(files) -> None:
    """Rename files out of the way (never delete a key)."""
    stamp = time.strftime("%Y%m%d%H%M%S")
    for p in files:
        if p.exists() or p.is_symlink():
            p.rename(p.with_name(f"{p.name}.replaced-{stamp}"))


def _generated_pairs(env: paths.Env) -> list:
    out = []
    for name in _KEY_FILES:
        pub = env.ssh_dir / f"{name}.pub"
        if pub.exists() or (env.ssh_dir / name).exists():
            try:
                text = pub.read_text().strip()
            except (OSError, UnicodeDecodeError):
                text = ""
            out.append((env.ssh_dir / name, pub, text))
    return out


def _read_user_key(args) -> tuple[str, Path] | None:
    """--ssh-public-key as (key line, file): read and checked before anything is written. Which key types are allowed
    depends on FIPS mode, which is only final after the options step, so _choose_ssh_key checks it there."""
    if not args.ssh_public_key:
        if args.ssh_private_key:
            ui.warn("--ssh-private-key is only used together with --ssh-public-key; ignoring it.")
        return None
    pub = Path(args.ssh_public_key).expanduser()
    return netutil.read_public_key(pub), pub


def _choose_ssh_key(cloud: clouds.Cloud, env: paths.Env, cfg: dict, existing: dict, user_key, private_key) -> bool:
    """Pick the environment's SSH key now that FIPS mode is final (prompt answer, --var or saved): a key made earlier
    could be ed25519 in a FIPS environment, whose hardened sshd then locks everyone out.
    - --ssh-public-key: used as given (refused if FIPS mode cannot use it);
    - a saved key: kept; a generated key of a never-deployed environment is replaced when it does not suit the mode;
    - FIPS mode itself cannot change on a deployed environment (every host image and the key type would change).
    Returns True when a key must be generated (_generate_ssh_key, called once every other check has passed)."""
    fips = bool(cfg["vars"].get("fips_mode"))
    deployed = bool(existing) and _env_has_resources(env)
    was_fips = _lenient_bool((existing.get("vars") or {}).get("fips_mode", False), False)
    if existing and deployed and fips != was_fips:
        raise ui.Abort(f"FIPS mode cannot be turned {'on' if fips else 'off'} for {env.id}: it is chosen when an "
                       "environment is created (it changes every host image and the SSH key type, so every host would "
                       f"be replaced). Create a new environment with --var fips_mode={'true' if fips else 'false'}, "
                       f"or destroy {env.id} first.")
    if user_key:
        text, pub = user_key
        problem = _key_problem(text, fips, cloud.key)
        if problem:
            raise ui.Abort(f"--ssh-public-key {pub}: {problem}.")
        priv, warning = netutil.private_key_for(pub, private_key)
        if warning:
            ui.warn(warning)
        cfg["ssh_public_key"], cfg["ssh_private_key_path"] = text, priv
        return False
    saved = existing.get("ssh_public_key")
    if saved:
        # generated by cloudseed: no private-key path of the user's, and the pair is in ssh/ (a user key given without
        # a private-key path is not one, and is never replaced)
        generated = not existing.get("ssh_private_key_path") and \
            any(text == str(saved).strip() for _, _, text in _generated_pairs(env))
        native = fips or _key_algo(saved) == "ssh-ed25519"        # what setup would generate for this mode
        if _key_problem(saved, fips, cloud.key) is None and (native or not generated or deployed):
            cfg["ssh_public_key"] = saved
            return False
        if deployed and _key_problem(saved, fips) is None:
            # the cloud accepted this key when the environment was deployed: only a FIPS problem (checked without the
            # cloud's own key-type rules, where _key_problem has them) stops setup, never a replacement that would
            # lock the user out
            cfg["ssh_public_key"] = saved
            return False
        if not generated or deployed:
            raise ui.Abort(f"The SSH key of {env.id} cannot be used here: {_key_problem(saved, fips, cloud.key)}. Pass a "
                           "suitable key with --ssh-public-key" +
                           (", or create a new environment with --var fips_mode=true." if fips else "."))
        ui.info(f"{env.id} was never deployed: its {_key_algo(saved)} key does not suit "
                f"{'FIPS' if fips else 'non-FIPS'} mode, so it gets a new one.")
    cfg.pop("ssh_public_key", None)
    return True


def _generate_ssh_key(cloud: clouds.Cloud, env: paths.Env, cfg: dict, scratch: Path | None = None) -> None:
    """Generate the environment's key pair for its (final) FIPS mode. A pair in ssh/ that does not suit the mode (left
    by an aborted setup, or the never-deployed key being replaced) is renamed out of the way: never reused, never
    deleted. `scratch`: a dry run of an existing environment generates there and leaves ssh/ untouched."""
    fips = bool(cfg["vars"].get("fips_mode"))
    if scratch is None:
        for priv, pub, text in _generated_pairs(env):
            algo = _key_algo(text)
            if not algo or _key_problem(text, fips, cloud.key) or (not fips and algo != "ssh-ed25519"):
                _set_aside([priv, pub])
    else:
        shutil.rmtree(scratch, ignore_errors=True)
    _, pub = netutil.ensure_ssh_key(scratch or env.ssh_dir, f"cloudseed-{env.id}", fips=fips, cloud=cloud.key)
    cfg["ssh_public_key"] = netutil.read_public_key(pub)
    cfg["ssh_private_key_path"] = None
    problem = _key_problem(cfg["ssh_public_key"], fips, cloud.key)
    if problem:     # defence in depth: never save a FIPS environment with a key its hosts will refuse
        raise ui.Abort(f"The generated SSH key cannot be used: {problem}.")


# ---------------------------------------------------------------- commands

def cmd_setup(args, settings) -> int:
    cloud = clouds.get(args.cloud)
    if not ui.interactive():
        ui.header(f"cloudseed · {cloud.display}")
    total = 4 if cloud.local else 5
    ui.step(1, total, "Environment", "name, working directory, infrastructure name")
    env_name = args.env or ui.ask("Environment name", "dev", validate=_validate_name)
    problem = _validate_name(env_name)
    if problem:
        raise ui.Abort(f"--env {env_name!r}: {problem}")
    given = _parse_setup_vars(cloud, args.var)          # every --var is typed and checked before anything is written
    _check_setup_flags(cloud, args, given)              # so are the other flags: the CLI, MCP and the web wizard alike
    _check_not_an_id(cloud, env_name)
    env, new_workdir = _setup_env(cloud, env_name, args)
    _hold_env_lock(env, f"setup {cloud.key} --env {env.name}")   # before anything is read or written (paths.Env.lock)
    fresh = not env.exists()
    dir_existed, before = env.dir.exists(), _artifact_listing(env)
    # what a directory the user chose already held: `destroy --purge` later removes only what cloudseed added
    preexisting = _dir_entries(env.dir) if fresh and new_workdir is not None else None
    if preexisting:
        ui.info(f"{env.dir} already holds {len(preexisting)} item(s) ({', '.join(preexisting[:5])}"
                f"{' …' if len(preexisting) > 5 else ''}); cloudseed adds its files next to them, and "
                "`destroy --purge` later removes only cloudseed's.")
    env.create_dirs()
    audit.attach(env)
    # --preview: a plan that saves nothing (the MCP tool and the console plan without applying). It is a --plan-only
    # whose configuration is put back afterwards: an existing environment keeps its previous one, a new one is not
    # created at all, so a later `apply` can never apply what was only previewed.
    preview_only = bool(getattr(args, "preview", False)) and not args.dry_run
    if preview_only:
        args.plan_only = True
    try:
        rc = _setup(args, cloud, env, env_name, given, new_workdir, preexisting, workdir_created=not dir_existed)
    except BaseException:
        if fresh and (preview_only or not env.exists()):
            _forget_new_env(env, dir_existed, before, new_workdir)
        raise
    if fresh and preview_only:
        _forget_new_env(env, dir_existed, before, new_workdir)
        ui.info(f"Nothing was saved: {env.id} was only previewed. To create it, run the same command without --preview.")
    return rc


def _forget_new_env(env: paths.Env, dir_existed: bool, before: dict, new_workdir: Path | None) -> None:
    """Take back everything a first setup of `env` wrote (a failed one, or a --preview): its configuration, its
    working directory claim and cloudseed's files in the directory (the directory itself when setup created it)."""
    try:
        env.config_path.unlink(missing_ok=True)
        if new_workdir is not None:
            index = paths._load_index()
            if index.pop(env.id, None) is not None:
                paths._save_index(index)
    except OSError:
        pass
    _discard_failed_setup(env, dir_existed, before)


def _check_not_an_id(cloud: clouds.Cloud, env_name: str) -> None:
    """`--env gcp-dev` where gcp-dev is the id (cloud + name) of an existing environment, as `cs list` shows it: that
    creates a second, billable environment gcp-gcp-dev, which is rarely what anyone copying the id meant."""
    if not env_name.startswith(cloud.key + "-") or paths.Env(cloud.key, env_name).exists():
        return
    other = paths.Env(cloud.key, env_name[len(cloud.key) + 1:])
    if not other.exists():
        return
    msg = (f"--env {env_name} is the id of the existing environment {other.id} (cloud {cloud.key}, name {other.name}); "
           f"to change it: cloudseed setup {cloud.key} --env {other.name}")
    if not ui.interactive():
        raise ui.Abort(msg + f". A new environment named {env_name} would be {cloud.key}-{env_name}; choose another name.",
                       code=2)
    ui.warn(msg + ".")
    if not ui.confirm(f"Create a new environment {cloud.key}-{env_name} anyway?", default=False):
        raise ui.Abort("Cancelled. Nothing was changed.", code=0)


def _dir_entries(d: Path) -> list[str]:
    try:
        return sorted(p.name for p in d.iterdir() if p.name != ".DS_Store")
    except OSError:
        return []


def _check_setup_flags(cloud: clouds.Cloud, args, given: dict | None = None) -> None:
    """Refuse bad flag values before any directory is created or anything is asked; the later checks (prompts, saved
    values) stay in place for everything that did not come from a flag."""
    if args.name is not None:
        problem = _validate_name(args.name)
        if problem:
            raise ui.Abort(f"--name {args.name!r}: {problem}")
    # a cloud-specific flag given for another cloud (--zone on aws ...) would otherwise be dropped without a word
    mine = {q.key for q in cloud.questions}
    foreign = [k for k in clouds.Question.FLAG_KEYS if getattr(args, k, None) not in (None, "") and k not in mine]
    if foreign:
        owners = {k: [c.key for c in clouds.CLOUDS.values() if k in {q.key for q in c.questions}] for k in foreign}
        ui.warn("Ignoring " + ", ".join(f"--{k.replace('_', '-')} (for {' and '.join(owners[k]) or 'another cloud'})"
                                        for k in foreign) + f": {'they do' if len(foreign) > 1 else 'it does'} not apply to {cloud.key}.")
    # the answers of the dedicated flags (--subscription-id, --project-id, --zone, the login names ...) and their --var
    # form, by the adapter's own rule (an Azure subscription ID is a GUID): a typo is refused now, not after the name,
    # network and allow-list questions. A zone waits for the final region unless --region came with it.
    view = {"region": _normalize_region(cloud, args.region) if getattr(args, "region", None) else "", "vars": {}}
    for q in cloud.questions:
        if q.key not in clouds.Question.FLAG_KEYS or (q.key == "zone" and not view["region"]):
            continue
        for source, raw in ((f"{q.flag} ", getattr(args, q.key, None)),
                            (f"--var {q.key}=", ((given or {}).get("answers") or {}).get(q.key))):
            if raw in (None, "") or (isinstance(raw, str) and not raw.strip()):
                continue
            try:
                value = _coerce_answer(q, raw)
                problem = cloud.answer_problem(q, value, view)
            except ValueError as e:
                problem = str(e)
            if problem:
                raise ui.Abort(f"{source}{raw}: {problem}")
    if cloud.local:
        ignored = [flag for flag, given in (("--region", args.region), ("--allow-ip", args.allow_ip)) if given]
        if ignored:
            ui.warn(f"{' and '.join(ignored)} {'do' if len(ignored) > 1 else 'does'} not apply to {cloud.key} (the VMs run on "
                    f"this machine, on a private network only it reaches); ignoring {'them' if len(ignored) > 1 else 'it'}.")
    else:
        if args.region:
            problem = _setup_region_problem(cloud, args.region)
            if problem:
                raise ui.Abort(f"--region: {problem}")
        flag = [x.strip() for item in (args.allow_ip or []) for x in item.split(",") if x.strip()]
        problem = _allow_list_problem(flag) if flag else None     # (an empty --allow-ip means: detect it)
        if problem:
            raise ui.Abort(f"--allow-ip: {problem}")
    if args.cidr is not None:
        problem = _cidr_problem(args.cidr)
        if problem:
            raise ui.Abort(f"--cidr: {problem}")
    for k, v in _parse_kv(args.tag).items():
        problem = cloud.tag_problem(str(k), str(v))
        if problem:
            raise ui.Abort(f"--tag {k}={v}: {problem}")


def _effective_tags(tags) -> dict:
    """The --tag values as Cloud.tags() applies them: keys are case-insensitive (a later spelling replaces an earlier
    one) and an emptied tag (KEY=) removes the key in every spelling. What is left is exactly what gets rendered."""
    out: dict = {}
    for k, v in (tags or {}).items():
        low = str(k).strip().lower()
        for old in [x for x in out if str(x).strip().lower() == low]:
            out.pop(old)
        if v not in (None, ""):
            out[k] = v
    return out


def _saved_tags(cloud: clouds.Cloud, existing: dict) -> dict:
    """The saved --tag values as they apply (_effective_tags: emptied ones and older spellings of a key are gone),
    minus any the cloud refuses (saved by an older version that did not check them): kept, such a tag would block
    every later setup, and no flag could remove it."""
    out = {}
    for k, v in _effective_tags(existing.get("tags")).items():
        problem = cloud.tag_problem(str(k), str(v))
        if problem:
            ui.warn(f"Dropping the saved tag {k}={v} ({problem}); add a valid one with --tag KEY=VALUE.")
        else:
            out[k] = v
    return out


def _merge_tags(saved: dict, new: dict) -> dict:
    """This run's --tag values over the saved ones. A new key replaces a saved one in any spelling (--tag Team=b after a
    saved team=a: tag keys are case-insensitive in the clouds), and KEY= removes it; nothing empty is saved. Two
    spellings given in the same run stay as given, so tags_problems refuses them."""
    lows = {str(k).strip().lower() for k in new}
    out = {k: v for k, v in saved.items() if str(k).strip().lower() not in lows}
    out.update({k: v for k, v in new.items() if v not in (None, "")})
    return out


def _setup(args, cloud: clouds.Cloud, env: paths.Env, env_name: str, given: dict, new_workdir: Path | None,
           preexisting: list[str] | None = None, workdir_created: bool = True) -> int:
    total = 4 if cloud.local else 5
    existing = copy.deepcopy(env.load()) if env.exists() else {}
    _check_owner(env, existing)
    if existing:
        ui.info(f"Existing environment {env.id} found; its values are offered as defaults.")
    ui.kv("Working directory", str(env.dir))
    deployed = bool(existing) and _env_has_resources(env)
    saved_extra, legacy = _saved_extra_vars(cloud, existing, set(given["extra"]) | set(given["unset"]))

    cfg: dict = {k: v for k, v in existing.items()}
    cfg["cloud"] = cloud.key
    cfg["env"] = env_name
    name = args.name or ui.ask("Infrastructure name (prefix + Project tag on every resource)",
                               existing.get("name") or "cloudseed", validate=_validate_name, flag="--name")
    problem = _validate_name(name)
    if problem:
        raise ui.Abort(f"Infrastructure name {name!r}: {problem} (flag: --name)")
    cfg["name"] = name
    if deployed and existing.get("name") and existing["name"] != name:
        _check_rename(args, cloud, env, existing["name"], name)
    cfg["owner"] = existing.get("owner") or netutil.local_username()
    if not cfg.get("uid") and not deployed:
        # this environment's own identity: resources are tagged with it (CloudseedEnvId), so a teammate's environment
        # with the same name and env never adopts them (reconcile.ownership). Kept for the environment's lifetime.
        cfg["uid"] = uuid.uuid4().hex[:16]
    ui.step(2, total, "Location and network", "region and address space" if not cloud.local else "private network")
    if cloud.local:
        cfg["region"] = "local"
    else:
        if args.region:
            problem = _setup_region_problem(cloud, args.region)
            if problem:
                raise ui.Abort(f"--region: {problem}")
            region = args.region
        else:
            region = ui.ask(cloud.region_prompt,
                            existing.get("region") or _env_default(cloud.region_env) or cloud.default_region,
                            required=True, flag="--region", validate=lambda s: _setup_region_problem(cloud, s))
        cfg["region"] = _normalize_region(cloud, region)
        old = existing.get("region")
        if old and _normalize_region(cloud, old) != cfg["region"] and deployed:
            raise ui.Abort(f"{env.id} already has resources in {old}; the region of an existing environment cannot be "
                           f"changed in place (existing resources stay in {old} and the environment would end up half "
                           f"moved and broken). Create a new environment: cloudseed setup {cloud.key} --env <new-name> "
                           f"--region {cfg['region']}, or tear this one down first: cloudseed destroy {cloud.key} --env {env.name}")

    cfg["network_cidr"], explicit_cidr = _setup_network(args, cloud, env, existing, given, legacy, deployed)
    if cloud.local:     # an explicit CIDR gets a dedicated vmnet; otherwise prepare() adopts VMware's host-only one
        cfg["cidr_explicit"] = explicit_cidr or bool(existing.get("cidr_explicit"))

    prev_state = (existing.get("state") or {}).get("type")
    if not cloud.local:
        ui.step(3, total, "Terraform state", "where cloudseed keeps the record of what it created")
    if cloud.local:
        if args.state == "remote":
            ui.warn("Local virtualization keeps Terraform state on this machine; ignoring --state remote.")
        state_type = "local"
        ui.info(f"Terraform state: local  ({env.stack_dir / 'terraform.tfstate'})")
    else:
        state_type = args.state or ui.choose("Where should Terraform state live?", [
            ("remote", "Remote: a hardened, versioned bucket cloudseed creates in your cloud account (recommended)"),
            ("local", f"Local: {env.stack_dir}/terraform.tfstate"),
        ], default=prev_state or "remote")
    keep_backend = (existing.get("state") or {}).get("backend") if prev_state == state_type else None
    if prev_state and prev_state != state_type:
        ui.warn(f"State location changes from {prev_state} to {state_type}; existing state will be migrated.")
    cfg["state"] = {"type": state_type, "backend": keep_backend}

    ui.step(3 if cloud.local else 4, total, "Access", "who may SSH to the bastion, and with which key")
    user_key = _read_user_key(args)
    if cloud.local:
        cfg["allowed_ssh_cidrs"] = ["127.0.0.1/32"]  # VMs are only reachable from this machine
    else:
        cfg["allowed_ssh_cidrs"] = _setup_allow_list(args, cloud, env, existing, given, legacy)
    if not user_key and not existing.get("ssh_public_key"):
        ui.info("SSH key: generated once the options are known (FIPS mode needs a FIPS-approved key type).")

    cfg["tags"] = _merge_tags(_saved_tags(cloud, existing), _parse_kv(args.tag))
    cfg["workdir"] = str(env.dir)
    ui.step(total, total, f"{cloud.display} options", "answer or press Enter for the recommended defaults")
    answers = _flag_answers(cloud, args, given)
    saved_answers = _saved_answers(cloud, existing, legacy, given, cfg, set(answers))
    cfg["vars"] = cloud.collect_vars(args, saved_answers, cfg, args.advanced, overrides=given["answers"])
    _check_answers(cloud, env, cfg)
    extra = {**saved_extra, **given["extra"]}
    for key in given["unset"]:
        extra.pop(key, None)
    cfg["extra_vars"] = extra
    # the adapter's own normalization and checks on the final answers (GCP zone/project/CIDRs, AWS EKS vs az_count
    # and node bounds), before anything is saved or a key is generated
    cloud.check_vars(cfg)
    _check_extra_vars(cloud, cfg["extra_vars"])
    if deployed:    # the account / zone of what exists: like the region, not something a re-run can move
        _check_in_place(cloud, env, existing, cfg)
    new_key = _choose_ssh_key(cloud, env, cfg, existing, user_key, args.ssh_private_key)
    problems = _config_problems(cloud, cfg)
    if problems:
        raise ui.Abort("This configuration cannot be deployed:\n  - " + "\n  - ".join(problems))
    # a run that cannot apply (a dry run, a plan, or -y without --auto-approve and no terminal) only warns about what
    # provisioning will need later; a real apply refuses before the first resource exists
    applying = not (args.dry_run or args.plan_only or (not args.auto_approve and not ui.interactive()))
    plan_preview = bool(getattr(args, "preview", False)) and not args.dry_run     # setup --preview (cmd_setup)
    _check_fips(cloud, cfg, applying=applying)
    _check_tailscale_key(args, cloud, cfg, applying)
    if new_key:     # only once every check passed, so a refused run leaves no key behind
        _generate_ssh_key(cloud, env, cfg, scratch=env.dir / "dry-run" / "ssh" if args.dry_run and existing else None)

    if args.dry_run and existing:
        if new_workdir is not None:
            # --workdir names a directory that already holds this environment's configuration, but cloudseed does not
            # know it (copied back from a purge's undo copy, or moved by hand): register it; config.json stays as it is
            env.set_workdir(new_workdir)
            ui.ok(f"Registered {env.dir} as the working directory of {env.id}.")
        ui.info(f"Dry run: the saved configuration of {env.id} is not changed.")
    else:
        if new_workdir is not None:
            env.set_workdir(new_workdir)
            # what the directory held before ([] = nothing: cloudseed created it, or it was empty), and whether cloudseed
            # created it: with this record `destroy --purge` removes only cloudseed's entries from any --workdir (the
            # user may have added files since), and the directory itself only when nothing else is left in it
            cfg["workdir_preexisting"] = list(preexisting or [])
            cfg["workdir_created"] = bool(workdir_created)
        env.save(cfg)
        if plan_preview:    # (put back once the plan is shown: cmd_setup / the plan-only branch below)
            ui.info("Planning with this configuration (--preview: nothing is kept afterwards).")
        else:
            ui.ok(f"Configuration saved: {env.config_path}")

    if args.dry_run:
        _print_summary(cloud, env, cfg, network_resolved=_vmnet_resolved(cfg, existing))
        for w in cloud.credential_warnings(cfg):
            ui.warn(w)
        return _setup_dry_run(cloud, env, cfg, in_place=not existing)

    if existing:
        cancelled = f"Cancelled. Nothing was applied; {env.id} keeps its previous configuration."
        unconfirmed = (f"Nothing applied (no terminal to confirm the plan); {env.id} keeps its previous configuration. "
                       "Re-run with --auto-approve to apply it.")
    else:
        cancelled = (f"Cancelled. Nothing was applied; the configuration is saved in {env.config_path}. "
                     f"Apply it later with: cloudseed apply {cloud.key} --env {env.name}")
        unconfirmed = ("Nothing applied (no terminal to confirm the plan). Re-run with --auto-approve, or later: "
                       f"cloudseed apply {cloud.key} --env {env.name} --auto-approve")
    if existing:    # the previous configuration is put back, so only the same command applies what was planned
        unconfirmed_preview = (f"Nothing applied (no terminal to confirm the plans above); {env.id} keeps its previous "
                               "configuration. Re-run the same command with --auto-approve: setup then creates the "
                               "remote state storage and applies the stack as planned.")
    else:
        unconfirmed_preview = ("Nothing applied (no terminal to confirm the plans above). With --auto-approve, setup "
                               "creates the remote state storage and then applies the stack as planned: "
                               f"cloudseed setup {cloud.key} --env {env.name} -y --auto-approve")
    try:
        cloud.prepare(cfg)
        if cloud.local:     # the host-only vmnet prepare() adopted must hold every VM too (the adapter's address
            # plan first - /29 minimum, statics below VMware's DHCP pool - as in _config_problems)
            problems = _network_problems(cloud, cfg)
            if problems:
                raise ui.Abort("This configuration cannot be deployed:\n  - " + "\n  - ".join(problems))
        env.save(cfg)
        _print_summary(cloud, env, cfg)
        for w in cloud.credential_warnings(cfg):
            ui.warn(w)
        needs_bootstrap = _pending_backend(cloud, cfg)
        # a run that cannot apply (--plan-only, or -y without --auto-approve) plans the state storage and the stack
        # without creating anything, so the whole change can be reviewed before the first resource exists
        preview = needs_bootstrap and (args.plan_only or (not args.auto_approve and not ui.interactive()))
        if needs_bootstrap:
            backend = _bootstrap_state(cloud, env, cfg, args.auto_approve, preview=preview,
                                       cancelled=cancelled, nothing_applied=unconfirmed)
            if backend:
                cfg["state"]["backend"] = backend
                env.save(cfg)
        ui.header("Planning the stack" + ("  (preview: local state until the storage above exists)" if preview else ""))
        migrate = _render(cloud, env, cfg)
        t = Terraform(env.stack_dir)
        t.init(migrate=migrate)
        before = set(t.state_list())
        first_pending = _first_apply_pending(env)
        if args.plan_only or preview:   # a plan only: nothing is adopted into the (possibly temporary local) state
            t.plan("tfplan")
        else:                           # adopts known singletons first, so the plan shown is the plan applied
            _plan_for_apply(cloud, env, cfg, t)
        if args.plan_only:
            # a saved plan holds the whole configuration and prior state, and nothing ever applies it: `apply` and a
            # later `setup` plan again
            (env.stack_dir / "tfplan").unlink(missing_ok=True)
            renamed = f" It renames the infrastructure {existing['name']} -> {cfg['name']} (resources are replaced)." \
                if deployed and existing.get("name") not in (None, cfg["name"]) else ""
            if plan_preview:
                if existing:        # the previous configuration comes back: only the same command applies this change
                    _restore_config(cloud, env, existing, cfg)
                    _release_os_login(cloud, env, cfg, env.load())
                    ui.ok(f"Plan complete (not applied); {env.id} keeps its previous configuration. To apply this "
                          f"change, run the same command without --preview.{renamed}")
                else:               # cmd_setup takes the new environment back
                    _release_os_login(cloud, env, cfg, None)
                    ui.ok("Plan complete (not applied).")
            elif preview:
                ui.ok("Plan complete (not applied). Applying creates the remote state storage planned above first, "
                      f"then this stack: cloudseed setup {cloud.key} --env {env.name} --auto-approve "
                      f"(or: cloudseed apply {cloud.key} --env {env.name}){renamed}")
            else:
                ui.ok("Plan complete (not applied). Apply later with: cloudseed apply " + f"{cloud.key} --env {env.name}{renamed}")
            return 0
        if preview:
            (env.stack_dir / "tfplan").unlink(missing_ok=True)
            raise ui.Abort(unconfirmed_preview, code=3)
        noop = _plan_is_noop(t)
        # what a deployed local environment's plan does to its VMs: re-created ones lose their disks, and node VMs of a
        # lower kubernetes_workers / kubernetes_control_planes leave the cluster before they go (after the approval)
        leaving = _local_vm_plan(cloud, env, cfg, t) if cloud.local and deployed and not noop else []
        keep = [] if noop or not deployed else _kept_deletes(cloud, existing or cfg, t)
        if keep:
            ui.warn("Kept in place instead of deleted (account/subscription/project-wide, only dropped from the "
                    "state): " + _kept_types(keep))
        if noop and not args.auto_approve and not ui.interactive():
            # nothing to apply; re-provisioning the hosts still changes them, so it waits for --auto-approve
            (env.stack_dir / "tfplan").unlink(missing_ok=True)
            pending = _changed_settings(existing, cfg) if existing else []
            if pending:     # settings only provisioning applies: saving them unapplied would misreport the hosts
                raise ui.Abort(f"No infrastructure changes, but the changed settings ({', '.join(pending)}) take effect "
                               f"only when the hosts are provisioned. Nothing was applied; {env.id} keeps its previous "
                               "configuration. Re-run with --auto-approve to apply them.", code=3)
            ui.ok(f"No infrastructure changes: {env.id} matches its configuration. Hosts were not re-provisioned "
                  f"(cloudseed provision {cloud.key} --env {env.name}, or re-run with --auto-approve).")
            return 0
        if not noop:
            _approve("Apply this plan?", args.auto_approve, cancelled=cancelled, nothing_applied=unconfirmed)
            _leave_deleted_nodes(cloud, env, existing or cfg, leaving)
            _forget_kept_for_apply(env, cfg, t, keep)
    except (ui.Abort, TerraformError, KeyboardInterrupt):
        if existing:
            _restore_config(cloud, env, existing, cfg)
            try:        # a key this run registered for OS Login that the restored configuration does not use
                _release_os_login(cloud, env, cfg, env.load())
            except Exception:  # noqa: BLE001 - never hide the reason setup stopped
                pass
        raise
    if noop:
        ui.ok(f"No infrastructure changes: {env.id} matches its configuration.")
    else:
        try:
            t.apply_reconciled(cloud.key, cfg, approve=lambda q: _approve(q, args.auto_approve))
        except TerraformError:
            audit.refresh(env, t, "apply-failed")
            raise
    (env.stack_dir / "tfplan").unlink(missing_ok=True)
    _settle_kept(env, cfg, t)
    _finish(cloud, env, cfg, t, explain_missing_ip=args.no_provision)
    if existing:    # an OS Login key the previous configuration used and this one no longer does (rotated, or turned off)
        _release_os_login(cloud, env, existing, cfg)
    if (not before and not deployed) or first_pending:
        # nothing existed before this apply (a dry run, a plan or a full destroy came first), or only the debris of a
        # failed first apply: undoing it must remove everything
        undo.record(env.id, f"setup {env.id} (created)", "created")
    elif existing:
        # the whole configuration minus bookkeeping: a key rotation or a vmware --cidr counts, a converging re-run with
        # nothing changed leaves no entry (as `apply`): it must not push real undo points - 'setup (created)' - out
        changed = _changed_settings(existing, cfg)
        if changed:
            undo.record(env.id, f"setup {env.id} (changed: {', '.join(changed)})", "config",
                        {"prev_cfg": existing, "what": ", ".join(changed), "rejoin_nodes": True})
    else:
        undo.record(env.id, f"setup {env.id} (existing resources adopted)", "info",
                    {"advice": "the stack already held resources before this setup; revert by hand (cloudseed destroy / apply)"})
    if not args.no_provision:
        _provision_all(cloud, env, cfg, harden=not args.no_harden, firewall=not args.no_firewall, tools=not args.no_tools)
    return 0


# config.json keys that record when and how, not what: a change in them alone is no change to undo
_SETUP_BOOKKEEPING = {"updated_at", "created_at", "provisioned", "workdir_preexisting", "workdir_created", "uid", "owner",
                      "os_login", "kept_shared"}


# configuration keys that hold stack variables: a change in them is named by the variables that changed
_VARIABLE_KEYS = ("vars", "extra_vars")


def _changed_settings(existing: dict, cfg: dict) -> list[str]:
    """The settings a setup run changes, bookkeeping left out: configuration keys, and for the stack variables (vars,
    extra_vars) the names of the variables that changed (workload_count, not "vars"), which the undo entry and its
    description show. Tags compare as they apply: dropping an emptied or superseded saved entry changes nothing that
    is rendered."""
    def value(c: dict, k: str):
        return _effective_tags(c.get(k)) if k == "tags" else c.get(k)
    changed: set[str] = set()
    for k in set(existing) | set(cfg):
        a, b = value(existing, k), value(cfg, k)
        if k in _SETUP_BOOKKEEPING or _same_setting(a, b):
            continue
        if k in _VARIABLE_KEYS and isinstance(a or {}, dict) and isinstance(b or {}, dict):
            a, b = a or {}, b or {}
            changed.update(v for v in set(a) | set(b) if not _same_setting(a.get(v), b.get(v)))
            continue            # (only unset values that compare differently: no change)
        changed.add(k)
    return sorted(changed)


def _same_setting(a, b) -> bool:
    """Equal, or both unset (a key an older version never wrote, and its empty/false value now; 0 is a value)."""
    def unset(v) -> bool:
        return v is None or v is False or (isinstance(v, (str, list, dict)) and not v)
    return a == b or (unset(a) and unset(b))


def _check_rename(args, cloud: clouds.Cloud, env: paths.Env, old: str, new: str) -> None:
    """--name on a deployed environment. The name prefixes every resource (and sets the Project tag), so Terraform
    replaces most of them - on AWS the CloudTrail bucket with its logs, on Azure the whole resource group. Unlike a
    region change it converges, so it is allowed, but never unnoticed: always a warning, a terminal asks (default No),
    and an unattended apply (-y --auto-approve without a terminal, e.g. an agent) is refused: review the plan first
    (--plan-only), then apply it with `cloudseed apply`."""
    what = {"aws": "the bastion, security groups, IAM roles, the KMS alias, log groups and the CloudTrail bucket with the "
                   "logs in it (the VPC, subnets and NAT only get new tags)",
            "gcp": "every resource", "azure": "the resource group and everything in it", "vmware": "every VM"}.get(
        cloud.key, "most resources")
    ui.warn(f"The infrastructure name of {env.id} changes from {old} to {new}: resources are named {new}-{env.name}-..., "
            f"so Terraform replaces {what}. To keep them, re-run with --name {old}.")
    if args.dry_run or args.plan_only:
        return
    if ui.interactive():
        if not ui.confirm(f"Rename {env.id} and replace those resources?", default=False):
            raise ui.Abort(f"Cancelled. Nothing was changed; {env.id} keeps the name {old}.", code=0)
    elif args.auto_approve:
        raise ui.Abort(f"Not renaming {env.id} unattended: it replaces {what}. Review the plan first: cloudseed setup "
                       f"{cloud.key} --env {env.name} --name {new} --plan-only, then apply it: cloudseed apply {cloud.key} "
                       f"--env {env.name} --auto-approve   (or keep the name: --name {old})", code=2)


# the setting that picks the account/project an environment lives in (the region is guarded the same way in _setup)
_ACCOUNT_KEYS = {"gcp": ("project_id", "project", "--project-id"), "azure": ("subscription_id", "subscription", "--subscription-id")}


def _check_in_place(cloud: clouds.Cloud, env: paths.Env, existing: dict, cfg: dict) -> None:
    """Settings a deployed environment cannot change in place, from whichever path they came (flag, --var, prompt,
    MCP, the console): its GCP project or Azure subscription (the resources stay in the old one, new ones land in the
    other: a half-moved, broken environment), and the GCP zone of a zonal GKE cluster (replaced with its workloads and
    volumes; without a cluster only the bastion and VPN host are rebuilt, which is only warned about)."""
    old_v, new_v = existing.get("vars") or {}, cfg.get("vars") or {}
    spec = _ACCOUNT_KEYS.get(cloud.key)
    if spec:
        key, what, flag = spec
        old, new = str(old_v.get(key) or "").strip(), str(new_v.get(key) or "").strip()
        if old and new and old.lower() != new.lower():       # Azure subscription GUIDs are case-insensitive
            raise ui.Abort(f"{env.id} already has resources in {what} {old}; the {what} of an existing environment cannot "
                           f"be changed in place (existing resources stay in {old} and the environment would end up half "
                           f"moved and broken). Create a new environment: cloudseed setup {cloud.key} --env <new-name> "
                           f"{flag} {new}, or tear this one down first: cloudseed destroy {cloud.key} --env {env.name}")
    if cloud.key == "gcp":
        from .clouds import gcp as gcpmod
        old, new = str(old_v.get("zone") or ""), str(new_v.get("zone") or "")
        # a saved zone that never existed or left the region is repaired by the adapter: never block that repair
        broken = old in gcpmod._MISSING_ZONES or not gcpmod.zone_in_region(old, cfg.get("region"))
        if old and new and old != new and not broken:
            if _lenient_bool(old_v.get("enable_kubernetes"), False) or _has_cluster(env):
                raise ui.Abort(f"{env.id} has a zonal GKE cluster in {old}; moving it to {new} deletes and re-creates the "
                               "cluster (its workloads and volumes are lost), the bastion and the VPN host. Keep --zone "
                               f"{old}, or create a new environment: cloudseed setup gcp --env <new-name> --zone {new}")
            ui.warn(f"The zone of {env.id} changes from {old} to {new}: Terraform re-creates the bastion (and the VPN host) "
                    f"there, with new SSH host keys. To keep them, re-run with --zone {old}.")


def _check_tailscale_key(args, cloud: clouds.Cloud, cfg: dict, applying: bool) -> None:
    """vpn_type=tailscale needs TS_AUTHKEY when the VPN host is provisioned: say so before anything is created, not
    after the whole stack (and a billable VPN VM) was applied. A dry run or plan only warns; --no-provision skips it
    (`cloudseed provision` checks it again)."""
    v = cfg.get("vars") or {}
    if cloud.local or not v.get("enable_vpn") or v.get("vpn_type", "openvpn") != "tailscale" or \
            os.environ.get("TS_AUTHKEY") or getattr(args, "no_provision", False):
        return
    msg = ("vpn_type=tailscale needs a tailnet auth key to provision the VPN host: export TS_AUTHKEY=tskey-auth-... "
           "(or store it: cloudseed creds set TS_AUTHKEY) - https://login.tailscale.com/admin/settings/keys, "
           "reusable + pre-authorized")
    if applying:
        raise ui.Abort(msg + ". Nothing was created. (To apply without provisioning the hosts: --no-provision.)")
    ui.warn(msg + "; the real setup refuses without it.")


def _setup_dry_run(cloud: clouds.Cloud, env: paths.Env, cfg: dict, in_place: bool) -> int:
    """Render and `terraform validate` the roots. A new environment is rendered in place; an existing one into
    <workdir>/dry-run, so its saved configuration and the roots other commands use stay exactly as they were."""
    cloud.prepare(cfg, dry_run=True)
    roots = [("stack", cloud.render_stack(cfg, paths.tf_root()))]
    if _pending_backend(cloud, cfg):    # only what setup would create: no bootstrap for local state or an existing backend
        roots.append(("bootstrap", cloud.render_bootstrap(cfg, paths.tf_root())))
    base = None if in_place else env.dir / "dry-run"
    dirs = {"stack": env.stack_dir, "bootstrap": env.bootstrap_dir} if in_place else \
        {name: base / name for name, _ in roots}
    try:
        for name, root in reversed(roots):
            _write_root(dirs[name], root)
            t = Terraform(dirs[name])
            t.init(backend=False)
            t.validate()
    finally:
        if base is not None:    # keep the rendered main.tf.json for review, not provider downloads or a scratch key
            shutil.rmtree(base / "ssh", ignore_errors=True)
            for name, _ in roots:
                shutil.rmtree(dirs[name] / ".terraform", ignore_errors=True)
                (dirs[name] / ".terraform.lock.hcl").unlink(missing_ok=True)
                (dirs[name] / ".cloudseed-platform").unlink(missing_ok=True)
    rendered = ", ".join(str(dirs[name]) for name, _ in roots)
    ui.ok(f"Dry run complete. Rendered root(s): {rendered}" +
          ("" if in_place else f"  ({env.id} itself is unchanged)"))
    return 0


def _restore_config(cloud: clouds.Cloud, env: paths.Env, existing: dict, cfg: dict) -> None:
    """Put the previous configuration back when setup stops before applying (declined, unconfirmed or failed plan),
    so a later `cloudseed apply` cannot apply a change that was only previewed or refused. The state location stays
    as it is now when this run may have created the state storage or migrated the state; a switch to remote state
    whose storage was never created (declined, unconfirmed or preview only) is taken back too, since the resources
    are still tracked where they were."""
    restored = copy.deepcopy(existing)
    if cfg.get("uid") and not restored.get("uid"):     # the environment's identity, not a setting: it stays
        restored["uid"] = cfg["uid"]
    new_state = cfg.get("state") or {}
    if not (new_state.get("type") == "remote" and not new_state.get("backend")):
        restored["state"] = copy.deepcopy(new_state or restored.get("state"))
    try:
        env.save(restored)
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        _render(cloud, env, restored)
    except Exception as e:  # noqa: BLE001 - never hide the reason setup stopped
        ui.warn(f"Could not fully restore the previous configuration of {env.id}: {e}")


def _release_os_login(cloud: clouds.Cloud, env: paths.Env, old: dict, new: dict | None) -> None:
    """GCP OS Login: remove the key `old` registered once nothing uses it (`new`: the configuration now in effect,
    None after a full destroy - the record is then dropped from the saved configuration, so a later apply registers
    the key again). Never raises: GCP.release_os_login warns with the manual command itself."""
    release = getattr(cloud, "release_os_login", None)
    if release is None or not (old or {}).get("os_login"):
        return
    try:
        removed = release(old, new)
    except Exception as e:  # noqa: BLE001 - a clean-up step must never fail the command that succeeded
        ui.warn(f"OS Login: could not check the SSH key of {env.id} ({e}).")
        return
    if removed and new is None:
        _update_saved(env, lambda saved: saved.pop("os_login", None) is not None)


def _forget_removed_cluster(env: paths.Env, cfg: dict, outputs: dict) -> None:
    """A local cluster whose VMs are gone (provision.forget_removed_cluster): drop its provisioned record from this
    command's configuration and from the saved one."""
    if prov.forget_removed_cluster(cfg, outputs):
        _update_saved(env, lambda saved: prov.forget_removed_cluster(saved, outputs))


def _update_saved(env: paths.Env, change) -> None:
    """Apply `change(saved)` to the saved config.json (not the command's copy, which may hold stand-ins for invalid or
    missing settings) and save it when it returns True."""
    try:
        saved = env.load()
    except Exception:  # noqa: BLE001 - nothing saved (a purge) or unreadable: nothing to update
        return
    if isinstance(saved, dict) and change(saved):
        env.save(saved)


def _settle_kept(env: paths.Env, cfg: dict, t: Terraform) -> None:
    """After a successful apply: forget the kept singletons (reconcile.remember_kept) that are back in the state or
    whose feature is off here now, so a later re-enable never adopts what someone else turned on meanwhile."""
    from . import reconcile
    if not cfg.get("kept_shared"):
        return
    try:
        if reconcile.settle_kept(cfg, t.state_list()):
            env.save(cfg)
    except Exception as e:  # noqa: BLE001 - bookkeeping: the apply itself succeeded
        ui.warn(f"Could not update the record of kept shared settings of {env.id}: {e}")


def _plan_for_apply(cloud: clouds.Cloud, env: paths.Env, cfg: dict, t: Terraform, targets: tuple = (),
                    save: bool = True) -> None:
    """The plan to approve (Terraform.plan_for_apply). When it would create account/subscription-wide singletons that
    already exist and that this environment only has on by default (GuardDuty ...), they are left alone instead of
    stopping the run: the variable that skips each one is saved with the configuration (so later runs and the undo
    of this one agree), the stack is rendered again and planned again (reconcile.SingletonExists.switch_off). One the
    user switched on explicitly still stops the run with the fix. save=False: the caller saves cfg itself once its
    apply worked (node add, cloud prerequisites: a declined or failed run restores the previous configuration)."""
    from . import reconcile
    for attempt in range(3):
        try:
            t.plan_for_apply(cloud.key, cfg, targets=targets)
            return
        except reconcile.SingletonExists as e:
            if not e.auto or attempt == 2:
                raise
            for line in e.switch_off(cfg):
                ui.warn(f"Already on in this {'account' if cloud.key == 'aws' else 'subscription'}, not created by "
                        f"this environment: {line}")
            if save:
                env.save(cfg)
            _render(cloud, env, cfg)


# a node VM of a local cluster: module.stack.module.kubernetes[0].vmdesktop_vm.node["wk2"]
_NODE_VM_ADDR = re.compile(r'vmdesktop_vm\.node\["((?:cp|wk)\d+)"\]$')


def _local_vm_plan(cloud: clouds.Cloud, env: paths.Env, cfg: dict, t: Terraform) -> list[str]:
    """What the saved plan of a deployed local environment does to its VMs, said before the approval: VMs it
    re-creates lose their disks (a changed packages / ssh_username / guest_os / key re-creates them). Returns the node
    keys ('wk3', 'cp2') whose VM it deletes for good (a lower kubernetes_workers / kubernetes_control_planes): they must
    leave the cluster first (_leave_deleted_nodes). A plan that cannot be read: the deployed nodes beyond the configured
    counts. Nothing leaves when the whole cluster goes (enable_kubernetes switched off)."""
    v = cfg.get("vars") or {}
    cluster_stays = _lenient_bool(v.get("enable_kubernetes"), False)
    changes = _plan_changes(t)
    if changes is None:
        if not cluster_stays:
            return []
        outputs, keys = _cached_outputs(env), []
        for role, key, out, default in (("cp", "kubernetes_control_planes", "kubernetes_control_plane_ips", 1),
                                        ("wk", "kubernetes_workers", "kubernetes_worker_ips", 2)):
            try:
                want = int(v.get(key, default))
            except (TypeError, ValueError):
                continue
            keys += [f"{role}{i}" for i in range(want + 1, len(outputs.get(out) or []) + 1)]
        return keys
    gone, rebuilt, deleted = [], [], []
    for c in changes:
        if c.get("type") != "vmdesktop_vm" or "delete" not in c["actions"]:
            continue
        address = str(c.get("address") or "")
        m = _NODE_VM_ADDR.search(address)
        if "create" in c["actions"]:
            rebuilt.append(_short_address(address))
        else:
            deleted.append(_short_address(address))
            if m:
                gone.append(m.group(1))

    def some(names: list[str]) -> str:
        return ", ".join(names[:6]) + (" …" if len(names) > 6 else "")
    if rebuilt:
        ui.warn(f"This plan re-creates {_count(len(rebuilt), 'VM')} ({some(rebuilt)}): their disks are wiped, so anything "
                "added on them by hand is lost (cloudseed provisions them again).")
    if deleted:
        ui.warn(f"This plan deletes {_count(len(deleted), 'VM')} for good ({some(deleted)}), their disks with them.")
    if gone and cluster_stays:
        ui.info(f"This plan deletes the node VM(s) {', '.join(gone)}: once approved, each is drained and taken out of the "
                "cluster first, as `cs node remove` does.")
        return gone
    return []


def _leave_deleted_nodes(cloud: clouds.Cloud, env: paths.Env, cfg: dict, keys: list[str]) -> None:
    """Before an apply deletes node VMs of a local cluster: drain each one and take it out of the cluster (a kubeadm
    control plane's etcd member too), workers first and the highest number first, as `cs node remove` does. A VM
    deleted under a running cluster leaves a NotReady node behind, and a control plane an etcd member that can cost the
    cluster its quorum. A step that fails stops before anything is deleted. `cfg`: the deployed configuration."""
    if not keys:
        return
    if not services.kubeconfig_path(env).exists():
        ui.info("Kubernetes was never installed on these VMs: nothing to drain before they go.")
        return
    outputs = _cached_outputs(env)
    kc = services.ensure_kubeconfig(cloud, env, cfg, outputs)
    kubectl = services.ensure_tool("kubectl", "to take the nodes out of the cluster before their VMs go")
    kenv = dict(services.cloud_cli_env(cloud.key, cfg, outputs), KUBECONFIG=str(kc))
    for key in sorted(keys, key=lambda k: (k.startswith("cp"), -int(k[2:]))):
        name = f"{cfg['name']}-{cfg['env']}-{key}"
        registered = _node_json_or_none(kubectl, kenv, name) is not None
        _leave_local_node(cloud, env, cfg, outputs, kubectl, kenv, name, registered=registered)


def _kept_deletes(cloud: clouds.Cloud, cfg: dict, t: Terraform) -> list[tuple[str, str]]:
    """Account/subscription/project-wide settings the saved plan deletes (e.g. enable_account_baseline switched off:
    the S3 account public-access block, EBS encryption by default, the password policy). Deleting them turns the
    protection off for the whole account, so an apply forgets them instead, as a destroy does (keep_on_destroy)."""
    changes = _plan_changes(t)
    deleting = [c["address"] for c in changes or [] if c["actions"] == ["delete"] and c.get("mode") != "data"]
    return cloud.keep_on_destroy(cfg, deleting) if deleting else []


def _forget_kept_for_apply(env: paths.Env, cfg: dict, t: Terraform, keep) -> None:
    """After the approval: drop `keep` from the state (the objects stay) and plan again without them."""
    if not keep:
        return
    _remember_kept(env, cfg, keep)
    for addr, _ in keep:
        t.run("state", "rm", addr, capture=True)     # a failure stops here: nothing is deleted that must be kept
    t.plan("tfplan")
    ui.info("Left in place (account/subscription/project-wide settings, now unmanaged): " + _kept_types(keep))
    for notice in dict.fromkeys(n for _, n in keep if n):
        ui.info(notice)


def _check_fips(cloud, cfg: dict, *, applying: bool = True) -> None:
    """Everything that goes into a FIPS environment must be FIPS-capable, or setup refuses up front - in every mode, a
    dry run included (that is what it is for). UBUNTU_PRO_TOKEN is not configuration but a secret provisioning needs:
    a run that cannot apply (`applying` False: --dry-run, --plan-only, a preview) only warns about it; `cloudseed
    provision` refuses without it anyway."""
    if not cfg["vars"].get("fips_mode"):
        return
    problems = []
    if cfg["vars"].get("enable_vpn") and cfg["vars"].get("vpn_type", "openvpn") == "tailscale":
        problems.append("vpn_type=tailscale: WireGuard (ChaCha20-Poly1305) is not a FIPS-approved cipher; use vpn_type=openvpn (AES-GCM, TLS 1.2+).")
    if cloud.local:
        if cfg["vars"].get("enable_kubernetes") and cfg["vars"].get("kubernetes_distro", "rke2") != "rke2":
            problems.append("kubernetes_distro=kubeadm: upstream kubeadm binaries are not FIPS builds; use kubernetes_distro=rke2 (FIPS-validated Go crypto).")
        if not str(cfg["vars"].get("guest_os", "ubuntu-24.04")).startswith("ubuntu"):
            problems.append("guest_os: FIPS packages are only available for Ubuntu (Ubuntu Pro); use guest_os=ubuntu-24.04 or ubuntu-22.04.")
    if cloud.key == "gcp":
        image = _gcp_fips_bastion_image(cfg)
        name = image.rsplit("/", 1)[-1].lower()
        if not any(k in name for k in ("ubuntu", "rhel", "rocky", "almalinux", "centos")):
            problems.append(f"bastion_image={image}: FIPS mode needs an Ubuntu (Ubuntu Pro FIPS) or RHEL-family image for "
                            f"the bastion; drop the override (--var bastion_image=null) to boot {scan.GCP_PRO_FIPS_IMAGE}.")
    if cloud.key == "aws" and cfg.get("region") and cfg["region"] not in AWS_FIPS_REGIONS:
        problems.append(f"region {cfg['region']}: AWS has FIPS 140 endpoints for everything this stack uses only in "
                        f"{', '.join(AWS_FIPS_REGIONS)}; pick one of those with --region.")
    problem = _key_problem(cfg["ssh_public_key"], True, cloud.key) if cfg.get("ssh_public_key") else None
    if problem:
        problems.append(f"SSH key: {problem}.")
    if problems:
        raise ui.Abort("FIPS mode is on, but this configuration cannot be FIPS-compliant:\n  - " + "\n  - ".join(problems))
    if _fips_needs_pro_token(cloud, cfg) and not os.environ.get("UBUNTU_PRO_TOKEN"):
        who = "every VM" if cloud.local else " and ".join(
            (["the bastion (Ubuntu image without Pro)"] if _fips_bastion_needs_token(cloud, cfg) else []) +
            (["the VPN host (Ubuntu)"] if _fips_vpn_needs_token(cloud) and cfg["vars"].get("enable_vpn") else []))
        what = (f"FIPS mode: the FIPS-validated modules for {who} come with Ubuntu Pro, and UBUNTU_PRO_TOKEN is not set. "
                "export UBUNTU_PRO_TOKEN=... or store it with: cloudseed creds set UBUNTU_PRO_TOKEN (free for personal "
                "use: https://ubuntu.com/pro/dashboard)")
        if applying:
            raise ui.Abort(what + ", then re-run. Nothing was created.")
        ui.warn(what + "; provisioning needs it, so set it before applying.")
    ui.info("FIPS mode: FIPS images/endpoints, kernel fips=1 on every host, FIPS-only SSH/TLS algorithms, RSA-4096 SSH keys. "
            "Platform items are checked for FIPS capability at install time; verify with: cs scan fips")


def _fips_needs_pro_token(cloud, cfg: dict) -> bool:
    """Hosts whose FIPS modules come from Ubuntu Pro through UBUNTU_PRO_TOKEN: every VMware VM, the AWS VPN host (plain
    Ubuntu) and a GCP bastion on a custom Ubuntu image without Pro. The AWS bastion is Amazon Linux (fips-mode-setup);
    GCP and Azure otherwise boot Ubuntu Pro FIPS images."""
    return bool(_fips_bastion_needs_token(cloud, cfg) or (_fips_vpn_needs_token(cloud) and cfg["vars"].get("enable_vpn")))


def _fips_vpn_needs_token(cloud) -> bool:
    """Does a VPN host get its FIPS modules from Ubuntu Pro through UBUNTU_PRO_TOKEN? Only AWS's (plain Ubuntu); GCP and
    Azure boot theirs from an Ubuntu Pro FIPS image, and a local target has no VPN host."""
    return cloud.key == "aws"


def _gcp_fips_bastion_image(cfg: dict) -> str:
    """The image a FIPS GCP bastion boots (terraform/gcp/main.tf: the default Debian image becomes Ubuntu Pro FIPS; a
    --var bastion_image override is used as it is). The same rule as `cs scan fips` (scan._gcp_bastion_image)."""
    v = {**(cfg.get("vars") or {}), **(cfg.get("extra_vars") or {})}
    image = str(v.get("bastion_image") or scan.GCP_DEFAULT_BASTION_IMAGE).strip()
    return scan.GCP_PRO_FIPS_IMAGE if image == scan.GCP_DEFAULT_BASTION_IMAGE else image


def _fips_bastion_needs_token(cloud, cfg: dict) -> bool:
    """Does the bastion get its FIPS modules from Ubuntu Pro through UBUNTU_PRO_TOKEN (the fips role attaches it)?"""
    if cloud.local:
        return True
    if cloud.key == "gcp":
        name = _gcp_fips_bastion_image(cfg).rsplit("/", 1)[-1].lower()
        return "ubuntu" in name and "pro" not in name
    return False


def _fips_rerun(host) -> str:
    """The command that provisions this host again: `cloudseed provision <cloud> --env <name> --host <label>`."""
    env = host.env
    where = f"{env.cloud} --env {env.name}" if env is not None else "<cloud> --env <name>"
    return f"cloudseed provision {where} --host {host.label}"


def _verify_fips(host, rerun: str | None = None) -> None:
    """After a bastion/VPN play with fips_mode: wait for the reboot the fips role scheduled and verify fips_enabled=1
    (provision.await_fips: a failed SSH check right after the play is waited out, never read as "no reboot pending";
    a host that does not come back is reported as unreachable, not as "FIPS not active"). `rerun`: the command that
    repeats this provisioning with the same choices (default: provision --host <label>)."""
    prov.await_fips(host, rerun or _fips_rerun(host))


def _fips_vars(cfg: dict) -> dict:
    return {"fips_mode": bool(cfg["vars"].get("fips_mode", False))}


def _pro_token(cloud, env, what: str, rerun: str | None = None) -> str:
    token = os.environ.get("UBUNTU_PRO_TOKEN", "")
    if not token:
        raise ui.Abort(f"FIPS mode: {what} gets its FIPS-validated modules from Ubuntu Pro. export UBUNTU_PRO_TOKEN=... "
                       f"(free for personal use: https://ubuntu.com/pro/dashboard), then re-run: "
                       + (rerun or f"cloudseed provision {cloud.key} --env {env.name}"))
    return token


def _provision_all(cloud, env, cfg, *, harden=True, firewall=True, tools=True, sync_only=False, only=None) -> list[str]:
    """Provision the environment's hosts: the bastion, the VPN host and (VMware) the Kubernetes VMs; `only` limits it
    to one of bastion | vpn | k8s. Returns the hosts handled: the keys of cfg["provisioned"] that were provisioned, or
    with sync_only the hosts whose copy of the repository was refreshed. Asking for a host the environment does not
    have is an error, never a silent success."""
    outputs = _cached_outputs(env)
    fips = bool(cfg["vars"].get("fips_mode"))

    def rerun(host: str | None, with_tools: bool = True) -> str:
        """What repeats this run for `host` with the same choices: a flag-less re-run would harden a --no-harden host
        again (or re-provision every host when only one was asked for)."""
        return prov.rerun_command(cloud, env, host, harden=harden, firewall=firewall, tools=tools or not with_tools,
                                  sync_only=sync_only)
    # the bastion's run is the whole environment's, unless only the bastion was asked for; the VPN host's is its own
    bastion_rerun, vpn_rerun = rerun("bastion" if only == "bastion" else None), rerun("vpn", with_tools=False)
    if only == "vpn" and not outputs.get("vpn_public_ip"):
        if cloud.local:
            raise ui.Abort(f"{env.id} has no VPN host: {LOCAL_NOT_APPLICABLE['enable_vpn']}.")
        if cfg["vars"].get("enable_vpn"):
            raise ui.Abort(f"{env.id} has no VPN host yet (enable_vpn is set but not applied): "
                           f"cloudseed apply {cloud.key} --env {env.name}")
        raise ui.Abort(f"{env.id} has no VPN host. Create one with: cloudseed setup {cloud.key} --env {env.name} --var enable_vpn=true")
    if only == "k8s":
        if not cloud.local:
            if not _has_cluster_outputs(outputs):
                if _lenient_bool(cfg["vars"].get("enable_kubernetes"), False):
                    raise ui.Abort(f"{env.id} has no Kubernetes cluster yet (enable_kubernetes is set but not applied): "
                                   f"cloudseed apply {cloud.key} --env {env.name}")
                raise ui.Abort(f"{env.id} has no Kubernetes cluster. Create one with: cloudseed setup {cloud.key} "
                               f"--env {env.name} --var enable_kubernetes=true")
            ui.info(f"The Kubernetes cluster of {env.id} is managed by {cloud.display}: its nodes are not provisioned "
                    "by cloudseed, so there is nothing to do.")
            return []
        if not outputs.get("kubernetes_control_plane_ips"):
            raise ui.Abort(f"{env.id} has no Kubernetes VMs. " + (
                f"They are configured but not applied yet: cloudseed apply {cloud.key} --env {env.name}"
                if cfg["vars"].get("enable_kubernetes") else
                f"Create them with: cloudseed setup {cloud.key} --env {env.name} --var enable_kubernetes=true"))
    done: list[str] = []
    if only in (None, "bastion") and not outputs.get("bastion_public_ip"):
        # never wait minutes on an empty address (Host('').wait) or report a success that provisioned nothing
        raise ui.Abort(_no_bastion_ip(cloud, env, refreshed=True))
    if only in (None, "bastion"):
        # SSH sources are enforced by the cloud firewall (SG / VPC firewall / NSG), which update-ip can change at any time;
        # pinning them in the host's nftables too would lock the user out after an IP change, since fixing the host needs SSH
        extra = {"allowed_ssh_cidrs": [], "ssh_open_any": True}
        if cloud.local:     # the bastion routes and trusts only the static zone of the address plan, not VMware's DHCP pool
            extra["nat_source_cidrs"] = cloud.nat_source_cidrs(cfg) if hasattr(cloud, "nat_source_cidrs") \
                else [cfg["network_cidr"]]
        extra.update(_fips_vars(cfg))
        if fips and _fips_bastion_needs_token(cloud, cfg) and not sync_only:
            token = _pro_token(cloud, env, "every VM" if cloud.local else "the bastion (Ubuntu image without Pro)",
                               rerun=bastion_rerun)
            host = prov.Host(outputs["bastion_public_ip"], cloud.ssh_user(cfg), env.private_key_path(cfg), "bastion", env=env)
            host.wait(retry=f"then re-run `{bastion_rerun}`.")
            host.put_json("~/cloudseed-secrets.json", {"ubuntu_pro_token": token})
        prov.provision(cloud, env, cfg, outputs, harden=harden, firewall=firewall, tools=tools, sync_only=sync_only,
                       extra_vars=extra, rerun=bastion_rerun)
        if fips and not sync_only:
            _verify_fips(prov.Host(outputs["bastion_public_ip"], cloud.ssh_user(cfg), env.private_key_path(cfg), "bastion", env=env),
                         rerun=bastion_rerun)
        done.append("bastion")
    if only in (None, "k8s") and cloud.local and outputs.get("kubernetes_control_plane_ips") and not sync_only:
        prov.provision_local_kubernetes(cloud, env, cfg, outputs, harden=harden)   # --no-harden reaches the nodes too
        done.append("kubernetes")
    if only in (None, "vpn") and outputs.get("vpn_public_ip"):
        # the port the cloud firewall opens (the stack's output); only a stack without that output falls back to the
        # configured --var vpn_port, then OpenVPN's default: a 0 or a typo must surface, not become 1194 silently
        port = outputs.get("vpn_port")
        if port is None:
            port = (cfg.get("extra_vars") or {}).get("vpn_port", 1194)
        extra = {"vpn_type": outputs.get("vpn_type") or cfg["vars"].get("vpn_type", "openvpn"),
                 "vpn_port": port, "allowed_ssh_cidrs": [], "ssh_open_any": True, **_fips_vars(cfg)}
        host = prov.Host(outputs["vpn_public_ip"], cloud.ssh_user(cfg), env.private_key_path(cfg), "vpn", env=env)
        host_secrets = {}
        if extra["vpn_type"] == "tailscale" and not sync_only:
            key = os.environ.get("TS_AUTHKEY")
            if not key:
                raise ui.Abort("vpn_type=tailscale needs a tailnet auth key: export TS_AUTHKEY=tskey-auth-... "
                               "(or: cloudseed creds set TS_AUTHKEY; https://login.tailscale.com/admin/settings/keys, "
                               f"reusable + pre-authorized), then re-run: {vpn_rerun}")
            host_secrets["tailscale_authkey"] = key
        if fips and not sync_only:
            # the AWS VPN host is plain Ubuntu: its FIPS packages need the Pro token (GCP's and Azure's VPN hosts boot
            # Ubuntu Pro FIPS images, which ignore it - whatever image the bastion uses)
            token = _pro_token(cloud, env, "the VPN host (Ubuntu)", rerun=vpn_rerun) if _fips_vpn_needs_token(cloud) \
                else os.environ.get("UBUNTU_PRO_TOKEN", "")
            if token:
                host_secrets["ubuntu_pro_token"] = token
        if host_secrets:
            host.wait(retry=f"then re-run `{vpn_rerun}`.")
            host.put_json("~/cloudseed-secrets.json", host_secrets)
        prov.provision(cloud, env, cfg, outputs, harden=harden, firewall=firewall, tools=False, sync_only=sync_only,
                       playbook="vpn.yml", host_key="vpn_public_ip", label="vpn", extra_vars=extra, rerun=vpn_rerun)
        done.append("vpn")
        if not sync_only:
            if fips:
                _verify_fips(host, rerun=vpn_rerun)
            if extra["vpn_type"] == "openvpn":
                ui.info(f"Create a client profile and connect:  cloudseed vpn connect {cloud.key} --env {env.name}")
            else:
                gke = f" (with the GKE control plane {outputs['kubernetes_master_cidr']})" if outputs.get("kubernetes_master_cidr") else ""
                ui.info(f"Approve all advertised subnet routes{gke} in the Tailscale admin console, then on this machine: "
                        f"cloudseed vpn connect {cloud.key} --env {env.name}")
    return done


def cmd_provision(args, settings) -> int:
    cloud = clouds.get(args.cloud)
    # refused before the environment is loaded: nothing here may start vmrest or fetch an image for a request that
    # cannot be done
    if cloud.local and args.host == "vpn":
        raise ui.Abort(f"--host vpn does not apply to {cloud.key}: {LOCAL_NOT_APPLICABLE['enable_vpn']}. Provision the "
                       f"VMs with: cloudseed provision {cloud.key}" + (f" --env {args.env}" if args.env else ""), code=2)
    if args.sync_only and args.host == "k8s":
        raise ui.Abort("--sync-only refreshes the copy of the repository on the bastion and the VPN host; the Kubernetes "
                       "nodes are provisioned from this machine, so there is nothing to sync on them. Drop --sync-only "
                       "to provision them, or drop --host k8s to sync the bastion and the VPN host.", code=2)
    # provisioning works over SSH: the environment is loaded without hypervisor work (no base image); only the
    # refresh-only apply below needs vmrest
    cloud, env, cfg = _load_env(args, hypervisor=False)
    if args.host == "k8s" and cloud.local and not _lenient_bool(cfg["vars"].get("enable_kubernetes"), False) \
            and not _cached_outputs(env).get("kubernetes_control_plane_ips"):
        raise ui.Abort(f"{env.id} has no Kubernetes VMs. Create them with: cloudseed setup {cloud.key} --env {env.name} "
                       "--var enable_kubernetes=true")
    prev_prov = copy.deepcopy(cfg.get("provisioned") or {})
    outputs = _cached_outputs(env)
    if not outputs.get("bastion_public_ip"):
        migrate = _render(cloud, env, cfg)
        t = Terraform(env.stack_dir)
        t.init(migrate=migrate)
        outputs = _cache_outputs(env, t)
        if cloud.local and not outputs.get("bastion_public_ip") and _managed(_state_addresses(t)):
            # a VM that booted after the apply gave up waiting for its address: re-read it (the provider asks VMware
            # for the guest IP on every refresh; a refresh-only apply changes nothing but the recorded attributes)
            try:
                _prepare_local_teardown()   # vmrest, which the provider reads the VMs through (not the base image)
            except ui.Abort as e:           # best effort: the refresh reports what it cannot reach, provisioning then why
                ui.warn(f"Could not start VMware's REST service to re-read the VMs' addresses: {e.msg}")
            with ui.Spinner("Reading the VMs' addresses from VMware"):
                t.run("apply", "-refresh-only", "-auto-approve", "-input=false", capture=True, check=False)
            outputs = _cache_outputs(env, t)
    done = _provision_all(cloud, env, cfg, harden=not args.no_harden, firewall=not args.no_firewall, tools=not args.no_tools,
                          sync_only=args.sync_only, only=args.host)
    if args.sync_only:
        if done:    # nothing synced (e.g. no such host): no undo entry that claims otherwise
            undo.record(env.id, f"provision {env.id} --sync-only ({', '.join(done)})", "info",
                        {"advice": f"only the copy of the repository on the {' and '.join(done)} was refreshed; nothing "
                                   "to revert"})
    elif done:
        # one entry for every host provisioned now, with what it had before (None: never provisioned)
        undo.record(env.id, f"provision {env.id} ({', '.join(done)})", "provision-prev",
                    {"hosts": {key: prev_prov.get(key) for key in done}})
    return 0


def _outputs_fresh(cloud, env, cfg) -> dict:
    outputs = _cached_outputs(env)
    if not outputs:
        migrate = _render(cloud, env, cfg)
        t = Terraform(env.stack_dir)
        t.init(migrate=migrate)
        outputs = _cache_outputs(env, t)
    return outputs


def cmd_k8s(args, settings) -> int:
    cloud, env, cfg = _load_env(args)
    outputs = _outputs_fresh(cloud, env, cfg)
    if args.k8s_cmd == "kubeconfig":
        kube = services.home_kubeconfig()
        # the cluster's own kubeconfig first (the explicit way to re-fetch a managed one): a request that is refused
        # here (no cluster yet) leaves no copy of the user's kubeconfig behind
        services.ensure_kubeconfig(cloud, env, cfg, outputs, refresh=not cloud.local)
        kubectl = deps.find("kubectl")
        before = _kubeconfig_raw(kubectl, kube)
        bak = undo.backup_file(kube)
        owned = False           # a copy no undo entry owns is deleted, whatever happens below
        try:
            rc = services.kubeconfig(cloud.key, cfg, outputs)
            if rc == 0:
                _record_merged_kubeconfig(cloud, env, kube)   # what a later destroy removes from it again
            if not _unchanged_file(kube, bak):
                # exactly what this merge added or overwrote, so the undo takes out only that (and puts back what it
                # overwrote), not the user's own later changes to the file (undo.py restore-files for a kubeconfig)
                data: dict = {"files": {str(kube): bak}}
                after = _kubeconfig_raw(kubectl, kube)
                if before is not None and after is not None:
                    data["kubeconfig"] = {"names": _kubeconfig_changes(before, after),
                                          "prev_current": before.get("current-context") or "",
                                          "set_current": after.get("current-context") or ""}
                # repeated merges share one slot, which keeps the oldest copy: undo goes back to before all of them
                entry = undo.record(env.id, f"k8s kubeconfig {env.id} (merged into {kube})", "restore-files", data,
                                    coalesce=f"kubeconfig-{env.id}")
                owned = bool(bak) and ((entry.get("data") or {}).get("files") or {}).get(str(kube)) == bak
                _widen_kubeconfig_record(entry, data.get("kubeconfig"))
            # else: merged the same entries again: no undo slot (it would push real undo points out), no copy kept
        finally:
            if not owned:
                _drop_backup(bak)
        return rc
    if args.k8s_cmd == "tunnel":
        services.ensure_kubeconfig(cloud, env, cfg, outputs, refresh=not cloud.local)
        ui.ok(f"kubeconfig ready: {services.kubeconfig_path(env)}   (cs kubectl get nodes)")
        return 0
    if args.k8s_cmd == "untunnel":
        services.close_tunnel(env)
        return 0
    if not outputs.get("kubernetes_cluster_name") and not outputs.get("kubernetes_control_plane_ips"):
        if (cfg.get("vars") or {}).get("enable_kubernetes"):
            # switched on in the configuration (e.g. by a --dry-run / --plan-only / declined setup) but never applied:
            # telling the user to "enable" it again would suggest their --var did not stick
            lines = [ui.dim("Kubernetes is enabled in the configuration but has not been created yet."),
                     f"{ui.style('create  ', 'muted')} cs setup {cloud.key} --env {env.name}   "
                     f"{ui.dim('(without --dry-run / --plan-only)')}"]
        else:
            lines = [ui.dim("No cluster in this environment."),
                     f"{ui.style('enable  ', 'muted')} cs setup {cloud.key} --env {env.name} --var enable_kubernetes=true"]
        ui.panel(f"Kubernetes · {env.id}", lines)
        return 0
    rows: list = []
    for k in ("kubernetes_cluster_name", "kubernetes_distro", "kubernetes_endpoint", "kubernetes_location", "kubernetes_master_version",
              "kubernetes_control_plane_ips", "kubernetes_worker_ips", "kubernetes_node_role_arn", "kubernetes_oidc_issuer"):
        if outputs.get(k):
            v = outputs[k]
            rows.append((k.replace("kubernetes_", "").replace("_", " "), ", ".join(v) if isinstance(v, list) else v))
    if not cloud.local:
        rows.append(("public endpoint", _fmt(cfg["vars"].get("kubernetes_public_endpoint", False))))
    if cloud.local and not services.kubeconfig_path(env).exists():
        # the VMs exist but the cluster was never installed on them (provisioning skipped or failed)
        rows.append(("kubeconfig", ui.dim("not there yet - install the cluster: ") + f"cs provision {cloud.key} --env {env.name} --host k8s"))
    else:
        rows.append(("kubeconfig", f"cs k8s kubeconfig {cloud.key} --env {env.name}"))
    ui.panel(f"Kubernetes · {env.id}", rows)
    return 0


def _kubeconfig_raw(kubectl: str | None, path: Path) -> dict | None:
    """The kubeconfig as `kubectl config view --raw` reads it ({} when the file does not exist); None when it cannot be
    read (no kubectl, a broken file): the merge is then recorded without names (undo falls back to merged.json)."""
    if not path.exists():
        return {}
    if not kubectl:
        return None
    try:
        proc = subprocess.run([kubectl, "config", "view", "--raw", "-o", "json", "--kubeconfig", str(path)],
                              capture_output=True, text=True, timeout=60)
        data = json.loads(proc.stdout or "{}") if proc.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _widen_kubeconfig_record(entry: dict, merged: dict | None) -> None:
    """A repeated merge coalesced into an older entry, which keeps its oldest copy and names: add the names this merge
    changed (an endpoint or user entry the first merge left as it was) and the current context it set, so the undo
    takes out everything the run of merges did. An entry recorded without names stays so (undo.py's fallback)."""
    rec = (entry.get("data") or {}).get("kubeconfig") if isinstance(entry, dict) else None
    if not isinstance(rec, dict) or not isinstance(rec.get("names"), dict) or not merged:
        return
    names = {k: sorted(set(rec["names"].get(k) or []) | set((merged.get("names") or {}).get(k) or []))
             for k in _KUBE_KINDS}
    if names == {k: sorted(rec["names"].get(k) or []) for k in _KUBE_KINDS} \
            and rec.get("set_current") == merged.get("set_current"):
        return
    rec["names"], rec["set_current"] = names, merged.get("set_current") or ""
    undo.update_data(entry)


def _kubeconfig_changes(before: dict, after: dict) -> dict:
    """{contexts|clusters|users: names} a merge added or overwrote: entries of `after` that are new or differ."""
    out = {}
    for kind in _KUBE_KINDS:
        prev = {x.get("name"): x for x in before.get(kind) or [] if isinstance(x, dict) and x.get("name")}
        out[kind] = sorted({x["name"] for x in after.get(kind) or [] if isinstance(x, dict) and x.get("name")
                            and prev.get(x["name"]) != x})
    return out


def _unchanged_file(path: Path, backup: str | None) -> bool:
    """Is `path` exactly what `backup` (undo.backup_file's copy; None: it did not exist) holds?"""
    import filecmp
    if backup is None:
        return not path.exists()
    try:
        return path.is_file() and filecmp.cmp(backup, path, shallow=False)
    except OSError:
        return False


def _drop_backup(backup: str | None) -> None:
    """Delete a backup copy that no undo entry owns."""
    if backup:
        undo._discard_backups({"data": {"files": {"-": backup}}})


def cmd_vpn(args, settings) -> int:
    sub = args.vpn_cmd
    if clouds.get(args.cloud).local:
        # a local environment's VMs are reached directly: nothing to read from Terraform, nothing for the hypervisor
        cloud, env, cfg = _load_env(args, hypervisor=False)
        if sub == "status":
            services.status(env, cfg, {}, cloud)
            return 0
        if sub == "disconnect":
            ui.info(f"No VPN runs for {env.id}: {LOCAL_NOT_APPLICABLE['enable_vpn']}.")
            return 0
        raise ui.Abort(services.vpn_not_applicable(cloud.key, env.name))
    cloud, env, cfg = _load_env(args)
    outputs = _outputs_fresh(cloud, env, cfg)
    if sub == "status":
        services.status(env, cfg, outputs)
        return 0
    if sub in ("add-user", "revoke") and not args.name:
        raise ui.Abort(f"cloudseed vpn {sub} needs a client name, e.g. cloudseed vpn {sub} {cloud.key} --env {env.name} alice")
    if sub == "add-user":
        path = services.add_user(cloud, env, cfg, outputs, args.name)
        undo.record(env.id, f"vpn add-user {args.name}", "vpn-revoke", {"name": args.name})
        ui.ok(f"Profile saved: {path}  (import it into any OpenVPN client, or: cloudseed vpn connect {cloud.key} --env {env.name} --user {args.name})")
        return 0
    if sub == "revoke":
        services.revoke_user(cloud, env, cfg, outputs, args.name)
        undo.record(env.id, f"vpn revoke {args.name}", "vpn-add", {"name": args.name})
        ui.ok(f"Revoked {args.name}")
        return 0
    if sub == "users":   # one SSH call: each client with its certificate expiry, renew warnings (clients and server)
        return services.users_report(cloud, env, cfg, outputs)
    # connect/disconnect are journalled only when they changed the connection: a no-op entry would undo into the
    # opposite of what the user has now, and push real entries out of the short undo history. Only this machine's
    # OpenVPN client has a state cloudseed can see (and undo); Tailscale is the tailnet's.
    openvpn = services._vpn_type(cfg, outputs) == "openvpn"
    if sub == "connect":
        was = bool(services._running(env)) if openvpn else True
        rc = services.connect(cloud, env, cfg, outputs, args.user)
        if rc == 0 and not was and services._running(env):
            undo.record(env.id, f"vpn connect {env.id}", "argv", {"argv": ["vpn", "disconnect", cloud.key, "--env", env.name]})
        return rc
    if sub == "disconnect":
        was = bool(services._running(env))
        rc = services.disconnect(env)
        if rc == 0 and was and not services._running(env):
            undo.record(env.id, f"vpn disconnect {env.id}", "argv", {"argv": ["vpn", "connect", cloud.key, "--env", env.name]})
        return rc
    if sub == "provision":
        prev_prov = copy.deepcopy(cfg.get("provisioned") or {})
        done = _provision_all(cloud, env, cfg, only="vpn")
        if "vpn" in done:
            undo.record(env.id, f"vpn provision {env.id}", "provision-prev", {"hosts": {"vpn": prev_prov.get("vpn")}})
        return 0
    return 1


def cmd_plan(args, settings) -> int:
    cloud, env, cfg = _load_env(args)
    if _pending_backend(cloud, cfg):
        ui.info(f"The remote state storage of {env.id} is not created yet (setup ran as a dry run or plan); it is "
                "created first on apply. This plan uses a temporary local state.")
    backend_changed = _render(cloud, env, cfg)
    t = Terraform(env.stack_dir)
    t.init(migrate=backend_changed)
    t.plan("tfplan")
    (env.stack_dir / "tfplan").unlink(missing_ok=True)
    return 0


def cmd_apply(args, settings) -> int:
    cloud, env, cfg = _load_env(args)
    if _lenient_bool((cfg.get("vars") or {}).get("fips_mode"), False) and _fips_needs_pro_token(cloud, cfg) \
            and not os.environ.get("UBUNTU_PRO_TOKEN"):
        # a --dry-run / --plan-only setup only warned about it; apply never provisions, `cloudseed provision` refuses
        ui.warn("FIPS mode: UBUNTU_PRO_TOKEN is not set. apply creates the hosts, but they become FIPS-compliant only when "
                f"provisioned, and `cloudseed provision {cloud.key} --env {env.name}` needs the token: export "
                "UBUNTU_PRO_TOKEN=... or store it with: cloudseed creds set UBUNTU_PRO_TOKEN")
    _ensure_backend(cloud, env, cfg, args.auto_approve)   # never apply into a stray local state of a 'remote' env
    backend_changed = _render(cloud, env, cfg)
    t = Terraform(env.stack_dir)
    t.init(migrate=backend_changed)
    # strict: a state read that fails must not look like "nothing existed" (that would record a destroy-everything undo)
    before = set(_managed(_state_addresses(t)))
    _plan_for_apply(cloud, env, cfg, t)
    if _plan_is_noop(t):   # nothing to approve: exit 3 ("needs approval") would be wrong for a converged environment
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        _cache_outputs(env, t)
        ui.ok(f"No changes: {env.id} matches its configuration. Nothing to apply.")
        return 0
    # a local cluster whose node count was lowered (e.g. by a --plan-only setup): those nodes leave it before their VMs go
    leaving = _local_vm_plan(cloud, env, cfg, t) if cloud.local and before else []
    keep = _kept_deletes(cloud, cfg, t) if before else []
    if keep:
        ui.warn("Kept in place instead of deleted (account/subscription/project-wide, only dropped from the state): "
                + _kept_types(keep))
    try:
        _approve("Apply this plan?", args.auto_approve)
        _leave_deleted_nodes(cloud, env, cfg, leaving)
        _forget_kept_for_apply(env, cfg, t, keep)
    except BaseException:
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        raise
    t.apply_reconciled(cloud.key, cfg, approve=lambda q: _approve(q, args.auto_approve))
    (env.stack_dir / "tfplan").unlink(missing_ok=True)
    _settle_kept(env, cfg, t)
    _finish(cloud, env, cfg, t)
    try:
        after = _managed(_state_addresses(t))
    except TerraformError:
        undo.record(env.id, f"apply {env.id}", "info", {"advice": "the state could not be read after the apply; "
                                                                   f"review it with: cloudseed status {cloud.key} --env {env.name}"})
        return 0
    created = [r for r in after if r not in before]
    after_set = set(after)
    removed = [r for r in before if r not in after_set]
    if created and not before:
        # the stack was built from nothing (after --plan-only, --dry-run, a destroy or a failed setup): undo = full destroy
        undo.record(env.id, f"apply {env.id} (created {_count(len(created), 'resource')})", "created")
    elif created:
        # every created address (data sources never are), so undo removes exactly what this apply added
        undo.record(env.id, f"apply {env.id} (created {_count(len(created), 'resource')})", "argv",
                    {"argv": ["destroy", cloud.key, "--env", env.name, "-y", "--auto-approve"] + [a for r in created for a in ("--target", r)]})
    elif removed:   # a converging re-apply with nothing new leaves no entry: it must not push real undo steps out
        undo.record(env.id, f"apply {env.id} (removed {_count(len(removed), 'resource')})", "info",
                    {"advice": "apply removed resources; revert with `cs undo` of the configuration change before it"})
    return 0


# ---------------------------------------------------------------- state / plan helpers (destroy, apply, update-ip, status)

def _count(n: int, word: str) -> str:
    """'1 resource', '3 resources'."""
    return f"{n} {word}{'' if n == 1 else 's'}"


def _is_data(address: str) -> bool:
    """data.TYPE.NAME, possibly inside modules (module.a["k"].data.x.y) - never a resource that is merely named `data`."""
    return bool(re.match(r'(module\.[^.\[]+(\[[^\]]*\])?\.)*data\.', address))


def _managed(addresses) -> list[str]:
    """Managed resources only: data sources are read, never created or destroyed."""
    return [a for a in addresses if not _is_data(a)]


def _state_addresses(t: Terraform) -> list[str]:
    """`terraform state list`, strictly. State that cannot be read (credentials, network, lock) raises instead of
    looking empty: an 'empty' answer would make destroy purge the config of live infrastructure, status suggest
    re-creating it, and apply record the wrong undo."""
    from .tf import explain
    proc = t.run("state", "list", capture=True, check=False)
    if proc.returncode != 0:
        out = (proc.stderr or "") + (proc.stdout or "")
        if "No state file was found" in out:   # local backend before the first apply
            return []
        raise TerraformError(explain(out, "state list", getattr(t, "workdir", None)))
    return [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]


def _plan_changes(t: Terraform, planfile: str = "tfplan") -> list[dict] | None:
    """The resource changes of a saved plan as [{address, type, mode, actions}] (no-ops and reads left out);
    None when the plan cannot be read, so callers fall back to asking about 'the plan above'."""
    proc = t.run("show", "-json", planfile, capture=True, check=False)
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        return None
    out: list[dict] = []
    for rc in data.get("resource_changes") or []:
        actions = list((rc.get("change") or {}).get("actions") or [])
        if not actions or actions in (["no-op"], ["read"]):
            continue
        out.append({"address": rc.get("address", ""), "type": rc.get("type", ""), "mode": rc.get("mode", "managed"),
                    "actions": actions})
    return out


def _plan_is_noop(t: Terraform, planfile: str = "tfplan") -> bool:
    """Does the saved plan change nothing at all - no resource, no output, no move or import? False whenever that
    cannot be told for sure (the plan is unreadable, or an older Terraform wrote no `applyable`), so the caller then
    asks about it as before."""
    proc = t.run("show", "-json", planfile, capture=True, check=False)
    if proc.returncode != 0:
        return False
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        return False
    if not isinstance(data, dict) or "format_version" not in data:
        return False
    if "applyable" in data:                    # Terraform's own verdict (1.7+): nothing to apply at all
        return data["applyable"] is False
    for rc in data.get("resource_changes") or []:
        change = rc.get("change") or {}
        if (change.get("actions") or []) not in (["no-op"], ["read"]) or rc.get("previous_address") or change.get("importing"):
            return False
    return all(((c or {}).get("actions") or []) == ["no-op"] for c in (data.get("output_changes") or {}).values())


def _module_groups(resources: list[str]) -> dict[str, int]:
    """Resource count under every module prefix, nested ones included: module.stack counts everything under it (its own
    resources and those of module.stack.module.network ...), so the number shown is what a -target on it destroys."""
    groups: dict[str, int] = {}
    seg = re.compile(r'module\.[^.\[]+(?:\[[^\]]*\])?\.')
    for r in resources:
        pos = 0
        m = seg.match(r, pos)
        while m:
            prefix = r[:m.end() - 1]
            groups[prefix] = groups.get(prefix, 0) + 1
            pos = m.end()
            m = seg.match(r, pos)
    return groups


def _address_in_state(target: str, resources: list[str]) -> bool:
    """Does a -target address cover anything in the state (itself, a module prefix, or all instances of a resource)?"""
    return any(r == target or r.startswith(target + ".") or r.startswith(target + "[") for r in resources)


def _did_you_mean(target: str, resources: list[str]) -> str:
    import difflib
    near = difflib.get_close_matches(target, list(_module_groups(resources)) + resources, n=3, cutoff=0.6)
    return f" (did you mean: {', '.join(near)}?)" if near else ""


def _parse_selection(raw: str, n: int) -> tuple[list[int], str | None]:
    """'1,3,5-9' -> [1, 3, 5, 6, 7, 8, 9]; every number must be in 1..n and every range low-high."""
    picked: list[int] = []
    for part in (p.strip() for p in raw.split(",")):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)|(\d+)", part)
        if not m:
            return [], f"'{part}' is not a number or a range like 5-9."
        a, b = (int(m.group(1)), int(m.group(2))) if m.group(1) else (int(m.group(3)), int(m.group(3)))
        if a > b:
            return [], f"'{part}' is a reversed range; write it low-high, e.g. {b}-{a}."
        if a < 1 or b > n:
            return [], f"'{part}' is out of range; choose numbers from 1 to {n}."
        picked += range(a, b + 1)
    if not picked:
        return [], "Nothing selected. Pick at least one number, or q to cancel."
    return picked, None


def _select_targets(resources: list[str]) -> list[str]:
    if not resources:
        raise ui.Abort("State is empty; nothing to select.", code=0)
    groups = _module_groups(resources)
    total = len(resources)
    options: list[str] = []
    print()
    print(ui.bold("Modules"))
    # a module holding every resource (the root wrapper module.stack) is not a selection but the whole environment:
    # that is a full `cloudseed destroy` (typed confirmation, outputs and state-storage clean-up, undo). Its own direct
    # resources (GCP's API enablements, Azure's resource group ...) stay selectable one by one below.
    whole = [g for g, n in groups.items() if n >= total and total > 1]
    for g, n in sorted(groups.items()):
        if g in whole:
            continue
        options.append(g)
        count = "(" + _count(n, "resource") + ")"
        print(f"  {len(options):>3}) {g}  {ui.dim(count)}")
    if whole:
        print(ui.dim(f"       ({', '.join(sorted(whole))}: all {total} resources - the whole environment; "
                     "use `cloudseed destroy` without --select for that)"))
    print(ui.bold("Resources"))
    for r in resources:
        options.append(r)
        print(f"  {len(options):>3}) {r}")
    while True:
        raw = ui.ask(f"Select what to destroy (1-{len(options)}, e.g. 1,3 or 5-9), q to cancel", "q").strip()
        if raw.lower() in ("q", "quit", ""):
            if not ui.interactive():    # nobody could pick: a usage error for a script, never a silent "Cancelled"
                raise ui.Abort("--select needs a terminal to pick from (and no -y, which never asks); pass --target "
                               "ADDRESS instead (the addresses are listed above). Nothing was changed.", code=2)
            raise ui.Abort("Cancelled. Nothing was changed.", code=0)
        picked, problem = _parse_selection(raw, len(options))
        if problem:   # re-ask: a bad selection must never fall through to "destroy everything"
            ui.warn(problem)
            continue
        return list(dict.fromkeys(options[i - 1] for i in picked))


def _approve_destroy(question: str, auto: bool) -> None:
    if auto:
        return
    if not ui.interactive():
        raise ui.Abort("Nothing destroyed. Review the plan above, then re-run with --auto-approve to destroy it.", code=3)
    if not ui.confirm(question, default=False):
        raise ui.Abort("Cancelled. Nothing was changed.", code=0)


def cmd_destroy(args, settings) -> int:
    cloud, env, cfg = _load_env(args)
    backend_changed = _render(cloud, env, cfg)
    t = Terraform(env.stack_dir)
    t.init(migrate=backend_changed)
    # strict: an unreadable state must never pass for "already empty" - the purge would then drop the only local
    # record (config, keys) of infrastructure that still runs
    resources = _state_addresses(t)

    targets = [x.strip() for item in (args.target or []) for x in item.split(",") if x.strip()]
    if args.target and not targets:
        raise ui.Abort("--target needs a Terraform address, e.g. --target module.stack.module.bastion. Nothing was changed.", code=2)
    if args.select:   # data sources are not offered: a destroy targeting one also deletes everything that reads it
        targets += _select_targets(_managed(resources))
    if targets:   # a partial request never reaches the destroy-everything path below
        if args.purge or args.purge_state:
            ui.warn("--purge / --purge-state apply to a full destroy only; this partial destroy keeps the working "
                    "directory and the state storage.")
        return _destroy_targets(cloud, env, cfg, t, resources, list(dict.fromkeys(targets)), args)
    audit.tag(destroy_scope="all")      # what this run removes, for troubleshoot (argv cannot say what --select picked)
    return _destroy_everything(cloud, env, cfg, t, resources, args, settings)


# A plan that deletes the cluster first removes what Kubernetes created in the cloud (a destroy of the network under
# it always deletes the cluster too, as a dependent). Deleting only a node pool or a NAT gateway leaves the cluster -
# and its load balancers and volumes - in place, so nothing is drained then.
_CLUSTER_TYPES = {"aws_eks_cluster", "google_container_cluster"}


def _covered(address: str, targets) -> bool:
    """Does one of these -target addresses cover `address` (itself, a module prefix, or all instances of a resource)?"""
    return any(address == x or address.startswith(x + ".") or address.startswith(x + "[") for x in targets)


def _kept_types(keep) -> str:
    return ", ".join(dict.fromkeys(re.sub(r"\[[^\]]*\]$", "", a).split(".")[-2] for a, _ in keep))


def _remember_kept(env: paths.Env, cfg: dict, keep) -> None:
    """Record the never-adopted singletons this destroy leaves in place (reconcile.remember_kept) in the saved
    configuration, before they leave the state: re-creating the environment (setup, apply, `cs undo` of the destroy)
    then adopts exactly those again instead of stopping at 'already exists outside this environment'."""
    from . import reconcile
    addresses = [a for a, _ in keep]
    if not addresses:
        return
    reconcile.remember_kept(cfg, addresses)             # the command's copy, for what it does next
    _update_saved(env, lambda saved: reconcile.remember_kept(saved, addresses))


def _forget_kept(t, keep, targets: tuple = ()) -> None:
    """Drop account/subscription/project-wide objects from the state (the objects stay), then plan the destroy again:
    the saved plan would still delete them, and Terraform refuses a plan whose state changed anyway."""
    for addr, _ in keep:
        t.run("state", "rm", addr, capture=True)     # a failure stops here: nothing is deleted that must be kept
    t.run("plan", "-input=false", "-out=tfplan", "-destroy", "-no-color", *[f"-target={x}" for x in targets], capture=True)
    ui.info("Left in place (account/subscription/project-wide settings, now unmanaged): " + _kept_types(keep))
    for notice in dict.fromkeys(n for _, n in keep if n):   # e.g. both Defender plans carry the same notice
        ui.info(notice)


def _has_cluster_outputs(outputs: dict) -> bool:
    return bool((outputs or {}).get("kubernetes_cluster_name") or (outputs or {}).get("kubernetes_control_plane_ips"))


def _destroy_targets(cloud, env, cfg, t, resources: list[str], targets: list[str], args) -> int:
    if not resources:
        ui.info("Stack state is empty; nothing to destroy.")
        return 0
    unknown = [x for x in targets if not _address_in_state(x, resources)]
    for x in unknown:   # warn and skip (an undo of `apply` names resources that may already be gone)
        ui.warn(f"{x} matches nothing in the state{_did_you_mean(x, resources)}; skipped.")
    targets = [x for x in targets if x not in unknown]
    if not targets:
        raise ui.Abort("None of the targets match anything in the state. Nothing was changed. "
                       f"See what exists with: cloudseed inventory {cloud.key} --env {env.name}   (or pick with --select)")
    audit.tag(destroy_scope=sorted(targets))   # the resolved addresses (--select picks included), for troubleshoot
    if cloud.local:
        _prepare_local_teardown()
    ui.header(f"Destroy selected resources in {env.id}")
    for x in targets:
        print(f"  - {x}")
    outputs_before = t.outputs() or _cached_outputs(env)
    # account/subscription/project-wide settings under a target are forgotten, not deleted (as in a full destroy)
    keep = [(a, n) for a, n in cloud.keep_on_destroy(cfg, resources) if _covered(a, targets)]
    t.plan("tfplan", destroy=True, targets=tuple(targets))
    changes = _plan_changes(t)
    deletes = None if changes is None else [c for c in changes if "delete" in c["actions"] and c["mode"] != "data"]
    if deletes is not None and not deletes:
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        ui.warn("Nothing to destroy: the targets match no managed resources. Nothing was changed.")
        return 1
    kept = {a for a, _ in keep}
    if deletes is not None:
        deletes = [c for c in deletes if c["address"] not in kept]
    doomed = [c["address"] for c in deletes] if deletes is not None else \
        [a for a in _managed(resources) if _covered(a, targets)]
    # every managed resource goes (--target module.stack, every module selected ...): that is a full teardown, and it
    # gets the full teardown's confirmation - the typed environment id - not a y/N
    everything = bool(doomed) and set(doomed) | kept >= set(_managed(resources))
    try:
        _warn_account_wide(cfg, doomed, kept)
        _warn_dependents(deletes, targets)
        if keep:
            ui.warn("Kept in place (account/subscription/project-wide, only dropped from the state): " + _kept_types(keep))
        if deletes == [] and keep:   # the targets hold nothing but account-wide settings
            question = "Drop the settings above from the state (they are not deleted)?"
        else:
            question = f"Destroy these {len(deletes)} resource(s)?" if deletes else "Destroy the resources above?"
        if everything and not args.auto_approve and ui.interactive():
            ui.warn(f"The targets cover every resource of {env.id} ({_count(len(doomed), 'resource')}): this destroys the "
                    "whole environment (a full `cloudseed destroy` also cleans up its outputs and offers undo).")
            ui.require_typed(env.id, f"Type '{env.id}' to confirm")
        else:
            _approve_destroy(question, args.auto_approve)
        if keep:
            _remember_kept(env, cfg, keep)
            _forget_kept(t, keep, tuple(targets))
        if deletes and _needs_cluster_drain(cloud, outputs_before) and any(c["type"] in _CLUSTER_TYPES for c in deletes):
            _drain_cluster_for_destroy(cloud, env, cfg, outputs_before)
        try:
            t.apply("tfplan")
        except TerraformError:
            audit.refresh(env, t, "destroy-targets-failed", {"targets": targets})
            raise
    finally:
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
    env.forget_host_keys()   # hosts re-created on the same addresses (vmware's fixed IPs, kept public IPs) get new SSH keys
    outputs_after = _cache_outputs(env, t)
    if cloud.local:          # the cluster's VMs were among the targets: its record goes with them
        _forget_removed_cluster(env, cfg, outputs_after)
    if _has_cluster_outputs(outputs_before) and not _has_cluster_outputs(outputs_after):
        _forget_cluster_access(env)     # the cluster itself went: its tunnel, kubeconfig entries and join token too
    elif any("kubernetes" in x for x in targets) or any(c["type"] in _CLUSTER_TYPES | {"azurerm_kubernetes_cluster"}
                                                        for c in deletes or []):
        services.close_tunnel(env, quiet=True)   # an SSH tunnel to the destroyed cluster's API is useless now
    audit.refresh(env, t, "destroy-targets", {"targets": targets})
    undo.record(env.id, f"destroy targets {ui.clip(' '.join(targets), 60)}", "argv", {"argv": ["apply", cloud.key, "--env", env.name, "-y"], "approve": True})
    done = f"Destroyed {len(deletes)} resource(s)." if deletes else \
        ("Nothing was deleted." if deletes == [] else "Selected resources destroyed.")
    ui.ok(f"{done} Re-create them any time with: cloudseed apply {cloud.key} --env {env.name}")
    return 0


def _warn_dependents(deletes: list[dict] | None, targets: list[str]) -> None:
    """A targeted destroy also deletes what depends on the targets (Terraform plans them in): name those, grouped by
    module, so the approval covers what really goes. The count asked about stays the plan's."""
    extra = [c["address"] for c in deletes or [] if not _covered(c["address"], targets)]
    if not extra:
        return
    groups: dict[str, list[str]] = {}
    for a in extra:
        m = re.match(r"((?:module\.[^.\[]+(?:\[[^\]]*\])?\.)*)(.+)$", a)
        mod, rest = (m.group(1).rstrip("."), m.group(2)) if m else ("", a)
        groups.setdefault(_short_address(mod) if mod != "module.stack" else "", []).append(rest)
    parts = [f"{mod}: {', '.join(names)}" if mod else ", ".join(names) for mod, names in groups.items()]
    ui.warn(f"Also destroyed, because they depend on the targets ({_count(len(extra), 'resource')}): " + "; ".join(parts))


# Account/region-wide AWS services this environment switched on (never adopted from elsewhere: reconcile.NEVER_ADOPT):
# a full destroy deletes them, which turns them off for everything else in that account and region.
_ACCOUNT_WIDE_DELETES = {"aws_guardduty_detector": "GuardDuty", "aws_securityhub_account": "Security Hub",
                         "aws_config_configuration_recorder": "AWS Config recording",
                         "aws_accessanalyzer_analyzer": "IAM Access Analyzer"}


def _warn_account_wide(cfg: dict, addresses, kept) -> None:
    """The one warning for a destroy (full or targeted) that deletes account/region-wide services this environment
    switched on: it reaches beyond the environment."""
    switched_off = _account_wide_deletes(list(addresses), kept)
    if switched_off:
        ui.warn(f"This also turns off {', '.join(switched_off)} for the whole account in {cfg.get('region')} (this "
                "environment enabled it there); anything else in the account that relies on it loses it.")


def _account_wide_deletes(resources: list[str], kept) -> list[str]:
    kept = set(kept)
    out = []
    for a in resources:
        if a in kept or _is_data(a):
            continue
        rtype = re.sub(r"\[[^\]]*\]$", "", a).split(".")[-2] if "." in a else ""
        name = _ACCOUNT_WIDE_DELETES.get(rtype)
        if name and name not in out:
            out.append(name)
    return out


def _destroy_everything(cloud, env, cfg, t, resources: list[str], args, settings) -> int:
    ui.header(f"Destroy EVERYTHING in {env.id}")
    auto = args.auto_approve
    outputs_before = (t.outputs() if resources else {}) or _cached_outputs(env)   # the state's own, else the cache
    # the VMs Terraform knows about, read before the destroy empties the inventory (the leftover sweep uses them).
    # Resolved here: older versions recorded a relative vm_dir's paths relative to Terraform's working directory
    # (<workdir>/stack), never to wherever this command runs (localvm.recorded_vmx_path)
    from . import localvm
    known_vmx = [localvm.recorded_vmx_path(r["vmx_path"], cfg.get("workdir") or str(env.dir))
                 for r in ((audit.load(env).get("current") or {}).get("resources") or [])
                 if r.get("type") == "vmdesktop_vm" and r.get("vmx_path")]
    if resources:
        if cloud.local:
            _prepare_local_teardown()
        # account/subscription/project-wide settings (AWS S3 public-access block, Azure Defender plans and FIPS image
        # terms, GCP's project-wide logging settings) are forgotten, not deleted: keep_on_destroy in clouds/aws.py,
        # clouds/azure.py and clouds/gcp.py
        keep = cloud.keep_on_destroy(cfg, resources)
        t.plan("tfplan", destroy=True)
        # shown in the preview too: it is the part of a teardown that reaches beyond this environment
        _warn_account_wide(cfg, resources, [a for a, _ in keep])
        if not auto:
            n = len(_managed(resources)) - len(keep)
            ui.warn(f"This deletes {'all ' if n != 1 else ''}{_count(n, 'resource')} above, including the bastion, "
                    "network and logs." if n != 1 else f"This deletes the {_count(n, 'resource')} above.")
            if keep:   # before the preview stops too: the plan above still lists them as deleted
                ui.warn("Kept in place (account/subscription/project-wide, only dropped from the state): " + _kept_types(keep))
            if not ui.interactive():   # -y or no terminal: a preview, never a teardown (help + skills promise exit 3)
                (env.stack_dir / "tfplan").unlink(missing_ok=True)
                raise ui.Abort("Nothing destroyed. The plan above lists what would be deleted" +
                               (" (except the settings kept in place, listed above)" if keep else "") +
                               "; review it, then re-run with --auto-approve to destroy it (add -y for a fully unattended run).",
                               code=3)
            try:
                ui.require_typed(env.id, f"Type '{env.id}' to confirm")
            except BaseException:
                (env.stack_dir / "tfplan").unlink(missing_ok=True)
                raise
        if keep:   # confirmed: drop them from the state, then plan the destroy again without them
            _remember_kept(env, cfg, keep)
            _forget_kept(t, keep)
        try:
            if _needs_cluster_drain(cloud, outputs_before):
                _drain_cluster_for_destroy(cloud, env, cfg, outputs_before)
            try:
                t.apply("tfplan")
            except TerraformError:
                audit.refresh(env, t, "destroy-failed")
                raise
        finally:
            (env.stack_dir / "tfplan").unlink(missing_ok=True)
        audit.refresh(env, t, "destroy")
        ui.ok("All stack resources destroyed.")
    else:
        ui.info("Stack state is already empty.")
        if not auto and not ui.interactive():
            pending = _pending_cleanup(cloud, env, cfg, args, known_vmx, outputs_before)
            if pending:
                raise ui.Abort("Nothing removed. Without --auto-approve this is a preview; it would also: " + "; ".join(pending) +
                               ". Re-run with --auto-approve to go ahead.", code=3)
            # nothing left to remove: the preview stays read-only - the cached outputs, SSH host keys and kubeconfig
            # entries are only forgotten by a run that is allowed to change something
            storage = _state_storage(env, cfg)
            if not storage and args.purge_state:
                _handle_state_storage(cloud, env, cfg, args)   # (with none recorded it only says so)
            elif storage:                                      # (with --purge-state it is pending above)
                ui.info(f"Remote state storage {storage} is kept (it is billable); delete it with: cloudseed destroy "
                        f"{cloud.key} --env {env.name} --purge-state --auto-approve")
            local = [what for what, there in (("cached outputs", (env.dir / "outputs.json").exists()),
                                              ("SSH host keys", env.known_hosts_path().exists()),
                                              ("cluster access files", (env.dir / "k8s").exists()))
                     if there]
            kept = " and ".join([", ".join(local[:-1]), local[-1]] if len(local) > 1 else local)
            ui.ok(f"Nothing to destroy in {env.id}." + (f" Its {kept} stay until a run with --auto-approve (or at a "
                                                         "terminal) forgets them." if local else ""))
            return 0
    env.forget_host_keys()   # the next hosts on these addresses will have new SSH keys
    if cloud.local:          # no VM is left: a cluster created later is a new one (also for the undo's configuration)
        _forget_removed_cluster(env, cfg, {})
    # nothing logs in any more: the OS Login key this environment registered goes (GCP; dropped from the saved record,
    # so re-creating the environment registers it again)
    _release_os_login(cloud, env, cfg, None)
    try:    # what an undo re-creates: the saved configuration, not this run's stand-ins for invalid or missing values
        destroyed_cfg = env.load()
    except Exception:  # noqa: BLE001 - unreadable now: the configuration this destroy used
        destroyed_cfg = copy.deepcopy(cfg)

    if cloud.local:
        _destroy_local_leftovers(env, cfg, purge=args.purge, known_vmx=known_vmx, vmnet=outputs_before.get("private_vmnet"),
                                 confirm=not resources and not auto, adopted=outputs_before.get("private_vmnet_adopted"),
                                 auto_approve=auto)
    _forget_cluster_access(env)
    # nothing in the cached outputs exists any more: list/env/ssh/k8s must not keep showing (or trusting) them
    (env.dir / "outputs.json").unlink(missing_ok=True)

    kept_storage = _handle_state_storage(cloud, env, cfg, args)

    purge = args.purge or ui.confirm(_purge_question(env), default=False)
    if kept_storage and not purge:     # (a purge prints the terraform command instead: this one needs config.json)
        ui.info(f"Delete the state storage later with: cloudseed destroy {cloud.key} --env {env.name} --purge-state")
    was_current = purge and settings.get("current_env") == env.id     # a purge unsets it: the undo can set it again
    workdir = str(env.dir)
    backup_dir = _purge_env_dir(env, settings, kept_storage) if purge else None
    # what an undo of a purge needs besides the copies: where the working directory was, and whether it was current
    marks = {"workdir": workdir, **({"current_env": env.id} if was_current else {})} if backup_dir else {}
    if resources:
        undo.record(env.id, f"destroy {env.id}" + (" --purge" if purge else ""), "recreate",
                    {"cfg": destroyed_cfg, "backup_dir": backup_dir, **marks})
    elif backup_dir:
        # nothing was deployed: the undo puts the files back and must not run setup (that would create resources that
        # never existed); the entry also owns the backup, so it is deleted when the entry expires. data['workdir'] (in
        # marks) is where they go back: a custom --workdir is checked (paths.workdir_problem) and registered again
        # (undo._register_workdir)
        b = Path(backup_dir)
        files = {str(env.dir / f): str(b / f) for f in ("config.json", "outputs.json") if (b / f).exists()}
        for sub, dest in (("ssh", env.ssh_dir), ("bootstrap", env.bootstrap_dir)):
            if (b / sub).exists():
                files[str(dest)] = str(b / sub)
        undo.record(env.id, f"destroy {env.id} --purge (nothing was deployed)", "restore-files",
                    {"files": files, "backup_dir": backup_dir, **marks})
    return 0


def _pending_cleanup(cloud, env, cfg, args, known_vmx, outputs_before: dict) -> list[str]:
    """What a destroy with an already empty state would still remove (shown instead, in preview mode)."""
    pending = []
    if cloud.local:
        vm_dir, prefix = _vm_dir(env, cfg, known_vmx), f"{cfg.get('name')}-{cfg.get('env')}"
        mine, _ = _env_vm_bundles(vm_dir, prefix, known_vmx)
        if mine:
            pending.append(f"delete leftover VM(s) {', '.join(b.name for b in mine)}")
        vmnet = outputs_before.get("private_vmnet")
        # only a vmnet this environment created is removed (localvm.remove_vmnet); an adopted one stays
        if vmnet and vmnet not in ("vmnet0", "vmnet1", "vmnet8") and outputs_before.get("private_vmnet_adopted") is False:
            pending.append(f"remove the private network {vmnet} from VMware's configuration")
    if args.purge_state and _state_storage(env, cfg):
        pending.append(f"delete the remote state storage {_state_storage(env, cfg)}")
    if args.purge:
        pending.append(f"delete {env.dir}" if _workdir_owned(env) else f"delete cloudseed's files from {env.dir}")
    login = cfg.get("os_login")
    if getattr(cloud, "release_os_login", None) and isinstance(login, dict) and login.get("added") and login.get("account") \
            and len(str(login.get("key") or "").split()) >= 2:
        # (_release_os_login after the teardown, for a key it can name; kept while another environment records it)
        pending.append(f"remove the OS Login SSH key cloudseed registered for {login['account']} (unless another "
                       "environment still uses it)")
    return pending


# ---------------------------------------------------------------- remote state storage on teardown

def _backend_name(backend: dict | None) -> str | None:
    for conf in (backend or {}).values():
        if isinstance(conf, dict):
            name = conf.get("bucket") or conf.get("storage_account_name")
            if name:
                return str(name)
    return None


def _state_storage(env: paths.Env, cfg: dict) -> str | None:
    """The state bucket / storage account cloudseed created for this environment, by name - judged by the bootstrap
    root's own state on disk, so it is still found after the env was switched from remote to local state."""
    if not (env.bootstrap_dir / "main.tf.json").exists():
        return None
    try:
        st = json.loads((env.bootstrap_dir / "terraform.tfstate").read_text())
    except (OSError, ValueError):
        return None
    if not st.get("resources"):
        return None
    outs = {k: (v or {}).get("value") for k, v in (st.get("outputs") or {}).items()}
    return str(outs.get("bucket") or outs.get("storage_account_name") or _backend_name((cfg.get("state") or {}).get("backend"))
               or "the state storage")


def _handle_state_storage(cloud, env: paths.Env, cfg: dict, args) -> str | None:
    """Delete the remote state storage when asked; otherwise say clearly that it is kept (and billable).
    Returns the name of storage that was kept, so a purge can preserve its Terraform record."""
    storage = _state_storage(env, cfg)
    if not storage:
        if args.purge_state:
            name = _backend_name((cfg.get("state") or {}).get("backend"))
            ui.warn("--purge-state: cloudseed has no record of state storage it created for this environment" +
                    (f"; the backend points at {name} - delete it with your cloud's CLI if you no longer need it." if name else "."))
        return None
    # asked exactly once: --purge-state names what, and a terminal run still confirms it unless --auto-approve (an
    # empty stack has no typed env-id step). "No" keeps the storage - never "Cancelled": the stack may be gone already.
    # Without a terminal and without --auto-approve both destroy paths stopped at their preview before this point.
    if args.purge_state:
        purge_state = args.auto_approve or ui.confirm(
            f"Delete the remote state storage {storage}? Its versioned state history cannot be recovered.", default=False)
    else:
        purge_state = ui.confirm(f"Also delete the remote state storage ({storage})?", default=False)
    if not purge_state:
        ui.warn(f"Remote state storage {storage} kept (it is billable).")
        return storage
    bt = Terraform(env.bootstrap_dir)
    bt.init()
    bt.plan("tfplan", destroy=True)
    try:
        bt.apply("tfplan")
    finally:
        (env.bootstrap_dir / "tfplan").unlink(missing_ok=True)
    if (cfg.get("state") or {}).get("type") == "remote":
        cfg["state"]["backend"] = None
    env.save(cfg)
    ui.ok(f"Remote state storage {storage} deleted.")
    # The stack backend now points at a deleted bucket; drop its local init cache.
    shutil.rmtree(env.stack_dir / ".terraform", ignore_errors=True)
    return None


# ---------------------------------------------------------------- --purge: the local working directory

# Everything cloudseed writes into a working directory (dry-run/ included); a purge of a user-chosen directory removes
# only these. One list with paths.workdir_problem, which accepts exactly these in a new working directory.
_ENV_ENTRIES = paths.ENV_ARTIFACTS


def _is_default_workdir(env: paths.Env) -> bool:
    """cloudseed's own ~/.cloudseed/envs/<id> (not a directory the user chose, and not a symlink to one)."""
    if env.dir.is_symlink():
        return False
    try:
        return env.dir.resolve() == (paths.ENVS_DIR / env.id).resolve()
    except OSError:
        return False


def _protected_dir(d: Path) -> bool:
    """Directories whose contents cloudseed must never delete wholesale: /, the user's home, the cloudseed home and the
    source checkout - or any directory that contains one of them."""
    try:
        rd = d.resolve()
        keep = [Path.home().resolve(), paths.HOME.resolve(), paths.ENVS_DIR.resolve(), paths.REPO_ROOT.resolve()]
    except OSError:
        return True
    return rd == Path(rd.anchor) or any(k == rd or k.is_relative_to(rd) for k in keep)


def _workdir_preexisting(env: paths.Env) -> list[str] | None:
    """What a directory the user chose held before cloudseed used it, as setup recorded it in config.json: [] when it
    held nothing (cloudseed created it, or the user made it empty: workdir_created tells which); None when unknown (the
    default directory, or set up by an older version)."""
    try:
        value = json.loads(env.config_path.read_text()).get("workdir_preexisting")
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    return [str(x) for x in value] if isinstance(value, list) else None


def _workdir_created(env: paths.Env) -> bool | None:
    """Did setup create the --workdir (True), or was it an existing, empty directory the user made (False)? None when
    not recorded (the default directory, or set up by an older version). Recorded since `destroy --purge` removes only
    cloudseed's own entries from any --workdir; older records keep their meaning (see _workdir_owned)."""
    try:
        value = json.loads(env.config_path.read_text()).get("workdir_created")
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    return value if isinstance(value, bool) else None


def _workdir_owned(env: paths.Env) -> bool:
    """Is the whole working directory cloudseed's to delete: the default one, or (recorded by an older version) a
    --workdir that was empty when setup took it? Any other --workdir - one the user made, or one setup created that the
    user has since put their own files into - loses only cloudseed's entries, and goes itself only when nothing else
    is left in it (the manual / `help destroy`: in a directory you chose, only cloudseed's own files are removed)."""
    return _is_default_workdir(env) or (_workdir_preexisting(env) == [] and _workdir_created(env) is None
                                        and not _protected_dir(env.dir))


def _foreign_entries(env: paths.Env) -> list[str]:
    """What the working directory holds besides cloudseed's own entries (files the user added later)."""
    try:
        return sorted(p.name for p in env.dir.iterdir() if p.name not in _ENV_ENTRIES + paths._OS_DEBRIS)
    except OSError:
        return []


def _purge_question(env: paths.Env) -> str:
    if _workdir_owned(env):
        extra = [] if _is_default_workdir(env) else _foreign_entries(env)
        also = (f"; it also holds {', '.join(extra[:5])}{' …' if len(extra) > 5 else ''}, which goes with it" if extra else "")
        return f"Delete the working directory {env.dir}? (config, SSH keys, state files, logs; the audit trail is kept{also})"
    return (f"Delete cloudseed's files from {env.dir}? (config, SSH keys, state files, logs; nothing else in that "
            "directory is touched, and the directory itself goes only when nothing else is left in it)")


# Directories whose every file cloudseed can name: in a directory the user chose, only these files are removed from them
_OWN_FILES = {"ssh": re.compile(r"(id_ed25519|id_rsa|id_ecdsa)(\.pub)?(\.replaced-\d{14})?|known_hosts(\.old)?"),
              "logs": re.compile(r"audit\.jsonl|\d{8}-\d{6}-.*\.log")}


def _adopted_at(env: paths.Env) -> float | None:
    """When cloudseed started using the working directory: config.json's created_at, written by the first save."""
    from datetime import datetime
    try:
        raw = json.loads(env.config_path.read_text()).get("created_at")
        return datetime.fromisoformat(str(raw)).timestamp() if raw else None
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _holds_older_files(path: Path, since: float) -> bool:
    """Does a directory hold a file last changed before `since`, i.e. from before cloudseed used the working directory?
    (Terraform's provider cache is skipped: unpacked plugins keep their release dates.)"""
    for root, dirs, files in os.walk(path):
        dirs[:] = [x for x in dirs if x != ".terraform"]
        for name in files:
            try:
                if os.lstat(os.path.join(root, name)).st_mtime < since:
                    return True
            except OSError:
                continue
    return False


def _remove_env_files(env: paths.Env) -> tuple[list[str], bool]:
    """Delete the working directory - the whole of it when it is cloudseed's: the default one, or a --workdir an older
    version recorded as empty when setup took it (workdir_preexisting == [] without workdir_created). In any other
    directory the user chose - one setup created for them included, since they may have added files later - only what
    cloudseed put there, and the directory only when nothing else is left: entries
    that were there before (as setup recorded them) are the user's and stay - of a pre-existing ssh/ or logs/ only
    cloudseed's own files go; without that record (older versions), a directory with one of cloudseed's names that
    already held files before cloudseed used the working directory - a project's own k8s/ or logs/ - stays. In /, a home
    directory or the source checkout, only cloudseed's config files go. Returns (names left in place, protected dir?)."""
    d = env.dir
    if not d.exists():
        return [], False
    pre = _workdir_preexisting(env)     # read before config.json goes
    created = _workdir_created(env)
    own = _is_default_workdir(env)
    if not own and _protected_dir(d):
        for name in ("config.json", "outputs.json", "inventory.json"):
            (d / name).unlink(missing_ok=True)
        return sorted(n for n in _ENV_ENTRIES if (d / n).exists()), True
    own = own or (pre == [] and created is None and not _protected_dir(d))   # an older record: taken whole, as before
    since = None if own or pre is not None else _adopted_at(env)
    for entry in list(d.iterdir()):
        if not own and entry.name not in _ENV_ENTRIES + paths._OS_DEBRIS:
            continue
        users = not own and pre is not None and entry.name in pre     # it was there before cloudseed
        if users and entry.name not in _OWN_FILES:
            continue
        if entry.is_dir() and not entry.is_symlink():
            if entry.name == "vms" and any(entry.glob("*.vmwarevm")):
                continue   # VMs that are not this environment's (the sweep removed its own): never delete them
            if not own and entry.name in _OWN_FILES and (pre is None or users):   # the private key and the logs, file by file
                for f in list(entry.iterdir()):
                    if _OWN_FILES[entry.name].fullmatch(f.name) and (f.is_file() or f.is_symlink()):
                        f.unlink(missing_ok=True)
                if not users and not any(entry.iterdir()):
                    entry.rmdir()
                continue
            if since is not None and _holds_older_files(entry, since - 2):
                continue
            shutil.rmtree(entry, ignore_errors=True)
        elif not users:
            entry.unlink(missing_ok=True)
    left = sorted(p.name for p in d.iterdir())
    if not left:
        d.rmdir()
    return left, False


def _keep_history(env: paths.Env, keep: Path) -> None:
    """Copy the environment's final inventory and its audit trail into logs/purged/<id> (0600). A second purge of the
    same id adds to what an earlier one kept instead of replacing it: new audit lines are appended (one that is there
    already, e.g. brought back by `cs undo`, is not repeated), and the earlier final inventory is kept under its time."""
    inv = env.dir / "inventory.json"
    if inv.is_file():
        dest = keep / "inventory.json"
        if dest.exists():
            stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(dest.stat().st_mtime))
            older = keep / f"inventory-{stamp}.json"
            n = 1
            while older.exists():
                n += 1
                older = keep / f"inventory-{stamp}-{n}.json"
            dest.rename(older)
        shutil.copy2(inv, dest)
        os.chmod(dest, 0o600)
    trail = env.dir / "logs" / "audit.jsonl"
    if trail.is_file():
        dest = keep / "audit.jsonl"
        try:
            seen = set(dest.read_text(errors="replace").splitlines()) if dest.exists() else set()
            new = [ln for ln in trail.read_text(errors="replace").splitlines() if ln.strip() and ln not in seen]
        except OSError:
            seen, new = set(), []
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            if new:
                fh.write("\n".join(new) + "\n")
        os.chmod(dest, 0o600)
    for f in keep.iterdir():        # what an older version kept world-readable
        if f.is_file():
            os.chmod(f, 0o600)


def _purge_env_dir(env: paths.Env, settings: dict, kept_storage: str | None) -> str | None:
    """--purge: keep the audit trail, park config + SSH keys where `cs undo` finds them (and where they are deleted with
    that undo entry), then remove the working directory. Returns the undo backup directory."""
    keep = paths.HOME / "logs" / "purged" / env.id   # audit copy: what existed and what happened (no secrets)
    keep.mkdir(parents=True, exist_ok=True)
    for d in (keep.parent, keep):   # private like the working directory it comes from (host names, addresses, users)
        os.chmod(d, 0o700)
    _keep_history(env, keep)
    if kept_storage and (env.bootstrap_dir / "terraform.tfstate").exists():
        # the only record of the kept bucket/storage account: without it no cloudseed command can ever delete it
        (keep / "bootstrap").mkdir(exist_ok=True)
        os.chmod(keep / "bootstrap", 0o700)
        for f in ("main.tf.json", "terraform.tfstate", ".terraform.lock.hcl"):
            if (env.bootstrap_dir / f).exists():
                shutil.copy2(env.bootstrap_dir / f, keep / "bootstrap" / f)
                os.chmod(keep / "bootstrap" / f, 0o600)
        ui.info(f"The Terraform record of {kept_storage} is kept at {keep / 'bootstrap'}; delete the storage later with: "
                f"terraform -chdir={keep / 'bootstrap'} init && terraform -chdir={keep / 'bootstrap'} destroy")
    backup_dir = None
    if not os.environ.get("CLOUDSEED_UNDOING"):   # an undo records no entry, so nothing would ever clean the copy up
        ub = undo.BACKUPS / f"{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{env.id}"
        ub.mkdir(parents=True, exist_ok=True)
        for d in (undo.BACKUPS, ub):
            os.chmod(d, 0o700)
        for f in ("config.json", "outputs.json", "inventory.json", "logs/audit.jsonl"):
            if (env.dir / f).exists():     # the history too: `cs undo` brings it back with the environment
                (ub / f).parent.mkdir(parents=True, exist_ok=True)
                os.chmod((ub / f).parent, 0o700)
                shutil.copy2(env.dir / f, ub / f)
                os.chmod(ub / f, 0o600)
        if env.ssh_dir.exists():   # so `cs undo` can re-create the environment with the same keys
            shutil.copytree(env.ssh_dir, ub / "ssh", dirs_exist_ok=True)
        if (keep / "bootstrap").exists() and kept_storage:   # and manage (or delete) the state storage it kept
            shutil.copytree(keep / "bootstrap", ub / "bootstrap", dirs_exist_ok=True)
        backup_dir = str(ub)
    legacy = keep / "ssh"   # older versions kept the private keys here, forever
    if legacy.exists() and not any((e.get("data") or {}).get("backup_dir") == str(keep) for e in undo.entries(env.id)):
        shutil.rmtree(legacy, ignore_errors=True)
    ui.info(f"Audit trail and final inventory kept at {keep}")
    if backup_dir:
        ui.info(f"Configuration and SSH keys kept for `cs undo` in {backup_dir} "
                "(deleted with that undo entry; see: cs undo --list)")
    audit.mark_purged()
    own = _workdir_owned(env)
    left, protected = _remove_env_files(env)
    index = paths._load_index()
    if index.pop(env.id, None) is not None:
        paths._save_index(index)
    if settings.get("current_env") == env.id:   # cluster commands must not keep defaulting to a deleted environment
        settings.pop("current_env", None)
        paths.save_settings(settings)
    if protected:
        ui.warn(f"{env.dir} is (or contains) your home, cloudseed's home or the source checkout, so only config.json, "
                f"outputs.json and inventory.json were removed. cloudseed's other files there: {', '.join(left) or 'none'} - "
                "delete them yourself if you no longer need them.")
    elif not left:
        ui.ok(f"Removed {env.dir}")
    elif own:
        ui.ok(f"Removed {env.id}'s files; kept {env.dir / 'vms'} (it holds VMs that are not {env.id}'s)")
    else:
        ui.ok(f"Removed cloudseed's files from {env.dir}")
        ui.info(f"Left in place (not cloudseed's, or holding files from before cloudseed used this directory): "
                f"{', '.join(left[:8])}" + (" …" if len(left) > 8 else ""))
    return backup_dir


# ---------------------------------------------------------------- vmware teardown

def _prepare_local_teardown() -> None:
    """A VMware destroy needs the hypervisor and vmrest (the provider deletes VMs and the network through them) but not
    the base image: a full prepare() would re-download ~600 MB - and fail offline - for a teardown that never reads it."""
    from . import localvm
    host = localvm.require_host()
    creds = localvm.ensure_vmrest(host)
    os.environ.update(localvm.provider_env(creds))


def _vm_dir(env: paths.Env, cfg: dict, known_vmx=()) -> Path:
    """Where this environment's VM bundles are: the adapter's rule (an old relative / ~ vm_dir whose VMs exist lives
    under <workdir>/stack/<value>, where the provider put it; see VMware.vm_dir_path). The adapter tells that from the
    Terraform state, which a destroy has just emptied (or which was lost): then the VMs recorded before (known_vmx,
    resolved, from the inventory) say it - all of them in one directory under <workdir>/stack, none in the other."""
    probe = dict(cfg, workdir=cfg.get("workdir") or str(env.dir))
    try:
        found = clouds.get("vmware").vm_dir_path(probe)
    except Exception:  # noqa: BLE001 - a broken saved value must never stop a teardown: fall back to the default
        return env.vms_dir
    dirs = {os.path.dirname(os.path.dirname(str(p))) for p in known_vmx if p}
    stack = os.path.realpath(os.path.join(probe["workdir"], "stack")) + os.sep
    if len(dirs) == 1 and os.path.realpath(str(found)) not in dirs and next(iter(dirs)).startswith(stack):
        return Path(next(iter(dirs)))
    return found


def _env_vm_bundles(vm_dir: Path, prefix: str, known_vmx) -> tuple[list[Path], list[Path]]:
    """Split the VM bundles in vm_dir into this environment's and everyone else's. Ours: a name the stack generates
    (<name>-<env>-bastion|vmN|cpN|wkN, matched exactly so env 'dev' never takes env 'dev-2's VMs) or a .vmx Terraform
    recorded for it - the same rule localvm.sweep_vms deletes by."""
    from . import localvm
    if not vm_dir.is_dir():
        return [], []
    known = {localvm.recorded_vmx_path(p) for p in known_vmx if p}   # resolved by the caller (_destroy_everything)
    mine: list[Path] = []
    foreign: list[Path] = []
    for bundle in sorted(vm_dir.glob("*.vmwarevm")):
        if localvm.env_vm_bundle(bundle.name, prefix) or any(os.path.realpath(str(v)) in known for v in bundle.glob("*.vmx")):
            mine.append(bundle)
        else:
            foreign.append(bundle)
    return mine, foreign


def _destroy_local_leftovers(env: paths.Env, cfg: dict, purge: bool, known_vmx=(), vmnet: str | None = None,
                             confirm: bool = False, adopted: bool | None = None, auto_approve: bool = False) -> None:
    """VMware: make sure nothing of THIS environment survives that Terraform did not track - its VM files, the private
    vmnet it created (never an adopted one), and (last one out) the vmrest cloudseed started. VMs and files that are
    not this environment's are never touched."""
    from . import localvm
    host = localvm.detect_host()
    if not host or not host.get("found"):
        return
    vm_dir = _vm_dir(env, cfg, known_vmx)
    prefix = f"{cfg.get('name')}-{cfg.get('env')}"
    own_dir = vm_dir.resolve() == env.vms_dir.resolve()
    mine, foreign = _env_vm_bundles(vm_dir, prefix, known_vmx)
    if mine and confirm:   # the state was empty, so no plan was approved: ask before deleting files
        for b in mine:
            print(f"  - {b}")
        if not ui.confirm(f"Delete these {len(mine)} leftover VM(s) of {env.id}?", default=False):
            mine = []
    removed = localvm.sweep_vms(host, vm_dir, prefix=prefix, known_vmx=known_vmx, remove_dir=own_dir) if mine else []
    if removed:
        ui.ok(f"Removed leftover VM(s): {', '.join(removed)}")
    else:
        ui.info("No VM files left behind.")
    if foreign:
        ui.info(f"Left {len(foreign)} VM(s) in {vm_dir} that are not {env.id}'s: {', '.join(b.name for b in foreign[:5])}")
    if own_dir and not removed:
        try:
            vm_dir.rmdir()   # only when empty; a directory the user chose is never removed
        except OSError:
            pass
    if vmnet is None:
        cached = _cached_outputs(env) or {}
        vmnet, adopted = cached.get("private_vmnet"), cached.get("private_vmnet_adopted")
    if vmnet:
        if localvm.remove_vmnet(host, vmnet, adopted=adopted, env_id=env.id, auto_approve=auto_approve):
            ui.ok(f"Deleted private network {vmnet}")
        elif adopted is False and vmnet not in ("vmnet0", "vmnet1", "vmnet8"):
            ui.info(f"Private network {vmnet} stays configured in VMware (harmless); it is reused next time.")
        else:
            ui.info(f"Private network {vmnet} is left in place (VMware's own, or it existed before {env.id}).")
    if purge and localvm.load_creds() and localvm._port_open():
        # only a vmrest this cloudseed home configured (it holds the credentials), only when nothing else can need it:
        # vmrest is machine-wide - other homes, other tools and running VMs may depend on it
        others = [e for e in paths.Env.list_all() if e.cloud == "vmware" and e.id != env.id]
        running = localvm.vmrun_list(host)
        if others:
            pass   # another VMware environment of this home still needs vmrest
        elif running:
            ui.info(f"vmrest left running: {len(running)} VM(s) still run on this machine.")
        elif localvm.stop_vmrest() is not False:   # False: it was not cloudseed's vmrest (left alone)
            ui.ok("Stopped vmrest (no VMware environments or running VMs left).")
    audit.note(env, "destroy-local-sweep", {"vms_removed": removed, "vmnet": vmnet})


# ---------------------------------------------------------------- Kubernetes: before and after the cluster goes

_DRAIN_POLL = 10   # seconds between checks while cloud load balancers / nodes / volumes go away


def _needs_cluster_drain(cloud, outputs: dict) -> bool:
    # EKS/GKE leave Service/Gateway load balancers, Karpenter nodes and CSI volumes behind; AKS keeps them in its node
    # resource group, which goes with the cluster; vmware's MetalLB addresses are not cloud resources.
    return not cloud.local and cloud.key in ("aws", "gcp") and bool(outputs.get("kubernetes_cluster_name"))


def _wait_gone(list_fn, timeout: int, what: str) -> list[str]:
    deadline = time.monotonic() + timeout
    while True:
        left = list_fn()
        if not left:
            return []
        if time.monotonic() >= deadline:
            ui.warn(f"{what} still present after {timeout}s: {', '.join(left[:5])}" + (" …" if len(left) > 5 else "") +
                    ". If the destroy then fails on the network, delete them in the cloud console and re-run it.")
            return left
        time.sleep(_DRAIN_POLL)


def _drain_cluster_for_destroy(cloud, env: paths.Env, cfg: dict, outputs: dict) -> None:
    """Delete what Kubernetes itself created in the cloud while the cluster, its controllers and the bastion tunnel still
    exist: Karpenter nodes, Service/Gateway/Ingress load balancers and dynamically provisioned volumes. None of it is in
    the Terraform state - left behind it blocks the subnet/VPC deletion and keeps billing. Best effort: never blocks."""
    manual = ("delete Karpenter NodePools, Gateways, Ingresses, Services of type LoadBalancer and PersistentVolumeClaims "
              "yourself (kubectl), then re-run the destroy if it fails on the network")
    ui.header("Removing cloud resources that Kubernetes created (load balancers, nodes, volumes)")
    try:
        kc = services.ensure_kubeconfig(cloud, env, cfg, outputs)
    except (ui.Abort, Exception) as e:  # noqa: BLE001 - an unreachable cluster must not block the teardown
        ui.warn(f"The cluster is not reachable ({getattr(e, 'msg', '') or e}); {manual}.")
        return
    kubectl = deps.find("kubectl")
    if not kubectl:
        ui.warn(f"kubectl is not installed (cloudseed install kubectl); {manual}.")
        return
    kenv = dict(deps.path_env(), KUBECONFIG=str(kc))

    def k(*a: str, timeout: int = 120) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([kubectl, *a], env=kenv, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            return subprocess.CompletedProcess([kubectl, *a], 1, "", str(e))

    def items(*a: str) -> list[dict]:
        proc = k("get", *a, "-o", "json")
        if proc.returncode != 0:
            return []
        try:
            return json.loads(proc.stdout or "{}").get("items") or []
        except ValueError:
            return []

    if k("get", "namespaces", "-o", "name", "--request-timeout=20s", timeout=45).returncode != 0:
        ui.warn(f"The cluster API does not answer; {manual}.")
        return
    crds = set(k("get", "crd", "-o", "name").stdout.split())
    stuck: list[str] = []   # what is still there after the waits (each wait already warned about it)

    def has(crd: str) -> bool:
        return f"customresourcedefinition.apiextensions.k8s.io/{crd}" in crds

    # 1. Karpenter nodes first, while its controller, IAM role and queue still exist to terminate the instances
    if has("nodepools.karpenter.sh"):
        ui.info("Deleting Karpenter NodePools (their EC2 instances are terminated)")
        k("delete", "nodepools.karpenter.sh", "--all", "--wait=false")
        stuck += _wait_gone(lambda: k("get", "nodeclaims.karpenter.sh", "-o", "name").stdout.split(), 600, "Karpenter nodes")
    # 2. load balancers: Gateways first (Envoy Gateway would re-create its Service), then Ingresses and LB Services
    ui.info("Deleting load balancers created by Services, Gateways and Ingresses")
    if has("gateways.gateway.networking.k8s.io"):
        k("delete", "gateways.gateway.networking.k8s.io", "-A", "--all", "--ignore-not-found", "--wait=false")
    k("delete", "ingress", "-A", "--all", "--ignore-not-found", "--wait=false")

    def lb_services() -> list[str]:
        left = []
        for s in items("svc", "-A"):
            if (s.get("spec") or {}).get("type") != "LoadBalancer":
                continue
            meta = s.get("metadata") or {}
            if not meta.get("deletionTimestamp"):
                k("delete", "svc", "-n", meta.get("namespace", "default"), meta.get("name", ""), "--wait=false")
            left.append(f"{meta.get('namespace')}/{meta.get('name')}")
        return left
    # the service.kubernetes.io/load-balancer-cleanup finalizer holds each Service until its cloud LB is gone
    stuck += _wait_gone(lb_services, 300, "Load balancer Services")
    # 3. dynamically provisioned volumes (reclaim policy Delete): release their claims so the CSI driver deletes them
    pvs = [p for p in items("pv") if (p.get("spec") or {}).get("persistentVolumeReclaimPolicy") == "Delete"
           and (p.get("spec") or {}).get("claimRef")]
    if pvs:
        ui.info(f"Deleting {len(pvs)} persistent volume(s) (their disks are billed until deleted)")
        claims = {((p["spec"]["claimRef"].get("namespace") or "default"), p["spec"]["claimRef"].get("name")) for p in pvs}
        # a StatefulSet would re-create the deleted pods and, from its volumeClaimTemplates, fresh claims and disks
        for sts in items("statefulsets", "-A"):
            meta = sts.get("metadata") or {}
            if (sts.get("spec") or {}).get("volumeClaimTemplates"):
                k("delete", "statefulset", "-n", meta.get("namespace", "default"), meta.get("name", ""), "--wait=false")
        for ns, name in sorted(claims):
            k("delete", "pvc", "-n", ns, name, "--ignore-not-found", "--wait=false")
        for pod in items("pods", "-A"):
            meta = pod.get("metadata") or {}
            used = {(meta.get("namespace"), (v.get("persistentVolumeClaim") or {}).get("claimName"))
                    for v in (pod.get("spec") or {}).get("volumes") or []}
            if used & claims:
                k("delete", "pod", "-n", meta.get("namespace", "default"), meta.get("name", ""), "--wait=false")
        names = {p["metadata"]["name"] for p in pvs}
        stuck += _wait_gone(lambda: sorted(names & {p.get("metadata", {}).get("name") for p in items("pv")}), 300,
                            "Persistent volumes")
    if not stuck:
        ui.ok("Kubernetes-created cloud resources removed.")


def _kubeconfig_view(kubectl: str, path: Path) -> dict:
    proc = subprocess.run([kubectl, "config", "view", "-o", "json", "--kubeconfig", str(path)], capture_output=True, text=True)
    try:
        return json.loads(proc.stdout) if proc.returncode == 0 else {}
    except ValueError:
        return {}


# cloudseed's files in <workdir>/k8s (services: kubeconfig, its source stamp, the tunnel; provision: the local cluster's
# join token, inventory, vars and version). Removed one by one: a directory the user chose may hold a project's own k8s/.
_K8S_FILES = ("kubeconfig", "kubeconfig.src", "kubeconfig.merge", "merged.json", "tunnel.pid", "token", "vars.json",
              "inventory.ini", "version")
_KUBE_KINDS = ("contexts", "clusters", "users")


def _merged_record_path(env: paths.Env) -> Path:
    return env.dir / "k8s" / "merged.json"


def _merged_record(env: paths.Env) -> dict:
    """What `cs k8s kubeconfig` merged into the user's kubeconfig: {files: [...], contexts/clusters/users: [...]}."""
    try:
        data = json.loads(_merged_record_path(env).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _record_merged_kubeconfig(cloud: clouds.Cloud, env: paths.Env, target: Path) -> None:
    """Remember the kubeconfig entries `cs k8s kubeconfig` put into `target`, so the teardown that deletes the cluster
    removes exactly those (and never an unrelated entry of the same name). Best effort: needs kubectl."""
    kubectl = deps.find("kubectl")
    own = services.kubeconfig_path(env)
    if not kubectl or not own.exists() or not target.exists():
        return
    mine = _kubeconfig_view(kubectl, own)
    if cloud.local:     # merged under vmware-<env> names (services.kubeconfig_local), not the cluster's own "default"
        mine = services._rename_kubeconfig(mine, f"vmware-{env.name}")
    theirs = _kubeconfig_view(kubectl, target)
    rec = _merged_record(env)
    for kind in _KUBE_KINDS:
        present = {x.get("name") for x in theirs.get(kind) or [] if x.get("name")}
        rec[kind] = sorted(set(rec.get(kind) or []) | ({x.get("name") for x in mine.get(kind) or []} & present))
    rec["files"] = sorted(set(rec.get("files") or []) | {str(target)})
    path = _merged_record_path(env)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(rec, fh, indent=2)


def _forget_cluster_access(env: paths.Env) -> None:
    """The cluster is gone: close its API tunnel, remove the contexts/clusters/users that `cs k8s kubeconfig` merged into
    the user's kubeconfig for it, and drop the environment's own cluster files (kubeconfig, join token, inventory ...),
    so nothing ever hands out a dead cluster's kubeconfig or re-joins new nodes with its token."""
    k8s_dir = env.dir / "k8s"
    if (k8s_dir / "tunnel.pid").exists():
        services.close_tunnel(env)
    own = services.kubeconfig_path(env)
    rec = _merged_record(env)
    kubectl = deps.find("kubectl")
    if kubectl:
        names = {kind: set(rec.get(kind) or []) for kind in _KUBE_KINDS}
        if env.cloud != "vmware" and own.exists():
            # a managed cluster is merged under the names its own kubeconfig has (the same cloud CLI call writes both)
            mine = _kubeconfig_view(kubectl, own)
            for kind in _KUBE_KINDS:
                names[kind] |= {x.get("name") for x in mine.get(kind) or [] if x.get("name")}
        elif env.cloud == "vmware" and not rec:
            # merged by an older version (no record): always as vmware-<env>. Never by the cluster's own names
            # ("default", "kubernetes-admin"), which may well be another cluster's entries in the user's file.
            names["contexts"].add(f"vmware-{env.name}")
            names["clusters"].add(f"vmware-{env.name}")
            names["users"].add(f"vmware-{env.name}")
        first = (os.environ.get("KUBECONFIG") or "").split(os.pathsep)[0]
        candidates = [Path(f) for f in rec.get("files") or []] + ([Path(first).expanduser()] if first else []) + \
            [Path.home() / ".kube" / "config"]
        if any(names.values()):
            for target in dict.fromkeys(candidates):
                if target.exists() and not (own.exists() and target.resolve() == own.resolve()):
                    _drop_kubeconfig_entries(kubectl, target, names, env.id)
    for name in _K8S_FILES:
        (k8s_dir / name).unlink(missing_ok=True)
    try:
        k8s_dir.rmdir()     # only when nothing else is in it
    except OSError:
        pass


def _drop_kubeconfig_entries(kubectl: str, target: Path, names: dict, env_id: str) -> None:
    theirs = _kubeconfig_view(kubectl, target)
    contexts = [c for c in theirs.get("contexts") or [] if c.get("name") in names["contexts"]]
    if not contexts:
        return
    run = lambda *a: subprocess.run([kubectl, "config", *a, "--kubeconfig", str(target)], capture_output=True, text=True)  # noqa: E731
    gone = {c["name"] for c in contexts}
    remaining = [c for c in theirs.get("contexts") or [] if c.get("name") not in gone]
    still_used = {(c.get("context") or {}).get(x) for c in remaining for x in ("cluster", "user")}
    for c in sorted(gone):
        run("delete-context", c)
    for cl in sorted(names["clusters"] & {x.get("name") for x in theirs.get("clusters") or []} - still_used):
        run("delete-cluster", cl)
    for u in sorted(names["users"] & {x.get("name") for x in theirs.get("users") or []} - still_used):
        if run("delete-user", u).returncode != 0:
            run("unset", f"users.{u}")
    if theirs.get("current-context") in gone:
        run("unset", "current-context")
    ui.info(f"Removed {env_id}'s cluster from {target} (context {', '.join(sorted(gone))})")


def _has_cluster(env: paths.Env) -> bool:
    out = _cached_outputs(env)
    return bool(out.get("kubernetes_cluster_name") or out.get("kubernetes_control_plane_ips"))


def _k8s_enabled(env: paths.Env) -> bool:
    """enable_kubernetes is on in the saved settings (a dry run, --plan-only or failed apply leaves it on without a
    cluster). An unreadable config.json or a value like "false" reads as off."""
    cfg, _ = env.try_load()
    return _lenient_bool(((cfg or {}).get("vars") or {}).get("enable_kubernetes", False), False)


def _no_cluster_hint(env: paths.Env) -> str:
    """How to get a cluster into `env`: create the one its settings already enable, or enable one (the same advice
    services.ensure_kubeconfig and `cs k8s info` give; asking to 'enable' it again would suggest the --var did not stick)."""
    if _k8s_enabled(env):
        return (f"Kubernetes is enabled for {env.id} but not created yet: cs setup {env.cloud} --env {env.name} "
                "(without --dry-run / --plan-only)")
    return f"Add one: cs setup {env.cloud} --env {env.name} --var enable_kubernetes=true"


def _no_cluster_among(envs: list[paths.Env]) -> str:
    """Advice when none of `envs` has a cluster: create the ones already enabled, else add one."""
    enabled = [e for e in envs if _k8s_enabled(e)]
    if len(enabled) == 1:
        return _no_cluster_hint(enabled[0])
    if enabled:
        return (f"Kubernetes is enabled but not created yet in {', '.join(e.id for e in enabled)}: "
                "cs setup <cloud> --env <name> (without --dry-run / --plan-only)")
    clouds_ = sorted({e.cloud for e in envs})
    cloud_arg = clouds_[0] if len(clouds_) == 1 else "<cloud>"
    return f"Add one: cs setup {cloud_arg} --env <name> --var enable_kubernetes=true"


def _check_env_name(name: str | None) -> None:
    """--env names a directory under the cloudseed home: '../x' and other odd strings never get that far."""
    if name and _validate_name(name):
        raise ui.Abort(f"Invalid environment name '{name}': {_validate_name(name)}")


def _best_effort(fn):
    """Run a step whose failure the caller reports as one warning: returns (result, None) or (None, reason). An Abort
    prints its ✖ line the moment it is raised, so stderr is held back while the step runs."""
    import contextlib
    import io
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return fn(), None
    except ui.Abort as e:
        return None, (e.msg or "failed").strip()


def _pick_cluster_env(cloud_key: str | None, env_name: str | None, settings: dict,
                      prompt: bool = True) -> tuple[paths.Env | None, str | None, str]:
    """Which environment with a cluster is meant: (env, None, "") when one is, (None, None, "") when the usual
    `<cloud> [--env]` resolution should decide, and (None, problem, kind) when nothing fits, kind being "no-cluster",
    "unknown" or "several". An explicit choice (arguments or `cs env use`) is never silently replaced by another cluster."""
    envs = paths.Env.list_all()
    known = {e.id: e for e in envs}
    clusters = [e for e in envs if _has_cluster(e)]
    listing = ", ".join(e.id for e in clusters)
    current = settings.get("current_env")
    if current and current not in known:
        ui.warn(f"The current environment {current} (cs env use) no longer exists; ignoring it. Clear it with: cs env clear")
        current = None
    if not cloud_key and not env_name and current:
        cur = known[current]
        if _has_cluster(cur):
            return cur, None, ""
        return None, (f"{current} is the current environment (cs env use) but has no Kubernetes cluster yet. {_no_cluster_hint(cur)}"
                      + (f"; or switch: cs env use <id> (clusters: {listing})" if clusters else "") + "; or: cs env clear"), "no-cluster"
    cands = [e for e in clusters if (not cloud_key or e.cloud == cloud_key) and (not env_name or e.name == env_name)]
    if current and any(e.id == current for e in cands):
        return known[current], None, ""
    if len(cands) == 1:
        return cands[0], None, ""
    if not cands:
        if cloud_key and not env_name:
            mine = [e for e in envs if e.cloud == cloud_key]
            if current and any(e.id == current for e in mine):
                return known[current], None, ""   # `cs env use` is honoured: the command says what that env lacks
            if len(mine) > 1:   # never fall through to a 'dev' default that may not exist ("aws-dev does not exist")
                return None, (f"No {cloud_key} environment has a Kubernetes cluster yet ({', '.join(e.id for e in mine)}). "
                              f"{_no_cluster_among(mine)}" + (f"  (clusters: {listing})" if clusters else "")), "no-cluster"
            return None, None, ""   # 0 or 1 environment of that cloud: the usual resolution names it (or says it is missing)
        if cloud_key:
            return None, None, ""
        if env_name:
            same = [e for e in envs if e.name == env_name]
            if len(same) == 1:
                return None, (f"{same[0].id} has no Kubernetes cluster yet. {_no_cluster_hint(same[0])}"
                              + (f"  (clusters: {listing})" if clusters else "")), "no-cluster"
            if same:
                return None, (f"{', '.join(e.id for e in same)} have no Kubernetes cluster yet. {_no_cluster_among(same)}"
                              + (f"  (clusters: {listing})" if clusters else "")), "no-cluster"
            return None, (f"No environment named '{env_name}'. " + (f"Clusters: {listing}" if clusters else f"Known: {', '.join(known) or 'none'}")), "unknown"
        return None, ("No environment with a Kubernetes cluster yet. " + (_no_cluster_among(envs) if envs else
                      "Create one with: cs setup <cloud> --env <name> --var enable_kubernetes=true")
                      + (f"  (environments: {', '.join(known)})" if known else "")), "no-cluster"
    if prompt and ui.interactive():
        labels = {e.id: e.try_load()[0] for e in cands}   # one broken config.json must not break the choice
        key = ui.choose("Which cluster?", [(e.id, f"{e.id}  ({labels[e.id].get('name', '?')} · {labels[e.id].get('region', '?')})") for e in cands])
        chosen = known[key]
        settings["current_env"] = chosen.id
        paths.save_settings(settings)
        ui.info(f"Current environment is now {chosen.id}  (cs env use <id> to change · cs env clear)")
        return chosen, None, ""
    return None, (f"Several clusters exist: {', '.join(e.id for e in cands)}. Pick one with `cs env use <id>` "
                  "or pass <cloud> --env <name>."), "several"


def _resolve_cluster_env(args, settings, vm_image: bool = True) -> tuple[clouds.Cloud, paths.Env, dict, dict]:
    """Which environment/cluster is the user 'in'? Explicit args > `cs env use` > the only cluster > ask.

    vm_image=False (cs node): a local environment is loaded like a read-only command - the saved base_disk, no
    hypervisor, vmrest or image work (the full prepare re-downloads a cleaned base image, ~600 MB, and fails offline).
    The caller does that work only on the path that really creates or deletes a VM, after the node name and the
    cluster were checked (a typo never starts vmrest)."""
    cloud_key, env_name = getattr(args, "cloud", None), getattr(args, "env", None)
    _check_env_name(env_name)
    if not (cloud_key and env_name):
        chosen, problem, _kind = _pick_cluster_env(cloud_key, env_name, settings)
        if problem:
            raise ui.Abort(problem)
        if chosen is not None:
            args.cloud, args.env = chosen.cloud, chosen.name
    if vm_image:
        cloud, env, cfg = _load_env(args)
    else:
        view = argparse.Namespace(**vars(args))
        view.node_cmd = None   # loaded like a read-only node command (_touches_vms): saved base_disk, no download
        cloud, env, cfg = _load_env(view)
    outputs = _outputs_fresh(cloud, env, cfg)
    return cloud, env, cfg, outputs


def _resolve_plain_env(args, settings, what: str, prefer_cluster: bool = False) -> None:
    """Environment for commands that work on any environment (finops, scan host/cloud/fips/stig/all/reports):
    <cloud> [--env] > --env NAME > `cs env use` > the only environment > (the only cluster) > ask. Sets args.cloud/env."""
    _check_env_name(getattr(args, "env", None))
    if getattr(args, "cloud", None):
        return
    envs = paths.Env.list_all()
    known = {e.id: e for e in envs}
    if args.env:   # a name, or an id as `cs list` shows it (one wording with the env-scoped commands' --env)
        problem = _env_name_problem(args.env, envs, what)
        if problem:
            raise ui.Abort(problem)
        e = next(e for e in envs if args.env in (e.name, e.id))
        args.cloud, args.env = e.cloud, e.name
        return
    current = settings.get("current_env")
    if current and current not in known:
        ui.warn(f"The current environment {current} (cs env use) no longer exists; ignoring it. Clear it with: cs env clear")
        current = None
    clusters = [e for e in envs if _has_cluster(e)]
    if current:
        chosen = known[current]
    elif len(envs) == 1:
        chosen = envs[0]
    elif prefer_cluster and len(clusters) == 1:
        chosen = clusters[0]
    elif envs and ui.interactive():
        chosen = known[ui.choose("Which environment?", [(e.id, e.id) for e in envs])]
    else:
        raise ui.Abort("Pass <cloud> --env <name> (or pick one with `cs env use <id>`)."
                       + (f" Environments: {', '.join(known)}" if known else " No environment yet: cs setup <cloud>"))
    args.cloud, args.env = chosen.cloud, chosen.name


def _env_use_target(given: str, envs: dict) -> str:
    """The id `cs env use` means: an id as `cs list` shows it, else a name that exactly one environment has (`cs env use
    prod` with only aws-prod). Anything else is refused with the candidates (did-you-mean for a typo)."""
    if given in envs:
        return given
    named = [i for i, e in envs.items() if e.name == given]
    if len(named) == 1:
        ui.info(f"'{given}' is the environment {named[0]}.")
        return named[0]
    if named:
        raise ui.Abort(f"'{given}' names several environments: {', '.join(named)}. Pick one: cs env use <id>", code=2)
    import difflib
    near = difflib.get_close_matches(given, list(envs) + [e.name for e in envs.values()], n=1, cutoff=0.6)
    near_id = next((i for i, e in envs.items() if near and near[0] in (i, e.name)), None)
    raise ui.Abort(f"Unknown environment '{given}'" + (f" (did you mean {near_id}?)" if near_id else "")
                   + f". Known: {', '.join(envs) or 'none'}", code=2)


def cmd_env(args, settings) -> int:
    envs = {e.id: e for e in paths.Env.list_all()}
    given = getattr(args, "id", None)
    # an id only goes with `use`: a `show` or `clear` must never quietly ignore it (checked before any undo record)
    if args.env_cmd == "show" and given:
        raise ui.Abort(f"cs env show takes no environment (got '{given}'). To switch: cs env use {given}", code=2)
    current = settings.get("current_env")
    # the current one by its id, or by a name only it has (the names `cs env use` accepts)
    if args.env_cmd == "clear" and given and given != current and [i for i, e in envs.items() if e.name == given] != [current]:
        raise ui.Abort(f"{given} is not the current environment ({current or 'none is set'}); "
                       "nothing was cleared. cs env clear takes no environment, or the current one.", code=2)
    if args.env_cmd == "use":
        if not args.id:
            if not envs:
                raise ui.Abort("Usage: cs env use <id>. No environments yet: create one with cloudseed setup <cloud>", code=2)
            if not ui.interactive():
                raise ui.Abort("Which environment? Usage: cs env use <id>. Known: " + ", ".join(envs), code=2)
            args.id = ui.choose("Which environment should be the current one?", [(k, k) for k in envs], default=settings.get("current_env"))
        args.id = _env_use_target(args.id, envs)
        if settings.get("current_env") == args.id:   # a no-op changes nothing and takes no undo slot
            ui.ok(f"Current environment: {args.id} (unchanged)")
            return 0
    if args.env_cmd == "clear" and not settings.get("current_env"):
        ui.info("No current environment is set; nothing to clear.")
        return 0
    if args.env_cmd in ("use", "clear"):
        # a run of switches (here or in the web console) takes one undo slot that goes back to before the whole run
        undo.record(undo.GLOBAL, f"env {args.env_cmd} {args.id if args.env_cmd == 'use' else ''}".strip(), "settings-restore",
                    undo.snapshot_settings(["current_env"]), coalesce="current_env")
    if args.env_cmd == "use":
        settings["current_env"] = args.id
        paths.save_settings(settings)
        ui.ok(f"Current environment: {args.id}")
        chosen = envs[args.id]
        if not _has_cluster(chosen):
            how = (f"Kubernetes is enabled but not created yet: cs setup {chosen.cloud} --env {chosen.name}" if _k8s_enabled(chosen)
                   else f"add one: cs setup {chosen.cloud} --env {chosen.name} --var enable_kubernetes=true")
            ui.info(f"{args.id} has no Kubernetes cluster yet: cluster commands (kubectl, helm, platform, node, chaos, dr) will say so "
                    f"until it has one ({how}); finops, scan and managed profiles use it as it is.")
        return 0
    if args.env_cmd == "clear":
        settings.pop("current_env", None)
        paths.save_settings(settings)
        ui.ok("Current environment cleared (commands will pick the only cluster or ask).")
        return 0
    cur = settings.get("current_env")
    rows = [(e.id + (ui.style("  ◀ current", "brand") if e.id == cur else ""), ("cluster" if _has_cluster(e) else ui.dim("no cluster")))
            for e in envs.values()]
    if cur and cur not in envs:   # a short key keeps the panel's columns aligned; the explanation is the value
        rows.append((ui.style(cur, "rose") + ui.dim("  ◀ current"), ui.dim("no longer exists · cs env clear")))
    ui.panel("Environments", rows or [ui.dim("none yet")])
    print(ui.dim("  cs env use <id>   ·   cs env clear"))
    return 0


# ---------------------------------------------------------------- nodes

def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"'{value}' is not a whole number")
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more (got {n})")
    return n


def _non_negative_int(value: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"'{value}' is not a whole number")
    if n < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or more (got {n})")
    return n


def _finops_days(value: str) -> int:
    n = _positive_int(value)
    if n > 365:
        raise argparse.ArgumentTypeError(f"at most 365 days (the cloud billing APIs cover about a year; got {n})")
    return n


def _node_json(kubectl: str, kenv: dict, name: str) -> dict:
    """The Node object, or a clean abort when the name is not a node of this cluster (typos never reach a drain)."""
    proc = subprocess.run([kubectl, "get", "node", name, "-o", "json"], env=kenv, capture_output=True, text=True)
    if proc.returncode != 0:
        if "NotFound" in proc.stderr or "not found" in proc.stderr:
            raise ui.Abort(f"No node '{name}' in this cluster. See: cs node list")
        raise ui.Abort(f"Could not read node '{name}': {secrets.redact(proc.stderr.strip()[-300:])}")
    try:
        return json.loads(proc.stdout or "{}")
    except ValueError:
        return {}


def _drain_node(kubectl: str, kenv: dict, name: str) -> None:
    rc = subprocess.call([kubectl, "drain", name, "--ignore-daemonsets", "--delete-emptydir-data", "--force", "--timeout=300s"], env=kenv)
    if rc != 0:
        subprocess.call([kubectl, "uncordon", name], env=kenv)
        raise ui.Abort(f"Could not drain {name} (exit {rc}); usually a PodDisruptionBudget or a pod that cannot be evicted. "
                       "The node was uncordoned and nothing was deleted. Fix the cause and run the command again.")


def _delete_node_object(kubectl: str, kenv: dict, name: str) -> None:
    rc = subprocess.call([kubectl, "delete", "node", name, "--ignore-not-found"], env=kenv)
    if rc != 0:
        raise ui.Abort(f"Could not delete node {name} from the cluster (exit {rc}).")


def _ready_nodes(kubectl: str, kenv: dict, selector: str | None = None) -> int:
    proc = subprocess.run([kubectl, "get", "nodes", "-o", "json"] + (["-l", selector] if selector else []), env=kenv, capture_output=True, text=True)
    try:
        items = json.loads(proc.stdout or "{}").get("items") or []
    except ValueError:
        return 0
    return sum(1 for n in items if any(c.get("type") == "Ready" and c.get("status") == "True" for c in (n.get("status") or {}).get("conditions") or []))


def _wait_ready_nodes(kubectl: str, kenv: dict, want: int, selector: str | None, timeout: int = 900) -> int:
    deadline = time.time() + timeout
    with ui.Spinner(f"Waiting for {want} Ready node(s)") as sp:
        while True:
            ready = _ready_nodes(kubectl, kenv, selector)
            if ready >= want or time.time() > deadline:
                sp.done_text = f"{ready} node(s) Ready" if ready >= want else ""
                return ready
            sp.update(f"Waiting for {want} Ready node(s) · {ready} so far")
            time.sleep(10)


def _cloud_cli(cmd: list[str], what: str, parse: bool = False, show: bool = True, env: dict | None = None):
    """Run a cloud CLI call (aws / gcloud / az) with the user's credentials; abort with its error when it fails. `env`:
    the process environment (services.cloud_cli_env: AWS FIPS mode sends every call to the FIPS endpoints)."""
    if show:
        print(ui.dim("  $ " + " ".join(secrets.redact(c) for c in [Path(cmd[0]).name, *cmd[1:]])))
    audit.write("$ " + " ".join(secrets.redact(c) for c in cmd))
    proc = subprocess.run(cmd, env=env or deps.path_env(), capture_output=True, text=True)
    if proc.returncode != 0:
        raise ui.Abort(f"{what} failed: " + secrets.redact((proc.stderr or proc.stdout or "").strip()[-500:]))
    if not parse:
        return proc.stdout
    try:
        return json.loads(proc.stdout or "null")
    except ValueError:
        raise ui.Abort(f"{what}: unexpected output from {Path(cmd[0]).name}")


def _pick_pool(names: list[str], cluster: str, managed: str | None = None) -> str:
    """The node pool cloudseed manages: the one the stack's output names (EKS kubernetes_node_group_name, GKE
    kubernetes_node_pool, which can be plain 'default' for long names), else the only '*-default' pool, else the only
    pool."""
    names = [n for n in names if n]
    if managed and managed in names:
        return managed
    default = [n for n in names if n.endswith("-default")]
    if len(default) == 1:
        return default[0]
    if len(names) == 1:
        return names[0]
    raise ui.Abort(f"Cannot tell which node pool of {cluster} cloudseed manages (found: {', '.join(names) or 'none'}).")


def _managed_pool(cloud, env, cfg: dict, outputs: dict) -> dict:
    """The managed node pool as the cloud reports it now. Terraform ignores the pool size (the autoscaler owns it), so
    `cs node` scales through the cloud's own API and keeps count/min/max in config.json in step with it."""
    cluster = outputs.get("kubernetes_cluster_name")
    if not cluster:
        raise ui.Abort(f"No cluster in {env.id}: cs setup {cloud.key} --env {env.name} --var enable_kubernetes=true")
    tool = {"aws": "aws", "gcp": "gcloud", "azure": "az"}[cloud.key]
    binary = deps.find(tool)
    if not binary:
        raise ui.Abort(f"Install {tool} first: cloudseed install {tool}")
    # the cloud CLI's process environment (AWS FIPS: the FIPS endpoints), kept with the pool for every later call; never
    # logged (audit.note records named fields only)
    pool: dict = {"cloud": cloud.key, "tool": binary, "cluster": cluster, "env": services.cloud_cli_env(cloud.key, cfg, outputs)}
    v = cfg.get("vars") or {}
    if cloud.key == "aws":
        pool["base"] = ["--region", cfg["region"]] + (["--profile", v["profile"]] if v.get("profile") else [])
        groups = (_cloud_cli([binary, "eks", "list-nodegroups", "--cluster-name", cluster, *pool["base"], "--output", "json"],
                             "Listing the EKS node groups", parse=True, show=False, env=pool["env"]) or {}).get("nodegroups") or []
        pool["name"] = _pick_pool(groups, cluster, outputs.get("kubernetes_node_group_name"))
        ng = (_cloud_cli([binary, "eks", "describe-nodegroup", "--cluster-name", cluster, "--nodegroup-name", pool["name"], *pool["base"], "--output", "json"],
                         "Reading the EKS node group", parse=True, show=False, env=pool["env"]) or {}).get("nodegroup") or {}
        sc = ng.get("scalingConfig") or {}
        pool.update(size=int(sc.get("desiredSize") or 0), min=int(sc.get("minSize") or 0), max=int(sc.get("maxSize") or 0),
                    selector=f"eks.amazonaws.com/nodegroup={pool['name']}")
    elif cloud.key == "gcp":
        pool["project"] = v.get("project_id", "")
        pool["base"] = ["--location", outputs.get("kubernetes_location") or v.get("zone", ""), "--project", pool["project"]]
        pools = _cloud_cli([binary, "container", "node-pools", "list", "--cluster", cluster, *pool["base"], "--format", "json"],
                           "Listing the GKE node pools", parse=True, show=False, env=pool["env"]) or []
        pool["name"] = _pick_pool([p.get("name", "") for p in pools], cluster, outputs.get("kubernetes_node_pool"))
        spec = next(p for p in pools if p.get("name") == pool["name"])
        auto = spec.get("autoscaling") or {}
        pool["migs"] = list(spec.get("instanceGroupUrls") or [])
        size = 0
        for url in pool["migs"]:
            zone, mig = _mig_of(url)
            d = _cloud_cli([binary, "compute", "instance-groups", "managed", "describe", mig, "--zone", zone, "--project", pool["project"], "--format", "json"],
                           "Reading the node pool's instance group", parse=True, show=False, env=pool["env"]) or {}
            size += int(d.get("targetSize") or 0)
        pool.update(size=size, min=int(auto.get("minNodeCount") or 0), max=int(auto.get("maxNodeCount") or size),
                    selector=f"cloud.google.com/gke-nodepool={pool['name']}")
    else:
        pool["base"] = ["--resource-group", outputs.get("resource_group_name", ""), "--cluster-name", cluster] + \
                       (["--subscription", v["subscription_id"]] if v.get("subscription_id") else [])
        pool["name"] = "system"   # the AKS default node pool cloudseed creates
        p = _cloud_cli([binary, "aks", "nodepool", "show", *pool["base"], "--name", pool["name"], "-o", "json"],
                       "Reading the AKS node pool", parse=True, show=False, env=pool["env"]) or {}
        pool.update(size=int(p.get("count") or 0), min=int(p.get("minCount") or 0), max=int(p.get("maxCount") or 0),
                    selector=f"kubernetes.azure.com/agentpool={pool['name']}")
    return pool


def _mig_of(url: str) -> tuple[str, str]:
    """(zone, name) of a GKE node pool instance group URL: .../zones/<zone>/instanceGroupManagers/<name>."""
    parts = url.rstrip("/").split("/")
    zone = parts[parts.index("zones") + 1] if "zones" in parts else ""
    return zone, parts[-1]


def _set_pool(pool: dict, size: int, lo: int, hi: int) -> None:
    """Scale the managed pool to `size` nodes with autoscaler bounds lo..hi (bounds first, so the size is allowed)."""
    b, c, name, base, penv = pool["tool"], pool["cluster"], pool["name"], pool["base"], pool.get("env")
    if pool["cloud"] == "aws":
        if (size, lo, hi) != (pool["size"], pool["min"], pool["max"]):
            _cloud_cli([b, "eks", "update-nodegroup-config", "--cluster-name", c, "--nodegroup-name", name,
                        "--scaling-config", f"minSize={lo},maxSize={hi},desiredSize={size}", *base, "--output", "json"], "Updating the EKS node group",
                       env=penv)
            with ui.Spinner("Waiting for the node group update to finish"):
                _cloud_cli([b, "eks", "wait", "nodegroup-active", "--cluster-name", c, "--nodegroup-name", name, *base],
                           "Waiting for the EKS node group", show=False, env=penv)
    elif pool["cloud"] == "gcp":
        if (lo, hi) != (pool["min"], pool["max"]):
            _cloud_cli([b, "container", "clusters", "update", c, "--node-pool", name, "--enable-autoscaling",
                        "--min-nodes", str(lo), "--max-nodes", str(hi), *base, "--quiet"], "Updating the GKE autoscaling limits", env=penv)
        if size != pool["size"]:
            _cloud_cli([b, "container", "clusters", "resize", c, "--node-pool", name, "--num-nodes", str(size), *base, "--quiet"],
                       "Resizing the GKE node pool", env=penv)
    else:
        # AKS refuses a manual count on an autoscaled pool: the autoscaler enforces the bounds (a raised minimum adds
        # nodes now; a lowered one lets it remove idle nodes later).
        if (lo, hi) != (pool["min"], pool["max"]):
            _cloud_cli([b, "aks", "nodepool", "update", *base, "--name", name, "--update-cluster-autoscaler",
                        "--min-count", str(lo), "--max-count", str(hi), "-o", "none"], "Updating the AKS autoscaler limits", env=penv)
    pool.update(size=size, min=lo, max=hi)


def _remove_pool_instance(pool: dict, node: dict, name: str) -> None:
    """Delete exactly the machine behind this node and shrink the pool by one (never an arbitrary instance)."""
    pid = str((node.get("spec") or {}).get("providerID") or "")
    b, base, penv = pool["tool"], pool["base"], pool.get("env")
    if pool["cloud"] == "aws":
        iid = pid.rstrip("/").rsplit("/", 1)[-1]
        if not pid.startswith("aws://") or not iid.startswith("i-"):
            raise ui.Abort(f"{name} is not an EC2 instance of the node group (providerID '{pid}'); nothing was deleted.")
        _cloud_cli([b, "autoscaling", "terminate-instance-in-auto-scaling-group", "--instance-id", iid,
                    "--should-decrement-desired-capacity", *base, "--output", "json"], f"Terminating {iid}", env=penv)
    elif pool["cloud"] == "gcp":
        m = re.match(r"gce://([^/]+)/([^/]+)/([^/]+)$", pid)
        if not m:
            raise ui.Abort(f"{name} is not a Compute Engine instance of the node pool (providerID '{pid}'); nothing was deleted.")
        zone, instance = m.group(2), m.group(3)
        mig = next((_mig_of(u)[1] for u in pool.get("migs", []) if _mig_of(u)[0] == zone), None)
        if not mig:
            raise ui.Abort(f"No instance group of pool {pool['name']} in zone {zone}; nothing was deleted.")
        _cloud_cli([b, "compute", "instance-groups", "managed", "delete-instances", mig, "--instances", instance,
                    "--zone", zone, "--project", pool["project"], "--quiet"], f"Deleting {instance}", env=penv)
    else:
        if "virtualMachineScaleSets" not in pid:
            raise ui.Abort(f"{name} is not a scale-set machine of pool {pool['name']} (providerID '{pid}'); nothing was deleted.")
        _cloud_cli([b, "aks", "nodepool", "delete-machines", *base, "--nodepool-name", pool["name"], "--machine-names", name, "-o", "none"],
                   f"Deleting machine {name}", env=penv)
    pool["size"] = max(0, pool["size"] - 1)


def _sync_pool_cfg(cfg: dict, pool: dict) -> None:
    """Keep config.json in step with the live pool so a later apply converges to the same count/min/max. The saved count
    is never 0 (an autoscaler may have emptied a pool whose minimum is 0): every stack requires kubernetes_node_count >= 1
    (EKS/AKS add-ons need a node), so a later apply would stop at variable validation."""
    cfg.setdefault("vars", {})["kubernetes_node_count"] = pool["size"]
    if not pool["size"]:   # emptied by the autoscaler: the pool's floor, at least one node
        cfg["vars"]["kubernetes_node_count"] = max(1, int(pool["min"] or 0))
    for key, val in (("kubernetes_node_min", pool["min"]), ("kubernetes_node_max", pool["max"])):
        if key in cfg["vars"]:
            cfg["vars"][key] = val
        else:
            cfg.setdefault("extra_vars", {})[key] = val


def _scale_undo(cloud, env, pool: dict) -> list[str]:
    # --count takes 1 or more: a pool the autoscaler had emptied comes back at one node (its minimum stays as it was)
    return ["node", "scale", cloud.key, "--env", env.name, "--count", str(max(1, pool["size"])), "--min", str(pool["min"]),
            "--max", str(max(1, pool["max"])), "-y", "--auto-approve"]


def _node_managed(args, cloud, env, cfg: dict, outputs: dict, kubectl: str, kenv: dict) -> int:
    """cs node add|remove|scale on EKS/GKE/AKS."""
    sub = args.node_cmd
    pool = _managed_pool(cloud, env, cfg, outputs)
    before = dict(pool)
    if sub == "remove":
        name = args.name
        node = _node_json(kubectl, kenv, name)
        if pool["size"] <= 1:
            raise ui.Abort(f"{name} is the last node of pool {pool['name']}; removing it leaves nothing to run workloads. "
                           f"Add a node first (cs node add) or destroy the cluster.")
        lo = min(pool["min"], pool["size"] - 1)
        _approve(f"Drain {name} and delete its machine (pool {pool['name']}: {pool['size']} -> {pool['size'] - 1} node(s))?", args.auto_approve)
        _drain_node(kubectl, kenv, name)
        try:
            if lo != pool["min"]:
                _set_pool(pool, pool["size"], lo, pool["max"])   # lower the floor first, or the autoscaler adds a node back
            _remove_pool_instance(pool, node, name)
        except BaseException:
            subprocess.call([kubectl, "uncordon", name], env=kenv)   # the machine is still there: let it take pods again
            raise
        _delete_node_object(kubectl, kenv, name)
        summary = f"node remove {name} on {env.id} (pool {pool['name']} {before['size']} -> {pool['size']})"
        done = f"{name} drained and its machine deleted; pool {pool['name']} is now {pool['size']} node(s) (autoscaler {pool['min']}..{pool['max']})."
    else:
        if sub == "add":
            size = before["size"] + (args.count or 1)
            lo, hi = max(before["min"], size), max(before["max"], size)
        else:   # scale
            if not args.count:
                raise ui.Abort(f"cs node scale {cloud.key} --env {env.name} --count N [--min N] [--max N]")
            size = args.count
            lo = args.min if args.min is not None else size
            hi = args.max if args.max is not None else max(before["max"], size)
        if cloud.key == "azure" and lo < 1:
            raise ui.Abort("The AKS system pool needs at least one node (--min 1 or more).")
        if not lo <= size <= hi:
            raise ui.Abort(f"The node count must lie within the autoscaler limits: min {lo} <= count {size} <= max {hi}.")
        if cloud.key == "azure":
            # AKS takes no manual count on an autoscaled pool: it keeps the current size within the new limits (a raised
            # floor adds nodes, a lowered maximum removes some). That size is what the panel, the wait and config.json
            # use - never nodes the autoscaler will not add without pending pods.
            target = min(max(before["size"], lo), hi)
            if size != target:
                ui.warn(f"AKS scales an autoscaled pool itself: it keeps between {lo} and {hi} node(s), so the pool stays at "
                        f"{target} for now; pass --min {size} to force {size}.")
            size = target
        if (size, lo, hi) == (before["size"], before["min"], before["max"]):
            ui.ok(f"Node pool {pool['name']} of {env.id} already has {size} node(s) (autoscaler {lo}..{hi}); nothing to change.")
            return 0
        ui.panel(f"Node pool {pool['name']} · {env.id}", [("nodes", f"{before['size']} -> {size}"),
                                                          ("autoscaler", f"min {before['min']} -> {lo}, max {before['max']} -> {hi}")])
        _approve(f"Scale node pool {pool['name']} of {env.id} to {size} node(s)?", args.auto_approve)
        _set_pool(pool, size, lo, hi)
        summary = f"node {sub} on {env.id} (pool {pool['name']} {before['size']} -> {size})"
        done = f"Node pool {pool['name']}: {size} node(s) (autoscaler {lo}..{hi})."
    _sync_pool_cfg(cfg, pool)
    env.save(cfg)
    audit.note(env, f"node-{sub}", {"pool": pool["name"], "from": before["size"], "to": pool["size"], "min": pool["min"], "max": pool["max"]})
    undo.record(env.id, summary, "argv", {"argv": _scale_undo(cloud, env, before)})
    if sub != "remove" and pool["size"] > before["size"]:
        ready = _wait_ready_nodes(kubectl, kenv, pool["size"], pool["selector"])
        if ready < pool["size"]:
            ui.warn(f"{ready} of {pool['size']} node(s) Ready so far; the pool is still growing (cs node list).")
    ui.ok(done + "  cs node list")
    return 0


def _check_add_only_creates(t: Terraform, cloud, env, auto: bool) -> None:
    """A node add only creates VMs. A plan that deletes or re-creates an existing VM (or the private network) is refused,
    even with --auto-approve: the running node would lose its disk, and only the new nodes are joined afterwards."""
    changes = _plan_changes(t)
    if changes is None:
        if auto:
            raise ui.Abort("Could not read the plan to check that it only adds VMs, so nothing was applied under "
                           "--auto-approve. Review it by running the command again without --auto-approve.")
        return   # the user reviews the plan above before approving it
    doomed = [c["address"] for c in changes if str(c.get("type") or "").startswith("vmdesktop_") and "delete" in c["actions"]]
    if doomed:
        raise ui.Abort(f"This node add would delete or re-create {', '.join(doomed)} (see the plan above). Adding nodes must "
                       f"only create VMs, so nothing was applied. Review the environment: cs plan {cloud.key} --env {env.name}")


# a node's own resources in the vmware stack: module.stack.module.kubernetes[0].vmdesktop_vm.node["wk3"] and its three
# MAC numbers random_integer.mac["wk3-0"] .. ["wk3-2"]
_NODE_VM_KEY = re.compile(r'(?:^|\.)(vmdesktop_vm\.node\["((?:cp|wk)\d+)"\]|random_integer\.mac\["((?:cp|wk)\d+)-[0-2]"\])$')


def _check_remove_only_node(t: Terraform, cloud, env, key: str, auto: bool) -> str:
    """A node remove deletes exactly that node's VM (and its MAC numbers). Pending unrelated changes - settings saved by a
    `setup --plan-only`, drift - must not ride along: a delete or re-create of anything else is refused even with
    --auto-approve (other VMs would lose their disks), other changes are refused under --auto-approve and named in the
    question otherwise. Returns the extra wording for the approval question. Runs before anything is drained."""
    changes = _plan_changes(t)
    review = f"Review them with: cs plan {cloud.key} --env {env.name} (cs apply applies them)"
    if changes is None:
        if auto:
            raise ui.Abort("Could not read the plan to check that it only deletes this node's VM, so nothing was drained or "
                           "applied under --auto-approve. Review it by running the command again without --auto-approve.")
        return ""   # the user reviews the plan above before approving it
    mine, other = [], []
    for c in changes:
        m = _NODE_VM_KEY.search(str(c.get("address") or ""))
        ours = m and (m.group(2) or m.group(3)) == key and c["actions"] == ["delete"]
        (mine if ours else other).append(c)
    if not any("vmdesktop_vm." in str(c.get("address")) for c in mine):
        raise ui.Abort(f"The plan does not delete the VM of node {key}, so nothing was drained or applied. Check the environment: "
                       f"cs plan {cloud.key} --env {env.name}")
    doomed = [c["address"] for c in other if "delete" in c["actions"]]
    if doomed:
        raise ui.Abort(f"This node remove would also delete or re-create {', '.join(doomed)} (pending changes of {env.id}, see "
                       f"the plan above), so nothing was drained or applied. {review}; then remove the node again.")
    if other:
        shown = ", ".join(c["address"] for c in other[:5]) + (" …" if len(other) > 5 else "")
        if auto or not ui.interactive():
            raise ui.Abort(f"The plan also changes {shown} (pending changes of {env.id}), so nothing was drained or applied"
                           + (" under --auto-approve" if auto else "") + f". {review}; then remove the node again.")
        ui.warn(f"The plan also applies pending changes of {env.id}: {shown}.")
        return f" This also applies the pending change(s) to {shown}."
    return ""


def _node_json_or_none(kubectl: str, kenv: dict, name: str) -> dict | None:
    """The Node object, None when the cluster has no such node; any other failure aborts. Only the API server's own
    NotFound counts: a 'not found' of anything else (a context, an exec credential plugin) must never read as 'this node
    never registered', which would delete its VM without a drain."""
    proc = subprocess.run([kubectl, "get", "node", name, "-o", "json"], env=kenv, capture_output=True, text=True)
    if proc.returncode != 0:
        if "(NotFound)" in proc.stderr or f'nodes "{name}" not found' in proc.stderr:
            return None
        raise ui.Abort(f"Could not read node '{name}': {secrets.redact(proc.stderr.strip()[-300:])}")
    try:
        return json.loads(proc.stdout or "{}")
    except ValueError:
        return {}


def _leave_local_node(cloud, env, cfg: dict, outputs: dict, kubectl: str, kenv: dict, name: str, *,
                      registered: bool = True) -> None:
    """Take a numbered node VM (<name>-<env>-cp2 / -wk3) out of the local cluster before its VM goes: drain it, remove a
    kubeadm control plane's etcd member (kubeadm reset over SSH), delete the Node object (RKE2 drops the etcd member and
    the node password with it). Nothing is deleted when a step fails: the node is uncordoned and the command stops.
    registered=False: the node never joined (no Node object), only a kubeadm control plane's reset is attempted.
    Also the step an undo of a configuration that lowers the node count needs before its apply (undo.py)."""
    m = re.fullmatch(rf"{re.escape(cfg['name'])}-{re.escape(cfg['env'])}-(cp|wk)(\d+)", name)
    cp, idx = bool(m and m.group(1) == "cp"), int(m.group(2)) if m else 0
    distro = outputs.get("kubernetes_distro") or cfg["vars"].get("kubernetes_distro", "rke2")
    if registered:
        _drain_node(kubectl, kenv, name)
    if cp and distro == "kubeadm":
        ips = outputs.get("kubernetes_control_plane_ips") or []
        ip = ips[idx - 1] if 0 < idx <= len(ips) else None
        if not ip:
            if not registered:
                ui.warn(f"No IP known for {name}; if it joined etcd before failing, remove its member by hand (etcdctl member remove).")
                return
            subprocess.call([kubectl, "uncordon", name], env=kenv)
            raise ui.Abort(f"No IP known for {name}; its etcd member cannot be removed. Nothing was deleted (cs status {cloud.key} --env {env.name}).")
        host = prov.Host(ip, cloud.ssh_user(cfg), env.private_key_path(cfg), name, env=env)
        ui.info(f"Removing {name}'s etcd member (kubeadm reset)")
        if host.run("sudo kubeadm reset -f") != 0:
            if not registered:
                ui.warn(f"kubeadm reset failed on {name}; if it joined etcd before failing, remove its member by hand (etcdctl member remove).")
                return
            subprocess.call([kubectl, "uncordon", name], env=kenv)
            raise ui.Abort(f"kubeadm reset failed on {name}; its etcd member is still in the cluster, so nothing was deleted.")
    if registered:
        _delete_node_object(kubectl, kenv, name)


def _rejoin_advice(cloud, env, cfg: dict, outputs: dict, name: str, cp: bool, idx: int) -> str:
    """How a node that left the cluster (its VM kept) comes back: its kubelet registers again when its agent restarts."""
    import shlex
    distro = outputs.get("kubernetes_distro") or cfg["vars"].get("kubernetes_distro", "rke2")
    ips = outputs.get("kubernetes_control_plane_ips" if cp else "kubernetes_worker_ips") or []
    ip = ips[idx - 1] if 0 < idx <= len(ips) else "<its IP>"
    ssh = f"ssh -i {shlex.quote(str(env.private_key_path(cfg)))} {cloud.ssh_user(cfg)}@{ip}"
    again = f"cs provision {cloud.key} --env {env.name} --host k8s"
    if cp and distro == "kubeadm":
        return f"{again} (kubeadm reset cleared it, so it joins again)"
    if cp:
        return (f"its etcd member was removed, so it rejoins with a clean etcd: {ssh} 'sudo rke2-killall.sh; sudo rm -rf "
                f"/var/lib/rancher/rke2/server/db', then {again}")
    return f"restart its agent: {ssh} sudo systemctl restart {'kubelet' if distro == 'kubeadm' else 'rke2-agent'}"


# Whether the cluster's nodes were provisioned with OS hardening (setup --no-harden): one rule, in provision.py (the
# kubernetes record, else the bastion's, else True). The name stays for undo.py's node rebuild.
_saved_harden = prov.saved_harden


def _metallb_ranges(kubectl: str, kenv: dict) -> list[tuple[str, int, int]]:
    """MetalLB's IPv4 address pools on the cluster as (as written, first, last address as int); [] when there is none
    or they cannot be read (MetalLB not installed: nothing hands out addresses on the private network). IPv6 pools are
    left out: the VMs' private network is IPv4, and their integers must never be compared with IPv4 ones."""
    try:
        proc = subprocess.run([kubectl, "get", "ipaddresspools.metallb.io", "-A", "-o", "json"], env=kenv,
                              capture_output=True, text=True, timeout=60)
        items = (json.loads(proc.stdout or "{}").get("items") or []) if proc.returncode == 0 else []
    except (subprocess.TimeoutExpired, OSError, ValueError, AttributeError):
        return []
    out = []
    for item in items if isinstance(items, list) else []:
        for spec in (((item or {}).get("spec") or {}).get("addresses") or []) if isinstance(item, dict) else []:
            text = str(spec).strip()
            try:
                if "-" in text:
                    lo, hi = (ipaddress.ip_address(x.strip()) for x in text.split("-", 1))
                else:
                    net = ipaddress.ip_network(text, strict=False)
                    lo, hi = net[0], net[-1]
            except ValueError:
                continue
            if lo.version == hi.version == 4:
                out.append((text, int(lo), int(hi)))
    return out


def _check_node_addresses(cfg: dict, cp: bool, before: int, n: int, kubectl: str | None, kenv: dict | None) -> None:
    """New local nodes get fixed addresses (control planes .20+, workers .40+). One inside MetalLB's pool would share
    an address with a LoadBalancer Service (ARP conflicts, a broken ingress): refused before anything is created."""
    if not kubectl:
        return
    from .clouds.vmware import CONTROL_PLANE_BASE, WORKER_BASE
    try:
        net = ipaddress.ip_network(str(cfg.get("network_cidr") or ""), strict=False)
    except ValueError:
        return
    pools = _metallb_ranges(kubectl, kenv or {})
    if not pools:
        return
    base = CONTROL_PLANE_BASE if cp else WORKER_BASE
    role = "control plane" if cp else "worker"
    start, last = int(net.network_address) + base, int(net.broadcast_address)
    for i in range(before, before + n):
        ip = net.network_address + base + i
        hit = next((text for text, lo, hi in pools if lo <= int(ip) <= hi), None)
        if hit:
            # the first pool address at or above this role's first one, on this network (a pool may start below it)
            first = min((max(lo, start) for _, lo, hi in pools if hi >= start and lo <= last), default=int(ip))
            most = first - start
            key = "kubernetes_control_planes" if cp else "kubernetes_workers"
            name = f"{cfg.get('name', '?')}-{cfg.get('env', '?')}-{'cp' if cp else 'wk'}{i + 1}"
            has = f"{key} is {before}"
            room = (f"At most {most} {role}(s) fit below the pool ({has}): add at most {most - before} (--count {most - before})."
                    if most > before else f"No more {role}s fit below the pool ({has}).")
            raise ui.Abort(f"The new {role} {name} would get {ip}, which is in MetalLB's LoadBalancer pool {hit}: a Service "
                           f"may already answer on that address. Nothing was changed. {room}")


def _node_local_add(args, cloud, env, cfg: dict, kubectl: str | None = None, kenv: dict | None = None) -> int:
    n = args.count or 1
    cp = args.role == "control-plane"
    key = "kubernetes_control_planes" if cp else "kubernetes_workers"
    before = int(cfg["vars"].get(key, 1 if cp else 2))
    wanted = copy.deepcopy(cfg)
    wanted["vars"][key] = before + n
    fits = getattr(cloud, "address_problems", None)   # the fixed address plan of the private network (vmware)
    problems = fits(wanted) if fits else []
    if problems:
        raise ui.Abort(f"{env.id} has no room for {n} more {'control plane' if cp else 'worker'}(s) "
                       f"({key} {before} -> {before + n}): " + "; ".join(problems) + ". Nothing was changed.")
    _check_node_addresses(cfg, cp, before, n, kubectl, kenv)
    # only now the hypervisor, vmrest and the base image: a node that cannot fit never starts any of them
    _prepare_local_vms(cloud, env, cfg)
    # The previous configuration is snapshotted before anything changes, so a failed or declined apply restores both
    # config.json and the rendered stack (every retry would otherwise add yet another node).
    prev_cfg = copy.deepcopy(cfg)
    cfg["vars"][key] = before + n
    ui.info(f"{env.id}: {key} {before} -> {before + n}")
    if cp and (before + n) % 2 == 0:
        ui.warn(f"{before + n} control planes: an even etcd member count tolerates no more failures than {before + n - 1}; prefer 3 or 5.")
    try:
        backend_changed = _render(cloud, env, cfg)
        t = Terraform(env.stack_dir)
        t.init(migrate=backend_changed)
        _plan_for_apply(cloud, env, cfg, t, save=False)            # saved below, with the new node count
        _check_add_only_creates(t, cloud, env, args.auto_approve)   # even with --auto-approve
        _approve(f"Add {n} node(s)?", args.auto_approve)
        t.apply_reconciled(cloud.key, cfg, approve=lambda q: _approve(q, args.auto_approve))
    except BaseException:
        cfg.clear()
        cfg.update(copy.deepcopy(prev_cfg))
        _render(cloud, env, cfg)
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        raise
    env.save(cfg)
    (env.stack_dir / "tfplan").unlink(missing_ok=True)
    _settle_kept(env, cfg, t)
    outputs = _cache_outputs(env, t)
    audit.refresh(env, t, "node-add", {"count": n})
    names = [f"{cfg['name']}-{cfg['env']}-{'cp' if cp else 'wk'}{i + 1}" for i in range(before, before + n)]
    # The inverse is the careful path users get: `node remove` of each new node, highest number first - drained,
    # removed from etcd (a control plane) and deleted from the cluster before its VM goes. Recorded as soon as the VMs
    # exist, so a join that fails below can still be undone (node remove deletes a VM that never registered).
    undo.record(env.id, f"node add {n} on {env.id} ({', '.join(names)})", "argv-seq",
                {"argvs": [["node", "remove", name, cloud.key, "--env", env.name, "-y", "--auto-approve"] for name in reversed(names)]})
    harden = prov.saved_harden(cfg)
    if not harden:
        ui.info(f"The cluster was provisioned without OS hardening (--no-harden): {', '.join(names)} join the same way.")
    if names:   # an empty limit would re-run the whole cluster playbook on every node
        prov.provision_local_kubernetes(cloud, env, cfg, outputs, limit=names, harden=harden)
    ui.ok(f"{n} node(s) added. cs node list")
    return 0


def _node_local_remove(args, cloud, env, cfg: dict, outputs: dict, kubectl: str, kenv: dict) -> int:
    name = args.name
    m = re.fullmatch(rf"{re.escape(cfg['name'])}-{re.escape(cfg['env'])}-(cp|wk)(\d+)", name)
    if not m:
        _node_json(kubectl, kenv, name)   # a typo stops here, before anything is drained
        _approve(f"Drain {name} and remove it from the cluster? (it is not one of {env.id}'s numbered VMs, so no VM is deleted)", args.auto_approve)
        _drain_node(kubectl, kenv, name)
        _delete_node_object(kubectl, kenv, name)
        undo.record(env.id, f"node remove {name}", "info",
                    {"advice": f"{name} is not one of {env.id}'s VMs: restart its kubelet / Kubernetes agent on that machine "
                               "to register it again"})
        ui.ok(f"{name} drained and removed from the cluster.")
        return 0
    cp = m.group(1) == "cp"
    idx = int(m.group(2))
    role = "control plane" if cp else "worker"
    key = "kubernetes_control_planes" if cp else "kubernetes_workers"
    count = int(cfg["vars"].get(key, 1 if cp else 2))
    registered = _node_json_or_none(kubectl, kenv, name) is not None
    if not registered:
        if idx > count and os.environ.get("CLOUDSEED_UNDOING"):
            ui.info(f"{name} is already gone ({env.id} has {count} {role}(s)); nothing to remove.")
            return 0   # an undo retried after a partial run: this step already happened
        if idx != count:
            raise ui.Abort(f"No node '{name}' in this cluster. See: cs node list")
    if cp and count <= 1:
        raise ui.Abort(f"{name} is the only control plane; removing it would destroy the cluster. "
                       "Add another first (cs node add --role control-plane) or destroy the environment.")
    expected_last = f"{cfg['name']}-{cfg['env']}-{m.group(1)}{count}"
    # without workers nothing schedules until the control planes may run workloads: provisioning lifts their taint
    # (CriticalAddonsOnly on RKE2, control-plane:NoSchedule on kubeadm) when the cluster has no workers
    last_worker = not cp and count <= 1
    untaint = f"cs provision {cloud.key} --env {env.name} --host k8s"
    if last_worker:
        ui.warn(f"{name} is the last worker: its pods have nowhere to go until the control plane(s) run workloads. "
                f"Afterwards run `{untaint}` (it lets them), or add a worker first (cs node add).")

    def leave_cluster() -> None:
        _leave_local_node(cloud, env, cfg, outputs, kubectl, kenv, name, registered=registered)
        if cp and (count - 1) % 2 == 0:
            ui.warn(f"{count - 1} control planes remain: an even etcd member count tolerates no more failures than {count - 2}.")

    if name != expected_last:
        _approve(f"Drain {name} and remove it from the cluster? Its VM keeps running: nodes are numbered, so VMs are deleted "
                 f"from the highest number down ({expected_last} first).", args.auto_approve)
        leave_cluster()
        how = _rejoin_advice(cloud, env, cfg, outputs, name, cp, idx)
        undo.record(env.id, f"node remove {name} (VM kept)", "info",
                    {"advice": f"{name} left the cluster; its VM still runs. To bring it back: {how}"})
        ui.warn(f"{name} was removed from the cluster; its VM keeps running (VMs are deleted from the highest number down, "
                f"{expected_last} first). To bring it back: {how}")
        return 0
    if cloud.local:
        _prepare_local_teardown()   # only now: the plan below and the VM deletion go through vmrest
    ips = outputs.get("kubernetes_control_plane_ips" if cp else "kubernetes_worker_ips") or []
    ip = ips[idx - 1] if 0 < idx <= len(ips) else None
    prev_cfg = copy.deepcopy(cfg)
    cfg["vars"][key] = count - 1
    try:
        backend_changed = _render(cloud, env, cfg)
        t = Terraform(env.stack_dir)
        t.init(migrate=backend_changed)   # _write_root says True until a pending backend migration really happened
        t.plan("tfplan")   # shown before anything is drained: declining leaves the cluster untouched
        extra = _check_remove_only_node(t, cloud, env, f"{m.group(1)}{idx}", args.auto_approve)
        what = f"Drain {name} and delete its VM" if registered else f"{name} never registered in the cluster; delete its VM"
        _approve(f"{what} (plan above)?" + extra + (" It is the last worker (see the warning above)." if last_worker else ""),
                 args.auto_approve)
        leave_cluster()
        t.apply("tfplan")
    except BaseException:
        cfg.clear()
        cfg.update(copy.deepcopy(prev_cfg))
        _render(cloud, env, cfg)
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        raise
    env.save(cfg)
    (env.stack_dir / "tfplan").unlink(missing_ok=True)
    _cache_outputs(env, t)
    if ip:   # a VM created later on this fixed address has a new host key; the remembered one would refuse it
        prov.forget_host_key(env, ip)
    audit.refresh(env, t, "node-remove", {"node": name})
    undo.record(env.id, f"node remove {name}", "config", {"prev_cfg": prev_cfg, "what": "node count", "rejoin_nodes": True})
    ui.ok(f"{name} removed from the cluster and its VM deleted." if registered else f"{name}'s VM deleted.")
    if last_worker:
        ui.info(f"No workers left: let the control plane(s) run workloads with: {untaint}")
    return 0


def _prepare_local_vms(cloud, env, cfg: dict) -> None:
    """What creating VMs needs (the hypervisor, vmrest, the base image): the full prepare that _load_env gives commands
    that touch VMs, done once the cluster was checked. Only what it resolves for real is saved."""
    before = copy.deepcopy(cfg)
    cloud.prepare(cfg, dry_run=False)
    if cfg != before:
        env.save(cfg)


def _node_env_stamp(env) -> tuple:
    """What a node change works from - config.json and the cached outputs - as they are on disk now (bytes, None when
    missing): a change between reading them and taking the environment lock means another run got there first."""
    def read(p: Path):
        try:
            return p.read_bytes()
        except OSError:
            return None
    return read(env.config_path), read(env.dir / "outputs.json")


def cmd_node(args, settings) -> int:
    sub = args.node_cmd
    if sub != "remove" and getattr(args, "name", None):
        raise ui.Abort(f"`cs node {sub}` takes no node name (got '{args.name}'); a cloud is aws, gcp, azure or vmware.")
    if sub == "remove" and not args.name:
        raise ui.Abort("cs node remove <node-name>   (see: cs node list)")
    if sub == "scale" and not args.count:
        raise ui.Abort("cs node scale <cloud> --env NAME --count N [--min N] [--max N]")
    # loaded without hypervisor work: the cluster and the node name are checked first (a typo never starts vmrest or
    # downloads an image); add and remove prepare the VMs themselves on the path that needs it
    cloud, env, cfg, outputs = _resolve_cluster_env(args, settings, vm_image=False)
    # what the configuration was read from, taken right away: the kubeconfig fetch and a kubectl install below can take
    # a while (or wait on a prompt), and a change that lands then must be seen under the lock too
    seen = _node_env_stamp(env)
    if sub == "scale" and cloud.local:
        raise ui.Abort("vmware nodes are numbered VMs: cs node add [--count N] / cs node remove <node-name>")
    kc = services.ensure_kubeconfig(cloud, env, cfg, outputs)   # also for a local add: no cluster, no nodes to add
    kubectl = services.ensure_tool("kubectl", "to manage the cluster's nodes")
    # the cloud CLI's environment (AWS FIPS endpoints) for the token command kubectl runs on EKS
    kenv = dict(services.cloud_cli_env(cloud.key, cfg, outputs), KUBECONFIG=str(kc))
    if sub == "list":
        return subprocess.call([kubectl, "get", "nodes", "-o", "wide"], env=kenv)
    with env.lock(f"node {sub} {cloud.key} --env {env.name}"):
        if _node_env_stamp(env) != seen:
            # another run (a node add/remove, setup, the web console) changed the environment while this one resolved
            # it: work from what it left, never from the configuration read before the lock
            ui.info(f"{env.id} changed while this command started; reading it again.")
            cloud, env, cfg, outputs = _resolve_cluster_env(args, settings, vm_image=False)
            kc = services.ensure_kubeconfig(cloud, env, cfg, outputs)
            kenv = dict(services.cloud_cli_env(cloud.key, cfg, outputs), KUBECONFIG=str(kc))
        if not cloud.local:
            return _node_managed(args, cloud, env, cfg, outputs, kubectl, kenv)
        if sub == "add":   # prepares the VMs itself, once the new nodes were checked to fit
            return _node_local_add(args, cloud, env, cfg, kubectl, kenv)
        return _node_local_remove(args, cloud, env, cfg, outputs, kubectl, kenv)


# ---------------------------------------------------------------- platform

def _pop_cloud_from_items(args) -> None:
    """`cs platform plan keda vmware --env lab` / `cs chaos run pod-kill vmware --env lab` read like every other command:
    a cloud key among the items selects the target (same as --cloud) and is never taken for an item."""
    items = list(getattr(args, "items", None) or [])
    keys = list(dict.fromkeys(i for i in items if i in CLOUD_KEYS))
    if not keys:
        return
    named = [args.cloud] if getattr(args, "cloud", None) else []
    if len(set(named + keys)) > 1:
        raise ui.Abort(f"Conflicting targets: {', '.join(dict.fromkeys(named + keys))}. Name one cloud.")
    args.cloud = keys[0]
    args.items = [i for i in items if i not in CLOUD_KEYS]


def _check_platform_names(names: list[str]) -> None:
    """Unknown catalog names fail up front, with a did-you-mean, before any cluster is contacted."""
    import difflib
    pool = list(platformmod.GROUPS) + [k for k, v in platformmod.CATALOG.items() if not v.get("hidden")]
    for n in names:
        if n not in platformmod.GROUPS and n not in platformmod.CATALOG:
            near = difflib.get_close_matches(n, pool, n=3, cutoff=0.7)
            raise ui.Abort(f"Unknown platform group or item '{n}'" + (f" - did you mean {' or '.join(near)}?" if near else ".")
                           + "  See: cs platform list")


def _platform_mode(items: list[str] | None, sets: list[str] | None) -> str | None:
    """--set mode=<m> picks the mode of meta items (istio: ambient | sidecar) - only when a meta item is part of the
    request (named, in a named group, or a dependency: platformmod.meta_mode_applies); a typo of such a mode must not
    silently install another one. Otherwise mode=... is an ordinary chart value (MinIO's standalone | distributed)."""
    mode, _ = platformmod.split_mode(list(items or []), sets)
    return mode


def _cluster_answers(ctx) -> str | None:
    """None when the cluster answers, else why not (cheap: one kubectl call with a short timeout)."""
    kubectl = deps.find("kubectl")
    if not kubectl:
        return "kubectl is not installed (cs install kubectl)"
    try:
        proc = subprocess.run([kubectl, "version", "-o", "json", "--request-timeout=8s"], env=ctx.procenv(), capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return f"the cluster of {ctx.env.id} does not answer"
    if proc.returncode != 0:
        return f"the cluster of {ctx.env.id} does not answer ({secrets.redact(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else 'no reply')[:160]})"
    return None


def _catalog_ctx(args, settings) -> tuple[platformmod.Cluster | None, str | None]:
    """Browsing the catalog (platform list / info) needs no cluster: show the chosen cluster's install state when it
    answers, otherwise the catalog alone. Never prompts, never switches the current environment, never aborts:
    (None, reason) means the install state is unknown, (None, None) that there is no cluster to ask."""
    cloud_key, env_name = getattr(args, "cloud", None), getattr(args, "env", None)
    _check_env_name(env_name)
    env = None
    if cloud_key and env_name:
        env = paths.Env(cloud_key, env_name)
        if not env.exists():
            return None, f"environment {env.id} does not exist"
    else:
        env, problem, kind = _pick_cluster_env(cloud_key, env_name, settings, prompt=False)
        if problem:
            return None, (problem if kind in ("several", "unknown") else None)
        if env is None:
            return None, None
    if not _has_cluster(env):
        return None, None
    cfg, problem = env.try_load()   # an unreadable config.json (core's ConfigError) leaves the catalog browsable too
    if problem:
        return None, problem
    cloud, outputs = clouds.get(env.cloud), _cached_outputs(env)
    if not cloud.local and outputs.get("kubernetes_cluster_name"):
        tool = {"aws": "aws", "gcp": "gcloud", "azure": "az"}.get(cloud.key, cloud.key)
        if not deps.find(tool):   # browsing the catalog never installs a cloud CLI
            return None, f"{tool} is not installed (cloudseed install {tool})"
    kc, problem = _best_effort(lambda: services.ensure_kubeconfig(cloud, env, cfg, outputs))
    if problem:
        return None, problem
    ctx = platformmod.Cluster(cloud, env, cfg, outputs, kc)
    problem = _cluster_answers(ctx)
    return (None, problem) if problem else (ctx, None)


def _offline_plan_env(args, settings) -> paths.Env | None:
    """The environment a plan is for when that environment has no cluster yet (plan offline, assuming nothing is
    installed), or None when the plan should ask a live cluster."""
    envs = paths.Env.list_all()
    known = {e.id: e for e in envs}
    cloud_key, env_name = args.cloud, args.env
    if cloud_key and env_name:
        env = paths.Env(cloud_key, env_name)
        # a name that does not exist falls through to the usual resolution, which says so (a typo of a FIPS
        # environment must not produce a plan for a made-up, non-FIPS one)
        return None if (_has_cluster(env) or not env.exists()) else env
    if cloud_key:
        cands = [e for e in envs if e.cloud == cloud_key and _has_cluster(e)]
        return None if cands else paths.Env(cloud_key, "plan")
    if env_name:
        cands = [e for e in envs if e.name == env_name and _has_cluster(e)]
        same = [e for e in envs if e.name == env_name]
        return same[0] if not cands and len(same) == 1 else None
    current = settings.get("current_env")
    if current in known and not _has_cluster(known[current]):
        return known[current]
    if not any(_has_cluster(e) for e in envs):
        return envs[0] if len(envs) == 1 else paths.Env("vmware", "plan")
    return None


def _platform_template(args) -> int:
    tdir = paths.REPO_ROOT / "templates"
    available = sorted(p.name for p in tdir.iterdir() if p.is_dir() and not p.name.startswith(".")) if tdir.is_dir() else []
    name = (args.items or ["gitlab-ci"])[0]
    if name not in available:
        raise ui.Abort(f"Unknown template '{name}'. Available: {', '.join(available) or 'none'}")
    src = tdir / name
    files: dict = {}
    for f in sorted(src.rglob("*")):
        if not f.is_file() or f.name == ".DS_Store":
            continue
        dest = Path.cwd() / f.relative_to(src)
        if dest.exists() and not args.auto_approve:
            if not ui.interactive():
                ui.warn(f"{dest} exists - kept (pass --auto-approve to overwrite)")
                continue
            if not ui.confirm(f"Overwrite {dest}?", default=False):
                ui.info(f"kept {dest}")
                continue
        files[str(dest)] = undo.backup_file(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, dest)
        ui.ok(f"wrote {dest}")
    if files:
        undo.record(undo.GLOBAL, f"platform template {name} in {Path.cwd().name}", "restore-files", {"files": files})
    return 0


def cmd_platform(args, settings) -> int:
    _pop_cloud_from_items(args)
    sub = args.platform_cmd
    if sub == "template":
        return _platform_template(args)
    _check_env_name(args.env)
    if sub in ("install", "uninstall", "plan", "info") and not args.items:
        raise ui.Abort(f"cs platform {sub} <group|item ...>   groups: " + ", ".join(platformmod.GROUPS) + "   (items: cs platform list)")
    _check_platform_names(args.items or [])
    mode = _platform_mode(args.items, args.set)
    user_sets, target = [], None
    if sub in ("plan", "install"):   # the dry run refuses and shows exactly what install would; both before any cluster work
        user_sets, target = platformmod.check_install_args(args.items, args.version, args.set)
    if sub in ("info", "list"):
        ctx, problem = _catalog_ctx(args, settings)
        if problem:
            ui.warn(f"Install state unknown: {problem}")
        if sub == "info":
            for item in args.items:
                platformmod.info(item, ctx)
            return 0
        if ctx:
            ui.info(f"Platform on {ctx.env.id} ({ctx.target}/{ctx.distro})")
        releases, why = {}, ""
        if ctx is not None and not problem:   # one helm list; a cluster that answers but cannot list (no helm, RBAC) is "unknown"
            releases, why = platformmod._releases_for_view(ctx)
            if why:
                ui.warn(f"Install state unknown: {why}")
        platformmod.status(ctx, charts=args.charts, unknown=bool(problem or why), releases=releases)
        return 0
    if sub == "plan":
        offline = _offline_plan_env(args, settings)
        if offline is not None:
            return _platform_plan_offline(args, offline, mode, user_sets, target)
    cloud, env, cfg, outputs = _resolve_cluster_env(args, settings)
    kc = services.ensure_kubeconfig(cloud, env, cfg, outputs)
    ctx = platformmod.Cluster(cloud, env, cfg, outputs, kc)
    if mode is not None:
        ctx.options["mode"] = mode
    if sub == "status":
        problem = _cluster_answers(ctx)
        if problem:   # never report every item as "not installed" just because the cluster did not answer
            raise ui.Abort(f"Cannot read the platform state: {problem}. Check it with: cs kubectl {cloud.key} --env {env.name} get nodes")
        ui.info(f"Platform on {env.id} ({ctx.target}/{ctx.distro})")
        platformmod.status(ctx, charts=args.charts)
        return 0
    if sub == "plan":
        ctx.upgrade = args.upgrade
        entries = platformmod.plan(args.items, ctx, force=args.force)
        platformmod.print_plan(entries, ctx, user_sets=user_sets, version=args.version, target=target)
        platformmod.target_flag_warnings(entries, ctx, target, user_sets, args.version)
        return 0
    with env.lock(f"platform {sub} {cloud.key} --env {env.name}"):
        if sub == "ui":
            return _platform_ui(args, cloud, env, cfg, ctx)
        if sub == "install":
            return _platform_install(args, cloud, env, cfg, kc, ctx, mode)
        if sub == "uninstall":
            return _platform_uninstall(args, env, ctx)
    return 1


def _platform_ui(args, cloud, env, cfg: dict, ctx) -> int:
    stack: list = []
    try:
        exposed = platformmod.expose_uis(ctx, auto_approve=args.auto_approve, installed=stack)
    finally:
        if stack:
            undo.record(env.id, f"platform install {' '.join(stack)}", "platform", {"inverse": "uninstall", "items": stack})
    addr = platformmod.ingress_address(ctx)
    rows = [(item, f"{url}   {ui.dim(cred)}") for item, url, cred in exposed] or [ui.dim("no known UIs installed yet")]
    ui.panel(f"UIs on {env.id}  ·  ingress {addr or '(pending)'}  ·  TLS by cert-manager (cloudseed-ca)", rows)
    if exposed:
        hosts = " ".join(url.replace("https://", "") for _, url, _ in exposed)
        dns = f"add to /etc/hosts:  {addr or '<ingress-ip>'} {hosts}"
        if cloud.local:   # MetalLB hands out addresses of the host-only network: this machine reaches them directly
            net = cfg.get("network_cidr")
            route = (f"the ingress IP is on the host-only network{' ' + net if net else ''}: reachable from this machine "
                     "directly (no VPN or bastion needed)")
        elif ctx.outputs.get("vpn_public_ip") or _lenient_bool((cfg.get("vars") or {}).get("enable_vpn"), False):
            route = f"connect the VPN (cs vpn connect {cloud.key} --env {env.name}) or use the bastion; the ingress IP is private"
        else:
            route = (f"the ingress IP is private: forward it through the bastion (cs ssh {cloud.key} --env {env.name} -- -L "
                     f"8443:{addr or '<ingress-ip>'}:443) or add a VPN host (cs setup {cloud.key} --env {env.name} --var enable_vpn=true)")
            # through the forward the names resolve to this machine and the UIs answer on port 8443
            dns = f"add to /etc/hosts:  127.0.0.1 {hosts}   (then open https://<name>:8443 while the forward runs)"
        ui.panel("Reach them", [
            f"{ui.style('route   ', 'muted')} {route}",
            f"{ui.style('dns     ', 'muted')} {dns}",
            f"{ui.style('trust   ', 'muted')} cs kubectl -n cert-manager get secret cloudseed-root-ca -o jsonpath='{{.data.ca\\.crt}}' | base64 -d > cloudseed-ca.crt  (import it)",
        ], accent="leaf")
    return 0


def _platform_plan_offline(args, env: paths.Env, mode: str | None, user_sets: list[str] | None = None,
                           target: str | None = None) -> int:
    """No cluster yet: plan for the target assuming nothing is installed (dedupe, conflicts, per-target values), without
    creating anything under the cloudseed home."""
    import tempfile
    cloud_key = env.cloud
    with tempfile.TemporaryDirectory(prefix="cloudseed-plan-") as td:
        label = env.id if env.exists() else f"any {cloud_key} environment" if env.name == "plan" else env.id
        cfg = env.load() if env.exists() else {"env": env.name, "region": "", "network_cidr": "10.100.0.0/24", "vars": {}}
        scratch = paths.Env(cloud_key, env.name, Path(td))   # the environment's settings, a throw-away working dir
        ctx = platformmod.Cluster(clouds.get(cloud_key), scratch, cfg, {}, Path(td) / "kubeconfig")
        ctx.upgrade = args.upgrade
        if mode is not None:
            ctx.options["mode"] = mode
        ui.info(f"No cluster in {label} yet: planning for target '{cloud_key}' assuming nothing is installed (<cloud> --env NAME to change).")
        entries = platformmod.plan(args.items, ctx, releases={}, force=args.force)
        platformmod.print_plan(entries, ctx, user_sets=user_sets, version=args.version, target=target)
        platformmod.target_flag_warnings(entries, ctx, target, user_sets or [], args.version)
    return 0


def _release_key(item: str) -> str:
    spec = platformmod.CATALOG[item]
    return f"{spec.get('ns', 'default')}/{spec.get('release', item)}"


def _revision(rel: dict | None) -> int | None:
    try:
        return int(str((rel or {}).get("revision", "")).strip())
    except ValueError:
        return None


def _is_present(item: str, releases: dict) -> bool:
    spec = platformmod.CATALOG[item]
    if spec["method"] in ("helm", "oci"):
        return _release_key(item) in releases
    return releases.get("probe:" + item) is not None   # every other item has a probe object that says it is there


def _platform_install(args, cloud, env, cfg: dict, kc, ctx, mode: str | None) -> int:
    """Install, and journal exactly what changed so `cs undo` reverts this run and nothing else: a new release is
    uninstalled (never its already-present dependencies), an upgraded one is rolled back to its previous revision, and a
    run that stops part-way still leaves an undo point for what it did install."""
    ctx.upgrade = args.upgrade
    platformmod.check_install_args(args.items, args.version, args.set)   # before any cloud prerequisite is applied
    platformmod.ensure_tools()   # without helm the releases below would read as none, and pre-existing ones as "new"
    before = platformmod.installed_releases(ctx)
    needed = platformmod.missing_prereqs(args.items, ctx, releases=before, force=args.force)
    if needed:
        outputs = _apply_prereqs(cloud, env, cfg, needed, args.auto_approve)
        ctx = platformmod.Cluster(cloud, env, cfg, outputs, kc)
        ctx.upgrade = args.upgrade
        if mode is not None:
            ctx.options["mode"] = mode
    _journaled_install(env, ctx, args.items, before, wait=not args.no_wait, version=args.version, extra_sets=args.set,
                       upgrade=args.upgrade, force=args.force)
    return 0


def _install_steps(items: list[str], ctx, before: dict, force: bool = False) -> list[dict]:
    """Per item the install would touch: its release and previous revision (Helm) or whether it was present (probe)."""
    steps = []
    for e in platformmod.plan(items, ctx, before, force=force):
        if e["action"] != "install":
            continue
        spec = platformmod.CATALOG[e["item"]]
        if spec["method"] in ("helm", "oci"):
            rel = before.get(_release_key(e["item"]))
            steps.append({"item": e["item"], "ns": spec.get("ns", "default"), "release": spec.get("release", e["item"]),
                          "prev_revision": _revision(rel), "existed": rel is not None})
        else:
            steps.append({"item": e["item"], "existed": _is_present(e["item"], before), "probe": bool(spec.get("probe"))})
    return steps


def _journaled_install(env, ctx, items: list[str], before: dict, *, force: bool = False, upgrade: bool = False, **kw) -> list[str]:
    """platform.install() with its undo entry ('platform install ...'), also for the installs other commands make on
    first use (Velero for `cs dr`, Chaos Mesh for `cs chaos run`): `before` is installed_releases() taken earlier."""
    ctx.upgrade = upgrade
    steps = _install_steps(items, ctx, before, force)
    failed = True
    try:
        done = platformmod.install(items, ctx, upgrade=upgrade, force=force, **kw)
        failed = False
    finally:
        _journal_install(env, ctx, steps, failed)
    return done


def _journal_install(env, ctx, steps: list[dict], failed: bool) -> None:
    if not steps:
        return
    after, _ = _best_effort(lambda: platformmod.installed_releases(ctx))
    if not after and not failed:
        after = None   # a finished install leaves releases behind: an empty answer means the cluster could not be asked
    changed: list[dict] = []
    seen_later_change = False
    for s in reversed(steps):   # walk backwards: a later change proves the run got past the earlier, undetectable items
        if "release" in s:
            now = (after or {}).get(f"{s['ns']}/{s['release']}") if after is not None else None
            if after is None:
                hit = not failed and (not s["existed"] or s["prev_revision"] is not None)
            elif not s["existed"]:
                hit = now is not None
            else:
                hit = s["prev_revision"] is not None and _revision(now) not in (None, s["prev_revision"])
        elif s["existed"]:
            hit = False   # a manifest re-applied by --upgrade has no previous version to go back to
        elif s["probe"] and after is not None:
            hit = after.get("probe:" + s["item"]) is not None
        else:
            hit = not failed or seen_later_change
        if hit:
            seen_later_change = True
            step = {k: v for k, v in s.items() if k in ("item", "ns", "release")}
            if s.get("existed") and s.get("prev_revision") is not None:
                step["prev_revision"] = s["prev_revision"]
            changed.append(step)
    changed.reverse()
    if not changed:
        return
    names = [s["item"] for s in changed]
    undo.record(env.id, f"platform install {' '.join(names)}" + (" (stopped part-way)" if failed else ""), "platform",
                {"inverse": "uninstall", "items": names, "steps": changed})
    if failed:
        ui.info(f"Undo point kept for what this run changed: {', '.join(names)}  (cs undo)")


def _platform_restore_info(ctx, items: list[str], before: dict, workdir: Path) -> dict:
    """What re-installing a removed item needs: its chart version and the values it was installed with."""
    helm = deps.find("helm")
    restore: dict = {}
    for item in items:
        spec = platformmod.CATALOG[item]
        if spec["method"] not in ("helm", "oci") or not _is_present(item, before):
            continue
        rel = before[_release_key(item)]
        info: dict = {}
        chart = str(rel.get("chart") or "")
        base = str(spec.get("chart") or "").rstrip("/").rsplit("/", 1)[-1]
        if base and chart.startswith(base + "-"):
            info["version"] = chart[len(base) + 1:]
        if helm:
            proc = subprocess.run([helm, "get", "values", spec.get("release", item), "-n", spec.get("ns", "default"), "-o", "json"],
                                  env=ctx.procenv(), capture_output=True, text=True)
            try:
                values = json.loads(proc.stdout or "null") if proc.returncode == 0 else None
            except ValueError:
                values = None
            if values:
                workdir.mkdir(parents=True, exist_ok=True)
                path = workdir / f"{item}.values.json"   # JSON is YAML: helm takes it with -f
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as fh:
                    json.dump(values, fh)
                info["values"] = str(path)
        restore[item] = info
    return restore


def _platform_uninstall(args, env, ctx) -> int:
    """Remove exactly the named items (platform.uninstall shows the removal list - no implicit dependencies, items that
    are not installed reported - and asks for approval), and journal what really went, with the chart version and
    values each one needs to come back. Exit 1 when an item could not be removed."""
    platformmod.ensure_tools()
    before = platformmod.installed_releases(ctx)
    # everything uninstall() could touch, in install order (dependencies first): the named items, their meta members in
    # every mode, and whatever the dependency resolution adds
    cands = list(dict.fromkeys(platformmod.resolve(args.items, ctx)))
    for item in list(cands):
        for members in (platformmod.CATALOG[item].get("modes") or {}).values():
            cands += [m for m in members if m not in cands]
    workdir = undo.BACKUPS / f"{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-platform-{env.id}"
    restore = _platform_restore_info(ctx, cands, before, workdir)
    # the mode a meta item (istio) runs in, read the way install reads it: a failed ztunnel still means ambient, so the
    # undo re-installs the mesh the cluster had, never the smaller member set that happened to be fully deployed
    mode = next((m for m in (platformmod._installed_mode(item, ctx, before) for item in cands
                             if platformmod.CATALOG[item].get("modes")) if m), None)
    try:
        # keep_objects: a --force removal of CRD charts saves the custom resources it deletes there, for the undo
        platformmod.uninstall(args.items, ctx, force=getattr(args, "force", False),
                              approve=lambda q: _approve(q, args.auto_approve), strict=False, keep_objects=workdir)
    finally:
        after, _ = _best_effort(lambda: platformmod.installed_releases(ctx))
        # every item tells whether it is there: a release (helm/oci) or a probe object (everything else)
        really = [item for item in cands
                  if _is_present(item, before) and after is not None and not _is_present(item, after)]
        for item, kept in (getattr(ctx, "saved_objects", None) or {}).items():
            if item in really:   # the undo re-installs the item, then creates these again
                restore.setdefault(item, {}).update(kept)
        if really:
            if workdir.exists():
                os.chmod(workdir, 0o700)
            undo.record(env.id, f"platform uninstall {' '.join(really)}", "platform",
                        {"inverse": "install", "items": really, "restore": {i: restore.get(i, {}) for i in really}, "mode": mode,
                         "backup_dir": str(workdir) if workdir.exists() else None})
        elif workdir.exists():
            shutil.rmtree(workdir, ignore_errors=True)
    return 1 if getattr(ctx, "failures", None) else 0


def _apply_prereqs(cloud, env, cfg: dict, prereqs: list[str], auto: bool) -> dict:
    """Platform items that need cloud-side resources (Velero's bucket + identity, Karpenter's roles/queue/tags) get them from
    the environment's own Terraform stack: the prerequisite is recorded in config.json, the stack is re-planned and applied
    (with the usual approval), and the fresh outputs are handed back to the installer. Idempotent and audited."""
    _ensure_backend(cloud, env, cfg, auto)   # never apply into a stray local state of a 'remote' env (kept on rollback)
    have = list(cfg.get("platform_prereqs") or [])
    prev_cfg = copy.deepcopy(cfg)   # taken before the change: a failed or declined apply restores config and render
    cfg["platform_prereqs"] = have + [p_ for p_ in prereqs if p_ not in have]
    ui.header(f"Cloud prerequisites for {', '.join(prereqs)} on {env.id}")
    ui.info({"velero": "S3/GCS/Blob bucket (versioned, encrypted, private) + least-privilege identity for the velero service account",
             "karpenter": "controller IRSA role, node role + instance profile + EKS access entry, SQS interruption queue + EventBridge rules, discovery tags"}
            .get(prereqs[0], "identity and storage") if len(prereqs) == 1 else "identities, storage and tags for: " + ", ".join(prereqs))
    try:
        backend_changed = _render(cloud, env, cfg)
        t = Terraform(env.stack_dir)
        t.init(migrate=backend_changed)
        _plan_for_apply(cloud, env, cfg, t, save=False)   # saved below, with the prerequisites
        _approve("Apply these cloud prerequisites?", auto)
        t.apply_reconciled(cloud.key, cfg, approve=lambda q: _approve(q, auto))
    except BaseException:
        cfg.clear()
        cfg.update(copy.deepcopy(prev_cfg))
        _render(cloud, env, cfg)
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        raise
    env.save(cfg)
    (env.stack_dir / "tfplan").unlink(missing_ok=True)
    _settle_kept(env, cfg, t)
    outputs = _cache_outputs(env, t)
    audit.refresh(env, t, "platform-prereqs", {"prereqs": prereqs})
    _record_prereqs_undo(cloud, env, cfg, prev_cfg, [p_ for p_ in prereqs if p_ not in have], outputs)
    ui.ok("Cloud prerequisites applied; installing the platform item(s).")
    return outputs


def _record_prereqs_undo(cloud, env, cfg: dict, prev_cfg: dict, added: list[str], outputs: dict) -> None:
    """Undo of cloud prerequisites. Velero's bucket (force_destroy) and identity are never removed by an undo: every backup
    lives in that bucket, also the scheduled ones no undo entry knows about - the same as `platform uninstall velero`,
    which keeps them. What else was added (Karpenter's roles, queue and tags) is removed by re-applying the previous
    configuration, with velero kept in it."""
    if not added:
        return
    summary = f"cloud prerequisites {' '.join(added)} on {env.id}"
    if "velero" not in added:
        undo.record(env.id, summary, "config", {"prev_cfg": prev_cfg, "what": "cloud prerequisites (identities / queue / tags)"})
        return
    store = outputs.get("kubernetes_velero_bucket") or outputs.get("kubernetes_velero_storage_account")
    kept = (f"the Velero {'storage account' if cloud.key == 'azure' else 'bucket'}{' ' + store if store else ''} and its "
            "identity are kept by undo because they hold the backups")
    rest = [p_ for p_ in added if p_ != "velero"]
    if not rest:
        undo.record(env.id, summary, "info",
                    {"advice": f"{kept}; remove Velero with cs platform uninstall velero. To delete the bucket with every "
                               f"backup in it deliberately: remove velero from platform_prereqs in {env.config_path}, then "
                               f"cs apply {cloud.key} --env {env.name}"})
        return
    keep_velero = copy.deepcopy(prev_cfg)
    keep_velero["platform_prereqs"] = list(dict.fromkeys(list(prev_cfg.get("platform_prereqs") or []) + ["velero"]))
    undo.record(env.id, summary, "config", {"prev_cfg": keep_velero, "what": f"cloud prerequisites of {', '.join(rest)}; {kept}"})


# ---------------------------------------------------------------- chaos / dr / scan

def _chaos_seconds(value: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([sm]?)\s*", str(value))
    if not m:
        raise argparse.ArgumentTypeError(f"'{value}' is not a duration: use seconds, e.g. 45, 45s or 2m")
    n = int(m.group(1)) * (60 if m.group(2) == "m" else 1)
    if not 15 <= n <= 3600:
        raise argparse.ArgumentTypeError(f"{n}s is outside 15s..1h (each experiment needs several probe samples at the 3s interval)")
    return n


def _chaos_replicas(value: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"'{value}' is not a whole number")
    if not 2 <= n <= 20:
        raise argparse.ArgumentTypeError(f"canary replicas must be 2..20 (got {n}; with one replica pod-kill is an outage by design)")
    return n


def _check_chaos_names(items: list[str]) -> None:
    import difflib
    for n in items or []:
        if n not in chaos.SUITES and n not in chaos.EXPERIMENTS:
            near = difflib.get_close_matches(n, list(chaos.SUITES) + list(chaos.EXPERIMENTS), n=3, cutoff=0.7)
            raise ui.Abort(f"Unknown experiment or suite '{n}'" + (f" - did you mean {' or '.join(near)}?" if near else ".")
                           + f" Experiments: {', '.join(chaos.EXPERIMENTS)}; suites: {', '.join(chaos.SUITES)}  (cs chaos list)")


def _chaos_target_preview(ctx, spec: str) -> str:
    """'<ns>/<deployment> (pods matching <selector>)': the pods the faults really hit (the Deployment's full pod selector,
    which can match more than its own pods). A Deployment that does not exist aborts here; a cluster that cannot be
    asked leaves the check to chaos.run."""
    ns, name, _port = chaos.parse_target(spec)
    plain = f"{ns}/{name}"
    if not deps.find("kubectl"):
        return plain
    proc = chaos._kubectl(ctx, "-n", ns, "get", "deploy", name, "-o", "json", timeout=60)
    if proc.returncode != 0:
        if "NotFound" in (proc.stderr or ""):
            raise ui.Abort(f"Deployment {plain} not found. Use --target <namespace>/<deployment>[:port|port-name], or omit it "
                           "for the cloudseed canary. Nothing was changed.")
        return plain
    try:
        sel = ((json.loads(proc.stdout or "{}").get("spec") or {}).get("selector")) or {}
    except (ValueError, AttributeError):
        return plain
    labels, exprs = sel.get("matchLabels") or {}, sel.get("matchExpressions") or []
    if not labels and not exprs:
        return plain
    text = chaos.Target(ns, name, name, name, 0, False, labels=labels, exprs=exprs).selector_text()
    return f"{plain} (pods in {ns} matching {text})"


def _chaos_reports(env) -> list[Path]:
    d = env.dir / "chaos"
    return sorted(d.glob("report-*.json")) if d.exists() else []


def _load_chaos_report(path: Path, env_id: str) -> dict | None:
    """A saved chaos report in the shape chaos.print_report reads, or None when it is empty, cut short or not a report
    (an interrupted save leaves an empty file under the claimed name)."""
    try:
        rep = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(rep, dict) or not isinstance(rep.get("results"), list):
        return None
    results = []
    for r in rep["results"]:
        if not isinstance(r, dict):
            return None
        r = dict(r)
        # a hand-edited or foreign file: text where print_report formats text, numbers where it computes with them
        r["experiment"] = str(r.get("experiment", "?"))
        if "verdict" in r:
            r["verdict"] = str(r["verdict"])
        if "reason" in r:
            r["reason"] = str(r["reason"])
        if "availability" in r and "min_availability" in r:
            try:
                r["availability"], r["min_availability"] = float(r["availability"]), float(r["min_availability"])
            except (TypeError, ValueError):
                r.pop("availability"), r.pop("min_availability")
            r.setdefault("recovery_s", "?")
            r.setdefault("recovery_bound_s", "?")
        results.append(r)
    counted = {v: sum(1 for r in results if r.get("verdict") == v) for v in ("PASS", "FAIL", "SKIP", "ERROR")}
    summary = rep.get("summary") if isinstance(rep.get("summary"), dict) else {}
    rep.update(results=results, summary={k: summary[k] if isinstance(summary.get(k), int) else counted[k] for k in counted})
    rep.setdefault("env", env_id)
    rep.setdefault("target", "?")
    rep.setdefault("run", path.stem.replace("report-", "", 1))
    return rep


def _ensure_chaos_mesh(args, env, ctx) -> None:
    """Chaos Mesh on first use - asked like `cs dr` asks for Velero (its daemon runs privileged on every node) and
    journaled like `cs platform install`, so `cs undo` removes it again after the run's own entry."""
    platformmod.ensure_tools()
    if chaos.chaos_mesh_ready(ctx):
        return
    if not args.auto_approve and not (ui.interactive() and ui.confirm(
            "Chaos Mesh is not installed yet (its daemon runs privileged on every node). Install it now?", default=True)):
        raise ui.Abort("Install Chaos Mesh first: cs platform install chaos-mesh (or pass --auto-approve to install it now)")
    before = platformmod.installed_releases(ctx)
    ui.info("Chaos Mesh is not installed yet; installing it (cs platform install chaos-mesh)")
    with env.lock(f"chaos run {env.cloud} --env {env.name}"):   # an install, like `cs platform install`
        # summary=False: the platform's closing panel (status / web UIs / k9s) does not belong in the middle of a chaos run
        _journaled_install(env, ctx, ["chaos-mesh"], before, wait=True, summary=False)
    chaos._kubectl(ctx, "-n", "chaos-mesh", "wait", "--for=condition=Available", "deployment", "--all", "--timeout=300s", timeout=330)


def _approve_worded(question: str, auto: bool, cancelled: str, nothing_applied: str) -> None:
    """_approve, with the command's own words for what did not happen (a declined prompt, or no terminal to ask on)."""
    try:
        _approve(question, auto)
    except ui.Abort as e:
        if e.code == 3:
            e.msg = nothing_applied
        elif e.code in (0, None):
            e.msg = cancelled
        raise


def cmd_chaos(args, settings) -> int:
    sub = args.chaos_cmd
    _pop_cloud_from_items(args)
    if sub == "list":
        chaos.list_experiments()
        return 0
    if sub != "run" and args.items:
        raise ui.Abort(f"`cs chaos {sub}` takes no experiment names (got: {' '.join(args.items)})")
    if sub == "report":   # reads the saved reports only: no kubeconfig, tunnel or reachable cluster needed
        _resolve_plain_env(args, settings, "chaos report", prefer_cluster=True)
        _cloud, env, _cfg = _load_env(args)
        for path in reversed(_chaos_reports(env)):
            rep = _load_chaos_report(path, env.id)
            if rep is not None:
                chaos.print_report(rep, path)
                return 0
            ui.warn(f"Skipping the unreadable chaos report {path.name} (empty, cut short or not a report).")
        raise ui.Abort("No chaos report yet: cs chaos run")
    if sub == "run":
        # typos (names, --suite, --target) fail here, before any kubeconfig, tunnel or Chaos Mesh install
        _check_chaos_names(args.items)
        chaos.resolve_names(args.items, args.suite)
        if args.target:
            chaos.parse_target(args.target)
            if args.replicas is not None:
                ui.warn("--replicas only sizes the cloudseed canary; it is ignored with --target")
    cloud, env, cfg, outputs = _resolve_cluster_env(args, settings)
    ctx = platformmod.Cluster(cloud, env, cfg, outputs, services.ensure_kubeconfig(cloud, env, cfg, outputs))
    if sub == "run":
        if args.target:
            what = _chaos_target_preview(ctx, args.target)   # a missing Deployment fails before Chaos Mesh is installed
            if not args.auto_approve:
                _approve_worded(f"Inject faults into {what} (pods killed, network delayed, CPU/memory stressed)?", False,
                                "Cancelled. No fault was injected.",
                                f"No fault injected into {what}. Re-run with --auto-approve to run the experiments without a "
                                "prompt (-y alone never approves).")
        _ensure_chaos_mesh(args, env, ctx)
        rc = chaos.run(ctx, args.items, args.suite, args.target, int(args.duration), int(args.replicas or 3), args.keep)
        # the report this run saved: chaos.run names it on the context, so a parallel run's report is never taken
        # (None when it stopped before saving one: that run records nothing)
        report = getattr(ctx, "chaos_report", None)
        if args.keep:   # the canary (and any experiment left behind) is still running: undo stops it
            undo.record(env.id, f"chaos run on {env.id} (canary kept)", "argv-seq",
                        {"argvs": [["chaos", "stop", "--cloud", cloud.key, "--env", env.name, "-y"]]})
        elif report:    # everything cleaned itself up: only this run's report is left
            report = Path(report)
            undo.record(env.id, f"chaos run on {env.id} (report {report.name})", "delete-paths",
                        {"paths": [str(report), str(report.with_suffix(".md"))]}, minor=True)
        return rc
    if sub == "status":
        chaos.status(ctx)
        return 0
    if sub == "stop":
        chaos.stop(ctx)
        return 0
    return 1


# Velero object names are Kubernetes names (RFC 1123 subdomains); a restore is named <backup>-restore-<14 digits> and a
# scheduled backup <schedule>-<14 digits>, so those leave room for the suffix
_K8S_NAME = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*")
# a Go duration (time.ParseDuration) without a sign: 720h, 1.5h, 90m30s, 500ms, 0 (dr.ttl_duration applies it)
_GO_DURATION = dr.GO_DURATION
_NS_GLOB = re.compile(r"[-a-z0-9*?\[\]]{1,63}")   # a namespace pattern: app-*, team-?, *


def _ns_glob(name: str) -> bool:
    return any(ch in name for ch in "*?[")


def _check_dr_args(args) -> None:
    """Arguments of `cs dr` are checked before any cluster, Terraform or Velero work (exit 2): a typo never waits for a
    Velero install, and velero's own usage dump never hides the one line that matters."""
    sub, name = args.dr_cmd, args.name
    if sub == "restore" and not name:
        raise ui.Abort("cs dr restore <backup-name>   (see: cs dr backups)", code=2)
    if sub == "schedule" and not name:
        raise ui.Abort("cs dr schedule <name> --cron '0 2 * * *' [--namespaces a,b] [--ttl 720h]", code=2)
    if sub in ("describe", "logs") and (getattr(args, "kind", None) not in dr.INSPECT_KINDS or not name):
        raise ui.Abort(f"cs dr {sub} backup|restore <name>   (see: cs dr backups)", code=2)
    limit = {"backup": 253, "restore": 230, "schedule": 238, "describe": 253, "logs": 253}.get(sub)
    if name and limit and (len(name) > limit or not _K8S_NAME.fullmatch(name)):
        noun = getattr(args, "kind", None) if sub in ("describe", "logs") else "schedule" if sub == "schedule" else "backup"
        raise ui.Abort(f"'{name}' is not a valid {noun} name: lower-case letters, digits, "
                       f"'-' and '.', starting and ending with a letter or digit, at most {limit} characters.", code=2)
    if getattr(args, "namespaces", None) is not None:
        names = [n.strip() for n in args.namespaces.split(",") if n.strip()]
        # a name, '*', or a pattern of them (app-*: Velero matches namespace globs)
        bad = [n for n in names if not (_NS_NAME.fullmatch(n) or (_ns_glob(n) and _NS_GLOB.fullmatch(n)))]
        if not names or bad:
            raise ui.Abort(f"--namespaces takes comma-separated namespace names (got '{args.namespaces}'"
                           + (f"; not a namespace name: {', '.join(bad)}" if bad else "") + ").", code=2)
        args.namespaces = ",".join(names)
    if sub == "schedule":
        if not dr.CRON_RE.match((args.cron or "").strip()):
            raise ui.Abort(f"--cron '{args.cron}' is not a cron expression: use 5 fields (minute hour day-of-month month "
                           "day-of-week, e.g. '0 2 * * *') or a descriptor like @daily / @every 6h.", code=2)
        ttl = str(args.ttl or "").strip()
        # one rule with dr.schedule: a Go duration; Go has no day unit, so Nd = N*24h; empty is Velero's default
        # (exit 2 for anything else)
        args.ttl = dr.ttl_duration(ttl)
        if args.ttl != ttl:
            ui.info(f"--ttl {ttl or '(empty)'} = {args.ttl}")


def _velero_names(ctx, kind: str) -> set[str] | None:
    """Names of the Velero objects of a kind (backup, restore), or None when velero cannot say."""
    proc = dr._velero(ctx, kind, "get", "-o", "json", check=False, quiet=True)
    if proc.returncode != 0:
        return None
    return {str((i.get("metadata") or {}).get("name")) for i in dr._items(proc.stdout)}


def _restorable_backup(ctx, name: str) -> dict:
    """The source backup of a restore, read before anything else happens: a missing or unusable one stops here, before
    the approval and before the undo-point backup of the cluster is taken."""
    proc = dr._velero(ctx, "backup", "get", name, "-o", "json", check=False, quiet=True)
    text = (proc.stderr or "") + (proc.stdout or "")
    if proc.returncode != 0:
        if "not found" in text.lower():
            raise ui.Abort(f"No backup named {name} (cs dr backups). A backup made from another cluster shows up here about a "
                           "minute after Velero synced its bucket.")
        raise ui.Abort(f"Could not read backup {name}: {secrets.redact(dr.velero_error(proc))}")
    items = dr._items(proc.stdout)
    backup = items[0] if items else {}
    phase = str((backup.get("status") or {}).get("phase") or "")
    if phase not in ("Completed", "PartiallyFailed"):
        raise ui.Abort(f"Backup {name} is {phase or 'in an unknown state'}: only a Completed or PartiallyFailed backup can be "
                       "restored (cs dr backups).")
    return backup


def _restore_started(ctx, backup: str, before: set[str] | None) -> bool:
    """Did `velero restore create` get as far as a Restore that runs (it may have changed objects), or did it never
    start (the create failed, or Velero refused it)? Unknown counts as started: the undo point is then kept."""
    return _started_restore(ctx, backup, before)[0]


def _started_restore(ctx, backup: str, before: set[str] | None) -> tuple[bool, str | None]:
    """(_restore_started, the name of the Restore this run created when it can be told): an interrupted --wait leaves
    it running in the cluster, and its undo must wait for it (undo.py reads its phase)."""
    now = _velero_names(ctx, "restore")
    if now is None or before is None:
        return True, None
    new = sorted(n for n in now - before if n.startswith(f"{backup}-restore-"))
    if not new:
        return False, None
    return str(dr._status(ctx, "restore", new[-1]).get("phase") or "") != "FailedValidation", new[-1]


def _dr_restore(args, cloud, env, ctx) -> int:
    source = _restorable_backup(ctx, args.name)
    _approve_worded(f"Restore {args.name} into {env.id} (existing objects are updated)?", args.auto_approve,
                    "Cancelled. Nothing was restored.",
                    f"Nothing restored into {env.id}. Re-run with --auto-approve to restore {args.name} without a prompt "
                    "(-y alone never approves).")
    ns_before = _namespaces_now(ctx)
    included = [n for n in (source.get("spec") or {}).get("includedNamespaces") or [] if n and n != "*"]
    asked = [n for n in (args.namespaces or "").split(",") if n and n != "*"]
    # the namespaces the restore can touch: the ones asked for, within the backup's own (None: the whole cluster). A
    # pattern (app-*) cannot be matched here, so it counts as the whole cluster: the undo point then covers everything.
    included = [] if any(_ns_glob(n) for n in included) else included
    asked = [] if any(_ns_glob(n) for n in asked) else asked
    affected = sorted(set(asked) & set(included)) if asked and included else (asked or included or None)
    candidates = sorted(set(affected or []) - (ns_before or set())) if ns_before is not None else []
    existing = [n for n in affected or [] if n not in candidates]
    if affected is None:
        pre = undo.velero_pre_backup(ctx, "restore", None)
    elif existing:   # only what exists now: a namespace the restore creates is removed by the undo, not backed up
        pre = undo.velero_pre_backup(ctx, "restore", existing)
    else:
        pre = None
    restores = _velero_names(ctx, "restore")
    try:
        restore = dr.restore(ctx, args.name, args.namespaces, wait=not args.no_wait)
    except (ui.Abort, KeyboardInterrupt):
        started, restore = _started_restore(ctx, args.name, restores)
        if started:   # objects may have changed: keep the way back
            _record_restore_undo(args, cloud, env, ctx, pre, ns_before, candidates, existing, affected, " (failed part-way)",
                                 restore=restore)
        else:
            undo.discard_velero_backup(ctx, pre)
        raise
    _record_restore_undo(args, cloud, env, ctx, pre, ns_before, candidates, existing, affected, "", restore=restore)
    return 0


def _record_restore_undo(args, cloud, env, ctx, pre, ns_before, candidates, existing, affected, suffix: str,
                         restore: str | None = None) -> None:
    """The undo entry of `cs dr restore`. `restore` (the Restore it created) lets the undo refuse until it has finished:
    a --no-wait restore (or an interrupted --wait) still runs in the cluster, and undoing it meanwhile would race Velero
    writing the objects back."""
    if args.no_wait:   # Velero creates the namespaces later: the ones it will create are those the backup brings and that are missing
        new_ns = candidates
        if affected is None:
            suffix += " (--no-wait: namespaces it creates later are not removed by undo)"
    else:
        now = _namespaces_now(ctx)
        new_ns = sorted((now or set()) - ns_before) if now is not None and ns_before is not None else candidates
    summary = f"dr restore {args.name}{suffix}"
    if pre:
        undo.record(env.id, summary, "velero-restore", {"backup": pre, "new_namespaces": new_ns,
                                                         **({"restore": restore} if restore else {})})
    elif new_ns:   # (the restore's name: undo.py waits for it to finish before it deletes what it creates)
        undo.record(env.id, summary, "argv-seq",
                    {"argvs": [["kubectl", cloud.key, "--env", env.name, "delete", "ns", *new_ns, "--ignore-not-found"]],
                     **({"restore": restore} if restore else {})})
    elif affected is None or existing:   # the undo-point backup failed (velero_pre_backup said why)
        undo.record(env.id, summary, "info", {"advice": "the Velero backup taken before the restore failed, so this restore "
                                                        "cannot be undone automatically (cs dr status)"})


def cmd_dr(args, settings) -> int:
    sub = args.dr_cmd
    _check_dr_args(args)
    cloud, env, cfg, outputs = _resolve_cluster_env(args, settings)
    kc = services.ensure_kubeconfig(cloud, env, cfg, outputs)
    ctx = platformmod.Cluster(cloud, env, cfg, outputs, kc)
    if sub in ("describe", "logs"):   # read-only: never installs Velero (dr.show says when it is missing)
        return dr.show(ctx, sub, args.kind, args.name, details=bool(getattr(args, "details", False)))
    if not dr.installed(ctx):
        if sub == "status":
            ui.panel(f"Disaster recovery · {env.id}", [ui.dim("Velero is not installed."),
                                                       f"{ui.style('install ', 'muted')} cs platform install velero   (creates the backup bucket + identity in your cloud first)"])
            return 0
        if not args.auto_approve and not (ui.interactive() and ui.confirm("Velero is not installed yet. Install it now (bucket + identity are created in your cloud)?", default=True)):
            raise ui.Abort("Install Velero first: cs platform install velero")
        # journaled like `cs platform install velero`: the undo chain then is <this command> -> uninstall velero ->
        # the cloud prerequisites (whose undo keeps the bucket), never the bucket from under a running Velero
        platformmod.ensure_tools()   # without helm the releases below would read as none
        before = platformmod.installed_releases(ctx)
        with env.lock(f"dr {sub} {cloud.key} --env {env.name}"):
            needed = platformmod.missing_prereqs(["velero"], ctx, releases=before)
            if needed:
                outputs = _apply_prereqs(cloud, env, cfg, needed, args.auto_approve)
                ctx = platformmod.Cluster(cloud, env, cfg, outputs, kc)
            # summary=False: the platform's closing panel (status / web UIs / k9s) does not belong in the middle of `cs dr`
            _journaled_install(env, ctx, ["velero"], before, wait=True, summary=False)
    if sub == "status":
        dr.status(ctx)
        return 0
    if sub == "backup":
        name = dr.backup(ctx, args.name, args.namespaces, wait=not args.no_wait)
        undo.record(env.id, f"dr backup {name}", "dr-delete", {"what": "backup", "name": name})
        return 0
    if sub == "restore":
        return _dr_restore(args, cloud, env, ctx)
    if sub == "backups":
        dr.backups(ctx)
        return 0
    if sub == "schedule":
        dr.schedule(ctx, args.name, args.cron, args.namespaces, args.ttl)
        undo.record(env.id, f"dr schedule {args.name}", "dr-delete", {"what": "schedule", "name": args.name})
        return 0
    if sub == "test":
        rc = dr.test(ctx, keep=args.keep, with_volume=None if args.volume is None else args.volume)
        if args.keep:   # without --keep the drill removes its namespace and backup itself: nothing to undo
            _record_kept_drill(cloud, env, getattr(ctx, "dr_drill", None))   # what this run left (set with its report)
        return rc
    return 1


def _undo_kind_known(kind: str, data: dict) -> bool:
    """Does this cloudseed's undo know how to revert an entry of `kind`? (undo.describe names an unknown kind by its
    bare name.) Lets a command record the precise inverse when undo has it, and a coarser one otherwise."""
    try:
        return undo.describe({"kind": kind, "scope": "", "data": data}) != kind
    except Exception:  # noqa: BLE001 - a describe that cannot render this data: treat the kind as unknown
        return False


def _record_kept_drill(cloud, env: paths.Env, drill) -> None:
    """The undo point of `dr test --keep`: exactly what this run left behind - the drill namespace and, when the drill
    got as far as starting it, its backup (dr.test sets ctx.dr_drill once the report is saved). A drill that stopped
    before that, or an undo without the 'dr-drill' kind, gets the namespace-only inverse."""
    data = None
    if isinstance(drill, dict) and drill.get("kept", True):
        data = {"namespace": str(drill.get("namespace") or dr.DRILL_NS), "backup": drill.get("backup") or None}
    if data is not None and _undo_kind_known("dr-drill", data):
        what = "namespace and backup " + data["backup"] if data["backup"] else "namespace"
        undo.record(env.id, f"dr test on {env.id} (drill {what} kept)", "dr-drill", data, minor=True)
        return
    ns = data["namespace"] if data is not None else dr.DRILL_NS
    undo.record(env.id, f"dr test on {env.id} (drill namespace kept)", "argv-seq",
                {"argvs": [["kubectl", cloud.key, "--env", env.name, "delete", "ns", ns, "--ignore-not-found"]]}, minor=True)


def _report_verdict(path) -> str | None:
    try:
        return str(json.loads(Path(path).read_text()).get("verdict") or "").upper() or None
    except (OSError, ValueError, AttributeError, TypeError):
        return None


def _scan_outputs(env, made: list) -> list[str]:
    """What this scan run wrote: each report (.json + .md) and the raw tool output it names (kubescape/trivy file,
    openscap-/prowler- directory). Never a directory listing: a scan running next to this one (another terminal, the
    web console, an agent) keeps its own files when this run is undone."""
    root = (env.dir / "scans").resolve()
    out: list[str] = []
    for p in made:
        if not p:
            continue
        p = Path(p)
        cands = [p, p.with_suffix(".md")]
        try:
            raw = json.loads(p.read_text()).get("raw")
        except (OSError, ValueError, AttributeError):
            raw = None
        if raw:
            cands.append(Path(raw))
        for c in cands:
            try:
                inside = root in c.resolve().parents
            except OSError:
                inside = False
            if inside and c.exists() and c.resolve() not in (root, root / "raw"):
                out.append(str(c))
    return list(dict.fromkeys(out))


def cmd_scan(args, settings) -> int:
    """Exits 1 when a verdict is FAIL (or, for `all`, a scan could not run), like `cs chaos run` and `cs dr test`."""
    sub = args.scan_cmd
    if sub == "reports" and getattr(args, "last", None) is not None and args.last < 1:   # 0 would read as "none yet"
        raise ui.Abort(f"--last must be 1 or more (got {args.last}).", code=2)
    # a --host typo stops here (exit 2), before any environment, kubeconfig or tunnel work; bastion/vpn/k8s in any
    # spelling (comma-separated, repeated, any case)
    hosts = scan.parse_hosts(args.host)
    cluster_kinds = {"cis", "kube", "images"}
    ctx = None
    cluster_problem = None
    if sub in cluster_kinds:
        cloud, env, cfg, outputs = _resolve_cluster_env(args, settings)
        ctx = platformmod.Cluster(cloud, env, cfg, outputs, services.ensure_kubeconfig(cloud, env, cfg, outputs))
    else:
        # the environment the user is in (explicit > --env > cs env use > the only one); its cluster, when it has one,
        # adds the Kubernetes checks to stig/fips/all
        _resolve_plain_env(args, settings, f"scan {sub}", prefer_cluster=sub in ("all", "fips", "stig"))
        cloud, env, cfg = _load_env(args)
        outputs = _cached_outputs(env)
        if sub in ("all", "fips", "stig") and _has_cluster(env):
            kc, cluster_problem = _best_effort(lambda: services.ensure_kubeconfig(cloud, env, cfg, outputs))
            if cluster_problem:
                ui.warn(f"Cluster checks skipped (the cluster of {env.id} is not reachable: {cluster_problem})")
            else:
                ctx = platformmod.Cluster(cloud, env, cfg, outputs, kc)
    if sub == "reports":
        scan.show_reports(env, args.last)
        return 0
    made: list = []
    claimed: list = []   # every output this run created (scan.collect): also the partial ones of a scan that failed
    errors: list = []
    try:
        # everything this run's scans claim (reports, raw tool output) is collected too: a scan that fails part-way
        # leaves outputs no returned report names (openscap-<run>/, a raw trivy file), never a parallel scan's files
        with scan.collect() as claimed:
            if sub == "cis":
                made.append(scan.cis(ctx))
            elif sub == "kube":
                made.append(scan.kube(ctx, args.framework))
            elif sub == "images":
                made.append(scan.images(ctx))
            elif sub == "host":
                made.append(scan.host(cloud, env, cfg, outputs, hosts, args.profile or "cis"))
            elif sub == "stig":
                if ctx is not None and ctx.distro in scan.STIG_BENCHMARKS and not args.host:
                    made.append(scan.cis(ctx, stig=True))
                made.append(scan.host(cloud, env, cfg, outputs, hosts, "stig"))
            elif sub == "cloud":
                made.append(scan.cloud_scan(cloud, env, cfg, args.framework))
            elif sub == "fips":
                made.append(scan.fips(cloud, env, cfg, outputs, ctx))
            elif sub == "all":
                if cluster_problem:   # the environment has a cluster its checks could not reach: `all` did not run them
                    errors.append("cluster checks (cis/kube/images)")
                # named hosts that are not there make `all` fail (exit 1); the default selection skips absent ones
                made += scan.run_all(cloud, env, cfg, outputs, ctx, hosts, errors=errors, explicit_hosts=bool(args.host))
            else:
                return 1
    finally:   # also when a later scan stopped: the reports and raw outputs already written stay undoable
        # (only what this run claimed or reported, inside scans/ and still there: never a parallel scan's files)
        produced = _scan_outputs(env, made + list(claimed))
        if produced:
            undo.record(env.id, f"scan {sub} on {env.id}", "delete-paths", {"paths": produced}, minor=True)
    failed = [Path(p).stem for p in made if p and _report_verdict(p) == "FAIL"]
    return 1 if failed or errors else 0


# ---------------------------------------------------------------- kubectl / helm / k9s passthrough

def _strip_leading_sep(rest) -> list[str]:
    """Drop the one `--` that separates cloudseed's arguments from the tool's; every later `--` belongs to the tool
    (`kubectl exec pod -- sh -c ...`, `kubectl run x --image=i -- sleep 1`)."""
    rest = list(rest or [])
    return rest[1:] if rest[:1] == ["--"] else rest


def _pull_env_arg(args, rest: list[str]) -> list[str]:
    """`--env NAME` / `-e NAME` / `--env=NAME` / `-eNAME` in front of the tool's own arguments."""
    if rest[:1] in (["--env"], ["-e"]) and len(rest) > 1:
        args.env = rest[1]
        return rest[2:]
    if rest and rest[0].startswith("--env="):
        args.env = rest[0].split("=", 1)[1]
        return rest[1:]
    if rest and rest[0].startswith("-e") and not rest[0].startswith("--") and len(rest[0]) > 2:
        args.env = rest[0][2:]
        return rest[1:]
    return rest


# ---------------------------------------------------------------- kubectl / helm command lines
# The one reader of kubectl/helm arguments: `cs kubectl|helm` (agent-session refusals, pre-change undo points) and
# undo.kubectl_namespaces all go through _kube_args, so a command line is never read two different ways.

# flags whose value is the next word (kubectl globals + the common per-command ones); `--flag=value` counts too
_KUBECTL_VALUE_FLAGS = frozenset((
    "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "--server", "--token", "--as", "--as-group", "--as-uid",
    "--request-timeout", "--cache-dir", "--certificate-authority", "--client-certificate", "--client-key", "--tls-server-name",
    "--profile", "--profile-output", "--v", "--vmodule",
    "--filename", "--kustomize", "--selector", "--output", "--patch", "--patch-file", "--container", "--containers",
    "--field-selector", "--type", "--replicas", "--image", "--timeout", "--grace-period", "--field-manager", "--overrides",
    "--port", "--label-columns", "--sort-by", "--template", "--from", "--from-literal", "--from-file", "--from-env-file",
    "--env", "--keys", "--prefix", "--labels", "--restart", "--limits", "--requests", "--to-revision", "--revision", "--name",
    "--target-port", "--protocol", "--external-ip", "--load-balancer-ip", "--session-affinity", "--cluster-ip", "--min",
    "--max", "--cpu-percent", "--current-replicas", "--resource-version", "--subresource", "--for", "--since",
    "--since-time", "--tail", "--chunk-size", "--raw", "--pod-running-timeout", "--serviceaccount", "--service-account",
    "--docker-server", "--docker-username", "--docker-password", "--docker-email", "--cert", "--key", "--clusterrole",
    "--role", "--group", "--verb", "--resource", "--resource-name",
    # kubectl create/run/expose options that take a value (never one with an optional value such as --cascade/--dry-run)
    "--schedule", "--hard", "--scopes", "--rule", "--class", "--default-backend", "--annotation", "--annotations", "--tcp",
    "--node-port", "--external-name", "--value", "--description", "--preemption-policy", "--min-available",
    "--max-unavailable", "--image-pull-policy", "--override-type", "--duration", "--audience", "--bound-object-kind",
    "--bound-object-name", "--bound-object-uid", "--non-resource-url", "--aggregation-rule", "--clusterip",
))
_HELM_VALUE_FLAGS = frozenset((
    "--namespace", "--values", "--set", "--set-string", "--set-file", "--set-json", "--set-literal", "--version",
    "--kube-context", "--kubeconfig", "--output", "--repo", "--username", "--password", "--timeout", "--description",
    "--post-renderer", "--post-renderer-args", "--ca-file", "--cert-file", "--key-file", "--keyring", "--history-max",
    "--max", "--kube-apiserver", "--kube-as-user", "--kube-as-group", "--kube-token", "--kube-ca-file",
    "--kube-tls-server-name", "--registry-config", "--repository-cache", "--repository-config", "--burst-limit", "--qps",
    "--labels", "--selector", "--filter", "--name-template", "--cascade",
))
# one-letter flags that take a value (`-n shop`, `-nshop`, `-n=shop`); the others are switches and may be bundled (-it)
_SHORT_VALUE_FLAGS = {"kubectl": "nfklopcsLve", "helm": "nfol"}
_NAMESPACE_KINDS = frozenset(("ns", "namespace", "namespaces"))
_NS_NAME = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")   # RFC 1123 label: what a namespace name can be
_CLUSTER_KINDS = frozenset((
    "node", "nodes", "no", "pv", "persistentvolume", "persistentvolumes", "sc", "storageclass", "storageclasses",
    "crd", "crds", "customresourcedefinition", "customresourcedefinitions", "clusterrole", "clusterroles",
    "clusterrolebinding", "clusterrolebindings", "pc", "priorityclass", "priorityclasses", "ingressclass", "ingressclasses",
    "apiservice", "apiservices", "mutatingwebhookconfiguration", "mutatingwebhookconfigurations",
    "validatingwebhookconfiguration", "validatingwebhookconfigurations", "validatingadmissionpolicy",
    "validatingadmissionpolicies", "validatingadmissionpolicybinding", "validatingadmissionpolicybindings",
    "csidriver", "csidrivers", "csinode", "csinodes", "runtimeclass", "runtimeclasses", "volumeattachment",
    "volumeattachments", "volumesnapshotclass", "volumesnapshotclasses", "clusterissuer", "clusterissuers",
    "gatewayclass", "gatewayclasses", "clusterpolicy", "clusterpolicies",
))
_ROLLOUT_MUTATING = frozenset(("undo", "restart", "pause", "resume"))
_NODE_INVERSE = {"cordon": "uncordon", "uncordon": "cordon", "drain": "uncordon"}


def _flag_on(value) -> bool:
    """A switch that is set: `--x`, `--x=true`, `--dry-run=client` - not `--x=false`, `--dry-run=none` or absent."""
    return value is not None and value is not False and str(value).lower() not in ("false", "none", "0")


def _kube_args(tool: str, rest: list[str]) -> dict:
    """Flag-aware reading of kubectl/helm arguments: {"pos", "flags", "ns", "all_ns"}. The values of flags that take one
    (`-n prod`, `-f v.yaml`, `--set a=b`) are never mistaken for the verb or the release; `--namespace=x`, `-nx` and
    `-n=x` count; the last namespace flag wins; everything after `--` is the pod's command and is not looked at."""
    long_flags = _KUBECTL_VALUE_FLAGS if tool == "kubectl" else _HELM_VALUE_FLAGS
    short = _SHORT_VALUE_FLAGS.get(tool, "")
    pos: list[str] = []
    flags: dict = {}
    ns = None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--":
            break
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if eq:
                flags[name] = val
            elif name in long_flags:
                val = rest[i + 1] if i + 1 < len(rest) else ""
                flags[name] = val
                i += 1
            else:
                flags[name] = True
            if name == "--namespace":
                ns = val
        elif a.startswith("-") and len(a) > 1 and not a[1:].replace(".", "").isdigit():
            if a[1] in short:
                if len(a) > 2:                      # -nshop / -n=shop / -ojson
                    val = a[3:] if a[2] == "=" else a[2:]
                else:
                    val = rest[i + 1] if i + 1 < len(rest) else ""
                    i += 1
                flags["-" + a[1]] = val
                if a[1] == "n":
                    ns = val
            elif len(a) > 2 and a[2] == "=":        # -w=false: a switch with an explicit value
                flags["-" + a[1]] = a[3:]
            else:
                for ch in a[1:]:                    # -it, -A, -g ...
                    flags["-" + ch] = True
        else:
            pos.append(a)
        i += 1
    all_ns = tool == "kubectl" and (flags.get("-A") is True or _flag_on(flags.get("--all-namespaces")))
    return {"pos": pos, "flags": flags, "ns": ns or None, "all_ns": all_ns}


def _kubectl_targets(verb: str, pos: list[str]) -> list[tuple[str, str | None]]:
    """(kind, name) pairs a kubectl verb acts on: `delete ns a b`, `delete ns/a deploy/b`, `rollout restart deploy/x`."""
    rest = pos[2:] if verb in ("rollout", "set") else pos[1:]
    if not rest:
        return []
    if "/" in rest[0]:
        out = []
        for tok in rest:
            if "/" in tok:                          # `label ns/shop team=a`: the rest are labels, not resources
                kind, _, name = tok.partition("/")
                out.append((kind.lower(), name or None))
        return out
    kinds = [k.lower() for k in rest[0].split(",") if k]
    return [(k, n) for k in kinds for n in (rest[1:] or [None])]


def _kubectl_scope(verb: str, pos: list[str], a: dict) -> list[str] | None:
    """Namespaces a mutating kubectl call touches, for the Velero safety backup (None = the whole cluster). Deleting,
    patching or labelling namespaces backs up exactly those (Namespace object included); cluster-scoped kinds, node
    operations and manifests (-f/-k) without -n back up everything; anything else the -n namespace (or default)."""
    if a["all_ns"] or verb in ("drain", "cordon", "uncordon", "taint"):
        return None                                 # node operations act on the cluster (and every pod on those nodes)
    flags = a["flags"]
    if any(f in flags for f in ("-f", "--filename", "-k", "--kustomize")):
        return [a["ns"]] if a["ns"] else None   # manifests name their own namespaces
    default_ns = a["ns"] or "default"
    targets = _kubectl_targets(verb, pos)
    if not targets:
        return [default_ns]
    out: list[str] = []
    for kind, name in targets:
        base = kind.split(".", 1)[0]
        if base in _NAMESPACE_KINDS:
            if not name or _flag_on(flags.get("--all")) or "-l" in flags or "--selector" in flags:
                return None                         # which namespaces is not known up front
            if _NS_NAME.fullmatch(name):            # not the `team=a` / `note-` of `label ns shop team=a`
                out.append(name)
        elif base in _CLUSTER_KINDS:
            return None
        else:
            out.append(default_ns)
    return sorted(set(out)) or None


def _kubectl_mutates(a: dict) -> bool:
    """Would this kubectl call change the cluster? Read-only verbs, rollout status/history, --dry-run, label/annotate
    --list and --local (label/annotate/set) do not."""
    pos, flags = a["pos"], a["flags"]
    if not pos or pos[0] not in undo.MUTATING_KUBECTL or _flag_on(flags.get("--dry-run")):
        return False
    if pos[0] == "rollout" and (len(pos) < 2 or pos[1] not in _ROLLOUT_MUTATING):
        return False
    if pos[0] in ("label", "annotate") and _flag_on(flags.get("--list")):
        return False
    return not _flag_on(flags.get("--local"))


def _kubectl_inverse(a: dict) -> list[str] | None:
    """kubectl arguments that revert a node operation (cordon <-> uncordon, drain -> uncordon; `node/n2` is n2), or None."""
    pos = a["pos"]
    inverse = _NODE_INVERSE.get(pos[0]) if pos else None
    nodes = [n.split("/", 1)[1] if n.startswith(("node/", "nodes/", "no/")) else n for n in pos[1:]]
    return [inverse, *nodes] if inverse and nodes else None


_KUBECTL_TTY_VERBS = frozenset(("exec", "attach", "run", "debug"))


def _needs_terminal(tool: str, rest: list[str]) -> str | None:
    """Why this call needs an interactive terminal (k9s, kubectl edit, exec/attach/run/debug with -i/-t), or None."""
    if tool == "k9s":
        return "k9s is a full-screen terminal UI"
    if tool != "kubectl":
        return None
    a = _kube_args("kubectl", rest)
    verb = a["pos"][0] if a["pos"] else ""
    if verb == "edit":
        return "kubectl edit opens an editor"
    if verb in _KUBECTL_TTY_VERBS and any(_flag_on(a["flags"].get(f)) for f in ("-i", "-t", "--stdin", "--tty")):
        return f"kubectl {verb} -i/-t is interactive"
    return None


_KUBECTL_ENDLESS_VERBS = frozenset(("port-forward", "proxy", "attach"))


def _never_ends(tool: str, rest: list[str]) -> str | None:
    """Why this kubectl call never finishes on its own (logs -f, get/events -w, port-forward ...), or None. An agent
    session waits for the call's whole output, so such a call would hang until the client gives up."""
    if tool != "kubectl":
        return None
    a = _kube_args("kubectl", rest)
    pos, flags = a["pos"], a["flags"]
    verb = pos[0] if pos else ""
    if verb in _KUBECTL_ENDLESS_VERBS:
        return f"kubectl {verb} runs until it is stopped"
    if verb == "logs":
        # -f takes no value, but the reader cannot know that: `logs -f pod/x` reads as {-f: pod/x}; only -f=false is off
        follow = _flag_on(flags.get("--follow")) or ("-f" in flags and str(flags["-f"]).lower() not in ("false", "0"))
        if follow:
            return "kubectl logs -f follows the log until it is stopped"
    if verb in ("get", "events") and any(_flag_on(flags.get(f)) for f in ("-w", "--watch", "--watch-only")):
        return f"kubectl {verb} -w watches until it is stopped"
    raw = str(flags.get("--raw") or "")
    if verb == "get" and re.search(r"[?&](watch|follow)=(true|1)\b", raw):
        return "a watch/follow request never ends"
    return None


def cmd_ktool(args, settings) -> int:
    """cs kubectl|helm|k9s ... : run the tool against the current environment's cluster."""
    tool = args.cmd
    rest = _strip_leading_sep(args.tool_args)
    if not getattr(args, "tool_verbatim", False):
        # `cs kubectl aws --env dev get pods`, `cs kubectl --env=dev get pods` and plain `cs kubectl get pods`. After an
        # explicit `--` (tool_verbatim: MCP and the console always send `kubectl [cloud] [--env X] -- <args>`) the words
        # are the tool's: a cloud key or --env among them never re-selects the cluster.
        if rest and rest[0] in CLOUD_KEYS:
            args.cloud = rest.pop(0)
        rest = _strip_leading_sep(_pull_env_arg(args, rest))
    redacted = secrets.redact_enabled()
    if redacted:   # an agent session: the tool's output is redacted line by line, which needs a plain, non-interactive run
        why = _needs_terminal(tool, rest)
        if why:
            raise ui.Abort(f"{why}, which is not available inside an agent session (its output is redacted and it gets no "
                           f"terminal). Run it in your own terminal instead: cs {tool} ...", code=2)
        endless = _never_ends(tool, rest)
        if endless:
            raise ui.Abort(f"{endless}, and an agent session waits for the whole output, so the call would hang until it is "
                           "cancelled. Use a bounded form: logs --tail=200 or --since=10m (without -f), get / events without "
                           "-w, or kubectl wait --for=condition=... --timeout=120s. Streams and port-forwards belong in your "
                           f"own terminal: cs {tool} ...", code=2)
    cloud, env, cfg, outputs = _resolve_cluster_env(args, settings)
    kc = services.ensure_kubeconfig(cloud, env, cfg, outputs)
    binary = services.ensure_tool(tool, "to talk to the cluster")
    ctx = platformmod.Cluster(cloud, env, cfg, outputs, kc)
    # the same process environment as the platform installer: KUBECONFIG, cloudseed's Helm homes and a registry/Docker
    # config without credential helpers that are not on PATH (Helm 4 would otherwise fail on OCI charts)
    kenv = ctx.procenv()
    if tool == "helm":
        _migrate_helm_registry_login(Path(kenv["HELM_REGISTRY_CONFIG"]))
        for var in ("DOCKER_CONFIG", "HELM_REGISTRY_CONFIG"):   # an explicit choice of the caller wins
            if os.environ.get(var):
                kenv[var] = os.environ[var]
    # secret flag values (--password x, --from-literal k=v, helm's -p) are never shown or journaled; the tool decides
    # what -p is (kubectl logs -p POD / patch -p '{...}' keep their value, helm's is a password)
    shown = " ".join(managed.mask_argv(rest, tool, auth=True))   # echoed and journaled: Authorization headers go too
    ui.eprint(ui.dim(f"  [{env.id}] $ {tool} {shown}"))   # plain text when stderr is redirected
    pre = _pre_change_undo(tool, rest, cloud, env, cfg, outputs, kc, ctx=ctx)
    if redacted:   # its output bypasses cloudseed's redacting stdout otherwise (secrets, tokens, kubeconfig data)
        # piped input stays available (`-f -`); a terminal never is, so no prompt can hang behind line-buffered output
        try:
            piped = not sys.stdin.isatty()
        except (AttributeError, ValueError, OSError):
            piped = False
        rc = secrets.run_redacted([binary, *rest], env=kenv, stdin=None if piped else subprocess.DEVNULL)
    else:
        rc = subprocess.call([binary, *rest], env=kenv)
    if pre:
        _finish_change_undo(pre, rc, tool, shown, cloud, env, ctx)
    return rc


def _migrate_helm_registry_login(reg: Path) -> None:
    """`cs helm registry login` used to write Helm's default registry file; the platform installer reads cloudseed's own
    one. Carry an existing login over once so both see it."""
    old = paths.HOME / "helm" / "config" / "registry" / "config.json"
    try:
        if old.exists() and (not reg.exists() or reg.read_text().strip() in ("", "{}")):
            reg.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(old, reg)
            os.chmod(reg, 0o600)
    except OSError:
        pass


def _helm_revisions(ctx, release: str, ns: str) -> list[int]:
    proc = subprocess.run([deps.find("helm"), "history", release, "-n", ns, "-o", "json"], env=ctx.procenv(), capture_output=True, text=True)
    try:
        return [int(r["revision"]) for r in json.loads(proc.stdout or "[]") if str(r.get("revision", "")).isdigit() or isinstance(r.get("revision"), int)]
    except (ValueError, TypeError, KeyError):
        return []


_HELM_PAGE = 256   # helm list returns at most --max releases per call (256 by default)


def _helm_releases_in(ctx, ns: str) -> set[str] | None:
    """Releases in a namespace (any live status), or None when helm cannot say. Explicit status filters: Helm 3 lists
    only deployed+failed by default and Helm 4 rejects -a/--all; these flags mean the same on both. Paged like
    platform.installed_releases: a release past the first page must not read as new (or as gone)."""
    helm = deps.find("helm")
    if not helm:
        return None
    base = [helm, "list", "-n", ns, "-q", "--deployed", "--failed", "--pending", "--uninstalling", "--max", str(_HELM_PAGE)]
    out: set[str] = set()
    offset = 0
    while True:
        try:
            proc = subprocess.run(base + (["--offset", str(offset)] if offset else []), env=ctx.procenv(),
                                  capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode != 0:
            return None
        page = proc.stdout.split()
        before = len(out)
        out.update(page)
        if len(page) < _HELM_PAGE or len(out) == before or offset > 100 * _HELM_PAGE:
            return out   # the last page (or a helm that ignores --offset: nothing new came back)
        offset += len(page)


def _namespaces_now(ctx) -> set[str] | None:
    proc = subprocess.run([deps.find("kubectl") or "kubectl", "get", "ns", "-o", "jsonpath={.items[*].metadata.name}"],
                          env=ctx.procenv(), capture_output=True, text=True)
    return set(proc.stdout.split()) if proc.returncode == 0 else None


# kinds Velero never restores (its non-restorable resources): an undo point cannot bring their changes back
_NODE_KINDS = frozenset(("node", "nodes", "no"))
_NOT_RESTORABLE_KINDS = _NODE_KINDS | {"csinode", "csinodes", "volumeattachment", "volumeattachments"}


def _kube_spec(token: str) -> bool:
    """A label/annotation argument (`team=a`, `example.com/team-`), not a resource: names never hold '=' or end in '-'."""
    return "=" in token or token.endswith("-")


def _non_restorable_targets(pos: list[str]) -> list[str] | None:
    """The names a label/annotate/patch/delete of Node-like objects acts on ([] for -l/--all), or None when the call
    also (or only) touches other kinds."""
    toks = [t for t in pos[1:] if not _kube_spec(t)]
    if not toks:
        return None
    if "/" in toks[0]:
        pairs = [t.split("/", 1) for t in toks]
        if all(k.lower().split(".", 1)[0] in _NOT_RESTORABLE_KINDS for k, _ in pairs):
            return [n for _, n in pairs if n]
        return None
    kinds = [k.lower().split(".", 1)[0] for k in toks[0].split(",") if k]
    return toks[1:] if kinds and all(k in _NOT_RESTORABLE_KINDS for k in kinds) else None


def _node_change_undo(verb: str, pos: list[str], a: dict, names: list[str], cloud, env, ctx) -> tuple | None:
    """Velero does not restore Nodes: a label/annotate of named nodes records the exact inverse (the previous values
    read right before); anything else (patch, delete, -l/--all) records how to revert it by hand."""
    flags = a["flags"]
    by_hand = ("info", {"advice": f"Velero does not restore Node objects, so this {verb} is not undone automatically: revert it "
                                  "by hand (label/annotate: <key>- removes a key, <key>=<old value> --overwrite restores one; a "
                                  "deleted node registers again when its kubelet restarts)"}, {"minor": True, "success_only": True})
    first = next((t for t in pos[1:] if not _kube_spec(t)), "")
    if verb not in ("label", "annotate") or not names or any(f in flags for f in ("-l", "--selector")) or \
            _flag_on(flags.get("--all")) or first.lower().split("/", 1)[0].split(".", 1)[0] not in _NODE_KINDS:
        return by_hand
    specs = [t for t in pos[1:] if _kube_spec(t)]
    field = "labels" if verb == "label" else "annotations"
    keys = list(dict.fromkeys(spec.split("=", 1)[0] if "=" in spec else spec[:-1] for spec in specs))
    argvs, nodes = [], []
    for n in names:
        current = _node_field(ctx, n, field)
        if current is False:
            continue   # no such node: kubectl changes nothing there (it still labels the nodes that exist)
        if current is None:
            return by_hand
        old = {key: current.get(key) for key in keys}
        inverse = [f"{key}={val}" if val is not None else f"{key}-" for key, val in old.items()
                   if val is not None or any(s.split("=", 1)[0] == key for s in specs if "=" in s)]
        if inverse:
            argvs.append(["kubectl", cloud.key, "--env", env.name, verb, "node", n, *inverse, "--overwrite"])
            nodes.append([n, old])
    # a call that fails part-way (`label node a b k=v` with b missing, or refused on one node) may still have changed
    # the others: _finish_change_undo keeps the inverse of each node whose values really changed
    return ("argv-seq", {"argvs": argvs}, {"success_only": True, "node_values": {"field": field, "nodes": nodes}}) if argvs else None


def _node_field(ctx, name: str, field: str):
    """A node's labels or annotations: a dict, False when the cluster has no such node (the API server's NotFound
    only), None when it cannot be read."""
    kubectl = deps.find("kubectl") or "kubectl"
    try:
        proc = subprocess.run([kubectl, "get", "node", name, "-o", "json"], env=ctx.procenv(), capture_output=True,
                              text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        err = proc.stderr or ""
        return False if "(NotFound)" in err or f'nodes "{name}" not found' in err else None
    try:
        current = (json.loads(proc.stdout or "{}").get("metadata") or {}).get(field) or {}
    except (ValueError, AttributeError):
        return None
    return current if isinstance(current, dict) else None


def _changed_node_inverses(ctx, argvs: list, info: dict) -> list:
    """The inverses (one per node, as _node_change_undo recorded them) of the nodes a failed label/annotate did change;
    a node that cannot be read now keeps its inverse (it may have changed)."""
    kept = []
    for argv, (name, old) in zip(argvs, info.get("nodes") or []):
        now = _node_field(ctx, name, info.get("field") or "labels")
        if not isinstance(now, dict) or any(now.get(k) != v for k, v in old.items()):
            kept.append(argv)
    return kept


def _named_creations(verb: str, pos: list[str], a: dict) -> list[str] | None:
    """kind/name of what `kubectl create <kind> NAME`, `run NAME`, `expose ... [--name N]` or `autoscale ... [--name N]`
    creates ([] for create token: nothing lasting), or None when the call is not one of these. The name must be the only
    word left where kubectl expects it: an extra word (the value of an option this reader does not know, `--foo bar`)
    means the name cannot be told for sure, and the undo would delete another object - such calls get the backup."""
    flags = a["flags"]
    if verb == "create":
        sub = pos[1].lower() if len(pos) > 1 else ""
        if sub == "token":
            return []
        if sub in ("secret", "service", "svc"):   # create secret generic NAME / create service clusterip NAME
            return [f"{'secret' if sub == 'secret' else 'service'}/{pos[3]}"] if len(pos) == 4 else None
        return [f"{sub}/{pos[2]}"] if len(pos) == 3 and sub else None
    if verb == "run":
        if len(pos) != 2:
            return None
        return [f"pod/{pos[1]}"] + ([f"service/{pos[1]}"] if _flag_on(flags.get("--expose")) else [])
    if verb in ("expose", "autoscale"):
        name = flags.get("--name")
        if not isinstance(name, str) or not name:
            tg = _kubectl_targets(verb, pos)
            if len(tg) != 1 or not tg[0][1]:
                return None
            name = tg[0][1]
        return [f"{'service' if verb == 'expose' else 'horizontalpodautoscaler'}/{name}"]
    return None


def _delete_argvs(cloud, env, groups: dict) -> list[list[str]]:
    """`cs kubectl` calls deleting the given objects ({namespace or None: [kind/name, ...]}), namespaces last."""
    argvs, namespaces = [], []
    for ns, refs in groups.items():
        objs = [r for r in refs if r.split("/", 1)[0].lower() not in _NAMESPACE_KINDS]
        namespaces += [r.split("/", 1)[1] for r in refs if r.split("/", 1)[0].lower() in _NAMESPACE_KINDS]
        if objs:
            argvs.append(["kubectl", cloud.key, "--env", env.name, *(["-n", ns] if ns else []), "delete", *objs, "--ignore-not-found"])
    if namespaces:
        argvs.append(["kubectl", cloud.key, "--env", env.name, "delete", "ns", *dict.fromkeys(namespaces), "--ignore-not-found"])
    return argvs


def _json_documents(text: str) -> list:
    """Every JSON document in `text` (kubectl prints one per object for some verbs); ValueError on anything else."""
    dec, docs, i = json.JSONDecoder(), [], 0
    text = text or ""
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return docs
        doc, i = dec.raw_decode(text, i)
        docs.append(doc)


def _manifest_objects(ctx, rest: list[str], a: dict) -> list[dict] | None:
    """The objects a create/apply -f|-k call will write, read with a dry run of the same arguments (never stdin):
    [{"ref": "deployment.apps/web", "kind", "name", "ns": explicit namespace or None}], None when they cannot be told."""
    flags = a["flags"]
    if "-" in (flags.get("-f"), flags.get("--filename")) or _flag_on(flags.get("--prune")):
        return None
    kubectl = deps.find("kubectl")
    if not kubectl:
        return None
    head = rest[:rest.index("--")] if "--" in rest else list(rest)
    mode = "server" if _flag_on(flags.get("--server-side")) else "client"
    try:
        proc = subprocess.run([kubectl, *head, f"--dry-run={mode}", "-o", "json"], env=ctx.procenv(), capture_output=True,
                              text=True, timeout=120, stdin=subprocess.DEVNULL)
        docs = _json_documents(proc.stdout) if proc.returncode == 0 else None
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return None
    if not docs or not all(isinstance(d, dict) for d in docs):
        return None
    # apply prints one List; create prints each object as its own document
    items = [i for d in docs for i in (d.get("items") or [] if d.get("kind") == "List" else [d])]
    out = []
    for o in items:
        if not isinstance(o, dict):
            return None
        meta = o.get("metadata") or {}
        kind, name = str((o or {}).get("kind") or ""), meta.get("name")
        if not kind or not name:
            return None   # generateName: the name is known only afterwards
        group = str((o or {}).get("apiVersion") or "").rpartition("/")[0]
        out.append({"ref": f"{kind.lower()}{'.' + group if group else ''}/{name}", "kind": kind, "name": name,
                    "ns": meta.get("namespace") or a["ns"]})
    return out or None


def _existing_objects(ctx, objs: list[dict]) -> dict | None:
    """{ref+namespace: the live object} for those of `objs` that exist now, None when the cluster cannot say."""
    kubectl = deps.find("kubectl")
    found: dict = {}
    groups: dict = {}
    for o in objs:
        groups.setdefault(o["ns"], []).append(o["ref"])
    for ns, refs in groups.items():
        proc = subprocess.run([kubectl, *(["-n", ns] if ns else []), "get", *refs, "--ignore-not-found", "-o", "json"],
                              env=ctx.procenv(), capture_output=True, text=True)
        if proc.returncode != 0:
            return None
        try:
            data = json.loads(proc.stdout or "{}") if proc.stdout.strip() else {}
        except ValueError:
            return None
        live = data.get("items") if data.get("kind") == "List" else ([data] if data else [])
        for obj in live or []:
            meta = obj.get("metadata") or {}
            found[(str(obj.get("kind") or "").lower(), meta.get("name"), ns)] = obj
    return found


def _manifest_undo(verb: str, rest: list[str], a: dict, cloud, env, ctx, ns_before: set | None):
    """create/apply -f|-k: objects that do not exist yet are deleted by the undo (exactly those, also after a run that
    failed part-way); objects that exist are brought back from a Velero backup of just their namespaces. None when the
    manifests cannot be read here (the caller backs up by namespace as before); False when there is nothing to undo (a
    create of objects that all exist changes nothing)."""
    objs = _manifest_objects(ctx, rest, a)
    if not objs:
        return None
    live = _existing_objects(ctx, objs)
    if live is None:
        return None
    key = lambda o: (o["kind"].lower(), o["name"], o["ns"])  # noqa: E731
    new = [o for o in objs if key(o) not in live]
    changed = [live[key(o)] for o in objs if key(o) in live]
    groups: dict = {}
    for o in new:
        groups.setdefault(o["ns"], []).append(o["ref"])
    if verb == "create" or not changed:   # create never touches what exists; an apply of only new objects neither
        if not new:
            return False
        return ("argv-seq", {"argvs": _delete_argvs(cloud, env, groups)}, {"exact": True})
    if any(not (obj.get("metadata") or {}).get("namespace") and str(obj.get("kind")) != "Namespace" for obj in changed):
        scope = None   # a cluster-scoped object is changed: the whole cluster
    else:
        scope = sorted({(obj.get("metadata") or {}).get("namespace") or (obj.get("metadata") or {}).get("name") for obj in changed})
    created = [{"ns": ns, "ref": r} for ns, refs in groups.items() for r in refs]
    kind, data, notes = _velero_undo_point(ctx, "kubectl", scope, {"ns_before": ns_before}, "kubectl change")
    if kind == "velero-restore" and created:
        data["created"] = created   # undo deletes these (they are not in the backup, so the restore keeps them)
    return kind, data, notes


# options with which a call reaches past the environment's kubeconfig: another kubeconfig file, or an API server given
# directly. (--context/--cluster/--user only choose among the entries of the kubeconfig cloudseed hands the tool, which
# holds just this environment's cluster; identity options such as --token or --as keep the cluster.)
_CLUSTER_OPTIONS = {"kubectl": ("--kubeconfig", "--server", "-s"), "helm": ("--kubeconfig", "--kube-apiserver")}


def _cluster_override(tool: str, a: dict, kubeconfig=None) -> list[str]:
    """The options of a kubectl/helm call (read by _kube_args) that point it at a cluster other than the environment's
    (a --kubeconfig naming the environment's own file does not)."""
    flags = a["flags"]
    used = [f for f in _CLUSTER_OPTIONS.get(tool, ()) if f in flags and flags[f] not in (None, "", True, False)]
    if used == ["--kubeconfig"] and kubeconfig:
        try:
            if Path(str(flags["--kubeconfig"])).expanduser().resolve() == Path(kubeconfig).resolve():
                return []
        except (OSError, RuntimeError, ValueError):
            pass
    return used


def _elsewhere_undo(tool: str, options: list[str], env) -> tuple[str, dict, dict]:
    """Undo of a call that picked its own cluster: none automatic. The Velero undo point, the Helm history, a node's
    previous labels are read from the environment's own cluster, and a recorded inverse would run there too - on a
    cluster this call may not have touched."""
    return ("info", {"advice": f"this {tool} call chose its cluster itself ({', '.join(options)}), and cloudseed's undo points "
                               f"cover only {env.id}'s own cluster: it is not undone automatically, revert it by hand"},
            {"minor": True, "success_only": True})


def _pre_change_undo(tool: str, rest: list[str], cloud, env, cfg, outputs, kc, ctx=None) -> tuple[str, dict, dict] | None:
    """Make mutating kubectl/helm calls undoable: helm install -> uninstall, helm upgrade/rollback -> rollback to the previous
    revision, cordon/drain <-> uncordon, a label/annotate of nodes -> the previous values, creating new objects -> deleting
    exactly those, everything else -> a Velero backup of the touched namespaces taken right before (when Velero is
    installed). Returns (kind, data, notes for after the call) or None when nothing needs recording.
    The arguments are read flag-aware (_kube_args, the parser undo.kubectl_namespaces uses too): the values of
    -n/--context/-f ... are never taken for the verb or the release, so `kubectl -n shop delete pod x` is a delete of a
    pod in shop.

    notes: success_only - record nothing when the call fails (a failed create/cordon changed nothing, and its inverse
    could remove what was there before); node_values - a label/annotate of named nodes: after a failed call, keep the
    inverse of each node whose values did change (it overrides success_only); exact - the inverse is right also after a
    call that failed part-way.
    A call that picks its own cluster (--kubeconfig, --server) gets no automatic undo: the undo points are read from,
    and replayed on, the environment's own cluster."""
    if os.environ.get("CLOUDSEED_UNDOING"):
        return None   # an undo replaying `cs kubectl ...` takes no new safety backup (its entry would be dropped anyway)
    if tool not in ("kubectl", "helm"):
        return None
    a = _kube_args(tool, rest)
    pos, flags = a["pos"], a["flags"]
    if not pos or _flag_on(flags.get("--dry-run")):
        return None
    verb = pos[0]
    elsewhere = _cluster_override(tool, a, kc or getattr(ctx, "kubeconfig", None))
    if tool == "helm":
        if elsewhere and verb in ("install", "upgrade", "rollback", "uninstall", "delete", "del", "un"):
            return _elsewhere_undo(tool, elsewhere, env)
        ns = a["ns"] or "default"
        generate = _flag_on(flags.get("--generate-name")) or _flag_on(flags.get("-g"))
        release = pos[1] if len(pos) > 1 and not (verb == "install" and generate) else None   # `install --generate-name CHART`
        ctx = ctx or platformmod.Cluster(cloud, env, cfg, outputs, kc)
        if verb == "install" and generate:   # the name is known only afterwards: the release that is new then
            return ("helm", {"ns": ns}, {"generated_from": _helm_releases_in(ctx, ns)})
        if verb in ("install", "upgrade") and release:
            revs = _helm_revisions(ctx, release, ns)
            return ("helm", {"release": release, "ns": ns, **({"revision": max(revs)} if revs else {})}, {})
        if verb == "rollback" and release:
            revs = _helm_revisions(ctx, release, ns)
            return ("helm", {"release": release, "ns": ns, "revision": max(revs)}, {}) if revs else None
        if verb in ("uninstall", "delete", "del", "un"):
            return _velero_undo_point(ctx, "helm", [ns], {}, "helm uninstall")
        return None
    if not _kubectl_mutates(a):
        return None   # read-only verbs, rollout status/history, label --list, --local
    if elsewhere:
        return _elsewhere_undo(tool, elsewhere, env)
    if verb in ("cordon", "uncordon", "drain"):   # Velero does not restore Node objects: record the direct inverse
        inverse = _kubectl_inverse(a)
        if not inverse:
            return None
        # a failed drain has already cordoned the node; a failed cordon/uncordon changed nothing
        return ("argv-seq", {"argvs": [["kubectl", cloud.key, "--env", env.name, *inverse]]}, {"success_only": verb != "drain"})
    if verb == "taint":
        return ("info", {"advice": "remove a taint again with: cs kubectl taint nodes <node> <key>[:<effect>]-"}, {"minor": True, "success_only": True})
    manifests = any(f in flags for f in ("-f", "--filename", "-k", "--kustomize"))
    ctx = ctx or platformmod.Cluster(cloud, env, cfg, outputs, kc)
    if verb in ("label", "annotate", "patch", "delete") and not manifests:
        names = _non_restorable_targets(pos)
        if names is not None:   # a whole-cluster backup would be slow and still revert nothing
            return _node_change_undo(verb, pos, a, names, cloud, env, ctx)
    if not manifests:
        refs = _named_creations(verb, pos, a)
        if refs is not None:   # a successful create made exactly these new objects: deleting them is the whole undo
            if not refs:
                return None
            return ("argv-seq", {"argvs": _delete_argvs(cloud, env, {a["ns"]: refs})}, {"success_only": True})
    ns_before = _namespaces_now(ctx) if verb in ("apply", "create", "replace") else None
    if manifests and verb in ("create", "apply"):
        exact = _manifest_undo(verb, rest, a, cloud, env, ctx, ns_before)
        if exact is False:
            return None
        if exact is not None:
            return exact
    scope = _kubectl_scope(verb, pos, a)
    if scope is not None and ns_before is not None and verb in ("apply", "create", "replace"):
        # a namespace that does not exist yet has nothing to back up (Velero would mark the backup PartiallyFailed);
        # the undo deletes it again when the call creates it
        scope = [n for n in scope if n in ns_before]
        if not scope:
            return ("info", {"advice": "nothing existed to back up"}, {"minor": True, "ns_before": ns_before, "nothing_before": True})
    notes: dict = {"ns_before": ns_before} if ns_before is not None else {}
    # a whole-cluster point holds object state only (fast), unless the change deletes data: `delete -A`, `delete ns
    # --all` / `-l ...`, `delete -f` without -n, PersistentVolumes or a CRD (its resources go along, and the PVCs they
    # own). Their undo must bring the pod volumes back too, or it restores empty PVCs.
    volumes = True if scope is None and verb == "delete" and _delete_takes_data(pos, a) else None
    return _velero_undo_point(ctx, "kubectl", scope, notes, "kubectl change", volumes=volumes)


# cluster-scoped kinds whose delete takes no pod volume data along (roles, classes, webhooks, policies ...): a
# whole-cluster undo point for it needs object state only - copying every volume in the cluster first would only be slow
_DATALESS_CLUSTER_KINDS = _CLUSTER_KINDS - frozenset((
    "pv", "persistentvolume", "persistentvolumes", "crd", "crds", "customresourcedefinition", "customresourcedefinitions"))


def _delete_takes_data(pos: list[str], a: dict) -> bool:
    """A `kubectl delete` across the cluster that may remove volume data: anything but a delete of only data-free
    cluster-scoped kinds (-A, namespaces, manifests without -n, PersistentVolumes, CRDs, mixed kinds)."""
    if a["all_ns"] or any(f in a["flags"] for f in ("-f", "--filename", "-k", "--kustomize")):
        return True
    targets = _kubectl_targets("delete", pos)
    return not targets or not all(kind.split(".", 1)[0] in _DATALESS_CLUSTER_KINDS for kind, _ in targets)


def _velero_undo_point(ctx, label: str, namespaces: list[str] | None, notes: dict, what: str,
                       volumes: bool | None = None) -> tuple[str, dict, dict]:
    """A Velero safety backup right before the change, or an info entry saying why there is none. volumes: see
    undo.velero_pre_backup (None: the default for the scope)."""
    b = undo.velero_pre_backup(ctx, label, namespaces, **({"volumes": volumes} if volumes is not None else {}))
    if b:
        return ("velero-restore", {"backup": b, "new_namespaces": []}, dict(notes, backup=b))
    try:
        installed = dr.installed(ctx)
    except (Exception, ui.Abort):  # noqa: BLE001 - only picks the wording of the advice
        installed = False
    if installed:   # Velero is there but its backup failed (velero_pre_backup has said why): no undo point this time
        advice = f"the Velero pre-change backup failed, so this {what} cannot be undone automatically (cs dr status)"
    else:
        advice = f"a {what} is undone from a Velero backup; install Velero (cs platform install velero) to make it undoable"
    return ("info", {"advice": advice}, dict(notes, minor=True))


def _finish_change_undo(pre: tuple, rc: int, tool: str, shown: str, cloud, env, ctx) -> None:
    """Record the undo entry of a kubectl/helm call once it ran. A call that failed may still have changed the cluster
    (kubectl goes on through several objects, a helm --wait that timed out leaves a FAILED revision, a drain cordons
    first): its entry is kept, marked '(failed part-way)', unless the call certainly changed nothing."""
    kind, data, notes = pre
    failed = rc != 0
    minor = bool(notes.get("minor"))

    def nothing() -> None:
        undo.discard_velero_backup(ctx, notes.get("backup"))   # only the TTL would remove it from the bucket otherwise

    if failed and notes.get("node_values"):
        # a label/annotate of several nodes goes on past a node it cannot change: the inverses of the nodes it did
        # change are kept (checked against the values read before), the others dropped
        argvs = _changed_node_inverses(ctx, data["argvs"], notes["node_values"])
        if not argvs:
            return nothing()
        data = dict(data, argvs=argvs)
    elif failed and notes.get("success_only"):
        return nothing()
    if "generated_from" in notes:
        now = _helm_releases_in(ctx, data["ns"])
        if now is None or notes["generated_from"] is None:
            if not failed:
                undo.record(env.id, f"{tool} {ui.clip(shown, 50)}", "info",
                            {"advice": f"the name of the release this install generated could not be read; uninstall it by "
                                       f"hand: cs helm uninstall <name> -n {data['ns']} (cs helm list -n {data['ns']})"})
            return nothing()
        new = sorted(now - notes["generated_from"])
        if len(new) != 1:
            return nothing()
        data["release"] = new[0]
    elif kind == "helm" and failed:   # only a failed call that left a new revision changed anything
        revs = _helm_revisions(ctx, data["release"], data["ns"])
        if not revs or max(revs) <= int(data.get("revision") or 0):
            return nothing()
    if notes.get("ns_before") is not None:
        now = _namespaces_now(ctx)
        new_ns = sorted((now or set()) - notes["ns_before"])
        if new_ns and kind == "velero-restore":
            data["new_namespaces"] = new_ns
        elif new_ns and kind == "info":   # no Velero, but the namespaces this call created can still be removed again
            kind, data, minor = "argv-seq", {"argvs": [["kubectl", cloud.key, "--env", env.name, "delete", "ns", *new_ns, "--ignore-not-found"]]}, False
    if kind == "info" and (failed or notes.get("nothing_before")):
        return nothing()   # nothing to revert automatically: a failed call (or one into a new namespace) needs no advice entry
    summary = f"{tool} {ui.clip(shown, 50)}" + (" (failed part-way)" if failed else "")   # cut at a word, never mid-word
    # retries of the same failing call take one undo slot and keep the first undo point (the one from before them all)
    entry = undo.record(env.id, summary, kind, data, minor=minor, coalesce=f"failed:{tool} {shown}" if failed else None)
    if notes.get("backup") and (entry.get("data") or {}).get("backup") not in (None, notes["backup"]):
        nothing()   # coalesced into an earlier failed attempt: this backup is not the undo point


# ---------------------------------------------------------------- finops

def _usd(amount) -> str:
    v = round(float(amount or 0), 2) + 0.0   # + 0.0 turns -0.0 into 0.0
    return f"-${abs(v):,.2f}" if v < 0 else f"${v:,.2f}"


def cmd_finops(args, settings) -> int:
    """Each requested view either shows real numbers or says why it cannot; `cloud`/`k8s` exit 1 when theirs could not be
    produced (a local environment's $0 bill is an answer, not a failure); `report` needs only the estimate."""
    sub = args.finops_cmd
    _resolve_plain_env(args, settings, f"finops {sub}")
    cloud, env, cfg = _load_env(args)
    outputs = _cached_outputs(env)
    report: dict = {"env": env.id, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    views: list[str] = []
    rc = 0
    if sub in ("estimate", "report"):
        est = finops.estimate(cloud, env, cfg)
        report["estimate"] = est
        total = ("≥ " if est.get("lower_bound") else "") + _usd(est["total"])   # a lower bound when some prices are unknown
        rows = [(name, _usd(cost)) for name, cost in est["lines"]] + [("", ""), (ui.style("total / month", "bold", "text"), ui.style(total, "bold", "leaf"))]
        notes = [ui.dim(n) for n in est.get("notes", [])]
        ui.panel(f"Estimate · {env.id}  ({est['period']})", rows + ([""] + notes if notes else []))
        views.append("estimate")
    if sub in ("cloud", "report"):
        if cloud.local:
            ui.info(f"{cloud.display} environments run on this machine: no cloud bill ($0). "
                    f"The VMs it runs: cs finops estimate {cloud.key} --env {env.name}")
            report["cloud"] = {"provider": cloud.key, "total": 0, "by_service": {}, "error": None, "note": "local VMs have no cloud bill"}
            views.append("cloud")
        else:
            with ui.Spinner(f"Fetching the last {args.days} days from {cloud.display}"):
                act = finops.cloud_actuals(cloud, cfg, args.days)
            report["cloud"] = act
            if act.get("error"):
                ui.warn(f"Cloud bill unavailable: {act['error']}")
                rc = 1 if sub == "cloud" else rc
            else:
                rows = [(svc, _usd(amt)) for svc, amt in sorted(act["by_service"].items(), key=lambda kv: -kv[1])[:20]]
                rows += [("", ""), (ui.style("total", "bold", "text"), ui.style(_usd(act["total"]), "bold", "leaf"))]
                ui.panel(f"{cloud.display} bill · whole account/subscription · {act['from']} → {act['to']}", rows)
                views.append("cloud")
    if sub in ("k8s", "report"):
        if not _has_cluster(env):
            ui.warn(f"No Kubernetes cluster in {env.id}. {_no_cluster_hint(env)}, then cs platform install finops")
            report["kubernetes"] = {"error": "no cluster"}
            rc = 1 if sub == "k8s" else rc
        else:
            if sub == "k8s":
                kc, problem = services.ensure_kubeconfig(cloud, env, cfg, outputs), None
            else:
                kc, problem = _best_effort(lambda: services.ensure_kubeconfig(cloud, env, cfg, outputs))
            if problem:
                ui.warn(f"Kubernetes costs unavailable: {problem}")
                report["kubernetes"] = {"error": problem}
            else:
                ctx = platformmod.Cluster(cloud, env, cfg, outputs, kc)
                with ui.Spinner("Querying OpenCost"):
                    oc = finops.opencost(ctx, args.window, args.by)
                report["kubernetes"] = oc
                if oc.get("error"):
                    ui.warn(f"Kubernetes costs unavailable: {oc['error']}")
                    rc = 1 if sub == "k8s" else rc
                else:
                    over = False
                    rows = []
                    for n, r in sorted(oc["rows"].items(), key=lambda kv: -kv[1]["total"])[:25]:
                        eff = int(r.get("efficiency") or 0)
                        over = over or eff > 100
                        rows.append((f"{n}", f"{_usd(r['total'])}   cpu {_usd(r['cpu'])}  ram {_usd(r['ram'])}  pv {_usd(r['pv'])}   "
                                             f"eff {eff}%" + ("*" if eff > 100 else "")))
                    rows += [("", ""), (ui.style("total", "bold", "text"), ui.style(_usd(oc["total"]), "bold", "leaf"))]
                    if over:
                        rows.append(("", ui.dim("* above 100%: the workload uses more than it requests (raise its requests)")))
                    ui.panel(f"Kubernetes allocation by {args.by} · last {args.window} (OpenCost)", rows)
                    views.append("kubernetes")
    if sub == "report" or args.save:
        if not views or rc != 0:
            ui.warn("Not saved: the requested cost view could not be produced (the last saved report is kept).")
            return rc or 1
        path = finops.save_report(env, report)
        undo.record(env.id, f"finops report {Path(path).name}", "delete-paths", {"paths": [str(path)]}, minor=True)
        ui.ok(f"Report saved: {path}   (cs agentic \"analyze my finops report and suggest savings\")")
    return rc


# ---------------------------------------------------------------- explain

_EXPLAIN_NAMESPACES = ("feature", "target", "topic", "command", "group", "item")


def _explain_also(word: str, *shown: str) -> None:
    """A bare word can name several things (vmware: feature, target and topic; security: group and topic): say where the
    others are (explain.also_for, wrapped to the terminal by explain.print_also)."""
    explain.print_also(explain.also_for(word, *shown))


def cmd_explain(args, settings) -> int:
    """One resolution (explain.resolve) for the page and for --json (explain.lookup): the same words find the same thing."""
    words = [w for w in ([args.feature] + (args.more or [])) if w]
    if getattr(args, "json", False):
        res = explain.lookup(words)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res["found"] else 1
    res = explain.resolve(words)
    if res["error"]:
        raise ui.Abort(res["error"])
    explain.show(res)
    return 0


# ---------------------------------------------------------------- managed data platforms

def _pull_profile_arg(rest: list[str]) -> tuple[list[str], str | None]:
    """`--profile NAME` before the first `--` is cloudseed's (help shows it after the subcommand). To hand the vendor CLI its
    own --profile, start its arguments with `--`: cs databricks -- clusters list --profile X."""
    out: list[str] = []
    prof = None
    i = 0
    while i < len(rest):
        t = rest[i]
        if t == "--":
            out += rest[i:]
            break
        if t == "--profile" and i + 1 < len(rest):
            prof = rest[i + 1]
            i += 2
            continue
        if t.startswith("--profile="):
            prof = t.split("=", 1)[1]
            i += 1
            continue
        out.append(t)
        i += 1
    return out, prof


def _managed_profile(service: str, explicit: str | None, current: str | None) -> tuple[str, str | None]:
    """The profile to use: --profile > the current environment's own profile > the saved 'default' one."""
    if explicit:
        return explicit, None
    if current and managed.profile(service, current):
        return current, None
    if current and managed.profile(service, "default"):
        return "default", (f"No {service} profile for {current}; using the 'default' profile "
                           f"(per-environment one: cs {service} connect while {current} is current, or pass --profile NAME)")
    return current or "default", None


def cmd_managed(args, settings) -> int:
    service = args.cmd
    _pull_env_from_remainder(args, "svc_args")
    rest, prof = _pull_profile_arg(list(args.svc_args or []))
    rest = _strip_leading_sep(rest)
    explicit = args.profile or prof
    current = settings.get("current_env")
    env_name = getattr(args, "env", None)
    if env_name:   # --env NAME: that environment's profile
        envs = paths.Env.list_all()
        same = [e for e in envs if env_name in (e.name, e.id)]
        if not same:
            raise ui.Abort(f"No environment named '{env_name}'. Known: {', '.join(e.id for e in envs) or 'none'}")
        if len(same) > 1:
            raise ui.Abort(f"Several environments are named '{env_name}' ({', '.join(e.id for e in same)}): pass the id, e.g. --env {same[0].id}")
        current = same[0].id
    if not rest or rest[0] == "status":
        managed.status()
        return 0
    if rest[0] == "connect":   # connect writes the named/current profile, never the shared 'default' one by accident
        values, prof = managed.parse_connect_args(service, rest[1:])   # --key value / key=value; unknown keys refused
        name = prof or explicit or current or "default"
        managed.connect(service, name, values)
        return managed.test(service, name)
    name, note = _managed_profile(service, explicit, current)
    if note:
        ui.info(note)
    if rest[0] == "test":
        return managed.test(service, name)
    return managed.run(service, name, rest)


def cmd_troubleshoot(args, settings) -> int:
    cloud, env, cfg = _load_env(args)
    return troubleshoot.run(cloud, env, cfg, last=args.last, show_log=args.log)


_HELPER_TYPES = ("random_", "null_", "time_", "terraform_data")   # plumbing resources: counted, not listed


def _short_address(address: str) -> str:
    return address[len("module.stack."):] if address.startswith("module.stack.") else address


def _json_stdout(args):
    """With --json, stdout carries the JSON document only: every message printed while the environment is loaded or read
    (a provider rebuild, the current-environment note, a stale-cache warning) goes to stderr, so `| jq`, agents and the
    MCP output tool always get parseable JSON."""
    import contextlib
    return contextlib.redirect_stdout(sys.stderr) if getattr(args, "json", False) else contextlib.nullcontext()


def _utc_time(value) -> str:
    """A timestamp cloudseed recorded (UTC: '2026-09-24T10:11:12Z' or '...+00:00') as '2026-09-24 10:11:12 UTC', so it
    is never read as local time; anything else as it is."""
    text = str(value or "")
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]00:?00)?$", text)
    if not m:
        return text[:19]
    return f"{m.group(1)} {m.group(2)}" + (" UTC" if m.group(3) else "")


def cmd_inventory(args, settings) -> int:
    last = getattr(args, "last", None)
    if last is not None and last < 1:
        raise ui.Abort(f"--last {last}: give the number of history entries to show (1 or more).", code=2)
    with _json_stdout(args):
        cloud, env, cfg = _load_env(args)
        inv = audit.load(env)
    if args.json:
        print(json.dumps(inv, indent=2))
        return 0
    cur = inv.get("current") or {}
    resources = cur.get("resources") or []
    updated = _utc_time(cur["updated_at"]) if cur.get("updated_at") else "never"
    ui.header(f"Inventory {env.id}  ({cur.get('count', len(resources))} resources, updated {updated})")
    helpers: dict[str, int] = {}
    for r in resources:
        rtype = str(r.get("type") or "")
        if rtype.startswith(_HELPER_TYPES):
            helpers[rtype] = helpers.get(rtype, 0) + 1
            continue
        address = str(r.get("address") or "")
        details = []
        if address and f"{rtype}." not in address:   # inventory.json of an older version: an IP attribute shadowed it
            details.append(f"address={address}")
            address = ""
        address = _short_address(address or f"{rtype}.{r.get('name', '')}")
        print(f"  {ui.style('●', 'brand')} {address}")
        shown: list[str] = []
        # the object's own name (a VM, a bucket, a role): cloud_name now; older files stored it over Terraform's `name`
        name = r.get("cloud_name") or r.get("name")
        if name and not address.endswith(f".{name}") and not re.search(re.escape(f".{name}") + r"\[[^\]]*\]$", address):
            details.append(f"name={name}")
            shown.append(str(name))
        if r.get("ip_address"):                       # an attribute called `address` (google_compute_address's IP)
            details.append(f"address={r['ip_address']}")
        ident = r.get("id")
        if ident and str(ident) not in shown and str(ident) != str(r.get("vmx_path") or ""):
            details.append(f"id={ident}")
        for k in ("public_ip", "private_ip", "ip", "endpoint", "vmx_path"):
            if r.get(k):
                v = r[k]
                details.append(f"{k}={', '.join(map(str, v)) if isinstance(v, list) else v}")
        if details:
            print("      " + ui.dim("  ".join(details)))
    if helpers:
        what = ", ".join(f"{t} ×{n}" for t, n in sorted(helpers.items()))
        print(ui.dim(f"  + {sum(helpers.values())} helper resource(s) not listed ({what}); everything: "
                     f"cs inventory {cloud.key} --env {env.name} --json"))
    if not resources:
        print(ui.dim("  (nothing deployed)"))
    print()
    print(ui.bold("History"))
    for h in (inv.get("history") or [])[-(last or 15):]:
        print(f"  {_utc_time(h.get('at'))}  {str(h.get('action')):<18} "
              + " ".join(f"{k}={v}" for k, v in h.items() if k not in ("at", "action", "by_type")))
    return 0


def _terraform_or_reason(env: paths.Env) -> tuple[Terraform | None, str]:
    """Terraform for the stack root, or (None, why) when it cannot run here (not installed): read-only commands then
    fall back to what cloudseed cached instead of failing outright."""
    try:
        return Terraform(env.stack_dir), ""
    except ui.Abort as e:
        return None, (e.msg or "terraform is not available").strip()


def _read_outputs(t: Terraform) -> dict:
    """`terraform output -json`, strictly: a failed read raises instead of looking like "no outputs" (which would wipe
    the cached outputs that ssh, list and the console rely on)."""
    from .tf import explain
    proc = t.run("output", "-json", capture=True, check=False)
    if proc.returncode != 0:
        raise TerraformError(explain((proc.stderr or "") + (proc.stdout or ""), "output", getattr(t, "workdir", None)))
    try:
        raw = json.loads(proc.stdout or "{}")
    except ValueError:
        raise TerraformError("terraform output returned something that is not JSON") from None
    return {k: (v or {}).get("value") for k, v in raw.items()} if isinstance(raw, dict) else {}


def cmd_status(args, settings) -> int:
    cloud, env, cfg = _load_env(args)
    _print_summary(cloud, env, cfg, network_resolved=not cloud.local or _vmnet_resolved(cfg))
    _render(cloud, env, cfg)
    t, problem = _terraform_or_reason(env)
    resources: list[str] = []
    state_ok = False
    if t is not None:
        try:
            with ui.Spinner("Reading Terraform state"):
                t.init()
                resources = _state_addresses(t)
            state_ok = True
        except TerraformError as e:
            problem = str(e)
    if state_ok and resources:
        outputs = _cache_outputs(env, t)
    elif state_ok:
        outputs = {}
        (env.dir / "outputs.json").unlink(missing_ok=True)   # nothing is deployed: drop a stale cache (list/ssh/env read it)
    else:
        ui.err(f"Could not read the Terraform state: {problem}")
        outputs = _cached_outputs(env)
    managed_count = len(_managed(resources))
    inv = audit.load(env)
    # the newest Terraform snapshot (apply, destroy, update-ip, node ...: they carry by_type), not a note such as a
    # finops report or a scan that changed nothing
    last = next((h for h in reversed(inv.get("history") or []) if isinstance(h, dict) and "by_type" in h), {})
    prov_info = cfg.get("provisioned") or {}
    if not state_ok:
        count = ui.style("unknown  (the state could not be read)", "rose")
    elif resources:
        count = ui.style(str(managed_count), "text", "bold")
    else:
        count = ui.dim("0  (not applied yet)")
    rows = [("Resources in state", count),
            ("Last change", f"{last.get('action', '-')}  {ui.dim(_utc_time(last.get('at')))}" if last else ui.dim("-")),
            ("Provisioned", ", ".join(f"{k} ({v.get('at', '')[:10]})" for k, v in prov_info.items()) or ui.dim("not yet"))]
    ui.panel("State", rows)
    if outputs:
        if not state_ok:
            ui.info("Last known outputs (cached; they may be stale):")
        _print_outputs(outputs, cfg)
    cmd = _ssh_command(cloud, env, cfg, outputs)
    nxt = []
    if t is None:
        nxt.append(f"{ui.style('install ', 'muted')} cloudseed install terraform")
    if not state_ok:   # never suggest (re-)creating an environment whose state simply could not be read
        nxt.append(f"{ui.style('check   ', 'muted')} cs doctor {cloud.key}   {ui.dim('(tools and credentials)')}")
        if not cloud.local:
            nxt.append(f"{ui.style('login   ', 'muted')} {cloud.login_hint}")
    elif not resources:
        nxt.append(f"{ui.style('create  ', 'muted')} cs setup {cloud.key} --env {env.name}")
    else:
        if cmd:
            nxt.append(f"{ui.style('ssh     ', 'muted')} cs ssh {cloud.key} --env {env.name}")
        nxt.append(f"{ui.style('change  ', 'muted')} cs setup {cloud.key} --env {env.name} --var key=value")
        nxt.append(f"{ui.style('destroy ', 'muted')} cs destroy {cloud.key} --env {env.name}")
    nxt.append(f"{ui.style('debug   ', 'muted')} cs troubleshoot {cloud.key} --env {env.name}")
    ui.panel("Next", nxt, accent="leaf")
    return 0 if state_ok else 1


def cmd_output(args, settings) -> int:
    with _json_stdout(args):
        cloud, env, cfg = _load_env(args)
        _render(cloud, env, cfg)
        t, problem = _terraform_or_reason(env)
        stale = False
        if t is not None:
            try:
                t.init()
                outputs = _read_outputs(t)
                try:
                    prov.forget_replaced_hosts(env, _cached_outputs(env), outputs)
                except OSError:
                    pass
                (env.dir / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n")
            except TerraformError as e:
                problem, t = str(e), None
        if t is None:   # cannot read the state here: the last known outputs, clearly marked, and a non-zero exit
            outputs, stale = _cached_outputs(env), True
            lines = [ln.strip() for ln in (problem or "").splitlines() if ln.strip()]
            why = lines[0] if lines else "unknown"
            fix = next((ln for ln in lines[1:] if ln.startswith("Fix:")), "")   # tf.explain's second line: what to do
            ui.warn(f"Could not read the outputs from the Terraform state ({why}); "
                    + ("showing the last known ones (cached; they may be stale)." if outputs else "no cached outputs either.")
                    + (f"\n  {fix}" if fix else ""))
    if args.json:
        print(json.dumps(outputs, indent=2))
    else:
        _print_outputs(outputs, cfg)
    return 1 if stale else 0


def _pull_env_from_remainder(args, attr: str) -> None:
    """argparse's catch-all swallows `--env NAME` after the cloud positional; recover it. Only the leading tokens are
    ours (`--env NAME`, `--env=NAME`, `-e NAME`, `-eNAME`): from the first other token - and always after `--` - the
    arguments belong to the wrapped tool (ssh's own -e sets its escape character, `grep -e` is a remote command)."""
    rest = list(getattr(args, attr, None) or [])
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in ("--env", "-e") and i + 1 < len(rest):
            args.env = rest[i + 1]
            i += 2
        elif tok.startswith("--env="):
            args.env = tok.split("=", 1)[1]
            i += 1
        elif tok.startswith("-e") and len(tok) > 2:
            args.env = tok[2:].lstrip("=")
            i += 1
        else:
            break
    setattr(args, attr, rest[i:])


def _parse_ssh_argv(argv: list[str]):
    """argparse drops a `--` that directly follows the cloud positional, so `cs ssh aws -- -e none` would lose the line
    between cloudseed's options and ssh's. Parse only what precedes the first `--`; keep the rest verbatim for ssh."""
    i = argv.index("--")
    _ENV_HINT["quiet"] = True        # the full parse already said which environment is used
    try:
        args = build_parser().parse_args(argv[:i])
    finally:
        _ENV_HINT["quiet"] = False
    args.ssh_args = list(args.ssh_args or []) + argv[i:]
    return args


_SSH_VALUE_OPTS = set("BbcDEeFIiJLlmOoPpQRSWw")   # ssh's getopt letters that take an argument


def _split_ssh_args(tokens: list[str]) -> tuple[list[str], list[str]]:
    """[--] ssh options [--] remote command -> (options, command). An option letter that takes a value keeps it,
    attached (-p2222, -vL8080:h:80) or as the next word (-F cfg, -o BatchMode=yes)."""
    rest = list(tokens)
    if rest[:1] == ["--"]:
        rest.pop(0)
    opts: list[str] = []
    while rest:
        tok = rest[0]
        if tok == "--":
            rest.pop(0)
            break
        if not tok.startswith("-") or tok == "-":
            break
        if tok.startswith("--"):
            raise ui.Abort(f"ssh has no option {tok}. cloudseed's own options go right after the cloud "
                           "(cs ssh aws --env dev -- -L 8080:10.0.1.5:80); everything after `--` is passed to ssh.", code=2)
        opts.append(rest.pop(0))
        for j, ch in enumerate(tok[1:], 1):
            if ch in _SSH_VALUE_OPTS:
                if j == len(tok) - 1 and rest:   # nothing attached: the value is the next word
                    opts.append(rest.pop(0))
                break
    return opts, rest


def cmd_ssh(args, settings) -> int:
    _pull_env_from_remainder(args, "ssh_args")
    opts, remote = _split_ssh_args(args.ssh_args or [])
    cloud, env, cfg = _load_env(args)
    outputs = _cached_outputs(env)
    cmd = _ssh_command(cloud, env, cfg, outputs)
    if not cmd:
        if _env_has_resources(env):
            raise ui.Abort(_no_bastion_ip(cloud, env))
        raise ui.Abort(f"No bastion IP known: {env.id} has not been applied yet, so there is no bastion to connect to. "
                       f"Apply it with: cloudseed apply {cloud.key} --env {env.name}   (or check: cloudseed status {cloud.key} "
                       f"--env {env.name})")
    # ssh options (-L, -p, -o ...) go before the destination; a remote command goes after it
    cmd = cmd[:-1] + opts + cmd[-1:] + remote
    print(ui.dim("$ " + shlex.join(cmd)))       # quoted: a working directory with spaces pastes back correctly
    rc = subprocess.call(cmd)
    if remote and rc != 255:   # 255: ssh itself failed (connect / auth), the command never ran
        # a run of remote commands takes one undo slot (the inverse is the same re-provisioning for all of them)
        undo.record(env.id, f"ssh command on {env.id}: {ui.clip(' '.join(remote), 40)}", "argv",
                    {"argv": ["provision", cloud.key, "--env", env.name, "--host", "bastion", "-y"], "note": "re-provisioning restores every cloudseed-managed setting on the host"},
                    coalesce=f"ssh-{env.id}")
    return rc


# Plan entries that carry the allowed SSH sources: the rules themselves (any action; AWS has one rule per CIDR), and
# the in-place update of a cluster's authorized networks (EKS public_access_cidrs, AKS/GKE authorized ranges).
_SSH_SOURCE_TYPES = {"aws_vpc_security_group_ingress_rule", "aws_security_group_rule", "google_compute_firewall",
                     "azurerm_network_security_rule"}
_SSH_SOURCE_CLUSTERS = {"aws_eks_cluster", "google_container_cluster", "azurerm_kubernetes_cluster"}


def _ssh_related(change: dict) -> bool:
    return change["type"] in _SSH_SOURCE_TYPES or (change["type"] in _SSH_SOURCE_CLUSTERS and change["actions"] == ["update"])


def cmd_update_ip(args, settings) -> int:
    cloud = clouds.get(args.cloud)
    if cloud.local:   # before _load_env: nothing here may start/reconfigure vmrest or fetch an image
        ui.info(f"update-ip does not apply to {cloud.key}: the VMs sit on a private VMware network that only this machine "
                "reaches, so your public IP plays no part. If SSH fails, check that the VMs are powered on "
                f"(VMware Fusion/Workstation) and run: cloudseed troubleshoot {cloud.key}" + (f" --env {args.env}" if args.env else ""))
        return 0
    cloud, env, cfg = _load_env(args)
    if args.allow_ip:
        raw = [x.strip() for item in args.allow_ip for x in item.split(",") if x.strip()]
    else:
        detected = netutil.detect_public_ip()
        if not detected:
            raise ui.Abort("Could not detect your public IP. Pass it with --allow-ip.")
        raw = [f"{detected}/32"]
    problem = netutil.validate_cidr_list(",".join(raw))
    if problem:
        raise ui.Abort(problem)
    new = netutil.normalize_cidr_list(raw)   # canonical (merged, sorted) like setup saves it
    old = list(cfg.get("allowed_ssh_cidrs") or [])
    if new == old:
        ui.ok(f"Allowed CIDRs already {', '.join(new)}; nothing to do.")
        _check_bastion_ssh(cloud, env, cfg, new)   # the address is right: if SSH still fails, say why and how to recover
        return 0
    ui.info(f"Allowed SSH sources: {', '.join(old) or '-'} -> {', '.join(new)}")
    prev_cfg = copy.deepcopy(cfg)
    # config.json changes only once Terraform has applied the new sources: a failed, declined or preview-only run
    # must leave it as it was, or the retry would report "nothing to do" while the firewall still has the old address
    cfg["allowed_ssh_cidrs"] = new
    try:
        backend_changed = _render(cloud, env, cfg)
        t = Terraform(env.stack_dir)
        t.init(migrate=backend_changed)
        if not _managed(_state_addresses(t)):
            raise ui.Abort(f"{env.id} has not been applied yet, so there is no firewall to update. Choose the allowed sources "
                           f"when you create it: cloudseed setup {cloud.key} --env {env.name} --allow-ip {','.join(new)}")
        applied = _apply_ssh_source_change(cloud, env, t, args.auto_approve)
    except BaseException:
        cfg.clear()
        cfg.update(prev_cfg)
        try:
            _render(cloud, env, cfg)   # the rendered root must not keep the sources that were not applied
        except Exception:  # noqa: BLE001 - never mask the original error
            pass
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
        raise
    env.save(cfg)
    if not applied:
        ui.ok(f"The cloud firewall already allows {', '.join(new)}; configuration updated, nothing to apply.")
        return 0
    audit.refresh(env, t, "update-ip", {"allowed_ssh_cidrs": new})
    undo.record(env.id, f"update-ip {env.id} -> {', '.join(new)}", "config", {"prev_cfg": prev_cfg, "what": "allowed SSH sources"})
    ui.ok(f"Cloud firewall updated: SSH to {env.id} is allowed from {', '.join(new)}.")
    _check_bastion_ssh(cloud, env, cfg, new)
    return 0


def _apply_ssh_source_change(cloud, env: paths.Env, t: Terraform, auto: bool) -> bool:
    """Plan, and apply only the SSH-source changes: pending unrelated changes (drift, settings saved by a --plan-only
    setup) must not ride along under a 'firewall change' label. Returns False when nothing needed applying."""
    t.plan("tfplan")
    changes = _plan_changes(t)
    question = "Apply the firewall change?"
    if changes is not None:
        related = [c for c in changes if _ssh_related(c)]
        other = [c for c in changes if not _ssh_related(c)]
        if not related:
            (env.stack_dir / "tfplan").unlink(missing_ok=True)
            if other:
                ui.info(f"{len(other)} other pending change(s) were left alone; review them with: cloudseed plan {cloud.key} --env {env.name}")
            return False
        if other:
            ui.info(f"The plan also holds {len(other)} pending change(s) unrelated to SSH access; applying only the "
                    f"{len(related)} SSH-access change(s). Review the rest with: cloudseed plan {cloud.key} --env {env.name}")
            t.plan("tfplan", targets=tuple(c["address"] for c in related))
            targeted = _plan_changes(t)
            if targeted is not None:
                related = [c for c in targeted if _ssh_related(c)]
                other = [c for c in targeted if not _ssh_related(c)]
            else:
                other = []
        if other:   # still there: dependencies of the targeted resources
            names = ", ".join(c["address"] for c in other[:4]) + (" …" if len(other) > 4 else "")
            if auto or not ui.interactive():
                (env.stack_dir / "tfplan").unlink(missing_ok=True)
                raise ui.Abort(f"The firewall change cannot be applied on its own: the plan also changes {names}. Nothing was "
                               f"changed. Review with `cloudseed plan {cloud.key} --env {env.name}`, apply with `cloudseed apply`, "
                               "then re-run update-ip.")
            ui.warn(f"The plan also changes {len(other)} resource(s) unrelated to SSH access: {names}")
            question = f"Apply this plan (includes {len(other)} change(s) unrelated to SSH access)?"
        else:
            question = f"Apply the SSH access change ({len(related)} resource(s))?"
    _approve(question, auto)
    try:
        t.apply("tfplan")
    finally:
        (env.stack_dir / "tfplan").unlink(missing_ok=True)
    return True


_BASTION_INSTANCE = {"aws": "module.stack.module.bastion.aws_instance.bastion",
                     "gcp": "module.stack.module.bastion.google_compute_instance.bastion",
                     "azure": "module.stack.module.bastion.azurerm_linux_virtual_machine.bastion"}


def _check_bastion_ssh(cloud, env: paths.Env, cfg: dict, new: list[str]) -> None:
    """The cloud firewall now admits the new address. Bastions provisioned by older cloudseed versions also pinned the
    SSH sources in their own nftables, which cannot be changed over SSH once the address has changed: check, and say
    how to recover."""
    outputs = _cached_outputs(env)
    ip = outputs.get("bastion_public_ip")
    if not ip or not (cfg.get("provisioned") or {}).get("bastion"):
        return
    host = prov.Host(ip, cloud.ssh_user(cfg), env.private_key_path(cfg), "bastion", env=env)
    reachable = False
    with ui.Spinner("Checking SSH to the bastion from here"):
        for delay in (0, 5, 15):   # cloud firewall changes take a few seconds to reach the edge
            time.sleep(delay)
            try:
                if subprocess.run(host.ssh("true"), capture_output=True, timeout=30).returncode == 0:
                    reachable = True
                    break
            except (OSError, subprocess.TimeoutExpired):
                pass
    if reachable:
        try:
            pinned = subprocess.run(host.ssh("sudo -n nft list set inet filter ssh_allowed 2>/dev/null"),
                                    capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.TimeoutExpired):
            pinned = ""
        ui.ok(f"SSH works: cs ssh {cloud.key} --env {env.name}")
        if "elements" in pinned:
            ui.info("The bastion's host firewall still pins SSH sources (set up by an older cloudseed). Run once: "
                    f"cloudseed provision {cloud.key} --env {env.name} - afterwards update-ip alone restores access.")
        _fail2ban_admit_new_ip(cloud, env, cfg, outputs, host, new)
        return
    v4 = ", ".join(c for c in new if ":" not in c) or "<your IPv4 address>/32"   # the host set is IPv4-only
    nft = f"nft add element inet filter ssh_allowed {{ {v4} }}"
    lines: list[str] = []
    if cloud.key == "aws":
        prof = f" --profile {cfg['vars']['profile']}" if (cfg.get("vars") or {}).get("profile") else ""
        lines.append(f"aws ssm send-command{prof} --region {cfg.get('region')} --instance-ids "
                     f"{outputs.get('bastion_instance_id') or '<bastion instance id>'} --document-name AWS-RunShellScript "
                     + "--parameters '" + json.dumps({"commands": [nft]}) + "'")
    elif cloud.key == "azure":
        lines.append(f"az vm run-command invoke --ids {outputs.get('bastion_vm_id') or '<bastion vm id>'} "
                     f"--command-id RunShellScript --scripts '{nft}'")
    else:
        lines.append(f"cloudseed destroy {cloud.key} --env {env.name} --target {_BASTION_INSTANCE.get(cloud.key, 'module.stack.module.bastion')} --auto-approve")
        lines.append(f"cloudseed setup {cloud.key} --env {env.name}      (re-creates and provisions the bastion)")
    lines.append(f"cloudseed provision {cloud.key} --env {env.name}      (the host firewall then leaves SSH sources to the cloud firewall)")
    ui.warn("The cloud firewall admits your address, but SSH to the bastion does not answer yet. Firewall changes can take "
            "a minute; if `cs ssh` keeps timing out, the bastion's own firewall (nftables, pinned to your old address by an "
            "older cloudseed) is dropping it. Fix it without SSH, then re-provision once:")
    for line in lines:   # plain lines, not a box: these are commands to copy
        print(f"    {line}")


def _fail2ban_admit_new_ip(cloud, env: paths.Env, cfg: dict, outputs: dict, bastion, new: list[str]) -> None:
    """fail2ban on the hosts ignores only the address provisioning saw (bootstrap.sh writes the SSH session's source
    into the jail): lift a ban of the new address and ignore it from now on, on the bastion and a provisioned VPN host
    that answers. Best effort (exit codes ignored); the jail file gets it with the next `cloudseed provision`."""
    ips = [c[:-3] for c in new if c.endswith("/32") and ":" not in c]
    if not ips:     # ranges only: the address this machine uses now, when it is one of them
        detected = netutil.detect_public_ip()
        ips = [detected] if detected and ":" not in detected and _ip_allowed(detected, new) else []
    if not ips:
        return
    hosts = [bastion]
    vpn_ip = outputs.get("vpn_public_ip")
    if vpn_ip and (cfg.get("provisioned") or {}).get("vpn"):
        hosts.append(prov.Host(vpn_ip, cloud.ssh_user(cfg), env.private_key_path(cfg), "vpn", env=env))
    script = "; ".join(f"sudo -n fail2ban-client set sshd unbanip {ip} >/dev/null 2>&1; "
                       f"sudo -n fail2ban-client set sshd addignoreip {ip} >/dev/null 2>&1" for ip in ips) + "; true"
    done = []
    for h in hosts:
        try:
            if subprocess.run(h.ssh(script), capture_output=True, timeout=60).returncode == 0:
                done.append(h.label)
        except (OSError, subprocess.TimeoutExpired):
            continue
    if done:
        ui.info(f"fail2ban on the {' and the '.join(done)} no longer bans {', '.join(ips)} (until it restarts); "
                f"`cloudseed provision {cloud.key} --env {env.name}` puts it into the jail for good.")


def _fit_path(path: str, width: int) -> str:
    """~ for the home directory, then a middle ellipsis: both ends of a path say the most."""
    home = str(Path.home())
    if path == home or path.startswith(home + os.sep):
        path = "~" + path[len(home):]
    if len(path) <= width:
        return path
    if width < 5:
        return path[:width]
    head = (width - 1) // 3
    return path[:head] + "…" + path[len(path) - (width - 1 - head):]


def cmd_list(args, settings) -> int:
    envs = paths.Env.list_all()
    if not envs:
        ui.info(f"No environments yet (looked in {paths.ENVS_DIR}). Start with: cloudseed setup aws")
        return 0
    rows, broken = [], []
    for e in envs:
        cfg, problem = e.try_load()
        if problem:
            broken.append(problem)
            rows.append([e.id, "(config.json unreadable)", "", "", "-", "", str(e.dir)])
            continue
        out = _cached_outputs(e)
        state = cfg.get("state")
        state = state if isinstance(state, dict) else {}   # a hand-edited "state": "local" (as headliner._env_line reads it)
        rows.append([e.id, cfg.get("name") or "", cfg.get("region") or "", state.get("type") or "",
                     out.get("bastion_public_ip") or "-", str(cfg.get("updated_at") or "")[:19].replace("T", " "), str(e.dir)])
    headers = ["ENV", "NAME", "REGION", "STATE", "BASTION IP", "UPDATED (UTC)", "WORKDIR"]
    if ui.stdout_is_tty():   # piped output keeps every column and whole absolute paths, so scripts can use them
        # fit the terminal: every column keeps its natural width except WORKDIR, which is shortened in the middle
        widths = [max(len(h), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
        room = ui.cols() - 3 - 2 * (len(headers) - 1) - sum(widths[:-1])
        if room < 24:   # narrow terminal: drop UPDATED before squeezing the path unreadable
            headers.pop(5)
            for r in rows:
                r.pop(5)
            room += widths.pop(5) + 2
        room = max(16, min(room, 60))       # ui.table cuts a longer cell at its end; the middle says more for a path
        for r in rows:
            r[-1] = _fit_path(r[-1], room)
    print()
    ui.table(headers, rows)
    for problem in broken:
        ui.warn(problem)
    return 0


def _doctor_row(row: dict, col: int) -> None:
    if row["path"] and row.get("outdated"):
        _doctor_line(ui.style("✖", "rose", "bold"), row["tool"], col, ui.style(row["version"][:22].ljust(22), "rose"),
                     f"too old: cloudseed install {row['tool']}")
    elif row["path"]:
        _doctor_line(ui.style("✔", "leaf", "bold"), row["tool"], col, ui.style(row["version"][:22].ljust(22), "text"),
                     row["path"], path=True)
    elif row["required"]:
        _doctor_line(ui.style("✖", "rose", "bold"), row["tool"], col, ui.style("missing".ljust(22), "rose"), row["desc"])
    else:
        _doctor_line(ui.style("○", "muted"), row["tool"], col, ui.style("optional".ljust(22), "dim"), row["desc"])


def _doctor_line(mark: str, tool: str, col: int, ver: str, tail: str, path: bool = False) -> None:
    """One doctor row: mark, tool, version, then the path or description. At a terminal the tail fits the width: a
    path is shortened in the middle, a description wraps under its own column. Piped output is never changed."""
    lead = f"    {mark} {tool:<{col}} {ver} "
    if not ui.stdout_is_tty():
        print(lead + ui.dim(tail))
        return
    indent = 4 + 2 + col + 1 + 22 + 1
    room = max(16, ui.cols() - 1 - indent)
    if path:
        print(lead + ui.dim(_fit_path(tail, room)))
        return
    import textwrap
    rows = textwrap.wrap(tail, room, break_on_hyphens=False, break_long_words=False) or [""]
    print(lead + ui.dim(rows[0]))
    for more in rows[1:]:
        print(" " * indent + ui.dim(more))


def _doctor_machine_notes(settings: dict) -> list[str]:
    """What doctor flags about this machine besides tools and credentials: login services of this home that do not
    match what runs (the web console's, the MCP HTTP server's - at every login they start something that can only
    refuse or restart forever), and a saved container engine this machine does not have. Never raises."""
    notes: list[str] = []
    try:
        leftover = webui.leftover_service(settings)
        if leftover:
            notes.append(f"Web console: {leftover}")
    except Exception:  # noqa: BLE001 - a status line must never fail the doctor
        pass
    try:
        state = mcp.load_state()
        stray = mcp.leftover_services(state)
        if stray:
            fix = "cs mcp restart" if state.get("transport") == "http" else "cs setup mcp --transport stdio"
            notes.append("MCP server: a login service that does not match the deployment is still installed: "
                         f"{', '.join(stray)}  (remove it: {fix})")
        outdated = mcp.outdated_service(state)
        if outdated:
            notes.append(f"MCP server: {outdated}  (cs mcp restart rewrites it)")
    except Exception:  # noqa: BLE001
        pass
    engine = settings.get("engine")
    try:
        engines = container.available_engines()
    except Exception:  # noqa: BLE001
        engines = None
    if engine and engines is not None and engine not in engines:
        other = [e for e in engines if e != engine]
        mode = settings.get("runtime") or "auto"
        notes.append(f"The saved container engine {engine} is not installed on this machine, so container runs stop: "
                     + (f"install it, or use {other[0]}: cloudseed deps runtime {mode} --engine {other[0]}" if other
                        else f"install it ({container.ENGINE_INSTALL.get(engine, ('', ''))[1] or 'docker or podman'})"))
    return notes


def cmd_doctor(args, settings) -> int:
    if ui.interactive():
        ui.banner(__version__, "doctor · tools, credentials, runtime")
    ui.panel("This machine", [
        ("Version", __version__),
        ("Python", platform.python_version()),
        ("Platform", f"{platform.system()} {platform.machine()}"),
        ("Home", str(paths.HOME)),
        ("Mode", "bundle" if paths.IS_BUNDLE else ("container" if paths.IN_CONTAINER else "source")),
        ("Runtime", settings.get("runtime", "auto") + (f" ({settings['engine']})" if settings.get("engine") else "")),
        ("Container engines", ", ".join(container.available_engines()) or ui.dim("none")),
    ])
    for line in _doctor_machine_notes(settings):
        ui.warn(line)
    problems: list[str] = []    # for a named cloud: what keeps it from working (the verdict line below)
    keys = [args.cloud] if args.cloud else list(CLOUD_KEYS)
    # tools no cloud needs (kubectl, helm, the VPN clients ...) once, under their own heading, not under every cloud.
    # deps.status(<cloud>) lists them with every cloud: they are taken from the first one (no second round of version
    # checks for tools that section does not show)
    per_cloud = [(k, deps.status(k)) for k in keys]
    common = [r for r in per_cloud[0][1] if not (deps.TOOLS.get(r["tool"]) or {}).get("clouds", ("?",))]
    shared = {r["tool"] for r in common}
    sections = [(k, [r for r in rows if r["tool"] not in shared]) for k, rows in per_cloud]
    # one tool column for every section, as wide as the longest name (gke-gcloud-auth-plugin): the versions line up
    col = max([12, len("provider")] + [len(r["tool"]) for _, rows in sections for r in rows] + [len(r["tool"]) for r in common])
    for cloud_key, rows in sections:
        cloud = clouds.get(cloud_key)
        ui.header(cloud.display)
        for row in rows:
            _doctor_row(row, col)
            if row["required"] and (not row["path"] or row.get("outdated")):
                problems.append(f"{row['tool']} {'is too old' if row['path'] else 'is missing'} (cloudseed install {row['tool']})")
        if cloud_key == "vmware":
            from . import localvm
            h = localvm.detect_host() or {}
            if h.get("found"):
                ui.ok(f"{h['product']} {h['version']} on {h['os']}/{h['arch']} (guests: {h['guest_arch']})")
            binary = localvm.provider_binary()
            built = binary.exists()
            src = paths.REPO_ROOT / "providers" / "vmdesktop"
            try:
                stale = built and (src / "go.mod").exists() and localvm._provider_stale(binary, src)
            except Exception:  # noqa: BLE001 - a status line must never fail the doctor
                stale = False
            if stale:   # built from older sources: the next vmware command rebuilds it (needs Go)
                _doctor_line(ui.style("▲", "seed", "bold"), "provider", col, ui.style("stale".ljust(22), "seed"),
                             "rebuilt on the next vmware command (or: cloudseed install vmware-provider --rebuild)")
            else:
                _doctor_line(ui.style("✔", "leaf", "bold") if built else ui.style("○", "muted"), "provider", col,
                             ui.style(("built" if built else "not built").ljust(22), "text" if built else "dim"),
                             "cloudseed install vmware-provider")
        # the live check first (the rule troubleshoot uses): the static hints (no credential file, no profile ...) only
        # stand in when it cannot say (no cloud CLI). Never 'No credentials detected' next to 'login valid', nor the
        # same missing login reported twice when the live check already says so with its fix
        live = deps.live_credential_check(cloud_key)
        if live:
            (ui.ok if live[0] else ui.warn)(live[1])
            if not live[0]:
                problems.append("the credentials do not work")
        else:
            for w in cloud.credential_warnings({"vars": {}}):
                ui.warn(w)
                problems.append("no credentials")
    if common:
        ui.header("Common tools")
        for row in common:
            _doctor_row(row, col)
            if row["required"] and (not row["path"] or row.get("outdated")):
                problems.append(f"{row['tool']} {'is too old' if row['path'] else 'is missing'} (cloudseed install {row['tool']})")
    # one verdict line for a named cloud (the rows above say why): a named cloud that is not ready exits 1 (a required
    # tool missing or too old, no or invalid credentials), the overview always 0
    if args.cloud and problems:
        ui.warn(f"{clouds.get(args.cloud).display} is not ready: " + "; ".join(dict.fromkeys(problems)) + ".")
    print()
    return 1 if args.cloud and problems else 0


def _absent_or_empty(p: Path) -> bool:
    """Nothing there yet (the container runtime pre-creates some of these directories, empty)."""
    try:
        return not p.exists() or (p.is_dir() and not p.is_symlink() and not any(p.iterdir()))
    except OSError:
        return False


def _file_stamp(p: Path) -> tuple | None:
    """(inode, size, mtime) of a regular file, None for anything else: tells whether an installer rewrote it."""
    try:
        st = p.lstat()
    except OSError:
        return None
    import stat as _stat
    return (st.st_ino, st.st_size, st.st_mtime_ns) if _stat.S_ISREG(st.st_mode) else None


def _install_tool(tool: str, files: dict) -> bool:
    """deps.install(tool), adding what its undo needs to `files` ({path: backup, None = new}): the directories the
    installer created in cloudseed's home (the Go toolchain, the gcloud SDK, the az/snow virtualenvs, the AWS CLI on
    Linux) and, when it upgrades a too-old binary in ~/.cloudseed/bin (terraform), a copy of the old one - discarded
    again when nothing was replaced. New files in ~/.cloudseed/bin are found by _record_installed itself."""
    fresh = [paths.HOME / d for d in deps.INSTALL_DIRS.get(tool, []) if _absent_or_empty(paths.HOME / d)]
    binary = paths.BIN_DIR / tool
    stamp = _file_stamp(binary)
    backup = None
    if stamp is not None and deps.too_old(tool, deps.version_of(tool)):
        backup = undo.backup_file(binary)
    ok = False
    try:
        ok = deps.install(tool)
    finally:
        if backup and ok and _file_stamp(binary) != stamp:
            _keep_first_backups(files, {str(binary): backup})
        elif backup:
            undo._discard_backups({"data": {"files": {str(binary): backup}}})
    if ok:
        _keep_first_backups(files, {str(p): None for p in fresh if not _absent_or_empty(p)})
    return ok


def cmd_deps(args, settings) -> int:
    if args.deps_cmd == "status":
        return cmd_doctor(argparse.Namespace(cloud=None), settings)
    if args.deps_cmd == "install":
        # `all` = the four core tools, expanded in place: `all openvpn` installs openvpn too, `all bogus` is refused
        tools = list(dict.fromkeys(t for w in args.tools for t in (INSTALL_GROUPS["deps"] if w == "all" else [w])))
        unknown = [t for t in tools if t not in deps.INSTALLERS]
        if unknown:
            raise ui.Abort(f"Unknown tool(s): {', '.join(unknown)}. Known: {', '.join(deps.INSTALLERS)} | all", code=2)
        before = undo.listing(paths.BIN_DIR)
        missing_before = {t for t in tools if not deps.find(t)}
        files: dict = {}
        failed: list[str] = []
        try:
            for t in tools:
                if not _install_tool(t, files):
                    failed.append(t)
        finally:   # also when a later tool fails or is interrupted: what was installed so far stays undoable
            _record_installed(f"deps install {' '.join(tools)}", before, files,
                              changed=[t for t in tools if t in missing_before and t not in failed and deps.find(t)])
        if failed:
            raise ui.Abort(f"Failed to install: {', '.join(failed)}")
        return 0
    if args.deps_cmd == "image":
        # an engine that was asked for (--engine, or the saved one) is used or reported missing, never swapped
        engine = container.choose_engine(settings, explicit=args.engine)
        container.build_image(engine) if (args.rebuild or not container.image_exists(engine)) else ui.ok(
            f"Image {container.IMAGE} already exists (use --rebuild to rebuild).")
        settings["engine"] = engine
        paths.save_settings(settings)
        return 0
    if args.deps_cmd == "bundle":
        script = paths.REPO_ROOT / "scripts" / "build-bundle.sh"
        if not script.exists():
            raise ui.Abort("Bundle builder needs a source checkout.")
        return subprocess.call(["bash", str(script)])
    if args.deps_cmd == "runtime":
        keys = ["runtime", "engine"]
        snap = undo.snapshot_settings(keys)          # from disk, before anything is saved
        if args.mode == "container" or args.engine:
            # checked before anything is saved or recorded: an engine that is not installed (and not installed now,
            # with consent) aborts here, so no undo entry and no unusable preference are left behind
            settings["engine"] = container.choose_engine(settings, explicit=args.engine)
        settings["runtime"] = args.mode
        paths.save_settings(settings)
        # only a real change gets an undo point: a no-op or a failed run must not push real ones out of the history
        if any(snap["settings"].get(k) != settings.get(k) for k in keys):
            undo.record(undo.GLOBAL, f"deps runtime {args.mode}", "settings-restore", snap)
        ui.ok(f"Default runtime set to {args.mode}" + (f" ({settings['engine']})" if args.mode == "container" or args.engine else ""))
        return 0
    return 1


# ---------------------------------------------------------------- agentic layer

FEATURES = ("agentic", "headliner", "mcp", "ui")


def _agent_session() -> bool:
    """True inside a session driven by an AI agent (built-in, Claude Code, Codex ...), where cloudseed must never
    install software on the machine by itself. MCP tool calls are not counted: their installs are confirm-gated.
    One definition with the dependency installers: deps.agent_session."""
    return deps.agent_session()


def _skill_needs_install(dest: Path, src: Path) -> bool:
    """dest/<skill> is missing or an outdated cloudseed copy (a link, or a directory that is not cloudseed's, is left
    alone by skills.install and never counts)."""
    target = dest / src.name
    if target.is_symlink() or (target.exists() and not skills._ours(target, src.name)):
        return False
    try:
        return (target / skills.MARKER).read_text().strip() != skills.src_hash(src)
    except OSError:
        return True


def _ensure_agent_skills(key: str, spec: dict) -> None:
    """Install the bundled cloudseed skills into an agent CLI's skills directory when they are missing."""
    if spec.get("builtin") or not spec.get("skills_dir"):
        return   # the built-in agent reads them from cloudseed itself; custom agents may have no skills dir
    if skills.installed(key):
        return                                          # current (or current apart from directories that are not ours)
    dest = skills.target_dir(key, None, False)
    if not any(_skill_needs_install(dest, src) for src in skills.available()):
        return                                          # everything cloudseed may install there is current: quiet
    ui.info(f"Installing cloudseed skills for {spec.get('display', key)} into {dest}")
    # a directory under one of the skills' names that is not cloudseed's (the user's own fork, a partial copy) is left
    # alone with a warning - this install is a convenience and must not block choosing or running the agent.
    # (`cloudseed skill install` still refuses it outright: there, --dir can pick another place.)
    for t in skills.install(None, dest, skip_foreign=True):
        ui.ok(f"skill {t.name} -> {t}")


def _install_agent_cli(key: str, spec: dict, explicit_install: bool) -> None:
    """Install a missing agent CLI - only after a yes at a terminal prompt, or (without a terminal) when the user asked
    for the install in so many words (`cloudseed install <agent>`). Never from inside an agent session."""
    display, hint = spec.get("display", key), spec.get("install_hint") or ""
    auth = spec.get("auth", "see the agent docs")
    tool = hint.split()[0] if hint.strip() else ""
    manager = hint.startswith(("npm ", "pip ", "brew "))
    installable = manager and bool(shutil.which(tool))
    how = f"cloudseed install {key}" + (f"   (or: {hint})" if hint else "")
    if not installable or _agent_session():
        why = ("agent sessions never install software; " if _agent_session() and installable else
               (f"`{tool}` is not available here; " if manager else ""))
        raise ui.Abort(f"{display} ('{spec.get('binary')}') is not installed. {why}install it first: {hint or how}\n"
                       f"  then authenticate: {auth}")
    if ui.interactive():
        ui.warn(f"{display} ('{spec.get('binary')}') is not installed.")
        if not ui.confirm(f"Install it now with `{hint}`?", default=True):
            raise ui.Abort(f"Not installed. Install it first: {how}\n  then authenticate: {auth}")
    elif not explicit_install:
        raise ui.Abort(f"{display} ('{spec.get('binary')}') is not installed, and nothing is installed system-wide without your OK "
                       f"in non-interactive mode. Install it with: {how}\n  then authenticate: {auth}")
    ui.info(f"Installing {display}: {hint}")
    try:
        rc = subprocess.call(hint.split())
    except OSError as e:
        raise ui.Abort(f"Install failed ({e}). Install manually: {hint}")
    if rc != 0:
        raise ui.Abort(f"Install failed (exit {rc}). Install manually: {hint}")
    if not agents.installed(spec):
        raise ui.Abort(f"`{hint}` finished, but '{spec.get('binary')}' is still not on PATH. Open a new shell, or add "
                       f"{tool}'s global bin directory to PATH, then run: cloudseed use {key}")


def _ensure_agent_ready(agent_key: str | None, settings: dict, auto_install_skills: bool = True, persist: bool = True,
                        explicit_install: bool = False, require_creds: bool = False) -> dict:
    """Pick/validate the agent, make sure its CLI exists and the cloudseed skills are installed.

    persist          save the agent as the selected one (use / enable); one-off runs (`do --agent X`) pass False
    explicit_install the user asked for the install in so many words (`cloudseed install codex`); otherwise a
                     missing CLI is only installed after a yes at a terminal prompt
    require_creds    the caller is about to run a task: abort (once, before skills are installed or anything is
                     printed) when the agent cannot run it - no credentials, not logged in, no exec template
    """
    key = _resolve_agent_key(agent_key, settings)
    spec = agents.get(key)
    if spec.get("builtin"):
        from . import builtin_agent
        if builtin_agent.has_api_credentials():
            builtin_agent.ensure_sdk()
        else:
            claude, state = builtin_agent.claude_fallback()
            if state == "ready":
                # the built-in agent stays selected; each run goes through Claude Code until an API key exists
                if not require_creds:          # a run (`do`) says it once itself, right before running
                    ui.info("No Anthropic API key found: agent tasks run through your logged-in Claude Code CLI until one is set "
                            "(ANTHROPIC_API_KEY or `ant auth login`). The built-in agent stays selected.")
                if auto_install_skills:
                    _ensure_agent_skills("claude", claude)   # the fallback run needs them
            elif require_creds:                # nothing can run the task: say so once, before anything else
                raise ui.Abort(builtin_agent.no_creds_msg(state))
            else:                              # the choice is saved; tasks work once a key or a Claude login exists
                ui.warn(builtin_agent.no_creds_msg(state))
    else:
        if not agents.installed(spec):
            _install_agent_cli(key, spec, explicit_install)
        if require_creds:                      # a task is about to run: the same check agents.run makes, but first
            ok, msg = agents.readiness(spec)
            if not ok:
                raise ui.Abort(f"{spec.get('display', key)} {'has' if msg.startswith('no ') else 'is'} {msg}")
        elif not agents.auth_ok(spec):
            ui.warn(f"{spec.get('display', key)} is installed but not logged in. Before running tasks: {spec.get('auth', 'see the agent docs')}")
        if auto_install_skills:
            _ensure_agent_skills(key, spec)
    if persist and settings.get("agent") != key:
        settings["agent"] = key
        paths.save_settings(settings)
    return spec


def _resolve_agent_key(agent_key: str | None, settings: dict) -> str:
    """The agent a command acts on: the one named, else the selected one, else (at a terminal) the user's pick."""
    key = agent_key or settings.get("agent")
    if not key:
        reg = agents.registry()
        options = [(k, f"{reg[k].get('display', k)}" + ("" if agents.installed(dict(reg[k], key=k)) else "  (not installed)"),
                    reg[k].get("display", k)) for k in reg]
        key = ui.choose("Which agent should cloudseed use?", options, default="builtin")
    return key


def _mcp_clients_arg(names: list[str] | None, need_present: bool) -> list[str]:
    """Client names from the command line (comma-separated or repeated). No names or 'all' = every client that is
    detected on this machine (need_present) or every known one; 'all' may be combined with explicit names, which are
    always honoured. 'none' = no client and cannot be combined."""
    keys = list(mcp.CLIENTS)
    names = list(dict.fromkeys(n.strip().lower() for item in (names or []) for n in str(item).split(",") if n.strip()))
    if "none" in names:
        if len(names) > 1:
            raise ui.Abort("'none' cannot be combined with client names.", code=2)
        return []
    unknown = [n for n in names if n not in keys and n != "all"]
    if unknown:
        raise ui.Abort(f"Unknown client(s): {', '.join(unknown)}. Known: {', '.join(keys)}  (or: all | none)", code=2)
    if not names or "all" in names:
        out = [k for k in keys if mcp.client_present(k)] if need_present else list(keys)
        return out + [n for n in names if n != "all" and n not in out]
    return names


def _can_bind(host: str, port: int) -> bool:
    """Would a server be able to listen on host:port right now? (same socket options as http.server)"""
    import socket
    host = str(host or "127.0.0.1").strip("[]")      # [::1] -> ::1
    try:
        with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, int(port)))
            s.listen(1)
        return True
    except (OSError, OverflowError):
        return False


def _log_tail(path: Path, pattern: str = "") -> str:
    """The last (matching) line of a service log, for error messages."""
    try:
        lines = [l for l in path.read_text(errors="replace").splitlines() if l.strip() and (not pattern or re.search(pattern, l))]
    except OSError:
        return ""
    return lines[-1].strip() if lines else ""


def _mcp_health_info(state: dict | None, timeout: float = 1.0) -> dict | None:
    """GET /health (no token needed): the answer when a cloudseed MCP server of this home listens on the deployed address."""
    s = state or {}
    if s.get("transport") != "http":
        return None
    return mcp.alive(s, timeout=timeout)


def _mcp_probe(state: dict | None) -> str | None:
    """'ok' = our server answers with the saved token; 'auth' = a cloudseed MCP server listens there but rejects the
    saved token (e.g. it still runs with a token that was rotated or put back by undo); None = nothing answers."""
    if not state or state.get("transport") != "http":
        return None
    if mcp.health(state):
        return "ok"
    return "auth" if _mcp_health_info(state) else None


def _pid_is_mcp_server(pid: int) -> bool:
    """/health is unauthenticated: only ever signal a live `cloudseed mcp serve --http` (the one check, in mcp.py)."""
    return mcp._is_our_server(pid)


def _mcp_kill_orphan(state: dict | None) -> bool:
    """Stop a cloudseed MCP server that still answers on the deployed address although the pid file / service lost
    track of it (it reports its own pid on /health). Returns True when one was stopped."""
    import signal as _signal
    info = _mcp_health_info(state)
    try:
        pid = int((info or {}).get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    if not pid or not _pid_is_mcp_server(pid):
        return False
    try:
        os.kill(pid, _signal.SIGTERM)
    except OSError:
        return False
    for _ in range(40):
        if not _mcp_health_info(state, timeout=0.3):
            break
        time.sleep(0.25)
    return True


def _mcp_backup_files() -> dict:
    """Undo backups of the deployment files (state, token, guide). Client configs are not copied back wholesale (the
    user may edit them meanwhile); the undo re-connects the clients instead, see _mcp_reconnect_argvs."""
    return {str(p): undo.backup_file(p) for p in (mcp.STATE_PATH, mcp.TOKEN_PATH, mcp.GUIDE_PATH)}


def _mcp_clients_wiring() -> dict[str, str]:
    return {k: t for k in mcp.CLIENTS for t in [mcp.connected(k)] if t}


def _mcp_reconnect_argvs(before: dict[str, str]) -> list[list[str]]:
    """Commands that put every client back the way it was wired in `before` ({client: transport})."""
    argvs = []
    now = _mcp_clients_wiring()
    for transport in ("http", "stdio"):
        keys = [k for k, t in before.items() if t == transport]
        if keys:
            argvs.append(["mcp", "connect", *keys, "--transport", transport])
    gone = [k for k in now if k not in before]
    if gone:
        argvs.append(["mcp", "disconnect", *gone])
    return argvs


def _mcp_restore_argvs(state: dict, wiring: dict[str, str], enabled: bool) -> list[list[str]]:
    """Commands that bring back exactly the MCP setup that exists now (for the undo of `cs destroy mcp`): the HTTP
    deployment as it was (port, auth, service kind) or stdio mode, every client on its own transport, and the on/off
    switch. Nothing that did not exist: a home that never deployed a server gets no server from the undo."""
    argvs: list[list[str]] = []
    tr = state.get("transport")
    if tr == "http":
        argvs.append(["mcp", "setup", "-y", "--transport", "http", "--client", "none",
                      "--port", str(state.get("port") or mcp.DEFAULT_PORT)]
                     + (["--host", str(state["host"])] if state.get("host") and state.get("host") != mcp.DEFAULT_HOST else [])
                     + (["--no-auth"] if state.get("auth") == "none" else [])
                     + (["--no-service"] if _mcp_no_service(state) else []))
    elif tr == "stdio":
        argvs.append(["mcp", "setup", "-y", "--transport", "stdio", "--client", "none"])
    elif enabled:
        argvs.append(["enable", "mcp"])                  # stdio-only home: no server.json existed
    argvs += [a for a in _mcp_reconnect_argvs(wiring) if a[:2] == ["mcp", "connect"]]
    if argvs and not enabled and tr in ("http", "stdio"):
        argvs.append(["disable", "mcp"])                 # `setup -y` switches MCP on; it was off
    return argvs


def _mcp_refresh(state: dict | None, skip=(), force: bool = False) -> list[str]:
    """Re-wire clients whose cloudseed entry no longer matches the deployment (other port, old token, server gone)."""
    done = []
    for k, msg in mcp.refresh_clients(state, skip=skip, force=force).items():
        display = mcp.CLIENTS[k]["display"]
        if msg.startswith("failed"):
            ui.warn(f"{display}: could not update its cloudseed entry ({msg}); run: cs mcp connect {k}")
        else:
            ui.ok(f"{display}: updated ({msg})")
            done.append(k)
    return done


def _ui_login_item() -> str | None:
    """'launchd' / 'systemd' when this home's console is installed as a login item (webui.login_item: its plist / unit
    file, under its own name or the shared name an older version gave it; never another home's), else None. Decided
    from the files on disk, never from server.json, whose 'service' is only the preference for the next start."""
    return webui.login_item()


def _ui_foreground_pid(st: dict) -> int | None:
    """The pid of a console running in a terminal (`cs ui serve`), when that is the console that runs now."""
    pid = webui.running_pid()
    try:
        fg = int(st.get("foreground_pid") or 0)
    except (TypeError, ValueError):
        fg = 0
    return pid if pid and fg == pid else None


def cmd_ui(args, settings) -> int:
    sub = args.ui_cmd or "open"
    if sub == "serve":
        return webui.serve(args.host, args.port)   # defaults: the saved host/port, so status/token/open agree with it
    if sub == "start":
        return _ui_start(args, settings)
    st = webui.load_state()
    if sub == "open":
        if not settings.get("ui") or not webui.health(st):
            return cmd_ui(argparse.Namespace(ui_cmd="start", port=None, host=None, no_open=False, lines=50, rotate=False), settings)
        webui.open_browser()
        _print_ui_info()
        return 0
    if sub == "status":
        pid = webui.running_pid()
        login = _ui_login_item()
        if _ui_foreground_pid(st):
            service = "foreground (cs ui serve)"
        elif login:
            service = f"{login}  (starts at login)"
        else:
            service = "background" if pid else "-"
        rows = [("Enabled", "yes" if settings.get("ui") else "no  (cs enable ui)"), ("URL", webui.url() if st else "-"),
                ("Health", ui.style("running", "leaf", "bold") if webui.health(st) else ui.style("not responding", "rose", "bold")),
                ("Service", service + (f"  pid {pid}" if pid else "")), ("Log", str(webui.LOG_PATH)), ("Token", f"{webui.TOKEN_PATH}  (cs ui token)")]
        leftover = webui.leftover_service(settings)   # a disabled console's login item, or one an older version wrote
        if leftover:
            what, sep, fix = leftover.partition("  (")
            rows.append(("Outdated login item" if "older version" in leftover else "Leftover",
                         ui.style(what, "seed", "bold") + (f"  ({fix}" if sep else "")))
        ui.panel("cloudseed console", rows)
        return 0
    if sub == "stop":
        foreground = _ui_foreground_pid(st)
        if not settings.get("ui") and not foreground:
            # a disabled console: its login item (if one is left) can only start, refuse and stop again - remove it
            # (one an older version wrote under the shared name too: leftover_service sees every one of this home's)
            kind = _ui_login_item()
            item = f"{kind} login item" if kind else "login item" if webui.leftover_service(settings) else None
            stopped = webui.stop()
            if item:
                webui.remove_service()
            if stopped and item:
                ui.ok(f"UI stopped and its {item} removed (the console is disabled). Back any time: cs enable ui")
            elif stopped:
                ui.ok("UI stopped (the console is disabled). Back any time: cs enable ui")
            elif item:
                ui.ok(f"Removed the {item} the disabled console left behind. Back any time: cs enable ui")
            else:
                ui.ok("No running UI found (the console is disabled: cs enable ui).")
            return 0
        if webui.stop():
            if foreground:   # a terminal's `cs ui serve` cannot be brought back by an undo (it would become a service)
                ui.ok(f"UI stopped (the console that ran in the foreground, pid {foreground}). Start it again: cs ui serve   (or as a service: cs ui start)")
                return 0
            undo.record(undo.GLOBAL, "ui stop", "argv", {"argv": ["ui", "start", "--no-open"]})
            login = _ui_login_item()
            back = f"  It starts again at login ({login} user service); `cs disable ui` removes it." if login else ""
            ui.ok("UI stopped." + back)
        else:
            ui.ok("No running UI found.")
        return 0
    if sub == "restart":
        if not settings.get("ui"):
            raise ui.Abort("The UI is disabled; enable it with: cs enable ui")
        foreground = _ui_foreground_pid(st)
        if foreground:   # restarting it here would turn a terminal session into a background service / login item
            raise ui.Abort(f"Not restarted: the console runs in the foreground (pid {foreground}, `cs ui serve`); restart it in that "
                           "terminal (Ctrl-C, then cs ui serve). A new token needs no restart: the console reads it from disk.", code=0)
        st = st or {"host": "127.0.0.1", "port": webui.DEFAULT_PORT}
        webui.stop()
        if not _can_bind(st.get("host", "127.0.0.1"), int(st.get("port") or webui.DEFAULT_PORT)):
            raise ui.Abort(f"Restart failed: port {st.get('port')} is in use by another program. Move the console with: cs ui start --port <free port>")
        with ui.Spinner(f"Restarting the cloudseed console on {webui.url(s=st)}"):
            webui.start(st)
        if not webui.health(st):
            why = _log_tail(webui.LOG_PATH, r"Cannot listen|Refusing|disabled|Error")
            webui.stop()                      # never leave a service behind that can only crash-loop
            raise ui.Abort("Restart failed" + (f": {why}" if why else "") + f"; see {webui.LOG_PATH}  (foreground: cs ui serve)")
        ui.ok(f"UI restarted: {webui.url(s=st)}")
        return 0
    if sub == "logs":
        if not webui.LOG_PATH.exists():
            ui.info(f"No log yet ({webui.LOG_PATH}).")
            return 0
        print("\n".join(webui.LOG_PATH.read_text(errors="replace").splitlines()[-max(1, int(args.lines or 1)):]))
        return 0
    if sub == "token":
        if args.rotate:
            # a running console re-reads the token file when it changes (webui.current_token), and so does it when an
            # undo puts the old file back: no restart, which would also turn a foreground `cs ui serve` into a service
            undo.record(undo.GLOBAL, "ui token --rotate", "restore-files", {"files": {str(webui.TOKEN_PATH): undo.backup_file(webui.TOKEN_PATH)}})
            webui.ensure_token(rotate=True)
            ui.ok("New token issued (the old link stops working now); open the console with the new link:")
        elif not webui.load_token():
            raise ui.Abort("No console token yet - the web console has not been enabled. Run: cs enable ui")
        print(webui.url(with_token=True))
        if not (settings.get("ui") and webui.health(st)):
            ui.info("The console is not running right now; start it with: cs ui" + ("" if settings.get("ui") else "   (first: cs enable ui)"))
        return 0
    return 1


def _ui_start(args, settings) -> int:
    given = getattr(args, "port", None)
    if given is not None and not 1 <= int(given) <= 65535:     # not "in use by another program": it is no port at all
        raise ui.Abort(f"--port {given} is not a TCP port (1-65535).", code=2)
    host_arg = getattr(args, "host", None)
    if host_arg and mcp._bare_host(host_arg) != "127.0.0.1":
        raise ui.Abort("--host applies only to `cs ui serve` (in the foreground); the console service always listens on "
                       "127.0.0.1, local only.", code=2)
    was_enabled = bool(settings.get("ui"))
    old = webui.load_state()
    host = "127.0.0.1"
    try:
        saved = int(old.get("port") or 0)
    except (TypeError, ValueError):
        saved = 0
    if not 1 <= saved <= 65535:
        saved = 0                               # a hand-edited state.json: pick a free port instead
    port = int(given or saved or webui.free_port(webui.DEFAULT_PORT))
    st = {"host": host, "port": port, "service": old.get("service")}
    if was_enabled and saved == port and webui.health(st):
        webui.save_state(dict(old, **{"host": host, "port": port}))
        ui.ok(f"UI already running: {webui.url()}")
    else:
        if not _can_bind(host, port):
            ours = saved == port and webui.health(st)
            if not ours:                       # someone else's port: nothing of ours is changed
                if given:
                    raise ui.Abort(f"Port {port} is in use by another program; choose another with --port.", code=2)
                port = webui.free_port(webui.DEFAULT_PORT)
                ui.info(f"The saved port {st['port']} is in use by another program now; using {port}.")
                st["port"] = port
        webui.ensure_token()
        settings["ui"] = True                  # serve() refuses to run while the UI is disabled
        paths.save_settings(settings)
        webui.save_state(dict(old, **st))      # so the messages below show the port that is being started

        def rollback() -> None:
            try:
                webui.remove_service()         # never leave a login item behind that can only crash-loop
            except Exception:  # noqa: BLE001 - the settings below must be restored whatever happens here
                pass
            settings["ui"] = was_enabled
            paths.save_settings(settings)
            if old:
                webui.save_state(old)          # keep the last working address, not the failing one
            else:
                webui.STATE_PATH.unlink(missing_ok=True)

        try:
            with ui.Spinner(f"Starting the cloudseed console on {webui.url(s=st)}"):
                webui.stop()
                kind = webui.start(st)
        except BaseException as e:             # e.g. ~/Library/LaunchAgents not writable: no half-enabled console
            rollback()
            if isinstance(e, (SystemExit, KeyboardInterrupt)):
                raise
            why = getattr(e, "strerror", None) or str(e) or type(e).__name__
            where = getattr(e, "filename", None)
            # the settings are back as they were; a console that was running was stopped before the start failed
            after = "nothing was changed" if not was_enabled else \
                "the settings are as they were, but the console is stopped (start it again: cs ui start)"
            raise ui.Abort(f"The UI did not start: {why}" + (f" ({where})" if where else "") +
                           f"; {after}. See {webui.LOG_PATH}  (try in the foreground: cs ui serve)") from e
        if not webui.health(st):
            why = _log_tail(webui.LOG_PATH, r"Cannot listen|Refusing|disabled|Error")
            rollback()
            raise ui.Abort("The UI did not start" + (f": {why}" if why else "") + f"; see {webui.LOG_PATH}  (try in the foreground: cs ui serve)")
        if not was_enabled:
            undo.record(undo.GLOBAL, "enable ui", "argv", {"argv": ["disable", "ui"]})
        ui.ok(f"cloudseed console is up: {webui.url()}   ({kind}" + ("; starts at login" if kind in ("launchd", "systemd") else "") +
              "; local only, token-protected)")
    _print_ui_info()
    if not args.no_open:
        webui.open_browser()
    return 0


def _print_ui_info() -> None:
    ui.panel("Open it", [f"{ui.style('link    ', 'muted')} {webui.url(with_token=True)}",
                         f"{ui.style('again   ', 'muted')} cs ui        (opens the browser; `cs ui token` prints the link)",
                         f"{ui.style('manage  ', 'muted')} cs ui status | stop | restart | logs   ·   cs disable ui",
                         f"{ui.style('inside  ', 'muted')} create/change/destroy environments, install the whole platform or single items, DR drills, chaos runs, scans, "
                         "agents & MCP, credentials, help - every action streams its output live"], accent="leaf")


_UNDO_GLOBAL_AGENT = ("Global actions (MCP/UI setup, credentials, enable/disable, agent and model choices) can only be undone by you, "
                      "from a terminal (cs undo --global) or the web console - not by an agent.")


# undo kinds that act on a live environment: when the environment is gone they can never succeed
_UNDO_NEEDS_ENV = ("config", "created", "platform", "helm", "velero-restore", "provision-prev", "vpn-revoke", "vpn-add", "dr-delete",
                   "dr-drill")
# inverses that stop the web console, which may be the very process running this undo: pop the entry first
_UNDO_STOPS_UI = (["disable", "ui"], ["ui", "stop"], ["ui", "restart"])


def _env_of_scope(scope: str) -> paths.Env | None:
    if not scope or scope == undo.GLOBAL or "-" not in scope:
        return None
    cloud_key, name = scope.split("-", 1)
    return paths.Env(cloud_key, name) if cloud_key in CLOUD_KEYS else None


def _undo_scope(args) -> str | list | None:
    """Which history `cs undo` acts on: one scope id, several (only for --list), or None (the newest entry anywhere).
    A cloud or an --env alone narrows the choice - it never widens it to other clouds or to the global history."""
    cloud, env_name = getattr(args, "cloud", None), getattr(args, "env", None)
    if getattr(args, "global_scope", False):
        if cloud or env_name:
            raise ui.Abort("--global cannot be combined with <cloud> / --env.", code=2)
        return undo.GLOBAL
    if cloud and env_name:
        return f"{cloud}-{env_name}"
    if not cloud and not env_name:
        return None
    known = {e.id for e in paths.Env.list_all()} | {e["scope"] for e in undo.entries() if e["scope"] != undo.GLOBAL}
    matching = sorted(s for s in known if "-" in s and (s.split("-", 1)[0] == cloud if cloud else s.split("-", 1)[1] == env_name))
    cands = [s for s in matching if undo.entries(s)] or matching
    what = cloud if cloud else f"--env {env_name}"
    if args.list:
        return cands
    if len(cands) == 1:
        if len(matching) > 1:
            ui.info(f"{cands[0]} is the only environment matching {what} with something to undo.")
        return cands[0]
    if not cands:
        return []
    if ui.interactive():
        return ui.choose("Which environment?", [(s, s + (f"   newest: {undo.latest(s)['summary']}" if undo.latest(s) else ""), s)
                                                for s in cands])
    raise ui.Abort(f"Several environments match {what}: {', '.join(cands)}. Pass <cloud> --env NAME.", code=2)


def _undo_filter_text(args) -> str:
    """The scope filters given on the command line, as the user typed them ('' when none)."""
    if getattr(args, "global_scope", False):
        return "--global"
    return " ".join(x for x in (getattr(args, "cloud", None) or "", f"--env {args.env}" if getattr(args, "env", None) else "") if x)


def _undo_scope_matches(args, scope_id: str) -> bool:
    """Does an entry's scope fit the <cloud> / --env / --global filters (all optional) of this command line?"""
    if getattr(args, "global_scope", False):
        return scope_id == undo.GLOBAL
    cloud, env_name = getattr(args, "cloud", None), getattr(args, "env", None)
    if not cloud and not env_name:
        return True
    if scope_id == undo.GLOBAL or "-" not in scope_id:
        return False
    c, n = scope_id.split("-", 1)
    return (not cloud or c == cloud) and (not env_name or n == env_name)


# undo kinds whose inverse runs Terraform or a cloud / cluster tool: `cs undo` needs the environment's runtime for them
# (and re-runs inside the container with --runtime container). Every other kind only edits local files, settings or
# the vault, and always runs on this machine: paths like ~/.kube/config and client configs are not in the container.
_UNDO_TOOLCHAIN = ("config", "created", "recreate", "provision-prev", "argv", "argv-seq", "platform", "helm",
                   "velero-restore", "dr-delete", "dr-drill", "vpn-add", "vpn-revoke")


def _undo_pick(args) -> tuple:
    """(scope, entry) that `cs undo` (not --list) acts on; entry is None when there is nothing to undo. Resolving the
    scope may ask which environment: _dispatch picks once (for the runtime gate) and cmd_undo reuses the answer."""
    cached = getattr(args, "undo_pick", None)
    if cached is not None:
        return cached
    agent = os.environ.get("CLOUDSEED_AGENT")
    entry_id = getattr(args, "id", None)
    global_scope = getattr(args, "global_scope", False)
    if global_scope and (getattr(args, "cloud", None) or args.env):
        raise ui.Abort("--global cannot be combined with <cloud> / --env.", code=2)
    if global_scope and agent:
        raise ui.Abort(_UNDO_GLOBAL_AGENT, code=2)
    # an exact entry: the filters only have to agree with it (they are not resolved to one environment first)
    scope = None if entry_id else _undo_scope(args)
    entry = None
    if entry_id:
        entry = next((e for e in undo.entries() if e["id"] == entry_id), None)
        if not entry:
            raise ui.Abort(f"No undo entry {entry_id}: it was already undone or dropped, or it expired. History: cs undo --list")
        if not _undo_scope_matches(args, entry["scope"]):
            raise ui.Abort(f"Entry {entry_id} belongs to {entry['scope']}, which does not match {_undo_filter_text(args)}.", code=2)
        newest = undo.latest(entry["scope"])
        if not args.drop and newest and newest["id"] != entry["id"]:
            raise ui.Abort(f"A newer action in {entry['scope']} must be undone first: {newest['summary']}  "
                           f"(cs undo --id {newest['id']}, or discard it with --drop)")
    elif scope is None and agent:      # an agent never reaches global entries (it could uninstall its own MCP server)
        pool = [e for e in undo.entries() if e["scope"] != undo.GLOBAL]
        entry = pool[-1] if pool else None
    elif scope != []:
        entry = undo.latest(scope)
    if agent and entry and entry["scope"] == undo.GLOBAL:
        raise ui.Abort(_UNDO_GLOBAL_AGENT, code=2)
    args.undo_pick = (scope, entry)
    return scope, entry


def cmd_undo(args, settings) -> int:
    agent = os.environ.get("CLOUDSEED_AGENT")
    if getattr(args, "global_scope", False) and (getattr(args, "cloud", None) or args.env):
        raise ui.Abort("--global cannot be combined with <cloud> / --env.", code=2)
    if args.list:
        scope = _undo_scope(args)
        if scope == []:
            ui.info("Nothing to undo for " + (args.cloud or f"--env {args.env}") + ". History: cs undo --list")
            return 0
        undo.print_list(scope)
        return 0
    scope, entry = _undo_pick(args)
    if not entry:
        where = scope if isinstance(scope, str) else (args.cloud or (f"--env {args.env}" if args.env else ""))
        ui.info("Nothing to undo" + (f" for {where}" if where else "") + ". History: cs undo --list")
        env = _env_of_scope(scope) if isinstance(scope, str) else None
        if env is not None:
            if env.exists():
                if _env_has_resources(env):    # an environment with nothing deployed has nothing to start over from
                    ui.info(f"Start over instead: cs destroy {env.cloud} --env {env.name}")
            else:
                ui.info(f"{env.id} does not exist. Known environments: " + (", ".join(e.id for e in paths.Env.list_all()) or "none"))
        if scope is None and agent and any(e["scope"] == undo.GLOBAL for e in undo.entries()):
            ui.info(_UNDO_GLOBAL_AGENT)
        return 0
    summary, when = entry["summary"], undo.when(entry)     # '2026-09-24 06:32 UTC', as `undo --list` shows it
    copies = _undo_copies(entry)
    if args.drop:
        undo.drop(entry)                       # also deletes the copies only this entry kept
        audit.write(f"undo dropped: {summary}")
        if copies:
            where = copies[0] if len(copies) == 1 else f"{len(copies)} copies in {undo.BACKUPS}"
            ui.ok(f"Dropped from the undo history: {summary}. Nothing was reverted; the copies it kept for the undo "
                  f"(e.g. a purged environment's configuration and SSH keys) were deleted: {where}")
        else:
            ui.ok(f"Dropped from the undo history (nothing was changed): {summary}")
        return 0
    ui.header(f"Undo: {summary}  ({when})")
    scope_env = _env_of_scope(entry["scope"])
    if scope_env is not None and entry["kind"] != "info":   # an undo changes its environment like the command it reverts
        _hold_env_lock(scope_env, f"undo {scope_env.cloud} --env {scope_env.name}")
    if entry["kind"] == "info":
        ui.info("Nothing automatic to undo: " + (entry.get("data") or {}).get("advice", "no automatic inverse"))
        if copies:
            # the advice restores from these copies: popping the entry would orphan them (a popped entry never expires),
            # dropping it would delete what the user was just told to copy back - keep both until the user drops them
            ui.info(f"The copy stays in {', '.join(copies)} with this undo step. Once you no longer need it: "
                    f"cs undo --id {entry['id']} --drop   (deletes the copy)")
            return 0
        undo.drop(entry)
        ui.ok(f"Removed '{summary}' from the undo history (nothing was reverted).")
        return 0
    env = _env_of_scope(entry["scope"])
    if env is not None and entry["kind"] in _UNDO_NEEDS_ENV and not env.exists():
        undo.drop(entry)
        ui.warn(f"{env.id} no longer exists, so '{summary}' cannot be undone; it was removed from the undo history.")
        return 0
    ui.info("This will " + undo.describe(entry))
    remaining = len(undo.entries(entry["scope"])) - 1
    if entry["kind"] == "argv" and list(entry["data"].get("argv") or [])[:2] in _UNDO_STOPS_UI:
        undo.pop(entry)                        # the console may be the process running this undo: it gets stopped
        try:
            undo.perform(entry, settings, args.auto_approve)
        except BaseException:
            undo.record(entry["scope"], summary, entry["kind"], entry["data"])   # not undone: keep it for a retry
            raise
    else:
        try:
            undo.perform(entry, settings, args.auto_approve)
        except ui.Abort as e:
            # only a real failure: not a cancel (0/130), nor the -y preview that applied nothing (3: --auto-approve)
            if e.code not in (0, 3, 130, None):
                e.msg = (e.msg + "\n" if e.msg else "") + f"To skip this step instead: cs undo --id {entry['id']} --drop"
            raise
        # restored: the copies (old tokens, replaced skills, a purge's private keys ...) are not needed any more, and a
        # popped entry never expires, so they would otherwise stay on disk
        undo.drop(entry)
    audit.write(f"undo: {summary}")
    if not remaining and env is not None and env.exists() and entry["kind"] != "created" and _env_has_resources(env):
        # the oldest step is undone, and resources are still deployed: only a destroy goes back further (never after
        # undoing a `created` step, which destroyed everything itself)
        ui.ok(f"Undone: {summary}.  No more undo steps for {entry['scope']}; to go back further: "
              f"cs destroy {env.cloud} --env {env.name}")
    else:
        ui.ok(f"Undone: {summary}.  {remaining} more undo step(s) for {entry['scope']}")
    return 0


def _undo_copies(entry: dict) -> list[str]:
    """The copies an undo entry owns in cloudseed's undo store (a purged environment's configuration and keys, file
    backups): what dropping it deletes, and what an 'info' entry's advice restores from."""
    d = entry.get("data") if isinstance(entry.get("data"), dict) else {}
    found: list[str] = []
    for b in [d.get("backup_dir")] + list((d.get("files") or {}).values() if isinstance(d.get("files"), dict) else []):
        if not b:
            continue
        try:
            p = undo._local(b)
            if undo._under_backups(p) and p.exists() and str(b) not in found:
                found.append(str(b))
        except (OSError, ValueError, TypeError):
            continue
    return found


def _creds_key(name: str) -> str:
    key = name.strip().upper()
    if not key or not key.replace("_", "").isalnum():
        raise ui.Abort(f"Not a variable name: '{name}' (letters, digits and _ only). Nothing was changed.", code=2)
    return key


def _forget_creds_copies(keys: set | None = None) -> int:
    """Drop the undo entries that keep copies of credential values (all of them, or those holding one of `keys`)."""
    n = 0
    for e in undo.entries(undo.GLOBAL):
        vals = (e.get("data") or {}).get("values") or {}
        if e["kind"] == "creds-restore" and vals and (keys is None or set(vals) & keys):
            undo.pop(e)
            n += 1
    return n


def _creds_value_problem(key: str, value: str) -> str | None:
    """Why a value cannot be stored for `key` (None when it can). creds.check_value decides - the one rule the web
    console applies too: a JSON-kind value (GOOGLE_CREDENTIALS) is written to a key file for the Google SDKs as it is,
    so it must be a whole JSON key (service account, authorized user and workload-identity-federation keys all carry a
    "type"). The message here says how to give it on the command line."""
    try:
        creds.check_value(key, value)
        return None
    except ValueError as e:
        if creds.kind(key) != "json":
            return str(e).rstrip().rstrip(".")      # (the callers add ". Nothing was changed.")
    try:
        data = json.loads(value)
    except ValueError:
        data = None
    what = "not JSON" if data is None else "JSON without a \"type\" (not a Google key file)"
    return (f"{key} takes the contents of a Google key file (JSON), and this is {what}. Paste the whole file at the "
            f"prompt: cs creds set {key}   (or point at the file: cs creds set GOOGLE_APPLICATION_CREDENTIALS=/path/key.json)")


def cmd_creds(args, settings) -> int:
    sub = args.creds_cmd
    forget = bool(getattr(args, "forget", False))
    if sub == "set":
        if not args.items:
            raise ui.Abort("Nothing to store. Usage: cs creds set KEY=VALUE ...   or   cs creds set KEY   (prompts, hidden input)", code=2)
        pairs: dict[str, str] = {}
        ask: list[str] = []
        for item in args.items:              # validate everything before anything is written
            k, eq, v = item.partition("=")
            try:
                key = creds.check_key(_creds_key(k))   # the vault refuses names that change how programs run
            except ValueError as e:
                raise ui.Abort(f"{e}. Nothing was changed.", code=2) from None
            if creds.kind(key) != "json":
                v = v.strip()                  # ' prod ' is 'prod' (as the web console stores it); '   ' is no value
            if not eq:
                ask.append(key)
            elif v == "":
                raise ui.Abort(f"{key}= has no value. To delete a stored credential: cs creds unset {key}. Nothing was changed.", code=2)
            else:
                pairs[key] = v
        if ask and not ui.interactive():
            raise ui.Abort(f"{', '.join(ask)}: no value given, and there is no terminal to ask on (-y or piped input). "
                           f"Pass {ask[0]}=VALUE, or run `cs creds set {ask[0]}` in a terminal (without -y) to type it hidden. "
                           "Nothing was changed.", code=2)
        for key, v in pairs.items():
            problem = _creds_value_problem(key, v)
            if problem:
                raise ui.Abort(f"{problem}. Nothing was changed.", code=2)
        if ask:
            import getpass
            for key in ask:
                try:
                    if creds.kind(key) == "json":   # a pasted key file spans many lines: getpass would keep only '{'
                        v = ui.read_hidden_blob(f"{key}: paste the key file's JSON",
                                                "(hidden; ends when the JSON is complete, or at Ctrl-D · Ctrl-C cancels · "
                                                "or use GOOGLE_APPLICATION_CREDENTIALS=/path/key.json)")
                    else:
                        v = getpass.getpass(f"  {key} (hidden input): ").strip()
                except (KeyboardInterrupt, EOFError):
                    raise ui.Abort("Cancelled. Nothing was changed.", code=130) from None
                if not v:
                    ui.info(f"{key}: empty input, left unchanged (`cs creds unset {key}` removes it)")
                    continue
                problem = _creds_value_problem(key, v)
                if problem:
                    raise ui.Abort(f"{problem}. Nothing was changed.", code=2)
                if creds.kind(key) == "json":
                    ui.ok(f"{key}: JSON key received ({len(v)} bytes, type {json.loads(v)['type']})")
                pairs[key] = v
        before = creds.load()
        stored: dict[str, str] = {}
        try:
            for k, v in pairs.items():       # set_ returns the value as stored (paths made absolute, ~ expanded)
                stored[k] = creds.set_(k, v)
        except ValueError as e:
            creds.save(before)               # all or nothing
            raise ui.Abort(f"{e}. Nothing was changed.", code=2) from None
        changed = [k for k in stored if before.get(k) != stored[k]]
        for k in pairs:
            shown = f" as {stored[k]}" if creds.kind(k) == "path" and stored[k] != pairs[k] else ""   # paths are no secret
            ui.ok(f"{k} stored in {creds.STORE}{shown}" if k in changed else f"{k} unchanged (the same value is already stored)")
            problem = creds.path_warning(k, stored[k])
            if problem:
                ui.warn(problem)
        if changed:   # one entry per command: undo puts back overwritten values and removes keys that are new
            undo.record(undo.GLOBAL, "creds set " + " ".join(changed), "creds-restore",
                        {"values": {k: before[k] for k in changed if k in before}, "unset": [k for k in changed if k not in before]})
        return 0
    if sub == "unset":
        if not args.items:
            raise ui.Abort("Which credential? Usage: cs creds unset KEY ...   (everything: cs creds clear)", code=2)
        keys = list(dict.fromkeys(_creds_key(k) for k in args.items))
        stored = creds.load()
        vals = {k: stored[k] for k in keys if k in stored}
        for k in keys:
            if k in vals:
                creds.unset(k)
                ui.ok(f"{k} removed")
            else:
                ui.info(f"{k} was not stored")
        if vals and forget:
            n = _forget_creds_copies(set(vals))
            ui.ok("No copy kept for undo" + (f"; {n} older undo step(s) holding these values were dropped" if n else "") + ".")
        elif vals:
            undo.record(undo.GLOBAL, "creds unset " + " ".join(vals), "creds-restore", {"values": vals})
            ui.info("`cs undo` can put them back: a copy stays in the undo journal (0600) until 5 newer global actions push it out. "
                    "Remove it now: cs creds unset " + " ".join(vals) + " --forget")
        return 0
    if sub == "clear":
        stored = creds.load()
        creds.clear()
        if forget:
            n = _forget_creds_copies()
            ui.ok("Credential vault cleared" + (f"; {n} undo step(s) holding copies of credentials were dropped" if n else "") + ".")
        elif not stored:
            ui.ok("Credential vault cleared (it was empty).")
        else:
            undo.record(undo.GLOBAL, "creds clear", "creds-restore", {"values": stored})
            ui.ok("Credential vault cleared.")
            ui.info("`cs undo` can put everything back: a copy stays in the undo journal (0600) until 5 newer global actions push it out. "
                    "Keep no copy: cs creds clear --forget")
        return 0
    rows = [(r["key"], (ui.style("stored", "leaf") + "  " + ui.dim(r["hint"])) if r["set"] else (ui.dim("from shell") if r["from_env"] else ui.dim("-"))) for r in creds.masked()]
    ui.panel(f"Credential vault  ({creds.STORE}, 0600; injected into cloudseed commands, shell variables win)", rows)
    ui.hints(["cs creds set AWS_PROFILE=prod", "cs creds set ANTHROPIC_API_KEY   (prompts, hidden)", "cs creds unset KEY",
              "cs creds clear [--forget]"])
    return 0


def _mcp_no_service(state: dict) -> bool:
    """Did the user opt out of the login service (--no-service)? Recorded as no_service. A deployment written before
    that key existed only says service=background, which also covers a refused launchd/systemd (the fallback): the
    running kind is kept either way."""
    if "no_service" in state:
        return bool(state["no_service"])
    return state.get("service") == "background"


def _mcp_no_auth_warning(host: str) -> str:
    return (f"No bearer token (--no-auth): any local process or user on this machine that can reach {host} can call "
            "every cloudseed tool, confirm=true ones (apply, destroy, ...) included. Use it only for a client that "
            "cannot send headers; require a token again with: cs setup mcp --rotate-token")


def _mcp_put_back(backups: dict, created_token: bool) -> None:
    """A failed `setup mcp`: the token as it was (a rotated one comes back, a new one goes), and no stray copies."""
    b = backups.get(str(mcp.TOKEN_PATH))
    try:
        if b and Path(b).exists():
            shutil.copy2(b, mcp.TOKEN_PATH)
        elif created_token:
            mcp.TOKEN_PATH.unlink(missing_ok=True)
    except OSError:
        pass
    undo._discard_backups({"data": {"files": backups}})


def cmd_mcp_setup(args, settings) -> int:
    """cloudseed setup mcp: deploy the local MCP server, connect clients, print the guide."""
    if ui.interactive():
        ui.banner(__version__, "MCP server · every cloudseed feature as a tool for Claude, Codex, Cursor, ...")
    # validate everything that can be wrong BEFORE a running server is stopped or any state is written
    named = [n for item in (args.client or []) + (args.clients or []) for n in item.split(",") if n.strip()]
    chosen_named = _mcp_clients_arg(named, need_present=True) if named else None   # 'all' = every DETECTED client
    prev = mcp.load_state()
    current = prev.get("transport")
    was_enabled = bool(settings.get("mcp"))
    wiring_before = _mcp_clients_wiring()
    ui.step(1, 3, "Server", "how the MCP server runs: one shared local HTTP service, or stdio launched by each client")
    if args.transport:
        transport = args.transport
    elif not ui.interactive():
        transport = current or "http"          # a re-run keeps the deployed transport
    elif current == "http":
        transport = "http"
    else:
        transport = ui.choose("How should the server run?", [
            ("http", "Deploy a local HTTP server (127.0.0.1, bearer token, launchd/systemd service): one server shared by every client (recommended)"),
            ("stdio", "stdio only: each client launches `cloudseed mcp serve` itself; nothing runs in the background"),
        ], default=current or "http")
    wired: dict[str, str] = {}
    if transport == "http":
        old = prev if current == "http" else {}
        host = args.host or old.get("host") or mcp.DEFAULT_HOST
        problem = mcp.host_problem(host)
        if problem:
            raise ui.Abort(problem, code=2)
        port = args.port or old.get("port")
        if port and not _can_bind(host, int(port)):
            ours = old and int(old.get("port") or 0) == int(port) and old.get("host", mcp.DEFAULT_HOST) == host and _mcp_health_info(old)
            if not ours:                       # someone else's port: say so before anything of ours is stopped
                if args.port:
                    raise ui.Abort(f"Port {port} on {host} is in use by another program; choose another with --port.", code=2)
                ui.info(f"Port {port} is in use by another program now; picking a free one.")
                port = None
        # the bearer token and the service kind are kept from the deployment, like host and port: --no-auth and
        # --no-service stay in force until --auth / --rotate-token (a token again), --service or, at a terminal, a
        # "no" to keeping them
        if args.auth is False:
            auth = "none"
        elif args.rotate_token or args.auth:
            auth = "token"
        elif old.get("auth") == "none" and ui.interactive():
            auth = "none" if ui.confirm("The server runs without a bearer token (--no-auth). Keep it that way?",
                                        default=True) else "token"
        else:
            auth = old.get("auth") or "token"
        if args.service is not None:
            no_service = not args.service
        elif _mcp_no_service(old) and ui.interactive():
            no_service = ui.confirm("The server runs as a detached background process (--no-service), not as a "
                                    "launchd/systemd login service. Keep it that way?", default=True)
        else:
            no_service = _mcp_no_service(old)
        if auth == "none":
            ui.warn(_mcp_no_auth_warning(host))
            if old.get("auth") != "none" and ui.interactive() and \
                    not ui.confirm("Deploy the MCP server without a bearer token?", default=False):
                raise ui.Abort("Cancelled. Nothing was changed.", code=0)
        if old:
            old_auth, old_no_service = old.get("auth") or "token", _mcp_no_service(old)
            if old_auth != auth:
                ui.info("Auth changes: " + ("bearer token -> none" if auth == "none" else "none -> bearer token (clients "
                        "connected over HTTP get it below)"))
            if old_no_service != no_service:
                ui.info("Service changes: " + ("launchd/systemd login service -> detached background process" if no_service
                                               else "background process -> launchd/systemd login service (starts at login)"))
            elif no_service and not ui.interactive():
                ui.info("Kept as a detached background process (--no-service); --service (or `cs setup mcp` at a "
                        "terminal) brings the login service back.")
        backups = _mcp_backup_files() if current else {}   # a re-run is undone by putting the previous deployment back
        created_token = not mcp.TOKEN_PATH.exists()
        with ui.Spinner("Stopping the previous MCP server" if old else "Preparing the MCP server"):
            mcp.remove_service()               # a service kind change (launchd <-> background) must not leave the old one behind
            _mcp_kill_orphan(old)
        if not port:
            port = mcp.free_port(mcp.DEFAULT_PORT, host)
            if port != mcp.DEFAULT_PORT:
                ui.info(f"Port {mcp.DEFAULT_PORT} is busy; using {port}.")
        state = {"transport": "http", "host": host, "port": int(port), "auth": auth, "no_service": no_service,
                 "service": "background" if no_service else None}
        if auth == "token":
            mcp.ensure_token(rotate=bool(args.rotate_token))
        settings["mcp"] = True                 # validated: switch MCP on (the server refuses to start while it is off)
        paths.save_settings(settings)
        with ui.Spinner(f"Starting the MCP server on {mcp.url(state)}"):
            kind = mcp.start(state)
        h = mcp.health(state)
        if h:
            ui.ok(f"MCP server up: {mcp.url(state)}   ({kind}, protocol {h.get('protocolVersion')}, {len(mcp.TOOLS)} tools, {len(mcp.resource_list())} resources, {len(mcp.PROMPTS)} prompts)")
            if auth == "none":
                mcp.TOKEN_PATH.unlink(missing_ok=True)   # the server uses none: no token that looks valid (undo has a copy)
        else:
            why = _log_tail(mcp.LOG_PATH, r"Cannot listen|Refusing|disabled|Error")
            mcp.remove_service(state)          # never leave a login service behind that fails and restarts forever
            if prev:
                mcp.save_state(prev)
            else:
                mcp.STATE_PATH.unlink(missing_ok=True)
            _mcp_put_back(backups, created_token)
            settings["mcp"] = was_enabled      # a failed setup leaves MCP as it was (a disabled one stays off)
            paths.save_settings(settings)
            ui.err(f"The server did not answer on {mcp.url(state)}" + (f": {why}" if why else "") +
                   f"; the service was removed again and nothing else was changed. Log: {mcp.LOG_PATH}")
            ui.eprint(ui.dim(f"  Try in the foreground to see the error:  cs mcp serve --http --host {state['host']} --port {state['port']}"
                             + ("  --no-auth" if auth == "none" else "")))
            if was_enabled and prev.get("transport") == "http" and prev.get("host") and prev.get("port"):
                mcp.start(prev)                # the deployment that worked before this run (it was stopped above)
                if mcp.health(prev):
                    ui.info(f"The previous server is running again: {mcp.url(prev)}")
                else:
                    mcp.remove_service(prev)   # not a service that can only crash-loop either
                    ui.warn("The previous server did not start again either; start it with: cs mcp start")
            return 1
    else:
        if args.auth is not None or args.service is not None:
            ui.info("--[no-]auth and --[no-]service apply to the HTTP server only; stdio needs neither.")
        backups = _mcp_backup_files() if current else {}
        had_http = current == "http" or any(p.exists() for p in (mcp._launchd_plist(), mcp._systemd_unit())) or bool(mcp.running_pid())
        mcp.remove_service()                   # also unloads the launchd/systemd service so nothing comes back at login
        _mcp_kill_orphan(prev)
        mcp.TOKEN_PATH.unlink(missing_ok=True)  # stdio needs no token; a later http deployment issues a new one
        state = {}
        settings["mcp"] = True
        paths.save_settings(settings)
        mcp.save_state({"transport": "stdio"})
        ui.ok("stdio mode: " + ("the background service and its token were removed; " if had_http else "") +
              "clients launch `cloudseed mcp serve` on demand; nothing listens on the network.")
    ui.step(2, 3, "Clients", "register the server with the MCP clients on this machine")
    present = [k for k in mcp.CLIENTS if mcp.client_present(k)]
    if chosen_named is not None:
        chosen = chosen_named
        if not chosen and "none" not in [n.strip().lower() for n in named]:
            ui.info("No MCP clients detected on this machine. Known: " + ", ".join(mcp.CLIENTS) + "   (cs mcp config prints snippets)")
    elif not ui.interactive():
        chosen = present if args.yes_clients else []
        if not chosen:
            ui.info("Non-interactive: no new client configs written (pass --client all | <name>... to wire them). Detected: " + (", ".join(present) or "none"))
    else:
        chosen = []
        for k in mcp.CLIENTS:
            if not mcp.client_present(k):
                continue
            cur = mcp.connected(k)
            if ui.confirm(f"Connect {mcp.CLIENTS[k]['display']}" + (f" (currently: {cur})" if cur else "") + "?", default=True):
                chosen.append(k)

    def client_transport(k: str) -> str:
        if k == "claude-desktop" or transport == "stdio":
            return "stdio"
        if args.client_transport:
            return args.client_transport
        cur = mcp.connected(k)
        # a re-run of an HTTP deployment keeps each client on the transport it was connected with (a client moved to
        # stdio on purpose - shell-exported credentials - stays there)
        return cur if current == "http" and cur in mcp.CLIENTS[k]["transports"] else "http"

    for k in chosen:
        try:
            msg = mcp.connect(k, client_transport(k), state or None)
            wired[k] = "http" if "(http)" in msg else "stdio"
            ui.ok(f"{mcp.CLIENTS[k]['display']}: {msg}")
        except ui.Abort as e:   # an Abort no longer prints itself: show its message here, once
            ui.warn(f"{mcp.CLIENTS[k]['display']}: not connected: {e}")
    # clients wired earlier keep working: point them at the new port/token, or at stdio when the server went away
    for k in _mcp_refresh(state or None, skip=chosen):
        wired[k] = mcp.connected(k) or "stdio"
    if current:
        # put the previous deployment's files back, then bring it up again (only when MCP was on: a disabled MCP ran
        # no server), re-wire the clients as they were, and switch MCP off again when this run switched it on
        if current == "http":
            then = [["mcp", "restart"]] if was_enabled else []
        else:
            then = [["mcp", "setup", "-y", "--transport", "stdio", "--client", "none"]]
        then += _mcp_reconnect_argvs(wiring_before)
        if not was_enabled:
            then.append(["disable", "mcp"])
        undo.record(undo.GLOBAL, "mcp setup (server + client configs)", "restore-files", {"files": backups, "then": then})
    else:
        # the first deployment: remove it again, and give back what existed before it (stdio client entries, the switch)
        argvs = [["mcp", "uninstall", "--auto-approve"]]
        argvs += [a for a in _mcp_reconnect_argvs(wiring_before) if a[:2] == ["mcp", "connect"]]
        if was_enabled:
            argvs.append(["enable", "mcp"])
        undo.record(undo.GLOBAL, "mcp setup (server + client configs)", "argv" if len(argvs) == 1 else "argv-seq",
                    {"argv": argvs[0]} if len(argvs) == 1 else {"argvs": argvs})
    ui.step(3, 3, "How to use it", "the guide below is also saved to " + str(mcp.GUIDE_PATH))
    print()
    mcp.print_guide(state or None, wired)
    return 0


def cmd_mcp(args, settings) -> int:
    sub = args.mcp_cmd or "status"
    if sub == "setup":
        return cmd_mcp_setup(args, settings)
    if sub == "serve":
        if args.http:
            return mcp.serve_http(args.host or mcp.DEFAULT_HOST, int(args.port or mcp.DEFAULT_PORT), auth=args.auth is not False)
        return mcp.serve()
    if sub == "tools":
        _mcp_tools_page()
        return 0
    if sub == "config":
        _mcp_config_page()
        return 0
    if sub == "guide":
        state = mcp.load_state()
        mcp.print_guide(state if state.get("transport") == "http" else None)
        return 0
    if sub == "test":
        return _mcp_test(args)
    if sub == "status":
        return _mcp_status(settings)
    if sub == "start":
        state = mcp.load_state()
        if state.get("transport") != "http":
            raise ui.Abort("No HTTP server deployed yet. Run: cs setup mcp")
        if not settings.get("mcp"):            # like restart: `cs disable mcp` stays in force until enable / setup
            raise ui.Abort("The MCP server is disabled; turn it on with: cs enable mcp   (or: cs setup mcp)")
        probe = _mcp_probe(state)
        if probe == "ok":
            ui.ok(f"Already running: {mcp.url(state)}")
            return 0
        if probe == "auth":
            raise ui.Abort(f"A cloudseed MCP server already runs on {mcp.url(state)} but rejects the saved token (it still has an "
                           "older one, e.g. after undoing `cs mcp token --rotate`). Load the current token with: cs mcp restart")
        kind = _mcp_start_checked(state)
        ui.ok(f"MCP server up: {mcp.url(state)}   ({kind}; log {mcp.LOG_PATH})")
        return 0
    if sub == "stop":
        state = mcp.load_state()
        stopped = mcp.stop()
        stopped = _mcp_kill_orphan(state) or stopped
        if stopped:
            undo.record(undo.GLOBAL, "mcp stop", "argv", {"argv": ["mcp", "start"]})
        msg = "MCP server stopped." if stopped else "No running MCP server found."
        if stopped and state.get("service") in ("launchd", "systemd"):
            msg += "  It starts again at login (as a launchd/systemd service); `cs disable mcp` keeps it off, `cs destroy mcp` removes it."
        ui.ok(msg)
        return 0
    if sub == "restart":
        state = mcp.load_state()
        if state.get("transport") != "http":
            raise ui.Abort("No HTTP server deployed yet. Run: cs setup mcp")
        if not settings.get("mcp"):
            raise ui.Abort("The MCP server is disabled; turn it on with: cs enable mcp   (or: cs setup mcp)")
        mcp.stop(state)
        _mcp_kill_orphan(state)
        _mcp_start_checked(state, what="Restart")
        ui.ok(f"MCP server restarted: {mcp.url(state)}")
        return 0
    if sub == "logs":
        if not mcp.LOG_PATH.exists():
            ui.info(f"No log yet ({mcp.LOG_PATH}).")
            return 0
        lines = mcp.LOG_PATH.read_text(errors="replace").splitlines()
        print("\n".join(lines[-max(1, int(args.lines or 1)):]))
        return 0
    if sub == "token":
        return _mcp_token(args)
    if sub == "connect":
        state = mcp.load_state()
        http_ok = state.get("transport") == "http"
        names = _mcp_clients_arg(args.clients, need_present=True) if args.clients else _mcp_pick_clients("connect")
        if args.transport == "http" and not http_ok:
            ui.warn("No HTTP server is deployed (cs setup mcp); connecting over stdio instead.")
        before = _mcp_clients_wiring()          # the undo puts back exactly this wiring of the clients touched
        wired = {}
        for k in names:
            c = mcp.CLIENTS[k]
            cur = before.get(k)
            # a connected client keeps its transport (one moved to stdio for shell-exported credentials stays there)
            # unless --transport says otherwise; a new one gets http when a server is deployed, else stdio
            want = args.transport or (cur if cur in c["transports"] else None) or ("http" if http_ok else "stdio")
            if want == "http" and not http_ok:
                want = "stdio"                  # its server is gone (warned above for --transport http)
            if want == "http" and http_ok and "http" not in c["transports"]:
                ui.info(f"{c['display']} only launches local commands; connecting it over stdio.")
            try:
                msg = mcp.connect(k, want, state if http_ok else None)
                wired[k] = "http" if "(http)" in msg else "stdio"
                ui.ok(f"{c['display']}: {msg}")
            except ui.Abort as e:   # an Abort no longer prints itself: show its message here, once
                ui.warn(f"{c['display']}: not connected: {e}")
        if not wired:
            ui.info("Nothing connected. Known clients: " + ", ".join(mcp.CLIENTS) + "  (cs mcp connect <client> | all)")
            return 1
        mcp.save_guide(state if http_ok else None, wired)
        # the inverse: clients that were not connected are disconnected, a changed transport is put back; a client
        # that was already wired this way needs nothing (a no-op must not push real undo points out)
        fresh = [k for k in wired if k not in before]
        undo_argvs = [["mcp", "disconnect", *fresh]] if fresh else []
        for tr in ("http", "stdio"):
            back = [k for k in wired if before.get(k) == tr and wired[k] != tr]
            if back:
                undo_argvs.append(["mcp", "connect", *back, "--transport", tr])
        offer = False
        # an undo that reconnects clients puts back how things were, MCP off included: it neither switches MCP on
        # nor asks to (a restore that needs it on runs `enable mcp` / `mcp setup` itself)
        if not settings.get("mcp") and not os.environ.get("CLOUDSEED_UNDOING"):
            if "mcp" not in settings and not mcp.STATE_PATH.exists():
                # never set up: connecting a client is the opt-in (stdio: clients launch `cs mcp serve` themselves)
                settings["mcp"] = True
                paths.save_settings(settings)
                undo_argvs.append(["disable", "mcp"])
                ui.ok("MCP enabled (it was never set up; cs disable mcp turns it off again).")
            else:   # switched off on purpose (disable / destroy mcp): never switch it back on behind the user's back
                offer = True
        if undo_argvs:   # one undo point for the command (it also switches MCP off again when this turned it on)
            undo.record(undo.GLOBAL, f"mcp connect {' '.join(wired)}", "argv" if len(undo_argvs) == 1 else "argv-seq",
                        {"argv": undo_argvs[0]} if len(undo_argvs) == 1 else {"argvs": undo_argvs})
        if offer and ui.interactive() and ui.confirm("MCP is disabled, so these clients cannot start cloudseed. Enable it now?", default=True):
            cmd_enable(argparse.Namespace(feature="mcp", agent=None, port=None, no_open=True), settings)   # records its own undo
        if settings.get("mcp"):
            ui.info(f"Restart the client(s) to load the tools. Guide: cs mcp guide   ({mcp.GUIDE_PATH})")
        else:
            ui.warn("MCP is disabled: these clients fail to start cloudseed ('cloudseed MCP is disabled') until you run: cs enable mcp")
        return 0
    if sub == "disconnect":
        gone = []
        for k in (_mcp_clients_arg(args.clients, need_present=False) if args.clients else _mcp_pick_clients("disconnect")):
            was = mcp.connected(k)
            msg = mcp.disconnect(k)
            if msg:
                gone.append((k, was or "stdio"))
                ui.ok(f"{mcp.CLIENTS[k]['display']}: {msg}")
        if gone:
            argvs = [["mcp", "connect", *[k for k, t in gone if t == tr], "--transport", tr] for tr in ("http", "stdio") if any(t == tr for _, t in gone)]
            undo.record(undo.GLOBAL, f"mcp disconnect {' '.join(k for k, _ in gone)}", "argv-seq", {"argvs": argvs})
        else:
            ui.info("No client had the cloudseed server configured.")
        return 0
    if sub == "uninstall":
        return _mcp_uninstall(args, settings)
    return 1


def _mcp_pick_clients(action: str) -> list[str]:
    """`cs mcp connect|disconnect` without client names: at a terminal, ask about each client it could act on;
    otherwise (-y, scripts, the console) refuse with the names to pass - no names never means every client."""
    if action == "connect":
        cands, what = [k for k in mcp.CLIENTS if mcp.client_present(k)], "Detected on this machine"
    else:
        cands, what = [k for k in mcp.CLIENTS if mcp.connected(k)], "Connected now"
    if not ui.interactive():
        raise ui.Abort(f"Name the clients to {action}: cs mcp {action} <client>... | all.   {what}: {', '.join(cands) or 'none'}.   "
                       f"Known: {', '.join(mcp.CLIENTS)}", code=2)
    if not cands:
        if action == "connect":
            ui.info("No MCP client detected on this machine. Known: " + ", ".join(mcp.CLIENTS) + "   (cs mcp config prints snippets)")
        return []
    chosen = []
    for k in cands:
        cur = mcp.connected(k)
        display = mcp.CLIENTS[k]["display"]
        q = (f"Connect {display}" + (f" (currently: {cur})" if cur else "") + "?") if action == "connect" else f"Disconnect {display} ({cur})?"
        if ui.confirm(q, default=True):
            chosen.append(k)
    return chosen


def _mcp_start_checked(state: dict, what: str = "Start") -> str:
    """Start the deployed HTTP server; refuse when its port belongs to someone else, and never leave a service
    behind that can only crash-loop (launchd/systemd restart a failing server forever)."""
    host, port = state.get("host", mcp.DEFAULT_HOST), int(state.get("port") or mcp.DEFAULT_PORT)
    if not _can_bind(host, port):
        raise ui.Abort(f"{what} failed: port {port} on {host} is in use by another program. Move the server with: "
                       f"cs setup mcp --port <free port>")
    with ui.Spinner(f"Starting the MCP server on {mcp.url(state)}"):
        kind = mcp.start(state)
    if not mcp.health(state):
        why = _log_tail(mcp.LOG_PATH, r"Cannot listen|Refusing|disabled|Error")
        mcp.remove_service(state)   # do not leave launchd/systemd restarting a server that cannot start (cs mcp start recreates it)
        raise ui.Abort(f"{what} failed: the MCP server did not answer on {mcp.url(state)}" + (f" ({why})" if why else "") +
                       f". Log: {mcp.LOG_PATH}   (foreground: cs mcp serve --http --host {host} --port {port})")
    return kind


def _mcp_token(args) -> int:
    state = mcp.load_state()
    http = state.get("transport") == "http"
    if args.rotate and not http:   # before any side effect: no token file, no undo entry
        raise ui.Abort("Nothing to rotate: the MCP server is not deployed over HTTP (stdio needs no token). "
                       "Deploy it with: cs setup mcp")
    if http and state.get("auth", "token") != "token":
        raise ui.Abort("The MCP server runs without a bearer token (deployed with --no-auth), so it uses none. "
                       "To require one: cs setup mcp --rotate-token")
    if not args.rotate:
        tok = mcp.load_token()
        if not tok:
            if not http:
                raise ui.Abort("No bearer token: the MCP server is not deployed over HTTP (stdio needs none). Deploy it with: cs setup mcp")
            tok = mcp.ensure_token()
        print(tok)
        return 0
    was_up = http and bool(_mcp_health_info(state) or mcp.running_pid())   # /health needs no token: works across the rotation
    backups = _mcp_backup_files()
    wiring = {k: t for k, t in _mcp_clients_wiring().items() if t == "http"}
    tok = mcp.ensure_token(rotate=True)
    then = ([["mcp", "restart"]] if was_up else []) + ([["mcp", "connect", *wiring, "--transport", "http"]] if wiring else [])
    undo.record(undo.GLOBAL, "mcp token --rotate", "restore-files", {"files": backups, "then": then})   # also if a step below fails
    ui.ok("New bearer token written.")
    if was_up:
        mcp.stop(state)
        _mcp_kill_orphan(state)
        _mcp_start_checked(state, what="Restart")
        ui.ok("Server restarted with the new token.")
    elif http:
        ui.info("The server is not running; it loads the new token when it starts (cs mcp start).")
    updated = _mcp_refresh(state if http else None, force=True) if http else []
    if http and mcp.GUIDE_PATH.exists():
        mcp.save_guide(state)
    left = [k for k in wiring if k not in updated]
    if left:
        ui.warn("Not updated: " + ", ".join(left) + "  - reconnect them with: cs mcp connect " + " ".join(left))
    print(tok)
    return 0


def _mcp_tools_page() -> None:
    """Tool / resource / prompt inventory; every row fits the panel (descriptions shortened on a word boundary)."""
    import textwrap
    body = ui.width() - 6                      # printable width of a plain panel row
    rows = []
    for t in mcp.tool_list():
        spec = mcp.TOOLS.get(t["name"]) or {}
        # always destructive, or only some uses (kubectl get needs no confirm, kubectl delete does)
        tag = "[confirm] " if spec.get("destructive") else "[confirm*] " if spec.get("destructive_when") else ""
        room = max(12, body - 25 - len(tag))
        desc = textwrap.shorten(t["description"], width=room, placeholder="…")
        rows.append(f"{ui.style(t['name'].ljust(24), 'text')} " + (ui.style(tag, "seed") if tag else "") + ui.dim(desc))
    ui.panel(f"cloudseed MCP tools ({len(rows)})", rows)
    # the legend under the panel, not in its title: a title is cut to the terminal (at 80 columns right before [confirm*])
    print(ui.dim("  [confirm] = always needs confirm=true · [confirm*] = only some uses do"))
    res = mcp.resource_list()
    kw = max([len(r["uri"]) for r in res] + [10]) + 1
    ui.panel(f"Resources ({len(res)})", [f"{r['uri']:<{kw}}" + ui.dim(textwrap.shorten(r["description"], width=max(12, body - kw), placeholder="…")) for r in res])
    ui.panel(f"Prompts ({len(mcp.PROMPTS)})", [(p["name"], ui.dim(p["description"])) for p in mcp.prompt_list()])


def _mcp_config_page() -> None:
    """Copy-paste snippets, printed raw: no panel borders, no wrapping, no colour inside a snippet."""
    state = mcp.load_state()
    s = state if state.get("transport") == "http" else None
    blocks = mcp.client_config_variants(s)
    for i, b in enumerate(blocks):
        if i:
            print()
        print(ui.style(b["display"], "bold", "brand"))
        print(ui.dim(f"  paste into: {b['path']}" if b.get("path") else "  run it in a terminal"))
        for label, snippet in b["variants"]:
            print()
            print(ui.dim(f"-- {label} --"))
            print(snippet)
    print()
    if not s:
        ui.info("No HTTP server is deployed, so only stdio snippets are shown (cs setup mcp deploys one).")
    if not mcp.enabled():
        ui.warn("MCP is disabled: clients with these entries fail to start cloudseed until you run: cs enable mcp   (or: cs setup mcp)")
    ui.info("Use ONE variant per client. The same snippets are saved unwrapped in " + str(mcp.GUIDE_PATH) + " (cs mcp guide).")
    mcp.save_guide(s)


def _mcp_test(args) -> int:
    import json as _json
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": mcp.PROTOCOL, "capabilities": {}, "clientInfo": {"name": "cs-mcp-test", "version": __version__}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "cloudseed://skills/cloudseed"}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "cloudseed_list", "arguments": {}}}]
    if not mcp.enabled():   # the test must see what clients see: a disabled server refuses to start for them
        ui.err("MCP is disabled: clients that launch `cs mcp serve` exit with 'cloudseed MCP is disabled'. "
               "Enable it: cs enable mcp   (or: cs setup mcp)")
        return 1
    if getattr(args, "http", False):
        state = mcp.load_state()
        if state.get("transport") != "http":
            raise ui.Abort("No HTTP server deployed. Run: cs setup mcp   (or test stdio: cs mcp test)")
        import urllib.request
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if state.get("auth", "token") == "token":
            headers["Authorization"] = f"Bearer {mcp.load_token()}"
        results, sid = [], None
        for m in msgs:
            req = urllib.request.Request(mcp.url(state), data=_json.dumps(m).encode(), method="POST",
                                         headers=dict(headers, **({"Mcp-Session-Id": sid} if sid else {})))
            try:
                with mcp._open(req, 120) as r:   # never through HTTP(S)_PROXY: the server is on this machine
                    sid = sid or r.headers.get("Mcp-Session-Id")
                    results.append(_json.loads(r.read().decode()))
            except Exception as e:  # noqa: BLE001
                ui.err(f"{m['method']} over HTTP failed: {e}")
                return 1
        if sid:                     # end the test's session, as a real client does
            try:
                mcp._open(urllib.request.Request(mcp.url(state), method="DELETE", headers=dict(headers, **{"Mcp-Session-Id": sid})), 5).close()
            except Exception:  # noqa: BLE001 - best effort
                pass
        where = mcp.url(state)
    else:
        proc = subprocess.run(mcp._launcher() + ["mcp", "serve"], text=True, capture_output=True, timeout=120, env=dict(os.environ),
                              input="".join(_json.dumps(m) + "\n" for m in msgs))
        results = []
        for line in proc.stdout.splitlines():
            try:
                results.append(_json.loads(line))
            except ValueError:
                continue                        # not a JSON-RPC message
        where = "stdio"
        if not results and proc.stderr.strip():
            ui.err("`cs mcp serve` answered nothing: " + proc.stderr.strip().splitlines()[-1])
    by_id = {r.get("id"): r for r in results if isinstance(r, dict)}     # replies matched by id, not by position
    ok = all((by_id.get(m["id"]) or {}).get("result") is not None for m in msgs)
    results = [by_id.get(m["id"]) or {} for m in msgs]
    n_tools = len((results[1]["result"] or {}).get("tools") or []) if ok else "?"
    (ui.ok if ok else ui.err)(f"MCP round-trip over {where}: initialize, tools/list ({n_tools} tools), resources/read skill, tools/call cloudseed_list")
    if not ok:
        for r in results:
            if r.get("error"):
                ui.err(_json.dumps(r["error"]))
    return 0 if ok else 1


def _mcp_status(settings) -> int:
    state = mcp.load_state()
    http = state.get("transport") == "http"
    rows: list = [("Enabled", "yes" if settings.get("mcp") else "no  (cs setup mcp)"), ("Transport", state.get("transport") or "stdio (not deployed; clients launch `cs mcp serve`)")]
    if http:
        h = mcp.health(state)
        alive = _mcp_health_info(state)
        pid = mcp.running_pid() or (alive or {}).get("pid")
        if h:
            health = ui.style("running", "leaf", "bold") + f"  protocol {h.get('protocolVersion')}"
        elif alive:
            health = ui.style("running, but it rejects the saved token", "seed", "bold") + "  (it still has an older one: cs mcp restart)"
        else:
            health = ui.style("not responding", "rose", "bold") + (f"  (cs mcp start; log {mcp.LOG_PATH})" if settings.get("mcp")
                                                                   else "  (MCP is disabled: cs enable mcp)")
        auth_row = "bearer token  (cs mcp token)" if state.get("auth", "token") == "token" else \
            ui.style("none", "seed", "bold") + "  (any local process can call every tool; require a token: cs setup mcp --rotate-token)"
        rows += [("URL", mcp.url(state)), ("Auth", auth_row),
                 ("Service", f"{state.get('service')}" + (f"  pid {pid}" if pid else "")), ("Health", health), ("Log", str(mcp.LOG_PATH))]
        outdated = mcp.outdated_service(state)   # a login service an older version wrote (throttled, or without the marker)
        if outdated:
            rows.append(("Outdated", ui.style(outdated, "seed", "bold") + "  (cs mcp restart rewrites it)"))
    # service definitions of this home that do not match the deployment (another kind, an older shared name, or any
    # at all without an HTTP deployment): at login they start a second server that cannot bind and restarts forever
    leftover = mcp.leftover_services(state)
    stray_pid = None if http else mcp.running_pid()
    if leftover or stray_pid:
        what = ("a launchd/systemd service of another kind is still installed" if http else
                "an HTTP server service is still installed")
        fix = "cs mcp restart" if http else "cs setup mcp --transport stdio"
        rows.append(("Leftover", ui.style(what, "seed", "bold") + "  " + (", ".join(leftover) or f"pid {stray_pid}") +
                     f"  (remove it: {fix})"))
    rows.append(("Tools", f"{len(mcp.TOOLS)} tools · {len(mcp.resource_list())} resources · {len(mcp.PROMPTS)} prompts   (cs mcp tools)"))
    ui.panel("cloudseed MCP server", rows)
    crow = []
    stale = []
    off = [k for k in mcp.CLIENTS if mcp.connected(k)] if not mcp.enabled() else []
    for k, c in mcp.CLIENTS.items():
        cur = mcp.connected(k)
        present = mcp.client_present(k)
        if cur and k in off:
            crow.append((c["display"], ui.style(f"connected ({cur}) but MCP is disabled", "seed") + "  " + ui.dim("(cs enable mcp)")))
        elif cur and mcp.stale(k, state):
            stale.append(k)
            crow.append((c["display"], ui.style(f"connected ({cur}) but out of date", "seed") + "  " + ui.dim(f"(other port/token or no server) cs mcp connect {k}")))
        else:
            crow.append((c["display"], (ui.style(f"connected ({cur})", "leaf") if cur else ("installed, not connected  " + ui.dim(f"cs mcp connect {k}") if present else ui.dim("not detected")))))
    ui.panel("Clients", crow)
    if off:
        ui.warn(f"{len(off)} client(s) are connected but MCP is disabled: they fail to start the server. Enable it: cs enable mcp"
                "   (or remove them: cs mcp disconnect all)")
    if stale:
        ui.warn(f"{len(stale)} client(s) point at a server that is not there any more; fix: cs mcp connect {' '.join(stale)}")
    parts = ["cs mcp guide", "cs mcp connect <client>|all", "cs mcp restart" if http else "cs setup mcp", "cs destroy mcp"]
    for sep in ("   ·   ", "  ·  ", " · "):         # one row: tighter separators rather than a wrapped footer
        footer = "  " + sep.join(parts)
        if len(footer) < ui.cols():
            break
    print(ui.dim(footer))
    return 0


def _mcp_uninstall(args, settings) -> int:
    ui.header("Remove the cloudseed MCP server")
    if not getattr(args, "auto_approve", False):
        if not ui.interactive():
            raise ui.Abort("Nothing removed. Re-run with --auto-approve to remove the MCP server without a prompt (cs destroy mcp --auto-approve).", code=3)
        if not ui.confirm("Stop the server, remove the service, the token and every client entry?", default=False):
            raise ui.Abort("Cancelled. Nothing was changed.", code=0)
    state = mcp.load_state()
    undo_argvs = _mcp_restore_argvs(state, _mcp_clients_wiring(), bool(settings.get("mcp")))   # before the disconnects
    if undo_argvs:     # nothing existed (never deployed, no client, disabled): a no-op leaves no undo point
        undo.record(undo.GLOBAL, "mcp uninstall", "argv-seq", {"argvs": undo_argvs})
    for k in mcp.CLIENTS:
        msg = mcp.disconnect(k)
        if msg:
            ui.ok(f"{mcp.CLIENTS[k]['display']}: {msg}")
    # disable and forget the deployment BEFORE stopping the service: if the stop kills this very process (an uninstall
    # started from inside the service), nothing is left that restarts at login or claims to be deployed
    settings["mcp"] = False
    paths.save_settings(settings)
    for p in (mcp.STATE_PATH, mcp.GUIDE_PATH):
        try:
            p.unlink()
        except OSError:
            pass
    mcp.remove_service(state)
    _mcp_kill_orphan(state)
    try:
        mcp.TOKEN_PATH.unlink()
    except OSError:
        pass
    if _mcp_health_info(state):
        ui.warn(f"A cloudseed MCP server still answers on {mcp.url(state)}; stop it by hand (its pid is on {mcp.url(state)[:-4]}/health).")
    ui.ok(f"MCP server removed and disabled (log kept at {mcp.LOG_PATH}). Deploy again any time: cs setup mcp")
    return 0


def cmd_enable(args, settings) -> int:
    feature = args.feature
    if feature == "ui":
        return cmd_ui(argparse.Namespace(ui_cmd="start", port=getattr(args, "port", None), host=None,
                                         no_open=bool(getattr(args, "no_open", False)), lines=50, rotate=False), settings)
    if feature == "mcp":
        if not settings.get("mcp"):
            undo.record(undo.GLOBAL, "enable mcp", "argv", {"argv": ["disable", "mcp"]})
        settings["mcp"] = True
        paths.save_settings(settings)
        state = mcp.load_state()
        http = state.get("transport") == "http"
        ui.ok("MCP enabled: every cloudseed feature is available as a tool (stdio: cs mcp serve" + (f"; http: {mcp.url(state)}" if http else "") + ").")
        if http:
            probe = _mcp_probe(state)
            if probe == "auth":
                ui.warn("The HTTP server runs with an older token; load the current one with: cs mcp restart")
            elif probe is None:
                _mcp_start_checked(state)
        ui.info("Deploy the shared local server and connect your clients with: cs setup mcp   ·   guide: cs mcp guide   ·   status: cs mcp status")
        return 0
    if feature == "headliner":
        if not headliner.enabled(settings):   # on by default: a fresh home changes nothing here
            undo.record(undo.GLOBAL, "enable headliner", "argv", {"argv": ["disable", "headliner"]})
        settings["headliner"] = True
        paths.save_settings(settings)
        ui.ok("Headliner enabled: agent prompts get a compact, secret-free research brief (saves tokens).")
        return 0
    keys = ["agentic", "headliner", "agent"]
    snap = undo.snapshot_settings(keys)
    spec = _ensure_agent_ready(args.agent, settings)     # may abort: then nothing is recorded or switched on
    settings["agentic"] = True
    settings.setdefault("headliner", True)
    paths.save_settings(settings)
    if any(snap["settings"].get(k) != settings.get(k) for k in keys):
        undo.record(undo.GLOBAL, "enable agentic", "settings-restore", snap)
    ui.ok(f"Agentic mode enabled with {spec['display']}.")
    agents.describe(spec, settings)
    print()
    ui.info('Now you can say:  cloudseed agentic "set up a dev environment on aws in us-west-2"')
    ui.info('short form:       cs agentic "..."   (cs is installed as an alias by scripts/install.sh)')
    ui.info("Deterministic commands (setup/plan/apply/destroy/...) keep working exactly as before.")
    return 0


def cmd_disable(args, settings) -> int:
    # the headliner is on by default (a fresh home has no key for it); the other features default to off
    was_on = headliner.enabled(settings) if args.feature == "headliner" else settings.get(args.feature)
    if was_on:
        # `ui start --no-open` is the exact inverse of `disable ui` (enable ui would also open a browser tab)
        inverse = ["ui", "start", "--no-open"] if args.feature == "ui" else ["enable", args.feature]
        undo.record(undo.GLOBAL, f"disable {args.feature}", "argv", {"argv": inverse})
    settings[args.feature] = False
    paths.save_settings(settings)
    if args.feature == "ui":
        # server.json keeps its service kind as the preference for the next start; `ui status` / `ui stop` read the
        # login item from disk (_ui_login_item), so they never claim one that was removed here
        webui.remove_service()
        ui.ok("UI disabled: the local console is stopped and removed from login items. Back any time: cs enable ui")
        return 0
    if args.feature == "mcp":
        state = mcp.load_state()
        stopped = mcp.stop()
        stopped = _mcp_kill_orphan(state) or stopped
        mcp.remove_service()   # a login-time service would otherwise start, refuse, and be restarted forever
        ui.ok("MCP disabled: the server " + ("was stopped and " if stopped else "") + "refuses to start until `cs enable mcp` / `cs setup mcp`.")
        ui.info("Client entries are kept (they will show 'failed' until re-enabled); remove them with: cs mcp disconnect all   ·   remove everything: cs destroy mcp")
        return 0
    if args.feature == "headliner":
        ui.ok("Headliner disabled: tasks go to the agent without the research brief.")
    else:
        ui.ok("Agentic mode disabled. Only deterministic commands run now.")
    return 0


def cmd_agents(args, settings) -> int:
    print(agents.agents_page(settings))
    return 0


def _confirm_model(key: str, spec: dict, model: str, settings: dict, declined: str = "Model not changed.") -> bool:
    """Check a model id before anything is changed. Unknown ids are accepted and remembered as custom (new models
    appear faster than cloudseed releases), but a likely typo gets a did-you-mean and, in a terminal, a confirmation
    (declined: Abort with `declined`, exit 0). Returns True when the id is a custom one. Saves nothing."""
    import difflib
    avail = agents.models(spec, settings)
    if model in avail:
        return False
    near = difflib.get_close_matches(model, avail, n=1, cutoff=0.8)
    if not near:   # an alias and its dated form (claude-haiku-4-5 / claude-haiku-4-5-20251001) are the same model
        near = [m for m in avail if m.startswith(model + "-") or model.startswith(m + "-")][:1]
    ui.warn(f"'{model}' is not in the known list for {spec['display']}" + (f" - did you mean {near[0]}?" if near else "."))
    if ui.interactive():
        if not ui.confirm(f"Use '{model}' anyway (it is remembered as a custom model)?", default=False):
            raise ui.Abort(declined, code=0)
    else:
        ui.info(f"Using it anyway (non-interactive); remove it later with: cloudseed model --forget {model} --agent {key}")
    return True


def _apply_model(key: str, model: str, is_custom: bool, settings: dict) -> None:
    """Select a (checked) model for an agent and save it."""
    if is_custom:
        custom = settings.setdefault("custom_models", {}).setdefault(key, [])
        if model not in custom:
            custom.append(model)
    settings.setdefault("models", {})[key] = model
    paths.save_settings(settings)


def _choose_model(key: str, spec: dict, model: str, settings: dict) -> None:
    """Check, then select a model for an agent (see _confirm_model)."""
    _apply_model(key, model, _confirm_model(key, spec, model, settings), settings)


def cmd_use(args, settings) -> int:
    if args.agent in ("help", "list", "?"):
        return cmd_agents(args, settings)
    keys = ["agent", "models", "custom_models"]
    snap = undo.snapshot_settings(keys)
    key = _resolve_agent_key(args.agent, settings)
    spec = agents.get(key)                               # an unknown agent stops here, before anything is changed
    # the model is checked first: a declined typo must not leave the agent switched or its skills installed
    is_custom = _confirm_model(key, spec, args.model, settings, declined="Nothing was changed.") if args.model else False
    try:
        spec = _ensure_agent_ready(key, settings)        # may abort: then nothing is switched
        if args.model:
            _apply_model(key, args.model, is_custom, settings)
    finally:   # whatever was saved gets its undo point, also when a later step failed
        if any(snap["settings"].get(k) != settings.get(k) for k in keys):
            undo.record(undo.GLOBAL, f"use {key}" + (f" --model {args.model}" if args.model else ""), "settings-restore", snap)
    agents.describe(spec, settings)
    if not settings.get("agentic"):
        ui.info('Agentic mode is off. Turn it on with: cloudseed enable agentic   (then: cloudseed agentic "<task>")')
    return 0


def cmd_model(args, settings) -> int:
    key = args.agent or settings.get("agent")
    if not key:
        key = "builtin"
        ui.info("No agent selected yet; showing the default (builtin). Choose one with: cloudseed use builtin | claude | codex | gemini | grok")
    spec = agents.get(key)
    keys = ["models", "custom_models"]
    snap = undo.snapshot_settings(keys)
    forget = getattr(args, "forget", None)
    if forget:
        custom = (settings.get("custom_models") or {}).get(key) or []
        if forget not in custom:
            raise ui.Abort(f"'{forget}' is not a custom model of {spec['display']}. Custom models: {', '.join(custom) or 'none'}", code=2)
        custom.remove(forget)
        if not custom:
            settings["custom_models"].pop(key, None)
        if (settings.get("models") or {}).get(key) == forget:
            settings["models"].pop(key, None)
            ui.info(f"It was the selected model; {spec['display']} is back on its default ({spec.get('default_model') or 'agent default'}).")
        paths.save_settings(settings)
        ui.ok(f"Forgot the custom model {forget} for {spec['display']}.")
    if args.model:
        _choose_model(key, spec, args.model, settings)
        ui.ok(f"Model for {spec['display']} set to {args.model}")
    if any(snap["settings"].get(k) != settings.get(k) for k in keys):
        undo.record(undo.GLOBAL, f"model {args.model or ('--forget ' + str(forget))}", "settings-restore", snap)
    agents.describe(spec, settings)
    return 0


def cmd_do(args, settings) -> int:
    args.cmd = "agentic"   # `do` is an alias: error hints and examples live under the long name
    if args.agent in ("help", "list", "?"):
        return cmd_agents(args, settings)
    task = " ".join(args.task).strip()
    if not task:
        raise ui.Abort('Give me a task, e.g. cloudseed agentic "create a staging env on gcp"')
    if not settings.get("agentic") and not args.force:
        # `cs agentic "list envs" --force now`: a flag in the middle of the task is task text - "pass --force" would
        # read as if it had been ignored
        stray = [w for w in args.task if w in _AGENTIC_SWITCHES or w.split("=", 1)[0] in _AGENTIC_VALUED]
        if stray and "--" not in (_ARGV or []):
            raise ui.Abort(f"Agentic mode is off. '{stray[0]}' inside the task is read as task text, not as a cloudseed flag: "
                           'put flags before the task (cloudseed agentic --force "<task>") or use -- to mark where the task '
                           "starts. To turn agentic mode on: cloudseed enable agentic")
        raise ui.Abort("Agentic mode is off. Enable it with `cloudseed enable agentic` (or pass --force for a one-off).")
    # --agent is a one-off: the selected agent is only saved when the user just picked one at the prompt
    persist = not args.agent and not settings.get("agent") and ui.interactive()
    spec = _ensure_agent_ready(args.agent, settings, persist=persist, require_creds=True)
    run_spec = spec
    if spec.get("builtin"):
        from . import builtin_agent
        if not builtin_agent.has_api_credentials():
            run_spec, state = builtin_agent.claude_fallback()
            if state != "ready":                          # _ensure_agent_ready(require_creds) already refuses this
                raise ui.Abort(builtin_agent.no_creds_msg(state))
            ui.info("No Anthropic API key: this task runs through your Claude Code CLI (the built-in agent stays selected).")
    model = args.model or agents.selected_model(spec, settings)
    use_headliner = headliner.enabled(settings) and not args.no_headliner
    prompt = headliner.build(task, settings) if use_headliner else \
        headliner.plain(task, skills_in_prompt=bool(run_spec.get("skills_in_prompt")))
    ui.header("cloudseed · agentic")
    agents.describe(spec, settings)
    ui.kv("Headliner", "on" if use_headliner else "off")
    ui.kv("Credentials", "stripped from agent env; output redacted")
    if args.show_prompt:
        print(ui.dim(prompt))
    print()
    return agents.run(run_spec, prompt, model, interactive=args.interactive, task=task)


def _skill_short(name: str) -> str:
    return skills.short_name(name)


def _is_skill_word(word: str) -> bool:
    w = word.strip().lower()
    return w == "all" or skills.is_skill_name(w)


def _skill_names(names: list[str] | None) -> list[str] | None:
    """Skill names from the command line - short ('aws', 'destroy', 'vmware') or full ('cloudseed-aws') - resolved to
    the bundled directory names; None = all. Every name is checked before anything is copied (unknown: rc 2)."""
    if not names or any(str(n).strip().lower() == "all" for n in names):
        return None
    return [p.name for p in skills.resolve_names(names)] or None


def _skill_target(agent_key: str | None, custom: str | None, project: bool) -> Path:
    """Where skills are installed: --dir, else the agent's skills dir (./.<agent>/skills with --project). The built-in
    agent reads them straight from cloudseed, so its installs go to Claude Code, the agent it falls back to."""
    return skills.resolve_target(agent_key or "claude", custom, project)[1]


def _install_skills(names: list[str] | None, dest: Path) -> dict:
    """Install skills; returns {target dir: backup of what it replaced (None = it was new)} for the undo entry."""
    backups: dict = {}
    for t in skills.install(names, dest, backups=backups):
        ui.ok(f"installed skill {t.name} -> {t}")
    return backups


def cmd_skill(args, settings) -> int:
    if args.skill_cmd == "list":
        avail = skills.available()
        width = max([len(p.name) for p in avail] + [20])
        room = max(12, ui.width() - 4 - width)         # the description fills the rest of the line, cut at a word
        for p in avail:
            desc = skills.frontmatter(p).get("description", "")
            print(f"  {p.name:<{width}}  {ui.dim(ui.clip(desc, room))}")
        for key, spec in agents.registry().items():
            if spec.get("builtin"):
                ui.kv(f"{key} skills", "read from the repo at run time (core skill + the ones a task needs; the rest on demand)")
                continue
            # one wording with `cs install list`: installed / outdated / not installed with the command that fixes it,
            # 'installed, except <skill> (... left alone)', or 'sent in each task's prompt' (Grok)
            ui.kv(f"{key} skills", skills.state_text(key))
        print(ui.dim("  short names work too: cs skill show aws · cs skill install aws destroy --agent codex"))
        return 0
    if args.skill_cmd == "install":
        names = _skill_names(args.names)
        dest = _skill_target(args.agent or settings.get("agent") or "claude", args.dir, args.project)
        backups = _install_skills(names, dest)
        if backups:
            undo.record(undo.GLOBAL, f"skill install -> {dest}", "restore-files", {"files": backups})
        return 0
    if args.skill_cmd == "show":
        if str(args.name).strip().lower() == "all":   # show prints one skill; `all` is only a word for install
            raise ui.Abort("`skill show` prints one skill: " + ", ".join(skills.short_names()) +
                           "   (cs skill list describes them all)", code=2)
        names = _skill_names([args.name])             # unknown names and paths ('../x') abort with the list
        if not names:
            raise ui.Abort("Which skill? e.g. cs skill show aws   (cs skill list shows them all)", code=2)
        print((skills.SKILLS_SRC / names[0] / "SKILL.md").read_text())
        return 0
    return 1


def cmd_help(args, settings) -> int:
    # every topic and cloud is lower case: `cs help SETUP` is `cs help setup` (explain matches any case too)
    args.topic = args.topic.lower() if args.topic else args.topic
    args.cloud = args.cloud.lower() if args.cloud else args.cloud
    if not helpmod.has_page(args.topic, args.cloud):
        ui.eprint(helpmod.page(args.topic, args.cloud))   # "No help for 'x'. Did you mean ...?" (plain when redirected)
        return 2
    helpmod.print_page(args.topic, args.cloud)
    return 0


# `cloudseed install` groups. `all` = every core tool plus the Kubernetes CLIs the platform, DR and kubectl features
# need, the VMware provider and the skills; databricks, snow, k9s and vmrun are installed on request only.
INSTALL_GROUPS = {
    "all": ["terraform", "aws", "gcloud", "az", "kubectl", "helm", "go", "qemu-img", "openvpn", "tailscale", "vmware-provider", "skills"],
    "cloud": ["terraform", "aws", "gcloud", "az"],
    "tools": ["terraform", "aws", "gcloud", "az"],
    "deps": ["terraform", "aws", "gcloud", "az"],
    "vmware": ["terraform", "go", "qemu-img", "vmware-provider"],
    "vpn": ["openvpn", "tailscale"],
    "kubernetes": ["kubectl", "helm"], "k8s": ["kubectl", "helm"],
    "aws-deps": ["terraform", "aws"], "gcp-deps": ["terraform", "gcloud"], "azure-deps": ["terraform", "az"],
}
_VMRUN_WORDS = ("vmrun", "vmware-fusion", "fusion", "workstation", "vmware-desktop")
# names people use for a tool whose installer is called differently (`install aws` is already the AWS CLI)
_INSTALL_ALIASES = {"azure": "az", "azure-cli": "az", "gcp": "gcloud", "google": "gcloud", "google-cloud-sdk": "gcloud",
                    "snowflake": "snow", "snowflake-cli": "snow", "awscli": "aws", "aws-cli": "aws", "kube": "kubectl"}


def _install_plan(words: list[str]) -> list[tuple[str, object]]:
    """The words of `cloudseed install` as concrete targets, all validated before anything is installed. Words right
    after skill/skills that name a skill ('aws', 'vmware', 'finops', 'all', 'cloudseed-x') are skill names, not tools
    or groups: `install skills vmware` installs the vmware skill, not the VMware toolchain."""
    agent_keys = list(agents.registry())
    plan: list[tuple[str, object]] = []
    unknown: list[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        if w in ("skill", "skills"):
            names = []
            i += 1
            while i < len(words) and _is_skill_word(words[i]):
                names.append(words[i])
                i += 1
            plan.append(("skills", tuple(_skill_names(names) or ())))
            continue
        if w == "agent":
            if i + 1 >= len(words):
                raise ui.Abort("Which agent? e.g. cloudseed install agent codex   (agents: " + ", ".join(agent_keys) + ")", code=2)
            agents.get(words[i + 1])
            plan.append(("agent", words[i + 1]))
            i += 2
            continue
        w = _INSTALL_ALIASES.get(w, w)
        for t in INSTALL_GROUPS.get(w, [w]):
            if t == "skills":
                plan.append(("skills", ()))
            elif t in agent_keys:
                plan.append(("agent", t))
            elif t in ("image", "bundle"):
                plan.append((t, None))
            elif t in _VMRUN_WORDS:
                plan.append(("vmrun", None))
            elif t in ("vmware-provider", "vmdesktop"):
                plan.append(("provider", None))
            elif t in deps.INSTALLERS:
                plan.append(("tool", t))
            else:
                unknown.append(w)
        i += 1
    if unknown:
        import difflib
        pool = list(dict.fromkeys(list(deps.INSTALLERS) + list(INSTALL_GROUPS) + agent_keys + list(_VMRUN_WORDS) + list(_INSTALL_ALIASES)
                                  + ["vmware-provider", "vmdesktop", "skills", "agent", "image", "bundle"]))
        near = list(dict.fromkeys(m for u in dict.fromkeys(unknown) for m in difflib.get_close_matches(u, pool, n=1, cutoff=0.6)))
        raise ui.Abort(f"Don't know how to install {', '.join(repr(u) for u in dict.fromkeys(unknown))}"
                       + (f" - did you mean {', '.join(near)}?" if near else ".") + " Nothing was installed. See: cloudseed install list")
    return list(dict.fromkeys(plan))


def cmd_install(args, settings) -> int:
    """cloudseed install <what...>: one front door for every installable thing."""
    what = [w.lower() for w in args.what]
    if not what or what == ["help"]:
        helpmod.print_page("install", None)
        return 0
    if what == ["list"]:
        return _install_list(settings)
    plan = _install_plan(what)
    done = 0
    failed: list[str] = []
    before_bin = undo.listing(paths.BIN_DIR)
    files: dict = {}
    changed: list[str] = []
    notes: list[str] = []
    try:
        for kind, target in plan:
            if kind == "skills":
                dest = _skill_target(args.agent or settings.get("agent") or "claude", args.dir, args.project)
                _keep_first_backups(files, _install_skills(list(target) or None, dest))
                done += 1
            elif kind == "agent":
                spec = agents.get(target)
                if spec.get("builtin"):
                    from . import builtin_agent
                    builtin_agent.ensure_sdk()
                had_cli = bool(agents.installed(spec))
                skills_dest = Path(spec["skills_dir"]).expanduser() if spec.get("skills_dir") and not skills.installed(target) else None
                # skill dirs the install may replace are backed up first, so the undo puts them back instead of deleting them
                # (symlinked skills are never replaced by skills.install, so they need no copy)
                skill_backups = {str(skills_dest / p.name): undo.backup_file(skills_dest / p.name) for p in skills.available()
                                 if not (skills_dest / p.name).is_symlink()} if skills_dest else {}
                try:
                    # installing selects the agent only when none is selected yet (`cloudseed use` switches)
                    _ensure_agent_ready(target, settings, explicit_install=True, persist=not settings.get("agent"))
                except BaseException:
                    undo._discard_backups({"data": {"files": skill_backups}})
                    raise
                _keep_first_backups(files, {p: b for p, b in skill_backups.items() if Path(p).exists()})
                hint = spec.get("install_hint") or ""
                if not had_cli and agents.installed(spec) and hint.startswith(("npm ", "pip ", "brew ")):
                    notes.append(f"{spec.get('display', target)} was installed system-wide: remove it with `{hint.replace(' install ', ' uninstall ', 1)}`")
                ui.ok(f"agent {target} ready (CLI + skills)")
                done += 1
            elif kind == "image":
                engine = container.choose_engine(settings, explicit=args.engine)
                if args.rebuild or not container.image_exists(engine):
                    container.build_image(engine)
                    notes.append(f"container image {container.IMAGE} built: remove it with `{engine} rmi {container.IMAGE}`")
                else:
                    ui.ok(f"image {container.IMAGE} already exists")
                settings["engine"] = engine
                paths.save_settings(settings)
                done += 1
            elif kind == "bundle":
                script = paths.REPO_ROOT / "scripts" / "build-bundle.sh"
                if not script.exists():
                    raise ui.Abort("Bundle builder needs a source checkout.")
                if subprocess.call(["bash", str(script)]) != 0:
                    raise ui.Abort("Bundle build failed.")
                done += 1
            elif kind == "vmrun":
                from . import localvm
                if not localvm.install_hypervisor(args.from_path):
                    raise ui.Abort("VMware Desktop is not installed yet.")
                done += 1
            elif kind == "provider":
                from . import localvm
                before_prov = undo.listing(localvm.PROVIDERS_DIR)
                rc_existed = localvm.TERRAFORM_RC.exists()
                localvm.ensure_provider(rebuild=args.rebuild, announce=True)   # say so when it is already built
                _keep_first_backups(files, {p: None for p in undo.new_files_since(localvm.PROVIDERS_DIR, before_prov)})
                if not rc_existed and localvm.TERRAFORM_RC.exists():
                    _keep_first_backups(files, {str(localvm.TERRAFORM_RC): None})
                done += 1
            elif kind == "tool":
                missing = not deps.find(target)
                if _install_tool(target, files):
                    done += 1
                    if missing and deps.find(target):
                        changed.append(target)
                else:
                    failed.append(target)
                    if (kind, target) != plan[-1]:
                        ui.warn(f"Could not install {target}; continuing with the rest.")
    finally:   # also when a later target fails: what was installed so far stays undoable
        _record_installed(f"install {' '.join(what)}", before_bin, files, changed, notes)
    if failed:   # one line naming every target that did not install (the rest did): the command failed
        raise ui.Abort(f"Failed to install: {', '.join(failed)}" + (f"  ({done} other target(s) installed)" if done else ""))
    return 0


def _keep_first_backups(files: dict, new: dict) -> None:
    """Add {path: backup} pairs to an install's undo map. A path that an earlier step of the same command already
    recorded keeps that earlier state (the undo must go back to before the whole command); the later copy is dropped."""
    for p, b in new.items():
        if p in files:
            if b and b != files[p]:
                undo._discard_backups({"data": {"files": {p: b}}})
        else:
            files[p] = b


def _record_installed(summary: str, before_bin: set, files: dict | None = None, changed: list[str] | None = None,
                      notes: list[str] | None = None) -> None:
    """One undo entry for an install: files it created are deleted, files it replaced (skills) are put back. Tools
    that went through Homebrew / the OS only get advice. When nothing changed there is no entry: no-ops must not push
    real, undoable entries out of the history (at most five of one kind)."""
    restore = {p: None for p in undo.new_files_since(paths.BIN_DIR, before_bin)}
    restore.update(files or {})
    advice = []
    outside = [t for t in changed or [] if not any(Path(p).name.startswith(t) for p in restore)]
    if outside:
        pkgs = " ".join((deps.TOOLS.get(t, {}).get("brew") or t).replace("--cask ", "").split("/")[-1] for t in outside)
        advice.append(f"{', '.join(outside)} went into Homebrew / OS packages; remove by hand if needed (brew uninstall {pkgs})")
    advice += list(notes or [])
    if restore:
        undo.record(undo.GLOBAL, summary, "restore-files", {"files": restore})
        for a in advice:
            ui.info("Not undoable automatically: " + a)
    elif advice:
        undo.record(undo.GLOBAL, summary, "info", {"advice": "; ".join(advice)})


_ARGV: list[str] = []          # the argv being parsed; errors must not read sys.argv (undo runs commands in-process)
# cloudseed's global options that take a value, with the values they accept
_GLOBAL_VALUED = {"--runtime": ("auto", "local", "container"), "--engine": ("docker", "podman")}
# commands that take <cloud> (at this position after the command) and may default to the current / only environment
_ENV_SCOPED = {"status": 1, "inventory": 1, "output": 1, "troubleshoot": 1, "plan": 1, "ssh": 1, "k8s": 2, "vpn": 2}


def _command_index(argv: list[str]) -> int:
    """Index of the command word, after leading global options (-y, --runtime X, --engine X)."""
    i = 0
    while i < len(argv) and argv[i].startswith("-") and argv[i] not in ("-h", "--help", "--version"):
        i += 2 if argv[i] in _GLOBAL_VALUED else 1
    return i


def _global_option_width(argv: list[str], i: int) -> int:
    """How many words the global option at argv[i] takes (-y/--yes: 1, --runtime X: 2, --engine=X: 1), or 0 when
    argv[i] is not a well-formed one: a missing or invalid value (`cs --runtime`, `cs --runtime bogus`) is left to
    the parser, which reports it as a usage error instead of showing the overview."""
    tok = argv[i]
    if tok in ("-y", "--yes"):
        return 1
    name, eq, value = tok.partition("=")
    choices = _GLOBAL_VALUED.get(name)
    if choices is None:
        return 0
    if eq:
        return 1 if value in choices else 0
    return 2 if i + 1 < len(argv) and argv[i + 1] in choices else 0


def _skip_global_options(argv: list[str], start: int = 0) -> int:
    """Index of the first word at or after `start` that is not a well-formed global option."""
    i = start
    while i < len(argv):
        width = _global_option_width(argv, i)
        if not width:
            break
        i += width
    return i


def _only_global_flags(argv: list[str]) -> bool:
    """`cs -y`, `cs --runtime local`: global options and nothing else (the overview, like a bare `cs`)."""
    return bool(argv) and _skip_global_options(argv) >= len(argv)


# options of the env-scoped commands that take a value (the value is never the cloud)
_ENV_SCOPED_VALUED = ("-e", "--env", "--user", "--last")
# env-scoped commands whose only positional is the cloud: a bare word there is a typo, never "use the default"
_CLOUD_ONLY = ("status", "inventory", "output", "troubleshoot", "plan", "k8s")
_ENV_HINT = {"quiet": False}       # the second parse of `cs ssh ... -- cmd` must not repeat the hint


def _env_name_problem(env_name: str, envs: list, what: str) -> str | None:
    """Why --env NAME (a name, or an id as `cs list` shows it) picks no single environment, or None."""
    problem = _validate_name(env_name)
    if problem:
        return f"Invalid environment name '{env_name}': {problem}"
    same = [e for e in envs if env_name in (e.name, e.id)]
    if len(same) == 1:
        return None
    if not same:
        return f"No environment named '{env_name}'. Known: {', '.join(e.id for e in envs) or 'none (create one: cloudseed setup <cloud>)'}"
    return (f"Several environments are named '{env_name}' ({', '.join(e.id for e in same)}): name the cloud too, "
            f"e.g. cs {what} {same[0].cloud} --env {env_name}")


def _ssh_option_width(tok: str) -> int:
    """How many words an ssh option takes: 2 when its value is the next word (-L 8080:h:80, -o X=y, -vp 2222), 1 when
    it has none or carries it attached (-p2222). See _SSH_VALUE_OPTS."""
    if tok.startswith("--") or len(tok) < 2:
        return 1
    for k, ch in enumerate(tok[1:], 1):
        if ch in _SSH_VALUE_OPTS:
            return 2 if k == len(tok) - 1 else 1
    return 1


def _default_env_argv(argv: list[str]) -> list[str]:
    """`cs status`, `cs ssh`, `cs inventory`, `cs k8s info`, `cs vpn add-user bob` ... without a cloud act on the current
    environment (`cs env use`) or on the only one that exists - the way the cluster commands already resolve it. An
    environment id in the cloud's place (`cs status aws-f1`, as `cs list` shows it) means that environment. An --env
    that matches no environment, or several, is refused with the list; anything else ambiguous is left to the parser,
    which then asks for the cloud."""
    i = _command_index(argv)
    if i >= len(argv) or argv[i] not in _ENV_SCOPED:
        return argv
    cmd = argv[i]
    p = i + _ENV_SCOPED[cmd]
    if _ENV_SCOPED[cmd] == 2 and (i + 1 >= len(argv) or argv[i + 1].startswith("-")):
        return argv                            # k8s / vpn without their subcommand: a normal usage error
    what = cmd if _ENV_SCOPED[cmd] == 1 else f"{cmd} {argv[i + 1]}"
    head = argv[: argv.index("--")] if "--" in argv else argv
    if any(t in ("-h", "--help") for t in head[i + 1:]):
        return argv                            # help is always help (ssh's own -h does not exist)
    # the first word in the cloud's place, skipping options (and their values) wherever they sit: `--env dev aws` has
    # its cloud, and must not get a second one
    j, env_name, env_at, ssh_opt = p, None, None, False
    while j < len(head):
        width = _global_option_width(head, j)
        if width:
            j += width
            continue
        tok = head[j]
        if tok in ("-e", "--env") and j + 1 < len(head):
            env_name, env_at = head[j + 1], j + 1
            j += 2
        elif tok in _ENV_SCOPED_VALUED:
            j += 2
        elif tok.startswith("--env="):
            env_name, env_at = tok.split("=", 1)[1], None
            j += 1
        elif tok.startswith("-"):
            ssh_opt = ssh_opt or (cmd == "ssh" and not tok.startswith("--"))
            j += _ssh_option_width(tok) if cmd == "ssh" else 1     # ssh's -L 8080:h:80 / -o X=y keep their value
        else:
            break
    word = head[j] if j < len(head) else None
    if ssh_opt and word is not None:
        # ssh options typed before the cloud or environment id (`cs ssh -L 8080:h:80 aws-f1`): the cloud goes first,
        # where the parser takes it; otherwise the id would become the remote command
        try:
            ids = {e.id for e in paths.Env.list_all()}
        except Exception:  # noqa: BLE001 - a broken env dir must not break argument parsing
            ids = set()
        if word in CLOUD_KEYS or word in ids:
            out = list(argv)
            out.insert(p, out.pop(j))
            return _default_env_argv(out)
    if word in CLOUD_KEYS or word == "mcp":
        return argv
    try:
        envs = paths.Env.list_all()
        current = paths.load_settings().get("current_env")
    except Exception:  # noqa: BLE001 - a broken env dir must not break argument parsing; the parser asks for the cloud
        return argv
    by_id = next((e for e in envs if e.id == word), None) if word else None
    # an --env after that word is the command's too (`vpn add-user bob --env prod`, `status aws-f1 --env prod`). For ssh
    # only right after an id in the cloud's place: any other word starts the remote command (`cs ssh uptime --env x`)
    k = j + 1
    while env_name is None and k < len(head) and \
            (cmd != "ssh" or (by_id is not None and head[k].startswith("-") and head[k] != "-")):
        tok = head[k]
        if tok in ("-e", "--env") and k + 1 < len(head):
            env_name, env_at = head[k + 1], k + 1
        elif tok.startswith("--env="):
            env_name, env_at = tok.split("=", 1)[1], None
        k += 2 if tok in _ENV_SCOPED_VALUED else 1

    def hint(text: str) -> None:
        if not _ENV_HINT["quiet"]:
            ui.eprint(ui.dim(f"  ({cmd}: {text})"))

    def refuse(msg: str) -> None:
        ui.err(msg)                            # printed here: an agent's parser reads the ✖ line from stderr
        raise SystemExit(2)

    if by_id is not None:
        if env_name and env_name not in (by_id.name, by_id.id):
            refuse(f"{word} and --env {env_name} name different environments; give one of them.")
        hint(by_id.id)
        out = list(argv)
        out[j:j + 1] = [by_id.cloud] + ([] if env_name else ["--env", by_id.name])
        return out
    if word is not None and cmd in _CLOUD_ONLY:
        return argv                            # `cs status foo`: the parser names 'foo' (no silent default env)
    if env_name is not None:
        problem = _env_name_problem(env_name, envs, what)
        if problem:
            refuse(problem)
        e = next(e for e in envs if env_name in (e.name, e.id))
        hint(e.id)
        out = list(argv)
        if env_at is not None and env_name != e.name:     # an id given as --env: the parser wants the name
            out[env_at] = e.name
        elif env_at is None and env_name != e.name:
            out = [f"--env={e.name}" if t == f"--env={env_name}" else t for t in out]
        return out[:p] + [e.cloud] + out[p:]
    cands, why = [e for e in envs if e.id == current], "the current environment"
    if not cands and len(envs) == 1:
        cands, why = envs, "the only environment"
    if len(cands) != 1:
        return argv
    e = cands[0]
    hint(f"{e.id}, {why}")
    return argv[:p] + [e.cloud, "--env", e.name] + argv[p:]


class _Parser(argparse.ArgumentParser):
    """argparse parser whose errors show examples for the command being typed."""

    def _check_value(self, action, value):
        # remember what the failing argument accepts, so "did you mean" offers real choices only
        if action.choices is not None and value not in action.choices:
            self._cs_bad_choices = [str(c) for c in action.choices]
            self._cs_bad_command = isinstance(action, argparse._SubParsersAction)
        return super()._check_value(action, value)

    def parse_known_args(self, args=None, namespace=None):
        if self.prog == "cloudseed" and args is not None:     # the top-level parser: once per command line
            global _ARGV
            args = list(args)
            _ARGV = args
            if _only_global_flags(args):                      # `cs -y` alone: the same overview as a bare `cs`
                helpmod.print_page(None, None)
                raise SystemExit(0)
            args = _default_env_argv(args)
        # Python < 3.12.7 (gh-59317) matches a trailing optional positional (nargs "?" or "*") as empty when an option
        # comes first, so `vpn add-user aws --env dev alice` / `node add --count 2 vmware --env dev` /
        # `chaos run --env dev basic` report "unrecognized arguments". Hand such leftover bare tokens to the still-empty
        # optional positionals, in order, as newer Pythons do ("?" takes one token, "*" takes the rest).
        ns, extras = super().parse_known_args(args, namespace)

        def empty(a) -> bool:
            v = getattr(ns, a.dest, None)
            return v == a.default or (a.nargs == argparse.ZERO_OR_MORE and v in (None, []))

        free = [a for a in self._actions if not a.option_strings and a.nargs in (argparse.OPTIONAL, argparse.ZERO_OR_MORE) and empty(a)]
        bare = [t for t in extras if not t.startswith("-")]
        if free and bare:
            taken: list[str] = []
            for action in free:
                if len(taken) == len(bare):
                    break
                toks = bare[len(taken):len(taken) + 1] if action.nargs == argparse.OPTIONAL else bare[len(taken):]
                try:
                    setattr(ns, action.dest, self._get_values(action, toks))
                except argparse.ArgumentError as e:
                    self.error(str(e))
                taken += toks
            rest = list(extras)
            for t in taken:
                rest.remove(t)
            extras = rest
        return ns, extras

    def _leaf_parser(self, cmd: str, argv: list[str]) -> argparse.ArgumentParser:
        """The (sub-)subparser the user was typing into, for a usage line that shows its own options."""
        parser: argparse.ArgumentParser = self
        rest = argv[_command_index(argv):]
        for _ in range(3):
            act = next((a for a in parser._actions if isinstance(a, argparse._SubParsersAction)), None)
            word = next((w for w in rest if act is not None and w in act.choices), None)
            if act is None or word is None:
                break
            parser = act.choices[word]
            rest = rest[rest.index(word) + 1:]
        return parser

    def _unknown_option_before(self, argv: list[str], bad: str) -> str | None:
        """The option this parser does not know that directly precedes `bad` in argv (before any `--`), if any: a known
        option, an accepted abbreviation, a negative number and --opt=value never count."""
        cut = argv.index("--") if "--" in argv else len(argv)
        for k in range(1, cut):
            tok = argv[k - 1]
            if argv[k] != bad or not tok.startswith("-") or tok in ("-", "--") or "=" in tok:
                continue
            if self._negative_number_matcher.match(tok):
                continue
            try:
                known = tok in self._option_string_actions or bool(self._get_option_tuples(tok))
            except Exception:  # noqa: BLE001 - argparse internals differ between versions: assume it is known
                known = True
            if not known:
                return tok
        return None

    def error(self, message):
        argv = _ARGV or sys.argv[1:]
        parts = self.prog.split()
        cmd = parts[1] if len(parts) > 1 else None
        if cmd is None:  # top-level parser reports unrecognized args; recover the command from the argv being parsed
            i = _command_index(argv)
            cmd = argv[i] if i < len(argv) and argv[i] in HANDLERS else next((a for a in argv if a in HANDLERS), None)
        if cmd == "do":
            cmd = "agentic"                    # help pages and examples live under the long name
        bad = None
        near_override = None   # ready-made suggestions (whole corrected command lines) instead of fuzzy word matches
        usage = self
        mm = re.match(r"argument (\w+): invalid choice: '([^']+)'", message)
        if mm:
            # `finops cloud --dayz 7`: argparse hands the value of the mistyped option to the optional positional, which
            # then fails first - report the unknown option instead (its 'did you mean --days' follows below)
            # (not for the command word itself: `cs --env w1 status` gets the whole corrected line from _unknown_command)
            top_command = self.prog == "cloudseed" and getattr(self, "_cs_bad_command", False)
            opt = None if top_command else self._unknown_option_before(argv, mm.group(2))
            if opt:
                message = f"unrecognized arguments: {opt} {mm.group(2)}"
            elif mm.group(1) == "cloud":
                key, sep, name = mm.group(2).partition("-")
                try:
                    is_id = bool(sep and key in CLOUD_KEYS and name and paths.Env(key, name).exists())
                except Exception:  # noqa: BLE001 - an odd name must not break the error message
                    is_id = False
                if is_id:      # `cs destroy aws-f1`: the id as `cs list` shows it
                    message = (f"'{mm.group(2)}' is an environment id, not a cloud: cloudseed {cmd or '<command>'} "
                               f"{key} --env {name}")
        m = re.search(r"invalid choice: '([^']+)'", message)
        if m:
            bad = m.group(1)
            bad_command = getattr(self, "_cs_bad_command", None)   # None: _check_value did not see the failing value
            if bad_command and self.prog == "cloudseed":
                cmd = None  # the command word itself is the typo: never show another command's examples
            if cmd is None and bad_command is not False:   # not for `cs --runtime bogus`: that is a bad option value
                message, near_override = _unknown_command(argv, bad, set(self._option_string_actions))
            elif getattr(self, "_cs_bad_choices", None) is None:
                # a bad value for one argument: suggest among ITS choices only. Normally _check_value recorded them
                # and helpmod.parser_suggestions offers them below; this reads them back from the message otherwise.
                import difflib
                cm = re.search(r"\(choose from (.+)\)", message)
                choices = [c.strip(" '\"") for c in cm.group(1).split(",")] if cm else []
                near = difflib.get_close_matches(bad, choices, n=3, cutoff=0.6)
                if near:
                    message += f"  - did you mean {', '.join(near)}?"
                bad = None
        if re.search(r"argument (--agent|agent): invalid choice", message):
            ui.eprint(agents.agents_page(paths.load_settings()))   # eprint: no ANSI codes when stderr is redirected
            raise SystemExit(2)
        m = re.search(r"the following arguments are required: (.+)", message)
        if m:
            names = [n.strip() for n in m.group(1).split(",")]
            if names == ["command"]:
                opt = next((a for a in argv if a.startswith("-") and a.split("=", 1)[0] not in self._option_string_actions), None)
                message = _unknown_option(self, opt) if opt else "which command? (cloudseed help lists them)"
            else:
                wants = []
                for n in names:
                    act = next((a for a in self._actions if a.dest == n), None)
                    if n == "cloud":           # only env-scoped commands fall back to `cs env use` (setup/destroy never do)
                        wants.append("a cloud: " + ", ".join(CLOUD_KEYS[:-1]) + " or " + CLOUD_KEYS[-1] +
                                     ("  (or set a default environment: cloudseed env use <id>)" if cmd in _ENV_SCOPED else ""))
                    elif act is not None and act.choices:
                        wants.append("a subcommand: " + " | ".join(act.choices))
                    else:
                        wants.append(f"<{n}>" + (f" ({act.help})" if act is not None and act.help else ""))
                message = f"`cloudseed {cmd}` needs " + " and ".join(wants)
        if os.environ.get("CLOUDSEED_UNDOING"):    # an undo's inverse command: the undo prints its own hint
            ui.err(f"`cloudseed {' '.join(argv)}`: {message}")
            raise SystemExit(2)
        if message.startswith("unrecognized arguments") and cmd and self.prog == "cloudseed":
            usage = self._leaf_parser(cmd, argv)
        near = near_override if near_override is not None else helpmod.parser_suggestions(self, cmd, message, bad)
        m = re.match(r"unrecognized arguments: (.*)", message)
        if m and near:
            # never "did you mean --project?" for the very option just refused: it is another subcommand's option
            rejected = {t.split("=", 1)[0] for t in m.group(1).split() if t.startswith("-")}
            homes = {o: self._option_homes(cmd, o) for o in sorted(rejected & set(near))}
            near = [n for n in near if n not in rejected]
            message += "".join(f"; {o} belongs to {' / '.join(h)}" for o, h in homes.items() if h)
        usage.print_usage(sys.stderr)
        # whole corrected command lines (near_override) are shown as they are: no help-topic pointer for the word
        ui.eprint(helpmod.error_hint(cmd, message, None if near_override is not None else bad, near=near))
        raise SystemExit(2)

    def _option_homes(self, cmd: str | None, opt: str) -> list[str]:
        """The subcommands of `cmd` that accept `opt` (`cloudseed skill install` for --project)."""
        top = next((a for a in self._actions if isinstance(a, argparse._SubParsersAction)), None)
        cp = top.choices.get(cmd) if top is not None and cmd else None
        out: list[str] = []
        for a in (cp._actions if cp is not None else []):
            if isinstance(a, argparse._SubParsersAction):
                out += [f"cloudseed {cmd} {name}" for name, sp in a.choices.items() if opt in sp._option_string_actions]
        return list(dict.fromkeys(out))


# ---------------------------------------------------------------- parser

# words people type for a command cloudseed calls differently (suggestions only: nothing is ever run under an alias)
_COMMAND_SYNONYMS = {"delete": "destroy", "remove": "destroy", "rm": "destroy", "teardown": "destroy", "tear-down": "destroy",
                     "down": "destroy", "create": "setup", "init": "setup", "new": "setup", "deploy": "setup", "up": "setup",
                     "bootstrap": "setup", "ls": "list", "version": "--version", "logs": "troubleshoot", "log": "troubleshoot"}
_CLOUD_WORDS = {"aws": "aws", "amazon": "aws", "gcp": "gcp", "gcloud": "gcp", "google": "gcp", "azure": "azure",
                "az": "azure", "vmware": "vmware", "fusion": "vmware"}


def _command_line_words(words: list[str]) -> tuple[list[str], list[str]]:
    """Split the words after a command into what a cloudseed command line takes (a cloud - `gcloud` means gcp -,
    `mcp`, options and their values) and the rest: words of a sentence (`cs deploy the aws stack`)."""
    kept: list[str] = []
    other: list[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        if w.startswith("-"):
            kept.append(w)
            if "=" not in w and i + 1 < len(words) and not words[i + 1].startswith("-") \
                    and words[i + 1].lower() not in _CLOUD_WORDS:
                kept.append(words[i + 1])    # the option's value (`--env dev`)
                i += 1
        elif w.lower() in _CLOUD_WORDS:
            kept.append(_CLOUD_WORDS[w.lower()])
        elif w == "mcp":
            kept.append(w)
        else:
            other.append(w)
        i += 1
    return kept, other


def _agentic_hint(argv: list[str]) -> str:
    """How to hand a sentence typed as a command to the agent."""
    sentence = " ".join(a for a in argv if not a.startswith("-"))
    if paths.load_settings().get("agentic"):
        return f'. To hand this sentence to the agent:  cloudseed agentic "{sentence}"'
    return f'. Natural-language tasks need agentic mode:  cloudseed enable agentic, then  cloudseed agentic "{sentence}"'


def _unknown_command(argv: list[str], bad: str, known_options: set) -> tuple[str, list[str] | None]:
    """The error for an unknown command word and what to type instead: whole corrected command lines for the common
    mistakes (the cloud first, another tool's verb, an option before the command, a help topic, CAPS), or None to let
    the parser's fuzzy match suggest a command. A sentence (2+ words that are not all a command line's words) also
    gets the agentic-mode hint."""
    msg = f"unknown command '{bad}'"
    i = argv.index(bad) if bad in argv else _command_index(argv)
    lead, rest = argv[:i], argv[i + 1:]       # lead: the global options typed before the command (-y, --runtime X)
    low = bad.lower()
    later = next((w for w in rest if w in HANDLERS), None)

    def line(words: list[str]) -> str:
        return " ".join(["cloudseed"] + words)

    def without_first(words: list[str], word: str) -> list[str]:
        out = list(words)
        out.remove(word)
        return out

    prev = argv[i - 1] if i > 0 else ""
    if prev.startswith("-") and prev.split("=", 1)[0] not in known_options:
        # `cs --env w1 status`: the option took the command's place (its value was read as the command)
        opt = prev.split("=", 1)[0]
        if later:
            return msg + f": options like {opt} go after the command", [line([later] + without_first(argv, later))]
        return msg + f": '{bad}' is the value of {opt}, and options like {opt} go after a command (cloudseed <command> {opt} {bad})", []
    if low in _CLOUD_WORDS:                   # `cs aws setup`, `cs gcp status --env dev`, `cs aws`
        c = _CLOUD_WORDS[low]
        msg += ": the command comes first, then the cloud"
        if later:
            kept, other = _command_line_words(without_first(rest, later))
            return msg + (_agentic_hint(argv) if other else ""), [line(lead + [later, c] + [w for w in kept if w != c])]
        return msg, [line(lead + ["setup", c]), line(lead + ["status", c]), line(lead + ["help", c])]
    if low in _COMMAND_SYNONYMS or (low == "uninstall" and rest[:1] and (rest[0] in CLOUD_KEYS or rest[0] == "mcp")):
        target = _COMMAND_SYNONYMS.get(low, "destroy")
        if target == "--version":
            return msg, [line(["--version"])]
        # `cs delete aws --env dev` becomes `cloudseed destroy aws --env dev`; the words of a sentence (`cs deploy the
        # aws stack`) are not a command line: suggest the command with its cloud, and hand the sentence to the agent
        kept, other = _command_line_words(rest)
        hint = _agentic_hint(argv) if other else ""
        if target == "troubleshoot":
            return msg + hint, [line(lead + ["troubleshoot"] + kept + ["--log"])]
        return msg + hint, [line(lead + [target] + kept)]
    if low in HANDLERS:                        # `cs SETUP aws`: commands are lower case
        return msg + " (commands are lower case)", [line(lead + [low] + rest)]
    if low in helpmod.help_topics():           # `cs quickstart`, `cs fips`, `cs variables aws`: a help page, not a command
        cloud = next((_CLOUD_WORDS[w.lower()] for w in rest if w.lower() in _CLOUD_WORDS), None)
        if low in ("variables", "outputs") and cloud:
            return msg + f": '{low}' is a help topic", [line(["help", low, cloud])]
        # error_hint names the page (`help topic cloudseed help quickstart`) and keeps a command one letter off
        # (`cs envs`: env) as its did-you-mean
        return msg + f": '{low}' is a help topic", None
    if len([a for a in argv if not a.startswith("-")]) >= 2:   # a sentence: maybe a task for the agent
        msg += _agentic_hint(argv)
    return msg, None


def _unknown_option(parser: argparse.ArgumentParser, opt: str) -> str:
    """The error for an option given without a command: a command's own option in front of it, or a typo."""
    import difflib
    name = opt.split("=", 1)[0]
    own = set(parser._option_string_actions)
    if name not in own and name in helpmod._option_strings(parser):
        return f"unknown option '{opt}' here: {name} belongs to a command and goes after it (cloudseed <command> ... {name} ...)"
    near = difflib.get_close_matches(name, sorted(own), n=1, cutoff=0.6)
    return f"unknown option '{opt}'" + (f" - did you mean {near[0]}?" if near else "")


def _install_list(settings) -> int:
    from . import localvm
    ui.header("Installable targets  (cloudseed install <name...> | all | cloud | vmware | vpn | kubernetes)")
    when = {deps.GKE_AUTH_PLUGIN: "installed with gcloud, or on its own"}
    rows = [(r["tool"], r["path"], r["desc"]) for r in deps.status(None)]
    # the scanners are not environment dependencies (doctor does not list them): `cs scan` installs them on first use
    rows += [("kubescape", deps.find("kubescape"), "Kubernetes security scanner (cs scan kube)"),
             ("trivy", deps.find("trivy"), "image vulnerability scanner (cs scan images)")]
    for tool in ("kubescape", "trivy"):
        when[tool] = "installed when named, or by cs scan on first use"
    for tool, found, desc in rows:
        mark = ui.style("✔", "leaf", "bold") if found else ui.style("○", "muted")
        print(f"  {mark} {ui.style(tool.ljust(22), 'text')} {ui.dim(desc + (f' - {when[tool]}' if tool in when else ''))}")
    mark = ui.style("✔", "leaf", "bold") if localvm.provider_binary().exists() else ui.style("○", "muted")
    print(f"  {mark} {'vmware-provider':<22} cloudseed's Terraform provider for Fusion/Workstation (built with Go)")
    for key, spec in agents.registry().items():
        ok, msg = agents.readiness(dict(spec, key=key))
        mark = ui.style("✔", "leaf", "bold") if ok else ui.style("○", "muted")
        print(f"  {mark} {ui.style(key.ljust(22), 'text')} {ui.dim('agent: ' + spec.get('display', key) + ' - ' + msg)}")
    installed_any = any(skills.state(k) in ("current", "partial") for k, sp in agents.registry().items() if sp.get("skills_dir"))
    mark = ui.style("✔", "leaf", "bold") if installed_any else ui.style("○", "muted")
    names = skills.short_names()
    print(f"  {mark} {'skills':<22} agent skills ({len(names)}): {', '.join(names)}   (skills <name...> for some)")
    print(f"  {ui._c('36', '·')} {'image':<22} all-in-one container image (docker/podman)")
    print(f"  {ui._c('36', '·')} {'bundle':<22} single self-contained binary")
    print()
    # wrapped at a terminal (continuation rows under the text after "Groups: "), one line each when piped
    ui.note("Groups: all = " + " ".join(INSTALL_GROUPS["all"]) + " · cloud = terraform aws gcloud az · "
            "vmware = terraform go qemu-img vmware-provider · vpn = openvpn tailscale · kubernetes = kubectl helm",
            indent="", hang="        ")
    ui.note("databricks, snow, k9s, kubescape, trivy and vmrun are installed only when named "
            "(gke-gcloud-auth-plugin comes with gcloud).", indent="        ")
    return 0


def _take_global(words: list, ns, parser, i: int = 0) -> bool:
    """When words[i] is one of cloudseed's global options (-y/--yes, --runtime X, --engine X, or --opt=X), apply it to
    the namespace, remove it from `words` and return True."""
    tok = words[i]
    if tok in ("-y", "--yes"):
        ns.yes = True
        del words[i]
        return True
    name, eq, value = tok.partition("=")
    if name not in _GLOBAL_VALUED:
        return False
    if not eq:
        if i + 1 >= len(words):
            parser.error(f"argument {name}: expected one argument")
        value = words[i + 1]
    if value not in _GLOBAL_VALUED[name]:
        parser.error(f"argument {name}: invalid choice: '{value}' (choose from {', '.join(_GLOBAL_VALUED[name])})")
    setattr(ns, name[2:], value)
    del words[i:i + (1 if eq else 2)]
    return True


def _kube_passthrough(words: list, ns, parser) -> None:
    """cs kubectl|helm|k9s [<cloud>] [--env NAME] [--] <tool arguments>: cloudseed's own selectors and global options
    come first; everything else reaches the tool exactly as typed (`cs kubectl -n kube-system get pods`)."""
    rest = list(words)
    while rest:
        tok = rest[0]
        if _take_global(rest, ns, parser):
            continue
        if tok in CLOUD_KEYS and not ns.cloud:
            ns.cloud = rest.pop(0)
        elif tok in ("--env", "-e") and len(rest) > 1 and not ns.env:
            ns.env = rest[1]
            del rest[:2]
        elif tok.startswith("--env=") and not ns.env:
            ns.env = rest.pop(0).split("=", 1)[1]
        else:
            break
    # after an explicit `--` everything is the tool's, verbatim: cmd_ktool then takes no cloud key or --env from it
    ns.tool_verbatim = rest[:1] == ["--"]
    if ns.tool_verbatim:
        rest.pop(0)
    else:
        # a -y given after the tool arguments (agents and the console append one) is cloudseed's: kubectl, helm and
        # k9s have no -y flag. Arguments after a later `--` (kubectl exec POD -- CMD -y) are never touched.
        cut = rest.index("--") if "--" in rest else len(rest)
        head = [t for t in rest[:cut] if t not in ("-y", "--yes")]
        if len(head) != cut:
            ns.yes = True
        rest = head + rest[cut:]
    ns.tool_args = rest


def _managed_passthrough(words: list, ns, parser) -> None:
    """cs databricks|snowflake [--profile NAME] [--] <service CLI arguments>, passed through as typed."""
    rest = list(words)
    while rest:
        tok = rest[0]
        if _take_global(rest, ns, parser):
            continue
        if tok == "--profile" and len(rest) > 1:
            ns.profile = rest[1]
            del rest[:2]
        elif tok.startswith("--profile="):
            ns.profile = rest.pop(0).split("=", 1)[1]
        else:
            break
    # An explicit leading `--` stays in svc_args: cmd_managed drops it, and until then it keeps the service CLI's own
    # -e/--env away from cloudseed's --env recovery. Without it, a trailing -y is cloudseed's (agents / the console add it).
    if rest[:1] != ["--"] and rest[-1:] in (["-y"], ["--yes"]):
        ns.yes = True
        rest.pop()
    ns.svc_args = rest


def _ssh_post(ns, parser) -> None:
    """`cs ssh aws -y`, `cs ssh aws --env=dev -- uptime`: among the ssh options before `--`, cloudseed's own options are
    cloudseed's; ssh options such as -L/-p/-o (and their values) stay in place for ssh. From the remote command's first
    word on - and always after `--` - everything is the host's (`grep -e x`, `apt-get install -y`, `docker run --env`).
    `-e NAME`/`-eNAME` select the env only in the leading run right after the cloud: after an ssh option, -e is ssh's
    escape character (`cs ssh aws -N -e none`)."""
    rest = list(ns.ssh_args or [])
    i, leading = 0, True
    while i < len(rest) and rest[i] != "--":
        tok = rest[i]
        if _take_global(rest, ns, parser, i):
            continue
        # ssh has no -h: before `--` and the remote command it asks for cloudseed's help. argparse drops a `--` right
        # after the cloud, so the command line itself says whether the user put it after one (`cs ssh aws -- --help`)
        typed = _ARGV[:_ARGV.index("--")] if "--" in _ARGV else _ARGV
        if tok in ("-h", "--help") and tok in typed:
            parser.print_help()
            parser.exit()
        if tok == "--env" and i + 1 < len(rest):
            ns.env = rest[i + 1]
            del rest[i:i + 2]
            continue
        if tok.startswith("--env="):
            ns.env = rest.pop(i).split("=", 1)[1]
            continue
        if leading and tok == "-e" and i + 1 < len(rest):
            ns.env = rest[i + 1]
            del rest[i:i + 2]
            continue
        if leading and tok.startswith("-e") and len(tok) > 2:
            ns.env = rest.pop(i)[2:].lstrip("=")
            continue
        if not tok.startswith("-") or tok == "-":
            break   # the remote command starts here
        leading = False
        i += 1
        if tok.startswith("--"):   # not an ssh option; cmd_ssh explains where cloudseed's options go
            continue
        for j, ch in enumerate(tok[1:], 1):   # an ssh option's value (-F cfg, -o X=y) is ssh's, never ours
            if ch in _SSH_VALUE_OPTS:
                if j == len(tok) - 1 and i < len(rest):
                    i += 1
                break
    ns.ssh_args = rest


_AGENTIC_SWITCHES = {"--force": "force", "--show-prompt": "show_prompt", "--no-headliner": "no_headliner",
                     "--interactive": "interactive", "-i": "interactive"}
_AGENTIC_VALUED = {"--agent": "agent", "--model": "model"}


def _agentic_post(ns, parser) -> None:
    """The task is everything after the flags (argparse REMAINDER: task text may contain dashes). cloudseed's own options
    typed AFTER the task (`cs agentic "list envs" --model x --force -y`) are still cloudseed's: they are taken off the
    END of the task and applied, never silently sent to the agent as words. Only the tail: `show pods -n kube-system`
    keeps its -n, and at least one task word always stays. `--` makes everything after it literal task text;
    -h/--help at the end shows this command's help."""
    task = list(ns.task or [])
    if "--" in task:                       # explicit end of cloudseed's options: nothing after it is taken
        task.remove("--")
        ns.task = task
        return

    def take(dest: str, value: str, flag: str) -> None:
        before = getattr(ns, dest, None)
        if before not in (None, "") and before != value:
            parser.error(f"argument {flag}: given twice ({before} and {value}); give it once")
        setattr(ns, dest, value)

    while len(task) > 1:
        tok = task[-1]
        name, eq, value = tok.partition("=")
        if tok in ("-h", "--help"):
            parser.print_help()
            parser.exit()
        if tok in ("-y", "--yes"):
            ns.yes = True
            task.pop()
        elif tok in _AGENTIC_SWITCHES:
            setattr(ns, _AGENTIC_SWITCHES[tok], True)
            task.pop()
        elif eq and name in _AGENTIC_VALUED:
            take(_AGENTIC_VALUED[name], value, name)
            task.pop()
        elif eq and name in _GLOBAL_VALUED:
            _take_global(task, ns, parser, len(task) - 1)
        elif len(task) > 2 and task[-2] in _AGENTIC_VALUED:
            take(_AGENTIC_VALUED[task[-2]], tok, task[-2])
            del task[-2:]
        elif len(task) > 2 and task[-2] in _GLOBAL_VALUED:
            _take_global(task, ns, parser, len(task) - 2)
        elif tok in _AGENTIC_VALUED:
            parser.error(f"argument {tok}: expected one argument")
        else:
            break
    ns.task = task


def _one_cloud(words: list, parser) -> str | None:
    keys = list(dict.fromkeys(w for w in words if w in CLOUD_KEYS))
    if len(keys) > 1:
        parser.error(f"more than one cloud given: {' '.join(keys)} (pick one of {', '.join(CLOUD_KEYS)})")
    return keys[0] if keys else None


def _node_post(ns, parser) -> None:
    """`node remove <node-name> [cloud]` (the documented order), `node remove <cloud> <node-name>`, `node add <cloud>`:
    a word that is a cloud key selects the target, the other one is the node name. Done at parse time so the runtime
    gate in _dispatch and _touches_vms see the real cloud."""
    words = list(vars(ns).pop("targets", None) or [])
    key = _one_cloud(words, parser)
    names = [w for w in words if w not in CLOUD_KEYS]
    if key and ns.cloud and key != ns.cloud:
        parser.error(f"two different clouds given: {key} and --cloud {ns.cloud}")
    if len(names) > 1:
        parser.error(f"expected one node name, got {len(names)}: {' '.join(names)}")
    if names and ns.node_cmd != "remove":
        parser.error(f"`node {ns.node_cmd}` takes no node name, and '{names[0]}' is not a cloud ({', '.join(CLOUD_KEYS)})")
    ns.cloud = ns.cloud or key
    ns.name = names[0] if names else None


def _dr_post(ns, parser) -> None:
    """`dr backup aws --env lab`, `dr restore <backup> aws --env lab`: a cloud key selects the target (unless --cloud is
    given, then the word is taken literally as the name); the other word is the backup/schedule name."""
    words = list(vars(ns).pop("words", None) or [])
    if not ns.cloud:
        key = _one_cloud(words, parser)
        if key:
            ns.cloud = key
            words = [w for w in words if w not in CLOUD_KEYS]
    ns.kind = None
    if ns.dr_cmd in ("describe", "logs"):   # `dr describe backup <name>`, `dr logs restore <name>`
        if len(words) != 2 or words[0] not in dr.INSPECT_KINDS:
            parser.error(f"`dr {ns.dr_cmd}` takes backup or restore and its name: cs dr {ns.dr_cmd} backup|restore <name> "
                         f"[<cloud> --env NAME] (got: {' '.join(words) or 'nothing'}; a name that is a cloud key needs --cloud)")
        ns.kind, ns.name = words
        return
    if len(words) > 1:
        parser.error(f"expected at most one backup/schedule name, got: {' '.join(words)}")
    if words and ns.dr_cmd in ("status", "backups", "test"):
        parser.error(f"`dr {ns.dr_cmd}` takes no name, and '{words[0]}' is not a cloud ({', '.join(CLOUD_KEYS)})")
    ns.name = words[0] if words else None


class _CmdParser(_Parser):
    """_Parser with optional per-command hooks, set as attributes on a sub-parser:

    post_parse(ns, parser)          runs once the command's own arguments are parsed (sort free words into cloud /
                                    name, take cloudseed's global options out of catch-all arguments).
    passthrough(words, ns, parser)  the command hands its arguments to another tool (kubectl, helm, databricks ...):
                                    argparse does not interpret them, so leading flags such as `kubectl -n NS ...`
                                    reach the tool as typed; the hook only takes cloudseed's own selectors off the front.
                                    `-h`/`--help` alone still shows cloudseed's help for the command.

    Commands without a catch-all argument parse "intermixed": positionals may come after options on every Python
    version (`cs node remove --env dev NAME`, `cs vpn add-user aws --env dev alice`, `cs platform install --env dev
    keda`); Python < 3.12.7 would otherwise bind the empty optional positional first and reject the later word.
    """

    post_parse = None
    passthrough = None
    _intermixing = False

    def parse_known_args(self, args=None, namespace=None):
        if self.passthrough is not None and args is not None:
            words = list(args)
            if words in (["-h"], ["--help"]):
                self.print_help()
                self.exit()
            ns = argparse.Namespace() if namespace is None else namespace
            for action in self._actions:
                if action.dest != argparse.SUPPRESS and action.default != argparse.SUPPRESS and not hasattr(ns, action.dest):
                    setattr(ns, action.dest, action.default)
            for dest, value in self._defaults.items():
                if not hasattr(ns, dest):
                    setattr(ns, dest, value)
            self.passthrough(words, ns, self)
            return ns, []
        if self._intermixing:   # the inner passes of parse_known_intermixed_args (older Pythons call back in here)
            return super().parse_known_args(args, namespace)
        if any(a.nargs in (argparse.PARSER, argparse.REMAINDER) for a in self._get_positional_actions()):
            ns, extras = super().parse_known_args(args, namespace)
        else:
            self._intermixing = True
            try:
                ns, extras = self.parse_known_intermixed_args(args, namespace)
            finally:
                self._intermixing = False
        if self.post_parse is not None:
            self.post_parse(ns, self)
        return ns, extras


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """`cs <command> -h` laid out for the terminal the way `cloudseed help` is: the description and examples are wrapped
    to its width with their tables kept in columns, and option help wraps without cutting words, names at hyphens or
    `a|b|c` lists mid-name. Output that is not a terminal (and no $COLUMNS) keeps the help text as written."""

    def __init__(self, prog, *args, **kwargs):
        w = helpmod.term_width()
        if w:
            if len(args) >= 3:
                args = args[:2] + (w - 2,) + args[3:]
            else:
                kwargs["width"] = w - 2
        super().__init__(prog, *args, **kwargs)
        self._cs_layout = bool(w)

    def _fill_text(self, text, width, indent):
        if not self._cs_layout:
            return super()._fill_text(text, width, indent)
        return "\n".join((indent + line).rstrip() for _kind, line in helpmod._layout(text, max(30, width), False))

    def _split_lines(self, text, width):
        import textwrap
        text = re.sub(r"\s+", " ", text).strip()
        out: list[str] = []
        for line in textwrap.wrap(text, max(11, width), break_on_hyphens=False, break_long_words=False) or [""]:
            out += helpmod._split_word(line, width) if len(line) > width else [line]   # cut after | / , only
        return out

    def format_help(self):
        text = super().format_help()
        return _break_choice_groups(text, self._width) if self._cs_layout else text


def _break_choice_groups(text: str, width: int) -> str:
    """argparse never breaks a `{a,b,c}` choice group, so at 60 columns `{status,add-user,...,provision}` runs past the
    edge of the usage lines: split such a group after a comma, the rest aligned under its first choice."""
    out: list[str] = []
    for line in text.split("\n"):
        for _ in range(20):
            if len(line) <= width:
                break
            # a whole group of plain choices, or (on a continuation row) the rest of one - never JSON in an example
            m = next((g for g in re.finditer(r"\{?[\w.-]+(?:,[\w.-]+)+\}", line) if g.end() > width), None)
            cut = m.group(0).rfind(",", 0, width - m.start()) if m else -1
            if cut <= 0:
                break
            out.append(line[:m.start() + cut + 1].rstrip())
            pad = m.start() + 1 if m.start() + 1 <= width // 2 else len(line) - len(line.lstrip()) + 2
            line = " " * pad + line[m.start() + cut + 1:]
        out.append(line)
    return "\n".join(out)


def _command_description(name: str) -> str | None:
    """Everything of a command's help page between its synopsis (argparse prints its own usage) and EXAMPLES."""
    text = helpmod.COMMANDS.get(name, "")
    if "\n\n" not in text:
        return None
    body = text.split("\n\n", 1)[1]
    cut = re.search(r"^EXAMPLES\b", body, re.M)
    return (body[:cut.start()] if cut else body).strip("\n") or None


def _command_epilog(name: str, sub: str | None = None) -> str:
    """The examples of a command's help page (for `deps install -h` & co. only the ones of that subcommand), then where
    the full guide is."""
    if sub is None:
        text = helpmod.epilog(name)
    else:
        ex = [e for e in helpmod.examples(name, limit=50) if re.search(rf"\b{name} {re.escape(sub)}\b", e)]
        text = ("\nEXAMPLES\n" + "\n".join("  " + e for e in ex)) if ex else ""
    return text.rstrip("\n") + f"\n\nFull guide: cloudseed help {name}"


ENV_HELP = "environment name (default: the current one - cs env use - else the only one that exists)"


def _tcp_port(value) -> int:
    """argparse type for --port: a TCP port, 1-65535 (0 would let the OS pick one nobody can find again)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"'{value}' is not a whole number") from None
    if not 1 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"must be a TCP port between 1 and 65535 (got {n})")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="cloudseed", formatter_class=_HelpFormatter,
        description="Secure multi-cloud landing zones (network + bastion + security baseline) on AWS, GCP, Azure and VMware (local).",
        epilog="Run `cloudseed help` for the full guide, `cloudseed help <command>` for a command, "
               "`cloudseed help <topic>` for: " + " ".join(helpmod.TOPICS) + " agents, "
               "and `cloudseed help variables|outputs <cloud>`.")
    p.add_argument("--version", action="version", version=f"cloudseed {__version__}")
    p.add_argument("--runtime", choices=["auto", "local", "container"], default=None,
                   help="where to run Terraform: on this machine or inside a container (default: saved preference/auto)")
    p.add_argument("--engine", choices=["docker", "podman"], default=None, help="container engine for --runtime container")
    p.add_argument("-y", "--yes", action="store_true", default=False,
                   help="non-interactive: never prompt, use flags/defaults")

    # The global options are accepted after every command too (`cs list -y`, `cs doctor --engine podman`). Their
    # defaults are SUPPRESS so a sub-command never overwrites a value given before it (`cs --engine podman deps image`).
    yesrt = argparse.ArgumentParser(add_help=False)
    yesrt.add_argument("--runtime", choices=["auto", "local", "container"], default=argparse.SUPPRESS,
                       help="where Terraform runs: auto | local | container (global option)")
    yesrt.add_argument("-y", "--yes", action="store_true", default=argparse.SUPPRESS,
                       help="non-interactive: never prompt, use flags/defaults (global option)")
    common = argparse.ArgumentParser(add_help=False, parents=[yesrt])
    common.add_argument("--engine", choices=["docker", "podman"], default=argparse.SUPPRESS,
                        help="container engine for --runtime container (global option)")

    envp = argparse.ArgumentParser(add_help=False)
    envp.add_argument("cloud", choices=CLOUD_KEYS)
    envp.add_argument("-e", "--env", default=None,
                      help="environment name (setup: dev by default; other commands: the only one of that cloud; "
                           "read-only commands use the current environment (cs env use); a terminal asks; else dev when "
                           "it exists - several without dev need --env)")

    sub = p.add_subparsers(dest="cmd", required=True, metavar="command", parser_class=_CmdParser)
    _add_parser = sub.add_parser

    def add_parser(name, **kw):  # every command gets the same rich formatter, its examples and the global options
        kw.setdefault("formatter_class", _HelpFormatter)
        kw.setdefault("epilog", _command_epilog(name))
        kw.setdefault("description", _command_description(name))
        kw.setdefault("parents", [common])
        return _add_parser(name, **kw)

    sub.add_parser = add_parser

    def add_sub(subs, parent: str, name: str, description: str, **kw):   # deps install, skill show ...
        kw.setdefault("formatter_class", _HelpFormatter)
        kw.setdefault("epilog", _command_epilog(parent, name))
        return subs.add_parser(name, description=description, **kw)

    s = sub.add_parser("setup", parents=[common, envp], help="create or update an environment (network, bastion, baseline)")
    s.add_argument("--name", help="infrastructure name; prefixes every resource and sets the Project tag (default: cloudseed)")
    s.add_argument("--region", help="cloud region / location")
    s.add_argument("--state", choices=["local", "remote"], help="where Terraform state lives (default: remote; always local for vmware)")
    s.add_argument("--workdir", help="working directory for this environment (default: ~/.cloudseed/envs/<cloud>-<env>)")
    s.add_argument("--cidr", help="network CIDR (default: an existing environment keeps its own, a new one gets the first "
                                  "free private /16; vmware: VMware's host-only vmnet)")
    s.add_argument("--allow-ip", action="append", help="IPv4 address or CIDR allowed to SSH to the bastion (repeatable or "
                   "comma-separated; default: your detected public IP for a new environment, an existing one keeps its list)")
    s.add_argument("--ssh-public-key", help="use this public key instead of generating one")
    s.add_argument("--ssh-private-key", help="the private half of --ssh-public-key, used by cloudseed ssh and provisioning")
    s.add_argument("--tag", action="append", metavar="KEY=VALUE", help="extra tag/label on every resource (repeatable)")
    s.add_argument("--var", action="append", metavar="KEY=VALUE",
                   help="override a stack variable or answer a setup question, read by its declared type (JSON for "
                        "lists/maps; KEY=null forgets a saved one); variables cloudseed manages are refused with the flag "
                        "to use (repeatable)")
    s.add_argument("--advanced", action="store_true", help="prompt for advanced options too")
    s.add_argument("--auto-approve", action="store_true", help="apply without asking")
    s.add_argument("--plan-only", action="store_true", help="stop after the plan (the configuration is saved for a later apply)")
    s.add_argument("--preview", action="store_true",
                   help="plan without keeping anything: an existing environment keeps its configuration, a new one is not "
                        "created (setup --plan-only saves the configuration for a later apply)")
    s.add_argument("--dry-run", action="store_true", help="render + validate only; touches nothing in the cloud, and an "
                   "existing environment is left unchanged")
    s.add_argument("--no-provision", action="store_true", help="skip copying the repo to the bastion and hardening it with Ansible")
    s.add_argument("--no-harden", action="store_true",
                   help="provision without OS hardening; sshd settings, fail2ban, kernel/core-dump/sudo settings and audit rules "
                        "from an earlier run are removed (PAM and umask edits stay; automatic updates are left as they are); "
                        "the host firewall and IP forwarding stay (use --no-firewall)")
    s.add_argument("--no-firewall", action="store_true",
                   help="provision without the nftables host firewall (an earlier run's is removed; VPN/NAT hosts keep their NAT rule)")
    s.add_argument("--no-tools", action="store_true", help="provision without installing terraform / cloud CLI on the bastion")
    # cloud-specific shortcuts (map onto question keys)
    s.add_argument("--profile", help="[aws] CLI profile")
    s.add_argument("--project-id", dest="project_id", help="[gcp] project ID")
    s.add_argument("--zone", help="[gcp] bastion zone")
    s.add_argument("--ssh-username", dest="ssh_username", help="[gcp, vmware] login user on the VMs (default: your local username)")
    s.add_argument("--subscription-id", dest="subscription_id", help="[azure] subscription ID")
    s.add_argument("--admin-username", dest="admin_username", help="[azure] admin user on the bastion")

    pv = sub.add_parser("provision", parents=[common, envp],
                        help="copy the repo to the bastion and run the Ansible hardening/tooling playbook there")
    pv.add_argument("--no-harden", action="store_true",
                    help="provision without OS hardening; sshd settings, fail2ban, kernel/core-dump/sudo settings and audit rules "
                         "from an earlier run are removed (PAM and umask edits stay; automatic updates are left as they are); "
                         "the host firewall and IP forwarding stay (use --no-firewall)")
    pv.add_argument("--no-firewall", action="store_true",
                    help="provision without the nftables host firewall (an earlier run's is removed; VPN/NAT hosts keep their NAT rule)")
    pv.add_argument("--no-tools", action="store_true", help="provision without installing terraform / cloud CLI on the bastion")
    pv.add_argument("--sync-only", action="store_true", help="only copy the repository, do not run Ansible")
    pv.add_argument("--host", choices=["bastion", "vpn", "k8s"], help="provision only this part (default: all)")

    k8 = sub.add_parser("k8s", help="the environment's cluster (EKS/GKE/AKS, RKE2 on vmware): cloudseed k8s info|kubeconfig|tunnel|untunnel <cloud> --env NAME")
    k8.add_argument("k8s_cmd", choices=["info", "kubeconfig", "tunnel", "untunnel"],
                    help="info: cluster facts · kubeconfig: add it to ~/.kube/config · tunnel/untunnel: SSH tunnel to a private API")
    k8.add_argument("cloud", choices=CLOUD_KEYS)
    k8.add_argument("-e", "--env", default=None, help=ENV_HELP)

    vp = sub.add_parser("vpn", help="VPN: cloudseed vpn status|add-user|users|revoke|connect|disconnect|provision <cloud> --env NAME [name]")
    vp.add_argument("vpn_cmd", choices=["status", "add-user", "revoke", "users", "connect", "disconnect", "provision"])
    vp.add_argument("cloud", choices=CLOUD_KEYS)
    vp.add_argument("name", nargs="?", help="client name for add-user / revoke")
    vp.add_argument("-e", "--env", default=None, help=ENV_HELP)
    vp.add_argument("--user", help="profile to use for connect (created if missing)")

    a = sub.add_parser("plan", parents=[common, envp], help="show what apply would change")
    a = sub.add_parser("apply", parents=[common, envp], help="re-apply the saved configuration")
    a.add_argument("--auto-approve", action="store_true", help="apply the plan without asking")

    d = sub.add_parser("destroy", parents=[common, envp], help="destroy everything, or pick resources with --select/--target")
    d.add_argument("--select", action="store_true", help="interactively choose modules/resources to destroy")
    d.add_argument("--target", action="append", help="Terraform address to destroy (repeatable / comma-separated)")
    d.add_argument("--purge-state", action="store_true", help="also delete the remote state storage")
    d.add_argument("--purge", action="store_true",
                   help="also delete the working directory (all of it when cloudseed created it; only cloudseed's files "
                        "in one that already held files)")
    d.add_argument("--auto-approve", action="store_true", help="destroy without asking (no typed confirmation)")

    sub.add_parser("status", parents=[common, envp], help="configuration, state summary and outputs")
    tsp = sub.add_parser("troubleshoot", parents=[common, envp],
                         help="deterministic diagnosis from the audit log, last failure, inventory and live checks")
    tsp.add_argument("--last", type=_positive_int, default=10, help="how many recent runs to show (default 10)")
    tsp.add_argument("--log", action="store_true", help="also print the tail of the last failure log")
    inv = sub.add_parser("inventory", parents=[common, envp], help="what exists in this environment and its change history")
    inv.add_argument("--json", action="store_true", help="machine-readable JSON instead of tables")
    inv.add_argument("--last", type=_positive_int, default=15, help="how many entries of the change history to show (default 15)")
    o = sub.add_parser("output", parents=[common, envp], help="print stack outputs")
    o.add_argument("--json", action="store_true", help="every output as JSON (for scripts)")

    ssh = sub.add_parser("ssh", parents=[common, envp], help="SSH into the bastion: cs ssh <cloud> [--env NAME] [ssh options] [-- remote command]")
    ssh.add_argument("ssh_args", nargs=argparse.REMAINDER, metavar="ARGS", help="ssh options, then -- and a remote command")
    ssh.post_parse = _ssh_post

    u = sub.add_parser("update-ip", parents=[common, envp], help="re-detect your public IP and update bastion access")
    u.add_argument("--allow-ip", action="append",
                   help="IPv4 address or CIDR to allow instead of your detected public IP (repeatable or comma-separated)")
    u.add_argument("--auto-approve", action="store_true", help="apply the new address without asking")

    sub.add_parser("list", help="list environments")
    doc = sub.add_parser("doctor", help="check dependencies and credentials")
    doc.add_argument("cloud", nargs="?", choices=CLOUD_KEYS)

    dp = sub.add_parser("deps", help="manage dependencies (install / container image / bundle)")
    dps = dp.add_subparsers(dest="deps_cmd", required=True, parser_class=_CmdParser)
    add_sub(dps, "deps", "status", "Which tools every cloud needs, which are installed (and their versions), and the credentials "
            "found - the same report as `cloudseed doctor`.", parents=[common], help="tools, versions and credentials (= cloudseed doctor)")
    di = add_sub(dps, "deps", "install", "Install tools on this machine: Homebrew when available, otherwise the official releases "
                 "into ~/.cloudseed/bin (checksum-verified where the vendor publishes sums). `all` = terraform aws gcloud az; "
                 "`cloudseed install` has more targets.", parents=[common], help="install tools locally")
    di.add_argument("tools", nargs="+", help="terraform aws gcloud az (and the other tools of `cloudseed install list`) | all")
    # these two take --engine themselves; SUPPRESS keeps a value given before the command (`cs --engine podman deps image`)
    dimg = add_sub(dps, "deps", "image", "Build the all-in-one container image (Terraform, aws, gcloud, az, kubectl, helm) with Docker "
                   "or Podman; then run any command with --runtime container.", parents=[yesrt], help="build the all-in-one container image")
    dimg.add_argument("--engine", choices=["docker", "podman"], default=argparse.SUPPRESS, help="container engine (docker|podman)")
    dimg.add_argument("--rebuild", action="store_true", help="rebuild the image even if it exists")
    add_sub(dps, "deps", "bundle", "Build dist/cloudseed-<os>-<arch>: one binary with the CLI, every Terraform module and Terraform "
            "itself (needs a source checkout).", parents=[common], help="build a single self-contained binary (Terraform embedded)")
    dr = add_sub(dps, "deps", "runtime", "Where Terraform runs by default: auto (this machine when the tools are here, else "
                 "the container), local or container.", parents=[yesrt], help="set the default runtime")
    dr.add_argument("mode", choices=["auto", "local", "container"], help="auto | local | container")
    dr.add_argument("--engine", choices=["docker", "podman"], default=argparse.SUPPRESS, help="container engine (docker|podman)")

    en = sub.add_parser("enable", help="enable a feature: agentic | headliner | mcp | ui")
    en.add_argument("feature", choices=FEATURES)
    en.add_argument("--agent", help="agent to use: builtin, claude, codex, gemini, grok (see: cloudseed agents)")
    en.add_argument("--port", type=_tcp_port, help="[ui] port for the local console (default 7434)")
    en.add_argument("--no-open", action="store_true", help="[ui] do not open the browser")
    dis = sub.add_parser("disable", help="disable a feature: agentic | headliner | mcp | ui")
    dis.add_argument("feature", choices=FEATURES)

    use = sub.add_parser("use", help="select the agent CLI (and optionally its model), installing skills if needed")
    use.add_argument("agent", nargs="?", help="builtin | claude | codex | gemini | grok (or a custom agent from agents.json)")
    use.add_argument("--model", help="also select this model for the agent (see: cloudseed model)")

    sub.add_parser("agents", help="list agents: what each is, whether it is installed and logged in")
    mo = sub.add_parser("model", help="show available models for the selected agent, or pick one")
    mo.add_argument("model", nargs="?", help="model id to select (none: list the agent's models)")
    mo.add_argument("--agent", help="the agent whose model to show or set (default: the selected one)")
    mo.add_argument("--forget", metavar="ID", help="remove a custom model id remembered earlier")

    do = sub.add_parser("agentic", aliases=["do"],
                        help='run a natural-language task through the selected agent, e.g. cloudseed agentic "set up aws"')
    do.add_argument("task", nargs=argparse.REMAINDER,
                    help="the task in plain English; cloudseed flags may also follow the task; -- makes the rest literal")
    do.add_argument("--agent", help="run this task with another agent (one-off: the selected agent stays)")
    do.add_argument("--model", help="model for this task (one-off: the saved choice stays)")
    do.add_argument("--interactive", "-i", action="store_true",
                    help="open the agent's interactive session instead of exec mode (external agents only)")
    do.add_argument("--no-headliner", action="store_true", help="send the task without the research brief")
    do.add_argument("--show-prompt", action="store_true", help="print the (redacted) prompt that is sent")
    do.add_argument("--force", action="store_true", help="run even if agentic mode is disabled")
    do.post_parse = _agentic_post

    sk = sub.add_parser("skill", help="list / install / show the bundled agent skills")
    sks = sk.add_subparsers(dest="skill_cmd", required=True, parser_class=_CmdParser)
    add_sub(sks, "skill", "list", "The bundled skills with their descriptions, and where each agent has them installed.",
            parents=[common], help="the bundled skills and where they are installed")
    si = add_sub(sks, "skill", "install", "Copy skills (all when no names are given) into the agent's skills directory "
                 "(~/.claude/skills, ~/.codex/skills, ...), into ./.<agent>/skills with --project, or anywhere with --dir. "
                 "Names can be short (aws, destroy) or full (cloudseed-aws).", parents=[common], help="install skills for an agent")
    si.add_argument("names", nargs="*", help="skill names (default: all)")
    si.add_argument("--agent", help="claude | codex | gemini | grok")
    si.add_argument("--dir", help="install into this directory instead")
    si.add_argument("--project", action="store_true", help="install into ./.<agent>/skills of the current project")
    ss = add_sub(sks, "skill", "show", "Print one skill (its SKILL.md).", parents=[common], help="print one skill")
    ss.add_argument("name", help="skill name, short (aws) or full (cloudseed-aws)")

    inst = sub.add_parser("install",
                          help="install anything: terraform aws gcloud az go qemu-img openvpn tailscale vmrun | all cloud vmware vpn | skills | vmware-provider | image | bundle | <agent>")
    inst.add_argument("what", nargs="*", help="what to install (see cloudseed help install)")
    inst.add_argument("--agent", help="target agent for skills (builtin|claude|codex|gemini|grok)")
    inst.add_argument("--dir", help="install skills into this directory")
    inst.add_argument("--project", action="store_true", help="install skills into ./.<agent>/skills")
    inst.add_argument("--rebuild", action="store_true", help="image / vmware-provider: rebuild even if it exists")
    inst.add_argument("--from", dest="from_path", help="installer file for `install vmrun` (VMware Fusion .dmg / Workstation .bundle or .exe)")

    ev = sub.add_parser("env", help="current environment for cluster commands: cs env | cs env use <id> | cs env clear")
    ev.add_argument("env_cmd", nargs="?", choices=["show", "use", "clear"], default="show")
    ev.add_argument("id", nargs="?")

    nd = sub.add_parser("node", help="cluster nodes: cs node add|list|remove|scale [node-name] [cloud] [--env NAME]")
    nd.add_argument("node_cmd", choices=["add", "list", "remove", "scale"])
    nd.add_argument("targets", nargs="*", metavar="NAME|CLOUD",
                    help="remove: the node name (see cs node list); a cloud key (aws gcp azure vmware) selects the target")
    nd.add_argument("--cloud", dest="cloud", choices=CLOUD_KEYS, default=None, help="target cloud (the same as the cloud word)")
    nd.add_argument("-e", "--env", default=None, help=ENV_HELP)
    nd.add_argument("--count", type=_positive_int, default=None, help="add: how many nodes to add (default 1) · scale: the pool size")
    nd.add_argument("--min", type=_non_negative_int, default=None, help="scale: autoscaler minimum (default: the new count)")
    nd.add_argument("--max", type=_positive_int, default=None, help="scale: autoscaler maximum (default: unchanged, or the count when larger)")
    nd.add_argument("--role", choices=["worker", "control-plane"], default="worker", help="[vmware] node role to add")
    nd.add_argument("--auto-approve", action="store_true", help="change the node pool without asking")
    nd.post_parse = _node_post

    platform_actions = ["list", "info", "plan", "install", "uninstall", "status", "ui", "template"]
    pl = sub.add_parser("platform", help=f"platform catalog: cs platform {'|'.join(platform_actions)} [group|item ...] [cloud] "
                                         "[--env NAME]")
    pl.add_argument("platform_cmd", choices=platform_actions)
    pl.add_argument("--force", action="store_true", help="install even when a conflicting item is present")
    pl.add_argument("--charts", action="store_true", help="list: also show each item's chart/repo/version source")
    pl.add_argument("items", nargs="*", help=f"groups ({' '.join(platformmod.GROUPS)}) and/or item names; a cloud key selects the target")
    pl.add_argument("-e", "--env", default=None, help=ENV_HELP)
    pl.add_argument("--cloud", dest="cloud", choices=CLOUD_KEYS, default=None, help="target cloud (the same as the cloud word)")
    pl.add_argument("--no-wait", action="store_true", help="don't wait for releases to become ready")
    pl.add_argument("--version", help="chart version for the one named item (not its dependencies)")
    pl.add_argument("--set", action="append", metavar="KEY=VALUE",
                    help="extra helm --set for the one named item, not its dependencies (repeatable). Values are remembered "
                         "per item and re-applied by later installs and --upgrade; KEY- forgets one. --set "
                         "mode=sidecar|ambient (the Istio mode) also works with groups that include istio; without istio "
                         "in the request, mode= is a chart value like any other")
    pl.add_argument("--auto-approve", action="store_true", help="install / uninstall without asking")
    pl.add_argument("--upgrade", action="store_true", help="re-apply items that are already installed")

    fo = sub.add_parser("finops", help="costs: cs finops estimate|cloud|k8s|report [cloud] [--env NAME]")
    fo.add_argument("finops_cmd", choices=["estimate", "cloud", "k8s", "report"])
    fo.add_argument("cloud", nargs="?", choices=CLOUD_KEYS)
    fo.add_argument("-e", "--env", default=None, help=ENV_HELP)
    fo.add_argument("--days", type=_finops_days, default=30, help="cloud bill window in days (1-365)")
    fo.add_argument("--window", default="7d", help="OpenCost window (e.g. 24h, 7d, 30d)")
    fo.add_argument("--by", default="namespace", help="OpenCost aggregation: namespace, controller, pod, label:team ...")
    fo.add_argument("--save", action="store_true", help="save the report under <workdir>/finops/")

    ch = sub.add_parser("chaos", help="chaos engineering: cs chaos run [suite|experiment ...] [cloud] [--env NAME] | list | status | stop | report")
    ch.add_argument("chaos_cmd", choices=["run", "list", "status", "stop", "report"])
    ch.add_argument("items", nargs="*", help="run: suites (basic network stress full) and/or experiment names; a cloud key selects the target")
    ch.add_argument("-e", "--env", default=None, help=ENV_HELP)
    ch.add_argument("--cloud", dest="cloud", choices=CLOUD_KEYS, default=None, help="target cloud (the same as the cloud word)")
    ch.add_argument("--suite", choices=["basic", "network", "stress", "full"], help="run: suite when no items are given (default basic)")
    ch.add_argument("--target", help="run: <namespace>/<deployment>[:port|port-name] to test YOUR workload instead of the canary")
    ch.add_argument("--duration", type=_chaos_seconds, default=45, help="run: time per experiment: 45, 45s or 2m (15s..1h, default 45s)")
    ch.add_argument("--replicas", type=_chaos_replicas, default=None, help="run: canary replicas, 2..20 (default 3)")
    ch.add_argument("--keep", action="store_true", help="run: keep the canary namespace afterwards")
    ch.add_argument("--auto-approve", action="store_true", help="run the experiments without asking")

    drp = sub.add_parser("dr", help="disaster recovery (Velero): cs dr status|backup|restore|backups|schedule|test|describe|logs [name] [cloud] [--env NAME]")
    drp.add_argument("dr_cmd", choices=["status", "backup", "restore", "backups", "schedule", "test", "describe", "logs"])
    drp.add_argument("words", nargs="*", metavar="NAME|CLOUD",
                     help="backup name (backup/restore) or schedule name; describe/logs: backup|restore and its name; a cloud "
                          "key (aws gcp azure vmware) selects the target")
    drp.add_argument("-e", "--env", default=None, help=ENV_HELP)
    drp.add_argument("--cloud", dest="cloud", choices=CLOUD_KEYS, default=None, help="target cloud (the same as the cloud word)")
    drp.add_argument("--namespaces", help="comma-separated namespaces (default: everything)")
    drp.add_argument("--cron", default="0 2 * * *", help="schedule: cron expression, evaluated by Velero in UTC (default \"0 2 * * *\" = 02:00 UTC nightly)")
    drp.add_argument("--ttl", default="720h", help="schedule: how long to keep backups (default 720h)")
    drp.add_argument("--no-wait", action="store_true", help="backup/restore: return immediately")
    drp.add_argument("--keep", action="store_true", help="test: keep the drill namespace and backup")
    drp.add_argument("--volume", action=argparse.BooleanOptionalAction, default=None, help="test: force volume backup on/off (default: when a default StorageClass exists)")
    drp.add_argument("--details", action="store_true", help="describe: also list every object and volume (velero describe --details)")
    drp.add_argument("--auto-approve", action="store_true", help="restore / schedule / test without asking")
    drp.post_parse = _dr_post

    sc = sub.add_parser("scan", help="security & compliance scans: cs scan cis | kube | images | host | stig | cloud | fips | all | reports")
    sc.add_argument("scan_cmd", choices=["cis", "kube", "images", "host", "stig", "cloud", "fips", "all", "reports"])
    sc.add_argument("cloud", nargs="?", choices=CLOUD_KEYS)
    sc.add_argument("-e", "--env", default=None, help=ENV_HELP)
    sc.add_argument("--host", action="append", help="host/stig/all: bastion, vpn, k8s (repeatable; default all reachable)")
    sc.add_argument("--profile", help="host: cis (default) | stig | a full XCCDF profile id")
    sc.add_argument("--framework", help="kube: kubescape frameworks (default nsa,mitre) · cloud: prowler compliance id (default newest CIS)")
    sc.add_argument("--last", type=_positive_int, default=10, help="reports: how many (default 10)")

    # Pass-through commands: argparse never interprets their arguments (see _CmdParser.passthrough).
    for svc in ("databricks", "snowflake"):
        sp = sub.add_parser(svc, help=f"{svc}: cs {svc} connect | test | status | <{svc} CLI args>   (profile per environment)")
        sp.add_argument("--profile", help="profile name (default: the current environment's profile, falling back to 'default'); also accepted after the subcommand")
        sp.add_argument("svc_args", nargs=argparse.REMAINDER, metavar="ARGS", help=f"connect | test | status, or arguments for the {svc} CLI")
        sp.passthrough = _managed_passthrough

    for tool in ("kubectl", "helm", "k9s"):
        kt = sub.add_parser(tool, help=f"run {tool} against the current environment's cluster: cs {tool} [cloud --env NAME] <args>")
        kt.add_argument("tool_args", nargs=argparse.REMAINDER, metavar="ARGS",
                        help=f"arguments passed to {tool} as typed (optionally prefixed by <cloud> --env NAME; `--` ends cloudseed's part)")
        kt.set_defaults(cloud=None, env=None)
        kt.passthrough = _kube_passthrough

    ex = sub.add_parser("explain", help="explain anything cloudseed does: features, targets, commands, topics, platform groups/items (cs help explain)")
    ex.add_argument("feature", nargs="?")
    ex.add_argument("more", nargs="*")
    ex.add_argument("--json", action="store_true",
                    help="the same page as data (title, summary, sections, commands, also, did_you_mean); exit 1 when nothing matches")

    mcp_actions = ["setup", "status", "guide", "connect", "disconnect", "tools", "config", "test", "serve", "start", "stop",
                   "restart", "logs", "token", "uninstall"]
    mc = sub.add_parser("mcp", help="MCP server: cs setup mcp | cs mcp " + "|".join(a for a in mcp_actions if a != "setup"))
    mc.add_argument("mcp_cmd", nargs="?", default="status", choices=mcp_actions, metavar="action",
                    help=" | ".join(mcp_actions) + " (default: status)")
    mc.add_argument("clients", nargs="*", help="connect/disconnect (required): client names (" + ", ".join(mcp.CLIENTS) + ") or all")
    mc.add_argument("--transport", choices=["http", "stdio"], help="setup: how the server runs · connect: how the client reaches it")
    mc.add_argument("--client", action="append", help="setup: clients to connect (repeatable; all | none | name)")
    mc.add_argument("--client-transport", choices=["http", "stdio"], help="setup: transport for the connected clients (default: http when deployed)")
    mc.add_argument("--yes-clients", action="store_true", help="setup -y: connect every detected client")
    mc.add_argument("--host", help="serve/setup: bind address (default 127.0.0.1; loopback only)")
    mc.add_argument("--port", type=_tcp_port, help=f"serve/setup: TCP port (default {mcp.DEFAULT_PORT}, or the next free one)")
    # tri-state (None = keep what is deployed): a setup re-run keeps both choices, like host, port and transport
    mc.add_argument("--no-auth", dest="auth", action="store_const", const=False, default=None,
                    help="serve/setup: no bearer token, only for clients that cannot send headers - any local process can "
                         "then call every tool (a setup re-run keeps it; --auth or --rotate-token requires a token again)")
    mc.add_argument("--auth", dest="auth", action="store_const", const=True,
                    help="setup: require the bearer token again after --no-auth (the token file is kept, or a new one "
                         "is written when there is none; --rotate-token always writes a new one)")
    mc.add_argument("--no-service", dest="service", action="store_const", const=False, default=None,
                    help="setup: a detached background process instead of a launchd/systemd login service (a setup re-run "
                         "keeps it; --service, or a re-run at a terminal, brings the service back)")
    mc.add_argument("--service", dest="service", action="store_const", const=True,
                    help="setup: run the HTTP server as a launchd/systemd login service again after --no-service")
    mc.add_argument("--rotate-token", action="store_true",
                    help="setup: issue a new bearer token (after --no-auth: the server requires a token again)")
    mc.add_argument("--http", action="store_true", help="serve: Streamable HTTP (+ legacy SSE) instead of stdio · test: test the deployed HTTP server")
    mc.add_argument("--rotate", action="store_true", help="token: issue a new one and restart the server")
    mc.add_argument("--lines", "-n", type=_positive_int, default=50, help="logs: how many lines")
    mc.add_argument("--auto-approve", action="store_true", help="uninstall: do not ask")

    ui_actions = ["open", "start", "status", "stop", "restart", "logs", "token", "serve"]
    uip = sub.add_parser("ui", help=f"local web console: cs enable ui | cs ui [{'|'.join(ui_actions)}]")
    uip.add_argument("ui_cmd", nargs="?", choices=ui_actions, default="open", metavar="action",
                     help=" | ".join(ui_actions) + " (default: open - starts the console first when it is not running)")
    uip.add_argument("--port", type=_tcp_port, help=f"start/serve: TCP port (default {webui.DEFAULT_PORT}, or the next free one)")
    uip.add_argument("--host", help="serve: bind address (default 127.0.0.1; loopback only)")
    uip.add_argument("--no-open", action="store_true", help="start: do not open the browser")
    uip.add_argument("--lines", "-n", type=_positive_int, default=50, help="logs: how many lines")
    uip.add_argument("--rotate", action="store_true", help="token: issue a new one")

    un = sub.add_parser("undo", help=f"undo the previous action (the last {undo.KEEP_TOTAL} changes per environment and globally, "
                                     f"at most {undo.KEEP} of one kind): cs undo [<cloud> --env NAME | --global | --id ID] "
                                     "[--list] [--drop]")
    un.add_argument("cloud", nargs="?", choices=CLOUD_KEYS, help="only this cloud's environments")
    un.add_argument("-e", "--env", default=None, help="only the environment with this name (with <cloud>, or on any cloud)")
    un.add_argument("--global", dest="global_scope", action="store_true", help="the global history (MCP/UI setup, credentials, enable/disable, agent/model)")
    un.add_argument("--id", help="exactly this entry (from --list / the console); refused when a newer one in its scope must go first")
    un.add_argument("--list", action="store_true", help="show the undo history instead of undoing")
    un.add_argument("--drop", action="store_true", help="discard the entry without undoing it (for a step that can never succeed)")
    un.add_argument("--auto-approve", action="store_true", help="undo without asking")

    cr = sub.add_parser("creds", help="local credential vault: cs creds [list] | set KEY=VALUE | set KEY (prompt) | unset KEY | clear")
    cr.add_argument("creds_cmd", nargs="?", choices=["list", "set", "unset", "clear"], default="list", metavar="action",
                    help="list | set | unset | clear (default: list)")
    cr.add_argument("items", nargs="*", help="set: KEY=VALUE, or KEY alone to type it hidden · unset: KEY")
    cr.add_argument("--forget", action="store_true", help="unset/clear: keep no copy of the removed values for undo")

    h = sub.add_parser("help", help="full guide: cloudseed help [command|topic] [cloud]")
    h.add_argument("topic", nargs="?", help="a command or topic (cloudseed help lists them)")
    h.add_argument("cloud", nargs="?", help="for variables / outputs: aws | gcp | azure | vmware")
    return p


HANDLERS = {
    "setup": cmd_setup, "plan": cmd_plan, "apply": cmd_apply, "destroy": cmd_destroy, "status": cmd_status,
    "output": cmd_output, "ssh": cmd_ssh, "update-ip": cmd_update_ip, "list": cmd_list, "doctor": cmd_doctor,
    "deps": cmd_deps, "enable": cmd_enable, "disable": cmd_disable, "use": cmd_use, "model": cmd_model,
    "agentic": cmd_do, "do": cmd_do, "skill": cmd_skill, "help": cmd_help, "install": cmd_install,
    "agents": cmd_agents, "provision": cmd_provision, "k8s": cmd_k8s, "vpn": cmd_vpn,
    "troubleshoot": cmd_troubleshoot, "inventory": cmd_inventory, "env": cmd_env, "node": cmd_node,
    "platform": cmd_platform, "kubectl": cmd_ktool, "helm": cmd_ktool, "k9s": cmd_ktool,
    "databricks": cmd_managed, "snowflake": cmd_managed, "finops": cmd_finops, "explain": cmd_explain, "mcp": cmd_mcp,
    "chaos": cmd_chaos, "dr": cmd_dr, "scan": cmd_scan, "ui": cmd_ui, "creds": cmd_creds, "undo": cmd_undo,
}

# ---------------------------------------------------------------- human-only commands

# What an agent session may still run of the commands that change this machine's setup (read-only forms). `ui token`
# and `mcp token` are not among them: they exist only to print a bearer secret (redacted in an agent session, and
# kept from the agents' file reads) - the console token alone would run every human-only action through the console.
_AGENT_READ_FORMS = {"creds": ("list",), "ui": ("status", "logs"),
                     "mcp": ("status", "guide", "tools", "config", "test", "serve", "logs"),
                     "deps": ("status",), "skill": ("list", "show")}
_HUMAN_ONLY_WHY = {
    "agentic": "an agent session cannot start another agent task",
    "install": "agent sessions never install software", "deps": "agent sessions never install software",
    "skill": "agent sessions never install software",
    "creds": "agent sessions never change the credential vault",
    "use": "agent sessions never change the agent or model choice", "model": "agent sessions never change the agent or model choice",
    "enable": "agent sessions never switch cloudseed features on or off", "disable": "agent sessions never switch cloudseed features on or off",
    "ui": "agent sessions never start, stop or re-key the web console",
    "mcp": "agent sessions never change the MCP deployment or client configs",
}


def human_only_reason(ns) -> str | None:
    """Why a parsed command line is for the human only (None when an agent session may run it). The one policy for
    every agent session: the CLI gate in _dispatch, and the built-in agent's tool validation. Read-only forms (creds
    list, model, ui status, mcp status/serve ...) stay available; ssh/k9s are fine for agents that have a terminal."""
    cmd = getattr(ns, "cmd", None)
    cmd = "agentic" if cmd == "do" else cmd
    why = _HUMAN_ONLY_WHY.get(cmd or "")
    if why is None:
        return None
    if cmd == "use":
        return None if getattr(ns, "agent", None) in ("help", "list", "?") else why
    if cmd == "model":
        return why if (getattr(ns, "model", None) or getattr(ns, "forget", None)) else None
    if cmd == "install":
        what = [str(w).lower() for w in getattr(ns, "what", None) or []]
        return None if what in ([], ["help"], ["list"]) else why
    sub = {"creds": "creds_cmd", "ui": "ui_cmd", "mcp": "mcp_cmd", "deps": "deps_cmd", "skill": "skill_cmd"}.get(cmd)
    if sub is None:
        return why                             # agentic, enable, disable
    action = getattr(ns, sub, None) or {"creds": "list", "ui": "open", "mcp": "status"}.get(cmd)
    if action == "token" and cmd in ("ui", "mcp"):
        return f"agent sessions never see or rotate the {'console' if cmd == 'ui' else 'MCP'} token"
    if action not in _AGENT_READ_FORMS[cmd]:
        return why
    return None


def _human_command(argv: list[str], ns=None) -> str:
    """The command line to hand to the human: without cloudseed's -y, and without credential values (`creds set KEY`
    prompts for them, hidden) - also when global options come before the command (`--runtime local creds set ...`,
    abbreviated too: `--run local`; `ns`, the parsed command line, says which command it is). The vault's words are
    read as the built-in agent reads them (builtin_agent._creds_args): KEY=VALUE keeps its KEY, the bare value of
    `creds set KEY value` is dropped whatever it looks like, and names are shown upper case, as the vault stores them."""
    words = [a for a in argv if a not in ("-y", "--yes")]
    # (only a global option's fixed choice can come before the command word, so the first "creds" is the command)
    i = words.index("creds") if getattr(ns, "cmd", None) == "creds" and "creds" in words else _command_index(words)
    if words[i:i + 1] == ["creds"]:
        from .builtin_agent import _creds_args
        words = words[:i + 1] + [w.upper() if what.startswith("name") else w
                                 for w, what in _creds_args(words[i + 1:]) if what in ("word", "name", "name=")]
    import shlex
    return "cloudseed " + " ".join(shlex.quote(w) for w in words)


_MCP_ALIASES = {"setup": "setup", "status": "status", "destroy": "uninstall"}
_NO_HOME_COMMANDS = {"help", "explain"}   # pure reading: they work even when CLOUDSEED_HOME cannot be created


def normalize_argv(argv: list[str]) -> list[str]:
    """argv rewrites applied before argparse. `cs setup|status|destroy mcp` read like every other target but are the mcp
    command (`mcp setup|status|uninstall`), also when global options come first (`cs -y setup mcp`) or sit in between
    (`cs setup -y mcp`); the options are kept (every command accepts them)."""
    argv = list(argv)
    i = _skip_global_options(argv)
    if i < len(argv) and argv[i] in _MCP_ALIASES:
        j = _skip_global_options(argv, i + 1)
        if j < len(argv) and argv[j] == "mcp":
            argv = argv[:i] + ["mcp", _MCP_ALIASES[argv[i]]] + argv[i + 1:j] + argv[j + 1:]
    return argv


def _changes_nothing(args) -> bool:
    """A command line that only shows something (help, list, status, a read-only subcommand ...): cutting its output
    short loses nothing but output."""
    cmd = getattr(args, "cmd", None)
    if cmd in ("help", "explain", "list", "status", "output", "inventory", "troubleshoot", "doctor", "agents", "plan"):
        return True
    sub = {"mcp": ("mcp_cmd", ("status", "guide", "tools", "config", "logs", "test")), "ui": ("ui_cmd", ("status", "logs")),
           "creds": ("creds_cmd", ("list",)), "skill": ("skill_cmd", ("list", "show")), "deps": ("deps_cmd", ("status",)),
           "env": ("env_cmd", ("show",)), "platform": ("platform_cmd", ("list", "info", "status", "plan")),
           "finops": ("finops_cmd", ("estimate", "cloud", "k8s")), "dr": ("dr_cmd", ("status", "backups", "describe", "logs")),
           "chaos": ("chaos_cmd", ("list", "status", "report")), "scan": ("scan_cmd", ("reports",)),
           "vpn": ("vpn_cmd", ("status", "users")), "node": ("node_cmd", ("list",)), "k8s": ("k8s_cmd", ("info",))}.get(cmd)
    if sub is not None:
        return getattr(args, sub[0], None) in sub[1]
    if cmd == "install":
        return [str(w).lower() for w in getattr(args, "what", None) or []] in ([], ["help"], ["list"])
    if cmd == "undo":
        return bool(getattr(args, "list", False))
    if cmd == "model":
        return not (getattr(args, "model", None) or getattr(args, "forget", None))
    return False


def _silence_stdout() -> None:
    """The reader of our output went away (`| head`, `| true`): point fd 1 at /dev/null, so what is still buffered is
    flushed there quietly (at exit Python would otherwise print 'Exception ignored ... BrokenPipeError', exit 120)."""
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(fd, sys.__stdout__.fileno())
        finally:
            os.close(fd)
    except (OSError, ValueError, AttributeError):
        pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    audit.begin(argv)
    rc = 0
    try:
        rc = _main(argv)
        try:
            sys.stdout.flush()      # a closed pipe shows up now (argparse's -h/--version output is still buffered)
        except (ValueError, AttributeError):
            pass
    except BrokenPipeError:        # -h, --version, the overview ... piped into a reader that left: leave quietly
        _silence_stdout()
    return rc


def _main(argv: list[str]) -> int:
    rc = 1
    try:
        rc = _dispatch(argv)
        return rc
    finally:
        audit.end(rc)


def _dispatch(argv: list[str]) -> int:
    try:
        sys.stdout.reconfigure(line_buffering=True)  # keep our output ordered with child processes' output
    except (AttributeError, ValueError):
        pass
    redact = secrets.redact_enabled()
    if redact:   # inside an agent session: everything this process prints is redacted, usage errors included
        secrets.wrap_std_streams()

    if _skip_global_options(argv) >= len(argv):   # no command at all (`cs`, `cs -y`): the overview
        if ui.interactive() and not argv:
            ui.banner(__version__)
        helpmod.print_page(None, None)
        return 0

    argv = normalize_argv(argv)
    try:
        args = build_parser().parse_args(argv)
        if args.cmd == "ssh" and "--" in argv:   # keep the user's `--`: after it, -e/-F/... are ssh's, not ours
            args = _parse_ssh_argv(argv)
    except SystemExit as e:  # argparse --help / usage errors: return the code instead of exiting mid-call
        if isinstance(e, ui.Abort):   # an Abort does not print itself: a parse-time one (a post-parse hook) must not be silent
            ui.show_abort(e)
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 2)
    audit.set_command(args.cmd)   # the parsed command names the audit record and its log files
    if deps.agent_session():      # before anything is read or written: a refused command touches nothing
        why = human_only_reason(args)
        if why:
            shown = _human_command(argv, args)
            ui.err(f"`{shown}` is human-only ({why}). Ask the user to run it in a terminal:\n    {shown}")
            return 2
    try:
        paths.ensure_home()
    except OSError as e:
        if args.cmd not in _NO_HOME_COMMANDS:
            ui.err(f"CLOUDSEED_HOME ({paths.HOME}) is not usable: {e.strerror or e}. "
                   "Point CLOUDSEED_HOME at a writable directory, or fix its permissions.")
            return 1
    secrets.restore_session_env()   # an agent session's parked credentials (registered as literal secrets)
    creds.apply()
    if redact:
        secrets.register_env_secrets()   # the credentials the vault just put into the environment are secrets too
    settings = paths.load_settings()
    # 1/true/yes/on switch it on (the same reading as every other boolean CLOUDSEED_* switch); 0/false/no/off do not
    ui.NON_INTERACTIVE = bool(getattr(args, "yes", False)) or secrets.env_flag("CLOUDSEED_NONINTERACTIVE")
    if args.engine and args.cmd in TF_COMMANDS:
        # for the runtime gate below (deps.ensure_runtime reads it there); other commands never see a one-off --engine
        # in their settings, so none of them saves it as the preference (deps runtime/image check it first)
        settings["engine"] = args.engine

    try:
        if getattr(args, "dry_run", False):
            from . import localvm
            localvm.DRY_RUN_OK["active"] = True
        if args.cmd == "setup" and ui.interactive():
            ui.banner(__version__, f"setting up {clouds.get(args.cloud).display}")
        want = args.runtime or settings.get("runtime") or "auto"
        # troubleshoot / inventory / undo --list only read local files (troubleshoot reports missing tools itself), and
        # undo --drop only edits the undo journal: none of them needs Terraform or the hypervisor
        reads_only = args.cmd in ("troubleshoot", "inventory") or \
            (args.cmd == "undo" and (getattr(args, "list", False) or getattr(args, "drop", False)))
        if args.cmd == "finops":
            # estimate is offline pure Python; cloud / k8s / report never run Terraform (they report a missing aws/az
            # CLI or kubeconfig per view): only a container user is sent into the container, for its CLIs and mounts
            reads_only = args.finops_cmd == "estimate" or want != "container"
        elif args.cmd in ("status", "output") and want != "container":
            # both fall back to the cached outputs (clearly marked, exit 1) when terraform is missing here: no install
            # prompt, no refusal; a container user still runs them in the container
            reads_only = True
        gate_cloud = getattr(args, "cloud", None)
        run_argv = argv
        if args.cmd == "undo" and not reads_only:
            # what the entry's inverse needs decides, not the filters typed: a Terraform/cloud-tool inverse needs the
            # environment's runtime (also for a plain `cs undo`); file, settings and vault restores run right here
            _scope, entry = _undo_pick(args)
            env_ = _env_of_scope(entry["scope"]) if entry and entry["kind"] in _UNDO_TOOLCHAIN else None
            gate_cloud = env_.cloud if env_ is not None else None
            if entry and not getattr(args, "id", None):
                run_argv = argv + ["--id", entry["id"]]   # the container must undo the entry picked here, without asking again
        if args.cmd in TF_COMMANDS and gate_cloud and not reads_only:
            # a dry run only renders and validates: no "Install az now?" before it (the cloud CLI is optional there)
            # Node and provision commands validate existing state first, and prepare
            # VMware themselves only on a path that actually needs the hypervisor.
            mode = deps.ensure_runtime(gate_cloud, want, settings, needs_host=_touches_vms(args) and args.cmd not in ("node", "provision"),
                                       nag_optional=args.cmd == "setup" and not getattr(args, "dry_run", False))
            if mode == "container" and not paths.IN_CONTAINER:
                engine = container.choose_engine(settings, explicit=args.engine)
                return container.reexec(engine, run_argv)
        with _env_lock_scope():   # the environment lock a changing command takes is released when it returns
            return HANDLERS[args.cmd](args, settings)
    except ui.Abort as e:
        ui.show_abort(e)   # the one place an Abort's message is printed (0 = note, 3/130 = warning, else error)
        # (an environment busy with another run is no usage mistake: the command's examples would only bury the message)
        if e.code not in (0, 3, 130, None) and not isinstance(e, paths.EnvBusy):
            ui.eprint(helpmod.error_hint(getattr(args, "cmd", None)))
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except TerraformError as e:
        ui.err(str(e))
        cloud = getattr(args, "cloud", None)
        nxt = [f"cloudseed doctor {cloud}" if cloud else "cloudseed doctor", "cloudseed help troubleshooting"]
        if cloud:
            nxt.append(f"cloudseed help variables {cloud}")
        ui.eprint(ui.dim("  Next: " + "   ·   ".join(nxt)), tee=True)
        _, log = audit.attached()
        if log:
            ui.eprint(ui.dim(f"  Full output: {log}"))
        return 1
    except KeyboardInterrupt:
        print()
        ui.warn("Interrupted.")
        return 130
    except paths.ConfigError as e:
        ui.err(str(e))
        return 1
    except BrokenPipeError:  # output piped into `head` & co.: leave quietly
        _silence_stdout()
        # a view cut short by its reader is fine; a command that changes something was stopped part-way: 141 (128 +
        # SIGPIPE, as the shell reports a process killed by it), so the audit log never records it as a success
        return 0 if _changes_nothing(args) else 141
    except Exception as e:  # noqa: BLE001 - last resort: never leave the user with a bare traceback
        import traceback
        tb = traceback.format_exc()
        ui.err(f"Unexpected error: {type(e).__name__}: {secrets.redact(str(e))}")
        saved = audit.record_crash(tb)    # the env log when one is attached, else ~/.cloudseed/logs/<ts>-<cmd>-crash.log
        env, _ = audit.attached()
        if secrets.env_flag("CLOUDSEED_DEBUG") or not saved:
            ui.eprint(secrets.redact(tb).rstrip())   # asked for, or it could not be saved anywhere: never lose it
        if saved:
            ui.eprint(ui.dim(f"  Full traceback: {saved}   (CLOUDSEED_DEBUG=1 prints it here)"))
        if env is not None and env.exists():
            ui.eprint(ui.dim(f"  Next: cloudseed troubleshoot {env.cloud} --env {env.name} --log"))
        return 1
