from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import time
from pathlib import Path

from .. import deps, ui
from .base import Cloud, Question, as_bool, as_int

_SUBSCRIPTION_CACHE: dict = {}      # (az path, AZURE_CONFIG_DIR) -> (subscription id, time): `az account show` takes seconds
_SUBSCRIPTION_TTL = 120.0           # short, so a later `az login` / `az account set` is picked up


SUBSCRIPTION_ENV = ("ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID")
_WARNED_ENV: set = set()            # (variable, value) pairs already reported as not being a subscription ID


def _subscription_env() -> tuple[str, str, list[str]]:
    """(the first of ARM_SUBSCRIPTION_ID / AZURE_SUBSCRIPTION_ID that holds a subscription ID, its value, the variables
    before it that are set to something else); ('', '', [...]) when none holds one."""
    bad = []
    for name in SUBSCRIPTION_ENV:
        value = str(os.environ.get(name) or "").strip()
        if not value:
            continue
        if _check_subscription_id(value) is None:
            return name, value, bad
        bad.append(name)
    return "", "", bad


def _default_subscription(cfg) -> str:
    """The subscription a blank answer stands for: ARM_SUBSCRIPTION_ID / AZURE_SUBSCRIPTION_ID, else the one
    `az account show` reports. A variable that is set but is not a GUID is reported and never silently replaced by the
    az CLI's subscription: the user named a subscription, and deploying into another one must not happen by accident
    (-y then stops with the flag to pass; the prompt waits for a typed one). An invalid ARM_SUBSCRIPTION_ID next to a
    valid AZURE_SUBSCRIPTION_ID is reported too, naming the variable that is used instead."""
    used, value, bad = _subscription_env()
    if bad:
        key = tuple((n, os.environ.get(n)) for n in bad) + ((used, value),)
        if key not in _WARNED_ENV:          # once per process (the web console recomputes defaults periodically)
            _WARNED_ENV.add(key)
            one = len(bad) == 1
            # the value itself is not shown: a mistyped variable may hold anything, e.g. a pasted client secret
            ui.warn(f"{' and '.join(bad)} {'is' if one else 'are'} set but not an Azure subscription ID (a GUID such as "
                    "00000000-0000-0000-0000-000000000000; see: az account show --query id -o tsv), so "
                    f"{'it is' if one else 'they are'} ignored" +
                    (f"; using the subscription in {used} instead. " if used else
                     " and no other subscription is assumed. ") +
                    f"Fix or unset {'it' if one else 'them'}, or pass --subscription-id <GUID>.")
    if value or bad:
        return value
    az = deps.find("az")
    return _az_subscription(az) if az else ""


def _az_subscription(az: str) -> str:
    """The subscription `az account show` reports: '' when az is not logged in (or fails). Cached for a short while
    per az binary and AZURE_CONFIG_DIR (az's login lives there)."""
    key = (az, str(os.environ.get("AZURE_CONFIG_DIR") or "").strip())
    hit = _SUBSCRIPTION_CACHE.get(key)
    if hit and time.monotonic() - hit[1] < _SUBSCRIPTION_TTL:
        return hit[0]
    try:
        # stdin closed: az never waits on a prompt (an auto-upgrade question) or reads the MCP server's stdio stream
        out = subprocess.run([az, "account", "show", "-o", "json"], capture_output=True, text=True, timeout=30,
                             stdin=subprocess.DEVNULL).stdout
        sub = str(json.loads(out).get("id") or "")
    except Exception:
        sub = ""
    _SUBSCRIPTION_CACHE[key] = (sub, time.monotonic())
    return sub


_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Admin user names Azure refuses for a Linux VM (the create call fails after the network is already built); matched
# case-insensitively. terraform/azure/variables.tf checks the same list.
RESERVED_ADMIN_NAMES = frozenset({
    "administrator", "admin", "user", "user1", "test", "user2", "test1", "user3", "admin1", "1", "123", "a",
    "actuser", "adm", "admin2", "aspnet", "backup", "console", "david", "guest", "john", "owner", "root", "server",
    "sql", "support", "support_388945a0", "sys", "test2", "test3", "user4", "user5",
})


def _check_subscription_id(value: str) -> str | None:
    if _GUID.match(str(value).strip()):
        return None
    return (f"'{value}' is not an Azure subscription ID (a GUID such as 00000000-0000-0000-0000-000000000000; "
            "see: az account show --query id -o tsv).")


def _check_admin_username(value: str) -> str | None:
    if str(value).strip().lower() in RESERVED_ADMIN_NAMES:
        return f"'{value}' is a name Azure does not allow as a VM admin user; choose another (the default is azureuser)."
    return None     # the general login-name rules (length, characters, system accounts) are Cloud.value_problem's


# ---- locations ----
# The physical locations of each Azure cloud (az account list-locations --query "[?metadata.regionType=='Physical']"),
# for checking --region offline. A location missing from this list is only warned about (new ones open every year);
# only the live list from the az CLI, when it is installed and logged in to the same cloud, refuses one.
PUBLIC_LOCATIONS = (
    # Americas
    "eastus", "eastus2", "centralus", "northcentralus", "southcentralus", "westcentralus", "westus", "westus2",
    "westus3", "centraluseuap", "eastus2euap", "canadacentral", "canadaeast", "brazilsouth", "brazilsoutheast",
    "mexicocentral", "chilecentral",
    # Europe
    "northeurope", "westeurope", "uksouth", "ukwest", "francecentral", "francesouth", "germanywestcentral",
    "germanynorth", "norwayeast", "norwaywest", "switzerlandnorth", "switzerlandwest", "swedencentral", "swedensouth",
    "polandcentral", "italynorth", "spaincentral", "austriaeast", "belgiumcentral", "denmarkeast",
    # Asia Pacific
    "eastasia", "southeastasia", "japaneast", "japanwest", "koreacentral", "koreasouth", "australiaeast",
    "australiasoutheast", "australiacentral", "australiacentral2", "centralindia", "southindia", "westindia",
    "jioindiacentral", "jioindiawest", "newzealandnorth", "indonesiacentral", "malaysiawest", "taiwannorth",
    # Middle East and Africa
    "uaenorth", "uaecentral", "qatarcentral", "israelcentral", "southafricanorth", "southafricawest",
)
USGOV_LOCATIONS = ("usgovvirginia", "usgovtexas", "usgovarizona", "usdodeast", "usdodcentral")
CHINA_LOCATIONS = ("chinaeast", "chinaeast2", "chinaeast3", "chinanorth", "chinanorth2", "chinanorth3")

# cloud -> (its locations, what it is called, ARM_ENVIRONMENT for it, the az CLI's name for it)
_CLOUDS = {
    "public": (PUBLIC_LOCATIONS, "the Azure public cloud", "", "AzureCloud"),
    "usgovernment": (USGOV_LOCATIONS, "Azure Government", "usgovernment", "AzureUSGovernment"),
    "china": (CHINA_LOCATIONS, "Azure China (21Vianet)", "china", "AzureChinaCloud"),
}
# ARM_ENVIRONMENT values the azurerm provider accepts (go-azure-sdk environments.FromName), by cloud
_ARM_ENVIRONMENTS = {
    "public": "public", "global": "public", "azurepublic": "public", "azurepubliccloud": "public",
    "usgovernment": "usgovernment", "azureusgovernment": "usgovernment", "azureusgovernmentcloud": "usgovernment",
    "usgovernmentl4": "usgovernment", "usgovernmentl5": "usgovernment", "azureusgovernmentl5": "usgovernment",
    "dod": "usgovernment",
    "china": "china", "azurechina": "china", "azurechinacloud": "china",
}
_LOCATION_NAME = re.compile(r"[a-z][a-z0-9]+")
_LOCATIONS_CACHE: dict = {}         # (az path, AZURE_CONFIG_DIR) -> (location names or None, time)
_LOCATIONS_TTL = 3600.0             # the list changes a few times a year
_WARNED_LOCATIONS: set = set()      # locations already warned about (setup checks --region more than once)


def arm_cloud(environ=None) -> str | None:
    """The Azure cloud Terraform targets: 'public', 'usgovernment' or 'china' from ARM_ENVIRONMENT (unset means
    public), as the azurerm provider and backend read it; None when it cannot be told (ARM_METADATA_HOSTNAME names a
    custom cloud such as Azure Stack, or ARM_ENVIRONMENT holds a value the provider does not know)."""
    e = os.environ if environ is None else environ
    if str(e.get("ARM_METADATA_HOSTNAME") or "").strip():
        return None
    raw = str(e.get("ARM_ENVIRONMENT") or "").strip().lower()
    return _ARM_ENVIRONMENTS.get(raw) if raw else "public"


def _location_cloud(location: str) -> str | None:
    """The cloud a location name belongs to, from its name: sovereign-cloud locations have distinctive prefixes."""
    if location.startswith(("usgov", "usdod")):
        return "usgovernment"
    if location.startswith("china"):
        return "china"
    return "public" if location in PUBLIC_LOCATIONS else None


def _az_locations() -> tuple | None:
    """The physical locations `az account list-locations` reports for az's current cloud; None when az is missing,
    not logged in or answers something else. Cached per az binary and AZURE_CONFIG_DIR."""
    az = deps.find("az")
    if not az:
        return None
    key = (az, str(os.environ.get("AZURE_CONFIG_DIR") or "").strip())
    hit = _LOCATIONS_CACHE.get(key)
    if hit and time.monotonic() - hit[1] < _LOCATIONS_TTL:
        return hit[0]
    names = None
    try:
        out = subprocess.run([az, "account", "list-locations", "--query", "[?metadata.regionType=='Physical'].name",
                              "-o", "json"], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL).stdout
        data = json.loads(out)
        if isinstance(data, list) and data and all(isinstance(x, str) and _LOCATION_NAME.fullmatch(x.lower())
                                                   for x in data):
            names = tuple(sorted({x.lower() for x in data}))
    except Exception:
        names = None
    _LOCATIONS_CACHE[key] = (names, time.monotonic())
    return names


def _did_you_mean(location: str, known) -> str:
    """' (did you mean eastus?)' for a typo, a word-order slip (useast2) included; '' when nothing is close."""
    known = list(known)
    close = []
    m = re.fullmatch(r"([a-z]+)(\d*)", location)
    if m:       # useast -> eastus, useast2 -> eastus2
        letters, digits = m.groups()
        close = [c for c in (letters[i:] + letters[:i] + digits for i in range(1, len(letters))) if c in known][:1]
    close += [c for c in difflib.get_close_matches(location, known, n=3, cutoff=0.75) if c not in close]
    return f" (did you mean {' or '.join(close[:3])}?)" if close else ""


def location_problem(value, environ=None) -> str | None:
    """Why `value` is not a location Terraform can deploy to, or None. Checked against the cloud ARM_ENVIRONMENT
    selects: a location of another Azure cloud is refused with the variable to set; an unknown one is refused when the
    az CLI's live list (of the same cloud) does not have it either, and only warned about when there is no live list
    to ask (a location newer than the bundled list must still work). No network call beyond the cached az list."""
    e = os.environ if environ is None else environ
    location = re.sub(r"\s+", "", str(value or "")).lower()      # "East US 2" is eastus2 to azurerm
    cloud = arm_cloud(e)
    if not location or cloud is None:
        return None                         # (a custom cloud has locations of its own)
    names, called, _arm, _az_cloud = _CLOUDS[cloud]
    home = _location_cloud(location)
    if home and home != cloud:
        _names, home_called, home_arm, home_az = _CLOUDS[home]
        if home == "public":
            return (f"'{location}' is a location of {home_called}, but ARM_ENVIRONMENT="
                    f"{str(e.get('ARM_ENVIRONMENT') or '').strip()} points Terraform at {called}: pick one of its "
                    f"locations ({', '.join(names)}), or unset ARM_ENVIRONMENT (and: az cloud set --name {home_az} && "
                    "az login).")
        return (f"'{location}' is a location of {home_called}, but Terraform targets {called}: export "
                f"ARM_ENVIRONMENT={home_arm} (and: az cloud set --name {home_az} && az login), or pick a location of "
                f"{called}" + (" such as eastus." if cloud == "public" else f" ({', '.join(names)})."))
    if location in names:
        return None
    live = _az_locations()
    if live and set(live) & set(names):     # az is logged in to the same cloud: its list is the authority
        if location in live:
            return None
        return (f"'{location}' is not an Azure location{_did_you_mean(location, live)}; the locations of {called}: "
                "az account list-locations -o table")
    if location not in _WARNED_LOCATIONS:
        _WARNED_LOCATIONS.add(location)
        ui.warn(f"'{location}' is not an Azure location cloudseed knows{_did_you_mean(location, names)}. A location "
                "newer than this release is fine; otherwise correct --region before anything is created (the list: "
                "az account list-locations -o table).")
    return None


# ---- tags ----
# Azure refuses these in tag names (InvalidTagNameCharacters), and every tag also lands on a storage account (the
# remote-state account, Velero's), where a name may have at most 128 characters; a value at most 256 everywhere.
_TAG_NAME_BAD = re.compile(r"[<>%&\\?/\x00-\x1f\x7f]")
TAG_NAME_MAX, TAG_VALUE_MAX, TAGS_MAX = 128, 256, 50
# AKS copies a cluster's tags onto the private DNS zone of a private cluster (kubernetes_public_endpoint=false), and
# Azure Private DNS zones hold at most 15 tags (Microsoft Learn: "Use Azure tags in AKS"; "Tag resources", limitations)
PRIVATE_DNS_TAGS_MAX = 15
# the tags cloudseed puts on resources itself (Cloud.tags, plus Role on the bastion and VPN VMs)
_BUILTIN_TAGS = ("Project", "Environment", "Owner", "ManagedBy", "CloudseedEnv", "CloudseedEnvId", "Role")


class Azure(Cloud):
    key = "azure"
    display = "Microsoft Azure"
    region_prompt = "Azure location"
    region_env = ("AZURE_LOCATION", "ARM_LOCATION")
    cli_tool = "az"
    login_hint = "az login   (or: export ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_TENANT_ID / ARM_SUBSCRIPTION_ID)"

    questions = [
        Question("subscription_id", "Azure subscription ID", _default_subscription, required=True,
                 env=("ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID")),
        Question("admin_username", "Admin username on the bastion", "azureuser", validate=_check_admin_username),
        Question("bastion_vm_size", "Bastion VM size", "Standard_B1s", advanced=True),
        Question("enable_activity_log", "Send the subscription Activity Log to Log Analytics", True,
                 kind="bool", advanced=True),
        Question("enable_defender", "Enable Microsoft Defender for Cloud (Servers + Storage, paid)", False,
                 kind="bool", advanced=True),
        Question("fips_mode", "FIPS 140 mode (Ubuntu Pro FIPS bastion/VPN, FIPS AKS nodes, FIPS-only SSH/TLS)?", False, kind="bool"),
        # the cluster's own settings follow its switch (asked only when a cluster is wanted), then the VPN's
        Question("enable_kubernetes", "Create a private managed Kubernetes cluster (AKS) in the private subnets?", False, kind="bool"),
        Question("kubernetes_node_size", "Kubernetes node size", "Standard_B2s", advanced=True),
        # the question refuses 0 itself (the prompt re-asks, --var is refused before anything is saved); stack_vars
        # keeps the same minimum as a backstop for a hand-edited config.json
        Question("kubernetes_node_count", "Kubernetes node count", 2, kind="int", advanced=True,
                 validate=lambda v: None if int(v) >= 1 else "AKS needs at least one node (a whole number >= 1)"),
        Question("kubernetes_public_endpoint", "Expose the Kubernetes API publicly (restricted to your IP; changing it later "
                 "re-creates the cluster)?", False, kind="bool", advanced=True),
        Question("enable_vpn", "Create a VPN host (OpenVPN or Tailscale) for private-network access?", False, kind="bool"),
        Question("vpn_type", "VPN type: openvpn (self-contained, client certs) or tailscale (subnet router, needs TS_AUTHKEY)",
                 "openvpn", choices=("openvpn", "tailscale")),
    ]

    # The same checks as data, for the web console (it cannot run the Python validators): question -> (a regex that is
    # valid in JavaScript too, what the answer must be), and question -> names Azure refuses (compared case-insensitively).
    answer_patterns = {
        "subscription_id": (_GUID.pattern, "an Azure subscription ID: a GUID such as 00000000-0000-0000-0000-000000000000 "
                                           "(az account show --query id -o tsv)"),
    }
    answer_reserved = {"admin_username": tuple(sorted(RESERVED_ADMIN_NAMES))}

    outputs = [
        "resource_group_name", "location", "vnet_id", "public_subnet_id", "private_subnet_id", "nat_public_ip",
        "bastion_public_ip", "bastion_vm_id", "bastion_instance_id", "log_analytics_workspace_id", "ssh_user",
        "kubernetes_external_secrets_client_id", "kubernetes_external_dns_client_id", "kubernetes_velero_client_id",
        "kubernetes_velero_storage_account", "kubernetes_velero_container", "kubernetes_node_resource_group", "tenant_id", "subscription_id", "fips_mode",
        "kubernetes_cluster_name", "kubernetes_endpoint", "vpn_public_ip", "vpn_instance_id", "vpn_type", "vpn_port",
    ]
    bootstrap_outputs = ["resource_group_name", "storage_account_name", "container_name"]

    def ssh_user(self, cfg):
        return cfg["vars"].get("admin_username", "azureuser")

    # ---- location ----
    @property
    def default_region(self) -> str:
        """eastus, or a location of the sovereign cloud ARM_ENVIRONMENT selects (eastus would only be refused there)."""
        return {"usgovernment": "usgovvirginia", "china": "chinanorth3"}.get(arm_cloud() or "", "eastus")

    def region_problem(self, value) -> str | None:
        """cli._region_problem's hook, after the format check: the location must exist in the Azure cloud Terraform
        targets (ARM_ENVIRONMENT). See location_problem."""
        return location_problem(value)

    # ---- tags ----
    def tag_problem(self, key: str, value: str) -> str | None:
        """Azure's own tag rules on top of the generic ones: a name without < > % & \\ ? / or control characters
        (InvalidTagNameCharacters otherwise fails the first resource at apply time) of at most 128 characters (every
        tag also lands on a storage account), a value of at most 256. An emptied tag (--tag KEY=, which removes a
        saved one) renders nothing, so only the generic rules apply to it."""
        problem = super().tag_problem(key, value)
        if problem or value in (None, ""):
            return problem
        bad = sorted(set(_TAG_NAME_BAD.findall(key)))
        if bad:
            what = " ".join(c for c in bad if c.isprintable())
            if not all(c.isprintable() for c in bad):
                what = f"{what} or control characters" if what else "control characters"
            fixed = re.sub(r"-{2,}", "-", _TAG_NAME_BAD.sub("-", key)).strip("-") or "name"
            return (f"Azure tag names cannot contain {what} (it refuses < > % & \\ ? / and control characters); use "
                    f". - _ or : instead, e.g. --tag {fixed}={value}")
        if len(key) > TAG_NAME_MAX:
            return (f"the tag name has {len(key)} characters; Azure allows at most {TAG_NAME_MAX} on a storage account, "
                    "and every tag also lands on the environment's storage accounts (remote state, Velero)")
        if len(value) > TAG_VALUE_MAX:
            return f"the tag value has {len(value)} characters; Azure allows at most {TAG_VALUE_MAX}"
        return None

    def tags_problems(self, cfg: dict) -> list[str]:
        """The generic whole-map rules (keys that differ only in case), plus Azure's limit of 50 tags on a resource:
        cloudseed sets 7 of them itself (Project, Environment, Owner, ManagedBy, CloudseedEnv, CloudseedEnvId, and Role
        on the VMs), so at most 43 other --tag names; azurerm would otherwise refuse the plan. With a private AKS cluster
        the limit is 15 tags in all (PRIVATE_DNS_TAGS_MAX): cloudseed's 6 on the cluster leave 9 --tag names, and more
        would only fail the cluster's creation, after the network is built."""
        problems = super().tags_problems(cfg)
        builtin = {k.lower() for k in _BUILTIN_TAGS}
        extra = sorted({str(k).strip().lower() for k, v in (cfg.get("tags") or {}).items()
                        if v not in (None, "")} - builtin)
        # a private AKS cluster carries every environment tag (Role is only on the VMs) and copies them onto its private
        # DNS zone: the stricter limit is the one to report. Counted as rendered: cloudseed's own that are set, plus the
        # user's other names (Project/Environment/Owner in any spelling only change a value).
        tags = self.tags({"name": "x", "env": "x", **cfg}) if self._private_cluster(cfg) else {}
        cloudseeds = {"project", "environment", "owner"} | {t.lower() for t in self.IDENTITY_TAGS}
        own = [k for k in tags if k.lower() in cloudseeds]
        room = TAGS_MAX - len(builtin)
        if len(tags) > PRIVATE_DNS_TAGS_MAX:
            problems.append(f"{len(tags) - len(own)} --tag names are too many for a private AKS cluster: AKS copies the "
                            f"cluster's tags onto its private DNS zone, which holds at most {PRIVATE_DNS_TAGS_MAX} tags, "
                            f"and cloudseed sets {len(own)} itself ({', '.join(own)}), so at most "
                            f"{PRIVATE_DNS_TAGS_MAX - len(own)} of your own; drop {len(tags) - PRIVATE_DNS_TAGS_MAX} (a "
                            "saved one with --tag KEY=)")
        elif len(extra) > room:
            problems.append(f"{len(extra)} --tag names are too many for Azure: a resource holds at most {TAGS_MAX} tags "
                            f"and cloudseed sets {len(builtin)} itself ({', '.join(_BUILTIN_TAGS)}), so at most {room} "
                            f"of your own; drop {len(extra) - room} (a saved one with --tag KEY=)")
        return problems

    @staticmethod
    def _private_cluster(cfg: dict) -> bool:
        """The configuration creates AKS with a private API endpoint (enable_kubernetes on, kubernetes_public_endpoint
        off). Saved strings are read leniently; an unreadable one counts as its default (the answer checks report it)."""
        answers = cfg.get("vars") or {}

        def on(key: str) -> bool:
            value = answers.get(key)
            if value is None or (isinstance(value, str) and not value.strip()):
                return False
            try:
                return as_bool(value)
            except ValueError:
                return False
        return on("enable_kubernetes") and not on("kubernetes_public_endpoint")

    # ---- the subscription ID ----
    # Checked wherever an answer is weighed (the prompt, which then asks again; a saved answer, reported with the flag
    # that fixes it; an env var default, see _default_subscription), so a typo is caught at the question instead of
    # after the whole wizard. Flag and --var values are checked before the first question (collect_vars below) and,
    # without a terminal, by check_vars right after the answers are collected.
    def answer_problem(self, q: Question, value, cfg: dict) -> str | None:
        problem = super().answer_problem(q, value, cfg)
        if problem is None and q.key == "subscription_id" and str(value or "").strip():
            problem = _check_subscription_id(value)
        return problem

    def collect_vars(self, args, existing: dict, cfg: dict, advanced: bool, overrides: dict | None = None) -> dict:
        """A --subscription-id / --var subscription_id that is not a GUID is refused before the first question, not
        after the user has answered every one of them (without a terminal nothing is asked, and check_vars refuses it
        right after the answers are collected)."""
        if ui.interactive():
            for given, source in ((getattr(args, "subscription_id", None), "--subscription-id "),
                                  ((overrides or {}).get("subscription_id"), "--var subscription_id=")):
                problem = _check_subscription_id(given) if str(given or "").strip() else None
                if problem:
                    raise ui.Abort(f"{source}{given}: {problem} Pass the right one with --subscription-id <GUID>.")
        return super().collect_vars(args, existing, cfg, advanced, overrides)

    def _default(self, q: Question, cfg: dict, existing: dict):
        # A blank subscription answer is _default_subscription's: the generic env lookup would skip an invalid
        # ARM_SUBSCRIPTION_ID without a word and take a valid AZURE_SUBSCRIPTION_ID instead.
        if q.key == "subscription_id" and existing.get(q.key) in (None, ""):
            return _default_subscription(cfg)
        return super()._default(q, cfg, existing)

    def check_vars(self, cfg: dict) -> None:
        """setup's final answers (prompt, flag, --var or saved): the provider and every Azure API call take the
        subscription as a GUID, and anything else would only fail once Terraform runs."""
        v = cfg["vars"]
        sub = str(v.get("subscription_id") or "").strip()
        problem = _check_subscription_id(sub) if sub else None
        if problem:
            raise ui.Abort(f"Azure subscription: {problem} Pass the right one with --subscription-id <GUID> (a blank "
                           "answer comes from ARM_SUBSCRIPTION_ID / AZURE_SUBSCRIPTION_ID, the vault or `az account show`).")
        if sub:
            v["subscription_id"] = sub

    # 4.65: azurerm_federated_identity_credential.user_assigned_identity_id (the stack's workload identities)
    AZURERM_VERSION = ">= 4.65, < 5.0"
    # The remote-state root (terraform/azure-bootstrap) needs 4.9, the first release with
    # azurerm_storage_container.storage_account_id. It stays below the stack's minimum so a state root locked to
    # 4.9-4.64 can still be destroyed without an upgrade; a lock older than 4.9 makes tf.init retry with -upgrade.
    AZURERM_BOOTSTRAP_VERSION = ">= 4.9, < 5.0"

    def required_providers(self):
        return {"azurerm": {"source": "hashicorp/azurerm", "version": self.AZURERM_VERSION},
                "random": {"source": "hashicorp/random", "version": "~> 3.6"}}

    def provider_block(self, cfg):
        return {"azurerm": {"features": {}, "subscription_id": cfg["vars"]["subscription_id"]}}

    def stack_vars(self, cfg):
        v = cfg["vars"]
        return {
            "location": cfg["region"],
            "name": cfg["name"],
            "environment": cfg["env"],
            "network_cidr": cfg["network_cidr"],
            "allowed_ssh_cidrs": cfg["allowed_ssh_cidrs"],
            "ssh_public_key": cfg["ssh_public_key"],
            "admin_username": self.ssh_user(cfg),
            "bastion_vm_size": v.get("bastion_vm_size", "Standard_B1s"),
            "enable_activity_log": self.var_bool(cfg, "enable_activity_log", True),
            "enable_defender": self.var_bool(cfg, "enable_defender", False),
            "fips_mode": self.var_bool(cfg, "fips_mode", False),
            "platform_prereqs": list(cfg.get("platform_prereqs") or []),
            "enable_kubernetes": self.var_bool(cfg, "enable_kubernetes", False),
            "kubernetes_node_size": v.get("kubernetes_node_size", "Standard_B2s"),
            "kubernetes_node_count": self._count(cfg, "kubernetes_node_count", 2, minimum=1),
            "kubernetes_public_endpoint": self.var_bool(cfg, "kubernetes_public_endpoint", False),
            "enable_vpn": self.var_bool(cfg, "enable_vpn", False),
            # one of the question's choices, as spelled there (a hand-edited "Tailscale" would fail the stack's check)
            "vpn_type": self._typed(cfg, "vpn_type", "openvpn", self.question("vpn_type").coerce),
            "tags": self.tags(cfg),
        }

    # ---- strict reading of saved answers ----
    # bool("False") and bool("no") are True in Python: a --var or a hand-edited config.json must never switch on paid
    # resources (AKS, Defender, FIPS images) that the user asked to leave off, and int("three") must not end in a
    # traceback that locks the environment. Cloud.var_bool / _typed parse strictly (unset, null or blank means the
    # default) and abort with the fix; _count's message names the minimum ("a whole number >= 1").
    def _count(self, cfg: dict, key: str, default: int, minimum: int = 0) -> int:
        def whole(value):
            try:
                return as_int(value, minimum=minimum)
            except ValueError:
                raise ValueError(f"expected a whole number >= {minimum}") from None
        return self._typed(cfg, key, default, whole)

    # ---- subscription-wide objects ----
    # Microsoft Defender plans and marketplace terms are settings of the whole subscription, not of one environment:
    # `terraform destroy` would switch Defender back to Free and cancel the Ubuntu Pro FIPS image terms for every
    # other environment and workload in the subscription. The CLI removes these addresses from the state (keeping the
    # objects) before destroying, and prints the notice.
    SHARED_RESOURCES = {
        "azurerm_security_center_subscription_pricing":
            "Microsoft Defender for Cloud (Servers, Storage) stays on for subscription {sub}: it is a subscription-wide "
            "setting other workloads may rely on. To turn it off: az security pricing create -n VirtualMachines "
            "--tier free && az security pricing create -n StorageAccounts --tier free",
        "azurerm_marketplace_agreement":
            "The Ubuntu Pro FIPS image terms stay accepted for subscription {sub} (other environments may use the "
            "image). To withdraw them: az vm image terms cancel --publisher canonical --offer "
            "0001-com-ubuntu-pro-jammy-fips --plan pro-fips-22_04-gen2",
    }

    def keep_on_destroy(self, cfg: dict, resources: list[str]) -> list[tuple[str, str]]:
        """(state address, notice) for each subscription-wide object in `resources` (terraform state list output):
        a destroy must `terraform state rm` these instead of deleting them."""
        sub = (cfg.get("vars") or {}).get("subscription_id") or "?"
        out = []
        for addr in resources:
            rtype = self._resource_type(addr)
            if rtype in self.SHARED_RESOURCES:
                out.append((addr, self.SHARED_RESOURCES[rtype].format(sub=sub)))
        return out

    @staticmethod
    def _resource_type(addr: str) -> str | None:
        """'module.stack.module.x.azurerm_foo.this["k"]' -> 'azurerm_foo'; None for data sources and modules."""
        base = addr.rsplit("[", 1)[0] if addr.endswith("]") else addr
        parts = base.split(".")
        if len(parts) < 2 or parts[-2] == "module":
            return None
        if len(parts) >= 3 and parts[-3] == "data" and (len(parts) == 3 or parts[-4] != "module"):
            return None
        return parts[-2]

    def render_bootstrap(self, cfg, tf_root):
        root = super().render_bootstrap(cfg, tf_root)
        root["terraform"]["required_providers"]["azurerm"]["version"] = self.AZURERM_BOOTSTRAP_VERSION
        return root

    def bootstrap_vars(self, cfg):
        return {"location": cfg["region"], "prefix": f"{cfg['name']}-{cfg['env']}", "tags": self.tags(cfg)}

    def backend_from_outputs(self, cfg, outputs):
        return {"azurerm": {
            "resource_group_name": outputs["resource_group_name"],
            "storage_account_name": outputs["storage_account_name"],
            "container_name": outputs["container_name"],
            "key": f"{self.key}-{cfg['env']}.tfstate",
            "subscription_id": cfg["vars"]["subscription_id"],
        }}

    def credential_warnings(self, cfg):
        env = os.environ
        if arm_credentials(env):
            return []                   # the provider authenticates with these and never runs the az CLI
        if str(env.get("ARM_USE_CLI") or "").strip().lower() in _ARM_FALSE:
            return ["ARM_USE_CLI is false, so Terraform will not use an az login, and no ARM_* credentials are set: "
                    "export ARM_CLIENT_ID + ARM_CLIENT_SECRET (or ARM_CLIENT_CERTIFICATE_PATH) + ARM_TENANT_ID, "
                    "ARM_USE_OIDC=true or ARM_USE_MSI=true, or unset ARM_USE_CLI and run az login"]
        # without ARM_* credentials the azurerm provider authenticates by running the az CLI itself
        az = deps.find("az")
        if not az:
            return ["The Azure CLI (az) is not installed and no ARM_* service-principal / managed-identity variables are "
                    "set; Terraform needs one of them: cloudseed install az && az login   (or export ARM_CLIENT_ID / "
                    "ARM_CLIENT_SECRET / ARM_TENANT_ID)"]
        # the login on disk, else what `az account show` says (cached; az may keep its login where the profile check
        # does not look): never 'no credentials' next to a login az itself reports as valid
        if az_logged_in(env) or _az_subscription(az):
            return []
        return [f"No Azure credentials detected. Log in first: {self.login_hint}"]


# ---- credential detection (shared with deps.optional_cli_note and the doctor) ----
_ARM_TRUE = ("1", "t", "true")      # how Terraform reads a boolean ARM_* variable (Go strconv.ParseBool)
_ARM_FALSE = ("0", "f", "false")


def _arm_true(environ, name: str) -> bool:
    return str(environ.get(name) or "").strip().lower() in _ARM_TRUE


def arm_credentials(environ=None) -> str | None:
    """What the azurerm provider authenticates with from ARM_* variables alone (it then never runs the az CLI), for
    messages; None when they are not enough. Mirrors the provider: a managed identity (ARM_USE_MSI=true; ARM_CLIENT_ID
    only picks a user-assigned one), AKS workload identity, or ARM_CLIENT_ID (or ARM_CLIENT_ID_FILE_PATH) with a client
    secret, a client certificate or OIDC (ARM_USE_OIDC=true: an OIDC token alone does nothing while use_oidc is off).
    Booleans are read as Terraform reads them, so ARM_USE_MSI=false or ARM_USE_OIDC=false is not a credential."""
    e = os.environ if environ is None else environ

    def has(*names):
        return any(str(e.get(n) or "").strip() for n in names)
    if _arm_true(e, "ARM_USE_MSI"):
        return "a managed identity (ARM_USE_MSI)"
    if _arm_true(e, "ARM_USE_AKS_WORKLOAD_IDENTITY"):
        return "AKS workload identity (ARM_USE_AKS_WORKLOAD_IDENTITY)"
    if not has("ARM_CLIENT_ID", "ARM_CLIENT_ID_FILE_PATH"):
        return None
    if has("ARM_CLIENT_SECRET", "ARM_CLIENT_SECRET_FILE_PATH"):
        return "a service principal secret (ARM_CLIENT_ID + ARM_CLIENT_SECRET)"
    if has("ARM_CLIENT_CERTIFICATE_PATH", "ARM_CLIENT_CERTIFICATE"):
        return "a service principal certificate (ARM_CLIENT_ID + ARM_CLIENT_CERTIFICATE_PATH)"
    if _arm_true(e, "ARM_USE_OIDC"):
        return "OpenID Connect (ARM_CLIENT_ID + ARM_USE_OIDC)"
    return None


def az_profile_path(environ=None) -> Path:
    """The az CLI's login profile: under $AZURE_CONFIG_DIR when set (as az itself reads it), else ~/.azure."""
    e = os.environ if environ is None else environ
    return Path(os.path.expanduser(str(e.get("AZURE_CONFIG_DIR") or "").strip() or "~/.azure")) / "azureProfile.json"


def az_logged_in(environ=None) -> bool:
    """An az CLI login is on disk: the profile lists at least one subscription (`az logout` leaves the file with none).
    A profile that cannot be read counts as logged in: never a false 'no credentials' warning."""
    path = az_profile_path(environ)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))     # az writes it with a byte order mark
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return path.exists()
    subs = data.get("subscriptions") if isinstance(data, dict) else None
    return not isinstance(subs, list) or bool(subs)
