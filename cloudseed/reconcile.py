"""Reconcile: make Terraform runs succeed when a resource already exists outside the state - but only adopt what is
provably this environment's.

Two mechanisms:
  * preflight(): for per-cluster singletons (the EKS OIDC provider), look up the existing object with the cloud CLI and
    import it before applying. Account-wide singletons (the GuardDuty detector, Security Hub, Microsoft Defender for
    Cloud) are never adopted: destroying this environment, or switching the feature off in it, would then turn off
    something it never created, for the whole account/region/subscription. The run stops before anything changes
    (SingletonExists, which names the variable that leaves the singleton alone). The one exception: a Defender plan
    this environment's own earlier destroy left on (recorded in cfg["kept_shared"] by remember_kept()) is its own again.
    The same stop applies to an account-level IAM Access Analyzer that exists under another name (AWS allows one per
    region: creating this environment's would fail halfway through the apply).
  * recover(): after an apply fails with an "already exists"-class error, map every failing resource address to an
    import id (from the planned values + resource-type rules), check that the existing object carries this
    environment's tags (CloudseedEnv + Owner, or CloudseedEnvId), `terraform import` it, and let the caller retry.
    Objects owned by another environment/user are never adopted; objects whose owner cannot be read are adopted only
    with consent (an interactive yes, or CLOUDSEED_ADOPT=1). Untagged account-wide objects that a destroy only forgets
    (service-linked roles, marketplace image terms) are adopted as they are. An object that another address of the same
    plan maps to as well is never adopted (two addresses would manage one object).
"""

from __future__ import annotations

import json
import os
import re
import subprocess

from . import deps, ui
from .tf import TerraformError

# resource type -> how to build the import id from the planned attributes (and, when needed, the cloud CLI)
IMPORT_ID = {
    "aws_iam_role": lambda v, c: v.get("name"),
    "aws_iam_instance_profile": lambda v, c: v.get("name"),
    "aws_iam_policy": lambda v, c: c.aws_iam_policy_arn(v.get("name")),
    "aws_key_pair": lambda v, c: v.get("key_name"),
    "aws_cloudwatch_log_group": lambda v, c: v.get("name"),
    "aws_kms_alias": lambda v, c: v.get("name"),
    "aws_s3_bucket": lambda v, c: v.get("bucket"),
    "aws_guardduty_detector": lambda v, c: c.aws_guardduty_detector(),
    # only when Security Hub is already on in this account/region (never imported: NEVER_ADOPT; the id is for the message)
    "aws_securityhub_account": lambda v, c: c.aws_securityhub_hub(),
    "aws_accessanalyzer_analyzer": lambda v, c: v.get("analyzer_name"),
    "aws_cloudtrail": lambda v, c: v.get("name"),
    "aws_eks_cluster": lambda v, c: v.get("name"),
    "aws_eks_node_group": lambda v, c: f"{v.get('cluster_name')}:{v.get('node_group_name')}",
    "aws_iam_openid_connect_provider": lambda v, c: c.aws_oidc_arn(v.get("url")),
    "aws_security_group": lambda v, c: c.aws_sg_id(v.get("name"), v.get("vpc_id")),
    "aws_iam_account_password_policy": lambda v, c: "iam-account-password-policy",
    "aws_s3_account_public_access_block": lambda v, c: c.aws_account_id(),
    "aws_ebs_encryption_by_default": lambda v, c: "default",
    "aws_iam_service_linked_role": lambda v, c: c.aws_service_linked_role_arn(v.get("aws_service_name")),
    "google_service_account": lambda v, c: f"projects/{v.get('project')}/serviceAccounts/{v.get('account_id')}@{v.get('project')}.iam.gserviceaccount.com",
    "google_compute_network": lambda v, c: f"projects/{v.get('project')}/global/networks/{v.get('name')}",
    "google_compute_firewall": lambda v, c: f"projects/{v.get('project')}/global/firewalls/{v.get('name')}",
    "google_compute_address": lambda v, c: f"projects/{v.get('project')}/regions/{v.get('region')}/addresses/{v.get('name')}",
    "google_compute_router": lambda v, c: f"projects/{v.get('project')}/regions/{v.get('region')}/routers/{v.get('name')}",
    "google_storage_bucket": lambda v, c: v.get("name"),
    "google_container_cluster": lambda v, c: f"projects/{v.get('project')}/locations/{v.get('location')}/clusters/{v.get('name')}",
    "azurerm_resource_group": lambda v, c: f"/subscriptions/{c.sub}/resourceGroups/{v.get('name')}",
    "azurerm_user_assigned_identity": lambda v, c: f"/subscriptions/{c.sub}/resourceGroups/{v.get('resource_group_name')}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{v.get('name')}",
    "azurerm_log_analytics_workspace": lambda v, c: f"/subscriptions/{c.sub}/resourceGroups/{v.get('resource_group_name')}/providers/Microsoft.OperationalInsights/workspaces/{v.get('name')}",
    "azurerm_storage_account": lambda v, c: f"/subscriptions/{c.sub}/resourceGroups/{v.get('resource_group_name')}/providers/Microsoft.Storage/storageAccounts/{v.get('name')}",
    # the Ubuntu Pro FIPS image terms, accepted once per subscription (a second FIPS environment adopts them)
    "azurerm_marketplace_agreement": lambda v, c: (f"/subscriptions/{c.sub}/providers/Microsoft.MarketplaceOrdering/agreements/"
                                                   f"{v.get('publisher')}/offers/{v.get('offer')}/plans/{v.get('plan')}") if c.sub else None,
    # only when Defender is already on (the pricing always exists; the provider refuses to create it over Standard)
    "azurerm_security_center_subscription_pricing": lambda v, c: c.azure_defender_pricing(v.get("resource_type")),
}

# Account/region-wide objects: never imported into an environment (destroy would switch them off for everyone).
NEVER_ADOPT = {
    "aws_guardduty_detector": "GuardDuty is already enabled in this account/region (not by this environment); cloudseed "
                              "leaves it alone. Re-run with --var enable_guardduty=false.",
    "aws_securityhub_account": "Security Hub is already enabled in this account/region; re-run with --var enable_security_hub=false.",
    # adopting it would let a later enable_defender=false in this environment switch the whole subscription's Defender off
    "azurerm_security_center_subscription_pricing": "Microsoft Defender for Cloud is already on for this subscription "
                                                    "(enabled outside this environment's state: by another environment, "
                                                    "by hand or by policy); it stays on. Re-run with "
                                                    "--var enable_defender=false.",
}
# NEVER_ADOPT objects a full or targeted destroy only forgets (clouds/*.keep_on_destroy): the id they keep, so that
# re-creating the environment (setup, apply, cs undo) adopts what it left on itself instead of refusing it
_KEPT_ID = {
    "azurerm_security_center_subscription_pricing":
        lambda key, cfg: (f"/subscriptions/{(cfg.get('vars') or {}).get('subscription_id')}/providers/Microsoft.Security/"
                          f"pricings/{key}") if key and (cfg.get("vars") or {}).get("subscription_id") else None,
}
# the variable that stops an environment from creating each NEVER_ADOPT / _REGION_ONE object (the exact re-run command)
DISABLE_VAR = {"aws_guardduty_detector": "enable_guardduty", "aws_securityhub_account": "enable_security_hub",
               "azurerm_security_center_subscription_pricing": "enable_defender",
               "aws_accessanalyzer_analyzer": "enable_access_analyzer"}


def _other_account_analyzer(values: dict, lookups: "CloudLookups"):
    """An account-level IAM Access Analyzer of this region under ANOTHER name than the planned one (AWS allows one per
    region, so creating ours would fail after half the stack was applied), or None - also when the analyzers cannot
    be listed (no aws CLI, credentials or permission: the check is skipped). One with the planned name is left to
    recover(), which adopts it when its tags say it is this environment's (its state was lost)."""
    if str(values.get("type") or "ACCOUNT").upper() != "ACCOUNT":
        return None
    names = lookups.aws_account_analyzers()
    mine = str(values.get("analyzer_name") or "")
    others = [n for n in names or [] if n != mine]
    return others[0] if others else None


# Region-wide objects the account can have only one of, that another name may already hold: checked before the apply
# (never adopted: another environment's or the account's own), with the variable that leaves them alone (DISABLE_VAR)
_REGION_ONE = {"aws_accessanalyzer_analyzer": _other_account_analyzer}
_REGION_ONE_TEXT = {
    "aws_accessanalyzer_analyzer": lambda names, cfg: (
        f"An account-level IAM Access Analyzer ({names}) already exists in {cfg.get('region') or 'this region'} (AWS "
        "allows one per region); re-run with --var enable_access_analyzer=false."),
}
# Account-wide objects that are adopted without an ownership check: they carry no owner tags, and a full destroy
# forgets them instead of deleting them (aws/azure keep_on_destroy), so adopting one never takes it away from anyone.
ADOPT_SHARED = ("aws_iam_service_linked_role", "azurerm_marketplace_agreement")
# Adopted before the apply, after a lookup that proves the object exists: objects that are unique to this environment's
# own cluster, and the service-linked role. (The marketplace agreement's id needs no lookup, so it is only adopted by
# recover(), once the apply has proved that it exists.)
PREFLIGHT_TYPES = ("aws_iam_openid_connect_provider", "aws_iam_service_linked_role")

CONFLICT_RE = re.compile(r"already ?exists?|AlreadyExists|AlreadyOwnedByYou|a detector already exists|ResourceExistsError|"
                         r"\.Duplicate\b|alreadyExists|has been taken|already subscribed", re.I)
ADDR_RE = re.compile(r"with ((?:module\.[\w-]+(?:\[[^\]]+\])?\.)*(?:data\.)?[\w-]+\.[\w-]+(?:\[[^\]]+\])?)")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_GUTTER = re.compile(r"(?m)^[ \t]*[│╷╵][ \t]?")


def plain(output: str) -> str:
    """Terraform output as plain text: no ANSI colours, no diagnostic box gutter (terminal runs are coloured)."""
    return _GUTTER.sub("", _ANSI.sub("", output or ""))


class SingletonExists(TerraformError):
    """The plan would create account/region/subscription-wide singletons that already exist and are not this
    environment's (never adopted). Nothing was applied. `disable` maps each variable that leaves one alone to False;
    `auto` is True when the user never asked for any of them explicitly (they are on by default, as GuardDuty is), so a
    caller that can render the stack again may switch_off() and plan again instead of stopping."""

    def __init__(self, message: str, disable: dict, auto: bool, found: list, owner=None):
        super().__init__(message)
        self.disable, self.auto, self.found, self._owner = dict(disable), bool(auto), list(found), owner

    def switch_off(self, cfg: dict) -> list:
        """Save the variables that leave the existing singletons alone into cfg["extra_vars"]; returns the lines to
        show (what exists, who it belongs to when its tags say so, and the saved variable)."""
        cfg.setdefault("extra_vars", {}).update(self.disable)
        lines = []
        for rtype, addr, ids in self.found:
            var = DISABLE_VAR.get(rtype)
            if not var:
                continue
            owner = ""
            if self._owner is not None:
                try:
                    owner = self._owner(rtype, addr, ids[0]) or ""
                except Exception:  # noqa: BLE001 - who owns it is a detail, never a failure
                    owner = ""
            lines.append(f"{_SINGLETON_NAME.get(rtype, rtype)} ({', '.join(ids)}{owner}) -> this environment leaves it "
                         f"alone ({var}=false saved with the environment)")
        return lines


_SINGLETON_NAME = {
    "aws_guardduty_detector": "GuardDuty is already enabled in this account/region",
    "aws_securityhub_account": "Security Hub is already enabled in this account/region",
    "azurerm_security_center_subscription_pricing": "Microsoft Defender for Cloud is already on for this subscription",
    "aws_accessanalyzer_analyzer": "An account-level IAM Access Analyzer already exists in this region",
}


def _explicit_on(cfg: dict, var: str) -> bool:
    """The user asked for `var` (a --var or an answered question set it true), as opposed to a stack default."""
    for src in ("extra_vars", "vars"):
        v = (cfg.get(src) or {}).get(var)
        if v is not None:
            return v is True or str(v).strip().lower() in ("true", "1", "yes", "on")
    return False


class CloudLookups:
    """Small cloud-CLI lookups used to compute import ids, and to read who owns an existing object."""

    def __init__(self, cloud_key: str, cfg: dict):
        self.cloud_key, self.cfg = cloud_key, cfg
        self.sub = cfg.get("vars", {}).get("subscription_id", "")
        self._aws = deps.find("aws")
        self._profile = cfg.get("vars", {}).get("profile")
        self._account: str | None = None
        self._partition: str | None = None
        self._env: dict | None = None

    def _cli_env(self) -> dict:
        """The cloud CLIs' environment: in AWS FIPS mode every lookup goes to the FIPS endpoints, as the Terraform
        provider's calls do (services.cloud_cli_env)."""
        if self._env is None:
            view = dict(self.cfg, vars={**(self.cfg.get("vars") or {}), **(self.cfg.get("extra_vars") or {})})
            try:
                from . import services
                self._env = services.cloud_cli_env(self.cloud_key, view)
            except Exception:  # noqa: BLE001 - never worse than the plain tool PATH
                self._env = deps.path_env()
                fips = view["vars"].get("fips_mode")
                if self.cloud_key == "aws" and (fips is True or str(fips).strip().lower() in ("true", "1", "yes", "on")):
                    self._env["AWS_USE_FIPS_ENDPOINT"] = "true"
        return self._env

    def _run_json(self, cmd: list[str], timeout: int = 60) -> dict | list | None:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, env=self._cli_env(), timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if p.returncode != 0:
            return None
        try:
            return json.loads(p.stdout or "{}")
        except ValueError:
            return None

    def _awscli(self, *args: str):
        if not self._aws:
            return None
        cmd = [self._aws, *args, "--output", "json", "--region", self.cfg.get("region", "us-east-1")]
        if self._profile:
            cmd += ["--profile", self._profile]
        return self._run_json(cmd)

    def _gcloud(self, *args: str):
        g = deps.find("gcloud")
        return self._run_json([g, *args, "--format=json"]) if g else None

    def _az(self, *args: str):
        a = deps.find("az")
        return self._run_json([a, *args, "-o", "json"], timeout=120) if a else None

    def _caller(self) -> None:
        """Account id and partition of the caller (asked once per lookup object: every IAM policy id needs them)."""
        if self._account is None:
            d = self._awscli("sts", "get-caller-identity")
            d = d if isinstance(d, dict) else {}
            self._account = str(d.get("Account") or "")
            arn = str(d.get("Arn") or "").split(":")
            # arn:<partition>:sts::<account>:assumed-role/...: aws, aws-us-gov (GovCloud), aws-cn, aws-iso, ...
            self._partition = arn[1] if len(arn) > 1 and arn[0] == "arn" and arn[1] else "aws"

    def aws_account_id(self):
        self._caller()
        return self._account or None

    def aws_partition(self) -> str:
        """The caller's AWS partition ("aws", "aws-us-gov", "aws-cn", ...); "aws" when it cannot be read."""
        self._caller()
        return self._partition or "aws"

    def azure_defender_pricing(self, resource_type):
        """Id of the subscription's Defender pricing for `resource_type` when it is already Standard (on), else None."""
        if not resource_type or not self.sub:
            return None
        d = self._az("security", "pricing", "show", "--name", resource_type, "--subscription", self.sub)
        if not isinstance(d, dict) or str(d.get("pricingTier") or "").lower() != "standard":
            return None
        return d.get("id") or f"/subscriptions/{self.sub}/providers/Microsoft.Security/pricings/{resource_type}"

    def aws_guardduty_detector(self):
        d = self._awscli("guardduty", "list-detectors")
        return ((d or {}).get("DetectorIds") or [None])[0]

    def aws_securityhub_hub(self):
        """The hub ARN when Security Hub is already on in this account/region, else None (describe-hub fails with
        InvalidAccessException "not subscribed"; a missing CLI, credentials or permission is None too)."""
        d = self._awscli("securityhub", "describe-hub")
        return d.get("HubArn") if isinstance(d, dict) and d.get("HubArn") else None

    def aws_oidc_arn(self, url):
        d = self._awscli("iam", "list-open-id-connect-providers")
        host = (url or "").replace("https://", "")
        for p in (d or {}).get("OpenIDConnectProviderList", []):
            if host and host in p.get("Arn", ""):
                return p["Arn"]
        return None

    def aws_iam_policy_arn(self, name):
        acct = self.aws_account_id()
        return f"arn:{self.aws_partition()}:iam::{acct}:policy/{name}" if acct and name else None

    def aws_account_analyzers(self) -> list | None:
        """Names of this region's account-level IAM Access Analyzers (the region allows one); None when they cannot be
        listed (no aws CLI, no credentials or permission)."""
        d = self._awscli("accessanalyzer", "list-analyzers", "--type", "ACCOUNT")
        if not isinstance(d, dict):
            return None
        return [str(a.get("name")) for a in d.get("analyzers") or [] if isinstance(a, dict) and a.get("name")]

    def aws_service_linked_role_arn(self, service):
        """ARN of the account's existing service-linked role for `service` (e.g. config.amazonaws.com), or None."""
        if not service:
            return None
        d = self._awscli("iam", "list-roles", "--path-prefix", f"/aws-service-role/{service}/")
        roles = (d or {}).get("Roles", [])
        return roles[0]["Arn"] if roles else None

    def aws_sg_id(self, name, vpc_id):
        if not name or not vpc_id:
            return None
        d = self._awscli("ec2", "describe-security-groups", "--filters", f"Name=group-name,Values={name}", f"Name=vpc-id,Values={vpc_id}")
        groups = (d or {}).get("SecurityGroups", [])
        return groups[0]["GroupId"] if groups else None

    # ---- ownership: the tags/labels of an existing object (None = could not be read) ----
    def tags(self, rtype: str, v: dict, ident: str) -> dict | None:
        try:
            return self._tags(rtype, v, str(ident))
        except Exception:  # noqa: BLE001 - an unreadable owner is "unknown", never a crash
            return None

    @staticmethod
    def _kv(items, k="Key", val="Value") -> dict:
        return {t.get(k): t.get(val) for t in (items or []) if isinstance(t, dict) and t.get(k)}

    def _tags(self, rtype: str, v: dict, ident: str) -> dict | None:
        a = self._awscli
        if rtype == "aws_iam_role":
            d = a("iam", "list-role-tags", "--role-name", ident)
            return None if d is None else self._kv(d.get("Tags"))
        if rtype == "aws_iam_instance_profile":
            d = a("iam", "list-instance-profile-tags", "--instance-profile-name", ident)
            return None if d is None else self._kv(d.get("Tags"))
        if rtype == "aws_iam_policy":
            d = a("iam", "list-policy-tags", "--policy-arn", ident)
            return None if d is None else self._kv(d.get("Tags"))
        if rtype == "aws_iam_openid_connect_provider":
            d = a("iam", "list-open-id-connect-provider-tags", "--open-id-connect-provider-arn", ident)
            return None if d is None else self._kv(d.get("Tags"))
        if rtype == "aws_key_pair":
            d = a("ec2", "describe-key-pairs", "--key-names", ident)
            pairs = (d or {}).get("KeyPairs") or []
            return self._kv(pairs[0].get("Tags")) if pairs else None
        if rtype == "aws_security_group":
            d = a("ec2", "describe-security-groups", "--group-ids", ident)
            groups = (d or {}).get("SecurityGroups") or []
            return self._kv(groups[0].get("Tags")) if groups else None
        if rtype == "aws_cloudwatch_log_group":
            d = a("logs", "list-tags-log-group", "--log-group-name", ident)
            return None if d is None else dict(d.get("tags") or {})
        if rtype == "aws_kms_alias":
            d = a("kms", "list-aliases")
            key = next((x.get("TargetKeyId") for x in (d or {}).get("Aliases", []) if x.get("AliasName") == ident), None)
            if not key:
                return None
            t = a("kms", "list-resource-tags", "--key-id", key)
            return None if t is None else self._kv(t.get("Tags"), "TagKey", "TagValue")
        if rtype == "aws_s3_bucket":
            if not self._aws:
                return None
            cmd = [self._aws, "s3api", "get-bucket-tagging", "--bucket", ident, "--output", "json"] + \
                (["--profile", self._profile] if self._profile else [])
            p = subprocess.run(cmd, capture_output=True, text=True, env=self._cli_env(), timeout=60)
            if p.returncode != 0:
                return {} if "NoSuchTagSet" in (p.stderr or "") else None
            return self._kv(json.loads(p.stdout or "{}").get("TagSet"))
        if rtype == "aws_accessanalyzer_analyzer":
            d = a("accessanalyzer", "get-analyzer", "--analyzer-name", ident)
            return None if d is None else dict((d.get("analyzer") or {}).get("tags") or {})
        if rtype == "aws_cloudtrail":
            d = a("cloudtrail", "describe-trails", "--trail-name-list", ident)
            trails = (d or {}).get("trailList") or []
            if not trails:
                return None
            t = a("cloudtrail", "list-tags", "--resource-id-list", trails[0].get("TrailARN", ident))
            lst = (t or {}).get("ResourceTagList") or []
            return self._kv(lst[0].get("TagsList")) if lst else ({} if t is not None else None)
        if rtype == "aws_guardduty_detector":
            d = a("guardduty", "get-detector", "--detector-id", ident)
            return None if d is None else dict(d.get("Tags") or {})
        if rtype == "aws_eks_cluster":
            d = a("eks", "describe-cluster", "--name", ident)
            return None if d is None else dict((d.get("cluster") or {}).get("tags") or {})
        if rtype == "aws_eks_node_group":
            cluster, _, ng = ident.partition(":")
            d = a("eks", "describe-nodegroup", "--cluster-name", cluster, "--nodegroup-name", ng)
            return None if d is None else dict((d.get("nodegroup") or {}).get("tags") or {})
        if rtype == "google_compute_address":
            d = self._gcloud("compute", "addresses", "describe", v.get("name", ""), f"--region={v.get('region')}", f"--project={v.get('project')}")
            return None if d is None else dict(d.get("labels") or {})
        if rtype == "google_storage_bucket":
            d = self._gcloud("storage", "buckets", "describe", f"gs://{ident}")
            return None if d is None else dict(d.get("labels") or d.get("default_labels") or {})
        if rtype == "google_container_cluster":
            d = self._gcloud("container", "clusters", "describe", v.get("name", ""), f"--location={v.get('location')}", f"--project={v.get('project')}")
            return None if d is None else dict(d.get("resourceLabels") or {})
        if rtype == "azurerm_resource_group":
            d = self._az("group", "show", "--name", v.get("name", ""))
            return None if d is None else dict(d.get("tags") or {})
        if rtype.startswith("azurerm_") and ident.startswith("/subscriptions/"):
            d = self._az("resource", "show", "--ids", ident)
            return None if d is None else dict(d.get("tags") or {})
        return None   # no tags on this type (GCP service accounts, networks, firewalls, ...)


def expected_tags(cloud_key: str, cfg: dict) -> dict:
    """The ownership tags this environment puts on everything (lower-cased keys), incl. CloudseedEnvId when it has one."""
    try:
        from . import clouds
        tags = clouds.get(cloud_key).tags(cfg)
    except Exception:  # noqa: BLE001 - a partial cfg (tests, old envs): fall back to the documented scheme
        tags = {"CloudseedEnv": f"{cloud_key}-{cfg.get('env', '')}", "Owner": cfg.get("owner", "")}
    out = {k.lower(): str(v) for k, v in tags.items() if k.lower() in ("cloudseedenv", "owner", "cloudseedenvid") and v}
    if cfg.get("uid") and "cloudseedenvid" not in out:
        out["cloudseedenvid"] = str(cfg["uid"])
    return out


def ownership(tags: dict | None, expected: dict) -> tuple[str, str]:
    """('mine' | 'other' | 'unknown', who) for an existing object's tags."""
    if tags is None:
        return "unknown", "its tags could not be read"
    t = {str(k).lower(): str(v) for k, v in tags.items()}
    who = ", ".join(f"{k}={t[k]}" for k in ("cloudseedenv", "owner", "cloudseedenvid") if t.get(k)) or "no cloudseed tags"
    if t.get("cloudseedenvid"):     # created by an environment with a unique id: only that one owns it
        return ("mine", who) if t["cloudseedenvid"] == expected.get("cloudseedenvid") else ("other", who)
    if not t.get("cloudseedenv") or t.get("cloudseedenv") != expected.get("cloudseedenv"):
        return "other", who
    if expected.get("owner") and t.get("owner") != expected.get("owner"):
        return "other", who
    return "mine", who


def _consent(addr: str, ident: str, why: str) -> bool:
    if os.environ.get("CLOUDSEED_ADOPT") == "1":
        return True
    if ui.interactive():
        return ui.confirm(f"{addr} already exists ({ident}) and cloudseed cannot tell whether this environment created it "
                          f"({why}). Adopt it into this environment? Destroying the environment later deletes it.",
                          default=False)
    ui.warn(f"{addr} already exists ({ident}) and its owner cannot be verified ({why}); not adopting it. If it is this "
            f"environment's (e.g. its state was lost), re-run with CLOUDSEED_ADOPT=1; otherwise use another --name/--env.")
    return False


def planned_values(tf, planfile: str = "tfplan") -> dict[str, dict]:
    """address -> planned attribute values (from `terraform show -json tfplan`)."""
    proc = tf.run("show", "-json", planfile, capture=True, check=False)
    if proc.returncode != 0:
        return {}
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return {}
    out: dict[str, dict] = {}

    def walk(mod):
        for r in mod.get("resources", []):
            out[r["address"]] = {"type": r.get("type"), "values": r.get("values") or {}}
        for child in mod.get("child_modules", []):
            walk(child)

    walk(((data.get("planned_values") or {}).get("root_module")) or {})
    return out


def conflicts(output: str) -> list[str]:
    """Resource addresses that failed with an already-exists class error, parsed from terraform's output
    (plain or coloured: interactive runs print boxed, ANSI-coloured diagnostics)."""
    found: list[str] = []
    for block in re.split(r"\n(?=Error: )", "\n" + plain(output)):
        if not block.startswith("Error: ") or not CONFLICT_RE.search(block):
            continue
        m = ADDR_RE.search(block)
        if m and m.group(1) not in found and not m.group(1).startswith("data."):
            found.append(m.group(1))
    return found


# an id built from planned values that are not known yet ("projects/None/...") names nothing
_UNKNOWN_PART = re.compile(r"(?:^|[/:@])None(?:[/:@.]|$)")
_DATA_ADDR = re.compile(r"(?:^|\.)data\.")


def _import_id(info: dict, lookups: CloudLookups):
    rule = IMPORT_ID.get(info.get("type"))
    if not rule:
        return None
    try:
        ident = rule(info.get("values") or {}, lookups)
    except Exception:  # noqa: BLE001 - an id that cannot be built is "unknown", never a crash
        return None
    return ident if ident and not _UNKNOWN_PART.search(str(ident)) else None


def recover(tf, cloud_key: str, cfg: dict, output: str, planned: dict[str, dict]) -> list[str]:
    """Import every conflicting resource that is provably this environment's; returns the imported addresses.

    An object is never imported when another address of the plan maps to the same cloud id (two addresses would then
    manage one object: e.g. truncated GCP service-account ids that collide), nor twice in one call."""
    lookups = CloudLookups(cloud_key, cfg)
    expected = expected_tags(cloud_key, cfg)
    imported: list[str] = []
    ids: dict[str, object] = {}          # address -> import id (built once: some rules ask the cloud CLI)
    taken: dict[tuple, str] = {}         # (type, id) -> the address it was imported as in this call

    def ident_of(address: str):
        if address not in ids:
            ids[address] = _import_id(planned[address], lookups)
        return ids[address]

    for addr in conflicts(output):
        info = planned.get(addr)
        if not info:
            ui.warn(f"{addr} already exists but is not in the plan output; import it manually.")
            continue
        if info["type"] in NEVER_ADOPT:
            kept = _kept_id(cfg, addr)
            if kept and (info["type"], kept.lower()) not in taken:
                # left on by this environment's own earlier destroy: its id is known without asking the cloud CLI
                ui.info(f"{addr} was left on by an earlier destroy of this environment -> adopting it again "
                        f"(terraform import {kept})")
                proc = tf.run("import", "-input=false", addr, kept, capture=True, check=False)
                if proc.returncode == 0:
                    imported.append(addr)
                    taken[(info["type"], kept.lower())] = addr
                else:
                    ui.warn(f"import failed for {addr}: {(proc.stderr or proc.stdout).strip()[-300:]}")
                continue
            ui.warn(f"{addr}: {NEVER_ADOPT[info['type']]}")
            continue
        if not IMPORT_ID.get(info["type"]):
            ui.warn(f"{addr} ({info['type']}) already exists; no import rule for this type yet -> terraform import {addr} <id>")
            continue
        ident = ident_of(addr)
        if not ident:
            ui.warn(f"{addr} already exists but its id could not be determined; import it manually.")
            continue
        key = (info["type"], str(ident))
        if key in taken:
            ui.warn(f"{addr} already exists ({ident}), but that object was just adopted as {taken[key]}; not adopting it "
                    "twice. Give the two resources distinct names (e.g. a shorter --name/--env).")
            continue
        twins = [a for a, i in planned.items()
                 if a != addr and i.get("type") == info["type"] and not _DATA_ADDR.search(a)
                 and str(ident_of(a) or "") == str(ident)]
        if twins:
            ui.warn(f"{addr} already exists ({ident}), but {', '.join(twins)} in this plan names the same object; not "
                    "adopting it (two resources would manage one object). Give them distinct names (e.g. a shorter "
                    "--name/--env).")
            continue
        if info["type"] in ADOPT_SHARED:
            verdict, who = "mine", "account-wide, kept on destroy"
        else:
            verdict, who = ownership(lookups.tags(info["type"], info["values"], ident), expected)
        if verdict == "other":
            ui.warn(f"{addr} already exists ({ident}) but belongs to someone else ({who}); not adopting it. "
                    f"Use a different --name/--env, or remove the other object.")
            continue
        if verdict == "unknown" and not _consent(addr, str(ident), who):
            continue
        ui.info(f"{addr} exists already and is this environment's -> adopting it (terraform import {ident})")
        proc = tf.run("import", "-input=false", addr, str(ident), capture=True, check=False)
        if proc.returncode == 0:
            imported.append(addr)
            taken[key] = addr
        else:
            ui.warn(f"import failed for {addr}: {(proc.stderr or proc.stdout).strip()[-300:]}")
    return imported


def _resource_type(addr: str) -> str | None:
    """'module.stack.module.x.azurerm_foo.this["k"]' -> 'azurerm_foo'; None for data sources and module addresses."""
    base = addr.rsplit("[", 1)[0] if addr.endswith("]") else addr
    parts = base.split(".")
    if len(parts) < 2 or parts[-2] == "module" or (len(parts) >= 3 and parts[-3] == "data"):
        return None
    return parts[-2]


def _instance_key(addr: str) -> str | None:
    """The for_each key of an address: 'x.this["VirtualMachines"]' -> 'VirtualMachines'."""
    m = re.search(r'\["([^"\]]+)"\]$', addr)
    return m.group(1) if m else None


def _kept_id(cfg: dict, addr: str) -> str | None:
    kept = cfg.get("kept_shared") or {}
    ident = kept.get(addr) if isinstance(kept, dict) else None
    return str(ident) if ident else None


def remember_kept(cfg: dict, addresses) -> bool:
    """Record in cfg["kept_shared"] the never-adopted singletons a destroy leaves in place instead of deleting (the
    addresses it `terraform state rm`s, e.g. both Defender plans): re-creating this environment then adopts exactly
    those again. Returns True when cfg changed (the caller saves it before the destroy runs)."""
    changed = False
    for addr in addresses:
        rtype = _resource_type(addr)
        build = _KEPT_ID.get(rtype)
        ident = build(_instance_key(addr), cfg) if build else None
        if ident:
            kept = cfg.setdefault("kept_shared", {})
            if kept.get(addr) != ident:
                kept[addr] = ident
                changed = True
    return changed


def settle_kept(cfg: dict, state_addresses) -> bool:
    """Forget cfg["kept_shared"] entries that no longer matter: the object is back in the state, or the feature is
    switched off in this environment (a later re-enable must not adopt what someone else turned on meanwhile). Call it
    after a successful apply; returns True when cfg changed (save it)."""
    kept = cfg.get("kept_shared")
    if not isinstance(kept, dict) or not kept:
        return False
    state = set(state_addresses or ())
    drop = [a for a in kept if a in state or (DISABLE_VAR.get(_resource_type(a) or "") and
                                               _var_off(cfg, DISABLE_VAR[_resource_type(a)]))]
    for a in drop:
        kept.pop(a, None)
    if not kept:
        cfg.pop("kept_shared", None)
    return bool(drop)


def _var_off(cfg: dict, var: str) -> bool:
    for src in ("extra_vars", "vars"):
        v = (cfg.get(src) or {}).get(var)
        if v is not None:
            return v is False or str(v).strip().lower() in ("false", "0", "no", "off")
    return False


def preflight(tf, cloud_key: str, cfg: dict, planned: dict[str, dict]) -> list[str]:
    """Before apply: adopt per-cluster singletons that already exist (avoids the error entirely), and stop - before
    anything is changed - when the plan would create account-wide singletons that already exist (SingletonExists,
    naming every one of them and the variables that leave them alone)."""
    wanted = [(a, i) for a, i in planned.items()
              if i["type"] in PREFLIGHT_TYPES or i["type"] in NEVER_ADOPT or i["type"] in _REGION_ONE]
    if not wanted:
        return []
    lookups = CloudLookups(cloud_key, cfg)
    state = set(tf.state_list())
    imported: list[str] = []
    found: dict = {}                     # NEVER_ADOPT / _REGION_ONE type -> [(address, existing id)]
    for addr, info in wanted:
        if addr in state:
            continue
        if info["type"] in _REGION_ONE:
            other = _REGION_ONE[info["type"]](info.get("values") or {}, lookups)
            if other:
                found.setdefault(info["type"], []).append((addr, other))
            continue
        ident = _import_id(info, lookups)
        if not ident:
            continue
        if info["type"] in NEVER_ADOPT:
            kept = _kept_id(cfg, addr)
            if kept and kept.lower() == str(ident).lower():
                ui.info(f"{addr} was left on by an earlier destroy of this environment -> adopting it again ({ident})")
                if tf.run("import", "-input=false", addr, str(ident), capture=True, check=False).returncode == 0:
                    imported.append(addr)
                continue
            found.setdefault(info["type"], []).append((addr, str(ident)))
            continue
        ui.info(f"{info['type']} already exists for this cluster -> adopting {ident} as {addr}")
        if tf.run("import", "-input=false", addr, str(ident), capture=True, check=False).returncode == 0:
            imported.append(addr)
    if found:
        _stop_for_singletons(lookups, cloud_key, cfg, planned, found)
    return imported


def _stop_for_singletons(lookups: CloudLookups, cloud_key: str, cfg: dict, planned: dict, found: dict) -> None:
    parts, disable, hits_out = [], {}, []
    for rtype, hits in found.items():
        ids = list(dict.fromkeys(i for _, i in hits))
        if rtype in _REGION_ONE_TEXT:
            parts.append(_REGION_ONE_TEXT[rtype](", ".join(ids), cfg))
        else:
            parts.append(f"{NEVER_ADOPT[rtype]} (existing: {', '.join(ids)}).")
        hits_out.append((rtype, hits[0][0], ids))
        var = DISABLE_VAR.get(rtype)
        if var:
            disable[var] = False
    env = cfg.get("env")
    again = (f"cloudseed setup {cloud_key} --env {env} " + " ".join(f"--var {v}=false" for v in disable)) \
        if env and disable else ""
    expected = expected_tags(cloud_key, cfg)

    def owner(rtype: str, addr: str, ident: str) -> str:
        """'; <its cloudseed tags>' for a detector cloudseed created (asked only when the caller shows it)."""
        if rtype != "aws_guardduty_detector":
            return ""
        tags = lookups.tags(rtype, (planned.get(addr) or {}).get("values") or {}, ident)
        if not tags:
            return ""
        verdict, who = ownership(tags, expected)
        return "; tagged as this environment's: its state was probably lost" if verdict == "mine" else f"; {who}"

    raise SingletonExists(" ".join(parts) + " Nothing was applied." + (f"\n  Fix: {again}" if again else ""),
                          disable, auto=bool(disable) and not any(_explicit_on(cfg, v) for v in disable),
                          found=hits_out, owner=owner)
