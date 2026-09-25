from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import unicodedata
from pathlib import Path

from .. import ui
from .base import Cloud, Question, as_bool, as_int   # value parsers; Cloud.var_bool / var_int read cfg["vars"]

# Stack defaults for the EKS node group bounds (terraform/aws/variables.tf kubernetes_node_min / kubernetes_node_max).
NODE_MIN_DEFAULT = 1
NODE_MAX_DEFAULT = 4

# EC2 instance types: family[generation][attributes].size, e.g. t3.micro, m7g.2xlarge, u-6tb1.56xlarge, r7iz.metal-16xl
_INSTANCE_TYPE = re.compile(r"[a-z][a-z0-9-]*\.[a-z0-9][a-z0-9-]*")


def _instance_type(value: str) -> str | None:
    return None if _INSTANCE_TYPE.fullmatch(value.strip()) else \
        f"'{value}' is not an EC2 instance type (lowercase family.size, e.g. t3.micro or m7g.large)."


def _saved_bool(value, default: bool) -> bool:
    """A saved yes/no answer as Cloud.var_bool reads it: missing, null or blank is the default; ValueError otherwise
    when it is not a yes/no."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    return as_bool(value)


def _regional_default(cfg: dict) -> bool:
    """The regional half of the security baseline follows the account-wide answer unless set: an existing second
    environment in the same account and region (baseline off, saved before the split) keeps managing nothing. A
    missing, blank or unreadable account answer means its default (on), as Cloud.var_bool reads it."""
    try:
        return _saved_bool((cfg.get("vars") or {}).get("enable_account_baseline"), True)
    except ValueError:
        return True


_REGIONAL_BASELINE = Question(
    "enable_regional_baseline",
    "Manage this region's security baseline (EBS encryption by default, GuardDuty, IAM Access Analyzer)? "
    "Yes in ONE env per account AND region (also in a second env that is alone in its region)",
    # its default is the account-wide answer (a form showing the default, such as the web console, follows it)
    _regional_default, kind="bool", follows="enable_account_baseline")


# Regions of the partitions the stack is not built for: China (aws-cn) and the isolated ones (aws-iso, aws-iso-b, ...).
_UNSUPPORTED_REGION = re.compile(r"cn-.*|.*-iso[a-z]*-.*")
_ACCOUNT_ID = re.compile(r"\d{12}")
# settings of each half of the security baseline that only take effect while that half is managed here
_REGIONAL_SETTINGS = ("enable_guardduty", "enable_access_analyzer", "enable_aws_config")
_ACCOUNT_SETTINGS = ("enable_cloudtrail",)
# the baseline's log bucket is '<name>-<env>-cloudtrail-<12-digit account id>' and S3 names are at most 63 characters
_LOG_BUCKET_PREFIX_MAX = 63 - len("-cloudtrail-") - 12

# --tag rules: the provider's default_tags put every tag on every resource, including IAM roles, S3 buckets, log groups
# and the GuardDuty detector, and the first service that refuses one fails the apply part-way. Keys and values: IAM's
# (and CloudWatch Logs') set - letters, digits, spaces and _ . : / = + - @ - keys 1-128 characters, values at most 256;
# 'aws:' is reserved by AWS. Every other tagged service of the stack (EC2, S3, KMS, EKS, SQS, CloudTrail, EventBridge,
# Access Analyzer) accepts at least that. GuardDuty alone takes fewer characters in a key (ASCII letters, digits and
# _ . : / = + -: no spaces, no @, no other letters): tags_problems applies them where this environment creates the
# detector (the regional baseline with enable_guardduty on), so a 'Cost Center' works everywhere else.
_TAG_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:/=+-")   # GuardDuty's
_TAG_VALUE_PUNCT = frozenset("_.:/=+-@")
_TAG_KEY_MAX, _TAG_VALUE_MAX = 128, 256


def _tag_value_char(ch: str) -> bool:
    """IAM's tag set (keys and values): any Unicode letter, number or separator (space) - its \\p{L} \\p{N} \\p{Z} - and
    _ . : / = + - @."""
    return unicodedata.category(ch)[0] in "LNZ" or ch in _TAG_VALUE_PUNCT


def _shown_chars(chars) -> str:
    """The characters a tag may not hold, readably (a space is invisible in quotes)."""
    names = {" ": "space", "\t": "tab"}
    return ", ".join(names.get(c, repr(c)) for c in dict.fromkeys(chars))


def _guardduty_key(key: str) -> str:
    """A tag key GuardDuty accepts that reads like `key`: 'Cost Center' -> 'Cost-Center', 'Équipe' -> 'Equipe'; ""
    when none is left that AWS takes (nothing ASCII, or only the reserved 'aws:' prefix)."""
    text = unicodedata.normalize("NFKD", key.strip()).encode("ascii", "ignore").decode()     # (accents dropped)
    text = re.sub(r"-{2,}", "-", "".join(c if c in _TAG_KEY_CHARS else "-" for c in text)).strip("-")
    text = text[:_TAG_KEY_MAX].rstrip("-")          # (NFKD can lengthen a key: 'ﬁ' -> 'fi')
    return "" if text.lower().startswith("aws:") else text


class AWS(Cloud):
    key = "aws"
    display = "Amazon Web Services"
    region_prompt = "AWS region"
    default_region = "us-east-1"
    region_env = ("AWS_REGION", "AWS_DEFAULT_REGION")
    cli_tool = "aws"
    login_hint = "aws configure   (or: aws sso login / export AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)"

    questions = [
        Question("profile", "AWS CLI profile to use (blank = default credential chain)", "", env=("AWS_PROFILE",)),
        Question("enable_account_baseline",
                 "Manage the account-wide security baseline (multi-region CloudTrail, S3 account public-access block, "
                 "IAM password policy)? Yes in ONE env per AWS account", True, kind="bool"),
        _REGIONAL_BASELINE,
        # (EKS's two-AZ minimum depends on enable_kubernetes, asked later: check_vars refuses it)
        Question("az_count", "Number of availability zones (1-5; EKS needs 2+)", 2, kind="int", advanced=True,
                 minimum=1, maximum=5),
        Question("single_nat_gateway", "Use a single NAT gateway (cheaper) instead of one per AZ", True,
                 kind="bool", advanced=True),
        Question("bastion_instance_type", "Bastion instance type", "t3.micro", advanced=True, validate=_instance_type),
        # part of the regional baseline: not asked while that is off (it keeps its saved or built-in value)
        Question("enable_security_hub", "Enable Security Hub (part of the regional baseline; FSBP standard; also turns on "
                 "AWS Config recording, billed per item)", False, kind="bool", advanced=True,
                 depends_on="enable_regional_baseline"),
        Question("fips_mode", "FIPS 140 mode (FIPS endpoints, FIPS bastion and EKS nodes, FIPS-only SSH/TLS)?", False, kind="bool"),
        Question("enable_kubernetes", "Create a private managed Kubernetes cluster (EKS) in the private subnets?", False, kind="bool"),
        # the cluster's own settings follow its switch (asked only when a cluster is wanted), then the VPN's
        Question("kubernetes_node_size", "Kubernetes node size", "t3.medium", advanced=True, validate=_instance_type),
        # at least one node: the CoreDNS and EBS CSI add-ons wait for one (kubernetes_node_min may still be 0)
        Question("kubernetes_node_count", "Kubernetes node count", 2, kind="int", advanced=True, minimum=1),
        Question("kubernetes_public_endpoint", "Expose the Kubernetes API publicly (restricted to your IP)?", False, kind="bool", advanced=True),
        Question("enable_vpn", "Create a VPN host (OpenVPN or Tailscale) for private-network access?", False, kind="bool"),
        Question("vpn_type", "VPN type: openvpn (self-contained, client certs) or tailscale (subnet router, needs TS_AUTHKEY)",
                 "openvpn", choices=("openvpn", "tailscale")),
    ]

    outputs = [
        "account_id", "region", "vpc_id", "vpc_cidr", "public_subnet_ids", "private_subnet_ids",
        "data_subnet_ids", "nat_public_ips", "bastion_public_ip", "bastion_instance_id",
        "bastion_security_group_id", "workload_security_group_id", "kms_key_arn", "cloudtrail_bucket", "ssh_user",
        "kubernetes_cluster_name", "kubernetes_node_group_name", "kubernetes_endpoint", "vpn_public_ip", "vpn_instance_id",
        "vpn_type", "vpn_port",
        "kubernetes_node_role_arn", "kubernetes_oidc_issuer", "kubernetes_irsa_role_arns", "kubernetes_oidc_provider_arn",
        "kubernetes_velero_bucket", "kubernetes_karpenter_queue", "kubernetes_karpenter_node_role", "kubernetes_cluster_security_group_id", "fips_mode",
    ]
    bootstrap_outputs = ["bucket", "region"]

    # Account-wide settings the security baseline writes with Put-style APIs over whatever the account already had.
    # Deleting them does not restore the earlier values, it switches the protection off for the whole account (S3
    # public-access block, EBS encryption by default, password policy), and the AWS Config service-linked role is
    # shared by every recorder in the account. A full destroy therefore leaves them in place and only forgets them.
    KEEP_ON_DESTROY = ("aws_s3_account_public_access_block", "aws_ebs_encryption_by_default",
                       "aws_iam_account_password_policy", "aws_iam_service_linked_role")
    _ADDRESS = re.compile(r"^((?:module\.[\w-]+(?:\[[^\]]*\])?\.)*)([\w-]+)\.")

    def tag_problem(self, key: str, value: str) -> str | None:
        """The generic rules, then AWS's own (see _TAG_KEY_CHARS; GuardDuty's narrower key set depends on the
        configuration: tags_problems). An emptied tag (--tag KEY=) is only checked by the generic rules: it is never
        rendered, and it is the way to drop a saved tag an older version accepted."""
        problem = super().tag_problem(key, value)
        if problem or value in (None, ""):
            return problem
        value = str(value)
        if key.lower().startswith("aws:"):
            return "tag keys starting with 'aws:' are reserved by AWS"
        if len(key) > _TAG_KEY_MAX:
            return f"AWS tag keys are at most {_TAG_KEY_MAX} characters (this one has {len(key)})"
        bad = [c for c in key if not _tag_value_char(c)]
        if bad:
            return (f"an AWS tag key may only hold letters, digits, spaces and _ . : / = + - @ (IAM and S3 refuse "
                    f"others), not {_shown_chars(bad)}")
        if len(value) > _TAG_VALUE_MAX:
            return f"AWS tag values are at most {_TAG_VALUE_MAX} characters (this one has {len(value)})"
        bad = [c for c in value if not _tag_value_char(c)]
        if bad:
            return (f"an AWS tag value may only hold letters, digits, spaces and _ . : / = + - @ (IAM and S3 refuse "
                    f"others), not {_shown_chars(bad)}")
        return None

    @staticmethod
    def manages_guardduty(cfg: dict) -> bool:
        """This environment creates the GuardDuty detector: the regional baseline is on (by default it follows the
        account-wide answer) and enable_guardduty (a stack variable, default true) is not switched off. Saved strings
        are read leniently; an unreadable one counts as its default (reported by the answer checks)."""
        answers, extra = cfg.get("vars") or {}, cfg.get("extra_vars") or {}

        def on(value, default: bool) -> bool:
            try:
                return _saved_bool(value, default)
            except ValueError:
                return default
        regional = on(answers.get("enable_regional_baseline"), on(answers.get("enable_account_baseline"), True))
        return regional and on(extra.get("enable_guardduty"), True)

    def tags_problems(self, cfg: dict) -> list[str]:
        """The generic whole-map rules, plus GuardDuty's key set where this environment creates the detector: it gets
        every tag (default_tags) and refuses a key with a space, an @ or a letter outside A-Z/a-z, failing the apply
        once the network already exists. Elsewhere IAM's set applies (tag_problem)."""
        problems = super().tags_problems(cfg)
        if not self.manages_guardduty(cfg):
            return problems
        reserved = {t.lower() for t in self.IDENTITY_TAGS}
        for k, v in (cfg.get("tags") or {}).items():
            key = str(k)
            if v in (None, "") or key.strip().lower() in reserved or self.tag_problem(key, str(v)):
                continue                  # emptied (not rendered), cloudseed's own, or refused by tag_problem already
            bad = [c for c in key if c not in _TAG_KEY_CHARS]
            if bad:
                other = _guardduty_key(key)
                drop = f"a saved one is dropped with --tag {shlex.quote(key + '=')}"
                rename = f"e.g. --tag {shlex.quote(f'{other}={v}')}; {drop}" if other else drop
                problems.append(f"--tag {k}={v}: this environment creates the GuardDuty detector, which gets every tag "
                                "and takes only the letters A-Z and a-z, digits and _ . : / = + - in a tag key, not "
                                f"{_shown_chars(bad)}. Rename the tag ({rename}), or leave GuardDuty to another "
                                "environment or tool: --var enable_guardduty=false")
        return problems

    def keep_on_destroy(self, cfg: dict, resources: list[str]) -> list[tuple[str, str]]:
        """State addresses a full destroy must forget instead of deleting (see KEEP_ON_DESTROY). No extra notice:
        destroy already lists the kept settings."""
        keep = []
        for address in resources:
            m = self._ADDRESS.match(address)
            if m and ".security_baseline[" in "." + m.group(1) and m.group(2) in self.KEEP_ON_DESTROY:
                keep.append((address, ""))
        return keep

    def ssh_user(self, cfg):
        # Bastion (Amazon Linux 2023) and VPN host (Ubuntu, whose default user cloud-init renames) both log in as ec2-user.
        return "ec2-user"

    def required_providers(self):
        # (no http provider: the load balancer controller's IAM policy is vendored in the kubernetes module)
        return {"aws": {"source": "hashicorp/aws", "version": "~> 6.0"},
                "random": {"source": "hashicorp/random", "version": "~> 3.6"},
                "tls": {"source": "hashicorp/tls", "version": "~> 4.0"}}

    def provider_block(self, cfg):
        block = {"region": cfg["region"], "default_tags": {"tags": self.tags(cfg)}}
        if cfg["vars"].get("profile"):
            block["profile"] = cfg["vars"]["profile"]
        if self.var_bool(cfg, "fips_mode", False):
            block["use_fips_endpoint"] = True   # every AWS API call goes to the FIPS 140 validated endpoints
        account = self.deployed_account(cfg)
        if account:
            # Terraform refuses ("AWS account ID not allowed") to plan with credentials of another account: without the
            # pin, a changed default profile would read every resource as gone, re-create the environment there and
            # leave the original resources running untracked (with local state; a remote state bucket already refuses).
            block["allowed_account_ids"] = [account]
        return {"aws": block}

    @staticmethod
    def _local_state(cfg: dict) -> dict:
        """The stack's state file when the environment keeps local state (with remote state the file is at most a
        leftover from before the migration)."""
        if (cfg.get("state") or {}).get("type") != "local" or not cfg.get("workdir"):
            return {}
        try:
            state = json.loads((Path(cfg["workdir"]) / "stack" / "terraform.tfstate").read_text())
        except (TypeError, OSError, ValueError):
            return {}
        return state if isinstance(state, dict) else {}

    @staticmethod
    def _cached_outputs(cfg: dict) -> dict:
        if not cfg.get("workdir"):      # a probe or half-built config: never a file of the current directory
            return {}
        try:
            outputs = json.loads((Path(cfg["workdir"]) / "outputs.json").read_text())
        except (TypeError, OSError, ValueError):
            return {}
        return outputs if isinstance(outputs, dict) else {}

    def _has_resources(self, cfg: dict) -> bool:
        """Best effort, from local files (as cli._env_has_resources, which also decides whether the region may still
        change): may the stack hold resources now? Every Terraform run records the resource count it left behind in
        inventory.json; the cached outputs and a local state count too. Unknown (no working directory, an unreadable
        inventory) counts as deployed."""
        workdir = cfg.get("workdir")
        if not workdir:
            return True
        if self._cached_outputs(cfg) or self._local_state(cfg).get("resources"):
            return True
        try:
            inventory = json.loads((Path(workdir) / "inventory.json").read_text())
        except FileNotFoundError:
            return False                    # no Terraform run has recorded anything for this environment
        except (OSError, ValueError):
            return True
        history = inventory.get("history") if isinstance(inventory, dict) else None
        for entry in reversed(history if isinstance(history, list) else []):
            count = entry.get("resources") if isinstance(entry, dict) else None
            if isinstance(count, int) and not isinstance(count, bool):
                return count > 0
        return False

    def deployed_account(self, cfg: dict) -> str | None:
        """The AWS account this environment's resources live in, as far as it is known here: the cached outputs
        (outputs.json: written by every apply, status and output; removed by a full destroy), else the local state
        (also after a first apply that failed before its outputs were cached; a remote state bucket refuses other
        accounts by itself). None when nothing is deployed, so a new or fully destroyed environment may go to any
        account."""
        candidates = [self._cached_outputs(cfg).get("account_id")]
        state = self._local_state(cfg)
        output = (state.get("outputs") or {}).get("account_id")
        candidates.append(output.get("value") if isinstance(output, dict) else None)
        for res in state.get("resources") or []:
            if isinstance(res, dict) and res.get("type") == "aws_caller_identity" and res.get("mode") == "data":
                for inst in res.get("instances") or []:
                    candidates.append(((inst or {}).get("attributes") or {}).get("account_id"))
        return next((str(c) for c in candidates if c is not None and _ACCOUNT_ID.fullmatch(str(c))), None)

    def deployed_az_count(self, cfg: dict) -> int | None:
        """How many availability zones the deployed network spans (its public subnets), from the cached outputs or a
        local state; None when unknown."""
        subnets = self._cached_outputs(cfg).get("public_subnet_ids")
        if not subnets:
            output = (self._local_state(cfg).get("outputs") or {}).get("public_subnet_ids")
            subnets = output.get("value") if isinstance(output, dict) else None
        return len(subnets) if isinstance(subnets, list) and subnets else None

    def subnet_stride(self, cfg: dict) -> int:
        """The subnet layout's stride (terraform/aws/variables.tf subnet_stride): pinned by setup to the AZ count of
        the first deployment (check_vars); an environment saved before that uses its az_count, as it always did."""
        for value in (cfg.get("subnet_stride"), (cfg.get("vars") or {}).get("az_count", 2)):
            try:
                if value not in (None, ""):
                    return min(as_int(value, minimum=1), 5)
            except ValueError:
                continue
        return 2

    def collect_vars(self, args, existing, cfg, advanced, *more, **kwargs):
        # A saved regional-baseline answer equal to the saved account-wide one was following it (the default): it
        # follows a changed account-wide answer again. Only a deliberate difference (an environment alone in its
        # region: account half off, regional half on) is kept as it was.
        existing = dict(existing or {})
        if "enable_regional_baseline" in existing and "enable_account_baseline" in existing:
            try:     # (a blank saved answer is its default: on for both halves)
                follows = _saved_bool(existing["enable_regional_baseline"], True) == \
                    _saved_bool(existing["enable_account_baseline"], True)
            except ValueError:
                follows = False
            if follows:
                existing.pop("enable_regional_baseline")
        return super().collect_vars(args, existing, cfg, advanced, *more, **kwargs)

    def managed_vars(self, cfg: dict | None = None) -> dict[str, str]:
        out = super().managed_vars(cfg)
        if "subnet_stride" in out:
            out["subnet_stride"] = ("--var az_count (the subnet layout is pinned to the AZ count of the first deployment; "
                                    "AZs added later get new subnets and no existing subnet moves)")
        return out

    def _node_bounds(self, cfg: dict) -> dict:
        """kubernetes_node_count, plus the node group max stack_vars must set. EKS rejects a node group whose size is
        outside min..max. When only the count was chosen (wizard or --var), widen the default max to include it, as
        `cs node add` does; explicit bounds (--var) always win. The minimum is never lowered to fit a count: a node group
        needs at least one node when it is created (the question and check_vars refuse 0), so the default minimum of 1
        always fits, and kubernetes_node_min=0 is only ever an explicit choice. Needs only the answers, so setup can
        check them (check_vars) before the SSH key exists."""
        node_count = self.var_int(cfg, "kubernetes_node_count", 2)
        extra = cfg.get("extra_vars") or {}
        bounds = {"kubernetes_node_count": node_count}
        if node_count > NODE_MAX_DEFAULT and "kubernetes_node_max" not in extra:
            bounds["kubernetes_node_max"] = node_count
        return bounds

    def stack_vars(self, cfg):
        v = cfg["vars"]
        bounds = self._node_bounds(cfg)
        out = {
            "name": cfg["name"],
            "environment": cfg["env"],
            "vpc_cidr": cfg["network_cidr"],
            "allowed_ssh_cidrs": cfg["allowed_ssh_cidrs"],
            "ssh_public_key": cfg["ssh_public_key"],
            "az_count": self.var_int(cfg, "az_count", 2, minimum=1),
            "subnet_stride": self.subnet_stride(cfg),
            "single_nat_gateway": self.var_bool(cfg, "single_nat_gateway", True),
            "bastion_instance_type": v.get("bastion_instance_type", "t3.micro"),
            "enable_account_baseline": self.var_bool(cfg, "enable_account_baseline", True),
            "enable_regional_baseline": self.var_bool(cfg, "enable_regional_baseline",
                                                      self.var_bool(cfg, "enable_account_baseline", True)),
            "enable_security_hub": self.var_bool(cfg, "enable_security_hub", False),
            "fips_mode": self.var_bool(cfg, "fips_mode", False),
            "platform_prereqs": list(cfg.get("platform_prereqs") or []),
            "enable_kubernetes": self.var_bool(cfg, "enable_kubernetes", False),
            "kubernetes_node_size": v.get("kubernetes_node_size", "t3.medium"),
            "kubernetes_node_count": bounds.pop("kubernetes_node_count"),
            "kubernetes_public_endpoint": self.var_bool(cfg, "kubernetes_public_endpoint", False),
            "enable_vpn": self.var_bool(cfg, "enable_vpn", False),
            "vpn_type": v.get("vpn_type", "openvpn"),
            "tags": self.tags(cfg),
        }
        out.update(bounds)      # kubernetes_node_max widened to the count (see _node_bounds)
        return out

    def check_vars(self, cfg: dict) -> None:
        """Run by setup once every answer is final: refuses what the stack's variable validations reject at plan time
        (EKS only fails at CreateCluster / CreateNodegroup, well into an apply), so `setup --dry-run` and the wizard
        catch it too; warns about baseline settings that have no effect; pins the subnet layout."""
        self._check(cfg, notify=True)

    def _check(self, cfg: dict, notify: bool) -> None:
        env = cfg.get("env", "<env>")
        region = str(cfg.get("region") or "")
        if _UNSUPPORTED_REGION.fullmatch(region):
            raise ui.Abort(f"Region {region} is not supported: cloudseed's AWS stack is built for the commercial regions "
                           "and GovCloud (us-gov-east-1, us-gov-west-1); AWS China and the isolated regions differ in "
                           "service principals, endpoints and images. Pick another region with --region.")
        az_count = self.var_int(cfg, "az_count", 2, minimum=1)
        if notify:
            self._pin_subnet_layout(cfg, az_count)
            self._baseline_notes(cfg)
        if not self.var_bool(cfg, "enable_kubernetes", False):
            return
        if az_count < 2:
            raise ui.Abort(f"EKS needs subnets in at least two availability zones, but az_count={az_count}. "
                           f"Re-run with: cloudseed setup aws --env {env} --var az_count=2")
        bounds = self._node_bounds(cfg)
        extra = cfg.get("extra_vars") or {}
        count = bounds["kubernetes_node_count"]
        if count < 1:
            raise ui.Abort(f"kubernetes_node_count={count}: an EKS node group needs at least one node when it is created "
                           "(the CoreDNS and EBS CSI add-ons wait for one and the apply fails). Re-run with: cloudseed "
                           f"setup aws --env {env} --var kubernetes_node_count=1   (kubernetes_node_min may stay 0 so the "
                           "autoscaler can scale down later)")
        low = extra.get("kubernetes_node_min")
        high = extra.get("kubernetes_node_max")
        try:     # (null / blank: the stack's default, or the max widened to the count)
            low = NODE_MIN_DEFAULT if low in (None, "") else as_int(low)
            high = bounds.get("kubernetes_node_max", NODE_MAX_DEFAULT) if high in (None, "") else as_int(high)
        except ValueError:
            raise ui.Abort(f"kubernetes_node_min/kubernetes_node_max must be whole numbers >= 0 (got {low!r}/{high!r}). "
                           f"Fix them with: cloudseed setup aws --env {env} --var kubernetes_node_min=N "
                           "--var kubernetes_node_max=N") from None
        if not low <= count <= high:
            raise ui.Abort(f"kubernetes_node_count={count} is outside kubernetes_node_min..kubernetes_node_max ({low}..{high}). "
                           f"Change the count, or the bounds with --var kubernetes_node_min=N / --var kubernetes_node_max=N")

    def prepare(self, cfg: dict, dry_run: bool = False) -> None:
        self._check(cfg, notify=False)     # setup already ran check_vars (its notes are not repeated)

    def _pin_subnet_layout(self, cfg: dict, az_count: int) -> None:
        """Remember the subnet layout of the first deployment: the AZ count the environment is deployed with (legacy
        environments: what the cached outputs / local state show), else the AZ count chosen now. It follows az_count
        while nothing is deployed (a dry run or a cancelled first setup, a full destroy); once resources may exist it is
        never re-pinned, so an az_count change only adds or removes the subnets of the AZs concerned."""
        deployed = self.deployed_az_count(cfg)
        if cfg.get("subnet_stride") in (None, "") or not self._has_resources(cfg):
            cfg["subnet_stride"] = deployed or az_count
        if deployed and deployed != az_count:
            state_output = (self._local_state(cfg).get("outputs") or {}).get("kubernetes_node_group_name")
            node_group = self._cached_outputs(cfg).get("kubernetes_node_group_name") or \
                (state_output.get("value") if isinstance(state_output, dict) else None)
            eks = " The EKS node group moves to the new set of private subnets, so Terraform replaces it (new " \
                  "nodes): check the plan." if node_group and self.var_bool(cfg, "enable_kubernetes", False) else ""
            ui.info(f"az_count {deployed} -> {az_count}: the existing subnets stay where they are; "
                    + ("the new AZ(s) get subnets of their own." if az_count > deployed else
                       f"the subnets of the last {deployed - az_count} AZ(s) are removed (a delete fails while "
                       "something still runs in them).") + eks)

    def _baseline_notes(self, cfg: dict) -> None:
        """Settings of a baseline half this environment does not manage have no effect: say so (a warning, not a
        refusal, so an environment that handed the baseline to another one keeps working with its saved answers)."""
        env, region = cfg.get("env", "<env>"), cfg.get("region", "this region")
        account = self.var_bool(cfg, "enable_account_baseline", True)
        regional = self.var_bool(cfg, "enable_regional_baseline", account)
        extra = cfg.get("extra_vars") or {}

        def explicit(keys):
            on = []
            for key in keys:
                try:
                    if key in extra and as_bool(extra[key]):
                        on.append(key)
                except ValueError:
                    pass
            return on

        if not regional:
            idle = (["enable_security_hub"] if self.var_bool(cfg, "enable_security_hub", False) else []) + explicit(_REGIONAL_SETTINGS)
            if idle:
                many = len(idle) > 1
                ui.warn(f"{', '.join(k + '=true' for k in idle)} {'have' if many else 'has'} no effect: "
                        f"{'they are' if many else 'it is'} part of the regional security baseline, which {env} does not "
                        f"manage (enable_regional_baseline=false). Turn {'them' if many else 'it'} on in the environment "
                        f"that manages {region}'s baseline, or here with: cloudseed setup aws --env {env} "
                        "--var enable_regional_baseline=true")
        if not account:
            idle = explicit(_ACCOUNT_SETTINGS)
            if idle:
                ui.warn(f"{', '.join(k + '=true' for k in idle)} has no effect: CloudTrail is part of the account-wide "
                        f"security baseline, which {env} does not manage (enable_account_baseline=false). Turn it on in "
                        "the environment that manages the account-wide baseline.")
        if not account and not regional:
            ui.info(f"{env} manages no security baseline: another environment must manage the account-wide one and "
                    f"{region}'s (EBS encryption by default, GuardDuty). If no other environment is in {region}, "
                    f"re-run with: cloudseed setup aws --env {env} --var enable_regional_baseline=true")

    def bootstrap_vars(self, cfg):
        return {"prefix": f"{cfg['name']}-{cfg['env']}", "tags": self.tags(cfg)}

    def check_config(self, cfg: dict) -> list[str]:
        """Adds the name length AWS Config's log bucket needs in an environment that manages only the regional half of
        the baseline: '<prefix>-cloudtrail-<account id>' must fit S3's 63 characters. (setup sizes the prefix for the
        CloudTrail bucket when the account-wide half is on, and for EKS names, which are shorter still.)"""
        problems = super().check_config(cfg)
        answers, extra = cfg.get("vars") or {}, cfg.get("extra_vars") or {}

        def flag(value, default):
            try:
                return default if value in (None, "") else as_bool(value)
            except ValueError:
                return default          # reported by the answer / Terraform variable checks

        account = flag(answers.get("enable_account_baseline"), True)
        config = flag(extra.get("enable_aws_config"), flag(answers.get("enable_security_hub"), False))
        prefix = f"{cfg.get('name', '')}-{cfg.get('env', '')}"
        if (not account and config and flag(answers.get("enable_regional_baseline"), account)
                and not flag(answers.get("enable_kubernetes"), False) and len(prefix) > _LOG_BUCKET_PREFIX_MAX):
            problems.append(f"'{prefix}' ({len(prefix)} characters) is too long a name prefix on AWS: at most "
                            f"{_LOG_BUCKET_PREFIX_MAX} with these settings, because of AWS Config's log bucket "
                            "'<prefix>-cloudtrail-<account id>' (63 characters). Shorten --name or --env.")
        return problems

    def network_problems(self, cfg):
        """AWS VPCs are IPv4 /16-/28 and every subnet (VPC prefix + subnet_newbits) must be /28 or larger; each AZ
        gets a public, a private and (optionally) a data subnet, laid out as the network module does (subnet_stride).
        A subnet_newbits / create_data_subnets override that is not a number / a yes-no is reported here (blank or
        null: the stack's default); an unreadable az_count is reported by its own question check."""
        try:
            net = ipaddress.ip_network(str(cfg.get("network_cidr")), strict=True)
        except ValueError:
            return [f"network CIDR {cfg.get('network_cidr')!r} is not a valid network (fix: --cidr 10.0.0.0/16)"]
        extra, answers = cfg.get("extra_vars") or {}, cfg.get("vars") or {}

        def given(value) -> bool:
            return not (value is None or (isinstance(value, str) and not value.strip()))

        newbits, data_subnets = extra.get("subnet_newbits"), extra.get("create_data_subnets")
        try:     # (the stack's own check: terraform/aws/variables.tf subnet_newbits, 1-12)
            newbits = as_int(newbits, minimum=1) if given(newbits) else 4
        except ValueError:
            return [f"subnet_newbits={newbits!r} must be a whole number between 1 and 12 (fix: --var subnet_newbits=4)"]
        try:
            tiers = 3 if (as_bool(data_subnets) if given(data_subnets) else True) else 2
        except ValueError:
            return [f"create_data_subnets={data_subnets!r} must be true or false (fix: --var create_data_subnets=true)"]
        try:
            azs = as_int(answers["az_count"], minimum=1) if given(answers.get("az_count")) else 2
        except ValueError:
            return []   # reported by the question check (check_config: invalid_answers)
        largest = 28 - newbits
        if largest < 16:
            return [f"subnet_newbits={newbits} is too large: even a /16 VPC (AWS's largest) would get /{16 + newbits} "
                    "subnets, and AWS's smallest subnet is /28; use at most 12 (fix: --var subnet_newbits=4)"]
        if net.version != 4 or net.prefixlen < 16 or net.prefixlen > largest:
            return [f"network CIDR {net}: an AWS VPC needs an IPv4 range from /16 to /{largest} (subnets are "
                    f"/{net.prefixlen}+{newbits} bits and AWS's smallest subnet is /28); fix: --cidr 10.N.0.0/16"]
        needed = subnet_blocks(azs, self.subnet_stride(cfg), tiers)
        if 2 ** newbits < needed:
            layout = "" if needed == tiers * azs else \
                f" (the subnet layout of this environment's first {self.subnet_stride(cfg)} AZ(s) is kept)"
            return [f"{azs} availability zones x {tiers} subnet tiers need {needed} subnets{layout}, but "
                    f"subnet_newbits={newbits} only makes {2 ** newbits}; raise --var subnet_newbits or lower --var az_count"]
        return []

    def backend_from_outputs(self, cfg, outputs):
        backend = {"bucket": outputs["bucket"], "key": f"{self.key}-{cfg['env']}/terraform.tfstate",
                   "region": outputs.get("region") or cfg["region"], "encrypt": True, "use_lockfile": True}
        if cfg["vars"].get("profile"):
            backend["profile"] = cfg["vars"]["profile"]
        if self.var_bool(cfg, "fips_mode", False):
            backend["use_fips_endpoint"] = True
        return {"s3": backend}

    def credential_warnings(self, cfg):
        home = Path.home()
        if os.environ.get("AWS_ACCESS_KEY_ID") or cfg["vars"].get("profile") or os.environ.get("AWS_PROFILE"):
            return []
        if (home / ".aws" / "credentials").exists() or (home / ".aws" / "config").exists():
            return []
        return [f"No AWS credentials detected. Log in first: {self.login_hint}"]


def subnet_blocks(azs: int, stride: int, tiers: int = 3) -> int:
    """How many cidrsubnet() blocks the network module's layout uses (terraform/aws/modules/network: the first
    `stride` AZs at tier*stride + i, every later AZ three blocks of its own): the highest block number + 1."""
    def block(tier: int, i: int) -> int:
        return tier * stride + i if i < stride else 3 * stride + 3 * (i - stride) + tier
    return max(block(tier, i) for tier in range(tiers) for i in range(azs)) + 1
