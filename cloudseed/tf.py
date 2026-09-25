"""Thin wrapper around the terraform binary."""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

from . import audit, deps, paths, secrets, ui


class TerraformError(RuntimeError):
    pass


# (regex on terraform output, human explanation, fix). explain() returns the FIRST match, so specific entries come
# before generic ones (e.g. "az is not installed" before "az login", throttling before quotas, all before "exists").
# The texts read well as they are, and troubleshoot shows them with <workdir> set to the environment's working
# directory. explain() knows the root terraform ran in: it fills ROOT and FAILED_ROOT with that root (stack/, bootstrap/
# or a dry run's copy), any other <workdir> with the environment's working directory, <env> with its name, this user's
# plugin cache (ANY_CACHE, or the _WITHOUT_CACHE variant when none is configured) and the _FILL placeholders from the
# error text itself.
ROOT = "<workdir>/stack"
FAILED_ROOT = "the Terraform root that failed (<workdir>/stack or <workdir>/bootstrap)"
ANY_CACHE = "TF_PLUGIN_CACHE_DIR or plugin_cache_dir in your Terraform CLI config"
PLUGIN_START = (r"Failed to read any lines from plugin|Unrecognized remote plugin message|Failed to load plugin schemas|"
                r"Plugin did not respond|failed to instantiate provider")
LOCK_MISMATCH = r"(does not|doesn't)\s+match\s+any\s+of\s+the\s+checksums"
# up to 400 characters of one diagnostic, across its wrapped lines but never into the next one (another resource's): a
# line starting "Error:" or "Warning:", or "Error:" anywhere (a log flattened to one line). A lower-case "error:" inside
# a message ("last error: ...") does not end it.
_SAME_ERROR = r"(?:(?!\n[ \t]*(?:Error|Warning):|(?-i:\bError:))[\s\S]){0,400}?"
HINTS = [
    (r"failed to get shared config profile|SharedConfigProfileNotExist",
     "The AWS profile this environment uses does not exist in ~/.aws/config or ~/.aws/credentials.",
     "create it (aws configure --profile NAME / aws configure sso), or use an existing one: `cloudseed setup aws --env "
     "<env> --profile <existing>`. A profile saved with the environment wins over AWS_PROFILE; without one (blank "
     "profile, the default credential chain) the AWS_PROFILE set in your shell (or saved with `cloudseed creds`) is the "
     "one missing: fix or unset it"),
    # allowed_account_ids (aws.provider_block) pins an environment to the account it was deployed into
    (r"AWS account ID not allowed",
     "This environment lives in another AWS account than the one the current credentials belong to (cloudseed pins it "
     "with allowed_account_ids, so it is never re-created in the wrong account).",
     "switch back to that account's credentials (unset AWS_PROFILE, or `cloudseed creds unset AWS_PROFILE` when it is "
     "saved there; aws sso login --profile NAME), or save the right profile with the environment: cloudseed setup aws "
     "--env <env> --profile NAME"),
    (r"InvalidClientTokenId|ExpiredToken|security token included in the request is (invalid|expired)|"
     r"no valid credential sources|NoCredentialProviders|failed to refresh cached credentials|SSO session",
     "AWS credentials are missing, invalid or expired.",
     "aws sso login   (or: aws configure / export AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY / --profile NAME)"),
    (r"could not find default credentials|Attempted to load application default credentials|"
     r"oauth2: .*(invalid_grant|token expired)|Reauthentication is needed",
     "Google credentials are missing or expired.",
     "gcloud auth application-default login   (or: export GOOGLE_APPLICATION_CREDENTIALS=/path/key.json)"),
    (r'exec: "az": executable file not found|launching Azure CLI|could not parse Azure CLI version',
     "The Azure CLI (az) is not installed and no ARM_* service-principal / managed-identity variables are set, so "
     "Terraform's azurerm provider cannot authenticate (az-login authentication runs the az binary).",
     "cloudseed install az && az login   (or: export ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_TENANT_ID / "
     "ARM_SUBSCRIPTION_ID, or save them once with `cloudseed creds set KEY`)"),
    (r"AADSTS|az login|building account|obtaining Authorization Token|Please run 'az login'|ARM_CLIENT_ID|"
     r"unable to build authorizer|could not configure \w+ Authorizer|could not acquire access token|"
     r"obtaining subscription ID|building AzureRM Client",
     "Azure credentials are missing or expired.",
     "az login   (or: export ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_TENANT_ID / ARM_SUBSCRIPTION_ID)"),
    (r"(GuardDuty|Detector).*(already exists|BadRequestException)|The request is rejected because a detector already exists",
     "GuardDuty is already enabled in this account/region.",
     "re-run with: --var enable_guardduty=false   (a second environment in the same account and region: "
     "--var enable_regional_baseline=false, which leaves the region's whole baseline to the first one)"),
    (r"Security Hub.*(already|subscribed)|ResourceConflictException.*[Ss]ecurity[Hh]ub",
     "Security Hub is already enabled.", "re-run with: --var enable_security_hub=false"),
    (r"MaxNumberOf(ConfigurationRecorders|DeliveryChannels)Exceeded",
     "AWS Config already records in this region (only one recorder per region).", "re-run with: --var enable_aws_config=false"),
    # an analyzer of this environment's own name is adopted (reconcile); another one is a quota of one per region. The
    # parts may be on different lines (a wrapped diagnostic) and in either order, but within the same error. Reached
    # when the preflight could not list the account's analyzers (it switches a default-on analyzer off by itself).
    (r"(Access Analyzer Analyzer|CreateAnalyzer)" + _SAME_ERROR + r"(ServiceQuotaExceeded|already exists)|"
     r"ServiceQuotaExceeded" + _SAME_ERROR + r"Analyzer",
     "IAM Access Analyzer allows only one account-level analyzer per region (not adjustable) and this account already "
     "has one this environment did not create.",
     "re-run with: --var enable_access_analyzer=false   (the existing analyzer keeps running)"),
    (r"pricing tier of this subscription is not Free",
     "Microsoft Defender for Cloud is already enabled for this subscription (org policy or another environment, or left "
     "on by an earlier destroy of this environment).",
     "re-run with: --var enable_defender=false   (Defender stays on for the subscription)"),
    (r"MarketplaceOrdering/agreements.*already exists|already exists.*MarketplaceOrdering/agreements",
     "The Ubuntu Pro FIPS image terms are already accepted in this subscription (by another environment or by hand); "
     "nothing is wrong with them.",
     f"adopt them, then re-run: terraform -chdir={ROOT} import 'module.stack.azurerm_marketplace_agreement."
     "ubuntu_pro_fips[0]' /subscriptions/<subscription>/providers/Microsoft.MarketplaceOrdering/agreements/canonical/"
     "offers/0001-com-ubuntu-pro-jammy-fips/plans/pro-fips-22_04-gen2   (a destroy keeps the terms accepted)"),
    (r"DependencyViolation|has dependenc(y|ies) and cannot be deleted|InUseSubnetCannotBeDeleted|"
     r"resourceInUseByAnotherResource|Deleting .*is already being used by",
     "Something outside this environment's Terraform state still uses the network, so the cloud refuses to delete it: "
     "typically a load balancer, network interface, volume or node created from inside the Kubernetes cluster "
     "(Services of type LoadBalancer, Gateways, PVCs, Karpenter), or a resource created by hand.",
     "delete what the error names (e.g. aws ec2 describe-network-interfaces --filters Name=vpc-id,Values=<vpc-id>; "
     "gcloud compute firewall-rules list --filter network=<network>; az network nic list -g <resource group>), then "
     "re-run the destroy"),
    (r"Error acquiring the state lock|Error releasing the state lock",
     "Another cloudseed/terraform run holds the state lock (or one was interrupted or crashed).",
     f"wait for it to finish; if none is running: terraform -chdir={ROOT} force-unlock <Lock Info ID>"),
    (r"Saved plan is stale",
     "The state changed after the plan was made (another run, or resources were adopted), so Terraform refused to "
     "apply a plan nobody reviewed.",
     "re-run the command: it plans again and shows you the new plan"),
    # A provider that crashed (its Go stack trace is in the output) or never started: before the lock-file entries,
    # which a parallel run sharing the plugin cache also triggers, and before every cloud error it could be mixed with.
    (r"(?m)^panic: |Stack trace from the terraform-provider|plugin crashed!",
     "A Terraform provider crashed (a bug in the provider, not in your configuration).",
     "re-run the same command; if it crashes the same way again, report it to the provider's issue tracker with the "
     "stack trace above"),
    # before "Required plugins are not installed": plan/validate report a checksum mismatch under that heading
    (LOCK_MISMATCH,
     "The provider packages in .terraform no longer match the hashes in .terraform.lock.hcl. Either the plugin cache "
     f"changed - a parallel run sharing the provider plugin cache ({ANY_CACHE}) rewrote a cached provider - or the "
     "lock file was written on another OS/CPU or through another mirror, or was edited.",
     "if another cloudseed/terraform run is active, wait for it and re-run; if it fails the same way with no other run "
     f"active, delete .terraform.lock.hcl and .terraform in {FAILED_ROOT}, then re-run (cloudseed writes a new lock)"),
    (r"Inconsistent\s+dependency\s+lock\s+file",
     f"The dependency lock file (.terraform.lock.hcl) of {FAILED_ROOT} does not select a provider version the "
     "configuration now needs: the stack changed after its last terraform init (a newer cloudseed, or a feature "
     "switched on), or the lock file was edited.",
     "re-run the same command (cloudseed runs terraform init first, which records the missing provider); if it fails "
     "the same way, delete .terraform.lock.hcl there and re-run"),
    # (not for the checksum mismatch terraform reports under the same heading: troubleshoot lists every match)
    (r"unavailable provider|Missing required provider|there is no package for|"
     r"Required plugins are not installed(?![\s\S]{0,1000}?" + LOCK_MISMATCH + ")",
     f"A provider this root needs is not installed in {ROOT}/.terraform (terraform init did not finish, or the "
     "directory was cleaned up).",
     "re-run the same command (cloudseed runs terraform init first); for a VMware environment also: cloudseed install "
     "vmware-provider"),
    (PLUGIN_START,
     "A Terraform provider plugin failed to start or stopped mid-run. The usual cause is another terraform or "
     f"cloudseed run using the same provider plugin cache ({ANY_CACHE}) at the same time: terraform init rewrites "
     "cached providers in place, which breaks a provider another run is using. Less often the machine ran out of "
     "memory.",
     "wait for other cloudseed/terraform runs to finish and re-run the same command; to run commands in parallel, give "
     "each its own TF_PLUGIN_CACHE_DIR (or none)"),
    (r"MissingSubscriptionRegistration|not registered to use namespace",
     "The Azure subscription has not registered a resource provider this stack needs.",
     "az provider register --namespace <Namespace from the error> --wait, then re-run"),
    (r"SERVICE_DISABLED|accessNotConfigured|API has not been used in project",
     "A required Google Cloud API is not enabled (or was just enabled and is still propagating).",
     "gcloud services enable <api> --project <project>, wait a minute and re-run the same command"),
    # the project itself (projects/<id>, nothing after it), not a resource inside it that is gone
    (r"Error 404: The resource '?projects/[^'/\s]+'? was not found",
     "The Google Cloud project does not exist, or the identity you are using cannot see it.",
     "check the project ID (gcloud projects describe <project>) and your login (gcloud auth list); fix it with: "
     "cloudseed setup gcp --env <env> --project-id <the right project>"),
    (r"Identity (Pool|namespace) does not exist",
     "The project's GKE workload identity pool (<project>.svc.id.goog) does not exist yet: it is created with the "
     "first GKE cluster, and older cloudseed stacks granted roles to it before the cluster was ready.",
     "re-run the same setup/apply: the cluster exists now, and so does the pool"),
    (r"RequestLimitExceeded|ThrottlingException|\bThrottling\b|Rate exceeded|TooManyRequests|Error 429",
     "The cloud API is throttling requests.", "wait a minute and re-run"),
    (r"AnotherOperationInProgress|operation is in progress|OperationInProgress",
     "Another operation on this resource is still running in the cloud.", "wait a few minutes and re-run"),
    (r"AccessDenied|UnauthorizedOperation|not authorized to perform|PERMISSION_DENIED|AuthorizationFailed|"
     r"Error 403: Required '[^']+' permission",
     "The identity you are using lacks permissions for this action.",
     "use an admin/owner identity for the first setup, or grant the missing permission and re-run"),
    (r"Unsupported Terraform Core version|required_version",
     "Terraform is too old (>= 1.10 needed).", "cloudseed install terraform"),
    (r"VcpuLimitExceeded|QuotaExceeded|(?<!Request)LimitExceeded|exceeded quota|OperationNotAllowed.*quota",
     "A service quota/limit was hit.", "request a quota increase or pick a smaller instance/region via --var"),
    (r"Conflicting configuration arguments",
     "Two settings that cannot be combined were set (often through --var).",
     "check your --var overrides against `cloudseed help variables <cloud>`"),
    (r"already ?exists?|AlreadyExists|AlreadyOwnedByYou|\.Duplicate\b|ResourceExistsError",
     "A resource with the same name already exists (maybe from a previous run or another env).",
     "use a different --name/--env, or import/delete the existing resource"),
]

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# the frame of terraform's coloured diagnostics ("│ Error: ...", "╷", "╵") at the start of a line
_GUTTER = re.compile(r"(?m)^[ \t]*[│╷╵][ \t]?")

# Placeholders in a hint that the error text itself can fill in (first match wins; left as-is otherwise).
_FILL = {
    "<api>": (r"apis/api/([a-z0-9-]+\.googleapis\.com)", r'"service"\s*:\s*"([a-z0-9-]+\.googleapis\.com)',
              r"\b(?!type\.)([a-z0-9-]+\.googleapis\.com)\b"),
    "<project>": (r"The resource '?projects/([a-z][a-z0-9-]{4,28}[a-z0-9])'? was not found",
                  r"\bin project ([a-z][a-z0-9-]{4,28}[a-z0-9]|\d{6,})\b", r"[?&]project=([a-z][a-z0-9-]{4,28}[a-z0-9]|\d{6,})\b",
                  r'"consumer"\s*:\s*"projects/([a-z0-9-]+)"', r"\b([a-z][a-z0-9-]{4,28}[a-z0-9])\.svc\.id\.goog\b"),
    "<subscription>": (r"/subscriptions/([0-9a-fA-F-]{36})/",),
    "<Lock Info ID>": (r"Lock Info:\s+ID:\s+([0-9A-Za-z][0-9A-Za-z-]{7,})",),
}

# Terraform's plugin cache is not safe for concurrent use (`terraform init` rewrites a cached provider in place while
# another run executes it), so with a cache parallel runs are the usual cause of these errors; without one they cannot
# be, and explain() uses these texts instead.
_WITHOUT_CACHE = {
    PLUGIN_START: (
        "A Terraform provider plugin failed to start or stopped mid-run: the machine may have run out of memory, or the "
        f"provider binary in {ROOT}/.terraform is damaged.",
        f"re-run the same command; if it fails again, delete {ROOT}/.terraform and re-run (terraform init installs the "
        "provider again)"),
    LOCK_MISMATCH: (
        "The provider packages in .terraform no longer match the hashes in .terraform.lock.hcl: the lock file was "
        "written on another OS/CPU or through another mirror, or was edited.",
        f"delete .terraform.lock.hcl and .terraform in {FAILED_ROOT}, then re-run (cloudseed writes a new lock)"),
}


def plugin_cache() -> str | None:
    """This user's shared provider plugin cache, as the hints name it: TF_PLUGIN_CACHE_DIR, else plugin_cache_dir in
    their Terraform CLI config; None when there is none (or the config cannot be read)."""
    env = os.environ.get("TF_PLUGIN_CACHE_DIR")
    if env:
        return f"TF_PLUGIN_CACHE_DIR={env}"
    try:
        cfg = user_cli_config()
        # HCL (plugin_cache_dir = "...") or the JSON syntax Terraform also reads ({"plugin_cache_dir": "..."})
        m = re.search(r'(?m)(?:^|[{,])\s*"?plugin_cache_dir"?\s*[=:]\s*"([^"]+)"',
                      cfg.read_text(errors="replace")) if cfg else None
    except OSError:
        m = None
    return f"plugin_cache_dir {m.group(1)} in {cfg}" if m else None


def _env_of(root: Path) -> tuple[Path, str | None]:
    """The working directory a Terraform root belongs to (<workdir>/stack, <workdir>/bootstrap,
    <workdir>/dry-run/<root>) and its environment's name, both from the config.json found there; the root's parent
    and None when there is none. Only a dry run's copy looks one level further up: the config.json of whatever
    directory holds a custom --workdir is not this environment's, and a hint must never name another --env."""
    dirs = [root.parent] + ([root.parent.parent] if root.parent.name == "dry-run" else [])
    for d in dirs:
        try:
            cfg = json.loads((d / "config.json").read_text())
        except (OSError, ValueError):
            continue
        if isinstance(cfg, dict):
            env = cfg.get("env")
            return d, (env if isinstance(env, str) and env else None)
    return root.parent, None


def _fill(fix: str, text: str, workdir=None) -> str:
    """`fix` with its placeholders filled: the _FILL ones from the error text; with `workdir` (the root terraform ran
    in) also FAILED_ROOT and ROOT (that root), any other <workdir> (its environment's working directory) and <env>."""
    for placeholder, patterns in _FILL.items():
        if placeholder not in fix:
            continue
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                fix = fix.replace(placeholder, m.group(1))
                break
    if not workdir:
        return fix                # troubleshoot fills <workdir> itself (with the environment's working directory)
    root = Path(workdir)
    # a command must work when pasted: a root with spaces (a custom --workdir) is quoted there, not in the prose
    fix = fix.replace(f"-chdir={ROOT}", "-chdir=" + shlex.quote(str(root)))
    fix = fix.replace(FAILED_ROOT, str(root)).replace(ROOT, str(root))
    if "<workdir>" in fix or "<env>" in fix:
        home, env = _env_of(root)
        fix = fix.replace("<workdir>", str(home))
        if env:
            fix = fix.replace("<env>", env)
    return fix


def explain(output: str, action: str, workdir=None) -> str:
    """The first HINTS entry matching terraform's output, as "terraform <action> failed: what\n  Fix: how", with the
    placeholders filled from the output and `workdir` (the root terraform ran in); a plain line when none matches."""
    text = _GUTTER.sub("", _ANSI.sub("", output or ""))
    for pattern, what, fix in HINTS:
        if re.search(pattern, text, re.I):
            what, fix = _for_this_machine(pattern, what, fix, no_cache=_uses_local_provider(workdir))
            return f"terraform {action} failed: {_fill(what, text, workdir)}\n  Fix: {_fill(fix, text, workdir)}"
    return f"terraform {action} failed (see the output above)"


def _for_this_machine(pattern: str, what: str, fix: str, no_cache: bool = False) -> tuple[str, str]:
    """A HINTS entry as it applies on this machine: ANY_CACHE named as this user's plugin cache, or, when none is
    configured (or no_cache: a root that needs the local VMware provider, which runs without one), the _WITHOUT_CACHE
    variant (a parallel run cannot be the cause then). troubleshoot can use it too."""
    if ANY_CACHE not in what + fix:
        return what, fix
    cache = None if no_cache else plugin_cache()
    if cache:
        return what.replace(ANY_CACHE, cache), fix.replace(ANY_CACHE, cache)
    return _WITHOUT_CACHE.get(pattern, (what, fix))


# ---------------------------------------------------------------- CLI configuration (VMware provider mirror)

LOCAL_PROVIDER = "registry.local/cloudseed/vmdesktop"


def _uses_local_provider(workdir) -> bool:
    """Does the Terraform root in `workdir` need cloudseed's locally built VMware provider (registry.local)?"""
    if not workdir:
        return False
    wd = Path(workdir)
    try:
        files = list(wd.glob("*.tf.json")) + list(wd.glob("*.tf"))
    except OSError:
        return False
    for f in files:
        try:
            if LOCAL_PROVIDER in f.read_text(errors="replace"):
                return True
        except OSError:
            continue
    return False


def cloudseed_cli_config() -> Path:
    """cloudseed's own CLI config (written by localvm.write_terraform_rc): the filesystem mirror of the VMware
    provider it builds from source."""
    return paths.HOME / "terraform.rc"


def merged_cli_config() -> Path:
    return paths.HOME / "terraform-merged.rc"


def user_cli_config() -> Path | None:
    """The CLI config Terraform would read for this user: $TF_CLI_CONFIG_FILE, else ~/.terraformrc
    (%APPDATA%/terraform.rc on Windows)."""
    explicit = os.environ.get("TF_CLI_CONFIG_FILE")
    if explicit:
        p = Path(explicit).expanduser()
        ours = {cloudseed_cli_config().resolve(), merged_cli_config().resolve()}
        return p if p.is_file() and p.resolve() not in ours else None
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA")
        p = Path(appdata) / "terraform.rc" if appdata else None
    else:
        p = Path.home() / ".terraformrc"
    return p if p is not None and p.is_file() else None


def _block_end(text: str, open_brace: int) -> int | None:
    """Index of the '}' closing the '{' at open_brace (strings and comments skipped); None when unbalanced."""
    depth, i, n = 0, open_brace, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def merge_cli_config(user_text: str, ours: str) -> str | None:
    """The user's CLI config plus cloudseed's registry.local filesystem mirror, or None when it cannot be merged
    safely. Terraform accepts only one provider_installation block, so appending ours is only possible when the user
    has none; otherwise our mirror goes into their block and their other methods exclude registry.local (a `direct`
    lookup of that fake hostname would fail)."""
    if user_text.lstrip().startswith("{"):
        return None                                   # JSON-syntax CLI config: not merged
    mirror = re.search(r"filesystem_mirror\s*\{[^{}]*\}", ours)
    blocks = list(re.finditer(r"(?m)^[ \t]*provider_installation\s*\{", user_text))
    if not blocks:
        return user_text.rstrip() + "\n\n# added by cloudseed for its local VMware provider\n" + ours
    if len(blocks) > 1 or not mirror:
        return None
    open_at = blocks[0].end() - 1
    close_at = _block_end(user_text, open_at)
    if close_at is None:
        return None
    body = user_text[open_at + 1:close_at]
    methods = []
    for m in re.finditer(r"\b(direct|network_mirror|filesystem_mirror)\s*\{", body):
        end = _block_end(body, m.end() - 1)
        if end is None:
            return None
        methods.append((m.end() - 1, end))
    for start, end in reversed(methods):             # edit from the back so earlier offsets stay valid
        inner = body[start + 1:end]
        if "registry.local" in inner:
            continue
        excl = re.search(r"\bexclude\s*=\s*\[", inner)
        if excl:
            at = start + 1 + excl.end()
            body = body[:at] + '"registry.local/*/*", ' + body[at:]
        else:
            body = body[:start + 1] + '\n    exclude = ["registry.local/*/*"]' + body[start + 1:]
    body = "\n  # added by cloudseed for its local VMware provider\n  " + mirror.group(0) + body
    return user_text[:open_at + 1] + body + user_text[close_at:]


def local_provider_cli_config() -> Path | None:
    """The CLI config to use for a root that needs the local VMware provider: cloudseed's mirror, merged with the
    user's own CLI config when there is one (so their mirrors, plugin cache and credentials still apply)."""
    ours_path = cloudseed_cli_config()
    try:
        ours = ours_path.read_text()
    except OSError:
        return None                                   # provider not installed yet; init explains what is missing
    user = user_cli_config()
    if not user:
        return ours_path
    try:
        merged = merge_cli_config(user.read_text(), ours)
    except (OSError, UnicodeDecodeError):
        merged = None
    if merged is None:
        ui.warn(f"Could not merge your Terraform CLI config {user} with cloudseed's VMware provider mirror; "
                "it is not used for this VMware environment.")
        return ours_path
    target = merged_cli_config()
    paths.atomic_write(target, without_plugin_cache(merged), 0o600)
    return target


_PLUGIN_CACHE_SETTING = re.compile(r"(?m)^([ \t]*)(plugin_cache_dir|plugin_cache_may_break_dependency_lock_file)\b")


def without_plugin_cache(cli_config: str) -> str:
    """A (merged) CLI config for a root that needs the local VMware provider, with the user's plugin cache settings
    commented out: that provider must never be shared through a cache (see Terraform._env)."""
    return _PLUGIN_CACHE_SETTING.sub(r"\1# not for cloudseed's VMware roots (a locally built provider is never cached): \2",
                                     cli_config)


# ---------------------------------------------------------------- interrupts

def _signal_child(child: subprocess.Popen, count: int) -> None:
    """Ctrl-C / cancel while terraform runs. Terraform is in its own session, so only cloudseed receives the signal
    and forwards it exactly once per interrupt: the first makes terraform stop gracefully (finish in-flight calls,
    save state, release the lock); a second is terraform's own "exit immediately"; a third kills it."""
    try:
        if count == 1:
            ui.warn("Interrupt received: stopping terraform safely (it saves state and releases the lock). "
                    "Press Ctrl-C again to make it exit immediately (may lose state).")
            child.send_signal(signal.SIGINT)
        elif count == 2:
            ui.warn("Second interrupt: telling terraform to exit immediately.")
            child.send_signal(signal.SIGINT)
        else:
            ui.warn("Killing terraform.")
            child.kill()
    except (ProcessLookupError, OSError):
        pass


class _SigtermAsInterrupt:
    """While terraform runs, treat SIGTERM like Ctrl-C so a stopped cloudseed still lets terraform shut down cleanly
    instead of leaving it to die from a broken pipe. Only possible in the main thread."""

    def __enter__(self):
        self.old = None
        if threading.current_thread() is threading.main_thread():
            try:
                self.old = signal.signal(signal.SIGTERM, self._raise)
            except (ValueError, OSError):
                self.old = None
        return self

    @staticmethod
    def _raise(signum, frame):
        raise KeyboardInterrupt

    def __exit__(self, *exc):
        if self.old is not None:
            try:
                signal.signal(signal.SIGTERM, self.old)
            except (ValueError, OSError):
                pass
        return False


class Terraform:
    LOCAL_PROVIDER = LOCAL_PROVIDER

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.binary = deps.find("terraform")
        if not self.binary:
            hint = "" if self.uses_local_provider() else " (aws/gcp/azure can also run it in a container: --runtime container)"
            raise ui.Abort(f"terraform is not installed. Run `cloudseed install terraform`{hint}.")

    # ---- plumbing ----
    def uses_local_provider(self) -> bool:
        """True when this root needs cloudseed's locally built VMware provider (registry.local)."""
        return _uses_local_provider(self.workdir)

    def _env(self) -> dict:
        env = deps.path_env()
        env.setdefault("TF_IN_AUTOMATION", "1")
        env.setdefault("TF_INPUT", "0")
        # Only roots using the local VMware provider get cloudseed's CLI config (merged with the user's own): every
        # other root keeps the user's ~/.terraformrc / TF_CLI_CONFIG_FILE (mirrors, plugin cache, credentials).
        if self.uses_local_provider():
            rc = local_provider_cli_config()
            if rc:
                env["TF_CLI_CONFIG_FILE"] = str(rc)
            # never through a shared plugin cache: the provider is built on this machine and keeps its version (0.1.0)
            # across rebuilds, so a cache entry another cloudseed home (or build) wrote - a link into ITS provider
            # directory - is taken for this one's, and `terraform output`/`show` then fail on the lock file's checksum
            env.pop("TF_PLUGIN_CACHE_DIR", None)
        return env

    def _popen(self, cmd: list[str], **kw) -> subprocess.Popen:
        # own session: a terminal Ctrl-C reaches only cloudseed, which forwards exactly one SIGINT (see _signal_child)
        return subprocess.Popen(cmd, env=self._env(), text=True, errors="replace", stdin=subprocess.DEVNULL,
                                start_new_session=True, **kw)

    def run(self, *args: str, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess:
        args = list(args)
        if args and args[0] in ("plan", "apply", "destroy", "init", "validate") and "-no-color" not in args \
                and (os.environ.get("NO_COLOR") or not sys.stdout.isatty()):
            args.append("-no-color")
        cmd = [self.binary, f"-chdir={self.workdir}", *args]
        if capture:
            proc = self._run_captured(cmd)
            if check and proc.returncode != 0:
                raise TerraformError(explain(proc.stderr + proc.stdout, args[0], self.workdir))
            return proc
        print(ui.dim("$ terraform " + " ".join(args)), flush=True)
        audit.write("$ terraform " + " ".join(args))
        redact_console = secrets.redact_enabled()
        redactor = secrets.StreamRedactor()          # multi-line private keys never reach the log (or an agent)
        child = self._popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert child.stdout is not None
        tail: list[str] = []
        interrupts = 0
        with _SigtermAsInterrupt():
            while True:
                try:
                    for line in child.stdout:
                        safe = redactor.feed(line)
                        print(safe if redact_console else line, end="", flush=True)
                        if safe:
                            audit.write(safe)
                        tail.append(line)
                        if len(tail) > 400:
                            tail.pop(0)
                    child.wait()
                    break
                except KeyboardInterrupt:
                    interrupts += 1
                    _signal_child(child, interrupts)
        child.stdout.close()
        proc = subprocess.CompletedProcess(cmd, child.returncode, "".join(tail), "")
        if interrupts:
            self._after_interrupt(proc)
            raise KeyboardInterrupt
        if check and proc.returncode != 0:
            raise TerraformError(explain(proc.stdout, args[0], self.workdir))
        return proc

    def _run_captured(self, cmd: list[str]) -> subprocess.CompletedProcess:
        child = self._popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        interrupts = 0
        with _SigtermAsInterrupt():
            while True:
                try:
                    out, err = child.communicate()
                    break
                except KeyboardInterrupt:
                    interrupts += 1
                    _signal_child(child, interrupts)
        proc = subprocess.CompletedProcess(cmd, child.returncode, out or "", err or "")
        if interrupts:
            self._after_interrupt(proc)
            raise KeyboardInterrupt
        return proc

    def _after_interrupt(self, proc: subprocess.CompletedProcess) -> None:
        text = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode is not None and proc.returncode < 0:
            ui.warn(f"terraform was killed; the state lock may still be held. If no other run is active: "
                    f"terraform -chdir={self.workdir} force-unlock <ID>")
        elif "Error releasing the state lock" in text:
            ui.warn(f"terraform stopped but could not release the state lock. If no other run is active: "
                    f"terraform -chdir={self.workdir} force-unlock <ID>")
        else:
            ui.info(f"terraform stopped after the interrupt (exit {proc.returncode}); its state was saved.")

    def _platform_guard(self) -> None:
        """Provider binaries and lock hashes are per-OS/arch. If this workdir was last
        used from another platform (host vs container, or a bundle), reset them."""
        marker = self.workdir / ".cloudseed-platform"
        current = f"{platform.system().lower()}_{platform.machine().lower()}"
        previous = marker.read_text().strip() if marker.exists() else None
        if previous and previous != current:
            ui.info(f"Terraform workdir was last used on {previous}; resetting provider cache for {current}.")
            shutil.rmtree(self.workdir / ".terraform", ignore_errors=True)
            (self.workdir / ".terraform.lock.hcl").unlink(missing_ok=True)
        marker.write_text(current + "\n")

    # ---- commands ----
    def init(self, migrate: bool = False, backend: bool = True) -> None:
        self._platform_guard()
        args = ["init", "-input=false", "-no-color"]
        if not backend:
            args.append("-backend=false")
        if migrate:
            args += ["-migrate-state", "-force-copy"]
        # Quiet init: only print when something goes wrong.
        proc = self.run(*args, capture=True, check=False)
        if proc.returncode != 0 and self._forget_stale_local_provider(proc.stdout + proc.stderr):
            proc = self.run(*args, capture=True, check=False)   # lock entry dropped; init records the new checksum
        if proc.returncode != 0 and "does not match configured version constraint" in " ".join(
                f"{proc.stdout or ''}{proc.stderr or ''}".split()):   # (terraform wraps the message)
            proc = self.run(*args, "-upgrade", capture=True, check=False)   # the stack now needs a newer provider than the lock
        if proc.returncode != 0:
            out = (proc.stdout or "") + (proc.stderr or "")
            safe = secrets.redact(out)
            print((safe if secrets.redact_enabled() else out).rstrip(), flush=True)
            audit.write("$ terraform " + " ".join(args) + "\n" + safe)    # so `cloudseed troubleshoot` can read it
            raise TerraformError(explain(out, "init", self.workdir))

    def _forget_stale_local_provider(self, output: str) -> bool:
        """cloudseed builds its VMware provider from source; after a rebuild the checksum in .terraform.lock.hcl no
        longer matches. That lock entry protects nothing (the binary is ours, not downloaded), so drop it and retry."""
        if self.LOCAL_PROVIDER not in output or "checksum" not in output:
            return False
        lock = Path(self.workdir) / ".terraform.lock.hcl"
        try:
            text = lock.read_text()
        except OSError:
            return False
        new = re.sub(r'provider "%s" \{.*?\n\}\n' % re.escape(self.LOCAL_PROVIDER), "", text, flags=re.S)
        if new == text:
            return False
        lock.write_text(new)
        return True

    def validate(self) -> None:
        self.run("validate", "-no-color")

    def plan(self, out: str = "tfplan", destroy: bool = False, targets: tuple[str, ...] = ()) -> None:
        args = ["plan", "-input=false", f"-out={out}"]
        if destroy:
            args.append("-destroy")
        args += [f"-target={t}" for t in targets]
        self.run(*args)

    # how often plan_for_apply switches off singletons that already exist and plans again before it gives up
    SWITCH_OFF_ROUNDS = 2

    def plan_for_apply(self, cloud_key: str, cfg: dict, out: str = "tfplan", targets: tuple[str, ...] = (),
                       render=None) -> None:
        """The plan to show the user before apply_reconciled(). reconcile.preflight checks it first: when the plan
        would create an account-wide singleton that already exists and that cloudseed never adopts
        (reconcile.NEVER_ADOPT: a GuardDuty detector, Security Hub, Defender for Cloud) it stops here, before anything
        is changed, naming the --var that skips it (reconcile.SingletonExists). Given `render(cfg)` (writes the stack
        again from cfg), a singleton that is only on by default (the user never asked for it) is left alone instead:
        its variable is set to false in cfg["extra_vars"] (the caller saves cfg with the approved plan), the stack is
        rendered and planned again. The few objects it does adopt up front (the EKS cluster's OIDC provider, the AWS
        Config service-linked role) are imported and the plan is made again, so the plan the user approves is exactly
        the plan that gets applied."""
        from . import reconcile
        self.plan(out, targets=targets)
        switched = 0
        while True:
            planned = reconcile.planned_values(self, out)
            try:
                adopted = reconcile.preflight(self, cloud_key, cfg, planned)
            except reconcile.SingletonExists as e:
                if render is None or not e.auto or switched >= self.SWITCH_OFF_ROUNDS:
                    raise                    # a TerraformError: the message names the --var that leaves it alone
                switched += 1
                for line in e.switch_off(cfg):
                    ui.info(line)
                ui.info("Planning again with that setting, so the plan below is what gets applied.")
                render(cfg)
                self.plan(out, targets=targets)
                continue
            if adopted:
                ui.info("Adopted existing resources into the state; planning again so the plan below is what gets applied.")
                self.plan(out, targets=targets)
            return

    def _guardrails(self, planfile):
        config_path = self.workdir.parent / "config.json"
        if not config_path.exists():
            return
        cfg = json.loads(config_path.read_text())
        if not cfg.get("operations"):
            return
        from . import clouds, guardrails
        if not planfile:
            raise ui.Abort("This environment has deployment guardrails; create and review a saved plan before apply.", code=2)
        cloud = clouds.get(cfg["cloud"])
        env = paths.Env(cloud.key, cfg["env"], workdir=self.workdir.parent)
        proc = self.run("show", "-json", str(planfile), capture=True, check=False)
        if proc.returncode:
            raise ui.Abort("Cannot inspect the exact Terraform plan for deployment guardrails; nothing was applied.", code=2)
        plan = json.loads(proc.stdout)
        guardrails.enforce(cloud, env, cfg, plan=plan)

    def apply(self, planfile: str | None = None, auto_approve: bool = False, targets: tuple[str, ...] = ()) -> None:
        self._guardrails(planfile)
        args = ["apply", "-input=false"]
        if planfile:
            args.append(planfile)
        else:
            if auto_approve:
                args.append("-auto-approve")
            args += [f"-target={t}" for t in targets]
        self.run(*args)

    def destroy(self, targets: tuple[str, ...] = (), auto_approve: bool = False) -> None:
        args = ["destroy", "-input=false"]
        if auto_approve:
            args.append("-auto-approve")
        args += [f"-target={t}" for t in targets]
        self.run(*args)

    SENSITIVE = "<sensitive>"

    # why the last outputs() call could not read the outputs (terraform's error, explained), None when it could
    outputs_error: str | None = None

    def outputs(self, sensitive: bool = False) -> dict:
        """The root module's outputs. `terraform output -json` prints the values of outputs marked sensitive in clear;
        they are replaced by "<sensitive>" (as terraform shows them) unless `sensitive` is True, so they never reach
        outputs.json, the console, the audit log or an agent. When terraform cannot read them (a provider it cannot
        load, a backend it cannot reach) the result is {} and `outputs_error` says why - its error is shown, never
        swallowed: empty outputs of an applied stack must not read as "the VM reported no address"."""
        self.outputs_error = None
        proc = self.run("output", "-json", capture=True, check=False)
        if proc.returncode != 0:
            self._outputs_failed((proc.stderr or "") + (proc.stdout or ""))
            return {}
        try:
            raw = json.loads(proc.stdout or "{}")
        except ValueError:
            self._outputs_failed("terraform output -json did not print JSON:\n" + (proc.stdout or "")[:400])
            return {}
        if not isinstance(raw, dict):
            self._outputs_failed("terraform output -json did not print an object of outputs")
            return {}
        return {k: (self.SENSITIVE if isinstance(v, dict) and v.get("sensitive") and not sensitive
                    else (v.get("value") if isinstance(v, dict) else None))
                for k, v in raw.items()}

    def _outputs_failed(self, output: str) -> None:
        out = output.strip() or f"(terraform printed nothing; it ran in {self.workdir})"
        safe = secrets.redact(out)
        audit.write("$ terraform output -json\n" + safe)          # so `cloudseed troubleshoot` can read it
        self.outputs_error = explain(out, "output", self.workdir)
        shown = safe if secrets.redact_enabled() else out
        ui.warn("Could not read the Terraform outputs (terraform output -json failed):\n    "
                + "\n    ".join(_GUTTER.sub("", _ANSI.sub("", shown)).strip().splitlines()[-12:])
                + "\n  " + self.outputs_error)

    def state_list(self) -> list[str]:
        proc = self.run("state", "list", capture=True, check=False)
        if proc.returncode != 0:
            return []
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]

    def _deleting(self, planfile: str) -> set[str] | None:
        """Addresses the plan deletes or replaces; None when the plan cannot be read."""
        proc = self.run("show", "-json", planfile, capture=True, check=False)
        if proc.returncode != 0:
            return None
        try:
            data = json.loads(proc.stdout or "{}")
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        return {rc.get("address", "") for rc in data.get("resource_changes") or []
                if "delete" in ((rc.get("change") or {}).get("actions") or [])}

    def apply_reconciled(self, cloud_key: str, cfg: dict, targets: tuple[str, ...] = (), rounds: int = 3,
                         planfile: str = "tfplan", approve=None, render=None) -> None:
        """Apply the plan the user reviewed (`planfile`, from plan()/plan_for_apply(); planned here when missing, with
        `render` passed on to plan_for_apply).

        When the apply fails because resources already exist outside the state, they are adopted (terraform import)
        and a new plan is made. That plan is never applied unreviewed: it is refused when it would delete or replace
        anything the reviewed plan did not (even with --auto-approve), and otherwise `approve(question)` is asked
        (it raises to stop; pass None to continue for pure creates/updates, e.g. under --auto-approve)."""
        from . import reconcile
        if not (Path(self.workdir) / planfile).exists():
            self.plan_for_apply(cloud_key, cfg, planfile, targets, render=render)
        reviewed_deletes: set[str] | None = None
        adopted: list[str] = []
        for attempt in range(1, rounds + 1):
            planned = reconcile.planned_values(self, planfile)
            proc = self.run("apply", "-input=false", planfile, check=False)
            if proc.returncode == 0:
                return
            if reviewed_deletes is None:
                # unreadable: assume the reviewed plan deleted nothing, so any delete after adoption is refused
                reviewed_deletes = self._deleting(planfile) or set()
            imported = reconcile.recover(self, cloud_key, cfg, proc.stdout, planned)
            if not imported or attempt == rounds:
                raise TerraformError(explain(proc.stdout, "apply", self.workdir))
            adopted += imported
            ui.info(f"Adopted {len(imported)} existing resource(s); re-planning (round {attempt + 1}/{rounds})")
            self.plan(planfile, targets=targets)
            deleting = self._deleting(planfile)
            if deleting is None:     # never apply a plan whose deletions could not be checked
                raise TerraformError(
                    f"After adopting {', '.join(adopted)}, the new plan could not be read (terraform show -json "
                    f"{planfile} failed), so it cannot be checked for deletions. Nothing more was applied.\n"
                    f"  Fix: re-run the command: it plans again and shows you the plan")
            unexpected = sorted(deleting - reviewed_deletes)
            if unexpected:
                raise TerraformError(
                    f"After adopting {', '.join(adopted)}, the new plan would delete or replace "
                    f"{', '.join(unexpected)}, which the plan you approved did not. Nothing more was applied.\n"
                    f"  Fix: review with `cloudseed plan <cloud> --env <env>`; if the adopted resource belongs to "
                    f"something else, remove it from the state (terraform state rm) and pick another --name/--env")
            if approve is not None:
                approve(f"Adopted {len(adopted)} existing resource(s) ({', '.join(adopted)}); apply the updated plan above?")

    def version(self) -> str:
        proc = self.run("version", "-json", capture=True, check=False)
        try:
            return json.loads(proc.stdout)["terraform_version"]
        except Exception:
            return "unknown"
