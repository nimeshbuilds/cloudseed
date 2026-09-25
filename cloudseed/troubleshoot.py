"""Deterministic troubleshooting: reads the audit trail, the last failing log, the inventory and the live
environment, and prints findings with fixes. No LLM involved."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import shutil
import socket
from pathlib import Path

from . import audit, deps, netutil, paths, tf, ui

# (regex over a log, what it means, fix[, fix for local VMs]). "{host}" (any "{name}") in what/fix is filled from a
# (?P<host>...) group; "<cloud>" and "<env>" in fix are filled with the environment being diagnosed, "<workdir>" with
# its working directory (quoted where it is part of a command), "~/.cloudseed" with this cloudseed home (CLOUDSEED_HOME) and
# "<vmrest log>" with vmrest's log in it. The optional fourth element replaces the fix for local (VMware) environments,
# where the host is a VM on this machine and no public IP is involved.
_VM_DOWN = ("the VM is probably powered off or still booting: start it in VMware Fusion/Workstation, then check: "
            "cloudseed status <cloud> --env <env>")
# Terraform's checksum mismatch ("doesn't match any of the checksums previously recorded in the dependency lock file",
# "does not match any of the checksums recorded in ...", wrapped anywhere), and the same about the VMware provider
_CHECKSUMS = r"(?:does\s+not|doesn't)\s+match\s+any\s+of\s+the\s+checksums"
# Terraform names the provider before the phrase ("Error while installing <provider> ...: the local package for
# <provider> doesn't match ...", "  - <provider>: the cached package for <provider> ... does not match ...") and wraps
# the sentence over lines; the two must be in the same sentence: never across a blank line (the next diagnostic) or
# a "  - " line (the next provider of a "Required plugins are not installed" list), where another provider's mismatch
# sits next to a VMware provider that is merely missing
_VM_LOCK = (r"registry\.local/cloudseed/vmdesktop(?:(?!\n[ \t]*(?:-[ \t]|\n))[\s\S]){0,300}?" + _CHECKSUMS)
_VM_MISSING = (r"cloudseed/vmdesktop:? (was not found|there is no package)|(Missing required provider|Failed to query available "
               r"provider packages|Required plugins are not installed)[\s\S]{0,400}?cloudseed/vmdesktop")
LOG_HINTS = [
    (r"must be in format K10<CA-HASH>", "RKE2 rejected the cluster join token (it contains a '.' and looks like RKE2's K10 format).",
     "delete <workdir>/k8s/token so cloudseed generates an RKE2-style one, then: cloudseed provision <cloud> --env <env> --host k8s"),
    (r"the bootstrap token is invalid|token: \[REDACTED\] value: .* the bootstrap token", "kubeadm rejected the join token (needs [a-z0-9]{6}.[a-z0-9]{16}).",
     "delete <workdir>/k8s/token so cloudseed generates a kubeadm-style one, then: cloudseed provision <cloud> --env <env> --host k8s"),
    (r"ip_forward contents are not set to 1", "kubeadm preflight: IP forwarding is off (a hardening sysctl file overrode it).",
     "re-run `cloudseed provision <cloud> --env <env> --host k8s` with the current cloudseed (its Kubernetes play sets "
     "ip_forward: true)."),
    (r"Installing experimental CRDs on top of standard channel CRDs is prohibited", "Gateway API CRD channel mismatch (standard on the cluster, experimental wanted).",
     "cloudseed platform install gateway-api  (it lifts upstream's safe-upgrades policy for the change), then retry the item."),
    (r"docker-credential-[a-z0-9-]+\": executable file not found", "helm tried the Docker credential helper from ~/.docker/config.json.",
     "current cloudseed points helm at its own DOCKER_CONFIG (~/.cloudseed/helm/docker); update cloudseed and retry."),
    # only the locally built VMware provider: any other provider's checksum mismatch is tf.HINTS' (the plugin cache)
    (_VM_LOCK,
     "The locally built VMware provider changed after the environment's Terraform lock file was written.",
     "newer cloudseed versions drop the stale lock entry automatically; otherwise delete the registry.local/cloudseed/vmdesktop block "
     "from <workdir>/stack/.terraform.lock.hcl and re-run."),
    (r"Provider returned invalid result object after apply", "The VMware provider reported an unknown value after apply (a provider bug).",
     "rebuild the provider from the current sources: cloudseed install vmware-provider --rebuild, then re-run."),
    # cloudseed's own crash banner, or a traceback through cloudseed's code (not a remote Ansible/module error)
    (r"Unexpected error: \w+|Traceback \(most recent call last\):[\s\S]{0,4000}?File \"(?:[^\"]*/)?cloudseed/\w+\.py\"",
     "cloudseed itself crashed (a bug, not your setup).",
     "run `cloudseed troubleshoot <cloud> --env <env> --log` for the traceback; update cloudseed (git pull) and re-run; report the traceback if it persists."),
    (r"Permission denied \(publickey", "SSH rejected the key.",
     "the bastion only accepts the key in <workdir>/ssh; use `cloudseed ssh` (not a personal key). If the host was re-created, delete <workdir>/ssh/known_hosts (cloudseed keeps host keys per environment)."),
    # ssh's own "connect to host X port 22: ..." (also inside Ansible's UNREACHABLE messages); a timeout means nothing
    # answered: a firewall that no longer admits this machine's IP, or a host that is not running
    (r"port 22: (?:Connection|Operation) timed out|port 22: No route to host|timed out during banner exchange",
     "The host is not reachable on port 22 (nothing answered).",
     "if your public IP changed, the firewall no longer admits you: `cloudseed update-ip <cloud> --env <env>`; also check "
     "the host is running (`cloudseed status <cloud> --env <env>`).", _VM_DOWN),
    (r"port 22: Connection refused", "The host answered but refused SSH on port 22 (sshd is not running: the host is "
     "still booting, or sshd failed to start).",
     "wait a minute and re-run `cloudseed provision <cloud> --env <env>`; if it keeps failing, look at the instance's "
     "serial console output in the cloud console.",
     "open the VM's console in VMware Fusion/Workstation to see whether it finished booting, then re-run "
     "`cloudseed provision <cloud> --env <env>`."),
    # cloudseed's own wait (provision.Host.wait): the line ends with ssh's last error, which the entries above explain
    (r"did not accept SSH within", "The host never accepted SSH while cloudseed waited for it (the log line ends with "
     "ssh's last error).",
     "check the host is running (`cloudseed status <cloud> --env <env>`); if the last error is a timeout, your public IP "
     "may have changed: `cloudseed update-ip <cloud> --env <env>`; then re-run `cloudseed provision <cloud> --env <env>`.",
     _VM_DOWN),
    # through the bastion (ProxyJump): the bastion answered, the private host behind it did not
    (r"open failed: connect failed: (?:Connection timed out|No route to host|Connection refused)",
     "The bastion was reached, but it could not connect to the private host behind it (the host is down, still "
     "booting, or its firewall does not admit the bastion).",
     "check the host is running (`cloudseed status <cloud> --env <env>`), then re-run `cloudseed provision <cloud> --env <env>`.",
     _VM_DOWN),
    (r"REMOTE HOST IDENTIFICATION HAS CHANGED|presents a different SSH host key|Host key verification failed",
     "SSH host key changed (the host was re-created on the same address).",
     "if you re-created it, forget the old key: ssh-keygen -R <ip> -f <workdir>/ssh/known_hosts (the log shows the exact "
     "command; cloudseed keeps host keys per environment and a full destroy clears them), then re-run. Otherwise stop: "
     "something else answers on that address."),
    (r"fatal: \[localhost\]: (FAILED|UNREACHABLE)!", "An Ansible task failed on the host.",
     "look at the task name just above the failure in the log and re-run `cloudseed provision <cloud> --env <env>`; the playbook is idempotent."),
    (r"fatal: \[(?P<host>(?!localhost\])[^\]]+)\]: (FAILED|UNREACHABLE)!", "An Ansible task failed on {host}.",
     "look at the task name just above the failure in the log; re-run `cloudseed provision <cloud> --env <env> --host k8s` "
     "for Kubernetes nodes (the playbook is idempotent); UNREACHABLE means the node did not answer on SSH."),
    # apt's own texts: "Temporary failure resolving 'host'" (DNS timeout) and "Failed to fetch <uri>  Could not connect
    # ..." (NAT down); not its 404 / Hash Sum mismatch / GPG failures, which are repository problems. dnf/librepo:
    # curl errors 6 (resolve), 7 (connect) and 28 (timeout).
    (r"Could not resolve|Temporary failure (?:in name resolution|resolving)|"
     r"Failed to fetch \S+\s+(?:Could not connect|Unable to connect|Cannot initiate the connection|Connection timed out|"
     r"Connection failed|Could not resolve)|Curl error \((?:6|7|28)\)|dnf.*Errors during downloading",
     "The host has no working internet egress (NAT / DNS).",
     "check the NAT gateway (cloud) or the bastion's forwarding rules (vmware); re-run `cloudseed provision <cloud> --env <env>`."),
    # cloudseed started vmrest and it quit at once: the log line quotes what vmrest printed on the way out
    (r"vmrest exited at once \(exit code (?P<code>[^)\n]{1,12})\): (?P<tail>[^\n]{1,300})",
     "vmrest (VMware's REST service) exited right after cloudseed started it (exit code {code}): {tail}",
     "read the end of <vmrest log>; if another program holds port 8697 (lsof -nP -iTCP:8697 -sTCP:LISTEN), stop it or "
     "quit VMware and retry; then re-run the command (cloudseed starts vmrest again)."),
    (r"vmrest is not configured for this OS user", "vmrest has no `vmrest -C` configuration for this OS user, and "
     "cloudseed does not write the credentials you gave it (VMREST_USER/VMREST_PASSWORD) into it without asking.",
     "run `vmrest -C` and enter the same user name and password as VMREST_USER/VMREST_PASSWORD; or unset them (and delete "
     "~/.cloudseed/vmware.json if they were saved there) to let cloudseed configure vmrest itself; then retry."),
    (r"vmrest is not responding", "vmrest is running but did not answer within 45 seconds.",
     "read <vmrest log>; if it hangs, quit VMware (or stop vmrest) and retry: cloudseed starts it again."),
    (r"vmrest .* connection refused|is `vmrest` running", "VMware's REST service is not running.",
     "cloudseed starts it automatically; if it keeps failing run `vmrest` in a terminal to see why (needs `vmrest -C` first)."),
    (r"vmrest rejected (?:the credentials|VMREST_USER)|vmrest on port 8697 rejects the credentials",
     "vmrest rejected the credentials cloudseed used (they are not what `vmrest -C` was configured with).",
     "set VMREST_USER/VMREST_PASSWORD to the credentials you gave `vmrest -C` (or run `vmrest -C` again with them); to let "
     "cloudseed manage vmrest instead, unset them, delete ~/.cloudseed/vmware.json and retry."),
    # a vmrest someone else started (another user's `vmrest`, a terminal) holds the port with credentials cloudseed lacks
    (r"vmrest running on port 8697 was not started by cloudseed",
     "A vmrest that cloudseed did not start is running on port 8697, and cloudseed has no credentials it accepts.",
     "export VMREST_USER/VMREST_PASSWORD with the credentials it was configured with (`vmrest -C`); or stop it (its PID: "
     "lsof -nP -iTCP:8697 -sTCP:LISTEN) and retry: cloudseed then starts and configures its own."),
    (r"Unexpected HTTP \d+ from \S*:8697", "Something other than vmrest answers on port 8697.",
     "find it with lsof -nP -iTCP:8697 -sTCP:LISTEN, stop it (or move it to another port) and retry."),
    # warnings: the run went on with the provider it had (see _WARN_HINTS)
    (r"Rebuilding the VMware provider from the updated sources failed",
     "The VMware provider sources changed, but rebuilding the provider failed (usually Go could not reach its module "
     "proxy, or Go is older than 1.24), so the existing build was used: new or changed VMs need the current one.",
     "once Go can reach its module proxy (network, GOPROXY): cloudseed install vmware-provider --rebuild   (an old Go: "
     "cloudseed install go first)"),
    (r"The VMware provider sources changed since it was built, but Go is not installed",
     "The VMware provider sources changed, but Go is not installed to rebuild it, so the existing build was used.",
     "cloudseed install go && cloudseed install vmware-provider --rebuild"),
    (r"vmrun start.*(The operation was canceled|Cannot open|Insufficient|failed)", "VMware could not start the VM.",
     "open the VM once in the Fusion/Workstation GUI to see the dialog (memory/CPU limits, nested virtualization)."),
    (r"Unable to get the IP address|did not report an IP", "The VM booted but no IP was learned.",
     "give it a minute and run `cloudseed status`; on vmware make sure the guest has open-vm-tools (cloud-init installs it) and the NAT network has DHCP."),
    (r"checksum mismatch", "A download was corrupted.", "re-run; cloudseed deletes bad downloads automatically."),
    (r"No space left on device", "The disk is full.", "free space in the working directory / image cache (~/.cloudseed/images)."),
    (r"qemu-img: command not found|qemu-img required", "qemu-img is missing (needed to convert qcow2 images).", "cloudseed install qemu-img"),
    (r"go: command not found|Go required", "The Go toolchain is missing (builds the VMware provider).", "cloudseed install go"),
    (_VM_MISSING, "The VMware Terraform provider is not installed.", "cloudseed install vmware-provider"),
    (r"failed to connect to the docker API|Cannot connect to the Docker daemon|Is the docker daemon running|"
     r"Cannot connect to Podman", "The container engine is installed but not running.",
     "start Docker Desktop (or: podman machine start), then re-run; or use --runtime local"),
    (r"terraform is not installed", "Terraform is not installed.", "cloudseed install terraform"),
    (r"Exec format error|exec format error", "A tool was built for another OS/CPU (e.g. a Linux binary the container runtime "
     "left in ~/.cloudseed/bin).", "delete that file (the path is in the log) and re-run; cloudseed installs the right one"),
    # a destroy that cannot delete the network: something Terraform does not manage still uses it, usually what
    # Kubernetes created for Services/Ingresses (load balancers, their security groups / firewall rules, NEGs)
    (r"DependencyViolation", "AWS refused to delete a VPC, subnet, security group or gateway: something outside the "
     "Terraform state still uses it (usually a load balancer, a k8s-* security group or a network interface that "
     "Kubernetes created for a Service or Ingress).",
     "if the cluster still exists, delete its LoadBalancer Services, Ingresses and Gateways first (cloudseed kubectl "
     "<cloud> --env <env> get svc,ingress -A); otherwise find what uses the VPC in the EC2 console (Network interfaces, "
     "Load balancers, Security groups, filtered by the VPC id in the error) and delete it; then re-run "
     "`cloudseed destroy <cloud> --env <env>`."),
    (r"is already being used by|resourceInUseByAnotherResource", "Google Cloud refused to delete a resource (a network, "
     "subnet, address or certificate) that something else still uses; the error names it (usually a forwarding rule, a "
     "k8s-* / gke-* firewall rule or a network endpoint group that GKE created for a Service or Ingress).",
     "if the cluster still exists, delete its LoadBalancer Services and Ingresses first; otherwise delete what the error "
     "names (gcloud compute forwarding-rules list / firewall-rules list --filter=\"name~^(k8s|gke)-\" / "
     "network-endpoint-groups list, with --project), then re-run `cloudseed destroy <cloud> --env <env>`."),
]
# LOG_HINTS that report something the run worked around (it went on): shown as warnings, not errors
_WARN_HINTS = ("Rebuilding the VMware provider", "The VMware provider sources changed since it was built")
# tf.HINTS entries that describe credentials: matched against the whole log (they are distinctive); every other terraform
# hint is matched against error text only, so command echoes such as `helm ... --force-conflicts` cannot trigger them.
_WHOLE_LOG_HINTS = ("credentials",)
_LOCK_MISMATCH = getattr(tf, "LOCK_MISMATCH", _CHECKSUMS)
# tf.HINTS' "a provider is not installed": Terraform says "Required plugins are not installed" for a package that is
# there but does not match the lock file too, which the checksum entry explains instead
_NOT_INSTALLED = "Required plugins are not installed"
_EITHER_ROOT = "<workdir>/stack or <workdir>/bootstrap"


def _roots_named(text: str, workdir) -> list[str]:
    """The Terraform roots of this working directory the log names (stack, bootstrap, dry-run/<root>: cloudseed's own
    explanation of a terraform failure quotes the root that failed), in order of appearance."""
    if not workdir:
        return []
    base = re.escape(str(workdir).rstrip("/"))
    return list(dict.fromkeys(re.findall(base + r"/((?:dry-run/)?(?:stack|bootstrap))(?![\w-])", text)))


_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_GUTTER = re.compile(r"(?m)^[ \t]*[│╷╵][ \t]?")
_ERRLINE = re.compile(r"(?i)\berror\b|\bfailed\b|denied|refused|fatal|exception|not found|exceeded|invalid|expired|conflict")


def _log_path(r: dict) -> Path:
    from . import container
    return container.host_path(r.get("log") or "")


class Finding:
    def __init__(self, level: str, what: str, fix: str = ""):
        self.level, self.what, self.fix = level, what, fix


def _port_open(ip: str, port: int = 22, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _clean(text: str) -> str:
    """Log text without colours / box gutters, and without cloudseed's own echo lines: the `# cloudseed ...` header and
    `$ command ...` lines quote command lines (flags like --force-conflicts), not what went wrong."""
    text = _GUTTER.sub("", _ANSI.sub("", text))
    keep = []
    for line in text.splitlines():
        s = line.lstrip()
        if s.startswith("$ ") or s.startswith("# cloudseed ") or re.match(r"# \d{4}-\d\d-\d\dT", s) or s.startswith("# exit "):
            continue
        keep.append(line)
    return "\n".join(keep)


def _error_text(text: str) -> str:
    """Terraform/helm `Error:` diagnostics (with their detail lines) plus other error-looking lines."""
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith(("Error: ", "error: ")):
            out += lines[i:i + 40]
            i += 40
            continue
        if _ERRLINE.search(lines[i]):
            out.append(lines[i])
        i += 1
    return "\n".join(out)


def _home_text() -> str:
    """This cloudseed home as the hints name it: "~/.cloudseed" when it is the default one, else its path."""
    home = Path(paths.HOME)
    try:
        if home.expanduser().resolve() == (Path.home() / ".cloudseed").resolve():
            return "~/.cloudseed"
    except (OSError, RuntimeError):
        pass
    return str(home)


# a path in a command the user pastes (terraform -chdir=<workdir>/stack, ssh-keygen ... -f <workdir>/ssh/known_hosts):
# quoted there when the working directory needs it (a custom --workdir with spaces); prose names the plain path
_IN_COMMAND = re.compile(r"(-chdir=|-f )<workdir>(/[^\s'\"`),;]*)?")


def _cache_named(what: str, fix: str) -> tuple[str, str]:
    """A tf.HINTS entry with the plugin cache named as this user has it configured (tf._for_this_machine). With none
    configured now the general wording stays: the failed run (another shell, CI) may well have used one, and the
    variant for "no cache" would rule that cause out."""
    if getattr(tf, "ANY_CACHE", None) is None or tf.ANY_CACHE not in what + fix:
        return what, fix
    try:
        cache = tf.plugin_cache()
    except Exception:  # noqa: BLE001 - a hint never fails the diagnosis
        cache = None
    return (what.replace(tf.ANY_CACHE, cache), fix.replace(tf.ANY_CACHE, cache)) if cache else (what, fix)


def _fill(text: str, groups: dict, cloud_key: str | None, env_name: str | None, workdir=None) -> str:
    for k, v in groups.items():
        if v:
            text = text.replace("{" + k + "}", v)
    if workdir:
        wd = str(workdir).rstrip("/") or "/"
        text = _IN_COMMAND.sub(lambda m: m.group(1) + shlex.quote(wd + (m.group(2) or "")), text)
        text = text.replace("<workdir>", wd)
    if cloud_key:
        text = text.replace("<cloud>", cloud_key)
    if env_name:
        text = text.replace("<env>", env_name)
    if "<vmrest log>" in text or "~/.cloudseed" in text:
        home = _home_text()
        text = text.replace("<vmrest log>", home.rstrip("/") + "/vmrest.log").replace("~/.cloudseed", home)
    return text


def _scan_log(path: Path, cloud_key: str | None = None, env_name: str | None = None,
              local: bool | None = None, workdir=None) -> list[Finding]:
    """Findings for a failed run's log. `local` (default: cloud_key is vmware) picks the local-VM fix of the hints
    that have one; `workdir` (the environment's working directory) fills the <workdir> of paths in the fixes (without
    it, "<workdir>" stays)."""
    try:
        raw = path.read_text(errors="replace")
    except OSError:
        return []
    if local is None:
        local = cloud_key == "vmware"
    text = _clean(raw)
    errors = _error_text(text)
    # a provider package that is there but does not match the lock file: Terraform calls it "not installed" too
    mismatch = bool(re.search(_LOCK_MISMATCH, errors or text, re.I))
    out = []
    vm_lock = False
    for hint in LOG_HINTS:
        pattern, what, fix = hint[:3]
        if local and len(hint) > 3:
            fix = hint[3]
        m = re.search(pattern, text, re.I)
        if not m:
            continue
        if pattern == _VM_LOCK:
            vm_lock = True
        elif pattern == _VM_MISSING and vm_lock:
            continue                 # the VMware provider is there, it just is not the build the lock file names
        g = m.groupdict()
        level = "warn" if any(w in pattern for w in _WARN_HINTS) else "error"
        out.append(Finding(level, _fill(what, g, cloud_key, env_name, workdir),
                           _fill(fix, g, cloud_key, env_name, workdir)))
    tf_fill = getattr(tf, "_fill", None)       # <subscription>, <project>, <api>: from the error text itself
    # the Terraform roots the log names (cloudseed's own explanation of a failure quotes the root terraform ran in):
    # tf.ROOT ("<workdir>/stack") is that root when there is exactly one, the stack root otherwise; FAILED_ROOT names
    # the roots it may be
    roots = _roots_named(text, workdir)
    tf_root = tf.ROOT
    for pattern, what, fix in tf.HINTS:
        if mismatch and _NOT_INSTALLED in pattern:
            continue
        if vm_lock and pattern == _LOCK_MISMATCH:
            continue                 # the VMware entry above names the one stale lock entry
        where = text if any(w in what for w in _WHOLE_LOG_HINTS) else errors
        if re.search(pattern, where, re.I):
            what, fix = _cache_named(what, fix)
            if roots:
                fix = fix.replace(_EITHER_ROOT, " or ".join(f"<workdir>/{r}" for r in roots))
                if len(roots) == 1:
                    one = f"<workdir>/{roots[0]}"
                    what, fix = what.replace(tf_root, one), fix.replace(tf_root, one)
            if tf_fill is not None:
                what, fix = tf_fill(what, errors or text), tf_fill(fix, errors or text)
            out.append(Finding("error", _fill(what, {}, cloud_key, env_name, workdir),
                               _fill(fix, {}, cloud_key, env_name, workdir)))
    return out


# ---------------------------------------------------------------- which later runs settle an earlier failure

# flags that take a value (their value is not a positional word)
_VALUE_FLAGS = {"--env", "-e", "--cloud", "--host", "--name", "--region", "--var", "--tag", "--workdir", "--allow-ip",
                "--state", "--runtime", "--engine", "--target", "--last", "--days", "--window", "--by", "--cidr",
                "--ssh-public-key", "--ssh-private-key", "--count", "--role", "--namespaces", "--ttl", "--schedule",
                "--profile", "--framework", "--duration", "--replicas", "--lines", "--from", "--agent", "--dir", "--model"}
_GROUPS = {"platform", "vpn", "node", "k8s", "finops", "scan", "dr", "chaos", "env", "deps", "mcp", "ui", "managed"}
_CONVERGE = {"setup", "apply"}
_CONVERGE_FIXES = {"setup", "apply", "plan", "update-ip", "provision"}


def _words(argv: list[str]) -> list[str]:
    out, skip = [], False
    for a in argv or []:
        if skip:
            skip = False
            continue
        if a in _VALUE_FLAGS:
            skip = True
            continue
        if not a.startswith("-"):
            out.append(a)
    return out


def _flag(argv: list[str], name: str) -> str | None:
    for i, a in enumerate(argv or []):
        if a == name and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None


def _action(r: dict) -> tuple:
    """(command, subcommand, targets) of an audit record: `platform install velero` and `platform install gitlab` differ,
    `provision --host k8s` and `provision --host bastion` differ."""
    argv = r.get("argv") or []
    w = _words(argv)
    cmd = audit.command_of(argv) if w else (r.get("command") or "")
    rest = w[1:] if w and w[0] == cmd else w
    sub = rest[0] if cmd in _GROUPS and rest else ""
    targets = tuple(sorted(x for x in rest[1 if sub else 0:] if x not in ("aws", "gcp", "azure", "vmware")))
    if cmd == "provision":
        targets = (_flag(argv, "--host") or "all",)
    return cmd, sub, targets


def _trial(r: dict) -> bool:
    argv = r.get("argv") or []
    return "--dry-run" in argv or "--plan-only" in argv


_CLOUD_KEYS = ("aws", "gcp", "azure", "vmware")
_SELECT = "<select>"          # an interactive `destroy --select` pick (what was chosen is not in the argv)


def _destroy_scope(r: dict):
    """What a destroy run removed: None for a full destroy, else a frozenset of Terraform addresses (plus _SELECT for
    an interactive --select pick). A `destroy_scope` field in the audit record (written by the destroy command once the
    targets are resolved: "all" or the addresses) is authoritative; otherwise the argv is read - argparse accepts
    abbreviations there (`--targ X`, `--sel`), and --target takes a comma-separated list."""
    tagged = r.get("destroy_scope")
    if tagged == "all":
        return None
    if isinstance(tagged, (list, tuple)) and tagged:
        return frozenset(str(t) for t in tagged)
    argv = r.get("argv") or []
    scope: set = set()
    partial = False
    for i, a in enumerate(argv):
        if a == "--":
            break
        name, eq, val = a.partition("=")
        if len(name) > 2 and "--target".startswith(name):            # --target / --targ / --t (unique for destroy)
            partial = True
            v = val if eq else (argv[i + 1] if i + 1 < len(argv) else "")
            scope.update(x.strip() for x in v.split(",") if x.strip())
        elif len(name) > 2 and "--select".startswith(name) and not eq:
            partial = True
            scope.add(_SELECT)
    return frozenset(scope) if partial else None


def _covered(addrs, by) -> bool:
    """Every address in `addrs` is one of `by`, or inside one of them (module.x covers module.x.aws_instance.y[0])."""
    return all(any(a == b or a.startswith(b + ".") or a.startswith(b + "[") for b in by) for a in addrs)


def _undo_readonly(argv: list[str]) -> bool:
    """`undo --list` / `--drop N` (argparse also accepts `--li`, `--dr=N`, ...): they only read or edit the journal."""
    for a in argv:
        if a == "--":
            break
        name = a.partition("=")[0]
        if len(name) > 2 and ("--list".startswith(name) or "--drop".startswith(name)):
            return True
    return False


# Checks that exit non-zero by design when they find something (a FAIL verdict: scan findings, a chaos experiment that
# did not recover, a DR drill that did not restore): their failure is a result to read, not a change to repair, so it
# never hides an earlier failed setup/apply/install. Alone, it is still diagnosed.
_CHECKS = {"scan": None, "chaos": ("run",), "dr": ("test",)}


def _kube_mutates(tool: str, argv: list[str]) -> bool:
    """Did this `cs kubectl|helm ...` change the cluster (kubectl apply/delete/..., helm install/upgrade/...)?"""
    rest = list(argv[argv.index(tool) + 1:]) if tool in argv else []
    out, skip = [], False
    for a in rest:          # cloudseed's own options and the cloud come first: `cs kubectl aws --env dev get pods`
        if skip:
            skip = False
            continue
        if a in ("--env", "-e", "--runtime", "--engine", "--cloud"):
            skip = True
            continue
        if a.startswith(("--env=", "--runtime=", "--engine=", "--cloud=")) or a in ("-y", "--yes") or \
                (not out and (a in _CLOUD_KEYS or a == "--")):
            continue
        out.append(a)
    try:
        from . import cli              # one kubectl/helm argument reader (flag values are never the verb)
        parsed = cli._kube_args(tool, out)
        if tool == "kubectl":
            return bool(cli._kubectl_mutates(parsed))
        pos = parsed["pos"]
    except Exception:  # noqa: BLE001 - a partial install / an older cli: first word that is not an option
        pos = [a for a in out if not a.startswith("-")]
        if tool == "kubectl":
            from . import undo
            return bool(pos) and pos[0] in undo.MUTATING_KUBECTL
    return bool(pos) and pos[0] in ("install", "upgrade", "uninstall", "delete", "del", "un", "rollback")


def _is_operation(r: dict) -> bool:
    """A run that changes the environment (setup, apply, destroy, provision, platform install, kubectl apply, ...): its
    failure is what needs fixing. Read-only runs (finops, kubectl get, ssh, status, ...) and checks (scan, chaos run, dr
    test) fail on their own, often by design (finops k8s without a cluster, a scan with findings exit 1), and must not
    hide an earlier failed change."""
    argv = r.get("argv") or []
    cmd, sub, _ = _action(r)
    if cmd in _CHECKS and (_CHECKS[cmd] is None or sub in _CHECKS[cmd]):
        return False
    if cmd in audit.MUTATING:
        return not (cmd == "undo" and _undo_readonly(argv))
    if cmd in audit.SUB_MUTATING:
        return sub in audit.SUB_MUTATING[cmd]
    if cmd in ("kubectl", "helm"):
        return _kube_mutates(cmd, argv)
    return False


def _supersedes(ok: dict, fail: dict) -> bool:
    """Did a later successful run get past this failure? Only the same operation retried successfully, or a full
    converge (setup/apply) after a failed setup/apply/plan/update-ip/provision, or a full destroy. A partial destroy
    (--target/--select) settles only a failed partial destroy of the same (or fewer) addresses. Read-only commands
    (status, plan, finops, vpn status, kubectl get, undo --list, ...) never do."""
    if ok.get("exit_code") != 0:
        return False
    if _trial(ok) and not _trial(fail):
        return False
    a_ok, a_fail = _action(ok), _action(fail)
    argv = ok.get("argv") or []
    if a_ok[0] == "undo" and _undo_readonly(argv):
        return False
    if a_ok[0] == "destroy":
        # for destroy "no targets" means everything, so the generic superset rule below is the wrong way round
        s_ok = _destroy_scope(ok)
        if s_ok is None:
            return True                          # a full destroy settles everything before it
        if a_fail[0] != "destroy":
            return False                         # a partial destroy never fixes a failed setup, apply, install, ...
        s_fail = _destroy_scope(fail)
        return s_fail is not None and _covered(s_fail, s_ok)
    if a_ok[:2] == a_fail[:2] and set(a_fail[2]) <= set(a_ok[2]):   # the same operation (or a superset) worked
        return True
    if a_ok[0] in _CONVERGE and a_fail[0] in _CONVERGE_FIXES:
        return not (a_fail[0] == "provision" and "--no-provision" in argv)
    return False


# the exit code of a run that showed its plan and stopped for approval (no terminal, no --auto-approve): nothing was
# changed, so it is not a failure to diagnose
APPROVAL_STOP = 3


def _not_failed(r: dict) -> bool:
    """A run that did not fail: it succeeded, is still running (no exit code yet) or stopped for approval."""
    return r.get("exit_code") in (0, None, APPROVAL_STOP)


def _pick_failure(runs: list[dict], diagnostic: set):
    """(failure to diagnose or None, (settled failure, the later run that got past it) or None, newer read-only
    failures). A change that failed and was not got past later wins over any read-only run that failed after it;
    without one, the newest failure that is not settled (a failing `cs ssh` alone is still worth reading); without
    that, the newest settled failure is reported as history."""
    open_, settled = [], []
    for i, r in enumerate(runs):
        if _not_failed(r) or _action(r)[0] in diagnostic:
            continue
        later = [x for x in runs[i + 1:] if _supersedes(x, r)]
        if later:
            settled.append((r, later[-1]))
        else:
            open_.append((i, r))
    ops = [x for x in open_ if _is_operation(x[1])]
    chosen = ops[-1] if ops else (open_[-1] if open_ else None)
    if chosen is None:
        return None, (settled[-1] if settled else None), []
    newer = [r for i, r in open_ if i > chosen[0] and not _is_operation(r)]
    return chosen[1], None, newer


def _state_finding(env: paths.Env) -> Finding | None:
    """A local Terraform state file that is not valid JSON (every plan/apply/status/destroy then fails)."""
    state = env.stack_dir / "terraform.tfstate"
    try:
        text = state.read_text(errors="replace")
    except OSError:
        return None
    if not text.strip():
        return None                             # an empty state file is what terraform treats as "no state"
    try:
        json.loads(text)
        return None
    except ValueError:
        pass
    backup = state.with_name(state.name + ".backup")
    try:
        json.loads(backup.read_text(errors="replace"))
        fix = (f"Terraform keeps the previous state in {backup}: copy it over {state} (keep the broken file aside first), "
               "then check with `cloudseed status`; a resource created in the last run may then have to be imported "
               "or deleted by hand")
    except (OSError, ValueError):
        fix = (f"restore {state} from a backup; without one, the resources this environment created have to be "
               "imported again (terraform import) or deleted by hand before re-running setup")
    return Finding("error", f"The Terraform state file is unreadable (not valid JSON): {state}", fix)


def run(cloud, env: paths.Env, cfg: dict, last: int = 10, show_log: bool = False) -> int:
    last = int(10 if last is None else last)
    if last < 1:
        # the window also decides which failure is diagnosed: 0 or a negative count must not silently change it
        raise ui.Abort(f"--last must be 1 or more (got {last}).", code=2)
    findings: list[Finding] = []
    ui.header(f"Troubleshooting {env.id}")
    ui.kv("Working dir", str(env.dir))

    # 1. audit trail
    runs = audit.read_audit(env, last)
    diagnostic = {"troubleshoot", "inventory", "status", "output", "doctor", "help", "list", "explain"}
    failed = [r for r in runs if not _not_failed(r) and _action(r)[0] not in diagnostic]
    waiting = [r for r in runs if r.get("exit_code") == APPROVAL_STOP]
    ui.kv("Recent runs", f"{len(runs)} (failed: {len(failed)}" + (f", stopped for approval: {len(waiting)})" if waiting else ")"))
    for r in runs[-last:]:
        good = r.get("exit_code") == 0
        paused = r.get("exit_code") == APPROVAL_STOP
        mark = ui.style("✔", "leaf") if good else ui.style("▲", "seed") if paused else ui.style("✖", "rose", "bold")
        cmd = " ".join(r.get("argv", []))[:80]
        note = ui.dim("  (plan shown, stopped for approval: nothing changed)") if paused else ""
        # ui.line: the rows reach this command's own log too (plain text)
        ui.line(f"      {mark} {ui.dim(r.get('at', '')[:19])}  {cmd if good or paused else ui.style(cmd, 'text', 'bold')}  "
                f"{ui.dim(str(r.get('duration_s', '?')) + 's')}{note}")
    last_fail, past, newer = _pick_failure(runs, diagnostic)
    settled = past[0] if past else None
    if past:
        # A failure that a later run really got past is history, not a problem to fix now.
        findings.append(Finding("info", f"An earlier run failed ({' '.join(settled.get('argv', []))[:60]}) but "
                                f"a later run got past it: {' '.join(past[1].get('argv', []))[:60]}.",
                                f"nothing to do; the old log is {_log_path(settled)}"))
    if last_fail and last_fail.get("log"):
        log = _log_path(last_fail)
        ui.kv("Last failure log", str(log))
        hits = _scan_log(log, cloud.key, env.name, local=bool(cloud.local), workdir=env.dir)
        for h in hits:
            if cloud.local and "update-ip" in h.fix:   # local VMs: the public IP plays no part, a stopped VM does
                h.fix = _fill(_VM_DOWN, {}, cloud.key, env.name, env.dir)
        if hits:
            findings += hits
        else:
            findings.append(Finding("warn", f"The last failed run ({' '.join(last_fail.get('argv', []))}) has no recognised error signature.",
                                    f"read the log: {log}   (or: cloudseed troubleshoot {cloud.key} --env {env.name} --log)"))
    elif last_fail:
        findings.append(Finding("warn", f"The last failed run ({' '.join(last_fail.get('argv', []))}) wrote no log "
                                "(it stopped before reaching the environment).", "re-run it to see the error"))
    if waiting and waiting[-1] is runs[-1] and not last_fail:
        # the newest run only waits for a yes: say how to give it, never "failed"
        findings.append(Finding("info", f"The last run ({' '.join(waiting[-1].get('argv', []))[:60]}) showed its plan and "
                                "stopped for approval (exit 3): nothing was changed.",
                                "re-run it in a terminal and answer the prompt, or add --auto-approve (setup: -y --auto-approve)"))
    if newer:   # e.g. `finops k8s` without a cluster, `kubectl get`, `ssh -- cmd`, a scan with findings: shown, not diagnosed instead
        shown_runs = "; ".join(" ".join(r.get("argv", []))[:50] for r in newer[-3:])
        their_logs = [str(_log_path(r)) for r in newer[-3:] if r.get("log")]
        findings.append(Finding("info", f"Read-only runs or checks after that failure also failed ({shown_runs}); the "
                                "failed change above is diagnosed first.",
                                ("read their own logs if they matter too: " + ", ".join(their_logs)) if their_logs else ""))
    shown = last_fail or settled
    if show_log and shown and shown.get("log"):
        log = _log_path(shown)
        ui.line()
        ui.line(ui.bold("Last failure log (tail)" if last_fail else "Earlier failure log (tail; a later run got past it)"))
        try:
            for line in log.read_text(errors="replace").splitlines()[-60:]:
                ui.line("   " + line)
        except OSError:
            ui.line("   " + ui.dim(f"(cannot read {log})"))

    # 2. inventory vs reality
    inv = audit.load(env)
    current = inv.get("current") or {}
    ui.kv("Inventory", f"{current.get('count', 0)} resources, updated {current.get('updated_at', 'never')}")
    outputs = current.get("outputs") or {}
    broken_state = _state_finding(env)
    unreadable = next((h for h in reversed(inv.get("history") or []) if "resources" in h or "state_unreadable" in h), {})
    if broken_state:
        findings.append(broken_state)
    elif unreadable.get("state_unreadable"):
        # the last Terraform run could not read the state back (audit.refresh): the inventory is older than the stack
        findings.append(Finding("error", f"Terraform could not read the state after the last {unreadable.get('action', 'run')} "
                                f"({unreadable['state_unreadable']}), so the inventory and outputs may be out of date.",
                                f"fix that error, then re-read the outputs: cloudseed status {cloud.key} --env {env.name} "
                                "(the inventory is recorded again by the next setup or apply)"))
    elif not current.get("updated_at"):   # only notes (a finops report, a scan): Terraform never wrote a snapshot
        findings.append(Finding("info", "Nothing has been applied yet (empty inventory).", f"cloudseed setup {cloud.key} --env {env.name}"))

    # 3. tools and credentials
    req, _opt = deps.missing(cloud.key)
    for t in req:
        if cloud.local and t == "vmrun":
            continue  # reported with the install link in the VMware section below
        findings.append(Finding("error", f"Required tool missing: {t}.", f"cloudseed install {t}"))
    live = deps.live_credential_check(cloud.key)
    if live is not None:
        if not live[0]:
            findings.append(Finding("error", live[1], ""))
    elif not cloud.local:
        for w in cloud.credential_warnings(cfg):
            findings.append(Finding("error", w, ""))

    # 4. reachability and allowed IPs
    ip = outputs.get("bastion_public_ip")
    if not ip and cloud.local and current.get("count"):
        # applied, yet no address: VMware never reported the bastion VM's IP (a stopped VM, no VMware Tools, no DHCP)
        findings.append(Finding("error", "The bastion VM has no IP address (VMware did not report one).",
                                "give it a minute, start it in VMware Fusion/Workstation if it is off, then refresh the "
                                f"outputs: cloudseed apply {cloud.key} --env {env.name}; the guest needs open-vm-tools "
                                "(cloud-init installs it) and the network DHCP"))
    if ip:
        ok = _port_open(ip)
        ui.kv("Bastion", f"{ip}  port 22 {'open' if ok else 'CLOSED'}")
        mine = None if cloud.local else netutil.detect_public_ip()
        allowed = cfg.get("allowed_ssh_cidrs", [])
        not_allowed = bool(mine) and not any(ipaddress.ip_address(mine) in ipaddress.ip_network(c, strict=False) for c in allowed)
        if not_allowed:
            findings.append(Finding("error", f"Your public IP {mine} is not in the allowed list {allowed}.",
                                    f"cloudseed update-ip {cloud.key} --env {env.name}"))
        if not ok and cloud.local:   # a host-only VMware network: the public IP plays no part
            findings.append(Finding("error", f"Cannot reach the bastion {ip} on port 22 from here.",
                                    "the bastion VM is probably powered off or still booting: start it in VMware Fusion/Workstation, "
                                    f"then check: cloudseed status {cloud.key} --env {env.name}"))
        elif not ok and mine and not not_allowed:   # the cloud firewall admits us, so update-ip would change nothing
            findings.append(Finding("error", f"Cannot reach the bastion {ip} on port 22 from here although your IP is allowed.",
                                    "check the instance is running (cloud console); a bastion provisioned by an older cloudseed may "
                                    f"still pin your previous IP in its host firewall: `cloudseed update-ip {cloud.key} --env {env.name}` "
                                    "checks SSH and prints the recovery steps"))
        elif not ok and not mine:   # public IP unknown: both causes are possible
            findings.append(Finding("error", f"Cannot reach the bastion {ip} on port 22 from here.",
                                    f"if your public IP changed: cloudseed update-ip {cloud.key} --env {env.name}; "
                                    "otherwise check the instance is running (cloud console)"))
        key = env.private_key_path(cfg)
        if not key.exists():
            findings.append(Finding("error", f"SSH private key missing: {key}", "re-run setup with --ssh-public-key/--ssh-private-key pointing at your key"))
    prov_info = cfg.get("provisioned") or {}
    if ip and not prov_info.get("bastion"):
        findings.append(Finding("warn", "The bastion has never been provisioned (no hardening applied).", f"cloudseed provision {cloud.key} --env {env.name}"))

    # 5. local virtualization specifics
    if cloud.local:
        from . import localvm
        h = localvm.detect_host()
        if not h or not h.get("found"):
            home = localvm.vmware_home_problem(h)     # VMWARE_HOME points somewhere without vmrun
            findings.append(Finding("error", home, "") if home else
                            Finding("error", "VMware Desktop (vmrun) not found.", "cloudseed install vmrun   (opens the download page, then installs the downloaded file)"))
        else:
            ui.kv("VMware", f"{h['product']} {h['version']} ({h['guest_arch']} guests)")
            too_old = localvm.version_problem(h)
            if too_old:
                findings.append(Finding("error", too_old, ""))
        if not localvm.provider_binary().exists():
            findings.append(Finding("error", "Terraform provider for VMware not built.", "cloudseed install vmware-provider"))
        base = cfg["vars"].get("base_disk")
        if base and base != "/dev/null" and not Path(base).exists():
            findings.append(Finding("error", f"Base image missing: {base}", "re-run setup; the image is downloaded again"))
        if not localvm._port_open():
            findings.append(Finding("warn", "vmrest is not running (needed for network changes).", "cloudseed starts it on the next plan/apply"))
        # where the VMs really are (a legacy relative / ~ value lives under <workdir>/stack/<value>)
        vm_dir = cloud.vm_dir_path(dict(cfg, workdir=cfg.get("workdir") or str(env.dir))) if hasattr(cloud, "vm_dir_path") \
            else Path((cfg.get("vars") or {}).get("vm_dir") or env.vms_dir)
        for r in current.get("resources", []):
            # a relative path an older version recorded is relative to <workdir>/stack, not to this command's directory
            if r.get("type") == "vmdesktop_vm" and r.get("vmx_path") and \
                    not Path(localvm.recorded_vmx_path(r["vmx_path"], cfg.get("workdir") or str(env.dir))).exists():
                vm = r.get("cloud_name") or r.get("name")
                findings.append(Finding("error", f"VM files missing for {vm}: {r['vmx_path']}",
                                        f"the VM was removed outside cloudseed; `cloudseed apply {cloud.key} --env {env.name}` "
                                        "re-creates it (or remove it from the state: terraform state rm)"))
        ui.kv("VM dir", str(vm_dir))

    # 6. disk space
    try:
        free_gb = shutil.disk_usage(env.dir).free / 1e9
        ui.kv("Free disk", f"{free_gb:.1f} GB")
        if free_gb < 5:
            findings.append(Finding("warn", f"Only {free_gb:.1f} GB free at {env.dir}.", "free space before creating VMs/images"))
    except OSError:
        pass

    # report (deduplicated: the same problem, or the same advice, is shown once)
    seen: set[str] = set()

    def _key(f: Finding) -> list[str]:
        return [f.what, re.sub(r"\W+", " ", f.fix.lower()).strip() or f.what]

    findings = [f for f in findings if not (any(k in seen for k in _key(f)) or seen.update(_key(f)))]
    if not findings:
        ui.panel("Findings", [ui.style("✔ No problems found.", "leaf", "bold")], accent="leaf")
        return 0
    color = {"error": "rose", "warn": "seed", "info": "sky"}
    lines: list[str] = []
    for f in findings:
        lines.append(f"{ui.style('●', color[f.level], 'bold')} {f.what}")
        if f.fix:
            lines.append(f"   {ui.style('fix', 'muted')} {ui.style(f.fix, 'text')}")
    lines.append("")
    lines.append(ui.dim(f"logs: {env.dir / 'logs'}"))
    lines.append(ui.dim(f"inventory: {env.dir / 'inventory.json'}"))
    ui.panel("Findings", lines, accent="rose" if any(f.level == "error" for f in findings) else "seed")
    return 0  # findings are the result, not a failure of this command
