"""Public IP detection, CIDR helpers, login names and SSH key handling."""

from __future__ import annotations

import base64
import binascii
import getpass
import ipaddress
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path

from . import ui

IP_SOURCES = (
    "https://checkip.amazonaws.com",
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://ifconfig.me/ip",
)


def detect_public_ip(timeout: float = 5.0) -> str | None:
    for url in IP_SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cloudseed"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read(64).decode().strip()
            ipaddress.IPv4Address(text)
            return text
        except Exception:
            continue
    return None


# ---------------------------------------------------------------- CIDRs

# The SSH allow-list must stay narrow: no single range wider than a /8 (16.7M addresses) and no more than two /8s in
# total. That refuses 0.0.0.0/0 and also its disguises (0.0.0.0/1 + 128.0.0.0/1, a typo such as 203.0.113.7/3).
MIN_ALLOWED_PREFIX = 8
MAX_ALLOWED_ADDRESSES = 2 * 2 ** 24


def normalize_cidr(value: str) -> str:
    value = str(value).strip()
    if "/" not in value:
        addr = ipaddress.ip_address(value)
        value = f"{value}/{32 if addr.version == 4 else 128}"
    net = ipaddress.ip_network(value, strict=False)
    return str(net)


def _split(raw) -> list[str]:
    items = raw if isinstance(raw, (list, tuple)) else [raw]
    return [p.strip() for item in items for p in str(item).split(",") if p.strip()]


def validate_cidr_list(raw) -> str | None:
    """Problem with an SSH allow-list (comma-separated string or list), or None. IPv4 only: every bastion firewall,
    security group, NSG and Kubernetes authorized-network list cloudseed renders is IPv4."""
    parts = _split(raw)
    if not parts:
        return "At least one CIDR is required."
    nets = []
    for p in parts:
        try:
            net = ipaddress.ip_network(normalize_cidr(p))
        except ValueError:
            return f"'{p}' is not a valid IP or CIDR."
        if net.version == 6:
            return (f"'{p}' is an IPv6 address; the bastion only has an IPv4 address and its firewall rules are IPv4-only. "
                    "Use your public IPv4 address (e.g. `curl -4 ifconfig.me`).")
        # an address with a prefix (203.0.113.7/24, pasted from `ip addr`, or a habitual /24 after one's own IP) is
        # refused at every prefix length: silently widening it to its network would admit the whole range
        if "/" in p:
            ip = ipaddress.ip_interface(p).ip
            if ip != net.network_address:
                whole = f", or {net} for the whole range" if net.prefixlen >= MIN_ALLOWED_PREFIX else ""
                return (f"'{p}' has host bits set, so it means {net} ({net.num_addresses:,} addresses). "
                        f"Did you mean {ip}/32 (just that address){whole}?")
        nets.append(net)
    merged = list(ipaddress.collapse_addresses(nets))
    if min(n.prefixlen for n in merged) == 0:
        return "Refusing 0.0.0.0/0: the bastion must not be open to the whole internet" + \
            (f" ({', '.join(parts)} together cover it)." if len(parts) > 1 else ".")
    # the width rule applies to the ranges as given: two /8s that happen to be adjacent (10/8 + 11/8) are as wide as
    # two that are not (11/8 + 12/8); the total below caps the list as a whole
    widest = min(nets, key=lambda n: n.prefixlen)
    if widest.prefixlen < MIN_ALLOWED_PREFIX:
        return (f"Refusing {widest}: ranges wider than /{MIN_ALLOWED_PREFIX} would open the bastion to a large part of the "
                "internet. Allow your own IP (or your office/VPN egress range) instead.")
    total = sum(n.num_addresses for n in merged)
    if total > MAX_ALLOWED_ADDRESSES:
        return (f"Refusing the allow-list: together it covers {total:,} addresses (more than two /8 networks). "
                "Allow your own IP (or your office/VPN egress range) instead.")
    return None


def normalize_cidr_list(raw) -> list[str]:
    """Canonical allow-list: normalized, duplicates and overlapping/adjacent ranges merged, sorted. A merge never yields
    a range wider than a /8 (10.0.0.0/8 + 11.0.0.0/8 stay two /8s rather than 10.0.0.0/7), so the saved list passes
    validate_cidr_list again on the next run."""
    nets = [ipaddress.ip_network(normalize_cidr(p)) for p in _split(raw)]
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    out: list[str] = []
    for n in ipaddress.collapse_addresses(v4):
        pieces = n.subnets(new_prefix=MIN_ALLOWED_PREFIX) if 0 < n.prefixlen < MIN_ALLOWED_PREFIX else [n]
        out += [str(x) for x in pieces]
    return out + [str(n) for n in ipaddress.collapse_addresses(v6)]


def validate_cidr(raw: str) -> str | None:
    """Problem with a network (VPC/VNet/vmnet) CIDR, or None."""
    text = str(raw).strip()
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError:
        try:
            loose = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return f"'{raw}' is not a valid network CIDR (e.g. 10.0.0.0/16)."
        return f"'{raw}' has host bits set; the network address is {loose} (use that)."
    if net.version != 4:
        return f"'{raw}' is IPv6; cloudseed networks are IPv4 (e.g. 10.0.0.0/16)."
    return None


def pick_network_cidr(used: list[str]) -> str:
    """First private /16 that doesn't overlap anything already used by another env: 10.0-255, then 172.17-31
    (172.16.0.0/16 holds the default GKE control-plane range 172.16.0.0/28), then 192.168.0.0/16."""
    used_nets = []
    for u in used:
        try:
            used_nets.append(ipaddress.ip_network(u, strict=False))
        except ValueError:
            pass
    candidates = [f"10.{n}.0.0/16" for n in range(256)] + [f"172.{n}.0.0/16" for n in range(17, 32)] + ["192.168.0.0/16"]
    for c in candidates:
        cand = ipaddress.ip_network(c)
        if not any(cand.version == u.version and cand.overlaps(u) for u in used_nets):
            return str(cand)
    raise ui.Abort("Every private /16 is already used by another environment; pass --cidr with a free range.")


# ---------------------------------------------------------------- login names

# Debian/Ubuntu (the images cloudseed boots) accept upper case and dots in user names, and Azure allows upper-case admin
# names: only refuse what breaks (spaces, ':', a leading digit or '-', more than 32 characters).
_LOGIN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
# accounts that already exist (with a nologin shell or special meaning) on the Ubuntu/Debian images cloudseed boots
SYSTEM_ACCOUNTS = frozenset({
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup",
    "list", "irc", "gnats", "nobody", "sshd", "syslog", "messagebus", "_apt", "polkitd", "tss", "uuidd", "tcpdump",
    "landscape", "fwupd-refresh", "usbmux", "dnsmasq", "lxd", "pollinate", "tpm",
})
# Names YAML (cloud-init user-data, Ansible inventories and vars) reads as a boolean or null, in any case: the user
# would be created as `true` or not at all.
YAML_KEYWORDS = frozenset({"yes", "no", "true", "false", "on", "off", "null"})


def validate_login_username(value) -> str | None:
    """Problem with a login name for the bastion/VMs, or None."""
    v = str(value or "").strip()
    if not _LOGIN_RE.match(v):
        return "Use 1-32 letters, digits, '_', '-' or '.', starting with a letter or '_'."
    if v in SYSTEM_ACCOUNTS or v.startswith("systemd-"):
        return (f"'{v}' is a system account on the VM images (root login is disabled: PermitRootLogin no); "
                "pick your own name.")
    if v.lower() in YAML_KEYWORDS:
        return (f"'{v}' is a YAML keyword (cloud-init and Ansible would read it as "
                f"{'null' if v.lower() == 'null' else 'true/false'}); pick another name.")
    return None


def local_username() -> str:
    """Default login name for new hosts: this machine's user, made safe. CLOUDSEED_USER wins (the container runtime
    passes the host user in, because inside the container everything runs as root); root and names Linux would refuse
    fall back to SUDO_USER, then to 'cloudseed'."""
    candidates = [os.environ.get("CLOUDSEED_USER")]
    try:
        candidates.append(getpass.getuser())
    except Exception:  # noqa: BLE001 - no passwd entry for this uid
        pass
    candidates.append(os.environ.get("SUDO_USER"))
    for raw in candidates:
        if not raw:
            continue
        name = re.sub(r"[^a-z0-9_-]", "", str(raw).lower())[:32]
        if validate_login_username(name) is None:
            return name
    return "cloudseed"


# ---------------------------------------------------------------- SSH keys

# File names of generated key pairs, in the order paths.Env.private_key_path looks for them.
KEY_FILES = ("id_ed25519", "id_rsa", "id_ecdsa")
_PUBKEY_RE = re.compile(r"^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+")
_ECDSA_BITS = {"nistp256": 256, "nistp384": 384, "nistp521": 521}
FIPS_MIN_RSA_BITS = 3072          # FIPS 186-5 / SP 800-131A: cloudseed asks for >= 3072 (the generated key is 4096)
MIN_RSA_BITS = 1024               # OpenSSH's RequiredRSASize default: sshd refuses anything shorter
AWS_RSA_SIZES = (1024, 2048, 4096)   # EC2 ImportKeyPair only accepts these RSA lengths
AZURE_MIN_RSA_BITS = 2048         # Azure refuses shorter RSA keys


def _ssh_fields(blob: bytes) -> list[bytes]:
    """Split an OpenSSH wire-format key blob into its length-prefixed fields."""
    out, i = [], 0
    while i + 4 <= len(blob):
        n = int.from_bytes(blob[i:i + 4], "big")
        i += 4
        if n > len(blob) - i:
            raise ValueError("truncated key blob")
        out.append(blob[i:i + n])
        i += n
    if i != len(blob):
        raise ValueError("trailing bytes in key blob")
    return out


def ssh_key_info(pub: str) -> tuple[str, int]:
    """(algorithm, bits) of an OpenSSH public key line, e.g. ('ssh-rsa', 4096); ('', 0) when it is not a valid key."""
    parts = str(pub or "").split()
    if len(parts) < 2 or not _PUBKEY_RE.match(f"{parts[0]} {parts[1]}"):
        return "", 0
    try:
        fields = _ssh_fields(base64.b64decode(parts[1], validate=True))
        algo = fields[0].decode("ascii")
    except (ValueError, binascii.Error, IndexError, UnicodeDecodeError):
        return "", 0
    if algo != parts[0]:
        return "", 0
    if algo == "ssh-rsa" and len(fields) >= 3:
        return algo, int.from_bytes(fields[2], "big").bit_length()
    if algo.startswith("ecdsa-sha2-") and len(fields) >= 3:
        return algo, _ECDSA_BITS.get(fields[1].decode("ascii", "replace"), 0)
    if algo == "ssh-ed25519" and len(fields) >= 2:
        return algo, 256
    return "", 0


def ssh_key_problem(pub: str, fips: bool = False, cloud: str = "") -> str | None:
    """Why this public key cannot be used for an environment on `cloud` (FIPS mode or not), or None.

    ed25519 is not FIPS 140-approved (FIPS-mode sshd refuses it); EC2 key pairs and Azure VMs refuse ECDSA; EC2 only
    imports RSA-1024/2048/4096 and Azure needs RSA >= 2048. RSA-4096 is the one key type every target accepts in FIPS
    mode, which is why cloudseed generates it there."""
    algo, bits = ssh_key_info(pub)
    if not algo:
        return "this is not a valid OpenSSH public key (expected a line like 'ssh-ed25519 AAAA... comment')"
    rsa_hint = "an RSA-4096 key (ssh-keygen -t rsa -b 4096)"
    if algo == "ssh-ed25519" and fips:
        return f"ed25519 is not a FIPS 140-approved algorithm (FIPS-mode sshd refuses it); use {rsa_hint}"
    if algo.startswith("ecdsa-") and cloud in ("aws", "azure"):
        who = "EC2 key pairs" if cloud == "aws" else "Azure VMs"
        return f"{who} accept only RSA and ED25519 SSH keys, not ECDSA; use " + (rsa_hint if fips else "ed25519 or RSA")
    if algo == "ssh-rsa":
        if bits < MIN_RSA_BITS:
            return f"RSA-{bits} is too weak (sshd refuses RSA keys under {MIN_RSA_BITS} bits); use {rsa_hint}"
        if fips and bits < FIPS_MIN_RSA_BITS:
            return f"RSA-{bits} is too short for FIPS mode (>= {FIPS_MIN_RSA_BITS} bits); use {rsa_hint}"
        if cloud == "aws" and bits not in AWS_RSA_SIZES:
            return (f"EC2 key pairs only accept RSA keys of {', '.join(map(str, AWS_RSA_SIZES))} bits, not {bits}; "
                    f"use {rsa_hint}")
        if cloud == "azure" and bits < AZURE_MIN_RSA_BITS:
            return f"Azure needs RSA keys of >= {AZURE_MIN_RSA_BITS} bits, not {bits}; use {rsa_hint}"
    return None


def ensure_ssh_key(ssh_dir: Path, comment: str, fips: bool = False, cloud: str = "") -> tuple[Path, Path]:
    """The environment's generated key pair: (private, public). Reuses a pair in ssh_dir when its type suits the mode
    and cloud, else generates one: ed25519 (id_ed25519) normally; RSA-4096 (id_rsa) in FIPS mode, because ed25519 is
    not FIPS-approved and EC2 key pairs and Azure VMs refuse ECDSA. A pair of the wrong type (e.g. an ed25519 key left
    by a setup that aborted before FIPS mode was chosen) is never overwritten; the new pair is created next to it."""
    ssh_dir = Path(ssh_dir)
    order = ("id_rsa", "id_ecdsa", "id_ed25519") if fips else ("id_ed25519", "id_rsa", "id_ecdsa")
    for name in order:
        priv, pub = ssh_dir / name, ssh_dir / f"{name}.pub"
        if not (priv.is_file() and pub.is_file()):
            continue
        try:
            text = pub.read_text().strip()
        except (OSError, UnicodeDecodeError):
            continue
        if ssh_key_problem(text, fips=fips, cloud=cloud) is None:
            return priv, pub
    if fips:
        name, args, label = "id_rsa", ["-t", "rsa", "-b", "4096"], "an RSA-4096 SSH key pair (FIPS mode)"
    else:
        name, args, label = "id_ed25519", ["-t", "ed25519"], "an ed25519 SSH key pair"
    priv, pub = ssh_dir / name, ssh_dir / f"{name}.pub"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    try:
        ssh_dir.chmod(0o700)
    except OSError:
        pass
    stamp = time.strftime("%Y%m%d%H%M%S")
    for p in (priv, pub):   # an unusable or half-written pair under the target name: keep it, but out of the way
        if p.exists() or p.is_symlink():
            p.rename(p.with_name(f"{p.name}.replaced-{stamp}"))
    ui.info(f"Generating {label} at {priv}")
    try:
        subprocess.run(["ssh-keygen", "-q", *args, "-N", "", "-C", comment, "-f", str(priv)], check=True,
                       stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise ui.Abort("ssh-keygen (OpenSSH client) is not installed; install it, or pass your own key with "
                       "--ssh-public-key.")
    except subprocess.CalledProcessError as e:
        raise ui.Abort(f"ssh-keygen failed (exit {e.returncode}) creating {priv}.")
    priv.chmod(0o600)
    return priv, pub


def private_key_for(pub_path, explicit=None) -> tuple[str, str | None]:
    """(private key path, warning or None) for a user-supplied public key. `explicit` is --ssh-private-key. Without it
    the private key is the .pub file minus its suffix; when there is no such file (a key that lives only in ssh-agent or
    on a security token, or a public key saved without the .pub suffix) the public key file itself is used as the
    identity: OpenSSH then signs with the matching key from ssh-agent."""
    pub_path = Path(pub_path).expanduser()
    if explicit:
        priv = Path(explicit).expanduser()
        if not priv.is_file():
            return str(priv), (f"--ssh-private-key {priv} does not exist; ssh will only work if ssh-agent holds that key.")
        return str(priv), None
    if pub_path.name.endswith(".pub"):
        priv = pub_path.with_name(pub_path.name[:-4])
        if priv.is_file():
            return str(priv), None
        return str(pub_path), (f"No private key next to {pub_path} (expected {priv}); ssh will use the matching key "
                               "from ssh-agent. Pass --ssh-private-key if the private key lives elsewhere.")
    sibling = pub_path.with_suffix("")
    if sibling != pub_path and sibling.is_file():
        try:
            if "PRIVATE KEY" in sibling.read_text(errors="replace")[:200]:
                return str(sibling), None
        except OSError:
            pass
    return str(pub_path), (f"Cannot tell where the private key for {pub_path} is (the file has no .pub suffix); ssh will "
                           "use the matching key from ssh-agent. Pass --ssh-private-key PATH to name it.")


def read_public_key(path: Path) -> str:
    """The first OpenSSH public key line in a file, validated. Clean errors for a missing file, a directory, a binary
    or private key file."""
    path = Path(path).expanduser()
    try:
        text = path.read_text()
    except IsADirectoryError:
        raise ui.Abort(f"{path} is a directory; pass the public key file itself (e.g. {path}/id_ed25519.pub).")
    except FileNotFoundError:
        raise ui.Abort(f"SSH public key not found: {path}")
    except (OSError, UnicodeDecodeError) as e:
        raise ui.Abort(f"Cannot read SSH public key {path}: {e}")
    line = next((ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")), "")
    if "PRIVATE KEY" in text:
        raise ui.Abort(f"{path} is a private key; pass the public key (usually the same name with .pub).")
    if not ssh_key_info(line)[0]:
        raise ui.Abort(f"{path} does not look like an OpenSSH public key (expected a line like 'ssh-ed25519 AAAA... comment').")
    return line
