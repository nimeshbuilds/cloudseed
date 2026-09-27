#!/usr/bin/env python3
"""Import a release-only Apple identity into an ephemeral Actions keychain.

No credential is emitted to logs, build outputs, or GITHUB_ENV. Only the public
identity fingerprint and temporary keychain directory cross step boundaries.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile


class SigningError(Exception):
    pass


def run(command: list[str], purpose: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True, timeout=90,
                              env={k: v for k, v in os.environ.items() if not k.startswith("APPLE_SIGNING_")})
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # A tool failure can contain credential arguments or imported data.
        raise SigningError(f"Apple signing: {purpose} failed; no unsigned release will be published.") from None


def required() -> bool:
    value = os.environ.get("CLOUDSEED_REQUIRE_APPLE_SIGNING", "false").lower()
    if value not in ("true", "false"):
        raise SigningError("CLOUDSEED_REQUIRE_APPLE_SIGNING must be true or false.")
    return value == "true"


def team_id() -> str:
    team = os.environ.get("CLOUDSEED_APPLE_TEAM_ID", "")
    if not re.fullmatch(r"[A-Z0-9]{10}", team):
        raise SigningError("A valid expected CLOUDSEED_APPLE_TEAM_ID is required.")
    return team


def emit_env(name: str, value: str) -> None:
    if "\n" in value or "\r" in value:
        raise SigningError("Invalid signing environment value.")
    with Path(os.environ["GITHUB_ENV"]).open("a") as out:
        out.write(f"{name}={value}\n")


def cleanup(directory: Path | None = None) -> None:
    value = str(directory) if directory else os.environ.get("CLOUDSEED_SIGNING_DIR", "")
    if not value:
        return
    folder = Path(value)
    root = Path(os.environ["RUNNER_TEMP"]).resolve()
    if folder.is_symlink() or folder.resolve().parent != root or not folder.name.startswith("cloudseed-signing-"):
        raise SigningError("Refusing to clean a path outside the temporary signing directory.")
    if not folder.exists():
        return
    errors = []
    try:
        saved = folder / "search-list.json"
        if saved.exists():
            try:
                original = json.loads(saved.read_text())
                if not isinstance(original, list) or not all(isinstance(p, str) for p in original):
                    raise SigningError("Invalid saved keychain search list.")
                run(["security", "list-keychains", "-d", "user", "-s", *original], "restoring the keychain search list")
            except (SigningError, ValueError, OSError) as exc:
                errors.append(str(exc))
        keychain = folder / "signing.keychain-db"
        if keychain.exists():
            try:
                run(["security", "delete-keychain", str(keychain)], "deleting the temporary keychain")
            except SigningError as exc:
                errors.append(str(exc))
    finally:
        shutil.rmtree(folder)
    if errors:
        raise SigningError("Temporary credential files were removed, but keychain cleanup reported an error.")


def prepare() -> None:
    certificate = os.environ.get("APPLE_SIGNING_CERTIFICATE_P12", "")
    password = os.environ.get("APPLE_SIGNING_PASSWORD", "")
    if not certificate and not password and not required():
        print("Apple signing is not configured: this manual build is ad-hoc signed and cannot publish a release.")
        return
    if not certificate or not password:
        raise SigningError("Both APPLE_SIGNING_CERTIFICATE_P12 and APPLE_SIGNING_PASSWORD are required for signed macOS releases.")
    team = team_id()
    try:
        decoded = base64.b64decode("".join(certificate.split()), validate=True)
        if not decoded:
            raise ValueError
    except (ValueError, binascii.Error):
        raise SigningError("APPLE_SIGNING_CERTIFICATE_P12 must contain a nonempty base64 PKCS#12 export.") from None
    folder = Path(tempfile.mkdtemp(prefix="cloudseed-signing-", dir=os.environ["RUNNER_TEMP"]))
    keychain = folder / "signing.keychain-db"
    certificate_path = folder / "certificate.p12"
    try:
        emit_env("CLOUDSEED_SIGNING_DIR", str(folder))
        with certificate_path.open("xb") as out:
            os.chmod(certificate_path, 0o600)
            out.write(decoded)
        search_list = shlex.split(run(["security", "list-keychains", "-d", "user"], "reading the keychain search list").stdout)
        (folder / "search-list.json").write_text(json.dumps(search_list))
        keychain_password = secrets.token_hex(32)
        run(["security", "create-keychain", "-p", keychain_password, str(keychain)], "creating the temporary keychain")
        run(["security", "set-keychain-settings", "-lut", "21600", str(keychain)], "setting the keychain lifetime")
        run(["security", "unlock-keychain", "-p", keychain_password, str(keychain)], "unlocking the temporary keychain")
        run(["security", "import", str(certificate_path), "-P", password, "-t", "cert", "-f", "pkcs12", "-k", str(keychain),
             "-T", "/usr/bin/codesign"], "importing the signing identity")
        certificate_path.unlink()
        run(["security", "set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", keychain_password, str(keychain)],
            "allowing noninteractive Apple code signing")
        identities = run(["security", "find-identity", "-v", "-p", "codesigning", str(keychain)], "validating the signing identity").stdout
        matches = re.findall(r'\b([A-Fa-f0-9]{40}) "Developer ID Application: [^"\r\n]+ \(' + re.escape(team) + r'\)"', identities)
        if len(matches) != 1:
            raise SigningError(f"The PKCS#12 must contain exactly one valid Developer ID Application identity for team {team}.")
        run(["security", "list-keychains", "-d", "user", "-s", str(keychain), *search_list], "selecting the signing keychain")
        emit_env("CLOUDSEED_CODESIGN_IDENTITY", matches[0].upper())
        print(f"Apple Developer ID signing is ready for team {team}.")
    except Exception:
        cleanup(folder)
        raise
    finally:
        certificate_path.unlink(missing_ok=True)


def verify(binary: Path) -> None:
    identity = os.environ.get("CLOUDSEED_CODESIGN_IDENTITY", "")
    if not identity:
        if required():
            raise SigningError("A tagged macOS release requires an imported Apple signing identity.")
        print("Manual build has no Apple Developer ID identity; publication remains disabled.")
        return
    team = team_id()
    run(["codesign", "--verify", "--strict", "--verbose=2", str(binary)], "verifying the finished binary signature")
    info = run(["codesign", "--display", "--verbose=4", str(binary)], "reading the finished binary identity")
    detail = info.stdout + "\n" + info.stderr
    if (f"TeamIdentifier={team}" not in detail.splitlines() or
            not any(line.startswith("Authority=Developer ID Application: ") for line in detail.splitlines()) or
            "Signature=adhoc" in detail):
        raise SigningError("The finished binary is not Developer ID signed by the expected Apple team.")
    if not re.search(r"^CodeDirectory .*flags=0x[0-9a-fA-F]+\([^)]*\bruntime\b", detail, re.M):
        raise SigningError("The finished binary's Developer ID signature does not enable hardened runtime.")
    if not any(line.startswith("Timestamp=") and line.partition("=")[2].strip().lower() not in ("", "none", "not set")
               for line in detail.splitlines()):
        raise SigningError("The finished binary's Developer ID signature has no secure timestamp.")
    print(f"Verified Developer ID signature for {binary.name}, team {team} (not a notarization check).")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify", "cleanup"))
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    try:
        if sys.platform != "darwin":
            raise SigningError("Apple release signing is only supported on macOS runners.")
        if args.action == "prepare":
            prepare()
        elif args.action == "cleanup":
            cleanup()
        else:
            if args.binary is None:
                raise SigningError("verify requires --binary.")
            verify(args.binary)
    except (SigningError, OSError, KeyError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
