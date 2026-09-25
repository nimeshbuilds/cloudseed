"""Verify downloaded release bytes and, optionally, the repository's signed release-workflow provenance."""
from __future__ import annotations

import hashlib
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from . import deps, health, ui

REPOSITORY = "nimeshbuilds/cloudseed"
WORKFLOW = REPOSITORY + "/.github/workflows/release.yml"
CERT_IDENTITY = r"^https://github\.com/nimeshbuilds/cloudseed/\.github/workflows/release\.yml@refs/tags/v[0-9][0-9A-Za-z.+-]*$"


def digest(path):
    """Stream a regular file without following a leaf symlink; refuse concurrently modified bytes."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if Path(path).is_symlink():
        raise ValueError("Artifact must be a regular file, not a symlink.")
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > 8 * 1024 ** 3:
                raise ValueError("Artifact must be a regular file no larger than 8 GiB.")
            sha = hashlib.sha256()
            read = 0
            for data in iter(lambda: stream.read(1024 * 1024), b""):
                read += len(data)
                if read > before.st_size:
                    raise ValueError("Artifact grew during verification.")
                sha.update(data)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError("Artifact changed during verification.")
            return sha.hexdigest(), before.st_size
    except OSError as error:
        raise ValueError("Artifact is unavailable or cannot be read safely.") from error


def execute(action, cloud, env, cfg, params=None):
    params = {} if params is None else params
    if action != "release-verify" or not isinstance(params, dict):
        raise ui.Abort("Release verification requires an options object.", code=2)
    artifact, expected = params.get("artifact"), params.get("sha256")
    attestation = params.get("verify_attestation", False)
    if not isinstance(artifact, str) or not artifact or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected) or type(attestation) is not bool:
        raise ui.Abort("Supply artifact, a trusted expected 64-character sha256, and an optional boolean verify_attestation.", code=2)
    path = Path(artifact).expanduser().absolute()
    try:
        actual, size = digest(path)
    except ValueError as error:
        raise ui.Abort(str(error), code=2) from None
    same = actual == expected.lower()
    findings = [health._finding("release.integrity", "PASS" if same else "FAIL", "Expected SHA-256",
                               "Artifact bytes match the supplied expected digest." if same else "Artifact bytes do not match the supplied expected digest.",
                               "Obtain the expected digest from a trusted signed release; do not execute mismatched files.", sha256=actual, bytes=size)]
    verified = False
    if attestation and same:
        gh = deps.find("gh")
        if gh:
            try:
                proc = health._run([gh, "attestation", "verify", str(path), "--repo", REPOSITORY,
                                    "--signer-workflow", WORKFLOW, "--cert-identity-regex", CERT_IDENTITY,
                                    "--deny-self-hosted-runners", "--format", "json"], env=deps.path_env(), timeout=60)
                verified = proc.returncode == 0 and digest(path)[0] == actual
                status = "PASS" if verified else "FAIL"
            except (OSError, ValueError):
                status = "UNKNOWN"
        else:
            status = "UNKNOWN"
    else:
        status = "UNKNOWN"
    findings.append(health._finding("release.provenance", status, "Signed release provenance",
                                   "GitHub verified this digest against the Cloudseed release workflow on a version tag." if verified else
                                   "Release provenance has not been verified." if status == "UNKNOWN" else "Release provenance verification failed.",
                                   "Use a current authenticated gh CLI and verify_attestation=true; review the signed build identity before running the artifact.",
                                   live=verified, repository=REPOSITORY, workflow=WORKFLOW))
    verdict = "FAIL" if any(f["status"] == "FAIL" for f in findings) else "PASS" if verified else "INCOMPLETE"
    return {"schema_version": 1, "kind": action, "verdict": verdict, "artifact": path.name, "sha256": actual,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "findings": findings,
            "summary": {"integrity": same, "provenance_verified": verified}, "coverage_limits": [
                "A checksum generated from the downloaded file itself does not authenticate its publisher.",
                "Provenance authenticates the repository/workflow build identity and bytes, not absence of vulnerabilities.",
                "Verification never executes, extracts, installs or replaces the artifact."]}
