#!/usr/bin/env python3
"""Generate SPDX JSON using a checksum-pinned Syft release, without running a downloaded installer."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

VERSION = "1.52.0"
# Official release checksums, reviewed from:
# https://github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_checksums.txt
# Update the version and all four digests together after reviewing the upstream release.
SHA256 = {
    ("darwin", "amd64"): "56975f5d7ffa9846a1eaf64330647841b878097bc7e3730cb9325f93add96917",
    ("darwin", "arm64"): "014d561b6d13059124155f74a6c5a9a99501f5e209313638dd884f39eb418ee6",
    ("linux", "amd64"): "caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d",
    ("linux", "arm64"): "c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706",
}
MAX_SBOM_BYTES = 128 * 1024 * 1024  # Full inventories are attested by file digest, not embedded predicates.


def install_syft(folder):
    system = platform.system().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    expected = SHA256.get((system, arch))
    if expected is None:
        raise ValueError("Syft release supports only Linux/macOS amd64/arm64 hosts.")
    archive = Path(folder) / "syft.tar.gz"
    url = f"https://github.com/anchore/syft/releases/download/v{VERSION}/syft_{VERSION}_{system}_{arch}.tar.gz"
    subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error", "--proto", "=https",
                    "--proto-redir", "=https", "--retry", "2", "--connect-timeout", "20", "--max-time", "180",
                    "--max-filesize", str(128 * 1024 * 1024), url, "--output", str(archive)], check=True, timeout=600)
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError("Syft archive checksum mismatch; refusing to extract or execute it.")
    binary = Path(folder) / "syft"
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember("syft")
        if not member.isfile() or not 0 < member.size <= 512 * 1024 * 1024:
            raise ValueError("Syft archive does not contain a regular executable.")
        with bundle.extractfile(member) as source, binary.open("wb") as destination:
            shutil.copyfileobj(source, destination)
    binary.chmod(0o755)
    return binary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--directory", type=Path)
    source.add_argument("--image", help="Image in the local Docker daemon; remote registry fallback is disabled")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.directory is not None and not args.directory.is_dir():
        parser.error("directory must exist")
    if args.image is not None and (not args.image or any(c.isspace() for c in args.image)):
        parser.error("image must be a nonempty local Docker image reference")
    target = "dir:" + str(args.directory.resolve()) if args.directory is not None else "docker:" + args.image
    with tempfile.TemporaryDirectory(prefix="cloudseed-sbom-") as folder:
        binary = install_syft(folder)
        report = Path(folder) / "sbom.spdx.json"
        subprocess.run([str(binary), "scan", target, "--output", "spdx-json=" + str(report)],
                       env=dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false"), check=True, timeout=600)
        size = report.stat().st_size
        if not 0 < size <= MAX_SBOM_BYTES:
            raise ValueError(f"SBOM is {size} bytes; expected 1 through {MAX_SBOM_BYTES} bytes (128 MiB maximum). Review the scan scope; do not truncate its inventory.")
        contents = report.read_bytes()
        document = json.loads(contents)
        if not isinstance(document, dict) or not str(document.get("spdxVersion", "")).startswith("SPDX-2."):
            raise ValueError("Syft did not produce an SPDX 2 JSON document.")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(contents)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
