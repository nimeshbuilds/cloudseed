#!/usr/bin/env python3
"""Write reproducible release inventory and checksums; authenticity comes from the workflow attestation."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cloudseed import __version__, paths  # noqa: E402
from cloudseed.releases import digest  # noqa: E402


def image_reference(value):
    """An explicit registry/repository and one canonical immutable SHA-256 digest."""
    invalid = "image reference must be a fully qualified registry/repository@sha256:<64 lowercase hex> with no tag or whitespace"
    if len(value) > 327 or any(c.isspace() for c in value):
        raise argparse.ArgumentTypeError(invalid)
    name, marker, digest_value = value.partition("@")
    registry, slash, repository = name.partition("/")
    component = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
    domain_label = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
    domain = rf"(?:{domain_label}(?:\.{domain_label})*|\[[a-fA-F0-9:]+\])"
    host = re.fullmatch(rf"(?P<host>{domain})(?::(?P<port>[0-9]+))?", registry)
    if not marker or not slash or len(name) > 255 or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest_value) or \
            not re.fullmatch(rf"{component}(?:/{component})*", repository) or host is None:
        raise argparse.ArgumentTypeError(invalid)
    hostname, port = host.group("host", "port")
    if hostname.startswith("["):
        try:
            ipaddress.IPv6Address(hostname[1:-1])
        except ValueError:
            raise argparse.ArgumentTypeError(invalid) from None
    elif "." not in hostname and hostname.lower() != "localhost" and port is None:
        # An unqualified first component is a namespace, not an explicit registry.
        raise argparse.ArgumentTypeError(invalid)
    if port is not None and not 1 <= int(port) <= 65535:
        raise argparse.ArgumentTypeError(invalid)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--terraform-version", default="1.16.4")
    parser.add_argument("--image-reference", type=image_reference,
                        help="Bind container inventories to an immutable registry/repository@sha256:digest")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("revision must be a full lowercase Git commit SHA")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.terraform_version):
        parser.error("Terraform version must be pinned as X.Y.Z")
    files = args.artifact
    names = [p.name for p in files] + [args.output.name, args.checksums.name]
    if len(names) != len(set(names)) or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", n) for n in names):
        parser.error("artifact and metadata names must be unique portable basenames")
    records = []
    for artifact in files:
        sha, size = digest(artifact)
        records.append({"file": artifact.name, "sha256": sha, "bytes": size})
    manifest = {"schema_version": 1, "product": "cloudseed", "version": __version__, "source_revision": args.revision,
                "artifacts": records, "compatibility": {"source_python": ">=3.9", "bundled_python": "3.14",
                "terraform": args.terraform_version, "operating_systems": ["linux"] if args.image_reference else ["linux", "darwin"],
                "architectures": ["amd64", "arm64"]},
                "verification": {"repository": "nimeshbuilds/cloudseed", "workflow": ".github/workflows/release.yml",
                "note": "SHA256SUMS detects byte changes; signed GitHub provenance establishes the build identity."}}
    if args.image_reference:
        manifest["image_reference"] = args.image_reference
    paths.atomic_write(args.output, json.dumps(manifest, sort_keys=True, indent=2) + "\n", mode=0o644)
    checks = [(x["sha256"], x["file"]) for x in records] + [(digest(args.output)[0], args.output.name)]
    paths.atomic_write(args.checksums, "".join(f"{sha}  {name}\n" for sha, name in sorted(checks, key=lambda row: row[1])), mode=0o644)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
