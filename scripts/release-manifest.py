#!/usr/bin/env python3
"""Write reproducible release inventory and checksums; authenticity comes from the workflow attestation."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cloudseed import __version__, paths  # noqa: E402
from cloudseed.releases import digest  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--terraform-version", default="1.16.4")
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
                "terraform": args.terraform_version, "operating_systems": ["linux", "darwin"], "architectures": ["amd64", "arm64"]},
                "verification": {"repository": "nimeshbuilds/cloudseed", "workflow": ".github/workflows/release.yml",
                "note": "SHA256SUMS detects byte changes; signed GitHub provenance establishes the build identity."}}
    paths.atomic_write(args.output, json.dumps(manifest, sort_keys=True, indent=2) + "\n", mode=0o644)
    checks = [(x["sha256"], x["file"]) for x in records] + [(digest(args.output)[0], args.output.name)]
    paths.atomic_write(args.checksums, "".join(f"{sha}  {name}\n" for sha, name in sorted(checks, key=lambda row: row[1])), mode=0o644)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
