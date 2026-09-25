#!/usr/bin/env python3
"""Preview by default. Real cloud acceptance requires explicit sandbox, cost and execution limits."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cloudseed import acceptance, ui  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cloud", choices=acceptance.CLOUDS)
    parser.add_argument("--identity")
    parser.add_argument("--region")
    parser.add_argument("--allow-ip")
    parser.add_argument("--max-budget-usd", type=float)
    parser.add_argument("--estimated-hourly-usd", type=float)
    parser.add_argument("--max-duration-minutes", type=int, default=120)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--allow-cloud-changes", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path.cwd() / "acceptance-results")
    args = parser.parse_args(argv)
    params = vars(args).copy()
    env = SimpleNamespace(dir=args.output_dir, id="acceptance-harness")
    try:
        report = acceptance.execute("acceptance", args.cloud, env, {}, params)
    except ui.Abort as error:
        print(str(error), file=sys.stderr)
        return error.code
    print(json.dumps(report, indent=2, allow_nan=False))
    return 1 if report["verdict"] == "FAIL" else 3 if report["verdict"] == "INCOMPLETE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
