#!/usr/bin/env python3
"""Scenario 14 fixture: review synthetic saved evidence through real CLI/MCP.

The caller's scenario harness has already selected a private HOME/CLOUDSEED_HOME
and started its own loopback MCP server. No cloud operation is performed here.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request


def main():
    home = Path(os.environ["CLOUDSEED_HOME"])
    assert "cs-scenario-14-" in str(home), "Use the isolated scenario 14 harness"
    envdir = home / "envs" / "aws-evidence"
    report_dir = envdir / "scans"
    report_dir.mkdir(parents=True, exist_ok=True)
    (envdir / "config.json").write_text(json.dumps({
        "cloud": "aws", "env": "evidence", "name": "scenario-evidence", "region": "us-west-2",
        "state": {"type": "local"}, "vars": {"enable_kubernetes": False},
    }))
    artifact = "scans/cloud-20000101-000000.json"
    observed = "2000-01-02T03:04:05Z"
    marker = "SCENARIO_DIAGNOSTIC: a synthetic service was not assessed"
    fake_secret = "scenario-evidence-test-secret"
    findings = [{
        "id": f"fixture-{number:02d}", "status": "FAIL" if number % 2 else "MANUAL",
        "detail": "Synthetic finding, not a live cloud observation. " * 17,
        "remediation": "Review the fixture evidence; do not change infrastructure.",
    } for number in range(40)]
    findings.append({"id": "last-finding-visible", "status": "PASS", "detail": "End of saved findings"})
    fixture = {
        "kind": "cloud", "tool": "synthetic scenario fixture", "verdict": "FAIL", "generated_at": observed,
        "scope": "Synthetic saved account evidence; no live cloud scan was run",
        "summary": {"pass": 1, "fail": 20, "manual": 20, "unknown": 0},
        "coverage_limits": ["Only synthetic observations are represented; this is not complete cloud coverage"],
        "diagnostics": {"error_lines": 1, "error_examples": [{"text": marker, "omitted_characters": 0}]},
        "findings": findings, "note": "password=" + fake_secret,
    }
    report_path = envdir / artifact
    report_path.write_text(json.dumps(fixture, indent=2) + "\n")

    def cli(action, **fields):
        argv = ["cs", "evidence", action, "aws", "--env", "evidence", "--json"]
        for key, value in fields.items():
            argv += ["--" + key.replace("_", "-"), str(value)]
        return subprocess.run(argv, capture_output=True, text=True, timeout=90)

    token = (home / "mcp" / "token").read_text().strip()
    url = "http://127.0.0.1:" + str(int(sys.argv[1])) + "/mcp"

    def mcp(action, **fields):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "cloudseed_evidence", "arguments": {"action": action, "cloud": "aws", "env": "evidence", **fields},
        }}
        request = urllib.request.Request(url, json.dumps(body).encode(), headers={
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer " + token,
        })
        with urllib.request.urlopen(request, timeout=90) as response:
            raw = response.read().decode("utf-8")
            if "text/event-stream" in response.headers.get("Content-Type", ""):
                messages = [json.loads(line[5:].strip()) for line in raw.splitlines() if line.startswith("data:")]
                replies = [message for message in messages if message.get("id") == 1]
                assert len(replies) == 1, "MCP stream did not contain one result"
                value = replies[0]
            else:
                value = json.loads(raw)
        assert "error" not in value, "MCP protocol error"
        return value["result"]

    def cli_page(**fields):
        result = cli("read", **fields)
        assert result.returncode == 0, "CLI evidence read failed"
        return json.loads(result.stdout)

    def mcp_page(**fields):
        result = mcp("read", **fields)
        assert not result.get("isError"), "MCP evidence read failed"
        return result["structuredContent"]

    listed = cli("list", area="scans")
    assert listed.returncode == 0
    assert artifact in [entry["artifact"] for entry in json.loads(listed.stdout)["artifacts"]]
    listed = mcp("list", area="scans")
    assert not listed.get("isError")
    assert artifact in [entry["artifact"] for entry in listed["structuredContent"]["artifacts"]]

    def read_every_page(read):
        offset, revision, chunks, pages = 0, None, [], 0
        while True:
            args = {"artifact": artifact, "offset": offset, "limit": 16000}
            if revision:
                args["revision"] = revision
            page = read(**args)
            assert page["offset"] == offset
            assert page["redacted"] is True
            assert re.fullmatch(r"[a-f0-9]{64}", page["revision"])
            assert revision in (None, page["revision"])
            revision = page["revision"]
            assert page["report_metadata"]["generated_at"] == observed
            assert page["run_from_filename"] == "20000101-000000"
            assert page["modified_at"] != observed
            assert page["report_metadata"]["summary"]["unknown"] == 0
            assert page["report_metadata"]["coverage_limits"]
            assert page["report_metadata"]["diagnostics"]["error_lines"] == 1
            assert marker == page["report_metadata"]["diagnostics"]["error_examples"][0]["text"]
            assert page["report_metadata"]["findings_count"] == 41
            chunks.append(page["content"])
            pages += 1
            if page["complete"]:
                assert page["next_offset"] is None
                break
            assert isinstance(page["next_offset"], int) and page["next_offset"] > offset
            offset = page["next_offset"]
            assert pages < 10, "Pagination did not reach the end"
        text = "".join(chunks)
        assert pages > 1, "The fixture must exercise pagination"
        assert fake_secret not in text and "[REDACTED]" in text
        parsed = json.loads(text)
        assert parsed["findings"] == findings
        return revision

    old_revision = read_every_page(cli_page)
    assert read_every_page(mcp_page) == old_revision
    print("CLI and MCP retrieved every redacted finding")

    rejected = cli("read", artifact="../config.json")
    assert rejected.returncode == 2
    assert mcp("read", artifact="../config.json").get("isError")
    # A reader must restart when the saved artifact changes between pages.
    report_path.write_text(report_path.read_text() + "\n")
    assert cli("read", artifact=artifact, offset=1, revision=old_revision).returncode == 2
    assert mcp("read", artifact=artifact, offset=1, revision=old_revision).get("isError")
    print("Historical timestamps, coverage limits, stale revisions and unsafe paths checked")


if __name__ == "__main__":
    main()
