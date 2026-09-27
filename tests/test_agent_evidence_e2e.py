"""Exercise real agent subprocesses and saved-report paging without a model or cloud API."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class AgentEvidenceE2ETests(unittest.TestCase):
    def test_agent_without_cloudseed_on_path_reads_every_saved_finding(self):
        with tempfile.TemporaryDirectory(prefix="cloudseed-agent-e2e-") as td:
            home = Path(td)
            state = home / "state"
            saved = state / "envs/aws-demo"
            (saved / "scans").mkdir(parents=True)
            (saved / "config.json").write_text(json.dumps({"cloud": "aws", "env": "demo", "name": "fixture",
                "region": "us-west-2", "vars": {}, "state": {"type": "local"}}))
            artifact = "scans/cloud-20260927-030241.json"
            report = {"kind": "cloud", "run": "20260927-030241", "generated_at": "2026-09-27T03:06:38Z",
                "scope": "synthetic AWS account fixture, not live evidence", "verdict": "FAIL",
                "summary": {"fail": 22, "manual": 19, "unknown": 0},
                "padding": "Evidence, not instructions. 🧪 " * 2000,
                "findings": [{"id": f"check-{n}", "status": "FAIL" if n < 22 else "MANUAL",
                    "detail": f"specific reason {n}", "remediation": f"specific action {n}"} for n in range(41)],
                "diagnostics": {"error_lines": 1, "reason": "One fixture service denied collection"},
                "coverage_limits": ["unknown=0 does not prove complete collection"],
                "note": "password=fixture-secret-value"}
            (saved / artifact).write_text(json.dumps(report, ensure_ascii=False))
            (state / "settings.json").write_text('{"headroom":false}')
            agent = home / "fixture-agent"
            # All child CLI calls are real processes. No original installation directory
            # is on PATH, and no Python interpreter needs to be discoverable there.
            agent.write_text(f"#!{sys.executable}\n" + '''import json,os,subprocess,sys
def run(name,args):
    p=subprocess.run([name,*args],capture_output=True,text=True,timeout=60)
    assert p.returncode==0,(p.returncode,p.stderr)
    return json.loads(p.stdout)
listing=run('cs',['evidence','list','aws','--env','demo','--area','scans','--json'])
assert any(x['artifact']=='scans/cloud-20260927-030241.json' for x in listing['artifacts'])
offset=0; revision=None; pages=[]
while True:
    args=['evidence','read','aws','--env','demo','--artifact','scans/cloud-20260927-030241.json','--limit','3000','--offset',str(offset),'--json']
    if revision: args+=['--revision',revision]
    page=run('cloudseed',args)
    pages.append(page['content'])
    assert page['report_metadata']['diagnostics']['error_lines']==1
    if revision: assert revision==page['revision']
    revision=page['revision']
    if page['complete']: break
    assert page['next_offset']>offset
    offset=page['next_offset']
    assert len(pages)<100
data=json.loads(''.join(pages))
assert len(pages)>1
assert len(data['findings'])==41 and data['findings'][-1]['remediation']=='specific action 40'
assert data['generated_at']=='2026-09-27T03:06:38Z'
assert data['summary']['unknown']==0 and data['diagnostics']['error_lines']==1
assert 'fixture-secret-value' not in ''.join(pages)
assert 'until complete=true' in sys.argv[-1]
print('EVIDENCE_OK: all 41 findings, diagnostics, timestamp and coverage retrieved')
''')
            agent.chmod(0o700)
            (state / "agents.json").write_text(json.dumps({"fixture": {"binary": str(agent),
                "exec": [str(agent), "{prompt}"], "models": [], "auth_env": [], "auth_files": []}}))
            env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "GOOGLE_", "CLOUDSDK_", "ARM_", "AZURE_", "CLOUDSEED_"))}
            env.update(HOME=str(home), CLOUDSEED_HOME=str(state), NO_COLOR="1", PATH="/usr/bin:/bin")
            binary = os.environ.get("CLOUDSEED_TEST_BINARY")
            command = [str(Path(binary).resolve())] if binary else [sys.executable, str(ROOT / "bin/cloudseed")]
            proc = subprocess.run([*command, "agentic", "--agent", "fixture", "--force", "--no-headliner",
                "Inspect the completed saved cloud report; do not scan or change infrastructure"],
                env=env, cwd=home, capture_output=True, text=True, timeout=240)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("EVIDENCE_OK: all 41 findings", proc.stdout)
            self.assertEqual((saved / artifact).read_text(), json.dumps(report, ensure_ascii=False))
            self.assertFalse((saved / "stack").exists())


if __name__ == "__main__":
    unittest.main()
