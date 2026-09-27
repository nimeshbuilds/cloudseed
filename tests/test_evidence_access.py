"""Saved evidence is complete, paginated and confined; no cloud access in these tests."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import quote

from cloudseed import evidence, mcp, paths, secrets

ROOT = Path(__file__).resolve().parents[1]
STAMP = '20260927-030241'
REPORT = f'scans/cloud-{STAMP}.json'


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cs-evidence-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.env = paths.Env('aws', 'fixture', workdir=self.home / 'work')
        self.env.dir.mkdir()
        self.env.config_path.write_text('{"cloud":"aws","env":"fixture","vars":{}}')
        self.report = {
            'run': STAMP, 'generated_at': '2026-09-27T03:06:38Z', 'schema_version': 1, 'kind': 'cloud', 'verdict': 'FAIL',
            'summary': {'pass': 8, 'fail': 180, 'manual': 1, 'unknown': 0},
            'findings': [{'id': f'check-{n:03}', 'status': 'FAIL', 'severity': 'LOW', 'resource': f'fixture-resource-{n}',
                          'detail': 'Observed fixture finding. ' * 4, 'remediation': 'Review this control.',
                          'references': ['https://example.invalid/control']} for n in range(180)],
            # These deliberately follow the long findings list, beyond the first page.
            'scope': 'Accessible account resources; actual region coverage requires recorded evidence.',
            'coverage_limits': ['Resource/check observations, not unique benchmark requirements.', 'A summary alone does not establish every permission or region.'],
            'diagnostics': {'error_lines': 1, 'process_exit_code': 0},
            'raw': str(self.env.dir / f'scans/prowler-{STAMP}'),
        }
        self.put(REPORT, json.dumps(self.report, indent=2))

    def put(self, name, text):
        p = self.env.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def test_full_normalized_report_including_last_finding_and_real_metadata(self):
        chunks, offset, revision = [], 0, None
        while True:
            page = evidence.read_artifact(self.env, REPORT, offset=offset, limit=16000, revision=revision)
            self.assertLessEqual(evidence._wire_size(page), evidence.MAX_RESPONSE_BYTES)
            meta = page['report_metadata']
            self.assertEqual(meta['run'], STAMP)
            self.assertEqual(meta['generated_at'], '2026-09-27T03:06:38Z')
            self.assertEqual(meta['summary']['unknown'], 0)
            self.assertEqual(meta['diagnostics']['error_lines'], 1)
            self.assertEqual(meta['scope'], self.report['scope'])
            self.assertEqual(meta['coverage_limits'], self.report['coverage_limits'])
            self.assertEqual(meta['raw'], self.report['raw'])
            self.assertEqual(meta['findings_count'], 180)
            chunks.append(page['content'])
            if page['complete']:
                self.assertIsNone(page['next_offset'])
                break
            self.assertGreater(page['next_offset'], offset)
            offset, revision = page['next_offset'], page['revision']
        self.assertGreater(len(chunks), 1)
        restored = json.loads(''.join(chunks))
        self.assertEqual(restored, self.report)
        self.assertEqual(restored['findings'][-1]['id'], 'check-179')

    def test_whole_file_redaction_precedes_page_boundaries(self):
        key = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\nfixture-private-key-body\n-----END OPENSSH PRIVATE KEY-----'
        literal = 'registered-custom-value-that-must-never-leak'
        log = self.put(f'logs/{STAMP}-scan.log', 'prefix' * 9 + '\npassword=page-boundary-password\nAuthorization: Bearer abcdefghijklmnopqrstuv\n' + key + '\n' + literal)
        with mock.patch.object(secrets, '_literals', return_value=(literal,)):
            chunks, offset, revision = [], 0, None
            while True:
                page = evidence.read_artifact(self.env, str(log.relative_to(self.env.dir)), offset=offset, limit=13, revision=revision)
                chunks.append(page['content'])
                if page['complete']: break
                offset, revision = page['next_offset'], page['revision']
        text = ''.join(chunks)
        for forbidden in ('page-boundary-password', 'abcdefghijklmnopqrstuv', 'fixture-private-key-body', literal):
            self.assertNotIn(forbidden, text)
        self.assertIn('[REDACTED]', text)

    def test_discovery_covers_safe_areas_and_raw_evidence_without_sensitive_files(self):
        wanted = [REPORT, f'scans/cloud-{STAMP}.md', f'scans/prowler-{STAMP}/prowler.ocsf.json',
                  f'scans/raw/kubescape-{STAMP}.json', f'scans/openscap-{STAMP}/bastion/results.xml',
                  f'scans/host-cis-{STAMP}.json', f'scans/host-xccdf_org.ssgproject.content_profile_cis_level1_server-{STAMP}.md',
                  f'scans/openscap-{STAMP}/bastion/meta.json', f'scans/prowler-{STAMP}/prowler.log',
                  f'logs/{STAMP}-setup.log', 'logs/audit.jsonl', f'finops/report-{STAMP}-abcdef.json',
                  'finops/latest.json', f'chaos/report-{STAMP}.json', f'dr/drill-{STAMP}.md',
                  'operations/upgrade-plan-' + 'a' * 32 + '.json']
        for artifact in wanted: self.put(artifact, '{}')
        forbidden = ['config.json', 'logs/credentials.json', 'scans/secret.json', f'scans/prowler-{STAMP}/credentials.json',
                     f'scans/prowler-{STAMP}/prowler-credentials.json', f'scans/openscap-{STAMP}/inventory.ini',
                     f'scans/arbitrary/cloud-{STAMP}.json', 'operations/credentials-' + 'a' * 32 + '.json']
        for artifact in forbidden: self.put(artifact, 'private')
        collected, offset, revision = [], 0, None
        while True:
            page = evidence.list_artifacts(self.env, offset=offset, limit=2, revision=revision)
            collected.extend(row['artifact'] for row in page['artifacts'])
            if page['complete']: break
            offset, revision = page['next_offset'], page['revision']
        self.assertEqual(set(collected), set(wanted))
        for artifact in forbidden:
            with self.subTest(artifact=artifact), self.assertRaises(evidence.EvidenceError):
                evidence.read_artifact(self.env, artifact)

    def test_traversal_absolute_encoded_hidden_and_symlink_paths_are_refused(self):
        for value in (str(self.env.dir / REPORT), '../config.json', 'scans/../config.json', 'scans//cloud.json',
                      'scans/./cloud.json', 'scans/%2e%2e/config.json', 'scans\\..\\config.json', 'scans/.hidden.json'):
            with self.subTest(value=value), self.assertRaises(evidence.EvidenceError):
                evidence.read_artifact(self.env, value)
        outside = self.home / 'outside'
        outside.write_text('must-not-read')
        report = self.env.dir / REPORT
        report.unlink(); report.symlink_to(outside)
        with self.assertRaises(evidence.EvidenceError): evidence.read_artifact(self.env, REPORT)
        self.assertEqual(evidence.list_artifacts(self.env)['excluded_unsafe_entries'], 1)
        report.unlink(); report.parent.rmdir()
        external = self.home / 'external'; external.mkdir()
        (external / Path(REPORT).name).write_text('must-not-read')
        (self.env.dir / 'scans').symlink_to(external, target_is_directory=True)
        with self.assertRaises(evidence.EvidenceError): evidence.read_artifact(self.env, REPORT)
        with self.assertRaises(evidence.EvidenceError): evidence.list_artifacts(self.env)

    def test_hardlinks_pipes_oversize_and_invalid_utf8_are_refused(self):
        report = self.env.dir / REPORT
        linked = self.home / 'linked'; os.link(report, linked)
        with self.assertRaises(evidence.EvidenceError): evidence.read_artifact(self.env, REPORT)
        linked.unlink()
        with mock.patch.object(evidence, 'MAX_FILE_BYTES', 50), self.assertRaisesRegex(evidence.EvidenceError, '32 MiB'):
            evidence.read_artifact(self.env, REPORT)
        report.write_bytes(b'\xff')
        with self.assertRaisesRegex(evidence.EvidenceError, 'UTF-8'): evidence.read_artifact(self.env, REPORT)
        report.unlink(); os.mkfifo(report)
        with self.assertRaises(evidence.EvidenceError): evidence.read_artifact(self.env, REPORT)

    def test_changed_files_and_listings_require_restart(self):
        first = evidence.read_artifact(self.env, REPORT, limit=5)
        self.put(REPORT, '{"new":"content"}')
        with self.assertRaisesRegex(evidence.EvidenceError, 'changed'):
            evidence.read_artifact(self.env, REPORT, offset=first['next_offset'], revision=first['revision'])
        first = evidence.list_artifacts(self.env, limit=1)
        self.put(f'scans/cloud-{STAMP}.md', 'new report')
        with self.assertRaisesRegex(evidence.EvidenceError, 'listing changed'):
            evidence.list_artifacts(self.env, offset=1, revision=first['revision'])

    def test_bad_limits_explicit_size_budget_and_metadata_omissions(self):
        for args in ({'offset': -1}, {'limit': 0}, {'limit': 16001}, {'offset': True}, {'revision': 'bad'}):
            with self.subTest(args=args), self.assertRaises(evidence.EvidenceError): evidence.read_artifact(self.env, REPORT, **args)
        for args in ({'offset': -1}, {'limit': 101}, {'area': '../'}, {'revision': 'bad'}):
            with self.subTest(args=args), self.assertRaises(evidence.EvidenceError): evidence.list_artifacts(self.env, **args)
        self.put(REPORT, json.dumps({'scope': '\U0001f642' * 30000, 'findings': [{'id': 'last'}]}, ensure_ascii=False))
        first = evidence.read_artifact(self.env, REPORT)
        self.assertFalse(first['complete'])
        self.assertIn('scope', first['metadata_omitted_fields'])
        self.assertLessEqual(evidence._wire_size(first), evidence.MAX_RESPONSE_BYTES)
        self.assertGreater(first['next_offset'], 0)
        with mock.patch.object(evidence, 'MAX_ENTRIES', 0), self.assertRaisesRegex(evidence.EvidenceError, 'listing exceeds'):
            evidence.list_artifacts(self.env)

    def test_malformed_report_is_visible_but_not_treated_as_complete_assessment(self):
        self.put(REPORT, '{broken')
        page = evidence.read_artifact(self.env, REPORT)
        self.assertTrue(page['complete'])
        self.assertEqual(page['content'], '{broken')
        self.assertIn('malformed', page['metadata_error'])
        self.assertEqual(page['report_metadata'], {})
        self.assertIn('retrieval', page['note'])

    def test_nonfinite_report_metadata_keeps_raw_evidence_in_cli_and_mcp(self):
        from cloudseed import cli
        uri = 'cloudseed://evidence/aws/fixture/' + quote(REPORT, safe='')
        for number in ('NaN', 'Infinity', '-Infinity', '1e999'):
            with self.subTest(number=number):
                text = '{"summary":{"unknown":' + number + '}}'
                self.put(REPORT, text)
                page = evidence.read_artifact(self.env, REPORT)
                self.assertEqual(page['content'], text)
                self.assertEqual(page['report_metadata'], {})
                self.assertIn('malformed', page['metadata_error'])
                json.dumps(page, allow_nan=False)
                args = cli.build_parser().parse_args(['evidence', 'read', 'aws', '--env', 'fixture', '--artifact', REPORT, '--json'])
                output = io.StringIO()
                with mock.patch.object(cli, '_resolve_plain_env'), mock.patch.object(cli.paths, 'Env', return_value=self.env), \
                     mock.patch.object(cli, '_check_owner'), mock.patch.object(cli.audit, 'attach'), contextlib.redirect_stdout(output):
                    self.assertEqual(cli.cmd_evidence(args, {}), 0)
                self.assertEqual(json.loads(output.getvalue())['content'], text)
                with mock.patch.object(evidence, 'resolve_env', return_value=self.env):
                    result = json.loads(mcp.read_resource(uri)['contents'][0]['text'])
                self.assertEqual(result['content'], text)
                self.assertIn('malformed', result['metadata_error'])

    def test_real_cli_does_not_modify_listings_or_audit_log_between_pages(self):
        state = self.home / 'cli-state'
        work = state / 'envs/aws-fixture'
        logs = work / 'logs'
        logs.mkdir(parents=True)
        (work / 'config.json').write_text(json.dumps({'cloud': 'aws', 'env': 'fixture', 'name': 'fixture',
            'region': 'us-west-2', 'vars': {}, 'state': {'type': 'local'}}))
        for number in range(60):
            (logs / f'20260927-0300{number:02d}-scan.log').write_text(f'Saved scanner observation {number}\n')
        saved_audit = ''.join(json.dumps({'command': 'fixture', 'exit_code': 0,
                             'message': f'Saved observation {number}'}) + '\n' for number in range(250))
        (logs / 'audit.jsonl').write_text(saved_audit)
        before = {str(p.relative_to(work)): (p.read_bytes(), p.stat().st_mtime_ns) for p in work.rglob('*') if p.is_file()}
        child_env = {'HOME': str(self.home), 'CLOUDSEED_HOME': str(state), 'PATH': '/usr/bin:/bin', 'NO_COLOR': '1'}
        launcher = ([str(Path(os.environ['CLOUDSEED_TEST_BINARY']).resolve())] if os.environ.get('CLOUDSEED_TEST_BINARY') else
                    [sys.executable, str(ROOT / 'bin/cloudseed')])

        def cli(action, **fields):
            argv = [*launcher, 'evidence', action, 'aws', '--env', 'fixture', '--json']
            for key, value in fields.items():
                argv += ['--' + key, str(value)]
            result = subprocess.run(argv, env=child_env, cwd=self.home, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        first = cli('list')  # Default area=all and limit=50; includes the audit trail itself.
        self.assertEqual(first['total'], 61)
        self.assertEqual(first['returned'], 50)
        self.assertFalse(first['complete'])
        second = cli('list', offset=first['next_offset'], revision=first['revision'])
        self.assertTrue(second['complete'])
        self.assertEqual(second['revision'], first['revision'])
        self.assertEqual(len({row['artifact'] for row in first['artifacts'] + second['artifacts']}), 61)

        chunks, offset, revision = [], 0, None
        while True:
            fields = {'artifact': 'logs/audit.jsonl', 'offset': offset, 'limit': 1500}
            if revision:
                fields['revision'] = revision
            page = cli('read', **fields)
            chunks.append(page['content'])
            if page['complete']:
                break
            offset, revision = page['next_offset'], page['revision']
        self.assertGreater(len(chunks), 1)
        self.assertEqual(''.join(chunks), saved_audit)
        other = state / 'envs/aws-other'
        other.mkdir(parents=True)
        (other / 'config.json').write_text(json.dumps({'cloud': 'aws', 'env': 'other', 'vars': {}}))
        (state / 'settings.json').write_text(json.dumps({'current_env': 'aws-fixture'}))
        selected = subprocess.run([*launcher, 'evidence', 'list', 'aws', '--limit', '1', '--json'],
                                  env=child_env, cwd=self.home, capture_output=True, text=True, timeout=30)
        self.assertEqual(selected.returncode, 0, selected.stderr)
        self.assertEqual(json.loads(selected.stdout)['environment'], 'aws-fixture')
        after = {str(p.relative_to(work)): (p.read_bytes(), p.stat().st_mtime_ns) for p in work.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertTrue((state / 'logs/audit.jsonl').is_file(), 'Evidence reads still belong in the global audit trail')

    def test_resource_and_tool_discovery_and_validation(self):
        self.assertIn('cloudseed://evidence', [r['uri'] for r in mcp.resource_list()])
        self.assertTrue(any(t['name'] == 'evidence-read' for t in mcp.resource_templates()))
        tool = mcp.TOOLS['cloudseed_evidence']
        self.assertFalse(mcp._is_destructive(tool, {'action': 'read', 'artifact': REPORT}))
        self.assertTrue(mcp._json_stdout('cloudseed_evidence', tool['argv']({'action': 'read', 'artifact': REPORT})))
        with mock.patch.object(mcp, '_run', return_value={'ok': True}) as run:
            self.assertEqual(mcp.call_tool('cloudseed_evidence', {'action': 'read', 'cloud': 'aws', 'env': 'fixture', 'artifact': REPORT}, {}), {'ok': True})
            self.assertEqual(run.call_args.args[1][:3], ['evidence', 'read', 'aws'])
        for args in ({'action': 'read'}, {'action': 'list', 'limit': 101}, {'action': 'read', 'artifact': REPORT, 'command': 'cat /etc/passwd'}):
            with mock.patch.object(mcp, '_run') as run:
                self.assertTrue(mcp.call_tool('cloudseed_evidence', args, {})['isError'])
                run.assert_not_called()
        with self.assertRaises(mcp.InvalidParams): mcp.call_tool('cloudseed_command', {'command': 'cat /etc/passwd'}, {})

    def test_resource_content_is_paginated_and_bad_resource_paths_fail(self):
        uri = 'cloudseed://evidence/aws/fixture/' + quote(REPORT, safe='')
        with mock.patch.object(evidence, 'resolve_env', return_value=self.env):
            first = json.loads(mcp.read_resource(uri + '?limit=300')['contents'][0]['text'])
            next_uri = uri + '?offset=' + str(first['next_offset']) + '&limit=300&revision=' + first['revision']
            second = json.loads(mcp.read_resource(next_uri)['contents'][0]['text'])
            self.assertEqual(second['offset'], 300)
            self.assertEqual(first['report_metadata']['diagnostics']['error_lines'], 1)
            for bad in ('cloudseed://evidence/aws/fixture/%2e%2e%2fconfig.json', uri + '?offset=-1', uri + '?limit=1&limit=2', uri + '?password=secret'):
                with self.subTest(bad=bad), self.assertRaises((evidence.EvidenceError, mcp.InvalidParams)):
                    mcp.read_resource(bad)

    def test_mcp_spawn_returns_a_full_page_larger_than_plain_output_limit(self):
        # The evidence JSON envelope must use structured stdout, not the generic
        # 16k character preview which would silently drop the middle of a page.
        data = evidence.read_artifact(self.env, REPORT)
        self.assertGreater(len(json.dumps(data)), mcp.MAX_OUTPUT)
        child = self.home / 'emit.py'; child.write_text('import json\nprint(' + repr(json.dumps(data)) + ')\n')
        env = dict(os.environ, CLOUDSEED_HOME=str(self.home / 'mcp-home'), NO_COLOR='1')
        with mock.patch.object(mcp, '_launcher', return_value=[sys.executable, str(child)]):
            result = mcp._spawn('cloudseed_evidence', ['evidence', 'read', '--json'], env)
        self.assertFalse(result['isError'])
        self.assertIn('structuredContent', result)
        self.assertEqual(result['structuredContent'], data)
        self.assertNotIn('...[truncated]...', result['content'][0]['text'])


if __name__ == '__main__':
    unittest.main()
