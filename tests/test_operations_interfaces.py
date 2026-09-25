"""Shared operation behavior at the actual CLI, MCP, console and agent boundaries."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('CLOUDSEED_HOME', tempfile.mkdtemp(prefix='cs-operation-interfaces-'))
from cloudseed import builtin_agent, cli, clouds, mcp, operations, paths, tf, ui, webui

ROOT = Path(__file__).resolve().parent.parent
COMMAND = [os.environ['CLOUDSEED_TEST_BINARY']] if os.environ.get('CLOUDSEED_TEST_BINARY') else [sys.executable, str(ROOT / 'bin/cloudseed')]


class OperationContractTests(unittest.TestCase):
    def test_every_operation_has_matching_cli_mcp_ui_and_agent_behavior(self):
        catalog = {a['name']: a for a in webui.actions_catalog()}
        for name, op in operations.OPERATIONS.items():
            with self.subTest(name=name):
                tool = 'cloudseed_ops_' + name.replace('-', '_')
                args = {'cloud': 'aws', 'env': 'review'}
                if op.effect == 'change':
                    args['confirm'] = True
                words = webui.build_argv(tool, args)
                parsed = cli.build_parser().parse_args(words)
                self.assertEqual(parsed.ops_cmd, name)
                self.assertEqual(parsed.cloud, 'aws')
                params = operations.parameters(parsed)
                self.assertEqual(params.get('approve', False), op.effect == 'change')
                self.assertEqual(bool(builtin_agent._approval_reason(parsed)), op.effect == 'change')
                self.assertEqual(catalog[tool]['schema']['properties']['json']['default'], True)
                self.assertIn('--json', words)
                with mock.patch.object(mcp, '_run', return_value={'ok': True}) as run:
                    self.assertEqual(mcp.call_tool(tool, args, {}), {'ok': True})
                    self.assertEqual(run.call_args.args[1], words)

    def test_mutations_need_confirmation_and_previews_do_not(self):
        for action, params in [('network', {'live': True, 'active': True}), ('acceptance', {'live': True}),
                               ('profile', {'profile': 'production', 'confirm': True}), ('upgrade-apply', {}),
                               ('recovery-test', {}), ('expiry-cleanup', {}), ('spec-export', {'output': '/tmp/spec.yaml'})]:
            name = 'cloudseed_ops_' + action.replace('-', '_')
            if action == 'profile':
                self.assertTrue(mcp._is_destructive(mcp.TOOLS[name], params))
                continue
            with self.subTest(action=action):
                with self.assertRaises(webui.NeedsConfirm):
                    webui.build_argv(name, params)
                self.assertTrue(mcp.call_tool(name, params, {})['isError'])
        for action in ['profile', 'acceptance', 'network', 'spec-export', 'health']:
            self.assertFalse(mcp.needs_confirm(mcp.TOOLS['cloudseed_ops_' + action.replace('-', '_')], {}))
        self.assertEqual(webui.raw_argv({'argv': ['ops', 'health', 'aws', '--env', 'review']})[0], '-y')
        with self.assertRaises(webui.NeedsConfirm):
            webui.raw_argv({'argv': ['ops', 'profile', 'aws', '--env', 'review', '--approve']})

    def test_input_types_finiteness_ranges_and_unknown_fields_fail_closed(self):
        for params in [{'timeout': 0}, {'timeout': True}, {'timeout': 301}, {'live': 'false'}, {'unknown': 1}]:
            with self.subTest(params=params), self.assertRaises(ValueError):
                operations.validate('health', params)
        for number in [float('inf'), float('nan'), 10 ** 1000, -1, True]:
            with self.assertRaises(ValueError):
                operations.validate('acceptance', {'max_budget_usd': number})
        with self.assertRaises(ValueError):
            operations.validate('spec-import', {'spec': {'value': 'x' * (1024 * 1024)}})
        for status, code in [('PASS', 0), ('PLAN', 0), ('BLOCKED', 1), ('FAIL', 1), ('UNKNOWN', 3), ('INCOMPLETE', 3), (None, 3), ('unexpected', 3)]:
            self.assertEqual(operations.exit_code({'verdict': status}), code)

    def test_stale_config_rejected_inside_environment_lock(self):
        env = mock.MagicMock()
        env.exists.return_value = True
        env.load.return_value = {'changed': True}
        with mock.patch('cloudseed.blueprints.execute') as domain:
            with self.assertRaisesRegex(ValueError, 'changed while waiting'):
                operations.execute('profile', clouds.get('aws'), env, {}, {'approve': True})
            domain.assert_not_called()
        env.lock.assert_called_once()


class OperationCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cs-operations-cli-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.directory = self.home / 'cs/envs/aws-review'
        self.directory.mkdir(parents=True)
        self.cfg = {'cloud': 'aws', 'env': 'review', 'name': 'review', 'region': 'us-west-2',
                    'network_cidr': '10.42.0.0/16', 'allowed_ssh_cidrs': ['203.0.113.4/32'],
                    'vars': {'enable_kubernetes': False}, 'extra_vars': {}}
        (self.directory / 'config.json').write_text(json.dumps(self.cfg))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('CLOUDSEED_', 'XDG_', 'AWS_', 'ARM_', 'AZURE_', 'GOOGLE_', 'GCLOUD_', 'CLOUDSDK_'))}
        (self.home / 'bin').mkdir()
        self.env.update(HOME=str(self.home), CLOUDSEED_HOME=str(self.home / 'cs'), PATH=str(self.home / 'bin'),
                        CLOUDSEED_NONINTERACTIVE='1', CLOUDSEED_MCP_FORCE='1', NO_COLOR='1')

    def run_cli(self, *words, input=None):
        result = subprocess.run(COMMAND + list(words), input=input, env=self.env, cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        self.assertNotIn('Unexpected error', result.stderr, result.stdout + result.stderr)
        return result

    def test_export_validate_preview_save_health_reports_without_external_tools(self):
        target = self.home / 'cloudseed.yaml'
        result = self.run_cli('ops', 'spec-export', 'aws', '--env', 'review', '--output', str(target), '--approve', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        spec = json.loads(target.read_text())
        self.assertEqual(spec, json.loads(result.stdout)['spec'])
        valid = self.run_cli('ops', 'spec-validate', '--input', str(target), '--json')
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
        before = (self.directory / 'config.json').read_text()
        preview = self.run_cli('ops', 'profile', 'aws', '--env', 'review', '--profile', 'production', '--json')
        self.assertEqual(preview.returncode, 0, preview.stdout + preview.stderr)
        self.assertFalse(json.loads(preview.stdout)['saved'])
        self.assertEqual(before, (self.directory / 'config.json').read_text())
        saved = self.run_cli('ops', 'profile', 'aws', '--env', 'review', '--profile', 'lab', '--approve', '--json')
        self.assertEqual(saved.returncode, 0, saved.stdout + saved.stderr)
        self.assertTrue(json.loads(saved.stdout)['saved'])
        self.assertEqual(json.loads((self.directory / 'config.json').read_text())['operations']['profile'], 'lab')
        for kind in ['health', 'network']:
            report = self.run_cli('ops', kind, 'aws', '--env', 'review', '--json')
            self.assertEqual(report.returncode, 3, report.stdout + report.stderr)
            data = json.loads(report.stdout)
            self.assertEqual(data['verdict'], 'INCOMPLETE')
            self.assertTrue(Path(data['report']).exists())
            self.assertTrue(list((self.directory / 'scans').glob(kind + '-*.md')))
        self.assertFalse(list((self.directory / 'stack').glob('*.tf')))
        self.assertFalse((self.directory / 'stack/terraform.tfstate').exists())

    def test_export_file_requires_approval_across_interfaces(self):
        target = self.home / 'cloudseed.yaml'
        target.write_text('original: keep me\n')
        result = self.run_cli('ops', 'spec-export', 'aws', '--env', 'review', '--output', str(target), '--json')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('explicit --approve', result.stderr)
        self.assertEqual(target.read_text(), 'original: keep me\n')
        self.assertEqual(list(self.home.glob('*.bak')), [])
        args = cli.build_parser().parse_args(['ops', 'spec-export', 'aws', '--output', str(target)])
        self.assertTrue(builtin_agent._approval_reason(args))
        with self.assertRaises(webui.NeedsConfirm):
            webui.raw_argv({'argv': ['ops', 'spec-export', 'aws', '--output', str(target)]})

    def test_export_preserves_previous_copy(self):
        target = self.home / 'cloudseed.yaml'
        target.write_text('original: keep me\n')
        result = self.run_cli('ops', 'spec-export', 'aws', '--env', 'review', '--output', str(target), '--approve', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(Path(json.loads(result.stdout)['previous_output']).read_text(), 'original: keep me\n')

    def test_actual_mcp_subprocess_returns_health_incomplete_as_structured_report(self):
        requests = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'operations-test', 'version': '1'}}},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'cloudseed_ops_health', 'arguments': {'cloud': 'aws', 'env': 'review'}}},
        ]
        result = self.run_cli('mcp', 'serve', input=''.join(json.dumps(r) + '\n' for r in requests))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        response = next(json.loads(s) for s in result.stdout.splitlines() if json.loads(s).get('id') == 2)
        self.assertEqual(response['result']['structuredContent']['verdict'], 'INCOMPLETE')
        self.assertTrue(response['result']['isError'])  # evidence is incomplete, while structured report remains available

    def test_global_previews_require_no_environment_or_credentials(self):
        result = self.run_cli('ops', 'acceptance', 'aws', '--json')
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertFalse(json.loads(result.stdout).get('live', False))
        result = self.run_cli('ops', 'credentials-backend', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['backend'], 'file')


class TerraformGuardrailHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.envdir = Path(self.temp.name)
        self.stack = self.envdir / 'stack'
        self.stack.mkdir()
        self.cfg = {'cloud': 'aws', 'env': 'review', 'operations': {'block_destroy': True}}
        (self.envdir / 'config.json').write_text(json.dumps(self.cfg))
        with mock.patch.object(tf.deps, 'find', return_value='/terraform'):
            self.tf = tf.Terraform(self.stack)

    def test_blocked_exact_plan_never_reaches_apply(self):
        plan = {'format_version': '1.2', 'resource_changes': [{'address': 'aws_instance.review', 'change': {'actions': ['delete']}}]}
        with mock.patch.object(self.tf, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(plan))) as run:
            with self.assertRaises(ui.Abort):
                self.tf.apply('reviewed.tfplan')
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args, ('show', '-json', 'reviewed.tfplan'))

    def test_no_saved_plan_fails_before_running_terraform(self):
        with mock.patch.object(self.tf, 'run') as run:
            with self.assertRaises(ui.Abort):
                self.tf.apply(auto_approve=True)
            run.assert_not_called()

    def test_existing_environment_without_policy_keeps_apply_behavior(self):
        (self.envdir / 'config.json').write_text('{"cloud":"aws","env":"review"}')
        with mock.patch.object(self.tf, 'run') as run:
            self.tf.apply('reviewed.tfplan')
            run.assert_called_once_with('apply', '-input=false', 'reviewed.tfplan')


if __name__ == '__main__':
    unittest.main()
