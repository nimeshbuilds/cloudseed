"""Bounded framing and resources still answer valid requests after rejecting oversized input."""
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault('CLOUDSEED_HOME', tempfile.mkdtemp(prefix='cs-mcp-resource-tests-'))
from cloudseed import mcp, paths


class ResourceBounds(unittest.TestCase):
    def test_bounded_file_reader_rejects_big_files_symlinks_and_pipes(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'data'
            f.write_text('x' * 65)
            with mock.patch.object(mcp, 'MAX_RESOURCE_FILE', 64), self.assertRaises(ValueError):
                mcp._resource_text(f)
            link = Path(d) / 'linked'
            link.symlink_to(f)
            with self.assertRaises((ValueError, OSError)):
                mcp._resource_text(link)
            if hasattr(os, 'mkfifo'):
                fifo = Path(d) / 'pipe'
                os.mkfifo(fifo)
                with self.assertRaises(ValueError):
                    mcp._resource_text(fifo)

    def test_resources_preserve_per_environment_errors_and_bound_aggregate(self):
        with tempfile.TemporaryDirectory() as d:
            e = paths.Env('aws', 'review', workdir=Path(d))
            e.config_path.write_text(json.dumps({'region': 'us-east-1'}))
            (e.dir / 'outputs.json').write_text(json.dumps({'data': 'x' * 300}))
            with mock.patch.object(paths.Env, 'list_all', return_value=[e]), mock.patch.object(mcp, 'MAX_RESOURCE_FILE', 64):
                result = mcp._environments()
                self.assertEqual(result[0]['config']['region'], 'us-east-1')
                self.assertEqual(result[0]['outputs'], {})
                self.assertIn('size limit', result[0]['outputs_note'])
            with mock.patch.object(paths.Env, 'list_all', return_value=[e]), mock.patch.object(mcp, 'MAX_RESOURCE', 64):
                with self.assertRaisesRegex(ValueError, 'targeted inventory'):
                    mcp._environments()

    def test_batch_limit_rejects_before_dispatching(self):
        with mock.patch.object(mcp, 'handle') as handle:
            result = mcp.dispatch([{'id': i, 'method': 'ping'} for i in range(mcp.MAX_BATCH + 1)], mcp.Session({}))
            self.assertEqual(result['error']['code'], -32600)
            handle.assert_not_called()

    def test_actual_resource_bytes_stay_bounded_without_pretty_print_amplification(self):
        with tempfile.TemporaryDirectory() as d:
            e = paths.Env('aws', 'review', workdir=Path(d))
            nested = 'ok'
            for _ in range(50):
                nested = {'nested': nested}
            e.config_path.write_text(json.dumps({'extra_vars': nested}))
            (e.dir / 'outputs.json').write_text('{}')
            with mock.patch.object(paths.Env, 'list_all', return_value=[e]), mock.patch.object(mcp, 'MAX_RESOURCE', 1024):
                resource = mcp.read_resource('cloudseed://environments')['contents'][0]['text']
                self.assertLessEqual(len(resource.encode()), 1024)
                self.assertEqual(json.loads(resource)[0]['config']['extra_vars'], nested)
                with mock.patch.object(mcp.secrets, 'redact', return_value='x' * 1025), self.assertRaises(ValueError):
                    mcp.read_resource('cloudseed://environments')

    def test_deep_invalid_config_and_outputs_do_not_hide_other_environments(self):
        with tempfile.TemporaryDirectory() as d:
            envs = [paths.Env('aws', name, workdir=Path(d) / name) for name in ('config', 'outputs', 'good')]
            for e in envs:
                e.dir.mkdir(parents=True, exist_ok=True)
                e.config_path.write_text('{"region":"us-east-1"}')
                (e.dir / 'outputs.json').write_text('{}')
            deep = '[' * 1100 + ']' * 1100
            envs[0].config_path.write_text('{"nested":' + '[' * 100 + '0' + ']' * 100 + '}')
            (envs[1].dir / 'outputs.json').write_text(deep)
            with mock.patch.object(paths.Env, 'list_all', return_value=envs):
                resources = mcp._environments()
            self.assertIn('ValueError', resources[0]['error'])
            self.assertEqual(resources[1]['outputs'], {})
            self.assertIn('outputs_note', resources[1])
            self.assertEqual(resources[2]['config']['region'], 'us-east-1')

    def test_oversized_batch_resource_preserves_other_executed_outcomes(self):
        requests = [{'id': i, 'method': 'tools/call'} for i in (1, 2, 3)]
        replies = [{'jsonrpc': '2.0', 'id': 1, 'result': {'changed': True}},
                   {'jsonrpc': '2.0', 'id': 2, 'result': 'x' * 2000},
                   {'jsonrpc': '2.0', 'id': 3, 'result': {'changed': False}}]
        with mock.patch.object(mcp, 'MAX_BODY', 1500), mock.patch.object(mcp, 'handle', side_effect=replies) as handle:
            result = mcp.dispatch(requests, mcp.Session({}))
        self.assertEqual(handle.call_count, 3)
        self.assertEqual(result[0], replies[0])
        self.assertEqual(result[1]['id'], 2)
        self.assertIn('may have completed', result[1]['error']['message'])
        self.assertEqual(result[2], replies[2])
        self.assertLessEqual(len(json.dumps(result).encode()), 1500)

    def test_oversized_batch_ids_reject_before_any_effect(self):
        with mock.patch.object(mcp, 'MAX_BODY', 1024), mock.patch.object(mcp, 'handle') as handle:
            result = mcp.dispatch([{'id': 'x' * 800, 'method': 'tools/call'}, {'id': 2, 'method': 'ping'}], mcp.Session({}))
        self.assertEqual(result['error']['code'], -32600)
        handle.assert_not_called()

    def test_stdio_oversized_and_deep_messages_do_not_kill_next_ping(self):
        huge = b'x' * 1024 + b'\n'
        deep = b'[' * 1100 + b']' * 1100 + b'\n'
        ping = json.dumps({'jsonrpc': '2.0', 'id': 5, 'method': 'ping'}).encode() + b'\n'
        output = io.BytesIO()
        with mock.patch.object(mcp, 'MAX_BODY', 512), mock.patch.object(mcp, 'enabled', return_value=True), \
             mock.patch.object(mcp, 'LiveEnv'), mock.patch.object(mcp, '_exit_on_signals'), \
             mock.patch.object(mcp.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(huge + deep + ping))), \
             mock.patch.object(mcp.sys, 'stdout', SimpleNamespace(buffer=output)):
            self.assertEqual(mcp.serve(), 0)
        messages = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([x['error']['code'] for x in messages[:2]], [-32600, -32600])
        self.assertEqual(messages[-1]['id'], 5)
        self.assertIn('result', messages[-1])

    def test_deep_json_is_rejected_and_transport_answers_next_ping(self):
        deep = b'[' * 1100 + b']' * 1100 + b'\n'
        ping = b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n'
        output = io.BytesIO()
        with mock.patch.object(mcp, 'enabled', return_value=True), mock.patch.object(mcp, 'LiveEnv'), \
             mock.patch.object(mcp, '_exit_on_signals'), \
             mock.patch.object(mcp.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(deep + ping))), \
             mock.patch.object(mcp.sys, 'stdout', SimpleNamespace(buffer=output)):
            self.assertEqual(mcp.serve(), 0)
        messages = [json.loads(line) for line in output.getvalue().splitlines()]
        # Decoder recursion limits differ across supported Python versions. A
        # decoded nested array is an invalid batch entry; either rejection must
        # leave the stdio transport running for the following valid request.
        rejected = messages[0][0] if isinstance(messages[0], list) else messages[0]
        self.assertIn(rejected['error']['code'], (-32700, -32600))
        self.assertEqual(messages[-1]['id'], 7)

    def test_tool_detection_checks_only_one_legal_batch_level(self):
        tool = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call'}
        self.assertTrue(mcp._is_tool_call(tool))
        self.assertTrue(mcp._is_tool_call([{'id': 2, 'method': 'ping'}, tool]))
        self.assertFalse(mcp._is_tool_call([[tool]]))
        nested = tool
        for _ in range(5000):
            nested = [nested]
        self.assertFalse(mcp._is_tool_call(nested))
        with mock.patch.object(mcp, 'call_tool') as call:
            result = mcp.dispatch([nested], mcp.Session({}))
        self.assertEqual(result[0]['error']['code'], -32600)
        call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
