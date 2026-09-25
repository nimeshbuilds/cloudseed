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

    def test_deep_json_is_parse_error_followed_by_usable_transport(self):
        deep = b'[' * 1100 + b']' * 1100 + b'\n'
        ping = b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n'
        output = io.BytesIO()
        with mock.patch.object(mcp, 'enabled', return_value=True), mock.patch.object(mcp, 'LiveEnv'), \
             mock.patch.object(mcp, '_exit_on_signals'), \
             mock.patch.object(mcp.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(deep + ping))), \
             mock.patch.object(mcp.sys, 'stdout', SimpleNamespace(buffer=output)):
            self.assertEqual(mcp.serve(), 0)
        messages = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(messages[0]['error']['code'], -32700)
        self.assertEqual(messages[-1]['id'], 7)


if __name__ == '__main__':
    unittest.main()
