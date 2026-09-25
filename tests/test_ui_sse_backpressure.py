"""A slow SSE reader must not retain unlimited output or hold up its job."""
import gc
import io
import json
import tempfile
import threading
import unittest
import weakref
from pathlib import Path
from unittest import mock

from cloudseed import secrets, webui


class _Line(str):
    """Weak references let the test count output still retained by the server."""


class StreamBackpressureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cs-sse-")
        self.addCleanup(temporary.cleanup)
        for patch in (mock.patch.object(webui, "JOBS_DIR", Path(temporary.name)),
                      mock.patch.object(webui, "MAX_LINES", 8), mock.patch.object(webui, "HEAD_LINES", 2),
                      mock.patch.dict(webui.JOBS, clear=True)):
            patch.start()
            self.addCleanup(patch.stop)
        self.job = webui.Job("slow-reader", ["list"], "list")
        webui.JOBS[self.job.id] = self.job

    def handler(self, output, last=None):
        handler = object.__new__(webui._Handler)
        handler.headers = {} if last is None else {"Last-Event-ID": str(last)}
        handler.wfile = output
        handler.send_response = mock.Mock()
        handler.send_header = mock.Mock()
        handler.end_headers = mock.Mock()
        return handler

    def start_stream(self, handler):
        errors = []

        def stream():
            try:
                handler._stream(self.job.id)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=stream, daemon=True)
        thread.start()
        return thread, errors

    @staticmethod
    def ids(text):
        return [int(line[4:]) for line in text.splitlines() if line.startswith("id: ")]

    def test_stalled_reader_retains_only_bounded_history_and_still_gets_completion(self):
        blocked, release, produced = threading.Event(), threading.Event(), threading.Event()
        retained = weakref.WeakSet()
        job = self.job

        class SlowSocket(io.BytesIO):
            def write(self, data):
                if data.startswith(b"retry:"):
                    blocked.set()
                    if not release.wait(5):
                        raise TimeoutError("test socket was not released")
                return super().write(data)

        output = SlowSocket()
        stream, errors = self.start_stream(self.handler(output))

        def produce():
            for index in range(5000):
                line = _Line(f"line {index}")
                retained.add(line)
                job.push(line)
            job.finish(7)
            produced.set()

        producer = threading.Thread(target=produce, daemon=True)
        try:
            self.assertTrue(blocked.wait(2), "stream did not reach the blocked socket")
            producer.start()
            self.assertTrue(produced.wait(2), "a slow reader blocked the job producer/completion")
            producer.join(2)
            gc.collect()
            self.assertLessEqual(len(retained), webui.MAX_LINES, "subscriber retained output evicted from job history")
        finally:
            release.set()
            stream.join(3)
        self.assertFalse(stream.is_alive())
        self.assertEqual(errors, [])
        text = output.getvalue().decode()
        self.assertEqual(self.ids(text), [1, 2, 4994, 4995, 4996, 4997, 4998, 4999, 5000])
        self.assertIn("4992 lines omitted", text)
        done = json.loads(text.split("event: done\ndata: ", 1)[1].split("\n", 1)[0])
        self.assertEqual((done["rc"], done["line_count"]), (7, 5000))
        self.assertEqual(self.job.subscribers, [])

        # A reconnect from within the omitted middle gets the gap marker and the retained tail, without duplicates.
        resumed = io.BytesIO()
        self.handler(resumed, last=2500)._stream(self.job.id)
        self.assertEqual(self.ids(resumed.getvalue().decode()), list(range(4994, 5001)))
        self.assertIn(b"event: done", resumed.getvalue())

    def test_updates_while_writing_are_replayed_once_with_redaction_and_done(self):
        self.job.push("first")
        job = self.job

        class UpdatingSocket(io.BytesIO):
            def write(self, data):
                if data.startswith(b"id: 1\n"):
                    redactor = secrets.StreamRedactor()
                    for line in (b"-----BEGIN PRIVATE KEY-----", b"private-key-body",
                                 b"-----END PRIVATE KEY-----", b"after"):
                        webui._push_raw(job, line, redactor)
                    job.finish(0)
                return super().write(data)

        output = UpdatingSocket()
        stream, errors = self.start_stream(self.handler(output))
        stream.join(3)
        self.assertFalse(stream.is_alive(), "job lock was held during socket output or a wakeup was lost")
        self.assertEqual(errors, [])
        text = output.getvalue().decode()
        self.assertEqual(self.ids(text), [1, 2, 3])
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("private-key-body", text)
        self.assertEqual(text.count("event: done"), 1)
        self.assertEqual(self.job.subscribers, [])

    def test_disconnection_while_sending_headers_unregisters_subscriber(self):
        handler = self.handler(io.BytesIO())
        handler.end_headers.side_effect = BrokenPipeError()
        handler._stream(self.job.id)
        self.assertEqual(self.job.subscribers, [])


if __name__ == "__main__":
    unittest.main()
