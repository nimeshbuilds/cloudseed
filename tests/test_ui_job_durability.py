"""Console completion must agree with the record a restarted console reads."""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from cloudseed import webui


class JobPersistenceTests(unittest.TestCase):
    def test_completion_is_visible_only_after_terminal_metadata_is_saved(self):
        with tempfile.TemporaryDirectory(prefix="cloudseed-job-persistence-") as temporary, \
                mock.patch.object(webui, "JOBS_DIR", Path(temporary)):
            job = webui.Job("persist", ["apply", "aws"], "apply")
            job.save_meta()
            saving, release, observing, observed = (threading.Event() for _ in range(4))
            result = []
            write = webui._write_json

            def slow_write(path, data):
                if data.get("rc") is not None:
                    saving.set()
                    release.wait(5)
                write(path, data)

            def observe():
                observing.set()
                result.append((job.running, json.loads(job.meta_path.read_text())["rc"]))
                observed.set()

            with mock.patch.object(webui, "_write_json", side_effect=slow_write):
                finisher = threading.Thread(target=job.finish, args=(137,))
                finisher.start()
                reader = None
                try:
                    self.assertTrue(saving.wait(2))
                    reader = threading.Thread(target=observe)
                    reader.start()
                    self.assertTrue(observing.wait(2))
                    self.assertFalse(observed.wait(0.05), "completion escaped before its metadata was durable")
                finally:
                    release.set()
                    finisher.join(2)
                    if reader is not None:
                        reader.join(2)
                self.assertFalse(finisher.is_alive())
                self.assertTrue(observed.is_set())
            self.assertEqual(result, [(False, 137)])


if __name__ == "__main__":
    unittest.main()
