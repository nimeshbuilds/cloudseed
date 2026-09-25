"""Environment mutations must never run when their serialization lock is unavailable."""
from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cloudseed import cli, paths, ui


class EnvLockFailureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cs-lock-failures-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        patches = contextlib.ExitStack()
        self.addCleanup(patches.close)
        patches.enter_context(mock.patch.object(paths, "HOME", self.home))
        patches.enter_context(mock.patch.object(paths, "ENVS_DIR", self.home / "envs"))
        patches.enter_context(mock.patch.object(paths, "WORKDIRS_INDEX", self.home / "workdirs.json"))
        patches.enter_context(mock.patch.dict(os.environ, {paths.LOCK_ENV_VAR: ""}))
        self.env = paths.Env("aws", "lock-failure")

    def assert_refused(self, message):
        changed = []
        with self.assertRaises(ui.Abort) as raised:
            with self.env.lock("apply aws --env lock-failure"):
                changed.append(True)
        self.assertIn(message, raised.exception.msg)
        self.assertIn(self.env.id, raised.exception.msg)
        self.assertEqual(changed, [], "the mutation body must never start")
        self.assertNotIn(self.env.id, paths._LOCKS)
        self.assertNotIn(self.env.id, paths._inherited_locks())

    def test_missing_platform_support_refuses_mutation(self):
        with mock.patch.object(paths, "fcntl", None):
            self.assert_refused("native Windows mutation is unsupported")
        self.assertFalse(self.env.lock_path().exists())

    @unittest.skipIf(paths.fcntl is None, "requires POSIX flock")
    def test_lock_directory_creation_failure_refuses_mutation(self):
        with mock.patch.object(Path, "mkdir", side_effect=PermissionError(errno.EACCES, "permission denied")):
            self.assert_refused("Cannot open the environment lock")

    @unittest.skipIf(paths.fcntl is None, "requires POSIX flock")
    def test_lock_file_open_failure_refuses_mutation(self):
        with mock.patch("cloudseed.paths.open", side_effect=OSError(errno.EROFS, "read-only filesystem")):
            self.assert_refused("Cannot open the environment lock")

    @unittest.skipIf(paths.fcntl is None, "requires POSIX flock")
    def test_filesystem_without_flock_refuses_mutation_and_closes_handle(self):
        self.env.lock_path().parent.mkdir()
        with open(self.env.lock_path(), "a+") as handle:
            with mock.patch("cloudseed.paths.open", return_value=handle), \
                    mock.patch.object(paths.fcntl, "flock", side_effect=OSError(errno.ENOTSUP, "not supported")):
                self.assert_refused("Cannot acquire the environment lock")
            self.assertTrue(handle.closed)
        with self.env.lock("retry"):
            self.assertEqual(self.env.lock_holder()["action"], "retry")

    @unittest.skipIf(paths.fcntl is None, "requires POSIX flock")
    def test_lock_metadata_failure_refuses_mutation_and_releases_lock(self):
        self.env.lock_path().parent.mkdir()
        with open(self.env.lock_path(), "a+") as handle:
            wrapper = mock.Mock(wraps=handle)
            wrapper.write.side_effect = OSError(errno.ENOSPC, "no space left")
            with mock.patch("cloudseed.paths.open", return_value=wrapper):
                self.assert_refused("Cannot record the environment lock")
            self.assertTrue(handle.closed)
        with self.env.lock("retry"):
            self.assertEqual(self.env.lock_holder()["action"], "retry")

    def test_environment_discovery_and_cached_configuration_work_without_flock(self):
        self.env.dir.mkdir(parents=True)
        self.env.config_path.write_text(json.dumps({"cloud": "aws", "env": self.env.name, "name": "test"}))
        with mock.patch.object(paths, "fcntl", None), \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual([env.id for env in paths.Env.list_all()], [self.env.id])
            self.assertEqual(self.env.load()["name"], "test")
            self.assertEqual(cli.main(["list"]), 0)
        self.assertIn(self.env.id, output.getvalue())
        self.assertFalse(self.env.lock_path().exists())
