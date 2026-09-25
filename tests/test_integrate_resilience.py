"""Integration of fix/resilience with the ops undo-journal fixes: Velero undo points.

ops made pre-change backups expiring, labelled and discardable (undo.discard_velero_backup); resilience made them keep a
backup only when Velero really finished it (dr.backup_usable) and never block the change. Offline: velero is faked.
"""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-"))

from cloudseed import clouds, dr, paths, platform as pl, ui, undo  # noqa: E402


def _ctx(name="intres"):
    env = paths.Env("vmware", name)
    env.create_dirs()
    cfg = {"env": name, "name": "t", "region": "r", "network_cidr": "10.0.0.0/16", "vars": {}}
    return pl.Cluster(clouds.get("vmware"), env, cfg, {"kubernetes_distro": "rke2"}, env.dir / "kc")


class _Velero:
    def __init__(self, phase):
        self.phase, self.calls = phase, []

    def __call__(self, ctx, *args, check=True, stream=False, timeout=1800, quiet=False):
        self.calls.append(args)
        if len(args) >= 3 and args[:2] == ("backup", "get"):
            return subprocess.CompletedProcess([], 0, json.dumps({"status": {"phase": self.phase}}), "")
        return subprocess.CompletedProcess([], 0, "", "")


@contextlib.contextmanager
def _quiet():
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield


class VeleroUndoPointTests(unittest.TestCase):
    def test_usable_backup_keeps_ttl_and_label(self):
        fake = _Velero("Completed")
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_velero", fake), _quiet():
            name = undo.velero_pre_backup(_ctx("intres1"), "kubectl", ["shop"])
        self.assertTrue(name.startswith("pre-kubectl-"))
        create = fake.calls[0]
        self.assertEqual(create[:3], ("backup", "create", name))
        self.assertIn(undo.VELERO_TTL, create)
        self.assertIn(undo.VELERO_LABEL, create)
        self.assertFalse(any(c[:2] == ("backup", "delete") for c in fake.calls))

    def test_failed_backup_is_not_an_undo_point_and_is_discarded(self):
        fake = _Velero("Failed")
        no_cluster = subprocess.CompletedProcess([], 1, "", "no cluster in unit tests")   # the hint's storage-location lookup
        with mock.patch.object(dr, "installed", return_value=True), mock.patch.object(dr, "_velero", fake), \
                mock.patch.object(dr, "_kubectl", return_value=no_cluster), _quiet():
            self.assertIsNone(undo.velero_pre_backup(_ctx("intres2"), "helm", ["shop"]))
        name = fake.calls[0][2]
        self.assertIn(("backup", "delete", name, "--confirm"), fake.calls)

    def test_discard_is_best_effort_even_when_the_cli_cannot_be_fetched(self):
        def offline(*a, **k):
            raise ui.Abort("Could not download the velero CLI")
        with mock.patch.object(dr, "_velero", offline), _quiet():
            undo.discard_velero_backup(_ctx("intres3"), "pre-x")   # must not raise


if __name__ == "__main__":
    unittest.main()
