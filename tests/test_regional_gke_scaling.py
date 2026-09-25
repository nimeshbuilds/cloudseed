"""GKE counts must stay per zone across live discovery, resizing, saved config and readiness.

Provider/cluster calls are deterministic fixtures: these tests do not provision a cloud account.
"""
from __future__ import annotations

import contextlib
import copy
import io
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-test-gke-"))

from cloudseed import cli, clouds, ui  # noqa: E402


class RegionalGKEScalingTests(unittest.TestCase):
    def setUp(self):
        self.cloud = clouds.get("gcp")
        self.env = SimpleNamespace(id="gcp-prod", name="prod", save=mock.Mock())
        self.zones = ["us-central1-a", "us-central1-b", "us-central1-c"]
        self.cfg = {"region": "us-central1", "vars": {"project_id": "p", "zone": "us-central1-a", "kubernetes_node_count": 1},
                    "extra_vars": {"kubernetes_regional": True, "kubernetes_node_locations": self.zones}}
        self.outputs = {"kubernetes_cluster_name": "c1", "kubernetes_location": "us-central1", "kubernetes_node_pool": "default"}
        self.spec = {"name": "default", "locations": self.zones, "autoscaling": {"minNodeCount": 1, "maxNodeCount": 3},
                     "instanceGroupUrls": [f"https://compute.googleapis.com/compute/v1/projects/p/zones/{z}/instanceGroupManagers/gke-{z}" for z in self.zones]}
        self.targets = {z: {"targetSize": 1} for z in self.zones}
        self.calls = []

    def provider(self, cmd, what, **kwargs):
        self.calls.append(cmd)
        if cmd[1:4] == ["container", "node-pools", "list"]:
            return [copy.deepcopy(self.spec)]
        if "instance-groups" in cmd and "describe" in cmd:
            return self.targets[cmd[cmd.index("--zone") + 1]]
        return ""

    @contextlib.contextmanager
    def mocks(self):
        with mock.patch.object(cli.deps, "find", return_value="gcloud"), \
                mock.patch.object(cli.services, "cloud_cli_env", return_value={}), \
                mock.patch.object(cli, "_cloud_cli", side_effect=self.provider), \
                mock.patch.object(cli.audit, "note"), mock.patch.object(cli.undo, "record") as undo, \
                mock.patch.object(cli, "_approve") as approve, \
                mock.patch.object(cli, "_wait_ready_nodes", side_effect=lambda k, e, n, s: n) as ready, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            yield undo, approve, ready, out

    def run_node(self, action="add", count=1):
        args = SimpleNamespace(node_cmd=action, count=count, min=None, max=None, auto_approve=True, name="node-a")
        return cli._node_managed(args, self.cloud, self.env, self.cfg, self.outputs, "kubectl", {})

    def test_regional_add_keeps_per_zone_units_and_waits_for_total(self):
        with self.mocks() as (undo, approve, ready, out):
            self.assertEqual(self.run_node(), 0)
        resize = next(c for c in self.calls if "resize" in c)
        update = next(c for c in self.calls if "update" in c)
        self.assertEqual(resize[resize.index("--num-nodes") + 1], "2")  # six total, never twelve
        self.assertEqual(update[update.index("--min-nodes") + 1], "2")
        self.assertEqual(update[update.index("--max-nodes") + 1], "3")
        self.assertEqual(resize[resize.index("--location") + 1], "us-central1")
        self.assertEqual(self.cfg["vars"]["kubernetes_node_count"], 2)
        self.assertEqual(self.cfg["extra_vars"]["kubernetes_node_min"], 2)
        ready.assert_called_once_with("kubectl", {}, 6, "cloud.google.com/gke-nodepool=default")
        self.assertIn("6 total", approve.call_args[0][0])
        self.assertIn("node(s) per zone", out.getvalue())
        argv = undo.call_args[0][3]["argv"]
        self.assertEqual(argv[argv.index("--count") + 1], "1")

    def test_regional_scale_count_is_per_zone(self):
        with self.mocks() as (_, _, ready, _):
            self.assertEqual(self.run_node("scale", 3), 0)
        resize = next(c for c in self.calls if "resize" in c)
        self.assertEqual(resize[resize.index("--num-nodes") + 1], "3")
        self.assertEqual(self.cfg["vars"]["kubernetes_node_count"], 3)
        self.assertEqual(ready.call_args[0][2], 9)

    def test_zonal_discovery_without_locations_stays_compatible(self):
        self.cfg["extra_vars"] = {}
        self.spec.pop("locations")
        self.spec["instanceGroupUrls"] = self.spec["instanceGroupUrls"][:1]
        self.outputs["kubernetes_location"] = "us-central1-a"
        with self.mocks() as (_, _, ready, _):
            self.assertEqual(self.run_node(), 0)
        self.assertEqual(ready.call_args[0][2], 2)
        self.assertEqual(self.cfg["vars"]["kubernetes_node_count"], 2)

    def test_unavailable_or_partial_zone_preflight_never_mutates(self):
        original = copy.deepcopy(self.spec)
        for edits in ({"instanceGroupUrls": []}, {"instanceGroupUrls": original["instanceGroupUrls"][:2]},
                      {"instanceGroupUrls": [original["instanceGroupUrls"][0]] * 3},
                      {"instanceGroupUrls": ["bad"]}, {"locations": "us-central1-a"},
                      {"locations": self.zones + [self.zones[0]]}):
            with self.subTest(edits=edits):
                self.calls.clear()
                self.spec = {**copy.deepcopy(original), **edits}
                with self.mocks() as (_, approve, ready, _), self.assertRaises(ui.Abort):
                    self.run_node()
                approve.assert_not_called(); ready.assert_not_called(); self.env.save.assert_not_called()
                self.assertFalse(any("resize" in c or "update" in c for c in self.calls))

    def test_missing_invalid_or_unbalanced_live_sizes_never_mutate(self):
        for value in ({}, {"targetSize": -1}, {"targetSize": True}, {"targetSize": "1"}, {"targetSize": 2}):
            with self.subTest(value=value):
                self.calls.clear()
                self.targets[self.zones[1]] = value
                with self.mocks() as (_, approve, _, _), self.assertRaises(ui.Abort):
                    self.run_node()
                approve.assert_not_called(); self.env.save.assert_not_called()
                self.assertFalse(any("resize" in c or "update" in c for c in self.calls))

    def test_total_autoscaler_mode_is_not_mistaken_for_per_zone_bounds(self):
        self.spec["autoscaling"] = {"totalMinNodeCount": 3, "totalMaxNodeCount": 9}
        with self.mocks() as (_, approve, _, _), self.assertRaises(ui.Abort):
            self.run_node()
        approve.assert_not_called(); self.env.save.assert_not_called()

    def test_targeted_multizone_remove_aborts_before_node_access_or_drain(self):
        with self.mocks(), mock.patch.object(cli, "_node_json") as node, \
                mock.patch.object(cli, "_drain_node") as drain, self.assertRaises(ui.Abort) as raised:
            self.run_node("remove")
        node.assert_not_called(); drain.assert_not_called(); self.env.save.assert_not_called()
        self.assertIn("cs node scale gcp --env prod --count N", str(raised.exception))

    def test_zero_live_target_size_is_valid_and_wait_uses_all_zones(self):
        self.targets = {z: {"targetSize": 0} for z in self.zones}
        self.spec["autoscaling"]["minNodeCount"] = 0
        with self.mocks() as (_, _, ready, _):
            self.assertEqual(self.run_node(), 0)
        self.assertEqual(ready.call_args[0][2], 3)
        self.assertEqual(self.cfg["vars"]["kubernetes_node_count"], 1)


if __name__ == "__main__":
    unittest.main()
