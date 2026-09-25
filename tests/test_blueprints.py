"""Profiles and portable specs must be previewable, reproducible and credential-free."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cloudseed import blueprints, clouds, paths, ui


class BlueprintTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name, value in (("HOME", self.root), ("ENVS_DIR", self.root / "envs"), ("WORKDIRS_INDEX", self.root / "workdirs.json")):
            patch = mock.patch.object(paths, name, value)
            patch.start(); self.addCleanup(patch.stop)

    def fixture(self, target="aws"):
        cloud = clouds.get(target)
        env = paths.Env(target, "review")
        cfg = {"cloud": target, "env": "review", "name": "cloudseed", "region": {"aws": "us-east-1", "gcp": "us-central1", "azure": "eastus", "vmware": "local"}[target],
               "network_cidr": "10.40.0.0/16", "allowed_ssh_cidrs": ["192.0.2.4/32"], "tags": {}, "vars": {}, "extra_vars": {}}
        if target == "gcp": cfg["vars"].update(project_id="review-project", zone="us-central1-a")
        if target == "azure": cfg["vars"]["subscription_id"] = "0123abcd-0000-0000-0000-000000000000"
        if target == "vmware": cfg["network_cidr"] = "10.40.0.0/24"
        return cloud, env, cfg

    def test_every_profile_on_every_cloud_validates_and_does_not_save(self):
        for target in clouds.CLOUDS:
            for profile in blueprints.PROFILES:
                cloud, env, cfg = self.fixture(target)
                before = copy.deepcopy(cfg)
                result = blueprints.execute("profile", cloud, env, cfg, {"profile": profile})
                self.assertFalse(result["saved"])
                self.assertFalse(env.exists())
                self.assertEqual(cfg, before)
                self.assertEqual(result["spec"]["operations"]["profile"], profile)
                self.assertFalse(result["cost"]["coverage_complete"])
                blueprints.validate_spec(result["spec"], cloud, env)

    def test_production_changes_real_rendered_cloud_controls(self):
        for target, values in {"aws": {"single_nat_gateway": False, "az_count": 3}, "gcp": {"kubernetes_regional": True}, "azure": {"kubernetes_sku_tier": "Standard", "kubernetes_zones": ["1", "2", "3"]}}.items():
            cloud, env, cfg = self.fixture(target)
            spec = blueprints.execute("profile", cloud, env, cfg, {"profile": "production"})["spec"]
            candidate = {**cfg, **spec["configuration"], "owner": "tester", "ssh_public_key": "ssh-ed25519 placeholder"}
            rendered = cloud.module_vars(candidate)
            for key, value in values.items(): self.assertEqual(rendered[key], value)

    def test_export_drops_credentials_machine_paths_and_ownership(self):
        cloud, env, cfg = self.fixture()
        cfg.update(uid="owner-id", ssh_public_key="public-key", ssh_private_key_path="/private/key", workdir="/private/run", state={"backend": {"secret": "hidden"}}, credentials="hidden")
        cfg["vars"].update(profile="private-login", secret="hidden", enable_kubernetes=True)
        cfg["extra_vars"].update(vm_dir="/private/run", unknown_token="hidden")
        spec = blueprints.execute("spec-export", cloud, env, cfg, {})["spec"]
        encoded = json.dumps(spec)
        for text in ("hidden", "owner-id", "/private", "public-key", "private-login"): self.assertNotIn(text, encoded)

    def test_roundtrip_save_preserves_local_identity_and_keys(self):
        cloud, env, cfg = self.fixture()
        cfg.update(uid="original-owner", ssh_private_key_path="/private/key", state={"type": "local"})
        cfg["vars"]["profile"] = "saved-login"
        env.save(cfg)
        spec = blueprints.export_spec(cloud, env, cfg)
        spec["configuration"]["tags"]["team"] = "platform"
        diff = blueprints.execute("spec-diff", cloud, env, cfg, {"spec": spec})
        self.assertEqual(diff["changes"][0]["path"], "configuration.tags.team")
        result = blueprints.execute("spec-import", cloud, env, cfg, {"spec": spec, "approve": True})
        self.assertTrue(result["saved"])
        saved = env.load()
        self.assertEqual(saved["uid"], "original-owner")
        self.assertEqual(saved["ssh_private_key_path"], "/private/key")
        self.assertEqual(saved["vars"]["profile"], "saved-login")
        self.assertEqual(saved["state"], {"type": "local"})
        self.assertEqual(saved["tags"]["team"], "platform")

    def test_spec_rejects_unknown_credentials_bad_types_and_foreign_target(self):
        cloud, env, cfg = self.fixture()
        base = blueprints.export_spec(cloud, env, cfg)
        mutations = [lambda x: x.update(schema_version=2), lambda x: x.update(cloud="azure"), lambda x: x["configuration"].update(workdir="/tmp"), lambda x: x["configuration"]["vars"].update(token="secret"), lambda x: x["configuration"]["extra_vars"].update(enable_flow_logs="yes"), lambda x: x["configuration"]["extra_vars"].update(allowed_ssh_cidrs=["0.0.0.0/0"]), lambda x: x.update(operations={"budget_max_monthly": float("nan")}), lambda x: x.update(operations={"cleanup_opt_in": True})]
        for mutate in mutations:
            spec = copy.deepcopy(base); mutate(spec)
            with self.assertRaises(ui.Abort): blueprints.validate_spec(spec, cloud, env)

    def test_private_keys_and_deep_inputs_never_export_or_import(self):
        cloud, env, cfg = self.fixture()
        cfg["tags"]["note"] = "-----BEGIN " + "PRIVATE KEY----- data"
        with self.assertRaises(ui.Abort): blueprints.export_spec(cloud, env, cfg)
        data = {}; current = data
        for _ in range(14): current["nested"] = {}; current = current["nested"]
        with self.assertRaises(ui.Abort): blueprints.validate_spec(data, cloud, env)

    def test_changed_config_is_not_overwritten_after_review(self):
        cloud, env, cfg = self.fixture()
        env.save(cfg)
        changed = copy.deepcopy(cfg); changed["tags"] = {"new": "value"}; env.save(changed)
        with self.assertRaises(ui.Abort): blueprints.execute("profile", cloud, env, cfg, {"profile": "lab", "approve": True})
        self.assertEqual(env.load()["tags"], {"new": "value"})

    def test_invalid_provider_topology_is_refused(self):
        for target, overrides in [("gcp", {"kubernetes_regional": True}), ("gcp", {"kubernetes_regional": True, "kubernetes_node_locations": ["europe-west1-b"]}), ("azure", {"kubernetes_zones": ["1", "1"]}), ("azure", {"kubernetes_sku_tier": "Premium"})]:
            cloud, env, cfg = self.fixture(target)
            spec = blueprints.export_spec(cloud, env, cfg); spec["configuration"]["extra_vars"].update(overrides)
            with self.assertRaises(ui.Abort): blueprints.validate_spec(spec, cloud, env)

    def test_regional_node_cost_multiplies_actual_node_zones(self):
        cloud, env, cfg = self.fixture("gcp")
        report = blueprints.execute("profile", cloud, env, cfg, {"profile": "production"})
        names = [c["name"] for c in report["cost"]["components"]]
        self.assertIn("GKE node e2-standard-2 x3", names)
        self.assertIn("GKE cluster fee (regional)", names)

    def test_load_json_and_safe_yaml_have_identical_results(self):
        cloud, env, cfg = self.fixture()
        expected = blueprints.export_spec(cloud, env, cfg)
        path = self.root / "cloudseed.yaml"
        path.write_text(json.dumps(expected))
        self.assertEqual(blueprints.load_spec(path), expected)
        path.write_text('''schema_version: 1
cloud: aws
environment: review
configuration:
  name: cloudseed
  region: us-east-1
  network_cidr: 10.40.0.0/16
  allowed_ssh_cidrs:
    - 192.0.2.4/32
  tags: {}
  vars: {}
  extra_vars: {}
''')
        self.assertEqual(blueprints.load_spec(path), expected)

    def test_yaml_rejects_tags_aliases_duplicate_fields_and_multidoc(self):
        path = self.root / "bad.yaml"
        for text in ('a: !!python/object:Thing {}', 'a: &anchor hi\nb: *anchor', 'a: 1\na: 2', '---\na: 1\n---\nb: 2', '{"a":1,"a":2}', 'a: .nan', 'a: |\n  multiline'):
            path.write_text(text)
            with self.assertRaises(ui.Abort): blueprints.load_spec(path)
