"""Guardrails must fail closed on incomplete budgets and unknown destructive plans."""
import copy
import unittest
from unittest import mock

from cloudseed import guardrails, ui
from tests import test_blueprints as fixtures


class GuardrailTests(unittest.TestCase):
    setUp = fixtures.BlueprintTests.setUp
    fixture = fixtures.BlueprintTests.fixture
    def call(self, cfg=None, **params):
        cloud, env, base = self.fixture()
        return guardrails.execute("policy-check", cloud, env, base if cfg is None else cfg, params)

    def test_incomplete_estimate_never_passes_a_budget(self):
        result = self.call(budget_max_monthly=10000)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["verdict"], "BLOCKED")
        result = self.call(budget_max_monthly=10000, require_complete_cost=False)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["verdict"], "INCOMPLETE")

    def test_known_cost_over_budget_blocks_even_when_unknowns_accepted(self):
        result = self.call(budget_max_monthly=1, require_complete_cost=False)
        self.assertFalse(result["allowed"])

    def test_complete_supplied_cost_must_be_finite_and_coherent(self):
        good = {"currency": "USD", "period": "month", "known_monthly": 100, "coverage_complete": True}
        result = self.call(estimate=good, budget_max_monthly=101, plan={"resource_changes": []})
        self.assertEqual(result["checks"][0]["status"], "PASS")
        for edits in ({"known_monthly": 10 ** 400}, {"known_monthly": float("nan")}, {"known_monthly": -1}, {"known_monthly": True}, {"coverage_complete": "true"}, {"unpriced": ["network"]}, {"currency": "EUR"}):
            with self.assertRaises(ui.Abort): self.call(estimate={**good, **edits})

    def test_deletion_replacement_forget_and_missing_plan_are_gated(self):
        for actions in (["delete"], ["create", "delete"], ["delete", "create"], ["forget"]):
            plan = {"resource_changes": [{"address": "module.stack.aws_instance.test", "change": {"actions": actions, "before": {"password": "DO_NOT_PRINT"}}}]}
            result = self.call(plan=plan)
            self.assertFalse(result["allowed"])
            self.assertNotIn("DO_NOT_PRINT", str(result))
            self.assertTrue(self.call(plan=plan, allow_destroy=True)["allowed"])
        self.assertFalse(self.call(block_destroy=True)["allowed"])
        self.assertTrue(self.call(block_destroy=True, plan={"resource_changes": []})["allowed"])

    def test_malformed_plan_is_not_a_successful_empty_plan(self):
        for plan in ({}, {"resource_changes": None}, {"resource_changes": [{}]}, {"resource_changes": [{"address": "x", "change": {"actions": ["new-action"]}}]}):
            with self.assertRaises(ui.Abort): self.call(plan=plan)

    def test_expiry_is_explicit_and_never_schedules_deletion(self):
        result = self.call(expires_at="2020-01-01T00:00:00Z", cleanup_opt_in=True)
        self.assertTrue(result["cleanup"]["due"])
        self.assertTrue(result["cleanup"]["opted_in"])
        self.assertFalse(result["cleanup"]["scheduled"])
        for params in ({"expires_at": "tomorrow"}, {"expires_at": "2020-01-01"}, {"cleanup_opt_in": True}):
            with self.assertRaises(ui.Abort): self.call(**params)

    def test_world_open_ssh_is_a_definite_policy_failure(self):
        _, _, cfg = self.fixture()
        cfg["allowed_ssh_cidrs"] = ["0.0.0.0/0"]
        self.assertFalse(self.call(cfg)["allowed"])

    def test_apply_gate_preserves_legacy_and_blocks_configured_limits(self):
        cloud, env, cfg = self.fixture()
        self.assertIsNone(guardrails.enforce(cloud, env, cfg))
        cfg["operations"] = {"budget_max_monthly": 1}
        with self.assertRaises(ui.Abort): guardrails.enforce(cloud, env, cfg, plan={"resource_changes": []})

    def test_estimate_uses_desired_topology_not_stale_inventory(self):
        cloud, env, cfg = self.fixture()
        cfg["vars"].update(single_nat_gateway=False, az_count=3)
        with mock.patch("cloudseed.finops.audit.load", side_effect=AssertionError("must not use stale inventory")):
            result = guardrails.cost_preview(cloud, env, cfg)
        self.assertIn("NAT gateway x3", [c["name"] for c in result["components"]])

    def test_scoped_destroy_exception_requires_exact_deletion_only_plan(self):
        cloud, env, cfg = self.fixture()
        cfg["operations"] = {"budget_max_monthly": 1, "block_destroy": True}
        cfg["allowed_ssh_cidrs"] = ["0.0.0.0/0"]
        def plan(actions): return {"resource_changes": [{"address": "aws_instance.x", "change": {"actions": actions}}]}
        with guardrails.allow_destroy_for(env.id):
            self.assertTrue(guardrails.enforce(cloud, env, cfg, plan=plan(["delete"]))["allowed"])
            for actions in (["delete", "create"], ["update"], ["create"]):
                with self.assertRaises(ui.Abort): guardrails.enforce(cloud, env, cfg, plan=plan(actions))
            with self.assertRaises(ui.Abort): guardrails.enforce(cloud, env, cfg)
        with self.assertRaises(ui.Abort): guardrails.enforce(cloud, env, cfg, plan=plan(["delete"]))
        with guardrails.allow_destroy_for("aws-somewhere-else"):
            with self.assertRaises(ui.Abort): guardrails.enforce(cloud, env, cfg, plan=plan(["delete"]))

    def test_expiry_cleanup_uses_saved_optin_exact_target_and_no_purge(self):
        cloud, env, cfg = self.fixture()
        cfg["operations"] = {"expires_at": "2020-01-01T00:00:00Z", "cleanup_opt_in": True}
        env.save(cfg)
        with mock.patch("cloudseed.cli.cmd_destroy", return_value=0) as destroy:
            preview = guardrails.execute("expiry-cleanup", cloud, env, cfg, {})
            self.assertFalse(preview["executed"]); destroy.assert_not_called()
            result = guardrails.execute("expiry-cleanup", cloud, env, cfg, {"approve": True})
        args = destroy.call_args[0][0]
        self.assertEqual(args.cloud, "aws")
        self.assertEqual(args.env, "review")
        self.assertFalse(args.purge); self.assertFalse(args.purge_state)
        self.assertTrue(result["executed"])
        self.assertIn("expiry-cleanup", (env.dir / "inventory.json").read_text())

    def test_expiry_cleanup_rejects_unsaved_optin_and_configuration_changes(self):
        cloud, env, cfg = self.fixture()
        cfg["operations"] = {"expires_at": "2020-01-01T00:00:00Z", "cleanup_opt_in": True}
        env.save(cfg)
        changed = copy.deepcopy(cfg); changed["operations"]["cleanup_opt_in"] = False; env.save(changed)
        with mock.patch("cloudseed.cli.cmd_destroy") as destroy:
            with self.assertRaises(ui.Abort): guardrails.execute("expiry-cleanup", cloud, env, cfg, {"approve": True})
            with self.assertRaises(ui.Abort): guardrails.execute("expiry-cleanup", cloud, env, changed, {"approve": True, "cleanup_opt_in": True})
        destroy.assert_not_called()


    def test_budget_rejects_integer_too_large_for_finite_cost_arithmetic(self):
        with self.assertRaises(ui.Abort): self.call(budget_max_monthly=10 ** 400)


    def test_live_evidence_failure_is_not_misclassified_as_unsafe_declaration(self):
        findings = [{"id": "evidence.health.cluster.certificates", "pillar": "security", "status": "FAIL", "evidence": [{"type": "saved_diagnostic", "live_verified": True}]}]
        with mock.patch("cloudseed.architecture.assess", return_value={"findings": findings}):
            report = self.call(plan={"resource_changes": []})
        self.assertTrue(report["allowed"])
        gate = next(c for c in report["checks"] if c["id"] == "security.declarations")
        self.assertEqual(gate["status"], "UNKNOWN")
