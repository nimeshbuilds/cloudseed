"""Metadata-only token accounting, safe scoped reporting and pinned native install."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from cloudseed import usage


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cloudseed-usage-test-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.patch = mock.patch.object(usage.paths, "HOME", self.home)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def message(self, mid="msg-1", **tokens):
        return {"id": mid, "model": "claude-sonnet-4-20250514", "content": [{"text": "DO-NOT-RETAIN-TRANSCRIPT"}],
                "usage": {"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 3,
                          "cache_creation_input_tokens": 2,
                          "cache_creation": {"ephemeral_5m_input_tokens": 2, "ephemeral_1h_input_tokens": 0}, **tokens}}

    def run_fixture(self, **kwargs):
        run = usage.start_run("builtin", **kwargs)
        run.observe_anthropic(self.message())
        run.finish(0)
        return run

    def test_private_atomic_metadata_without_transcripts(self):
        run = self.run_fixture()
        path = self.home / "usage/runs" / (run.id + ".json")
        data = json.loads(path.read_text())
        self.assertRegex(run.id, usage._UUID)
        self.assertNotIn("DO-NOT-RETAIN", path.read_text())
        self.assertEqual(data["usage"], {"input_tokens": 15, "output_tokens": 5, "total_tokens": 20,
            "cache_read_tokens": 3, "cache_write_tokens": 2, "reasoning_tokens": None})
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)
        self.assertEqual(data["status"], "complete")
        self.assertFalse(list(path.parent.glob("*.tmp")))

    def test_sdk_objects_and_duplicate_messages(self):
        run = usage.start_run("builtin")
        msg = self.message()
        run.observe_anthropic(SimpleNamespace(**{**msg, "usage": SimpleNamespace(**msg["usage"])}))
        run.observe_anthropic(msg)
        run.observe_anthropic(self.message("msg-2"))
        run.finish(0)
        self.assertEqual(usage.report()["summary"]["usage"]["total_tokens"], 40)

    def test_duplicate_final_message_updates_instead_of_adding(self):
        run = usage.start_run("builtin")
        run.observe_anthropic(self.message(output_tokens=1))
        run.observe_anthropic(self.message(output_tokens=8))
        run.finish(0)
        self.assertEqual(usage.report()["summary"]["usage"]["output_tokens"], 8)

    def test_missing_counts_not_zero(self):
        run = usage.start_run("builtin")
        run.observe_anthropic({"id": "msg-1", "model": "model", "usage": {"input_tokens": 10}})
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertIsNone(row["usage"]["output_tokens"])
        self.assertIsNone(row["usage"]["total_tokens"])
        self.assertEqual(row["status"], "partial")
        self.assertTrue(row["reasons"])

    def test_invalid_numbers_not_coerced(self):
        for value in (False, -1, "4", 3.5, float("nan"), 2**54):
            with self.subTest(value=value):
                run = usage.start_run("builtin")
                run.observe_anthropic(self.message(input_tokens=value))
                run.finish(0)
                self.assertIsNone(usage.report(run_id=run.id)["runs"][0]["usage"]["input_tokens"])

    def test_no_observations_unavailable_with_reason(self):
        run = usage.start_run("custom", mode="interactive")
        run.finish(0)
        row = usage.report(run_id=run.id)["runs"][0]
        self.assertEqual(row["status"], "unavailable")
        self.assertIsNone(row["usage"]["total_tokens"])
        self.assertIn("no supported", row["reasons"][0])

    def test_anonymous_exact_repeats_are_explicitly_partial(self):
        run = usage.start_run("builtin")
        msg = self.message()
        msg.pop("id")
        run.observe_anthropic(msg)
        run.observe_anthropic(msg)
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["usage"]["total_tokens"], 20)
        self.assertEqual(row["status"], "partial")

    def test_failed_run_retains_known_usage(self):
        run = usage.start_run("builtin")
        run.observe_anthropic(self.message())
        run.finish(1)
        self.assertEqual(usage.report()["runs"][0]["status"], "partial")
        self.assertEqual(usage.report()["summary"]["known_usage"]["total_tokens"], 20)

    def test_finish_is_idempotent_and_later_usage_ignored(self):
        run = self.run_fixture()
        run.finish(1)
        run.observe_anthropic(self.message("later"))
        row = usage.report()["runs"][0]
        self.assertEqual(row["exit_code"], 0)
        self.assertEqual(row["usage"]["total_tokens"], 20)

    def test_claude_authoritative_result_not_double_counted(self):
        run = usage.start_run("claude")
        run.observe_claude({"type": "assistant", "session_id": "native-1", "message": self.message()})
        run.observe_claude({"type": "result", "session_id": "native-1", "usage": self.message()["usage"], "total_cost_usd": 0.12})
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["usage"]["total_tokens"], 20)
        self.assertEqual(row["native_session_id"], "native-1")

    def test_codex_identical_turns_not_deduplicated_together(self):
        run = usage.start_run("codex", "gpt-5")
        run.observe_codex({"type": "thread.started", "thread_id": "native-codex"})
        for _ in range(2):
            run.observe_codex({"type": "turn.started"})
            event = {"type": "turn.completed", "usage": {"input_tokens": 100, "cached_input_tokens": 80,
                "output_tokens": 20, "reasoning_output_tokens": 10}}
            run.observe_codex(event)
            run.observe_codex(event)
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["usage"]["total_tokens"], 240)
        self.assertEqual(row["usage"]["cache_read_tokens"], 160)
        self.assertEqual(row["usage"]["reasoning_tokens"], 20)
        self.assertEqual(row["model_provenance"], "requested or unavailable")
        self.assertEqual(row["status"], "complete")

    def test_codex_cache_cannot_exceed_input(self):
        run = usage.start_run("codex")
        run.observe_codex({"type": "turn.completed", "id": "turn-1", "usage": {
            "input_tokens": 1, "cached_input_tokens": 2, "output_tokens": 5}})
        run.finish(0)
        self.assertIsNone(usage.report()["runs"][0]["usage"]["input_tokens"])

    def test_gemini_models_and_reasoning(self):
        run = usage.start_run("gemini")
        event = {"type": "result", "session_id": "gemini-1", "stats": {"models": {
            "gemini-2.5-pro": {"tokens": {"prompt": 100, "candidates": 30, "cached": 40, "thoughts": 20, "tool": 2}},
            "gemini-2.5-flash": {"tokens": {"prompt": 10, "candidates": 5}}}}}
        run.observe_gemini(event)
        run.observe_gemini(event)
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["usage"]["input_tokens"], 112)
        self.assertEqual(row["usage"]["output_tokens"], 55)
        self.assertEqual(row["usage"]["reasoning_tokens"], 20)
        self.assertEqual(len(row["models"]), 2)

    def test_gemini_current_stream_preserves_cached_prompt_counts(self):
        run = usage.start_run("gemini")
        run.observe_gemini({"type": "result", "status": "success", "stats": {"models": {
            "gemini-2.5-pro": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120, "cached": 60, "input": 40}}}})
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["usage"]["input_tokens"], 100)
        self.assertEqual(row["usage"]["cache_read_tokens"], 60)
        self.assertEqual(row["usage"]["output_tokens"], 20)
        self.assertEqual(row["status"], "complete")

    def test_gemini_unclassified_tokens_preserve_total_without_guessing_reasoning(self):
        run = usage.start_run("gemini")
        run.observe_gemini({"type": "result", "stats": {"models": {
            "gemini-2.5-pro": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 150, "cached": 60, "input": 40}}}})
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["usage"]["total_tokens"], 150)
        self.assertIsNone(row["usage"]["output_tokens"])
        self.assertIsNone(row["usage"]["reasoning_tokens"])
        self.assertEqual(row["status"], "partial")
        self.assertIn("omits separate reasoning/tool", " ".join(row["reasons"]))
        with mock.patch.object(usage, "ccusage_status", return_value={"installed": True}), \
             mock.patch.object(usage.subprocess, "run") as process:
            priced = usage.ccusage_report(run_id=run.id)
        process.assert_not_called()
        self.assertIsNone(priced["ccusage"]["estimated_cost_usd"])

    def test_gemini_legacy_prompt_precedes_uncached_input(self):
        run = usage.start_run("gemini")
        run.observe_gemini({"type": "result", "stats": {"models": {
            "gemini-2.5-pro": {"tokens": {"prompt": 100, "input": 40, "cached": 60, "candidates": 20}}}}})
        run.finish(0)
        self.assertEqual(usage.report()["runs"][0]["usage"]["input_tokens"], 100)

    def test_claude_model_usage_result_is_usable_without_assistant_events(self):
        run = usage.start_run("claude")
        run.observe_claude({"type": "result", "modelUsage": {"claude-sonnet-4-20250514": {
            "inputTokens": 100, "outputTokens": 20, "cacheReadInputTokens": 50, "cacheCreationInputTokens": 10}}})
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["usage"]["total_tokens"], 180)
        self.assertEqual(row["models"], ["claude-sonnet-4-20250514"])

    def test_anthropic_cache_ttl_is_preserved_for_correct_pricing(self):
        run = usage.start_run("builtin")
        run.observe_anthropic(self.message(cache_creation={"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 2}))
        run.finish(0)
        data = json.loads((self.home / "usage/runs" / (run.id + ".json")).read_text())
        exported = usage._export_event(data["events"][0], "claude")
        self.assertEqual(exported["message"]["usage"]["cache_creation"]["ephemeral_1h_input_tokens"], 2)
        self.assertEqual(data["usage"]["total_tokens"], 20)

    def test_anthropic_missing_cache_ttl_keeps_tokens_but_price_unknown(self):
        run = usage.start_run("builtin")
        msg = self.message()
        msg["usage"].pop("cache_creation")
        run.observe_anthropic(msg)
        run.finish(0)
        self.assertEqual(usage.report()["runs"][0]["status"], "complete")
        with mock.patch.object(usage, "ccusage_status", return_value={"installed": True}), \
             mock.patch.object(usage.subprocess, "run") as process:
            report = usage.ccusage_report()
        process.assert_not_called()
        self.assertIn("TTL split", " ".join(report["ccusage"]["reasons"]))

    def test_anthropic_cache_ttl_inconsistent_total_is_unknown(self):
        run = usage.start_run("builtin")
        run.observe_anthropic(self.message(cache_creation={"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 5}))
        run.finish(0)
        self.assertIsNone(usage.report()["runs"][0]["usage"]["input_tokens"])

    def test_claude_zero_exit_missing_result_is_partial(self):
        run = usage.start_run("claude")
        run.observe_claude({"type": "assistant", "message": self.message()})
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["status"], "partial")
        self.assertIn("terminal result", " ".join(row["reasons"]))

    def test_codex_open_turn_after_completed_turn_is_partial(self):
        run = usage.start_run("codex")
        run.observe_codex({"type": "turn.started"})
        run.observe_codex({"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 5}})
        run.observe_codex({"type": "turn.started"})
        run.finish(0)
        self.assertEqual(usage.report()["runs"][0]["status"], "partial")

    def test_gemini_init_without_result_is_unavailable_with_specific_reason(self):
        run = usage.start_run("gemini")
        run.observe_gemini({"type": "init", "session_id": "gemini-test", "model": "gemini-2.5-pro"})
        run.finish(0)
        row = usage.report()["runs"][0]
        self.assertEqual(row["status"], "unavailable")
        self.assertIn("Gemini", " ".join(row["reasons"]))

    def test_event_limit_is_reported(self):
        run = usage.start_run("builtin")
        with mock.patch.object(usage, "MAX_EVENTS", 2):
            for i in range(3):
                run.observe_anthropic(self.message("msg-" + str(i)))
        run.finish(0)
        self.assertEqual(usage.report()["runs"][0]["status"], "partial")
        self.assertEqual(usage.report()["summary"]["known_usage"]["total_tokens"], 40)

    def test_mcp_activity_never_invents_tokens(self):
        usage.record_mcp("cloudseed_evidence", 12.5, True, 400, "claude")
        report = usage.report()
        self.assertEqual(report["mcp"]["call_count"], 1)
        self.assertIsNone(report["mcp"]["model_tokens"])
        self.assertIn("host model", report["mcp"]["reason"])
        self.assertIsNone(report["summary"]["usage"]["total_tokens"])

    def test_report_filters_and_combined_pagination(self):
        expected = set()
        for _ in range(3):
            expected.add(self.run_fixture().id)
            usage.record_mcp("cloudseed_list", 1, True, 5)
        offset, ids = 0, []
        while True:
            page = usage.report(limit=2, offset=offset)
            ids.extend(r["id"] for r in page["runs"] + page["mcp"]["calls"])
            self.assertEqual(page["coverage"]["total_records"], 6)
            offset = page["coverage"]["next_offset"]
            if offset is None:
                break
        self.assertEqual(len(set(ids)), 6)
        self.assertTrue(expected.issubset(ids))
        self.assertEqual(usage.report(agent="builtin")["mcp"]["call_count"], 0)
        self.assertEqual(usage.report(run_id=next(iter(expected)))["summary"]["run_count"], 1)

    def test_unknown_aggregate_separate_known_sum(self):
        self.run_fixture()
        run = usage.start_run("custom")
        run.finish(0)
        summary = usage.report()["summary"]
        self.assertIsNone(summary["usage"]["total_tokens"])
        self.assertEqual(summary["known_usage"]["total_tokens"], 20)

    def test_report_does_not_expose_extra_file_fields(self):
        run = self.run_fixture()
        path = self.home / "usage/runs" / (run.id + ".json")
        data = json.loads(path.read_text())
        data["prompt"] = "UNEXPECTED-SECRET-TEXT"
        path.write_text(json.dumps(data))
        self.assertNotIn("UNEXPECTED-SECRET", json.dumps(usage.report()))
        self.assertNotIn('"events"', json.dumps(usage.report()))

    def test_malformed_record_is_explicit(self):
        run = self.run_fixture()
        (self.home / "usage/runs" / (run.id + ".json")).write_text('{"bad":NaN}')
        report = usage.report(run_id=run.id)
        self.assertEqual(report["summary"]["run_count"], 0)
        self.assertTrue(report["coverage"]["reasons"])

    def test_rejects_traversal_and_bad_limits(self):
        for kwargs in ({"run_id": "../../credentials"}, {"limit": True}, {"limit": 0}, {"limit": 1001}, {"offset": -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                usage.report(**kwargs)

    def test_symlink_storage_refused(self):
        outside = self.home / "outside"
        outside.mkdir()
        (self.home / "usage").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            usage.start_run("builtin")
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlink_run_refused(self):
        run = self.run_fixture()
        path = self.home / "usage/runs" / (run.id + ".json")
        target = self.home / "private"
        path.replace(target)
        path.symlink_to(target)
        report = usage.report(run_id=run.id)
        self.assertFalse(report["runs"])
        self.assertIn("unsafe", " ".join(report["coverage"]["reasons"]))

    def test_ccusage_missing_never_installs_implicitly(self):
        with mock.patch.object(usage, "install_ccusage") as install:
            with self.assertRaisesRegex(ValueError, "cs usage install"):
                usage.ccusage_report()
            install.assert_not_called()

    def archive(self, payload=b"native", symlink=False):
        blob = io.BytesIO()
        with tarfile.open(fileobj=blob, mode="w:gz") as archive:
            item = tarfile.TarInfo("package/bin/ccusage")
            if symlink:
                item.type, item.linkname = tarfile.SYMTYPE, "/private/other"
                archive.addfile(item)
            else:
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
        return blob.getvalue()

    def test_install_requires_pinned_integrity(self):
        with mock.patch.object(usage, "_platform_key", return_value="darwin-arm64"), \
             mock.patch.object(usage.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong")):
            with self.assertRaisesRegex(ValueError, "SHA-512"):
                usage.install_ccusage()
        self.assertFalse((self.home / "usage/tools/ccusage").exists())

    def test_install_extracts_only_verified_binary_and_detects_tampering(self):
        blob = self.archive()
        integrity = base64.b64encode(hashlib.sha512(blob).digest()).decode()
        with mock.patch.object(usage, "_platform_key", return_value="darwin-arm64"), \
             mock.patch.dict(usage._INTEGRITY, {"darwin-arm64": integrity}), \
             mock.patch.object(usage.urllib.request, "urlopen", return_value=io.BytesIO(blob)):
            result = usage.install_ccusage()
            self.assertEqual(result["version"], "20.0.24")
            self.assertTrue(usage.ccusage_status()["installed"])
            Path(result["path"]).write_bytes(b"changed")
            self.assertFalse(usage.ccusage_status()["installed"])

    def test_install_rejects_link_even_with_matching_archive_hash(self):
        blob = self.archive(symlink=True)
        integrity = base64.b64encode(hashlib.sha512(blob).digest()).decode()
        with mock.patch.object(usage, "_platform_key", return_value="darwin-arm64"), \
             mock.patch.dict(usage._INTEGRITY, {"darwin-arm64": integrity}), \
             mock.patch.object(usage.urllib.request, "urlopen", return_value=io.BytesIO(blob)):
            with self.assertRaisesRegex(ValueError, "safe native binary"):
                usage.install_ccusage()

    def test_ccusage_exports_only_scoped_metadata_and_retains_ledger_shape(self):
        selected = self.run_fixture()
        self.run_fixture()
        observed = []
        def run(command, **kwargs):
            env = kwargs["env"]
            self.assertEqual(env["HOME"], str(kwargs["cwd"]))
            self.assertNotIn("ANTHROPIC_API_KEY", env)
            self.assertIn("--offline", command)
            self.assertIn("--config", command)
            files = list(Path(env["CLAUDE_CONFIG_DIR"]).rglob("*.jsonl"))
            self.assertEqual(len(files), 1)
            text = files[0].read_text()
            self.assertIn(selected.id, text)
            self.assertNotIn("DO-NOT-RETAIN", text)
            observed.append(files[0])
            kwargs["stdout"].write(json.dumps({"sessions": [{"sessionId": selected.id, "totalCost": .1}], "totals": {"totalCost": .1, "totalTokens": 20}}).encode())
            return SimpleNamespace(returncode=0)
        with mock.patch.object(usage, "ccusage_status", return_value={"installed": True}), \
             mock.patch.object(usage.subprocess, "run", side_effect=run):
            result = usage.ccusage_report(run_id=selected.id)
        self.assertEqual(result["summary"]["run_count"], 1)
        self.assertEqual(result["ccusage"]["estimated_cost_usd"], .1)
        self.assertIn("not actual billing", result["ccusage"]["basis"])
        self.assertFalse(observed[0].exists())

    def test_ccusage_unpriced_model_is_unknown_not_free(self):
        selected = self.run_fixture()
        def run(command, **kwargs):
            kwargs["stdout"].write(json.dumps({"sessions": [], "totals": {"totalCost": 0, "unpricedModels": ["new-model"]}}).encode())
            return SimpleNamespace(returncode=0)
        with mock.patch.object(usage, "ccusage_status", return_value={"installed": True}), \
             mock.patch.object(usage.subprocess, "run", side_effect=run):
            result = usage.ccusage_report(run_id=selected.id)
        self.assertIsNone(result["ccusage"]["estimated_cost_usd"])
        self.assertEqual(result["ccusage"]["unpriced_models"], ["new-model"])

    def test_ccusage_refuses_to_price_requested_codex_model_as_observed(self):
        run = usage.start_run("codex", "gpt-5")
        run.observe_codex({"type": "turn.started"})
        run.observe_codex({"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 2}})
        run.finish(0)
        with mock.patch.object(usage, "ccusage_status", return_value={"installed": True}), \
             mock.patch.object(usage.subprocess, "run") as process:
            report = usage.ccusage_report(run_id=run.id)
        process.assert_not_called()
        self.assertIsNone(report["ccusage"]["estimated_cost_usd"])
        self.assertTrue(report["ccusage"]["reasons"])

    def test_ccusage_aggregate_mismatch_not_priced_as_complete(self):
        run = usage.start_run("claude")
        run.observe_claude({"type": "assistant", "message": self.message()})
        run.observe_claude({"type": "result", "usage": {"input_tokens": 100, "output_tokens": 200}})
        run.finish(0)
        with mock.patch.object(usage, "ccusage_status", return_value={"installed": True}), \
             mock.patch.object(usage.subprocess, "run") as process:
            report = usage.ccusage_report(run_id=run.id)
        process.assert_not_called()
        self.assertEqual(report["summary"]["usage"]["total_tokens"], 300)
        self.assertIsNone(report["ccusage"]["estimated_cost_usd"])

    def test_malformed_nested_metadata_never_crashes_report(self):
        run = self.run_fixture()
        path = self.home / "usage/runs" / (run.id + ".json")
        original = json.loads(path.read_text())
        for field, bad in (("events", [None]), ("models", 5), ("reasons", {}), ("usage", {"input_tokens": True})):
            with self.subTest(field=field):
                path.write_text(json.dumps({**original, field: bad}))
                result = usage.report()
                self.assertFalse(result["runs"])
                self.assertIn("malformed", " ".join(result["coverage"]["reasons"]))

    def test_large_metadata_paginates_below_mcp_pretty_json_budget(self):
        for _ in range(8):
            run = self.run_fixture()
            path = self.home / "usage/runs" / (run.id + ".json")
            data = json.loads(path.read_text())
            data["reasons"] = [str(i) + " valid reason" * 40 for i in range(20)]
            path.write_text(json.dumps(data))
        page = usage.report(limit=50)
        self.assertLess(len(json.dumps(page, indent=2).encode()), 64000)
        self.assertIsNotNone(page["coverage"]["next_offset"])
        self.assertLess(page["coverage"]["returned_records"], 8)

    def test_ccusage_timeout_is_actionable_and_native_report_survives(self):
        self.run_fixture()
        with mock.patch.object(usage, "ccusage_status", return_value={"installed": True}), \
             mock.patch.object(usage.subprocess, "run", side_effect=subprocess.TimeoutExpired("ccusage", 30)):
            with self.assertRaisesRegex(ValueError, "30-second"):
                usage.ccusage_report()
        self.assertEqual(usage.report()["summary"]["run_count"], 1)

    def test_ccusage_empty_engine_rows_cannot_claim_free_complete_usage(self):
        self.run_fixture()
        def run(command, **kwargs):
            kwargs["stdout"].write(b'{"sessions":[],"totals":{"totalCost":0,"totalTokens":0}}')
            return SimpleNamespace(returncode=0)
        with mock.patch.object(usage, "ccusage_status", return_value={"installed": True}), \
             mock.patch.object(usage.subprocess, "run", side_effect=run):
            result = usage.ccusage_report()
        self.assertIsNone(result["ccusage"]["estimated_cost_usd"])
        self.assertIn("every exported token", " ".join(result["ccusage"]["reasons"]))

    def test_usage_revision_tracks_events_even_when_totals_unchanged(self):
        run = self.run_fixture()
        first = usage.report()["runs"][0]["revision"]
        path = self.home / "usage/runs" / (run.id + ".json")
        data = json.loads(path.read_text())
        data["events"][0]["model"] = "different-model"
        path.write_text(json.dumps(data))
        self.assertNotEqual(first, usage.report()["runs"][0]["revision"])


if __name__ == "__main__":
    unittest.main()
