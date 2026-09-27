"""Private, metadata-only accounting for Cloudseed-started agent runs and MCP calls.

Provider tokens are evidence, not an invoice. Input includes cache subsets;
output includes reasoning. Missing fields stay null. No transcript is retained.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import os
import platform
import re
import stat
import subprocess
import tarfile
import tempfile
import threading
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import netutil, paths

VERSION = "20.0.24"
MAX_EVENTS = 512
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 5000
TOKEN_KEYS = ("input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens", "reasoning_tokens")
MCP_REASON = "MCP exposes Cloudseed tool activity, not the host model's token usage or billing."
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+\-]{0,191}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
# Reviewed npm platform archives, pinned independently of mutable registry metadata.
_INTEGRITY = {
    "darwin-arm64": "jdJP78y2SYRSoGcakANRYeqAbwG2FBw5dzyb6bakIM3S08G2LNrBFQVbsQvNB/f2OXbUtQpJzofHJvoDIyVW1Q==",
    "darwin-x64": "iCko1HCk7fVLrs7TYyztMUv9Ze6iQDp6IhyeIzNfh9QJUUssxoNh9t7AkUgZL0EkiRbBBdsBrdYrAZ2WmkHpkQ==",
    "linux-arm64": "P3tkw7vIv78MKx9Xycqt6RE+cBv4wpZbmWFP81w5MYngYB9s1c8RqS24F/6a+B439WXLQ2051bqAqh96hTe0lw==",
    "linux-x64": "ydXM6AEUTO/T5dZK04GFGy6ePYBOjv3euQmJt0mDNg+/8SJDLWpg5GCtF9pnBrRR2GVA6b4PGouHe+ObLokBIw==",
    "win32-arm64": "BDPgaqNPSlVM2dHGJRW1uRj53AOK1C+ih/1Ik5vUC8TOzr4t2Glb9abtnt0Jq0lUyr8qTQ5k0ow6p6LQyUa9AQ==",
    "win32-x64": "Pxb7rcHEoB4EByJKRQBaoPJcIvXxeRZZDK8aSHvX4Ah3VmuKJJoGGGqZ5pKnYuBTSmrpBo2EzRQ7fCGiFcv5+g==",
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _get(value, key, default=None):
    return value.get(key, default) if isinstance(value, dict) else getattr(value, key, default)


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        return None
    if value.startswith(("sk-", "AIza", "ghp_", "gho_", "AKIA", "ASIA")):
        return None
    return value


def _reason(value):
    from . import audit, secrets
    return audit.scrub_auth(secrets.redact(str(value))).replace("\x00", "")[:500]


def _client(value):
    if not isinstance(value, str) or len(value) > 80 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. ()+\-]*", value):
        return None
    return value if _reason(value) == value and not value.startswith(("sk-", "AIza", "ghp_", "AKIA", "ASIA")) else None


def _number(value):
    return value if type(value) is int and 0 <= value <= 2**53 - 1 else None


def _add(*values):
    return sum(values) if all(v is not None for v in values) else None


def _empty():
    return {k: None for k in TOKEN_KEYS}


def _normalize(raw, kind):
    """Only absent optional subsets of an actual usage record may default to zero."""
    if raw is None:
        return _empty()
    inp = _number(_get(raw, "input_tokens"))
    out = _number(_get(raw, "output_tokens"))
    if kind == "anthropic":
        read = _number(_get(raw, "cache_read_input_tokens", 0))
        write = _number(_get(raw, "cache_creation_input_tokens", 0))
        creation = _get(raw, "cache_creation")
        if creation is not None:
            split_write = _add(_number(_get(creation, "ephemeral_5m_input_tokens", 0)),
                               _number(_get(creation, "ephemeral_1h_input_tokens", 0)))
            write = split_write if _get(raw, "cache_creation_input_tokens") is None else write if split_write == write else None
        inp = _add(inp, read, write)
        reasoning = None  # Anthropic does not expose a separate reasoning-token counter.
    else:
        read = _number(_get(raw, "cached_input_tokens", 0))
        write = _number(_get(raw, "cache_write_input_tokens", 0))
        reasoning = _number(_get(raw, "reasoning_output_tokens"))
    if inp is not None and any(v is not None and v > inp for v in (read, write)):
        inp = None
    if inp is not None and read is not None and write is not None and read + write > inp:
        inp = None
    if out is not None and reasoning is not None and reasoning > out:
        out = None
    return dict(zip(TOKEN_KEYS, (inp, out, _add(inp, out), read, write, reasoning)))


def _sum(events):
    if not events:
        return _empty()
    return {k: _add(*(e["usage"].get(k) for e in events)) for k in TOKEN_KEYS}


def _directory(area=None, create=False):
    root = paths.HOME / "usage"
    for directory in ([root] if area is None else [root, root / area]):
        if create:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink():
            raise ValueError("Usage storage must not be a symbolic link")
        if directory.exists():
            mode = directory.stat()
            if not stat.S_ISDIR(mode.st_mode):
                raise ValueError("Usage storage must be a directory")
            if hasattr(os, "getuid") and mode.st_uid != os.getuid():
                raise ValueError("Usage storage must belong to the current user")
            if create:
                directory.chmod(0o700)
    return root if area is None else root / area


def _write(area, name, data):
    dest = _directory(area, True) / name
    if dest.is_symlink():
        raise ValueError("Usage files must not be symbolic links")
    text = json.dumps(data, allow_nan=False, separators=(",", ":"))
    if len(text.encode()) > MAX_FILE_BYTES:
        raise ValueError("Usage metadata exceeds its bounded file limit")
    paths.atomic_write(dest, text, mode=0o600)


def _read(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as fh:
        info = os.fstat(fh.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES or path.is_symlink():
            raise ValueError("Unsafe or oversized usage metadata")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ValueError("Usage metadata belongs to another user")
        try:
            return json.loads(fh.read(MAX_FILE_BYTES + 1), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite metadata")))
        except RecursionError as error:
            raise ValueError("Usage metadata is nested too deeply") from error


class UsageRun:
    def __init__(self, agent, model=None, mode="exec"):
        if not _identifier(agent) or mode not in ("exec", "interactive", "builtin"):
            raise ValueError("Invalid usage agent or mode")
        self.id = str(uuid.uuid4())
        self._lock = threading.RLock()
        self._finished = False
        self._events = {}
        self._aggregate = None
        self._codex_turn = 0
        self._external_source = None
        self._terminal = False
        self._data = {"schema_version": 1, "id": self.id, "agent": agent, "model": _identifier(model), "mode": mode,
                      "started_at": _now(), "finished_at": None, "exit_code": None, "status": "running",
                      "native_session_id": None, "usage": _empty(), "models": [], "reasons": [], "events": []}
        self._save()

    def _save(self):
        self._data["events"] = list(self._events.values())
        self._data["usage"] = self._aggregate or _sum(self._data["events"])
        models = sorted({e["model"] for e in self._events.values() if e.get("model")})
        self._data["models"] = models[:64]
        self._data["model_names_omitted"] = max(0, len(models) - 64)
        _write("runs", self.id + ".json", self._data)

    def unavailable(self, reason):
        with self._lock:
            message = _reason(reason)
            if message not in self._data["reasons"] and len(self._data["reasons"]) < 20:
                self._data["reasons"].append(message)
            self._save()

    def _observe(self, source, raw, model, event_id=None, kind="anthropic", normalized=None, model_verified=True):
        if self._finished:
            return
        usage = normalized or _normalize(raw, kind)
        event_id = _identifier(event_id)
        if event_id is None:
            # An exact repeat without an ID cannot safely be added twice.
            event_id = "anonymous-" + hashlib.sha256(json.dumps([source, _identifier(model), usage], sort_keys=True).encode()).hexdigest()
            self.unavailable("A usage event lacks a provider request/message ID; exact repeated records are deduplicated, so totals may be partial.")
        key = source + ":" + event_id
        if key not in self._events and len(self._events) >= MAX_EVENTS:
            self.unavailable("The 512-event metadata limit was reached; later per-event usage was not retained.")
            return
        if usage["input_tokens"] is None or usage["output_tokens"] is None:
            self.unavailable("The provider usage record has missing or invalid input/output token counts.")
        previous = self._events.get(key)
        self._events[key] = {"id": event_id, "source": source, "model": _identifier(model), "model_verified": model_verified,
                             "timestamp": previous["timestamp"] if previous else _now(), "usage": usage}
        creation = _get(raw, "cache_creation")
        if kind == "anthropic" and creation is not None:
            self._events[key]["cache_creation"] = {k: _number(_get(creation, k, 0)) for k in
                                                   ("ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens")}
        self._save()

    def observe_anthropic(self, message):
        with self._lock:
            self._observe("anthropic", _get(message, "usage"), _get(message, "model"), _get(message, "id"))

    def observe_claude(self, event):
        with self._lock:
            if self._finished or not isinstance(event, dict):
                return
            self._external_source = "Claude"
            sid = _identifier(event.get("session_id"))
            if sid:
                self._data["native_session_id"] = sid
            if event.get("type") == "assistant" and event.get("message") is not None:
                self.observe_anthropic(event["message"])
            elif event.get("type") == "result":
                self._terminal = True
                model_usage = event.get("modelUsage")
                if not self._events and isinstance(model_usage, dict):
                    if len(model_usage) > 64:
                        self.unavailable("Claude returned more than 64 model usage entries; per-model accounting was bounded.")
                    for model, raw in list(model_usage.items())[:64]:
                        if isinstance(raw, dict) and _identifier(model):
                            self._observe("claude-result", {"input_tokens": raw.get("inputTokens"), "output_tokens": raw.get("outputTokens"),
                                "cache_read_input_tokens": raw.get("cacheReadInputTokens", 0),
                                "cache_creation_input_tokens": raw.get("cacheCreationInputTokens", 0)}, model, "result-" + model)
                if isinstance(event.get("usage"), dict):
                    self._aggregate = _normalize(event["usage"], "anthropic")
                estimate = event.get("total_cost_usd")
                if type(estimate) in (int, float) and math.isfinite(estimate) and estimate >= 0:
                    self._data["provider_estimated_cost_usd"] = estimate
                    self._data["cost_basis"] = "API-equivalent estimate; not subscription billing or an invoice"
                if event.get("is_error"):
                    self.unavailable("Claude reported an unsuccessful result; usage may exclude failed requests.")
            self._save()

    def observe_codex(self, event):
        with self._lock:
            if self._finished or not isinstance(event, dict):
                return
            self._external_source = "Codex"
            if event.get("type") == "thread.started":
                self._data["native_session_id"] = _identifier(event.get("thread_id"))
            if event.get("type") == "turn.started":
                self._codex_turn += 1
                self._terminal = False
            if event.get("type") == "turn.completed":
                self._terminal = True
                self._observe("codex", event.get("usage"), event.get("model") or self._data["model"],
                              event.get("turn_id") or event.get("id") or (f"turn-{self._codex_turn}" if self._codex_turn else None),
                              kind="codex", model_verified=bool(_identifier(event.get("model"))))
            if event.get("type") in ("turn.failed", "error"):
                self.unavailable("Codex reported a failed turn or stream error; usage may exclude failed requests.")
            self._save()

    def observe_gemini(self, event):
        with self._lock:
            if self._finished or not isinstance(event, dict):
                return
            self._external_source = "Gemini"
            if event.get("type") == "result":
                self._terminal = True
            sid = _identifier(event.get("session_id") or event.get("sessionId"))
            if sid:
                self._data["native_session_id"] = sid
            if event.get("type") == "init" and _identifier(event.get("model")):
                self._data["model"] = event["model"]
            stats = event.get("stats")
            if isinstance(stats, dict):
                models = stats.get("models")
                if isinstance(models, dict):
                    if len(models) > 64:
                        self.unavailable("Gemini returned more than 64 model usage entries; later models were not counted.")
                    for model, details in list(models.items())[:64]:
                        if not _identifier(model) or not isinstance(details, dict):
                            self.unavailable("Gemini returned invalid per-model usage metadata.")
                            continue
                        if "input_tokens" in details or "output_tokens" in details:
                            normalized = self._gemini_stream(details)
                            self._observe("gemini", None, model, "result-" + model, normalized=normalized)
                            continue
                        raw = details.get("tokens") if isinstance(details, dict) else None
                        if not isinstance(raw, dict):
                            self.unavailable("Gemini's per-model statistics lack supported token counters.")
                            continue
                        inp = _number(raw.get("prompt", raw.get("input")))
                        out = _number(raw.get("candidates", raw.get("output")))
                        thoughts = _number(raw.get("thoughts", 0))
                        tool = _number(raw.get("tool", 0))
                        normalized = {"input_tokens": _add(inp, tool), "output_tokens": _add(out, thoughts),
                                      "cache_read_tokens": _number(raw.get("cached", 0)), "cache_write_tokens": 0,
                                      "reasoning_tokens": thoughts, "total_tokens": _add(inp, tool, out, thoughts)}
                        self._observe("gemini", None, model, "result-" + model, normalized=normalized)
                    if not models and all(_number(stats.get(k)) == 0 for k in ("input_tokens", "output_tokens", "total_tokens")):
                        self._aggregate = self._gemini_stream(stats)
                else:
                    if "input_tokens" in stats or "output_tokens" in stats:
                        self._aggregate = self._gemini_stream(stats)
                    self.unavailable("Gemini's result lacks per-model token statistics; model attribution and cost are unavailable.")
            if event.get("type") == "result" and event.get("status") == "error":
                self.unavailable("Gemini reported an unsuccessful result; usage may exclude failed requests.")
            self._save()

    def _gemini_stream(self, raw):
        # Gemini's stream formatter exposes candidates only as output_tokens;
        # total_tokens may additionally include thoughts and tool-prompt tokens.
        inp, candidates, total = (_number(raw.get(k)) for k in ("input_tokens", "output_tokens", "total_tokens"))
        read = _number(raw.get("cached", 0))
        reasoning = 0 if total is not None and total == _add(inp, candidates) else None
        out = candidates if reasoning == 0 else None
        if total is not None and inp is not None and candidates is not None and total > inp + candidates:
            self.unavailable(f"Gemini reports {total} total tokens, {inp} prompt tokens and {candidates} candidate-output tokens, "
                             "but omits separate reasoning/tool counters; the full output breakdown and cost are unavailable.")
        elif reasoning is None:
            self.unavailable("Gemini's stream has missing or inconsistent total/input/output counters; the output breakdown is unavailable.")
        if inp is not None and read is not None and read > inp:
            inp = None
        return {"input_tokens": inp, "output_tokens": out, "total_tokens": total,
                "cache_read_tokens": read, "cache_write_tokens": 0, "reasoning_tokens": reasoning}

    def finish(self, exit_code):
        with self._lock:
            if self._finished:
                return
            if type(exit_code) is not int:
                raise ValueError("exit_code must be an integer")
            self._data["finished_at"] = _now()
            self._data["exit_code"] = exit_code
            if self._external_source and not self._terminal:
                self.unavailable(self._external_source + "'s stream ended without its terminal result/completed-turn event; usage may be partial.")
            if exit_code != 0:
                self.unavailable("The agent did not finish successfully; usage recorded before failure may be partial.")
            self._save()
            counts = self._data["usage"]
            if counts["input_tokens"] is None and counts["output_tokens"] is None:
                if not self._data["reasons"]:
                    self._data["reasons"].append("The agent returned no supported token-usage records.")
                self._data["status"] = "unavailable"
            elif self._data["reasons"] or counts["total_tokens"] is None:
                self._data["status"] = "partial"
            else:
                self._data["status"] = "complete"
            self._finished = True
            self._save()


def start_run(agent, model=None, mode="exec"):
    return UsageRun(agent, model, mode)


def record_mcp(tool, duration_ms, success, response_bytes, client=None):
    if not _identifier(tool) or type(success) is not bool or _number(response_bytes) is None:
        raise ValueError("Invalid MCP activity metadata")
    if type(duration_ms) not in (int, float) or not math.isfinite(duration_ms) or not 0 <= duration_ms <= 86400000:
        raise ValueError("Invalid MCP duration")
    data = {"schema_version": 1, "id": str(uuid.uuid4()), "timestamp": _now(), "tool": tool,
            "duration_ms": round(duration_ms, 3), "success": success, "response_bytes": response_bytes,
            "client": _client(client), "model_tokens": None, "reason": MCP_REASON}
    _write("mcp", data["id"] + ".json", data)


def _arguments(limit, run_id, agent, offset=0):
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer from 1 to 1000")
    if type(offset) is not int or not 0 <= offset <= 1000000:
        raise ValueError("offset must be an integer from 0 to 1000000")
    if run_id is not None and (not isinstance(run_id, str) or not _UUID.fullmatch(run_id)):
        raise ValueError("run_id must be a Cloudseed run UUID")
    if agent is not None and not _identifier(agent):
        raise ValueError("Invalid agent filter")


def _validate_run(data):
    def counters(value):
        return isinstance(value, dict) and all(value.get(k) is None or _number(value[k]) is not None for k in TOKEN_KEYS)
    if not counters(data.get("usage")) or not isinstance(data.get("events"), list) or len(data["events"]) > MAX_EVENTS:
        raise ValueError("Invalid run usage counters or events")
    for field, bound in (("models", 64), ("reasons", 20)):
        values = data.get(field)
        if not isinstance(values, list) or len(values) > bound or any(not isinstance(v, str) for v in values):
            raise ValueError("Invalid run model/reason metadata")
    if not _identifier(data.get("agent")):
        raise ValueError("Invalid run agent")
    for event in data["events"]:
        if not isinstance(event, dict) or not counters(event.get("usage")) or not _identifier(event.get("id")):
            raise ValueError("Invalid per-event usage metadata")
        if not isinstance(event.get("timestamp"), str) or len(event["timestamp"]) > 40:
            raise ValueError("Invalid usage event timestamp")


def _revision(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _records(area, limit, run_id=None, agent=None):
    root = _directory(area)
    if not root.exists():
        return [], []
    warnings = []
    if run_id is not None:
        candidates = [root / (run_id + ".json")]
    else:
        candidates = []
        with os.scandir(root) as entries:
            for scanned, entry in enumerate(entries):
                if scanned >= MAX_FILES:
                    warnings.append("Usage discovery reached the 5000-file limit; the listing is incomplete.")
                    break
                if entry.name.endswith(".json") and _UUID.fullmatch(entry.name[:-5]) and entry.is_file(follow_symlinks=False):
                    candidates.append(Path(entry.path))
        def modified(path):
            try:
                return path.lstat().st_mtime_ns
            except OSError:
                return 0
        candidates.sort(key=modified, reverse=True)
    result = []
    budget = 16 * 1024 * 1024
    for path in candidates:
        if len(result) >= limit:
            warnings.append("The selected usage limit was reached; increase --limit or select a run.")
            break
        try:
            size = path.lstat().st_size
            budget -= size
            if budget < 0:
                warnings.append("Usage discovery reached its 16 MiB metadata budget; the listing is incomplete.")
                break
            data = _read(path)
            if not isinstance(data, dict) or data.get("schema_version") != 1 or data.get("id") != path.stem:
                raise ValueError("Invalid usage record")
            if agent is not None and data.get("agent") != agent:
                continue
            if area == "runs":
                _validate_run(data)
            result.append(data)
        except (OSError, ValueError, UnicodeError):
            warnings.append("A selected usage record was unavailable, unsafe or malformed; it was not included.")
    return result, list(dict.fromkeys(warnings))


def _public_run(r):
    return {"schema_version": 1, "id": r["id"], "agent": _identifier(r.get("agent")), "model": _identifier(r.get("model")),
            "mode": r.get("mode") if r.get("mode") in ("exec", "interactive", "builtin") else "unknown",
            "started_at": str(r.get("started_at", ""))[:40], "finished_at": str(r["finished_at"])[:40] if r.get("finished_at") else None,
            "exit_code": r.get("exit_code") if type(r.get("exit_code")) is int else None,
            "status": r.get("status") if r.get("status") in ("running", "complete", "partial", "unavailable") else "unavailable",
            "native_session_id": _identifier(r.get("native_session_id")),
            "usage": {k: _number(r["usage"].get(k)) for k in TOKEN_KEYS},
            "models": [_identifier(m) for m in (r.get("models") or [])[:64] if _identifier(m)],
            "model_names_omitted": _number(r.get("model_names_omitted", 0)),
            "model_provenance": "provider" if r.get("events") and all(e.get("model_verified", True) for e in r["events"]) else "requested or unavailable",
            "revision": _revision(r),
            "reasons": [_reason(s) for s in (r.get("reasons") or [])[:20] if isinstance(s, str)]}


def _page(limit, run_id, agent, offset):
    runs, reasons = _records("runs", MAX_FILES, run_id, agent)
    calls, mcp_reasons = _records("mcp", MAX_FILES) if run_id is None and agent is None else ([], [])
    rows = [(r.get("started_at", ""), "run", r) for r in runs] + [(r.get("timestamp", ""), "mcp", r) for r in calls]
    rows.sort(key=lambda item: (str(item[0]), item[2]["id"]), reverse=True)
    selected, cost = [], 0
    for row in rows[offset:offset + limit]:
        visible = _public_run(row[2]) if row[1] == "run" else _public_mcp(row[2])
        size = len(json.dumps(visible, ensure_ascii=True, indent=2).encode()) + 1000
        if selected and cost + size > 40000:
            break
        selected.append(row)
        cost += size
    return selected, len(rows), reasons, mcp_reasons


def _public_mcp(r):
    return {"id": r["id"], "timestamp": str(r.get("timestamp", ""))[:40], "tool": _identifier(r.get("tool")),
            "client": _client(r.get("client")), "success": r.get("success") if type(r.get("success")) is bool else None,
            "duration_ms": r.get("duration_ms") if type(r.get("duration_ms")) in (int, float) and math.isfinite(r["duration_ms"]) else None,
            "response_bytes": _number(r.get("response_bytes")), "model_tokens": None, "reason": MCP_REASON}


def report(limit=100, run_id=None, agent=None, offset=0):
    _arguments(limit, run_id, agent, offset)
    rows, count, reasons, mcp_reasons = _page(limit, run_id, agent, offset)
    public = [_public_run(r) for _, kind, r in rows if kind == "run"]
    calls = [_public_mcp(r) for _, kind, r in rows if kind == "mcp"]
    runs = public
    total = {k: _add(*(_number(r["usage"].get(k)) for r in runs)) if runs else None for k in TOKEN_KEYS}
    known = {k: sum(_number(r["usage"].get(k)) or 0 for r in runs) for k in TOKEN_KEYS}
    gaps = [r["id"] for r in runs if r.get("status") != "complete"]
    coverage = {"status": "partial" if reasons or mcp_reasons or gaps else "complete" if runs or calls else "unavailable",
                "reasons": reasons + mcp_reasons + (["Some selected agent runs have unavailable, partial or still-running usage."] if gaps else []),
                "run_listing_truncated": bool(reasons), "mcp_listing_truncated": bool(mcp_reasons),
                "offset": offset, "returned_records": len(rows), "total_records": count,
                "next_offset": offset + len(rows) if offset + len(rows) < count else None,
                "pagination_scope": "One chronological sequence of agent runs and MCP calls; totals cover this page only."}
    if not runs and not calls:
        coverage["reasons"].append("No matching Cloudseed usage has been recorded; earlier sessions were not tracked.")
    return {"schema_version": 1, "generated_at": _now(), "scope": "Only recorded Cloudseed-started agent runs and Cloudseed MCP tool activity; totals cover the selected records.",
            "runs": public, "summary": {"run_count": len(runs), "usage": total, "known_usage": known},
            "mcp": {"calls": calls, "call_count": len(calls), "model_tokens": None, "reason": MCP_REASON},
            "coverage": coverage, "ccusage": ccusage_status()}


def _platform_key():
    system = {"Darwin": "darwin", "Linux": "linux", "Windows": "win32"}.get(platform.system())
    machine = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(platform.machine().lower())
    key = f"{system}-{machine}"
    if key not in _INTEGRITY:
        raise ValueError("ccusage is not supported on this operating system/architecture")
    return key


def _binary():
    return _directory("tools") / ("ccusage.exe" if platform.system() == "Windows" else "ccusage")


def ccusage_status():
    try:
        binary = _binary()
        meta = _read(binary.with_name("ccusage-install.json"))
        if binary.is_symlink() or not binary.is_file() or binary.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("Invalid ccusage binary")
        if meta.get("version") != VERSION or meta.get("platform") != _platform_key():
            raise ValueError("Incompatible ccusage installation")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != meta.get("sha256"):
            raise ValueError("ccusage integrity check failed")
        return {"installed": True, "version": VERSION, "reason": None}
    except (OSError, ValueError, AttributeError):
        return {"installed": False, "version": VERSION, "reason": "Pinned ccusage is missing or failed its integrity check; run cs usage install."}


def install_ccusage():
    key = _platform_key()
    url = f"https://registry.npmjs.org/@ccusage/ccusage-{key}/-/ccusage-{key}-{VERSION}.tgz"
    request = urllib.request.Request(url, headers={"User-Agent": "cloudseed-usage"})
    with urllib.request.urlopen(request, timeout=60, context=netutil.https_context()) as response:
        blob = response.read(32 * 1024 * 1024 + 1)
    if len(blob) > 32 * 1024 * 1024 or base64.b64encode(hashlib.sha512(blob).digest()).decode() != _INTEGRITY[key]:
        raise ValueError("ccusage archive did not match the reviewed SHA-512 integrity value")
    member_name = "package/bin/ccusage.exe" if key.startswith("win32") else "package/bin/ccusage"
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        matches = [m for m in archive.getmembers() if m.name == member_name]
        if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= 32 * 1024 * 1024:
            raise ValueError("ccusage archive lacks a safe native binary")
        stream = archive.extractfile(matches[0])
        binary_data = stream.read() if stream else b""
    directory = _directory("tools", True)
    target = _binary()
    if target.is_symlink():
        raise ValueError("ccusage binary must not be a symbolic link")
    fd, temporary = tempfile.mkstemp(prefix=".ccusage-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(binary_data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(temporary, 0o700)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    _write("tools", "ccusage-install.json", {"version": VERSION, "platform": key, "sha256": hashlib.sha256(binary_data).hexdigest(),
                                              "archive_integrity": "sha512-" + _INTEGRITY[key], "source": url})
    return {"version": VERSION, "path": str(target), "archive_integrity": "sha512-" + _INTEGRITY[key]}


def _export_event(event, source):
    u, model = event.get("usage", {}), _identifier(event.get("model"))
    if not model or event.get("model_verified") is False or any(_number(u.get(k)) is None for k in TOKEN_KEYS[:5]):
        return None
    inp, out, read, write = (u[k] for k in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"))
    if read + write > inp:
        return None
    if source == "claude":
        creation = event.get("cache_creation")
        if write and (not isinstance(creation, dict) or _add(*(_number(creation.get(k)) for k in
                    ("ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"))) != write):
            return None
        entry = {"timestamp": event["timestamp"], "message": {"id": event["id"], "model": model,
                "usage": {"input_tokens": inp - read - write, "output_tokens": out, "cache_read_input_tokens": read,
                          "cache_creation_input_tokens": write}}}
        if creation:
            entry["message"]["usage"]["cache_creation"] = creation
        return entry
    if source == "codex":
        return {"timestamp": event["timestamp"], "type": "event_msg", "payload": {"type": "token_count", "info": {
            "last_token_usage": {"input_tokens": inp, "output_tokens": out, "cached_input_tokens": read,
                                 "cache_write_input_tokens": write, "reasoning_output_tokens": u.get("reasoning_tokens") or 0,
                                 "total_tokens": inp + out}}}}
    return {"type": "gemini", "id": event["id"], "timestamp": event["timestamp"], "model": model,
            "tokens": {"input": inp, "output": out - (u.get("reasoning_tokens") or 0), "cached": read,
                       "thoughts": u.get("reasoning_tokens") or 0, "total": inp + out}}


def ccusage_report(run_id=None, agent=None, limit=100, offset=0):
    _arguments(limit, run_id, agent, offset)
    if not ccusage_status()["installed"]:
        raise ValueError("Pinned ccusage is not installed or failed verification; run cs usage install.")
    result = report(limit=limit, run_id=run_id, agent=agent, offset=offset)
    records, warnings = [], []
    for public in result["runs"]:
        loaded, errors = _records("runs", 1, public["id"])
        warnings.extend(errors)
        if loaded and _revision(loaded[0]) == public["revision"]:
            records.extend(loaded)
        else:
            warnings.append("A run changed during reporting; retry to estimate a consistent usage snapshot.")
    outputs = {}
    with tempfile.TemporaryDirectory(prefix="cloudseed-usage-", dir=_directory(create=True)) as temp:
        home = Path(temp)
        config = home / "empty.json"
        config.write_text("{}", encoding="utf-8")
        sources = set()
        for run in records:
            events = run.get("events", [])
            if _sum(events) != run["usage"]:
                warnings.append("A run's final aggregate differs from its per-model events; its cost estimate is unavailable.")
                continue
            if run.get("status") != "complete":
                warnings.append("Some estimates use partial agent usage; missing requests cannot be priced.")
            source = "codex" if run["agent"] == "codex" else "gemini" if run["agent"] == "gemini" else "claude"
            directory = home / source / ("projects/cloudseed" if source == "claude" else "sessions" if source == "codex" else "chats")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            lines = []
            for event in events:
                entry = _export_event(event, source)
                if entry is None:
                    if source == "claude" and event.get("usage", {}).get("cache_write_tokens") and not event.get("cache_creation"):
                        warnings.append("Anthropic cache-write usage lacks the 5-minute/1-hour TTL split; its cost cannot be estimated reliably.")
                    else:
                        warnings.append("A usage event lacks verified model/token metadata; it was excluded from cost estimation.")
                    continue
                if source == "codex":
                    lines.append({"timestamp": event["timestamp"], "type": "turn_context", "payload": {"model": event["model"]}})
                entry["sessionId"] = run["id"]
                lines.append(entry)
            if lines:
                dest = directory / (run["id"] + ".jsonl")
                paths.atomic_write(dest, "\n".join(json.dumps(row, allow_nan=False, separators=(",", ":")) for row in lines) + "\n", mode=0o600)
                sources.add(source)
        env = {"HOME": str(home), "USERPROFILE": str(home), "XDG_CONFIG_HOME": str(home / "config"),
               "XDG_CACHE_HOME": str(home / "cache"), "CLAUDE_CONFIG_DIR": str(home / "claude"),
               "CODEX_HOME": str(home / "codex"), "GEMINI_DATA_DIR": str(home / "gemini"), "NO_COLOR": "1"}
        for key in ("SYSTEMROOT", "WINDIR"):
            if key in os.environ:
                env[key] = os.environ[key]
        for source in sorted(sources):
            # Bound output on disk rather than retaining an unbounded pipe in RAM.
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                try:
                    proc = subprocess.run([str(_binary()), source, "session", "--json", "--offline", "--config", str(config)],
                                          env=env, cwd=home, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=30)
                except subprocess.TimeoutExpired as error:
                    raise ValueError("ccusage exceeded the 30-second offline report timeout; native usage remains available.") from error
                except OSError as error:
                    raise ValueError("The verified ccusage binary could not be started; run cs usage install to repair it.") from error
                stdout.seek(0)
                raw = stdout.read(4 * 1024 * 1024 + 1)
                if proc.returncode or len(raw) > 4 * 1024 * 1024:
                    raise ValueError("ccusage could not produce a bounded report from Cloudseed's metadata.")
                outputs[source] = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid ccusage numeric output")))
                if not isinstance(outputs[source], dict) or not isinstance(outputs[source].get("sessions"), list):
                    raise ValueError("ccusage returned an unsupported report shape")
                expected = sum(e["usage"]["total_tokens"] for r in records
                               if ("codex" if r["agent"] == "codex" else "gemini" if r["agent"] == "gemini" else "claude") == source
                               for e in r.get("events", []) if _export_event(e, source) is not None)
                if outputs[source].get("totals", {}).get("totalTokens") != expected:
                    warnings.append("ccusage did not account for every exported token; its estimate is incomplete.")
    unpriced, models, cost = set(), set(), 0.0
    costs = []
    for source, output in outputs.items():
        totals = output.get("totals", {})
        value = totals.get("costUSD", totals.get("totalCost"))
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            warnings.append("ccusage did not provide a valid cost total.")
        else:
            cost += value
        for row in output.get("sessions", []):
            row_models = row.get("models", {})
            for name, detail in row_models.items() if isinstance(row_models, dict) else []:
                models.add(name)
                if detail.get("missingPricing") or detail.get("isFallback"):
                    unpriced.add(name)
            for detail in row.get("modelBreakdowns", []):
                name = detail.get("modelName", detail.get("model"))
                if name:
                    models.add(name)
                    if detail.get("missingPricing"):
                        unpriced.add(name)
            unpriced.update(row.get("unpricedModels", []))
            costs.append({"run_id": row.get("sessionId"), "source": source,
                          "estimated_cost_usd": row.get("costUSD", row.get("totalCost"))})
        unpriced.update(totals.get("unpricedModels", []))
    if unpriced:
        warnings.append("Some observed models lack reliable pricing; the complete estimated cost is unknown.")
    if not outputs:
        warnings.append("No complete, verified per-model usage is available to estimate.")
    result["ccusage"] = {"installed": True, "version": VERSION, "engine": "ccusage", "offline": True,
                         "status": "partial" if warnings and outputs else "unavailable" if not outputs else "complete",
                         "basis": "Offline API-equivalent estimates for this page only; not actual billing, subscription quota or credits",
                         "estimated_cost_usd": cost if outputs and not warnings else None, "known_estimated_cost_usd": cost if outputs else None,
                         "unpriced_models": sorted(unpriced)[:64], "models": sorted(models)[:64],
                         "model_names_omitted": max(0, len(models) - 64), "reasons": list(dict.fromkeys(warnings)),
                         "costs": costs[:100], "cost_rows_omitted": max(0, len(costs) - 100)}
    return result
