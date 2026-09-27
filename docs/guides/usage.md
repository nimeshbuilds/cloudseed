---
title: "Agent usage - understand Cloudseed task activity"
description: "Review tokens, available cost estimates and MCP activity for Cloudseed runs through the CLI, agents, MCP and the local console."
---

# Agent usage

Cloudseed records usage metadata for tasks it starts. Each run has its own identifier, so you can distinguish a
particular task from another agent session. Reports describe observed activity; they are not a provider invoice,
subscription allowance or account-wide usage report.

## Read a report

```bash
cs usage
cs usage report --agent claude --limit 10
cs usage report --offset 10 --limit 10 --json
cs usage report --json
```

Use a run identifier returned by the report to inspect that task:

```bash
cs usage report --run-id RUN_ID --json
```

Replace `RUN_ID` with the actual identifier. No Cloudseed environment selection or cloud credentials are required.
The native report reads saved local usage metadata without making a model request. It reports observed counters;
the optional ccusage engine adds price-based estimates where the recorded model and token details are sufficient.
Use `--offset` and `--limit` to page through the combined chronological list of agent runs and MCP calls. A response
splits the selected rows into `runs` and `mcp`; `coverage.total_records` describes the matching record count. Follow
`coverage.next_offset` until it is `null`. The response byte limit can make a page shorter than the requested limit,
so use the returned offset rather than adding the page size yourself. Cost totals apply only to the selected page.

## Understand what was measured

| Activity | Available evidence | What remains outside the report |
|---|---|---|
| Built-in agent | Usage returned by the model provider during the Cloudseed task | Requests made outside this task; provider invoice and quota |
| Standard noninteractive Claude Code, Codex or Gemini task | Usage exposed by the agent's structured output | Fields the agent did not return; unrelated agent history |
| Interactive or custom agent | Run metadata and an explanation when token usage cannot be collected | Unobserved tokens and cost |
| MCP requests | Tool calls, latency, errors and response bytes observed by the Cloudseed server | Tokens used by the client application's model |

A missing value means **unavailable**, with a reason. It does not mean zero. An estimate, when available, is not a
charge or a promise about your subscription. Model prices, cache treatment and provider billing can differ; use
your provider's billing page for billed totals. Response bytes and tool calls are activity measurements, not a
token conversion.

`input_tokens` includes cache-read and cache-write tokens; `output_tokens` includes reasoning tokens when the
provider exposes them. Those fields are subsets, so adding them to input/output would double-count them.
`summary.known_usage` sums observed values only; it does not fill missing counters. Read each run's `status` and
`reasons` alongside the summary. A complete recorded run still does not describe activity outside Cloudseed.

Some limits depend on the provider's output:

- **Codex:** a configured model is a requested model, not proof of which model answered. Token counts can still be
  usable, but cost remains unavailable without a verified model.
- **Gemini:** some stream results omit separate reasoning or tool-token counters. Cloudseed preserves a reported
  total, explains the missing breakdown and marks that part partial instead of guessing output tokens or cost.
- **Anthropic:** five-minute and one-hour cache writes have different prices. Cloudseed retains that split when
  supplied; when it is missing, token counts can be complete while the cost estimate remains unavailable.
- **Interrupted output:** a stream that ends without its expected final result or completed turn is partial,
  even if some usage records were received.

The records contain usage metadata, not saved conversation bodies. They cover Cloudseed-launched tasks and
Cloudseed MCP calls. They do not import other agent sessions or search your global agent history.

## Optional ccusage analysis

The native report works without ccusage. To use the optional analyzer, install it explicitly:

```bash
cs usage install
cs usage report --engine ccusage --json
```

Cloudseed downloads the platform's pinned **ccusage 20.0.24 native binary**, checks its archive against the reviewed
SHA-512 value, and records a local integrity check. This installation does not require a separate Node.js setup.
Analysis uses only usage inputs generated from
Cloudseed's records; it does not read your global Claude Code or other agent history. Missing measurements remain
unavailable. An analyzer result does not expand the evidence Cloudseed collected or establish account-wide usage.
The analyzer uses offline prices; estimates can be unavailable for missing model details or incomplete counters.

## Use an agent, MCP or the console

**Agent:** ask “Review my recent Cloudseed usage. Explain which metrics were collected, distinguish estimated cost
from billing, and name any unavailable metrics. Do not install anything.” The agent can use the read-only
`cs usage report --json` command. If ccusage is not installed, run `cs usage install` yourself or explicitly confirm
the MCP installation tool before requesting that engine.

**MCP:** call `cloudseed_usage` with no arguments for the native report, or narrow the result:

```json
{"engine":"native","agent":"claude","limit":10}
```

Pass `run_id` to inspect a returned run. This read-only tool needs no confirmation. The Cloudseed MCP server cannot
see its client's model tokens; a client-side billing or usage display remains a separate source.
Use `offset` with the returned `coverage.next_offset` to page through the report. Installing the optional analyzer is a separate `cloudseed_usage_install`
call with `confirm=true`; approve that dependency installation before making the call.

**Console:** open **Agents & MCP** and its **Cloudseed usage** panel. Select an agent and choose **Recorded usage**
or **ccusage cost estimates**. **Next** and **Previous** move between pages; **Download this page** exports the
displayed JSON, not the entire history. Expand **Recorded metadata** on a run or **MCP tool activity** for details.
The console uses the same reporting backend as the CLI and MCP and needs no selected cloud environment.
**Install ccusage…** requires confirmation before downloading the optional analyzer; use **Refresh** afterward.

Try [scenario 14](../scenarios/14-ai-agents-and-mcp.md#step-7b-review-usage-without-guessing-costs) to compare a local
echo-agent task, a real agent task and MCP activity. The echo agent makes no model request, so its unavailable
token fields are an expected and useful check.
