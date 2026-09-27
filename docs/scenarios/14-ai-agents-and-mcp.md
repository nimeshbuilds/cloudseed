---
title: "Scenario 14: AI agents and an MCP server for your cloud"
description: "Let AI agents drive cloudseed safely: Claude Code, Codex, Gemini or the built-in agent with redaction, and an MCP server for Claude Desktop, Cursor and VS Code."
---

# 14 · AI agents and MCP

**Outcome:** agentic mode switched on with the agent and model you choose, the cloudseed skills installed for your
agent, proof of exactly what an agent receives (a research brief, your task with secrets redacted, no credentials in
its environment), and a local MCP server that gives Claude Code, Claude Desktop, Cursor, VS Code, Codex, Gemini CLI
and Windsurf every cloudseed feature as a tool, with confirmation required for anything that changes infrastructure.

!!! success "Verified live on macOS (local services, no cloud or VMs needed)"
    [`tests/scenarios/14-ai-agents-and-mcp.sh`](https://github.com/nimeshbuilds/cloudseed/blob/main/tests/scenarios/14-ai-agents-and-mcp.sh)
    checks the local workflow in a throw-away home: it starts a real MCP server without installing a login service,
    round-trips the protocol over stdio and HTTP, wires a client, rotates the token and removes it. The step that
    sends a task to a real model runs when `ANTHROPIC_API_KEY` is set. Reviewing your own saved report additionally
    requires an existing environment and artifact; no cloud deployment is needed for the local interface checks.

| :material-clock-outline: Time | :material-cash: Cost | :material-signal-cellular-1: Level | :material-robot-outline: Needs |
|---|---|---|---|
| ~15 min | $0 (model usage is billed by your provider) | Beginner | For real tasks: an Anthropic API key, or Claude Code / Codex / Gemini CLI logged in |

## What you'll build

```mermaid
flowchart TB
  subgraph agentic["cs agentic #quot;...#quot;"]
    brief["Context brief<br/>environments, outputs, tools"] --> prompt["Prompt<br/>(redacted)"]
    task["Your task"] --> prompt
    prompt --> agent["Agent: builtin / claude / codex /<br/>gemini / grok + cloudseed skills"]
  end
  subgraph mcp["cs setup mcp"]
    clients["Claude Code · Claude Desktop · Cursor<br/>VS Code · Codex · Gemini CLI · Windsurf"] -- "HTTP :7433 + bearer token<br/>or stdio" --> server["cloudseed MCP server<br/>typed tools · resources · prompts"]
  end
  agent -- "cloudseed ... only<br/>destructive steps wait for you" --> cli["cloudseed CLI"]
  server --> cli
  vault["Credential vault<br/>secrets stripped from agents,<br/>output redacted"] -.-> cli
```

## Before you start

- cloudseed installed. The local echo-agent and MCP checks do not require a model login.
- For step 5 (a real task): `ANTHROPIC_API_KEY` for the built-in agent, or a logged-in Claude Code (`claude`),
  Codex (`codex login`), Gemini CLI (`gemini`) or Grok CLI (`GROK_API_KEY`).

## Step 1: See the agents

```bash
cs agents
```

`agents` shows each agent, whether it is installed and logged in, and the exact command to fix it when not. The
built-in agent runs inside cloudseed with the official Anthropic SDK; its only tool is "run a cloudseed command".

## Step 2: Turn on agentic mode and pick a model

```bash
cs enable agentic
cs use builtin --model claude-sonnet-5
cs model
cs model claude-opus-5
```

The **Context brief** prepares environment facts and a command guide before a task. Its legacy `headliner`
setting remains available; step 4 shows how to inspect the brief and turn it on or off.

Prefer Claude Code with your claude.ai subscription? `cs use claude` (or `codex`, `gemini`, `grok`). Store an API key
in the vault with hidden input:

```bash
cs creds set ANTHROPIC_API_KEY
```

## Step 3: Install the skills for your agent

```bash
cs skill list
cs skill show aws
cs skill install --agent claude
cs install skills aws destroy --agent codex
```

Ten skills in the Agent Skills format (`SKILL.md`): the core `cloudseed` driver plus `aws`, `gcp`, `azure`,
`vmware`, `destroy`, `platform`, `finops`, `managed` and `architecture`. `enable agentic` and `use` install them
automatically; `--project` puts them in `./.claude/skills` of the current repository.

## Step 4: See exactly what an agent receives (no API key needed)

A custom agent in `~/.cloudseed/agents.json` can be any command. This one only reports what it was given.
If that file already exists, merge the `echo` entry into it instead of replacing your agents:

```bash
cat > ~/.cloudseed/agents.json <<'EOF'
{
  "echo": {
    "display": "Echo agent",
    "exec": ["sh", "-c", "echo \"brief: $(printf '%s' \"$1\" | grep -c .) lines\"; printf '%s\\n' \"$1\" | tail -n 2; echo \"secrets in env: $(env | grep -cE 'SECRET|API_KEY' || true)\"; cloudseed creds set X=1; echo \"human-only refused: exit $?\"", "echo-agent", "{prompt}"]
  }
}
EOF
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
cs agentic --agent echo "list my environments; my database is postgres://shop:Tr0ub4dor-3@db.internal:5432/shop"
unset AWS_SECRET_ACCESS_KEY
```

??? example "Expected output"
    ```text
      ━━ cloudseed · agentic ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Agent                  Echo agent (echo)
        Status                 ✔ ready
        Context brief          on
        Credentials            stripped from agent env; output redacted

    $ sh ... (exec mode, model=default)
    brief: 40 lines
    ## Task
    list my environments; my database is postgres://shop:[REDACTED]@db.internal:5432/shop
    secrets in env: 0
      ✖ `cloudseed creds set X` is human-only (agent sessions never change the credential vault). Ask the user to
        run it in a terminal:
            cloudseed creds set X
    human-only refused: exit 2
    ```

- **Context brief**: a compact brief (environments, outputs, tool and credential status, a command cheat-sheet) is
  put in front of every task. It is deterministic research gathered before the task. The legacy `headliner`
  setting still controls it: compare with `cs disable headliner`, then restore `cs enable headliner`.
- **Command access**: the external agent receives temporary `cloudseed` and `cs` launchers for the installation
  running this task, even when you started a standalone binary by its full path. If its shell resets `PATH`, use
  the absolute launcher path printed in the prompt. Do not guess another executable or search credential folders.
- **Redaction**: the database password in the task never reaches the agent (AWS keys, tokens, private keys and
  signed URLs are masked the same way).
- **Credential stripping**: `AWS_SECRET_ACCESS_KEY` and every vault secret are removed from the agent's
  environment; child `cloudseed` commands get them back through a per-session broker.
- **Human-only commands** (credentials, installs, enabling features, the MCP and console settings) are refused in
  every agent session with exit code 2 and the command for you to run.

```bash
cs disable headliner
cs agentic --agent echo "list my environments"
cs enable headliner
```

## Step 5: Let a real agent work

```bash
cs agentic "what environments exist, and what would a dev environment on aws in us-west-2 cost per month?"
cs do "show me the undo history"
cs agentic --show-prompt "list my environments"
```

`do` is a short alias. With the built-in agent, commands that change things (any `--auto-approve`, provisioning,
scans, VPN users, platform installs, chaos runs, DR actions ...) pause for your approval, and destroy, undo, node
changes and restores first run as a preview. `-i` opens the interactive session of an external agent
(`cs agentic -i --agent claude "..."`).

## Step 6: Deploy the MCP server

=== "Interactive"

    ```bash
    cs setup mcp
    ```

    Deploys the server, asks which detected clients to connect, and prints the guide.

=== "Unattended"

    ```bash
    cs setup mcp -y --client none
    ```

    Add `--client all` to connect every detected client, `--transport stdio` for no service at all, `--port 7440`
    when 7433 is taken.

??? example "Expected output (abbreviated)"
    ```text
      ◆ 1/3  Server   how the MCP server runs: one shared local HTTP service, or stdio launched by each client
      ● Starting the MCP server on http://127.0.0.1:7433/mcp...
      ✔ MCP server up: http://127.0.0.1:7433/mcp   (transport, protocol and installed tool/resource counts follow)

      ◆ 2/3  Clients   register the server with the MCP clients on this machine
      ◆ 3/3  How to use it   the guide below is also saved to ~/.cloudseed/mcp/CONNECT.md
    ```

## Step 7: Check it and connect clients

```bash
cs mcp status
cs status mcp
cs mcp tools
cs mcp test
cs mcp test --http
cs mcp connect claude-desktop
cs mcp connect claude-code cursor vscode
cs mcp config
cs mcp guide
```

- `test` does a protocol round-trip (initialize, tools/list, a resource read, a tool call) over stdio; `--http`
  against the running server.
- `connect` writes each client's own config: `claude mcp add -s user` for Claude Code,
  `claude_desktop_config.json` (stdio) for Claude Desktop, `~/.cursor/mcp.json`, VS Code's `mcp.json`,
  `~/.codex/config.toml`, `~/.gemini/settings.json`. `config` prints snippets for any other client.
- Then ask your client: *"Plan a dev environment on AWS in us-west-2 with a private EKS cluster and show me the
  monthly estimate before applying."* Tools that change infrastructure refuse to run until the client asks you
  and sends `confirm=true`.

??? example "Expected output of `cs mcp test --http`"
    ```text
      ✔ MCP round-trip over http://127.0.0.1:7433/mcp: initialize, tools/list, resources/read skill,
        tools/call cloudseed_list
    ```

## Step 7a: Explain a saved scan without running it again

Use an environment with a saved scan, such as one from [scenario 10](10-compliance-scans.md). Replace `aws` and `dev`
with that environment, then select a JSON artifact returned by the list:

```bash
cs evidence list aws --env dev --area scans --json
cs evidence read aws --env dev --artifact scans/NAME.json --offset 0 --limit 8000 --json
```

`scans/NAME.json` is a placeholder, not a filename to invent. When `complete` is false, repeat the read with the
returned `next_offset` and the same `revision`. Keep reading until `complete` is true. If the revision changes,
restart at offset 0. This reads redacted, saved evidence; it makes no cloud query and changes no infrastructure.

Then give your agent this task:

> Review the saved cloud scan for aws-dev. Use evidence list/read and follow every page with the same revision.
> Explain failed and manual controls, the recorded time and scope, and the diagnostics and coverage limits.
> Do not infer complete coverage from unknown=0. Do not run another scan or make changes.

Over MCP, call `cloudseed_evidence` with `action=list`, `cloud=aws`, `env=dev`, `area=scans`. Then use `action=read`
with the returned `artifact`; pass `offset`, `limit` and `revision` for subsequent pages. These calls need no
confirmation. [The MCP guide](../guides/mcp.md#read-saved-reports) shows the JSON calls and size limits.

In the console, select the same environment and open **Reports**. Read its findings and coverage limits, then use
**View full JSON** or **View full Markdown** when the preview is truncated. The Agents & MCP task box can run the
same prompt; its agent reads evidence on the machine hosting the console.

Verify that the explanation cites findings from the actual report and distinguishes **all pages read** from
**all cloud resources assessed**. `unknown=0` only describes counted observations, and saved evidence may be stale.
If a file or page cannot be read, the agent should name that gap instead of inventing a complete result.

## Step 7b: Review usage without guessing costs

The earlier echo-agent task makes no model request. Start by looking at the recorded Cloudseed runs:

```bash
cs usage report
cs usage report --agent echo --json
cs usage report --offset 0 --limit 10 --json
```

The custom echo agent should explain why token usage is unavailable. It must not turn a missing measurement into
a zero-cost claim. If you completed step 5 with a supported standard agent, compare that run's reported metrics.
Copy its actual run identifier to narrow the result:

```bash
cs usage report --run-id RUN_ID --json
```

**Agent:** “Read my recent Cloudseed usage. Identify the task and explain observed tokens, any estimated cost,
and unavailable measurements. Do not install software or make another model request just to estimate usage.”

**MCP:** call `cloudseed_usage` with `{"engine":"native","limit":10}`. The report includes activity observed by
the Cloudseed server, such as tool calls, latency and errors. Model tokens from an independently running MCP
client are unavailable to Cloudseed; they belong to that client's model connection.

**UI:** open **Agents & MCP → Cloudseed usage**, select an agent and the **Recorded usage** engine, then inspect the
run's **Recorded metadata**. Use **Next** and **Previous** to find the run, and **Download this page** to export its
JSON. No cloud environment needs to be selected. Confirm that the run identifier and metric availability match
the CLI result.

To try the optional ccusage analyzer, install it yourself and then request that engine:

```bash
cs usage install
cs usage report --engine ccusage --json
```

Installation downloads and verifies the pinned native analyzer. Reporting uses only Cloudseed-generated usage inputs,
not global agent history. Native reporting works without this installation. Costs, where available, are estimates,
not invoices or remaining quota. See [agent usage](../guides/usage.md) for the supported metrics and limits.
For the same installation through MCP, approve the download first, then call `cloudseed_usage_install` with
`{"confirm":true}`. The console exposes the corresponding confirmed install action. Use the report's
`coverage.next_offset` to read another page until it is `null`; page sizes may shrink to fit the response limit.
Reported cost totals apply to the selected page, not all stored runs.

## Step 8: Operate the server

```bash
cs mcp logs -n 20
cs mcp token --rotate
cs mcp restart
cs mcp stop
cs mcp start
cs disable mcp
cs enable mcp
cs mcp disconnect claude-desktop
```

- The server listens on 127.0.0.1 only, validates the Origin header and requires the bearer token
  (`~/.cloudseed/mcp/token`, 0600). `token --rotate` issues a new one and updates every HTTP-connected client.
- `disable mcp` stops it and keeps it off; client entries stay until you disconnect them.
- A client connected over stdio launches the server itself; this is the command it runs (it speaks MCP on stdin and
  stdout, so you do not run it by hand):

```bash
cs mcp serve
```

## Use an agent, MCP or the UI

Follow the same numbered steps and verification/cleanup conditions through your chosen interface. Start with the
[interface setup and coverage guide](interfaces-and-coverage.md); replace account/project/subscription and SSH
placeholders before any live request.

**Agent prompt:** “Inspect my cloudseed agent and MCP setup, list the available tools and load the architecture/platform skills. Demonstrate read-only environment discovery, then use evidence list/read to review a saved report completely, including its scope and coverage limits. Review the available usage metadata without inventing missing measurements or treating estimates as invoices. Explain the permissions for changes. Ask me to complete host login or service bootstrap steps that cannot run inside an agent.”

**MCP starter:** `cloudseed_skill` with:

```json
{
  "name": "architecture"
}
```

Use the matching tool for each remaining step in this page; the [command-to-tool map](interfaces-and-coverage.md#command-to-interface-map)
lists the tool family. Keep `vmware-lab` selected. Preview first; add `confirm:true` only to the specific change
you have authorized. For the saved-report exercise, select the environment that owns the artifact instead of assuming
`vmware-lab`. Host bootstrap, provider login and interactive applications retain their documented human steps.

**UI:** Open Agents & MCP to select the agent/model, inspect MCP status and connect clients; use its task box for the page’s agent prompt. Host authentication/service installation is performed by the human. After connection, use All actions for equivalent deterministic tools and inspect Activity.

## Verify it worked

```bash
cs mcp status
cs undo --list
```

- `mcp status` shows Enabled, the URL, the service (launchd / systemd), Health `running` and the connected clients.
- The undo list shows your recent global changes (agent, model, MCP, clients). It keeps at most five of one kind, so
  after this many MCP steps the oldest of them (such as `mcp setup`) have already dropped off. `cs undo --global`
  reverts the newest one. AI agents can never undo global settings.

## Clean up

```bash
cs destroy mcp
cs disable agentic
```

Remove the temporary `echo` entry from `~/.cloudseed/agents.json`. Remove the file itself only if this exercise
created it and it contains no other agents.

`destroy mcp` (the same as `cs mcp uninstall`) stops the server, removes the service, the token and every client
entry it wrote. Unattended: `cs destroy mcp -y --auto-approve`.

## What just happened

- Agentic mode is optional and additive: `cloudseed setup aws` stays a literal command; `cloudseed agentic "set up
  aws"` is a request to an agent that drives the same CLI.
- The MCP server exposes each feature as a typed tool (list, doctor, status, setup, plan, apply, platform, kubectl,
  dr, chaos, scan, finops, explain, undo, destroy, ...), plus the skills as resources and four prompts.
- Every call is checked against the tool's schema, runs cloudseed as a child under the credential broker, and its
  output is redacted.
- Learn more: [Agentic mode](../guides/agentic.md) · [MCP server](../guides/mcp.md) ·
  [Agent usage](../guides/usage.md) ·
  [MCP tools reference](../reference/mcp-tools.md) · [Skills](../reference/skills.md) ·
  [Explain index](../reference/explain-index.md)

```bash
cs explain agentic
cs explain mcp
cs help agents
```

## Next steps

- [15 · Web console](15-web-console-and-finops.md): agents and MCP are a page there too.
- [13 · Day-2 operations](13-day-2-operations.md): what an agent can do for you, and what it will ask first.
- [01 · Your first lab](01-first-lab-vmware.md): then ask an agent "what does my lab cost and is the bastion
  reachable?"
