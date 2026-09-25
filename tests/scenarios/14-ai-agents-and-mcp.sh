#!/usr/bin/env bash
# Scenario 14 - AI agents and MCP (docs/scenarios/14-ai-agents-and-mcp.md)
# Local scenario, always in a throw-away HOME and CLOUDSEED_HOME (also with CLOUDSEED_LIVE=1): agentic mode, skills, the
# echo agent (brief, redaction, credential stripping, human-only refusals), and a real MCP server on SCN_MCP_PORT
# (default 7984) that is tested over stdio and HTTP, wired to Claude Desktop's config, re-keyed and removed. A task for
# a real model runs only when ANTHROPIC_API_KEY is set in the environment that starts this script.
REAL_ANTHROPIC_KEY="${ANTHROPIC_API_KEY:-}"
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 14-ai-agents-and-mcp "AI agents and MCP" local
need python3 curl
PORT="${SCN_MCP_PORT:-7984}"
on_exit cs destroy mcp -y --auto-approve
on_exit cs disable agentic

step "1. See the agents"
ok cs agents
has "builtin +Built-in agent"
has "claude +Claude Code"

step "2. Turn on agentic mode and pick a model"
ok cs enable agentic
has "Agentic mode enabled with Built-in agent"
ok cs use builtin --model claude-sonnet-5
has "claude-sonnet-5 \*"
ok cs model
has "Available models"
ok cs model claude-opus-5
has "Model for Built-in agent set to claude-opus-5"
skip "cs use claude (installs and selects Claude Code)"
rc 2 cs creds set ANTHROPIC_API_KEY
has "no terminal to ask on"

step "3. Install the skills for your agent"
ok cs skill list
has "cloudseed-platform"
ok cs skill show aws
has "name: cloudseed-aws"
ok cs skill install --agent claude
check "10 skills in ~/.claude/skills" test "$(find "$HOME/.claude/skills" -name SKILL.md | wc -l | tr -d ' ')" -eq 10
ok cs install skills aws destroy --agent codex
check "2 skills in ~/.codex/skills" test -f "$HOME/.codex/skills/cloudseed-destroy/SKILL.md"

step "4. See exactly what an agent receives"
cat > "$CLOUDSEED_HOME/agents.json" <<'JSON'
{
  "echo": {
    "display": "Echo agent",
    "exec": ["sh", "-c", "echo \"brief: $(printf '%s' \"$1\" | grep -c .) lines\"; printf '%s\\n' \"$1\" | tail -n 2; echo \"secrets in env: $(env | grep -cE 'SECRET|API_KEY' || true)\"; cloudseed creds set X=1; echo \"human-only refused: exit $?\"", "echo-agent", "{prompt}"]
  }
}
JSON
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ok cs agentic --agent echo "list my environments; my database is postgres://shop:Tr0ub4dor-3@db.internal:5432/shop"
unset AWS_SECRET_ACCESS_KEY
has "Credentials +stripped from agent env; output redacted"
has "my database is postgres://shop:\[REDACTED\]@db.internal"
hasnt "Tr0ub4dor-3"
has "secrets in env: 0"
has "human-only refused: exit 2"
check "the headliner brief is long" bash -c "grep -Eo 'brief: [0-9]+ lines' '$SCN_OUT' | awk '{exit !(\$2 > 10)}'"
ok cs disable headliner
ok cs agentic --agent echo "list my environments"
has "brief: [0-9] lines"
ok cs enable headliner

step "5. Let a real agent work"
if [[ -n "$REAL_ANTHROPIC_KEY" ]]; then
  ok env ANTHROPIC_API_KEY="$REAL_ANTHROPIC_KEY" cs agentic "what environments exist, and what would a dev environment on aws in us-west-2 cost per month?"
else
  skip "cs agentic / cs do with a real model (ANTHROPIC_API_KEY or a logged-in agent CLI)"
  rc 1 cs "do" "show me the undo history"
  has "needs Anthropic API credentials"
  rc 1 cs agentic --show-prompt "list my environments"
fi

step "6. Deploy the MCP server"
# Exercise a real server without creating a login service from a throw-away home.
ok cs setup mcp -y --no-service --client none --port "$PORT"
has "MCP server up: http://127.0.0.1:$PORT/mcp"
has "48 tools"

step "7. Check it and connect clients"
ok cs mcp status
has "Health +running"
ok cs status mcp
has "Transport +http"
ok cs mcp tools
has "cloudseed_platform"
ok cs mcp test
has "MCP round-trip over stdio"
ok cs mcp test --http
has "MCP round-trip over http://127.0.0.1:$PORT/mcp"
ok curl -s "http://127.0.0.1:$PORT/health"
has '"server": "cloudseed"'
ok curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$PORT/mcp" -H "Content-Type: application/json" -d "{}"
has "^401$"
ok cs mcp connect claude-desktop
check "Claude Desktop config written" bash -c "grep -rq cloudseed \"$HOME/Library/Application Support/Claude/claude_desktop_config.json\" \"$HOME/.config/Claude/claude_desktop_config.json\" 2>/dev/null"
skip "cs mcp connect claude-code cursor vscode (runs the client CLIs; writes their user configs)"
ok cs mcp config
has "claude mcp add"
ok cs mcp guide
has "Your cloudseed MCP server"
ok curl -s -X POST "http://127.0.0.1:$PORT/mcp" -H "Authorization: Bearer $(cat "$CLOUDSEED_HOME/mcp/token")" \
  -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"cloudseed_ops_acceptance","arguments":{"cloud":"aws"}}}'
has '"structuredContent"'
has '"INCOMPLETE"'
has '"live": false'

step "8. Operate the server"
ok cs mcp logs -n 20
has "listening on http://127.0.0.1:$PORT/mcp"
OLD_TOKEN="$(cat "$CLOUDSEED_HOME/mcp/token")"
ok cs mcp token --rotate
has "Server restarted with the new token"
check "token rotated" test "$(cat "$CLOUDSEED_HOME/mcp/token")" != "$OLD_TOKEN"
ok cs mcp restart
has "MCP server restarted"
ok cs mcp stop
has "MCP server stopped"
ok cs mcp start
has "MCP server up"
ok cs disable mcp
has "MCP disabled"
ok cs enable mcp
has "MCP enabled"
ok cs mcp disconnect claude-desktop
has "removed mcpServers.cloudseed"
ok bash -c "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"scenario\",\"version\":\"1\"}}}' | cs mcp serve"
has '"serverInfo"'

step "Verify it worked"
ok cs mcp status
has "Enabled +yes"
ok cs undo --list
has "mcp setup|enable mcp"

step "Clean up"
rc 3 cs destroy mcp
ok cs destroy mcp -y --auto-approve
has "MCP server removed and disabled"
ok cs disable agentic
has "Agentic mode disabled"
ok rm "$CLOUDSEED_HOME/agents.json"
ok cs explain agentic
ok cs explain mcp
has "bearer token|token"
ok cs help agents
