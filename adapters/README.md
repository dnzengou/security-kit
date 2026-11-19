# Adapters: exposing the kit to agents and apps

The kit is plain Markdown + JSON + stdlib Python, so it plugs into most stacks. Keep every adapter **read-only and passive**: the tools assess, they never change targets. Enforce an authorization check (an approved engagement per `schemas/engagement.schema.json` whose scope contains the target) before running any network check.

## 1. Agent skills / system prompts
Load `skills/<name>/SKILL.md` as a skill, custom instruction, GPT/Gem/Project knowledge file, or system-prompt section. Frontmatter `description` ("Use when ...") is written for automatic skill routing.

## 2. MCP server (Model Context Protocol)
Wrap the scripts as MCP tools with any MCP SDK (Python `mcp` package, TypeScript `@modelcontextprotocol/sdk`). Suggested tools:

| Tool | Input | Runs | Output |
|---|---|---|---|
| `posture_check` | `{hosts: string[], engagement_id: string, pq?: bool}` | `scripts/posture_check.py` | finding[] + summary |
| `score_assessment` | answers JSON | `scripts/score_assessment.py` | assessment result |
| `get_skill` | `{name}` | reads `skills/<name>/SKILL.md` | markdown |
| `get_template` | `{name}` | reads `templates/...` | markdown/csv |

Expose skills/templates as MCP **resources** or **prompts** too. Annotate network tools `readOnlyHint: true, openWorldHint: true`. Minimal Python sketch:

```python
from mcp.server.fastmcp import FastMCP
import json, subprocess, sys
mcp = FastMCP("security-kit")

@mcp.tool()
def posture_check(hosts: list[str], engagement_id: str) -> dict:
    """Passive TLS/PQ/header/manifest check on hosts inside an approved engagement scope."""
    assert_in_scope(engagement_id, hosts)          # implement: load engagement, compare scope
    out = subprocess.run([sys.executable, "scripts/posture_check.py", *hosts], capture_output=True, text=True, timeout=120)
    return json.loads(out.stdout)

if __name__ == "__main__":
    mcp.run()
```

## 3. OpenAPI / HTTP tool
For platforms that call REST tools (custom GPT actions, function calling, workflow tools): put a small HTTP wrapper (FastAPI, Flask, serverless function) in front of the scripts and publish `openapi.yaml` below. Require auth (API key or OAuth), rate-limit, log every call with engagement ID.

```yaml
openapi: 3.1.0
info: {title: Security Kit, version: 1.0.0}
paths:
  /posture-check:
    post:
      operationId: postureCheck
      requestBody: {required: true, content: {application/json: {schema: {type: object, required: [hosts, engagement_id], properties: {hosts: {type: array, items: {type: string}}, engagement_id: {type: string}}}}}}
      responses: {"200": {description: Findings, content: {application/json: {schema: {$ref: "../schemas/finding.schema.json"}}}}}
  /score-assessment:
    post:
      operationId: scoreAssessment
      requestBody: {required: true, content: {application/json: {schema: {type: object}}}}
      responses: {"200": {description: Assessment, content: {application/json: {schema: {$ref: "../schemas/assessment.schema.json"}}}}}
components:
  securitySchemes: {apiKey: {type: apiKey, in: header, name: X-API-Key}}
security: [{apiKey: []}]
```

## 4. Agent-to-agent discovery
`agent-card.json` is an example A2A-style card to publish at `/.well-known/agent-card.json` when the kit runs as a hosted agent. Only advertise endpoints that exist and require auth; the posture checker itself flags cards that advertise dead endpoints.

## 5. Human teams
Use the skills as runbooks, the templates as documents, the CSVs in a spreadsheet, and run the scripts from a laptop.
