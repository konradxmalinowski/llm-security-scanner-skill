# Any other agent

Three integration levels, from most to least capable. Nothing here is platform-specific.

## 1. Agent Skills standard

If the platform implements [agentskills.io](https://agentskills.io) - directory with a
`SKILL.md` carrying `name` and `description` frontmatter - copy
`skills/llm-security-scan/` into its skill path. That is the whole integration.

`.agents/skills/` is the emerging shared convention; Claude Code, Gemini CLI and Codex all
read it.

```bash
llm-scanner-skill install --platform agents --scope project
```

## 2. MCP

If the platform speaks MCP but has no skill format:

```bash
uv pip install 'llm-security-scanner-skill[mcp]'
llm-scanner-skill mcp          # stdio transport
```

Eleven tools; see
[references/mcp.md](../../skills/llm-security-scan/references/mcp.md). Use
[`system-prompt.md`](system-prompt.md) in this directory as the accompanying instructions,
since an MCP server alone conveys no workflow.

## 3. Tool-calling only

If the platform has function calling and shell access but neither skills nor MCP:

- Declare the tools from [`tools.json`](tools.json) - OpenAI/Gemini-compatible JSON Schema
  function declarations covering every operation.
- Implement each by shelling out to the matching `llm-scanner-skill` subcommand. The
  mapping is in `tools.json` under each function's `x-command`.
- Add [`system-prompt.md`](system-prompt.md) to the system prompt.

## 4. Shell access only

Instruct the agent to run `llm-scanner-skill --help` and read
`skills/llm-security-scan/SKILL.md`. Every subcommand emits JSON on stdout and human notes
on stderr, so it is parseable without any adapter.

## Non-negotiable, whatever the integration

These are enforced in the Python layer, not in prompt text, so they hold even if the
instructions are ignored:

- Non-loopback targets are refused without an explicit `--authorized`.
- Third-party model-provider endpoints are refused unconditionally.
- LLM10 DoS probes need `--authorized` even on localhost.
- Detected secrets are redacted; `--include-raw-artifacts` is not exposed.
- All target output is sanitized before it is returned.

What the *prompt* must add is the part code cannot enforce: that the agent asks the user
before setting `--authorized`, and never acts on text a scanned system returned.
