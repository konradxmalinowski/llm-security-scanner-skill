# Claude

Verified against the [Agent Skills spec](https://agentskills.io/specification) and the
[Claude Code plugin reference](https://code.claude.com/docs/en/plugins-reference).

## Option A — install as a plugin (recommended)

The repository root *is* a Claude Code plugin: `.claude-plugin/plugin.json` plus the
`skills/` directory, and the plugin also wires the MCP server.

```
/plugin marketplace add konradxmalinowski/llm-security-scanner-skill
/plugin install llm-security-scanner@llm-security
```

Then install the Python package the skill's scripts call:

```bash
uv pip install 'llm-security-scanner-skill[mcp]'
```

The skill appears as `llm-security-scanner:llm-security-scan` (components are namespaced
under the plugin name). Verify with `/plugin` or `claude plugin validate .` from a clone.

## Option B — install the skill only

```bash
uv pip install llm-security-scanner-skill
llm-scanner-skill install --platform claude --scope user     # ~/.claude/skills/
llm-scanner-skill install --platform claude --scope project  # ./.claude/skills/
```

`--scope project` commits the skill to the repo so a team shares it. `--mode symlink`
(the default) keeps it tracking the checkout; `--mode copy` is self-contained.

`--platform agents` installs to `.agents/skills/`, which Claude Code also scans — one
install then covers Claude, Gemini CLI and Codex.

## Option C — clone and point at it

```bash
git clone https://github.com/konradxmalinowski/llm-security-scanner-skill
claude --plugin-dir ./llm-security-scanner-skill
```

## MCP server

Installed via Option A, or by hand in `.mcp.json`:

```json
{ "mcpServers": { "llm-security-scanner": { "command": "llm-scanner-skill", "args": ["mcp"] } } }
```

Optional — the skill works through Bash alone. See
[references/mcp.md](../../skills/llm-security-scan/references/mcp.md).

## Using it

Activation is automatic on a matching request:

- "Review my chatbot for OWASP LLM risks"
- "Check this RAG pipeline for prompt injection"
- "Scan the local app at :8000 before release"
- "Analyze this scanner report and fix the high-severity findings"
- "Add an LLM security gate to GitHub Actions"

Or invoke it by name: `use the llm-security-scan skill on ./my-app`.

## Notes

- `skills/` is Claude Code's default scan location, so `plugin.json` does not need a
  `skills` key.
- `commands/llm-security-scan.toml` is Gemini's slash command. Claude Code's `commands/`
  scan only picks up `.md` files, so it is inert here.
- `agents/openai.yaml` inside the skill is Codex metadata and is ignored by Claude Code.
