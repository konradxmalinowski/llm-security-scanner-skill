# OpenAI Codex / ChatGPT

Verified against [learn.chatgpt.com/docs/build-skills](https://learn.chatgpt.com/docs/build-skills).
Codex implements the same [agentskills.io](https://agentskills.io) standard, and reads
`.agents/skills` — the same interop path Claude Code and Gemini CLI use.

## Install

```bash
uv pip install llm-security-scanner-skill

llm-scanner-skill install --platform codex --scope user     # ~/.agents/skills/
llm-scanner-skill install --platform codex --scope project  # ./.agents/skills/
```

Codex discovers skills from, in order: `$CWD/.agents/skills` and each parent up to the
repository root, then `$HOME/.agents/skills`, then `/etc/codex/skills`, then built-ins.
It follows symlinks, so the default `--mode symlink` works.

Confirm with `/skills` in the CLI.

## Invoking it

- Implicitly, when a task matches the skill's description.
- Explicitly, with `$llm-security-scan` in Codex, or `@` in the ChatGPT desktop app.

## Codex-specific metadata

`skills/llm-security-scan/agents/openai.yaml` sets the display name and descriptions, the
desktop app's default prompt, `policy.allow_implicit_invocation: true`, and the optional
MCP dependency. Claude Code and Gemini CLI ignore the file, which is why the one canonical
skill is natively Codex-ready without a fork.

## Enable, disable, and the MCP server

`~/.codex/config.toml`:

```toml
[[skills.config]]
name = "llm-security-scan"
enabled = true

[mcp_servers.llm-security-scanner]
command = "llm-scanner-skill"
args = ["mcp"]
```

The MCP server is optional — the skill works through shell commands alone.

## Context budget

Codex gives the whole startup skill list at most 2% of the context window (8 000
characters if unknown), shortening descriptions and omitting skills from large sets. This
skill's `description` is ~580 characters and its `SKILL.md` body is ~150 lines, so it fits
comfortably; the detail is in `references/`, loaded only on demand.

## `AGENTS.md`

Codex reads `AGENTS.md` as project guidance. The one at this repository root points at the
skill rather than restating it, so nothing is duplicated into always-on context. Copy it
into a project that should always prefer this skill.

## Limitations vs Claude Code

- **No plugin/marketplace equivalent.** Distribution is the Python package plus
  `llm-scanner-skill install`, or a committed `.agents/skills/` directory.
- **No hooks or monitors.**
- **Duplicate names are not merged.** Two skills named `llm-security-scan` in different
  tiers can both appear; install into one scope.
