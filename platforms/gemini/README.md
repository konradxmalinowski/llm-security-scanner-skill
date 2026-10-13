# Gemini CLI

Verified against the
[Gemini CLI extension reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md)
and [agent skills doc](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills.md).
Gemini CLI implements the same [agentskills.io](https://agentskills.io) standard as Claude
and Codex, so there is no separate skill format to maintain.

## Option A — install as an extension (recommended)

The repository root *is* a Gemini extension: `gemini-extension.json` declares the MCP
server, `GEMINI.md` is its context file, `skills/` holds the skill, and
`commands/llm-security-scan.toml` adds the slash command.

```bash
gemini extensions install https://github.com/konradxmalinowski/llm-security-scanner-skill
uv pip install 'llm-security-scanner-skill[mcp]'
```

Restart the CLI — extension changes only take effect on a new session. Then:

```
/extensions list
/skills list
/llm-security-scan ./my-app
```

For local development, symlink instead of reinstalling on every change:

```bash
gemini extensions link /path/to/llm-security-scanner-skill
```

## Option B — install the skill only

```bash
uv pip install llm-security-scanner-skill
llm-scanner-skill install --platform gemini --scope user     # ~/.gemini/skills/
llm-scanner-skill install --platform agents --scope project  # ./.agents/skills/
```

Gemini CLI reads `.agents/skills/` as an interop alias with precedence over
`.gemini/skills/`, so `--platform agents` covers Gemini, Claude Code and Codex at once.

```
/skills reload      # pick it up without restarting
```

## Extension settings

Gemini CLI does **not** pass your full shell environment to an extension — only standard
safe variables plus those declared in the manifest's `settings` array. Two are declared:

| Setting | Env var | Purpose |
|---|---|---|
| Ollama host | `OLLAMA_HOST` | Where the judge daemon is. Default `http://localhost:11434` |
| Scanner binary override | `LLM_SCANNER_BIN` | Explicit command that runs `llm-scanner`. Leave empty to auto-detect |

```bash
gemini extensions config llm-security-scanner
```

If the skill cannot find Ollama inside Gemini CLI but works in your shell, this
sanitization is why — set `OLLAMA_HOST` through the setting.

## Limitations vs Claude Code

- **No `userConfig` prompt-on-enable.** Gemini's `settings` array is the equivalent and is
  used above.
- **No plugin marketplace.** Install from the Git URL. Public extensions can be listed at
  [geminicli.com/extensions](https://geminicli.com/extensions).
- **Management commands need a restart**, unlike `/skills reload` for skills alone.
- **Extension policies cannot grant `allow`.** Gemini ignores `allow` decisions and `yolo`
  mode from an extension, so this extension ships no `policies/` — the authorization gate
  is enforced in the Python layer, where it cannot be configured away.
