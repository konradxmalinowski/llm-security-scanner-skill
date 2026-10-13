# The MCP server

For agents that can call tools but **cannot run a shell**. If your platform can run the
`scripts/`, use those instead — they are the same code with one less moving part.

```bash
uv pip install 'llm-security-scanner-skill[mcp]'
llm-scanner-skill mcp          # stdio transport
```

## Tools

| Tool | Does | Maps to |
|---|---|---|
| `inspect_llm_application` | Maps a project's LLM attack surface (read-only) | `inspect` |
| `list_scan_categories` | The ten categories and their opt-in status | `categories` |
| `check_authorization` | Classify a target; may it be scanned? | `authorize` |
| `generate_scan_config` | Build a valid `llm-scan.yml` | `init-config` |
| `validate_scan_config` | Check a config against the real schema | `validate-config` |
| `scan_target` | **Run the real scanner**; returns an envelope | `scan` |
| `summarize_findings` | Parse an existing `report.json` | `summarize` |
| `get_remediation_guidance` | Fix guidance for a category | `remediate` |
| `compare_scan_results` | Before/after diff | `compare` |
| `read_report_excerpt` | One finding's full evidence, fenced as data | — |
| `server_info` | Versions and health | `doctor` |

Every one is a few lines that validate input and call the same `llm_scanner_skill`
function the CLI calls, which calls the real `llm-scanner`. No scanning logic lives in
the MCP layer.

## Client configuration

Claude Code — already wired when the plugin is installed. Standalone:

```json
{
  "mcpServers": {
    "llm-security-scanner": {
      "command": "llm-scanner-skill",
      "args": ["mcp"]
    }
  }
}
```

Gemini CLI — in `gemini-extension.json` (the bundled extension already includes it):

```json
{
  "mcpServers": {
    "llm-security-scanner": {
      "command": "llm-scanner-skill",
      "args": ["mcp"],
      "cwd": "${extensionPath}"
    }
  }
}
```

Codex — in `~/.codex/config.toml`:

```toml
[mcp_servers.llm-security-scanner]
command = "llm-scanner-skill"
args = ["mcp"]
```

## Safety boundaries the server enforces

- `scan_target` runs the authorization gate first. `authorized` defaults to `false`, so a
  non-loopback target is refused until the caller sets it — which it must only do after
  the user confirms ownership.
- Third-party provider endpoints are refused regardless of `authorized`.
- `check_authorization` always reports as if unauthorized, so it is safe to call for
  classification without granting anything.
- Every string that originated from a target is sanitized; `read_report_excerpt` also
  fences it in an unguessable delimiter block and labels it as data.
- `--include-raw-artifacts` is not exposed. Secrets stay redacted.
- Results are capped (default 15 findings) so one call cannot flood the context.

## Reading `scan_target` results

Identical envelope to the CLI: check `status` first, then `summary`, then per-finding
`evidence_class`. See the tables in `SKILL.md`. `reports` holds on-disk paths for the
full JSON/HTML/SARIF.
