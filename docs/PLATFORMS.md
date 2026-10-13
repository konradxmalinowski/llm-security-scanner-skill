# Platform support, and the exact gaps

Every claim here was verified against official documentation while building this, and
each is covered by a test in [`tests/test_platforms.py`](../tests/test_platforms.py).
Nothing is claimed as supported on the strength of a blog post.

## Sources

| Platform | Document |
|---|---|
| Agent Skills standard | <https://agentskills.io/specification> |
| Claude Code plugins | <https://code.claude.com/docs/en/plugins-reference> |
| Gemini CLI extensions | [`docs/extensions/reference.md`](https://github.com/google-gemini/gemini-cli/blob/main/docs/extensions/reference.md) |
| Gemini CLI skills | [`docs/cli/skills.md`](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/skills.md) |
| Codex / ChatGPT skills | <https://learn.chatgpt.com/docs/build-skills> |
| MCP Python SDK | <https://pypi.org/project/mcp/> (2.3.0) |

## The thing that makes this tractable

All three major agent platforms now implement the **same** open Agent Skills standard —
a directory with a `SKILL.md` carrying `name` and `description` frontmatter — and all
three read `.agents/skills/` as a shared interop path.

So this repository contains exactly **one** skill directory. The platform adapters are
install manifests and metadata, not forks of the knowledge. A test asserts the repo never
contains more than one `SKILL.md`.

## Capability matrix

| | Claude Code | Gemini CLI | Codex / ChatGPT | Generic |
|---|---|---|---|---|
| Agent Skills (`SKILL.md`) | ✅ native | ✅ native | ✅ native | ✅ if supported |
| Reads `.agents/skills/` | ✅ | ✅ (alias, higher precedence) | ✅ (primary) | — |
| Progressive disclosure | ✅ | ✅ | ✅ | ✅ |
| Bundled scripts | ✅ | ✅ | ✅ | needs shell |
| Plugin/extension package | ✅ `plugin.json` | ✅ `gemini-extension.json` | ❌ none exists | ❌ |
| Marketplace | ✅ `marketplace.json` | ⚠️ Git URL + public listing | ❌ | ❌ |
| Slash command | ⚠️ skills preferred | ✅ `commands/*.toml` | ❌ | ❌ |
| MCP server | ✅ | ✅ | ✅ | ✅ |
| Declared user settings | ✅ `userConfig` | ✅ `settings` array | ❌ | ❌ |
| Platform metadata file | — | — | ✅ `agents/openai.yaml` | — |
| Hooks | ✅ | ✅ | ❌ | ❌ |

✅ implemented · ⚠️ implemented with a caveat below · ❌ no platform equivalent exists

## Claude Code — fully native

The repository root *is* a plugin: `.claude-plugin/plugin.json`, the default-scanned
`skills/` directory, `.claude-plugin/marketplace.json`, and an `mcpServers` declaration.

`plugin.json` sets no `skills` key on purpose: `skills/` is Claude Code's default scan
location, and the manifest key *adds to* rather than replaces it, so declaring it would be
redundant.

Validated by `claude plugin validate . --strict` in CI when the CLI is available, and by
tests covering the reserved-name rules, the recognized-field set, the `./` path prefix
rule, the absence of a root `CLAUDE.md` (which `validate` warns about) and of a top-level
`bin/` (which blocks installation on claude.ai and Cowork).

## Gemini CLI — fully native

The same repository root is also a Gemini extension: `gemini-extension.json`, `GEMINI.md`
as its context file, the shared `skills/` directory, and `commands/llm-security-scan.toml`
for the slash command.

**Caveats, honestly:**

- **No marketplace.** Installation is from the Git URL. Public extensions can be listed at
  [geminicli.com/extensions](https://geminicli.com/extensions), which is a directory, not
  an install mechanism.
- **The environment is sanitized.** An extension receives only standard safe variables
  plus those declared in the manifest's `settings` array. `OLLAMA_HOST` and
  `LLM_SCANNER_BIN` are declared for exactly this reason; without that, the skill would
  fail to find Ollama inside Gemini CLI while working fine in a shell. A test asserts both
  stay declared.
- **Extension policies cannot grant `allow`.** Gemini deliberately ignores `allow`
  decisions and `yolo` mode from an extension. This extension therefore ships no
  `policies/` directory — the authorization gate lives in the Python layer, where it
  cannot be configured away. That is a better place for it regardless.
- **Management commands need a restart**, unlike `/skills reload` for skills alone.

## Codex / ChatGPT — native skill, no package format

Codex implements the same standard and reads `.agents/skills`, so the canonical skill is
natively Codex-ready. `skills/llm-security-scan/agents/openai.yaml` adds the optional
Codex metadata — display name, descriptions, the desktop app's default prompt,
`policy.allow_implicit_invocation`, and the optional MCP dependency. Claude Code and
Gemini CLI ignore that file, which is what lets one directory serve all three.

**What does not exist, and therefore is not implemented:**

- **No plugin or marketplace equivalent.** Distribution is the PyPI package plus
  `llm-scanner-skill install`, or a committed `.agents/skills/` directory. There is no
  format to target, so none is invented.
- **No hooks or monitors.**
- **Duplicate skill names are not merged** — two installs in different tiers can both
  appear. Install into one scope.

Codex caps the startup skill list at 2% of the context window (8 000 characters if
unknown), shortening descriptions and omitting skills from large sets. This skill's
description is ~580 characters and its `SKILL.md` body is ~150 lines, with the detail in
`references/`. A test enforces both bounds.

## Generic — three levels

1. **Agent Skills standard** — copy the skill directory. That is the whole integration.
2. **MCP** — `llm-scanner-skill mcp`, 11 tools, plus
   [`platforms/generic/system-prompt.md`](../platforms/generic/system-prompt.md), since an
   MCP server alone conveys no workflow.
3. **Tool calling only** — [`platforms/generic/tools.json`](../platforms/generic/tools.json)
   holds OpenAI/Gemini-compatible function declarations, **generated** from the MCP
   server's own definitions by `tools/gen_tools_json.py`. CI fails if the committed file
   drifts, so the two can never disagree.

## Platforms deliberately NOT claimed

| Platform | Why not |
|---|---|
| GitHub Copilot | No Agent Skills support and no public reusable-skill package format at the time of writing. Copilot can still run the CLI from a terminal, but that is not an integration and is not presented as one |
| Cursor / Windsurf / Zed | They read instruction files, so the generic path applies, but none has been tested here. Untested is not supported |
| Hosted ChatGPT without Codex | The skill needs to execute the scanner. A hosted chat with no shell and no MCP cannot |
| LangChain / LlamaIndex agents | Would work through `tools.json`, but no adapter has been written or tested |

If you integrate one of these, the generic layer is the place to start — and the
authorization gate and sanitizer come along automatically, because they are enforced in
Python rather than in prompt text.

## Why MCP is included, but optional

MCP was added for one reason, not because it is fashionable: the skill files require a
shell, and some agents have tool calling but no terminal. For those, MCP is the only path
to the scanner.

It is therefore a transport, not a second implementation. Each of the 11 tools validates
input and calls the same `llm_scanner_skill` function the CLI calls, which calls the real
`llm-scanner`. A test asserts no scanner logic (`OllamaJudge`, `LLMScanner`,
`run_detectors`, `reconcile`, `YamlPayloadLoader`) appears anywhere in the MCP layer, and
it stays an optional extra so a shell-capable platform never pays for it.

Surface: [skills/llm-security-scan/references/mcp.md](../skills/llm-security-scan/references/mcp.md).
