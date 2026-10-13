# Installation

## Prerequisites

| Requirement | Why |
|---|---|
| Python 3.11+ | The scanner requires it |
| [`llm-security-scanner`](https://pypi.org/project/llm-security-scanner/) ≥ 0.8.0 | The actual engine. Installed automatically as a dependency |
| [Ollama](https://ollama.com) + one pulled model | The AI judge. **Hard requirement** — there is no cloud fallback by design |
| A reachable target | A running LLM app, or a local Ollama model |

```bash
uv pip install llm-security-scanner-skill          # or: pip install …
uv pip install 'llm-security-scanner-skill[mcp]'   # plus the MCP server

ollama serve &
ollama pull llama3.2:3b     # ~2 GB; a good default judge

llm-scanner-skill doctor    # verifies all three
```

`doctor` is the single check that matters. It reports on the scanner CLI, Ollama, and the
bundled skill, and exits non-zero if any is unusable.

### Where the skill finds the scanner

In order:

1. `$LLM_SCANNER_BIN` — an explicit override. Accepts a multi-word shim, so
   `export LLM_SCANNER_BIN="docker run --rm --network host ghcr.io/konradxmalinowski/llm-security-scanner:latest"`
   works.
2. `llm-scanner` on `PATH` — the normal install.
3. The current interpreter, if `llm_scanner` is importable. Covers a venv whose `bin/` is
   off `PATH`, which is common when an agent runs in one environment and the scanner
   lives in another.

If all three fail, every command returns a JSON error naming the install step — never a
traceback.

---

## Claude Code

### As a plugin (recommended — also wires the MCP server)

```
/plugin marketplace add konradxmalinowski/llm-security-scanner-skill
/plugin install llm-security-scanner@llm-security
```

```bash
uv pip install 'llm-security-scanner-skill[mcp]'
```

The skill appears as `llm-security-scanner:llm-security-scan`. Verify with `/plugin`.

### Skill only

```bash
llm-scanner-skill install --platform claude --scope user     # ~/.claude/skills/
llm-scanner-skill install --platform claude --scope project  # ./.claude/skills/ (committable)
```

### From a clone

```bash
git clone https://github.com/konradxmalinowski/llm-security-scanner-skill
cd llm-security-scanner-skill && uv pip install -e ".[dev]"
claude --plugin-dir .
```

More: [platforms/claude/README.md](../platforms/claude/README.md).

---

## Gemini CLI

```bash
gemini extensions install https://github.com/konradxmalinowski/llm-security-scanner-skill
uv pip install 'llm-security-scanner-skill[mcp]'
```

Restart the CLI — extension changes need a new session. Then `/skills list` and
`/llm-security-scan ./my-app`.

**Gemini sanitizes the environment**: an extension receives only standard safe variables
plus those declared in the manifest. `OLLAMA_HOST` and `LLM_SCANNER_BIN` are declared for
exactly this reason. If the skill cannot find Ollama inside Gemini CLI but works in your
shell, that is why:

```bash
gemini extensions config llm-security-scanner
```

Skill only, no extension:

```bash
llm-scanner-skill install --platform gemini --scope user
# then, in the CLI:  /skills reload
```

More: [platforms/gemini/README.md](../platforms/gemini/README.md).

---

## Codex / ChatGPT

```bash
llm-scanner-skill install --platform codex --scope user     # ~/.agents/skills/
llm-scanner-skill install --platform codex --scope project  # ./.agents/skills/
```

Codex discovers skills from `$CWD/.agents/skills` (and each parent up to the repo root),
then `$HOME/.agents/skills`, then `/etc/codex/skills`. Confirm with `/skills`; invoke
explicitly with `$llm-security-scan`.

Optional, in `~/.codex/config.toml`:

```toml
[[skills.config]]
name = "llm-security-scan"
enabled = true

[mcp_servers.llm-security-scanner]
command = "llm-scanner-skill"
args = ["mcp"]
```

More: [platforms/codex/README.md](../platforms/codex/README.md).

---

## Any other agent

```bash
llm-scanner-skill install --platform agents --scope project   # ./.agents/skills/
```

`.agents/skills/` is the shared interop path. If the platform has no skill mechanism, use
the MCP server or the generated function declarations in
[platforms/generic/tools.json](../platforms/generic/tools.json), plus
[platforms/generic/system-prompt.md](../platforms/generic/system-prompt.md).

More: [platforms/generic/README.md](../platforms/generic/README.md).

---

## Install modes

```bash
llm-scanner-skill install --platform all --scope user          # every platform at once
llm-scanner-skill install --platform agents --mode copy        # self-contained
llm-scanner-skill install --platform agents --force            # replace an existing install
llm-scanner-skill uninstall --platform all --scope user
```

`--mode symlink` (default) keeps the installed skill tracking the source, which is what
you want while developing it. `--mode copy` is self-contained — right for a wheel install
or a container image. `--platform all` installs every path; `claude` and `codex` resolve
to the same `.agents` location, and the second is reported as already installed rather
than as an error.

---

## Docker

```bash
docker build -t llm-scanner-skill .

docker run --rm --network host \
  -v "$PWD/reports:/reports" \
  llm-scanner-skill scan \
    --target http://localhost:8000/chat --target-type url \
    --judge-model llama3.2:3b --output-dir /reports
```

`--network host` lets the container reach both the target and Ollama on the host. Without
it, the image defaults `OLLAMA_HOST` to `http://host.docker.internal:11434` (Docker
Desktop); on Linux use `--add-host=host.docker.internal:host-gateway`.

The container does **not** bundle Ollama — run it on the host or as a second container.

---

## CI

CI must install and run Ollama on the runner, because the judge is local. Cache
`~/.ollama/models` or you pay a 2 GB download per build. Ready-made workflows:
[examples/ci/](../examples/ci/), with the reasoning in
[skills/llm-security-scan/references/ci-cd.md](../skills/llm-security-scan/references/ci-cd.md).

---

## Air-gapped

Everything except the target runs locally, so this works offline once three things are
present:

1. The wheels: `pip download llm-security-scanner-skill -d ./wheels` on a connected
   machine, then `pip install --no-index --find-links ./wheels llm-security-scanner-skill`.
2. The judge model: `ollama pull llama3.2:3b` on a connected machine, then copy
   `~/.ollama/models`.
3. The target, reachable from the scanner.

No telemetry, no cloud judge, no outbound request other than to the target itself.

---

## Upgrading

```bash
uv pip install --upgrade llm-security-scanner-skill
llm-scanner-skill doctor
```

A `--mode symlink` install needs no re-install. A `--mode copy` install does:

```bash
llm-scanner-skill install --platform <p> --scope <s> --mode copy --force
```

A nightly contract job in this repo tests the skill against the latest scanner release
and opens an issue if the contract breaks, so a scanner upgrade that would invalidate the
adapter is caught upstream rather than in your terminal.

---

## Troubleshooting

`llm-scanner-skill doctor` first. Then
[skills/llm-security-scan/references/troubleshooting.md](../skills/llm-security-scan/references/troubleshooting.md),
which covers every failure mode: scanner not found, Ollama down, model not pulled,
self-judging, HTTP 404 at preflight, all-inconclusive scans, slow scans, empty payload
filters, and both kinds of authorization refusal.
