# LLM Security Scanner - AI Skill

[![CI](https://github.com/konradxmalinowski/llm-security-scanner-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/konradxmalinowski/llm-security-scanner-skill/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/llm-security-scanner-skill)](https://pypi.org/project/llm-security-scanner-skill/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A portable [Agent Skill](https://agentskills.io) that lets Claude, Gemini, Codex and
other AI coding agents run [**llm-security-scanner**](https://github.com/konradxmalinowski/llm-security-scanner)
against an LLM application you operate - then interpret the findings honestly and help
fix them.

It is not a second scanner. The engine, the 51+ OWASP payloads, the Ollama judge, the
deterministic detectors and every report format stay in `llm-security-scanner`, which
this package depends on and invokes through its CLI.

---

## What it adds on top of the scanner

The scanner is a good CLI and a poor agent interface. Five things were missing:

| | Why the raw CLI is not enough for an agent |
|---|---|
| **Attack-surface inspection** | "Scan my app" is not actionable. `inspect` reads the project, decides whether an LLM exists at all, names its shape (chatbot / RAG / tool-using agent / MCP server) and derives which OWASP categories apply, with `file:line` evidence |
| **An authorization gate** | An agent must not be able to point 51 adversarial payloads at an arbitrary host. Non-loopback targets are refused without explicit consent; third-party provider endpoints are refused outright |
| **Output sanitization** | The scanner's whole job is prompt-injecting a target, so its reports transcribe attacker-influenced text. Feeding that raw into an agent's context hands control of the agent to the thing it was auditing |
| **A versioned result envelope** | `report.json` has no run-level status, so "no findings" and "never ran" look alike. The envelope adds `status`, and maps `verdict_source` onto an explicit evidence class |
| **Honest interpretation** | A 1.00 canary proof and a 0.50 rule/judge conflict must not become the same sentence. The skill carries the vocabulary that keeps them apart |

## How it fits together

```
Claude Code · Gemini CLI · Codex · any MCP or tool-calling agent
        │
        ├── skills/llm-security-scan/        ONE canonical Agent Skill
        │     SKILL.md · references/ · workflows/ · scripts/ · examples/
        │
        └── llm_scanner_skill  (this package)
              inspect · authz · config · adapter · sanitize · summarize
              compare · remediation · mcp_server
                        │
                        ▼
              llm-scanner CLI          ← the real scanner, unmodified
                        │
                        ├── target adapter (HTTP · Ollama)
                        ├── payload engine (LLM01-LLM10)
                        ├── Ollama judge + deterministic detectors
                        └── reporters (json · sarif · html · md · txt)
```

All three platforms now implement the same [agentskills.io](https://agentskills.io/specification)
standard, and all three read `.agents/skills/`. So there is exactly **one** skill
directory; the platform adapters are install manifests, not copies. A test asserts
there is never more than one `SKILL.md` in the repo.

## Install

```bash
uv pip install llm-security-scanner-skill          # pulls in the scanner
uv pip install 'llm-security-scanner-skill[mcp]'   # plus the MCP server

ollama serve &                 # the judge runs locally - nothing leaves your machine
ollama pull llama3.2:3b

llm-scanner-skill doctor       # check all three prerequisites
```

Then install the skill for your agent:

| Platform | Command | Details |
|---|---|---|
| **Claude Code** | `/plugin marketplace add konradxmalinowski/llm-security-scanner-skill` then `/plugin install llm-security-scanner@llm-security` | [platforms/claude](platforms/claude/README.md) |
| **Gemini CLI** | `gemini extensions install https://github.com/konradxmalinowski/llm-security-scanner-skill` | [platforms/gemini](platforms/gemini/README.md) |
| **Codex / ChatGPT** | `llm-scanner-skill install --platform codex` | [platforms/codex](platforms/codex/README.md) |
| **Any agent** | `llm-scanner-skill install --platform agents` | [platforms/generic](platforms/generic/README.md) |

`--platform agents` installs into `.agents/skills/`, which Claude Code, Gemini CLI **and**
Codex all read - one install covers all three.

Full instructions, Docker, and air-gapped notes: **[docs/INSTALL.md](docs/INSTALL.md)**.

## Use it

Activation is automatic on a matching request:

> "Review my chatbot for OWASP LLM risks."
> "Check this RAG pipeline for prompt injection."
> "Scan the local app on :8000 before release."
> "Analyze this scanner report and fix the high-severity findings."
> "Re-scan after the patch and tell me what changed."
> "Add an LLM security gate to GitHub Actions."

The agent then works through: inspect → authorize → configure → scan → interpret →
remediate → re-scan → compare. Worked examples:
[`skills/llm-security-scan/examples/`](skills/llm-security-scan/examples/).

### Or drive it yourself

```bash
# 1. Is there even an LLM here, and which categories apply?
llm-scanner-skill inspect ./my-app

# 2. May this target be scanned?
llm-scanner-skill authorize --target http://localhost:8000/chat --target-type url

# 3. Scan (loopback needs no --authorized; anything else does)
llm-scanner-skill scan --target http://localhost:8000/chat --target-type url \
  --judge-model llama3.2:3b --categories LLM01,LLM05,LLM07

# 4. Fix, re-scan, then prove it worked
llm-scanner-skill remediate LLM07
llm-scanner-skill compare reports/<before>/report.json reports/<after>/report.json
```

Every subcommand prints JSON on stdout and human notes on stderr.

## Reading results without overstating them

Each finding carries an `evidence_class`, mapped from the scanner's own
`verdict_source`:

| Class | Means | Say |
|---|---|---|
| `confirmed` | A canary token appeared verbatim - proof by string match | "Confirmed" |
| `likely` | A deterministic detector and the judge agree | "Likely" |
| `heuristic` | One local LLM's opinion | "Possible, needs verification" |
| `needs_review` | A rule fired but the judge disagreed | "Conflicting evidence" |
| `inconclusive` | No verdict was reached - **not a pass** | "Could not be evaluated" |

And a run-level `status`, because a scan whose judge died is not a clean bill of health:
`completed` · `completed_with_threshold_breach` · `completed_untrustworthy` · `blocked` ·
`failed` · `scanner_not_found`.

## Safety model

Enforced in Python, not in prompt text, so it holds even if an agent ignores its
instructions:

- **Loopback and local Ollama models** scan freely. **Anything else** requires an explicit
  `--authorized`, which an agent may set only after the user confirms ownership.
- **Third-party provider endpoints** (`api.openai.com`, `api.anthropic.com`, …) are
  refused unconditionally - `--authorized` does not unlock them.
- **LLM10 DoS probes** need `--authorized` even on localhost.
- **Secrets stay redacted.** `--include-raw-artifacts` is never passed and is not exposed
  over MCP.
- **All target output is sanitized** - control tokens and tool-call syntax have their
  literal byte sequences broken, injection phrases are labelled, zero-width and bidi
  characters and ANSI escapes are stripped, residual credentials are redacted, and the
  text is truncated and fenced in an unguessable delimiter block.

Details: **[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)**.

## Documentation

| | |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Prerequisites, every platform, Docker, air-gapped |
| [docs/PLATFORMS.md](docs/PLATFORMS.md) | What each platform supports, with sources, and the exact gaps |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component map, the result envelope, how the scanner is invoked |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Threat model and every control |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | What this cannot do, stated plainly |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development, tests, releases |
| [skills/llm-security-scan/SKILL.md](skills/llm-security-scan/SKILL.md) | The skill itself |

## Limitations

Honestly, up front - the long version is [docs/LIMITATIONS.md](docs/LIMITATIONS.md):

- **A scan samples behaviour; it does not prove absence.** LLMs are non-deterministic.
- **The judge is a small local model** with measurable error. `llm-scanner judge-eval`
  quantifies it; nothing removes it.
- **Categories you do not select are untested, not safe.**
- **Behavioural only.** LLM03 (supply chain) and LLM05 (output handling) verdicts need a
  code read to be actionable - the report says what the model *did*, not whether your app
  renders or executes it.
- **A running target is required.** No LLM component, or nothing reachable, means nothing
  to scan, and the skill will say so rather than inventing findings.
- **Ollama is a hard prerequisite**, including in CI.

## License

MIT. See [LICENSE](LICENSE).

The scanner it wraps, [llm-security-scanner](https://github.com/konradxmalinowski/llm-security-scanner),
is also MIT.
