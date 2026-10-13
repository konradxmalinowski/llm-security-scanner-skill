# Security model

This project hands an AI agent a tool that fires 51+ adversarial payloads at an LLM
endpoint. Two risks follow, and both are addressed in code rather than in prompt text -
because an agent can ignore prompt text, and because a prompt-injected agent *will*.

## Risk 1 - the skill becomes an attack tool

**Control: the authorization gate** (`src/llm_scanner_skill/authz.py`), enforced by
`run_scan()` *before* the scanner is executed. A test asserts the scanner binary is never
invoked for a blocked target.

| Target class | Needs explicit authorization |
|---|---|
| `loopback` (localhost, 127.0.0.1, ::1) | No |
| `ollama_local` (a local model name) | No |
| `private` (RFC1918, link-local) | **Yes** |
| `external` (any public address) | **Yes** |
| `unknown` (unresolvable or ambiguous) | **Yes** |

Design decisions worth stating:

- **A hostname is only as local as its least-local address.** If any resolved IP is
  public, the target is `external`.
- **Resolution failure yields `unknown`, never `loopback`.** Ambiguity resolves *against*
  scanning.
- **Third-party provider endpoints are refused unconditionally.** `api.openai.com`,
  `api.anthropic.com`, `googleapis.com`, `mistral.ai`, `groq.com`, `bedrock.amazonaws.com`
  and others. `--authorized` does not unlock them, and the refusal sets
  `requires_ack: false` so an agent is not invited to ask. They are not the user's
  systems; scanning them breaches their terms and bills someone's account.
- **LLM10 DoS probes require authorization even on localhost.** The scanner has its own
  opt-in flag; this is a second, independent lock.
- **Production hostnames raise a warning** the agent must relay - computed before
  classification branches, so an internal production host that cannot be resolved still
  gets it. That is the case where it matters most.

What code cannot enforce is that the agent *asks* before setting `--authorized`. That is
stated in `SKILL.md`, `AGENTS.md`, `GEMINI.md`, the MCP server's instructions, the
parameter description, and `platforms/generic/system-prompt.md`. The gate is the backstop;
the instruction is the intent.

## Risk 2 - the target hijacks the agent

This is the sharp one. The tool prompt-injects a target on purpose, so **every target
response is attacker-influenced by construction**, and every report transcribes those
responses. An agent that pastes a raw response into its context has handed control of
itself to the thing it was auditing.

In the indirect categories (LLM01, LLM08) it is worse: the injection may have been planted
in a document store by someone who is not the user at all.

**Control: layered sanitization** (`src/llm_scanner_skill/sanitize.py`), applied at the
single boundary in `summarize.py` where report text becomes envelope text.

| Layer | Against | How |
|---|---|---|
| **Invisible** | Zero-width smuggling, bidi spoofing | Strip `U+200B-200F`, `U+202A-202E`, `U+2060-2069`, `U+FEFF`, tag characters. **First**, so the lexical pass cannot be bypassed by a zero-width character mid-token |
| **Escapes** | Terminal control, OSC 8/52 exfiltration | Strip ANSI CSI and OSC sequences |
| **Secrets** | A report becoming the leak | Redact residual prefixed credentials (the scanner already redacts what its own detectors found; this catches the rest) |
| **Control tokens** | `<\|im_start\|>`, `[INST]`, `### System:` read as a turn boundary | Label **and break the literal byte sequence** with an inserted middle dot |
| **Tool syntax** | `<invoke name=…>`, `{{…}}`, `/command` executing from a tool result | Label and break the literal sequence |
| **Injection phrases** | An LLM obeying "ignore all previous instructions" | Label. Deliberately *not* mangled - a model reads `i·gnore` fine, so the defence is the label plus the fence, and keeping it legible preserves triage |
| **Budget** | Megabytes of adversarial text crowding out instructions | Truncate to 1 200 characters per excerpt |
| **Fence** | Breaking out of the quoted block | Wrap in a delimiter with a random nonce the target cannot predict |

Two deliberate choices:

- **Breaking the literal sequence, not just labelling it.** Wrapping `<|im_start|>` in
  brackets leaves the exact string intact for any downstream parser scanning for it. The
  inserted dot removes it while the text still reads correctly. (A test asserts the
  literal is gone.)
- **Nothing is destroyed.** The untouched text stays in `report.json` on disk for a human
  to open deliberately. Only what crosses into a model's context is treated.

And the attempt is itself reported: `warnings` names what was neutralized, so the agent
tells the user "the target echoed injection markers" instead of silently hiding it.

## Secrets

- `--include-raw-artifacts` is **never** passed and is **not exposed** over MCP. Two tests
  enforce this. The scanner's default - detected secrets replaced by a per-run HMAC
  fingerprint - is exactly right when the output is headed for CI logs or an agent's
  context.
- Generated configs reference credentials as `${ENV_VAR}`, never inline. The scanner
  resolves them at run time and keeps them out of logs and error output.
- A CI job scans `examples/` for inline credential shapes and fails the build.
- `reports/` and `*.sarif` are gitignored: a report transcribes target responses.

## What the skill refuses to claim

- **A scan does not prove absence.** LLMs are non-deterministic; one scan is one sample.
- **Unselected categories are untested, not safe.** `SKILL.md` requires saying which.
- **`inconclusive` is not a pass.** Any such finding forces
  `status: completed_untrustworthy`, and the skill must not report that as clean.
- **The judge has measurable error.** `llm-scanner judge-eval` quantifies it against 32
  hand-labelled entries; nothing eliminates it.
- **LLM03 and LLM05 verdicts need a code read.** The report says what the model *did*, not
  whether your app renders or executes it.

## Reporting a vulnerability in this project

See [SECURITY.md](../SECURITY.md).
