# Architecture

## The separation this repository exists to make

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. SCANNER  (separate repo + PyPI package — unmodified)             │
│    llm-security-scanner: payloads, Ollama judge, detectors,         │
│    reconciliation, reporters, baselines, SARIF, judge-eval          │
└─────────────────────────────────────────────────────────────────────┘
                                 ▲  invoked through its CLI only
┌─────────────────────────────────────────────────────────────────────┐
│ 2. ADAPTER  src/llm_scanner_skill/   (this package)                 │
│    inspect · authz · config · adapter · sanitize · summarize ·      │
│    compare · remediation · install · cli · mcp_server               │
└─────────────────────────────────────────────────────────────────────┘
                                 ▲
┌─────────────────────────────────────────────────────────────────────┐
│ 3. KNOWLEDGE  skills/llm-security-scan/   (ONE canonical skill)     │
│    SKILL.md · references/ · workflows/ · scripts/ · examples/       │
└─────────────────────────────────────────────────────────────────────┘
                                 ▲
┌─────────────────────────────────────────────────────────────────────┐
│ 4. PLATFORM ADAPTERS  (manifests and metadata — never knowledge)    │
│    .claude-plugin/ · gemini-extension.json · commands/ ·            │
│    agents/openai.yaml · AGENTS.md · GEMINI.md · platforms/*/        │
└─────────────────────────────────────────────────────────────────────┘
```

Layers 1 and 2 are code. Layer 3 is the single source of knowledge. Layer 4 only tells
each platform where layer 3 lives.

## Why the scanner is invoked as a subprocess

The adapter shells out to `llm-scanner` rather than importing `llm_scanner.scanner`:

- **The CLI is the supported interface.** Its internals may change between releases; its
  flags are versioned. The contract tests assert against the CLI's parser, not its guts.
- **Not re-driving the engine is the point.** The CLI already owns preflight, payload
  loading, concurrency, the judge, the detectors, reconciliation, redaction and every
  reporter. Importing and orchestrating those would duplicate exactly what must not be
  duplicated.
- **Isolation.** A scan that hangs or crashes cannot take the agent's process with it, and
  a subprocess gives a hard timeout.

`adapter.py` is the only module that executes anything. Everything else reads its output.

## The result envelope

`report.json` is the right artifact for humans and CI and the wrong one for an agent:

1. **No run-level status.** A scan that aborted in preflight writes no report at all, so
   an agent reading only the report cannot tell "no findings" from "never ran".
2. **Raw target responses.** Feeding those verbatim into an agent's context is the
   injection vector this project studies.
3. **No schema version.** An agent cannot detect drift.

`ResultEnvelope` wraps rather than replaces it. Findings keep the scanner's own field
names, and `reports` points at the untouched files for full fidelity.

```jsonc
{
  "schema_version": "1.0",
  "status": "completed_untrustworthy",   // the field to read first
  "target": "http://localhost:8000/chat",
  "target_type": "url",
  "judge_model": "llama3.2:3b",
  "categories_requested": ["LLM01", "LLM07"],
  "categories_scanned":  ["LLM01", "LLM07"],
  "summary": {
    "risk_score": 7.5, "total_attacks": 31,
    "vulnerable": 4, "safe": 26, "inconclusive": 1, "suppressed": 0,
    "by_severity": {"high": 3, "critical": 1},
    "by_category": {"LLM01": 2, "LLM07": 2},
    "by_evidence_class": {"confirmed": 1, "likely": 2, "heuristic": 1, "inconclusive": 1}
  },
  "findings": [{
    "attack_id": "LLM07-001", "owasp_category": "LLM07", "severity": "high",
    "outcome": "vulnerable",                  // scanner's own vocabulary
    "verdict_source": "rule_proof",           // scanner's own vocabulary
    "confidence_score": 1.0,
    "evidence_class": "confirmed",            // the skill's addition
    "cwe_ids": ["CWE-200", "CWE-522"],
    "cvss_vector": "CVSS:3.1/AV:N/...", "cvss_score": 7.5,
    "payload_excerpt": "…", "evidence": "…",  // SANITIZED, truncated
    "judge_reasoning_excerpt": "…",
    "artifact_types": ["canary"]
  }],
  "reports": {"json": "...", "html": "...", "sarif": "...", "metrics": "..."},
  "scanner_version": "0.8.0",
  "exit_code": 0,
  "warnings": [], "errors": [], "blocked_reason": ""
}
```

### `verdict_source` → `evidence_class`

The mapping that stops an agent overstating a result. A contract test asserts every
`VerdictSource` the scanner can emit is mapped, so a new one cannot slip through
unclassified.

| Scanner | Skill | Why |
|---|---|---|
| `rule_proof` | `confirmed` | Canary matched verbatim — proof by string comparison |
| `both_agree` | `likely` | Rule and judge agree |
| `judge_only` | `heuristic` | One small local model's opinion |
| `judge_degraded` | `heuristic` | Same, via a fallback parser |
| `conflict` | `needs_review` | Rule fired, judge disagreed — surfaced, never resolved |
| `judge_error` | `inconclusive` | No verdict reached. Not a pass |

`outcome == "error"` forces `inconclusive` regardless of source: there is no verdict to be
confident about.

### `status` is not the exit code

The scanner's exit code 1 is overloaded (threshold breach *or* setup error), so status is
derived from the report plus the exit code. One rule matters most: **any
`inconclusive > 0` forces `completed_untrustworthy`, even on exit 0.** A scan whose judge
partly failed is not a clean result, and the adapter will not let it render as one.

## Module responsibilities

| Module | Does | Never does |
|---|---|---|
| `envelope.py` | The versioned schema; `verdict_source` → `evidence_class` | I/O |
| `authz.py` | Target classification; the authorization gate | Network scanning |
| `sanitize.py` | Neutralizes untrusted text; fences it | Destroy the on-disk report |
| `inspect.py` | Static attack-surface mapping | Import or execute project code |
| `config.py` | Builds/validates the scanner's **own** config schema | Define a parallel schema |
| `adapter.py` | Finds the scanner, builds argv, runs it, wraps the result | Reimplement scanning |
| `summarize.py` | `report.json` → sanitized envelope | Invent findings |
| `compare.py` | Attack-keyed before/after diff | Average away a regression |
| `remediation.py` | Fix guidance, reading the scanner's category metadata | Hardcode recommendations |
| `install.py` | Places the one skill in each platform's path | Fork the skill |
| `cli.py` | JSON on stdout, notes on stderr | Business logic |
| `mcp_server.py` | MCP transport over the above | Business logic |

## Guardrails against drift

The adapter is thin only because drift is detected rather than hoped against.

- **`tests/test_contract.py`** asserts, against the *installed* scanner: every CLI flag the
  adapter emits exists; every `VerdictSource` is mapped; `CONFIG_KEYS` equals
  `ScanConfig.model_fields` exactly; every report field read still exists; every category
  has ≥ 4 payloads; the reporter format set matches. It even builds a real `ScanReport`
  with the scanner's own models and parses it.
- **`.github/workflows/contract-nightly.yml`** runs those tests against the *latest*
  scanner release nightly and opens an issue on failure — so a scanner release that breaks
  the contract is caught without a commit here.
- **`tests/test_platforms.py`** validates every platform manifest against its published
  format, checks that no referenced file is missing, and asserts exactly one `SKILL.md`
  exists.
- **`platforms/generic/tools.json`** is generated from the MCP server; CI fails if the
  committed file drifts.
- **Release** verifies the version matches across `pyproject.toml`, `plugin.json`,
  `gemini-extension.json`, `__init__.py` and `SKILL.md`, and that the wheel really bundles
  the skill.

## Token budget

| Stage | Cost | What loads |
|---|---|---|
| Startup | ~150 tokens | `name` + `description` only |
| Activation | ~2 000 tokens | The `SKILL.md` body (~150 lines) |
| On demand | 1 000–3 000 each | One `references/` or `workflows/` file |

Tests enforce the budget: `SKILL.md` ≤ 500 lines, each reference ≤ 250 lines, each script
≤ 25 lines, and the always-in-context `AGENTS.md`/`GEMINI.md` ≤ 80 lines each.
