# Configuration (`llm-scan.yml`)

This is the scanner's own config format (`llm_scanner.cli.ScanConfig`). Do not invent a
parallel one. Generate it with `scripts/init_config.py` and check it with
`scripts/validate_config.py`.

## Full schema

| Key | Type | Notes |
|---|---|---|
| `target` | str | URL or Ollama model name. Supports `${ENV_VAR}` |
| `target_type` | `url` \| `ollama` | |
| `judge_model` | str | Ollama model; must differ from an `ollama` target |
| `api_key` | str | Bearer token. **Always** `${ENV_VAR}`, never a literal |
| `categories` | str \| list | `LLM01,LLM07` or `[LLM01, LLM07]` |
| `severity` | str | Minimum: `critical`\|`high`\|`medium`\|`low`\|`info` |
| `output_dir` | path | Default `./reports` |
| `formats` | str \| list | `md`,`json`,`html`,`txt`,`sarif`. Keep `json` |
| `include_dos_tests` | bool | Required for LLM10; stresses the target |
| `fail_on_score` | float | 0.0-10.0; exit 1 at or above |
| `suppressions_file` | path | Accepted false positives |
| `payloads_dir` | path | Extra YAML payloads, loaded alongside the bundled set |

Any other key is **silently ignored** by the scanner (`extra="ignore"`), which is why
`validate_config.py` rejects unknown keys - it catches `judge-model` vs `judge_model`
before a long scan runs on a default you did not intend.

## Precedence

CLI flags beat config-file values. A flag left at its default does not override the
config, so a config can set `output_dir` while the CLI sets `--categories`.

## Examples

Local development:

```yaml
target: http://localhost:8000/chat
target_type: url
judge_model: llama3.2:3b
categories: [LLM01, LLM02, LLM05, LLM07]
formats: [json, html]
output_dir: ./reports
```

CI gate:

```yaml
target: ${LLM_ENDPOINT}
target_type: url
judge_model: llama3.2:3b
api_key: ${LLM_API_KEY}
categories: [LLM01, LLM02, LLM05, LLM07]
severity: medium
formats: [json, sarif]
output_dir: ./reports
fail_on_score: 7.0
```

Model comparison:

```yaml
target: mistral:7b
target_type: ollama
judge_model: llama3.2:3b
categories: [LLM01, LLM07, LLM09]
formats: [json, html]
```

## Category selection

Do not scan all ten by reflex. `scripts/inspect_target.py` returns
`recommended_categories` with a per-category rationale drawn from what it actually found
in the code - use that. A tool-less, retrieval-less chatbot has no LLM06 or LLM08 surface,
and scanning for them costs minutes and produces noise.

LLM10 is never auto-recommended: its probes stress the target and need explicit consent.

## Suppressions

```yaml
suppressions:
  - attack_id: "LLM09-*"          # exact ID or an fnmatch glob
    reason: "Creative-writing assistant; factual grounding is out of scope"
    expires: "2026-12-31"         # metadata only, not enforced
```

Suppressions are applied **after** the attack runs, so the evidence is still in the
report; only the risk score and labels change. Every entry needs a real reason - a
suppression with no justification is a silently accepted vulnerability.

## Multi-target comparison

```yaml
targets:
  - name: staging
    target: http://staging.internal:8000/chat
    target_type: url
    api_key: ${STAGING_TOKEN}
  - name: mistral-baseline
    target: mistral:7b
    target_type: ollama
```

Run with `--targets targets.yml` for a side-by-side table. Every non-loopback entry still
needs the user's authorization.
