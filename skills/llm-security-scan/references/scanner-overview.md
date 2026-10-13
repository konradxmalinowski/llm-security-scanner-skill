# How the scanner works

`llm-security-scanner` is a standalone CLI (`llm-scanner`). This skill wraps it; it does
not replace or re-implement any of it.

## Pipeline

```
llm-scanner
  ├─ Preflight            Ollama reachable? judge model pulled? target reachable?
  │                       judge model != target model (no self-judging)
  ├─ YamlPayloadLoader    payloads/ → 51+ payloads across LLM01-LLM10
  ├─ TargetFactory
  │    ├─ HttpTarget      httpx AsyncClient → POST {"prompt": …}
  │    └─ OllamaTarget    ollama AsyncClient → local model; auto-injects a canary
  ├─ LLMScanner           asyncio.Semaphore (default 3 concurrent), Rich progress
  │    ├─ OllamaJudge     local model, temperature 0, structured JSON verdict
  │    ├─ Detectors       canary match · secret regex+entropy · prompt n-gram overlap
  │    │                  (pure, zero I/O, zero LLM calls)
  │    └─ reconcile()     judge + detectors → outcome · confidence · verdict_source
  └─ Reporters            terminal · md · txt · json · html · sarif
```

Two models are always involved and must differ: the **target** (under test) and the
**judge** (evaluates each response). The scanner refuses to let a model judge itself.

## Everything is local

No request leaves the machine except to the target. The judge is a local Ollama model.
That is what makes this runnable in an air-gapped environment, and why `ollama serve`
plus one pulled model is a hard prerequisite.

## CLI surface this skill uses

```
llm-scanner --target <url|model> --target-type {url,ollama} --judge-model <model>
            [--config llm-scan.yml] [--categories LLM01,LLM07] [--severity medium]
            [--format md,json,html,txt,sarif] [--output-dir ./reports]
            [--api-key TOKEN] [--fail-on-score 7.0] [--fail-on-judge-error]
            [--include-dos-tests] [--concurrency N] [--retries N]
            [--canary TOKEN] [--system-prompt "text"|@path]
            [--suppressions file.yml] [--payloads-dir dir/] [--targets targets.yml]
            [--log-level LEVEL] [--log-file path] [--include-raw-artifacts]

llm-scanner baseline save --name production
llm-scanner baseline compare --name production
llm-scanner judge-eval --judge <model> [--min-kappa 0.4] [--json out.json]
```

Never pass `--include-raw-artifacts`. It disables the default redaction of detected
secrets, and these reports end up in CI logs and agent context.

## Output layout

Each run writes its own timestamped folder:

```
reports/
├── 20260713T120000_http_localhost_8000_chat/
│   ├── report.json      ← the machine interface; this skill parses it
│   ├── report.sarif     ← for GitHub code scanning
│   ├── report.html      ← for humans
│   ├── report.md
│   └── metrics.json     ← latency and counts for this run
├── audit.jsonl          ← append-only record of every scan ever run
├── index.html           ← trend dashboard, regenerated after each scan
└── baselines/           ← saved baselines
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan ran; no configured threshold breached |
| 1 | Risk score ≥ `--fail-on-score`, **or** a setup/validation error |
| 2 | `--fail-on-judge-error` and at least one attack was not evaluated |
| 130 | Interrupted |

Code 1 is overloaded, which is why this skill reads `report.json` rather than inferring
from the exit code alone: a report that exists means the scan ran.

## Risk score

Sum of severity weights over **successful** attacks, capped at 10.0:
`critical 4.0 · high 2.5 · medium 1.5 · low 0.5 · info 0.0`.

Findings the judge could not evaluate contribute **zero**. So on any scan with
`inconclusive > 0`, the risk score is a lower bound - state that explicitly.
