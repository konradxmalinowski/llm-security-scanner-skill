# Example: a GitHub Actions security gate

End-to-end, with the reasoning behind each choice. Platform variants:
[references/ci-cd.md](../references/ci-cd.md).

## 1. Measure before gating

```bash
scripts/scan.py --target http://localhost:8000/chat --target-type url \
  --judge-model llama3.2:3b --categories LLM01,LLM02,LLM05,LLM07
```

Say the score came out 5.5. Set the gate at 6.0 — above today's reality, so the build is
not red on day one, and ratchet it down as findings are fixed. A threshold you never
measured either blocks everything or nothing.

## 2. The workflow

```yaml
name: LLM Security
on:
  pull_request:
  schedule: [{ cron: "0 3 * * 1" }]   # full sweep weekly

jobs:
  llm-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    permissions:
      contents: read
      security-events: write          # to upload SARIF
    steps:
      - uses: actions/checkout@v7

      # Cache first: pulling a 2 GB judge model every run is the main cost.
      - uses: actions/cache@v4
        with:
          path: ~/.ollama/models
          key: ollama-llama3.2-3b

      # The target is a container this workflow starts: disposable, and
      # --authorized is legitimate because we created it.
      - name: Start the app
        run: |
          docker compose up -d app
          timeout 60 bash -c 'until curl -sf http://localhost:8000/health; do sleep 2; done'

      - name: Install Ollama and the judge
        run: |
          curl -fsSL https://ollama.com/install.sh | sh
          ollama serve &
          timeout 60 bash -c 'until curl -sf http://localhost:11434/api/version; do sleep 2; done'
          ollama pull llama3.2:3b

      - run: pip install llm-security-scanner-skill

      - name: Scan
        id: scan
        run: |
          llm-scanner-skill scan \
            --target http://localhost:8000/chat --target-type url \
            --judge-model llama3.2:3b \
            --categories LLM01,LLM02,LLM05,LLM07 \
            --severity medium \
            --format json,sarif \
            --fail-on-score 6.0 \
            --output-dir llm-scan-reports \
            --authorized \
            | tee envelope.json

      # if: always() — the reports matter most on the run that failed.
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: llm-scan-reports

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: llm-scan-reports
          path: |
            llm-scan-reports/
            envelope.json
```

## 3. Why these flags

| Flag | Why |
|---|---|
| `--categories LLM01,LLM02,LLM05,LLM07` | What `inspect` recommended. A full sweep on every PR wastes runner minutes |
| `--severity medium` | Drops informational noise from PR comments |
| `--format json,sarif` | JSON for the envelope, SARIF for the Security tab |
| `--fail-on-score 6.0` | Measured in step 1, not guessed |
| `--authorized` | The target is a container this workflow started |
| *no* `--include-dos-tests` | LLM10 stresses the target; never in shared CI |

`llm-scanner-skill scan` defaults `--fail-on-judge-error` **on**, so a scan whose judge
failed reports `completed_untrustworthy` rather than passing green.

## 4. Reading the gate in the PR

Check `status` in `envelope.json`:

- `completed` → pass.
- `completed_with_threshold_breach` → the gate fired. Summarize the findings by evidence
  class; do not just paste the score.
- `completed_untrustworthy` → the judge failed on some attacks. **This is not a pass.**
  Usually the model was evicted from VRAM — add `--concurrency 1`.
- `blocked` → the authorization gate refused. Check the target in the workflow.

## 5. A nightly full sweep

```yaml
  full-sweep:
    if: github.event_name == 'schedule'
    # ... same setup ...
      - run: |
          llm-scanner-skill scan --target http://localhost:8000/chat --target-type url \
            --judge-model llama3.2:3b --output-dir llm-scan-reports --authorized
          # all of LLM01-LLM09; still no LLM10
```

## 6. Guard the judge itself

```yaml
  judge-quality:
    if: github.event_name == 'schedule'
    steps:
      # ... Ollama setup ...
      - run: llm-scanner judge-eval --judge llama3.2:3b --min-kappa 0.4
```

Catches an Ollama or model upgrade silently degrading every verdict in the pipeline — the
failure mode that would otherwise make the whole gate meaningless without anyone noticing.
