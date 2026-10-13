# CI/CD integration

The constraint that shapes everything: the judge is a local Ollama model, so **CI must
install and run Ollama on the runner**. Pulling a 2 GB model on every build is the main
cost — cache it.

## Exit codes to gate on

| Code | Meaning | Gate |
|---|---|---|
| 0 | Ran, no threshold breached | pass |
| 1 | Risk score ≥ `--fail-on-score`, or a setup error | fail |
| 2 | `--fail-on-judge-error` and some attacks unevaluated | fail — results untrustworthy |

Always set `--fail-on-judge-error`. A green build from a scan whose judge was down is
worse than a red one.

## GitHub Actions

The scanner repo ships a composite action at `.github/actions/llm-scan`:

```yaml
name: LLM Security
on:
  pull_request:
  schedule: [{ cron: "0 3 * * 1" }]

jobs:
  llm-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    permissions:
      contents: read
      security-events: write        # required to upload SARIF
    steps:
      - uses: actions/checkout@v7

      - name: Start the application under test
        run: |
          docker compose up -d app
          timeout 60 bash -c 'until curl -sf http://localhost:8000/health; do sleep 2; done'

      - uses: konradxmalinowski/llm-security-scanner/.github/actions/llm-scan@v0.8.0
        id: scan
        with:
          target: http://localhost:8000/chat
          target-type: url
          judge-model: llama3.2:3b
          categories: LLM01,LLM02,LLM05,LLM07
          severity: medium
          fail-on-score: "7.0"
          output-dir: llm-scan-reports

      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: llm-scan-reports

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: llm-scan-reports
          path: llm-scan-reports/
```

`if: always()` on both upload steps matters: the reports are most useful on the run that
failed.

### Cache the judge model

```yaml
      - uses: actions/cache@v4
        with:
          path: ~/.ollama/models
          key: ollama-llama3.2-3b
```

## Doing it by hand

```yaml
      - run: |
          curl -fsSL https://ollama.com/install.sh | sh
          ollama serve &
          timeout 60 bash -c 'until curl -sf http://localhost:11434/api/version; do sleep 2; done'
          ollama pull llama3.2:3b

      - run: uv pip install --system llm-security-scanner-skill

      - run: |
          llm-scanner-skill scan \
            --target http://localhost:8000/chat --target-type url \
            --judge-model llama3.2:3b \
            --categories LLM01,LLM02,LLM05,LLM07 \
            --fail-on-score 7.0 \
            --output-dir llm-scan-reports \
            --authorized > scan-envelope.json
```

`--authorized` is correct here and only here: the target is a container the workflow
itself started. Never hardcode it for an external host.

## GitLab CI

```yaml
llm-security-scan:
  image: python:3.11
  timeout: 45m
  services:
    - name: $CI_REGISTRY_IMAGE/app:$CI_COMMIT_SHA
      alias: app
  script:
    - curl -fsSL https://ollama.com/install.sh | sh
    - ollama serve & sleep 5
    - ollama pull llama3.2:3b
    - pip install llm-security-scanner-skill
    - |
      llm-scanner-skill scan --config ci/llm-scan.yml \
        --fail-on-score 7.0 --output-dir reports --authorized
  artifacts:
    when: always
    paths: [reports/]
    reports:
      sast: reports/*/report.sarif
  cache:
    key: ollama-models
    paths: [/root/.ollama/models]
```

## Docker

```bash
docker run --rm --network host \
  -v "$PWD/reports:/reports" \
  ghcr.io/konradxmalinowski/llm-security-scanner:0.8.0 \
  --target http://localhost:8000/chat --target-type url \
  --judge-model llama3.2:3b --output-dir /reports
```

`--network host` lets the container reach both the app and Ollama on the host. Without
it, use `host.docker.internal` and `OLLAMA_HOST=http://host.docker.internal:11434`.

## Choosing a gate

**`--fail-on-score`** is right for a new project: a single number, easy to ratchet down.
Start at the current score and lower it over time.

**Baseline compare** is right for a mature app with accepted residual risk — it fails only
on *new* findings:

```bash
llm-scanner baseline compare --name production
```

**`judge-eval --min-kappa`** guards the judge itself. Worth a scheduled job: it catches an
Ollama or model upgrade silently degrading every verdict.

```bash
llm-scanner judge-eval --judge llama3.2:3b --min-kappa 0.4
```

## Keeping CI runs sane

- Narrow `--categories` to what `inspect` recommended. A full sweep belongs in a nightly
  or pre-release job, not on every PR.
- `--severity medium` drops informational noise.
- Never enable `--include-dos-tests` in a shared CI environment.
- Pass secrets as `${VAR}` in the config and set the variable in CI's secret store; never
  inline a token into a committed file.
- Keep `--format json,sarif` in CI; add `html` only if someone will actually read it.
