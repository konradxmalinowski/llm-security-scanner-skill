# Workflow: add an LLM security gate to CI

The decisions to make before writing any YAML. Platform specifics:
[references/ci-cd.md](../references/ci-cd.md).

## 1. Establish what to gate on

Run a scan locally first. Gating on a threshold you have never measured either fails
every build on day one or never fires.

```bash
scripts/scan.py --target http://localhost:8000/chat --target-type url \
  --judge-model llama3.2:3b --categories LLM01,LLM02,LLM05,LLM07
```

Note the risk score. That is your starting `fail_on_score`; ratchet it down over time.

## 2. Pick the gate

| Gate | Right when | Flag |
|---|---|---|
| Risk score | New project; want one number to ratchet | `--fail-on-score 7.0` |
| Baseline diff | Mature app with accepted residual risk; fail only on *new* findings | `llm-scanner baseline compare --name production` |
| Judge quality | Scheduled; catch a model upgrade degrading verdicts | `llm-scanner judge-eval --min-kappa 0.4` |

Always add `--fail-on-judge-error`. A green build from a scan whose judge was down is
worse than a red one.

## 3. Decide where the target comes from

CI needs a running target. In order of preference:

1. **A container the workflow starts** - `docker compose up -d app`, then scan
   `http://localhost:8000/chat`. Self-contained, disposable, and `--authorized` is
   legitimate because the workflow created it.
2. **A dedicated staging deployment** - needs the user's standing authorization and a URL
   in CI secrets.
3. **Never production.** Say so if it is proposed.

## 4. Budget the run

The runner must install Ollama and pull a judge model (~2 GB). So:

- Cache `~/.ollama/models`.
- Narrow `--categories` on PRs to what `inspect` recommended; full sweeps go nightly or
  pre-release.
- `--severity medium` drops informational noise.
- `timeout-minutes: 45`.
- Never `--include-dos-tests` in shared CI.

## 5. Wire the outputs

- `--format json,sarif` - SARIF into `github/codeql-action/upload-sarif` so findings show
  in the Security tab and on PRs.
- Upload the report directory as an artifact with `if: always()` - the reports matter most
  on the run that failed.

## 6. Handle secrets

Reference them as `${VAR}` in the config and set the variable in CI's secret store. Never
inline a token into a committed file. The scanner resolves `${VAR}` at run time and keeps
the key out of logs and error output.

## 7. Write it

Copy the matching template from [references/ci-cd.md](../references/ci-cd.md) - GitHub
Actions (composite action or by hand), GitLab CI, or Docker - and adapt it. Then tell the
user:

- what gates the build and at what threshold;
- what the first run will likely do (it may well fail - that is information);
- how to ratchet the threshold down;
- that `--include-dos-tests` is deliberately absent.
