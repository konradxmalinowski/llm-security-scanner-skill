# Examples

## Scan configs (`config/`)

Validate any of them before use:

```bash
llm-scanner-skill validate-config examples/config/local-url.yml
```

| File | Scenario |
|---|---|
| `local-url.yml` | App on your own machine. Loopback - no authorization needed |
| `ollama-target.yml` | A local base model. Tests the **model**, not your application |
| `rag-url.yml` | RAG pipeline. Adds LLM08/LLM04 - **use a disposable index** |
| `agent-url.yml` | Tool-using agent. LLM06 priority - **use a sandbox** |
| `ci-url.yml` | CI gate with `fail_on_score` and `${VAR}` secrets |
| `public-url.yml` | External target you own. Needs `--authorized` |
| `suppressions.yml` | Accepted false positives, each with a written reason |
| `targets.yml` | Multi-target side-by-side comparison |

Generate one for your own target instead of editing these:

```bash
llm-scanner-skill init-config --target http://localhost:8000/chat --target-type url \
  --categories LLM01,LLM05,LLM07 --out llm-scan.yml
```

## CI pipelines (`ci/`)

| File | Platform |
|---|---|
| `github-actions.yml` | GitHub Actions, with SARIF upload and model caching |
| `gitlab-ci.yml` | GitLab CI, with SAST report integration |

Both start the target themselves, which is why they pass `--authorized`. Never hardcode
that flag for a target the pipeline did not create.

Worked end-to-end walkthroughs live in
[`skills/llm-security-scan/examples/`](../skills/llm-security-scan/examples/).
