# Workflow: assess, then scan

Stages 1-4. Do not skip to the scan - a scan with no reachable target or no
authorization produces nothing, and a scan of a project with no LLM produces noise.

## 1. Inspect

```bash
scripts/inspect_target.py /path/to/project
```

Decide from `is_llm_application` and `scan_readiness`:

- `is_llm_application: false` → **stop.** Tell the user no LLM component was found and
  that this scanner tests run-time LLM behaviour, so there is nothing to test. If the LLM
  lives in another service, offer to inspect that repo.
- `scan_readiness: not_applicable` → same.
- `ready_with_setup` → continue.

Then tell the user, in this order:

1. What the app is: `application_kind`, with two or three `signals` as evidence
   (`file:line`).
2. Which categories are relevant and why - from `category_rationale`, not from the
   category list.
3. Which protections are missing (`missing_controls`).
4. What setup is needed (`next_steps`).

Per-shape guidance: [references/attack-surface-mapping.md](../references/attack-surface-mapping.md).

## 2. Authorize

```bash
scripts/check_authorization.py --target <t> --target-type <url|ollama>
```

`allowed: true` → continue. `allowed: false`:

- `requires_ack: true` → ask: *"<target> is not local. Do you own it, or do you have
  written permission to security-test it?"* On a clear yes, re-run with `--authorized`.
- `requires_ack: false` → hard refusal. Relay `reason` and stop. Do not look for a bypass.

Relay every `warnings` entry - production markers, plaintext transport, DoS consent.

Also check, from the inspection:

- `autonomous_action: true` → model output can reach shell/`eval`. **Require a sandbox**;
  a successful LLM06 probe could execute something real.
- `rag_retrieval` / `document_ingestion` → LLM04 and LLM08 probes write adversarial
  documents. **Require a disposable index copy.**

Rules: [references/authorization.md](../references/authorization.md).

## 3. Prepare

Get the target running and confirm the contract:

```bash
curl -i -X POST http://localhost:8000/chat \
  -H 'Content-Type: application/json' -d '{"prompt":"hello"}'
```

It must accept `{"prompt": …}` and return `{"response": …}` or `{"message": …}`. If it
does not, add the test adapter from
[references/target-types.md](../references/target-types.md) rather than changing the app.

If `system_prompt` was detected, plant a canary - this is the single highest-value step,
turning LLM07 from a judge guess into proof:

```bash
CANARY="LLMSCAN-CANARY-$(openssl rand -hex 16)"
# add $CANARY to the app's own system prompt, restart, then pass it below
```

Then generate and check the config:

```bash
scripts/init_config.py --target http://localhost:8000/chat --target-type url \
  --judge-model llama3.2:3b --categories LLM01,LLM02,LLM05,LLM07 --out llm-scan.yml
scripts/validate_config.py llm-scan.yml
```

Fix every `error`. Read every `warning`; most matter.

## 4. Scan

```bash
scripts/doctor.py        # all three prerequisites, before a long run

scripts/scan.py --target http://localhost:8000/chat --target-type url \
  --judge-model llama3.2:3b \
  --categories LLM01,LLM02,LLM05,LLM07 \
  --canary "$CANARY" --system-prompt @prompts/system.txt \
  --output-dir ./reports
```

Tell the user before starting that each payload costs two model round-trips, so this
takes minutes, not seconds.

Then go to [triage-findings.md](triage-findings.md).

## Scanning a model instead of an app

When no HTTP surface exists:

```bash
scripts/scan.py --target mistral:7b --target-type ollama --judge-model llama3.2:3b \
  --categories LLM01,LLM07,LLM09
```

Be explicit with the user: this measures the **base model's** susceptibility. It says
nothing about their prompt, retrieval, tools or output handling - those live in their code.
