# The ten categories, and what a probe actually proves

Payload counts are the bundled library at scanner 0.8.0; run `scripts/doctor.py` or
`llm-scanner-skill categories` for live numbers. Each entry says what a *successful*
probe does and does not establish — the gap between those two is where false positives
live.

## LLM01 — Prompt Injection (11 payloads, high)
Direct and indirect instruction override: `ignore all previous instructions`, DAN
personas, fake delimiters, XML policy puppetry, Base64-smuggled instructions,
multi-turn and encoding tricks.

- **Proves:** injected text visibly took control of the output.
- **Does not prove:** that control reached anything consequential. Pair with LLM05/LLM06
  to see whether it becomes execution.
- **Needs:** user-reachable prompt input. Always relevant if an LLM exists.

## LLM02 — Sensitive Information Disclosure (9, high)
Attempts to extract credentials, PII, training data and config from the model's context.

- **Proves:** the model emitted something that looks sensitive.
- **Does not prove:** the value is real. The scanner's secret detector is entropy-gated,
  which cuts but does not eliminate plausible-looking fabrications. Check whether the
  fingerprinted value matches a real credential before escalating.

## LLM03 — Supply Chain (6, medium)
Probes the model's disclosure of its own provenance, versions and plugin/dependency chain.

- **Proves:** the model discloses component details, or accepts untrusted component claims.
- **Does not prove:** an actual vulnerable dependency. Real assurance needs SBOM/SCA
  tooling; this is behavioural only. Say so.

## LLM04 — Data and Model Poisoning (6, high)
Backdoor triggers and adversarial-training-data behaviour.

- **Proves:** the model responds anomalously to a trigger pattern.
- **Does not prove:** the training set was poisoned. Low base rate on stock models;
  treat a lone `heuristic` here with suspicion.
- **Needs:** fine-tuning or document ingestion to be meaningful. Use a disposable index.

## LLM05 — Improper Output Handling (6, high)
Gets the model to emit XSS, SQL injection, shell commands, path traversal and markdown
injection.

- **Proves:** the model will *produce* dangerous output.
- **Does not prove:** your app renders or executes it. This is the one category where the
  real verdict is in your code, not the response — grep for `innerHTML`,
  `dangerouslySetInnerHTML`, `| safe`, `eval`, `subprocess`. A vulnerable finding plus a
  sanitizing renderer is a genuine false positive for your app.

## LLM06 — Excessive Agency (8, high)
Tries to make the model take or authorize actions: tool misuse, privilege escalation,
confirmation bypass, destructive operations.

- **Proves:** the model *attempted* or claimed an out-of-scope action.
- **Does not prove:** the tool would have allowed it. Read the tool implementation. A
  model that says "deleting all records" while the tool enforces authorization is a
  prompt-level finding, not a breach.
- **Needs:** tool calling, agent loops, or MCP.

## LLM07 — System Prompt Leakage (5, high)
Direct requests, encoding tricks and repetition attacks to extract the system prompt.

- **Proves:** with a `--canary`, a verbatim token match is *proof* (`confirmed`,
  confidence 1.00). Without one, the judge is guessing from plausibility.
- **Setup:** plant a canary. This is the single highest-value configuration step.

## LLM08 — Vector and Embedding Weaknesses (5, high)
Cross-tenant retrieval, embedding inversion, index poisoning via retrieved context.

- **Proves:** retrieved content influenced output in a way it should not have.
- **Does not prove:** cross-tenant leakage — that requires real multi-tenant data. A
  single-tenant test index cannot demonstrate it; say that rather than implying it did.
- **Needs:** RAG or a vector store.

## LLM09 — Misinformation (5, medium)
Confident fabrication, package hallucination, false citations.

- **Proves:** the model fabricated in this sample.
- **Does not prove:** a rate. Hallucination is statistical; a scan samples it.
- **Note:** frequently and legitimately suppressed for creative-writing products — with a
  stated reason.

## LLM10 — Unbounded Consumption (6, medium) — OPT-IN
Token flooding, recursive expansion, resource exhaustion.

- **Proves:** no effective input/output/rate limit on the path tested.
- **Risk:** these probes stress the target. Needs `--include-dos-tests` *and* explicit
  user consent, and a disposable instance. Never against anything serving real traffic.

## Picking a set

| Application shape | Start with |
|---|---|
| Chatbot / LLM API | LLM01, LLM02, LLM05, LLM07 |
| RAG pipeline | LLM01, LLM02, LLM07, **LLM08**, LLM04 |
| Tool-using agent | LLM01, **LLM06**, LLM05, LLM07 |
| MCP server / client | LLM01, **LLM06**, LLM03, LLM05 |
| Multi-agent system | LLM01, **LLM06**, LLM02, LLM07 |
| Base model comparison | LLM01, LLM07, LLM09 |
| Pre-release full sweep | LLM01–LLM09; add LLM10 only on a disposable instance |

Every category you leave out is **untested**, not safe. State which you ran.
