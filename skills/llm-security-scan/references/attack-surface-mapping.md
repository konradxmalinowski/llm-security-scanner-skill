# Reading `inspect_target.py` output

`scripts/inspect_target.py <path>` statically reads a project and returns an
`AttackSurface`. It never imports or executes project code - the project is untrusted input.

## The fields that drive decisions

```
is_llm_application     false → STOP. Nothing here to test at run time.
application_kind       chatbot_or_llm_api | rag_application | tool_using_agent |
                       mcp_server_or_client | multi_agent_system | llm_api |
                       llm_integration | unknown
confidence             high | medium | low
features{}             24 booleans - see below
signals[]              file + line + excerpt for every detection. This is the evidence
recommended_categories derived from features, never from the app's name
category_rationale{}   per category, which feature implied it and why
missing_controls[]     absent protections that raise priority
candidate_endpoints[]  inferred prompt URLs (route × detected port)
scan_readiness         not_applicable | not_ready | ready_with_setup
next_steps[]           the concrete setup required before scanning
```

Always cite `signals` when you tell the user why a category matters. "LLM06 applies
because `agent.py:42` calls `bind_tools`" is checkable; "this looks like an agent" is not.

## Features and what they imply

| Feature | Implies |
|---|---|
| `llm_sdk`, `llm_framework`, `chat_completion_call` | an LLM exists at all |
| `http_llm_endpoint` | a reachable target → scan via `url` |
| `user_controlled_prompt` | LLM01 is live |
| `system_prompt` | LLM07 - plant a canary |
| `rag_retrieval`, `vector_db` | LLM08 + indirect LLM01 |
| `document_ingestion` | LLM01 indirect + LLM04 |
| `tool_calling`, `agent_loop`, `multi_agent` | LLM06 |
| `mcp_integration` | LLM06 + LLM03 (each server is a privilege boundary) |
| `autonomous_action` (shell/`eval`) | LLM06 + LLM05, **and a sandbox requirement** |
| `output_rendered_raw` | LLM05 is real, not theoretical |
| `secrets_in_scope` | LLM02 + LLM07 |
| `memory` | an injection can persist across turns |
| `file_upload` | uploads are untrusted prompt content |
| `database_access`, `external_data_access` | LLM02 / indirect LLM01 |
| `auth_present`, `rate_limiting`, `output_validation` | present = good; **absent = raises priority** |

## Per-shape playbook

**`chatbot_or_llm_api`** - Start the app. Scan `url` with LLM01, LLM02, LLM05, LLM07.
Plant a canary if `system_prompt` is set.

**`rag_application`** - Add LLM08 and LLM04. Use a **disposable copy** of the vector
store: the probes write adversarial documents. Check whether the retrieval call applies a
server-side tenant filter - that answers LLM08 better than any probe.

**`tool_using_agent`** - LLM06 is the priority. Before scanning, read every tool
definition and note what each can reach. Scan a sandboxed instance if
`autonomous_action` is true. After a finding, the question is always "would the tool have
*allowed* it", which only the code answers.

**`mcp_server_or_client`** - Enumerate the configured servers; each is a trust boundary
and a supply-chain dependency (LLM03). Check whether tools re-verify the caller's
authorization rather than trusting the model's intent.

**`multi_agent_system`** - One injection propagates across handoffs. Map the graph and
find the highest-privilege agent; that is the real target.

**`llm_integration`** (SDK present, no HTTP surface) - No reachable target. Either add a
thin HTTP harness, or scan the underlying model with `--target-type ollama` and be clear
that this tests the *model*, not the application.

**`unknown` / `is_llm_application: false`** - Say there is nothing to scan. If the LLM
lives in another service, inspect that repository instead. Do not scan to look busy.

## When `candidate_endpoints` is empty

The inspector infers endpoints from route decorators × detected ports. It misses
dynamically mounted routes, API gateways and non-standard frameworks. Ask the user for
the URL, or read the app's own startup/README. An empty list is not evidence that no
endpoint exists.

## Then

Re-check authorization (`references/authorization.md`), work through `next_steps`, and
only then scan.
