# Remediation

Get the per-category detail from the tool, not from memory:

```bash
scripts/remediate.py LLM01      # or an attack ID: LLM01-003
```

It returns root causes, where to look, the fix pattern, how to verify, and the honest
limits of that fix. The one-line recommendation and the CWE/CVSS mapping come from the
scanner itself, so they always match the report.

## The loop

```
finding → read the actual source → explain the root cause → propose a fix
        → (on request) change the code → run the project's tests → re-scan
        → compare before/after
```

**Never skip the source read.** The report says what the model *did*; only the code says
whether it mattered. Two examples that recur:

- LLM05 vulnerable + a sanitizing renderer = a false positive for this app.
- LLM06 vulnerable + a tool that enforces authorization = a prompt-level finding, not a
  breach.

Say which of the two you are looking at.

## Priority

1. `confirmed` findings (canary proof) — real, by string comparison.
2. `needs_review` conflicts — a rule fired; a human must look.
3. `critical`/`high` + `likely`.
4. `inconclusive` — **re-run these before anything else.** They are unknowns, and a
   scan carrying them is not a clean result.
5. `heuristic` — verify by hand before spending effort.

Within a tier, prefer the categories whose fix removes a *class* of problem: LLM05 output
encoding and LLM06 least privilege both blunt LLM01 as a side effect, because they remove
what a successful injection can reach.

## Cross-cutting fixes worth more than their category

- **Treat model output exactly like user input.** Fixes LLM05, blunts LLM01.
- **Re-authorize inside every tool, on the caller's identity.** Fixes LLM06, blunts LLM01.
- **Assume the system prompt is public.** Makes LLM07 a non-event.
- **Mandatory server-side tenant filter on retrieval.** Fixes LLM08.
- **Per-identity rate and token budgets.** Fixes LLM10, caps injection cost.

## Verifying

```bash
scripts/scan.py --target … --categories <the affected ones>     # re-scan
scripts/compare_scans.py reports/<before>/report.json reports/<after>/report.json
```

Read the comparison `verdict`. It names regressions and inconclusive results first on
purpose — a fix that quietly broke a previously-safe category is not progress.

Also: add a regression test in the project's own suite. A scan is a sample; a test is a
gate. For LLM01 assert the canonical payload does not change the response shape; for
LLM05 assert `<img onerror=...>` is escaped at render; for LLM06 assert the tool rejects
an out-of-scope argument even when the model asks for it.

## What to tell the user when you cannot fix it

Some findings are accepted risk, not bugs — LLM09 on a creative-writing product, LLM07 on
a deliberately published prompt. Say so plainly, and record it:

```yaml
suppressions:
  - attack_id: "LLM09-*"
    reason: "Creative-writing assistant; factual grounding is out of scope"
    expires: "2026-12-31"
```

A suppression with no reason is a silently accepted vulnerability. Always write the reason.
