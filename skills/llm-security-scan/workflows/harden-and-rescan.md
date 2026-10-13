# Workflow: fix, then prove it

Stages 6–7. Detection without verification is half the job.

```
finding → read the source → root cause → propose → change → test → re-scan → compare
```

## 1. Get the guidance

```bash
scripts/remediate.py LLM01
```

Root causes, where to look, fix pattern, verification, limits. The recommendation and
CWE/CVSS come from the scanner, so they match the report.

## 2. Read the actual source — do not skip this

Use the inspection `signals` (`file:line`) to find the code. Then answer the category's
real question:

| Category | The question only the code answers |
|---|---|
| LLM01 | Where is untrusted text concatenated into the prompt? |
| LLM02 | What secrets are reachable from this process? |
| LLM05 | Is model output rendered or executed unescaped? |
| LLM06 | Would the tool have *allowed* the action the model attempted? |
| LLM07 | Does anything in the system prompt matter if published? |
| LLM08 | Is there a server-side tenant filter on every retrieval? |
| LLM10 | Is there a per-identity rate and token budget before the model call? |

This is where false positives get resolved. LLM05 vulnerable + a sanitizing renderer is a
false positive *for this app*; say that rather than filing a bug.

## 3. Explain the root cause

One or two sentences, naming the file and line, and what the attacker controls. If the
finding is `heuristic` and the code shows the path is not reachable, say so and stop —
that is a complete and correct outcome.

## 4. Propose before changing

Show the fix. Say what it does and does not prevent — prompt-level defences are
probabilistic, and claiming otherwise sets the user up badly. Change code only when asked.

## 5. Run the project's own tests

```bash
pytest            # or whatever the project uses
```

A security fix that breaks the app is not a fix. Also add a regression test — a scan is a
sample, a test is a gate:

- LLM01: the canonical override payload does not change the response shape.
- LLM05: an `<img onerror=...>` response is escaped at render.
- LLM06: the tool rejects an out-of-scope argument even when the model requests it.
- LLM08: tenant A's query cannot retrieve tenant B's document.

## 6. Re-scan the same scope

```bash
scripts/scan.py --target <same> --target-type <same> --judge-model <same> \
  --categories <the affected ones> --canary "$CANARY" --output-dir ./reports
```

Same target, same judge, same categories. A narrower re-scan cannot demonstrate a fix,
and the comparison will tell you so.

## 7. Compare

```bash
scripts/compare_scans.py reports/<before>/report.json reports/<after>/report.json
```

Read `verdict` first — it names regressions and inconclusive results ahead of wins, on
purpose.

| Bucket | Means |
|---|---|
| `fixed` | Vulnerable before, safe now |
| `still_vulnerable` | No change |
| `regressed` | **Safe before, vulnerable now.** The fix broke something — handle first |
| `new` | Vulnerable and absent from the earlier scan |
| `inconclusive` | Not evaluated; the comparison is partial |
| `removed` | Absent from the later scan and scope differed — not a fix |

## 8. Report honestly

- A single `heuristic` verdict flipping may be model variance, not a fix. Re-run before
  claiming success, and prefer `confirmed`/`likely` as evidence.
- `regressed` findings outweigh `fixed` ones. Lead with them.
- If `inconclusive` is non-zero, the comparison is partial. Say so.
- Risk score alone is a poor summary: it is severity-weighted and excludes unevaluated
  attacks. Quote the attack-level deltas.

## Iterate

Repeat per category, highest-confidence findings first. Stop when the remaining findings
are accepted risk — and record each one as a suppression with a written reason
([references/configuration.md](../references/configuration.md)).
