# Limitations

Stated plainly, because a security tool that overstates itself is worse than none.

## Inherited from the scanner

**Non-determinism.** LLMs vary run to run. A scan is a sample, not a proof. A
`heuristic` verdict flipping between runs may be variance rather than a fix — re-run
before concluding, and prefer `confirmed` or `likely` evidence.

**The judge is a small local model.** Offline-first means the judge is whatever Ollama
model you pulled, with real error in both directions. `llm-scanner judge-eval` measures it
(precision / recall / F1 / Cohen's kappa against 32 hand-labelled entries) and `--min-kappa`
gates CI — but nothing removes the error. A judge-only verdict is one model's opinion, and
the skill calls it `heuristic` for that reason.

**Behavioural testing only.** The scanner probes a running system; it does not read your
code. Two categories are therefore only half-answered by a report:

- **LLM03 (supply chain)** — probes what the model *says* about its components. Real
  assurance needs SBOM and SCA tooling.
- **LLM05 (improper output handling)** — proves the model will *produce* dangerous output,
  not that your app renders or executes it. A vulnerable finding plus a sanitizing renderer
  is a genuine false positive for your app.

Likewise **LLM06** proves the model *attempted* an action, not that the tool would have
allowed it. The skill's workflow requires reading the source before reporting these.

**A running target is required.** No reachable endpoint and no local model means nothing
to scan. The inspector will say so.

**The endpoint contract is fixed.** `POST {"prompt": …}` → `{"response": …}` or
`{"message": …}`. Anything else needs a thin test adapter (documented, with code).
Preflight uses `HEAD`, so an endpoint that rejects `HEAD` aborts the scan.

**Ollama is a hard prerequisite**, including in CI, where it means installing Ollama and
pulling a ~2 GB model on the runner.

**Single-tenant blind spots.** LLM08 cross-tenant leakage cannot be demonstrated against
a single-tenant test index. The skill says so and supplies the two-tenant test instead.

## Limitations of the skill layer

**Static inspection has both error modes.** `inspect.py` is regex-based pattern matching
over source text. It misses dynamically registered routes, unusual frameworks, LLM calls
behind an internal abstraction, and anything in a language whose idioms are not in the
pattern set. It can also over-match — a commented-out import counts. Treat
`recommended_categories` as a starting point backed by the `signals` evidence, never as a
complete attack-surface map. `candidate_endpoints` being empty is not evidence that no
endpoint exists.

**Sanitization is defence in depth, not a proof.** The injection-phrase and control-token
sets are finite; novel phrasings will pass through labelled only as prose. The structural
defence (an unguessable fence plus an explicit data label) is what carries the weight, and
it depends on the agent honouring it. There is no way to make a string unable to influence
a language model.

**The authorization gate classifies, it does not verify ownership.** It can tell loopback
from external; it cannot tell whether the user owns `app.example.com`. That is why
`--authorized` exists and why the skill requires asking. An agent that sets the flag
without asking defeats it — the gate narrows the blast radius, it does not remove the
need for judgement.

**DNS-dependent classification.** Resolution happens at classification time, so a
split-horizon or rebinding setup could resolve differently later. Unresolvable hosts are
treated as `unknown` (authorization required), which is the safe direction.

**The scanner is invoked as a subprocess.** That buys isolation and a hard timeout and
costs process overhead and a dependency on the CLI's surface. The contract tests and the
nightly job exist to detect that surface changing.

**The comparison is attack-keyed.** It cannot tell a genuine fix from model variance on a
`heuristic` finding. It flags scope differences and refuses to call a disappeared attack
"fixed" when the scopes differed — but re-running is still the only way to be sure.

## Not implemented, and why

| | Reason |
|---|---|
| GitHub Copilot integration | No Agent Skills support and no public reusable-skill format at the time of writing |
| Cursor / Windsurf / Zed adapters | The generic path applies, but none has been tested. Untested is not supported |
| Cloud judge models | Offline-first is a project constraint, not an oversight |
| Writing payloads from the skill | Payloads belong in the scanner. The skill adds `--payloads-dir`, it does not author attacks |
| Auto-applying fixes | Remediation is proposed; code changes happen only on request, after a source read |
| Non-HTTP transports (gRPC, WebSocket) | The scanner's target adapters are HTTP and Ollama. Use a thin HTTP shim |

## Recommended future work

1. **AST-based inspection** for Python and TypeScript, replacing regex matching — fewer
   false positives and resolution through internal abstractions.
2. **An indirect-injection harness.** The highest-value RAG test writes a poisoned
   document to a disposable index and asks an innocent question. It is documented as a
   project test because only the application can write to its own index; a pluggable
   harness would automate it.
3. **Tool-permission correlation.** For LLM06, parse tool definitions and automatically
   answer "would this tool have allowed it", which is currently a manual code read.
4. **Multi-run aggregation**, to separate a real fix from model variance statistically
   instead of by re-running and squinting.
5. **Copilot and IDE adapters** once a reusable-skill format exists for them.
6. **A judge-quality dashboard** tracking `judge-eval` metrics over time, so a model or
   Ollama upgrade that degrades verdicts is visible rather than inferred.
