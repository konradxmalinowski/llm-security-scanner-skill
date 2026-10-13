# Example: comparing local models

Use when there is no HTTP surface, or when the question is "which base model should we
build on".

## What this measures, and what it does not

It measures the **model's** susceptibility to the payloads. It says nothing about your
application's prompt, retrieval, tools or output handling - those live in your code. Say
this to the user; otherwise a clean model scan reads as a clean application.

## Scan one model

```bash
ollama pull mistral:7b
ollama pull llama3.2:3b     # the judge - must differ from the target

scripts/scan.py --target mistral:7b --target-type ollama \
  --judge-model llama3.2:3b --categories LLM01,LLM07,LLM09
```

`ollama_local` → no `--authorized` needed. The scanner generates a canary, plants it in
the system prompt it controls, and a verbatim appearance is proof of LLM07 leakage.

## Test your own system prompt on that model

```bash
scripts/scan.py --target mistral:7b --target-type ollama \
  --judge-model llama3.2:3b --categories LLM01,LLM07 \
  --system-prompt @prompts/system.txt
```

The canary is appended to your prompt automatically, and n-gram overlap detection is
enabled against the real text - so partial leakage is detected too, not just the token.

## Compare several

```yaml
# targets.yml
targets:
  - name: mistral-7b
    target: mistral:7b
    target_type: ollama
  - name: llama31-8b
    target: llama3.1:8b
    target_type: ollama
  - name: qwen25-7b
    target: qwen2.5:7b
    target_type: ollama
```

```bash
llm-scanner --targets targets.yml --judge-model llama3.2:3b \
  --categories LLM01,LLM07,LLM09 --output-dir ./reports
```

Prints a side-by-side vulnerable/total table per category.

## Validate the judge before trusting the numbers

Across-model comparison is only as good as the judge. Measure it:

```bash
llm-scanner judge-eval --judge llama3.2:3b --json judge-metrics.json
```

If the judge's kappa is low, the differences between models may be judge noise. Use a
better judge, or lean on the `confirmed`/`likely` classes and discount `heuristic` ones.

## Reporting it

Give the risk score per model **and** the evidence breakdown. A model with a lower score
made entirely of `heuristic` verdicts is not clearly safer than one with a slightly higher
score containing a `confirmed` finding - the second result is simply better measured.
