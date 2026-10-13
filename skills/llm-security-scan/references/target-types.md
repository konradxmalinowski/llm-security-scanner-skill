# Target types and the endpoint contract

The scanner takes exactly two kinds of target.

## `--target-type url`

An HTTP endpoint. The scanner sends:

```http
POST <target>
Content-Type: application/json
Authorization: Bearer <--api-key>   (only if provided)

{"prompt": "<attack payload>"}
```

and reads the reply as, in order of preference:

1. `{"response": "..."}`
2. `{"message": "..."}`
3. the raw response body

Timeouts are connect 5s / read 30s, with `--retries` (default 2) on timeout,
connection error, and 5xx. A 4xx fails immediately - it is not transient.

### When your app's shape does not match

Most real apps do not accept `{"prompt": ...}`. Do not change the application to suit
the scanner - put a small test-only adapter in front of it:

```python
# scan_adapter.py - run this alongside the app, for scanning only. Never ship it.
from fastapi import FastAPI
from pydantic import BaseModel
import httpx

app = FastAPI()
REAL = "http://localhost:8000/api/v2/conversation"


class Probe(BaseModel):
    prompt: str


@app.post("/chat")
async def chat(probe: Probe) -> dict[str, str]:
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(REAL, json={"messages": [{"role": "user", "content": probe.prompt}]})
        r.raise_for_status()
        return {"response": r.json()["choices"][0]["message"]["content"]}
```

Then scan `http://localhost:8001/chat`. Keep the adapter out of production builds, and
tell the user it exists.

### Preflight

The scanner sends a `HEAD` request first. 401 and 403 pass (the server is up but wants
auth); 404 and 5xx abort. If your endpoint rejects `HEAD`, that aborts the scan - the
adapter above is the usual fix.

## `--target-type ollama`

A local Ollama model name, e.g. `mistral:7b`. The scanner talks to the model directly
through the Ollama SDK and **controls the system prompt**, which unlocks the strongest
detector: it generates a unique canary token, plants it in the system prompt, and a
verbatim appearance in any response is *proof* of system-prompt leakage
(`verdict_source: rule_proof`, confidence 1.00) rather than a judge opinion.

```bash
llm-scanner --target mistral:7b --target-type ollama --judge-model llama3.2:3b
```

Use this to measure a **base model's** susceptibility. It tells you nothing about your
application's prompt, retrieval, tools or output handling - those live in your code, so
scan the running app via `url` for those.

Pass `--system-prompt @prompts/system.txt` to test your real prompt on that model; the
canary is appended to it automatically.

## Canaries on URL targets

The scanner cannot inject into a remote app's system prompt. To get deterministic LLM07
proof against a `url` target, do it yourself:

1. Add a unique token to the app's own system prompt out of band, e.g.
   `LLMSCAN-CANARY-<random hex>`.
2. Declare it: `--canary LLMSCAN-CANARY-<same hex>`.
3. Optionally pass the prompt text with `--system-prompt @path` to enable n-gram
   overlap detection too.

Without a canary, LLM07 verdicts rest on the judge alone (`heuristic`). With one, a
leak is `confirmed`. This single step is the highest-value setup change available.

## Choosing

| Situation | Target type |
|---|---|
| Chatbot, LLM API, RAG pipeline, agent with an HTTP entry point | `url` (start the app first) |
| Comparing base models, or no HTTP surface exists | `ollama` |
| Testing your system prompt's resistance in isolation | `ollama` + `--system-prompt` |
| App is running in Docker | `url` against the published port |
| Library with no server | neither - add a thin HTTP harness, or scan the model |
