# Troubleshooting

Run `scripts/doctor.py` first — it checks all three prerequisites at once and tells you
which failed.

## `scanner_not_found` / `llm-scanner: command not found`

```bash
uv pip install llm-security-scanner-skill     # pulls the scanner in as a dependency
# or point at an existing install:
export LLM_SCANNER_BIN=/path/to/venv/bin/llm-scanner
```

`$LLM_SCANNER_BIN` also accepts a multi-word shim, e.g.
`docker run --rm --network host ghcr.io/konradxmalinowski/llm-security-scanner:latest`.

## `Ollama is not running at http://localhost:11434`

```bash
ollama serve &
ollama pull llama3.2:3b
```

Non-default host: `export OLLAMA_HOST=http://127.0.0.1:11435`. The scanner and the
skill both read it.

## `Model 'X' is not available`

```bash
ollama pull llama3.2:3b     # ~2 GB, a good default judge
ollama list                 # what you already have
```

## `Judge model and target model cannot be the same`

A model cannot judge itself. Use different models — e.g. target `mistral:7b`, judge
`llama3.2:3b`.

## `HTTP target returned 404` at preflight

Preflight sends `HEAD`. Either the path is wrong, or the app rejects `HEAD`. Verify:

```bash
curl -i -X POST http://localhost:8000/chat -H 'Content-Type: application/json' -d '{"prompt":"hi"}'
```

If `POST` works but `HEAD` 404s, put the test adapter from
`references/target-types.md` in front of it.

## `HTTP target is not reachable`

The app is not running, or not on that port. Start it. In Docker, make sure the port is
published and use `host.docker.internal` (or `--network host` on Linux) from inside a
container.

## Every finding is `inconclusive` / `status: completed_untrustworthy`

The judge is failing. Usually:

- The judge model was evicted from VRAM mid-scan → use a smaller judge, or lower
  `--concurrency` to 1.
- Judge timeouts on a loaded machine → `--concurrency 1`.
- The model emits unparseable output → try a model with better instruction following
  (`llama3.2:3b`, `qwen2.5:7b`) and measure it with
  `llm-scanner judge-eval --judge <model>`.

Never report these as clean. They are unknowns.

## The scan is very slow

Each payload costs two model round-trips. 51 payloads on a slow local model is tens of
minutes. Options: narrow `--categories` to what `inspect` recommended; raise
`--concurrency` if you have VRAM headroom; use a smaller judge; raise `--severity` to
`high`.

Default timeout is 2700s; raise it with `--timeout`.

## `No payloads matched the specified filters`

`--categories` and `--severity` intersected to nothing. Severity is per *file*, not per
payload: `--severity critical` plus `--categories LLM09` (a medium file) yields zero.

## `blocked` with `requires_ack: true`

The authorization gate refused. Ask the user whether they own the target, then re-run with
`--authorized`. See `references/authorization.md`.

## `blocked` with `requires_ack: false`

A hard refusal — a third-party provider endpoint. Relay the reason and stop.

## Scan passed but I do not believe it

```bash
llm-scanner judge-eval --judge llama3.2:3b     # how good is this judge?
```

Then add a `--canary` for deterministic LLM07 proof, and confirm the target actually
received the payloads (`--log-level DEBUG --log-file scan.jsonl`).

## Timeouts against a slow app

```bash
--retries 4          # retries transient timeouts and 5xx
--concurrency 1      # stop overwhelming a single-worker dev server
```

## MCP server will not start

```bash
uv pip install 'llm-security-scanner-skill[mcp]'
llm-scanner-skill mcp      # should block on stdio, printing nothing
```

Nothing on stdout is correct — stdio MCP uses it for the protocol.
