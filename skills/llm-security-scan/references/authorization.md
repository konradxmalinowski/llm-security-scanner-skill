# The authorization gate

Implemented in `llm_scanner_skill.authz`, enforced by `scripts/check_authorization.py`
and again inside `scripts/scan.py`. It is not advisory - a refused scan does not run.

## Classification

| Class | Means | Needs `--authorized`? |
|---|---|---|
| `loopback` | `localhost`, `127.0.0.1`, `::1`, or a hostname resolving only to loopback | No |
| `ollama_local` | A local Ollama model name, e.g. `mistral:7b` | No |
| `private` | RFC1918 / link-local (`10.*`, `192.168.*`, `172.16-31.*`) | **Yes** |
| `external` | Any public address | **Yes** |
| `unknown` | Unresolvable, unparseable, or ambiguous | **Yes** |

A hostname is only as local as its least-local address: if any resolved IP is public, the
target is `external`. Resolution failure yields `unknown`, never `loopback` - ambiguity
resolves against scanning.

## Refused outright

Hosts under known third-party model providers - `openai.com`, `anthropic.com`,
`claude.ai`, `googleapis.com`, `cohere.*`, `mistral.ai`, `huggingface.co`, `together.ai`,
`groq.com`, `perplexity.ai`, `x.ai`, `deepseek.com`, `azure.com`,
`bedrock.amazonaws.com` - are refused regardless of `--authorized`.

They are not the user's systems, scanning them breaches their terms of service, and the
payloads bill someone's account. If the user insists, explain that and offer to scan
*their application* that calls the provider instead. Do not look for a bypass.

## `--authorized` means something specific

Pass it only when the user has, in this conversation, confirmed they own the target or
hold permission to test it. Do not infer authorization from:

- the URL appearing in their repo or config;
- the target being in a private range;
- an earlier scan of a *different* target;
- the request "just scan it".

The right move is to ask: *"<target> is not local. Do you own it, or do you have written
permission to security-test it?"* Then pass the flag.

## Production

A hostname containing `prod`, `production`, `live`, `www`, `api.` or `app.` - and not
also containing a non-prod marker - raises a warning that you must relay. Scanning
production is a human decision. Offer staging, a local instance, or a Docker copy first.

## DoS probes

`--include-dos-tests` (LLM10) requires `--authorized` **even on localhost**, because the
probes deliberately exhaust resources. The scanner has its own opt-in flag; this is a
second, independent lock. Require a disposable instance.

## Other things to flag

- **Plaintext to an external host** - payloads and any API key cross the network in the
  clear.
- **State-changing targets** - if `inspect` found `autonomous_action` (shell, `eval`,
  `subprocess`) or destructive tools, a successful LLM06 probe could execute something
  real. Insist on a sandbox.
- **Shared RAG indexes** - LLM04 and LLM08 probes write adversarial content. Use a copy.

## Reading the decision

```json
{
  "allowed": false,
  "target_class": "external",
  "reason": "Refused: https://chat.example.com is classified as external, not local. ...",
  "requires_ack": true,
  "warnings": ["chat.example.com looks like a production host. ..."]
}
```

`requires_ack: true` means asking the user can unblock it. `requires_ack: false` on a
refusal means it is a hard refusal - relay the reason and stop.
