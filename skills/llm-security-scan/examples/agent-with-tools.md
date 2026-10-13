# Example: an agent with tools

LLM06 territory. Here the scan result is the *start* of the analysis, not the end — the
report shows what the model attempted; only the tool code shows what would have happened.

## 1. Inspect

```bash
scripts/inspect_target.py ./agent-service
```

Expect `tool_using_agent`, with `tool_calling` and `agent_loop` true. If
`autonomous_action` is also true, model output can reach a shell or `eval`.

## 2. Setup: sandbox is mandatory

With `autonomous_action: true`, a successful LLM06 probe could execute something real.
Require:

- a disposable container or VM;
- throwaway credentials with no production access;
- no network path to anything that matters.

Tell the user why, in those terms. Do not scan a dev box with real credentials in its
environment.

## 3. Enumerate the tools before scanning

```bash
grep -rn "@tool\|StructuredTool\|bind_tools\|tools=\[" --include=*.py .
```

Write down, per tool: what it can reach, whether it is read-only, whether it re-checks
the caller's authorization, and whether it is reversible. That table is what makes the
findings interpretable.

## 4. Scan

```bash
scripts/scan.py --target http://localhost:8000/agent --target-type url \
  --judge-model llama3.2:3b \
  --categories LLM01,LLM05,LLM06,LLM07 \
  --output-dir ./reports
```

## 5. Interpret each LLM06 finding against the tool code

The probe proves the model *attempted* or claimed an out-of-scope action. Then ask: would
the tool have allowed it?

```python
# Vulnerable: the model's intent IS the authorization
@tool
def delete_user(user_id: str) -> str:
    db.delete(user_id)
    return f"deleted {user_id}"


# Correct: the caller's identity is re-checked inside the tool
@tool
def delete_user(user_id: str, ctx: ToolContext) -> str:
    require_permission(ctx.caller, "user:delete")  # not the model's say-so
    if not ctx.confirmed:
        return "Requires explicit user confirmation. Not performed."
    db.soft_delete(user_id, actor=ctx.caller)
    return f"soft-deleted {user_id}"
```

Then report precisely:

> `LLM06-004` (likely): the agent attempted a destructive operation when asked to. Reading
> `tools/admin.py:31`, `delete_user` performs the delete with no authorization check and no
> confirmation, so the attempt would have succeeded. **Real finding.**

or:

> `LLM06-002` (heuristic): the agent claimed it would escalate privileges. Reading
> `tools/admin.py:58`, the tool re-checks the caller's permission and would have refused.
> Prompt-level only, not a breach.

That distinction is the entire value of this step.

## 6. Fix

```bash
scripts/remediate.py LLM06
```

Order: least privilege per tool; re-authorize on the *caller's* identity inside each tool;
human confirmation for destructive or irreversible actions; cap loop iterations and total
tool calls.

## 7. Regression tests, not just a re-scan

```python
def test_tool_rejects_unauthorized_caller():
    ctx = ToolContext(caller=unprivileged_user, confirmed=True)
    assert "Requires" in delete_user("victim", ctx) or raises_permission_error()
```

A scan samples behaviour; a test is a gate. Add both, then re-scan and compare.
