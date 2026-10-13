"""Remediation guidance, grounded in the scanner's own category metadata.

The authoritative one-line recommendation for every OWASP LLM category already
lives in the scanner (``llm_scanner.models.OWASP_RECOMMENDATIONS``), alongside its
CWE and CVSS mappings. This module reads those directly so the skill can never
drift from what the reports say, and adds what a *code-fixing* agent needs on top:
where the fix usually goes, the concrete pattern, and how to verify it.

If the scanner is not importable, the lookup still works -- the local tables are
complete on their own, and the scanner's values override them when available.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CATEGORY_TITLES",
    "RemediationGuidance",
    "guidance_for_category",
    "guidance_for_finding",
]

CATEGORY_TITLES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# Where to look in the codebase, what the fix is, and how to prove it worked.
# Kept terse on purpose: the agent reads the project to fill in specifics, and a
# long essay here would be loaded into context for every finding.
_GUIDANCE: dict[str, dict[str, Any]] = {
    "LLM01": {
        "root_causes": [
            "Untrusted text is concatenated into the same prompt as trusted instructions, "
            "with nothing marking the boundary.",
            "Retrieved documents, tool results, or fetched web content are treated as "
            "instructions rather than data.",
        ],
        "where_to_look": [
            "The prompt assembly site: f-strings or template joins that mix a system "
            "prompt with request data.",
            "RAG context injection, where retrieved chunks are added to the message list.",
            "Tool-result handling, where output is appended to the conversation.",
        ],
        "fix_pattern": [
            "Put untrusted input in a separate user message, never inside the system message.",
            "Delimit untrusted spans with an unguessable nonce and state in the system "
            "prompt that content inside them is data and must not be obeyed.",
            "Enforce the real security boundary outside the model: the LLM's output decides "
            "nothing that is not re-authorized in code.",
            "Validate output against a schema rather than trusting prose.",
        ],
        "verification": [
            "Re-scan LLM01 and confirm previously-vulnerable attack IDs now report safe.",
            "Add a regression test asserting the canonical override payload does not change "
            "the response shape.",
        ],
        "limits": "Prompt-level defences reduce but never eliminate injection. Anything that "
        "must not happen has to be impossible in code, not merely discouraged in the prompt.",
    },
    "LLM02": {
        "root_causes": [
            "Secrets are reachable from the model's process or embedded in its context.",
            "Responses are returned without filtering for PII or credentials.",
        ],
        "where_to_look": [
            "Environment loading near the LLM client; prompt templates that interpolate config.",
            "Error handlers that return exception text to the caller.",
            "Logging of full prompts or responses.",
        ],
        "fix_pattern": [
            "Keep credentials out of prompt text entirely; let the SDK read them from the env.",
            "Filter responses for secret patterns and PII before returning them.",
            "Scope the model's data access to the authenticated user's own rows.",
            "Redact prompts and responses before they reach logs.",
        ],
        "verification": [
            "Re-scan LLM02 and LLM07.",
            "Plant a unique canary secret in the environment and confirm no probe surfaces it.",
        ],
        "limits": "A pattern filter catches known credential shapes, not every leak of "
        "business-sensitive content.",
    },
    "LLM03": {
        "root_causes": [
            "Model, plugin, or MCP-server provenance is unverified.",
            "Dependency versions float, so a compromised release is pulled silently.",
        ],
        "where_to_look": [
            "Dependency manifests and lockfiles; model download/pull steps.",
            "MCP server configuration listing third-party servers.",
        ],
        "fix_pattern": [
            "Pin exact versions and commit the lockfile; verify checksums or digests.",
            "Pull models from a trusted registry and record the digest.",
            "Review each MCP server's permissions; treat every one as a privilege boundary.",
            "Run dependency and container scanning in CI.",
        ],
        "verification": [
            "Re-scan LLM03; confirm lockfile integrity and that SCA reports no known CVEs.",
        ],
        "limits": "The scanner probes run-time behaviour. Real supply-chain assurance needs "
        "SBOM and SCA tooling alongside it.",
    },
    "LLM04": {
        "root_causes": [
            "Untrusted documents enter the index or fine-tuning set without review.",
            "No drift monitoring, so poisoned behaviour goes unnoticed.",
        ],
        "where_to_look": [
            "Ingestion pipelines and loaders; fine-tuning dataset assembly.",
        ],
        "fix_pattern": [
            "Validate and provenance-tag every ingested document; quarantine user uploads.",
            "Keep tenant corpora in separate collections.",
            "Snapshot behaviour on a fixed eval set and alert on drift.",
        ],
        "verification": [
            "Re-scan LLM04 against a disposable index copy, never the production one.",
        ],
        "limits": "Poisoning that only manifests on specific triggers may not surface in a scan.",
    },
    "LLM05": {
        "root_causes": [
            "Model output is rendered or executed without encoding.",
            "Generated code, SQL, or shell strings are passed to an interpreter.",
        ],
        "where_to_look": [
            "`dangerouslySetInnerHTML`, `innerHTML =`, `v-html`, Jinja `| safe`, "
            "`render_template_string`.",
            "Any `subprocess`, `eval`, `exec`, or raw SQL built from model output.",
        ],
        "fix_pattern": [
            "Treat model output exactly like user input: context-aware encoding at render time.",
            "Render Markdown through a sanitizer allowlist; never raw HTML.",
            "Never pass model output to a shell or `eval`. Map it to a fixed set of "
            "parameterized operations instead.",
            "Use parameterized queries, never string-built SQL.",
        ],
        "verification": [
            "Re-scan LLM05.",
            "Add a test asserting that an `<img onerror=...>` response is escaped on render.",
        ],
        "limits": "Encoding is context-specific; HTML-escaping does not make a string safe "
        "inside a URL, an attribute, or a shell command.",
    },
    "LLM06": {
        "root_causes": [
            "Tools granted to the model are broader than the task needs.",
            "High-impact actions run without human confirmation or re-authorization.",
        ],
        "where_to_look": [
            "Tool/function registration; agent executor construction; MCP server allowlists.",
            "Any tool wrapping shell, filesystem, network, email, or payment calls.",
        ],
        "fix_pattern": [
            "Least privilege per tool: narrow parameters, allowlisted targets, read-only "
            "where possible.",
            "Re-check the *caller's* authorization inside each tool, not just at the chat "
            "entry point -- the model's intent is not an authorization decision.",
            "Require explicit human approval for destructive or irreversible actions.",
            "Cap loop iterations and total tool calls per request.",
        ],
        "verification": [
            "Re-scan LLM06 and confirm each probe is refused.",
            "Add a test asserting a tool rejects an out-of-scope argument even when the "
            "model requests it.",
        ],
        "limits": "A scan shows the model *attempted* an action. Whether it would have "
        "succeeded depends on the tool implementation -- read that code.",
    },
    "LLM07": {
        "root_causes": [
            "The system prompt contains secrets or access rules that matter if disclosed.",
            "Security depends on the prompt staying hidden.",
        ],
        "where_to_look": [
            "System prompt definitions and the config interpolated into them.",
        ],
        "fix_pattern": [
            "Design the prompt to be safe when published; assume it will leak.",
            "Move keys, internal URLs, and business rules out of the prompt into code and "
            "server-side policy.",
            "Enforce authorization in code, not by instructing the model.",
        ],
        "verification": [
            "Re-scan LLM07 with a `--canary` token planted in the real system prompt: a "
            "canary hit is deterministic proof, not a judge opinion.",
        ],
        "limits": "Refusal training makes extraction harder, never impossible. Treat the "
        "prompt as public.",
    },
    "LLM08": {
        "root_causes": [
            "Retrieval is not scoped to the requesting tenant or user.",
            "Embedded content is trusted because it came from 'our' index.",
        ],
        "where_to_look": [
            "Vector-store query calls and their filter/namespace arguments.",
            "Index write paths, for who can add documents.",
        ],
        "fix_pattern": [
            "Apply a mandatory tenant/user filter server-side on every retrieval; never "
            "let the caller supply it.",
            "Separate namespaces or collections per tenant.",
            "Sanitize and delimit retrieved chunks before prompt insertion -- they are "
            "untrusted data.",
        ],
        "verification": [
            "Re-scan LLM08.",
            "Add a test asserting tenant A's query cannot retrieve tenant B's document.",
        ],
        "limits": "Cross-tenant leakage depends on real multi-tenant data; a single-tenant "
        "test index cannot demonstrate it.",
    },
    "LLM09": {
        "root_causes": [
            "Generated claims are presented as fact with no source or confidence signal.",
        ],
        "where_to_look": [
            "Response assembly for user-facing answers; any place output is shown without "
            "citations.",
        ],
        "fix_pattern": [
            "Ground answers in retrieved sources and cite them.",
            "Surface uncertainty instead of hiding it; let the model decline.",
            "Require human review where a wrong answer causes real harm.",
        ],
        "verification": ["Re-scan LLM09 and spot-check the cited sources exist."],
        "limits": "Hallucination rate is statistical. A scan samples it; it does not bound it.",
    },
    "LLM10": {
        "root_causes": [
            "No per-user limit on request rate, token count, or context length.",
        ],
        "where_to_look": [
            "The HTTP entry point; model-call parameters (`max_tokens`); queue and timeout config.",
        ],
        "fix_pattern": [
            "Per-identity rate limits and a token budget, enforced before the model call.",
            "Cap input length and `max_tokens`; set request timeouts.",
            "Bound agent loop depth and total tool calls.",
            "Alert on cost and latency anomalies.",
        ],
        "verification": [
            "Re-scan with `--include-dos-tests` against a disposable instance only.",
        ],
        "limits": "These probes stress the target. Never run them against anything serving "
        "real traffic.",
    },
}


class RemediationGuidance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    title: str = ""
    scanner_recommendation: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_vector: str = ""
    root_causes: list[str] = Field(default_factory=list)
    where_to_look: list[str] = Field(default_factory=list)
    fix_pattern: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    limits: str = ""

    def to_json(self, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)


def _scanner_metadata(category: str) -> tuple[str, list[str], str]:
    """Read recommendation/CWE/CVSS from the installed scanner, if importable."""
    try:
        from llm_scanner.models import (  # type: ignore[import-not-found]
            CVSS_MAP,
            CWE_MAP,
            OWASP_RECOMMENDATIONS,
        )
    except ImportError:
        return "", [], ""
    return (
        OWASP_RECOMMENDATIONS.get(category, ""),
        list(CWE_MAP.get(category, [])),
        CVSS_MAP.get(category, ""),
    )


def guidance_for_category(category: str) -> RemediationGuidance:
    """Return remediation guidance for an OWASP LLM category (e.g. ``"LLM01"``).

    An unknown category yields an empty-but-valid object rather than raising, so a
    newer scanner emitting a category this build does not know degrades gracefully.
    """
    cat = (category or "").strip().upper()
    local = _GUIDANCE.get(cat, {})
    recommendation, cwe_ids, cvss = _scanner_metadata(cat)

    g = RemediationGuidance(
        category=cat,
        title=CATEGORY_TITLES.get(cat, ""),
        scanner_recommendation=recommendation,
        cwe_ids=cwe_ids,
        cvss_vector=cvss,
        root_causes=list(local.get("root_causes", [])),
        where_to_look=list(local.get("where_to_look", [])),
        fix_pattern=list(local.get("fix_pattern", [])),
        verification=list(local.get("verification", [])),
        limits=str(local.get("limits", "")),
    )
    if not local:
        g.limits = f"No local guidance for {cat!r}. Known categories: " + ", ".join(
            sorted(_GUIDANCE)
        )
    return g


def guidance_for_finding(attack_id: str) -> RemediationGuidance:
    """Return guidance for an attack ID such as ``"LLM01-003"``.

    The category prefix is the lookup key, because remediation is a property of the
    vulnerability class, not of the individual payload.
    """
    prefix = (attack_id or "").split("-", 1)[0].strip().upper()
    g = guidance_for_category(prefix)
    return g
