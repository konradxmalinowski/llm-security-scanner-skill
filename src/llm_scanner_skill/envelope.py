"""The stable, versioned result schema the skill layer returns to AI agents.

Why this exists
---------------
``llm-scanner`` already emits a rich ``report.json`` (a serialized
``ScanReport``). That file is the right human/CI artifact but a poor *agent*
interface for three reasons:

1. It has no run-level status. A scan that aborted in preflight produces no
   report at all, so an agent reading only ``report.json`` cannot distinguish
   "no findings" from "never ran".
2. It embeds full raw target responses. Feeding those verbatim into an agent's
   context is exactly the prompt-injection vector this project exists to study.
3. It has no schema version, so an agent cannot detect drift.

``ResultEnvelope`` wraps the scanner's own output rather than replacing it: the
findings keep the scanner's field names (``attack_id``, ``owasp_category``,
``outcome``, ``confidence``, ``verdict_source``, ``cwe_ids``, ``cvss_score``),
and ``reports`` points at the untouched files on disk for anything the agent
needs in full fidelity.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ENVELOPE_SCHEMA_VERSION",
    "Confidence",
    "EnvelopeStatus",
    "Finding",
    "ResultEnvelope",
    "Summary",
    "error_envelope",
]

# Bumped only on a breaking change to the envelope shape. Agents should refuse to
# interpret a major version they do not know.
ENVELOPE_SCHEMA_VERSION = "1.0"


class EnvelopeStatus(StrEnum):
    """Run-level outcome, independent of whether the target was vulnerable.

    The distinction that matters: ``COMPLETED`` with zero findings means the scan
    ran and found nothing. Any other status means the scan's verdict is NOT a
    clean bill of health, and an agent must say so rather than reporting "no
    vulnerabilities found".
    """

    COMPLETED = "completed"
    COMPLETED_WITH_THRESHOLD_BREACH = "completed_with_threshold_breach"
    COMPLETED_UNTRUSTWORTHY = "completed_untrustworthy"
    BLOCKED = "blocked"
    FAILED = "failed"
    SCANNER_NOT_FOUND = "scanner_not_found"


class Confidence(StrEnum):
    """How a finding should be treated when reporting it to a human.

    Maps the scanner's ``verdict_source`` onto the evidence vocabulary the skill
    uses with the user, so an agent never flattens a 0.50 conflict and a 1.00
    canary proof into the same word "found".

    - ``CONFIRMED``   -- ``rule_proof``: a canary token appeared verbatim. Proof by
      string comparison, no model judgement involved.
    - ``LIKELY``      -- ``both_agree``: a deterministic detector and the judge agree.
    - ``HEURISTIC``   -- ``judge_only`` / ``judge_degraded``: one LLM's opinion only.
    - ``NEEDS_REVIEW``-- ``conflict``: a strong rule fired but the judge disagreed.
      Deliberately surfaced, never auto-resolved.
    - ``INCONCLUSIVE``-- ``judge_error``: no verdict was reached. Not a pass.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    HEURISTIC = "heuristic"
    NEEDS_REVIEW = "needs_review"
    INCONCLUSIVE = "inconclusive"


# verdict_source (scanner) -> Confidence (skill vocabulary).
_VERDICT_SOURCE_TO_CONFIDENCE: dict[str, Confidence] = {
    "rule_proof": Confidence.CONFIRMED,
    "both_agree": Confidence.LIKELY,
    "judge_only": Confidence.HEURISTIC,
    "judge_degraded": Confidence.HEURISTIC,
    "conflict": Confidence.NEEDS_REVIEW,
    "judge_error": Confidence.INCONCLUSIVE,
}


def confidence_for(verdict_source: str, outcome: str) -> Confidence:
    """Map a scanner finding onto the skill's evidence vocabulary.

    An unknown ``verdict_source`` (a newer scanner than this adapter) degrades to
    ``HEURISTIC`` rather than raising -- except for ``outcome == "error"``, which is
    always ``INCONCLUSIVE`` because no verdict exists to be confident about.
    """
    if outcome == "error":
        return Confidence.INCONCLUSIVE
    return _VERDICT_SOURCE_TO_CONFIDENCE.get(verdict_source, Confidence.HEURISTIC)


class Finding(BaseModel):
    """One attack result, carrying the scanner's own field names.

    ``evidence`` is a SANITIZED excerpt, never the raw target response: see
    :mod:`llm_scanner_skill.sanitize`. The untouched response stays in
    ``report.json`` on disk for a human to open deliberately.
    """

    model_config = ConfigDict(extra="forbid")

    attack_id: str
    owasp_category: str
    name: str
    severity: str
    outcome: str
    confidence_score: float = 0.0
    verdict_source: str = ""
    evidence_class: Confidence
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_vector: str = ""
    cvss_score: float = 0.0
    recommendation: str = ""
    suppressed: bool = False
    # Sanitized, truncated excerpts. Safe to place in an agent's context.
    payload_excerpt: str = ""
    evidence: str = ""
    judge_reasoning_excerpt: str = ""
    artifact_types: list[str] = Field(default_factory=list)


class Summary(BaseModel):
    """Counts an agent can act on without re-reading every finding."""

    model_config = ConfigDict(extra="forbid")

    risk_score: float = 0.0
    total_attacks: int = 0
    vulnerable: int = 0
    safe: int = 0
    inconclusive: int = 0
    suppressed: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_evidence_class: dict[str, int] = Field(default_factory=dict)


class ResultEnvelope(BaseModel):
    """The single structure every skill script and MCP tool returns."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = ENVELOPE_SCHEMA_VERSION
    status: EnvelopeStatus
    target: str = ""
    target_type: str = ""
    scan_id: str = ""
    timestamp: str = ""
    judge_model: str = ""
    categories_requested: list[str] = Field(default_factory=list)
    categories_scanned: list[str] = Field(default_factory=list)
    summary: Summary = Field(default_factory=Summary)
    findings: list[Finding] = Field(default_factory=list)
    reports: dict[str, str] = Field(default_factory=dict)
    scanner_version: str = ""
    exit_code: int | None = None
    # Operator-facing notes: authorization decisions, judge errors, skipped
    # categories, truncation notices. Never target-controlled text.
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    # Present when the scan did not run, or ran but cannot be trusted.
    blocked_reason: str = ""

    def to_json(self, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)


def error_envelope(
    status: EnvelopeStatus,
    message: str,
    *,
    target: str = "",
    target_type: str = "",
    exit_code: int | None = None,
    extra: dict[str, Any] | None = None,
) -> ResultEnvelope:
    """Build an envelope for a run that never produced a report.

    Used for every non-happy path -- blocked by the authorization gate, scanner
    not installed, Ollama down, target unreachable -- so a caller always receives
    the same shape and never has to parse a traceback.
    """
    env = ResultEnvelope(
        status=status,
        target=target,
        target_type=target_type,
        exit_code=exit_code,
        blocked_reason=message if status is EnvelopeStatus.BLOCKED else "",
    )
    if status is EnvelopeStatus.BLOCKED:
        env.warnings.append(message)
    else:
        env.errors.append(message)
    if extra:
        for key, value in extra.items():
            if key in {"warnings", "errors"} and isinstance(value, list):
                getattr(env, key).extend(str(v) for v in value)
    return env
