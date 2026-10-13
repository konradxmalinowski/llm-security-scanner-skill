"""Before/after scan comparison -- the "did my fix actually work" step.

The scanner already ships ``llm-scanner baseline save/compare``, which is the right
tool for a CI gate: it answers "are there findings that were not in the baseline".
This module answers the different question an agent needs during a remediation
loop: for one specific attack that was vulnerable before, what is it now, and did
anything regress while I was fixing it.

Comparison is keyed on ``attack_id`` because that is the scanner's stable payload
identifier.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from llm_scanner_skill.envelope import Finding, ResultEnvelope
from llm_scanner_skill.summarize import summarize_report_file

__all__ = [
    "ComparisonResult",
    "DeltaKind",
    "FindingDelta",
    "compare_envelopes",
    "compare_report_files",
]


class DeltaKind(StrEnum):
    """What happened to one attack between the two scans."""

    FIXED = "fixed"
    STILL_VULNERABLE = "still_vulnerable"
    REGRESSED = "regressed"
    NEW = "new"
    REMOVED = "removed"
    UNCHANGED_SAFE = "unchanged_safe"
    BECAME_INCONCLUSIVE = "became_inconclusive"
    WAS_INCONCLUSIVE = "was_inconclusive"
    # An attack still reported vulnerable, but the DETERMINISTIC evidence behind it
    # changed. This matters because the attack-level verdict alone can hide real
    # progress: when a canary stops leaking, the proof disappears while a small local
    # judge may keep guessing "vulnerable" from a refusal message. Losing proof is
    # progress; gaining it is a hardening regression.
    PROOF_LOST = "proof_lost"
    PROOF_GAINED = "proof_gained"


class FindingDelta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    owasp_category: str
    name: str
    severity: str
    kind: DeltaKind
    before_outcome: str = ""
    after_outcome: str = ""
    before_evidence_class: str = ""
    after_evidence_class: str = ""


class ComparisonResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    before_target: str = ""
    after_target: str = ""
    before_timestamp: str = ""
    after_timestamp: str = ""
    before_risk_score: float = 0.0
    after_risk_score: float = 0.0
    risk_score_delta: float = 0.0
    fixed: list[FindingDelta] = Field(default_factory=list)
    still_vulnerable: list[FindingDelta] = Field(default_factory=list)
    regressed: list[FindingDelta] = Field(default_factory=list)
    new: list[FindingDelta] = Field(default_factory=list)
    removed: list[FindingDelta] = Field(default_factory=list)
    inconclusive: list[FindingDelta] = Field(default_factory=list)
    proof_lost: list[FindingDelta] = Field(default_factory=list)
    proof_gained: list[FindingDelta] = Field(default_factory=list)
    verdict: str = ""
    warnings: list[str] = Field(default_factory=list)

    def to_json(self, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)


# How much a verdict rests on deterministic evidence rather than on model judgement.
_EVIDENCE_STRENGTH: dict[str, int] = {
    "confirmed": 4,  # a canary matched verbatim -- proof by string comparison
    "likely": 3,  # a rule fired and the judge agreed
    "needs_review": 2,  # a rule fired, the judge disagreed
    "heuristic": 1,  # the judge alone
    "inconclusive": 0,  # no verdict reached
}
# At or above this, a deterministic detector contributed to the verdict.
_DETERMINISTIC_FLOOR = 3


def _index(envelope: ResultEnvelope) -> dict[str, Finding]:
    return {f.attack_id: f for f in envelope.findings if f.attack_id}


def _delta(
    attack_id: str,
    kind: DeltaKind,
    before: Finding | None,
    after: Finding | None,
) -> FindingDelta:
    ref = after or before
    assert ref is not None  # one of the two is always present
    return FindingDelta(
        attack_id=attack_id,
        owasp_category=ref.owasp_category,
        name=ref.name,
        severity=ref.severity,
        kind=kind,
        before_outcome=before.outcome if before else "",
        after_outcome=after.outcome if after else "",
        before_evidence_class=str(before.evidence_class) if before else "",
        after_evidence_class=str(after.evidence_class) if after else "",
    )


def compare_envelopes(before: ResultEnvelope, after: ResultEnvelope) -> ComparisonResult:
    """Diff two envelopes attack-by-attack.

    Note on asymmetry: by default an envelope lists only non-SAFE findings, so an
    attack present in ``before`` and absent from ``after`` usually means it is now
    SAFE (fixed), not that it was skipped. That inference is only drawn when the
    two scans covered the same categories; otherwise the attack is reported as
    ``REMOVED`` and a warning says the scopes differed, because claiming a fix from
    a narrower re-scan would be wrong.
    """
    result = ComparisonResult(
        before_target=before.target,
        after_target=after.target,
        before_timestamp=before.timestamp,
        after_timestamp=after.timestamp,
        before_risk_score=before.summary.risk_score,
        after_risk_score=after.summary.risk_score,
        risk_score_delta=round(after.summary.risk_score - before.summary.risk_score, 2),
    )

    if before.target and after.target and before.target != after.target:
        result.warnings.append(
            f"Comparing different targets ({before.target!r} vs {after.target!r}); "
            "the delta may not be meaningful."
        )

    before_cats = set(before.categories_scanned)
    after_cats = set(after.categories_scanned)
    same_scope = not before_cats or not after_cats or before_cats == after_cats
    if not same_scope:
        result.warnings.append(
            "The two scans covered different OWASP categories "
            f"(before: {sorted(before_cats)}, after: {sorted(after_cats)}). "
            "An attack missing from the later scan is reported as removed, not fixed."
        )

    b_idx, a_idx = _index(before), _index(after)

    for attack_id in sorted(set(b_idx) | set(a_idx)):
        b, a = b_idx.get(attack_id), a_idx.get(attack_id)

        if b is None and a is not None:
            if a.outcome == "vulnerable":
                result.new.append(_delta(attack_id, DeltaKind.NEW, b, a))
            elif a.outcome == "error":
                result.inconclusive.append(_delta(attack_id, DeltaKind.BECAME_INCONCLUSIVE, b, a))
            continue

        if a is None and b is not None:
            kind = (
                DeltaKind.FIXED if (b.outcome == "vulnerable" and same_scope) else DeltaKind.REMOVED
            )
            bucket = result.fixed if kind is DeltaKind.FIXED else result.removed
            bucket.append(_delta(attack_id, kind, b, a))
            continue

        assert b is not None and a is not None
        if b.outcome == "vulnerable" and a.outcome == "safe":
            result.fixed.append(_delta(attack_id, DeltaKind.FIXED, b, a))
        elif b.outcome == "vulnerable" and a.outcome == "vulnerable":
            result.still_vulnerable.append(_delta(attack_id, DeltaKind.STILL_VULNERABLE, b, a))
            before_rank = _EVIDENCE_STRENGTH.get(str(b.evidence_class), 0)
            after_rank = _EVIDENCE_STRENGTH.get(str(a.evidence_class), 0)
            if before_rank >= _DETERMINISTIC_FLOOR > after_rank:
                result.proof_lost.append(_delta(attack_id, DeltaKind.PROOF_LOST, b, a))
            elif after_rank >= _DETERMINISTIC_FLOOR > before_rank:
                result.proof_gained.append(_delta(attack_id, DeltaKind.PROOF_GAINED, b, a))
        elif b.outcome == "safe" and a.outcome == "vulnerable":
            result.regressed.append(_delta(attack_id, DeltaKind.REGRESSED, b, a))
        elif a.outcome == "error":
            result.inconclusive.append(_delta(attack_id, DeltaKind.BECAME_INCONCLUSIVE, b, a))
        elif b.outcome == "error":
            result.inconclusive.append(_delta(attack_id, DeltaKind.WAS_INCONCLUSIVE, b, a))

    result.verdict = _verdict(result)
    return result


def _verdict(result: ComparisonResult) -> str:
    """One sentence an agent can relay without re-deriving it from the lists.

    Regressions and inconclusive results are called out first on purpose: a fix
    that silently broke a previously-safe category, or a re-scan whose judge
    failed, must not be reported as progress.
    """
    if result.regressed:
        return (
            f"REGRESSION: {len(result.regressed)} attack(s) that were safe before now "
            f"succeed. {len(result.fixed)} fixed, {len(result.still_vulnerable)} still open."
        )
    if result.proof_gained:
        return (
            f"HARDENING REGRESSION: {len(result.proof_gained)} attack(s) now carry "
            "deterministic proof (a detector fired) where before only the judge flagged "
            f"them. {len(result.fixed)} fixed, {len(result.still_vulnerable)} still open."
        )
    if result.new:
        return (
            f"{len(result.new)} new vulnerable attack(s) appeared, "
            f"{len(result.fixed)} fixed, {len(result.still_vulnerable)} still open."
        )
    if result.inconclusive:
        return (
            f"INCOMPLETE: {len(result.inconclusive)} attack(s) could not be evaluated, so "
            f"the comparison is partial. {len(result.fixed)} fixed, "
            f"{len(result.still_vulnerable)} still open."
        )
    if result.fixed and not result.still_vulnerable:
        return (
            f"All {len(result.fixed)} previously-vulnerable attack(s) are now safe. "
            f"Risk score {result.before_risk_score:.1f} -> {result.after_risk_score:.1f}."
        )
    if result.fixed:
        proof = (
            f" A further {len(result.proof_lost)} lost their deterministic evidence and now "
            "rest on the judge alone -- re-read those before treating them as real."
            if result.proof_lost
            else ""
        )
        return (
            f"{len(result.fixed)} fixed, {len(result.still_vulnerable)} still vulnerable. "
            f"Risk score {result.before_risk_score:.1f} -> {result.after_risk_score:.1f}.{proof}"
        )
    if result.proof_lost and not result.fixed:
        return (
            f"PARTIAL PROGRESS: no attack flipped to safe, but {len(result.proof_lost)} lost "
            "its deterministic evidence (e.g. the canary stopped leaking), so those now rest "
            f"on the judge alone. {len(result.still_vulnerable)} are still reported "
            "vulnerable -- re-read those, they are the likeliest false positives."
        )
    if result.still_vulnerable:
        return f"No change: {len(result.still_vulnerable)} attack(s) remain vulnerable."
    return "No vulnerable attacks in either scan."


def compare_report_files(
    before_path: str | Path,
    after_path: str | Path,
) -> ComparisonResult:
    """Compare two ``report.json`` files on disk."""
    before = summarize_report_file(before_path, include_safe=True)
    after = summarize_report_file(after_path, include_safe=True)
    result = compare_envelopes(before, after)
    for env, label in ((before, "before"), (after, "after")):
        if env.errors:
            result.warnings.append(f"Could not fully read the {label} report: {env.errors[0]}")
    return result
