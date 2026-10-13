"""The result envelope: the stable contract every consumer parses."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from llm_scanner_skill.envelope import (
    ENVELOPE_SCHEMA_VERSION,
    Confidence,
    EnvelopeStatus,
    Finding,
    ResultEnvelope,
    Summary,
    error_envelope,
)


class TestSchema:
    def test_version_is_pinned(self) -> None:
        assert ENVELOPE_SCHEMA_VERSION == "1.0"
        assert ResultEnvelope(status=EnvelopeStatus.COMPLETED).schema_version == "1.0"

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' is what makes drift loud instead of silent."""
        with pytest.raises(ValidationError):
            ResultEnvelope(status=EnvelopeStatus.COMPLETED, surprise="x")

    def test_round_trips(self) -> None:
        env = ResultEnvelope(
            status=EnvelopeStatus.COMPLETED,
            target="http://localhost:8000/chat",
            summary=Summary(risk_score=2.5, total_attacks=10, vulnerable=1),
            findings=[
                Finding(
                    attack_id="LLM01-001",
                    owasp_category="LLM01",
                    name="x",
                    severity="high",
                    outcome="vulnerable",
                    evidence_class=Confidence.HEURISTIC,
                )
            ],
        )
        again = ResultEnvelope.model_validate(json.loads(env.to_json()))
        assert again.findings[0].attack_id == "LLM01-001"

    def test_enums_serialize_as_values(self) -> None:
        env = ResultEnvelope(status=EnvelopeStatus.BLOCKED)
        assert json.loads(env.to_json())["status"] == "blocked"

    def test_statuses_are_exhaustive(self) -> None:
        assert {str(s) for s in EnvelopeStatus} == {
            "completed",
            "completed_with_threshold_breach",
            "completed_untrustworthy",
            "blocked",
            "failed",
            "scanner_not_found",
        }

    def test_evidence_classes_are_exhaustive(self) -> None:
        assert {str(c) for c in Confidence} == {
            "confirmed",
            "likely",
            "heuristic",
            "needs_review",
            "inconclusive",
        }


class TestErrorEnvelope:
    def test_blocked_sets_reason_and_warning(self) -> None:
        env = error_envelope(EnvelopeStatus.BLOCKED, "nope", target="t", target_type="url")
        assert env.blocked_reason == "nope"
        assert "nope" in env.warnings
        assert env.errors == []

    def test_failure_sets_errors_not_blocked_reason(self) -> None:
        env = error_envelope(EnvelopeStatus.FAILED, "boom")
        assert env.errors == ["boom"]
        assert env.blocked_reason == ""

    def test_defaults_are_safe(self) -> None:
        """An error envelope must never look like a clean result."""
        env = error_envelope(EnvelopeStatus.FAILED, "boom")
        assert env.findings == []
        assert env.summary.vulnerable == 0
        assert env.status is not EnvelopeStatus.COMPLETED

    def test_extra_warnings_merged(self) -> None:
        env = error_envelope(EnvelopeStatus.BLOCKED, "nope", extra={"warnings": ["also this"]})
        assert "also this" in env.warnings
