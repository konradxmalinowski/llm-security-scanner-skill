"""Before/after comparison: the step that verifies a fix actually worked."""

from __future__ import annotations

from llm_scanner_skill.compare import DeltaKind, compare_envelopes, compare_report_files
from llm_scanner_skill.summarize import summarize_report


def _env(findings: list[dict], risk: float = 0.0, target: str = "http://localhost:8000/chat"):
    return summarize_report(
        {
            "target": target,
            "timestamp": "2026-10-13T12:00:00+00:00",
            "risk_score": risk,
            "findings": findings,
        },
        include_safe=True,
    )


class TestDeltas:
    def test_fixed(self, make_finding) -> None:
        before = _env([make_finding("LLM01-001", "LLM01")], risk=2.5)
        after = _env([make_finding("LLM01-001", "LLM01", outcome="safe")], risk=0.0)
        r = compare_envelopes(before, after)
        assert [d.attack_id for d in r.fixed] == ["LLM01-001"]
        assert r.risk_score_delta == -2.5
        assert "now safe" in r.verdict

    def test_still_vulnerable(self, make_finding) -> None:
        f = [make_finding("LLM01-001", "LLM01")]
        r = compare_envelopes(_env(f, 2.5), _env(f, 2.5))
        assert [d.attack_id for d in r.still_vulnerable] == ["LLM01-001"]
        assert "No change" in r.verdict

    def test_regression_is_surfaced_first(self, make_finding) -> None:
        """A fix that broke a previously-safe category must not read as progress."""
        before = _env(
            [
                make_finding("LLM01-001", "LLM01"),
                make_finding("LLM05-001", "LLM05", outcome="safe"),
            ],
            risk=2.5,
        )
        after = _env(
            [
                make_finding("LLM01-001", "LLM01", outcome="safe"),
                make_finding("LLM05-001", "LLM05"),
            ],
            risk=2.5,
        )
        r = compare_envelopes(before, after)
        assert [d.attack_id for d in r.regressed] == ["LLM05-001"]
        assert [d.attack_id for d in r.fixed] == ["LLM01-001"]
        assert r.verdict.startswith("REGRESSION")

    def test_new_finding(self, make_finding) -> None:
        before = _env([make_finding("LLM01-001", "LLM01", outcome="safe")])
        after = _env(
            [
                make_finding("LLM01-001", "LLM01", outcome="safe"),
                make_finding("LLM06-009", "LLM06"),
            ]
        )
        r = compare_envelopes(before, after)
        assert [d.attack_id for d in r.new] == ["LLM06-009"]

    def test_became_inconclusive_blocks_a_success_claim(self, make_finding) -> None:
        before = _env([make_finding("LLM01-001", "LLM01")])
        after = _env(
            [
                make_finding(
                    "LLM01-001",
                    "LLM01",
                    outcome="error",
                    verdict_source="judge_error",
                    judge_error="judge_timeout",
                ),
            ]
        )
        r = compare_envelopes(before, after)
        assert r.inconclusive
        assert "INCOMPLETE" in r.verdict
        assert not r.fixed

    def test_both_clean(self, make_finding) -> None:
        f = [make_finding("LLM01-001", "LLM01", outcome="safe")]
        r = compare_envelopes(_env(f), _env(f))
        assert r.verdict == "No vulnerable attacks in either scan."


class TestScopeSafety:
    def test_narrower_rescan_does_not_claim_a_fix(self, make_finding) -> None:
        """A disappearing attack from a narrower scan is 'removed', not 'fixed'."""
        before = summarize_report(
            {
                "target": "t",
                "timestamp": "",
                "risk_score": 5.0,
                "findings": [
                    make_finding("LLM01-001", "LLM01"),
                    make_finding("LLM05-001", "LLM05"),
                ],
            },
            include_safe=True,
        )
        after = summarize_report(
            {
                "target": "t",
                "timestamp": "",
                "risk_score": 2.5,
                "findings": [
                    make_finding("LLM01-001", "LLM01"),
                ],
            },
            include_safe=True,
        )
        r = compare_envelopes(before, after)
        assert [d.attack_id for d in r.removed] == ["LLM05-001"]
        assert not r.fixed
        assert any("different OWASP categories" in w for w in r.warnings)

    def test_different_targets_warn(self, make_finding) -> None:
        before = _env([make_finding("LLM01-001", "LLM01")], target="http://localhost:8000/a")
        after = _env([make_finding("LLM01-001", "LLM01")], target="http://localhost:9000/b")
        r = compare_envelopes(before, after)
        assert any("different targets" in w for w in r.warnings)


class TestFiles:
    def test_compare_two_files(self, make_finding, write_report) -> None:
        b = write_report(
            {
                "target": "t",
                "timestamp": "",
                "risk_score": 2.5,
                "findings": [make_finding("LLM01-001", "LLM01")],
            },
            "before.json",
        )
        a = write_report(
            {
                "target": "t",
                "timestamp": "",
                "risk_score": 0.0,
                "findings": [make_finding("LLM01-001", "LLM01", outcome="safe")],
            },
            "after.json",
        )
        r = compare_report_files(b, a)
        assert [d.attack_id for d in r.fixed] == ["LLM01-001"]

    def test_missing_file_is_reported_not_raised(
        self, tmp_path, make_finding, write_report
    ) -> None:
        a = write_report({"target": "t", "timestamp": "", "risk_score": 0.0, "findings": []})
        r = compare_report_files(tmp_path / "nope.json", a)
        assert any("before report" in w for w in r.warnings)

    def test_result_serializes(self, make_finding, write_report) -> None:
        import json

        b = write_report(
            {
                "target": "t",
                "timestamp": "",
                "risk_score": 1.0,
                "findings": [make_finding("LLM01-001", "LLM01")],
            },
            "b.json",
        )
        a = write_report(
            {
                "target": "t",
                "timestamp": "",
                "risk_score": 0.0,
                "findings": [make_finding("LLM01-001", "LLM01", outcome="safe")],
            },
            "a.json",
        )
        data = json.loads(compare_report_files(b, a).to_json())
        assert data["fixed"][0]["kind"] == DeltaKind.FIXED


class TestEvidenceStrength:
    """Attack-level verdicts alone hide a real class of progress.

    When a canary stops leaking, the deterministic proof disappears while a small
    local judge may keep reporting "vulnerable" from a refusal message. That is
    genuine progress and must be surfaced, not averaged into "no change". Found
    while validating the skill end to end against a live target.
    """

    def test_losing_deterministic_proof_is_surfaced(self, make_finding) -> None:
        before = _env(
            [
                make_finding(
                    "LLM07-001",
                    "LLM07",
                    verdict_source="rule_proof",
                    confidence=1.0,
                    artifacts=[
                        {
                            "type": "canary",
                            "detector": "canary_exact",
                            "fingerprint": "ab..cd",
                            "span": [0, 4],
                            "confidence": 1.0,
                            "raw": None,
                        }
                    ],
                ),
            ],
            risk=2.5,
        )
        after = _env(
            [
                make_finding("LLM07-001", "LLM07", verdict_source="judge_only", confidence=0.6),
            ],
            risk=2.5,
        )
        r = compare_envelopes(before, after)
        assert [d.attack_id for d in r.proof_lost] == ["LLM07-001"]
        assert [d.attack_id for d in r.still_vulnerable] == ["LLM07-001"]
        assert "PARTIAL PROGRESS" in r.verdict
        assert "judge alone" in r.verdict

    def test_gaining_deterministic_proof_is_a_hardening_regression(self, make_finding) -> None:
        before = _env([make_finding("LLM07-001", "LLM07", verdict_source="judge_only")])
        after = _env(
            [
                make_finding("LLM07-001", "LLM07", verdict_source="rule_proof", confidence=1.0),
            ]
        )
        r = compare_envelopes(before, after)
        assert [d.attack_id for d in r.proof_gained] == ["LLM07-001"]
        assert "HARDENING REGRESSION" in r.verdict

    def test_unchanged_evidence_is_not_flagged(self, make_finding) -> None:
        f = [make_finding("LLM01-001", "LLM01", verdict_source="judge_only")]
        r = compare_envelopes(_env(f), _env(f))
        assert r.proof_lost == [] and r.proof_gained == []
        assert "No change" in r.verdict

    def test_proof_lost_is_mentioned_alongside_real_fixes(self, make_finding) -> None:
        before = _env(
            [
                make_finding("LLM01-001", "LLM01"),
                make_finding("LLM07-001", "LLM07", verdict_source="rule_proof", confidence=1.0),
            ],
            risk=5.0,
        )
        after = _env(
            [
                make_finding("LLM01-001", "LLM01", outcome="safe"),
                make_finding("LLM07-001", "LLM07", verdict_source="judge_only", confidence=0.6),
            ],
            risk=2.5,
        )
        r = compare_envelopes(before, after)
        assert len(r.fixed) == 1
        assert len(r.proof_lost) == 1
        assert "lost their deterministic evidence" in r.verdict

    def test_a_real_fix_is_not_counted_as_proof_lost(self, make_finding) -> None:
        """Vulnerable -> safe is `fixed`, not a weakened-evidence case."""
        before = _env([make_finding("LLM07-001", "LLM07", verdict_source="rule_proof")])
        after = _env(
            [make_finding("LLM07-001", "LLM07", outcome="safe", verdict_source="both_agree")]
        )
        r = compare_envelopes(before, after)
        assert len(r.fixed) == 1
        assert r.proof_lost == []
