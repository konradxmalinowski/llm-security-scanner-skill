"""The CLI surface. Every subcommand must emit parseable JSON on stdout."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_scanner_skill.cli import main


def _json_out(capsys) -> dict:
    out = capsys.readouterr().out
    return json.loads(out)


class TestContractEverySubcommandEmitsJson:
    def test_inspect(self, capsys, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("from openai import OpenAI\n", encoding="utf-8")
        assert main(["inspect", str(tmp_path)]) == 0
        assert _json_out(capsys)["is_llm_application"] is True

    def test_authorize_allowed(self, capsys) -> None:
        rc = main(["authorize", "--target", "http://localhost:8000/chat", "--target-type", "url"])
        assert rc == 0
        assert _json_out(capsys)["allowed"] is True

    def test_authorize_blocked_uses_a_distinct_exit_code(self, capsys) -> None:
        """Exit 3 lets a caller distinguish 'refused' from 'failed'."""
        rc = main(
            ["authorize", "--target", "https://api.openai.com/v1/chat", "--target-type", "url"]
        )
        assert rc == 3
        assert _json_out(capsys)["allowed"] is False

    def test_categories(self, capsys) -> None:
        assert main(["categories"]) == 0
        data = _json_out(capsys)
        assert len(data["categories"]) == 10
        assert data["categories"][-1]["id"] == "LLM10"
        assert data["categories"][-1]["requires_opt_in"] is True

    def test_categories_reads_real_payload_counts(self, capsys) -> None:
        """Counts come from the installed scanner, not a hardcoded table."""
        main(["categories"])
        data = _json_out(capsys)
        assert data["total_payloads"] >= 40, data.get("note")
        llm01 = next(c for c in data["categories"] if c["id"] == "LLM01")
        assert llm01["payloads"] >= 4

    def test_init_config(self, capsys, tmp_path: Path) -> None:
        out = tmp_path / "llm-scan.yml"
        rc = main(
            [
                "init-config",
                "--target",
                "http://localhost:8000/chat",
                "--target-type",
                "url",
                "--categories",
                "LLM01,LLM07",
                "--out",
                str(out),
            ]
        )
        assert rc == 0
        data = _json_out(capsys)
        assert data["config"]["categories"] == ["LLM01", "LLM07"]
        assert out.is_file()

    def test_init_config_output_is_valid(self, capsys, tmp_path: Path) -> None:
        """init-config then validate-config must round-trip cleanly."""
        out = tmp_path / "llm-scan.yml"
        main(
            [
                "init-config",
                "--target",
                "http://localhost:8000/chat",
                "--target-type",
                "url",
                "--out",
                str(out),
            ]
        )
        capsys.readouterr()
        assert main(["validate-config", str(out)]) == 0
        assert _json_out(capsys)["valid"] is True

    def test_validate_config_invalid_exits_nonzero(self, capsys, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("target_type: grpc\n", encoding="utf-8")
        assert main(["validate-config", str(bad)]) == 1
        assert _json_out(capsys)["valid"] is False

    def test_summarize(self, capsys, report_with_findings, write_report) -> None:
        path = write_report(report_with_findings)
        assert main(["summarize", str(path)]) == 0
        data = _json_out(capsys)
        assert data["summary"]["vulnerable"] == 4
        assert data["status"] == "completed_untrustworthy"

    def test_summarize_missing_file(self, capsys, tmp_path: Path) -> None:
        assert main(["summarize", str(tmp_path / "nope.json")]) == 1
        assert _json_out(capsys)["errors"]

    def test_compare(self, capsys, make_finding, write_report) -> None:
        b = write_report(
            {
                "target": "t",
                "timestamp": "",
                "risk_score": 2.5,
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
        assert main(["compare", str(b), str(a)]) == 0
        assert _json_out(capsys)["fixed"][0]["attack_id"] == "LLM01-001"

    @pytest.mark.parametrize("arg", ["LLM01", "LLM01-003", "llm01"])
    def test_remediate_accepts_category_or_attack_id(self, capsys, arg: str) -> None:
        assert main(["remediate", arg]) == 0
        data = _json_out(capsys)
        assert data["category"] == "LLM01"
        assert data["fix_pattern"]

    def test_remediate_unknown_category_degrades(self, capsys) -> None:
        assert main(["remediate", "LLM99"]) == 0
        assert "No local guidance" in _json_out(capsys)["limits"]

    def test_doctor_reports_without_crashing(self, capsys) -> None:
        main(["doctor"])
        data = _json_out(capsys)
        assert {"ok", "checks", "skill_version"} <= set(data)
        names = {c["check"] for c in data["checks"]}
        assert names == {"scanner_cli", "ollama", "skill_bundle"}


class TestScanSubcommand:
    def test_blocked_target_exits_3_and_emits_envelope(self, capsys) -> None:
        rc = main(
            ["scan", "--target", "https://api.anthropic.com/v1/messages", "--target-type", "url"]
        )
        assert rc == 3
        data = _json_out(capsys)
        assert data["status"] == "blocked"
        assert data["blocked_reason"]

    def test_unauthorized_external_is_blocked(self, capsys) -> None:
        rc = main(["scan", "--target", "http://93.184.216.34/chat", "--target-type", "url"])
        assert rc == 3
        assert _json_out(capsys)["status"] == "blocked"


class TestStdoutPurity:
    def test_human_notes_go_to_stderr_only(self, capsys, tmp_path: Path) -> None:
        """stdout must stay machine-parseable even when a note is printed."""
        out = tmp_path / "c.yml"
        main(
            [
                "init-config",
                "--target",
                "http://localhost:8000/chat",
                "--target-type",
                "url",
                "--out",
                str(out),
            ]
        )
        captured = capsys.readouterr()
        json.loads(captured.out)
        assert "Wrote" in captured.err


class TestParser:
    def test_version_flag(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_unknown_subcommand_exits_2(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["nope"])
        assert exc.value.code == 2

    def test_subcommand_required(self) -> None:
        with pytest.raises(SystemExit):
            main([])
