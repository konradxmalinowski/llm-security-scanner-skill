"""Config validation against the scanner's real schema."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from llm_scanner_skill.config import (
    CONFIG_KEYS,
    SAFE_CATEGORIES,
    build_config,
    dump_config,
    validate_config,
    validate_config_file,
)


class TestValid:
    def test_minimal(self) -> None:
        ok, errors, _ = validate_config(
            {
                "target": "http://localhost:8000/chat",
                "target_type": "url",
                "judge_model": "llama3.2:3b",
            }
        )
        assert ok, errors

    def test_full(self) -> None:
        ok, errors, _ = validate_config(
            {
                "target": "${LLM_ENDPOINT}",
                "target_type": "url",
                "judge_model": "llama3.2:3b",
                "api_key": "${TOKEN}",
                "categories": ["LLM01", "LLM07"],
                "severity": "medium",
                "output_dir": "./reports",
                "formats": ["json", "sarif"],
                "fail_on_score": 7.0,
            }
        )
        assert ok, errors

    def test_csv_categories(self) -> None:
        ok, errors, _ = validate_config({"categories": "LLM01,LLM07", "formats": "json,html"})
        assert ok, errors

    def test_env_placeholder_target_not_flagged(self) -> None:
        """${VAR} is resolved by the CLI at run time, so it is legitimate here."""
        _, _, warnings = validate_config({"target": "${LLM_ENDPOINT}", "target_type": "url"})
        assert not any("no scheme" in w for w in warnings)


class TestInvalid:
    def test_unknown_key_rejected(self) -> None:
        """The scanner silently IGNORES extras; catching them here is the point."""
        ok, errors, _ = validate_config({"judge-model": "llama3.2:3b"})
        assert not ok
        assert "judge-model" in errors[0]

    def test_bad_target_type(self) -> None:
        ok, errors, _ = validate_config({"target_type": "grpc"})
        assert not ok and "target_type" in errors[0]

    def test_bad_severity(self) -> None:
        ok, _errors, _ = validate_config({"severity": "urgent"})
        assert not ok

    def test_bad_category(self) -> None:
        ok, errors, _ = validate_config({"categories": ["LLM01", "LLM99"]})
        assert not ok and "LLM99" in errors[0]

    def test_bad_format(self) -> None:
        ok, errors, _ = validate_config({"formats": ["json", "pdf"]})
        assert not ok and "pdf" in errors[0]

    def test_fail_on_score_out_of_range(self) -> None:
        ok, _errors, _ = validate_config({"fail_on_score": 42})
        assert not ok

    def test_fail_on_score_not_a_number(self) -> None:
        ok, _errors, _ = validate_config({"fail_on_score": "high"})
        assert not ok

    def test_self_judging_rejected(self) -> None:
        """The scanner refuses this at run time; catching it early saves a long scan."""
        ok, errors, _ = validate_config(
            {"target": "mistral:7b", "target_type": "ollama", "judge_model": "mistral:7b"}
        )
        assert not ok
        assert "judge itself" in errors[0]

    def test_not_a_mapping(self) -> None:
        ok, _errors, _ = validate_config(["a", "list"])  # type: ignore[arg-type]
        assert not ok

    def test_empty_target(self) -> None:
        ok, _, _ = validate_config({"target": "   "})
        assert not ok


class TestWarnings:
    def test_llm10_without_opt_in_warns(self) -> None:
        _, _, warnings = validate_config({"categories": ["LLM01", "LLM10"]})
        assert any("LLM10" in w and "DROP" in w for w in warnings)

    def test_llm10_with_opt_in_does_not_warn(self) -> None:
        _, _, warnings = validate_config({"categories": ["LLM10"], "include_dos_tests": True})
        assert not any("DROP" in w for w in warnings)

    def test_missing_json_format_warns(self) -> None:
        _, _, warnings = validate_config({"formats": ["html"]})
        assert any("json" in w for w in warnings)

    def test_missing_file_warns_not_errors(self) -> None:
        ok, _, warnings = validate_config({"suppressions_file": "/nope/supp.yml"})
        assert ok
        assert any("does not exist" in w for w in warnings)

    def test_schemeless_url_warns(self) -> None:
        _, _, warnings = validate_config({"target": "localhost:8000/chat", "target_type": "url"})
        assert any("no scheme" in w for w in warnings)


class TestBuild:
    def test_defaults_to_safe_categories(self) -> None:
        cfg = build_config(target="http://localhost:8000/chat", target_type="url")
        assert cfg["categories"] == list(SAFE_CATEGORIES)
        assert "LLM10" not in cfg["categories"]

    def test_built_config_is_valid(self) -> None:
        cfg = build_config(
            target="http://localhost:8000/chat",
            target_type="url",
            categories=["LLM01"],
            severity="high",
            fail_on_score=7.0,
        )
        ok, errors, _ = validate_config(cfg)
        assert ok, errors

    def test_api_key_is_a_placeholder_never_a_literal(self) -> None:
        cfg = build_config(target="http://x/chat", target_type="url", api_key_env="MY_TOKEN")
        assert cfg["api_key"] == "${MY_TOKEN}"

    def test_dos_opt_in_recorded(self) -> None:
        cfg = build_config(
            target="http://x/chat",
            target_type="url",
            categories=["LLM10"],
            include_dos_tests=True,
        )
        assert cfg["include_dos_tests"] is True

    def test_only_declared_keys_are_emitted(self) -> None:
        cfg = build_config(target="t", target_type="url")
        assert set(cfg) <= CONFIG_KEYS

    def test_dump_is_loadable_yaml(self) -> None:
        cfg = build_config(target="http://localhost:8000/chat", target_type="url")
        assert yaml.safe_load(dump_config(cfg)) == cfg


class TestFile:
    def test_valid_file(self, tmp_path: Path) -> None:
        p = tmp_path / "llm-scan.yml"
        p.write_text(
            yaml.safe_dump(build_config(target="http://localhost:8000/chat", target_type="url")),
            encoding="utf-8",
        )
        ok, errors, _ = validate_config_file(p)
        assert ok, errors

    def test_missing_file(self, tmp_path: Path) -> None:
        ok, errors, _ = validate_config_file(tmp_path / "nope.yml")
        assert not ok and "not found" in errors[0]

    def test_malformed_yaml(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.yml"
        p.write_text("target: [unclosed\n", encoding="utf-8")
        ok, errors, _ = validate_config_file(p)
        assert not ok and "Invalid YAML" in errors[0]

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.yml"
        p.write_text("", encoding="utf-8")
        ok, _errors, _ = validate_config_file(p)
        assert not ok

    @pytest.mark.parametrize(
        "name",
        ["ci-url.yml", "local-url.yml", "ollama-target.yml", "public-url.yml"],
    )
    def test_shipped_examples_are_valid(self, name: str) -> None:
        """The example configs in this repo must actually pass validation."""
        path = Path(__file__).resolve().parents[1] / "examples" / "config" / name
        if not path.is_file():
            pytest.skip(f"{name} not present")
        ok, errors, _ = validate_config_file(path)
        assert ok, errors
