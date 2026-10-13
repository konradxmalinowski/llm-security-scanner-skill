"""Builds and validates the scanner's own YAML config -- no parallel schema.

``llm-scanner --config llm-scan.yml`` already defines the configuration format
(``llm_scanner.cli.ScanConfig``). Inventing a second one would mean an agent
writing a file the scanner then silently half-ignores, so this module validates
against the real key set and the real CLI semantics instead.

Two things it adds that ``ScanConfig`` deliberately does not do, because they are
agent concerns rather than CLI concerns:

- it rejects unknown keys (``ScanConfig`` uses ``extra="ignore"``, so a typo like
  ``judge-model`` instead of ``judge_model`` would be dropped without complaint);
- it checks cross-field rules the CLI only enforces at run time, so an agent gets
  the error before a 10-minute scan starts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "ALL_CATEGORIES",
    "CONFIG_KEYS",
    "SAFE_CATEGORIES",
    "build_config",
    "dump_config",
    "validate_config",
    "validate_config_file",
]

# The exact key set accepted by llm_scanner.cli.ScanConfig (scanner 0.8.x).
CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "target",
        "target_type",
        "judge_model",
        "api_key",
        "categories",
        "severity",
        "output_dir",
        "formats",
        "include_dos_tests",
        "fail_on_score",
        "suppressions_file",
        "payloads_dir",
    }
)

# LLM01-LLM09 are the scanner's default "safe" set; LLM10 is opt-in only.
SAFE_CATEGORIES: tuple[str, ...] = tuple(f"LLM{i:02d}" for i in range(1, 10))
ALL_CATEGORIES: tuple[str, ...] = (*SAFE_CATEGORIES, "LLM10")

_VALID_TARGET_TYPES = frozenset({"url", "ollama"})
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_VALID_FORMATS = frozenset({"md", "json", "html", "txt", "sarif"})


def _as_list(value: Any) -> list[str]:
    """Normalize the scanner's ``str | list[str]`` config fields to a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value)]


def validate_config(config: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    """Validate a scan config mapping. Returns (ok, errors, warnings).

    ``ok`` is False only when ``errors`` is non-empty; warnings never block.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(config, dict):
        return False, [f"Config must be a YAML mapping, got {type(config).__name__}."], []

    unknown = sorted(set(config) - CONFIG_KEYS)
    if unknown:
        errors.append(
            f"Unknown config key(s): {', '.join(unknown)}. "
            f"Valid keys: {', '.join(sorted(CONFIG_KEYS))}."
        )

    target_type = config.get("target_type")
    if target_type is not None and target_type not in _VALID_TARGET_TYPES:
        errors.append(f"target_type must be 'url' or 'ollama', got {target_type!r}.")

    target = config.get("target")
    if target is not None and not str(target).strip():
        errors.append("target is present but empty.")
    if target and target_type == "url" and "://" not in str(target):
        # ${ENV_VAR} placeholders are resolved by the CLI at run time, so a bare
        # placeholder is legitimate here and must not be flagged.
        if not str(target).startswith("${"):
            warnings.append(
                f"target {target!r} has no scheme; the scanner will POST to it as-is. "
                "Prefer an explicit http:// or https:// URL."
            )

    severity = config.get("severity")
    if severity is not None and str(severity).lower() not in _VALID_SEVERITIES:
        errors.append(
            f"severity must be one of {', '.join(sorted(_VALID_SEVERITIES))}, got {severity!r}."
        )

    categories = _as_list(config.get("categories"))
    bad_categories = [c for c in categories if c.upper() not in ALL_CATEGORIES]
    if bad_categories:
        errors.append(
            f"Unknown categor(ies): {', '.join(bad_categories)}. "
            f"Valid: {', '.join(ALL_CATEGORIES)}."
        )
    if any(c.upper() == "LLM10" for c in categories) and not config.get("include_dos_tests"):
        warnings.append(
            "LLM10 is listed but include_dos_tests is not true, so the scanner will DROP "
            "LLM10 and warn. Set include_dos_tests: true, or remove LLM10."
        )

    formats = _as_list(config.get("formats"))
    bad_formats = [f for f in formats if f.lower() not in _VALID_FORMATS]
    if bad_formats:
        errors.append(
            f"Unknown format(s): {', '.join(bad_formats)}. "
            f"Valid: {', '.join(sorted(_VALID_FORMATS))}."
        )
    if formats and "json" not in [f.lower() for f in formats]:
        warnings.append(
            "formats does not include 'json'. The skill reads report.json to build its "
            "structured result, so add 'json' unless you only want human reports."
        )

    fail_on_score = config.get("fail_on_score")
    if fail_on_score is not None:
        try:
            score = float(fail_on_score)
        except (TypeError, ValueError):
            errors.append(f"fail_on_score must be a number, got {fail_on_score!r}.")
        else:
            if not 0.0 <= score <= 10.0:
                errors.append(f"fail_on_score must be between 0.0 and 10.0, got {score}.")

    judge_model = config.get("judge_model")
    if judge_model and target_type == "ollama" and str(judge_model) == str(target):
        errors.append(
            f"judge_model and target are both {judge_model!r}. The scanner refuses to let a "
            "model judge itself -- pick a different judge model."
        )

    for key in ("suppressions_file", "payloads_dir"):
        value = config.get(key)
        if value and not Path(str(value)).exists():
            warnings.append(f"{key} points at {value!r}, which does not exist yet.")

    return (not errors), errors, warnings


def validate_config_file(path: str | Path) -> tuple[bool, list[str], list[str]]:
    """Load and validate a YAML config file. Returns (ok, errors, warnings)."""
    p = Path(path)
    if not p.is_file():
        return False, [f"Config file not found: {p}"], []
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return False, [f"Invalid YAML in {p}: {exc}"], []
    if raw is None:
        return False, [f"{p} is empty."], []
    return validate_config(raw)


def build_config(
    *,
    target: str,
    target_type: str,
    judge_model: str = "llama3.2:3b",
    categories: list[str] | None = None,
    severity: str | None = None,
    formats: list[str] | None = None,
    output_dir: str = "./reports",
    fail_on_score: float | None = None,
    include_dos_tests: bool = False,
    api_key_env: str | None = None,
) -> dict[str, Any]:
    """Build a valid scan config for the real scanner.

    Secrets are never inlined: ``api_key_env`` becomes a ``${VAR}`` placeholder,
    which the scanner expands from the environment at run time.
    """
    config: dict[str, Any] = {
        "target": target,
        "target_type": target_type,
        "judge_model": judge_model,
        "categories": list(categories) if categories else list(SAFE_CATEGORIES),
        "formats": list(formats) if formats else ["json", "html", "sarif"],
        "output_dir": output_dir,
    }
    if severity:
        config["severity"] = severity
    if fail_on_score is not None:
        config["fail_on_score"] = fail_on_score
    if include_dos_tests:
        config["include_dos_tests"] = True
    if api_key_env:
        config["api_key"] = "${" + api_key_env + "}"
    return config


def dump_config(config: dict[str, Any]) -> str:
    """Serialize a config to YAML with stable key order."""
    ordered = {k: config[k] for k in sorted(config, key=lambda k: (k != "target", k))}
    return yaml.safe_dump(ordered, sort_keys=False, default_flow_style=False)
