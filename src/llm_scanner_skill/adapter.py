"""The one place that invokes the real scanner. Everything else reads its output.

Design
------
The skill shells out to the installed ``llm-scanner`` CLI rather than importing
``llm_scanner.scanner`` and driving the engine itself. That is deliberate:

- the CLI is the scanner's supported, versioned public interface, while its
  internals are free to change between releases;
- the CLI already owns preflight checks, payload loading, concurrency, the judge,
  the detector layer, reconciliation, redaction and every reporter. Re-driving
  those from here would duplicate exactly what this skill must not duplicate;
- a subprocess boundary means a scan that hangs or crashes cannot take the
  agent's own process with it, and it gives us a hard timeout.

This module therefore does three things only: find the scanner, build an argv,
and turn what came back into a :class:`~llm_scanner_skill.envelope.ResultEnvelope`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from llm_scanner_skill.authz import authorize
from llm_scanner_skill.envelope import EnvelopeStatus, ResultEnvelope, error_envelope
from llm_scanner_skill.summarize import summarize_report_file

__all__ = [
    "DEFAULT_TIMEOUT_S",
    "ScannerNotFoundError",
    "find_scanner",
    "run_scan",
    "scanner_version",
]

# A full 51-payload scan against a slow local model legitimately takes a long
# time (two model round-trips per payload). 45 minutes is the ceiling before we
# assume something is wedged rather than slow.
DEFAULT_TIMEOUT_S = 2700

# Exit codes the scanner defines (see llm_scanner.cli._ScanAbort).
_EXIT_OK = 0
_EXIT_FAIL = 1  # scan ran; risk threshold breached, or a setup error
_EXIT_JUDGE_ERROR = 2  # --fail-on-judge-error: part of the scan was not evaluated


class ScannerNotFoundError(RuntimeError):
    """Raised when no usable ``llm-scanner`` can be located."""


def find_scanner() -> list[str]:
    """Return the argv prefix that runs the scanner.

    Resolution order:

    1. ``$LLM_SCANNER_BIN`` -- an explicit override, so a user can point the skill
       at a pinned virtualenv, a wrapper script, or a ``docker run`` shim.
    2. ``llm-scanner`` on ``PATH`` -- the normal pip/uv install.
    3. The current interpreter, if ``llm_scanner`` is importable. This covers a
       venv whose ``bin/`` is not on ``PATH``, which is common when an agent runs
       inside one environment and the scanner lives in another.

    Raises:
        ScannerNotFoundError: if none of the above resolves.
    """
    override = os.environ.get("LLM_SCANNER_BIN", "").strip()
    if override:
        parts = override.split()
        # Only verify the executable when it looks like a path/name we can resolve;
        # a shim such as "docker run ..." is passed through untouched.
        if len(parts) == 1 and not shutil.which(parts[0]) and not Path(parts[0]).is_file():
            raise ScannerNotFoundError(
                f"$LLM_SCANNER_BIN points at {override!r}, which is not executable."
            )
        return parts

    found = shutil.which("llm-scanner")
    if found:
        return [found]

    try:
        import llm_scanner  # noqa: F401
    except ImportError as exc:
        raise ScannerNotFoundError(
            "llm-security-scanner is not installed. Install it with:\n"
            "  uv pip install llm-security-scanner\n"
            "or set $LLM_SCANNER_BIN to an executable that runs it."
        ) from exc
    return [sys.executable, "-c", "from llm_scanner.cli import main; main()"]


def scanner_version() -> str:
    """Return the installed scanner's version, or "" when it cannot be determined."""
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover - importlib.metadata is stdlib on 3.11+
        return ""
    try:
        return version("llm-security-scanner")
    except PackageNotFoundError:
        return ""


def _newest_report_dir(output_dir: Path) -> Path | None:
    """Find the scan subfolder the run just wrote.

    The scanner names each run ``<output_dir>/<YYYYmmddTHHMMSS>_<target_slug>/``
    and also keeps ``baselines/`` under the same parent, which is excluded here.
    """
    if not output_dir.is_dir():
        return None
    candidates = [
        p
        for p in output_dir.iterdir()
        if p.is_dir() and p.name != "baselines" and (p / "report.json").is_file()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _build_argv(
    scanner: Sequence[str],
    *,
    target: str,
    target_type: str,
    judge_model: str,
    output_dir: Path,
    categories: list[str] | None,
    severity: str | None,
    formats: list[str],
    api_key: str | None,
    config_file: str | Path | None,
    fail_on_score: float | None,
    fail_on_judge_error: bool,
    include_dos_tests: bool,
    concurrency: int | None,
    retries: int | None,
    canary: str | None,
    system_prompt: str | None,
    suppressions_file: str | Path | None,
    payloads_dir: str | Path | None,
    log_level: str | None,
) -> list[str]:
    """Assemble the scanner argv. Flag names mirror the CLI exactly."""
    argv = [*scanner]
    if config_file:
        argv += ["--config", str(config_file)]
    if target:
        argv += ["--target", target]
    if target_type:
        argv += ["--target-type", target_type]
    if judge_model:
        argv += ["--judge-model", judge_model]
    argv += ["--output-dir", str(output_dir)]
    argv += ["--format", ",".join(formats)]
    if categories:
        argv += ["--categories", ",".join(categories)]
    if severity:
        argv += ["--severity", severity]
    if api_key:
        argv += ["--api-key", api_key]
    if fail_on_score is not None:
        argv += ["--fail-on-score", str(fail_on_score)]
    if fail_on_judge_error:
        argv.append("--fail-on-judge-error")
    if include_dos_tests:
        argv.append("--include-dos-tests")
    if concurrency is not None:
        argv += ["--concurrency", str(concurrency)]
    if retries is not None:
        argv += ["--retries", str(retries)]
    if canary:
        argv += ["--canary", canary]
    if system_prompt:
        argv += ["--system-prompt", system_prompt]
    if suppressions_file:
        argv += ["--suppressions", str(suppressions_file)]
    if payloads_dir:
        argv += ["--payloads-dir", str(payloads_dir)]
    if log_level:
        argv += ["--log-level", log_level]
    # NOTE: --include-raw-artifacts is never passed. The scanner redacts detected
    # secrets and canaries to a fingerprint by default, and that default is exactly
    # what we want when the output is headed for an AI agent's context.
    return argv


def run_scan(
    *,
    target: str = "",
    target_type: str = "",
    judge_model: str = "llama3.2:3b",
    output_dir: str | Path = "./reports",
    categories: list[str] | None = None,
    severity: str | None = None,
    formats: list[str] | None = None,
    api_key: str | None = None,
    config_file: str | Path | None = None,
    fail_on_score: float | None = None,
    fail_on_judge_error: bool = True,
    include_dos_tests: bool = False,
    concurrency: int | None = None,
    retries: int | None = None,
    canary: str | None = None,
    system_prompt: str | None = None,
    suppressions_file: str | Path | None = None,
    payloads_dir: str | Path | None = None,
    log_level: str | None = None,
    authorized: bool = False,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    max_findings: int | None = None,
    env: dict[str, str] | None = None,
) -> ResultEnvelope:
    """Run the real scanner and return a structured envelope.

    The authorization gate runs first and can refuse before any payload is sent;
    see :mod:`llm_scanner_skill.authz`. ``fail_on_judge_error`` defaults to True
    here (the CLI defaults it off) because an agent that reports "no issues" from
    a scan whose judge was unavailable would be stating something false.
    """
    out_dir = Path(output_dir)

    decision = authorize(
        target,
        target_type,
        authorized=authorized,
        include_dos_tests=include_dos_tests,
    )
    if not decision.allowed:
        env_out = error_envelope(
            EnvelopeStatus.BLOCKED,
            decision.reason,
            target=target,
            target_type=target_type,
        )
        env_out.warnings.extend(decision.warnings)
        return env_out

    try:
        scanner = find_scanner()
    except ScannerNotFoundError as exc:
        return error_envelope(
            EnvelopeStatus.SCANNER_NOT_FOUND,
            str(exc),
            target=target,
            target_type=target_type,
        )

    fmts = [f.lower() for f in (formats or ["json", "html", "sarif"])]
    if "json" not in fmts:
        # report.json is this adapter's input. Without it there is nothing to parse.
        fmts.insert(0, "json")

    argv = _build_argv(
        scanner,
        target=target,
        target_type=target_type,
        judge_model=judge_model,
        output_dir=out_dir,
        categories=categories,
        severity=severity,
        formats=fmts,
        api_key=api_key,
        config_file=config_file,
        fail_on_score=fail_on_score,
        fail_on_judge_error=fail_on_judge_error,
        include_dos_tests=include_dos_tests,
        concurrency=concurrency,
        retries=retries,
        canary=canary,
        system_prompt=system_prompt,
        suppressions_file=suppressions_file,
        payloads_dir=payloads_dir,
        log_level=log_level,
    )

    run_env = {**os.environ, **(env or {})}
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            env=run_env,
        )
    except subprocess.TimeoutExpired:
        return error_envelope(
            EnvelopeStatus.FAILED,
            f"Scan exceeded the {timeout_s}s timeout and was terminated. "
            "Reduce --categories, raise --concurrency, or use a smaller judge model.",
            target=target,
            target_type=target_type,
        )
    except OSError as exc:
        return error_envelope(
            EnvelopeStatus.FAILED,
            f"Could not execute the scanner: {exc}",
            target=target,
            target_type=target_type,
        )

    scan_dir = _newest_report_dir(out_dir)
    if scan_dir is None:
        # No report means the run aborted before the scan loop -- almost always
        # preflight (Ollama down, model not pulled, target unreachable). The
        # scanner's own stderr is the most useful thing we can hand back, and it
        # is operator-authored text, not target-controlled.
        detail = (proc.stderr or proc.stdout or "").strip()
        return error_envelope(
            EnvelopeStatus.FAILED,
            "The scanner produced no report. Most likely a preflight failure "
            "(Ollama not running, judge model not pulled, or target unreachable).\n"
            f"Scanner output:\n{detail[-2000:]}",
            target=target,
            target_type=target_type,
            exit_code=proc.returncode,
        )

    envelope = summarize_report_file(
        scan_dir / "report.json",
        max_findings=max_findings,
    )
    envelope.target_type = target_type
    envelope.judge_model = judge_model
    envelope.categories_requested = list(categories or [])
    envelope.scanner_version = scanner_version()
    envelope.exit_code = proc.returncode
    envelope.warnings.extend(decision.warnings)

    for fmt in fmts:
        name = "report.md" if fmt == "md" else f"report.{fmt}"
        candidate = scan_dir / name
        if candidate.is_file():
            envelope.reports[fmt] = str(candidate)
    metrics = scan_dir / "metrics.json"
    if metrics.is_file():
        envelope.reports["metrics"] = str(metrics)

    # Status reflects trustworthiness, not just the exit code.
    if envelope.summary.inconclusive:
        envelope.status = EnvelopeStatus.COMPLETED_UNTRUSTWORTHY
        envelope.warnings.append(
            f"{envelope.summary.inconclusive} attack(s) were not evaluated by the judge. "
            "Their result is UNKNOWN, not safe, and the risk score is a lower bound."
        )
    elif proc.returncode == _EXIT_JUDGE_ERROR:
        envelope.status = EnvelopeStatus.COMPLETED_UNTRUSTWORTHY
    elif proc.returncode == _EXIT_FAIL:
        envelope.status = EnvelopeStatus.COMPLETED_WITH_THRESHOLD_BREACH
    elif proc.returncode == _EXIT_OK:
        envelope.status = EnvelopeStatus.COMPLETED
    else:
        envelope.status = EnvelopeStatus.FAILED
        envelope.errors.append(f"Scanner exited with unexpected code {proc.returncode}.")

    return envelope


def run_scan_json(**kwargs: Any) -> str:
    """Convenience wrapper returning the envelope as a JSON string."""
    return run_scan(**kwargs).to_json()


def load_report(path: str | Path) -> dict[str, Any]:
    """Load a scanner ``report.json`` as a plain dict.

    Raises:
        FileNotFoundError: if *path* does not exist.
        ValueError: if the file is not valid JSON or not a JSON object.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{p} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{p} should contain a JSON object, got {type(data).__name__}.")
    return data
