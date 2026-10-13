"""The adapter: scanner discovery, argv construction, and every failure path.

The real scanner is never invoked here. A fake `llm-scanner` script stands in, which
lets the tests assert on the exact argv and simulate conditions (no Ollama, an
unreachable target, a hung scan) that would otherwise need real infrastructure.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from llm_scanner_skill import adapter
from llm_scanner_skill.adapter import (
    DEFAULT_TIMEOUT_S,
    ScannerNotFoundError,
    find_scanner,
    run_scan,
)
from llm_scanner_skill.envelope import EnvelopeStatus


@pytest.fixture
def fake_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Install a fake `llm-scanner` and return a factory to configure its behaviour."""

    def _make(
        *,
        exit_code: int = 0,
        report: dict | None = None,
        stderr: str = "",
        sleep: float = 0.0,
    ) -> Path:
        argv_log = tmp_path / "argv.json"
        script = tmp_path / "llm-scanner"
        report_json = json.dumps(report) if report is not None else ""
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys, os, time, pathlib\n"
            f"pathlib.Path({str(argv_log)!r}).write_text(json.dumps(sys.argv[1:]))\n"
            f"time.sleep({sleep})\n"
            f"sys.stderr.write({stderr!r})\n"
            f"report = {report_json!r}\n"
            "if report:\n"
            "    args = sys.argv[1:]\n"
            "    out = pathlib.Path(args[args.index('--output-dir') + 1])\n"
            "    d = out / '20260101T000000_fake'\n"
            "    d.mkdir(parents=True, exist_ok=True)\n"
            "    (d / 'report.json').write_text(report)\n"
            "    (d / 'report.html').write_text('<html></html>')\n"
            "    (d / 'report.sarif').write_text('{}')\n"
            "    (d / 'metrics.json').write_text('{}')\n"
            f"sys.exit({exit_code})\n",
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        monkeypatch.setenv("LLM_SCANNER_BIN", str(script))
        return argv_log

    return _make


class TestDiscovery:
    def test_env_override_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        exe = tmp_path / "my-scanner"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        monkeypatch.setenv("LLM_SCANNER_BIN", str(exe))
        assert find_scanner() == [str(exe)]

    def test_multiword_shim_passes_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 'docker run ...' shim must not be validated as a single executable."""
        monkeypatch.setenv("LLM_SCANNER_BIN", "docker run --rm img llm-scanner")
        assert find_scanner() == ["docker", "run", "--rm", "img", "llm-scanner"]

    def test_bad_override_raises_with_a_usable_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LLM_SCANNER_BIN", "/definitely/not/here")
        with pytest.raises(ScannerNotFoundError, match="not executable"):
            find_scanner()

    def test_falls_back_to_interpreter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A venv whose bin/ is off PATH must still work."""
        monkeypatch.delenv("LLM_SCANNER_BIN", raising=False)
        monkeypatch.setattr(adapter.shutil, "which", lambda _: None)
        argv = find_scanner()
        assert argv[0] == adapter.sys.executable
        assert "llm_scanner.cli" in argv[-1]

    def test_missing_scanner_reports_how_to_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("LLM_SCANNER_BIN", raising=False)
        monkeypatch.setattr(adapter.shutil, "which", lambda _: None)
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

        def _blocked(name, *a, **k):
            if name == "llm_scanner":
                raise ImportError("blocked")
            return real_import(name, *a, **k)

        monkeypatch.setattr("builtins.__import__", _blocked)
        with pytest.raises(ScannerNotFoundError, match="uv pip install"):
            find_scanner()


class TestAuthorizationIsEnforcedBeforeExecution:
    def test_external_target_is_blocked_and_scanner_never_runs(
        self, fake_scanner, tmp_path: Path
    ) -> None:
        argv_log = fake_scanner(
            report={"target": "x", "timestamp": "", "risk_score": 0.0, "findings": []}
        )
        env = run_scan(
            target="http://93.184.216.34/chat",
            target_type="url",
            output_dir=tmp_path / "reports",
        )
        assert env.status is EnvelopeStatus.BLOCKED
        assert env.blocked_reason
        assert not argv_log.exists(), "the scanner must not be invoked on a blocked target"

    def test_provider_target_blocked_even_when_authorized(
        self, fake_scanner, tmp_path: Path
    ) -> None:
        argv_log = fake_scanner(
            report={"target": "x", "timestamp": "", "risk_score": 0.0, "findings": []}
        )
        env = run_scan(
            target="https://api.openai.com/v1/chat/completions",
            target_type="url",
            authorized=True,
            output_dir=tmp_path / "reports",
        )
        assert env.status is EnvelopeStatus.BLOCKED
        assert not argv_log.exists()

    def test_dos_blocked_without_authorization(self, fake_scanner, tmp_path: Path) -> None:
        argv_log = fake_scanner(
            report={"target": "x", "timestamp": "", "risk_score": 0.0, "findings": []}
        )
        env = run_scan(
            target="http://localhost:8000/chat",
            target_type="url",
            include_dos_tests=True,
            output_dir=tmp_path / "reports",
        )
        assert env.status is EnvelopeStatus.BLOCKED
        assert not argv_log.exists()


class TestArgv:
    def _run(self, fake_scanner, tmp_path, **kwargs):
        argv_log = fake_scanner(
            report={
                "target": "http://localhost:8000/chat",
                "timestamp": "",
                "risk_score": 0.0,
                "findings": [],
            }
        )
        run_scan(
            target="http://localhost:8000/chat",
            target_type="url",
            output_dir=tmp_path / "reports",
            **kwargs,
        )
        return json.loads(argv_log.read_text())

    def test_core_flags(self, fake_scanner, tmp_path: Path) -> None:
        argv = self._run(fake_scanner, tmp_path, judge_model="llama3.2:3b")
        assert "--target" in argv and "http://localhost:8000/chat" in argv
        assert "--target-type" in argv and "url" in argv
        assert "--judge-model" in argv and "llama3.2:3b" in argv

    def test_json_is_forced_into_formats(self, fake_scanner, tmp_path: Path) -> None:
        """report.json is the adapter's input; without it there is nothing to parse."""
        argv = self._run(fake_scanner, tmp_path, formats=["html"])
        fmts = argv[argv.index("--format") + 1]
        assert "json" in fmts

    def test_raw_artifacts_is_never_passed(self, fake_scanner, tmp_path: Path) -> None:
        """Secrets must stay redacted on the way to an agent's context."""
        argv = self._run(fake_scanner, tmp_path, categories=["LLM02"])
        assert "--include-raw-artifacts" not in argv

    def test_fail_on_judge_error_defaults_on(self, fake_scanner, tmp_path: Path) -> None:
        argv = self._run(fake_scanner, tmp_path)
        assert "--fail-on-judge-error" in argv

    def test_fail_on_judge_error_can_be_disabled(self, fake_scanner, tmp_path: Path) -> None:
        argv = self._run(fake_scanner, tmp_path, fail_on_judge_error=False)
        assert "--fail-on-judge-error" not in argv

    def test_optional_flags_only_when_given(self, fake_scanner, tmp_path: Path) -> None:
        argv = self._run(fake_scanner, tmp_path)
        for flag in (
            "--canary",
            "--system-prompt",
            "--api-key",
            "--severity",
            "--suppressions",
            "--payloads-dir",
            "--fail-on-score",
        ):
            assert flag not in argv

    def test_detector_inputs_forwarded(self, fake_scanner, tmp_path: Path) -> None:
        argv = self._run(
            fake_scanner,
            tmp_path,
            canary="LLMSCAN-CANARY-abc",
            system_prompt="@prompts/system.txt",
        )
        assert argv[argv.index("--canary") + 1] == "LLMSCAN-CANARY-abc"
        assert argv[argv.index("--system-prompt") + 1] == "@prompts/system.txt"

    def test_dos_flag_forwarded_when_authorized(self, fake_scanner, tmp_path: Path) -> None:
        argv = self._run(fake_scanner, tmp_path, include_dos_tests=True, authorized=True)
        assert "--include-dos-tests" in argv


class TestStatusMapping:
    def _scan(self, fake_scanner, tmp_path, *, exit_code, findings):
        fake_scanner(
            exit_code=exit_code,
            report={
                "target": "http://localhost:8000/chat",
                "timestamp": "",
                "risk_score": 5.0,
                "findings": findings,
            },
        )
        return run_scan(
            target="http://localhost:8000/chat",
            target_type="url",
            output_dir=tmp_path / "reports",
        )

    def test_clean_run(self, fake_scanner, tmp_path: Path) -> None:
        env = self._scan(fake_scanner, tmp_path, exit_code=0, findings=[])
        assert env.status is EnvelopeStatus.COMPLETED
        assert env.exit_code == 0

    def test_threshold_breach(self, fake_scanner, tmp_path: Path, make_finding) -> None:
        env = self._scan(
            fake_scanner, tmp_path, exit_code=1, findings=[make_finding("LLM01-001", "LLM01")]
        )
        assert env.status is EnvelopeStatus.COMPLETED_WITH_THRESHOLD_BREACH

    def test_judge_error_exit_code(self, fake_scanner, tmp_path: Path, make_finding) -> None:
        env = self._scan(
            fake_scanner, tmp_path, exit_code=2, findings=[make_finding("LLM01-001", "LLM01")]
        )
        assert env.status is EnvelopeStatus.COMPLETED_UNTRUSTWORTHY

    def test_inconclusive_finding_overrides_a_zero_exit(
        self, fake_scanner, tmp_path: Path, make_finding
    ) -> None:
        """Exit 0 plus an unevaluated attack is still not a clean result."""
        env = self._scan(
            fake_scanner,
            tmp_path,
            exit_code=0,
            findings=[
                make_finding(
                    "LLM01-001",
                    "LLM01",
                    outcome="error",
                    verdict_source="judge_error",
                    judge_error="judge_timeout",
                )
            ],
        )
        assert env.status is EnvelopeStatus.COMPLETED_UNTRUSTWORTHY
        assert any("UNKNOWN, not safe" in w for w in env.warnings)

    def test_report_paths_collected(self, fake_scanner, tmp_path: Path) -> None:
        env = self._scan(fake_scanner, tmp_path, exit_code=0, findings=[])
        assert set(env.reports) >= {"json", "html", "sarif", "metrics"}
        assert Path(env.reports["json"]).is_file()

    def test_metadata_populated(self, fake_scanner, tmp_path: Path) -> None:
        fake_scanner(report={"target": "t", "timestamp": "", "risk_score": 0.0, "findings": []})
        env = run_scan(
            target="http://localhost:8000/chat",
            target_type="url",
            judge_model="llama3.2:3b",
            categories=["LLM01"],
            output_dir=tmp_path / "reports",
        )
        assert env.target_type == "url"
        assert env.judge_model == "llama3.2:3b"
        assert env.categories_requested == ["LLM01"]
        assert env.scanner_version


class TestFailurePaths:
    def test_no_report_means_preflight_failed(self, fake_scanner, tmp_path: Path) -> None:
        """Ollama down / model missing / target unreachable all land here."""
        fake_scanner(
            exit_code=1,
            report=None,
            stderr="[ERROR] Ollama is not running at http://localhost:11434.",
        )
        env = run_scan(
            target="http://localhost:8000/chat", target_type="url", output_dir=tmp_path / "reports"
        )
        assert env.status is EnvelopeStatus.FAILED
        assert "preflight" in env.errors[0]
        assert "Ollama is not running" in env.errors[0]

    def test_unreachable_target_surfaces_scanner_stderr(self, fake_scanner, tmp_path: Path) -> None:
        fake_scanner(
            exit_code=1,
            report=None,
            stderr="[ERROR] HTTP target at http://localhost:8000/chat is not reachable",
        )
        env = run_scan(
            target="http://localhost:8000/chat", target_type="url", output_dir=tmp_path / "reports"
        )
        assert env.status is EnvelopeStatus.FAILED
        assert "not reachable" in env.errors[0]

    def test_timeout_is_reported_with_advice(self, fake_scanner, tmp_path: Path) -> None:
        fake_scanner(
            report={"target": "t", "timestamp": "", "risk_score": 0.0, "findings": []}, sleep=2.0
        )
        env = run_scan(
            target="http://localhost:8000/chat",
            target_type="url",
            output_dir=tmp_path / "reports",
            timeout_s=1,
        )
        assert env.status is EnvelopeStatus.FAILED
        assert "timeout" in env.errors[0]

    def test_scanner_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LLM_SCANNER_BIN", "/nonexistent/llm-scanner")
        env = run_scan(
            target="http://localhost:8000/chat", target_type="url", output_dir=tmp_path / "reports"
        )
        assert env.status is EnvelopeStatus.SCANNER_NOT_FOUND

    def test_unexpected_exit_code(self, fake_scanner, tmp_path: Path) -> None:
        fake_scanner(
            exit_code=42, report={"target": "t", "timestamp": "", "risk_score": 0.0, "findings": []}
        )
        env = run_scan(
            target="http://localhost:8000/chat", target_type="url", output_dir=tmp_path / "reports"
        )
        assert env.status is EnvelopeStatus.FAILED
        assert "42" in env.errors[0]

    def test_baselines_dir_is_not_mistaken_for_a_scan(self, fake_scanner, tmp_path: Path) -> None:
        reports = tmp_path / "reports"
        (reports / "baselines").mkdir(parents=True)
        (reports / "baselines" / "report.json").write_text(
            '{"target":"old","timestamp":"","risk_score":9.9,"findings":[]}', encoding="utf-8"
        )
        fake_scanner(report={"target": "new", "timestamp": "", "risk_score": 0.0, "findings": []})
        env = run_scan(target="http://localhost:8000/chat", target_type="url", output_dir=reports)
        assert env.target == "new"


def test_default_timeout_is_generous_enough_for_a_real_scan() -> None:
    """51 payloads x 2 model round-trips on a slow local model is genuinely slow."""
    assert DEFAULT_TIMEOUT_S >= 1800
