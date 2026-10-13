"""``llm-scanner-skill`` -- the command surface the skill's scripts and agents call.

Every subcommand prints JSON to stdout and nothing else, so an AI agent can parse
the result without scraping prose. Human-readable text goes to stderr.

This CLI never reimplements scanning. ``scan`` shells out to the real
``llm-scanner``; everything else reads its artifacts or inspects local source.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from llm_scanner_skill import __version__
from llm_scanner_skill.adapter import ScannerNotFoundError, find_scanner, run_scan, scanner_version
from llm_scanner_skill.authz import authorize
from llm_scanner_skill.compare import compare_report_files
from llm_scanner_skill.config import (
    ALL_CATEGORIES,
    SAFE_CATEGORIES,
    build_config,
    dump_config,
    validate_config_file,
)
from llm_scanner_skill.envelope import ENVELOPE_SCHEMA_VERSION
from llm_scanner_skill.inspect import inspect_project
from llm_scanner_skill.install import PLATFORM_PATHS, install, skill_source_dir, uninstall
from llm_scanner_skill.remediation import CATEGORY_TITLES, guidance_for_category
from llm_scanner_skill.summarize import summarize_report_file

__all__ = ["build_parser", "main"]

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_BLOCKED = 3


def _emit(payload: Any) -> None:
    """Write a JSON payload to stdout."""
    if hasattr(payload, "to_json"):
        sys.stdout.write(payload.to_json() + "\n")
    else:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")


def _note(message: str) -> None:
    """Write a human note to stderr, keeping stdout pure JSON."""
    print(message, file=sys.stderr)


def _csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-scanner-skill",
        description=(
            "Agent-facing adapter around the llm-security-scanner CLI. "
            "Every subcommand emits JSON on stdout."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # --- inspect -------------------------------------------------------------
    p_inspect = sub.add_parser(
        "inspect", help="Statically map a project's LLM attack surface (read-only)."
    )
    p_inspect.add_argument("path", nargs="?", default=".", help="Project root (default: .)")

    # --- authorize -----------------------------------------------------------
    p_auth = sub.add_parser(
        "authorize", help="Classify a target and report whether a scan may proceed."
    )
    p_auth.add_argument("--target", required=True)
    p_auth.add_argument("--target-type", required=True, choices=["url", "ollama"])
    p_auth.add_argument(
        "--authorized",
        action="store_true",
        help="The user has confirmed they own or may test this target.",
    )
    p_auth.add_argument("--include-dos-tests", action="store_true")

    # --- categories ----------------------------------------------------------
    sub.add_parser(
        "categories", help="List the OWASP LLM categories and the bundled payload counts."
    )

    # --- init-config ---------------------------------------------------------
    p_init = sub.add_parser("init-config", help="Emit a valid llm-scan.yml for a target.")
    p_init.add_argument("--target", required=True)
    p_init.add_argument("--target-type", required=True, choices=["url", "ollama"])
    p_init.add_argument("--judge-model", default="llama3.2:3b")
    p_init.add_argument("--categories", default=None, help="Comma-separated, e.g. LLM01,LLM07")
    p_init.add_argument("--severity", default=None)
    p_init.add_argument("--formats", default="json,html,sarif")
    p_init.add_argument("--output-dir", default="./reports")
    p_init.add_argument("--fail-on-score", type=float, default=None)
    p_init.add_argument("--include-dos-tests", action="store_true")
    p_init.add_argument(
        "--api-key-env",
        default=None,
        help="Name of an env var holding the bearer token; written as ${VAR}, never inlined.",
    )
    p_init.add_argument("-o", "--out", type=Path, default=None, help="Write YAML here.")

    # --- validate-config -----------------------------------------------------
    p_val = sub.add_parser("validate-config", help="Validate an llm-scan.yml file.")
    p_val.add_argument("path", help="Path to the YAML config.")

    # --- scan ----------------------------------------------------------------
    p_scan = sub.add_parser("scan", help="Run the real scanner and emit a structured envelope.")
    p_scan.add_argument("--target", default="")
    p_scan.add_argument("--target-type", default="", choices=["url", "ollama", ""])
    p_scan.add_argument("--judge-model", default="llama3.2:3b")
    p_scan.add_argument("--config", dest="config_file", default=None)
    p_scan.add_argument("--categories", default=None)
    p_scan.add_argument("--severity", default=None)
    p_scan.add_argument("--formats", default="json,html,sarif")
    p_scan.add_argument("--output-dir", default="./reports")
    p_scan.add_argument("--api-key", default=None)
    p_scan.add_argument("--fail-on-score", type=float, default=None)
    p_scan.add_argument("--include-dos-tests", action="store_true")
    p_scan.add_argument("--concurrency", type=int, default=None)
    p_scan.add_argument("--retries", type=int, default=None)
    p_scan.add_argument("--canary", default=None)
    p_scan.add_argument("--system-prompt", default=None, help="Literal text or @path.")
    p_scan.add_argument("--suppressions", dest="suppressions_file", default=None)
    p_scan.add_argument("--payloads-dir", dest="payloads_dir", default=None)
    p_scan.add_argument("--timeout", type=int, default=None, help="Seconds (default 2700).")
    p_scan.add_argument("--max-findings", type=int, default=None)
    p_scan.add_argument(
        "--authorized",
        action="store_true",
        help="Required for any non-loopback target, and for --include-dos-tests.",
    )
    p_scan.add_argument(
        "--no-fail-on-judge-error",
        action="store_true",
        help="Allow a scan whose judge failed to still report status=completed. Not advised.",
    )

    # --- summarize -----------------------------------------------------------
    p_sum = sub.add_parser("summarize", help="Turn a scanner report.json into an envelope.")
    p_sum.add_argument("report", help="Path to report.json.")
    p_sum.add_argument("--max-findings", type=int, default=None)
    p_sum.add_argument(
        "--include-safe", action="store_true", help="Also list findings that were SAFE."
    )

    # --- compare -------------------------------------------------------------
    p_cmp = sub.add_parser("compare", help="Diff two report.json files (before vs after a fix).")
    p_cmp.add_argument("before")
    p_cmp.add_argument("after")

    # --- remediate -----------------------------------------------------------
    p_rem = sub.add_parser("remediate", help="Remediation guidance for a category or attack ID.")
    p_rem.add_argument("category", help="e.g. LLM01, or an attack ID such as LLM01-003.")

    # --- doctor --------------------------------------------------------------
    p_doc = sub.add_parser("doctor", help="Check that the scanner and its prerequisites work.")
    p_doc.add_argument(
        "--ollama-host", default=None, help="Default: $OLLAMA_HOST or http://localhost:11434"
    )

    # --- install / uninstall -------------------------------------------------
    p_ins = sub.add_parser("install", help="Install the skill into a platform's skill path.")
    p_ins.add_argument(
        "--platform",
        default="agents",
        choices=[*sorted(PLATFORM_PATHS), "all"],
        help="'agents' is the shared interop path read by Claude Code, Gemini CLI and Codex.",
    )
    p_ins.add_argument("--scope", default="user", choices=["user", "project"])
    p_ins.add_argument("--project-root", default=".")
    p_ins.add_argument("--mode", default="symlink", choices=["symlink", "copy"])
    p_ins.add_argument("--force", action="store_true")

    p_uni = sub.add_parser("uninstall", help="Remove an installed skill.")
    p_uni.add_argument("--platform", default="agents", choices=[*sorted(PLATFORM_PATHS), "all"])
    p_uni.add_argument("--scope", default="user", choices=["user", "project"])
    p_uni.add_argument("--project-root", default=".")

    # --- mcp -----------------------------------------------------------------
    sub.add_parser("mcp", help="Run the MCP server on stdio.")

    return parser


def _cmd_categories() -> int:
    """List categories with the bundled payload counts, read from the scanner."""
    counts: dict[str, int] = {}
    note = ""
    try:
        from llm_scanner.cli import _PAYLOAD_DIR  # type: ignore[import-not-found]
        from llm_scanner.payloads.loader import YamlPayloadLoader  # type: ignore[import-not-found]

        payloads = YamlPayloadLoader(_PAYLOAD_DIR).load()
        for p in payloads:
            counts[p.category] = counts.get(p.category, 0) + 1
    except Exception as exc:
        note = (
            f"Payload counts unavailable ({type(exc).__name__}: {exc}). "
            "Install llm-security-scanner to see them."
        )

    _emit(
        {
            "schema_version": "1.0",
            "categories": [
                {
                    "id": cat,
                    "title": CATEGORY_TITLES.get(cat, ""),
                    "payloads": counts.get(cat, 0),
                    "default_enabled": cat in SAFE_CATEGORIES,
                    "requires_opt_in": cat == "LLM10",
                }
                for cat in ALL_CATEGORIES
            ],
            "total_payloads": sum(counts.values()),
            "note": note,
        }
    )
    return _EXIT_OK


def _cmd_doctor(ollama_host: str | None) -> int:
    """Report on each prerequisite without ever failing hard."""
    import os

    host = ollama_host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    checks: list[dict[str, Any]] = []
    ok = True

    try:
        argv = find_scanner()
        checks.append(
            {
                "check": "scanner_cli",
                "ok": True,
                "detail": " ".join(argv),
                "version": scanner_version(),
            }
        )
    except ScannerNotFoundError as exc:
        ok = False
        checks.append({"check": "scanner_cli", "ok": False, "detail": str(exc)})

    try:
        import httpx

        resp = httpx.get(f"{host}/api/version", timeout=3.0)
        resp.raise_for_status()
        checks.append(
            {"check": "ollama", "ok": True, "detail": f"{host} -> {resp.text.strip()[:120]}"}
        )
    except Exception as exc:
        ok = False
        checks.append(
            {
                "check": "ollama",
                "ok": False,
                "detail": f"Cannot reach Ollama at {host} ({type(exc).__name__}). Run: ollama serve",
            }
        )

    try:
        source = skill_source_dir()
        checks.append({"check": "skill_bundle", "ok": True, "detail": str(source)})
    except FileNotFoundError as exc:
        ok = False
        checks.append({"check": "skill_bundle", "ok": False, "detail": str(exc)})

    _emit(
        {
            "schema_version": "1.0",
            "ok": ok,
            "envelope_schema_version": ENVELOPE_SCHEMA_VERSION,
            "skill_version": __version__,
            "checks": checks,
        }
    )
    return _EXIT_OK if ok else _EXIT_ERROR


def _cmd_install(args: argparse.Namespace) -> int:
    platforms = sorted(PLATFORM_PATHS) if args.platform == "all" else [args.platform]
    results: list[dict[str, Any]] = []
    exit_code = _EXIT_OK
    seen: set[Path] = set()
    for platform in platforms:
        try:
            dest, action = install(
                platform,
                scope=args.scope,
                project_root=args.project_root,
                mode=args.mode,
                force=args.force,
            )
        except FileExistsError as exc:
            # 'claude' and 'codex' can resolve to the same .agents path; a second
            # install there is a no-op, not a failure.
            results.append({"platform": platform, "ok": False, "detail": str(exc)})
            exit_code = _EXIT_ERROR
        except (ValueError, FileNotFoundError, OSError) as exc:
            results.append({"platform": platform, "ok": False, "detail": str(exc)})
            exit_code = _EXIT_ERROR
        else:
            if dest in seen:
                results.append(
                    {
                        "platform": platform,
                        "ok": True,
                        "path": str(dest),
                        "action": "already installed at this shared path",
                    }
                )
            else:
                seen.add(dest)
                results.append(
                    {"platform": platform, "ok": True, "path": str(dest), "action": action}
                )
    _emit({"schema_version": "1.0", "scope": args.scope, "results": results})
    return exit_code


def _cmd_uninstall(args: argparse.Namespace) -> int:
    platforms = sorted(PLATFORM_PATHS) if args.platform == "all" else [args.platform]
    results: list[dict[str, Any]] = []
    for platform in platforms:
        try:
            path, removed = uninstall(platform, scope=args.scope, project_root=args.project_root)
        except (ValueError, OSError) as exc:
            results.append({"platform": platform, "ok": False, "detail": str(exc)})
        else:
            results.append(
                {"platform": platform, "ok": True, "path": str(path), "removed": removed}
            )
    _emit({"schema_version": "1.0", "scope": args.scope, "results": results})
    return _EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "inspect":
        _emit(inspect_project(args.path))
        return _EXIT_OK

    if args.command == "authorize":
        decision = authorize(
            args.target,
            args.target_type,
            authorized=args.authorized,
            include_dos_tests=args.include_dos_tests,
        )
        _emit({"schema_version": "1.0", **decision.to_dict()})
        return _EXIT_OK if decision.allowed else _EXIT_BLOCKED

    if args.command == "categories":
        return _cmd_categories()

    if args.command == "init-config":
        config = build_config(
            target=args.target,
            target_type=args.target_type,
            judge_model=args.judge_model,
            categories=_csv(args.categories),
            severity=args.severity,
            formats=_csv(args.formats),
            output_dir=args.output_dir,
            fail_on_score=args.fail_on_score,
            include_dos_tests=args.include_dos_tests,
            api_key_env=args.api_key_env,
        )
        yaml_text = dump_config(config)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(yaml_text, encoding="utf-8")
            _note(f"Wrote {args.out}")
        _emit(
            {
                "schema_version": "1.0",
                "config": config,
                "yaml": yaml_text,
                "path": str(args.out) if args.out else "",
            }
        )
        return _EXIT_OK

    if args.command == "validate-config":
        ok, errors, warnings = validate_config_file(args.path)
        _emit(
            {
                "schema_version": "1.0",
                "path": args.path,
                "valid": ok,
                "errors": errors,
                "warnings": warnings,
            }
        )
        return _EXIT_OK if ok else _EXIT_ERROR

    if args.command == "scan":
        envelope = run_scan(
            target=args.target,
            target_type=args.target_type,
            judge_model=args.judge_model,
            output_dir=args.output_dir,
            categories=_csv(args.categories),
            severity=args.severity,
            formats=_csv(args.formats),
            api_key=args.api_key,
            config_file=args.config_file,
            fail_on_score=args.fail_on_score,
            fail_on_judge_error=not args.no_fail_on_judge_error,
            include_dos_tests=args.include_dos_tests,
            concurrency=args.concurrency,
            retries=args.retries,
            canary=args.canary,
            system_prompt=args.system_prompt,
            suppressions_file=args.suppressions_file,
            payloads_dir=args.payloads_dir,
            max_findings=args.max_findings,
            authorized=args.authorized,
            **({"timeout_s": args.timeout} if args.timeout else {}),
        )
        _emit(envelope)
        if envelope.status == "blocked":
            return _EXIT_BLOCKED
        if envelope.status in {"failed", "scanner_not_found"}:
            return _EXIT_ERROR
        return _EXIT_OK

    if args.command == "summarize":
        envelope = summarize_report_file(
            args.report, max_findings=args.max_findings, include_safe=args.include_safe
        )
        _emit(envelope)
        return _EXIT_ERROR if envelope.errors else _EXIT_OK

    if args.command == "compare":
        _emit(compare_report_files(args.before, args.after))
        return _EXIT_OK

    if args.command == "remediate":
        _emit(guidance_for_category(args.category.split("-", 1)[0]))
        return _EXIT_OK

    if args.command == "doctor":
        return _cmd_doctor(args.ollama_host)

    if args.command == "install":
        return _cmd_install(args)

    if args.command == "uninstall":
        return _cmd_uninstall(args)

    if args.command == "mcp":
        from llm_scanner_skill.mcp_server import run_stdio

        run_stdio()
        return _EXIT_OK

    parser.error(f"Unhandled command: {args.command}")
    return _EXIT_ERROR  # pragma: no cover - parser.error exits


def entrypoint() -> None:
    """Console-script entry point declared in pyproject.toml."""
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _note("Interrupted.")
        sys.exit(130)
