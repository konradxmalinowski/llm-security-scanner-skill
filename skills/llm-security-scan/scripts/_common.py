"""Shared bootstrap for the skill's scripts.

Every script in this directory is a thin front end for one `llm-scanner-skill`
subcommand, which is itself a thin front end for the real `llm-scanner`. Nothing
here implements scanning logic.

The indirection exists for one practical reason: an agent runs these scripts with
whatever `python3` is on PATH, which is frequently not the interpreter that has
`llm_scanner_skill` installed. So resolution is tried in order:

1. import it in-process (fast path, when the interpreter already has it);
2. the `llm-scanner-skill` console script on PATH;
3. `$LLM_SCANNER_SKILL_PYTHON -m llm_scanner_skill.cli`, an explicit escape hatch.

If all three fail, the message says exactly what to install rather than raising a
traceback an agent then has to interpret.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

__all__ = ["delegate"]

_INSTALL_HINT = (
    "llm-scanner-skill is not available. Install it with:\n"
    "  uv pip install llm-security-scanner-skill\n"
    "or set $LLM_SCANNER_SKILL_PYTHON to a Python that has it."
)


def _fail(message: str) -> int:
    """Emit a machine-readable failure on stdout so a caller can always parse it."""
    json.dump(
        {"schema_version": "1.0", "status": "failed", "errors": [message]},
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    print(message, file=sys.stderr)
    return 1


def delegate(subcommand: str, argv: list[str]) -> int:
    """Run `llm-scanner-skill <subcommand> <argv...>` and return its exit code."""
    args = [subcommand, *argv]

    try:
        from llm_scanner_skill.cli import main as _main
    except ImportError:
        pass
    else:
        return _main(args)

    exe = shutil.which("llm-scanner-skill")
    if exe:
        return subprocess.run([exe, *args], check=False).returncode  # noqa: S603

    python = os.environ.get("LLM_SCANNER_SKILL_PYTHON", "").strip()
    if python:
        return subprocess.run(  # noqa: S603
            [python, "-m", "llm_scanner_skill.cli", *args], check=False
        ).returncode

    return _fail(_INSTALL_HINT)
