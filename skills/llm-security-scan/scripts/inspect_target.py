#!/usr/bin/env python3
"""Statically map a project's LLM attack surface. Read-only: never imports or runs project code.

Thin wrapper: forwards every argument to `llm-scanner-skill inspect`.
Prints JSON on stdout. Run with --help for the full flag list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _common import delegate

if __name__ == "__main__":
    sys.exit(delegate("inspect", sys.argv[1:]))
