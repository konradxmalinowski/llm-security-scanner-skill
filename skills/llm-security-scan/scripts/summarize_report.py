#!/usr/bin/env python3
"""Turn a scanner report.json into a sanitized, structured envelope.

Thin wrapper: forwards every argument to `llm-scanner-skill summarize`.
Prints JSON on stdout. Run with --help for the full flag list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _common import delegate

if __name__ == "__main__":
    sys.exit(delegate("summarize", sys.argv[1:]))
