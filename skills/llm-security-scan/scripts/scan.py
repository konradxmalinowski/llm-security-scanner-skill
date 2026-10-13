#!/usr/bin/env python3
"""Run the real llm-security-scanner and return a structured result envelope.

Thin wrapper: forwards every argument to `llm-scanner-skill scan`.
Prints JSON on stdout. Run with --help for the full flag list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _common import delegate

if __name__ == "__main__":
    sys.exit(delegate("scan", sys.argv[1:]))
