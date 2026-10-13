#!/usr/bin/env python3
"""Classify a target and report whether scanning it is permitted. Call before scanning.

Thin wrapper: forwards every argument to `llm-scanner-skill authorize`.
Prints JSON on stdout. Run with --help for the full flag list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _common import delegate

if __name__ == "__main__":
    sys.exit(delegate("authorize", sys.argv[1:]))
