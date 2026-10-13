#!/usr/bin/env python3
"""Validate an llm-scan.yml against the scanner's real schema before a scan runs.

Thin wrapper: forwards every argument to `llm-scanner-skill validate-config`.
Prints JSON on stdout. Run with --help for the full flag list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _common import delegate

if __name__ == "__main__":
    sys.exit(delegate("validate-config", sys.argv[1:]))
