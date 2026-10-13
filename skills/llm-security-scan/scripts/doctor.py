#!/usr/bin/env python3
"""Check that the scanner, Ollama and the skill bundle are all usable.

Thin wrapper: forwards every argument to `llm-scanner-skill doctor`.
Prints JSON on stdout. Run with --help for the full flag list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _common import delegate

if __name__ == "__main__":
    sys.exit(delegate("doctor", sys.argv[1:]))
