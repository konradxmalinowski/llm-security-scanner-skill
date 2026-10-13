#!/usr/bin/env python3
"""Generate a valid llm-scan.yml for a target. API keys are written as ${ENV_VAR}, never inlined.

Thin wrapper: forwards every argument to `llm-scanner-skill init-config`.
Prints JSON on stdout. Run with --help for the full flag list.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _common import delegate

if __name__ == "__main__":
    sys.exit(delegate("init-config", sys.argv[1:]))
