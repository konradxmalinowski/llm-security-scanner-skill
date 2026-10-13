"""Cross-platform AI-agent skill layer for llm-security-scanner.

This package is a *thin* adapter. It contains no attack payloads, no judge, no
detectors and no scan engine: every scan is executed by the real
``llm-security-scanner`` distribution (the ``llm-scanner`` CLI). What lives here
is only the part an AI agent needs that the CLI does not already provide:

- :mod:`llm_scanner_skill.envelope`  -- a versioned, machine-readable result schema
- :mod:`llm_scanner_skill.authz`     -- target classification + authorization gate
- :mod:`llm_scanner_skill.sanitize`  -- neutralizes untrusted target/report output
- :mod:`llm_scanner_skill.inspect`   -- maps a local project's LLM attack surface
- :mod:`llm_scanner_skill.config`    -- builds/validates the scanner's own YAML config
- :mod:`llm_scanner_skill.adapter`   -- invokes the real CLI, returns an envelope
- :mod:`llm_scanner_skill.summarize` -- report.json -> agent-facing summary
- :mod:`llm_scanner_skill.compare`   -- before/after scan diff
- :mod:`llm_scanner_skill.remediation` -- grounded remediation guidance lookup
- :mod:`llm_scanner_skill.mcp_server`  -- optional MCP server over the above
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"  # x-release-please-version
