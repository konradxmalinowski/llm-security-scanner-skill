"""Validates every platform adapter against its published format.

Each assertion traces to a documented requirement:
  - Agent Skills spec       https://agentskills.io/specification
  - Claude Code plugins     https://code.claude.com/docs/en/plugins-reference
  - Gemini CLI extensions   google-gemini/gemini-cli docs/extensions/reference.md
  - Codex skills            https://learn.chatgpt.com/docs/build-skills
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "llm-security-scan"


def _frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{path} must open with YAML frontmatter"
    _, fm, _ = text.split("---", 2)
    return yaml.safe_load(fm)


class TestAgentSkillsSpec:
    """Constraints from https://agentskills.io/specification."""

    def test_skill_md_exists(self) -> None:
        assert (SKILL / "SKILL.md").is_file()

    def test_required_fields_present(self) -> None:
        fm = _frontmatter(SKILL / "SKILL.md")
        assert fm["name"] and fm["description"]

    def test_name_rules(self) -> None:
        name = _frontmatter(SKILL / "SKILL.md")["name"]
        assert 1 <= len(name) <= 64
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name), name
        assert not name.startswith("-") and not name.endswith("-")
        assert "--" not in name

    def test_name_matches_directory(self) -> None:
        """The spec requires name == parent directory name."""
        assert _frontmatter(SKILL / "SKILL.md")["name"] == SKILL.name

    def test_description_length(self) -> None:
        desc = _frontmatter(SKILL / "SKILL.md")["description"]
        assert 1 <= len(desc) <= 1024

    def test_description_says_what_and_when(self) -> None:
        desc = _frontmatter(SKILL / "SKILL.md")["description"].lower()
        assert "use when" in desc or "use this" in desc
        assert "owasp" in desc

    def test_compatibility_length(self) -> None:
        compat = _frontmatter(SKILL / "SKILL.md").get("compatibility")
        if compat is not None:
            assert 1 <= len(compat) <= 500

    def test_only_spec_fields_used(self) -> None:
        allowed = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
        assert set(_frontmatter(SKILL / "SKILL.md")) <= allowed

    def test_metadata_values_are_strings(self) -> None:
        """The spec defines metadata as a map of string to string."""
        meta = _frontmatter(SKILL / "SKILL.md").get("metadata", {})
        for key, value in meta.items():
            assert isinstance(key, str) and isinstance(value, str), (key, value)

    def test_skill_md_stays_under_500_lines(self) -> None:
        """Progressive disclosure: the body loads whole on activation."""
        lines = (SKILL / "SKILL.md").read_text(encoding="utf-8").splitlines()
        assert len(lines) <= 500, f"SKILL.md is {len(lines)} lines"

    def test_conventional_directories_used(self) -> None:
        for sub in ("references", "scripts", "examples", "workflows"):
            assert (SKILL / sub).is_dir()

    def test_every_referenced_file_exists(self) -> None:
        """A dangling link breaks progressive disclosure silently."""
        broken: list[str] = []
        for md in SKILL.rglob("*.md"):
            for target in re.findall(r"\]\((?!https?://|#)([^)]+)\)", md.read_text("utf-8")):
                clean = target.split("#")[0].rstrip("/")
                if not clean:
                    continue
                if not (md.parent / clean).exists():
                    broken.append(f"{md.relative_to(SKILL)} -> {target}")
        assert not broken, f"broken links: {broken}"

    def test_references_are_one_level_deep(self) -> None:
        """The spec advises against deeply nested reference chains."""
        for md in (SKILL / "references").glob("*.md"):
            assert md.parent.parent == SKILL

    def test_reference_files_stay_focused(self) -> None:
        """Smaller reference files mean less context burned per load."""
        for md in (SKILL / "references").glob("*.md"):
            lines = len(md.read_text("utf-8").splitlines())
            assert lines <= 250, f"{md.name} is {lines} lines; split it"


class TestScripts:
    def test_scripts_are_executable(self) -> None:
        for script in (SKILL / "scripts").glob("*.py"):
            if script.name.startswith("_"):
                continue
            assert script.stat().st_mode & stat.S_IXUSR, f"{script.name} is not executable"

    def test_scripts_have_a_shebang(self) -> None:
        for script in (SKILL / "scripts").glob("*.py"):
            if script.name.startswith("_"):
                continue
            first = script.read_text("utf-8").splitlines()[0]
            assert first.startswith("#!"), script.name

    def test_every_script_named_in_skill_md_exists(self) -> None:
        body = (SKILL / "SKILL.md").read_text("utf-8")
        for name in set(re.findall(r"scripts/([a-z_]+\.py)", body)):
            assert (SKILL / "scripts" / name).is_file(), name

    def test_no_scanning_logic_in_the_skill_scripts(self) -> None:
        """The skill must delegate, never reimplement. This is the core constraint."""
        for script in (SKILL / "scripts").glob("*.py"):
            text = script.read_text("utf-8")
            for forbidden in (
                "judge_criteria",
                "payloads/",
                "OllamaJudge",
                "LLMScanner",
                "run_detectors",
            ):
                assert forbidden not in text, f"{script.name} contains scanner logic: {forbidden}"

    def test_scripts_are_thin(self) -> None:
        for script in (SKILL / "scripts").glob("*.py"):
            if script.name.startswith("_"):
                continue
            lines = len(script.read_text("utf-8").splitlines())
            assert lines <= 25, f"{script.name} is {lines} lines; it should be a wrapper"


class TestClaudePlugin:
    """Constraints from https://code.claude.com/docs/en/plugins-reference."""

    @pytest.fixture
    def manifest(self) -> dict:
        return json.loads((REPO / ".claude-plugin" / "plugin.json").read_text("utf-8"))

    def test_manifest_location(self) -> None:
        assert (REPO / ".claude-plugin" / "plugin.json").is_file()

    def test_name_is_required_and_kebab_case(self, manifest: dict) -> None:
        name = manifest["name"]
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name), name
        for bad in (" ", "@", ":", "/", "\\"):
            assert bad not in name

    def test_name_is_not_reserved(self, manifest: dict) -> None:
        """validate rejects names that pass as Anthropic's own."""
        name = manifest["name"].lower()
        for prefix in ("claude-", "anthropic-", "anthropics-", "cc-plugin-"):
            assert not name.startswith(prefix)
        assert name not in {"claude", "anthropic", "anthropics", "claude-code", "claude-mods"}

    def test_metadata_present_to_avoid_validate_warnings(self, manifest: dict) -> None:
        assert manifest.get("version") and manifest.get("description")
        assert manifest.get("author", {}).get("name")

    def test_only_recognized_top_level_fields(self, manifest: dict) -> None:
        allowed = {
            "$schema",
            "name",
            "displayName",
            "version",
            "description",
            "author",
            "homepage",
            "repository",
            "license",
            "keywords",
            "metadata",
            "icon",
            "documentationUrl",
            "supportUrl",
            "privacyPolicyUrl",
            "termsOfServiceUrl",
            "defaultEnabled",
            "dependencies",
            "settings",
            "userConfig",
            "types",
            "channels",
            "skills",
            "commands",
            "agents",
            "hooks",
            "mcpServers",
            "lspServers",
            "outputStyles",
            "workflows",
            "experimental",
        }
        assert set(manifest) <= allowed, f"unknown: {set(manifest) - allowed}"

    def test_skills_use_the_default_location(self) -> None:
        """skills/ is scanned by default, so no manifest key is needed."""
        assert (REPO / "skills" / "llm-security-scan" / "SKILL.md").is_file()

    def test_component_paths_use_the_required_prefix(self, manifest: dict) -> None:
        for key in ("skills", "commands", "agents", "outputStyles", "workflows"):
            value = manifest.get(key)
            for path in [value] if isinstance(value, str) else (value or []):
                if isinstance(path, str):
                    assert path.startswith("./") or path == ".", path

    def test_mcp_server_declared(self, manifest: dict) -> None:
        server = manifest["mcpServers"]["llm-security-scanner"]
        assert server["command"] == "llm-scanner-skill"
        assert server["args"] == ["mcp"]

    def test_no_claude_md_at_plugin_root(self) -> None:
        """validate warns about one; instructions belong in a skill."""
        assert not (REPO / "CLAUDE.md").exists()

    def test_no_top_level_bin_directory(self) -> None:
        """claude.ai and Cowork refuse to install a plugin with one."""
        assert not (REPO / "bin").exists()

    def test_marketplace_entry(self) -> None:
        mk = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text("utf-8"))
        assert mk["name"] and mk["owner"]["name"]
        entry = mk["plugins"][0]
        assert entry["name"] == "llm-security-scanner"
        assert entry["source"] == "./"

    def test_marketplace_name_matches_manifest(self, manifest: dict) -> None:
        """A mismatch namespaces components under one name and enables the other."""
        mk = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text("utf-8"))
        assert mk["plugins"][0]["name"] == manifest["name"]

    def test_root_mcp_json_matches_the_manifest(self, manifest: dict) -> None:
        root = json.loads((REPO / ".mcp.json").read_text("utf-8"))
        assert root["mcpServers"] == manifest["mcpServers"]


class TestGeminiExtension:
    @pytest.fixture
    def manifest(self) -> dict:
        return json.loads((REPO / "gemini-extension.json").read_text("utf-8"))

    def test_manifest_at_repo_root(self) -> None:
        assert (REPO / "gemini-extension.json").is_file()

    def test_required_fields(self, manifest: dict) -> None:
        assert manifest["name"] and manifest["version"] and manifest["description"]

    def test_name_uses_dashes_not_underscores(self, manifest: dict) -> None:
        """Gemini requires lowercase/numbers with dashes."""
        assert re.fullmatch(r"[a-z0-9-]+", manifest["name"])
        assert "_" not in manifest["name"]

    def test_context_file_exists(self, manifest: dict) -> None:
        assert (REPO / manifest["contextFileName"]).is_file()

    def test_mcp_server_uses_extension_path_for_portability(self, manifest: dict) -> None:
        server = manifest["mcpServers"]["llm-security-scanner"]
        assert server["cwd"] == "${extensionPath}"
        assert "args" in server, "command and args must be separate"

    def test_env_vars_declared_because_gemini_sanitizes_the_environment(
        self, manifest: dict
    ) -> None:
        """Undeclared env vars are NOT passed to a Gemini extension."""
        declared = {s["envVar"] for s in manifest["settings"]}
        assert "OLLAMA_HOST" in declared
        assert "LLM_SCANNER_BIN" in declared

    def test_settings_entries_are_complete(self, manifest: dict) -> None:
        for setting in manifest["settings"]:
            assert {"name", "description", "envVar"} <= set(setting)

    def test_skill_discoverable_in_the_extension_skills_dir(self) -> None:
        assert (REPO / "skills" / "llm-security-scan" / "SKILL.md").is_file()

    def test_command_is_toml_in_commands_dir(self) -> None:
        assert (REPO / "commands" / "llm-security-scan.toml").is_file()

    def test_command_has_prompt_and_description(self) -> None:
        import tomllib

        data = tomllib.loads((REPO / "commands" / "llm-security-scan.toml").read_text("utf-8"))
        assert data["description"] and data["prompt"]
        assert "{{args}}" in data["prompt"]

    def test_no_policies_dir_since_gemini_ignores_allow(self) -> None:
        """Gemini ignores `allow` from an extension, so the gate lives in Python."""
        assert not (REPO / "policies").exists()

    def test_no_md_commands_that_claude_would_also_load(self) -> None:
        """commands/ holds Gemini TOML only; Claude's scan picks up .md files."""
        assert list((REPO / "commands").glob("*.md")) == []


class TestCodex:
    def test_openai_yaml_lives_inside_the_skill(self) -> None:
        assert (SKILL / "agents" / "openai.yaml").is_file()

    def test_openai_yaml_is_valid(self) -> None:
        data = yaml.safe_load((SKILL / "agents" / "openai.yaml").read_text("utf-8"))
        assert data["interface"]["display_name"]
        assert data["policy"]["allow_implicit_invocation"] is True

    def test_agents_md_at_repo_root(self) -> None:
        assert (REPO / "AGENTS.md").is_file()

    def test_agents_md_points_at_the_skill_rather_than_restating_it(self) -> None:
        """It is always in context, so it must stay a pointer."""
        text = (REPO / "AGENTS.md").read_text("utf-8")
        assert "skills/llm-security-scan/SKILL.md" in text
        assert len(text.splitlines()) <= 80

    def test_skill_fits_the_codex_startup_budget(self) -> None:
        """Codex caps the startup skill list at ~8000 chars across all skills."""
        desc = _frontmatter(SKILL / "SKILL.md")["description"]
        assert len(desc) <= 1024


class TestGenericAdapter:
    def test_tools_json_exists(self) -> None:
        assert (REPO / "platforms" / "generic" / "tools.json").is_file()

    def test_tools_json_shape(self) -> None:
        doc = json.loads((REPO / "platforms" / "generic" / "tools.json").read_text("utf-8"))
        assert doc["tools"]
        for tool in doc["tools"]:
            assert tool["type"] == "function"
            fn = tool["function"]
            assert fn["name"] and fn["description"]
            assert fn["parameters"]["type"] == "object"
            assert tool["x-command"], f"{fn['name']} has no x-command mapping"

    def test_system_prompt_fragment_exists(self) -> None:
        text = (REPO / "platforms" / "generic" / "system-prompt.md").read_text("utf-8")
        assert "untrusted data" in text
        assert "authorized" in text

    def test_every_platform_has_a_readme(self) -> None:
        for platform in ("claude", "gemini", "codex", "generic"):
            assert (REPO / "platforms" / platform / "README.md").is_file()


class TestNoDuplicatedKnowledge:
    def test_exactly_one_skill_directory(self) -> None:
        """One canonical copy. Platform adapters are manifests, not forks."""
        found = [p for p in REPO.rglob("SKILL.md") if ".venv" not in p.parts]
        assert len(found) == 1, f"multiple SKILL.md files: {found}"

    def test_platform_readmes_do_not_restate_the_workflow(self) -> None:
        """They should describe installation and link onward, not duplicate content."""
        for platform in ("claude", "gemini", "codex", "generic"):
            text = (REPO / "platforms" / platform / "README.md").read_text("utf-8")
            assert len(text.splitlines()) <= 120, f"{platform}/README.md is too long"

    def test_always_loaded_context_files_stay_small(self) -> None:
        for name in ("AGENTS.md", "GEMINI.md"):
            lines = len((REPO / name).read_text("utf-8").splitlines())
            assert lines <= 80, f"{name} is {lines} lines and is always in context"
