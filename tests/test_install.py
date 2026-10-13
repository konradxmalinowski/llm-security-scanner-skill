"""The cross-platform installer: one skill, many discovery paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_scanner_skill.install import (
    PLATFORM_PATHS,
    SKILL_NAME,
    install,
    skill_source_dir,
    uninstall,
)


def test_bundled_skill_is_locatable() -> None:
    source = skill_source_dir()
    assert (source / "SKILL.md").is_file()
    assert (source / "references").is_dir()
    assert (source / "scripts").is_dir()


def test_every_supported_platform_is_declared() -> None:
    assert set(PLATFORM_PATHS) == {"agents", "claude", "gemini", "codex"}


def test_claude_and_codex_share_the_interop_path() -> None:
    """.agents/skills is the path all three implementations read."""
    assert PLATFORM_PATHS["codex"] == PLATFORM_PATHS["agents"]


@pytest.mark.parametrize("platform", sorted(PLATFORM_PATHS))
def test_project_install_lands_in_the_documented_path(platform: str, tmp_path: Path) -> None:
    dest, action = install(platform, scope="project", project_root=tmp_path)
    expected = tmp_path / PLATFORM_PATHS[platform][0] / SKILL_NAME
    assert dest == expected
    assert (dest / "SKILL.md").is_file()
    assert action in {"symlinked", "copied", "copied (symlink unsupported)"}


def test_copy_mode_is_self_contained(tmp_path: Path) -> None:
    dest, action = install("agents", scope="project", project_root=tmp_path, mode="copy")
    assert action == "copied"
    assert not dest.is_symlink()
    assert (dest / "references" / "scanner-overview.md").is_file()


def test_symlink_mode_tracks_the_source(tmp_path: Path) -> None:
    dest, action = install("agents", scope="project", project_root=tmp_path, mode="symlink")
    if action == "symlinked":
        assert dest.is_symlink()
        assert dest.resolve() == skill_source_dir().resolve()


def test_reinstall_without_force_refuses(tmp_path: Path) -> None:
    install("agents", scope="project", project_root=tmp_path)
    with pytest.raises(FileExistsError, match="force"):
        install("agents", scope="project", project_root=tmp_path)


def test_force_replaces(tmp_path: Path) -> None:
    install("agents", scope="project", project_root=tmp_path, mode="copy")
    dest, _ = install("agents", scope="project", project_root=tmp_path, mode="copy", force=True)
    assert (dest / "SKILL.md").is_file()


def test_uninstall_removes(tmp_path: Path) -> None:
    install("agents", scope="project", project_root=tmp_path, mode="copy")
    path, removed = uninstall("agents", scope="project", project_root=tmp_path)
    assert removed and not path.exists()


def test_uninstall_is_idempotent(tmp_path: Path) -> None:
    _, removed = uninstall("agents", scope="project", project_root=tmp_path)
    assert removed is False


def test_unknown_platform_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown platform"):
        install("copilot", scope="project", project_root=tmp_path)


def test_unknown_scope_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="scope"):
        install("agents", scope="global", project_root=tmp_path)


def test_unknown_mode_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mode"):
        install("agents", scope="project", project_root=tmp_path, mode="hardlink")


def test_installed_skill_is_fully_usable(tmp_path: Path) -> None:
    """Everything SKILL.md references must exist in the installed copy."""
    dest, _ = install("agents", scope="project", project_root=tmp_path, mode="copy")
    for rel in (
        "SKILL.md",
        "references/scanner-overview.md",
        "references/troubleshooting.md",
        "workflows/assess-and-scan.md",
        "scripts/scan.py",
        "scripts/_common.py",
        "examples/http-endpoint.md",
        "agents/openai.yaml",
    ):
        assert (dest / rel).is_file(), f"missing {rel} in the installed skill"
