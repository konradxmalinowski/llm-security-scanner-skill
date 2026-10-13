"""The cross-platform installer: one skill, many discovery paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_scanner_skill.install import (
    PLATFORM_PATHS,
    SKILL_NAME,
    install,
    install_destination,
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


class TestSharedDestinations:
    """Several platforms deliberately resolve to the same directory.

    'claude' and 'codex' both use `.agents/skills`, so `--platform all` names that
    path twice. Before the destinations were deduplicated up front, the second
    install raised FileExistsError and made `--platform all` fail by design. Caught
    by CI on the first push.
    """

    def test_install_destination_resolves_without_installing(self, tmp_path: Path) -> None:
        dest = install_destination("agents", scope="project", project_root=tmp_path)
        assert dest == tmp_path / ".agents" / "skills" / SKILL_NAME
        assert not dest.exists()

    def test_install_destination_rejects_an_unknown_platform(self) -> None:
        with pytest.raises(ValueError, match="Unknown platform"):
            install_destination("copilot")

    def test_platform_all_succeeds_despite_a_shared_path(self, tmp_path: Path) -> None:
        from llm_scanner_skill.cli import main

        rc = main(
            [
                "install",
                "--platform",
                "all",
                "--scope",
                "project",
                "--project-root",
                str(tmp_path),
                "--mode",
                "copy",
            ]
        )
        assert rc == 0, "--platform all must not fail on a shared destination"

    def test_shared_path_is_reported_as_shared_not_as_an_error(
        self, tmp_path: Path, capsys
    ) -> None:
        import json

        from llm_scanner_skill.cli import main

        main(
            [
                "install",
                "--platform",
                "all",
                "--scope",
                "project",
                "--project-root",
                str(tmp_path),
                "--mode",
                "copy",
            ]
        )
        results = json.loads(capsys.readouterr().out)["results"]
        by_platform = {r["platform"]: r for r in results}
        assert all(r["ok"] for r in results), results
        # 'agents' installs; 'codex' reports the same path as already covered.
        assert "shares this path" in by_platform["codex"]["action"]
        assert by_platform["agents"]["action"] == "copied"

    def test_every_distinct_destination_really_gets_the_skill(self, tmp_path: Path) -> None:
        from llm_scanner_skill.cli import main

        main(
            [
                "install",
                "--platform",
                "all",
                "--scope",
                "project",
                "--project-root",
                str(tmp_path),
                "--mode",
                "copy",
            ]
        )
        for rel in (".agents/skills", ".claude/skills", ".gemini/skills"):
            assert (tmp_path / rel / SKILL_NAME / "SKILL.md").is_file(), rel
