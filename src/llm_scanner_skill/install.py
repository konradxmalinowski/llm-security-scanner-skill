"""Installs the one canonical skill into each platform's discovery path.

The point of this module is that there is exactly ONE copy of the skill's
knowledge -- ``skills/llm-security-scan/`` in this repository -- and every platform
gets a link or copy of it. No platform has its own fork of the instructions, so
they cannot drift.

Where each platform looks (verified against current official docs, see
``docs/PLATFORMS.md``):

======================  ====================================================
Platform                Discovery path
======================  ====================================================
Interop (all three)     ``.agents/skills/`` (project) / ``~/.agents/skills/``
Claude Code             ``.claude/skills/`` (project) / ``~/.claude/skills/``
Gemini CLI              ``.gemini/skills/`` (project) / ``~/.gemini/skills/``
Codex / ChatGPT         ``.agents/skills/`` (project) / ``~/.agents/skills/``
======================  ====================================================

``.agents/skills/`` is the shared interop path all three implementations read, so
``--platform agents`` alone is enough for most setups; the per-platform paths exist
for installs that predate that alias or that disable it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

__all__ = [
    "PLATFORM_PATHS",
    "SKILL_NAME",
    "install",
    "skill_source_dir",
    "uninstall",
]

SKILL_NAME = "llm-security-scan"

# platform -> (project-relative dir, home-relative dir)
PLATFORM_PATHS: dict[str, tuple[str, str]] = {
    "agents": (".agents/skills", ".agents/skills"),
    "claude": (".claude/skills", ".claude/skills"),
    "gemini": (".gemini/skills", ".gemini/skills"),
    "codex": (".agents/skills", ".agents/skills"),
}


def skill_source_dir() -> Path:
    """Locate the bundled skill directory.

    Two layouts must both work: a git checkout (skill at ``<repo>/skills/<name>``)
    and an installed wheel (skill shipped inside the package as
    ``llm_scanner_skill/skill_bundle/<name>``).
    """
    packaged = Path(__file__).parent / "skill_bundle" / SKILL_NAME
    if (packaged / "SKILL.md").is_file():
        return packaged
    repo = Path(__file__).resolve().parents[2] / "skills" / SKILL_NAME
    if (repo / "SKILL.md").is_file():
        return repo
    raise FileNotFoundError(
        f"Could not locate the bundled skill directory. Expected {packaged} or {repo}."
    )


def _target_dir(platform: str, scope: str, project_root: Path) -> Path:
    try:
        project_rel, home_rel = PLATFORM_PATHS[platform]
    except KeyError:
        raise ValueError(
            f"Unknown platform {platform!r}. Choose from: {', '.join(sorted(PLATFORM_PATHS))}."
        ) from None
    if scope == "user":
        return Path.home() / home_rel / SKILL_NAME
    if scope == "project":
        return project_root / project_rel / SKILL_NAME
    raise ValueError(f"scope must be 'user' or 'project', got {scope!r}.")


def install(
    platform: str,
    *,
    scope: str = "user",
    project_root: str | Path = ".",
    mode: str = "symlink",
    force: bool = False,
) -> tuple[Path, str]:
    """Install the skill for *platform*. Returns (destination, action).

    ``mode="symlink"`` keeps the installed skill tracking this checkout, which is
    what you want while developing it. ``mode="copy"`` is self-contained and is the
    right choice when installing from a wheel or into a container image.

    Raises:
        FileExistsError: if the destination exists and *force* is False.
    """
    source = skill_source_dir()
    dest = _target_dir(platform, scope, Path(project_root).resolve())

    if dest.exists() or dest.is_symlink():
        if not force:
            raise FileExistsError(f"{dest} already exists. Pass force=True to replace it.")
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)

    dest.parent.mkdir(parents=True, exist_ok=True)

    if mode == "symlink":
        try:
            dest.symlink_to(source, target_is_directory=True)
            return dest, "symlinked"
        except (OSError, NotImplementedError):
            # Windows without developer mode, or a filesystem with no symlink
            # support. Copying is a correct fallback, just not self-updating.
            shutil.copytree(source, dest)
            return dest, "copied (symlink unsupported)"
    if mode == "copy":
        shutil.copytree(source, dest)
        return dest, "copied"
    raise ValueError(f"mode must be 'symlink' or 'copy', got {mode!r}.")


def uninstall(
    platform: str,
    *,
    scope: str = "user",
    project_root: str | Path = ".",
) -> tuple[Path, bool]:
    """Remove an installed skill. Returns (path, removed)."""
    dest = _target_dir(platform, scope, Path(project_root).resolve())
    if dest.is_symlink() or dest.is_file():
        dest.unlink()
        return dest, True
    if dest.is_dir():
        shutil.rmtree(dest)
        return dest, True
    return dest, False
