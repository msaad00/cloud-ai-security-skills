"""The release version must agree everywhere it is stated."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _pyproject_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return str(tomllib.load(fh)["project"]["version"])


def test_readme_badge_matches_pyproject() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    badge = re.search(r"badge/version-([0-9][^-]*)-", readme)
    assert badge, "README version badge not found"
    assert badge.group(1) == _pyproject_version()


def test_framework_registry_matches_pyproject() -> None:
    registry = json.loads((REPO_ROOT / "docs" / "framework-coverage.json").read_text())
    assert registry["repo_version"] == _pyproject_version()


def test_changelog_has_section_for_pyproject_version() -> None:
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{_pyproject_version()}]" in changelog
