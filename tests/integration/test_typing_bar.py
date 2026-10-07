"""Guards the mypy typing bar wired in pyproject.toml and scripts/run_mypy.sh."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STRICT_FLAGS = (
    "--disallow-untyped-defs",
    "--disallow-incomplete-defs",
    "--warn-return-any",
    "--disallow-any-generics",
)


def _mypy_config(root: Path) -> dict:
    return tomllib.loads((root / "pyproject.toml").read_text())["tool"]["mypy"]


def _strict_detection_block(root: Path) -> str:
    script = (root / "scripts" / "run_mypy.sh").read_text()
    start = script.index("STRICT_SKILL_DIRS=(")
    end = script.index("done", script.index('for dir in "${STRICT_SKILL_DIRS[@]}"'))
    return script[start:end]


def test_missing_imports_are_not_ignored_globally() -> None:
    config = _mypy_config(ROOT)
    assert "ignore_missing_imports" not in config


def test_missing_import_overrides_are_module_scoped() -> None:
    for override in _mypy_config(ROOT).get("overrides", []):
        if override.get("ignore_missing_imports"):
            modules = override["module"]
            assert modules, override
            assert "*" not in modules


def test_every_detection_skill_is_in_the_strict_lane() -> None:
    block = _strict_detection_block(ROOT)
    assert "skills/detection/*/src" in block
    for flag in STRICT_FLAGS:
        assert flag in block, flag
