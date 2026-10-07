"""Repo-root pytest conftest.

Adds the repo root to sys.path so per-skill `tests/conftest.py` files can
import `tests._pytest_isolation` regardless of how pytest is invoked.

pytest imports the conftest of every command-line arg before it imports any
test module, so a per-skill conftest alone cannot keep sibling skills passed
as separate args (`pytest skills/a/x/tests skills/a/y/tests`) from seeing each
other's flat `src/` modules. The hooks below re-activate the owning skill's
`src/` right before its test modules are imported and before each test runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests._pytest_isolation import activate_skill_src_cached, owning_skill_src  # noqa: E402

_SKILLS_ROOT = _REPO_ROOT / "skills"


def _activate_owner(path: Path | None) -> None:
    if path is None:
        return
    src = owning_skill_src(path, _SKILLS_ROOT)
    if src is not None:
        activate_skill_src_cached(src)


def pytest_collectstart(collector: pytest.Collector) -> None:
    _activate_owner(getattr(collector, "path", None))


def pytest_runtest_setup(item: pytest.Item) -> None:
    _activate_owner(item.path)
