"""Pytest sibling-module isolation helper for per-skill test suites.

Why this exists
---------------
Every shipped skill in `skills/<layer>/<skill>/` follows the same flat
`src/<entrypoint>.py` layout — `src/ingest.py`, `src/detect.py`,
`src/handler.py`, `src/checks.py`, `src/convert.py`, `src/discover.py`.
pytest collects all skill test suites in one process and the entrypoint
module name (e.g. `handler`) collides across siblings: when
`remediate-okta-session-kill/tests/test_handler.py` imports `handler`,
Python's import system can return the cached `handler` from a sibling
skill that was collected first.

Per-skill `tests/conftest.py` fixes this by:

1. Removing any cached sibling-named modules from `sys.modules`
2. Removing any other `*/src` directory from `sys.path`
3. Inserting THIS skill's `src/` at position 0

Each skill needs the same 14-line snippet — that duplication is what this
helper eliminates. After this refactor, every per-skill conftest is a
2-line shim:

    from tests._pytest_isolation import isolate_skill_src
    isolate_skill_src(__file__)

The helper accepts the conftest's own `__file__` path and infers the
sibling `src/` directory as `<conftest_dir>/../src/`.

A conftest only runs once, and pytest imports the conftest of every
command-line arg before any test module, so the repo-root `conftest.py` also
calls `activate_skill_src_cached` for the owning skill before each test module
is imported and before each test runs. Activation stashes the other skills'
flat modules instead of dropping them, so each skill gets back the exact module
objects its tests imported.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

# Module names that appear as `src/<name>.py` across multiple skills and
# therefore collide in sys.modules during cross-skill pytest collection.
_SIBLING_MODULE_NAMES: tuple[str, ...] = (
    "ingest",
    "detect",
    "checks",
    "convert",
    "discover",
    "handler",
)


_stashed: dict[str, dict[str, ModuleType]] = {}
_active_src: str | None = None


def _flat_src_dir(name: str, module: ModuleType) -> str | None:
    """Return the skill `src/` dir a module was imported from as a top-level name.

    Only modules resolved through a `skills/<layer>/<skill>/src` sys.path entry
    qualify (`handler` -> `src/handler.py`, `steps.x` -> `src/steps/x.py`).
    """
    file = getattr(module, "__file__", None)
    if not file:
        return None
    path = Path(file)
    if path.name == "__init__.py":
        path = path.parent
    for part in reversed(name.split(".")):
        if path.name.split(".")[0] != part:
            return None
        path = path.parent
    if path.name != "src" or path.parent.parent.parent.name != "skills":
        return None
    return str(path)


def activate_skill_src(src_dir: str | Path) -> None:
    """Make `src_dir` the only skill `src/` visible to flat imports.

    Modules other skills imported from their own `src/` are stashed rather than
    discarded, and restored on that skill's next activation, so a test module
    and `mock.patch("handler.x")` keep resolving to the same module object.
    """
    global _active_src
    src = str(Path(src_dir).resolve())
    stash = _stashed.setdefault(src, {})
    for name, module in list(sys.modules.items()):
        owner = _flat_src_dir(name, module)
        if owner == src:
            continue
        if owner is not None:
            _stashed.setdefault(owner, {})[name] = sys.modules.pop(name)
        elif name in _SIBLING_MODULE_NAMES:
            sys.modules.pop(name)
    for name, module in stash.items():
        sys.modules.setdefault(name, module)
    sys.path[:] = [p for p in sys.path if not p.endswith("/src")]
    sys.path.insert(0, src)
    _active_src = src


def activate_skill_src_cached(src_dir: str | Path) -> None:
    """`activate_skill_src` unless `src_dir` is still the active one."""
    src = str(Path(src_dir).resolve())
    if _active_src == src and sys.path and sys.path[0] == src:
        return
    activate_skill_src(src)


def owning_skill_src(path: str | Path, skills_root: Path) -> Path | None:
    """Return `skills/<layer>/<skill>/src` for a path under that skill's tests."""
    try:
        parts = Path(path).resolve().relative_to(skills_root).parts
    except ValueError:
        return None
    if len(parts) < 4 or parts[2] != "tests":
        return None
    src = skills_root / parts[0] / parts[1] / "src"
    return src if src.is_dir() else None


def isolate_skill_src(conftest_file: str | Path) -> Path:
    """Isolate this skill's `src/` directory from sibling skills' identically
    named entrypoint modules.

    Call from a per-skill `tests/conftest.py` with `__file__`. Returns the
    `src/` directory path so callers can also reference it if needed.

    Idempotent: calling twice is harmless. The repo-root conftest re-runs the
    same activation before each skill's test modules are imported and before
    each of its tests runs, because pytest imports every command-line arg's
    conftest up front.
    """
    src_dir = Path(conftest_file).resolve().parent.parent / "src"
    activate_skill_src(src_dir)
    return src_dir
