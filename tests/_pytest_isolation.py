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
"""

from __future__ import annotations

import sys
from pathlib import Path

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


def isolate_skill_src(conftest_file: str | Path) -> Path:
    """Isolate this skill's `src/` directory from sibling skills' identically
    named entrypoint modules.

    Call from a per-skill `tests/conftest.py` with `__file__`. Returns the
    `src/` directory path so callers can also reference it if needed.

    Idempotent: calling twice is harmless.
    """
    tests_dir = Path(conftest_file).resolve().parent
    src_dir = tests_dir.parent / "src"

    # 1. Drop cached sibling-name modules so the next import re-resolves
    for name in _SIBLING_MODULE_NAMES:
        sys.modules.pop(name, None)

    # 2. Strip any other `*/src` from sys.path so they don't shadow ours
    sys.path[:] = [p for p in sys.path if not p.endswith("/src")]

    # 3. Put this skill's src/ at the front
    sys.path.insert(0, str(src_dir))

    return src_dir
