"""Per-skill pytest conftest: isolate this skill's src/ from sibling skills."""

from __future__ import annotations

import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
_SRC_DIR = _TESTS_DIR.parent / "src"

# Drop sibling-skill `handler` modules that may have been imported earlier in
# the test session and put our src/ on the path.
for _name in ("handler", "steps"):
    sys.modules.pop(_name, None)

sys.path[:] = [p for p in sys.path if not p.endswith("/src")]
sys.path.insert(0, str(_SRC_DIR))
