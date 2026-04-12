"""Per-skill pytest conftest: isolate this skill's src/ from sibling skills.

Many skills in this repo share short module basenames (`ingest.py`,
`detect.py`, `checks.py`, `convert.py`) inside their own `src/` directory.
When `pytest skills/` runs from the repo root, the default import mode
caches the first `ingest` it sees in `sys.modules`, so the second skill's
tests import the wrong module.

This conftest runs before tests in this directory are collected, flushes
the sibling module cache, and prepends this skill's own `src/` to
`sys.path` so its imports resolve correctly.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SIBLING_MODULE_NAMES = ("ingest", "detect", "checks", "convert", "discover")

_TESTS_DIR = Path(__file__).resolve().parent
_SRC_DIR = _TESTS_DIR.parent / "src"

# Evict any cached sibling-skill modules so the upcoming import resolves
# against THIS skill's src/.
for _name in _SIBLING_MODULE_NAMES:
    sys.modules.pop(_name, None)

# Remove any sibling `src/` entries the default pytest path manipulation may
# have inserted, then prepend this skill's src/.
sys.path[:] = [p for p in sys.path if not p.endswith("/src")]
sys.path.insert(0, str(_SRC_DIR))
