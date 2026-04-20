"""Repo-root pytest conftest.

Adds the repo root to sys.path so per-skill `tests/conftest.py` files can
import `tests._pytest_isolation` regardless of how pytest is invoked.
This is the minimum needed to support the shared sibling-isolation helper
that replaces ~14 lines of duplicated boilerplate per skill.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
