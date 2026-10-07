"""Sibling skill test dirs passed as separate pytest args must stay isolated.

Each pair below ships the same flat `src/<entrypoint>.py` module name. pytest
imports every arg's conftest before it imports any test module, so isolation
that only runs at conftest import time lets the last skill's `src/` win for
every arg. Run each pair in a subprocess, in both orders.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

SIBLING_PAIRS = [
    pytest.param(
        "skills/evaluation/container-security/tests",
        "skills/evaluation/k8s-security-benchmark/tests",
        id="evaluation-checks",
    ),
    pytest.param(
        "skills/remediation/remediate-okta-session-kill/tests",
        "skills/remediation/remediate-workspace-session-kill/tests",
        id="remediation-handler",
    ),
    pytest.param(
        "skills/detection/detect-entra-credential-addition/tests",
        "skills/detection/detect-entra-role-grant-escalation/tests",
        id="detection-detect",
    ),
]


def _run_pytest(*paths: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *paths],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )


@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reverse"])
@pytest.mark.parametrize(("first", "second"), SIBLING_PAIRS)
def test_sibling_skill_args_are_isolated(first: str, second: str, reverse: bool) -> None:
    paths = (second, first) if reverse else (first, second)
    result = _run_pytest(*paths)
    output = result.stdout + result.stderr
    summary = output.strip().splitlines()[-1]
    assert result.returncode == 0, output[-4000:]
    assert " passed" in summary and "error" not in summary, output[-4000:]


@pytest.fixture
def import_state() -> Iterator[None]:
    saved_path = list(sys.path)
    saved_modules = dict(sys.modules)
    yield
    sys.path[:] = saved_path
    for name in set(sys.modules) - set(saved_modules):
        del sys.modules[name]
    sys.modules.update(saved_modules)


def _make_skill(root: Path, name: str, marker: str) -> Path:
    src = root / "skills" / "layer" / name / "src"
    (src / "steps").mkdir(parents=True)
    (src / "handler.py").write_text(f"MARKER = {marker!r}\n")
    (src / "steps" / "__init__.py").write_text(f"MARKER = {marker!r}\n")
    return src


def test_activate_skill_src_swaps_and_restores_flat_modules(
    tmp_path: Path, import_state: None
) -> None:
    from tests._pytest_isolation import activate_skill_src

    src_a = _make_skill(tmp_path, "skill-a", "a")
    src_b = _make_skill(tmp_path, "skill-b", "b")

    activate_skill_src(src_a)
    handler_a = importlib.import_module("handler")
    steps_a = importlib.import_module("steps")

    assert (handler_a.MARKER, steps_a.MARKER) == ("a", "a")
    assert sys.path[0] == str(src_a)

    activate_skill_src(src_b)
    assert str(src_a) not in sys.path
    handler_b = importlib.import_module("handler")
    steps_b = importlib.import_module("steps")

    assert (handler_b.MARKER, steps_b.MARKER) == ("b", "b")

    activate_skill_src(src_a)
    assert sys.modules["handler"] is handler_a
    assert sys.modules["steps"] is steps_a
    assert sys.path[0] == str(src_a)


def test_activate_skill_src_drops_foreign_sibling_name_without_file(
    tmp_path: Path, import_state: None
) -> None:
    import types

    from tests._pytest_isolation import activate_skill_src

    sys.modules["detect"] = types.ModuleType("detect")
    activate_skill_src(_make_skill(tmp_path, "skill-a", "a"))
    assert "detect" not in sys.modules
