"""Invalid evidence must not become a successful empty or partial diagram."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "src" / "convert.py"
VALID = '{"class_uid": 2004, "finding_info": {"uid": "test"}}\n'


@pytest.mark.parametrize(
    "payload", ["{broken", "[]", "null", '{"class_uid": 6003}', VALID + "{broken"]
)
@pytest.mark.parametrize("fenced", [False, True])
def test_invalid_input_emits_no_diagram(payload: str, fenced: bool) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *(["--fenced"] if fenced else [])],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert "invalid input" in result.stderr
    assert "Traceback" not in result.stderr


def test_invalid_input_preserves_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "flow.mmd"
    output.write_text("previous diagram")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--output", str(output)],
        input=VALID + "{broken",
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert output.read_text() == "previous diagram"


def test_empty_input_is_a_valid_empty_diagram() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], input="\n", capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert "No findings" in result.stdout
