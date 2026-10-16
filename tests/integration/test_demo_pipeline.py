"""The public demo must not report success after any failed pipeline stage."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("stage", ["ingest.py", "detect.py", "convert.py", ""])
def test_demo_propagates_stage_failure(tmp_path: Path, stage: str) -> None:
    runner = tmp_path / "runner.py"
    runner.write_text(
        "import os, subprocess, sys\n"
        "if os.environ['FAIL_STAGE'] and sys.argv[2].endswith(os.environ['FAIL_STAGE']):\n"
        "    sys.exit(42)\n"
        "sys.exit(subprocess.call([sys.executable, *sys.argv[2:]]))\n"
    )
    output = tmp_path / "cloud-security-demo.sarif"
    output.write_text("previous successful artifact")
    result = subprocess.run(
        ["make", "demo", f"RUN={sys.executable} {runner}"],
        cwd=ROOT,
        env={**os.environ, "TMPDIR": str(tmp_path), "FAIL_STAGE": stage},
        capture_output=True,
        text=True,
        check=False,
    )
    if stage:
        assert result.returncode != 0, result.stdout
        assert "Findings written" not in result.stdout
        assert output.read_text() == "previous successful artifact"
    else:
        assert result.returncode == 0, result.stderr
        assert "1 finding(s) emitted" in result.stdout
        assert "AWS IAM access key created" in result.stdout
    assert not list(tmp_path.glob("cloud-security-demo.sarif.*"))
