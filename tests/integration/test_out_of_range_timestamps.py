"""A record with an unrepresentable timestamp is skipped at ingest and must not
take down the detector batch it lands in."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = REPO_ROOT / "skills" / "detection-engineering" / "golden"
INGEST = REPO_ROOT / "skills" / "ingestion" / "ingest-databricks-audit-ocsf" / "src" / "ingest.py"
DETECT = (
    REPO_ROOT
    / "skills"
    / "detection"
    / "detect-databricks-workspace-admin-grant"
    / "src"
    / "detect.py"
)
HUGE_TS = 10**22


def _huge_first_record() -> str:
    lines = (GOLDEN / "databricks_workspace_admin_grant_raw.jsonl").read_text().splitlines()
    first = json.loads(lines[0])
    first["timestamp"] = HUGE_TS
    return "\n".join([json.dumps(first), *lines[1:]]) + "\n"


def _run(script: Path, stdin: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script)],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
        timeout=60,
    )


def _grantees(stdout: str) -> list[str]:
    return [json.loads(line)["evidence"]["grantee"] for line in stdout.splitlines() if line]


def test_ingest_skips_out_of_range_timestamp_and_detect_still_fires():
    ingested = _run(INGEST, _huge_first_record())
    assert ingested.returncode == 0, ingested.stderr
    assert "skipping record 1: missing or unparseable source timestamp" in ingested.stderr
    events = [json.loads(line) for line in ingested.stdout.splitlines() if line]
    assert len(events) == 3
    assert all(event["time"] < HUGE_TS for event in events)

    detected = _run(DETECT, ingested.stdout)
    assert detected.returncode == 0, detected.stderr
    assert _grantees(detected.stdout) == ["bob-promoted@example.com"]


def test_detect_survives_out_of_range_time_in_ocsf_input():
    ingested = _run(INGEST, (GOLDEN / "databricks_workspace_admin_grant_raw.jsonl").read_text())
    events = [json.loads(line) for line in ingested.stdout.splitlines() if line]
    events[0]["time"] = HUGE_TS
    detected = _run(DETECT, "".join(json.dumps(event) + "\n" for event in events))
    assert detected.returncode == 0, detected.stderr
    assert "bob-promoted@example.com" in _grantees(detected.stdout)
