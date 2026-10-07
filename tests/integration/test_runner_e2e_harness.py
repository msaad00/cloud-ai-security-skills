"""Tests for the GCP and Azure scenarios in `scripts/_runner_e2e_harness.py`.

These drive the real runner handlers against in-process fakes of the cloud
SDK clients, so they never touch a real cloud.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "skills" / "detection-engineering" / "golden"


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "runner_e2e_harness_test", ROOT / "scripts" / "_runner_e2e_harness.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HARNESS = _load_harness()


def _golden_lines(name: str) -> list[str]:
    text = (GOLDEN / name).read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip()]


@pytest.mark.parametrize(
    ("scenario", "runner", "golden"),
    [
        (
            "run_gcp_cloud_runner_scenario",
            "cloud-runner-gcp-gcs-pubsub",
            "gcp_open_firewall_pipe_findings.ocsf.jsonl",
        ),
        (
            "run_azure_cloud_runner_scenario",
            "cloud-runner-azure-blob-eventgrid",
            "azure_open_nsg_pipe_findings.ocsf.jsonl",
        ),
    ],
)
def test_cloud_runner_scenario_publishes_golden_findings_once_and_dedupes(scenario, runner, golden):
    expected = _golden_lines(golden)
    record = getattr(HARNESS, scenario)(3)

    assert record["runner"] == runner
    assert record["status"] == "ok", record
    assert record["backend"] == "in_process_fakes"
    assert record["samples"] == 3
    assert record["successful_requests"] == 3
    assert record["failed_requests"] == 0
    # Exactly one copy of each golden finding reaches the findings sink;
    # the two redeliveries are suppressed by the dedupe store.
    assert record["sink_arrival_count"] == len(expected)
    assert record["findings_published"] == len(expected)
    assert record["duplicates_suppressed"] == 2 * len(expected)
    assert record["dedupe_rows"] == len(expected)
    assert record["dedupe_status"] == "ok_redelivery_suppressed"
    assert record["p50_ms"] > 0
    # Same base shape as the AWS scenario record.
    for key in ("audit_chain_verified", "audit_chain_status", "sink_status", "captured_at"):
        assert key in record
    json.dumps(record)


def test_cloud_runner_scenario_single_sample_marks_dedupe_unexercised():
    record = HARNESS.run_gcp_cloud_runner_scenario(1)
    assert record["status"] == "ok", record
    assert record["duplicates_suppressed"] == 0
    assert record["dedupe_status"] == "not_exercised_single_sample"


def test_cloud_runner_scenario_fails_when_detect_finds_nothing(monkeypatch):
    # A detector that emits nothing must not be reported as ok.
    monkeypatch.setattr(
        HARNESS,
        "_GCP_DETECT_SKILL",
        HARNESS.REPO_ROOT / "skills/detection/detect-azure-open-nsg/src/detect.py",
    )
    record = HARNESS.run_gcp_cloud_runner_scenario(2)
    assert record["status"] == "fail"
    assert record["findings_published"] == 0


def test_cloud_runner_scenarios_restore_sys_modules():
    before = {name for name in sys.modules if name.startswith("azure")}
    HARNESS.run_azure_cloud_runner_scenario(1)
    after = {name for name in sys.modules if name.startswith("azure")}
    assert after == before
