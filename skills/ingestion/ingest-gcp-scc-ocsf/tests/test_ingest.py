"""Tests for ingest-gcp-scc-ocsf."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_gcp_scc", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

CATEGORY_UID = _INGEST.CATEGORY_UID
CLASS_UID = _INGEST.CLASS_UID
OCSF_VERSION = _INGEST.OCSF_VERSION
SEVERITY_CRITICAL = _INGEST.SEVERITY_CRITICAL
SEVERITY_HIGH = _INGEST.SEVERITY_HIGH
SEVERITY_INFORMATIONAL = _INGEST.SEVERITY_INFORMATIONAL
SEVERITY_LOW = _INGEST.SEVERITY_LOW
SEVERITY_MEDIUM = _INGEST.SEVERITY_MEDIUM
SKILL_NAME = _INGEST.SKILL_NAME
TYPE_UID = _INGEST.TYPE_UID
convert_finding = _INGEST.convert_finding
ingest = _INGEST.ingest
iter_raw_findings = _INGEST.iter_raw_findings
severity_to_id = _INGEST.severity_to_id
validate_finding = _INGEST.validate_finding

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "gcp_scc_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "gcp_scc_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _finding(**overrides) -> dict:
    finding = {
        "name": "organizations/123/sources/456/findings/finding-1",
        "category": "PUBLIC_BUCKET",
        "resourceName": "//cloudresourcemanager.googleapis.com/projects/prod-project",
        "severity": "HIGH",
        "state": "ACTIVE",
        "findingClass": "MISCONFIGURATION",
        "description": "Cloud Storage bucket is publicly accessible.",
        "eventTime": "2026-04-10T05:00:00.000000Z",
    }
    finding.update(overrides)
    return finding


class TestSeverity:
    def test_mapping(self):
        assert severity_to_id("CRITICAL") == SEVERITY_CRITICAL
        assert severity_to_id("HIGH") == SEVERITY_HIGH
        assert severity_to_id("MEDIUM") == SEVERITY_MEDIUM
        assert severity_to_id("LOW") == SEVERITY_LOW
        assert severity_to_id(None) == SEVERITY_INFORMATIONAL


class TestValidation:
    def test_valid(self):
        ok, reason = validate_finding(_finding())
        assert ok, reason

    def test_missing_field(self):
        ok, reason = validate_finding({"category": "x"})
        assert not ok
        assert "resourceName" in reason or "name" in reason


class TestConvert:
    def test_pinned_ocsf_fields(self):
        event = convert_finding(_finding())
        assert event["class_uid"] == CLASS_UID == 2004
        assert event["category_uid"] == CATEGORY_UID == 2
        assert event["type_uid"] == TYPE_UID
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert event["cloud"]["provider"] == "GCP"
        assert event["cloud"]["account"]["uid"] == "prod-project"
        assert event["finding_info"]["title"] == "PUBLIC_BUCKET"


class TestStream:
    def test_wrapper_parsing(self):
        wrapped = {"finding": _finding()}
        assert list(iter_raw_findings([json.dumps(wrapped)]))[0]["name"].endswith("finding-1")

    def test_golden_fixture(self):
        produced = list(ingest([RAW_FIXTURE.read_text()]))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert produced == expected
