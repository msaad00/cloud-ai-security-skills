"""Tests for convert-ocsf-to-sarif."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from convert import (  # type: ignore[import-not-found]
    SARIF_SCHEMA,
    SARIF_VERSION,
    convert,
    load_jsonl,
    severity_to_sarif_level,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT_FIXTURE = GOLDEN / "k8s_priv_esc_findings.ocsf.jsonl"
EXPECTED = GOLDEN / "k8s_priv_esc_findings.sarif"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _detection_finding(
    *,
    uid: str = "det-test-1",
    technique_uid: str = "T1611",
    technique_name: str = "Escape to Host",
    tactic_uid: str = "TA0004",
    tactic_name: str = "Privilege Escalation",
    sub_uid: str | None = None,
    severity_id: int = 4,
    title: str = "Test finding",
    desc: str = "Test description",
    detector: str = "detect-test",
) -> dict:
    attack: dict = {
        "version": "v14",
        "tactic": {"name": tactic_name, "uid": tactic_uid},
        "technique": {"name": technique_name, "uid": technique_uid},
    }
    if sub_uid:
        attack["sub_technique"] = {"name": "Sub", "uid": sub_uid}
    return {
        "class_uid": 2004,
        "category_uid": 2,
        "type_uid": 200401,
        "severity_id": severity_id,
        "status_id": 1,
        "time": 1775797200000,
        "metadata": {
            "version": "1.8.0",
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": "msaad00/cloud-ai-security-skills",
                "feature": {"name": detector},
            },
        },
        "finding_info": {
            "uid": uid,
            "title": title,
            "desc": desc,
            "attacks": [attack],
        },
        "observables": [{"name": "actor.name", "type": "Other", "value": "test-actor"}],
        "evidence": {"events_observed": 1},
    }


# ── Severity mapping ─────────────────────────────────────────────────


class TestSeverityMapping:
    def test_unknown(self):
        assert severity_to_sarif_level(0) == "none"

    def test_informational(self):
        assert severity_to_sarif_level(1) == "note"

    def test_low(self):
        assert severity_to_sarif_level(2) == "note"

    def test_medium(self):
        assert severity_to_sarif_level(3) == "warning"

    def test_high(self):
        assert severity_to_sarif_level(4) == "error"

    def test_critical(self):
        assert severity_to_sarif_level(5) == "error"

    def test_fatal(self):
        assert severity_to_sarif_level(6) == "error"

    def test_unmapped_falls_to_none(self):
        assert severity_to_sarif_level(99) == "none"


# ── Document shape ───────────────────────────────────────────────────


class TestDocShape:
    def test_empty_input(self):
        doc = convert([])
        assert doc["$schema"] == SARIF_SCHEMA
        assert doc["version"] == SARIF_VERSION
        assert len(doc["runs"]) == 1
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_single_finding(self):
        doc = convert([_detection_finding()])
        assert len(doc["runs"][0]["results"]) == 1
        result = doc["runs"][0]["results"][0]
        assert result["ruleId"] == "T1611"
        assert result["level"] == "error"
        assert "Test finding" in result["message"]["text"]
        assert "Test description" in result["message"]["text"]

    def test_tool_name_pinned(self):
        doc = convert([_detection_finding()])
        assert (
            doc["runs"][0]["tool"]["driver"]["name"]
            == "cloud-ai-security-skills-detection-engineering"
        )

    def test_rejects_non_detection_finding(self):
        with pytest.raises(ValueError, match="class_uid=2004"):
            convert([_detection_finding(), {"class_uid": 6003}])


# ── Rule deduplication ───────────────────────────────────────────────


class TestRuleDedup:
    def test_converter_does_not_invent_detector_precision(self):
        rule = convert([_detection_finding()])["runs"][0]["tool"]["driver"]["rules"][0]
        assert "precision" not in rule["properties"]

    def test_two_findings_same_technique_one_rule(self):
        doc = convert(
            [
                _detection_finding(uid="a", technique_uid="T1611"),
                _detection_finding(uid="b", technique_uid="T1611"),
            ]
        )
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "T1611"
        # But two results
        assert len(doc["runs"][0]["results"]) == 2

    def test_three_findings_three_techniques_three_rules(self):
        doc = convert(
            [
                _detection_finding(uid="a", technique_uid="T1611"),
                _detection_finding(uid="b", technique_uid="T1098"),
                _detection_finding(uid="c", technique_uid="T1552"),
            ]
        )
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert rule_ids == {"T1611", "T1098", "T1552"}


# ── MITRE tags ───────────────────────────────────────────────────────


class TestMitreTags:
    def test_tags_include_technique_and_tactic(self):
        doc = convert(
            [
                _detection_finding(
                    technique_uid="T1611", tactic_uid="TA0004", tactic_name="Privilege Escalation"
                )
            ]
        )
        result = doc["runs"][0]["results"][0]
        tags = result["properties"]["tags"]
        assert "mitre/attack/technique/T1611" in tags
        assert "mitre/attack/privilege-escalation/TA0004" in tags

    def test_sub_technique_in_tags_when_present(self):
        doc = convert([_detection_finding(sub_uid="T1552.007")])
        tags = doc["runs"][0]["results"][0]["properties"]["tags"]
        assert "mitre/attack/sub-technique/T1552.007" in tags


# ── Properties carry observables + evidence ──────────────────────────


class TestProperties:
    def test_observables_passthrough(self):
        f = _detection_finding()
        f["observables"] = [
            {"name": "actor.name", "type": "Other", "value": "alice"},
            {"name": "tool.name", "type": "Other", "value": "query_db"},
        ]
        doc = convert([f])
        obs = doc["runs"][0]["results"][0]["properties"]["observables"]
        assert len(obs) == 2
        assert obs[0]["value"] == "alice"

    def test_evidence_passthrough(self):
        f = _detection_finding()
        f["evidence"] = {"events_observed": 5, "before_event_time": 1000, "after_event_time": 2000}
        doc = convert([f])
        ev = doc["runs"][0]["results"][0]["properties"]["evidence"]
        assert ev["events_observed"] == 5

    def test_detector_metadata(self):
        f = _detection_finding(detector="detect-mcp-tool-drift")
        doc = convert([f])
        assert doc["runs"][0]["results"][0]["properties"]["detector"] == "detect-mcp-tool-drift"


# ── Locations ───────────────────────────────────────────────────────


class TestLocations:
    def test_logical_location_present(self):
        doc = convert([_detection_finding(uid="abc", detector="detect-test")])
        loc = doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
        assert loc["name"] == "detect-test"
        assert "abc" in loc["fullyQualifiedName"]
        assert loc["kind"] == "module"


# ── Fingerprints (dedup across runs) ─────────────────────────────────


class TestFingerprints:
    def test_partial_fingerprint_present_when_uid(self):
        doc = convert([_detection_finding(uid="det-abc")])
        result = doc["runs"][0]["results"][0]
        assert "partialFingerprints" in result
        assert "primaryLocationLineHash" in result["partialFingerprints"]

    @pytest.mark.parametrize(
        "uid",
        [
            "det-abc-123",
            "a" * 32,
            "{12345678-1234-4234-8234-123456789abc}",
            "12345678-1234-7234-8234-123456789abc",
        ],
    )
    def test_opaque_uid_is_preserved_without_invalid_guid(self, uid):
        result = convert([_detection_finding(uid=uid)])["runs"][0]["results"][0]
        assert "guid" not in result
        assert result["properties"]["finding_uid"] == uid

    def test_canonical_guid_is_preserved(self):
        uid = "12345678-1234-4234-8234-123456789abc"
        result = convert([_detection_finding(uid=uid)])["runs"][0]["results"][0]
        assert result["guid"] == uid
        assert result["properties"]["finding_uid"] == uid

    def test_generated_results_satisfy_sarif_guid_pattern(self):
        # OASIS SARIF 2.1.0 schema, definitions.result.properties.guid.pattern.
        pattern = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
        for result in convert(_load_jsonl(INPUT_FIXTURE))["runs"][0]["results"]:
            assert "guid" not in result or re.fullmatch(pattern, result["guid"])

    def test_repeated_uid_does_not_drop_occurrences(self):
        finding = _detection_finding(uid="same")
        results = convert([finding, finding])["runs"][0]["results"]
        assert len(results) == 2
        assert all(result["properties"]["finding_uid"] == "same" for result in results)


# ── load_jsonl robustness ────────────────────────────────────────────


class TestLoadJsonl:
    @pytest.mark.parametrize("payload", ['{"bad": ', "[1,2,3]", '"text"', "null", "42"])
    def test_rejects_invalid_records(self, payload):
        with pytest.raises(ValueError, match="line 2"):
            list(load_jsonl(['{"class_uid": 2004}', payload]))


class TestCliFailure:
    @pytest.mark.parametrize("payload", ['{"bad": ', "[]", "null", '{"class_uid":6003}'])
    @pytest.mark.parametrize("valid_prefix", [False, True])
    def test_invalid_input_does_not_publish_or_replace_report(
        self, tmp_path, payload, valid_prefix
    ):
        source = (json.dumps(_detection_finding()) + "\n" if valid_prefix else "") + payload
        entrypoint = THIS.parent / "src" / "convert.py"
        destination = tmp_path / "existing.sarif"
        destination.write_text("previous report")
        for args in [[], ["--output", str(destination)]]:
            result = subprocess.run(
                [sys.executable, str(entrypoint), *args],
                input=source,
                text=True,
                capture_output=True,
            )
            assert result.returncode != 0
            assert result.stdout == ""
            assert "invalid input" in result.stderr
            assert destination.read_text() == "previous report"

    @pytest.mark.parametrize(
        "field,value",
        [
            ("severity_id", "PRIVATE_TEST_VALUE"),
            ("finding_info", ["PRIVATE_TEST_VALUE"]),
            ("metadata", ["PRIVATE_TEST_VALUE"]),
        ],
    )
    def test_malformed_fields_fail_without_disclosing_payload(self, tmp_path, field, value):
        finding = _detection_finding()
        finding[field] = value
        destination = tmp_path / "existing.sarif"
        destination.write_text("previous report")
        result = subprocess.run(
            [sys.executable, str(THIS.parent / "src" / "convert.py"), "-o", str(destination)],
            input=json.dumps(finding),
            text=True,
            capture_output=True,
        )
        assert result.returncode == 2
        assert result.stdout == ""
        assert "invalid input" in result.stderr
        assert "PRIVATE_TEST_VALUE" not in result.stderr
        assert "Traceback" not in result.stderr
        assert destination.read_text() == "previous report"

    def test_input_and_output_can_be_same_file(self, tmp_path):
        path = tmp_path / "report.jsonl"
        path.write_text(json.dumps(_detection_finding()) + "\n")
        result = subprocess.run(
            [sys.executable, str(THIS.parent / "src" / "convert.py"), str(path), "-o", str(path)],
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0
        assert len(json.loads(path.read_text())["runs"][0]["results"]) == 1

    def test_blank_input_is_valid_empty_report(self):
        result = subprocess.run(
            [sys.executable, str(THIS.parent / "src" / "convert.py")],
            input="\n",
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0
        assert json.loads(result.stdout)["runs"][0]["results"] == []


# ── Golden fixture parity ────────────────────────────────────────────


class TestGoldenFixture:
    def test_k8s_priv_esc_to_sarif_matches_frozen(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        produced = convert(findings)
        expected = json.loads(EXPECTED.read_text())
        assert produced == expected, (
            "SARIF golden drift — re-generate via:\n  python src/convert.py ../golden/k8s_priv_esc_findings.ocsf.jsonl > ../golden/k8s_priv_esc_findings.sarif"
        )

    def test_three_findings_three_rules(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        doc = convert(findings)
        assert len(doc["runs"][0]["results"]) == 3
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert rule_ids == {"T1552", "T1611", "T1098"}

    def test_all_results_are_error_level(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        doc = convert(findings)
        for r in doc["runs"][0]["results"]:
            assert r["level"] == "error"

    def test_sarif_declares_schema_and_version(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        doc = convert(findings)
        assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
        assert doc["version"] == "2.1.0"
