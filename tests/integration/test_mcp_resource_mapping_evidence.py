"""Resource thresholds retain evidence without asserting an adversary technique."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CASES = [
    ("detect-mcp-model-token-flood", "mcp_token_flood", "total_tokens", 240000),
    ("detect-mcp-unbounded-tool-output", "mcp_unbounded_tool_output", "breach_count", 5),
]


def run(script: Path, payload: str, *args: str) -> str:
    result = subprocess.run(
        [sys.executable, str(script), *args],
        input=payload,
        text=True,
        capture_output=True,
        check=True,
        timeout=15,
    )
    return result.stdout


@pytest.mark.parametrize("skill,fixture,metric,value", CASES)
@pytest.mark.parametrize("output_format", ["ocsf", "native"])
def test_threshold_crossing_does_not_assert_cost_harvesting(
    skill, fixture, metric, value, output_format
):
    bundle = ROOT / "skills/detection" / skill
    payload = (bundle / "tests/golden" / f"{fixture}_input.ocsf.jsonl").read_text()
    result = run(bundle / "src/detect.py", payload, "--output-format", output_format)
    finding = json.loads(result)
    if output_format == "ocsf":
        assert finding["finding_info"]["attacks"] == []
        assert finding["evidence"][metric] == value
        description = finding["finding_info"]["desc"]
        old = json.loads((bundle / "tests/golden" / f"{fixture}_findings.ocsf.jsonl").read_text())
        assert finding["finding_info"]["uid"] == old["finding_info"]["uid"]
        assert finding["evidence"] == old["evidence"]
        assert finding["observables"] == old["observables"]
    else:
        assert finding["mitre_attacks"] == []
        assert finding[metric] == value
        description = finding["description"]
    assert "LLM10:2025" in description
    assert "does not establish" in description
    assert "AML.T0034" not in result
    assert "LLM04" not in result


@pytest.mark.parametrize("skill,fixture,metric,value", CASES)
def test_sarif_retains_unmapped_resource_finding(skill, fixture, metric, value):
    bundle = ROOT / "skills/detection" / skill
    payload = (bundle / "tests/golden" / f"{fixture}_input.ocsf.jsonl").read_text()
    findings = run(bundle / "src/detect.py", payload)
    sarif = json.loads(run(ROOT / "skills/view/convert-ocsf-to-sarif/src/convert.py", findings))
    result = sarif["runs"][0]["results"]
    assert len(result) == 1
    assert "AML." not in json.dumps(sarif)
    assert "LLM10:2025" in result[0]["message"]["text"]


def test_registry_does_not_claim_atlas_for_resource_thresholds():
    registry = json.loads((ROOT / "docs/framework-coverage.json").read_text())
    skills = {row["path"]: row for row in registry["skills"]}
    for skill, *_ in CASES:
        assert "mitre-atlas" not in skills[f"skills/detection/{skill}"]["frameworks"]
