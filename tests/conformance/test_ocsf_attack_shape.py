"""Conformance: every Detection Finding carries MITRE in the OCSF 1.8 attack shape.

skills/detection-engineering/OCSF_CONTRACT.md pins `finding_info.attacks[]`
entries to nested `technique: {uid, name}` / `tactic: {uid, name}` /
`sub_technique: {uid, name}` objects. Downstream consumers (SARIF, Mermaid,
SIEM pivots) read `technique.uid`, so a flat `technique_uid` key silently
drops the MITRE mapping.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_DIR = REPO_ROOT / "skills" / "detection-engineering" / "golden"
DETECT_SOURCES = sorted((REPO_ROOT / "skills" / "detection").glob("*/src/detect.py"))

TECHNIQUE_UID = re.compile(r"^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$")
TACTIC_UID = re.compile(r"^(TA\d{4}|AML\.TA\d{4})$")
FLAT_KEYS = {
    "technique_uid",
    "technique_name",
    "tactic_uid",
    "tactic_name",
    "sub_technique_uid",
    "sub_technique_name",
}


def _detect_golden_findings() -> list[tuple[str, int, dict]]:
    findings = []
    for path in sorted(GOLDEN_DIR.glob("*.jsonl")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            feature = (
                event.get("metadata", {}).get("product", {}).get("feature", {}).get("name", "")
            )
            if event.get("class_uid") == 2004 and feature.startswith("detect-"):
                findings.append((path.name, lineno, event))
    return findings


GOLDEN_FINDINGS = _detect_golden_findings()


def attack_shape_errors(attack: object) -> list[str]:
    if not isinstance(attack, dict):
        return ["attack entry is not an object"]
    errors = [f"flat key `{key}`" for key in sorted(FLAT_KEYS & attack.keys())]
    technique = attack.get("technique")
    if not isinstance(technique, dict) or not TECHNIQUE_UID.match(str(technique.get("uid", ""))):
        errors.append(f"technique.uid invalid: {technique!r}")
    tactic = attack.get("tactic")
    if tactic is not None and (
        not isinstance(tactic, dict) or not TACTIC_UID.match(str(tactic.get("uid", "")))
    ):
        errors.append(f"tactic.uid invalid: {tactic!r}")
    sub = attack.get("sub_technique")
    if sub is not None and (
        not isinstance(sub, dict) or not TECHNIQUE_UID.match(str(sub.get("uid", "")))
    ):
        errors.append(f"sub_technique.uid invalid: {sub!r}")
    return errors


def test_golden_corpus_has_detect_findings() -> None:
    assert len(GOLDEN_FINDINGS) > 50


@pytest.mark.parametrize(
    ("name", "lineno", "finding"),
    GOLDEN_FINDINGS,
    ids=[f"{name}:{lineno}" for name, lineno, _ in GOLDEN_FINDINGS],
)
def test_golden_detect_finding_attacks_use_contract_shape(
    name: str, lineno: int, finding: dict
) -> None:
    attacks = finding["finding_info"].get("attacks")
    assert attacks, f"{name}:{lineno} has no finding_info.attacks"
    for attack in attacks:
        assert attack_shape_errors(attack) == [], f"{name}:{lineno}"


@pytest.mark.parametrize(
    "attack",
    [
        {"technique_uid": "T1098", "tactic_uid": "TA0003"},
        {"technique": {"uid": "", "name": "Unknown"}},
        {"technique": {"uid": "T1098"}, "tactic": {"uid": "Persistence"}},
        {"technique": {"uid": "T1098"}, "sub_technique": {"uid": "1098.001"}},
    ],
)
def test_attack_shape_check_rejects_drift(attack: dict) -> None:
    assert attack_shape_errors(attack)


def test_attack_shape_check_accepts_contract_example() -> None:
    attack = {
        "version": "v14",
        "tactic": {"name": "Persistence", "uid": "TA0003"},
        "technique": {"name": "Account Manipulation", "uid": "T1098"},
        "sub_technique": {"name": "Additional Cloud Credentials", "uid": "T1098.001"},
    }
    assert attack_shape_errors(attack) == []
    assert attack_shape_errors({"technique": {"uid": "AML.T0024.002"}}) == []


def _attacks_values(tree: ast.AST) -> list[ast.expr]:
    values = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "attacks":
                    values.append(value)
    return values


@pytest.mark.parametrize("source", DETECT_SOURCES, ids=[p.parts[-3] for p in DETECT_SOURCES])
def test_detector_source_never_emits_flat_attacks(source: Path) -> None:
    """Covers detectors whose OCSF output has no frozen golden fixture."""
    for value in _attacks_values(ast.parse(source.read_text(encoding="utf-8"))):
        assert not isinstance(value, (ast.Subscript, ast.Name)), (
            f"{source}:{value.lineno} passes a native attack list straight into OCSF"
        )
        literal_keys = {
            key.value
            for node in ast.walk(value)
            if isinstance(node, ast.Dict)
            for key in node.keys
            if isinstance(key, ast.Constant)
        }
        assert not (FLAT_KEYS & literal_keys), f"{source}:{value.lineno} uses flat attack keys"


def test_readme_demo_pipe_yields_real_technique_rule_id() -> None:
    def run(script: str, stdin: str | None, *args: str) -> str:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / script), *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO_ROOT,
        )
        return result.stdout

    ocsf = run(
        "skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py",
        None,
        str(GOLDEN_DIR / "cloudtrail_raw_sample.jsonl"),
    )
    findings = run("skills/detection/detect-aws-access-key-creation/src/detect.py", ocsf)
    sarif = json.loads(run("skills/view/convert-ocsf-to-sarif/src/convert.py", findings))

    results = sarif["runs"][0]["results"]
    assert results
    assert {r["ruleId"] for r in results} == {"T1098"}
    tags = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "mitre/attack/sub-technique/T1098.001" in tags
