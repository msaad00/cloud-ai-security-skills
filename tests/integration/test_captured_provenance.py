"""Provenance declarations must fail closed without claiming authenticity."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "captured_provenance_under_test", ROOT / "scripts/validate_captured_provenance.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    captured = tmp_path / "captured"
    captured.mkdir()
    detectors = tmp_path / "detectors"
    skill = detectors / "detect-example"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("test detector contract\n")
    (captured / "sample.ocsf.jsonl").write_text('{"time":1704067200000}\n')
    manifest = captured / "MANIFEST.yaml"
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "CAPTURED_DIR", captured)
    monkeypatch.setattr(MODULE, "DETECTOR_DIR", detectors)
    monkeypatch.setattr(MODULE, "MANIFEST_PATH", manifest)
    entry = {
        "path": "sample.ocsf.jsonl",
        "origin": "https://example.org/revision/123/recorded-events.jsonl",
        "license": "MIT",
        "capture_window_utc": "2024-01-01T00:00:00Z/2024-01-01T00:01:00Z",
        "attack_pattern": "T1098.001",
        "consuming_detector": "detect-example",
        "synthetic_seeded": False,
        "sha256": hashlib.sha256((captured / "sample.ocsf.jsonl").read_bytes()).hexdigest(),
    }
    return captured, manifest, entry


def write_manifest(corpus, entries):
    corpus[1].write_text(yaml.safe_dump({"fixtures": entries}))


def test_valid_declarations_pass_without_authenticity_claim(corpus, capsys):
    write_manifest(corpus, [corpus[2]])
    assert MODULE.main() == 0
    output = capsys.readouterr().out
    assert "declaration" in output.lower()


def test_explicit_empty_corpus_reports_no_capture_evidence(corpus, capsys):
    (corpus[0] / "sample.ocsf.jsonl").unlink()
    write_manifest(corpus, [])
    assert MODULE.main() == 0
    assert "no captured-traffic evidence" in capsys.readouterr().out


@pytest.mark.parametrize(
    "document",
    ["", "[]", "null", "fixtures: null", "fixtures: {}", "fixtures: false", "{}", "fixtures: ["],
)
def test_malformed_manifest_is_an_error(corpus, document, capsys):
    corpus[1].write_text(document)
    assert MODULE.main() == 1
    assert "ERROR" in capsys.readouterr().err


@pytest.mark.parametrize(
    "field",
    [
        "origin",
        "license",
        "capture_window_utc",
        "attack_pattern",
        "consuming_detector",
        "synthetic_seeded",
        "sha256",
    ],
)
def test_null_required_values_are_rejected(corpus, field):
    corpus[2][field] = None
    write_manifest(corpus, [corpus[2]])
    assert MODULE.main() == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("synthetic_seeded", True),
        ("synthetic_seeded", 0),
        ("origin", "https://"),
        ("origin", "CITATION:an attack command"),
        ("license", []),
        ("license", "unknown"),
        ("attack_pattern", ""),
        ("consuming_detector", ""),
        ("consuming_detector", "../detect-example"),
        ("path", "../sample.ocsf.jsonl"),
        ("path", ".hidden.ocsf.jsonl"),
        ("capture_window_utc", "2024-01-01/2024-01-02"),
        ("capture_window_utc", "2024-01-02T00:00:00Z/2024-01-01T00:00:00Z"),
        ("capture_window_utc", "2024-01-01T00:00:00+01:00/2024-01-02T00:00:00+01:00"),
        ("sha256", "0" * 64),
        ("sha256", "not-a-digest"),
    ],
)
def test_invalid_declarations_fail_without_crashing(corpus, field, value):
    corpus[2][field] = value
    write_manifest(corpus, [corpus[2]])
    assert MODULE.main() == 1


def test_duplicate_entries_rejected(corpus):
    write_manifest(corpus, [corpus[2], corpus[2]])
    assert MODULE.main() == 1


def test_changed_fixture_bytes_rejected(corpus):
    write_manifest(corpus, [corpus[2]])
    (corpus[0] / "sample.ocsf.jsonl").write_text("changed bytes\n")
    assert MODULE.main() == 1


def test_unlisted_fixture_rejected(corpus):
    write_manifest(corpus, [])
    assert MODULE.main() == 1


def test_missing_fixture_rejected(corpus):
    write_manifest(corpus, [corpus[2]])
    (corpus[0] / "sample.ocsf.jsonl").unlink()
    assert MODULE.main() == 1


def test_nested_fixture_cannot_evade_inventory(corpus):
    write_manifest(corpus, [corpus[2]])
    nested = corpus[0] / "nested"
    nested.mkdir()
    (nested / "unlisted.jsonl").write_text("{}\n")
    assert MODULE.main() == 1


def test_symlinked_fixture_rejected(corpus, tmp_path):
    write_manifest(corpus, [corpus[2]])
    source = corpus[0] / "sample.ocsf.jsonl"
    outside = tmp_path / "outside.jsonl"
    source.rename(outside)
    source.symlink_to(outside)
    assert MODULE.main() == 1


@pytest.mark.parametrize(
    "scenario,detector,operation",
    [
        (
            "synthetic_aws_create_access_key.ocsf.jsonl",
            "detect-aws-access-key-creation",
            "CreateAccessKey",
        ),
        (
            "synthetic_aws_create_login_profile.ocsf.jsonl",
            "detect-aws-login-profile-creation",
            "CreateLoginProfile",
        ),
    ],
)
def test_reclassified_scenarios_retain_detector_regressions(scenario, detector, operation):
    import json
    import subprocess
    import sys

    event = json.loads((ROOT / "skills/detection-engineering/golden" / scenario).read_text())
    assert "synthetic" in event["metadata"]["labels"]
    assert "captured" not in event["metadata"]["labels"]
    assert event["api"]["operation"] == operation
    entrypoint = ROOT / "skills/detection" / detector / "src/detect.py"
    for status, expected in [(1, 1), (2, 0)]:
        event["status_id"] = status
        result = subprocess.run(
            [sys.executable, str(entrypoint)],
            input=json.dumps(event),
            text=True,
            capture_output=True,
            timeout=15,
            check=True,
        )
        findings = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(findings) == expected
        if findings:
            assert findings[0]["class_uid"] == 2004
            assert findings[0]["metadata"]["product"]["feature"]["name"] == detector
