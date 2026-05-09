"""Tests for `scripts/coverage_summary.py`.

The script is a deterministic generator: same `framework-coverage.json`
should always produce the same `COVERAGE_SNAPSHOT.md`. The CI gate
(`--check`) refuses any PR where the doc has drifted from the JSON.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "coverage_summary.py"
spec = importlib.util.spec_from_file_location(
    "cloud_security_coverage_summary_test", SCRIPT
)
assert spec and spec.loader
COV = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = COV
spec.loader.exec_module(COV)


def test_check_mode_passes_on_real_repo():
    """Regression: the on-disk snapshot must match what the script
    regenerates from `framework-coverage.json`. If this fails, run
    `python scripts/coverage_summary.py --write` and commit."""
    assert COV.main(["--check"]) == 0


def test_render_includes_total_count():
    skills = COV._load()
    rendered = COV.render(skills)
    assert f"**Total shipped skills:** {len(skills)}" in rendered


def test_render_lists_every_provider_in_input():
    skills = COV._load()
    rendered = COV.render(skills)
    providers = set()
    for s in skills:
        providers.update(s.get("providers", []))
    for key in providers:
        label = COV.PROVIDER_LABEL.get(key, key)
        assert label in rendered, f"provider `{key}` ({label}) missing from snapshot"


def test_render_lists_every_framework_in_input():
    skills = COV._load()
    rendered = COV.render(skills)
    frameworks = set()
    for s in skills:
        frameworks.update(s.get("frameworks", []))
    for key in frameworks:
        label = COV.FRAMEWORK_LABEL.get(key, key)
        assert label in rendered, f"framework `{key}` ({label}) missing from snapshot"


def test_render_is_deterministic():
    skills = COV._load()
    a = COV.render(skills)
    b = COV.render(skills)
    assert a == b


def test_check_fails_when_snapshot_is_stale(tmp_path, monkeypatch):
    """Simulate drift by pointing the script at a tmpdir snapshot
    that doesn't match what the script would regenerate."""
    fake_snapshot = tmp_path / "stale.md"
    fake_snapshot.write_text("# Coverage Snapshot\n\nstale content\n", encoding="utf-8")
    monkeypatch.setattr(COV, "SNAPSHOT_MD", fake_snapshot)
    assert COV.main(["--check"]) == 1


def test_check_fails_when_snapshot_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(COV, "SNAPSHOT_MD", tmp_path / "does-not-exist.md")
    assert COV.main(["--check"]) == 1


def test_write_mode_creates_snapshot(tmp_path, monkeypatch):
    target = tmp_path / "out.md"
    monkeypatch.setattr(COV, "SNAPSHOT_MD", target)
    assert COV.main(["--write"]) == 0
    assert target.is_file()
    body = target.read_text(encoding="utf-8")
    assert body.startswith("# Coverage Snapshot")
    # Idempotency: --check on the just-written file must pass.
    assert COV.main(["--check"]) == 0


def test_synthetic_skills_render_known_buckets(tmp_path, monkeypatch):
    """Feed a hand-built `framework-coverage.json` so the test does not
    depend on the live repo state. Confirms the bucketing logic."""
    synthetic = tmp_path / "framework-coverage.json"
    synthetic.write_text(
        json.dumps(
            {
                "skills": [
                    {
                        "path": "skills/x/y",
                        "layer": "detection",
                        "providers": ["aws"],
                        "frameworks": ["mitre-attack-v14", "cis-aws-v3"],
                    },
                    {
                        "path": "skills/x/z",
                        "layer": "ingestion",
                        "providers": ["aws", "gcp"],
                        "frameworks": ["ocsf-1.8"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(COV, "COVERAGE_JSON", synthetic)
    skills = COV._load()
    assert len(skills) == 2
    rendered = COV.render(skills)
    assert "AWS | 2 | 100.0%" in rendered  # both skills target AWS
    assert "GCP | 1 | 50.0%" in rendered
    assert "Kubernetes" not in rendered  # not in the input
    assert "**Total shipped skills:** 2" in rendered
