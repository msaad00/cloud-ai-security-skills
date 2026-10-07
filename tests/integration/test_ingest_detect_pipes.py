"""Golden ingest→detect pipe tests.

The pipe list lives in ``golden_pipes.json`` (also read by
``scripts/validate_golden_pipes.py``) so the two cannot drift.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipe_harness import (  # noqa: E402
    GOLDEN_DIR,
    IngestDetectPipe,
    load_jsonl,
    load_registry,
    run_ingest_detect_pipe,
)

INGEST_DETECT_PIPES = load_registry()


@pytest.mark.parametrize("pipe", INGEST_DETECT_PIPES, ids=lambda p: p.name)
class TestIngestDetectGoldenPipes:
    def test_raw_to_findings_matches_frozen_golden(self, pipe: IngestDetectPipe):
        ocsf_events, findings = run_ingest_detect_pipe(pipe)
        expected = load_jsonl(GOLDEN_DIR / pipe.expected_fixture)

        if pipe.expected_ocsf_count is not None:
            assert len(ocsf_events) == pipe.expected_ocsf_count

        if pipe.expected_finding_count is not None:
            assert len(findings) == pipe.expected_finding_count == len(expected), (
                f"{pipe.name}: finding count drift (produced {len(findings)}, "
                f"expected {len(expected)})"
            )

        for produced, expected_f in zip(findings, expected):
            assert produced == expected_f, (
                f"{pipe.name}: wire-contract drift between {pipe.ingest_skill} and "
                f"{pipe.detect_skill}.\n"
                f"  produced: {json.dumps(produced, sort_keys=True)}\n"
                f"  expected: {json.dumps(expected_f, sort_keys=True)}"
            )

    def test_findings_use_detection_finding_class_uid(self, pipe: IngestDetectPipe):
        _, findings = run_ingest_detect_pipe(pipe)
        for finding in findings:
            assert finding["class_uid"] == 2004
            assert finding["metadata"]["version"] == "1.8.0"
            assert "attacks" not in finding
            assert "attacks" in finding["finding_info"]


class TestPipeRegistry:
    def test_pipe_names_are_unique(self):
        names = [pipe.name for pipe in INGEST_DETECT_PIPES]
        assert len(names) == len(set(names))

    def test_unknown_registry_keys_fail_closed(self, tmp_path: Path):
        bad = tmp_path / "pipes.json"
        bad.write_text(
            json.dumps(
                {
                    "pipes": [
                        {
                            "name": "x",
                            "ingest_skill": "i",
                            "detect_skill": "d",
                            "raw_fixture": "r",
                            "expected_fixture": "e",
                            "expected_finding_cuont": 1,
                        }
                    ]
                }
            )
        )
        with pytest.raises(ValueError, match="unknown pipe keys"):
            load_registry(bad)
