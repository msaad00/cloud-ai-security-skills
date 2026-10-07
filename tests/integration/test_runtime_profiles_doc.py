"""Claims rendered by `scripts/build_runtime_profiles_doc.py`."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "build_runtime_profiles_doc_test", ROOT / "scripts" / "build_runtime_profiles_doc.py"
)
assert _spec and _spec.loader
BUILDER = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = BUILDER
_spec.loader.exec_module(BUILDER)


def _record(runner: str, scenario: str, **extra):
    return {
        "runner": runner,
        "scenario": scenario,
        "status": "ok",
        "samples": 2,
        "p50_ms": 1.0,
        "p95_ms": 1.0,
        "mean_ms": 1.0,
        "sink_arrival_count": 1,
        "audit_chain_verified": None,
        "captured_at": "2026-01-01T00:00:00Z",
        **extra,
    }


def test_doc_does_not_claim_real_cloud_deploy_proof():
    doc = BUILDER.render_doc(
        [
            _record("cloud-runner-gcp-gcs-pubsub", "gcs", backend="in_process_fakes"),
            _record("cloud-runner-azure-blob-eventgrid", "blob", backend="in_process_fakes"),
        ]
    )
    assert "Closes" not in doc
    assert "still gap" not in doc
    assert "real-cloud deploy proof is still outstanding" in doc
    assert "in-process fakes" in doc
