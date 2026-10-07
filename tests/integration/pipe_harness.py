"""Shared helpers for ingest→detect golden pipe integration tests."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_ROOT = REPO_ROOT / "skills"
INGESTION_DIR = SKILLS_ROOT / "ingestion"
DETECTION_DIR = SKILLS_ROOT / "detection"
GOLDEN_DIR = SKILLS_ROOT / "detection-engineering" / "golden"
REGISTRY_PATH = Path(__file__).resolve().parent / "golden_pipes.json"


@dataclass(frozen=True)
class ExtraIngestStream:
    """Additional ingest stream concatenated before detection."""

    ingest_skill: str
    raw_fixture: str
    raw_json_document: bool = False


@dataclass(frozen=True)
class IngestDetectPipe:
    """One frozen raw→ingest→detect→findings pipe."""

    name: str
    ingest_skill: str
    detect_skill: str
    raw_fixture: str
    expected_fixture: str
    raw_json_document: bool = False
    extra_ingest_streams: tuple[ExtraIngestStream, ...] = ()
    expected_ocsf_count: int | None = None
    expected_finding_count: int | None = None
    ingest_kwargs: dict[str, Any] = field(default_factory=dict)
    detect_env: dict[str, str] = field(default_factory=dict)


_PIPE_KEYS = {f.name for f in fields(IngestDetectPipe)} - {"extra_ingest_streams"}
_EXTRA_KEYS = {f.name for f in fields(ExtraIngestStream)}


def load_registry(path: Path = REGISTRY_PATH) -> tuple[IngestDetectPipe, ...]:
    """Parse golden_pipes.json — the single source of truth for pipe tests."""
    pipes: list[IngestDetectPipe] = []
    for entry in json.loads(path.read_text(encoding="utf-8"))["pipes"]:
        entry = dict(entry)
        extras = entry.pop("extra_raw_fixtures", [])
        unknown = set(entry) - _PIPE_KEYS
        if unknown:
            raise ValueError(f"{entry.get('name')}: unknown pipe keys {sorted(unknown)}")
        for extra in extras:
            if set(extra) - _EXTRA_KEYS:
                raise ValueError(f"{entry['name']}: unknown extra keys {sorted(extra)}")
        pipes.append(
            IngestDetectPipe(
                **entry,
                extra_ingest_streams=tuple(ExtraIngestStream(**extra) for extra in extras),
            )
        )
    return tuple(pipes)


@contextmanager
def _patched_env(overrides: dict[str, str]) -> Iterator[None]:
    saved = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"could not spec {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _ingest_stream(
    module_name: str,
    ingest_skill: str,
    raw_fixture: str,
    raw_json_document: bool,
    ingest_kwargs: dict[str, Any] | None = None,
) -> list[dict]:
    ingest = load_module(
        module_name,
        INGESTION_DIR / ingest_skill / "src" / "ingest.py",
    )
    raw_path = GOLDEN_DIR / raw_fixture
    raw_text = raw_path.read_text(encoding="utf-8")
    raw_stream = [raw_text] if raw_json_document else raw_text.splitlines()
    return list(ingest.ingest(raw_stream, **(ingest_kwargs or {})))


def run_ingest_detect_pipe(pipe: IngestDetectPipe) -> tuple[list[dict], list[dict]]:
    detect = load_module(
        f"_pipe_detect_{pipe.name}",
        DETECTION_DIR / pipe.detect_skill / "src" / "detect.py",
    )
    ocsf_events = _ingest_stream(
        f"_pipe_ingest_{pipe.name}",
        pipe.ingest_skill,
        pipe.raw_fixture,
        pipe.raw_json_document,
        pipe.ingest_kwargs,
    )
    for idx, extra in enumerate(pipe.extra_ingest_streams):
        ocsf_events.extend(
            _ingest_stream(
                f"_pipe_ingest_{pipe.name}_extra_{idx}",
                extra.ingest_skill,
                extra.raw_fixture,
                extra.raw_json_document,
            )
        )
    with _patched_env(pipe.detect_env):
        findings = list(detect.detect(ocsf_events))
    return ocsf_events, findings
