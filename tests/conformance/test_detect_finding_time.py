"""Conformance: a finding's `time` comes from its triggering events, never "now".

When no triggering event carries a usable time the detector skips the finding
and writes one structured `finding_time_missing` warning (OCSF_CONTRACT.md,
"Event time"). Substituting the wall clock made finding uids and output
differ between replays of the same input.
"""

from __future__ import annotations

import ast
import copy
import json
import time
from pathlib import Path

import pytest

from tests.integration.pipe_harness import (
    DETECTION_DIR,
    _ingest_stream,
    _patched_env,
    load_module,
    load_registry,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DETECT_SOURCES = sorted(DETECTION_DIR.glob("detect-*/src/*.py"))
# No detector has a legitimate wall-clock use today. A future non-output use
# (for example a rate-limit deadline) must be listed here with its reason.
ALLOWED_CLOCK_USES: dict[str, str] = {}

CLOCK_ATTRS = {"now", "utcnow", "today", "time", "time_ns"}
CLOCK_NAMES = {"_now_ms", "now", "utcnow", "time_ns"}


def _ids(paths: list[Path]) -> list[str]:
    return [p.parts[-3] for p in paths]


def test_every_detector_is_covered() -> None:
    assert len(DETECT_SOURCES) >= 70


@pytest.mark.parametrize("source", DETECT_SOURCES, ids=_ids(DETECT_SOURCES))
def test_detector_never_reads_the_wall_clock(source: Path) -> None:
    tree = ast.parse(source.read_text(encoding="utf-8"))
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_now_ms":
            hits.append(f"{node.lineno}: def _now_ms")
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in CLOCK_ATTRS:
            target = ast.unparse(func.value)
            if func.attr != "time" or target == "time":
                hits.append(f"{node.lineno}: {ast.unparse(func)}()")
        elif isinstance(func, ast.Name) and func.id in CLOCK_NAMES:
            hits.append(f"{node.lineno}: {func.id}()")
    rel = str(source.relative_to(REPO_ROOT))
    if rel in ALLOWED_CLOCK_USES:
        return
    assert not hits, f"{rel} reads the wall clock: {hits}"


PIPES = load_registry()


def _events(pipe) -> list[dict]:
    events = _ingest_stream(
        f"_ft_ingest_{pipe.name}",
        pipe.ingest_skill,
        pipe.raw_fixture,
        pipe.raw_json_document,
        pipe.ingest_kwargs,
    )
    for idx, extra in enumerate(pipe.extra_ingest_streams):
        events.extend(
            _ingest_stream(
                f"_ft_ingest_{pipe.name}_extra_{idx}",
                extra.ingest_skill,
                extra.raw_fixture,
                extra.raw_json_document,
            )
        )
    return events


def _detect(pipe, events: list[dict]) -> str:
    detect = load_module(
        f"_ft_detect_{pipe.name}", DETECTION_DIR / pipe.detect_skill / "src" / "detect.py"
    )
    with _patched_env(pipe.detect_env):
        findings = list(detect.detect(copy.deepcopy(events)))
    return "\n".join(json.dumps(f, sort_keys=True) for f in findings)


def _without_time(event: dict) -> dict:
    return {k: v for k, v in event.items() if k not in ("time", "time_ms")}


@pytest.mark.parametrize("pipe", PIPES, ids=[p.name for p in PIPES])
def test_time_less_events_never_produce_a_finding(pipe, monkeypatch, capsys) -> None:
    monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
    events = _events(pipe)
    assert _detect(pipe, events), "pipe must produce findings before times are removed"
    capsys.readouterr()

    assert _detect(pipe, [_without_time(e) for e in events]) == ""
    for line in capsys.readouterr().err.splitlines():
        payload = json.loads(line)
        assert payload["level"] == "warning", payload


@pytest.mark.parametrize("pipe", PIPES, ids=[p.name for p in PIPES])
def test_replay_with_a_time_less_event_is_byte_identical(pipe) -> None:
    events = _events(pipe)
    for idx in range(len(events)):
        mixed = [_without_time(e) if i == idx else e for i, e in enumerate(events)]
        first = _detect(pipe, mixed)
        time.sleep(0.002)
        assert _detect(pipe, mixed) == first, f"event {idx} without time"
