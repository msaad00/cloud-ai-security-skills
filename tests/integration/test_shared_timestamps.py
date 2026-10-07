"""Tests for `skills/_shared/timestamps.py`."""

from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TS_PATH = REPO_ROOT / "skills" / "_shared" / "timestamps.py"
spec = importlib.util.spec_from_file_location("cs_timestamps_test", TS_PATH)
assert spec and spec.loader
TS = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = TS
spec.loader.exec_module(TS)

BASE_MS = 1775797200000  # 2026-04-10T05:00:00Z


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-04-10T05:00:00Z", BASE_MS),
        ("2026-04-10T05:00:00z", BASE_MS),
        ("  2026-04-10T05:00:00Z  ", BASE_MS),
        ("2026-04-10T05:00:00.123Z", BASE_MS + 123),
        ("2026-04-10T05:00:00.123456Z", BASE_MS + 123),
        ("2026-04-10T05:00:00.123456789Z", BASE_MS + 123),
        ("2026-04-10T05:00:00.1234567+00:00", BASE_MS + 123),
        ("2026-04-10T05:00:00+02:00", BASE_MS - 2 * 3600 * 1000),
        ("2026-04-10T05:00:00-0500", BASE_MS + 5 * 3600 * 1000),
        ("2026-04-10T05:00:00+0000", BASE_MS),
        ("2026-04-10T05:00:00", BASE_MS),
        ("2026-04-10 05:00:00", BASE_MS),
        ("2026-04-10 05:00:00.999", BASE_MS + 999),
        ("2026-04-10", BASE_MS - 5 * 3600 * 1000),
        ("20260410 050000", BASE_MS),
        ("20260410050000", BASE_MS),
        ("20260410", BASE_MS - 5 * 3600 * 1000),
        ("10.04.2026 05:00:00", BASE_MS),
        (1775797200, BASE_MS),
        (1775797200.5, BASE_MS + 500),
        (1775797200.123, BASE_MS + 123),
        (BASE_MS, BASE_MS),
        (BASE_MS * 1000, BASE_MS),
        (BASE_MS * 1000 + 999, BASE_MS),
        (BASE_MS * 1_000_000, BASE_MS),
        ("1775797200", BASE_MS),
        ("1775797200.123", BASE_MS + 123),
        (str(BASE_MS), BASE_MS),
        (str(BASE_MS * 1000), BASE_MS),
        (str(BASE_MS * 1_000_000), BASE_MS),
        ("17757972000000", 17757972000000),
    ],
)
def test_parse_ts_ms_accepts_supported_shapes(value, expected):
    assert TS.parse_ts_ms(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "garbage",
        "2026-13-40T99:00:00Z",
        "not-a-date 12:00",
        "-1775797200",
        "1e9",
        True,
        False,
        0,
        -1,
        -1775797200,
        math.nan,
        math.inf,
        -math.inf,
        {},
        [],
        {"time": BASE_MS},
        b"2026-04-10T05:00:00Z",
    ],
)
def test_parse_ts_ms_returns_none_for_missing_or_unparseable(value):
    assert TS.parse_ts_ms(value) is None


def test_parse_ts_ms_is_deterministic_never_now():
    assert TS.parse_ts_ms("garbage") is None
    assert TS.parse_ts_ms("2026-04-10T05:00:00Z") == TS.parse_ts_ms("2026-04-10T05:00:00Z")


def test_require_ts_ms_raises_typed_error():
    assert TS.require_ts_ms("2026-04-10T05:00:00Z") == BASE_MS
    with pytest.raises(TS.TimestampUnparseable):
        TS.require_ts_ms(None)
    with pytest.raises(ValueError):
        TS.require_ts_ms("garbage")


def test_emit_timestamp_unparseable_is_structured_and_payload_free(monkeypatch, capsys):
    monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
    TS.emit_timestamp_unparseable("ingest-x", record=7)
    payload = json.loads(capsys.readouterr().err)
    assert payload["skill"] == "ingest-x"
    assert payload["level"] == "warning"
    assert payload["event"] == "timestamp_unparseable"
    assert payload["record"] == 7
    assert "7" in payload["message"]
    assert set(payload) == {"timestamp", "skill", "level", "event", "message", "record"}


def test_emit_timestamp_unparseable_adds_line_when_known(monkeypatch, capsys):
    monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
    TS.emit_timestamp_unparseable("ingest-x", record=3, line=4)
    payload = json.loads(capsys.readouterr().err)
    assert (payload["record"], payload["line"]) == (3, 4)


def test_emit_timestamp_unparseable_plain_text(monkeypatch, capsys):
    monkeypatch.delenv("SKILL_LOG_FORMAT", raising=False)
    monkeypatch.delenv("AGENT_TELEMETRY", raising=False)
    TS.emit_timestamp_unparseable("ingest-x", record=2)
    assert capsys.readouterr().err == (
        "[ingest-x] skipping record 2: missing or unparseable source timestamp\n"
    )
