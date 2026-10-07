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
MAX_MS = 253402300799999  # 9999-12-31T23:59:59.999Z, datetime.max at ms precision


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
        ("9999-12-31T23:59:59.999Z", MAX_MS),
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
        10**22,
        1e22,
        10**30,
        "10000000000000000000000",
        "1" + "0" * 40,
        "9999-12-31T23:59:59-05:00",
    ],
)
def test_parse_ts_ms_returns_none_for_missing_or_unparseable(value):
    assert TS.parse_ts_ms(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # Exponent strings parse exactly like the equivalent float.
        ("1.7e12", 1_700_000_000_000),
        ("1.7E12", 1_700_000_000_000),
        ("1e9", 1_000_000_000_000),
        ("1.775797200e9", BASE_MS),
        # Leap second clamps to the last representable millisecond of the minute.
        ("2016-12-31T23:59:60Z", 1483228799999),
        ("2016-12-31T23:59:60.5Z", 1483228799999),
        ("2016-12-31 23:59:60", 1483228799999),
        ("2017-01-01T01:59:60+02:00", 1483228799999),
        # Smallest accepted numeric value: 1e8 (1973-03-03T09:46:40Z in seconds).
        ("100000000", 100_000_000_000),
        (100_000_000, 100_000_000_000),
        # ISO dates after the epoch but before the numeric floor stay valid.
        ("1970-01-01T00:00:00.001Z", 1),
    ],
)
def test_parse_ts_ms_edge_cases_accepted(value, expected):
    assert TS.parse_ts_ms(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        # Short numerics (years, counters) are not epoch values.
        "2026",
        2026,
        "99999999",
        99_999_999,
        "1e3",
        12.5,
        # Pre-epoch and epoch-zero times are rejected for ISO and epoch alike.
        "1969-12-31T23:59:59Z",
        "1960-01-01T00:00:00Z",
        "1970-01-01T00:00:00Z",
        "-1.7e12",
        -1_700_000_000_000,
        # Non-ASCII digits are never accepted.
        "\u0661\u0667\u0667\u0665\u0667\u0669\u0667\u0662\u0660\u0660",
        "2026-04-1\u0660T05:00:00Z",
        "\uff11\uff17\uff17\uff15\uff17\uff19\uff17\uff12\uff10\uff10",
        # A minute or hour of 60 is not a leap second.
        "2016-12-31T23:60:00Z",
        "2016-12-31T24:59:60Z",
    ],
)
def test_parse_ts_ms_edge_cases_rejected(value):
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
