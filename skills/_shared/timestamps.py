"""Source-timestamp parsing shared by every ingest skill.

`parse_ts_ms` turns a vendor timestamp into Unix epoch milliseconds (UTC) or
returns None. It never substitutes the current time: a fabricated "now" makes
finding uids non-deterministic across replays and fakes event times inside
windowed detectors. Callers skip the record instead (see
skills/detection-engineering/OCSF_CONTRACT.md, "Event time").
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from skills._shared.runtime_telemetry import emit_stderr_event

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_MS = timedelta(milliseconds=1)
# datetime.max at millisecond precision; anything later cannot be rendered by
# datetime.fromtimestamp downstream and is never a real event time.
MAX_TS_MS = (datetime.max.replace(tzinfo=timezone.utc) - _EPOCH) // _ONE_MS
_NUMERIC = re.compile(r"^\d+(\.\d+)?([eE][+-]?\d+)?$", re.ASCII)
# Smallest numeric epoch accepted: 1e8 seconds is 1973-03-03T09:46:40Z, and so
# is the 1e11 seconds/milliseconds cut-off below. Smaller numbers (a year, a
# counter) are never treated as an epoch time.
_MIN_EPOCH = Decimal("1e8")
# A leap second (hh:mm:60) clamps to the last millisecond of that minute.
_LEAP_SECOND = re.compile(r"(?<=[T ])([01]\d|2[0-3]):([0-5]\d):60(?:[.,]\d+)?", re.ASCII)
# Legacy non-ISO layouts seen in SAP audit exports (DATUM/UZEIT, dd.mm.yyyy).
_EXTRA_FORMATS = ("%Y%m%d %H%M%S", "%d.%m.%Y %H:%M:%S")
_COMPACT_FORMATS = {8: "%Y%m%d", 14: "%Y%m%d%H%M%S"}


class TimestampUnparseable(ValueError):
    """Raised by `require_ts_ms` when a record has no usable source timestamp."""


def _epoch_to_ms(number: Decimal) -> int | None:
    if not number.is_finite() or number < _MIN_EPOCH:
        return None
    if number < Decimal("1e11"):
        scaled = number * 1000
    elif number < Decimal("1e14"):
        scaled = number
    elif number < Decimal("1e17"):
        scaled = number / 1000
    else:
        scaled = number / 1_000_000
    return int(scaled)


def _datetime_to_ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - _EPOCH) // _ONE_MS


def _parse_text(text: str) -> int | None:
    if not text.isascii():
        return None
    compact_format = _COMPACT_FORMATS.get(len(text)) if text.isdigit() else None
    if compact_format:
        try:
            return _datetime_to_ms(datetime.strptime(text, compact_format))
        except ValueError:
            pass
    if _NUMERIC.match(text):
        return _epoch_to_ms(Decimal(text))
    if text.endswith("z"):
        text = text[:-1] + "Z"
    try:
        return _datetime_to_ms(datetime.fromisoformat(text))
    except ValueError:
        pass
    leap_clamped = _LEAP_SECOND.sub(r"\1:\2:59.999", text, count=1)
    if leap_clamped != text:
        try:
            return _datetime_to_ms(datetime.fromisoformat(leap_clamped))
        except ValueError:
            pass
    for fmt in _EXTRA_FORMATS:
        try:
            return _datetime_to_ms(datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def parse_ts_ms(value: Any) -> int | None:
    """Return epoch milliseconds for an ISO-8601 / epoch timestamp, else None.

    Accepts ISO-8601 strings (`Z`, numeric offsets, any fractional precision;
    naive values are UTC; a leap second `:60` clamps to `:59.999`) and epoch
    numbers or numeric strings (plain, decimal, or exponent form) of at least
    1e8 whose unit (s / ms / us / ns) is inferred from magnitude. Missing,
    empty, boolean, non-ASCII, non-finite, unrecognised, smaller-than-1e8
    numeric, at-or-before-1970-01-01T00:00:00Z, and post-year-9999 values
    return None.
    """
    parsed = _parse_any(value)
    if parsed is None or parsed <= 0 or parsed > MAX_TS_MS:
        return None
    return parsed


def _parse_any(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _epoch_to_ms(Decimal(value))
    if isinstance(value, float):
        return _epoch_to_ms(Decimal(repr(value)))
    if isinstance(value, str):
        text = value.strip()
        return _parse_text(text) if text else None
    return None


def require_ts_ms(value: Any) -> int:
    """`parse_ts_ms` for a record's primary event time; raises when unusable."""
    parsed = parse_ts_ms(value)
    if parsed is None:
        raise TimestampUnparseable("missing or unparseable source timestamp")
    return parsed


def emit_timestamp_unparseable(skill_name: str, *, record: int, line: int | None = None) -> None:
    """Structured skip warning. Never includes the raw value or payload.

    `record` is the 1-based position of the raw record in the input stream
    (the line number for line-oriented ingesters, which also pass `line`).
    """
    emit_stderr_event(
        skill_name,
        level="warning",
        event="timestamp_unparseable",
        message=f"skipping record {record}: missing or unparseable source timestamp",
        record=record,
        line=line,
    )


def finding_time_ms(*event_times: Any) -> int | None:
    """A finding's `time`: the first usable epoch-ms among its triggering events.

    Detectors pass already-normalised event times in their preference order
    (for example the last event of a burst). None, booleans, non-numeric,
    non-positive, and post-year-9999 values are skipped. Returns None when no
    candidate is usable; the detector then skips the finding and calls
    `emit_finding_time_missing` instead of substituting the current time.
    """
    for value in event_times:
        if value is None or isinstance(value, bool):
            continue
        try:
            ms = int(value)
        except (TypeError, ValueError, OverflowError):
            continue
        if 0 < ms <= MAX_TS_MS:
            return ms
    return None


def emit_finding_time_missing(skill_name: str) -> None:
    """Structured skip warning for a finding none of whose events has a time."""
    emit_stderr_event(
        skill_name,
        level="warning",
        event="finding_time_missing",
        message="skipping finding: no triggering event has a usable source time",
    )
