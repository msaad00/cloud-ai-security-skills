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
_NUMERIC = re.compile(r"^\d+(\.\d+)?$")
# Legacy non-ISO layouts seen in SAP audit exports (DATUM/UZEIT, dd.mm.yyyy).
_EXTRA_FORMATS = ("%Y%m%d %H%M%S", "%d.%m.%Y %H:%M:%S")
_COMPACT_FORMATS = {8: "%Y%m%d", 14: "%Y%m%d%H%M%S"}


class TimestampUnparseable(ValueError):
    """Raised by `require_ts_ms` when a record has no usable source timestamp."""


def _epoch_to_ms(number: Decimal) -> int | None:
    if not number.is_finite() or number <= 0:
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
    for fmt in _EXTRA_FORMATS:
        try:
            return _datetime_to_ms(datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def parse_ts_ms(value: Any) -> int | None:
    """Return epoch milliseconds for an ISO-8601 / epoch timestamp, else None.

    Accepts ISO-8601 strings (`Z`, numeric offsets, any fractional precision;
    naive values are UTC) and positive epoch numbers or numeric strings whose
    unit (s / ms / us / ns) is inferred from magnitude. Missing, empty,
    boolean, non-positive, non-finite, and unrecognised values return None.
    """
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
