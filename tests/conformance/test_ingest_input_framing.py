"""Conformance: input framing quirks never drop records.

A leading UTF-8 byte-order mark and a JSON array on the first line of an
NDJSON stream are both handled by `skills/_shared/json_input.py`; every
ingester must produce exactly the records it produces for the clean input.
"""

from __future__ import annotations

import json

import pytest

from tests.conformance.test_ingest_timestamps import ALL_SKIP_CASES, _run_ingest, _source_text

BOM = "﻿"
CASES = [(skill, source) for skill, source, _ in ALL_SKIP_CASES]


@pytest.mark.parametrize(("skill", "source"), CASES, ids=[c[0] for c in CASES])
def test_leading_bom_does_not_drop_the_first_record(skill: str, source: str) -> None:
    text = _source_text(source)
    expected = _run_ingest(skill, text)
    assert expected
    assert _run_ingest(skill, BOM + text) == expected


NDJSON_CASES = [
    (skill, source)
    for skill, source in CASES
    if source.endswith(".jsonl") and len(_source_text(source).splitlines()) >= 3
]


@pytest.mark.parametrize(("skill", "source"), NDJSON_CASES, ids=[c[0] for c in NDJSON_CASES])
def test_first_line_array_followed_by_ndjson_keeps_every_record(skill: str, source: str) -> None:
    lines = [line for line in _source_text(source).splitlines() if line.strip()]
    expected = _run_ingest(skill, "\n".join(lines))
    batched = [json.dumps([json.loads(lines[0]), json.loads(lines[1])]), *lines[2:]]
    assert _run_ingest(skill, "\n".join(batched)) == expected
