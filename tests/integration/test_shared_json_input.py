"""Tests for `skills/_shared/json_input.py`."""

from __future__ import annotations

import importlib.util
import itertools
import json
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MOD_PATH = REPO_ROOT / "skills" / "_shared" / "json_input.py"
spec = importlib.util.spec_from_file_location("cs_json_input_test", MOD_PATH)
assert spec and spec.loader
JI = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = JI
spec.loader.exec_module(JI)


def _legacy(stream: Iterable[str]) -> tuple[Any, list[str]]:
    """The whole-buffer decision every ingester used before the shared helper."""
    buf = list(stream)
    full = "\n".join(line.rstrip("\n") for line in buf).strip()
    if not full:
        return None, []
    try:
        return json.loads(full), buf
    except json.JSONDecodeError:
        return None, buf


CORPUS: list[list[str]] = [
    [],
    [""],
    ["\n", "  \n", "\t\n"],
    ['{"a": 1}\n'],
    ['{"a": 1}'],
    ["\n", '{"a": 1}\n', "\n", "   \n"],
    ['{"a": 1}\n', '{"b": 2}\n'],
    ['{"a": 1}', '{"b": 2}'],
    ["\n", '{"a": 1}\n', "\n", '{"b": 2}\n', "garbage\n"],
    ["{\n", '  "Records": [\n', '    {"x": 1}\n', "  ]\n", "}\n"],
    ["[\n", '{"x": 1},\n', '{"x": 2}\n', "]\n"],
    ['[{"x": 1}, {"x": 2}]\n'],
    ["not json\n", '{"a": 1}\n'],
    ['{"a": 1\n', '{"b": 2}\n'],
    ["null\n"],
    ["null\n", '{"a": 1}\n'],
    ["5\n"],
    ['"s"\n', '"t"\n'],
    [' {"a": 1} \n', " \n"],
    ['{"a": 1}\r\n', "\r\n"],
    ['{"a": 1}\r\n', '{"b": 2}\r\n'],
    ['{"a": 1} {"b": 2}\n'],
    ['{"a": 1}\n', " \n", '{"b": 2}\n'],
]


@pytest.mark.parametrize("lines", CORPUS)
def test_matches_legacy_whole_buffer_decision(lines: list[str]) -> None:
    expected_doc, expected_lines = _legacy(lines)
    doc, replay = JI.split_json_document(lines)
    assert doc == expected_doc
    assert list(replay) == expected_lines


@pytest.mark.parametrize("lines", CORPUS)
def test_accepts_one_shot_iterators(lines: list[str]) -> None:
    expected_doc, expected_lines = _legacy(lines)
    doc, replay = JI.split_json_document(iter(lines))
    assert doc == expected_doc
    assert list(replay) == expected_lines


def test_jsonl_stream_is_consumed_lazily() -> None:
    consumed = 0

    def source() -> Iterator[str]:
        nonlocal consumed
        for i in range(100_000):
            consumed += 1
            yield json.dumps({"i": i}) + "\n"

    doc, replay = JI.split_json_document(source())
    assert doc is None
    assert consumed <= 2
    first = list(itertools.islice(replay, 3))
    assert [json.loads(line)["i"] for line in first] == [0, 1, 2]
    assert consumed <= 3
    assert sum(1 for _ in replay) == 100_000 - 3
    assert consumed == 100_000


def test_multiline_document_is_buffered_and_parsed() -> None:
    text = json.dumps({"Records": [{"eventID": str(i)} for i in range(3)]}, indent=2)
    doc, replay = JI.split_json_document(io_lines(text))
    assert doc == {"Records": [{"eventID": "0"}, {"eventID": "1"}, {"eventID": "2"}]}
    assert "".join(replay) == text


def io_lines(text: str) -> list[str]:
    return text.splitlines(keepends=True)
