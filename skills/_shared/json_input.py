"""Whole-document vs line-delimited JSON input detection with bounded memory.

Ingest skills accept either one JSON document (a `{"Records": [...]}` digest, a
top-level array, a pretty-printed export) or NDJSON. `split_json_document`
decides which without buffering a JSONL stream: if the first non-blank line is
a complete JSON value, the input is one document only when every later line is
blank; otherwise the stream is replayed line by line as it is read. Only input
whose first line is not a complete value (a multi-line document, or a
malformed first record) is buffered, to attempt the whole-document parse.

A leading UTF-8 byte-order mark is stripped once (stdin and `open(...,
encoding="utf-8")` keep it). When the first line is a JSON array and NDJSON
lines follow, the array's elements are replayed one per line ahead of the
rest, so they reach the ingester like any other NDJSON record instead of
being rejected as a non-object line. Line numbers in later per-line
diagnostics then count the expanded elements.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Iterable, Iterator
from typing import Any


def split_json_document(stream: Iterable[str]) -> tuple[Any, Iterator[str]]:
    """Return `(document, lines)`.

    `document` is the parsed value when the whole input is a single JSON
    document, else None (also None for a literal `null` document or blank
    input). `lines` replays every input line in order for line-by-line
    parsing, and is empty when the input is blank.
    """
    it = _strip_leading_bom(iter(stream))
    head: list[str] = []
    for line in it:
        head.append(line)
        if line.strip():
            break
    else:
        return None, iter(())

    try:
        first = json.loads(head[-1].strip())
    except json.JSONDecodeError:
        buf = head + list(it)
        full = "\n".join(line.rstrip("\n") for line in buf).strip()
        try:
            return json.loads(full), iter(buf)
        except json.JSONDecodeError:
            return None, iter(buf)

    first_index = len(head) - 1
    for line in it:
        head.append(line)
        if line.strip():
            if isinstance(first, list):
                head[first_index : first_index + 1] = [json.dumps(v) + "\n" for v in first]
            return None, itertools.chain(head, it)
    return first, iter(head)


def _strip_leading_bom(lines: Iterator[str]) -> Iterator[str]:
    for line in lines:
        yield line.removeprefix("\ufeff")
        break
    yield from lines
