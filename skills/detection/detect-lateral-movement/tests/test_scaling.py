"""Dense-input parity and scaling tests for detect-lateral-movement.

The parity digest was captured from the detector before the timeline
rewrite, so any change in findings or their serialized bytes fails here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import detect  # type: ignore[import-not-found]  # noqa: E402

GOLDEN = Path(__file__).resolve().parents[3] / "detection-engineering" / "golden"
TEMPLATES = [
    json.loads(line)
    for line in (GOLDEN / "lateral_movement_input.ocsf.jsonl").read_text().splitlines()
    if line.strip()
]
ANCHOR, FLOW = TEMPLATES[0], TEMPLATES[1]
BASE_MS = ANCHOR["time"]
PARITY_EVENTS = 3000
PARITY_FINDINGS = 840
PARITY_SHA256 = "6a22a4f473f59fe907eb24429f37c73e7aaeaa8f16b55f837ac9c79edda6ddc6"


def _anchor(i: int, time_ms: int, session: str, account: str | None) -> dict:
    event = copy.deepcopy(ANCHOR)
    event["time"] = time_ms
    event["metadata"]["uid"] = f"a-{i}"
    event["actor"]["session"]["uid"] = session
    if account is not None:
        event["cloud"]["account"]["uid"] = account
        event["actor"]["user"]["account"]["uid"] = account
    return event


def _flow(j: int, time_ms: int, ip: str, port: int, account: str | None) -> dict:
    event = copy.deepcopy(FLOW)
    event["time"] = time_ms
    event["metadata"]["uid"] = f"f-{j}"
    event["dst_endpoint"]["ip"] = ip
    event["dst_endpoint"]["port"] = port
    if account is None:
        del event["cloud"]["account"]
    else:
        event["cloud"]["account"]["uid"] = account
    return event


def mixed_events(n: int) -> list[dict]:
    """Several sessions and accounts, flows inside and outside the window."""
    events = []
    for i in range(n // 2):
        account = "222233334444" if i % 3 == 2 else "111122223333"
        events.append(_anchor(i, BASE_MS + i * 7000, f"S{i % 4}", account))
    for j in range(n - n // 2):
        account = None if j % 11 == 10 else ("222233334444" if j % 5 == 4 else "111122223333")
        ip = f"10.0.{j % 30}.{j % 7}"
        events.append(_flow(j, BASE_MS + j * 3000 + 500, ip, (22, 3389, 5432)[j % 3], account))
    return events


def dense_events(n: int) -> list[dict]:
    """One session's anchors followed by n/2 distinct internal destinations."""
    half = n // 2
    events = [_anchor(i, BASE_MS + i * 10, "S0", None) for i in range(half)]
    for j in range(half):
        ip = f"10.{(j >> 16) & 255}.{(j >> 8) & 255}.{j & 255}"
        events.append(_flow(j, BASE_MS + half * 10 + j, ip, 22, "111122223333"))
    return events


def _serialize(findings) -> list[str]:
    return [json.dumps(f, separators=(",", ":")) for f in findings]


def _best_time(n: int) -> float:
    events = dense_events(n)
    best = float("inf")
    for _ in range(2):
        start = time.perf_counter()
        list(detect(events))
        best = min(best, time.perf_counter() - start)
    return best


def test_mixed_output_matches_pre_rewrite_digest():
    lines = _serialize(detect(mixed_events(PARITY_EVENTS)))
    digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    assert (len(lines), digest) == (PARITY_FINDINGS, PARITY_SHA256)


def test_dense_session_scales_near_linearly():
    _best_time(1000)  # warm-up
    small = _best_time(5000)
    large = _best_time(20000)
    # 4x the events; anchors x destinations shows up as ~16x. Bound is generous for CI noise.
    assert large / small <= 8, f"5k={small:.3f}s 20k={large:.3f}s"
