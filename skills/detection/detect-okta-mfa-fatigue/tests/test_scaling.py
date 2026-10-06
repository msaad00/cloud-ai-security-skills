"""Dense-input parity and scaling tests for detect-okta-mfa-fatigue.

The parity digest was captured from the detector before the deque/counter
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
    for line in (GOLDEN / "okta_mfa_fatigue_input.ocsf.jsonl").read_text().splitlines()
    if line.strip()
]
CHALLENGE = next(e for e in TEMPLATES if e["status_id"] == 1)
DENY = next(e for e in TEMPLATES if e["status_id"] == 2)
BASE_MS = 1775797200000
PARITY_EVENTS = 3000
PARITY_FINDINGS = 84
PARITY_SHA256 = "534debaf34258c17f11d158eecffd100b97f13f66bd2dce0b96bd4c305e52519"


def dense_events(n: int, *, users: int, step_ms: int, gap_every: int = 0) -> list[dict]:
    events = []
    for i in range(n):
        event = copy.deepcopy(DENY if i % 5 == 4 else CHALLENGE)
        user = f"00u-dense-{i % users}"
        event["user"] = {"uid": user, "email_addr": f"{user}@example.com"}
        event["src_endpoint"] = {"ip": f"198.51.100.{(i // 5) % 9}"}
        event["session"] = {"uid": f"sess-{i % 11}"}
        # Every 101st event replays the previous uid to exercise de-duplication.
        event["metadata"]["uid"] = f"m-{i - 1 if i % 101 == 100 else i}"
        # Periodic gaps longer than the window end a burst so it can fire again.
        gaps = i // gap_every if gap_every else 0
        event["time"] = BASE_MS + i * step_ms + gaps * 20 * 60 * 1000
        events.append(event)
    return events


def _serialize(findings) -> list[str]:
    return [json.dumps(f, separators=(",", ":")) for f in findings]


def _best_time(n: int) -> float:
    events = dense_events(n, users=1, step_ms=1)
    best = float("inf")
    for _ in range(2):
        start = time.perf_counter()
        list(detect(events))
        best = min(best, time.perf_counter() - start)
    return best


def test_dense_output_matches_pre_rewrite_digest():
    events = dense_events(PARITY_EVENTS, users=7, step_ms=900, gap_every=250)
    lines = _serialize(detect(events))
    digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    assert (len(lines), digest) == (PARITY_FINDINGS, PARITY_SHA256)


def test_single_user_dense_window_scales_near_linearly():
    _best_time(1000)  # warm-up
    small = _best_time(5000)
    large = _best_time(20000)
    # 4x the events; quadratic behaviour shows up as ~16x. Bound is generous for CI noise.
    assert large / small <= 8, f"5k={small:.3f}s 20k={large:.3f}s"
