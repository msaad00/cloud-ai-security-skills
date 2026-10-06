"""Dense-input parity and scaling tests for detect-privilege-escalation-k8s.

The parity digest was captured from the detector before the linear-time
rewrite, so any change in findings or their serialized bytes fails here.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import detect  # type: ignore[import-not-found]  # noqa: E402

BASE_MS = 1775797200000
PARITY_EVENTS = 3000
PARITY_FINDINGS = 188
PARITY_SHA256 = "050bea5c23e4d7e7935d67473392e0a896328d5863f3a6eb52f194203d00a91e"


def _event(i: int, actor: str, operation: str, rtype: str, name: str, ns: str, sub: str = ""):
    resource = {"type": rtype, "name": name, "namespace": ns}
    if sub:
        resource["subresource"] = sub
    return {
        "class_uid": 6003,
        "time": BASE_MS + i * 150,
        "metadata": {"uid": f"k-{i}"},
        "actor": {"user": {"name": actor, "type": "ServiceAccount", "groups": []}},
        "api": {"operation": operation},
        "resources": [resource],
        "cloud": {"provider": "Kubernetes"},
    }


def dense_events(n: int) -> list[dict]:
    """Few service accounts hammering list/get secrets in a handful of namespaces."""
    events = []
    for i in range(n):
        pair = (i // 2) % 3
        actor = f"system:serviceaccount:ns{pair % 2}:sa{pair}"
        ns = f"ns{pair % 2}"
        if i % 97 == 0:
            events.append(_event(i, actor, "create", "pods", f"pod-{i % 11}", ns, "exec"))
        elif i % 89 == 0:
            events.append(_event(i, actor, "create", "rolebindings", f"rb-{i % 13}", ns))
        elif i % 83 == 0:
            events.append(_event(i, actor, "create", "serviceaccounts", f"sa-{i % 7}", ns, "token"))
        elif i % 2 == 0:
            events.append(_event(i, actor, "list", "secrets", "", ns))
        else:
            events.append(_event(i, actor, "get", "secrets", f"secret-{i % 41}", ns))
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


def test_dense_output_matches_pre_rewrite_digest():
    lines = _serialize(detect(dense_events(PARITY_EVENTS)))
    digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    assert (len(lines), digest) == (PARITY_FINDINGS, PARITY_SHA256)


def test_dense_input_scales_near_linearly():
    _best_time(1000)  # warm-up
    small = _best_time(5000)
    large = _best_time(20000)
    # 4x the events; quadratic behaviour shows up as ~16x. Bound is generous for CI noise.
    assert large / small <= 8, f"5k={small:.3f}s 20k={large:.3f}s"


def test_rule1_window_edges_match_original_semantics():
    actor = "system:serviceaccount:ns0:sa0"

    def at(ms: int, operation: str, name: str = "") -> dict:
        event = _event(0, actor, operation, "secrets", name, "ns0")
        event["time"] = BASE_MS + ms
        return event

    from detect import RULE1_WINDOW_MS  # type: ignore[import-not-found]

    exactly_window = [at(0, "list"), at(RULE1_WINDOW_MS, "get", "s1")]
    just_outside = [at(0, "list"), at(RULE1_WINDOW_MS + 1, "get", "s2")]
    same_instant = [at(0, "list"), at(0, "get", "s3")]
    assert len(list(detect(exactly_window))) == 1
    assert list(detect(just_outside)) == []
    assert list(detect(same_instant)) == []
