from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared import http as shared_http  # noqa: E402


class _Recorder:
    """Return a scripted sequence of status codes, recording each call."""

    def __init__(self, statuses, *, headers_by_call=None):
        self._statuses = list(statuses)
        self._headers_by_call = headers_by_call or {}
        self.calls = 0

    def __call__(self, request):
        index = self.calls
        self.calls += 1
        status = self._statuses[min(index, len(self._statuses) - 1)]
        headers = self._headers_by_call.get(index, {})
        return httpx.Response(status, headers=headers, text=f"call-{index}")


# ---- resolve_max_attempts --------------------------------------------------


def test_resolve_max_attempts_default(monkeypatch):
    monkeypatch.delenv(shared_http.MAX_ATTEMPTS_ENV, raising=False)
    assert shared_http.resolve_max_attempts() == 8


def test_resolve_max_attempts_env_override(monkeypatch):
    monkeypatch.setenv(shared_http.MAX_ATTEMPTS_ENV, "3")
    assert shared_http.resolve_max_attempts() == 3


def test_resolve_max_attempts_explicit_wins(monkeypatch):
    monkeypatch.setenv(shared_http.MAX_ATTEMPTS_ENV, "3")
    assert shared_http.resolve_max_attempts(5) == 5


def test_resolve_max_attempts_clamped_to_one(monkeypatch):
    monkeypatch.delenv(shared_http.MAX_ATTEMPTS_ENV, raising=False)
    assert shared_http.resolve_max_attempts(0) == 1


# ---- retry_after_seconds ---------------------------------------------------


def test_retry_after_seconds_integer():
    resp = httpx.Response(429, headers={"Retry-After": "7"})
    assert shared_http.retry_after_seconds(resp) == 7.0


def test_retry_after_seconds_absent():
    assert shared_http.retry_after_seconds(httpx.Response(429)) is None


def test_retry_after_seconds_http_date():
    future = datetime.now(timezone.utc) + timedelta(seconds=120)
    header = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp = httpx.Response(503, headers={"Retry-After": header})
    now = datetime.now(timezone.utc)
    seconds = shared_http.retry_after_seconds(resp, now=now)
    assert seconds is not None
    assert 100 <= seconds <= 121


def test_retry_after_seconds_past_date_is_zero():
    past = datetime.now(timezone.utc) - timedelta(seconds=60)
    header = past.strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp = httpx.Response(503, headers={"Retry-After": header})
    assert shared_http.retry_after_seconds(resp) == 0.0


def test_retry_after_seconds_garbage_is_none():
    resp = httpx.Response(429, headers={"Retry-After": "soon-ish"})
    assert shared_http.retry_after_seconds(resp) is None


# ---- RetryTransport behavior ----------------------------------------------


def _build(recorder, *, sleeps, **kwargs):
    transport = shared_http.retrying_transport(
        httpx.MockTransport(recorder), sleep=sleeps.append, **kwargs
    )
    return httpx.Client(transport=transport)


def test_no_retry_on_success():
    recorder = _Recorder([200])
    sleeps: list[float] = []
    client = _build(recorder, sleeps=sleeps)
    resp = client.get("https://svc.test/x")
    assert resp.status_code == 200
    assert recorder.calls == 1
    assert sleeps == []


def test_retries_then_succeeds():
    recorder = _Recorder([429, 503, 200])
    sleeps: list[float] = []
    client = _build(recorder, sleeps=sleeps, backoff_factor=0.5)
    resp = client.get("https://svc.test/x")
    assert resp.status_code == 200
    assert recorder.calls == 3
    # Two backoffs: 0.5 * 2**0, 0.5 * 2**1
    assert sleeps == [0.5, 1.0]


def test_honors_retry_after_header_over_backoff():
    recorder = _Recorder([429, 200], headers_by_call={0: {"Retry-After": "4"}})
    sleeps: list[float] = []
    client = _build(recorder, sleeps=sleeps, backoff_factor=0.5)
    resp = client.get("https://svc.test/x")
    assert resp.status_code == 200
    assert sleeps == [4.0]


def test_exhausts_attempts_returns_last_response():
    recorder = _Recorder([503, 503, 503, 503])
    sleeps: list[float] = []
    client = _build(recorder, sleeps=sleeps, max_attempts=3)
    resp = client.get("https://svc.test/x")
    assert resp.status_code == 503
    assert recorder.calls == 3  # exactly max_attempts, no more
    assert len(sleeps) == 2  # slept between the 3 attempts


def test_method_not_in_allowlist_is_not_retried():
    recorder = _Recorder([429, 200])
    sleeps: list[float] = []
    client = _build(recorder, sleeps=sleeps, allowed_methods=frozenset({"GET"}))
    resp = client.request("PATCH", "https://svc.test/x")
    assert resp.status_code == 429
    assert recorder.calls == 1
    assert sleeps == []


def test_status_not_in_forcelist_is_not_retried():
    recorder = _Recorder([404, 200])
    sleeps: list[float] = []
    client = _build(recorder, sleeps=sleeps)
    resp = client.get("https://svc.test/x")
    assert resp.status_code == 404
    assert recorder.calls == 1


def test_respect_retry_after_disabled_uses_backoff():
    recorder = _Recorder([429, 200], headers_by_call={0: {"Retry-After": "4"}})
    sleeps: list[float] = []
    client = _build(recorder, sleeps=sleeps, backoff_factor=0.5, respect_retry_after_header=False)
    resp = client.get("https://svc.test/x")
    assert resp.status_code == 200
    assert sleeps == [0.5]


def test_backoff_is_capped():
    recorder = _Recorder([429, 429, 200])
    sleeps: list[float] = []
    # A large backoff factor would exceed the cap on the second wait.
    client = _build(recorder, sleeps=sleeps, backoff_factor=1000.0)
    resp = client.get("https://svc.test/x")
    assert resp.status_code == 200
    assert all(s <= shared_http.BACKOFF_MAX_SECONDS for s in sleeps)


def test_retrying_client_env_attempts(monkeypatch):
    monkeypatch.setenv(shared_http.MAX_ATTEMPTS_ENV, "2")
    recorder = _Recorder([503, 503, 503])
    transport = shared_http.retrying_transport(httpx.MockTransport(recorder), sleep=lambda _d: None)
    client = httpx.Client(transport=transport)
    resp = client.get("https://svc.test/x")
    assert resp.status_code == 503
    assert recorder.calls == 2  # capped by env-provided budget


def test_retrying_client_passes_through_client_kwargs():
    recorder = _Recorder([200])
    client = shared_http.retrying_client(
        transport=httpx.MockTransport(recorder),
        base_url="https://svc.test",
        headers={"Authorization": "SSWS token"},
    )
    resp = client.get("/api/v1/thing")
    assert resp.status_code == 200
    assert resp.request.url == httpx.URL("https://svc.test/api/v1/thing")
    assert resp.request.headers["Authorization"] == "SSWS token"
