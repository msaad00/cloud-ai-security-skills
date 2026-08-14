"""Retry-After / throttle resilience for the stdlib http.client Graph path.

These tests exercise the inline retry loop added to `MsGraphClient._request_json`
via `_graph_http_request`. They mock `http.client.HTTPSConnection` and patch the
Graph token so NO Azure credential (and no `azure`/`httpx`/`requests` import) is
needed — only stdlib `http.client`.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    MsGraphClient,
    _graph_http_request,
    _retry_delay_seconds,
)


class _FakeResponse:
    def __init__(self, status: int, *, reason: str = "", body: bytes = b"", retry_after=None):
        self.status = status
        self.reason = reason
        self._body = body
        self._retry_after = retry_after

    def read(self) -> bytes:
        return self._body

    def getheader(self, name: str, default=None):
        if name.lower() == "retry-after" and self._retry_after is not None:
            return self._retry_after
        return default


class _FakeConnection:
    """One connection == one scripted item (a response, or an OSError to raise)."""

    def __init__(self, item, netloc: str):
        self._item = item
        self.netloc = netloc
        self.requested = None
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.requested = (method, path, body, headers)
        if isinstance(self._item, OSError):
            raise self._item

    def getresponse(self):
        if isinstance(self._item, Exception):
            raise self._item
        return self._item

    def close(self):
        self.closed = True


class _ConnFactory:
    """Callable stand-in for `http.client.HTTPSConnection` yielding scripted conns."""

    def __init__(self, script):
        self._script = list(script)
        self.conns: list[_FakeConnection] = []

    def __call__(self, netloc, *args, **kwargs):
        item = self._script.pop(0)
        conn = _FakeConnection(item, netloc)
        self.conns.append(conn)
        return conn

    @property
    def opened(self) -> int:
        return len(self.conns)


@pytest.fixture
def sleeps():
    calls: list[float] = []
    return calls


def _client() -> MsGraphClient:
    client = MsGraphClient(tenant_id="t", client_id="c", client_secret="s")
    # Bypass the real credential (which would import azure.identity).
    object.__setattr__(client, "_token", lambda: "fake-token")  # type: ignore[misc]
    return client


def _patch_http(monkeypatch, factory, sleeps):
    # Patch the stdlib modules directly (not `handler.http` / `handler.time`):
    # multiple remediation skills ship a top-level `handler` module, so a
    # `import handler` here can bind to the wrong skill under a full-suite run.
    monkeypatch.setattr("http.client.HTTPSConnection", factory)
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))


URL = "https://graph.microsoft.com/v1.0/servicePrincipals/abc?$select=id"


def test_429_then_200_retries_once_and_succeeds(monkeypatch, sleeps):
    factory = _ConnFactory(
        [
            _FakeResponse(429, reason="Too Many Requests", retry_after="1"),
            _FakeResponse(200, body=b'{"id":"abc"}'),
        ]
    )
    _patch_http(monkeypatch, factory, sleeps)

    result = _client()._request_json("GET", URL)

    assert result == {"id": "abc"}
    assert factory.opened == 2  # exactly one retry
    assert len(sleeps) == 1


def test_retry_after_header_is_honored(monkeypatch, sleeps):
    factory = _ConnFactory(
        [
            _FakeResponse(429, retry_after="2"),
            _FakeResponse(200, body=b'{"ok":true}'),
        ]
    )
    _patch_http(monkeypatch, factory, sleeps)

    result = _client()._request_json("GET", URL)

    assert result == {"ok": True}
    assert sleeps == [2.0]  # slept exactly the Retry-After seconds


def test_persistent_503_exhausts_budget_and_raises(monkeypatch, sleeps):
    monkeypatch.setenv("CLOUD_SECURITY_HTTP_MAX_ATTEMPTS", "3")
    factory = _ConnFactory([_FakeResponse(503, reason="Service Unavailable") for _ in range(3)])
    _patch_http(monkeypatch, factory, sleeps)

    with pytest.raises(RuntimeError, match="Microsoft Graph 503"):
        _client()._request_json("GET", URL)

    assert factory.opened == 3  # budget honored, no infinite loop
    assert len(sleeps) == 2  # attempts - 1 backoffs


def test_200_first_try_does_not_retry(monkeypatch, sleeps):
    factory = _ConnFactory([_FakeResponse(200, body=b'{"id":"abc"}')])
    _patch_http(monkeypatch, factory, sleeps)

    result = _client()._request_json("GET", URL)

    assert result == {"id": "abc"}
    assert factory.opened == 1
    assert sleeps == []


def test_default_backoff_when_no_retry_after(monkeypatch, sleeps):
    factory = _ConnFactory(
        [
            _FakeResponse(429),  # no Retry-After header
            _FakeResponse(200, body=b"{}"),
        ]
    )
    _patch_http(monkeypatch, factory, sleeps)

    _client()._request_json("GET", URL)

    assert sleeps == [0.5]  # min(0.5 * 2**0, 60)


def test_transient_oserror_is_retried_then_wrapped(monkeypatch, sleeps):
    # First attempt raises a connection error, second succeeds.
    factory = _ConnFactory(
        [
            OSError("connection reset"),
            _FakeResponse(200, body=b'{"id":"abc"}'),
        ]
    )
    _patch_http(monkeypatch, factory, sleeps)

    result = _client()._request_json("GET", URL)

    assert result == {"id": "abc"}
    assert factory.opened == 2
    assert len(sleeps) == 1


def test_oserror_exhaustion_wraps_in_runtime_error(monkeypatch, sleeps):
    monkeypatch.setenv("CLOUD_SECURITY_HTTP_MAX_ATTEMPTS", "2")
    factory = _ConnFactory([OSError("boom"), OSError("boom")])
    _patch_http(monkeypatch, factory, sleeps)

    with pytest.raises(RuntimeError, match="Microsoft Graph connection failed"):
        _client()._request_json("GET", URL)


def test_404_with_allow_not_found_returns_none(monkeypatch, sleeps):
    factory = _ConnFactory([_FakeResponse(404, reason="Not Found")])
    _patch_http(monkeypatch, factory, sleeps)

    result = _client()._request_json("GET", URL, allow_not_found=True)

    assert result is None
    assert factory.opened == 1  # 404 is not retryable
    assert sleeps == []


def test_retry_delay_helper_units():
    # Integer Retry-After honored and capped.
    assert _retry_delay_seconds("2", 0) == 2.0
    assert _retry_delay_seconds("999", 0) == 60.0
    # No header → exponential min(0.5 * 2**attempt, 60).
    assert _retry_delay_seconds(None, 0) == 0.5
    assert _retry_delay_seconds(None, 1) == 1.0
    assert _retry_delay_seconds(None, 10) == 60.0
    # HTTP-date in the past → 0.0 (retry immediately).
    assert _retry_delay_seconds("Wed, 21 Oct 2015 07:28:00 GMT", 0) == 0.0


def test_graph_http_request_is_credential_free(monkeypatch, sleeps):
    # The module-level helper needs no client/token at all.
    factory = _ConnFactory([_FakeResponse(200, body=b"{}")])
    monkeypatch.setattr("http.client.HTTPSConnection", factory)

    result = _graph_http_request(
        "graph.microsoft.com",
        "GET",
        "/v1.0/servicePrincipals/abc",
        headers={"Authorization": "Bearer fake"},
        sleep=lambda s: sleeps.append(s),
    )

    assert result.status == 200
    assert factory.opened == 1
