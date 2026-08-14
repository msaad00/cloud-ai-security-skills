"""Retry-After / throttle resilience for the stdlib http.client Graph path.

Exercises the inline retry loop added to `EntraRemediationClient._graph_request`
and `._graph_collection` via `_graph_http_request`. Mocks
`http.client.HTTPSConnection` and patches `_graph_token` so NO Azure credential
(and no `azure`/`httpx`/`requests` import) is needed — only stdlib `http.client`.
"""

from __future__ import annotations

import sys

import pytest

# Isolate this skill's `function_worker` package (mirrors the sibling tests).
for _name in ("handler", "steps"):
    sys.modules.pop(_name, None)

from function_worker import handler as h  # type: ignore[import-not-found]  # noqa: E402


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
    return []


def _client() -> "h.EntraRemediationClient":
    client = h.EntraRemediationClient(tenant_id="t", client_id="c", client_secret="s")
    # Bypass the real credential (which would import azure.identity).
    client._graph_token = lambda: "fake-token"  # type: ignore[method-assign]
    return client


def _patch_http(monkeypatch, factory, sleeps):
    monkeypatch.setattr(h.http.client, "HTTPSConnection", factory)
    monkeypatch.setattr(h.time, "sleep", lambda s: sleeps.append(s))


# ── _graph_request (write path, returns None) ───────────────────────────────


def test_429_then_204_retries_once_and_succeeds(monkeypatch, sleeps):
    factory = _ConnFactory(
        [
            _FakeResponse(429, reason="Too Many Requests", retry_after="1"),
            _FakeResponse(204),
        ]
    )
    _patch_http(monkeypatch, factory, sleeps)

    # No exception == success for a write.
    assert (
        _client()._graph_request("PATCH", "/v1.0/users/abc", body={"accountEnabled": False}) is None
    )
    assert factory.opened == 2
    assert len(sleeps) == 1


def test_retry_after_header_is_honored(monkeypatch, sleeps):
    factory = _ConnFactory([_FakeResponse(429, retry_after="2"), _FakeResponse(204)])
    _patch_http(monkeypatch, factory, sleeps)

    _client()._graph_request("POST", "/v1.0/users/abc/revokeSignInSessions")

    assert sleeps == [2.0]


def test_persistent_503_exhausts_budget_and_raises(monkeypatch, sleeps):
    monkeypatch.setenv("CLOUD_SECURITY_HTTP_MAX_ATTEMPTS", "3")
    factory = _ConnFactory([_FakeResponse(503, reason="Service Unavailable") for _ in range(3)])
    _patch_http(monkeypatch, factory, sleeps)

    with pytest.raises(RuntimeError, match="Microsoft Graph 503"):
        _client()._graph_request("DELETE", "/v1.0/users/abc")

    assert factory.opened == 3
    assert len(sleeps) == 2


def test_204_first_try_does_not_retry(monkeypatch, sleeps):
    factory = _ConnFactory([_FakeResponse(204)])
    _patch_http(monkeypatch, factory, sleeps)

    _client()._graph_request("DELETE", "/v1.0/users/abc")

    assert factory.opened == 1
    assert sleeps == []


def test_404_is_not_an_error_and_not_retried(monkeypatch, sleeps):
    # Preserve existing behavior: 404 on a write is tolerated (idempotent delete).
    factory = _ConnFactory([_FakeResponse(404, reason="Not Found")])
    _patch_http(monkeypatch, factory, sleeps)

    _client()._graph_request("DELETE", "/v1.0/groups/g/members/u/$ref")

    assert factory.opened == 1
    assert sleeps == []


# ── _graph_collection (paginated GET) ───────────────────────────────────────


def test_collection_retries_then_paginates(monkeypatch, sleeps):
    factory = _ConnFactory(
        [
            _FakeResponse(429, retry_after="1"),  # first page throttled
            _FakeResponse(
                200,
                body=b'{"value":[{"id":"a"}],'
                b'"@odata.nextLink":"https://graph.microsoft.com/v1.0/x?$skiptoken=2"}',
            ),
            _FakeResponse(200, body=b'{"value":[{"id":"b"}]}'),  # second page
        ]
    )
    _patch_http(monkeypatch, factory, sleeps)

    items = _client()._graph_collection("/v1.0/users/abc/memberOf")

    assert [i["id"] for i in items] == ["a", "b"]
    assert factory.opened == 3  # 1 retry + 2 real pages
    assert len(sleeps) == 1


def test_collection_persistent_503_raises(monkeypatch, sleeps):
    monkeypatch.setenv("CLOUD_SECURITY_HTTP_MAX_ATTEMPTS", "2")
    factory = _ConnFactory([_FakeResponse(503) for _ in range(2)])
    _patch_http(monkeypatch, factory, sleeps)

    with pytest.raises(RuntimeError, match="Microsoft Graph 503"):
        _client()._graph_collection("/v1.0/users/abc/memberOf")

    assert factory.opened == 2
    assert len(sleeps) == 1


# ── module-level helper units ───────────────────────────────────────────────


def test_retry_delay_helper_units():
    assert h._retry_delay_seconds("2", 0) == 2.0
    assert h._retry_delay_seconds("999", 0) == 60.0
    assert h._retry_delay_seconds(None, 0) == 0.5
    assert h._retry_delay_seconds(None, 1) == 1.0
    assert h._retry_delay_seconds(None, 10) == 60.0
    assert h._retry_delay_seconds("Wed, 21 Oct 2015 07:28:00 GMT", 0) == 0.0


def test_graph_http_request_is_credential_free(monkeypatch, sleeps):
    factory = _ConnFactory([_FakeResponse(200, body=b"{}")])
    monkeypatch.setattr(h.http.client, "HTTPSConnection", factory)

    result = h._graph_http_request(
        "graph.microsoft.com",
        "GET",
        "/v1.0/users/abc/memberOf",
        headers={"Authorization": "Bearer fake"},
        sleep=lambda s: sleeps.append(s),
    )

    assert result.status == 200
    assert factory.opened == 1


def test_transient_oserror_is_retried(monkeypatch, sleeps):
    factory = _ConnFactory([OSError("reset"), _FakeResponse(204)])
    _patch_http(monkeypatch, factory, sleeps)

    _client()._graph_request("DELETE", "/v1.0/users/abc")

    assert factory.opened == 2
    assert len(sleeps) == 1
