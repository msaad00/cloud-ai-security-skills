"""Shared httpx client factory with Retry-After / throttle resilience.

Raw-HTTP SaaS and warehouse calls in this repo (Okta management API, Workday
RaaS, and similar) go through `httpx` — the repo's declared HTTP client
(`http-client` dependency group). `httpx` does not, on its own, retry
throttled responses or honor the `Retry-After` header: `HTTPTransport(retries=)`
only covers connection-level failures, not `429` / `5xx` status codes.

This module supplies that missing layer. `retrying_client()` builds an
`httpx.Client` whose transport retries a bounded number of times on the
throttle/transient status codes, honoring a server-supplied `Retry-After`
header (seconds or HTTP-date) and otherwise backing off exponentially. It is
the HTTP-path complement to `_shared/aws.py` (adaptive boto3 retries) and the
Azure/GCP SDKs' own built-in Retry-After-aware policies.

`requests` is intentionally NOT used: it is not a declared dependency of this
repo, so importing it here would add an undeclared runtime dependency and risk
an ImportError in the deployed workers that consume this module.

The attempt budget resolves from (in order): an explicit `max_attempts`
argument, the `CLOUD_SECURITY_HTTP_MAX_ATTEMPTS` env var, else the default of 8.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from skills._shared.env import env_int

SKILL_NAME = "_shared.http"
MAX_ATTEMPTS_ENV = "CLOUD_SECURITY_HTTP_MAX_ATTEMPTS"
DEFAULT_MAX_ATTEMPTS = 8
DEFAULT_BACKOFF_FACTOR = 0.5
# Cap a single backoff wait so a large `Retry-After` or a high attempt count
# cannot stall a worker indefinitely. Mirrors urllib3's BACKOFF_MAX intent.
BACKOFF_MAX_SECONDS = 60.0
RETRYABLE_STATUS: tuple[int, ...] = (429, 500, 502, 503, 504)
RETRYABLE_METHODS = frozenset({"GET", "POST", "PUT", "DELETE"})


def resolve_max_attempts(max_attempts: int | None = None) -> int:
    """Resolve the attempt budget.

    `max_attempts` wins when provided, else `CLOUD_SECURITY_HTTP_MAX_ATTEMPTS`,
    else `DEFAULT_MAX_ATTEMPTS`. Values below 1 are clamped to 1 (always at
    least one attempt).
    """
    attempts = (
        max_attempts
        if max_attempts is not None
        else env_int(MAX_ATTEMPTS_ENV, DEFAULT_MAX_ATTEMPTS, skill_name=SKILL_NAME)
    )
    return max(1, attempts)


def retry_after_seconds(response: httpx.Response, *, now: datetime | None = None) -> float | None:
    """Parse a `Retry-After` header into seconds, or None when absent/invalid.

    Per RFC 9110 the value is either a non-negative integer number of seconds
    or an HTTP-date. A date in the past yields 0.0 (retry immediately).
    """
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        return None
    if raw.isdigit():
        return float(raw)
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return max(0.0, (parsed - reference).total_seconds())


class RetryTransport(httpx.BaseTransport):
    """An httpx transport that wraps another and retries throttled responses.

    Composition (not subclassing `HTTPTransport`) keeps the retry loop unit
    testable against `httpx.MockTransport` without a live socket. On a
    retryable status the previous response body is drained and closed before
    the next attempt so pooled connections are released cleanly.
    """

    def __init__(
        self,
        inner: httpx.BaseTransport,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        status_forcelist: tuple[int, ...] = RETRYABLE_STATUS,
        allowed_methods: frozenset[str] = RETRYABLE_METHODS,
        respect_retry_after_header: bool = True,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._inner = inner
        self._max_attempts = max(1, max_attempts)
        self._backoff_factor = backoff_factor
        self._status_forcelist = frozenset(status_forcelist)
        self._allowed_methods = frozenset(m.upper() for m in allowed_methods)
        self._respect_retry_after = respect_retry_after_header
        self._sleep = sleep

    def _backoff_delay(self, attempt: int) -> float:
        # attempt is 1-based; first backoff uses backoff_factor * 2**0.
        return min(self._backoff_factor * (2 ** (attempt - 1)), BACKOFF_MAX_SECONDS)

    def _delay_for(self, response: httpx.Response, attempt: int) -> float:
        if self._respect_retry_after:
            after = retry_after_seconds(response)
            if after is not None:
                return min(after, BACKOFF_MAX_SECONDS)
        return self._backoff_delay(attempt)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        method = request.method.upper()
        response = self._inner.handle_request(request)
        attempt = 1
        while (
            attempt < self._max_attempts
            and method in self._allowed_methods
            and response.status_code in self._status_forcelist
        ):
            delay = self._delay_for(response, attempt)
            response.read()
            response.close()
            if delay > 0:
                self._sleep(delay)
            response = self._inner.handle_request(request)
            attempt += 1
        return response

    def close(self) -> None:
        self._inner.close()


def retrying_transport(
    inner: httpx.BaseTransport | None = None,
    *,
    max_attempts: int | None = None,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    status_forcelist: tuple[int, ...] = RETRYABLE_STATUS,
    allowed_methods: frozenset[str] = RETRYABLE_METHODS,
    respect_retry_after_header: bool = True,
    sleep: Callable[[float], None] = time.sleep,
) -> RetryTransport:
    """Build a `RetryTransport`.

    `inner` defaults to a real `httpx.HTTPTransport` whose own `retries` cover
    connection-level failures (mirroring urllib3's total budget covering
    connect errors), leaving status-code retries to `RetryTransport`.
    """
    attempts = resolve_max_attempts(max_attempts)
    if inner is None:
        inner = httpx.HTTPTransport(retries=attempts - 1)
    return RetryTransport(
        inner,
        max_attempts=attempts,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=allowed_methods,
        respect_retry_after_header=respect_retry_after_header,
        sleep=sleep,
    )


def retrying_client(
    *,
    max_attempts: int | None = None,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    status_forcelist: tuple[int, ...] = RETRYABLE_STATUS,
    allowed_methods: frozenset[str] = RETRYABLE_METHODS,
    transport: httpx.BaseTransport | None = None,
    **client_kwargs: Any,
) -> httpx.Client:
    """`httpx.Client` whose transport honors `Retry-After` / 429 / 5xx retries.

    Extra keyword arguments (`base_url`, `headers`, `timeout`, ...) pass
    straight through to `httpx.Client`. Pass `transport=` to wrap a specific
    inner transport (e.g. an `httpx.MockTransport` in tests).
    """
    retry_transport = retrying_transport(
        transport,
        max_attempts=max_attempts,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=allowed_methods,
    )
    return httpx.Client(transport=retry_transport, **client_kwargs)
