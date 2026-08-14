"""Shared boto3 client factory with adaptive retry / throttle resilience.

Every AWS call in this repo should be built through this factory rather than
`boto3.client(...)` / `boto3.resource(...)` directly. The factory applies a
bounded, throttle-aware retry policy (`mode="adaptive"`) so that transient
`Throttling` / `RequestLimitExceeded` responses are retried with client-side
rate limiting instead of surfacing as hard failures on the first hit.

The attempt budget resolves from (in order): an explicit `max_attempts`
argument, the `CLOUD_SECURITY_AWS_MAX_ATTEMPTS` env var, else the default of 8.
A caller that needs its own botocore settings passes `config=Config(...)` and
those settings win: the adaptive base is merged *under* the caller's config via
`Config.merge`.
"""

from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config

from skills._shared.env import env_int

SKILL_NAME = "_shared.aws"
MAX_ATTEMPTS_ENV = "CLOUD_SECURITY_AWS_MAX_ATTEMPTS"
DEFAULT_MAX_ATTEMPTS = 8


def boto_config(max_attempts: int | None = None) -> Config:
    """Return an adaptive-retry botocore Config.

    `max_attempts` wins when provided, else `CLOUD_SECURITY_AWS_MAX_ATTEMPTS`,
    else `DEFAULT_MAX_ATTEMPTS`.
    """
    attempts = (
        max_attempts
        if max_attempts is not None
        else env_int(MAX_ATTEMPTS_ENV, DEFAULT_MAX_ATTEMPTS, skill_name=SKILL_NAME)
    )
    return Config(retries={"max_attempts": attempts, "mode": "adaptive"})


def _merged_config(kwargs: dict[str, Any]) -> Config:
    """Build the adaptive base config, letting a caller-supplied config win."""
    caller = kwargs.pop("config", None)
    base = boto_config()
    if caller is None:
        return base
    return base.merge(caller)


def client(service_name: str, **kwargs: Any) -> Any:
    """`boto3.client` with the adaptive retry config applied."""
    config = _merged_config(kwargs)
    return boto3.client(service_name, config=config, **kwargs)


def resource(service_name: str, **kwargs: Any) -> Any:
    """`boto3.resource` with the adaptive retry config applied."""
    config = _merged_config(kwargs)
    return boto3.resource(service_name, config=config, **kwargs)


def session_client(session: boto3.Session, service_name: str, **kwargs: Any) -> Any:
    """`session.client` with the adaptive retry config applied."""
    config = _merged_config(kwargs)
    return session.client(service_name, config=config, **kwargs)
