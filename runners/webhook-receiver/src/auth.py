"""Request authentication for the webhook receiver.

Two layers; every routed skill must have at least one configured:

1. **HMAC-SHA-256** over `"{timestamp}." + raw body`, keyed per skill via
   `WEBHOOK_HMAC_SECRETS` (JSON object). The timestamp is integer Unix
   seconds in `X-Webhook-Timestamp` (`WEBHOOK_TIMESTAMP_HEADER`) and must
   be within `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` (default 300) of the
   receiver clock. The signature header is configurable
   (`WEBHOOK_HMAC_HEADER`, default `X-Hub-Signature-256`) and accepts
   either `sha256=<hex>` or bare hex. Body-only signatures (no timestamp)
   are replayable forever and are refused unless the deprecated
   `WEBHOOK_ALLOW_LEGACY_HMAC=1` opt-in is set.
2. **Bearer token** for internal webhooks where the upstream cannot
   sign. Configured via `WEBHOOK_BEARER_TOKEN`.

The verifier is body-first: an invalid signature is rejected before the
skill subprocess is spawned, and the audit record still fires with
`result: error` so post-hoc reviewers see the rejected attempt.

Fail closed: a skill with neither an HMAC secret nor a bearer token is
refused (`auth_not_configured`), and a malformed `WEBHOOK_HMAC_SECRETS`
raises instead of silently disabling signature checks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

DEFAULT_TIMESTAMP_HEADER = "X-Webhook-Timestamp"
DEFAULT_TIMESTAMP_TOLERANCE_SECONDS = 300
_TOLERANCE_ENV = "WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS"
_MAX_TIMESTAMP_DIGITS = 12


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    reason: str = ""
    # Set on a verified HMAC request: the key and expiry the caller feeds to
    # `ReplayCache` so the same signed request is accepted at most once.
    replay_key: str = ""
    replay_expires_at: int = 0
    legacy: bool = False


class ReplayCache:
    """Bounded in-process record of accepted signatures.

    Each entry lives until its timestamp leaves the freshness window, so a
    captured request cannot be re-sent while it would still verify. The
    cache is per process: replicas behind a load balancer do not share it,
    and the timestamp window remains the cross-replica bound. Only verified
    signatures are stored, so an unauthenticated caller cannot fill it;
    when full the oldest entry is evicted.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        self._max_entries = max_entries
        self._entries: OrderedDict[str, int] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._entries)

    def check_and_store(self, key: str, *, expires_at: int, now: int) -> bool:
        """Return True and remember `key` if it is unseen; False on replay."""
        with self._lock:
            for stale in [k for k, exp in self._entries.items() if exp < now]:
                del self._entries[stale]
            if key in self._entries:
                return False
            self._entries[key] = expires_at
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
            return True


def _const_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def hmac_secrets(env: dict[str, str] | None = None) -> dict[str, str]:
    """Parse `WEBHOOK_HMAC_SECRETS`. Raises ValueError when it is set but is
    not a JSON object of string secrets."""
    src = os.environ if env is None else env
    raw = (src.get("WEBHOOK_HMAC_SECRETS") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("WEBHOOK_HMAC_SECRETS is not valid JSON") from exc
    if not isinstance(parsed, dict) or not all(isinstance(v, str) and v for v in parsed.values()):
        raise ValueError(
            "WEBHOOK_HMAC_SECRETS must be a JSON object mapping skill name to a non-empty secret"
        )
    return {str(k): v for k, v in parsed.items()}


def _bearer_token(env: dict[str, str] | None = None) -> str:
    src = os.environ if env is None else env
    return (src.get("WEBHOOK_BEARER_TOKEN") or "").strip()


def auth_configured_for(skill_name: str, *, env: dict[str, str] | None = None) -> bool:
    """True when the skill has an HMAC secret or a bearer token is set."""
    return skill_name in hmac_secrets(env) or bool(_bearer_token(env))


def _hmac_header_name(env: dict[str, str] | None = None) -> str:
    src = os.environ if env is None else env
    name = (src.get("WEBHOOK_HMAC_HEADER") or "").strip()
    return name or "X-Hub-Signature-256"


def _normalised_signature(value: str) -> str:
    """Accept `sha256=<hex>` or bare `<hex>` so the receiver works with
    GitHub-style and bare-hex sigs without per-vendor branches."""
    cleaned = value.strip()
    if cleaned.lower().startswith("sha256="):
        cleaned = cleaned.split("=", 1)[1].strip()
    return cleaned.lower()


def _expected_signature(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _timestamp_header_name(env: dict[str, str] | None = None) -> str:
    src = os.environ if env is None else env
    name = (src.get("WEBHOOK_TIMESTAMP_HEADER") or "").strip()
    return name or DEFAULT_TIMESTAMP_HEADER


def timestamp_tolerance_seconds(env: dict[str, str] | None = None) -> int:
    """Parse `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS`. Raises ValueError when it
    is set but is not a positive integer."""
    src = os.environ if env is None else env
    raw = (src.get(_TOLERANCE_ENV) or "").strip()
    if not raw:
        return DEFAULT_TIMESTAMP_TOLERANCE_SECONDS
    if not raw.isdigit() or int(raw) <= 0:
        raise ValueError(f"{_TOLERANCE_ENV} must be a positive integer, got {raw!r}")
    return int(raw)


def legacy_hmac_allowed(env: dict[str, str] | None = None) -> bool:
    src = os.environ if env is None else env
    return (src.get("WEBHOOK_ALLOW_LEGACY_HMAC") or "").strip().lower() in {"1", "true", "yes"}


def _header(headers: dict[str, str], name: str) -> str:
    # Header lookup is case-insensitive (FastAPI lowercases by default).
    return headers.get(name.lower()) or headers.get(name) or ""


def verify_hmac(
    skill_name: str,
    headers: dict[str, str],
    body: bytes,
    *,
    env: dict[str, str] | None = None,
    now: int | None = None,
) -> AuthResult:
    """Verify the HMAC signature for one webhook request. Returns ok=True
    when no secret is configured for the skill; `auth_configured_for`
    guarantees the bearer layer is then required."""
    secrets = hmac_secrets(env)
    secret = secrets.get(skill_name)
    if secret is None:
        # No per-skill secret configured -> HMAC layer is opt-in. The bearer
        # layer is the alternative authenticator.
        return AuthResult(ok=True)
    raw_sig = _header(headers, _hmac_header_name(env))
    if not raw_sig:
        return AuthResult(ok=False, reason="missing_signature")
    presented = _normalised_signature(raw_sig)
    tolerance = timestamp_tolerance_seconds(env)
    current = int(time.time()) if now is None else now

    raw_ts = _header(headers, _timestamp_header_name(env))
    if not raw_ts:
        if not legacy_hmac_allowed(env):
            return AuthResult(ok=False, reason="missing_timestamp")
        if not _const_eq(presented, _expected_signature(secret, body)):
            return AuthResult(ok=False, reason="signature_invalid")
        return AuthResult(
            ok=True,
            replay_key=f"{skill_name}:{presented}",
            replay_expires_at=current + tolerance,
            legacy=True,
        )

    if not raw_ts.isascii() or not raw_ts.isdigit() or len(raw_ts) > _MAX_TIMESTAMP_DIGITS:
        return AuthResult(ok=False, reason="timestamp_invalid")
    expected = _expected_signature(secret, raw_ts.encode("ascii") + b"." + body)
    if not _const_eq(presented, expected):
        return AuthResult(ok=False, reason="signature_invalid")
    timestamp = int(raw_ts)
    if abs(current - timestamp) > tolerance:
        return AuthResult(ok=False, reason="timestamp_out_of_window")
    return AuthResult(
        ok=True,
        replay_key=f"{skill_name}:{presented}",
        replay_expires_at=timestamp + tolerance,
    )


def verify_bearer(headers: dict[str, str], *, env: dict[str, str] | None = None) -> AuthResult:
    """Verify the bearer token, if one is configured."""
    expected = _bearer_token(env)
    if not expected:
        return AuthResult(ok=True)
    raw = headers.get("authorization") or headers.get("Authorization") or ""
    if not raw.lower().startswith("bearer "):
        return AuthResult(ok=False, reason="missing_bearer")
    token = raw.split(" ", 1)[1].strip()
    if not _const_eq(token, expected):
        return AuthResult(ok=False, reason="bearer_invalid")
    return AuthResult(ok=True)
