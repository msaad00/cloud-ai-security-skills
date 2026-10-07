"""Request authentication for the webhook receiver.

Two layers; every routed skill must have at least one configured:

1. **HMAC-SHA-256** of the raw request body, keyed per skill via
   `WEBHOOK_HMAC_SECRETS` (JSON object). The signature header is
   configurable (`WEBHOOK_HMAC_HEADER`, default `X-Hub-Signature-256`)
   and accepts either `sha256=<hex>` or bare hex.
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
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    reason: str = ""


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


def verify_hmac(
    skill_name: str,
    headers: dict[str, str],
    body: bytes,
    *,
    env: dict[str, str] | None = None,
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
    header_name = _hmac_header_name(env).lower()
    # Header lookup is case-insensitive (FastAPI lowercases by default).
    raw_sig = headers.get(header_name) or headers.get(_hmac_header_name(env))
    if not raw_sig:
        return AuthResult(ok=False, reason="missing_signature")
    presented = _normalised_signature(raw_sig)
    expected = _expected_signature(secret, body)
    if not _const_eq(presented, expected):
        return AuthResult(ok=False, reason="signature_invalid")
    return AuthResult(ok=True)


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
