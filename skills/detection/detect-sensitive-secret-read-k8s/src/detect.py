"""Detect reads of Kubernetes Secrets matching sensitive name patterns.

Reads OCSF 1.8 API Activity (class 6003) events produced by
ingest-k8s-audit-ocsf and emits OCSF 1.8 Detection Finding (class 2004)
for any `get` or `list` on a secret whose name matches at least one
sensitive pattern.

Stateless pattern matcher — no window, no correlation required. Works on
Metadata-level audit logs.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "detect-sensitive-secret-read-k8s"
OCSF_VERSION = "1.8.0"

# Detection Finding (2004)
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4

# MITRE ATT&CK v14 — T1552.007 Unsecured Credentials: Container API
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0006"
MITRE_TACTIC_NAME = "Credential Access"
MITRE_TECH_UID = "T1552"
MITRE_TECH_NAME = "Unsecured Credentials"
MITRE_SUB_UID = "T1552.007"
MITRE_SUB_NAME = "Container API"

# K8s read verbs we care about
READ_VERBS = {"get", "list"}

# Default sensitive-name patterns (case-insensitive, fnmatch-style globs)
SENSITIVE_NAME_PATTERNS: tuple[str, ...] = (
    # Generic credential / password markers
    "*credential*",
    "*creds*",
    "*password*",
    "*passwd*",
    "*pwd*",
    # Tokens
    "*token*",
    "*-token",
    # API keys
    "*api-key*",
    "*apikey*",
    "*api_key*",
    # Signing keys / secret keys
    "*secret-key*",
    "*-secret",
    "*signing-key*",
    "*hmac-key*",
    # AWS credential patterns
    "aws-*",
    "*-aws",
    "*aws-creds*",
    "*aws-access*",
    # GCP credential patterns
    "gcp-*",
    "*-gcp",
    "*gcp-creds*",
    "*service-account-key*",
    # Azure credential patterns
    "azure-*",
    "*-azure",
    "*azure-creds*",
    # Docker registry pull secrets
    "dockerconfig*",
    "*dockerconfigjson*",
    # TLS material
    "*-tls",
    "tls-*",
    "*certificate*",
    "*private-key*",
    "*.pem",
    "*.key",
    # K8s cluster root CA (rare legitimate workload read)
    "kube-root-ca*",
)


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------


def matches_sensitive_pattern(name: str, patterns: tuple[str, ...] | list[str]) -> list[str]:
    """Return the list of patterns that match `name` case-insensitively.

    Empty list means no match. Multiple matches are preserved so the
    finding can report exactly which patterns fired.
    """
    if not name:
        return []
    lowered = name.lower()
    return [p for p in patterns if fnmatch.fnmatchcase(lowered, p.lower())]


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


def _is_api_activity(event: dict[str, Any]) -> bool:
    return event.get("class_uid") == 6003


def _verb(event: dict[str, Any]) -> str:
    return (event.get("api") or {}).get("operation", "")


def _resource(event: dict[str, Any]) -> dict[str, Any]:
    resources = event.get("resources") or []
    return resources[0] if resources else {}


def _actor_name(event: dict[str, Any]) -> str:
    return ((event.get("actor") or {}).get("user") or {}).get("name", "")


def _event_time(event: dict[str, Any]) -> int:
    return int(event.get("time") or 0)


def _short(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()[:8]


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------


def _build_finding(
    *,
    event: dict[str, Any],
    actor: str,
    namespace: str,
    secret_name: str,
    matched_patterns: list[str],
) -> dict[str, Any]:
    uid = f"det-k8s-secret-read-{_short(actor)}-{_short(f'{namespace}/{secret_name}')}"

    patterns_str = ", ".join(matched_patterns)
    desc = (
        f"Principal '{actor}' called `{_verb(event)}` on secret '{secret_name}' "
        f"in namespace '{namespace}'. The secret name matches the sensitive "
        f"pattern(s): {patterns_str}. Workloads should mount secret data as "
        f"files — the Kubernetes API is not the intended credential read path "
        f"at runtime. (MITRE T1552.007 Unsecured Credentials: Container API)"
    )

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": 1,
        "time": _event_time(event) or _now_ms(),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "cloud-security",
                "vendor_name": "msaad00/cloud-security",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "kubernetes", "credential-access", "secret-read"],
        },
        "finding_info": {
            "uid": uid,
            "title": "Kubernetes workload read a sensitive secret by name",
            "desc": desc,
            "types": ["k8s-sensitive-secret-read"],
            "first_seen_time": _event_time(event),
            "last_seen_time": _event_time(event),
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic": {"name": MITRE_TACTIC_NAME, "uid": MITRE_TACTIC_UID},
                    "technique": {"name": MITRE_TECH_NAME, "uid": MITRE_TECH_UID},
                    "sub_technique": {"name": MITRE_SUB_NAME, "uid": MITRE_SUB_UID},
                }
            ],
        },
        "observables": [
            {"name": "actor.name", "type": "Other", "value": actor},
            {"name": "namespace", "type": "Other", "value": namespace},
            {"name": "secret.name", "type": "Other", "value": secret_name},
            {"name": "verb", "type": "Other", "value": _verb(event)},
            {"name": "matched_patterns", "type": "Other", "value": patterns_str},
            {"name": "rule", "type": "Other", "value": "k8s-sensitive-secret-read"},
        ],
        "evidence": {
            "events_observed": 1,
            "first_seen_time": _event_time(event),
            "last_seen_time": _event_time(event),
            "raw_events": [],
        },
    }


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------


def detect(
    events: Iterable[dict[str, Any]],
    *,
    patterns: tuple[str, ...] | list[str] | None = None,
) -> Iterable[dict[str, Any]]:
    """Walk OCSF API Activity events; yield one finding per sensitive secret read.

    Idempotent: the same (actor, namespace, secret_name) tuple produces
    at most one finding per call, even if the actor reads the same secret
    multiple times in the input.
    """
    active_patterns: tuple[str, ...] = tuple(patterns) if patterns is not None else SENSITIVE_NAME_PATTERNS
    seen: set[str] = set()

    for event in events:
        if not _is_api_activity(event):
            continue
        verb = _verb(event)
        if verb not in READ_VERBS:
            continue
        r = _resource(event)
        if r.get("type") != "secrets":
            continue
        secret_name = r.get("name") or ""
        if not secret_name:
            # `list` with no specific name — that's enumeration, covered by
            # detect-privilege-escalation-k8s Rule 1 in a different pipeline.
            continue
        matched = matches_sensitive_pattern(secret_name, active_patterns)
        if not matched:
            continue

        actor = _actor_name(event)
        namespace = r.get("namespace") or ""
        dedup_key = f"{actor}|{namespace}|{secret_name}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        yield _build_finding(
            event=event,
            actor=actor,
            namespace=namespace,
            secret_name=secret_name,
            matched_patterns=matched,
        )


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {e}", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect reads of Kubernetes Secrets with sensitive names.")
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="OCSF Detection Finding JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--sensitive-pattern",
        action="append",
        default=None,
        help="Add an extra sensitive-name glob pattern (case-insensitive). Repeatable.",
    )
    args = parser.parse_args(argv)

    patterns: tuple[str, ...] | list[str]
    if args.sensitive_pattern:
        # Merge defaults + custom
        patterns = list(SENSITIVE_NAME_PATTERNS) + list(args.sensitive_pattern)
    else:
        patterns = SENSITIVE_NAME_PATTERNS

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events, patterns=patterns):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
