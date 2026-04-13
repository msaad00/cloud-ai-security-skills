"""Detect Kubernetes privilege escalation patterns in OCSF 1.8 API Activity.

Reads OCSF 1.8 API Activity (class 6003) events produced by
ingest-k8s-audit-ocsf and emits OCSF 1.8 Detection Findings (class 2004) for
four K8s priv-esc patterns.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

SKILL_NAME = "detect-privilege-escalation-k8s"
OCSF_VERSION = "1.8.0"

# Detection Finding (2004)
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

# Severity
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5

# MITRE ATT&CK v14
MITRE_VERSION = "v14"

# Rule 1: T1552.007
R1_TACTIC_UID = "TA0006"
R1_TACTIC_NAME = "Credential Access"
R1_TECH_UID = "T1552"
R1_TECH_NAME = "Unsecured Credentials"
R1_SUB_UID = "T1552.007"
R1_SUB_NAME = "Container API"

# Rule 2: T1611
R2_TACTIC_UID = "TA0004"
R2_TACTIC_NAME = "Privilege Escalation"
R2_TECH_UID = "T1611"
R2_TECH_NAME = "Escape to Host"

# Rule 3: T1098
R3_TACTIC_UID = "TA0003"
R3_TACTIC_NAME = "Persistence"
R3_TECH_UID = "T1098"
R3_TECH_NAME = "Account Manipulation"

# Rule 4: T1550.001
R4_TACTIC_UID = "TA0008"
R4_TACTIC_NAME = "Lateral Movement"
R4_TECH_UID = "T1550"
R4_TECH_NAME = "Use Alternate Authentication Material"
R4_SUB_UID = "T1550.001"
R4_SUB_NAME = "Application Access Tokens"

# Rule 1 correlation window (milliseconds)
RULE1_WINDOW_MS = 5 * 60 * 1000

# Admin-like principals that should NOT trigger Rule 3
ADMIN_GROUPS = {"system:masters"}
ADMIN_USERS = {"kubernetes-admin", "kube-admin"}


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------


def _is_api_activity(event: dict[str, Any]) -> bool:
    return event.get("class_uid") == 6003


def _actor_name(event: dict[str, Any]) -> str:
    return ((event.get("actor") or {}).get("user") or {}).get("name", "")


def _actor_is_service_account(event: dict[str, Any]) -> bool:
    return ((event.get("actor") or {}).get("user") or {}).get("type") == "ServiceAccount"


def _actor_groups(event: dict[str, Any]) -> set[str]:
    groups = ((event.get("actor") or {}).get("user") or {}).get("groups") or []
    return {g.get("name", "") for g in groups}


def _verb(event: dict[str, Any]) -> str:
    return (event.get("api") or {}).get("operation", "")


def _resource(event: dict[str, Any]) -> dict[str, Any]:
    resources = event.get("resources") or []
    return resources[0] if resources else {}


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
    rule_id: str,
    title: str,
    desc: str,
    severity_id: int,
    tactic_uid: str,
    tactic_name: str,
    technique_uid: str,
    technique_name: str,
    sub_technique_uid: str | None,
    sub_technique_name: str | None,
    actor: str,
    target: str,
    first_seen_time: int,
    last_seen_time: int,
    observables: list[dict[str, Any]],
    evidence_count: int,
) -> dict[str, Any]:
    uid = f"det-k8s-{rule_id}-{_short(actor)}-{_short(target)}"
    attack: dict[str, Any] = {
        "version": MITRE_VERSION,
        "tactic": {"name": tactic_name, "uid": tactic_uid},
        "technique": {"name": technique_name, "uid": technique_uid},
    }
    if sub_technique_uid and sub_technique_name:
        attack["sub_technique"] = {"name": sub_technique_name, "uid": sub_technique_uid}

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": severity_id,
        "status_id": 1,
        "time": last_seen_time or _now_ms(),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "cloud-security",
                "vendor_name": "msaad00/cloud-security",
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "kubernetes", "privilege-escalation", rule_id],
        },
        "finding_info": {
            "uid": uid,
            "title": title,
            "desc": desc,
            "types": [f"k8s-{rule_id}"],
            "first_seen_time": first_seen_time,
            "last_seen_time": last_seen_time,
            "attacks": [attack],
        },
        "observables": observables,
        "evidence": {
            "events_observed": evidence_count,
            "first_seen_time": first_seen_time,
            "last_seen_time": last_seen_time,
            "raw_events": [],
        },
    }


# ---------------------------------------------------------------------------
# Rule 1: Service-account secret enumeration + read (T1552.007)
# ---------------------------------------------------------------------------


def rule1_secret_enumeration(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """list(secrets) → get(secrets) in the same namespace, same SA, within window."""
    # Index: (actor, namespace) → list of (time_ms, event) for list events
    list_events: dict[tuple[str, str], list[tuple[int, dict]]] = {}

    # First pass: collect list events
    for ev in events:
        if not _is_api_activity(ev):
            continue
        if not _actor_is_service_account(ev):
            continue
        if _verb(ev) != "list":
            continue
        r = _resource(ev)
        if r.get("type") != "secrets":
            continue
        key = (_actor_name(ev), r.get("namespace", ""))
        list_events.setdefault(key, []).append((_event_time(ev), ev))

    # Second pass: match get events against list events within the window
    seen_findings: set[str] = set()
    for ev in events:
        if not _is_api_activity(ev):
            continue
        if not _actor_is_service_account(ev):
            continue
        if _verb(ev) != "get":
            continue
        r = _resource(ev)
        if r.get("type") != "secrets":
            continue
        actor = _actor_name(ev)
        ns = r.get("namespace", "")
        get_time = _event_time(ev)
        secret_name = r.get("name", "")

        candidates = list_events.get((actor, ns), [])
        matching = [(t, le) for t, le in candidates if 0 < get_time - t <= RULE1_WINDOW_MS]
        if not matching:
            continue

        first_list_time = min(t for t, _ in matching)
        key = f"r1|{actor}|{ns}|{secret_name}"
        if key in seen_findings:
            continue
        seen_findings.add(key)

        target = f"{ns}/{secret_name}"
        yield _build_finding(
            rule_id="r1-secret-enum",
            title="Service account enumerated and read a Kubernetes secret",
            desc=(
                f"Service account '{actor}' performed `list` on secrets in namespace "
                f"'{ns}' and then `get` on secret '{secret_name}' within the "
                f"{RULE1_WINDOW_MS // 1000}-second correlation window. Workloads that "
                f"need secret data should mount secrets as files, not call the K8s "
                f"API for them — this pattern is a strong signal of a compromised "
                f"pod searching for credentials. (MITRE T1552.007)"
            ),
            severity_id=SEVERITY_HIGH,
            tactic_uid=R1_TACTIC_UID,
            tactic_name=R1_TACTIC_NAME,
            technique_uid=R1_TECH_UID,
            technique_name=R1_TECH_NAME,
            sub_technique_uid=R1_SUB_UID,
            sub_technique_name=R1_SUB_NAME,
            actor=actor,
            target=target,
            first_seen_time=first_list_time,
            last_seen_time=get_time,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "namespace", "type": "Other", "value": ns},
                {"name": "secret.name", "type": "Other", "value": secret_name},
                {"name": "rule", "type": "Other", "value": "r1-secret-enum"},
            ],
            evidence_count=len(matching) + 1,
        )


# ---------------------------------------------------------------------------
# Rule 2: Service-account pod exec (T1611)
# ---------------------------------------------------------------------------


def rule2_pod_exec(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """create on pods/exec by a service account."""
    seen: set[str] = set()
    for ev in events:
        if not _is_api_activity(ev):
            continue
        if not _actor_is_service_account(ev):
            continue
        if _verb(ev) != "create":
            continue
        r = _resource(ev)
        if r.get("type") != "pods" or r.get("subresource") != "exec":
            continue
        actor = _actor_name(ev)
        pod = r.get("name", "")
        ns = r.get("namespace", "")
        target = f"{ns}/{pod}"
        key = f"r2|{actor}|{target}"
        if key in seen:
            continue
        seen.add(key)
        t = _event_time(ev)
        yield _build_finding(
            rule_id="r2-pod-exec",
            title="Service account executed a shell inside a pod",
            desc=(
                f"Service account '{actor}' called `create` on pods/exec for pod "
                f"'{pod}' in namespace '{ns}'. Workloads (as opposed to human "
                f"operators) should never exec into other pods — this is the "
                f"precursor to container escape. (MITRE T1611)"
            ),
            severity_id=SEVERITY_CRITICAL,
            tactic_uid=R2_TACTIC_UID,
            tactic_name=R2_TACTIC_NAME,
            technique_uid=R2_TECH_UID,
            technique_name=R2_TECH_NAME,
            sub_technique_uid=None,
            sub_technique_name=None,
            actor=actor,
            target=target,
            first_seen_time=t,
            last_seen_time=t,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "pod.name", "type": "Other", "value": pod},
                {"name": "namespace", "type": "Other", "value": ns},
                {"name": "rule", "type": "Other", "value": "r2-pod-exec"},
            ],
            evidence_count=1,
        )


# ---------------------------------------------------------------------------
# Rule 3: Non-admin creates a RoleBinding / ClusterRoleBinding (T1098)
# ---------------------------------------------------------------------------


def _is_admin(event: dict[str, Any]) -> bool:
    actor = _actor_name(event)
    if actor in ADMIN_USERS:
        return True
    if _actor_groups(event) & ADMIN_GROUPS:
        return True
    return False


def rule3_rbac_self_grant(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """create on rolebindings or clusterrolebindings by a non-admin."""
    seen: set[str] = set()
    for ev in events:
        if not _is_api_activity(ev):
            continue
        if _verb(ev) != "create":
            continue
        r = _resource(ev)
        rtype = r.get("type", "")
        if rtype not in ("rolebindings", "clusterrolebindings"):
            continue
        if _is_admin(ev):
            continue
        actor = _actor_name(ev)
        binding_name = r.get("name", "")
        ns = r.get("namespace", "")
        target = f"{rtype}/{ns}/{binding_name}"
        key = f"r3|{actor}|{target}"
        if key in seen:
            continue
        seen.add(key)
        t = _event_time(ev)
        yield _build_finding(
            rule_id="r3-rbac-self-grant",
            title=f"Non-admin principal created a {rtype[:-1]}",
            desc=(
                f"Principal '{actor}' created {rtype[:-1]} '{binding_name}'"
                f"{f' in namespace {ns}' if ns else ''}. This principal is not "
                f"in system:masters and is not a recognised admin user — creating "
                f"a binding is the canonical K8s privilege-escalation move after "
                f"initial compromise. (MITRE T1098)"
            ),
            severity_id=SEVERITY_CRITICAL,
            tactic_uid=R3_TACTIC_UID,
            tactic_name=R3_TACTIC_NAME,
            technique_uid=R3_TECH_UID,
            technique_name=R3_TECH_NAME,
            sub_technique_uid=None,
            sub_technique_name=None,
            actor=actor,
            target=target,
            first_seen_time=t,
            last_seen_time=t,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "binding.type", "type": "Other", "value": rtype},
                {"name": "binding.name", "type": "Other", "value": binding_name},
                {"name": "namespace", "type": "Other", "value": ns},
                {"name": "rule", "type": "Other", "value": "r3-rbac-self-grant"},
            ],
            evidence_count=1,
        )


# ---------------------------------------------------------------------------
# Rule 4: Service-account token self-grant (T1550.001)
# ---------------------------------------------------------------------------


def rule4_token_self_grant(events: list[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """create on serviceaccounts/token(request) or tokenreviews by a service account."""
    seen: set[str] = set()
    for ev in events:
        if not _is_api_activity(ev):
            continue
        if not _actor_is_service_account(ev):
            continue
        if _verb(ev) != "create":
            continue
        r = _resource(ev)
        rtype = r.get("type", "")
        subres = r.get("subresource", "")
        hit = (rtype == "serviceaccounts" and subres in ("token", "tokenrequest")) or rtype == "tokenreviews"
        if not hit:
            continue
        actor = _actor_name(ev)
        target_sa = r.get("name", "")
        ns = r.get("namespace", "")
        target = f"{ns}/{target_sa}"
        key = f"r4|{actor}|{target}"
        if key in seen:
            continue
        seen.add(key)
        t = _event_time(ev)
        yield _build_finding(
            rule_id="r4-token-self-grant",
            title="Service account issued itself (or another SA) an API token",
            desc=(
                f"Service account '{actor}' created a token for '{target_sa or 'tokenreview'}' "
                f"in namespace '{ns}'. Combined with secret access or RBAC "
                f"manipulation this is token-theft in progress. (MITRE T1550.001)"
            ),
            severity_id=SEVERITY_HIGH,
            tactic_uid=R4_TACTIC_UID,
            tactic_name=R4_TACTIC_NAME,
            technique_uid=R4_TECH_UID,
            technique_name=R4_TECH_NAME,
            sub_technique_uid=R4_SUB_UID,
            sub_technique_name=R4_SUB_NAME,
            actor=actor,
            target=target,
            first_seen_time=t,
            last_seen_time=t,
            observables=[
                {"name": "actor.name", "type": "Other", "value": actor},
                {"name": "target.serviceaccount", "type": "Other", "value": target_sa},
                {"name": "namespace", "type": "Other", "value": ns},
                {"name": "rule", "type": "Other", "value": "r4-token-self-grant"},
            ],
            evidence_count=1,
        )


# ---------------------------------------------------------------------------
# Main detect entry point
# ---------------------------------------------------------------------------


def detect(events: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """Run all four rules over an event stream and yield all findings.

    Events are materialised into a list so rules can make two passes (needed
    for Rule 1's correlation). Findings are yielded in deterministic order:
    r1 findings, then r2, then r3, then r4, each in event-time order.
    """
    events_list = list(events)
    # Sort by time for deterministic output
    events_list.sort(key=_event_time)

    yield from rule1_secret_enumeration(events_list)
    yield from rule2_pod_exec(events_list)
    yield from rule3_rbac_self_grant(events_list)
    yield from rule4_token_self_grant(events_list)


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
    parser = argparse.ArgumentParser(description="Detect K8s privilege escalation from OCSF API Activity events.")
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="OCSF Detection Finding JSONL output. Defaults to stdout.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
