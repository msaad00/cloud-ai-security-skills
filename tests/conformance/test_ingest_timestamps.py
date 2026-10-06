"""Conformance: ingesters share one timestamp parser and never invent "now".

A record whose source timestamp is missing or unparseable is skipped with a
structured `timestamp_unparseable` warning (OCSF_CONTRACT.md, "Event time").
Substituting the wall clock made finding uids and windowed detections differ
between replays of the same input.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_DIR = REPO_ROOT / "skills" / "detection-engineering" / "golden"
INGEST_SOURCES = sorted((REPO_ROOT / "skills" / "ingestion").glob("ingest-*/src/*.py"))

LOCAL_PARSER_NAMES = {"parse_ts_ms", "_now_ms", "sec_to_ms"}
CLOCK_OR_PARSE_ATTRS = {
    "fromisoformat",
    "strptime",
    "now",
    "utcnow",
    "fromtimestamp",
    "utcfromtimestamp",
    "time_ns",
}


def _ids(paths: list[Path]) -> list[str]:
    return [p.parts[-3] for p in paths]


def test_every_ocsf_ingester_is_covered() -> None:
    assert len(INGEST_SOURCES) >= 25


@pytest.mark.parametrize("source", INGEST_SOURCES, ids=_ids(INGEST_SOURCES))
def test_ingester_has_no_private_timestamp_parser_or_clock(source: Path) -> None:
    tree = ast.parse(source.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assert node.name not in LOCAL_PARSER_NAMES, f"{source}:{node.lineno} {node.name}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            target = ast.unparse(node.func.value)
            assert attr not in CLOCK_OR_PARSE_ATTRS, f"{source}:{node.lineno} .{attr}()"
            assert not (target == "time" and attr == "time"), f"{source}:{node.lineno}"


@pytest.mark.parametrize("source", INGEST_SOURCES, ids=_ids(INGEST_SOURCES))
def test_ingester_uses_shared_timestamp_helper(source: Path) -> None:
    assert "from skills._shared.timestamps import" in source.read_text(encoding="utf-8")


def _garble_key(value: object, key: str) -> object:
    if isinstance(value, dict):
        return {k: "not-a-timestamp" if k == key else _garble_key(v, key) for k, v in value.items()}
    if isinstance(value, list):
        return [_garble_key(v, key) for v in value]
    return value


def _with_unparseable_timestamps(fixture: str, key: str) -> str:
    text = (GOLDEN_DIR / fixture).read_text(encoding="utf-8")
    try:
        return json.dumps(_garble_key(json.loads(text), key))
    except json.JSONDecodeError:
        return "\n".join(
            json.dumps(_garble_key(json.loads(line), key)) for line in text.splitlines() if line
        )


def _pipe(ingest_skill: str, detect_skill: str, raw: str) -> tuple[str, str]:
    env = {**os.environ, "SKILL_LOG_FORMAT": "json"}
    ingested = subprocess.run(
        [sys.executable, str(REPO_ROOT / "skills/ingestion" / ingest_skill / "src/ingest.py")],
        input=raw,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    detected = subprocess.run(
        [sys.executable, str(REPO_ROOT / "skills/detection" / detect_skill / "src/detect.py")],
        input=ingested.stdout,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    return detected.stdout, ingested.stderr


REPLAY_CASES = [
    (
        "ingest-cloudtrail-ocsf",
        "detect-aws-open-security-group",
        "aws_open_security_group_raw.jsonl",
        "eventTime",
    ),
    (
        "ingest-cloudtrail-ocsf",
        "detect-aws-access-key-creation",
        "cloudtrail_raw_sample.jsonl",
        "eventTime",
    ),
    (
        "ingest-okta-system-log-ocsf",
        "detect-okta-mfa-fatigue",
        "okta_mfa_fatigue_raw.json",
        "published",
    ),
    (
        "ingest-k8s-audit-ocsf",
        "detect-privilege-escalation-k8s",
        "k8s_audit_raw_sample.jsonl",
        "requestReceivedTimestamp",
    ),
]


@pytest.mark.parametrize(
    ("ingest_skill", "detect_skill", "fixture", "key"),
    REPLAY_CASES,
    ids=[case[1] for case in REPLAY_CASES],
)
def test_replay_with_unparseable_source_timestamps_is_deterministic(
    ingest_skill: str, detect_skill: str, fixture: str, key: str
) -> None:
    raw = _with_unparseable_timestamps(fixture, key)
    first, first_stderr = _pipe(ingest_skill, detect_skill, raw)
    second, _ = _pipe(ingest_skill, detect_skill, raw)

    assert first == second
    assert first == ""
    events = [json.loads(line) for line in first_stderr.splitlines() if line.startswith("{")]
    skipped = [e for e in events if e["event"] == "timestamp_unparseable"]
    assert skipped
    assert all(e["skill"] == ingest_skill and isinstance(e["record"], int) for e in skipped)


INGESTION_DIR = REPO_ROOT / "skills" / "ingestion"
GARBAGE = "not-a-timestamp"


def _json_inline(payload: object) -> str:
    return json.dumps(payload)


SALESFORCE_RECORD = {
    "EVENT_TYPE": "ReportExport",
    "TIMESTAMP": "2026-06-08T12:00:00.000Z",
    "USER_ID": "005xx000001",
    "USERNAME": "analyst@example.com",
    "REQUEST_ID": "req-1",
}
SAP_RECORD = {
    "timestamp": "2026-06-08T12:00:00Z",
    "client": "100",
    "user": "SAP*",
    "message_id": "AUDIT_LOGON",
    "message_text": "User SAP* successful logon with profile SAP_ALL",
}
WORKDAY_RECORD = {
    "eventName": "Terminate Employee",
    "eventTime": "2026-06-06T14:30:00Z",
    "workerId": "W-1001",
    "workerEmail": "departed@example.com",
    "businessProcess": "Terminate Employee",
}
WORKSPACE_ADMIN_ACTIVITY = {
    "id": {
        "time": "2026-06-06T04:00:00.000Z",
        "uniqueQualifier": "login-1",
        "applicationName": "login",
        "customerId": "C123",
    },
    "actor": {"email": "alice@example.com", "profileId": "1001", "callerType": "USER"},
    "events": [{"type": "event", "name": "login_success", "parameters": []}],
}

# (ingester, source text, timestamp keys to garble). Text sources are either a
# golden fixture path relative to the repo or an inline JSON document.
SKIP_CASES: list[tuple[str, str, tuple[str, ...]]] = [
    (
        "ingest-aws-config-ocsf",
        "golden:aws_config_raw_sample.json",
        (
            "configurationItemCaptureTime",
            "configurationItemDeliveryTime",
            "NotificationCreateTime",
            "resultRecordedTime",
            "notificationCreationTime",
            "orderingTimestamp",
        ),
    ),
    ("ingest-azure-activity-ocsf", "golden:azure_activity_raw_sample.jsonl", ("time",)),
    (
        "ingest-azure-defender-for-cloud-ocsf",
        "golden:azure_defender_raw_sample.json",
        ("timeGeneratedUtc", "startTimeUtc"),
    ),
    ("ingest-cloudtrail-ocsf", "golden:cloudtrail_raw_sample.jsonl", ("eventTime",)),
    ("ingest-databricks-audit-ocsf", "golden:databricks_token_creation_raw.jsonl", ("timestamp",)),
    (
        "ingest-entra-directory-audit-ocsf",
        "golden:entra_directory_audit_raw_sample.json",
        ("activityDateTime",),
    ),
    ("ingest-gcp-audit-ocsf", "golden:gcp_audit_raw_sample.jsonl", ("timestamp",)),
    ("ingest-gcp-scc-ocsf", "golden:gcp_scc_raw_sample.json", ("eventTime", "createTime")),
    (
        "ingest-github-audit-log-ocsf",
        "skills/ingestion/ingest-github-audit-log-ocsf/tests/golden/github_audit_log_raw_sample.json",
        ("@timestamp", "created_at"),
    ),
    (
        "ingest-google-workspace-login-ocsf",
        "golden:google_workspace_login_raw_sample.json",
        ("time",),
    ),
    ("ingest-guardduty-ocsf", "golden:guardduty_raw_sample.json", ("UpdatedAt", "CreatedAt")),
    ("ingest-k8s-audit-ocsf", "golden:k8s_audit_raw_sample.jsonl", ("requestReceivedTimestamp",)),
    ("ingest-mcp-proxy-ocsf", "golden:mcp_proxy_raw_sample.jsonl", ("timestamp",)),
    ("ingest-okta-system-log-ocsf", "golden:okta_system_log_raw_sample.json", ("published",)),
    (
        "ingest-salesforce-event-mon-ocsf",
        _json_inline({"records": [SALESFORCE_RECORD]}),
        ("TIMESTAMP",),
    ),
    ("ingest-sap-audit-log-ocsf", _json_inline({"SecurityAuditLog": [SAP_RECORD]}), ("timestamp",)),
    ("ingest-security-hub-ocsf", "golden:security_hub_raw_sample.json", ("UpdatedAt",)),
    (
        "ingest-slack-audit-ocsf",
        "skills/ingestion/ingest-slack-audit-ocsf/tests/golden/slack_audit_raw_sample.json",
        ("date_create",),
    ),
    (
        "ingest-snowflake-login-history-ocsf",
        "golden:snowflake_failed_mfa_burst_raw.jsonl",
        ("EVENT_TIMESTAMP",),
    ),
    (
        "ingest-snowflake-query-history-ocsf",
        "golden:snowflake_share_creation_raw.jsonl",
        ("START_TIME",),
    ),
    (
        "ingest-vpc-flow-logs-gcp-ocsf",
        "golden:gcp_vpc_flow_logs_raw_sample.jsonl",
        ("start_time", "end_time", "timestamp"),
    ),
    ("ingest-workday-audit-ocsf", _json_inline({"Report_Entry": [WORKDAY_RECORD]}), ("eventTime",)),
    ("ingest-workspace-admin-ocsf", _json_inline({"items": [WORKSPACE_ADMIN_ACTIVITY]}), ("time",)),
]


def _source_text(source: str) -> str:
    if source.startswith("golden:"):
        return (GOLDEN_DIR / source.removeprefix("golden:")).read_text(encoding="utf-8")
    if source.startswith("skills/"):
        return (REPO_ROOT / source).read_text(encoding="utf-8")
    return source


def _garble_keys(text: str, keys: tuple[str, ...]) -> str:
    def garble(value: object) -> object:
        if isinstance(value, dict):
            return {k: GARBAGE if k in keys else garble(v) for k, v in value.items()}
        if isinstance(value, list):
            return [garble(v) for v in value]
        if isinstance(value, str) and value.startswith("{"):
            return json.dumps(garble(json.loads(value)))
        return value

    try:
        return json.dumps(garble(json.loads(text)))
    except json.JSONDecodeError:
        return "\n".join(json.dumps(garble(json.loads(line))) for line in text.splitlines() if line)


def _garble_nsg(text: str) -> str:
    payload = json.loads(text)
    for record in payload["records"]:
        for group in record["properties"]["flows"]:
            for flow in group["flows"]:
                flow["flowTuples"] = [
                    GARBAGE + "," + t.split(",", 1)[1] for t in flow["flowTuples"]
                ]
    return json.dumps(payload)


def _garble_vpc(text: str) -> str:
    lines = text.splitlines()
    header = lines[0].split()
    start, end = header.index("start"), header.index("end")
    out = [lines[0]]
    for line in lines[1:]:
        cols = line.split()
        if len(cols) == len(header):
            cols[start] = cols[end] = "-"
        out.append(" ".join(cols))
    return "\n".join(out)


SKIP_CASES_CUSTOM = [
    ("ingest-nsg-flow-logs-azure-ocsf", "golden:azure_nsg_flow_logs_raw_sample.json", _garble_nsg),
    ("ingest-vpc-flow-logs-ocsf", "golden:vpc_flow_logs_raw_sample.log", _garble_vpc),
]


def _load_ingest(skill: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        f"_ts_conformance_{skill.replace('-', '_')}", INGESTION_DIR / skill / "src" / "ingest.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_ingest(skill: str, text: str) -> list[dict]:
    return list(_load_ingest(skill).ingest(text.splitlines()))


def _all_skip_cases():
    for skill, source, keys in SKIP_CASES:
        yield skill, source, lambda text, keys=keys: _garble_keys(text, keys)
    yield from SKIP_CASES_CUSTOM


ALL_SKIP_CASES = list(_all_skip_cases())


def test_skip_cases_cover_every_ingester() -> None:
    assert {case[0] for case in ALL_SKIP_CASES} == {p.parts[-3] for p in INGEST_SOURCES}


@pytest.mark.parametrize(
    ("skill", "source", "garble"), ALL_SKIP_CASES, ids=[c[0] for c in ALL_SKIP_CASES]
)
def test_unparseable_timestamp_skips_record_with_structured_warning(
    skill: str, source: str, garble, capsys, monkeypatch
) -> None:
    monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
    text = _source_text(source)
    assert _run_ingest(skill, text), "fixture must convert cleanly before garbling"
    capsys.readouterr()

    assert _run_ingest(skill, garble(text)) == []
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    skipped = [e for e in events if e["event"] == "timestamp_unparseable"]
    assert skipped, events
    for event in skipped:
        assert event["skill"] == skill
        assert event["level"] == "warning"
        assert isinstance(event["record"], int) and event["record"] >= 1
        assert GARBAGE not in json.dumps(event)
