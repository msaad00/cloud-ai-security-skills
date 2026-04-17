from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

SKILL_NAME = "azure-blob-eventgrid-detect"
_DEFAULT_DEDUPE_TTL_DAYS = 30
_MAX_SERVICE_BUS_SEND = 100
_SECONDS_PER_DAY = 86_400


def _skill_command() -> list[str]:
    raw = os.environ.get("DETECT_SKILL_CMD", "").strip()
    if not raw:
        raise ValueError("DETECT_SKILL_CMD is required")
    return shlex.split(raw)


def _service_bus_fqdn() -> str:
    fqdn = os.environ.get("SERVICE_BUS_FQDN", "").strip()
    if not fqdn:
        raise ValueError("SERVICE_BUS_FQDN is required")
    return fqdn


def _alert_topic_name() -> str:
    topic = os.environ.get("ALERT_TOPIC_NAME", "").strip()
    if not topic:
        raise ValueError("ALERT_TOPIC_NAME is required")
    return topic


def _dedupe_table_name() -> str:
    table_name = os.environ.get("DEDUPE_TABLE_NAME", "").strip()
    if not table_name:
        raise ValueError("DEDUPE_TABLE_NAME is required")
    return table_name


def _table_account_url() -> str:
    url = os.environ.get("TABLE_ACCOUNT_URL", "").strip()
    if not url:
        raise ValueError("TABLE_ACCOUNT_URL is required")
    return url


def _dedupe_ttl_days() -> int:
    raw = os.environ.get("DEDUPE_TTL_DAYS", "").strip()
    if not raw:
        return _DEFAULT_DEDUPE_TTL_DAYS
    try:
        days = int(raw)
    except ValueError as exc:
        raise ValueError(f"DEDUPE_TTL_DAYS must be an integer, got {raw!r}") from exc
    if days < 1 or days > 365:
        raise ValueError(f"DEDUPE_TTL_DAYS must be between 1 and 365, got {days}")
    return days


def _expires_at(now: float | None = None) -> int:
    current = time.time() if now is None else now
    return int(current) + _dedupe_ttl_days() * _SECONDS_PER_DAY


def _entity_is_expired(entity: dict[str, Any], now: float | None = None) -> bool:
    expires_at = entity.get("expires_at")
    if not isinstance(expires_at, int):
        return False
    current = time.time() if now is None else now
    return expires_at <= int(current)


def _batched(items: list[tuple[str, str]], size: int) -> list[list[tuple[str, str]]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _run_skill(lines: list[str]) -> list[str]:
    completed = subprocess.run(
        _skill_command(),
        input="\n".join(lines) + ("\n" if lines else ""),
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "detect skill failed")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _extract_uid(record: dict[str, Any]) -> str:
    finding_info = record.get("finding_info")
    if isinstance(finding_info, dict):
        uid = finding_info.get("uid")
        if isinstance(uid, str) and uid:
            return uid

    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        uid = metadata.get("uid")
        if isinstance(uid, str) and uid:
            return uid

    event_uid = record.get("event_uid")
    if isinstance(event_uid, str) and event_uid:
        return event_uid

    raise ValueError("record is missing finding_info.uid, metadata.uid, and event_uid")


def _dedupe_table():
    from azure.data.tables import TableServiceClient
    from azure.identity import DefaultAzureCredential

    service = TableServiceClient(
        endpoint=_table_account_url(),
        credential=DefaultAzureCredential(),
    )
    table = service.get_table_client(table_name=_dedupe_table_name())
    table.create_table_if_not_exists()
    return table


def _put_if_new(uid: str, payload: str) -> bool:
    from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError

    table = _dedupe_table()
    item = {
        "PartitionKey": "finding",
        "RowKey": uid,
        "seen_at": datetime.now(UTC).isoformat(),
        "payload_sha256": sha256(payload.encode("utf-8")).hexdigest(),
        "expires_at": _expires_at(),
    }
    try:
        table.create_entity(entity=item)
        return True
    except ResourceExistsError:
        try:
            existing = table.get_entity(partition_key="finding", row_key=uid)
        except ResourceNotFoundError:
            table.create_entity(entity=item)
            return True
        if _entity_is_expired(existing):
            table.delete_entity(partition_key="finding", row_key=uid)
            table.create_entity(entity=item)
            return True
        return False


def _publish_findings(records: list[tuple[str, str]]) -> None:
    from azure.identity import DefaultAzureCredential
    from azure.servicebus import ServiceBusClient, ServiceBusMessage

    client = ServiceBusClient(
        fully_qualified_namespace=_service_bus_fqdn(),
        credential=DefaultAzureCredential(),
    )
    with client:
        sender = client.get_topic_sender(topic_name=_alert_topic_name())
        with sender:
            for batch in _batched(records, _MAX_SERVICE_BUS_SEND):
                sender.send_messages(
                    [ServiceBusMessage(line, subject=f"skill-finding:{uid}") for line, uid in batch]
                )


def handle_detect_messages(messages: list[str]) -> dict[str, int]:
    findings = _run_skill(messages)
    to_publish: list[tuple[str, str]] = []
    duplicates = 0
    for line in findings:
        record = json.loads(line)
        uid = _extract_uid(record)
        if _put_if_new(uid, line):
            to_publish.append((line, uid))
        else:
            duplicates += 1
    if to_publish:
        _publish_findings(to_publish)
    return {
        "messages_processed": len(messages),
        "published": len(to_publish),
        "duplicates": duplicates,
    }
