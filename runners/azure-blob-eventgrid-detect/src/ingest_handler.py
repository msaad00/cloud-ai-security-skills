from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections.abc import Iterable
from typing import Any

SKILL_NAME = "azure-blob-eventgrid-detect"


def _skill_command() -> list[str]:
    raw = os.environ.get("INGEST_SKILL_CMD", "").strip()
    if not raw:
        raise ValueError("INGEST_SKILL_CMD is required")
    return shlex.split(raw)


def _service_bus_fqdn() -> str:
    fqdn = os.environ.get("SERVICE_BUS_FQDN", "").strip()
    if not fqdn:
        raise ValueError("SERVICE_BUS_FQDN is required")
    return fqdn


def _ingest_queue_name() -> str:
    queue_name = os.environ.get("DETECT_QUEUE_NAME", "").strip()
    if not queue_name:
        raise ValueError("DETECT_QUEUE_NAME is required")
    return queue_name


def _event_payloads(message_body: str) -> list[dict[str, Any]]:
    parsed = json.loads(message_body)
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    raise ValueError("Event Grid payload must be a JSON object or array of objects")


def _blob_url(event: dict[str, Any]) -> str:
    data = event.get("data")
    if isinstance(data, dict):
        url = data.get("url") or data.get("blobUrl")
        if isinstance(url, str) and url.strip():
            return url.strip()
    raise ValueError("Event Grid blob event is missing data.url")


def _download_blob_text(blob_url: str) -> str:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobClient

    blob = BlobClient.from_blob_url(blob_url, credential=DefaultAzureCredential())
    return blob.download_blob().readall().decode("utf-8")


def _run_skill(payload: str) -> list[str]:
    completed = subprocess.run(
        _skill_command(),
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "ingest skill failed")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _enqueue_detect_lines(lines: Iterable[str]) -> int:
    from azure.identity import DefaultAzureCredential
    from azure.servicebus import ServiceBusClient, ServiceBusMessage

    client = ServiceBusClient(
        fully_qualified_namespace=_service_bus_fqdn(),
        credential=DefaultAzureCredential(),
    )
    total = 0
    with client:
        sender = client.get_queue_sender(queue_name=_ingest_queue_name())
        with sender:
            for line in lines:
                if not line.strip():
                    continue
                sender.send_messages(ServiceBusMessage(line))
                total += 1
    return total


def handle_ingest_message(message_body: str) -> dict[str, int]:
    events = _event_payloads(message_body)
    blobs_processed = 0
    messages_enqueued = 0
    for event in events:
        payload = _download_blob_text(_blob_url(event))
        lines = _run_skill(payload)
        blobs_processed += 1
        messages_enqueued += _enqueue_detect_lines(lines)
    return {
        "blob_events_processed": len(events),
        "blobs_processed": blobs_processed,
        "messages_enqueued": messages_enqueued,
    }


def handle_ingest_messages(messages: list[str]) -> dict[str, int]:
    totals = {
        "queue_messages_processed": len(messages),
        "blob_events_processed": 0,
        "blobs_processed": 0,
        "messages_enqueued": 0,
    }
    for body in messages:
        result = handle_ingest_message(body)
        for key in ("blob_events_processed", "blobs_processed", "messages_enqueued"):
            totals[key] += result[key]
    return totals
