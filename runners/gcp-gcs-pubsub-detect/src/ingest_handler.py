from __future__ import annotations

import os
import shlex
import subprocess
from typing import Any

try:
    from google.cloud import pubsub_v1, storage
except ImportError:  # pragma: no cover - exercised only in minimal local test envs
    pubsub_v1 = None
    storage = None


def _storage_client():
    if storage is None:
        raise RuntimeError("google-cloud-storage is required for the GCP runner")
    return storage.Client()


def _publisher_client():
    if pubsub_v1 is None:
        raise RuntimeError("google-cloud-pubsub is required for the GCP runner")
    return pubsub_v1.PublisherClient()


def _skill_command() -> list[str]:
    raw = os.environ.get("INGEST_SKILL_CMD", "").strip()
    if not raw:
        raise ValueError("INGEST_SKILL_CMD is required")
    return shlex.split(raw)


def _detect_topic() -> str:
    topic = os.environ.get("DETECT_TOPIC", "").strip()
    if not topic:
        raise ValueError("DETECT_TOPIC is required")
    return topic


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


def _read_object(bucket: str, name: str) -> str:
    blob = _storage_client().bucket(bucket).blob(name)
    return blob.download_as_text()


def _event_data(event: Any) -> dict[str, Any]:
    # 2nd gen functions receive a CloudEvent (payload on `.data`); 1st gen
    # background functions receive the payload dict directly.
    data = getattr(event, "data", event)
    if not isinstance(data, dict):
        raise ValueError("storage event payload must be a JSON object")
    return data


def handle_gcs_event(event: Any, _context: Any = None) -> dict[str, int]:
    data = _event_data(event)
    bucket = data.get("bucket")
    name = data.get("name")
    if not isinstance(bucket, str) or not bucket or not isinstance(name, str) or not name:
        raise ValueError("storage event is missing bucket or name")
    payload = _read_object(bucket, name)
    lines = _run_skill(payload)

    topic = _detect_topic()
    published = 0
    publisher = _publisher_client()
    for line in lines:
        publisher.publish(topic, line.encode("utf-8"))
        published += 1

    return {"objects_processed": 1, "messages_enqueued": published}
