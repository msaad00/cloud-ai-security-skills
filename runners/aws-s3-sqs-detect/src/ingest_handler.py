from __future__ import annotations

import os
import shlex
import subprocess
from collections.abc import Iterable
from typing import Any

try:
    import boto3
except ImportError:  # pragma: no cover - exercised only in minimal local test envs
    boto3 = None


def _s3_client():
    if boto3 is None:
        raise RuntimeError("boto3 is required for the AWS runner")
    return boto3.client("s3")


def _sqs_client():
    if boto3 is None:
        raise RuntimeError("boto3 is required for the AWS runner")
    return boto3.client("sqs")


def _skill_command() -> list[str]:
    raw = os.environ.get("INGEST_SKILL_CMD", "").strip()
    if not raw:
        raise ValueError("INGEST_SKILL_CMD is required")
    return shlex.split(raw)


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


def _batched(values: Iterable[str], size: int = 10) -> Iterable[list[str]]:
    batch: list[str] = []
    for value in values:
        batch.append(value)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def _queue_url() -> str:
    url = os.environ.get("DETECT_QUEUE_URL", "").strip()
    if not url:
        raise ValueError("DETECT_QUEUE_URL is required")
    return url


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, int]:
    total_records = 0
    total_messages = 0

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]
        obj = _s3_client().get_object(Bucket=bucket, Key=key)
        payload = obj["Body"].read().decode("utf-8")
        lines = _run_skill(payload)
        total_records += 1
        for line in lines:
            _sqs_client().send_message(QueueUrl=_queue_url(), MessageBody=line)
            total_messages += 1

    return {"objects_processed": total_records, "messages_enqueued": total_messages}
