"""Ingest scan results from agent-bom (SARIF/JSON) and upload to S3 trigger bucket."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3

logger = logging.getLogger(__name__)

FINDINGS_BUCKET = os.environ.get("FINDINGS_BUCKET", "vuln-remediation-findings")


def detect_format(data: dict[str, Any]) -> str:
    """Detect whether input is SARIF or agent-bom JSON."""
    if "$schema" in data and "sarif" in data.get("$schema", ""):
        return "sarif"
    if "vulnerabilities" in data:
        return "agent-bom-json"
    if "runs" in data:
        return "sarif"
    return "unknown"


def load_findings(path: str | Path) -> dict[str, Any]:
    """Load findings from a local file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Findings file not found: {path}")
    if path.suffix.lower() not in (".json", ".sarif"):
        raise ValueError(f"Unsupported file format: {path.suffix}")

    with open(path) as f:
        data = json.load(f)

    fmt = detect_format(data)
    if fmt == "unknown":
        raise ValueError("Could not detect format — expected SARIF or agent-bom JSON")

    logger.info("Loaded %s findings from %s", fmt, path)
    return data


def upload_to_s3(
    data: dict[str, Any],
    bucket: str | None = None,
    prefix: str = "incoming",
) -> str:
    """Upload findings JSON to S3 trigger bucket.

    Returns the S3 key.
    """
    bucket = bucket or FINDINGS_BUCKET
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fmt = detect_format(data)
    ext = "sarif" if fmt == "sarif" else "json"
    key = f"{prefix}/{timestamp}.{ext}"

    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(data),
        ContentType="application/json",
        ServerSideEncryption="aws:kms",
    )

    logger.info("Uploaded findings to s3://%s/%s", bucket, key)
    return key


def ingest_and_upload(path: str | Path, bucket: str | None = None) -> str:
    """Load findings from local file and upload to S3.

    Returns the S3 key for the uploaded file.
    """
    data = load_findings(path)
    return upload_to_s3(data, bucket=bucket)
