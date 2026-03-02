"""S3 exporter — writes change-detected remediation manifests.

Exports only fire when ChangeDetector confirms the data has changed.
Each export is a dated JSON file that triggers EventBridge → Step Function.

S3 layout:
    s3://{bucket}/departures/YYYY-MM-DD.json     — daily manifest
    s3://{bucket}/departures/.last_hash           — change detection hash
    s3://{bucket}/departures/audit/               — remediation audit logs
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reconciler.sources import DepartureRecord

logger = logging.getLogger(__name__)


class S3Exporter:
    """Export remediation manifests to S3 with change detection."""

    def __init__(self, s3_client: Any, bucket: str) -> None:
        self.s3 = s3_client
        self.bucket = bucket

    def export_manifest(
        self,
        records: list[DepartureRecord],
        source: str,
        content_hash: str,
    ) -> str:
        """Write the remediation manifest to S3.

        Args:
            records: Departure records to export.
            source: HR source name (e.g., 'snowflake').
            content_hash: SHA-256 hash for deduplication tracking.

        Returns:
            S3 key of the exported manifest.
        """
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        s3_key = f"departures/{date_str}.json"

        # Filter to only actionable records
        actionable = [r for r in records if r.should_remediate()]
        skipped = [r for r in records if not r.should_remediate()]

        manifest = {
            "export_timestamp": now.isoformat(),
            "source": source,
            "hash": content_hash,
            "total_records": len(records),
            "actionable_count": len(actionable),
            "skipped_count": len(skipped),
            "skip_reasons": self._summarize_skips(skipped),
            "entries": [r.to_dict() for r in actionable],
        }

        body = json.dumps(manifest, indent=2, default=str)
        self.s3.put_object(
            Bucket=self.bucket,
            Key=s3_key,
            Body=body.encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            Metadata={
                "source": source,
                "hash": content_hash,
                "actionable-count": str(len(actionable)),
            },
        )

        logger.info(
            "Exported manifest: s3://%s/%s (%d actionable, %d skipped)",
            self.bucket,
            s3_key,
            len(actionable),
            len(skipped),
        )
        return s3_key

    def export_audit_log(self, audit_entries: list[dict]) -> str:
        """Write remediation audit log to S3.

        Called after Lambda 2 completes remediation to record
        what was done, by whom, and when — for compliance.
        """
        now = datetime.now(timezone.utc)
        s3_key = f"departures/audit/{now.strftime('%Y-%m-%dT%H-%M-%S')}.json"

        body = json.dumps(
            {
                "audit_timestamp": now.isoformat(),
                "entry_count": len(audit_entries),
                "entries": audit_entries,
            },
            indent=2,
            default=str,
        )

        self.s3.put_object(
            Bucket=self.bucket,
            Key=s3_key,
            Body=body.encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
        )

        logger.info("Exported audit log: s3://%s/%s", self.bucket, s3_key)
        return s3_key

    @staticmethod
    def _summarize_skips(skipped: list[DepartureRecord]) -> dict[str, int]:
        """Categorize why records were skipped."""
        reasons: dict[str, int] = {
            "iam_already_deleted": 0,
            "rehire_same_iam": 0,
            "already_remediated": 0,
            "no_termination_date": 0,
        }
        for r in skipped:
            if r.iam_deleted:
                reasons["iam_already_deleted"] += 1
            elif r.is_rehire and r.iam_last_used_at and r.rehire_date and r.iam_last_used_at > r.rehire_date:
                reasons["rehire_same_iam"] += 1
            elif r.remediation_status.value == "remediated":
                reasons["already_remediated"] += 1
            else:
                reasons["no_termination_date"] += 1
        return {k: v for k, v in reasons.items() if v > 0}
