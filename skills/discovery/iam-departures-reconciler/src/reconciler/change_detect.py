"""Change detection — row-level hash diff for manifest planning.

Compares the current normalized departure set to a previously stored content
hash so runners can decide whether to persist and fan out a new manifest.

Algorithm:
    1. Sort all DepartureRecords deterministically (email + account_id)
    2. Compute SHA-256 of the full serialized payload
    3. Compare against the previously stored hash in S3
    4. Export only if hashes differ
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reconciler.sources import DepartureRecord

logger = logging.getLogger(__name__)


class ChangeDetector:
    """Detect changes in the departures table via content hashing."""

    HASH_KEY = "departures/.last_hash"

    def __init__(self, s3_client: Any, bucket: str) -> None:
        self.s3 = s3_client
        self.bucket = bucket

    def compute_hash(self, records: list[DepartureRecord]) -> str:
        """Compute deterministic SHA-256 hash of the record set.

        Records are sorted by (email, recipient_account_id) to ensure
        consistent hashing regardless of query ordering.
        """
        sorted_records = sorted(
            records,
            key=lambda r: (r.email, r.recipient_account_id),
        )
        stable_records = []
        for record in sorted_records:
            payload = record.to_dict()
            # Observation timestamps change every run and should not trigger
            # a remediation export when the underlying departure data is unchanged.
            payload.pop("last_checked_at", None)
            stable_records.append(payload)
        canonical_payload = json.dumps(
            stable_records,
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

    def get_previous_hash(self) -> str | None:
        """Read the last-known hash from S3.

        Returns None if no previous hash exists (first run).
        """
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=self.HASH_KEY)
            return response["Body"].read().decode("utf-8").strip()
        except self.s3.exceptions.NoSuchKey:
            logger.info("No previous hash found — first run")
            return None
        except Exception:
            logger.exception("Failed to read previous hash from S3")
            return None

    def has_changed(self, records: list[DepartureRecord]) -> tuple[bool, str]:
        """Check if the record set has changed since last export.

        Returns:
            (changed: bool, current_hash: str)
        """
        current_hash = self.compute_hash(records)
        previous_hash = self.get_previous_hash()

        if previous_hash is None:
            logger.info("No previous hash — treating as changed")
            return True, current_hash

        changed = current_hash != previous_hash
        if changed:
            logger.info(
                "Data changed: %s → %s",
                previous_hash[:12],
                current_hash[:12],
            )
        else:
            logger.info("No changes detected (hash: %s)", current_hash[:12])

        return changed, current_hash
