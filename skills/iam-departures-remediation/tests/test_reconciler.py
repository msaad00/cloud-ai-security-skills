"""Tests for the reconciler module — sources, change detection, export."""

from __future__ import annotations

import json
import os

# We test the source code directly by adding the src dir to path
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reconciler.change_detect import ChangeDetector
from reconciler.export import S3Exporter
from reconciler.sources import (
    DepartureRecord,
    RemediationStatus,
    TerminationSource,
    get_source,
)

# ── Fixtures ────────────────────────────────────────────────────────

# Frozen reference time so record_hash is deterministic across calls.
# (Using datetime.now() inside the fixture made identical calls produce
# different hashes, which broke test_record_hash_deterministic.)
_FROZEN_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _now() -> datetime:
    return _FROZEN_NOW


def _days_ago(n: int) -> datetime:
    return _now() - timedelta(days=n)


# Sentinel so callers can pass terminated_at=None explicitly without the
# fallback turning it into "30 days ago".
_UNSET = object()


def _make_record(
    email: str = "jane.doe@company.com",
    account_id: str = "123456789012",
    iam_username: str = "jane.doe",
    terminated_at=_UNSET,
    is_rehire: bool = False,
    rehire_date: datetime | None = None,
    iam_deleted: bool = False,
    iam_last_used_at: datetime | None = None,
    iam_created_at: datetime | None = None,
    status: RemediationStatus = RemediationStatus.PENDING,
) -> DepartureRecord:
    if terminated_at is _UNSET:
        terminated_at = _days_ago(30)
    if iam_created_at is None:
        iam_created_at = _days_ago(365)
    return DepartureRecord(
        email=email,
        recipient_account_id=account_id,
        iam_username=iam_username,
        iam_created_at=iam_created_at,
        terminated_at=terminated_at,
        termination_source=TerminationSource.SNOWFLAKE,
        is_rehire=is_rehire,
        rehire_date=rehire_date,
        iam_deleted=iam_deleted,
        iam_last_used_at=iam_last_used_at,
        remediation_status=status,
    )


# ── DepartureRecord Tests ──────────────────────────────────────────


class TestDepartureRecord:
    """Test the core DepartureRecord data model."""

    def test_basic_termination_should_remediate(self):
        """Standard case: terminated, not rehired → remediate."""
        record = _make_record(terminated_at=_days_ago(30))
        assert record.should_remediate() is True

    def test_already_deleted_should_not_remediate(self):
        """IAM already deleted by admin → skip."""
        record = _make_record(iam_deleted=True)
        assert record.should_remediate() is False

    def test_already_remediated_should_not_remediate(self):
        """Already processed → skip."""
        record = _make_record(status=RemediationStatus.REMEDIATED)
        assert record.should_remediate() is False

    def test_no_termination_date_should_not_remediate(self):
        """Still employed → skip."""
        record = _make_record(terminated_at=None)
        assert record.should_remediate() is False

    def test_rehire_same_iam_in_use_should_not_remediate(self):
        """Rehired + same IAM used after rehire → skip.

        Scenario: Employee terminated, rehired 2 weeks later, using
        the same IAM user in their new role.
        """
        record = _make_record(
            terminated_at=_days_ago(60),
            is_rehire=True,
            rehire_date=_days_ago(30),
            iam_last_used_at=_days_ago(5),  # Used after rehire
        )
        assert record.should_remediate() is False

    def test_rehire_different_iam_should_remediate_old(self):
        """Rehired + old IAM NOT used after rehire → remediate old IAM.

        Scenario: Employee terminated, rehired, got a NEW IAM user.
        The old IAM is orphaned and should be deleted.
        """
        record = _make_record(
            terminated_at=_days_ago(60),
            is_rehire=True,
            rehire_date=_days_ago(30),
            iam_last_used_at=_days_ago(45),  # Last used BEFORE rehire
        )
        assert record.should_remediate() is True

    def test_rehire_iam_created_after_rehire_should_not_remediate(self):
        """IAM created after rehire → this is the new IAM → skip.

        Scenario: Employee rehired, new IAM created for them.
        This record represents their current active IAM.
        """
        record = _make_record(
            terminated_at=_days_ago(60),
            is_rehire=True,
            rehire_date=_days_ago(30),
            iam_created_at=_days_ago(25),  # Created AFTER rehire
        )
        assert record.should_remediate() is False

    def test_rehire_no_usage_data_should_remediate(self):
        """Rehired + no last-used data → conservative: remediate old IAM.

        If we can't confirm the IAM is in use, assume it's orphaned.
        """
        record = _make_record(
            terminated_at=_days_ago(60),
            is_rehire=True,
            rehire_date=_days_ago(30),
            iam_last_used_at=None,
            iam_created_at=_days_ago(365),  # Created long before rehire
        )
        assert record.should_remediate() is True

    def test_terminated_rehired_terminated_again(self):
        """Terminated → rehired → terminated again → remediate.

        The latest termination means they're gone again.
        is_rehire would be False for the latest termination record.
        """
        record = _make_record(
            terminated_at=_days_ago(10),
            is_rehire=False,
        )
        assert record.should_remediate() is True

    def test_email_normalized_to_lowercase(self):
        record = _make_record(email="Jane.Doe@Company.COM")
        assert record.email == "jane.doe@company.com"

    def test_record_hash_deterministic(self):
        r1 = _make_record(email="test@co.com", terminated_at=_days_ago(10))
        r2 = _make_record(email="test@co.com", terminated_at=_days_ago(10))
        assert r1.record_hash == r2.record_hash

    def test_record_hash_changes_on_different_data(self):
        r1 = _make_record(email="a@co.com")
        r2 = _make_record(email="b@co.com")
        assert r1.record_hash != r2.record_hash

    def test_to_dict_serializable(self):
        record = _make_record()
        d = record.to_dict()
        # Should be JSON-serializable
        json.dumps(d, default=str)
        assert d["email"] == "jane.doe@company.com"
        assert d["remediation_status"] == "pending"
        assert d["termination_source"] == "snowflake"


# ── ChangeDetector Tests ────────────────────────────────────────────


class TestChangeDetector:
    """Test change detection via content hashing."""

    def test_first_run_always_changed(self):
        """No previous hash → treat as changed."""
        s3 = MagicMock()
        s3.exceptions = MagicMock()
        s3.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})
        s3.get_object.side_effect = s3.exceptions.NoSuchKey()

        detector = ChangeDetector(s3, "my-bucket")
        records = [_make_record()]
        changed, hash_val = detector.has_changed(records)

        assert changed is True
        assert len(hash_val) == 64  # SHA-256 hex

    def test_same_data_not_changed(self):
        """Same data → same hash → not changed."""
        records = [_make_record(email="a@co.com"), _make_record(email="b@co.com")]

        s3 = MagicMock()
        detector = ChangeDetector(s3, "my-bucket")

        # Compute hash first
        expected_hash = detector.compute_hash(records)

        # Mock S3 returning the same hash
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=expected_hash.encode()))}

        changed, _ = detector.has_changed(records)
        assert changed is False

    def test_different_data_changed(self):
        """Different data → different hash → changed."""
        s3 = MagicMock()
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=b"old_hash_value_here"))}

        detector = ChangeDetector(s3, "my-bucket")
        records = [_make_record()]
        changed, _ = detector.has_changed(records)

        assert changed is True

    def test_hash_order_independent(self):
        """Records in different order → same hash."""
        r1 = _make_record(email="a@co.com")
        r2 = _make_record(email="b@co.com")

        s3 = MagicMock()
        detector = ChangeDetector(s3, "my-bucket")

        h1 = detector.compute_hash([r1, r2])
        h2 = detector.compute_hash([r2, r1])
        assert h1 == h2

    def test_store_hash_uses_kms(self):
        """Hash storage uses server-side KMS encryption."""
        s3 = MagicMock()
        detector = ChangeDetector(s3, "my-bucket")
        detector.store_hash("abc123")

        s3.put_object.assert_called_once()
        call_kwargs = s3.put_object.call_args[1]
        assert call_kwargs["ServerSideEncryption"] == "aws:kms"


# ── S3Exporter Tests ────────────────────────────────────────────────


class TestS3Exporter:
    """Test S3 manifest export."""

    def test_export_only_actionable_records(self):
        """Export should only include records that should_remediate()."""
        s3 = MagicMock()
        exporter = S3Exporter(s3, "my-bucket")

        actionable = _make_record(email="fired@co.com", terminated_at=_days_ago(30))
        deleted = _make_record(email="gone@co.com", iam_deleted=True)

        key = exporter.export_manifest([actionable, deleted], "snowflake", "hash123")

        assert "departures/" in key
        assert key.endswith(".json")

        # Check what was written to S3
        call_args = s3.put_object.call_args[1]
        body = json.loads(call_args["Body"].decode())
        assert body["actionable_count"] == 1
        assert body["skipped_count"] == 1
        assert len(body["entries"]) == 1
        assert body["entries"][0]["email"] == "fired@co.com"

    def test_export_uses_kms_encryption(self):
        s3 = MagicMock()
        exporter = S3Exporter(s3, "my-bucket")
        exporter.export_manifest([_make_record()], "snowflake", "hash123")

        call_kwargs = s3.put_object.call_args[1]
        assert call_kwargs["ServerSideEncryption"] == "aws:kms"

    def test_skip_reasons_categorized(self):
        s3 = MagicMock()
        exporter = S3Exporter(s3, "my-bucket")

        deleted = _make_record(iam_deleted=True)
        already_done = _make_record(status=RemediationStatus.REMEDIATED)

        exporter.export_manifest([deleted, already_done], "snowflake", "h")

        body = json.loads(s3.put_object.call_args[1]["Body"].decode())
        assert body["skip_reasons"]["iam_already_deleted"] == 1


# ── Source Factory Tests ────────────────────────────────────────────


class TestSourceFactory:
    """Test the get_source factory."""

    def test_unknown_source_raises(self):
        with pytest.raises(ValueError, match="Unknown HR source"):
            get_source("oracle")

    @patch.dict(
        os.environ,
        {
            "SNOWFLAKE_ACCOUNT": "test",
            "SNOWFLAKE_USER": "user",
            "SNOWFLAKE_PASSWORD": "pass",
        },
    )
    def test_snowflake_source_creation(self):
        source = get_source("snowflake")
        assert source.__class__.__name__ == "SnowflakeSource"

    @patch.dict(
        os.environ,
        {
            "DATABRICKS_HOST": "test.cloud.databricks.com",
            "DATABRICKS_TOKEN": "token",
        },
    )
    def test_databricks_source_creation(self):
        source = get_source("databricks")
        assert source.__class__.__name__ == "DatabricksSource"

    @patch.dict(
        os.environ,
        {
            "CLICKHOUSE_HOST": "test.clickhouse.cloud",
        },
    )
    def test_clickhouse_source_creation(self):
        source = get_source("clickhouse")
        assert source.__class__.__name__ == "ClickHouseSource"
