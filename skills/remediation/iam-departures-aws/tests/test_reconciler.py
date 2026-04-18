"""Tests for the reconciler module — sources, change detection, export."""

from __future__ import annotations

import json
import os
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


class TestDepartureRecord:
    def test_basic_termination_should_remediate(self):
        record = _make_record(terminated_at=_days_ago(30))
        assert record.should_remediate() is True

    def test_already_deleted_should_not_remediate(self):
        record = _make_record(iam_deleted=True)
        assert record.should_remediate() is False

    def test_already_remediated_should_not_remediate(self):
        record = _make_record(status=RemediationStatus.REMEDIATED)
        assert record.should_remediate() is False

    def test_no_termination_date_should_not_remediate(self):
        record = _make_record(terminated_at=None)
        assert record.should_remediate() is False

    def test_rehire_same_iam_in_use_should_not_remediate(self):
        record = _make_record(
            terminated_at=_days_ago(60),
            is_rehire=True,
            rehire_date=_days_ago(30),
            iam_last_used_at=_days_ago(5),
        )
        assert record.should_remediate() is False

    def test_rehire_different_iam_should_remediate_old(self):
        record = _make_record(
            terminated_at=_days_ago(60),
            is_rehire=True,
            rehire_date=_days_ago(30),
            iam_last_used_at=_days_ago(45),
        )
        assert record.should_remediate() is True

    def test_rehire_iam_created_after_rehire_should_not_remediate(self):
        record = _make_record(
            terminated_at=_days_ago(60),
            is_rehire=True,
            rehire_date=_days_ago(30),
            iam_created_at=_days_ago(25),
        )
        assert record.should_remediate() is False

    def test_rehire_no_usage_data_should_remediate(self):
        record = _make_record(
            terminated_at=_days_ago(60),
            is_rehire=True,
            rehire_date=_days_ago(30),
            iam_last_used_at=None,
            iam_created_at=_days_ago(365),
        )
        assert record.should_remediate() is True

    def test_terminated_rehired_terminated_again(self):
        record = _make_record(terminated_at=_days_ago(10), is_rehire=False)
        assert record.should_remediate() is True

    def test_email_normalized_to_lowercase(self):
        record = _make_record(email="Jane.Doe@Company.COM")
        assert record.email == "jane.doe@company.com"

    def test_record_hash_deterministic(self):
        terminated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        r1 = _make_record(email="test@co.com", terminated_at=terminated_at)
        r2 = _make_record(email="test@co.com", terminated_at=terminated_at)
        assert r1.record_hash == r2.record_hash

    def test_record_hash_changes_on_different_data(self):
        assert _make_record(email="a@co.com").record_hash != _make_record(email="b@co.com").record_hash

    def test_to_dict_serializable(self):
        d = _make_record().to_dict()
        json.dumps(d, default=str)
        assert d["email"] == "jane.doe@company.com"
        assert d["remediation_status"] == "pending"
        assert d["termination_source"] == "snowflake"


class TestChangeDetector:
    def test_first_run_always_changed(self):
        s3 = MagicMock()
        s3.exceptions = MagicMock()
        s3.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})
        s3.get_object.side_effect = s3.exceptions.NoSuchKey()

        detector = ChangeDetector(s3, "my-bucket")
        changed, hash_val = detector.has_changed([_make_record()])

        assert changed is True
        assert len(hash_val) == 64

    def test_same_data_not_changed(self):
        records = [_make_record(email="a@co.com"), _make_record(email="b@co.com")]
        s3 = MagicMock()
        detector = ChangeDetector(s3, "my-bucket")
        expected_hash = detector.compute_hash(records)
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=expected_hash.encode()))}
        changed, _ = detector.has_changed(records)
        assert changed is False

    def test_different_data_changed(self):
        s3 = MagicMock()
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=b"old_hash_value_here"))}
        detector = ChangeDetector(s3, "my-bucket")
        changed, _ = detector.has_changed([_make_record()])
        assert changed is True

    def test_hash_order_independent(self):
        detector = ChangeDetector(MagicMock(), "my-bucket")
        h1 = detector.compute_hash([_make_record(email="a@co.com"), _make_record(email="b@co.com")])
        h2 = detector.compute_hash([_make_record(email="b@co.com"), _make_record(email="a@co.com")])
        assert h1 == h2


class TestS3Exporter:
    def test_export_manifest(self):
        s3 = MagicMock()
        exporter = S3Exporter(s3, "my-bucket")
        key = exporter.export_manifest([_make_record()], "snowflake", "abc123")
        assert key.startswith("departures/")
        assert key.endswith(".json")

    def test_skip_reasons_categorized(self):
        s3 = MagicMock()
        exporter = S3Exporter(s3, "my-bucket")
        exporter.export_manifest(
            [
                _make_record(iam_deleted=True),
                _make_record(status=RemediationStatus.REMEDIATED),
            ],
            "snowflake",
            "h",
        )
        body = json.loads(s3.put_object.call_args[1]["Body"].decode())
        assert body["skip_reasons"]["iam_already_deleted"] == 1


class TestSourceFactory:
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
        assert get_source("snowflake").__class__.__name__ == "SnowflakeSource"

    @patch.dict(
        os.environ,
        {
            "SNOWFLAKE_ACCOUNT": "test",
            "SNOWFLAKE_USER": "user",
            "SNOWFLAKE_PASSWORD": "pass",
            "SNOWFLAKE_HR_DATABASE": "bad-name",
        },
    )
    def test_snowflake_invalid_identifier_rejected(self):
        with pytest.raises(ValueError, match="Invalid SQL identifier"):
            get_source("snowflake")

    @patch.dict(
        os.environ,
        {
            "DATABRICKS_HOST": "test.cloud.databricks.com",
            "DATABRICKS_TOKEN": "token",
        },
    )
    def test_databricks_source_creation(self):
        assert get_source("databricks").__class__.__name__ == "DatabricksSource"

    @patch.dict(
        os.environ,
        {
            "CLICKHOUSE_HOST": "test.clickhouse.cloud",
        },
    )
    def test_clickhouse_source_creation(self):
        assert get_source("clickhouse").__class__.__name__ == "ClickHouseSource"


class TestSnowflakeLogging:
    def test_snowflake_source_suppresses_verbose_connector_logs(self):
        from reconciler import sources

        with patch("reconciler.sources.logging.getLogger") as mock_get_logger:
            connector_logger = MagicMock()
            mock_get_logger.return_value = connector_logger

            sources._configure_snowflake_logging()

        mock_get_logger.assert_called_once_with("snowflake.connector")
        connector_logger.setLevel.assert_called_once_with(sources.logging.WARNING)
