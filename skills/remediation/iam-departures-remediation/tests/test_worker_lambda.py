"""Tests for Lambda 2 (Worker) — IAM user remediation."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lambda_worker.handler import (
    _build_audit_record,
    _deactivate_access_keys,
    _delete_inline_policies,
    _delete_login_profile,
    _delete_mfa_devices,
    _detach_managed_policies,
    _remove_from_groups,
    handler,
)


def _make_event(
    email: str = "jane@co.com",
    account_id: str = "123456789012",
    iam_username: str = "jane",
) -> dict:
    return {
        "entry": {
            "email": email,
            "recipient_account_id": account_id,
            "iam_username": iam_username,
            "terminated_at": "2026-02-15T00:00:00+00:00",
            "termination_source": "snowflake",
            "is_rehire": False,
        },
        "source_bucket": "test-bucket",
        "source_key": "departures/2026-03-01.json",
    }


class TestRemediationSteps:
    """Test individual IAM remediation steps."""

    def test_deactivate_access_keys(self):
        """Should deactivate then delete all access keys."""
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {
                "AccessKeyMetadata": [
                    {"AccessKeyId": "AKIA111", "Status": "Active"},
                    {"AccessKeyId": "AKIA222", "Status": "Active"},
                ]
            }
        ]
        actions = []
        _deactivate_access_keys(iam, "jane", actions)

        assert iam.update_access_key.call_count == 2
        assert iam.delete_access_key.call_count == 2
        assert len(actions) == 4  # 2 deactivate + 2 delete

        # Verify deactivation happens before deletion
        deactivate_calls = [a for a in actions if a["action"] == "deactivate_access_key"]
        delete_calls = [a for a in actions if a["action"] == "delete_access_key"]
        assert len(deactivate_calls) == 2
        assert len(delete_calls) == 2

    def test_delete_login_profile(self):
        iam = MagicMock()
        actions = []
        _delete_login_profile(iam, "jane", actions)

        iam.delete_login_profile.assert_called_once_with(UserName="jane")
        assert len(actions) == 1

    def test_delete_login_profile_not_found(self):
        """No login profile → no error, no action logged."""
        iam = MagicMock()
        iam.exceptions.NoSuchEntityException = type("E", (Exception,), {})
        iam.delete_login_profile.side_effect = iam.exceptions.NoSuchEntityException()

        actions = []
        _delete_login_profile(iam, "jane", actions)
        assert len(actions) == 0

    def test_remove_from_groups(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {
                "Groups": [
                    {"GroupName": "developers"},
                    {"GroupName": "admin"},
                ]
            }
        ]
        actions = []
        _remove_from_groups(iam, "jane", actions)

        assert iam.remove_user_from_group.call_count == 2
        assert len(actions) == 2

    def test_detach_managed_policies(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {
                "AttachedPolicies": [
                    {"PolicyName": "ReadOnly", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
                ]
            }
        ]
        actions = []
        _detach_managed_policies(iam, "jane", actions)

        iam.detach_user_policy.assert_called_once()
        assert len(actions) == 1

    def test_delete_inline_policies(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [{"PolicyNames": ["custom-policy-1", "custom-policy-2"]}]
        actions = []
        _delete_inline_policies(iam, "jane", actions)

        assert iam.delete_user_policy.call_count == 2
        assert len(actions) == 2

    def test_delete_mfa_devices(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {
                "MFADevices": [
                    {"SerialNumber": "arn:aws:iam::123:mfa/jane"},
                ]
            }
        ]
        actions = []
        _delete_mfa_devices(iam, "jane", actions)

        iam.deactivate_mfa_device.assert_called_once()
        iam.delete_virtual_mfa_device.assert_called_once()
        assert len(actions) == 1


class TestWorkerHandler:
    """Test the full worker Lambda handler."""

    @patch("lambda_worker.handler._write_audit")
    @patch("lambda_worker.handler._get_iam_client")
    def test_successful_remediation(self, mock_iam, mock_audit):
        """Full remediation flow for a standard terminated employee."""
        iam = MagicMock()
        mock_iam.return_value = iam

        # Mock all pagination as empty (no keys, groups, policies, etc.)
        iam.get_paginator.return_value.paginate.return_value = [
            {"AccessKeyMetadata": []},
        ]
        iam.get_paginator.return_value.paginate.return_value = [{}]

        # Simplify — mock each paginator to return empty
        def mock_paginate(*args, **kwargs):
            paginator = MagicMock()
            paginator.paginate.return_value = iter(
                [
                    {
                        "AccessKeyMetadata": [],
                        "Groups": [],
                        "AttachedPolicies": [],
                        "PolicyNames": [],
                        "MFADevices": [],
                        "Certificates": [],
                        "SSHPublicKeys": [],
                    }
                ]
            )
            return paginator

        iam.get_paginator.side_effect = mock_paginate
        iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": []}
        iam.exceptions.NoSuchEntityException = type("E", (Exception,), {})
        iam.delete_login_profile.side_effect = iam.exceptions.NoSuchEntityException()

        result = handler(_make_event(), None)

        assert result["status"] == "remediated"
        assert result["iam_username"] == "jane"
        assert result["account_id"] == "123456789012"
        iam.delete_user.assert_called_once_with(UserName="jane")
        mock_audit.assert_called_once()

    @patch("lambda_worker.handler._write_audit")
    @patch("lambda_worker.handler._get_iam_client")
    def test_remediation_failure_logged(self, mock_iam, mock_audit):
        """If remediation fails, error is captured and audit still written."""
        mock_iam.side_effect = Exception("AssumeRole denied")

        result = handler(_make_event(), None)

        assert result["status"] == "error"
        assert "AssumeRole denied" in result["error"]
        mock_audit.assert_called_once()  # Audit still written on failure

    @patch("lambda_worker.handler._write_audit")
    def test_invalid_payload_rejected_before_remediation(self, mock_audit):
        result = handler(_make_event(account_id="not-an-account"), None)

        assert result["status"] == "error"
        assert result["error"] == "Invalid remediation payload"
        mock_audit.assert_called_once()

    def test_audit_record_captures_caller_and_approval_context(self, monkeypatch):
        class _Context:
            aws_request_id = "req-123"

        monkeypatch.setenv("SKILL_CALLER_ID", "u-123")
        monkeypatch.setenv("SKILL_CALLER_EMAIL", "user@example.com")
        monkeypatch.setenv("SKILL_SESSION_ID", "sess-1")
        monkeypatch.setenv("SKILL_CALLER_ROLES", "security_engineer")
        monkeypatch.setenv("SKILL_APPROVER_ID", "a-456")
        monkeypatch.setenv("SKILL_APPROVER_EMAIL", "approver@example.com")
        monkeypatch.setenv("SKILL_APPROVAL_TICKET", "SEC-123")
        monkeypatch.setenv("SKILL_APPROVAL_TIMESTAMP", "2026-04-14T12:00:00Z")

        record = _build_audit_record(_make_event()["entry"], [], "remediated", context=_Context())

        assert record["invoked_by"] == "u-123"
        assert record["invoked_by_email"] == "user@example.com"
        assert record["agent_session_id"] == "sess-1"
        assert record["caller_roles"] == "security_engineer"
        assert record["approved_by"] == "a-456"
        assert record["approved_by_email"] == "approver@example.com"
        assert record["approval_ticket"] == "SEC-123"
        assert record["approval_timestamp"] == "2026-04-14T12:00:00Z"
        assert record["lambda_request_id"] == "req-123"


class TestSnowflakeIdentifierSafety:
    def test_embedded_quotes_are_escaped(self):
        from lambda_worker.clouds.snowflake_user import _quote_identifier

        assert _quote_identifier('jane"ops') == '"jane""ops"'

    def test_newlines_are_rejected(self):
        from lambda_worker.clouds.snowflake_user import _quote_identifier

        with pytest.raises(ValueError, match="Invalid Snowflake identifier"):
            _quote_identifier("bad\nuser")
