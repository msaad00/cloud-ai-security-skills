"""Tests for Lambda 2 (Worker) — IAM user remediation."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lambda_worker.handler import (
    handler,
    _deactivate_access_keys,
    _delete_login_profile,
    _remove_from_groups,
    _detach_managed_policies,
    _delete_inline_policies,
    _delete_mfa_devices,
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
            {"AccessKeyMetadata": [
                {"AccessKeyId": "AKIA111", "Status": "Active"},
                {"AccessKeyId": "AKIA222", "Status": "Active"},
            ]}
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
            {"Groups": [
                {"GroupName": "developers"},
                {"GroupName": "admin"},
            ]}
        ]
        actions = []
        _remove_from_groups(iam, "jane", actions)

        assert iam.remove_user_from_group.call_count == 2
        assert len(actions) == 2

    def test_detach_managed_policies(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {"AttachedPolicies": [
                {"PolicyName": "ReadOnly", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
            ]}
        ]
        actions = []
        _detach_managed_policies(iam, "jane", actions)

        iam.detach_user_policy.assert_called_once()
        assert len(actions) == 1

    def test_delete_inline_policies(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {"PolicyNames": ["custom-policy-1", "custom-policy-2"]}
        ]
        actions = []
        _delete_inline_policies(iam, "jane", actions)

        assert iam.delete_user_policy.call_count == 2
        assert len(actions) == 2

    def test_delete_mfa_devices(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {"MFADevices": [
                {"SerialNumber": "arn:aws:iam::123:mfa/jane"},
            ]}
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
            paginator.paginate.return_value = iter([
                {"AccessKeyMetadata": [], "Groups": [], "AttachedPolicies": [],
                 "PolicyNames": [], "MFADevices": [], "Certificates": [],
                 "SSHPublicKeys": []}
            ])
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
