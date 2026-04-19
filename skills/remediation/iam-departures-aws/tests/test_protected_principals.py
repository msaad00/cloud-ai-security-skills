"""Tests for the defense-in-depth protected-principal deny list.

The IaC deny policy is the authoritative guard. These tests verify the
Python mirror used by the worker handler as a local second layer.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lambda_worker.handler import handler  # noqa: E402
from lambda_worker.protected_principals import (  # noqa: E402
    PROTECTED_USER_PATTERNS,
    ProtectedPrincipalError,
    assert_not_protected,
    is_protected_user,
)


class TestIsProtectedUser:
    def test_root_is_protected(self):
        assert is_protected_user("root")

    def test_root_case_insensitive(self):
        assert is_protected_user("ROOT")
        assert is_protected_user("Root")

    def test_break_glass_wildcard(self):
        assert is_protected_user("break-glass-1")
        assert is_protected_user("break-glass-incident-42")
        assert is_protected_user("break-glass-")

    def test_emergency_wildcard(self):
        assert is_protected_user("emergency-ops")
        assert is_protected_user("emergency-sre-oncall")

    def test_regular_user_not_protected(self):
        assert not is_protected_user("alice")
        assert not is_protected_user("jane.doe@co.com")

    def test_partial_match_not_protected(self):
        # `fnmatchcase` anchors the whole string, so substring matches don't trigger.
        assert not is_protected_user("alice-break-glass-1")
        assert not is_protected_user("emergencyops")  # no dash → no match
        assert not is_protected_user("notroot")

    def test_every_pattern_triggers(self):
        # Ensure every pattern in the list actually triggers at least one match
        # — catches a malformed pattern (e.g. typo) that would never fire.
        for pattern in PROTECTED_USER_PATTERNS:
            sample = pattern.replace("*", "x")
            assert is_protected_user(sample), f"pattern `{pattern}` failed to match `{sample}`"


class TestAssertNotProtected:
    def test_passes_for_regular_user(self):
        assert_not_protected("alice")  # no raise

    def test_raises_for_root(self):
        with pytest.raises(ProtectedPrincipalError) as excinfo:
            assert_not_protected("root")
        assert "protected principal" in str(excinfo.value)
        # Error must reference the IaC file so operators know where to look.
        assert "cross_account_remediation_role.json" in str(excinfo.value)

    def test_raises_for_break_glass(self):
        with pytest.raises(ProtectedPrincipalError):
            assert_not_protected("break-glass-1")

    def test_raises_for_emergency(self):
        with pytest.raises(ProtectedPrincipalError):
            assert_not_protected("emergency-ops")


class TestHandlerRefusesProtectedPrincipal:
    """End-to-end: the worker handler must return `status=refused` without
    ever touching the IAM client when the target is protected."""

    def _event(self, iam_username: str) -> dict:
        return {
            "entry": {
                "email": f"{iam_username}@co.com",
                "recipient_account_id": "123456789012",
                "iam_username": iam_username,
                "terminated_at": "2026-02-15T00:00:00+00:00",
                "termination_source": "snowflake",
                "is_rehire": False,
            },
            "source_bucket": "test-bucket",
        }

    @pytest.mark.parametrize("username", ["root", "break-glass-1", "emergency-ops"])
    def test_handler_refuses_and_never_calls_iam(self, username: str):
        with (
            patch("lambda_worker.handler._get_iam_client") as mock_iam,
            patch("lambda_worker.handler._write_audit") as mock_audit,
            patch("lambda_worker.handler._load_checkpoint") as mock_checkpoint,
        ):
            mock_checkpoint.return_value = {
                "status": "not_started",
                "actions_taken": [],
                "completed_steps": [],
                "updated_at": None,
            }
            result = handler(self._event(username), context=None)
            assert result["status"] == "refused"
            assert "protected principal" in result["error"]
            # Audit record written with refused status — forensic trail intact.
            mock_audit.assert_called_once()
            # Critical: IAM client was never instantiated.
            mock_iam.assert_not_called()

    def test_handler_still_processes_regular_user(self):
        # Sanity check: regular usernames pass the protected-principal guard.
        with (
            patch("lambda_worker.handler._get_iam_client") as mock_iam,
            patch("lambda_worker.handler._write_audit"),
            patch("lambda_worker.handler._load_checkpoint") as mock_checkpoint,
        ):
            mock_checkpoint.return_value = {
                "status": "remediated",  # short-circuit after guard so we don't need real IAM mocks
                "actions_taken": [],
                "completed_steps": [],
                "updated_at": "2026-04-18T00:00:00Z",
            }
            result = handler(self._event("jane.doe"), context=None)
            # Short-circuits to remediated status without calling IAM.
            assert result["status"] == "remediated"
            mock_iam.assert_not_called()
