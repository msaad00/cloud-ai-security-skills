"""Tests for CIS GCP Foundations Benchmark v3.0 checks.

Uses unittest.mock to simulate GCP SDK responses.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import check_1_1_no_gmail_accounts, check_1_3_no_sa_keys, check_2_3_no_public_buckets


class TestIAMChecks:
    def test_1_1_gmail_found_fails(self):
        mock_crm = MagicMock()
        binding = MagicMock()
        binding.role = "roles/editor"
        binding.members = ["user:someone@gmail.com"]
        policy = MagicMock()
        policy.bindings = [binding]
        mock_crm.get_iam_policy.return_value = policy

        f = check_1_1_no_gmail_accounts(mock_crm, "test-project")
        assert f.status == "FAIL"
        assert f.severity == "HIGH"
        assert len(f.resources) == 1

    def test_1_1_no_gmail_passes(self):
        mock_crm = MagicMock()
        binding = MagicMock()
        binding.role = "roles/viewer"
        binding.members = ["user:admin@company.com"]
        policy = MagicMock()
        policy.bindings = [binding]
        mock_crm.get_iam_policy.return_value = policy

        f = check_1_1_no_gmail_accounts(mock_crm, "test-project")
        assert f.status == "PASS"

    def test_1_3_sa_keys_found_fails(self):
        mock_iam = MagicMock()
        sa = MagicMock()
        sa.name = "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com"
        sa.email = "sa@test.iam.gserviceaccount.com"
        mock_iam.list_service_accounts.return_value = [sa]
        key = MagicMock()
        mock_iam.list_service_account_keys.return_value = [key]

        f = check_1_3_no_sa_keys(mock_iam, "test-project")
        assert f.status == "FAIL"

    def test_1_3_no_sa_keys_passes(self):
        mock_iam = MagicMock()
        sa = MagicMock()
        sa.name = "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com"
        sa.email = "sa@test.iam.gserviceaccount.com"
        mock_iam.list_service_accounts.return_value = [sa]
        mock_iam.list_service_account_keys.return_value = []

        f = check_1_3_no_sa_keys(mock_iam, "test-project")
        assert f.status == "PASS"


class TestStorageChecks:
    def test_2_3_public_bucket_fails(self):
        mock_storage = MagicMock()
        bucket = MagicMock()
        bucket.name = "public-bucket"
        policy = MagicMock()
        policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]
        bucket.get_iam_policy.return_value = policy
        mock_storage.list_buckets.return_value = [bucket]

        f = check_2_3_no_public_buckets(mock_storage, "test-project")
        assert f.status == "FAIL"
        assert "public-bucket" in f.resources[0]

    def test_2_3_private_bucket_passes(self):
        mock_storage = MagicMock()
        bucket = MagicMock()
        bucket.name = "private-bucket"
        policy = MagicMock()
        policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["user:admin@company.com"]}]
        bucket.get_iam_policy.return_value = policy
        mock_storage.list_buckets.return_value = [bucket]

        f = check_2_3_no_public_buckets(mock_storage, "test-project")
        assert f.status == "PASS"


class TestFindingStructure:
    def test_finding_has_compliance_fields(self):
        mock_crm = MagicMock()
        policy = MagicMock()
        policy.bindings = []
        mock_crm.get_iam_policy.return_value = policy

        f = check_1_1_no_gmail_accounts(mock_crm, "test-project")
        assert f.nist_csf == "PR.AC-1"
        assert f.control_id == "1.1"
