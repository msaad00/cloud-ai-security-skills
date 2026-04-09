"""Tests for CIS Azure Foundations Benchmark v2.1 checks.

Uses unittest.mock to simulate Azure SDK responses.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import check_2_1_storage_encryption, check_4_1_no_open_ssh


class TestStorageChecks:
    def test_2_1_encryption_enabled_passes(self):
        mock_client = MagicMock()
        account = MagicMock()
        account.name = "teststorage"
        account.encryption = MagicMock()
        account.encryption.services = MagicMock()
        account.encryption.services.blob = MagicMock()
        account.encryption.services.blob.enabled = True
        mock_client.storage_accounts = MagicMock()
        mock_client.storage_accounts.list.return_value = [account]

        f = check_2_1_storage_encryption(mock_client)
        assert f.control_id == "2.1"
        assert f.status == "PASS"

    def test_2_1_encryption_disabled_fails(self):
        mock_client = MagicMock()
        account = MagicMock()
        account.name = "unencrypted"
        account.encryption = MagicMock()
        account.encryption.services = MagicMock()
        account.encryption.services.blob = MagicMock()
        account.encryption.services.blob.enabled = False
        mock_client.storage_accounts = MagicMock()
        mock_client.storage_accounts.list.return_value = [account]

        f = check_2_1_storage_encryption(mock_client)
        assert f.status == "FAIL"
        assert "unencrypted" in f.resources


class TestNetworkChecks:
    def test_4_1_open_ssh_fails(self):
        mock_client = MagicMock()
        nsg = MagicMock()
        nsg.name = "open-nsg"
        nsg.id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/open-nsg"
        rule = MagicMock()
        rule.direction = "Inbound"
        rule.access = "Allow"
        rule.destination_port_range = "22"
        rule.source_address_prefix = "*"
        rule.protocol = "Tcp"
        nsg.security_rules = [rule]
        mock_client.network_security_groups = MagicMock()
        mock_client.network_security_groups.list_all.return_value = [nsg]

        f = check_4_1_no_open_ssh(mock_client)
        assert f.status == "FAIL"

    def test_4_1_restricted_ssh_passes(self):
        mock_client = MagicMock()
        nsg = MagicMock()
        nsg.name = "restricted-nsg"
        rule = MagicMock()
        rule.direction = "Inbound"
        rule.access = "Allow"
        rule.destination_port_range = "22"
        rule.source_address_prefix = "10.0.0.0/8"
        rule.protocol = "Tcp"
        nsg.security_rules = [rule]
        mock_client.network_security_groups = MagicMock()
        mock_client.network_security_groups.list_all.return_value = [nsg]

        f = check_4_1_no_open_ssh(mock_client)
        assert f.status == "PASS"


class TestFindingStructure:
    def test_finding_has_compliance(self):
        mock_client = MagicMock()
        mock_client.storage_accounts = MagicMock()
        mock_client.storage_accounts.list.return_value = []

        f = check_2_1_storage_encryption(mock_client)
        assert f.nist_csf
        assert f.control_id == "2.1"
