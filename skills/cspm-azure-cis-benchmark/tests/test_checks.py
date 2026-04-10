"""Tests for CIS Azure Foundations Benchmark v2.1 checks.

Uses unittest.mock to simulate Azure SDK responses. Each test maps 1:1 to a
function that actually exists in src/checks.py — if a check is not implemented,
it does not appear here.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import (
    check_2_2_https_only,
    check_2_3_no_public_blob,
    check_2_4_network_rules,
    check_4_1_no_unrestricted_ssh,
    check_4_2_no_unrestricted_rdp,
    check_4_3_nsg_flow_logs,
)

SUB_ID = "00000000-0000-0000-0000-000000000000"


# ── Storage ───────────────────────────────────────────────────────


class TestStorageChecks:
    def _account(self, name, *, https=True, public_blob=False, default_action="Deny"):
        a = MagicMock()
        a.name = name
        a.enable_https_traffic_only = https
        a.allow_blob_public_access = public_blob
        a.network_rule_set = MagicMock()
        a.network_rule_set.default_action = default_action
        return a

    def test_2_2_https_only_passes(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("ok", https=True)]
        f = check_2_2_https_only(client, SUB_ID)
        assert f.control_id == "2.2"
        assert f.status == "PASS"

    def test_2_2_https_only_fails(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("bad", https=False)]
        f = check_2_2_https_only(client, SUB_ID)
        assert f.status == "FAIL"
        assert "bad" in f.resources

    def test_2_3_public_blob_fails(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("leak", public_blob=True)]
        f = check_2_3_no_public_blob(client, SUB_ID)
        assert f.control_id == "2.3"
        assert f.status == "FAIL"
        assert "leak" in f.resources

    def test_2_3_no_public_blob_passes(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("ok", public_blob=False)]
        f = check_2_3_no_public_blob(client, SUB_ID)
        assert f.status == "PASS"

    def test_2_4_default_allow_fails(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("open", default_action="Allow")]
        f = check_2_4_network_rules(client, SUB_ID)
        assert f.control_id == "2.4"
        assert f.status == "FAIL"
        assert "open" in f.resources

    def test_2_4_deny_by_default_passes(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("ok", default_action="Deny")]
        f = check_2_4_network_rules(client, SUB_ID)
        assert f.status == "PASS"


# ── Networking ────────────────────────────────────────────────────


class TestNetworkChecks:
    def _nsg_with_rule(self, name, *, port="22", source="*", access="Allow", direction="Inbound"):
        nsg = MagicMock()
        nsg.name = name
        rule = MagicMock()
        rule.name = "rule0"
        rule.direction = direction
        rule.access = access
        rule.destination_port_range = port
        rule.source_address_prefix = source
        rule.protocol = "Tcp"
        nsg.security_rules = [rule]
        return nsg

    def test_4_1_open_ssh_fails(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [self._nsg_with_rule("open", port="22", source="*")]
        f = check_4_1_no_unrestricted_ssh(client, SUB_ID)
        assert f.control_id == "4.1"
        assert f.status == "FAIL"

    def test_4_1_restricted_ssh_passes(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [self._nsg_with_rule("ok", port="22", source="10.0.0.0/8")]
        f = check_4_1_no_unrestricted_ssh(client, SUB_ID)
        assert f.status == "PASS"

    def test_4_2_open_rdp_fails(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [self._nsg_with_rule("open", port="3389", source="*")]
        f = check_4_2_no_unrestricted_rdp(client, SUB_ID)
        assert f.control_id == "4.2"
        assert f.status == "FAIL"

    def test_4_3_no_watchers_fails(self):
        client = MagicMock()
        client.network_watchers.list_all.return_value = []
        f = check_4_3_nsg_flow_logs(client, SUB_ID)
        assert f.control_id == "4.3"
        assert f.status == "FAIL"

    def test_4_3_with_watchers_passes(self):
        client = MagicMock()
        client.network_watchers.list_all.return_value = [MagicMock()]
        f = check_4_3_nsg_flow_logs(client, SUB_ID)
        assert f.status == "PASS"


class TestFindingStructure:
    def test_finding_has_compliance(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = []
        f = check_2_3_no_public_blob(client, SUB_ID)
        assert f.nist_csf
        assert f.control_id == "2.3"
