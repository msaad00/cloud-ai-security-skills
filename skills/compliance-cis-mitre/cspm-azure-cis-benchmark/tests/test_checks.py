"""Tests for CIS Azure Foundations Benchmark v2.1 checks.

Uses unittest.mock to simulate Azure SDK responses. Each test maps 1:1 to a
function that actually exists in src/checks.py — if a check is not implemented,
it does not appear here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_azure_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

check_2_2_https_only = _CHECKS.check_2_2_https_only
check_2_3_no_public_blob = _CHECKS.check_2_3_no_public_blob
check_2_4_network_rules = _CHECKS.check_2_4_network_rules
check_4_1_no_unrestricted_ssh = _CHECKS.check_4_1_no_unrestricted_ssh
check_4_2_no_unrestricted_rdp = _CHECKS.check_4_2_no_unrestricted_rdp
check_4_3_nsg_flow_logs = _CHECKS.check_4_3_nsg_flow_logs

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
        nsg.id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/rg-net/providers/"
            f"Microsoft.Network/networkSecurityGroups/{name}"
        )
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
        client.network_security_groups.list_all.return_value = [self._nsg_with_rule("nsg-a")]
        client.network_watchers.list_all.return_value = []
        f = check_4_3_nsg_flow_logs(client, SUB_ID)
        assert f.control_id == "4.3"
        assert f.status == "FAIL"

    def test_4_3_with_enabled_logs_passes(self):
        client = MagicMock()
        watcher = MagicMock()
        watcher.name = "nw-eastus"
        watcher.id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/NetworkWatcherRG/providers/"
            "Microsoft.Network/networkWatchers/nw-eastus"
        )
        client.network_security_groups.list_all.return_value = [
            self._nsg_with_rule("nsg-a"),
            self._nsg_with_rule("nsg-b"),
        ]
        client.network_watchers.list_all.return_value = [watcher]
        flow_log_a = MagicMock(enabled=True)
        flow_log_a.target_resource_id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/rg-net/providers/"
            "Microsoft.Network/networkSecurityGroups/nsg-a"
        )
        flow_log_b = MagicMock(enabled=True)
        flow_log_b.target_resource_id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/rg-net/providers/"
            "Microsoft.Network/networkSecurityGroups/nsg-b"
        )
        client.flow_logs.list.return_value = [flow_log_a, flow_log_b]
        f = check_4_3_nsg_flow_logs(client, SUB_ID)
        assert f.status == "PASS"
        assert "all 2 NSG" in f.detail

    def test_4_3_missing_logs_fail(self):
        client = MagicMock()
        watcher = MagicMock()
        watcher.name = "nw-eastus"
        watcher.id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/NetworkWatcherRG/providers/"
            "Microsoft.Network/networkWatchers/nw-eastus"
        )
        nsg_a = self._nsg_with_rule("nsg-a")
        nsg_b = self._nsg_with_rule("nsg-b")
        client.network_security_groups.list_all.return_value = [nsg_a, nsg_b]
        client.network_watchers.list_all.return_value = [watcher]
        flow_log = MagicMock(enabled=True)
        flow_log.target_resource_id = nsg_a.id
        client.flow_logs.list.return_value = [flow_log]
        f = check_4_3_nsg_flow_logs(client, SUB_ID)
        assert f.status == "FAIL"
        assert nsg_b.id in f.resources


class TestFindingStructure:
    def test_finding_has_compliance(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = []
        f = check_2_3_no_public_blob(client, SUB_ID)
        assert f.nist_csf
        assert f.control_id == "2.3"
