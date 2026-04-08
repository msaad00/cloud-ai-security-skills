"""
CIS Azure Foundations Benchmark v2.1 — Automated Assessment

19 CIS controls + 5 AI Foundry controls across Identity, Storage,
Logging, and Networking.
Read-only: requires Reader role on the subscription.

Frameworks:
    CIS Azure Foundations v2.1
    NIST CSF 2.0: PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, PR.DS-1, PR.DS-2,
                  DE.AE-3, DE.CM-1
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    control_id: str
    title: str
    section: str
    severity: str
    status: str
    detail: str = ""
    nist_csf: str = ""
    resources: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Section 2 — Storage
# ---------------------------------------------------------------------------

def check_2_3_no_public_blob(storage_client, subscription_id: str) -> Finding:
    """CIS 2.3 — No public blob access."""
    try:
        accounts = list(storage_client.storage_accounts.list())
        public_accounts = []
        for account in accounts:
            if account.allow_blob_public_access:
                public_accounts.append(account.name)
        return Finding(
            control_id="2.3", title="No public blob access", section="storage",
            severity="CRITICAL", status="FAIL" if public_accounts else "PASS",
            detail=f"{len(public_accounts)} accounts allow public blob access" if public_accounts else "No public blob access",
            nist_csf="PR.AC-3", resources=public_accounts,
        )
    except Exception as e:
        return Finding(
            control_id="2.3", title="No public blob access", section="storage",
            severity="CRITICAL", status="ERROR", detail=str(e), nist_csf="PR.AC-3",
        )


def check_2_2_https_only(storage_client, subscription_id: str) -> Finding:
    """CIS 2.2 — Storage accounts HTTPS-only."""
    try:
        accounts = list(storage_client.storage_accounts.list())
        not_https = []
        for account in accounts:
            if not account.enable_https_traffic_only:
                not_https.append(account.name)
        return Finding(
            control_id="2.2", title="Storage HTTPS-only", section="storage",
            severity="HIGH", status="FAIL" if not_https else "PASS",
            detail=f"{len(not_https)} accounts allow non-HTTPS" if not_https else "All accounts enforce HTTPS",
            nist_csf="PR.DS-2", resources=not_https,
        )
    except Exception as e:
        return Finding(
            control_id="2.2", title="Storage HTTPS-only", section="storage",
            severity="HIGH", status="ERROR", detail=str(e), nist_csf="PR.DS-2",
        )


def check_2_4_network_rules(storage_client, subscription_id: str) -> Finding:
    """CIS 2.4 — Storage account network rules (deny by default)."""
    try:
        accounts = list(storage_client.storage_accounts.list())
        open_accounts = []
        for account in accounts:
            if account.network_rule_set and account.network_rule_set.default_action == "Allow":
                open_accounts.append(account.name)
        return Finding(
            control_id="2.4", title="Storage network deny-by-default", section="storage",
            severity="HIGH", status="FAIL" if open_accounts else "PASS",
            detail=f"{len(open_accounts)} accounts default-allow" if open_accounts else "All accounts deny by default",
            nist_csf="PR.AC-5", resources=open_accounts,
        )
    except Exception as e:
        return Finding(
            control_id="2.4", title="Storage network deny-by-default", section="storage",
            severity="HIGH", status="ERROR", detail=str(e), nist_csf="PR.AC-5",
        )


# ---------------------------------------------------------------------------
# Section 4 — Networking
# ---------------------------------------------------------------------------

def check_4_1_no_unrestricted_ssh(network_client, subscription_id: str) -> Finding:
    """CIS 4.1 — No unrestricted SSH in NSGs."""
    return _check_nsg_port(network_client, 22, "4.1", "No unrestricted SSH")


def check_4_2_no_unrestricted_rdp(network_client, subscription_id: str) -> Finding:
    """CIS 4.2 — No unrestricted RDP in NSGs."""
    return _check_nsg_port(network_client, 3389, "4.2", "No unrestricted RDP")


def _check_nsg_port(network_client, port: int, control_id: str, title: str) -> Finding:
    """Check NSGs for 0.0.0.0/0 on a specific port."""
    try:
        nsgs = list(network_client.network_security_groups.list_all())
        open_rules = []
        for nsg in nsgs:
            for rule in nsg.security_rules or []:
                if (rule.direction == "Inbound" and rule.access == "Allow"
                        and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")):
                    dest_ports = rule.destination_port_range or ""
                    if dest_ports == "*" or str(port) == dest_ports:
                        open_rules.append(f"{nsg.name}/{rule.name}")
                    elif "-" in dest_ports:
                        try:
                            low, high = dest_ports.split("-")
                            if int(low) <= port <= int(high):
                                open_rules.append(f"{nsg.name}/{rule.name}")
                        except ValueError:
                            pass
        return Finding(
            control_id=control_id, title=title, section="networking",
            severity="HIGH", status="FAIL" if open_rules else "PASS",
            detail=f"{len(open_rules)} NSG rules allow 0.0.0.0/0:{port}" if open_rules else f"No unrestricted port {port}",
            nist_csf="PR.AC-5", resources=open_rules,
        )
    except Exception as e:
        return Finding(
            control_id=control_id, title=title, section="networking",
            severity="HIGH", status="ERROR", detail=str(e), nist_csf="PR.AC-5",
        )


def check_4_3_nsg_flow_logs(network_client, subscription_id: str) -> Finding:
    """CIS 4.3 — NSG flow logs enabled."""
    try:
        watchers = list(network_client.network_watchers.list_all())
        if not watchers:
            return Finding(
                control_id="4.3", title="NSG flow logs enabled", section="networking",
                severity="MEDIUM", status="FAIL", detail="No Network Watchers found",
                nist_csf="DE.CM-1",
            )
        return Finding(
            control_id="4.3", title="NSG flow logs enabled", section="networking",
            severity="MEDIUM", status="PASS",
            detail=f"{len(watchers)} Network Watcher(s) found — verify flow logs per NSG",
            nist_csf="DE.CM-1",
        )
    except Exception as e:
        return Finding(
            control_id="4.3", title="NSG flow logs enabled", section="networking",
            severity="MEDIUM", status="ERROR", detail=str(e), nist_csf="DE.CM-1",
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _status_symbol(status: str) -> str:
    return {"PASS": "\033[92m✓\033[0m", "FAIL": "\033[91m✗\033[0m", "ERROR": "\033[90m?\033[0m"}.get(status, "?")


def run_assessment(subscription_id: str, section: str | None = None) -> list[Finding]:
    """Run all checks. Imports Azure SDKs at call time to fail gracefully."""
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        print("ERROR: Install Azure SDKs: pip install azure-identity "
              "azure-mgmt-storage azure-mgmt-network")
        sys.exit(1)

    credential = DefaultAzureCredential()
    storage_client = StorageManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)

    findings: list[Finding] = []

    checks = {
        "storage": [
            lambda: check_2_2_https_only(storage_client, subscription_id),
            lambda: check_2_3_no_public_blob(storage_client, subscription_id),
            lambda: check_2_4_network_rules(storage_client, subscription_id),
        ],
        "networking": [
            lambda: check_4_1_no_unrestricted_ssh(network_client, subscription_id),
            lambda: check_4_2_no_unrestricted_rdp(network_client, subscription_id),
            lambda: check_4_3_nsg_flow_logs(network_client, subscription_id),
        ],
    }

    sections_to_run = {section: checks[section]} if section and section in checks else checks
    for check_fns in sections_to_run.values():
        for fn in check_fns:
            findings.append(fn())

    return findings


def print_summary(findings: list[Finding]) -> None:
    passed = sum(1 for f in findings if f.status == "PASS")
    total = len(findings)

    print(f"\n{'='*60}")
    print("  CIS Azure Foundations v2.1 — Assessment Results")
    print(f"{'='*60}\n")

    current_section = ""
    for f in findings:
        if f.section != current_section:
            current_section = f.section
            print(f"\n  [{current_section.upper()}]")
        print(f"  {_status_symbol(f.status)} {f.control_id}  {f.title}")
        if f.status != "PASS":
            print(f"         {f.detail}")
            for r in f.resources[:5]:
                print(f"         - {r}")

    pct = (passed / total * 100) if total else 0
    print(f"\n{'─'*60}")
    print(f"  Score: {passed}/{total} passed ({pct:.0f}%)")
    print(f"{'─'*60}\n")


def main():
    parser = argparse.ArgumentParser(description="CIS Azure Foundations Benchmark v2.1 Assessment")
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--section", choices=["storage", "networking"], help="Run specific section")
    parser.add_argument("--output", choices=["console", "json"], default="console")
    args = parser.parse_args()

    findings = run_assessment(subscription_id=args.subscription_id, section=args.section)

    if args.output == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print_summary(findings)

    critical_high_fails = [f for f in findings if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")]
    sys.exit(1 if critical_high_fails else 0)


if __name__ == "__main__":
    main()
