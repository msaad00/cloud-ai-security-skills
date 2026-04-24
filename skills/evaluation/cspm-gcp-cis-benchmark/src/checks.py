"""
CIS GCP Foundations Benchmark v3.0 — Automated Assessment

10 CIS controls across IAM, Storage, Logging, and Networking.
Read-only: requires roles/viewer + roles/iam.securityReviewer.

Frameworks:
    CIS GCP Foundations v3.0
    NIST CSF 2.0: PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, PR.DS-1, PR.DS-2,
                  DE.AE-3, DE.AE-5, DE.CM-1
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_native, findings_to_ocsf  # noqa: E402

SKILL_NAME = "cspm-gcp-cis-benchmark"
BENCHMARK_NAME = "CIS GCP Foundations Benchmark v3.0"
PROVIDER_NAME = "GCP"
OUTPUT_FORMATS = ("native", "ocsf")

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
# Section 1 — IAM
# ---------------------------------------------------------------------------


def check_1_1_no_gmail_accounts(crm_client, project_id: str) -> Finding:
    """CIS 1.1 — Corporate credentials only (no personal Gmail)."""
    try:
        policy = crm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
        gmail_members = []
        for binding in policy.bindings:
            for member in binding.members:
                if "gmail.com" in member.lower():
                    gmail_members.append(f"{member} -> {binding.role}")
        return Finding(
            control_id="1.1",
            title="No personal Gmail accounts",
            section="iam",
            severity="HIGH",
            status="FAIL" if gmail_members else "PASS",
            detail=f"{len(gmail_members)} personal Gmail accounts in IAM" if gmail_members else "No personal Gmail accounts",
            nist_csf="PR.AC-1",
            resources=gmail_members,
        )
    except Exception as e:
        return Finding(
            control_id="1.1",
            title="No personal Gmail accounts",
            section="iam",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_1_3_no_sa_keys(iam_client, project_id: str) -> Finding:
    """CIS 1.3 — No user-managed service account keys."""
    try:
        request = {"name": f"projects/{project_id}"}
        service_accounts = list(iam_client.list_service_accounts(request=request))
        sas_with_keys = []
        for sa in service_accounts:
            keys = list(iam_client.list_service_account_keys(request={"name": sa.name, "key_types": ["USER_MANAGED"]}))
            if keys:
                sas_with_keys.append(f"{sa.email} ({len(keys)} keys)")
        return Finding(
            control_id="1.3",
            title="No user-managed SA keys",
            section="iam",
            severity="HIGH",
            status="FAIL" if sas_with_keys else "PASS",
            detail=f"{len(sas_with_keys)} SAs with user-managed keys" if sas_with_keys else "No user-managed keys found",
            nist_csf="PR.AC-1",
            resources=sas_with_keys,
        )
    except Exception as e:
        return Finding(
            control_id="1.3",
            title="No user-managed SA keys",
            section="iam",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_1_4_sa_key_rotation(iam_client, project_id: str) -> Finding:
    """CIS 1.4 — Service account key rotation within 90 days."""
    try:
        now = datetime.now(timezone.utc)
        request = {"name": f"projects/{project_id}"}
        service_accounts = list(iam_client.list_service_accounts(request=request))
        old_keys = []
        for sa in service_accounts:
            keys = list(iam_client.list_service_account_keys(request={"name": sa.name, "key_types": ["USER_MANAGED"]}))
            for key in keys:
                created = key.valid_after_time
                if created and (now - created.replace(tzinfo=timezone.utc)).days > 90:
                    old_keys.append(f"{sa.email}: key {key.name.split('/')[-1]}")
        return Finding(
            control_id="1.4",
            title="SA key rotation (90 days)",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if old_keys else "PASS",
            detail=f"{len(old_keys)} keys older than 90 days" if old_keys else "All keys within 90 days",
            nist_csf="PR.AC-1",
            resources=old_keys,
        )
    except Exception as e:
        return Finding(
            control_id="1.4",
            title="SA key rotation (90 days)",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


# ---------------------------------------------------------------------------
# Section 2 — Storage
# ---------------------------------------------------------------------------


def check_2_3_no_public_buckets(storage_client, project_id: str) -> Finding:
    """CIS 2.3 — No public buckets."""
    try:
        buckets = list(storage_client.list_buckets(project=project_id))
        public_buckets = []
        for bucket in buckets:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                    public_buckets.append(f"{bucket.name} -> {binding['role']}")
        return Finding(
            control_id="2.3",
            title="No public buckets",
            section="storage",
            severity="CRITICAL",
            status="FAIL" if public_buckets else "PASS",
            detail=f"{len(public_buckets)} public bucket bindings" if public_buckets else "No public buckets",
            nist_csf="PR.AC-3",
            resources=public_buckets,
        )
    except Exception as e:
        return Finding(
            control_id="2.3",
            title="No public buckets",
            section="storage",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
        )


def check_2_1_uniform_access(storage_client, project_id: str) -> Finding:
    """CIS 2.1 — Uniform bucket-level access."""
    try:
        buckets = list(storage_client.list_buckets(project=project_id))
        legacy_acl = []
        for bucket in buckets:
            if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                legacy_acl.append(bucket.name)
        return Finding(
            control_id="2.1",
            title="Uniform bucket-level access",
            section="storage",
            severity="HIGH",
            status="FAIL" if legacy_acl else "PASS",
            detail=f"{len(legacy_acl)} buckets with legacy ACL" if legacy_acl else "All buckets use uniform access",
            nist_csf="PR.AC-3",
            resources=legacy_acl,
        )
    except Exception as e:
        return Finding(
            control_id="2.1",
            title="Uniform bucket-level access",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
        )


# ---------------------------------------------------------------------------
# Section 3 — Logging
# ---------------------------------------------------------------------------


def _iter_audit_configs(policy) -> list:
    configs = getattr(policy, "audit_configs", None)
    if configs is None and isinstance(policy, dict):
        configs = policy.get("audit_configs")
    return list(configs or [])


def _iter_audit_log_configs(config) -> list:
    audit_log_configs = getattr(config, "audit_log_configs", None)
    if audit_log_configs is None and isinstance(config, dict):
        audit_log_configs = config.get("audit_log_configs")
    return list(audit_log_configs or [])


def check_3_1_audit_logging_all_services(crm_client, project_id: str) -> Finding:
    """CIS 3.1 — Audit logging enabled for all services."""
    try:
        policy = crm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
        required = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
        configured: set[str] = set()
        exemptions: list[str] = []

        for config in _iter_audit_configs(policy):
            service = getattr(config, "service", None)
            if service is None and isinstance(config, dict):
                service = config.get("service")
            if service != "allServices":
                continue
            for log_config in _iter_audit_log_configs(config):
                log_type = getattr(log_config, "log_type", None)
                if log_type is None and isinstance(log_config, dict):
                    log_type = log_config.get("log_type")
                if log_type:
                    configured.add(str(log_type))
                exempted_members = getattr(log_config, "exempted_members", None)
                if exempted_members is None and isinstance(log_config, dict):
                    exempted_members = log_config.get("exempted_members")
                for member in exempted_members or []:
                    exemptions.append(f"{log_type}:{member}")

        missing = sorted(required - configured)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if exemptions:
            details.append(f"{len(exemptions)} exempted member(s)")

        return Finding(
            control_id="3.1",
            title="Audit logging for all services",
            section="logging",
            severity="HIGH",
            status="FAIL" if details else "PASS",
            detail="; ".join(details) if details else "Admin Read, Data Read, and Data Write enabled for allServices",
            nist_csf="DE.AE-3",
            resources=missing + exemptions,
        )
    except Exception as e:
        return Finding(
            control_id="3.1",
            title="Audit logging for all services",
            section="logging",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
        )


# ---------------------------------------------------------------------------
# Section 4 — Networking
# ---------------------------------------------------------------------------


def check_4_1_default_network_deleted(network_client, project_id: str) -> Finding:
    """CIS 4.1 — Default network should be deleted."""
    try:
        request = {"project": project_id}
        networks = list(network_client.list(request=request))
        default_networks = [network.name for network in networks if getattr(network, "name", "") == "default"]
        return Finding(
            control_id="4.1",
            title="Default network deleted",
            section="networking",
            severity="HIGH",
            status="FAIL" if default_networks else "PASS",
            detail="Default VPC network still exists" if default_networks else "Default VPC network not present",
            nist_csf="PR.AC-5",
            resources=default_networks,
        )
    except Exception as e:
        return Finding(
            control_id="4.1",
            title="Default network deleted",
            section="networking",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


def check_4_2_no_unrestricted_ssh_rdp(compute_client, project_id: str) -> Finding:
    """CIS 4.2 — No unrestricted SSH/RDP in firewall rules."""
    try:
        request = {"project": project_id}
        firewalls = compute_client.list(request=request)
        open_rules = []
        for rule in firewalls:
            if rule.direction != "INGRESS" or rule.disabled:
                continue
            for allowed in rule.allowed or []:
                ports: list[int] = []
                for p in allowed.ports or []:
                    if "-" in p:
                        low, high = p.split("-")
                        ports.extend(range(int(low), int(high) + 1))
                    else:
                        ports.append(int(p))
                if (22 in ports or 3389 in ports) and "0.0.0.0/0" in (rule.source_ranges or []):
                    open_rules.append(f"{rule.name}: {allowed.ip_protocol}/{','.join(allowed.ports or [])}")
        return Finding(
            control_id="4.2",
            title="No unrestricted SSH/RDP",
            section="networking",
            severity="HIGH",
            status="FAIL" if open_rules else "PASS",
            detail=f"{len(open_rules)} rules allow 0.0.0.0/0 on SSH/RDP" if open_rules else "No unrestricted SSH/RDP",
            nist_csf="PR.AC-5",
            resources=open_rules,
        )
    except Exception as e:
        return Finding(
            control_id="4.2",
            title="No unrestricted SSH/RDP",
            section="networking",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


def check_4_3_vpc_flow_logs(compute_client, project_id: str) -> Finding:
    """CIS 4.3 — VPC flow logs enabled on all subnets."""
    try:
        request = {"project": project_id}
        subnets = []
        for region_subnets in compute_client.aggregated_list(request=request):
            for subnet in region_subnets.subnetworks or []:
                subnets.append(subnet)
        no_logs = [s.name for s in subnets if not getattr(s, "log_config", None) or not s.log_config.enable]
        return Finding(
            control_id="4.3",
            title="VPC flow logs on all subnets",
            section="networking",
            severity="MEDIUM",
            status="FAIL" if no_logs else "PASS",
            detail=f"{len(no_logs)} subnets without flow logs" if no_logs else "All subnets have flow logs",
            nist_csf="DE.CM-1",
            resources=no_logs,
        )
    except Exception as e:
        return Finding(
            control_id="4.3",
            title="VPC flow logs on all subnets",
            section="networking",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
        )


def check_4_4_private_google_access(compute_client, project_id: str) -> Finding:
    """CIS 4.4 — Private Google Access enabled on all subnets."""
    try:
        request = {"project": project_id}
        subnets = []
        for region_subnets in compute_client.aggregated_list(request=request):
            for subnet in region_subnets.subnetworks or []:
                subnets.append(subnet)
        missing_pga = [s.name for s in subnets if not getattr(s, "private_ip_google_access", False)]
        return Finding(
            control_id="4.4",
            title="Private Google Access on all subnets",
            section="networking",
            severity="MEDIUM",
            status="FAIL" if missing_pga else "PASS",
            detail=f"{len(missing_pga)} subnets without Private Google Access" if missing_pga else "All subnets enable Private Google Access",
            nist_csf="PR.AC-5",
            resources=missing_pga,
        )
    except Exception as e:
        return Finding(
            control_id="4.4",
            title="Private Google Access on all subnets",
            section="networking",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _status_symbol(status: str) -> str:
    return {"PASS": "\033[92m✓\033[0m", "FAIL": "\033[91m✗\033[0m", "ERROR": "\033[90m?\033[0m"}.get(status, "?")


def run_assessment(project_id: str, section: str | None = None) -> list[Finding]:
    """Run all checks. Imports GCP SDKs at call time to fail gracefully."""
    try:
        from google.cloud import iam_admin_v1, resourcemanager_v3, storage
        from google.cloud.compute_v1.services.firewalls import FirewallsClient
        from google.cloud.compute_v1.services.networks import NetworksClient
        from google.cloud.compute_v1.services.subnetworks import SubnetworksClient
    except ImportError:
        print(
            "ERROR: Install GCP SDKs: pip install google-cloud-iam google-cloud-storage google-cloud-resource-manager google-cloud-compute"
        )
        sys.exit(1)

    crm = resourcemanager_v3.ProjectsClient()
    iam = iam_admin_v1.IAMClient()
    gcs = storage.Client(project=project_id)
    fw = FirewallsClient()
    nw = NetworksClient()
    sn = SubnetworksClient()

    findings: list[Finding] = []

    checks = {
        "iam": [
            lambda: check_1_1_no_gmail_accounts(crm, project_id),
            lambda: check_1_3_no_sa_keys(iam, project_id),
            lambda: check_1_4_sa_key_rotation(iam, project_id),
        ],
        "storage": [
            lambda: check_2_1_uniform_access(gcs, project_id),
            lambda: check_2_3_no_public_buckets(gcs, project_id),
        ],
        "logging": [
            lambda: check_3_1_audit_logging_all_services(crm, project_id),
        ],
        "networking": [
            lambda: check_4_1_default_network_deleted(nw, project_id),
            lambda: check_4_2_no_unrestricted_ssh_rdp(fw, project_id),
            lambda: check_4_3_vpc_flow_logs(sn, project_id),
            lambda: check_4_4_private_google_access(sn, project_id),
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

    print(f"\n{'=' * 60}")
    print("  CIS GCP Foundations v3.0 — Assessment Results")
    print(f"{'=' * 60}\n")

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
    print(f"\n{'─' * 60}")
    print(f"  Score: {passed}/{total} passed ({pct:.0f}%)")
    print(f"{'─' * 60}\n")


def main():
    parser = argparse.ArgumentParser(description="CIS GCP Foundations Benchmark v3.0 Assessment")
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--section", choices=["iam", "storage", "logging", "networking"], help="Run specific section")
    parser.add_argument("--output", choices=["console", "json"], default="console")
    parser.add_argument("--output-format", choices=list(OUTPUT_FORMATS), default="native")
    args = parser.parse_args()

    findings = run_assessment(project_id=args.project, section=args.section)

    if args.output == "json":
        rendered = (
            findings_to_ocsf(
                findings,
                skill_name=SKILL_NAME,
                benchmark_name=BENCHMARK_NAME,
                provider=PROVIDER_NAME,
                frameworks=["CIS GCP Foundations v3.0", "NIST CSF 2.0"],
            )
            if args.output_format == "ocsf"
            else findings_to_native(findings)
        )
        print(json.dumps(rendered, indent=2))
    else:
        print_summary(findings)

    critical_high_fails = [f for f in findings if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")]
    sys.exit(1 if critical_high_fails else 0)


if __name__ == "__main__":
    main()
