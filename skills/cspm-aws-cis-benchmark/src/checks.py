"""
CIS AWS Foundations Benchmark v3.0 — Automated Assessment

18 checks across IAM, Storage, Logging, and Networking.
Read-only: requires SecurityAudit managed policy.

Frameworks:
    CIS AWS Foundations v3.0
    NIST CSF 2.0: PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, PR.DS-1, PR.DS-6, DE.AE-3, DE.CM-1
    ISO 27001:2022: A.5.15, A.5.17, A.5.18, A.8.2, A.8.3, A.8.5, A.8.13, A.8.15, A.8.16, A.8.20, A.8.24
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    control_id: str
    title: str
    section: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str  # PASS, FAIL, ERROR
    detail: str = ""
    nist_csf: str = ""
    iso_27001: str = ""
    resources: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Section 1 — IAM
# ---------------------------------------------------------------------------

def check_1_1_root_mfa(iam) -> Finding:
    """CIS 1.1 — MFA on root account."""
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        has_mfa = summary.get("AccountMFAEnabled", 0) == 1
        return Finding(
            control_id="1.1", title="MFA on root account", section="iam",
            severity="CRITICAL", status="PASS" if has_mfa else "FAIL",
            detail="Root MFA enabled" if has_mfa else "Root account has no MFA",
            nist_csf="PR.AC-1", iso_27001="A.8.5",
        )
    except ClientError as e:
        return Finding(
            control_id="1.1", title="MFA on root account", section="iam",
            severity="CRITICAL", status="ERROR", detail=str(e),
            nist_csf="PR.AC-1", iso_27001="A.8.5",
        )


def check_1_2_user_mfa(iam) -> Finding:
    """CIS 1.2 — MFA for console users."""
    try:
        users = iam.list_users()["Users"]
        no_mfa = []
        for user in users:
            try:
                iam.get_login_profile(UserName=user["UserName"])
            except ClientError:
                continue  # no console access
            mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            if not mfa_devices:
                no_mfa.append(user["UserName"])
        return Finding(
            control_id="1.2", title="MFA for console users", section="iam",
            severity="HIGH", status="FAIL" if no_mfa else "PASS",
            detail=f"{len(no_mfa)} console users without MFA" if no_mfa else "All console users have MFA",
            nist_csf="PR.AC-1", iso_27001="A.8.5", resources=no_mfa,
        )
    except ClientError as e:
        return Finding(
            control_id="1.2", title="MFA for console users", section="iam",
            severity="HIGH", status="ERROR", detail=str(e),
            nist_csf="PR.AC-1", iso_27001="A.8.5",
        )


def check_1_3_stale_credentials(iam) -> Finding:
    """CIS 1.3 — Credentials unused 45+ days."""
    try:
        iam.generate_credential_report()
        report = iam.get_credential_report()["Content"].decode()
        now = datetime.now(timezone.utc)
        stale = []
        for line in report.strip().split("\n")[1:]:  # skip header
            fields = line.split(",")
            username = fields[0]
            password_last_used = fields[4]
            if password_last_used not in ("N/A", "no_information", "not_supported"):
                try:
                    last_used = datetime.fromisoformat(password_last_used.replace("Z", "+00:00"))
                    if (now - last_used).days > 45:
                        stale.append(username)
                except (ValueError, IndexError):
                    pass
        return Finding(
            control_id="1.3", title="Credentials unused 45+ days", section="iam",
            severity="MEDIUM", status="FAIL" if stale else "PASS",
            detail=f"{len(stale)} users with stale credentials" if stale else "No stale credentials",
            nist_csf="PR.AC-1", iso_27001="A.5.18", resources=stale,
        )
    except ClientError as e:
        return Finding(
            control_id="1.3", title="Credentials unused 45+ days", section="iam",
            severity="MEDIUM", status="ERROR", detail=str(e),
            nist_csf="PR.AC-1", iso_27001="A.5.18",
        )


def check_1_4_key_rotation(iam) -> Finding:
    """CIS 1.4 — Access keys rotated within 90 days."""
    try:
        now = datetime.now(timezone.utc)
        old_keys = []
        for user in iam.list_users()["Users"]:
            for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
                if key["Status"] == "Active":
                    age = (now - key["CreateDate"].replace(tzinfo=timezone.utc)).days
                    if age > 90:
                        old_keys.append(f"{user['UserName']}:{key['AccessKeyId']} ({age}d)")
        return Finding(
            control_id="1.4", title="Access keys rotated 90 days", section="iam",
            severity="MEDIUM", status="FAIL" if old_keys else "PASS",
            detail=f"{len(old_keys)} keys older than 90 days" if old_keys else "All keys within 90 days",
            nist_csf="PR.AC-1", iso_27001="A.5.17", resources=old_keys,
        )
    except ClientError as e:
        return Finding(
            control_id="1.4", title="Access keys rotated 90 days", section="iam",
            severity="MEDIUM", status="ERROR", detail=str(e),
            nist_csf="PR.AC-1", iso_27001="A.5.17",
        )


def check_1_5_password_policy(iam) -> Finding:
    """CIS 1.5 — Password policy strength."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"MinLength={policy.get('MinimumPasswordLength', 0)} (need 14+)")
        if not policy.get("RequireSymbols", False):
            issues.append("RequireSymbols=false")
        if not policy.get("RequireNumbers", False):
            issues.append("RequireNumbers=false")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("RequireUppercase=false")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("RequireLowercase=false")
        return Finding(
            control_id="1.5", title="Password policy strength", section="iam",
            severity="MEDIUM", status="FAIL" if issues else "PASS",
            detail="; ".join(issues) if issues else "Password policy meets CIS requirements",
            nist_csf="PR.AC-1", iso_27001="A.5.17",
        )
    except iam.exceptions.NoSuchEntityException:
        return Finding(
            control_id="1.5", title="Password policy strength", section="iam",
            severity="MEDIUM", status="FAIL", detail="No password policy configured",
            nist_csf="PR.AC-1", iso_27001="A.5.17",
        )


def check_1_6_no_root_keys(iam) -> Finding:
    """CIS 1.6 — No root access keys."""
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        root_keys = summary.get("AccountAccessKeysPresent", 0)
        return Finding(
            control_id="1.6", title="No root access keys", section="iam",
            severity="CRITICAL", status="PASS" if root_keys == 0 else "FAIL",
            detail="No root access keys" if root_keys == 0 else f"Root has {root_keys} access key(s)",
            nist_csf="PR.AC-4", iso_27001="A.8.2",
        )
    except ClientError as e:
        return Finding(
            control_id="1.6", title="No root access keys", section="iam",
            severity="CRITICAL", status="ERROR", detail=str(e),
            nist_csf="PR.AC-4", iso_27001="A.8.2",
        )


def check_1_7_no_inline_policies(iam) -> Finding:
    """CIS 1.7 — IAM policies not inline."""
    try:
        inline_users = []
        for user in iam.list_users()["Users"]:
            policies = iam.list_user_policies(UserName=user["UserName"])["PolicyNames"]
            if policies:
                inline_users.append(user["UserName"])
        return Finding(
            control_id="1.7", title="No inline IAM policies", section="iam",
            severity="LOW", status="FAIL" if inline_users else "PASS",
            detail=f"{len(inline_users)} users with inline policies" if inline_users else "No inline policies",
            nist_csf="PR.AC-4", iso_27001="A.5.15", resources=inline_users,
        )
    except ClientError as e:
        return Finding(
            control_id="1.7", title="No inline IAM policies", section="iam",
            severity="LOW", status="ERROR", detail=str(e),
            nist_csf="PR.AC-4", iso_27001="A.5.15",
        )


# ---------------------------------------------------------------------------
# Section 2 — Storage
# ---------------------------------------------------------------------------

def check_2_1_s3_encryption(s3) -> Finding:
    """CIS 2.1 — S3 default encryption."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        unencrypted = []
        for bucket in buckets:
            try:
                s3.get_bucket_encryption(Bucket=bucket["Name"])
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    unencrypted.append(bucket["Name"])
        return Finding(
            control_id="2.1", title="S3 default encryption", section="storage",
            severity="HIGH", status="FAIL" if unencrypted else "PASS",
            detail=f"{len(unencrypted)} buckets without encryption" if unencrypted else "All buckets encrypted",
            nist_csf="PR.DS-1", iso_27001="A.8.24", resources=unencrypted,
        )
    except ClientError as e:
        return Finding(
            control_id="2.1", title="S3 default encryption", section="storage",
            severity="HIGH", status="ERROR", detail=str(e),
            nist_csf="PR.DS-1", iso_27001="A.8.24",
        )


def check_2_2_s3_logging(s3) -> Finding:
    """CIS 2.2 — S3 server access logging."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        no_logging = []
        for bucket in buckets:
            logging_config = s3.get_bucket_logging(Bucket=bucket["Name"])
            if "LoggingEnabled" not in logging_config:
                no_logging.append(bucket["Name"])
        return Finding(
            control_id="2.2", title="S3 server access logging", section="storage",
            severity="MEDIUM", status="FAIL" if no_logging else "PASS",
            detail=f"{len(no_logging)} buckets without logging" if no_logging else "All buckets have logging",
            nist_csf="DE.AE-3", iso_27001="A.8.15", resources=no_logging,
        )
    except ClientError as e:
        return Finding(
            control_id="2.2", title="S3 server access logging", section="storage",
            severity="MEDIUM", status="ERROR", detail=str(e),
            nist_csf="DE.AE-3", iso_27001="A.8.15",
        )


def check_2_3_s3_public_access(s3) -> Finding:
    """CIS 2.3 — S3 public access blocked."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        public_buckets = []
        for bucket in buckets:
            try:
                pab = s3.get_public_access_block(Bucket=bucket["Name"])["PublicAccessBlockConfiguration"]
                if not all([
                    pab.get("BlockPublicAcls", False),
                    pab.get("IgnorePublicAcls", False),
                    pab.get("BlockPublicPolicy", False),
                    pab.get("RestrictPublicBuckets", False),
                ]):
                    public_buckets.append(bucket["Name"])
            except ClientError:
                public_buckets.append(bucket["Name"])
        return Finding(
            control_id="2.3", title="S3 public access blocked", section="storage",
            severity="CRITICAL", status="FAIL" if public_buckets else "PASS",
            detail=f"{len(public_buckets)} buckets without full public access block" if public_buckets else "All buckets block public access",
            nist_csf="PR.AC-3", iso_27001="A.8.3", resources=public_buckets,
        )
    except ClientError as e:
        return Finding(
            control_id="2.3", title="S3 public access blocked", section="storage",
            severity="CRITICAL", status="ERROR", detail=str(e),
            nist_csf="PR.AC-3", iso_27001="A.8.3",
        )


def check_2_4_s3_versioning(s3) -> Finding:
    """CIS 2.4 — S3 versioning enabled."""
    try:
        buckets = s3.list_buckets()["Buckets"]
        no_versioning = []
        for bucket in buckets:
            versioning = s3.get_bucket_versioning(Bucket=bucket["Name"])
            if versioning.get("Status") != "Enabled":
                no_versioning.append(bucket["Name"])
        return Finding(
            control_id="2.4", title="S3 versioning enabled", section="storage",
            severity="MEDIUM", status="FAIL" if no_versioning else "PASS",
            detail=f"{len(no_versioning)} buckets without versioning" if no_versioning else "All buckets versioned",
            nist_csf="PR.DS-1", iso_27001="A.8.13", resources=no_versioning,
        )
    except ClientError as e:
        return Finding(
            control_id="2.4", title="S3 versioning enabled", section="storage",
            severity="MEDIUM", status="ERROR", detail=str(e),
            nist_csf="PR.DS-1", iso_27001="A.8.13",
        )


# ---------------------------------------------------------------------------
# Section 3 — Logging
# ---------------------------------------------------------------------------

def check_3_1_cloudtrail_multiregion(ct) -> Finding:
    """CIS 3.1 — CloudTrail multi-region enabled."""
    try:
        trails = ct.describe_trails()["trailList"]
        multi_region = [t["Name"] for t in trails if t.get("IsMultiRegionTrail")]
        active_mr = []
        for name in multi_region:
            status = ct.get_trail_status(Name=name)
            if status.get("IsLogging"):
                active_mr.append(name)
        return Finding(
            control_id="3.1", title="CloudTrail multi-region", section="logging",
            severity="CRITICAL", status="PASS" if active_mr else "FAIL",
            detail=f"{len(active_mr)} active multi-region trail(s)" if active_mr else "No active multi-region trail",
            nist_csf="DE.AE-3", iso_27001="A.8.15", resources=active_mr,
        )
    except ClientError as e:
        return Finding(
            control_id="3.1", title="CloudTrail multi-region", section="logging",
            severity="CRITICAL", status="ERROR", detail=str(e),
            nist_csf="DE.AE-3", iso_27001="A.8.15",
        )


def check_3_2_cloudtrail_validation(ct) -> Finding:
    """CIS 3.2 — CloudTrail log file validation."""
    try:
        trails = ct.describe_trails()["trailList"]
        no_validation = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
        return Finding(
            control_id="3.2", title="CloudTrail log validation", section="logging",
            severity="HIGH", status="FAIL" if no_validation else "PASS",
            detail=f"{len(no_validation)} trails without log validation" if no_validation else "All trails have log validation",
            nist_csf="PR.DS-6", iso_27001="A.8.15", resources=no_validation,
        )
    except ClientError as e:
        return Finding(
            control_id="3.2", title="CloudTrail log validation", section="logging",
            severity="HIGH", status="ERROR", detail=str(e),
            nist_csf="PR.DS-6", iso_27001="A.8.15",
        )


def check_3_3_cloudtrail_s3_not_public(ct, s3) -> Finding:
    """CIS 3.3 — CloudTrail S3 bucket not public."""
    try:
        trails = ct.describe_trails()["trailList"]
        public_trail_buckets = []
        for trail in trails:
            bucket = trail.get("S3BucketName")
            if not bucket:
                continue
            try:
                pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
                if not all([
                    pab.get("BlockPublicAcls", False),
                    pab.get("IgnorePublicAcls", False),
                    pab.get("BlockPublicPolicy", False),
                    pab.get("RestrictPublicBuckets", False),
                ]):
                    public_trail_buckets.append(bucket)
            except ClientError:
                public_trail_buckets.append(bucket)
        return Finding(
            control_id="3.3", title="CloudTrail S3 not public", section="logging",
            severity="CRITICAL", status="FAIL" if public_trail_buckets else "PASS",
            detail=f"{len(public_trail_buckets)} trail buckets without public access block" if public_trail_buckets else "All trail buckets block public access",
            nist_csf="PR.AC-3", iso_27001="A.8.3", resources=public_trail_buckets,
        )
    except ClientError as e:
        return Finding(
            control_id="3.3", title="CloudTrail S3 not public", section="logging",
            severity="CRITICAL", status="ERROR", detail=str(e),
            nist_csf="PR.AC-3", iso_27001="A.8.3",
        )


def check_3_4_cloudwatch_alarms(cw) -> Finding:
    """CIS 3.4 — CloudWatch alarms for key events."""
    try:
        alarms = cw.describe_alarms()["MetricAlarms"]
        return Finding(
            control_id="3.4", title="CloudWatch alarms configured", section="logging",
            severity="MEDIUM", status="PASS" if alarms else "FAIL",
            detail=f"{len(alarms)} alarm(s) configured" if alarms else "No CloudWatch alarms configured",
            nist_csf="DE.CM-1", iso_27001="A.8.16",
        )
    except ClientError as e:
        return Finding(
            control_id="3.4", title="CloudWatch alarms configured", section="logging",
            severity="MEDIUM", status="ERROR", detail=str(e),
            nist_csf="DE.CM-1", iso_27001="A.8.16",
        )


# ---------------------------------------------------------------------------
# Section 4 — Networking
# ---------------------------------------------------------------------------

def _check_unrestricted_port(ec2, port: int, control_id: str, title: str) -> Finding:
    """Check for 0.0.0.0/0 on a specific port in security groups."""
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        open_sgs = []
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)
                if from_port <= port <= to_port:
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            open_sgs.append(f"{sg['GroupId']} ({sg.get('GroupName', '')})")
                    for ip_range in perm.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            open_sgs.append(f"{sg['GroupId']} ({sg.get('GroupName', '')})")
        return Finding(
            control_id=control_id, title=title, section="networking",
            severity="HIGH", status="FAIL" if open_sgs else "PASS",
            detail=f"{len(open_sgs)} SGs allow 0.0.0.0/0:{port}" if open_sgs else f"No SGs allow unrestricted port {port}",
            nist_csf="PR.AC-5", iso_27001="A.8.20", resources=open_sgs,
        )
    except ClientError as e:
        return Finding(
            control_id=control_id, title=title, section="networking",
            severity="HIGH", status="ERROR", detail=str(e),
            nist_csf="PR.AC-5", iso_27001="A.8.20",
        )


def check_4_1_no_unrestricted_ssh(ec2) -> Finding:
    """CIS 4.1 — No unrestricted SSH."""
    return _check_unrestricted_port(ec2, 22, "4.1", "No unrestricted SSH")


def check_4_2_no_unrestricted_rdp(ec2) -> Finding:
    """CIS 4.2 — No unrestricted RDP."""
    return _check_unrestricted_port(ec2, 3389, "4.2", "No unrestricted RDP")


def check_4_3_vpc_flow_logs(ec2) -> Finding:
    """CIS 4.3 — VPC flow logs enabled."""
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        flow_logs = ec2.describe_flow_logs()["FlowLogs"]
        vpc_ids_with_logs = {fl["ResourceId"] for fl in flow_logs if fl.get("ResourceId")}
        no_logs = [v["VpcId"] for v in vpcs if v["VpcId"] not in vpc_ids_with_logs]
        return Finding(
            control_id="4.3", title="VPC flow logs enabled", section="networking",
            severity="MEDIUM", status="FAIL" if no_logs else "PASS",
            detail=f"{len(no_logs)} VPCs without flow logs" if no_logs else "All VPCs have flow logs",
            nist_csf="DE.CM-1", iso_27001="A.8.16", resources=no_logs,
        )
    except ClientError as e:
        return Finding(
            control_id="4.3", title="VPC flow logs enabled", section="networking",
            severity="MEDIUM", status="ERROR", detail=str(e),
            nist_csf="DE.CM-1", iso_27001="A.8.16",
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

SECTIONS: dict[str, list] = {
    "iam": [
        check_1_1_root_mfa, check_1_2_user_mfa, check_1_3_stale_credentials,
        check_1_4_key_rotation, check_1_5_password_policy, check_1_6_no_root_keys,
        check_1_7_no_inline_policies,
    ],
    "storage": [check_2_1_s3_encryption, check_2_2_s3_logging, check_2_3_s3_public_access, check_2_4_s3_versioning],
    "logging": [check_3_1_cloudtrail_multiregion, check_3_2_cloudtrail_validation, check_3_3_cloudtrail_s3_not_public, check_3_4_cloudwatch_alarms],
    "networking": [check_4_1_no_unrestricted_ssh, check_4_2_no_unrestricted_rdp, check_4_3_vpc_flow_logs],
}


def _get_clients(region: str) -> dict[str, Any]:
    session = boto3.Session(region_name=region)
    return {
        "iam": session.client("iam"),
        "s3": session.client("s3"),
        "ct": session.client("cloudtrail"),
        "cw": session.client("cloudwatch"),
        "ec2": session.client("ec2"),
    }


def _run_check(fn, clients: dict) -> Finding:
    """Route check function to the right client(s)."""
    name = fn.__name__
    if "cloudtrail_s3" in name:
        return fn(clients["ct"], clients["s3"])
    if name.startswith("check_1") or name.startswith("check_1"):
        return fn(clients["iam"])
    if name.startswith("check_2"):
        return fn(clients["s3"])
    if "cloudtrail" in name or "cloudwatch" in name:
        return fn(clients["ct"] if "cloudtrail" in name else clients["cw"])
    if name.startswith("check_4"):
        return fn(clients["ec2"])
    return fn(clients["iam"])


def run_assessment(region: str = "us-east-1", section: str | None = None) -> list[Finding]:
    clients = _get_clients(region)
    findings: list[Finding] = []

    sections_to_run = {section: SECTIONS[section]} if section and section in SECTIONS else SECTIONS
    for checks in sections_to_run.values():
        for check_fn in checks:
            findings.append(_run_check(check_fn, clients))

    return findings


def _severity_color(severity: str) -> str:
    return {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[36m"}.get(severity, "")


def _status_symbol(status: str) -> str:
    return {"PASS": "\033[92m✓\033[0m", "FAIL": "\033[91m✗\033[0m", "ERROR": "\033[90m?\033[0m"}.get(status, "?")


def print_summary(findings: list[Finding]) -> None:
    passed = sum(1 for f in findings if f.status == "PASS")
    failed = sum(1 for f in findings if f.status == "FAIL")
    errors = sum(1 for f in findings if f.status == "ERROR")
    total = len(findings)

    print(f"\n{'='*60}")
    print("  CIS AWS Foundations v3.0 — Assessment Results")
    print(f"{'='*60}\n")

    current_section = ""
    for f in findings:
        if f.section != current_section:
            current_section = f.section
            print(f"\n  [{current_section.upper()}]")
        symbol = _status_symbol(f.status)
        print(f"  {symbol} {f.control_id}  {f.title}")
        if f.status != "PASS":
            print(f"         {f.detail}")
            if f.resources:
                for r in f.resources[:5]:
                    print(f"         - {r}")
                if len(f.resources) > 5:
                    print(f"         ... and {len(f.resources) - 5} more")

    print(f"\n{'─'*60}")
    pct = (passed / total * 100) if total else 0
    print(f"  Score: {passed}/{total} passed ({pct:.0f}%)")
    print(f"  PASS: {passed}  FAIL: {failed}  ERROR: {errors}")
    print(f"{'─'*60}\n")


def main():
    parser = argparse.ArgumentParser(description="CIS AWS Foundations Benchmark v3.0 Assessment")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--section", choices=list(SECTIONS.keys()), help="Run specific section only")
    parser.add_argument("--output", choices=["console", "json"], default="console", help="Output format")
    args = parser.parse_args()

    findings = run_assessment(region=args.region, section=args.section)

    if args.output == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print_summary(findings)

    # Exit code: 1 if any CRITICAL/HIGH failures
    critical_high_fails = [f for f in findings if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")]
    sys.exit(1 if critical_high_fails else 0)


if __name__ == "__main__":
    main()
