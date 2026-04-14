"""Lambda 2: Worker — execute IAM remediation for each validated user.

Receives validated entries from the parser Lambda via Step Function
Map state. For each IAM user:

    1. Deactivate all access keys
    2. Delete login profile (console access)
    3. Remove from all groups
    4. Detach all managed policies
    5. Delete all inline policies
    6. Delete MFA devices
    7. Delete signing certificates
    8. Tag user with audit metadata
    9. DELETE the IAM user (after all dependencies removed)
    10. Write audit record

AWS IAM deletion requires ALL dependencies to be removed first.
The order matters — you cannot delete a user with active keys, policies,
group memberships, MFA devices, or signing certificates.

MITRE ATT&CK coverage:
    T1531     Account Access Removal — revoking departed-employee access
    T1098.001 Account Manipulation: Additional Cloud Credentials — removing orphaned keys
    T1078.004 Valid Accounts: Cloud Accounts — eliminating persistence vector

NIST CSF:
    PR.AC-1   Identities and credentials are issued, managed, verified, revoked
    PR.AC-4   Access permissions and authorizations are managed
    RS.MI-2   Incidents are mitigated

CIS Controls v8:
    5.3   Disable Dormant Accounts
    6.2   Establish an Access Revoking Process
    6.5   Require MFA for Administrative Access (clean up MFA devices)

SOC 2 (Trust Services Criteria):
    CC6.1   Logical and Physical Access Controls — access revocation
    CC6.2   Prior to Issuing System Credentials — lifecycle management
    CC6.3   Registration and Authorization — deprovisioning
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CROSS_ACCOUNT_ROLE = os.environ.get("IAM_CROSS_ACCOUNT_ROLE", "iam-remediation-role")
AUDIT_TABLE = os.environ.get("IAM_AUDIT_DYNAMODB_TABLE", "iam-remediation-audit")
AUDIT_BUCKET = os.environ.get("IAM_REMEDIATION_BUCKET", "")
ACCOUNT_ID_RE = re.compile(r"^\d{12}$")


def handler(event: dict, context: Any) -> dict:
    """Step Function Map task: remediate a single IAM user.

    Input (from Step Function Map over validated_entries):
        {
            "entry": {
                "email": "jane.doe@company.com",
                "recipient_account_id": "123456789012",
                "iam_username": "jane.doe",
                "terminated_at": "2026-02-15T00:00:00+00:00",
                ...
            },
            "source_bucket": "my-bucket",
            "source_key": "departures/2026-03-01.json"
        }

    Output:
        {
            "email": "...",
            "iam_username": "...",
            "account_id": "...",
            "status": "remediated"|"error",
            "actions_taken": [...],
            "error": "..." (if status == "error")
        }
    """
    entry = event.get("entry", event)
    if not isinstance(entry, dict):
        entry = {}

    try:
        account_id = _require_non_empty_str(entry, "recipient_account_id")
        iam_username = _require_non_empty_str(entry, "iam_username")
        email = _require_non_empty_str(entry, "email")
        if not ACCOUNT_ID_RE.fullmatch(account_id):
            raise ValueError("recipient_account_id must be a 12-digit AWS account ID")
    except ValueError as exc:
        logger.warning("Invalid remediation payload: %s", exc)
        audit_record = _build_audit_record(entry, [], "error", error="Invalid remediation payload", context=context)
        _write_audit(audit_record)
        return {
            "email": entry.get("email", ""),
            "iam_username": entry.get("iam_username", ""),
            "account_id": entry.get("recipient_account_id", ""),
            "status": "error",
            "actions_taken": [],
            "error": "Invalid remediation payload",
        }

    logger.info(
        "Remediating IAM user: %s in account %s (employee: %s)",
        iam_username,
        account_id,
        email,
    )

    actions_taken: list[dict] = []
    try:
        iam = _get_iam_client(account_id)

        # Step 1: Deactivate all access keys
        _deactivate_access_keys(iam, iam_username, actions_taken)

        # Step 2: Delete login profile (console access)
        _delete_login_profile(iam, iam_username, actions_taken)

        # Step 3: Remove from all groups
        _remove_from_groups(iam, iam_username, actions_taken)

        # Step 4: Detach all managed policies
        _detach_managed_policies(iam, iam_username, actions_taken)

        # Step 5: Delete all inline policies
        _delete_inline_policies(iam, iam_username, actions_taken)

        # Step 6: Deactivate and delete MFA devices
        _delete_mfa_devices(iam, iam_username, actions_taken)

        # Step 7: Delete signing certificates
        _delete_signing_certificates(iam, iam_username, actions_taken)

        # Step 8: Delete SSH public keys
        _delete_ssh_keys(iam, iam_username, actions_taken)

        # Step 9: Delete service-specific credentials
        _delete_service_credentials(iam, iam_username, actions_taken)

        # Step 10: Tag user with audit metadata before deletion
        _tag_user_for_audit(iam, iam_username, entry, actions_taken)

        # Step 11: DELETE the IAM user (all deps removed)
        iam.delete_user(UserName=iam_username)
        actions_taken.append(
            {
                "action": "delete_user",
                "target": iam_username,
                "timestamp": _now(),
            }
        )

        logger.info("Successfully deleted IAM user: %s", iam_username)

        # Step 12: Write audit record
        audit_record = _build_audit_record(entry, actions_taken, "remediated", context=context)
        _write_audit(audit_record)

        return {
            "email": email,
            "iam_username": iam_username,
            "account_id": account_id,
            "status": "remediated",
            "actions_taken": actions_taken,
            "remediated_at": _now(),
        }

    except Exception as exc:
        logger.exception("Remediation failed for %s in %s", iam_username, account_id)

        # Still write audit — record the failure
        audit_record = _build_audit_record(entry, actions_taken, "error", error=str(exc), context=context)
        _write_audit(audit_record)

        return {
            "email": email,
            "iam_username": iam_username,
            "account_id": account_id,
            "status": "error",
            "actions_taken": actions_taken,
            "error": str(exc),
        }


# ── IAM Remediation Steps ──────────────────────────────────────────


def _deactivate_access_keys(iam: Any, username: str, actions: list) -> None:
    """Deactivate and delete all access keys for the user."""
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=username):
        for key_meta in page["AccessKeyMetadata"]:
            key_id = key_meta["AccessKeyId"]

            # Deactivate first (safer — reversible)
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key_id,
                Status="Inactive",
            )
            actions.append(
                {
                    "action": "deactivate_access_key",
                    "target": key_id,
                    "timestamp": _now(),
                }
            )

            # Then delete (required before user deletion)
            iam.delete_access_key(
                UserName=username,
                AccessKeyId=key_id,
            )
            actions.append(
                {
                    "action": "delete_access_key",
                    "target": key_id,
                    "timestamp": _now(),
                }
            )


def _delete_login_profile(iam: Any, username: str, actions: list) -> None:
    """Delete console login profile (password)."""
    try:
        iam.delete_login_profile(UserName=username)
        actions.append(
            {
                "action": "delete_login_profile",
                "target": username,
                "timestamp": _now(),
            }
        )
    except iam.exceptions.NoSuchEntityException:
        pass  # No login profile — console access was never enabled


def _remove_from_groups(iam: Any, username: str, actions: list) -> None:
    """Remove user from all IAM groups."""
    paginator = iam.get_paginator("list_groups_for_user")
    for page in paginator.paginate(UserName=username):
        for group in page["Groups"]:
            group_name = group["GroupName"]
            iam.remove_user_from_group(
                GroupName=group_name,
                UserName=username,
            )
            actions.append(
                {
                    "action": "remove_from_group",
                    "target": group_name,
                    "timestamp": _now(),
                }
            )


def _detach_managed_policies(iam: Any, username: str, actions: list) -> None:
    """Detach all managed policies from the user."""
    paginator = iam.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=username):
        for policy in page["AttachedPolicies"]:
            iam.detach_user_policy(
                UserName=username,
                PolicyArn=policy["PolicyArn"],
            )
            actions.append(
                {
                    "action": "detach_managed_policy",
                    "target": policy["PolicyArn"],
                    "timestamp": _now(),
                }
            )


def _delete_inline_policies(iam: Any, username: str, actions: list) -> None:
    """Delete all inline policies from the user."""
    paginator = iam.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=username):
        for policy_name in page["PolicyNames"]:
            iam.delete_user_policy(
                UserName=username,
                PolicyName=policy_name,
            )
            actions.append(
                {
                    "action": "delete_inline_policy",
                    "target": policy_name,
                    "timestamp": _now(),
                }
            )


def _delete_mfa_devices(iam: Any, username: str, actions: list) -> None:
    """Deactivate and delete all MFA devices."""
    paginator = iam.get_paginator("list_mfa_devices")
    for page in paginator.paginate(UserName=username):
        for device in page["MFADevices"]:
            serial = device["SerialNumber"]
            iam.deactivate_mfa_device(
                UserName=username,
                SerialNumber=serial,
            )
            # Virtual MFA devices need explicit deletion
            if ":mfa/" in serial:
                try:
                    iam.delete_virtual_mfa_device(SerialNumber=serial)
                except iam.exceptions.NoSuchEntityException:
                    pass
            actions.append(
                {
                    "action": "delete_mfa_device",
                    "target": serial,
                    "timestamp": _now(),
                }
            )


def _delete_signing_certificates(iam: Any, username: str, actions: list) -> None:
    """Delete all signing certificates."""
    paginator = iam.get_paginator("list_signing_certificates")
    for page in paginator.paginate(UserName=username):
        for cert in page["Certificates"]:
            iam.delete_signing_certificate(
                UserName=username,
                CertificateId=cert["CertificateId"],
            )
            actions.append(
                {
                    "action": "delete_signing_certificate",
                    "target": cert["CertificateId"],
                    "timestamp": _now(),
                }
            )


def _delete_ssh_keys(iam: Any, username: str, actions: list) -> None:
    """Delete all SSH public keys."""
    paginator = iam.get_paginator("list_ssh_public_keys")
    for page in paginator.paginate(UserName=username):
        for key in page["SSHPublicKeys"]:
            iam.delete_ssh_public_key(
                UserName=username,
                SSHPublicKeyId=key["SSHPublicKeyId"],
            )
            actions.append(
                {
                    "action": "delete_ssh_key",
                    "target": key["SSHPublicKeyId"],
                    "timestamp": _now(),
                }
            )


def _delete_service_credentials(iam: Any, username: str, actions: list) -> None:
    """Delete service-specific credentials (CodeCommit, etc.)."""
    try:
        response = iam.list_service_specific_credentials(UserName=username)
        for cred in response.get("ServiceSpecificCredentials", []):
            iam.delete_service_specific_credential(
                UserName=username,
                ServiceSpecificCredentialId=cred["ServiceSpecificCredentialId"],
            )
            actions.append(
                {
                    "action": "delete_service_credential",
                    "target": cred["ServiceSpecificCredentialId"],
                    "timestamp": _now(),
                }
            )
    except Exception:
        pass  # Some accounts may not support this API


def _tag_user_for_audit(iam: Any, username: str, entry: dict, actions: list) -> None:
    """Tag IAM user with audit metadata before deletion.

    Tags persist briefly before deletion but are captured in CloudTrail.
    """
    tags = [
        {"Key": "remediation-action", "Value": "departed-employee-cleanup"},
        {"Key": "remediation-timestamp", "Value": _now()},
        {"Key": "employee-email", "Value": entry.get("email", "")[:256]},
        {"Key": "terminated-at", "Value": entry.get("terminated_at", "")[:256]},
        {"Key": "termination-source", "Value": entry.get("termination_source", "")[:256]},
    ]
    try:
        iam.tag_user(UserName=username, Tags=tags)
        actions.append(
            {
                "action": "tag_user",
                "target": username,
                "tags": {t["Key"]: t["Value"] for t in tags},
                "timestamp": _now(),
            }
        )
    except Exception:
        logger.warning("Failed to tag user %s before deletion", username)


# ── Audit ───────────────────────────────────────────────────────────


def _build_audit_record(
    entry: dict,
    actions: list[dict],
    status: str,
    error: str = "",
    context: Any | None = None,
) -> dict:
    """Build a complete audit record for compliance logging."""
    return {
        "audit_timestamp": _now(),
        "email": entry.get("email", ""),
        "iam_username": entry.get("iam_username", ""),
        "account_id": entry.get("recipient_account_id", ""),
        "terminated_at": entry.get("terminated_at", ""),
        "termination_source": entry.get("termination_source", ""),
        "is_rehire": entry.get("is_rehire", False),
        "rehire_date": entry.get("rehire_date"),
        "status": status,
        "error": error,
        "actions_taken": actions,
        "actions_count": len(actions),
        "lambda_function": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unknown"),
        "lambda_request_id": getattr(context, "aws_request_id", ""),
        "invoked_by": os.environ.get("SKILL_CALLER_ID", ""),
        "invoked_by_email": os.environ.get("SKILL_CALLER_EMAIL", ""),
        "agent_session_id": os.environ.get("SKILL_SESSION_ID", ""),
        "caller_roles": os.environ.get("SKILL_CALLER_ROLES", ""),
        "approved_by": os.environ.get("SKILL_APPROVER_ID", ""),
        "approved_by_email": os.environ.get("SKILL_APPROVER_EMAIL", ""),
        "approval_ticket": os.environ.get("SKILL_APPROVAL_TICKET", ""),
        "approval_timestamp": os.environ.get("SKILL_APPROVAL_TIMESTAMP", ""),
    }


def _write_audit(record: dict) -> None:
    """Write audit record to DynamoDB and S3.

    Dual-write ensures audit durability:
    - DynamoDB: fast queries for operational dashboards
    - S3: immutable long-term storage for compliance

    The audit record is then ingested back to the source data warehouse
    (Snowflake/Databricks/ClickHouse) via a separate ETL process to
    update the remediation_status column and close the loop.
    """
    # DynamoDB audit
    if AUDIT_TABLE:
        try:
            dynamodb = boto3.resource("dynamodb")
            table = dynamodb.Table(AUDIT_TABLE)
            table.put_item(
                Item={
                    "pk": f"AUDIT#{record['account_id']}#{record['iam_username']}",
                    "sk": record["audit_timestamp"],
                    **{k: v for k, v in record.items() if v is not None and v != ""},
                    "actions_taken": json.dumps(record.get("actions_taken", [])),
                }
            )
        except Exception:
            logger.exception("Failed to write DynamoDB audit record")

    # S3 audit (append to daily log)
    if AUDIT_BUCKET:
        try:
            s3 = boto3.client("s3")
            date_str = record["audit_timestamp"][:10]
            key = f"departures/audit/{date_str}/{record['iam_username']}.json"
            s3.put_object(
                Bucket=AUDIT_BUCKET,
                Key=key,
                Body=json.dumps(record, indent=2, default=str).encode("utf-8"),
                ContentType="application/json",
                ServerSideEncryption="aws:kms",
            )
        except Exception:
            logger.exception("Failed to write S3 audit record")


# ── Helpers ─────────────────────────────────────────────────────────


def _get_iam_client(account_id: str) -> Any:
    """Assume cross-account role for IAM operations."""
    if not ACCOUNT_ID_RE.fullmatch(account_id):
        raise ValueError("Invalid AWS account ID")

    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}"

    credentials = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="iam-departures-worker",
        DurationSeconds=3600,  # 1 hour for full remediation
    )["Credentials"]

    return boto3.client(
        "iam",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_non_empty_str(entry: dict[str, Any], field: str) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing required field: {field}")
    return value.strip()
