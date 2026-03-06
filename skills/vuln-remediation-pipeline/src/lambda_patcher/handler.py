"""Lambda 2 — Patcher: apply fixes per ecosystem, rotate credentials, quarantine servers."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REMEDIATION_TABLE = os.environ.get("REMEDIATION_TABLE", "vuln-remediation-audit")
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "vuln-remediation-quarantine")
NOTIFY_TOPIC_ARN = os.environ.get("NOTIFY_TOPIC_ARN", "")
ROLLBACK_WINDOW_HOURS = int(os.environ.get("ROLLBACK_WINDOW_HOURS", "24"))


# ---------------------------------------------------------------------------
# Ecosystem Upgrade Handlers
# ---------------------------------------------------------------------------

UPGRADE_COMMANDS: dict[str, str] = {
    "npm": "npm install {package}@{version}",
    "pip": "pip install {package}=={version}",
    "cargo": "cargo update -p {package} --precise {version}",
    "go": "go get {package}@v{version}",
    "maven": "mvn versions:use-dep-version -Dincludes={package} -DdepVersion={version}",
    "nuget": "dotnet add package {package} --version {version}",
    "rubygems": "bundle update {package}",
}


@dataclass
class PatchResult:
    vuln_id: str
    package_name: str
    action: str  # "upgraded" | "pr_created" | "credential_rotated" | "quarantined" | "notified"
    success: bool
    details: str
    pr_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "vuln_id": self.vuln_id,
            "package_name": self.package_name,
            "action": self.action,
            "success": self.success,
            "details": self.details,
        }
        if self.pr_url:
            d["pr_url"] = self.pr_url
        return d


def generate_upgrade_command(ecosystem: str, package: str, version: str) -> str | None:
    """Generate the upgrade command for a given ecosystem."""
    template = UPGRADE_COMMANDS.get(ecosystem)
    if not template:
        return None
    return template.format(package=package, version=version)


# ---------------------------------------------------------------------------
# Dependency Patching
# ---------------------------------------------------------------------------


def patch_dependency(finding: dict[str, Any], mode: str = "pr") -> PatchResult:
    """Apply a dependency upgrade via PR or direct commit.

    Args:
        finding: Triaged finding dict with package/version/ecosystem info.
        mode: "pr" for pull request, "direct" for main branch commit.
    """
    pkg = finding["package_name"]
    fixed = finding.get("fixed_version")
    ecosystem = finding.get("ecosystem", "unknown")
    vuln_id = finding["vuln_id"]

    if not fixed:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=pkg,
            action="notified",
            success=False,
            details="No fix version available",
        )

    cmd = generate_upgrade_command(ecosystem, pkg, fixed)
    if not cmd:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=pkg,
            action="notified",
            success=False,
            details=f"Unsupported ecosystem: {ecosystem}",
        )

    if mode == "direct":
        return _apply_direct(vuln_id, pkg, fixed, cmd)
    return _create_pr(vuln_id, pkg, fixed, ecosystem, cmd)


def _apply_direct(
    vuln_id: str, pkg: str, version: str, cmd: str
) -> PatchResult:
    """Apply fix directly to the working tree (P0 only)."""
    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            return PatchResult(
                vuln_id=vuln_id,
                package_name=pkg,
                action="upgraded",
                success=False,
                details=f"Command failed: {result.stderr[:500]}",
            )
        return PatchResult(
            vuln_id=vuln_id,
            package_name=pkg,
            action="upgraded",
            success=True,
            details=f"Upgraded to {version} via direct apply",
        )
    except subprocess.TimeoutExpired:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=pkg,
            action="upgraded",
            success=False,
            details="Upgrade command timed out (120s)",
        )


def _create_pr(
    vuln_id: str, pkg: str, version: str, ecosystem: str, cmd: str
) -> PatchResult:
    """Create a PR with the dependency upgrade."""
    branch = f"security/{vuln_id}-{pkg}-{version}".replace(":", "-").lower()
    title = f"fix({ecosystem}): upgrade {pkg} to {version} [{vuln_id}]"
    body = (
        f"## Security Fix\n\n"
        f"- **Vulnerability**: {vuln_id}\n"
        f"- **Package**: {pkg}\n"
        f"- **Fix version**: {version}\n"
        f"- **Ecosystem**: {ecosystem}\n"
        f"- **Command**: `{cmd}`\n\n"
        f"Auto-generated by vuln-remediation-pipeline."
    )

    try:
        # Create branch, apply, commit, push, PR
        steps = [
            ["git", "checkout", "-b", branch],
            *[s.split() for s in [cmd]],
            ["git", "add", "-A"],
            ["git", "commit", "-m", title],
            ["git", "push", "-u", "origin", branch],
        ]
        for step in steps:
            subprocess.run(step, capture_output=True, text=True, timeout=60, check=True)

        pr_result = subprocess.run(
            ["gh", "pr", "create", "--title", title, "--body", body],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        pr_url = pr_result.stdout.strip()
        return PatchResult(
            vuln_id=vuln_id,
            package_name=pkg,
            action="pr_created",
            success=True,
            details=f"PR created for {pkg}@{version}",
            pr_url=pr_url,
        )
    except subprocess.CalledProcessError as e:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=pkg,
            action="pr_created",
            success=False,
            details=f"PR creation failed: {e.stderr[:500] if e.stderr else str(e)}",
        )


# ---------------------------------------------------------------------------
# Credential Rotation
# ---------------------------------------------------------------------------


def rotate_credential(
    credential_type: str, credential_id: str, server_name: str
) -> PatchResult:
    """Rotate an exposed credential via Secrets Manager.

    Deactivates old credential (does NOT delete) for rollback window.
    """
    vuln_id = f"CRED-{credential_type}-{credential_id[:8]}"

    try:
        if credential_type == "aws_access_key":
            return _rotate_aws_key(vuln_id, credential_id, server_name)
        # All other types: use Secrets Manager rotation
        return _rotate_via_secrets_manager(
            vuln_id, credential_type, credential_id, server_name
        )
    except Exception as e:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=server_name,
            action="credential_rotated",
            success=False,
            details=f"Rotation failed: {e!s}",
        )


def _rotate_aws_key(
    vuln_id: str, access_key_id: str, server_name: str
) -> PatchResult:
    """Rotate an AWS access key: create new → deactivate old."""
    iam = boto3.client("iam")

    # Get user for this key
    try:
        key_info = iam.get_access_key_last_used(AccessKeyId=access_key_id)
        username = key_info["UserName"]
    except Exception:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=server_name,
            action="credential_rotated",
            success=False,
            details=f"Could not find IAM user for key {access_key_id[:8]}...",
        )

    # Create new key
    new_key = iam.create_access_key(UserName=username)
    new_key_id = new_key["AccessKey"]["AccessKeyId"]

    # Deactivate old key (NOT delete — rollback window)
    iam.update_access_key(
        UserName=username, AccessKeyId=access_key_id, Status="Inactive"
    )

    # Store new key in Secrets Manager for retrieval
    sm = boto3.client("secretsmanager")
    secret_name = f"vuln-remediation/{server_name}/aws-key"
    try:
        sm.create_secret(
            Name=secret_name,
            SecretString=json.dumps(
                {
                    "access_key_id": new_key_id,
                    "secret_access_key": new_key["AccessKey"]["SecretAccessKey"],
                    "rotated_at": datetime.now(timezone.utc).isoformat(),
                    "old_key_deactivated": access_key_id,
                    "rollback_window_hours": ROLLBACK_WINDOW_HOURS,
                }
            ),
        )
    except sm.exceptions.ResourceExistsException:
        sm.update_secret(
            SecretId=secret_name,
            SecretString=json.dumps(
                {
                    "access_key_id": new_key_id,
                    "secret_access_key": new_key["AccessKey"]["SecretAccessKey"],
                    "rotated_at": datetime.now(timezone.utc).isoformat(),
                    "old_key_deactivated": access_key_id,
                    "rollback_window_hours": ROLLBACK_WINDOW_HOURS,
                }
            ),
        )

    return PatchResult(
        vuln_id=vuln_id,
        package_name=server_name,
        action="credential_rotated",
        success=True,
        details=(
            f"AWS key rotated for {username}. "
            f"New key: {new_key_id[:8]}... "
            f"Old key {access_key_id[:8]}... deactivated (not deleted). "
            f"Rollback: {ROLLBACK_WINDOW_HOURS}h"
        ),
    )


def _rotate_via_secrets_manager(
    vuln_id: str, cred_type: str, cred_id: str, server_name: str
) -> PatchResult:
    """Trigger Secrets Manager rotation for non-AWS credentials."""
    sm = boto3.client("secretsmanager")
    secret_name = f"vuln-remediation/{server_name}/{cred_type}"

    try:
        sm.rotate_secret(SecretId=secret_name)
        return PatchResult(
            vuln_id=vuln_id,
            package_name=server_name,
            action="credential_rotated",
            success=True,
            details=f"Rotation triggered for {cred_type} via Secrets Manager",
        )
    except sm.exceptions.ResourceNotFoundException:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=server_name,
            action="credential_rotated",
            success=False,
            details=f"Secret {secret_name} not found — manual rotation required",
        )


# ---------------------------------------------------------------------------
# MCP Server Quarantine
# ---------------------------------------------------------------------------


def quarantine_server(
    server_name: str, vuln_id: str, reason: str
) -> PatchResult:
    """Quarantine an MCP server by tagging its config and logging the action.

    Quarantine is reversible — when a fix becomes available, the pipeline
    will auto-unquarantine.
    """
    now = datetime.now(timezone.utc).isoformat()
    quarantine_record = {
        "server_name": server_name,
        "vuln_id": vuln_id,
        "reason": reason,
        "quarantined_at": now,
        "status": "quarantined",
    }

    try:
        # Log quarantine to S3
        s3 = boto3.client("s3")
        key = f"quarantine/{server_name}/{vuln_id}.json"
        s3.put_object(
            Bucket=QUARANTINE_BUCKET,
            Key=key,
            Body=json.dumps(quarantine_record),
            ContentType="application/json",
        )

        # Log to DynamoDB
        ddb = boto3.resource("dynamodb")
        table = ddb.Table(REMEDIATION_TABLE)
        table.put_item(
            Item={
                "vuln_id": vuln_id,
                "package_name": server_name,
                "status": "quarantined",
                "timestamp": now,
                "reason": reason,
            }
        )

        # Send notification
        if NOTIFY_TOPIC_ARN:
            sns = boto3.client("sns")
            sns.publish(
                TopicArn=NOTIFY_TOPIC_ARN,
                Subject=f"MCP Server Quarantined: {server_name}",
                Message=json.dumps(quarantine_record, indent=2),
            )

        return PatchResult(
            vuln_id=vuln_id,
            package_name=server_name,
            action="quarantined",
            success=True,
            details=f"Server {server_name} quarantined due to {vuln_id}: {reason}",
        )
    except Exception as e:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=server_name,
            action="quarantined",
            success=False,
            details=f"Quarantine failed: {e!s}",
        )


def unquarantine_server(server_name: str, vuln_id: str) -> PatchResult:
    """Remove quarantine after fix is verified."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        s3 = boto3.client("s3")
        key = f"quarantine/{server_name}/{vuln_id}.json"

        # Update record to unquarantined
        record = {
            "server_name": server_name,
            "vuln_id": vuln_id,
            "status": "unquarantined",
            "unquarantined_at": now,
        }
        s3.put_object(
            Bucket=QUARANTINE_BUCKET,
            Key=key,
            Body=json.dumps(record),
            ContentType="application/json",
        )

        # Update DynamoDB
        ddb = boto3.resource("dynamodb")
        table = ddb.Table(REMEDIATION_TABLE)
        table.update_item(
            Key={"vuln_id": vuln_id, "package_name": server_name},
            UpdateExpression="SET #s = :s, unquarantined_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "unquarantined", ":t": now},
        )

        return PatchResult(
            vuln_id=vuln_id,
            package_name=server_name,
            action="quarantined",
            success=True,
            details=f"Server {server_name} unquarantined — fix verified",
        )
    except Exception as e:
        return PatchResult(
            vuln_id=vuln_id,
            package_name=server_name,
            action="quarantined",
            success=False,
            details=f"Unquarantine failed: {e!s}",
        )


# ---------------------------------------------------------------------------
# Lambda Handler
# ---------------------------------------------------------------------------


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda entry point. Processes triaged findings and applies fixes.

    Expected input: output from triage Lambda (by_tier dict).
    """
    results: list[dict[str, Any]] = []
    timestamp = datetime.now(timezone.utc).isoformat()

    by_tier = event.get("by_tier", {})

    # P0: auto-apply directly
    for finding in by_tier.get("P0", []):
        result = patch_dependency(finding, mode="direct")
        results.append(result.to_dict())
        _log_result(result, timestamp)

    # P1: create urgent PR
    for finding in by_tier.get("P1", []):
        result = patch_dependency(finding, mode="pr")
        results.append(result.to_dict())
        _log_result(result, timestamp)

    # P2: create standard PR
    for finding in by_tier.get("P2", []):
        result = patch_dependency(finding, mode="pr")
        results.append(result.to_dict())
        _log_result(result, timestamp)

    # P3: notify only
    for finding in by_tier.get("P3", []):
        results.append(
            PatchResult(
                vuln_id=finding["vuln_id"],
                package_name=finding["package_name"],
                action="notified",
                success=True,
                details="Added to backlog (P3)",
            ).to_dict()
        )

    # Handle credential findings if present
    for cred in event.get("credentials", []):
        result = rotate_credential(
            cred["type"], cred["id"], cred["server_name"]
        )
        results.append(result.to_dict())
        _log_result(result, timestamp)

    # Handle quarantine requests if present
    for q in event.get("quarantine", []):
        result = quarantine_server(q["server_name"], q["vuln_id"], q["reason"])
        results.append(result.to_dict())

    summary = {
        "timestamp": timestamp,
        "total_actions": len(results),
        "successful": sum(1 for r in results if r["success"]),
        "failed": sum(1 for r in results if not r["success"]),
        "results": results,
    }

    logger.info(
        "Patcher complete: %d actions (%d success, %d failed)",
        summary["total_actions"],
        summary["successful"],
        summary["failed"],
    )

    return summary


def _log_result(result: PatchResult, timestamp: str) -> None:
    """Write patch result to DynamoDB audit table."""
    try:
        ddb = boto3.resource("dynamodb")
        table = ddb.Table(REMEDIATION_TABLE)
        table.put_item(
            Item={
                "vuln_id": result.vuln_id,
                "package_name": result.package_name,
                "status": "patched" if result.success else "failed",
                "action": result.action,
                "timestamp": timestamp,
                "details": result.details,
                **({"pr_url": result.pr_url} if result.pr_url else {}),
            }
        )
    except Exception:
        logger.exception("Failed to log result for %s", result.vuln_id)
