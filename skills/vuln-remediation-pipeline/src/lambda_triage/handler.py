"""Lambda 1 — Triage: classify findings by severity, EPSS, KEV status."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REMEDIATION_TABLE = os.environ.get("REMEDIATION_TABLE", "vuln-remediation-audit")
FINDINGS_BUCKET = os.environ.get("FINDINGS_BUCKET", "vuln-remediation-findings")
GRACE_PERIOD_HOURS = int(os.environ.get("GRACE_PERIOD_HOURS", "2"))
PROTECTED_PACKAGES_SSM = os.environ.get(
    "PROTECTED_PACKAGES_SSM", "/vuln-remediation/protected-packages"
)


class Tier(str, Enum):
    P0_IMMEDIATE = "P0"
    P1_URGENT = "P1"
    P2_STANDARD = "P2"
    P3_BACKLOG = "P3"
    SKIP = "SKIP"


@dataclass
class TriagedFinding:
    """A vulnerability finding with triage classification."""

    vuln_id: str
    package_name: str
    package_version: str
    ecosystem: str
    fixed_version: str | None
    cvss_score: float
    epss_score: float
    is_kev: bool
    tier: Tier
    sla_hours: int
    skip_reason: str | None = None
    affected_agents: list[str] = field(default_factory=list)
    affected_servers: list[str] = field(default_factory=list)
    source_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "ecosystem": self.ecosystem,
            "fixed_version": self.fixed_version,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "is_kev": self.is_kev,
            "tier": self.tier.value,
            "sla_hours": self.sla_hours,
            "skip_reason": self.skip_reason,
            "affected_agents": self.affected_agents,
            "affected_servers": self.affected_servers,
            "source_file": self.source_file,
        }


# ---------------------------------------------------------------------------
# SARIF / JSON Parsers
# ---------------------------------------------------------------------------


def parse_sarif(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract findings from SARIF 2.1.0 format."""
    findings = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            props = result.get("properties", {})
            finding = {
                "vuln_id": result.get("ruleId", "UNKNOWN"),
                "package_name": props.get("package_name", ""),
                "package_version": props.get("package_version", ""),
                "ecosystem": props.get("ecosystem", "unknown"),
                "fixed_version": props.get("fixed_version"),
                "cvss_score": float(props.get("cvss_score", 0)),
                "epss_score": float(props.get("epss_score", 0)),
                "is_kev": props.get("is_kev", False),
                "affected_agents": props.get("affected_agents", []),
                "affected_servers": props.get("affected_servers", []),
                "message": result.get("message", {}).get("text", ""),
            }
            severity = result.get("level", "warning")
            if severity == "error" and finding["cvss_score"] == 0:
                finding["cvss_score"] = 7.0
            elif severity == "warning" and finding["cvss_score"] == 0:
                finding["cvss_score"] = 4.0
            findings.append(finding)
    return findings


def parse_agent_bom_json(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract findings from agent-bom JSON output."""
    findings = []
    for vuln in data.get("vulnerabilities", []):
        finding = {
            "vuln_id": vuln.get("id", "UNKNOWN"),
            "package_name": vuln.get("package", ""),
            "package_version": vuln.get("version", ""),
            "ecosystem": vuln.get("ecosystem", "unknown"),
            "fixed_version": vuln.get("fixed_version"),
            "cvss_score": float(vuln.get("cvss_score", 0)),
            "epss_score": float(vuln.get("epss_score", 0)),
            "is_kev": vuln.get("is_kev", False),
            "affected_agents": vuln.get("affected_agents", []),
            "affected_servers": vuln.get("affected_servers", []),
            "message": vuln.get("summary", ""),
        }
        findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Triage Classification
# ---------------------------------------------------------------------------

SLA_MAP = {
    Tier.P0_IMMEDIATE: 1,
    Tier.P1_URGENT: 4,
    Tier.P2_STANDARD: 72,
    Tier.P3_BACKLOG: 720,  # 30 days
}


def classify(finding: dict[str, Any]) -> Tier:
    """Classify a finding into a remediation tier."""
    cvss = finding.get("cvss_score", 0)
    epss = finding.get("epss_score", 0)
    is_kev = finding.get("is_kev", False)

    # P0: actively exploited or critical severity
    if is_kev or cvss >= 9.0:
        return Tier.P0_IMMEDIATE

    # P1: high severity with high exploitability
    if cvss >= 7.0 and epss > 0.7:
        return Tier.P1_URGENT

    # P2: medium severity or moderate exploitability
    if cvss >= 4.0 or epss > 0.3:
        return Tier.P2_STANDARD

    return Tier.P3_BACKLOG


def _load_protected_packages() -> set[str]:
    """Load protected package list from SSM Parameter Store."""
    try:
        ssm = boto3.client("ssm")
        resp = ssm.get_parameter(Name=PROTECTED_PACKAGES_SSM, WithDecryption=True)
        return set(json.loads(resp["Parameter"]["Value"]))
    except Exception:
        logger.warning("Could not load protected packages from SSM, using empty set")
        return set()


def _is_already_remediated(vuln_id: str, package_name: str) -> bool:
    """Check DynamoDB remediation log for prior fix."""
    try:
        ddb = boto3.resource("dynamodb")
        table = ddb.Table(REMEDIATION_TABLE)
        resp = table.get_item(
            Key={"vuln_id": vuln_id, "package_name": package_name}
        )
        item = resp.get("Item")
        if not item:
            return False
        return item.get("status") in ("patched", "verified")
    except Exception:
        logger.warning("Could not check remediation log, treating as new finding")
        return False


def triage(findings: list[dict[str, Any]]) -> list[TriagedFinding]:
    """Triage a list of raw findings into actionable remediation items."""
    protected = _load_protected_packages()
    triaged = []

    for f in findings:
        vuln_id = f["vuln_id"]
        pkg = f["package_name"]

        # Skip: already remediated
        if _is_already_remediated(vuln_id, pkg):
            triaged.append(_skip(f, "already_remediated"))
            continue

        # Skip: no fix available
        if not f.get("fixed_version"):
            triaged.append(_skip(f, "no_fix_available"))
            continue

        # Skip: protected package (notify only)
        if pkg in protected:
            triaged.append(_skip(f, "protected_package"))
            continue

        tier = classify(f)
        triaged.append(
            TriagedFinding(
                vuln_id=vuln_id,
                package_name=pkg,
                package_version=f.get("package_version", ""),
                ecosystem=f.get("ecosystem", "unknown"),
                fixed_version=f.get("fixed_version"),
                cvss_score=f.get("cvss_score", 0),
                epss_score=f.get("epss_score", 0),
                is_kev=f.get("is_kev", False),
                tier=tier,
                sla_hours=SLA_MAP[tier],
                affected_agents=f.get("affected_agents", []),
                affected_servers=f.get("affected_servers", []),
            )
        )

    return triaged


def _skip(f: dict[str, Any], reason: str) -> TriagedFinding:
    return TriagedFinding(
        vuln_id=f["vuln_id"],
        package_name=f["package_name"],
        package_version=f.get("package_version", ""),
        ecosystem=f.get("ecosystem", "unknown"),
        fixed_version=f.get("fixed_version"),
        cvss_score=f.get("cvss_score", 0),
        epss_score=f.get("epss_score", 0),
        is_kev=f.get("is_kev", False),
        tier=Tier.SKIP,
        sla_hours=0,
        skip_reason=reason,
    )


# ---------------------------------------------------------------------------
# Lambda Handler
# ---------------------------------------------------------------------------


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda entry point. Reads SARIF/JSON from S3, triages findings."""
    s3 = boto3.client("s3")
    bucket = event.get("bucket", FINDINGS_BUCKET)
    key = event["key"]

    logger.info("Triaging findings from s3://%s/%s", bucket, key)

    # Download findings file
    resp = s3.get_object(Bucket=bucket, Key=key)
    body = json.loads(resp["Body"].read().decode("utf-8"))

    # Parse based on format
    if "$schema" in body and "sarif" in body.get("$schema", ""):
        raw_findings = parse_sarif(body)
    else:
        raw_findings = parse_agent_bom_json(body)

    logger.info("Parsed %d raw findings", len(raw_findings))

    # Triage
    triaged = triage(raw_findings)
    actionable = [t for t in triaged if t.tier != Tier.SKIP]
    skipped = [t for t in triaged if t.tier == Tier.SKIP]

    logger.info(
        "Triage complete: %d actionable, %d skipped", len(actionable), len(skipped)
    )

    # Log skipped to DynamoDB
    _log_skipped(skipped)

    # Group by tier for Step Function map state
    result = {
        "source_key": key,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(raw_findings),
        "actionable_count": len(actionable),
        "skipped_count": len(skipped),
        "by_tier": {
            "P0": [t.to_dict() for t in actionable if t.tier == Tier.P0_IMMEDIATE],
            "P1": [t.to_dict() for t in actionable if t.tier == Tier.P1_URGENT],
            "P2": [t.to_dict() for t in actionable if t.tier == Tier.P2_STANDARD],
            "P3": [t.to_dict() for t in actionable if t.tier == Tier.P3_BACKLOG],
        },
        "skipped": [t.to_dict() for t in skipped],
    }

    return result


def _log_skipped(skipped: list[TriagedFinding]) -> None:
    """Write skip reasons to DynamoDB for audit trail."""
    if not skipped:
        return
    try:
        ddb = boto3.resource("dynamodb")
        table = ddb.Table(REMEDIATION_TABLE)
        now = datetime.now(timezone.utc).isoformat()
        with table.batch_writer() as batch:
            for t in skipped:
                batch.put_item(
                    Item={
                        "vuln_id": t.vuln_id,
                        "package_name": t.package_name,
                        "status": f"skipped:{t.skip_reason}",
                        "timestamp": now,
                        "cvss_score": str(t.cvss_score),
                        "epss_score": str(t.epss_score),
                    }
                )
    except Exception:
        logger.exception("Failed to log skipped findings to DynamoDB")
