"""Standalone triage module — can run locally without Lambda."""

from __future__ import annotations

from typing import Any

from ..lambda_triage.handler import (
    Tier,
    TriagedFinding,
    classify,
    parse_agent_bom_json,
    parse_sarif,
)


def triage_local(
    data: dict[str, Any],
    protected_packages: set[str] | None = None,
    remediated_ids: set[tuple[str, str]] | None = None,
) -> list[TriagedFinding]:
    """Triage findings locally without AWS dependencies.

    Args:
        data: SARIF or agent-bom JSON dict.
        protected_packages: Set of package names to skip (notify only).
        remediated_ids: Set of (vuln_id, package_name) already remediated.

    Returns:
        List of triaged findings sorted by tier (P0 first).
    """
    protected = protected_packages or set()
    remediated = remediated_ids or set()

    # Parse
    if "$schema" in data and "sarif" in data.get("$schema", ""):
        raw = parse_sarif(data)
    else:
        raw = parse_agent_bom_json(data)

    # Classify
    SLA_MAP = {
        Tier.P0_IMMEDIATE: 1,
        Tier.P1_URGENT: 4,
        Tier.P2_STANDARD: 72,
        Tier.P3_BACKLOG: 720,
    }

    triaged: list[TriagedFinding] = []
    for f in raw:
        vuln_id = f["vuln_id"]
        pkg = f["package_name"]

        # Skip checks
        skip_reason = None
        if (vuln_id, pkg) in remediated:
            skip_reason = "already_remediated"
        elif not f.get("fixed_version"):
            skip_reason = "no_fix_available"
        elif pkg in protected:
            skip_reason = "protected_package"

        if skip_reason:
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
                    tier=Tier.SKIP,
                    sla_hours=0,
                    skip_reason=skip_reason,
                )
            )
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

    # Sort: P0 first, then P1, P2, P3, SKIP
    tier_order = {Tier.P0_IMMEDIATE: 0, Tier.P1_URGENT: 1, Tier.P2_STANDARD: 2, Tier.P3_BACKLOG: 3, Tier.SKIP: 4}
    triaged.sort(key=lambda t: (tier_order.get(t.tier, 5), -t.cvss_score))

    return triaged


def summarize(triaged: list[TriagedFinding]) -> dict[str, Any]:
    """Generate a summary of triage results."""
    by_tier: dict[str, int] = {}
    for t in triaged:
        key = t.tier.value
        by_tier[key] = by_tier.get(key, 0) + 1

    actionable = [t for t in triaged if t.tier != Tier.SKIP]
    kev_count = sum(1 for t in actionable if t.is_kev)

    return {
        "total": len(triaged),
        "actionable": len(actionable),
        "skipped": len(triaged) - len(actionable),
        "by_tier": by_tier,
        "kev_findings": kev_count,
        "top_findings": [t.to_dict() for t in actionable[:10]],
    }
