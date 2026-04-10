"""Tests for vulnerability triage logic — EPSS/KEV/CVSS classification."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lambda_triage.handler import (  # type: ignore[import-not-found]
    Tier,
    TriagedFinding,
    classify,
    parse_sarif,
    triage,
)


def _finding(
    *,
    vuln_id="CVE-2024-0001",
    package_name="express",
    fixed_version="4.19.0",
    cvss_score=5.0,
    epss_score=0.1,
    is_kev=False,
):
    return {
        "vuln_id": vuln_id,
        "package_name": package_name,
        "package_version": "4.18.0",
        "ecosystem": "npm",
        "fixed_version": fixed_version,
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "is_kev": is_kev,
    }


class TestClassify:
    def test_kev_is_p0(self):
        f = _finding(is_kev=True, cvss_score=5.0, epss_score=0.1)
        assert classify(f) == Tier.P0_IMMEDIATE

    def test_cvss_9_is_p0(self):
        f = _finding(cvss_score=9.5, epss_score=0.1)
        assert classify(f) == Tier.P0_IMMEDIATE

    def test_high_cvss_high_epss_is_p1(self):
        f = _finding(cvss_score=7.5, epss_score=0.8)
        assert classify(f) == Tier.P1_URGENT

    def test_medium_cvss_is_p2(self):
        f = _finding(cvss_score=5.0, epss_score=0.4)
        assert classify(f) == Tier.P2_STANDARD

    def test_low_everything_is_p3(self):
        f = _finding(cvss_score=2.0, epss_score=0.1)
        assert classify(f) == Tier.P3_BACKLOG

    def test_missing_scores_default_p3(self):
        # classify() reads via .get with defaults of 0/False, so an empty
        # dict must end up in the lowest backlog tier.
        assert classify({}) == Tier.P3_BACKLOG


class TestParseSarif:
    def test_parse_empty_sarif(self):
        assert parse_sarif({"runs": [{"results": []}]}) == []

    def test_parse_sarif_with_result(self):
        sarif = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CVE-2024-1234",
                            "message": {"text": "Vulnerability in express"},
                            "level": "error",
                            "properties": {
                                "package_name": "express",
                                "package_version": "4.18.0",
                                "ecosystem": "npm",
                                "fixed_version": "4.19.0",
                                "cvss_score": 7.5,
                                "epss_score": 0.6,
                                "is_kev": False,
                            },
                        }
                    ]
                }
            ]
        }
        findings = parse_sarif(sarif)
        assert len(findings) == 1
        assert findings[0]["vuln_id"] == "CVE-2024-1234"
        assert findings[0]["package_name"] == "express"
        assert findings[0]["cvss_score"] == 7.5


class TestTriage:
    @patch("lambda_triage.handler._is_already_remediated", return_value=False)
    @patch("lambda_triage.handler._load_protected_packages", return_value=set())
    def test_triage_classifies_all(self, _protected, _remediated):
        findings = [
            _finding(vuln_id="CVE-1", is_kev=True, cvss_score=9.8, epss_score=0.95),
            _finding(vuln_id="CVE-2", package_name="lodash", cvss_score=3.0, epss_score=0.05),
        ]
        triaged = triage(findings)
        tiers = {t.tier for t in triaged}
        assert Tier.P0_IMMEDIATE in tiers
        assert Tier.P3_BACKLOG in tiers
        assert all(t.skip_reason is None for t in triaged)

    @patch("lambda_triage.handler._is_already_remediated", return_value=True)
    @patch("lambda_triage.handler._load_protected_packages", return_value=set())
    def test_already_remediated_skipped(self, _protected, _remediated):
        triaged = triage([_finding(is_kev=True, cvss_score=9.8)])
        assert all(t.tier == Tier.SKIP for t in triaged)
        assert all(t.skip_reason == "already_remediated" for t in triaged)

    @patch("lambda_triage.handler._is_already_remediated", return_value=False)
    @patch("lambda_triage.handler._load_protected_packages", return_value={"lodash"})
    def test_protected_package_skipped(self, _protected, _remediated):
        triaged = triage([_finding(package_name="lodash", cvss_score=5.0, epss_score=0.3)])
        assert all(t.tier == Tier.SKIP for t in triaged)
        assert all(t.skip_reason == "protected_package" for t in triaged)

    @patch("lambda_triage.handler._is_already_remediated", return_value=False)
    @patch("lambda_triage.handler._load_protected_packages", return_value=set())
    def test_no_fix_skipped(self, _protected, _remediated):
        triaged = triage([_finding(fixed_version=None, cvss_score=8.0)])
        assert all(t.tier == Tier.SKIP for t in triaged)
        assert all(t.skip_reason == "no_fix_available" for t in triaged)


class TestTriagedFinding:
    def test_triaged_finding_fields(self):
        tf = TriagedFinding(
            vuln_id="CVE-2024-1234",
            package_name="express",
            package_version="4.18.0",
            ecosystem="npm",
            fixed_version="4.19.0",
            cvss_score=9.8,
            epss_score=0.95,
            is_kev=True,
            tier=Tier.P0_IMMEDIATE,
            sla_hours=1,
        )
        assert tf.tier == Tier.P0_IMMEDIATE
        assert tf.is_kev is True
        assert tf.skip_reason is None
        d = tf.to_dict()
        assert d["tier"] == "P0"
        assert d["vuln_id"] == "CVE-2024-1234"
