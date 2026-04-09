"""Tests for vulnerability triage logic — EPSS/KEV/CVSS classification."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lambda_triage.handler import Tier, TriagedFinding, classify, parse_sarif, triage


class TestClassify:
    def test_kev_is_p0(self):
        finding = {"is_kev": True, "cvss_score": 5.0, "epss_score": 0.1}
        assert classify(finding) == Tier.P0

    def test_cvss_9_is_p0(self):
        finding = {"is_kev": False, "cvss_score": 9.5, "epss_score": 0.1}
        assert classify(finding) == Tier.P0

    def test_high_cvss_high_epss_is_p1(self):
        finding = {"is_kev": False, "cvss_score": 7.5, "epss_score": 0.8}
        assert classify(finding) == Tier.P1

    def test_medium_cvss_is_p2(self):
        finding = {"is_kev": False, "cvss_score": 5.0, "epss_score": 0.4}
        assert classify(finding) == Tier.P2

    def test_low_everything_is_p3(self):
        finding = {"is_kev": False, "cvss_score": 2.0, "epss_score": 0.1}
        assert classify(finding) == Tier.P3

    def test_missing_scores_default_p3(self):
        finding = {}
        assert classify(finding) == Tier.P3


class TestParseSarif:
    def test_parse_empty_sarif(self):
        sarif = {"runs": [{"results": []}]}
        findings = parse_sarif(sarif)
        assert findings == []

    def test_parse_sarif_with_result(self):
        sarif = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CVE-2024-1234",
                            "message": {"text": "Vulnerability in express"},
                            "level": "error",
                            "properties": {"cvss_score": 7.5, "epss_score": 0.6, "is_kev": False},
                        }
                    ]
                }
            ]
        }
        findings = parse_sarif(sarif)
        assert len(findings) == 1
        assert findings[0]["vulnerability_id"] == "CVE-2024-1234"


class TestTriage:
    @patch("lambda_triage.handler._is_already_remediated", return_value=False)
    @patch("lambda_triage.handler._load_protected_packages", return_value=set())
    def test_triage_classifies_all(self, mock_protected, mock_remediated):
        findings = [
            {"vulnerability_id": "CVE-1", "is_kev": True, "cvss_score": 9.8, "epss_score": 0.95, "package": "express"},
            {"vulnerability_id": "CVE-2", "is_kev": False, "cvss_score": 3.0, "epss_score": 0.05, "package": "lodash"},
        ]
        triaged = triage(findings)
        tiers = {t.tier for t in triaged if not t.skipped}
        assert Tier.P0 in tiers
        assert Tier.P3 in tiers

    @patch("lambda_triage.handler._is_already_remediated", return_value=True)
    @patch("lambda_triage.handler._load_protected_packages", return_value=set())
    def test_already_remediated_skipped(self, mock_protected, mock_remediated):
        findings = [{"vulnerability_id": "CVE-1", "is_kev": True, "cvss_score": 9.8, "epss_score": 0.95, "package": "express"}]
        triaged = triage(findings)
        assert all(t.skipped for t in triaged)

    @patch("lambda_triage.handler._is_already_remediated", return_value=False)
    @patch("lambda_triage.handler._load_protected_packages", return_value={"lodash"})
    def test_protected_package_skipped(self, mock_protected, mock_remediated):
        findings = [{"vulnerability_id": "CVE-1", "is_kev": False, "cvss_score": 5.0, "epss_score": 0.3, "package": "lodash"}]
        triaged = triage(findings)
        assert all(t.skipped for t in triaged)


class TestTriagedFinding:
    def test_triaged_finding_fields(self):
        tf = TriagedFinding(
            vulnerability_id="CVE-2024-1234",
            package="express",
            tier=Tier.P0,
            cvss_score=9.8,
            epss_score=0.95,
            is_kev=True,
            skipped=False,
            skip_reason="",
        )
        assert tf.tier == Tier.P0
        assert tf.is_kev is True
        assert not tf.skipped
