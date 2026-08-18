"""Golden ingest→detect pipe tests (#607)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipe_harness import (  # noqa: E402
    GOLDEN_DIR,
    ExtraIngestStream,
    IngestDetectPipe,
    load_jsonl,
    run_ingest_detect_pipe,
)

INGEST_DETECT_PIPES = (
    IngestDetectPipe(
        name="mcp_tool_drift",
        ingest_skill="ingest-mcp-proxy-ocsf",
        detect_skill="detect-mcp-tool-drift",
        raw_fixture="mcp_proxy_raw_sample.jsonl",
        expected_fixture="tool_drift_finding.ocsf.jsonl",
        expected_ocsf_count=7,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="mcp_prompt_injection",
        ingest_skill="ingest-mcp-proxy-ocsf",
        detect_skill="detect-prompt-injection-mcp-proxy",
        raw_fixture="mcp_prompt_injection_raw.jsonl",
        expected_fixture="mcp_prompt_injection_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=2,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="entra_credential_addition",
        ingest_skill="ingest-entra-directory-audit-ocsf",
        detect_skill="detect-entra-credential-addition",
        raw_fixture="entra_directory_audit_raw_sample.json",
        expected_fixture="entra_credential_addition_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="google_workspace_suspicious_login",
        ingest_skill="ingest-google-workspace-login-ocsf",
        detect_skill="detect-google-workspace-suspicious-login",
        raw_fixture="google_workspace_login_raw_sample.json",
        expected_fixture="google_workspace_suspicious_login_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="cloudtrail_access_key_creation",
        ingest_skill="ingest-cloudtrail-ocsf",
        detect_skill="detect-aws-access-key-creation",
        raw_fixture="cloudtrail_raw_sample.jsonl",
        expected_fixture="cloudtrail_access_key_creation_pipe_findings.ocsf.jsonl",
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="k8s_sensitive_secret_read",
        ingest_skill="ingest-k8s-audit-ocsf",
        detect_skill="detect-sensitive-secret-read-k8s",
        raw_fixture="k8s_audit_raw_sample.jsonl",
        expected_fixture="k8s_sensitive_secret_read_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=5,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="k8s_priv_esc",
        ingest_skill="ingest-k8s-audit-ocsf",
        detect_skill="detect-privilege-escalation-k8s",
        raw_fixture="k8s_audit_raw_sample.jsonl",
        expected_fixture="k8s_priv_esc_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=5,
        expected_finding_count=3,
    ),
    IngestDetectPipe(
        name="k8s_container_escape",
        ingest_skill="ingest-k8s-audit-ocsf",
        detect_skill="detect-container-escape-k8s",
        raw_fixture="k8s_container_escape_raw_sample.jsonl",
        expected_fixture="k8s_container_escape_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=4,
        expected_finding_count=3,
    ),
    IngestDetectPipe(
        name="aws_lateral_movement",
        ingest_skill="ingest-cloudtrail-ocsf",
        detect_skill="detect-lateral-movement",
        raw_fixture="aws_lateral_movement_raw_cloudtrail.json",
        expected_fixture="lateral_movement_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        extra_ingest_streams=(
            ExtraIngestStream(
                ingest_skill="ingest-vpc-flow-logs-ocsf",
                raw_fixture="aws_lateral_movement_raw_vpcflow.log",
            ),
        ),
        expected_ocsf_count=6,
        expected_finding_count=2,
    ),
    IngestDetectPipe(
        name="okta_mfa_fatigue",
        ingest_skill="ingest-okta-system-log-ocsf",
        detect_skill="detect-okta-mfa-fatigue",
        raw_fixture="okta_mfa_fatigue_raw.json",
        expected_fixture="okta_mfa_fatigue_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=3,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="okta_credential_stuffing",
        ingest_skill="ingest-okta-system-log-ocsf",
        detect_skill="detect-credential-stuffing-okta",
        raw_fixture="okta_credential_stuffing_raw.json",
        expected_fixture="okta_credential_stuffing_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=6,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="entra_role_grant",
        ingest_skill="ingest-entra-directory-audit-ocsf",
        detect_skill="detect-entra-role-grant-escalation",
        raw_fixture="entra_role_grant_raw.json",
        expected_fixture="entra_role_grant_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="entra_federated_credential",
        ingest_skill="ingest-entra-directory-audit-ocsf",
        detect_skill="detect-entra-credential-addition",
        raw_fixture="entra_federated_credential_raw.json",
        expected_fixture="entra_federated_credential_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="aws_login_profile",
        ingest_skill="ingest-cloudtrail-ocsf",
        detect_skill="detect-aws-login-profile-creation",
        raw_fixture="aws_login_profile_raw.jsonl",
        expected_fixture="aws_login_profile_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="cloudtrail_disabled",
        ingest_skill="ingest-cloudtrail-ocsf",
        detect_skill="detect-cloudtrail-disabled",
        raw_fixture="cloudtrail_disabled_raw.jsonl",
        expected_fixture="cloudtrail_disabled_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="gcp_audit_disabled",
        ingest_skill="ingest-gcp-audit-ocsf",
        detect_skill="detect-gcp-audit-logs-disabled",
        raw_fixture="gcp_audit_disabled_raw.json",
        expected_fixture="gcp_audit_disabled_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="azure_activity_logs_disabled",
        ingest_skill="ingest-azure-activity-ocsf",
        detect_skill="detect-azure-activity-logs-disabled",
        raw_fixture="azure_activity_logs_disabled_raw.json",
        expected_fixture="azure_activity_logs_disabled_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="gcp_sa_key_creation",
        ingest_skill="ingest-gcp-audit-ocsf",
        detect_skill="detect-gcp-service-account-key-creation",
        raw_fixture="gcp_sa_key_creation_raw.json",
        expected_fixture="gcp_sa_key_creation_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="aws_enumeration_burst",
        ingest_skill="ingest-cloudtrail-ocsf",
        detect_skill="detect-aws-enumeration-burst",
        raw_fixture="aws_enumeration_burst_raw.jsonl",
        expected_fixture="aws_enumeration_burst_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=6,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="aws_model_artifact_download",
        ingest_skill="ingest-cloudtrail-ocsf",
        detect_skill="detect-aws-model-artifact-download",
        raw_fixture="aws_model_artifact_download_raw.jsonl",
        expected_fixture="aws_model_artifact_download_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="gcp_sa_token_minting",
        ingest_skill="ingest-gcp-audit-ocsf",
        detect_skill="detect-gcp-service-account-token-minting",
        raw_fixture="gcp_sa_token_minting_raw.json",
        expected_fixture="gcp_sa_token_minting_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="gcp_model_artifact_download",
        ingest_skill="ingest-gcp-audit-ocsf",
        detect_skill="detect-gcp-model-artifact-download",
        raw_fixture="gcp_model_artifact_download_raw.json",
        expected_fixture="gcp_model_artifact_download_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="aws_open_security_group",
        ingest_skill="ingest-cloudtrail-ocsf",
        detect_skill="detect-aws-open-security-group",
        raw_fixture="aws_open_security_group_raw.jsonl",
        expected_fixture="aws_open_security_group_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="azure_open_nsg",
        ingest_skill="ingest-azure-activity-ocsf",
        detect_skill="detect-azure-open-nsg",
        raw_fixture="azure_open_nsg_raw.json",
        expected_fixture="azure_open_nsg_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="gcp_open_firewall",
        ingest_skill="ingest-gcp-audit-ocsf",
        detect_skill="detect-gcp-open-firewall",
        raw_fixture="gcp_open_firewall_raw.json",
        expected_fixture="gcp_open_firewall_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_ocsf_count=1,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="snowflake_account_key_creation",
        ingest_skill="ingest-snowflake-query-history-ocsf",
        detect_skill="detect-snowflake-account-key-creation",
        raw_fixture="snowflake_account_key_creation_raw.jsonl",
        expected_fixture="snowflake_account_key_creation_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=3,
        expected_finding_count=2,
    ),
    IngestDetectPipe(
        name="snowflake_bulk_egress",
        ingest_skill="ingest-snowflake-query-history-ocsf",
        detect_skill="detect-snowflake-bulk-data-egress",
        raw_fixture="snowflake_bulk_egress_raw.jsonl",
        expected_fixture="snowflake_bulk_egress_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=3,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="snowflake_network_policy_disable",
        ingest_skill="ingest-snowflake-query-history-ocsf",
        detect_skill="detect-snowflake-network-policy-disable",
        raw_fixture="snowflake_network_policy_disable_raw.jsonl",
        expected_fixture="snowflake_network_policy_disable_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=3,
        expected_finding_count=2,
    ),
    IngestDetectPipe(
        name="snowflake_replication_config_change",
        ingest_skill="ingest-snowflake-query-history-ocsf",
        detect_skill="detect-snowflake-replication-config-change",
        raw_fixture="snowflake_replication_config_change_raw.jsonl",
        expected_fixture="snowflake_replication_config_change_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=2,
        expected_finding_count=2,
    ),
    IngestDetectPipe(
        name="snowflake_session_policy_bypass",
        ingest_skill="ingest-snowflake-query-history-ocsf",
        detect_skill="detect-snowflake-session-policy-bypass",
        raw_fixture="snowflake_session_policy_bypass_raw.jsonl",
        expected_fixture="snowflake_session_policy_bypass_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=2,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="snowflake_share_creation",
        ingest_skill="ingest-snowflake-query-history-ocsf",
        detect_skill="detect-snowflake-share-creation",
        raw_fixture="snowflake_share_creation_raw.jsonl",
        expected_fixture="snowflake_share_creation_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=3,
        expected_finding_count=2,
    ),
    IngestDetectPipe(
        name="snowflake_unauthorized_grant",
        ingest_skill="ingest-snowflake-query-history-ocsf",
        detect_skill="detect-snowflake-unauthorized-grant",
        raw_fixture="snowflake_unauthorized_grant_raw.jsonl",
        expected_fixture="snowflake_unauthorized_grant_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=3,
        expected_finding_count=2,
    ),
    IngestDetectPipe(
        name="snowflake_warehouse_resize_burst",
        ingest_skill="ingest-snowflake-query-history-ocsf",
        detect_skill="detect-snowflake-warehouse-resize-burst",
        raw_fixture="snowflake_resize_burst_raw.jsonl",
        expected_fixture="snowflake_resize_burst_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=3,
        expected_finding_count=1,
    ),
)


@pytest.mark.parametrize("pipe", INGEST_DETECT_PIPES, ids=lambda p: p.name)
class TestIngestDetectGoldenPipes:
    def test_raw_to_findings_matches_frozen_golden(self, pipe: IngestDetectPipe):
        ocsf_events, findings = run_ingest_detect_pipe(pipe)
        expected = load_jsonl(GOLDEN_DIR / pipe.expected_fixture)

        if pipe.expected_ocsf_count is not None:
            assert len(ocsf_events) == pipe.expected_ocsf_count

        if pipe.expected_finding_count is not None:
            assert len(findings) == pipe.expected_finding_count == len(expected), (
                f"{pipe.name}: finding count drift (produced {len(findings)}, "
                f"expected {len(expected)})"
            )

        for produced, expected_f in zip(findings, expected):
            assert produced == expected_f, (
                f"{pipe.name}: wire-contract drift between {pipe.ingest_skill} and "
                f"{pipe.detect_skill}.\n"
                f"  produced: {json.dumps(produced, sort_keys=True)}\n"
                f"  expected: {json.dumps(expected_f, sort_keys=True)}"
            )

    def test_findings_use_detection_finding_class_uid(self, pipe: IngestDetectPipe):
        _, findings = run_ingest_detect_pipe(pipe)
        for finding in findings:
            assert finding["class_uid"] == 2004
            assert finding["metadata"]["version"] == "1.8.0"
            assert "attacks" not in finding
            assert "attacks" in finding["finding_info"]
