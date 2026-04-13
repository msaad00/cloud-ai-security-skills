"""Tests for model serving security benchmark checks."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import (
    Finding,
    check_1_1_endpoint_auth_required,
    check_1_2_no_hardcoded_api_keys,
    check_1_3_rbac_model_access,
    check_2_1_rate_limiting_enabled,
    check_2_2_input_size_limits,
    check_3_1_output_filtering,
    check_3_3_logging_no_pii,
    check_4_1_no_privileged_containers,
    check_4_2_read_only_rootfs,
    check_4_3_non_root_user,
    check_5_1_tls_enforced,
    check_5_2_no_public_endpoints,
    check_6_1_prompt_injection_guard,
    check_6_2_content_safety_enabled,
    check_6_3_model_versioning,
    run_benchmark,
)

# ═══════════════════════════════════════════════════════════════════════════
# Auth checks
# ═══════════════════════════════════════════════════════════════════════════


class TestAuthChecks:
    def test_1_1_no_auth_fails(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "none"}}]}
        f = check_1_1_endpoint_auth_required(config)
        assert f.status == "FAIL"
        assert f.severity == "CRITICAL"

    def test_1_1_with_auth_passes(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "api_key", "enabled": True}}]}
        f = check_1_1_endpoint_auth_required(config)
        assert f.status == "PASS"

    def test_1_1_empty_endpoints_passes(self):
        f = check_1_1_endpoint_auth_required({"endpoints": []})
        assert f.status == "PASS"

    def test_1_2_hardcoded_key_fails(self):
        config = {"endpoints": [{"api_key": "sk-1234567890abcdefghij1234567890abcdefghij"}]}
        f = check_1_2_no_hardcoded_api_keys(config)
        assert f.status == "FAIL"

    def test_1_2_clean_config_passes(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "env_ref"}}]}
        f = check_1_2_no_hardcoded_api_keys(config)
        assert f.status == "PASS"

    def test_1_3_rbac_passes(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "oauth2", "roles": ["admin", "user"]}}]}
        f = check_1_3_rbac_model_access(config)
        assert f.status == "PASS"

    def test_1_3_no_rbac_fails(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "api_key"}}]}
        f = check_1_3_rbac_model_access(config)
        assert f.status == "FAIL"


# ═══════════════════════════════════════════════════════════════════════════
# Abuse prevention
# ═══════════════════════════════════════════════════════════════════════════


class TestAbusePrevention:
    def test_2_1_rate_limit_fails(self):
        config = {"endpoints": [{"name": "inference", "rate_limit": {"enabled": False}}]}
        f = check_2_1_rate_limiting_enabled(config)
        assert f.status == "FAIL"

    def test_2_1_rate_limit_passes(self):
        config = {"endpoints": [{"name": "inference", "rate_limit": {"rpm": 100}}]}
        f = check_2_1_rate_limiting_enabled(config)
        assert f.status == "PASS"

    def test_2_2_no_limits_fails(self):
        config = {"endpoints": [{"name": "inference", "limits": {}}]}
        f = check_2_2_input_size_limits(config)
        assert f.status == "FAIL"

    def test_2_2_with_limits_passes(self):
        config = {"endpoints": [{"name": "inference", "limits": {"max_tokens": 4096}}]}
        f = check_2_2_input_size_limits(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Data egress
# ═══════════════════════════════════════════════════════════════════════════


class TestDataEgress:
    def test_3_1_no_filter_fails(self):
        f = check_3_1_output_filtering({})
        assert f.status == "FAIL"

    def test_3_1_filter_enabled_passes(self):
        config = {"safety": {"output_filter": True}}
        f = check_3_1_output_filtering(config)
        assert f.status == "PASS"

    def test_3_3_logging_no_redaction_fails(self):
        config = {"logging": {"log_requests": True, "redact_pii": False}}
        f = check_3_3_logging_no_pii(config)
        assert f.status == "FAIL"

    def test_3_3_logging_with_redaction_passes(self):
        config = {"logging": {"log_requests": True, "redact_pii": True}}
        f = check_3_3_logging_no_pii(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Runtime
# ═══════════════════════════════════════════════════════════════════════════


class TestRuntime:
    def test_4_1_privileged_fails(self):
        config = {"containers": [{"name": "model", "security_context": {"privileged": True}}]}
        f = check_4_1_no_privileged_containers(config)
        assert f.status == "FAIL"
        assert f.severity == "CRITICAL"

    def test_4_1_not_privileged_passes(self):
        config = {"containers": [{"name": "model", "security_context": {"privileged": False}}]}
        f = check_4_1_no_privileged_containers(config)
        assert f.status == "PASS"

    def test_4_2_writable_rootfs_fails(self):
        config = {"containers": [{"name": "model", "security_context": {}}]}
        f = check_4_2_read_only_rootfs(config)
        assert f.status == "FAIL"

    def test_4_3_root_user_fails(self):
        config = {"containers": [{"name": "model", "security_context": {"runAsUser": 0}}]}
        f = check_4_3_non_root_user(config)
        assert f.status == "FAIL"

    def test_4_3_non_root_passes(self):
        config = {"containers": [{"name": "model", "security_context": {"runAsNonRoot": True, "runAsUser": 1000}}]}
        f = check_4_3_non_root_user(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Network
# ═══════════════════════════════════════════════════════════════════════════


class TestNetwork:
    def test_5_1_http_fails(self):
        config = {"endpoints": [{"name": "inference", "url": "http://model.internal:8080"}]}
        f = check_5_1_tls_enforced(config)
        assert f.status == "FAIL"

    def test_5_1_https_passes(self):
        config = {"endpoints": [{"name": "inference", "url": "https://model.internal:8443"}]}
        f = check_5_1_tls_enforced(config)
        assert f.status == "PASS"

    def test_5_2_public_fails(self):
        config = {"endpoints": [{"name": "inference", "visibility": "public"}]}
        f = check_5_2_no_public_endpoints(config)
        assert f.status == "FAIL"


# ═══════════════════════════════════════════════════════════════════════════
# Safety
# ═══════════════════════════════════════════════════════════════════════════


class TestSafety:
    def test_6_1_no_injection_guard_fails(self):
        f = check_6_1_prompt_injection_guard({})
        assert f.status == "FAIL"

    def test_6_1_injection_guard_passes(self):
        config = {"safety": {"prompt_injection": True}}
        f = check_6_1_prompt_injection_guard(config)
        assert f.status == "PASS"

    def test_6_2_no_content_safety_fails(self):
        f = check_6_2_content_safety_enabled({})
        assert f.status == "FAIL"

    def test_6_3_latest_tag_fails(self):
        config = {"models": [{"name": "claude", "version": "latest"}]}
        f = check_6_3_model_versioning(config)
        assert f.status == "FAIL"

    def test_6_3_pinned_version_passes(self):
        config = {"models": [{"name": "claude", "version": "3.5-sonnet-20241022"}]}
        f = check_6_3_model_versioning(config)
        assert f.status == "PASS"


# ═══════════════════════════════════════════════════════════════════════════
# Integration
# ═══════════════════════════════════════════════════════════════════════════


class TestBenchmarkRunner:
    def test_run_all_sections(self):
        config = {
            "endpoints": [{"name": "inference", "auth": {"type": "api_key"}, "url": "https://model:8443"}],
            "containers": [{"name": "model", "security_context": {"runAsNonRoot": True, "readOnlyRootFilesystem": True}}],
        }
        findings = run_benchmark(config)
        assert len(findings) == 16  # All 16 checks
        assert all(isinstance(f, Finding) for f in findings)

    def test_run_single_section(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "api_key"}}]}
        findings = run_benchmark(config, section="auth")
        assert len(findings) == 3  # 3 auth checks

    def test_finding_has_compliance_mappings(self):
        config = {"endpoints": [{"name": "inference", "auth": {"type": "none"}}]}
        findings = run_benchmark(config, section="auth")
        for f in findings:
            assert f.nist_csf, f"Check {f.check_id} missing NIST CSF mapping"
