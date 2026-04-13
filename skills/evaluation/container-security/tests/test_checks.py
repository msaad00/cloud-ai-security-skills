"""Tests for container security benchmark."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import Finding, run_benchmark


class TestDockerfile:
    def test_root_user_fails(self):
        config = {"images": [{"name": "app", "user": "root"}]}
        findings = run_benchmark(config, section="dockerfile")
        assert findings[0].status == "FAIL"

    def test_non_root_passes(self):
        config = {"images": [{"name": "app", "user": "1000"}]}
        findings = run_benchmark(config, section="dockerfile")
        assert findings[0].status == "PASS"

    def test_latest_base_fails(self):
        config = {"images": [{"name": "app", "base_image": "python:latest"}]}
        findings = run_benchmark(config, section="dockerfile")
        tag = next(f for f in findings if f.check_id == "CTR-1.2")
        assert tag.status == "FAIL"

    def test_pinned_base_passes(self):
        config = {"images": [{"name": "app", "base_image": "python:3.11-alpine"}]}
        findings = run_benchmark(config, section="dockerfile")
        tag = next(f for f in findings if f.check_id == "CTR-1.2")
        assert tag.status == "PASS"

    def test_no_healthcheck_fails(self):
        config = {"images": [{"name": "app"}]}
        findings = run_benchmark(config, section="dockerfile")
        hc = next(f for f in findings if f.check_id == "CTR-1.3")
        assert hc.status == "FAIL"


class TestImageSecurity:
    def test_secret_in_env_fails(self):
        config = {"images": [{"name": "app", "env": ["DATABASE_PASSWORD=secret123"]}]}
        findings = run_benchmark(config, section="image_security")
        sec = next(f for f in findings if f.check_id == "CTR-2.1")
        assert sec.status == "FAIL"
        assert sec.severity == "CRITICAL"

    def test_clean_env_passes(self):
        config = {"images": [{"name": "app", "env": ["NODE_ENV=production"]}]}
        findings = run_benchmark(config, section="image_security")
        sec = next(f for f in findings if f.check_id == "CTR-2.1")
        assert sec.status == "PASS"

    def test_bloated_base_fails(self):
        config = {"images": [{"name": "app", "base_image": "ubuntu:22.04"}]}
        findings = run_benchmark(config, section="image_security")
        base = next(f for f in findings if f.check_id == "CTR-2.2")
        assert base.status == "FAIL"

    def test_alpine_base_passes(self):
        config = {"images": [{"name": "app", "base_image": "python:3.11-alpine"}]}
        findings = run_benchmark(config, section="image_security")
        base = next(f for f in findings if f.check_id == "CTR-2.2")
        assert base.status == "PASS"


class TestRuntime:
    def test_writable_rootfs_fails(self):
        config = {"containers": [{"name": "app", "security_context": {}}]}
        findings = run_benchmark(config, section="runtime")
        ro = next(f for f in findings if f.check_id == "CTR-3.1")
        assert ro.status == "FAIL"

    def test_no_resource_limits_fails(self):
        config = {"containers": [{"name": "app", "resources": {}}]}
        findings = run_benchmark(config, section="runtime")
        lim = next(f for f in findings if f.check_id == "CTR-3.2")
        assert lim.status == "FAIL"

    def test_with_limits_passes(self):
        config = {"containers": [{"name": "app", "resources": {"limits": {"cpu": "1", "memory": "512Mi"}}}]}
        findings = run_benchmark(config, section="runtime")
        lim = next(f for f in findings if f.check_id == "CTR-3.2")
        assert lim.status == "PASS"


class TestRunner:
    def test_run_all(self):
        config = {"images": [{"name": "app", "user": "1000", "base_image": "python:3.11-alpine"}], "containers": []}
        findings = run_benchmark(config)
        assert len(findings) == 8
        assert all(isinstance(f, Finding) for f in findings)

    def test_all_have_cis_mapping(self):
        config = {"images": [{"name": "test"}]}
        findings = run_benchmark(config)
        for f in findings:
            assert f.cis_docker, f"{f.check_id} missing CIS Docker mapping"
