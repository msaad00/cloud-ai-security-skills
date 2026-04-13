"""Tests for Kubernetes security benchmark."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import Finding, run_benchmark


class TestPodSecurity:
    def test_privileged_pod_fails(self):
        config = {"pods": [{"name": "bad", "containers": [{"name": "c1", "securityContext": {"privileged": True}}]}]}
        findings = run_benchmark(config, section="pod_security")
        priv = next(f for f in findings if f.check_id == "K8S-1.1")
        assert priv.status == "FAIL"

    def test_safe_pod_passes(self):
        config = {
            "pods": [
                {
                    "name": "good",
                    "containers": [
                        {"name": "c1", "securityContext": {"privileged": False, "capabilities": {"drop": ["ALL"]}}},
                    ],
                }
            ]
        }
        findings = run_benchmark(config, section="pod_security")
        assert findings[0].status == "PASS"  # not privileged
        assert findings[3].status == "PASS"  # drops ALL

    def test_host_pid_fails(self):
        config = {"pods": [{"name": "bad", "spec": {"hostPID": True}}]}
        findings = run_benchmark(config, section="pod_security")
        pid = next(f for f in findings if f.check_id == "K8S-1.2")
        assert pid.status == "FAIL"

    def test_host_network_fails(self):
        config = {"pods": [{"name": "bad", "spec": {"hostNetwork": True}}]}
        findings = run_benchmark(config, section="pod_security")
        net = next(f for f in findings if f.check_id == "K8S-1.3")
        assert net.status == "FAIL"


class TestRBAC:
    def test_cluster_admin_default_fails(self):
        config = {
            "cluster_role_bindings": [
                {"name": "bad-binding", "roleRef": {"name": "cluster-admin"}, "subjects": [{"name": "default", "namespace": "default"}]}
            ]
        }
        findings = run_benchmark(config, section="rbac")
        admin = next(f for f in findings if f.check_id == "K8S-2.1")
        assert admin.status == "FAIL"

    def test_wildcard_permissions_fails(self):
        config = {"cluster_roles": [{"name": "too-broad", "rules": [{"verbs": ["*"], "resources": ["*"]}]}]}
        findings = run_benchmark(config, section="rbac")
        wc = next(f for f in findings if f.check_id == "K8S-2.2")
        assert wc.status == "FAIL"


class TestNetwork:
    def test_no_deny_policy_fails(self):
        config = {"namespaces": [{"name": "default", "network_policies": []}]}
        findings = run_benchmark(config, section="network")
        assert findings[0].status == "FAIL"

    def test_deny_policy_passes(self):
        config = {"namespaces": [{"name": "production", "network_policies": [{"name": "default-deny-ingress"}]}]}
        findings = run_benchmark(config, section="network")
        assert findings[0].status == "PASS"


class TestSecrets:
    def test_env_secrets_fails(self):
        config = {
            "pods": [
                {
                    "name": "app",
                    "containers": [
                        {"name": "c1", "env": [{"name": "DB_PASS", "valueFrom": {"secretKeyRef": {"name": "db", "key": "password"}}}]}
                    ],
                }
            ]
        }
        findings = run_benchmark(config, section="secrets")
        env = next(f for f in findings if f.check_id == "K8S-4.1")
        assert env.status == "FAIL"

    def test_no_etcd_encryption_fails(self):
        config = {"api_server": {}}
        findings = run_benchmark(config, section="secrets")
        enc = next(f for f in findings if f.check_id == "K8S-4.2")
        assert enc.status == "FAIL"


class TestImages:
    def test_latest_tag_fails(self):
        config = {"pods": [{"name": "app", "containers": [{"name": "c1", "image": "nginx:latest"}]}]}
        findings = run_benchmark(config, section="images")
        assert findings[0].status == "FAIL"

    def test_pinned_tag_passes(self):
        config = {"pods": [{"name": "app", "containers": [{"name": "c1", "image": "nginx:1.25.3-alpine"}]}]}
        findings = run_benchmark(config, section="images")
        assert findings[0].status == "PASS"


class TestRunner:
    def test_run_all(self):
        config = {"pods": [], "namespaces": [], "api_server": {}}
        findings = run_benchmark(config)
        assert len(findings) == 10
        assert all(isinstance(f, Finding) for f in findings)

    def test_all_have_cis_mapping(self):
        config = {"pods": [{"name": "test", "containers": [{"name": "c", "image": "app:v1"}]}]}
        findings = run_benchmark(config)
        for f in findings:
            assert f.cis_k8s, f"{f.check_id} missing CIS K8s mapping"
