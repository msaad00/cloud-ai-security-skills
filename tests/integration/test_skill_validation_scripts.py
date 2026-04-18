from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COMMON = _load_module(
    "cloud_security_skill_validation_common_test",
    SCRIPTS / "skill_validation_common.py",
)
CONTRACT = _load_module(
    "cloud_security_validate_skill_contract_test",
    SCRIPTS / "validate_skill_contract.py",
)
SAFE = _load_module(
    "cloud_security_validate_safe_skill_bar_test",
    SCRIPTS / "validate_safe_skill_bar.py",
)
INTEGRITY = _load_module(
    "cloud_security_validate_skill_integrity_test",
    SCRIPTS / "validate_skill_integrity.py",
)
DEPENDENCIES = _load_module(
    "cloud_security_validate_dependency_consistency_test",
    SCRIPTS / "validate_dependency_consistency.py",
)
COVERAGE = _load_module(
    "cloud_security_validate_framework_coverage_test",
    SCRIPTS / "validate_framework_coverage.py",
)
OCSF_METADATA = _load_module(
    "cloud_security_validate_ocsf_metadata_test",
    SCRIPTS / "validate_ocsf_metadata.py",
)
TEST_COVERAGE = _load_module(
    "cloud_security_validate_test_coverage_test",
    SCRIPTS / "validate_test_coverage.py",
)


class TestSkillValidationCommon:
    def test_discovers_skills_and_entrypoints(self):
        skills = COMMON.discover_skill_contracts()
        assert len(skills) >= 32
        names = {skill.name for skill in skills}
        assert "source-s3-select" in names
        assert "source-databricks-query" in names
        assert "source-snowflake-query" in names
        assert "sink-s3-jsonl" in names
        assert "sink-snowflake-jsonl" in names
        assert "sink-clickhouse-jsonl" in names
        assert "detect-lateral-movement" in names
        assert "detect-okta-mfa-fatigue" in names
        assert "detect-entra-credential-addition" in names
        assert "detect-entra-role-grant-escalation" in names
        assert "detect-google-workspace-suspicious-login" in names
        assert "ingest-entra-directory-audit-ocsf" in names
        assert "ingest-google-workspace-login-ocsf" in names
        assert "ingest-gcp-scc-ocsf" in names
        assert "ingest-azure-defender-for-cloud-ocsf" in names
        assert "ingest-okta-system-log-ocsf" in names
        assert "discover-ai-bom" in names
        assert "discover-control-evidence" in names
        assert "discover-cloud-control-evidence" in names

        ingest = next(skill for skill in skills if skill.name == "ingest-cloudtrail-ocsf")
        assert ingest.entrypoint is not None
        assert ingest.entrypoint.name == "ingest.py"
        assert ingest.approval_model == "none"
        assert ingest.execution_modes == ("jit", "ci", "mcp", "persistent")
        assert ingest.side_effects == ("none",)
        assert ingest.concurrency_safety == "stateless"
        assert ingest.caller_roles == ()
        assert ingest.approver_roles == ()
        assert ingest.min_approvers is None

    def test_reference_policy_accepts_known_official_hosts(self):
        assert COMMON.reference_url_allowed("https://docs.aws.amazon.com/IAM/latest/APIReference/")
        assert COMMON.reference_url_allowed("https://attack.mitre.org/techniques/T1021/")
        assert COMMON.reference_url_allowed("https://github.com/opencontainers/image-spec")
        assert not COMMON.reference_url_allowed("http://example.com/not-https")
        assert not COMMON.reference_url_allowed("https://example.com/not-approved")


class TestValidationScripts:
    def test_contract_validator_passes(self):
        assert CONTRACT.main() == 0

    def test_safe_skill_validator_passes(self):
        assert SAFE.main() == 0


class TestAssumeRoleBoundaryGuardrail:
    """Unit tests for the sts:AssumeRole boundary-condition check.

    Every Allow of sts:AssumeRole in a skill's IaC must carry a boundary
    condition (PrincipalOrgID, SourceAccount, PrincipalTag, SourceOrgID) or
    an explicit ASSUME_ROLE_CONDITION_OK justification. Trust-policy
    statements (Service/Federated principals) are exempt — they are bounded
    by the principal itself, not by the condition.
    """

    def _write_policy(self, tmp_path: Path, filename: str, body: str) -> None:
        # Put the file inside a skill-shaped tree so the recursive scan finds it.
        (tmp_path / "skills" / "remediation" / "fake" / "infra").mkdir(parents=True, exist_ok=True)
        (tmp_path / "skills" / "remediation" / "fake" / "infra" / filename).write_text(body)

    def _run_against(self, tmp_path: Path) -> list[str]:
        # Point both SKILLS_ROOT (scan target) and ROOT (relative-path anchor
        # for error messages) at the temp tree, then restore.
        original_root = SAFE.ROOT
        original_skills_root = SAFE.SKILLS_ROOT
        SAFE.ROOT = tmp_path
        SAFE.SKILLS_ROOT = tmp_path / "skills"
        try:
            return SAFE.validate_assume_role_boundaries()
        finally:
            SAFE.ROOT = original_root
            SAFE.SKILLS_ROOT = original_skills_root

    def test_passes_when_org_condition_present_json(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "role.json",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Sid": "AssumeTarget",
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::*:role/target",
                            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
                        }
                    ]
                },
                indent=2,
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_fails_when_no_condition_json(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "role.json",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Sid": "AssumeTarget",
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::*:role/target",
                        }
                    ]
                },
                indent=2,
            ),
        )
        errors = self._run_against(tmp_path)
        assert len(errors) == 1
        assert "sts:AssumeRole Allow must carry" in errors[0]

    def test_trust_policy_service_principal_is_exempt(self, tmp_path: Path):
        """Lambda/EC2 service-role trust policies never need PrincipalOrgID."""
        self._write_policy(
            tmp_path,
            "lambda-trust.json",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                indent=2,
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_source_account_condition_accepted(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "role.json",
            json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::123456789012:role/target",
                            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
                        }
                    ]
                },
                indent=2,
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_explicit_opt_out_marker_accepted(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "role.json",
            "\n".join(
                [
                    "{",
                    "  // ASSUME_ROLE_CONDITION_OK: justified because ...",
                    "  \"Statement\": [",
                    "    {",
                    "      \"Effect\": \"Allow\",",
                    "      \"Action\": \"sts:AssumeRole\",",
                    "      \"Resource\": \"arn:aws:iam::*:role/target\"",
                    "    }",
                    "  ]",
                    "}",
                ]
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_terraform_hcl_flavor_detected(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "main.tf",
            "\n".join(
                [
                    "resource \"aws_iam_role_policy\" \"worker\" {",
                    "  policy = jsonencode({",
                    "    Statement = [",
                    "      {",
                    "        Effect   = \"Allow\"",
                    "        Action   = \"sts:AssumeRole\"",
                    "        Resource = \"arn:aws:iam::*:role/target\"",
                    "      }",
                    "    ]",
                    "  })",
                    "}",
                ]
            ),
        )
        errors = self._run_against(tmp_path)
        assert len(errors) == 1

    def test_terraform_hcl_with_condition_passes(self, tmp_path: Path):
        self._write_policy(
            tmp_path,
            "main.tf",
            "\n".join(
                [
                    "resource \"aws_iam_role_policy\" \"worker\" {",
                    "  policy = jsonencode({",
                    "    Statement = [",
                    "      {",
                    "        Effect   = \"Allow\"",
                    "        Action   = \"sts:AssumeRole\"",
                    "        Resource = \"arn:aws:iam::*:role/target\"",
                    "        Condition = {",
                    "          StringEquals = { \"aws:PrincipalOrgID\" = \"o-abc\" }",
                    "        }",
                    "      }",
                    "    ]",
                    "  })",
                    "}",
                ]
            ),
        )
        assert self._run_against(tmp_path) == []

    def test_integrity_validator_passes(self):
        assert INTEGRITY.main() == 0

    def test_dependency_consistency_validator_passes(self):
        assert DEPENDENCIES.main() == 0

    def test_framework_coverage_validator_passes(self):
        assert COVERAGE.main() == 0

    def test_ocsf_metadata_validator_passes(self):
        assert OCSF_METADATA.main() == 0

    def test_test_coverage_validator_passes(self, tmp_path: Path):
        report = tmp_path / "coverage.xml"
        report.write_text(
            """<?xml version="1.0" ?>
<coverage line-rate="0.82">
  <packages>
    <package name="skills">
      <classes>
        <class filename="skills/detection/example/src/detect.py">
          <lines>
            <line number="1" hits="1" />
            <line number="2" hits="1" />
            <line number="3" hits="1" />
            <line number="4" hits="1" />
            <line number="5" hits="0" />
          </lines>
        </class>
        <class filename="skills/evaluation/example/src/checks.py">
          <lines>
            <line number="1" hits="1" />
            <line number="2" hits="1" />
            <line number="3" hits="1" />
            <line number="4" hits="0" />
            <line number="5" hits="0" />
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
""",
            encoding="utf-8",
        )
        assert TEST_COVERAGE.main([str(report)]) == 0

    def test_test_coverage_validator_fails_low_detection_floor(self, tmp_path: Path):
        report = tmp_path / "coverage-low.xml"
        report.write_text(
            """<?xml version="1.0" ?>
<coverage line-rate="0.82">
  <packages>
    <package name="skills">
      <classes>
        <class filename="skills/detection/example/src/detect.py">
          <lines>
            <line number="1" hits="1" />
            <line number="2" hits="1" />
            <line number="3" hits="1" />
            <line number="4" hits="0" />
            <line number="5" hits="0" />
          </lines>
        </class>
        <class filename="skills/evaluation/example/src/checks.py">
          <lines>
            <line number="1" hits="1" />
            <line number="2" hits="1" />
            <line number="3" hits="1" />
            <line number="4" hits="0" />
            <line number="5" hits="0" />
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
""",
            encoding="utf-8",
        )
        assert TEST_COVERAGE.main([str(report)]) == 1

    def test_gpu_skill_ai_framework_depth_is_registered(self):
        registry = json.loads((ROOT / "docs" / "framework-coverage.json").read_text())
        gpu = next(item for item in registry["skills"] if item["path"] == "skills/evaluation/gpu-cluster-security")
        assert "mitre-atlas" in gpu["frameworks"]
        assert "nist-ai-rmf" in gpu["frameworks"]

    def test_model_serving_ai_framework_depth_is_registered(self):
        registry = json.loads((ROOT / "docs" / "framework-coverage.json").read_text())
        model_serving = next(item for item in registry["skills"] if item["path"] == "skills/evaluation/model-serving-security")
        assert "mitre-atlas" in model_serving["frameworks"]
        assert "nist-ai-rmf" in model_serving["frameworks"]

    def test_lateral_movement_identity_assets_are_registered(self):
        registry = json.loads((ROOT / "docs" / "framework-coverage.json").read_text())
        skill = next(item for item in registry["skills"] if item["path"] == "skills/detection/detect-lateral-movement")
        assert "service-accounts" in skill["asset_classes"]
        assert "service-principals" in skill["asset_classes"]
        assert "managed-identities" in skill["asset_classes"]

    def test_remediation_skill_declares_human_approval(self):
        skills = {skill.name: skill for skill in COMMON.discover_skill_contracts()}
        remediation = skills["iam-departures-aws"]
        assert remediation.approval_model == "human_required"
        assert remediation.execution_modes == ("jit", "persistent")
        assert "writes-identity" in remediation.side_effects
        assert remediation.concurrency_safety == "operator_coordinated"
        assert remediation.caller_roles == ("security_engineer", "incident_responder")
        assert remediation.approver_roles == ("security_lead", "cis_officer")
        assert remediation.min_approvers == 1

    def test_sink_skill_declares_human_approval(self):
        skills = {skill.name: skill for skill in COMMON.discover_skill_contracts()}
        sink = skills["sink-snowflake-jsonl"]
        assert sink.approval_model == "human_required"
        assert sink.execution_modes == ("jit", "mcp", "persistent")
        assert sink.side_effects == ("writes-database",)
        assert sink.concurrency_safety == "operator_coordinated"
        assert sink.caller_roles == ("security_engineer", "platform_engineer")
        assert sink.approver_roles == ("security_lead", "data_platform_owner")
        assert sink.min_approvers == 1

    def test_clickhouse_sink_declares_human_approval(self):
        skills = {skill.name: skill for skill in COMMON.discover_skill_contracts()}
        sink = skills["sink-clickhouse-jsonl"]
        assert sink.approval_model == "human_required"
        assert sink.execution_modes == ("jit", "mcp", "persistent")
        assert sink.side_effects == ("writes-database",)
        assert sink.concurrency_safety == "operator_coordinated"
        assert sink.caller_roles == ("security_engineer", "platform_engineer")
        assert sink.approver_roles == ("security_lead", "data_platform_owner")
        assert sink.min_approvers == 1

    def test_s3_sink_declares_human_approval(self):
        skills = {skill.name: skill for skill in COMMON.discover_skill_contracts()}
        sink = skills["sink-s3-jsonl"]
        assert sink.approval_model == "human_required"
        assert sink.execution_modes == ("jit", "mcp", "persistent")
        assert sink.side_effects == ("writes-storage",)
        assert sink.concurrency_safety == "operator_coordinated"
        assert sink.caller_roles == ("security_engineer", "platform_engineer")
        assert sink.approver_roles == ("security_lead", "data_platform_owner")
        assert sink.min_approvers == 1

    def test_skill_like_dirs_are_canonical_categories_only(self):
        skill_like_dirs = COMMON.iter_skill_like_dirs()
        assert skill_like_dirs
        for path in skill_like_dirs:
            assert path.parent.name in COMMON.CANONICAL_SKILL_CATEGORIES
            assert path.name != "__pycache__"

    def test_every_skill_like_dir_has_a_contract(self):
        skill_like_dirs = COMMON.iter_skill_like_dirs()
        missing = [path for path in skill_like_dirs if not (path / "SKILL.md").exists()]
        assert missing == []
