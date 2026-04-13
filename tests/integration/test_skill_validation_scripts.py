from __future__ import annotations

import importlib.util
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


class TestSkillValidationCommon:
    def test_discovers_skills_and_entrypoints(self):
        skills = COMMON.discover_skill_contracts()
        assert len(skills) >= 27
        names = {skill.name for skill in skills}
        assert "detect-lateral-movement" in names
        assert "ingest-gcp-scc-ocsf" in names
        assert "ingest-azure-defender-for-cloud-ocsf" in names

        ingest = next(skill for skill in skills if skill.name == "ingest-cloudtrail-ocsf")
        assert ingest.entrypoint is not None
        assert ingest.entrypoint.name == "ingest.py"

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

    def test_integrity_validator_passes(self):
        assert INTEGRITY.main() == 0
