"""End-to-end integration test for the K8s detection-engineering pipeline.

This is the canonical proof that the OCSF wire contract holds across skill
boundaries: raw kube-apiserver audit logs go in one end, OCSF Detection
Findings come out the other, and the deep-equality assertion against the
frozen golden output catches any drift in either skill.

Layout:
    1. Read the raw K8s audit fixture from skills/detection-engineering/golden/
    2. Pipe it through ingest-k8s-audit-ocsf  → OCSF API Activity events
    3. Pipe those through detect-privilege-escalation-k8s → Detection Findings
    4. Assert deep-eq against the frozen Detection Finding golden

The test does NOT shell out — it imports both skills' modules directly so
the integration runs in-process and any traceback points at the actual
skill code, not a subprocess wrapper.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = REPO_ROOT / "skills" / "detection-engineering"
GOLDEN_DIR = SKILLS_DIR / "golden"


def _load_module(name: str, path: Path):
    """Load a Python module from a file path without polluting sys.path globally.

    Each skill keeps its own src/ directory and we cannot import them by
    package name (no __init__.py, deliberate per Anthropic skill spec). So
    we load them as anonymous modules with unique names per call to avoid
    sys.modules cache collisions across the test run.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"could not spec {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ── Integration test ──────────────────────────────────────────────────


class TestK8sPipelineEndToEnd:
    """The full pipe: raw → ingest → detect → finding."""

    def setup_method(self):
        self.ingest = _load_module(
            "_int_ingest_k8s_audit_ocsf",
            SKILLS_DIR / "ingest-k8s-audit-ocsf" / "src" / "ingest.py",
        )
        self.detect = _load_module(
            "_int_detect_priv_esc_k8s",
            SKILLS_DIR / "detect-privilege-escalation-k8s" / "src" / "detect.py",
        )

    def test_raw_to_ocsf_to_findings_matches_frozen_golden(self):
        raw_lines = (GOLDEN_DIR / "k8s_audit_raw_sample.jsonl").read_text().splitlines()
        ocsf_events = list(self.ingest.ingest(raw_lines))

        # Sanity: ingest filters RequestReceived stage, so 6 raw → 5 OCSF
        assert len(ocsf_events) == 5

        findings = list(self.detect.detect(ocsf_events))

        expected = _load_jsonl(GOLDEN_DIR / "k8s_priv_esc_findings.ocsf.jsonl")
        assert len(findings) == len(expected) == 3, (
            f"finding count drift: produced {len(findings)}, expected {len(expected)}. "
            f"This means either the ingest skill changed its OCSF output OR the detector "
            f"logic moved. Re-generate the golden by running:\n"
            f"  python skills/detection-engineering/ingest-k8s-audit-ocsf/src/ingest.py "
            f"skills/detection-engineering/golden/k8s_audit_raw_sample.jsonl "
            f"| python skills/detection-engineering/detect-privilege-escalation-k8s/src/detect.py "
            f"> skills/detection-engineering/golden/k8s_priv_esc_findings.ocsf.jsonl"
        )

        for produced, expected_f in zip(findings, expected):
            assert produced == expected_f, (
                f"OCSF wire-contract drift between ingest-k8s-audit-ocsf and "
                f"detect-privilege-escalation-k8s.\n"
                f"  produced:  {json.dumps(produced, sort_keys=True)}\n"
                f"  expected:  {json.dumps(expected_f, sort_keys=True)}"
            )

    def test_ocsf_findings_carry_mitre_inside_finding_info(self):
        """OCSF 1.8 contract: attacks[] lives in finding_info, NOT at event root."""
        raw_lines = (GOLDEN_DIR / "k8s_audit_raw_sample.jsonl").read_text().splitlines()
        ocsf_events = list(self.ingest.ingest(raw_lines))
        findings = list(self.detect.detect(ocsf_events))

        for f in findings:
            assert "attacks" not in f, (
                f"OCSF 1.8 violation: attacks[] must NOT be at the event root. "
                f"That was the deprecated Security Finding (2001) layout. "
                f"Detection Finding (2004) puts attacks[] inside finding_info. "
                f"Offending uid: {f.get('finding_info', {}).get('uid', '?')}"
            )
            assert "attacks" in f["finding_info"]
            assert len(f["finding_info"]["attacks"]) >= 1
            for attack in f["finding_info"]["attacks"]:
                assert attack["version"] == "v14"
                assert "tactic" in attack
                assert "technique" in attack
                assert attack["technique"]["uid"].startswith("T")

    def test_findings_class_uid_is_2004(self):
        """OCSF 1.8 contract: detections emit Detection Finding 2004, not deprecated 2001."""
        raw_lines = (GOLDEN_DIR / "k8s_audit_raw_sample.jsonl").read_text().splitlines()
        findings = list(self.detect.detect(self.ingest.ingest(raw_lines)))
        for f in findings:
            assert f["class_uid"] == 2004
            assert f["category_uid"] == 2
            assert f["type_uid"] == 200401  # 2004 * 100 + 1
            assert f["metadata"]["version"] == "1.8.0"

    def test_pipeline_is_idempotent(self):
        """Re-running on the same input produces byte-identical findings."""
        raw_lines = (GOLDEN_DIR / "k8s_audit_raw_sample.jsonl").read_text().splitlines()

        first = list(self.detect.detect(self.ingest.ingest(raw_lines)))
        second = list(self.detect.detect(self.ingest.ingest(raw_lines)))

        assert first == second, "Pipeline is not idempotent — re-running produced different findings"

        # Stronger assertion: serialized form is byte-identical
        first_bytes = "\n".join(json.dumps(f, sort_keys=True) for f in first)
        second_bytes = "\n".join(json.dumps(f, sort_keys=True) for f in second)
        assert first_bytes == second_bytes


class TestMcpPipelineEndToEnd:
    """Same end-to-end shape but for the MCP stack."""

    def setup_method(self):
        self.ingest = _load_module(
            "_int_ingest_mcp_proxy_ocsf",
            SKILLS_DIR / "ingest-mcp-proxy-ocsf" / "src" / "ingest.py",
        )
        self.detect = _load_module(
            "_int_detect_mcp_tool_drift",
            SKILLS_DIR / "detect-mcp-tool-drift" / "src" / "detect.py",
        )

    def test_raw_to_ocsf_to_findings_matches_frozen_golden(self):
        raw_lines = (GOLDEN_DIR / "mcp_proxy_raw_sample.jsonl").read_text().splitlines()
        ocsf_events = list(self.ingest.ingest(raw_lines))

        # Fixture has 5 raw lines, ingest emits one OCSF event per tool in
        # tools/list responses + one per tools/call → 7 OCSF events
        assert len(ocsf_events) == 7

        findings = list(self.detect.detect(ocsf_events))

        expected = _load_jsonl(GOLDEN_DIR / "tool_drift_finding.ocsf.jsonl")
        assert len(findings) == len(expected) == 1, f"finding count drift: produced {len(findings)}, expected {len(expected)}"

        for produced, expected_f in zip(findings, expected):
            assert produced == expected_f, (
                f"MCP wire-contract drift.\n"
                f"  produced: {json.dumps(produced, sort_keys=True)}\n"
                f"  expected: {json.dumps(expected_f, sort_keys=True)}"
            )

    def test_finding_uses_t1195_001(self):
        raw_lines = (GOLDEN_DIR / "mcp_proxy_raw_sample.jsonl").read_text().splitlines()
        findings = list(self.detect.detect(self.ingest.ingest(raw_lines)))
        assert len(findings) == 1
        attack = findings[0]["finding_info"]["attacks"][0]
        assert attack["technique"]["uid"] == "T1195.001"

    def test_finding_class_uid_is_2004(self):
        raw_lines = (GOLDEN_DIR / "mcp_proxy_raw_sample.jsonl").read_text().splitlines()
        findings = list(self.detect.detect(self.ingest.ingest(raw_lines)))
        assert findings[0]["class_uid"] == 2004
        assert findings[0]["metadata"]["version"] == "1.8.0"


class TestCrossSkillOcsfWireContract:
    """OCSF wire-contract assertions that must hold for any ingest+detect pair.

    These are not specific to K8s or MCP — they encode the rules pinned in
    skills/detection-engineering/OCSF_CONTRACT.md. If you ship a new ingest
    or detect skill, add it to the parametrised list below.
    """

    INGEST_SKILLS = [
        ("ingest-cloudtrail-ocsf", "ingest.py", 6003),
        ("ingest-gcp-audit-ocsf", "ingest.py", 6003),
        ("ingest-azure-activity-ocsf", "ingest.py", 6003),
        ("ingest-k8s-audit-ocsf", "ingest.py", 6003),
        ("ingest-mcp-proxy-ocsf", "ingest.py", 6002),
    ]

    DETECT_SKILLS = [
        ("detect-mcp-tool-drift", "detect.py"),
        ("detect-privilege-escalation-k8s", "detect.py"),
    ]

    def test_every_ingest_skill_pins_ocsf_1_8(self):
        for name, entry, _ in self.INGEST_SKILLS:
            module = _load_module(f"_contract_{name}", SKILLS_DIR / name / "src" / entry)
            assert module.OCSF_VERSION == "1.8.0", f"{name}: expected OCSF 1.8.0, got {module.OCSF_VERSION}"

    def test_every_ingest_skill_uses_expected_class_uid(self):
        for name, entry, expected_class in self.INGEST_SKILLS:
            module = _load_module(f"_contract_class_{name}", SKILLS_DIR / name / "src" / entry)
            assert module.CLASS_UID == expected_class, f"{name}: expected CLASS_UID={expected_class}, got {module.CLASS_UID}"

    def test_every_detect_skill_emits_2004(self):
        for name, entry in self.DETECT_SKILLS:
            module = _load_module(f"_contract_det_{name}", SKILLS_DIR / name / "src" / entry)
            assert module.FINDING_CLASS_UID == 2004, (
                f"{name}: must emit OCSF 1.8 Detection Finding (2004), not deprecated Security Finding (2001)"
            )
            assert module.FINDING_TYPE_UID == 200401

    def test_every_detect_skill_pins_mitre_v14(self):
        for name, entry in self.DETECT_SKILLS:
            module = _load_module(f"_contract_mitre_{name}", SKILLS_DIR / name / "src" / entry)
            assert module.MITRE_VERSION == "v14", f"{name}: must pin MITRE ATT&CK v14 to match the OCSF_CONTRACT version"
