from __future__ import annotations

import re
import sys

from skill_validation_common import ROOT, SKILLS_ROOT, discover_skill_contracts

SUBPROCESS_PATTERNS = (
    "import subprocess",
    "from subprocess import",
    "os.system(",
    "Popen(",
    "check_output(",
)

WILDCARD_PATTERNS = (
    re.compile(r'"Action"\s*:\s*"\*"'),
    re.compile(r'"Resource"\s*:\s*"\*"'),
    re.compile(r"\bAction\s*=\s*\"\*\""),
    re.compile(r"\bResource\s*=\s*\"\*\""),
)

POLICY_SUFFIXES = (".json", ".tf", ".yaml", ".yml")


def validate_read_only_no_subprocess(skill: object) -> list[str]:
    errors: list[str] = []
    skill_dir = getattr(skill, "skill_dir")
    is_write_capable = bool(getattr(skill, "is_write_capable"))
    approval_model = getattr(skill, "approval_model")
    side_effects = getattr(skill, "side_effects")
    if is_write_capable:
        return errors

    for path in sorted((skill_dir / "src").rglob("*.py")):
        text = path.read_text()
        for pattern in SUBPROCESS_PATTERNS:
            if pattern in text:
                rel = path.relative_to(ROOT)
                errors.append(
                    f"{rel}: read-only skill must not use subprocess/shell pattern `{pattern}`"
                )
    if approval_model != "none":
        errors.append(f"{skill_dir.relative_to(ROOT)}: read-only skill must keep approval_model `none`")
    if side_effects != ("none",):
        errors.append(f"{skill_dir.relative_to(ROOT)}: read-only skill must keep side_effects `none`")
    return errors


def validate_write_skill_dry_run(skill: object) -> list[str]:
    errors: list[str] = []
    skill_dir = getattr(skill, "skill_dir")
    is_write_capable = bool(getattr(skill, "is_write_capable"))
    approval_model = getattr(skill, "approval_model")
    if not is_write_capable:
        return errors

    skill_md = (skill_dir / "SKILL.md").read_text().lower()
    if "dry-run" not in skill_md and "dry_run" not in skill_md:
        errors.append(f"{skill_dir.relative_to(ROOT)}: write-capable skill must document dry-run in SKILL.md")

    tests_dir = skill_dir / "tests"
    test_text = "\n".join(path.read_text() for path in sorted(tests_dir.rglob("*.py")))
    if "dry_run" not in test_text and "--dry-run" not in test_text and "dry-run" not in test_text:
        errors.append(f"{skill_dir.relative_to(ROOT)}: write-capable skill must exercise dry-run in tests")
    if approval_model != "human_required":
        errors.append(f"{skill_dir.relative_to(ROOT)}: write-capable skill must require human approval")

    return errors


def _has_wildcard_marker(lines: list[str], line_index: int) -> bool:
    # JSON IAM statements and Terraform policy blocks can span many lines before
    # the wildcard resource/action appears. Keep the marker local to the block,
    # but don't make the validator brittle on line wrapping.
    start = max(0, line_index - 32)
    window = "\n".join(lines[start : line_index + 1])
    return "WILDCARD_OK" in window


def validate_wildcards() -> list[str]:
    errors: list[str] = []
    for path in sorted(SKILLS_ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in POLICY_SUFFIXES:
            continue
        text = path.read_text()
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            if any(pattern.search(line) for pattern in WILDCARD_PATTERNS):
                if not _has_wildcard_marker(lines, idx):
                    rel = path.relative_to(ROOT)
                    errors.append(
                        f"{rel}:{idx + 1}: wildcard Action/Resource requires explicit WILDCARD_OK justification"
                    )
    return errors


# -- Guardrail: every Allow of sts:AssumeRole must carry a boundary condition --
#
# Zero-trust guardrail. A remediation Lambda that can AssumeRole anywhere is an
# instant privilege-escalation surface. Any Allow of `sts:AssumeRole` MUST carry
# at least one boundary condition:
#   - aws:PrincipalOrgID (org boundary — recommended default)
#   - aws:PrincipalTag / aws:SourceAccount / aws:SourceOrgID (adjacent boundary
#     conditions that are still acceptable)
#
# The alternative — "just trust the IAM policy on the target role" — is not
# sufficient: a misconfigured target role becomes an escape hatch, and the
# target role is often in a separate account with a different review culture.
#
# To opt out for a genuinely unusual case, add ASSUME_ROLE_CONDITION_OK near
# the statement with a written justification. Symmetrical to WILDCARD_OK.

ASSUME_ROLE_ACTION_PATTERNS = (
    re.compile(r'"Action"\s*:\s*"sts:AssumeRole"', re.IGNORECASE),
    re.compile(r'\bAction\s*=\s*"sts:AssumeRole"', re.IGNORECASE),
    re.compile(r'^\s*Action\s*:\s*sts:AssumeRole\s*$', re.IGNORECASE | re.MULTILINE),
)

_BOUNDARY_CONDITION_MARKERS = (
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    "aws:PrincipalTag",
    "aws:SourceAccount",
    "aws:SourceOrgID",
    "aws:SourceOrgPaths",
    "aws:ResourceOrgID",
    "ASSUME_ROLE_CONDITION_OK",
)

# Trust-policy statements (the AssumeRolePolicyDocument that lets a service
# principal assume this role) are NOT the concern here. Those are bounded by
# `Principal: { Service: "lambda.amazonaws.com" }` or similar, not by a
# PrincipalOrgID condition. Skip any AssumeRole line whose 32-line window
# contains a Service or Federated principal marker.
_TRUST_POLICY_MARKERS = (
    '"Service"',
    "Service =",
    "Service:",
    '"Federated"',
    "Federated =",
    "Federated:",
)


def _is_trust_policy_statement(lines: list[str], line_index: int) -> bool:
    start = max(0, line_index - 32)
    end = min(len(lines), line_index + 32)
    window = "\n".join(lines[start:end])
    return any(marker in window for marker in _TRUST_POLICY_MARKERS)


def _has_boundary_condition(lines: list[str], line_index: int) -> bool:
    # Look ~32 lines in either direction for a boundary condition on the same
    # statement. Policy statements in CFN/TF/JSON commonly put the Condition
    # block after the Action line, so forward-scan generously.
    start = max(0, line_index - 8)
    end = min(len(lines), line_index + 32)
    window = "\n".join(lines[start:end])
    return any(marker in window for marker in _BOUNDARY_CONDITION_MARKERS)


def validate_assume_role_boundaries() -> list[str]:
    errors: list[str] = []
    for path in sorted(SKILLS_ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in POLICY_SUFFIXES:
            continue
        text = path.read_text()
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            if not any(pattern.search(line) for pattern in ASSUME_ROLE_ACTION_PATTERNS):
                continue
            if _is_trust_policy_statement(lines, idx):
                continue
            if not _has_boundary_condition(lines, idx):
                rel = path.relative_to(ROOT)
                errors.append(
                    f"{rel}:{idx + 1}: sts:AssumeRole Allow must carry an org/account/tag "
                    "boundary condition (aws:PrincipalOrgID, aws:SourceAccount, "
                    "aws:PrincipalTag, aws:SourceOrgID) or an explicit "
                    "ASSUME_ROLE_CONDITION_OK justification"
                )
    return errors


def main() -> int:
    errors: list[str] = []
    for skill in discover_skill_contracts():
        errors.extend(validate_read_only_no_subprocess(skill))
        errors.extend(validate_write_skill_dry_run(skill))
    errors.extend(validate_wildcards())
    errors.extend(validate_assume_role_boundaries())

    if errors:
        print("Safe-skill validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("Safe-skill validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
