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


def main() -> int:
    errors: list[str] = []
    for skill in discover_skill_contracts():
        errors.extend(validate_read_only_no_subprocess(skill))
        errors.extend(validate_write_skill_dry_run(skill))
    errors.extend(validate_wildcards())

    if errors:
        print("Safe-skill validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("Safe-skill validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
