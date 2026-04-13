from __future__ import annotations

import sys

from skill_validation_common import NAME_RE, ROOT, discover_skill_contracts


def main() -> int:
    errors: list[str] = []
    checked = 0

    for skill in discover_skill_contracts():
        checked += 1
        rel = skill.skill_dir.relative_to(ROOT)

        for required in ("src", "tests", "REFERENCES.md"):
            if not (skill.skill_dir / required).exists():
                errors.append(f"{rel}: missing required path `{required}`")

        if not skill.name:
            errors.append(f"{rel}: frontmatter missing `name`")
        else:
            if not NAME_RE.fullmatch(skill.name):
                errors.append(f"{rel}: invalid skill name `{skill.name}`")

        if "Use when" not in skill.skill_text:
            errors.append(f"{rel}: SKILL.md must include `Use when`")
        if "Do NOT use" not in skill.skill_text:
            errors.append(f"{rel}: SKILL.md must include `Do NOT use`")

    if errors:
        print("Skill contract validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print(f"Skill contract validation passed for {checked} skills.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
