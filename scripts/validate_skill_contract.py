from __future__ import annotations

import sys

from skill_validation_common import (
    APPROVAL_MODE_VALUES,
    EXECUTION_MODE_VALUES,
    NAME_RE,
    ROOT,
    SIDE_EFFECT_VALUES,
    discover_skill_contracts,
)


def main() -> int:
    errors: list[str] = []
    checked = 0

    for skill in discover_skill_contracts():
        checked += 1
        rel = skill.skill_dir.relative_to(ROOT)

        for required in ("src", "tests", "REFERENCES.md"):
            if not (skill.skill_dir / required).exists():
                errors.append(f"{rel}: missing required path `{required}`")

        for field in ("name", "description", "license", "approval_model", "execution_modes", "side_effects"):
            if not skill.frontmatter.get(field):
                errors.append(f"{rel}: frontmatter missing `{field}`")

        if not skill.name:
            errors.append(f"{rel}: frontmatter missing `name`")
        else:
            if not NAME_RE.fullmatch(skill.name):
                errors.append(f"{rel}: invalid skill name `{skill.name}`")

        if skill.approval_model and skill.approval_model not in APPROVAL_MODE_VALUES:
            errors.append(f"{rel}: invalid approval_model `{skill.approval_model}`")

        if skill.execution_modes:
            unknown_modes = [mode for mode in skill.execution_modes if mode not in EXECUTION_MODE_VALUES]
            if unknown_modes:
                errors.append(f"{rel}: invalid execution_modes {unknown_modes}")
        elif skill.frontmatter.get("execution_modes"):
            errors.append(f"{rel}: execution_modes must not be empty")

        if skill.side_effects:
            unknown_effects = [effect for effect in skill.side_effects if effect not in SIDE_EFFECT_VALUES]
            if unknown_effects:
                errors.append(f"{rel}: invalid side_effects {unknown_effects}")
            if "none" in skill.side_effects and skill.side_effects != ("none",):
                errors.append(f"{rel}: side_effects `none` must not be combined with other values")
        elif skill.frontmatter.get("side_effects"):
            errors.append(f"{rel}: side_effects must not be empty")

        if skill.is_write_capable:
            if skill.approval_model != "human_required":
                errors.append(f"{rel}: write-capable skills must set approval_model to `human_required`")
            if not skill.side_effects or skill.side_effects == ("none",):
                errors.append(f"{rel}: write-capable skills must declare concrete side_effects")
        else:
            if skill.approval_model and skill.approval_model != "none":
                errors.append(f"{rel}: read-only skills must set approval_model to `none`")
            if skill.side_effects and skill.side_effects != ("none",):
                errors.append(f"{rel}: read-only skills must set side_effects to `none`")

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
