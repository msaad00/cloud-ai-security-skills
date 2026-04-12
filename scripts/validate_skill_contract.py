from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_ROOT = ROOT / "skills"
NAME_RE = re.compile(r"^[a-z0-9-]{1,64}$")
FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
NAME_FIELD_RE = re.compile(r"^name:\s*([^\n]+)$", re.MULTILINE)


def iter_skill_dirs() -> list[Path]:
    return sorted(path.parent for path in SKILLS_ROOT.glob("*/*/SKILL.md"))


def main() -> int:
    errors: list[str] = []
    checked = 0

    for skill_dir in iter_skill_dirs():
        checked += 1
        skill_md = skill_dir / "SKILL.md"
        text = skill_md.read_text()
        rel = skill_dir.relative_to(ROOT)

        for required in ("src", "tests", "REFERENCES.md"):
            if not (skill_dir / required).exists():
                errors.append(f"{rel}: missing required path `{required}`")

        match = FRONTMATTER_RE.match(text)
        if not match:
            errors.append(f"{rel}: SKILL.md missing YAML frontmatter")
            continue

        frontmatter = match.group(1)
        name_match = NAME_FIELD_RE.search(frontmatter)
        if not name_match:
            errors.append(f"{rel}: frontmatter missing `name`")
        else:
            name = name_match.group(1).strip().strip("\"'")
            if not NAME_RE.fullmatch(name):
                errors.append(f"{rel}: invalid skill name `{name}`")

        if "Use when" not in text:
            errors.append(f"{rel}: SKILL.md must include `Use when`")
        if "Do NOT use" not in text:
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
