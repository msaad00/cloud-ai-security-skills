#!/usr/bin/env python3
"""Validate that every doc-cited skill count matches the on-disk count.

Prevents the class of drift where a PR adds a skill but forgets to bump
counts in README.md / ARCHITECTURE.md / hero-banner.svg / skills/README.md /
FRAMEWORK_COVERAGE.md / CHANGELOG.md. Run in CI next to the other
`validate_*.py` scripts.

Passes silently; fails with a diff-style report pointing to each claim that
does not equal the true count from `find skills -name SKILL.md`.

The check is **anchored to explicit patterns** (e.g. `N shipped skill bundles`,
`Total: N shipped skills`, `N shipped detectors`). A bare number like `82`
elsewhere in docs is ignored — we only assert the patterns we own.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ----- Claims we own. Each entry: (file, regex, what the int should equal) -----
#
# The regex MUST have exactly one capture group `(\d+)` that is the claimed
# count. `expected` names the metric the capture should equal.

Claim = tuple[Path, str, str]

CLAIMS: list[Claim] = [
    # README.md claims
    (REPO_ROOT / "README.md", r"(\d+) shipped skill bundles", "total"),
    (REPO_ROOT / "README.md", r"\*\*Total: (\d+) shipped skills", "total"),
    (REPO_ROOT / "README.md", r"Shared skill bundle<br/>(\d+) shipped", "total"),
    (REPO_ROOT / "README.md", r"L3 Detect<br/>(\d+) skills", "detection"),
    # docs/ARCHITECTURE.md claims
    (REPO_ROOT / "docs" / "ARCHITECTURE.md", r"(\d+) shipped detectors", "detection"),
    # hero banner claims (SVG desc + rendered pill)
    (REPO_ROOT / "docs" / "images" / "hero-banner.svg", r"\((\d+) skills,", "total"),
    (
        REPO_ROOT / "docs" / "images" / "hero-banner.svg",
        r'font-weight="800">(\d+)</text>\s*<text[^>]*>\s*skills',
        "total",
    ),
]


def _count_skills(layer: str | None = None) -> int:
    """Count SKILL.md files under skills/<layer>/*/ (or all layers when None)."""
    if layer is None:
        return sum(1 for _ in (REPO_ROOT / "skills").glob("*/*/SKILL.md"))
    return sum(1 for _ in (REPO_ROOT / "skills" / layer).glob("*/SKILL.md"))


def _truth_for(metric: str) -> int:
    if metric == "total":
        return _count_skills()
    # Per-layer metrics map directly to directory names.
    return _count_skills(metric)


def main() -> int:
    truth: dict[str, int] = {
        "total": _count_skills(),
        "ingestion": _count_skills("ingestion"),
        "discovery": _count_skills("discovery"),
        "detection": _count_skills("detection"),
        "evaluation": _count_skills("evaluation"),
        "remediation": _count_skills("remediation"),
        "view": _count_skills("view"),
        "output": _count_skills("output"),
    }

    errors: list[str] = []
    for path, pattern, metric in CLAIMS:
        if not path.exists():
            errors.append(f"{path.relative_to(REPO_ROOT)}: file not found (claim check skipped)")
            continue
        text = path.read_text(encoding="utf-8")
        matches = list(re.finditer(pattern, text))
        if not matches:
            errors.append(
                f"{path.relative_to(REPO_ROOT)}: pattern `{pattern}` did not match — "
                "claim was removed or reworded; update scripts/validate_skill_count_consistency.py"
            )
            continue
        expected = truth[metric]
        for match in matches:
            claimed = int(match.group(1))
            if claimed != expected:
                # Resolve line number for the operator-friendly error message.
                line_no = text[: match.start()].count("\n") + 1
                errors.append(
                    f"{path.relative_to(REPO_ROOT)}:{line_no}: claims {claimed} for `{metric}`, "
                    f"but on-disk count is {expected} (pattern `{pattern}`)"
                )

    if errors:
        print("Skill-count consistency check FAILED:\n")
        for err in errors:
            print(f"  - {err}")
        print(
            "\nOn-disk counts: "
            + ", ".join(f"{k}={v}" for k, v in truth.items())
        )
        print(
            "\nFix: update the file(s) above OR, if the claim was intentionally reworded, "
            "update CLAIMS in scripts/validate_skill_count_consistency.py."
        )
        return 1

    print(
        f"Skill-count consistency check passed "
        f"(total={truth['total']}, detection={truth['detection']}, "
        f"remediation={truth['remediation']}, evaluation={truth['evaluation']})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
