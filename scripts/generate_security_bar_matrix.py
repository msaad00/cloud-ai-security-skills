#!/usr/bin/env python3
"""Regenerate the per-skill matrix block in docs/SECURITY_BAR.md.

The matrix sits between two HTML comment markers:

    <!-- AUTO-GENERATED MATRIX START -->
    ...table content...
    <!-- AUTO-GENERATED MATRIX END -->

Everything outside the markers is preserved verbatim (the 11-principle
preamble at the top and the "How to add a skill" section at the bottom
are both hand-edited prose).

Run in CI with `--check` to fail the build if the committed matrix has
drifted from the current skill set.

Closes #246.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

from skill_validation_common import SkillContract, discover_skill_contracts  # noqa: E402

OUTPUT = REPO_ROOT / "SECURITY_BAR.md"
MARKER_START = "<!-- AUTO-GENERATED MATRIX START — do not edit by hand; run scripts/generate_security_bar_matrix.py -->"
MARKER_END = "<!-- AUTO-GENERATED MATRIX END -->"

# Categories where OCSF is the wire contract today (ingest + detect).
# Everything else emits native / bridge / pass-through — `n/a` in the matrix.
_OCSF_CATEGORIES = frozenset({"ingestion", "detection"})


def _read_only_cell(skill: SkillContract) -> str:
    if not skill.is_write_capable:
        return "✅"
    if skill.category == "remediation":
        return "⚠️ write via HITL"
    if skill.category == "output":
        return "⚠️ append-only sink"
    return "⚠️ write-capable"


def _least_privilege_cell(skill: SkillContract) -> str:
    # Proxy: a skill's REFERENCES.md is where the minimum IAM/RBAC is pinned.
    # validate_safe_skill_bar.py already fails CI on wildcards without
    # WILDCARD_OK justification, so presence of REFERENCES.md + passing
    # the safe-skill-bar gate is a reliable "least privilege documented" signal.
    return "✅" if skill.references_path.exists() else "⚠️ REFERENCES.md missing"


def _closed_loop_cell(skill: SkillContract) -> str:
    # Closed-loop evidence per layer:
    #   - ingestion / detection: frozen golden fixture under detection-engineering/golden/
    #   - remediation: dual-audit + re-verify enforced by the safe-skill-bar gate
    #   - evaluation: deterministic checks re-runnable against same input
    #   - discovery / view / output: deterministic transforms or append-only
    if skill.category in {"remediation", "output"}:
        return "✅ audit + re-verify"
    if skill.category in {"ingestion", "detection"}:
        return "✅ golden fixture"
    return "✅ deterministic"


def _ocsf_cell(skill: SkillContract) -> str:
    if skill.category in _OCSF_CATEGORIES:
        return "✅ 1.8"
    # Evaluation opt-in (2003); Discovery/View/Remediation/Output are native.
    if skill.category == "evaluation":
        return "✅ 1.8 opt-in"
    return "n/a"


def _telemetry_cell(skill: SkillContract) -> str:
    # Repo invariant: no skill phones home. `validate_safe_skill_bar.py`
    # greps for undeclared HTTP libs; `bandit` + hardcoded-secret grep run
    # in CI. If a future skill declares `network_egress: telemetry`, that
    # becomes visible here automatically.
    egress = skill.network_egress
    if any("telemetry" in mode.lower() for mode in egress):
        return "⚠️ declared"
    return "✅"


def _agentless_cell(_: SkillContract) -> str:
    # Repo-wide invariant enforced by scripts/validate_skill_integrity.py:
    # every skill is a short-lived subprocess; no daemons/sidecars/DaemonSets.
    return "✅"


def _render_matrix(skills: list[SkillContract]) -> str:
    """Return the markdown table body, excluding the MARKER lines themselves."""
    lines: list[str] = []
    lines.append(
        "| Skill | Layer | Read-only | Agentless | Least privilege | Closed loop | OCSF wire | No telemetry |"
    )
    lines.append("|---|---|:-:|:-:|---|---|---|:-:|")

    def _sort_key(skill: SkillContract) -> tuple[str, str]:
        # Group by layer, then alphabetical within layer.
        layer_order = {
            "ingestion": "1",
            "discovery": "2",
            "detection": "3",
            "evaluation": "4",
            "remediation": "5",
            "view": "6",
            "output": "7",
            "detection-engineering": "9",
        }
        return (layer_order.get(skill.category, "8"), skill.name)

    for skill in sorted(skills, key=_sort_key):
        row = [
            f"`{skill.name}`",
            skill.category,
            _read_only_cell(skill),
            _agentless_cell(skill),
            _least_privilege_cell(skill),
            _closed_loop_cell(skill),
            _ocsf_cell(skill),
            _telemetry_cell(skill),
        ]
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")
    lines.append(
        f"_{len(skills)} skills · generated from SKILL.md frontmatter + layer conventions. "
        "Run `python scripts/generate_security_bar_matrix.py` to refresh after adding a skill; "
        "CI enforces parity via `--check`._"
    )
    return "\n".join(lines)


def _splice_into_doc(doc: str, matrix_body: str) -> str:
    """Replace the region between MARKER_START and MARKER_END."""
    block = f"{MARKER_START}\n{matrix_body}\n{MARKER_END}"
    if MARKER_START not in doc or MARKER_END not in doc:
        raise RuntimeError(
            f"{OUTPUT.relative_to(REPO_ROOT)} is missing the AUTO-GENERATED markers. "
            "Add them around the per-skill matrix:\n"
            f"    {MARKER_START}\n"
            "    ...\n"
            f"    {MARKER_END}"
        )
    prefix, rest = doc.split(MARKER_START, 1)
    _, suffix = rest.split(MARKER_END, 1)
    return f"{prefix}{block}{suffix}"


def main() -> int:
    skills = discover_skill_contracts()
    doc = OUTPUT.read_text(encoding="utf-8")
    matrix_body = _render_matrix(skills)
    generated = _splice_into_doc(doc, matrix_body)

    if len(sys.argv) >= 2 and sys.argv[1] == "--check":
        if doc != generated:
            print(
                f"ERROR: {OUTPUT.relative_to(REPO_ROOT)} per-skill matrix is out of "
                "sync with the current skill frontmatter. Run:\n"
                "  python scripts/generate_security_bar_matrix.py",
                file=sys.stderr,
            )
            return 1
        print(f"SECURITY_BAR.md matrix in sync ({len(skills)} skills).")
        return 0

    OUTPUT.write_text(generated, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} matrix ({len(skills)} skills).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
