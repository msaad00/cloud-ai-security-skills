"""Skill metadata shared by CI validation and runtime discovery.

Keep parsing and entrypoint precedence identical across consumers. Validation
policy and MCP execution policy remain with their respective callers.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)

ENTRYPOINT_CANDIDATES = (
    "src/ingest.py",
    "src/detect.py",
    "src/convert.py",
    "src/checks.py",
    "src/discover.py",
    "src/handler.py",
    "src/sink.py",
)


def extract_frontmatter(skill_md: Path) -> str:
    text = skill_md.read_text()
    match = _FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError(f"{skill_md} missing YAML frontmatter")
    return match.group(1)


def _flatten_value(value: Any) -> str:
    """Render a YAML scalar/list/dict back into the string shape the rest of the
    registry consumes. Lists are joined with commas (matches `parse_modes`),
    folded multi-line scalars collapse into a single space-separated string.
    """
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(_flatten_value(item) for item in value if item not in (None, ""))
    if isinstance(value, dict):
        return ", ".join(f"{k}={_flatten_value(v)}" for k, v in value.items())
    if isinstance(value, bool):
        return "true" if value else "false"
    return " ".join(str(value).split())


def parse_frontmatter(frontmatter: str) -> dict[str, str]:
    """Parse a YAML mapping into the string values consumed by both callers.

    Scalars, lists, and nested metadata use the runtime registry's normalization.
    Non-mapping documents fail before either consumer applies its own policy.
    """
    raw = yaml.safe_load(frontmatter)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"SKILL.md frontmatter must parse to a mapping, got {type(raw).__name__}")
    return {str(key): _flatten_value(value) for key, value in raw.items()}


def parse_modes(raw_value: str | None) -> tuple[str, ...]:
    if not raw_value:
        return ()
    return tuple(part.strip() for part in raw_value.split(",") if part.strip())


def resolve_entrypoint(skill_dir: Path) -> Path | None:
    for candidate in ENTRYPOINT_CANDIDATES:
        path = skill_dir / candidate
        if path.exists():
            return path
    return None
