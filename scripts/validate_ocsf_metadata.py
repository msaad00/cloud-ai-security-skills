from __future__ import annotations

import ast
import sys

from skill_validation_common import discover_skill_contracts

OCSF_LAYERS = {"ingestion", "discovery", "detection"}


def _declares_ocsf_output(raw_modes: str) -> bool:
    if not raw_modes.strip():
        return True
    return "ocsf" in {part.strip() for part in raw_modes.split(",") if part.strip()}


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dict_has_key(node: ast.Dict, key: str) -> bool:
    return any(_const_str(candidate) == key for candidate in node.keys)


def _metadata_dicts(tree: ast.AST) -> list[ast.Dict]:
    found: list[ast.Dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key_node, value_node in zip(node.keys, node.values):
            if _const_str(key_node) == "metadata" and isinstance(value_node, ast.Dict):
                found.append(value_node)
    return found


def _looks_like_ocsf_emitter(tree: ast.AST) -> bool:
    constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    return "class_uid" in constants and "category_uid" in constants


def main() -> int:
    errors: list[str] = []

    for skill in discover_skill_contracts():
        if skill.category not in OCSF_LAYERS or skill.entrypoint is None:
            continue
        if not _declares_ocsf_output(skill.frontmatter.get("output_formats", "")):
            continue

        tree = ast.parse(skill.entrypoint.read_text(), filename=str(skill.entrypoint))
        if not _looks_like_ocsf_emitter(tree):
            continue
        metadata_dicts = _metadata_dicts(tree)
        if not metadata_dicts:
            errors.append(f"{skill.entrypoint}: no OCSF metadata dict found")
            continue

        for index, metadata_dict in enumerate(metadata_dicts, start=1):
            if not _dict_has_key(metadata_dict, "uid"):
                errors.append(f"{skill.entrypoint}: metadata dict #{index} missing `uid`")

    if errors:
        print("OCSF metadata validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("OCSF metadata validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
