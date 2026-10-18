"""CI validation and MCP must interpret the same skill contract consistently."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


VALIDATION = _load("metadata_validation_test", "scripts/skill_validation_common.py")
REGISTRY = _load("metadata_registry_test", "mcp-server/src/tool_registry.py")


@pytest.mark.parametrize("parser", [VALIDATION.parse_frontmatter, REGISTRY._parse_frontmatter])
@pytest.mark.parametrize(
    "text, expected",
    [
        ("execution_modes:\n  - jit\n  - mcp\n", {"execution_modes": "jit, mcp"}),
        ('description: "Detect: a:b"\n', {"description": "Detect: a:b"}),
        (
            "description: >-\n  first line\n  second line\n",
            {"description": "first line second line"},
        ),
        ("min_approvers: 2 # approved count\n", {"min_approvers": "2"}),
        ("worker_mode: true\ncaller_roles: null\n", {"worker_mode": "true", "caller_roles": ""}),
        ("metadata:\n  version: 1\n", {"metadata": "version=1"}),
        ("", {}),
    ],
)
def test_frontmatter_has_consistent_normalization(parser, text, expected):
    assert parser(text) == expected


@pytest.mark.parametrize("parser", [VALIDATION.parse_frontmatter, REGISTRY._parse_frontmatter])
@pytest.mark.parametrize("text", ["- jit\n- mcp\n", "not a mapping\n"])
def test_non_mapping_contract_is_rejected(parser, text):
    with pytest.raises(ValueError, match="must parse to a mapping"):
        parser(text)


def test_shipped_contract_metadata_matches_runtime():
    contracts = VALIDATION.discover_skill_contracts()
    specs = {skill.name: skill for skill in REGISTRY.discover_skills(ROOT)}
    assert len(contracts) == len(specs)
    for contract in contracts:
        spec = specs[contract.name]
        assert contract.entrypoint == spec.entrypoint
        assert contract.description == spec.description
        for field in (
            "execution_modes",
            "side_effects",
            "network_egress",
            "caller_roles",
            "approver_roles",
        ):
            assert getattr(contract, field) == getattr(spec, field), (contract.name, field)
