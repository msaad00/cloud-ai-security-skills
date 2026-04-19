from __future__ import annotations

import ast
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on Python <3.11
    sys.stderr.write(
        "error: validate_dependency_consistency.py requires Python 3.11+ "
        "(stdlib `tomllib`). Detected Python "
        f"{sys.version_info.major}.{sys.version_info.minor}. "
        "See pyproject.toml `requires-python = \">=3.11\"`.\n"
    )
    sys.exit(2)

from skill_validation_common import ROOT

PYPROJECT = ROOT / "pyproject.toml"

IMPORT_TO_PACKAGE = {
    "azure.identity": "azure-identity",
    "azure.mgmt.network": "azure-mgmt-network",
    "azure.mgmt.resource": "azure-mgmt-resource",
    "azure.mgmt.storage": "azure-mgmt-storage",
    "boto3": "boto3",
    "botocore": "boto3",
    "clickhouse_connect": "clickhouse-connect",
    "databricks": "databricks-sql-connector",
    "google.cloud.compute_v1": "google-cloud-compute",
    "google.cloud.iam_admin_v1": "google-cloud-iam",
    "google.cloud.iam_v1": "google-cloud-iam",
    "google.cloud.resourcemanager_v3": "google-cloud-resource-manager",
    "google.cloud.storage": "google-cloud-storage",
    "googleapiclient": "google-api-python-client",
    "httpx": "httpx",
    "moto": "moto",
    "pytest": "pytest",
    "snowflake.connector": "snowflake-connector-python",
}

RUNTIME_ROOTS = (
    *(ROOT / "skills").glob("*/*/src"),
    ROOT / "mcp-server" / "src",
    ROOT / "scripts",
)
TEST_ROOTS = (
    ROOT / "tests",
    ROOT / "mcp-server" / "tests",
)


def _canonical_package(spec: str) -> str:
    package = spec.split("[", 1)[0]
    for marker in (">=", "<=", "==", "~=", "!=", "<", ">"):
        package = package.split(marker, 1)[0]
    return package


def _load_dependency_groups() -> dict[str, set[str]]:
    data = tomllib.loads(PYPROJECT.read_text())
    groups = data.get("dependency-groups", {})
    return {group: {_canonical_package(spec) for spec in specs} for group, specs in groups.items()}


def _iter_python_files(*roots: Path) -> list[Path]:
    paths: list[Path] = []
    for root in roots:
        if root.is_file():
            paths.append(root)
            continue
        if root.exists():
            paths.extend(sorted(root.rglob("*.py")))
    return paths


def _extract_imports(path: Path) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or not node.module:
                continue
            names.add(node.module)
            for alias in node.names:
                if alias.name != "*":
                    names.add(f"{node.module}.{alias.name}")
    return names


def _required_packages(paths: list[Path]) -> set[str]:
    imports: set[str] = set()
    for path in paths:
        imports.update(_extract_imports(path))

    packages: set[str] = set()
    for name in imports:
        for prefix, package in IMPORT_TO_PACKAGE.items():
            if name == prefix or name.startswith(f"{prefix}."):
                packages.add(package)
                break
    return packages


def main() -> int:
    groups = _load_dependency_groups()
    errors: list[str] = []

    owners: dict[str, list[str]] = {}
    for group, packages in groups.items():
        for package in packages:
            owners.setdefault(package, []).append(group)
    for package, group_names in sorted(owners.items()):
        if len(group_names) > 1:
            errors.append(
                f"pyproject.toml: package `{package}` is duplicated across dependency groups: "
                f"{', '.join(sorted(group_names))}"
            )

    runtime_required = _required_packages(_iter_python_files(*RUNTIME_ROOTS))
    runtime_declared = set().union(
        groups.get("aws", set()),
        groups.get("gcp", set()),
        groups.get("azure", set()),
        groups.get("iam_departures", set()),
    )
    for package in sorted(runtime_required - runtime_declared):
        errors.append(f"pyproject.toml: runtime import requires undeclared package `{package}`")

    test_roots = [*TEST_ROOTS, *(ROOT / "skills").glob("*/*/tests")]
    test_required = _required_packages(_iter_python_files(*test_roots))
    dev_declared = groups.get("dev", set())
    for package in sorted(test_required & {"pytest", "moto"}):
        if package not in dev_declared:
            errors.append(f"pyproject.toml: test import requires `{package}` in the dev dependency group")

    if errors:
        print("Dependency consistency validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print("Dependency consistency validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
