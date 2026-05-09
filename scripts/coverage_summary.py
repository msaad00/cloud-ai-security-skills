#!/usr/bin/env python3
"""Generate the repo's coverage snapshot from `docs/framework-coverage.json`.

Three tables: by cloud / vendor (provider), by framework, by layer.
Plus the layered-target progress against each open roadmap issue.

The snapshot is checked in at `docs/COVERAGE_SNAPSHOT.md` and the
README "Progress snapshot" section pulls from the same numbers via
the `--readme` mode. A CI gate (`--check`) refuses any PR where the
on-disk snapshot has drifted from `framework-coverage.json`.

Usage:
  python scripts/coverage_summary.py            # print to stdout
  python scripts/coverage_summary.py --write    # write docs/COVERAGE_SNAPSHOT.md
  python scripts/coverage_summary.py --check    # exit 1 if disk != regenerated
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COVERAGE_JSON = REPO_ROOT / "docs" / "framework-coverage.json"
SNAPSHOT_MD = REPO_ROOT / "docs" / "COVERAGE_SNAPSHOT.md"


def _label_path(path: Path) -> str:
    """Pretty-print a path relative to the repo root when possible.
    Falls back to the absolute string for tmp_path / monkey-patched
    locations used in tests."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)

# Friendly labels for the framework / provider / layer keys we ship.
PROVIDER_LABEL = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "multi": "Multi-cloud (vendor-neutral)",
    "kubernetes": "Kubernetes",
    "mcp": "MCP / AI runtime",
    "okta": "Okta",
    "entra": "Microsoft Entra",
    "snowflake": "Snowflake",
    "databricks": "Databricks",
    "clickhouse": "ClickHouse",
    "google-workspace": "Google Workspace",
    "microsoft-graph": "Microsoft Graph",
    "containers": "Containers (runtime)",
    "workday": "Workday",
}

FRAMEWORK_LABEL = {
    "ocsf-1.8": "OCSF 1.8",
    "mitre-attack-v14": "MITRE ATT&CK v14",
    "mitre-atlas": "MITRE ATLAS",
    "nist-csf-2.0": "NIST CSF 2.0",
    "nist-ai-rmf": "NIST AI RMF",
    "soc2-tsc": "SOC 2 TSC",
    "pci-dss-4.0": "PCI DSS 4.0",
    "iso-27001-2022": "ISO 27001:2022",
    "owasp-llm-top-10": "OWASP LLM Top 10",
    "owasp-mcp-top-10": "OWASP MCP Top 10",
    "owasp-top-10": "OWASP Top 10",
    "cyclonedx-ml-bom": "CycloneDX ML-BOM",
    "cis-aws-v3": "CIS AWS v3",
    "cis-gcp-v3": "CIS GCP v3",
    "cis-azure-v2.1": "CIS Azure v2.1",
    "cis-k8s": "CIS Kubernetes",
    "cis-controls-v8": "CIS Controls v8",
    "cis-docker": "CIS Docker",
}

# Roadmap targets — bound to the open umbrella issues. Update these
# alongside the issue text when targets shift.
ROADMAP_TARGETS = [
    ("MITRE ATT&CK breadth", "#253", "mitre-attack-v14", 50),
    ("MITRE ATLAS", "#255", "mitre-atlas", 40),
    ("OWASP LLM Top 10", "#255", "owasp-llm-top-10", 40),
    ("OWASP MCP Top 10", "#255", "owasp-mcp-top-10", 50),
    ("OWASP Top 10 (web)", "TBD", "owasp-top-10", 30),
    ("NIST AI RMF", "TBD", "nist-ai-rmf", 30),
]


def _load() -> list[dict]:
    return json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))["skills"]


def _bucket_by(skills: list[dict], key: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for s in skills:
        for v in s.get(key, []):
            out[v].add(s["path"])
    return dict(out)


def _bucket_by_layer(skills: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for s in skills:
        out[s["layer"]].add(s["path"])
    return dict(out)


def _row(label: str, count: int, total: int) -> str:
    pct = 100 * count / total if total else 0
    return f"| {label} | {count} | {pct:.1f}% |"


def _label(key: str, table: dict[str, str]) -> str:
    return table.get(key, key)


def render(skills: list[dict]) -> str:
    total = len(skills)
    providers = _bucket_by(skills, "providers")
    frameworks = _bucket_by(skills, "frameworks")
    layers = _bucket_by_layer(skills)

    lines: list[str] = []
    lines.append("# Coverage Snapshot")
    lines.append("")
    lines.append(
        "Auto-generated from [`framework-coverage.json`](framework-coverage.json) by "
        "[`scripts/coverage_summary.py`](../scripts/coverage_summary.py). Do not edit "
        "by hand — the CI gate `--check` will refuse the PR. Regenerate with:"
    )
    lines.append("")
    lines.append("```bash")
    lines.append("python scripts/coverage_summary.py --write")
    lines.append("```")
    lines.append("")
    lines.append(f"**Total shipped skills:** {total}")
    lines.append("")
    lines.append("## By cloud / vendor")
    lines.append("")
    lines.append("Skills overlap when a skill targets multiple providers (the `multi` row), so the column may sum to more than the total.")
    lines.append("")
    lines.append("| Cloud / vendor | Skills | % of repo |")
    lines.append("|---|---:|---:|")
    for key in sorted(providers, key=lambda k: -len(providers[k])):
        lines.append(_row(_label(key, PROVIDER_LABEL), len(providers[key]), total))
    lines.append("")
    lines.append("## By framework")
    lines.append("")
    lines.append("Skills can carry multiple framework tags (e.g. a CIS check tagged with NIST CSF mapping); the column does not sum to 100%.")
    lines.append("")
    lines.append("| Framework | Skills | % of repo |")
    lines.append("|---|---:|---:|")
    for key in sorted(frameworks, key=lambda k: -len(frameworks[k])):
        lines.append(_row(_label(key, FRAMEWORK_LABEL), len(frameworks[key]), total))
    lines.append("")
    lines.append("## By layer")
    lines.append("")
    lines.append("| Layer | Skills | % of repo |")
    lines.append("|---|---:|---:|")
    for key in sorted(layers, key=lambda k: -len(layers[k])):
        lines.append(_row(key, len(layers[key]), total))
    lines.append("")
    lines.append("## Roadmap progress")
    lines.append("")
    lines.append(
        "Per-track breadth toward the published target. Numbers are "
        "**rough** — the framework tag count is a proxy for breadth, not "
        "depth. Each track lives under a roadmap issue."
    )
    lines.append("")
    lines.append("| Track | Tag | Issue | Target | Today |")
    lines.append("|---|---|---|---:|---:|")
    for label, issue, key, target in ROADMAP_TARGETS:
        skill_count = len(frameworks.get(key, set()))
        pct_today = 100 * skill_count / total if total else 0
        lines.append(
            f"| {label} | `{key}` | {issue} | {target}% | {pct_today:.0f}% |"
        )
    lines.append("")
    lines.append("## Where the gaps are")
    lines.append("")
    lines.append(
        "- **CIS depth** — only 4–6 controls per cloud × 3 clouds today. "
        "Roadmap [#254](https://github.com/msaad00/cloud-ai-security-skills/issues/254) "
        "calls for 50% per platform; ~35–40 more controls to ship."
    )
    lines.append(
        "- **OWASP Top 10 (web)** — zero detectors today. The hero banner "
        "advertises the framework — coverage owed."
    )
    lines.append(
        "- **NIST AI RMF + CycloneDX ML-BOM** — only 4 + 2 skills. AI "
        "inventory and posture is a credible next theme."
    )
    lines.append(
        "- **Per-vendor depth** — Snowflake / Databricks / ClickHouse are "
        "3–4 skills each. Detect-side coverage on those is thin."
    )
    lines.append(
        "- **PCI / ISO** — 3–4 skills each, mostly evidence-side. "
        "Detect / remediate slices could be added cheaply."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--write", action="store_true", help="overwrite docs/COVERAGE_SNAPSHOT.md")
    g.add_argument("--check", action="store_true", help="exit 1 if disk drifts from regenerated")
    args = parser.parse_args(argv)

    skills = _load()
    rendered = render(skills)

    if args.write:
        SNAPSHOT_MD.write_text(rendered, encoding="utf-8")
        print(f"wrote {_label_path(SNAPSHOT_MD)} ({len(rendered)} bytes)")
        return 0
    if args.check:
        if not SNAPSHOT_MD.is_file():
            print(
                f"error: {_label_path(SNAPSHOT_MD)} is missing. "
                f"Run `python scripts/coverage_summary.py --write`.",
                file=sys.stderr,
            )
            return 1
        on_disk = SNAPSHOT_MD.read_text(encoding="utf-8")
        if on_disk != rendered:
            print(
                f"error: {_label_path(SNAPSHOT_MD)} is stale. "
                f"Run `python scripts/coverage_summary.py --write` and commit.",
                file=sys.stderr,
            )
            return 1
        print(f"{_label_path(SNAPSHOT_MD)} is in sync.")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
