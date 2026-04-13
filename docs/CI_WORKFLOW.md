# CI Workflow

The CI pipeline is split into independent lanes so failures point at the right kind of work without duplicating the entire repo in every job.

## Lanes

- `lint`
  - fast repo-wide Ruff gate
- `security-scan`
  - scoped Bandit for the currently enforced high-risk paths
- `safe-skill-bar`
  - policy lane for abuse resistance, write-path guardrails, wildcard IAM exceptions, secrets scan, and dependency audit against the repo's declared project dependencies
- `test-compliance`
  - benchmark skills grouped under one lane
- `test-remediation`
  - write-capable workflows isolated from read-only checks
- `test-detection-engineering`
  - OCSF ingest, detect, and convert skills in one grouped lane
- `test-ai-infra`
  - discovery, cross-cloud evidence, model serving, GPU, and AI inventory/BOM skills in one grouped lane
- `test-integration`
  - cross-skill contracts and pipe-level regression tests
- `validate-iac`
  - CloudFormation and Terraform validation
- `agent-bom`
  - advisory artifact and SARIF generation

## Simplification Rules

- Share Python setup and dependency install logic through a composite action.
- Keep required checks small and actionable.
- Keep advisory scans separate from merge-blocking gates.
- Install only the packages each lane needs.
- Prefer grouped layer lanes over per-skill matrix fan-out when the skill family can share one dependency set.
- Cancel stale in-flight runs on the same PR branch so queued checks do not pile up behind superseded pushes.

## Next Tightenings

1. Pin all third-party GitHub Actions to immutable SHAs.
2. Move repeated skill-family package sets into lock-backed sync commands once the dependency groups settle further.
3. Add a reusable workflow for test lanes only if grouped lanes stop being sufficient.

## Dependency Policy

Dependency refreshes should land in grouped batches, not one-package PR spam:

- `deps: github-actions`
- `deps: python-dev-tools`
- `deps: cloud-sdks`

Use the dependency hygiene skill spec as the review contract for those batches.

The `skill-contract` lane also enforces repo-level dependency/import consistency so cloud SDK imports cannot drift away from the declared dependency groups in `pyproject.toml`.
