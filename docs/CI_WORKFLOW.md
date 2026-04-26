# CI Workflow

The CI pipeline is split into independent lanes so failures point at the right kind of work without duplicating the entire repo in every job.

## Lanes

- `lint`
  - fast repo-wide Ruff gate
- `skill-contract`
  - shipped-skill metadata, integrity, dependency, framework, and OCSF contract validation
- `type-check`
  - repo-aware `mypy` run that checks each skill `src/` tree in isolation plus `mcp-server/` and `scripts/`
- `security-scan`
  - Bandit across `skills/`, `mcp-server/`, and `scripts/`
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
- `coverage`
  - repo coverage gates for overall, detection, and evaluation floors
- `sbom`
  - publishes a signed CycloneDX artifact set for the full locked dependency graph
- `release-assets`
  - rebuilds and attaches the signed CycloneDX SBOM set to published GitHub Releases
- `validate-iac`
  - CloudFormation and Terraform validation
- `agent-bom`
  - advisory artifact and SARIF generation
- `Auto Merge`
  - label-gated workflow that enables GitHub native auto-merge for trusted PRs

## Simplification Rules

- Share Python setup and dependency install logic through a composite action.
- Keep required checks small and actionable.
- Keep advisory scans separate from merge-blocking gates.
- Install only the packages each lane needs.
- Prefer grouped layer lanes over per-skill matrix fan-out when the skill family can share one dependency set.
- Cancel stale in-flight runs on the same PR branch so queued checks do not pile up behind superseded pushes.

## Auto-Merge Policy

Auto-merge is opt-in per PR:

1. The PR must come from the same repository, not a fork.
2. The PR must not be a draft.
3. The PR must have the `automerge` label.

When those conditions are true, `.github/workflows/automerge.yml` runs with
`pull_request_target` and does not check out or execute PR code. It calls
GitHub native auto-merge with squash merge and delete-branch enabled. GitHub
then waits for required checks and branch protection before merging.

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

Release cuts should follow [`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) so version bumps, changelog updates, and tag creation stay consistent with the CI bar.

For dependency transparency and provenance language, see
[`docs/SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md).
