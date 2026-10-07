# CI Workflow

The CI pipeline is split into independent lanes so failures point at the right kind of work without duplicating the entire repo in every job.

## Lanes

Branch protection requires `lint`, `skill-contract`, `safe-skill-bar`,
`security-scan`, `test-compliance`, `test-remediation`,
`test-detection-engineering`, `test-ai-infra`, `test-integration`, and
`validate-iac`. Those names are stable on purpose.

- `changes`
  - classifies a pull request's diff (merge commit vs. base, renames split into delete + add); push to `main` and `workflow_dispatch` always run everything
- `lint`
  - `uv lock --check`, Ruff check + format, sqlfluff over `packs/`
- `skill-contract`
  - shipped-skill metadata, integrity, dependency, framework, OCSF contract, doc-count/parity validation, and generated-doc freshness
- `type-check`
  - `scripts/run_mypy.sh`: each skill `src/` tree in isolation plus `skills/_shared/`, `mcp-server/`, and `scripts/`
- `safe-skill-bar`
  - abuse resistance, write-path guardrails, wildcard IAM exceptions, golden OCSF fixtures, secrets scan, and dependency audit; also fails when `type-check` failed, so a type error blocks merge through a required check
- `security-scan`
  - Bandit across `skills/`, `mcp-server/`, `scripts/`, and `examples/agents/`
- `test-compliance` — `skills/evaluation/`
- `test-remediation` — `skills/remediation/`
- `test-detection-engineering` — `skills/ingestion/`, `skills/detection/`, `skills/view/`, `skills/output/`, `skills/detection-engineering/`
- `test-ai-infra` — `skills/discovery/` (environment inventory, AI BOM, control evidence, IAM departures reconciler), plus the lane partition check
- `test-integration` — `tests/integration/`, `tests/conformance/`, `mcp-server/tests/`
- `coverage`
  - combines the five lanes' coverage data and enforces the overall and per-layer floors in `scripts/validate_test_coverage.py`; it does not re-run tests
- `agent-examples`
  - Ruff + tests for `examples/agents/`, LangGraph harness eval and drift checks
- `sbom`
  - publishes a signed CycloneDX artifact set for the full locked dependency graph
- `validate-iac`
  - cfn-lint, `terraform validate`, tflint, Bicep build, and shellcheck
- `agent-bom`
  - advisory artifact and SARIF generation
- `release-assets`
  - rebuilds and attaches the signed CycloneDX SBOM set to published GitHub Releases
- `Auto Merge`
  - label-gated workflow that enables GitHub native auto-merge for trusted PRs

### How the test lanes work

Every lane runs its slice of the suite once, under coverage, in the full
locked environment (`uv sync --frozen --all-groups`, the same environment
the old single coverage run used). The lane -> path mapping lives only in
[`.github/actions/test-lane/action.yml`](../.github/actions/test-lane/action.yml).

- Lanes are whole layer directories. A new skill is picked up by its
  layer's lane with no CI edit. Do not split a layer into sibling skill
  directories on one pytest command line: per-skill `conftest.py` isolation
  of flat `src/` module names (`checks`, `detect`, ...) only holds for the
  collection order pytest uses when it walks a parent directory.
- `test-ai-infra` first proves the lanes partition the full suite
  (`skills tests/integration tests/conformance mcp-server/tests`): every
  collected test id must belong to exactly one lane. A new layer or test
  root that no lane claims fails this required check.
- `coverage` downloads the per-lane data files and runs
  `coverage combine`. The union of line hits equals a single-process run
  except for lines that only execute because an earlier test in the same
  process left state behind (for example a module already in
  `sys.modules`); those incidental hits are no longer counted.

### Conditional execution

Required checks must always report, so `ci.yml` never uses `on.paths`.
Instead, jobs read the `changes` job outputs and skip via job-level `if:`
(GitHub reports a job skipped by `if:` as success). Gated jobs use
`!cancelled()`, so if `changes` itself fails every lane runs.

| PR diff | Skipped |
|---|---|
| Only `*.md` outside `skills/`, `mcp-server/`, `tests/`, `runners/`, `examples/`, `scripts/`, `packs/`, `.github/`, or `docs/images/**` | `type-check`, `security-scan`, the four skill test lanes, `coverage`, `agent-examples`, `sbom`, `agent-bom`, `validate-iac` |
| No IaC-relevant path (`*/infra/*`, `runners/*`, `scripts/*.sh`, `*.tf`, `*.tfvars`, `*.hcl`, `*.bicep`, `*.yaml`, `*.yml`, `.github/*`, `Makefile`, `pyproject.toml`, `uv.lock`) | `validate-iac` |
| Anything else | nothing |

`lint`, `skill-contract`, `safe-skill-bar`, and `test-integration` always
run, because they validate docs (counts, parity, generated docs, README and
`docs/images` tests).

### Job graph

Every job starts in parallel except: gated jobs wait for `changes` (a few
seconds), `safe-skill-bar` waits for `type-check`, and `coverage` waits for
the five test lanes. Test lanes do not wait for lint or type checking;
superseded pushes are cancelled by the workflow `concurrency` group.

## Simplification Rules

- Share Python setup and dependency install logic through a composite action.
- Keep required checks small and actionable.
- Keep advisory scans separate from merge-blocking gates.
- Never let a non-required job gate a required one through `needs:` alone: a
  required job skipped because a dependency failed reports success.
- Run each test exactly once per workflow run.
- Install only the packages each lane needs; each distinct dependency set
  gets its own uv cache entry (`cache-suffix` in `setup-python-deps`).
- Prefer grouped layer lanes over per-skill matrix fan-out when the skill family can share one dependency set.
- Cancel stale in-flight runs on the same PR branch so queued checks do not pile up behind superseded pushes.
- Pin third-party actions to full commit SHAs with a version comment
  (Dependabot keeps them current).

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

1. Pin GitHub-owned actions (`actions/*`, `github/codeql-action`) to SHAs as well.
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
