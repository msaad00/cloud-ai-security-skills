# Release Checklist

This repo releases as one trust boundary. We do not version individual skills
independently.

## Cadence And Support

- Releases are demand-driven, not calendar-driven.
- During `0.x`, `main` and the most recent tagged release are the supported lines.
- Older `0.x` tags are not long-term-support releases unless a release note says otherwise.
- We do not publish a separate LTS line yet; if that changes, the release notes for that tag will state it explicitly.

## Semver Rules

- `PATCH` (`0.4.1`)
  - doc, visual, test, or CI-only changes
  - bug fixes that do not change a shipped skill's input/output, approval, or
    execution contract
  - validator hardening that rejects broken content without changing valid
    skill behavior
- `MINOR` (`0.5.0`)
  - new shipped skills
  - new providers, frameworks, assets, or runtime surfaces
  - new native/OCSF/bridge support on existing skills
  - new runner, sink, or orchestration templates
  - materially expanded telemetry, audit, or agent integration surface
- `MAJOR` (`1.0.0`)
  - incompatible wire-format changes
  - removed or renamed shipped skills
  - incompatible `SKILL.md` contract changes
  - incompatible approval, side-effect, or runtime-model changes

If a change mixes categories, bump to the highest applicable level.

While the repo is on `0.x`, an incompatible change ships as a `MINOR` bump
instead of `MAJOR`, and the CHANGELOG lists it under **Changed (breaking)**
with what consumers must change. `1.0.0` is reserved for declaring the
contract stable.

## Pre-Release

1. Confirm scope and target version.
2. Update [`CHANGELOG.md`](../CHANGELOG.md) with the material changes.
3. Update `pyproject.toml` version and any README/version badge references.
4. Confirm shipped-vs-planned language is still accurate in:
   - [`README.md`](../README.md)
   - [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
   - [`docs/ROADMAP.md`](ROADMAP.md)
5. Run the full CI-equivalent local bar when practical:
   - `ruff check skills/ tests/ mcp-server/ scripts/ --config pyproject.toml`
   - `python scripts/validate_skill_contract.py`
   - `python scripts/validate_skill_integrity.py`
   - `python scripts/validate_dependency_consistency.py`
   - `python scripts/validate_framework_coverage.py`
   - `python scripts/validate_ocsf_metadata.py`
   - `python scripts/validate_safe_skill_bar.py`
   - `bash scripts/run_mypy.sh`
   - `bandit -r skills mcp-server scripts -c pyproject.toml --severity-level medium`
6. Confirm coverage gates still pass: CI's `coverage` job runs
   `scripts/validate_test_coverage.py`, which holds the overall and per-layer
   floors (shipped code only; test files are excluded from measurement)
7. Confirm docs and registries are current:
   - [`docs/INSTALL.md`](INSTALL.md)
   - [`docs/framework-coverage.json`](framework-coverage.json)
   - [`docs/COVERAGE_MODEL.md`](COVERAGE_MODEL.md)
   - [`docs/USE_CASES.md`](USE_CASES.md)
   - [`docs/SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md)

## Tag And Publish

1. Merge the release PR to `main`.
2. Create a signed tag:

```bash
git tag -s vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

3. Publish the GitHub Release for the tag (`gh release create vX.Y.Z --notes-file <notes>`).
   `release-assets.yml` runs on `release: published`, not on a bare tag push.
4. Verify the tag points at the intended merge commit.
5. Verify GitHub Actions passed on the tagged commit if a release workflow uses
   tag triggers.
6. Verify the release workflow attached the signed CycloneDX SBOM **and** the signed source tarball:
   - SBOM: `cloud-ai-security-skills-full-lock.cdx.json` plus `.sigstore.json`
   - Source tarball: `cloud-ai-security-skills-<tag>-source.tar.gz` plus `.sigstore.json`
7. Verify the release workflow published SLSA build-provenance attestations for both the SBOM and the source tarball, plus a CycloneDX SBOM attestation binding the SBOM to the tarball. The attestations appear under the repo's GitHub attestation log and can be checked with `gh attestation verify <asset> --repo msaad00/cloud-ai-security-skills`.

## Post-Release

1. Verify `README.md`, `CHANGELOG.md`, and `pyproject.toml` agree on the version.
2. Verify docs still distinguish:
   - shipped today
   - supported pattern
   - roadmap / planned
3. Verify MCP-discovered metadata still matches shipped skill contracts.
4. Open the next `Unreleased` section immediately after the cut if needed.
