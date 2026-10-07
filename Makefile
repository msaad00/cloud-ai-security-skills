## Convenience targets for contributors. CI does not depend on this
## file — every command below has a direct shell-script equivalent
## documented in `CONTRIBUTING.md`.
##
## Every tool runs through `uv run` against the locked environment.
## Install it once with `uv sync --all-groups`.

RUN := uv run --frozen

.PHONY: help check lint typecheck docs-regen docs-check validate test ruff agent-evals demo

help:
	@echo "Common targets:"
	@echo "  make check       — lint + typecheck + validate + test (run before opening a PR)"
	@echo "  make lint        — ruff check + ruff format --check (same paths as CI)"
	@echo "  make typecheck   — mypy via scripts/run_mypy.sh in a dev-group-only env (same as CI's type-check job)"
	@echo "  make validate    — run every shared validator under scripts/ (includes docs-check)"
	@echo "  make test        — pytest over the same paths CI runs (skills, integration, conformance, mcp-server, agent examples)"
	@echo "  make demo        — run the captured-fixture ingest→detect→view pipeline (no cloud creds)"
	@echo "  make docs-regen  — regenerate every auto-generated doc (run after editing framework-coverage.json or adding a skill)"
	@echo "  make docs-check  — exit 1 if any auto-generated doc is stale (mirrors the CI gate)"
	@echo "  make ruff        — ruff check only"
	@echo "  make agent-evals — run agent example tests and LangGraph harness evals"

check: lint typecheck validate test

lint:
	$(RUN) ruff check skills/ tests/ mcp-server/ scripts/ examples/agents --config pyproject.toml
	$(RUN) ruff format --check . --config pyproject.toml

# mypy runs against the default (dev) group only, exactly like CI's type-check
# job, so results do not depend on which optional cloud SDK groups happen to
# be installed in the main .venv.
TYPECHECK_ENV := .venv-typecheck

typecheck:
	env -u VIRTUAL_ENV UV_PROJECT_ENVIRONMENT=$(TYPECHECK_ENV) uv sync --frozen --quiet
	env -u VIRTUAL_ENV UV_PROJECT_ENVIRONMENT=$(TYPECHECK_ENV) bash scripts/run_mypy.sh

demo:
	@set -e; \
	out="$${TMPDIR:-/tmp}/cloud-security-demo.sarif"; \
	echo "Running 3-step ingest -> detect -> view pipeline on a captured CloudTrail fixture..."; \
	$(RUN) python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py \
	        skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl \
	  | $(RUN) python skills/detection/detect-aws-access-key-creation/src/detect.py \
	  | $(RUN) python skills/view/convert-ocsf-to-sarif/src/convert.py \
	  > "$$out"; \
	echo ""; \
	echo "Findings written to $$out"; \
	$(RUN) python -c "import json, sys; rs = json.load(open(sys.argv[1]))['runs'][0]['results']; print(f'{len(rs)} finding(s) emitted'); [print(f\"  - {r['ruleId']}: {r['message']['text']}\") for r in rs]" "$$out"

docs-regen:
	@echo "Regenerating auto-generated docs..."
	$(RUN) python scripts/generate_framework_coverage_doc.py
	$(RUN) python scripts/generate_security_bar_matrix.py
	$(RUN) python scripts/coverage_summary.py --write
	@echo ""
	@echo "Now run \`git status\` and stage any updated files:"
	@echo "  docs/FRAMEWORK_COVERAGE.md"
	@echo "  SECURITY_BAR.md"
	@echo "  docs/COVERAGE_SNAPSHOT.md"

docs-check:
	@set -e; \
	$(RUN) python scripts/generate_framework_coverage_doc.py --check; \
	$(RUN) python scripts/generate_security_bar_matrix.py --check; \
	$(RUN) python scripts/coverage_summary.py --check

validate:
	$(RUN) python scripts/validate_skill_contract.py
	$(RUN) python scripts/validate_skill_integrity.py
	$(RUN) python scripts/validate_skill_runtime.py
	$(RUN) python scripts/validate_skill_structure.py
	$(RUN) python scripts/validate_presets.py
	$(RUN) python scripts/validate_dependency_consistency.py
	$(RUN) python scripts/validate_framework_coverage.py
	$(RUN) python scripts/validate_framework_depth.py
	$(RUN) python scripts/validate_remediation_infra.py
	$(RUN) python scripts/validate_ocsf_metadata.py
	$(RUN) python scripts/validate_skill_count_consistency.py
	$(RUN) python scripts/validate_doc_counts.py
	$(RUN) python scripts/validate_doc_parity.py
	$(RUN) python scripts/validate_mcp_tool_schemas.py
	$(RUN) python scripts/validate_deny_list_parity.py
	$(RUN) python scripts/validate_captured_provenance.py
	$(RUN) python scripts/add_skill_trust_frontmatter.py --check
	$(RUN) python scripts/validate_safe_skill_bar.py
	$(RUN) python scripts/validate_golden_ocsf.py
	$(RUN) python scripts/validate_golden_pipes.py
	$(RUN) python scripts/check_secret_literals.py
	$(MAKE) docs-check

test:
	$(RUN) pytest skills/ tests/integration/ tests/conformance/ mcp-server/tests/ -q --no-header --tb=line
	$(RUN) pytest examples/agents/tests -q --no-header --tb=line

ruff:
	$(RUN) ruff check skills/ tests/ mcp-server/ scripts/ --config pyproject.toml

agent-evals:
	$(RUN) ruff check examples/agents --config pyproject.toml
	$(RUN) pytest examples/agents/tests -q
	$(RUN) python examples/agents/eval_langgraph_harness.py --check
