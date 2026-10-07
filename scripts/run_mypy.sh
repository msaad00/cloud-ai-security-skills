#!/usr/bin/env bash
set -euo pipefail

: "${UV_CACHE_DIR:=/tmp/cloud-security-core-foundation-uv-cache}"
export UV_CACHE_DIR
: "${MYPY_CACHE_DIR:=/tmp/cloud-security-mypy-cache}"

# Directories that scripts and the MCP server put on sys.path at runtime
# (e.g. `from skill_validation_common import ...`, `from sandbox import ...`).
# Resolving them gives mypy the real types instead of exempting the imports.
FIRST_PARTY_PATH="scripts:mcp-server/src:mcp-server/src/transports"

if command -v uv >/dev/null 2>&1; then
  MYPY_CMD=(uv run mypy)
else
  MYPY_CMD=(python -m mypy)
fi

# Tighten the shared/runtime surfaces first. Keep per-skill checking gradual
# while this repo incrementally removes Any and missing annotations.
# Phase 2 of #608: every module under skills/_shared/ is strict-typed.
MYPYPATH="$FIRST_PARTY_PATH" "${MYPY_CMD[@]}" \
  skills/_shared \
  --config-file pyproject.toml \
  --cache-dir "$MYPY_CACHE_DIR" \
  --disallow-untyped-defs \
  --disallow-incomplete-defs \
  --warn-return-any \
  --disallow-any-generics

MYPYPATH="$FIRST_PARTY_PATH" "${MYPY_CMD[@]}" \
  mcp-server/src \
  scripts \
  --config-file pyproject.toml \
  --cache-dir "$MYPY_CACHE_DIR" \
  --disallow-untyped-defs \
  --disallow-incomplete-defs \
  --warn-return-any

# Phase 3 of #608: the whole detection layer is strict-typed with the same
# flag set as skills/_shared/. --follow-imports=silent scopes each run to the
# detector's own files (see the remediation note below).
# New detection skills must land strict-clean under these flags (see
# CONTRIBUTING.md).
STRICT_SKILL_DIRS=()
for dir in skills/detection/*/src; do
  STRICT_SKILL_DIRS+=("$dir")
done

for dir in "${STRICT_SKILL_DIRS[@]}"; do
  "${MYPY_CMD[@]}" \
    "$dir" \
    --config-file pyproject.toml \
    --cache-dir "$MYPY_CACHE_DIR" \
    --disallow-untyped-defs \
    --disallow-incomplete-defs \
    --warn-return-any \
    --disallow-any-generics \
    --follow-imports=silent
done

# Phase 1 of #608: the whole remediation layer is strict-typed.
# --follow-imports=silent scopes the strict check to each remediation skill's
# OWN files: imported modules are still analyzed for types, so remediation
# call sites stay fully strict-checked, while errors in imported code are
# reported by the invocation that owns that code (skills/_shared/ above).
# New remediation skills must land strict-clean under these flags (see
# CONTRIBUTING.md).
REMEDIATION_STRICT_DIRS=(
  "skills/remediation/iam-departures-aws/src"
  "skills/remediation/iam-departures-azure-entra/src"
  "skills/remediation/iam-departures-gcp/src"
  "skills/remediation/remediate-aws-sg-revoke/src"
  "skills/remediation/remediate-azure-nsg-revoke/src"
  "skills/remediation/remediate-container-escape-k8s/src"
  "skills/remediation/remediate-entra-credential-revoke/src"
  "skills/remediation/remediate-gcp-firewall-revoke/src"
  "skills/remediation/remediate-k8s-rbac-revoke/src"
  "skills/remediation/remediate-mcp-tool-quarantine/src"
  "skills/remediation/remediate-okta-session-kill/src"
  "skills/remediation/remediate-workspace-session-kill/src"
)

for dir in "${REMEDIATION_STRICT_DIRS[@]}"; do
  "${MYPY_CMD[@]}" \
    "$dir" \
    --config-file pyproject.toml \
    --cache-dir "$MYPY_CACHE_DIR" \
    --disallow-untyped-defs \
    --disallow-incomplete-defs \
    --warn-return-any \
    --follow-imports=silent
done

for dir in skills/*/*/src; do
  case " ${STRICT_SKILL_DIRS[*]} ${REMEDIATION_STRICT_DIRS[*]} " in
    *" ${dir} "*) continue ;;
  esac
  if ! find "$dir" -maxdepth 1 \( -name '*.py' -o -name '*.pyi' \) | grep -q .; then
    continue
  fi
  "${MYPY_CMD[@]}" "$dir" --config-file pyproject.toml --cache-dir "$MYPY_CACHE_DIR"
done

MYPYPATH="$FIRST_PARTY_PATH" "${MYPY_CMD[@]}" mcp-server/src scripts --config-file pyproject.toml --cache-dir "$MYPY_CACHE_DIR"
