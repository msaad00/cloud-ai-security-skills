#!/usr/bin/env bash
set -euo pipefail

: "${UV_CACHE_DIR:=/tmp/cloud-security-core-foundation-uv-cache}"
export UV_CACHE_DIR

if command -v uv >/dev/null 2>&1; then
  MYPY_CMD=(uv run mypy)
else
  MYPY_CMD=(python -m mypy)
fi

# Tighten the shared/runtime surfaces first. Keep per-skill checking gradual
# while this repo incrementally removes Any and missing annotations.
"${MYPY_CMD[@]}" \
  skills/_shared/runtime_telemetry.py \
  mcp-server/src \
  scripts \
  --config-file pyproject.toml \
  --disallow-untyped-defs \
  --disallow-incomplete-defs \
  --warn-return-any

STRICT_SKILL_DIRS=(
  "skills/detection/detect-entra-role-grant-escalation/src"
  "skills/detection/detect-google-workspace-suspicious-login/src"
  "skills/detection/detect-mcp-tool-drift/src"
)

for dir in "${STRICT_SKILL_DIRS[@]}"; do
  "${MYPY_CMD[@]}" \
    "$dir" \
    --config-file pyproject.toml \
    --disallow-untyped-defs \
    --disallow-incomplete-defs \
    --warn-return-any
done

for dir in skills/*/*/src; do
  case " ${STRICT_SKILL_DIRS[*]} " in
    *" ${dir} "*) continue ;;
  esac
  if ! find "$dir" -maxdepth 1 \( -name '*.py' -o -name '*.pyi' \) | grep -q .; then
    continue
  fi
  "${MYPY_CMD[@]}" "$dir" --config-file pyproject.toml
done

"${MYPY_CMD[@]}" mcp-server/src scripts --config-file pyproject.toml
