#!/usr/bin/env bash
set -euo pipefail

: "${UV_CACHE_DIR:=/tmp/cloud-security-core-foundation-uv-cache}"
export UV_CACHE_DIR

for dir in skills/*/*/src; do
  uv run mypy "$dir" --config-file pyproject.toml
done

uv run mypy mcp-server/src scripts --config-file pyproject.toml
