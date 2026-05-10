# Hardened reference Dockerfile for the MCP server (stdio).
#
# Pairs with #427 (sandboxing umbrella):
#   * RLIMIT_AS / FSIZE / CPU enforced in the wrapper (already shipped #428)
#   * Container-level: non-root UID, read-only-friendly, --cap-drop=ALL
#   * stdio transport — no listening socket, no port to expose
#
# Build: docker build -t cloud-security-mcp-server -f mcp-server/Dockerfile .
#
# Run (production-shape, single-call invocation):
#   docker run --rm -i \
#     --read-only --tmpfs /tmp \
#     --cap-drop=ALL --security-opt=no-new-privileges \
#     --user 65532:65532 \
#     --memory=512m --cpus=1.0 --pids-limit=128 \
#     -e CLOUD_SECURITY_MCP_ALLOWED_SKILLS=cspm-aws-cis-benchmark \
#     -e CLOUD_SECURITY_MCP_AUDIT_LOG=/var/log/cloud-security/audit.jsonl \
#     -e CLOUD_SECURITY_AUDIT_HMAC_KEY="$(cat secrets/hmac.key)" \
#     -v $PWD/audit:/var/log/cloud-security:rw \
#     cloud-security-mcp-server
#
# For Claude Desktop / Cursor / Codex, point the MCP client config at
# `docker run` (or its equivalent) instead of the Python entrypoint.
# See docs/integrations/<client>.md for a worked example.

FROM python:3.11-slim AS build

ENV PIP_NO_CACHE_DIR=1
WORKDIR /build

# The MCP server itself only needs pyyaml (frontmatter parsing) plus
# the SDKs the operator actually plans to call through. Add cloud SDKs
# here per deployment; the server lazy-imports per-skill.
RUN pip install --upgrade pip && pip install --prefix=/install \
        "pyyaml>=6.0" \
        "boto3>=1.34" \
        "google-cloud-compute>=1.20" \
        "google-cloud-iam>=2.16" \
        "google-cloud-resource-manager>=1.13" \
        "google-cloud-storage>=2.18" \
        "google-api-python-client>=2.100" \
        "azure-identity>=1.17" \
        "azure-mgmt-network>=28" \
        "azure-mgmt-resource>=23" \
        "azure-mgmt-storage>=21" \
        "defusedxml>=0.7"


FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN groupadd --system --gid 65532 nonroot \
 && useradd --system --uid 65532 --gid 65532 --no-create-home --shell /sbin/nologin nonroot

COPY --from=build /install /usr/local

# Only what the server runtime needs.
COPY --chown=65532:65532 mcp-server/src /app/mcp-server/src
COPY --chown=65532:65532 skills         /app/skills

WORKDIR /app
USER 65532:65532

# stdio transport — no EXPOSE. Stdin/stdout drive the JSON-RPC loop.
ENTRYPOINT ["python", "/app/mcp-server/src/server.py"]
