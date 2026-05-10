# Hardened reference Dockerfile for the webhook-receiver runner.
#
# Trust posture (sandboxing layer 1 — paired with #427 RLIMIT enforcement
# in the wrapper, which already shipped as #428):
#
#   * non-root UID  (no privilege escalation)
#   * read-only rootfs friendly (writes only to /tmp + the configurable
#     audit-log mount)
#   * `--cap-drop=ALL`         no Linux capabilities
#   * `--security-opt=no-new-privileges`
#   * default seccomp profile  (Docker / Kubernetes default is fine for
#                                the FastAPI + boto3 + sink-skill stack)
#
# Build: docker build -t cloud-security-webhook-receiver -f runners/webhook-receiver/Dockerfile .
#
# Run (production-shape):
#   docker run --rm -p 8080:8080 \
#     --read-only \
#     --tmpfs /tmp \
#     --cap-drop=ALL \
#     --security-opt=no-new-privileges \
#     --user 65532:65532 \
#     --memory=512m --cpus=1.0 --pids-limit=128 \
#     -e WEBHOOK_ALLOWED_SKILLS=ingest-cloudtrail-ocsf \
#     -e WEBHOOK_HMAC_SECRETS='{"ingest-cloudtrail-ocsf":"secret"}' \
#     -e WEBHOOK_SINK_TARGETS=s3,clickhouse \
#     -e CLOUD_SECURITY_MCP_AUDIT_LOG=/var/log/cloud-security/audit.jsonl \
#     -v $PWD/audit:/var/log/cloud-security:rw \
#     cloud-security-webhook-receiver
#
# Helm operators: the same flags are encoded in the chart under
# securityContext / resources / volumes. See `templates/helm/`.

# ── Build stage — pip install into an isolated prefix ────────────────
FROM python:3.11-slim AS build

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Pinned dependency set. Add the cloud SDKs the operator actually
# fans out to; the receiver imports lazily so unused SDKs are never
# loaded at runtime.
RUN pip install --upgrade pip && pip install --prefix=/install \
        "fastapi>=0.115" \
        "uvicorn[standard]>=0.30" \
        "pyyaml>=6.0" \
        "boto3>=1.34" \
        "snowflake-connector-python>=3.7" \
        "clickhouse-connect>=0.7" \
        "defusedxml>=0.7"


# ── Runtime stage — distroless-friendly, non-root by default ─────────
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/usr/local/lib/python3.11/site-packages

# Create the non-root UID we run as. 65532 matches Google distroless'
# `nonroot` so Helm RunAsUser bindings line up.
RUN groupadd --system --gid 65532 nonroot \
 && useradd --system --uid 65532 --gid 65532 --no-create-home --shell /sbin/nologin nonroot

# Bring deps in from the build stage (already isolated under /install).
COPY --from=build /install /usr/local

# Copy only what the receiver needs at runtime. No tests, no infra,
# no docs, no fixtures — keeps the rootfs read-only-friendly and the
# attack surface small. The `webhook-receiver` directory has a hyphen
# in its name (intentional, public-facing), so we can't import it as
# a Python package — the CMD below uses `--app-dir` to put the source
# directory on sys.path and load `server:app` by module name instead.
COPY --chown=65532:65532 mcp-server/src                 /app/mcp-server/src
COPY --chown=65532:65532 skills                         /app/skills
COPY --chown=65532:65532 runners/webhook-receiver/src   /app/webhook_receiver

WORKDIR /app
USER 65532:65532

EXPOSE 8080

# Healthcheck mirrors the receiver's /healthz route. Read-only-rootfs
# operators can still run it because it does not write to disk.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)" || exit 1

CMD ["python", "-m", "uvicorn", \
     "server:app", \
     "--app-dir", "/app/webhook_receiver", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "2"]
