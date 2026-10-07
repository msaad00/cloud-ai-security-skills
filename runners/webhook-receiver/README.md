# Webhook receiver — any-source → ingest → S3 / Snowflake / ClickHouse

A vendor-neutral HTTP receiver that turns any webhook into the same
shipped pipeline the other reference runners use.

```
HTTP POST                                                shipped sinks
─────────                                                ─────────────
                                                       ┌── sink-s3-jsonl
vendor webhook ─► /webhook/<ingest-skill> ─► ingest ──┼── sink-snowflake-jsonl
S3 EventBridge ─►                            skill   └── sink-clickhouse-jsonl
generic POST  ─►                                ▼
                                          OCSF JSONL
                                          (fan-out)
```

Read next:

- [`../README.md`](../README.md) — how shipped runners relate to atomic
  skills.
- [`../../docs/RUNNER_CONTRACT.md`](../../docs/RUNNER_CONTRACT.md) — the
  contract every runner satisfies.
- [`../../docs/MCP_AUDIT_CONTRACT.md`](../../docs/MCP_AUDIT_CONTRACT.md)
  — same audit shape this receiver writes.

## Why

The other reference runners (`aws-s3-sqs-detect`, `gcp-gcs-pubsub-detect`,
`azure-blob-eventgrid-detect`) are pinned to one cloud's primitives. A
SaaS webhook callback, a vendor signing receipt, or an internal HTTP
gateway have no out-of-the-box landing pad in the repo today. This
receiver fills that gap without forking the skill model — every
webhook payload is dispatched to a **named atomic ingest skill**, the
output is routed to the operator's choice of shipped sinks, and one
audit record is emitted per request.

## What it is, exactly

- **One process.** A FastAPI app under `src/server.py`. Stateless. Deploy
  on AWS App Runner / Lambda Function URL, GCP Cloud Run, Azure Container
  Apps, or any container runtime.
- **Authentication before routing.** Per-route timestamped HMAC-SHA-256,
  or bearer token, or both, is checked before the route is resolved.
  Every auth failure (missing / invalid / stale / replayed signature,
  missing bearer, no auth configured) returns the same
  `401 {"detail": "unauthorized"}` on every path, so an unauthenticated
  caller cannot tell which skills exist or are allowlisted. The specific
  reason is written to the audit record (`error_type`) only.
- **Closed-set routing, after auth.** `POST /webhook/<skill-name>`
  resolves `<skill-name>` against the shipped tool registry. Unknown
  skill → `404`. Skill outside `WEBHOOK_ALLOWED_SKILLS` or not an
  ingestion skill → `403`.
- **Replay protection.** The HMAC covers a timestamp as well as the body;
  requests outside the freshness window are refused, and a signature
  already accepted inside the window is refused as a replay. See
  [Signing requests](#signing-requests).
- **Fail closed.** A route with no HMAC secret and no
  `WEBHOOK_BEARER_TOKEN` → `401` (audit `auth_not_configured`). A
  malformed `WEBHOOK_HMAC_SECRETS`, `WEBHOOK_MAX_BODY_BYTES`, or
  `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` stops the process at startup
  instead of silently disabling the check.
- **Bounded bodies.** Requests larger than `WEBHOOK_MAX_BODY_BYTES`
  (default 1 MiB) → `413`, enforced while streaming so a chunked upload
  without `Content-Length` cannot buffer past the cap.
- **Sink fan-out.** Each emitted OCSF event is written to every sink in
  `WEBHOOK_SINK_TARGETS` (`s3,snowflake,clickhouse`). Sinks are the
  shipped `skills/output/sink-*-jsonl` skills — same dual-audit, same
  idempotent semantics.
- **One audit record per request.** Same JSON shape as
  `mcp_tool_call`: route, payload SHA-256, sink fan-out targets, the
  outbound `correlation_id`, and the wrapped skill exit code.

## Configuration

| Env var | Purpose |
|---|---|
| `WEBHOOK_ALLOWED_SKILLS` | Comma-separated allowlist. Any other skill name returns `403`. Defaults to **none** (locked-down by default). |
| `WEBHOOK_HMAC_SECRETS` | JSON object: `{"<skill-name>": "shared-secret"}`. Per-skill secret used for HMAC-SHA-256 verification of `X-Hub-Signature-256` (or the configurable header). |
| `WEBHOOK_HMAC_HEADER` | Header carrying the signature. Defaults to `X-Hub-Signature-256`. |
| `WEBHOOK_TIMESTAMP_HEADER` | Header carrying the signed Unix-seconds timestamp. Defaults to `X-Webhook-Timestamp`. |
| `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` | Freshness window in seconds, applied in both directions (default `300`). Older or future-dated requests return `401`. |
| `WEBHOOK_ALLOW_LEGACY_HMAC` | **Deprecated.** `1` also accepts body-only signatures (no timestamp header) for senders that cannot be updated yet. Off by default because a body-only signature can be replayed after the window. |
| `WEBHOOK_BEARER_TOKEN` | Bearer token. When set, `Authorization: Bearer <token>` is required on every route. Combine with HMAC for two-factor request auth. Every allowlisted skill needs an HMAC secret or this token. |
| `WEBHOOK_MAX_BODY_BYTES` | Max request body in bytes (default `1048576`). Larger bodies return `413`. |
| `WEBHOOK_SINK_TARGETS` | Comma-separated subset of `s3`, `snowflake`, `clickhouse`. Empty means no sink fan-out (response payload only). |
| `CLOUD_SECURITY_MCP_AUDIT_LOG` | Same env as the MCP wrapper — durable JSONL audit file (append + fsync per request). This surface does not add the HMAC chain fields. |

## Deployment templates

The `templates/` directory ships reference manifests for:

- AWS App Runner via container image
- AWS Lambda Function URL via container image (zero-cold-start at low volume)
- GCP Cloud Run
- Azure Container Apps
- Helm chart for self-hosted Kubernetes

Each template surfaces the env vars above and wires the audit log to a
mounted volume / managed secret store as appropriate. Adapting one for
a different runtime is a 10-line config change.

## Local quickstart

```bash
uv sync --group dev --group webhook --group http-runtime
export WEBHOOK_ALLOWED_SKILLS=ingest-cloudtrail-ocsf
export WEBHOOK_HMAC_SECRETS='{"ingest-cloudtrail-ocsf":"local-dev-secret"}'
export WEBHOOK_SINK_TARGETS=
uvicorn runners.webhook-receiver.src.server:app --port 8080

# In another shell:
BODY='[{"eventVersion":"1.08","eventSource":"signin.amazonaws.com",…}]'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac local-dev-secret -hex | sed 's/^.* //')
curl -sS -X POST localhost:8080/webhook/ingest-cloudtrail-ocsf \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Timestamp: $TS" \
  -H "X-Hub-Signature-256: sha256=$SIG" \
  --data "$BODY" | jq
```

## Signing requests

For a route with an HMAC secret, the sender computes:

```
timestamp = current Unix time in whole seconds, as decimal digits
signature = hex(HMAC-SHA-256(secret, timestamp + "." + raw_body))
```

and sends `X-Webhook-Timestamp: <timestamp>` plus
`X-Hub-Signature-256: sha256=<signature>` (bare hex is also accepted).
The receiver rejects the request with `401` when:

| Audit `error_type` | Cause |
|---|---|
| `missing_signature` | no signature header |
| `missing_timestamp` | no timestamp header and `WEBHOOK_ALLOW_LEGACY_HMAC` is off |
| `timestamp_invalid` | timestamp is not 1-12 decimal digits |
| `signature_invalid` | the MAC does not match (comparison is constant-time) |
| `timestamp_out_of_window` | the signed timestamp is more than `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` from the receiver clock |
| `replayed_request` | the same signature was already accepted and is still inside its window |

The timestamp is part of the MAC, so a captured request cannot be
re-stamped. Two deliveries of the same body need different timestamps
(or bodies); within one second, an identical re-send is a replay.

Replay limits to know:

- The accepted-signature cache is in process memory, bounded to 10,000
  entries (oldest evicted first). Replicas do not share it, and it is
  empty after a restart, so across replicas the freshness window is the
  bound: a captured request can be replayed to a different replica until
  its timestamp is older than the window. Keep the window short and
  clocks in sync (NTP).
- Bearer-only routes have no replay protection; the token is the
  credential. Prefer HMAC for anything reachable from outside.
- Legacy body-only signatures (`WEBHOOK_ALLOW_LEGACY_HMAC=1`) are
  de-duplicated for one window after first use and are replayable after
  that. The audit record marks them `hmac_scheme: legacy_body_only` so you
  can find senders still to migrate. This opt-in will be removed in a
  future release.

## What it is not

- Not a managed multi-tenant SaaS — operators run this themselves, same
  line as the other reference runners.
- Not an authentication service. HMAC + bearer cover the request-auth
  surface; identity federation, OIDC, mTLS belong upstream of the
  receiver.
- Not a scheduler. One request → one skill → one fan-out. Recurring or
  buffered ingestion belongs in the existing event-driven runners.

## Trust model

- **Default-deny on routing.** `WEBHOOK_ALLOWED_SKILLS` is empty by
  default; the receiver returns `403` until an operator opts a skill
  in.
- **Request authenticated before routing and before skill invocation.**
  An invalid, stale, or replayed signature never reaches routing or the
  skill subprocess; the audit record still fires with `result: error`
  and the specific `error_type`, while the caller sees only
  `401 unauthorized`.
- **Minimal skill environment.** The receiver spawns the skill with
  `PATH`, `PYTHONPATH`, and `CLOUD_SECURITY_*` settings only, minus
  wrapper-only values (`CLOUD_SECURITY_AUDIT_HMAC_KEY`,
  `CLOUD_SECURITY_MCP_*`, and names containing `BEARER` or `HMAC`).
  `WEBHOOK_*` secrets never reach the skill process.
- **Sink fan-out is best-effort, never silent.** Sink failures are
  logged into the audit record per-target. The webhook response
  surfaces `"sink_results": [{"target": "s3", "ok": true}, ...]` so
  the caller can tell.

## Hardened deployment (production-shape)

Recommended `docker run` flags pair with the shipped Dockerfile so the
runtime trust posture matches the Helm chart:

```bash
docker run --rm -p 8080:8080 \
  --read-only --tmpfs /tmp \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65532:65532 \
  --memory=512m --cpus=1.0 --pids-limit=128 \
  -e WEBHOOK_ALLOWED_SKILLS=ingest-cloudtrail-ocsf \
  -e WEBHOOK_HMAC_SECRETS='{"ingest-cloudtrail-ocsf":"shared-secret"}' \
  -e WEBHOOK_SINK_TARGETS=s3,clickhouse \
  -e CLOUD_SECURITY_MCP_AUDIT_LOG=/var/log/cloud-security/audit.jsonl \
  -e CLOUD_SECURITY_AUDIT_HMAC_KEY="$(cat secrets/hmac.key)" \
  -v $PWD/audit:/var/log/cloud-security:rw \
  cloud-security-webhook-receiver
```

The same controls in Kubernetes: see [`templates/helm/`](templates/helm/) — `securityContext.runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, `seccompProfile.type: RuntimeDefault`, `pids-limit` via the resource block, `emptyDir{medium: Memory}` for `/tmp`.

For the MCP server itself (stdio, no listening socket), see [`../../mcp-server/Dockerfile`](../../mcp-server/Dockerfile) — same hardened posture, no `EXPOSE`.
