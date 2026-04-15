# Credential Provenance

This repo is **secret-minimizing**, not password-free.

The default credential order is:

1. workload identity, federation, or short-lived cloud credentials
2. vendor-issued access tokens
3. manager-injected secrets only where a vendor API or connector still requires them

The repo does **not** hardcode credentials in source. Skills should never ask for passwords in prompts, write secrets into findings, or echo sensitive values into stdout or stderr.

## Preferred credential order

| Preference | Pattern | Use when |
|---|---|---|
| 1 | workload identity / federation / STS / impersonation / OIDC | the platform supports ephemeral execution identity |
| 2 | short-lived vendor token | the vendor exposes token auth but not full federation |
| 3 | manager-injected secret or password | the vendor path still requires a client secret, password, or legacy connector credential |

## Runtime posture

| Surface | Expected credential posture |
|---|---|
| Ingest / detect / evaluate / discover / view | read-only cloud or local access only; prefer provider SDK default credential chains or workload identity |
| MCP wrapper | inherits the wrapped skill contract; must not persist or echo caller secrets |
| CI | prefer OIDC or runner-scoped ephemeral credentials; never store long-lived credentials in repo config |
| Remediation | prefer scoped execution roles and short-lived credentials; use injected secrets only for vendor paths that still require them |

## Current secret-bearing paths

The main secret-bearing paths are in `iam-departures-remediation`, which supports multiple HR and cross-cloud backends.

| Integration | Supported auth today | Preferred path |
|---|---|---|
| AWS execution | Lambda role / STS / org-scoped AssumeRole | workload identity and short-lived STS sessions |
| Snowflake source | `SNOWFLAKE_USER` + `SNOWFLAKE_PASSWORD` | storage integration or other federated warehouse access when available |
| Snowflake remediation | `SNOWFLAKE_REMEDIATION_PASSWORD` | scoped service identity with the smallest possible role |
| Databricks | `DATABRICKS_TOKEN` | short-lived scoped token |
| ClickHouse | `CLICKHOUSE_USER` + `CLICKHOUSE_PASSWORD` | manager-injected secret until a stronger platform-native option is available |
| Workday API | `WORKDAY_CLIENT_ID` + `WORKDAY_CLIENT_SECRET` | manager-injected secret; direct API path is a documented exception |
| Azure Entra | `AZURE_CLIENT_SECRET` | workload identity or cert-based app auth when operationally available |

These are runtime interfaces, not a recommendation to store plaintext secrets in shells, scripts, or source files.

## Handling rules

- Never commit passwords, client secrets, tokens, certificates, or customer data.
- Never print or persist secret values in logs, findings, evidence, or audit records.
- Redact sensitive values if they appear in examples, bug reports, or operator input.
- Prefer secret managers, vaults, parameter stores, or injected runtime env vars over developer shell profiles.
- Prefer official vendor SDKs and auth flows before introducing new direct dependencies.

## Dependency and API policy

Credential-bearing integrations should follow this order:

1. official vendor SDK
2. repo-owned code around that SDK or API
3. canonical OSS client only when the vendor does not provide a materially better option

Current documented exception:

- `httpx` is retained for the direct Workday REST path in `iam-departures-remediation`
- the stdlib alternative would reduce ergonomics without meaningfully improving trust or blast radius
- this exception is explicit so the repo does not imply that all network calls are cloud-provider SDK traffic only

## What this doc does not claim

- It does not claim every integration is passwordless today.
- It does not claim every vendor path supports federation.
- It does not claim secrets never exist in runtime memory.

It does claim:

- secrets are not hardcoded in source
- secret-bearing paths are narrow and documented
- federation and short-lived credentials are the preferred operating model
- operators should treat any remaining password or client-secret path as a compatibility edge, not the target state
