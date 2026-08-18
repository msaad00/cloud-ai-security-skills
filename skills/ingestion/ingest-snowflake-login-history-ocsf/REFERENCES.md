# References — ingest-snowflake-login-history-ocsf

## Source schema (Snowflake ACCOUNT_USAGE)

- **LOGIN_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/login_history
- **LOGIN_HISTORY table function** — https://docs.snowflake.com/en/sql-reference/functions/login_history
- **USERS view** (source of `USER_TYPE` / email enrichment, joined on `USER_NAME`) — https://docs.snowflake.com/en/sql-reference/account-usage/users
- **Multi-factor authentication (MFA)** — https://docs.snowflake.com/en/user-guide/security-mfa

### Column casing (verified against the LOGIN_HISTORY view docs)

The exact documented column names and types this skill reads (all uppercase in
the view):

| Column | Type | Mapping |
|---|---|---|
| `EVENT_ID` | NUMBER | `metadata.uid`, `unmapped.snowflake.event_id` |
| `EVENT_TIMESTAMP` | TIMESTAMP_LTZ | `time` (epoch ms) |
| `EVENT_TYPE` | VARCHAR | `unmapped.snowflake.event_type` |
| `USER_NAME` | VARCHAR | `actor.user.uid` |
| `CLIENT_IP` | VARCHAR | `src_endpoint.ip` |
| `REPORTED_CLIENT_TYPE` | VARCHAR | `unmapped.snowflake.reported_client_type` |
| `FIRST_AUTHENTICATION_FACTOR` | VARCHAR | `unmapped.snowflake.first_authentication_factor` |
| `SECOND_AUTHENTICATION_FACTOR` | VARCHAR | `unmapped.snowflake.second_authentication_factor` (→ `authentication_method`) |
| `IS_SUCCESS` | VARCHAR (`YES`/`NO`) | `status_id`, `unmapped.snowflake.is_success` (boolean) |
| `ERROR_CODE` | NUMBER | `unmapped.snowflake.error_code` |
| `ERROR_MESSAGE` | VARCHAR | `unmapped.snowflake.error_message` |
| `RELATED_EVENT_ID` | NUMBER | (not currently mapped) |

`IS_SUCCESS` is documented as a VARCHAR reporting `YES` / `NO`; this skill maps
it to a boolean `unmapped.snowflake.is_success` and to OCSF `status_id`
(1 success / 2 failure). `ERROR_CODE` and `ERROR_MESSAGE` are populated only when
the login was not successful.

## Output format

- **OCSF 1.8 Authentication (3002)** — https://schema.ocsf.io/1.8.0/classes/authentication
- **OCSF 1.8 Metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 Actor object** — https://schema.ocsf.io/1.8.0/objects/actor
- **OCSF 1.8 schema browser** — https://schema.ocsf.io/

OCSF Authentication `activity_id` is `1` (Logon) for every LOGIN_HISTORY row;
the login outcome is carried by `status_id`, mirroring the repo's other
authentication producers (`ingest-okta-system-log-ocsf`,
`ingest-google-workspace-login-ocsf`).

## Collection guidance

The skill itself reads JSON from stdin or local files and never connects to
Snowflake. Upstream collectors (`source-snowflake-query`) should:

- read `ACCOUNT_USAGE.LOGIN_HISTORY` with parameterised queries (never string-concatenate)
- preserve `EVENT_ID`, `EVENT_TIMESTAMP`, `EVENT_TYPE`, `USER_NAME`, `CLIENT_IP`, `REPORTED_CLIENT_TYPE`, `FIRST_AUTHENTICATION_FACTOR`, `SECOND_AUTHENTICATION_FACTOR`, `IS_SUCCESS`, `ERROR_CODE`, `ERROR_MESSAGE`
- optionally left-join `USERS` on `USER_NAME` to enrich `USER_TYPE` / email

Snowflake notes that `ACCOUNT_USAGE` views have latency and retain 365 days of
history. The skill keeps the source `EVENT_TIMESTAMP` and `EVENT_ID` intact so
downstream correlation can reason about ordering and dedupe explicitly.

## Assumptions not asserted against a pinned source

- The specific numeric meanings of individual Snowflake authentication
  `ERROR_CODE` values (e.g. `390127`, `390114`) are treated as opaque,
  pass-through evidence. Snowflake documents that `ERROR_CODE` / `ERROR_MESSAGE`
  are populated on failed logins but does not publish a stable per-code table in
  the LOGIN_HISTORY reference; the skill never branches on a specific code, so no
  code-to-meaning mapping is claimed.
