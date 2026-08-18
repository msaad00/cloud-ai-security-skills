# References — ingest-snowflake-query-history-ocsf

## Source schema (Snowflake ACCOUNT_USAGE)

- **QUERY_HISTORY view** — https://docs.snowflake.com/en/sql-reference/account-usage/query_history
- **SESSIONS view** (source of `CLIENT_IP`, joined on `SESSION_ID`) — https://docs.snowflake.com/en/sql-reference/account-usage/sessions
- **USERS view** (source of `TYPE` / email enrichment) — https://docs.snowflake.com/en/sql-reference/account-usage/users
- **QUERY_HISTORY table function** — https://docs.snowflake.com/en/sql-reference/functions/query_history

## Parsed statements (official DDL/DCL syntax)

- **GRANT ROLE** — https://docs.snowflake.com/en/sql-reference/sql/grant-role
- **ALTER USER** (`RSA_PUBLIC_KEY`, `RSA_PUBLIC_KEY_2`) — https://docs.snowflake.com/en/sql-reference/sql/alter-user
- **ALTER ACCOUNT** (`NETWORK_POLICY`) — https://docs.snowflake.com/en/sql-reference/sql/alter-account
- **ALTER NETWORK POLICY** (`ALLOWED_IP_LIST`) — https://docs.snowflake.com/en/sql-reference/sql/alter-network-policy
- **ALTER DATABASE … ENABLE REPLICATION / FAILOVER** — https://docs.snowflake.com/en/sql-reference/sql/alter-database
- **CREATE / ALTER SESSION POLICY** — https://docs.snowflake.com/en/sql-reference/sql/create-session-policy
- **CREATE SHARE / ALTER SHARE** — https://docs.snowflake.com/en/sql-reference/sql/create-share
- **ALTER WAREHOUSE** (`WAREHOUSE_SIZE`) — https://docs.snowflake.com/en/sql-reference/sql/alter-warehouse
- **COPY INTO location (unload)** — https://docs.snowflake.com/en/sql-reference/sql/copy-into-location
- **GET** — https://docs.snowflake.com/en/sql-reference/sql/get

## Output format

- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 Actor object** — https://schema.ocsf.io/1.8.0/objects/actor
- **OCSF 1.8 schema browser** — https://schema.ocsf.io/

## Collection guidance

The skill itself reads JSON from stdin or local files and never connects to
Snowflake. Upstream collectors (`source-snowflake-query`) should:

- read `ACCOUNT_USAGE.QUERY_HISTORY` with parameterised queries (never string-concatenate)
- preserve `QUERY_ID`, `QUERY_TEXT`, `QUERY_TYPE`, `USER_NAME`, `ROLE_NAME`, `START_TIME`, `EXECUTION_STATUS`, `BYTES_SCANNED`, `ROWS_UNLOADED`
- optionally left-join `SESSIONS` on `SESSION_ID` to enrich `CLIENT_IP`, and `USERS` on `USER_NAME` to enrich `USER_TYPE` / email

Snowflake notes that `ACCOUNT_USAGE` views have latency (up to ~45 minutes for
QUERY_HISTORY) and retain 365 days of history. The skill keeps the source
`START_TIME` and `QUERY_ID` intact so downstream correlation can reason about
ordering and dedupe explicitly. `EXECUTION_STATUS` values are `success`, `fail`,
`incident`, and `failed_with_incident`.
