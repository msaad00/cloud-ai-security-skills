# References — iam-departures-reconciler

The reconciler is the shared read-only planner for IAM departures manifests.
These references are limited to the upstream HR and warehouse sources the
planner normalizes.

## Official source references

- Workday Reporting-as-a-Service / custom report API docs — https://community.workday.com/content/workday-community/en-us/public/products/platform-and-product-extensions/soap-api-reference.html
- Snowflake Python Connector — https://docs.snowflake.com/en/developer-guide/python-connector/python-connector
- Databricks SQL Connector for Python — https://docs.databricks.com/en/dev-tools/python-sql-connector.html
- ClickHouse Python integration (`clickhouse-connect`) — https://clickhouse.com/docs/integrations/python

## Related repo contracts

- AWS parser / worker contract — [`../../remediation/iam-departures-aws/SKILL.md`](../../remediation/iam-departures-aws/SKILL.md)
- Shared skill contract — [`../../../docs/SKILL_CONTRACT.md`](../../../docs/SKILL_CONTRACT.md)
