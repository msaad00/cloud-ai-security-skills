"""Reconciler — daily HR-to-IAM reconciliation engine.

Ingests termination data from multiple HR sources (Workday via Snowflake,
Databricks, ClickHouse, or direct API), reconciles against AWS IAM state,
and produces a change-detected manifest for remediation.

MITRE ATT&CK coverage:
    T1078.004  Valid Accounts: Cloud Accounts — detects departed-employee IAM persistence
    T1098.001  Account Manipulation: Additional Cloud Credentials — catches orphaned access keys
    T1087.004  Account Discovery: Cloud Account — enumerates IAM users per account
"""

from reconciler.change_detect import ChangeDetector
from reconciler.export import ManifestBuilder
from reconciler.sources import (
    ClickHouseSource,
    DatabricksSource,
    HRSource,
    SnowflakeSource,
    WorkdayAPISource,
)

__all__ = [
    "HRSource",
    "SnowflakeSource",
    "DatabricksSource",
    "ClickHouseSource",
    "WorkdayAPISource",
    "ChangeDetector",
    "ManifestBuilder",
]
