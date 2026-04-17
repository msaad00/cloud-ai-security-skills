import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACK_DIR = ROOT / "packs" / "privilege-escalation-k8s"
SNOWFLAKE_SQL = PACK_DIR / "snowflake.sql"
DATABRICKS_SQL = PACK_DIR / "databricks.sql"
PACK_README = PACK_DIR / "README.md"
EXPECTED_COLUMNS = PACK_DIR / "golden" / "expected_columns.json"
EXPECTED_COLUMN_TYPES = PACK_DIR / "golden" / "expected_column_types.json"
EXPECTED_DATABRICKS_COLUMN_TYPES = PACK_DIR / "golden" / "expected_column_types_databricks.json"


def test_k8s_priv_esc_pack_files_exist() -> None:
    assert PACK_DIR.is_dir()
    assert SNOWFLAKE_SQL.is_file()
    assert DATABRICKS_SQL.is_file()
    assert PACK_README.is_file()
    assert EXPECTED_COLUMNS.is_file()
    assert EXPECTED_COLUMN_TYPES.is_file()
    assert EXPECTED_DATABRICKS_COLUMN_TYPES.is_file()


def test_k8s_priv_esc_pack_keeps_detector_contract() -> None:
    sql = SNOWFLAKE_SQL.read_text()

    for marker in (
        "IDENTIFIER($source_table)",
        "300000",
        "r1-secret-enum",
        "r2-pod-exec",
        "r3-rbac-self-grant",
        "r4-token-self-grant",
        "resource_type = 'secrets'",
        "subresource = 'exec'",
        "resource_type IN ('rolebindings', 'clusterrolebindings')",
        "subresource IN ('token', 'tokenrequest')",
        "resource_type = 'tokenreviews'",
        "T1552.007",
        "T1611",
        "T1098",
        "T1550.001",
        "finding_json",
    ):
        assert marker in sql


def test_k8s_priv_esc_pack_emits_expected_columns() -> None:
    sql = SNOWFLAKE_SQL.read_text()
    expected_columns = json.loads(EXPECTED_COLUMNS.read_text())

    for column in expected_columns:
        assert re.search(rf"\bAS\s+{re.escape(column)}\b", sql, re.IGNORECASE), column


def test_k8s_priv_esc_pack_locks_expected_column_types() -> None:
    sql = SNOWFLAKE_SQL.read_text()
    expected_column_types = json.loads(EXPECTED_COLUMN_TYPES.read_text())

    for column, column_type in expected_column_types.items():
        assert re.search(
            rf"::\s*{re.escape(column_type)}\s+AS\s+{re.escape(column)}\b",
            sql,
            re.IGNORECASE,
        ), column


def test_k8s_priv_esc_databricks_pack_keeps_detector_contract() -> None:
    sql = DATABRICKS_SQL.read_text()

    for marker in (
        "${source_table}",
        "${lookback_hours}",
        "300000",
        "r1-secret-enum",
        "r2-pod-exec",
        "r3-rbac-self-grant",
        "r4-token-self-grant",
        "resource_type = 'secrets'",
        "subresource = 'exec'",
        "resource_type IN ('rolebindings', 'clusterrolebindings')",
        "subresource IN ('token', 'tokenrequest')",
        "resource_type = 'tokenreviews'",
        "T1552.007",
        "T1611",
        "T1098",
        "T1550.001",
        "TO_JSON",
        "NAMED_STRUCT",
        "-- sqlfluff:dialect:databricks",
    ):
        assert marker in sql


def test_k8s_priv_esc_databricks_pack_emits_expected_columns() -> None:
    sql = DATABRICKS_SQL.read_text()
    expected_columns = json.loads(EXPECTED_COLUMNS.read_text())

    for column in expected_columns:
        assert re.search(rf"\bAS\s+{re.escape(column)}\b", sql, re.IGNORECASE), column


def test_k8s_priv_esc_databricks_pack_locks_expected_column_types() -> None:
    sql = DATABRICKS_SQL.read_text()
    expected_column_types = json.loads(EXPECTED_DATABRICKS_COLUMN_TYPES.read_text())

    for column, column_type in expected_column_types.items():
        if column == "finding_json":
            assert re.search(
                rf"CAST\(\s*TO_JSON\(.+?\)\s+AS\s+{re.escape(column_type)}\s*\)\s+AS\s+{re.escape(column)}\b",
                sql,
                re.IGNORECASE | re.DOTALL,
            ), column
            continue
        assert re.search(
            rf"CAST\(.+?\s+AS\s+{re.escape(column_type)}\)\s+AS\s+{re.escape(column)}\b",
            sql,
            re.IGNORECASE | re.DOTALL,
        ), column


def test_k8s_priv_esc_readme_describes_rules_and_window() -> None:
    readme = PACK_README.read_text()

    for phrase in (
        "API Activity (`6003`)",
        "raw_json STRING",
        "T1552.007",
        "T1611",
        "T1098",
        "T1550.001",
        "5 minutes",
        "databricks.sql",
        "sink-snowflake-jsonl",
    ):
        assert phrase in readme
