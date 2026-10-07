"""Run a read-only Databricks SQL query and emit raw JSONL rows."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Iterable, Iterator

from skills._shared.read_only_sql import normalize_read_only_query

SKILL_NAME = "source-databricks-query"
FETCH_BATCH_SIZE = 1000


def _read_query(cli_query: str | None, stdin: Iterable[str]) -> str:
    if cli_query and cli_query.strip():
        return cli_query.strip()
    stdin_text = "".join(stdin).strip()
    if stdin_text:
        return stdin_text
    raise ValueError("provide a read-only SQL query via --query or stdin")


def _normalize_query(query: str) -> str:
    return normalize_read_only_query(query)


def _connect() -> Any:
    from databricks import sql

    kwargs: dict[str, str] = {
        "server_hostname": os.environ["DATABRICKS_SERVER_HOSTNAME"],
        "http_path": os.environ["DATABRICKS_HTTP_PATH"],
        "access_token": os.environ["DATABRICKS_TOKEN"],
    }
    catalog = os.environ.get("DATABRICKS_CATALOG")
    schema = os.environ.get("DATABRICKS_SCHEMA")
    if catalog:
        kwargs["catalog"] = catalog
    if schema:
        kwargs["schema"] = schema
    return sql.connect(**kwargs)


def _normalize_row(row: Any, column_names: list[str]) -> dict[str, Any]:
    if isinstance(row, dict):
        return dict(row)
    if column_names:
        return {name: value for name, value in zip(column_names, row, strict=False)}
    return {"value": row}


def fetch_rows(query: str, batch_size: int = FETCH_BATCH_SIZE) -> Iterator[dict[str, Any]]:
    conn = _connect()
    try:
        cursor = conn.cursor()
        try:
            cursor.execute(_normalize_query(query))
            column_names = [column[0] for column in (cursor.description or [])]
            while rows := cursor.fetchmany(batch_size):
                for row in rows:
                    yield _normalize_row(row, column_names)
        finally:
            cursor.close()
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a read-only Databricks SQL query and emit raw JSONL rows."
    )
    parser.add_argument(
        "--query", help="Read-only SQL query to run. If omitted, the query is read from stdin."
    )
    parser.add_argument(
        "--output-format",
        choices=("raw",),
        default="raw",
        help="Declared output rendering mode for this source adapter.",
    )
    args = parser.parse_args(argv)

    try:
        query = _read_query(args.query, sys.stdin)
        for row in fetch_rows(query):
            sys.stdout.write(json.dumps(row, default=str, separators=(",", ":")) + "\n")
    except Exception as exc:
        print(f"[{SKILL_NAME}] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
