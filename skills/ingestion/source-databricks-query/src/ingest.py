"""Run a read-only Databricks SQL query and emit raw JSONL rows."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Iterable

SKILL_NAME = "source-databricks-query"
ALLOWED_PREFIXES = ("SELECT", "WITH", "SHOW", "DESCRIBE")
DISALLOWED_PATTERNS = (
    re.compile(r"--"),
    re.compile(r"/\*"),
    re.compile(r"\*/"),
    re.compile(r"\b(?:ALTER|CALL|COPY\s+INTO|CREATE|DELETE|DROP|EXECUTE\s+IMMEDIATE|GET|GRANT|INSERT|MERGE|PUT|REVOKE|TRUNCATE|UPDATE|USE)\b"),
    re.compile(r"\bIDENTIFIER\s*\("),
    re.compile(r"\bSYSTEM\$"),
)


def _read_query(cli_query: str | None, stdin: Iterable[str]) -> str:
    if cli_query and cli_query.strip():
        return cli_query.strip()
    stdin_text = "".join(stdin).strip()
    if stdin_text:
        return stdin_text
    raise ValueError("provide a read-only SQL query via --query or stdin")


def _normalize_query(query: str) -> str:
    cleaned = query.strip()
    if not cleaned:
        raise ValueError("query must not be empty")
    while cleaned.endswith(";"):
        cleaned = cleaned[:-1].rstrip()
    if ";" in cleaned:
        raise ValueError("multiple SQL statements are not allowed")

    head = cleaned.lstrip("(\n\t ").upper()
    if not any(head.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        raise ValueError("only SELECT, WITH, SHOW, and DESCRIBE statements are allowed")
    _validate_read_only_shape(cleaned)
    return cleaned


def _strip_quoted_sql(text: str) -> str:
    result: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is None and char in ("'", '"', "`"):
            quote = char
            result.append(" ")
            index += 1
            continue
        if quote is not None:
            if char == quote:
                if index + 1 < len(text) and text[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            result.append(" ")
            index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _validate_read_only_shape(query: str) -> None:
    stripped = _strip_quoted_sql(query).upper()
    for pattern in DISALLOWED_PATTERNS:
        if pattern.search(stripped):
            raise ValueError(
                "query contains comments or disallowed control/write keywords; "
                "only plain read-only SELECT, WITH, SHOW, and DESCRIBE queries are allowed"
            )


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


def fetch_rows(query: str) -> list[dict[str, Any]]:
    conn = _connect()
    try:
        cursor = conn.cursor()
        try:
            cursor.execute(_normalize_query(query))
            rows = cursor.fetchall()
            column_names = [column[0] for column in (cursor.description or [])]
        finally:
            cursor.close()
    finally:
        conn.close()

    normalized: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            normalized.append(dict(row))
            continue
        if column_names:
            normalized.append({name: value for name, value in zip(column_names, row, strict=False)})
        else:
            normalized.append({"value": row})
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a read-only Databricks SQL query and emit raw JSONL rows.")
    parser.add_argument("--query", help="Read-only SQL query to run. If omitted, the query is read from stdin.")
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
