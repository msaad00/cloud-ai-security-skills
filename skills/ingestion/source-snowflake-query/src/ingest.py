"""Run a read-only Snowflake query and emit raw JSONL rows."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from typing import Any, Iterable

SKILL_NAME = "source-snowflake-query"
ALLOWED_PREFIXES = ("SELECT", "WITH", "SHOW", "DESCRIBE")
DISALLOWED_PATTERNS = (
    re.compile(r"--"),
    re.compile(r"/\*"),
    re.compile(r"\*/"),
    re.compile(r"\b(?:ALTER|CALL|COPY\s+INTO|CREATE|DELETE|DROP|EXECUTE\s+IMMEDIATE|GET|GRANT|INSERT|MERGE|PUT|REVOKE|TRUNCATE|UPDATE|USE)\b"),
    re.compile(r"\bIDENTIFIER\s*\("),
    re.compile(r"\bSYSTEM\$"),
)


def _configure_snowflake_logging() -> None:
    logging.getLogger("snowflake.connector").setLevel(logging.WARNING)


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
    import snowflake.connector

    _configure_snowflake_logging()
    kwargs: dict[str, str] = {
        "account": os.environ["SNOWFLAKE_ACCOUNT"],
        "user": os.environ["SNOWFLAKE_USER"],
        "password": os.environ["SNOWFLAKE_PASSWORD"],
    }
    for env_name, key in (
        ("SNOWFLAKE_WAREHOUSE", "warehouse"),
        ("SNOWFLAKE_DATABASE", "database"),
        ("SNOWFLAKE_SCHEMA", "schema"),
        ("SNOWFLAKE_ROLE", "role"),
    ):
        value = os.environ.get(env_name)
        if value:
            kwargs[key] = value
    return snowflake.connector.connect(**kwargs)


def _dict_cursor_class() -> Any:
    import snowflake.connector

    return snowflake.connector.DictCursor


def fetch_rows(query: str) -> list[dict[str, Any]]:
    conn = _connect()
    try:
        cursor = conn.cursor(_dict_cursor_class())
        try:
            cursor.execute(_normalize_query(query))
            rows = cursor.fetchall()
        finally:
            cursor.close()
    finally:
        conn.close()

    normalized: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            normalized.append(dict(row))
        else:
            normalized.append({"value": row})
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a read-only Snowflake query and emit raw JSONL rows.")
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
