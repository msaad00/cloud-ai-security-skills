"""Append JSONL records into a pre-provisioned Snowflake table."""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Iterator

SKILL_NAME = "sink-snowflake-jsonl"
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,254}$")
DEFAULT_BATCH_SIZE = 1000


@dataclass(frozen=True)
class PreparedRow:
    payload_json: str
    schema_mode: str
    event_uid: str
    finding_uid: str


def _configure_snowflake_logging() -> None:
    logging.getLogger("snowflake.connector").setLevel(logging.WARNING)


def _quote_identifier(identifier: str) -> str:
    if not IDENTIFIER_RE.fullmatch(identifier):
        raise ValueError(f"invalid Snowflake identifier `{identifier}`")
    return f'"{identifier}"'


def _normalize_table_name(raw_table: str) -> str:
    table = raw_table.strip()
    if not table:
        raise ValueError("table must not be empty")
    parts = table.split(".")
    if not 1 <= len(parts) <= 3:
        raise ValueError("table must be one of: table, schema.table, database.schema.table")
    return ".".join(_quote_identifier(part) for part in parts)


def _extract_schema_mode(record: dict[str, Any]) -> str:
    schema_mode = record.get("schema_mode")
    if isinstance(schema_mode, str) and schema_mode.strip():
        return schema_mode
    if "class_uid" in record or "finding_info" in record or "metadata" in record:
        return "ocsf"
    return "raw"


def _extract_event_uid(record: dict[str, Any]) -> str:
    event_uid = record.get("event_uid")
    if isinstance(event_uid, str):
        return event_uid
    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        metadata_uid = metadata.get("uid")
        if isinstance(metadata_uid, str):
            return metadata_uid
    return ""


def _extract_finding_uid(record: dict[str, Any]) -> str:
    finding_uid = record.get("finding_uid")
    if isinstance(finding_uid, str):
        return finding_uid
    finding_info = record.get("finding_info")
    if isinstance(finding_info, dict):
        finding_info_uid = finding_info.get("uid")
        if isinstance(finding_info_uid, str):
            return finding_info_uid
    return ""


def _prepare_rows(stdin: Iterable[str]) -> Iterator[PreparedRow]:
    for line_number, raw_line in enumerate(stdin, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON ({exc.msg})") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"line {line_number}: expected a JSON object")
        yield PreparedRow(
            payload_json=json.dumps(payload, separators=(",", ":"), sort_keys=True),
            schema_mode=_extract_schema_mode(payload),
            event_uid=_extract_event_uid(payload),
            finding_uid=_extract_finding_uid(payload),
        )


def _tally(rows: Iterable[PreparedRow], schema_modes: Counter[str]) -> Iterator[PreparedRow]:
    for row in rows:
        schema_modes[row.schema_mode] += 1
        yield row


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


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
    conn = snowflake.connector.connect(**kwargs)
    conn.autocommit(False)
    return conn


def _insert_rows(
    table_name: str, rows: Iterable[PreparedRow], batch_size: int = DEFAULT_BATCH_SIZE
) -> int:
    # Bandit flags dynamic SQL strings generically, but the only interpolated
    # value here is the already-validated table identifier path.
    sql = (
        f"INSERT INTO {table_name} "  # nosec B608
        "(payload, schema_mode, event_uid, finding_uid) "
        "VALUES (PARSE_JSON(%s), %s, %s, %s)"
    )
    conn = _connect()
    try:
        cursor = conn.cursor()
        try:
            # All batches share one transaction, so any failure (including an
            # invalid input line mid-stream) rolls back every earlier batch.
            inserted = 0
            it = iter(rows)
            while batch := list(itertools.islice(it, batch_size)):
                cursor.executemany(
                    sql,
                    [
                        (row.payload_json, row.schema_mode, row.event_uid, row.finding_uid)
                        for row in batch
                    ],
                )
                inserted += len(batch)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
    finally:
        conn.close()
    return inserted


def _summary(
    table_name: str, schema_modes: Counter[str], dry_run: bool, inserted: int
) -> dict[str, Any]:
    input_records = sum(schema_modes.values())
    return {
        "schema_mode": "native",
        "canonical_schema_version": "v1",
        "record_type": "sink_result",
        "sink": "snowflake",
        "table": table_name,
        "dry_run": dry_run,
        "input_records": input_records,
        "inserted_records": inserted,
        "would_insert_records": input_records if dry_run else 0,
        "schema_modes": dict(sorted(schema_modes.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Append JSONL records into a pre-provisioned Snowflake table.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--table",
        required=True,
        help="Target Snowflake table: table, schema.table, or database.schema.table.",
    )
    parser.add_argument(
        "--output-format",
        choices=("native",),
        default="native",
        help="Declared output rendering mode for the sink result.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Validate and summarize without inserting.",
    )
    mode.add_argument(
        "--apply",
        dest="dry_run",
        action="store_false",
        help="Execute parameterized INSERT statements.",
    )
    parser.add_argument(
        "--batch-size",
        type=_positive_int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Rows per executemany call within the single transaction (default {DEFAULT_BATCH_SIZE}).",
    )
    parser.set_defaults(dry_run=True)
    args = parser.parse_args(argv)

    try:
        table_name = _normalize_table_name(args.table)
        schema_modes: Counter[str] = Counter()
        rows = _tally(_prepare_rows(sys.stdin), schema_modes)
        first = next(rows, None)
        if first is None:
            raise ValueError("stdin did not contain any JSONL records")
        rows = itertools.chain([first], rows)
        if args.dry_run:
            inserted = 0
            for _ in rows:
                pass
        else:
            inserted = _insert_rows(table_name, rows, args.batch_size)
        sys.stdout.write(
            json.dumps(
                _summary(table_name, schema_modes, args.dry_run, inserted), separators=(",", ":")
            )
            + "\n"
        )
    except Exception as exc:
        print(f"[{SKILL_NAME}] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
