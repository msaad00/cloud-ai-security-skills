"""Tests for sink-snowflake-jsonl."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src" / "sink.py"
_SPEC = importlib.util.spec_from_file_location("sink_snowflake_jsonl", _SRC)
assert _SPEC and _SPEC.loader
_SINK = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SINK
_SPEC.loader.exec_module(_SINK)

_normalize_table_name = _SINK._normalize_table_name
_prepare_rows = _SINK._prepare_rows
_summary = _SINK._summary
main = _SINK.main


class _FakeCursor:
    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.raise_message = "insert failed"
        self.executemany_sql = ""
        self.executemany_params = []
        self.batches: list[list] = []
        self.closed = False

    def executemany(self, sql, params) -> None:
        self.executemany_sql = sql
        self.executemany_params = list(params)
        self.batches.append(self.executemany_params)
        if self.should_fail:
            raise RuntimeError(self.raise_message)

    def close(self) -> None:
        self.closed = True


class _FakeConnection:
    def __init__(self, *, should_fail: bool = False) -> None:
        self.cursor_instance = _FakeCursor(should_fail=should_fail)
        self.closed = False
        self.autocommit_calls = []
        self.commit_called = False
        self.rollback_called = False

    def autocommit(self, value) -> None:
        self.autocommit_calls.append(value)

    def cursor(self):
        return self.cursor_instance

    def commit(self) -> None:
        self.commit_called = True

    def rollback(self) -> None:
        self.rollback_called = True

    def close(self) -> None:
        self.closed = True


class TestNormalizeTableName:
    def test_accepts_database_schema_table(self):
        assert (
            _normalize_table_name("security_db.ops.findings_sink")
            == '"security_db"."ops"."findings_sink"'
        )

    def test_rejects_invalid_identifier(self):
        try:
            _normalize_table_name("security_db.ops.findings;drop")
        except ValueError as exc:
            assert "invalid Snowflake identifier" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestPrepareRows:
    def test_extracts_metadata_from_native_and_ocsf(self):
        rows = list(
            _prepare_rows(
                [
                    '{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n',
                    '{"metadata":{"uid":"evt-2"},"finding_info":{"uid":"f-2"}}\n',
                ]
            )
        )

        assert rows[0].schema_mode == "native"
        assert rows[0].event_uid == "evt-1"
        assert rows[0].finding_uid == "f-1"
        assert rows[1].schema_mode == "ocsf"
        assert rows[1].event_uid == "evt-2"
        assert rows[1].finding_uid == "f-2"

    def test_rejects_non_object_json(self):
        try:
            list(_prepare_rows(['["not","an","object"]\n']))
        except ValueError as exc:
            assert "expected a JSON object" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestInsertAndMain:
    def test_apply_uses_parameterized_insert(self, monkeypatch):
        fake = _FakeConnection()
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)

        inserted = _SINK._insert_rows(
            '"security_db"."ops"."findings_sink"',
            _prepare_rows(['{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n']),
        )

        assert inserted == 1
        assert "PARSE_JSON(%s)" in fake.cursor_instance.executemany_sql
        assert "INSERT INTO" in fake.cursor_instance.executemany_sql
        assert fake.cursor_instance.executemany_params == [
            (
                '{"event_uid":"evt-1","finding_uid":"f-1","schema_mode":"native"}',
                "native",
                "evt-1",
                "f-1",
            )
        ]
        assert fake.commit_called is True
        assert fake.rollback_called is False
        assert fake.cursor_instance.closed is True
        assert fake.closed is True

    def test_insert_rolls_back_when_executemany_fails(self, monkeypatch):
        fake = _FakeConnection(should_fail=True)
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)

        try:
            _SINK._insert_rows(
                '"security_db"."ops"."findings_sink"',
                _prepare_rows(
                    ['{"schema_mode":"native","event_uid":"evt-1","finding_uid":"f-1"}\n']
                ),
            )
        except RuntimeError as exc:
            assert "insert failed" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")

        assert fake.commit_called is False
        assert fake.rollback_called is True
        assert fake.cursor_instance.closed is True
        assert fake.closed is True

    def test_summary_reports_dry_run(self):
        result = _summary('"security_db"."ops"."findings_sink"', Counter(native=1), True, 0)

        assert result["record_type"] == "sink_result"
        assert result["dry_run"] is True
        assert result["would_insert_records"] == 1
        assert result["inserted_records"] == 0
        assert result["input_records"] == 1
        assert result["schema_modes"] == {"native": 1}

    def test_main_defaults_to_dry_run(self, monkeypatch, capsys):
        monkeypatch.setattr(
            _SINK.sys, "stdin", io.StringIO('{"schema_mode":"native","event_uid":"evt-1"}\n')
        )

        exit_code = main(["--table", "security_db.ops.findings_sink"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is True
        assert payload["would_insert_records"] == 1

    def test_main_apply_executes_insert(self, monkeypatch, capsys):
        fake = _FakeConnection()
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO('{"metadata":{"uid":"evt-2"}}\n'))

        exit_code = main(["--table", "security_db.ops.findings_sink", "--apply"])

        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is False
        assert payload["inserted_records"] == 1
        assert fake.cursor_instance.executemany_params

    def test_main_apply_returns_error_when_insert_fails(self, monkeypatch, capsys):
        fake = _FakeConnection(should_fail=True)
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO('{"metadata":{"uid":"evt-2"}}\n'))

        exit_code = main(["--table", "security_db.ops.findings_sink", "--apply"])

        assert exit_code == 1
        assert "insert failed" in capsys.readouterr().err
        assert fake.commit_called is False
        assert fake.rollback_called is True

    def test_main_requires_records(self, monkeypatch, capsys):
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO(""))

        exit_code = main(["--table", "security_db.ops.findings_sink"])

        assert exit_code == 1
        assert "stdin did not contain any JSONL records" in capsys.readouterr().err

    def test_apply_batches_executemany_in_one_transaction(self, monkeypatch, capsys):
        fake = _FakeConnection()
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)
        lines = "".join(f'{{"event_uid":"evt-{i}"}}\n' for i in range(5))
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO(lines))

        exit_code = main(["--table", "findings_sink", "--apply", "--batch-size", "2"])

        assert exit_code == 0
        assert [len(batch) for batch in fake.cursor_instance.batches] == [2, 2, 1]
        assert [row[2] for batch in fake.cursor_instance.batches for row in batch] == [
            f"evt-{i}" for i in range(5)
        ]
        assert fake.commit_called is True
        assert fake.rollback_called is False
        payload = json.loads(capsys.readouterr().out)
        assert payload["input_records"] == 5
        assert payload["inserted_records"] == 5
        assert payload["schema_modes"] == {"raw": 5}

    def test_invalid_line_after_a_batch_rolls_back_everything(self, monkeypatch, capsys):
        fake = _FakeConnection()
        monkeypatch.setattr(_SINK, "_connect", lambda: fake)
        lines = '{"event_uid":"a"}\n{"event_uid":"b"}\n{"event_uid":"c"}\nnot json\n'
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO(lines))

        exit_code = main(["--table", "findings_sink", "--apply", "--batch-size", "2"])

        assert exit_code == 1
        assert "line 4: invalid JSON" in capsys.readouterr().err
        assert len(fake.cursor_instance.batches) == 1
        assert fake.commit_called is False
        assert fake.rollback_called is True
        assert fake.closed is True

    def test_apply_with_empty_stdin_does_not_connect(self, monkeypatch, capsys):
        def _no_connect():
            raise AssertionError("must not connect without records")

        monkeypatch.setattr(_SINK, "_connect", _no_connect)
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO("\n"))

        assert main(["--table", "findings_sink", "--apply"]) == 1
        assert "stdin did not contain any JSONL records" in capsys.readouterr().err

    def test_dry_run_counts_streamed_records(self, monkeypatch, capsys):
        lines = '{"schema_mode":"native"}\n{"metadata":{"uid":"e"}}\n{"x":1}\n'
        monkeypatch.setattr(_SINK.sys, "stdin", io.StringIO(lines))

        assert main(["--table", "findings_sink"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["input_records"] == 3
        assert payload["would_insert_records"] == 3
        assert payload["schema_modes"] == {"native": 1, "ocsf": 1, "raw": 1}

    @pytest.mark.parametrize("value", ["0", "-1", "abc"])
    def test_rejects_non_positive_batch_size(self, value, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--table", "findings_sink", "--batch-size", value])
        assert exc.value.code == 2
