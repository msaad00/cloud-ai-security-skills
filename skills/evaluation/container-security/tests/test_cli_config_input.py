"""CLI config input: stdin (JSON or YAML) and file path give the same findings."""

from __future__ import annotations

import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import checks  # noqa: E402


def _run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    stdin: str = "",
) -> list:
    monkeypatch.setattr(sys, "argv", ["checks.py", *argv, "--output", "json"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    try:
        checks.main()
    except SystemExit as exc:
        assert exc.code in (0, 1, None)
    out = capsys.readouterr().out
    return json.loads(out)


def test_stdin_json_and_yaml_and_path_agree(monkeypatch, capsys, tmp_path):
    from_json = _run(monkeypatch, capsys, [], stdin="{}")
    from_yaml = _run(monkeypatch, capsys, ["-"], stdin="a: 1\n")
    path = tmp_path / "config.json"
    path.write_text("{}")
    from_path = _run(monkeypatch, capsys, [str(path)])
    assert from_json == from_path
    assert isinstance(from_yaml, type(from_json))


def test_empty_yaml_stdin_is_empty_config(monkeypatch, capsys):
    assert _run(monkeypatch, capsys, ["-"], stdin="") == _run(
        monkeypatch, capsys, ["-"], stdin="{}"
    )
