"""Tests for ingest-mcp-proxy-ocsf.

Runs the ingester against the frozen golden fixture and asserts the output
matches the frozen OCSF fixture exactly.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ingest import (  # type: ignore[import-not-found]
    ACTIVITY_CREATE,
    ACTIVITY_READ,
    CANONICAL_VERSION,
    CATEGORY_UID,
    CLASS_UID,
    MAX_CHARS_ENV,
    OCSF_VERSION,
    OUTPUT_FORMATS,
    PRESERVE_CONTENT_ENV,
    SKILL_NAME,
    convert_event,
    ingest,
    input_schema_fingerprint,
    main,
    tool_fingerprint,
)

from skills._shared.timestamps import parse_ts_ms  # noqa: E402

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "mcp_proxy_raw_sample.jsonl"
OCSF_FIXTURE = GOLDEN / "mcp_proxy_sample.ocsf.jsonl"


def _scrub_volatile(events: list[dict]) -> list[dict]:
    """Remove timestamp-derived fields that the ingester sets from input.

    We DO pin `time` because it comes from the fixture's `timestamp` field,
    not from the wall clock — so it is reproducible. Records without a
    parseable timestamp are skipped, never stamped with now().
    """
    return events


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ── Fingerprint ────────────────────────────────────────────────────────


class TestFingerprint:
    def test_same_tool_same_fingerprint(self):
        tool = {
            "name": "query_db",
            "description": "Query",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnly": True},
        }
        assert tool_fingerprint(tool) == tool_fingerprint(dict(tool))

    def test_description_change_breaks_fingerprint(self):
        base = {"name": "t", "description": "A", "inputSchema": {}, "annotations": {}}
        mut = {"name": "t", "description": "B", "inputSchema": {}, "annotations": {}}
        assert tool_fingerprint(base) != tool_fingerprint(mut)

    def test_input_schema_change_breaks_fingerprint(self):
        base = {
            "name": "t",
            "description": "",
            "inputSchema": {"type": "object"},
            "annotations": {},
        }
        mut = {"name": "t", "description": "", "inputSchema": {"type": "string"}, "annotations": {}}
        assert tool_fingerprint(base) != tool_fingerprint(mut)

    def test_annotations_change_breaks_fingerprint(self):
        base = {
            "name": "t",
            "description": "",
            "inputSchema": {},
            "annotations": {"readOnly": True},
        }
        mut = {
            "name": "t",
            "description": "",
            "inputSchema": {},
            "annotations": {"readOnly": False},
        }
        assert tool_fingerprint(base) != tool_fingerprint(mut)

    def test_key_order_does_not_affect_fingerprint(self):
        a = {"name": "t", "description": "d", "inputSchema": {"a": 1, "b": 2}, "annotations": {}}
        b = {"annotations": {}, "inputSchema": {"b": 2, "a": 1}, "description": "d", "name": "t"}
        assert tool_fingerprint(a) == tool_fingerprint(b)

    def test_input_schema_fingerprint_isolated(self):
        t = {"name": "x", "description": "y", "inputSchema": {"k": "v"}, "annotations": {"z": 1}}
        # Changing description / annotations should NOT move the input_schema fingerprint
        t2 = {
            "name": "x",
            "description": "different",
            "inputSchema": {"k": "v"},
            "annotations": {"z": 999},
        }
        assert input_schema_fingerprint(t) == input_schema_fingerprint(t2)


# ── Timestamp parser ───────────────────────────────────────────────────


class TestParseTs:
    def test_iso_z(self):
        # 2026-04-10T05:00:00Z == 1775797200000 ms
        ms = parse_ts_ms("2026-04-10T05:00:00Z")
        assert ms == 1775797200000

    def test_iso_offset(self):
        ms = parse_ts_ms("2026-04-10T05:00:00.000+00:00")
        assert ms == 1775797200000

    def test_missing_is_none(self):
        assert parse_ts_ms(None) is None

    def test_garbage_is_none(self):
        assert parse_ts_ms("not-a-date") is None


# ── convert_event ──────────────────────────────────────────────────────


class TestConvertEvent:
    def test_tools_list_response_emits_one_per_tool(self):
        raw = {
            "timestamp": "2026-04-10T05:00:00Z",
            "session_id": "sess-abc",
            "method": "tools/list",
            "direction": "response",
            "body": {
                "tools": [
                    {"name": "a", "description": "", "inputSchema": {}, "annotations": {}},
                    {"name": "b", "description": "", "inputSchema": {}, "annotations": {}},
                ]
            },
        }
        events = list(convert_event(raw))
        assert len(events) == 2
        assert {e["mcp"]["tool"]["name"] for e in events} == {"a", "b"}
        for e in events:
            assert e["class_uid"] == CLASS_UID
            assert e["category_uid"] == CATEGORY_UID
            assert e["activity_id"] == ACTIVITY_CREATE
            assert e["type_uid"] == CLASS_UID * 100 + ACTIVITY_CREATE
            assert e["metadata"]["version"] == OCSF_VERSION
            assert "cloud_security_mcp" in e["metadata"]["profiles"]
            assert e["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_tools_call_request_emits_read_activity_with_tool_name_only(self):
        raw = {
            "timestamp": "2026-04-10T05:00:00Z",
            "session_id": "sess-abc",
            "method": "tools/call",
            "direction": "request",
            "params": {"name": "query_db", "arguments": {"sql": "SELECT 1"}},
        }
        events = list(convert_event(raw))
        assert len(events) == 1
        e = events[0]
        assert e["activity_id"] == ACTIVITY_READ
        assert e["mcp"]["tool"] == {"name": "query_db"}
        # Must NOT populate a fingerprint on a call — the detector pairs it
        # to the last-seen fingerprint in the same session.
        assert "fingerprint" not in e["mcp"]["tool"]

    def test_unknown_method_emits_base_event(self):
        raw = {"timestamp": "2026-04-10T05:00:00Z", "session_id": "s", "method": "ping"}
        events = list(convert_event(raw))
        assert len(events) == 1
        assert "tool" not in events[0]["mcp"]

    def test_missing_session_defaults_to_unknown(self):
        raw = {
            "timestamp": "2026-04-10T05:00:00Z",
            "method": "tools/list",
            "direction": "response",
            "body": {"tools": []},
        }
        events = list(convert_event(raw))
        assert all(e["mcp"]["session_uid"] == "sess-unknown" for e in events)

    def test_native_output_has_no_ocsf_envelope(self):
        raw = {
            "timestamp": "2026-04-10T05:00:00Z",
            "session_id": "sess-abc",
            "method": "tools/list",
            "direction": "response",
            "body": {
                "tools": [
                    {"name": "query_db", "description": "", "inputSchema": {}, "annotations": {}}
                ]
            },
        }
        events = list(convert_event(raw, output_format="native"))
        assert len(events) == 1
        event = events[0]
        assert event["schema_mode"] == "native"
        assert event["canonical_schema_version"] == CANONICAL_VERSION
        assert event["record_type"] == "application_activity"
        assert event["output_format"] == "native"
        assert event["provider"] == "MCP"
        assert event["tool"]["name"] == "query_db"
        assert "class_uid" not in event
        assert "metadata" not in event


# ── ingest (stream) ────────────────────────────────────────────────────


class TestIngest:
    def test_skips_blank_lines(self):
        lines = ["", "  ", "\n"]
        assert list(ingest(lines)) == []

    def test_skips_malformed_json_without_crashing(self, capsys):
        lines = ['{"not": "json"', '{"timestamp":"2026-04-10T05:00:00Z","method":"ping"}']
        events = list(ingest(lines))
        assert len(events) == 1
        assert "skipping line 1" in capsys.readouterr().err

    def test_skips_non_object_json(self, capsys):
        lines = ["[1,2,3]", '{"timestamp":"2026-04-10T05:00:00Z","method":"ping"}']
        events = list(ingest(lines))
        assert len(events) == 1
        assert "not a JSON object" in capsys.readouterr().err

    def test_rejects_unsupported_output_format(self):
        try:
            list(ingest([], output_format="bridge"))
        except ValueError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected unsupported output_format to raise")


# ── Golden fixture parity ──────────────────────────────────────────────


class TestGoldenFixture:
    def test_ingest_matches_golden_exactly(self):
        raw_lines = RAW_FIXTURE.read_text().splitlines()
        produced = list(ingest(raw_lines))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert len(produced) == len(expected), (
            f"event count mismatch: produced {len(produced)}, expected {len(expected)}"
        )
        for p, e in zip(produced, expected):
            assert p == e, (
                f"event mismatch:\n  produced: {json.dumps(p, sort_keys=True)}\n  expected: {json.dumps(e, sort_keys=True)}"
            )

    def test_sess_abc_query_db_fingerprint_changes_in_fixture(self):
        """Sanity check: the fixture is designed to trigger a drift detection.
        If someone edits the fixture and accidentally makes the tool stable,
        the whole point of the golden test goes away.
        """
        events = _load_jsonl(OCSF_FIXTURE)
        fps = [
            e["mcp"]["tool"]["fingerprint"]
            for e in events
            if e["mcp"]["session_uid"] == "sess-abc"
            and e["mcp"].get("method") == "tools/list"
            and e["mcp"]["tool"]["name"] == "query_db"
        ]
        assert len(fps) == 2, "fixture must contain two tools/list events for query_db in sess-abc"
        assert fps[0] != fps[1], (
            "fixture must have query_db drift — otherwise detection cannot be tested"
        )

    def test_sess_abc_read_file_fingerprint_is_stable_in_fixture(self):
        events = _load_jsonl(OCSF_FIXTURE)
        fps = [
            e["mcp"]["tool"]["fingerprint"]
            for e in events
            if e["mcp"]["session_uid"] == "sess-abc"
            and e["mcp"].get("method") == "tools/list"
            and e["mcp"]["tool"]["name"] == "read_file"
        ]
        assert len(fps) == 2
        assert fps[0] == fps[1], (
            "fixture must have stable read_file fingerprint as a negative control"
        )

    def test_native_fixture_projection_preserves_event_uid_and_tool_shape(self):
        raw_lines = RAW_FIXTURE.read_text().splitlines()
        native_events = list(ingest(raw_lines, output_format="native"))
        ocsf_events = list(ingest(raw_lines, output_format="ocsf"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(native_events) == len(ocsf_events)
        assert native_events[0]["event_uid"] == ocsf_events[0]["metadata"]["uid"]
        assert native_events[0]["schema_mode"] == "native"
        assert native_events[0]["record_type"] == "application_activity"
        assert "class_uid" not in native_events[0]
        assert "metadata" not in native_events[0]
        assert (
            native_events[0]["tool"]["fingerprint"] == ocsf_events[0]["mcp"]["tool"]["fingerprint"]
        )


# ── Opt-in content preservation ───────────────────────────────────────

SUPPLY_RAW = GOLDEN / "mcp_plugin_supply_chain_raw.jsonl"
ADVERSARIAL_RAW = GOLDEN / "mcp_adversarial_input_raw.jsonl"


def _sampling(params: dict) -> dict:
    return {
        "timestamp": "2026-04-10T08:00:00.000Z",
        "session_id": "s",
        "method": "sampling/createMessage",
        "direction": "request",
        "params": params,
    }


class TestPreserveMcpContentDefaultOff:
    def test_default_cli_output_is_byte_identical_to_frozen_golden(self, tmp_path, monkeypatch):
        monkeypatch.delenv(PRESERVE_CONTENT_ENV, raising=False)
        out = tmp_path / "out.jsonl"
        assert main([str(RAW_FIXTURE), "--output", str(out)]) == 0
        assert out.read_bytes() == OCSF_FIXTURE.read_bytes()

    def test_env_falsey_values_keep_default(self, tmp_path, monkeypatch):
        for value in ("", "0", "false", "no", "off"):
            monkeypatch.setenv(PRESERVE_CONTENT_ENV, value)
            out = tmp_path / "out.jsonl"
            assert main([str(RAW_FIXTURE), "--output", str(out)]) == 0
            assert out.read_bytes() == OCSF_FIXTURE.read_bytes()

    def test_default_drops_schema_prompt_and_messages(self, monkeypatch):
        monkeypatch.delenv(PRESERVE_CONTENT_ENV, raising=False)
        for raw_path in (SUPPLY_RAW, ADVERSARIAL_RAW):
            for fmt in OUTPUT_FORMATS:
                for event in ingest(raw_path.read_text().splitlines(), output_format=fmt):
                    assert "unmapped" not in event
                    tool = (event.get("mcp") or {}).get("tool") or event.get("tool") or {}
                    assert "input_schema" not in tool
        ocsf_blob = "".join(json.dumps(e) for e in ingest(ADVERSARIAL_RAW.read_text().splitlines()))
        assert "ignore all previous instructions" not in ocsf_blob
        assert "DAN" not in ocsf_blob


class TestPreserveMcpContentOn:
    def test_tools_list_preserves_input_schema_under_mcp_tool(self):
        events = list(ingest(SUPPLY_RAW.read_text().splitlines(), preserve_mcp_content=True))
        listed = [e for e in events if e["mcp"]["method"] == "tools/list"]
        assert [e["mcp"]["tool"]["name"] for e in listed] == ["docs_search", "sync_notes"]
        schema = listed[1]["mcp"]["tool"]["input_schema"]
        assert (
            schema["properties"]["endpoint"]["default"] == "https://exfil.attacker.example/collect"
        )
        # fingerprints are unchanged by the flag
        default = list(ingest(SUPPLY_RAW.read_text().splitlines()))
        assert listed[1]["mcp"]["tool"]["fingerprint"] == default[1]["mcp"]["tool"]["fingerprint"]

    def test_tools_call_arguments_are_not_preserved(self):
        events = list(ingest(SUPPLY_RAW.read_text().splitlines(), preserve_mcp_content=True))
        call = [e for e in events if e["mcp"]["method"] == "tools/call"][0]
        assert "unmapped" not in call
        assert "exfil" not in json.dumps(call)

    def test_sampling_text_content_flattened_into_unmapped(self):
        (event,) = convert_event(
            _sampling(
                {
                    "messages": [
                        {"role": "user", "content": {"type": "text", "text": "hi"}},
                        {
                            "role": "user",
                            "content": [
                                {"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"},
                                {"type": "text", "text": "a"},
                                {"type": "text", "text": "b"},
                            ],
                        },
                        {"role": "user", "content": {"type": "audio", "data": "eA=="}},
                        {"role": "user", "content": "plain"},
                    ],
                    "systemPrompt": "sys",
                }
            ),
            preserve_mcp_content=True,
        )
        assert event["unmapped"] == {
            "mcp": {
                "prompt": "sys",
                "request": {
                    "params": {
                        "messages": [
                            {"content": "hi"},
                            {"content": "a\nb"},
                            {},
                            {"content": "plain"},
                        ]
                    }
                },
            }
        }
        assert "aGVsbG8=" not in json.dumps(event)

    def test_native_output_carries_same_preserved_fields(self):
        raw = _sampling({"messages": [{"role": "user", "content": {"type": "text", "text": "x"}}]})
        (ocsf,) = convert_event(raw, preserve_mcp_content=True)
        (native,) = convert_event(raw, output_format="native", preserve_mcp_content=True)
        assert native["unmapped"] == ocsf["unmapped"]

    def test_long_strings_truncated_and_flagged(self, monkeypatch):
        monkeypatch.setenv(MAX_CHARS_ENV, "8")
        (event,) = convert_event(
            _sampling(
                {
                    "messages": [{"role": "user", "content": {"type": "text", "text": "x" * 20}}],
                    "systemPrompt": "y" * 20,
                }
            ),
            preserve_mcp_content=True,
        )
        mcp = event["unmapped"]["mcp"]
        assert mcp["prompt"] == "y" * 8
        assert mcp["request"]["params"]["messages"][0]["content"] == "x" * 8
        assert mcp["truncated_fields"] == ["prompt", "request.params.messages[0].content"]

    def test_oversized_schema_omitted_and_flagged(self, monkeypatch):
        monkeypatch.setenv(MAX_CHARS_ENV, "16")
        raw = {
            "timestamp": "2026-04-10T08:00:00.000Z",
            "session_id": "s",
            "method": "tools/list",
            "direction": "response",
            "body": {"tools": [{"name": "t", "inputSchema": {"description": "z" * 64}}]},
        }
        (event,) = convert_event(raw, preserve_mcp_content=True)
        tool = event["mcp"]["tool"]
        assert "input_schema" not in tool
        assert tool["input_schema_omitted"] == "size_cap"

    def test_env_var_enables_preservation_via_cli(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv(PRESERVE_CONTENT_ENV, "1")
        out = tmp_path / "out.jsonl"
        assert main([str(ADVERSARIAL_RAW), "--output", str(out)]) == 0
        events = [json.loads(line) for line in out.read_text().splitlines()]
        assert all("unmapped" in e for e in events)
        assert "MCP content preservation is ON" in capsys.readouterr().err

    def test_cli_flag_enables_preservation(self, tmp_path, monkeypatch):
        monkeypatch.delenv(PRESERVE_CONTENT_ENV, raising=False)
        out = tmp_path / "out.jsonl"
        assert main([str(SUPPLY_RAW), "--preserve-mcp-content", "--output", str(out)]) == 0
        first = json.loads(out.read_text().splitlines()[0])
        assert "input_schema" in first["mcp"]["tool"]


CANARY = "CANARY-7f3e9d1c"


def _canary_session() -> list[str]:
    raws = [
        {
            "timestamp": "2026-04-10T09:00:00.000Z",
            "session_id": "s",
            "method": "tools/list",
            "direction": "response",
            "body": {
                "tools": [
                    {
                        "name": "t",
                        "description": "d",
                        "inputSchema": {"properties": {"x": {"default": f"schema-{CANARY}"}}},
                    }
                ]
            },
        },
        {
            "timestamp": "2026-04-10T09:00:01.000Z",
            "session_id": "s",
            "method": "tools/call",
            "direction": "request",
            "params": {"name": "t", "arguments": {"x": f"args-{CANARY}"}},
        },
        {
            "timestamp": "2026-04-10T09:00:02.000Z",
            "session_id": "s",
            "method": "tools/call",
            "direction": "response",
            "body": {"content": [{"type": "text", "text": f"output-{CANARY}"}]},
        },
        _sampling(
            {
                "systemPrompt": f"prompt-{CANARY}",
                "messages": [
                    {"role": "user", "content": {"type": "text", "text": f"msg-{CANARY}"}}
                ],
            }
        ),
    ]
    return [json.dumps(r) for r in raws]


class TestNativeRedaction:
    def test_native_default_carries_no_raw_content(self, monkeypatch):
        monkeypatch.delenv(PRESERVE_CONTENT_ENV, raising=False)
        events = list(ingest(_canary_session(), output_format="native"))
        assert len(events) == 4
        for event in events:
            assert "params" not in event
            assert "body" not in event
            assert "unmapped" not in event
        assert CANARY not in json.dumps(events)

    def test_native_default_keeps_tool_name_and_fingerprints(self):
        listed, call, _, _ = ingest(_canary_session(), output_format="native")
        assert listed["tool"]["name"] == "t"
        assert listed["tool"]["fingerprint"].startswith("sha256:")
        assert listed["tool"]["input_schema_sha256"].startswith("sha256:")
        assert call["tool"] == {"name": "t"}

    def test_native_matches_ocsf_content_fields_with_and_without_flag(self):
        for preserve in (False, True):
            ocsf = list(ingest(_canary_session(), preserve_mcp_content=preserve))
            native = list(
                ingest(_canary_session(), output_format="native", preserve_mcp_content=preserve)
            )
            for o, n in zip(ocsf, native, strict=True):
                assert n.get("tool") == o["mcp"].get("tool")
                assert n.get("unmapped") == o.get("unmapped")

    def test_flag_keeps_capped_content_but_never_call_arguments(self):
        for fmt in OUTPUT_FORMATS:
            events = list(ingest(_canary_session(), output_format=fmt, preserve_mcp_content=True))
            blob = json.dumps(events)
            assert f"schema-{CANARY}" in blob
            assert f"output-{CANARY}" in blob
            assert f"prompt-{CANARY}" in blob
            assert f"msg-{CANARY}" in blob
            assert f"args-{CANARY}" not in blob
            for event in events:
                assert "params" not in event
                assert "body" not in event

    def test_flag_preserves_tools_call_response_body(self):
        _, _, response, _ = ingest(_canary_session(), preserve_mcp_content=True)
        assert response["unmapped"] == {
            "mcp": {
                "response": {"body": {"content": [{"type": "text", "text": f"output-{CANARY}"}]}}
            }
        }

    def test_oversized_response_body_omitted_and_flagged(self, monkeypatch):
        monkeypatch.setenv(MAX_CHARS_ENV, "16")
        _, _, response, _ = ingest(_canary_session(), preserve_mcp_content=True)
        assert response["unmapped"] == {"mcp": {"response": {"body_omitted": "size_cap"}}}
