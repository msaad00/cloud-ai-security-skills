"""A rejected CloudTrail batch must not become a successful empty report."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INGEST = ROOT / "skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py"
DETECT = ROOT / "skills/detection/detect-aws-access-key-creation/src/detect.py"
EXPORT = ROOT / "skills/view/convert-ocsf-to-sarif/src/convert.py"
GOLDEN = ROOT / "skills/detection-engineering/golden"
RAW = (GOLDEN / "cloudtrail_raw_sample.jsonl").read_text().splitlines()[0]
EVENT = (GOLDEN / "cloudtrail_sample.ocsf.jsonl").read_text().splitlines()[0]
SECRET = "do-not-echo-rejected-payload"


def run(script, payload, *args):
    return subprocess.run(
        [sys.executable, str(script), *map(str, args)],
        input=payload,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )


def assert_rejected(result):
    assert result.returncode == 1, result.stderr
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(records) == 1, "failure must emit only an error envelope, never partial data"
    assert records[0]["event"] == "skill_error"
    assert records[0]["error_class"] == "contract"
    assert SECRET not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "bad",
    [
        '{"secret":"' + SECRET + '"',
        "null",
        "42",
        '"' + SECRET + '"',
        '{"Records":null}',
        '{"Records":{}}',
        '{"Records":"' + SECRET + '"}',
        "[null]",
        '{"Records":[null]}',
        '{"event":"skill_error","message":"' + SECRET + '"}',
        json.dumps({**json.loads(RAW), "eventTime": SECRET}),
        json.dumps({**json.loads(RAW), "userIdentity": SECRET}),
    ],
)
@pytest.mark.parametrize("output_format", ["ocsf", "native"])
def test_ingest_rejects_late_bad_record_without_partial_output(bad, output_format):
    assert_rejected(run(INGEST, RAW + "\n" + bad, "--output-format", output_format))


@pytest.mark.parametrize("bad", ["null", "[null]", '{"Records":null}', '{"Records":[null]}'])
def test_ingest_rejects_bad_whole_document(bad):
    assert_rejected(run(INGEST, bad))


def test_ingest_preserves_existing_destination_on_rejection(tmp_path):
    target = tmp_path / "output.jsonl"
    target.write_text("previous evidence\n")
    assert_rejected(run(INGEST, RAW + '\n{"broken":', "--output", target))
    assert target.read_text() == "previous evidence\n"


def test_ingest_allows_same_input_and_output_path(tmp_path):
    target = tmp_path / "events.jsonl"
    target.write_text(RAW + "\n")
    result = run(INGEST, "", target, "--output", target)
    assert result.returncode == 0, result.stderr
    assert json.loads(target.read_text())["class_uid"] == 6003


@pytest.mark.parametrize(
    "bad",
    [
        '{"secret":"' + SECRET + '"',
        "null",
        "[]",
        "{}",
        '{"event":"skill_error","message":"' + SECRET + '"}',
        json.dumps({**json.loads(EVENT), "time": SECRET}),
        json.dumps({**json.loads(EVENT), "resources": []}),
        json.dumps({**json.loads(EVENT), "metadata": SECRET}),
        json.dumps({**json.loads(EVENT), "class_uid": 2004}),
        json.dumps({**json.loads(EVENT), "status_id": None}),
        json.dumps({**json.loads(EVENT), "api": {}}),
    ],
)
@pytest.mark.parametrize("output_format", ["ocsf", "native"])
def test_detector_rejects_late_bad_record_without_partial_findings(bad, output_format):
    assert_rejected(run(DETECT, EVENT + "\n" + bad, "--output-format", output_format))


@pytest.mark.parametrize("payload", ["", "\n \n", "[]", '{"Records":[]}'])
def test_empty_ingest_batch_remains_valid(payload):
    result = run(INGEST, payload)
    assert result.returncode == 0 and result.stdout == ""


@pytest.mark.parametrize("patch", [{"status_id": 2}, {"api": {"operation": "ListUsers"}}])
def test_detector_nonmatches_remain_successful(patch):
    result = run(DETECT, json.dumps({**json.loads(EVENT), **patch}))
    assert result.returncode == 0 and result.stdout == ""


def test_failed_ingest_propagates_through_detector_and_export(tmp_path):
    target = tmp_path / "report.sarif"
    target.write_text("previous report\n")
    ingested = run(INGEST, RAW + '\n{"broken":')
    detected = run(DETECT, ingested.stdout)
    exported = run(EXPORT, detected.stdout, "--output", target)
    assert_rejected(ingested)
    assert_rejected(detected)
    assert exported.returncode != 0
    assert target.read_text() == "previous report\n"


@pytest.mark.parametrize("script", [INGEST, DETECT])
def test_invalid_utf8_is_a_payload_free_contract_error(script):
    result = subprocess.run(
        [sys.executable, str(script)],
        input=b"\xff",
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["error_class"] == "contract"
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("omit_event_id", [False, True])
def test_source_reference_survives_ingest_detect_and_sarif(omit_event_id):
    raw = json.loads(RAW)
    if omit_event_id:
        raw.pop("eventID", None)
    raw["requestParameters"]["password"] = SECRET
    raw["responseElements"] = {"accessKey": {"secretAccessKey": SECRET}}
    ingested = run(INGEST, json.dumps(raw))
    assert ingested.returncode == 0, ingested.stderr
    event = json.loads(ingested.stdout)
    detected = run(DETECT, ingested.stdout)
    assert detected.returncode == 0, detected.stderr
    finding = json.loads(detected.stdout)
    exported = run(EXPORT, detected.stdout)
    assert exported.returncode == 0, exported.stderr
    result = json.loads(exported.stdout)["runs"][0]["results"][0]
    reference = result["properties"]["evidence"]["source_event"]
    assert reference == {
        "uid": event["metadata"]["uid"],
        "producer": "ingest-cloudtrail-ocsf",
        "account_uid": raw["recipientAccountId"],
        "region": raw["awsRegion"],
    }
    if not omit_event_id:
        assert reference["uid"] == raw["eventID"]
    assert reference == finding["evidence"]["source_event"]
    assert SECRET not in detected.stdout + detected.stderr + exported.stdout + exported.stderr
    assert run(DETECT, ingested.stdout).stdout == detected.stdout


@pytest.mark.parametrize("output_format", ["ocsf", "native"])
def test_invalid_source_uid_rejects_batch_without_partial_findings(output_format):
    event = json.loads(EVENT)
    event["metadata"]["uid"] = {"secret": SECRET}
    assert_rejected(run(DETECT, EVENT + "\n" + json.dumps(event), "--output-format", output_format))


@pytest.mark.parametrize("uid", [{"secret": SECRET}, [SECRET], 42, True, "x" * 1025, "a\nb"])
@pytest.mark.parametrize("output_format", ["ocsf", "native"])
def test_ingest_rejects_malformed_source_id_without_stringifying_payload(uid, output_format):
    raw = json.loads(RAW)
    raw["eventID"] = uid
    assert_rejected(run(INGEST, RAW + "\n" + json.dumps(raw), "--output-format", output_format))


def test_cross_account_findings_keep_distinct_ids_through_sarif_export():
    first = json.loads(RAW)
    second = {**first, "recipientAccountId": "444455556666"}
    ingested = run(INGEST, json.dumps(first) + "\n" + json.dumps(second))
    assert ingested.returncode == 0, ingested.stderr
    detected = run(DETECT, ingested.stdout)
    assert detected.returncode == 0, detected.stderr
    findings = [json.loads(line) for line in detected.stdout.splitlines()]
    ids = {finding["metadata"]["uid"] for finding in findings}
    assert len(ids) == 2
    exported = run(EXPORT, detected.stdout)
    assert exported.returncode == 0, exported.stderr
    results = json.loads(exported.stdout)["runs"][0]["results"]
    assert {result["properties"]["finding_uid"] for result in results} == ids
    assert (
        len({result["partialFingerprints"]["primaryLocationLineHash"] for result in results}) == 2
    )
    assert {
        result["properties"]["evidence"]["source_event"]["account_uid"] for result in results
    } == {
        first["recipientAccountId"],
        second["recipientAccountId"],
    }
