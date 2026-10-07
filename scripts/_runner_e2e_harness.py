"""End-to-end harness for the shipped runner templates.

Invoked by `scripts/runner_e2e.sh`. Each runner gets its own scenario
block; per scenario we send N synthetic events that match the runner's
real contract, measure round-trip latency, and assert:

- the runner accepted + processed the event
- the audit log captured the event (and, where the runner writes an
  HMAC-chained audit, that the chain verifies)
- the configured sink actually received the event

Records are written as JSONL to `runtime-profile-results.jsonl` in the
repository root — one record per (runner, scenario). The shell wrapper
forwards the exit code of this harness, so any assertion failure fails
the workflow.

Honest gaps
-----------
- The webhook receiver's built-in audit log is single-line, not
  HMAC-chained. We record `audit_chain_verified=null` with a reason
  field rather than fabricate a chain status. The SSE runner does write
  a chained log; we run `scripts/verify_audit_chain.py` and capture the
  exit status.
- The GCP and Azure cloud runners have no in-tree local equivalent to
  `moto`. Their real handlers run against in-process fakes of the cloud
  SDK clients (`backend="in_process_fakes"` on the record). That proves
  handler wiring, the real ingest + detect skill round-trip, and
  redelivery dedupe — not IAM, triggers, or packaging in a real cloud.
  Real-cloud deploy proof stays tracked in issue #198.
- Sample size defaults to 20. These numbers are CI-runner numbers, not
  customer-scale numbers. See `docs/RUNTIME_PROFILES.md`.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import importlib.util
import json
import os
import shlex
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_PATH = REPO_ROOT / "runtime-profile-results.jsonl"

DEFAULT_SAMPLES = 20

# Make the webhook + SSE source trees importable.
sys.path.insert(0, str(REPO_ROOT / "mcp-server" / "src"))
sys.path.insert(0, str(REPO_ROOT / "runners" / "webhook-receiver" / "src"))


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _hex_hmac(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    sorted_values = sorted(values)
    # Linear-interpolation between closest ranks; matches NumPy default.
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * frac


def _summarize_timings(timings_ms: list[float]) -> dict[str, float]:
    if not timings_ms:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "mean_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}
    return {
        "p50_ms": round(_percentile(timings_ms, 50.0), 2),
        "p95_ms": round(_percentile(timings_ms, 95.0), 2),
        "mean_ms": round(statistics.fmean(timings_ms), 2),
        "min_ms": round(min(timings_ms), 2),
        "max_ms": round(max(timings_ms), 2),
    }


def _append_result(record: dict[str, Any]) -> None:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


# --------------------------------------------------------------------------- #
# Webhook receiver scenario                                                    #
# --------------------------------------------------------------------------- #


def _load_webhook_app(env: dict[str, str]) -> Any:
    """Load the receiver module under a controlled env so module-level
    config (allowlist, secrets) takes effect for this scenario."""
    for key, value in env.items():
        os.environ[key] = value
    # Force a fresh load so module-level reads see our env.
    for cached in [
        "webhook_server_e2e",
        "server",
        "auth",
        "router",
        "sinks",
    ]:
        sys.modules.pop(cached, None)
    src_dir = REPO_ROOT / "runners" / "webhook-receiver" / "src"
    spec = importlib.util.spec_from_file_location(
        "webhook_server_e2e",
        src_dir / "server.py",
        submodule_search_locations=[str(src_dir)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["webhook_server_e2e"] = module
    spec.loader.exec_module(module)
    return module


def run_webhook_scenario(samples: int) -> dict[str, Any]:
    """Boot the webhook receiver in-process (FastAPI TestClient) and
    exercise it with HMAC-signed CloudTrail events. The sink fan-out is
    disabled here because the shipped sinks need CLI flags that the
    receiver template does not yet pass; the sink-arrival assertion is
    treated as an honest gap. The receiver subprocess does invoke the
    real ingest skill, so the round-trip exercises router + auth +
    skill subprocess + audit write.
    """
    scenario = "ingest-cloudtrail-ocsf"
    correlation_ids: list[str] = []
    timings_ms: list[float] = []
    sink_arrivals = 0  # See sink_status below.

    with tempfile.TemporaryDirectory() as tmp:
        audit_log = Path(tmp) / "webhook-audit.jsonl"
        secret = "runner-e2e-shared-secret"
        env = {
            "WEBHOOK_ALLOWED_SKILLS": scenario,
            "WEBHOOK_HMAC_SECRETS": json.dumps({scenario: secret}),
            "WEBHOOK_HMAC_HEADER": "X-Hub-Signature-256",
            "WEBHOOK_SINK_TARGETS": "",
            "CLOUD_SECURITY_MCP_AUDIT_LOG": str(audit_log),
        }
        try:
            server_mod = _load_webhook_app(env)
        except Exception as exc:  # pragma: no cover - import is a precondition
            return {
                "runner": "webhook-receiver",
                "scenario": scenario,
                "status": "error",
                "error": f"import failed: {exc!r}",
                "samples": 0,
            }

        from fastapi.testclient import TestClient  # noqa: WPS433

        # Use the fixture the rest of the harness expects.
        fixture_path = REPO_ROOT / "skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl"
        if not fixture_path.is_file():
            return {
                "runner": "webhook-receiver",
                "scenario": scenario,
                "status": "error",
                "error": f"fixture missing: {fixture_path}",
                "samples": 0,
            }

        # Take the first non-empty event line as one CloudTrail record.
        raw_lines = [
            line.strip()
            for line in fixture_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not raw_lines:
            return {
                "runner": "webhook-receiver",
                "scenario": scenario,
                "status": "error",
                "error": f"fixture empty: {fixture_path}",
                "samples": 0,
            }
        record = raw_lines[0]

        client = TestClient(server_mod.app)

        # Liveness gate.
        healthz = client.get("/healthz")
        if healthz.status_code != 200:
            return {
                "runner": "webhook-receiver",
                "scenario": scenario,
                "status": "error",
                "error": f"healthz failed: {healthz.status_code}",
                "samples": 0,
            }

        failures = 0
        for i in range(samples):
            # Each sample is a distinct delivery: the receiver rejects a
            # re-sent signature as a replay, so vary the body (trailing JSON
            # whitespace) and sign it with a fresh timestamp.
            body = (record + " " * i + "\n").encode("utf-8")
            stamp = str(int(time.time()))
            sig = "sha256=" + _hex_hmac(secret, stamp.encode("ascii") + b"." + body)
            t0 = time.perf_counter()
            resp = client.post(
                f"/webhook/{scenario}",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Hub-Signature-256": sig,
                    "X-Webhook-Timestamp": stamp,
                },
            )
            dur_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status_code != 200:
                failures += 1
                continue
            timings_ms.append(dur_ms)
            payload = resp.json()
            cid = payload.get("correlation_id") or ""
            if cid:
                correlation_ids.append(cid)

        # Audit-log assertion — count `webhook_request` events that match
        # our correlation_ids.
        audit_records: list[dict[str, Any]] = []
        if audit_log.exists():
            for line in audit_log.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    audit_records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        audit_matches = sum(
            1 for rec in audit_records if rec.get("correlation_id") in set(correlation_ids)
        )

    timings_summary = _summarize_timings(timings_ms)
    status = "ok" if failures == 0 and audit_matches == samples else "fail"
    return {
        "runner": "webhook-receiver",
        "scenario": scenario,
        "status": status,
        "samples": samples,
        "successful_requests": samples - failures,
        "failed_requests": failures,
        "audit_records_matched": audit_matches,
        "audit_chain_verified": None,
        "audit_chain_status": "not_applicable_receiver_audit_is_unchained",
        "sink_arrival_count": sink_arrivals,
        "sink_status": "gap_sink_fanout_needs_per_sink_flags",
        "captured_at": _now_iso(),
        **timings_summary,
    }


# --------------------------------------------------------------------------- #
# MCP SSE scenario                                                             #
# --------------------------------------------------------------------------- #


def run_mcp_sse_scenario(samples: int) -> dict[str, Any]:
    """Boot the SSE transport on an ephemeral port + exercise the
    synchronous JSON-RPC `/rpc` endpoint with `ping` and `tools/list`.
    The transport writes an HMAC-chained audit log; after the run we
    invoke `scripts/verify_audit_chain.py` and capture its exit code."""
    scenario = "jsonrpc-ping-and-tools-list"
    timings_ms: list[float] = []

    with tempfile.TemporaryDirectory() as tmp:
        audit_log = Path(tmp) / "sse-audit.jsonl"
        keys_file = Path(tmp) / "sse-bearer-keys.json"

        # Mint a single bearer key + bearer secret pair in the keys file.
        # Schema: top-level JSON array of {kid, secret, issued, expires?}.
        bearer_secret = uuid.uuid4().hex + uuid.uuid4().hex
        keys_payload = [
            {
                "kid": "runner-e2e",
                "secret": bearer_secret,
                "issued": _now_iso(),
                "expires": "2099-01-01T00:00:00Z",
            }
        ]
        keys_file.write_text(json.dumps(keys_payload), encoding="utf-8")

        hmac_key_hex = uuid.uuid4().hex + uuid.uuid4().hex
        port = _free_port()
        sse_env = {
            **os.environ,
            "MCP_SSE_BIND": "127.0.0.1",
            "MCP_SSE_PORT": str(port),
            "MCP_SSE_BEARER_KEYS_FILE": str(keys_file),
            "CLOUD_SECURITY_MCP_AUDIT_LOG": str(audit_log),
            "CLOUD_SECURITY_AUDIT_HMAC_KEY": hmac_key_hex,
        }

        sse_entry = REPO_ROOT / "mcp-server" / "src" / "transports" / "sse.py"
        log_path = Path(tmp) / "sse-server.log"
        proc = subprocess.Popen(
            [sys.executable, str(sse_entry)],
            env=sse_env,
            cwd=str(REPO_ROOT),
            stdout=open(log_path, "wb"),
            stderr=subprocess.STDOUT,
        )

        try:
            # Wait for /healthz.
            import urllib.request  # noqa: WPS433

            ready = False
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                try:
                    # B310: localhost-only readiness probe against a port
                    # this process just started; URL is constructed here
                    # and never sourced from external input.
                    with urllib.request.urlopen(  # nosec B310
                        f"http://127.0.0.1:{port}/healthz", timeout=1.0
                    ) as resp:
                        if resp.status == 200:
                            ready = True
                            break
                except Exception:  # noqa: BLE001 - readiness loop
                    time.sleep(0.2)
            if not ready:
                return {
                    "runner": "mcp-sse",
                    "scenario": scenario,
                    "status": "error",
                    "error": "sse listener never became ready",
                    "samples": 0,
                    "captured_at": _now_iso(),
                }

            failures = 0
            valid_payloads = 0
            for i in range(samples):
                # Alternate ping and tools/list so we exercise dispatch.
                if i % 2 == 0:
                    payload = {"jsonrpc": "2.0", "id": i + 1, "method": "ping"}
                else:
                    payload = {
                        "jsonrpc": "2.0",
                        "id": i + 1,
                        "method": "tools/list",
                        "params": {},
                    }
                body = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/rpc",
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {bearer_secret}",
                    },
                )
                t0 = time.perf_counter()
                try:
                    # B310: localhost-only RPC; URL is constructed in this
                    # function for the listener this process just started.
                    with urllib.request.urlopen(req, timeout=10.0) as resp:  # nosec B310
                        dur_ms = (time.perf_counter() - t0) * 1000.0
                        if resp.status != 200:
                            failures += 1
                            continue
                        body_out = resp.read()
                except Exception:  # noqa: BLE001 - record as failure
                    failures += 1
                    continue
                # Sink-arrival = the JSON-RPC response carries result/error.
                try:
                    parsed = json.loads(body_out.decode("utf-8"))
                except json.JSONDecodeError:
                    failures += 1
                    continue
                if parsed.get("jsonrpc") != "2.0" or "id" not in parsed:
                    failures += 1
                    continue
                if "result" not in parsed and "error" not in parsed:
                    failures += 1
                    continue
                # ping → result is empty dict; tools/list → result has tools list.
                if payload["method"] == "tools/list":
                    res = parsed.get("result") or {}
                    if not isinstance(res, dict) or "tools" not in res:
                        failures += 1
                        continue
                valid_payloads += 1
                timings_ms.append(dur_ms)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

        # Chain verification.
        verify_cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "verify_audit_chain.py"),
            str(audit_log),
        ]
        verify_env = {**os.environ, "CLOUD_SECURITY_AUDIT_HMAC_KEY": hmac_key_hex}
        verify_proc = subprocess.run(
            verify_cmd,
            env=verify_env,
            capture_output=True,
            text=True,
            check=False,
        )
        audit_chain_verified = verify_proc.returncode == 0
        audit_chain_exit = verify_proc.returncode

        # Count chain records to confirm one per sample landed.
        audit_count = 0
        if audit_log.exists():
            for line in audit_log.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    audit_count += 1

    timings_summary = _summarize_timings(timings_ms)
    # `ping` + `tools/list` are auditless by design in mcp-server (only
    # `tools/call` writes an audit record). We still get one chain entry
    # from `bearer_key_rotated` at boot — so the chain assertion is
    # "exit 0 from verify_audit_chain AND >=1 record landed".
    status = "ok" if failures == 0 and audit_chain_verified and audit_count >= 1 else "fail"
    return {
        "runner": "mcp-sse",
        "scenario": scenario,
        "status": status,
        "samples": samples,
        "successful_requests": valid_payloads,
        "failed_requests": failures,
        "audit_records": audit_count,
        "audit_chain_verified": audit_chain_verified,
        "audit_chain_exit": audit_chain_exit,
        "audit_chain_status": ("ok_chain_verified_ping_and_tools_list_are_auditless_by_design"),
        "sink_arrival_count": valid_payloads,
        "sink_status": "ok_response_payload_shape_verified",
        "captured_at": _now_iso(),
        **timings_summary,
    }


# --------------------------------------------------------------------------- #
# AWS cloud-runner scenario (moto)                                             #
# --------------------------------------------------------------------------- #


def run_aws_cloud_runner_scenario(samples: int) -> dict[str, Any]:
    """Drive `runners/aws-s3-sqs-detect/src/ingest_handler.lambda_handler`
    against a moto-mocked S3 + SQS pair. The assertion is exact
    SQS-message arrival count per (samples × records-per-event)."""
    scenario = "s3-eventbridge-ingest"
    timings_ms: list[float] = []

    try:
        import boto3  # noqa: WPS433
        from moto import mock_aws  # noqa: WPS433
    except ImportError as exc:
        return {
            "runner": "cloud-runner-aws-s3-sqs",
            "scenario": scenario,
            "status": "gap",
            "error": f"boto3/moto not installed: {exc!r}",
            "samples": 0,
            "captured_at": _now_iso(),
        }

    fixture_path = REPO_ROOT / "skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl"
    if not fixture_path.is_file():
        return {
            "runner": "cloud-runner-aws-s3-sqs",
            "scenario": scenario,
            "status": "error",
            "error": f"fixture missing: {fixture_path}",
            "samples": 0,
            "captured_at": _now_iso(),
        }
    raw_lines = [
        line for line in fixture_path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if not raw_lines:
        return {
            "runner": "cloud-runner-aws-s3-sqs",
            "scenario": scenario,
            "status": "error",
            "error": f"fixture empty: {fixture_path}",
            "samples": 0,
            "captured_at": _now_iso(),
        }
    # One record per S3 object so the SQS arrival count is exactly samples.
    object_body = (raw_lines[0] + "\n").encode("utf-8")

    handler_path = REPO_ROOT / "runners" / "aws-s3-sqs-detect" / "src" / "ingest_handler.py"
    spec = importlib.util.spec_from_file_location("aws_ingest_handler_e2e", handler_path)
    assert spec is not None and spec.loader is not None
    handler_mod = importlib.util.module_from_spec(spec)
    sys.modules["aws_ingest_handler_e2e"] = handler_mod
    spec.loader.exec_module(handler_mod)

    bucket = "runner-e2e-bucket"
    successful = 0
    failures = 0
    sink_arrivals = 0

    skill_cmd = (
        f"{sys.executable} "
        f"{REPO_ROOT / 'skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py'} "
        "--output-format ocsf"
    )

    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        sqs = boto3.client("sqs", region_name="us-east-1")
        s3.create_bucket(Bucket=bucket)
        queue = sqs.create_queue(QueueName="runner-e2e-detect")
        queue_url = queue["QueueUrl"]

        prev_env = os.environ.copy()
        try:
            os.environ["INGEST_SKILL_CMD"] = skill_cmd
            os.environ["DETECT_QUEUE_URL"] = queue_url
            os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

            for i in range(samples):
                key = f"events/runner-e2e-{i:03d}.jsonl"
                s3.put_object(Bucket=bucket, Key=key, Body=object_body)
                event = {
                    "Records": [
                        {
                            "s3": {
                                "bucket": {"name": bucket},
                                "object": {"key": key},
                            }
                        }
                    ]
                }
                t0 = time.perf_counter()
                try:
                    handler_mod.lambda_handler(event, None)
                    dur_ms = (time.perf_counter() - t0) * 1000.0
                    timings_ms.append(dur_ms)
                    successful += 1
                except Exception:  # noqa: BLE001 - record as failure
                    failures += 1
                    continue

            # Count messages that arrived on the queue (drain in batches).
            for _ in range(samples * 2):  # safety upper bound
                resp = sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=0,
                )
                messages = resp.get("Messages") or []
                if not messages:
                    break
                sink_arrivals += len(messages)
                for msg in messages:
                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        finally:
            os.environ.clear()
            os.environ.update(prev_env)

    timings_summary = _summarize_timings(timings_ms)
    status = "ok" if failures == 0 and sink_arrivals == samples else "fail"
    return {
        "runner": "cloud-runner-aws-s3-sqs",
        "scenario": scenario,
        "status": status,
        "samples": samples,
        "successful_requests": successful,
        "failed_requests": failures,
        "audit_chain_verified": None,
        "audit_chain_status": "gap_aws_runner_audit_writes_via_cloudwatch_only",
        "sink_arrival_count": sink_arrivals,
        "sink_status": "ok_sqs_message_count_matches_samples",
        "captured_at": _now_iso(),
        **timings_summary,
    }


# --------------------------------------------------------------------------- #
# GCP / Azure cloud-runner scenarios (in-process SDK fakes)                    #
# --------------------------------------------------------------------------- #
#
# Neither cloud has an in-tree local equivalent of `moto`, and docker-based
# emulators are out of scope for this harness. Instead the real runner
# handlers run unmodified while the cloud SDK clients they construct are
# replaced with small in-memory fakes:
#
#   GCP    `_storage_client` / `_publisher_client` / `_firestore_client`
#          factories (the same seams the handler unit tests use)
#   Azure  `azure.identity`, `azure.storage.blob`, `azure.servicebus`,
#          `azure.data.tables`, and `azure.core.exceptions` modules, swapped
#          in `sys.modules` for the duration of the scenario so every line
#          of the handlers' SDK call sites still executes
#
# Every delivery runs a real ingest + detect skill subprocess against a
# golden raw fixture. The first delivery must publish exactly the golden
# findings; each later delivery is the same trigger redelivered
# (at-least-once semantics) and must be fully suppressed by the dedupe
# store. This proves handler wiring and dedupe logic locally. It is NOT a
# real-cloud deploy proof: IAM, triggers, packaging, and quotas are only
# exercised by a real deployment (issue #198).

_GOLDEN = REPO_ROOT / "skills" / "detection-engineering" / "golden"

_GCP_RAW_FIXTURE = _GOLDEN / "gcp_open_firewall_raw.json"
_GCP_EXPECTED_FINDINGS = _GOLDEN / "gcp_open_firewall_pipe_findings.ocsf.jsonl"
_GCP_INGEST_SKILL = REPO_ROOT / "skills/ingestion/ingest-gcp-audit-ocsf/src/ingest.py"
_GCP_DETECT_SKILL = REPO_ROOT / "skills/detection/detect-gcp-open-firewall/src/detect.py"

_AZURE_RAW_FIXTURE = _GOLDEN / "azure_open_nsg_raw.json"
_AZURE_EXPECTED_FINDINGS = _GOLDEN / "azure_open_nsg_pipe_findings.ocsf.jsonl"
_AZURE_INGEST_SKILL = REPO_ROOT / "skills/ingestion/ingest-azure-activity-ocsf/src/ingest.py"
_AZURE_DETECT_SKILL = REPO_ROOT / "skills/detection/detect-azure-open-nsg/src/detect.py"


def _load_runner_module(alias: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(alias, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


def _skill_cmd(script: Path) -> str:
    return shlex.join([sys.executable, str(script)])


def _jsonl_lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@contextlib.contextmanager
def _scoped_env(values: dict[str, str]) -> Iterator[None]:
    previous = os.environ.copy()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


@contextlib.contextmanager
def _scoped_modules(modules: dict[str, ModuleType]) -> Iterator[None]:
    missing = object()
    saved = {name: sys.modules.get(name, missing) for name in modules}
    sys.modules.update(modules)
    try:
        yield
    finally:
        for name, previous in saved.items():
            if previous is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous  # type: ignore[assignment]


def _dedupe_pipeline_record(
    *,
    runner: str,
    scenario: str,
    samples: int,
    deliver: Callable[[], tuple[int, int]],
    expected_findings: list[str],
    sink_messages: Callable[[], list[str]],
    dedupe_rows: Callable[[], int],
    audit_chain_status: str,
) -> dict[str, Any]:
    timings_ms: list[float] = []
    published = 0
    duplicates = 0
    failures = 0
    last_error = ""
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            new, dup = deliver()
        except Exception as exc:  # noqa: BLE001 - record as failure
            failures += 1
            last_error = f"{type(exc).__name__}: {exc}"
            continue
        timings_ms.append((time.perf_counter() - t0) * 1000.0)
        published += new
        duplicates += dup

    arrived = sink_messages()
    rows = dedupe_rows()
    expected = len(expected_findings)
    expected_duplicates = expected * (samples - 1)
    redelivery_ok = expected > 0 and duplicates == expected_duplicates
    if samples < 2:
        dedupe_status = "not_exercised_single_sample"
    elif redelivery_ok:
        dedupe_status = "ok_redelivery_suppressed"
    else:
        dedupe_status = "fail_redelivery_not_suppressed"

    ok = (
        failures == 0
        and expected > 0
        and sorted(arrived) == sorted(expected_findings)
        and published == expected
        and duplicates == expected_duplicates
        and rows == expected
    )
    record: dict[str, Any] = {
        "runner": runner,
        "scenario": scenario,
        "status": "ok" if ok else "fail",
        "backend": "in_process_fakes",
        "samples": samples,
        "successful_requests": samples - failures,
        "failed_requests": failures,
        "findings_published": published,
        "duplicates_suppressed": duplicates,
        "dedupe_rows": rows,
        "dedupe_status": dedupe_status,
        "audit_chain_verified": None,
        "audit_chain_status": audit_chain_status,
        "sink_arrival_count": len(arrived),
        "sink_status": (
            "ok_findings_match_golden_and_redelivery_deduped"
            if ok
            else "fail_findings_or_dedupe_mismatch"
        ),
        "captured_at": _now_iso(),
        **_summarize_timings(timings_ms),
    }
    if last_error:
        record["error"] = last_error
    return record


class _FakeCloudEvent:
    """Minimal stand-in for `cloudevents.http.CloudEvent` as delivered to a
    Cloud Functions 2nd gen handler: attributes by key, payload on `.data`."""

    def __init__(self, attributes: dict[str, Any], data: dict[str, Any]) -> None:
        self._attributes = attributes
        self.data = data

    def __getitem__(self, key: str) -> Any:
        return self._attributes[key]


class _FakeGcs:
    def __init__(self, objects: dict[tuple[str, str], str]) -> None:
        self.objects = objects
        self.downloads = 0

    def bucket(self, bucket_name: str) -> Any:
        gcs = self

        class _Blob:
            def __init__(self, name: str) -> None:
                self.name = name

            def download_as_text(self) -> str:
                gcs.downloads += 1
                return gcs.objects[(bucket_name, self.name)]

        class _Bucket:
            def blob(self, name: str) -> _Blob:
                return _Blob(name)

        return _Bucket()


class _FakePubSub:
    def __init__(self) -> None:
        self.messages: dict[str, list[bytes]] = {}

    def publish(self, topic: str, data: bytes) -> Any:
        if not isinstance(data, bytes):
            raise TypeError("Pub/Sub message data must be bytes")
        bucket = self.messages.setdefault(topic, [])
        bucket.append(data)
        message_id = str(len(bucket))

        class _Future:
            def result(self, timeout: float | None = None) -> str:
                return message_id

        return _Future()


class _FakeFirestore:
    def __init__(self, conflict: type[Exception]) -> None:
        self.conflict = conflict
        self.documents: dict[str, dict[str, dict[str, Any]]] = {}

    def collection(self, name: str) -> Any:
        store = self.documents.setdefault(name, {})
        conflict = self.conflict

        class _Document:
            def __init__(self, doc_id: str) -> None:
                self.doc_id = doc_id

            def create(self, item: dict[str, Any]) -> None:
                if self.doc_id in store:
                    raise conflict(f"409 document {self.doc_id} already exists")
                store[self.doc_id] = dict(item)

        class _Collection:
            def document(self, doc_id: str) -> _Document:
                return _Document(doc_id)

        return _Collection()


def run_gcp_cloud_runner_scenario(samples: int) -> dict[str, Any]:
    """Drive the GCP runner's real `handle_gcs_event` and
    `handle_pubsub_event` entrypoints with 2nd gen CloudEvents against
    in-memory GCS / Pub/Sub / Firestore fakes."""
    runner = "cloud-runner-gcp-gcs-pubsub"
    scenario = "gcs-finalize-ingest-detect-dedupe"
    src = REPO_ROOT / "runners" / "gcp-gcs-pubsub-detect" / "src"
    ingest_mod = _load_runner_module("gcp_ingest_handler_e2e", src / "ingest_handler.py")
    detect_mod = _load_runner_module("gcp_detect_handler_e2e", src / "detect_handler.py")

    project = "runner-e2e"
    bucket = "runner-e2e-raw"
    object_name = f"incoming/{_GCP_RAW_FIXTURE.name}"
    detect_topic = f"projects/{project}/topics/cloud-security-detect"
    findings_topic = f"projects/{project}/topics/cloud-security-findings"
    collection = "cloud-security-dedupe"
    raw = _GCP_RAW_FIXTURE.read_text(encoding="utf-8")

    gcs = _FakeGcs({(bucket, object_name): raw})
    pubsub = _FakePubSub()
    firestore = _FakeFirestore(detect_mod.Conflict)
    setattr(ingest_mod, "_storage_client", lambda: gcs)
    setattr(ingest_mod, "_publisher_client", lambda: pubsub)
    setattr(detect_mod, "_publisher_client", lambda: pubsub)
    setattr(detect_mod, "_firestore_client", lambda: firestore)

    finalized = _FakeCloudEvent(
        {
            "specversion": "1.0",
            "type": "google.cloud.storage.object.v1.finalized",
            "source": f"//storage.googleapis.com/projects/_/buckets/{bucket}",
            "subject": f"objects/{object_name}",
            "id": "runner-e2e-finalize-1",
        },
        {
            "kind": "storage#object",
            "bucket": bucket,
            "name": object_name,
            "generation": "1",
            "contentType": "application/json",
            "size": str(len(raw.encode("utf-8"))),
        },
    )

    def deliver() -> tuple[int, int]:
        queued = pubsub.messages.setdefault(detect_topic, [])
        before = len(queued)
        ingest_mod.handle_gcs_event(finalized)
        published = duplicates = 0
        for offset, payload in enumerate(queued[before:], start=before + 1):
            event = _FakeCloudEvent(
                {
                    "specversion": "1.0",
                    "type": "google.cloud.pubsub.topic.v1.messagePublished",
                    "source": f"//pubsub.googleapis.com/{detect_topic}",
                    "id": str(offset),
                },
                {
                    "message": {
                        "data": base64.b64encode(payload).decode("ascii"),
                        "messageId": str(offset),
                    },
                    "subscription": f"projects/{project}/subscriptions/cloud-security-detect",
                },
            )
            result = detect_mod.handle_pubsub_event(event)
            published += int(result["published"])
            duplicates += int(result["duplicates"])
        return published, duplicates

    env = {
        "INGEST_SKILL_CMD": _skill_cmd(_GCP_INGEST_SKILL),
        "DETECT_SKILL_CMD": _skill_cmd(_GCP_DETECT_SKILL),
        "DETECT_TOPIC": detect_topic,
        "FINDINGS_TOPIC": findings_topic,
        "DEDUPE_COLLECTION": collection,
    }
    with _scoped_env(env):
        record = _dedupe_pipeline_record(
            runner=runner,
            scenario=scenario,
            samples=samples,
            deliver=deliver,
            expected_findings=_jsonl_lines(_GCP_EXPECTED_FINDINGS),
            sink_messages=lambda: [
                m.decode("utf-8") for m in pubsub.messages.get(findings_topic, [])
            ],
            dedupe_rows=lambda: len(firestore.documents.get(collection, {})),
            audit_chain_status="gap_gcp_runner_audit_via_cloud_logging_only",
        )
    record["detect_queue_messages"] = len(pubsub.messages.get(detect_topic, []))
    return record


class _FakeAzure:
    """In-memory Blob Storage + Service Bus + Table Storage, exposed as
    stand-in `azure.*` SDK modules."""

    def __init__(self, blobs: dict[str, bytes]) -> None:
        self.blobs = blobs
        self.queues: dict[str, list[str]] = {}
        self.topics: dict[str, list[tuple[str, str | None]]] = {}
        self.tables: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}

    def modules(self) -> dict[str, ModuleType]:
        cloud = self

        class ResourceExistsError(Exception):
            pass

        class ResourceNotFoundError(Exception):
            pass

        class DefaultAzureCredential:
            pass

        class _Downloader:
            def __init__(self, body: bytes) -> None:
                self._body = body

            def readall(self) -> bytes:
                return self._body

        class BlobClient:
            def __init__(self, url: str) -> None:
                self.url = url

            @classmethod
            def from_blob_url(cls, blob_url: str, credential: Any = None) -> BlobClient:
                return cls(blob_url)

            def download_blob(self) -> _Downloader:
                if self.url not in cloud.blobs:
                    raise ResourceNotFoundError(self.url)
                return _Downloader(cloud.blobs[self.url])

        class ServiceBusMessage:
            def __init__(self, body: str, subject: str | None = None) -> None:
                self.body = body
                self.subject = subject

        class _Sender:
            def __init__(self, deliver: Callable[[ServiceBusMessage], None]) -> None:
                self._deliver = deliver

            def __enter__(self) -> _Sender:
                return self

            def __exit__(self, *exc: object) -> None:
                return None

            def send_messages(self, message: Any) -> None:
                batch = message if isinstance(message, list) else [message]
                for item in batch:
                    self._deliver(item)

        class ServiceBusClient:
            def __init__(self, fully_qualified_namespace: str, credential: Any) -> None:
                self.namespace = fully_qualified_namespace

            def __enter__(self) -> ServiceBusClient:
                return self

            def __exit__(self, *exc: object) -> None:
                return None

            def get_queue_sender(self, queue_name: str) -> _Sender:
                queue = cloud.queues.setdefault(queue_name, [])
                return _Sender(lambda msg: queue.append(str(msg.body)))

            def get_topic_sender(self, topic_name: str) -> _Sender:
                topic = cloud.topics.setdefault(topic_name, [])
                return _Sender(lambda msg: topic.append((str(msg.body), msg.subject)))

        class _TableClient:
            def __init__(self, name: str) -> None:
                self._rows = cloud.tables.setdefault(name, {})

            def create_table_if_not_exists(self) -> None:
                return None

            def create_entity(self, entity: dict[str, Any]) -> None:
                key = (entity["PartitionKey"], entity["RowKey"])
                if key in self._rows:
                    raise ResourceExistsError(str(key))
                self._rows[key] = dict(entity)

            def get_entity(self, partition_key: str, row_key: str) -> dict[str, Any]:
                try:
                    return self._rows[(partition_key, row_key)]
                except KeyError as exc:
                    raise ResourceNotFoundError(row_key) from exc

            def delete_entity(self, partition_key: str, row_key: str) -> None:
                self._rows.pop((partition_key, row_key), None)

        class TableServiceClient:
            def __init__(self, endpoint: str, credential: Any) -> None:
                self.endpoint = endpoint

            def get_table_client(self, table_name: str) -> _TableClient:
                return _TableClient(table_name)

        def _module(name: str, **attrs: Any) -> ModuleType:
            module = ModuleType(name)
            for key, value in attrs.items():
                setattr(module, key, value)
            return module

        return {
            "azure.core.exceptions": _module(
                "azure.core.exceptions",
                ResourceExistsError=ResourceExistsError,
                ResourceNotFoundError=ResourceNotFoundError,
            ),
            "azure.identity": _module(
                "azure.identity", DefaultAzureCredential=DefaultAzureCredential
            ),
            "azure.storage.blob": _module("azure.storage.blob", BlobClient=BlobClient),
            "azure.servicebus": _module(
                "azure.servicebus",
                ServiceBusClient=ServiceBusClient,
                ServiceBusMessage=ServiceBusMessage,
            ),
            "azure.data.tables": _module(
                "azure.data.tables", TableServiceClient=TableServiceClient
            ),
        }


def run_azure_cloud_runner_scenario(samples: int) -> dict[str, Any]:
    """Drive the Azure runner's real `handle_ingest_messages` and
    `handle_detect_messages` entrypoints with an Event Grid BlobCreated
    event (EventGridSchema, as routed to the Service Bus queue by
    `template.bicep`) against in-memory Azure SDK fakes."""
    runner = "cloud-runner-azure-blob-eventgrid"
    scenario = "blob-eventgrid-ingest-detect-dedupe"
    src = REPO_ROOT / "runners" / "azure-blob-eventgrid-detect" / "src"
    ingest_mod = _load_runner_module("azure_ingest_handler_e2e", src / "ingest_handler.py")
    detect_mod = _load_runner_module("azure_detect_handler_e2e", src / "detect_handler.py")

    account = "runnere2e"
    container = "raw"
    blob_name = f"incoming/{_AZURE_RAW_FIXTURE.name}"
    blob_url = f"https://{account}.blob.core.windows.net/{container}/{blob_name}"
    detect_queue = "cloud-security-detect"
    alert_topic = "cloud-security-findings"
    dedupe_table = "cloudsecuritydedupe"
    raw = _AZURE_RAW_FIXTURE.read_bytes()
    cloud = _FakeAzure({blob_url: raw})

    blob_created = {
        "topic": (
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            f"runner-e2e/providers/Microsoft.Storage/storageAccounts/{account}"
        ),
        "subject": f"/blobServices/default/containers/{container}/blobs/{blob_name}",
        "eventType": "Microsoft.Storage.BlobCreated",
        "id": "runner-e2e-blob-created-1",
        "eventTime": "2026-01-01T00:00:00Z",
        "dataVersion": "",
        "metadataVersion": "1",
        "data": {
            "api": "PutBlob",
            "contentType": "application/json",
            "contentLength": len(raw),
            "blobType": "BlockBlob",
            "url": blob_url,
        },
    }
    queue_body = json.dumps(blob_created)

    def deliver() -> tuple[int, int]:
        queued = cloud.queues.setdefault(detect_queue, [])
        before = len(queued)
        ingest_mod.handle_ingest_messages([queue_body])
        result = detect_mod.handle_detect_messages(list(queued[before:]))
        return int(result["published"]), int(result["duplicates"])

    env = {
        "INGEST_SKILL_CMD": _skill_cmd(_AZURE_INGEST_SKILL),
        "DETECT_SKILL_CMD": _skill_cmd(_AZURE_DETECT_SKILL),
        "SERVICE_BUS_FQDN": f"{account}.servicebus.windows.net",
        "DETECT_QUEUE_NAME": detect_queue,
        "ALERT_TOPIC_NAME": alert_topic,
        "DEDUPE_TABLE_NAME": dedupe_table,
        "TABLE_ACCOUNT_URL": f"https://{account}.table.core.windows.net",
    }
    with _scoped_env(env), _scoped_modules(cloud.modules()):
        record = _dedupe_pipeline_record(
            runner=runner,
            scenario=scenario,
            samples=samples,
            deliver=deliver,
            expected_findings=_jsonl_lines(_AZURE_EXPECTED_FINDINGS),
            sink_messages=lambda: [body for body, _subject in cloud.topics.get(alert_topic, [])],
            dedupe_rows=lambda: len(cloud.tables.get(dedupe_table, {})),
            audit_chain_status="gap_azure_runner_audit_via_platform_logging_only",
        )
    record["detect_queue_messages"] = len(cloud.queues.get(detect_queue, []))
    return record


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    global RESULTS_PATH  # noqa: PLW0603 - module-level mutable target shared with _append_result
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--samples",
        type=int,
        default=DEFAULT_SAMPLES,
        help="Iterations per (runner, scenario). Default %(default)s.",
    )
    parser.add_argument(
        "--results-path",
        type=Path,
        default=RESULTS_PATH,
        help="JSONL output file (one record per scenario).",
    )
    parser.add_argument(
        "--only",
        choices=("webhook", "sse", "aws", "gcp", "azure", "all"),
        default="all",
        help="Run a subset of scenarios.",
    )
    args = parser.parse_args(argv)
    samples = max(1, int(args.samples))

    RESULTS_PATH = args.results_path

    # Truncate prior results so each invocation owns its file.
    if RESULTS_PATH.exists():
        RESULTS_PATH.unlink()

    scenarios: list[Callable[[], dict[str, Any]]] = []
    if args.only in ("webhook", "all"):
        scenarios.append(lambda: run_webhook_scenario(samples))
    if args.only in ("sse", "all"):
        scenarios.append(lambda: run_mcp_sse_scenario(samples))
    if args.only in ("aws", "all"):
        scenarios.append(lambda: run_aws_cloud_runner_scenario(samples))
    if args.only in ("gcp", "all"):
        scenarios.append(lambda: run_gcp_cloud_runner_scenario(samples))
    if args.only in ("azure", "all"):
        scenarios.append(lambda: run_azure_cloud_runner_scenario(samples))

    overall_failure = False
    for run in scenarios:
        try:
            record = run()
        except Exception as exc:  # noqa: BLE001 - one failed scenario must not hide others
            record = {
                "runner": "harness",
                "scenario": "unknown",
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "captured_at": _now_iso(),
            }
        _append_result(record)
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        if record.get("status") not in ("ok", "gap"):
            overall_failure = True

    return 1 if overall_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
