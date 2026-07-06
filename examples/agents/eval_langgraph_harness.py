"""Offline eval runner for the LangGraph agent harness example.

This is intentionally not an LLM-as-judge. It replays golden cases through the
same deterministic graph and checks bounded agent outputs, HITL routing, model
metadata, idempotency, and profile allowlist behavior.

Run:

    python examples/agents/eval_langgraph_harness.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from langgraph_security_graph import load_harness_profile, run_graph, summarize

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = Path(__file__).with_name("evals") / "langgraph_triage_golden.json"
ENV_KEYS = [
    "DEMO_APPROVE",
    "DEMO_APPROVER",
    "DEMO_TICKET",
    "DEMO_EXTERNAL_LLM_ALLOWED",
    "DEMO_LLM_PROVIDER",
    "DEMO_LLM_MODEL",
    "DEMO_LLM_ADAPTER_FIXTURE",
    "DEMO_OPENAI_BASE_URL",
    "DEMO_OPENAI_API_KEY_ENV",
    "DEMO_OPENAI_TIMEOUT_SECONDS",
]
# Model-quality mode keeps the operator's adapter env (fixture or live
# OpenAI-compatible endpoint) so the run measures that adapter; it still
# strips approval context so no case can auto-approve.
MODEL_QUALITY_STRIPPED_ENV_KEYS = ["DEMO_APPROVE", "DEMO_APPROVER", "DEMO_TICKET"]


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else REPO_ROOT / path


def _without_case_env() -> dict[str, str | None]:
    saved = {key: os.environ.get(key) for key in ENV_KEYS}
    for key in saved:
        os.environ.pop(key, None)
    return saved


def _restore_env(saved: dict[str, str | None]) -> None:
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _first_recommendation(summary: dict[str, Any]) -> dict[str, Any]:
    recommendations = summary.get("agent_recommendations") or []
    if not recommendations:
        return {}
    return recommendations[0]


def _triage_agent(summary: dict[str, Any]) -> dict[str, Any]:
    for agent in summary.get("agents") or []:
        if agent.get("agent_id") == "triage-agent":
            return agent
    return {}


def _first_finding_uid(case: dict[str, Any]) -> str:
    raw_events = case.get("raw_events") or [{"source": "demo"}]
    return f"det-evt-{_stable_hash(raw_events[0])[:12]}"


def _replace_placeholders(payload: Any, replacements: dict[str, str]) -> Any:
    if isinstance(payload, str):
        rendered = payload
        for key, value in replacements.items():
            rendered = rendered.replace(f"{{{{{key}}}}}", value)
        return rendered
    if isinstance(payload, list):
        return [_replace_placeholders(item, replacements) for item in payload]
    if isinstance(payload, dict):
        return {key: _replace_placeholders(value, replacements) for key, value in payload.items()}
    return payload


def _write_adapter_fixture(case: dict[str, Any]) -> Path | None:
    fixture = case.get("llm_adapter_fixture")
    if not fixture:
        return None
    rendered = _replace_placeholders(fixture, {"finding_uid": _first_finding_uid(case)})
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False)
    with handle:
        json.dump(rendered, handle, sort_keys=True)
    return Path(handle.name)


def _check(name: str, actual: Any, expected: Any) -> dict[str, Any]:
    return {
        "name": name,
        "actual": actual,
        "expected": expected,
        "passed": actual == expected,
    }


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    saved_env = _without_case_env()
    fixture_path = _write_adapter_fixture(case)
    try:
        for key, value in (case.get("env") or {}).items():
            os.environ[key] = str(value)
        if fixture_path:
            os.environ["DEMO_LLM_ADAPTER_FIXTURE"] = str(fixture_path)
        profile = load_harness_profile(str(_resolve(case["profile"])))
        initial = {
            "harness_profile": profile,
            "caller_context": profile["caller_context"],
            "raw_events": case.get("raw_events") or [{"source": "demo"}],
        }
        summary = summarize(run_graph(initial))
    finally:
        if fixture_path:
            fixture_path.unlink(missing_ok=True)
        _restore_env(saved_env)

    expected = case["expected"]
    recommendation = _first_recommendation(summary)
    triage_agent = _triage_agent(summary)
    checks = [
        _check("profile_id", summary["profile"]["profile_id"], expected["profile_id"]),
        _check("harness_mode", summary["harness"]["mode"], expected["harness_mode"]),
        _check(
            "recommendation_action",
            recommendation.get("recommended_action"),
            expected["recommendation_action"],
        ),
        _check(
            "recommendation_priority",
            recommendation.get("priority"),
            expected["recommendation_priority"],
        ),
        _check("review_status", summary["review"]["status"], expected["review_status"]),
        _check(
            "remediation_status", summary["remediation"]["status"], expected["remediation_status"]
        ),
        _check(
            "route_after_review",
            summary["audit"]["route"]["after_review"],
            expected["route_after_review"],
        ),
        _check(
            "planned_steps_absent",
            "planned_steps" not in summary["remediation"],
            expected["planned_steps_absent"],
        ),
    ]
    token_usage = summary.get("token_budget_usage") or {}
    token_budget = (summary.get("harness") or {}).get("token_budget") or {}
    model_policy = (summary.get("harness") or {}).get("model_policy") or {}
    agents = {agent.get("agent_id"): agent for agent in summary.get("agents") or []}
    remediation_agent = agents.get("remediation-planner") or {}
    agent_policy = summary.get("agent_policy") or {}
    policy_entries = {entry.get("agent_id"): entry for entry in agent_policy.get("entries") or []}
    triage_policy = policy_entries.get("triage-agent") or {}
    remediation_policy = policy_entries.get("remediation-planner") or {}
    checks.extend(
        [
            _check(
                "token_budget_status_present",
                token_usage.get("status") in {"within_budget", "fallback"},
                True,
            ),
            _check(
                "token_budget_input_within_limit_or_fallback",
                token_usage.get("compact_input_tokens_estimate", 0)
                <= token_budget.get("max_input_tokens", 0)
                or token_usage.get("status") == "fallback",
                True,
            ),
            _check(
                "token_budget_evidence_within_limit_or_fallback",
                token_usage.get("compact_evidence_chars", 0)
                <= token_budget.get("max_evidence_chars", 0)
                or token_usage.get("status") == "fallback",
                True,
            ),
            _check(
                "token_budget_model_tier_bounded",
                token_budget.get("model_tier") in {"tiny", "small"},
                True,
            ),
            _check(
                "model_policy_selected_tier_matches_budget",
                model_policy.get("selected_model_tier") == token_budget.get("model_tier"),
                True,
            ),
            _check(
                "model_policy_selection_source_recorded",
                model_policy.get("selection_source") in {"profile_model_policy", "env_override"},
                True,
            ),
            _check(
                "llm_evidence_cards_compact",
                all(
                    "raw_events" not in card and "ocsf_events" not in card
                    for card in summary.get("llm_evidence_cards") or []
                ),
                True,
            ),
            _check(
                "triage_agent_no_write_privilege",
                triage_agent.get("privilege_boundary"),
                "no_tool_writes",
            ),
            _check("triage_agent_no_skill_scope", triage_agent.get("skill_scope"), []),
            _check(
                "triage_agent_model_tier_allowed",
                triage_agent.get("model_tier")
                in set(model_policy.get("allowed_model_tiers") or []),
                True,
            ),
            _check(
                "remediation_agent_requires_hitl",
                remediation_agent.get("requires_human_approval"),
                True,
            ),
            _check(
                "remediation_agent_dry_run_boundary",
                remediation_agent.get("privilege_boundary"),
                "dry_run_write_planning",
            ),
            _check(
                "agent_policy_schema_version",
                agent_policy.get("schema_version"),
                "langgraph-agent-policy-v1",
            ),
            _check("agent_policy_hash_present", bool(agent_policy.get("policy_hash")), True),
            _check(
                "triage_policy_grants_no_skills", triage_policy.get("effective_skill_grants"), []
            ),
            _check(
                "triage_policy_decision_no_direct_tools",
                triage_policy.get("decision"),
                "no_direct_tools",
            ),
            _check(
                "remediation_policy_write_boundary",
                remediation_policy.get("write_policy"),
                "dry_run_only_after_hitl",
            ),
        ]
    )

    if "recommendation_generated_by" in expected:
        checks.append(
            _check(
                "recommendation_generated_by",
                recommendation.get("generated_by"),
                expected["recommendation_generated_by"],
            )
        )

    if "llm_validation_status" in expected:
        validation = (summary.get("llm_validation") or [{}])[0]
        checks.append(
            _check(
                "llm_validation_status",
                validation.get("status"),
                expected["llm_validation_status"],
            )
        )
        checks.append(
            _check(
                "llm_validation_reason",
                validation.get("reason"),
                expected["llm_validation_reason"],
            )
        )

    if "llm_adapter_accepted" in expected:
        checks.append(
            _check(
                "llm_adapter_accepted",
                summary["audit"]["llm_adapter_accepted"],
                expected["llm_adapter_accepted"],
            )
        )
        checks.append(
            _check(
                "llm_adapter_rejected",
                summary["audit"]["llm_adapter_rejected"],
                expected["llm_adapter_rejected"],
            )
        )

    for key in expected.get("integrity_keys_present", []):
        checks.append(
            _check(
                f"integrity_key_present:{key}",
                bool((summary.get("integrity") or {}).get(key)),
                True,
            )
        )

    for key in expected.get("idempotency_keys_present", []):
        checks.append(
            _check(
                f"idempotency_key_present:{key}",
                bool((summary.get("idempotency") or {}).get(key)),
                True,
            )
        )

    if "idempotency_duplicate_write_suppressed" in expected:
        checks.append(
            _check(
                "idempotency_duplicate_write_suppressed",
                (summary.get("idempotency") or {}).get("duplicate_write_suppressed"),
                expected["idempotency_duplicate_write_suppressed"],
            )
        )

    if "remediation_dry_run" in expected:
        checks.append(
            _check(
                "remediation_dry_run",
                summary["remediation"].get("dry_run"),
                expected["remediation_dry_run"],
            )
        )

    if expected.get("remediation_key_matches_idempotency"):
        checks.append(
            _check(
                "remediation_key_matches_idempotency",
                summary["remediation"].get("idempotency_key"),
                (summary.get("idempotency") or {}).get("remediation_key"),
            )
        )

    if expected.get("audit_key_matches_remediation"):
        checks.append(
            _check(
                "audit_key_matches_remediation",
                summary["audit"].get("idempotency_key"),
                summary["remediation"].get("idempotency_key"),
            )
        )

    if "route_after_remediation" in expected:
        checks.append(
            _check(
                "route_after_remediation",
                summary["audit"]["route"]["after_remediation"],
                expected["route_after_remediation"],
            )
        )

    if "eval_status" in expected:
        checks.append(
            _check(
                "eval_status",
                summary["eval"]["status"],
                expected["eval_status"],
            )
        )

    if "audit_api_error_count" in expected:
        checks.append(
            _check(
                "audit_api_error_count",
                summary["audit"]["api_error_count"],
                expected["audit_api_error_count"],
            )
        )
        checks.append(
            _check(
                "audit_retryable_api_error_count",
                summary["audit"]["retryable_api_error_count"],
                expected.get("audit_retryable_api_error_count", 0),
            )
        )

    if "api_error_classification" in expected:
        api_error = (summary.get("api_errors") or [{}])[0]
        checks.append(
            _check(
                "api_error_classification",
                api_error.get("classification"),
                expected["api_error_classification"],
            )
        )
        checks.append(
            _check(
                "api_error_status_code",
                api_error.get("status_code"),
                expected["api_error_status_code"],
            )
        )

    if "retry_status" in expected:
        checks.append(
            _check(
                "retry_status",
                (summary.get("retry") or {}).get("status"),
                expected["retry_status"],
            )
        )
        checks.append(
            _check(
                "retry_policy",
                (summary.get("retry") or {}).get("policy"),
                expected["retry_policy"],
            )
        )

    if expected.get("retry_key_matches_remediation"):
        checks.append(
            _check(
                "retry_key_matches_remediation",
                (summary.get("retry") or {}).get("idempotency_key"),
                summary["remediation"].get("idempotency_key"),
            )
        )

    if "escalation_status" in expected:
        checks.append(
            _check(
                "escalation_status",
                (summary.get("escalation") or {}).get("status"),
                expected["escalation_status"],
            )
        )
        checks.append(
            _check(
                "escalation_reason",
                (summary.get("escalation") or {}).get("reason"),
                expected["escalation_reason"],
            )
        )

    for skill in expected.get("effective_allowed_includes", []):
        checks.append(
            _check(
                f"effective_allowed_includes:{skill}",
                skill in summary["effective_allowed_skills"],
                True,
            )
        )

    for skill in expected.get("effective_allowed_excludes", []):
        checks.append(
            _check(
                f"effective_allowed_excludes:{skill}",
                skill not in summary["effective_allowed_skills"],
                True,
            )
        )

    for field in expected.get("triage_forbidden_outputs", []):
        checks.append(
            _check(
                f"triage_forbidden_output:{field}",
                field in triage_agent.get("forbidden_outputs", []),
                True,
            )
        )

    passed = all(check["passed"] for check in checks)
    return {
        "case_id": case["case_id"],
        "status": "pass" if passed else "fail",
        "output_hash": _stable_hash(
            {
                "profile": summary["profile"]["profile_id"],
                "recommendation": recommendation,
                "review": summary["review"],
                "remediation": summary["remediation"],
                "route": summary["audit"]["route"],
                "effective_allowed_skills": summary["effective_allowed_skills"],
                "llm_validation": summary.get("llm_validation"),
                "integrity": summary.get("integrity"),
                "idempotency": summary.get("idempotency"),
                "api_errors": summary.get("api_errors"),
                "retry": summary.get("retry"),
                "escalation": summary.get("escalation"),
                "token_budget_usage": summary.get("token_budget_usage"),
            }
        )[:16],
        "checks": checks,
    }


def run_dataset(dataset_path: Path) -> dict[str, Any]:
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    results = [run_case(case) for case in dataset["cases"]]
    passed = sum(1 for result in results if result["status"] == "pass")
    total = len(results)
    return {
        "event": "langgraph_agent_harness_eval",
        "dataset_version": dataset["dataset_version"],
        "dataset_hash": _stable_hash(dataset)[:16],
        "cases_total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": passed / total if total else 0.0,
        "model_policy": "llm_may_rank_summarize_draft_only",
        "results": results,
    }


def _first_validation(summary: dict[str, Any]) -> dict[str, Any]:
    records = summary.get("llm_validation") or []
    if not records:
        return {}
    return records[0]


def _operator_adapter_configured() -> bool:
    return any(
        os.environ.get(key)
        for key in (
            "DEMO_LLM_ADAPTER_FIXTURE",
            "DEMO_LANGCHAIN_ADAPTER_FIXTURE",
            "DEMO_OPENAI_BASE_URL",
        )
    )


def run_model_quality_case(case: dict[str, Any], *, operator_adapter: bool) -> dict[str, Any]:
    """Replay one golden case and score adapter agreement with the golden triage.

    Unlike ``run_case`` this keeps the operator's DEMO_LLM_* / DEMO_OPENAI_*
    env so the fixture or live OpenAI-compatible adapter under test actually
    runs. When no operator adapter is configured, case-declared fixtures
    apply, matching the regression behavior. Approval env is always stripped.
    """
    saved_env = {key: os.environ.get(key) for key in MODEL_QUALITY_STRIPPED_ENV_KEYS}
    for key in saved_env:
        os.environ.pop(key, None)
    fixture_path = None if operator_adapter else _write_adapter_fixture(case)
    case_env = {
        key: str(value)
        for key, value in (case.get("env") or {}).items()
        if key not in MODEL_QUALITY_STRIPPED_ENV_KEYS and not (operator_adapter and key in ENV_KEYS)
    }
    saved_env.update({key: os.environ.get(key) for key in case_env})
    if fixture_path:
        saved_env.setdefault("DEMO_LLM_ADAPTER_FIXTURE", os.environ.get("DEMO_LLM_ADAPTER_FIXTURE"))
    try:
        os.environ.update(case_env)
        if fixture_path:
            os.environ["DEMO_LLM_ADAPTER_FIXTURE"] = str(fixture_path)
        profile = load_harness_profile(str(_resolve(case["profile"])))
        initial = {
            "harness_profile": profile,
            "caller_context": profile["caller_context"],
            "raw_events": case.get("raw_events") or [{"source": "demo"}],
        }
        summary = summarize(run_graph(initial))
    finally:
        if fixture_path:
            fixture_path.unlink(missing_ok=True)
        _restore_env(saved_env)

    expected = case["expected"]
    recommendation = _first_recommendation(summary)
    validation = _first_validation(summary)
    priority_agrees = recommendation.get("priority") == expected["recommendation_priority"]
    action_agrees = recommendation.get("recommended_action") == expected["recommendation_action"]
    return {
        "case_id": case["case_id"],
        "adapter": validation.get("adapter", "deterministic_fallback"),
        "adapter_status": validation.get("status", "fallback"),
        "adapter_reason": validation.get("reason"),
        "generated_by": recommendation.get("generated_by"),
        "expected_priority": expected["recommendation_priority"],
        "actual_priority": recommendation.get("priority"),
        "expected_action": expected["recommendation_action"],
        "actual_action": recommendation.get("recommended_action"),
        "priority_agrees": priority_agrees,
        "action_agrees": action_agrees,
        "agreement": priority_agrees and action_agrees,
    }


def run_model_quality(dataset_path: Path) -> dict[str, Any]:
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    operator_adapter = _operator_adapter_configured()
    results = [
        run_model_quality_case(case, operator_adapter=operator_adapter) for case in dataset["cases"]
    ]
    total = len(results)
    agreements = sum(1 for result in results if result["agreement"])
    status_counts = {"accepted": 0, "rejected": 0, "fallback": 0}
    for result in results:
        status = result["adapter_status"]
        if status in status_counts:
            status_counts[status] += 1
    return {
        "event": "langgraph_model_quality_eval",
        "dataset_version": dataset["dataset_version"],
        "dataset_hash": _stable_hash(dataset)[:16],
        "adapter_env": {
            "fixture": bool(os.environ.get("DEMO_LLM_ADAPTER_FIXTURE")),
            "langchain_fixture": bool(os.environ.get("DEMO_LANGCHAIN_ADAPTER_FIXTURE")),
            "live_openai_compat": bool(os.environ.get("DEMO_OPENAI_BASE_URL")),
        },
        "cases_total": total,
        "adapter_accepted": status_counts["accepted"],
        "adapter_rejected": status_counts["rejected"],
        "adapter_fallback": status_counts["fallback"],
        "agreement": agreements,
        "agreement_rate": agreements / total if total else 0.0,
        "model_policy": "llm_may_rank_summarize_draft_only",
        "results": results,
    }


def _encoded_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def _write_json(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _append_history(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    recorded_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    record = {
        "recorded_at": recorded_at,
        "report_hash": _stable_hash(report)[:16],
        **report,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--min-pass-rate", type=float, default=1.0)
    parser.add_argument(
        "--check", action="store_true", help="exit nonzero when pass rate is below threshold"
    )
    parser.add_argument(
        "--model-quality",
        action="store_true",
        help=(
            "score the configured triage adapter (fixture or live "
            "OpenAI-compatible endpoint) against the golden priorities and "
            "actions instead of running the harness regression checks"
        ),
    )
    parser.add_argument(
        "--min-agreement",
        type=float,
        default=1.0,
        help="minimum agreement rate for --model-quality --check",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the JSON eval report to this path",
    )
    parser.add_argument(
        "--append-jsonl",
        type=Path,
        help="append a timestamped eval report row to this JSONL history",
    )
    args = parser.parse_args()

    if args.model_quality:
        report = run_model_quality(args.dataset)
        gate = report["agreement_rate"] >= args.min_agreement
    else:
        report = run_dataset(args.dataset)
        gate = report["pass_rate"] >= args.min_pass_rate
    encoded = _encoded_report(report)
    print(encoded, end="")
    if args.output:
        _write_json(args.output, encoded)
    if args.append_jsonl:
        _append_history(args.append_jsonl, report)
    if args.check and not gate:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
