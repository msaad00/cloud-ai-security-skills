"""LangGraph — one graph node per skill layer with an explicit HITL gate node.

Shows the layered flow from `CLAUDE.md`:

    ingest  →  detect  →  evaluate  →  HITL gate  →  remediate  →  audit

Each node is a thin wrapper around the corresponding skill-layer MCP tool
invocation. The graph's state carries `caller_context`, current findings,
and (after the HITL node) an `approval_context`. The `remediate` node
refuses to run if `approval_context` is absent.

This is a reference implementation. The LangGraph SDK is not pinned as a
repo dep; real code would `from langgraph.graph import StateGraph` and
build the graph with the nodes below. The module is runnable without
LangGraph installed — it emits a deterministic dry-run trace.

Run:

    python examples/agents/langgraph_security_graph.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, TypedDict

REPO_ROOT = Path(__file__).resolve().parents[2]

ALLOWED_SKILLS_READ_ONLY = ",".join([
    "ingest-cloudtrail-ocsf",
    "detect-lateral-movement",
    "cspm-aws-cis-benchmark",
    "convert-ocsf-to-sarif",
])
ALLOWED_SKILLS_REMEDIATION = "iam-departures-aws"


class GraphState(TypedDict, total=False):
    caller_context: dict[str, str]
    raw_events: list[dict[str, Any]]
    ocsf_events: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    evaluation_results: list[dict[str, Any]]
    approval_context: dict[str, str] | None
    remediation_result: dict[str, Any]


# ----- Nodes -------------------------------------------------------------------

def ingest_node(state: GraphState) -> GraphState:
    """L1 Ingest — normalize raw events into OCSF 1.8."""
    sys.stderr.write(json.dumps({"node": "ingest", "allowlist": ALLOWED_SKILLS_READ_ONLY}) + "\n")
    state["ocsf_events"] = [{"class_uid": 6003, "activity_id": 1, "metadata": {"uid": "graph-demo-1"}}]
    return state


def detect_node(state: GraphState) -> GraphState:
    """L3 Detect — deterministic rules, OCSF 2004 out."""
    sys.stderr.write(json.dumps({"node": "detect"}) + "\n")
    state["findings"] = [{"finding_info": {"uid": "det-graph-1", "title": "Demo finding"}}]
    return state


def evaluate_node(state: GraphState) -> GraphState:
    """L4 Evaluate — posture checks, compliance result."""
    sys.stderr.write(json.dumps({"node": "evaluate"}) + "\n")
    state["evaluation_results"] = [{"control_id": "CIS-1.4", "status": "fail"}]
    return state


def hitl_gate_node(state: GraphState) -> GraphState:
    """Hard pause. No auto-approve. Must get `approval_context` from operator."""
    sys.stderr.write(json.dumps({"node": "hitl_gate", "waiting_for": "operator_approval"}) + "\n")
    if os.environ.get("DEMO_APPROVE") == "yes":
        state["approval_context"] = {
            "approver_id": os.environ.get("DEMO_APPROVER", "operator@example.com"),
            "ticket_id": os.environ.get("DEMO_TICKET", "SEC-GRAPH-1"),
            "approval_timestamp": "2026-04-18T12:00:00Z",
        }
    else:
        state["approval_context"] = None
    return state


def remediate_node(state: GraphState) -> GraphState:
    """L5 Remediate — refuses without approval_context."""
    approval = state.get("approval_context")
    if not approval:
        sys.stderr.write(json.dumps({
            "node": "remediate",
            "status": "skipped",
            "reason": "no approval_context — HITL gate was not passed",
        }) + "\n")
        state["remediation_result"] = {"status": "skipped"}
        return state
    sys.stderr.write(json.dumps({
        "node": "remediate",
        "status": "dry_run",
        "allowlist": ALLOWED_SKILLS_REMEDIATION,
        "approval": approval,
    }) + "\n")
    state["remediation_result"] = {
        "status": "dry_run",
        "planned_actions": ["deactivate_access_keys", "delete_user"],
        "approval": approval,
    }
    return state


# ----- Graph assembly (real code would use langgraph.graph.StateGraph) ---------

def run_graph(initial: GraphState) -> GraphState:
    """Deterministic linear execution. Real LangGraph would add branching +
    retry + checkpointing."""
    state: GraphState = dict(initial)  # copy
    for node in (ingest_node, detect_node, evaluate_node, hitl_gate_node, remediate_node):
        state = node(state)
    return state


def main() -> int:
    initial: GraphState = {
        "caller_context": {
            "user_id": "graph-demo-operator",
            "email": "graph-demo@example.com",
            "session_id": "graph-demo-1",
            "roles": "security_engineer",
        },
        "raw_events": [{"source": "demo"}],
    }
    final = run_graph(initial)
    # Strip deeply-nested state for a readable summary
    summary = {
        "caller_context": final.get("caller_context"),
        "findings_count": len(final.get("findings") or []),
        "evaluation_failures": sum(1 for e in final.get("evaluation_results") or [] if e["status"] == "fail"),
        "remediation": final.get("remediation_result"),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
