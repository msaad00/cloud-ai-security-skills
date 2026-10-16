"""Tests for convert-ocsf-to-mermaid-attack-flow."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from convert import (  # type: ignore[import-not-found]
    extract_actor,
    extract_attack,
    extract_target,
    load_jsonl,
    main,
    mermaid_label,
    render,
    severity_class,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT_FIXTURE = GOLDEN / "k8s_priv_esc_findings.ocsf.jsonl"
EXPECTED = GOLDEN / "k8s_priv_esc_attack_flow.mmd"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _finding(
    *,
    uid: str = "det-test-1",
    severity_id: int = 4,
    technique_uid: str = "T1611",
    technique_name: str = "Escape to Host",
    actor: str = "system:serviceaccount:default:builder",
    observables: list[dict] | None = None,
    detector: str = "detect-test",
) -> dict:
    return {
        "class_uid": 2004,
        "category_uid": 2,
        "type_uid": 200401,
        "severity_id": severity_id,
        "status_id": 1,
        "time": 1775797200000,
        "metadata": {
            "version": "1.8.0",
            "product": {
                "name": "cloud-ai-security-skills",
                "feature": {"name": detector},
            },
        },
        "finding_info": {
            "uid": uid,
            "title": "Test",
            "desc": "Test desc",
            "attacks": [
                {
                    "version": "v14",
                    "tactic": {"name": "Privilege Escalation", "uid": "TA0004"},
                    "technique": {"name": technique_name, "uid": technique_uid},
                }
            ],
        },
        "observables": observables
        or [
            {"name": "actor.name", "type": "Other", "value": actor},
            {"name": "pod.name", "type": "Other", "value": "test-pod"},
            {"name": "namespace", "type": "Other", "value": "default"},
        ],
    }


# ── Severity → CSS class ──────────────────────────────────────────────


class TestSeverityClass:
    def test_critical(self):
        assert severity_class(5) == "critical"
        assert severity_class(6) == "critical"

    def test_high(self):
        assert severity_class(4) == "high"

    def test_medium(self):
        assert severity_class(3) == "medium"

    def test_low(self):
        for s in (0, 1, 2):
            assert severity_class(s) == "low"

    def test_unmapped_falls_to_low(self):
        assert severity_class(99) == "low"


# ── Literal labels ────────────────────────────────────────────────────


class TestMermaidLabel:
    def test_ordinary_text_is_preserved(self):
        assert (
            mermaid_label("system:serviceaccount:default:builder")
            == "system:serviceaccount:default:builder"
        )

    def test_controls_are_not_structural_newlines(self):
        assert mermaid_label("a\n\r\tb\x00") == "a   b "


# ── extract_actor / extract_target / extract_attack ──────────────────


class TestExtractors:
    def test_extract_actor_from_observables(self):
        f = _finding()
        assert extract_actor(f) == "system:serviceaccount:default:builder"

    def test_extract_actor_falls_back_to_session_uid(self):
        f = _finding(observables=[{"name": "session.uid", "type": "Other", "value": "sess-123"}])
        assert extract_actor(f) == "sess-123"

    def test_extract_actor_is_unknown_without_identity(self):
        # Scope alone does not identify an actor.
        f = _finding(observables=[{"name": "namespace", "type": "Other", "value": "default"}])
        assert extract_actor(f) == "Unknown actor"

    def test_extract_target_secret(self):
        f = _finding(
            observables=[
                {"name": "actor.name", "value": "alice"},
                {"name": "secret.name", "value": "db-password"},
                {"name": "namespace", "value": "default"},
            ]
        )
        raw, label = extract_target(f)
        assert "db-password" in raw
        assert "secret · default/db-password" == label

    def test_extract_target_pod(self):
        f = _finding(
            observables=[
                {"name": "actor.name", "value": "alice"},
                {"name": "pod.name", "value": "web-01"},
                {"name": "namespace", "value": "default"},
            ]
        )
        raw, label = extract_target(f)
        assert "web-01" in raw
        assert "pod · default/web-01" == label

    def test_extract_target_clusterrolebinding(self):
        f = _finding(
            observables=[
                {"name": "actor.name", "value": "alice"},
                {"name": "binding.type", "value": "clusterrolebindings"},
                {"name": "binding.name", "value": "attacker-admin"},
            ]
        )
        raw, label = extract_target(f)
        assert "attacker-admin" in raw
        assert "clusterrolebinding" in label

    def test_extract_target_mcp_tool(self):
        f = _finding(
            observables=[
                {"name": "actor.name", "value": "agent-1"},
                {"name": "tool.name", "value": "query_db"},
                {"name": "session.uid", "value": "sess-abc"},
            ]
        )
        raw, label = extract_target(f)
        assert "query_db" in raw
        assert "mcp tool" in label

    def test_extract_attack_with_sub_technique_prefers_sub(self):
        f = _finding()
        f["finding_info"]["attacks"][0]["sub_technique"] = {
            "name": "Container API",
            "uid": "T1552.007",
        }
        uid, _name = extract_attack(f)
        assert uid == "T1552.007"

    def test_extract_attack_no_attacks_returns_unknown(self):
        f = _finding()
        f["finding_info"]["attacks"] = []
        uid, name = extract_attack(f)
        assert uid == "no-mitre"
        assert name == "Unknown"


# ── render() ──────────────────────────────────────────────────────────


class TestRender:
    def test_empty_input_renders_empty_node(self):
        out = render([])
        assert "flowchart LR" in out
        assert "No findings" in out

    def test_rejects_non_detection_finding(self):
        with pytest.raises(ValueError, match="class_uid=2004"):
            render([{"class_uid": 6003, "metadata": {}, "finding_info": {}}])

    def test_single_finding(self):
        out = render([_finding()])
        assert "flowchart LR" in out
        assert "system:serviceaccount:default:builder" in out
        assert "test-pod" in out
        assert "T1611" in out

    def test_severity_class_in_output(self):
        out = render([_finding(severity_id=5)])  # Critical
        assert ":::critical" in out

    def test_low_severity_class(self):
        out = render([_finding(severity_id=1)])
        assert ":::low" in out

    def test_finding_severity_does_not_spread_to_same_named_actor(self):
        # Matching names do not establish a shared identity.
        f1 = _finding(uid="a", severity_id=3, technique_uid="T1098")
        f2 = _finding(uid="b", severity_id=5, technique_uid="T1611")
        out = render([f1, f2])
        # Find the actor line
        actor_lines = [line for line in out.splitlines() if "system:serviceaccount" in line]
        assert len(actor_lines) == 2
        assert ":::medium" in actor_lines[0]
        assert ":::critical" in actor_lines[1]

    def test_three_findings_three_edges(self):
        out = render(
            [
                _finding(uid="a", technique_uid="T1611"),
                _finding(
                    uid="b",
                    technique_uid="T1098",
                    observables=[
                        {"name": "actor.name", "value": "system:serviceaccount:default:builder"},
                        {"name": "binding.type", "value": "clusterrolebindings"},
                        {"name": "binding.name", "value": "cb1"},
                    ],
                ),
                _finding(
                    uid="c",
                    technique_uid="T1552.007",
                    observables=[
                        {"name": "actor.name", "value": "system:serviceaccount:default:builder"},
                        {"name": "secret.name", "value": "s1"},
                        {"name": "namespace", "value": "default"},
                    ],
                ),
            ]
        )
        edges = [line for line in out.splitlines() if "-->" in line]
        assert len(edges) == 3

    def test_edge_label_format(self):
        out = render([_finding(detector="detect-privilege-escalation-k8s")])
        # Technique, detector and provenance each get a readable line.
        assert '"T1611<br>privilege-escalation-k8s<br>UID: det-test-1"' in out

    def test_no_double_quotes_in_node_labels(self):
        # Mermaid node label syntax uses double quotes — internal " must be escaped/replaced
        f = _finding(actor='alice"injected')
        out = render([f])
        # Preserve the quote as literal text through Mermaid entity encoding.
        assert "alice#34;injected" in out


# ── load_jsonl robustness ────────────────────────────────────────────


class TestLoadJsonl:
    def test_rejects_malformed(self):
        with pytest.raises(ValueError, match="line 1: invalid JSON"):
            list(load_jsonl(['{"bad": ', '{"class_uid": 2004}']))


# ── Golden fixture parity ────────────────────────────────────────────


class TestGoldenFixture:
    def test_k8s_priv_esc_to_mermaid_matches_frozen(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        produced = render(findings)
        expected = EXPECTED.read_text()
        assert produced == expected, (
            "Mermaid golden drift — re-generate via:\n  python src/convert.py ../golden/k8s_priv_esc_findings.ocsf.jsonl > ../golden/k8s_priv_esc_attack_flow.mmd"
        )

    def test_three_finding_occurrences_keep_three_actor_nodes(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        out = render(findings)
        # Filter to NODE definition lines only (have `]:::class`), skip edges (`-->`)
        node_lines = [line for line in out.splitlines() if "]:::" in line and "-->" not in line]
        actor_node_lines = [line for line in node_lines if line.strip().startswith("A")]
        target_node_lines = [line for line in node_lines if line.strip().startswith("T")]
        assert len(actor_node_lines) == 3, f"expected 3 actor nodes, got {actor_node_lines}"
        assert len(target_node_lines) == 3, f"expected 3 target nodes, got {target_node_lines}"

    def test_three_mitre_techniques_in_edges(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        out = render(findings)
        for technique in ("T1552.007", "T1611", "T1098"):
            assert technique in out

    def test_actor_severities_follow_individual_findings(self):
        findings = _load_jsonl(INPUT_FIXTURE)
        out = render(findings)
        actor_lines = [line for line in out.splitlines() if "system:serviceaccount" in line]
        assert ":::high" in actor_lines[0]
        assert all(":::critical" in line for line in actor_lines[1:])


class TestMain:
    def test_file_conversion_with_fences(self, tmp_path):
        source = tmp_path / "findings.jsonl"
        destination = tmp_path / "flow.md"
        source.write_text(json.dumps(_finding()) + "\n")
        assert main([str(source), "--output", str(destination), "--fenced"]) == 0
        output = destination.read_text()
        assert output.startswith("```mermaid\n---\nconfig:")
        assert output.endswith("```\n")
        assert "T1611" in output

    @pytest.mark.parametrize("payload", ["{broken", "[]", '{"class_uid": 6003}'])
    def test_invalid_stdin_does_not_replace_output(self, tmp_path, monkeypatch, capsys, payload):
        destination = tmp_path / "flow.mmd"
        destination.write_text("previous diagram")
        monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
        assert main(["--output", str(destination)]) == 2
        assert destination.read_text() == "previous diagram"
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "invalid input" in captured.err

    def test_blank_stdin_is_valid(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
        assert main([]) == 0
        assert "No findings" in capsys.readouterr().out


class TestFindingBoundaries:
    @pytest.mark.parametrize("scope", ["account.uid", "cluster.uid", "tenant.uid"])
    def test_same_names_in_different_scopes_stay_separate(self, scope):
        findings = []
        for uid, boundary, severity in [("one", "production", 5), ("two", "sandbox", 2)]:
            finding = _finding(uid=uid, severity_id=severity)
            finding["observables"].append({"name": scope, "value": boundary})
            findings.append(finding)
        output = render(findings)
        actors = [line for line in output.splitlines() if '["system:serviceaccount:' in line]
        targets = [line for line in output.splitlines() if '["pod ·' in line]
        assert len(actors) == len(targets) == 2
        assert sum(":::critical" in line for line in actors) == 1
        assert sum(":::low" in line for line in actors) == 1

    def test_missing_scope_is_not_permission_to_correlate(self):
        output = render([_finding(uid="one"), _finding(uid="two")])
        assert output.count('["system:serviceaccount:') == 2
        assert 'subgraph F0["Finding 1 · High"]' in output
        assert 'UID: one" -->' in output
        assert 'subgraph F1["Finding 2 · High"]' in output
        assert 'UID: two" -->' in output

    def test_duplicate_uids_still_preserve_distinct_occurrences(self):
        finding = _finding(uid="same")
        output = render([finding, finding])
        assert output.count('["system:serviceaccount:') == 2
        assert output.count("-->") == 2

    def test_missing_actor_is_explicit(self):
        assert (
            extract_actor(_finding(observables=[{"name": "pod.name", "value": "web"}]))
            == "Unknown actor"
        )

    def test_context_identifiers_are_not_targets(self):
        finding = _finding(
            observables=[
                {"name": "session.uid", "value": "session-1"},
                {"name": "account.uid", "value": "account-1"},
                {"name": "cluster.name", "value": "cluster-1"},
                {"name": "namespace.uid", "value": "namespace-1"},
                {"name": "region.name", "value": "region-1"},
                {"name": "provider.name", "value": "provider-1"},
                {"name": "api.service.name", "value": "service-1"},
            ]
        )
        assert extract_target(finding)[1] == "Unknown target"

    def test_explicit_target_wins_over_context_order(self):
        finding = _finding(
            observables=[
                {"name": "session.uid", "value": "session-1"},
                {"name": "account.uid", "value": "account-1"},
                {"name": "target.name", "value": "bob"},
            ]
        )
        assert extract_target(finding)[1] == "target · bob"

    def test_labels_cannot_add_mermaid_or_markdown_structure(self):
        payload = 'alice"\n```\nflowchart TB\nX[<br/>] #quot; &'
        finding = _finding(uid=payload, actor=payload, detector=payload)
        output = render([finding])
        assert "```" not in output
        assert "<br/>" not in output
        assert "\nflowchart TB" not in output
        assert "#34;" in output
        assert "#60;" in output
        assert "#35;quot;" in output


class TestReadableContext:
    @pytest.mark.parametrize(
        "scope", ["account.uid", "cloud.account.uid", "cluster.uid", "cluster.name", "tenant.uid"]
    )
    def test_recorded_context_is_visible_without_merging(self, scope):
        first = _finding(uid="one")
        second = _finding(uid="two")
        first["observables"].append({"name": scope, "value": "production"})
        second["observables"].append({"name": scope, "value": "sandbox"})
        output = render([first, second])
        assert f"{scope}: production" in output
        assert f"{scope}: sandbox" in output
        assert output.count("-->") == 2

    def test_conflicting_context_is_not_silently_overwritten(self):
        finding = _finding()
        finding["observables"].extend(
            [
                {"name": "cluster.uid", "value": "one"},
                {"name": "cluster.uid", "value": "two"},
            ]
        )
        output = render([finding])
        assert "cluster.uid: one" in output and "cluster.uid: two" in output

    def test_context_cannot_inject_structure(self):
        finding = _finding()
        finding["observables"].append({"name": "cluster.uid", "value": '"<br/>\n```\nX[bad]'})
        output = render([finding])
        assert "<br/>" not in output and "```" not in output
        assert "#34;#60;br/#62;" in output
        assert output.count("subgraph") == 1

    @pytest.mark.parametrize(
        "severity,label",
        [
            (0, "Unknown"),
            (1, "Informational"),
            (2, "Low"),
            (3, "Medium"),
            (4, "High"),
            (5, "Critical"),
            (6, "Fatal"),
            (99, "Unknown"),
        ],
    )
    def test_severity_does_not_depend_on_colour(self, severity, label):
        output = render([_finding(severity_id=severity)])
        assert f"Finding 1 · {label}" in output
