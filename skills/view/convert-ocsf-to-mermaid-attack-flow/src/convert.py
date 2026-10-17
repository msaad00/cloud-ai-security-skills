"""Convert OCSF 1.8 Detection Findings (class 2004) to a Mermaid attack flow.

Reads OCSF Detection Finding JSONL on stdin, emits a single Mermaid
flowchart LR block on stdout (optionally wrapped in fenced code to render inline
on any Markdown surface that supports Mermaid — GitHub, GitLab, most
wikis).

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterable

SKILL_NAME = "convert-ocsf-to-mermaid-attack-flow"
SKILL_VERSION = "0.1.0"

DETECTION_FINDING_CLASS_UID = 2004

# Severity → Mermaid CSS class
_SEVERITY_CLASS = {
    0: "low",  # Unknown
    1: "low",  # Informational
    2: "low",  # Low
    3: "medium",
    4: "high",
    5: "critical",
    6: "critical",
}


def severity_class(severity_id: int) -> str:
    return _SEVERITY_CLASS.get(severity_id, "low")


def mermaid_label(value: str) -> str:
    """Encode literal labels without accepting Mermaid, HTML, or Markdown syntax."""
    return "".join(
        " "
        if ord(char) < 32 or ord(char) == 127
        else f"#{ord(char)};"
        if char in '"&<>`#|\\'
        else char
        for char in value
    )


# ---------------------------------------------------------------------------
# Observable extraction
# ---------------------------------------------------------------------------


def _observables_by_name(observables: list[dict[str, Any]]) -> dict[str, str]:
    """Index an observables[] array by name → first value."""
    out: dict[str, str] = {}
    for obs in observables or []:
        name = obs.get("name", "")
        value = obs.get("value", "")
        if name and value and name not in out:
            out[name] = str(value)
    return out


def extract_actor(finding: dict[str, Any]) -> str:
    """Pull the actor identifier from a finding's observables.

    Looks for actor.name, then session.uid. Missing identity remains unknown.
    """
    obs = _observables_by_name(finding.get("observables") or [])
    for key in ("actor.name", "session.uid"):
        if key in obs:
            return obs[key]
    return "Unknown actor"


def extract_target(finding: dict[str, Any]) -> tuple[str, str]:
    """Pull a target identifier and a human label from a finding's observables.

    Returns (raw_id, display_label). Context identifiers are not targets;
    missing target identity is rendered explicitly as unknown.
    """
    obs_list = finding.get("observables") or []
    obs_by_name = _observables_by_name(obs_list)

    # Special-case the well-known target shapes the existing detect skills emit
    # K8s priv-esc rules
    if "secret.name" in obs_by_name:
        ns = obs_by_name.get("namespace", "")
        return (
            f"secret/{ns}/{obs_by_name['secret.name']}",
            f"secret · {ns}/{obs_by_name['secret.name']}",
        )
    if "pod.name" in obs_by_name:
        ns = obs_by_name.get("namespace", "")
        return (f"pod/{ns}/{obs_by_name['pod.name']}", f"pod · {ns}/{obs_by_name['pod.name']}")
    if "binding.name" in obs_by_name:
        bt = obs_by_name.get("binding.type", "binding")
        ns = obs_by_name.get("namespace", "")
        ns_part = f"{ns}/" if ns else ""
        return (
            f"{bt}/{ns_part}{obs_by_name['binding.name']}",
            f"{bt[:-1] if bt.endswith('s') else bt} · {ns_part}{obs_by_name['binding.name']}",
        )
    if "target.serviceaccount" in obs_by_name:
        ns = obs_by_name.get("namespace", "")
        return (
            f"sa/{ns}/{obs_by_name['target.serviceaccount']}",
            f"serviceaccount · {ns}/{obs_by_name['target.serviceaccount']}",
        )

    # MCP rules
    if "tool.name" in obs_by_name:
        sess = obs_by_name.get("session.uid", "")
        return (
            f"mcp-tool/{sess}/{obs_by_name['tool.name']}",
            f"mcp tool · {obs_by_name['tool.name']}",
        )

    # Prefer explicit targets; account, session, and cluster describe scope,
    # not the entity acted upon. Never manufacture a target from a rule type.
    target_items = sorted(obs_by_name.items(), key=lambda item: not item[0].startswith("target."))
    for name, value in target_items:
        if name.startswith(
            (
                "actor.",
                "session.",
                "account.",
                "cloud.",
                "cluster.",
                "tenant.",
                "metadata.",
                "namespace.",
                "region.",
                "provider.",
                "api.",
                "src_endpoint.",
            )
        ):
            continue
        if name.endswith((".name", ".uid")):
            return (f"{name}/{value}", f"{name.split('.')[0]} · {value}")
    return ("unknown-target", "Unknown target")


def extract_attack(finding: dict[str, Any]) -> tuple[str, str]:
    """Return (technique_uid, technique_name) for the first MITRE attack."""
    attacks = (finding.get("finding_info") or {}).get("attacks") or []
    if not attacks:
        return ("no-mitre", "Unknown")
    a = attacks[0]
    technique = a.get("technique") or {}
    sub = a.get("sub_technique") or {}
    uid = sub.get("uid") or technique.get("uid") or "no-mitre"
    name = sub.get("name") or technique.get("name") or "Unknown technique"
    return (uid, name)


def extract_detector_short(finding: dict[str, Any]) -> str:
    """Return a short detector name for the edge label."""
    feature = ((finding.get("metadata") or {}).get("product") or {}).get("feature") or {}
    name = feature.get("name") or ""
    # Strip detect- / ingest- prefix and -k8s / -aws etc suffix for compactness
    name = name.replace("detect-", "").replace("ingest-", "")
    return name


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


_HEADER = """---
config:
  theme: base
  themeVariables:
    fontFamily: Arial, sans-serif
    fontSize: 20px
    primaryTextColor: '#0f172a'
    lineColor: '#64748b'
    edgeLabelBackground: '#f8fafc'
    clusterBkg: '#f8fafc'
    clusterBorder: '#94a3b8'
  flowchart:
    htmlLabels: true
    wrappingWidth: 280
    subGraphTitleMargin:
      top: 12
      bottom: {title_margin}
---
flowchart LR
    classDef critical fill:#3f1d1d,stroke:#f87171,color:#fff1f2
    classDef high     fill:#3a2a0e,stroke:#fb923c,color:#fff7ed
    classDef medium   fill:#3a3a0e,stroke:#fbbf24,color:#fefce8
    classDef low      fill:#1e293b,stroke:#64748b,color:#f1f5f9
"""


def finding_heading(finding: dict[str, Any], index: int) -> list[str]:
    """Return visible heading lines; recorded context is never used as identity."""
    severity = {
        0: "Unknown",
        1: "Informational",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
        6: "Fatal",
    }.get(int(finding.get("severity_id", 0)), "Unknown")
    heading = f"Finding {index + 1} · {severity}"
    # Show recorded boundary context without inferring or merging identities.
    context = []
    for obs in finding.get("observables") or []:
        name, value = obs.get("name", ""), obs.get("value")
        if (
            name
            in {"account.uid", "cloud.account.uid", "tenant.uid", "cluster.uid", "cluster.name"}
            and value
        ):
            context.append(f"{name}: {value}")
    # Bound each context line while keeping every character in the source value.
    # Fixed renderer-owned breaks also let us reserve enough title space.
    return [heading, *(part[i : i + 48] for part in context for i in range(0, len(part), 48))]


def render(findings: Iterable[dict[str, Any]]) -> str:
    """Convert an iterable of OCSF Detection Findings to a Mermaid flowchart string.

    The string is a complete `flowchart LR` block with presentation frontmatter. Wrap it in
    triple-backtick `mermaid` fences if you're embedding into Markdown.
    """
    materialised: list[dict[str, Any]] = []
    for f in findings:
        if f.get("class_uid") == DETECTION_FINDING_CLASS_UID:
            materialised.append(f)
        else:
            raise ValueError("only Detection Finding (class_uid=2004) is supported")

    if not materialised:
        return _HEADER.format(title_margin=28) + '    empty["No findings"]:::low\n'

    # Finding-local occurrence IDs deliberately do not infer identity from
    # display names, incomplete scope, or a repeated finding UID. Each input
    # finding keeps its own evidence and severity, even when labels match.
    headings = [finding_heading(finding, index) for index, finding in enumerate(materialised)]
    title_margin = 28 + 32 * (max(map(len, headings)) - 1)
    lines: list[str] = [_HEADER.format(title_margin=title_margin)]
    for index, finding in enumerate(materialised):
        actor_label = mermaid_label(extract_actor(finding))
        _, target = extract_target(finding)
        target_label = mermaid_label(target)
        technique_uid, _ = extract_attack(finding)
        detector = extract_detector_short(finding)
        cls = severity_class(int(finding.get("severity_id", 0)))
        uid = (finding.get("finding_info") or {}).get("uid") or f"Finding {index + 1} (UID unknown)"
        # Line breaks are renderer-owned; every input fragment is encoded first.
        edge_label = "<br>".join(
            mermaid_label(part) for part in (technique_uid, detector, f"UID: {uid}") if part
        )
        group_label = "<br>".join(mermaid_label(part) for part in headings[index])
        lines.extend(
            [
                f'    subgraph F{index}["{group_label}"]',
                "        direction LR",
                f'        A{index}["{actor_label}"]:::{cls}',
                f'        T{index}["{target_label}"]:::{cls}',
                f'        A{index} -- "{edge_label}" --> T{index}',
                "    end",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"line {lineno}: invalid JSON") from e
        if not isinstance(obj, dict):
            raise ValueError(f"line {lineno}: expected a JSON object")
        yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert OCSF Detection Findings to a Mermaid attack flow.", allow_abbrev=False
    )
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Mermaid output file. Defaults to stdout.")
    parser.add_argument(
        "--fenced",
        action="store_true",
        help="Wrap output in ```mermaid ... ``` fences for direct Markdown embedding.",
    )
    args = parser.parse_args(argv)

    # Render completely before opening the destination: a bad record must not
    # publish a partial diagram or truncate a previously useful artifact.
    try:
        if args.input:
            with open(args.input, "r", encoding="utf-8") as in_stream:
                body = render(load_jsonl(in_stream))
        else:
            body = render(load_jsonl(sys.stdin))
    except ValueError as exc:
        print(f"[{SKILL_NAME}] invalid input: {exc}", file=sys.stderr)
        return 2

    if args.fenced:
        body = f"```mermaid\n{body}```\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_stream:
            out_stream.write(body)
    else:
        sys.stdout.write(body)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
