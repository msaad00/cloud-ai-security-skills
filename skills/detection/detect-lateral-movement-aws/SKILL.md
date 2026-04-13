---
name: detect-lateral-movement-aws
description: >-
  Detect AWS lateral movement by joining OCSF 1.8 API Activity events from
  CloudTrail (class 6003) with OCSF 1.8 Network Activity events from VPC
  Flow Logs (class 4001) in a single detection. Correlates a recent
  AssumeRole event by a principal with accepted network flows from an
  instance running under that role's session to an internal destination
  the principal has not previously touched — the canonical east-west
  pivot pattern. Emits OCSF 1.8 Detection Finding (class 2004) with
  MITRE ATT&CK T1021 Remote Services and T1078.004 Cloud Accounts inside
  finding_info.attacks[]. First multi-source detection in the category
  — proves the OCSF fan-out architecture where one detector consumes
  multiple ingest streams. Use when the user mentions AWS lateral
  movement, east-west pivot, assume-role chain detection, or wants to
  detect attackers moving between AWS resources after initial access.
  Do NOT use on raw logs — pipe both CloudTrail and VPC Flow through
  their respective ingest-*-ocsf skills first. Do NOT use for
  pre-compromise detection (that is credential access, covered by
  other detectors). Do NOT use for cross-cloud lateral movement — that
  requires GCP and Azure VPC Flow ingest skills that are still on the
  roadmap.
license: Apache-2.0
---

# detect-lateral-movement-aws

## Attack pattern

The canonical AWS lateral-movement sequence after initial access:

1. Attacker compromises an IAM principal (stolen access key, compromised EC2 instance profile, phished human)
2. Attacker calls `sts:AssumeRole` to escalate into a role with broader permissions
3. From a compute resource inside the VPC (EC2 / ECS task / Lambda-in-VPC), attacker initiates east-west traffic to an internal service the original principal never accessed
4. Data transfer starts

CloudTrail alone sees step 2. VPC Flow Logs alone see steps 3–4. **Neither source alone tells you the story** — step 2 looks like routine assume-role traffic, step 3 looks like normal intra-VPC chatter. The join is where the detection lives.

This skill correlates them.

## Detection logic

One pass over a merged OCSF stream of API Activity (6003) + Network Activity (4001). For each `AssumeRole` event in the API stream:

1. Record the `(actor.session.uid, time)` as an assume-role anchor
2. Within a correlation window (default: 15 minutes), scan the Network Activity stream for flows where:
   - `src_endpoint.instance_uid` matches an EC2 instance the assumed role's session is associated with (via CloudTrail's `responseElements` or inferred from adjacent events), OR
   - `src_endpoint.ip` is in the same VPC and the flow `time` falls within the window after the assume-role anchor
   - `activity_id == 6` (Traffic ACCEPT — only successful flows count)
   - `dst_endpoint.ip` is **RFC1918 internal** (east-west, not egress to the internet)
   - `traffic.bytes >= 1024` (filter out scan probes — real data transfer threshold)
3. Emit one finding per distinct `(session_uid, dst_endpoint.ip, dst_endpoint.port)` tuple

**Stateless per-run, deterministic UIDs.** Findings are keyed on `(session_uid, dst_ip, dst_port)` so re-running on the same merged stream produces byte-identical output.

### Window semantics

Default 15 minutes post-`AssumeRole`. Rationale: attackers tend to act fast after escalating to avoid token-lifetime limits (STS sessions default to 1 hour). A longer window catches more but produces more false positives on legitimate cross-service traffic.

### Why RFC1918-only

The purpose of this rule is **east-west detection**. Egress to the public internet is a different detector (data exfiltration). Filtering to RFC1918 destinations — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, plus the shared `100.64.0.0/10` — means any fire is definitionally east-west.

## Output contract

OCSF 1.8 Detection Finding (class `2004`) with:

- `finding_info.attacks[]` — two techniques populated per MITRE v14:
  - **T1021** Remote Services (Lateral Movement tactic, TA0008)
  - **T1078.004** Valid Accounts: Cloud Accounts (Defense Evasion / Persistence / Privilege Escalation / Initial Access — v14 lists multiple tactics for this technique; we pin Persistence as the primary)
- `finding_info.uid` — deterministic (`det-aws-lm-<session-hash>-<dst-hash>`)
- `finding_info.types[]` — `["aws-lateral-movement"]`
- `observables[]` — session uid, source principal, source instance, destination IP, destination port, bytes transferred, correlation window

## Usage

```bash
# Merge CloudTrail + VPC Flow OCSF streams, then pipe through the detector
{
  python ../ingest-cloudtrail-ocsf/src/ingest.py cloudtrail.json
  python ../ingest-vpc-flow-logs-ocsf/src/ingest.py vpc-flow.log
} > merged.ocsf.jsonl

python src/detect.py < merged.ocsf.jsonl > findings.ocsf.jsonl

# Or, run the whole pipe and feed into the SARIF converter
cat merged.ocsf.jsonl \
  | python src/detect.py \
  | python ../convert-ocsf-to-sarif/src/convert.py \
  > lateral-movement.sarif
```

## What does NOT fire

- `AssumeRole` with no subsequent internal traffic → not fired
- Internal traffic with no preceding `AssumeRole` → not fired (covered by other detectors)
- `AssumeRole` followed by egress traffic (public internet dst) → not fired (data exfil detector, roadmap)
- `AssumeRole` by a role that is NOT a compute-service role (e.g. a human console session) → fires, but the session-uid heuristic won't find an instance — the finding will carry only the IP-based correlation
- Small flows under 1024 bytes → filtered (scan / handshake noise)
- `REJECT` flows → not fired (failed connection attempts don't count as movement)

## Tests

Golden fixture parity: `../golden/aws_lateral_movement_input.ocsf.jsonl` → `../golden/aws_lateral_movement_findings.ocsf.jsonl`. Plus unit tests for the RFC1918 detector, the window logic, session-uid matching, byte-threshold filtering, and negative controls (egress dst, REJECT flow, no preceding AssumeRole, stale correlation outside window).

## See also

- [`ingest-cloudtrail-ocsf/REFERENCES.md`](../ingest-cloudtrail-ocsf/REFERENCES.md) — CloudTrail source format
- [`ingest-vpc-flow-logs-ocsf/REFERENCES.md`](../ingest-vpc-flow-logs-ocsf/REFERENCES.md) — VPC Flow Logs v5 source format
- [`OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — the wire contract both upstream ingest skills honour
- `convert-ocsf-to-sarif` — downstream view layer
- `RUNBOOK.md` (this skill) — triage flow when a finding fires
