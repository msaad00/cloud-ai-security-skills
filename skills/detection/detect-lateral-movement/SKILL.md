---
name: detect-lateral-movement
description: >-
  Detect cloud lateral movement by joining OCSF 1.8 API Activity events
  from cloud audit ingestors (class 6003) with OCSF 1.8 Network Activity
  events from cloud flow-log ingestors (class 4001) in a single
  detection. Correlates a recent privileged identity pivot event with
  accepted east-west traffic to an internal destination — the canonical
  post-access movement pattern. Emits OCSF 1.8 Detection Finding (class
  2004) with MITRE ATT&CK T1021 Remote Services and T1078.004 Cloud
  Accounts inside finding_info.attacks[]. Multi-source, cross-cloud
  detection that proves the OCSF fan-out architecture where one detector
  consumes multiple ingest streams. Use when the user mentions lateral
  movement, east-west pivot, cloud identity pivot followed by internal
  traffic, or wants to detect attackers moving between cloud resources
  after initial access. Do NOT use on raw logs — pipe audit and network
  telemetry through their respective ingest-*-ocsf skills first. Do NOT
  use for pre-compromise detection. Do NOT use as an exfiltration
  detector — public internet destinations are deliberately filtered out.
license: Apache-2.0
---

# detect-lateral-movement

## Attack pattern

The canonical cloud lateral-movement sequence after initial access:

1. Attacker compromises an IAM principal (stolen access key, compromised EC2 instance profile, phished human)
2. Attacker pivots identity with a privileged cloud API operation:
   - AWS `AssumeRole*`
   - GCP service-account impersonation / key generation
   - Azure role assignment / access elevation
3. From a compute resource inside the cloud network, attacker initiates east-west traffic to an internal service the original principal never accessed
4. Data transfer starts

Audit logs alone see step 2. Flow logs alone see steps 3–4. **Neither source alone tells you the story** — the API call may look routine and the flow may look like ordinary internal traffic. The join is where the detection lives.

This skill correlates them.

## Detection logic

One pass over a merged OCSF stream of API Activity (6003) + Network Activity (4001). For each identity-pivot anchor in the API stream:

1. Record the `(cloud.provider, cloud.account.uid, actor.session.uid, time)` as an anchor
2. Within a correlation window (default: 15 minutes), scan the Network Activity stream for flows where:
   - `cloud.provider` matches the anchor provider
   - `cloud.account.uid` matches the anchor account when both are present
   - `activity_id == 6` (Traffic ACCEPT — only successful flows count)
   - `dst_endpoint.ip` is **RFC1918 internal** (east-west, not egress to the internet)
   - `traffic.bytes >= 1024` (filter out scan probes — real data transfer threshold)
3. Emit one finding per distinct `(provider, session_uid, dst_endpoint.ip, dst_endpoint.port)` tuple

**Stateless per-run, deterministic UIDs.** Findings are keyed on `(session_uid, dst_ip, dst_port)` so re-running on the same merged stream produces byte-identical output.

### Window semantics

Default 15 minutes post-anchor. Rationale: attackers tend to act fast after acquiring a more powerful cloud identity. A longer window catches more but produces more false positives on legitimate cross-service traffic.

### Why RFC1918-only

The purpose of this rule is **east-west detection**. Egress to the public internet is a different detector (data exfiltration). Filtering to RFC1918 destinations — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, plus the shared `100.64.0.0/10` — means any fire is definitionally east-west.

## Output contract

OCSF 1.8 Detection Finding (class `2004`) with:

- `finding_info.attacks[]` — two techniques populated per MITRE v14:
  - **T1021** Remote Services (Lateral Movement tactic, TA0008)
  - **T1078.004** Valid Accounts: Cloud Accounts (Defense Evasion / Persistence / Privilege Escalation / Initial Access — v14 lists multiple tactics for this technique; we pin Persistence as the primary)
- `finding_info.uid` — deterministic (`det-lm-<provider-hash>-<session-hash>-<dst-hash>`)
- `finding_info.types[]` — `["cloud-lateral-movement"]`
- `observables[]` — provider, account, session uid, source principal, anchor operation, source instance, destination IP, destination port, bytes transferred, correlation window

## Usage

```bash
# Merge cloud audit + flow OCSF streams, then pipe through the detector
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

- identity pivot with no subsequent internal traffic → not fired
- Internal traffic with no preceding `AssumeRole` → not fired (covered by other detectors)
- `AssumeRole` followed by egress traffic (public internet dst) → not fired (data exfil detector, roadmap)
- identity pivots with no valid `cloud.provider` or account context → not fired
- Small flows under 1024 bytes → filtered (scan / handshake noise)
- `REJECT` flows → not fired (failed connection attempts don't count as movement)

## Tests

Golden fixture parity: `../golden/lateral_movement_input.ocsf.jsonl` → `../golden/lateral_movement_findings.ocsf.jsonl`. Plus unit tests for the RFC1918 detector, the window logic, provider/account correlation, byte-threshold filtering, and negative controls (egress dst, REJECT flow, no preceding anchor, stale correlation outside the window).

## See also

- [`ingest-cloudtrail-ocsf/REFERENCES.md`](../ingest-cloudtrail-ocsf/REFERENCES.md) — CloudTrail source format
- [`ingest-vpc-flow-logs-ocsf/REFERENCES.md`](../ingest-vpc-flow-logs-ocsf/REFERENCES.md) — VPC Flow Logs v5 source format
- [`OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — the wire contract both upstream ingest skills honour
- `convert-ocsf-to-sarif` — downstream view layer
- `RUNBOOK.md` (this skill) — triage flow when a finding fires
