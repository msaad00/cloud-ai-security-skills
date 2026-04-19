---
name: detect-container-escape-k8s
description: >-
  Detect Kubernetes container-escape signals from normalized kube-apiserver
  audit events in native or OCSF mode. Fires on three high-signal behaviors:
  patches that introduce privileged / host-namespace / risky-capability
  settings, patches that introduce dangerous hostPath mounts, and
  ephemeral-container creation on running pods. Use when the user mentions
  Kubernetes container escape, hostPath abuse, privileged pod patching, or
  `kubectl debug` / ephemeral container activity. Do NOT use on raw audit
  logs — pipe them through ingest-k8s-audit-ocsf first. Do NOT use for
  Falco or Tracee runtime events in this PR; that fusion path is a follow-up.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: native, ocsf
output_formats: native, ocsf
concurrency_safety: stateless
---

# detect-container-escape-k8s

## Use when

- Kubernetes audit telemetry is already normalized by `ingest-k8s-audit-ocsf`
- you want deterministic findings for post-deploy escape-to-host changes
- you need native or OCSF findings for patch-driven container-escape signals

## Attack patterns detected

This PR ships the K8s-audit-first subset of issue `#274`: three single-event
rules that do not depend on Falco, Tracee, or operator/deployer history.

### Rule 1: Risky spec patch (T1611)

Fires when a `patch` request introduces one or more of:

- `privileged: true`
- `hostPID: true`
- `hostNetwork: true`
- `CAP_SYS_ADMIN`
- `CAP_SYS_PTRACE`

These settings materially weaken workload isolation and are explicitly aligned
to container escape behavior in MITRE ATT&CK and Kubernetes hardening guidance.

- **Trigger:** `patch` on a pod or pod-owning workload with a request payload that adds one or more risky settings
- **MITRE:** T1611 — Escape to Host
- **Severity:** Critical (5)
- **Observables:** actor, resource type/name, namespace, risky settings

### Rule 2: hostPath injection (T1611)

Fires when a `patch` request introduces a `hostPath` mount to one of:

- `/`
- `/proc`
- `/var/lib/docker`
- `/var/lib/containerd`

Kubernetes documents `hostPath` as a powerful escape hatch and warns that it
poses significant security risk. These paths are the classic host-access pivot.

- **Trigger:** `patch` on a pod or pod-owning workload with a request payload that adds a risky `hostPath`
- **MITRE:** T1611 — Escape to Host
- **Severity:** Critical (5)
- **Observables:** actor, resource type/name, namespace, host paths

### Rule 3: Ephemeral container creation (T1610)

Fires when a running pod is modified through the `pods/ephemeralcontainers`
subresource, the API path used by `kubectl debug` and related troubleshooting
flows.

- **Trigger:** `patch` or `update` on `pods` with `subresource == "ephemeralcontainers"` and an ephemeral container payload
- **MITRE:** T1610 — Deploy Container
- **Severity:** High (4)
- **Observables:** actor, pod, namespace, ephemeral container names

## Output contract

Each match emits a full OCSF 1.8 Detection Finding (class `2004`) by default.
Deterministic `finding_info.uid` uses the rule id plus stable actor/target
hashes so re-running on the same input is idempotent.

`finding_info.attacks[]` always carries:

- `version: "v14"`
- `tactic: { name, uid }`
- `technique: { name, uid }`

## What this PR does NOT detect

- Falco / Tracee runtime events
- `kubectl exec` versus known-operator correlation
- cross-run or cross-source fusion on `container_id`
- automatic remediation or forensic collection

Those stay for later `#274` slices so this detector PR remains reviewable.

## Native output format

`--output-format native` emits one native detection-finding record per match
with:

- `schema_mode`
- `canonical_schema_version`
- `record_type`
- `source_skill`
- `output_format`
- `finding_uid`
- `event_uid`
- `provider`
- `time_ms`
- `severity`
- `severity_id`
- `status`
- `status_id`
- `title`
- `description`
- `finding_types`
- `first_seen_time_ms`
- `last_seen_time_ms`
- `mitre_attacks`
- `actor_name`
- `target`
- `rule_name`
- `observables`
- `evidence_count`

## Usage

```bash
# Piped from ingest-k8s-audit-ocsf (default OCSF output)
python ../ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python src/detect.py \
  > findings.ocsf.jsonl

# Native end-to-end path
python ../ingest-k8s-audit-ocsf/src/ingest.py --output-format native audit.log \
  | python src/detect.py --output-format native \
  > findings.native.jsonl

# Standalone OCSF file
python src/detect.py ../golden/k8s_container_escape_sample.ocsf.jsonl
```

## Tests

Golden fixture parity against
[`../golden/k8s_container_escape_sample.ocsf.jsonl`](../golden/k8s_container_escape_sample.ocsf.jsonl)
→
[`../golden/k8s_container_escape_findings.ocsf.jsonl`](../golden/k8s_container_escape_findings.ocsf.jsonl).
Plus unit tests for risky-setting extraction, `hostPath` path filtering, JSON
Patch handling, ephemeral container name extraction, native input, OCSF class
pinning, and deterministic finding UIDs.
