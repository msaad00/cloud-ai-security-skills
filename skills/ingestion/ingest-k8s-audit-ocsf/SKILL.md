---
name: ingest-k8s-audit-ocsf
description: >-
  Convert raw Kubernetes audit logs (`audit.k8s.io/v1`) into normalized API
  activity records, with OCSF as the default wire format and native output as
  an option. Maps user, source IP, verb, objectRef, and response status with
  enough fidelity for K8s privilege-escalation and secret-access detectors.
  Use when the user mentions Kubernetes audit logs, kube-apiserver audit
  sinks, K8s detection engineering, or feeding K8s audit into a SIEM. Do NOT
  use for container runtime logs, kubelet logs, or CloudTrail / GCP audit /
  Azure Activity. Do NOT use as a detection skill; this only normalizes
  events.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: stateless
---

# ingest-k8s-audit-ocsf

Thin, single-purpose ingestion skill: raw Kubernetes audit logs in → OCSF 1.8 API Activity JSONL out by default, with an optional native enriched event shape when `--output-format native` is selected. No detection logic, no K8s API calls, no side effects.

## Wire contract

Reads the `audit.k8s.io/v1` `Event` object that `kube-apiserver` writes to its audit sink:

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "abc-123",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/secrets",
  "verb": "list",
  "user": {
    "username": "system:serviceaccount:default:default",
    "groups": ["system:serviceaccounts", "system:authenticated"]
  },
  "sourceIPs": ["10.0.0.1"],
  "userAgent": "kubectl/v1.28",
  "objectRef": {
    "resource": "secrets",
    "namespace": "default",
    "apiVersion": "v1"
  },
  "responseStatus": {"metadata": {}, "code": 200},
  "requestReceivedTimestamp": "2026-04-10T05:00:00.000000Z",
  "stageTimestamp": "2026-04-10T05:00:00.100000Z",
  "annotations": {"authorization.k8s.io/decision": "allow"}
}
```

Writes OCSF 1.8 **API Activity** (`class_uid: 6003`, `category_uid: 6`) by default.
With `--output-format native`, writes the repo's native enriched API activity
shape instead of the OCSF envelope.

## activity_id inference

K8s verbs are standard — no guessing needed:

| K8s verb | OCSF activity | id |
|---|---|---:|
| `create` | Create | 1 |
| `get`, `list`, `watch`, `proxy` | Read | 2 |
| `update`, `patch` | Update | 3 |
| `delete`, `deletecollection` | Delete | 4 |
| anything else (`connect`, `bind`, custom) | Other | 99 |

## status_id

`responseStatus.code` is an HTTP status code:

- `2xx` → `status_id = 1` (Success)
- `4xx` / `5xx` → `status_id = 2` (Failure)
- missing (audit level below `Metadata`) → `status_id = 0` (Unknown)

On failure, `status_detail` is populated with `responseStatus.message` (e.g. `"secrets \"db-password\" is forbidden: User ... cannot get resource"`) for fast triage and detection rule pivots.

## Filtering by stage

K8s audit events are emitted at 4 stages: `RequestReceived`, `ResponseStarted`, `ResponseComplete`, `Panic`. The skill processes **only `ResponseComplete` and `Panic`** events — those are the ones with authoritative `responseStatus`. Earlier-stage events are skipped with a `stderr` debug line.

## Field mapping

| K8s field | OCSF field |
|---|---|
| `user.username` | `actor.user.name` |
| `user.uid` | `actor.user.uid` |
| `user.groups` | `actor.user.groups[]` (each as `{name: ...}`) |
| `sourceIPs[0]` | `src_endpoint.ip` |
| `userAgent` | `src_endpoint.svc_name` |
| `verb` | `api.operation` |
| `"kubernetes"` | `api.service.name` (hard-coded) |
| `auditID` | `api.request.uid` |
| `objectRef.resource` / `namespace` / `name` / `apiGroup` | `resources[0]` |
| `requestReceivedTimestamp` | `time` (ms epoch) |
| `annotations["authorization.k8s.io/decision"]` | `metadata.labels` (`authz-allow` / `authz-deny`) |

`cloud.provider` is hard-coded to `"Kubernetes"` (even though K8s is not a cloud, OCSF uses the `cloud` object as the deployment-context holder).

### `unmapped.k8s.*` preservation

Fields without a clean first-class OCSF slot round-trip verbatim under
`unmapped.k8s.*` in both native and OCSF output:

- `requestObject` → `unmapped.k8s.request_object`
- `responseObject` → `unmapped.k8s.response_object`
- raw `objectRef` → `unmapped.k8s.object_ref`

This preserves spec-patch and response-body detail for downstream detectors
without overloading the normalized `resources[]` shape.

## Service-account marker

When `user.username` starts with `system:serviceaccount:<namespace>:<name>`, the skill sets `actor.user.type = "ServiceAccount"` and records `mcp.sa_namespace` under a non-standard k8s custom profile so detection skills can key off it without parsing the username string.

## Usage

```bash
# Audit log file (as written by kube-apiserver)
python src/ingest.py /var/log/k8s-audit.log > k8s-audit.ocsf.jsonl

# Piped from a dynamic webhook sink
kubectl logs -n kube-system audit-webhook-receiver \
  | python src/ingest.py

# Native enriched output (same source truth, no OCSF envelope)
python src/ingest.py --output-format native /var/log/k8s-audit.log > k8s-audit.native.jsonl
```

## Native output format

`--output-format native` emits one enriched event per accepted audit entry with:

- `schema_mode`
- `canonical_schema_version`
- `record_type`
- `event_uid`
- `provider`
- `account_uid`
- `region`
- `time_ms`
- `activity_id`
- `activity_name`
- `status_id`
- `status`
- `status_detail` when present
- `operation`
- `service_name`
- `actor`
- `src`
- `resources`
- `source`
- `k8s.service_account_namespace` when the actor is a service account
- `unmapped.k8s.*` when raw request / response / objectRef detail is present

## Tests

Golden fixture parity against [`../golden/k8s_audit_raw_sample.jsonl`](../golden/k8s_audit_raw_sample.jsonl) → [`../golden/k8s_audit_sample.ocsf.jsonl`](../golden/k8s_audit_sample.ocsf.jsonl).
