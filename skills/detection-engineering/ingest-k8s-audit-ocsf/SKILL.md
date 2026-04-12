---
name: ingest-k8s-audit-ocsf
description: >-
  Convert raw Kubernetes audit logs (audit.k8s.io/v1) into OCSF 1.8 API
  Activity events (class 6003). Reads the JSON format kube-apiserver writes to
  its audit log sink (file, webhook, or dynamic backend). Maps user.username
  and user.groups to OCSF actor, sourceIPs to src_endpoint, verb to
  api.operation, api.service.name to "kubernetes", and infers activity_id
  (Create / Read / Update / Delete) from the K8s verb. Sets status_id from
  responseStatus.code. Captures objectRef (resource, namespace, name, apiGroup)
  in resources[] with enough precision for detectors to spot
  service-account-token-theft, privileged-pod creation, and secret access.
  Use when the user mentions Kubernetes audit logs, kube-apiserver audit sink,
  OCSF pipeline for K8s, k8s detection engineering, or feeding K8s audit into
  a SIEM. Do NOT use for container runtime logs (different source), kubelet
  logs (different source), or CloudTrail / GCP audit / Azure activity (use the
  matching ingest-* skills). Do NOT use as a detection skill — this only
  normalises events.
license: Apache-2.0
---

# ingest-k8s-audit-ocsf

Thin, single-purpose ingestion skill: raw Kubernetes audit logs in → OCSF 1.8 API Activity JSONL out. No detection logic, no K8s API calls, no side effects.

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

Writes OCSF 1.8 **API Activity** (`class_uid: 6003`, `category_uid: 6`).

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

## Service-account marker

When `user.username` starts with `system:serviceaccount:<namespace>:<name>`, the skill sets `actor.user.type = "ServiceAccount"` and records `mcp.sa_namespace` under a non-standard k8s custom profile so detection skills can key off it without parsing the username string.

## Usage

```bash
# Audit log file (as written by kube-apiserver)
python src/ingest.py /var/log/k8s-audit.log > k8s-audit.ocsf.jsonl

# Piped from a dynamic webhook sink
kubectl logs -n kube-system audit-webhook-receiver \
  | python src/ingest.py
```

## Tests

Golden fixture parity against [`../golden/k8s_audit_raw_sample.jsonl`](../golden/k8s_audit_raw_sample.jsonl) → [`../golden/k8s_audit_sample.ocsf.jsonl`](../golden/k8s_audit_sample.ocsf.jsonl).
