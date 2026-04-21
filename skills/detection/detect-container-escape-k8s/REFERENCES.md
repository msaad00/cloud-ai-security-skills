# References — detect-container-escape-k8s

## Standards implemented

- **MITRE ATT&CK** — pinned at v14
  - **T1611** Escape to Host — https://attack.mitre.org/techniques/T1611/
  - **T1610** Deploy Container — https://attack.mitre.org/techniques/T1610/
- **NIST CSF 2.0** — DE.CM, DE.AE — https://www.nist.gov/cyberframework

## Input format

OCSF 1.8 API Activity (class 6003) or the native enriched K8s audit shape
produced by `ingest-k8s-audit-ocsf`, plus optional Falco / Tracee runtime
records on stdin for rule 5 fusion.

The detector keys off:

- `api.operation` / `operation`
- `resources[0].type`, `resources[0].name`, `resources[0].namespace`, `resources[0].subresource`
- `unmapped.k8s.request_object`
- `unmapped.k8s.response_object`
- Falco `rule`, `output`, `output_fields.container.id`, `output_fields.k8s.ns.name`, `output_fields.k8s.pod.name`
- Tracee `eventName`, `description`, `container.id`, `kubernetes.namespace`, `kubernetes.podName`

The K8s audit API documents:

- `requestObject` is the request body recorded as JSON and is available at
  Request level and higher
- `responseObject` is the response object recorded at Response level

Source: Kubernetes audit event schema —
https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding
- MITRE ATT&CK populated inside `finding_info.attacks[]`
- Deterministic `finding_info.uid` for idempotent re-runs

## Rules

| Rule | Pattern | MITRE | Severity |
|---|---|---|---|
| R1 | `patch` introduces privileged / host namespace / risky capabilities | T1611 | Critical (5) |
| R2 | `patch` introduces risky `hostPath` mounts (`/`, `/proc`, `/var/lib/docker`, `/var/lib/containerd`) | T1611 | Critical (5) |
| R3 | `pods/ephemeralcontainers` mutation adds an ephemeral container to a running pod | T1610 | High (4) |
| R4 | `pods/exec` actor differs from the recent deploy actor and is not a declared operator | T1613 | High (4) |
| R5 | Falco / Tracee runtime breakout signals, fused on `container_id` when available | T1611 | High (4) or Critical (5) |

## Kubernetes references behind the rules

- **Audit event schema** — `requestObject`, `responseObject`, and `objectRef`
  fields are defined in the `audit.k8s.io/v1` Event schema:
  https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- **Ephemeral containers** — Kubernetes documents that ephemeral containers
  are created using a special `ephemeralcontainers` API handler rather than by
  editing `pod.spec` directly:
  https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/
- **Pod exec and attach are connect-style API requests** — Kubernetes audit
  preserves the `pods/exec` subresource so API-activity correlation can
  distinguish interactive container access from normal pod CRUD:
  https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- **hostPath warning** — Kubernetes documents that `hostPath` mounts present
  many security risks and should be avoided when possible:
  https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
- **Falco default rules** — includes `Terminal shell in container`,
  `Write below root`, and `Container Drift Detected` style signals:
  https://github.com/falcosecurity/rules
- **Tracee event catalog** — runtime event names such as `container_drift` are
  documented in the official event reference:
  https://github.com/aquasecurity/tracee/tree/main/docs/docs/events

## MITRE grounding behind the rules

- **T1611 Escape to Host** explicitly calls out privileged containers and bind
  or host mounts such as `/` or `/proc` as container-escape signals:
  https://attack.mitre.org/techniques/T1611/
- **T1610 Deploy Container** notes that adversaries may deploy privileged or
  vulnerable containers in Kubernetes to facilitate execution and then escape
  to host:
  https://attack.mitre.org/techniques/T1610/
- **T1613 Container and Resource Discovery** covers adversary activity that
  enumerates or inspects containers interactively after access is established:
  https://attack.mitre.org/techniques/T1613/

## Non-goals for this detector slice

- remediation or evidence collection
- replacing Falco / Tracee rather than consuming their events
- persistent cross-batch state outside the current input window

Those stay outside this detector's deterministic single-batch contract.

## See also

- `ingest-k8s-audit-ocsf` (sibling) — upstream producer
- `detect-privilege-escalation-k8s` (sibling) — adjacent K8s detector focused
  on RBAC abuse and secret enumeration rather than runtime escape surfaces
