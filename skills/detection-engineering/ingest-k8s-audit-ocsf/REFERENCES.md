# References — ingest-k8s-audit-ocsf

## Source format

- **Kubernetes audit policy + event reference** — https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- **`audit.k8s.io/v1` Event schema** — https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- **Audit policy levels** (None / Metadata / Request / RequestResponse) — https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#audit-policy
- **Audit stages** (RequestReceived / ResponseStarted / ResponseComplete / Panic) — https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#audit-backends

## Output format

- **OCSF 1.8 API Activity (class 6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 actor / user / group objects** — https://schema.ocsf.io/1.8.0/objects/user
- **OCSF 1.8 resource object** — https://schema.ocsf.io/1.8.0/objects/resource

## Required permissions (collection)

The skill itself reads from stdin or a file — no cluster access. To
collect audit logs there are three common patterns:

1. **Log backend** — `kube-apiserver --audit-log-path=/var/log/k8s-audit.log` writes to the node filesystem. You need read access to that file on the control-plane nodes. https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#log-backend
2. **Webhook backend** — `kube-apiserver --audit-webhook-config-file=…` POSTs each event to a webhook. Webhook receiver needs HTTPS endpoint + mTLS cert. https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#webhook-backend
3. **Managed cluster forwarding** — EKS (CloudWatch), GKE (Cloud Logging), AKS (Log Analytics) forward audit events automatically. Read access to the log destination is all you need.

## K8s verb reference

The K8s API supports these verbs, all of which the skill classifies:
https://kubernetes.io/docs/reference/access-authn-authz/authorization/#determine-the-request-verb

```
get, list, watch, create, update, patch, delete, deletecollection,
proxy, connect, bind
```

`connect` and `bind` fall to `OTHER` (activity_id 99) because they don't
fit CRUD cleanly. The full verb table is in `src/ingest.py` (`_VERB_MAP`).

## Service account username format

The `system:serviceaccount:<namespace>:<name>` format is part of the K8s
authentication contract:
https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens

The skill uses this format to populate `actor.user.type = "ServiceAccount"`
and the custom `k8s.service_account_namespace` field that
`detect-privilege-escalation-k8s` pivots on.

## See also

- `OCSF_CONTRACT.md` (sibling) for the per-skill wire contract
- `detect-privilege-escalation-k8s` (sibling) — the downstream detector that consumes this skill's output
