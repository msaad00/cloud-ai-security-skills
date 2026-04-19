# References — remediate-k8s-rbac-revoke

## Kubernetes RBAC API

- RBAC overview — https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- `RoleBinding` v1 reference — https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/role-binding-v1/
- `ClusterRoleBinding` v1 reference — https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/cluster-role-binding-v1/
- Default user-facing roles (system:* prefix) — https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles
- Default core component roles (system:* prefix) — https://kubernetes.io/docs/reference/access-authn-authz/rbac/#core-components-roles
- API endpoint paths used:
  - `DELETE /apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{name}`
  - `DELETE /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}`
  - `GET /apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{name}` (re-verify)
  - `GET /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}` (re-verify)

## Python kubernetes client

- The official `kubernetes` Python client (PyPI: `kubernetes`) provides `RbacAuthorizationV1Api` with the methods this skill calls:
  - `read_namespaced_role_binding`, `delete_namespaced_role_binding`
  - `read_cluster_role_binding`, `delete_cluster_role_binding`
- Lazy import pattern: tests inject a stub implementing `KubernetesClient`; the real `KubernetesRbacClient` only imports `kubernetes` inside `_api()`.

## MITRE ATT&CK

- T1098 — Account Manipulation: https://attack.mitre.org/techniques/T1098/
- T1098.003 — Additional Cloud Roles: https://attack.mitre.org/techniques/T1098/003/ (the Kubernetes RBAC variant of this technique is what r3-rbac-self-grant catches)
- TA0003 — Persistence (the tactic the bound technique falls under): https://attack.mitre.org/tactics/TA0003/

## OCSF 1.8

- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding
- The producer (`detect-privilege-escalation-k8s`) emits class 2004 findings; this skill consumes the `observables[]` array and `metadata.product.feature.name` for source-skill provenance.
- Repo-pinned contract: [`skills/detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)

## AWS audit infrastructure (reused from container-escape)

- DynamoDB `PutItem` — https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
- S3 server-side encryption with KMS (`aws:kms`) — https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html
- Audit table schema: partition key `target_uid` (`{binding_type}/{namespace|_cluster}/{binding_name}`), sort key `action_at` (ISO-8601 UTC). Compatible with the existing `k8s-remediation-audit` table used by `remediate-container-escape-k8s`.

## Compliance frameworks

- NIST CSF 2.0 — `PR.AC-04` (Access permissions are managed, incorporating the principles of least privilege)
- SOC 2 — CC6.1 (Logical access controls), CC6.3 (Provisioning + deprovisioning)
- CIS Kubernetes Benchmark v1.9 — Control 5.1.1 (Ensure that the cluster-admin role is only used where required)

## Repo-internal contracts this skill conforms to

- [`SECURITY_BAR.md`](../../../SECURITY_BAR.md) — 11-principle contract; this skill satisfies all destructive-write principles
- [`docs/HITL_POLICY.md`](../../../docs/HITL_POLICY.md) — `human_required` approval model with `min_approvers: 1`
- [`scripts/validate_safe_skill_bar.py`](../../../scripts/validate_safe_skill_bar.py) — enforces dry-run default, deny-list presence, IAM/RBAC scoping
