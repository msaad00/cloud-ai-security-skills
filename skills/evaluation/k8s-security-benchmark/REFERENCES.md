# References — k8s-security-benchmark

## Standards implemented

- **CIS Kubernetes Benchmark** — https://www.cisecurity.org/benchmark/kubernetes
- **Kubernetes Pod Security Standards** — https://kubernetes.io/docs/concepts/security/pod-security-standards/
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework

## Kubernetes APIs read

This skill is **agentless** and consumes JSON / YAML resource exports —
either output of `kubectl get -o json`, files exported by `velero`, or any
other K8s API serialiser. It does not call the K8s API directly.

If you do want to feed it live cluster state, the simplest collection
command is:

```bash
kubectl get all,roles,rolebindings,clusterroles,clusterrolebindings,networkpolicies,secrets,configmaps -A -o json > cluster-state.json
python skills/evaluation/k8s-security-benchmark/src/checks.py cluster-state.json
```

## Required permissions (if collecting via kubectl)

A minimal viewer ClusterRole — `system:auth-delegator` is too narrow,
`view` is the right built-in:

- https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: k8s-cis-benchmark-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: ServiceAccount
  name: cis-benchmark
  namespace: kube-system
```

## What gets checked

| Check | CIS Section | What |
|---|---|---|
| Pod security standards (restricted profile) | 5.x | https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted |
| RBAC: no `cluster-admin` to `system:authenticated` | 5.1.x | https://kubernetes.io/docs/reference/access-authn-authz/rbac/ |
| Network policies present in non-system namespaces | 5.3.x | https://kubernetes.io/docs/concepts/services-networking/network-policies/ |
| Secrets not in environment variables | 5.4.x | https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod |
| Image tags pinned (no `:latest`) | 5.1.4 | https://kubernetes.io/docs/concepts/containers/images/#image-names |

The full check list is in `src/checks.py` — one function per check.
