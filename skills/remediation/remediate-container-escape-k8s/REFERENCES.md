# References — remediate-container-escape-k8s

## Kubernetes APIs and security guidance

- **Kubernetes NetworkPolicy** — https://kubernetes.io/docs/concepts/services-networking/network-policies/
  - `networking.k8s.io/v1` `NetworkPolicy`
  - empty `ingress` + empty `egress` with `policyTypes: [Ingress, Egress]` is
    the deny-all quarantine shape used by this skill
- **Kubernetes Ephemeral Containers** — https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/
  - ephemeral containers are added through the `pods/ephemeralcontainers`
    subresource commonly used by `kubectl debug`
- **Kubernetes Pod Security Standards** — https://kubernetes.io/docs/concepts/security/pod-security-standards/
  - `privileged`, host namespaces, and added Linux capabilities are explicitly
    higher-risk controls
- **Kubernetes Volumes: hostPath** — https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
  - warns that `hostPath` mounts expose privileged host resources and should be
    avoided unless absolutely necessary
- **Kubernetes Volume Snapshots** — https://kubernetes.io/docs/concepts/storage/volume-snapshots/
  - CSI `VolumeSnapshot` objects are the portable snapshot primitive this
    forensic collector can optionally create for PVC-backed pod volumes
- **Kubernetes Logging Architecture** — https://kubernetes.io/docs/concepts/cluster-administration/logging/
  - container logs under `/var/log/containers/` and `/var/log/pods/` are the
    runtime-log sources bundled by the collector

## OCSF wire format

- **OCSF 1.8 Detection Finding (class 2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding
  - input consumed by this skill

## Threat framework

- **MITRE ATT&CK T1611 Escape to Host** — https://attack.mitre.org/techniques/T1611/
- **MITRE ATT&CK T1610 Deploy Container** — https://attack.mitre.org/techniques/T1610/
- **MITRE ATT&CK M1042 Disable or Remove Feature or Program** — https://attack.mitre.org/mitigations/M1042/

## AWS APIs for dual audit

- **Amazon S3 PutObject** — https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
- **Amazon DynamoDB PutItem** — https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_PutItem.html
- **AWS KMS GenerateDataKey / Decrypt** — https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html

## Required Kubernetes RBAC / AWS IAM

Minimal Kubernetes permissions for the skill runtime:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "replicationcontrollers"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["deployments", "daemonsets", "statefulsets", "replicasets"]
    verbs: ["get"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "create", "update"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshots"]
    verbs: ["create", "get"]
```

Minimal AWS IAM for audit writes:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WriteAuditToDynamoDB",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem"],
      "Resource": "arn:aws:dynamodb:*:*:table/${K8S_REMEDIATION_AUDIT_DYNAMODB_TABLE}"
    },
    {
      "Sid": "WriteAuditToS3",
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::${K8S_REMEDIATION_AUDIT_BUCKET}/container-escape/audit/*"
    },
    {
      "Sid": "KmsForAuditObjects",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "${KMS_KEY_ARN}",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.${AWS_REGION}.amazonaws.com"
        }
      }
    }
  ]
}
```

## Closed-loop verification contract

The skill's `--apply` path emits a native `remediation_action` record and
dual-audits the mutation. The `--reverify` path reads the expected
`NetworkPolicy` back and emits `remediation_verification` with `status:
verified` or `status: drift`. This keeps the quarantine proof local to the
operator-owned audit loop.
