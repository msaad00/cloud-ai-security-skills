# References — discover-environment

## Standards implemented

- **MITRE ATT&CK** — Enterprise (cloud + container matrices) — https://attack.mitre.org/matrices/enterprise/
- **MITRE ATLAS** — adversarial ML technique catalog — https://atlas.mitre.org/
- **NIST CSF 2.0** — ID.AM (Asset Management) — https://www.nist.gov/cyberframework

## Inputs

Two modes:

1. **Live discovery** — call cloud SDKs against the target account / project / subscription using viewer credentials.
2. **Static config** — read a JSON file describing the environment (useful in CI for reproducible scans).

## Cloud APIs read (live mode)

| Cloud | API | Purpose |
|---|---|---|
| AWS | EC2, IAM, S3, RDS, Lambda, ECS, EKS, GuardDuty | Resource inventory |
| GCP | Resource Manager, Compute, IAM, Storage, GKE, BigQuery | Resource inventory |
| Azure | Resource Graph, Storage, Network, Compute, AKS | Resource inventory |

## Required permissions

- **AWS** — `SecurityAudit` managed policy https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html
- **GCP** — `roles/viewer` + `roles/iam.securityReviewer` https://cloud.google.com/iam/docs/understanding-roles
- **Azure** — Reader role https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general#reader

## Output

Graph JSON with three node kinds and edges between them:

- **Resources** — EC2 instances, GCS buckets, Azure VMs, K8s pods, etc.
- **Identities** — IAM principals, service accounts, K8s service accounts
- **Networks** — VPCs, subnets, security groups, network policies

Edges carry MITRE ATT&CK technique IDs where the relationship represents a known attack vector (e.g. an IAM role with `iam:PassRole` to a high-privilege role gets a `T1098` edge).

## SDKs

- **boto3** — https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
- **google-cloud-asset** — https://cloud.google.com/python/docs/reference/cloudasset/latest
- **azure-mgmt-resource** — https://learn.microsoft.com/en-us/python/api/overview/azure/resources

## Graph format

Internal format documented in `src/discover.py` (`Node`, `Edge` dataclasses). Future PR will add an `OCSF Inventory Info (5001)` exporter so the graph composes with `detection-engineering/` skills via the same OCSF wire format.
