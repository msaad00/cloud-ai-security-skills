# References — cspm-gcp-cis-benchmark

## Standards implemented

- **CIS GCP Foundations Benchmark v3.0** — https://www.cisecurity.org/benchmark/google_cloud_computing_platform
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework
- **ISO/IEC 27001:2022** — https://www.iso.org/standard/27001

The full v3.0 benchmark has 80+ controls. This skill implements **7
high-impact checks** that cover the most common findings on real GCP
projects. The remaining controls are tracked in the Roadmap section of
[`SKILL.md`](SKILL.md).

## GCP APIs read

| Section | API | Method | Why |
|---|---|---|---|
| IAM | Cloud Resource Manager v3 | `projects.getIamPolicy` | Personal Gmail principals (CIS 1.1) |
| IAM | IAM Admin v1 | `serviceAccounts.list`, `serviceAccounts.keys.list` | Service-account key audit (CIS 1.3, 1.4) |
| Storage | Cloud Storage JSON v1 | `buckets.list`, `buckets.getIamPolicy` | Public bucket detection (CIS 2.3), uniform access (CIS 2.1) |
| Compute | Compute Engine v1 | `firewalls.list`, `subnetworks.list` | Unrestricted SSH/RDP (CIS 4.2), VPC flow logs (CIS 4.3) |

## Required permissions

Two GCP-managed roles cover everything:

- `roles/viewer` — https://cloud.google.com/iam/docs/understanding-roles#viewer
- `roles/iam.securityReviewer` — https://cloud.google.com/iam/docs/understanding-roles#iam.securityReviewer

If you want a custom role, the minimal permission set is:

```
resourcemanager.projects.getIamPolicy
iam.serviceAccounts.list
iam.serviceAccountKeys.list
storage.buckets.list
storage.buckets.getIamPolicy
compute.firewalls.list
compute.subnetworks.list
```

## SDKs

- **google-cloud-resource-manager** — https://cloud.google.com/python/docs/reference/cloudresourcemanager/latest
- **google-cloud-iam** — https://cloud.google.com/python/docs/reference/iam/latest
- **google-cloud-storage** — https://cloud.google.com/python/docs/reference/storage/latest
- **google-cloud-compute** — https://cloud.google.com/python/docs/reference/compute/latest

Authentication uses Application Default Credentials
(https://cloud.google.com/docs/authentication/application-default-credentials),
so the skill works locally with `gcloud auth application-default login`
and in GCE / GKE / Cloud Run / Cloud Functions without code changes.
