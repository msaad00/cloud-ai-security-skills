# References — gpu-cluster-security

## Standards implemented

- **MITRE ATT&CK** — T1610 Deploy Container, T1611 Escape to Host, T1078.004 Cloud Accounts
  https://attack.mitre.org/techniques/T1610/
  https://attack.mitre.org/techniques/T1611/
- **CIS Kubernetes Benchmark** — https://www.cisecurity.org/benchmark/kubernetes
- **NIST CSF 2.0** — PR.AC-3, PR.AC-4, PR.PT-3 — https://www.nist.gov/cyberframework
- **NVIDIA Container Toolkit security guidance** — https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/

## Inputs

Pure config analysis. The skill consumes JSON or YAML describing your
GPU cluster:

- Kubernetes Pod / Node / NetworkPolicy export (`kubectl get -o json`)
- NVIDIA device plugin config
- DCGM exporter config
- InfiniBand subnet manager config

Does not call any NVIDIA API. Does not require GPU access.

## What gets checked (13 controls across 6 domains)

| Domain | Controls | Reference |
|---|---|---|
| Container runtime | Non-root, dropped caps, no privileged | https://kubernetes.io/docs/concepts/security/pod-security-standards/ |
| GPU driver | CVE-tracked driver version pinning | https://nvidia.custhelp.com/app/answers/list/page/1/c/2902 |
| Network | InfiniBand subnet partitioning, no host network | https://docs.nvidia.com/networking/ |
| Storage | Encrypted model artifacts, no host path mounts | https://kubernetes.io/docs/concepts/storage/volumes/#hostpath |
| Tenant isolation | Namespace-per-tenant, distinct GPU resource quotas | https://kubernetes.io/docs/tasks/administer-cluster/manage-resources/quota-memory-cpu-namespace/ |
| Observability | DCGM exporter present, GPU metrics scraped | https://github.com/NVIDIA/dcgm-exporter |

The full check list is in `src/checks.py`.

## NVIDIA-specific references

- **CDI (Container Device Interface)** — https://github.com/cncf-tags/container-device-interface
- **NVIDIA Container Toolkit** — https://github.com/NVIDIA/nvidia-container-toolkit
- **NVIDIA Multi-Instance GPU (MIG)** — https://docs.nvidia.com/datacenter/tesla/mig-user-guide/
