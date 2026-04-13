# References — detect-sensitive-secret-read-k8s

## Standards implemented

- **MITRE ATT&CK v14** (pinned)
  - **T1552** Unsecured Credentials — https://attack.mitre.org/techniques/T1552/
  - **T1552.007** Unsecured Credentials: Container API — https://attack.mitre.org/techniques/T1552/007/
- **NIST CSF 2.0** — DE.CM, PR.AC-1 — https://www.nist.gov/cyberframework
- **Kubernetes Pod Security Standards** — https://kubernetes.io/docs/concepts/security/pod-security-standards/

## Input format

OCSF 1.8 API Activity (class 6003) produced by `ingest-k8s-audit-ocsf`. Keys off:

- `class_uid == 6003`
- `api.operation` ∈ {`get`, `list`}
- `resources[0].type == "secrets"`
- `resources[0].name` matches a sensitive pattern

## Output format

- **OCSF 1.8 Detection Finding** (class `2004`) — https://schema.ocsf.io/1.8.0/classes/detection_finding
- **Attack object** — https://schema.ocsf.io/1.8.0/objects/attack
- MITRE ATT&CK populated **inside `finding_info.attacks[]`** per the OCSF 1.8 contract

## Why name-based detection

Kubernetes secrets are opaque at the API-audit layer — the audit log carries the `objectRef.name` but not the secret's type annotation or its contents. Name-based pattern matching is the highest-signal stateless detection you can run on `Metadata`-level audit logs (the most common cluster audit policy, because `Request`/`RequestResponse` levels are expensive and retain secret material).

This skill is **complementary** to [`detect-privilege-escalation-k8s`](../detect-privilege-escalation-k8s/) Rule 1 (list + get enumeration). Rule 1 catches workloads that enumerate-then-read. This skill catches targeted reads where the attacker already knows the secret name — no list step, no window.

## Required permissions

None at runtime. Reads OCSF JSONL from stdin.

Upstream `ingest-k8s-audit-ocsf` needs read access to kube-apiserver audit logs (file backend, webhook backend, or managed-cluster forwarding). See [`../ingest-k8s-audit-ocsf/REFERENCES.md`](../ingest-k8s-audit-ocsf/REFERENCES.md).

## Default sensitive-name patterns

The full list is in `src/detect.py` as `SENSITIVE_NAME_PATTERNS`. Categories:

| Category | Rationale |
|---|---|
| `*credential*`, `*creds*`, `*password*` | Generic credential names |
| `*token*`, `*-token` | Bearer / SA / OAuth tokens |
| `*api-key*`, `*apikey*`, `*api_key*` | API keys |
| `aws-*`, `*aws-access*`, `*aws-creds*` | AWS access keys |
| `gcp-*`, `*service-account-key*` | GCP service account JSON keys |
| `azure-*`, `*azure-creds*` | Azure credentials |
| `dockerconfig*`, `*dockerconfigjson*` | Registry pull secrets |
| `*.pem`, `*.key`, `*private-key*`, `*signing-key*` | Asymmetric key material |
| `*-tls`, `tls-*` | TLS material (tight — doesn't match mid-name `-tls-`) |
| `kube-root-ca*` | Cluster root CA |

Pattern matching is **case-insensitive** `fnmatch`-style glob. Users can add patterns at runtime with `--sensitive-pattern "foo-*"` (repeatable).

## What does NOT fire (negative controls, tested)

- `watch` verb — watches establish long-lived streams, different TTP
- `create` / `update` / `delete` — this skill is read-only detection
- `list` with no specific `name` — enumeration pattern, covered by `detect-privilege-escalation-k8s` Rule 1
- Non-`secrets` resource types (`configmaps`, `pods`, `deployments`, etc.)
- Benign secret names that don't match any pattern (`my-app-config`, `feature-flags`, `nginx-conf`)

## Reference attack chains

- **Supply-chain-compromised sidecar**: sidecar injected via a compromised base image reads `aws-access-key` from its pod's namespace. Rule 1 of `detect-privilege-escalation-k8s` won't fire (no preceding `list`); this skill catches it.
- **Credential rotation poisoning**: a compromised CI/CD workload reads `*-token` secrets to fingerprint which services it should target next. Rule 2 (pod exec) won't fire; this skill does.
- **Token exfiltration via init container**: init container in a cluster-admin namespace reads all `*-tls` secrets during startup. Stateless detection catches every instance individually.

## See also

- [`OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — the wire contract this skill conforms to
- [`detect-privilege-escalation-k8s`](../detect-privilege-escalation-k8s/) — complementary enumeration-style detector
- [`ingest-k8s-audit-ocsf`](../ingest-k8s-audit-ocsf/) — upstream producer
- Kubernetes Secrets best practices — https://kubernetes.io/docs/concepts/configuration/secret/#best-practices
- Falco equivalent rules (the closest open-source comparison) — https://github.com/falcosecurity/rules
