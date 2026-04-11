# References — detect-privilege-escalation-k8s

## Standards implemented

- **MITRE ATT&CK** — pinned at v14
  - **T1552.007** Unsecured Credentials: Container API — https://attack.mitre.org/techniques/T1552/007/
  - **T1611** Escape to Host — https://attack.mitre.org/techniques/T1611/
  - **T1098** Account Manipulation — https://attack.mitre.org/techniques/T1098/
  - **T1550.001** Use Alternate Authentication Material: Application Access Tokens — https://attack.mitre.org/techniques/T1550/001/
- **NIST CSF 2.0** — DE.CM, DE.AE — https://www.nist.gov/cyberframework

## Input format

OCSF 1.8 API Activity (class 6003) as produced by `ingest-k8s-audit-ocsf`.
The skill keys off:

- `class_uid == 6003`
- `actor.user.type == "ServiceAccount"` (rules 1, 2, 4)
- `api.operation` (the K8s verb)
- `resources[0].type` and `resources[0].subresource` (the K8s resource and subresource)
- `actor.user.groups[]` (rule 3 admin check)

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding
- MITRE ATT&CK populated inside `finding_info.attacks[]` per the OCSF 1.8 contract
- Deterministic `finding_info.uid` for idempotent re-runs

## Rules

| Rule | Pattern | MITRE | Severity | Window |
|---|---|---|---|---|
| R1 | SA `list secrets` then `get secrets` in same namespace | T1552.007 | High (4) | 5 min sliding |
| R2 | SA `create pods/exec` (subresource) | T1611 | Critical (5) | none (single event) |
| R3 | non-admin `create rolebindings` or `clusterrolebindings` | T1098 | Critical (5) | none |
| R4 | SA `create serviceaccounts/token{,request}` or `tokenreviews` | T1550.001 | High (4) | none |

## Admin allow-list (Rule 3)

The `_is_admin` helper treats these as legitimate binders and skips them:

- Username `kubernetes-admin` or `kube-admin`
- Membership in group `system:masters`

To extend the allow-list (e.g. for a custom break-glass user), edit
`ADMIN_USERS` and `ADMIN_GROUPS` at the top of `src/detect.py`. The
test suite will catch over-broad allow-lists via the
`test_non_admin_*_fires` tests.

## Required permissions

None. Reads OCSF JSONL from stdin.

## Window semantics

Rule 1 uses a sliding 5-minute window (`RULE1_WINDOW_MS = 5 * 60 * 1000`).
The detector is **stateless across invocations** — if a `list` and `get`
straddle two pipeline runs, the correlation is lost. A future PR will add
optional state persistence to a small JSON file for streaming use.

## Reference attack chains

- **Pod compromise → secret exfil** — pod runs as a SA with `secrets:get/list`
  on its namespace; attacker uses Rule 1 to find and steal credentials.
  Mitigation: pod security standards + secret-mount-only access.
- **Container escape via exec** — pod with broad RBAC (`pods/exec`) is
  used to drop into another pod and pivot. Mitigation: deny `pods/exec`
  on workload SAs (Rule 2 detects the attempt).
- **RBAC self-grant** — compromised SA creates a `ClusterRoleBinding`
  that binds itself to `cluster-admin`. Mitigation: admission webhook +
  PSA restricted profile (Rule 3 detects the attempt).
- **Token theft via TokenRequest** — compromised SA issues a fresh
  bearer token for itself or another SA, which the attacker exfiltrates.
  Rule 4 detects.

## See also

- `OCSF_CONTRACT.md` (sibling) — wire format
- `ingest-k8s-audit-ocsf` (sibling) — upstream producer
- Kubernetes Pod Security Standards — https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Falco rules (the closest open-source comparison) — https://github.com/falcosecurity/rules
