# Kubernetes end-to-end detection pipeline (example)

This file documents the **full closed-loop Kubernetes detection pipeline**
composed from the skills that live in `skills/detection-engineering/`.
Copy-paste any of the blocks below into a shell or a CI step — they work
as-is against the frozen golden fixtures.

## The layers

```
raw kube-apiserver audit log
        │
        │ Layer 1: ingestion
        ▼
ingest-k8s-audit-ocsf                 → OCSF API Activity (class 6003)
        │
        │ Layer 3: detection (two skills in parallel)
        ▼
detect-privilege-escalation-k8s       → OCSF Detection Finding (2004)
                                         T1552.007 enumeration
                                         T1611 pod exec
                                         T1098 RBAC self-grant
                                         T1550.001 token self-grant
detect-sensitive-secret-read-k8s      → OCSF Detection Finding (2004)
                                         T1552.007 targeted read
        │
        │ Layer 5: view / convert (cross-vendor, built once)
        ▼
convert-ocsf-to-sarif                 → SARIF 2.1.0 → GitHub Security tab
convert-ocsf-to-mermaid-attack-flow   → Mermaid     → PR comments
```

Every hop speaks **OCSF 1.8 JSONL** on the wire. Every finding carries
**MITRE ATT&CK v14** inside `finding_info.attacks[]`. Every view output
describes the same underlying detection.

## Usage — run each detector

```bash
# Priv-esc chain: list → get → exec → CRB → token
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py k8s-audit.log \
  | python skills/detection/detect-privilege-escalation-k8s/src/detect.py \
  > findings-priv-esc.ocsf.jsonl

# Targeted sensitive-secret reads
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py k8s-audit.log \
  | python skills/detection/detect-sensitive-secret-read-k8s/src/detect.py \
  > findings-secret-read.ocsf.jsonl
```

## Usage — run both detectors and merge findings

```bash
# Ingest once, branch to both detectors, merge OCSF findings
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py k8s-audit.log > events.ocsf.jsonl

{
  python skills/detection/detect-privilege-escalation-k8s/src/detect.py < events.ocsf.jsonl
  python skills/detection/detect-sensitive-secret-read-k8s/src/detect.py < events.ocsf.jsonl
} > all-k8s-findings.ocsf.jsonl
```

## Usage — full closed loop → SARIF → GitHub Security tab

```bash
# Produce SARIF from the merged findings
python skills/view/convert-ocsf-to-sarif/src/convert.py \
  < all-k8s-findings.ocsf.jsonl \
  > k8s-findings.sarif

# Upload to GitHub code scanning (from a CI step)
gh api repos/:owner/:repo/code-scanning/sarifs \
  --input k8s-findings.sarif \
  --field commit_sha="$(git rev-parse HEAD)" \
  --field ref=refs/heads/main
```

Or, in a GitHub Action step:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: k8s-findings.sarif
    category: k8s-detection-engineering
```

## Usage — Mermaid attack flow → PR comment

```bash
python skills/view/convert-ocsf-to-mermaid-attack-flow/src/convert.py \
  --fenced \
  < all-k8s-findings.ocsf.jsonl \
  > attack-flow.md

# Post to a PR via gh
gh pr comment <PR-NUM> --body-file attack-flow.md
```

The `--fenced` flag wraps the output in a ` ```mermaid ... ``` ` block so
it renders inline in the PR comment on GitHub.

## Usage — pipe directly end-to-end (no intermediate files)

The whole thing works as one shell pipe:

```bash
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py k8s-audit.log \
  | tee >(python skills/detection/detect-privilege-escalation-k8s/src/detect.py >/tmp/priv-esc.ocsf.jsonl) \
  | python skills/detection/detect-sensitive-secret-read-k8s/src/detect.py \
  | { cat /tmp/priv-esc.ocsf.jsonl; cat; } \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py \
  > k8s-findings.sarif
```

(The `tee >(...)` split runs priv-esc in a background process; the
foreground pipe runs sensitive-secret-read. Both outputs concatenate
before the SARIF converter.)

## Expected output on the golden fixture

Running the full pipe over `skills/detection-engineering/golden/k8s_audit_raw_sample.jsonl`:

- **3 priv-esc findings** (T1552.007 list+get, T1611 pod exec, T1098 RBAC self-grant)
- **1 sensitive-secret-read finding** (`db-password` matches `*password*` pattern)
- Total: **4 OCSF Detection Findings** across both detectors
- SARIF output has **4 results** and **2 deduplicated rules** (T1552 and T1611/T1098 — priv-esc and secret-read both use T1552 so the rule is shared, and T1611/T1098 are the other two techniques)

(Note: the `k8s_audit_raw_sample.jsonl` fixture's `db-password` name
matches the `*password*` pattern. Running this pipe against a different
fixture gives different counts.)

## What fires on what

| Event pattern in the audit log | `detect-privilege-escalation-k8s` | `detect-sensitive-secret-read-k8s` |
|---|---|---|
| `list` secrets then `get` secret X in same namespace, same SA, < 5 min | ✅ Rule 1 (T1552.007) | ✅ if X matches a sensitive pattern |
| Direct `get` on sensitive secret name, no preceding list | ❌ (no list to correlate with) | ✅ (name-pattern match) |
| SA `create` on `pods/exec` subresource | ✅ Rule 2 (T1611) | ❌ (different resource) |
| Non-admin `create` on `clusterrolebindings` | ✅ Rule 3 (T1098) | ❌ |
| SA `create` on `serviceaccounts/token` | ✅ Rule 4 (T1550.001) | ❌ |
| `watch` on secrets | ❌ (not a read verb Rule 1 cares about) | ❌ (watch excluded) |
| Admin reads sensitive secret | ❌ (Rule 1 filters to SA actors only) | ✅ (pattern match is actor-agnostic) |

The two skills together give near-complete coverage of the credential-access layer of K8s threats without overlap: Rule 1 catches enumeration behaviour, and this skill catches targeted lookups.
