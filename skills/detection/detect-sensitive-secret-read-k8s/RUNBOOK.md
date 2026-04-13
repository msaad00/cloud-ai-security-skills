# Runbook — detect-sensitive-secret-read-k8s

What to do when this detector fires. Written for an on-caller at 2am who has the SARIF result in front of them and needs to decide fast.

## Triage — first 5 minutes

1. **Pull the finding.** `finding_info.uid` identifies it; `finding_info.desc` gives you the one-line summary. The `observables[]` array has:
   - `actor.name` — the service account or user that read the secret
   - `namespace` — the K8s namespace
   - `secret.name` — which secret
   - `matched_patterns` — which sensitive-name patterns fired
   - `verb` — `get` or `list`

2. **Is the actor a service account?** Check `actor.name` — if it starts with `system:serviceaccount:`, it's a workload. If it's a human name (e.g. `kube-admin`), it's a user.

3. **Is the secret a credential?** Look at `matched_patterns`. Patterns like `aws-*`, `*api-key*`, `*token*` are high-confidence credentials. Patterns like `*-tls` are keys but usually less sensitive.

4. **Is this a known-good workflow?** Some workloads legitimately need to read credentials via the API — e.g. a secrets-sync controller, an external-secrets-operator, a cert-manager solver, a Vault agent injector. Check the `actor.name` against your cluster's allow-list of secret-reading SAs.

## Common scenarios

### Scenario A: legitimate secrets-sync workload

**Signal:** actor is a well-known SA like `system:serviceaccount:external-secrets:external-secrets`, `cert-manager/cert-manager`, or `vault-secrets-operator/vault-secrets-operator`.

**Action:** verify the workload is running an expected image and version. Add the SA to your allow-list by extending the detector with a filter (not yet implemented — file a tracking issue for `--exclude-actor` flag). For now, acknowledge the finding and document the exception.

### Scenario B: application workload needs to read a secret

**Signal:** actor is an app SA (`system:serviceaccount:<your-namespace>:<your-app>`). The app mounts the secret as a file but also calls the K8s API to read it.

**Action:** this is a common anti-pattern. Move the secret read to a file mount and remove the runtime API read. The app should work from the mounted file alone. If your app genuinely needs the API read (e.g. it has to react to secret rotation), use a Kubernetes secret-watching client library that reads the mounted file and reloads, not the API.

### Scenario C: suspicious SA reads cloud credentials

**Signal:** actor is a workload SA, `matched_patterns` contains `aws-*`, `gcp-*`, `azure-*`, or `*-access*`, and you don't recognise the actor as a known secrets-sync tool.

**Action:** **treat as compromise until proven otherwise.**
1. Identify the pod(s) running under this SA: `kubectl get pods -n <namespace> -o json | jq '.items[] | select(.spec.serviceAccountName == "<sa-name>") | .metadata.name'`
2. Get the image digest of each pod: `kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].image}'`
3. Check image provenance: was it pulled from the expected registry? Signed? Recent build?
4. If suspicious, **isolate the namespace** with a deny-all NetworkPolicy and delete the pods
5. Rotate the cloud credential that was read (the secret is now considered exposed)
6. Check audit logs for any subsequent use of the credential (CloudTrail / GCP audit / Azure activity — you already have the ingestion skills for those in this repo)

### Scenario D: admin user reads a TLS cert

**Signal:** actor is a human user (`kube-admin`, a named engineer), secret matches `*-tls` or `*.pem`.

**Action:** low urgency but still worth logging. Ask the engineer why they needed the cert. If it's a debug session, fine. If they downloaded and kept it, rotate the cert as a precaution and establish a lesson-learned that cluster TLS material doesn't leave the cluster.

### Scenario E: rapid sensitive-secret reads across many secrets

**Signal:** multiple findings, same actor, different secrets, short time window.

**Action:** **treat as compromise.** This is the targeted-read variant of Rule 1 enumeration. Same playbook as scenario C, plus:
1. Check `detect-privilege-escalation-k8s` findings for the same actor in the same window — if you see Rule 2 (`pods/exec`) or Rule 3 (RBAC self-grant) from the same actor, the attacker has already pivoted
2. Dump the pod's network connections via eBPF / flow logs and check for exfiltration
3. Page the incident responder

## How to suppress false positives

If a workload legitimately needs to read credentials via the API:

1. **Short term:** acknowledge the finding and document the exception in your incident tracker
2. **Medium term:** extend the detector with a `--exclude-actor` flag (file a PR against this repo's detector) to filter out known-good actors
3. **Long term:** architect the workload to mount secrets as files — the K8s secrets API should not be the credential read path at runtime

## How to tune the detector

The default `SENSITIVE_NAME_PATTERNS` in `src/detect.py` is deliberately conservative. If your environment uses different naming conventions, add your patterns at runtime:

```bash
python src/detect.py \
  --sensitive-pattern "*-mfa-seed" \
  --sensitive-pattern "stripe-*" \
  --sensitive-pattern "segment-*"
```

Or, for permanent additions, edit `SENSITIVE_NAME_PATTERNS` directly and re-run the tests.

## Related

- [`detect-privilege-escalation-k8s`](../detect-privilege-escalation-k8s/) — Rule 1 catches enumeration-then-read; this skill catches targeted reads
- [`ingest-k8s-audit-ocsf`](../ingest-k8s-audit-ocsf/) — the upstream producer
- [Kubernetes Secrets best practices](https://kubernetes.io/docs/concepts/configuration/secret/#best-practices) — why mounting as files is the intended pattern
