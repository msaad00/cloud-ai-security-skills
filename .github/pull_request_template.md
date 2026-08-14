<!-- Keep PRs small and single-purpose. Delete sections that don't apply. -->

## What & why

<!-- One or two sentences: what changes, and the reason. Link the issue: Closes #NNN -->

## Layer(s) touched

<!-- Check all that apply -->

- [ ] ingestion (raw → OCSF 1.8)
- [ ] discovery (inventory / graph / AI BOM / evidence)
- [ ] detection (OCSF → Detection Finding 2004)
- [ ] evaluation (posture / benchmark checks)
- [ ] view (OCSF → rendered format)
- [ ] remediation (gated write workflow)
- [ ] output (append-only sink)
- [ ] shared / infra / docs / CI

## Safety checklist

<!-- Remediation and any write-capable change MUST tick the first four. -->

- [ ] Read-only by default; no new wildcard IAM or `sts:AssumeRole` outside the org boundary
- [ ] Dry-run path preserved; destructive actions stay HITL-gated per `docs/HITL_POLICY.md`
- [ ] No hardcoded credentials; secrets via env / Secrets Manager / SSM
- [ ] Untrusted input (findings, manifests, events) validated before use
- [ ] Golden fixtures / contract tests updated if the OCSF shape changed

## Verification

<!-- Paste the commands you actually ran and their result. "should work" is not enough. -->

```
make validate && make test
```

<!-- Screenshots for any README/diagram change. -->
