# Examples — iam-departures-azure-entra

Three workflows: dry-run plan, applied soft-delete, and re-verify.

## 1. Dry-run plan (default, safe)

```bash
python skills/remediation/iam-departures-azure-entra/src/function_parser/handler.py \
  skills/remediation/iam-departures-azure-entra/examples/manifest.json
```

The parser reads the manifest, applies the rehire + grace-period filter, and prints one JSON line per entry to stdout describing whether it would be remediated. No Azure API calls are made.

```jsonl
{"action":"remediate","entry":{"upn":"former-employee-1@acme.example", ...}}
{"action":"skip","reason":"Within grace period (3d < 7d)","entry":{"upn":"former-employee-2@acme.example", ...}}
{"action":"skip","reason":"Rehired employee — Entra user used after rehire date (same user in use)","entry":{"upn":"rehired-1@acme.example", ...}}
{"action":"skip","reason":"Entra user already deleted","entry":{"upn":"former-employee-3@acme.example", ...}}
```

The worker also has a dry-run path that lists the 11 steps it **would** take per validated entry, without calling Microsoft Graph or Azure RBAC.

## 2. Applied soft-delete (default — `accountEnabled=false` + audit tag, NO hard delete)

Out-of-band approval first: open an incident, get a security-lead approver to record an `IAM_DEPARTURES_AZURE_INCIDENT_ID` and `IAM_DEPARTURES_AZURE_APPROVER` value. Both env vars are required before `--apply` will fire.

```bash
export IAM_DEPARTURES_AZURE_INCIDENT_ID=INC-2026-04-20-001
export IAM_DEPARTURES_AZURE_APPROVER=alice@security
export AZURE_TENANT_ID=11111111-2222-3333-4444-555555555555
export AZURE_CLIENT_ID=66666666-7777-8888-9999-000000000000
export AZURE_CLIENT_SECRET=...                                # via Key Vault reference in production
export IAM_DEPARTURES_AZURE_AUDIT_COSMOS_ACCOUNT=acme-iam-departures
export IAM_DEPARTURES_AZURE_AUDIT_COSMOS_DATABASE=audit
export IAM_DEPARTURES_AZURE_AUDIT_COSMOS_CONTAINER=actions
export IAM_DEPARTURES_AZURE_AUDIT_BLOB_ACCOUNT=acmeiamdeparturesaudit
export IAM_DEPARTURES_AZURE_AUDIT_BLOB_CONTAINER=audit
export IAM_DEPARTURES_AZURE_KEY_VAULT_KEY_ID=https://kv-acme-iam.vault.azure.net/keys/audit-cmk/abc
export IAM_DEPARTURES_AZURE_MANAGEMENT_GROUP_ID=mg-acme-prod

python skills/remediation/iam-departures-azure-entra/src/function_worker/handler.py \
  skills/remediation/iam-departures-azure-entra/examples/manifest.json --apply
```

Expected behaviour per entry:

1. `accountEnabled=false` set on the user
2. all sign-in sessions revoked (refresh tokens invalidated)
3. all OAuth2 permission grants deleted
4. all group memberships removed
5. all directoryRole memberships removed
6. all appRoleAssignments deleted
7. Azure RBAC role assignments at subscription scope detached
8. Azure RBAC role assignments at management-group + resource-group scope detached
9. assigned licenses removed
10. user tagged with `extension_audit_remediated_at`
11. **Soft delete only** — the user object is left in place so the next reconciler run can still see and audit it. Hard delete (`DELETE /users/{id}`) is opt-in.

Each step writes a Cosmos DB row + a Blob Storage evidence object BEFORE and AFTER the action. The before-row records the planned step; the after-row records the result (success / failure / skipped). Failures still write an audit row.

## 3. Hard delete (opt-in)

```bash
# After the soft-delete pass has been audit-reviewed
python skills/remediation/iam-departures-azure-entra/src/function_worker/handler.py \
  skills/remediation/iam-departures-azure-entra/examples/manifest.json --apply --hard-delete
```

`--hard-delete` is independent of `--apply` — running with only `--hard-delete` (no `--apply`) is rejected. The hard-delete path replaces step 11 from "tag and leave" with `DELETE /users/{id}`.

## 4. Re-verify (read-only, no Azure write)

```bash
python skills/remediation/iam-departures-azure-entra/src/function_worker/handler.py \
  skills/remediation/iam-departures-azure-entra/examples/manifest.json --reverify
```

For each entry the worker re-reads the user via Microsoft Graph and emits one verification record:

- `VERIFIED` — user is `accountEnabled=false` (soft-delete) or absent (hard-delete already ran)
- `DRIFT` — user was re-enabled (`accountEnabled=true`); a paired OCSF Detection Finding is emitted
- `UNREACHABLE` — Microsoft Graph call raised; cannot determine state

`--reverify` does not write Cosmos / Blob audit rows; the verification record itself is the audit artifact.

## 5. End-to-end via the Azure orchestration stack

In production the parser + worker are not invoked by hand. The flow is:

1. The **reconciler** (in your runner / CI / Function App) writes a manifest to a Blob Storage container.
2. **EventGrid** fires a `Microsoft.Storage.BlobCreated` event filtered by suffix `.json` and prefix `departures/`.
3. The **Logic App** receives the event, invokes the parser Function with the blob URI, then maps over the validated entries and invokes the worker Function for each.
4. Cosmos DB + Blob audit writes happen synchronously per step.
5. The reconciler ingests the audit rows back into the source warehouse so the next reconciler run can detect drift.

See [`infra/arm_template.json`](infra/arm_template.json), [`infra/eventgrid_subscription.json`](infra/eventgrid_subscription.json), and [`infra/logic_app.json`](infra/logic_app.json) for the deployable reference.

## 6. CIS Azure benchmark closed loop

Run [`cspm-azure-cis-benchmark`](../../evaluation/cspm-azure-cis-benchmark/) to find stale Entra users (CIS Azure 1.x guest / inactive checks). Feed the resulting findings into your reconciler to produce the manifest, then run this skill. The audit rows close the loop by proving each remediation actually landed.
