# Runtime Isolation

This repo ships security skills, not a shared trusted runtime. Isolation is
part of the product contract.

The rule is simple:
- read-only skills run with the smallest possible local and cloud trust surface
- write-capable skills run in tighter, separate execution boundaries
- transport, storage, and audit controls are explicit, not assumed

Each shipped `SKILL.md` now declares:
- `approval_model`
- `execution_modes`
- `side_effects`
- optional `network_egress`

Agents and wrappers should treat those fields as part of the runtime contract, not optional documentation.

Important meaning:
- `execution_modes: persistent` means the skill is compatible with a persistent runner or serverless loop
- it does **not** mean the repo already ships a dedicated daemon, queue worker, sink, or Lambda wrapper for that skill
- today, most skills are persistent-compatible but still run as stateless CLI tools; only a small number of workflows ship repo-owned persistent code paths

## Modes

| Mode | Best for | Isolation posture | Human approval |
|---|---|---|---|
| CLI / just-in-time | local triage, one-off conversions, fixture checks | local venv or container, scoped files, least-privilege creds | only for write-capable skills |
| CI | regression testing, policy checks, snapshots | ephemeral runner, short-lived creds, no write skills in normal PR lanes | never for read-only skills |
| MCP | local agent tool calling | stdio-only wrapper, fixed tool surface, timeouts, no generic shell tool | inherited from the wrapped skill |
| Persistent / serverless | continuous detection, sinks, remediation | isolated runner or cloud service boundary, checkpointing, egress controls, idempotent writes | required for destructive actions |

Persistent mode should be read as:
- the skill stays stateless and deterministic
- a separate runner or serverless wrapper owns checkpoints, retries, queue offsets, and sink writes
- operators still need to provide the surrounding runtime unless the skill explicitly ships one

## Read-only skills

These layers should stay read-only unless the skill contract says otherwise:
- `ingestion/`
- `discovery/`
- `detection/`
- `evaluation/`
- `view/`

Expected controls:
- no arbitrary shell passthrough
- no hidden writes
- no broad network egress outside documented API use
- deterministic `stdout` output
- warnings and skips only on `stderr`
- strict input validation before parse, convert, or cloud calls

## Write-capable skills and edge components

These are the only places where side effects should happen:
- `remediation/`
- future `sinks/`
- future `runners/`

Current shipped exception:
- `iam-departures-remediation` includes repo-owned Lambda handlers and infrastructure for its event-driven persistent path

Required controls:
- `--dry-run` support
- explicit blast-radius docs
- approval gates for destructive actions
- dedicated credentials, separate from read-only analysis paths
- idempotency keys or merge-on-UID behavior
- immutable or append-only audit trail where feasible

Where the runtime supports it, write-capable skills should also preserve:
- caller identity
- approver identity
- session or request identifiers
- execution principal details
- change-control or ticket references

Those fields are part of the audit contract, not optional debug noise.

## Credentials and cloud access

Best practice for operators:
- use dedicated dev or sandbox accounts, subscriptions, or projects for local testing
- prefer short-lived credentials and workload identity over static secrets
- do not expose production credentials to agent sessions unless the task truly requires them
- keep remediation credentials separate from read-only discovery and detection credentials

Best practice for this repo:
- cloud SDK default chains are preferred over ad hoc token plumbing
- secrets come from secret stores or the execution environment, never hardcoded
- logs must not echo secrets, tokens, or connection strings

## Data in transit and at rest

Transport expectations:
- TLS for external API calls and remote sinks
- local MCP uses stdio, not an unauthenticated network listener
- any future HTTP or SSE transport must add explicit authentication, integrity, and timeout controls

Storage expectations:
- findings, evidence, and inventories should be encrypted at rest in the chosen sink
- retention should be minimal and documented
- raw high-risk payloads should be retained only when justified by audit or replay needs

## Integrity, drift, and indexing

Threats to defend against:
- code drift
- skill poisoning
- prompt injection through untrusted logs or findings
- hidden write behavior in a read-only skill
- schema drift and deprecated vendor APIs
- dependency and supply-chain drift

Repo controls already in place:
- skill contract validation
- integrity validation
- dependency consistency validation
- framework coverage validation
- safe-skill bar checks

Operational guidance:
- use only official references in `REFERENCES.md`
- treat scanner output and upstream findings as untrusted input until validated
- keep deterministic identifiers for replay-sensitive artifacts
- prefer UTC epoch-millisecond timestamps in wire outputs
- index persistent stores on stable provider, account, region, resource, framework, and severity fields before free-form text

## Compatibility note

Some repo-local bridge and profile identifiers still use older names:
- `cloud_security_mcp`
- `cloud-security.environment-graph.v1`
- `cloud-security:*` CycloneDX property keys

Those names remain stable for compatibility with downstream readers. Public repo
identity and emitted OCSF `metadata.product` identity should still use
`cloud-ai-security-skills`.
