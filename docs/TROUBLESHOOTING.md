# Troubleshooting

Use this doc when a skill runs but the output is empty, malformed, or not in
the schema mode you expected, and when a repo-level behavior needs explaining.

For the repo-wide exit-code contract, see [ERROR_CODES.md](ERROR_CODES.md).

## Fast checklist

1. Confirm the skill contract:
   - check `input_formats`
   - check `output_formats`
   - check `approval_model`
2. Confirm the invocation mode:
   - CLI
   - CI
   - MCP
   - persistent runner wrapper
3. Confirm the input shape:
   - `raw`
   - `native`
   - `canonical`
   - `ocsf`
4. Confirm you are reading `stdout` for structured results and `stderr` for
   warnings or partial-skip hints.

## Common symptoms

### `--output-format native` fails

Cause:
- the skill has not shipped dual-mode support yet

Check:
- the skill's `SKILL.md` `output_formats`
- the repo `README.md` schema-mode rollout section

Fix:
- use the default supported output mode for that skill
- or compose through a dual-mode upstream/downstream skill that already supports
  `native`

### Native output still looks like OCSF

Expected behavior:
- native output keeps the repo's canonical identity fields
- native output must not include the OCSF envelope fields such as:
  - `class_uid`
  - `category_uid`
  - `type_uid`
  - `metadata`

Check:
- `schema_mode` should be `native`
- `canonical_schema_version` should be present on current dual-mode skills

### Detector returns nothing

Most common causes:
- wrong input mode for that detector
- required upstream ingester was skipped
- timestamps fall outside the correlation window
- the source event family is out of scope for that rule

For windowed detectors, inspect:
- event ordering
- event timestamps
- provider and account alignment
- session identifiers

### Large-batch guidance

`detect-lateral-movement` currently materializes the normalized event stream for
the current run before correlation. That is fine for bounded batch windows, but
operators should not treat it as an infinite-stream daemon.

Recommended pattern today:
- partition by provider and account or tenant where possible
- process in bounded time windows
- keep each batch near the existing `15-minute` correlation window or another
  explicit operator-chosen chunk size
- for enterprise-scale replay, use a runner that chunks upstream data instead of
  pushing a full day of mixed audit and flow telemetry into one process

If you expect `100k+` events per day for one detection pass, document and apply
the chunking policy in the surrounding runner or job definition.

### MCP-specific symptoms

If an MCP call fails before the skill runs:
- confirm the requested `output_format` is declared by the skill
- confirm write-capable skills include `--dry-run` where required
- confirm the MCP wrapper is exposing the latest skill metadata from `SKILL.md`

Relevant files:
- `mcp-server/src/server.py`
- `mcp-server/src/tool_registry.py`

### Cloud SDK import failures

Many cloud SDKs are imported lazily inside provider-specific functions.

If a skill loads but fails only when a provider branch executes:
- install the required dependency group
- confirm the provider SDK is declared in `pyproject.toml`
- confirm the target API response shape still matches the documented source

Use:
- `docs/SKILL_CONTRACT.md`
- `docs/DEPENDENCY_HYGIENE_SKILL.md`
- the skill's `REFERENCES.md`

### When to suspect schema drift

Look for:
- new enum values
- renamed nested fields
- timestamp format changes
- missing natural IDs
- provider-side deprecations

Fix pattern:
- add a fixture for the new shape
- keep the old shape covered during migration
- update `REFERENCES.md`
- update the skill contract only in the same PR as the code change

## FAQ

### Why does a skill name still end in `-ocsf` if OCSF is optional?

`-ocsf` means OCSF is the default interoperable wire format for that skill
family. It does not mean OCSF is the only supported mode. The repo uses:

- OCSF by default for event and finding streams
- native by default for evaluation, discovery/evidence, sinks, remediation,
  and domains where OCSF would be lossy

Check the skill's `output_formats` frontmatter for the current truth.

### Why doesn't every skill support `native` yet?

The repo is rolling out dual-mode support skill-by-skill. The contract is
stable now, but implementation is intentionally phased to avoid a risky
big-bang rewrite.

Use the `README.md` schema-mode section and `SKILL.md` frontmatter as the
source of truth for current support.

### Can I ask for `canonical` output?

Not directly today. `canonical` is the repo's stable internal model. Current
wire outputs are:
- `native`
- `ocsf`
- `bridge`

The skill code normalizes into canonical internally and then projects outward.

### Why does `execution_modes: persistent` not mean a daemon already exists?

`persistent` means the skill is safe to embed unchanged in a runner, queue
consumer, scheduler, or serverless loop. It does not mean the repo already
ships that runner for every skill.

Current shipped exception:
- `iam-departures-remediation`

### Why is a read-only skill refusing to write or mutate anything?

That is the intended contract. Read-only skills must not perform hidden writes.
If you need a state-changing action, use a documented remediation or sink path
with the correct approval model.

### Why is a write-capable skill asking for dry-run or human approval?

Because the repo treats approval metadata as runtime policy, not just
documentation. Agents and wrappers should stop for approval where the skill
contract says they must.

### What happens when a user, service principal, or resource disappears?

The repo should preserve:
- historical events
- last-known state
- last-seen time
- lifecycle status when the source exposes it

Absence from a later snapshot should be treated as a state signal, not as an
instruction to erase history.

See:
- `docs/STATE_AND_TIMELINE_MODEL.md`

### Why do I see `Expected — Waiting for status to be reported` on a PR?

In practice this usually means one of two things:
- the PR branch is stale or marked conflicted, so GitHub has not started the
  required checks on the latest mergeable head
- branch protection still expects an old check name that no longer exists

Rebase or refresh the PR branch first before assuming Actions is frozen.

### How should I store this data in a database or lake?

Prefer the canonical model for:
- tables
- views
- joins
- indexes
- metrics

Treat OCSF as a transport and interoperability projection, not the only storage
schema.

See:
- `docs/CANONICAL_SCHEMA.md`
- `docs/SIEM_INDEX_GUIDE.md`
