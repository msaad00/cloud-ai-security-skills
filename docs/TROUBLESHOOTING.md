# Troubleshooting

## Why does a skill name still end in `-ocsf` if OCSF is optional?

`-ocsf` means OCSF is the default interoperable wire format for that skill
family. It does not mean OCSF is the only supported mode. The repo uses:

- OCSF by default for event and finding streams
- native by default for evaluation, discovery/evidence, sinks, remediation,
  and domains where OCSF would be lossy

Check the skill's `output_formats` frontmatter for the current truth.

## Why doesn't every skill support `native` yet?

The repo is rolling out dual-mode support skill-by-skill. The contract is
stable now, but implementation is intentionally phased to avoid a risky
big-bang rewrite.

Use the `README.md` schema-mode section and `SKILL.md` frontmatter as the
source of truth for current support.

## Can I ask for `canonical` output?

Not directly today. `canonical` is the repo's stable internal model. Current
wire outputs are:
- `native`
- `ocsf`
- `bridge`

The skill code normalizes into canonical internally and then projects outward.

## Why does `execution_modes: persistent` not mean a daemon already exists?

`persistent` means the skill is safe to embed unchanged in a runner, queue
consumer, scheduler, or serverless loop. It does not mean the repo already
ships that runner for every skill.

Current shipped exception:
- `iam-departures-remediation`

## Why is a read-only skill refusing to write or mutate anything?

That is the intended contract. Read-only skills must not perform hidden writes.
If you need a state-changing action, use a documented remediation or sink path
with the correct approval model.

## Why is a write-capable skill asking for dry-run or human approval?

Because the repo treats approval metadata as runtime policy, not just
documentation. Agents and wrappers should stop for approval where the skill
contract says they must.

## What happens when a user, service principal, or resource disappears?

The repo should preserve:
- historical events
- last-known state
- last-seen time
- lifecycle status when the source exposes it

Absence from a later snapshot should be treated as a state signal, not as an
instruction to erase history.

See:
- `docs/STATE_AND_TIMELINE_MODEL.md`

## Why do I see `Expected — Waiting for status to be reported` on a PR?

In practice this usually means one of two things:
- the PR branch is stale or marked conflicted, so GitHub has not started the
  required checks on the latest mergeable head
- branch protection still expects an old check name that no longer exists

Rebase or refresh the PR branch first before assuming Actions is frozen.

## How should I store this data in a database or lake?

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
