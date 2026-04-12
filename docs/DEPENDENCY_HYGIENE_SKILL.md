# Dependency Hygiene Skill Spec

This is a proposed skill contract for safe dependency refresh work. It is intentionally documented as a spec first, not shipped as runnable code yet.

## Goal

Let an agent inspect stale or vulnerable dependencies, update them in controlled batches, run the relevant verification, and stop before it breaks the repo.

## Non-Goals

- blind repo-wide upgrades
- automatic major-version jumps without explicit approval
- editing dependencies without running scoped verification
- rewriting unrelated code just to satisfy a package bump

## Proposed Skill Name

`dependency-hygiene`

## Trigger Phrases

- update vulnerable packages
- align dependencies safely
- refresh lockfile without breaking tests
- bump dev tools in scoped batches

## Inputs

- manifest files and lockfiles
- allowed update scope: `patch`, `minor`, or approved `major`
- package family:
  - `dev`
  - `aws`
  - `gcp`
  - `azure`
  - `iam_departures`
- verification commands for the affected skills

## Required Behavior

1. inventory outdated and vulnerable dependencies
2. group updates into small batches by ecosystem or skill family
3. update manifest and lockfile together
4. run only the relevant lint / test / type checks
5. stop on breakage and summarize the failing package delta
6. open a PR summary with:
   - packages changed
   - risk level
   - commands run
   - residual issues

## Do Not Use

Do not use this skill to bulk-upgrade the full repo in one pass, to auto-merge major-version changes without approval, or to suppress test failures caused by an update.

## Minimum Verification Contract

- dependency graph diff
- lockfile updated
- scoped tests pass
- lint passes for touched files
- migration notes captured when a package changes behavior
