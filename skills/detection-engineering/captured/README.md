# Captured fixtures — admission contract

**Current status: zero captured-traffic fixtures.** The two command-derived
scenarios previously stored here are synthetic and now live under
[`golden/`](../golden/README.md#constructed-aws-scenarios). Their timestamps,
identities, accounts, and IP addresses were constructed; no execution record or
recorded telemetry artifact was supplied. A public attack command is not an
observed event, and its documentation does not establish a capture window.

The empty [`MANIFEST.yaml`](MANIFEST.yaml) records this evidence gap explicitly.
Passing CI with an empty manifest does not demonstrate detector performance on
recorded traffic. Existing scoring results use synthetic fixtures.

## Admitting recorded telemetry

Before adding a fixture, a reviewer must inspect an identifiable upstream
telemetry artifact, its redistribution terms, the observed time range, and the
normalization procedure. Record the original source, retained fields, and any
redactions; do not invent missing values. A command recipe or technique page
alone is insufficient. Lab captures should be described as lab captures and
must include the actual execution and recording evidence.

Each entry requires:

| Field | Contract |
|---|---|
| `path` | Unique local `.ocsf.jsonl` filename; no directories or symlinks |
| `origin` | HTTP(S) URL to the reviewed recorded-telemetry artifact; prefer an immutable revision |
| `license` | Declared SPDX identifier from the validator's permissive allowlist |
| `capture_window_utc` | Observed UTC `start/end` timestamps, ordered earliest to latest |
| `attack_pattern` | Nonempty technique identifier supported by the source and review |
| `consuming_detector` | Existing `detect-*` skill name |
| `synthetic_seeded` | Explicit boolean `false`; constructed data belongs in `golden/` |
| `sha256` | Lowercase SHA-256 digest of the local normalized fixture bytes |

The allowed license identifiers are `Apache-2.0`, `MIT`, `BSD-2-Clause`,
`BSD-3-Clause`, `CC0-1.0`, and `CC-BY-4.0`. Checking an identifier is not a
substitute for reviewing the source's actual terms.

Add a detector test that exercises the imported artifact and documents the
expected match and nonmatch behavior. Detector existence alone does not prove
that a fixture is exercised. Keep immutable upstream evidence and the
normalization instructions reviewable alongside the fixture.

## What CI checks

Run `uv run python scripts/validate_captured_provenance.py`.
The offline gate validates manifest shape, required values, unique paths,
local files, declared time ranges, detector existence, and fixture hashes.
A changed file requires a reviewed hash update. Unlisted files, malformed
manifests, missing declarations, nested directories, and symlinks fail.
Only an explicit `fixtures: []` with no fixture files is accepted as empty.

The gate does not fetch upstream URLs, authenticate provenance, verify license
terms, prove that a command ran, or measure real-world precision or recall.
A matching hash proves that the local bytes match their declared digest.
Human source review remains required for every admission.
