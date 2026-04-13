---
name: detect-okta-mfa-fatigue
description: >-
  Detect repeated Okta Verify push-challenge and denial bursts from OCSF 1.8
  Authentication (3002) events produced by ingest-okta-system-log-ocsf. Tracks
  one user at a time, looks for multiple Okta Verify push sends plus at least
  one explicit deny or MFA verification failure inside a short time window, and
  emits OCSF 1.8 Detection Finding (class 2004) with MITRE ATT&CK T1621
  Multi-Factor Authentication Request Generation. Use when the user mentions
  MFA fatigue, repeated Okta Verify prompts, push bombing, or suspicious Okta
  MFA denial bursts. Do NOT use on raw Okta System Log JSON — normalize it
  through ingest-okta-system-log-ocsf first. Do NOT use as a generic failed-logon
  detector or credential-stuffing rule.
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-okta-mfa-fatigue
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud:
    - okta
---

# detect-okta-mfa-fatigue

## Attack pattern

Okta push bombing / MFA fatigue is the pattern where an attacker repeatedly
triggers Okta Verify push challenges until a user eventually approves one or
becomes conditioned to repeated prompts. In Okta System Log terms, that pattern
shows up as a burst of:

- `system.push.send_factor_verify_push`
- `user.mfa.okta_verify.deny_push`
- `user.mfa.okta_verify.deny_push_upgrade_needed`
- or the OIE generic failure path `user.authentication.auth_via_mfa` with
  `INVALID_CREDENTIALS` while the authenticator is `Okta Verify`

This skill keeps the logic narrow to those verified event families. It does not
guess at every MFA-related event type in the catalog.

## Detection logic

One pass over OCSF Authentication (3002) events from
`ingest-okta-system-log-ocsf`:

1. Group by `user.uid`
2. Sort by `time`
3. Maintain a 10-minute burst window
4. Fire once per burst when all of the following are true:
   - at least `3` relevant Okta Verify events
   - at least `2` push challenge events
   - at least `1` deny or MFA verification failure event

The detector emits one finding per burst and suppresses repeat findings until
there is a quiet period longer than the correlation window.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) with:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["okta-mfa-fatigue", "mfa-request-generation"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1621`
- `evidence.challenge_events`, `evidence.denial_events`, `evidence.raw_event_uids`
- `observables[]` carrying the impacted user, source IPs, and session IDs

## Usage

```bash
python ../ingest-okta-system-log-ocsf/src/ingest.py okta-system-log.json \
  | python src/detect.py \
  > okta-mfa-fatigue-findings.ocsf.jsonl
```

## Do NOT use

- On raw Okta JSON before normalization
- As a generic failed-login detector
- As a credential-stuffing detector
- On non-Okta identity sources like Entra, Workspace, or CloudTrail

## Tests

The test suite covers:

- out-of-order OCSF auth input
- exact window-boundary behavior
- duplicate event suppression by `metadata.uid`
- classic `deny_push` and OIE `auth_via_mfa` failure paths
- a frozen golden fixture for detector output parity
