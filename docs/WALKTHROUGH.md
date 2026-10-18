# Investigate an AWS access-key finding

**Question:** who created an IAM user access key, and what should an analyst
check before treating it as an incident?

This local walkthrough uses four **synthetic** CloudTrail events. It makes no
AWS API calls and needs no cloud credentials. The commands write local files.
Python 3.11+, [uv](https://docs.astral.sh/uv/), and Make are required for the
quick demo. Dependency installation may access the package registry.

## Run it

```bash
git clone https://github.com/msaad00/cloud-ai-security-skills.git
cd cloud-ai-security-skills
uv sync --frozen
uv run make demo
```

Expected: `1 finding(s) emitted`, titled `AWS IAM access key created`, with
SARIF rule `T1098`. The report is saved to `$TMPDIR/cloud-security-demo.sarif`
(`/tmp` when `TMPDIR` is unset). Structured diagnostic logs go to stderr.

![Annotated synthetic access-key finding with actor, target, rule match, and investigation limits.](images/access-key-walkthrough.svg)

The image annotates the fixture result; it is not an application screen or an
additional report format. The emitted report is SARIF JSON.

## Follow the evidence

Open the [four source events](../skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl).
The first record is the match:

| Question | Source field | Value in this fixture |
|---|---|---|
| Who made the request? | `userIdentity.principalId` | `AROAEXAMPLEID:alice` |
| Which session? | `userIdentity.arn` | `arn:aws:sts::123456789012:assumed-role/Admin/alice` |
| What happened? | `eventName` | `CreateAccessKey` |
| Whose key? | `requestParameters.userName` | `bob` |
| Which account? | `recipientAccountId` | `123456789012` |
| When? | `eventTime` | `2026-04-10T05:00:00Z` |
| Where did the request come from? | `sourceIPAddress` | `203.0.113.42` |
| Which source record? | `eventID` | `e1-create-key` |

`alice` is part of a role-session identifier in the example. It is not proof
of a verified human identity. AWS documents the distinction in the
[CloudTrail userIdentity reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html).

The [ingester](../skills/ingestion/ingest-cloudtrail-ocsf/SKILL.md) projects the
record into OCSF API Activity (`6003`). The
[detector](../skills/detection/detect-aws-access-key-creation/SKILL.md) matches
successful `CreateAccessKey` activity with a resolvable target IAM username,
then emits OCSF Detection Finding (`2004`). The
[converter](../skills/view/convert-ocsf-to-sarif/SKILL.md) exports that finding
as SARIF. Its `ruleId` is the parent technique `T1098`; `T1098.001` is retained
in result tags.

The other three events are `ListBuckets`, a denied `DeleteUser`, and
`PutBucketPolicy`. They do not match this access-key rule. That does not make
them benign or mean another detector would ignore them.

## Inspect each stage locally

Run this block from the repository root in **Bash**. It creates a fresh output
directory so inspection does not overwrite an earlier report. Commands run
sequentially and stop if a stage fails.

```bash
set -euo pipefail
walkthrough_dir=$(mktemp -d "${TMPDIR:-/tmp}/cloud-security-walkthrough.XXXXXX")
uv run python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py \
  skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl \
  > "$walkthrough_dir/events.ocsf.jsonl"
uv run python skills/detection/detect-aws-access-key-creation/src/detect.py \
  "$walkthrough_dir/events.ocsf.jsonl" \
  > "$walkthrough_dir/findings.ocsf.jsonl"
uv run python skills/view/convert-ocsf-to-sarif/src/convert.py \
  < "$walkthrough_dir/findings.ocsf.jsonl" \
  > "$walkthrough_dir/findings.sarif"
uv run python -m json.tool "$walkthrough_dir/findings.sarif"
printf 'Inspect the stage outputs in %s\n' "$walkthrough_dir"
```

Expect four normalized event lines, one finding line, and one SARIF result.
In SARIF, inspect `runs[0].results[0]`: `message.text` explains the match,
`properties.observables` carries actor/target/account/source-IP context, and
`properties.detected_at_ms` preserves the finding's source event time.

**Trace the finding to its input.** Inspect
`runs[0].results[0].properties.evidence.source_event` in SARIF, or
`evidence.source_event` in the OCSF finding. It preserves the normalized input's
`metadata.uid`, producer, recipient account, and region. For this fixture the
UID is the original CloudTrail `eventID`; use it to locate the input event.
The finding UID is a separate identifier.

**Keep the original events.** If raw input lacks `eventID`, the ingester generates
a deterministic fallback UID. That value references normalized input, not a
CloudTrail-assigned ID; it is not a guarantee of uniqueness or authenticity.
Missing normalized UIDs omit the reference. The finding still does not contain
the created key ID or raw request/response bodies, and it cannot verify whether
all relevant events were collected.

## Interpret the result

The rule assigns HIGH severity to successful key creation. That is a rule
priority, not a measured probability of compromise. A routine, approved key
rotation also matches. AWS's [CreateAccessKey reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html)
describes the operation; it does not determine the actor's intent.

| Established by this fixture | Still requires investigation |
|---|---|
| A successful key-creation event matched the rule | Whether the change was approved |
| The request named IAM user `bob` | Whether the new key was subsequently used |
| The source named an assumed-role session | Who actually controlled the session |
| One local report was produced | Whether all relevant events were collected |

For an actual alert, compare the event with the change record and user owner,
resolve the role session using your identity logs, and review subsequent
activity in the same account and time window. Recover the created key ID from
the original event where available before correlating key use. The current
finding alone cannot perform that correlation.

This walkthrough stops at investigation. It does not revoke credentials or
show a verified remediation. Any response belongs in your approved incident
workflow with scope, audit, and verification requirements.

## Check behavior and limits

Run the existing boundary tests and the labelled scorer:

```bash
uv run pytest tests/integration/test_cloudtrail_failure_integrity.py \
  tests/integration/test_demo_pipeline.py -q
uv run python skills/detection-engineering/scoring/score.py \
  --detector detect-aws-access-key-creation --markdown
```

The scoring fixture is separate from the four-event demo. It includes a
successful key creation, a failed attempt, an unrelated operation, and a wrong
producer. These are **synthetic rule-matching cases**. Even perfect scores here
do not measure whether alerts are malicious on real traffic.

The scorer rejects malformed labels and findings without usable scoring IDs.
In `event_uid` mode, predictions outside the labelled set appear under
`Unlabelled (excluded)`; they do not count toward precision or recall. In
`finding_uid` mode, unexpected finding IDs count as false positives. The
aggregate includes only successfully scored entries and shows an error count;
any detector error makes the command exit nonzero. These checks validate ID
matching, not finding content or the accuracy of the labels themselves.

Empty input is valid and can produce an empty report. Malformed or unsupported
input can fail the batch. Neither an empty report nor a passing fixture proves
that an account is secure. See the [skill contract](../skills/detection/detect-aws-access-key-creation/SKILL.md)
for exact acceptance and failure behavior.

## Try a useful next step

Use a finite, local CloudTrail export you are authorized to analyze as the
input to the same stages. Review its fields and the skill contract first;
the detector requires a resolvable target username, even though AWS permits
some calls with an implicit user. Compare matches with your known legitimate
key changes before making the workflow an alert source.

For design and operational evidence, read the
[GCP runner deployment case study](GCP_RUNNER_CASE_STUDY.md). To expose local
tools to an agent, follow [agent setup](AGENT_QUICKSTART.md).
