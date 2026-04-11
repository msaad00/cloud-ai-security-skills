# References — ingest-cloudtrail-ocsf

## Source format

- **AWS CloudTrail event reference** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- **CloudTrail Records JSON shape** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-format.html
- **userIdentity element** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
- **CloudTrail event delivery to S3** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-find-log-files.html

## Output format

- **OCSF 1.8 API Activity (class 6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 actor object** — https://schema.ocsf.io/1.8.0/objects/actor

## Required AWS permissions (collection)

The skill itself reads from stdin or a local file — it does not call AWS. To
collect CloudTrail events for ingestion, the upstream caller needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::<your-cloudtrail-bucket>",
      "arn:aws:s3:::<your-cloudtrail-bucket>/AWSLogs/<account-id>/CloudTrail/*"
    ]
  }]
}
```

That's it. **No CloudTrail API calls, no IAM read.** The skill operates
on the event JSON only.

## Verb-prefix table source

The Create / Read / Update / Delete classification is derived from the
AWS API verb conventions documented at
https://docs.aws.amazon.com/general/latest/gr/glos-chap.html and
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html
The full table is in `src/ingest.py` (`_VERB_TABLE`).

## See also

- `OCSF_CONTRACT.md` (sibling) for the per-skill wire contract
- `ingest-gcp-audit-ocsf` for the GCP equivalent
- `ingest-azure-activity-ocsf` for the Azure equivalent
