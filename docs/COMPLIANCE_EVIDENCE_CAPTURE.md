# UI Evidence Capture for Compliance

This repo already has strong evidence paths for cloud state, logs, benchmark checks, and access-review exports. The gap is the class of controls where the system of record exposes the relevant control state only in an admin UI, or where the certification program explicitly asks for screenshots.

## What the research says

Screenshots are valid evidence, but they should not be the default evidence type.

- Prefer machine-readable evidence first:
  - AWS Audit Manager automatically collects configuration snapshots, user activity evidence, and compliance-check evidence from AWS services, CloudTrail, Security Hub, and Config.
  - Microsoft Entra access reviews support downloadable review history reports and downloadable results, and the same decisions can also be retrieved programmatically through Microsoft Graph or PowerShell.
  - Okta Access Certifications supports CSV export for completed campaign reports.
- Use screenshots when they add evidence you cannot reliably get from an export or API:
  - Microsoft 365 Certification explicitly requires full-screen screenshots with the URL, logged-in user, and time/date stamp visible for screenshot-based evidence submissions.
  - UI-only control surfaces, review-state pages, and point-in-time visual attestations can still matter to auditors when no structured export exists.

The implication for this repo is straightforward: an evidence-capture skill family is useful, but only as a controlled fallback and only when the output is tied back to structured metadata and audit trails.

## Good fit for this repo

A repo-native evidence capture capability would fit best as read-only discovery or evidence skills, not as ad hoc browser macros.

Suggested family:

- `evidence-entra-access-reviews`
  - prefer CSV / Graph exports first
  - capture screenshots only for review state, reviewer UI, or apply-state pages
- `evidence-okta-access-certifications`
  - prefer campaign exports first
  - capture screenshots for reassignment history or policy-state pages when export is incomplete
- `evidence-m365-certification-controls`
  - screenshot-first because the certification guidance explicitly accepts and describes screenshot submissions
- `evidence-console-control-snapshot-*`
  - tightly scoped vendor skills for cases where a control is genuinely visible only in the UI

## Required guardrails

If this is built, it should follow the same design discipline as the rest of the repo:

- read-only only
- deterministic navigation
- explicit vendor / framework scope
- timestamp, URL, tenant/account, and operator identity captured alongside the image
- DOM/text context stored with the screenshot so the evidence is searchable and less brittle
- image hashing for tamper detection
- redaction hooks for secrets, tokens, user PII, and customer data
- append-only sink support for evidence packages
- no marketing claims that screenshots are equivalent to continuous control monitoring

## Output contract

The output should not be a raw `.png` alone. It should be an evidence bundle:

- screenshot
- metadata JSON
- capture timestamp
- canonical control id / framework mapping
- tenant / account / resource identifier
- URL / page title
- operator / agent identity
- optional DOM extract or CSV export collected in the same run

That keeps screenshot evidence auditable, reviewable, and attachable to the same evidence workflows already used elsewhere in the repo.

## Recommendation

This is worth building, but as a narrow evidence-capture surface, not as a general “let the agent click around” feature.

Priority order:

1. export-first skills for Entra and Okta access reviews / certifications
2. screenshot-backed Microsoft 365 certification evidence capture
3. vendor-specific UI-only control evidence skills where no better API/export path exists

## Sources

- AWS Audit Manager: reviewing evidence and evidence types
  - https://docs.aws.amazon.com/audit-manager/latest/userguide/review-evidence.html
  - https://aws.amazon.com/audit-manager/faqs/
- Microsoft Entra access reviews: downloadable history and downloadable/programmatic results
  - https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-downloadable-review-history
  - https://learn.microsoft.com/en-us/entra/id-governance/complete-access-review
- Microsoft 365 Certification evidence guidance
  - https://learn.microsoft.com/en-us/microsoft-365-app-certification/docs/seg2_overview
- Okta Access Certifications CSV export
  - https://help.okta.com/en-us/content/topics/identity-governance/access-certification/iga-view-prev-campaigns.htm
