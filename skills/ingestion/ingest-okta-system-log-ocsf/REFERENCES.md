# References — ingest-okta-system-log-ocsf

## Source formats and schemas

- **Okta System Log API** — https://developer.okta.com/docs/reference/api/system-log
- **Okta System Log query guide** — https://developer.okta.com/docs/reference/system-log-query/
- **Okta event hook implementation sample payload** — https://developer.okta.com/docs/guides/event-hook-implementation/-/main/

## Output format

- **OCSF 1.8 Identity & Access Management category** — https://schema.ocsf.io/
- **OCSF 1.8 Account Change (3001)** — https://schema.ocsf.io/1.8.0/classes/account_change
- **OCSF 1.8 User Access Management (3005)** — https://schema.ocsf.io/1.8.0/classes/user_access
- **OCSF 1.8 Metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 Actor object** — https://schema.ocsf.io/1.8.0/objects/actor

## Collection guidance

The skill itself reads JSON from stdin or local files and does not call Okta.
Upstream collectors should:

- follow `next` links when polling `/api/v1/logs`
- preserve raw `uuid`, `published`, `authenticationContext.externalSessionId`, and `transaction.id`
- avoid crafting pagination manually with `since` / `until` for continuous exports

Okta documents that polling requests may return events out of order relative to
`published`, while bounded requests are ordered by `published`. The skill keeps
the source `published` time and Okta natural IDs intact so downstream
correlation can reason about that behavior explicitly.
