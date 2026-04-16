# Normalization Examples

This document shows concrete side-by-side normalization examples for the most
common shipped source families.

Use it when you want to see:

- raw vendor payload shape
- native repo-owned output shape
- OCSF output shape
- where `metadata.uid`, `api.request.uid`, `event_uid`, `session_uid`, and
  `unmapped.*` land

Use this together with:

- [`NORMALIZATION_REFERENCE.md`](./NORMALIZATION_REFERENCE.md)
- [`NATIVE_VS_OCSF.md`](./NATIVE_VS_OCSF.md)
- [`CANONICAL_SCHEMA.md`](./CANONICAL_SCHEMA.md)
- [`SCHEMA_COVERAGE.md`](./SCHEMA_COVERAGE.md)

The examples here are abbreviated on purpose. They show the placement of the
important fields, not every field the full output may include.

## Reading the examples

Short rule:

- `raw` shows the vendor payload shape
- `native` shows the repo-owned external wire format
- `ocsf` shows the interoperable external wire format
- omitted fields are still available in the skill contract and golden fixtures

## 1. AWS CloudTrail

### What this source becomes

| Concern | Value |
|---|---|
| Source skill | `ingest-cloudtrail-ocsf` |
| Native type | `api_activity` |
| Default OCSF class | API Activity `6003` |
| Main natural ID | `eventID` |
| Main request ID | `eventID -> api.request.uid` |
| Stable repo event ID | preserve `eventID` as `event_uid` and OCSF `metadata.uid` |

### Raw

```json
{
  "eventVersion": "1.10",
  "eventTime": "2026-04-15T05:00:00Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.10",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alice"
  },
  "recipientAccountId": "111122223333",
  "eventID": "ct-1234"
}
```

### Native

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "api_activity",
  "event_uid": "ct-1234",
  "provider": "AWS",
  "account_uid": "111122223333",
  "region": "us-east-1",
  "time_ms": 1776238800000,
  "activity_id": 1,
  "activity_name": "Create",
  "operation": "AssumeRole",
  "service_name": "sts.amazonaws.com",
  "actor": {
    "user": {
      "name": "alice"
    }
  },
  "src": {
    "ip": "203.0.113.10"
  },
  "source": {
    "kind": "cloudtrail",
    "event_id": "ct-1234"
  }
}
```

### OCSF

```json
{
  "class_uid": 6003,
  "category_uid": 6,
  "time": 1776238800000,
  "activity_id": 1,
  "activity_name": "Create",
  "metadata": {
    "uid": "ct-1234"
  },
  "cloud": {
    "provider": "AWS",
    "account": {
      "uid": "111122223333"
    },
    "region": "us-east-1"
  },
  "actor": {
    "user": {
      "name": "alice"
    }
  },
  "src_endpoint": {
    "ip": "203.0.113.10"
  },
  "api": {
    "service": {
      "name": "sts.amazonaws.com"
    },
    "operation": "AssumeRole",
    "request": {
      "uid": "ct-1234"
    }
  }
}
```

### What to notice

- `eventID` survives cleanly as both `event_uid` and OCSF `metadata.uid`
- CloudTrail is a good OCSF fit for standard API activity
- the main loss is larger nested request and response detail, not the event ID

## 2. Azure Activity Log

### What this source becomes

| Concern | Value |
|---|---|
| Source skill | `ingest-azure-activity-ocsf` |
| Native type | `api_activity` |
| Default OCSF class | API Activity `6003` |
| Main natural ID | `correlationId` for request correlation |
| Main resource anchor | `resourceId` |
| Stable repo event ID | deterministic `event_uid`; preserve `correlationId` under `api.request.uid` |

### Raw

```json
{
  "time": "2026-04-15T05:00:00.0000000Z",
  "resourceId": "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stg1",
  "operationName": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
  "callerIpAddress": "198.51.100.20",
  "correlationId": "azcorr-123",
  "identity": {
    "claims": {
      "name": "alice@example.com",
      "appid": "app-123"
    }
  },
  "resultType": "Success",
  "properties": {
    "statusCode": "OK"
  }
}
```

### Native

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "api_activity",
  "event_uid": "evt-azure-4ab1...",
  "provider": "Azure",
  "account_uid": "sub-123",
  "time_ms": 1776238800000,
  "activity_id": 1,
  "activity_name": "Create",
  "operation": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
  "service_name": "MICROSOFT.STORAGE",
  "actor": {
    "user": {
      "name": "alice@example.com",
      "uid": "app-123"
    }
  },
  "src": {
    "ip": "198.51.100.20"
  },
  "resource": {
    "name": "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stg1"
  },
  "correlation_uid": "azcorr-123"
}
```

### OCSF

```json
{
  "class_uid": 6003,
  "category_uid": 6,
  "metadata": {
    "uid": "evt-azure-4ab1..."
  },
  "time": 1776238800000,
  "activity_id": 1,
  "activity_name": "Create",
  "cloud": {
    "provider": "Azure",
    "account": {
      "uid": "sub-123"
    }
  },
  "actor": {
    "user": {
      "name": "alice@example.com",
      "uid": "app-123"
    }
  },
  "src_endpoint": {
    "ip": "198.51.100.20"
  },
  "api": {
    "operation": "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
    "request": {
      "uid": "azcorr-123"
    }
  },
  "resources": [
    {
      "name": "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stg1"
    }
  ]
}
```

### What to notice

- Azure often gives you a correlation handle rather than a single immutable raw event ID
- the repo keeps a deterministic `event_uid` and also preserves `correlationId`
- `resourceId` is the main resource anchor; subscription is the main account anchor

## 3. GCP Cloud Audit Logs

### What this source becomes

| Concern | Value |
|---|---|
| Source skill | `ingest-gcp-audit-ocsf` |
| Native type | `api_activity` |
| Default OCSF class | API Activity `6003` |
| Main natural ID | `insertId` |
| Main request ID | `insertId -> api.request.uid` |
| Stable repo event ID | deterministic `event_uid`; `insertId` preserved for request correlation |

### Raw

```json
{
  "insertId": "gcp-123",
  "timestamp": "2026-04-15T05:00:00.000Z",
  "resource": {
    "type": "service_account",
    "labels": {
      "project_id": "proj-1"
    }
  },
  "protoPayload": {
    "serviceName": "iam.googleapis.com",
    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
    "resourceName": "projects/-/serviceAccounts/sa@proj-1.iam.gserviceaccount.com",
    "authenticationInfo": {
      "principalEmail": "alice@example.com"
    },
    "requestMetadata": {
      "callerIp": "203.0.113.30"
    }
  }
}
```

### Native

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "api_activity",
  "event_uid": "evt-gcp-8b90...",
  "provider": "GCP",
  "account_uid": "proj-1",
  "time_ms": 1776238800000,
  "activity_id": 1,
  "activity_name": "Create",
  "operation": "google.iam.admin.v1.CreateServiceAccountKey",
  "service_name": "iam.googleapis.com",
  "actor": {
    "user": {
      "name": "alice@example.com"
    }
  },
  "src": {
    "ip": "203.0.113.30"
  },
  "resource": {
    "name": "projects/-/serviceAccounts/sa@proj-1.iam.gserviceaccount.com"
  },
  "source": {
    "request_id": "gcp-123"
  }
}
```

### OCSF

```json
{
  "class_uid": 6003,
  "category_uid": 6,
  "metadata": {
    "uid": "evt-gcp-8b90..."
  },
  "time": 1776238800000,
  "activity_id": 1,
  "activity_name": "Create",
  "cloud": {
    "provider": "GCP",
    "account": {
      "uid": "proj-1"
    }
  },
  "actor": {
    "user": {
      "name": "alice@example.com"
    }
  },
  "src_endpoint": {
    "ip": "203.0.113.30"
  },
  "api": {
    "service": {
      "name": "iam.googleapis.com"
    },
    "operation": "google.iam.admin.v1.CreateServiceAccountKey",
    "request": {
      "uid": "gcp-123"
    }
  },
  "resources": [
    {
      "name": "projects/-/serviceAccounts/sa@proj-1.iam.gserviceaccount.com"
    }
  ]
}
```

### What to notice

- `insertId` is the main request correlation key, not a human-friendly business identifier
- project ID becomes the main account or tenant anchor
- GCP Cloud Audit also fits well into OCSF API Activity

## 4. Okta System Log

### What this source becomes

| Concern | Value |
|---|---|
| Source skill | `ingest-okta-system-log-ocsf` |
| Native type | `authentication`, `account_change`, or `user_access_management` |
| Default OCSF class | Authentication `3002`, Account Change `3001`, or User Access Management `3005` |
| Main natural ID | `uuid` |
| Main session / transaction IDs | `authenticationContext.externalSessionId`, `transaction.id`, `rootSessionId` |
| Stable repo event ID | preserve `uuid` as `event_uid` and OCSF `metadata.uid` |

### Raw

```json
{
  "uuid": "okta-123",
  "published": "2026-04-15T05:00:00.000Z",
  "eventType": "user.session.start",
  "actor": {
    "id": "00u123",
    "alternateId": "alice@example.com"
  },
  "client": {
    "ipAddress": "203.0.113.40"
  },
  "authenticationContext": {
    "externalSessionId": "sess-123",
    "rootSessionId": "root-456"
  },
  "transaction": {
    "id": "trn-789"
  }
}
```

### Native

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "authentication",
  "event_uid": "okta-123",
  "provider": "Okta",
  "time_ms": 1776238800000,
  "event_name": "user.session.start",
  "actor": {
    "user": {
      "uid": "00u123",
      "name": "alice@example.com"
    }
  },
  "src": {
    "ip": "203.0.113.40"
  },
  "session": {
    "uid": "sess-123"
  },
  "unmapped": {
    "okta": {
      "transaction_id": "trn-789",
      "root_session_id": "root-456"
    }
  }
}
```

### OCSF

```json
{
  "class_uid": 3002,
  "category_uid": 3,
  "metadata": {
    "uid": "okta-123"
  },
  "time": 1776238800000,
  "actor": {
    "user": {
      "uid": "00u123",
      "name": "alice@example.com"
    }
  },
  "src_endpoint": {
    "ip": "203.0.113.40"
  },
  "session": {
    "uid": "sess-123"
  },
  "unmapped": {
    "okta": {
      "transaction_id": "trn-789",
      "root_session_id": "root-456"
    }
  }
}
```

### What to notice

- `uuid` survives directly as the stable event identity
- this is a good example of vendor detail being preserved under `unmapped.*`
- the loss is not “OCSF removes everything,” but that some Okta context is no longer a first-class standard field

## 5. Microsoft Entra `directoryAudit`

### What this source becomes

| Concern | Value |
|---|---|
| Source skill | `ingest-entra-directory-audit-ocsf` |
| Native type | `api_activity` |
| Default OCSF class | API Activity `6003` |
| Main natural ID | `id` |
| Main correlation ID | `correlationId` |
| Stable repo event ID | use `id` when available, otherwise deterministic fallback |

### Raw

```json
{
  "id": "entra-123",
  "correlationId": "corr-456",
  "activityDateTime": "2026-04-15T05:00:00Z",
  "activityDisplayName": "Add service principal credentials",
  "initiatedBy": {
    "user": {
      "userPrincipalName": "alice@example.com"
    }
  },
  "targetResources": [
    {
      "id": "sp-123",
      "type": "ServicePrincipal",
      "displayName": "prod-app"
    }
  ],
  "additionalDetails": [
    {
      "key": "CredentialType",
      "value": "Password"
    }
  ]
}
```

### Native

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "api_activity",
  "event_uid": "entra-123",
  "provider": "Azure",
  "time_ms": 1776238800000,
  "operation": "Add service principal credentials",
  "correlation_uid": "corr-456",
  "actor": {
    "user": {
      "name": "alice@example.com"
    }
  },
  "resources": [
    {
      "uid": "sp-123",
      "type": "ServicePrincipal",
      "name": "prod-app"
    }
  ],
  "unmapped": {
    "entra": {
      "additional_details": [
        {
          "key": "CredentialType",
          "value": "Password"
        }
      ]
    }
  }
}
```

### OCSF

```json
{
  "class_uid": 6003,
  "category_uid": 6,
  "metadata": {
    "uid": "entra-123"
  },
  "time": 1776238800000,
  "actor": {
    "user": {
      "name": "alice@example.com"
    }
  },
  "api": {
    "operation": "Add service principal credentials",
    "request": {
      "uid": "corr-456"
    }
  },
  "resources": [
    {
      "uid": "sp-123",
      "type": "ServicePrincipal",
      "name": "prod-app"
    }
  ],
  "unmapped": {
    "entra": {
      "additional_details": [
        {
          "key": "CredentialType",
          "value": "Password"
        }
      ]
    }
  }
}
```

### What to notice

- Entra gives both a natural event ID and a correlation ID; both matter
- `additionalDetails` is preserved under `unmapped.entra`
- target resource identity stays first-class in both native and OCSF

## Cross-example ID guide

| Field | Meaning | Typical source examples |
|---|---|---|
| `event_uid` | repo-stable event identity | CloudTrail `eventID`, Okta `uuid`, Entra `id`, deterministic flow keys |
| `finding_uid` | repo-stable finding identity | GuardDuty `Id` hash, detector semantic key hash |
| OCSF `metadata.uid` | OCSF event or finding identity | usually same semantic identity as `event_uid` or `finding_uid` |
| OCSF `api.request.uid` | request or operation handle | CloudTrail `eventID`, GCP `insertId`, Azure `correlationId`, K8s `auditID`, Entra `correlationId` |
| `session_uid` | stable login or session context | Okta `externalSessionId`, MCP session ID, cloud session handles where present |
| `correlation_uid` | broader cross-event transaction link | Azure `correlationId`, Entra `correlationId` |

## Update rule

Add a new example here when one of these changes:

- a major new vendor source lands
- an existing ingest skill changes its OCSF class mapping
- an identifier rule changes
- `unmapped.*` preservation becomes materially different

If this file, `NORMALIZATION_REFERENCE.md`, and a skill's `SKILL.md` disagree,
the skill contract and its tests win until the docs are updated together.
