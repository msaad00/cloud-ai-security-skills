# References — iam-departures-azure-entra

Every reference below is from `learn.microsoft.com` (the only allowed Azure docs host per repo policy). MITRE / NIST / CIS references for the framework mappings live in [`SKILL.md`](SKILL.md).

## Microsoft Graph — User lifecycle

- **Update user** — https://learn.microsoft.com/en-us/graph/api/user-update
- **Delete user** — https://learn.microsoft.com/en-us/graph/api/user-delete
- **revokeSignInSessions** — https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions
- **Get user** — https://learn.microsoft.com/en-us/graph/api/user-get
- **Microsoft Graph SDK for Python** — https://learn.microsoft.com/en-us/graph/sdks/sdk-installation
- **Permissions reference** — https://learn.microsoft.com/en-us/graph/permissions-reference
- **Extension properties** — https://learn.microsoft.com/en-us/graph/extensibility-overview

## Microsoft Graph — Group + role memberships

- **Group members** — https://learn.microsoft.com/en-us/graph/api/group-list-members
- **Remove group member** — https://learn.microsoft.com/en-us/graph/api/group-delete-members
- **DirectoryRole list members** — https://learn.microsoft.com/en-us/graph/api/directoryrole-list-members
- **DirectoryRole remove member** — https://learn.microsoft.com/en-us/graph/api/directoryrole-delete-member

## Microsoft Graph — App + delegated grants

- **OAuth2 permission grants** — https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant
- **Delete oauth2PermissionGrant** — https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-delete
- **List user appRoleAssignments** — https://learn.microsoft.com/en-us/graph/api/user-list-approleassignments
- **Delete appRoleAssignment** — https://learn.microsoft.com/en-us/graph/api/user-delete-approleassignments

## Microsoft Graph — Licenses

- **assignLicense** — https://learn.microsoft.com/en-us/graph/api/user-assignlicense
- **List licenseDetails** — https://learn.microsoft.com/en-us/graph/api/user-list-licensedetails

## Azure RBAC

- **Role assignments REST API** — https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments
- **Delete role assignment** — https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/delete
- **List role assignments by scope** — https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-scope
- **Management group scope** — https://learn.microsoft.com/en-us/azure/governance/management-groups/overview
- **azure-mgmt-authorization SDK** — https://learn.microsoft.com/en-us/python/api/overview/azure/authorization

## Azure Identity (auth for the Function App)

- **DefaultAzureCredential** — https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential
- **Managed identities for Azure resources** — https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview

## Azure infrastructure (orchestration stack)

- **Azure Functions Python** — https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-python
- **Durable Functions overview** — https://learn.microsoft.com/en-us/azure/azure-functions/durable/durable-functions-overview
- **Logic Apps overview** — https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview
- **EventGrid Blob Storage events** — https://learn.microsoft.com/en-us/azure/event-grid/event-schema-blob-storage
- **EventGrid system topics** — https://learn.microsoft.com/en-us/azure/event-grid/system-topics
- **Azure Cosmos DB Python SDK** — https://learn.microsoft.com/en-us/azure/cosmos-db/nosql/quickstart-python
- **Azure Blob Storage Python SDK** — https://learn.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-python
- **Customer-managed keys for storage encryption** — https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview
- **Azure Key Vault REST API** — https://learn.microsoft.com/en-us/rest/api/keyvault
- **Azure Resource Manager templates** — https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/overview
