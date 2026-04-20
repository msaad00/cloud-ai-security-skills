# iam-departures-azure-entra — Terraform module
#
# Equivalent to arm_template.json. Deploys the manifest + audit storage
# accounts (customer-managed keys from Azure Key Vault), the Cosmos DB audit
# account, three user-assigned managed identities (parser, worker, Logic
# App), and the EventGrid system topic on the manifest storage account.
#
# Custom RBAC role for the Worker MSI at the management-group scope is in
# infra/iam_policies/cross_subscription_role.json and is deployed via
# `az role definition create`, NOT terraform — the management-group API
# surface is fiddly under terraform and the custom role shape is already
# declarative JSON.
#
# MITRE ATT&CK: T1078.004, T1098.001, T1087.004, T1531, T1552
# NIST CSF 2.0: PR.AC-1, PR.AC-4, DE.CM-3, RS.MI-2
# CIS Controls v8: 5.3, 6.1, 6.2, 6.5

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.80"
    }
  }
}

provider "azurerm" {
  features {}
}

# ── Variables ──────────────────────────────────────────────────────────

variable "name_prefix" {
  description = "Resource name prefix (max 12 chars to stay inside Azure naming limits after unique suffix)."
  type        = string
  default     = "iam-dep"
  validation {
    condition     = length(var.name_prefix) <= 12
    error_message = "name_prefix must be <= 12 characters."
  }
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "resource_group_name" {
  description = "Target resource group (must already exist)."
  type        = string
}

variable "management_group_id" {
  description = "Management group ID that bounds the Worker's cross-subscription role."
  type        = string
}

variable "key_vault_key_id" {
  description = "Customer-managed key URI used to encrypt manifest + audit blobs and Cosmos data."
  type        = string
  validation {
    condition     = can(regex("^https://[a-zA-Z0-9-]+\\.vault\\.azure\\.net/keys/", var.key_vault_key_id))
    error_message = "key_vault_key_id must be a Key Vault key URI (https://<vault>.vault.azure.net/keys/<name>...)."
  }
}

variable "grace_period_days" {
  description = "Days after termination before remediation may fire. Never zero."
  type        = number
  default     = 7
  validation {
    condition     = var.grace_period_days >= 1 && var.grace_period_days <= 90
    error_message = "grace_period_days must be between 1 and 90."
  }
}

variable "alert_email" {
  description = "Action Group email for Logic App failure alerts."
  type        = string
}

# ── Managed identities ────────────────────────────────────────────────

resource "azurerm_user_assigned_identity" "parser" {
  name                = "${var.name_prefix}-parser-msi"
  resource_group_name = var.resource_group_name
  location            = var.location
}

resource "azurerm_user_assigned_identity" "worker" {
  name                = "${var.name_prefix}-worker-msi"
  resource_group_name = var.resource_group_name
  location            = var.location
}

resource "azurerm_user_assigned_identity" "logicapp" {
  name                = "${var.name_prefix}-logicapp-msi"
  resource_group_name = var.resource_group_name
  location            = var.location
}

# ── Storage (manifest + audit) ────────────────────────────────────────

resource "random_string" "unique" {
  length  = 6
  lower   = true
  numeric = true
  special = false
  upper   = false
}

resource "azurerm_storage_account" "manifest" {
  name                     = "${replace(var.name_prefix, "-", "")}${random_string.unique.result}m"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false

  customer_managed_key {
    key_vault_key_id          = var.key_vault_key_id
    user_assigned_identity_id = azurerm_user_assigned_identity.worker.id
  }
}

resource "azurerm_storage_account" "audit" {
  name                     = "${replace(var.name_prefix, "-", "")}${random_string.unique.result}a"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GZRS"
  min_tls_version          = "TLS1_2"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false

  customer_managed_key {
    key_vault_key_id          = var.key_vault_key_id
    user_assigned_identity_id = azurerm_user_assigned_identity.worker.id
  }
}

# ── Cosmos DB (audit rows) ────────────────────────────────────────────

resource "azurerm_cosmosdb_account" "audit" {
  name                = "${var.name_prefix}-cosmos-${random_string.unique.result}"
  resource_group_name = var.resource_group_name
  location            = var.location
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  local_authentication_disabled = true
  public_network_access_enabled = false
  minimal_tls_version           = "Tls12"
  key_vault_key_id              = var.key_vault_key_id

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }
}

# ── EventGrid system topic ────────────────────────────────────────────

resource "azurerm_eventgrid_system_topic" "manifest" {
  name                   = "${azurerm_storage_account.manifest.name}-evt"
  resource_group_name    = var.resource_group_name
  location               = var.location
  source_arm_resource_id = azurerm_storage_account.manifest.id
  topic_type             = "Microsoft.Storage.StorageAccounts"
}

# ── Role assignments (scoped, not wildcard) ───────────────────────────
# The parser reads the manifest blob only.
resource "azurerm_role_assignment" "parser_manifest_read" {
  scope                = azurerm_storage_account.manifest.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.parser.principal_id
}

# The worker writes audit rows + blobs only on the audit resources.
resource "azurerm_role_assignment" "worker_cosmos" {
  scope                = azurerm_cosmosdb_account.audit.id
  role_definition_name = "Cosmos DB Built-in Data Contributor"
  principal_id         = azurerm_user_assigned_identity.worker.principal_id
}

resource "azurerm_role_assignment" "worker_audit_blob" {
  scope                = azurerm_storage_account.audit.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.worker.principal_id
}

# ── Outputs ───────────────────────────────────────────────────────────

output "manifest_storage_account" { value = azurerm_storage_account.manifest.name }
output "audit_storage_account"    { value = azurerm_storage_account.audit.name }
output "cosmos_account"           { value = azurerm_cosmosdb_account.audit.name }
output "parser_msi_principal_id"  { value = azurerm_user_assigned_identity.parser.principal_id }
output "worker_msi_principal_id"  { value = azurerm_user_assigned_identity.worker.principal_id }
output "logicapp_msi_principal_id" { value = azurerm_user_assigned_identity.logicapp.principal_id }
output "management_group_id"      { value = var.management_group_id }
output "grace_period_days"        { value = var.grace_period_days }
