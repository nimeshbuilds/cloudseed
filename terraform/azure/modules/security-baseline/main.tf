variable "prefix" { type = string }
variable "location" { type = string }
variable "resource_group_name" { type = string }
variable "enable_activity_log" { type = bool }
variable "log_retention_days" { type = number }
variable "enable_defender" { type = bool }
variable "tags" { type = map(string) }

data "azurerm_client_config" "current" {}

resource "azurerm_log_analytics_workspace" "this" {
  name                = "${var.prefix}-logs"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = max(30, var.log_retention_days)
  tags                = var.tags
}

locals {
  # Defender plan (resource type) -> sub-plan; the keys are the instance keys in the state, keep them stable
  defender_plans = { VirtualMachines = "P2", StorageAccounts = "DefenderForStorageV2" }
  activity_categories = [
    "Administrative", "Security", "ServiceHealth", "Alert",
    "Recommendation", "Policy", "Autoscale", "ResourceHealth",
  ]
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  count = var.enable_activity_log ? 1 : 0

  name                       = "${var.prefix}-activity-log"
  target_resource_id         = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  dynamic "enabled_log" {
    for_each = toset(local.activity_categories)
    content {
      category = enabled_log.value
    }
  }
}

# Microsoft Defender for Cloud: Defender for Servers Plan 2 and Defender for Storage (the per-account V2 plan), the
# plans the Pricings API applies to a Standard tier without a sub-plan and reports back afterwards. The provider treats
# subplan as ForceNew and not computed: left unset, every later plan would replace both pricings, and a replacement
# switches Defender to Free for the whole subscription before enabling it again. ignore_changes keeps a plan or an
# extension (agentless scanning, malware scanning ...) an administrator chose later instead of replacing or disabling
# it: these are subscription-wide settings other workloads rely on.
resource "azurerm_security_center_subscription_pricing" "this" {
  for_each = var.enable_defender ? local.defender_plans : {}

  tier          = "Standard"
  resource_type = each.key
  subplan       = each.value

  lifecycle {
    ignore_changes = [subplan, extension]
  }
}

output "log_analytics_workspace_id" { value = azurerm_log_analytics_workspace.this.id }
