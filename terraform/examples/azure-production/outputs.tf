output "resource_group_name" {
  description = "Resource group name"
  value       = module.atb_azure.resource_group_name
}

output "cluster_name" {
  description = "AKS cluster name"
  value       = module.atb_azure.cluster_name
}

output "cluster_endpoint" {
  description = "AKS cluster endpoint"
  value       = module.atb_azure.kube_config.host
  sensitive   = true
}

output "atb_namespace" {
  description = "ATB Kubernetes namespace"
  value       = module.atb_kubernetes.namespace
}

output "broker_endpoint" {
  description = "ATB broker endpoint"
  value       = module.atb_kubernetes.broker_service.endpoint
}

output "key_vault_name" {
  description = "Key Vault name for secrets"
  value       = azurerm_key_vault.atb.name
}

output "key_vault_uri" {
  description = "Key Vault URI"
  value       = azurerm_key_vault.atb.vault_uri
}

output "get_credentials_command" {
  description = "Command to get AKS credentials"
  value       = "az aks get-credentials --resource-group ${module.atb_azure.resource_group_name} --name ${module.atb_azure.cluster_name}"
}
