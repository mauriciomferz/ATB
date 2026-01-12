# ATB Azure Terraform Module

Deploys ATB to Azure Kubernetes Service (AKS) with:
- Managed identity with Workload Identity
- Azure Key Vault for secrets
- Azure Container Registry
- Azure Monitor integration

## Usage

```hcl
module "atb" {
  source = "github.com/mauriciomferz/ATB//terraform/azure"

  resource_group_name = "atb-prod-rg"
  location            = "westeurope"
  cluster_name        = "atb-cluster"
  trust_domain        = "atb.example.com"

  # Optional: Customize node pool
  node_pool_vm_size = "Standard_D4s_v3"
  node_pool_count   = 3

  # Optional: Enable monitoring
  enable_monitoring = true

  tags = {
    Environment = "production"
    Project     = "ATB"
  }
}

output "kube_config" {
  value     = module.atb.kube_config
  sensitive = true
}

output "broker_endpoint" {
  value = module.atb.broker_endpoint
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5 |
| azurerm | >= 3.80 |
| azuread | >= 2.45 |
| helm | >= 2.12 |
| kubernetes | >= 2.25 |

## Providers

| Name | Version |
|------|---------|
| azurerm | >= 3.80 |
| azuread | >= 2.45 |
| helm | >= 2.12 |
| kubernetes | >= 2.25 |

## Resources

This module creates:

- Azure Resource Group (optional)
- Azure Kubernetes Service cluster
- Azure Container Registry
- Azure Key Vault
- User Assigned Managed Identities
- Workload Identity federation
- Kubernetes namespace
- SPIRE deployment
- OPA deployment
- ATB services

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| resource_group_name | Name of the resource group | `string` | n/a | yes |
| location | Azure region | `string` | n/a | yes |
| cluster_name | AKS cluster name | `string` | n/a | yes |
| trust_domain | SPIFFE trust domain | `string` | `"atb.example.com"` | no |
| namespace | Kubernetes namespace | `string` | `"atb-system"` | no |
| node_pool_vm_size | VM size for node pool | `string` | `"Standard_D2s_v3"` | no |
| node_pool_count | Number of nodes | `number` | `3` | no |
| enable_monitoring | Enable Azure Monitor | `bool` | `true` | no |
| enable_network_policies | Enable Kubernetes network policies | `bool` | `true` | no |
| broker_replicas | Number of broker replicas | `number` | `2` | no |
| tags | Resource tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| kube_config | Kubernetes configuration |
| cluster_name | AKS cluster name |
| resource_group_name | Resource group name |
| broker_endpoint | Broker service endpoint |
| acr_login_server | Container registry URL |
| key_vault_name | Key Vault name |
| workload_identity_client_id | Workload identity client ID |
