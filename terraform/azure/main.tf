terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.80"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 2.45"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

provider "azuread" {}

provider "helm" {
  kubernetes {
    host                   = azurerm_kubernetes_cluster.main.kube_config[0].host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].cluster_ca_certificate)
  }
}

provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.main.kube_config[0].host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].cluster_ca_certificate)
}

# Data sources
data "azurerm_client_config" "current" {}
data "azuread_client_config" "current" {}

# Resource Group
resource "azurerm_resource_group" "main" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

locals {
  resource_group_name = var.create_resource_group ? azurerm_resource_group.main[0].name : var.resource_group_name
  resource_group_id   = var.create_resource_group ? azurerm_resource_group.main[0].id : data.azurerm_resource_group.existing[0].id
}

data "azurerm_resource_group" "existing" {
  count = var.create_resource_group ? 0 : 1
  name  = var.resource_group_name
}

# Azure Container Registry
resource "azurerm_container_registry" "main" {
  name                = replace("${var.cluster_name}acr", "-", "")
  resource_group_name = local.resource_group_name
  location            = var.location
  sku                 = "Standard"
  admin_enabled       = false
  tags                = var.tags
}

# Azure Key Vault
resource "azurerm_key_vault" "main" {
  name                       = "${var.cluster_name}-kv"
  location                   = var.location
  resource_group_name        = local.resource_group_name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = true
  enable_rbac_authorization  = true
  tags                       = var.tags
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = var.location
  resource_group_name = local.resource_group_name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version

  default_node_pool {
    name                = "default"
    node_count          = var.node_pool_count
    vm_size             = var.node_pool_vm_size
    enable_auto_scaling = var.enable_autoscaling
    min_count           = var.enable_autoscaling ? var.node_pool_min_count : null
    max_count           = var.enable_autoscaling ? var.node_pool_max_count : null
  }

  identity {
    type = "SystemAssigned"
  }

  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  network_profile {
    network_plugin    = "azure"
    network_policy    = var.enable_network_policies ? "azure" : null
    load_balancer_sku = "standard"
  }

  dynamic "oms_agent" {
    for_each = var.enable_monitoring ? [1] : []
    content {
      log_analytics_workspace_id = azurerm_log_analytics_workspace.main[0].id
    }
  }

  tags = var.tags
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "main" {
  count               = var.enable_monitoring ? 1 : 0
  name                = "${var.cluster_name}-logs"
  location            = var.location
  resource_group_name = local.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

# User Assigned Identity for Workload Identity
resource "azurerm_user_assigned_identity" "atb" {
  name                = "${var.cluster_name}-atb-identity"
  location            = var.location
  resource_group_name = local.resource_group_name
  tags                = var.tags
}

# Federated identity credential for ATB workloads
resource "azurerm_federated_identity_credential" "atb" {
  name                = "${var.cluster_name}-atb-federated"
  resource_group_name = local.resource_group_name
  parent_id           = azurerm_user_assigned_identity.atb.id
  issuer              = azurerm_kubernetes_cluster.main.oidc_issuer_url
  subject             = "system:serviceaccount:${var.namespace}:atb-broker"
  audience            = ["api://AzureADTokenExchange"]
}

# Key Vault access for ATB identity
resource "azurerm_role_assignment" "atb_kv_secrets" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.atb.principal_id
}

# ACR pull access for AKS
resource "azurerm_role_assignment" "aks_acr_pull" {
  scope                            = azurerm_container_registry.main.id
  role_definition_name             = "AcrPull"
  principal_id                     = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
  skip_service_principal_aad_check = true
}

# Kubernetes namespace
resource "kubernetes_namespace" "atb" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "atb"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  depends_on = [azurerm_kubernetes_cluster.main]
}

# Helm release for ATB
resource "helm_release" "atb" {
  name       = "atb"
  namespace  = kubernetes_namespace.atb.metadata[0].name
  chart      = "${path.module}/../../../charts/atb"
  
  values = [
    yamlencode({
      global = {
        trustDomain = var.trust_domain
        namespace   = var.namespace
      }
      broker = {
        replicas = var.broker_replicas
        serviceAccount = {
          annotations = {
            "azure.workload.identity/client-id" = azurerm_user_assigned_identity.atb.client_id
          }
        }
      }
      agentauth = {
        replicas = var.agentauth_replicas
      }
      opa = {
        replicas = var.opa_replicas
      }
    })
  ]

  depends_on = [
    kubernetes_namespace.atb,
    azurerm_federated_identity_credential.atb,
  ]
}
