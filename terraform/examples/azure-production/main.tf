terraform {
  required_version = ">= 1.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.10.0"
    }
  }

  backend "azurerm" {
    # Configure your backend
    # resource_group_name  = "tfstate"
    # storage_account_name = "tfstate"
    # container_name       = "tfstate"
    # key                  = "atb.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "azurerm_client_config" "current" {}

# -----------------------------------------------------------------------------
# ATB Azure Module
# -----------------------------------------------------------------------------

module "atb_azure" {
  source = "../../azure"

  resource_group_name = var.resource_group_name
  location            = var.location
  cluster_name        = var.cluster_name
  trust_domain        = var.trust_domain

  # Networking
  vnet_address_space    = var.vnet_address_space
  subnet_address_prefix = var.subnet_address_prefix
  enable_private_cluster = var.enable_private_cluster

  # Node pools
  default_node_pool = {
    name                = "system"
    vm_size             = "Standard_D4s_v3"
    node_count          = 3
    enable_auto_scaling = true
    min_count           = 3
    max_count           = 10
  }

  additional_node_pools = {
    atb = {
      name                = "atb"
      vm_size             = "Standard_D4s_v3"
      node_count          = 2
      enable_auto_scaling = true
      min_count           = 2
      max_count           = 6
      node_labels = {
        "workload" = "atb"
      }
      node_taints = ["workload=atb:NoSchedule"]
    }
  }

  # Security
  enable_workload_identity = true
  enable_azure_policy      = true

  # Monitoring
  enable_monitoring = true
  log_analytics_workspace_id = var.log_analytics_workspace_id

  tags = var.tags
}

# -----------------------------------------------------------------------------
# ATB Kubernetes Module
# -----------------------------------------------------------------------------

provider "kubernetes" {
  host                   = module.atb_azure.kube_config.host
  cluster_ca_certificate = base64decode(module.atb_azure.kube_config.cluster_ca_certificate)
  token                  = module.atb_azure.kube_config.token
}

provider "helm" {
  kubernetes {
    host                   = module.atb_azure.kube_config.host
    cluster_ca_certificate = base64decode(module.atb_azure.kube_config.cluster_ca_certificate)
    token                  = module.atb_azure.kube_config.token
  }
}

module "atb_kubernetes" {
  source = "../../kubernetes"

  namespace    = "atb"
  trust_domain = var.trust_domain

  broker_config = {
    replicas = 3
    image    = var.broker_image
    resources = {
      requests = {
        cpu    = "200m"
        memory = "512Mi"
      }
      limits = {
        cpu    = "1000m"
        memory = "1Gi"
      }
    }
  }

  agentauth_config = {
    replicas = 2
    image    = var.agentauth_image
  }

  connectors = var.connectors

  enable_spire            = true
  enable_monitoring       = true
  enable_network_policies = true

  helm_values = {
    tolerations = [{
      key      = "workload"
      operator = "Equal"
      value    = "atb"
      effect   = "NoSchedule"
    }]
    nodeSelector = {
      workload = "atb"
    }
  }

  depends_on = [module.atb_azure]
}

# -----------------------------------------------------------------------------
# Key Vault for Secrets
# -----------------------------------------------------------------------------

resource "azurerm_key_vault" "atb" {
  name                = "${var.cluster_name}-kv"
  location            = var.location
  resource_group_name = module.atb_azure.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  enable_rbac_authorization = true
  purge_protection_enabled  = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  tags = var.tags
}

# Grant ATB workload identity access to Key Vault
resource "azurerm_role_assignment" "atb_keyvault" {
  scope                = azurerm_key_vault.atb.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = module.atb_azure.workload_identity_principal_id
}
