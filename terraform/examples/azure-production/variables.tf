variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "westeurope"
}

variable "cluster_name" {
  description = "Name of the AKS cluster"
  type        = string
}

variable "trust_domain" {
  description = "SPIFFE trust domain"
  type        = string
}

variable "vnet_address_space" {
  description = "VNet address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "subnet_address_prefix" {
  description = "Subnet address prefix for AKS"
  type        = string
  default     = "10.0.0.0/20"
}

variable "enable_private_cluster" {
  description = "Enable private AKS cluster"
  type        = bool
  default     = true
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for monitoring"
  type        = string
  default     = null
}

variable "broker_image" {
  description = "ATB broker container image"
  type        = string
  default     = "ghcr.io/mauriciomferz/atb-broker:latest"
}

variable "agentauth_image" {
  description = "ATB agentauth container image"
  type        = string
  default     = "ghcr.io/mauriciomferz/atb-agentauth:latest"
}

variable "connectors" {
  description = "ATB connector configurations"
  type = map(object({
    type     = string
    endpoint = string
    auth     = optional(string, "spiffe")
    config   = optional(map(string), {})
  }))
  default = {}
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "ATB"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
