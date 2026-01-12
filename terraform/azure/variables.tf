# Required variables
variable "resource_group_name" {
  description = "Name of the Azure resource group"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
}

variable "cluster_name" {
  description = "Name of the AKS cluster"
  type        = string
}

# Optional variables
variable "create_resource_group" {
  description = "Whether to create a new resource group"
  type        = bool
  default     = true
}

variable "trust_domain" {
  description = "SPIFFE trust domain"
  type        = string
  default     = "atb.example.com"
}

variable "namespace" {
  description = "Kubernetes namespace for ATB"
  type        = string
  default     = "atb-system"
}

variable "kubernetes_version" {
  description = "Kubernetes version for AKS"
  type        = string
  default     = "1.28"
}

variable "node_pool_vm_size" {
  description = "VM size for the default node pool"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "node_pool_count" {
  description = "Number of nodes in the default node pool"
  type        = number
  default     = 3
}

variable "enable_autoscaling" {
  description = "Enable cluster autoscaling"
  type        = bool
  default     = false
}

variable "node_pool_min_count" {
  description = "Minimum number of nodes when autoscaling"
  type        = number
  default     = 1
}

variable "node_pool_max_count" {
  description = "Maximum number of nodes when autoscaling"
  type        = number
  default     = 5
}

variable "enable_monitoring" {
  description = "Enable Azure Monitor for containers"
  type        = bool
  default     = true
}

variable "enable_network_policies" {
  description = "Enable Kubernetes network policies"
  type        = bool
  default     = true
}

variable "broker_replicas" {
  description = "Number of broker replicas"
  type        = number
  default     = 2
}

variable "agentauth_replicas" {
  description = "Number of agentauth replicas"
  type        = number
  default     = 2
}

variable "opa_replicas" {
  description = "Number of OPA replicas"
  type        = number
  default     = 2
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
