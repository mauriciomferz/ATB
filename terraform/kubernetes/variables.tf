# -----------------------------------------------------------------------------
# General
# -----------------------------------------------------------------------------

variable "namespace" {
  description = "Kubernetes namespace for ATB deployment"
  type        = string
  default     = "atb"
}

variable "create_namespace" {
  description = "Whether to create the namespace"
  type        = bool
  default     = true
}

variable "release_name" {
  description = "Helm release name"
  type        = string
  default     = "atb"
}

variable "labels" {
  description = "Additional labels to apply to resources"
  type        = map(string)
  default     = {}
}

variable "trust_domain" {
  description = "SPIFFE trust domain for workload identity"
  type        = string
}

# -----------------------------------------------------------------------------
# Helm Configuration
# -----------------------------------------------------------------------------

variable "helm_repository" {
  description = "Helm chart repository URL"
  type        = string
  default     = "https://mauriciomferz.github.io/ATB"
}

variable "helm_chart" {
  description = "Helm chart name"
  type        = string
  default     = "atb"
}

variable "helm_chart_version" {
  description = "Helm chart version"
  type        = string
  default     = null
}

variable "helm_values" {
  description = "Additional Helm values to merge"
  type        = any
  default     = {}
}

variable "helm_timeout" {
  description = "Timeout for Helm operations in seconds"
  type        = number
  default     = 600
}

variable "wait_for_ready" {
  description = "Wait for all resources to be ready"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Broker Configuration
# -----------------------------------------------------------------------------

variable "broker_config" {
  description = "Broker deployment configuration"
  type = object({
    replicas = optional(number, 2)
    image    = optional(string, "ghcr.io/mauriciomferz/atb-broker:latest")
    resources = optional(object({
      requests = optional(object({
        cpu    = optional(string, "100m")
        memory = optional(string, "256Mi")
      }), {})
      limits = optional(object({
        cpu    = optional(string, "500m")
        memory = optional(string, "512Mi")
      }), {})
    }), {})
  })
  default = {}
}

# -----------------------------------------------------------------------------
# Agent Auth Configuration
# -----------------------------------------------------------------------------

variable "agentauth_config" {
  description = "Agent Auth deployment configuration"
  type = object({
    replicas = optional(number, 2)
    image    = optional(string, "ghcr.io/mauriciomferz/atb-agentauth:latest")
    resources = optional(object({
      requests = optional(object({
        cpu    = optional(string, "50m")
        memory = optional(string, "128Mi")
      }), {})
      limits = optional(object({
        cpu    = optional(string, "200m")
        memory = optional(string, "256Mi")
      }), {})
    }), {})
  })
  default = {}
}

# -----------------------------------------------------------------------------
# OPA Configuration
# -----------------------------------------------------------------------------

variable "opa_config" {
  description = "OPA deployment configuration"
  type = object({
    replicas = optional(number, 2)
    resources = optional(object({
      requests = optional(object({
        cpu    = optional(string, "50m")
        memory = optional(string, "64Mi")
      }), {})
      limits = optional(object({
        cpu    = optional(string, "200m")
        memory = optional(string, "128Mi")
      }), {})
    }), {})
  })
  default = {}
}

# -----------------------------------------------------------------------------
# Connectors
# -----------------------------------------------------------------------------

variable "connectors" {
  description = "Connector configurations"
  type = map(object({
    type     = string
    endpoint = string
    auth     = optional(string, "spiffe")
    config   = optional(map(string), {})
  }))
  default = {}
}

# -----------------------------------------------------------------------------
# SPIRE Configuration
# -----------------------------------------------------------------------------

variable "enable_spire" {
  description = "Enable SPIRE for workload identity"
  type        = bool
  default     = true
}

variable "deploy_spire_separately" {
  description = "Deploy SPIRE agent separately from Helm chart"
  type        = bool
  default     = false
}

variable "spire_agent_image" {
  description = "SPIRE agent container image"
  type        = string
  default     = "ghcr.io/spiffe/spire-agent:1.8.0"
}

# -----------------------------------------------------------------------------
# Monitoring
# -----------------------------------------------------------------------------

variable "enable_monitoring" {
  description = "Enable Prometheus ServiceMonitors"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Security
# -----------------------------------------------------------------------------

variable "enable_network_policies" {
  description = "Enable Kubernetes network policies"
  type        = bool
  default     = true
}

variable "ingress_namespace_labels" {
  description = "Labels for namespaces allowed to access ATB"
  type        = map(string)
  default = {
    "atb.io/access" = "allowed"
  }
}
