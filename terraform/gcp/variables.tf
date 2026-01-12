# Required variables
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
}

# Optional variables
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

variable "use_autopilot" {
  description = "Use GKE Autopilot mode"
  type        = bool
  default     = false
}

variable "node_machine_type" {
  description = "Machine type for node pool"
  type        = string
  default     = "e2-standard-2"
}

variable "node_count" {
  description = "Number of nodes per zone"
  type        = number
  default     = 1
}

variable "node_min_count" {
  description = "Minimum number of nodes per zone"
  type        = number
  default     = 1
}

variable "node_max_count" {
  description = "Maximum number of nodes per zone"
  type        = number
  default     = 3
}

variable "create_vpc" {
  description = "Create a new VPC for the cluster"
  type        = bool
  default     = true
}

variable "network_name" {
  description = "Existing VPC network name (if create_vpc=false)"
  type        = string
  default     = ""
}

variable "subnetwork_name" {
  description = "Existing subnetwork name (if create_vpc=false)"
  type        = string
  default     = ""
}

variable "subnet_cidr" {
  description = "CIDR for the subnet"
  type        = string
  default     = "10.0.0.0/24"
}

variable "pods_cidr" {
  description = "CIDR for pods secondary range"
  type        = string
  default     = "10.1.0.0/16"
}

variable "services_cidr" {
  description = "CIDR for services secondary range"
  type        = string
  default     = "10.2.0.0/20"
}

variable "pods_range_name" {
  description = "Name of existing pods secondary range"
  type        = string
  default     = ""
}

variable "services_range_name" {
  description = "Name of existing services secondary range"
  type        = string
  default     = ""
}

variable "enable_monitoring" {
  description = "Enable Cloud Monitoring"
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
