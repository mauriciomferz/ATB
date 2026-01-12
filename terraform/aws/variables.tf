# Required variables
variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for the cluster"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the cluster"
  type        = list(string)
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

variable "kubernetes_version" {
  description = "Kubernetes version for EKS"
  type        = string
  default     = "1.28"
}

variable "node_instance_type" {
  description = "Instance type for node group"
  type        = string
  default     = "m5.large"
}

variable "node_desired_size" {
  description = "Desired number of nodes"
  type        = number
  default     = 3
}

variable "node_min_size" {
  description = "Minimum number of nodes"
  type        = number
  default     = 1
}

variable "node_max_size" {
  description = "Maximum number of nodes"
  type        = number
  default     = 5
}

variable "enable_public_access" {
  description = "Enable public access to cluster endpoint"
  type        = bool
  default     = false
}

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "enable_alb_ingress" {
  description = "Enable ALB Ingress Controller"
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
