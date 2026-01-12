variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "cluster_version" {
  description = "Kubernetes version for EKS"
  type        = string
  default     = "1.28"
}

variable "vpc_id" {
  description = "VPC ID for EKS cluster"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for EKS cluster"
  type        = list(string)
}

variable "trust_domain" {
  description = "SPIFFE trust domain"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
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
