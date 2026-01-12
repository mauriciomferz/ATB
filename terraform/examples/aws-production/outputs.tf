output "region" {
  description = "AWS region"
  value       = var.region
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.atb_aws.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.atb_aws.cluster_endpoint
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

output "secrets_arn" {
  description = "Secrets Manager secret ARN"
  value       = aws_secretsmanager_secret.atb.arn
}

output "atb_role_arn" {
  description = "IAM role ARN for ATB service account"
  value       = module.atb_aws.atb_role_arn
}

output "update_kubeconfig_command" {
  description = "Command to update kubeconfig"
  value       = "aws eks update-kubeconfig --name ${module.atb_aws.cluster_name} --region ${var.region}"
}
