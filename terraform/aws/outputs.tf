output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.main.name
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = aws_eks_cluster.main.arn
}

output "cluster_certificate_authority" {
  description = "EKS cluster CA certificate"
  value       = aws_eks_cluster.main.certificate_authority[0].data
  sensitive   = true
}

output "broker_endpoint" {
  description = "Broker service endpoint (internal)"
  value       = "http://broker.${var.namespace}.svc.cluster.local:8080"
}

output "ecr_repository_url" {
  description = "ECR repository URL for ATB images"
  value       = aws_ecr_repository.atb.repository_url
}

output "broker_role_arn" {
  description = "IAM role ARN for broker service account"
  value       = aws_iam_role.broker.arn
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN for IRSA"
  value       = aws_iam_openid_connect_provider.cluster.arn
}

output "secrets_manager_secret_arn" {
  description = "Secrets Manager secret ARN"
  value       = aws_secretsmanager_secret.atb.arn
}

output "namespace" {
  description = "Kubernetes namespace"
  value       = var.namespace
}

output "kubeconfig_command" {
  description = "Command to update kubeconfig"
  value       = "aws eks update-kubeconfig --name ${aws_eks_cluster.main.name} --region ${data.aws_region.current.name}"
}
