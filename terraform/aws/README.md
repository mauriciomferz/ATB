# ATB AWS Terraform Module

Deploys ATB to Amazon EKS with:
- IAM Roles for Service Accounts (IRSA)
- AWS Secrets Manager integration
- Amazon ECR for container images
- Application Load Balancer Ingress
- CloudWatch monitoring

## Usage

```hcl
module "atb" {
  source = "github.com/mauriciomferz/ATB//terraform/aws"

  cluster_name = "atb-cluster"
  vpc_id       = "vpc-xxxxxxxxx"
  subnet_ids   = ["subnet-xxx", "subnet-yyy", "subnet-zzz"]
  trust_domain = "atb.example.com"

  # Optional: Customize node group
  node_instance_type = "m5.large"
  node_desired_size  = 3

  # Optional: Enable monitoring
  enable_monitoring = true

  tags = {
    Environment = "production"
    Project     = "ATB"
  }
}

output "cluster_endpoint" {
  value = module.atb.cluster_endpoint
}

output "broker_endpoint" {
  value = module.atb.broker_endpoint
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5 |
| aws | >= 5.30 |
| helm | >= 2.12 |
| kubernetes | >= 2.25 |

## Resources

This module creates:

- EKS Cluster with managed node groups
- IAM OIDC provider for IRSA
- IAM roles for ATB workloads
- ECR repository
- Secrets Manager secrets
- CloudWatch log group
- Kubernetes namespace
- SPIRE deployment
- OPA deployment
- ATB services
- ALB Ingress Controller (optional)

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| cluster_name | EKS cluster name | `string` | n/a | yes |
| vpc_id | VPC ID | `string` | n/a | yes |
| subnet_ids | List of subnet IDs | `list(string)` | n/a | yes |
| trust_domain | SPIFFE trust domain | `string` | `"atb.example.com"` | no |
| namespace | Kubernetes namespace | `string` | `"atb-system"` | no |
| kubernetes_version | Kubernetes version | `string` | `"1.28"` | no |
| node_instance_type | Instance type for nodes | `string` | `"m5.large"` | no |
| node_desired_size | Desired number of nodes | `number` | `3` | no |
| node_min_size | Minimum number of nodes | `number` | `1` | no |
| node_max_size | Maximum number of nodes | `number` | `5` | no |
| enable_monitoring | Enable CloudWatch monitoring | `bool` | `true` | no |
| enable_alb_ingress | Enable ALB Ingress Controller | `bool` | `true` | no |
| broker_replicas | Number of broker replicas | `number` | `2` | no |
| tags | Resource tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| cluster_endpoint | EKS cluster endpoint |
| cluster_name | EKS cluster name |
| broker_endpoint | Broker service endpoint |
| ecr_repository_url | ECR repository URL |
| broker_role_arn | IAM role ARN for broker |
