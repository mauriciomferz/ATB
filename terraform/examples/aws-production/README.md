# ATB AWS Example - Production Deployment

This example demonstrates a production-grade deployment of ATB on AWS EKS.

## Features

- EKS cluster with IRSA (IAM Roles for Service Accounts)
- AWS Secrets Manager integration
- CloudWatch Logs integration
- Private networking with VPC
- KMS encryption for secrets

## Prerequisites

- AWS CLI installed and authenticated
- Terraform >= 1.0.0
- kubectl configured
- eksctl (optional, for add-ons)

## Usage

1. Copy `terraform.tfvars.example` to `terraform.tfvars`:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

2. Edit `terraform.tfvars` with your values

3. Initialize Terraform:
   ```bash
   terraform init
   ```

4. Review the plan:
   ```bash
   terraform plan
   ```

5. Apply:
   ```bash
   terraform apply
   ```

## Post-Deployment

Update kubeconfig:
```bash
aws eks update-kubeconfig --name $(terraform output -raw cluster_name) --region $(terraform output -raw region)
```

Verify ATB is running:
```bash
kubectl get pods -n atb
```

## Cleanup

```bash
terraform destroy
```
