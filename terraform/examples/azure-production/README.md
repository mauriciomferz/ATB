# ATB Azure Example - Production Deployment

This example demonstrates a production-grade deployment of ATB on Azure AKS.

## Features

- AKS cluster with workload identity
- Azure Key Vault integration for secrets
- Azure Monitor integration
- Private networking with VNet
- Managed identities

## Prerequisites

- Azure CLI installed and authenticated
- Terraform >= 1.0.0
- kubectl configured

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

Get the kubeconfig:
```bash
az aks get-credentials --resource-group $(terraform output -raw resource_group_name) --name $(terraform output -raw cluster_name)
```

Verify ATB is running:
```bash
kubectl get pods -n atb
```

## Cleanup

```bash
terraform destroy
```
