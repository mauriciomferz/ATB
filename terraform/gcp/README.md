# ATB GCP Terraform Module

Deploys ATB to Google Kubernetes Engine (GKE) with:
- Workload Identity for secure pod authentication
- Secret Manager integration
- Artifact Registry for container images
- Cloud Monitoring and Logging
- Cloud Armor WAF (optional)

## Usage

```hcl
module "atb" {
  source = "github.com/mauriciomferz/ATB//terraform/gcp"

  project_id   = "my-project-id"
  region       = "europe-west1"
  cluster_name = "atb-cluster"
  trust_domain = "atb.example.com"

  # Optional: Customize node pool
  node_machine_type = "e2-standard-4"
  node_count        = 3

  # Optional: Enable monitoring
  enable_monitoring = true
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
| google | >= 5.10 |
| google-beta | >= 5.10 |
| helm | >= 2.12 |
| kubernetes | >= 2.25 |

## Resources

This module creates:

- GKE Autopilot or Standard cluster
- Artifact Registry repository
- Secret Manager secrets
- Service Accounts with Workload Identity
- VPC and subnets (optional)
- Cloud NAT (optional)
- Kubernetes namespace
- SPIRE deployment
- OPA deployment
- ATB services

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| project_id | GCP project ID | `string` | n/a | yes |
| region | GCP region | `string` | n/a | yes |
| cluster_name | GKE cluster name | `string` | n/a | yes |
| trust_domain | SPIFFE trust domain | `string` | `"atb.example.com"` | no |
| namespace | Kubernetes namespace | `string` | `"atb-system"` | no |
| use_autopilot | Use GKE Autopilot | `bool` | `false` | no |
| node_machine_type | Machine type for nodes | `string` | `"e2-standard-2"` | no |
| node_count | Number of nodes per zone | `number` | `1` | no |
| enable_monitoring | Enable Cloud Monitoring | `bool` | `true` | no |
| broker_replicas | Number of broker replicas | `number` | `2` | no |

## Outputs

| Name | Description |
|------|-------------|
| cluster_endpoint | GKE cluster endpoint |
| cluster_name | GKE cluster name |
| broker_endpoint | Broker service endpoint |
| artifact_registry_url | Artifact Registry URL |
| workload_identity_pool | Workload Identity pool |
