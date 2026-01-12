output "cluster_endpoint" {
  description = "GKE cluster endpoint"
  value       = google_container_cluster.main.endpoint
}

output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.main.name
}

output "cluster_location" {
  description = "GKE cluster location"
  value       = google_container_cluster.main.location
}

output "cluster_ca_certificate" {
  description = "GKE cluster CA certificate"
  value       = google_container_cluster.main.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "broker_endpoint" {
  description = "Broker service endpoint (internal)"
  value       = "http://broker.${var.namespace}.svc.cluster.local:8080"
}

output "artifact_registry_url" {
  description = "Artifact Registry URL for ATB images"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.atb.repository_id}"
}

output "workload_identity_pool" {
  description = "Workload Identity pool"
  value       = "${var.project_id}.svc.id.goog"
}

output "service_account_email" {
  description = "Service account email for ATB"
  value       = google_service_account.atb.email
}

output "secret_manager_secret" {
  description = "Secret Manager secret name"
  value       = google_secret_manager_secret.atb.secret_id
}

output "namespace" {
  description = "Kubernetes namespace"
  value       = var.namespace
}

output "kubeconfig_command" {
  description = "Command to update kubeconfig"
  value       = "gcloud container clusters get-credentials ${google_container_cluster.main.name} --region ${var.region} --project ${var.project_id}"
}
