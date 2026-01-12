# -----------------------------------------------------------------------------
# Namespace
# -----------------------------------------------------------------------------

output "namespace" {
  description = "The namespace where ATB is deployed"
  value       = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace
}

# -----------------------------------------------------------------------------
# Helm Release
# -----------------------------------------------------------------------------

output "helm_release_name" {
  description = "Helm release name"
  value       = helm_release.atb.name
}

output "helm_release_version" {
  description = "Helm release version"
  value       = helm_release.atb.version
}

output "helm_release_status" {
  description = "Helm release status"
  value       = helm_release.atb.status
}

# -----------------------------------------------------------------------------
# Service Endpoints
# -----------------------------------------------------------------------------

output "broker_service" {
  description = "Broker service details"
  value = {
    name      = "${helm_release.atb.name}-broker"
    namespace = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace
    port      = 8080
    endpoint  = "${helm_release.atb.name}-broker.${var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace}.svc.cluster.local:8080"
  }
}

output "agentauth_service" {
  description = "Agent Auth service details"
  value = {
    name      = "${helm_release.atb.name}-agentauth"
    namespace = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace
    port      = 8081
    endpoint  = "${helm_release.atb.name}-agentauth.${var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace}.svc.cluster.local:8081"
  }
}

output "opa_service" {
  description = "OPA service details"
  value = {
    name      = "${helm_release.atb.name}-opa"
    namespace = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace
    port      = 8181
    endpoint  = "${helm_release.atb.name}-opa.${var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace}.svc.cluster.local:8181"
  }
}

# -----------------------------------------------------------------------------
# SPIRE
# -----------------------------------------------------------------------------

output "spire_agent_socket" {
  description = "Path to SPIRE agent socket"
  value       = var.enable_spire ? "/run/spire/sockets/agent.sock" : null
}

output "trust_domain" {
  description = "SPIFFE trust domain"
  value       = var.trust_domain
}

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

output "connectors" {
  description = "Configured connectors"
  value       = keys(var.connectors)
}

output "features" {
  description = "Enabled features"
  value = {
    spire            = var.enable_spire
    monitoring       = var.enable_monitoring
    network_policies = var.enable_network_policies
  }
}
