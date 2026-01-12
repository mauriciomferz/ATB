terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.10"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 5.10"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

data "google_client_config" "default" {}
data "google_project" "project" {}

# Enable required APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "container.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])

  service            = each.value
  disable_on_destroy = false
}

# VPC Network (optional - can use existing)
resource "google_compute_network" "main" {
  count                   = var.create_vpc ? 1 : 0
  name                    = "${var.cluster_name}-vpc"
  auto_create_subnetworks = false
  project                 = var.project_id

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "main" {
  count         = var.create_vpc ? 1 : 0
  name          = "${var.cluster_name}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.main[0].id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }
}

locals {
  network    = var.create_vpc ? google_compute_network.main[0].name : var.network_name
  subnetwork = var.create_vpc ? google_compute_subnetwork.main[0].name : var.subnetwork_name
}

# GKE Cluster
resource "google_container_cluster" "main" {
  provider = google-beta

  name     = var.cluster_name
  location = var.region

  # Use Autopilot or Standard
  dynamic "cluster_autoscaling" {
    for_each = var.use_autopilot ? [] : [1]
    content {
      enabled = true
      resource_limits {
        resource_type = "cpu"
        minimum       = 1
        maximum       = 100
      }
      resource_limits {
        resource_type = "memory"
        minimum       = 1
        maximum       = 1000
      }
    }
  }

  # Remove default node pool for Standard clusters
  remove_default_node_pool = var.use_autopilot ? false : true
  initial_node_count       = var.use_autopilot ? null : 1

  enable_autopilot = var.use_autopilot

  network    = local.network
  subnetwork = local.subnetwork

  ip_allocation_policy {
    cluster_secondary_range_name  = var.create_vpc ? "pods" : var.pods_range_name
    services_secondary_range_name = var.create_vpc ? "services" : var.services_range_name
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  release_channel {
    channel = "REGULAR"
  }

  dynamic "monitoring_config" {
    for_each = var.enable_monitoring ? [1] : []
    content {
      enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
      managed_prometheus {
        enabled = true
      }
    }
  }

  dynamic "logging_config" {
    for_each = var.enable_monitoring ? [1] : []
    content {
      enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
    }
  }

  depends_on = [google_project_service.apis]
}

# Node Pool (for Standard clusters)
resource "google_container_node_pool" "main" {
  count      = var.use_autopilot ? 0 : 1
  name       = "${var.cluster_name}-pool"
  location   = var.region
  cluster    = google_container_cluster.main.name
  node_count = var.node_count

  autoscaling {
    min_node_count = var.node_min_count
    max_node_count = var.node_max_count
  }

  node_config {
    machine_type = var.node_machine_type
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}

# Artifact Registry
resource "google_artifact_registry_repository" "atb" {
  location      = var.region
  repository_id = "${var.cluster_name}-atb"
  format        = "DOCKER"
  description   = "ATB container images"

  depends_on = [google_project_service.apis]
}

# Service Account for ATB workloads
resource "google_service_account" "atb" {
  account_id   = "${var.cluster_name}-atb"
  display_name = "ATB Service Account"
}

# Workload Identity binding
resource "google_service_account_iam_member" "atb_workload_identity" {
  service_account_id = google_service_account.atb.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/atb-broker]"
}

# Secret Manager access
resource "google_project_iam_member" "atb_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.atb.email}"
}

# Secret Manager secret for ATB config
resource "google_secret_manager_secret" "atb" {
  secret_id = "${var.cluster_name}-atb-config"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

# Kubernetes provider
provider "helm" {
  kubernetes {
    host                   = "https://${google_container_cluster.main.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(google_container_cluster.main.master_auth[0].cluster_ca_certificate)
  }
}

provider "kubernetes" {
  host                   = "https://${google_container_cluster.main.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.main.master_auth[0].cluster_ca_certificate)
}

# Kubernetes namespace
resource "kubernetes_namespace" "atb" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "atb"
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }

  depends_on = [
    google_container_cluster.main,
    google_container_node_pool.main,
  ]
}

# Helm release for ATB
resource "helm_release" "atb" {
  name       = "atb"
  namespace  = kubernetes_namespace.atb.metadata[0].name
  chart      = "${path.module}/../../../charts/atb"

  values = [
    yamlencode({
      global = {
        trustDomain = var.trust_domain
        namespace   = var.namespace
      }
      broker = {
        replicas = var.broker_replicas
        serviceAccount = {
          annotations = {
            "iam.gke.io/gcp-service-account" = google_service_account.atb.email
          }
        }
      }
      agentauth = {
        replicas = var.agentauth_replicas
      }
      opa = {
        replicas = var.opa_replicas
      }
    })
  ]

  depends_on = [
    kubernetes_namespace.atb,
    google_service_account_iam_member.atb_workload_identity,
  ]
}
