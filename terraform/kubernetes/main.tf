terraform {
  required_version = ">= 1.0.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.10.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Namespace
# -----------------------------------------------------------------------------

resource "kubernetes_namespace" "atb" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace

    labels = merge({
      "app.kubernetes.io/name"       = "atb"
      "app.kubernetes.io/managed-by" = "terraform"
    }, var.labels)
  }
}

# -----------------------------------------------------------------------------
# ATB Helm Release
# -----------------------------------------------------------------------------

resource "helm_release" "atb" {
  name       = var.release_name
  namespace  = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace
  repository = var.helm_repository
  chart      = var.helm_chart
  version    = var.helm_chart_version

  values = [
    yamlencode({
      global = {
        trustDomain = var.trust_domain
      }

      broker = {
        replicaCount = var.broker_config.replicas
        image = {
          repository = split(":", var.broker_config.image)[0]
          tag        = length(split(":", var.broker_config.image)) > 1 ? split(":", var.broker_config.image)[1] : "latest"
        }
        resources = var.broker_config.resources
      }

      agentauth = {
        replicaCount = var.agentauth_config.replicas
        image = {
          repository = split(":", var.agentauth_config.image)[0]
          tag        = length(split(":", var.agentauth_config.image)) > 1 ? split(":", var.agentauth_config.image)[1] : "latest"
        }
        resources = var.agentauth_config.resources
      }

      opa = {
        replicaCount = var.opa_config.replicas
        resources    = var.opa_config.resources
      }

      connectors = var.connectors

      spire = {
        enabled = var.enable_spire
      }

      monitoring = {
        enabled = var.enable_monitoring
        serviceMonitor = {
          enabled = var.enable_monitoring
        }
      }

      networkPolicy = {
        enabled = var.enable_network_policies
      }
    }),
    yamlencode(var.helm_values)
  ]

  wait    = var.wait_for_ready
  timeout = var.helm_timeout

  depends_on = [kubernetes_namespace.atb]
}

# -----------------------------------------------------------------------------
# Connector ConfigMap (if not using Helm)
# -----------------------------------------------------------------------------

resource "kubernetes_config_map" "connectors" {
  count = length(var.connectors) > 0 ? 1 : 0

  metadata {
    name      = "atb-connectors"
    namespace = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace

    labels = {
      "app.kubernetes.io/name"      = "atb"
      "app.kubernetes.io/component" = "broker"
    }
  }

  data = {
    "connectors.json" = jsonencode({
      connectors = [
        for name, config in var.connectors : merge({
          name = name
        }, config)
      ]
    })
  }
}

# -----------------------------------------------------------------------------
# SPIRE Agent DaemonSet (if enabled and not using Helm)
# -----------------------------------------------------------------------------

resource "kubernetes_daemonset" "spire_agent" {
  count = var.enable_spire && var.deploy_spire_separately ? 1 : 0

  metadata {
    name      = "spire-agent"
    namespace = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace

    labels = {
      "app.kubernetes.io/name"      = "spire-agent"
      "app.kubernetes.io/component" = "agent"
    }
  }

  spec {
    selector {
      match_labels = {
        "app.kubernetes.io/name" = "spire-agent"
      }
    }

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name" = "spire-agent"
        }
      }

      spec {
        host_pid     = true
        host_network = true

        service_account_name = "spire-agent"

        container {
          name  = "spire-agent"
          image = var.spire_agent_image

          args = ["-config", "/run/spire/config/agent.conf"]

          volume_mount {
            name       = "spire-config"
            mount_path = "/run/spire/config"
            read_only  = true
          }

          volume_mount {
            name       = "spire-agent-socket"
            mount_path = "/run/spire/sockets"
          }

          volume_mount {
            name       = "spire-token"
            mount_path = "/var/run/secrets/tokens"
          }

          resources {
            requests = {
              cpu    = "50m"
              memory = "64Mi"
            }
            limits = {
              cpu    = "200m"
              memory = "128Mi"
            }
          }
        }

        volume {
          name = "spire-config"
          config_map {
            name = "spire-agent"
          }
        }

        volume {
          name = "spire-agent-socket"
          host_path {
            path = "/run/spire/sockets"
            type = "DirectoryOrCreate"
          }
        }

        volume {
          name = "spire-token"
          projected {
            sources {
              service_account_token {
                path               = "spire-agent"
                expiration_seconds = 7200
                audience           = "spire-server"
              }
            }
          }
        }
      }
    }
  }
}

# -----------------------------------------------------------------------------
# Network Policies
# -----------------------------------------------------------------------------

resource "kubernetes_network_policy" "atb_default_deny" {
  count = var.enable_network_policies ? 1 : 0

  metadata {
    name      = "atb-default-deny"
    namespace = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace
  }

  spec {
    pod_selector {}

    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy" "atb_broker" {
  count = var.enable_network_policies ? 1 : 0

  metadata {
    name      = "atb-broker"
    namespace = var.create_namespace ? kubernetes_namespace.atb[0].metadata[0].name : var.namespace
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name"      = "atb"
        "app.kubernetes.io/component" = "broker"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = var.ingress_namespace_labels
        }
      }

      ports {
        protocol = "TCP"
        port     = 8080
      }
    }

    egress {
      # Allow to OPA
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name"      = "atb"
            "app.kubernetes.io/component" = "opa"
          }
        }
      }

      ports {
        protocol = "TCP"
        port     = 8181
      }
    }

    egress {
      # Allow DNS
      to {
        namespace_selector {}
      }

      ports {
        protocol = "UDP"
        port     = 53
      }
    }

    egress {
      # Allow to connectors (external)
      to {
        ip_block {
          cidr = "0.0.0.0/0"
          except = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16"
          ]
        }
      }
    }
  }
}
