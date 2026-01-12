terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.10.0"
    }
  }

  backend "s3" {
    # Configure your backend
    # bucket         = "tfstate-bucket"
    # key            = "atb/terraform.tfstate"
    # region         = "eu-west-1"
    # dynamodb_table = "tfstate-lock"
    # encrypt        = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -----------------------------------------------------------------------------
# ATB AWS Module
# -----------------------------------------------------------------------------

module "atb_aws" {
  source = "../../aws"

  cluster_name = var.cluster_name
  vpc_id       = var.vpc_id
  subnet_ids   = var.subnet_ids
  trust_domain = var.trust_domain

  # Cluster configuration
  cluster_version = var.cluster_version

  # Node groups
  node_groups = {
    system = {
      instance_types = ["m6i.xlarge"]
      desired_size   = 3
      min_size       = 3
      max_size       = 10
      labels = {
        role = "system"
      }
    }
    atb = {
      instance_types = ["m6i.xlarge"]
      desired_size   = 2
      min_size       = 2
      max_size       = 6
      labels = {
        workload = "atb"
      }
      taints = [{
        key    = "workload"
        value  = "atb"
        effect = "NO_SCHEDULE"
      }]
    }
  }

  # Security
  enable_irsa = true
  kms_key_arn = var.kms_key_arn

  # Logging
  enable_cloudwatch_logs = true
  log_retention_days     = 30

  tags = var.tags
}

# -----------------------------------------------------------------------------
# ATB Kubernetes Module
# -----------------------------------------------------------------------------

provider "kubernetes" {
  host                   = module.atb_aws.cluster_endpoint
  cluster_ca_certificate = base64decode(module.atb_aws.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.atb_aws.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.atb_aws.cluster_endpoint
    cluster_ca_certificate = base64decode(module.atb_aws.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.atb_aws.cluster_name]
    }
  }
}

module "atb_kubernetes" {
  source = "../../kubernetes"

  namespace    = "atb"
  trust_domain = var.trust_domain

  broker_config = {
    replicas = 3
    image    = var.broker_image
    resources = {
      requests = {
        cpu    = "200m"
        memory = "512Mi"
      }
      limits = {
        cpu    = "1000m"
        memory = "1Gi"
      }
    }
  }

  agentauth_config = {
    replicas = 2
    image    = var.agentauth_image
  }

  connectors = var.connectors

  enable_spire            = true
  enable_monitoring       = true
  enable_network_policies = true

  helm_values = {
    serviceAccount = {
      annotations = {
        "eks.amazonaws.com/role-arn" = module.atb_aws.atb_role_arn
      }
    }
    tolerations = [{
      key      = "workload"
      operator = "Equal"
      value    = "atb"
      effect   = "NoSchedule"
    }]
    nodeSelector = {
      workload = "atb"
    }
  }

  depends_on = [module.atb_aws]
}

# -----------------------------------------------------------------------------
# Secrets Manager for ATB Secrets
# -----------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "atb" {
  name        = "${var.cluster_name}/atb/config"
  description = "ATB configuration secrets"
  kms_key_id  = var.kms_key_arn

  tags = {
    Name = "${var.cluster_name}-atb-secrets"
  }
}

resource "aws_secretsmanager_secret_version" "atb" {
  secret_id = aws_secretsmanager_secret.atb.id
  secret_string = jsonencode({
    # Add your secrets here
    # These would typically come from variables marked sensitive
  })
}

# Grant ATB IRSA role access to secrets
resource "aws_iam_role_policy" "atb_secrets" {
  name = "${var.cluster_name}-atb-secrets"
  role = module.atb_aws.atb_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.atb.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })
}
