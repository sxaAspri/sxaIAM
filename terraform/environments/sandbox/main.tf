# =============================================================================
# sxaiam — Fase 1: Entorno de prueba sandbox
#
# Este entorno crea identidades IAM deliberadamente vulnerables en AWS.
# Cada recurso documenta exactamente qué técnica de escalación representa
# y qué ruta de ataque debería detectar sxaiam.
#
# USO:
#   terraform init
#   terraform apply        # levanta el entorno
#   terraform destroy      # lo limpia completamente
#
# COSTO: todos los recursos IAM son gratuitos en AWS.
# RIESGO: usar SOLO en una cuenta sandbox aislada, nunca en producción.
# =============================================================================

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project     = "sxaiam"
      Environment = "sandbox"
      ManagedBy   = "terraform"
      Purpose     = "attack-path-testing"
    }
  }
}

# Llama al módulo que contiene todas las identidades vulnerables
module "vulnerable_identities" {
  source = "../../modules/vulnerable_identities"

  account_id  = data.aws_caller_identity.current.account_id
  name_prefix = var.name_prefix
}

# Datos de la cuenta actual
data "aws_caller_identity" "current" {}
