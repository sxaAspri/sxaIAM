# =============================================================================
# RUTA DE ATAQUE 1: CreatePolicyVersion swap
#
# Técnica: el atacante tiene iam:CreatePolicyVersion sobre una política
# gestionada. Puede crear una nueva versión de esa política con Allow *:*
# y establecerla como la versión activa. Si la política está adjunta a un
# rol o recurso importante, el atacante hereda esos permisos.
#
# Cadena:
#   low_priv_user
#     → iam:CreatePolicyVersion on DeploymentPolicy
#     → crea versión {"Effect":"Allow","Action":"*","Resource":"*"}
#     → DeploymentPolicy ahora otorga admin
#     → low_priv_user hereda admin (DeploymentPolicy está adjunta a sí mismo)
#
# Lo que sxaiam debe detectar:
#   low_priv_user tiene iam:CreatePolicyVersion sobre una política
#   que está adjunta a su propia identidad → puede escalar a admin
# =============================================================================

# La política que el usuario puede modificar
resource "aws_iam_policy" "deployment_policy" {
  name        = "${var.name_prefix}-DeploymentPolicy"
  description = "VULNERABLE: policy that low_priv_user can replace via CreatePolicyVersion"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Permiso legítimo inicial — solo describe instancias EC2
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances"]
        Resource = "*"
      }
    ]
  })
}

# Política de permisos del usuario bajo privilegio
# Solo tiene CreatePolicyVersion — parece inofensivo
resource "aws_iam_policy" "low_priv_permissions" {
  name        = "${var.name_prefix}-LowPrivPermissions"
  description = "VULNERABLE: grants iam:CreatePolicyVersion — enables policy version swap attack"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # VECTOR DE ATAQUE: puede crear nuevas versiones de la política de deployment
        Sid      = "CanReplaceDeploymentPolicy"
        Effect   = "Allow"
        Action   = ["iam:CreatePolicyVersion"]
        Resource = aws_iam_policy.deployment_policy.arn
      },
      {
        # Necesita esto para poder activar la nueva versión como default
        Sid      = "CanSetDefaultVersion"
        Effect   = "Allow"
        Action   = ["iam:SetDefaultPolicyVersion"]
        Resource = aws_iam_policy.deployment_policy.arn
      }
    ]
  })
}

# El usuario víctima — parece un usuario de solo lectura
resource "aws_iam_user" "low_priv_user" {
  name = "${var.name_prefix}-low-priv-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-1-create-policy-version"
    Technique   = "CreatePolicyVersion swap"
    Severity    = "CRITICAL"
    Description = "Can replace DeploymentPolicy to grant self admin access"
  }
}

# Le adjuntamos sus propios permisos (los vulnerables)
resource "aws_iam_user_policy_attachment" "low_priv_permissions" {
  user       = aws_iam_user.low_priv_user.name
  policy_arn = aws_iam_policy.low_priv_permissions.arn
}

# También tiene la DeploymentPolicy adjunta — así cuando la reemplace, hereda admin
resource "aws_iam_user_policy_attachment" "low_priv_deployment" {
  user       = aws_iam_user.low_priv_user.name
  policy_arn = aws_iam_policy.deployment_policy.arn
}
