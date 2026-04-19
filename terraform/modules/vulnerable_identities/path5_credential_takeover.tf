# =============================================================================
# RUTA DE ATAQUE 5: Credential takeover via CreateAccessKey
#
# Técnica: el atacante tiene iam:CreateAccessKey sobre otro usuario
# que tiene más privilegios. Crea una access key para ese usuario
# y la usa para autenticarse como él.
#
# Cadena:
#   support_user
#     → iam:CreateAccessKey on privileged_user
#     → genera credenciales de privileged_user
#     → se autentica como privileged_user (que tiene PowerUserAccess)
#
# Lo que sxaiam debe detectar:
#   support_user tiene iam:CreateAccessKey sobre privileged_user
#   privileged_user tiene PowerUserAccess → credential takeover da acceso elevado
# =============================================================================

# El usuario privilegiado — el objetivo del credential takeover
resource "aws_iam_user" "privileged_user" {
  name = "${var.name_prefix}-privileged-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-5-credential-takeover"
    Role        = "target-privileged-user"
    Description = "High-privilege user whose credentials can be stolen via CreateAccessKey"
  }
}

# El usuario privilegiado tiene PowerUserAccess — casi todo menos IAM
resource "aws_iam_user_policy_attachment" "privileged_user_power_access" {
  user       = aws_iam_user.privileged_user.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# Política del support_user — parece un usuario de soporte legítimo
resource "aws_iam_policy" "support_permissions" {
  name        = "${var.name_prefix}-SupportPermissions"
  description = "VULNERABLE: includes iam:CreateAccessKey on privileged_user — enables credential takeover"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Permisos legítimos de soporte
        Sid    = "SupportReadAccess"
        Effect = "Allow"
        Action = [
          "support:*",
          "health:Describe*",
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
        ]
        Resource = "*"
      },
      {
        # VECTOR DE ATAQUE: puede crear access keys para privileged_user
        Sid    = "CanCreateAccessKeyForPrivilegedUser"
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:ListAccessKeys",
        ]
        Resource = aws_iam_user.privileged_user.arn
      }
    ]
  })
}

resource "aws_iam_user" "support_user" {
  name = "${var.name_prefix}-support-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-5-credential-takeover"
    Technique   = "CreateAccessKey on privileged user"
    Severity    = "HIGH"
    Description = "Can generate credentials for privileged_user and act as them"
  }
}

resource "aws_iam_user_policy_attachment" "support_permissions" {
  user       = aws_iam_user.support_user.name
  policy_arn = aws_iam_policy.support_permissions.arn
}
