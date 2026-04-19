# =============================================================================
# RUTA DE ATAQUE 4: AttachUserPolicy directo
#
# Técnica: el atacante tiene iam:AttachUserPolicy sobre su propio usuario
# o sobre cualquier usuario. Puede adjuntarse directamente la política
# AdministratorAccess de AWS sin necesidad de pasar por ningún rol.
#
# Cadena:
#   readonly_user
#     → iam:AttachUserPolicy on self     (puede adjuntarse cualquier política)
#     → adjunta arn:aws:iam::aws:policy/AdministratorAccess
#     → readonly_user ahora tiene acceso total
#
# Lo que sxaiam debe detectar:
#   readonly_user tiene iam:AttachUserPolicy sin restricción de Resource
#   → puede adjuntarse AdministratorAccess directamente
# =============================================================================

resource "aws_iam_policy" "readonly_permissions" {
  name        = "${var.name_prefix}-ReadonlyPermissions"
  description = "VULNERABLE: includes iam:AttachUserPolicy — enables self-escalation to admin"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Permisos legítimos — parece un usuario de solo lectura
        Sid    = "ReadOnlyAccess"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "s3:List*",
          "s3:Get*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
        ]
        Resource = "*"
      },
      {
        # VECTOR DE ATAQUE: puede adjuntar cualquier política a cualquier usuario
        # Resource "*" significa que incluye a sí mismo
        Sid      = "CanAttachAnyPolicy"
        Effect   = "Allow"
        Action   = ["iam:AttachUserPolicy"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "readonly_user" {
  name = "${var.name_prefix}-readonly-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-4-attach-policy"
    Technique   = "AttachUserPolicy self-escalation"
    Severity    = "CRITICAL"
    Description = "Can attach AdministratorAccess directly to self via iam:AttachUserPolicy"
  }
}

resource "aws_iam_user_policy_attachment" "readonly_permissions" {
  user       = aws_iam_user.readonly_user.name
  policy_arn = aws_iam_policy.readonly_permissions.arn
}
