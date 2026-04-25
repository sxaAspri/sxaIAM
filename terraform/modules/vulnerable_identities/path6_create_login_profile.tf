# =============================================================================
# RUTA DE ATAQUE 6: Console takeover via CreateLoginProfile
#
# Técnica: el atacante tiene iam:CreateLoginProfile sobre un usuario
# privilegiado que no tiene contraseña de consola. Crea una contraseña
# y se autentica como ese usuario en la consola AWS.
#
# Cadena:
#   helpdesk_user
#     → iam:CreateLoginProfile on admin_console_user
#     → crea contraseña de consola para admin_console_user
#     → se autentica como admin_console_user (que tiene PowerUserAccess)
# =============================================================================

resource "aws_iam_user" "admin_console_user" {
  name = "${var.name_prefix}-admin-console-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-6-create-login-profile"
    Role        = "target-admin-console-user"
  }
}

resource "aws_iam_user_policy_attachment" "admin_console_user_power" {
  user       = aws_iam_user.admin_console_user.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_policy" "helpdesk_permissions" {
  name        = "${var.name_prefix}-HelpdeskPermissions"
  description = "VULNERABLE: includes iam:CreateLoginProfile on admin_console_user"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "HelpdeskReadAccess"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:GetUser",
        ]
        Resource = "*"
      },
      {
        Sid    = "CanCreateLoginProfile"
        Effect = "Allow"
        Action = [
          "iam:CreateLoginProfile",
        ]
        Resource = aws_iam_user.admin_console_user.arn
      }
    ]
  })
}

resource "aws_iam_user" "helpdesk_user" {
  name = "${var.name_prefix}-helpdesk-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath = "path-6-create-login-profile"
    Technique  = "CreateLoginProfile on admin console user"
    Severity   = "HIGH"
  }
}

resource "aws_iam_user_policy_attachment" "helpdesk_permissions" {
  user       = aws_iam_user.helpdesk_user.name
  policy_arn = aws_iam_policy.helpdesk_permissions.arn
}