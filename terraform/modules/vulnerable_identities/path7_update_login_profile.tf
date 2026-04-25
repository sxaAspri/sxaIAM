# =============================================================================
# RUTA DE ATAQUE 7: Password reset via UpdateLoginProfile
#
# Cadena:
#   password_reset_user
#     → iam:UpdateLoginProfile on finance_user
#     → resetea contraseña de consola de finance_user
#     → se autentica como finance_user (que tiene ReadOnlyAccess)
# =============================================================================

resource "aws_iam_user" "finance_user" {
  name = "${var.name_prefix}-finance-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath = "path-7-update-login-profile"
    Role       = "target-finance-user"
  }
}

resource "aws_iam_user_policy_attachment" "finance_user_readonly" {
  user       = aws_iam_user.finance_user.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_policy" "password_reset_permissions" {
  name        = "${var.name_prefix}-PasswordResetPermissions"
  description = "VULNERABLE: includes iam:UpdateLoginProfile on finance_user"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LegitimateHelpdesk"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:GetLoginProfile",
        ]
        Resource = "*"
      },
      {
        Sid    = "CanResetPassword"
        Effect = "Allow"
        Action = [
          "iam:UpdateLoginProfile",
        ]
        Resource = aws_iam_user.finance_user.arn
      }
    ]
  })
}

resource "aws_iam_user" "password_reset_user" {
  name = "${var.name_prefix}-password-reset-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath = "path-7-update-login-profile"
    Technique  = "UpdateLoginProfile on finance user"
    Severity   = "HIGH"
  }
}

resource "aws_iam_user_policy_attachment" "password_reset_permissions" {
  user       = aws_iam_user.password_reset_user.name
  policy_arn = aws_iam_policy.password_reset_permissions.arn
}