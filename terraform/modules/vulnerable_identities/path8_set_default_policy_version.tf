# =============================================================================
# RUTA DE ATAQUE 8: Privilege swap via SetDefaultPolicyVersion
#
# Cadena:
#   policy_manager_user
#     → iam:SetDefaultPolicyVersion on sxaiam-test-FlexPolicy
#     → puede activar versión no-default con Allow *:*
#     → policy_manager_user obtiene AdministratorAccess
# =============================================================================

resource "aws_iam_policy" "flex_policy" {
  name        = "${var.name_prefix}-FlexPolicy"
  description = "Policy with multiple versions — non-default has Allow *:*"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "LimitedAccess"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "policy_manager_permissions" {
  name        = "${var.name_prefix}-PolicyManagerPermissions"
  description = "VULNERABLE: includes iam:SetDefaultPolicyVersion on FlexPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CanListVersions"
        Effect = "Allow"
        Action = [
          "iam:ListPolicyVersions",
          "iam:GetPolicyVersion",
        ]
        Resource = aws_iam_policy.flex_policy.arn
      },
      {
        Sid    = "CanSetDefault"
        Effect = "Allow"
        Action = [
          "iam:SetDefaultPolicyVersion",
        ]
        Resource = aws_iam_policy.flex_policy.arn
      }
    ]
  })
}

resource "aws_iam_user" "policy_manager_user" {
  name = "${var.name_prefix}-policy-manager-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath = "path-8-set-default-policy-version"
    Technique  = "SetDefaultPolicyVersion on FlexPolicy"
    Severity   = "HIGH"
  }
}

resource "aws_iam_user_policy_attachment" "policy_manager_flex_policy" {
  user       = aws_iam_user.policy_manager_user.name
  policy_arn = aws_iam_policy.flex_policy.arn
}

resource "aws_iam_user_policy_attachment" "policy_manager_permissions" {
  user       = aws_iam_user.policy_manager_user.name
  policy_arn = aws_iam_policy.policy_manager_permissions.arn
}