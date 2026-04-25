# =============================================================================
# RUTA DE ATAQUE 9: Self-escalation via AddUserToGroup
#
# Cadena:
#   contractor_user
#     → iam:AddUserToGroup on admin_group
#     → se agrega al admin_group
#     → hereda AdministratorAccess del grupo
# =============================================================================

resource "aws_iam_group" "admin_group" {
  name = "${var.name_prefix}-admin-group"
  path = "/sxaiam-test/"
}

resource "aws_iam_group_policy_attachment" "admin_group_admin_access" {
  group      = aws_iam_group.admin_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_policy" "contractor_permissions" {
  name        = "${var.name_prefix}-ContractorPermissions"
  description = "VULNERABLE: includes iam:AddUserToGroup on admin_group"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LegitimateContractor"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "ec2:DescribeInstances",
        ]
        Resource = "*"
      },
      {
        Sid    = "CanAddToAdminGroup"
        Effect = "Allow"
        Action = [
          "iam:AddUserToGroup",
        ]
        Resource = aws_iam_group.admin_group.arn
      }
    ]
  })
}

resource "aws_iam_user" "contractor_user" {
  name = "${var.name_prefix}-contractor-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath = "path-9-add-user-to-group"
    Technique  = "AddUserToGroup on admin_group"
    Severity   = "HIGH"
  }
}

resource "aws_iam_user_policy_attachment" "contractor_permissions" {
  user       = aws_iam_user.contractor_user.name
  policy_arn = aws_iam_policy.contractor_permissions.arn
}