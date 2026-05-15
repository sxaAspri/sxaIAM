# =============================================================================
# RUTA DE ATAQUE 11: PutRolePolicy inline escalation
#
# Técnica: el atacante tiene iam:PutRolePolicy y sts:AssumeRole sobre
# un rol asumible. Inyecta una inline policy con Allow *:* en ese rol
# y luego lo asume para heredar acceso de administrador.
#
# Cadena:
#   put_role_policy_user
#     → iam:PutRolePolicy on assumable_role
#     → crea inline policy {"Effect":"Allow","Action":"*","Resource":"*"}
#     → sts:AssumeRole on assumable_role
#     → hereda admin via rol comprometido
#
# Lo que sxaiam debe detectar:
#   put_role_policy_user tiene iam:PutRolePolicy + sts:AssumeRole
#   sobre un rol asumible → puede escalar a admin
# =============================================================================

resource "aws_iam_role" "assumable_role" {
  name        = "${var.name_prefix}-assumable-role"
  description = "VULNERABLE: role that can be injected with inline policy via PutRolePolicy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = aws_iam_user.put_role_policy_user.arn }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    AttackPath = "path-11-put-role-policy"
    Role       = "target-assumable-role"
  }
}

resource "aws_iam_policy" "put_role_policy_permissions" {
  name        = "${var.name_prefix}-PutRolePolicyPermissions"
  description = "VULNERABLE: grants iam:PutRolePolicy + sts:AssumeRole — enables role inline injection"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CanInjectRoleInlinePolicy"
        Effect   = "Allow"
        Action   = ["iam:PutRolePolicy"]
        Resource = aws_iam_role.assumable_role.arn
      },
      {
        Sid      = "CanAssumeRole"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = aws_iam_role.assumable_role.arn
      }
    ]
  })
}

resource "aws_iam_user" "put_role_policy_user" {
  name = "${var.name_prefix}-put-role-policy-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-11-put-role-policy"
    Technique   = "PutRolePolicy inline escalation"
    Severity    = "CRITICAL"
    Description = "Can inject inline policy into assumable role then assume it"
  }
}

resource "aws_iam_user_policy_attachment" "put_role_policy_permissions" {
  user       = aws_iam_user.put_role_policy_user.name
  policy_arn = aws_iam_policy.put_role_policy_permissions.arn
}