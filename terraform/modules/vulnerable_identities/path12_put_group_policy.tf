# =============================================================================
# RUTA DE ATAQUE 12: PutGroupPolicy inline escalation
#
# Técnica: el atacante es miembro de un grupo y tiene iam:PutGroupPolicy sobre
# él. Inyecta una inline policy con Allow *:* en ese grupo y, como miembro,
# hereda acceso de administrador inmediatamente.
#
# Cadena:
#   put_group_policy_user (miembro de target_group)
#     → iam:PutGroupPolicy on target_group
#     → crea inline policy {"Effect":"Allow","Action":"*","Resource":"*"}
#     → put_group_policy_user hereda admin como miembro de target_group
#
# Lo que sxaiam debe detectar:
#   put_group_policy_user es miembro de un grupo y tiene iam:PutGroupPolicy
#   sobre él → puede escalar a admin. El grupo no necesita políticas previas.
# =============================================================================

resource "aws_iam_group" "target_group" {
  name = "${var.name_prefix}-target-group"
  path = "/sxaiam-test/"
}

resource "aws_iam_group_policy_attachment" "target_group_readonly" {
  group      = aws_iam_group.target_group.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_policy" "put_group_policy_permissions" {
  name        = "${var.name_prefix}-PutGroupPolicyPermissions"
  description = "VULNERABLE: grants iam:PutGroupPolicy — enables group inline policy injection"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CanInjectGroupInlinePolicy"
        Effect   = "Allow"
        Action   = ["iam:PutGroupPolicy"]
        Resource = aws_iam_group.target_group.arn
      }
    ]
  })
}

resource "aws_iam_user" "put_group_policy_user" {
  name = "${var.name_prefix}-put-group-policy-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-12-put-group-policy"
    Technique   = "PutGroupPolicy inline escalation"
    Severity    = "CRITICAL"
    Description = "Can inject inline policy into group to escalate all members"
  }
}

resource "aws_iam_user_policy_attachment" "put_group_policy_permissions" {
  user       = aws_iam_user.put_group_policy_user.name
  policy_arn = aws_iam_policy.put_group_policy_permissions.arn
}

# El atacante debe ser miembro del grupo: sin membresía, inyectar una
# política en target_group no le da ningún permiso.
resource "aws_iam_user_group_membership" "put_group_policy_user_membership" {
  user   = aws_iam_user.put_group_policy_user.name
  groups = [aws_iam_group.target_group.name]
}
