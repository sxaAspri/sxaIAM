# =============================================================================
# RUTA DE ATAQUE 12: PutGroupPolicy inline escalation
#
# Técnica: el atacante tiene iam:PutGroupPolicy sobre un grupo con miembros.
# Inyecta una inline policy con Allow *:* en ese grupo. Todos los miembros
# heredan acceso de administrador inmediatamente.
#
# Cadena:
#   put_group_policy_user
#     → iam:PutGroupPolicy on target_group
#     → crea inline policy {"Effect":"Allow","Action":"*","Resource":"*"}
#     → todos los miembros de target_group heredan admin
#
# Lo que sxaiam debe detectar:
#   put_group_policy_user tiene iam:PutGroupPolicy sobre un grupo
#   con políticas adjuntas → puede escalar a admin
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