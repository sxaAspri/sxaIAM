# =============================================================================
# RUTA DE ATAQUE 13: AttachGroupPolicy escalation
#
# Técnica: el atacante tiene iam:AttachGroupPolicy sobre un grupo.
# Adjunta AdministratorAccess directamente al grupo. Todos los miembros
# heredan acceso de administrador inmediatamente.
#
# Cadena:
#   attach_group_policy_user
#     → iam:AttachGroupPolicy on escalation_group
#     → adjunta arn:aws:iam::aws:policy/AdministratorAccess
#     → todos los miembros de escalation_group heredan admin
#
# Lo que sxaiam debe detectar:
#   attach_group_policy_user tiene iam:AttachGroupPolicy sobre un grupo
#   → puede adjuntar AdministratorAccess y escalar a admin
# =============================================================================

resource "aws_iam_group" "escalation_group" {
  name = "${var.name_prefix}-escalation-group"
  path = "/sxaiam-test/"
}

resource "aws_iam_policy" "attach_group_policy_permissions" {
  name        = "${var.name_prefix}-AttachGroupPolicyPermissions"
  description = "VULNERABLE: grants iam:AttachGroupPolicy — enables attaching AdministratorAccess to group"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CanAttachPolicyToGroup"
        Effect   = "Allow"
        Action   = ["iam:AttachGroupPolicy"]
        Resource = aws_iam_group.escalation_group.arn
      }
    ]
  })
}

resource "aws_iam_user" "attach_group_policy_user" {
  name = "${var.name_prefix}-attach-group-policy-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-13-attach-group-policy"
    Technique   = "AttachGroupPolicy escalation"
    Severity    = "CRITICAL"
    Description = "Can attach AdministratorAccess to group to escalate all members"
  }
}

resource "aws_iam_user_policy_attachment" "attach_group_policy_permissions" {
  user       = aws_iam_user.attach_group_policy_user.name
  policy_arn = aws_iam_policy.attach_group_policy_permissions.arn
}