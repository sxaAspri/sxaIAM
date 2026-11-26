# =============================================================================
# RUTA DE ATAQUE 13: AttachGroupPolicy escalation
#
# Técnica: el atacante es miembro de un grupo y tiene iam:AttachGroupPolicy
# sobre él. Adjunta AdministratorAccess directamente al grupo y, como miembro,
# la hereda inmediatamente.
#
# Cadena:
#   attach_group_policy_user (miembro de escalation_group)
#     → iam:AttachGroupPolicy on escalation_group
#     → adjunta arn:aws:iam::aws:policy/AdministratorAccess
#     → attach_group_policy_user hereda admin como miembro de escalation_group
#
# Lo que sxaiam debe detectar:
#   attach_group_policy_user es miembro de un grupo y tiene
#   iam:AttachGroupPolicy sobre él → puede adjuntar AdministratorAccess y escalar
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

# El atacante debe ser miembro del grupo: sin membresía, adjuntar
# AdministratorAccess a escalation_group no le da ningún permiso.
resource "aws_iam_user_group_membership" "attach_group_policy_user_membership" {
  user   = aws_iam_user.attach_group_policy_user.name
  groups = [aws_iam_group.escalation_group.name]
}
