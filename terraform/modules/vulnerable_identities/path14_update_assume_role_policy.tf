# =============================================================================
# RUTA DE ATAQUE 14: UpdateAssumeRolePolicy trust hijack
#
# Técnica: el atacante tiene iam:UpdateAssumeRolePolicy y sts:AssumeRole
# sobre un rol privilegiado. Modifica la trust policy para incluirse
# como principal autorizado y luego asume el rol.
#
# Cadena:
#   update_assume_role_user
#     → iam:UpdateAssumeRolePolicy on privileged_role
#     → agrega su propio ARN como trusted principal
#     → sts:AssumeRole on privileged_role
#     → hereda todos los permisos del rol privilegiado
#
# Lo que sxaiam debe detectar:
#   update_assume_role_user tiene iam:UpdateAssumeRolePolicy + sts:AssumeRole
#   sobre un rol con permisos significativos → puede escalar a admin
# =============================================================================

resource "aws_iam_role" "privileged_role" {
  name        = "${var.name_prefix}-privileged-role"
  description = "VULNERABLE: trust policy can be hijacked via UpdateAssumeRolePolicy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    AttackPath = "path-14-update-assume-role-policy"
    Role       = "target-privileged-role"
  }
}

resource "aws_iam_role_policy_attachment" "privileged_role_admin" {
  role       = aws_iam_role.privileged_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_policy" "update_assume_role_permissions" {
  name        = "${var.name_prefix}-UpdateAssumeRolePermissions"
  description = "VULNERABLE: grants iam:UpdateAssumeRolePolicy + sts:AssumeRole — enables trust policy hijack"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CanHijackTrustPolicy"
        Effect   = "Allow"
        Action   = ["iam:UpdateAssumeRolePolicy"]
        Resource = aws_iam_role.privileged_role.arn
      },
      {
        Sid      = "CanAssumePrivilegedRole"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = aws_iam_role.privileged_role.arn
      }
    ]
  })
}

resource "aws_iam_user" "update_assume_role_user" {
  name = "${var.name_prefix}-update-assume-role-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-14-update-assume-role-policy"
    Technique   = "UpdateAssumeRolePolicy trust hijack"
    Severity    = "HIGH"
    Description = "Can modify role trust policy to assume privileged role"
  }
}

resource "aws_iam_user_policy_attachment" "update_assume_role_permissions" {
  user       = aws_iam_user.update_assume_role_user.name
  policy_arn = aws_iam_policy.update_assume_role_permissions.arn
}