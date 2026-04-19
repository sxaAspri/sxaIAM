# =============================================================================
# RUTA DE ATAQUE 3: AssumeRole chaining
#
# Técnica: ci_role tiene sts:AssumeRole sobre admin_role.
# El trust policy de admin_role permite que ci_role lo asuma.
# Un atacante que comprometa ci_role puede pivotar directamente a admin.
#
# Cadena:
#   ci_role (comprometido)
#     → sts:AssumeRole on admin_role   (trust policy lo permite)
#     → admin_role tiene AdministratorAccess
#
# Lo que sxaiam debe detectar:
#   ci_role → sts:AssumeRole → admin_role → AdministratorAccess
#   El trust policy de admin_role es el edge en el grafo
# =============================================================================

# ci_role — simula un rol de CI/CD (GitHub Actions, Jenkins, etc.)
# Su trust policy permite ser asumido por EC2 (simula un runner de CI)
resource "aws_iam_role" "ci_role" {
  name        = "${var.name_prefix}-ci-role"
  description = "VULNERABLE: has sts:AssumeRole on admin_role — enables role chaining to admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Simula que este rol es asumido por una instancia EC2 (runner de CI)
        Sid    = "AllowEC2Assume"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    AttackPath  = "path-3-assumerole-chain"
    Technique   = "AssumeRole chaining"
    Severity    = "HIGH"
    Description = "CI/CD role that can pivot to admin_role via sts:AssumeRole"
  }
}

# Permisos del ci_role — incluye sts:AssumeRole sobre admin_role
resource "aws_iam_policy" "ci_permissions" {
  name        = "${var.name_prefix}-CIPermissions"
  description = "VULNERABLE: includes sts:AssumeRole on admin_role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # VECTOR DE ATAQUE: puede asumir admin_role directamente
        Sid      = "CanAssumeAdminRole"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = aws_iam_role.admin_role.arn
      },
      {
        # Permisos legítimos de CI — parece un rol de deployment normal
        Sid    = "LegitimateCI"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "ecr:GetAuthorizationToken",
          "ecr:BatchGetImage",
          "logs:CreateLogGroup",
          "logs:PutLogEvents",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ci_permissions" {
  role       = aws_iam_role.ci_role.name
  policy_arn = aws_iam_policy.ci_permissions.arn
}
