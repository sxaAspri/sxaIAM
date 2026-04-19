# =============================================================================
# RUTA DE ATAQUE 2: PassRole + Lambda
#
# Técnica: el atacante tiene iam:PassRole sobre un rol privilegiado
# Y tiene lambda:CreateFunction + lambda:InvokeFunction.
# Puede crear una función Lambda que corre CON el rol privilegiado,
# y dentro de esa función ejecutar cualquier acción con esos permisos.
#
# Cadena:
#   developer_user
#     → iam:PassRole on admin_role         (puede asignar admin_role a Lambda)
#     → lambda:CreateFunction              (crea una función que asume admin_role)
#     → lambda:InvokeFunction              (ejecuta código arbitrario como admin)
#
# Lo que sxaiam debe detectar:
#   developer_user tiene PassRole + lambda:CreateFunction sobre un rol
#   cuyo trust policy permite lambda.amazonaws.com → puede ejecutar como admin
# =============================================================================

# El rol admin — el objetivo de la escalación
# También es el destino de las rutas 2 y 3
resource "aws_iam_role" "admin_role" {
  name        = "${var.name_prefix}-admin-role"
  description = "TARGET: high-privilege role — destination node for attack paths 2 and 3"

  # Trust policy: permite ser asumido por Lambda Y por otros roles (para path 3)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Permite que Lambda asuma este rol (necesario para el ataque PassRole+Lambda)
        Sid    = "AllowLambdaAssume"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
      {
        # Permite que ci_role asuma este rol (para el ataque AssumeRole chain, path 3)
        Sid    = "AllowCIRoleAssume"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ci_role.arn
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    AttackPath  = "path-2-passrole-lambda, path-3-assumerole-chain"
    Role        = "target-admin-node"
    Severity    = "CRITICAL"
    Description = "High-privilege role — destination of multiple attack paths"
  }
}

# Le damos AdministratorAccess — es el nodo de alto privilegio
resource "aws_iam_role_policy_attachment" "admin_role_full_access" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Permisos del developer_user — parecen razonables para un CI/CD developer
resource "aws_iam_policy" "developer_permissions" {
  name        = "${var.name_prefix}-DeveloperPermissions"
  description = "VULNERABLE: PassRole + Lambda combo enables code execution as admin_role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # VECTOR DE ATAQUE: puede pasar admin_role a una función Lambda
        Sid      = "CanPassAdminRole"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = aws_iam_role.admin_role.arn
      },
      {
        # Puede crear y gestionar funciones Lambda
        Sid    = "CanManageLambda"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:InvokeFunction",
          "lambda:GetFunction",
          "lambda:ListFunctions",
        ]
        Resource = "*"
      },
      {
        # Permisos legítimos — parece un developer normal
        Sid    = "LegitimateDevPermissions"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "logs:DescribeLogGroups",
          "logs:GetLogEvents",
        ]
        Resource = "*"
      }
    ]
  })
}

# El usuario developer — parece un developer de CI/CD legítimo
resource "aws_iam_user" "developer_user" {
  name = "${var.name_prefix}-developer-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-2-passrole-lambda"
    Technique   = "PassRole + Lambda execution"
    Severity    = "HIGH"
    Description = "Can create Lambda with admin_role and execute arbitrary code as admin"
  }
}

resource "aws_iam_user_policy_attachment" "developer_permissions" {
  user       = aws_iam_user.developer_user.name
  policy_arn = aws_iam_policy.developer_permissions.arn
}
