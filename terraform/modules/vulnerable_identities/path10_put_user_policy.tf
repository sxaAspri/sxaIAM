# =============================================================================
# RUTA DE ATAQUE 10: PutUserPolicy inline escalation
#
# Técnica: el atacante tiene iam:PutUserPolicy sobre sí mismo.
# Puede crear una inline policy con Allow *:* directamente en su usuario,
# heredando acceso de administrador en una sola llamada a la API.
#
# Cadena:
#   put_user_policy_user
#     → iam:PutUserPolicy on self
#     → crea inline policy {"Effect":"Allow","Action":"*","Resource":"*"}
#     → put_user_policy_user ahora tiene acceso de administrador
#
# Lo que sxaiam debe detectar:
#   put_user_policy_user tiene iam:PutUserPolicy sobre su propio ARN
#   → puede escalar a admin en una llamada
# =============================================================================

resource "aws_iam_policy" "put_user_policy_permissions" {
  name        = "${var.name_prefix}-PutUserPolicyPermissions"
  description = "VULNERABLE: grants iam:PutUserPolicy on self — enables inline policy injection"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CanInjectInlinePolicy"
        Effect   = "Allow"
        Action   = ["iam:PutUserPolicy"]
        Resource = "arn:aws:iam::${var.account_id}:user/sxaiam-test/${var.name_prefix}-put-user-policy-user"
      }
    ]
  })
}

resource "aws_iam_user" "put_user_policy_user" {
  name = "${var.name_prefix}-put-user-policy-user"
  path = "/sxaiam-test/"

  tags = {
    AttackPath  = "path-10-put-user-policy"
    Technique   = "PutUserPolicy inline escalation"
    Severity    = "CRITICAL"
    Description = "Can inject inline policy on self to grant admin access"
  }
}

resource "aws_iam_user_policy_attachment" "put_user_policy_permissions" {
  user       = aws_iam_user.put_user_policy_user.name
  policy_arn = aws_iam_policy.put_user_policy_permissions.arn
}