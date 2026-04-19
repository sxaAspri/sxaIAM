output "user_arns" {
  description = "ARNs of all test users"
  value = {
    low_priv_user   = aws_iam_user.low_priv_user.arn
    developer_user  = aws_iam_user.developer_user.arn
    readonly_user   = aws_iam_user.readonly_user.arn
    support_user    = aws_iam_user.support_user.arn
    privileged_user = aws_iam_user.privileged_user.arn
  }
}

output "role_arns" {
  description = "ARNs of all test roles"
  value = {
    admin_role = aws_iam_role.admin_role.arn
    ci_role    = aws_iam_role.ci_role.arn
  }
}

output "policy_arns" {
  description = "ARNs of all test policies"
  value = {
    deployment_policy    = aws_iam_policy.deployment_policy.arn
    low_priv_permissions = aws_iam_policy.low_priv_permissions.arn
    developer_perms      = aws_iam_policy.developer_permissions.arn
    ci_permissions       = aws_iam_policy.ci_permissions.arn
    readonly_perms       = aws_iam_policy.readonly_permissions.arn
    support_perms        = aws_iam_policy.support_permissions.arn
  }
}
