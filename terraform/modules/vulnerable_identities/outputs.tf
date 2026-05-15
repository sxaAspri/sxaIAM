output "user_arns" {
  description = "ARNs of all test users"
  value = {
    low_priv_user             = aws_iam_user.low_priv_user.arn
    developer_user            = aws_iam_user.developer_user.arn
    readonly_user             = aws_iam_user.readonly_user.arn
    support_user              = aws_iam_user.support_user.arn
    privileged_user           = aws_iam_user.privileged_user.arn
    helpdesk_user             = aws_iam_user.helpdesk_user.arn
    password_reset_user       = aws_iam_user.password_reset_user.arn
    policy_manager_user       = aws_iam_user.policy_manager_user.arn
    contractor_user           = aws_iam_user.contractor_user.arn
    put_user_policy_user      = aws_iam_user.put_user_policy_user.arn
    put_role_policy_user      = aws_iam_user.put_role_policy_user.arn
    put_group_policy_user     = aws_iam_user.put_group_policy_user.arn
    attach_group_policy_user  = aws_iam_user.attach_group_policy_user.arn
    update_assume_role_user   = aws_iam_user.update_assume_role_user.arn
  }
}

output "role_arns" {
  description = "ARNs of all test roles"
  value = {
    admin_role      = aws_iam_role.admin_role.arn
    ci_role         = aws_iam_role.ci_role.arn
    assumable_role  = aws_iam_role.assumable_role.arn
    privileged_role = aws_iam_role.privileged_role.arn
  }
}

output "policy_arns" {
  description = "ARNs of all test policies"
  value = {
    deployment_policy              = aws_iam_policy.deployment_policy.arn
    low_priv_permissions           = aws_iam_policy.low_priv_permissions.arn
    developer_perms                = aws_iam_policy.developer_permissions.arn
    ci_permissions                 = aws_iam_policy.ci_permissions.arn
    readonly_perms                 = aws_iam_policy.readonly_permissions.arn
    support_perms                  = aws_iam_policy.support_permissions.arn
    put_user_policy_permissions    = aws_iam_policy.put_user_policy_permissions.arn
    put_role_policy_permissions    = aws_iam_policy.put_role_policy_permissions.arn
    put_group_policy_permissions   = aws_iam_policy.put_group_policy_permissions.arn
    attach_group_policy_permissions = aws_iam_policy.attach_group_policy_permissions.arn
    update_assume_role_permissions = aws_iam_policy.update_assume_role_permissions.arn
  }
}