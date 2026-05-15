output "account_id" {
  description = "AWS account ID where the sandbox was deployed"
  value       = data.aws_caller_identity.current.account_id
}

output "attack_paths_summary" {
  description = "Attack paths present — sxaiam should detect all of these"
  value = {
    path_1  = "low_priv_user → iam:CreatePolicyVersion → swap DeploymentPolicy → AdministratorAccess"
    path_2  = "developer_user → iam:PassRole + lambda:CreateFunction → execute as admin_role"
    path_3  = "ci_role → sts:AssumeRole → admin_role → AdministratorAccess"
    path_4  = "readonly_user → iam:AttachUserPolicy → attach AdministratorAccess to self"
    path_5  = "support_user → iam:CreateAccessKey → on privileged_user → credential takeover"
    path_6  = "helpdesk_user → iam:CreateLoginProfile → on console_admin_user → console takeover"
    path_7  = "password_reset_user → iam:UpdateLoginProfile → on finance_user → password reset"
    path_8  = "policy_manager_user → iam:SetDefaultPolicyVersion → swap DeploymentPolicy → admin"
    path_9  = "contractor_user → iam:AddUserToGroup → admin_group → AdministratorAccess"
    path_10 = "put_user_policy_user → iam:PutUserPolicy → inline policy on self → AdministratorAccess"
    path_11 = "put_role_policy_user → iam:PutRolePolicy + sts:AssumeRole → assumable_role → AdministratorAccess"
    path_12 = "put_group_policy_user → iam:PutGroupPolicy → inline policy on target_group → AdministratorAccess"
    path_13 = "attach_group_policy_user → iam:AttachGroupPolicy → AdministratorAccess on escalation_group"
    path_14 = "update_assume_role_user → iam:UpdateAssumeRolePolicy + sts:AssumeRole → privileged_role → AdministratorAccess"
  }
}

output "user_arns" {
  description = "ARNs of all test users created"
  value       = module.vulnerable_identities.user_arns
}

output "role_arns" {
  description = "ARNs of all test roles created"
  value       = module.vulnerable_identities.role_arns
}
