output "account_id" {
  description = "AWS account ID where the sandbox was deployed"
  value       = data.aws_caller_identity.current.account_id
}

output "attack_paths_summary" {
  description = "Attack paths present — sxaiam should detect all of these"
  value = {
    path_1 = "low_priv_user → iam:CreatePolicyVersion → swap DeploymentPolicy → AdministratorAccess"
    path_2 = "developer_user → iam:PassRole + lambda:CreateFunction → execute as admin_role"
    path_3 = "ci_role → sts:AssumeRole → admin_role → AdministratorAccess"
    path_4 = "readonly_user → iam:AttachUserPolicy → attach AdministratorAccess to self"
    path_5 = "support_user → iam:CreateAccessKey → on privileged_user → credential takeover"
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
