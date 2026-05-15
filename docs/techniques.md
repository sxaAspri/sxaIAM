# Escalation Techniques

sxaiam currently models 14 IAM privilege escalation techniques.
Each technique is a self-contained class that knows what permissions it needs,
how to find viable targets, and what evidence to attach to each finding.

## Technique registry

| ID | Name | Severity | Key permissions |
|---|---|---|---|
| `create-policy-version` | CreatePolicyVersion swap | CRITICAL | `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` |
| `attach-policy` | AttachUserPolicy / AttachRolePolicy | CRITICAL | `iam:AttachUserPolicy`, `iam:AttachRolePolicy` |
| `put-user-policy` | PutUserPolicy inline escalation | CRITICAL | `iam:PutUserPolicy` |
| `put-role-policy` | PutRolePolicy inline escalation | CRITICAL | `iam:PutRolePolicy`, `sts:AssumeRole` |
| `put-group-policy` | PutGroupPolicy inline escalation | CRITICAL | `iam:PutGroupPolicy` |
| `attach-group-policy` | AttachGroupPolicy escalation | CRITICAL | `iam:AttachGroupPolicy` |
| `passrole-lambda` | PassRole + Lambda execution | HIGH | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` |
| `assumerole-chain` | AssumeRole chaining | HIGH | `sts:AssumeRole` |
| `create-access-key` | CreateAccessKey credential takeover | HIGH | `iam:CreateAccessKey` |
| `create-login-profile` | CreateLoginProfile console takeover | HIGH | `iam:CreateLoginProfile` |
| `update-login-profile` | UpdateLoginProfile password reset | HIGH | `iam:UpdateLoginProfile` |
| `set-default-policy-version` | SetDefaultPolicyVersion privilege swap | HIGH | `iam:SetDefaultPolicyVersion` |
| `add-user-to-group` | AddUserToGroup self-escalation | HIGH | `iam:AddUserToGroup` |
| `update-assume-role-policy` | UpdateAssumeRolePolicy trust hijack | HIGH | `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole` |

---

## Technique details

### CreatePolicyVersion swap
**Severity:** CRITICAL

The identity has `iam:CreatePolicyVersion` on a managed policy that is also attached
to itself. By creating a new policy version with `Allow *:*` and setting it as default,
the identity grants itself full administrator access.

**Attack steps:**

1. `iam:CreatePolicyVersion` on target policy with `{"Effect":"Allow","Action":"*","Resource":"*"}`
2. `iam:SetDefaultPolicyVersion` to activate the new version
3. Identity now has AdministratorAccess

---

### AttachUserPolicy / AttachRolePolicy
**Severity:** CRITICAL

The identity has `iam:AttachUserPolicy` or `iam:AttachRolePolicy` with a resource scope
that includes itself. It can attach `AdministratorAccess` directly in one API call.

**Attack steps:**

1. `iam:AttachUserPolicy` with `PolicyArn=arn:aws:iam::aws:policy/AdministratorAccess`
2. Identity now has AdministratorAccess

---

### PutUserPolicy inline escalation
**Severity:** CRITICAL

The identity has `iam:PutUserPolicy` on itself. By creating an inline policy with
`Allow *:*` directly on its own user, it grants itself full administrator access
in a single API call.

**Attack steps:**

1. `iam:PutUserPolicy` with `UserName=<self>` and `{"Effect":"Allow","Action":"*","Resource":"*"}`
2. Identity now has full administrator access via inline policy

---

### PutRolePolicy inline escalation
**Severity:** CRITICAL

The identity has `iam:PutRolePolicy` on a role it can assume. By injecting an inline
policy with `Allow *:*` into that role and then assuming it, the attacker gains full
administrator access.

**Attack steps:**

1. `iam:PutRolePolicy` on target role with `{"Effect":"Allow","Action":"*","Resource":"*"}`
2. `sts:AssumeRole` with `RoleArn=<target_role_arn>`
3. Operate as the target role with full administrator access

---

### PutGroupPolicy inline escalation
**Severity:** CRITICAL

The identity has `iam:PutGroupPolicy` on a group. By injecting an inline policy with
`Allow *:*` into that group, all members immediately inherit full administrator access.

**Attack steps:**

1. `iam:PutGroupPolicy` on target group with `{"Effect":"Allow","Action":"*","Resource":"*"}`
2. All members of the group immediately inherit full administrator access

---

### AttachGroupPolicy escalation
**Severity:** CRITICAL

The identity has `iam:AttachGroupPolicy` on a group. By attaching `AdministratorAccess`
to that group, all its members immediately inherit full administrator access.

**Attack steps:**

1. `iam:AttachGroupPolicy` with `GroupName=<target_group>` and `PolicyArn=arn:aws:iam::aws:policy/AdministratorAccess`
2. All members of the group immediately inherit AdministratorAccess

---

### PassRole + Lambda execution
**Severity:** HIGH

The identity has `iam:PassRole` on a privileged role and can create Lambda functions.
By creating a Lambda that runs as the privileged role and invoking it, the attacker
executes arbitrary code with those permissions.

**Attack steps:**

1. `lambda:CreateFunction` with `Role=<privileged_role_arn>`
2. `lambda:InvokeFunction` to execute arbitrary code as the privileged role

---

### AssumeRole chaining
**Severity:** HIGH

The identity has `sts:AssumeRole` on a more privileged role, and that role's trust
policy allows this identity to assume it. Direct pivot in a single API call.

**Attack steps:**

1. `sts:AssumeRole` with `RoleArn=<target_role_arn>`
2. Receive temporary credentials for the target role

---

### CreateAccessKey credential takeover
**Severity:** HIGH

The identity has `iam:CreateAccessKey` on a more privileged user. By generating a
new access key for that user, the attacker can authenticate as them and inherit
all their permissions.

**Attack steps:**

1. `iam:CreateAccessKey` with `UserName=<target_user>`
2. Configure AWS CLI with the returned credentials
3. Operate as the target user

---

### CreateLoginProfile console takeover
**Severity:** HIGH

The identity has `iam:CreateLoginProfile` on a more privileged user that has no
console password yet. By setting a password, the attacker can log into the AWS
console as that user.

**Attack steps:**

1. `iam:CreateLoginProfile` with `UserName=<target_user>` and a chosen password
2. Log into AWS console as the target user

---

### UpdateLoginProfile password reset
**Severity:** HIGH

The identity has `iam:UpdateLoginProfile` on a more privileged user that already
has a console password. By resetting it, the attacker can log in as that user.

**Attack steps:**

1. `iam:UpdateLoginProfile` with `UserName=<target_user>` and a new password
2. Log into AWS console as the target user

---

### SetDefaultPolicyVersion privilege swap
**Severity:** HIGH

The identity has `iam:SetDefaultPolicyVersion` on a managed policy attached to
itself. If a non-default version with broader permissions exists, the attacker
can activate it.

**Attack steps:**

1. `iam:ListPolicyVersions` to find non-default versions
2. `iam:SetDefaultPolicyVersion` to activate a version with broader permissions

---

### AddUserToGroup self-escalation
**Severity:** HIGH

The identity has `iam:AddUserToGroup` on a privileged group. By adding itself
to that group, it immediately inherits all the group's permissions.

**Attack steps:**

1. `iam:AddUserToGroup` with `GroupName=<admin_group>` and `UserName=<self>`
2. Identity immediately inherits all group permissions

---

### UpdateAssumeRolePolicy trust hijack
**Severity:** HIGH

The identity has `iam:UpdateAssumeRolePolicy` on a privileged role. By modifying
the trust policy to allow itself to assume that role, the attacker can then call
`sts:AssumeRole` and inherit all of the role's permissions.

**Attack steps:**

1. `iam:UpdateAssumeRolePolicy` on target role to add self as trusted principal
2. `sts:AssumeRole` with `RoleArn=<target_role_arn>`
3. Operate as the target role with its full permissions

---

## Adding a new technique

See [Contributing](contributing.md) for step-by-step instructions on how to
add a new escalation technique to sxaiam.