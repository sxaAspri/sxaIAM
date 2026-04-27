# Escalation Techniques

sxaiam currently models 9 IAM privilege escalation techniques.
Each technique is a self-contained class that knows what permissions it needs,
how to find viable targets, and what evidence to attach to each finding.

## Technique registry

| ID | Name | Severity | Key permissions |
|---|---|---|---|
| `create-policy-version` | CreatePolicyVersion swap | CRITICAL | `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` |
| `attach-policy` | AttachUserPolicy / AttachRolePolicy | CRITICAL | `iam:AttachUserPolicy`, `iam:AttachRolePolicy` |
| `passrole-lambda` | PassRole + Lambda execution | HIGH | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` |
| `assumerole-chain` | AssumeRole chaining | HIGH | `sts:AssumeRole` |
| `create-access-key` | CreateAccessKey credential takeover | HIGH | `iam:CreateAccessKey` |
| `create-login-profile` | CreateLoginProfile console takeover | HIGH | `iam:CreateLoginProfile` |
| `update-login-profile` | UpdateLoginProfile password reset | HIGH | `iam:UpdateLoginProfile` |
| `set-default-policy-version` | SetDefaultPolicyVersion privilege swap | HIGH | `iam:SetDefaultPolicyVersion` |
| `add-user-to-group` | AddUserToGroup self-escalation | HIGH | `iam:AddUserToGroup` |

---

## Technique details

### CreatePolicyVersion swap
**Severity:** CRITICAL

The identity has `iam:CreatePolicyVersion` on a managed policy that is also attached
to itself. By creating a new policy version with `Allow *:*` and setting it as default,
the identity grants itself full administrator access.

**Attack steps:**

iam:CreatePolicyVersion on target policy with {"Effect":"Allow","Action":"","Resource":""}
iam:SetDefaultPolicyVersion to activate the new version
Identity now has AdministratorAccess


---

### AttachUserPolicy / AttachRolePolicy
**Severity:** CRITICAL

The identity has `iam:AttachUserPolicy` or `iam:AttachRolePolicy` with a resource scope
that includes itself. It can attach `AdministratorAccess` directly in one API call.

**Attack steps:**

iam:AttachUserPolicy with PolicyArn=arn:aws:iam::aws:policy/AdministratorAccess
Identity now has AdministratorAccess


---

### PassRole + Lambda execution
**Severity:** HIGH

The identity has `iam:PassRole` on a privileged role and can create Lambda functions.
By creating a Lambda that runs as the privileged role and invoking it, the attacker
executes arbitrary code with those permissions.

**Attack steps:**

lambda:CreateFunction with Role=<privileged_role_arn>
lambda:InvokeFunction to execute arbitrary code as the privileged role


---

### AssumeRole chaining
**Severity:** HIGH

The identity has `sts:AssumeRole` on a more privileged role, and that role's trust
policy allows this identity to assume it. Direct pivot in a single API call.

**Attack steps:**

sts:AssumeRole with RoleArn=<target_role_arn>
Receive temporary credentials for the target role


---

### CreateAccessKey credential takeover
**Severity:** HIGH

The identity has `iam:CreateAccessKey` on a more privileged user. By generating a
new access key for that user, the attacker can authenticate as them and inherit
all their permissions.

**Attack steps:**

iam:CreateAccessKey with UserName=<target_user>
Configure AWS CLI with the returned credentials
Operate as the target user


---

### CreateLoginProfile console takeover
**Severity:** HIGH

The identity has `iam:CreateLoginProfile` on a more privileged user that has no
console password yet. By setting a password, the attacker can log into the AWS
console as that user.

**Attack steps:**

iam:CreateLoginProfile with UserName=<target_user> and a chosen password
Log into AWS console as the target user


---

### UpdateLoginProfile password reset
**Severity:** HIGH

The identity has `iam:UpdateLoginProfile` on a more privileged user that already
has a console password. By resetting it, the attacker can log in as that user.

**Attack steps:**

iam:UpdateLoginProfile with UserName=<target_user> and a new password
Log into AWS console as the target user


---

### SetDefaultPolicyVersion privilege swap
**Severity:** HIGH

The identity has `iam:SetDefaultPolicyVersion` on a managed policy attached to
itself. If a non-default version with broader permissions exists, the attacker
can activate it.

**Attack steps:**

iam:ListPolicyVersions to find non-default versions
iam:SetDefaultPolicyVersion to activate a version with broader permissions


---

### AddUserToGroup self-escalation
**Severity:** HIGH

The identity has `iam:AddUserToGroup` on a privileged group. By adding itself
to that group, it immediately inherits all the group's permissions.

**Attack steps:**

iam:AddUserToGroup with GroupName=<admin_group> and UserName=<self>
Identity immediately inherits all group permissions


---

## Adding a new technique

See [Contributing](contributing.md) for step-by-step instructions on how to
add a new escalation technique to sxaiam.