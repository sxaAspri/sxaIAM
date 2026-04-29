# Installation

## Requirements

- Python 3.10 or higher
- AWS credentials configured (via `~/.aws/credentials`, environment variables, or IAM role)
- Read-only IAM access to the target account

## Install from PyPI

```bash
pip install sxaiam
```
## Install from source

```bash
git clone https://github.com/sxaAspri/sxaIAM
cd sxaIAM
pip install -e ".[dev]"
```
## Verify installation

```bash
sxaiam --version
sxaiam --help
```
## AWS permissions required

sxaiam is **read-only** — it never modifies your account. The minimum required policy:

```json

{
"Version": "2012-10-17",
"Statement": [
{
"Effect": "Allow",
"Action": [
"iam:GetAccountAuthorizationDetails",
"iam:GetPolicy",
"iam:GetPolicyVersion",
"organizations:ListPolicies",
"organizations:GetPolicy",
"sts:GetCallerIdentity",
"access-analyzer:ListFindings"
],
"Resource": "*"
}
]
}
```
## AWS profile setup

sxaiam uses standard boto3 credential resolution. The recommended approach is named profiles:

```
ini~/.aws/credentials
[my-audit-profile]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
region = us-east-1

```

Then pass the profile name to sxaiam:

```
sxaiam scan --profile my-audit-profile
```