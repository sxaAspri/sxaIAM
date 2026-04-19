# iamspy

> AWS IAM attack path analysis — find privilege escalation chains before attackers do.

[![CI](https://github.com/tu-usuario/iamspy/actions/workflows/ci.yml/badge.svg)](https://github.com/tu-usuario/iamspy/actions)
[![PyPI](https://img.shields.io/pypi/v/iamspy)](https://pypi.org/project/iamspy/)
[![Python](https://img.shields.io/pypi/pyversions/iamspy)](https://pypi.org/project/iamspy/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The problem

AWS tells you what permissions exist. It doesn't tell you what an attacker can do with them *in combination*.

AWS Security Hub might flag that a user has `iam:CreatePolicyVersion`. What it won't tell you is that this user, chaining three permissions that look harmless in isolation, can reach `AdministratorAccess` in two steps. That gap is what iamspy closes.

```
$ iamspy scan --profile staging

[iamspy] Scanning account 123456789012...

  Found 3 privilege escalation paths:

  PATH 1 — CRITICAL (2 steps)
  developer_user
    → iam:CreatePolicyVersion  →  policy/DeploymentPolicy
    → iam:AttachUserPolicy     →  AdministratorAccess
  Evidence: developer_user has iam:CreatePolicyVersion on arn:aws:iam::*:policy/*

  PATH 2 — HIGH (3 steps)
  ci_role
    → iam:PassRole             →  arn:aws:iam::*:role/admin_role
    → lambda:CreateFunction    →  executes as admin_role
    → lambda:InvokeFunction    →  arbitrary code with admin permissions
  Evidence: ci_role trust policy allows sts:AssumeRole from lambda.amazonaws.com
```

---

## How it works

iamspy ingests your AWS account's IAM configuration, resolves **effective permissions**
(accounting for SCPs, permission boundaries, and resource-based policies), builds a
directed graph of identities and resources, and runs a path-finding algorithm to find
all chains that lead to high-privilege nodes.

Every finding is backed by explicit evidence — you can see exactly which IAM permission
justifies each edge in the attack graph.

```
AWS account
    │
    ▼  (boto3 — read-only, agentless)
┌─────────────┐
│   Ingestion  │  get_account_authorization_details + SCPs
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  Policy resolver │  effective permissions per identity
└──────┬──────────┘
       │
       ▼
┌──────────────┐
│ Graph engine  │  networkx DiGraph — nodes: identities/resources
└──────┬───────┘                      edges: permissions
       │
       ▼
┌─────────────┐
│  Path finder │  BFS from any identity → admin nodes
└──────┬──────┘
       │
       ▼
  JSON · Markdown · GraphML
```

---

## Install

```bash
pip install iamspy
```

Requires Python 3.10+ and AWS credentials with read-only IAM access.
The minimum required policy is in [`docs/required-policy.json`](docs/required-policy.json).

---

## Usage

**Scan a full account:**
```bash
iamspy scan --profile my-aws-profile --output findings.json
```

**Scan and export as Markdown (for pentest reports):**
```bash
iamspy scan --profile my-aws-profile --format markdown --output report.md
```

**Export the attack graph (for Gephi / Neo4j / visualization):**
```bash
iamspy scan --profile my-aws-profile --format graphml --output graph.graphml
```

**Compare findings against AWS Security Hub:**
```bash
iamspy compare findings.json --region us-east-1
```

**Use as a Python library:**
```python
from iamspy.ingestion import IAMSnapshot
from iamspy.graph import AttackGraph

snapshot = IAMSnapshot.from_profile("my-profile")
graph = AttackGraph.from_snapshot(snapshot)

paths = graph.find_escalation_paths(origin="arn:aws:iam::123:user/developer")
for path in paths:
    print(path.summary())
```

---

## Why iamspy vs existing tools

| Feature | iamspy | PMapper | Cloudsplaining | Ermetic |
|---|---|---|---|---|
| Attack path chaining | ✅ | ✅ (basic) | ❌ | ✅ |
| Offensive perspective | ✅ | partial | ❌ | ❌ |
| Full evidence per finding | ✅ | ❌ | ❌ | ❌ |
| Effective permissions (SCPs) | ✅ | partial | ❌ | ✅ |
| Security Hub comparison | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ✅ | ❌ |
| Free | ✅ | ✅ | ✅ | ❌ (SaaS) |
| Active maintenance | ✅ | ❌ | partial | N/A |

---

## IAM permissions required to run iamspy

iamspy is **read-only**. It never modifies your account.
The minimum required permissions are:

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

---

## Escalation techniques covered

iamspy currently models the following IAM privilege escalation classes:

- `CreatePolicyVersion` — replace a managed policy with an Allow \*:\* version
- `AttachUserPolicy` / `AttachRolePolicy` — attach AdministratorAccess to self
- `PassRole` + `lambda:CreateFunction` — execute code as a more privileged role
- `sts:AssumeRole` chaining — pivot through roles with permissive trust policies
- `UpdateLoginProfile` / `CreateAccessKey` — credential takeover of a privileged user

Coverage is documented explicitly. If a technique is not yet modeled, it is listed
in [`docs/technique-coverage.md`](docs/technique-coverage.md) as a known gap.

---

## Project structure

```
iamspy/
├── iamspy/
│   ├── cli.py           # CLI entry point (Typer)
│   ├── ingestion/       # boto3 data collection
│   ├── resolver/        # effective permissions calculator
│   ├── graph/           # networkx graph builder + path finder
│   ├── findings/        # escalation technique definitions
│   └── output/          # JSON / Markdown / GraphML exporters
├── tests/
│   ├── unit/            # moto-based AWS mocks, no real credentials needed
│   └── integration/     # against the Terraform test environment
├── terraform/           # deliberately vulnerable IAM test environment
└── docs/
```

---

## Development setup

```bash
git clone https://github.com/tu-usuario/iamspy
cd iamspy
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests (no AWS credentials needed)
pytest

# Lint + type check
ruff check iamspy/
mypy iamspy/
```

---

## Contributing

Contributions are welcome — especially new escalation techniques.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the architecture principles and PR process.

---

## License

MIT — see [LICENSE](LICENSE).

---

## References

- [Rhino Security Labs — AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [MITRE ATT&CK for Cloud — Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/)
- [AWS IAM Policy Evaluation Logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
