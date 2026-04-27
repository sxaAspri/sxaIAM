# sxaiam

**Security eXplainable AI for IAM Attack Mapping**

> Detects privilege escalation paths in AWS IAM using graph analysis and explainable techniques.

[![CI](https://github.com/sxaAspri/sxaIAM/actions/workflows/ci.yml/badge.svg)](https://github.com/sxaAspri/sxaIAM/actions)
[![PyPI](https://img.shields.io/pypi/v/sxaiam)](https://pypi.org/project/sxaiam/)
[![Python](https://img.shields.io/pypi/pyversions/sxaiam)](https://pypi.org/project/sxaiam/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-25%20passed-brightgreen)](https://github.com/sxaAspri/sxaIAM/actions)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue)](https://sxaAspri.github.io/sxaIAM/)

---

## The problem

AWS tells you what permissions exist. It doesn't tell you what an attacker can do with them *in combination*.

AWS Security Hub might flag that a user has `iam:CreatePolicyVersion`. What it won't tell you is that this user, chaining three permissions that look harmless in isolation, can reach `AdministratorAccess` in two steps. **That gap is what sxaiam closes.**

---

## What makes sxaiam different

Most tools answer: *Is this permission dangerous?*

sxaiam answers:

- **Can this principal become admin?**
- **Through which path?**
- **Why? Which permissions justify each step?**
- **Which techniques were used?**

Every finding is backed by explicit IAM permission evidence — no black box, no guessing.

---

## Demo

```bash
$ sxaiam scan --profile staging

sxaiam — IAM Attack Path Analysis
  profile : staging
  output  : findings.json (json)
  cutoff  : 5 hops

1/4 Collecting IAM data from AWS...
  ✓ 12 users, 10 roles, 4 groups — account 123456789012
2/4 Resolving effective permissions...
  ✓ 22 identities resolved
3/4 Building attack graph and finding paths...
  ✓ 27 nodes, 10 edges — 9 escalation path(s) found
4/4 Exporting results (json)...
  ✓ Saved to findings.json

Escalation Paths Found:
  [CRITICAL] low-priv-user      → create-policy-version
  [CRITICAL] readonly-user      → attach-policy
  [HIGH]     developer-user     → passrole-lambda
  [HIGH]     contractor-user    → add-user-to-group
```

## How it works

```
AWS account
    │
    ▼  boto3 — read-only, agentless
    │
Ingestion      →  get_account_authorization_details
    │
Policy resolver  →  effective permissions per identity
    │
Graph engine   →  networkx DiGraph (nodes: identities, edges: permissions)
    │
Path finder    →  BFS from any identity to admin nodes
    │
    ▼
JSON · Markdown · GraphML
```
---

## Install

```bash
pip install sxaiam
```

Requires Python 3.10+ and AWS credentials with read-only IAM access.

---

## Usage

**Scan a full account:**
```bash
sxaiam scan --profile my-aws-profile --output findings.json
```

**Export as Markdown for pentest reports:**
```bash
sxaiam scan --profile my-profile --format markdown --output report.md
```

**Export the attack graph:**
```bash
sxaiam scan --profile my-profile --format graphml --output graph.graphml
```

**Compare against AWS Security Hub:**
```bash
sxaiam compare findings.json --region us-east-1
```

**Use as a Python library:**
```python
import boto3
from sxaiam.ingestion.client import IngestionClient
from sxaiam.resolver.engine import PolicyResolver
from sxaiam.graph.builder import AttackGraph
from sxaiam.graph.pathfinder import PathFinder

session = boto3.Session(profile_name="my-profile")
client = IngestionClient(session=session)
snapshot = client.collect()

resolver = PolicyResolver(snapshot)
resolved = resolver.resolve_all()

graph = AttackGraph()
G = graph.build(snapshot, list(resolved.values()))

finder = PathFinder(G)
paths = finder.find_all_paths()

for path in paths:
    print(path.summary())
```

---

## Escalation techniques covered

| Technique | Severity | Key permissions |
|---|---|---|
| CreatePolicyVersion swap | CRITICAL | `iam:CreatePolicyVersion` |
| AttachUserPolicy / AttachRolePolicy | CRITICAL | `iam:AttachUserPolicy`, `iam:AttachRolePolicy` |
| PassRole + Lambda execution | HIGH | `iam:PassRole`, `lambda:CreateFunction` |
| AssumeRole chaining | HIGH | `sts:AssumeRole` |
| CreateAccessKey credential takeover | HIGH | `iam:CreateAccessKey` |
| CreateLoginProfile console takeover | HIGH | `iam:CreateLoginProfile` |
| UpdateLoginProfile password reset | HIGH | `iam:UpdateLoginProfile` |
| SetDefaultPolicyVersion privilege swap | HIGH | `iam:SetDefaultPolicyVersion` |
| AddUserToGroup self-escalation | HIGH | `iam:AddUserToGroup` |

---

## Why sxaiam vs existing tools

| Feature | sxaiam | PMapper | Cloudsplaining | Ermetic |
|---|---|---|---|---|
| Attack path chaining | ✅ | ✅ (basic) | ❌ | ✅ |
| Full evidence per finding | ✅ | ❌ | ❌ | ❌ |
| Offensive perspective | ✅ | partial | ❌ | ❌ |
| Security Hub comparison | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ✅ | ❌ |
| Free | ✅ | ✅ | ✅ | ❌ |
| Active maintenance | ✅ | ❌ | partial | N/A |

---

## IAM permissions required

sxaiam is **read-only** — it never modifies your account.

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

## Project structure

```
sxaiam/
  sxaiam/
    cli.py              # CLI entry point (Typer)
    ingestion/          # boto3 data collection
    resolver/           # effective permissions calculator
    graph/              # networkx graph builder + path finder
    findings/           # escalation technique definitions
    output/             # JSON / Markdown / GraphML exporters
  tests/
    unit/               # moto-based unit tests
    integration/        # against the Terraform test environment
  terraform/            # deliberately vulnerable IAM sandbox
  docs/                 # MkDocs documentation
```
---

## Development setup

```bash
git clone https://github.com/sxaAspri/sxaIAM
cd sxaIAM
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Run tests (no AWS credentials needed)
pytest

# Lint + type check
ruff check sxaiam/
mypy sxaiam/
```

---

## Documentation

Full documentation available at **[sxaAspri.github.io/sxaIAM](https://sxaAspri.github.io/sxaIAM/)**.

---

## Contributing

Contributions are welcome — especially new escalation techniques.
See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture principles and the PR process.

---

## License

MIT — see [LICENSE](LICENSE).

---

## References

- [Rhino Security Labs — AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [AWS IAM documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/)