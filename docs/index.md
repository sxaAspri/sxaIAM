# sxaiam

> AWS IAM attack path analysis — find privilege escalation chains before attackers do.

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

## How it works

AWS account
│
▼  (boto3 — read-only, agentless)
┌─────────────┐
│   Ingestion  │  get_account_authorization_details
└──────┬──────┘
│
▼
┌──────────────────┐
│  Policy resolver  │  effective permissions per identity
└──────┬───────────┘
│
▼
┌──────────────┐
│ Graph engine  │  networkx DiGraph
└──────┬───────┘
│
▼
┌─────────────┐
│  Path finder │  BFS → admin nodes
└──────┬──────┘
│
▼
JSON · Markdown · GraphML

---

## Quick comparison

| Feature | sxaiam | PMapper | Cloudsplaining | Ermetic |
|---|---|---|---|---|
| Attack path chaining | ✅ | ✅ (basic) | ❌ | ✅ |
| Full evidence per finding | ✅ | ❌ | ❌ | ❌ |
| Offensive perspective | ✅ | partial | ❌ | ❌ |
| Security Hub comparison | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ✅ | ❌ |
| Free | ✅ | ✅ | ✅ | ❌ |

---

## Get started

```bash
pip install sxaiam
sxaiam scan --profile my-aws-profile --output findings.json
```

→ [Installation guide](installation.md)
→ [Quickstart](quickstart.md)