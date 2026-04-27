# Quickstart

## Your first scan

```bash
sxaiam scan --profile my-aws-profile --output findings.json
```

sxaiam will:

1. Collect all IAM users, roles, groups and policies from your account
2. Resolve effective permissions for each identity
3. Build an attack graph and find escalation paths
4. Export results to `findings.json`

## Output formats

**JSON** — machine-readable, full evidence included:
```bash
sxaiam scan --profile my-profile --format json --output findings.json
```

**Markdown** — for pentest reports:
```bash
sxaiam scan --profile my-profile --format markdown --output report.md
```

**GraphML** — for Gephi, Neo4j or other graph visualization tools:
```bash
sxaiam scan --profile my-profile --format graphml --output graph.graphml
```

## Compare against AWS Security Hub

```bash
sxaiam compare findings.json --region us-east-1
```

This shows which paths sxaiam found that Security Hub missed, and vice versa.

## Use as a Python library

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

## Understanding the output

Each escalation path includes:

- **Origin** — the identity that can escalate
- **Severity** — CRITICAL, HIGH, MEDIUM, or LOW
- **Techniques** — which IAM techniques are used
- **Steps** — the exact API calls an attacker would make
- **Evidence** — the specific IAM permissions that justify each step