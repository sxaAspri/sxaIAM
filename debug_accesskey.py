import boto3
from sxaiam.ingestion.client import IngestionClient
from sxaiam.resolver.engine import PolicyResolver
from sxaiam.findings.techniques import PassRoleLambdaTechnique, AssumeRoleChainTechnique

session = boto3.Session(profile_name="sandbox")
client = IngestionClient(session=session)
snapshot = client.collect()
resolver = PolicyResolver(snapshot)
resolved = resolver.resolve_all()

developer_arn = "arn:aws:iam::474945406391:user/sxaiam-test/sxaiam-test-developer-user"
ci_arn = "arn:aws:iam::474945406391:role/sxaiam-test-ci-role"

developer = resolved.get(developer_arn)
ci = resolved.get(ci_arn)

print("=== PassRoleLambda (developer_user) ===")
if developer:
    matches = PassRoleLambdaTechnique().check(developer, snapshot)
    print(f"Matches: {len(matches)}")
    for m in matches:
        print(f"  {m.origin_name} → {m.target_name}")
else:
    print("developer_user no encontrado en resolved")

print("\n=== AssumeRoleChain (ci_role) ===")
if ci:
    matches = AssumeRoleChainTechnique().check(ci, snapshot)
    print(f"Matches: {len(matches)}")
    for m in matches:
        print(f"  {m.origin_name} → {m.target_name}")
else:
    print("ci_role no encontrado en resolved")