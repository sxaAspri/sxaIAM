import sys
sys.path.insert(0, ".")

from sxaiam.ingestion.models import (
    IAMSnapshot, IAMUser, IAMRole, IAMGroup,
    PolicyDocument, PolicyStatement, AttachedPolicy,
)
from sxaiam.resolver.engine import PolicyResolver
from sxaiam.graph.builder import AttackGraph
from sxaiam.graph.pathfinder import PathFinder

LOW_PRIV_ARN = "arn:aws:iam::123456789012:user/low_priv_user"

def _stmt(effect, actions, resources, principal=None):
    return PolicyStatement(
        Effect=effect, actions=actions, resources=resources,
        principal=principal,
    )

def _inline_doc(actions):
    return PolicyDocument(statements=[_stmt("Allow", actions, ["*"])])

def _make_user(arn, name, inline_actions):
    return IAMUser(
        arn=arn, name=name,
        user_id=f"AIDA{name.upper()[:12]}",
        path="/",
        inline_policies={"sandbox-policy": _inline_doc(inline_actions)},
        attached_policies=[], group_names=[],
    )

low_priv = _make_user(LOW_PRIV_ARN, "low_priv_user", ["iam:CreatePolicyVersion"])

snapshot = IAMSnapshot(
    account_id="123456789012",
    users=[low_priv], roles=[], groups=[], policies=[],
)
snapshot.build_indexes()

resolver = PolicyResolver(snapshot)
resolved = resolver.resolve_all()
print("Resolved identities:", list(resolved.keys()))

identity = resolved.get(LOW_PRIV_ARN)
if identity:
    print("can CreatePolicyVersion *:", identity.can("iam:CreatePolicyVersion", "*"))
    print("permissions:", list(identity.permissions_for_action("iam:CreatePolicyVersion")))
else:
    print("identity NOT FOUND in resolved")


print("\nInline policies:")
for name, doc in low_priv.inline_policies.items():
    print(f"  policy: {name}")
    for stmt in doc.statements:
        print(f"    effect: {stmt.effect}")
        print(f"    actions: {stmt.actions}")
        print(f"    resources: {stmt.resources}")