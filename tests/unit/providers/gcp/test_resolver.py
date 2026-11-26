"""
Tests for sxaiam.providers.gcp.resolver and sxaiam.providers.gcp.roles

Verifica can(permission, resource) por principal sobre el fixture, la
herencia proyecto → service account, y el manejo de miembros, roles y
bindings fuera de alcance (ignorados con advertencia).
"""

from pathlib import Path
from typing import Any

import pytest

from sxaiam.providers.gcp.loader import load_snapshot, parse_snapshot
from sxaiam.providers.gcp.resolver import (
    GCPResolvedPrincipal,
    GCPResolver,
    MemberKind,
    parse_member_kind,
)
from sxaiam.providers.gcp.roles import (
    GET_SA_ACCESS_TOKEN,
    ROLE_PERMISSIONS,
    SET_PROJECT_IAM_POLICY,
)

FIXTURE = Path(__file__).parents[3] / "fixtures" / "gcp" / "vulnerable_project.json"

PROJECT = "projects/acme-poc-123456"
DEPLOYER = "deployer@acme-poc-123456.iam.gserviceaccount.com"
READER = "reader@acme-poc-123456.iam.gserviceaccount.com"
CI_RUNNER = "ci-runner@acme-poc-123456.iam.gserviceaccount.com"
DEPLOYER_RES = f"{PROJECT}/serviceAccounts/{DEPLOYER}"
READER_RES = f"{PROJECT}/serviceAccounts/{READER}"

ALICE = "user:alice@acme-poc.example"
BOB = "user:bob@acme-poc.example"
CAROL = "user:carol@acme-poc.example"
DAVE = "user:dave@acme-poc.example"


@pytest.fixture(scope="module")
def resolver() -> GCPResolver:
    return GCPResolver(load_snapshot(FIXTURE))


@pytest.fixture(scope="module")
def principals(resolver: GCPResolver) -> dict[str, GCPResolvedPrincipal]:
    return resolver.resolve_all()


def resolve(raw: dict[str, Any]) -> tuple[GCPResolver, dict[str, GCPResolvedPrincipal]]:
    r = GCPResolver(parse_snapshot({"project_id": "p", **raw}))
    return r, r.resolve_all()


def project_policy(*bindings: dict[str, Any]) -> dict[str, Any]:
    return {"project_iam_policy": {"bindings": list(bindings)}}


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

def test_role_map_has_the_six_poc_roles() -> None:
    assert set(ROLE_PERMISSIONS) == {
        "roles/owner",
        "roles/editor",
        "roles/viewer",
        "roles/iam.serviceAccountTokenCreator",
        "roles/resourcemanager.projectIamAdmin",
        "roles/iam.securityAdmin",
    }


def test_editor_cannot_set_iam_policy() -> None:
    assert SET_PROJECT_IAM_POLICY not in ROLE_PERMISSIONS["roles/editor"]


# ---------------------------------------------------------------------------
# Fixture: can(permission, resource) por principal
# ---------------------------------------------------------------------------

def test_resource_names(resolver: GCPResolver) -> None:
    assert resolver.project_resource == PROJECT
    assert resolver.service_account_resource(DEPLOYER) == DEPLOYER_RES


def test_principals_in_fixture(principals: dict[str, GCPResolvedPrincipal]) -> None:
    # dave no aparece: su único binding es condicional
    assert set(principals) == {
        ALICE, BOB, CAROL,
        f"serviceAccount:{DEPLOYER}",
        f"serviceAccount:{READER}",
        f"serviceAccount:{CI_RUNNER}",
    }


def test_alice_can_set_project_iam_policy(principals: dict[str, GCPResolvedPrincipal]) -> None:
    assert principals[ALICE].can(SET_PROJECT_IAM_POLICY, PROJECT)


def test_alice_evidence(principals: dict[str, GCPResolvedPrincipal]) -> None:
    [perm] = principals[ALICE].permissions_for(SET_PROJECT_IAM_POLICY, PROJECT)
    assert perm.role == "roles/resourcemanager.projectIamAdmin"
    assert perm.as_evidence() == (
        f"{SET_PROJECT_IAM_POLICY} on {PROJECT} "
        "(via role roles/resourcemanager.projectIamAdmin)"
    )


def test_bob_can_impersonate_deployer_only(principals: dict[str, GCPResolvedPrincipal]) -> None:
    bob = principals[BOB]
    assert bob.can(GET_SA_ACCESS_TOKEN, DEPLOYER_RES)
    assert not bob.can(GET_SA_ACCESS_TOKEN, READER_RES)
    assert not bob.can(SET_PROJECT_IAM_POLICY, PROJECT)


def test_bob_evidence_points_to_sa(principals: dict[str, GCPResolvedPrincipal]) -> None:
    [perm] = principals[BOB].permissions_for(GET_SA_ACCESS_TOKEN, DEPLOYER_RES)
    assert perm.resource == DEPLOYER_RES
    assert perm.role == "roles/iam.serviceAccountTokenCreator"


def test_sa_level_grant_does_not_cover_project(
    principals: dict[str, GCPResolvedPrincipal],
) -> None:
    assert not principals[BOB].can(GET_SA_ACCESS_TOKEN, PROJECT)


def test_carol_viewer_cannot_escalate(principals: dict[str, GCPResolvedPrincipal]) -> None:
    carol = principals[CAROL]
    assert carol.can("resourcemanager.projects.get", PROJECT)
    assert not carol.can(SET_PROJECT_IAM_POLICY, PROJECT)
    assert not carol.can(GET_SA_ACCESS_TOKEN, DEPLOYER_RES)


def test_ci_runner_can_impersonate_reader(principals: dict[str, GCPResolvedPrincipal]) -> None:
    ci = principals[f"serviceAccount:{CI_RUNNER}"]
    assert ci.kind is MemberKind.SERVICE_ACCOUNT
    assert ci.can(GET_SA_ACCESS_TOKEN, READER_RES)
    assert not ci.can(GET_SA_ACCESS_TOKEN, DEPLOYER_RES)


def test_deployer_owner_can_set_iam_policy(principals: dict[str, GCPResolvedPrincipal]) -> None:
    deployer = principals[f"serviceAccount:{DEPLOYER}"]
    assert deployer.can(SET_PROJECT_IAM_POLICY, PROJECT)
    assert {p.role for p in deployer.permissions} == {"roles/owner"}


def test_conditional_binding_warning_names_role_and_member(resolver: GCPResolver) -> None:
    resolver.resolve_all()
    assert len(resolver.warnings) == 1
    warning = resolver.warnings[0]
    assert "condicional" in warning
    assert "roles/resourcemanager.projectIamAdmin" in warning
    assert DAVE in warning


# ---------------------------------------------------------------------------
# Herencia proyecto → service account
# ---------------------------------------------------------------------------

def test_project_level_token_creator_covers_all_sas() -> None:
    _, principals = resolve({
        **project_policy({
            "role": "roles/iam.serviceAccountTokenCreator",
            "members": ["user:eve@x"],
        }),
        "service_accounts": [
            {"email": "a@p.iam.gserviceaccount.com", "iam_policy": {}},
            {"email": "b@p.iam.gserviceaccount.com", "iam_policy": {}},
        ],
    })
    eve = principals["user:eve@x"]
    assert eve.can(GET_SA_ACCESS_TOKEN, "projects/p/serviceAccounts/a@p.iam.gserviceaccount.com")
    assert eve.can(GET_SA_ACCESS_TOKEN, "projects/p/serviceAccounts/b@p.iam.gserviceaccount.com")


def test_prefix_match_respects_segment_boundary() -> None:
    _, principals = resolve(project_policy({"role": "roles/owner", "members": ["user:a@x"]}))
    # "projects/p" no debe cubrir "projects/p2"
    assert not principals["user:a@x"].can(SET_PROJECT_IAM_POLICY, "projects/p2")


# ---------------------------------------------------------------------------
# Miembros
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("member", "kind"), [
    ("user:a@x.com", MemberKind.USER),
    ("serviceAccount:sa@p.iam.gserviceaccount.com", MemberKind.SERVICE_ACCOUNT),
    ("group:devs@x.com", MemberKind.GROUP),
    ("domain:x.com", MemberKind.DOMAIN),
    ("allUsers", MemberKind.ALL_USERS),
    ("allAuthenticatedUsers", MemberKind.ALL_AUTHENTICATED_USERS),
])
def test_supported_member_kinds(member: str, kind: MemberKind) -> None:
    assert parse_member_kind(member) is kind


@pytest.mark.parametrize("member", [
    "deleted:user:old@x.com?uid=123",
    "deleted:serviceAccount:sa@p.iam.gserviceaccount.com?uid=456",
    "principal://iam.googleapis.com/locations/global/workforcePools/p/subject/s",
    "user:",
    "foo",
])
def test_unsupported_member_kinds(member: str) -> None:
    assert parse_member_kind(member) is None


def test_special_members_are_normal_principals() -> None:
    members = ["group:devs@x.com", "domain:x.com", "allUsers", "allAuthenticatedUsers"]
    resolver, principals = resolve(
        project_policy({"role": "roles/resourcemanager.projectIamAdmin", "members": members})
    )
    for member in members:
        assert principals[member].can(SET_PROJECT_IAM_POLICY, "projects/p")
    assert resolver.warnings == []


def test_deleted_member_ignored_with_warning() -> None:
    deleted = "deleted:user:old@x.com?uid=123"
    resolver, principals = resolve(
        project_policy({"role": "roles/owner", "members": [deleted, "user:a@x"]})
    )
    assert deleted not in principals
    assert "user:a@x" in principals
    assert len(resolver.warnings) == 1
    assert "eliminado" in resolver.warnings[0]
    assert deleted in resolver.warnings[0]


def test_unknown_member_kind_ignored_with_warning() -> None:
    member = "principalSet://iam.googleapis.com/locations/global/workforcePools/p/*"
    resolver, principals = resolve(project_policy({"role": "roles/owner", "members": [member]}))
    assert member not in principals
    assert "no soportado" in resolver.warnings[0]


# ---------------------------------------------------------------------------
# Roles y bindings fuera de alcance
# ---------------------------------------------------------------------------

def test_unknown_role_ignored_with_warning() -> None:
    resolver, principals = resolve(
        project_policy({"role": "projects/p/roles/customRole", "members": ["user:a@x"]})
    )
    assert "user:a@x" not in principals
    assert len(resolver.warnings) == 1
    assert "projects/p/roles/customRole" in resolver.warnings[0]


def test_conditional_binding_warns_once_per_member() -> None:
    resolver, principals = resolve(project_policy({
        "role": "roles/owner",
        "members": ["user:a@x", "user:b@x"],
        "condition": {"title": "t", "expression": "true"},
    }))
    assert principals == {}
    assert len(resolver.warnings) == 2
    assert any("user:a@x" in w for w in resolver.warnings)
    assert any("user:b@x" in w for w in resolver.warnings)


def test_conditional_binding_does_not_hide_unconditional_one() -> None:
    _, principals = resolve(project_policy(
        {"role": "roles/owner", "members": ["user:a@x"],
         "condition": {"title": "t", "expression": "true"}},
        {"role": "roles/viewer", "members": ["user:a@x"]},
    ))
    a = principals["user:a@x"]
    assert a.can("resourcemanager.projects.get", "projects/p")
    assert not a.can(SET_PROJECT_IAM_POLICY, "projects/p")


def test_duplicate_grants_are_merged() -> None:
    _, principals = resolve(project_policy(
        {"role": "roles/viewer", "members": ["user:a@x"]},
        {"role": "roles/viewer", "members": ["user:a@x"]},
    ))
    perms = principals["user:a@x"].permissions
    assert len(perms) == len(set(perms))


def test_sa_without_grants_is_still_a_principal() -> None:
    _, principals = resolve({
        "service_accounts": [{"email": "idle@p.iam.gserviceaccount.com", "iam_policy": {}}],
    })
    idle = principals["serviceAccount:idle@p.iam.gserviceaccount.com"]
    assert idle.permissions == []


def test_resolve_all_resets_warnings(resolver: GCPResolver) -> None:
    resolver.resolve_all()
    resolver.resolve_all()
    assert len(resolver.warnings) == 1
