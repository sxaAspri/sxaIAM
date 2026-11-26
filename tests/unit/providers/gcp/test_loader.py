"""
Tests for sxaiam.providers.gcp.loader

Carga el fixture tests/fixtures/gcp/vulnerable_project.json y verifica que
el envoltorio sobre la salida cruda de gcloud se traduce a GCPSnapshot.
"""

from pathlib import Path

import pytest

from sxaiam.providers.gcp.loader import GCPSnapshotError, load_snapshot, parse_snapshot
from sxaiam.providers.gcp.models import GCPSnapshot

FIXTURE = Path(__file__).parents[3] / "fixtures" / "gcp" / "vulnerable_project.json"

DEPLOYER = "deployer@acme-poc-123456.iam.gserviceaccount.com"
READER = "reader@acme-poc-123456.iam.gserviceaccount.com"
CI_RUNNER = "ci-runner@acme-poc-123456.iam.gserviceaccount.com"


@pytest.fixture(scope="module")
def snapshot() -> GCPSnapshot:
    return load_snapshot(FIXTURE)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

def test_project_id(snapshot: GCPSnapshot) -> None:
    assert snapshot.project_id == "acme-poc-123456"


def test_counts(snapshot: GCPSnapshot) -> None:
    assert len(snapshot.project_bindings) == 4
    assert len(snapshot.service_accounts) == 3


def test_service_account_emails(snapshot: GCPSnapshot) -> None:
    assert {sa.email for sa in snapshot.service_accounts} == {DEPLOYER, READER, CI_RUNNER}


def test_sa_member_identifier(snapshot: GCPSnapshot) -> None:
    sa = snapshot.get_service_account(DEPLOYER)
    assert sa is not None
    assert sa.member == f"serviceAccount:{DEPLOYER}"


def test_sa_level_bindings(snapshot: GCPSnapshot) -> None:
    deployer = snapshot.get_service_account(DEPLOYER)
    assert deployer is not None
    assert len(deployer.bindings) == 1
    assert deployer.bindings[0].role == "roles/iam.serviceAccountTokenCreator"
    assert deployer.bindings[0].members == ["user:bob@acme-poc.example"]


def test_policy_without_bindings_key_is_empty(snapshot: GCPSnapshot) -> None:
    # gcloud devuelve {"etag": "ACAB"} cuando la SA no tiene bindings
    ci_runner = snapshot.get_service_account(CI_RUNNER)
    assert ci_runner is not None
    assert ci_runner.bindings == []


def test_conditional_binding_is_kept(snapshot: GCPSnapshot) -> None:
    # El loader conserva la condición; ignorarla es trabajo del resolver
    conditional = [b for b in snapshot.project_bindings if b.is_conditional]
    assert len(conditional) == 1
    assert conditional[0].members == ["user:dave@acme-poc.example"]
    assert conditional[0].condition is not None
    assert conditional[0].condition.title == "expira-fin-de-anio"


def test_unconditional_bindings(snapshot: GCPSnapshot) -> None:
    assert sum(not b.is_conditional for b in snapshot.project_bindings) == 3


def test_get_unknown_service_account(snapshot: GCPSnapshot) -> None:
    assert snapshot.get_service_account("nope@x.iam.gserviceaccount.com") is None


# ---------------------------------------------------------------------------
# Casos borde y errores
# ---------------------------------------------------------------------------

def test_minimal_snapshot() -> None:
    snap = parse_snapshot({"project_id": "p"})
    assert snap.project_bindings == []
    assert snap.service_accounts == []


def test_missing_project_id() -> None:
    with pytest.raises(GCPSnapshotError, match="project_id"):
        parse_snapshot({"project_iam_policy": {}})


def test_not_an_object() -> None:
    with pytest.raises(GCPSnapshotError):
        parse_snapshot([])


def test_binding_without_role() -> None:
    with pytest.raises(GCPSnapshotError):
        parse_snapshot({
            "project_id": "p",
            "project_iam_policy": {"bindings": [{"members": ["user:a@x"]}]},
        })


def test_service_account_without_email() -> None:
    with pytest.raises(GCPSnapshotError, match="email"):
        parse_snapshot({"project_id": "p", "service_accounts": [{"iam_policy": {}}]})


def test_project_policy_not_an_object() -> None:
    with pytest.raises(GCPSnapshotError, match="IAM policy"):
        parse_snapshot({"project_id": "p", "project_iam_policy": ["roles/owner"]})


def test_sa_policy_not_an_object() -> None:
    with pytest.raises(GCPSnapshotError, match="IAM policy"):
        parse_snapshot({
            "project_id": "p",
            "service_accounts": [{"email": "a@p.iam.gserviceaccount.com", "iam_policy": "x"}],
        })


def test_service_account_not_an_object() -> None:
    with pytest.raises(GCPSnapshotError, match="service account"):
        parse_snapshot({"project_id": "p", "service_accounts": ["a@p.iam.gserviceaccount.com"]})


def test_duplicate_service_account() -> None:
    sa = {"email": "a@p.iam.gserviceaccount.com", "iam_policy": {"etag": "ACAB"}}
    with pytest.raises(GCPSnapshotError, match="duplicada"):
        parse_snapshot({"project_id": "p", "service_accounts": [sa, sa]})


def test_invalid_json_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(GCPSnapshotError, match="JSON inválido"):
        load_snapshot(bad)
