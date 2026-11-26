"""
sxaiam.providers.gcp.models
===========================
Modelos Pydantic del snapshot IAM de un proyecto GCP.

Son el contrato entre el loader y el resto de la capa GCP (resolver, técnicas,
builder). No conocen el formato de salida de gcloud: eso es responsabilidad
de ``loader.py``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class GCPCondition(BaseModel):
    """Condición IAM (CEL) adjunta a un binding. La PoC no la evalúa."""

    title: str = ""
    description: str = ""
    expression: str


class GCPBinding(BaseModel):
    """Un binding IAM: un rol otorgado a una lista de miembros."""

    role: str
    members: list[str] = Field(default_factory=list)
    condition: GCPCondition | None = None

    @property
    def is_conditional(self) -> bool:
        return self.condition is not None


class GCPServiceAccount(BaseModel):
    """
    Service account del proyecto.

    ``bindings`` son los bindings **sobre la SA como recurso** (quién puede
    actuar sobre ella), no los roles que la SA tiene en el proyecto; esos
    están en ``GCPSnapshot.project_bindings`` con miembro
    ``serviceAccount:<email>``.
    """

    email: str
    bindings: list[GCPBinding] = Field(default_factory=list)

    @property
    def member(self) -> str:
        """Identificador de la SA tal como aparece en ``members``."""
        return f"serviceAccount:{self.email}"


class GCPSnapshot(BaseModel):
    """Estado IAM completo de un proyecto GCP."""

    project_id: str
    project_bindings: list[GCPBinding] = Field(default_factory=list)
    service_accounts: list[GCPServiceAccount] = Field(default_factory=list)

    def get_service_account(self, email: str) -> GCPServiceAccount | None:
        for sa in self.service_accounts:
            if sa.email == email:
                return sa
        return None
