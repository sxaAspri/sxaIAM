"""
sxaiam.providers.gcp.roles
==========================
Mapa fijo rol predefinido → permisos, para la PoC.

IMPORTANTE: cada rol lista solo el **subconjunto de permisos relevante** para
las técnicas de la PoC, no su definición completa (p. ej. ``roles/owner``
tiene miles de permisos). Un permiso ausente aquí no significa que el rol
real no lo tenga.

Roles custom y roles predefinidos fuera de este mapa: el resolver los ignora
con una advertencia (fuera de alcance, ver planning/gcp-poc-plan.md §4).
"""

from __future__ import annotations

# Permisos que consultan las técnicas
SET_PROJECT_IAM_POLICY = "resourcemanager.projects.setIamPolicy"
GET_SA_ACCESS_TOKEN = "iam.serviceAccounts.getAccessToken"

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "roles/owner": frozenset({
        "resourcemanager.projects.get",
        "resourcemanager.projects.getIamPolicy",
        SET_PROJECT_IAM_POLICY,
    }),
    "roles/editor": frozenset({
        "resourcemanager.projects.get",
        "resourcemanager.projects.getIamPolicy",
    }),
    "roles/viewer": frozenset({
        "resourcemanager.projects.get",
        "resourcemanager.projects.getIamPolicy",
    }),
    "roles/iam.serviceAccountTokenCreator": frozenset({
        GET_SA_ACCESS_TOKEN,
        "iam.serviceAccounts.getOpenIdToken",
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
    }),
    "roles/resourcemanager.projectIamAdmin": frozenset({
        "resourcemanager.projects.getIamPolicy",
        SET_PROJECT_IAM_POLICY,
    }),
    "roles/iam.securityAdmin": frozenset({
        "resourcemanager.projects.getIamPolicy",
        SET_PROJECT_IAM_POLICY,
        "iam.serviceAccounts.getIamPolicy",
        "iam.serviceAccounts.setIamPolicy",
    }),
}


def permissions_for_role(role: str) -> frozenset[str] | None:
    """Permisos del rol, o ``None`` si el rol no está en el mapa."""
    return ROLE_PERMISSIONS.get(role)
