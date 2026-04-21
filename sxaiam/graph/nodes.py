"""
sxaiam/graph/nodes.py

Definición de todos los tipos de nodos del grafo de ataque.

Regla de arquitectura #1: los nodos son extensibles.
Agregar un nuevo tipo de nodo (ej. LambdaNode, S3BucketNode) no debe
tocar el pathfinder ni el builder — solo agregar la clase aquí y
registrarla en NODE_TYPES.

Cada nodo tiene:
  - node_id  : identificador único, normalmente el ARN de AWS
  - node_type: string constante que identifica el tipo
  - label    : nombre legible para visualización y reportes
"""

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Constantes de tipo — el pathfinder y el builder usan estas constantes,
# nunca strings mágicos.
# ---------------------------------------------------------------------------

NODE_TYPE_USER   = "user"
NODE_TYPE_ROLE   = "role"
NODE_TYPE_GROUP  = "group"
NODE_TYPE_POLICY = "policy"
NODE_TYPE_ADMIN  = "admin"   # Nodo virtual — no existe en AWS


# ---------------------------------------------------------------------------
# Clase base
# ---------------------------------------------------------------------------

@dataclass
class IAMNode:
    """
    Clase base para todos los nodos del grafo.

    No instanciar directamente — usar las subclases tipadas.
    """
    node_id:   str          # ARN de AWS o identificador sintético (AdminNode)
    node_type: str          # Una de las constantes NODE_TYPE_*
    label:     str          # Nombre legible: username, role name, etc.
    account_id: Optional[str] = field(default=None)

    def __hash__(self) -> int:
        return hash(self.node_id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IAMNode):
            return NotImplemented
        return self.node_id == other.node_id

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(node_id={self.node_id!r}, label={self.label!r})"


# ---------------------------------------------------------------------------
# Nodos concretos
# ---------------------------------------------------------------------------

@dataclass
class UserNode(IAMNode):
    """
    Representa un IAM User.

    node_id  = ARN del usuario  (arn:aws:iam::123456789012:user/alice)
    label    = nombre del usuario (alice)
    """
    node_type: str = field(default=NODE_TYPE_USER, init=False)


@dataclass
class RoleNode(IAMNode):
    """
    Representa un IAM Role.

    node_id  = ARN del rol  (arn:aws:iam::123456789012:role/developer)
    label    = nombre del rol (developer)

    has_trust_policy indica si el rol tiene una trust policy que
    permite AssumeRole desde otras identidades — el builder usa esto
    para generar aristas de tipo AssumeRole chain.
    """
    node_type: str = field(default=NODE_TYPE_ROLE, init=False)
    has_trust_policy: bool = field(default=False)


@dataclass
class GroupNode(IAMNode):
    """
    Representa un IAM Group.

    Los grupos no ejecutan acciones por sí solos, pero son nodos
    intermedios útiles para visualización y para trazar de dónde
    vienen los permisos de un usuario.

    node_id  = ARN del grupo  (arn:aws:iam::123456789012:group/developers)
    label    = nombre del grupo (developers)
    """
    node_type: str = field(default=NODE_TYPE_GROUP, init=False)


@dataclass
class PolicyNode(IAMNode):
    """
    Representa una IAM Policy (managed).

    Útil para visualización de qué política específica habilita
una arista de escalación. En v0.1.0 es un nodo de soporte —
    el pathfinder no atraviesa PolicyNodes, los usa solo como
    evidencia en las aristas.

    node_id  = ARN de la policy  (arn:aws:iam::aws:policy/AdministratorAccess)
    label    = nombre de la policy (AdministratorAccess)
    """
    node_type: str = field(default=NODE_TYPE_POLICY, init=False)
    is_aws_managed: bool = field(default=False)


@dataclass
class AdminNode(IAMNode):
    """
    Nodo virtual que representa el estado de AdministratorAccess.

    NO existe en AWS — es un singleton sintético creado por el builder
    para que el BFS tenga un destino concreto al que llegar.

    Cualquier identidad que tenga permisos equivalentes a admin
    (iam:* sobre *, AdministratorAccess policy, etc.) tendrá una
    arista directa hacia este nodo.

    node_id fijo: "sxaiam::admin" — nunca cambia.
    """
    node_id:   str = field(default="sxaiam::admin", init=False)
    node_type: str = field(default=NODE_TYPE_ADMIN, init=False)
    label:     str = field(default="AdministratorAccess", init=False)
    account_id: Optional[str] = field(default=None)

    def __init__(self) -> None:
        # Ignoramos los parámetros de IAMNode — AdminNode es un singleton
        object.__setattr__(self, "node_id",    "sxaiam::admin")
        object.__setattr__(self, "node_type",  NODE_TYPE_ADMIN)
        object.__setattr__(self, "label",      "AdministratorAccess")
        object.__setattr__(self, "account_id", None)


# ---------------------------------------------------------------------------
# Registro de tipos — para extensibilidad futura
# Agregar un nuevo nodo = agregar la clase aquí.
# ---------------------------------------------------------------------------

NODE_TYPES: dict[str, type[IAMNode]] = {
    NODE_TYPE_USER:   UserNode,
    NODE_TYPE_ROLE:   RoleNode,
    NODE_TYPE_GROUP:  GroupNode,
    NODE_TYPE_POLICY: PolicyNode,
    NODE_TYPE_ADMIN:  AdminNode,
}
