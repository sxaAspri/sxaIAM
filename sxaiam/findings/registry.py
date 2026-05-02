"""
sxaiam.findings.registry
========================
Central registry for privilege escalation techniques.
"""

from __future__ import annotations

import importlib

from sxaiam.findings.technique_base import EscalationTechnique


class TechniqueRegistry:
    """Registry of instantiated techniques keyed by technique_id."""

    _techniques: dict[str, EscalationTechnique] = {}
    _loaded = False

    @classmethod
    def register(cls, technique: EscalationTechnique) -> None:
        """Register a technique instance by its technique_id."""
        cls._techniques[technique.technique_id] = technique

    @classmethod
    def all(cls) -> list[EscalationTechnique]:
        """Return all registered technique instances."""
        cls._ensure_loaded()
        return list(cls._techniques.values())

    @classmethod
    def get(cls, technique_id: str) -> EscalationTechnique | None:
        """Return a registered technique by ID, if present."""
        cls._ensure_loaded()
        return cls._techniques.get(technique_id)

    @classmethod
    def _ensure_loaded(cls) -> None:
        """Import techniques once so module-level registrations can run."""
        if cls._loaded:
            return
        importlib.import_module("sxaiam.findings.techniques")
        cls._loaded = True
