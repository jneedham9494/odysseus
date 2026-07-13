"""Connector registry: name -> factory.

``get_connector(name, owner)`` returns a fresh connector instance for the given
registry name. Owner is accepted for forward-compatibility (owner-scoped
connector construction) but current connectors take the owner at sync time via
``run_sync(connector, owner, store)``; the JSON integration store is currently
global/unowned.
"""
from __future__ import annotations

from typing import Callable, Optional

from src.connectors.base import Connector
from src.connectors.miniflux import MinifluxConnector

_REGISTRY: dict[str, Callable[[], Connector]] = {
    MinifluxConnector.name: MinifluxConnector,
}


def get_connector(name: str, owner: Optional[str] = None) -> Optional[Connector]:
    """Return a new connector instance for ``name``, or None if unknown."""
    factory = _REGISTRY.get(name)
    if factory is None:
        return None
    return factory()


def available_connectors() -> list[str]:
    """Return the sorted list of registered connector names."""
    return sorted(_REGISTRY)
