"""n8n push connector.

Unlike Miniflux (which *pulls* on a cursor via ``fetch_changes``), n8n is a
*push* source: the personal-intelligence workflows POST batches of records to
``/api/connectors/ingest`` and the route hands them to the SAME write-path
(``ingest.ingest_records``). This connector exists only to carry the two
security-critical class attributes into that write-path:

- ``source_type = "connector:n8n:<workflow>"`` — a per-workflow provenance tag.
  Because it starts with ``connector:`` it is treated as ``taint=untrusted`` at
  retrieval by MR-2b, exactly like Miniflux.
- ``default_sensitivity = personal`` — n8n personal-intelligence content is
  assumed personal unless a record overrides it. This is the conservative
  (fail-toward-more-sensitive) default; Miniflux defaults to ``public`` because
  RSS is public.

The workflow slug is stamped into ``source_type`` and MUST therefore be a
constrained token — validated by :func:`sanitize_workflow` so a caller cannot
inject arbitrary text into the provenance tag.

PORT NOTE (rebuild/n8n-ingest onto refactor/base):
    The connector framework (MR-2: ``src/connectors/base.py`` and the
    ``SENSITIVITY_*`` constants in ``src/context_taint.py``) is a PREREQUISITE
    that is not present on ``refactor/base`` yet. The framework imports below
    are guarded so this module still imports cleanly on the current base; the
    guards become inert no-ops once MR-2 is merged. ``sanitize_workflow`` is a
    pure function and never depends on the framework.
"""
from __future__ import annotations

import re
from typing import Optional

try:  # MR-2 (connector framework) prerequisite — inert once merged.
    from src.connectors.base import Connector, ConnectorRecord  # noqa: F401
except ImportError:  # pragma: no cover - exercised only on refactor/base
    Connector = object  # type: ignore[assignment,misc]

try:  # MR-2 also adds the graded-sensitivity constants to context_taint.
    from src.context_taint import SENSITIVITY_PERSONAL
except ImportError:  # pragma: no cover - exercised only on refactor/base
    # Fallback value is byte-identical to the framework constant, so behaviour
    # is unchanged; this only keeps the module importable pre-merge.
    SENSITIVITY_PERSONAL = "personal"

# Workflow slugs become part of the provenance tag (source_type), so keep them
# to a short, boring token: lowercase letters, digits, dash, underscore.
_WORKFLOW_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_DEFAULT_WORKFLOW = "default"


def sanitize_workflow(workflow: Optional[str]) -> Optional[str]:
    """Normalize + validate a workflow slug, or return None if invalid.

    Lowercases and trims. Returns None (caller rejects) rather than silently
    coercing, so a malformed workflow name never lands in ``source_type``.
    """
    if workflow is None:
        return _DEFAULT_WORKFLOW
    if not isinstance(workflow, str):
        return None
    slug = workflow.strip().lower()
    if not slug:
        return _DEFAULT_WORKFLOW
    return slug if _WORKFLOW_RE.match(slug) else None


class N8nConnector(Connector):
    """A push connector whose ``source_type`` names the originating workflow."""

    name = "n8n"
    default_sensitivity = SENSITIVITY_PERSONAL

    def __init__(self, workflow: str) -> None:
        slug = sanitize_workflow(workflow)
        if slug is None:
            raise ValueError(f"invalid n8n workflow slug: {workflow!r}")
        self.workflow = slug
        # Instance attr shadows the class annotation; stamped into every record.
        self.source_type = f"connector:n8n:{slug}"

    async def fetch_changes(self, since: Optional[str]) -> list:
        """n8n is push-only — there is nothing to pull.

        Present to satisfy the ABC; ``run_sync`` is never used for this
        connector. Records arrive through the ingest route and go straight to
        ``ingest_records``.
        """
        return []
