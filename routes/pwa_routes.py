# routes/pwa_routes.py
"""Serve the PWA manifest and service worker at the app root (MR-23).

The static copies also live under ``/static/``, but a service worker can only
control the scope it is served from. Serving ``sw.js`` from ``/`` (with
``Service-Worker-Allowed: /``) lets it claim the whole origin and act as a real
offline shell for the SPA. Serving ``manifest.json`` here lets us return the
canonical ``application/manifest+json`` content-type rather than the generic
``application/json`` a static mount infers from the extension.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

_MANIFEST_MEDIA_TYPE = "application/manifest+json"
_SW_MEDIA_TYPE = "text/javascript"


def setup_pwa_routes(static_dir: str | Path) -> APIRouter:
    """Build the root-scope PWA router serving files from ``static_dir``."""
    static_path = Path(static_dir)
    router = APIRouter(tags=["pwa"])

    @router.get("/manifest.json")
    async def serve_manifest() -> FileResponse:
        path = static_path / "manifest.json"
        if not path.is_file():
            raise HTTPException(404, "manifest.json not found")
        return FileResponse(
            str(path),
            media_type=_MANIFEST_MEDIA_TYPE,
            headers={"Cache-Control": "no-cache"},
        )

    @router.get("/sw.js")
    async def serve_service_worker() -> FileResponse:
        path = static_path / "sw.js"
        if not path.is_file():
            raise HTTPException(404, "sw.js not found")
        return FileResponse(
            str(path),
            media_type=_SW_MEDIA_TYPE,
            # Allow a script served from "/" to control the entire origin scope.
            headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"},
        )

    return router
