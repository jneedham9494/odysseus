"""Single source of truth for parsing api_call / app_api tool content (MR-16).

The tier classifier (``src.actuator_tiers._api_call_tier``) and the executor
(``src.tool_implementations.do_api_call``) MUST agree on what an api_call does.
When they parsed content differently, an attacker could pick a content form the
executor honours but the classifier ignores and thereby dodge the money gate
(e.g. the line-based ``"firefly\\nPOST /...\\n{...}"`` form, which the executor
runs but a JSON-only classifier saw as unparseable). Both now call
``parse_api_call_content`` so their notion of method / target / body is identical.

Depends only on the stdlib so it can be imported by both the low-level classifier
and the tool executor without an import cycle.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional


def _parse_line_based(content: str) -> Dict[str, Any]:
    """Parse the legacy line-based form ``integration\\nMETHOD path\\nbody``.

    Mirrors ``do_api_call`` exactly so the classifier sees the same request the
    executor will run.
    """
    lines = content.strip().split("\n")
    args: Dict[str, Any] = {"integration": lines[0].strip() if lines else ""}
    if len(lines) > 1:
        parts = lines[1].strip().split(" ", 1)
        args["method"] = parts[0] if parts else "GET"
        args["path"] = parts[1] if len(parts) > 1 else "/"
    if len(lines) > 2:
        try:
            args["body"] = json.loads("\n".join(lines[2:]))
        except json.JSONDecodeError:
            pass
    return args


def parse_api_call_content(content: Optional[str]) -> Optional[Any]:
    """Parse api_call / app_api tool content into its argument object.

    Returns the parsed value (normally a ``dict`` of integration/method/path/body).
    Tries JSON first, then falls back to the line-based form the executor also
    accepts. Returns ``None`` for empty content. May return a non-dict when the
    content is valid JSON that is not an object (e.g. a list); callers decide how
    to treat that - the executor errors on it and the classifier fails closed.
    """
    if not content:
        return None
    try:
        return json.loads(content)
    except (ValueError, TypeError):
        return _parse_line_based(content)
