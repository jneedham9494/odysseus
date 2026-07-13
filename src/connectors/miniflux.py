"""Miniflux reference connector.

Pulls RSS entries from a Miniflux instance via the proven live agent path:
``execute_api_call`` against the JSON integration store (data/integrations.json,
via load_integrations). RSS cleanly demonstrates the two axes: content is
``sensitivity=public`` yet provenance is ``taint=untrusted`` — injection-laden
entries become inert, taint-stamped RAG rows.

NOTE: There is a parallel ``Integration`` ORM table (core/database.py) that this
connector intentionally does NOT use. The live agent path (do_api_call ->
execute_api_call) uses the JSON store, so this MR builds only on that; ORM
reconciliation is deferred to a later MR.

The connector NEVER interprets entry content — it only strips HTML tags and
hands text to the write-path.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from src.connectors.base import Connector, ConnectorRecord
from src.context_taint import SENSITIVITY_PUBLIC
from src.integrations import _strip_html_tags, execute_api_call, load_integrations

logger = logging.getLogger(__name__)

_PRESET = "miniflux"
# execute_api_call truncates JSON responses at 12000 chars and injects a
# _truncated sentinel; RSS content is full HTML, so we page with a small limit
# and shrink it when truncation is detected.
_DEFAULT_PAGE_SIZE = 20
_MIN_PAGE_SIZE = 1


class MinifluxConnector(Connector):
    name = "miniflux"
    source_type = "connector:miniflux"
    default_sensitivity = SENSITIVITY_PUBLIC

    def _resolve_integration_id(self) -> Optional[str]:
        """Find the Miniflux integration id from the JSON store by preset."""
        for item in load_integrations():
            if item.get("preset") == _PRESET and item.get("enabled", True):
                return item.get("id")
        return None

    async def fetch_changes(self, since: Optional[str]) -> list[ConnectorRecord]:
        integration_id = self._resolve_integration_id()
        if not integration_id:
            logger.warning("Miniflux integration not found in JSON store; nothing to fetch")
            return []

        after = self._parse_cursor(since)
        records: list[ConnectorRecord] = []
        limit = _DEFAULT_PAGE_SIZE

        while True:
            entries, truncated = await self._fetch_page(integration_id, after, limit)
            if truncated:
                if limit > _MIN_PAGE_SIZE:
                    limit = max(_MIN_PAGE_SIZE, limit // 2)
                    continue  # retry the same window with a smaller page
                # limit == 1 and still truncated: a single entry's body exceeds
                # the response cap. Skip rather than ingest a partial, and stop
                # paging so we never spin. Cursor advances only up to prior pages.
                logger.warning(
                    "Miniflux entry after id %s too large even at limit=1; skipping body", after
                )
                break
            if entries is None:  # error / non-200 → no cursor advance
                return []
            if not entries:
                break

            for entry in entries:
                record = self._to_record(entry)
                if record is not None:
                    records.append(record)

            last_id = self._last_id(entries)
            if last_id is None or last_id <= after:
                break  # guard against non-advancing cursor
            after = last_id
            if len(entries) < limit:
                break  # short page → caught up
            limit = _DEFAULT_PAGE_SIZE  # reset for the next full page

        return records  # ascending id order → newest-last

    async def _fetch_page(
        self, integration_id: str, after: int, limit: int
    ) -> tuple[Optional[list[dict[str, Any]]], bool]:
        """Return (entries, truncated). entries is None on error."""
        params = {
            "after_entry_id": after,
            "order": "id",
            "direction": "asc",
            "limit": limit,
        }
        result = await execute_api_call(integration_id, "GET", "/v1/entries", params=params)
        if result.get("exit_code") != 0 or "output" not in result:
            logger.warning("Miniflux fetch failed: %s", result.get("error", "unknown error"))
            return None, False

        parsed = self._parse_output(result["output"])
        if parsed is None:
            return None, False

        # Dict response truncated by execute_api_call drops the whole "entries"
        # key and leaves a top-level _truncated marker.
        if isinstance(parsed, dict) and parsed.get("_truncated") and "entries" not in parsed:
            return None, True

        entries = parsed.get("entries") if isinstance(parsed, dict) else parsed
        if not isinstance(entries, list):
            return None, False

        # Defensive: a list-shaped response truncates with a trailing sentinel.
        if entries and isinstance(entries[-1], dict) and entries[-1].get("_truncated"):
            return entries[:-1], True

        return entries, False

    @staticmethod
    def _parse_output(output: str) -> Optional[Any]:
        """Strip the leading 'HTTP <status>\\n' line and json.loads the rest."""
        if not isinstance(output, str) or "\n" not in output:
            return None
        body = output.split("\n", 1)[1]
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Miniflux response was not valid JSON")
            return None

    @staticmethod
    def _parse_cursor(since: Optional[str]) -> int:
        try:
            return int(since) if since not in (None, "") else 0
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _last_id(entries: list[dict[str, Any]]) -> Optional[int]:
        try:
            return int(entries[-1]["id"])
        except (KeyError, IndexError, TypeError, ValueError):
            return None

    @staticmethod
    def _to_record(entry: dict[str, Any]) -> Optional[ConnectorRecord]:
        if not isinstance(entry, dict) or "id" not in entry:
            return None
        entry_id = str(entry["id"])
        title = str(entry.get("title") or "")
        content = str(entry.get("content") or "")
        url = str(entry.get("url") or "")
        text = _strip_html_tags(f"{title}\n\n{content}".strip())
        return ConnectorRecord(
            external_id=entry_id,
            text=text,
            title=title,
            url=url,
            updated_at=entry_id,  # cursor == entry id (integer, monotonic)
        )
