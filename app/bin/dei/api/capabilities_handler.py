"""Splunk persistent-connection adapter for DEI capabilities."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from dei.core.capabilities import CapabilityInventory, CapabilityService
from dei.core.config import RuntimeConfig
from dei.knowledgepacks.loader import KnowledgePackError, KnowledgePackLoader

CapabilityInventoryFactory = Callable[[], CapabilityInventory]
APP_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = APP_ROOT / "schemas" / "knowledge-pack.schema.json"
PACK_ROOT = APP_ROOT / "knowledgepacks"


def _default_inventory_factory() -> CapabilityInventory:
    """Build inventory from Knowledge Packs installed with the Splunk app."""
    config = RuntimeConfig()
    packs = KnowledgePackLoader(
        SCHEMA_PATH, current_dei_version=config.app_version
    ).load_all(PACK_ROOT)
    return CapabilityService().inventory(packs)


class CapabilitiesHandler:
    """Expose installed DEI capabilities through Splunk REST."""

    def __init__(
        self,
        command_line: Sequence[str] | None = None,
        command_arg: Sequence[str] | None = None,
        inventory_factory: CapabilityInventoryFactory = _default_inventory_factory,
    ) -> None:
        self._command_line = tuple(command_line or ())
        self._command_arg = tuple(command_arg or ())
        self._inventory_factory = inventory_factory

    def handle(self, request: str) -> dict[str, Any]:
        """Return a persistent-handler response for an authenticated GET."""
        try:
            request_data = json.loads(request)
        except json.JSONDecodeError:
            return self._response(400, {"error": "request must be valid JSON"})

        if not isinstance(request_data, dict):
            return self._response(400, {"error": "request must be a JSON object"})

        method = str(request_data.get("method", "GET")).upper()
        if method != "GET":
            return self._response(405, {"error": "method not allowed"})

        try:
            inventory = self._inventory_factory()
        except KnowledgePackError as exc:
            return self._response(
                500,
                {"error": "knowledge pack validation failed", "detail": str(exc)},
            )

        return self._response(200, inventory.to_mapping())

    @staticmethod
    def _response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "payload": json.dumps(payload, separators=(",", ":"), sort_keys=True),
            "status": status,
            "headers": {"Content-Type": "application/json"},
        }
