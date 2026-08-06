"""Splunk REST adapter for DEI telemetry intelligence."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from dei.core.config import RuntimeConfig
from dei.knowledgepacks.loader import KnowledgePackError, KnowledgePackLoader
from dei.telemetry.analyzer import TelemetryAnalyzer

APP_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = APP_ROOT / "schemas" / "knowledge-pack.schema.json"
PACK_ROOT = APP_ROOT / "knowledgepacks"


class TelemetryHandler:
    """Analyze submitted telemetry sources through Splunk REST."""

    def __init__(
        self,
        command_line: Sequence[str] | None = None,
        command_arg: Sequence[str] | None = None,
    ) -> None:
        self._command_line = tuple(command_line or ())
        self._command_arg = tuple(command_arg or ())

    def handle(self, request: str) -> dict[str, Any]:
        """Analyze a JSON request containing a `sources` string array."""
        try:
            request_data = json.loads(request)
        except json.JSONDecodeError:
            return self._response(400, {"error": "request must be valid JSON"})

        if not isinstance(request_data, dict):
            return self._response(400, {"error": "request must be a JSON object"})
        if str(request_data.get("method", "POST")).upper() != "POST":
            return self._response(405, {"error": "method not allowed"})

        sources = request_data.get("sources")
        if not isinstance(sources, list) or not all(isinstance(item, str) for item in sources):
            return self._response(400, {"error": "sources must be an array of strings"})

        try:
            config = RuntimeConfig()
            packs = KnowledgePackLoader(
                SCHEMA_PATH, current_dei_version=config.app_version
            ).load_all(PACK_ROOT)
            analysis = TelemetryAnalyzer().analyze(tuple(sources), packs)
        except KnowledgePackError as exc:
            return self._response(
                500,
                {"error": "knowledge pack validation failed", "detail": str(exc)},
            )

        return self._response(200, analysis.to_mapping())

    @staticmethod
    def _response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "payload": json.dumps(payload, separators=(",", ":"), sort_keys=True),
            "status": status,
            "headers": {"Content-Type": "application/json"},
        }
