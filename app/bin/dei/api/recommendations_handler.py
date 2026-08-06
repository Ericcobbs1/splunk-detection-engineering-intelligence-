"""Splunk REST adapter for explainable detection recommendations."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from dei.api.response import persistent_response
from dei.recommendations.engine import (
    RecommendationEngine,
    RecommendationError,
    RecommendationReport,
)

RecommendationFactory = Callable[[list[str], bool, bool], RecommendationReport]
APP_ROOT = Path(__file__).resolve().parents[3]
CATALOG_PATH = APP_ROOT / "detections" / "catalog.json"


def _default_factory(
    sources: list[str], enterprise_security_enabled: bool, include_unsupported: bool
) -> RecommendationReport:
    """Build recommendations from the catalog packaged with the Splunk app."""
    return RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        sources,
        enterprise_security_enabled=enterprise_security_enabled,
        include_unsupported=include_unsupported,
    )


class RecommendationsHandler:
    """Expose detection recommendations through Splunk persistent REST."""

    def __init__(
        self,
        command_line: Sequence[str] | None = None,
        command_arg: Sequence[str] | None = None,
        recommendation_factory: RecommendationFactory = _default_factory,
    ) -> None:
        self._command_line = tuple(command_line or ())
        self._command_arg = tuple(command_arg or ())
        self._recommendation_factory = recommendation_factory

    def handle(self, request: str) -> dict[str, Any]:
        """Process a POST request containing observed telemetry sources."""
        try:
            request_data = json.loads(request)
        except json.JSONDecodeError:
            return persistent_response(400, {"error": "request must be valid JSON"})

        if not isinstance(request_data, dict):
            return persistent_response(400, {"error": "request must be a JSON object"})
        if str(request_data.get("method", "POST")).upper() != "POST":
            return persistent_response(405, {"error": "method not allowed"})

        payload = request_data.get("payload", request_data)
        if not isinstance(payload, dict):
            return persistent_response(400, {"error": "payload must be a JSON object"})
        sources = payload.get("sources")
        if not isinstance(sources, list) or not all(isinstance(item, str) for item in sources):
            return persistent_response(400, {"error": "sources must be an array of strings"})

        enterprise_security_enabled = payload.get("enterprise_security_enabled", False)
        include_unsupported = payload.get("include_unsupported", False)
        if not isinstance(enterprise_security_enabled, bool):
            return persistent_response(
                400, {"error": "enterprise_security_enabled must be boolean"}
            )
        if not isinstance(include_unsupported, bool):
            return persistent_response(400, {"error": "include_unsupported must be boolean"})

        try:
            report = self._recommendation_factory(
                sources, enterprise_security_enabled, include_unsupported
            )
        except RecommendationError as exc:
            return persistent_response(
                500,
                {"error": "recommendation engine failed", "detail": str(exc)},
            )
        return persistent_response(200, report.to_mapping())
