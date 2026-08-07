"""Splunk REST adapter for explainable detection recommendations."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Optional, cast

from dei.api.response import persistent_response
from dei.recommendations.engine import (
    RecommendationEngine,
    RecommendationError,
    RecommendationReport,
)

RecommendationFactory = Callable[
    [list[str], bool, bool, Optional[dict[str, list[str]]]], RecommendationReport
]
APP_ROOT = Path(__file__).resolve().parents[3]
CATALOG_PATH = APP_ROOT / "detections" / "catalog.json"


def _default_factory(
    sources: list[str], enterprise_security_enabled: bool,
    include_unsupported: bool, fields_by_source: Optional[dict[str, list[str]]],
) -> RecommendationReport:
    return RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        sources,
        enterprise_security_enabled=enterprise_security_enabled,
        include_unsupported=include_unsupported,
        fields_by_source=fields_by_source,
    )


def _decode_payload(request_data: dict[str, Any]) -> Optional[dict[str, Any]]:
    raw_payload: Any = request_data.get("payload", request_data)
    if isinstance(raw_payload, str):
        try:
            raw_payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
    if not isinstance(raw_payload, dict):
        return None
    nested_payload = raw_payload.get("payload")
    if isinstance(nested_payload, str):
        try:
            nested_payload = json.loads(nested_payload)
        except json.JSONDecodeError:
            return None
    if isinstance(nested_payload, dict):
        raw_payload = nested_payload
    return cast(dict[str, Any], raw_payload)


class RecommendationsHandler:
    """Expose detection recommendations through Splunk persistent REST."""

    def __init__(
        self,
        command_line: Optional[Sequence[str]] = None,
        command_arg: Optional[Sequence[str]] = None,
        recommendation_factory: RecommendationFactory = _default_factory,
    ) -> None:
        self._command_line = tuple(command_line or ())
        self._command_arg = tuple(command_arg or ())
        self._recommendation_factory = recommendation_factory

    def handle(self, request: str) -> dict[str, Any]:
        try:
            request_data = json.loads(request)
        except json.JSONDecodeError:
            return persistent_response(400, {"error": "request must be valid JSON"})
        if not isinstance(request_data, dict):
            return persistent_response(400, {"error": "request must be a JSON object"})
        if str(request_data.get("method", "POST")).upper() != "POST":
            return persistent_response(405, {"error": "method not allowed"})

        payload = _decode_payload(request_data)
        if payload is None:
            return persistent_response(400, {"error": "payload must be valid JSON"})

        sources = payload.get("sources")
        if not isinstance(sources, list) or not all(isinstance(item, str) for item in sources):
            return persistent_response(400, {"error": "sources must be an array of strings"})

        enterprise_security_enabled = payload.get("enterprise_security_enabled", False)
        include_unsupported = payload.get("include_unsupported", False)
        if not isinstance(enterprise_security_enabled, bool):
            return persistent_response(400, {"error": "enterprise_security_enabled must be boolean"})
        if not isinstance(include_unsupported, bool):
            return persistent_response(400, {"error": "include_unsupported must be boolean"})

        fields_by_source = payload.get("fields_by_source")
        if fields_by_source is not None:
            if not isinstance(fields_by_source, dict):
                return persistent_response(400, {"error": "fields_by_source must be an object"})
            for source, fields in fields_by_source.items():
                if not isinstance(source, str) or not isinstance(fields, list) or not all(
                    isinstance(field, str) for field in fields
                ):
                    return persistent_response(
                        400,
                        {"error": "fields_by_source must map source names to arrays of strings"},
                    )

        try:
            report = self._recommendation_factory(
                sources, enterprise_security_enabled, include_unsupported, fields_by_source
            )
        except RecommendationError as exc:
            return persistent_response(500, {"error": "recommendation engine failed", "detail": str(exc)})
        except Exception as exc:  # noqa: BLE001
            return persistent_response(500, {"error": "unexpected recommendation failure", "detail": str(exc)})
        return persistent_response(200, report.to_mapping())
