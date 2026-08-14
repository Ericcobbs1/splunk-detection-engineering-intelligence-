"""Splunk persistent-connection adapter for DEI runtime health."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from dei_intelligence.api.response import persistent_response
from dei_intelligence.core.config import RuntimeConfig
from dei_intelligence.core.health import HealthReport, HealthService
from dei_intelligence.knowledgepacks.loader import KnowledgePackError, KnowledgePackLoader

HealthReportFactory = Callable[[], HealthReport]
APP_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = APP_ROOT / "schemas" / "knowledge-pack.schema.json"
PACK_ROOT = APP_ROOT / "knowledgepacks"


def _default_report_factory() -> HealthReport:
    """Build health from the Knowledge Packs installed with the Splunk app."""
    config = RuntimeConfig()
    packs = KnowledgePackLoader(
        SCHEMA_PATH, current_dei_version=config.app_version
    ).load_all(PACK_ROOT)
    return HealthService(config).report(knowledge_pack_count=len(packs))


class HealthHandler:
    """Expose DEI health through Splunk's persistent REST handler contract."""

    def __init__(
        self,
        command_line: Sequence[str] | None = None,
        command_arg: Sequence[str] | None = None,
        report_factory: HealthReportFactory = _default_report_factory,
    ) -> None:
        self._command_line = tuple(command_line or ())
        self._command_arg = tuple(command_arg or ())
        self._report_factory = report_factory

    def handle(self, request: str) -> dict[str, Any]:
        """Return a Splunk persistent-handler response for a GET request."""
        try:
            request_data = json.loads(request)
        except json.JSONDecodeError:
            return persistent_response(400, {"error": "request must be valid JSON"})

        if not isinstance(request_data, dict):
            return persistent_response(400, {"error": "request must be a JSON object"})

        method = str(request_data.get("method", "GET")).upper()
        if method != "GET":
            return persistent_response(405, {"error": "method not allowed"})

        try:
            report = self._report_factory()
        except KnowledgePackError as exc:
            return persistent_response(
                500,
                {"error": "knowledge pack validation failed", "detail": str(exc)},
            )

        return persistent_response(200, report.to_mapping())
