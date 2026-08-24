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
from dei_intelligence.recommendations.engine import RecommendationEngine, RecommendationError

HealthReportFactory = Callable[[], HealthReport]
DependencyChecker = Callable[[str], dict[str, dict[str, Any]]]
APP_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = APP_ROOT / "schemas" / "knowledge-pack.schema.json"
PACK_ROOT = APP_ROOT / "knowledgepacks"
DETECTION_SCHEMA_PATH = APP_ROOT / "schemas" / "detection.schema.json"


def _session_key(request_data: dict[str, Any]) -> str:
    for source in (request_data, request_data.get("session", {}), request_data.get("connection", {})):
        if isinstance(source, dict):
            value = source.get("sessionKey") or source.get("session_key") or source.get("authtoken")
            if isinstance(value, str) and value:
                return value
    return ""


def _default_dependency_checker(session_key: str) -> dict[str, dict[str, Any]]:
    from splunk.rest import simpleRequest  # type: ignore[import-not-found]

    endpoints = {
        "splunk_api": "/services/server/info?output_mode=json",
        "search_api": "/services/search/jobs?count=0&output_mode=json",
        "kv_store": "/servicesNS/nobody/splunk_detection_engineering_intelligence/storage/collections/config/dei_lifecycle_records?output_mode=json",
    }
    checks: dict[str, dict[str, Any]] = {}
    for name, path in endpoints.items():
        try:
            response, _ = simpleRequest(path, sessionKey=session_key, method="GET", raiseAllErrors=False)
            status = int(response.get("status", 0))
            checks[name] = {"ready": status == 200, "http_status": status}
        except Exception as exc:
            checks[name] = {"ready": False, "detail": str(exc)[:240]}
    return checks


def _default_report_factory() -> HealthReport:
    """Build health from the Knowledge Packs installed with the Splunk app."""
    config = RuntimeConfig()
    packs = KnowledgePackLoader(
        SCHEMA_PATH, current_dei_version=config.app_version
    ).load_all(PACK_ROOT)
    engine = RecommendationEngine.from_knowledge_packs(
        PACK_ROOT,
        SCHEMA_PATH,
        DETECTION_SCHEMA_PATH,
        current_dei_version=config.app_version,
    )
    return HealthService(config).report(
        knowledge_pack_count=len(packs),
        detection_count=engine.detection_count,
    )


class HealthHandler:
    """Expose DEI health through Splunk's persistent REST handler contract."""

    def __init__(
        self,
        command_line: Sequence[str] | None = None,
        command_arg: Sequence[str] | None = None,
        report_factory: HealthReportFactory = _default_report_factory,
        dependency_checker: DependencyChecker = _default_dependency_checker,
    ) -> None:
        self._command_line = tuple(command_line or ())
        self._command_arg = tuple(command_arg or ())
        self._report_factory = report_factory
        self._dependency_checker = dependency_checker

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
        except (KnowledgePackError, RecommendationError) as exc:
            return persistent_response(
                500,
                {"error": "knowledge pack validation failed", "detail": str(exc)},
            )

        payload = report.to_mapping()
        session_key = _session_key(request_data)
        if session_key:
            dependencies = self._dependency_checker(session_key)
            ready = all(bool(item.get("ready")) for item in dependencies.values())
            payload["dependencies"] = dependencies
            payload["readiness"] = "ready" if ready else "degraded"
            if not ready:
                payload["status"] = "degraded"
        else:
            payload["dependencies"] = {"authenticated_checks": {"ready": False, "detail": "session unavailable"}}
            payload["readiness"] = "unknown"
        return persistent_response(200, payload)
