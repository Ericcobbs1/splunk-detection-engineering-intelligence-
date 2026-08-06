"""Splunk persistent-connection adapter for DEI runtime health."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

from dei.core.config import RuntimeConfig
from dei.core.health import HealthReport, HealthService

HealthReportFactory = Callable[[], HealthReport]


def _default_report_factory() -> HealthReport:
    """Build the baseline health report used by the Splunk REST endpoint."""
    return HealthService(RuntimeConfig()).report(knowledge_pack_count=0)


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
            return self._response(400, {"error": "request must be valid JSON"})

        if not isinstance(request_data, dict):
            return self._response(400, {"error": "request must be a JSON object"})

        method = str(request_data.get("method", "GET")).upper()
        if method != "GET":
            return self._response(405, {"error": "method not allowed"})

        return self._response(200, self._report_factory().to_mapping())

    @staticmethod
    def _response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "payload": json.dumps(payload, separators=(",", ":"), sort_keys=True),
            "status": status,
            "headers": {"Content-Type": "application/json"},
        }
