"""Splunk persistent REST entrypoints for DEI services."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from splunk.persistconn.application import (  # noqa: E402
    PersistentServerConnectionApplication,
)


class _DelegatingApplication(PersistentServerConnectionApplication):
    """Lazy-load and delegate requests to a DEI handler.

    Splunk resolves this application class before processing a request. Keeping
    project imports out of module scope prevents a DEI dependency error from
    breaking the persistconn loader and corrupting the reply-size protocol.
    """

    handler_module = ""
    handler_name = ""

    def __init__(self, command_line: list[str], command_arg: list[str]) -> None:
        super().__init__()
        self._command_line = command_line
        self._command_arg = command_arg
        self._handler: Any | None = None

    def _load_handler(self) -> Any:
        if self._handler is None:
            module = importlib.import_module(self.handler_module)
            handler_class = getattr(module, self.handler_name)
            self._handler = handler_class(self._command_line, self._command_arg)
        return self._handler

    def handle(self, in_string: str) -> dict[str, object]:
        try:
            return self._load_handler().handle(in_string)
        except Exception as exc:  # Splunk must receive a valid response frame.
            return {
                "payload": {
                    "error": "DEI handler load or execution failed",
                    "detail": str(exc),
                    "exception_type": type(exc).__name__,
                    "handler": f"{self.handler_module}.{self.handler_name}",
                },
                "status": 500,
            }


class HealthApplication(_DelegatingApplication):
    handler_module = "dei_intelligence.api.health_handler"
    handler_name = "HealthHandler"


class CapabilitiesApplication(_DelegatingApplication):
    handler_module = "dei_intelligence.api.capabilities_handler"
    handler_name = "CapabilitiesHandler"


class TelemetryApplication(_DelegatingApplication):
    handler_module = "dei_intelligence.api.telemetry_handler"
    handler_name = "TelemetryHandler"


class RecommendationsApplication(_DelegatingApplication):
    handler_module = "dei_intelligence.api.recommendations_handler"
    handler_name = "RecommendationsHandler"
