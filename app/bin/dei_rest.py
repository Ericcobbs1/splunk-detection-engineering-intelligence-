"""Splunk persistent REST entrypoints for DEI services."""

from __future__ import annotations

import sys
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from splunk.persistconn.application import PersistentServerConnectionApplication

from dei.api.capabilities_handler import CapabilitiesHandler
from dei.api.health_handler import HealthHandler
from dei.api.recommendations_handler import RecommendationsHandler
from dei.api.telemetry_handler import TelemetryHandler


class _DelegatingApplication(PersistentServerConnectionApplication):
    """Delegate Splunk persistent-connection requests to a DEI handler."""

    handler_class: type

    def __init__(self, command_line: list[str], command_arg: list[str]) -> None:
        super().__init__()
        self._handler = self.handler_class(command_line, command_arg)

    def handle(self, in_string: str) -> dict[str, object]:
        return self._handler.handle(in_string)


class HealthApplication(_DelegatingApplication):
    handler_class = HealthHandler


class CapabilitiesApplication(_DelegatingApplication):
    handler_class = CapabilitiesHandler


class TelemetryApplication(_DelegatingApplication):
    handler_class = TelemetryHandler


class RecommendationsApplication(_DelegatingApplication):
    handler_class = RecommendationsHandler
