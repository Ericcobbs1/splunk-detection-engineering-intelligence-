"""Splunk persistent REST entrypoint for DEI health."""

from __future__ import annotations

import sys
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from splunk.persistconn.application import (  # noqa: E402
    PersistentServerConnectionApplication,
)


class HealthApplication(PersistentServerConnectionApplication):
    """Delegate health requests to the DEI health handler."""

    def __init__(self, command_line: list[str], command_arg: list[str]) -> None:
        super().__init__()
        from dei_intelligence.api.health_handler import HealthHandler

        self._handler = HealthHandler(command_line, command_arg)

    def handle(self, in_string: str) -> dict[str, object]:
        return self._handler.handle(in_string)
