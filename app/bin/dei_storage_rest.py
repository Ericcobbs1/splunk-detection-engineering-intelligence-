"""Splunk persistent REST entrypoint for governed DEI storage."""

from __future__ import annotations

import sys
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402


class StorageApplication(PersistentServerConnectionApplication):
    def __init__(self, command_line: list[str], command_arg: list[str]) -> None:
        super().__init__()
        from dei_intelligence.api.storage_handler import StorageHandler

        self._handler = StorageHandler()

    def handle(self, in_string: str) -> dict[str, object]:
        return self._handler.handle(in_string)
