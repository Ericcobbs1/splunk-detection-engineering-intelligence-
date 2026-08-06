"""Shared response helpers for Splunk persistent REST handlers."""

from __future__ import annotations

import json
from typing import Any


def persistent_response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
    """Return the response shape expected by Splunk persistconn."""
    return {
        "payload": json.dumps(payload, separators=(",", ":"), sort_keys=True),
        "status": status,
        "headers": {"Content-Type": "application/json"},
    }
