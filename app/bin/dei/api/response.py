"""Shared response helpers for Splunk persistent REST handlers."""

from __future__ import annotations

from typing import Any


def persistent_response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
    """Return Splunk's documented persistent-handler response shape."""
    return {
        "payload": payload,
        "status": status,
    }
