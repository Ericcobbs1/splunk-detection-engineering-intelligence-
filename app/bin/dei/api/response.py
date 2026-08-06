"""Shared response helpers for Splunk persistent REST handlers."""

from __future__ import annotations

from typing import Any


def persistent_response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
    """Return a response object for Splunk's persistent REST framework.

    Splunk owns JSON serialization and persistent-connection framing. Returning a
    pre-serialized JSON string can corrupt the reply-size protocol used between
    splunkd and the persistent Python process.
    """
    return {
        "payload": payload,
        "status": status,
    }
