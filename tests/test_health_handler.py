"""Tests for the Splunk health REST adapter."""

import json

from dei.api.health_handler import HealthHandler
from dei.core.health import HealthReport


def _report() -> HealthReport:
    return HealthReport(
        status="healthy",
        version="0.1.0",
        knowledge_pack_count=3,
        enterprise_security_enabled=False,
    )


def test_health_handler_returns_json_payload() -> None:
    handler = HealthHandler(report_factory=_report)

    response = handler.handle('{"method":"GET"}')

    assert response["status"] == 200
    assert response["headers"] == {"Content-Type": "application/json"}
    assert json.loads(response["payload"]) == {
        "enterprise_security_enabled": False,
        "knowledge_pack_count": 3,
        "status": "healthy",
        "version": "0.1.0",
    }


def test_health_handler_rejects_invalid_json() -> None:
    handler = HealthHandler(report_factory=_report)

    response = handler.handle("not-json")

    assert response["status"] == 400
    assert json.loads(response["payload"]) == {"error": "request must be valid JSON"}


def test_health_handler_rejects_non_object_json() -> None:
    handler = HealthHandler(report_factory=_report)

    response = handler.handle("[]")

    assert response["status"] == 400
    assert json.loads(response["payload"]) == {"error": "request must be a JSON object"}


def test_health_handler_rejects_non_get_method() -> None:
    handler = HealthHandler(report_factory=_report)

    response = handler.handle('{"method":"POST"}')

    assert response["status"] == 405
    assert json.loads(response["payload"]) == {"error": "method not allowed"}
