"""Tests for the Splunk health REST adapter."""

from dei.api.health_handler import HealthHandler, _default_report_factory
from dei.core.health import HealthReport
from dei.knowledgepacks.loader import KnowledgePackError


def _report() -> HealthReport:
    return HealthReport(
        status="healthy",
        version="0.1.0",
        knowledge_pack_count=3,
        enterprise_security_enabled=False,
    )


def test_default_report_counts_packaged_knowledge_packs() -> None:
    report = _default_report_factory()

    assert report.knowledge_pack_count == 3
    assert report.status == "healthy"


def test_health_handler_returns_json_payload() -> None:
    handler = HealthHandler(report_factory=_report)

    response = handler.handle('{"method":"GET"}')

    assert response["status"] == 200
    assert response["payload"] == {
        "enterprise_security_enabled": False,
        "knowledge_pack_count": 3,
        "status": "healthy",
        "version": "0.1.0",
    }


def test_health_handler_returns_controlled_pack_error() -> None:
    def invalid_report() -> HealthReport:
        raise KnowledgePackError("invalid manifest")

    handler = HealthHandler(report_factory=invalid_report)

    response = handler.handle('{"method":"GET"}')

    assert response["status"] == 500
    assert response["payload"] == {
        "detail": "invalid manifest",
        "error": "knowledge pack validation failed",
    }


def test_health_handler_rejects_invalid_json() -> None:
    handler = HealthHandler(report_factory=_report)

    response = handler.handle("not-json")

    assert response["status"] == 400
    assert response["payload"] == {"error": "request must be valid JSON"}


def test_health_handler_rejects_non_object_json() -> None:
    handler = HealthHandler(report_factory=_report)

    response = handler.handle("[]")

    assert response["status"] == 400
    assert response["payload"] == {"error": "request must be a JSON object"}


def test_health_handler_rejects_non_get_method() -> None:
    handler = HealthHandler(report_factory=_report)

    response = handler.handle('{"method":"POST"}')

    assert response["status"] == 405
    assert response["payload"] == {"error": "method not allowed"}
