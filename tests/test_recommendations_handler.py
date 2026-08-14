"""Tests for the recommendation REST adapter."""

from __future__ import annotations

import json

from dei_intelligence.api.recommendations_handler import RecommendationsHandler
from dei_intelligence.recommendations.engine import RecommendationError, RecommendationReport


def _report(
    sources: list[str], enterprise_security_enabled: bool,
    include_unsupported: bool, fields_by_source: dict[str, list[str]] | None,
    telemetry_routes: list[dict[str, object]] | None,
) -> RecommendationReport:
    assert sources == ["aws:cloudtrail"]
    assert enterprise_security_enabled is False
    assert include_unsupported is False
    assert fields_by_source in (None, {"aws:cloudtrail": ["eventName"]})
    assert telemetry_routes is None
    return RecommendationReport(
        observed_source_count=1,
        normalized_source_count=1,
        production_ready_count=3,
        partial_count=1,
        unsupported_count=5,
        field_gap_count=0,
        field_unverified_count=0,
        source_mappings=(),
        unmapped_sources=(),
        recommendations=(),
    )


def test_handler_returns_recommendation_report() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)
    response = handler.handle(json.dumps({"method": "POST", "payload": {"sources": ["aws:cloudtrail"]}}))
    assert response["status"] == 200
    assert response["payload"]["production_ready_count"] == 3


def test_handler_accepts_field_inventory() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)
    response = handler.handle(json.dumps({
        "method": "POST",
        "payload": {
            "sources": ["aws:cloudtrail"],
            "fields_by_source": {"aws:cloudtrail": ["eventName"]},
        },
    }))
    assert response["status"] == 200


def test_handler_parses_raw_splunk_payload() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)
    raw_body = json.dumps({"sources": ["aws:cloudtrail"]})
    response = handler.handle(json.dumps({"method": "POST", "payload": raw_body}))
    assert response["status"] == 200


def test_handler_unwraps_ui_payload_inside_splunk_payload() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)
    raw_body = json.dumps({"payload": {"sources": ["aws:cloudtrail"]}})
    response = handler.handle(json.dumps({"method": "POST", "payload": raw_body}))
    assert response["status"] == 200


def test_handler_rejects_invalid_sources() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)
    response = handler.handle(json.dumps({"method": "POST", "payload": {"sources": "aws:cloudtrail"}}))
    assert response["status"] == 400
    assert response["payload"] == {"error": "sources must be an array of strings"}


def test_handler_rejects_invalid_field_inventory() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)
    response = handler.handle(json.dumps({
        "method": "POST",
        "payload": {
            "sources": ["aws:cloudtrail"],
            "fields_by_source": {"aws:cloudtrail": "eventName"},
        },
    }))
    assert response["status"] == 400
    assert response["payload"] == {
        "error": "fields_by_source must map source names to arrays of strings"
    }


def test_handler_rejects_non_post_method() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)
    response = handler.handle(json.dumps({"method": "GET", "sources": []}))
    assert response["status"] == 405


def test_handler_reports_engine_failure() -> None:
    def fail(
        sources: list[str], enterprise_security_enabled: bool,
        include_unsupported: bool, fields_by_source: dict[str, list[str]] | None,
        telemetry_routes: list[dict[str, object]] | None,
    ) -> RecommendationReport:
        raise RecommendationError("catalog failed")

    handler = RecommendationsHandler(recommendation_factory=fail)
    response = handler.handle(json.dumps({"method": "POST", "sources": []}))
    assert response["status"] == 500
    assert response["payload"] == {
        "detail": "catalog failed",
        "error": "recommendation engine failed",
    }


def test_handler_accepts_route_scoped_inventory() -> None:
    captured: list[list[dict[str, object]] | None] = []

    def report(
        sources: list[str], enterprise_security_enabled: bool,
        include_unsupported: bool, fields_by_source: dict[str, list[str]] | None,
        telemetry_routes: list[dict[str, object]] | None,
    ) -> RecommendationReport:
        captured.append(telemetry_routes)
        return _report(sources, enterprise_security_enabled, include_unsupported, fields_by_source, None)

    routes = [{"index": "windows", "sourcetype": "XmlWinEventLog", "channels": ["Security"], "fields": ["EventCode"]}]
    response = RecommendationsHandler(recommendation_factory=report).handle(json.dumps({
        "method": "POST", "payload": {"sources": ["aws:cloudtrail"], "telemetry_routes": routes}
    }))
    assert response["status"] == 200
    assert captured == [routes]
