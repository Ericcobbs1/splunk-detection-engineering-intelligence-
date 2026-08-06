"""Tests for the recommendation REST adapter."""

import json

from dei.api.recommendations_handler import RecommendationsHandler
from dei.recommendations.engine import RecommendationError, RecommendationReport


def _report(
    sources: list[str], enterprise_security_enabled: bool, include_unsupported: bool
) -> RecommendationReport:
    assert sources == ["aws:cloudtrail"]
    assert enterprise_security_enabled is False
    assert include_unsupported is False
    return RecommendationReport(
        observed_source_count=1,
        production_ready_count=3,
        partial_count=1,
        unsupported_count=5,
        recommendations=(),
    )


def test_handler_returns_recommendation_report() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)

    response = handler.handle(
        json.dumps({"method": "POST", "payload": {"sources": ["aws:cloudtrail"]}})
    )

    assert response["status"] == 200
    assert json.loads(response["payload"])["production_ready_count"] == 3


def test_handler_rejects_invalid_sources() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)

    response = handler.handle(
        json.dumps({"method": "POST", "payload": {"sources": "aws:cloudtrail"}})
    )

    assert response["status"] == 400
    assert json.loads(response["payload"]) == {
        "error": "sources must be an array of strings"
    }


def test_handler_rejects_non_post_method() -> None:
    handler = RecommendationsHandler(recommendation_factory=_report)

    response = handler.handle(json.dumps({"method": "GET", "sources": []}))

    assert response["status"] == 405


def test_handler_reports_engine_failure() -> None:
    def fail(
        sources: list[str], enterprise_security_enabled: bool, include_unsupported: bool
    ) -> RecommendationReport:
        raise RecommendationError("catalog failed")

    handler = RecommendationsHandler(recommendation_factory=fail)
    response = handler.handle(json.dumps({"method": "POST", "sources": []}))

    assert response["status"] == 500
    assert json.loads(response["payload"]) == {
        "detail": "catalog failed",
        "error": "recommendation engine failed",
    }
