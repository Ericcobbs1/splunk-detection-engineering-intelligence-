"""Tests for telemetry intelligence analysis and REST handling."""

import json
from pathlib import Path

from dei.api.telemetry_handler import TelemetryHandler
from dei.knowledgepacks.loader import KnowledgePackLoader
from dei.telemetry.analyzer import TelemetryAnalyzer

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "app" / "schemas" / "knowledge-pack.schema.json"
PACK_ROOT = REPO_ROOT / "app" / "knowledgepacks"


def test_analyzer_matches_sources_to_packs_and_capabilities() -> None:
    packs = KnowledgePackLoader(SCHEMA_PATH).load_all(PACK_ROOT)

    analysis = TelemetryAnalyzer().analyze(
        ("aws:cloudtrail", "XmlWinEventLog:Security", "unknown:source"),
        packs,
    )

    assert analysis.matched_packs == ("ai", "aws", "windows")
    assert analysis.matched_sources == ("XmlWinEventLog:Security", "aws:cloudtrail")
    assert analysis.unmatched_sources == ("unknown:source",)
    assert "aws.iam" in analysis.enabled_capabilities
    assert "windows.authentication" in analysis.enabled_capabilities
    assert "ai.shadow_usage" in analysis.enabled_capabilities
    assert analysis.source_coverage_percent > 0


def test_analyzer_normalizes_duplicates_and_blank_sources() -> None:
    packs = KnowledgePackLoader(SCHEMA_PATH).load_all(PACK_ROOT)

    analysis = TelemetryAnalyzer().analyze(
        ("aws:cloudtrail", " aws:cloudtrail ", ""),
        packs,
    )

    assert analysis.observed_sources == ("aws:cloudtrail",)
    assert analysis.matched_sources == ("aws:cloudtrail",)


def test_telemetry_handler_returns_analysis() -> None:
    handler = TelemetryHandler()

    response = handler.handle(
        json.dumps({"method": "POST", "sources": ["aws:cloudtrail"]})
    )
    payload = response["payload"]

    assert response["status"] == 200
    assert payload["matched_sources"] == ["aws:cloudtrail"]
    assert payload["matched_packs"] == ["ai", "aws"]


def test_telemetry_handler_validates_sources() -> None:
    response = TelemetryHandler().handle(
        json.dumps({"method": "POST", "sources": "aws:cloudtrail"})
    )

    assert response["status"] == 400
    assert response["payload"] == {
        "error": "sources must be an array of strings"
    }


def test_telemetry_handler_rejects_get() -> None:
    response = TelemetryHandler().handle(json.dumps({"method": "GET", "sources": []}))

    assert response["status"] == 405
