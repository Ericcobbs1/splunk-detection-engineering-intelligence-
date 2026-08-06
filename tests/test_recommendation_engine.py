"""Tests for the data-driven DEI recommendation engine."""

from pathlib import Path

import pytest

from dei.recommendations.engine import RecommendationEngine, RecommendationError

CATALOG_PATH = Path("app/detections/catalog.json")


def test_recommendations_rank_ready_cloud_detections() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(["aws:cloudtrail"])

    assert report.production_ready_count == 3
    assert report.partial_count == 1
    assert report.recommendations[0].detection_id == "aws-iam-policy-escalation"
    assert report.recommendations[0].readiness == "production_ready"
    assert report.recommendations[0].score == 100
    assert report.recommendations[0].missing_sources == ()


def test_recommendations_explain_partial_ai_coverage() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        ["ai:gateway"], include_unsupported=True
    )

    sensitive = next(
        item for item in report.recommendations if item.detection_id == "ai-sensitive-data-exposure"
    )
    assert sensitive.readiness == "partial"
    assert sensitive.observed_sources == ("ai:gateway",)
    assert sensitive.missing_sources == ("dlp",)


def test_recommendations_are_case_insensitive_and_deduplicated() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        ["AWS:CLOUDTRAIL", "aws:cloudtrail", ""]
    )

    assert report.observed_source_count == 1
    assert report.normalized_source_count == 1
    assert report.production_ready_count == 3


def test_production_like_lab_baseline_has_expected_readiness() -> None:
    observed_sources = [
        "XmlWinEventLog:Security",
        "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
        "aws:cloudtrail",
        "ai:gateway",
        "dlp",
        "azure:openai:diagnostic",
        "gcp:audit:vertexai",
    ]

    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        observed_sources,
        enterprise_security_enabled=True,
        include_unsupported=True,
    )

    assert report.observed_source_count == 7
    assert report.production_ready_count == 8
    assert report.partial_count == 0
    assert report.unsupported_count == 1

    readiness = {item.detection_id: item.readiness for item in report.recommendations}
    assert readiness == {
        "ai-sensitive-data-exposure": "production_ready",
        "aws-cloudtrail-disabled": "production_ready",
        "aws-iam-policy-escalation": "production_ready",
        "windows-password-spray": "production_ready",
        "windows-kerberoasting": "production_ready",
        "aws-s3-public-access": "production_ready",
        "windows-powershell-encoded": "production_ready",
        "ai-model-admin-change": "production_ready",
        "ai-shadow-usage": "unsupported",
    }

    shadow_ai = next(
        item for item in report.recommendations if item.detection_id == "ai-shadow-usage"
    )
    assert shadow_ai.missing_sources == ("proxy",)


def test_full_lab_inventory_normalizes_vendor_sources_and_reaches_full_catalog() -> None:
    observed_sources = [
        "XmlWinEventLog:Security",
        "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
        "aws:cloudtrail",
        "zscaler:web",
        "OktaIM2:log",
        "crowdstrike:events:sensor",
        "linux_secure",
        "azure:openai:diagnostic",
        "gcp:audit:vertexai",
        "ai:gateway",
        "dlp",
    ]

    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        observed_sources,
        enterprise_security_enabled=True,
        include_unsupported=True,
    )

    assert report.observed_source_count == 11
    assert report.normalized_source_count == 11
    assert report.production_ready_count == 9
    assert report.partial_count == 0
    assert report.unsupported_count == 0
    assert report.unmapped_sources == ()

    mappings = {
        item.observed_source: item.canonical_source for item in report.source_mappings
    }
    assert mappings["zscaler:web"] == "proxy"
    assert mappings["OktaIM2:log"] == "identity.authentication"
    assert mappings["crowdstrike:events:sensor"] == "endpoint.edr"
    assert mappings["linux_secure"] == "linux.authentication"


def test_unsupported_detections_are_hidden_by_default() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend([])

    assert report.recommendations == ()
    assert report.unsupported_count == 9


def test_invalid_catalog_is_rejected(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    catalog.write_text('[{"id":"broken"}]', encoding="utf-8")

    with pytest.raises(RecommendationError, match="missing"):
        RecommendationEngine.from_catalog(catalog)
