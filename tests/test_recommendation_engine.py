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


def test_recommendations_explain_partial_ai_coverage() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        ["ai:gateway"], include_unsupported=True
    )
    sensitive = next(
        item for item in report.recommendations
        if item.detection_id == "ai-sensitive-data-exposure"
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


def test_production_like_lab_baseline_preserves_legacy_readiness() -> None:
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
    assert report.unsupported_count == 13

    readiness = {item.detection_id: item.readiness for item in report.recommendations}
    for detection_id in (
        "ai-sensitive-data-exposure",
        "aws-cloudtrail-disabled",
        "aws-iam-policy-escalation",
        "windows-password-spray",
        "windows-kerberoasting",
        "aws-s3-public-access",
        "windows-powershell-encoded",
        "ai-model-admin-change",
    ):
        assert readiness[detection_id] == "production_ready"
    assert readiness["ai-shadow-usage"] == "unsupported"


def test_eleven_source_lab_enables_identity_endpoint_and_linux_packs() -> None:
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
    assert report.production_ready_count == 15
    assert report.partial_count == 0
    assert report.unsupported_count == 6
    assert report.unmapped_sources == ()


def test_full_enterprise_lab_reaches_full_catalog_readiness() -> None:
    observed_sources = [
        "XmlWinEventLog:Security",
        "crowdstrike:events:sensor",
        "aws:cloudtrail",
        "zscaler:web",
        "OktaIM2:log",
        "linux_secure",
        "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
        "gcp:audit:vertexai",
        "dlp",
        "azure:openai:diagnostic",
        "ai:gateway",
        "WinEventLog:Security",
        "access_combined",
        "cisco:asa",
        "otx:indicator",
        "modular_alerts:risk",
        "stash",
        "cisco:ios",
        "cdcc:edr",
        "stream:dns",
        "json",
        "otx:pulse",
    ]
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        observed_sources,
        enterprise_security_enabled=True,
        include_unsupported=True,
    )
    assert report.observed_source_count == 22
    assert report.production_ready_count == 21
    assert report.partial_count == 0
    assert report.unsupported_count == 0
    assert report.unmapped_sources == ("stash", "json")

    ready_packs = {item.pack_id for item in report.recommendations}
    assert {
        "windows", "aws", "ai", "identity", "endpoint", "linux",
        "network", "threat_intel", "enterprise_security", "web",
    } <= ready_packs


def test_unsupported_detections_are_hidden_by_default() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend([])
    assert report.recommendations == ()
    assert report.unsupported_count == 21


def test_invalid_catalog_is_rejected(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    catalog.write_text('[{"id":"broken"}]', encoding="utf-8")
    with pytest.raises(RecommendationError, match="missing"):
        RecommendationEngine.from_catalog(catalog)
