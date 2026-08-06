"""Tests for the data-driven DEI recommendation engine."""

from pathlib import Path

import pytest

from dei.recommendations.engine import RecommendationEngine, RecommendationError

CATALOG_PATH = Path("app/detections/catalog.json")


def test_recommendations_rank_ready_cloud_detections() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(["aws:cloudtrail"])

    assert report.production_ready_count == 3
    assert report.partial_count == 1
    assert report.recommendations[0].detection_id == "aws-cloudtrail-disabled"
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
    assert report.production_ready_count == 3


def test_unsupported_detections_are_hidden_by_default() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend([])

    assert report.recommendations == ()
    assert report.unsupported_count == 9


def test_invalid_catalog_is_rejected(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    catalog.write_text('[{"id":"broken"}]', encoding="utf-8")

    with pytest.raises(RecommendationError, match="missing"):
        RecommendationEngine.from_catalog(catalog)
