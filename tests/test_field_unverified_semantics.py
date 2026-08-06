"""Regression tests for field validation when recent telemetry cannot be sampled."""

from pathlib import Path

from dei.recommendations.engine import RecommendationEngine

CATALOG_PATH = Path("app/detections/catalog.json")


def test_present_source_without_field_sample_is_unverified_not_field_gap() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        ["aws:cloudtrail"],
        include_unsupported=True,
        fields_by_source={},
    )

    cloudtrail = next(
        item for item in report.recommendations
        if item.detection_id == "aws-cloudtrail-disabled"
    )
    assert cloudtrail.readiness == "field_unverified"
    assert cloudtrail.field_validation == "unverified"
    assert cloudtrail.unverified_field_sources == ("aws:cloudtrail",)
    assert cloudtrail.missing_fields == {}
    assert report.field_unverified_count == 3
    assert report.field_gap_count == 0


def test_sampled_source_with_missing_required_fields_is_confirmed_field_gap() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        ["aws:cloudtrail"],
        include_unsupported=True,
        fields_by_source={"aws:cloudtrail": ["host", "source"]},
    )

    cloudtrail = next(
        item for item in report.recommendations
        if item.detection_id == "aws-cloudtrail-disabled"
    )
    assert cloudtrail.readiness == "field_gap"
    assert cloudtrail.field_validation == "failed"
    assert cloudtrail.unverified_field_sources == ()
    assert report.field_gap_count == 3
    assert report.field_unverified_count == 0
