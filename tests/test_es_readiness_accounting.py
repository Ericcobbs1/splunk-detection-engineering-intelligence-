"""Regression coverage for Enterprise Security readiness and risk-field handling."""

from pathlib import Path

from dei.recommendations.engine import RecommendationEngine

CATALOG_PATH = Path("app/detections/catalog.json")


def _base_fields() -> dict[str, list[str]]:
    return {
        "modular_alerts:risk": [
            "risk_object",
            "risk_object_type",
            "calculated_risk_score",
        ]
    }


def test_es_risk_is_ready_when_es_enabled_and_risk_fields_exist() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        ["modular_alerts:risk"],
        enterprise_security_enabled=True,
        include_unsupported=True,
        fields_by_source=_base_fields(),
    )
    risk = next(item for item in report.recommendations if item.detection_id == "es-risk-score-spike")

    assert risk.readiness == "production_ready"
    assert risk.field_validation == "passed"
    assert report.production_ready_count == 1
    assert report.field_gap_count == 0


def test_es_prerequisite_overrides_field_gap_without_double_counting() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        ["modular_alerts:risk"],
        enterprise_security_enabled=False,
        include_unsupported=True,
        fields_by_source={"modular_alerts:risk": []},
    )
    risk = next(item for item in report.recommendations if item.detection_id == "es-risk-score-spike")

    assert risk.field_validation == "failed"
    assert risk.readiness == "requires_enterprise_security"
    assert report.field_gap_count == 0
    assert report.partial_count == 0
    assert report.unsupported_count == 31


def test_es_field_gap_counts_when_es_is_enabled() -> None:
    report = RecommendationEngine.from_catalog(CATALOG_PATH).recommend(
        ["modular_alerts:risk"],
        enterprise_security_enabled=True,
        include_unsupported=True,
        fields_by_source={"modular_alerts:risk": ["risk_object"]},
    )
    risk = next(item for item in report.recommendations if item.detection_id == "es-risk-score-spike")

    assert risk.readiness == "field_gap"
    assert report.field_gap_count == 1
    assert report.partial_count == 1
