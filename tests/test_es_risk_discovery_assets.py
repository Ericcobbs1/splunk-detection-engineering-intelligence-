"""Regression checks for Enterprise Security risk profiling in the command center."""

from pathlib import Path

COMMAND_CENTER = Path("app/appserver/static/command_center.js")
CATALOG = Path("app/detections/catalog.json")


def test_command_center_profiles_risk_data_model() -> None:
    javascript = COMMAND_CENTER.read_text(encoding="utf-8")

    assert "| from datamodel:Risk.All_Risk" in javascript
    assert 'source.toLowerCase() === "modular_alerts:risk"' in javascript
    assert '$("#dei-es-enabled").prop("checked", true)' in javascript
    assert "Enterprise Security " in javascript


def test_catalog_accepts_authoritative_calculated_risk_score() -> None:
    catalog = CATALOG.read_text(encoding="utf-8")

    assert '"calculated_risk_score","risk_score"' in catalog
