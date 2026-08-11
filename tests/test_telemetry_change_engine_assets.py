"""Contracts for versioned telemetry baselines and detection-impact analysis."""

from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
STATIC = APP / "appserver" / "static"


def test_scan_engine_persists_immutable_history_and_latest_snapshot() -> None:
    collections = (APP / "default" / "collections.conf").read_text(encoding="utf-8")
    metadata = (APP / "metadata" / "default.meta").read_text(encoding="utf-8")
    engine = (STATIC / "dei_environment_scan_v1.js").read_text(encoding="utf-8")
    assert "[dei_scan_history]" in collections
    assert "[collections/dei_scan_history]" in metadata
    assert 'historyCollection="dei_scan_history"' in engine
    assert "fields_by_source:fieldsBySource||{}" in engine
    assert "fields_by_scope:fieldsByScope||{}" in engine
    assert "scoped_inventory:scopedInventory" in engine
    assert "Profiling telemetry route" in engine
    assert 'search index="' in engine
    assert "_key:snapshot.assessment_id" in engine
    assert "writeRecord(historyCollection,history)" in engine
    assert 'writeRecord(scanCollection,snapshot)' in engine


def test_change_engine_classifies_source_schema_volume_and_detection_impact() -> None:
    engine = (STATIC / "dei_environment_scan_v1.js").read_text(encoding="utf-8")
    for contract in (
        "new_sources", "removed_sources", "field_changes", "volume_changes",
        "new_routes", "removed_routes", "detection_changes", "newly_buildable", "readiness_regressions",
        "baseline_assessment_id", "action_required", "change_count",
    ):
        assert contract in engine
    assert 'previous.readiness!=="production_ready"&&next.readiness==="production_ready"' in engine
    assert 'previous.readiness==="production_ready"&&next.readiness!=="production_ready"' in engine
    assert "Math.abs(change)>=50" in engine
    assert "routeVolumes" in engine
    assert "removed_fields.length>0" in engine
    assert "baseline.fields_by_scope||baseline.fields_by_source" in engine


def test_command_center_uses_the_shared_scan_engine() -> None:
    command_center = (STATIC / "command_center.js").read_text(encoding="utf-8")
    assert "window.DEIEnvironmentScan.run" in command_center
    assert '$(document).on("dei:scan-progress"' in command_center
    assert '$(document).on("dei:environment-refreshed"' in command_center


def test_environment_intelligence_exposes_proven_change_evidence() -> None:
    view = ElementTree.parse(
        APP / "default" / "data" / "ui" / "views" / "environment_insights.xml"
    ).getroot()
    assert "dei_telemetry_change_v1.css" in view.attrib["stylesheet"].split(",")
    for element_id in (
        "dei-telemetry-change-section", "dei-change-baseline-state",
        "dei-change-new-sources", "dei-change-removed-sources",
        "dei-change-schema", "dei-change-buildable", "dei-change-regressions",
        "dei-telemetry-change-findings",
    ):
        assert view.find(f".//*[@id='{element_id}']") is not None
    renderer = (STATIC / "environment_intelligence_v2.js").read_text(encoding="utf-8")
    assert 'CHANGE_KEY = "dei.latestScanChanges"' in renderer
    assert "requires telemetry-family mapping and field review" in renderer
    assert "requires revalidation" in renderer
