from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
STATIC = APP / "appserver" / "static"
VIEWS = APP / "default" / "data" / "ui" / "views"


def test_detection_standards_engine_is_packaged_and_integrated() -> None:
    engine = (STATIC / "dei_detection_standards_v1.js").read_text(encoding="utf-8")
    builder = ElementTree.parse(VIEWS / "detection_workflow.xml").getroot()
    generator = (STATIC / "detection_query_generator_v2.js").read_text(encoding="utf-8")
    assert "DEIDetectionStandards" in engine
    for contract in ("index\\s*=\\s*\\*", "command.transaction", "command.join", "schedule.window", "mitre.missing", "context.entity", "es.risk-object"):
        assert contract in engine
    assert "dei_detection_standards_v1.js" in builder.attrib["script"]
    for element_id in ("builder-quality-workspace", "builder-quality-score", "builder-quality-state", "builder-quality-dimensions", "builder-quality-issues"):
        assert builder.find(f".//*[@id='{element_id}']") is not None
    assert "renderStandards" in generator
    assert "Quality gate blocked validation" in generator


def test_detection_health_is_a_real_workspace() -> None:
    view = ElementTree.parse(VIEWS / "detection_health.xml").getroot()
    javascript = (STATIC / "detection_health_v1.js").read_text(encoding="utf-8")
    nav = ElementTree.parse(APP / "default" / "data" / "ui" / "nav" / "default.xml").getroot()
    assert view.attrib["script"].startswith("dei_lifecycle_store_v1.js,")
    for element_id in ("dei-detection-health-page", "health-refresh", "health-managed", "health-healthy", "health-attention", "health-failed", "health-unvalidated", "health-filter", "health-state", "health-records"):
        assert view.find(f".//*[@id='{element_id}']") is not None
    assert nav.find(".//view[@name='detection_health']") is not None
    for contract in ("DEILifecycleStore", "validation.status", "health_evidence", "detection_workflow?detection=", "Run intelligence scan"):
        assert contract in javascript


def test_accessible_readability_baseline_is_packaged() -> None:
    css = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    for contract in ("-webkit-font-smoothing:antialiased", "font-size:max(14px,1em)", "text-shadow:none", ":focus-visible", ".dei-health-record", ".dei-quality-workspace"):
        assert contract in css
