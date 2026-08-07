"""Regression tests for the packaged DEI command center assets."""

from pathlib import Path
from xml.etree import ElementTree

APP_ROOT = Path("app")
VIEW_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "command_center.xml"
NAV_PATH = APP_ROOT / "default" / "data" / "ui" / "nav" / "default.xml"
STATIC_ROOT = APP_ROOT / "appserver" / "static"


def test_command_center_view_is_valid_and_references_assets() -> None:
    root = ElementTree.parse(VIEW_PATH).getroot()
    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert root.attrib["script"] == "command_center.js"
    assert root.attrib["stylesheet"] == "command_center_v2.css"
    assert root.find(".//*[@id='dei-command-center']") is not None
    assert root.find(".//*[@id='dei-overview']") is not None
    assert root.find(".//*[@id='dei-telemetry']") is not None
    assert root.find(".//*[@id='dei-portfolio-section']") is not None
    assert root.find(".//*[@id='dei-coverage-section']") is not None
    assert root.find(".//*[@id='dei-advisor-section']") is not None
    assert root.find(".//*[@id='metric-understanding']") is not None
    assert root.find(".//*[@id='portfolio-total']") is not None
    assert root.find(".//*[@id='portfolio-field-gaps']") is not None
    assert root.find(".//*[@id='portfolio-unverified']") is not None
    source_inventory = root.find(".//*[@id='dei-sources']")
    assert source_inventory is not None
    assert source_inventory.attrib["readonly"] == "readonly"


def test_command_center_is_default_navigation_view() -> None:
    root = ElementTree.parse(NAV_PATH).getroot()
    command_center = root.find("./view[@name='command_center']")
    assert command_center is not None
    assert command_center.attrib["default"] == "true"


def test_command_center_static_assets_are_packaged() -> None:
    javascript = (STATIC_ROOT / "command_center.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "command_center_v2.css").read_text(encoding="utf-8")
    assert "Splunk.util.make_url.apply(" in javascript
    assert '"servicesNS"' in javascript
    assert '"splunk_detection_engineering_intelligence"' in javascript
    assert '"recommendations"' in javascript
    assert '"health"' in javascript
    assert '"X-Splunk-Form-Key"' in javascript
    assert 'Splunk.util.getConfigValue("FORM_KEY")' in javascript
    assert '"search", "jobs", "export"' in javascript
    assert '"splunkjs/mvc/searchmanager"' not in javascript
    assert "| tstats count WHERE index=* earliest=-7d latest=now" in javascript
    assert 'NOT match(index, "^_")' in javascript
    assert 'like(index, "_%")' not in javascript
    assert 'search index=* earliest=-7d latest=now sourcetype=' in javascript
    assert 'search earliest=-7d latest=now sourcetype=' not in javascript
    assert 'output_mode: "json"' in javascript
    assert "parseExportRows" in javascript
    assert '"#metric-understanding"' in javascript
    assert "understood / observed" in javascript
    assert "telemetry understanding" in javascript
    assert "fieldSampleEvents = 200" in javascript
    assert "fieldDiscoveryConcurrency = 4" in javascript
    assert "| fieldsummary" in javascript
    assert "fields_by_source" in javascript
    assert "Profiling fields..." in javascript
    assert "Analysis stopped rather than assuming field readiness." in javascript
    assert "field_gap_count" in javascript
    assert "field_unverified_count" in javascript
    assert "Telemetry discovery timed out after 30 seconds." in javascript
    assert "#dei-analyze" in javascript
    assert "renderPortfolio" in javascript
    assert "renderMitre" in javascript
    assert "dei-field-state" in javascript
    assert ".dei-shell" in stylesheet
    assert "--dei-accent" in stylesheet
    assert ".dei-product-bar" in stylesheet
    assert ".dei-workspace-nav" in stylesheet
    assert ".dei-hero-visual" in stylesheet
    assert ".dei-source-frame" in stylesheet
    assert ".dei-portfolio-grid" in stylesheet
    assert ".dei-recommendation" in stylesheet
    assert ".dei-severity.critical" in stylesheet
    assert "scroll-behavior: smooth" in stylesheet
