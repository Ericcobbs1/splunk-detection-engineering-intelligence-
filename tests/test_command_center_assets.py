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
    assert root.attrib["script"] == "command_center.js,mitre_coverage.js"
    assert root.attrib["stylesheet"] == "command_center_v2.css,mitre_coverage.css"
    for element_id in (
        "dei-command-center", "dei-overview", "dei-telemetry", "dei-portfolio-section",
        "dei-coverage-section", "dei-advisor-section", "dei-mitre-section", "mitre-swimlane",
        "protection-title", "protection-summary", "protection-outcomes", "metric-understanding",
        "portfolio-total", "portfolio-field-gaps", "portfolio-unverified",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None
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
    mitre_js = (STATIC_ROOT / "mitre_coverage.js").read_text(encoding="utf-8")
    mitre_css = (STATIC_ROOT / "mitre_coverage.css").read_text(encoding="utf-8")
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
    assert 'search index=* earliest=-7d latest=now sourcetype=' in javascript
    assert 'output_mode: "json"' in javascript
    assert "fieldDiscoveryConcurrency = 6" in javascript
    assert "fieldSearchTimeoutMs = 12000" in javascript
    assert "fieldDiscoveryTimeoutMs = 90000" in javascript
    assert "| fieldsummary" in javascript
    assert "fields_by_source" in javascript
    assert "Profiling fields 0/" in javascript
    assert "Field profiling reached its 90-second ceiling" in javascript
    assert "Telemetry inventory timed out after 20 seconds." in javascript
    assert "renderPortfolio" in javascript
    assert "renderMitre" in javascript
    assert ".dei-shell" in stylesheet
    assert "--dei-accent" in stylesheet
    assert ".dei-product-bar" in stylesheet
    assert ".dei-recommendation" in stylesheet
    assert "scroll-behavior: smooth" in stylesheet
    assert 'TA0006", "Credential Access"' in mitre_js
    assert 'TA0010", "Exfiltration"' in mitre_js
    assert '"T1110.003"' in mitre_js
    assert '"T1098"' in mitre_js
    assert "DEIRecommendationReport" in mitre_js
    assert "ajaxSuccess" in mitre_js
    assert "renderSelection" in mitre_js
    assert ".dei-mitre-swimlane" in mitre_css
    assert ".dei-mitre-tactic.covered" in mitre_css
    assert ".dei-protection-grid" in mitre_css
    assert ".dei-recommendation.selected" in mitre_css
