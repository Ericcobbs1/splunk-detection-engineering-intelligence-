"""Regression contracts for the dedicated Detection Action Center."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
VIEWS = APP / "default" / "data" / "ui" / "views"
STATIC = APP / "appserver" / "static"


def test_action_center_is_a_packaged_dedicated_workspace() -> None:
    root = ElementTree.parse(VIEWS / "detection_action_center.xml").getroot()
    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert "detection_action_center_v1.js" in root.attrib["script"].split(",")
    assert "detection_action_center_v1.css" in root.attrib["stylesheet"].split(",")
    for element_id in (
        "dei-action-center-page", "action-count-all", "action-count-critical",
        "action-count-telemetry", "action-count-validation", "action-count-monitoring",
        "action-search", "action-severity", "action-category", "action-readiness",
        "action-reset-filters", "action-refresh", "action-findings", "action-empty",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None


def test_home_keeps_operational_findings_off_the_landing_page() -> None:
    home = ElementTree.parse(VIEWS / "dei_home.xml").getroot()
    action = home.find(".//*[@id='dei-home-health-action']")
    assert action is None
    assert home.find(".//*[@id='dei-home-health-actions']") is None
    javascript = (STATIC / "dei_workspace_layout_v10.js").read_text(encoding="utf-8")
    assert '.attr("href","detection_action_center")' in javascript
    assert '#dei-home-health-actions-close' not in javascript


def test_action_center_prioritizes_real_pipeline_evidence() -> None:
    javascript = (STATIC / "detection_action_center_v1.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "detection_action_center_v1.css").read_text(encoding="utf-8")
    for contract in (
        "dei.latestRecommendationReport", "DEILifecycleStore", "field_unverified",
        'validation.status==="failed"', 'health==="degraded"', 'health==="failing"',
        "detection_workflow?detection=", "detection_workflow?detection=",
        "command_center#dei-telemetry", "highest priority first", "URLSearchParams",
    ):
        assert contract in javascript
    for contract in (
        ".dei-action-summary", ".dei-action-filters", ".dei-action-finding",
        '[data-severity="critical"]', "@media(max-width:1050px)",
    ):
        assert contract in stylesheet


def test_action_center_exposes_filters_and_direct_remediation_actions() -> None:
    javascript = (STATIC / "detection_action_center_v1.js").read_text(encoding="utf-8")
    for contract in (
        "#action-search,#action-severity,#action-category,#action-readiness",
        "[data-action-summary]", "#action-reset-filters", "#action-refresh",
        "Repair and validate", "Review health evidence", "Record health baseline",
        "Build engineering draft", "Resolve telemetry evidence",
    ):
        assert contract in javascript
