"""Contracts for the simplified, detection-specific workflow driver."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
VIEWS = APP / "default" / "data" / "ui" / "views"
STATIC = APP / "appserver" / "static"


def test_guided_workflow_is_a_packaged_dedicated_page() -> None:
    root = ElementTree.parse(VIEWS / "detection_workflow.xml").getroot()
    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert "detection_workflow_v1.js" in root.attrib["script"].split(",")
    assert "detection_lifecycle_v2.js" in root.attrib["script"].split(",")
    assert "detection_workflow_v1.css" in root.attrib["stylesheet"].split(",")
    for element_id in (
        "dei-guided-detection-page", "workflow-data-status", "workflow-detection-select",
        "workflow-empty", "workflow-driver", "workflow-stage-count",
        "workflow-detection-title", "workflow-current-stage", "workflow-stage-rail",
        "workflow-next-title", "workflow-next-explanation", "workflow-requirements",
        "workflow-primary-action", "workflow-action-note", "workflow-advanced-evidence",
        "lifecycle-action-center", "lifecycle-action-title", "lifecycle-action-position",
        "lifecycle-action-state", "lifecycle-action-summary", "lifecycle-action-feedback",
        "lifecycle-action-progress", "lifecycle-action-evidence", "lifecycle-action-fields",
        "lifecycle-action-buttons", "lifecycle-action-history",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None


def test_workflow_driver_covers_every_detection_lifecycle_stage() -> None:
    javascript = (STATIC / "detection_workflow_v1.js").read_text(encoding="utf-8")
    for stage in (
        "recommendation", "draft", "testing", "peer_review", "catalog",
        "production", "monitoring", "tuning", "retired",
    ):
        assert f'id:"{stage}"' in javascript
        assert f"{stage}:{{" in javascript
    assert 'aria-current="step"' in javascript
    assert "You are here" in javascript
    assert '"Stage "+(current+1)+" of "+STAGES.length' in javascript
    assert '"Current stage: "+label(stage)' in javascript


def test_workflow_routes_one_primary_action_to_the_owning_workspace() -> None:
    javascript = (STATIC / "detection_workflow_v1.js").read_text(encoding="utf-8")
    for destination in (
        "detection_builder?detection=", "detection_operations?detection=",
        "detection_catalog?detection=", "detection_action_center?category=telemetry",
    ):
        assert destination in javascript
    for action in (
        "Start detection draft", "Review telemetry actions", "Open Builder and validate", "Open validation handoff",
        "Open peer review", "Open catalog enablement", "Record monitoring baseline",
        "Manage monitoring", "Open Builder for tuning", "Review retired detection",
    ):
        assert action in javascript
    assert "workflow-primary-action" in javascript
    assert "workflow-requirements" in javascript
    assert "View advanced evidence" in ElementTree.tostring(
        ElementTree.parse(VIEWS / "detection_workflow.xml").getroot(), encoding="unicode"
    )


def test_guided_workflow_is_primary_but_advanced_workspaces_remain_available() -> None:
    nav = ElementTree.parse(APP / "default/data/ui/nav/default.xml").getroot()
    assert nav.find(".//view[@name='detection_workflow']") is not None
    home = ElementTree.tostring(ElementTree.parse(VIEWS / "dei_home.xml").getroot(), encoding="unicode")
    assert 'href="detection_workflow"' in home
    assert "Guided Detection Workflow" in home
    for view_name in ("detection_lifecycle", "detection_operations", "detection_catalog", "detection_builder"):
        root = ElementTree.parse(VIEWS / f"{view_name}.xml").getroot()
        assert root.find(".//option[@value='detection_workflow']") is not None


def test_guided_workflow_layout_prioritizes_current_action() -> None:
    stylesheet = (STATIC / "detection_workflow_v1.css").read_text(encoding="utf-8")
    for contract in (
        ".dei-workflow-current", ".dei-workflow-stage-rail", ".dei-workflow-focus-grid",
        ".dei-workflow-next-card", ".dei-workflow-requirements",
        "@media(max-width:1100px)", "@media(max-width:700px)",
    ):
        assert contract in stylesheet


def test_action_center_is_functionally_owned_by_guided_workflow() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v2.js").read_text(encoding="utf-8")
    workflow = (STATIC / "detection_workflow_v1.js").read_text(encoding="utf-8")
    operations = ElementTree.parse(VIEWS / "detection_operations.xml").getroot()
    guided = ElementTree.parse(VIEWS / "detection_workflow.xml").getroot()
    assert operations.find(".//*[@id='lifecycle-action-center']") is None
    assert guided.find(".//*[@id='lifecycle-action-center']") is not None
    assert 'href="detection_workflow?detection=' in lifecycle
    assert "dei:workflow-detection-selected" in lifecycle
    assert "dei:workflow-detection-selected" in workflow
    assert "dei:lifecycle-records-updated" in lifecycle
    assert "dei:lifecycle-records-updated" in workflow
    for action in (
        "submit_review", "approve_review", "return_draft", "record_health",
        "start_tuning", "retire",
    ):
        assert f'action==="{action}"' in lifecycle
