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
    assert "detection_workflow_v2.js" in root.attrib["script"].split(",")
    assert "detection_lifecycle_v3.js" in root.attrib["script"].split(",")
    assert "detection_query_generator_v5.js" in root.attrib["script"].split(",")
    assert "dei_detection_standards_v1.js" in root.attrib["script"].split(",")
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
        "workflow-unified-workspace", "workflow-tab-all", "workflow-tab-artifact", "workflow-tab-change-control",
        "workflow-artifact-mode", "lifecycle-action-close",
        "guided-builder-workspace", "builder-detection-select", "builder-generate",
        "detection-generator", "generator-spl", "builder-quality-workspace",
        "builder-run-validation", "builder-validation-resolution",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None


def test_workflow_driver_covers_every_detection_lifecycle_stage() -> None:
    javascript = (STATIC / "detection_workflow_v2.js").read_text(encoding="utf-8")
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
    assert 'requirements:[["Telemetry readiness",false],["MITRE mapping",false],["Observed sourcetype",false]]' in javascript
    assert '$(document).on("dei:detection-draft-generated dei:detection-artifact-saved"' in javascript
    assert "dei:detection-artifact-saved" in javascript
    assert "dei:lifecycle-action-complete" in (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    assert 'String($("#builder-detection-select").val()||"")!==key(item)' in javascript


def test_workflow_keeps_core_builder_and_lifecycle_actions_on_one_page() -> None:
    javascript = (STATIC / "detection_workflow_v2.js").read_text(encoding="utf-8")
    for destination in ("#detection-generator", "#lifecycle-action-center", "detection_action_center?category=telemetry"):
        assert destination in javascript
    for action in (
        "Start detection draft", "Review telemetry actions", "Review SPL and validate", "Open validation handoff",
        "Open peer review", "Open catalog change control", "Record monitoring baseline",
        "Manage monitoring", "Open tuning workspace", "Review retired detection",
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
    home = ElementTree.parse(VIEWS / "dei_home.xml").getroot()
    assert home.find(".//*[@class='dei-product-bar']") is None
    for view_name in ("detection_catalog",):
        root = ElementTree.parse(VIEWS / f"{view_name}.xml").getroot()
        assert root.find(".//a[@href='detection_workflow']") is not None
        assert root.find(".//a[@href='detection_catalog']") is not None
    redirect = ElementTree.parse(VIEWS / "detection_builder.xml").getroot()
    assert "detection_builder_redirect_v1.js" in redirect.attrib["script"].split(",")


def test_guided_workflow_layout_prioritizes_current_action() -> None:
    stylesheet = (STATIC / "detection_workflow_v1.css").read_text(encoding="utf-8")
    for contract in (
        ".dei-workflow-current", ".dei-workflow-stage-rail", ".dei-workflow-focus-grid",
        ".dei-workflow-next-card", ".dei-workflow-requirements",
        "@media(max-width:1100px)", "@media(max-width:700px)",
    ):
        assert contract in stylesheet


def test_workflow_uses_readable_progressive_disclosure_without_removing_controls() -> None:
    root = ElementTree.parse(VIEWS / "detection_workflow.xml").getroot()
    stylesheet = (STATIC / "detection_workflow_v1.css").read_text(encoding="utf-8")
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    assert root.find(".//details[@id='builder-quality-workspace']") is not None
    for element_id in ("generator-es-output", "lifecycle-action-evidence", "lifecycle-action-history"):
        assert root.find(f".//details//*[@id='{element_id}']") is not None
    assert "Gate guidance and ownership" in lifecycle
    assert ".dei-workflow-disclosure" in stylesheet
    assert "font-size:14px;line-height:1.55" in stylesheet
    assert "grid-template-columns:minmax(0,1fr)" in stylesheet
    assert "@media(min-width:1600px)" in stylesheet


def test_guided_workflow_uses_one_compact_workspace_selector() -> None:
    root = ElementTree.parse(VIEWS / "detection_workflow.xml").getroot()
    navigation = root.find(".//nav[@class='dei-workspace-nav']")
    assert navigation is not None
    links = [(link.text, link.attrib["href"]) for link in navigation.findall("a")]
    assert links == [
        ("Home", "dei_home"), ("Discover", "command_center"),
        ("Coverage", "mitre_coverage"), ("Build", "detection_workflow"),
        ("Operate", "detection_catalog"),
    ]
    javascript = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    assert 'root.is("#dei-guided-detection-page")' in javascript


def test_action_center_is_functionally_owned_by_guided_workflow() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    workflow = (STATIC / "detection_workflow_v2.js").read_text(encoding="utf-8")
    generator = (STATIC / "detection_query_generator_v5.js").read_text(encoding="utf-8")
    operations = ElementTree.parse(VIEWS / "detection_operations.xml").getroot()
    guided = ElementTree.parse(VIEWS / "detection_workflow.xml").getroot()
    assert operations.find(".//*[@id='lifecycle-action-center']") is None
    assert guided.find(".//*[@id='lifecycle-action-center']") is not None
    action_center = guided.find(".//*[@id='lifecycle-action-center']")
    assert action_center.attrib["role"] == "tabpanel"
    assert "aria-modal" not in action_center.attrib
    assert guided.find(".//*[@id='workflow-unified-workspace']") is not None
    assert "function activateWorkspacePanel(panel)" in lifecycle
    assert "dei:workflow-detection-selected" in lifecycle
    assert "dei:workflow-detection-selected" in workflow
    assert "dei:lifecycle-records-updated" in lifecycle
    assert "dei:lifecycle-records-updated" in workflow
    assert "generatedDrafts" in lifecycle
    assert "draftStarted" in lifecycle
    assert "opensActionWindow" in lifecycle
    assert "openActionWindow" in lifecycle
    assert "closeActionWindow" in lifecycle
    assert '$("#workflow-primary-action").on("click"' in lifecycle
    assert 'activateWorkspacePanel("artifact")' in lifecycle
    assert 'activateWorkspacePanel("change-control")' in lifecycle
    assert "dei:detection-draft-reset" in lifecycle
    assert "dei:detection-draft-generated" in lifecycle
    assert "dei:detection-draft-reset" in generator
    assert "dei:detection-draft-generated" in generator
    assert '$(document).on("dei:artifact-inspection-requested"' in generator
    assert 'artifact = record ? $.extend(true, {}, record)' in generator
    assert 'window.location.href="detection_catalog?detection="' in lifecycle
    assert 'action:"open_catalog"' in lifecycle
    for action in (
        "submit_review", "approve_review", "return_draft", "record_health",
        "start_tuning", "retire",
    ):
        assert f'action==="{action}"' in lifecycle


def test_selected_detection_uses_one_in_place_governed_workspace() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    workflow = (STATIC / "detection_workflow_v2.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "detection_workflow_v1.css").read_text(encoding="utf-8")
    assert 'activateWorkspacePanel("artifact")' in lifecycle
    assert 'activateWorkspacePanel("change-control")' in lifecycle
    assert "dei-lifecycle-modal-open" not in lifecycle
    assert "lifecycle-action-backdrop" not in lifecycle
    assert 'window.location.href="detection_workflow?detection="+encodeURIComponent(recordKey(record))' not in lifecycle
    assert 'href:"#lifecycle-action-center"' in workflow
    assert "function applyArtifactMode(stage,record)" in workflow
    assert '["peer_review","catalog","production","monitoring","retired"]' in workflow
    assert ".dei-unified-workspace" in stylesheet
    assert ".dei-workspace-tabs" in stylesheet
    assert 'activateWorkspacePanel("all")' in lifecycle
    assert 'data-active-panel="all"' in stylesheet


def test_tuning_opens_an_editable_version_with_visible_guidance() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    view = (VIEWS / "detection_workflow.xml").read_text(encoding="utf-8")
    assert 'action==="start_tuning"' in lifecycle
    assert 'actionError("Document the tuning objective before opening a new editable version."' in lifecycle
    assert 'pendingWorkspaceAction==="start_tuning"' in lifecycle
    assert 'activateWorkspacePanel("all")' in lifecycle
    assert 'Tuning version opened. Revise the editable artifact, then run fresh validation.' in lifecycle
    assert 'id="lifecycle-inline-error"' in lifecycle
    assert "Full workflow" in view


def test_failed_validation_can_edit_spl_without_page_scroll_lock() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    workflow = (STATIC / "detection_workflow_v2.js").read_text(encoding="utf-8")
    generator = (STATIC / "detection_query_generator_v5.js").read_text(encoding="utf-8")
    assert 'stage==="testing"&&validation.status==="passed"' in workflow
    assert "function applyArtifactMode(stage,record)" in workflow
    assert '$(document).trigger("dei:edit-spl-requested")' in generator
    assert 'editor[0].focus({preventScroll:true})' in generator
    assert 'pane.scrollTop(Math.max(0,editor.position().top-80))' in generator
    assert '$("#generator-spl")[0].scrollIntoView' not in generator
    assert '$(document).on("dei:edit-spl-requested"' in lifecycle
    assert 'activateWorkspacePanel("artifact")' in lifecycle


def test_all_lifecycle_controls_are_non_submitting_and_peer_review_is_guarded() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    assert lifecycle.count('<button type="button"') >= 7
    assert 'type="button" class="primary next" data-action="' in lifecycle
    assert 'type="button" class="previous" data-action="' in lifecycle
    assert 'type="button" class="restart" data-action="restart_recommendation"' in lifecycle
    assert 'type="button" class="primary" data-action="open_builder"' in lifecycle
    assert 'type="button" class="danger" data-action="retire"' in lifecycle
    assert 'button[data-action]' in lifecycle
    assert "event.preventDefault(); event.stopPropagation();" in lifecycle
    assert 'if ($(this).prop("disabled")) { return; }' in lifecycle
    assert 'actionError("Summarize the validation evidence' in lifecycle
    assert 'actionError("Document why this version is safe, scoped, and operationally actionable' in lifecycle
    assert 'transition(record,"peer_review","submitted_for_review"' in lifecycle
    assert 'Store.appendHistory(approved,"peer_review_approved"' in lifecycle


def test_detection_usability_guidance_and_es_handoff_are_packaged() -> None:
    root = ElementTree.parse(VIEWS / "detection_workflow.xml").getroot()
    scripts = root.attrib["script"].split(",")
    styles = root.attrib["stylesheet"].split(",")
    xml = (VIEWS / "detection_workflow.xml").read_text(encoding="utf-8")
    usability = (STATIC / "dei_detection_usability_v1.js").read_text(encoding="utf-8")
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    assert "dei_detection_usability_v1.js" in scripts
    assert "dei_detection_usability_v1.css" in styles
    assert "Deploy to Enterprise Security" in xml
    assert "Configure → Content → Content Management" in xml
    assert 'field.style.height=Math.max(240,field.scrollHeight+4)+"px"' in usability
    assert 'resize:vertical' in (STATIC / "dei_detection_usability_v1.css").read_text(encoding="utf-8")
    assert "lifecycle-review-period" in lifecycle
    assert "review_period:reviewPeriod" in lifecycle
    assert "Settings → Searches, Reports, and Alerts" in usability
