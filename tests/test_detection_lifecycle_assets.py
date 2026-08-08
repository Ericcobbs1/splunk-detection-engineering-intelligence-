"""Regression tests for the Detection Engineering Lifecycle workspace."""

from pathlib import Path
from xml.etree import ElementTree

APP_ROOT = Path("app")
VIEW_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "detection_lifecycle.xml"
BUILDER_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "detection_builder.xml"
NAV_PATH = APP_ROOT / "default" / "data" / "ui" / "nav" / "default.xml"
STATIC_ROOT = APP_ROOT / "appserver" / "static"
FRAMEWORK_PATH = Path("docs") / "DETECTION_ENGINEERING_FRAMEWORK.md"


def test_detection_lifecycle_view_is_valid_and_packaged() -> None:
    root = ElementTree.parse(VIEW_PATH).getroot()
    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert root.attrib["script"] == "dei_lifecycle_store_v1.js,detection_lifecycle_v2.js"
    assert root.attrib["stylesheet"] == (
        "command_center_v2.css,dei_visual_polish_v1.css,detection_lifecycle_v1.css"
    )
    for element_id in (
        "dei-lifecycle-page", "lifecycle-data-status", "lifecycle-analysis-age",
        "lifecycle-maturity-percent", "life-sources", "life-opportunities",
        "life-mitre-mapped", "life-field-verified", "life-telemetry-ready",
        "life-spl-generated", "stage-discover", "stage-profile", "stage-qualify",
        "stage-recommend", "stage-design", "stage-generate", "stage-validate",
        "state-draft", "state-testing", "state-review", "state-production",
        "state-monitoring", "state-tuning", "state-retired",
        "lifecycle-search", "lifecycle-readiness", "lifecycle-stage",
        "lifecycle-queue-count", "lifecycle-work-queue", "lifecycle-workspace-menu",
        "lifecycle-reset-filters", "lifecycle-action-center", "lifecycle-action-title",
        "lifecycle-action-state", "lifecycle-action-summary", "lifecycle-action-feedback",
        "lifecycle-action-evidence", "lifecycle-action-fields", "lifecycle-action-buttons",
        "lifecycle-action-history",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None


def test_detection_lifecycle_is_registered_in_navigation() -> None:
    root = ElementTree.parse(NAV_PATH).getroot()
    assert root.find(".//view[@name='detection_lifecycle']") is not None
    assert root.find(".//view[@name='detection_builder']") is not None


def test_detection_builder_is_valid_and_owns_action_workspace() -> None:
    lifecycle = ElementTree.parse(VIEW_PATH).getroot()
    builder = ElementTree.parse(BUILDER_PATH).getroot()
    assert builder.tag == "form"
    assert builder.attrib["theme"] == "dark"
    assert builder.attrib["script"] == "dei_lifecycle_store_v1.js,detection_query_generator_v2.js"
    assert builder.attrib["stylesheet"] == (
        "command_center_v2.css,dei_visual_polish_v1.css,detection_lifecycle_v1.css"
    )
    for element_id in (
        "dei-detection-builder-page", "lifecycle-workspace-menu",
        "builder-ready-count", "builder-detection-select", "builder-generate",
        "detection-generator", "generator-es-state", "generator-empty",
        "generator-output", "generator-title", "generator-badges",
        "builder-feedback", "builder-cron", "builder-earliest", "builder-latest",
        "generator-spl", "builder-save-draft", "builder-reset-draft",
        "builder-run-validation", "builder-validation-state",
        "builder-validation-metrics", "validation-status",
        "validation-result-count", "validation-runtime", "validation-time",
        "builder-validation-results", "validation-result-head", "validation-result-body",
        "generator-es-output", "copy-generated-spl", "copy-generated-json",
        "download-generated-json",
    ):
        assert builder.find(f".//*[@id='{element_id}']") is not None
    assert lifecycle.find(".//*[@id='detection-generator']") is None
    assert lifecycle.find(".//*[@class='dei-lifecycle-capabilities']") is None


def test_detection_lifecycle_assets_use_evidence_not_mock_completion() -> None:
    javascript = (STATIC_ROOT / "detection_lifecycle_v2.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "detection_lifecycle_v1.css").read_text(encoding="utf-8")
    framework = FRAMEWORK_PATH.read_text(encoding="utf-8")
    assert "dei.latestRecommendationReport" in javascript
    assert "source_mappings" in javascript
    assert "observedSourcetypes" in javascript
    assert "stateFor" in javascript
    assert "nextAction" in javascript
    assert "detection_builder?detection=" in javascript
    assert "dei.selectedDetectionDraft" in javascript
    assert "DEILifecycleStore" in javascript
    assert '$("#life-spl-generated").text(records.length)' in javascript
    assert '$("#stage-generate").text(records.length+" SPL")' in javascript
    assert '$("#stage-validate").text(passed+" passed")' in javascript
    assert "mergedQueue" in javascript
    assert "submit_review" in javascript
    assert "approve_review" in javascript
    assert "record_deployment" in javascript
    assert "record_health" in javascript
    assert "start_tuning" in javascript
    assert "detection_retired" in javascript
    assert ".dei-pipeline-grid" in stylesheet
    assert ".dei-state-grid" in stylesheet
    assert ".dei-lifecycle-table" in stylesheet
    assert ".dei-lifecycle-filters>*{width:100%;min-width:0" in stylesheet
    assert ".dei-generator-grid" in stylesheet
    assert "Discover" in framework
    assert "Generate" in framework
    assert "Validate" in framework
    assert "draft → testing → peer_review → production → monitoring → tuning → retired" in framework
    assert "Initial releases must not automatically deploy or enable detections" in framework


def test_detection_query_generator_is_review_safe_and_es_aware() -> None:
    javascript = (STATIC_ROOT / "detection_query_generator_v2.js").read_text(encoding="utf-8")
    assert "production_ready" in javascript
    assert "sourceClause" in javascript
    assert "analyticLogic" in javascript
    assert "mitre_attack:item.mitre_techniques" in javascript
    assert 'cron:"*/5 * * * *"' in javascript
    assert "SplunkEnterpriseSecuritySuite" in javascript
    assert 'search_type:"Correlation"' in javascript
    assert "notable_enabled:true" in javascript
    assert "risk_based_alerting" in javascript
    assert "disabled:true" in javascript
    assert "DEI does not enable or deploy detections" not in javascript
    assert "window.localStorage.setItem(ARTIFACT_KEY" in javascript
    assert "builder-detection-select" in javascript
    assert "populateDetectionSelector" in javascript
    assert "requestedDetectionId" in javascript
    assert "buildableRecommendations" in javascript
    assert "field_unverified:true" in javascript
    assert "field_gap:true" in javascript
    assert "selectorGroup" in javascript
    assert "engineering_warnings" in javascript
    assert "unresolved_fields" in javascript
    assert "No environment analysis is loaded" in javascript
    assert '"services", "search", "jobs", "export"' in javascript
    assert "VALIDATION_RESULT_LIMIT = 25" in javascript
    assert "VALIDATION_TIMEOUT_MS = 60000" in javascript
    assert "earliest_time:artifact.schedule.earliest" in javascript
    assert "latest_time:artifact.schedule.latest" in javascript
    assert 'artifact.status = "testing"' in javascript
    assert "sample_results:rows" in javascript
    assert "saveCurrentDraft" in javascript


def test_dashboard_clear_removes_detection_drafts() -> None:
    javascript = (STATIC_ROOT / "persistent_environment.js").read_text(encoding="utf-8")
    assert 'ARTIFACT_KEY = "dei.detectionDraftArtifacts"' in javascript
    assert "DISCOVERY_TIME_KEY, ES_KEY, ARTIFACT_KEY" in javascript
