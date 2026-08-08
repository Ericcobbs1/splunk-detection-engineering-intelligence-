"""Regression tests for the Detection Engineering Lifecycle workspace."""

from pathlib import Path
from xml.etree import ElementTree

APP_ROOT = Path("app")
VIEW_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "detection_lifecycle.xml"
NAV_PATH = APP_ROOT / "default" / "data" / "ui" / "nav" / "default.xml"
STATIC_ROOT = APP_ROOT / "appserver" / "static"
FRAMEWORK_PATH = Path("docs") / "DETECTION_ENGINEERING_FRAMEWORK.md"


def test_detection_lifecycle_view_is_valid_and_packaged() -> None:
    root = ElementTree.parse(VIEW_PATH).getroot()
    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert root.attrib["script"] == "detection_lifecycle_v1.js"
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
        "lifecycle-queue-count", "lifecycle-work-queue",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None


def test_detection_lifecycle_is_registered_in_navigation() -> None:
    root = ElementTree.parse(NAV_PATH).getroot()
    assert root.find(".//view[@name='detection_lifecycle']") is not None


def test_detection_lifecycle_assets_use_evidence_not_mock_completion() -> None:
    javascript = (STATIC_ROOT / "detection_lifecycle_v1.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "detection_lifecycle_v1.css").read_text(encoding="utf-8")
    framework = FRAMEWORK_PATH.read_text(encoding="utf-8")
    assert "dei.latestRecommendationReport" in javascript
    assert "source_mappings" in javascript
    assert "observedSourcetypes" in javascript
    assert "engineeringStage" in javascript
    assert "nextAction" in javascript
    assert '$("#life-spl-generated").text("0")' in javascript
    assert '$("#stage-generate").text("0 SPL")' in javascript
    assert '$("#stage-validate").text("0 passed")' in javascript
    assert ".dei-pipeline-grid" in stylesheet
    assert ".dei-state-grid" in stylesheet
    assert ".dei-lifecycle-table" in stylesheet
    assert "Discover" in framework
    assert "Generate" in framework
    assert "Validate" in framework
    assert "draft → testing → peer_review → production → monitoring → tuning → retired" in framework
    assert "Initial releases must not automatically deploy or enable detections" in framework
