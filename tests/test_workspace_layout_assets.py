"""Regression tests for shared analyst workspace layouts and motion."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
STATIC = APP / "appserver" / "static"
VIEWS = APP / "default" / "data" / "ui" / "views"


def test_shared_workspace_assets_are_packaged_on_operational_pages() -> None:
    for view in ("command_center", "mitre_coverage", "detection_lifecycle", "detection_builder"):
        root = ElementTree.parse(VIEWS / f"{view}.xml").getroot()
        assert "dei_workspace_layout_v1.js" in root.attrib["script"]
        assert "dei_workspace_layout_v1.css" in root.attrib["stylesheet"]


def test_workspace_modes_and_density_are_persisted_accessibly() -> None:
    javascript = (STATIC / "dei_workspace_layout_v1.js").read_text(encoding="utf-8")
    for value in (
        "dei.workspaceMode", "dei.workspaceDensity", "analyst", "coverage",
        "engineering", "aria-pressed", "ArrowLeft", "ArrowRight",
        "dei:workspace-mode-changed",
    ):
        assert value in javascript
    assert "window.localStorage.setItem" in javascript
    assert "Compact spacing" in javascript
    assert "Comfortable spacing" in javascript


def test_detection_pipeline_motion_is_state_aware_and_reduced_motion_safe() -> None:
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    lifecycle = (STATIC / "detection_lifecycle_v2.js").read_text(encoding="utf-8")
    for state in ("complete", "current", "blocked", "upcoming"):
        assert f'data-pipeline-state="{state}"' in stylesheet
    assert "@keyframes dei-pipeline-flow" in stylesheet
    assert "@keyframes dei-current-stage" in stylesheet
    assert ".dei-detection-flow" in stylesheet
    assert ".dei-flow-rail" in stylesheet
    assert ".dei-flow-packet" in stylesheet
    assert ".dei-flow-nodes" in stylesheet
    assert "@keyframes dei-flow-packet" in stylesheet
    assert "@keyframes dei-flow-current-node" in stylesheet
    assert "--dei-flow-progress" in stylesheet
    assert "@media(prefers-reduced-motion:reduce)" in stylesheet
    assert "renderPipelineState" in lifecycle
    assert "activatePipelineStage" in lifecycle
    assert '.css("--dei-flow-progress",progress+"%")' in lifecycle
    assert '$("#dei-flow-status").text' in lifecycle
    assert 'event.key==="Enter" || event.key===" "' in lifecycle


def test_analyst_layouts_prioritize_actions_and_sticky_context() -> None:
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    lifecycle_view = ElementTree.parse(VIEWS / "detection_lifecycle.xml").getroot()
    assert lifecycle_view.find(".//*[@class='dei-lifecycle-workspace-grid']") is not None
    for selector in (
        '.dei-lifecycle-workspace-grid.has-selection',
        '#dei-lifecycle-page[data-dei-workspace-mode="analyst"]',
        '#dei-command-center[data-dei-workspace-mode="coverage"]',
        '#dei-mitre-page[data-dei-workspace-mode="analyst"]',
        '#dei-detection-builder-page .dei-generator-grid>article:nth-child(2)',
    ):
        assert selector in stylesheet
    assert "position:sticky" in stylesheet
