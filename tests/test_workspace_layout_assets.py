"""Regression tests for shared analyst workspace layouts and motion."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
STATIC = APP / "appserver" / "static"
VIEWS = APP / "default" / "data" / "ui" / "views"


def test_shared_workspace_assets_are_packaged_on_operational_pages() -> None:
    for view in ("dei_home", "command_center", "mitre_coverage", "detection_lifecycle", "detection_builder"):
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
    assert "renderHomePipeline" in javascript
    assert "dei.latestRecommendationReport" in javascript
    assert "dei.detectionDraftArtifacts" in javascript
    assert "dei:environment-refreshed" in javascript
    assert "dei:detection-artifacts-changed" in javascript
    assert "dei-home-health" in javascript
    assert "dei-home-use-case-count" in javascript
    assert "dei-home-blocked-count" in javascript
    assert "stageCounts" in javascript


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
    analyst_pipeline = stylesheet.index('#dei-lifecycle-page[data-dei-workspace-mode="analyst"]>.dei-pipeline-section{order:3}')
    analyst_queue = stylesheet.index('#dei-lifecycle-page[data-dei-workspace-mode="analyst"]>.dei-lifecycle-workspace-grid{order:4}')
    assert analyst_pipeline >= 0 and analyst_queue > analyst_pipeline
    assert "position:sticky" in stylesheet


def test_official_home_pipeline_is_immediately_visible_and_data_driven() -> None:
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    home = ElementTree.parse(VIEWS / "dei_home.xml").getroot()
    shell = home.find(".//*[@id='dei-home-page']")
    assert shell is not None
    children = list(shell)
    ids = [child.attrib.get("id") for child in children]
    pipeline_index = ids.index("dei-home-pipeline")
    hero_index = next(
        index for index, child in enumerate(children)
        if "dei-home-hero" in child.attrib.get("class", "").split()
    )
    workspaces_index = next(
        index for index, child in enumerate(children)
        if "dei-home-workspaces" in child.attrib.get("class", "").split()
    )
    assert hero_index < pipeline_index < workspaces_index
    assert shell.find(".//*[@id='dei-home-detection-flow']") is not None
    assert shell.find(".//*[@id='dei-home-flow-status']") is not None
    assert ".dei-official-home>.dei-home-flow-section{order:1" in stylesheet
    assert ".dei-official-home>.dei-home-hero{order:2" in stylesheet
    assert "min-height:max(780px,calc(100vh - 108px))" in stylesheet
    assert ".dei-official-home .dei-topology-core{width:340px;height:340px" in stylesheet
    assert ".dei-official-home{max-width:1880px" in stylesheet
    assert ".dei-home-workspace-grid" in stylesheet
    assert ".dei-official-home .dei-topology-flow{min-height:590px" in stylesheet
    assert ".dei-topology-core{position:absolute" in stylesheet
    assert ".dei-topology-connections" in stylesheet
    assert "@keyframes dei-topology-signal" in stylesheet
    assert "@keyframes dei-topology-orbit" in stylesheet
    assert "@keyframes dei-home-pipeline-scan" in stylesheet
    assert ".dei-flow-health-summary" in stylesheet
    assert ".dei-flow-stage-count" in stylesheet
    assert 'id="dei-home-health"' in ElementTree.tostring(home, encoding="unicode")
    assert 'id="dei-home-use-case-count"' in ElementTree.tostring(home, encoding="unicode")
    assert 'id="dei-home-blocked-count"' in ElementTree.tostring(home, encoding="unicode")
    assert ElementTree.tostring(home, encoding="unicode").count("dei-flow-stage-count") == 7
    markup = ElementTree.tostring(home, encoding="unicode")
    for description in (
        "Telemetry inventory", "Field evidence", "Readiness gates", "Use-case portfolio",
        "Detection logic", "Reviewable SPL", "Test evidence", "DEI Intelligence Core",
    ):
        assert description in markup
    topology = shell.find(".//*[@class='dei-topology-canvas']")
    assert topology is not None
    connections = topology.find(".//*[@class='dei-topology-connections']")
    assert connections is not None
    assert len([element for element in connections.iter() if element.tag.endswith("path")]) == 14
    geo_map = topology.find(".//*[@id='dei-global-secops-map']")
    assert geo_map is not None
    land = geo_map.find(".//*[@class='dei-geo-land dei-geo-land-accurate']")
    borders = geo_map.find(".//*[@class='dei-geo-borders']")
    assert land is not None and len(list(land)) == 1
    assert borders is not None and len(list(borders)) == 1
    assert "Natural Earth 1:110m" in ElementTree.tostring(geo_map, encoding="unicode")
    assert len(geo_map.findall(".//*[@class='dei-geo-points']/*")) == 5
    assert len(geo_map.findall(".//*[@class='dei-geo-hotspots']/*")) == 5
    assert ".dei-geo-map" in stylesheet
    assert ".dei-geo-land-accurate" in stylesheet
    assert ".dei-geo-borders" in stylesheet
    assert "@keyframes dei-geo-pulse" in stylesheet
    assert "@keyframes dei-geo-arc" in stylesheet
    assert "@keyframes dei-geo-hotspot-bloom" in stylesheet
    assert "@keyframes dei-geo-reticle" in stylesheet
    assert shell.find(".//*[@id='dei-topology-core-count']") is not None
    command_center = ElementTree.parse(VIEWS / "command_center.xml").getroot()
    assert command_center.find(".//*[@id='dei-home-pipeline']") is None
