"""Regression tests for shared analyst workspace layouts and motion."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
STATIC = APP / "appserver" / "static"
VIEWS = APP / "default" / "data" / "ui" / "views"


def test_shared_workspace_assets_are_packaged_on_operational_pages() -> None:
    for view in ("dei_home", "command_center", "environment_insights", "mitre_coverage", "detection_lifecycle", "detection_builder"):
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
    assert "window.sessionStorage.getItem" in javascript
    assert "renderScanContext" in javascript
    assert "No active environment scan" in javascript
    assert "Compact spacing" in javascript
    assert "Comfortable spacing" in javascript
    assert ">Guided</button>" in javascript
    assert ">Advanced</button>" in javascript
    assert "renderGuidedWorkflow" in javascript
    assert "workflowSnapshot" in javascript
    assert "dei-guided-learning-text" in javascript
    assert "Show advanced tools" in javascript
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
    workspaces_index = next(
        index for index, child in enumerate(children)
        if "dei-home-workspaces" in child.attrib.get("class", "").split()
    )
    assert pipeline_index < workspaces_index
    assert shell.find(".//*[@class='dei-hero dei-home-hero']") is None
    assert shell.find(".//*[@id='dei-home-detection-flow']") is not None
    assert shell.find(".//*[@id='dei-home-flow-status']") is not None
    assert ".dei-official-home>.dei-home-flow-section{order:1" in stylesheet
    assert "min-height:calc(100vh - 76px)" in stylesheet
    assert "border:0!important" in stylesheet
    assert ".dei-official-home .dei-topology-flow{order:1;flex:1 1 auto" in stylesheet
    assert ".dei-official-home .dei-flow-health-summary{order:2" in stylesheet
    assert ".dei-home-flow-tags" in stylesheet
    assert "Move telemetry through a measurable detection pipeline." in ElementTree.tostring(home, encoding="unicode")
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
    assert 'id="dei-home-health-action"' in ElementTree.tostring(home, encoding="unicode")
    assert 'id="dei-home-health-actions"' in ElementTree.tostring(home, encoding="unicode")
    assert home.attrib["script"].startswith("dei_lifecycle_store_v1.js,")
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
    assert len(geo_map.findall(".//*[@class='dei-geo-network-chords']/*")) == 7
    assert len(geo_map.findall(".//*[@class='dei-geo-orbit-tracks']/*")) == 3
    satellites = geo_map.find(".//*[@class='dei-geo-satellites']")
    assert satellites is not None and len(list(satellites)) == 3
    assert len([element for element in satellites.iter() if element.tag.endswith("animateMotion")]) == 3
    assert ".dei-geo-map" in stylesheet
    assert ".dei-geo-land-accurate" in stylesheet
    assert ".dei-geo-borders" in stylesheet
    assert "@keyframes dei-geo-pulse" in stylesheet
    assert "@keyframes dei-geo-arc" in stylesheet
    assert "@keyframes dei-geo-hotspot-bloom" in stylesheet
    assert "@keyframes dei-geo-reticle" in stylesheet
    assert "@keyframes dei-geo-network-signal" in stylesheet
    assert "@keyframes dei-satellite-beacon" in stylesheet
    assert ".dei-geo-satellites" in stylesheet
    assert shell.find(".//*[@id='dei-topology-core-count']") is not None
    command_center = ElementTree.parse(VIEWS / "command_center.xml").getroot()
    assert command_center.find(".//*[@id='dei-home-pipeline']") is None


def test_guided_workflow_prioritizes_primary_tasks_and_progressive_disclosure() -> None:
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    javascript = (STATIC / "dei_workspace_layout_v1.js").read_text(encoding="utf-8")
    for stage in ("discover", "review", "build", "validate", "operate"):
        assert f'key:"{stage}"' in javascript
    for selector in (
        "#dei-home-page>.dei-guided-workflow{order:2!important}",
        "#dei-command-center>#dei-telemetry{order:2!important}",
        "#dei-environment-insights>.dei-guided-workflow{order:1!important}",
        "#dei-command-center.dei-environment-discovery>.dei-discovery-next{order:3!important}",
        "#dei-mitre-page>.dei-guided-workflow{order:1!important}",
        "#dei-detection-builder-page>.dei-builder-selector-section{order:2!important}",
        "#dei-lifecycle-page>.dei-lifecycle-workspace-grid{order:2!important}",
    ):
        assert selector in stylesheet
    assert ".dei-guided-learning" in stylesheet
    assert ".dei-active-scan-context" in stylesheet
    assert "#dei-guided-workflow-advanced" in stylesheet
    assert "How this step works" in javascript
    assert "run telemetry discovery" in javascript
    assert "Filter Detection Advisor by sourcetype" in javascript
    assert "Select a qualified recommendation" in javascript


def test_first_session_onboarding_is_dismissible_and_accessible() -> None:
    javascript = (STATIC / "dei_workspace_layout_v1.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    for value in (
        "dei.onboardingDismissed.v1", "dei.onboardingSeen.session",
        'role="dialog"', 'aria-modal="true"', "Do not show this welcome guide again",
        "Start telemetry discovery", "closeOnboarding", 'event.key==="Escape"',
        'event.key==="Tab"',
    ):
        assert value in javascript
    assert ".dei-onboarding-overlay" in stylesheet
    assert ".dei-onboarding-dialog" in stylesheet
    assert "body.dei-onboarding-open" in stylesheet


def test_environment_workflow_is_split_between_discovery_and_results() -> None:
    command = ElementTree.parse(VIEWS / "command_center.xml").getroot()
    insights = ElementTree.parse(VIEWS / "environment_insights.xml").getroot()
    assert command.find(".//*[@id='dei-telemetry']") is not None
    assert command.find(".//*[@id='dei-open-environment-insights']") is not None
    assert command.find(".//*[@id='dei-coverage-section']") is None
    assert insights.find(".//*[@id='dei-telemetry']") is None
    assert insights.find(".//*[@id='dei-coverage-section']") is not None
    assert insights.find(".//*[@id='dei-portfolio-section']") is not None


def test_visible_controls_have_handlers_or_real_destinations() -> None:
    shared = (STATIC / "dei_workspace_layout_v1.js").read_text(encoding="utf-8")
    command = (STATIC / "command_center.js").read_text(encoding="utf-8")
    state = (STATIC / "dashboard_state_v2.js").read_text(encoding="utf-8")
    mitre = (STATIC / "mitre_workspace_v2.js").read_text(encoding="utf-8")
    builder = (STATIC / "detection_query_generator_v2.js").read_text(encoding="utf-8")
    lifecycle = (STATIC / "detection_lifecycle_v2.js").read_text(encoding="utf-8")

    handlers = {
        "dei-analyze": command,
        "dei-clear-environment": state,
        "dei-refresh-environment": state,
        "builder-generate": builder,
        "builder-save-draft": builder,
        "builder-reset-draft": builder,
        "copy-generated-spl": builder,
        "copy-generated-json": builder,
        "download-generated-json": builder,
        "builder-run-validation": builder,
        "lifecycle-reset-filters": lifecycle,
    }
    for control_id, javascript in handlers.items():
        assert f'$("#{control_id}").on("click"' in javascript

    for view_name in (
        "dei_home", "command_center", "environment_insights",
        "mitre_coverage", "detection_builder", "detection_lifecycle",
    ):
        root = ElementTree.parse(VIEWS / f"{view_name}.xml").getroot()
        for link in root.findall(".//a"):
            href = link.attrib.get("href", "")
            assert href and href != "#"

    for contract in (
        "experiencePanelMarkup", "guidedActions", "coverageActions",
        "openExperienceActions", "openAdvancedTools", "closeAdvancedTools",
        "[data-dei-focus]", "data-dei-activate", "announceAction",
        "Guided experience", "Coverage experience", "Moved to ",
        "dei-advanced-action-center",
    ):
        assert contract in shared
    assert "dei-mitre-next-action" in mitre
    assert "detection_builder?detection=" in mitre
    assert 'document.execCommand("copy")' in builder
    assert "Clipboard access is unavailable" in builder


def test_landing_assessment_uses_real_scan_and_lifecycle_evidence() -> None:
    javascript = (STATIC / "dei_workspace_layout_v1.js").read_text(encoding="utf-8")
    lifecycle = (STATIC / "detection_lifecycle_v2.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    for contract in (
        "refreshHomeLifecycleRecords", "DEILifecycleStore", "homeLifecycleRecords",
        "renderHomeHealthActions", "missingHealth", "validation.status===\"failed\"",
        'qualify:ready>0', "buildable===0", "detection_lifecycle?detection=",
        "detection_builder?detection=", "homeStageDestination",
        "#dei-home-health-action", "#dei-home-health-actions-close",
    ):
        assert contract in javascript
    assert 'qualify:ready>0' in lifecycle
    assert "buildableCount===0" in lifecycle
    assert "requestedDetection" in lifecycle
    assert "telemetry ready" in lifecycle
    for destination in ("command_center#dei-telemetry", "environment_insights#dei-coverage-section", "environment_insights#recommendations", "mitre_coverage#mitre-detection-list", "detection_builder#builder-detection-select", "detection_builder#detection-generator", "detection_builder#builder-validation-title"):\n        assert destination in javascript\n    assert "focusDeepLinkedWorkspace" in javascript\n    assert ".dei-home-health-actions" in stylesheet
    assert ".dei-topology-node[role=\"link\"]" in stylesheet
    assert ".dei-topology-flow>.dei-flow-header{position:relative!important" in stylesheet
