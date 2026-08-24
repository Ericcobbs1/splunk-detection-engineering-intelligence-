"""Regression tests for shared analyst workspace layouts and motion."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
STATIC = APP / "appserver" / "static"
VIEWS = APP / "default" / "data" / "ui" / "views"


def test_shared_workspace_assets_are_packaged_on_operational_pages() -> None:
    for view in ("command_center", "environment_insights", "mitre_coverage", "detection_catalog", "detection_action_center", "detection_workflow"):
        root = ElementTree.parse(VIEWS / f"{view}.xml").getroot()
        scripts = root.attrib["script"].split(",")
        assert "dei_interactive_guide_v3.js" not in scripts
        assert "dei_guide_adapter_v8.js" in scripts
        assert "dei_workspace_layout_v14.js" in scripts
        assert "dei_workspace_layout_v1.css" in root.attrib["stylesheet"]
        assert "dei_responsive_v1.css" in root.attrib["stylesheet"]
    home = ElementTree.parse(VIEWS / "dei_home.xml").getroot()
    home_scripts = home.attrib["script"].split(",")
    assert "dei_interactive_guide_v3.js" not in home_scripts
    assert "dei_guide_adapter_v8.js" in home_scripts
    assert "dei_workspace_layout_v14.js" in home_scripts
    assert "dei_home_actions_v1.css" in home.attrib["stylesheet"].split(",")
    assert "dei_home_globe_react_v1.js" in home_scripts
    assert home.attrib["stylesheet"].split(",")[-5:] == ["dei_home_globe_v2.css", "dei_home_globe_v3.css", "dei_home_globe_v4.css", "dei_home_globe_v7.css", "dei_theme_v1.css"]
    assert "dei_responsive_v1.css" in home.attrib["stylesheet"].split(",")
    home_actions = (STATIC / "dei_home_actions_v1.css").read_text(encoding="utf-8")
    assert "grid-template-columns:repeat(4,max-content)!important" in home_actions
    assert "height:40px!important" in home_actions


def test_shared_responsive_layer_supports_browser_resizing() -> None:
    stylesheet = (STATIC / "dei_responsive_v1.css").read_text(encoding="utf-8")
    for breakpoint in ("@media(max-width:1400px)", "@media(max-width:1100px)", "@media(max-width:760px)", "@media(max-width:520px)"):
        assert breakpoint in stylesheet
    assert "max-width:1920px" in stylesheet
    assert "overflow-x:auto" in stylesheet
    assert "flex-wrap:wrap!important" in stylesheet


def test_workspace_modes_and_density_are_persisted_accessibly() -> None:
    javascript = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
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
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
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
    operations_view = ElementTree.parse(VIEWS / "detection_catalog.xml").getroot()
    assert lifecycle_view.find(".//*[@class='dei-lifecycle-workspace-grid']") is None
    assert operations_view.find(".//*[@class='dei-lifecycle-section dei-lifecycle-queue-section']") is not None
    for selector in (
        '.dei-lifecycle-workspace-grid.has-selection',
        '#dei-lifecycle-page[data-dei-workspace-mode="analyst"]',
        '#dei-command-center[data-dei-workspace-mode="coverage"]',
        '#dei-mitre-page[data-dei-workspace-mode="analyst"]',
        '#dei-detection-builder-page .dei-generator-grid>article:nth-child(2)',
    ):
        assert selector in stylesheet
    assert "position:sticky" in stylesheet


def test_official_home_pipeline_is_immediately_visible_and_data_driven() -> None:
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    javascript = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    home = ElementTree.parse(VIEWS / "dei_home.xml").getroot()
    shell = home.find(".//*[@id='dei-home-page']")
    assert shell is not None
    children = list(shell)
    ids = [child.attrib.get("id") for child in children]
    pipeline_index = ids.index("dei-home-pipeline")
    assert pipeline_index == 0
    assert shell.find(".//*[@class='dei-product-bar']") is None
    assert shell.find(".//*[@class='dei-hero dei-home-hero']") is None
    assert shell.find(".//*[@id='dei-home-detection-flow']") is not None
    assert shell.find(".//*[@id='dei-home-flow-status']") is not None
    assert shell.find(".//*[@id='dei-home-refresh']") is not None
    assert shell.find(".//*[@id='dei-home-tour']") is not None
    assert shell.find(".//*[@class='dei-home-flow-link dei-open-environment-discovery']") is not None
    lifecycle_action = shell.find(".//*[@class='dei-home-flow-link']")
    assert lifecycle_action is not None
    assert lifecycle_action.text == "Detection Engineering Lifecycle"
    assert lifecycle_action.attrib["href"] == "detection_catalog#lifecycle-map"
    assert shell.find(".//*[@id='dei-topology-core-health']") is not None
    core_action = shell.find(".//*[@id='dei-topology-core-action']")
    assert core_action is not None
    assert core_action.tag == "button"
    assert ".dei-official-home>.dei-home-flow-section{order:1" in stylesheet
    assert "min-height:calc(100vh - 76px)" in stylesheet
    assert "border:0!important" in stylesheet
    assert ".dei-official-home .dei-topology-flow{order:1;flex:1 1 auto" in stylesheet
    assert ".dei-official-home .dei-flow-health-summary{order:2" in stylesheet
    assert "Your detection pipeline, in motion." in ElementTree.tostring(home, encoding="unicode")
    assert "Animation-led home" in stylesheet
    assert "min-height:clamp(620px,calc(100vh - 150px),820px)" in stylesheet
    assert shell.find(".//*[@class='dei-flow-health-summary']") is None
    assert shell.find(".//*[@class='dei-home-workspaces']") is None
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
    assert '[data-pipeline-health="critical"]' in stylesheet
    assert "refreshHomeLifecycleRecords(true)" in javascript
    assert '$(document).on("click", "#dei-home-refresh"' in javascript
    assert '$(document).on("click", "#dei-topology-core-action"' in javascript
    assert '"All evidence stages complete"' in javascript
    assert "Pipeline refreshed with the latest lifecycle evidence." in javascript
    assert 'if (!root.length) { return; }' in javascript
    assert 'if (bar.length && !bar.find(".dei-workspace-controls").length)' in javascript
    assert '!bar.length' not in javascript
    assert "#dei-home-refresh" in stylesheet
    assert ".dei-home-flow-actions{display:flex;align-items:center;gap:9px;flex:0 0 auto;flex-wrap:nowrap" in stylesheet
    assert ".dei-home-flow-actions>.dei-run-intelligence-scan,.dei-home-flow-actions>#dei-home-refresh,.dei-home-flow-actions>#dei-home-tour,.dei-home-flow-actions>.dei-home-flow-link" in stylesheet
    assert "width:auto!important" in stylesheet
    assert 'shell().is("#dei-home-page")' in javascript
    assert shell.find(".//*[@id='dei-earth-react-root']") is not None
    assert ".dei-official-home .dei-earth-track{position:relative;z-index:0;display:flex;width:200%" in stylesheet
    assert "width:min(72vw,760px)" in stylesheet
    assert "aspect-ratio:1" in stylesheet
    assert "border:2px solid rgba(112,214,255,.58)" in stylesheet
    assert ".dei-official-home .dei-earth-globe:before" in stylesheet
    assert "brightness(.92)" in stylesheet
    globe_stylesheet = (STATIC / "dei_home_globe_v2.css").read_text(encoding="utf-8")
    assert "visibility:visible!important" in globe_stylesheet
    assert "opacity:1!important" in globe_stylesheet
    assert "@keyframes dei-home-globe-v2-rotation" in globe_stylesheet
    surface_stylesheet = (STATIC / "dei_home_globe_v3.css").read_text(encoding="utf-8")
    assert 'background-image:url("dei_earth_360_v2.png?v=106")!important' in surface_stylesheet
    assert ".dei-official-home .dei-earth-track{display:none!important}" in surface_stylesheet
    assert "@keyframes dei-earth-surface-v3" in surface_stylesheet
    position_stylesheet = (STATIC / "dei_home_globe_v4.css").read_text(encoding="utf-8")
    assert "inset:auto!important;top:50%!important" in position_stylesheet
    assert "left:50%!important" in position_stylesheet
    assert "transform:translate(-50%,-50%)!important" in position_stylesheet
    react_source = Path("ui/home-globe.jsx").read_text(encoding="utf-8")
    react_stylesheet = (STATIC / "dei_home_globe_v7.css").read_text(encoding="utf-8")
    assert "createRoot(host).render(<HomeGlobe />)" in react_source
    assert "dei_earth_360_v3.png?v=107" in react_source
    assert "dei_realistic_earth_v1.webp?v=107" in react_source
    assert 'data-renderer="react"' in react_source
    assert "@keyframes dei-react-earth-rotation" in react_stylesheet
    assert "width:clamp(420px,34vw,620px)!important" in react_stylesheet
    assert ".dei-official-home .dei-earth-globe{display:none!important}" in react_stylesheet
    earth_texture = (STATIC / "dei_earth_360_v3.png").read_bytes()
    assert earth_texture.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(earth_texture) > 1_000_000
    assert "@keyframes dei-realistic-earth-rotation" in stylesheet
    assert "animation:dei-realistic-earth-rotation 52s linear infinite" in stylesheet
    assert "transform:translateX(-50%)" in stylesheet
    assert (STATIC / "dei_realistic_earth_v1.webp").stat().st_size < 200_000
    assert ".dei-flow-health-summary" in stylesheet
    assert ".dei-flow-stage-count" in stylesheet
    assert 'id="dei-home-health"' not in ElementTree.tostring(home, encoding="unicode")
    assert 'id="dei-home-health-action"' not in ElementTree.tostring(home, encoding="unicode")
    assert 'id="dei-home-health-actions"' not in ElementTree.tostring(home, encoding="unicode")
    assert home.attrib["script"].startswith("dei_environment_scan_v1.js,dei_lifecycle_store_v1.js,")
    assert ElementTree.tostring(home, encoding="unicode").count("dei-flow-stage-count") == 7
    for node in shell.findall(".//*[@data-home-flow-stage]"):
        assert node.attrib["role"] == "link"
        assert node.attrib["tabindex"] == "0"
        assert node.attrib["aria-label"]
    markup = ElementTree.tostring(home, encoding="unicode")
    for description in (
        "Telemetry inventory", "Field evidence", "Readiness gates", "Use-case portfolio",
        "Detection logic", "Reviewable SPL", "Test evidence", "Pipeline health",
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


def test_removed_home_widgets_remain_available_in_owned_workspaces() -> None:
    home = ElementTree.parse(VIEWS / "dei_home.xml").getroot()
    health = ElementTree.parse(VIEWS / "detection_health.xml").getroot()
    lifecycle = ElementTree.parse(VIEWS / "detection_catalog.xml").getroot()
    actions = ElementTree.parse(VIEWS / "detection_action_center.xml").getroot()
    insights = ElementTree.parse(VIEWS / "environment_insights.xml").getroot()
    assert home.find(".//*[@class='dei-flow-health-summary']") is None
    assert home.find(".//*[@class='dei-home-workspaces']") is None
    for element_id in ("health-managed", "health-healthy", "health-attention", "health-failed", "health-refresh"):
        assert health.find(f".//*[@id='{element_id}']") is not None
    for element_id in ("catalog-count-development", "catalog-count-staging", "catalog-count-enabled", "catalog-count-monitoring"):
        assert lifecycle.find(f".//*[@id='{element_id}']") is not None
    for element_id in ("action-count-all", "action-count-critical", "action-count-telemetry", "action-refresh"):
        assert actions.find(f".//*[@id='{element_id}']") is not None
    for element_id in ("metric-ready", "portfolio-field-gaps", "dei-refresh-environment"):
        assert insights.find(f".//*[@id='{element_id}']") is not None


def test_guided_workflow_prioritizes_primary_tasks_and_progressive_disclosure() -> None:
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    javascript = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    for stage in ("discover", "review", "build", "validate", "operate"):
        assert f'key:"{stage}"' in javascript
    for selector in (
        "#dei-home-page>.dei-guided-workflow{order:2!important}",
        "#dei-command-center>#dei-telemetry{order:2!important}",
        "#dei-command-center.dei-environment-discovery>.dei-discovery-next{order:3!important;margin-top:14px}",
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
    assert 'if (!shell().is("#dei-home-page")) { return; }' in javascript


def test_first_session_onboarding_is_dismissible_and_accessible() -> None:
    javascript = (STATIC / "dei_guide_adapter_v8.js").read_text(encoding="utf-8")
    react_source = Path("ui/interactive-guide.jsx").read_text(encoding="utf-8")
    stylesheet = (STATIC / "dei_guided_tour_v6.css").read_text(encoding="utf-8")
    for value in (
        "dei.nextGuide.seen", "dei.nextGuide.step", "scrollIntoView",
        'event.key==="Escape"', 'event.key==="F6"', "sessionKey",
        "window.DEINextGuide",
    ):
        assert value in javascript
    assert 'role="dialog"' in react_source
    assert 'aria-modal="false"' in react_source
    assert "onClose" in react_source
    assert "onFocusTarget" in react_source
    assert "reviewMode" in react_source
    assert "onForward" in react_source
    assert "disabled={stepNumber === 1}" in react_source
    assert "step.lockBack" not in react_source
    assert "reviewCeiling" in javascript
    assert "reviewMode ? 'Next'" in react_source
    assert "Ã" not in javascript
    assert 'function sessionKey(base) {' in javascript
    assert 'return base+"."+GUIDE_STATE_VERSION' in javascript
    assert 'Splunk.util.getConfigValue("FORM_KEY")' not in javascript
    assert 'document.createElement("script")' in javascript
    assert "dei_interactive_guide_v3.js" in javascript
    assert "script.onerror" in javascript
    assert "dashboard remains available" in javascript
    assert 'OVERLAY_ID="dei-next-guide-overlay"' in javascript
    assert "window.MutationObserver" in javascript
    assert "#lifecycle-external-id" in javascript
    assert '[data-action="record_deployment"]' in javascript
    assert "dei-next-guide-collapse" in react_source
    assert "dei-guide-positioned" in stylesheet
    assert "#dei-guide-action-marker" in stylesheet
    assert ".dei-onboarding-overlay" in stylesheet
    assert ".dei-next-guide-dialog" in stylesheet
    assert ".dei-next-guide-action" in stylesheet


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
    shared = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    command = (STATIC / "command_center.js").read_text(encoding="utf-8")
    state = (STATIC / "dashboard_state_v2.js").read_text(encoding="utf-8")
    mitre = (STATIC / "mitre_workspace_v4.js").read_text(encoding="utf-8")
    builder = (STATIC / "detection_query_generator_v5.js").read_text(encoding="utf-8")
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")

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
        direct = f'$("#{control_id}").on("click"'
        namespaced = f'$("#{control_id}").off("click.deiGenerate").on("click.deiGenerate"'
        delegated = f'$(document).off("click.deiGenerate", "#{control_id}").on("click.deiGenerate", "#{control_id}"'
        assert direct in javascript or namespaced in javascript or delegated in javascript

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
    assert "detection_workflow?detection=" in mitre
    assert 'document.execCommand("copy")' in builder
    assert "Clipboard access is unavailable" in builder


def test_landing_assessment_uses_real_scan_and_lifecycle_evidence() -> None:
    javascript = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    for contract in (
        "refreshHomeLifecycleRecords", "DEILifecycleStore", "homeLifecycleRecords",
        "renderHomeHealthActions", "missingHealth", "validation.status===\"failed\"",
        'qualify:ready>0', "buildable===0", "detection_workflow?detection=",
        "detection_workflow?detection=", "homeStageDestination",
        "#dei-home-health-action", "detection_action_center",
    ):
        assert contract in javascript
    assert 'qualify:ready>0' in lifecycle
    assert "buildableCount===0" in lifecycle
    assert "requestedDetection" in lifecycle
    assert "requestedPipelineStage" in lifecycle
    assert "applyRequestedPipelineStage" in lifecycle
    assert "field-evidence verification" in lifecycle
    assert "telemetry ready" in lifecycle
    for destination in (
        "command_center#dei-telemetry", "environment_insights#dei-portfolio-section",
        "environment_insights#metric-ready", "mitre_coverage#mitre-detection-list",
        "detection_workflow#workflow-driver", "detection_workflow#guided-builder-workspace",
        "detection_workflow#builder-validation-title",
    ):
        assert destination in javascript
    assert "focusDeepLinkedWorkspace" in javascript
    assert '.attr("href","detection_action_center")' in javascript
    assert ".dei-topology-node[role=\"link\"]" in stylesheet
    assert ".dei-topology-flow>.dei-flow-header{position:relative!important" in stylesheet


def test_every_home_topology_step_targets_an_existing_owned_section() -> None:
    javascript = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    routes = {
        "discover": ("command_center", "dei-telemetry"),
        "profile": ("environment_insights", "dei-portfolio-section"),
        "qualify": ("environment_insights", "metric-ready"),
        "recommend": ("mitre_coverage", "mitre-detection-list"),
        "design": ("detection_workflow", "workflow-driver"),
        "generate": ("detection_workflow", "guided-builder-workspace"),
        "validate": ("detection_workflow", "builder-validation-title"),
    }
    for stage, (view_name, section_id) in routes.items():
        destination = f'{stage}:"{view_name}#{section_id}"'
        assert destination in javascript
        view = ElementTree.parse(VIEWS / f"{view_name}.xml").getroot()
        assert view.find(f".//*[@id='{section_id}']") is not None, destination


def test_catalog_makes_enabled_and_disabled_states_immediately_visible() -> None:
    view = (VIEWS / "detection_catalog.xml").read_text(encoding="utf-8")
    javascript = (STATIC / "detection_catalog_v2.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "detection_catalog_state_v1.css").read_text(encoding="utf-8")
    assert 'data-catalog-filter="enabled" data-deployment-state="enabled"' in view
    assert 'data-catalog-filter="disabled" data-deployment-state="disabled"' in view
    assert 'id="catalog-count-disabled"' in view
    assert 'data-catalog-status="' in javascript
    assert 'DEI record: production enabled' in javascript
    assert 'referenced Splunk object was not changed' in javascript
    assert 'class="dei-deployment-state ' in javascript
    assert '"ENABLED"' in javascript and '"DISABLED"' in javascript
    assert '[data-deployment-state="enabled"]' in stylesheet
    assert '[data-deployment-state="disabled"]' in stylesheet
    assert ".dei-deployment-state.disabled" in stylesheet
