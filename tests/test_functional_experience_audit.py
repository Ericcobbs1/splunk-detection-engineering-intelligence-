from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).parents[1]
VIEWS = ROOT / "app/default/data/ui/views"
STATIC = ROOT / "app/appserver/static"


def _source(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_every_workspace_loads_the_shared_scan_service():
    for view in VIEWS.glob("*.xml"):
        root = ElementTree.parse(view).getroot()
        assert "dei_environment_scan_v1.js" in root.attrib["script"].split(","), view.name


def test_home_scan_is_an_operation_not_a_redirect():
    layout = _source("dei_workspace_layout_v13.js")
    service = _source("dei_environment_scan_v1.js")
    assert 'class="dei-run-intelligence-scan"' in layout
    assert 'window.DEIEnvironmentScan.run(' in layout
    assert '<a href="command_center#dei-telemetry">Run intelligence scan' not in layout
    assert "dei:scan-progress" in service
    assert "dei:environment-refreshed" in service
    assert "latestRecommendationReport" in service
    assert 'dei_force_refresh:"1"' in service
    assert "isExplicitFreshScan" in _source("dashboard_state_v2.js")
    assert "The intelligence scan failed" in service
    assert 'scanCollection="dei_scan_summaries"' in service
    assert 'scanEndpoint("latest")' in service
    assert "assessment_id" in service
    assert "active_sourcetype_count" in service
    assert "active_index_count" in service
    assert "field_profile_failures" in service
    assert "enterprise_security_enabled" in service
    assert "function hydrate()" in service


def test_assisted_tour_opens_once_per_session_and_is_dismissible():
    adapter = _source("dei_guide_adapter_v3.js")
    react_source = (ROOT / "ui/interactive-guide.jsx").read_text(encoding="utf-8")
    bundle = _source("dei_interactive_guide_v2.js")
    for page in ("home", "environment", "environment_insights", "mitre", "builder", "catalog"):
        assert f'page:"{page}"' in adapter
    for event in (
        "dei:scan-progress", "dei:advisor-detection-selected",
        "dei:detection-draft-generated", "dei:detection-validation-complete",
        "dei:lifecycle-records-updated", "dei:catalog-action-complete",
    ):
        assert event in adapter
    assert 'event.key==="Escape"' in adapter
    assert 'event.key==="F6"' in adapter
    assert 'Splunk.util.getConfigValue("FORM_KEY")' in adapter
    assert "Math.imul(hash,16777619)" in adapter
    assert "window.DEINextGuide" in adapter
    assert 'document.createElement("script")' in adapter
    assert "script.async=true" in adapter
    assert "script.onerror" in adapter
    assert "Waiting for this action to complete" in react_source
    assert "The guide advances automatically" in react_source
    assert "Next" not in react_source
    assert "window.DEIInteractiveGuide" in bundle


def test_react_bundle_is_progressive_enhancement_not_a_dashboard_dependency():
    for view in VIEWS.glob("*.xml"):
        scripts = ElementTree.parse(view).getroot().attrib["script"].split(",")
        assert "dei_interactive_guide_v2.js" not in scripts, view.name
        assert "dei_guide_adapter_v3.js" in scripts, view.name
    adapter = _source("dei_guide_adapter_v3.js")
    assert "finishGuideLoad(false)" in adapter
    assert "dashboard remains available" in adapter


def test_tour_dialog_stays_above_spotlight_on_every_tour_page():
    tour_styles = _source("dei_guided_tour_v6.css")
    assert ".dei-onboarding-overlay{z-index:10002" in tour_styles
    assert ".dei-onboarding-target{z-index:10001!important;pointer-events:auto}" in tour_styles
    assert ".dei-onboarding-overlay{z-index:10002" in tour_styles
    assert '.dei-onboarding-dialog[data-placement="right"]' in tour_styles
    assert '.dei-onboarding-dialog[data-placement="left"]' in tour_styles
    assert '.dei-onboarding-dialog::before{content:""' in tour_styles
    assert ".dei-next-guide{padding:18px" in tour_styles
    assert ".dei-next-guide-action" in tour_styles
    for view in (
        "dei_home.xml", "command_center.xml", "environment_insights.xml",
        "mitre_coverage.xml", "detection_workflow.xml", "detection_operations.xml",
        "detection_lifecycle.xml", "detection_health.xml", "detection_catalog.xml",
        "detection_builder.xml", "detection_action_center.xml",
    ):
        root = ElementTree.parse(VIEWS / view).getroot()
        assert "dei_guided_tour_v6.css" in root.attrib["stylesheet"].split(",")


def test_home_pipeline_drilldowns_open_owned_workspaces():
    layout = _source("dei_workspace_layout_v11.js")
    assert 'generate:"detection_workflow#guided-builder-workspace"' in layout
    assert 'validate:"detection_workflow#builder-validation-title"' in layout
    assert '"detection_action_center"' in layout
    assert '"detection_health"' in layout
    assert '"command_center#dei-telemetry"' in layout
    assert '"detection_operations"' in layout


def test_tour_targets_exist_in_their_owning_views():
    targets = {
        "dei_home.xml": ".//*[@id='dei-home-pipeline']",
        "command_center.xml": ".//*[@id='dei-telemetry']",
        "mitre_coverage.xml": ".//*[@class='dei-mitre-advisor']",
        "detection_workflow.xml": ".//*[@id='guided-builder-workspace']",
        "detection_operations.xml": ".//*[@id='lifecycle-work-queue']",
    }
    for view, xpath in targets.items():
        assert ElementTree.parse(VIEWS / view).getroot().find(xpath) is not None, view


def test_no_duplicate_control_ids_within_any_view():
    for view in VIEWS.glob("*.xml"):
        root = ElementTree.parse(view).getroot()
        ids = [node.attrib["id"] for node in root.iter() if "id" in node.attrib]
        assert len(ids) == len(set(ids)), view.name


def test_core_action_controls_have_implementation_bindings():
    sources = "\n".join(path.read_text(encoding="utf-8") for path in STATIC.glob("*.js"))
    controls = {
        "dei-analyze": "discoverEnvironment(true)",
        "builder-generate": "generateSelectedDetection",
        "builder-clear-spl": '$("#generator-spl").val("")',
        "builder-save-draft": "saveCurrentDraft",
        "builder-run-validation": "runValidation",
        "builder-apply-validation-fix": "Recommended correction applied",
        "lifecycle-reset-filters": "renderQueue()",
        "dei-density-toggle": "applyDensity(next)",
    }
    for control, behavior in controls.items():
        assert control in sources, control
        assert behavior in sources, f"{control} does not expose {behavior}"


def test_react_tour_drives_real_analyst_actions_instead_of_long_form_content():
    adapter = _source("dei_guide_adapter_v3.js")
    react_source = (ROOT / "ui/interactive-guide.jsx").read_text(encoding="utf-8")
    assert adapter.count("actionLabel:") == 11
    for target in (
        ".dei-run-intelligence-scan", "#dei-open-environment-insights",
        ".dei-mitre-glow-button", "#mitre-sourcetype-filter",
        ".dei-advisor-item", "#builder-detection-select", "#builder-generate",
        "#builder-run-validation", '#lifecycle-action-buttons [data-action]:not(:disabled)',
        "#catalog-external-id", '[data-catalog-action="enable"]',
        '[data-catalog-action="disable"]', '[data-catalog-action="reenable"]',
    ):
        assert target in adapter
    assert "Waiting for this action to complete" in react_source
    assert "The guide advances automatically" in react_source
    assert "Production objective" not in react_source
    assert "Evidence before continuing" not in react_source
    styles = _source("dei_guided_tour_v6.css")
    assert ".dei-next-guide-action" in styles
    assert "#dei-guide-action-marker" in styles
    assert "deiGuideTargetPulse" in styles
    assert "prefers-reduced-motion:reduce" in styles


def test_react_guide_survives_dynamic_controls_and_finishes_at_catalog_state():
    adapter = _source("dei_guide_adapter_v3.js")
    layout = _source("dei_workspace_layout_v13.js")
    assert "window.MutationObserver" in adapter
    assert "window.setTimeout(advance,0)" in adapter
    assert 'OVERLAY_ID="dei-next-guide-overlay"' in adapter
    assert 'data-dei-guide-owner="react"' in adapter
    assert "window.DEIReactGuideConfigured=true" in adapter
    assert "window.DEIReactGuideConfigured || window.DEINextGuide" in layout
    assert 'status==="enabled"||status==="disabled"' in adapter
    assert "readStep()===10" in adapter
