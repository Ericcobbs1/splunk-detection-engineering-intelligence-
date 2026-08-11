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
    layout = _source("dei_workspace_layout_v8.js")
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
    layout = _source("dei_workspace_layout_v8.js")
    home_layout = _source("dei_workspace_layout_v7.js")
    stylesheet = _source("dei_workspace_layout_v1.css")
    for control in (
        "dei-onboarding-next",
        "dei-onboarding-back",
        "dei-onboarding-not-now",
    ):
        assert control in layout
    for page in ("home", "environment", "mitre", "builder", "lifecycle"):
        assert f'page:"{page}"' in layout
    assert "window.location.href=onboardingPage(step)" in layout
    assert "detection_workflow#guided-builder-workspace" in layout
    assert "restartOnboarding" in home_layout
    assert "#dei-home-tour" in home_layout
    assert '$(document).on("click", "#dei-home-tour", restartOnboarding)' in home_layout
    assert "&times;" in home_layout
    assert "Ã" not in home_layout
    assert "#dei-topology-core-action" in home_layout
    assert "showOnboarding();" in home_layout
    assert 'safeSessionGet(ONBOARDING_SESSION_KEY)==="true"' in home_layout
    assert 'safeSessionSet(ONBOARDING_SESSION_KEY, "true")' in home_layout
    assert '$(document).on("click", "#dei-onboarding-overlay"' in home_layout
    assert "if (event.target===this) { closeOnboarding(); }" in home_layout
    assert 'event.key==="Escape"' in home_layout
    assert "Shown once per login session" in home_layout
    assert "dei-onboarding-dismiss-permanently" not in home_layout
    assert "loadOnboardingPreference" not in home_layout
    assert ".dei-onboarding-target" in stylesheet


def test_tour_dialog_stays_above_spotlight_on_every_tour_page():
    tour_styles = _source("dei_guided_tour_v3.css")
    assert ".dei-onboarding-overlay{z-index:10002" in tour_styles
    assert ".dei-onboarding-target{z-index:10001!important}" in tour_styles
    assert "#dei-onboarding-back,#dei-onboarding-next" in tour_styles
    for view in (
        "dei_home.xml", "command_center.xml", "environment_insights.xml",
        "mitre_coverage.xml", "detection_workflow.xml", "detection_operations.xml",
        "detection_lifecycle.xml", "detection_health.xml", "detection_catalog.xml",
        "detection_builder.xml", "detection_action_center.xml",
    ):
        root = ElementTree.parse(VIEWS / view).getroot()
        assert "dei_guided_tour_v3.css" in root.attrib["stylesheet"].split(",")


def test_home_pipeline_drilldowns_open_owned_workspaces():
    layout = _source("dei_workspace_layout_v7.js")
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


def test_tour_teaches_production_actions_evidence_and_cautions():
    for controller in ("dei_workspace_layout_v8.js", "dei_workspace_layout_v7.js"):
        source = _source(controller)
        for field in ("objective:", "actions:", "evidence:", "caution:"):
            assert source.count(field) >= 5
        for section_id in (
            "dei-onboarding-objective", "dei-onboarding-actions",
            "dei-onboarding-evidence", "dei-onboarding-caution",
        ):
            assert section_id in source
        assert "Never enable generated SPL directly in production" in source
        assert "State changes must reflect real operational actions" in source
    styles = _source("dei_guided_tour_v3.css")
    assert ".dei-onboarding-production" in styles
