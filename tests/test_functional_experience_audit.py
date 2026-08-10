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
    layout = _source("dei_workspace_layout_v1.js")
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


def test_assisted_tour_has_real_cross_page_targets_and_opt_out():
    layout = _source("dei_workspace_layout_v1.js")
    stylesheet = _source("dei_workspace_layout_v1.css")
    for control in (
        "dei-onboarding-next",
        "dei-onboarding-back",
        "dei-onboarding-not-now",
        "dei-onboarding-dismiss-permanently",
    ):
        assert control in layout
    for page in ("home", "environment", "mitre", "builder", "lifecycle"):
        assert f'page:"{page}"' in layout
    assert "window.location.href=onboardingPage(step)" in layout
    assert 'safeStorageSet(ONBOARDING_KEY, "true")' in layout
    assert ".dei-onboarding-target" in stylesheet


def test_tour_targets_exist_in_their_owning_views():
    targets = {
        "dei_home.xml": ".//*[@id='dei-home-pipeline']",
        "command_center.xml": ".//*[@id='dei-telemetry']",
        "mitre_coverage.xml": ".//*[@class='dei-mitre-advisor']",
        "detection_builder.xml": ".//*[@id='dei-detection-builder-page']",
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
        "dei-home-health-action": "detection_action_center",
        "dei-density-toggle": "applyDensity(next)",
    }
    for control, behavior in controls.items():
        assert control in sources, control
        assert behavior in sources, f"{control} does not expose {behavior}"
