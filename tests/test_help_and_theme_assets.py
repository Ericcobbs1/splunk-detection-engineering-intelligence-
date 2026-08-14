"""Contracts for premium visual themes and durable manual help."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
STATIC = APP / "appserver/static"
VIEWS = APP / "default/data/ui/views"


def test_help_is_a_first_class_navigation_workspace() -> None:
    nav = ElementTree.parse(APP / "default/data/ui/nav/default.xml").getroot()
    assert nav.find(".//view[@name='dei_help']") is not None
    root = ElementTree.parse(VIEWS / "dei_help.xml").getroot()
    assert root.attrib["version"] == "1.1"
    assert "dei_theme_v1.js" in root.attrib["script"].split(",")
    assert "dei_help_v1.css" in root.attrib["stylesheet"].split(",")


def test_help_covers_the_detection_lifecycle_and_recovery() -> None:
    source = (VIEWS / "dei_help.xml").read_text(encoding="utf-8")
    for topic in (
        "help-discovery", "help-build", "help-validate", "help-review",
        "help-deploy", "help-monitor", "help-health-metrics", "help-tune", "help-retire",
        "help-troubleshoot",
    ):
        assert f'id="{topic}"' in source
    for guidance in (
        "Settings → Searches, Reports, and Alerts",
        "Configure → Content → Content Management",
        "Zero results can be healthy",
        "does not disable the actual Splunk saved search",
        "observed problem; supporting evidence; proposed change",
        "enabled or disabled detection",
        "Signal precision:",
    ):
        assert guidance in source


def test_theme_is_locked_to_dark_without_an_appearance_toggle() -> None:
    javascript = (STATIC / "dei_theme_v1.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "dei_theme_v1.css").read_text(encoding="utf-8")
    assert 'setAttribute("data-dei-theme", "dark")' in javascript
    assert 'localStorage.removeItem("dei.colorScheme")' in javascript
    assert 'localStorage.setItem' not in javascript
    assert 'id="dei-theme-toggle"' not in javascript
    assert 'data-dei-theme' in javascript
    assert '[data-dei-theme="dark"]' in stylesheet
    assert '[data-dei-theme="light"]' not in stylesheet
    assert "--dei-action:#4f8df7" in stylesheet
    assert "--dei-success:#42c7a5" in stylesheet
    assert "--dei-warning:#e8ad4f" in stylesheet
    assert "--dei-danger:#ef6673" in stylesheet


def test_every_canonical_workspace_loads_theme_assets_last() -> None:
    canonical = (
        "dei_home", "command_center", "environment_insights", "mitre_coverage",
        "mitre_heatmap", "detection_workflow", "detection_catalog",
        "detection_health", "detection_health_detail", "detection_action_center", "dei_help",
    )
    for name in canonical:
        root = ElementTree.parse(VIEWS / f"{name}.xml").getroot()
        scripts = root.attrib["script"].split(",")
        styles = root.attrib["stylesheet"].split(",")
        assert scripts[-1] == "dei_theme_v1.js", name
        assert "dei_theme_v1.css" in styles, name
        if name != "dei_help":
            assert styles[-1] == "dei_theme_v1.css", name


def test_theme_uses_color_plus_status_contracts() -> None:
    design = (STATIC / "dei_design_system_v2.css").read_text(encoding="utf-8")
    assert 'content:"✓"' in design
    assert 'content:"!"' in design
    assert 'content:"×"' in design
    assert ":focus-visible" in design


def test_theme_has_no_obsolete_light_mode_rules() -> None:
    stylesheet = (STATIC / "dei_theme_v1.css").read_text(encoding="utf-8")
    assert 'color-scheme:light' not in stylesheet
    assert '.dei-theme-toggle' not in stylesheet
    assert '.dei-theme-standalone' not in stylesheet


def test_health_is_visible_and_restores_summary_visuals() -> None:
    health_xml = (VIEWS / "detection_health.xml").read_text(encoding="utf-8")
    health_js = (STATIC / "detection_health_v1.js").read_text(encoding="utf-8")
    assert 'href="detection_health">Health</a>' in health_xml
    for element_id in (
        "health-donut", "health-donut-total", "health-ready-percent",
        "health-ready-bar", "health-ready-label",
    ):
        assert f'id="{element_id}"' in health_xml
    assert 'role="progressbar"' in health_xml
    assert 'role="img"' in health_xml
    assert '"--health-healthy"' in health_js
    assert 'aria-valuenow' in health_js


def test_every_primary_workspace_links_directly_to_health() -> None:
    for name in (
        "command_center", "environment_insights", "mitre_coverage",
        "mitre_heatmap", "detection_workflow", "detection_catalog",
        "detection_action_center", "detection_health",
    ):
        source = (VIEWS / f"{name}.xml").read_text(encoding="utf-8")
        assert 'href="detection_health">Health</a>' in source, name
    home = (VIEWS / "dei_home.xml").read_text(encoding="utf-8")
    assert 'href="detection_health">Detection Health</a>' in home


def test_global_workflow_ribbon_is_home_only() -> None:
    javascript = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    assert 'if (!shell().is("#dei-home-page")) { return; }' in javascript
    assert 'if (!$("#dei-guided-workflow").length) { return; }' in javascript
    assert '#dei-command-center,#dei-environment-insights,#dei-mitre-page,#dei-guided-detection-page' in javascript
    assert '$("#dei-active-scan-context").remove()' in javascript


def test_health_metric_actions_use_the_shared_dark_control_design() -> None:
    view = (VIEWS / "detection_health_detail.xml").read_text(encoding="utf-8")
    stylesheet = (STATIC / "detection_health_controls_v1.css").read_text(encoding="utf-8")
    assert 'class="dei-health-detail-actions"' in view
    assert "detection_health_controls_v1.css" in view
    assert ".dei-health-detail-actions #health-detail-refresh" in stylesheet
    assert "var(--dei-surface-2)" in stylesheet


def test_mitre_workspace_is_detection_first_and_recommends_improvements() -> None:
    view = (VIEWS / "mitre_coverage.xml").read_text(encoding="utf-8")
    javascript = (STATIC / "mitre_workspace_v3.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "mitre_workspace_readability.css").read_text(encoding="utf-8")
    assert "dei-mitre-selection-strip" in view
    assert '"not-applicable"' in javascript
    assert "Recommended detection improvements" in javascript
    assert "Based on the selected mapping, readiness state, and observed log sources" in javascript
    assert ".dei-mitre-linear-layout" in stylesheet


def test_deep_links_open_nested_lifecycle_evidence_smoothly() -> None:
    javascript = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    assert 'target.parents("details").prop("open",true)' in javascript
    assert "scrollIntoView({behavior:\"smooth\",block:\"center\"})" in javascript
    assert "scroll-margin-top:24px" in stylesheet
