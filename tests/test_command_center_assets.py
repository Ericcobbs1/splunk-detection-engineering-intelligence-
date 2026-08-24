"""Regression tests for the packaged DEI command center assets."""

from pathlib import Path
from xml.etree import ElementTree

APP_ROOT = Path("app")
VIEW_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "command_center.xml"
INSIGHTS_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "environment_insights.xml"
NAV_PATH = APP_ROOT / "default" / "data" / "ui" / "nav" / "default.xml"
STATIC_ROOT = APP_ROOT / "appserver" / "static"


def test_command_center_view_is_valid_and_references_assets() -> None:
    root = ElementTree.parse(VIEW_PATH).getroot()
    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert root.attrib["script"] == (
        "dashboard_state_v2.js,command_center.js,analysis_bridge.js,"
        "environment_intelligence_v2.js,dei_environment_scan_v1.js,dei_guide_adapter_v8.js,dei_workspace_layout_v14.js,dei_theme_v1.js"
    )
    assert root.attrib["stylesheet"] == (
        "command_center_v2.css,environment_intelligence.css,environment_intelligence_v2.css,"
            "dei_visual_polish_v1.css,dei_workspace_layout_v1.css,dei_guided_tour_v6.css,dei_responsive_v1.css,dei_design_system_v2.css,dei_theme_v1.css"
    )
    for element_id in (
        "dei-command-center", "dei-telemetry", "dei-sources", "dei-es-enabled",
        "dei-discovery-window", "dei-window-note", "dei-source-summary",
        "dei-analyze", "dei-feedback", "dei-discovery-next",
        "dei-discovery-result-state", "dei-discovery-next-summary",
        "dei-review-scan-results", "dei-open-environment-insights",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None
    for moved_id in (
        "dei-portfolio-section", "dei-coverage-section",
        "metric-sources", "dei-refresh-environment", "dei-clear-environment",
    ):
        assert root.find(f".//*[@id='{moved_id}']") is None
    source_inventory = root.find(".//*[@id='dei-sources']")
    assert source_inventory is not None
    assert source_inventory.attrib["readonly"] == "readonly"
    next_step = root.find(".//*[@id='dei-discovery-next']")
    assert next_step is not None
    assert next_step.attrib["hidden"] == "hidden"
    assert root.find(".//a[@href='mitre_coverage']") is not None
    assert root.find(".//a[@href='detection_workflow']") is not None


def test_completed_scan_reveals_an_explicit_next_step() -> None:
    javascript = (STATIC_ROOT / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    assert 'next.prop("hidden",!ready)' in javascript
    assert '"The scan generated "+recommendationCount+" detection recommendation"' in javascript
    assert '$("#dei-review-scan-results").toggleClass("ready",ready)' in javascript
    assert ".dei-discovery-next[hidden]" in stylesheet
    assert "#dei-review-scan-results.ready" in stylesheet


def test_environment_insights_contains_saved_results_without_discovery_form() -> None:
    root = ElementTree.parse(INSIGHTS_PATH).getroot()
    assert root.tag == "form"
    assert root.attrib["script"] == (
        "dashboard_state_v2.js,command_center.js,analysis_bridge.js,"
        "environment_intelligence_v2.js,dei_environment_scan_v1.js,dei_guide_adapter_v8.js,dei_workspace_layout_v14.js,dei_theme_v1.js"
    )
    assert root.attrib["stylesheet"] == (
        "command_center_v2.css,environment_intelligence.css,environment_intelligence_v2.css,"
        "dei_telemetry_change_v1.css,dei_visual_polish_v1.css,dei_workspace_layout_v1.css,"
            "dei_guided_tour_v6.css,dei_responsive_v1.css,dei_design_system_v2.css,dei_theme_v1.css"
    )
    for element_id in (
        "dei-environment-insights", "metric-sources",
        "metric-understanding", "metric-ready", "metric-partial", "metric-potential",
        "dei-portfolio-section", "portfolio-total", "portfolio-ready",
        "portfolio-partial", "portfolio-field-gaps", "portfolio-unverified",
        "dei-coverage-section", "environment-snapshot-age",
        "dei-clear-environment", "dei-refresh-environment", "coverage-ring",
        "coverage-domains", "env-tactics-covered", "env-tactics-partial",
        "env-tactics-uncovered", "env-tactic-donut", "env-top-domains",
        "env-domain-donut", "env-domain-count", "env-domain-legend",
        "env-tactic-bars", "env-index-count", "env-source-count",
        "env-event-count", "env-detection-count", "env-es-state",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None
    assert root.find(".//*[@id='dei-telemetry']") is None
    assert root.find(".//*[@id='dei-analyze']") is None
    assert root.find(".//a[@href='command_center#dei-telemetry']") is not None

def test_dei_home_is_default_navigation_view_and_workspaces_are_registered() -> None:
    root = ElementTree.parse(NAV_PATH).getroot()
    home = root.find("./view[@name='dei_home']")
    assert home is not None
    assert home.attrib["default"] == "true"
    assert root.find(".//view[@name='command_center']") is not None
    assert root.find(".//view[@name='mitre_coverage']") is not None
    assert root.find(".//view[@name='detection_lifecycle']") is None


def test_command_center_static_assets_are_packaged() -> None:
    javascript = (STATIC_ROOT / "command_center.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "command_center_v2.css").read_text(encoding="utf-8")
    bridge = (STATIC_ROOT / "analysis_bridge.js").read_text(encoding="utf-8")
    persistence = (STATIC_ROOT / "dashboard_state_v2.js").read_text(encoding="utf-8")
    environment_css = (STATIC_ROOT / "environment_intelligence.css").read_text(encoding="utf-8")
    premium_js = (STATIC_ROOT / "environment_intelligence_v2.js").read_text(encoding="utf-8")
    premium_css = (STATIC_ROOT / "environment_intelligence_v2.css").read_text(encoding="utf-8")
    polish_css = (STATIC_ROOT / "dei_visual_polish_v1.css").read_text(encoding="utf-8")
    assert "Splunk.util.make_url.apply(" in javascript
    assert '"servicesNS"' in javascript
    assert '"splunk_detection_engineering_intelligence"' in javascript
    assert '"recommendations"' in javascript
    assert '"health"' in javascript
    assert '"X-Splunk-Form-Key"' in javascript
    assert 'Splunk.util.getConfigValue("FORM_KEY")' in javascript
    assert '"search", "jobs", "export"' in javascript
    assert '"splunkjs/mvc/searchmanager"' not in javascript
    assert "| tstats count latest(_time) AS last_seen" in javascript
    assert 'earliest=-"+days+"d latest=now' in javascript
    assert 'NOT match(index, "^_")' in javascript
    assert "selectedWindowDays" in javascript
    assert "windowDays:selectedWindowDays()" in javascript
    assert "[ACTIVE]" in javascript
    assert "[STALE]" in javascript
    assert 'output_mode: "json"' in javascript
    assert "fieldDiscoveryConcurrency = 6" in javascript
    assert "fieldSearchTimeoutMs = 12000" in javascript
    assert "fieldDiscoveryTimeoutMs = 90000" in javascript
    assert "| fieldsummary" in javascript
    assert "fields_by_source" in javascript
    assert "Profiling fields 0/" in javascript
    assert "Field profiling reached its 90-second ceiling" in javascript
    assert "Telemetry inventory timed out after 20 seconds." in javascript
    assert "renderPortfolio" in javascript
    assert ".dei-shell" in stylesheet
    assert "--dei-accent" in stylesheet
    assert ".dei-product-bar" in stylesheet
    assert "scroll-behavior: smooth" in stylesheet
    assert "ajaxSuccess" in bridge
    assert "dei.latestRecommendationReport" in bridge
    assert "dei.latestDiscoveryExport" in persistence
    assert "forceRefresh" in persistence
    assert "window.sessionStorage" in persistence
    assert 'discoverEnvironment(false);' not in javascript
    assert "Run intelligence scan" in javascript
    assert "renderSavedReport" in persistence
    assert "No scan data is loaded" in persistence
    assert "setGlobalRefreshState" in persistence
    assert "clearPersistedDashboard" in persistence
    assert 'CLEAR_KEY = "dei.dashboardCleared"' in persistence
    assert "activeEnvironmentRequests" in persistence
    assert "request.abort()" in persistence
    assert 'window.sessionStorage.removeItem(key)' in persistence
    assert '$(document).trigger("dei:environment-cleared")' in persistence
    assert '$(document).trigger("dei:environment-refresh-started")' in persistence
    assert '$(document).trigger("dei:environment-refreshed", [payload])' in persistence
    assert 'window.sessionStorage.setItem(REPORT_TIME_KEY, String(Date.now()))' in persistence
    assert ".dei-environment-grid" in environment_css
    assert ".dei-refresh-button" in environment_css
    assert "TECHNIQUE_TACTICS" in premium_js
    assert "tacticData" in premium_js
    assert "readinessWeight" in premium_js
    assert "parsed.count" in premium_js
    assert "env-event-count" in premium_js
    assert "renderDomains" in premium_js
    assert "renderTactics" in premium_js
    assert 'function render(reportOverride)' in premium_js
    assert "resetPremiumDashboard" in premium_js
    assert '.on("dei:environment-cleared"' in premium_js
    assert '.on("dei:environment-refreshed"' in premium_js
    assert '.on("dei:environment-refresh-started"' in premium_js
    assert ".dei-env-summary-card" in premium_css
    assert "grid-template-columns:1.05fr 1.35fr .9fr .9fr" in premium_css
    assert ".dei-env-detail-grid" in premium_css
    assert ".dei-tactic-bars" in premium_css
    assert ".dei-domain-donut" in premium_css
    assert ".dei-mitre-glow-button" in premium_css
    assert '"Splunk Platform Sans"' in polish_css
    assert '"Splunk Data Sans"' in polish_css
    assert "@keyframes deiCoreBreath" in polish_css
    assert "@keyframes deiSignalWave" in polish_css
    assert ".dei-orbit-one" in polish_css
    assert "prefers-reduced-motion" in polish_css
    assert "Enterprise Security-style readable type scale" in polish_css
    assert ".dei-metric span { font-size: 13px; }" in polish_css
    assert ".dei-env-card-head p { font-size: 12px; }" in polish_css
    assert ".dei-env-mitre-cta h3" in polish_css
    assert "font-size: 18px" in polish_css
    assert "font-size: 14px" in polish_css
    assert "-webkit-font-smoothing: auto" in polish_css
    assert ".dei-clear-button-v2" in premium_css


def test_official_home_is_focused_on_pipeline_and_workspace_actions() -> None:
    home_path = APP_ROOT / "default" / "data" / "ui" / "views" / "dei_home.xml"
    root = ElementTree.parse(home_path).getroot()
    assert root.attrib["script"] == "dei_environment_scan_v1.js,dei_lifecycle_store_v1.js,dei_guide_adapter_v8.js,dei_workspace_layout_v12.js,dei_home_globe_react_v1.js,dei_theme_v1.js"
    assert "dei_workspace_layout_v1.css" in root.attrib["stylesheet"]
    for element_id in (
        "dei-home-page", "dei-home-pipeline", "dei-home-flow-title",
        "dei-home-detection-flow", "dei-home-flow-status",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None
    assert root.find(".//*[@class='dei-product-bar']") is None
    assert root.find(".//a[@href='detection_catalog#lifecycle-map']") is not None
    assert root.find(".//*[@id='dei-telemetry']") is None
    assert root.find(".//*[@id='dei-portfolio-section']") is None
    assert root.find(".//*[@id='dei-coverage-section']") is None
