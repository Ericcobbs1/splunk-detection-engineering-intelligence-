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
        "help-deploy", "help-monitor", "help-tune", "help-retire",
        "help-troubleshoot",
    ):
        assert f'id="{topic}"' in source
    for guidance in (
        "Settings → Searches, Reports, and Alerts",
        "Configure → Content → Content Management",
        "Zero results can be healthy",
        "does not disable the actual Splunk saved search",
        "observed problem; supporting evidence; proposed change",
    ):
        assert guidance in source


def test_theme_switch_is_persistent_accessible_and_independent_of_workflow() -> None:
    javascript = (STATIC / "dei_theme_v1.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "dei_theme_v1.css").read_text(encoding="utf-8")
    assert 'KEY="dei.colorScheme"' in javascript
    assert 'window.localStorage.setItem(KEY,value)' in javascript
    assert 'id="dei-theme-toggle"' in javascript
    assert 'aria-pressed' in javascript
    assert 'data-dei-theme' in javascript
    assert '[data-dei-theme="dark"]' in stylesheet
    assert '[data-dei-theme="light"]' in stylesheet
    assert "--dei-action:#4f8df7" in stylesheet
    assert "--dei-success:#42c7a5" in stylesheet
    assert "--dei-warning:#e8ad4f" in stylesheet
    assert "--dei-danger:#ef6673" in stylesheet


def test_every_canonical_workspace_loads_theme_assets_last() -> None:
    canonical = (
        "dei_home", "command_center", "environment_insights", "mitre_coverage",
        "mitre_heatmap", "detection_workflow", "detection_catalog",
        "detection_health", "detection_action_center", "dei_help",
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
