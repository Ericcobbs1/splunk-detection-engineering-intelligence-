"""Regression tests for the packaged DEI command center assets."""

from pathlib import Path
from xml.etree import ElementTree

APP_ROOT = Path("app")
VIEW_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "command_center.xml"
NAV_PATH = APP_ROOT / "default" / "data" / "ui" / "nav" / "default.xml"
STATIC_ROOT = APP_ROOT / "appserver" / "static"


def test_command_center_view_is_valid_and_references_assets() -> None:
    root = ElementTree.parse(VIEW_PATH).getroot()

    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert root.attrib["script"] == "command_center.js"
    assert root.attrib["stylesheet"] == "command_center.css"
    assert root.find(".//*[@id='dei-command-center']") is not None


def test_command_center_is_default_navigation_view() -> None:
    root = ElementTree.parse(NAV_PATH).getroot()
    command_center = root.find("./view[@name='command_center']")

    assert command_center is not None
    assert command_center.attrib["default"] == "true"


def test_command_center_static_assets_are_packaged() -> None:
    javascript = (STATIC_ROOT / "command_center.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "command_center.css").read_text(encoding="utf-8")

    assert 'Splunk.util.make_url(' in javascript
    assert '"recommendations"' in javascript
    assert '"health"' in javascript
    assert "#dei-analyze" in javascript
    assert ".dei-shell" in stylesheet
    assert "--dei-accent" in stylesheet
