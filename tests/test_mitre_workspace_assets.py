"""Regression tests for the dedicated MITRE ATT&CK workspace."""

from pathlib import Path
from xml.etree import ElementTree

APP_ROOT = Path("app")
VIEW_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "mitre_coverage.xml"
STATIC_ROOT = APP_ROOT / "appserver" / "static"


def test_mitre_workspace_view_is_valid_and_contained() -> None:
    root = ElementTree.parse(VIEW_PATH).getroot()
    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert root.attrib["script"] == "mitre_workspace.js"
    assert root.attrib["stylesheet"] == "command_center_v2.css,mitre_workspace.css"
    for element_id in (
        "dei-mitre-page", "mitre-data-status", "mitre-analysis-age", "mitre-filter",
        "mitre-readiness-filter", "mitre-detection-list", "mitre-matrix",
        "mitre-covered-tactics", "mitre-inspector-title", "mitre-inspector-body",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None


def test_mitre_workspace_includes_current_enterprise_matrix_context() -> None:
    javascript = (STATIC_ROOT / "mitre_workspace.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "mitre_workspace.css").read_text(encoding="utf-8")
    assert 'id:"TA0043", name:"Reconnaissance", count:12' in javascript
    assert 'id:"TA0005", name:"Stealth", count:30' in javascript
    assert 'id:"TA0112", name:"Defense Impairment", count:18' in javascript
    assert 'id:"TA0007", name:"Discovery", count:34' in javascript
    assert 'id:"TA0040", name:"Impact", count:15' in javascript
    assert '"T1110.003"' in javascript
    assert '"T1098"' in javascript
    assert '"T1562.008"' in javascript
    assert "Sub-technique of" in javascript
    assert "Open selected technique on MITRE ATT&CK" in javascript
    assert "What this protects" in javascript
    assert "dei.latestRecommendationReport" in javascript
    assert ".dei-mitre-layout" in stylesheet
    assert "grid-template-columns:290px minmax(620px,1fr) 360px" in stylesheet
    assert ".dei-mitre-matrix" in stylesheet
    assert "repeat(15,minmax(142px,1fr))" in stylesheet
