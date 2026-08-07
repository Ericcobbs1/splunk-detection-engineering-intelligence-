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
    assert root.attrib["stylesheet"] == (
        "command_center_v2.css,mitre_workspace.css,mitre_workspace_readability.css"
    )
    for element_id in (
        "dei-mitre-page", "mitre-data-status", "mitre-analysis-age", "mitre-filter",
        "mitre-readiness-filter", "mitre-detection-list", "mitre-matrix",
        "mitre-covered-tactics", "mitre-inspector-title", "mitre-inspector-body",
        "mitre-coverage-donut", "mitre-coverage-percent", "mitre-portfolio-covered",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None

    matrix = root.find(".//*[@class='dei-mitre-matrix-pane']")
    inspector = root.find(".//*[@class='dei-mitre-inspector']")
    content = root.find(".//*[@class='dei-mitre-content']")
    assert matrix is not None and inspector is not None and content is not None
    assert list(content).index(matrix) < list(content).index(inspector)


def test_mitre_workspace_includes_current_enterprise_matrix_context() -> None:
    javascript = (STATIC_ROOT / "mitre_workspace.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "mitre_workspace.css").read_text(encoding="utf-8")
    readability = (STATIC_ROOT / "mitre_workspace_readability.css").read_text(encoding="utf-8")
    assert 'id:"TA0043", name:"Reconnaissance", count:12' in javascript
    assert 'id:"TA0005", name:"Stealth", count:30' in javascript
    assert 'id:"TA0112", name:"Defense Impairment", count:18' in javascript
    assert 'id:"TA0007", name:"Discovery", count:34' in javascript
    assert 'id:"TA0040", name:"Impact", count:15' in javascript
    assert '"T1110.003"' in javascript
    assert '"T1098"' in javascript
    assert '"T1562.008"' in javascript
    assert 'currentId:"T1685.002"' in javascript
    assert "Bundled ATT&CK reference reviewed" in javascript
    assert "Detection guidance" in javascript
    assert "Mitigation themes" in javascript
    assert "The live MITRE record is authoritative" in javascript
    assert "Open live MITRE ATT&amp;CK" in javascript
    assert "renderPortfolioCoverage" in javascript
    assert "actionable[item.readiness]" in javascript
    assert "dei.latestRecommendationReport" in javascript
    assert ".dei-mitre-layout" in stylesheet
    assert "grid-template-columns:290px minmax(0,1fr)" in stylesheet
    assert ".dei-mitre-content" in stylesheet
    assert ".dei-mitre-matrix" in stylesheet
    assert "repeat(15,minmax(142px,1fr))" in stylesheet
    assert ".dei-coverage-donut" in stylesheet
    assert "conic-gradient" in stylesheet
    assert ".dei-attack-live-button" in stylesheet
    assert "deiMitrePulse" in stylesheet
    assert "prefers-reduced-motion" in stylesheet

    # Readability overrides prevent the lower inspector from being clipped by
    # a viewport-height grid while keeping the matrix itself compact.
    assert ".dei-mitre-page" in readability
    assert "height: auto" in readability
    assert "overflow: visible" in readability
    assert ".dei-mitre-matrix-pane" in readability
    assert "height: 480px" in readability
    assert ".dei-mitre-inspector-body" in readability
    assert "max-height: none" in readability
    assert "position: sticky" in readability
