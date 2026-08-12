"""Contracts for the simplified customer navigation and accessible visual system."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
VIEWS = APP / "default/data/ui/views"
STATIC = APP / "appserver/static"


def test_customer_navigation_exposes_five_clear_destinations() -> None:
    for view_name in ("command_center", "environment_insights", "mitre_coverage", "detection_workflow"):
        root = ElementTree.parse(VIEWS / f"{view_name}.xml").getroot()
        nav = root.find(".//nav[@class='dei-workspace-nav']")
        assert nav is not None
        assert [(item.text, item.attrib["href"]) for item in nav.findall("a")] == [
            ("Home", "dei_home"), ("Discover", "command_center"),
            ("Coverage", "mitre_coverage"), ("Build", "detection_workflow"),
            ("Operate", "detection_operations"),
        ]


def test_customer_pages_load_shared_readable_design_system() -> None:
    for view_name in (
        "command_center", "environment_insights", "mitre_coverage", "detection_workflow",
        "detection_lifecycle", "detection_operations", "detection_catalog",
        "detection_action_center", "detection_health", "detection_builder",
    ):
        root = ElementTree.parse(VIEWS / f"{view_name}.xml").getroot()
        assert "dei_design_system_v1.css" in root.attrib["stylesheet"].split(",")
    css = (STATIC / "dei_design_system_v1.css").read_text(encoding="utf-8")
    for contract in (
        "--dei-border-interactive:#536b82", "--dei-focus:#75e5cf",
        "font-size:14px", "outline:3px solid var(--dei-focus)",
        ".dei-status-symbol:before", ".dei-workspace-disclosure",
    ):
        assert contract in css


def test_high_density_reference_content_uses_progressive_disclosure() -> None:
    environment = ElementTree.parse(VIEWS / "environment_insights.xml").getroot()
    lifecycle = ElementTree.parse(VIEWS / "detection_lifecycle.xml").getroot()
    assert environment.find(".//details[@id='dei-telemetry-change-section']") is not None
    assert environment.find(".//details[@id='dei-portfolio-section']") is not None
    assert lifecycle.find(".//details[@class='dei-workspace-disclosure dei-lifecycle-evidence-summary']") is not None
    assert lifecycle.find(".//section[@class='dei-lifecycle-metrics dei-lifecycle-core-metrics']") is not None
