"""Regression tests for the Splunk review checkpoint."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SCRIPT = ROOT / "tools" / "package_app.sh"
REVIEW_GUIDE = ROOT / "docs" / "SPLUNK_REVIEW_CHECKPOINT.md"


def test_package_script_builds_a_spl_archive() -> None:
    script = PACKAGE_SCRIPT.read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert "splunk_detection_engineering_intelligence" in script
    assert "tar -czf" in script
    assert "dist/" not in script  # destination is assembled safely from ROOT_DIR


def test_review_guide_covers_installation_and_validation() -> None:
    guide = REVIEW_GUIDE.read_text(encoding="utf-8")

    assert "Install app from file" in guide
    assert "Analyze environment" in guide
    assert "Enterprise Security" in guide
    assert "/services/dei/v1/health" in guide
    assert "Known checkpoint limitations" in guide
