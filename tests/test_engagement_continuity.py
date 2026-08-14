"""Contracts for resumable, per-user DEI engagement workflows."""

from pathlib import Path
from xml.etree import ElementTree

APP = Path("app")
STATIC = APP / "appserver/static"
VIEWS = APP / "default/data/ui/views"


def test_saved_filters_cover_primary_return_workspaces() -> None:
    source = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    for page in ("coverage", "catalog", "health", "health_detail", "action_center"):
        assert f"{page}:[" in source
    for selector in (
        "#mitre-filter", "#lifecycle-assignment", "#catalog-status-filter",
        "#action-readiness", "#health-state", "#health-detection-filter",
    ):
        assert selector in source
    assert "Saved filters restored" in source
    assert "Filters save automatically for your next visit" in source
    assert "saveWorkspacePosition" in source
    assert "restoreWorkspacePosition" in source
    assert 'resource:"preferences"' in source
    assert "hydrateEngagement" in source


def test_builder_recovery_never_claims_to_be_a_governed_save() -> None:
    source = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    for contract in (
        "dei.builderRecovery.v1", "Recovered work", "not an official lifecycle save",
        "Restore recovered SPL", "Compare with current", "Discard recovery",
        "Recovered query restored", "dei:detection-artifact-saved",
    ):
        assert contract in source
    assert "clearDraftRecovery()" in source


def test_home_resume_activity_and_completion_guidance_are_packaged() -> None:
    source = (STATIC / "dei_workspace_layout_v14.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "dei_workspace_layout_v1.css").read_text(encoding="utf-8")
    for contract in (
        "Continue where you left off", "Recent activity", "Engineering history",
        "Lifecycle progress saved", "Current stage:", "Environment scan completed",
    ):
        assert contract in source
    for selector in (
        ".dei-engagement-home", ".dei-resume-work", ".dei-recent-activity",
        ".dei-engagement-confirmation", ".dei-scan-change-summary",
    ):
        assert selector in stylesheet


def test_lifecycle_records_accept_accountable_ownership_and_due_dates() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    catalog = ElementTree.parse(VIEWS / "detection_catalog.xml").getroot()
    for field in (
        "lifecycle-owner", "lifecycle-reviewer", "lifecycle-review-due",
        "lifecycle-health-due", "lifecycle-assignment",
    ):
        assert catalog.find(f".//*[@id='{field}']") is not None if field == "lifecycle-assignment" else field in lifecycle
    for contract in ("Owned by me", "Awaiting my review", "Overdue work"):
        assert contract in ElementTree.tostring(catalog, encoding="unicode")
    assert "record.ownership=" in lifecycle
    assert 'assignment==="overdue"' in lifecycle
    assert 'data-action="save_assignment"' in lifecycle
    assert '"work_assignment_updated"' in lifecycle


def test_help_explains_safe_resume_behavior() -> None:
    help_source = (VIEWS / "dei_help.xml").read_text(encoding="utf-8")
    for contract in (
        'id="help-resume-work"', "Saved filters:", "Recovered query:",
        "not a governed lifecycle save", "Owned by me", "Awaiting my review",
    ):
        assert contract in help_source


def test_user_preferences_are_durable_when_kv_store_is_available() -> None:
    handler = (APP / "bin/dei/api/storage_handler.py").read_text(encoding="utf-8")
    collections = (APP / "default/collections.conf").read_text(encoding="utf-8")
    assert 'USER_PREFERENCES = "dei_user_preferences"' in handler
    assert 'resource == "preferences" and operation == "read"' in handler
    assert "store.upsert(USER_PREFERENCES, record)" in handler
    assert "[dei_user_preferences]" in collections
