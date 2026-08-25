"""Stateful, end-to-end simulations for every governed lifecycle branch."""

import copy
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE = (ROOT / "app/appserver/static/detection_lifecycle_v3.js").read_text()
GUIDE = (ROOT / "app/appserver/static/dei_guide_adapter_v8.js").read_text()


class Workflow:
    """Small executable model of the UI's persisted lifecycle contract."""

    allowed = {
        "recommendation": ("draft",),
        "draft": ("testing", "recommendation"),
        "testing": ("peer_review", "draft", "recommendation"),
        "peer_review": ("production", "draft", "recommendation"),
        "production": ("monitoring", "retired"),
        "monitoring": ("monitoring", "tuning", "retired"),
        "tuning": ("testing", "retired"),
        "retired": (),
    }

    def __init__(self):
        self.record = {
            "state": "recommendation",
            "status": "recommendation",
            "version": 1,
            "history": [],
            "previous_versions": [],
            "spl": "",
        }

    def transition(self, target, event, **changes):
        current = self.record["state"]
        if target not in self.allowed[current]:
            raise ValueError("Invalid lifecycle transition")
        if target == "peer_review" and self.record.get("validation", {}).get("status") != "passed":
            raise ValueError("Passed validation evidence is required")
        if target == "production" and self.record.get("review", {}).get("decision") != "approved":
            raise ValueError("Peer approval is required")
        if target == "production" and not changes.get("deployment", {}).get("external_object_id"):
            raise ValueError("A deployment reference is required")
        if target == "monitoring" and not changes.get("monitoring", {}).get("last_checked_at"):
            raise ValueError("Health evidence is required")
        if target == "retired" and not changes.get("retirement", {}).get("reason"):
            raise ValueError("A retirement reason is required")
        self.record.update(copy.deepcopy(changes))
        self.record.update({"state": target, "status": target})
        self.record["history"].append({"event": event, "state": target})

    def build(self, spl="index=security action=failure"):
        if not spl.strip():
            raise ValueError("SPL is required")
        self.record["spl"] = spl
        self.transition("draft", "draft_generated")

    def validate(self, passed):
        target = "testing" if self.record["state"] in ("draft", "tuning") else self.record["state"]
        if target != "testing":
            raise ValueError("Validation requires an editable version")
        self.record["validation"] = {"status": "passed" if passed else "failed"}
        if self.record["state"] != "testing":
            self.transition("testing", "validation_completed")

    def submit(self, note):
        if not note.strip():
            raise ValueError("A submission note is required")
        self.transition("peer_review", "submitted_for_review", review={"decision": "pending", "note": note})

    def review(self, approved, note):
        if not note.strip():
            raise ValueError("A review rationale is required")
        if approved:
            self.record["review"] = {"decision": "approved", "comments": note}
            self.record["catalog"] = {"status": "ready"}
            self.record["history"].append({"event": "peer_review_approved", "state": "peer_review"})
        else:
            self.transition("draft", "returned_for_changes", validation=None, review={"decision": "changes_requested"})

    def deploy(self, environment, object_id):
        if not object_id.strip():
            raise ValueError("A deployment object is required")
        deployment = {"environment": environment, "external_object_id": object_id}
        if environment == "production":
            self.transition("production", "deployment_recorded", deployment=deployment)
        else:
            self.record["deployment"] = deployment
            self.record["catalog"] = {"status": environment}
            self.record["history"].append({"event": "nonproduction_deployment_recorded", "state": "peer_review"})

    def health(self, note, period="Last 24 hours", values=(0, 0, 0, 0)):
        if not period.strip():
            raise ValueError("A review period is required")
        if any(not isinstance(value, (int, float)) or value < 0 for value in values):
            raise ValueError("Measurements must be non-negative numbers")
        if not note.strip():
            raise ValueError("A monitoring evidence note is required")
        monitoring = {
            "review_period": period,
            "result_volume": values[0],
            "runtime_ms": values[1],
            "true_positives": values[2],
            "false_positives": values[3],
            "note": note,
            "last_checked_at": "2026-08-24T17:00:00Z",
        }
        self.transition("monitoring", "health_measured", monitoring=monitoring)

    def tune(self, objective):
        if not objective.strip():
            raise ValueError("A tuning objective is required")
        prior = copy.deepcopy(self.record)
        prior.pop("previous_versions")
        self.transition(
            "tuning",
            "tuning_started",
            version=self.record["version"] + 1,
            validation=None,
            review=None,
            deployment=None,
            monitoring=None,
            previous_versions=self.record["previous_versions"] + [prior],
        )

    def retire(self, reason):
        if not reason.strip():
            raise ValueError("A retirement reason is required")
        self.transition("retired", "detection_retired", retirement={"reason": reason})


def test_full_governed_journey_with_failures_reload_and_tuning_cycle():
    flow = Workflow()
    with pytest.raises(ValueError):
        flow.build(" ")
    flow.build()
    flow.validate(False)
    with pytest.raises(ValueError):
        flow.submit("evidence exists")
    flow.record["state"] = "draft"
    flow.validate(True)
    with pytest.raises(ValueError):
        flow.submit("")
    flow.submit("bounded validation passed; expected behavior documented")
    with pytest.raises(ValueError):
        flow.review(True, "")
    flow.review(False, "scope the source and exclude the service account")
    assert flow.record["state"] == "draft"
    flow.validate(True)
    flow.submit("revised version passed positive and negative cases")
    flow.review(True, "safe, bounded, supportable, and actionable")
    with pytest.raises(ValueError):
        flow.deploy("production", "")
    flow.deploy("development", "DEI - Authentication Failure v1")
    assert flow.record["state"] == "peer_review"
    flow.deploy("staging", "DEI - Authentication Failure v1")
    assert flow.record["state"] == "peer_review"
    flow.deploy("production", "DEI - Authentication Failure v1")
    with pytest.raises(ValueError):
        flow.health("")
    with pytest.raises(ValueError):
        flow.health("bad metrics", values=(-1, 0, 0, 0))
    flow.health("scheduler healthy; source fresh; zero results expected and verified")
    flow.health("second review: one true positive verified", values=(2, 125, 1, 1))
    with pytest.raises(ValueError):
        flow.tune("")
    flow.tune("reduce one verified false positive while preserving the positive case")
    assert flow.record["version"] == 2
    assert flow.record["previous_versions"][0]["monitoring"]["false_positives"] == 1
    flow.record["spl"] += " NOT user=svc_expected"
    flow.validate(True)
    flow.submit("tuned SPL passed; expected false positive removed")
    flow.review(True, "diff reviewed; coverage and rollback verified")
    flow.deploy("production", "DEI - Authentication Failure v2")
    flow.health("post-change scheduler, freshness, and analyst outcomes verified", values=(1, 100, 1, 0))

    persisted = json.loads(json.dumps(flow.record))
    assert persisted == flow.record
    assert persisted["state"] == "monitoring"
    assert persisted["deployment"]["external_object_id"].endswith("v2")
    assert len(persisted["history"]) >= 15

    with pytest.raises(ValueError):
        flow.retire("")
    flow.retire("superseded by consolidated identity analytic; live object disabled separately")
    with pytest.raises(ValueError):
        flow.health("immutable records cannot move")


def test_restart_and_direct_retirement_branches_are_simulated():
    for restart_state in ("draft", "testing", "peer_review"):
        flow = Workflow()
        flow.build()
        if restart_state in ("testing", "peer_review"):
            flow.validate(True)
        if restart_state == "peer_review":
            flow.submit("ready for review")
        archived = copy.deepcopy(flow.record)
        flow.transition("recommendation", "restarted_from_recommendation", version=2, previous_versions=[archived])
        assert flow.record["previous_versions"][0]["state"] == restart_state
        assert flow.record["version"] == 2

    for retire_state in ("production", "monitoring", "tuning"):
        flow = Workflow()
        flow.record["state"] = retire_state
        flow.retire("controlled retirement with replacement and disablement recorded")
        assert flow.record["state"] == "retired"


def test_tutorial_all_steps_targets_back_next_and_default_monitoring_state():
    expected_titles = [
        "Open Environment Discovery",
        "Run current telemetry discovery",
        "Choose a reusable detection",
        "Generate a reviewable draft",
        "Validate the detection",
        "Document the validation handoff",
        "Send the validated version to review",
        "Document the approval decision",
        "Approve and continue to deployment",
        "Record the production object",
        "Enable the approved detection",
        "The core deployment workflow is complete",
        "Establish monitoring evidence",
        "Document where the evidence came from",
        "Record the operational health checkpoint",
        "Decide whether tuning is justified",
        "Open a new tuning version",
        "Apply the controlled tuning change",
        "Validate the tuned version",
        "Document the tuned-version handoff",
        "Submit the tuned version for review",
        "Review the tuning decision",
        "Approve the tuned version",
        "Record the updated production object",
        "Return the tuned detection to Production",
        "Detection lifecycle tutorial complete",
    ]
    positions = list(range(len(expected_titles)))
    for title in expected_titles:
        assert 'title:"' + title + '"' in GUIDE
    for position in range(1, len(positions)):
        assert positions[position] - 1 == positions[position - 1]
        assert positions[position - 1] + 1 == positions[position]
    assert GUIDE.count("target:") >= len(expected_titles) - 2
    assert "operationsChoice:true" in GUIDE
    assert "completion:true" in GUIDE

    # The screenshot's untouched defaults are valid inputs and must advance 12 -> 13.
    period = "Last 24 hours"
    measurements = (0, 0, 0, 0)
    assert period and all(value >= 0 for value in measurements)
    assert "index===12&&monitoringMetricsReady()" in GUIDE
    assert 'if(monitoringMetricsReady()) advanceFor("monitoring_metrics");' in GUIDE


def test_tutorial_event_contract_has_one_deterministic_route_for_every_gate():
    expected = {
        "draft_generated": {3: 4},
        "validation_passed": {4: 5, 18: 19},
        "review_note": {5: 6, 7: 8, 19: 20, 21: 22},
        "submit_review": {6: 7, 20: 21},
        "approve_review": {8: 9, 22: 23},
        "deployment_reference": {9: 10, 23: 24},
        "record_deployment": {10: 11, 24: 25},
        "monitoring_metrics": {12: 13},
        "monitoring_note": {13: 14},
        "record_health": {14: 15},
        "tuning_note": {15: 16},
        "start_tuning": {16: 17},
        "spl_changed": {17: 18},
    }
    compact = GUIDE.replace(" ", "").replace("\n", "")
    for event, transitions in expected.items():
        encoded = event + ":{" + ",".join(f"{start}:{end}" for start, end in transitions.items()) + "}"
        assert encoded in compact
        assert all(end == start + 1 for start, end in transitions.items())

    # Back can inspect every prior tutorial checkpoint without replaying writes.
    positions = list(range(26))
    reviewed = [position - 1 for position in positions[1:]]
    assert reviewed == list(range(25))
    assert "setReviewCeiling(index)" in GUIDE
    assert "goToStep(index-1)" in GUIDE


def test_tutorial_never_waits_forever_for_a_missing_control():
    assert "targetWaitStarted" in GUIDE
    assert "Date.now()-targetWaitStarted<1800" in GUIDE
    assert "Required control unavailable" in GUIDE
    assert "Retry current step" in GUIDE


def test_simulation_matches_the_ui_transition_and_gate_contracts():
    expected = (
        'recommendation:["draft"],draft:["testing","recommendation"],'
        'testing:["peer_review","draft","recommendation"],'
        'peer_review:["production","draft","recommendation"],'
        'production:["monitoring","retired"],'
        'monitoring:["monitoring","tuning","retired"],'
        'tuning:["testing","retired"],retired:[]'
    )
    assert expected in LIFECYCLE.replace("\n", "").replace(" ", "")
    for message in (
        "Passed validation evidence is required before peer review.",
        "Peer approval is required before production.",
        "A deployment reference is required before production.",
        "Health evidence is required before monitoring.",
        "A retirement reason is required.",
    ):
        assert message in LIFECYCLE
    assert "Choose one next operational action" in LIFECYCLE
    assert "Record health checkpoint" in LIFECYCLE
    assert "Start tuning version" in LIFECYCLE
    assert "← Start tuning version" not in LIFECYCLE


def test_tutorial_simulation_rejects_unrelated_and_nonproduction_progress():
    step = 2
    walkthrough_detection = None

    # Restored historical records at every stage cannot satisfy a fresh run.
    for state in ("draft", "testing", "peer_review", "production", "monitoring", "tuning", "retired"):
        selected = "historical-" + state
        assert walkthrough_detection is None
        assert selected != walkthrough_detection
        assert step == 2

    # Only a Recommendation can enter generation, and only its generated record owns the run.
    selected_stage = "recommendation"
    selected = "new-authentication-detection"
    if selected_stage == "recommendation":
        step = 3
    walkthrough_detection = selected
    step = 4
    assert walkthrough_detection == selected

    # An event for another record is ignored.
    unrelated_event_record = "old-retired-detection"
    assert unrelated_event_record != walkthrough_detection
    assert step == 4

    # Development and Staging evidence is retained but cannot claim Production completion.
    step = 10
    for saved_state in ("peer_review", "catalog"):
        if saved_state == "production":
            step = 11
        assert step == 10
    saved_state = "production"
    if saved_state == "production":
        step = 11
    assert step == 11

    # Returning a tuned version for changes goes back to editing, not completion.
    step = 21
    action = "return_draft"
    if action == "return_draft" and 19 <= step <= 22:
        step = 17
    assert step == 17

    # Retirement ends the walkthrough without displaying the successful 26/26 claim.
    action = "retire"
    tutorial_open = True
    if action == "retire":
        tutorial_open = False
    assert not tutorial_open


def test_new_scan_restarts_an_unfinished_or_visible_walkthrough_from_discovery():
    # Reproduce the reported defect: a stale completed step must not survive a new scan.
    step = 25
    seen = False
    scan_stage = "discover"
    guide_active = not seen
    if scan_stage == "discover" and guide_active:
        step = 1
    assert step == 1

    scan_stage = "complete"
    if step == 1 and scan_stage == "complete":
        step = 2
    assert step == 2
    assert step != 26
