"""Contract tests for the hardened managed lifecycle workflow."""

from pathlib import Path

APP = Path("app")
STATIC = APP / "appserver" / "static"


def test_shared_lifecycle_collection_and_role_are_packaged() -> None:
    collections = (APP / "default" / "collections.conf").read_text(encoding="utf-8")
    authorization = (APP / "default" / "authorize.conf").read_text(encoding="utf-8")
    metadata = (APP / "metadata" / "default.meta").read_text(encoding="utf-8")
    assert "[dei_lifecycle_records]" in collections
    assert "[dei_scan_summaries]" in collections
    assert "[dei_scan_history]" in collections
    assert "[role_dei_lifecycle_analyst]" in authorization
    assert "importRoles = user" in authorization
    assert "srchIndexesAllowed" not in authorization
    assert "capabilities" not in authorization
    assert "[collections/dei_lifecycle_records]" in metadata
    assert "[collections/dei_scan_summaries]" in metadata
    assert "[collections/dei_scan_history]" in metadata
    assert "[collections/dei_user_preferences]" in metadata
    assert "write : [ admin, dei_lifecycle_analyst ]" in metadata
    assert "write : [ * ]" not in metadata.split("[collections/dei_lifecycle_records]", 1)[1]


def test_store_uses_kv_with_explicit_browser_fallback() -> None:
    javascript = (STATIC / "dei_lifecycle_store_v1.js").read_text(encoding="utf-8")
    assert 'COLLECTION = "dei_lifecycle_records"' in javascript
    assert '"dei", "v1", "storage"' in javascript
    assert "X-Splunk-Form-Key" in javascript
    assert "saveFallback" in javascript
    assert 'mode = "Splunk KV Store"' in javascript
    assert 'mode = "browser fallback"' in javascript
    assert "appendHistory" in javascript
    assert "updated_by:username()" in javascript


def test_lifecycle_state_transitions_require_evidence() -> None:
    javascript = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    assert 'draft:["testing","recommendation"]' in javascript
    assert 'testing:["peer_review","draft","recommendation"]' in javascript
    assert 'peer_review:["production","draft","recommendation"]' in javascript
    assert 'action:"return_draft",label:"Previous · Return to Draft"' in javascript
    assert 'production:["monitoring","retired"]' in javascript
    assert 'monitoring:["monitoring","tuning","retired"]' in javascript
    assert 'tuning:["testing","retired"]' in javascript
    assert "Passed validation evidence is required before peer review." in javascript
    assert "Peer approval is required before production." in javascript
    assert "A deployment reference is required before production." in javascript
    assert "Health evidence is required before monitoring." in javascript
    assert "A retirement reason is required." in javascript
    assert "Gate 3 · Independent peer review" in javascript
    assert "Gate 4 · Controlled deployment record" in javascript
    assert "Gate 5 · Production health baseline" in javascript
    assert "Gate 6 · Continuous detection operations" in javascript
    assert "Gate 7 · Controlled tuning cycle" in javascript
    assert "lifecycle-deployment-environment" in javascript
    assert "true_positives:truePositives" in javascript
    assert "false_positives:falsePositives" in javascript
    assert "previous_versions" in javascript
    assert "deployment:null,monitoring:null" in javascript


def test_catalog_manage_preserves_peer_review_and_routes_deployment_buckets() -> None:
    catalog = (STATIC / "detection_catalog_v2.js").read_text(encoding="utf-8")
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    view = (APP / "default" / "data" / "ui" / "views" / "detection_catalog.xml").read_text(encoding="utf-8")
    for bucket in ("development", "staging", "production"):
        assert f'<option value="{bucket}">' in view
    for target in ("splunk_platform", "enterprise_security", "external"):
        assert target in catalog
    assert 'detection_workflow?detection=' in catalog
    assert 'Open peer review and lifecycle' in catalog
    assert 'data-catalog-action="return_draft"' in catalog
    assert 'production=environment==="production"' in catalog
    assert 'copy.state=production?"production":"peer_review"' in catalog
    assert 'production?"enabled":environment' in catalog
    assert 'nonproduction_deployment_recorded' in catalog
    assert 'record.state!=="draft"' in catalog
    assert 'copy.catalog=null' in catalog
    assert 'deployment:null,catalog:null' in lifecycle
    assert 'environment==="production"' in lifecycle


def test_unified_lifecycle_workspace_has_fluid_evidence_gated_stage_controls() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "detection_lifecycle_v1.css").read_text(encoding="utf-8")
    assert "function stageControls(record)" in lifecycle
    assert 'label:"Previous · Return to Draft"' in lifecycle
    assert 'label:"Continue · Submit for peer review"' in lifecycle
    assert 'label:"Continue · Approve version"' in lifecycle
    assert 'label:"Continue · Record deployment"' in lifecycle
    assert 'data-stage-action=' in lifecycle
    assert 'pendingWorkspaceAction=action' in lifecycle
    assert 'pendingWorkspaceAction!=="return_draft"' in lifecycle
    assert 'builder.scrollIntoView' not in lifecycle
    assert "function activateWorkspacePanel(panel)" in lifecycle
    assert '.dei-stage-controller' in stylesheet
    assert '.dei-progress-step.available' in stylesheet


def test_return_to_draft_has_explicit_validation_and_storage_transition() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "detection_lifecycle_v1.css").read_text(encoding="utf-8")
    assert "function returnToDraft(record,comment)" in lifecycle
    assert '["testing","peer_review"].indexOf(record.state)===-1' in lifecycle
    assert 'transition(record,"draft","returned_for_changes"' in lifecycle
    assert "returned_at:new Date().toISOString()" in lifecycle
    assert 'validation:null,deployment:null,catalog:null' in lifecycle
    assert 'actionError("Enter the required change before returning this detection to Draft' in lifecycle
    assert 'setActionBusy(true,action==="return_draft"' in lifecycle
    assert 'Returned to Draft and reopened in Guided Builder.' in lifecycle
    assert 'id="lifecycle-inline-error"' in lifecycle
    assert '.dei-inline-action-error' in stylesheet
    assert 'textarea[aria-invalid="true"]' in stylesheet


def test_detection_can_restart_at_recommendation_without_losing_audit_history() -> None:
    lifecycle = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    workflow = (STATIC / "detection_workflow_v2.js").read_text(encoding="utf-8")
    view = (APP / "default/data/ui/views/detection_workflow.xml").read_text(encoding="utf-8")
    assert 'draft:["testing","recommendation"]' in lifecycle
    assert 'testing:["peer_review","draft","recommendation"]' in lifecycle
    assert 'peer_review:["production","draft","recommendation"]' in lifecycle
    assert "function restartFromRecommendation(record,reason)" in lifecycle
    assert 'closure:"restarted_from_recommendation"' in lifecycle
    assert 'previous_versions:(record.previous_versions||[]).concat([archived])' in lifecycle
    assert 'version:Number(record.version||1)+1' in lifecycle
    assert 'spl:"",schedule:null,validation:null,review:null,deployment:null,monitoring:null,catalog:null' in lifecycle
    assert 'action==="restart_recommendation"' in lifecycle
    assert "function syncBrowserArtifact(record)" in lifecycle
    assert 'action==="return_draft"||action==="restart_recommendation"' in lifecycle
    assert "function updateRestartControl(record)" in lifecycle
    assert '$("#workflow-unified-workspace").prop("hidden",false)' in workflow
    for element_id in ("builder-restart-workflow", "builder-restart-panel", "builder-restart-reason", "builder-confirm-restart", "builder-cancel-restart"):
        assert f'id="{element_id}"' in view


def test_work_queue_joins_recommendations_and_records() -> None:
    javascript = (STATIC / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    assert "function mergedQueue()" in javascript
    assert "records.forEach" in javascript
    assert "No lifecycle work is available." in javascript
    assert "No items match these filters." in javascript
    assert "lifecycle-reset-filters" in javascript
    for state in ("draft", "testing", "production", "monitoring", "tuning", "retired"):
        assert f'countState("{state}")' in javascript
    assert 'record.state==="peer_review" && !(record.catalog && record.catalog.cataloged_at)' in javascript
    assert "state-catalog" in javascript


def test_builder_writes_drafts_and_validation_to_shared_store() -> None:
    javascript = (STATIC / "detection_query_generator_v5.js").read_text(encoding="utf-8")
    assert "function lifecycleRecord(artifact)" in javascript
    assert "Store.appendHistory" in javascript
    assert "Store.write(record)" in javascript
    assert '"validation_completed"' in javascript
    assert '"draft_saved"' in javascript
    assert "initializeBuilder" in javascript
    assert "sharedRecords" in javascript


def test_platform_spl_always_emits_mitre_mapping_without_es() -> None:
    javascript = (STATIC / "detection_query_generator_v5.js").read_text(encoding="utf-8")
    assert "function platformMitreMetadata(item)" in javascript
    assert "function stripPlatformMitreMetadata(spl)" in javascript
    assert "function attachPlatformMitreMetadata(spl, item)" in javascript
    assert "function enforcePlatformMitreMetadata(artifact, item)" in javascript
    assert "artifact=buildArtifact(item)" in javascript
    assert "saveArtifact(artifact)" in javascript
    assert "A fresh detection draft replaced the prior saved SPL" in javascript
    assert 'artifact.spl = attachPlatformMitreMetadata(String($("#generator-spl").val()' in javascript
    for field in ("mitre_attack_ttp", "mitre_attack_id", "mitre_attack_description"):
        assert field in javascript
    for removed_field in (
        "mitre_attack_framework", "mitre_attack_technique_url",
        "mitre_attack_subtechnique_id", "mitre_attack_tactic_url",
        "mitre_attack_platform", "mitre_attack_detection_guidance",
        "mitre_attack_version", "mitre_attack_last_modified",
    ):
        assert removed_field not in javascript
    for value in (
        "T1567.001", "T1567.002", "T1567.003", "T1567.004",
        "Exfiltration", "TA0010", "ESXi", "Office Suite", "macOS",
    ):
        assert value in javascript
    assert "var spl = attachPlatformMitreMetadata" in javascript
    assert javascript.index("var spl = attachPlatformMitreMetadata") < javascript.index("var es = artifact.enterprise_security")


def test_analyst_runbook_covers_complete_workflow() -> None:
    runbook = Path("docs/MANAGED_LIFECYCLE_RUNBOOK.md").read_text(encoding="utf-8")
    for heading in (
        "Recommendation to Draft", "Draft to Testing", "Testing to Peer Review",
        "Peer Review", "Production", "Monitoring", "Tuning", "Retirement",
    ):
        assert heading in runbook
    assert "dei_lifecycle_analyst" in runbook
    assert "does not silently" in runbook
    assert "persisted records" in runbook
