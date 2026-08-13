"""Regression tests for the Detection Engineering Lifecycle workspace."""

from pathlib import Path
from xml.etree import ElementTree

APP_ROOT = Path("app")
VIEW_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "detection_lifecycle.xml"
BUILDER_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "detection_builder.xml"
OPERATIONS_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "detection_operations.xml"
CATALOG_PATH = APP_ROOT / "default" / "data" / "ui" / "views" / "detection_catalog.xml"
NAV_PATH = APP_ROOT / "default" / "data" / "ui" / "nav" / "default.xml"
STATIC_ROOT = APP_ROOT / "appserver" / "static"
FRAMEWORK_PATH = Path("docs") / "DETECTION_ENGINEERING_FRAMEWORK.md"


def test_detection_lifecycle_view_is_valid_and_packaged() -> None:
    root = ElementTree.parse(VIEW_PATH).getroot()
    catalog = ElementTree.parse(CATALOG_PATH).getroot()
    assert root.tag == "form"
    assert root.attrib["theme"] == "dark"
    assert root.attrib["script"] == "detection_lifecycle_redirect_v1.js"
    assert root.attrib["stylesheet"] == "dei_design_system_v2.css"
    assert root.find(".//*[@href='detection_catalog#lifecycle-map']") is not None
    for element_id in (
        "dei-lifecycle-page", "lifecycle-data-status", "lifecycle-analysis-age",
        "lifecycle-maturity-percent", "life-sources", "life-opportunities",
        "life-mitre-mapped", "life-field-verified", "life-telemetry-ready",
        "life-spl-generated", "stage-discover", "stage-profile", "stage-qualify",
        "stage-recommend", "stage-design", "stage-generate", "stage-validate",
        "state-draft", "state-testing", "state-review", "state-catalog", "state-production",
        "state-monitoring", "state-tuning", "state-retired",
        "dei-detection-flow", "dei-flow-status",
    ):
        if element_id.startswith("stage-") or element_id in ("dei-detection-flow", "dei-flow-status"):
            assert catalog.find(f".//*[@id='{element_id}']") is not None
    assert catalog.find(".//*[@id='lifecycle-map']") is not None


def test_detection_catalog_owns_the_engineering_work_queue() -> None:
    root = ElementTree.parse(CATALOG_PATH).getroot()
    for element_id in (
        "lifecycle-search", "lifecycle-readiness", "lifecycle-stage",
        "lifecycle-visible-rows",
        "lifecycle-queue-count", "lifecycle-work-queue",
        "lifecycle-reset-filters",
    ):
        assert root.find(f".//*[@id='{element_id}']") is not None
    assert root.find(".//*[@id='dei-detection-flow']") is not None
    assert root.find(".//*[@id='lifecycle-action-center']") is None


def test_engineering_queue_has_scrollable_ten_or_twenty_five_row_viewport() -> None:
    root = ElementTree.parse(CATALOG_PATH).getroot()
    queue_section = root.find(".//*[@class='dei-lifecycle-section dei-lifecycle-queue-section']")
    row_filter = root.find(".//*[@id='lifecycle-visible-rows']")
    stylesheet = (STATIC_ROOT / "detection_lifecycle_v1.css").read_text(encoding="utf-8")
    javascript = (STATIC_ROOT / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    assert queue_section is not None and queue_section.attrib["data-visible-rows"] == "10"
    assert row_filter is not None
    assert [(option.attrib["value"], option.text) for option in row_filter.findall("option")] == [
        ("10", "10 rows"), ("25", "25 rows")
    ]
    assert 'data-visible-rows="25"' in stylesheet
    assert "max-height:762px" in stylesheet
    assert "max-height:1842px" in stylesheet
    assert "overflow-y:auto" in stylesheet
    assert "scrollbar-gutter:stable" in stylesheet
    assert '#lifecycle-work-queue tr{height:72px}' in stylesheet
    assert '#lifecycle-visible-rows' in javascript
    assert '.attr("data-visible-rows",rows==="25"?"25":"10")' in javascript
    assert "var visibleItems=items.slice(0,visibleRows);" in javascript
    assert '$("#lifecycle-visible-rows").on("change"' in javascript
    assert "renderQueue();" in javascript


def test_detection_lifecycle_compatibility_route_is_not_duplicated_in_navigation() -> None:
    root = ElementTree.parse(NAV_PATH).getroot()
    assert root.find(".//view[@name='detection_lifecycle']") is None
    assert root.find(".//view[@name='detection_workflow']") is not None
    assert root.find(".//view[@name='detection_action_center']") is None
    assert root.find(".//view[@name='detection_builder']") is None
    assert root.find(".//collection[@label='Operate']/view[@name='detection_catalog']") is not None
    assert root.find(".//view[@name='detection_operations']") is None


def test_approved_detections_move_from_engineering_queue_to_catalog() -> None:
    catalog = ElementTree.parse(CATALOG_PATH).getroot()
    javascript = (STATIC_ROOT / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    catalog_javascript = (STATIC_ROOT / "detection_catalog_v2.js").read_text(encoding="utf-8")
    assert "detection_catalog_v2.js" in catalog.attrib["script"].split(",")
    assert "detection_catalog_v1.css" in catalog.attrib["stylesheet"].split(",")
    for element_id in (
        "dei-detection-catalog-page", "catalog-total", "catalog-table",
        "catalog-search", "catalog-status-filter", "catalog-action-panel",
        "catalog-deployment-target", "catalog-external-id", "catalog-action-buttons",
    ):
        assert catalog.find(f".//*[@id='{element_id}']") is not None
    external_id = catalog.find(".//*[@id='catalog-external-id']")
    external_id_help = catalog.find(".//*[@id='catalog-external-id-help']")
    assert external_id.attrib["aria-describedby"] == "catalog-external-id-help"
    assert "exact deployed object name" in "".join(external_id_help.itertext())
    assert catalog.find(".//a[@href='detection_catalog']") is not None
    assert "isEngineeringWork" in javascript
    assert "mergedQueue().filter(isEngineeringWork)" in javascript
    assert 'status:"ready"' in javascript
    assert '"added_to_detection_catalog"' in javascript
    assert "saveAndOpenCatalog" in javascript
    assert 'window.location.href="detection_catalog?detection="' in javascript
    assert 'action:"open_catalog"' in javascript
    assert '"Peer review approved. Record the deployment target in this workspace."' in javascript
    for contract in (
        "cataloged(record)", '["ready","development","staging"]', 'data-catalog-action="deploy"',
        'production?"production":"peer_review"', 'production?"enabled":environment', "catalog_detection_disabled",
        "detection_workflow?detection=", "Record health, tune, or retire",
    ):
        assert contract in catalog_javascript


def test_guided_detection_builder_owns_the_action_workspace() -> None:
    lifecycle = ElementTree.parse(VIEW_PATH).getroot()
    builder = ElementTree.parse(APP_ROOT / "default" / "data" / "ui" / "views" / "detection_workflow.xml").getroot()
    assert "detection_query_generator_v5.js" in builder.attrib["script"].split(",")
    assert "dei_detection_standards_v1.js" in builder.attrib["script"].split(",")
    for element_id in (
            "dei-guided-detection-page", "guided-builder-workspace",
        "builder-ready-count", "builder-detection-select", "builder-generate",
        "detection-generator", "generator-es-state", "generator-empty",
        "generator-output", "generator-title", "generator-badges",
        "builder-feedback", "builder-cron", "builder-earliest", "builder-latest",
        "generator-spl", "builder-save-draft", "builder-reset-draft", "builder-clear-spl",
        "builder-run-validation", "builder-validation-state",
        "builder-validation-metrics", "validation-status",
        "validation-result-count", "validation-runtime", "validation-time",
        "builder-validation-results", "validation-result-head", "validation-result-body",
        "builder-validation-resolution", "builder-validation-resolution-title",
        "builder-validation-resolution-category", "builder-validation-resolution-summary",
        "builder-validation-error", "builder-validation-resolution-steps",
        "builder-apply-validation-fix", "builder-edit-validation-query",
        "builder-retry-validation",
        "generator-es-output", "copy-generated-spl", "copy-generated-json",
        "download-generated-json",
    ):
        assert builder.find(f".//*[@id='{element_id}']") is not None
    assert lifecycle.find(".//*[@id='detection-generator']") is None
    assert lifecycle.find(".//*[@class='dei-lifecycle-capabilities']") is None


def test_detection_lifecycle_assets_use_evidence_not_mock_completion() -> None:
    javascript = (STATIC_ROOT / "detection_lifecycle_v3.js").read_text(encoding="utf-8")
    stylesheet = (STATIC_ROOT / "detection_lifecycle_v1.css").read_text(encoding="utf-8")
    framework = FRAMEWORK_PATH.read_text(encoding="utf-8")
    assert "dei.latestRecommendationReport" in javascript
    assert "source_mappings" in javascript
    assert "observedSourcetypes" in javascript
    assert "stateFor" in javascript
    assert "nextAction" in javascript
    assert "detection_workflow?detection=" in javascript
    assert "dei.selectedDetectionDraft" in javascript
    assert "DEILifecycleStore" in javascript
    assert '$("#life-spl-generated").text(records.length)' in javascript
    assert '$("#stage-generate").text(records.length+" SPL")' in javascript
    assert '$("#stage-validate").text(passed+" passed")' in javascript
    assert "mergedQueue" in javascript
    assert "submit_review" in javascript
    assert "approve_review" in javascript
    assert "record_deployment" in javascript
    assert "record_health" in javascript
    assert "start_tuning" in javascript
    assert "detection_retired" in javascript
    assert "workflowProgress" in javascript
    assert "lifecyclePosition" in javascript
    assert 'label:"Catalog ready"' in javascript
    assert 'aria-current="step"' in javascript
    assert '"Stage "+position.index+" of "+position.total' in javascript
    assert '"Current stage: "+label(position.stage)+" · Version "' in javascript
    assert '"Next required action: "+nextAction' in javascript
    assert "gateGuidance" in javascript
    assert "renderGateGuide" in javascript
    assert "renderPipelineState" in javascript
    assert "activatePipelineStage" in javascript
    assert "data-pipeline-state" in javascript
    assert "Record deployment" in javascript
    assert "Continue · Start Monitoring" in javascript
    assert ".dei-pipeline-grid" in stylesheet
    assert ".dei-state-grid" in stylesheet
    assert ".dei-lifecycle-table" in stylesheet
    assert ".dei-lifecycle-filters>*{width:100%;min-width:0" in stylesheet
    assert ".dei-generator-grid" in stylesheet
    assert "Discover" in framework
    assert "Generate" in framework
    assert "Validate" in framework
    assert "draft → testing → peer_review → production → monitoring → tuning → retired" in framework
    assert "Initial releases must not automatically deploy or enable detections" in framework


def test_detection_standards_block_malformed_pipeline_syntax() -> None:
    javascript = (STATIC_ROOT / "dei_detection_standards_v1.js").read_text(encoding="utf-8")
    assert 'VERSION="1.1.0"' in javascript
    assert "function syntaxSummary(text)" in javascript
    assert 'issue("spl.empty-pipeline","error"' in javascript
    assert 'issue("spl.unbalanced-quote","error"' in javascript


def test_detection_query_generator_is_review_safe_and_es_aware() -> None:
    javascript = (STATIC_ROOT / "detection_query_generator_v5.js").read_text(encoding="utf-8")
    assert "production_ready" in javascript
    assert "sourceClause" in javascript
    assert "analyticLogic" in javascript
    assert "platformMitreMetadata" in javascript
    assert "stripPlatformMitreMetadata" in javascript
    assert "generatedSplIntegrity" in javascript
    assert "attachPlatformMitreMetadata" in javascript
    assert "enforcePlatformMitreMetadata" in javascript
    for field in ("mitre_attack_ttp", "mitre_attack_id", "mitre_attack_description"):
        assert field in javascript
    for removed_field in (
        "mitre_attack_framework", "mitre_attack_technique_url",
        "mitre_attack_subtechnique_id", "mitre_attack_tactic_url",
        "mitre_attack_platform", "mitre_attack_detection_guidance",
    ):
        assert removed_field not in javascript
    assert "var spl = attachPlatformMitreMetadata" in javascript
    assert "mitre_attack:item.mitre_techniques" in javascript
    assert 'cron:"*/5 * * * *"' in javascript
    assert "SplunkEnterpriseSecuritySuite" in javascript
    assert 'search_type:"Correlation"' in javascript
    assert "notable_enabled:true" in javascript
    assert "risk_based_alerting" in javascript
    assert "disabled:true" in javascript
    assert "DEI does not enable or deploy detections" not in javascript
    assert "window.localStorage.setItem(ARTIFACT_KEY" in javascript
    assert "builder-detection-select" in javascript
    assert "populateDetectionSelector" in javascript
    assert "setStartFeedback" in javascript
    assert 'item.capability || ""' in javascript
    assert 'aria-busy","true"' in javascript
    assert "requestedDetectionId" in javascript
    assert "buildableRecommendations" in javascript
    assert "field_unverified:true" in javascript
    assert "field_gap:true" in javascript
    assert "selectorGroup" in javascript
    assert "engineering_warnings" in javascript
    assert "unresolved_fields" in javascript
    assert "No environment analysis is loaded" in javascript
    assert '"services", "search", "jobs", "export"' in javascript
    assert "VALIDATION_RESULT_LIMIT = 25" in javascript
    assert "VALIDATION_TIMEOUT_MS = 60000" in javascript
    assert "earliest_time:artifact.schedule.earliest" in javascript
    assert "latest_time:artifact.schedule.latest" in javascript
    assert 'artifact.status = "testing"' in javascript
    assert "sample_results:rows" in javascript
    assert "saveCurrentDraft" in javascript
    assert "validationResolution" in javascript
    assert "renderValidationResolution" in javascript
    assert "narrow_window" in javascript
    assert "search_prefix" in javascript
    assert "Missing command or macro" in javascript
    assert "Splunk permissions" in javascript
    assert "Field mapping" in javascript
    assert "validation_history" in javascript
    assert "builder-apply-validation-fix" in javascript
    assert "builder-edit-validation-query" in javascript
    assert "builder-retry-validation" in javascript
    assert "Run validation again" in javascript
    assert 'command.toLowerCase() === "rshell"' in javascript
    assert 'replaceCommandAtBoundary(spl, "rshell", "search")' in javascript
    assert "field values and quoted text are not modified" in javascript
    assert "DEI will not guess a replacement" in javascript
    assert 'result.fix="rshell_to_search"' in javascript
    assert "function pipelineSyntax(spl)" in javascript
    assert "function collapseEmptyPipelines(spl)" in javascript
    assert "function canAddSearchPrefix(spl)" in javascript
    assert 'result.fix="empty_pipeline"' in javascript
    assert "result.autoApply=true" in javascript
    assert "function applyValidationCorrection(artifact, resolution)" in javascript
    assert "corrected automatically" in javascript
    assert "adding another search prefix would be incorrect" in javascript
    assert 'return "mvappend("' in javascript
    assert 'split(" + quote(cleaned.join("||"))' not in javascript
    assert 'return analyticSpl+"\\n"+platformMitreMetadata(item)' in javascript
    assert 'return analyticSpl + "\\\\n"' not in javascript
    assert '(-enc\\\\s|encodedcommand' in javascript
    assert '(-enc\\\\\\\\s|encodedcommand' not in javascript
    assert "artifact=buildArtifact(item)" in javascript
    assert "Generated SPL integrity check failed" in javascript
    assert "DEI blocked an invalid generated query" in javascript
    assert "function resetDraftWorkspace(message)" in javascript
    assert '$("#detection-generator,#generator-output").hide()' in javascript
    assert '$("#detection-generator").show()' in javascript
    assert 'return String(window.localStorage.getItem(SELECTED_DETECTION_KEY)' not in javascript
    assert "generateSelectedDetection();" not in javascript
    builder = ElementTree.parse(APP_ROOT / "default" / "data" / "ui" / "views" / "detection_workflow.xml").getroot()
    assert builder.find(".//*[@id='detection-generator']").attrib["style"] == "display:none"


def test_dashboard_clear_removes_detection_drafts() -> None:
    javascript = (STATIC_ROOT / "persistent_environment.js").read_text(encoding="utf-8")
    assert 'ARTIFACT_KEY = "dei.detectionDraftArtifacts"' in javascript
    assert "DISCOVERY_TIME_KEY, ES_KEY, ARTIFACT_KEY" in javascript


def test_generate_draft_is_single_flight_and_confirms_persistence_before_completion() -> None:
    javascript = (STATIC_ROOT / "detection_query_generator_v5.js").read_text(encoding="utf-8")
    assert "var generationInFlight = false" in javascript
    assert "generationInFlight || window.DEIDraftGenerationInFlight" in javascript
    assert 'off("click.deiGenerate", "#builder-generate")' in javascript
    assert "return deferred.promise()" in javascript
    assert "saveArtifact(artifact).done(function (savedRecord)" in javascript
    assert 'attr("data-dei-generated-detection", item.detection_id)' in javascript
    assert 'window.DEINextGuide.completeDraft(item.detection_id,confirmedRecord)' in javascript
    assert 'trigger("dei:detection-draft-generated", [item.detection_id, confirmedRecord' in javascript
    assert "Detection draft generated and saved" in javascript
    assert 'trigger("dei:detection-artifact-saved"' in javascript
    assert 'saveArtifact(artifact).done(function(savedRecord)' in javascript


def test_generate_draft_is_idempotent_for_the_confirmed_selection() -> None:
    javascript = (STATIC_ROOT / "detection_query_generator_v5.js").read_text(encoding="utf-8")
    assert "event.stopImmediatePropagation()" in javascript
    assert 'attr("data-dei-generated-detection") === id' in javascript
    assert 'removeAttr("data-dei-generated-detection")' in javascript
