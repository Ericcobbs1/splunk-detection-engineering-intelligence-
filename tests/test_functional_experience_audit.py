from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).parents[1]
VIEWS = ROOT / "app/default/data/ui/views"
STATIC = ROOT / "app/appserver/static"


def _source(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_every_workspace_loads_the_shared_scan_service():
    for view in VIEWS.glob("*.xml"):
        root = ElementTree.parse(view).getroot()
        if view.name in {"detection_builder.xml", "detection_lifecycle.xml", "detection_operations.xml"}:
            assert "redirect_v1.js" in root.attrib["script"]
            continue
        assert "dei_environment_scan_v1.js" in root.attrib["script"].split(","), view.name


def test_home_scan_is_consolidated_into_environment_discovery():
    layout = _source("dei_workspace_layout_v14.js")
    service = _source("dei_environment_scan_v1.js")
    assert 'href="command_center#dei-telemetry"' in layout
    assert 'window.DEIEnvironmentScan.run(' not in layout
    assert 'dei-run-intelligence-scan' not in layout
    assert 'command_center#dei-telemetry' in layout
    assert "dei:scan-progress" in service
    assert "dei:environment-refreshed" in service
    assert "latestRecommendationReport" in service
    assert 'dei_force_refresh:"1"' in service
    assert "isExplicitFreshScan" in _source("dashboard_state_v2.js")
    assert "The intelligence scan failed" in service
    assert 'scanCollection="dei_scan_summaries"' in service
    assert 'scanEndpoint("latest")' in service
    assert "assessment_id" in service
    assert "active_sourcetype_count" in service
    assert "active_index_count" in service
    assert "field_profile_failures" in service
    assert "enterprise_security_enabled" in service
    assert "function hydrate()" in service


def test_assisted_tour_opens_once_per_session_and_is_dismissible():
    adapter = _source("dei_guide_adapter_v5.js")
    react_source = (ROOT / "ui/interactive-guide.jsx").read_text(encoding="utf-8")
    bundle = _source("dei_interactive_guide_v2.js")
    for page in ("home", "environment", "builder"):
        assert f'page:"{page}"' in adapter
    for event in (
        "dei:scan-progress", "workflow-detection-select",
        "dei:detection-draft-generated", "dei:detection-validation-complete",
        "dei:lifecycle-action-complete",
    ):
        assert event in adapter
    assert 'event.key==="Escape"' in adapter
    assert 'event.key==="F6"' in adapter
    assert 'function sessionKey(base) {' in adapter
    assert "return base;" in adapter
    assert 'Splunk.util.getConfigValue("FORM_KEY")' not in adapter
    assert "window.DEINextGuide" in adapter
    assert 'document.createElement("script")' in adapter
    assert "script.async=true" in adapter
    assert "script.onerror" in adapter
    assert "Waiting for this action to complete" in react_source
    assert "The guide advances automatically" in react_source
    assert "Next" not in react_source
    assert "window.DEIInteractiveGuide" in bundle


def test_react_bundle_is_progressive_enhancement_not_a_dashboard_dependency():
    for view in VIEWS.glob("*.xml"):
        scripts = ElementTree.parse(view).getroot().attrib["script"].split(",")
        assert "dei_interactive_guide_v2.js" not in scripts, view.name
        if view.name in {"detection_builder.xml", "detection_lifecycle.xml", "detection_operations.xml"}:
            continue
        assert "dei_guide_adapter_v5.js" in scripts, view.name
    adapter = _source("dei_guide_adapter_v5.js")
    assert "finishGuideLoad(false)" in adapter
    assert "dashboard remains available" in adapter


def test_tour_dialog_stays_above_spotlight_on_every_tour_page():
    tour_styles = _source("dei_guided_tour_v6.css")
    assert ".dei-onboarding-overlay{z-index:10002" in tour_styles
    assert ".dei-onboarding-target{z-index:10001!important;pointer-events:auto}" in tour_styles
    assert ".dei-onboarding-overlay{z-index:10002" in tour_styles
    assert '.dei-onboarding-dialog[data-placement="right"]' in tour_styles
    assert '.dei-onboarding-dialog[data-placement="left"]' in tour_styles
    assert '.dei-onboarding-dialog::before{content:""' in tour_styles
    assert ".dei-next-guide{padding:18px" in tour_styles
    assert ".dei-next-guide-action" in tour_styles
    for view in (
        "dei_home.xml", "command_center.xml", "environment_insights.xml",
            "mitre_coverage.xml", "detection_workflow.xml",
            "detection_health.xml", "detection_catalog.xml", "detection_action_center.xml",
    ):
        root = ElementTree.parse(VIEWS / view).getroot()
        assert "dei_guided_tour_v6.css" in root.attrib["stylesheet"].split(",")


def test_home_pipeline_drilldowns_open_owned_workspaces():
    layout = _source("dei_workspace_layout_v12.js")
    assert 'generate:"detection_workflow#guided-builder-workspace"' in layout
    assert 'validate:"detection_workflow#builder-validation-title"' in layout
    assert '"detection_action_center"' in layout
    assert '"detection_health"' in layout
    assert '"command_center#dei-telemetry"' in layout
    assert '"detection_catalog"' in layout


def test_tour_targets_exist_in_their_owning_views():
    targets = {
        "dei_home.xml": ".//*[@id='dei-home-pipeline']",
        "command_center.xml": ".//*[@id='dei-telemetry']",
        "mitre_coverage.xml": ".//*[@class='dei-mitre-advisor']",
        "detection_workflow.xml": ".//*[@id='guided-builder-workspace']",
        "detection_catalog.xml": ".//*[@id='lifecycle-work-queue']",
    }
    for view, xpath in targets.items():
        assert ElementTree.parse(VIEWS / view).getroot().find(xpath) is not None, view


def test_no_duplicate_control_ids_within_any_view():
    for view in VIEWS.glob("*.xml"):
        root = ElementTree.parse(view).getroot()
        ids = [node.attrib["id"] for node in root.iter() if "id" in node.attrib]
        assert len(ids) == len(set(ids)), view.name


def test_core_action_controls_have_implementation_bindings():
    sources = "\n".join(path.read_text(encoding="utf-8") for path in STATIC.glob("*.js"))
    controls = {
        "dei-analyze": "discoverEnvironment(true)",
        "builder-generate": "generateSelectedDetection",
        "builder-clear-spl": '$("#generator-spl").val("")',
        "builder-save-draft": "saveCurrentDraft",
        "builder-run-validation": "runValidation",
        "builder-apply-validation-fix": "Recommended correction applied",
        "lifecycle-reset-filters": "renderQueue()",
        "dei-density-toggle": "applyDensity(next)",
    }
    for control, behavior in controls.items():
        assert control in sources, control
        assert behavior in sources, f"{control} does not expose {behavior}"


def test_react_tour_drives_real_analyst_actions_instead_of_long_form_content():
    adapter = _source("dei_guide_adapter_v5.js")
    react_source = (ROOT / "ui/interactive-guide.jsx").read_text(encoding="utf-8")
    assert adapter.count("actionLabel:") == 13
    for target in (
        ".dei-open-environment-discovery", "#dei-analyze", "#dei-open-environment-insights",
        "#workflow-detection-select", "#builder-generate",
        "#builder-run-validation", "#lifecycle-action-comment",
        '[data-action="submit_review"]', '[data-action="approve_review"]',
        "#lifecycle-external-id", '[data-action="record_deployment"]',
    ):
        assert target in adapter
    assert "Waiting for this action to complete" in react_source
    assert "The guide advances automatically" in react_source
    assert "Production objective" not in react_source
    assert "Evidence before continuing" not in react_source
    styles = _source("dei_guided_tour_v6.css")
    assert ".dei-next-guide-action" in styles
    assert "#dei-guide-action-marker" in styles
    assert "deiGuideTargetPulse" in styles
    assert "prefers-reduced-motion:reduce" in styles


def test_post_scan_tutorial_stays_in_the_detection_engineering_workspace():
    adapter = _source("dei_guide_adapter_v5.js")
    steps_source = adapter.split("var steps=[", 1)[1].split("];", 1)[0]
    assert steps_source.count('page:"builder"') == 10
    assert 'page:"environment_insights"' not in steps_source
    assert 'page:"mitre"' not in steps_source
    assert 'page:"catalog"' not in steps_source
    assert 'target:"#workflow-detection-select"' in steps_source
    assert 'target:"#lifecycle-external-id"' in steps_source
    assert 'target:\'[data-action="record_deployment"]\'' in steps_source


def test_guide_is_compact_collapsible_and_pointer_draggable():
    adapter = _source("dei_guide_adapter_v5.js")
    react_source = (ROOT / "ui/interactive-guide.jsx").read_text(encoding="utf-8")
    stylesheet = _source("dei_guided_tour_v6.css")
    assert "useState(false)" in react_source
    assert "dei-next-guide-collapse" in react_source
    assert "is-collapsed" in react_source
    assert '$(document).on("pointerdown", ".dei-next-guide-header"' in adapter
    assert '$(document).on("pointermove", ".dei-next-guide-header"' in adapter
    assert 'window.sessionStorage.setItem("dei.guide.position"' in adapter
    assert "dei-guide-positioned" in stylesheet
    assert ".dei-next-guide.is-collapsed" in stylesheet
    assert "width:min(380px" in stylesheet


def test_react_guide_survives_dynamic_controls_and_finishes_in_workspace():
    adapter = _source("dei_guide_adapter_v5.js")
    layout = _source("dei_workspace_layout_v14.js")
    stylesheet = _source("dei_guided_tour_v6.css")
    react_source = (ROOT / "ui/interactive-guide.jsx").read_text(encoding="utf-8")
    assert "window.MutationObserver" in adapter
    assert "scheduleRender(60)" in adapter
    assert 'OVERLAY_ID="dei-next-guide-overlay"' in adapter
    assert 'data-dei-guide-owner="react"' in adapter
    assert "window.DEIReactGuideConfigured=true" in adapter
    assert "window.DEIReactGuideConfigured || window.DEINextGuide" in layout
    assert 'readStep()===11&&action==="record_deployment") goToStep(12)' in adapter
    assert 'title:"Detection enabled — workflow complete"' in adapter
    assert "Splunk saved searches: Settings → Searches, Reports, and Alerts" in adapter
    assert "Enterprise Security detections: Configure → Content → Content Management" in adapter
    assert "step.completion ? 'Finish' : 'Show me'" in react_source
    assert 'action==="submit_review"' in adapter
    assert 'action==="approve_review"' in adapter
    assert 'action==="return_draft"&&readStep()>=6&&readStep()<=9' in adapter
    assert 'target:"#lifecycle-external-id"' in adapter
    assert "reviewReturnMode" not in adapter
    assert "onContinueReview" not in react_source
    assert "step.lockBack" in react_source
    assert 'index===4 && $("#detection-generator").attr("data-dei-generated-detection")' in adapter
    assert "completeDraft(id,record)" in adapter
    assert 'window.DEINextGuide={start:start,render:render,close:close,completeDraft:completeDraft}' in adapter
    assert "if(readStep()<=4)" in adapter
    assert 'if (page()!==step.page) { close(false); return; }' in adapter
    assert 'if(page()!==step.page){ window.location.href=route(step.page); return; }' in adapter
    assert "candidate[0]!==activeTarget" in adapter
    assert "if(stepChanged&&!step.completion) focusTarget(false)" in adapter
    assert "onFocusTarget:function(){ focusTarget(true); }" in adapter
    assert 'status.text("Target highlighted — complete the glowing action in the workspace.")' in adapter
    assert 'target.addClass("dei-guide-focus-pulse")' in adapter
    assert '.text("CLICK HERE").addClass("dei-guide-marker-focus")' in adapter
    assert 'window.clearTimeout(focusPulseTimer)' in adapter
    assert 'id="dei-guide-return"' in adapter
    assert 'id="dei-guide-focus-status"' in adapter
    assert 'aria-live="assertive"' in adapter
    assert 'restoreGuide(true)' in adapter
    assert 'hasClass("dei-guide-focus-mode")) restoreGuide(true)' in adapter
    assert 'target.trigger("click")' not in adapter
    assert "deiGuideShowMe" in stylesheet
    assert "deiGuideShowMarker" in stylesheet
    assert "body.dei-guide-focus-mode .dei-onboarding-dialog" in stylesheet
    assert "#dei-guide-return" in stylesheet
    assert 'content:"↓"' in stylesheet


def test_show_me_centers_then_reanchors_marker_to_the_actual_control():
    adapter = _source("dei_guide_adapter_v5.js")
    assert 'scrollIntoView({behavior:"auto",block:"center",inline:"center"})' in adapter
    assert "rect.left+(rect.width-markerWidth)/2" in adapter
    assert "function settleTarget(step,target)" in adapter
    assert "window.requestAnimationFrame(function()" in adapter
    assert "current[0]!==target[0]" in adapter
    assert "settleTarget(step,target)" in adapter
    assert 'scrollIntoView({behavior:"smooth"' not in adapter


def test_every_action_step_resolves_to_a_visible_interactive_control_and_frame():
    adapter = _source("dei_guide_adapter_v5.js")
    stylesheet = _source("dei_guided_tour_v6.css")
    assert "function prepareStep(step)" in adapter
    assert 'tab:"#workflow-tab-artifact"' in adapter
    assert 'tab:"#workflow-tab-change-control"' in adapter
    assert 'tab.trigger("click")' in adapter
    assert "rect.width>0&&rect.height>0" in adapter
    assert 'target.is("button,input,select,textarea,a,[role=\'button\']")' in adapter
    assert 'target.prop("disabled")' in adapter
    assert 'target.prop("readonly")' in adapter
    assert 'target.attr("aria-disabled")==="true"' in adapter
    assert 'target:"#lifecycle-external-id"' in adapter
    assert 'id="dei-guide-action-frame"' in adapter
    assert "frame.css({top:rect.top-6,left:rect.left-6,width:rect.width+12,height:rect.height+12})" in adapter
    assert "#dei-guide-action-frame" in stylesheet


def test_tutorial_reconciles_completed_gates_before_requesting_an_action():
    adapter = _source("dei_guide_adapter_v5.js")
    assert "function reconcileCompletedStep(index)" in adapter
    assert 'index===5&&($("#builder-validation-state").hasClass("passed")' in adapter
    assert 'String($("#validation-status").text()||"").toLowerCase()==="passed"' in adapter
    assert "(index===6||index===7)&&$('[data-action=\"approve_review\"]:visible').length" in adapter
    assert 'index===8&&String($("#lifecycle-action-comment").val()||"").trim()' in adapter
    assert 'index===10&&String($("#lifecycle-external-id").val()||"").trim()' in adapter
    assert 'index===11&&!$(\'[data-action="record_deployment"]:visible\').length' in adapter
    assert "if(reconcileCompletedStep(index)) return" in adapter
    assert 'index>=6&&index<=11&&/(production|monitoring|tuning|retired)/.test(lifecycleState)' in adapter
    assert 'index>=6&&index<=9&&$("#lifecycle-external-id:visible").length' in adapter
    assert 'if(reconcileCompletedStep(readStep())) return false' in adapter
    assert "Updating to the next available action" in adapter


def test_completion_step_never_highlights_the_entire_workspace():
    adapter = _source("dei_guide_adapter_v5.js")
    assert "if(step.completion) return $()" in adapter
    assert "if (!target.length&&!step.completion)" in adapter
    assert "if(stepChanged&&!step.completion) focusTarget(false)" in adapter
    assert 'else if(!target.length)' in adapter


def test_deployment_recommendation_is_plain_text_not_selected_code():
    usability = _source("dei_detection_usability_v1.js")
    styles = _source("dei_detection_usability_v1.css")
    assert "Recommended name:" in usability
    assert 'class="dei-recommended-object-name"' in usability
    assert "<code>" not in usability
    assert ".dei-recommended-object-name" in styles


def test_tutorial_state_machine_covers_every_required_action_through_completion():
    adapter = _source("dei_guide_adapter_v5.js")
    transitions = (
        'readStep()===0) goToStep(1)',
        'readStep()===1 && status.stage==="complete") advance()',
        'readStep()===2) advance()',
        'readStep()===3 && $(this).val()) advance()',
        'if(readStep()===5 && validation && validation.status==="passed") advance()',
        '(step===6||step===8)',
        'readStep()===7&&action==="submit_review") goToStep(8)',
        'readStep()===9&&action==="approve_review") goToStep(10)',
        'readStep()===10 && String($(this).val()||"").trim()) goToStep(11)',
        'readStep()===11&&action==="record_deployment") goToStep(12)',
    )
    for transition in transitions:
        assert transition in adapter
    assert '$(document).on("change", "#lifecycle-action-comment"' in adapter
    assert '$(document).on("change", "#lifecycle-external-id"' in adapter
    assert '$(document).on("input change", "#lifecycle-action-comment"' not in adapter
    assert '$(document).on("input change", "#lifecycle-external-id"' not in adapter


def test_every_tutorial_target_exists_in_its_runtime_page_or_renderer():
    home = (VIEWS / "dei_home.xml").read_text(encoding="utf-8")
    discovery = (VIEWS / "command_center.xml").read_text(encoding="utf-8")
    insights = (VIEWS / "environment_insights.xml").read_text(encoding="utf-8")
    mitre = (VIEWS / "mitre_coverage.xml").read_text(encoding="utf-8") + _source("mitre_workspace_v3.js")
    builder = (VIEWS / "detection_workflow.xml").read_text(encoding="utf-8") + _source("detection_lifecycle_v3.js")
    catalog = (VIEWS / "detection_catalog.xml").read_text(encoding="utf-8") + _source("detection_catalog_v2.js")
    expected = (
        (home, 'class="dei-home-flow-link dei-open-environment-discovery"'),
        (discovery, 'id="dei-analyze"'),
        (discovery, 'id="dei-open-environment-insights"'),
        (insights, 'class="dei-mitre-glow-button"'),
        (mitre, 'id="mitre-sourcetype-filter"'),
        (mitre, 'class="dei-advisor-item '),
        (builder, 'id="builder-detection-select"'),
        (builder, 'id="builder-generate"'),
        (builder, 'id="builder-run-validation"'),
        (builder, 'id="lifecycle-action-comment"'),
        (catalog, 'id="catalog-external-id-field"'),
        (catalog, 'data-catalog-action="deploy"'),
        (catalog, 'id="catalog-action-panel"'),
    )
    for source, target in expected:
        assert target in source, target
    assert 'action:"submit_review"' in builder
    assert 'action:"approve_review"' in builder
    assert "data-action=\"'+esc" in builder


def test_approved_review_has_one_clear_inline_deployment_handoff():
    lifecycle = _source("detection_lifecycle_v3.js")
    guide = _source("dei_guide_adapter_v5.js")
    catalog = (VIEWS / "detection_catalog.xml").read_text(encoding="utf-8")
    assert 'action:"record_deployment"' in lifecycle
    assert "Continue below to record deployment without leaving this workspace" in lifecycle
    assert 'id="lifecycle-external-id"' in lifecycle
    assert 'id="catalog-external-id-field"' in catalog
    assert 'target:"#lifecycle-external-id"' in guide
    assert 'lockBack:true' in guide
    assert "selection.removeAllRanges" in guide
