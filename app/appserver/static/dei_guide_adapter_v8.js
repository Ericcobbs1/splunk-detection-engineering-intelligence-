window.DEIReactGuideConfigured=true;
window.DEIGuideAssetVersion="v17";
require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";
  var guideLoadState="idle";
  var guideLoadCallbacks=[];
  function finishGuideLoad(ready) {
    guideLoadState=ready?"ready":"failed";
    var callbacks=guideLoadCallbacks.slice();
    guideLoadCallbacks=[];
    callbacks.forEach(function(callback){ try { callback(ready); } catch(error) { window.console.error("DEI guide callback failed",error); } });
  }
  function loadGuide(callback) {
    if(window.DEIInteractiveGuide){ callback(true); return; }
    if(guideLoadState==="failed"){ callback(false); return; }
    guideLoadCallbacks.push(callback);
    if(guideLoadState==="loading") return;
    guideLoadState="loading";
    var script=document.createElement("script");
    script.async=true;
    script.src=Splunk.util.make_url("/static/app/splunk_detection_engineering_intelligence/dei_interactive_guide_v3.js");
    script.setAttribute("data-dei-guide-bundle","v3");
    script.onload=function(){
      if(window.DEIInteractiveGuide) finishGuideLoad(true);
      else { window.console.warn("DEI guide bundle loaded without its public API; dashboard remains available."); finishGuideLoad(false); }
    };
    script.onerror=function(){ window.console.warn("DEI guide bundle could not be loaded; dashboard remains available."); finishGuideLoad(false); };
    document.head.appendChild(script);
  }
  var STEP_KEY="dei.nextGuide.step";
  var SEEN_KEY="dei.nextGuide.seen";
  var ACTIVE_KEY="dei.nextGuide.active";
  var DETECTION_KEY="dei.nextGuide.detection";
  var REVIEW_KEY="dei.nextGuide.reviewCeiling";
  var GUIDE_STATE_VERSION="v10";
  var OVERLAY_ID="dei-next-guide-overlay";
  var selectedDetection="";
  var renderTimer=null;
  var focusPulseTimer=null;
  var targetObserver=null;
  var renderedStep=-1;
  var activeTarget=null;
  var renderingGuide=false;
  var dragState=null;
  var reviewCeiling=-1;
  var reviewPollTimer=null;
  var targetWaitStep=-1;
  var targetWaitStarted=0;
  var EVENT_TRANSITIONS={draft_generated:{3:4},validation_passed:{4:5,18:19},review_note:{5:6,7:8,19:20,21:22},submit_review:{6:7,20:21},approve_review:{8:9,22:23},deployment_reference:{9:10,23:24},record_deployment:{10:11,24:25},monitoring_metrics:{12:13},monitoring_note:{13:14},record_health:{14:15},tuning_note:{15:16},start_tuning:{16:17},spl_changed:{17:18}};
  var steps=[
    {page:"home",target:".dei-open-environment-discovery",title:"Open the Detection Workspace",instruction:"Use the unified workspace to scan telemetry and complete the governed detection lifecycle without page hopping.",actionLabel:"Select Open Detection Workspace"},
    {page:"builder",target:"#dei-analyze",title:"Run current telemetry discovery",instruction:"Run the intelligence scan at the top of this workspace so every downstream tutorial step uses current, saved evidence.",actionLabel:"Select Run intelligence scan"},
    {page:"builder",target:"#workflow-detection-select",title:"Choose a reusable detection",instruction:"Select any definition under Detection Library to start a new governed use case. Existing lifecycle records remain available separately and never remove a definition from the library.",actionLabel:"Select a library detection"},
    {page:"builder",target:"#builder-generate",tab:"#workflow-tab-artifact",title:"Generate a reviewable draft",instruction:"Create the initial SPL and metadata from the selected telemetry evidence.",actionLabel:"Select Generate detection draft"},
    {page:"builder",target:"#builder-run-validation",tab:"#workflow-tab-artifact",title:"Validate the detection",instruction:"Run the bounded historical search and review the returned evidence.",actionLabel:"Select Run validation"},
    {page:"builder",target:"#lifecycle-action-comment",tab:"#workflow-tab-change-control",title:"Document the validation handoff",instruction:"Summarize the validated analytic intent, expected analyst behavior, evidence, and known limitations for peer review.",actionLabel:"Enter the review submission note"},
    {page:"builder",target:'[data-action="submit_review"]',tab:"#workflow-tab-change-control",title:"Send the validated version to review",instruction:"Submit this exact version and its evidence. The next screen is the independent approval decision.",actionLabel:"Select Submit for peer review"},
    {page:"builder",target:"#lifecycle-action-comment",tab:"#workflow-tab-change-control",title:"Document the approval decision",instruction:"As the reviewer, record why this version is safe, scoped, supportable, and operationally actionable.",actionLabel:"Enter the approval rationale"},
    {page:"builder",target:'[data-action="approve_review"]',tab:"#workflow-tab-change-control",title:"Approve and continue to deployment",instruction:"Approve this version. The deployment form will open below without leaving this workspace.",actionLabel:"Select Approve version"},
    {page:"builder",target:"#lifecycle-external-id",tab:"#workflow-tab-change-control",title:"Record the production object",instruction:"Keep Production selected and enter the exact saved-search, ES detection, or external object name that was deployed.",actionLabel:"Enter the exact deployed object name"},
    {page:"builder",target:'[data-action="record_deployment"]',tab:"#workflow-tab-change-control",title:"Enable the approved detection",instruction:"Review the target, environment, and object name once, then record deployment to enter Production.",actionLabel:"Select Record deployment and enter Production"},
    {page:"builder",phase:"Production checkpoint",title:"The core deployment workflow is complete",instruction:"The detection is now governed in Production. Finish here, or continue into the optional operational walkthrough to learn monitoring, evidence-based tuning, revalidation, and redeployment.",actionLabel:"Choose whether to continue",operationsChoice:true,details:["Continue only with real operational evidence; do not enter sample values merely to advance the guide.","Tuning is not required after every deployment. A healthy detection can remain in Monitoring.","The operational walkthrough creates a new governed version and preserves the deployed version in history."]},
    {page:"builder",phase:"Operate and improve",target:"#lifecycle-review-period",tab:"#workflow-tab-change-control",title:"Establish monitoring evidence",instruction:"Define the period represented by this review, then enter evidence from Splunk search history, Job Inspector, scheduler health, and analyst outcomes.",actionLabel:"Review and complete the monitoring evidence",details:["Confirm the scheduled search ran without skips or errors and that required source data remained fresh.","Result volume and runtime come from search history or Job Inspector; verify downstream findings, notables, or risk events were created when expected.","True and false positives come from analyst disposition during this review period.","Zero results can be healthy, but the operational note must explain why zero was expected and how data coverage was verified."]},
    {page:"builder",phase:"Operate and improve",target:"#lifecycle-action-comment",tab:"#workflow-tab-change-control",title:"Document where the evidence came from",instruction:"Record the scheduler or search-history evidence, data-freshness check, analyst outcomes, and downstream-action verification represented by this checkpoint.",actionLabel:"Enter the monitoring evidence note",details:["Do not enter fabricated values to advance the tutorial.","If result volume is zero, explain why that is expected and how you confirmed the source data was present.","If health is degraded or failing, identify the owner and next corrective action."]},
    {page:"builder",phase:"Operate and improve",target:'[data-action="record_health"]',tab:"#workflow-tab-change-control",title:"Record the operational health checkpoint",instruction:"Confirm the evidence represents one review period. Recording it preserves an auditable health checkpoint and moves the detection into continuous Monitoring.",actionLabel:"Select Record health"},
    {page:"builder",phase:"Operate and improve",target:"#lifecycle-action-comment",tab:"#workflow-tab-change-control",title:"Decide whether tuning is justified",instruction:"A healthy detection can remain in Monitoring. For this optional walkthrough, document a real tuning objective only when evidence shows a coverage, fidelity, or performance problem.",actionLabel:"Enter the evidence-based tuning objective",details:["Use this structure: observed problem; supporting evidence; proposed change; measurable expected result; rollback condition.","Possible controls include SPL, thresholds, time windows, schedules, allowlists, suppression or throttling, risk settings, and response actions.","The currently deployed version and its evidence remain in history."]},
    {page:"builder",phase:"Operate and improve",target:'[data-action="start_tuning"]',tab:"#workflow-tab-change-control",title:"Open a new tuning version",instruction:"Start Tuning to archive the current operational version and unlock a new editable version in the same workspace.",actionLabel:"Select Start tuning version"},
    {page:"builder",phase:"Operate and improve",target:"#generator-spl",tab:"#workflow-tab-artifact",title:"Apply the controlled tuning change",instruction:"Apply the documented objective to the editable analytic. This workspace exposes SPL; operational changes to schedules, thresholds, suppression, risk, or response actions must also be applied and recorded in the deployed Splunk object.",actionLabel:"Edit the SPL for the tuning objective",details:["Preserve required result fields and recheck ATT&CK mappings after the change.","Make a meaningful change tied to the objective; whitespace or cosmetic edits are not tuning.","Keep a rollback path to the archived production version."]},
    {page:"builder",phase:"Operate and improve",target:"#builder-run-validation",tab:"#workflow-tab-artifact",title:"Validate the tuned version",instruction:"Run fresh validation. Prior validation does not carry forward because tuning created a new version of the analytic.",actionLabel:"Select Run validation",details:["Confirm an expected positive case matches and a known benign or negative case does not.","Verify required output fields, time bounds, result volume, and runtime.","Confirm the result meets the measurable tuning objective before review."]},
    {page:"builder",phase:"Operate and improve",target:"#lifecycle-action-comment",tab:"#workflow-tab-change-control",title:"Document the tuned-version handoff",instruction:"Summarize what changed, the monitoring evidence that justified it, the validation result, and the expected improvement.",actionLabel:"Enter the tuned-version review note"},
    {page:"builder",phase:"Operate and improve",target:'[data-action="submit_review"]',tab:"#workflow-tab-change-control",title:"Submit the tuned version for review",instruction:"Send the newly validated version through the same independent review gate as the original detection.",actionLabel:"Select Submit for peer review"},
    {page:"builder",phase:"Operate and improve",target:"#lifecycle-action-comment",tab:"#workflow-tab-change-control",title:"Review the tuning decision",instruction:"A reviewer other than the submitter should verify the version difference and record why the change resolves the objective without unacceptable coverage or operational risk.",actionLabel:"Enter the tuned-version approval rationale",details:["Review logic, source and field availability, time bounds, schedule, suppression, actions, ATT&CK mapping, and rollback.","If this environment cannot enforce a separate reviewer, treat separation of duties as a required procedural control."]},
    {page:"builder",phase:"Operate and improve",target:'[data-action="approve_review"]',tab:"#workflow-tab-change-control",title:"Approve the tuned version",instruction:"Approve this exact revised version. Deployment evidence must be recorded again because approval alone does not change the live Splunk object.",actionLabel:"Select Approve version"},
    {page:"builder",phase:"Operate and improve",target:"#lifecycle-external-id",tab:"#workflow-tab-change-control",title:"Record the updated production object",instruction:"Deploy the approved tuning through the normal change process, then record the exact updated saved-search, ES detection, or external object name.",actionLabel:"Enter the updated deployed object name",details:["Verify app context, owner, schedule and time range, enablement state, actions, and ATT&CK annotations.","For Enterprise Security, verify whether the object is an event-based or finding-based detection and confirm the expected notable, finding, or risk output.","Test safely before full enablement and retain the prior version as the rollback reference."]},
    {page:"builder",phase:"Operate and improve",target:'[data-action="record_deployment"]',tab:"#workflow-tab-change-control",title:"Return the tuned detection to Production",instruction:"Record the updated deployment to close the tuning loop and return this version to governed Production.",actionLabel:"Select Record deployment and enter Production"},
    {page:"builder",phase:"Lifecycle complete",target:"#lifecycle-action-center",title:"Detection lifecycle tutorial complete",instruction:"You built, validated, reviewed, deployed, monitored, tuned, revalidated, and redeployed one governed detection without leaving the workspace.",actionLabel:"Tutorial complete",completion:true,details:["Continue recording health on the cadence required by your organization; tune only when evidence justifies a change.","Retire is optional: confirm a replacement or accepted coverage gap, document the reason, disable the actual Splunk object separately, and retain the audit history. DEI retirement does not disable the saved search.","Detection Catalog manages the operational portfolio after enablement.","Splunk saved searches: Settings → Searches, Reports, and Alerts.","Enterprise Security detections: Configure → Content → Content Management."]}
  ];
  function guideActive() { return window.sessionStorage.getItem(sessionKey(ACTIVE_KEY))==="true"; }

  function page() {
    if ($("#dei-home-page").length) return "home";
    if ($("#dei-command-center").length) return "environment";
    if ($("#dei-environment-insights").length) return "environment_insights";
    if ($("#dei-mitre-page").length) return "mitre";
    if ($("#dei-guided-detection-page").length) return "builder";
    if ($("#dei-detection-catalog-page").length) return "catalog";
    return "other";
  }
  function recordKey(record) {
    return String(record&&(record._key||record.detection_id||record.id)||"").replace(/^dei-/,"");
  }
  function normalizeDetectionKey(value) { return String(value||"").replace(/^instance:/,"").replace(/^dei-/,""); }
  function sessionKey(base) {
    return base+"."+GUIDE_STATE_VERSION;
  }
  function setReviewCeiling(value) {
    reviewCeiling=value;
    if(value<0) window.sessionStorage.removeItem(sessionKey(REVIEW_KEY));
    else window.sessionStorage.setItem(sessionKey(REVIEW_KEY),String(value));
  }
  function resetWalkthroughDetection() {
    selectedDetection="";
    window.sessionStorage.removeItem(sessionKey(DETECTION_KEY));
    window.localStorage.removeItem("dei.selectedDetectionDraft");
    $("#workflow-detection-select,#builder-detection-select").val("");
  }
  function walkthroughDetection() {
    return selectedDetection||String(window.sessionStorage.getItem(sessionKey(DETECTION_KEY))||"");
  }
  function selectedWorkflowDetection() {
    return normalizeDetectionKey($("#workflow-detection-select").val()||window.localStorage.getItem("dei.selectedDetectionDraft")||"");
  }
  function walkthroughOwnsSelectedDetection() {
    var expected=walkthroughDetection();
    return !!expected&&selectedWorkflowDetection()===expected;
  }
  function selectedRecommendationOpportunity() {
    return String($("#workflow-detection-select").val()||"").indexOf("library:")===0;
  }
  function advanceFromLibrarySelectionWhenReady() {
    if(!guideActive()||readStep()!==2||!selectedRecommendationOpportunity()) return false;
    var button=$("#builder-generate").filter(":visible").first();
    var selected=normalizeDetectionKey($("#workflow-detection-select").val()||"");
    var builderSelected=normalizeDetectionKey($("#builder-detection-select").val()||"");
    if(!button.length||button.prop("disabled")||!selected||builderSelected!==selected) {
      $("#workflow-tutorial-status").prop("hidden",false).removeClass("unhealthy").text("Preparing the draft controls for the selected library detection…");
      return false;
    }
    $("#workflow-tutorial-status").prop("hidden",true).empty();
    advance();
    return true;
  }
  function applyTutorialSelectionScope(index) {
    var select=$("#workflow-detection-select");
    if(!select.length) return;
    var tutorialSelection=index===2&&reviewCeiling<0;
    // Guidance must never disable, clear, or replace a user's manual choice.
    var eligible=select.find("option").filter(function(){
      return String($(this).val()||"").indexOf("library:")===0;
    }).length;
    var status=$("#workflow-tutorial-status");
    if(!tutorialSelection||eligible) status.prop("hidden",true).empty();
    else if(select.find("option[value]").length<=1) status.prop("hidden",false).removeClass("unhealthy").text("Loading the detection library…");
    else status.prop("hidden",false).addClass("unhealthy").text("The reusable detection library is unavailable. Refresh the page before continuing the tutorial.");
  }

  $(document).on("dei:workflow-options-updated",function(){
    applyTutorialSelectionScope(readStep());
    if(readStep()===2&&reviewCeiling<0) restoreGuide(true);
  });
  function route(name) {
    var base={home:"dei_home",environment:"detection_workflow#workflow-environment-panel",environment_insights:"environment_insights",mitre:"mitre_coverage",builder:"detection_workflow",catalog:"detection_catalog"}[name];
    var detection=walkthroughDetection()||String(window.localStorage.getItem("dei.selectedDetectionDraft")||"");
    return detection&&(name==="builder"||name==="catalog")?base+"?detection="+encodeURIComponent(detection):base;
  }
  function readStep() { var value=Number(window.sessionStorage.getItem(sessionKey(STEP_KEY))||0); return Math.max(0,Math.min(steps.length-1,value)); }
  function writeStep(value) { window.sessionStorage.setItem(sessionKey(STEP_KEY),String(value)); }
  reviewCeiling=Number(window.sessionStorage.getItem(sessionKey(REVIEW_KEY))||-1);
  if(!isFinite(reviewCeiling)||reviewCeiling<0) reviewCeiling=-1;
  function activeStep(index) {
    return steps[index];
  }
  function monitoringMetricsReady() {
    var reviewPeriod=String($("#lifecycle-review-period").val()||"").trim();
    var required=["#lifecycle-result-volume","#lifecycle-runtime"].map(function(selector){return String($(selector).val()||"").trim();});
    var optional=["#lifecycle-true-positives","#lifecycle-false-positives"].map(function(selector){return String($(selector).val()||"").trim();});
    return !!reviewPeriod&&required.every(function(raw){return raw!==""&&isFinite(Number(raw))&&Number(raw)>=0;})&&optional.every(function(raw){return raw===""||(isFinite(Number(raw))&&Number(raw)>=0);});
  }
  function prepareStep(step) {
    if(!step.tab) return;
    var tab=$(step.tab).filter(":visible").first();
    if(tab.length&&tab.attr("aria-selected")!=="true") tab.trigger("click");
  }
  function targetFor(step) {
    if(reviewCeiling>=0) return $();
    if(step.completion||step.operationsChoice) return $();
    var target=$(step.target).filter(":visible").filter(function(){ var rect=this.getBoundingClientRect(); return rect.width>0&&rect.height>0; }).first();
    if(!target.length) return target;
    if(!target.is("button,input,select,textarea,a,[role='button']")) return $();
    if(target.prop("disabled")||target.prop("readonly")||target.attr("aria-disabled")==="true") return $();
    return target;
  }
  function reconcileCompletedStep(index) {
    var lifecycleState=String($("#lifecycle-action-state").text()||"").toLowerCase();
    if(index>=4&&!walkthroughOwnsSelectedDetection()) return false;
    if(index>=5&&index<=10&&lifecycleState.indexOf("production")!==-1){ goToStep(11); return true; }
    if(index>=5&&index<=14&&lifecycleState.indexOf("monitoring")!==-1){ goToStep(15); return true; }
    if(index>=5&&index<=16&&lifecycleState.indexOf("tuning")!==-1){ goToStep(17); return true; }
    if(index<25&&lifecycleState.indexOf("retired")!==-1){ close(true); return true; }
    if(index>=5&&index<=8&&$("#lifecycle-external-id:visible").length){ goToStep(9); return true; }
    if(index===4&&($("#builder-validation-state").hasClass("passed")||String($("#validation-status").text()||"").toLowerCase()==="passed")){ goToStep(5); return true; }
    if((index===5||index===6)&&$('[data-action="approve_review"]:visible').length){ goToStep(7); return true; }
    if(index===7&&String($("#lifecycle-action-comment").val()||"").trim()){ goToStep(8); return true; }
    if(index===9&&String($("#lifecycle-external-id").val()||"").trim()){ goToStep(10); return true; }
    if(index===10&&!$('[data-action="record_deployment"]:visible').length&&lifecycleState.indexOf("production")!==-1){ goToStep(11); return true; }
    if(index===12&&monitoringMetricsReady()){ goToStep(13); return true; }
    if(index===12&&lifecycleState.indexOf("monitoring")!==-1){ goToStep(15); return true; }
    if((index===13||index===14)&&lifecycleState.indexOf("monitoring")!==-1){ goToStep(15); return true; }
    if(index===17&&String($("#generator-spl").val()||"").trim()!==String($("#generator-spl").attr("data-dei-guide-original")||"").trim()&&$("#generator-spl").attr("data-dei-guide-original")!==undefined){ goToStep(18); return true; }
    if(index===18&&($("#builder-validation-state").hasClass("passed")||String($("#validation-status").text()||"").toLowerCase()==="passed")){ goToStep(19); return true; }
    if((index===19||index===20)&&$('[data-action="approve_review"]:visible').length){ goToStep(21); return true; }
    if(index===21&&String($("#lifecycle-action-comment").val()||"").trim()){ goToStep(22); return true; }
    if(index===23&&String($("#lifecycle-external-id").val()||"").trim()){ goToStep(24); return true; }
    if(index===24&&!$('[data-action="record_deployment"]:visible').length&&lifecycleState.indexOf("production")!==-1){ goToStep(25); return true; }
    return false;
  }
  function focusFor(step,target) { var focus=step.focusTarget?$(step.focusTarget).filter(":visible").first():target; return focus.length?focus:target; }
  function scheduleRender(delay) { window.clearTimeout(renderTimer); renderTimer=window.setTimeout(render,delay||80); }
  function observeTargets() {
    if(targetObserver||!window.MutationObserver) return;
    targetObserver=new window.MutationObserver(function(){
      if(renderingGuide||!$("#"+OVERLAY_ID).length) return;
      var candidate=targetFor(activeStep(readStep()));
      if(!candidate.length||candidate[0]!==activeTarget) scheduleRender(60);
    });
    targetObserver.observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:["disabled","hidden","aria-disabled","style"]});
  }
  function updateMarker(target) {
    var marker=$("#dei-guide-action-marker");
    var frame=$("#dei-guide-action-frame");
    if(!target.length){ marker.remove(); frame.remove(); return; }
    if(!marker.length){ marker=$('<span id="dei-guide-action-marker" aria-hidden="true">NEXT ACTION</span>').appendTo("body"); }
    if(!frame.length){ frame=$('<span id="dei-guide-action-frame" aria-hidden="true"></span>').appendTo("body"); }
    var rect=target[0].getBoundingClientRect();
    var markerWidth=marker.outerWidth()||118;
    frame.css({top:rect.top-6,left:rect.left-6,width:rect.width+12,height:rect.height+12});
    marker.css({top:Math.max(18,rect.top-26),left:Math.min(window.innerWidth-markerWidth-8,Math.max(8,rect.left+(rect.width-markerWidth)/2))});
  }
  function settleTarget(step,target) {
    window.requestAnimationFrame(function(){
      var current=targetFor(step);
      if(!current.length||current[0]!==target[0]) return;
      updateMarker(current);
      position(current);
      var focus=focusFor(step,current);
      focus.attr("tabindex",focus.attr("tabindex")||"-1").trigger("focus");
    });
  }
  function restoreGuide(moveFocus) {
    $("body").removeClass("dei-guide-focus-mode");
    $(".dei-onboarding-dialog").removeAttr("aria-hidden");
    $("#dei-guide-return,#dei-guide-focus-status,#dei-guide-action-frame").remove();
    $("#dei-guide-action-marker").text("NEXT ACTION").removeClass("dei-guide-marker-focus");
    if(moveFocus){
      window.setTimeout(function(){
        $(".dei-next-guide-footer button").filter(function(){ return $(this).text().trim()==="Show me"; }).first().trigger("focus");
      },0);
    }
  }
  function focusTarget(showTargetMode) {
    var step=activeStep(readStep());
    var target=targetFor(step);
    var status=$(".dei-next-guide-status span");
    if (!target.length) {
      if(reconcileCompletedStep(readStep())) return false;
      status.text("Required control unavailable. Retry this step, use Back, or close the tutorial without affecting manual work.");
      scheduleRender(80);
      return false;
    }
    window.clearTimeout(focusPulseTimer);
    target[0].scrollIntoView({behavior:"auto",block:"center",inline:"center"});
    target.removeClass("dei-guide-focus-pulse");
    void target[0].offsetWidth;
    target.addClass("dei-guide-focus-pulse");
    updateMarker(target);
    if(showTargetMode){
      if(window.getSelection){ var selection=window.getSelection(); if(selection&&selection.removeAllRanges) selection.removeAllRanges(); }
      $("body").addClass("dei-guide-focus-mode");
      $(".dei-onboarding-dialog").attr("aria-hidden","true");
      if(!$("#dei-guide-return").length){
        $('<button id="dei-guide-return" type="button">Return to tutorial</button>').appendTo("body");
        $('<span id="dei-guide-focus-status" class="dei-visually-hidden" role="status" aria-live="assertive">The tutorial is collapsed. The required action is centered and marked Click Here. Use Return to tutorial to reopen the instructions.</span>').appendTo("body");
      }
      $("#dei-guide-action-marker").text("CLICK HERE").addClass("dei-guide-marker-focus");
      status.text("Target highlighted — complete the glowing action in the workspace.");
    } else {
      $("#dei-guide-action-marker").text("NEXT ACTION").removeClass("dei-guide-marker-focus");
    }
    settleTarget(step,target);
    focusPulseTimer=window.setTimeout(function(){
      target.removeClass("dei-guide-focus-pulse");
    },1800);
    return true;
  }
  function position(target) {
    var dialog=$(".dei-onboarding-dialog"); if (!dialog.length||dialog.hasClass("dei-guide-positioned")) return;
    var pad=14,width=dialog.outerWidth(),height=dialog.outerHeight();
    if(!target.length) { dialog.attr("data-placement","right").css({left:window.innerWidth-width-pad,right:"auto",top:pad,bottom:"auto"}); return; }
    var rect=target[0].getBoundingClientRect(),targetX=rect.left+rect.width/2,targetY=rect.top+rect.height/2;
    var candidates=[
      {name:"top-left",left:pad,top:pad},{name:"top-right",left:window.innerWidth-width-pad,top:pad},
      {name:"bottom-left",left:pad,top:window.innerHeight-height-pad},{name:"bottom-right",left:window.innerWidth-width-pad,top:window.innerHeight-height-pad}
    ];
    function overlaps(candidate){return candidate.left<rect.right+18&&candidate.left+width>rect.left-18&&candidate.top<rect.bottom+18&&candidate.top+height>rect.top-18;}
    candidates.forEach(function(candidate){var centerX=candidate.left+width/2,centerY=candidate.top+height/2;candidate.score=Math.pow(centerX-targetX,2)+Math.pow(centerY-targetY,2)-(overlaps(candidate)?1e12:0);});
    candidates.sort(function(a,b){return b.score-a.score;}); var chosen=candidates[0];
    var placement=chosen.left+width/2<targetX?"left":"right";
    dialog.attr("data-placement",placement).css({left:Math.max(pad,chosen.left),right:"auto",top:Math.max(pad,chosen.top),bottom:"auto"});
  }
  function savedGuidePosition() {
    try { return JSON.parse(window.sessionStorage.getItem("dei.guide.position")||"null"); } catch(error) { return null; }
  }
  function applySavedGuidePosition() {
    var position=savedGuidePosition(),dialog=$(".dei-onboarding-dialog");
    if(!position||!dialog.length) return;
    dialog.addClass("dei-guide-positioned").css({left:Math.max(8,Math.min(window.innerWidth-dialog.outerWidth()-8,position.left)),top:Math.max(8,Math.min(window.innerHeight-dialog.outerHeight()-8,position.top)),right:"auto",bottom:"auto"});
  }
  function close(markSeen) {
    window.clearInterval(reviewPollTimer); reviewPollTimer=null;
    if (markSeen!==false) window.sessionStorage.setItem(sessionKey(SEEN_KEY),"true");
    if (markSeen!==false) window.sessionStorage.removeItem(sessionKey(ACTIVE_KEY));
    if (markSeen!==false) setReviewCeiling(-1);
    window.clearTimeout(renderTimer);
    window.clearTimeout(focusPulseTimer);
    restoreGuide(false);
    if(targetObserver){ targetObserver.disconnect(); targetObserver=null; }
    renderedStep=-1;
    activeTarget=null;
    if (window.DEIInteractiveGuide) window.DEIInteractiveGuide.unmount();
    $("#"+OVERLAY_ID+",#dei-guide-action-marker,#dei-guide-action-frame,#dei-guide-return,#dei-guide-focus-status").remove();
    $(".dei-onboarding-target,.dei-guide-focus-pulse").removeClass("dei-onboarding-target dei-guide-focus-pulse").removeAttr("aria-describedby");
    $("body").removeClass("dei-onboarding-open dei-guide-focus-mode");
    $("#workflow-detection-select option").prop("disabled",false);
  }
  function render() {
    if(!window.DEIInteractiveGuide){ loadGuide(function(ready){ if(ready) render(); }); return; }
    var index=readStep(),step=activeStep(index);
    if (page()!==step.page) { close(false); return; }
    prepareStep(step);
    if((index===7||index===8||index===21||index===22)&&$("#lifecycle-review-handoff:visible").length){
      step=$.extend({},step,{target:"#lifecycle-review-handoff",title:"Hand off to an independent reviewer",instruction:"This version is saved at Peer Review. Ask the assigned reviewer to sign in with their own Splunk account, open this detection, inspect the evidence, and approve or return it. This tutorial resumes automatically after their decision."});
      step["action"+"Label"]="Waiting for the assigned reviewer";
      if(!reviewPollTimer){ reviewPollTimer=window.setInterval(function(){ $(document).trigger("dei:lifecycle-refresh-requested"); },5000); }
    } else if(reviewPollTimer) {
      window.clearInterval(reviewPollTimer); reviewPollTimer=null;
    }
    applyTutorialSelectionScope(index);
    if(index===17&&$("#generator-spl").attr("data-dei-guide-original")===undefined){ $("#generator-spl").attr("data-dei-guide-original",String($("#generator-spl").val()||"")); }
    if(reviewCeiling<0&&reconcileCompletedStep(index)) return;
    var target=targetFor(step);
    if (!target.length&&!step.completion&&!step.operationsChoice&&reviewCeiling<0) {
      if(targetWaitStep!==index){targetWaitStep=index;targetWaitStarted=Date.now();}
      if(Date.now()-targetWaitStarted<1800){scheduleRender(180);return;}
      step=$.extend({},step,{targetUnavailable:true,instruction:step.instruction+" The required control is not currently available. Use Back to verify the prior action, or select Retry after the workspace finishes loading.",actionLabel:"Retry current step"});
    } else { targetWaitStep=-1;targetWaitStarted=0; }
    var stepChanged=index!==renderedStep;
    var targetChanged=(target[0]||null)!==activeTarget;
    if (!$("#"+OVERLAY_ID).length) { $("body").append('<div id="'+OVERLAY_ID+'" class="dei-onboarding-overlay" data-dei-guide-owner="react"><div class="dei-onboarding-dialog dei-next-guide-dialog"><div id="dei-onboarding-react-root"></div></div></div>').addClass("dei-onboarding-open"); }
    observeTargets();
    if(targetChanged&&target.length){
      $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
      target.addClass("dei-onboarding-target").attr("aria-describedby","dei-guide-instruction");
      activeTarget=target[0];
    } else if(!target.length) {
      $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
      activeTarget=null;
    }
    updateMarker(target);
    position(target);
    if(stepChanged||targetChanged){
      renderingGuide=true;
      window.DEIInteractiveGuide.render({step:step,stepNumber:index+1,totalSteps:steps.length,reviewMode:reviewCeiling>=0,onBack:function(){ guideBack(index);},onForward:function(){ guideForward(index);},onClose:function(){close(true);},onFocusTarget:function(){ focusTarget(true); },onContinueOperations:function(){ goToStep(12); },onFinishCore:function(){ close(true); }});
      renderedStep=index;
      window.setTimeout(function(){ renderingGuide=false; position(targetFor(activeStep(readStep()))); },0);
    }
    if(stepChanged&&!step.completion&&!step.operationsChoice) focusTarget(false);
  }
  function goToStep(index) {
    restoreGuide(false);
    writeStep(index);
    renderedStep=-1;
    var step=steps[readStep()];
    if(page()!==step.page){ window.location.href=route(step.page); return; }
    render();
  }
  function guideBack(index) {
    if(index<=0) return;
    if(reviewCeiling<0) setReviewCeiling(index);
    goToStep(index-1);
  }
  function guideForward(index) {
    if(reviewCeiling<0) return;
    if(index+1<reviewCeiling) { goToStep(index+1); return; }
    setReviewCeiling(-1);
    goToStep(Math.min(index+1,steps.length-1));
  }
  function advance() { var index=readStep(); if (index>=steps.length-1) { close(true); return; } goToStep(index+1); }
  function advanceFor(eventName,payload) {
    var index=readStep(),next=EVENT_TRANSITIONS[eventName]&&EVENT_TRANSITIONS[eventName][index];
    if(next===undefined) return false;
    if((eventName==="validation_passed")&&(!payload||payload.status!=="passed")) return false;
    if(eventName==="record_deployment"&&(!payload||payload.state!=="production")) return false;
    goToStep(next); return true;
  }
  function completeDraft(id,record) {
    if(!id||!record||page()!=="builder"||readStep()!==3) return false;
    var generatedKey=normalizeDetectionKey(id),selectedKey=selectedWorkflowDetection();
    if(selectedKey&&selectedKey!==generatedKey&&selectedKey!=="library:"+String(record.template_detection_id||record.detection_id||"")) return false;
    selectedDetection=generatedKey;
    window.sessionStorage.setItem(sessionKey(DETECTION_KEY),selectedDetection);
    if(readStep()<=3){
      writeStep(EVENT_TRANSITIONS.draft_generated[3]);
      renderedStep=-1;
      window.clearTimeout(renderTimer);
      renderTimer=window.setTimeout(render,0);
    }
    return readStep()>=4;
  }
  function start() { close(false); setReviewCeiling(-1); resetWalkthroughDetection(); writeStep(0); window.sessionStorage.setItem(sessionKey(ACTIVE_KEY),"true"); window.sessionStorage.setItem(sessionKey(SEEN_KEY),"false"); loadGuide(function(ready){ if(ready) render(); }); }

  window.DEINextGuide={start:start,render:render,close:close,completeDraft:completeDraft};
  $(document).on("click", "#dei-guide-return", function(event){ event.preventDefault(); restoreGuide(true); });
  $(document).on("pointerdown", ".dei-next-guide-header", function(event){
    if($(event.target).closest("button").length) return;
    var dialog=$(event.currentTarget).closest(".dei-onboarding-dialog"),rect=dialog[0].getBoundingClientRect();
    dragState={dialog:dialog,offsetX:event.clientX-rect.left,offsetY:event.clientY-rect.top};
    dialog.addClass("dei-guide-positioned dei-guide-dragging"); event.currentTarget.setPointerCapture(event.pointerId); event.preventDefault();
  });
  $(document).on("pointermove", ".dei-next-guide-header", function(event){
    if(!dragState) return; var dialog=dragState.dialog,left=Math.max(8,Math.min(window.innerWidth-dialog.outerWidth()-8,event.clientX-dragState.offsetX)),top=Math.max(8,Math.min(window.innerHeight-dialog.outerHeight()-8,event.clientY-dragState.offsetY));
    dialog.css({left:left,top:top,right:"auto",bottom:"auto"});
  });
  $(document).on("pointerup pointercancel", ".dei-next-guide-header", function(){
    if(!dragState) return; var rect=dragState.dialog[0].getBoundingClientRect(); dragState.dialog.removeClass("dei-guide-dragging"); window.sessionStorage.setItem("dei.guide.position",JSON.stringify({left:rect.left,top:rect.top})); dragState=null;
  });
  $(document).on("click", "#dei-home-tour", function (event) { event.preventDefault(); event.stopImmediatePropagation(); start(); });
  $(document).on("click", ".dei-open-environment-discovery", function(event){ if(guideActive()&&readStep()===0){ event.preventDefault(); goToStep(1); } });
  $(document).on("dei:scan-progress", function (_event,status) {
    if(status.stage==="discover"&&guideActive()&&page()==="environment") { resetWalkthroughDetection(); writeStep(1); renderedStep=-1; scheduleRender(0); return; }
    if(guideActive()&&readStep()===1&&(status.stage==="complete"||status.stage==="complete_with_warning")) { resetWalkthroughDetection(); goToStep(2); }
  });
  $(document).on("change", "#workflow-detection-select", function(){
    if(!guideActive()||readStep()!==2||!$(this).val()) return;
    if(!selectedRecommendationOpportunity()) { restoreGuide(true); $("#workflow-tutorial-status").prop("hidden",false).addClass("unhealthy").text("Select a detection from the reusable library to continue the tutorial."); return; }
    window.setTimeout(advanceFromLibrarySelectionWhenReady,0);
  });
  $(document).on("dei:builder-selection-ready", function(){
    if(guideActive()&&page()==="builder"&&readStep()===2) { advanceFromLibrarySelectionWhenReady(); return; }
    if(guideActive()&&page()==="builder"&&readStep()===3) scheduleRender(0);
  });
  $(document).on("dei:detection-draft-generated", function(_event,id,record){ completeDraft(id,record); });
  $(document).on("dei:detection-validation-complete", function(_event,validation){ if(walkthroughOwnsSelectedDetection()) advanceFor("validation_passed",validation); });
  $(document).on("change", "#lifecycle-action-comment", function(){ var step=readStep(),eventName={5:"review_note",7:"review_note",13:"monitoring_note",15:"tuning_note",19:"review_note",21:"review_note"}[step]; if(walkthroughOwnsSelectedDetection()&&eventName&&String($(this).val()||"").trim()) advanceFor(eventName); });
  $(document).on("change", "#lifecycle-review-period,#lifecycle-health,#lifecycle-result-volume,#lifecycle-runtime,#lifecycle-true-positives,#lifecycle-false-positives", function(){
    if(readStep()!==12||!walkthroughOwnsSelectedDetection()) return;
    if(monitoringMetricsReady()) advanceFor("monitoring_metrics");
  });
  $(document).on("input", "#generator-spl", function(){ if(walkthroughOwnsSelectedDetection()&&String($(this).val()||"").trim()!==String($(this).attr("data-dei-guide-original")||"").trim()) advanceFor("spl_changed"); });
  $(document).on("dei:lifecycle-action-complete", function(_event,action,saved){
    if(readStep()>=4&&(!saved||recordKey(saved)!==walkthroughDetection())) return;
    if(action==="submit_review") advanceFor("submit_review",saved);
    if(action==="approve_review") advanceFor("approve_review",saved);
    if(action==="record_deployment") advanceFor("record_deployment",saved);
    if(action==="record_health") advanceFor("record_health",saved);
    if(action==="start_tuning") advanceFor("start_tuning",saved);
    if(action==="return_draft"&&readStep()>=5&&readStep()<=8) goToStep(4);
    if(action==="return_draft"&&readStep()>=19&&readStep()<=22) goToStep(17);
    if(action==="restart_recommendation"&&readStep()>=4&&readStep()<=22) { resetWalkthroughDetection(); goToStep(2); }
    if(action==="retire") close(true);
  });
  $(document).on("dei:lifecycle-records-updated",function(){
    var index=readStep();
    if(reviewCeiling<0&&(index===7||index===8||index===21||index===22)&&reconcileCompletedStep(index)) return;
    if(reviewPollTimer) scheduleRender(0);
  });
  $(document).on("change", "#lifecycle-external-id", function(){ if(walkthroughOwnsSelectedDetection()&&String($(this).val()||"").trim()) advanceFor("deployment_reference"); });
  $(document).on("keydown", function(event){ if(!$("#"+OVERLAY_ID).length) return; if(event.key==="Escape") close(true); if(event.key==="F6"){ if($("body").hasClass("dei-guide-focus-mode")) restoreGuide(true); else if($(event.target).closest(".dei-onboarding-dialog").length) focusTarget(false); else $(".dei-next-guide-close").focus(); event.preventDefault(); } });
  $(window).on("resize.deiNextGuide scroll.deiNextGuide", function(){ if($("#"+OVERLAY_ID).length){ var target=targetFor(activeStep(readStep())); position(target); updateMarker(target); } });
  window.setTimeout(function(){ if(guideActive()) render(); },250);
});
