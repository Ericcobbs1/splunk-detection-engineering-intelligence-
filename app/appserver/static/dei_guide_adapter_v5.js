window.DEIReactGuideConfigured=true;
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
    script.src=Splunk.util.make_url("/static/app/splunk_detection_engineering_intelligence/dei_interactive_guide_v2.js");
    script.setAttribute("data-dei-guide-bundle","v2");
    script.onload=function(){
      if(window.DEIInteractiveGuide) finishGuideLoad(true);
      else { window.console.warn("DEI guide bundle loaded without its public API; dashboard remains available."); finishGuideLoad(false); }
    };
    script.onerror=function(){ window.console.warn("DEI guide bundle could not be loaded; dashboard remains available."); finishGuideLoad(false); };
    document.head.appendChild(script);
  }
  var STEP_KEY="dei.nextGuide.step";
  var SEEN_KEY="dei.nextGuide.seen";
  var OVERLAY_ID="dei-next-guide-overlay";
  var selectedDetection="";
  var renderTimer=null;
  var focusPulseTimer=null;
  var targetObserver=null;
  var renderedStep=-1;
  var activeTarget=null;
  var renderingGuide=false;
  var steps=[
    {page:"home",target:".dei-open-environment-discovery",title:"Open Environment Discovery",instruction:"Use the single Discovery workspace to run a current, permission-aware scan of Splunk telemetry.",actionLabel:"Select Open Environment Discovery"},
    {page:"environment",target:"#dei-analyze",title:"Run current telemetry discovery",instruction:"Run the seven-day intelligence scan so every downstream tutorial step uses current, saved evidence.",actionLabel:"Select Run intelligence scan"},
    {page:"environment",target:"#dei-open-environment-insights",title:"Open the readiness results",instruction:"Continue to the intelligence generated from the completed telemetry scan.",actionLabel:"Select View intelligence results"},
    {page:"environment_insights",target:".dei-mitre-glow-button",title:"Move from evidence to coverage",instruction:"Use the saved readiness evidence to continue into ATT&CK coverage analysis.",actionLabel:"Open the MITRE workspace"},
    {page:"mitre",target:"#mitre-sourcetype-filter",title:"Scope the detection opportunities",instruction:"Choose one observed sourcetype so the advisor shows relevant, supportable detections.",actionLabel:"Select a sourcetype"},
    {page:"mitre",target:".dei-advisor-item",title:"Choose a detection opportunity",instruction:"Select a recommendation to inspect its ATT&CK and telemetry-readiness evidence.",actionLabel:"Select one Detection Advisor result"},
    {page:"builder",target:"#builder-detection-select",title:"Load the selected detection",instruction:"Confirm the recommendation you want to engineer through the guided workflow.",actionLabel:"Select the detection in Builder"},
    {page:"builder",target:"#builder-generate",title:"Generate a reviewable draft",instruction:"Create the initial SPL and metadata from the selected telemetry evidence.",actionLabel:"Select Generate detection draft"},
    {page:"builder",target:"#builder-run-validation",title:"Validate the detection",instruction:"Run the bounded historical search and review the returned evidence.",actionLabel:"Select Run validation"},
    {page:"builder",target:"#lifecycle-action-comment",title:"Document the validation handoff",instruction:"Summarize the validated analytic intent, expected analyst behavior, evidence, and known limitations for peer review.",actionLabel:"Enter the review submission note"},
    {page:"builder",target:'[data-action="submit_review"]',title:"Send the validated version to review",instruction:"Submit this exact version and its evidence. The next screen is the independent approval decision.",actionLabel:"Select Submit for peer review"},
    {page:"builder",target:"#lifecycle-action-comment",title:"Document the approval decision",instruction:"As the reviewer, record why this version is safe, scoped, supportable, and operationally actionable.",actionLabel:"Enter the approval rationale",lockBack:true},
    {page:"builder",target:'[data-action="approve_review"]',title:"Approve and continue to deployment",instruction:"Approve this version. The tutorial will take you directly to its single deployment workspace in Detection Catalog.",actionLabel:"Select Approve version",lockBack:true},
    {page:"catalog",target:"#catalog-external-id-field",focusTarget:"#catalog-external-id",title:"Record the production object",instruction:"This is the only deployment form. Keep Production selected and enter the exact saved-search, ES detection, or external object name that was deployed.",actionLabel:"Enter the exact deployed object name",lockBack:true},
    {page:"catalog",target:'[data-catalog-action="deploy"]',title:"Enable the approved detection",instruction:"Review the target, environment, and object name once, then record the production deployment to enable the detection.",actionLabel:"Select Enable in Production",lockBack:true},
    {page:"catalog",target:"#catalog-action-panel",title:"Detection enabled — workflow complete",instruction:"The detection is now governed in the Catalog. Continue operational work here without returning to the Builder deployment form.",actionLabel:"Tutorial complete",completion:true,lockBack:true,details:["Detection Catalog: manage status, deployment reference, health, tuning, disablement, and retirement.","Splunk saved searches: Settings → Searches, Reports, and Alerts.","Enterprise Security detections: Configure → Content → Content Management."]}
  ];

  function page() {
    if ($("#dei-home-page").length) return "home";
    if ($("#dei-command-center").length) return "environment";
    if ($("#dei-environment-insights").length) return "environment_insights";
    if ($("#dei-mitre-page").length) return "mitre";
    if ($("#dei-guided-detection-page").length) return "builder";
    if ($("#dei-detection-catalog-page").length) return "catalog";
    return "other";
  }
  function sessionKey(base) {
    return base;
  }
  function route(name) {
    var base={home:"dei_home",environment:"command_center",environment_insights:"environment_insights",mitre:"mitre_coverage",builder:"detection_workflow",catalog:"detection_catalog"}[name];
    var detection=selectedDetection||String(window.localStorage.getItem("dei.selectedDetectionDraft")||"");
    return detection&&(name==="builder"||name==="catalog")?base+"?detection="+encodeURIComponent(detection):base;
  }
  function readStep() { var value=Number(window.sessionStorage.getItem(sessionKey(STEP_KEY))||0); return Math.max(0,Math.min(steps.length-1,value)); }
  function writeStep(value) { window.sessionStorage.setItem(sessionKey(STEP_KEY),String(value)); }
  function activeStep(index) {
    return steps[index];
  }
  function targetFor(step) { return $(step.target).filter(":visible").first(); }
  function focusFor(step,target) { var focus=step.focusTarget?$(step.focusTarget).filter(":visible").first():target; return focus.length?focus:target; }
  function scheduleRender(delay) { window.clearTimeout(renderTimer); renderTimer=window.setTimeout(render,delay||80); }
  function observeTargets() {
    if(targetObserver||!window.MutationObserver) return;
    targetObserver=new window.MutationObserver(function(){
      if(renderingGuide||!$("#"+OVERLAY_ID).length) return;
      var candidate=targetFor(activeStep(readStep()));
      if(!candidate.length||candidate[0]!==activeTarget) scheduleRender(60);
    });
    targetObserver.observe(document.body,{childList:true,subtree:true});
  }
  function updateMarker(target) {
    var marker=$("#dei-guide-action-marker");
    if(!target.length){ marker.remove(); return; }
    if(!marker.length){ marker=$('<span id="dei-guide-action-marker" aria-hidden="true">NEXT ACTION</span>').appendTo("body"); }
    var rect=target[0].getBoundingClientRect();
    var markerWidth=marker.outerWidth()||118;
    marker.css({top:Math.max(18,rect.top-18),left:Math.min(window.innerWidth-markerWidth-8,Math.max(8,rect.left+(rect.width-markerWidth)/2))});
  }
  function settleTarget(step,target) {
    window.requestAnimationFrame(function(){
      var current=targetFor(step);
      if(!current.length||current[0]!==target[0]) return;
      updateMarker(current);
      var focus=focusFor(step,current);
      focus.attr("tabindex",focus.attr("tabindex")||"-1").trigger("focus");
    });
  }
  function restoreGuide(moveFocus) {
    $("body").removeClass("dei-guide-focus-mode");
    $(".dei-onboarding-dialog").removeAttr("aria-hidden");
    $("#dei-guide-return,#dei-guide-focus-status").remove();
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
      status.text("Locating this action…");
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
    var dialog=$(".dei-onboarding-dialog"); if (!dialog.length) return;
    var placement="right";
    if (target.length && window.innerWidth>900) { var rect=target[0].getBoundingClientRect(); placement=(rect.left+rect.width/2)<window.innerWidth/2?"right":"left"; }
    else if (target.length) { placement=target[0].getBoundingClientRect().top>window.innerHeight/2?"top":"bottom"; }
    dialog.attr("data-placement",placement);
  }
  function close(markSeen) {
    if (markSeen!==false) window.sessionStorage.setItem(sessionKey(SEEN_KEY),"true");
    window.clearTimeout(renderTimer);
    window.clearTimeout(focusPulseTimer);
    restoreGuide(false);
    if(targetObserver){ targetObserver.disconnect(); targetObserver=null; }
    renderedStep=-1;
    activeTarget=null;
    if (window.DEIInteractiveGuide) window.DEIInteractiveGuide.unmount();
    $("#"+OVERLAY_ID+",#dei-guide-action-marker,#dei-guide-return,#dei-guide-focus-status").remove();
    $(".dei-onboarding-target,.dei-guide-focus-pulse").removeClass("dei-onboarding-target dei-guide-focus-pulse").removeAttr("aria-describedby");
    $("body").removeClass("dei-onboarding-open dei-guide-focus-mode");
  }
  function render() {
    if(!window.DEIInteractiveGuide){ loadGuide(function(ready){ if(ready) render(); }); return; }
    var index=readStep(),step=activeStep(index);
    if (page()!==step.page) { close(false); return; }
    if(index===6 && $("#builder-detection-select").val()){ writeStep(7); scheduleRender(0); return; }
    if(index===7 && $("#detection-generator").attr("data-dei-generated-detection") && String($("#generator-spl").val()||"").trim()){ writeStep(8); scheduleRender(0); return; }
    var target=targetFor(step);
    if (!target.length) { scheduleRender(180); return; }
    var stepChanged=index!==renderedStep;
    var targetChanged=target[0]!==activeTarget;
    if (!$("#"+OVERLAY_ID).length) $("body").append('<div id="'+OVERLAY_ID+'" class="dei-onboarding-overlay" data-dei-guide-owner="react"><div class="dei-onboarding-dialog dei-next-guide-dialog"><div id="dei-onboarding-react-root"></div></div></div>').addClass("dei-onboarding-open");
    observeTargets();
    if(targetChanged){
      $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
      target.addClass("dei-onboarding-target").attr("aria-describedby","dei-guide-instruction");
      activeTarget=target[0];
    }
    updateMarker(target);
    position(target);
    if(stepChanged||targetChanged){
      renderingGuide=true;
      window.DEIInteractiveGuide.render({step:step,stepNumber:index+1,totalSteps:steps.length,onBack:function(){ guideBack(index);},onClose:function(){close(true);},onFocusTarget:function(){ focusTarget(true); }});
      renderedStep=index;
      window.setTimeout(function(){ renderingGuide=false; },0);
    }
    if(stepChanged) focusTarget(false);
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
    if(index>0&&!activeStep(index).lockBack) goToStep(index-1);
  }
  function advance() { var index=readStep(); if (index>=steps.length-1) { close(true); return; } goToStep(index+1); }
  function completeDraft(id,record) {
    if(!id||!record||page()!=="builder") return false;
    selectedDetection=String(id);
    if(readStep()<=7){
      writeStep(8);
      renderedStep=-1;
      window.clearTimeout(renderTimer);
      renderTimer=window.setTimeout(render,0);
    }
    return readStep()>=8;
  }
  function start() { close(false); writeStep(0); window.sessionStorage.setItem(sessionKey(SEEN_KEY),"false"); loadGuide(function(ready){ if(ready) render(); }); }

  window.DEINextGuide={start:start,render:render,close:close,completeDraft:completeDraft};
  $(document).on("click", "#dei-guide-return", function(event){ event.preventDefault(); restoreGuide(true); });
  $(document).on("click", "#dei-home-tour", function (event) { event.preventDefault(); event.stopImmediatePropagation(); start(); });
  $(document).on("click", ".dei-open-environment-discovery", function(){ if(readStep()===0) goToStep(1); });
  $(document).on("dei:scan-progress", function (_event,status) { if(readStep()===1 && status.stage==="complete") advance(); });
  $(document).on("click", "#dei-open-environment-insights", function(){ if(readStep()===2) advance(); });
  $(document).on("click", ".dei-mitre-glow-button", function(){ if(readStep()===3) advance(); });
  $(document).on("change", "#mitre-sourcetype-filter", function(){ if(readStep()===4 && $(this).val()!=="all") window.setTimeout(advance,0); });
  $(document).on("dei:advisor-detection-selected", function(_event,id){ if(readStep()===5){ selectedDetection=String(id||""); if(selectedDetection) window.localStorage.setItem("dei.selectedDetectionDraft",selectedDetection); advance(); } });
  $(document).on("change", "#builder-detection-select", function(){ if(readStep()===6 && $(this).val()) advance(); });
  $(document).on("dei:detection-draft-generated", function(_event,id,record){ completeDraft(id,record); });
  $(document).on("dei:detection-validation-complete", function(_event,validation){ if(readStep()===8 && validation && validation.status==="passed") advance(); });
  $(document).on("change", "#lifecycle-action-comment", function(){ var step=readStep(); if((step===9||step===11)&&String($(this).val()||"").trim()) advance(); });
  $(document).on("dei:lifecycle-action-complete", function(_event,action){
    if(readStep()===10&&action==="submit_review") goToStep(11);
    if(readStep()===12&&action==="approve_review") goToStep(13);
    if(action==="return_draft"&&readStep()>=9&&readStep()<=12) goToStep(8);
  });
  $(document).on("change", "#catalog-external-id", function(){ if(readStep()===13 && String($(this).val()||"").trim()) goToStep(14); });
  $(document).on("dei:catalog-action-complete", function(_event,status){ if(readStep()===14 && status==="enabled") goToStep(15); });
  $(document).on("keydown", function(event){ if(!$("#"+OVERLAY_ID).length) return; if(event.key==="Escape") close(true); if(event.key==="F6"){ if($("body").hasClass("dei-guide-focus-mode")) restoreGuide(true); else if($(event.target).closest(".dei-onboarding-dialog").length) focusTarget(false); else $(".dei-next-guide-close").focus(); event.preventDefault(); } });
  $(window).on("resize.deiNextGuide scroll.deiNextGuide", function(){ if($("#"+OVERLAY_ID).length){ var target=targetFor(activeStep(readStep())); position(target); updateMarker(target); } });
  window.setTimeout(function(){ if(window.sessionStorage.getItem(sessionKey(SEEN_KEY))!=="true") render(); },250);
});
