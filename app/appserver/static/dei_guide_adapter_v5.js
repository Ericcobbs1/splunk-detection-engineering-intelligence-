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
  var dragState=null;
  var steps=[
    {page:"home",target:".dei-open-environment-discovery",title:"Open Environment Discovery",instruction:"Use the single Discovery workspace to run a current, permission-aware scan of Splunk telemetry.",actionLabel:"Select Open Environment Discovery"},
    {page:"environment",target:"#dei-analyze",title:"Run current telemetry discovery",instruction:"Run the seven-day intelligence scan so every downstream tutorial step uses current, saved evidence.",actionLabel:"Select Run intelligence scan"},
    {page:"environment",target:"#dei-open-environment-insights",title:"Open the Detection Engineering Workspace",instruction:"The scan is complete. Continue into the single workspace used for every remaining detection action.",actionLabel:"Select Open Detection Engineering Workspace"},
    {page:"builder",target:"#workflow-detection-select",title:"Choose a detection opportunity",instruction:"Select a scan-supported recommendation. ATT&CK, telemetry readiness, lifecycle position, and required evidence remain visible on this page.",actionLabel:"Select a detection"},
    {page:"builder",target:"#builder-generate",tab:"#workflow-tab-artifact",title:"Generate a reviewable draft",instruction:"Create the initial SPL and metadata from the selected telemetry evidence.",actionLabel:"Select Generate detection draft"},
    {page:"builder",target:"#builder-run-validation",tab:"#workflow-tab-artifact",title:"Validate the detection",instruction:"Run the bounded historical search and review the returned evidence.",actionLabel:"Select Run validation"},
    {page:"builder",target:"#lifecycle-action-comment",tab:"#workflow-tab-change-control",title:"Document the validation handoff",instruction:"Summarize the validated analytic intent, expected analyst behavior, evidence, and known limitations for peer review.",actionLabel:"Enter the review submission note"},
    {page:"builder",target:'[data-action="submit_review"]',tab:"#workflow-tab-change-control",title:"Send the validated version to review",instruction:"Submit this exact version and its evidence. The next screen is the independent approval decision.",actionLabel:"Select Submit for peer review"},
    {page:"builder",target:"#lifecycle-action-comment",tab:"#workflow-tab-change-control",title:"Document the approval decision",instruction:"As the reviewer, record why this version is safe, scoped, supportable, and operationally actionable.",actionLabel:"Enter the approval rationale",lockBack:true},
    {page:"builder",target:'[data-action="approve_review"]',tab:"#workflow-tab-change-control",title:"Approve and continue to deployment",instruction:"Approve this version. The deployment form will open below without leaving this workspace.",actionLabel:"Select Approve version",lockBack:true},
    {page:"builder",target:"#lifecycle-external-id",tab:"#workflow-tab-change-control",title:"Record the production object",instruction:"Keep Production selected and enter the exact saved-search, ES detection, or external object name that was deployed.",actionLabel:"Enter the exact deployed object name",lockBack:true},
    {page:"builder",target:'[data-action="record_deployment"]',tab:"#workflow-tab-change-control",title:"Enable the approved detection",instruction:"Review the target, environment, and object name once, then record deployment to enter Production.",actionLabel:"Select Record deployment and enter Production",lockBack:true},
    {page:"builder",target:"#lifecycle-action-center",title:"Detection enabled — workflow complete",instruction:"The full engineering workflow is complete without leaving this workspace.",actionLabel:"Tutorial complete",completion:true,lockBack:true,details:["Detection Catalog: manage the operational portfolio after enablement.","Splunk saved searches: Settings → Searches, Reports, and Alerts.","Enterprise Security detections: Configure → Content → Content Management."]}
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
  function prepareStep(step) {
    if(!step.tab) return;
    var tab=$(step.tab).filter(":visible").first();
    if(tab.length&&tab.attr("aria-selected")!=="true") tab.trigger("click");
  }
  function targetFor(step) {
    if(step.completion) return $();
    var target=$(step.target).filter(":visible").filter(function(){ var rect=this.getBoundingClientRect(); return rect.width>0&&rect.height>0; }).first();
    if(!target.length) return target;
    if(!target.is("button,input,select,textarea,a,[role='button']")) return $();
    if(target.prop("disabled")||target.prop("readonly")||target.attr("aria-disabled")==="true") return $();
    return target;
  }
  function reconcileCompletedStep(index) {
    var lifecycleState=String($("#lifecycle-action-state").text()||"").toLowerCase();
    if(index>=6&&index<=11&&/(production|monitoring|tuning|retired)/.test(lifecycleState)){ goToStep(12); return true; }
    if(index>=6&&index<=9&&$("#lifecycle-external-id:visible").length){ goToStep(10); return true; }
    if(index===5&&($("#builder-validation-state").hasClass("passed")||String($("#validation-status").text()||"").toLowerCase()==="passed")){ goToStep(6); return true; }
    if((index===6||index===7)&&$('[data-action="approve_review"]:visible').length){ goToStep(8); return true; }
    if(index===8&&String($("#lifecycle-action-comment").val()||"").trim()){ goToStep(9); return true; }
    if(index===10&&String($("#lifecycle-external-id").val()||"").trim()){ goToStep(11); return true; }
    if(index===11&&!$('[data-action="record_deployment"]:visible').length&&String($("#lifecycle-action-state").text()||"").toLowerCase().indexOf("production")!==-1){ goToStep(12); return true; }
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
    targetObserver.observe(document.body,{childList:true,subtree:true});
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
      status.text("Updating to the next available action…");
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
    var placement="right";
    if (target.length && window.innerWidth>900) { var rect=target[0].getBoundingClientRect(); placement=(rect.left+rect.width/2)<window.innerWidth/2?"right":"left"; }
    else if (target.length) { placement=target[0].getBoundingClientRect().top>window.innerHeight/2?"top":"bottom"; }
    dialog.attr("data-placement",placement);
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
    if (markSeen!==false) window.sessionStorage.setItem(sessionKey(SEEN_KEY),"true");
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
  }
  function render() {
    if(!window.DEIInteractiveGuide){ loadGuide(function(ready){ if(ready) render(); }); return; }
    var index=readStep(),step=activeStep(index);
    if (page()!==step.page) { close(false); return; }
    prepareStep(step);
    if(index===3 && $("#workflow-detection-select").val()){ writeStep(4); scheduleRender(0); return; }
    if(index===4 && $("#detection-generator").attr("data-dei-generated-detection") && String($("#generator-spl").val()||"").trim()){ writeStep(5); scheduleRender(0); return; }
    if(reconcileCompletedStep(index)) return;
    var target=targetFor(step);
    if (!target.length&&!step.completion) { scheduleRender(180); return; }
    var stepChanged=index!==renderedStep;
    var targetChanged=(target[0]||null)!==activeTarget;
    if (!$("#"+OVERLAY_ID).length) { $("body").append('<div id="'+OVERLAY_ID+'" class="dei-onboarding-overlay" data-dei-guide-owner="react"><div class="dei-onboarding-dialog dei-next-guide-dialog"><div id="dei-onboarding-react-root"></div></div></div>').addClass("dei-onboarding-open"); applySavedGuidePosition(); }
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
      window.DEIInteractiveGuide.render({step:step,stepNumber:index+1,totalSteps:steps.length,onBack:function(){ guideBack(index);},onClose:function(){close(true);},onFocusTarget:function(){ focusTarget(true); }});
      renderedStep=index;
      window.setTimeout(function(){ renderingGuide=false; },0);
    }
    if(stepChanged&&!step.completion) focusTarget(false);
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
    if(readStep()<=4){
      writeStep(5);
      renderedStep=-1;
      window.clearTimeout(renderTimer);
      renderTimer=window.setTimeout(render,0);
    }
    return readStep()>=5;
  }
  function start() { close(false); writeStep(0); window.sessionStorage.setItem(sessionKey(SEEN_KEY),"false"); loadGuide(function(ready){ if(ready) render(); }); }

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
  $(document).on("click", ".dei-open-environment-discovery", function(){ if(readStep()===0) goToStep(1); });
  $(document).on("dei:scan-progress", function (_event,status) { if(readStep()===1 && status.stage==="complete") advance(); });
  $(document).on("click", "#dei-open-environment-insights", function(){ if(readStep()===2) advance(); });
  $(document).on("change", "#workflow-detection-select", function(){ if(readStep()===3 && $(this).val()) advance(); });
  $(document).on("dei:detection-draft-generated", function(_event,id,record){ completeDraft(id,record); });
  $(document).on("dei:detection-validation-complete", function(_event,validation){ if(readStep()===5 && validation && validation.status==="passed") advance(); });
  $(document).on("change", "#lifecycle-action-comment", function(){ var step=readStep(); if((step===6||step===8)&&String($(this).val()||"").trim()) advance(); });
  $(document).on("dei:lifecycle-action-complete", function(_event,action){
    if(readStep()===7&&action==="submit_review") goToStep(8);
    if(readStep()===9&&action==="approve_review") goToStep(10);
    if(readStep()===11&&action==="record_deployment") goToStep(12);
    if(action==="return_draft"&&readStep()>=6&&readStep()<=9) goToStep(5);
  });
  $(document).on("change", "#lifecycle-external-id", function(){ if(readStep()===10 && String($(this).val()||"").trim()) goToStep(11); });
  $(document).on("keydown", function(event){ if(!$("#"+OVERLAY_ID).length) return; if(event.key==="Escape") close(true); if(event.key==="F6"){ if($("body").hasClass("dei-guide-focus-mode")) restoreGuide(true); else if($(event.target).closest(".dei-onboarding-dialog").length) focusTarget(false); else $(".dei-next-guide-close").focus(); event.preventDefault(); } });
  $(window).on("resize.deiNextGuide scroll.deiNextGuide", function(){ if($("#"+OVERLAY_ID).length){ var target=targetFor(activeStep(readStep())); position(target); updateMarker(target); } });
  window.setTimeout(function(){ if(window.sessionStorage.getItem(sessionKey(SEEN_KEY))!=="true") render(); },250);
});
