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
  var waitingForLifecycleWrite=false;
  var renderTimer=null;
  var targetObserver=null;
  var steps=[
    {page:"home",target:".dei-run-intelligence-scan",title:"Discover active telemetry",instruction:"Start a current, permission-aware scan of the Splunk data available to DEI.",actionLabel:"Select Run new scan"},
    {page:"environment",target:"#dei-open-environment-insights",title:"Open the readiness results",instruction:"Continue to the intelligence generated from the completed telemetry scan.",actionLabel:"Select View intelligence results"},
    {page:"environment_insights",target:".dei-mitre-glow-button",title:"Move from evidence to coverage",instruction:"Use the saved readiness evidence to continue into ATT&CK coverage analysis.",actionLabel:"Open the MITRE workspace"},
    {page:"mitre",target:"#mitre-sourcetype-filter",title:"Scope the detection opportunities",instruction:"Choose one observed sourcetype so the advisor shows relevant, supportable detections.",actionLabel:"Select a sourcetype"},
    {page:"mitre",target:".dei-advisor-item",title:"Choose a detection opportunity",instruction:"Select a recommendation to inspect its ATT&CK and telemetry-readiness evidence.",actionLabel:"Select one Detection Advisor result"},
    {page:"builder",target:"#builder-detection-select",title:"Load the selected detection",instruction:"Confirm the recommendation you want to engineer through the guided workflow.",actionLabel:"Select the detection in Builder"},
    {page:"builder",target:"#builder-generate",title:"Generate a reviewable draft",instruction:"Create the initial SPL and metadata from the selected telemetry evidence.",actionLabel:"Select Generate detection draft"},
    {page:"builder",target:"#builder-run-validation",title:"Validate the detection",instruction:"Run the bounded historical search and review the returned evidence.",actionLabel:"Select Run validation"},
    {page:"builder",target:"#lifecycle-action-buttons [data-action]:not(:disabled)",title:"Complete the analyst-controlled gate",instruction:"Complete each evidence, review, and deployment gate shown for this detection. The guide stays with the record until it is catalog-ready.",actionLabel:"Complete the highlighted lifecycle action"},
    {page:"catalog",target:"#catalog-external-id",title:"Identify the production object",instruction:"Record the exact saved search, correlation search, or deployment object that will run this detection.",actionLabel:"Enter the deployment object ID"},
    {page:"catalog",target:'[data-catalog-action="enable"],[data-catalog-action="disable"],[data-catalog-action="reenable"]',title:"Set the detection operating state",instruction:"Complete the final catalog action. Enable a ready detection, disable an active detection, or re-enable a disabled detection.",actionLabel:"Select the highlighted catalog action"}
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
    var seed="active-login";
    try { seed=String(Splunk.util.getConfigValue("USERNAME")||"unknown")+"|"+String(Splunk.util.getConfigValue("FORM_KEY")||"active-login"); } catch(error) {}
    var hash=2166136261;
    for(var index=0;index<seed.length;index+=1){ hash^=seed.charCodeAt(index); hash=Math.imul(hash,16777619); }
    return base+"."+(hash>>>0).toString(36);
  }
  function route(name) {
    var base={home:"dei_home",environment:"command_center",environment_insights:"environment_insights",mitre:"mitre_coverage",builder:"detection_workflow",catalog:"detection_catalog"}[name];
    var detection=selectedDetection||String(window.localStorage.getItem("dei.selectedDetectionDraft")||"");
    return detection&&(name==="builder"||name==="catalog")?base+"?detection="+encodeURIComponent(detection):base;
  }
  function readStep() { var value=Number(window.sessionStorage.getItem(sessionKey(STEP_KEY))||0); return Math.max(0,Math.min(steps.length-1,value)); }
  function writeStep(value) { window.sessionStorage.setItem(sessionKey(STEP_KEY),String(value)); }
  function targetFor(step) { return $(step.target).filter(":visible").first(); }
  function scheduleRender(delay) { window.clearTimeout(renderTimer); renderTimer=window.setTimeout(render,delay||80); }
  function observeTargets() {
    if(targetObserver||!window.MutationObserver) return;
    targetObserver=new window.MutationObserver(function(){ if($("#"+OVERLAY_ID).length) scheduleRender(60); });
    targetObserver.observe(document.body,{childList:true,subtree:true});
  }
  function updateMarker(target) {
    var marker=$("#dei-guide-action-marker");
    if(!target.length){ marker.remove(); return; }
    if(!marker.length){ marker=$('<span id="dei-guide-action-marker" aria-hidden="true">NEXT ACTION</span>').appendTo("body"); }
    var rect=target[0].getBoundingClientRect();
    marker.css({top:Math.max(8,rect.top-13),left:Math.min(window.innerWidth-112,Math.max(8,rect.right-98))});
  }
  function focusTarget() { var target=targetFor(steps[readStep()]); if (!target.length) return; target[0].scrollIntoView({behavior:"smooth",block:"center"}); window.setTimeout(function(){ target.attr("tabindex",target.attr("tabindex")||"-1").focus(); },320); }
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
    if(targetObserver){ targetObserver.disconnect(); targetObserver=null; }
    if (window.DEIInteractiveGuide) window.DEIInteractiveGuide.unmount();
    $("#"+OVERLAY_ID+",#dei-guide-action-marker").remove();
    $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
    $("body").removeClass("dei-onboarding-open");
  }
  function render() {
    if(!window.DEIInteractiveGuide){ loadGuide(function(ready){ if(ready) render(); }); return; }
    var index=readStep(),step=steps[index];
    if (page()!==step.page) { window.location.href=route(step.page); return; }
    if(index===5 && $("#builder-detection-select").val()){ writeStep(6); scheduleRender(0); return; }
    if(index===9 && !$("#catalog-external-id").filter(":visible").length && $(steps[10].target).filter(":visible").length){ writeStep(10); scheduleRender(0); return; }
    var target=targetFor(step);
    if (!target.length) { scheduleRender(180); return; }
    if (!$("#"+OVERLAY_ID).length) $("body").append('<div id="'+OVERLAY_ID+'" class="dei-onboarding-overlay" data-dei-guide-owner="react"><div class="dei-onboarding-dialog dei-next-guide-dialog"><div id="dei-onboarding-react-root"></div></div></div>').addClass("dei-onboarding-open");
    observeTargets();
    $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
    target.addClass("dei-onboarding-target").attr("aria-describedby","dei-guide-instruction");
    updateMarker(target);
    position(target);
    window.DEIInteractiveGuide.render({step:step,stepNumber:index+1,totalSteps:steps.length,onBack:function(){ if(index>0){writeStep(index-1);render();}},onClose:function(){close(true);},onFocusTarget:focusTarget});
    focusTarget();
  }
  function advance() { var index=readStep(); if (index>=steps.length-1) { close(true); return; } writeStep(index+1); render(); }
  function start() { close(false); writeStep(0); window.sessionStorage.setItem(sessionKey(SEEN_KEY),"false"); loadGuide(function(ready){ if(ready) render(); }); }

  window.DEINextGuide={start:start,render:render,close:close};
  $(document).on("click", "#dei-home-tour", function (event) { event.preventDefault(); event.stopImmediatePropagation(); start(); });
  $(document).on("dei:scan-progress", function (_event,status) { if(readStep()===0 && status.stage==="complete") advance(); });
  $(document).on("click", "#dei-open-environment-insights", function(){ if(readStep()===1) advance(); });
  $(document).on("click", ".dei-mitre-glow-button", function(){ if(readStep()===2) advance(); });
  $(document).on("change", "#mitre-sourcetype-filter", function(){ if(readStep()===3 && $(this).val()!=="all") window.setTimeout(advance,0); });
  $(document).on("dei:advisor-detection-selected", function(_event,id){ if(readStep()===4){ selectedDetection=String(id||""); if(selectedDetection) window.localStorage.setItem("dei.selectedDetectionDraft",selectedDetection); advance(); } });
  $(document).on("change", "#builder-detection-select", function(){ if(readStep()===5 && $(this).val()) advance(); });
  $(document).on("dei:detection-draft-generated", function(){ if(readStep()===6) advance(); });
  $(document).on("dei:detection-validation-complete", function(_event,validation){ if(readStep()===7 && validation && validation.status==="passed") advance(); });
  $(document).on("click", "#lifecycle-action-buttons [data-action]", function(){ if(readStep()===8) waitingForLifecycleWrite=true; });
  $(document).on("dei:lifecycle-records-updated", function(_event,records){
    if(readStep()!==8 || !waitingForLifecycleWrite) return;
    waitingForLifecycleWrite=false;
    var detection=selectedDetection||String(window.localStorage.getItem("dei.selectedDetectionDraft")||"");
    var record=(records||[]).filter(function(item){ return String(item.id||item.detection_id||"")===detection; })[0];
    if(record && record.catalog && record.catalog.status==="ready") advance(); else render();
  });
  $(document).on("change", "#catalog-external-id", function(){ if(readStep()===9 && String($(this).val()||"").trim()){ writeStep(10); scheduleRender(0); } });
  $(document).on("dei:catalog-action-complete", function(_event,status){ if(readStep()===10 && (status==="enabled"||status==="disabled")) close(true); });
  $(document).on("keydown", function(event){ if(!$("#"+OVERLAY_ID).length) return; if(event.key==="Escape") close(true); if(event.key==="F6"){ if($(event.target).closest(".dei-onboarding-dialog").length) focusTarget(); else $(".dei-next-guide-close").focus(); event.preventDefault(); } });
  $(window).on("resize.deiNextGuide scroll.deiNextGuide", function(){ if($("#"+OVERLAY_ID).length){ var target=targetFor(steps[readStep()]); position(target); updateMarker(target); } });
  window.setTimeout(function(){ if(window.sessionStorage.getItem(sessionKey(SEEN_KEY))!=="true") render(); },250);
});
