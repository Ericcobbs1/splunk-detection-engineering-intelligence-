require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";
  var STEP_KEY="dei.nextGuide.step";
  var SEEN_KEY="dei.nextGuide.seen";
  var selectedDetection="";
  var waitingForLifecycleWrite=false;
  var steps=[
    {page:"home",target:".dei-run-intelligence-scan",title:"Discover active telemetry",instruction:"Start a current, permission-aware scan of the Splunk data available to DEI.",actionLabel:"Select Run new scan"},
    {page:"environment",target:"#dei-open-environment-insights",title:"Open the readiness results",instruction:"Continue to the intelligence generated from the completed telemetry scan.",actionLabel:"Select View intelligence results"},
    {page:"environment_insights",target:".dei-mitre-glow-button",title:"Move from evidence to coverage",instruction:"Use the saved readiness evidence to continue into ATT&CK coverage analysis.",actionLabel:"Open the MITRE workspace"},
    {page:"mitre",target:"#mitre-sourcetype-filter",title:"Scope the detection opportunities",instruction:"Choose one observed sourcetype so the advisor shows relevant, supportable detections.",actionLabel:"Select a sourcetype"},
    {page:"mitre",target:".dei-advisor-item",title:"Choose a detection opportunity",instruction:"Select a recommendation to inspect its ATT&CK and telemetry-readiness evidence.",actionLabel:"Select one Detection Advisor result"},
    {page:"builder",target:"#builder-detection-select",title:"Load the selected detection",instruction:"Confirm the recommendation you want to engineer through the guided workflow.",actionLabel:"Select the detection in Builder"},
    {page:"builder",target:"#builder-generate",title:"Generate a reviewable draft",instruction:"Create the initial SPL and metadata from the selected telemetry evidence.",actionLabel:"Select Generate detection draft"},
    {page:"builder",target:"#builder-run-validation",title:"Validate the detection",instruction:"Run the bounded historical search and review the returned evidence.",actionLabel:"Select Run validation"},
    {page:"builder",target:"#lifecycle-action-center",title:"Complete the analyst-controlled gate",instruction:"Use the current lifecycle action to submit evidence, review, deploy, or record health. The guide follows the record state.",actionLabel:"Complete the displayed lifecycle action"},
    {page:"catalog",target:'[data-catalog-action="enable"]',title:"Enable the approved detection",instruction:"Record the authorized deployment object and enable the catalog entry.",actionLabel:"Select Enable detection"}
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
    if (window.DEIInteractiveGuide) window.DEIInteractiveGuide.unmount();
    $("#dei-onboarding-overlay").remove();
    $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
    $("body").removeClass("dei-onboarding-open");
  }
  function render() {
    var index=readStep(),step=steps[index];
    if (page()!==step.page) { window.location.href=route(step.page); return; }
    var target=targetFor(step);
    if (!target.length) { window.setTimeout(render,300); return; }
    if (!$("#dei-onboarding-overlay").length) $("body").append('<div id="dei-onboarding-overlay" class="dei-onboarding-overlay"><div class="dei-onboarding-dialog dei-next-guide-dialog"><div id="dei-onboarding-react-root"></div></div></div>').addClass("dei-onboarding-open");
    $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
    target.addClass("dei-onboarding-target").attr("aria-describedby","dei-guide-instruction");
    position(target);
    window.DEIInteractiveGuide.render({step:step,stepNumber:index+1,totalSteps:steps.length,onBack:function(){ if(index>0){writeStep(index-1);render();}},onClose:function(){close(true);},onFocusTarget:focusTarget});
    focusTarget();
  }
  function advance() { var index=readStep(); if (index>=steps.length-1) { close(true); return; } writeStep(index+1); render(); }
  function start() { close(false); writeStep(0); window.sessionStorage.setItem(sessionKey(SEEN_KEY),"false"); render(); }

  window.DEINextGuide={start:start,render:render,close:close};
  $(document).on("click", "#dei-home-tour", function (event) { event.preventDefault(); event.stopImmediatePropagation(); start(); });
  $(document).on("dei:scan-progress", function (_event,status) { if(readStep()===0 && status.stage==="complete") advance(); });
  $(document).on("click", "#dei-open-environment-insights", function(){ if(readStep()===1) advance(); });
  $(document).on("click", ".dei-mitre-glow-button", function(){ if(readStep()===2) advance(); });
  $(document).on("change", "#mitre-sourcetype-filter", function(){ if(readStep()===3 && $(this).val()!=="all") advance(); });
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
  $(document).on("dei:catalog-action-complete", function(_event,status){ if(readStep()===9 && status==="enabled") close(true); });
  $(document).on("keydown", function(event){ if(!$("#dei-onboarding-overlay").length) return; if(event.key==="Escape") close(true); if(event.key==="F6"){ if($(event.target).closest(".dei-onboarding-dialog").length) focusTarget(); else $(".dei-next-guide-close").focus(); event.preventDefault(); } });
  $(window).on("resize.deiNextGuide", function(){ if($("#dei-onboarding-overlay").length) position(targetFor(steps[readStep()])); });
  window.setTimeout(function(){ if(window.sessionStorage.getItem(sessionKey(SEEN_KEY))!=="true") render(); },250);
});
