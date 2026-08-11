require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var REPORT_KEY="dei.latestRecommendationReport"; var Store=null; var recommendations=[]; var records=[]; var items=[];
  var STAGES=[
    {id:"recommendation",label:"Recommendation"},{id:"draft",label:"Draft"},{id:"testing",label:"Testing"},
    {id:"peer_review",label:"Peer review"},{id:"catalog",label:"Catalog ready"},{id:"production",label:"Production"},
    {id:"monitoring",label:"Monitoring"},{id:"tuning",label:"Tuning"},{id:"retired",label:"Retired"}
  ];

  function safeJson(value,fallback) { try { return JSON.parse(value||"null")||fallback; } catch (error) { return fallback; } }
  function esc(value) { return String(value==null?"":value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
  function label(value) { return String(value||"unknown").replace(/_/g," ").replace(/\b\w/g,function (c) { return c.toUpperCase(); }); }
  function key(item) { return String(item&&(item.detection_id||item._key||item.id)||"").replace(/^dei-/,""); }
  function recordFor(item) { var id=key(item); return records.filter(function (record) { return key(record)===id; })[0]||null; }
  function stageFor(item) { var record=item.record; if (!record) { return "recommendation"; } if (record.catalog&&record.catalog.status==="ready") { return "catalog"; } return record.state||"draft"; }
  function mitre(item) { var values=item.mitre_techniques||(item.record&&item.record.mitre_attack)||[]; return values.map(function (value) { return typeof value==="string"?value:(value.id||value.technique_id||""); }).filter(Boolean); }
  function sources(item) { return item.sourcetypes||(item.record&&item.record.sourcetypes)||[]; }

  function mergeItems() {
    var seen={}; items=recommendations.map(function (recommendation) { var copy=$.extend(true,{},recommendation); copy.record=recordFor(copy); seen[key(copy)]=true; return copy; });
    records.forEach(function (record) { if (seen[key(record)]) { return; } items.push({detection_id:key(record),name:record.name,readiness:record.source_readiness||"persisted",record:record,sourcetypes:record.sourcetypes||[],mitre_techniques:record.mitre_attack||[]}); });
    items.sort(function (left,right) { return String(left.name||key(left)).localeCompare(String(right.name||key(right))); });
  }

  function guide(item) {
    var record=item.record||{}; var id=encodeURIComponent(key(item)); var stage=stageFor(item); var validation=record.validation||{}; var review=record.review||{}; var deployment=record.deployment||{}; var monitoring=record.monitoring||{};
    var buildable=["production_ready","field_unverified","field_gap"].indexOf(item.readiness)!==-1;
    var guides={
      recommendation:{title:buildable?"Build the first detection draft":"Resolve telemetry prerequisites",explanation:buildable?"The recommendation is available, but no versioned detection artifact exists yet.":"This recommendation is blocked until its required telemetry or field evidence is available.",why:buildable?"The integrated builder converts telemetry and ATT&CK evidence into reviewable SPL without enabling anything.":"Resolving telemetry first prevents the user from generating SPL that cannot run correctly in this environment.",requirements:[["Telemetry readiness",false],["MITRE mapping",false],["Observed sourcetype",false]],action:buildable?"Start detection draft":"Review telemetry actions",href:buildable?"#builder-generate":"detection_action_center?category=telemetry",note:buildable?"Generate and edit the draft in the workspace below.":"The Action Center will show the evidence that must be resolved before building."},
      draft:{title:"Complete and validate the SPL",explanation:"A draft exists. Review its search logic and run bounded historical validation before review.",why:"Validation proves that the SPL parses, runs safely, and produces reviewable evidence against the available telemetry.",requirements:[["Detection SPL",!!record.spl],["Schedule",!!record.schedule],["Validation passed",validation.status==="passed"]],action:validation.status==="passed"?"Continue to review handoff":"Review SPL and validate",href:validation.status==="passed"?"#lifecycle-action-center":"#detection-generator",note:"Only passed validation can advance to peer review."},
      testing:{title:validation.status==="passed"?"Submit for peer review":"Repair or rerun validation",explanation:validation.status==="passed"?"Validation passed. Add the review handoff note and submit this version for an independent decision.":"Testing is active, but passed validation evidence is still required.",why:"Peer review should evaluate a stable, tested version with documented intent and expected analyst behavior.",requirements:[["Validation passed",validation.status==="passed"],["Result evidence",Number(validation.result_count||0)>=0],["Review submission",review.decision==="pending"]],action:validation.status==="passed"?"Open validation handoff":"Open validation workspace",href:validation.status==="passed"?"#lifecycle-action-center":"#detection-generator",note:"Complete the current gate in the workspace below."},
      peer_review:{title:"Complete the peer-review decision",explanation:"A reviewer must approve this version or return it with specific changes.",why:"Independent review prevents untested or poorly scoped logic from reaching the operational catalog.",requirements:[["Validation passed",validation.status==="passed"],["Submitted for review",review.decision==="pending"||review.decision==="approved"],["Peer approval",review.decision==="approved"]],action:"Open peer review",href:"#lifecycle-action-center",note:"Approval automatically moves the detection out of the engineering queue and into the catalog."},
      catalog:{title:"Enable the approved detection",explanation:"Peer review is complete. Record the exact platform object and enable this detection from the governed catalog.",why:"Catalog enablement separates approved content from active production content and preserves the deployment reference.",requirements:[["Peer approval",review.decision==="approved"],["Catalog entry",!!(record.catalog&&record.catalog.cataloged_at)],["Deployment object",!!deployment.external_object_id]],action:"Open catalog enablement",href:"detection_catalog?detection="+id,note:"The detection will enter Production only after its deployment object is recorded."},
      production:{title:"Record the production health baseline",explanation:"The detection is enabled. Capture its first result volume, runtime, and analyst outcome evidence.",why:"An enabled search is not proven healthy until the SOC records how it performs in production.",requirements:[["Deployment enabled",deployment.enabled!==false&&!!deployment.external_object_id],["Initial result volume",monitoring.result_volume!=null],["Health baseline",!!monitoring.last_checked_at]],action:"Record monitoring baseline",href:"#lifecycle-action-center",note:"The first health measurement advances the lifecycle to Monitoring."},
      monitoring:{title:"Continue operational monitoring",explanation:"Review health, analyst outcomes, and tuning needs for this active detection.",why:"Continuous evidence identifies failing searches, noisy logic, and detections that no longer provide useful coverage.",requirements:[["Health measured",!!monitoring.last_checked_at],["Current health",!!monitoring.health],["Analyst outcomes",monitoring.true_positives!=null||monitoring.false_positives!=null]],action:"Manage monitoring",href:"detection_catalog?detection="+id,note:"Use the catalog to manage operational status or open tuning and retirement actions."},
      tuning:{title:"Revise and revalidate the detection",explanation:"A new tuning version is active. Update the SPL and repeat validation and peer review.",why:"Operational changes must not inherit validation or approval from the prior version.",requirements:[["Tuning version",Number(record.version||1)>1],["Revised SPL",!!record.spl],["Fresh validation",validation.status==="passed"]],action:"Open tuning workspace",href:"#detection-generator",note:"The tuned version returns through validation and peer review before re-enablement."},
      retired:{title:"Review retained lifecycle history",explanation:"This detection is retired. Its evidence and decisions remain available for audit.",why:"Retained history explains why coverage was removed and supports future replacement decisions.",requirements:[["Retirement reason",!!(record.retirement&&record.retirement.reason)],["Retirement timestamp",!!(record.retirement&&record.retirement.retired_at)],["Audit history",(record.history||[]).length>0]],action:"Review retired detection",href:"detection_catalog?detection="+id,note:"Retired records remain read-only."}
    };
    return guides[stage]||guides.draft;
  }

  function renderRail(stage) {
    var current=Math.max(0,STAGES.map(function (item) { return item.id; }).indexOf(stage));
    $("#workflow-stage-rail").html(STAGES.map(function (item,index) { var status=index<current?"complete":(index===current?"current":"upcoming"); return '<li data-state="'+status+'"'+(status==="current"?' aria-current="step"':"")+'><span>'+(status==="complete"?"✓":String(index+1))+'</span><div><strong>'+esc(item.label)+'</strong><small>'+(status==="complete"?"Complete":status==="current"?"You are here":"Upcoming")+'</small></div></li>'; }).join(""));
  }

  function renderSelected() {
    var id=String($("#workflow-detection-select").val()||""); var item=items.filter(function (candidate) { return key(candidate)===id; })[0];
    if (!item) { $("#workflow-empty").prop("hidden",false); $("#workflow-driver,#guided-builder-workspace").prop("hidden",true); $(document).trigger("dei:workflow-detection-selected",[""]); return; }
    var stage=stageFor(item); var builderStage=["recommendation","draft","testing","tuning"].indexOf(stage)!==-1;
    $("#guided-builder-workspace").prop("hidden",!builderStage);
    if (builderStage && String($("#builder-detection-select").val()||"")!==key(item)) {
      $("#builder-detection-select").val(key(item)).trigger("change");
    }
    if (item.record) {
      $("#workflow-empty,#workflow-driver").prop("hidden",true);
      $(document).trigger("dei:workflow-detection-selected",[key(item)]);
      try { window.history.replaceState({},"",window.location.pathname+"?detection="+encodeURIComponent(key(item))); } catch (error) { /* URL state is optional. */ }
      return;
    }
    $("#lifecycle-action-center").hide();
    var current=Math.max(0,STAGES.map(function (value) { return value.id; }).indexOf(stage)); var config=guide(item); var record=item.record||{};
    $("#workflow-empty").prop("hidden",true); $("#workflow-driver").prop("hidden",false);
    $("#workflow-stage-count").text("Stage "+(current+1)+" of "+STAGES.length); $("#workflow-detection-title").text(item.name||key(item));
    $("#workflow-current-stage").text("Current stage: "+label(stage)+(record.version?" · Version "+record.version:""));
    var metadata=[item.readiness?label(item.readiness):"",mitre(item).join(" · "),sources(item).join(" · ")].filter(Boolean); $("#workflow-detection-meta").html(metadata.map(function (value) { return "<span>"+esc(value)+"</span>"; }).join(""));
    renderRail(stage); $("#workflow-next-title").text(config.title); $("#workflow-next-explanation").text(config.explanation); $("#workflow-why-text").text(config.why);
    $("#workflow-requirements").html(config.requirements.map(function (requirement) { return '<div data-state="'+(requirement[1]?"complete":"required")+'"><span>'+(requirement[1]?"✓":"!")+'</span><strong>'+esc(requirement[0])+'</strong><small>'+(requirement[1]?"Complete":"Required now")+'</small></div>'; }).join(""));
    $("#workflow-primary-action").attr("href",config.href).text(config.action+" →"); $("#workflow-action-note").text(config.note); $("#workflow-why-title").text("Why "+label(stage)+" matters");
    var history=(record.history||[]).slice(-3).reverse(); $("#workflow-advanced-evidence").html('<dl><dt>Lifecycle state</dt><dd>'+esc(label(stage))+'</dd><dt>Record version</dt><dd>'+esc(record.version||"Not created")+'</dd><dt>Storage</dt><dd>'+esc(Store?Store.mode():"Unavailable")+'</dd></dl>'+(history.length?'<h4>Recent history</h4>'+history.map(function (entry) { return '<p><strong>'+esc(label(entry.event))+'</strong><br/><small>'+esc(entry.detail||"No detail")+'</small></p>'; }).join(""):""));
    try { window.history.replaceState({},"",window.location.pathname+"?detection="+encodeURIComponent(id)); } catch (error) { /* URL state is optional. */ }
  }

  function requested() { var match=String(window.location.search||"").match(/[?&]detection=([^&]+)/); if (!match) { return ""; } try { return decodeURIComponent(match[1]); } catch (error) { return match[1]; } }
  function populate() { mergeItems(); var selected=requested()||String($("#workflow-detection-select").val()||""); $("#workflow-detection-select").html('<option value="">Select a detection</option>'+items.map(function (item) { return '<option value="'+esc(key(item))+'">'+esc(item.name||key(item))+' — '+esc(label(stageFor(item)))+'</option>'; }).join("")); if (selected&&items.some(function (item) { return key(item)===selected; })) { $("#workflow-detection-select").val(selected); } $("#workflow-data-status").text("Workflow: "+items.length+" detections").toggleClass("healthy",items.length>0); renderSelected(); }
  function initialize(attempt) { Store=window.DEILifecycleStore; if (!Store&&attempt<40) { window.setTimeout(function () { initialize(attempt+1); },50); return; } recommendations=(safeJson(window.sessionStorage.getItem(REPORT_KEY),{}).recommendations)||[]; if (!Store) { records=[]; populate(); return; } Store.load().done(function (loaded) { records=Array.isArray(loaded)?loaded:[]; populate(); }); }

  $("#workflow-detection-select").on("change",renderSelected); $("#lifecycle-workspace-menu").on("change",function () { var destination=$(this).val(); if (destination) { window.location.href=destination; } }); initialize(0);
  $(document).on("dei:lifecycle-records-updated",function (event,loaded) { records=Array.isArray(loaded)?loaded:records; populate(); });
  $(document).on("dei:detection-draft-generated",function (event,id,record) {
    var value=String(id||"");
    if (!value || !record) { return; }
    records=records.filter(function (item) { return key(item)!==value; });
    records.push(record);
    populate();
  });
});
