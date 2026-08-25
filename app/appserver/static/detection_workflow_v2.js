require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var REPORT_KEY="dei.latestRecommendationReport"; var Store=null; var recommendations=[]; var library=Array.isArray(window.DEIDetectionLibrary)?window.DEIDetectionLibrary.slice():[]; var libraryState=library.length?"ready":"error"; var records=[]; var items=[];
  var STAGES=[
    {id:"recommendation",label:"Recommendation"},{id:"draft",label:"Draft"},{id:"testing",label:"Testing"},
    {id:"peer_review",label:"Peer review"},{id:"catalog",label:"Catalog ready"},{id:"production",label:"Production"},
    {id:"monitoring",label:"Monitoring"},{id:"tuning",label:"Tuning"},{id:"retired",label:"Retired"}
  ];

  function safeJson(value,fallback) { try { return JSON.parse(value||"null")||fallback; } catch (error) { return fallback; } }
  function esc(value) { return String(value==null?"":value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
  function label(value) { return String(value||"unknown").replace(/_/g," ").replace(/\b\w/g,function (c) { return c.toUpperCase(); }); }
  function key(item) { return String(item&&(item._workflow_key||item._key||item.detection_id||item.id)||"").replace(/^dei-/,""); }
  function stageFor(item) { var record=item.record; if (!record) { return "recommendation"; } if (record.catalog&&["ready","development","staging"].indexOf(record.catalog.status)!==-1) { return "catalog"; } return record.state||"draft"; }
  function mitre(item) { var values=item.mitre_techniques||(item.record&&item.record.mitre_attack)||[]; return values.map(function (value) { return typeof value==="string"?value:(value.id||value.technique_id||""); }).filter(Boolean); }
  function sources(item) { return item.sourcetypes||item.observed_sourcetypes||item.observed_sources||(item.record&&item.record.sourcetypes)||[]; }
  function missingSources(item) { return item.missing_sources||[]; }
  function fieldGapSummary(item) {
    var gaps=[]; Object.keys(item.missing_fields||{}).forEach(function (source) {
      (item.missing_fields[source]||[]).forEach(function (fields) { gaps.push(source+": "+fields); });
    });
    (item.unverified_field_sources||[]).forEach(function (source) { gaps.push(source+": fields not verified"); });
    return gaps;
  }

  function mergeItems() {
    var evidence={}; recommendations.forEach(function(item){evidence[item.detection_id]=item;}); items=[];
    library.forEach(function(template){ var copy=$.extend(true,{},template,evidence[template.detection_id]||{}); copy.detection_id=template.detection_id; copy.readiness=copy.readiness||"not_observed"; copy._workflow_key="library:"+template.detection_id; copy.library_template=true; items.push(copy); });
    records.forEach(function (record) { items.push({detection_id:record.detection_id||key(record),_workflow_key:"instance:"+key(record),name:record.name,readiness:record.source_readiness||"persisted",record:record,sourcetypes:record.sourcetypes||[],mitre_techniques:record.mitre_attack||[]}); });
    items.sort(function (left,right) { return String(left.name||key(left)).localeCompare(String(right.name||key(right))); });
  }

  function guide(item) {
    var record=item.record||{}; var id=encodeURIComponent(key(item)); var stage=stageFor(item); var validation=record.validation||{}; var review=record.review||{}; var deployment=record.deployment||{}; var monitoring=record.monitoring||{};
    var buildable=["production_ready","field_unverified","field_gap"].indexOf(item.readiness)!==-1;
    // Keep the router aligned with the generator: an unobserved library item
    // is authorable as a telemetry-gated planning draft, not diverted away.
    var planning=["partial","unsupported","requires_es","requires_enterprise_security","not_observed"].indexOf(item.readiness)!==-1;
    var observed=sources(item); var techniques=mitre(item); var missing=missingSources(item); var fieldGaps=fieldGapSummary(item);
    var telemetryReady=item.readiness==="production_ready";
    var recommendationRequirements=[
      ["Telemetry readiness",telemetryReady,telemetryReady?"Required telemetry and fields are verified.":(missing.length?"Missing: "+missing.join(" · "):(fieldGaps.length?fieldGaps.join(" · "):"No qualifying telemetry route was verified by the latest scan."))],
      ["MITRE mapping",techniques.length>0,techniques.length?techniques.join(" · "):"No ATT&CK technique is mapped."],
      ["Observed sourcetype",observed.length>0,observed.length?observed.join(" · "):"No observed sourcetype currently maps to the required source."]
    ];
    var remediationHref="#workflow-environment-panel";
    var guides={
      recommendation:{title:buildable?"Build the first detection draft":planning?"Create a telemetry-gated planning draft":"Resolve telemetry prerequisites",explanation:buildable?"The recommendation is available, but no versioned detection artifact exists yet.":planning?"You can author and syntax-test the SPL now. Lifecycle advancement remains blocked until the required telemetry is verified.":"This recommendation is blocked until its required telemetry or field evidence is available.",why:buildable?"The integrated builder converts telemetry and ATT&CK evidence into reviewable SPL without enabling anything.":"Planning drafts preserve engineering progress without treating unavailable telemetry as production-ready evidence.",requirements:recommendationRequirements,action:buildable?"Start detection draft":planning?"Create planning draft":"Review telemetry actions",href:(buildable||planning)?"#builder-generate":remediationHref,secondaryAction:planning?"Resolve telemetry evidence":"",secondaryHref:planning?remediationHref:"",note:buildable?"Generate and edit the draft in the workspace below.":planning?"The draft will remain at Recommendation/Draft until a new scan verifies its telemetry.":"The Action Center will show the exact evidence that must be resolved before building."},
      draft:{title:"Complete and validate the SPL",explanation:"A draft exists. Review its search logic and run bounded historical validation before review.",why:"Validation proves that the SPL parses, runs safely, and produces reviewable evidence against the available telemetry.",requirements:[["Detection SPL",!!record.spl],["Schedule",!!record.schedule],["Validation passed",validation.status==="passed"]],action:validation.status==="passed"?"Continue to review handoff":"Review SPL and validate",href:validation.status==="passed"?"#lifecycle-action-center":"#detection-generator",note:"Only passed validation can advance to peer review."},
      testing:{title:validation.status==="passed"?"Submit for peer review":"Repair or rerun validation",explanation:validation.status==="passed"?"Validation passed. Add the review handoff note and submit this version for an independent decision.":"Testing is active, but passed validation evidence is still required.",why:"Peer review should evaluate a stable, tested version with documented intent and expected analyst behavior.",requirements:[["Validation passed",validation.status==="passed"],["Result evidence",Number(validation.result_count||0)>=0],["Review submission",review.decision==="pending"]],action:validation.status==="passed"?"Open validation handoff":"Open validation workspace",href:validation.status==="passed"?"#lifecycle-action-center":"#detection-generator",note:"Complete the current gate in the workspace below."},
      peer_review:{title:"Complete the peer-review decision",explanation:"A reviewer must approve this version or return it with specific changes.",why:"Independent review prevents untested or poorly scoped logic from reaching the operational catalog.",requirements:[["Validation passed",validation.status==="passed"],["Submitted for review",review.decision==="pending"||review.decision==="approved"],["Peer approval",review.decision==="approved"]],action:"Open peer review",href:"#lifecycle-action-center",note:"Approval automatically moves the detection out of the engineering queue and into the catalog."},
      catalog:{title:record.catalog&&["development","staging"].indexOf(record.catalog.status)!==-1?"Promote or return the deployed version":"Deploy the approved detection",explanation:"Peer review is complete. Record the exact target object in Development, Staging, or Production from the governed catalog.",why:"Environment-aware catalog routing prevents a development or staging object from being mislabeled as production.",requirements:[["Peer approval",review.decision==="approved"],["Catalog entry",!!(record.catalog&&record.catalog.cataloged_at)],["Deployment object",!!deployment.external_object_id]],action:"Open catalog change control",href:"#lifecycle-action-center",note:"Only the Production environment advances the lifecycle to Production. Development and Staging remain governed catalog buckets."},
      production:{title:"Record the production health baseline",explanation:"The detection is enabled. Capture its first result volume, runtime, and analyst outcome evidence.",why:"An enabled search is not proven healthy until the SOC records how it performs in production.",requirements:[["Deployment enabled",deployment.enabled!==false&&!!deployment.external_object_id],["Initial result volume",monitoring.result_volume!=null],["Health baseline",!!monitoring.last_checked_at]],action:"Record monitoring baseline",href:"#lifecycle-action-center",note:"The first health measurement advances the lifecycle to Monitoring."},
      monitoring:{title:"Continue operational monitoring",explanation:"Review health, analyst outcomes, and tuning needs for this active detection.",why:"Continuous evidence identifies failing searches, noisy logic, and detections that no longer provide useful coverage.",requirements:[["Health measured",!!monitoring.last_checked_at],["Current health",!!monitoring.health],["Analyst outcomes",monitoring.true_positives!=null||monitoring.false_positives!=null]],action:"Manage monitoring",href:"#lifecycle-action-center",note:"Record health, open tuning, or retire from Change control in this workspace."},
      tuning:{title:"Revise and revalidate the detection",explanation:"A new tuning version is active. Update the SPL and repeat validation and peer review.",why:"Operational changes must not inherit validation or approval from the prior version.",requirements:[["Tuning version",Number(record.version||1)>1],["Revised SPL",!!record.spl],["Fresh validation",validation.status==="passed"]],action:"Open tuning workspace",href:"#detection-generator",note:"The tuned version returns through validation and peer review before re-enablement."},
      retired:{title:"Review retained lifecycle history",explanation:"This detection is retired. Its evidence and decisions remain available for audit.",why:"Retained history explains why coverage was removed and supports future replacement decisions.",requirements:[["Retirement reason",!!(record.retirement&&record.retirement.reason)],["Retirement timestamp",!!(record.retirement&&record.retirement.retired_at)],["Audit history",(record.history||[]).length>0]],action:"Review retired detection",href:"#lifecycle-action-center",note:"Retired records remain read-only."}
    };
    return guides[stage]||guides.draft;
  }

  function renderRail(stage) {
    var current=Math.max(0,STAGES.map(function (item) { return item.id; }).indexOf(stage));
    $("#workflow-stage-rail").html(STAGES.map(function (item,index) { var status=index<current?"complete":(index===current?"current":"upcoming"); return '<li data-state="'+status+'"'+(status==="current"?' aria-current="step"':"")+'><span>'+(status==="complete"?"✓":String(index+1))+'</span><div><strong>'+esc(item.label)+'</strong><small>'+(status==="complete"?"Complete":status==="current"?"You are here":"Upcoming")+'</small></div></li>'; }).join(""));
  }

  function applyArtifactMode(stage,record) {
    var validation=record&&record.validation||{};
    var locked=["peer_review","catalog","production","monitoring","retired"].indexOf(stage)!==-1 || (stage==="testing"&&validation.status==="passed");
    $("#workflow-artifact-mode").text(locked?"Read-only governed version":"Editable artifact").toggleClass("locked",locked);
    $("#generator-spl,#builder-cron,#builder-earliest,#builder-latest").prop("readonly",locked).attr("aria-readonly",locked?"true":"false");
    $("#builder-save-draft,#builder-reset-draft,#builder-clear-spl,#builder-run-validation,#builder-apply-validation-fix,#builder-edit-validation-query,#builder-retry-validation").prop("disabled",locked);
  }

  function renderSelected() {
    var id=String($("#workflow-detection-select").val()||""); var item=items.filter(function (candidate) { return key(candidate)===id; })[0];
    if (!item) { $("#workflow-empty").prop("hidden",false); $("#workflow-driver,#workflow-unified-workspace").prop("hidden",true); $(document).trigger("dei:workflow-detection-selected",[""]); return; }
    var stage=stageFor(item);
    $("#workflow-unified-workspace").prop("hidden",false);
    if (item.library_template) {
      // The generator may still be loading its library options. Publish an
      // explicit request that it can reconcile after asynchronous startup.
      $(document).trigger("dei:builder-selection-requested",[item.detection_id]);
    }
    applyArtifactMode(stage,item.record);
    window.setTimeout(function () { applyArtifactMode(stage,item.record); },0);
    // A saved Draft must not populate the SPL editor merely because its
    // recommendation was selected.  The Generate action owns draft creation
    // (and intentional regeneration); later governed stages remain inspectable.
    if (item.record && stage!=="draft") { $(document).trigger("dei:artifact-inspection-requested",[key(item.record),stage,item.record]); }
    var current=Math.max(0,STAGES.map(function (value) { return value.id; }).indexOf(stage)); var config=guide(item); var record=item.record||{};
    $("#workflow-empty").prop("hidden",true); $("#workflow-driver").prop("hidden",false);
    $("#workflow-stage-count").text("Stage "+(current+1)+" of "+STAGES.length); $("#workflow-detection-title").text(item.name||key(item));
    $("#workflow-current-stage").text("Current stage: "+label(stage)+(record.version?" · Version "+record.version:""));
    var metadata=[item.readiness?label(item.readiness):"",mitre(item).join(" · "),sources(item).join(" · ")].filter(Boolean); $("#workflow-detection-meta").html(metadata.map(function (value) { return "<span>"+esc(value)+"</span>"; }).join(""));
    renderRail(stage); $("#workflow-next-title").text(config.title); $("#workflow-next-explanation").text(config.explanation); $("#workflow-why-text").text(config.why);
    $("#workflow-requirements").html(config.requirements.map(function (requirement) { return '<div data-state="'+(requirement[1]?"complete":"required")+'"><span>'+(requirement[1]?"✓":"!")+'</span><div class="dei-workflow-requirement-copy"><strong>'+esc(requirement[0])+'</strong><small>'+esc(requirement[2]||"")+'</small></div><small>'+(requirement[1]?"Complete":"Required now")+'</small></div>'; }).join(""));
    $("#workflow-primary-action").attr("href",config.href).text(config.action+" →");
    $("#workflow-secondary-action").prop("hidden",!config.secondaryAction).attr("href",config.secondaryHref||"#").text((config.secondaryAction||"")+" →");
    $("#workflow-action-note").text(config.note); $("#workflow-why-title").text("Why "+label(stage)+" matters");
    var history=(record.history||[]).slice(-3).reverse(); $("#workflow-advanced-evidence").html('<dl><dt>Lifecycle state</dt><dd>'+esc(label(stage))+'</dd><dt>Record version</dt><dd>'+esc(record.version||"Not created")+'</dd><dt>Storage</dt><dd>'+esc(Store?Store.mode():"Unavailable")+'</dd></dl>'+(history.length?'<h4>Recent history</h4>'+history.map(function (entry) { return '<p><strong>'+esc(label(entry.event))+'</strong><br/><small>'+esc(entry.detail||"No detail")+'</small></p>'; }).join(""):""));
    $(document).trigger("dei:workflow-detection-selected",[item.record?key(item.record):item.detection_id]);
    try { window.history.replaceState({},"",window.location.pathname+"?detection="+encodeURIComponent(id)); } catch (error) { /* URL state is optional. */ }
  }

  function requested() { var match=String(window.location.search||"").match(/[?&]detection=([^&]+)/); if (!match) { return ""; } try { return decodeURIComponent(match[1]); } catch (error) { return match[1]; } }
  function populate() { mergeItems(); var selected=requested()||String($("#workflow-detection-select").val()||""); var templates=items.filter(function(item){return item.library_template;}); var instances=items.filter(function(item){return !item.library_template;}); var libraryOptions=templates.length?templates.map(function (item) { return '<option value="'+esc(key(item))+'">'+esc(item.name||item.detection_id)+'</option>'; }).join(""):'<option value="" disabled="disabled">'+(libraryState==="loading"?"Loading detection library…":"Detection library unavailable")+'</option>'; $("#workflow-detection-select").html('<option value="">Select a detection</option><optgroup label="Detection Library · start a new use case">'+libraryOptions+'</optgroup>'+(instances.length?'<optgroup label="Lifecycle work · continue an existing use case">'+instances.map(function(item){return '<option value="'+esc(key(item))+'">'+esc(item.name||key(item))+' — '+esc(label(stageFor(item)))+'</option>';}).join("")+'</optgroup>':"")); if(selected&&items.some(function(item){return key(item)===selected;})){ $("#workflow-detection-select").val(selected); } else if(selected&&items.some(function(item){return key(item)==="instance:"+selected;})){ $("#workflow-detection-select").val("instance:"+selected); } if(libraryState==="ready"){ $("#workflow-data-status").removeClass("unhealthy").addClass("healthy").text("Library: "+templates.length+" detections · "+instances.length+" lifecycle use cases"); } else { $("#workflow-data-status").removeClass("healthy").addClass(libraryState==="error"?"unhealthy":"").text(libraryState==="loading"?"Detection library: loading…":"Detection library unavailable · reload or contact the app administrator"); } renderSelected(); $(document).trigger("dei:workflow-options-updated",[items.slice()]); }
  function initialize(attempt) {
    recommendations=(safeJson(window.sessionStorage.getItem(REPORT_KEY),{}).recommendations)||[];
    if(attempt===0) { populate(); }
    Store=window.DEILifecycleStore;
    if (!Store&&attempt<40) { window.setTimeout(function () { initialize(attempt+1); },50); return; }
    if (!Store) { records=[]; populate(); $("#workflow-data-status").removeClass("healthy").addClass("unhealthy").text("Workflow storage unavailable · showing current scan recommendations"); return; }
    var settled=false; var timer=window.setTimeout(function(){
      if(settled) return; $("#workflow-data-status").removeClass("healthy").addClass("unhealthy").text("Workflow records are taking longer than expected · current scan recommendations remain available");
    },8000);
    Store.load().done(function (loaded) { settled=true; window.clearTimeout(timer); records=Array.isArray(loaded)?loaded:[]; populate(); });
  }

  $("#workflow-detection-select").on("change",renderSelected); initialize(0);
  $(document).on("dei:lifecycle-records-updated",function (event,loaded) { records=Array.isArray(loaded)?loaded:records; populate(); });
  $(document).on("dei:environment-refreshed",function () {
    recommendations=(safeJson(window.sessionStorage.getItem(REPORT_KEY),{}).recommendations)||[];
    $("#workflow-environment-state").text("Current");
    $("#workflow-environment-panel").prop("open",false);
    populate();
    window.setTimeout(function(){var target=document.getElementById("workflow-detection-select");if(target){target.scrollIntoView({behavior:"smooth",block:"center"});target.focus();}},120);
  });
  $(document).on("dei:artifact-inspection-requested",function (event,id,stage,record) { if (id) { $("#workflow-detection-select").val(String(id)); } applyArtifactMode(String(stage||"draft"),record); });
  $(document).on("dei:detection-draft-generated dei:detection-artifact-saved",function (event,id,record) {
    var value=String(id||"");
    if (!value || !record) { return; }
    records=records.filter(function (item) { return key(item)!==value; });
    records.push(record);
    try { window.history.replaceState({},"",window.location.pathname+"?detection="+encodeURIComponent("instance:"+value)); } catch (error) { /* URL state is optional. */ }
    populate();
    $("#workflow-detection-select").val("instance:"+value); renderSelected();
  });
});
