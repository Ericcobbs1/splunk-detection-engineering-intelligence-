require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var REPORT_KEY = "dei.latestRecommendationReport";
  var REPORT_TIME_KEY = "dei.latestRecommendationTime";
  var SELECTED_DETECTION_KEY = "dei.selectedDetectionDraft";
  var ARTIFACT_KEY = "dei.detectionDraftArtifacts";
  var report = null;
  var records = [];
  var selectedRecord = null;
  var pendingWorkspaceAction = "";
  var Store = null;
  var generatedDrafts = {};

  function safeJson(value) { try { return JSON.parse(value || "null"); } catch (error) { return null; } }
  function esc(value) { return String(value == null ? "" : value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
  function label(value) { return String(value || "unknown").replace(/_/g," ").replace(/\b\w/g,function (c) { return c.toUpperCase(); }); }
  function recommendations() { return report && report.recommendations ? report.recommendations : []; }
  function sourceMappings() { return report && report.source_mappings ? report.source_mappings : []; }
  function recordKey(item) { return String(item && (item._key || item.detection_id || item.id) || "").replace(/^dei-/,""); }
  function recordFor(item) { var key=recordKey(item); return records.filter(function (record) { return recordKey(record)===key; })[0] || null; }
  function guidedBuilderPage() { return $("#dei-guided-detection-page").length>0; }
  function draftStarted(key) { return generatedDrafts[String(key||"")]===true; }
  function syncBrowserArtifact(record) {
    if (!record) { return; } var key=recordKey(record); var artifacts=safeJson(window.localStorage.getItem(ARTIFACT_KEY))||[];
    artifacts=(Array.isArray(artifacts)?artifacts:[]).filter(function(item){return recordKey(item)!==key;}); artifacts.push(record);
    window.localStorage.setItem(ARTIFACT_KEY,JSON.stringify(artifacts));
  }
  function updateRestartControl(record) { $("#builder-restart-workflow").toggle(!!record&&record.state==="draft"); if (!record||record.state!=="draft") { $("#builder-restart-panel").prop("hidden",true); } }
  function opensActionWindow(record) { return !!(record && ["testing","peer_review","production","monitoring","retired"].indexOf(record.state)!==-1); }
  function activateWorkspacePanel(panel) {
    var workspace=$("#workflow-unified-workspace"); if (!workspace.length) { return; }
    var mode=["all","artifact","change-control"].indexOf(panel)!==-1?panel:"all";
    workspace.prop("hidden",false).attr("data-active-panel",mode);
    $("#guided-builder-workspace").prop("hidden",mode==="change-control");
    $("#lifecycle-action-center").prop("hidden",mode==="artifact").toggle(mode!=="artifact");
    $("#workflow-tab-all").attr("aria-selected",mode==="all"?"true":"false").toggleClass("active",mode==="all");
    $("#workflow-tab-artifact").attr("aria-selected",mode==="artifact"?"true":"false").toggleClass("active",mode==="artifact");
    $("#workflow-tab-change-control").attr("aria-selected",mode==="change-control"?"true":"false").toggleClass("active",mode==="change-control");
  }
  function closeActionWindow() {
    activateWorkspacePanel("artifact");
    var tab=document.getElementById("workflow-tab-artifact"); if (tab) { tab.focus(); }
  }
  function hideActionWindow() {
    activateWorkspacePanel("artifact");
  }
  function openActionWindow() {
    var center=$("#lifecycle-action-center"); if (!center.length) { return; }
    activateWorkspacePanel("all");
  }

  function observedSourcetypes(item) {
    if (item.sourcetypes && item.sourcetypes.length) { return item.sourcetypes; }
    var matched=(item.observed_sources||[]).map(function (source) { return String(source||"").toLowerCase(); });
    return sourceMappings().filter(function (mapping) {
      return [mapping.canonical_source].concat(mapping.additional_canonical_sources||[]).some(function (source) {
        return matched.indexOf(String(source||"").toLowerCase())!==-1;
      });
    }).map(function (mapping) { return mapping.observed_source; });
  }

  function buildable(item) { return {production_ready:true,field_unverified:true,field_gap:true,partial:true,unsupported:true,requires_es:true,requires_enterprise_security:true,not_observed:true}[item.readiness]===true; }
  function stateFor(item, record) { return record && record.state ? record.state : "recommendation"; }
  function nextAction(item, record) {
    var state=stateFor(item,record);
    if (state==="recommendation") {
      if (buildable(item)) { return item.readiness==="production_ready"?"Generate and save a versioned detection draft":"Create a telemetry-gated planning draft"; }
      if (item.readiness==="partial") { return "Onboard the missing required telemetry"; }
      if (item.readiness==="field_gap") { return "Resolve confirmed fields in an engineering draft"; }
      return "Qualify telemetry and field prerequisites";
    }
    if (state==="draft") { return "Complete bounded validation in Guided Detection Builder"; }
    if (state==="testing") { return record.validation && record.validation.status==="passed" ? "Submit validated evidence for peer review" : "Run or repair historical validation"; }
    if (state==="peer_review") { return record.review && record.review.decision==="approved" ? "Record the approved deployment target" : "Approve or return the detection with review comments"; }
    if (state==="production") { return "Record the first production health measurement"; }
    if (state==="monitoring") { return "Record health evidence, tune, or retire"; }
    if (state==="tuning") { return "Revise, validate, and resubmit the new version"; }
    return "Retirement history retained";
  }

  function mergedQueue() {
    var seen={};
    var items=recommendations().map(function (item) {
      var copy=$.extend(true,{},item); var record=recordFor(item);
      copy.lifecycle_record=record; seen[recordKey(item)]=true; return copy;
    });
    records.forEach(function (record) {
      var key=recordKey(record); if (seen[key]) { return; }
      items.push({detection_id:key,name:record.name,capability:record.capability,severity:record.severity,
        readiness:record.source_readiness||"persisted",mitre_techniques:record.mitre_attack||[],
        sourcetypes:record.sourcetypes||[],lifecycle_record:record});
    });
    return items;
  }

  function isEngineeringWork(item) {
    var record=item.lifecycle_record;
    if (!record) { return true; }
    if (record.state==="tuning" || record.state==="draft" || record.state==="testing") { return true; }
    if (record.state==="peer_review" && !(record.catalog && record.catalog.cataloged_at)) { return true; }
    return false;
  }

  function loadReport() {
    report=safeJson(window.sessionStorage.getItem(REPORT_KEY));
    var timestamp=Number(window.sessionStorage.getItem(REPORT_TIME_KEY)||0);
    if (report && report.recommendations) {
      $("#lifecycle-data-status").text("Lifecycle: "+(Store ? Store.mode() : "loading")).addClass("healthy").removeClass("unhealthy");
      $("#lifecycle-analysis-age").text(timestamp ? "Analyzed "+new Date(timestamp).toLocaleString() : "Analysis loaded");
    } else {
      $("#lifecycle-data-status").text("Lifecycle records: "+records.length).toggleClass("healthy",records.length>0).toggleClass("unhealthy",!records.length);
      $("#lifecycle-analysis-age").text(records.length ? "Using persisted lifecycle records" : "No analysis or lifecycle records");
    }
  }

  function countState(state) { return records.filter(function (record) { return record.state===state; }).length; }
  function renderPipelineState(signals) {
    var stages=["discover","profile","qualify","recommend","design","generate","validate"];
    var firstIncomplete=-1;
    stages.some(function (stage,index) {
      if (!signals[stage]) { firstIncomplete=index; return true; }
      return false;
    });
    stages.forEach(function (stage,index) {
      var state=signals[stage]?"complete":(index===firstIncomplete?"current":"upcoming");
      if (state==="current" && ((stage==="qualify" && signals.qualificationBlocked) ||
          (stage==="design" && signals.designBlocked) || (stage==="validate" && signals.validationBlocked))) {
        state="blocked";
      }
      var card=$('.dei-pipeline-stage[data-stage="'+stage+'"]');
      var metric=card.find("strong").text();
      var status=state==="complete"?"complete":state==="blocked"?"blocked by evidence":"next stage";
      card.attr("data-pipeline-state",state).attr("aria-label",label(stage)+": "+metric+", "+status)
        .attr("title",label(stage)+" · "+metric+" · "+status);
      $('.dei-flow-nodes [data-flow-stage="'+stage+'"]').attr("data-pipeline-state",state);
    });
    var progress=firstIncomplete===-1 ? 100 : Math.round((firstIncomplete/(stages.length-1))*100);
    var currentStage=firstIncomplete===-1 ? "Lifecycle evidence complete" : label(stages[firstIncomplete]);
    var currentCard=firstIncomplete===-1 ? $() : $('.dei-pipeline-stage[data-stage="'+stages[firstIncomplete]+'"]');
    var flowState=firstIncomplete===-1 ? "complete" :
      (currentCard.attr("data-pipeline-state")==="blocked" ? "blocked" : "active");
    $("#dei-detection-flow").css("--dei-flow-progress",progress+"%")
      .attr("data-flow-state",flowState).toggleClass("has-flow",progress>0);
    $("#dei-flow-status").text(firstIncomplete===-1 ? "All evidence stages complete" :
      currentStage+(flowState==="blocked" ? " is blocked by required evidence" : " is the active evidence stage"));
  }

  function renderMetrics() {
    var items=recommendations();
    var sources=Number(report && report.observed_source_count||0);
    var verified=items.filter(function (item) { return item.field_validation==="passed"; }).length;
    var mapped=items.filter(function (item) { return (item.mitre_techniques||[]).length>0; }).length;
    var ready=items.filter(function (item) { return item.readiness==="production_ready"; }).length;
    var buildableCount=items.filter(buildable).length;
    var passed=records.filter(function (record) { return record.validation && record.validation.status==="passed"; }).length;
    var maturity=(report?4:0)+(records.length?1:0)+(passed?1:0)+(countState("production")||countState("monitoring")?1:0);
    $("#life-sources").text(sources); $("#life-opportunities").text(mergedQueue().length);
    $("#life-mitre-mapped").text(mapped); $("#life-field-verified").text(verified);
    $("#life-telemetry-ready").text(ready); $("#life-spl-generated").text(records.length);
    $("#lifecycle-maturity-percent").text(Math.round((maturity/7)*100)+"%");
    $("#stage-discover").text(sources+" sources"); $("#stage-profile").text(verified+" profiled");
    $("#stage-qualify").text(ready+" telemetry ready"); $("#stage-recommend").text(items.length+" use cases");
    $("#stage-design").text(records.length+" designed"); $("#stage-generate").text(records.length+" SPL");
    $("#stage-validate").text(passed+" passed");
    var failed=records.filter(function (record) { return record.validation && record.validation.status==="failed"; }).length;
    renderPipelineState({
      discover:!!report && sources>0,
      profile:verified>0,
      qualify:ready>0,
      recommend:items.length>0,
      design:records.length>0,
      generate:records.length>0,
      validate:passed>0,
      qualificationBlocked:!!report && items.length>0 && verified===0,
      designBlocked:items.length>0 && buildableCount===0,
      validationBlocked:failed>0 && passed===0
    });
    var catalogReady=records.filter(function (record) { return record.catalog && record.catalog.status==="ready"; }).length;
    var reviewPending=records.filter(function (record) { return record.state==="peer_review" && !(record.catalog && record.catalog.cataloged_at); }).length;
    $("#state-draft").text(countState("draft")); $("#state-testing").text(countState("testing"));
    $("#state-review").text(reviewPending); $("#state-catalog").text(catalogReady); $("#state-production").text(countState("production"));
    $("#state-monitoring").text(countState("monitoring")); $("#state-tuning").text(countState("tuning"));
    $("#state-retired").text(countState("retired"));
  }

  function renderQueue() {
    var query=String($("#lifecycle-search").val()||"").toLowerCase();
    var readiness=$("#lifecycle-readiness").val()||"all";
    var stage=$("#lifecycle-stage").val()||"all";
    var assignment=$("#lifecycle-assignment").val()||"all"; var currentUser=String(Store&&Store.username?Store.username():"").toLowerCase(); var today=new Date().toISOString().slice(0,10);
    var visibleRows=parseInt($("#lifecycle-visible-rows").val(),10)||10;
    var all=mergedQueue().filter(isEngineeringWork);
    var items=all.filter(function (item) {
      var record=item.lifecycle_record; var current=stateFor(item,record);
      var haystack=[item.name,item.capability,item.pack_id,observedSourcetypes(item).join(" "),
        (item.mitre_techniques||[]).join(" "),current].join(" ").toLowerCase();
      var ownership=record&&record.ownership||{}; var assignmentMatch=assignment==="all" ||
        (assignment==="owner"&&String(ownership.owner||"").toLowerCase()===currentUser) ||
        (assignment==="reviewer"&&current==="peer_review"&&String(ownership.reviewer||"").toLowerCase()===currentUser) ||
        (assignment==="overdue"&&((ownership.review_due_at&&ownership.review_due_at<today)||(ownership.health_due_at&&ownership.health_due_at<today)));
      return (!query||haystack.indexOf(query)!==-1) && assignmentMatch &&
        (readiness==="all"||item.readiness===readiness) && (stage==="all"||current===stage);
    });
    var visibleItems=items.slice(0,visibleRows);
    $("#lifecycle-queue-count").text(visibleItems.length+" shown · "+items.length+" matching · "+all.length+" total");
    $("#lifecycle-queue-total").text(items.length);
    if (!all.length) {
      $("#lifecycle-work-queue").html('<tr><td colspan="7"><strong>No lifecycle work is available.</strong><br/>Run Analyze Environment in Command Center or restore a persisted lifecycle record.</td></tr>');
      return;
    }
    $("#lifecycle-work-queue").html(items.length ? visibleItems.map(function (item) {
      var record=item.lifecycle_record; var state=stateFor(item,record); var sources=observedSourcetypes(item);
      var button=record ? '<a class="dei-manage-lifecycle" href="detection_workflow?detection='+encodeURIComponent(recordKey(item))+'">Continue</a>' :
        (buildable(item) ? '<button type="button" class="dei-generate-detection" data-detection="'+esc(item.detection_id)+'">Build</button>' : '<span class="dei-generation-blocked">Resolve gaps</span>');
      return "<tr><td><strong>"+esc(item.name)+"</strong><small>"+esc(item.capability||item.pack_id)+"</small></td>"+
        "<td>"+esc(sources.join(" · ")||"No observed match")+"</td>"+
        '<td><span class="dei-lifecycle-readiness '+esc(item.readiness)+'">'+esc(label(item.readiness))+"</span></td>"+
        "<td>"+esc((item.mitre_techniques||[]).join(" · ")||"Not mapped")+"</td>"+
        '<td><span class="dei-lifecycle-stage '+esc(state)+'">'+esc(label(state))+"</span></td>"+
        "<td>"+esc(nextAction(item,record))+"</td><td>"+button+"</td></tr>";
    }).join("") : '<tr><td colspan="7">No items match these filters. <button type="button" class="dei-inline-reset">Reset filters</button></td></tr>');
  }

  function evidence(record) {
    var checks=[
      ["Generated SPL",!!record.spl],["MITRE mapping",(record.mitre_attack||[]).length>0],
      ["Validation passed",record.validation && record.validation.status==="passed"],
      ["Peer approval",record.review && record.review.decision==="approved"],
      ["Deployment reference",record.deployment && record.deployment.external_object_id],
      ["Health evidence",record.monitoring && record.monitoring.last_checked_at],
      ["Retirement reason",record.retirement && record.retirement.reason]
    ];
    return checks.map(function (check) { return '<div class="dei-evidence '+(check[1]?"complete":"pending")+'"><span>'+(check[1]?"✓":"○")+'</span>'+esc(check[0])+"</div>"; }).join("");
  }

  function history(record) {
    var entries=(record.history||[]).slice().reverse();
    return entries.length ? entries.map(function (entry) {
      return '<div class="dei-audit-entry"><strong>'+esc(label(entry.event))+'</strong><span>'+esc(entry.actor||"unknown")+' · '+esc(new Date(entry.at).toLocaleString())+'</span><p>'+esc(entry.detail||"No additional detail")+"</p></div>";
    }).join("") : '<p class="dei-empty">No lifecycle history recorded.</p>';
  }

  function workflowProgress(record) {
    var states=[
      {id:"draft",label:"Draft"},{id:"testing",label:"Testing"},{id:"peer_review",label:"Peer review"},
      {id:"catalog",label:"Catalog ready"},{id:"production",label:"Production"},{id:"monitoring",label:"Monitoring"},
      {id:"tuning",label:"Tuning"},{id:"retired",label:"Retired"}
    ];
    var currentStage=record.catalog && ["ready","development","staging"].indexOf(record.catalog.status)!==-1 ? "catalog" : record.state;
    var current=Math.max(0,states.map(function (state) { return state.id; }).indexOf(currentStage));
    var controls=stageControls(record);
    return '<div class="dei-lifecycle-progress">'+states.map(function (state,index) {
      var status=index<current?"complete":(index===current?"current":"future");
      var statusLabel=status==="complete"?"Complete":(status==="current"?"Current stage":"Upcoming");
      var action=controls.previous&&controls.previous.stage===state.id?controls.previous.action:(controls.alternate&&controls.alternate.stage===state.id?controls.alternate.action:(controls.next&&controls.next.stage===state.id?controls.next.action:""));
      var actionLabel=controls.previous&&action===controls.previous.action?controls.previous.label:(controls.alternate&&action===controls.alternate.action?controls.alternate.label:(controls.next&&action===controls.next.action?controls.next.label:""));
      var tag=action?"button":"div"; var actionText=action?' data-stage-action="'+esc(action)+'" type="button" title="'+esc(actionLabel)+'"':"";
      return '<'+tag+' class="dei-progress-step '+status+(action?' available':'')+'"'+actionText+(status==="current"?' aria-current="step"':"")+'><span>'+(status==="complete"?"✓":String(index+1))+'</span><div><strong>'+esc(state.label)+'</strong><small>'+(action?"Available action":statusLabel)+'</small></div></'+tag+'>';
    }).join("")+"</div>";
  }

  function stageControls(record) {
    var approved=record.review&&record.review.decision==="approved";
    if (record.state==="testing") { return {previous:{stage:"draft",action:"return_draft",label:"Previous · Return to Draft"},edit:{action:"open_builder",label:"Edit detection"},next:record.validation&&record.validation.status==="passed"?{stage:"peer_review",action:"submit_review",label:"Continue · Submit for peer review"}:null}; }
    if (record.state==="peer_review"&&!approved) { var sameUser=record.review&&record.review.submitted_by&&String(record.review.submitted_by).toLowerCase()===String(Store.username()).toLowerCase(); return {previous:{stage:"draft",action:"return_draft",label:"Previous · Return for changes"},edit:{action:"open_builder",label:"Inspect detection"},next:sameUser?null:{stage:"catalog",action:"approve_review",label:"Continue · Approve version"},reviewHandoff:sameUser}; }
    if (record.state==="peer_review"&&approved) { return {previous:{stage:"draft",action:"return_draft",label:"Previous · Reopen Draft"},edit:{action:"open_builder",label:"Inspect detection"},next:{stage:"production",action:"record_deployment",label:"Continue · Record deployment"}}; }
    if (record.state==="production") { return {previous:null,edit:{action:"open_builder",label:"Inspect detection"},next:{stage:"monitoring",action:"record_health",label:"Continue · Record health and start monitoring"}}; }
    if (record.state==="monitoring") { return {previous:null,alternate:{stage:"tuning",action:"start_tuning",label:"Start tuning version"},edit:null,next:{stage:"monitoring",action:"record_health",label:"Record health checkpoint"}}; }
    return {previous:null,edit:null,next:null};
  }

  function lifecyclePosition(record) {
    var stages=["draft","testing","peer_review","catalog","production","monitoring","tuning","retired"];
    var current=record.catalog && ["ready","development","staging"].indexOf(record.catalog.status)!==-1 ? "catalog" : record.state;
    var index=Math.max(0,stages.indexOf(current));
    return {stage:current,index:index+1,total:stages.length};
  }

  function gateGuidance(record) {
    var approved=record.review && record.review.decision==="approved";
    var guides={
      draft:{gate:"Gate 1 · Detection design",owner:"Detection engineer",required:"Complete and save the SPL, schedule, telemetry mappings, and ATT&CK context.",steps:["Open Guided Detection Builder.","Review or edit the generated platform SPL and optional ES artifact.","Run bounded historical validation."],outcome:"A successful validation advances the record to Testing.",instruction:"Open guided builder and complete bounded validation before continuing."},
      testing:{gate:"Gate 2 · Validation handoff",owner:"Detection engineer",required:"A passed validation result and a review-submission note.",steps:["Review the sampled results and runtime evidence.","Describe the analytic intent, expected behavior, and known limitations.","Submit the validated version for peer review."],outcome:"The record becomes available to a reviewer in Peer Review.",instruction:"Document the validation evidence, then submit this version for peer review."},
      peer_review:approved?{gate:"Gate 4 · Controlled deployment record",owner:"Deployment owner",required:"The exact deployed saved-search, ES detection, or external object reference.",steps:["Deploy the approved artifact through the normal change process.","Select the deployment target and environment.","Record the exact object name/ID and optional change ticket."],outcome:"Recording deployment advances the detection to Production; DEI does not silently deploy it.",instruction:"Peer review is approved. Record the real deployment reference to enter Production."}:{gate:"Gate 3 · Independent peer review",owner:"DEI lifecycle reviewer",required:"A written approval rationale or specific change request.",steps:["Open guided builder and inspect SPL, ATT&CK mapping, schedule, warnings, and validation evidence.","Confirm the logic is safe, scoped, and operationally actionable.","Approve this version or return it to Draft with required changes."],outcome:"Approval unlocks deployment recording; returned work reopens Draft.",instruction:"A reviewer must approve or return this version with written rationale."},
      production:{gate:"Gate 5 · Production health baseline",owner:"Detection owner / SOC",required:"Initial health, result volume, runtime, and analyst outcome evidence.",steps:["Confirm the deployed object is scheduled and enabled through the target platform.","Measure result volume and search runtime.","Record initial true-positive and false-positive observations."],outcome:"The first health measurement advances the record to Monitoring.",instruction:"Record the first production health measurement to begin Monitoring."},
      monitoring:{gate:"Gate 6 · Continuous detection operations",owner:"Detection owner / SOC",required:"Periodic health and analyst outcome evidence.",steps:["Record current health, result volume, runtime, and analyst outcomes.","Continue monitoring when performance remains acceptable.","Start Tuning for logic changes or Retire with a documented reason."],outcome:"Each decision is retained in the audit history.",instruction:"Record health, open a tuning version, or retire the detection with evidence."},
      tuning:{gate:"Gate 7 · Controlled tuning cycle",owner:"Detection engineer",required:"A revised version followed by fresh validation and peer review.",steps:["Open guided builder and revise the SPL or schedule.","Run bounded validation; prior approval cannot be reused.","Submit the new version through peer review and deployment again."],outcome:"Successful validation returns the new version to Testing.",instruction:"Open guided builder, revise this version, and complete fresh validation."},
      retired:{gate:"Lifecycle closed · Retired",owner:"Detection governance",required:"No further action; retained history is immutable.",steps:["Review the retirement reason and replacement context.","Retain deployment, monitoring, and approval evidence for audit.","Create a new recommendation or draft if the capability is needed again."],outcome:"The detection remains retired with its complete history preserved.",instruction:"Lifecycle complete. The retired record is retained for audit."}
    };
    return guides[record.state]||guides.draft;
  }

  function renderGateGuide(record) {
    var guide=gateGuidance(record);
    var deployment=record.deployment||{}; var monitoring=record.monitoring||{};
    var facts=[];
    if (deployment.external_object_id) { facts.push("Deployment: "+deployment.external_object_id); }
    if (monitoring.last_checked_at) { facts.push("Last health: "+label(monitoring.health)+" · "+new Date(monitoring.last_checked_at).toLocaleString()); }
    if (record.retirement && record.retirement.reason) { facts.push("Retired: "+record.retirement.reason); }
    return workflowProgress(record)+'<details class="dei-workflow-disclosure dei-gate-disclosure"><summary><span><strong>Gate guidance and ownership</strong><small>'+esc(guide.gate)+'</small></span></summary><div class="dei-gate-guide"><div><span class="dei-generator-label">Current gate</span><h3>'+esc(guide.gate)+'</h3><p>'+esc(guide.required)+'</p><dl><dt>Responsible role</dt><dd>'+esc(guide.owner)+'</dd><dt>Gate outcome</dt><dd>'+esc(guide.outcome)+'</dd></dl></div><div><span class="dei-generator-label">What to do next</span><ol>'+guide.steps.map(function (step) { return "<li>"+esc(step)+"</li>"; }).join("")+"</ol>"+(facts.length?'<div class="dei-gate-facts">'+facts.map(function (fact) { return "<span>"+esc(fact)+"</span>"; }).join("")+"</div>":"")+"</div></div></details>";
  }

  function ownershipMarkup(record) {
    var ownership=record.ownership||{};
    return '<details class="dei-workflow-disclosure dei-ownership-fields" open><summary><span><strong>Work ownership and due dates</strong><small>Assign the next accountable roles</small></span></summary><div class="dei-action-fields-row">'+
      '<label class="dei-action-field"><span>Detection owner</span><input id="lifecycle-owner" type="text" value="'+esc(ownership.owner||Store.username())+'" placeholder="Splunk username or team"/></label>'+
      '<label class="dei-action-field"><span>Peer reviewer</span><input id="lifecycle-reviewer" type="text" value="'+esc(ownership.reviewer||"")+'" placeholder="Independent reviewer"/></label>'+
      '<label class="dei-action-field"><span>Review due</span><input id="lifecycle-review-due" type="date" value="'+esc(ownership.review_due_at||"")+'"/></label>'+
      '<label class="dei-action-field"><span>Next health review</span><input id="lifecycle-health-due" type="date" value="'+esc(ownership.health_due_at||"")+'"/></label></div></details>';
  }

  function fieldMarkup(record) {
    var ownership=record.state==="retired"?"":ownershipMarkup(record);
    if (record.state==="testing") {
      return ownership+'<label class="dei-action-field"><span id="lifecycle-action-comment-label">Transition rationale *</span><textarea id="lifecycle-action-comment" aria-describedby="lifecycle-action-comment-help lifecycle-inline-error" placeholder="For Continue, summarize validation evidence. For Return to Draft, document the required change."></textarea><small id="lifecycle-action-comment-help">This note is required for both forward submission and governed rollback.</small></label><div id="lifecycle-inline-error" class="dei-inline-action-error" role="alert" hidden="hidden"></div>';
    }
    if (record.state==="peer_review") {
      if (record.review && record.review.decision==="approved") {
        return ownership+'<div class="dei-action-fields-row"><label class="dei-action-field"><span>Deployment target *</span><select id="lifecycle-deployment-target"><option value="splunk_platform">Splunk saved search</option><option value="enterprise_security">Enterprise Security detection</option><option value="external">External deployment</option></select></label><label class="dei-action-field"><span>Environment *</span><select id="lifecycle-deployment-environment"><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option></select></label><label class="dei-action-field"><span>Saved-search or object ID *</span><input id="lifecycle-external-id" type="text" aria-describedby="lifecycle-inline-error" placeholder="Exact deployed object name"/></label></div><label class="dei-action-field"><span>Change ticket or deployment note</span><textarea id="lifecycle-action-comment" placeholder="Optional deployment evidence or change reference."></textarea></label><div id="lifecycle-inline-error" class="dei-inline-action-error" role="alert" hidden="hidden"></div>';
      }
      var sameUser=record.review&&record.review.submitted_by&&String(record.review.submitted_by).toLowerCase()===String(Store.username()).toLowerCase();
      return ownership+(sameUser?'<div id="lifecycle-review-handoff" class="dei-inline-action-error" role="status"><strong>Independent review required.</strong> You submitted this version, so another authenticated Splunk user must open this detection and approve or return it. The tutorial resumes from this record after that reviewer completes the gate.</div>':'')+'<label class="dei-action-field"><span id="lifecycle-action-comment-label">Peer-review decision rationale *</span><textarea id="lifecycle-action-comment" aria-describedby="lifecycle-inline-error" placeholder="Document why this version is approved or list the exact changes required."></textarea></label><div id="lifecycle-inline-error" class="dei-inline-action-error" role="alert" hidden="hidden"></div>';
    }
    if (record.state==="production" || record.state==="monitoring") {
      var prior=record.monitoring||{};
      function priorValue(name) { return prior[name]===undefined||prior[name]===null?"":prior[name]; }
      return ownership+'<div class="dei-action-fields-row"><label class="dei-action-field"><span>Health *</span><select id="lifecycle-health"><option value="healthy"'+(prior.health==="healthy"?" selected":"")+'>Healthy</option><option value="degraded"'+(prior.health==="degraded"?" selected":"")+'>Degraded</option><option value="failing"'+(prior.health==="failing"?" selected":"")+'>Failing</option></select></label><label class="dei-action-field"><span>Review period *</span><input id="lifecycle-review-period" type="text" aria-describedby="lifecycle-inline-error" value="'+esc(prior.review_period||"")+'" placeholder="Example: Last 24 hours"/></label><label class="dei-action-field"><span>Result volume *</span><input id="lifecycle-result-volume" type="number" min="0" aria-describedby="lifecycle-inline-error" value="'+esc(priorValue("result_volume"))+'"/></label><label class="dei-action-field"><span>Runtime ms *</span><input id="lifecycle-runtime" type="number" min="0" aria-describedby="lifecycle-inline-error" value="'+esc(priorValue("runtime_ms"))+'"/></label><label class="dei-action-field"><span>True positives</span><input id="lifecycle-true-positives" type="number" min="0" aria-describedby="lifecycle-inline-error" value="'+esc(priorValue("true_positives"))+'"/></label><label class="dei-action-field"><span>False positives</span><input id="lifecycle-false-positives" type="number" min="0" aria-describedby="lifecycle-inline-error" value="'+esc(priorValue("false_positives"))+'"/></label></div><label class="dei-action-field"><span id="lifecycle-action-comment-label">Monitoring evidence note *</span><textarea id="lifecycle-action-comment" aria-describedby="lifecycle-action-comment-help lifecycle-inline-error" placeholder="Record scheduler/search-history evidence, source-data freshness, analyst outcomes, downstream actions, and the next corrective action when needed."></textarea><small id="lifecycle-action-comment-help">Use real evidence. Explain zero results, degraded or failing health, and any corrective action. This note also supports a later tuning or retirement decision.</small></label><div id="lifecycle-inline-error" class="dei-inline-action-error" role="alert" hidden="hidden"></div>';
    }
    if (record.state==="tuning") { return ownership+'<label class="dei-action-field"><span id="lifecycle-action-comment-label">Tuning objective or retirement reason *</span><textarea id="lifecycle-action-comment" aria-describedby="lifecycle-inline-error" placeholder="Document the revision objective before opening Builder, or provide the retirement reason."></textarea></label><div id="lifecycle-inline-error" class="dei-inline-action-error" role="alert" hidden="hidden"></div>'; }
    if (record.state==="retired") { return '<p class="dei-empty">This lifecycle record is complete and immutable. Deployment, monitoring, decisions, and retirement evidence remain available in Audit history.</p>'; }
    return ownership+'<label class="dei-action-field"><span>Lifecycle note</span><textarea id="lifecycle-action-comment" placeholder="Document the engineering decision."></textarea></label>';
  }

  function buttonMarkup(record) {
    var controls=stageControls(record); var markup='<div class="dei-stage-controller" aria-label="Lifecycle stage controls">';
    if (controls.reviewHandoff) { markup='<div class="dei-monitoring-choice" role="note"><strong>Waiting for an independent reviewer</strong><span>Share this detection with the assigned reviewer. They must sign in with their own Splunk account to approve or return it; your tutorial progress remains saved.</span></div>'+markup; }
    if (record.state==="monitoring") { markup='<div class="dei-monitoring-choice" role="note"><strong>Choose one next operational action</strong><span>To remain in Monitoring, complete the measurements and enter their evidence note, then select Record health checkpoint. To revise the detection, replace the note with one specific tuning objective, then select Start tuning version. Retire requires a documented reason and confirmation.</span></div>'+markup; }
    markup+=controls.previous?'<button type="button" class="previous" data-action="'+esc(controls.previous.action)+'">← '+esc(controls.previous.label.replace(/^Previous · |^Revise · /,""))+'</button>':(controls.alternate?"":'<span class="dei-stage-controller-spacer"></span>');
    if (controls.alternate) { markup+='<button type="button" data-action="'+esc(controls.alternate.action)+'">'+esc(controls.alternate.label)+' →</button>'; }
    if (controls.edit) { markup+='<button type="button" data-action="'+esc(controls.edit.action)+'">'+esc(controls.edit.label)+'</button>'; }
    if (controls.next) { markup+='<button type="button" class="primary next" data-action="'+esc(controls.next.action)+'">'+esc(controls.next.label.replace(/^Continue · /,""))+' →</button>'; }
    markup+='<button type="button" data-action="save_assignment">Save assignment</button>';
    if (["testing","peer_review"].indexOf(record.state)!==-1) { markup+='<button type="button" class="restart" data-action="restart_recommendation">↶ Restart from recommendation</button>'; }
    markup+='</div>';
    if (record.state==="draft") { return '<button type="button" class="primary" data-action="open_builder">Open guided builder</button>'; }
    if (["testing","peer_review","production","monitoring"].indexOf(record.state)!==-1) { return markup+(record.state==="production"||record.state==="monitoring"?'<button type="button" class="danger" data-action="retire">Retire</button>':""); }
    if (record.state==="tuning") { return '<button type="button" class="primary" data-action="open_builder">Open guided builder for tuning</button><button type="button" class="danger" data-action="retire">Retire</button>'; }
    return "";
  }

  function updateLifecycleDeploymentWorkflow() {
    var environment=String($("#lifecycle-deployment-environment").val()||"production");
    var button=$("#lifecycle-action-buttons [data-action='record_deployment']");
    if (button.length) { button.text(environment==="production"?"Record deployment and enter Production":"Record "+label(environment)+" deployment"); }
  }

  function selectRecord(key) {
    selectedRecord=records.filter(function (record) { return recordKey(record)===key; })[0]||null;
    if (!selectedRecord) { return; }
    if (!$("#lifecycle-action-center").length) { window.location.href="detection_workflow?detection="+encodeURIComponent(key); return; }
    $(".dei-lifecycle-workspace-grid").addClass("has-selection");
    if (opensActionWindow(selectedRecord)) { openActionWindow(); } else { hideActionWindow(); }
    $("#lifecycle-action-title").text(selectedRecord.name);
    var position=lifecyclePosition(selectedRecord);
    $("#lifecycle-action-position").text("Stage "+position.index+" of "+position.total);
    $("#lifecycle-action-state").text("Current stage: "+label(position.stage)+" · Version "+(selectedRecord.version||1));
    $("#lifecycle-action-summary").text("Next required action: "+nextAction(selectedRecord,selectedRecord));
    $("#lifecycle-action-progress").html(renderGateGuide(selectedRecord));
    $("#lifecycle-action-evidence").html(evidence(selectedRecord));
    $("#lifecycle-action-fields").html(fieldMarkup(selectedRecord));
    $("#lifecycle-action-buttons").html(buttonMarkup(selectedRecord));
    $("#lifecycle-action-history").html(history(selectedRecord));
    $("#lifecycle-action-feedback").removeClass("error success").addClass("ready").text(gateGuidance(selectedRecord).instruction); updateLifecycleDeploymentWorkflow();
  }

  function note() { return String($("#lifecycle-action-comment").val()||"").trim(); }
  function applyOwnership(record) {
    if (!$("#lifecycle-owner").length) { return record; }
    record.ownership={owner:String($("#lifecycle-owner").val()||"").trim(),reviewer:String($("#lifecycle-reviewer").val()||"").trim(),review_due_at:String($("#lifecycle-review-due").val()||""),health_due_at:String($("#lifecycle-health-due").val()||"")};
    return record;
  }
  function actionError(message,label) {
    fieldError("#lifecycle-action-comment",message,label);
  }
  function fieldError(selector,message,label) {
    var field=$(selector); var inline=$("#lifecycle-inline-error");
    if (label) { $("#lifecycle-action-comment-label").text(label); }
    inline.prop("hidden",false).text(message); field.attr("aria-invalid","true").trigger("focus");
    $("#lifecycle-action-feedback").removeClass("ready success").addClass("error").text(message);
  }
  function clearActionError() { $("#lifecycle-inline-error").prop("hidden",true).text(""); $("#lifecycle-action-fields [aria-invalid]").removeAttr("aria-invalid"); }
  function setActionBusy(busy,labelText) {
    $("#lifecycle-action-buttons button,#lifecycle-action-progress [data-stage-action]").prop("disabled",busy);
    if (busy) { $("#lifecycle-action-feedback").removeClass("error success").addClass("working").text(labelText||"Saving lifecycle transition…"); }
  }
  function transition(record,to,event,detail,changes) {
    var allowed={recommendation:["draft"],draft:["testing","recommendation"],testing:["peer_review","draft","recommendation"],peer_review:["production","draft","recommendation"],
      production:["monitoring","retired"],monitoring:["monitoring","tuning","retired"],tuning:["testing","retired"],retired:[]};
    if ((allowed[record.state]||[]).indexOf(to)===-1) { return $.Deferred().reject("Invalid lifecycle transition").promise(); }
    if (to==="peer_review" && (!record.validation || record.validation.status!=="passed")) { return $.Deferred().reject("Passed validation evidence is required before peer review.").promise(); }
    if (to==="production" && (!record.review || record.review.decision!=="approved")) { return $.Deferred().reject("Peer approval is required before production.").promise(); }
    if (to==="production" && (!changes || !changes.deployment || !changes.deployment.external_object_id)) { return $.Deferred().reject("A deployment reference is required before production.").promise(); }
    if (to==="monitoring" && (!changes || !changes.monitoring || !changes.monitoring.last_checked_at)) { return $.Deferred().reject("Health evidence is required before monitoring.").promise(); }
    if (to==="retired" && (!changes || !changes.retirement || !changes.retirement.reason)) { return $.Deferred().reject("A retirement reason is required.").promise(); }
    var next=$.extend(true,{},record,changes||{},{state:to,status:to});
    next=Store.appendHistory(next,event,detail); return Store.write(next);
  }

  function saveAndReload(promise,message,action) {
    clearActionError(); setActionBusy(true,action==="return_draft"?"Returning this detection to Draft…":"Saving lifecycle transition…");
    promise.done(function (saved) {
      if (action==="return_draft"||action==="restart_recommendation") { syncBrowserArtifact(saved); }
      $("#lifecycle-action-feedback").removeClass("error ready").addClass("success").text(message);
      $(document).trigger("dei:lifecycle-action-complete",[action,saved]);
      pendingWorkspaceAction=action; reloadRecords();
    }).fail(function (error) {
      setActionBusy(false);
      $("#lifecycle-action-feedback").removeClass("success ready").addClass("error").text(String(error&&error.message||error||"Unable to save lifecycle record."));
    });
  }

  function returnToDraft(record,comment) {
    if (["testing","peer_review"].indexOf(record.state)===-1) { return $.Deferred().reject("Only Testing or Peer Review can return directly to Draft.").promise(); }
    return transition(record,"draft","returned_for_changes",comment,{review:$.extend({},record.review,{decision:"changes_requested",reviewer:Store.username(),comments:comment,returned_at:new Date().toISOString()}),validation:null,deployment:null,catalog:null});
  }

  function restartFromRecommendation(record,reason) {
    if (["draft","testing","peer_review"].indexOf(record.state)===-1) { return $.Deferred().reject("Only Draft, Testing, or Peer Review can restart from Recommendation.").promise(); }
    var archived={version:Number(record.version||1),state:record.state,spl:record.spl,schedule:record.schedule,validation:record.validation,review:record.review,deployment:record.deployment,catalog:record.catalog,closed_at:new Date().toISOString(),closure:"restarted_from_recommendation",reason:reason};
    return transition(record,"recommendation","restarted_from_recommendation",reason,{version:Number(record.version||1)+1,spl:"",schedule:null,validation:null,review:null,deployment:null,monitoring:null,catalog:null,enterprise_security:null,previous_versions:(record.previous_versions||[]).concat([archived]),restart:{reason:reason,restarted_at:new Date().toISOString(),restarted_by:Store.username()}});
  }

  function saveApprovedReview(record,action) {
    saveAndReload(Store.write(record),"Peer review approved. Continue below to record deployment without leaving this workspace.",action);
  }

  function handleAction(action) {
    var record=applyOwnership($.extend(true,{},selectedRecord)); var comment=note();
    if (!record) { return; }
    if (action==="open_builder") {
      window.localStorage.setItem(SELECTED_DETECTION_KEY,recordKey(record));
      activateWorkspacePanel("artifact");
      $(document).trigger("dei:artifact-inspection-requested",[recordKey(record),record.state,record]);
      return;
    }
    if (action==="open_catalog") {
      window.location.href="detection_catalog?detection="+encodeURIComponent(recordKey(record));
      return;
    }
    if (action==="save_assignment") {
      record=Store.appendHistory(record,"work_assignment_updated","Owner: "+(record.ownership.owner||"unassigned")+" · Reviewer: "+(record.ownership.reviewer||"unassigned"));
      saveAndReload(Store.write(record),"Ownership and due dates saved.",action); return;
    }
    if (action==="submit_review") {
      if (!record.validation || record.validation.status!=="passed") { actionError("Passed validation evidence is required before submitting this version for peer review."); return; }
      if (!comment) { actionError("Summarize the validation evidence, analytic intent, expected analyst behavior, and known limitations before submitting for peer review.","Peer-review submission note *"); return; }
      saveAndReload(transition(record,"peer_review","submitted_for_review",comment,{review:{decision:"pending",submitted_at:new Date().toISOString(),submitted_by:Store.username(),submission_note:comment}}),"Submitted for peer review.",action); return;
    }
    if (action==="approve_review") {
      if (!comment) { actionError("Document why this version is safe, scoped, and operationally actionable before approving it.","Peer-review approval rationale *"); return; }
      var catalogedAt=new Date().toISOString();
      var approved=$.extend(true,{},record,{review:$.extend({},record.review,{decision:"approved",reviewed_at:catalogedAt,reviewer:Store.username(),comments:comment}),catalog:{status:"ready",cataloged_at:catalogedAt,cataloged_by:Store.username()}});
      approved=Store.appendHistory(approved,"peer_review_approved",comment);
      approved=Store.appendHistory(approved,"added_to_detection_catalog","Ready to enable");
      saveApprovedReview(approved,action); return;
    }
    if (action==="return_draft") {
      if (!comment) { actionError("Enter the required change before returning this detection to Draft, then select Return to Draft again.","Required change to return to Draft *"); return; }
      saveAndReload(returnToDraft(record,comment),"Returned to Draft and reopened in Guided Builder.",action); return;
    }
    if (action==="restart_recommendation") {
      if (!comment) { actionError("Enter a restart reason before archiving this version and returning to Recommendation.","Reason to restart from recommendation *"); return; }
      saveAndReload(restartFromRecommendation(record,comment),"Current version archived. Detection returned to Recommendation.",action); return;
    }
    if (action==="record_deployment") {
      var target=String($("#lifecycle-deployment-target").val()||""); var environment=String($("#lifecycle-deployment-environment").val()||"production"); var external=String($("#lifecycle-external-id").val()||"").trim();
      if (!external) { fieldError("#lifecycle-external-id","Enter the exact deployed saved-search, Enterprise Security detection, or external object name before recording deployment."); return; }
      var deployedAt=new Date().toISOString(); var deployment={target:target,environment:environment,external_object_id:external,change_reference:comment,deployed_at:deployedAt,deployed_by:Store.username(),analyst_recorded:true,enabled:environment==="production"};
      if (environment==="production") { saveAndReload(transition(record,"production","deployment_recorded",target+" / "+environment+": "+external+(comment?" · "+comment:""),{deployment:deployment,catalog:$.extend({},record.catalog,{status:"enabled",enabled_at:deployedAt,enabled_by:Store.username()})}),"Production deployment recorded.",action); return; }
      record.deployment=deployment; record.catalog=$.extend({},record.catalog,{status:environment}); record=Store.appendHistory(record,"nonproduction_deployment_recorded",target+" / "+environment+": "+external+(comment?" · "+comment:""));
      saveAndReload(Store.write(record),label(environment)+" deployment recorded. The detection remains approved and can be promoted or returned for changes.",action); return;
    }
    if (action==="record_health") {
      var health=String($("#lifecycle-health").val()||"healthy"); var reviewPeriod=String($("#lifecycle-review-period").val()||"").trim(); var volumeRaw=String($("#lifecycle-result-volume").val()||"").trim(); var runtimeRaw=String($("#lifecycle-runtime").val()||"").trim(); var volume=Number(volumeRaw); var runtime=Number(runtimeRaw); var truePositives=Number($("#lifecycle-true-positives").val()||0); var falsePositives=Number($("#lifecycle-false-positives").val()||0);
      if (!reviewPeriod) { fieldError("#lifecycle-review-period","Enter the review period represented by these measurements."); return; }
      if (!volumeRaw||!isFinite(volume)||volume<0) { fieldError("#lifecycle-result-volume","Enter a non-negative result volume. Use 0 only when the evidence note explains why zero is expected."); return; }
      if (!runtimeRaw||!isFinite(runtime)||runtime<0) { fieldError("#lifecycle-runtime","Enter a non-negative runtime in milliseconds from search history or Job Inspector."); return; }
      if (![truePositives,falsePositives].every(function (value) { return isFinite(value) && value>=0; })) { fieldError("#lifecycle-true-positives","True-positive and false-positive counts must be non-negative numbers."); return; }
      if (!comment) { actionError("Document the evidence source, data freshness, scheduler status, analyst outcomes, and any required corrective action before recording health.","Monitoring evidence note *"); return; }
      var monitoring={health:health,review_period:reviewPeriod,result_volume:volume,runtime_ms:runtime,true_positives:truePositives,false_positives:falsePositives,note:comment,last_checked_at:new Date().toISOString(),checked_by:Store.username()};
      saveAndReload(transition(record,"monitoring","health_measured",health+", "+volume+" results, "+runtime+" ms",{monitoring:monitoring}),"Monitoring evidence recorded.",action); return;
    }
    if (action==="start_tuning") {
      if (!comment) { actionError("Document the tuning objective before opening a new editable version.","Tuning objective *"); return; }
      var previousVersion={version:Number(record.version||1),spl:record.spl,schedule:record.schedule,validation:record.validation,review:record.review,deployment:record.deployment,monitoring:record.monitoring,closed_at:new Date().toISOString()};
      saveAndReload(transition(record,"tuning","tuning_started",comment,{version:Number(record.version||1)+1,validation:null,review:null,deployment:null,monitoring:null,catalog:$.extend({},record.catalog,{status:"tuning"}),previous_versions:(record.previous_versions||[]).concat([previousVersion])}),"Tuning version opened. The detection returned to the engineering queue and prior operational evidence was archived.",action); return;
    }
    if (action==="retire") {
      var reason=comment; if (!reason) { actionError("Document the retirement reason, replacement or accepted coverage gap, and the plan to disable the live Splunk object.","Retirement reason *"); return; }
      if (!window.confirm("Retire this governed detection record? DEI will preserve its history, but it will not disable the live Splunk saved search or Enterprise Security detection.")) { $("#lifecycle-action-feedback").removeClass("error success").addClass("ready").text("Retirement cancelled. No lifecycle changes were saved."); return; }
      saveAndReload(transition(record,"retired","detection_retired",reason,{retirement:{reason:reason,retired_at:new Date().toISOString(),retired_by:Store.username()}}),"Detection retired with history retained.",action);
    }
  }

  function completePendingWorkspaceAction() {
    if (pendingWorkspaceAction==="start_tuning") {
      pendingWorkspaceAction=""; activateWorkspacePanel("all");
      $("#lifecycle-action-feedback").removeClass("error ready working").addClass("success").text("Tuning version opened. Revise the editable artifact, then run fresh validation.");
      window.setTimeout(function () { var spl=document.getElementById("generator-spl"); if (spl&&spl.offsetParent!==null) { spl.focus(); } },100);
      return;
    }
    if (pendingWorkspaceAction==="restart_recommendation") {
      pendingWorkspaceAction=""; hideActionWindow();
      var start=document.getElementById("builder-generate"); if (start) { window.setTimeout(function(){start.focus();},100); }
      return;
    }
    if (pendingWorkspaceAction!=="return_draft") { pendingWorkspaceAction=""; return; }
    pendingWorkspaceAction=""; hideActionWindow();
    window.setTimeout(function () { var spl=document.getElementById("generator-spl"); if (spl&&spl.offsetParent!==null) { spl.focus(); } },100);
  }

  function requestedPipelineStage() {
    var match=String(window.location.search||"").match(/[?&]pipeline=([^&]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  function applyRequestedPipelineStage() {
    var requested=requestedPipelineStage();
    var filters={
      profile:{stage:"recommendation",readiness:"field_unverified"},
      qualify:{stage:"recommendation",readiness:"production_ready"},
      design:{stage:"draft",readiness:"all"},
      generate:{stage:"draft",readiness:"all"},
      validate:{stage:"testing",readiness:"all"}
    };
    var config=filters[requested];
    if(!config){return false;}
    $("#lifecycle-stage").val(config.stage);
    $("#lifecycle-readiness").val(config.readiness);
    $(".dei-pipeline-stage").removeClass("dei-action-target").filter('[data-stage="'+requested+'"]').addClass("dei-action-target");
    renderQueue();
    var labels={profile:"field-evidence verification",qualify:"telemetry-ready qualification",design:"detection design artifacts",generate:"generated SPL artifacts",validate:"historical validation evidence"};
    $("#lifecycle-action-feedback").removeClass("error").addClass("ready").text("Showing "+labels[requested]+". Use the filtered work queue to open the exact detection and required next action.");
    window.setTimeout(function(){var section=document.querySelector(".dei-lifecycle-queue-section");if(section){section.scrollIntoView({behavior:"smooth",block:"start"});}},250);
    return true;
  }

  function requestedDetection() {
    var match=String(window.location.search||"").match(/[?&]detection=([^&]+)/);
    if (!match) { return ""; }
    try { return decodeURIComponent(match[1]); } catch (error) { return match[1]; }
  }

  function render() { loadReport(); renderMetrics(); renderQueue(); }
  function reloadRecords() {
    Store.load().done(function (loaded) {
      records=loaded||[]; render();
      $(document).trigger("dei:lifecycle-records-updated",[records]);
      applyRequestedPipelineStage();
      var requested=requestedDetection();
      var requestedRecord=records.filter(function (record) { return recordKey(record)===requested; })[0]||null;
      if (requested && (!guidedBuilderPage() || draftStarted(requested) || opensActionWindow(requestedRecord))) {
        selectRecord(requested);
      } else if (selectedRecord && (draftStarted(recordKey(selectedRecord)) || opensActionWindow(selectedRecord))) {
        selectRecord(recordKey(selectedRecord));
      } else {
        hideActionWindow();
      }
      completePendingWorkspaceAction();
    });
  }
  $(document).on("dei:lifecycle-refresh-requested",reloadRecords);
  function initialize(attempt) {
    Store=window.DEILifecycleStore;
    if (!Store && attempt<40) { window.setTimeout(function () { initialize(attempt+1); },50); return; }
    if (!Store) { $("#lifecycle-data-status").text("Lifecycle store unavailable").addClass("unhealthy"); return; }
    reloadRecords();
  }

  function activatePipelineStage(card) {
    if (!$("#lifecycle-work-queue").length) {
      window.location.href="detection_catalog?pipeline="+encodeURIComponent(String(card.data("stage")||""));
      return;
    }
    var state=String(card.data("filter-state")||"all");
    $("#lifecycle-stage").val(state);
    $(".dei-pipeline-stage").removeClass("dei-action-target"); card.addClass("dei-action-target");
    $("#dei-flow-status").text("Showing "+String(card.data("stage")||"lifecycle")+" work. Select Continue to open the full lifecycle in Guided Detection Builder.");
    renderQueue();
    document.querySelector(".dei-lifecycle-queue-section").scrollIntoView({behavior:"smooth",block:"start"});
  }

  $(".dei-pipeline-grid").on("click",".dei-pipeline-stage",function () { activatePipelineStage($(this)); });
  $(".dei-pipeline-grid").on("keydown",".dei-pipeline-stage",function (event) {
    if (event.key==="Enter" || event.key===" ") { activatePipelineStage($(this)); event.preventDefault(); }
  });

  $("#lifecycle-work-queue").on("click",".dei-generate-detection",function () {
    var id=String($(this).data("detection")||""); window.localStorage.setItem(SELECTED_DETECTION_KEY,id);
    window.location.href="detection_workflow?detection="+encodeURIComponent(id);
  });
  $(document).on("dei:workflow-detection-selected",function (event,key) {
    var record=records.filter(function (item) { return recordKey(item)===String(key||""); })[0]||null;
    updateRestartControl(record);
    if (key && (!guidedBuilderPage() || draftStarted(key) || opensActionWindow(record))) { selectRecord(String(key)); }
    else { closeActionWindow(); }
  });
  $(document).on("dei:detection-draft-reset",function (event,key) {
    if (key) { generatedDrafts[String(key)]=false; }
    selectedRecord=null;
    closeActionWindow();
  });
  $(document).on("dei:detection-draft-generated dei:detection-artifact-saved",function (event,key,record) {
    var value=String(key||"");
    if (!value || !record) { return; }
    generatedDrafts[value]=true;
    records=records.filter(function (item) { return recordKey(item)!==value; });
    records.push(record);
    selectRecord(value);
  });
  $("#lifecycle-work-queue").on("click",".dei-inline-reset",function () { $("#lifecycle-reset-filters").trigger("click"); });
  $("#lifecycle-action-buttons").on("click","button[data-action]",function (event) { event.preventDefault(); event.stopPropagation(); if ($(this).prop("disabled")) { return; } handleAction(String($(this).data("action")||"")); });
  $("#lifecycle-action-progress").on("click","[data-stage-action]",function (event) { event.preventDefault(); event.stopPropagation(); if ($(this).prop("disabled")) { return; } handleAction(String($(this).data("stage-action")||"")); });
  $("#workflow-primary-action").on("click",function (event) {
    if (String($(this).attr("href")||"")!=="#lifecycle-action-center") { return; }
    var key=String($("#workflow-detection-select").val()||""); if (key) { selectRecord(key); event.preventDefault(); }
  });
  $("#lifecycle-action-close").on("click",closeActionWindow);
  $("#workflow-tab-all").on("click",function () { activateWorkspacePanel("all"); });
  $("#workflow-tab-artifact").on("click",function () { activateWorkspacePanel("artifact"); });
  $("#workflow-tab-change-control").on("click",function () { if (selectedRecord) { activateWorkspacePanel("change-control"); } });
  $(document).on("dei:edit-spl-requested",function () { activateWorkspacePanel("artifact"); });
  $("#lifecycle-action-fields").on("change","#lifecycle-deployment-environment",updateLifecycleDeploymentWorkflow);
  $("#lifecycle-action-fields").on("input","#lifecycle-action-comment",clearActionError);
  $("#builder-restart-workflow").on("click",function () { $("#builder-restart-panel").prop("hidden",false); $("#builder-restart-reason").trigger("focus"); });
  $("#builder-cancel-restart").on("click",function () { $("#builder-restart-panel").prop("hidden",true); $("#builder-restart-reason").val(""); });
  $("#builder-confirm-restart").on("click",function () {
    var key=String($("#workflow-detection-select").val()||$("#builder-detection-select").val()||""); var record=records.filter(function(item){return recordKey(item)===key;})[0]||null; var reason=String($("#builder-restart-reason").val()||"").trim();
    if (!record) { $("#builder-start-feedback").removeClass("ready success").addClass("error").text("Select a persisted detection before restarting its lifecycle."); return; }
    if (!reason) { $("#builder-start-feedback").removeClass("ready success").addClass("error").text("A restart reason is required."); $("#builder-restart-reason").trigger("focus"); return; }
    selectedRecord=record; saveAndReload(restartFromRecommendation(record,reason),"Current version archived. Detection returned to Recommendation.","restart_recommendation");
  });
  $("#lifecycle-reset-filters").on("click",function () { $("#lifecycle-search").val(""); $("#lifecycle-readiness,#lifecycle-stage,#lifecycle-assignment").val("all"); $("#lifecycle-visible-rows").val("10"); $(".dei-lifecycle-queue-section").attr("data-visible-rows","10"); renderQueue(); });
  $("#lifecycle-search,#lifecycle-readiness,#lifecycle-stage,#lifecycle-assignment").on("input change",renderQueue);
  $("#lifecycle-visible-rows").on("change",function () { var rows=String($(this).val()||"10"); $(".dei-lifecycle-queue-section").attr("data-visible-rows",rows==="25"?"25":"10"); renderQueue(); });
  $(window).on("storage",function (event) { if(!event.originalEvent||event.originalEvent.key===REPORT_KEY){render();} });
  initialize(0);
});
