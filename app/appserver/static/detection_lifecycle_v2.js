require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var REPORT_KEY = "dei.latestRecommendationReport";
  var REPORT_TIME_KEY = "dei.latestRecommendationTime";
  var SELECTED_DETECTION_KEY = "dei.selectedDetectionDraft";
  var report = null;
  var records = [];
  var selectedRecord = null;
  var Store = null;

  function safeJson(value) { try { return JSON.parse(value || "null"); } catch (error) { return null; } }
  function esc(value) { return String(value == null ? "" : value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
  function label(value) { return String(value || "unknown").replace(/\\b\\w/g,function (c) { return c.toUpperCase(); }); }
  function recommendations() { return report && report.recommendations ? report.recommendations : []; }
  function sourceMappings() { return report && report.source_mappings ? report.source_mappings : []; }
  function recordKey(item) { return String(item && (item.detection_id || item._key || item.id) || "").replace(/^dei-/,""); }
  function recordFor(item) { var key=recordKey(item); return records.filter(function (record) { return recordKey(record)===key; })[0] || null; }

  function observedSourcetypes(item) {
    if (item.sourcetypes && item.sourcetypes.length) { return item.sourcetypes; }
    var matched=(item.observed_sources||[]).map(function (source) { return String(source||"").toLowerCase(); });
    return sourceMappings().filter(function (mapping) {
      return [mapping.canonical_source].concat(mapping.additional_canonical_sources||[]).some(function (source) {
        return matched.indexOf(String(source||"").toLowerCase())!==-1;
      });
    }).map(function (mapping) { return mapping.observed_source; });
  }

  function buildable(item) { return {production_ready:true,field_unverified:true,field_gap:true}[item.readiness]===true; }
  function stateFor(item, record) { return record && record.state ? record.state : "recommendation"; }
  function nextAction(item, record) {
    var state=stateFor(item,record);
    if (state==="recommendation") {
      if (buildable(item)) { return "Generate and save a versioned detection draft"; }
      if (item.readiness==="partial") { return "Onboard the missing required telemetry"; }
      if (item.readiness==="field_gap") { return "Resolve confirmed fields in an engineering draft"; }
      return "Qualify telemetry and field prerequisites";
    }
    if (state==="draft") { return "Complete bounded validation in Detection Builder"; }
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
    var all=mergedQueue().filter(isEngineeringWork);
    var items=all.filter(function (item) {
      var record=item.lifecycle_record; var current=stateFor(item,record);
      var haystack=[item.name,item.capability,item.pack_id,observedSourcetypes(item).join(" "),
        (item.mitre_techniques||[]).join(" "),current].join(" ").toLowerCase();
      return (!query||haystack.indexOf(query)!==-1) &&
        (readiness==="all"||item.readiness===readiness) && (stage==="all"||current===stage);
    });
    $("#lifecycle-queue-count").text(items.length+" of "+all.length+" items");
    $("#lifecycle-queue-total").text(items.length);
    if (!all.length) {
      $("#lifecycle-work-queue").html('<tr><td colspan="7"><strong>No lifecycle work is available.</strong><br/>Run Analyze Environment in Command Center or restore a persisted lifecycle record.</td></tr>');
      return;
    }
    $("#lifecycle-work-queue").html(items.length ? items.map(function (item) {
      var record=item.lifecycle_record; var state=stateFor(item,record); var sources=observedSourcetypes(item);
      var button=record ? '<button type="button" class="dei-manage-lifecycle" data-detection="'+esc(recordKey(item))+'">Manage</button>' :
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
    var currentStage=record.catalog && record.catalog.status==="ready" ? "catalog" : record.state;
    var current=Math.max(0,states.map(function (state) { return state.id; }).indexOf(currentStage));
    return '<div class="dei-lifecycle-progress">'+states.map(function (state,index) {
      var status=index<current?"complete":(index===current?"current":"future");
      var statusLabel=status==="complete"?"Complete":(status==="current"?"Current stage":"Upcoming");
      return '<div class="dei-progress-step '+status+'"'+(status==="current"?' aria-current="step"':"")+'><span>'+(status==="complete"?"✓":String(index+1))+'</span><div><strong>'+esc(state.label)+'</strong><small>'+statusLabel+'</small></div></div>';
    }).join("")+"</div>";
  }

  function lifecyclePosition(record) {
    var stages=["draft","testing","peer_review","catalog","production","monitoring","tuning","retired"];
    var current=record.catalog && record.catalog.status==="ready" ? "catalog" : record.state;
    var index=Math.max(0,stages.indexOf(current));
    return {stage:current,index:index+1,total:stages.length};
  }

  function gateGuidance(record) {
    var approved=record.review && record.review.decision==="approved";
    var guides={
      draft:{gate:"Gate 1 · Detection design",owner:"Detection engineer",required:"Complete and save the SPL, schedule, telemetry mappings, and ATT&CK context.",steps:["Open Detection Builder.","Review or edit the generated platform SPL and optional ES artifact.","Run bounded historical validation."],outcome:"A successful validation advances the record to Testing.",instruction:"Open Builder and complete bounded validation before continuing."},
      testing:{gate:"Gate 2 · Validation handoff",owner:"Detection engineer",required:"A passed validation result and a review-submission note.",steps:["Review the sampled results and runtime evidence.","Describe the analytic intent, expected behavior, and known limitations.","Submit the validated version for peer review."],outcome:"The record becomes available to a reviewer in Peer Review.",instruction:"Document the validation evidence, then submit this version for peer review."},
      peer_review:approved?{gate:"Gate 4 · Controlled deployment record",owner:"Deployment owner",required:"The exact deployed saved-search, ES detection, or external object reference.",steps:["Deploy the approved artifact through the normal change process.","Select the deployment target and environment.","Record the exact object name/ID and optional change ticket."],outcome:"Recording deployment advances the detection to Production; DEI does not silently deploy it.",instruction:"Peer review is approved. Record the real deployment reference to enter Production."}:{gate:"Gate 3 · Independent peer review",owner:"DEI lifecycle reviewer",required:"A written approval rationale or specific change request.",steps:["Open Builder and inspect SPL, ATT&CK mapping, schedule, warnings, and validation evidence.","Confirm the logic is safe, scoped, and operationally actionable.","Approve this version or return it to Draft with required changes."],outcome:"Approval unlocks deployment recording; returned work reopens Draft.",instruction:"A reviewer must approve or return this version with written rationale."},
      production:{gate:"Gate 5 · Production health baseline",owner:"Detection owner / SOC",required:"Initial health, result volume, runtime, and analyst outcome evidence.",steps:["Confirm the deployed object is scheduled and enabled through the target platform.","Measure result volume and search runtime.","Record initial true-positive and false-positive observations."],outcome:"The first health measurement advances the record to Monitoring.",instruction:"Record the first production health measurement to begin Monitoring."},
      monitoring:{gate:"Gate 6 · Continuous detection operations",owner:"Detection owner / SOC",required:"Periodic health and analyst outcome evidence.",steps:["Record current health, result volume, runtime, and analyst outcomes.","Continue monitoring when performance remains acceptable.","Start Tuning for logic changes or Retire with a documented reason."],outcome:"Each decision is retained in the audit history.",instruction:"Record health, open a tuning version, or retire the detection with evidence."},
      tuning:{gate:"Gate 7 · Controlled tuning cycle",owner:"Detection engineer",required:"A revised version followed by fresh validation and peer review.",steps:["Open Builder and revise the SPL or schedule.","Run bounded validation; prior approval cannot be reused.","Submit the new version through peer review and deployment again."],outcome:"Successful validation returns the new version to Testing.",instruction:"Open Builder, revise this version, and complete fresh validation."},
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
    return workflowProgress(record)+'<div class="dei-gate-guide"><div><span class="dei-generator-label">Current gate</span><h3>'+esc(guide.gate)+'</h3><p>'+esc(guide.required)+'</p><dl><dt>Responsible role</dt><dd>'+esc(guide.owner)+'</dd><dt>Gate outcome</dt><dd>'+esc(guide.outcome)+'</dd></dl></div><div><span class="dei-generator-label">What to do next</span><ol>'+guide.steps.map(function (step) { return "<li>"+esc(step)+"</li>"; }).join("")+"</ol>"+(facts.length?'<div class="dei-gate-facts">'+facts.map(function (fact) { return "<span>"+esc(fact)+"</span>"; }).join("")+"</div>":"")+"</div></div>";
  }

  function fieldMarkup(record) {
    if (record.state==="testing") {
      return '<label class="dei-action-field"><span>Review submission note *</span><textarea id="lifecycle-action-comment" placeholder="Summarize validation evidence, analytic intent, expected analyst behavior, and known limitations."></textarea></label>';
    }
    if (record.state==="peer_review") {
      if (record.review && record.review.decision==="approved") {
        return '<div class="dei-action-fields-row"><label class="dei-action-field"><span>Deployment target *</span><select id="lifecycle-deployment-target"><option value="splunk_platform">Splunk saved search</option><option value="enterprise_security">Enterprise Security detection</option><option value="external">External deployment</option></select></label><label class="dei-action-field"><span>Environment *</span><select id="lifecycle-deployment-environment"><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option></select></label><label class="dei-action-field"><span>Saved-search or object ID *</span><input id="lifecycle-external-id" type="text" placeholder="Exact deployed object reference"/></label></div><label class="dei-action-field"><span>Change ticket or deployment note</span><textarea id="lifecycle-action-comment" placeholder="Optional change request, deployment evidence, or required rationale when reopening Draft."></textarea></label>';
      }
      return '<label class="dei-action-field"><span>Peer-review decision rationale *</span><textarea id="lifecycle-action-comment" placeholder="Document why this version is approved or list the exact changes required."></textarea></label>';
    }
    if (record.state==="production" || record.state==="monitoring") {
      var prior=record.monitoring||{};
      return '<div class="dei-action-fields-row"><label class="dei-action-field"><span>Health *</span><select id="lifecycle-health"><option value="healthy"'+(prior.health==="healthy"?" selected":"")+'>Healthy</option><option value="degraded"'+(prior.health==="degraded"?" selected":"")+'>Degraded</option><option value="failing"'+(prior.health==="failing"?" selected":"")+'>Failing</option></select></label><label class="dei-action-field"><span>Result volume *</span><input id="lifecycle-result-volume" type="number" min="0" value="'+esc(prior.result_volume||0)+'"/></label><label class="dei-action-field"><span>Runtime ms *</span><input id="lifecycle-runtime" type="number" min="0" value="'+esc(prior.runtime_ms||0)+'"/></label><label class="dei-action-field"><span>True positives</span><input id="lifecycle-true-positives" type="number" min="0" value="'+esc(prior.true_positives||0)+'"/></label><label class="dei-action-field"><span>False positives</span><input id="lifecycle-false-positives" type="number" min="0" value="'+esc(prior.false_positives||0)+'"/></label></div><label class="dei-action-field"><span>Operational note</span><textarea id="lifecycle-action-comment" placeholder="Document health context. A rationale is required when starting Tuning or retiring."></textarea></label>';
    }
    if (record.state==="tuning") { return '<label class="dei-action-field"><span>Tuning or retirement note *</span><textarea id="lifecycle-action-comment" placeholder="Document the revision objective before opening Builder, or provide the retirement reason."></textarea></label>'; }
    if (record.state==="retired") { return '<p class="dei-empty">This lifecycle record is complete and immutable. Deployment, monitoring, decisions, and retirement evidence remain available in Audit history.</p>'; }
    return '<label class="dei-action-field"><span>Lifecycle note</span><textarea id="lifecycle-action-comment" placeholder="Document the engineering decision."></textarea></label>';
  }

  function buttonMarkup(record) {
    if (record.state==="draft") { return '<button class="primary" data-action="open_builder">Open Builder</button>'; }
    if (record.state==="testing") {
      return (record.validation && record.validation.status==="passed" ? '<button class="primary" data-action="submit_review">Submit for peer review</button>' : "")+'<button data-action="open_builder">Open Builder</button>';
    }
    if (record.state==="peer_review") {
      return record.review && record.review.decision==="approved" ?
        '<button class="primary" data-action="record_deployment">Record deployment and enter Production</button><button data-action="return_draft">Reopen draft</button>' :
        '<button class="primary" data-action="approve_review">Approve version</button><button class="danger" data-action="return_draft">Return for changes</button><button data-action="open_builder">Inspect in Builder</button>';
    }
    if (record.state==="production") { return '<button class="primary" data-action="record_health">Record baseline and start Monitoring</button><button class="danger" data-action="retire">Retire</button>'; }
    if (record.state==="monitoring") { return '<button class="primary" data-action="record_health">Record health</button><button data-action="start_tuning">Start tuning version</button><button class="danger" data-action="retire">Retire</button>'; }
    if (record.state==="tuning") { return '<button class="primary" data-action="open_builder">Open Builder for tuning</button><button class="danger" data-action="retire">Retire</button>'; }
    return "";
  }

  function selectRecord(key) {
    selectedRecord=records.filter(function (record) { return recordKey(record)===key; })[0]||null;
    if (!selectedRecord) { return; }
    $(".dei-lifecycle-workspace-grid").addClass("has-selection");
    $("#lifecycle-action-center").show(); $("#lifecycle-action-title").text(selectedRecord.name);
    var position=lifecyclePosition(selectedRecord);
    $("#lifecycle-action-position").text("Stage "+position.index+" of "+position.total);
    $("#lifecycle-action-state").text("Current stage: "+label(position.stage)+" · Version "+(selectedRecord.version||1));
    $("#lifecycle-action-summary").text("Next required action: "+nextAction(selectedRecord,selectedRecord));
    $("#lifecycle-action-progress").html(renderGateGuide(selectedRecord));
    $("#lifecycle-action-evidence").html(evidence(selectedRecord));
    $("#lifecycle-action-fields").html(fieldMarkup(selectedRecord));
    $("#lifecycle-action-buttons").html(buttonMarkup(selectedRecord));
    $("#lifecycle-action-history").html(history(selectedRecord));
    $("#lifecycle-action-feedback").removeClass("error success").addClass("ready").text(gateGuidance(selectedRecord).instruction);
    document.getElementById("lifecycle-action-center").scrollIntoView({behavior:"smooth",block:"start"});
  }

  function note() { return String($("#lifecycle-action-comment").val()||"").trim(); }
  function transition(record,to,event,detail,changes) {
    var allowed={draft:["testing"],testing:["peer_review","draft"],peer_review:["production","draft"],
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

  function saveAndReload(promise,message) {
    promise.done(function () {
      $("#lifecycle-action-feedback").removeClass("error ready").addClass("success").text(message);
      reloadRecords();
    }).fail(function (error) {
      $("#lifecycle-action-feedback").removeClass("success ready").addClass("error").text(String(error||"Unable to save lifecycle record."));
    });
  }

  function saveAndOpenCatalog(record) {
    Store.write(record).done(function () {
      window.location.href="detection_catalog?detection="+encodeURIComponent(recordKey(record));
    }).fail(function (error) {
      $("#lifecycle-action-feedback").removeClass("success ready").addClass("error").text(String(error||"Unable to catalog the approved detection."));
    });
  }

  function handleAction(action) {
    var record=$.extend(true,{},selectedRecord); var comment=note();
    if (!record) { return; }
    if (action==="open_builder") {
      window.localStorage.setItem(SELECTED_DETECTION_KEY,recordKey(record));
      window.location.href="detection_builder?detection="+encodeURIComponent(recordKey(record)); return;
    }
    if (action==="submit_review") {
      if (!record.validation || record.validation.status!=="passed") { return; }
      if (!comment) { $("#lifecycle-action-feedback").addClass("error").text("A review submission note is required."); return; }
      saveAndReload(transition(record,"peer_review","submitted_for_review",comment,{review:{decision:"pending",submitted_at:new Date().toISOString(),submitted_by:Store.username(),submission_note:comment}}),"Submitted for peer review."); return;
    }
    if (action==="approve_review") {
      if (!comment) { $("#lifecycle-action-feedback").addClass("error").text("Approval rationale is required."); return; }
      var catalogedAt=new Date().toISOString();
      var approved=$.extend(true,{},record,{review:$.extend({},record.review,{decision:"approved",reviewed_at:catalogedAt,reviewer:Store.username(),comments:comment}),catalog:{status:"ready",cataloged_at:catalogedAt,cataloged_by:Store.username()}});
      approved=Store.appendHistory(approved,"peer_review_approved",comment);
      approved=Store.appendHistory(approved,"added_to_detection_catalog","Ready to enable");
      saveAndOpenCatalog(approved); return;
    }
    if (action==="return_draft") {
      if (!comment) { $("#lifecycle-action-feedback").addClass("error").text("Change rationale is required."); return; }
      saveAndReload(transition(record,"draft","returned_for_changes",comment,{review:{decision:"changes_requested",reviewer:Store.username(),comments:comment},validation:null}),"Returned to Draft."); return;
    }
    if (action==="record_deployment") {
      var target=String($("#lifecycle-deployment-target").val()||""); var environment=String($("#lifecycle-deployment-environment").val()||"production"); var external=String($("#lifecycle-external-id").val()||"").trim();
      if (!external) { $("#lifecycle-action-feedback").addClass("error").text("A deployment object ID or saved-search name is required."); return; }
      saveAndReload(transition(record,"production","deployment_recorded",target+" / "+environment+": "+external+(comment?" · "+comment:""),{deployment:{target:target,environment:environment,external_object_id:external,change_reference:comment,deployed_at:new Date().toISOString(),deployed_by:Store.username(),analyst_recorded:true}}),"Production deployment recorded."); return;
    }
    if (action==="record_health") {
      var health=String($("#lifecycle-health").val()||"healthy"); var volume=Number($("#lifecycle-result-volume").val()||0); var runtime=Number($("#lifecycle-runtime").val()||0); var truePositives=Number($("#lifecycle-true-positives").val()||0); var falsePositives=Number($("#lifecycle-false-positives").val()||0);
      if (![volume,runtime,truePositives,falsePositives].every(function (value) { return isFinite(value) && value>=0; })) { $("#lifecycle-action-feedback").addClass("error").text("Volume, runtime, and analyst outcome counts must be non-negative numbers."); return; }
      var monitoring={health:health,result_volume:volume,runtime_ms:runtime,true_positives:truePositives,false_positives:falsePositives,note:comment,last_checked_at:new Date().toISOString(),checked_by:Store.username()};
      saveAndReload(transition(record,"monitoring","health_measured",health+", "+volume+" results, "+runtime+" ms",{monitoring:monitoring}),"Monitoring evidence recorded."); return;
    }
    if (action==="start_tuning") {
      if (!comment) { $("#lifecycle-action-feedback").addClass("error").text("A tuning rationale is required."); return; }
      var previousVersion={version:Number(record.version||1),spl:record.spl,schedule:record.schedule,validation:record.validation,review:record.review,deployment:record.deployment,monitoring:record.monitoring,closed_at:new Date().toISOString()};
      saveAndReload(transition(record,"tuning","tuning_started",comment,{version:Number(record.version||1)+1,validation:null,review:null,deployment:null,monitoring:null,catalog:$.extend({},record.catalog,{status:"tuning"}),previous_versions:(record.previous_versions||[]).concat([previousVersion])}),"Tuning version opened. The detection returned to the engineering queue and prior operational evidence was archived."); return;
    }
    if (action==="retire") {
      var reason=comment; if (!reason) { $("#lifecycle-action-feedback").addClass("error").text("A retirement reason is required in Lifecycle note."); return; }
      saveAndReload(transition(record,"retired","detection_retired",reason,{retirement:{reason:reason,retired_at:new Date().toISOString(),retired_by:Store.username()}}),"Detection retired with history retained.");
    }
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
      applyRequestedPipelineStage();
      var requested=requestedDetection();
      if (requested) {
        selectRecord(requested);
        if (selectedRecord) {
          document.querySelector("#lifecycle-action-center").scrollIntoView({behavior:"smooth",block:"start"});
        }
      } else if (selectedRecord) {
        selectRecord(recordKey(selectedRecord));
      }
    });
  }
  function initialize(attempt) {
    Store=window.DEILifecycleStore;
    if (!Store && attempt<40) { window.setTimeout(function () { initialize(attempt+1); },50); return; }
    if (!Store) { $("#lifecycle-data-status").text("Lifecycle store unavailable").addClass("unhealthy"); return; }
    reloadRecords();
  }

  function activatePipelineStage(card) {
    if (!$("#lifecycle-work-queue").length) {
      window.location.href="detection_operations?pipeline="+encodeURIComponent(String(card.data("stage")||""));
      return;
    }
    var state=String(card.data("filter-state")||"all");
    $("#lifecycle-stage").val(state);
    renderQueue();
    document.querySelector(".dei-lifecycle-queue-section").scrollIntoView({behavior:"smooth",block:"start"});
  }

  $(".dei-pipeline-grid").on("click",".dei-pipeline-stage",function () { activatePipelineStage($(this)); });
  $(".dei-pipeline-grid").on("keydown",".dei-pipeline-stage",function (event) {
    if (event.key==="Enter" || event.key===" ") { activatePipelineStage($(this)); event.preventDefault(); }
  });

  $("#lifecycle-work-queue").on("click",".dei-generate-detection",function () {
    var id=String($(this).data("detection")||""); window.localStorage.setItem(SELECTED_DETECTION_KEY,id);
    window.location.href="detection_builder?detection="+encodeURIComponent(id);
  });
  $("#lifecycle-work-queue").on("click",".dei-manage-lifecycle",function () { selectRecord(String($(this).data("detection")||"")); });
  $("#lifecycle-work-queue").on("click",".dei-inline-reset",function () { $("#lifecycle-reset-filters").trigger("click"); });
  $("#lifecycle-action-buttons").on("click","button",function () { handleAction(String($(this).data("action")||"")); });
  $("#lifecycle-reset-filters").on("click",function () { $("#lifecycle-search").val(""); $("#lifecycle-readiness,#lifecycle-stage").val("all"); $("#lifecycle-visible-rows").val("10"); $(".dei-lifecycle-queue-section").attr("data-visible-rows","10"); renderQueue(); });
  $("#lifecycle-search,#lifecycle-readiness,#lifecycle-stage").on("input change",renderQueue);
  $("#lifecycle-visible-rows").on("change",function () { var rows=String($(this).val()||"10"); $(".dei-lifecycle-queue-section").attr("data-visible-rows",rows==="25"?"25":"10"); });
  $("#lifecycle-workspace-menu").on("change",function () { var destination=$(this).val(); if(destination){window.location.href=destination;} });
  $(window).on("storage",function (event) { if(!event.originalEvent||event.originalEvent.key===REPORT_KEY){render();} });
  initialize(0);
});
